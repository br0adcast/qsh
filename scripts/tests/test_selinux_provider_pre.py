"""Temporary filesystem controls; never host manager/native calls."""
import fcntl
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
import qshd_selinux_activation as model
import qshd_selinux_activation_state as state
import qshd_selinux_package_state as package
import qshd_selinux_provider_pre as pre

class StateTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.common=self.root/'qshd';self.guards=0
        self.trusted=model.TrustedArtifact('test1','a'*64,'b'*64)
        outer=self
        class Bindings:
            def preconditions(self): pass
            def package(self):return package.PackageState(outer.common,uid=os.getuid(),anchor=outer.root)
            def slot(self):return state.ActivationSlot(outer.common/'selinux-activation',uid=os.getuid(),anchor=outer.root)
            def guard(self,deadline):
                outer.guards+=1
                if outer.guards==1:outer.assertFalse(outer.common.exists())
                else:
                    for name in ('selinux-package.lock','selinux-activation/lock'):
                        fd=os.open(outer.common/name,os.O_RDONLY)
                        try:
                            with outer.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                        finally:os.close(fd)
        self.bindings=Bindings()
    def run_pre(self):return pre._Coordinator(self.bindings).invalidate(self.trusted,deadline=time.monotonic()+30)
    def test_absent_exact_pending_and_real_locks(self):
        r=self.run_pre();self.assertEqual(r.state,'PENDING');self.assertEqual(r.artifact,self.trusted)
        self.assertEqual(r.module,model.ModuleIdentity('qshd',400,'targeted','pp'));self.assertIsNone(r.completion)
        self.assertEqual(self.guards,2);self.assertEqual(model.parse_activation((self.common/'selinux-activation/activation.json').read_bytes()),r)
    def test_existing_pending_preserved(self):
        self.run_pre();p=self.common/'selinux-activation/activation.json';before=(p.read_bytes(),p.stat())
        self.bindings.guard=lambda deadline:None
        with self.assertRaisesRegex(pre.PreError,'EXISTING_RECORD'):self.run_pre()
        self.assertEqual(p.read_bytes(),before[0]);self.assertEqual(p.stat(),before[1])
    def test_guard_refusal_before_initialization(self):
        def refuse(deadline):raise RuntimeError('synthetic')
        self.bindings.guard=refuse
        with self.assertRaises(pre.PreError):self.run_pre()
        self.assertFalse(self.common.exists())
    def test_single_use_invalid_and_expired(self):
        c=pre._Coordinator(self.bindings)
        with self.assertRaises(pre.PreError):c.invalidate(None,deadline=time.monotonic()+30)
        with self.assertRaisesRegex(pre.PreError,'SINGLE_USE'):c.invalidate(self.trusted,deadline=time.monotonic()+30)
        with self.assertRaises(pre.PreError):pre._Coordinator(self.bindings).invalidate(self.trusted,deadline=time.monotonic()-1)
        self.assertFalse(self.common.exists())

    def test_complete_and_malformed_refuse_unchanged(self):
        from dataclasses import asdict
        import json
        self.bindings.guard=lambda deadline:None
        with self.bindings.package().initialize():pass
        p=self.common/'selinux-activation/activation.json'
        complete=model.Activation(1,'COMPLETE','c'*32,'fedora44-targeted-v1',1,1,
            self.trusted,model.ModuleIdentity('qshd',400,'targeted','pp'),
            model.Completion('normal-install-reload-v1','b'*64,model.ContextBinding('d'*64,'e'*64)))
        for data in (pre._json(asdict(complete)),b'{malformed'):
            p.write_bytes(data);p.chmod(0o600);before=(p.read_bytes(),p.stat())
            with self.assertRaises(pre.PreError):self.run_pre()
            self.assertEqual((p.read_bytes(),p.stat()),before)

    def test_partial_layout_never_repaired(self):
        self.bindings.guard=lambda deadline:None
        self.common.mkdir(mode=0o700)
        (self.common/'selinux-activation').mkdir(mode=0o700)
        with self.assertRaises(pre.PreError):self.run_pre()
        self.assertFalse((self.common/'selinux-activation/lock').exists())

    def test_postrename_hook_failure_is_uncertain(self):
        from unittest.mock import patch
        original=self.bindings.slot
        def faulty():
            value=original()
            def hook(event):
                if event=='slot_rename':raise OSError('synthetic post-rename failure')
            value.hook=hook
            return value
        self.bindings.slot=faulty
        with self.assertRaisesRegex(pre.PreError,'^STATE_UNCERTAIN$'):self.run_pre()
        self.assertEqual(model.parse_activation((self.common/'selinux-activation/activation.json').read_bytes()).state,'PENDING')

    def test_outer_exit_is_uncertain(self):
        from contextlib import contextmanager
        self.bindings.guard=lambda deadline:None
        original=self.bindings.package
        class Scope:
            @contextmanager
            def initialize(inner):
                with original().initialize():yield
                raise OSError('synthetic outer close')
        self.bindings.package=lambda:Scope()
        with self.assertRaisesRegex(pre.PreError,'^STATE_UNCERTAIN$'):self.run_pre()
        self.assertEqual(model.parse_activation((self.common/'selinux-activation/activation.json').read_bytes()).state,'PENDING')

    def test_late_after_publication_is_uncertain(self):
        now=[time.monotonic()];original=self.bindings.slot
        def faulty():
            value=original()
            def hook(event):
                if event=='slot_readback':now[0]+=31
            value.hook=hook;return value
        self.bindings.slot=faulty
        with self.assertRaisesRegex(pre.PreError,'^STATE_UNCERTAIN$'):
            pre._Coordinator(self.bindings,clock=lambda:now[0]).invalidate(self.trusted,deadline=now[0]+30)


    def test_actual_directory_fsync_failure_is_uncertain(self):
        from unittest.mock import patch
        native=os.fsync;armed=[False];original=self.bindings.slot
        def faulty():
            value=original()
            value.hook=lambda event:armed.__setitem__(0,True) if event=='slot_rename' else None
            return value
        def sync(fd):
            if armed[0]:raise OSError('synthetic directory fsync')
            return native(fd)
        self.bindings.slot=faulty
        with patch.object(os,'fsync',sync),self.assertRaisesRegex(pre.PreError,'^STATE_UNCERTAIN$'):self.run_pre()
        self.assertEqual(model.parse_activation((self.common/'selinux-activation/activation.json').read_bytes()).state,'PENDING')

    def test_actual_trace_after_begin_pending_returns_is_uncertain(self):
        import inspect
        lines,start=inspect.getsourcelines(pre._Coordinator.invalidate)
        target=start+next(i for i,line in enumerate(lines) if 'writer.begin_pending(document,initial)' in line)+1
        hit=[]
        def trace(frame,event,arg):
            if event=='line' and frame.f_code is pre._Coordinator.invalidate.__code__ and frame.f_lineno==target:
                hit.append(True);raise KeyboardInterrupt()
            return trace
        previous=sys.gettrace()
        try:
            sys.settrace(trace)
            with self.assertRaisesRegex(pre.PreError,'^STATE_UNCERTAIN$'):self.run_pre()
        finally:sys.settrace(previous)
        self.assertEqual(hit,[True]);self.assertEqual(model.parse_activation((self.common/'selinux-activation/activation.json').read_bytes()).state,'PENDING')

    def test_readback_drift_never_returns_success(self):
        original=self.bindings.slot
        def faulty():
            value=original()
            def hook(event):
                if event=='slot_readback':
                    path=self.common/'selinux-activation/activation.json'
                    path.write_bytes(b'malformed');path.chmod(0o600)
            value.hook=hook;return value
        self.bindings.slot=faulty
        with self.assertRaisesRegex(pre.PreError,'^STATE_UNCERTAIN$'):self.run_pre()


    def test_forged_artifact_shape_refused_before_setup(self):
        forged=model.TrustedArtifact('test1','a'*64,'b'*64)
        object.__setattr__(forged,'pp_sha256','invalid')
        with self.assertRaises(pre.PreError):pre._Coordinator(self.bindings).invalidate(forged,deadline=time.monotonic()+30)
        self.assertEqual(self.guards,0);self.assertFalse(self.common.exists())

if __name__=='__main__':unittest.main()
