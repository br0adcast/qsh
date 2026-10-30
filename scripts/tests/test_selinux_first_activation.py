"""Actual private state and locks; policy/registry/native seams are injected."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import stat
from unittest.mock import Mock, patch
from types import SimpleNamespace
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
import qshd_selinux_first_activation as c
import qshd_selinux_package_state as package
import qshd_selinux_activation_state as slot
import qshd_selinux_transaction as tx
from qshd_selinux_activation import TrustedArtifact
from qshd_selinux_modules import HllIdentity

PP=b'inert canonical test PP';TRUST=TrustedArtifact('fixture','a'*64,hashlib.sha256(PP).hexdigest())

class Bindings:
    def __init__(self,root):
        self.root=root;self.common=root/'qshd';self.target=root/'context'
        self.original=b'system_r:sshd_t:s0 user_r:user_t:s0\n'
        self.target.write_bytes(self.original);self.target.chmod(0o640)
        self.ids={'/contexts':dict(path='/contexts',source_type='sshd_t',original_package='fixture')}
        self.routing=json.dumps(self.ids,sort_keys=True,separators=(',',':')).encode()
        self.events=[];self.active=set();self.failure=None;self.registry_count=0;self.loads=0;self.now=100
    def fails(self,name):
        return name in self.failure if isinstance(self.failure,set) else self.failure==name
    def point(self,name):
        self.events.append(name)
        if self.fails(name):raise RuntimeError('controlled '+name)
    def preconditions(self):self.point('preconditions')
    @contextmanager
    def track(self,name,manager):
        self.point(name+' enter')
        try:
            with manager as value:
                self.active.add(name)
                try:yield value
                finally:self.active.remove(name)
        finally:self.point(name+' exit')
    def package(self):return self.track('package',package.PackageState(self.common,uid=os.getuid(),anchor=self.root).initialize())
    def slot_object(self):return slot.ActivationSlot(self.common/'selinux-activation',uid=os.getuid(),anchor=self.root,hook=self.slot_hook)
    def activation(self):return self.track('activation',self.slot_object().writer())
    def transaction_object(self):return tx.Transaction(self.common/'selinux-contexts',{'/contexts':self.target},uid=os.getuid(),anchor=self.root,hook=self.transaction_hook)
    def contexts(self,paths):
        assert paths==['/contexts']
        return self.track('contexts',self.transaction_object().writer())
    def transaction_hook(self,event):
        if self.failure=='journal' and event=='journal_directory_sync':raise RuntimeError('controlled durable journal failure')
    def slot_hook(self,event):
        if event=='slot_rename' and self.record()['state']=='COMPLETE':
            self.assert_locked()
            assert 'registry' not in self.active
            self.point('complete replace')
        if self.fails('completion fsync') and event=='slot_directory_sync' and self.record()['state']=='COMPLETE':
            raise OSError('controlled completion directory sync acknowledgement')
    def record(self):return json.loads((self.common/'selinux-activation/activation.json').read_bytes())
    def assert_locked(self):
        for path in (self.common/'selinux-package.lock',self.common/'selinux-activation/lock',self.common/'selinux-contexts/lock'):
            fd=os.open(path,os.O_RDONLY)
            try:
                try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                except BlockingIOError:pass
                else:raise AssertionError('coordinator lost exclusion')
            finally:os.close(fd)
    @contextmanager
    def registry(self):
        self.registry_count+=1;number=self.registry_count
        self.point('registry enter');self.active.add('registry')
        binding=self
        class View:
            def routing(self):
                binding.point('routing')
                return b'{}' if binding.failure=='routing drift' and number==2 else binding.routing
            def capture(self):
                binding.point('registry capture')
                return SimpleNamespace(registry_bytes=binding.routing,registry_sha256=hashlib.sha256(binding.routing).hexdigest())
            def recheck(self,value):binding.point('registry recheck')
        try:yield View()
        finally:self.active.remove('registry')
        self.point('registry exit')
    def installer(self,trust,pp):
        binding=self
        class Installer:
            def install(self,*,deadline):
                assert 'registry' not in binding.active
                assert {'package','activation','contexts'}<=binding.active
                binding.assert_locked();assert binding.record()['state']=='PENDING'
                assert binding.target.read_bytes()==binding.original
                assert trust==TRUST and pp==PP and deadline<=binding.now+240
                binding.point('load');binding.loads+=1
                if binding.failure=='late load':binding.now=400
                return SimpleNamespace(artifact=trust,pp_sha256=trust.pp_sha256)
        return Installer()
    @contextmanager
    def modules(self,trust):
        binding=self;self.point('module enter')
        class View:
            def capture(self):
                binding.assert_locked();binding.point('module capture')
                return SimpleNamespace(hll=HllIdentity(len(PP),'b'*64 if binding.failure=='HLL mismatch' else TRUST.pp_sha256))
            def recheck(self,value):binding.point('module recheck')
        yield View()
        self.point('module exit')
    @contextmanager
    def window(self):
        self.point('window enter');self.assert_locked()
        yield True
        self.point('window exit')

class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.b=Bindings(Path(self.temp.name))
    def run_coordinator(self,trust=TRUST,pp=PP,deadline=1000):
        return c._Coordinator(self.b,clock=lambda:self.b.now).activate_first(trust,pp,deadline=deadline)
    def test_positive_real_durable_state_and_normal_exit_order(self):
        result=self.run_coordinator()
        self.assertEqual(result.state,'COMPLETE');self.assertEqual(self.b.record()['state'],'COMPLETE')
        self.assertEqual(self.b.loads,1);self.assertEqual(self.b.registry_count,2)
        self.assertEqual(self.b.events.count('window enter'),1)
        self.assertLess(self.b.events.index('registry exit'),self.b.events.index('load'))
        self.assertLess(self.b.events.index('window exit'),self.b.events.index('module exit'))
        self.assertLess(self.b.events.index('module exit'),self.b.events.index('complete replace'))
        self.assertEqual(self.b.events.count('complete replace'),1)
        self.assertEqual(self.b.events[-3:],['contexts exit','activation exit','package exit'])
        self.assertFalse(self.b.active)
        self.assertEqual(result.completion.contexts.registry_sha256,hashlib.sha256(self.b.routing).hexdigest())
        self.assertEqual(result.completion.contexts.receipts_sha256,hashlib.sha256((self.b.common/'selinux-contexts/receipts').read_bytes()).hexdigest())
        self.assertEqual(self.b.target.stat().st_mode & 0o777,0o640)
        with self.assertRaises(FrozenInstanceError):result.state='PENDING'
    def test_failed_installer_stays_pending_and_never_reconciles(self):
        self.b.failure='load'
        with self.assertRaises(c.CoordinatorError):self.run_coordinator()
        self.assertEqual(self.b.record()['state'],'PENDING')
        self.assertEqual(self.b.target.read_bytes(),self.b.original)
        self.assertFalse(self.b.active)
    def test_postload_failures_never_publish_complete(self):
        for failure in ('routing drift','registry recheck','module recheck','window exit','module exit','HLL mismatch'):
            with tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.failure=failure
                with self.assertRaises(c.CoordinatorError):self.run_coordinator()
                self.assertEqual(self.b.record()['state'],'PENDING',failure)
    def test_journal_failure_preserves_pending_and_durable_journal(self):
        self.b.failure='journal'
        with self.assertRaises(c.CoordinatorError):self.run_coordinator()
        self.assertEqual(self.b.record()['state'],'PENDING')
        self.assertTrue((self.b.common/'selinux-contexts/journal').exists())
    def test_postpublication_failures_are_uncertain_with_complete_readback(self):
        for failure in ('completion fsync','contexts exit','activation exit','package exit'):
            with tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.failure=failure
                with self.assertRaises(slot.OutcomeUncertain):self.run_coordinator()
                self.assertEqual(self.b.record()['state'],'COMPLETE',failure)
    def test_existing_activation_refuses_without_new_operation(self):
        self.run_coordinator();before=(self.b.common/'selinux-activation/activation.json').read_bytes();loads=self.b.loads
        with self.assertRaises(c.CoordinatorError):self.run_coordinator()
        self.assertEqual((self.b.common/'selinux-activation/activation.json').read_bytes(),before)
        self.assertEqual(self.b.loads,loads)
    def test_pristine_unknown_state_refuses_before_load(self):
        with package.PackageState(self.b.common,uid=os.getuid(),anchor=self.b.root).initialize():pass
        with self.b.transaction_object().writer():pass
        orphan=self.b.common/'selinux-contexts/unknown';orphan.write_bytes(b'preserve')
        with self.assertRaises(c.CoordinatorError):self.run_coordinator()
        self.assertEqual(self.b.loads,0);self.assertEqual(orphan.read_bytes(),b'preserve')
        self.assertEqual(self.b.record()['state'],'PENDING')
    def test_input_process_and_expired_deadline_gate_before_state(self):
        for pp,deadline in ((b'wrong',1000),(PP,True),(PP,float('inf')),(PP,99)):
            with self.assertRaises(c.CoordinatorError):self.run_coordinator(pp=pp,deadline=deadline)
            self.assertFalse(self.b.common.exists())
        self.b.failure='preconditions'
        with self.assertRaises(c.CoordinatorError):self.run_coordinator()
        self.assertFalse(self.b.common.exists())
    def test_late_load_cannot_publish_or_reconcile(self):
        self.b.failure='late load'
        with self.assertRaises(c.CoordinatorError):self.run_coordinator()
        self.assertEqual(self.b.record()['state'],'PENDING');self.assertEqual(self.b.target.read_bytes(),self.b.original)

    def test_uncertain_completion_survives_later_unwind_failures(self):
        for later in ('contexts exit','activation exit','package exit'):
            with tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.failure=later
                native_sync=os.fsync;failed=[]
                def fsync(fd):
                    directory=self.b.common/'selinux-activation'
                    record=directory/'activation.json'
                    if (record.exists() and self.b.record()['state']=='COMPLETE'
                            and stat.S_ISDIR(os.fstat(fd).st_mode)
                            and os.fstat(fd).st_ino==directory.stat().st_ino):
                        failed.append(True);raise OSError('controlled real directory fsync')
                    return native_sync(fd)
                with patch.object(slot.os,'fsync',side_effect=fsync),self.assertRaises(slot.OutcomeUncertain):
                    self.run_coordinator()
                self.assertEqual(failed,[True]);self.assertEqual(self.b.record()['state'],'COMPLETE')

    def test_existing_pending_retry_refuses_without_new_operation(self):
        self.b.failure='load'
        with self.assertRaises(c.CoordinatorError):self.run_coordinator()
        path=self.b.common/'selinux-activation/activation.json';before=path.read_bytes()
        self.b.failure=None
        with self.assertRaisesRegex(c.CoordinatorError,'ACTIVATION_EXISTS'):self.run_coordinator()
        self.assertEqual(path.read_bytes(),before);self.assertEqual(self.b.loads,0)

    def test_real_pristine_journal_receipts_and_rows_refuse_before_installer(self):
        for kind in ('journal','receipts','administrator row'):
            with tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root))
                with package.PackageState(self.b.common,uid=os.getuid(),anchor=self.b.root).initialize():pass
                with self.b.transaction_object().writer() as writer:
                    if kind=='receipts':writer.reconcile(self.b.ids)
                if kind=='journal':(self.b.common/'selinux-contexts/journal').write_bytes(b'foreign malformed journal')
                if kind=='administrator row':self.b.target.write_bytes(self.b.original+b'system_r:qshd_t:s0 user_r:user_t:s0\n')
                before=self.b.target.read_bytes()
                with patch.object(tx.Transaction,'recover',side_effect=AssertionError('must not recover')) as recovery:
                    with self.assertRaises(c.CoordinatorError):self.run_coordinator()
                    recovery.assert_not_called()
                self.assertNotIn('load',self.b.events);self.assertEqual(self.b.loads,0)
                self.assertEqual(self.b.target.read_bytes(),before);self.assertEqual(self.b.record()['state'],'PENDING')

    def test_unknown_activation_stage_refuses_before_pending_or_load(self):
        with package.PackageState(self.b.common,uid=os.getuid(),anchor=self.b.root).initialize():pass
        unknown=self.b.common/'selinux-activation/orphan';unknown.write_bytes(b'preserve')
        with self.assertRaises(c.CoordinatorError):self.run_coordinator()
        self.assertEqual(unknown.read_bytes(),b'preserve');self.assertEqual(self.b.loads,0)
        self.assertFalse((self.b.common/'selinux-activation/activation.json').exists())

    def test_actual_public_entrypoint_uses_fixed_factory_binding(self):
        self.b.now=time.monotonic()
        with patch.object(c,'_Production',return_value=self.b) as production:
            observed=c.activate_first(TRUST,PP,deadline=time.monotonic()+200)
        production.assert_called_once_with();self.assertEqual(observed.state,'COMPLETE')

    def test_fixed_production_factory_delegation_without_native_calls(self):
        import importlib
        production=c._Production();sentinel=object()
        for module,method,facade,args in [('qshd_selinux_package_state','package','initialize',()),
                                         ('qshd_selinux_activation_state','activation','writer',()),
                                         ('qshd_selinux_registry','registry','inspection',()),
                                         ('qshd_selinux_transaction','contexts','writer',(['/contexts'],))]:
            target=importlib.import_module(module);value=Mock();getattr(value,facade).return_value=sentinel
            with patch.object(target,'production',return_value=value) as factory:
                self.assertIs(getattr(production,method)(*args),sentinel)
            factory.assert_called_once_with(*args);getattr(value,facade).assert_called_once_with()
        target=importlib.import_module('qshd_selinux_module_install')
        with patch.object(target,'production_installer',return_value=sentinel) as factory:
            self.assertIs(production.installer(TRUST,PP),sentinel)
        factory.assert_called_once_with(TRUST,PP)
        target=importlib.import_module('qshd_selinux_module_observer')
        with patch.object(target,'production_observer',return_value=sentinel) as factory:
            self.assertIs(production.modules(TRUST),sentinel)
        factory.assert_called_once_with(TRUST)
        native=importlib.import_module('qshd_selinux_api');queries=importlib.import_module('qshd_selinux_queries')
        with patch.object(native,'SelinuxApi',return_value='injected') as api,patch.object(queries,'required_observation',return_value=sentinel) as window:
            self.assertIs(production.window(),sentinel)
        api.assert_called_once_with();window.assert_called_once_with('injected')
        process=importlib.import_module('qshd_selinux_process')
        with patch.object(c.os,'geteuid',return_value=1000),patch.object(process,'_preconditions') as preconditions:
            with self.assertRaisesRegex(c.CoordinatorError,'ROOT_REQUIRED'):production.preconditions()
            preconditions.assert_not_called()
        with patch.object(c.os,'geteuid',return_value=0),patch.object(process,'_preconditions') as preconditions:
            production.preconditions();preconditions.assert_called_once_with()

    def test_phase_deadlines_refuse_before_pending_or_complete(self):
        for phase in ('initial routing','final registry'):
            with tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));original=self.b.point
                def point(name):
                    original(name)
                    if ((phase=='initial routing' and name=='routing') or
                            (phase=='final registry' and name=='registry exit' and self.b.registry_count==2)):
                        self.b.now=400
                self.b.point=point
                with self.assertRaisesRegex(c.CoordinatorError,'DEADLINE'):self.run_coordinator()
                if phase=='initial routing':
                    self.assertFalse((self.b.common/'selinux-activation/activation.json').exists())
                    self.assertEqual(self.b.loads,0)
                else:self.assertEqual(self.b.record()['state'],'PENDING')

    def test_final_deadline_after_publication_is_uncertain(self):
        original=self.b.point
        def point(name):
            original(name)
            if name=='package exit':self.b.now=400
        self.b.point=point
        with self.assertRaises(slot.OutcomeUncertain):self.run_coordinator()
        self.assertEqual(self.b.record()['state'],'COMPLETE')

    def test_interruption_after_actual_publication_return_is_uncertain(self):
        class ReturnInterruption(BaseException):pass
        actual=slot._Writer.publish_complete
        def interrupted(writer,*args,**kwargs):
            actual(writer,*args,**kwargs)
            raise ReturnInterruption('deterministic return-boundary interruption')
        for later in (None,'contexts exit'):
            with tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.failure=later
                with patch.object(slot._Writer,'publish_complete',interrupted),self.assertRaises(slot.OutcomeUncertain):
                    self.run_coordinator()
                self.assertEqual(self.b.record()['state'],'COMPLETE')

    def test_known_preplacement_slot_error_remains_ordinary_pending(self):
        for later in (None,'contexts exit'):
            with tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.failure=later
                original=self.b.slot_hook
                def hook(event):
                    original(event)
                    path=self.b.common/'selinux-activation/activation.json'
                    if event=='before_slot_rename' and path.exists():
                        self.assertEqual(self.b.record()['state'],'PENDING')
                        raise slot.SlotError('CONTROLLED_BEFORE_COMPLETION_REPLACE')
                self.b.slot_hook=hook
                with self.assertRaises(c.CoordinatorError):self.run_coordinator()
                self.assertEqual(self.b.record()['state'],'PENDING')

    def test_trace_interrupt_on_first_caller_line_after_actual_publish_return(self):
        class ReturnInterruption(BaseException):pass
        for later in (None,'contexts exit'):
            with tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.failure=later
                returned=[False];interrupted=[];previous=sys.gettrace()
                def trace(frame,event,arg):
                    if event=='return' and frame.f_code is slot._Writer.publish_complete.__code__:
                        returned[0]=True
                    elif returned[0] and event=='line' and frame.f_code is c._Coordinator.activate_first.__code__:
                        returned[0]=False;interrupted.append(frame.f_lineno)
                        raise ReturnInterruption('first coordinator line after actual publication return')
                    return trace
                try:
                    sys.settrace(trace)
                    with self.assertRaises(slot.OutcomeUncertain):self.run_coordinator()
                finally:sys.settrace(previous)
                self.assertEqual(len(interrupted),1)
                self.assertIs(sys.gettrace(),previous)
                self.assertEqual(self.b.record()['state'],'COMPLETE')

if __name__=='__main__':unittest.main()
