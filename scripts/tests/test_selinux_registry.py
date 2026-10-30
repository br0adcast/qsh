"""Disposable registry inventories and synthetic RPM replies; no host RPM calls."""
from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
import qshd_selinux_contexts as pure
import qshd_selinux_registry as reg

BASE='/etc/selinux/targeted/contexts'
ROW=b'system_r:sshd_t:s0 user_r:user_t:s0\n'
def frame(*values):return b''.join(json.dumps(v).encode()+b'\n' for v in values)

class Replies:
    def __init__(self, paths):self.paths=paths;self.calls=[];self.owner='selinux-policy-targeted';self.fail=False;self.mapping={}
    def _run(self,argv,cwd,*,deadline=None):
        self.calls.append((argv,cwd))
        if self.fail:raise RuntimeError('private command diagnostic')
        if '-qf' in argv:return SimpleNamespace(stdout=frame(self.mapping.get(argv[-1],self.owner)),stderr=b'')
        name=argv[-1]
        paths=[p for p in self.paths if self.mapping.get(p,self.owner)==name]
        return SimpleNamespace(stdout=frame(name,*paths),stderr=b'')

class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup);self.root=Path(self.temp.name)
        self.contexts=self.root/'contexts';self.contexts.mkdir(mode=0o700);(self.contexts/'users').mkdir(mode=0o700)
        (self.contexts/'default_contexts').write_bytes(ROW);(self.contexts/'users/user_u').write_bytes(ROW)
        (self.contexts/'users/root').write_bytes(b'user_r:user_t:s0 user_r:user_t:s0\n')
        for p in self.contexts.rglob('*'):
            if p.is_file():p.chmod(0o644)
        self.paths=[BASE+'/default_contexts',BASE+'/users/user_u'];self.runner=Replies(self.paths)
    def lease(self,**kw):return reg.Registry(self.contexts,anchor=self.root,uid=os.geteuid(),owner=self.runner,**kw).inspection()
    def test_routing_capture_recheck_and_immutable(self):
        with self.lease() as lease:
            routing=lease.routing();self.assertEqual(json.loads(routing),{p:dict(path=p,source_type='sshd_t',original_package='selinux-policy-targeted') for p in self.paths})
            self.assertEqual(sum('-q' in a for a,_ in self.runner.calls),1)
            observation=lease.capture();self.assertEqual(observation.registry_bytes,routing)
            self.assertEqual(len(observation.candidates),3)
            with self.assertRaises(FrozenInstanceError):observation.registry_bytes=b'bad'
            lease.recheck(observation);lease.recheck(observation)
            self.assertEqual(sum('-q' in a for a,_ in self.runner.calls),4)
            with self.assertRaises(reg.RegistryError):lease.capture()
        with self.assertRaises(reg.RegistryError):lease.recheck(observation)
    def test_optional_container_and_exact_command_vectors(self):
        with self.lease() as lease:lease.routing()
        self.assertFalse(any(a[-1]=='container-selinux' for a,_ in self.runner.calls))
        path=BASE+'/users/container_u';local=self.contexts/'users/container_u'
        local.write_bytes(b'system_r:sshd_t:s0 container_user_r:container_user_t:s0\n');local.chmod(0o644)
        self.paths.append(path);self.runner.mapping[path]='container-selinux'
        self.runner.calls=[]
        with self.lease() as lease:
            ids=json.loads(lease.routing());self.assertEqual(ids[path]['original_package'],'container-selinux')
            lease.recheck(lease.capture())
        for argv,cwd in self.runner.calls:
            self.assertEqual(cwd,str(self.contexts));self.assertEqual(argv[0],'/usr/bin/rpm')
            if '-qf' in argv:self.assertEqual(argv[:5],('/usr/bin/rpm','-qf','--qf','%{NAME:json}\n','--'))
            else:self.assertEqual(argv[:5],('/usr/bin/rpm','-q','--qf','%{NAME:json}\n[%{FILENAMES:json}\n]','--'))

    def test_candidate_binding_and_metadata_drift(self):
        path=self.contexts/'users/user_u'
        for kind in ('inode','mode','xattr'):
            with self.subTest(kind=kind),self.lease() as lease:
                lease.routing();record=lease.capture()
                if kind=='inode':
                    replacement=self.root/'replacement';replacement.write_bytes(path.read_bytes());replacement.chmod(0o644);replacement.replace(path)
                elif kind=='mode':path.chmod(0o600)
                else:os.setxattr(path,'user.synthetic',b'change')
                with self.assertRaises(reg.RegistryError):lease.recheck(record)
        with self.lease() as lease:
            lease.routing();record=lease.capture()
            users=self.contexts/'users';users.rename(self.contexts/'old-users');users.mkdir(mode=0o700)
            with self.assertRaises((reg.RegistryError,reg.Conflict)):lease.recheck(record)

    def test_classifier_uses_both_rows_and_markers(self):
        self.assertTrue(pure.context_relevant(ROW));self.assertFalse(pure.context_relevant(b'# unrelated\n'))
        self.assertTrue(pure.context_relevant(b'system_r:qshd_t:s0 user_r:user_t:s0\n'))
        self.assertTrue(pure.context_relevant(b'# qshd-context-row broken\n'))
        for raw in (ROW+ROW, b'system_r:qshd_t:s0 bad\n',ROW+b'system_r:qshd_t:s0 bad\n'):
            with self.assertRaises(pure.ReconcileError):pure.context_relevant(raw)
    def test_json_protocol_and_manifest_membership(self):
        self.assertEqual(reg.parse_owner(frame('container-selinux')),'container-selinux')
        self.assertEqual(reg.parse_manifest(frame('container-selinux','/a'),'container-selinux'),('/a',))
        for raw in (b'selinux-policy-targeted\n',b' \"container-selinux\"\n',frame('bad'),frame('container-selinux','container-selinux'),frame('container-selinux')+b'junk'):
            with self.assertRaises(reg.RegistryError):reg.parse_owner(raw)
        for raw in (frame('container-selinux','/a','/a'),frame('container-selinux','/a\n/forged'),frame('container-selinux','../a'),frame('container-selinux','/a/../b'),frame('container-selinux','/é'),b'"container-selinux"\n"/a" junk\n'):
            with self.assertRaises(reg.RegistryError):reg.parse_manifest(raw,'container-selinux')
        self.runner.paths=[]
        with self.assertRaises(reg.RegistryError):
            with self.lease() as lease:lease.routing()
    def test_relevant_limits_and_irrelevant_inventory(self):
        with self.lease() as lease:
            self.assertEqual(len(json.loads(lease.routing())),2)
        for i in range(15):
            p=self.contexts/'users'/f'u{i}';p.write_bytes(ROW);p.chmod(0o644)
        with self.assertRaises(reg.RegistryError):
            with self.lease() as lease:lease.routing()
    def test_drift_and_failing_lease_cannot_reset(self):
        with self.lease() as lease:
            lease.routing();observation=lease.capture();(self.contexts/'users/new').write_bytes(b'# unrelated\n')
            with self.assertRaises(reg.RegistryError):lease.recheck(observation)
            (self.contexts/'users/new').unlink()
            with self.assertRaises(reg.RegistryError):lease.recheck(observation)
        with self.lease() as lease:
            lease.routing();(self.contexts/'users/new').write_bytes(ROW)
            with self.assertRaises(reg.RegistryError):lease.capture()
    def test_authority_types_and_no_bootstrap(self):
        (self.contexts/'users/user_u').chmod(0o666)
        with self.assertRaises((reg.RegistryError,reg.Conflict)):
            with self.lease() as lease:lease.routing()
        (self.contexts/'users/user_u').chmod(0o644)
        for kind in ('link','fifo','dir'):
            path=self.contexts/'users/bad'
            if kind=='link':path.symlink_to(self.contexts/'default_contexts')
            elif kind=='fifo':os.mkfifo(path)
            else:path.mkdir()
            with self.assertRaises((reg.RegistryError,reg.Conflict)):
                with self.lease() as lease:lease.routing()
            path.rmdir() if kind=='dir' else path.unlink()
        (self.contexts/'default_contexts').unlink()
        with self.assertRaises((reg.RegistryError,reg.Conflict)):
            with self.lease() as lease:lease.routing()
        self.assertFalse((self.contexts/'default_contexts').exists())
    def test_composed_context_receipt_coverage_and_single_window(self):
        import qshd_selinux_transaction as tx
        from contextlib import contextmanager
        ids={p:dict(path=p,source_type='sshd_t',original_package='selinux-policy-targeted') for p in self.paths}
        targets={p:self.contexts/p.removeprefix(BASE+'/') for p in self.paths}
        engine=tx.Transaction(self.root/'state',targets,uid=os.geteuid())
        engine.reconcile(ids)
        events=[]
        @contextmanager
        def status():
            events.append('open')
            try:yield
            finally:events.append('close')
        with self.lease() as lease:
            self.assertEqual(json.loads(lease.routing()),ids)
            with engine.inspection(ids) as context:
                with status():
                    registry=lease.capture();rows=context.capture()
                    lease.recheck(registry);context.recheck(rows)
                    self.assertEqual(events,['open'])
        self.assertEqual(events,['open','close'])
        # Discovery is not a receipt authority. A no-longer-relevant leaf must
        # still be rejected by mandatory context inspection's receipt coverage.
        (self.contexts/'users/user_u').write_bytes(b'# unrelated now\n')
        with self.lease() as lease:
            current=json.loads(lease.routing())
            target={p:self.contexts/p.removeprefix(BASE+'/') for p in current}
            with self.assertRaises(tx.Conflict):
                with tx.Transaction(self.root/'state',target,uid=os.geteuid()).inspection(current) as context:
                    with status():
                        lease.capture();context.capture()

    def test_production_fixed_roots_and_profile(self):
        with patch.object(reg.os,'geteuid',return_value=1000):
            with self.assertRaises(reg.RegistryError):reg.production()
        # Native process construction is injected: no host process owner setup.
        with patch.object(reg.os,'geteuid',return_value=0), patch.object(reg,'_process_owner',return_value=self.runner) as factory:
            engine=reg.production()
            self.assertEqual(str(engine.contexts),BASE)
            self.assertEqual(str(engine.anchor),'/');self.assertEqual(engine.uid,0)
            factory.assert_called_once_with()

    def test_foreign_precapture_and_command_refresh_drift(self):
        with self.lease() as lease:
            with self.assertRaises(reg.RegistryError):lease.recheck(None)
        with self.lease() as lease:
            lease.routing();first=lease.capture()
            with self.lease() as other:
                other.routing();other.capture()
                with self.assertRaises(reg.RegistryError):other.recheck(first)
            self.runner.owner='container-selinux'
            with self.assertRaises(reg.RegistryError):lease.recheck(first)
        self.runner.owner='selinux-policy-targeted'
        with self.lease() as lease:
            lease.routing();record=lease.capture();self.runner.paths.append('/synthetic/new')
            with self.assertRaises(reg.RegistryError):lease.recheck(record)

    def test_no_write_calls_candidate_count_and_bounds(self):
        from contextlib import ExitStack
        with ExitStack() as stack:
            for name in ('mkdir','write','rename','unlink','fsync','fchmod','fchown','setxattr','removexattr'):
                stack.enter_context(patch.object(reg.os,name,side_effect=AssertionError('mutation')))
            original=reg.os.open
            def opened(path,flags,*a,**kw):
                self.assertFalse(flags & (os.O_CREAT|os.O_WRONLY|os.O_RDWR));return original(path,flags,*a,**kw)
            stack.enter_context(patch.object(reg.os,'open',side_effect=opened))
            with self.lease() as lease:lease.routing();lease.recheck(lease.capture())
        for i in range(126):
            p=self.contexts/'users'/f'irrelevant{i}';p.write_bytes(b'# unrelated\n');p.chmod(0o644)
        with self.assertRaises(reg.RegistryError):
            with self.lease() as lease:lease.routing()
        for raw in (b'x'*(reg.MAX_OUTPUT+1),frame('container-selinux',*['/a'+str(i) for i in range(reg.MAX_FILES+1)]),frame('container-selinux','/'+('x'*4096))):
            with self.assertRaises(reg.RegistryError):reg.parse_manifest(raw,'container-selinux')

    def test_rpm_stderr_and_deadline_during_command_refuse(self):
        original=self.runner._run
        def diagnostic(*a,**kw):
            result=original(*a,**kw);result.stderr=b'private warning';return result
        with patch.object(self.runner,'_run',side_effect=diagnostic):
            with self.assertRaises(reg.RegistryError):
                with self.lease() as lease:lease.routing()
        now=[0.0]
        def late(*a,**kw):
            self.assertEqual(kw['deadline'],60);now[0]=61;return original(*a,**kw)
        with patch.object(self.runner,'_run',side_effect=late):
            with self.assertRaises(reg.RegistryError):
                with self.lease(clock=lambda:now[0]) as lease:lease.routing()

    def test_total_deadline_includes_routing_and_commands(self):
        now=[0.0]
        with self.lease(clock=lambda:now[0]) as lease:
            now[0]=61
            with self.assertRaises(reg.RegistryError):lease.routing()
        with self.lease(clock=lambda:now[0]) as lease:
            lease.routing();now[0]+=61
            with self.assertRaises(reg.RegistryError):lease.capture()
    def test_command_failure_bounded_and_cleanup(self):
        before=len(list(Path('/proc/self/fd').iterdir()));self.runner.fail=True
        for _ in range(3):
            with self.assertRaises(reg.RegistryError) as caught:
                with self.lease() as lease:lease.routing()
            self.assertNotIn('private',str(caught.exception))
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)

if __name__=='__main__':unittest.main()
