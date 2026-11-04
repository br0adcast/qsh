"""Actual private state and locks; policy/registry/native seams are injected."""
from contextlib import contextmanager
from dataclasses import FrozenInstanceError, asdict, replace
import importlib.util
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

CONTEXTS_PP=b'inert contexts test PP'
PP=b'inert canonical test PP';TRUST=TrustedArtifact('fixture','a'*64,hashlib.sha256(PP).hexdigest(),hashlib.sha256(b'inert contexts test PP').hexdigest())


@contextmanager
def reference_exit_fault(bindings,fault):
    """Fail real final recheck or a real held descriptor close, never publication."""
    import qshd_selinux_reference_loader as references
    original=references.References.__exit__;native_close=os.close;observed=[]
    def exit(reader,kind,value,traceback):
        if kind is not None:return original(reader,kind,value,traceback)
        record=bindings.record()
        observed.append(dict(state=record['state'] if type(record) is dict else record.state,
            package='package' in bindings.active,activation='activation' in bindings.active))
        if fault=='recheck':
            path=reader.anchor/references._SHARE/'reference.json'
            path.write_bytes(path.read_bytes()+b' ')
        if fault=='descriptor-close':
            held=set(reader.anchors+[part for route in reader.routes for part in (route[0],route[2])]);failed=[]
            def close(fd):
                native_close(fd)
                if fd in held and not failed:
                    failed.append(fd);raise OSError('controlled after real reference descriptor close')
            with patch.object(references.os,'close',close):return original(reader,kind,value,traceback)
        return original(reader,kind,value,traceback)
    with patch.object(references.References,'__exit__',exit):yield observed


def require_reference_failure_before_complete(test,bindings,invoke,fault):
    calls=[];original=slot._Writer.publish_complete
    def publish(writer,*args,**kwargs):
        calls.append(True);return original(writer,*args,**kwargs)
    with reference_exit_fault(bindings,fault) as observed,patch.object(slot._Writer,'publish_complete',publish):
        with test.assertRaises(c.CoordinatorError):invoke()
    test.assertEqual(calls,[])
    record=bindings.record()
    test.assertEqual(record['state'] if type(record) is dict else record.state,'PENDING')
    test.assertEqual(observed,[dict(state='PENDING',package=True,activation=True)])


class Bindings:
    def __init__(self,root):
        self.root=root;self.common=root/'qshd';self.target=root/'context'
        self.original=b'system_r:sshd_t:s0 user_r:user_t:s0\n'
        self.target.write_bytes(self.original);self.target.chmod(0o640)
        self.ids={'/contexts':dict(path='/contexts',source_type='sshd_t',original_package='fixture')}
        self.routing=json.dumps(self.ids,sort_keys=True,separators=(',',':')).encode()
        self.expected_trust=TRUST
        for name in ('usr/bin','etc/pam.d','var/log','run'):(root/name).mkdir(parents=True,exist_ok=True)
        for path in root.rglob('*'):
            if path.is_dir():path.chmod(0o755)
        (root/'var/run').symlink_to('../run')
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
            assert 'references' not in self.active
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
    def guard(self,deadline):self.point('guard')
    def consumer_paths(self,pam,*,fresh):
        from qshd_selinux_consumer_activation import _ConsumerPaths
        return _ConsumerPaths(pam,_root=self.root,_uid=os.getuid()).inspection(fresh=fresh)
    def retained(self,*,deadline,pristine=False):
        import qshd_selinux_retained_labels as retained
        value=retained.RetainedLabels(_root=self.root,_uid=os.getuid(),_clock=lambda:self.now)
        return value.pristine_install(deadline=deadline) if pristine else value.managed_inspection(deadline=deadline)
    @contextmanager
    def queries(self,status):
        from qshd_selinux_queries import required_observation
        with required_observation(status.require_open(),status=status) as value:yield value
    def installer(self,trust,pp,contexts_pp):
        binding=self
        class Installer:
            def install(self,*,deadline):
                assert 'registry' not in binding.active
                assert {'package','activation','contexts'}<=binding.active
                binding.assert_locked();assert binding.record()['state']=='PENDING'
                assert binding.target.read_bytes()==binding.original
                assert trust==binding.expected_trust and pp==PP and deadline>binding.now
                binding.point('load');binding.loads+=1
                if binding.failure=='late load':binding.now=1001
                return SimpleNamespace(artifact=trust,pp_sha256=trust.core_pp_sha256)
        return Installer()
    @contextmanager
    def modules(self,trust,*,mode='pair',deadline=None):
        binding=self;self.point('module enter')
        class View:
            def capture(self):
                binding.assert_locked();binding.point('module capture')
                return SimpleNamespace(core=SimpleNamespace(hll=HllIdentity(len(PP),'b'*64 if binding.failure=='HLL mismatch' else trust.core_pp_sha256)),contexts=SimpleNamespace(hll=HllIdentity(len(CONTEXTS_PP),trust.contexts_pp_sha256)))
            def recheck(self,value):binding.point('module recheck')
        yield View()
        self.point('module exit')
    @contextmanager
    def window(self):
        import qshd_selinux_api as native
        from scripts.tests.test_selinux_api import SharedStatus
        from scripts.tests.test_selinux_queries import FakeApi
        self.point('window enter')
        shared=SharedStatus();api=native.SelinuxApi(shared.library());fake=FakeApi();fake.active=True
        for name in ('check_context','require_av','compute_create','compute_relabel','validate_transition'):
            setattr(api,name,getattr(fake,name))
        @contextmanager
        def defaults():
            class Defaults:
                def lookup(inner,path,kind):raise AssertionError('all missing inventory')
            yield Defaults()
        api.file_defaults=defaults
        with api.status_observation() as status:yield status
        self.point('window exit')

class CoordinatorTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.b=Bindings(Path(self.temp.name))
    def run_coordinator(self,trust=TRUST,pp=PP,deadline=1000):
        return c._Coordinator(self.b,clock=lambda:self.b.now).activate_first(trust,pp,CONTEXTS_PP,deadline=deadline)
    def installed(self):
        import qshd_selinux_reference_loader as refs
        root=Path(__file__).resolve().parents[2]
        spec=importlib.util.spec_from_file_location('builder',root/'packaging/selinux/assemble_payload.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        pp=self.b.root/'qshd.pp';pp.write_bytes(PP)
        contexts_pp=self.b.root/'qshd_contexts.pp';contexts_pp.write_bytes(CONTEXTS_PP)
        source=root/'packaging/selinux';artifact=source/'artifact.json';pam=root/'packaging/pam.d/qshd.fedora-selinux'
        expected={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in builder.MODULES}
        expected.update({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (pp,contexts_pp,artifact,pam)})
        out=self.b.root/'installed';builder.assemble_payload(source,pp,contexts_pp,artifact,pam,expected,out,1000000000)
        self.b.expected_trust=TrustedArtifact(json.loads(artifact.read_bytes())['policy_version'],expected['artifact.json'],expected['qshd.pp'],expected['qshd_contexts.pp'])
        @contextmanager
        def references():
            assert 'package' in self.b.active
            with self.b.track('references',refs._testing_references(out)) as reader:yield reader
        self.b.references=references
        return out/'usr/share/qshd-selinux/reference.json'

    def test_installed_reference_recheck_and_fd_close_precede_complete(self):
        for fault in ('recheck','descriptor-close'):
            with self.subTest(fault=fault),tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.installed()
                require_reference_failure_before_complete(self,self.b,
                    lambda:c._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_first(deadline=1000),fault)

    def test_installed_real_references_under_single_package_lease(self):
        self.installed()
        with reference_exit_fault(self.b,None) as closed:
            value=c._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_first(deadline=1000)
        self.assertEqual(closed,[dict(state='PENDING',package=True,activation=True)])
        self.assertLess(self.b.events.index('references exit'),self.b.events.index('complete replace'))
        self.assertEqual(value.artifact,self.b.expected_trust)
        self.assertEqual(self.b.events.count('package enter'),1)
        self.assertLess(self.b.events.index('references exit'),self.b.events.index('package exit'))
        self.assertEqual(self.b.record()['state'],'COMPLETE')

    def test_installed_reference_drift_before_complete_remains_pending(self):
        path=self.installed();point=self.b.point
        def drift(name):
            point(name)
            if name=='window exit':path.write_bytes(path.read_bytes()+b' ')
        self.b.point=drift
        with self.assertRaises(c.CoordinatorError):
            c._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_first(deadline=1000)
        self.assertEqual(self.b.record()['state'],'PENDING')

    def test_installed_reference_finalizer_failure_keeps_pending(self):
        self.installed()
        require_reference_failure_before_complete(self,self.b,
            lambda:c._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_first(deadline=1000),'recheck')

    def test_installed_invalid_reference_never_begins_pending_or_load(self):
        path=self.installed();path.write_bytes(b'{}')
        with self.assertRaises(c.CoordinatorError):
            c._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_first(deadline=1000)
        self.assertFalse((self.b.common/'selinux-activation/activation.json').exists())
        self.assertEqual(self.b.loads,0)
        self.assertEqual(self.b.target.read_bytes(),self.b.original)

    def test_installed_uncertainty_survives_package_exit_masking(self):
        self.installed();self.b.failure={'completion fsync','package exit'}
        with self.assertRaises(slot.OutcomeUncertain):
            c._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_first(deadline=1000)
        self.assertEqual(self.b.record()['state'],'COMPLETE')

    def test_installed_public_entry_and_reference_factory_are_fixed(self):
        self.installed();self.b.now=time.monotonic()
        with patch.object(c,'_Production',return_value=self.b) as factory:
            self.assertEqual(c.activate_installed_first(deadline=time.monotonic()+430).state,'COMPLETE')
        factory.assert_called_once_with()
        import qshd_selinux_reference_loader as references
        sentinel=object()
        with patch.object(references,'production_references',return_value=sentinel) as factory:
            self.assertIs(c._Production().references(),sentinel)
        factory.assert_called_once_with()

    def test_positive_real_durable_state_and_normal_exit_order(self):
        result=self.run_coordinator()
        self.assertEqual(result.state,'COMPLETE');self.assertEqual(self.b.record()['state'],'COMPLETE')
        self.assertEqual(self.b.loads,1);self.assertEqual(self.b.registry_count,2)
        self.assertEqual(self.b.events.count('window enter'),2)
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
        for pp,deadline in ((b'wrong',1000),(PP,True),(PP,float('inf')),(PP,10**10000),(PP,99)):
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
            observed=c.activate_first(TRUST,PP,CONTEXTS_PP,deadline=time.monotonic()+430)
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
            self.assertIs(production.installer(TRUST,PP,CONTEXTS_PP),sentinel)
        factory.assert_called_once_with(TRUST,PP,CONTEXTS_PP)
        target=importlib.import_module('qshd_selinux_module_observer')
        with patch.object(target,'production_observer',return_value=sentinel) as factory:
            self.assertIs(production.modules(TRUST,deadline=1000),sentinel)
        factory.assert_called_once_with(TRUST,deadline=1000,mode='pair')
        native=importlib.import_module('qshd_selinux_api');queries=importlib.import_module('qshd_selinux_queries')
        value=Mock();value.status_observation.return_value=sentinel
        with patch.object(native,'SelinuxApi',return_value=value) as api:
            self.assertIs(production.window(),sentinel)
        api.assert_called_once_with();value.status_observation.assert_called_once_with()
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
                        self.b.now=1001
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
            if name=='package exit':self.b.now=1001
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
                    elif returned[0] and event=='line' and frame.f_code is c._Coordinator._publish.__code__:
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


class PristinePendingBridgeTests(unittest.TestCase):
    installed=CoordinatorTests.installed
    def setUp(self):
        CoordinatorTests.setUp(self)
        self.configure()
    def configure(self):
        self.reference_path=self.installed()
        self.prior=replace(c._pending(self.b.expected_trust,'provider-fresh'),operation_id='1'*32)
        with package.PackageState(self.b.common,uid=os.getuid(),anchor=self.b.root).initialize():
            with self.b.slot_object().writer() as writer:
                initial=writer.capture_current();writer.begin_pending(c._json(asdict(self.prior)),initial)
        self.b.events.clear()
        self.b.package_operation=lambda:self.b.track('package',package.PackageState(self.b.common,uid=os.getuid(),anchor=self.b.root).operation())
        self.b.package=Mock(side_effect=AssertionError('initializer forbidden'))
    @contextmanager
    def fresh(self):
        with tempfile.TemporaryDirectory() as root:
            self.b=Bindings(Path(root));self.configure();yield
    def run_bridge(self,deadline=1000):
        return c._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_pristine_pending_first(deadline=deadline)
    def test_pristine_reference_recheck_and_fd_close_precede_complete(self):
        for fault in ('recheck','descriptor-close'):
            with self.subTest(fault=fault),self.fresh():
                require_reference_failure_before_complete(self,self.b,self.run_bridge,fault)

    def test_matching_pending_becomes_new_complete_under_one_existing_package_lease(self):
        with reference_exit_fault(self.b,None) as closed:result=self.run_bridge()
        self.assertEqual(closed,[dict(state='PENDING',package=True,activation=True)])
        self.assertLess(self.b.events.index('references exit'),self.b.events.index('complete replace'))
        self.assertEqual(result.state,'COMPLETE');self.assertNotEqual(result.operation_id,self.prior.operation_id)
        self.assertEqual(result.artifact,self.b.expected_trust);self.assertEqual(self.b.loads,1)
        self.assertEqual(self.b.events.count('package enter'),1);self.b.package.assert_not_called()
        self.assertIn('complete replace',self.b.events);self.assertFalse(self.b.active)
    def test_matching_pending_still_refuses_in_both_original_first_apis(self):
        before=self.b.record()
        self.b.package=lambda:self.b.track('package',package.PackageState(self.b.common,uid=os.getuid(),anchor=self.b.root).initialize())
        for invoke in (lambda:c._Coordinator(self.b,clock=lambda:self.b.now).activate_first(self.b.expected_trust,PP,CONTEXTS_PP,deadline=1000),lambda:c._Coordinator(self.b,clock=lambda:self.b.now).activate_installed_first(deadline=1000)):
            with self.assertRaisesRegex(c.CoordinatorError,'^ACTIVATION_EXISTS$'):invoke()
        self.assertEqual(self.b.record(),before);self.assertEqual(self.b.loads,0)
    def test_all_three_incoming_artifact_fields_must_match_before_replacement(self):
        for changes in ({'provider_version':'different'},{'manifest_sha256':'b'*64},{'core_pp_sha256':'c'*64},{'contexts_pp_sha256':'c'*64}):
            with self.subTest(changes=changes),self.fresh():
                prior=replace(self.prior,artifact=replace(self.prior.artifact,**changes))
                path=self.b.common/'selinux-activation/activation.json';path.write_bytes(c._json(asdict(prior)))
                before=path.read_bytes()
                with self.assertRaisesRegex(c.CoordinatorError,'^PENDING_IDENTITY$'):self.run_bridge()
                self.assertEqual(path.read_bytes(),before);self.assertEqual(self.b.loads,0)
    def test_absent_record_or_complete_is_not_this_bridge(self):
        path=self.b.common/'selinux-activation/activation.json';path.unlink()
        with self.assertRaisesRegex(c.CoordinatorError,'^PENDING_REQUIRED$'):self.run_bridge()
        self.assertFalse(path.exists());self.assertEqual(self.b.loads,0)
        with self.fresh():
            self.run_bridge();before=self.b.record();loads=self.b.loads
            with self.assertRaisesRegex(c.CoordinatorError,'^PENDING_REQUIRED$'):self.run_bridge()
            self.assertEqual(self.b.record(),before);self.assertEqual(self.b.loads,loads)

    def test_generation_collision_never_reuses_old_pending_token(self):
        before=self.b.record()
        with patch.object(c.secrets,'token_hex',return_value=self.prior.operation_id),self.assertRaises(c.CoordinatorError):self.run_bridge()
        self.assertEqual(self.b.record(),before);self.assertEqual(self.b.loads,0)
    def test_missing_partial_or_malformed_prerequisites_never_repair(self):
        for defect in ('package-lock','activation-lock','bad-json','bad-profile','bad-abi','bad-module','unsafe-mode'):
            with self.subTest(defect=defect),self.fresh():
                path=self.b.common/'selinux-activation/activation.json'
                if defect=='package-lock':missing=self.b.common/'selinux-package.lock';missing.unlink()
                elif defect=='activation-lock':missing=self.b.common/'selinux-activation/lock';missing.unlink()
                elif defect=='bad-json':path.write_bytes(b'{')
                elif defect=='unsafe-mode':path.chmod(0o644)
                else:
                    value=self.b.record()
                    if defect=='bad-profile':value['profile']='unsupported'
                    elif defect=='bad-abi':value['abi']=True
                    else:value['modules']['core']['priority']=100
                    path.write_text(json.dumps(value))
                before=path.read_bytes();mode=path.stat().st_mode
                with self.assertRaises(c.CoordinatorError):self.run_bridge()
                self.assertEqual(path.read_bytes(),before);self.assertEqual(path.stat().st_mode,mode)
                if defect in ('package-lock','activation-lock'):self.assertFalse(missing.exists())
                self.assertEqual(self.b.loads,0);self.b.package.assert_not_called()
    def test_real_nonpristine_contexts_refuse_without_recovery(self):
        for defect in ('journal','symlink-journal','receipts','administrator-row','marker','foreign-stage'):
            with self.subTest(defect=defect),self.fresh():
                engine=self.b.transaction_object()
                with engine.writer() as writer:
                    if defect=='receipts':writer.reconcile(self.b.ids)
                state=self.b.common/'selinux-contexts'
                if defect=='journal':(state/'journal').write_bytes(b'not JSON')
                elif defect=='symlink-journal':
                    foreign=self.b.root/'foreign';foreign.write_bytes(b'unchanged foreign');(state/'journal').symlink_to(foreign)
                elif defect=='administrator-row':self.b.target.write_bytes(self.b.original+b'system_r:qshd_t:s0\tuser_r:user_t:s0\n')
                elif defect=='marker':self.b.target.write_bytes(self.b.original+b'# qshd-context-row begin unknown\n')
                elif defect=='foreign-stage':(state/'unknown').write_bytes(b'foreign')
                before=(self.b.target.read_bytes(),self.b.target.stat().st_mode,(state/'receipts').read_bytes())
                journal=(state/'journal').read_bytes() if (state/'journal').exists() else None
                with self.assertRaises(c.CoordinatorError):self.run_bridge()
                self.assertEqual((self.b.target.read_bytes(),self.b.target.stat().st_mode,(state/'receipts').read_bytes()),before)
                if journal is not None:self.assertEqual((state/'journal').read_bytes(),journal)
                self.assertEqual(self.b.loads,0);self.assertEqual(self.b.record()['state'],'PENDING')
                self.assertNotEqual(self.b.record()['operation_id'],self.prior.operation_id)
    def test_existing_module_real_firstinstaller_is_list_only_after_generation_refresh(self):
        from scripts.tests import test_selinux_module_install as fixture
        import qshd_selinux_module_install as install
        for listing in (b'400 qshd pp\n',b'100 qshd cil disabled\n',b'999 qshd pp\n'):
            with self.subTest(listing=listing),self.fresh():
                store=fixture.InstallTests();store.setUp()
                try:
                    store.listing=listing
                    self.b.installer=lambda trust,pp,contexts:install.FirstInstall(trust,pp,contexts,_root=store.root,_uid=os.getuid(),_owner=store,_clock=lambda:100)
                    with self.assertRaises(c.CoordinatorError):self.run_bridge()
                    self.assertEqual(len(store.calls),1);self.assertEqual(store.calls[0][0][-1],'-lfull')
                    self.assertEqual(list((store.root/'run').iterdir()),[])
                    self.assertNotEqual(self.b.record()['operation_id'],self.prior.operation_id)
                    self.assertEqual(self.b.target.read_bytes(),self.b.original)
                finally:store.doCleanups()
    def test_prepublication_failures_and_reference_drift_never_complete(self):
        for failure in ('load','window exit','registry recheck','module exit','late load','reference drift'):
            with self.subTest(failure=failure),self.fresh():
                if failure=='reference drift':
                    point=self.b.point
                    def drift(name):
                        point(name)
                        if name=='window exit':self.reference_path.write_bytes(self.reference_path.read_bytes()+b' ')
                    self.b.point=drift
                else:self.b.failure=failure
                with self.assertRaises(c.CoordinatorError):self.run_bridge()
                self.assertEqual(self.b.record()['state'],'PENDING')
    def test_real_completion_sync_uncertainty_survives_every_outer_exit(self):
        for later in ('contexts exit','activation exit','package exit'):
            with self.subTest(later=later),self.fresh():
                self.b.failure=later;native_sync=os.fsync;failed=[]
                def fsync(fd):
                    directory=self.b.common/'selinux-activation'
                    if self.b.record()['state']=='COMPLETE' and stat.S_ISDIR(os.fstat(fd).st_mode) and os.fstat(fd).st_ino==directory.stat().st_ino:
                        failed.append(True);raise OSError('controlled real directory sync')
                    return native_sync(fd)
                with patch.object(slot.os,'fsync',side_effect=fsync),self.assertRaises(slot.OutcomeUncertain):self.run_bridge()
                self.assertEqual(failed,[True]);self.assertEqual(self.b.record()['state'],'COMPLETE')
    def test_trace_return_boundary_and_package_unwind_stay_uncertain(self):
        class Interruption(BaseException):pass
        for later in (None,'package exit'):
            with self.subTest(later=later),self.fresh():
                self.b.failure=later;returned=[False];interruptions=[];previous=sys.gettrace()
                def trace(frame,event,arg):
                    if event=='return' and frame.f_code is slot._Writer.publish_complete.__code__:returned[0]=True
                    elif returned[0] and event=='line' and frame.f_code is c._Coordinator._publish.__code__:
                        returned[0]=False;interruptions.append(True);raise Interruption()
                    return trace
                try:
                    sys.settrace(trace)
                    with self.assertRaises(slot.OutcomeUncertain):self.run_bridge()
                finally:sys.settrace(previous)
                self.assertEqual(interruptions,[True]);self.assertIs(sys.gettrace(),previous)
                self.assertEqual(self.b.record()['state'],'COMPLETE')
    def test_known_precompletion_slot_error_stays_ordinary_even_with_later_exit(self):
        for later in (None,'package exit'):
            with self.subTest(later=later),self.fresh():
                self.b.failure=later;hook=self.b.slot_hook
                def refuse(event):
                    hook(event)
                    if event=='before_slot_rename' and self.b.loads:raise slot.SlotError('CONTROLLED_PRE_REPLACE')
                self.b.slot_hook=refuse
                with self.assertRaises(c.CoordinatorError):self.run_bridge()
                self.assertEqual(self.b.record()['state'],'PENDING');self.assertEqual(self.b.loads,1)
    def test_public_factory_operation_deadline_and_single_use(self):
        production=c._Production();value=Mock();sentinel=object();value.operation.return_value=sentinel
        with patch.object(package,'production',return_value=value) as factory:self.assertIs(production.package_operation(),sentinel)
        factory.assert_called_once_with();value.operation.assert_called_once_with();value.initialize.assert_not_called()
        for deadline in (True,float('inf'),100,150):
            with self.assertRaises(c.CoordinatorError):self.run_bridge(deadline)
        self.assertNotIn('package enter',self.b.events)
        self.b.now=time.monotonic()
        with patch.object(c,'_Production',return_value=self.b):result=c.activate_installed_pristine_pending_first(deadline=self.b.now+430)
        self.assertEqual(result.state,'COMPLETE')
        with self.fresh():
            coordinator=c._Coordinator(self.b,clock=lambda:self.b.now)
            coordinator.activate_installed_pristine_pending_first(deadline=1000)
            with self.assertRaisesRegex(c.CoordinatorError,'^COORDINATOR_USED$'):coordinator.activate_installed_pristine_pending_first(deadline=1000)

if __name__=='__main__':unittest.main()


class ProviderUpgradeTests(unittest.TestCase):
    def setUp(self):
        from scripts.tests.test_selinux_consumer_activation import Bindings as OwnedBindings
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.b=OwnedBindings(Path(self.temp.name));self.old=self.b.trust
        self.old_complete=self.b.record();self.calls=[]

    def coordinator(self):return c._Coordinator(self.b,clock=lambda:self.b.now)

    def incoming(self,*,core=True,contexts=True):
        manifest=json.loads((Path(__file__).resolve().parents[2]/'packaging/selinux/artifact.json').read_bytes())
        manifest['policy_version']='0.3.0'
        self.incoming_manifest=c._json(manifest)+b'\n'
        return TrustedArtifact('0.3.0',hashlib.sha256(self.incoming_manifest).hexdigest(),
            hashlib.sha256(b'incoming core' if core else __import__('scripts.tests.test_selinux_consumer_activation',fromlist=['PP']).PP).hexdigest(),
            hashlib.sha256(b'incoming contexts' if contexts else __import__('scripts.tests.test_selinux_consumer_activation',fromlist=['CONTEXTS_PP']).CONTEXTS_PP).hexdigest())

    def replace_references(self,incoming):
        from scripts.tests.test_selinux_consumer_activation import PP as old_core, CONTEXTS_PP as old_contexts
        import assemble_payload as builder
        root=self.b.root;source=Path(__file__).resolve().parents[2]/'packaging/selinux'
        incoming_dir=root/'incoming';incoming_dir.mkdir()
        core=incoming_dir/'qshd.pp';contexts=incoming_dir/'qshd_contexts.pp'
        core.write_bytes(b'incoming core' if incoming.core_pp_sha256!=self.old.core_pp_sha256 else old_core)
        contexts.write_bytes(b'incoming contexts' if incoming.contexts_pp_sha256!=self.old.contexts_pp_sha256 else old_contexts)
        manifest=incoming_dir/'artifact.json'
        manifest.write_bytes(self.incoming_manifest if incoming!=self.old else (source/'artifact.json').read_bytes())
        pam=source.parent/'pam.d/qshd.fedora-selinux'
        expected={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in builder.MODULES}
        expected.update({path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (core,contexts,manifest,pam)})
        provider=root/'incoming-provider';builder.assemble_payload(source,core,contexts,manifest,pam,expected,provider,1000000000)
        self.b.provider=provider;self.b.trust=incoming
        binding=self.b
        outer=self
        def reloader(owned,target,core,contexts):
            outer.assertEqual(owned,outer.old);outer.assertEqual(target,incoming)
            outer.assertEqual(hashlib.sha256(core).hexdigest(),incoming.core_pp_sha256)
            outer.assertEqual(hashlib.sha256(contexts).hexdigest(),incoming.contexts_pp_sha256)
            class Reload:
                def reload(inner,*,deadline,old_check):
                    outer.assertEqual(deadline,1000)
                    with binding.window() as status:old_check(status)
                    outer.assertNotIn('window',binding.active)
                    outer.calls.append((owned,target));binding.loads+=1
                    return __import__('types').SimpleNamespace(artifact=target,core_pp_sha256=target.core_pp_sha256,contexts_pp_sha256=target.contexts_pp_sha256)
            return Reload()
        self.b.reloader=reloader

    def test_owned_provider_reference_recheck_and_fd_close_precede_complete(self):
        for fault in ('recheck','descriptor-close'):
            with self.subTest(fault=fault):
                if self.calls:self.setUp()
                incoming=self.incoming();self.coordinator().invalidate_installed_provider_upgrade(incoming,deadline=1000)
                self.replace_references(incoming)
                require_reference_failure_before_complete(self,self.b,
                    lambda:self.coordinator().activate_installed_owned_provider(deadline=1000),fault)

    def test_independent_a_to_b_both_or_single_component_and_same_pair_reload(self):
        for components in ((True,True),(True,False),(False,True),(False,False)):
            with self.subTest(components=components):
                if self.calls:self.setUp()
                incoming=self.incoming(core=components[0],contexts=components[1]) if any(components) else self.old
                pending=self.coordinator().invalidate_installed_provider_upgrade(incoming,deadline=1000)
                self.assertEqual(pending.intent,'provider-refresh');self.assertEqual(pending.basis.artifact,self.old)
                self.assertEqual(pending.basis.completion,self.old_complete.completion)
                self.replace_references(incoming)
                with reference_exit_fault(self.b,None) as closed:
                    complete=self.coordinator().activate_installed_owned_provider(deadline=1000)
                self.assertEqual(closed,[dict(state='PENDING',package=True,activation=True)])
                self.assertLess(max(i for i,event in enumerate(self.b.events) if event=='references exit'),self.b.events.index('publish COMPLETE'))
                self.assertEqual(complete.artifact,incoming);self.assertIsNone(complete.basis)
                self.assertEqual(complete.state,'COMPLETE');self.assertEqual(self.calls,[(self.old,incoming)])
                self.assertEqual(self.b.record(),complete)

    def test_wrong_intent_or_old_binding_refuses_before_reload(self):
        incoming=self.incoming();pending=self.coordinator().invalidate_installed_provider_upgrade(incoming,deadline=1000)
        self.replace_references(incoming)
        path=self.b.common/'selinux-activation/activation.json'
        for changed in (replace(pending,intent='consumer-install'),replace(pending,basis=c.HistoricalBasis(self.old,
                replace(pending.basis.completion,contexts=c.ContextBinding('1'*64,'2'*64))))):
            path.write_bytes(c._json(asdict(changed)))
            with self.assertRaises(c.CoordinatorError):self.coordinator().activate_installed_owned_provider(deadline=1000)
            self.assertEqual(self.calls,[])

    def test_owned_pre_readback_requires_exact_protected_pending_bytes(self):
        incoming=self.incoming();original=slot._Writer.begin_pending
        def changed(writer,*args):
            token=original(writer,*args)
            path=self.b.common/'selinux-activation/activation.json'
            path.write_bytes(path.read_bytes()+b' ')
            return token
        with patch.object(slot._Writer,'begin_pending',changed),self.assertRaises(slot.OutcomeUncertain):
            self.coordinator().invalidate_installed_provider_upgrade(incoming,deadline=1000)
        self.assertEqual(self.b.record().state,'PENDING');self.assertEqual(self.b.loads,0)

    def test_final_b_failure_keeps_pending_without_adopting_loaded_pair(self):
        incoming=self.incoming();self.coordinator().invalidate_installed_provider_upgrade(incoming,deadline=1000)
        self.replace_references(incoming);self.b.hll_override='1'*64
        with self.assertRaises(c.CoordinatorError):self.coordinator().activate_installed_owned_provider(deadline=1000)
        self.assertEqual(len(self.calls),1);self.assertEqual(self.b.record().state,'PENDING')
