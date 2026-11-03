"""Owned temporary state; policy/native/tool boundaries are explicit test seams."""
from contextlib import contextmanager
from dataclasses import asdict, replace
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
import qshd_selinux_activation as model
import qshd_selinux_activation_state as slot
import qshd_selinux_package_state as package
import qshd_selinux_transaction as transaction
import qshd_selinux_reference_loader as references
import qshd_selinux_files as files
from qshd_selinux_registry import RegistryObservation
from qshd_selinux_modules import HllIdentity
# This is the missing PR B implementation, not a replacement production seam.
import qshd_selinux_consumer_activation as consumer

PP=b'explicit synthetic consumer policy; never loaded'
ROOT=Path(__file__).resolve().parents[2]


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


class Bindings:
    def __init__(self,root):
        self.root=root;self.common=root/'var/lib/qshd';self.target=root/'context'
        self.target.write_bytes(b'system_r:sshd_t:s0 user_r:user_t:s0\n');self.target.chmod(0o640)
        self.identities={'/context':dict(path='/context',source_type='sshd_t',original_package='fixture')}
        self.routing=canonical(self.identities)
        self.events=[];self.active=set();self.failure=None;self.now=100.0;self.loads=0;self.phase_active=False
        self.registry_snapshot=b'fixed directory'
        self.expected_pam=(ROOT/'packaging/pam.d/qshd.fedora-selinux').read_bytes()
        for name in ('usr/bin','etc/pam.d','var/lib','var/log','run'):(root/name).mkdir(parents=True,exist_ok=True)
        for path in root.rglob('*'):
            if path.is_dir():path.chmod(0o755)
        spec=importlib.util.spec_from_file_location('consumer_fixture_builder',ROOT/'packaging/selinux/assemble_payload.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        source=ROOT/'packaging/selinux';pp=root/'qshd.pp';pp.write_bytes(PP)
        artifact=source/'artifact.json';pam=ROOT/'packaging/pam.d/qshd.fedora-selinux'
        expected={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in builder.MODULES}
        expected.update({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (pp,artifact,pam)})
        self.provider=root/'provider';builder.assemble_payload(source,pp,artifact,pam,expected,self.provider,1000000000)
        self.trust=model.TrustedArtifact('0.2.0',expected['artifact.json'],expected['qshd.pp'])
        # Fixture-owned state setup, never a production phase or policy claim.
        with self.package_object().initialize():
            with self.transaction_object().writer() as writer:writer.reconcile(self.identities)
            with self.slot_object().writer() as writer:
                pending=self.record_value('PENDING','a'*32)
                token=writer.begin_pending(canonical(asdict(pending)),writer.capture_current())
                with self.transaction_object().inspection(self.identities) as reader:
                    view=reader.capture();reader.recheck(view)
                binding=model.ContextBinding(view.registry_sha256,view.receipts_sha256)
                complete=replace(pending,state='COMPLETE',completion=model.Completion('normal-install-reload-v1',self.trust.pp_sha256,binding))
                writer.publish_complete(canonical(asdict(complete)),token,trusted_artifact=self.trust,trusted_context_binding=binding)
        self.events=[];self.phase_active=True

    def point(self,name):
        self.events.append(name)
        if self.failure==name:raise RuntimeError('controlled '+name)

    def preconditions(self):self.point('preconditions')
    def guard(self,deadline):self.point('guard')
    def package_object(self):return package.PackageState(self.common,uid=os.getuid(),anchor=self.root)
    def slot_object(self):return slot.ActivationSlot(self.common/'selinux-activation',uid=os.getuid(),anchor=self.root,hook=self.slot_hook)
    def transaction_object(self):return transaction.Transaction(self.common/'selinux-contexts',{'/context':self.target},uid=os.getuid(),anchor=self.root)
    def record_value(self,state,operation):return model.Activation(1,state,operation,'fedora44-targeted-v1',1,1,self.trust,model.ModuleIdentity('qshd',400,'targeted','pp'),None)
    def record(self):return model.parse_activation((self.common/'selinux-activation/activation.json').read_bytes())

    def busy(self,path):
        fd=os.open(path,os.O_RDONLY)
        try:
            try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:return True
            return False
        finally:os.close(fd)

    def assert_locked(self):
        assert all(self.busy(self.common/name) for name in ('selinux-package.lock','selinux-activation/lock','selinux-contexts/lock'))

    @contextmanager
    def track(self,name,scope):
        self.point(name+' enter')
        try:
            with scope as value:
                self.active.add(name)
                try:yield value
                finally:self.active.remove(name)
        finally:self.point(name+' exit')

    def package(self):return self.track('package',self.package_object().operation())
    def references(self):return self.track('references',references._testing_references(self.provider))
    def activation(self):return self.track('activation',self.slot_object().writer())
    def consumer_paths(self,expected_pam,*,fresh):
        return self.track('consumer',consumer._ConsumerPaths(expected_pam,_root=self.root,_uid=os.getuid()).inspection(fresh=fresh))

    def policy_context(self,trust):
        self.point('policy child');assert trust==self.trust and self.active=={'package','references'}
        assert self.busy(self.common/'selinux-package.lock')
        assert not self.busy(self.common/'selinux-activation/lock')
        with self.transaction_object().inspection(self.identities) as reader:
            value=reader.capture();reader.recheck(value)
        return SimpleNamespace(profile='fedora44-targeted-v1',contexts=model.ContextBinding(value.registry_sha256,value.receipts_sha256))

    def context_inspection(self,paths,identities):
        assert paths==['/context'] and identities==self.identities
        assert self.busy(self.common/'selinux-package.lock') and self.busy(self.common/'selinux-activation/lock')
        return self.track('preflight',self.transaction_object().inspection(identities))

    @contextmanager
    def contexts(self,paths):
        assert paths==['/context']
        assert not self.busy(self.common/'selinux-contexts/lock')
        self.point('context writer acquisition')
        with self.track('contexts',self.transaction_object().writer()) as writer:
            with patch.object(writer,'reconcile',side_effect=AssertionError('post must not mutate contexts')),patch.object(writer,'require_pristine',side_effect=AssertionError('post must not adopt pristine state')):
                yield writer

    @contextmanager
    def registry(self):
        binding=self
        class Registry:
            def routing(self):binding.point('routing');return binding.routing
            seen=None
            def capture(self):
                binding.point('registry capture')
                self.seen=RegistryObservation(binding.routing,hashlib.sha256(binding.routing).hexdigest(),(('/context',b'fixed candidate'),),(binding.registry_snapshot,),(('/context','fixture'),),(('fixture',('/context',)),))
                return self.seen
            def recheck(self,value):
                assert value is self.seen,'registry token from another lease'
                binding.point('registry recheck')
        with self.track('registry',_value_scope(Registry())) as value:yield value

    def reloader(self,trust,pp):
        binding=self
        class Reload:
            def reload(self,*,deadline):
                binding.assert_locked();assert 'registry' not in binding.active
                assert trust==binding.trust and pp==PP and binding.record().state=='PENDING'
                binding.point('reload');binding.loads+=1
                return SimpleNamespace(artifact=trust,pp_sha256=trust.pp_sha256)
        return Reload()

    @contextmanager
    def modules(self,trust):
        binding=self;assert trust==self.trust
        class Module:
            def capture(self):binding.point('module capture');return SimpleNamespace(hll=HllIdentity(len(PP),getattr(binding,'hll_override',trust.pp_sha256)))
            def recheck(self,value):binding.point('module recheck')
        with self.track('module',_value_scope(Module())) as value:yield value

    @contextmanager
    def window(self):
        self.assert_locked()
        with self.track('window',_value_scope(True)) as value:yield value

    def files(self,expected_pam):
        binding=self
        class Api:
            @contextmanager
            def file_defaults(self):yield self
            def lookup(self,path,kind):return getattr(binding,'default_override',None) or next(row[2] for row in files._PATHS if row[0]==path)
            def file_context(self,fd):
                physical=Path(os.readlink('/proc/self/fd/'+str(fd)));logical='/'+str(physical.relative_to(binding.root))
                return self.lookup(logical,None)
        assert expected_pam==self.expected_pam
        return self.track('files',files._testing(expected_pam,self.root,Api(),os.getuid()).inspection())

    def slot_hook(self,event):
        if not self.phase_active:return  # Trusted temporary setup is not a phase.
        if event=='slot_rename':
            self.point('publish '+self.record().state)
            if self.record().state=='COMPLETE':
                self.assert_locked();assert not ({'window','module','registry','files'}&self.active)

    def installed_files(self):
        for path,data,mode in [('usr/bin/qshd',b'public inert executable',0o755),('etc/pam.d/qshd',self.expected_pam,0o644)]:
            p=self.root/path;p.write_bytes(data);p.chmod(mode)
        (self.root/'run/qshd').mkdir(mode=0o700)

    def matching_pending(self):
        with self.package_object().operation():
            with self.slot_object().writer() as writer:
                value=self.record_value('PENDING','b'*32)
                writer.begin_pending(canonical(asdict(value)),writer.capture_current())
        self.events=[];return value


@contextmanager
def _value_scope(value):yield value


class ConsumerTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.b=Bindings(Path(self.temp.name));self.fd_before=set(os.listdir('/proc/self/fd'))
        self.addCleanup(lambda:self.assertEqual(set(os.listdir('/proc/self/fd')),self.fd_before))

    def coordinator(self):return consumer._Coordinator(self.b,clock=lambda:self.b.now)

    def test_fresh_pre_real_state_one_lease_child_before_writer(self):
        initial=self.b.record();result=self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=1000)
        self.assertEqual(result.state,'PENDING');self.assertNotEqual(result.operation_id,initial.operation_id)
        self.assertEqual(self.b.events.count('package enter'),1)
        self.assertLess(self.b.events.index('policy child'),self.b.events.index('activation enter'))
        self.assertEqual(self.b.loads,0);self.assertFalse(self.b.active)
        self.assertFalse(self.b.busy(self.b.common/'selinux-package.lock'))
        self.assertFalse(self.b.busy(self.b.common/'selinux-activation/lock'))

    def test_installed_pre_canonical_pam_is_not_rewritten(self):
        self.b.installed_files();pam=self.b.root/'etc/pam.d/qshd';before=(pam.read_bytes(),pam.stat().st_mtime_ns,pam.stat().st_ino)
        result=self.coordinator().invalidate_installed_consumer_pre(fresh=False,deadline=1000)
        self.assertEqual(result.state,'PENDING');self.assertEqual((pam.read_bytes(),pam.stat().st_mtime_ns,pam.stat().st_ino),before)

    def test_pre_unsafe_modes_and_custom_pam_preserve_complete(self):
        self.b.installed_files();pam=self.b.root/'etc/pam.d/qshd';pam.write_bytes(b'custom unsupported PAM\n')
        before=(self.b.common/'selinux-activation/activation.json').read_bytes()
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().invalidate_installed_consumer_pre(fresh=False,deadline=1000)
        self.assertEqual((self.b.common/'selinux-activation/activation.json').read_bytes(),before)
        self.assertEqual(pam.read_bytes(),b'custom unsupported PAM\n')
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().invalidate_installed_consumer_pre(fresh=1,deadline=1000)

    def test_owned_post_new_generation_and_complete_last_without_context_mutation(self):
        self.b.installed_files();initial=self.b.matching_pending();target=self.b.target.read_bytes()
        result=self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertEqual(result.state,'COMPLETE');self.assertNotEqual(result.operation_id,initial.operation_id)
        self.assertEqual(self.b.loads,1);self.assertEqual(self.b.target.read_bytes(),target)
        self.assertEqual(self.b.events.count('package enter'),1)
        self.assertLess(self.b.events.index('publish PENDING'),self.b.events.index('reload'))
        self.assertLess(self.b.events.index('window exit'),self.b.events.index('publish COMPLETE'))
        self.assertFalse(self.b.active)

    def test_post_reload_failure_retains_pending_and_owned_context(self):
        self.b.installed_files();self.b.matching_pending();self.b.failure='reload';target=self.b.target.read_bytes()
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertEqual(self.b.record().state,'PENDING');self.assertEqual(self.b.target.read_bytes(),target)
        self.assertNotIn('publish COMPLETE',self.b.events)


    def test_fresh_existing_binary_or_pam_and_broken_links_refuse(self):
        before=(self.b.common/'selinux-activation/activation.json').read_bytes()
        for name,symlink in [('usr/bin/qshd',False),('etc/pam.d/qshd',False),('usr/bin/qshd',True),('etc/pam.d/qshd',True)]:
            path=self.b.root/name
            if symlink:path.symlink_to(self.b.root/'missing')
            else:path.write_bytes(b'existing consumer')
            try:
                with self.subTest(path=name,symlink=symlink),self.assertRaises(consumer.CoordinatorError):
                    self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=1000)
                self.assertEqual((self.b.common/'selinux-activation/activation.json').read_bytes(),before)
                self.assertEqual(self.b.loads,0)
            finally:path.unlink()

    def test_installed_missing_symlink_hardlink_or_writable_pam_refuses(self):
        self.b.installed_files();pam=self.b.root/'etc/pam.d/qshd';other=self.b.root/'public-pam'
        other.write_bytes(self.b.expected_pam);other.chmod(0o644)
        before=(self.b.common/'selinux-activation/activation.json').read_bytes()
        for mode in ('missing','symlink','hardlink','writable','fifo','oversize'):
            pam.unlink()
            if mode=='symlink':pam.symlink_to(other)
            elif mode=='hardlink':os.link(other,pam)
            elif mode=='writable':pam.write_bytes(self.b.expected_pam);pam.chmod(0o666)
            elif mode=='fifo':os.mkfifo(pam,0o600)
            elif mode=='oversize':pam.write_bytes(b'x'*65537);pam.chmod(0o644)
            try:
                with self.subTest(mode=mode),self.assertRaises(consumer.CoordinatorError):
                    self.coordinator().invalidate_installed_consumer_pre(fresh=False,deadline=1000)
                self.assertEqual((self.b.common/'selinux-activation/activation.json').read_bytes(),before)
            finally:
                if pam.exists() or pam.is_symlink():pam.unlink()
                pam.write_bytes(self.b.expected_pam);pam.chmod(0o644)

    def test_post_complete_absent_mismatch_and_journal_never_load(self):
        self.b.installed_files();path=self.b.common/'selinux-activation/activation.json';complete=path.read_bytes()
        for mode in ('complete','absent','mismatch','journal'):
            path.write_bytes(complete);path.chmod(0o600)
            journal=self.b.common/'selinux-contexts/journal'
            if mode=='absent':path.unlink()
            elif mode in ('mismatch','journal'):
                record=self.b.matching_pending()
                if mode=='mismatch':path.write_bytes(canonical(asdict(replace(record,artifact=model.TrustedArtifact('other','a'*64,'b'*64)))))
                else:journal.write_bytes(b'unknown journal must stay untouched');journal.chmod(0o600)
            with self.subTest(mode=mode),self.assertRaises(consumer.CoordinatorError):
                self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
            self.assertEqual(self.b.loads,0)
            if journal.exists():
                self.assertEqual(journal.read_bytes(),b'unknown journal must stay untouched');journal.unlink()

    def test_second_guard_and_reference_drift_prevent_pre_publication(self):
        before=(self.b.common/'selinux-activation/activation.json').read_bytes();guards=[]
        def guard(deadline):
            guards.append(deadline)
            if len(guards)==2:raise RuntimeError('controlled final guard refusal')
        self.b.guard=guard
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=1000)
        self.assertEqual((self.b.common/'selinux-activation/activation.json').read_bytes(),before)
        self.b.guard=lambda deadline:None;point=self.b.point
        def drift(name):
            point(name)
            if name=='policy child':
                path=self.b.provider/'usr/share/qshd-selinux/reference.json';path.write_bytes(path.read_bytes()+b' ')
        self.b.point=drift
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=1000)
        self.assertEqual((self.b.common/'selinux-activation/activation.json').read_bytes(),before)

    def test_post_completion_return_interruption_survives_later_exit(self):
        self.b.installed_files();self.b.matching_pending();original=slot._Writer.publish_complete
        def after_real_return(writer,*args,**kwargs):
            original(writer,*args,**kwargs)
            raise KeyboardInterrupt('controlled after actual COMPLETE return')
        self.b.failure='references exit'
        with patch.object(slot._Writer,'publish_complete',after_real_return),self.assertRaises(slot.OutcomeUncertain):
            self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertEqual(self.b.record().state,'COMPLETE')

    def test_post_missing_context_state_never_bootstraps(self):
        import shutil
        self.b.installed_files();self.b.matching_pending()
        state=self.b.common/'selinux-contexts';shutil.rmtree(state)
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertFalse(state.exists());self.assertEqual(self.b.loads,0)


    def inventory(self):
        import stat
        result={}
        for path in [self.b.target]+sorted(self.b.common.rglob('*')):
            info=path.lstat();value=(info.st_mode,info.st_uid,info.st_gid,info.st_ino,info.st_mtime_ns,info.st_ctime_ns)
            if stat.S_ISREG(info.st_mode):value+=(path.read_bytes(),)
            elif stat.S_ISLNK(info.st_mode):value+=(os.readlink(path),)
            result[str(path.relative_to(self.b.root))]=value
        return result

    def unowned_current(self,administrator):
        import qshd_selinux_contexts as pure
        path=self.b.common/'selinux-contexts/receipts';old=json.loads(path.read_bytes())['/context']
        source=pure.plan_remove(self.b.target.read_bytes(),old)[0]
        content=source+b'system_r:qshd_t:s0 user_r:user_t:s0\n'
        _,receipt=pure.plan_reconcile(content,None,self.b.identities['/context'])
        self.assertEqual(receipt['owner'],'administrator')
        self.b.target.write_bytes(content)
        path.write_bytes(canonical({'/context':receipt} if administrator else {}))
        # Prove why capture alone is insufficient for this owned-only API.
        with self.b.transaction_object().inspection(self.b.identities) as reader:
            observed=reader.capture();reader.recheck(observed)

    def test_readonly_admission_all_missing_partial_and_unowned_states_create_nothing(self):
        import shutil
        modes=('missing-state','missing-lock','missing-receipts','partial','malformed',
               'missing-keys','extra-keys','administrator','unowned-current','source-drift',
               'journal-file','journal-directory','journal-symlink')
        for mode in modes:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.installed_files();self.b.matching_pending()
                state=self.b.common/'selinux-contexts';receipt=state/'receipts'
                if mode=='missing-state':shutil.rmtree(state)
                elif mode=='missing-lock':(state/'lock').unlink()
                elif mode=='missing-receipts':receipt.unlink()
                elif mode=='partial':shutil.rmtree(state);state.mkdir(mode=0o700)
                elif mode=='malformed':receipt.write_bytes(b'{malformed')
                elif mode=='missing-keys':receipt.write_bytes(b'{}')
                elif mode=='extra-keys':
                    value=json.loads(receipt.read_bytes());value['/foreign']=value['/context'];receipt.write_bytes(canonical(value))
                elif mode in ('administrator','unowned-current'):self.unowned_current(mode=='administrator')
                elif mode=='source-drift':self.b.target.write_bytes(self.b.target.read_bytes().replace(b'user_r:user_t',b'staff_r:staff_t'))
                elif mode=='journal-file':(state/'journal').write_bytes(b'unknown journal')
                elif mode=='journal-directory':(state/'journal').mkdir()
                else:(state/'journal').symlink_to(self.b.root/'missing-journal')
                before=self.inventory()
                with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
                self.assertEqual(self.inventory(),before)
                self.assertNotIn('context writer acquisition',self.b.events)
                self.assertNotIn('publish PENDING',self.b.events);self.assertEqual(self.b.loads,0)

    def test_preflight_normal_exit_is_required_before_context_writer(self):
        for failure in ('registry capture','registry recheck','preflight exit','window exit'):
            with self.subTest(failure=failure),tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.installed_files();self.b.matching_pending()
                before=self.inventory();self.b.failure=failure
                with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
                self.assertNotIn('context writer acquisition',self.b.events);self.assertEqual(self.b.loads,0)
                self.assertEqual(self.inventory(),before);self.assertFalse(self.b.active)
                self.assertFalse(self.b.busy(self.b.common/'selinux-contexts/lock'))

    def test_borrowed_full_snapshots_not_just_content_hashes_must_equal_preflight(self):
        for mode in ('target-metadata','registry-metadata'):
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.installed_files();initial=self.b.matching_pending()
                target=self.b.target.read_bytes();point=self.b.point
                def change(name):
                    point(name)
                    if name=='preflight exit':
                        if mode=='target-metadata':self.b.target.chmod(0o600)
                        else:self.b.registry_snapshot=b'changed protected directory snapshot'
                self.b.point=change
                with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
                self.assertIn('context writer acquisition',self.b.events)
                self.assertEqual(self.b.target.read_bytes(),target)
                self.assertEqual(self.b.record(),initial);self.assertEqual(self.b.loads,0)
                self.assertNotIn('publish PENDING',self.b.events)

    def test_borrowed_window_exit_failure_prevents_fresh_pending_and_load(self):
        self.b.installed_files();initial=self.b.matching_pending();point=self.b.point;windows=[]
        def fail(name):
            point(name)
            if name=='window exit':
                windows.append(name)
                if len(windows)==2:raise RuntimeError('controlled borrowed window exit')
        self.b.point=fail
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertEqual(len(windows),2);self.assertEqual(self.b.record(),initial)
        self.assertEqual(self.b.loads,0);self.assertFalse(self.b.active)

    def test_actual_complete_fsync_failure_plus_later_exit_is_uncertain(self):
        self.b.installed_files();self.b.matching_pending();point=self.b.point;armed=[];native=os.fsync
        def arm(name):
            point(name)
            if name=='publish COMPLETE':armed.append(True)
        def sync(fd):
            if armed:raise OSError('controlled actual directory sync')
            return native(fd)
        self.b.point=arm;self.b.failure='references exit'
        with patch.object(os,'fsync',sync),self.assertRaises(slot.OutcomeUncertain):
            self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertTrue(armed);self.assertEqual(self.b.record().state,'COMPLETE')

    def test_deadline_and_known_precomplete_slot_error_do_not_publish_complete(self):
        self.b.installed_files();self.b.matching_pending()
        with patch.object(slot._Writer,'publish_complete',side_effect=slot.SlotError('controlled before replacement')),self.assertRaises(consumer.CoordinatorError):
            self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertEqual(self.b.record().state,'PENDING')
        self.b.matching_pending();point=self.b.point
        def late(name):
            point(name)
            if name=='preflight exit':self.b.now=280
        self.b.point=late
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertNotIn('context writer acquisition',self.b.events)

    def test_post_observes_private_metadata_without_reading_or_modifying_contents(self):
        self.b.installed_files();self.b.matching_pending()
        for name in ('etc/qshd','var/log/qshd'):(self.b.root/name).mkdir(mode=0o700)
        private=[]
        for name,data,mode in [('etc/qshd/host_key',b'x'*64,0o400),('var/log/qshd/qshd.log',b'synthetic private log',0o600)]:
            path=self.b.root/name;path.write_bytes(data);path.chmod(mode);private.append((path,data,path.stat().st_mtime_ns,path.stat().st_ino))
        native=os.read
        def read(fd,size):
            path=os.readlink('/proc/self/fd/'+str(fd))
            if path.endswith(('host_key','qshd.log','qshd.log.1')):raise AssertionError('private content read')
            return native(fd,size)
        with patch.object(os,'read',read):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        for path,data,mtime,inode in private:
            self.assertEqual((path.read_bytes(),path.stat().st_mtime_ns,path.stat().st_ino),(data,mtime,inode))


    def test_administrator_current_receipt_is_explicitly_not_owned(self):
        self.b.installed_files();initial=self.b.matching_pending();self.unowned_current(True)
        before=self.inventory()
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertNotIn('context writer acquisition',self.b.events)
        self.assertEqual(self.b.loads,0);self.assertEqual(self.inventory(),before)
        self.assertEqual(self.b.record(),initial)


    def test_mode_deadline_and_single_use_refuse_before_guard(self):
        for value in (None,1,'fresh'):
            item=self.coordinator();self.b.events=[]
            with self.assertRaises(consumer.CoordinatorError):item.invalidate_installed_consumer_pre(fresh=value,deadline=1000)
            self.assertEqual(self.b.events,[])
            with self.assertRaisesRegex(consumer.CoordinatorError,'COORDINATOR_USED'):item.invalidate_installed_consumer_pre(fresh=True,deadline=1000)
        for deadline in (True,float('inf'),99,160):
            self.b.events=[]
            with self.assertRaises(consumer.CoordinatorError):self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=deadline)
            self.assertEqual(self.b.events,[])

    def test_pam_same_bytes_replacement_before_pre_pending_refuses(self):
        self.b.installed_files();before=self.b.record()
        # Replace on the first reference recheck before final guard instead of
        # claiming exclusion against an arbitrary mutation after the last check.
        factory=self.b.references
        @contextmanager
        def refs():
            with factory() as reader:
                original=reader.recheck
                def recheck(value):
                    path=self.b.root/'etc/pam.d/qshd';new=path.with_name('owned-replacement')
                    new.write_bytes(self.b.expected_pam);new.chmod(0o644);new.replace(path)
                    return original(value)
                reader.recheck=recheck
                yield reader
        self.b.references=refs
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().invalidate_installed_consumer_pre(fresh=False,deadline=1000)
        self.assertEqual(self.b.record(),before)

    def test_pre_pending_actual_fsync_failure_and_later_exit_are_uncertain(self):
        point=self.b.point;armed=[];native=os.fsync
        def arm(name):
            point(name)
            if name=='publish PENDING':armed.append(True)
        def sync(fd):
            if armed:raise OSError('controlled PENDING directory sync')
            return native(fd)
        self.b.point=arm;self.b.failure='references exit'
        with patch.object(os,'fsync',sync),self.assertRaises(slot.OutcomeUncertain):
            self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=1000)
        self.assertEqual(self.b.record().state,'PENDING');self.assertTrue(armed);self.assertFalse(self.b.active)

    def test_preflight_releases_lock_before_writer_and_borrowed_views_never_relock(self):
        self.b.installed_files();self.b.matching_pending();native=fcntl.flock;blocking=[]
        def flock(fd,operation):
            path=os.readlink('/proc/self/fd/'+str(fd))
            if path.endswith('/selinux-contexts/lock') and operation==fcntl.LOCK_EX:
                self.assertNotIn('contexts',self.b.active,'borrowed inspection attempted a new blocking flock')
                blocking.append(path)
            return native(fd,operation)
        with patch.object(fcntl,'flock',flock):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
        self.assertEqual(len(blocking),2)
        self.assertLess(self.b.events.index('preflight exit'),self.b.events.index('context writer acquisition'))
        self.assertEqual(self.b.events.count('package enter'),1);self.assertEqual(self.b.events.count('activation enter'),1)
        self.assertEqual(self.b.events.count('window enter'),3)

    def test_postload_observer_and_all_window_finalizers_suppress_complete(self):
        modes=('module recheck','module exit','files exit','post-window','post-registry','default','PAM','HLL','reference')
        for mode in modes:
            with self.subTest(mode=mode),tempfile.TemporaryDirectory() as root:
                self.b=Bindings(Path(root));self.b.installed_files();self.b.matching_pending();point=self.b.point;counts={}
                def fail(name):
                    point(name);counts[name]=counts.get(name,0)+1
                    if mode=='reference' and name=='window exit' and counts[name]==3:
                        path=self.b.provider/'usr/share/qshd-selinux/reference.json';path.write_bytes(path.read_bytes()+b' ')
                    if ((mode in ('module recheck','module exit','files exit') and name==mode)
                            or (mode=='post-window' and name=='window exit' and counts[name]==3)
                            or (mode=='post-registry' and name=='registry exit' and counts[name]==3)):
                        raise RuntimeError('controlled final observer failure')
                self.b.point=fail
                if mode=='default':self.b.default_override='wrong_u:object_r:qshd_exec_t:s0'
                elif mode=='PAM':(self.b.root/'etc/pam.d/qshd').write_bytes(b'unsupported installed PAM')
                elif mode=='HLL':self.b.hll_override='b'*64
                with self.assertRaises(consumer.CoordinatorError):self.coordinator().finalize_installed_owned_pending_consumer(deadline=1000)
                self.assertEqual(self.b.loads,1);self.assertEqual(self.b.record().state,'PENDING')
                self.assertNotIn('publish COMPLETE',self.b.events);self.assertFalse(self.b.active)

    def test_fixed_public_factories_delegate_without_nested_package_or_tool_calls(self):
        import qshd_selinux_observer as observer
        import qshd_selinux_module_install as install
        sentinel=object();production=consumer._Production()
        with patch.object(package,'production',return_value=SimpleNamespace(operation=lambda:sentinel)) as factory:
            self.assertIs(production.package(),sentinel)
        factory.assert_called_once_with()
        with patch.object(observer,'_observe_policy_context',return_value=sentinel) as private,patch.object(observer,'observe_installed_policy_context',side_effect=AssertionError('nested package gate')):
            self.assertIs(production.policy_context(self.b.trust),sentinel)
        private.assert_called_once_with(self.b.trust)
        with patch.object(install,'production_owned_reloader',return_value=sentinel) as owned,patch.object(install,'production_installer',side_effect=AssertionError('first installer used by post')):
            self.assertIs(production.reloader(self.b.trust,PP),sentinel)
        owned.assert_called_once_with(self.b.trust,PP)


    def test_consumer_setup_after_fd_acquisition_closes_routes_without_publication(self):
        original=consumer._ConsumerReader._directory;before=self.inventory()
        def fail(reader,path):
            value=original(reader,path)
            if str(path).endswith('/etc/pam.d'):raise OSError('controlled after directory acquisition')
            return value
        with patch.object(consumer._ConsumerReader,'_directory',fail),self.assertRaises(consumer.CoordinatorError):
            self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=1000)
        self.assertEqual(self.inventory(),before);self.assertNotIn('publish PENDING',self.b.events)
        self.assertFalse(self.b.active)

    def test_consumer_close_after_real_close_cannot_report_pending_success(self):
        native=os.close;failed=[]
        def close(fd):
            path=os.readlink('/proc/self/fd/'+str(fd));native(fd)
            if path.endswith('/etc/pam.d') and not failed:
                failed.append(True);raise OSError('controlled after real route close')
        with patch.object(os,'close',close),self.assertRaises(slot.OutcomeUncertain):
            self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=1000)
        self.assertTrue(failed);self.assertEqual(self.b.record().state,'PENDING');self.assertFalse(self.b.active)

    def test_public_phase_entries_use_only_fixed_production_binding(self):
        with patch.object(consumer,'_Production',return_value=self.b) as factory:
            result=consumer.invalidate_installed_consumer_pre(fresh=True,deadline=time.monotonic()+220)
            self.assertEqual(result.state,'PENDING')
            self.b.installed_files()
            result=consumer.finalize_installed_owned_pending_consumer(deadline=time.monotonic()+220)
            self.assertEqual(result.state,'COMPLETE')
        self.assertEqual(factory.call_count,2)
        self.assertTrue(all(call.args==() and call.kwargs=={} for call in factory.call_args_list))


    def test_slot_change_after_policy_observation_refuses_pre_publication(self):
        before=self.b.record();point=self.b.point;path=self.b.common/'selinux-activation/activation.json'
        changed=replace(before,state='PENDING',completion=None)
        def drift(name):
            point(name)
            if name=='policy child':path.write_bytes(canonical(asdict(changed)))
        self.b.point=drift
        with self.assertRaises(consumer.CoordinatorError):self.coordinator().invalidate_installed_consumer_pre(fresh=True,deadline=1000)
        self.assertEqual(self.b.record(),changed);self.assertNotIn('publish PENDING',self.b.events)
        self.assertEqual(self.b.loads,0)


class OwnedEraseAdmissionTests(unittest.TestCase):
    coordinator=ConsumerTests.coordinator
    inventory=ConsumerTests.inventory
    unowned_current=ConsumerTests.unowned_current

    def setUp(self):
        ConsumerTests.setUp(self)
        for name in ('usr/lib','usr/bin','etc/selinux','var/lib/selinux/targeted/active/modules'):
            (self.b.root/name).mkdir(parents=True,exist_ok=True)
        for name in ('usr/lib','etc/selinux','var/lib/selinux','var/lib/selinux/targeted','var/lib/selinux/targeted/active','var/lib/selinux/targeted/active/modules'):
            (self.b.root/name).chmod(0o755)
        for name,data,mode in [('usr/bin/semodule',b'inert',0o755),('usr/lib/os-release',b'ID=fedora\nVERSION_ID=44\n',0o644),('etc/selinux/semanage.conf',b'# controlled',0o644),('var/lib/selinux/targeted/semanage.read.LOCK',b'',0o600)]:
            p=self.b.root/name;p.write_bytes(data);p.chmod(mode)
        self.module_calls=[];self.module_listing=b'100 base cil\n400 qshd pp\n';self.module_pp=PP;self.module_action=None
        self.b.modules=self.modules

    @contextmanager
    def modules(self,trust):
        import qshd_selinux_module_observer as observer
        from qshd_selinux_process import _Outcome
        outer=self
        class Owner:
            _last=None
            def _run(owner,operation,cwd,*,deadline=None):
                outer.assertIn('window',outer.b.active)
                outer.module_calls.append((operation,deadline))
                owner._last=_Outcome(b'',b'',0,None,True)
                if outer.module_action is not None:outer.module_action(operation,cwd,owner)
                if operation=='list':return outer.module_listing
                path=Path(cwd)/'qshd.pp';path.write_bytes(outer.module_pp);path.chmod(0o600);return b''
        with self.b.track('module',observer.ModuleObserver(trust,_root=self.b.root,_uid=os.getuid(),_runner=lambda *args:None)) as lease:
            lease._owner=Owner();yield lease

    @contextmanager
    def held(self):
        from contextlib import ExitStack
        item=self.coordinator();item._end=340
        with self.b.package(),self.b.references() as refs,self.b.activation() as writer:
            captured=refs.capture();trust=captured.artifact
            with ExitStack() as forbidden:
                for name in ('package','activation','policy_context','contexts','files','consumer_paths','preconditions','guard'):
                    forbidden.enter_context(patch.object(self.b,name,side_effect=AssertionError('nested or unrelated phase call')))
                forbidden.enter_context(patch.object(item,'_start',side_effect=AssertionError('deadline restarted')))
                try:yield item,writer,trust
                finally:refs.recheck(captured)

    def test_complete_and_pending_capture_full_owned_evidence_without_mutation(self):
        from dataclasses import FrozenInstanceError
        for pending in (False,True):
            if pending:self.b.matching_pending()
            self.b.events=[];self.module_calls=[];before=self.inventory()
            with self.held() as (item,writer,trust):
                result=item._admit_owned_erase(writer,trust)
                self.assertIs(result.slot,writer._initial)
                self.assertEqual(result.slot.record.state,'PENDING' if pending else 'COMPLETE')
                self.assertEqual(result.routing,self.b.routing)
                self.assertEqual(result.registry.registry_bytes,result.routing)
                self.assertEqual(result.contexts.registry_bytes,result.routing)
                self.assertEqual(self.b.active,{'package','references','activation'})
                with self.assertRaises(FrozenInstanceError):result.routing=b'changed'
                self.assertIsInstance(result.contexts.target_snapshots,tuple)
                self.assertIsInstance(result.registry.candidates,tuple)
                self.assertFalse(hasattr(result,'identities'))
                identities=json.loads(result.routing);identities.clear();self.assertEqual(result.routing,self.b.routing)
            self.assertEqual(self.module_calls,[('list',330),('extract',330),('list',330),('extract',330)])
            self.assertEqual(self.b.events.count('package enter'),1)
            self.assertEqual(self.b.events.count('activation enter'),1)
            self.assertNotIn('policy child',self.b.events);self.assertEqual(self.b.loads,0)
            self.assertEqual(self.inventory(),before);self.assertFalse(self.b.active)

    def test_returned_exact_slot_is_eligible_only_without_intervening_slot_change(self):
        with self.held() as (item,writer,trust):
            result=item._admit_owned_erase(writer,trust)
            pending=self.b.record_value('PENDING','c'*32)
            token=writer.begin_pending(canonical(asdict(pending)),result.slot)
            self.assertEqual(token.observation.record,pending)
        self.b.events=[]
        with self.held() as (item,writer,trust):
            result=item._admit_owned_erase(writer,trust)
            path=self.b.common/'selinux-activation/activation.json';other=self.b.record_value('PENDING','d'*32)
            path.write_bytes(canonical(asdict(other)))
            with self.assertRaises(slot.SlotError):writer.begin_pending(canonical(asdict(self.b.record_value('PENDING','e'*32))),result.slot)
            self.assertEqual(self.b.record(),other)

    def test_pending_uses_an_explicit_branch_without_calling_complete_guard(self):
        self.b.matching_pending()
        with self.held() as (item,writer,trust),patch.object(model,'require_complete',side_effect=AssertionError('no pending exception fallback')):
            result=item._admit_owned_erase(writer,trust)
            self.assertEqual(result.slot.record.state,'PENDING')
        self.assertEqual(len(self.module_calls),4)

    def test_pending_requires_real_module_admission_not_policy_child_exception(self):
        self.b.matching_pending();before=self.inventory()
        self.module_listing=b'100 base cil\n'
        with self.held() as (item,writer,trust),patch.object(model,'require_complete',side_effect=AssertionError('PENDING is a separate branch')):
            with self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.assertTrue(self.module_calls);self.assertEqual(self.inventory(),before)
        self.assertFalse(self.b.active)

    def test_all_nonowned_priority_language_hll_and_recheck_drift_refuse(self):
        self.b.matching_pending();before=self.inventory()
        for listing in (b'400 qshd pp disabled\n',b'500 qshd pp\n',b'100 qshd pp\n',b'400 qshd pp\n500 qshd pp\n',b'400 qshd cil\n',b'bad'):
            self.module_listing=listing;self.module_calls=[]
            with self.subTest(listing=listing),self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.module_listing=b'400 qshd pp\n';self.module_pp=b'wrong'
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.module_pp=PP;self.module_calls=[]
        def drift(operation,cwd,owner):
            if len(self.module_calls)==3:self.module_listing=b'500 qshd pp\n'
        self.module_action=drift
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.assertEqual(self.inventory(),before)

    def test_stale_complete_binding_and_wrong_artifact_refuse(self):
        before=self.b.record();path=self.b.common/'selinux-activation/activation.json'
        stale=replace(before,completion=replace(before.completion,contexts=model.ContextBinding('f'*64,'e'*64)))
        path.write_bytes(canonical(asdict(stale)))
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.assertEqual(len(self.module_calls),4)
        path.write_bytes(canonical(asdict(before)));self.module_calls=[]
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,replace(trust,provider_version='another'))
        self.assertEqual(self.module_calls,[])

    def test_absent_malformed_and_unsupported_slot_refuse_before_module(self):
        path=self.b.common/'selinux-activation/activation.json';raw=path.read_bytes()
        for case in ('absent','malformed','profile','module','pending-completion'):
            if case=='absent':path.unlink()
            elif case=='malformed':path.write_bytes(b'{malformed')
            else:
                value=json.loads(raw)
                if case=='profile':value['abi']=2
                elif case=='module':value['module']['priority']=500
                else:value['state']='PENDING'
                path.write_bytes(canonical(value))
            with self.subTest(case=case),self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
            self.assertEqual(self.module_calls,[]);path.write_bytes(raw)

    def test_admin_and_receipt_free_current_rows_are_not_owned(self):
        self.b.matching_pending();self.unowned_current(True);before=self.inventory()
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.assertEqual(self.module_calls,[]);self.assertEqual(self.inventory(),before)
        receipts=self.b.common/'selinux-contexts/receipts';receipts.write_bytes(b'{}');before=self.inventory()
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.assertEqual(self.inventory(),before)

    def test_dirty_or_missing_context_state_never_creates_or_enters_writer(self):
        import shutil
        state=self.b.common/'selinux-contexts';original={p.name:p.read_bytes() for p in state.iterdir() if p.is_file()};target=self.b.target.read_bytes()
        for case in ('missing','partial','missing-lock','missing-receipt','extra-receipt','source','journal-file','journal-symlink','journal-fifo','journal-dir'):
            self.b.target.write_bytes(target)
            if state.exists():shutil.rmtree(state)
            state.mkdir(mode=0o700)
            for name,data in original.items():p=state/name;p.write_bytes(data);p.chmod(0o600)
            if case=='missing':shutil.rmtree(state)
            elif case=='partial':(state/'lock').unlink();(state/'receipts').unlink()
            elif case=='missing-lock':(state/'lock').unlink()
            elif case=='missing-receipt':(state/'receipts').unlink()
            elif case=='extra-receipt':
                value=json.loads((state/'receipts').read_bytes());value['/foreign']=value['/context'];(state/'receipts').write_bytes(canonical(value))
            elif case=='source':self.b.target.write_bytes(self.b.target.read_bytes().replace(b'user_r:user_t',b'staff_r:staff_t'))
            elif case=='journal-file':(state/'journal').write_bytes(b'unknown')
            elif case=='journal-symlink':(state/'journal').symlink_to(self.b.root/'missing')
            elif case=='journal-fifo':os.mkfifo(state/'journal')
            else:(state/'journal').mkdir()
            before=self.inventory();self.module_calls=[]
            with self.subTest(case=case),self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
            self.assertEqual(self.inventory(),before);self.assertEqual(self.module_calls,[])

    def test_scope_finalizers_and_late_closure_suppress_admission(self):
        before=self.inventory()
        for event in ('window exit','module exit','preflight exit','registry exit'):
            self.b.failure=event
            with self.subTest(event=event),self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
            self.assertFalse(self.b.active);self.assertEqual(self.inventory(),before)
        self.b.failure=None;point=self.b.point
        def late(event):
            point(event)
            if event=='module exit':self.b.now=340
        self.b.point=late
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.assertEqual(self.inventory(),before)

    def test_original_budget_consumes_setup_and_does_not_start_an_observer_late(self):
        self.b.now=270
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.assertEqual(self.module_calls,[])
        self.b.now=100;point=self.b.point
        def elapsed(event):
            point(event)
            if event=='routing':self.b.now=270
        self.b.point=elapsed
        with self.held() as (item,writer,trust),self.assertRaises(consumer.CoordinatorError):item._admit_owned_erase(writer,trust)
        self.assertEqual(self.module_calls,[]);self.assertNotIn('module enter',self.b.events)


if __name__=='__main__':unittest.main()
