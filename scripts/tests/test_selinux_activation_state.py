"""Real disposable activation slot files/locks/faults, never host policy paths."""
from dataclasses import FrozenInstanceError, replace
from contextlib import nullcontext
import errno
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

MODULES=Path(__file__).resolve().parents[2]/'packaging/selinux'
sys.path.insert(0,str(MODULES))
import qshd_selinux_activation as model
import qshd_selinux_activation_state as state


def document(kind='PENDING', operation='b'*32):
    return dict(schema=1,state=kind,operation_id=operation,profile='fedora44-targeted-v1',
                abi=1,query_profile=1,
                artifact=dict(provider_version='0.2.0-1.fc44',manifest_sha256='c'*64,pp_sha256='d'*64),
                module=dict(name='qshd',priority=400,store='targeted',format='pp'),
                completion=None if kind=='PENDING' else dict(load='normal-install-reload-v1',
                    extracted_hll_sha256='d'*64,contexts=dict(registry_sha256='e'*64,receipts_sha256='f'*64)))


def encoded(kind='PENDING', operation='b'*32):return json.dumps(document(kind,operation)).encode()
TRUST=model.TrustedArtifact('0.2.0-1.fc44','c'*64,'d'*64)
BINDING=model.ContextBinding('e'*64,'f'*64)


class SlotTests(unittest.TestCase):
    def setUp(self):
        self.fd_baseline=set(os.listdir('/proc/self/fd'))
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.directory=self.root/'activation';self.directory.mkdir(mode=0o700)
        (self.directory/'lock').write_bytes(b'');(self.directory/'lock').chmod(0o600)
        self.path=self.directory/'activation.json'
    def tearDown(self):
        self.assertEqual(set(os.listdir('/proc/self/fd')),self.fd_baseline)
    def slot(self,hook=None):return state.ActivationSlot(self.directory,uid=os.geteuid(),anchor=self.root,hook=hook)
    def write(self,data):self.path.write_bytes(data);self.path.chmod(0o600)
    def complete(self,writer,token,data=None,**kwargs):
        return writer.publish_complete(data or encoded('COMPLETE'),token,
            trusted_artifact=kwargs.get('artifact',TRUST),trusted_context_binding=kwargs.get('binding',BINDING))

    def test_reader_absence_baseline_immutable_no_write_and_closed_use(self):
        before=set(os.listdir('/proc/self/fd'))
        mutations=('mkdir','write','rename','unlink','fsync','fchmod','fchown','setxattr','removexattr')
        from contextlib import ExitStack
        with ExitStack() as stack:
            for name in mutations:stack.enter_context(patch.object(state.os,name,side_effect=AssertionError('mutation')))
            with self.slot().inspection() as lease:
                observation=lease.capture();self.assertIsNone(observation.record)
                self.assertIsNone(observation.document);self.assertIsNone(observation.snapshot)
                self.assertFalse(hasattr(lease,'begin_pending'))
                lease.recheck(observation);lease.recheck(observation)
                with self.assertRaises(FrozenInstanceError):observation.document=b'changed'
                with self.assertRaises(state.SlotError):lease.capture()
                with self.assertRaises(state.SlotError):lease.recheck(replace(observation))
        with self.assertRaises(state.SlotError):lease.recheck(observation)
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)
        self.assertEqual(sorted(p.name for p in self.directory.iterdir()),['lock'])

    def test_reader_full_snapshot_and_content_metadata_inode_drift(self):
        for change in ('data','mode','xattr','inode','lock','route'):
            with self.subTest(change=change):
                self.write(encoded('COMPLETE','a'*32));os.setxattr(self.path,'user.fixture',b'original')
                slot=self.slot()
                exit_check=self.assertRaises(state.SlotError) if change in ('lock','route') else nullcontext()
                with exit_check, slot.inspection() as lease:
                    observation=lease.capture();self.assertEqual(observation.record.state,'COMPLETE')
                    self.assertIn(('user.fixture',b'original'),observation.snapshot[5])
                    if change=='data':self.path.write_bytes(observation.document+b' ')
                    elif change=='mode':self.path.chmod(0o640)
                    elif change=='xattr':os.setxattr(self.path,'user.fixture',b'changed')
                    elif change=='inode':
                        self.path.unlink();self.write(observation.document)
                    elif change=='lock':
                        lock=self.directory/'lock';lock.unlink();lock.write_bytes(b'');lock.chmod(0o600)
                    else:
                        moved=self.root/'moved';self.directory.rename(moved);self.directory.mkdir(mode=0o700)
                        (self.directory/'lock').write_bytes(b'');(self.directory/'lock').chmod(0o600)
                    with self.assertRaises(state.SlotError):lease.recheck(observation)
                if change=='route':
                    import shutil
                    shutil.rmtree(self.directory);moved.rename(self.directory)

    def test_missing_partial_and_unsafe_state_refuse_without_repair(self):
        for kind in ('missing-directory','missing-lock','state-mode','state-symlink','parent-mode','wrong-uid','lock-mode','lock-symlink','lock-hardlink','lock-fifo','document-fifo','document-symlink','document-hardlink','document-mode','document-oversize','malformed'):
            with self.subTest(kind=kind),tempfile.TemporaryDirectory(dir=self.root) as temporary:
                root=Path(temporary);directory=root/'state'
                if kind=='state-symlink':
                    real=root/'real';real.mkdir(mode=0o700);directory.symlink_to(real,target_is_directory=True)
                elif kind!='missing-directory':directory.mkdir(mode=0o700)
                if kind not in ('missing-directory','missing-lock'):
                    lock=directory/'lock';lock.write_bytes(b'');lock.chmod(0o600)
                    if kind=='state-mode':directory.chmod(0o750)
                    if kind=='parent-mode':root.chmod(0o770)
                    if kind=='lock-hardlink':os.link(lock,root/'other-lock')
                    if kind=='lock-mode':lock.chmod(0o640)
                    if kind=='lock-symlink':lock.unlink();lock.symlink_to(root/'foreign')
                    if kind=='lock-fifo':lock.unlink();os.mkfifo(lock,0o600)
                    doc=directory/'activation.json'
                    if kind=='document-fifo':os.mkfifo(doc,0o600)
                    elif kind=='document-symlink':doc.symlink_to(root/'foreign')
                    elif kind in ('document-hardlink','document-mode','document-oversize','malformed'):
                        doc.write_bytes(b'x'*65537 if kind=='document-oversize' else b'not JSON' if kind=='malformed' else encoded())
                        doc.chmod(0o640 if kind=='document-mode' else 0o600)
                        if kind=='document-hardlink':os.link(doc,root/'other')
                names=sorted(str(p.relative_to(root)) for p in root.rglob('*'))
                with self.assertRaises(state.SlotError):
                    with state.ActivationSlot(directory,uid=os.geteuid()+1 if kind=='wrong-uid' else os.geteuid(),anchor=root).inspection() as lease:lease.capture()
                self.assertEqual(sorted(str(p.relative_to(root)) for p in root.rglob('*')),names)

    def test_orphan_stage_is_neither_adopted_nor_removed(self):
        orphan=self.directory/'.qshd-orphan';orphan.write_bytes(encoded('COMPLETE'));orphan.chmod(0o600)
        with self.slot().inspection() as reader:self.assertIsNone(reader.capture().record)
        with self.slot().writer() as writer:
            writer.begin_pending(encoded(),writer.capture_current())
        self.assertEqual(orphan.read_bytes(),encoded('COMPLETE'))
        self.assertEqual(model.parse_activation(self.path.read_bytes()).state,'PENDING')

    def test_full_lifecycle_absent_old_complete_and_old_pending(self):
        for prior in (None,'COMPLETE','PENDING'):
            with self.subTest(prior=prior):
                if self.path.exists():self.path.unlink()
                if prior:self.write(encoded(prior,'a'*32));os.setxattr(self.path,'user.fixture',b'kept')
                with self.slot().writer() as writer:
                    initial=writer.capture_current()
                    token=writer.begin_pending(encoded(),initial)
                    self.assertEqual(model.parse_activation(self.path.read_bytes()).state,'PENDING')
                    self.assertNotEqual(token.observation,initial)
                    completed=self.complete(writer,token)
                    self.assertEqual(completed.record.state,'COMPLETE')
                    self.assertEqual(completed.document,encoded('COMPLETE'))
                    self.assertEqual(self.path.stat().st_mode&0o7777,0o600)
                    if prior:self.assertEqual(os.getxattr(self.path,'user.fixture'),b'kept')
                    with self.assertRaises(state.SlotError):self.complete(writer,token)
                self.assertEqual(list(self.directory.glob('.qshd-*')),[])

    def test_writer_order_new_operation_and_foreign_consumed_tokens(self):
        self.write(encoded('PENDING'))
        with self.slot().writer() as writer:
            old=writer.capture_current()
            with self.assertRaises(state.SlotError):self.complete(writer,old)
            with self.assertRaises(state.SlotError):writer.begin_pending(encoded('PENDING','c'*32),old)
        with self.slot().writer() as writer:
            old=writer.capture_current()
            with self.assertRaises(state.SlotError):writer.begin_pending(encoded(),old)
        self.write(encoded('COMPLETE','a'*32))
        with self.slot().writer() as writer:
            initial=writer.capture_current();token=writer.begin_pending(encoded(),initial)
            with self.assertRaises(state.SlotError):writer.begin_pending(encoded('PENDING','c'*32),initial)
        with self.slot().writer() as other:
            other.capture_current()
            with self.assertRaises(state.SlotError):self.complete(other,token)
        with self.assertRaises(state.SlotError):writer.observe_outcome()

    def test_begin_validation_poisoning_and_same_instance_nested_refusal(self):
        for value in (encoded('COMPLETE'),b'x'*65537,'not bytes'):
            with self.subTest(value_type=type(value).__name__):
                if self.path.exists():self.path.unlink()
                with self.slot().writer() as writer:
                    baseline=writer.capture_current()
                    with self.assertRaises(state.SlotError):writer.begin_pending(value,baseline)
                    with self.assertRaises(state.SlotError):writer.begin_pending(encoded(),baseline)
                self.assertFalse(self.path.exists())
        slot=self.slot()
        with slot.inspection():
            with self.assertRaises(state.SlotError):
                with slot.writer():self.fail('nested same-instance lease admitted')

    def test_begin_faults_never_return_mutation_authority(self):
        for event in ('stage_file_sync','before_slot_rename','slot_rename','slot_directory_sync','slot_readback'):
            with self.subTest(event=event):
                self.write(encoded('COMPLETE','a'*32));allowed=[]
                def hook(current):
                    if current==event:raise OSError(errno.EIO,'private begin failure')
                with self.slot(hook).writer() as writer:
                    with self.assertRaises(state.SlotError):
                        writer.begin_pending(encoded(),writer.capture_current());allowed.append(True)
                    self.assertEqual(allowed,[])
                    outcome=writer.observe_outcome()
                    self.assertEqual(outcome.record.state,'COMPLETE' if event in ('stage_file_sync','before_slot_rename') else 'PENDING')
                self.assertEqual(list(self.directory.glob('.qshd-*')),[])

    def test_completion_header_trust_and_current_pending_must_match(self):
        for change in ('operation','artifact','trusted','binding','pending-data','pending-inode'):
            with self.subTest(change=change):
                self.write(encoded('COMPLETE','a'*32))
                with self.slot().writer() as writer:
                    token=writer.begin_pending(encoded(),writer.capture_current())
                    doc=document('COMPLETE');kwargs={}
                    if change=='operation':doc['operation_id']='c'*32
                    elif change=='artifact':doc['artifact']['provider_version']='different'
                    elif change=='trusted':kwargs['artifact']=model.TrustedArtifact('different','c'*64,'d'*64)
                    elif change=='binding':kwargs['binding']=model.ContextBinding('a'*64,'f'*64)
                    elif change=='pending-data':self.path.write_bytes(self.path.read_bytes()+b' ')
                    else:self.path.unlink();self.write(encoded())
                    with self.assertRaises(state.SlotError):self.complete(writer,token,json.dumps(doc).encode(),**kwargs)
                    self.assertEqual(model.parse_activation(self.path.read_bytes()).state,'PENDING')

    def test_completion_faults_distinguish_before_and_after_rename(self):
        for event in ('stage_file_sync','stage_directory_sync','before_slot_rename','slot_rename','slot_directory_sync','slot_readback'):
            with self.subTest(event=event):
                self.write(encoded('COMPLETE','a'*32));enabled=[False]
                def hook(current):
                    if enabled[0] and current==event:raise OSError(errno.EIO,'private fixture path')
                with self.slot(hook).writer() as writer:
                    token=writer.begin_pending(encoded(),writer.capture_current());enabled[0]=True
                    expected=state.OutcomeUncertain if event in ('slot_rename','slot_directory_sync','slot_readback') else state.SlotError
                    with self.assertRaises(expected) as caught:self.complete(writer,token)
                    if expected is state.SlotError:self.assertNotIsInstance(caught.exception,state.OutcomeUncertain)
                    self.assertNotIn('private',str(caught.exception))
                    enabled[0]=False
                    outcome=writer.observe_outcome()
                    self.assertEqual(outcome.record.state,'COMPLETE' if expected is state.OutcomeUncertain else 'PENDING')
                    with self.assertRaises(state.SlotError):self.complete(writer,token)
                self.assertEqual(list(self.directory.glob('.qshd-*')),[])

    def test_rename_ack_and_directory_fsync_errors_have_uncertain_outcome(self):
        for failure in ('rename-ack','directory-fsync'):
            with self.subTest(failure=failure):
                self.write(encoded('COMPLETE','a'*32));after=[False]
                def hook(event):
                    if event=='slot_rename':after[0]=True
                slot=self.slot(hook)
                with slot.writer() as writer:
                    token=writer.begin_pending(encoded(),writer.capture_current());after[0]=False
                    original_rename,original_sync=os.rename,os.fsync
                    def rename(*args,**kwargs):
                        original_rename(*args,**kwargs)
                        raise OSError(errno.EIO,'lost acknowledgment')
                    def sync(fd):
                        if after[0] and fd==slot.state_fd:raise OSError(errno.EIO,'directory sync')
                        return original_sync(fd)
                    target='rename' if failure=='rename-ack' else 'fsync'
                    with patch.object(state.os,target,side_effect=rename if target=='rename' else sync):
                        with self.assertRaises(state.OutcomeUncertain):self.complete(writer,token)
                    self.assertEqual(writer.observe_outcome().record.state,'COMPLETE')
                with self.slot().inspection() as reader:self.assertEqual(reader.capture().record.state,'COMPLETE')

    def test_begin_fault_and_caller_failure_never_authorize_completion(self):
        self.write(encoded('COMPLETE','a'*32))
        def hook(event):
            if event=='slot_rename':raise KeyboardInterrupt()
        with self.slot(hook).writer() as writer:
            initial=writer.capture_current()
            with self.assertRaises(KeyboardInterrupt):writer.begin_pending(encoded(),initial)
            self.assertEqual(writer.observe_outcome().record.state,'PENDING')
            with self.assertRaises(state.SlotError):self.complete(writer,initial)
        self.write(encoded('COMPLETE','a'*32))
        with self.assertRaisesRegex(RuntimeError,'caller load failed'):
            with self.slot().writer() as writer:
                writer.begin_pending(encoded(),writer.capture_current())
                raise RuntimeError('caller load failed')
        self.assertEqual(model.parse_activation(self.path.read_bytes()).state,'PENDING')

    def test_completion_interrupt_before_and_after_replacement(self):
        for event in ('before_slot_rename','slot_rename'):
            with self.subTest(event=event):
                self.write(encoded('COMPLETE','a'*32));enabled=[False]
                def hook(current):
                    if enabled[0] and current==event:raise KeyboardInterrupt()
                with self.slot(hook).writer() as writer:
                    token=writer.begin_pending(encoded(),writer.capture_current());enabled[0]=True
                    expected=KeyboardInterrupt if event=='before_slot_rename' else state.OutcomeUncertain
                    with self.assertRaises(expected):self.complete(writer,token)
                    enabled[0]=False
                    self.assertEqual(writer.observe_outcome().record.state,'PENDING' if event=='before_slot_rename' else 'COMPLETE')
                self.assertEqual(list(self.directory.glob('.qshd-*')),[])

    def test_substituted_owned_stage_is_preserved_cleanup_failure_visible(self):
        self.write(encoded('COMPLETE','a'*32));enabled=[False];foreign=[]
        def hook(event):
            if enabled[0] and event=='before_slot_rename':
                path=next(self.directory.glob('.qshd-*'));path.unlink();path.write_bytes(b'foreign');path.chmod(0o600);foreign.append(path)
        with self.assertRaises(state.SlotError):
            with self.slot(hook).writer() as writer:
                token=writer.begin_pending(encoded(),writer.capture_current());enabled[0]=True
                with self.assertRaises(state.SlotError):self.complete(writer,token)
        self.assertEqual(foreign[0].read_bytes(),b'foreign')
        self.assertEqual(model.parse_activation(self.path.read_bytes()).state,'PENDING')

    def test_actual_cooperating_writer_waits_and_descriptors_close(self):
        before=set(os.listdir('/proc/self/fd'));child=None
        code='import sys,os;sys.path.insert(0,sys.argv[1]);import qshd_selinux_activation_state as s;print("waiting",flush=True)\nwith s.ActivationSlot(sys.argv[2],uid=os.geteuid(),anchor=sys.argv[3]).writer():print("acquired",flush=True)'
        try:
            with self.slot().inspection():
                child=subprocess.Popen([sys.executable,'-I','-B','-c',code,str(MODULES),str(self.directory),str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=os.environ|{'HOME':str(self.root),'XDG_CONFIG_HOME':str(self.root),'XDG_CACHE_HOME':str(self.root),'HISTFILE':'/dev/null'})
                self.assertTrue(select.select([child.stdout],[],[],5)[0]);self.assertEqual(child.stdout.readline().strip(),'waiting')
                self.assertFalse(select.select([child.stdout],[],[],.15)[0])
            self.assertTrue(select.select([child.stdout],[],[],5)[0]);self.assertEqual(child.stdout.readline().strip(),'acquired')
            self.assertEqual(child.wait(timeout=5),0)
        finally:
            if child is not None:
                if child.poll() is None:child.terminate();child.wait(timeout=5)
                child.stdout.close();child.stderr.close()
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_production_constructor_and_invalid_paths_do_not_touch_system(self):
        with patch.object(state.os,'geteuid',return_value=0):self.assertEqual(state.production().state,Path('/var/lib/qshd/selinux-activation'))
        with patch.object(state.os,'geteuid',return_value=1000):
            with self.assertRaises(state.SlotError):state.production()
        for value in ('relative','/tmp/../invalid'):
            with self.assertRaises(state.SlotError):state.ActivationSlot(value)

if __name__=='__main__':unittest.main()
