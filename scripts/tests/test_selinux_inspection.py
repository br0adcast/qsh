"""Disposable coherent context inspection tests; no host policy access."""
from contextlib import ExitStack
from dataclasses import FrozenInstanceError
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
import qshd_selinux_transaction as tx

class InspectionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.target=self.root/'context'
        self.target.write_bytes(b'system_r:sshd_t:s0 user_r:user_t:s0\n')
        self.ids={'/contexts':{'path':'/contexts','source_type':'sshd_t','original_package':'fixture-1'}}
        self.engine().reconcile(self.ids)
    def engine(self):return tx.Transaction(self.root/'state',{'/contexts':self.target},uid=os.geteuid())
    def test_canonical_capture_immutable_and_live_lease(self):
        ids=json.loads(json.dumps(self.ids))
        with self.engine().inspection(ids) as lease:
            ids['/contexts']['original_package']='changed'
            record=lease.capture()
            registry=json.dumps(self.ids,sort_keys=True,separators=(',',':')).encode()
            self.assertEqual(record.registry_bytes,registry)
            self.assertEqual(record.receipts_bytes,(self.root/'state/receipts').read_bytes())
            self.assertEqual(record.registry_sha256,hashlib.sha256(registry).hexdigest())
            self.assertEqual(record.receipts_sha256,hashlib.sha256(record.receipts_bytes).hexdigest())
            with self.assertRaises(FrozenInstanceError):record.registry_bytes=b''
            lease.recheck(record);lease.recheck(record)
            with self.assertRaises(tx.Conflict):lease.capture()
        with self.assertRaises(tx.Conflict):lease.recheck(record)
        with self.engine().inspection(self.ids) as other:
            with self.assertRaises(tx.Conflict):other.recheck(record)
            own=other.capture()
            with self.assertRaises(tx.Conflict):other.recheck(record)
            other.recheck(own)
    def test_no_writes_or_recovery(self):
        with ExitStack() as stack:
            for name in ('mkdir','write','rename','unlink','fsync','fchmod','fchown','setxattr','removexattr'):
                stack.enter_context(patch.object(tx.os,name,side_effect=AssertionError('mutation')))
            for name in ('recover','_journal_load','_create'):
                stack.enter_context(patch.object(tx.Transaction,name,side_effect=AssertionError('mutation')))
            original=tx.os.open
            def opened(path,flags,*args,**kwargs):
                self.assertFalse(flags & (os.O_CREAT|os.O_WRONLY|os.O_RDWR));return original(path,flags,*args,**kwargs)
            stack.enter_context(patch.object(tx.os,'open',side_effect=opened))
            with self.engine().inspection(self.ids) as lease:lease.recheck(lease.capture())
    def test_missing_state_never_bootstraps(self):
        for name in ('lock','receipts'):
            path=self.root/'state'/name;saved=path.read_bytes();path.unlink()
            with self.assertRaises(tx.Conflict):
                with self.engine().inspection(self.ids):pass
            self.assertFalse(path.exists());path.write_bytes(saved);path.chmod(0o600)
        empty=self.root/'absent'
        e=tx.Transaction(empty,{'/contexts':self.target},uid=os.geteuid())
        with self.assertRaises(tx.Conflict):
            with e.inspection(self.ids):pass
        self.assertFalse(empty.exists())
    def test_journal_variants_and_appearance(self):
        journal=self.root/'state/journal'
        for kind in ('file','symlink','fifo'):
            if kind=='file':journal.write_bytes(b'malformed')
            elif kind=='symlink':journal.symlink_to(self.root/'absent')
            else:os.mkfifo(journal)
            with patch.object(tx.Transaction,'snapshot',side_effect=AssertionError('target opened')):
                with self.assertRaises(tx.Conflict):
                    with self.engine().inspection(self.ids) as lease:lease.capture()
            journal.unlink()
        with self.engine().inspection(self.ids) as lease:
            record=lease.capture();journal.write_bytes(b'{}')
            with self.assertRaises(tx.Conflict):lease.recheck(record)
    def test_drift_and_substitutions(self):
        for kind in ('content','mode','xattr','target-inode','receipt-inode','lock','parent'):
            with self.subTest(kind=kind),self.engine().inspection(self.ids) as lease:
                record=lease.capture()
                if kind=='content':self.target.write_bytes(self.target.read_bytes()+b'# edit\n')
                elif kind=='mode':self.target.chmod(0o600 if self.target.stat().st_mode&0o777!=0o600 else 0o640)
                elif kind=='xattr':os.setxattr(self.target,'user.synthetic',b'changed')
                elif kind in ('target-inode','receipt-inode'):
                    path=self.target if kind=='target-inode' else self.root/'state/receipts'
                    replacement=self.root/'replacement';replacement.write_bytes(path.read_bytes());replacement.chmod(path.stat().st_mode&0o777);replacement.replace(path)
                elif kind=='lock':
                    (self.root/'state/lock').rename(self.root/'old-lock');(self.root/'state/lock').write_bytes(b'');(self.root/'state/lock').chmod(0o600)
                else:
                    (self.root/'state').rename(self.root/'old-state');(self.root/'state').mkdir(mode=0o700)
                with self.assertRaises(tx.Conflict):lease.recheck(record)
            if kind=='parent':
                (self.root/'state').rmdir();(self.root/'old-state').rename(self.root/'state')
    def test_semantic_refusal_and_admin_bytes(self):
        with self.target.open('ab') as f:f.write(b'# administrator bytes\n')
        with self.engine().inspection(self.ids) as lease:lease.recheck(lease.capture())
        with patch.object(tx.pure,'check_current',return_value=False):
            with self.assertRaises(tx.Conflict):
                with self.engine().inspection(self.ids) as lease:lease.capture()
        bad=json.loads(json.dumps(self.ids));bad['/contexts']['path']='/wrong'
        with self.assertRaises((tx.Conflict,tx.pure.ReconcileError)):
            with self.engine().inspection(bad):pass
    def test_special_targets_and_state_authority(self):
        saved=self.target.read_bytes()
        for kind in ('symlink','hardlink','fifo'):
            self.target.unlink()
            if kind=='symlink':self.target.symlink_to(self.root/'absent')
            elif kind=='fifo':os.mkfifo(self.target)
            else:
                self.target.write_bytes(saved);os.link(self.target,self.root/'link')
            with self.assertRaises(tx.Conflict):
                with self.engine().inspection(self.ids) as lease:lease.capture()
            self.target.unlink()
            if kind=='hardlink':(self.root/'link').unlink()
            self.target.write_bytes(saved)
        (self.root/'state/receipts').chmod(0o644)
        with self.assertRaises(tx.Conflict):
            with self.engine().inspection(self.ids):pass
        (self.root/'state/receipts').chmod(0o600)
        with patch.object(tx.Transaction,'_dir_mode',side_effect=tx.Conflict('DIRECTORY_AUTHORITY')):
            with self.assertRaises(tx.Conflict):
                with self.engine().inspection(self.ids):pass

    def test_journal_appearing_during_capture_and_final_status_failure(self):
        journal=self.root/'state/journal';engine=self.engine();original=engine.snapshot
        def observed(key):
            result=original(key);journal.write_bytes(b'{}');return result
        with patch.object(engine,'snapshot',side_effect=observed):
            with self.assertRaises(tx.Conflict):
                with engine.inspection(self.ids) as lease:lease.capture()
        journal.unlink()
        from contextlib import contextmanager
        @contextmanager
        def status():
            yield
            raise RuntimeError('status finalization')
        accepted=False
        with self.assertRaises(RuntimeError):
            with self.engine().inspection(self.ids) as lease:
                with status():
                    lease.recheck(lease.capture())
            accepted=True
        self.assertFalse(accepted)
        with self.assertRaises(tx.Conflict):lease.capture()

    def test_cleanup_and_writer_exclusion(self):
        before=len(list(Path('/proc/self/fd').iterdir()))
        with self.engine().inspection(self.ids) as lease:
            lease.capture()
            code="import sys,os;from pathlib import Path;sys.path.insert(0,sys.argv[1]);import qshd_selinux_transaction as t;print('ready',flush=True);e=t.Transaction(Path(sys.argv[2])/'state',{'/contexts':Path(sys.argv[2])/'context'},uid=os.geteuid());\nwith e.locked(provision=False):print('locked',flush=True)"
            p=subprocess.Popen([sys.executable,'-B','-c',code,str(Path(tx.__file__).parent),str(self.root)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=os.environ|{'HOME':str(self.root),'XDG_CONFIG_HOME':str(self.root),'XDG_CACHE_HOME':str(self.root),'HISTFILE':'/dev/null'})
            try:
                self.assertEqual(p.stdout.readline().strip(),'ready');self.assertFalse(select.select([p.stdout],[],[],0.1)[0])
            except BaseException:p.kill();p.communicate();raise
        stdout,stderr=p.communicate(timeout=5);self.assertEqual(p.returncode,0,stderr);self.assertEqual(stdout.strip(),'locked')
        for _ in range(3):
            with self.assertRaises(RuntimeError):
                with self.engine().inspection(self.ids) as lease:lease.capture();raise RuntimeError('caller/status exit')
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)

if __name__=='__main__':unittest.main()
