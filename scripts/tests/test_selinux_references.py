"""Actual assembled temporary reference trees; no host policy/native calls."""
from contextlib import ExitStack
from dataclasses import FrozenInstanceError
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'packaging/selinux'))
import qshd_selinux_reference_loader as m

class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.out=self.root/'staged'
        spec=importlib.util.spec_from_file_location('builder',ROOT/'packaging/selinux/assemble_payload.py')
        self.builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.builder)
        self.pp=self.root/'qshd.pp';self.pp.write_bytes(b'inert synthetic reference PP\n')
        self.contexts_pp=self.root/'qshd_contexts.pp';self.contexts_pp.write_bytes(b'inert contexts PP\n')
        self.artifact=ROOT/'packaging/selinux/artifact.json';self.pam=ROOT/'packaging/pam.d/qshd.fedora-selinux'
        source=ROOT/'packaging/selinux'
        expected={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in self.builder.MODULES}
        expected.update({name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in [('qshd.pp',self.pp),('qshd_contexts.pp',self.contexts_pp),('artifact.json',self.artifact),('qshd.fedora-selinux',self.pam)]})
        self.builder.assemble_payload(source,self.pp,self.contexts_pp,self.artifact,self.pam,expected,self.out,1000000000)
        self.share=self.out/'usr/share/qshd-selinux'
    def reader(self):return m._testing_references(self.out)
    def document(self):return json.loads((self.share/'reference.json').read_bytes())
    def write_document(self,value):
        path=self.share/'reference.json';path.write_text(json.dumps(value));path.chmod(0o644)
    def test_actual_assembly_frozen_values_and_live_recheck(self):
        with self.reader() as reader:
            value=reader.capture();reader.recheck(value);reader.recheck(value)
            self.assertEqual(value.artifact.provider_version,'0.3.0')
            self.assertEqual(value.artifact.manifest_sha256,self.document()['manifest_sha256'])
            self.assertEqual(value.core_pp_bytes,self.pp.read_bytes())
            self.assertEqual(value.contexts_pp_bytes,self.contexts_pp.read_bytes())
            self.assertEqual(value.expected_pam,self.pam.read_bytes())
            with self.assertRaises(FrozenInstanceError):value.core_pp_bytes=b'changed'
        for action in (reader.capture,lambda:reader.recheck(value)):
            with self.assertRaises(m.ReferenceError):action()
    def test_each_reference_mismatch_refuses_without_minting_new_hashes(self):
        for name in ('qshd.pp','qshd_contexts.pp','artifact.json','qshd.fedora-selinux'):
            path=self.share/name;original=path.read_bytes();path.write_bytes(original+b'changed')
            try:
                with self.assertRaises(m.ReferenceError):
                    with self.reader() as reader:reader.capture()
            finally:path.write_bytes(original)
    def test_strict_pair_json_fields_scalars_duplicates_and_utf8(self):
        original=(self.share/'reference.json').read_bytes();valid=self.document()
        invalid=[valid|{'extra':1},{k:v for k,v in valid.items() if k!='contexts_pp_sha256'},
                 valid|{'provider_version':True},valid|{'manifest_sha256':'not a digest'},
                 valid|{'expected_pam':['wrong']},valid|{'expected_pam':'\ud800'},
                 valid|{'expected_pam':'x'*4097}]
        for value in invalid:
            self.write_document(value)
            with self.assertRaises(m.ReferenceError):
                with self.reader() as reader:reader.capture()
        for raw in [b'\xff',b'{}\n',original[:-2]+b',"provider_version":"duplicate"}\n',b'x'*16385]:
            (self.share/'reference.json').write_bytes(raw)
            with self.assertRaises(m.ReferenceError):
                with self.reader() as reader:reader.capture()
    def test_leaf_type_mode_links_and_protected_routes(self):
        path=self.share/'qshd.pp';original=path.read_bytes()
        for kind in ('mode','symlink','fifo','hardlink'):
            if kind=='mode':path.chmod(0o666)
            elif kind=='symlink':path.unlink();path.symlink_to(self.pp)
            elif kind=='fifo':path.unlink();os.mkfifo(path)
            else:os.link(path,self.root/'alias')
            try:
                with self.assertRaises(m.ReferenceError):
                    with self.reader() as reader:reader.capture()
            finally:
                if kind=='hardlink':(self.root/'alias').unlink()
                elif kind!='mode':path.unlink();path.write_bytes(original)
                path.chmod(0o644)
        self.share.chmod(0o777)
        with self.assertRaises(m.ReferenceError):
            with self.reader():pass
    def test_same_bytes_replacement_and_late_json_drift_refuse(self):
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:
                value=reader.capture();path=self.share/'artifact.json'
                new=path.with_suffix('.new');new.write_bytes(path.read_bytes());new.chmod(0o644);new.replace(path)
                reader.recheck(value)
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:
                value=reader.capture();reader.recheck(value)
                self.write_document(self.document()|{'provider_version':'changed'})
    def test_required_recheck_foreign_capture_and_duplicate_capture(self):
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:reader.capture()
        with self.reader() as reader:
            value=reader.capture();reader.recheck(value)
            with self.assertRaises(m.ReferenceError):
                with self.reader() as other:other.capture();other.recheck(value)
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:reader.capture();reader.capture()
    def test_capture_and_recheck_are_lock_free_read_only(self):
        import fcntl,subprocess,ctypes
        with self.reader() as reader,ExitStack() as stack:
            for name in ('write','rename','unlink','mkdir','fsync','fchmod','fchown','setxattr','removexattr'):
                stack.enter_context(patch.object(m.os,name,side_effect=AssertionError('reference mutation')))
            for target,name in ((fcntl,'flock'),(subprocess,'Popen'),(ctypes,'CDLL')):
                stack.enter_context(patch.object(target,name,side_effect=AssertionError('lock/process/native call')))
            native=os.open
            def opened(path,flags,*args,**kwargs):
                self.assertFalse(flags & (os.O_CREAT|os.O_WRONLY|os.O_RDWR|os.O_TRUNC))
                return native(path,flags,*args,**kwargs)
            stack.enter_context(patch.object(m.os,'open',side_effect=opened))
            reader.recheck(reader.capture())
    def test_acquired_directory_fstat_fault_closes_owned_fds(self):
        before=set(os.listdir('/proc/self/fd'));native=os.fstat;failed=[]
        def fault(fd):
            if not failed:failed.append(fd);raise OSError(errno.EIO,'synthetic directory fstat')
            return native(fd)
        with patch.object(m.os,'fstat',side_effect=fault),self.assertRaises(m.ReferenceError):
            with self.reader():pass
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)
    def test_close_failure_attempts_all_and_never_retries_uncertain_fd(self):
        reader=self.reader();reader.__enter__();reader.recheck(reader.capture())
        held=set(reader.anchors+[part for route in reader.routes for part in (route[0],route[2])]);target=reader.anchors[0]
        native=os.close;attempts=[]
        def close(fd):
            attempts.append(fd)
            if fd==target:raise OSError(errno.EIO,'synthetic close acknowledgement')
            return native(fd)
        try:
            with patch.object(m.os,'close',side_effect=close),self.assertRaises(m.ReferenceError):reader.__exit__(None,None,None)
            self.assertTrue(held<=set(attempts));self.assertEqual(attempts.count(target),1)
            with self.assertRaises(m.ReferenceError):reader.__enter__()
        finally:native(target)
    def test_production_root_gate_before_filesystem_work(self):
        with patch.object(m.os,'geteuid',return_value=1000),patch.object(m.os,'open',side_effect=AssertionError('host open')):
            with self.assertRaises(m.ReferenceError):m.production_references()

    def test_pam_limit_counts_encoded_utf8_bytes_not_characters(self):
        value=self.document();text='é'*2049
        self.assertLess(len(text),4096);self.assertGreater(len(text.encode('utf-8')),4096)
        value['expected_pam']=text;value['pam_sha256']=hashlib.sha256(text.encode('utf-8')).hexdigest()
        self.write_document(value)
        with self.assertRaisesRegex(m.ReferenceError,'PAM_LIMIT'):
            with self.reader() as reader:reader.capture()

    def test_directory_rebinding_refuses_before_reading_new_leaves(self):
        held=self.share.with_name('held');read=None
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:
                value=reader.capture();self.share.rename(held);self.share.mkdir(mode=0o755)
                with patch.object(reader,'_read',side_effect=AssertionError('read after route replacement')) as read:
                    reader.recheck(value)
        self.assertIsNotNone(read);read.assert_not_called()
        self.assertTrue(held.is_dir());self.assertTrue(self.share.is_dir())
        self.assertEqual((held/'qshd.pp').read_bytes(),self.pp.read_bytes())

    def test_failure_after_regular_read_open_closes_probe_read_and_routes(self):
        import fcntl
        before=set(os.listdir('/proc/self/fd'));native=os.fstat;failed=[]
        def fault(fd):
            path=os.readlink('/proc/self/fd/'+str(fd))
            if path==str(self.share/'qshd.pp') and not fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_PATH and not failed:
                failed.append(fd);raise OSError(errno.EIO,'synthetic acquired read fstat')
            return native(fd)
        with patch.object(m.os,'fstat',side_effect=fault),self.assertRaises(m.ReferenceError):
            with self.reader() as reader:reader.capture()
        self.assertEqual(len(failed),1);self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_companion_absence_swap_replacement_and_legacy_reference_refuse(self):
        path=self.share/'qshd_contexts.pp';original=path.read_bytes()
        path.unlink()
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:reader.capture()
        path.write_bytes(original);path.chmod(0o644)
        core=self.share/'qshd.pp';core_bytes=core.read_bytes()
        core.write_bytes(original);path.write_bytes(core_bytes)
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:reader.capture()
        core.write_bytes(core_bytes);path.write_bytes(original)
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:
                value=reader.capture();new=path.with_suffix('.new');new.write_bytes(original);new.chmod(0o644);new.replace(path)
                reader.recheck(value)
        value=self.document();value.pop('schema');value['pp_sha256']=value.pop('core_pp_sha256');value.pop('contexts_pp_sha256')
        self.write_document(value)
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:reader.capture()

    def test_companion_metadata_and_per_file_bound_without_large_read(self):
        path=self.share/'qshd_contexts.pp';original=path.read_bytes()
        path.chmod(0o666)
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:reader.capture()
        path.chmod(0o644)
        with path.open('wb') as stream:stream.truncate(16*1024**2+1)
        with self.assertRaises(m.ReferenceError):
            with self.reader() as reader:reader.capture()
        path.write_bytes(original)
        self.assertEqual(m._LIMITS['qshd.pp']+m._LIMITS['qshd_contexts.pp'],32*1024**2)

if __name__=='__main__':unittest.main()
