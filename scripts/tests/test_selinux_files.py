"""Fixed-file observer controls on disposable files; no native policy calls."""
from contextlib import contextmanager, ExitStack
import os
import errno
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
import qshd_selinux_files as m

PAM=b'independent synthetic PAM\n'


class Api:
    def __init__(self):self.opened=0;self.closed=0;self.lookups=[];self.labels={};self.override=None
    @contextmanager
    def file_defaults(self):
        self.opened+=1
        try:yield self
        finally:self.closed+=1
    def lookup(self,path,kind):
        self.lookups.append((path,kind))
        return self.override or next(row[2] for row in m._PATHS if row[0]==path)
    def file_context(self,fd):
        os.fstat(fd)
        path=os.readlink('/proc/self/fd/'+str(fd))
        logical='/' + path.split('/root/',1)[1]
        return self.labels.get(logical,next(row[2] for row in m._PATHS if row[0]==logical))


class FileTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)/'root';self.root.mkdir(mode=0o700)
        for name in ('usr/bin','etc/pam.d','var/log','run/qshd'):(self.root/name).mkdir(parents=True,exist_ok=True)
        for path in self.root.rglob('*'):
            if path.is_dir():path.chmod(0o755)
        (self.root/'run/qshd').chmod(0o700)
        for name,data,mode in (('usr/bin/qshd',b'public executable',0o755),('etc/pam.d/qshd',PAM,0o644)):
            path=self.root/name;path.write_bytes(data);path.chmod(mode)
        self.api=Api();self.fds=len(os.listdir('/proc/self/fd'))
    def tearDown(self):
        self.assertEqual(len(os.listdir('/proc/self/fd')),self.fds)
        self.tmp.cleanup()
    def files(self):return m._testing(PAM,self.root,self.api,os.getuid())
    def test_erase_absent_runtime_preserves_startup_refusal_and_absent_children(self):
        (self.root/'run/qshd').rmdir()
        before=set(self.root.rglob('*'))
        files=self.files()
        with self.assertRaises(m.FilesError):
            with files.inspection() as lease:
                lease.capture()
        self.api.lookups.clear()
        with files.erase_inspection() as lease:
            result=lease.capture()
            self.assertEqual(result.phase,'consumer-erase')
            self.assertEqual(tuple(row.path for row in result.paths),tuple(row[0] for row in m._PATHS))
            self.assertTrue(all(not row.present for row in result.paths[-3:]))
            lease.recheck(result)
        self.assertEqual(set(self.root.rglob('*')),before)
        self.assertIn(('/run/qshd',m.stat.S_IFDIR),self.api.lookups)
        self.assertIn(('/run/qshd/helper-status.sock.lock',m.stat.S_IFREG),self.api.lookups)
        expected=[(path,kind) for path,kind,context,required,role in m._PATHS if context is not None]
        self.assertEqual(self.api.lookups,expected*2)

    def test_erase_present_runtime_matches_every_startup_path_field(self):
        files=self.files()
        with files.inspection() as lease:
            startup=lease.capture()
            lease.recheck(startup)
        with files.erase_inspection() as lease:
            erase=lease.capture()
            lease.recheck(erase)
        self.assertEqual(startup.phase,'managed-prestart')
        self.assertEqual(erase.phase,'consumer-erase')
        self.assertEqual(startup.paths,erase.paths)
        with self.assertRaises(Exception):
            erase.phase='managed-prestart'

    def test_erase_runtime_appearance_disappearance_and_replacement_refuse(self):
        runtime=self.root/'run/qshd'
        for change in ('appearance','disappearance','replacement'):
            if change=='appearance':
                runtime.rmdir()
            held=runtime.with_name('held')
            try:
                with self.subTest(change=change),self.assertRaises(m.FilesError):
                    with self.files().erase_inspection() as lease:
                        result=lease.capture()
                        if change=='appearance':
                            runtime.mkdir(mode=0o700)
                        elif change=='disappearance':
                            runtime.rmdir()
                        else:
                            runtime.rename(held)
                            runtime.mkdir(mode=0o700)
                        lease.recheck(result)
            finally:
                if held.exists():
                    runtime.rmdir()
                    held.rename(runtime)
                elif not runtime.exists():
                    runtime.mkdir(mode=0o700)

    def test_erase_runtime_mode_uid_type_and_dangling_link_refuse(self):
        runtime=self.root/'run/qshd'
        parent=self.root/'run'
        parent.chmod(0o000)
        try:
            with self.assertRaises(m.FilesError):
                with self.files().erase_inspection() as lease:
                    lease.capture()
        finally:
            parent.chmod(0o755)
        runtime.chmod(0o755)
        with self.assertRaises(m.FilesError):
            with self.files().erase_inspection() as lease:
                lease.capture()
        runtime.chmod(0o700)
        native_fstat=os.fstat
        def wrong_uid(fd):
            info=native_fstat(fd)
            if os.readlink('/proc/self/fd/'+str(fd))==str(runtime):
                values=list(info)
                values[4]=info.st_uid+1
                return os.stat_result(values)
            return info
        with patch.object(m.os,'fstat',side_effect=wrong_uid):
            with self.assertRaises(m.FilesError):
                with self.files().erase_inspection() as lease:
                    lease.capture()
        runtime.rmdir()
        for kind in ('regular','dangling-link','fifo'):
            if kind=='regular':
                runtime.write_bytes(b'not a directory')
            elif kind=='dangling-link':
                runtime.symlink_to(runtime.with_name('absent'))
            else:
                os.mkfifo(runtime)
            try:
                with self.subTest(kind=kind),self.assertRaises(m.FilesError):
                    with self.files().erase_inspection() as lease:
                        lease.capture()
            finally:
                runtime.unlink()
        runtime.mkdir(mode=0o700)

    def test_erase_absent_runtime_defaults_and_present_actual_labels_still_required(self):
        runtime=self.root/'run/qshd'
        runtime.rmdir()
        original=self.api.lookup
        for target in ('/run/qshd','/run/qshd/helper-status.sock.lock'):
            def lookup(path,kind):
                return 'system_u:object_r:wrong_t:s0' if path==target else original(path,kind)
            with patch.object(self.api,'lookup',side_effect=lookup):
                with self.subTest(target=target),self.assertRaises(m.FilesError):
                    with self.files().erase_inspection() as lease:
                        lease.capture()
        runtime.mkdir(mode=0o700)
        self.api.labels['/run/qshd']='system_u:object_r:wrong_t:s0'
        with self.assertRaises(m.FilesError):
            with self.files().erase_inspection() as lease:
                lease.capture()

    def test_erase_private_contents_unread_no_mutators_and_socket_never_opened(self):
        for name in ('etc/qshd','var/log/qshd'):
            (self.root/name).mkdir(mode=0o700)
        for name,data,mode in [('etc/qshd/host_key',b'x'*64,0o400),
                               ('var/log/qshd/qshd.log',b'synthetic private log',0o600),
                               ('run/qshd/helper-status.sock.lock',b'synthetic lock',0o600)]:
            path=self.root/name
            path.write_bytes(data)
            path.chmod(mode)
        native_read=os.read
        def read(fd,size):
            path=os.readlink('/proc/self/fd/'+str(fd))
            if path.endswith(('host_key','qshd.log','qshd.log.1','helper-status.sock.lock')):
                raise AssertionError('private content read')
            return native_read(fd,size)
        with ExitStack() as stack:
            stack.enter_context(patch.object(m.os,'read',side_effect=read))
            for name in ('mkdir','write','unlink','rename','chmod','fchmod','chown','fchown','setxattr','removexattr'):
                stack.enter_context(patch.object(m.os,name,side_effect=AssertionError('erase observer mutation')))
            with self.files().erase_inspection() as lease:
                result=lease.capture()
                lease.recheck(result)
        self.assertNotIn(b'synthetic private',repr(result).encode())
        expected=[(path,kind) for path,kind,context,required,role in m._PATHS if context is not None]
        self.assertEqual(self.api.lookups,expected*2)
        path=self.root/'run/qshd/helper-status.sock'
        native_open=os.open
        def opening(name,*args,**kwargs):
            if str(name).endswith('helper-status.sock'):
                raise AssertionError('socket opened')
            return native_open(name,*args,**kwargs)
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.bind(str(path))
            with patch.object(m.os,'open',side_effect=opening):
                with self.assertRaises(m.FilesError):
                    with self.files().erase_inspection() as lease:
                        lease.capture()
        path.unlink()

    def test_erase_required_binary_pam_and_optional_metadata_remain_strict(self):
        (self.root/'run/qshd').rmdir()
        for name in ('usr/bin/qshd','etc/pam.d/qshd'):
            path=self.root/name
            held=path.with_name('held')
            path.rename(held)
            try:
                with self.subTest(missing=name),self.assertRaises(m.FilesError):
                    with self.files().erase_inspection() as lease:
                        lease.capture()
            finally:
                held.rename(path)
        pam=self.root/'etc/pam.d/qshd'
        pam.write_bytes(b'custom PAM')
        with self.assertRaises(m.FilesError):
            with self.files().erase_inspection() as lease:
                lease.capture()
        pam.write_bytes(PAM)
        for name in ('etc/qshd','var/log/qshd','run/qshd'):
            (self.root/name).mkdir(mode=0o700)
        cases=[('etc/qshd/host_key',b'x'*63,0o400),
               ('var/log/qshd/qshd.log',b'log',0o644),
               ('run/qshd/helper-status.sock.lock',b'',0o644)]
        for name,data,mode in cases:
            path=self.root/name
            path.write_bytes(data)
            path.chmod(mode)
            try:
                with self.subTest(optional=name),self.assertRaises(m.FilesError):
                    with self.files().erase_inspection() as lease:
                        lease.capture()
            finally:
                path.unlink()

    def test_erase_exact_token_sequence_and_cross_method_nesting(self):
        files=self.files()
        for outer,inner in ((files.inspection,files.erase_inspection),(files.erase_inspection,files.inspection)):
            with outer() as lease:
                result=lease.capture()
                with self.assertRaises(m.FilesError):
                    with inner():
                        self.fail('cross-method nested lease admitted')
                lease.recheck(result)
        with self.assertRaises(m.FilesError):
            with files.erase_inspection() as lease:
                lease.capture()
        with files.erase_inspection() as lease:
            result=lease.capture()
            lease.recheck(result)
        with self.assertRaises(m.FilesError):
            lease.recheck(result)
        with self.assertRaises(m.FilesError):
            with files.erase_inspection() as other:
                other.capture()
                other.recheck(result)
        with self.assertRaises(m.FilesError):
            with files.erase_inspection() as other:
                token=other.capture()
                other.recheck(type(token)(token.phase,token.paths))
        with self.assertRaises(m.FilesError):
            with files.erase_inspection() as other:
                other.capture()
                other.capture()
        with self.assertRaises(m.FilesError):
            with files.inspection() as other:
                other.capture()
                other.recheck(result)

    def test_erase_interruption_final_readback_and_close_fault_release_descriptors(self):
        files=self.files()
        with self.assertRaises(KeyboardInterrupt):
            with files.erase_inspection() as lease:
                lease.capture()
                raise KeyboardInterrupt()
        self.assertEqual(len(os.listdir('/proc/self/fd')),self.fds)
        with self.assertRaises(m.FilesError):
            with files.erase_inspection() as lease:
                result=lease.capture()
                self.api.override='system_u:object_r:wrong_t:s0'
                lease.recheck(result)
        self.api.override=None
        original=self.api.file_defaults
        closes=0
        @contextmanager
        def close_failure():
            nonlocal closes
            with original() as defaults:
                yield defaults
            closes+=1
            if closes==2:
                raise RuntimeError('synthetic final native close failure')
        with patch.object(self.api,'file_defaults',close_failure):
            with self.assertRaises(m.FilesError):
                with files.erase_inspection() as lease:
                    result=lease.capture()
                    lease.recheck(result)
        self.assertEqual(closes,2)
        with files.erase_inspection() as lease:
            result=lease.capture()
            lease.recheck(result)


    def test_required_and_optional_absence_defaults_fresh_endpoints(self):
        before=set(self.root.rglob('*'))
        with self.files().inspection() as lease:
            result=lease.capture();lease.recheck(result)
        self.assertEqual(set(self.root.rglob('*')),before)
        self.assertEqual((self.api.opened,self.api.closed),(2,2))
        self.assertEqual(len(self.api.lookups),16) # eight eligible paths; PAM/socket deliberately excluded
        with self.assertRaises(Exception):result.paths=()
    def test_private_key_and_logs_are_never_read(self):
        for name in ('etc/qshd','var/log/qshd'):(self.root/name).mkdir(mode=0o700)
        for name,data,mode in (('etc/qshd/host_key',b'x'*64,0o400),('var/log/qshd/qshd.log',b'secret log',0o600)):
            path=self.root/name;path.write_bytes(data);path.chmod(mode)
        native_read=os.read
        def read(fd,size):
            path=os.readlink('/proc/self/fd/'+str(fd))
            if path.endswith(('host_key','qshd.log','qshd.log.1')):raise AssertionError('private content read')
            return native_read(fd,size)
        with patch.object(m.os,'read',side_effect=read):
            with self.files().inspection() as lease:
                result=lease.capture();lease.recheck(result)
        self.assertNotIn(b'secret',repr(result).encode())
    def test_each_required_path_missing_refuses(self):
        for name in ('usr/bin/qshd','etc/pam.d/qshd','run/qshd'):
            path=self.root/name;held=path.with_name('held');path.rename(held)
            try:
                with self.assertRaises(m.FilesError):
                    with self.files().inspection() as lease:lease.capture()
            finally:held.rename(path)
    def test_default_only_and_actual_only_full_context_mismatch(self):
        self.api.override='wrong_u:object_r:qshd_exec_t:s0'
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:lease.capture()
        self.api.override=None;self.api.labels['/usr/bin/qshd']='system_u:wrong_r:qshd_exec_t:s1'
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:lease.capture()
    def test_pam_mismatch_and_rpmnew_do_not_approve(self):
        (self.root/'etc/pam.d/qshd').write_bytes(b'old generic')
        (self.root/'etc/pam.d/qshd.rpmnew').write_bytes(PAM)
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:lease.capture()
    def test_optional_appearance_and_same_bytes_replacement_refuse(self):
        for change in ('appearance','replacement'):
            with self.assertRaises(m.FilesError):
                with self.files().inspection() as lease:
                    result=lease.capture()
                    if change=='appearance':(self.root/'etc/qshd').mkdir(mode=0o700)
                    else:
                        path=self.root/'usr/bin/qshd';new=path.with_name('new');new.write_bytes(path.read_bytes());new.chmod(0o755);new.replace(path)
                    lease.recheck(result)
            if change=='appearance':(self.root/'etc/qshd').rmdir()
    def test_socket_is_never_opened_and_existing_socket_refuses(self):
        path=self.root/'run/qshd/helper-status.sock'
        with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
            sock.bind(str(path))
            with self.assertRaises(m.FilesError):
                with self.files().inspection() as lease:lease.capture()
        path.unlink()
    def test_missing_recheck_double_capture_foreign_and_closed_refuse(self):
        files=self.files()
        with self.assertRaises(m.FilesError):
            with files.inspection() as lease:result=lease.capture()
        with self.assertRaises(m.FilesError):lease.recheck(result)
        with self.assertRaises(m.FilesError):
            with files.inspection() as other:other.recheck(result)
        with self.assertRaises(m.FilesError):
            with files.inspection() as other:other.capture();other.capture()
    def test_metadata_drift_and_unsafe_authority_refuse(self):
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:
                result=lease.capture();(self.root/'usr/bin/qshd').chmod(0o700);lease.recheck(result)
        (self.root/'usr/bin/qshd').chmod(0o777)
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:lease.capture()
    def test_no_mutator_and_exact_label_vectors(self):
        with ExitStack() as stack:
            for name in ('mkdir','write','unlink','rename','chmod','fchmod','chown','fchown','setxattr','removexattr'):
                stack.enter_context(patch.object(m.os,name,side_effect=AssertionError('observer mutator')))
            with self.files().inspection() as lease:
                result=lease.capture();lease.recheck(result)
        expected=[(path,kind) for path,kind,context,required,role in m._PATHS if context is not None]
        self.assertEqual(self.api.lookups,expected*2)
    def test_key_size_private_modes_and_status_lock(self):
        (self.root/'etc/qshd').mkdir(mode=0o755)
        key=self.root/'etc/qshd/host_key';key.write_bytes(b'x'*64);key.chmod(0o400)
        lock=self.root/'run/qshd/helper-status.sock.lock';lock.write_bytes(b'');lock.chmod(0o600)
        with self.files().inspection() as lease:
            result=lease.capture();lease.recheck(result)
        key.chmod(0o600);key.write_bytes(b'x'*63)
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:lease.capture()
        key.write_bytes(b'x'*64);key.chmod(0o640)
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:lease.capture()
    def test_symlink_hardlink_and_fifo_refuse_without_opening_special(self):
        path=self.root/'usr/bin/qshd';saved=path.read_bytes();path.unlink()
        for kind in ('symlink','hardlink','fifo'):
            if kind=='symlink':path.symlink_to(self.root/'etc/pam.d/qshd')
            elif kind=='hardlink':os.link(self.root/'etc/pam.d/qshd',path)
            else:os.mkfifo(path)
            try:
                with self.assertRaises(m.FilesError):
                    with self.files().inspection() as lease:lease.capture()
            finally:path.unlink()
        path.write_bytes(saved);path.chmod(0o755)
    def test_post_open_failure_closes_actual_acquired_fd(self):
        original=m._Inspection._open;native_fstat=os.fstat;target=[];failed=False
        def opening(lease,*args,**kwargs):
            fd=original(lease,*args,**kwargs);target.append(fd);return fd
        def failure(fd):
            nonlocal failed
            if fd in target and not failed:
                failed=True;raise OSError(errno.EIO,'injected')
            return native_fstat(fd)
        with patch.object(m._Inspection,'_open',opening),patch.object(m.os,'fstat',side_effect=failure):
            with self.assertRaises(m.FilesError):
                with self.files().inspection() as lease:lease.capture()
        self.assertTrue(failed)
        for fd in target:
            with self.assertRaises(OSError):native_fstat(fd)
    def test_final_default_drift_and_native_close_failure_refuse(self):
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:
                result=lease.capture();self.api.override='system_u:object_r:wrong_t:s0';lease.recheck(result)
        self.api.override=None
        original=self.api.file_defaults
        @contextmanager
        def close_failure():
            with original() as defaults:yield defaults
            raise RuntimeError('native close failure')
        self.api.file_defaults=close_failure
        with self.assertRaises(m.FilesError):
            with self.files().inspection() as lease:lease.capture()
    def test_body_interruption_and_nested_lease_close_all_fds(self):
        files=self.files()
        with self.assertRaises(KeyboardInterrupt):
            with files.inspection() as lease:
                lease.capture()
                with self.assertRaises(m.FilesError):
                    with files.inspection():pass
                raise KeyboardInterrupt()
        self.assertEqual(len(os.listdir('/proc/self/fd')),self.fds)
    def test_canonical_asset_hash_and_generic_asset_unchanged(self):
        import hashlib
        directory=Path(__file__).resolve().parents[2]/'packaging/pam.d'
        self.assertEqual(hashlib.sha256((directory/'qshd.fedora-selinux').read_bytes()).hexdigest(),m.PAM_SHA256)
        self.assertEqual(hashlib.sha256((directory/'qshd.fedora').read_bytes()).hexdigest(),
                         '17a767ada29218d54cf475d80399993d489fee4251f7c99d1b93a62a7c22ddc7')
    def test_production_expected_bytes_cannot_be_installed_self_trust(self):
        with self.assertRaises(m.FilesError):m.production(PAM,self.api)

if __name__=='__main__':unittest.main()
