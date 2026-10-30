"""Real private filesystem and harmless child controls; never host state/policy."""
import errno
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'packaging/selinux'))
import qshd_selinux_package_state as package


class PackageStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.anchor = Path(self.temp.name)
        self.common = self.anchor / 'qshd'

    def state(self):
        return package.PackageState(self.common, uid=os.getuid(), anchor=self.anchor)

    def test_fresh_layout_and_idempotent_document_preservation(self):
        state = self.state()
        with state.initialize():
            for path, mode in ((self.common, 0o700), (self.common/'selinux-package.lock', 0o600),
                               (self.common/'selinux-activation', 0o700),
                               (self.common/'selinux-activation/lock', 0o600)):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), mode)
            self.assertFalse((self.common/'selinux-contexts').exists())
            self.assertFalse((self.common/'selinux-activation/activation.json').exists())
        lock = self.common/'selinux-package.lock'
        inode = lock.stat().st_ino
        document = self.common/'selinux-activation/activation.json'
        document.write_bytes(b'opaque public bytes: initializer does not parse readiness')
        document.chmod(0o600)
        with self.state().initialize():
            self.assertEqual(lock.stat().st_ino, inode)
        self.assertEqual(document.read_bytes(), b'opaque public bytes: initializer does not parse readiness')

    def test_existing_protected_common_preserves_unrelated_state_and_mode(self):
        self.common.mkdir(mode=0o755)
        unrelated = self.common/'other-state'
        unrelated.write_bytes(b'public unrelated state')
        before = unrelated.stat().st_ino
        with self.state().initialize():
            self.assertEqual(stat.S_IMODE(self.common.stat().st_mode), 0o755)
        self.assertEqual(unrelated.read_bytes(), b'public unrelated state')
        self.assertEqual(unrelated.stat().st_ino, before)

    def test_operation_never_provisions_and_real_package_contention_is_busy(self):
        with self.assertRaises(package.PackageStateError):
            with self.state().operation():
                self.fail('missing operation state accepted')
        self.assertFalse(self.common.exists())
        with self.state().initialize():
            with self.assertRaisesRegex(package.PackageStateError, '^BUSY$'):
                with self.state().operation():
                    self.fail('second independent lock description accepted')
        with self.state().operation():
            pass

    def test_partial_activation_and_unknown_stage_are_preserved(self):
        self.common.mkdir(mode=0o700)
        activation = self.common/'selinux-activation'
        activation.mkdir(mode=0o700)
        with self.assertRaisesRegex(package.PackageStateError, '^PARTIAL_STATE$'):
            with self.state().initialize():
                self.fail('partial initialized')
        self.assertFalse((activation/'lock').exists())
        (activation/'lock').write_bytes(b'')
        (activation/'lock').chmod(0o600)
        unknown = activation/'orphan-stage'
        unknown.write_bytes(b'preserve this unknown public object')
        with self.assertRaisesRegex(package.PackageStateError, '^PARTIAL_STATE$'):
            with self.state().initialize():
                self.fail('unknown stage adopted')
        self.assertEqual(unknown.read_bytes(), b'preserve this unknown public object')

    def test_invalid_inputs_and_root_gate_do_not_open_host_paths(self):
        for common, options in (("relative", {}), (str(self.common)+"\0", {}),
                                (self.common, {'uid':True}), (self.common, {'hook':1})):
            with self.subTest(common=repr(common)), self.assertRaises(package.PackageStateError):
                package.PackageState(common, **options)
        with mock.patch.object(package.os, 'geteuid', return_value=1), \
             mock.patch.object(package.os, 'open', side_effect=AssertionError('host path opened')), \
             self.assertRaisesRegex(package.PackageStateError, '^ROOT_REQUIRED$'):
            package.production()

    def test_unsafe_lock_types_modes_and_document_metadata_are_preserved(self):
        for kind in ('symlink', 'fifo', 'hardlink', 'mode'):
            common = self.anchor/kind
            common.mkdir(mode=0o700)
            foreign = self.anchor/(kind+'-foreign')
            foreign.write_bytes(b'public foreign content')
            lock = common/'selinux-package.lock'
            if kind=='symlink':lock.symlink_to(foreign)
            elif kind=='fifo':os.mkfifo(lock,0o600)
            elif kind=='hardlink':os.link(foreign,lock)
            else:lock.write_bytes(b'');lock.chmod(0o644)
            with self.subTest(kind=kind), self.assertRaises(package.PackageStateError):
                with package.PackageState(common,uid=os.getuid(),anchor=self.anchor).initialize():pass
            self.assertEqual(foreign.read_bytes(), b'public foreign content')
            self.assertFalse((common/'selinux-activation').exists())
        with self.state().initialize():pass
        document=self.common/'selinux-activation/activation.json'
        document.symlink_to(self.anchor/'not-owned')
        with self.assertRaises(package.PackageStateError):
            with self.state().initialize():pass
        self.assertTrue(document.is_symlink())

    def test_named_lock_substitution_refuses_and_preserves_both_objects(self):
        with self.state().initialize():pass
        lock=self.common/'selinux-package.lock'
        held=self.common/'retained-original-lock'
        with self.assertRaisesRegex(package.PackageStateError, '^FILE_BINDING$'):
            with self.state().operation():
                lock.rename(held)
                lock.write_bytes(b'foreign public lock');lock.chmod(0o600)
        self.assertEqual(held.read_bytes(), b'')
        self.assertEqual(lock.read_bytes(), b'foreign public lock')

    def test_partial_creation_fault_and_new_file_fstat_failure_close_owned_fds(self):
        def interrupted(event):
            if event=='activation_mkdir':raise OSError(errno.EIO,'injected')
        with self.assertRaises(package.PackageStateError):
            with package.PackageState(self.common,uid=os.getuid(),anchor=self.anchor,hook=interrupted).initialize():pass
        activation=self.common/'selinux-activation'
        self.assertTrue(activation.is_dir());self.assertFalse((activation/'lock').exists())
        with self.assertRaisesRegex(package.PackageStateError, '^PARTIAL_STATE$'):
            with self.state().initialize():pass
        common=self.anchor/'fd-fault';opened=[];target=[];native_open=os.open;native_stat=os.fstat
        def opening(name,*args,**kwargs):
            fd=native_open(name,*args,**kwargs);opened.append(fd)
            if name=='selinux-package.lock':target.append(fd)
            return fd
        def broken(fd):
            if fd in target:raise OSError(errno.EIO,'post-open')
            return native_stat(fd)
        with mock.patch.object(package.os,'open',side_effect=opening), \
             mock.patch.object(package.os,'fstat',side_effect=broken),self.assertRaises(package.PackageStateError):
            with package.PackageState(common,uid=os.getuid(),anchor=self.anchor).initialize():pass
        for fd in set(opened):
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertTrue((common/'selinux-package.lock').is_file())
        with package.PackageState(common,uid=os.getuid(),anchor=self.anchor).initialize():pass

    def test_close_failure_attempts_all_descriptors_and_poisoned_instance_refuses(self):
        state=self.state();native_close=os.close;failed=[]
        target=None
        def close(fd):
            if fd==target:failed.append(fd);raise OSError(errno.EIO,'before-close')
            return native_close(fd)
        with mock.patch.object(package.os,'close',side_effect=close):
            with self.assertRaisesRegex(package.PackageStateError, '^CLOSE_FAILED$'):
                with state.initialize():target=state._package_lock
        self.assertEqual(failed,[target])
        os.close(target)  # Test-owned injected failure deliberately left this exact FD open.
        with self.assertRaisesRegex(package.PackageStateError, '^CLOSE_FAILED$'):
            with state.operation():pass
        with self.state().operation():pass

    def test_real_child_keeps_package_excluded_but_can_take_inner_locks(self):
        with self.state().initialize():pass
        context=self.common/'selinux-contexts';context.mkdir(mode=0o700)
        (context/'lock').write_bytes(b'');(context/'lock').chmod(0o600)
        source=str(Path(package.__file__).parent)
        body=r'''import fcntl,os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import qshd_selinux_package_state as p
common=Path(sys.argv[2]);anchor=common.parent
try:
 with p.PackageState(common,uid=os.getuid(),anchor=anchor).operation():raise AssertionError('package exclusion lost')
except p.PackageStateError as e:assert str(e)=='BUSY'
expected=(int(sys.argv[3]),int(sys.argv[4]))
for entry in Path('/proc/self/fd').iterdir():
 try:s=os.fstat(int(entry.name))
 except OSError:continue
 assert (s.st_dev,s.st_ino)!=expected,'parent package FD inherited'
for name in ('selinux-activation','selinux-contexts'):
 fd=os.open(common/name/'lock',os.O_RDONLY)
 try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
 finally:os.close(fd)
print('excluded-package; inner-locks-free; no-inherited-package-fd')
'''
        with self.state().operation():
            info=(self.common/'selinux-package.lock').stat()
            child=subprocess.run([sys.executable,'-I','-B','-c',body,source,str(self.common),str(info.st_dev),str(info.st_ino)],
                                 stdin=subprocess.DEVNULL,capture_output=True,text=True,timeout=5)
            self.assertEqual(child.returncode,0,child.stderr)
            self.assertIn('inner-locks-free',child.stdout)

    def test_complete_layout_retries_after_fsync_failure_without_replacing_lock(self):
        native_sync=os.fsync;failed=[]
        activation_lock=self.common/'selinux-activation/lock'
        def fsync(fd):
            if activation_lock.exists() and os.fstat(fd).st_ino==activation_lock.stat().st_ino and not failed:
                failed.append(True);raise OSError(errno.EIO,'injected sync')
            native_sync(fd)
        with mock.patch.object(package.os,'fsync',side_effect=fsync),self.assertRaises(package.PackageStateError):
            with self.state().initialize():pass
        inode=activation_lock.stat().st_ino
        with self.state().initialize():pass
        self.assertEqual(activation_lock.stat().st_ino,inode)
        self.assertEqual(activation_lock.read_bytes(),b'')

    def test_retry_syncs_existing_package_lock_after_its_initial_sync_failure(self):
        lock=self.common/'selinux-package.lock'
        self._retry_sync_failure(lock)

    def test_retry_syncs_common_parent_after_new_common_parent_sync_failure(self):
        self._retry_sync_failure(self.anchor)

    def _retry_sync_failure(self, target):
        native_sync=os.fsync
        failed=[]
        def fault(fd):
            if target.exists() and os.fstat(fd).st_ino==target.stat().st_ino and not failed:
                failed.append(True)
                raise OSError(errno.EIO,'injected durability edge')
            native_sync(fd)
        with mock.patch.object(package.os,'fsync',side_effect=fault),self.assertRaises(package.PackageStateError):
            with self.state().initialize():pass
        self.assertEqual(failed,[True])
        before={p:(p.stat().st_ino,stat.S_IMODE(p.stat().st_mode),p.read_bytes() if p.is_file() else None)
                for p in [self.common,*self.common.rglob('*')]}
        synced=[]
        def record(fd):
            synced.append(os.fstat(fd).st_ino)
            native_sync(fd)
        with mock.patch.object(package.os,'fsync',side_effect=record):
            with self.state().initialize():pass
        self.assertIn(target.stat().st_ino,synced)
        for p,value in before.items():
            self.assertEqual((p.stat().st_ino,stat.S_IMODE(p.stat().st_mode),p.read_bytes() if p.is_file() else None),value)

    def test_operation_is_only_a_lease_and_optional_document_is_bounded(self):
        self.common.mkdir(mode=0o700)
        lock=self.common/'selinux-package.lock';lock.write_bytes(b'');lock.chmod(0o600)
        with self.state().operation():pass
        self.assertEqual({p.name for p in self.common.iterdir()},{'selinux-package.lock'})
        with self.state().initialize():pass
        document=self.common/'selinux-activation/activation.json'
        with document.open('wb') as stream:stream.truncate(package.ACTIVATION_LIMIT+1)
        document.chmod(0o600)
        with self.assertRaisesRegex(package.PackageStateError,'^STATE_LIMIT$'):
            with self.state().initialize():pass
        self.assertEqual(document.stat().st_size,package.ACTIVATION_LIMIT+1)

    def test_concurrent_initializers_share_one_persistent_inode_under_private_umask(self):
        import select
        source=str(Path(package.__file__).parent)
        body=r'''import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[1])
import qshd_selinux_package_state as p
os.umask(0o077)
common=Path(sys.argv[2])
try:
 with p.PackageState(common,uid=os.getuid(),anchor=common.parent).initialize():
  print('ACQUIRED',flush=True)
  assert sys.stdin.readline()=='release\n'
except p.PackageStateError as e:
 assert str(e)=='BUSY',str(e)
 print('BUSY',flush=True)
'''
        children=[]
        try:
            for _ in range(2):
                children.append(subprocess.Popen([sys.executable,'-I','-B','-c',body,source,str(self.common)],
                    stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True))
            outcomes=[]
            for child in children:
                ready,_,_=select.select([child.stdout],[],[],5)
                self.assertTrue(ready,'owned initializer readiness deadline')
                outcomes.append(child.stdout.readline().strip())
            self.assertEqual(set(outcomes),{'ACQUIRED','BUSY'})
            inode=(self.common/'selinux-package.lock').stat().st_ino
        finally:
            settled=[]
            for child in children:
                try:out,err=child.communicate('release\n',timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill();out,err=child.communicate(timeout=5)
                settled.append((child.returncode,err))
            # Attempt every owned child's settlement before checking outcomes.
            for code,err in settled:self.assertEqual(code,0,err)
        self.assertEqual((self.common/'selinux-package.lock').stat().st_ino,inode)
        with self.state().operation():pass

    def test_caller_refusal_is_not_reclassified_and_lease_releases(self):
        class CallerRefusal(ValueError):pass
        with self.assertRaisesRegex(CallerRefusal,'^public-caller-refusal$'):
            with self.state().initialize():raise CallerRefusal('public-caller-refusal')
        with self.state().operation():pass


if __name__ == '__main__':
    unittest.main()
