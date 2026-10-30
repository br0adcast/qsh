"""Actual temporary filesystem controls; commands are injected, never semodule."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import errno
import ast
import inspect
import textwrap

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'packaging/selinux'))
from qshd_selinux_activation import TrustedArtifact
import qshd_selinux_module_observer as m

PP = b'independently supplied test policy'
TRUST = TrustedArtifact('1', 'a'*64, hashlib.sha256(PP).hexdigest())


class ObserverTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for name in ('usr/bin','etc/selinux','var/lib/selinux/targeted/active/modules','run'):
            (self.root/name).mkdir(parents=True, exist_ok=True)
        for name, data, mode in (('usr/bin/semodule',b'executable',0o755),('etc/selinux/semanage.conf',b'# trusted config\n',0o644),('var/lib/selinux/targeted/semanage.read.LOCK',b'',0o600)):
            (self.root/name).write_bytes(data);(self.root/name).chmod(mode)
        for path in self.root.rglob('*'):
            if path.is_dir():path.chmod(0o755)
        self.calls=[];self.action=None
    def tearDown(self):self.tmp.cleanup()
    def runner(self, operation, cwd):
        self.calls.append((operation,Path(cwd)))
        if self.action is not None:
            result=self.action(operation,Path(cwd))
            if result is not None:return result
        if operation=='list':return b'100 base cil\n400 qshd pp\n'
        (Path(cwd)/'qshd.pp').write_bytes(PP);(Path(cwd)/'qshd.pp').chmod(0o600)
        return b''
    def observer(self):return m._testing_observer(TRUST,self.root,self.runner)
    def test_four_calls_and_fresh_scratch_cleanup(self):
        with self.observer() as lease:
            result=lease.capture();lease.recheck(result)
        self.assertEqual([x[0] for x in self.calls],['list','extract','list','extract'])
        self.assertNotEqual(self.calls[1][1],self.calls[3][1])
        self.assertEqual(list((self.root/'run').iterdir()),[])
    def test_every_missing_bootstrap_input_refuses_before_command(self):
        for name in ('usr/bin/semodule','etc/selinux/semanage.conf','var/lib/selinux/targeted/semanage.read.LOCK','var/lib/selinux/targeted/active/modules','var/lib/selinux/targeted/active','var/lib/selinux/targeted'):
            path=self.root/name;held=path.with_name(path.name+'.held');path.rename(held)
            try:
                with self.assertRaises(m.ObserverError):
                    with self.observer():pass
                self.assertEqual(self.calls,[])
            finally:held.rename(path)
    def test_conflict_never_extracts_and_poison_is_sticky(self):
        self.action=lambda op,cwd:b'400 qshd pp\n500 qshd pp\n' if op=='list' else None
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:
                with self.assertRaises(m.ObserverError):lease.capture()
                lease.capture()
        self.assertEqual([x[0] for x in self.calls],['list'])
    def test_same_bytes_replacement_and_config_drift_refuse(self):
        for name in ('usr/bin/semodule','etc/selinux/semanage.conf'):
            self.calls=[]
            with self.assertRaises(m.ObserverError):
                with self.observer() as lease:
                    result=lease.capture();path=self.root/name
                    other=path.with_name(path.name+'.new');other.write_bytes(path.read_bytes());other.chmod(path.stat().st_mode & 0o777);other.replace(path)
                    lease.recheck(result)
            self.assertEqual(len(self.calls),2)
    def test_wrong_hll_and_missing_recheck_refuse(self):
        def wrong(op,cwd):
            if op=='extract':(cwd/'qshd.pp').write_bytes(b'wrong');(cwd/'qshd.pp').chmod(0o600);return b''
        self.action=wrong
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:lease.capture()
        self.action=None
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:lease.capture()
    def test_foreign_double_closed_and_frozen_evidence(self):
        with self.observer() as first:
            result=first.capture()
            with self.assertRaises(Exception):result.pp_sha256='b'*64
            first.recheck(result)
        with self.assertRaises(m.ObserverError):first.recheck(result)
        with self.assertRaises(m.ObserverError):
            with self.observer() as other:other.recheck(result)
        with self.assertRaises(m.ObserverError):
            with self.observer() as other:
                other.capture();other.capture()
    def test_unsafe_modes_and_symlinks_refuse(self):
        path=self.root/'etc/selinux/semanage.conf';path.chmod(0o666)
        with self.assertRaises(m.ObserverError):
            with self.observer():pass
        self.assertEqual(self.calls,[])
        path.chmod(0o644);path.unlink();path.symlink_to('elsewhere')
        with self.assertRaises(m.ObserverError):
            with self.observer():pass
        self.assertEqual(self.calls,[])
    def test_unknown_scratch_entry_is_preserved_and_refuses(self):
        def extra(op,cwd):
            if op=='extract':(cwd/'unknown').write_bytes(b'keep')
        self.action=extra
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:lease.capture()
        self.assertTrue(list((self.root/'run').rglob('unknown')))
    def test_completed_updates_before_capture_form_fresh_baseline(self):
        with self.observer() as lease:
            path=self.root/'usr/bin/semodule'
            path.write_bytes(b'updated installed executable')
            result=lease.capture();lease.recheck(result)
    def test_store_route_rebinding_refuses_before_command(self):
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:
                result=lease.capture()
                path=self.root/'var/lib/selinux/targeted/active/modules'
                path.rename(path.with_name('held'));path.mkdir(mode=0o700)
                lease.recheck(result)
        self.assertEqual(len(self.calls),2)
    def test_hll_symlink_and_hardlink_preserve_unsafe_names(self):
        for kind in ('symlink','hardlink'):
            def unsafe(op,cwd):
                if op=='extract':
                    source=self.root/'usr/bin/semodule'
                    if kind=='symlink':(cwd/'qshd.pp').symlink_to(source)
                    else:os.link(source,cwd/'qshd.pp')
                    return b''
            self.action=unsafe
            with self.assertRaises(m.ObserverError):
                with self.observer() as lease:lease.capture()
            for path in (self.root/'run').rglob('qshd.pp'):path.unlink()
            for path in sorted((self.root/'run').rglob('*'),reverse=True):
                if path.is_dir():path.rmdir()
    def test_cleanup_rebinding_preserves_foreign_output(self):
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:
                result=lease.capture();lease.recheck(result)
                path=self.calls[1][1]/'qshd.pp'
                replacement=path.with_name('replacement');replacement.write_bytes(b'foreign');replacement.replace(path)
        self.assertTrue(any(path.read_bytes()==b'foreign' for path in (self.root/'run').rglob('qshd.pp')))
    def test_recheck_none_and_recheck_twice_refuse(self):
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:lease.recheck(None)
        self.assertEqual(self.calls,[])
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:
                result=lease.capture();lease.recheck(result);lease.recheck(result)
        self.assertEqual(len(self.calls),4)
    def test_in_place_configuration_drift_refuses_without_raw_error(self):
        with self.assertRaises(m.ObserverError) as failure:
            with self.observer() as lease:
                result=lease.capture()
                (self.root/'etc/selinux/semanage.conf').write_bytes(b'private configuration')
                lease.recheck(result)
        self.assertNotIn(str(self.root),str(failure.exception))
        self.assertNotIn('private',str(failure.exception))
        self.assertEqual(len(self.calls),2)
    def test_failed_admission_and_success_close_all_descriptors(self):
        before=len(os.listdir('/proc/self/fd'))
        with self.observer() as lease:
            result=lease.capture();lease.recheck(result)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        with self.assertRaises(m.ObserverError):lease.__exit__(None,None,None)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        (self.root/'etc/selinux/semanage.conf').chmod(0o666)
        with self.assertRaises(m.ObserverError):
            with self.observer():pass
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
    def test_command_failure_preserved_without_retry(self):
        def failure(op,cwd):raise m._CommandError('TOOL_FAILURE')
        self.action=failure
        with self.assertRaises(m.ObserverError):
            with self.observer() as lease:
                with self.assertRaises(m.ObserverError):lease.capture()
        self.assertEqual(len(self.calls),1)
        self.assertEqual(list((self.root/'run').iterdir()),[])
    def test_scratch_post_open_fstat_failure_closes_acquired_fd(self):
        before=len(os.listdir('/proc/self/fd'));opened=[]
        native_open=os.open;native_fstat=os.fstat;failed=False
        def opening(name,*args,**kwargs):
            fd=native_open(name,*args,**kwargs)
            if str(name).startswith('qshd-module-'):opened.append(fd)
            return fd
        def failing(fd):
            nonlocal failed
            if fd in opened and not failed:
                failed=True;raise OSError(errno.EIO,'injected')
            return native_fstat(fd)
        try:
            with patch.object(m.os,'open',side_effect=opening),patch.object(m.os,'fstat',side_effect=failing):
                with self.assertRaises(m.ObserverError):
                    with self.observer():pass
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
            self.assertTrue(list((self.root/'run').iterdir()))
        finally:
            for fd in opened:
                try:native_fstat(fd)
                except OSError:continue
                os.close(fd)
    def test_hll_post_open_fstat_failure_closes_acquired_fd(self):
        before=len(os.listdir('/proc/self/fd'));opened=[];count=0;failed=False
        original=m.ModuleObserver._open;native_fstat=os.fstat
        def opening(lease,parent,name,**kwargs):
            nonlocal count
            fd=original(lease,parent,name,**kwargs)
            if name=='qshd.pp':
                count+=1
                if count==2:opened.append(fd)
            return fd
        def failing(fd):
            nonlocal failed
            if fd in opened and not failed:
                failed=True;raise OSError(errno.EIO,'injected')
            return native_fstat(fd)
        try:
            with patch.object(m.ModuleObserver,'_open',opening),patch.object(m.os,'fstat',side_effect=failing):
                with self.assertRaises(m.ObserverError):
                    with self.observer() as lease:lease.capture()
            self.assertEqual(len(os.listdir('/proc/self/fd')),before)
            self.assertTrue(list((self.root/'run').rglob('qshd.pp')))
        finally:
            for fd in opened:
                try:native_fstat(fd)
                except OSError:continue
                os.close(fd)
    def test_platform_fields_refuse_all_duplicates(self):
        tree=ast.parse(textwrap.dedent(inspect.getsource(m.ModuleObserver.__enter__)))
        gate=next(node for node in ast.walk(tree) if isinstance(node,ast.If)
                  and 'fields' in ast.unparse(node.test))
        code=compile(ast.Expression(gate.test),'<platform-predicate>','eval')
        def refused(data):return eval(code,{},dict(fields=data.splitlines()))
        self.assertFalse(refused(b'ID=fedora\nVERSION_ID=44\n'))
        for data in (b'ID=fedora\nID=other\nVERSION_ID=44\n',
                     b'ID=fedora\nID=fedora\nVERSION_ID=44\n',
                     b'ID=fedora\nVERSION_ID=44\nVERSION_ID=45\n',
                     b'ID=fedora\nVERSION_ID=44\nVERSION_ID=44\n'):
            self.assertTrue(refused(data))
    def test_caller_error_cleans_scratch(self):
        with self.assertRaisesRegex(RuntimeError,'caller'):
            with self.observer() as lease:
                lease.capture();raise RuntimeError('caller')
        self.assertEqual(list((self.root/'run').iterdir()),[])
    def test_unrelated_listing_changes_and_lock_timestamps_allowed(self):
        with self.observer() as lease:
            result=lease.capture()
            os.utime(self.root/'var/lib/selinux/targeted/semanage.read.LOCK',None)
            self.action=lambda op,cwd:b'200 unrelated cil\n400 qshd pp\n' if op=='list' else None
            lease.recheck(result)

if __name__=='__main__':unittest.main()
