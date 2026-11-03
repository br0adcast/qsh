"""Real temporary metadata/FDs with injected SELinux; no host label writes."""
from contextlib import contextmanager
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'packaging/selinux'
sys.path.insert(0,str(SOURCE))


def module():
    path=SOURCE/'qshd_selinux_retained_labels.py'
    assert path.is_file(),'retained-label primitive missing'
    import qshd_selinux_retained_labels
    return qshd_selinux_retained_labels


class RetainedLabelsTests(unittest.TestCase):
    def test_absent_inventory_exact_token_lifecycle(self):
        m=module()
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            for item in ('etc','var/log','run'):(root/item).mkdir(parents=True,exist_ok=True)
            for item in root.rglob('*'):
                if item.is_dir():item.chmod(0o755)
            (root/'var/run').symlink_to('../run')
            class Api:
                @contextmanager
                def status_observation(self):yield
                @contextmanager
                def file_defaults(self):yield self
                def lookup(self,path,kind):raise AssertionError('no absent target defaults')
            factory=m.RetainedLabels(_root=root,_uid=os.getuid(),_api_factory=Api,_clock=lambda:100.0)
            with factory.inspection(deadline=120) as scope:
                observed=scope.capture()
                self.assertEqual(len(observed.paths),7)
                self.assertTrue(all(not item.present for item in observed.paths))
                scope.recheck_before_removal(observed)
                restored=scope.restore_defaults(observed)
                scope.recheck_restored(restored)
            self.assertFalse((root/'etc/qshd').exists())


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.m=module();self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for path in ('etc/qshd','var/log/qshd','run/qshd'):(self.root/path).mkdir(parents=True,exist_ok=True)
        for path in self.root.rglob('*'):
            if path.is_dir():path.chmod(0o700 if path==self.root/'run/qshd' else 0o755)
        (self.root/'var/run').symlink_to('../run')
        for name,data,mode in [('etc/qshd/host_key',b'k'*64,0o400),('var/log/qshd/qshd.log',b'private log',0o600),('var/log/qshd/qshd.log.1',b'old private log',0o600),('run/qshd/helper-status.sock.lock',b'private lock',0o600)]:
            path=self.root/name;path.write_bytes(data);path.chmod(mode)
        self.labels={};self.extra={};self.events=[];self.now=100.;self.after=False;self.set_count=0
        self.fail_set=None;self.evm=False;self.default_drift=False;self.bad_default=None
        self.fds=set(os.listdir('/proc/self/fd'));self.addCleanup(lambda:self.assertEqual(set(os.listdir('/proc/self/fd')),self.fds))
        for path,kind,role,label in self.m._ITEMS:
            physical=self.root/path[1:];key=(physical.stat().st_dev,physical.stat().st_ino)
            self.labels[key]=label.encode()+b'\0'
            mode=physical.stat().st_mode & 0o777
            if physical.is_file():physical.chmod(0o600)
            os.setxattr(physical,'user.fixture',b'preserved');physical.chmod(mode)
        self.factory=self.make_factory()

    def key(self,fd):
        info=os.fstat(fd);return info.st_dev,info.st_ino

    def make_factory(self,**kw):
        return self.m.RetainedLabels(_root=self.root,_uid=os.getuid(),_api_factory=self.api,
            _clock=lambda:self.now,_getxattr=self.get,_listxattr=self.names,_setxattr=self.set,**kw)

    def names(self,fd):return os.listxattr(fd)+['security.selinux']+list(self.extra.get(self.key(fd),{}))
    def get(self,fd,name):
        if name=='security.selinux':return self.labels[self.key(fd)]
        if name in self.extra.get(self.key(fd),{}):return self.extra[self.key(fd)][name]
        return os.getxattr(fd,name)
    def set(self,fd,name,value,flags):
        self.assertIs(type(fd),int);self.assertEqual((name,flags),('security.selinux',os.XATTR_REPLACE))
        self.assertTrue(self.after);self.set_count+=1;self.events.append(('set',self.set_count))
        if self.fail_set==self.set_count:raise OSError('controlled setter refusal')
        self.labels[self.key(fd)]=value
        # Simulate the ctime transition of a label change on a real held FD.
        os.fchmod(fd,os.fstat(fd).st_mode & 0o777)
        if self.evm:self.extra[self.key(fd)]={'security.evm':b'collateral change'}

    def api(self):
        outer=self;identity=object()
        class Api:
            @contextmanager
            def status_observation(self):
                outer.events.append(('status enter',identity))
                try:yield
                finally:
                    outer.events.append(('status exit',identity))
                    if getattr(outer,'status_fail',False):raise RuntimeError('status finalizer')
            @contextmanager
            def file_defaults(self):
                outer.events.append(('defaults enter',identity));yield self
                outer.events.append(('defaults exit',identity))
            def lookup(self,path,kind):
                outer.events.append(('lookup',path))
                if outer.bad_default==path:raise RuntimeError('missing default')
                if not outer.after:return next(row[3] for row in outer.m._ITEMS if row[0]==path)
                suffix='changed_t' if outer.default_drift else 'etc_t'
                return 'system_u:object_r:'+suffix+':s0'
            def file_context(self,fd):
                raw=outer.labels[outer.key(fd)].removesuffix(b'\0').decode()
                if outer.after and raw.split(':')[2].startswith('qshd_'):raise RuntimeError('obsolete type')
                return raw
            def check_context(self,text):outer.m._context(text)
        return Api()

    def ready(self,scope):
        observed=scope.capture();scope.recheck_before_removal(observed);self.after=True;return observed

    def complete(self,scope,observed):
        result=scope.restore_defaults(observed);scope.recheck_restored(result);return result

    def test_present_restore_same_fds_all_defaults_first_and_metadata_preserved(self):
        with self.factory.inspection(deadline=120) as scope:
            observed=self.ready(scope);self.assertEqual(len(observed.paths),7)
            before=[item.metadata for item in observed.paths]
            result=self.complete(scope,observed)
            self.assertEqual(self.set_count,7)
            self.assertTrue(all(self.m._Inspection._preserved(a,b.metadata) for a,b in zip(before,result.paths)))
            events=self.events;first=next(i for i,x in enumerate(events) if x[0]=='set')
            old_closed=[x for x in events[:first] if x[0]=='status exit']
            self.assertEqual(len(old_closed),2)
            self.assertEqual(len([x for x in events[:first] if x[0]=='lookup']),21)
            self.assertEqual(len([x for x in events if x[0]=='defaults enter']),4)
            self.assertEqual(len([x for x in events if x[0]=='status enter']),3)
            self.assertEqual(len([x for x in events if x[0]=='status exit']),3)

    def test_unknown_children_and_unsafe_leaf_types_never_write(self):
        cases=('unknown','socket-name','rotation','symlink','hardlink','fifo','mode','runtime-mode','alias')
        for mode in cases:
            with self.subTest(mode=mode):
                self.setUp();key=self.root/'etc/qshd/host_key'
                if mode=='unknown':(self.root/'etc/qshd/unknown').mkdir()
                elif mode=='socket-name':(self.root/'run/qshd/helper-status.sock').write_bytes(b'not opened')
                elif mode=='rotation':(self.root/'var/log/qshd/qshd.log.2').write_bytes(b'not opened')
                elif mode in ('symlink','hardlink','fifo'):
                    key.unlink()
                    if mode=='symlink':key.symlink_to('/missing')
                    elif mode=='hardlink':os.link(self.root/'var/log/qshd/qshd.log',key)
                    else:os.mkfifo(key,0o600)
                elif mode=='mode':key.chmod(0o644)
                elif mode=='runtime-mode':(self.root/'run/qshd').chmod(0o755)
                else:(self.root/'var/run').unlink();(self.root/'var/run').symlink_to('/tmp')
                captured=[]
                with self.assertRaises(self.m.RetainedLabelError):
                    with self.factory.inspection(deadline=120) as scope:captured.append(scope.capture())
                self.assertFalse(captured,'unsafe capture returned before finalizer refusal')
                self.assertEqual(self.set_count,0)

    def test_custom_old_labels_raw_nul_and_defaults_refuse(self):
        for raw in (b'custom',b'system_u:object_r:qshd_config_t:s0\0\0',b'x'*4097):
            self.labels[self.key_for_path('/etc/qshd')]=raw
            captured=[]
            with self.subTest(raw=raw[:10]),self.assertRaises(self.m.RetainedLabelError):
                with self.make_factory().inspection(deadline=120) as scope:captured.append(scope.capture())
            self.assertEqual(captured,[])
            self.assertEqual(self.set_count,0)

    def key_for_path(self,path):
        info=(self.root/path[1:]).stat();return info.st_dev,info.st_ino

    def test_exact_tokens_sequence_and_factory_reuse(self):
        from dataclasses import replace
        for mode in ('equal','double-capture','restore-early','foreign-result'):
            with self.subTest(mode=mode),self.assertRaises(self.m.RetainedLabelError):
                with self.make_factory().inspection(deadline=120) as scope:
                    observed=scope.capture()
                    if mode=='equal':scope.recheck_before_removal(replace(observed))
                    elif mode=='double-capture':scope.capture()
                    elif mode=='restore-early':scope.restore_defaults(observed)
                    else:
                        scope.recheck_before_removal(observed);self.after=True
                        result=scope.restore_defaults(observed);scope.recheck_restored(replace(result))
            self.after=False
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=100):pass
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=120):pass

    def test_all_new_defaults_resolved_before_any_setter(self):
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=120) as scope:
                observed=self.ready(scope)
                self.bad_default='/run/qshd/helper-status.sock.lock'
                scope.restore_defaults(observed)
        self.assertEqual(self.set_count,0)

    def test_obsolete_raw_conversion_refuses_without_current_validation(self):
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=120) as scope:
                observed=self.ready(scope)
                self.labels[self.key_for_path('/etc/qshd')]=b'system_u:object_r:unlabeled_t:s0\0'
                scope.restore_defaults(observed)
        self.assertEqual(self.set_count,0)

    def test_partial_setter_and_collateral_evm_drift_are_uncertain(self):
        for mode in ('first','second','evm'):
            with self.subTest(mode=mode):
                self.setUp();self.fail_set=1 if mode=='first' else 2 if mode=='second' else None;self.evm=mode=='evm'
                restored=[]
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=120) as scope:
                        observed=self.ready(scope);restored.append(scope.restore_defaults(observed))
                self.assertFalse(restored,'mutation failure returned provisional restoration')
                self.assertEqual(self.set_count,2 if mode=='second' else 1)

    def test_second_defaults_drift_and_post_status_failure_are_uncertain(self):
        for mode in ('default','status'):
            with self.subTest(mode=mode):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=120) as scope:
                        observed=self.ready(scope);result=scope.restore_defaults(observed)
                        if mode=='default':self.default_drift=True
                        else:self.status_fail=True
                        scope.recheck_restored(result)

    def test_no_private_content_reads_or_path_setter_and_real_xattrs_preserved(self):
        from unittest.mock import patch
        def forbidden(*args,**kwargs):raise AssertionError('private bytes or creation')
        with patch.object(os,'read',forbidden),patch.object(os,'pread',forbidden),patch.object(self.m.SafeFiles,'_read',forbidden),patch.object(self.m.SafeFiles,'_create',forbidden):
            with self.factory.inspection(deadline=120) as scope:
                observed=self.ready(scope);self.complete(scope,observed)
        self.assertEqual(os.getxattr(self.root/'etc/qshd/host_key','user.fixture'),b'preserved')


    def test_none_token_refuses_before_native_observation_and_poisons(self):
        for operation in ('recheck','restore'):
            with self.subTest(operation=operation):
                with self.assertRaises(self.m.RetainedLabelError):
                    with self.make_factory().inspection(deadline=120) as scope:
                        observed=scope.capture()
                        if operation=='restore':scope.recheck_before_removal(observed)
                        count=len(self.events)
                        try:
                            if operation=='recheck':scope.recheck_before_removal(None)
                            else:scope.restore_defaults(None)
                        finally:entered=len(self.events)!=count
                self.assertFalse(entered,'invalid token entered native scope')

    def test_actual_final_close_deadline_is_uncertain(self):
        from unittest.mock import patch
        original=os.close;armed=[]
        def close(fd):
            original(fd)
            if armed:self.now=120
        with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
            with patch.object(os,'close',close):
                with self.factory.inspection(deadline=120) as scope:
                    observed=self.ready(scope);self.complete(scope,observed);armed.append(True)

    def test_failed_post_window_enter_does_not_exit_unentered_scope(self):
        count=[];normal=self.api
        def api():
            value=normal()
            if self.after:
                class Window:
                    def __enter__(inner):raise RuntimeError('controlled enter failure')
                    def __exit__(inner,*args):count.append('invalid exit');raise RuntimeError('must not exit')
                value.status_observation=Window
            return value
        self.factory=self.m.RetainedLabels(_root=self.root,_uid=os.getuid(),_api_factory=api,
            _clock=lambda:self.now,_getxattr=self.get,_listxattr=self.names,_setxattr=self.set)
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=120) as scope:
                observed=self.ready(scope);scope.restore_defaults(observed)
        self.assertEqual(count,[]);self.assertEqual(self.set_count,0)


    def test_original_deadline_validation_and_no_reset(self):
        values=(True,False,float('nan'),float('inf'),10**10000,'120',100)
        for value in values:
            with self.subTest(kind=type(value).__name__),self.assertRaises(self.m.RetainedLabelError):
                with self.make_factory().inspection(deadline=value):pass
        for stage in ('before','between','after'):
            with self.subTest(stage=stage):
                self.setUp()
                expected=self.m.RetainedLabelError if stage=='before' else self.m.RetainedLabelOutcomeUncertain
                with self.assertRaises(expected):
                    with self.factory.inspection(deadline=120) as scope:
                        observed=self.ready(scope)
                        if stage=='before':self.now=120
                        if stage=='between':
                            original=self.set
                            def late(*args):original(*args);self.now=120
                            scope._factory._set=late
                        result=scope.restore_defaults(observed)
                        if stage=='after':self.now=120
                        scope.recheck_restored(result)
                self.assertEqual(self.set_count,0 if stage=='before' else 1 if stage=='between' else 7)

    def test_raw_terminal_nul_change_after_capture_is_not_equal(self):
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=120) as scope:
                observed=self.ready(scope)
                key=self.key_for_path('/etc/qshd');self.labels[key]=self.labels[key].removesuffix(b'\0')
                scope.restore_defaults(observed)
        self.assertEqual(self.set_count,0)

    def test_routes_membership_and_absence_rechecks_refuse(self):
        for mode in ('gid','mode','mtime','xattr','replace','alias','unknown','absent-appear'):
            with self.subTest(mode=mode):
                self.setUp()
                if mode=='absent-appear':
                    leaf=self.root/'etc/qshd/host_key';leaf.unlink()
                with self.assertRaises(self.m.RetainedLabelError):
                    with self.factory.inspection(deadline=120) as scope:
                        observed=scope.capture();leaf=self.root/'var/log/qshd/qshd.log'
                        if mode=='gid':
                            original=scope._metadata
                            def changed(*args):
                                value=original(*args);return value[:3]+(value[3]+1,)+value[4:]
                            scope._metadata=changed
                        elif mode=='mode':leaf.chmod(0o400)
                        elif mode=='mtime':os.utime(leaf,ns=(leaf.stat().st_atime_ns,leaf.stat().st_mtime_ns+1))
                        elif mode=='xattr':os.setxattr(leaf,'user.fixture',b'changed')
                        elif mode=='replace':leaf.unlink();leaf.write_bytes(b'new');leaf.chmod(0o600)
                        elif mode=='alias':(self.root/'var/run').unlink();(self.root/'var/run').symlink_to('/run')
                        elif mode=='unknown':(self.root/'etc/qshd/unknown').write_bytes(b'not read')
                        else:(self.root/'etc/qshd/host_key').write_bytes(b'x'*64)
                        scope.recheck_before_removal(observed)
                self.assertEqual(self.set_count,0)

    def test_changed_middle_object_and_fsync_failure_are_uncertain(self):
        from unittest.mock import patch
        for mode in ('middle','fsync'):
            with self.subTest(mode=mode):
                self.setUp();original=self.set
                def changed(*args):
                    original(*args)
                    if self.set_count==1:os.setxattr(self.root/'var/log/qshd/qshd.log','user.fixture',b'changed')
                if mode=='middle':self.factory._set=changed
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=120) as scope:
                        observed=self.ready(scope)
                        if mode=='fsync':
                            with patch.object(os,'fsync',side_effect=OSError('controlled sync')):scope.restore_defaults(observed)
                        else:scope.restore_defaults(observed)
                self.assertEqual(self.set_count,1)

    def test_xattr_boundaries_are_admission_not_streaming_claims(self):
        original_names=self.names;original_get=self.get
        for mode in ('count','name','value'):
            with self.subTest(mode=mode):
                factory=self.make_factory()
                factory._list=lambda fd:['x']*129 if mode=='count' else ['x'*256] if mode=='name' else ['user.large','security.selinux']
                factory._get=lambda fd,name:b'x'*65537 if name=='user.large' else original_get(fd,name)
                captured=[]
                with self.assertRaises(self.m.RetainedLabelError):
                    with factory.inspection(deadline=120) as scope:captured.append(scope.capture())
                self.assertEqual(captured,[])
                self.assertEqual(self.set_count,0)
        factory=self.make_factory()
        names=['user.fixture'+str(i) for i in range(127)]+['security.selinux']
        factory._list=lambda fd:names
        factory._get=lambda fd,name:original_get(fd,name) if name=='security.selinux' else b'x'*65536
        with factory.inspection(deadline=120) as scope:
            observed=self.ready(scope);self.complete(scope,observed)

    def test_final_fd_close_failure_preserves_prior_interruption(self):
        from unittest.mock import patch
        original=os.close;owned=set();closed=[]
        def close(fd):
            original(fd)
            if fd in owned:
                closed.append(fd)
                if len(closed)==1:raise OSError('after actual close')
        error=KeyboardInterrupt('controlled body')
        with self.assertRaises(KeyboardInterrupt) as caught:
            with patch.object(os,'close',close):
                with self.factory.inspection(deadline=120) as scope:
                    scope.capture();owned.update(scope._fds+scope.anchors+[r[2] for r in scope.routes])
                    raise error
        self.assertIs(caught.exception,error)
        self.assertEqual(set(closed),owned)
        self.assertIn('RETAINED_LABEL_CLEANUP_FAILED',caught.exception.__notes__)

    def test_real_fd_cleanup_after_open_metadata_failure(self):
        from unittest.mock import patch
        original=self.m._Inspection._metadata;acquired=[]
        def failure(scope,fd,*args):
            acquired.append(fd);raise OSError('controlled after acquisition')
        with patch.object(self.m._Inspection,'_metadata',failure),self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=120) as scope:scope.capture()
        self.assertTrue(acquired)
        for fd in acquired:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_postwrite_scope_finalizer_rechecks_after_explicit_result(self):
        with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
            with self.factory.inspection(deadline=120) as scope:
                observed=self.ready(scope);self.complete(scope,observed)
                os.setxattr(self.root/'etc/qshd','user.fixture',b'late drift')


    def test_qshd_post_default_refuses_and_original_tail_cutoff_is_fixed(self):
        original=self.api
        def factory():
            api=original();lookup=api.lookup
            api.lookup=lambda path,kind:'system_u:object_r:qshd_unknown_t:s0' if self.after else lookup(path,kind)
            return api
        self.factory._api_factory=factory
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=230) as scope:
                observed=self.ready(scope)
                self.assertEqual(scope._end,230)  # Caller passed original E240 minus10.
                scope.restore_defaults(observed)
        self.assertEqual(self.set_count,0)
        self.after=False;self.factory=self.make_factory();self.now=229
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=230) as scope:
                scope.capture();self.now=230;scope.recheck_before_removal(None)
        self.assertEqual(self.set_count,0)

    def test_uid_admission_and_setup_failure_consume_factory(self):
        from unittest.mock import patch
        factory=self.make_factory()
        with patch.object(self.m._Inspection,'_setup',side_effect=OSError('controlled setup')),self.assertRaises(self.m.RetainedLabelError):
            with factory.inspection(deadline=120):pass
        with self.assertRaises(self.m.RetainedLabelError):
            with factory.inspection(deadline=120):pass
        factory=self.m.RetainedLabels(_root=self.root,_uid=os.getuid()+1,_api_factory=self.api,_clock=lambda:self.now)
        with self.assertRaises(self.m.RetainedLabelError):
            with factory.inspection(deadline=120) as scope:scope.capture()


if __name__=='__main__':unittest.main()
