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

    def borrowed_api(self):
        import qshd_selinux_api as native
        from scripts.tests.test_selinux_api import SharedStatus
        shared=SharedStatus();owner=native.SelinuxApi(shared.library());fake=self.api()
        for name in ('file_defaults','file_context','check_context'):
            setattr(owner,name,getattr(fake,name))
        return owner,shared

    def test_managed_readonly_borrows_one_owner_and_rechecks_across_windows(self):
        owner,shared=self.borrowed_api()
        with self.factory.managed_inspection(deadline=120) as scope:
            with owner.status_observation() as status:
                token=scope.capture(status=status);scope.recheck(token,status=status)
                self.assertEqual(shared.events,['open','updated'])
            with owner.status_observation() as status:
                scope.recheck(token,status=status)
        self.assertEqual(shared.events,['open','updated','updated','close']*2)
        self.assertEqual(self.set_count,0)

    def test_managed_requires_final_owner_closed_and_exact_observation(self):
        from dataclasses import replace
        for fault in ('open','copied','drift','wrong-status'):
            with self.subTest(fault=fault):
                self.factory=self.make_factory();owner,shared=self.borrowed_api()
                with self.assertRaises(self.m.RetainedLabelError):
                    with owner.status_observation() as status:
                        with self.factory.managed_inspection(deadline=120) as scope:
                            token=scope.capture(status=status)
                            if fault=='copied':token=replace(token)
                            if fault=='drift':self.labels[self.key(scope._objects['/etc/qshd'])]=b'bad'
                            scope.recheck(token,status=object() if fault=='wrong-status' else status)
                self.assertEqual(self.set_count,0)
                for path,kind,role,label in self.m._ITEMS:
                    physical=self.root/path[1:];self.labels[(physical.stat().st_dev,physical.stat().st_ino)]=label.encode()+b'\0'

    def test_pristine_install_validates_all_targets_before_setting_and_preserves_files(self):
        owner,shared=self.borrowed_api();self.after=True
        for key in self.labels:self.labels[key]=b'system_u:object_r:etc_t:s0\0'
        original_lookup=owner.file_defaults
        from contextlib import contextmanager
        @contextmanager
        def defaults():
            with original_lookup() as view:
                class Defaults:
                    def lookup(inner,path,kind):
                        if not loaded[0]:return 'system_u:object_r:etc_t:s0'
                        return next(row[3] for row in self.m._ITEMS if row[0]==path)
                yield Defaults()
        owner.file_defaults=defaults;loaded=[False]
        # Translation uses the same raw-label mapping before and after load.
        owner.file_context=lambda fd:self.labels[self.key(fd)].removesuffix(b'\0').decode()
        with self.factory.pristine_install(deadline=120) as scope:
            with owner.status_observation() as status:
                token=scope.capture_defaults(status=status);scope.recheck_defaults(token,status=status)
            loaded[0]=True
            with owner.status_observation() as status:
                result=scope.apply_managed(token,status=status)
                scope.recheck_managed(result,status=status)
        self.assertEqual(self.set_count,7)
        self.assertEqual(shared.events,['open','updated','updated','close']*2)
        self.assertTrue(all(self.m._Inspection._preserved(a.metadata,b.metadata) for a,b in zip(token.paths,result.paths)))
        self.assertEqual((self.root/'etc/qshd/host_key').read_bytes(),b'k'*64)

    def test_borrowed_managed_absent_and_mixed_inventory_never_creates_or_sets(self):
        for mode in ('mixed','absent'):
            with self.subTest(mode=mode):
                for path in ('var/log/qshd/qshd.log','var/log/qshd/qshd.log.1'):
                    physical=self.root/path
                    if physical.exists():physical.unlink()
                if mode=='absent':
                    for path in ('etc/qshd/host_key','run/qshd/helper-status.sock.lock'):(self.root/path).unlink()
                    for path in ('etc/qshd','var/log/qshd','run/qshd'):(self.root/path).rmdir()
                owner,shared=self.borrowed_api();self.factory=self.make_factory()
                with self.factory.managed_inspection(deadline=120) as scope:
                    with owner.status_observation() as status:
                        token=scope.capture(status=status);scope.recheck(token,status=status)
                self.assertEqual(sum(item.present for item in token.paths),5 if mode=='mixed' else 0)
                self.assertEqual(self.set_count,0)

    def test_pristine_custom_unlabeled_and_missing_raw_labels_refuse_before_setter(self):
        for raw in (b'system_u:object_r:unlabeled_t:s0',b'system_u:object_r:custom_t:s0',b''):
            with self.subTest(raw_kind=len(raw)):
                self.factory=self.make_factory();owner,shared=self.borrowed_api();self.after=True
                for key in self.labels:self.labels[key]=raw
                with self.assertRaises(self.m.RetainedLabelError):
                    with self.factory.pristine_install(deadline=120) as scope:
                        with owner.status_observation() as status:scope.capture_defaults(status=status)
                self.assertEqual(self.set_count,0)

    def test_managed_rejects_foreign_closed_or_unissued_status_without_opening_native(self):
        import copy
        import qshd_selinux_api as native
        owner,shared=self.borrowed_api()
        with owner.status_observation() as status:pass
        for candidate in (status,object(),native._StatusToken(status._record)):
            self.factory=self.make_factory();before=list(shared.events)
            with self.assertRaises(self.m.RetainedLabelError):
                with self.factory.managed_inspection(deadline=120) as scope:scope.capture(status=candidate)
            self.assertEqual(shared.events,before)

    def test_pristine_complete_target_vector_and_setter_failures_are_causal(self):
        for fault in ('last-target','setter','evm','readback','close'):
            with self.subTest(fault=fault):
                self.factory=self.make_factory();self.after=True;self.set_count=0;self.extra={}
                self.fail_set=1 if fault=='setter' else None;self.evm=fault=='evm'
                for key in self.labels:self.labels[key]=b'system_u:object_r:etc_t:s0\0'
                owner,shared=self.borrowed_api();loaded=[False]
                @contextmanager
                def defaults():
                    class Defaults:
                        def lookup(inner,path,kind):
                            if not loaded[0]:return 'system_u:object_r:etc_t:s0'
                            if fault=='last-target' and path==self.m._ITEMS[-1][0]:return 'system_u:object_r:custom_t:s0'
                            return next(row[3] for row in self.m._ITEMS if row[0]==path)
                    yield Defaults()
                owner.file_defaults=defaults
                owner.file_context=lambda fd:self.labels[self.key(fd)].removesuffix(b'\0').decode()
                expected=self.m.RetainedLabelError if fault=='last-target' else self.m.RetainedLabelOutcomeUncertain
                with self.assertRaises(expected):
                    with self.factory.pristine_install(deadline=120) as scope:
                        with owner.status_observation() as status:
                            token=scope.capture_defaults(status=status);scope.recheck_defaults(token,status=status)
                        loaded[0]=True
                        with owner.status_observation() as status:
                            result=scope.apply_managed(token,status=status)
                            if fault=='readback':self.labels[self.key(scope._objects['/etc/qshd'])]=b'bad'
                            scope.recheck_managed(result,status=status)
                            if fault=='close':shared.counter+=1
                self.assertEqual(self.set_count,0 if fault=='last-target' else 1 if fault in ('setter','evm') else 7)

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

    def test_raw_refusal_discriminates_old_sample(self):
        self.labels[self.key_for_path('/etc/qshd')]=b'system_u:object_r:unlabeled_t:s0\0'
        with self.assertRaises(self.m.RetainedLabelError) as caught:
            with self.factory.inspection(deadline=120) as scope:scope.capture()
        self.assertEqual(self.set_count,0)
        chain=[];error=caught.exception
        while error is not None:
            chain.append(error);error=error.__context__
        claims=[error for error in chain if type(error).__name__=='RetainedLabelRawError']
        self.assertEqual(len(claims),1,'actual raw refusal must retain its closed role/reason')
        self.assertEqual(claims[0].args,('RAW_LABEL_REFUSED','CONFIG_DIR','UNLABELED_LITERAL'))

    def raw_claim(self,error):
        claims=[]
        while error is not None:
            if type(error) is self.m.RetainedLabelRawError:claims.append(error)
            error=error.__context__
        self.assertEqual(len(claims),1)
        return claims[0].args

    def raw_metadata_before(self):
        result={}
        for path,kind,role,label in self.m._ITEMS:
            physical=self.root/path[1:];info=physical.stat()
            result[path]=(self.m._stat(info),os.getxattr(physical,'user.fixture'),
                          physical.read_bytes() if physical.is_file() else None)
        return result

    def test_raw_refusal_table_at_real_restore_sample(self):
        cases=((None,'ABSENT'),(b'x'*4097,'OVERSIZE'),
               (b'system_u:object_r:unlabeled_t:s0','UNLABELED_LITERAL'),
               (b'system_u:object_r:unlabeled_t:s0\0','UNLABELED_LITERAL'),
               (b'system_u:object_r:unlabeled_t:s0\0\0','OTHER_BYTES'),
               (b'private-byte-canary','OTHER_BYTES'))
        for path,role in (('/etc/qshd','CONFIG_DIR'),('/run/qshd/helper-status.sock.lock','STATUS_LOCK')):
            managed=next(row[3] for row in self.m._ITEMS if row[0]==path).encode('ascii')
            for value,reason in cases+((managed+b'\0\0','OTHER_BYTES'),):
                with self.subTest(role=role,reason=reason,value=value):
                    self.setUp();key=self.key_for_path(path);before=self.raw_metadata_before()
                    with self.assertRaises(self.m.RetainedLabelError) as caught:
                        with self.factory.inspection(deadline=120) as scope:
                            observed=self.ready(scope)
                            if value is None:
                                original=self.factory._list
                                self.factory._list=lambda fd:[name for name in original(fd)
                                    if name!='security.selinux' or self.key(fd)!=key]
                            else:self.labels[key]=value
                            scope.restore_defaults(observed)
                    self.assertIs(type(caught.exception),self.m.RetainedLabelError)
                    self.assertEqual(self.raw_claim(caught.exception),('RAW_LABEL_REFUSED',role,reason))
                    self.assertEqual(self.set_count,0)
                    self.assertEqual(self.raw_metadata_before(),before)
                    self.assertNotIn('private-byte-canary',repr(self.raw_claim(caught.exception)))

    def test_raw_refusal_managed_bytes_with_optional_nul_still_restore(self):
        for path in ('/etc/qshd','/run/qshd/helper-status.sock.lock'):
            for suffix in (b'',b'\0'):
                with self.subTest(path=path,suffix=suffix):
                    self.setUp();context=next(row[3] for row in self.m._ITEMS if row[0]==path)
                    self.labels[self.key_for_path(path)]=context.encode('ascii')+suffix
                    with self.factory.inspection(deadline=120) as scope:
                        observed=self.ready(scope);self.complete(scope,observed)
                    self.assertEqual(self.set_count,7)

    def test_raw_refusal_closed_args_and_metadata_type_precedence(self):
        m=self.m;context=m._CONFIG
        with self.assertRaises(m.RetainedLabelRawError) as caught:
            m._Inspection._raw(((('security.selinux',bytearray(b'canary')),),),context,'HOST_KEY')
        self.assertEqual(caught.exception.args,('RAW_LABEL_REFUSED','HOST_KEY','INVALID_TYPE'))
        for role,reason in (('private-role-canary','OTHER_BYTES'),('CONFIG_DIR','private-reason-canary')):
            with self.assertRaises(m.RetainedLabelError) as invalid:m.RetainedLabelRawError(role,reason)
            self.assertIs(type(invalid.exception),m.RetainedLabelError)
            self.assertNotIn('canary',str(invalid.exception))
        with self.assertRaises(m.RetainedLabelError) as invalid:
            m._Inspection._raw(((('security.selinux',context.encode()),),),context,'private-role-canary')
        self.assertIs(type(invalid.exception),m.RetainedLabelError)
        self.labels[self.key_for_path('/etc/qshd')]=bytearray(b'canary')
        with self.assertRaises(m.RetainedLabelError) as caught:
            with self.factory.inspection(deadline=120) as scope:scope.capture()
        error=caught.exception
        while error is not None:
            self.assertIsNot(type(error),m.RetainedLabelRawError);error=error.__context__
        self.assertEqual(self.set_count,0)

    def test_raw_refusal_postset_error_preserves_uncertainty(self):
        for path,role,attempts in (('/etc/qshd','CONFIG_DIR',1),
                ('/run/qshd/helper-status.sock.lock','STATUS_LOCK',7)):
            with self.subTest(role=role):
                self.setUp();original=self.factory._set;target=self.key_for_path(path)
                def corrupt(fd,name,value,flags):
                    original(fd,name,value,flags)
                    if self.key(fd)==target:self.labels[target]=b'private-postset-canary'
                self.factory._set=corrupt;returned=[]
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain) as caught:
                    with self.factory.inspection(deadline=120) as scope:
                        observed=self.ready(scope);returned.append(scope.restore_defaults(observed))
                self.assertEqual(returned,[]);self.assertEqual(self.set_count,attempts)
                self.assertEqual(self.raw_claim(caught.exception),('RAW_LABEL_REFUSED',role,'OTHER_BYTES'))
                self.assertNotIn('private-postset-canary',str(caught.exception))

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


class BorrowedEraseTests(unittest.TestCase):
    key=FixtureTests.key
    key_for_path=FixtureTests.key_for_path
    make_factory=FixtureTests.make_factory
    names=FixtureTests.names
    get=FixtureTests.get
    api=FixtureTests.api

    def setUp(self):
        FixtureTests.setUp(self)
        import qshd_selinux_api as native
        from scripts.tests.test_selinux_api import SharedStatus
        self.shared=SharedStatus();self.native=native.SelinuxApi(self.shared.library())
        self.policy='pair';self.core_removed=False;self.default_calls=[];self.setter_fds=[]
        self.translated_override=None;self.default_override=None;self.fail_default_exit=None
        self.native.file_defaults=self.defaults
        self.native.file_context=self.file_context
        self.native.check_context=self.check_context
        self.factory._api_factory=lambda:(_ for _ in ()).throw(AssertionError('borrower constructed status API'))

    def set(self,fd,name,value,flags):
        self.assertFalse(self.core_removed,'setter after core removal')
        self.setter_fds.append(fd);FixtureTests.set(self,fd,name,value,flags)

    @contextmanager
    def defaults(self):
        phase=self.policy;self.events.append(('defaults enter',phase))
        outer=self
        class Defaults:
            def lookup(inner,path,kind):
                outer.default_calls.append((outer.policy,path,kind))
                if outer.bad_default==path:raise RuntimeError('controlled missing current default')
                if outer.default_override is not None:return outer.default_override
                if outer.policy=='pair':return next(row[3] for row in outer.m._ITEMS if row[0]==path)
                return 'system_u:object_r:etc_t:s0'
        yield Defaults()
        self.events.append(('defaults exit',phase))
        if self.fail_default_exit==phase:raise RuntimeError('controlled default handle close')

    def file_context(self,fd):
        if self.translated_override is not None:return self.translated_override
        return self.labels[self.key(fd)].removesuffix(b'\0').decode()

    def check_context(self,value):
        self.m._context(value)
        if self.core_removed and value.split(':',3)[2].startswith('qshd_'):
            raise RuntimeError('obsolete type after core removal')

    def remove_contexts(self):
        self.assertFalse(self.shared.mapped);self.after=True;self.policy='core-only';self.shared.counter+=1

    def remove_core(self):
        self.assertFalse(self.shared.mapped);self.after=True;self.policy='absent';self.core_removed=True;self.shared.counter+=1
        for key,raw in self.labels.items():
            if raw.removesuffix(b'\0').decode().split(':',3)[2].startswith('qshd_'):
                self.labels[key]=b'system_u:object_r:unlabeled_t:s0\0'

    def pair(self,scope):
        with self.native.status_observation() as status:
            old=scope.capture(status=status);scope.recheck_before_removal(old,status=status)
        return old

    def restored(self,scope):
        old=self.pair(scope);self.remove_contexts()
        with self.native.status_observation() as status:
            restored=scope.restore_defaults(old,status=status)
            self.assertIsNone(scope.recheck_restored(restored))
            self.assertIs(status.require_open(),self.native)
        return old,restored

    def final(self,scope,restored):
        with self.native.status_observation() as status:
            with scope.final_policy(restored,status=status) as final:
                self.assertIsNone(final.capture());self.assertIsNone(final.recheck())
            self.assertIs(status.require_open(),self.native)

    def test_borrowed_three_windows_same_fds_current_post_core_defaults_and_metadata(self):
        private={path:(self.root/path[1:]).read_bytes() for path,kind,role,label in self.m._ITEMS if kind!=__import__('stat').S_IFDIR}
        with self.factory.inspection(deadline=530) as scope:
            old,restored=self.restored(scope);held=dict(scope._objects)
            self.assertEqual(self.set_count,7);self.assertEqual(set(self.setter_fds),set(held.values()))
            self.assertTrue(all(self.m._Inspection._preserved(a.metadata,b.metadata) for a,b in zip(old.paths,restored.paths)))
            self.remove_core();before=len(self.default_calls);self.final(scope,restored)
            self.assertEqual(len(self.default_calls)-before,14)
            self.assertEqual(scope._objects,held)
        self.assertEqual(self.shared.events,['open','updated','updated','close']*3)
        self.assertEqual(len(self.default_calls),42)
        self.assertEqual([phase for kind,phase in self.events if kind=='defaults enter'],['pair','pair','core-only','core-only','absent','absent'])
        for fd in held.values():
            with self.assertRaises(OSError):os.fstat(fd)
        self.assertEqual(private,{path:(self.root/path[1:]).read_bytes() for path in private})

    def test_original_owning_old_window_cannot_nest_inside_real_pair_owner(self):
        self.factory._api_factory=lambda:self.native
        with self.native.status_observation():
            with self.assertRaises(self.m.RetainedLabelError):
                with self.factory.inspection(deadline=530) as scope:scope.capture()
            self.assertEqual(self.shared.events,['open','updated'])
        self.assertEqual(self.shared.events,['open','updated','updated','close'])

    def test_old_single_module_unload_loses_raw_labels_before_restore_but_pair_order_succeeds(self):
        with self.assertRaises(self.m.RetainedLabelError) as caught:
            with self.factory.inspection(deadline=530) as scope:
                old=self.pair(scope);self.remove_core()
                with self.native.status_observation() as status:scope.restore_defaults(old,status=status)
        self.assertEqual(self.set_count,0)
        self.assertEqual(FixtureTests.raw_claim(self,caught.exception),('RAW_LABEL_REFUSED','CONFIG_DIR','UNLABELED_LITERAL'))


    def test_borrowed_initial_exact_status_pid_same_pair_and_mode_custody(self):
        from dataclasses import replace
        from unittest.mock import patch
        import qshd_selinux_api as native
        for fault in ('wrong-type','unissued','pid','copied-data','mix-owning','closed-pair','new-pair'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelError):
                    with self.factory.inspection(deadline=530) as scope:
                        with self.native.status_observation() as pair:
                            if fault in ('wrong-type','unissued'):
                                scope.capture(status=object() if fault=='wrong-type' else native._StatusToken(pair._record))
                            elif fault=='pid':
                                pid=os.getpid()
                                with patch.object(native.os,'getpid',return_value=pid+1):scope.capture(status=pair)
                            else:
                                old=scope.capture(status=pair)
                                if fault=='copied-data':scope.recheck_before_removal(replace(old),status=pair)
                                elif fault=='mix-owning':scope.recheck_before_removal(old)
                        if fault=='closed-pair':scope.recheck_before_removal(old,status=pair)
                        elif fault=='new-pair':
                            with self.native.status_observation() as changed:scope.recheck_before_removal(old,status=changed)
                self.assertEqual(self.set_count,0)
                self.assertFalse(self.shared.mapped)

    def test_owning_inspection_cannot_switch_to_borrowed_recheck(self):
        self.factory._api_factory=self.api
        with self.assertRaises(self.m.RetainedLabelError):
            with self.factory.inspection(deadline=530) as scope:
                old=scope.capture()
                with self.native.status_observation() as status:scope.recheck_before_removal(old,status=status)
        self.assertEqual(self.set_count,0)

    def test_pair_owner_must_close_normally_before_restore_and_calls_cannot_mix(self):
        for fault in ('still-open','failed-close','mix-owning','copied-data'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelError):
                    with self.factory.inspection(deadline=530) as scope:
                        if fault=='still-open':
                            with self.native.status_observation() as pair:
                                old=scope.capture(status=pair);scope.recheck_before_removal(old,status=pair)
                                scope.restore_defaults(old,status=pair)
                        else:
                            try:
                                with self.native.status_observation() as pair:
                                    old=scope.capture(status=pair);scope.recheck_before_removal(old,status=pair)
                                    if fault=='failed-close':self.shared.counter+=1
                            except Exception:
                                if fault!='failed-close':raise
                            self.remove_contexts()
                            with self.native.status_observation() as core:
                                from dataclasses import replace
                                scope.restore_defaults(replace(old) if fault=='copied-data' else old,
                                    **({} if fault=='mix-owning' else {'status':core}))
                self.assertEqual(self.set_count,0)

    def test_borrowed_complete_target_vector_and_setter_failure_boundaries(self):
        from unittest.mock import patch
        for fault in ('last-target','qshd-target','setter','evm','sync','readback','metadata'):
            with self.subTest(fault=fault):
                self.setUp();expected=self.m.RetainedLabelError if fault in ('last-target','qshd-target','metadata') else self.m.RetainedLabelOutcomeUncertain
                with self.assertRaises(expected):
                    with self.factory.inspection(deadline=530) as scope:
                        old=self.pair(scope);self.remove_contexts()
                        if fault=='last-target':self.bad_default=self.m._ITEMS[-1][0]
                        elif fault=='qshd-target':self.default_override='system_u:object_r:qshd_config_t:s0'
                        elif fault=='setter':self.fail_set=1
                        elif fault=='evm':self.evm=True
                        elif fault=='metadata':os.setxattr(self.root/'etc/qshd','user.fixture',b'changed')
                        elif fault=='readback':
                            original=self.factory._set
                            def changed(fd,*args):
                                original(fd,*args);self.labels[self.key(fd)]=b'bad readback'
                            self.factory._set=changed
                        with self.native.status_observation() as core:
                            if fault=='sync':
                                with patch.object(self.m.os,'fsync',side_effect=OSError('controlled sync')):scope.restore_defaults(old,status=core)
                            else:scope.restore_defaults(old,status=core)
                self.assertEqual(self.set_count,0 if fault in ('last-target','qshd-target','metadata') else 1)

    def test_final_policy_fresh_changed_default_raw_translation_and_metadata_refuse(self):
        for fault in ('default','raw','translated','metadata','alias','membership'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=530) as scope:
                        old,restored=self.restored(scope);self.remove_core();calls=len(self.default_calls)
                        if fault=='default':self.default_override='system_u:object_r:changed_t:s0'
                        elif fault=='raw':self.labels[self.key_for_path('/etc/qshd')]=b'system_u:object_r:custom_t:s0'
                        elif fault=='translated':self.translated_override='system_u:object_r:custom_t:s0'
                        elif fault=='metadata':os.setxattr(self.root/'etc/qshd','user.fixture',b'post-core drift')
                        elif fault=='alias':
                            (self.root/'var/run').unlink();(self.root/'var/run').symlink_to('/run')
                        else:(self.root/'etc/qshd/unknown').write_bytes(b'unexpected child')
                        self.final(scope,restored)
                self.assertGreater(len(self.default_calls),calls,'post-core proof must use actual current defaults')
                self.assertEqual(self.set_count,7)

    def test_final_policy_requires_checked_restoration_new_live_owner_and_exact_data(self):
        from dataclasses import replace
        import qshd_selinux_api as native
        for fault in ('unchecked','core-open','core-token','closed-token','unissued','copied-data'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=530) as scope:
                        if fault in ('unchecked','core-open'):
                            old=self.pair(scope);self.remove_contexts()
                            with self.native.status_observation() as core:
                                restored=scope.restore_defaults(old,status=core)
                                if fault=='core-open':scope.recheck_restored(restored)
                                with scope.final_policy(restored,status=core):pass
                        else:
                            old,restored=self.restored(scope);self.remove_core()
                            with self.native.status_observation() as absent:pass
                            closed=absent
                            with self.native.status_observation() as absent:
                                token=(scope._core_status if fault=='core-token' else closed if fault=='closed-token'
                                    else native._StatusToken(absent._record) if fault=='unissued' else absent)
                                with scope.final_policy(replace(restored) if fault=='copied-data' else restored,status=token):pass
                self.assertEqual(self.set_count,7)

    def test_final_view_exactly_one_capture_and_recheck_and_no_missing_proof(self):
        for fault in ('missing','capture-missing','recheck-missing','double-capture','double-recheck','reverse'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=530) as scope:
                        old,restored=self.restored(scope);self.remove_core()
                        if fault!='missing':
                            with self.native.status_observation() as absent:
                                with scope.final_policy(restored,status=absent) as final:
                                    if fault=='reverse':final.recheck()
                                    if fault!='capture-missing':final.capture()
                                    if fault=='double-capture':final.capture()
                                    if fault not in ('capture-missing','recheck-missing'):final.recheck()
                                    if fault=='double-recheck':final.recheck()
                self.assertEqual(self.set_count,7)

    def test_outer_finish_requires_final_owner_closed_and_never_closes_lender(self):
        manager=self.factory.inspection(deadline=530);scope=manager.__enter__()
        old,restored=self.restored(scope);self.remove_core()
        with self.native.status_observation() as absent:
            with scope.final_policy(restored,status=absent) as final:final.capture();final.recheck()
            before=list(self.shared.events)
            with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):manager.__exit__(None,None,None)
            self.assertEqual(self.shared.events,before)
            self.assertIs(absent.require_open(),self.native)
        self.assertEqual(self.shared.events,['open','updated','updated','close']*3)

    def test_no_setter_is_usable_after_core_removal(self):
        with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
            with self.factory.inspection(deadline=530) as scope:
                old,restored=self.restored(scope);self.remove_core();count=self.set_count
                with self.native.status_observation() as absent:scope.restore_defaults(old,status=absent)
        self.assertEqual(self.set_count,count)

    def test_final_owner_exit_failure_cannot_be_swallowed_into_success(self):
        import qshd_selinux_api as native
        from unittest.mock import patch
        for fault in ('counter','close'):
            with self.subTest(fault=fault),patch.object(native,'_STATUS_POISONED',False):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=530) as scope:
                        old,restored=self.restored(scope);self.remove_core()
                        try:
                            with self.native.status_observation() as absent:
                                with scope.final_policy(restored,status=absent) as final:final.capture();final.recheck()
                                if fault=='counter':self.shared.counter+=1
                                else:self.shared.close_error=True
                        except Exception:pass
                self.assertEqual(self.shared.events.count('close'),3)
                self.assertEqual(self.set_count,7)

    def test_all_missing_and_mixed_inventory_remain_absent_with_three_owners(self):
        for mode in ('mixed','missing'):
            with self.subTest(mode=mode):
                self.setUp()
                for path in ('var/log/qshd/qshd.log','var/log/qshd/qshd.log.1'):(self.root/path).unlink()
                if mode=='missing':
                    for path in ('etc/qshd/host_key','run/qshd/helper-status.sock.lock'):(self.root/path).unlink()
                    for path in ('etc/qshd','var/log/qshd','run/qshd'):(self.root/path).rmdir()
                with self.factory.inspection(deadline=530) as scope:
                    old,restored=self.restored(scope);self.remove_core();self.final(scope,restored)
                self.assertEqual(self.set_count,5 if mode=='mixed' else 0)
                self.assertEqual(self.shared.events,['open','updated','updated','close']*3)
                self.assertFalse((self.root/'var/log/qshd/qshd.log').exists())


    def test_restoration_callback_uses_exact_live_core_owner_and_actual_defaults(self):
        for fault in ('closed-core','changed-default','failed-core-close'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=530) as scope:
                        old=self.pair(scope);self.remove_contexts()
                        try:
                            with self.native.status_observation() as core:
                                restored=scope.restore_defaults(old,status=core)
                                if fault=='changed-default':self.default_override='system_u:object_r:changed_t:s0'
                                if fault!='closed-core':scope.recheck_restored(restored)
                                if fault=='failed-core-close':self.shared.counter+=1
                        except Exception:
                            if fault!='failed-core-close':raise
                        if fault=='closed-core':
                            with self.native.status_observation():scope.recheck_restored(restored)
                        elif fault=='failed-core-close':
                            self.remove_core();self.final(scope,restored)
                self.assertEqual(self.set_count,7)

    def test_every_defaults_handle_must_close_normally_without_borrowed_status_closure(self):
        for phase in ('pair','core-only','absent'):
            with self.subTest(phase=phase):
                self.setUp();self.fail_default_exit=phase
                expected=self.m.RetainedLabelOutcomeUncertain if phase=='absent' else self.m.RetainedLabelError
                with self.assertRaises(expected):
                    with self.factory.inspection(deadline=530) as scope:
                        old,restored=self.restored(scope);self.remove_core();self.final(scope,restored)
                self.assertEqual(self.set_count,7 if phase=='absent' else 0)
                self.assertEqual(self.shared.events.count('open'),self.shared.events.count('close'))

    def test_final_recheck_uses_second_current_handle_and_late_inventory_is_not_accepted(self):
        for fault in ('default-after-capture','late-metadata','appeared'):
            with self.subTest(fault=fault):
                self.setUp()
                if fault=='appeared':(self.root/'var/log/qshd/qshd.log.1').unlink()
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=530) as scope:
                        old,restored=self.restored(scope);self.remove_core()
                        with self.native.status_observation() as absent:
                            with scope.final_policy(restored,status=absent) as final:
                                final.capture();calls=len(self.default_calls)
                                if fault=='default-after-capture':self.default_override='system_u:object_r:changed_t:s0'
                                elif fault=='appeared':
                                    path=self.root/'var/log/qshd/qshd.log.1';path.write_bytes(b'new unexpected leaf');path.chmod(0o600)
                                final.recheck()
                        if fault=='late-metadata':os.setxattr(self.root/'etc/qshd','user.fixture',b'after final owner closed')
                if fault!='late-metadata':self.assertGreater(len(self.default_calls),calls)
                self.assertEqual(self.set_count,6 if fault=='appeared' else 7)

    def test_final_fd_closure_failure_attempts_all_retained_fds_and_keeps_uncertainty(self):
        from unittest.mock import patch
        manager=self.factory.inspection(deadline=530);scope=manager.__enter__()
        old,restored=self.restored(scope);self.remove_core();self.final(scope,restored)
        owned=set(scope._fds+scope.anchors+[row[2] for row in scope.routes]);closed=[];native_close=os.close
        def close(fd):
            self.assertEqual(self.shared.events.count('close'),3)
            native_close(fd);closed.append(fd)
            if len(closed)==1:raise OSError('controlled after actual retained close')
        with patch.object(self.m.os,'close',close),self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
            manager.__exit__(None,None,None)
        self.assertEqual(set(closed),owned)
        for fd in owned:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_original_deadline_refuses_slow_final_proof_and_final_close(self):
        for fault in ('proof','close'):
            with self.subTest(fault=fault):
                self.setUp()
                with self.assertRaises(self.m.RetainedLabelOutcomeUncertain):
                    with self.factory.inspection(deadline=530) as scope:
                        old,restored=self.restored(scope);self.remove_core();self.assertEqual(scope._end,530)
                        if fault=='proof':self.now=530
                        else:self.final(scope,restored)
                        self.now=530
                        if fault=='proof':self.final(scope,restored)
                self.assertEqual(self.set_count,7)



if __name__=='__main__':unittest.main()
