"""Owned temporary stores and injected tools only; never host policy calls."""
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
from qshd_selinux_activation import TrustedArtifact
from qshd_selinux_process import _Streams, _Outcome, _CommandError, _Limits
import qshd_selinux_module_install as m

PP=b'synthetic trusted package policy'
CONTEXTS_PP=b'synthetic contexts policy'
TRUST=TrustedArtifact('fixture','a'*64,hashlib.sha256(PP).hexdigest(),hashlib.sha256(CONTEXTS_PP).hexdigest())

def natural_outcome(*args,**kwargs):
    value=_Outcome(*args,**kwargs)
    from dataclasses import replace
    return replace(value,natural=value.failure is None and value.settled and not value.unreaped,stdout_eof=True,stderr_eof=True)

class InstallTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for name in ('usr/bin','usr/lib','etc/selinux','var/lib/selinux/targeted/active/modules','run'):
            (self.root/name).mkdir(parents=True,exist_ok=True)
        for name,data,mode in [('usr/bin/semodule',b'inert',0o755),('usr/lib/os-release',b'ID=fedora\nVERSION_ID=44\n',0o644),('etc/selinux/semanage.conf',b'# fixture',0o644),('var/lib/selinux/targeted/semanage.read.LOCK',b'',0o600)]:
            p=self.root/name;p.write_bytes(data);p.chmod(mode)
        for path in self.root.rglob('*'):
            if path.is_dir():path.chmod(0o755)
        self.calls=[];self.listing=b'100 base cil\n';self.action=None;self.clock=lambda:100.0
        self._last=None
    def _run(self,argv,cwd,*,deadline):
        self.calls.append((argv,Path(cwd),deadline))
        if self.action:return self.action(argv,Path(cwd),deadline)
        self._last=natural_outcome(b'',b'',0,None,True)
        return _Streams(self.listing if argv[-1]=='-lfull' else b'',b'bounded normal diagnostic\n')
    def installer(self,pp=PP):return m.FirstInstall(TRUST,pp,CONTEXTS_PP,_root=self.root,_uid=os.getuid(),_owner=self,_clock=self.clock)
    def test_exact_command_success_stderr_and_owned_cleanup(self):
        value=self.installer().install(deadline=530)
        self.assertEqual(value.artifact,TRUST);self.assertEqual(value.core_pp_sha256,TRUST.core_pp_sha256)
        self.assertEqual(len(self.calls),2)
        prefix=('/usr/bin/semodule','--store-path','/var/lib/selinux','-s','targeted')
        self.assertEqual(self.calls[0][0],prefix+('-lfull',))
        self.assertEqual(self.calls[1][0][:-2],prefix+('-X','400','-i'))
        self.assertEqual(self.calls[0][2],520);self.assertEqual(self.calls[1][2],520)
        self.assertEqual(list((self.root/'run').iterdir()),[])
    def test_any_preexisting_qshd_refuses_without_install(self):
        for row in [b'400 qshd pp\n',b'100 qshd cil disabled\n',b'999 qshd pp\n',b'broken']:
            self.calls=[];self.listing=row
            with self.assertRaises(m.InstallError):self.installer().install(deadline=530)
            self.assertEqual(len(self.calls),1)
            self.assertEqual(list((self.root/'run').iterdir()),[])
    def test_bad_artifact_and_deadline_fail_before_tools(self):
        with self.assertRaises(m.InstallError):self.installer(b'wrong')
        for deadline in (True,float('inf'),100,105):
            with self.assertRaises(m.InstallError):self.installer().install(deadline=deadline)
        self.assertEqual(self.calls,[])
    def test_install_checks_exact_pp_and_active_replacement_is_allowed(self):
        def action(argv,cwd,deadline):
            self._last=natural_outcome(b'',b'',0,None,True)
            if argv[-1]=='-lfull':return _Streams(self.listing,b'')
            self.assertEqual(Path(argv[-2]).read_bytes(),PP)
            self.assertEqual(Path(argv[-1]).read_bytes(),CONTEXTS_PP)
            shutil.rmtree(self.root/'var/lib/selinux/targeted/active')
            (self.root/'var/lib/selinux/targeted/active/modules').mkdir(parents=True)
            (self.root/'var/lib/selinux/targeted/active').chmod(0o755)
            (self.root/'var/lib/selinux/targeted/active/modules').chmod(0o755)
            return _Streams(b'',b'warning is not readiness')
        self.action=action;self.installer().install(deadline=530)
    def test_failure_and_unsettled_dominate_output(self):
        def action(argv,cwd,deadline):
            if argv[-1]=='-lfull':
                self._last=natural_outcome(b'',b'',0,None,True);return _Streams(self.listing,b'')
            self._last=natural_outcome(b'looks successful',b'',0,'COMMAND_CUSTODY',False,(123,))
            return _Streams(b'looks successful',b'')
        self.action=action
        with self.assertRaises(m.InstallError):self.installer().install(deadline=530)
        self.assertTrue(list((self.root/'run').iterdir()))
    def test_stable_input_drift_and_extra_scratch_are_preserved(self):
        def action(argv,cwd,deadline):
            self._last=natural_outcome(b'',b'',0,None,True)
            if argv[-1]=='-lfull':return _Streams(self.listing,b'')
            (cwd/'foreign').write_bytes(b'preserve')
            (self.root/'etc/selinux/semanage.conf').write_bytes(b'drift')
            return _Streams(b'',b'')
        self.action=action
        with self.assertRaises(m.InstallError):self.installer().install(deadline=530)
        self.assertEqual(next((self.root/'run').iterdir()).joinpath('foreign').read_bytes(),b'preserve')
    def test_single_use_and_profile_enumeration(self):
        item=self.installer();item.install(deadline=530)
        with self.assertRaises(m.InstallError):item.install(deadline=530)
        self.assertEqual(_Limits(75,1024*1024).execution_seconds,75)
        for pair in [(75,4096),(74,1024*1024),(60,1024*1024),(16,4096)]:
            with self.assertRaises(_CommandError):_Limits(*pair)

    def test_missing_inputs_and_platform_duplicates_never_bootstrap(self):
        missing=self.root/'var/lib/selinux/targeted/active/modules'
        missing.rmdir()
        with self.assertRaises(m.InstallError):self.installer().install(deadline=530)
        self.assertFalse(missing.exists());self.assertEqual(self.calls,[])
        missing.mkdir(mode=0o755)
        (self.root/'usr/lib/os-release').write_bytes(b'ID=fedora\nID=fedora\nVERSION_ID=44\n')
        with self.assertRaises(m.InstallError):self.installer().install(deadline=530)
        self.assertEqual(self.calls,[])

    def test_expired_remainder_after_listing_cannot_start_install(self):
        now=[100.0];self.clock=lambda:now[0]
        def action(argv,cwd,deadline):
            self._last=natural_outcome(b'',b'',0,None,True)
            now[0]=316
            return _Streams(self.listing,b'')
        self.action=action
        with self.assertRaises(m.InstallError):self.installer().install(deadline=530)
        self.assertEqual(len(self.calls),1)
        self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_write_and_post_open_fstat_faults_close_all_acquired_fds(self):
        import errno
        for operation in ('write','fstat'):
            before=set(os.listdir('/proc/self/fd'))
            native=getattr(m.os,operation);failed=[]
            def fault(*args,**kwargs):
                fd=args[0]
                target=os.readlink('/proc/self/fd/'+str(fd))
                if '/qshd-install-' in target and not failed:
                    failed.append(True);raise OSError(errno.EIO,'injected owned descriptor')
                return native(*args,**kwargs)
            with patch.object(m.os,operation,side_effect=fault),self.assertRaises(m.InstallError):
                self.installer().install(deadline=530)
            self.assertEqual(failed,[True]);self.assertEqual(set(os.listdir('/proc/self/fd')),before)
            self.assertEqual(self.calls,[])
            self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_created_directory_unknown_identity_is_preserved_and_reported(self):
        import errno
        native=os.stat
        def fault(name,*args,**kwargs):
            if type(name) is str and name.startswith('qshd-install-'):
                raise OSError(errno.EIO,'injected creation identity')
            return native(name,*args,**kwargs)
        before=set(os.listdir('/proc/self/fd'))
        with patch.object(m.os,'stat',side_effect=fault),self.assertRaisesRegex(m.InstallError,'CLEANUP'):
            self.installer().install(deadline=530)
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)
        self.assertEqual(len(list((self.root/'run').iterdir())),1)
        self.assertEqual(self.calls,[])

    def test_overflow_and_settled_nonzero_are_never_load_success(self):
        for outcome,streams in [(natural_outcome(b'',b'',1,None,True),_Streams(b'looks good',b'')),
                                (natural_outcome(b'',b'',0,None,True),_Streams(b'x'*(1024*1024),b'x'))]:
            self.calls=[]
            def action(argv,cwd,deadline):
                if argv[-1]=='-lfull':
                    self._last=natural_outcome(b'',b'',0,None,True);return _Streams(self.listing,b'')
                self._last=outcome;return streams
            self.action=action
            with self.assertRaises(m.InstallError):self.installer().install(deadline=530)
            self.assertEqual(len(self.calls),2)
            self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_malformed_typed_artifact_has_fixed_install_error(self):
        bad=object.__new__(TrustedArtifact)
        for name,value in [('provider_version','fixture'),('manifest_sha256','bad'),('core_pp_sha256',TRUST.core_pp_sha256),('contexts_pp_sha256',TRUST.contexts_pp_sha256)]:
            object.__setattr__(bad,name,value)
        with self.assertRaises(m.InstallError):m.FirstInstall(bad,PP,CONTEXTS_PP,_root=self.root,_uid=os.getuid())

    def test_real_binding_selects_two_exact_limits_without_process_calls(self):
        limits=[]
        def owner(profile):limits.append(profile);return self
        item=m.FirstInstall(TRUST,PP,CONTEXTS_PP,_root=self.root,_uid=os.getuid(),_clock=self.clock)
        with patch.object(m,'_Owner',side_effect=owner):item.install(deadline=530)
        self.assertEqual([(x.execution_seconds,x.output_bytes) for x in limits],[(15,1024*1024),(75,1024*1024)])
        self.assertEqual([x[2] for x in self.calls],[520,520])

class OwnedReloadTests(unittest.TestCase):
    def setUp(self):
        InstallTests.setUp(self)
        import importlib.util
        import qshd_selinux_api as native_api
        from scripts.tests.test_selinux_api import SharedStatus, PATH
        spec = importlib.util.spec_from_file_location('reload_status_fixture', PATH)
        self.status_api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.status_api)
        self.status = SharedStatus()
        constructor = patch.object(native_api, 'SelinuxApi',
            side_effect=lambda: self.status_api.SelinuxApi(self.status.library()))
        constructor.start()
        self.addCleanup(constructor.stop)
        errors = patch.object(native_api, 'SelinuxError', self.status_api.SelinuxError)
        errors.start()
        self.addCleanup(errors.stop)
    _run = InstallTests._run

    def observer(self,trusted,*,mode,deadline):
        import qshd_selinux_module_observer as observer
        outer=self
        class Owner:
            _last=None
            def _run(inner, operation, cwd, *, deadline=None):
                outer.observations.append((operation,Path(cwd),deadline))
                inner._last=natural_outcome(b'',b'',0,None,True)
                if outer.observe_action is not None:
                    result=outer.observe_action(operation,Path(cwd),inner)
                    if result is not None:return result
                if operation=='list':return outer.owned_listing
                name,data=('qshd.pp',PP) if operation=='extract-core' else ('qshd_contexts.pp',CONTEXTS_PP)
                path=Path(cwd)/name;path.write_bytes(data);path.chmod(0o600)
                return b''
        class Lease(observer.ModuleObserver):
            def __enter__(inner):
                super().__enter__();inner._owner=Owner();return inner
        return Lease(trusted,mode=mode,deadline=deadline,_root=self.root,_uid=os.getuid(),_runner=lambda *args:None,_clock=self.clock)

    def reloader(self):
        self.observations=[];self.observe_action=None;self.owned_listing=b'100 base cil\n400 qshd pp\n400 qshd_contexts pp\n'
        return m.OwnedReload(TRUST,TRUST,PP,CONTEXTS_PP,_root=self.root,_uid=os.getuid(),
                             _owner=self,_clock=self.clock,_observer=self.observer)

    def test_exact_owned_observation_then_one_normal_load(self):
        item=self.reloader();value=item.reload(deadline=530)
        self.assertEqual(value,m.InstallResult(TRUST,TRUST.core_pp_sha256,TRUST.contexts_pp_sha256))
        self.assertEqual([x[0] for x in self.observations],['list','extract-core','extract-contexts','list','extract-core','extract-contexts'])
        self.assertEqual([x[2] for x in self.observations],[520]*6)
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][0][:-2],m._PREFIX+('-X','400','-i'))
        self.assertEqual(self.calls[0][2],520)
        self.assertEqual(list((self.root/'run').iterdir()),[])
        with self.assertRaises(m.InstallError):item.reload(deadline=530)


    def test_old_check_runs_once_inside_six_call_window_and_refuses_before_scratch(self):
        for fault in ('none','return','raise','drift'):
            with self.subTest(fault=fault):
                item=self.reloader();seen=[]
                def check(status):
                    self.assertEqual(len(self.observations),6)
                    self.assertTrue(self.status.mapped)
                    seen.append(status);status.require_open()
                    if fault=='return':return True
                    if fault=='raise':raise ValueError('controlled old proof refusal')
                    if fault=='drift':self.status.counter+=1
                if fault=='none':
                    item.reload(deadline=530,old_check=check)
                    seen[0].require_closed();self.assertEqual(len(self.calls),1)
                    self.calls=[]
                else:
                    with self.assertRaises(Exception):item.reload(deadline=530,old_check=check)
                    self.assertEqual(self.calls,[]);self.assertIsNone(item._scratch)
                self.assertEqual(len(seen),1)

    def test_native_policy_drift_refuses_old_pair_before_scratch_or_load(self):
        item = self.reloader()
        def drift(operation, cwd, owner):
            if len(self.observations) == 3:
                self.status.counter += 1
        self.observe_action = drift
        with self.assertRaises(m.InstallError):
            item.reload(deadline=530)
        self.assertEqual(self.calls, [])
        self.assertIsNone(item._scratch)
        self.assertEqual(list((self.root/'run').iterdir()), [])
        self.assertFalse(self.status.mapped)

    def test_native_mode_drift_and_close_failure_prevent_reload_mutation(self):
        for fault in ('mode', 'close'):
            with self.subTest(fault=fault):
                item = self.reloader()
                self.status.enforcing = 1
                self.status.close_error = fault == 'close'
                def changed(operation, cwd, owner):
                    if fault == 'mode' and len(self.observations) == 3:
                        self.status.enforcing = 0
                self.observe_action = changed
                error = m.InstallError if fault == 'mode' else RuntimeError
                with self.assertRaises(error):
                    item.reload(deadline=530)
                self.assertEqual(self.calls, [])
                self.assertIsNone(item._scratch)
                self.assertEqual(list((self.root/'run').iterdir()), [])
                self.assertEqual(self.status.events.count('close'), 1 if fault == 'mode' else 2)

    def test_scratch_and_load_follow_both_normal_admission_exits(self):
        from contextlib import contextmanager
        item = self.reloader()
        original_observer = item._observer
        original_scratch = item._make_scratch
        closed = []
        @contextmanager
        def observer(*args, **kwargs):
            with original_observer(*args, **kwargs) as scope:
                yield scope
            self.assertFalse(self.status.mapped)
            closed.append('observer')
        def observed(operation, cwd, owner):
            self.assertTrue(self.status.mapped)
        def scratch():
            self.assertEqual(closed, ['observer'])
            self.assertEqual(self.status.events, ['open', 'updated', 'updated', 'close'])
            self.assertFalse(self.status.mapped)
            original_scratch()
        def load(argv, cwd, deadline):
            self.assertFalse(self.status.mapped)
            self.assertEqual(closed, ['observer'])
            self.assertEqual(len(self.observations), 6)
            self.assertEqual(deadline, 520)
            self._last = natural_outcome(b'', b'', 0, None, True)
            return _Streams(b'', b'')
        item._observer = observer
        item._make_scratch = scratch
        self.observe_action = observed
        self.action = load
        item.reload(deadline=530)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual([entry[2] for entry in self.observations], [520] * 6)
        self.assertEqual(self.status.events, ['open', 'updated', 'updated', 'close'])

    def test_every_nonowned_listing_and_wrong_hll_refuse_before_load(self):
        for listing in (b'100 base cil\n',b'400 qshd pp disabled\n',b'100 qshd pp\n',
                        b'500 qshd pp\n',b'400 qshd pp\n500 qshd pp\n',b'400 qshd cil\n',b'bad'):
            item=self.reloader();self.owned_listing=listing
            with self.subTest(listing=listing),self.assertRaises(m.InstallError):item.reload(deadline=530)
            self.assertEqual(self.calls,[]);self.assertEqual(list((self.root/'run').iterdir()),[])
        item=self.reloader()
        def wrong(operation,cwd,owner):
            if operation=='extract-core':
                p=cwd/'qshd.pp';p.write_bytes(b'wrong HLL');p.chmod(0o600);return b''
        self.observe_action=wrong
        with self.assertRaises(m.InstallError):item.reload(deadline=530)
        self.assertEqual(self.calls,[])

    def test_observer_recheck_drift_and_exit_failure_prevent_load(self):
        item=self.reloader()
        def drift(operation,cwd,owner):
            if len(self.observations)==4:return b'400 qshd pp disabled\n'
        self.observe_action=drift
        with self.assertRaises(m.InstallError):item.reload(deadline=530)
        self.assertEqual(self.calls,[])
        from contextlib import contextmanager
        factory=self.observer
        @contextmanager
        def bad_exit(trusted,**kwargs):
            with factory(trusted,**kwargs) as lease:yield lease
            raise m.ObserverError('synthetic normal-exit failure')
        item=self.reloader();item._observer=bad_exit
        with self.assertRaises(m.InstallError):item.reload(deadline=530)
        self.assertEqual(self.calls,[]);self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_observer_close_error_closes_all_fds_and_prevents_load(self):
        item=self.reloader();native=os.close;failed=[];before=set(os.listdir('/proc/self/fd'))
        def close(fd):
            target=os.readlink('/proc/self/fd/'+str(fd));native(fd)
            if 'qshd-module-' in target and not failed:
                failed.append(True);raise OSError('synthetic after real close')
        with patch.object(m.os,'close',side_effect=close),self.assertRaises(m.InstallError):item.reload(deadline=530)
        self.assertTrue(failed);self.assertEqual(self.calls,[])
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_original_deadline_includes_observation_without_reset(self):
        now=[100.0];self.clock=lambda:now[0];item=self.reloader()
        def advance(operation,cwd,owner):
            if len(self.observations)==6:now[0]=160.0
        self.observe_action=advance
        item.reload(deadline=530)
        self.assertEqual([x[2] for x in self.observations],[520]*6)
        self.assertEqual(self.calls[0][2],520)
        self.calls=[];now[0]=100.0;item=self.reloader()
        def expire(operation,cwd,owner):now[0]=316.0
        self.observe_action=expire
        with self.assertRaises(m.InstallError):item.reload(deadline=530)
        self.assertEqual(self.calls,[])

    def test_protected_scratch_exact_pp_after_observer_cleanup_and_active_replacement(self):
        item=self.reloader()
        def load(argv,cwd,deadline):
            self.assertEqual([p.name for p in (self.root/'run').iterdir()],[cwd.name])
            self.assertEqual((cwd/'qshd.pp').read_bytes(),PP)
            self.assertEqual((cwd/'qshd.pp').stat().st_mode&0o777,0o600)
            self.assertEqual(cwd.stat().st_mode&0o777,0o700)
            shutil.rmtree(self.root/'var/lib/selinux/targeted/active')
            (self.root/'var/lib/selinux/targeted/active/modules').mkdir(parents=True)
            (self.root/'var/lib/selinux/targeted/active').chmod(0o755)
            (self.root/'var/lib/selinux/targeted/active/modules').chmod(0o755)
            self._last=natural_outcome(b'',b'',0,None,True);return _Streams(b'',b'normal diagnostic')
        self.action=load;item.reload(deadline=530)
        self.assertEqual(len(self.calls),1);self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_load_nonzero_overflow_and_unsettled_never_return_result(self):
        for mode in ('nonzero','overflow','unsettled'):
            self.calls=[];item=self.reloader()
            def fail(argv,cwd,deadline):
                self._last=natural_outcome(b'',b'',1 if mode=='nonzero' else 0,
                                    'COMMAND_CUSTODY' if mode=='unsettled' else None,
                                    mode!='unsettled',(123,) if mode=='unsettled' else ())
                return _Streams(b'x'*(1024*1024+1) if mode=='overflow' else b'',b'')
            self.action=fail
            with self.subTest(mode=mode),self.assertRaises(m.InstallError):item.reload(deadline=530)
            self.assertEqual(len(self.calls),1)
            if mode=='unsettled':self.assertTrue(list((self.root/'run').iterdir()))
            else:self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_observer_unsettled_preserves_its_owned_scratch_without_load(self):
        item=self.reloader();before=set(os.listdir('/proc/self/fd'))
        def unsettled(operation,cwd,owner):
            owner._last=natural_outcome(b'',b'',None,'COMMAND_CUSTODY',False,(123,))
            raise _CommandError('COMMAND_CUSTODY')
        self.observe_action=unsettled
        with self.assertRaises(m.InstallError):item.reload(deadline=530)
        self.assertEqual(self.calls,[]);self.assertTrue(list((self.root/'run').iterdir()))
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_final_cleanup_and_final_deadline_failure_suppress_result(self):
        for mode in ('close','late'):
            now=[100.0];self.clock=lambda:now[0];item=self.reloader();original=item._cleanup
            def cleanup():
                original()
                if mode=='close':raise m.InstallError('CLEANUP')
                now[0]=531.0
            item._cleanup=cleanup
            with self.subTest(mode=mode),self.assertRaises(m.InstallError):item.reload(deadline=530)
            self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_production_factory_fixed_observer_and_normal_load_profile(self):
        item=self.reloader();factory=self.observer;limits=[]
        def owner(profile):limits.append(profile);return self
        with patch.object(m.os,'geteuid',return_value=0),patch.object(m,'production_observer',side_effect=factory) as observed,patch.object(m,'_Owner',side_effect=owner):
            value=m.production_owned_reloader(TRUST,TRUST,PP,CONTEXTS_PP)
            value.anchor=self.root;value.uid=os.getuid();value._clock=self.clock
            value.reload(deadline=530)
        observed.assert_called_once_with(TRUST,mode='pair',deadline=530)
        self.assertEqual(limits,[_Limits(75,1024*1024)])
        self.assertFalse(hasattr(value,'install'))
        with patch.object(m.os,'geteuid',return_value=65534),self.assertRaises(m.InstallError):m.production_owned_reloader(TRUST,TRUST,PP,CONTEXTS_PP)


    def test_stable_authority_drift_after_observer_exit_never_loads(self):
        from contextlib import contextmanager
        factory=self.observer;item=self.reloader()
        @contextmanager
        def drift(trusted,**kwargs):
            with factory(trusted,**kwargs) as lease:yield lease
            (self.root/'etc/selinux/semanage.conf').write_bytes(b'changed after observer cleanup')
        item._observer=drift
        with self.assertRaises(m.InstallError):item.reload(deadline=530)
        self.assertEqual(self.calls,[]);self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_real_owner_timeout_category_and_expired_admission_never_succeed(self):
        item=self.reloader()
        def timeout(argv,cwd,deadline):
            self._last=natural_outcome(b'',b'',None,'COMMAND_TIMEOUT',True)
            raise _CommandError('COMMAND_TIMEOUT')
        self.action=timeout
        with self.assertRaises(m.InstallError):item.reload(deadline=530)
        self.assertEqual(len(self.calls),1);self.assertEqual(list((self.root/'run').iterdir()),[])
        self.calls=[];item=self.reloader()
        with self.assertRaises(m.InstallError):item.reload(deadline=105)
        self.assertEqual(self.observations,[]);self.assertEqual(self.calls,[])




class PairRemovalSessionTests(unittest.TestCase):
    setUp=InstallTests.setUp
    def setup_session(self,*,deadline=530):
        from contextlib import contextmanager
        import qshd_selinux_module_observer as module
        self.listing=b'100 base cil\n400 qshd pp\n400 qshd_contexts pp\n'
        self.observations=[];self.events=[];self.window_count=0;self.window_open=0
        self.window_failure=None;self.observe_action=None;self.remove_action=None
        outer=self
        def runner(operation,cwd,*,deadline):
            outer.observations.append((operation,deadline))
            if outer.observe_action is not None:
                result=outer.observe_action(operation,Path(cwd))
                if result is not None:return result
            if operation=='list':return outer.listing
            name,data=('qshd.pp',PP) if operation=='extract-core' else ('qshd_contexts.pp',CONTEXTS_PP)
            p=Path(cwd)/name;p.write_bytes(data);p.chmod(0o600);return b''
        def observer(trust,*,mode,deadline):
            outer.assertEqual(trust,TRUST)
            return module._testing_observer(trust,outer.root,runner,mode=mode,deadline=deadline,_clock=outer.clock)
        @contextmanager
        def window():
            outer.window_count+=1;count=outer.window_count
            outer.window_open+=1;outer.events.append(('window enter',count))
            try:yield
            finally:outer.window_open-=1;outer.events.append(('window exit',count))
            if outer.window_failure==count:raise RuntimeError('controlled native finalizer')
        return m.PairRemovalSession(TRUST,PP,CONTEXTS_PP,deadline=deadline,_root=self.root,_uid=os.getuid(),_owner=self,_clock=self.clock,_observer=observer,_window=window)
    def _run(self,argv,cwd,*,deadline):
        self.calls.append((argv,Path(cwd),deadline));self.assertEqual(self.window_open,0)
        self._last=natural_outcome(b'',b'',0,None,True)
        if self.remove_action:return self.remove_action(argv,cwd,deadline)
        self.assertEqual(argv[:-1],m._PREFIX+('-X','400','-r'))
        if argv[-1]=='qshd_contexts':self.listing=b'400 qshd pp\n'
        else:self.assertEqual(argv[-1],'qshd');self.listing=b'100 base cil\n'
        return _Streams(b'',b'bounded tool diagnostic')
    def pair(self,session):
        with session.observation('pair') as view:
            token=view.capture();view.recheck(token)
        return token
    def core(self,session,callback=None):
        def checked():
            self.assertEqual(self.window_open,1);self.events.append(('restoration checked',2))
        with session.observation('core-only') as view:
            token=view.capture();view.recheck(token)
            restored=view.recheck_restoration(token,checked if callback is None else callback)
        return token,restored
    def finish(self,session):
        with session.observation('absent') as view:
            token=view.capture();view.recheck(token)
    def full(self,session):
        with session:
            pair=self.pair(session);session.remove_contexts(pair)
            core,restored=self.core(session);session.remove_core(core,restored)
            self.finish(session)
        return pair,core,restored
    def test_same_session_fourteen_calls_and_ordered_normal_windows(self):
        session=self.setup_session();self.full(session)
        self.assertEqual([x[0][-1] for x in self.calls],['qshd_contexts','qshd'])
        self.assertEqual(len(self.observations),12);self.assertEqual(session._index,14)
        self.assertEqual([x[1] for x in self.observations],[520]*12)
        self.assertEqual([x[2] for x in self.calls],[520]*2)
        self.assertIn(('restoration checked',2),self.events)
        self.assertEqual(list((self.root/'run').iterdir()),[])
    def test_nonowned_module_never_reaches_remove(self):
        for row in (b'',b'100 qshd pp\n400 qshd_contexts pp\n',b'400 qshd pp\n500 qshd_contexts pp\n'):
            self.calls=[];session=self.setup_session();self.listing=row
            with self.assertRaises(Exception):
                with session:self.pair(session)
            self.assertEqual(self.calls,[])
    def test_external_copied_open_and_reused_tokens_refuse(self):
        for kind in ('foreign','open','copy'):
            self.calls=[];session=self.setup_session()
            with self.assertRaises(m.InstallError):
                with session:
                    if kind=='open':
                        with session.observation('pair') as view:
                            token=view.capture();view.recheck(token);session.remove_contexts(token)
                    else:
                        token=self.pair(session);session.remove_contexts(object() if kind=='foreign' else m._Admission())
            self.assertEqual(self.calls,[])
        session=self.setup_session();self.calls=[]
        with self.assertRaises(m.InstallError):
            with session:
                token=self.pair(session);session.remove_contexts(token);session.remove_contexts(token)
        self.assertEqual(len(self.calls),1)
    def test_tokens_cannot_be_serialized_or_substituted_after_close(self):
        import pickle
        session=self.setup_session()
        with session:
            token=self.pair(session)
            with self.assertRaises(TypeError):pickle.dumps(token)
            session.remove_contexts(token);core,restored=self.core(session);session.remove_core(core,restored);self.finish(session)
        before=len(self.calls)
        with self.assertRaises(m.InstallError):session.remove_core(core,restored)
        self.assertEqual(len(self.calls),before)
    def test_restoration_callback_exactly_once_after_recheck(self):
        for result in (True,object(),RuntimeError('controlled restore failure')):
            session=self.setup_session();self.calls=[];called=[]
            def callback():
                called.append(True)
                if isinstance(result,Exception):raise result
                return result
            with self.assertRaises(Exception):
                with session:
                    session.remove_contexts(self.pair(session))
                    with session.observation('core-only') as view:
                        token=view.capture();view.recheck(token)
                        with self.assertRaises(Exception):view.recheck_restoration(token,callback)
                        with self.assertRaises(m.InstallError):view.recheck_restoration(token,callback)
            self.assertEqual(called,[True]);self.assertEqual(len(self.calls),1)
        session=self.setup_session();self.calls=[]
        with self.assertRaises(m.InstallError):
            with session:
                session.remove_contexts(self.pair(session))
                with session.observation('core-only') as view:
                    token=view.capture();view.recheck_restoration(token,lambda:None)
        self.assertEqual(len(self.calls),1)
    def test_native_and_observer_cleanup_failure_invalidate_admissions(self):
        session=self.setup_session();self.window_failure=1
        with self.assertRaises(RuntimeError):
            with session:self.pair(session)
        self.assertEqual(self.calls,[])
        session=self.setup_session();self.calls=[];self.window_failure=2
        with self.assertRaises(RuntimeError):
            with session:
                session.remove_contexts(self.pair(session));self.core(session)
        self.assertEqual(len(self.calls),1)
    def test_wrong_hll_recheck_drift_and_observer_close_refuse(self):
        session=self.setup_session()
        def wrong(op,cwd):
            if op=='extract-contexts':
                p=cwd/'qshd_contexts.pp';p.write_bytes(PP);p.chmod(0o600);return b''
        self.observe_action=wrong
        with self.assertRaises(Exception):
            with session:self.pair(session)
        self.assertEqual(self.calls,[])
    def test_removal_failure_never_reaches_later_observation(self):
        session=self.setup_session()
        def refuse(*args):self._last=natural_outcome(b'',b'',1,None,True);return _Streams(b'',b'')
        self.remove_action=refuse
        with self.assertRaises(m.InstallError):self.full(session)
        self.assertEqual(len(self.observations),6);self.assertEqual(len(self.calls),1)
    def test_both_fresh_absence_samples_reject_reserved_names(self):
        for which in (11,12):
            self.calls=[];session=self.setup_session()
            def conflict(op,cwd):
                if len(self.observations)==which:return b'999 qshd_contexts pp disabled\n'
            self.observe_action=conflict
            with self.assertRaises(Exception):self.full(session)
            self.assertEqual(len(self.calls),2)
    def test_original_deadline_admission_and_two_removal_reserves(self):
        for now,passes in ((149.999,True),(150,False),(150.001,False)):
            self.calls=[];self.clock=lambda:now;session=self.setup_session()
            if passes:self.full(session);self.assertEqual(len(self.calls),2)
            else:
                with self.assertRaises(m.InstallError):
                    with session:pass
                self.assertEqual(self.observations,[]);self.assertEqual(self.calls,[])
        now=[100];self.clock=lambda:now[0];session=self.setup_session();self.calls=[]
        with self.assertRaises(m.InstallError):
            with session:
                token=self.pair(session);now[0]=240;session.remove_contexts(token)
        self.assertEqual(self.calls,[])
        now[0]=100;session=self.setup_session();self.calls=[]
        with self.assertRaises(m.InstallError):
            with session:
                session.remove_contexts(self.pair(session));now[0]=250
                core,restored=self.core(session);now[0]=375;session.remove_core(core,restored)
        self.assertEqual(len(self.calls),1)
    def test_late_command_and_final_cleanup_suppress_result(self):
        now=[100];self.clock=lambda:now[0];session=self.setup_session()
        def late(*args):self._last=natural_outcome(b'',b'',0,None,True);now[0]=530;return _Streams(b'',b'')
        self.remove_action=late
        with self.assertRaises(Exception):self.full(session)
        self.assertEqual(len(self.calls),1)
        now[0]=100;self.calls=[];session=self.setup_session();original=session._cleanup
        def cleanup():original();now[0]=530
        session._cleanup=cleanup
        with self.assertRaises(m.InstallError):self.full(session)
    def test_active_tree_replacement_is_readmitted(self):
        session=self.setup_session();original=self._run
        def replaced(argv,cwd,*,deadline):
            value=original(argv,cwd,deadline=deadline)
            active=self.root/'var/lib/selinux/targeted/active';shutil.rmtree(active);(active/'modules').mkdir(parents=True)
            active.chmod(0o755);(active/'modules').chmod(0o755);return value
        self._run=replaced;self.full(session)
    def test_unsafe_active_and_changed_authority_refuse_after_remove(self):
        session=self.setup_session()
        def drift(*args):
            self._last=natural_outcome(b'',b'',0,None,True)
            (self.root/'etc/selinux/semanage.conf').write_bytes(b'changed')
            return _Streams(b'',b'')
        self.remove_action=drift
        with self.assertRaises(Exception):self.full(session)
        self.assertEqual(len(self.calls),1)
    def test_normal_and_failed_setup_close_all_route_fds(self):
        before=set(os.listdir('/proc/self/fd'));self.full(self.setup_session())
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)
        (self.root/'usr/bin/semodule').chmod(0o666)
        with self.assertRaises(Exception):
            with self.setup_session():pass
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)
    def test_production_factory_root_gate_and_original_profiles(self):
        with patch.object(m.os,'geteuid',return_value=1000),self.assertRaises(m.InstallError):
            m.production_removal_session(TRUST,PP,CONTEXTS_PP,deadline=530)
        self.assertEqual(_Limits(75,1024**2).execution_seconds,75)
    def test_each_mutation_before_equal_after_reserve_uses_same_end(self):
        for role,boundary in (('contexts',240),('core',375)):
            for shift in (-.001,0,.001):
                now=[100];self.clock=lambda:now[0];self.calls=[];session=self.setup_session()
                def flow():
                    with session:
                        pair=self.pair(session)
                        if role=='contexts':now[0]=boundary+shift
                        session.remove_contexts(pair)
                        core,restored=self.core(session)
                        if role=='core':now[0]=boundary+shift
                        session.remove_core(core,restored);self.finish(session)
                if shift<0:flow();self.assertEqual(len(self.calls),2)
                else:
                    with self.assertRaises(m.InstallError):flow()
                    self.assertEqual(len(self.calls),0 if role=='contexts' else 1)

    def test_restore_admission_not_usable_while_open_or_from_another_scope(self):
        for kind in ('open','foreign-restoration','foreign-core','second-callback'):
            self.calls=[];session=self.setup_session();called=[]
            def callback():called.append(True)
            with self.assertRaises(m.InstallError):
                with session:
                    pair=self.pair(session);session.remove_contexts(pair)
                    with session.observation('core-only') as view:
                        token=view.capture();view.recheck(token);restored=view.recheck_restoration(token,callback)
                        if kind=='open':session.remove_core(token,restored)
                        if kind=='second-callback':view.recheck_restoration(token,callback)
                    session.remove_core(pair if kind=='foreign-core' else token,m._RestorationAdmission() if kind=='foreign-restoration' else restored)
            self.assertEqual(called,[True]);self.assertEqual(len(self.calls),1)

    def test_close_error_after_absence_attempts_every_owned_fd(self):
        session=self.setup_session();before=set(os.listdir('/proc/self/fd'));native=os.close;failed=[]
        def close(fd):
            native(fd)
            if not failed:failed.append(fd);raise OSError('after real owned close')
        with self.assertRaises(m.InstallError):
            with session:
                session.remove_contexts(self.pair(session));core,restored=self.core(session);session.remove_core(core,restored);self.finish(session)
                with patch.object(m.os,'close',side_effect=close):session.__exit__(None,None,None)
        self.assertTrue(failed);self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_unsettled_observer_preserves_scratch_without_removal(self):
        import qshd_selinux_module_observer as observer
        session=self.setup_session();before=set(os.listdir('/proc/self/fd'))
        class Owner:
            _last=_Outcome(b'',b'',None,'COMMAND_UNSETTLED',False,(123,))
            def _run(inner,*args,**kwargs):raise _CommandError('COMMAND_UNSETTLED')
        outer=self
        class Lease(observer.ModuleObserver):
            def __enter__(inner):
                super().__enter__();inner._owner=Owner();return inner
        session._observer=lambda trust,**kwargs:Lease(trust,_root=self.root,_uid=os.getuid(),_runner=lambda *a:None,_clock=self.clock,**kwargs)
        with self.assertRaises(Exception):
            with session:self.pair(session)
        self.assertEqual(self.calls,[]);self.assertTrue(list((self.root/'run').iterdir()))
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_unsettled_removal_cannot_be_followed_by_absence(self):
        session=self.setup_session()
        def unsettled(*args):self._last=outcome=_Outcome(b'',b'',None,'COMMAND_UNSETTLED',False,(123,));return _Streams(b'',b'')
        self.remove_action=unsettled
        with self.assertRaises(Exception):self.full(session)
        self.assertEqual(len(self.observations),6)

    def real_status_session(self):
        from contextlib import contextmanager
        import importlib.util
        from scripts.tests.test_selinux_api import SharedStatus, PATH
        spec = importlib.util.spec_from_file_location('session_status_fixture', PATH)
        status_api = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(status_api)
        shared = SharedStatus()
        owner = status_api.SelinuxApi(shared.library())
        session = self.setup_session()
        @contextmanager
        def window():
            self.window_open += 1
            try:
                with owner.status_observation() as token:
                    yield token
            finally:
                self.window_open -= 1
        session._window = window
        return session, shared, owner, status_api

    def test_real_api_tokens_follow_three_normal_session_windows(self):
        session, shared, owner, status_api = self.real_status_session()
        tokens = []
        with session:
            with session.observation('pair') as view:
                tokens.append(view.status_token)
                self.assertIs(tokens[-1].require_open(), owner)
                pair = view.capture()
                view.recheck(pair)
            tokens[-1].require_closed()
            session.remove_contexts(pair)
            with session.observation('core-only') as view:
                tokens.append(view.status_token)
                tokens[0].require_closed()
                core = view.capture()
                view.recheck(core)
                def restore_recheck():
                    before = list(shared.events)
                    self.assertIs(view.status_token.require_open(), owner)
                    self.assertEqual(shared.events, before)
                restored = view.recheck_restoration(core, restore_recheck)
            tokens[-1].require_closed()
            session.remove_core(core, restored)
            with session.observation('absent') as view:
                tokens.append(view.status_token)
                for previous in tokens[:-1]: previous.require_closed()
                absence = view.capture()
                view.recheck(absence)
        for token in tokens:
            token.require_closed()
            with self.assertRaises(status_api.SelinuxError): token.require_open()
        self.assertEqual(shared.events, ['open', 'updated', 'updated', 'close'] * 3)
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(session._index, 14)

    def test_real_owner_drift_prevents_core_admission_after_callback(self):
        session, shared, owner, status_api = self.real_status_session()
        with self.assertRaises(status_api.SelinuxError):
            with session:
                session.remove_contexts(self.pair(session))
                with session.observation('core-only') as view:
                    status = view.status_token
                    core = view.capture()
                    view.recheck(core)
                    def drift():
                        self.assertIs(status.require_open(), owner)
                        shared.counter += 1
                    view.recheck_restoration(core, drift)
        with self.assertRaises(status_api.SelinuxError): status.require_closed()
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(shared.mapped)
        self.assertEqual(shared.events.count('close'), 2)
        self.assertEqual(list((self.root/'run').iterdir()), [])

if __name__=='__main__':unittest.main()
