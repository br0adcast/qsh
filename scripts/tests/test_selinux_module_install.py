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
TRUST=TrustedArtifact('fixture','a'*64,hashlib.sha256(PP).hexdigest())

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
        self._last=_Outcome(b'',b'',0,None,True)
        return _Streams(self.listing if argv[-1]=='-lfull' else b'',b'bounded normal diagnostic\n')
    def installer(self,pp=PP):return m.FirstInstall(TRUST,pp,_root=self.root,_uid=os.getuid(),_owner=self,_clock=self.clock)
    def test_exact_command_success_stderr_and_owned_cleanup(self):
        value=self.installer().install(deadline=250)
        self.assertEqual(value.artifact,TRUST);self.assertEqual(value.pp_sha256,TRUST.pp_sha256)
        self.assertEqual(len(self.calls),2)
        prefix=('/usr/bin/semodule','--store-path','/var/lib/selinux','-s','targeted')
        self.assertEqual(self.calls[0][0],prefix+('-lfull',))
        self.assertEqual(self.calls[1][0][:-1],prefix+('-X','400','-i'))
        self.assertEqual(self.calls[0][2],200);self.assertEqual(self.calls[1][2],200)
        self.assertEqual(list((self.root/'run').iterdir()),[])
    def test_any_preexisting_qshd_refuses_without_install(self):
        for row in [b'400 qshd pp\n',b'100 qshd cil disabled\n',b'999 qshd pp\n',b'broken']:
            self.calls=[];self.listing=row
            with self.assertRaises(m.InstallError):self.installer().install(deadline=210)
            self.assertEqual(len(self.calls),1)
            self.assertEqual(list((self.root/'run').iterdir()),[])
    def test_bad_artifact_and_deadline_fail_before_tools(self):
        with self.assertRaises(m.InstallError):self.installer(b'wrong')
        for deadline in (True,float('inf'),100,105):
            with self.assertRaises(m.InstallError):self.installer().install(deadline=deadline)
        self.assertEqual(self.calls,[])
    def test_install_checks_exact_pp_and_active_replacement_is_allowed(self):
        def action(argv,cwd,deadline):
            self._last=_Outcome(b'',b'',0,None,True)
            if argv[-1]=='-lfull':return _Streams(self.listing,b'')
            self.assertEqual(Path(argv[-1]).read_bytes(),PP)
            shutil.rmtree(self.root/'var/lib/selinux/targeted/active')
            (self.root/'var/lib/selinux/targeted/active/modules').mkdir(parents=True)
            (self.root/'var/lib/selinux/targeted/active').chmod(0o755)
            (self.root/'var/lib/selinux/targeted/active/modules').chmod(0o755)
            return _Streams(b'',b'warning is not readiness')
        self.action=action;self.installer().install(deadline=210)
    def test_actual_launch_exception_preserves_scratch_for_known_and_unknown_census(self):
        import importlib.util
        import subprocess
        path = Path(__file__).with_name('test_selinux_module_process.py')
        spec = importlib.util.spec_from_file_location('launch_custody_controls', path)
        controls = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(controls)
        for case in ('launch-child-consumer', 'launch-child-consumer-unknown'):
            with self.subTest(case=case):
                result = subprocess.run(
                    [sys.executable, '-I', '-B', '-c', controls.HARNESS,
                     str(controls.SOURCE), case],
                    capture_output=True, text=True, timeout=15)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('"passed": true', result.stdout)

    def test_failure_and_unsettled_dominate_output(self):
        def action(argv,cwd,deadline):
            if argv[-1]=='-lfull':
                self._last=_Outcome(b'',b'',0,None,True);return _Streams(self.listing,b'')
            self._last=_Outcome(b'looks successful',b'',0,'COMMAND_CUSTODY',False,(123,))
            return _Streams(b'looks successful',b'')
        self.action=action
        with self.assertRaises(m.InstallError):self.installer().install(deadline=210)
        self.assertTrue(list((self.root/'run').iterdir()))
    def test_stable_input_drift_and_extra_scratch_are_preserved(self):
        def action(argv,cwd,deadline):
            self._last=_Outcome(b'',b'',0,None,True)
            if argv[-1]=='-lfull':return _Streams(self.listing,b'')
            (cwd/'foreign').write_bytes(b'preserve')
            (self.root/'etc/selinux/semanage.conf').write_bytes(b'drift')
            return _Streams(b'',b'')
        self.action=action
        with self.assertRaises(m.InstallError):self.installer().install(deadline=210)
        self.assertEqual(next((self.root/'run').iterdir()).joinpath('foreign').read_bytes(),b'preserve')
    def test_single_use_and_profile_enumeration(self):
        item=self.installer();item.install(deadline=210)
        with self.assertRaises(m.InstallError):item.install(deadline=210)
        self.assertEqual(_Limits(75,1024*1024).execution_seconds,75)
        for pair in [(75,4096),(74,1024*1024),(60,1024*1024),(16,4096)]:
            with self.assertRaises(_CommandError):_Limits(*pair)

    def test_missing_inputs_and_platform_duplicates_never_bootstrap(self):
        missing=self.root/'var/lib/selinux/targeted/active/modules'
        missing.rmdir()
        with self.assertRaises(m.InstallError):self.installer().install(deadline=210)
        self.assertFalse(missing.exists());self.assertEqual(self.calls,[])
        missing.mkdir(mode=0o755)
        (self.root/'usr/lib/os-release').write_bytes(b'ID=fedora\nID=fedora\nVERSION_ID=44\n')
        with self.assertRaises(m.InstallError):self.installer().install(deadline=210)
        self.assertEqual(self.calls,[])

    def test_expired_remainder_after_listing_cannot_start_install(self):
        now=[100.0];self.clock=lambda:now[0]
        def action(argv,cwd,deadline):
            self._last=_Outcome(b'',b'',0,None,True)
            now[0]=201
            return _Streams(self.listing,b'')
        self.action=action
        with self.assertRaises(m.InstallError):self.installer().install(deadline=210)
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
                self.installer().install(deadline=210)
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
            self.installer().install(deadline=210)
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)
        self.assertEqual(len(list((self.root/'run').iterdir())),1)
        self.assertEqual(self.calls,[])

    def test_overflow_and_settled_nonzero_are_never_load_success(self):
        for outcome,streams in [(_Outcome(b'',b'',1,None,True),_Streams(b'looks good',b'')),
                                (_Outcome(b'',b'',0,None,True),_Streams(b'x'*(1024*1024),b'x'))]:
            self.calls=[]
            def action(argv,cwd,deadline):
                if argv[-1]=='-lfull':
                    self._last=_Outcome(b'',b'',0,None,True);return _Streams(self.listing,b'')
                self._last=outcome;return streams
            self.action=action
            with self.assertRaises(m.InstallError):self.installer().install(deadline=210)
            self.assertEqual(len(self.calls),2)
            self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_malformed_typed_artifact_has_fixed_install_error(self):
        bad=object.__new__(TrustedArtifact)
        for name,value in [('provider_version','fixture'),('manifest_sha256','bad'),('pp_sha256',TRUST.pp_sha256)]:
            object.__setattr__(bad,name,value)
        with self.assertRaises(m.InstallError):m.FirstInstall(bad,PP,_root=self.root,_uid=os.getuid())

    def test_real_binding_selects_two_exact_limits_without_process_calls(self):
        limits=[]
        def owner(profile):limits.append(profile);return self
        item=m.FirstInstall(TRUST,PP,_root=self.root,_uid=os.getuid(),_clock=self.clock)
        with patch.object(m,'_Owner',side_effect=owner):item.install(deadline=205)
        self.assertEqual([(x.execution_seconds,x.output_bytes) for x in limits],[(15,1024*1024),(75,1024*1024)])
        self.assertEqual([x[2] for x in self.calls],[195,195])

class OwnedReloadTests(unittest.TestCase):
    setUp = InstallTests.setUp
    _run = InstallTests._run

    def observer(self, trusted):
        import qshd_selinux_module_observer as observer
        outer=self
        class Owner:
            _last=None
            def _run(inner, operation, cwd, *, deadline=None):
                outer.observations.append((operation,Path(cwd),deadline))
                inner._last=_Outcome(b'',b'',0,None,True)
                if outer.observe_action is not None:
                    result=outer.observe_action(operation,Path(cwd),inner)
                    if result is not None:return result
                if operation=='list':return outer.owned_listing
                path=Path(cwd)/'qshd.pp';path.write_bytes(PP);path.chmod(0o600)
                return b''
        class Lease(observer.ModuleObserver):
            def __enter__(inner):
                super().__enter__();inner._owner=Owner();return inner
        return Lease(trusted,_root=self.root,_uid=os.getuid(),_runner=lambda *args:None)

    def reloader(self):
        self.observations=[];self.observe_action=None;self.owned_listing=b'100 base cil\n400 qshd pp\n'
        return m.OwnedReload(TRUST,PP,_root=self.root,_uid=os.getuid(),
                             _owner=self,_clock=self.clock,_observer=self.observer)

    def test_exact_owned_observation_then_one_normal_load(self):
        item=self.reloader();value=item.reload(deadline=250)
        self.assertEqual(value,m.InstallResult(TRUST,TRUST.pp_sha256))
        self.assertEqual([x[0] for x in self.observations],['list','extract','list','extract'])
        self.assertEqual([x[2] for x in self.observations],[200]*4)
        self.assertEqual(len(self.calls),1)
        self.assertEqual(self.calls[0][0][:-1],m._PREFIX+('-X','400','-i'))
        self.assertEqual(self.calls[0][2],200)
        self.assertEqual(list((self.root/'run').iterdir()),[])
        with self.assertRaises(m.InstallError):item.reload(deadline=250)


    def test_every_nonowned_listing_and_wrong_hll_refuse_before_load(self):
        for listing in (b'100 base cil\n',b'400 qshd pp disabled\n',b'100 qshd pp\n',
                        b'500 qshd pp\n',b'400 qshd pp\n500 qshd pp\n',b'400 qshd cil\n',b'bad'):
            item=self.reloader();self.owned_listing=listing
            with self.subTest(listing=listing),self.assertRaises(m.InstallError):item.reload(deadline=250)
            self.assertEqual(self.calls,[]);self.assertEqual(list((self.root/'run').iterdir()),[])
        item=self.reloader()
        def wrong(operation,cwd,owner):
            if operation=='extract':
                p=cwd/'qshd.pp';p.write_bytes(b'wrong HLL');p.chmod(0o600);return b''
        self.observe_action=wrong
        with self.assertRaises(m.InstallError):item.reload(deadline=250)
        self.assertEqual(self.calls,[])

    def test_observer_recheck_drift_and_exit_failure_prevent_load(self):
        item=self.reloader()
        def drift(operation,cwd,owner):
            if len(self.observations)==3:return b'400 qshd pp disabled\n'
        self.observe_action=drift
        with self.assertRaises(m.InstallError):item.reload(deadline=250)
        self.assertEqual(self.calls,[])
        from contextlib import contextmanager
        factory=self.observer
        @contextmanager
        def bad_exit(trusted):
            with factory(trusted) as lease:yield lease
            raise m.ObserverError('synthetic normal-exit failure')
        item=self.reloader();item._observer=bad_exit
        with self.assertRaises(m.InstallError):item.reload(deadline=250)
        self.assertEqual(self.calls,[]);self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_observer_close_error_closes_all_fds_and_prevents_load(self):
        item=self.reloader();native=os.close;failed=[];before=set(os.listdir('/proc/self/fd'))
        def close(fd):
            target=os.readlink('/proc/self/fd/'+str(fd));native(fd)
            if 'qshd-module-' in target and not failed:
                failed.append(True);raise OSError('synthetic after real close')
        with patch.object(m.os,'close',side_effect=close),self.assertRaises(m.InstallError):item.reload(deadline=250)
        self.assertTrue(failed);self.assertEqual(self.calls,[])
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_original_deadline_includes_observation_without_reset(self):
        now=[100.0];self.clock=lambda:now[0];item=self.reloader()
        def advance(operation,cwd,owner):
            if len(self.observations)==4:now[0]=160.0
        self.observe_action=advance
        item.reload(deadline=250)
        self.assertEqual([x[2] for x in self.observations],[200]*4)
        self.assertEqual(self.calls[0][2],200)
        self.calls=[];now[0]=100.0;item=self.reloader()
        def expire(operation,cwd,owner):now[0]=201.0
        self.observe_action=expire
        with self.assertRaises(m.InstallError):item.reload(deadline=250)
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
            self._last=_Outcome(b'',b'',0,None,True);return _Streams(b'',b'normal diagnostic')
        self.action=load;item.reload(deadline=250)
        self.assertEqual(len(self.calls),1);self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_load_nonzero_overflow_and_unsettled_never_return_result(self):
        for mode in ('nonzero','overflow','unsettled'):
            self.calls=[];item=self.reloader()
            def fail(argv,cwd,deadline):
                self._last=_Outcome(b'',b'',1 if mode=='nonzero' else 0,
                                    'COMMAND_CUSTODY' if mode=='unsettled' else None,
                                    mode!='unsettled',(123,) if mode=='unsettled' else ())
                return _Streams(b'x'*(1024*1024+1) if mode=='overflow' else b'',b'')
            self.action=fail
            with self.subTest(mode=mode),self.assertRaises(m.InstallError):item.reload(deadline=250)
            self.assertEqual(len(self.calls),1)
            if mode=='unsettled':self.assertTrue(list((self.root/'run').iterdir()))
            else:self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_observer_unsettled_preserves_its_owned_scratch_without_load(self):
        item=self.reloader();before=set(os.listdir('/proc/self/fd'))
        def unsettled(operation,cwd,owner):
            owner._last=_Outcome(b'',b'',None,'COMMAND_CUSTODY',False,(123,))
            raise _CommandError('COMMAND_CUSTODY')
        self.observe_action=unsettled
        with self.assertRaises(m.InstallError):item.reload(deadline=250)
        self.assertEqual(self.calls,[]);self.assertTrue(list((self.root/'run').iterdir()))
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)

    def test_final_cleanup_and_final_deadline_failure_suppress_result(self):
        for mode in ('close','late'):
            now=[100.0];self.clock=lambda:now[0];item=self.reloader();original=item._cleanup
            def cleanup():
                original()
                if mode=='close':raise m.InstallError('CLEANUP')
                now[0]=211.0
            item._cleanup=cleanup
            with self.subTest(mode=mode),self.assertRaises(m.InstallError):item.reload(deadline=250)
            self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_production_factory_fixed_observer_and_normal_load_profile(self):
        item=self.reloader();factory=self.observer;limits=[]
        def owner(profile):limits.append(profile);return self
        with patch.object(m.os,'geteuid',return_value=0),patch.object(m,'production_observer',side_effect=factory) as observed,patch.object(m,'_Owner',side_effect=owner):
            value=m.production_owned_reloader(TRUST,PP)
            value.anchor=self.root;value.uid=os.getuid();value._clock=self.clock
            value.reload(deadline=250)
        observed.assert_called_once_with(TRUST)
        self.assertEqual(limits,[_Limits(75,1024*1024)])
        self.assertFalse(hasattr(value,'install'))
        with patch.object(m.os,'geteuid',return_value=65534),self.assertRaises(m.InstallError):m.production_owned_reloader(TRUST,PP)


    def test_stable_authority_drift_after_observer_exit_never_loads(self):
        from contextlib import contextmanager
        factory=self.observer;item=self.reloader()
        @contextmanager
        def drift(trusted):
            with factory(trusted) as lease:yield lease
            (self.root/'etc/selinux/semanage.conf').write_bytes(b'changed after observer cleanup')
        item._observer=drift
        with self.assertRaises(m.InstallError):item.reload(deadline=250)
        self.assertEqual(self.calls,[]);self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_real_owner_timeout_category_and_expired_admission_never_succeed(self):
        item=self.reloader()
        def timeout(argv,cwd,deadline):
            self._last=_Outcome(b'',b'',None,'COMMAND_TIMEOUT',True)
            raise _CommandError('COMMAND_TIMEOUT')
        self.action=timeout
        with self.assertRaises(m.InstallError):item.reload(deadline=250)
        self.assertEqual(len(self.calls),1);self.assertEqual(list((self.root/'run').iterdir()),[])
        self.calls=[];item=self.reloader()
        with self.assertRaises(m.InstallError):item.reload(deadline=105)
        self.assertEqual(self.observations,[]);self.assertEqual(self.calls,[])


class OwnedRemoveTests(unittest.TestCase):
    setUp = InstallTests.setUp

    def _run(self,argv,cwd,*,deadline):
        self.calls.append((argv,Path(cwd),deadline))
        self.command_events.append(tuple(self.events))
        self.assertEqual(list((self.root/'run').iterdir()),[])
        if self.action:return self.action(argv,Path(cwd),deadline)
        stdout=self.listing if argv[-1]=='-lfull' else b''
        self._last=_Outcome(stdout,b'normal bounded diagnostic',0,None,True)
        return _Streams(stdout,b'normal bounded diagnostic')

    def observer(self,trusted):
        from contextlib import contextmanager
        @contextmanager
        def lease():
            with OwnedReloadTests.observer(self,trusted) as observed:
                yield observed
            if self.close_error:raise m.ObserverError('synthetic close failure')
            self.events.append('observer closed')
        return lease()

    def remover(self):
        self.observations=[];self.observe_action=None;self.owned_listing=b'100 base cil\n400 qshd pp\n'
        self.events=[];self.command_events=[];self.close_error=False;self.calls=[];self.action=None
        self.now=100.0;self.clock=lambda:self.now
        return m.OwnedRemove(TRUST,PP,_root=self.root,_uid=os.getuid(),
                             _owner=self,_clock=self.clock,_observer=self.observer)

    def test_owned_observer_closes_before_one_remove_and_two_fresh_absence_reads(self):
        item=self.remover()
        with patch.object(item,'_make_scratch',side_effect=AssertionError('PP scratch forbidden')):
            result=item.remove(deadline=1000)
        self.assertEqual(result,m.RemovalResult(TRUST,TRUST.pp_sha256))
        self.assertNotIsInstance(result,m.InstallResult)
        self.assertEqual(self.command_events,[('observer closed',)]*3)
        self.assertEqual([x[0] for x in self.observations],['list','extract','list','extract'])
        self.assertEqual([x[2] for x in self.observations],[330]*4)
        self.assertEqual([x[0] for x in self.calls],[m._PREFIX+('-X','400','-r','qshd'),m._PREFIX+('-lfull',),m._PREFIX+('-lfull',)])
        self.assertEqual([x[1] for x in self.calls],[Path('/')]*3)
        self.assertEqual([x[2] for x in self.calls],[330]*3)
        with self.assertRaises(m.InstallError):item.remove(deadline=1000)

    def test_nonowned_module_never_reaches_remove(self):
        for listing in (b'100 base cil\n',b'400 qshd pp disabled\n',b'100 qshd pp\n',b'500 qshd pp\n',
                        b'400 qshd pp\n500 qshd pp\n',b'400 qshd cil\n',b'broken'):
            item=self.remover();self.owned_listing=listing
            with self.subTest(listing=listing),self.assertRaises(m.InstallError):item.remove(deadline=1000)
            self.assertEqual(self.calls,[])
            self.assertEqual(list((self.root/'run').iterdir()),[])

    def test_wrong_hll_recheck_drift_and_observer_close_refuse(self):
        for case in ('HLL','recheck','close'):
            item=self.remover()
            def action(operation,cwd,owner):
                if case=='HLL' and operation=='extract':
                    path=cwd/'qshd.pp';path.write_bytes(b'wrong');path.chmod(0o600);return b''
                if case=='recheck' and len(self.observations)==3:return b'400 qshd pp disabled\n'
            self.observe_action=action;self.close_error=case=='close'
            with self.subTest(case=case),self.assertRaises(m.InstallError):item.remove(deadline=1000)
            self.assertEqual(self.calls,[])

    def test_removal_failure_never_reaches_absence(self):
        for case in ('nonzero','failure','timeout','unsettled','unreaped','overflow','wrong result','wrong bytes'):
            item=self.remover()
            def action(argv,cwd,deadline):
                if case=='timeout':raise _CommandError('COMMAND_TIMEOUT')
                self._last=_Outcome(b'',b'',1 if case=='nonzero' else 0,'COMMAND_FAILURE' if case=='failure' else None,case!='unsettled',(987654,) if case=='unreaped' else ())
                if case=='overflow':return _Streams(b'x'*(1024**2+1),b'')
                if case=='wrong result':return b''
                if case=='wrong bytes':return _Streams('not bytes',b'')
                return _Streams(b'',b'')
            self.action=action
            with self.subTest(case=case),self.assertRaises(m.InstallError):item.remove(deadline=1000)
            self.assertEqual(len(self.calls),1)

    def test_both_fresh_absence_samples_reject_any_qshd_or_invalid_listing(self):
        for at in (2,3):
            for listing in (b'1 qshd pp disabled\n',b'999 qshd cil\n',b'400 qshd pp\n',b'broken',b'100 base cil\n100 base cil\n',b'x'*(1024**2+1)):
                item=self.remover()
                def action(argv,cwd,deadline):
                    stdout=listing if len(self.calls)==at else (b'100 base cil\n' if argv[-1]=='-lfull' else b'')
                    self._last=_Outcome(stdout,b'',0,None,True);return _Streams(stdout,b'')
                self.action=action
                with self.subTest(at=at,listing=listing[:40]),self.assertRaises(m.InstallError):item.remove(deadline=1000)
                self.assertEqual(len(self.calls),at)

    def test_absence_exit_failure_suppresses_both_read_positions(self):
        for at in (2,3):
            item=self.remover()
            def action(argv,cwd,deadline):
                stdout=b'100 base cil\n' if argv[-1]=='-lfull' else b''
                self._last=_Outcome(stdout,b'',1 if len(self.calls)==at else 0,None,True)
                return _Streams(stdout,b'')
            self.action=action
            with self.subTest(at=at),self.assertRaises(m.InstallError):item.remove(deadline=1000)
            self.assertEqual(len(self.calls),at)

    def test_unsettled_observer_keeps_its_scratch_and_closes_fds(self):
        item=self.remover();before=len(os.listdir('/proc/self/fd'))
        def unsettled(operation,cwd,owner):
            owner._last=_Outcome(b'',b'',None,'COMMAND_CUSTODY',False,(987654,))
            raise _CommandError('COMMAND_CUSTODY')
        self.observe_action=unsettled
        with self.assertRaises(m.InstallError):item.remove(deadline=1000)
        self.assertEqual(self.calls,[]);self.assertTrue(list((self.root/'run').iterdir()))
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_original_deadline_and_reserves_refuse_before_mutation(self):
        for deadline in (True,float('nan'),float('inf'),10**1000,100,280):
            item=self.remover()
            with self.subTest(deadline=deadline),self.assertRaises(m.InstallError):item.remove(deadline=deadline)
            self.assertEqual(self.calls,[]);self.assertEqual(self.observations,[])
            with self.assertRaises(m.InstallError):item.remove(deadline=1000)
        item=self.remover()
        def elapsed(operation,cwd,owner):
            if len(self.observations)==4:self.now=230
        self.observe_action=elapsed
        with self.assertRaises(m.InstallError):item.remove(deadline=1000)
        self.assertEqual(self.calls,[])

    def test_late_command_and_final_cleanup_suppress_result(self):
        for case in ('command','cleanup'):
            item=self.remover()
            if case=='command':
                def late(argv,cwd,deadline):
                    self.now=340;self._last=_Outcome(b'',b'',0,None,True);return _Streams(b'',b'')
                self.action=late
                with self.assertRaises(m.InstallError):item.remove(deadline=1000)
                self.assertEqual(len(self.calls),1)
            else:
                original=item._cleanup
                def late_cleanup():original();self.now=340
                with patch.object(item,'_cleanup',side_effect=late_cleanup),self.assertRaises(m.InstallError):item.remove(deadline=1000)
                self.assertEqual(len(self.calls),3)

    def test_active_tree_replacement_is_readmitted(self):
        item=self.remover();active=self.root/'var/lib/selinux/targeted/active'
        def replacement(argv,cwd,deadline):
            if len(self.calls)==1:
                shutil.rmtree(active);(active/'modules').mkdir(parents=True)
                active.chmod(0o755);(active/'modules').chmod(0o755)
            self._last=_Outcome(b'',b'',0,None,True);return _Streams(self.listing if argv[-1]=='-lfull' else b'',b'')
        self.action=replacement
        self.assertEqual(item.remove(deadline=1000),m.RemovalResult(TRUST,TRUST.pp_sha256))

    def test_unsafe_active_and_changed_authority_refuse_after_remove(self):
        for case in ('active','config','lock'):
            item=self.remover();active=self.root/'var/lib/selinux/targeted/active/modules'
            config=self.root/'etc/selinux/semanage.conf';lock=self.root/'var/lib/selinux/targeted/semanage.read.LOCK'
            def changed(argv,cwd,deadline):
                if case=='active':active.rmdir();active.symlink_to(self.root/'run',target_is_directory=True)
                elif case=='config':config.write_bytes(b'changed')
                else:lock.chmod(0o644)
                self._last=_Outcome(b'',b'',0,None,True);return _Streams(b'',b'')
            self.action=changed
            with self.subTest(case=case),self.assertRaises(m.InstallError):item.remove(deadline=1000)
            self.assertEqual(len(self.calls),1)
            if case=='active':active.unlink();active.mkdir();active.chmod(0o755)
            elif case=='config':config.write_bytes(b'# fixture')
            else:lock.chmod(0o600)

    def test_normal_and_failed_setup_close_all_route_fds(self):
        item=self.remover();before=len(os.listdir('/proc/self/fd'));item.remove(deadline=1000)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        item=self.remover();(self.root/'usr/lib/os-release').unlink()
        with self.assertRaises(m.InstallError):item.remove(deadline=1000)
        self.assertEqual(len(os.listdir('/proc/self/fd')),before);self.assertEqual(self.calls,[])

    def test_close_failure_after_second_absence_closes_remaining_fds(self):
        item=self.remover();before=len(os.listdir('/proc/self/fd'));close=os.close;failed=False
        def fault(fd):
            nonlocal failed
            close(fd)
            if len(self.calls)==3 and not failed:failed=True;raise OSError('synthetic close failure')
        with patch.object(m.os,'close',side_effect=fault),self.assertRaises(m.InstallError):item.remove(deadline=1000)
        self.assertTrue(failed);self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_production_factory_and_exact_existing_profiles(self):
        with patch.object(m.os,'geteuid',return_value=1),self.assertRaises(m.InstallError):m.production_owned_remover(TRUST,PP)
        item=self.remover();item._injected=None;profiles=[]
        def owner(limits):profiles.append(limits);return self
        with patch.object(m,'_Owner',side_effect=owner):item.remove(deadline=1000)
        self.assertEqual(profiles,[m._INSTALL,m._LIST,m._LIST])
        self.assertEqual([(x.execution_seconds,x.output_bytes) for x in profiles],[(75,1024**2),(15,1024**2),(15,1024**2)])
        with self.assertRaises(m.InstallError):m.OwnedRemove(TRUST,b'wrong')


if __name__=='__main__':unittest.main()
