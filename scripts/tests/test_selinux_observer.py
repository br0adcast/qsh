"""Managed-prestart composition contracts; no host native/policy operations."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]/'packaging/selinux'
sys.path.insert(0,str(ROOT))

def normal_outcome(**values):
    from qshd_selinux_process import _Outcome
    fields=dict(natural=True,stdout_eof=True,stderr_eof=True);fields.update(values)
    return _Outcome(**fields)

class ProtocolTests(unittest.TestCase):
    def test_public_request_is_canonical_and_strict(self):
        import qshd_selinux_observer as m
        from qshd_selinux_activation import TrustedArtifact
        trust=TrustedArtifact('0.3.0','a'*64,'b'*64,'f'*64)
        pam=(ROOT.parent/'pam.d/qshd.fedora-selinux').read_bytes()
        encoded=m._request(trust,pam)
        self.assertLessEqual(len(encoded),8192)
        self.assertEqual(m._parse_request(encoded),(trust,pam))
        for bad in (encoded+'=',base64.b64encode(b'{"schema":2,"schema":2}').decode(),'x'*8193):
            with self.assertRaises(m.ObserverError):m._parse_request(bad)
        with self.assertRaises(m.ObserverError):m._request(trust,b'installed bytes')



    def test_deep_bounded_json_is_a_bounded_protocol_refusal(self):
        import qshd_selinux_observer as m
        nested=b'['*1100+b'0'+b']'*1100
        self.assertLess(len(nested),4096)
        # Exercise the standard-library recursive decoder independently of
        # accelerator-specific C stack limits on this Python build.
        from unittest.mock import patch
        with patch.object(json.scanner,'make_scanner',json.scanner.py_make_scanner):
            with self.assertRaisesRegex(m.ObserverError,'^RESPONSE$'):
                m._parse_response(nested,'public-request')
            with self.assertRaisesRegex(m.ObserverError,'^PROTOCOL$'):
                m._parse_request(base64.b64encode(nested).decode('ascii'))

    def test_pending_requires_clean_settled_exit_and_exact_private_record(self):
        import qshd_selinux_observer as m
        from types import SimpleNamespace as N
        from unittest.mock import patch
        trust=m.TrustedArtifact('0.3.0','a'*64,'b'*64,'f'*64)
        pam=(ROOT.parent/'pam.d/qshd.fedora-selinux').read_bytes()
        request=m._request(trust,pam)
        record=m._json(dict(schema=2,error='ACTIVATION_PENDING',request_sha256=__import__('hashlib').sha256(request.encode('ascii')).hexdigest()))+b'\n'
        base=dict(exit_code=1,failure=None,settled=True,unreaped=(),stdout=b'',stderr=record)
        cases=[({},'ACTIVATION_PENDING'),({'natural':False},'CHILD_REFUSED'),({'group_term_attempts':1},'CHILD_REFUSED'),({'stderr_eof':False},'CHILD_REFUSED'),({'failure':'TOOL_FAILURE'},'CHILD_REFUSED'),({'exit_code':2},'CHILD_REFUSED'),({'settled':False},'CHILD_REFUSED'),({'unreaped':(123,)},'CHILD_REFUSED'),({'stdout':b'extra'},'CHILD_REFUSED'),({'stderr':record+record},'CHILD_REFUSED'),({'stderr':record.replace(b'ACTIVATION_PENDING',b'OTHER')},'CHILD_REFUSED')]
        for changes,expected in cases:
            owner=N(_last=normal_outcome(**(base|changes)))
            def run(*args,**kwargs):raise m._CommandError('TOOL_FAILURE')
            owner._run=run
            with self.subTest(changes=changes),patch.object(m,'_Owner',return_value=owner),self.assertRaisesRegex(m.ObserverError,'^'+expected+'$'):
                m.observe_managed_prestart(trust,pam)
        for code in ('COMMAND_TIMEOUT','COMMAND_CUSTODY','COMMAND_UNSETTLED','OUTPUT_LIMIT'):
            owner=N(_last=normal_outcome(**base),_run=lambda *a,**kw:(_ for _ in ()).throw(m._CommandError(code)))
            with patch.object(m,'_Owner',return_value=owner),self.assertRaises(m.ObserverError) as error:
                m.observe_managed_prestart(trust,pam)
            self.assertNotEqual(str(error.exception),'ACTIVATION_PENDING')
        owner=N(_last=normal_outcome(**base),_run=lambda *a,**kw:(_ for _ in ()).throw(m._CommandError('TOOL_FAILURE')))
        with patch.object(m,'_Owner',return_value=owner),patch.object(m.time,'monotonic',side_effect=[0,121]),self.assertRaisesRegex(m.ObserverError,'^DEADLINE$'):
            m.observe_managed_prestart(trust,pam)
        with patch.object(m,'_Owner',return_value=owner),patch.object(m.time,'monotonic',side_effect=[0,0,121]),self.assertRaisesRegex(m.ObserverError,'^DEADLINE$'):
            m.observe_managed_prestart(trust,pam)

    def test_original_child_end_and_slow_normal_scope_exit(self):
        import qshd_selinux_observer as m
        from unittest.mock import patch
        from contextlib import contextmanager
        clock=[100]
        with patch.object(m.time,'monotonic',lambda:clock[0]):
            self.assertEqual(m._child_end(['100','210']),210)
            for args in (['100','211'],['101','211'],['nan','210'],['100','nan']):
                with self.assertRaises(m.ObserverError):m._child_end(args)
            clock[0]=210
            with self.assertRaises(m.ObserverError):m._child_end(['100','210'])
            clock[0]=100;closed=[]
            @contextmanager
            def slow():
                yield
                closed.append(True);clock[0]=210
            with self.assertRaises(m.ObserverError):
                with m._within(slow(),210):pass
            self.assertEqual(closed,[True])

    def test_response_binding_shape_and_custody_categories(self):
        import qshd_selinux_observer as m
        from types import SimpleNamespace as N
        from unittest.mock import patch
        trust=m.TrustedArtifact('0.3.0','a'*64,'b'*64,'f'*64)
        pam=(ROOT.parent/'pam.d/qshd.fedora-selinux').read_bytes()
        request=m._request(trust,pam);binding=m.ContextBinding('c'*64,'d'*64)
        response=m._response(request,binding)
        self.assertEqual(m._parse_response(response,request).contexts,binding)
        for bad in (response+response,response.rstrip(),b'{}',response.replace(b'"schema":2',b'"schema":true'),response.replace(b'"phase":',b'"unknown":')):
            with self.assertRaises(m.ObserverError):m._parse_response(bad,request)
        with self.assertRaises(m.ObserverError):m._parse_response(response,request+'changed')
        for code,expected in (('COMMAND_CUSTODY','CUSTODY'),('COMMAND_UNSETTLED','CUSTODY'),('PROCESS_THREADS','CALLER_PROCESS'),('COMMAND_TIMEOUT','DEADLINE')):
            with patch.object(m,'_Owner',side_effect=m._CommandError(code)),self.assertRaisesRegex(m.ObserverError,'^'+expected+'$'):
                m.observe_managed_prestart(trust,pam)
        owner=N(_last=N(settled=True,unreaped=()),_run=lambda *args,**kwargs:N(stdout=response,stderr=b'PRIVATE'))
        with patch.object(m,'_Owner',return_value=owner),self.assertRaisesRegex(m.ObserverError,'^OBSERVATION_REFUSED$'):
            m.observe_managed_prestart(trust,pam)

# Private sibling production-factory fixtures run through the real fixed child.
COMMON=r'''
from contextlib import contextmanager
import fcntl,json,os,time
from pathlib import Path
from types import SimpleNamespace as N
from qshd_selinux_activation import *
ROOT=Path(__file__).parent
CASE=(ROOT/'case').read_text()
def case(value):return value in CASE.split('+')
TRUST=TrustedArtifact('0.3.0','a'*64,'b'*64,'f'*64)
ROUTING=b'{"/fixed":"owner"}'
def event(s):
 with (ROOT/'events').open('a') as f:f.write(s+'\n')
class Lease:
 def __init__(self,name):self.name=name;self.baseline=None
 def __enter__(self):
  event('enter-'+self.name)
  if case('enter-'+self.name):raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
  if case('setup') and self.name=='slot':time.sleep(30)
  if case('lock') and self.name=='slot':
   self.fd=os.open(ROOT/'lock',os.O_RDWR);fcntl.flock(self.fd,fcntl.LOCK_EX)
  return self
 def __exit__(self,*exc):
  event('exit-'+self.name)
  if hasattr(self,'fd'):os.close(self.fd)
  if case('exit-'+self.name):raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
 def inspection(self,*args):return self
 def routing(self):event('routing');return ROUTING
 def capture(self):
  event('capture-'+self.name)
  if case('capture-'+self.name):raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
  if self.name=='slot':
   binding=ContextBinding('c'*64,'d'*64)
   rec=Activation(2,'PENDING' if case('pending') else 'COMPLETE','a'*32,'fedora44-targeted-pair-v2',2,1,TRUST,ModulePair(ModuleIdentity('qshd',400,'targeted','pp'),ModuleIdentity('qshd_contexts',400,'targeted','pp')),'provider-fresh',None,None if case('pending') else Completion('normal-pair-install-reload-v2',PairDigests('b'*64,'f'*64),binding))
   result=N(record=rec)
  elif self.name in ('registry','context'):result=N(registry_bytes=b'{}' if case('drift') else ROUTING,registry_sha256='c'*64,receipts_sha256='d'*64)
  else:result=object()
  assert self.baseline is None;self.baseline=result;return result
 def recheck(self,baseline):
  event('recheck-'+self.name);assert baseline is self.baseline
  if case('recheck-'+self.name):raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
@contextmanager
def window(api):
 event('enter-window')
 try:yield object()
 finally:event('exit-window')
 if case('exit-window'):raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
'''
HARNESS=r'''
import json,pathlib,resource,sys,time
root=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(root))
resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024**2,16*1024**2));resource.setrlimit(resource.RLIMIT_CPU,(10,10));resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
import qshd_selinux_observer as m
from qshd_selinux_process import _children
trust=m.TrustedArtifact('0.3.0','a'*64,'b'*64,'f'*64)
if (root/'case').read_text() in ('setup','lock'):m._SECONDS=.25
started=time.monotonic()
try:
 result=m.observe_managed_prestart(trust,(root/'pam').read_bytes());value={'ok':True,'profile':result.profile}
except m.ObserverError as e:value={'ok':False,'error':str(e)}
assert _children()==[]
value['elapsed']=time.monotonic()-started
print(json.dumps(value))
'''

class ChildTests(unittest.TestCase):
    def run_child(self,case,*,policy=False):
        import fcntl,os,shutil,subprocess,tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name in ('qshd_selinux_observer.py','qshd_selinux_activation.py','qshd_selinux_process.py'):
                shutil.copy2(ROOT/name,root/name)
            # Only this disposable copy substitutes UID admission; all filesystem/native factories below are private fixtures.
            path=root/'qshd_selinux_observer.py'
            path.write_text('import os\nos.geteuid=lambda:'+('1' if case=='rootgate' else '0')+'\n'+path.read_text())
            if case=='child-thread':
                path.write_text("import sys\nif len(sys.argv)>1 and sys.argv[1] in ('_managed_prestart_pair_v2','_consumer_preinstall_pair_v2'):\n import threading,time\n threading.Thread(target=lambda:time.sleep(30),daemon=True).start()\n"+path.read_text())
            (root/'case').write_text(case);(root/'common.py').write_text(COMMON)
            (root/'pam').write_bytes((ROOT.parent/'pam.d/qshd.fedora-selinux').read_bytes())
            modules={
                'qshd_selinux_activation_state':'from common import *\ndef production():return Lease("slot")\n',
                'qshd_selinux_registry':'from common import *\ndef production():return Lease("registry")\n',
                'qshd_selinux_transaction':'from common import *\ndef production(paths):\n assert paths==["/fixed"]\n return Lease("context")\n',
                'qshd_selinux_module_observer':'from common import *\ndef production_observer(trust,**kwargs):\n assert trust==TRUST\n return Lease("module")\n',
                'qshd_selinux_files':'from common import *\ndef production(pam,api):\n assert type(pam)is bytes\n return Lease("files")\n',
                'qshd_selinux_queries':'from common import *\nrequired_observation=window\n',
                'qshd_selinux_api':'class SelinuxApi:pass\n'}
            if policy:modules['qshd_selinux_files']="raise AssertionError('deployed file observer forbidden')\n"
            for name,value in modules.items():(root/(name+'.py')).write_text(value)
            fd=os.open(root/'lock',os.O_RDWR|os.O_CREAT,0o600)
            try:
                if case=='lock':fcntl.flock(fd,fcntl.LOCK_EX)
                harness=HARNESS.replace("m.observe_managed_prestart(trust,(root/'pam').read_bytes())","m._observe_policy_context(trust)") if policy else HARNESS
                p=subprocess.run([sys.executable,'-I','-B','-c',harness,str(root)],capture_output=True,text=True,timeout=15)
            finally:os.close(fd)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertNotIn('DO_NOT_EXPOSE',p.stdout+p.stderr)
            value=json.loads(p.stdout)
            events=(root/'events').read_text().splitlines() if (root/'events').exists() else []
            return value,events

    def test_child_root_gate_precedes_production_setup(self):
        for case in ('rootgate','child-thread'):
            with self.subTest(case=case):
                result,events=self.run_child(case)
                self.assertFalse(result['ok'])
                self.assertEqual(events,[])

    def test_real_pending_refusal_waits_for_every_normal_exit(self):
        result,events=self.run_child('pending')
        self.assertEqual(result['error'],'ACTIVATION_PENDING')
        self.assertEqual(events[-6:],['exit-window','exit-files','exit-module','exit-context','exit-registry','exit-slot'])
        for failure in ('exit-window','recheck-files','exit-slot'):
            result,_=self.run_child('pending+'+failure)
            self.assertFalse(result['ok']);self.assertNotEqual(result['error'],'ACTIVATION_PENDING')

    def test_real_child_all_scopes_before_success(self):
        result,events=self.run_child('normal')
        self.assertTrue(result['ok'])
        self.assertEqual(events[:6],['enter-slot','enter-registry','routing','enter-context','enter-module','enter-files'])
        start=events.index('enter-window');end=events.index('exit-window')
        for name in ('slot','registry','context','module','files'):
            self.assertLess(start,events.index('capture-'+name));self.assertLess(events.index('recheck-'+name),end)
        self.assertEqual(events[-6:],['exit-window','exit-files','exit-module','exit-context','exit-registry','exit-slot'])

    def test_real_child_pending_drift_and_every_finalizer_refuse(self):
        for case in ('pending','drift','enter-slot','enter-registry','enter-context','enter-module','enter-files','exit-window','exit-files','exit-module','exit-context','exit-registry','exit-slot','capture-module','recheck-files'):
            with self.subTest(case=case):
                result,_=self.run_child(case);self.assertFalse(result['ok'])

    def test_real_child_blocked_setup_and_actual_lock_are_deadline_bounded(self):
        for case in ('setup','lock'):
            with self.subTest(case=case):
                result,events=self.run_child(case)
                self.assertEqual(result['error'],'DEADLINE')
                self.assertLess(result['elapsed'],5)
                self.assertNotIn('capture-slot',events)

class InstalledTests(unittest.TestCase):
    def setUp(self):
        import tempfile, hashlib
        from unittest.mock import patch
        import qshd_selinux_package_state as package
        import qshd_selinux_reference_loader as references
        import qshd_selinux_observer as observer
        self.m=observer;self.patch=patch
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.common=self.root/'qshd'
        self.pkg=lambda:package.PackageState(self.common,uid=__import__('os').getuid(),anchor=self.root)
        with self.pkg().initialize():pass
        spec=importlib.util.spec_from_file_location('builder',ROOT/'assemble_payload.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        contexts_pp=self.root/'qshd_contexts.pp';contexts_pp.write_bytes(b'inert contexts fixture')
        pp=self.root/'qshd.pp';pp.write_bytes(b'inert synthetic PP')
        artifact=ROOT/'artifact.json';pam=ROOT.parent/'pam.d/qshd.fedora-selinux'
        expected={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in builder.MODULES}
        expected.update({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (pp,contexts_pp,artifact,pam)})
        self.out=self.root/'installed';builder.assemble_payload(ROOT,pp,contexts_pp,artifact,pam,expected,self.out,1000000000)
        self.reader=lambda:references._testing_references(self.out)
        self.document=self.out/'usr/share/qshd-selinux/reference.json'
        self.now=100

    def invoke(self,child,deadline=300):
        import qshd_selinux_package_state as package
        import qshd_selinux_reference_loader as references
        with self.patch.object(package,'production',self.pkg),self.patch.object(references,'production_references',self.reader),self.patch.object(self.m,'_preconditions'),self.patch.object(self.m.time,'monotonic',lambda:self.now),self.patch.object(self.m,'observe_managed_prestart',side_effect=child) as run:
            try:return self.m.observe_installed_managed_prestart(deadline=deadline)
            finally:self.last_run=run

    def test_installed_holds_only_one_package_lease_and_rechecks(self):
        import fcntl,os
        def child(trust,pam,**kwargs):
            fd=os.open(self.common/'selinux-package.lock',os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            with self.reader() as reader:
                value=reader.capture();reader.recheck(value)
            self.assertEqual((trust,pam),(value.artifact,value.expected_pam))
            return 'observed'
        self.assertEqual(self.invoke(child),'observed')
        self.last_run.assert_called_once()
        with self.pkg().operation():pass

    def test_insufficient_or_invalid_caller_deadline_never_starts_child(self):
        for deadline in (True,float('nan'),170,169,100):
            with self.subTest(deadline=deadline),self.assertRaises(self.m.ObserverError):self.invoke(lambda *a,**k:'unexpected',deadline)
            self.last_run.assert_not_called()

    def test_pending_waits_for_reference_and_package_finalization(self):
        def pending(*args,**kwargs):raise self.m.ObserverError('ACTIVATION_PENDING')
        with self.assertRaisesRegex(self.m.ObserverError,'^ACTIVATION_PENDING$'):self.invoke(pending)
        with self.pkg().operation():pass
        def drift(*args,**kwargs):
            self.document.write_bytes(self.document.read_bytes()+b' ')
            raise self.m.ObserverError('ACTIVATION_PENDING')
        with self.assertRaises(self.m.ObserverError) as error:self.invoke(drift)
        self.assertNotEqual(str(error.exception),'ACTIVATION_PENDING')

    def test_child_success_or_pending_after_deadline_is_refused(self):
        for pending in (False,True):
            def late(*args,**kwargs):
                self.now=301
                if pending:raise self.m.ObserverError('ACTIVATION_PENDING')
                return 'observed'
            self.now=100
            with self.assertRaisesRegex(self.m.ObserverError,'^DEADLINE$'):self.invoke(late)

    def test_package_exit_failure_dominates_pending(self):
        from contextlib import contextmanager
        original=self.pkg
        class BadExit:
            @contextmanager
            def operation(inner):
                with original().operation():yield
                raise OSError('controlled package close failure')
        self.pkg=lambda:BadExit()
        def pending(*args,**kwargs):raise self.m.ObserverError('ACTIVATION_PENDING')
        with self.assertRaisesRegex(self.m.ObserverError,'^INSTALLED_REFUSED$'):self.invoke(pending)

    def test_remaining_budget_is_checked_after_reference_capture(self):
        from contextlib import contextmanager
        original=self.reader
        @contextmanager
        def delayed():
            with original() as reader:
                class Reader:
                    def capture(inner):
                        value=reader.capture();self.now=171;return value
                    def recheck(inner,value):return reader.recheck(value)
                yield Reader()
        self.reader=delayed
        with self.assertRaisesRegex(self.m.ObserverError,'^DEADLINE$'):self.invoke(lambda *a,**k:'unexpected')
        self.last_run.assert_not_called()

    def test_child_custody_refusal_is_never_reclassified_pending(self):
        def failed(*args,**kwargs):raise self.m.ObserverError('CUSTODY')
        with self.assertRaisesRegex(self.m.ObserverError,'^CUSTODY$'):self.invoke(failed)

    def test_expired_child_result_starts_no_reference_recheck(self):
        from contextlib import contextmanager
        from unittest.mock import Mock
        original=self.reader;recheck=Mock()
        @contextmanager
        def recorded():
            with original() as reader:
                class Reader:
                    capture=reader.capture
                    def recheck(inner,value):recheck();return reader.recheck(value)
                yield Reader()
        self.reader=recorded
        for pending in (False,True):
            def late(*args,**kwargs):
                self.now=301
                if pending:raise self.m.ObserverError('ACTIVATION_PENDING')
                return 'observed'
            self.now=100
            with self.assertRaisesRegex(self.m.ObserverError,'^DEADLINE$'):self.invoke(late)
            recheck.assert_not_called()

    def test_expired_scope_admission_starts_no_reference_capture(self):
        from contextlib import contextmanager
        from unittest.mock import Mock
        original=self.reader;capture=Mock()
        @contextmanager
        def delayed():
            with original() as reader:
                self.now=171
                class Reader:
                    def capture(inner):capture();return reader.capture()
                    recheck=reader.recheck
                yield Reader()
        self.reader=delayed
        with self.assertRaisesRegex(self.m.ObserverError,'^DEADLINE$'):self.invoke(lambda *a,**k:'unexpected')
        capture.assert_not_called();self.last_run.assert_not_called()


class PolicyContextTests(unittest.TestCase):
    setUp=InstalledTests.setUp

    def invoke(self,child,deadline=300):
        import qshd_selinux_package_state as package
        import qshd_selinux_reference_loader as references
        with self.patch.object(package,'production',self.pkg),self.patch.object(references,'production_references',self.reader),self.patch.object(self.m,'_preconditions'),self.patch.object(self.m.time,'monotonic',lambda:self.now),self.patch.object(self.m,'_observe_policy_context',side_effect=child) as run:
            try:return self.m.observe_installed_policy_context(deadline=deadline)
            finally:self.last_run=run

    def test_installed_policy_context_owns_package_without_deployed_leaves(self):
        import fcntl,os
        def child(trust,**kwargs):
            fd=os.open(self.common/'selinux-package.lock',os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
            finally:os.close(fd)
            with self.reader() as reader:
                value=reader.capture();reader.recheck(value)
            self.assertEqual(trust,value.artifact)
            return self.m.PolicyContextObservation('fedora44-targeted-pair-v2',self.m.ContextBinding('c'*64,'d'*64))
        value=self.invoke(child)
        self.assertEqual(value.contexts,self.m.ContextBinding('c'*64,'d'*64))
        self.last_run.assert_called_once()
        with self.pkg().operation():pass

    def test_policy_phase_protocol_is_exact_and_not_prestart(self):
        m=self.m;trust=m.TrustedArtifact('0.3.0','a'*64,'b'*64,'f'*64)
        request=m._policy_request(trust);self.assertEqual(m._parse_policy_request(request),trust)
        binding=m.ContextBinding('c'*64,'d'*64)
        data=m._policy_response(request,binding)
        self.assertEqual(m._parse_policy_response(data,request).contexts,binding)
        from dataclasses import FrozenInstanceError
        with self.assertRaises(FrozenInstanceError):m._parse_policy_response(data,request).profile='changed'
        for bad in (m._response(request,binding),data+data,data.replace(b'consumer-preinstall',b'managed-prestart')):
            with self.assertRaises(m.ObserverError):m._parse_policy_response(bad,request)
        for bad in (request+'=',m._request(trust,(ROOT.parent/'pam.d/qshd.fedora-selinux').read_bytes()),base64.b64encode(b'{"schema":2,"schema":2}').decode(),base64.b64encode(b'['*1100+b'0'+b']'*1100).decode()):
            with self.assertRaises(m.ObserverError):m._parse_policy_request(bad)

    def test_policy_pending_is_deferred_and_reference_failure_dominates(self):
        def pending(*args,**kwargs):raise self.m.ObserverError('ACTIVATION_PENDING')
        with self.assertRaisesRegex(self.m.ObserverError,'^ACTIVATION_PENDING$'):self.invoke(pending)
        def drift(*args,**kwargs):
            self.document.write_bytes(self.document.read_bytes()+b' ')
            raise self.m.ObserverError('ACTIVATION_PENDING')
        with self.assertRaises(self.m.ObserverError) as error:self.invoke(drift)
        self.assertNotEqual(str(error.exception),'ACTIVATION_PENDING')

    def test_policy_expired_child_starts_no_postchild_reference_recheck(self):
        from contextlib import contextmanager
        from unittest.mock import Mock
        original=self.reader;recheck=Mock()
        @contextmanager
        def recorded():
            with original() as reader:
                class Reader:
                    capture=reader.capture
                    def recheck(inner,value):recheck();return reader.recheck(value)
                yield Reader()
        self.reader=recorded
        def late(*args,**kwargs):self.now=301;return 'late'
        with self.assertRaisesRegex(self.m.ObserverError,'^DEADLINE$'):self.invoke(late)
        recheck.assert_not_called()

    def test_policy_invalid_or_insufficient_deadline_starts_no_child(self):
        for deadline in (True,float('nan'),170,100):
            with self.subTest(deadline=deadline),self.assertRaises(self.m.ObserverError):self.invoke(lambda *a,**k:'unexpected',deadline)
            self.last_run.assert_not_called()

    def test_policy_owned_error_provenance_is_required_for_pending(self):
        from unittest.mock import Mock
        from types import SimpleNamespace as N
        m=self.m;trust=m.TrustedArtifact('0.3.0','a'*64,'b'*64,'f'*64)
        request=m._policy_request(trust)
        base=dict(exit_code=1,failure=None,settled=True,unreaped=(),stdout=b'',stderr=m._pending_record(request))
        for changes,expected in (({},'ACTIVATION_PENDING'),({'natural':False},'CHILD_REFUSED'),({'group_term_attempts':1},'CHILD_REFUSED'),({'stderr_eof':False},'CHILD_REFUSED'),({'failure':'TOOL_FAILURE'},'CHILD_REFUSED'),({'exit_code':2},'CHILD_REFUSED'),({'unreaped':(123,)},'CHILD_REFUSED'),({'settled':False},'CHILD_REFUSED'),({'stdout':b'extra'},'CHILD_REFUSED'),({'stderr':m._pending_record('another phase')},'CHILD_REFUSED')):
            owner=N(_last=normal_outcome(**(base|changes)))
            owner._run=Mock(side_effect=m._CommandError('TOOL_FAILURE'))
            with self.subTest(changes=changes),self.patch.object(m,'_Owner',return_value=owner),self.assertRaisesRegex(m.ObserverError,'^'+expected+'$'):
                m._observe_policy_context(trust)
        for code,expected in (('COMMAND_TIMEOUT','DEADLINE'),('COMMAND_CUSTODY','CUSTODY'),('OUTPUT_INCOMPLETE','CUSTODY'),('OUTPUT_LIMIT','CHILD_REFUSED')):
            owner=N(_last=normal_outcome(**base),_run=Mock(side_effect=m._CommandError(code)))
            with self.patch.object(m,'_Owner',return_value=owner),self.assertRaisesRegex(m.ObserverError,'^'+expected+'$'):
                m._observe_policy_context(trust)

    def test_policy_package_exit_failure_supersedes_pending(self):
        from contextlib import contextmanager
        original=self.pkg
        class BadExit:
            @contextmanager
            def operation(inner):
                with original().operation():yield
                raise OSError('controlled package close')
        self.pkg=lambda:BadExit()
        def pending(*args,**kwargs):raise self.m.ObserverError('ACTIVATION_PENDING')
        with self.assertRaisesRegex(self.m.ObserverError,'^INSTALLED_REFUSED$'):self.invoke(pending)

    @__import__('contextlib').contextmanager
    def actual_policy_state(self,*,pending=False):
        import dataclasses,hashlib
        from scripts.tests import test_selinux_first_activation as fixture
        import qshd_selinux_activation as model
        import qshd_selinux_activation_state as state
        import qshd_selinux_registry as registry
        import qshd_selinux_transaction as transaction
        import qshd_selinux_module_observer as modules
        import qshd_selinux_queries as queries
        import qshd_selinux_api as native
        import qshd_selinux_files as files
        from contextlib import contextmanager
        b=fixture.Bindings(self.root)
        with self.reader() as reader:
            references=reader.capture();reader.recheck(references)
        trust=references.artifact;engine=b.transaction_object();slot=b.slot_object()
        with self.pkg().operation():
            with slot.writer() as writer:
                initial=writer.capture_current()
                record=model.Activation(2,'PENDING','a'*32,'fedora44-targeted-pair-v2',2,1,trust,model.ModulePair(model.ModuleIdentity('qshd',400,'targeted','pp'),model.ModuleIdentity('qshd_contexts',400,'targeted','pp')),'provider-fresh',None,None)
                encode=lambda value:json.dumps(dataclasses.asdict(value),sort_keys=True,separators=(',',':')).encode()
                token=writer.begin_pending(encode(record),initial)
                with engine.writer() as context_writer:
                    context_writer.reconcile(b.ids)
                    with context_writer.inspection(b.ids) as view:
                        context=view.capture();view.recheck(context)
                    binding=model.ContextBinding(context.registry_sha256,context.receipts_sha256)
                    if not pending:
                        complete=dataclasses.replace(record,state='COMPLETE',completion=model.Completion('normal-pair-install-reload-v2',model.PairDigests(trust.core_pp_sha256,trust.contexts_pp_sha256),binding))
                        # Fixture seeding only: real publication migration belongs to Task3.
                        slot._publish(encode(complete),token.observation,lambda:None)
            @contextmanager
            def module_scope(actual,**kwargs):
                self.assertEqual(actual,trust)
                class View:
                    def capture(inner):b.assert_locked();b.point('module capture');return object()
                    def recheck(inner,value):b.point('module recheck')
                yield View()
            with self.patch.object(state,'production',return_value=slot),self.patch.object(registry,'production',return_value=__import__('types').SimpleNamespace(inspection=b.registry)),self.patch.object(transaction,'production',side_effect=lambda paths:engine),self.patch.object(modules,'production_observer',side_effect=module_scope),self.patch.object(queries,'required_observation',side_effect=lambda api:b.window()),self.patch.object(native,'SelinuxApi',return_value=object()),self.patch.object(files,'production',side_effect=AssertionError('deployed files forbidden')):
                yield b,trust,binding,engine,slot

    def test_real_temp_complete_binding_and_all_three_lock_exclusions(self):
        with self.actual_policy_state() as (b,trust,binding,engine,slot):
            self.assertEqual(self.m._compose_policy_context(trust,deadline=__import__('time').monotonic()+110),binding)
            self.assertIn('window exit',b.events)
            # Both inner locks have left normally; the package lock stays held.
            with slot.inspection() as view:
                value=view.capture();view.recheck(value)
            with engine.inspection(b.ids) as view:
                value=view.capture();view.recheck(value)

    def test_real_temp_journal_refuses_without_recovery_or_writes(self):
        with self.actual_policy_state() as (b,trust,binding,engine,slot):
            journal=engine.state/'journal';journal.write_bytes(b'not recoverable JSON');journal.chmod(0o600)
            before=(b.target.read_bytes(),(engine.state/'receipts').read_bytes())
            b.events.clear()
            from qshd_selinux_fs import Conflict
            with self.assertRaisesRegex(Conflict,'^JOURNAL_PRESENT$'):self.m._compose_policy_context(trust,deadline=__import__('time').monotonic()+110)
            self.assertEqual(journal.read_bytes(),b'not recoverable JSON')
            self.assertEqual((b.target.read_bytes(),(engine.state/'receipts').read_bytes()),before)
            self.assertNotIn('window enter',b.events)

    def test_real_temp_pending_requires_normal_native_and_outer_exits(self):
        with self.actual_policy_state(pending=True) as (b,trust,binding,engine,slot):
            with self.assertRaises(self.m._PendingRefusal):self.m._compose_policy_context(trust,deadline=__import__('time').monotonic()+110)
            b.failure='window exit'
            with self.assertRaisesRegex(RuntimeError,'controlled window exit'):self.m._compose_policy_context(trust,deadline=__import__('time').monotonic()+110)
            self.assertEqual(b.record()['state'],'PENDING')


class PolicyChildTests(unittest.TestCase):
    def run_child(self,case):return ChildTests.run_child(self,case,policy=True)

    def test_real_policy_child_succeeds_without_any_files_observer(self):
        result,events=self.run_child('normal');self.assertTrue(result['ok'])
        self.assertEqual(events[:5],['enter-slot','enter-registry','routing','enter-context','enter-module'])
        self.assertEqual(events[-5:],['exit-window','exit-module','exit-context','exit-registry','exit-slot'])
        for name in ('slot','registry','context','module'):
            self.assertLess(events.index('enter-window'),events.index('capture-'+name))
            self.assertLess(events.index('recheck-'+name),events.index('exit-window'))

    def test_real_policy_pending_and_every_exit_are_causal(self):
        result,events=self.run_child('pending');self.assertEqual(result['error'],'ACTIVATION_PENDING')
        self.assertEqual(events[-5:],['exit-window','exit-module','exit-context','exit-registry','exit-slot'])
        for failure in ('exit-window','exit-module','exit-context','exit-registry','exit-slot','recheck-slot','recheck-module','drift'):
            with self.subTest(failure=failure):
                result,_=self.run_child('pending+'+failure)
                self.assertFalse(result['ok']);self.assertNotEqual(result['error'],'ACTIVATION_PENDING')

    def test_real_policy_root_threads_setup_and_lock_remain_bounded(self):
        for case in ('rootgate','child-thread','setup','lock'):
            with self.subTest(case=case):
                result,events=self.run_child(case)
                self.assertFalse(result['ok'])
                if case in ('setup','lock'):self.assertEqual(result['error'],'DEADLINE');self.assertLess(result['elapsed'],5)
                else:self.assertEqual(events,[])
