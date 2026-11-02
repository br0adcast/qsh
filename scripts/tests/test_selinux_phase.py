"""Fixed installed phase contracts; no real phase/native action in source tests.

Private helper names express the test seam, not public CLI options.
"""
from dataclasses import asdict
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[2]
SOURCE=ROOT/'packaging/selinux'
SCRIPT=SOURCE/'qshd_selinux_phase.py'
PHASES={'provider-post-pristine':'COMPLETE','consumer-pre-fresh':'PENDING',
        'consumer-pre-installed':'PENDING','consumer-post-owned':'COMPLETE'}
RUNTIME_MODULES=tuple('qshd_selinux_'+name+'.py' for name in (
    'activation','activation_state','contexts','transaction','fs','registry',
    'process','modules','module_observer','api','queries','files','observer',
    'reference_loader','package_state','module_install','first_activation',
    'consumer_activation','phase'))+('stop_guard.py',)
TRUST={'provider_version':'fixture','manifest_sha256':'a'*64,'pp_sha256':'b'*64}


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def load_phase():
    # No synthetic phase module or copied PR B dependency is supplied here.
    # The actual merged module must exist before these controls can run.
    if str(SOURCE) not in sys.path:sys.path.insert(0,str(SOURCE))
    spec=importlib.util.spec_from_file_location('phase_under_test',SCRIPT)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    return module


class ProtocolTests(unittest.TestCase):
    def setUp(self):self.phase=load_phase()

    def response(self,phase):
        request=canonical({'schema':1,'phase':phase})
        result=dict(schema=1,phase=phase,request_sha256=hashlib.sha256(request).hexdigest(),
                    operation_id='c'*32,state=PHASES[phase],artifact=TRUST)
        return request,result

    def test_fixed_four_requests_and_exact_response_binding(self):
        for phase in PHASES:
            request,frame=self.response(phase)
            self.assertEqual(self.phase._request(phase),request)
            self.assertEqual(self.phase._parse_response(canonical(frame)+b'\n',request),frame)
        for phase in ('','provider-pre','erase','consumer-pre','/private/path','consumer-pre-fresh --deadline 999'):
            with self.subTest(phase=phase),self.assertRaises(self.phase.PhaseError):self.phase._request(phase)

    def test_wrong_shape_phase_state_digest_type_and_noncanonical_response_refuse(self):
        request,frame=self.response('consumer-pre-fresh');raw=canonical(frame)+b'\n'
        wrong=[raw+b'\n',raw+b'{}\n',raw.replace(b'"schema":1',b'"schema":true'),
               raw.replace(b'"schema":1',b'"schema":1,"schema":1')]
        for changes in ({'phase':'consumer-pre-installed'},{'state':'COMPLETE'},
                        {'operation_id':'INVALID'},{'request_sha256':'d'*64},
                        {'artifact':dict(TRUST,extra='unsupported')},{'extra':True}):
            wrong.append(canonical(frame|changes)+b'\n')
        for value in wrong:
            with self.subTest(value=value[:60]),self.assertRaises(self.phase.PhaseError):self.phase._parse_response(value,request)
        with self.assertRaises(self.phase.PhaseError):self.phase._parse_response(b'['*1500+b']'*1500,request)
        with self.assertRaises(self.phase.PhaseError):self.phase._parse_response(b'x'*4097,request)

    def test_actual_typed_pending_and_complete_records_emit_only_final_frame(self):
        from qshd_selinux_activation import Activation,TrustedArtifact,ModuleIdentity,Completion,ContextBinding
        trust=TrustedArtifact(**TRUST)
        for name,state in PHASES.items():
            completion=Completion('normal-install-reload-v1',trust.pp_sha256,ContextBinding('d'*64,'e'*64)) if state=='COMPLETE' else None
            record=Activation(1,state,'c'*32,'fedora44-targeted-v1',1,1,trust,ModuleIdentity('qshd',400,'targeted','pp'),completion)
            request=self.phase._request(name)
            frame=self.phase._response(record,request)
            self.assertEqual(self.phase._parse_response(frame,request)['state'],state)
        with self.assertRaises(self.phase.PhaseError):self.phase._response(object(),self.phase._request('consumer-pre-fresh'))

    def test_only_exact_250_combined_profile_is_new(self):
        from qshd_selinux_process import _Limits,_CommandError
        self.assertEqual(_Limits(250,4096).execution_seconds,250)
        for seconds,cap in ((249,4096),(251,4096),(250,4095),(250,8192),(240,4096),(260,4096)):
            with self.subTest(seconds=seconds,cap=cap),self.assertRaises(_CommandError):_Limits(seconds,cap)
        for seconds,cap in ((15,1024**2),(30,4096),(60,4096),(75,1024**2)):
            self.assertEqual(_Limits(seconds,cap).execution_seconds,seconds)


class DispatchTests(unittest.TestCase):
    def test_four_modes_call_only_selected_existing_api_with_no_outer_package_recursion(self):
        phase=load_phase()
        import qshd_selinux_first_activation as first
        import qshd_selinux_consumer_activation as consumer
        import qshd_selinux_package_state as package
        calls=[];records={name:object() for name in PHASES}
        def bridge(*,deadline):calls.append(('bridge',deadline));return records['provider-post-pristine']
        def pre(*,fresh,deadline):calls.append(('pre',fresh,deadline));return records['consumer-pre-fresh' if fresh else 'consumer-pre-installed']
        def post(*,deadline):calls.append(('post',deadline));return records['consumer-post-owned']
        with patch.object(first,'activate_installed_pristine_pending_first',side_effect=bridge),\
             patch.object(consumer,'invalidate_installed_consumer_pre',side_effect=pre),\
             patch.object(consumer,'finalize_installed_owned_pending_consumer',side_effect=post),\
             patch.object(consumer._Production,'guard',side_effect=lambda deadline:calls.append(('guard',deadline))),\
             patch.object(package,'production',side_effect=AssertionError('entry must not nest a package lease')):
            for name in PHASES:self.assertIs(phase._dispatch(name,deadline=340.0),records[name])
        self.assertEqual(calls,[('guard',340.0),('bridge',340.0),('pre',True,340.0),('pre',False,340.0),('post',340.0)])


class DeadlineTests(unittest.TestCase):
    def test_original_work_budget_expired_before_owner_admission(self):
        phase=load_phase()
        with patch.object(phase,'_resources'),patch.object(phase.time,'monotonic',return_value=345.0),\
             patch.object(phase,'_owner',side_effect=AssertionError('expired work must not create owner')):
            with self.assertRaises(phase.PhaseError):phase._parent('consumer-pre-fresh',100.0)

    def test_owner_setup_cannot_renew_original_work_budget(self):
        phase=load_phase()
        from unittest.mock import Mock
        owner=Mock()
        with patch.object(phase,'_resources'),patch.object(phase.time,'monotonic',side_effect=[339.0,341.0]),\
             patch.object(phase,'_owner',return_value=owner):
            with self.assertRaises(phase.PhaseError):phase._parent('consumer-pre-fresh',100.0)
        owner._run.assert_not_called()

    def test_child_rejects_widened_or_expired_deadline_before_resources(self):
        phase=load_phase();request=phase._request('consumer-pre-fresh').decode()
        with patch.object(phase.time,'monotonic',return_value=341.0),\
             patch.object(phase,'_resources',side_effect=AssertionError('no resource access')):
            for start,end in (('100','340'),('100','350'),('nan','340'),('342','582')):
                with self.subTest(start=start,end=end),self.assertRaises(phase.PhaseError):
                    phase._child_main([request,start,end])


class ParentTests(unittest.TestCase):
    setUp=ProtocolTests.setUp
    response=ProtocolTests.response
    def test_parent_restores_all_signal_handlers_when_owner_fails(self):
        import signal
        phase=self.phase
        before={key:signal.getsignal(key) for key in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT)}
        with patch.object(phase,'_resources'),patch.object(phase.time,'monotonic',return_value=101.0),\
             patch.object(phase,'_owner',side_effect=RuntimeError('synthetic private refusal')):
            with self.assertRaises(RuntimeError):phase._parent('consumer-pre-fresh',100.0)
        self.assertEqual({key:signal.getsignal(key) for key in before},before)

    def test_fixed_child_vector_original_deadlines_and_normal_settlement(self):
        import io
        from types import SimpleNamespace
        phase=self.phase;request,frame=self.response('consumer-pre-fresh');raw=canonical(frame)+b'\n'
        calls=[]
        class Owner:
            _last=SimpleNamespace(failure=None,exit_code=0,settled=True,unreaped=())
            def _run(self,argv,cwd,*,deadline):
                calls.append((argv,cwd,deadline));return SimpleNamespace(stdout=raw,stderr=b'')
        output=SimpleNamespace(buffer=io.BytesIO())
        with patch.object(phase,'_resources'),patch.object(phase,'_owner',return_value=Owner()),\
             patch.object(phase.time,'monotonic',return_value=101.0),patch.object(phase.sys,'stdout',output):
            self.assertEqual(phase._parent('consumer-pre-fresh',100.0),0)
        self.assertEqual(calls,[(('/usr/bin/python3','-I','-B',phase._SCRIPT,phase._CHILD,request.decode(),'100.0','340.0'),'/',350.0)])
        self.assertEqual(output.buffer.getvalue(),raw)

    def test_owner_failure_stderr_unsettled_and_late_result_never_forward(self):
        import io
        from types import SimpleNamespace
        request,frame=self.response('consumer-pre-fresh');raw=canonical(frame)+b'\n'
        for failure,exit_code,settled,unreaped,stderr,clock in (
            ('TOOL_FAILURE',0,True,(),b'',101.0),(None,1,True,(),b'',101.0),
            (None,0,False,(),b'',101.0),(None,0,True,(123,),b'',101.0),
            (None,0,True,(),b'warning',101.0),(None,0,True,(),b'',350.0)):
            owner=SimpleNamespace(_last=SimpleNamespace(failure=failure,exit_code=exit_code,settled=settled,unreaped=unreaped),
                _run=lambda *a,**kw:SimpleNamespace(stdout=raw,stderr=stderr))
            output=SimpleNamespace(buffer=io.BytesIO())
            with patch.object(self.phase,'_resources'),patch.object(self.phase,'_owner',return_value=owner),\
                 patch.object(self.phase.time,'monotonic',side_effect=[101.0,101.0,clock]),\
                 patch.object(self.phase.sys,'stdout',output):
                with self.assertRaises(self.phase.PhaseError):self.phase._parent('consumer-pre-fresh',100.0)
            self.assertEqual(output.buffer.getvalue(),b'')


class DeliveryTests(unittest.TestCase):
    def test_actual_bad_public_cli_has_one_fixed_refusal_without_phase_execution(self):
        self.assertTrue(SCRIPT.is_file(),'phase entry missing')
        with tempfile.TemporaryDirectory() as directory:
            env=os.environ|dict(HOME=directory,XDG_CACHE_HOME=directory,XDG_CONFIG_HOME=directory,HISTFILE='/dev/null')
            for args in ([],['unsupported'],['consumer-pre-fresh','extra'],['--deadline','999']):
                result=subprocess.run([sys.executable,'-I','-B',str(SCRIPT),*args],cwd=directory,env=env,capture_output=True,timeout=10)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual(result.stdout,b'')
                self.assertEqual(result.stderr,b'PHASE_REFUSED\n')

    def test_import_only_leaves_process_resources_and_subreaper_unchanged(self):
        self.assertTrue(SCRIPT.is_file(),'phase entry missing')
        code="""import ctypes,importlib.util,resource,sys
sys.path.insert(0,sys.argv[1])
keys=(resource.RLIMIT_CORE,resource.RLIMIT_FSIZE,resource.RLIMIT_AS,resource.RLIMIT_NOFILE,resource.RLIMIT_CPU)
before=tuple(resource.getrlimit(k) for k in keys)
lib=ctypes.CDLL(None,use_errno=True);flag=ctypes.c_int()
assert lib.prctl(37,ctypes.byref(flag),0,0,0)==0
old=flag.value
spec=importlib.util.spec_from_file_location('phase_import_only',sys.argv[2])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
assert before==tuple(resource.getrlimit(k) for k in keys)
assert lib.prctl(37,ctypes.byref(flag),0,0,0)==0 and flag.value==old
"""
        result=subprocess.run([sys.executable,'-I','-B','-c',code,str(SOURCE),str(SCRIPT)],capture_output=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(result.stdout,b'')

    def test_exact_resources_and_real_owned_harmless_child_profile(self):
        code="""import importlib.util,sys,resource,time,os
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
spec=importlib.util.spec_from_file_location('phase_resource_test',sys.argv[2])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
# Root admission alone is substituted; resource changes and child custody are real.
with patch.object(m.os,'geteuid',return_value=0):m._resources(configure=True);m._resources(configure=False)
for key,value in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,16*1024**2),(resource.RLIMIT_AS,1024**3),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_CPU,260)):
 assert resource.getrlimit(key)==(value,value)
owner=m._owner()
streams=owner._run(('/usr/bin/python3','-I','-B','-c','print("public fixture")'),os.getcwd(),deadline=time.monotonic()+3)
assert streams.stdout==b'public fixture\\n' and streams.stderr==b''
assert owner._last.settled and not owner._last.unreaped and owner._last.failure is None
from qshd_selinux_process import _CommandError,_children
try:owner._run(('/usr/bin/python3','-I','-B','-c','import time;time.sleep(5)'),os.getcwd(),deadline=time.monotonic()+0.1)
except _CommandError:assert owner._last.failure=='COMMAND_TIMEOUT' and owner._last.settled and not owner._last.unreaped
else:raise AssertionError('deadline widened')
assert not _children()
"""
        with tempfile.TemporaryDirectory() as directory:
            env=os.environ|dict(HOME=directory,XDG_CONFIG_HOME=directory,XDG_CACHE_HOME=directory,HISTFILE='/dev/null')
            result=subprocess.run([sys.executable,'-I','-B','-c',code,str(SOURCE),str(SCRIPT)],cwd=directory,env=env,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(result.stdout,b'')

    def test_fixed_loader_rejects_preloaded_modules_and_has_no_directory_fallback(self):
        code="""import importlib.util,sys,types,pathlib
spec=importlib.util.spec_from_file_location('entry_test',sys.argv[1])
m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m)
if sys.argv[2]=='preloaded':
 sys.modules['qshd_selinux_activation']=types.ModuleType('qshd_selinux_activation')
 try:m._install_loader()
 except m.PhaseError:pass
 else:raise AssertionError('preloaded code admitted')
else:
 before=list(sys.path);m._install_loader();assert sys.path==before
 import qshd_selinux_phase
 assert qshd_selinux_phase is m
 import qshd_selinux_activation
 assert pathlib.Path(qshd_selinux_activation.__file__).parent==pathlib.Path(sys.argv[1]).parent
 for name in ('qshd_selinux_unknown','stop_guard.extra','qshd_selinux.extra'):
  try:__import__(name)
  except ModuleNotFoundError:pass
  else:raise AssertionError('unknown project import admitted')
"""
        with tempfile.TemporaryDirectory() as directory:
            poison=Path(directory);(poison/'qshd_selinux_activation.py').write_text('raise AssertionError("poison")')
            env=os.environ|dict(PYTHONPATH=directory,HOME=directory,XDG_CONFIG_HOME=directory,XDG_CACHE_HOME=directory,HISTFILE='/dev/null')
            for mode in ('preloaded','fixed'):
                result=subprocess.run([sys.executable,'-I','-B','-c',code,str(SCRIPT),mode],cwd=directory,env=env,capture_output=True,timeout=10)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(result.stdout,b'')

    def test_four_modes_dispatch_through_actual_assembled_payload_and_fixed_importer(self):
        spec=importlib.util.spec_from_file_location('integrated_payload_builder',SOURCE/'assemble_payload.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);self.assertEqual(base.stat().st_mode & 0o777,0o700)
            pp=base/'qshd.pp';pp.write_bytes(b'synthetic public PP, never loaded')
            artifact=SOURCE/'artifact.json';pam=ROOT/'packaging/pam.d/qshd.fedora-selinux'
            expected={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in RUNTIME_MODULES}
            expected.update({path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (pp,artifact,pam)})
            out=base/'payload';inventory=builder.assemble_payload(SOURCE,pp,artifact,pam,expected,out,1000000000)
            self.assertEqual(len(inventory),24)
            installed=out/'usr/libexec/qshd-selinux'
            poison=base/'poison';poison.mkdir();(poison/'qshd_selinux_consumer_activation.py').write_text('raise AssertionError("source fallback")')
            code="""import importlib.util,sys,pathlib
from unittest.mock import patch
root=pathlib.Path(sys.argv[1]);mode=sys.argv[2]
# This is a real module loaded from the delivered file, not a fabricated module.
spec=importlib.util.spec_from_file_location('qshd_selinux_phase',root/'qshd_selinux_phase.py')
phase=importlib.util.module_from_spec(spec);sys.modules[spec.name]=phase;spec.loader.exec_module(phase)
before=list(sys.path);phase._install_loader();assert before==sys.path
import qshd_selinux_phase
assert qshd_selinux_phase is phase
import qshd_selinux_consumer_activation as consumer
import qshd_selinux_first_activation as first
import qshd_selinux_package_state as package
from qshd_selinux_activation import Activation,TrustedArtifact,ModuleIdentity,Completion,ContextBinding
state=phase._PHASES[mode];trust=TrustedArtifact('fixture','a'*64,'b'*64)
completion=Completion('normal-install-reload-v1',trust.pp_sha256,ContextBinding('d'*64,'e'*64)) if state=='COMPLETE' else None
record=Activation(1,state,'c'*32,'fedora44-targeted-v1',1,1,trust,ModuleIdentity('qshd',400,'targeted','pp'),completion)
calls=[]
def pre(*,fresh,deadline):calls.append(('pre',fresh,deadline));return record
def post(*,deadline):calls.append(('post',deadline));return record
def bridge(*,deadline):calls.append(('bridge',deadline));return record
with patch.object(consumer,'invalidate_installed_consumer_pre',side_effect=pre),patch.object(consumer,'finalize_installed_owned_pending_consumer',side_effect=post),patch.object(first,'activate_installed_pristine_pending_first',side_effect=bridge),patch.object(consumer._Production,'guard',side_effect=lambda end:calls.append(('guard',end))),patch.object(package,'production',side_effect=AssertionError('nested package operation')):
 result=phase._dispatch(mode,deadline=1234.0)
 assert result is record
 request=phase._request(mode);frame=phase._response(result,request)
 assert phase._parse_response(frame,request)['state']==state
expected={'provider-post-pristine':[('guard',1234.0),('bridge',1234.0)],'consumer-pre-fresh':[('pre',True,1234.0)],'consumer-pre-installed':[('pre',False,1234.0)],'consumer-post-owned':[('post',1234.0)]}
assert calls==expected[mode]
for name,module in list(sys.modules.items()):
 if name in phase._MODULES:
  assert pathlib.Path(module.__file__).parent==root,(name,module.__file__)
assert str(root) not in sys.path
"""
            env=os.environ|dict(PYTHONPATH=str(poison),HOME=directory,XDG_CONFIG_HOME=directory,XDG_CACHE_HOME=directory,HISTFILE='/dev/null')
            for mode in PHASES:
                with self.subTest(mode=mode):
                    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(installed),mode],cwd=poison,env=env,capture_output=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(result.stdout,b'')

    def test_exact_offline_payload_twenty_modules_twentyfour_files_no_renderer(self):
        spec=importlib.util.spec_from_file_location('phase_payload_builder',SOURCE/'assemble_payload.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        self.assertEqual(set(builder.MODULES),set(RUNTIME_MODULES));self.assertEqual(len(builder.MODULES),20)
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);source=base/'source';source.mkdir()
            for name in RUNTIME_MODULES:shutil.copy2(SOURCE/name,source/name)
            (source/'private-experiment.txt').write_text('PRIVATE DECOY: DO NOT DELIVER')
            (source/'embed_provider_pre.py').write_text('raise AssertionError("incoming renderer must not ship")')
            pp=base/'qshd.pp';pp.write_bytes(b'public synthetic PP, never loaded')
            artifact=SOURCE/'artifact.json';pam=ROOT/'packaging/pam.d/qshd.fedora-selinux'
            expected={name:hashlib.sha256((source/name).read_bytes()).hexdigest() for name in RUNTIME_MODULES}
            expected.update({path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (pp,artifact,pam)})
            out=base/'out';inventory=builder.assemble_payload(source,pp,artifact,pam,expected,out,1000000000)
            self.assertEqual(len(inventory),24)
            actual={str(path.relative_to(out)) for path in out.rglob('*') if path.is_file()}
            self.assertEqual(actual,{'usr/libexec/qshd-selinux/'+name for name in RUNTIME_MODULES}|{
                'usr/share/qshd-selinux/'+name for name in ('qshd.pp','artifact.json','qshd.fedora-selinux','reference.json')})
            for name in RUNTIME_MODULES:self.assertEqual((out/'usr/libexec/qshd-selinux'/name).read_bytes(),(source/name).read_bytes())


if __name__=='__main__':unittest.main()
