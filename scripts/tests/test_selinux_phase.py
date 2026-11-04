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
        'consumer-pre-installed':'PENDING','consumer-post-owned':'COMPLETE',
        'consumer-preun-final':'PENDING'}
RUNTIME_MODULES=tuple('qshd_selinux_'+name+'.py' for name in (
    'activation','activation_state','contexts','transaction','fs','registry',
    'process','modules','module_observer','api','queries','files','observer',
    'reference_loader','package_state','module_install','first_activation',
    'consumer_activation','phase','rpm_query'))+('stop_guard.py',)
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

    def test_fixed_five_requests_and_exact_response_binding(self):
        self.assertEqual(self.phase._PHASES,PHASES)
        for phase in PHASES:
            request,frame=self.response(phase)
            self.assertEqual(self.phase._request(phase),request)
            self.assertEqual(self.phase._parse_request(request),{'schema':1,'phase':phase})
            self.assertEqual(self.phase._parse_response(canonical(frame)+b'\n',request),frame)
        for phase in ('','provider-pre','erase','consumer-pre','/private/path','consumer-pre-fresh --deadline 999',
                      'consumer-preun','consumer-preun-final ','Consumer-preun-final','consumer-postun-final',
                      'consumer-preun-upgrade'):
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

    def test_final_erase_preparation_frame_binds_its_own_phase_pending_state_and_digest(self):
        request,frame=self.response('consumer-preun-final');raw=canonical(frame)+b'\n'
        self.assertEqual(self.phase._parse_response(raw,request),frame)
        other,_=self.response('consumer-post-owned')
        for changes in ({'state':'COMPLETE'},{'phase':'consumer-post-owned'},{'phase':'consumer-pre-installed'},
                        {'request_sha256':hashlib.sha256(other).hexdigest()}):
            with self.subTest(changes=changes),self.assertRaises(self.phase.PhaseError):
                self.phase._parse_response(canonical(frame|changes)+b'\n',request)
        with self.assertRaises(self.phase.PhaseError):self.phase._parse_response(raw,other)
        for value in (canonical({'schema':1,'phase':'consumer-preun-final'})+b' ',
                      b'{"phase":"consumer-preun-final","schema":1,"schema":1}',
                      b'{"phase":"consumer-preun-final","schema":true}',
                      b'{"phase":"consumer-preun-final","schema":1,"deadline":340}',
                      b'{"schema":1,"phase":"consumer-preun-final"}'):
            with self.subTest(value=value),self.assertRaises(self.phase.PhaseError):self.phase._parse_request(value)

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
        completion=Completion('normal-install-reload-v1',trust.pp_sha256,ContextBinding('d'*64,'e'*64))
        complete=Activation(1,'COMPLETE','c'*32,'fedora44-targeted-v1',1,1,trust,ModuleIdentity('qshd',400,'targeted','pp'),completion)
        with self.assertRaises(self.phase.PhaseError):self.phase._response(complete,self.phase._request('consumer-preun-final'))

    def test_only_exact_250_combined_profile_is_new(self):
        from qshd_selinux_process import _Limits,_CommandError
        self.assertEqual(_Limits(250,4096).execution_seconds,250)
        for seconds,cap in ((249,4096),(251,4096),(250,4095),(250,8192),(240,4096),(260,4096)):
            with self.subTest(seconds=seconds,cap=cap),self.assertRaises(_CommandError):_Limits(seconds,cap)
        for seconds,cap in ((15,1024**2),(30,4096),(60,4096),(75,1024**2)):
            self.assertEqual(_Limits(seconds,cap).execution_seconds,seconds)


class DispatchTests(unittest.TestCase):
    def test_five_modes_call_only_selected_existing_api_with_no_outer_package_recursion(self):
        phase=load_phase()
        import qshd_selinux_first_activation as first
        import qshd_selinux_consumer_activation as consumer
        import qshd_selinux_package_state as package
        calls=[];records={name:object() for name in PHASES}
        def bridge(*,deadline):calls.append(('bridge',deadline));return records['provider-post-pristine']
        def pre(*,fresh,deadline):calls.append(('pre',fresh,deadline));return records['consumer-pre-fresh' if fresh else 'consumer-pre-installed']
        def post(*,deadline):calls.append(('post',deadline));return records['consumer-post-owned']
        def erase(*,deadline):calls.append(('erase',deadline));return records['consumer-preun-final']
        with patch.object(first,'activate_installed_pristine_pending_first',side_effect=bridge),\
             patch.object(consumer,'invalidate_installed_consumer_pre',side_effect=pre),\
             patch.object(consumer,'finalize_installed_owned_pending_consumer',side_effect=post),\
             patch.object(consumer,'invalidate_installed_consumer_erase',side_effect=erase),\
             patch.object(consumer._Production,'guard',side_effect=lambda deadline:calls.append(('guard',deadline))),\
             patch.object(package,'production',side_effect=AssertionError('entry must not nest a package lease')):
            for name in PHASES:self.assertIs(phase._dispatch(name,deadline=340.0),records[name])
        self.assertEqual(calls,[('guard',340.0),('bridge',340.0),('pre',True,340.0),('pre',False,340.0),('post',340.0),
                                ('erase',340.0)])

    def patched_consumer(self,erase):
        import qshd_selinux_first_activation as first
        import qshd_selinux_consumer_activation as consumer
        import qshd_selinux_package_state as package
        refuse=lambda name:AssertionError(name+' must not be called for final erase preparation')
        return (patch.object(consumer,'invalidate_installed_consumer_erase',side_effect=erase),
                patch.object(consumer,'invalidate_installed_consumer_pre',side_effect=refuse('pre')),
                patch.object(consumer,'finalize_installed_owned_pending_consumer',side_effect=refuse('post')),
                patch.object(first,'activate_installed_pristine_pending_first',side_effect=refuse('bridge')),
                patch.object(consumer._Production,'guard',side_effect=refuse('another guard')),
                patch.object(package,'production',side_effect=refuse('another package lease')))

    def test_final_erase_preparation_passes_the_exact_original_deadline_once(self):
        phase=load_phase();deadline=object();record=object();calls=[]
        def erase(**kwargs):calls.append(kwargs);return record
        patches=self.patched_consumer(erase)
        with patches[0],patches[1],patches[2],patches[3],patches[4],patches[5]:
            self.assertIs(phase._dispatch('consumer-preun-final',deadline=deadline),record)
        self.assertEqual(len(calls),1);self.assertEqual(set(calls[0]),{'deadline'})
        self.assertIs(calls[0]['deadline'],deadline)

    def test_final_erase_preparation_failure_propagates_without_fallback_or_frame(self):
        import io
        from types import SimpleNamespace
        phase=load_phase();request=phase._request('consumer-preun-final').decode()
        class Failure(Exception):pass
        failure=Failure('synthetic outcome-uncertain erase preparation');calls=[]
        def erase(*,deadline):calls.append(deadline);raise failure
        output=SimpleNamespace(buffer=io.BytesIO())
        patches=self.patched_consumer(erase)
        with patches[0],patches[1],patches[2],patches[3],patches[4],patches[5],\
             patch.object(phase,'_resources'),patch.object(phase.time,'monotonic',return_value=101.0),\
             patch.object(phase,'_response',side_effect=AssertionError('no frame after a failed operation')),\
             patch.object(phase.sys,'stdout',output),patch.object(phase.sys,'stderr',SimpleNamespace(buffer=io.BytesIO())) as errors:
            self.assertEqual(phase._child_main([request,'100.0','340.0']),1)
            self.assertEqual(phase._parse_failure(errors.buffer.getvalue(),request.encode())['codes'],['UNKNOWN'])
        self.assertEqual(calls,[340.0])
        self.assertEqual(output.buffer.getvalue(),b'')


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


class FailureProtocolTests(unittest.TestCase):
    def test_install_timeout_retains_only_closed_bound_provenance(self):
        phase=load_phase()
        import qshd_selinux_first_activation as first
        import qshd_selinux_process as process
        inner=process._CommandError('COMMAND_TIMEOUT')
        outer=first.CoordinatorError('INSTALL');outer.__context__=inner;outer.__suppress_context__=True
        request=phase._request('provider-post-pristine')
        frame=phase._failure(outer,request)
        value=phase._parse_failure(frame,request)
        self.assertEqual(value['codes'],['COORDINATOR_INSTALL','COMMAND_TIMEOUT'])
        self.assertLessEqual(len(frame),1024)


class FailureSafetyTests(unittest.TestCase):
    def setUp(self):self.phase=load_phase();self.request=self.phase._request('provider-post-pristine')

    def test_launch_code_validation_preserves_command_schema(self):
        import qshd_selinux_process as process
        for outcome in (None, object(),
                process._Outcome(b'',b'',0,'TOOL_FAILURE',True,launch_code='OS_EMFILE'),
                process._Outcome(b'',b'',None,'COMMAND_TIMEOUT',True,launch_code='OS_EMFILE'),
                process._Outcome(b'',b'',None,'TOOL_FAILURE',True,launch_code='PRIVATE'),
                process._Outcome(b'',b'',None,'TOOL_FAILURE',True,launch_code=True)):
            self.assertIsNone(process._launch_code(outcome))
        for code in ('PRIVATE',True,object(),None):
            error=process._CommandError('TOOL_FAILURE',_outcome=code)
            value=self.phase._parse_failure(self.phase._failure(error,self.request),self.request)
            self.assertEqual(value['codes'],['TOOL_FAILURE'])
        self.assertEqual(set(self.phase._parse_failure(self.phase._failure(error,self.request),self.request)),
                         {'version','request','codes','command'})

    def test_unknown_private_text_and_cycles_are_bounded_without_rendering(self):
        class Private(Exception):
            def __str__(self):raise AssertionError('must not render exception')
            def __repr__(self):raise AssertionError('must not render exception')
        error=Private('PRIVATE_PATH_TOKEN');error.__context__=error
        raw=self.phase._failure(error,self.request)
        self.assertNotIn(b'PRIVATE',raw)
        self.assertEqual(self.phase._parse_failure(raw,self.request)['codes'],['UNKNOWN'])
        current=error
        for _ in range(20):
            newer=Private('PRIVATE');newer.__context__=current;current=newer
        self.assertEqual(len(self.phase._parse_failure(self.phase._failure(current,self.request),self.request)['codes']),8)

    def test_unknown_launch_census_keeps_null_command_and_known_count_is_bounded(self):
        import qshd_selinux_process as process
        limits = process._Limits(15, 1024**2)
        for children in (None, (98765,)):
            with self.subTest(known=children is not None):
                outcome = process._Outcome(b'PRIVATE_STDOUT', b'PRIVATE_STDERR',
                    None, 'COMMAND_UNSETTLED', False, children)
                summary = process._failure_summary(outcome, limits)
                error = process._CommandError('COMMAND_UNSETTLED', summary=summary)
                raw = self.phase._failure(error, self.request)
                parsed = self.phase._parse_failure(raw, self.request)
                self.assertEqual(parsed['codes'], ['COMMAND_UNSETTLED'])
                if children is None:
                    self.assertIsNone(summary)
                    self.assertIsNone(parsed['command'])
                else:
                    self.assertEqual(parsed['command']['unreaped'], 1)
                    self.assertFalse(parsed['command']['settled'])
                self.assertNotIn(b'98765', raw)
                self.assertNotIn(b'PRIVATE', raw)

    def test_actual_summary_types_and_outcome_categories_cannot_leak_streams(self):
        from dataclasses import FrozenInstanceError
        import qshd_selinux_process as process
        for failure,exit_code,settled,unreaped in ((None,7,True,()),(None,-25,True,()),('COMMAND_TIMEOUT',-15,True,()),('COMMAND_UNSETTLED',None,False,(98765,))):
            outcome=process._Outcome(b'PRIVATE_STDOUT',b'PRIVATE_STDERR',exit_code,failure,settled,unreaped)
            summary=process._failure_summary(outcome,process._Limits(75,1024**2))
            self.assertEqual(summary.exit_code,exit_code);self.assertEqual(summary.unreaped,len(unreaped))
            with self.assertRaises(FrozenInstanceError):summary.exit_code=1
            error=process._CommandError(failure or 'TOOL_FAILURE',summary=summary)
            raw=self.phase._failure(error,self.request)
            self.assertNotIn(b'PRIVATE',raw);self.assertNotIn(b'98765',raw)
            self.assertEqual(self.phase._parse_failure(raw,self.request)['command']['profile'],'module75')
        self.assertIsNone(process._failure_summary(process._Outcome(b'',b'',True,None,True),process._Limits(5,1)))

    def test_builtin_errno_codes_are_closed_and_custom_canaries_are_unknown(self):
        import errno
        class Foreign(OSError):
            def __str__(self):raise AssertionError('must not stringify private errno')
        for name in ('EMFILE','ENFILE','ENOMEM','EFBIG','ENOSPC','EACCES','EPERM'):
            error=OSError(getattr(errno,name),'PRIVATE_MESSAGE','PRIVATE_FILENAME')
            raw=self.phase._failure(error,self.request)
            self.assertEqual(self.phase._parse_failure(raw,self.request)['codes'],['OS_'+name])
            self.assertNotIn(b'PRIVATE',raw)
        for error in (Foreign(errno.EMFILE,'PRIVATE'),OSError(errno.ENOENT,'PRIVATE')):
            self.assertEqual(self.phase._parse_failure(self.phase._failure(error,self.request),self.request)['codes'],['UNKNOWN'])
        error=OSError(errno.EMFILE,'PRIVATE');error.errno=True
        self.assertEqual(self.phase._parse_failure(self.phase._failure(error,self.request),self.request)['codes'],['UNKNOWN'])

    def test_noncanonical_foreign_oversized_and_wrong_typed_frames_refuse(self):
        value=self.phase._parse_failure(self.phase._failure(ValueError('PRIVATE'),self.request),self.request)
        bad=[b'x'*1025,canonical(value),canonical(dict(value,version=True))+b'\n',canonical(dict(value,codes=['PRIVATE']))+b'\n',canonical(dict(value,codes=['UNKNOWN']*9))+b'\n']
        foreign=dict(value,request={'schema':1,'phase':'consumer-pre-fresh'});bad.append(canonical(foreign)+b'\n')
        command=dict(profile='module75',failure=None,exit_code=True,settled=True,unreaped=0)
        bad.append(canonical(dict(value,command=command))+b'\n')
        for raw in bad:
            with self.subTest(raw=raw[:30]),self.assertRaises(self.phase.PhaseError):self.phase._parse_failure(raw,self.request)

    def test_parent_owner_failure_dominates_even_valid_private_refusal(self):
        import io
        from types import SimpleNamespace
        import qshd_selinux_process as process
        raw=self.phase._failure(ValueError('PRIVATE'),self.request)
        for failure,code,settled,unreaped,stdout,stderr,clock in (
                ('TOOL_FAILURE',1,True,(),b'',raw,101),('COMMAND_TIMEOUT',1,True,(),b'',raw,101),
                (None,1,False,(),b'',raw,101),(None,1,True,(999,),b'',raw,101),
                (None,1,True,(),b'other',raw,101),(None,2,True,(),b'',raw,101),
                (None,1,True,(),b'',b'PRIVATE',101),(None,1,True,(),b'',raw,350)):
            owner=SimpleNamespace(_last=process._Outcome(stdout,stderr,code,failure,settled,unreaped))
            def run(*a,**k):raise process._CommandError('TOOL_FAILURE')
            owner._run=run;output=SimpleNamespace(buffer=io.BytesIO());errors=SimpleNamespace(buffer=io.BytesIO())
            with patch.object(self.phase,'_resources'),patch.object(self.phase,'_owner',return_value=owner),patch.object(self.phase.time,'monotonic',side_effect=[101,101,clock]),patch.object(self.phase.sys,'stdout',output),patch.object(self.phase.sys,'stderr',errors):
                with self.assertRaises(self.phase.PhaseError):self.phase._parent('provider-post-pristine',100.0)
            self.assertEqual(output.buffer.getvalue(),b'');self.assertEqual(errors.buffer.getvalue(),b'')

    def test_child_cancellation_does_not_become_normal_refusal(self):
        import io
        from types import SimpleNamespace
        output=SimpleNamespace(buffer=io.BytesIO());errors=SimpleNamespace(buffer=io.BytesIO())
        with patch.object(self.phase,'_resources'),patch.object(self.phase.time,'monotonic',return_value=101),patch.object(self.phase,'_dispatch',side_effect=KeyboardInterrupt()),patch.object(self.phase.sys,'stdout',output),patch.object(self.phase.sys,'stderr',errors):
            with self.assertRaises(KeyboardInterrupt):self.phase._child_main([self.request.decode(),'100','340'])
        self.assertEqual(output.buffer.getvalue(),b'');self.assertEqual(errors.buffer.getvalue(),b'')

    def test_real_harmless_child_parent_forwards_one_refusal_after_settlement(self):
        program=r'''
import importlib.util, pathlib, resource, sys, time
root=pathlib.Path(sys.argv[1]);helper=pathlib.Path(sys.argv[2]);sys.path.insert(0,str(root))
for key,value in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,16*1024**2),(resource.RLIMIT_AS,1024**3),(resource.RLIMIT_CPU,15)):
 resource.setrlimit(key,(value,value))
spec=importlib.util.spec_from_file_location('actual_phase',root/'qshd_selinux_phase.py');phase=importlib.util.module_from_spec(spec);sys.modules[spec.name]=phase;spec.loader.exec_module(phase)
phase._resources=lambda **kw:None
if len(sys.argv)>3:
 import qshd_selinux_first_activation as first
 import qshd_selinux_process as process
 def refuse(*args,**kw):
  inner=process._CommandError('COMMAND_TIMEOUT',summary=process._FailureSummary('module75','COMMAND_TIMEOUT',-15,True,0))
  outer=first.CoordinatorError('INSTALL');outer.__context__=inner;raise outer from None
 phase._dispatch=refuse
 raise SystemExit(phase._child_main(sys.argv[4:]))
phase._SCRIPT=str(helper)
status=phase._parent('provider-post-pristine',time.monotonic())
import qshd_selinux_process as process
assert process._children()==[]
raise SystemExit(status)
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700);helper=root/'child.py'
            helper.write_text(program);helper.chmod(0o600)
            env=os.environ|dict(HOME=directory,XDG_CACHE_HOME=directory,XDG_CONFIG_HOME=directory,TMPDIR=directory,HISTFILE='/dev/null')
            # Child script receives the fixed production child selector then original request/times.
            child_program=program.replace("root=pathlib.Path(sys.argv[1]);helper=pathlib.Path(sys.argv[2]);", "root=pathlib.Path("+repr(str(SOURCE))+ ");helper=pathlib.Path(__file__);").replace('if len(sys.argv)>3:', 'if True:').replace('sys.argv[4:]', 'sys.argv[2:]')
            helper.write_text(child_program)
            result=subprocess.run([sys.executable,'-I','-B','-c',program,str(SOURCE),str(helper)],cwd=directory,env=env,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertEqual(result.stdout,b'')
            value=self.phase._parse_failure(result.stderr,self.request)
            self.assertEqual(value['codes'],['COORDINATOR_INSTALL','COMMAND_TIMEOUT'])
            self.assertEqual(value['command']['exit_code'],-15)

    def test_real_owner_launch_errno_crosses_child_parent_after_settlement(self):
        program=r'''
import importlib.util, pathlib, resource, sys, time
root=pathlib.Path(sys.argv[1]);helper=pathlib.Path(sys.argv[2]);sys.path.insert(0,str(root))
for key,value in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,16*1024**2),(resource.RLIMIT_AS,1024**3),(resource.RLIMIT_CPU,15)):
 resource.setrlimit(key,(value,value))
spec=importlib.util.spec_from_file_location('actual_phase',root/'qshd_selinux_phase.py');phase=importlib.util.module_from_spec(spec);sys.modules[spec.name]=phase;spec.loader.exec_module(phase)
phase._resources=lambda **kw:None
if len(sys.argv)>3:
 import qshd_selinux_first_activation as first
 import qshd_selinux_process as process
 def refuse(*args,**kw):
  import errno, tempfile
  from unittest.mock import patch
  def fail(*a,**k):raise OSError(errno.EMFILE,'PRIVATE_MESSAGE','/private/canary')
  with tempfile.TemporaryDirectory() as directory,patch.object(process.subprocess,'Popen',side_effect=fail):
   try:process._Owner(process._Limits(15,1024**2))._run(('/trusted/tool',),directory)
   except process._CommandError as inner:
    from qshd_selinux_fs import Conflict
    try:raise Conflict('PRIVATE') from inner
    except Conflict as context:raise first.CoordinatorError('OBSERVATION') from context
 phase._dispatch=refuse
 raise SystemExit(phase._child_main(sys.argv[4:]))
phase._SCRIPT=str(helper)
status=phase._parent('provider-post-pristine',time.monotonic())
import qshd_selinux_process as process
assert process._children()==[]
raise SystemExit(status)
'''
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);root.chmod(0o700);helper=root/'child.py'
            helper.write_text(program);helper.chmod(0o600)
            env=os.environ|dict(HOME=directory,XDG_CACHE_HOME=directory,XDG_CONFIG_HOME=directory,TMPDIR=directory,HISTFILE='/dev/null')
            # Child script receives the fixed production child selector then original request/times.
            child_program=program.replace("root=pathlib.Path(sys.argv[1]);helper=pathlib.Path(sys.argv[2]);", "root=pathlib.Path("+repr(str(SOURCE))+ ");helper=pathlib.Path(__file__);").replace('if len(sys.argv)>3:', 'if True:').replace('sys.argv[4:]', 'sys.argv[2:]')
            helper.write_text(child_program)
            result=subprocess.run([sys.executable,'-I','-B','-c',program,str(SOURCE),str(helper)],cwd=directory,env=env,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertEqual(result.stdout,b'')
            value=self.phase._parse_failure(result.stderr,self.request)
            self.assertEqual(value['codes'],['COORDINATOR_OBSERVATION','CONTEXT_REFUSED','OS_EMFILE'])
            self.assertIsNone(value['command']['exit_code'])
            self.assertEqual(value['command']['failure'],'TOOL_FAILURE')
            self.assertEqual(value['command']['profile'],'module15')
            self.assertTrue(value['command']['settled'])
            self.assertEqual(value['command']['unreaped'],0)
            self.assertLessEqual(len(result.stderr),1024)
            self.assertNotIn(b'PRIVATE',result.stderr)
            self.assertNotIn(b'/private',result.stderr)


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

    def test_five_modes_dispatch_through_actual_assembled_payload_and_fixed_importer(self):
        spec=importlib.util.spec_from_file_location('integrated_payload_builder',SOURCE/'assemble_payload.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);self.assertEqual(base.stat().st_mode & 0o777,0o700)
            pp=base/'qshd.pp';pp.write_bytes(b'synthetic public PP, never loaded')
            artifact=SOURCE/'artifact.json';pam=ROOT/'packaging/pam.d/qshd.fedora-selinux'
            expected={name:hashlib.sha256((SOURCE/name).read_bytes()).hexdigest() for name in RUNTIME_MODULES}
            expected.update({path.name:hashlib.sha256(path.read_bytes()).hexdigest() for path in (pp,artifact,pam)})
            out=base/'payload';inventory=builder.assemble_payload(SOURCE,pp,artifact,pam,expected,out,1000000000)
            self.assertEqual(len(expected),24)
            self.assertEqual(len(inventory),25)
            installed=out/'usr/libexec/qshd-selinux'
            poison=base/'poison';poison.mkdir()
            for name in ('qshd_selinux_consumer_activation.py','qshd_selinux_rpm_query.py'):
                (poison/name).write_text('raise AssertionError("source fallback")')
            code="""import importlib.util,sys,pathlib
from unittest.mock import patch
root=pathlib.Path(sys.argv[1]);mode=sys.argv[2]
# This is a real module loaded from the delivered file, not a fabricated module.
spec=importlib.util.spec_from_file_location('qshd_selinux_phase',root/'qshd_selinux_phase.py')
phase=importlib.util.module_from_spec(spec);sys.modules[spec.name]=phase;spec.loader.exec_module(phase)
if mode=='preloaded-query':
 finder=phase._FixedFinder(root);sys.meta_path.insert(0,finder)
 import qshd_selinux_rpm_query as query
 assert pathlib.Path(query.__file__).parent==root
 # Retain the actual query module alone, so this specifically proves its guard.
 for name in list(sys.modules):
  if name in phase._MODULES and name not in ('qshd_selinux_phase','qshd_selinux_rpm_query'):
   del sys.modules[name]
 sys.meta_path.remove(finder)
 try:phase._install_loader()
 except phase.PhaseError as error:assert str(error)=='MODULE_PRESENT'
 else:raise AssertionError('preloaded delivered query admitted')
 raise SystemExit(0)
before=list(sys.path);phase._install_loader();assert before==sys.path
if mode=='missing-query':
 try:import qshd_selinux_rpm_query
 except (ModuleNotFoundError,FileNotFoundError):pass
 else:raise AssertionError('missing delivered query used fallback')
 assert 'qshd_selinux_rpm_query' not in sys.modules
 raise SystemExit(0)
import qshd_selinux_phase
assert qshd_selinux_phase is phase
import qshd_selinux_consumer_activation as consumer
import qshd_selinux_first_activation as first
import qshd_selinux_package_state as package
import qshd_selinux_rpm_query as query
assert pathlib.Path(query.__file__).parent==root
from qshd_selinux_activation import Activation,TrustedArtifact,ModuleIdentity,Completion,ContextBinding
state=phase._PHASES[mode];trust=TrustedArtifact('fixture','a'*64,'b'*64)
completion=Completion('normal-install-reload-v1',trust.pp_sha256,ContextBinding('d'*64,'e'*64)) if state=='COMPLETE' else None
record=Activation(1,state,'c'*32,'fedora44-targeted-v1',1,1,trust,ModuleIdentity('qshd',400,'targeted','pp'),completion)
calls=[]
def pre(*,fresh,deadline):calls.append(('pre',fresh,deadline));return record
def post(*,deadline):calls.append(('post',deadline));return record
def bridge(*,deadline):calls.append(('bridge',deadline));return record
def erase(*,deadline):calls.append(('erase',deadline));return record
assert pathlib.Path(consumer.__file__).parent==root
with patch.object(consumer,'invalidate_installed_consumer_pre',side_effect=pre),patch.object(consumer,'finalize_installed_owned_pending_consumer',side_effect=post),patch.object(consumer,'invalidate_installed_consumer_erase',side_effect=erase),patch.object(first,'activate_installed_pristine_pending_first',side_effect=bridge),patch.object(consumer._Production,'guard',side_effect=lambda end:calls.append(('guard',end))),patch.object(package,'production',side_effect=AssertionError('nested package operation')):
 result=phase._dispatch(mode,deadline=1234.0)
 assert result is record
 request=phase._request(mode);frame=phase._response(result,request)
 assert phase._parse_response(frame,request)['state']==state
expected={'provider-post-pristine':[('guard',1234.0),('bridge',1234.0)],'consumer-pre-fresh':[('pre',True,1234.0)],'consumer-pre-installed':[('pre',False,1234.0)],'consumer-post-owned':[('post',1234.0)],'consumer-preun-final':[('erase',1234.0)]}
assert calls==expected[mode]
for name,module in list(sys.modules.items()):
 if name in phase._MODULES:
  assert pathlib.Path(module.__file__).parent==root,(name,module.__file__)
assert str(root) not in sys.path
"""
            env=os.environ|dict(PYTHONPATH=str(poison),HOME=directory,XDG_CONFIG_HOME=directory,XDG_CACHE_HOME=directory,HISTFILE='/dev/null')
            for mode in (*PHASES,'preloaded-query','missing-query'):
                if mode=='missing-query':
                    (installed/'qshd_selinux_rpm_query.py').unlink()
                with self.subTest(mode=mode):
                    result=subprocess.run([sys.executable,'-I','-B','-c',code,str(installed),mode],cwd=poison,env=env,capture_output=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr)
                    self.assertEqual(result.stdout,b'')

    def test_exact_offline_payload_twenty_one_modules_twentyfive_files_no_renderer(self):
        spec=importlib.util.spec_from_file_location('phase_payload_builder',SOURCE/'assemble_payload.py')
        builder=importlib.util.module_from_spec(spec);spec.loader.exec_module(builder)
        self.assertEqual(set(builder.MODULES),set(RUNTIME_MODULES));self.assertEqual(len(builder.MODULES),21)
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
            self.assertEqual(len(inventory),25)
            actual={str(path.relative_to(out)) for path in out.rglob('*') if path.is_file()}
            self.assertEqual(actual,{'usr/libexec/qshd-selinux/'+name for name in RUNTIME_MODULES}|{
                'usr/share/qshd-selinux/'+name for name in ('qshd.pp','artifact.json','qshd.fedora-selinux','reference.json')})
            for name in RUNTIME_MODULES:self.assertEqual((out/'usr/libexec/qshd-selinux'/name).read_bytes(),(source/name).read_bytes())


if __name__=='__main__':unittest.main()
