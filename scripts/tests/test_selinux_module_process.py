"""Harmless controls run process/resource ownership only in disposable children."""
import pathlib
import subprocess
import sys
import unittest


SOURCE = pathlib.Path(__file__).resolve().parents[2] / 'packaging/selinux/qshd_selinux_module_observer.py'
HARNESS = r'''
import importlib.util, json, os, pathlib, resource, signal, subprocess, sys, tempfile, threading, time
path=pathlib.Path(sys.argv[1]); case=sys.argv[2]
assert path.exists(), 'private module command owner missing'
spec=importlib.util.spec_from_file_location('observer',path)
binding=importlib.util.module_from_spec(spec);sys.modules[spec.name]=binding;sys.path.insert(0,str(path.parent));spec.loader.exec_module(binding)
import qshd_selinux_process as m
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024**2,16*1024**2))
resource.setrlimit(resource.RLIMIT_CPU,(15,15))
resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
native_popen=subprocess.Popen
if case=='preconditions':
    before=m._children()
    for option in (resource.RLIMIT_CORE,resource.RLIMIT_FSIZE,resource.RLIMIT_CPU,resource.RLIMIT_AS):
        original=resource.getrlimit
        def limits(key):return (-1,-1) if key==option else original(key)
        resource.getrlimit=limits
        try:
            try:binding._SemoduleOwner()
            except m._CommandError as exc:assert str(exc)=='PROCESS_LIMITS'
            else:raise AssertionError('unbounded owner admitted')
        finally:resource.getrlimit=original
    old_handler=signal.signal(signal.SIGCHLD,signal.SIG_IGN)
    try:
        try:binding._SemoduleOwner()
        except m._CommandError as exc:assert str(exc)=='PROCESS_SIGNALS'
        else:raise AssertionError('auto-reaping handler admitted')
    finally:signal.signal(signal.SIGCHLD,old_handler)
    stop=threading.Event(); thread=threading.Thread(target=stop.wait);thread.start()
    try:
        try:binding._SemoduleOwner()
        except m._CommandError as exc:assert str(exc)=='PROCESS_THREADS'
        else:raise AssertionError('threaded owner admitted')
    finally:stop.set();thread.join()
    child=native_popen([sys.executable,'-I','-B','-c','import time;time.sleep(30)'])
    try:
        try:binding._SemoduleOwner()
        except m._CommandError as exc:assert str(exc)=='PROCESS_CHILDREN'
        else:raise AssertionError('prior child admitted')
        assert child.poll() is None
    finally:child.terminate();child.wait(timeout=3)
    assert m._children()==before
else:
    binding._LIMITS=m._Limits(.2,1024**2);m._TERM_SECONDS=.1
    owner=binding._SemoduleOwner(); events=[]; seen=[]; started=[]
    original_group=os.killpg;original_poll=subprocess.Popen.poll
    def group(pid,sig):events.append(('group',sig));return original_group(pid,sig)
    def poll(proc):
        events.append(('poll',))
        if case=='cleanup-interrupt' and sum(event[0]=='poll' for event in events)==1:raise KeyboardInterrupt()
        return original_poll(proc)
    os.killpg=group;subprocess.Popen.poll=poll
    scripts={
      'short-tail':'import os;os.write(1,b"abcdefghij"*20);os.write(2,b"tail"*25)',
      'tail-overflow':'import os;os.write(1,b"x"*200)',
      'normal':'import os;os.write(1,b"raw\\xff\\x00")',
      'nonzero':'raise SystemExit(7)',
      'timeout':'import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)',
      'stdout':'import os;\nwhile True:os.write(1,b"x"*4096)',
      'stderr':'import os;\nwhile True:os.write(2,b"x"*4096)',
      'pipe':'import os,signal,time;\np=os.fork();\nif p==0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)\nelse:os._exit(0)',
      'detached':'import os,signal,time;\np=os.fork();\nif p==0:\n os.setsid();signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)\nelse:os._exit(0)',
      'interrupt':'import time;time.sleep(30)',
      'cleanup-interrupt':'import time;time.sleep(30)',
      'unsettled':'import time;time.sleep(30)',
      'anchor':'import time;time.sleep(30)',
      'extract-output':'print("unexpected")',
      'stderr-finite':'import os;os.write(1,b"400 qshd pp\\n");os.write(2,b"200 diagnostic pp\\n")',
      'streams':'import os;os.write(1,b"out\\xff");os.write(2,b"err\\x00")',
      'profile':'import os;os.write(1,b"x"*(2*1024**2))',
      'combined':'import os;os.write(1,b"x"*600000);os.write(2,b"y"*600000)',
      'remaining':'import time;time.sleep(30)',
      'lease-cleanup':'import os,signal,time;\np=os.fork();\nif p==0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)\nelse:os._exit(0)',
    }
    def spawn(argv,**kwargs):
        seen.append(tuple(argv));assert kwargs['start_new_session'] and kwargs['umask']==0o077
        assert kwargs['stdin']==subprocess.DEVNULL and kwargs['stderr']==subprocess.PIPE
        assert kwargs['env']=={'PATH':'/usr/bin:/bin','LANG':'C','LC_ALL':'C','HOME':kwargs['cwd'],'XDG_CONFIG_HOME':kwargs['cwd'],'XDG_CACHE_HOME':kwargs['cwd'],'HISTFILE':'/dev/null'}
        result=native_popen([sys.executable,'-I','-B','-c',scripts.get(case,'pass')],**kwargs)
        started.append(result)
        if case in ('short-tail','tail-overflow'):
            os.waitid(os.P_PID,result.pid,os.WEXITED|os.WNOWAIT)
        return result
    m.subprocess.Popen=spawn
    if case in ('short-tail','tail-overflow'):
        native_read=os.read
        def short_read(fd,size):return native_read(fd,min(size,1))
        m.os.read=short_read
        if case=='tail-overflow':owner._owner._limits=m._Limits(.2,100)

    if case=='anchor':
        def lost_anchor(*args):raise ChildProcessError()
        m.os.waitid=lost_anchor
    if case=='interrupt':
        original_select=m.select.select
        def interrupted(*args):m.select.select=original_select;raise KeyboardInterrupt()
        m.select.select=interrupted
    if case=='unsettled':
        m._CLEANUP_SECONDS=.15;m._TERM_SECONDS=10
        def no_group(pid,sig):events.append(('group',sig))
        os.killpg=no_group
    with tempfile.TemporaryDirectory() as temporary:
        result=None;error=None
        try:
            try:
                if case in ('streams','profile','short-tail'):
                    owner=m._Owner(m._Limits(5,4*1024**2))
                    result=owner._run(('/usr/bin/semodule','--store-path','/var/lib/selinux','-s','targeted','-lfull'),temporary)
                elif case in ('remaining','lease-cleanup'):
                    if case=='lease-cleanup':m._TERM_SECONDS=.25
                    owner=m._Owner(m._Limits(5,1024**2));start=time.monotonic()
                    try:owner._run(('/usr/bin/semodule','--store-path','/var/lib/selinux','-s','targeted','-lfull'),temporary,deadline=start+.15)
                    except m._CommandError as exc:assert str(exc)=='COMMAND_TIMEOUT'
                    else:raise AssertionError('remaining lease ignored')
                    assert time.monotonic()-start<1.5
                elif case=='expired':
                    try:owner._run('list',temporary,deadline=time.monotonic()-1)
                    except m._CommandError as exc:assert str(exc)=='COMMAND_TIMEOUT'
                    else:raise AssertionError('expired lease launched')
                    assert seen==[]
                    result=b''
                elif case=='binding':
                    try:owner._run('arbitrary',temporary)
                    except m._CommandError as exc:assert str(exc)=='COMMAND_KIND'
                    else:raise AssertionError('arbitrary operation admitted')
                    assert seen==[]
                    for operation in ('list','extract','list','extract'):owner._run(operation,temporary)
                    try:owner._run('list',temporary)
                    except m._CommandError as exc:assert str(exc)=='COMMAND_BUDGET'
                    else:raise AssertionError('fifth command admitted')
                else:result=owner._run('extract' if case=='extract-output' else 'list',temporary)
            except (m._CommandError,KeyboardInterrupt) as exc:error=exc
            if case=='short-tail':assert result.stdout==b'abcdefghij'*20 and result.stderr==b'tail'*25 and error is None
            elif case=='tail-overflow':assert isinstance(error,m._CommandError) and str(error)=='OUTPUT_LIMIT'
            elif case=='normal':assert result==b'raw\xff\x00' and error is None
            elif case=='streams':assert result.stdout==b'out\xff' and result.stderr==b'err\x00' and error is None
            elif case=='profile':assert result.stdout==b'x'*(2*1024**2) and result.stderr==b'' and error is None
            elif case=='stderr-finite':assert isinstance(error,m._CommandError) and str(error)=='COMMAND_STDERR'
            elif case in ('pipe','detached','binding','expired','remaining','lease-cleanup'):assert error is None
            elif case=='anchor':assert isinstance(error,m._CommandError) and str(error)=='COMMAND_CUSTODY'
            elif case=='extract-output':assert isinstance(error,m._CommandError) and str(error)=='COMMAND_OUTPUT'
            elif case in ('interrupt','cleanup-interrupt'):assert isinstance(error,KeyboardInterrupt)
            elif case=='unsettled':
                assert isinstance(error,m._CommandError) and str(error)=='COMMAND_UNSETTLED'
                assert not owner._last.settled and owner._last.unreaped
                assert started[0].poll() is None
            else:
                expected={'nonzero':'TOOL_FAILURE','timeout':'COMMAND_TIMEOUT','stdout':'OUTPUT_LIMIT','stderr':'OUTPUT_LIMIT','combined':'OUTPUT_LIMIT'}[case]
                assert isinstance(error,m._CommandError) and str(error)==expected,(case,error)
            prefix=('/usr/bin/semodule','--store-path','/var/lib/selinux','-s','targeted')
            listing=prefix+('-lfull',);extract=prefix+('-X','400','--hll','-E','qshd')
            assert seen==([] if case=='expired' else [listing,extract,listing,extract] if case=='binding' else [extract] if case=='extract-output' else [listing])
            if case in ('anchor','expired'):assert not any(event[0]=='group' for event in events),events
            else:assert events[0]==('group',signal.SIGTERM) and sum(event[0]=='group' for event in events)==(4 if case=='binding' else 1),events
            if case!='expired':assert len(owner._last.stdout)+len(owner._last.stderr)<=(4*1024**2 if case=='profile' else 1024**2)
            if case not in ('unsettled','expired'):assert owner._last.settled and m._children()==[]
        finally:
            m.subprocess.Popen=native_popen;os.killpg=original_group;subprocess.Popen.poll=original_poll
            for proc in started:
                if proc.poll() is None:proc.kill()
                proc.wait(timeout=3)
            # Failure paths also settle this harness's own adopted children.
            end=time.monotonic()+3
            while m._children():
                for pid in m._children():
                    try:os.kill(pid,signal.SIGKILL)
                    except ProcessLookupError:pass
                while True:
                    try:pid,_=os.waitpid(-1,os.WNOHANG)
                    except ChildProcessError:break
                    if not pid:break
                assert time.monotonic()<end,'test cleanup did not settle'
                time.sleep(.01)
    assert m._children()==[]
print(json.dumps({'passed':True,'case':case}))
'''


class ProcessTests(unittest.TestCase):
    def control(self, case):
        result = subprocess.run([sys.executable, '-I', '-B', '-c', HARNESS, str(SOURCE), case],
                                capture_output=True, text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('"passed": true', result.stdout)

    def test_resource_thread_and_prior_child_preconditions(self): self.control('preconditions')
    def test_exact_fixed_list_raw_output_and_environment(self): self.control('normal')
    def test_fixed_extract_and_four_call_budget(self): self.control('binding')
    def test_extract_diagnostics_refuse(self): self.control('extract-output')
    def test_unprovable_leader_anchor_never_signals_group(self): self.control('anchor')
    def test_separate_binary_streams(self): self.control('streams')
    def test_fixed_rpm_profile_allows_two_megabytes(self): self.control('profile')
    def test_combined_stream_cap(self): self.control('combined')
    def test_valid_looking_stderr_is_never_merged(self): self.control('stderr-finite')
    def test_expired_lease_never_launches(self): self.control('expired')
    def test_short_reads_preserve_completed_child_tail(self): self.control('short-tail')
    def test_completed_child_trailing_overflow_refuses(self): self.control('tail-overflow')
    def test_cleanup_after_lease_cannot_succeed(self): self.control('lease-cleanup')
    def test_remaining_lease_shortens_profile_deadline(self): self.control('remaining')
    def test_nonzero_exit_refuses(self): self.control('nonzero')
    def test_deadline_reaps_term_resistant_child(self): self.control('timeout')
    def test_stdout_overflow_settles(self): self.control('stdout')
    def test_stderr_overflow_settles(self): self.control('stderr')
    def test_exited_leader_pipe_retainer_settles(self): self.control('pipe')
    def test_detached_term_resistant_descendant_settles(self): self.control('detached')
    def test_cleanup_interruption_still_settles_before_propagating(self): self.control('cleanup-interrupt')
    def test_interruption_reaps_and_propagates(self): self.control('interrupt')
    def test_unresolved_custody_is_finite_and_never_success(self): self.control('unsettled')


if __name__ == '__main__': unittest.main()
