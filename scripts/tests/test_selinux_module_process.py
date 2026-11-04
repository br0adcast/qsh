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
if case=='observer-profile':
    assert m._Limits(60,4096).execution_seconds==60
    assert m._Limits(30,4096).execution_seconds==30
    assert m._Limits(75,1024**2).execution_seconds==75
    assert m._Limits(250,4096).execution_seconds==250
    assert m._Limits(120,4096).execution_seconds==120
    assert m._Limits(440,4096).execution_seconds==440
    assert m._Limits(15,4*1024**2).execution_seconds==15
    for pair in ((16,4096),(29,4096),(31,4096),(30,4095),(30,4097),(59,4096),(60,4097),(60,1024**2),(249,4096),(251,4096),(250,4095),(250,4097),(260,4096),(119,4096),(121,4096),(120,8192),(439,4096),(441,4096),(440,4095)):
        try:m._Limits(*pair)
        except m._CommandError:pass
        else:raise AssertionError('unapproved observer profile')
elif case=='natural-orphan':
    owner=m._Owner(m._Limits(2,4096));m._TERM_SECONDS=.1
    source='import os,signal,time; p=os.fork();\nif p==0:\n signal.signal(signal.SIGTERM,signal.SIG_IGN);time.sleep(30)\nelse:os._exit(0)'
    with tempfile.TemporaryDirectory() as directory:
        try:owner._run((sys.executable,'-I','-B','-c',source),directory)
        except m._CommandError:pass
        else:raise AssertionError('rescued orphan was accepted as natural success')
    assert owner._last.settled and not owner._last.unreaped and not m._children()
    assert owner._last.natural is False
    assert owner._last.group_term_attempts>0 or owner._last.adopted_term_attempts>0
elif case=='launch-error':
    import errno
    owner=m._Owner(m._Limits(15,1024**2))
    def refuse(*args,**kwargs):raise OSError(errno.EMFILE,'PRIVATE_MESSAGE','/private/canary')
    m.subprocess.Popen=refuse
    try:
        with tempfile.TemporaryDirectory() as directory:
            try:owner._run(('/trusted/tool',),directory)
            except m._CommandError as error:
                assert getattr(error,'launch_code',None)=='OS_EMFILE','launch errno category lost'
                assert owner._last.launch_code=='OS_EMFILE'
                assert error.summary.failure=='TOOL_FAILURE' and error.summary.exit_code is None
                assert error.summary.settled and error.summary.unreaped==0
                try:error.launch_code='PRIVATE'
                except AttributeError:pass
                else:raise AssertionError('launch code property writable')
                assert 'PRIVATE' not in str(error) and '/private' not in repr(error.__dict__)
            else:raise AssertionError('launch refusal accepted')
    finally:m.subprocess.Popen=native_popen
    assert m._children()==[]
elif case=='launch-matrix':
    import errno
    class Custom(OSError):
        @property
        def errno(self):raise AssertionError('custom errno inspected')
    cases=[(OSError(getattr(errno,name),'PRIVATE','/private'), 'OS_'+name)
           for name in ('EMFILE','ENFILE','ENOMEM','EFBIG','ENOSPC','EACCES','EPERM')]
    cases += [(OSError(999,'PRIVATE'),None),(Custom(errno.EMFILE,'PRIVATE'),None),
              (OSError(True,'PRIVATE'),None),(OSError('24','PRIVATE'),None)]
    owner=m._Owner(m._Limits(15,1024**2))
    native_children=m._children;post_censuses=[];launch_refused=[False]
    def census():
        result=native_children()
        if launch_refused[0]:post_censuses.append(tuple(result))
        return result
    m._children=census
    with tempfile.TemporaryDirectory() as directory:
        for fault,expected in cases:
            launch_refused[0]=False
            before_censuses=len(post_censuses)
            def refuse(*args,**kwargs):
                launch_refused[0]=True
                raise fault
            m.subprocess.Popen=refuse
            try:owner._run(('/trusted/tool',),directory)
            except m._CommandError as error:
                assert error.launch_code==expected and owner._last.launch_code==expected
                assert error.summary.failure=='TOOL_FAILURE' and error.summary.exit_code is None
                assert error.summary.settled and not error.summary.unreaped
                assert '/private' not in repr(error.__dict__)
                assert post_censuses[before_censuses:]==[()], 'missing fresh empty census'
            else:raise AssertionError('launch error accepted')
        launch_refused[0]=False
        m._children=native_children
        m.subprocess.Popen=native_popen
        assert owner._run((sys.executable,'-I','-B','-c','pass'),directory).stdout==b''
        assert owner._last.launch_code is None
        try:owner._run((sys.executable,'-I','-B','-c','raise SystemExit(7)'),directory)
        except m._CommandError as error:
            assert error.launch_code is None and error.summary.exit_code==7
        else:raise AssertionError('nonzero accepted')
        # A post-acquisition read failure must not masquerade as launch errno.
        original_read=os.read
        def post_read(*args):
            os.read=original_read
            raise OSError(errno.EMFILE,'PRIVATE')
        def acquired(*args,**kwargs):
            proc=native_popen(*args,**kwargs);os.read=post_read;return proc
        m.subprocess.Popen=acquired
        try:
            try:owner._run((sys.executable,'-I','-B','-c','pass'),directory)
            except m._CommandError as error:
                assert error.launch_code is None and owner._last.launch_code is None
            else:raise AssertionError('post-spawn error accepted')
        finally:os.read=original_read;m.subprocess.Popen=native_popen
    assert m._children()==[]
elif case=='launch-empty-pending':
    owner=m._Owner(m._Limits(15,1024**2))
    original_children=m._children;events=[]
    def census():
        ids=original_children();events.append('census');return ids
    def refuse(*args,**kwargs):
        events.append('launch');raise RuntimeError('PRIVATE_PENDING')
    m._children=census;m.subprocess.Popen=refuse
    try:
        with tempfile.TemporaryDirectory() as directory:
            try:owner._run(('/trusted/tool',),directory)
            except RuntimeError as error:
                assert type(error) is RuntimeError
                assert owner._last.settled and owner._last.unreaped==()
                assert owner._last.failure=='TOOL_FAILURE' and owner._last.exit_code is None
                assert not owner._unsettled
            else:raise AssertionError('pending original exception lost')
        assert events==['census','launch','census']
    finally:m._children=original_children;m.subprocess.Popen=native_popen
    assert m._children()==[]
elif case.startswith('launch-child-'):
    import errno
    owner=m._Owner(m._Limits(15,1024**2))
    native_children=m._children
    native_calls={name:getattr(os,name) for name in ('kill','killpg','waitpid','waitid')}
    held=[];attempts=[];post_censuses=[];product_calls=[];scratch=[]
    entry_fds=set(os.listdir('/proc/self/fd'))
    unknown=case in ('launch-child-unknown','launch-child-consumer-unknown')
    consumer=case.startswith('launch-child-consumer')
    def census():
        if held:
            post_censuses.append(True)
            if unknown:raise OSError(errno.EACCES,'PRIVATE_CENSUS')
        return native_children()
    def forbidden(name):
        def call(*args,**kwargs):
            product_calls.append(name)
            raise AssertionError('no-Popen path attempted signal or reap')
        return call
    def launched_then_failed(argv,**kwargs):
        attempts.append(True)
        child=native_popen([sys.executable,'-I','-B','-c',
            'import os;os.write(1,b"R");assert os.read(0,1)==b"X"'],
            **dict(kwargs,stdin=subprocess.PIPE))
        held.append(child)
        assert os.read(child.stdout.fileno(),1)==b'R'
        if consumer:
            directory=pathlib.Path(kwargs['cwd']);pp=directory/'qshd.pp'
            scratch.append((directory,[(name,(directory/name).read_bytes(),(directory/name).stat()) for name in ('qshd.pp','qshd_contexts.pp')],directory.stat()))
        for name in native_calls:setattr(os,name,forbidden(name))
        if case=='launch-child-pending':raise RuntimeError('PRIVATE_PENDING')
        raise OSError(errno.EMFILE,'PRIVATE_MESSAGE','/private/canary')
    m._children=census;m.subprocess.Popen=launched_then_failed
    fixture=None
    try:
        with tempfile.TemporaryDirectory() as directory:
            if consumer:
                sys.path.insert(0,str(path.parents[2]/'scripts/tests'))
                import test_selinux_module_install as fixtures
                fixture=fixtures.InstallTests();fixture.setUp()
                item=fixtures.m.FirstInstall(fixtures.TRUST,fixtures.PP,fixtures.CONTEXTS_PP,
                    _root=fixture.root,_uid=os.getuid(),_owner=owner)
                try:item.install(deadline=time.monotonic()+440)
                except fixtures.m.InstallError:pass
                else:raise AssertionError('unsettled install accepted')
                assert item._uncertain,'actual launcher outcome did not protect scratch'
                assert len(scratch)==1
                target,inputs,directory_metadata=scratch[0]
                assert target.is_dir()
                for name,data,metadata in inputs:
                    assert (target/name).read_bytes()==data
                    after=(target/name).stat()
                    assert (after.st_dev,after.st_ino,after.st_mode,after.st_size,after.st_mtime_ns,after.st_ctime_ns)==(metadata.st_dev,metadata.st_ino,metadata.st_mode,metadata.st_size,metadata.st_mtime_ns,metadata.st_ctime_ns)
                after_directory=target.stat()
                assert (after_directory.st_dev,after_directory.st_ino,after_directory.st_mode,after_directory.st_mtime_ns)==(directory_metadata.st_dev,directory_metadata.st_ino,directory_metadata.st_mode,directory_metadata.st_mtime_ns)
                assert not item._fds and not item.routes and not item.anchors,'consumer retained owned descriptors'
            else:
                try:owner._run(('/trusted/tool',),directory)
                except m._CommandError as error:
                    assert str(error)=='COMMAND_UNSETTLED','launcher child was reported safely settled'
                    assert error.launch_code is None
                    if unknown:
                        assert error.summary is None
                    else:
                        assert error.summary.unreaped==1 and not error.summary.settled
                        assert error.summary.failure=='COMMAND_UNSETTLED' and error.summary.exit_code is None
                    assert 'PRIVATE' not in repr(error.__dict__)
                else:raise AssertionError('launch exception accepted')
            assert owner._unsettled and not owner._last.settled
            assert owner._last.failure=='COMMAND_UNSETTLED' and owner._last.exit_code is None
            assert owner._last.unreaped is None if unknown else owner._last.unreaped==(held[0].pid,)
            assert len(post_censuses)==1,'missing fresh post-launch census'
            try:owner._run(('/trusted/tool',),directory)
            except m._CommandError as error:assert str(error)=='PROCESS_OWNER'
            else:raise AssertionError('poisoned owner reused')
            assert len(attempts)==1 and product_calls==[]
    finally:
        m.subprocess.Popen=native_popen;m._children=native_children
        for name,native in native_calls.items():setattr(os,name,native)
        for child in held:
            # Independent test custody, never a product-guessed PID/group.
            try:
                out,err=child.communicate(input=b'X',timeout=3)
                assert child.returncode==0 and out==b'' and err==b''
            finally:
                if child.poll() is None:child.kill()
                child.wait(timeout=3)
                for pipe in (child.stdin,child.stdout,child.stderr):
                    if pipe is not None:pipe.close()
        if fixture is not None:fixture.doCleanups()
    assert native_children()==[]
    assert set(os.listdir('/proc/self/fd'))==entry_fds,'test leaked descriptors'
elif case=='preconditions':
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
                    except m._CommandError as exc:assert str(exc) in ('COMMAND_TIMEOUT','COMMAND_CUSTODY')
                    else:raise AssertionError('remaining lease ignored')
                    assert time.monotonic()-start<1.5
                elif case=='expired':
                    try:owner._run('list',temporary,deadline=time.monotonic()-1)
                    except m._CommandError as exc:
                        assert str(exc)=='COMMAND_TIMEOUT'
                        assert exc.summary.profile=='OTHER'
                        assert exc.summary.failure=='COMMAND_TIMEOUT' and exc.summary.exit_code is None
                        assert exc.summary.settled and exc.summary.unreaped==0 and seen==[]
                        assert set(vars(exc.summary))=={'profile','failure','exit_code','settled','unreaped'}
                        assert not hasattr(exc.summary,'stdout') and not hasattr(exc.summary,'stderr')
                    else:raise AssertionError('expired lease launched')
                    assert seen==[]
                    result=b''
                elif case=='binding':
                    try:owner._run('arbitrary',temporary)
                    except m._CommandError as exc:assert str(exc)=='COMMAND_KIND'
                    else:raise AssertionError('arbitrary operation admitted')
                    assert seen==[]
                    for operation in ('list','extract-core','extract-contexts','list','extract-core','extract-contexts'):owner._run(operation,temporary)
                    try:owner._run('list',temporary)
                    except m._CommandError as exc:assert str(exc)=='COMMAND_BUDGET'
                    else:raise AssertionError('fifth command admitted')
                else:result=owner._run('extract-core' if case=='extract-output' else 'list',temporary)
            except (m._CommandError,KeyboardInterrupt) as exc:error=exc
            if case=='short-tail':assert result.stdout==b'abcdefghij'*20 and result.stderr==b'tail'*25 and error is None
            elif case=='tail-overflow':assert isinstance(error,m._CommandError) and str(error)=='OUTPUT_LIMIT'
            elif case=='normal':assert result==b'raw\xff\x00' and error is None
            elif case=='streams':assert result.stdout==b'out\xff' and result.stderr==b'err\x00' and error is None
            elif case=='profile':assert result.stdout==b'x'*(2*1024**2) and result.stderr==b'' and error is None
            elif case=='stderr-finite':assert isinstance(error,m._CommandError) and str(error)=='COMMAND_STDERR'
            elif case in ('pipe','detached'):assert isinstance(error,m._CommandError) and str(error)=='COMMAND_CUSTODY'
            elif case in ('binding','expired','remaining','lease-cleanup'):assert error is None
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
            listing=prefix+('-lfull',);extract=prefix+('-X','400','--hll','-E','qshd');contexts=prefix+('-X','400','--hll','-E','qshd_contexts')
            assert seen==([] if case=='expired' else [listing,extract,contexts,listing,extract,contexts] if case=='binding' else [extract] if case=='extract-output' else [listing])
            natural_cases=('normal','short-tail','streams','profile','binding','nonzero','stderr-finite','extract-output')
            if case in natural_cases or case in ('anchor','expired'):
                assert not any(event[0]=='group' for event in events),events
                if case in natural_cases:
                    assert owner._last.natural and owner._last.stdout_eof and owner._last.stderr_eof
                    assert owner._last.group_term_attempts==owner._last.adopted_term_attempts==owner._last.kill_attempts==0
            else:assert sum(event[0]=='group' for event in events)==1,events
            if case in ('expired','nonzero','timeout','interrupt','cleanup-interrupt','unsettled'):
                assert getattr(error,'launch_code',None) is None
                assert owner._last.launch_code is None
            if case=='nonzero':
                assert error.summary.exit_code==7 and error.summary.failure is None and error.summary.settled
                assert not hasattr(error.summary,'stdout') and not hasattr(error.summary,'stderr')
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

    def test_exit_zero_orphan_cannot_be_rescued_into_success(self): self.control('natural-orphan')

    def test_launch_error_preserves_only_closed_errno(self): self.control('launch-error')

    def test_launch_categories_types_and_later_calls_are_isolated(self): self.control('launch-matrix')

    def test_empty_post_launch_census_preserves_pending_original_exception(self): self.control('launch-empty-pending')

    def test_spawn_then_oserror_keeps_actual_child_custody(self): self.control('launch-child-oserror')

    def test_spawn_then_pending_exception_cannot_bypass_custody(self): self.control('launch-child-pending')

    def test_unknown_post_launch_census_poison_has_no_invented_children(self): self.control('launch-child-unknown')

    def test_exact_observer_profile_only(self): self.control('observer-profile')

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
