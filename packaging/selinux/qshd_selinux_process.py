"""Internal owned-child mechanics for fixed trusted SELinux observers.

Not a CLI or public command runner. A fresh, single-threaded verifier owns all
children; its caller imposes the complete verifier's external hard deadline.
No resources or subreaper state change merely by importing this module.
"""
import ctypes
import errno
from dataclasses import dataclass
import math
import os
from pathlib import Path
import resource
import select
import signal
import subprocess
import time


_TERM_SECONDS = 1
_CLEANUP_SECONDS = 10


class _CommandError(RuntimeError):
    """Fixed bounded refusal; raw command output never enters its message."""
    def __init__(self, code, *, summary=None, _outcome=None):
        super().__init__(code)
        self._summary=summary
        self._launch_code=_launch_code(_outcome)

    @property
    def summary(self):return self._summary

    @property
    def launch_code(self):return self._launch_code



def _finite_number(value):
    try:return type(value) in (int,float) and math.isfinite(value)
    except OverflowError:return False


@dataclass(frozen=True)
class _Limits:
    execution_seconds: float
    output_bytes: int

    def __post_init__(self):
        if (not _finite_number(self.execution_seconds)
                or not (0 < self.execution_seconds <= 15 or
                        (self.execution_seconds == 30 and self.output_bytes == 4096) or
                        (self.execution_seconds == 60 and self.output_bytes == 4096) or
                        (self.execution_seconds == 75 and self.output_bytes == 1024 * 1024) or
                        (self.execution_seconds == 250 and self.output_bytes == 4096) or
                        (self.execution_seconds == 120 and self.output_bytes == 4096) or
                        (self.execution_seconds == 440 and self.output_bytes == 4096))
                or type(self.output_bytes) is not int
                or not 0 < self.output_bytes <= 4 * 1024 * 1024):
            raise _CommandError('COMMAND_LIMITS')


@dataclass(frozen=True)
class _Streams:
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True)
class _Outcome:
    stdout: bytes
    stderr: bytes
    exit_code: int | None
    failure: str | None
    settled: bool
    # None means census unknown; () means observed empty.
    unreaped: tuple[int, ...] | None = ()
    launch_code: str | None = None
    natural: bool = False
    stdout_eof: bool = False
    stderr_eof: bool = False
    group_term_attempts: int = 0
    adopted_term_attempts: int = 0
    kill_attempts: int = 0


_ERRNO_CODES={getattr(errno,name):'OS_'+name for name in ('EMFILE','ENFILE','ENOMEM','EFBIG','ENOSPC','EACCES','EPERM')}


def _launch_code(outcome):
    if (type(outcome) is _Outcome and type(outcome.failure) is str and outcome.failure=='TOOL_FAILURE'
            and outcome.exit_code is None and type(outcome.launch_code) is str
            and outcome.launch_code in _ERRNO_CODES.values()):return outcome.launch_code
    return None


_FAILURES=frozenset(('COMMAND_TIMEOUT','OUTPUT_LIMIT','COMMAND_CUSTODY','TOOL_FAILURE','COMMAND_UNSETTLED','OUTPUT_INCOMPLETE'))
_PROFILES={(5,16384):'guard5',(5,4*1024**2):'rpm5',(15,4*1024**2):'rpm15',
           (15,1024**2):'module15',(75,1024**2):'module75',(30,4096):'capsule30',
           (60,4096):'observer60',(250,4096):'phase250',(120,4096):'pair-observer120',
           (440,4096):'pair-phase440'}


@dataclass(frozen=True)
class _FailureSummary:
    profile: str
    failure: str | None
    exit_code: int | None
    settled: bool
    unreaped: int

    def __post_init__(self):
        if (type(self.profile) is not str or self.profile not in frozenset(_PROFILES.values())|{'OTHER'}
                or self.failure is not None and (type(self.failure) is not str or self.failure not in _FAILURES)
                or self.exit_code is not None and (type(self.exit_code) is not int or not -255<=self.exit_code<=255)
                or type(self.settled) is not bool or type(self.unreaped) is not int or not 0<=self.unreaped<=64):
            raise ValueError('COMMAND_SUMMARY')


def _failure_summary(outcome,limits):
    if type(outcome) is not _Outcome or type(limits) is not _Limits:return None
    if (type(outcome.stdout) is not bytes or type(outcome.stderr) is not bytes
            or type(outcome.unreaped) is not tuple):return None
    try:
        return _FailureSummary(_PROFILES.get((limits.execution_seconds,limits.output_bytes),'OTHER'),
            outcome.failure,outcome.exit_code,outcome.settled,len(outcome.unreaped))
    except ValueError:return None


def _children():
    return [int(value) for value in Path(
        f'/proc/self/task/{os.getpid()}/children').read_text().split()]


def _preconditions():
    if len(list(Path('/proc/self/task').iterdir())) != 1:
        raise _CommandError('PROCESS_THREADS')
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        # Auto-reaping or a competing handler would destroy the leader anchor.
        raise _CommandError('PROCESS_SIGNALS')
    if _children():
        raise _CommandError('PROCESS_CHILDREN')
    if resource.getrlimit(resource.RLIMIT_CORE) != (0, 0):
        raise _CommandError('PROCESS_LIMITS')
    for key in (resource.RLIMIT_FSIZE, resource.RLIMIT_CPU, resource.RLIMIT_AS):
        soft, hard = resource.getrlimit(key)
        if not 0 < soft <= hard or hard == resource.RLIM_INFINITY:
            raise _CommandError('PROCESS_LIMITS')
        if key == resource.RLIMIT_FSIZE and hard > 16 * 1024 * 1024:
            raise _CommandError('PROCESS_LIMITS')


def _subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    function = libc.prctl
    function.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
                         ctypes.c_ulong, ctypes.c_ulong]
    function.restype = ctypes.c_int
    if function(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        raise _CommandError('PROCESS_SUBREAPER')


def _reap_adopted():
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return []
        if pid == 0:
            return _children()


def _natural_terminal(pid):
    """Before signals/reap: terminal reserved leader is the only possible child.

    Exactly one caller task, enabled subreaper, full child census and WNOWAIT
    retain the leader's identity. Repeated proof immediately precedes skipping
    rescue; terminal leader plus no other producer cannot fork a future child.
    """
    tasks=tuple(Path('/proc/self/task').iterdir())
    if len(tasks)!=1 or tasks[0].name!=str(os.getpid()):raise _CommandError('COMMAND_CUSTODY')
    libc=ctypes.CDLL(None,use_errno=True);get=libc.prctl
    get.argtypes=[ctypes.c_int,ctypes.c_void_p,ctypes.c_ulong,ctypes.c_ulong,ctypes.c_ulong];get.restype=ctypes.c_int
    value=ctypes.c_int()
    if get(37,ctypes.byref(value),0,0,0)!=0 or value.value!=1:raise _CommandError('COMMAND_CUSTODY')
    children=[]
    for task in tasks:children.extend(int(x) for x in (task/'children').read_text().split())
    if children!=[pid]:raise _CommandError('COMMAND_CUSTODY')
    status=os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
    if status is None or status.si_pid!=pid or status.si_code!=os.CLD_EXITED:raise _CommandError('COMMAND_CUSTODY')
    return status


def _normal_outcome(outcome):
    return (type(outcome) is _Outcome and outcome.natural is True
            and outcome.stdout_eof is True and outcome.stderr_eof is True
            and all(type(x) is int and x==0 for x in (outcome.group_term_attempts,outcome.adopted_term_attempts,outcome.kill_attempts))
            and outcome.settled is True and type(outcome.unreaped) is tuple and not outcome.unreaped
            and outcome.failure is None and type(outcome.exit_code) is int
            and type(outcome.stdout) is bytes and type(outcome.stderr) is bytes)


class _Owner:
    """Internal mechanism; only trusted consumers construct fixed argument tuples."""

    def __init__(self, limits):
        if type(limits) is not _Limits:
            raise _CommandError('COMMAND_LIMITS')
        self._limits = limits
        _preconditions()
        _subreaper()
        self._pid = os.getpid()
        self._last = None
        self._unsettled = False

    def _run(self, argv, cwd, *, deadline=None):
        if self._pid != os.getpid() or self._unsettled:
            raise _CommandError('PROCESS_OWNER')
        _preconditions()
        cwd = str(cwd)
        if (type(argv) is not tuple or not argv or
                any(type(arg) is not str or '\0' in arg for arg in argv)
                or not Path(cwd).is_absolute() or '\0' in cwd):
            raise _CommandError('COMMAND_INPUT')
        if deadline is not None and (not _finite_number(deadline)):
            raise _CommandError('COMMAND_INPUT')
        lease_deadline = deadline
        now = time.monotonic()
        deadline = min(now + self._limits.execution_seconds, deadline) if deadline is not None else now + self._limits.execution_seconds
        if deadline <= now:
            self._last = _Outcome(b'', b'', None, 'COMMAND_TIMEOUT', True)
            raise _CommandError('COMMAND_TIMEOUT',summary=_failure_summary(self._last,self._limits))
        env = {'PATH': '/usr/bin:/bin', 'LANG': 'C', 'LC_ALL': 'C',
               'HOME': cwd, 'XDG_CONFIG_HOME': cwd, 'XDG_CACHE_HOME': cwd,
               'HISTFILE': '/dev/null'}
        proc = None
        output = [bytearray(), bytearray()]
        pipes = ()
        readable = set()
        overflow = False
        nonblocking = False
        failure = None
        pending = None
        launch_code = None
        natural = False
        group_term_attempts = adopted_term_attempts = kill_attempts = 0

        def custody_error(error):
            nonlocal failure, pending
            failure = failure or 'COMMAND_CUSTODY'
            if not isinstance(error,(OSError,ValueError,_CommandError)):
                pending = pending or error

        def captured():
            return bytes(output[0]), bytes(output[1])

        def drain():
            nonlocal overflow
            for index, pipe in enumerate(pipes):
                if index not in readable:
                    continue
                for _ in range(16):
                    try:
                        data = os.read(pipe.fileno(), 4096)
                    except BlockingIOError:
                        break
                    if not data:
                        readable.remove(index)
                        break
                    room = self._limits.output_bytes - sum(map(len, output))
                    output[index].extend(data[:room])
                    overflow |= len(data) > room

        try:
            proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    start_new_session=True, umask=0o077)
            pipes = (proc.stdout, proc.stderr)
            for pipe in pipes:
                os.set_blocking(pipe.fileno(), False)
            readable = {0, 1}
            nonblocking = True
            while True:
                drain()
                # The unreaped leader anchors the numeric process-group identity.
                ended = os.waitid(os.P_PID, proc.pid,
                                  os.WEXITED | os.WNOHANG | os.WNOWAIT)
                if overflow:
                    failure = 'OUTPUT_LIMIT'
                elif time.monotonic() >= deadline:
                    failure = 'COMMAND_TIMEOUT'
                if failure:break
                if ended is not None:
                    try:
                        # A terminal leader with a descendant is already not
                        # natural completion, even if rescue later drains EOF.
                        _natural_terminal(proc.pid)
                    except BaseException as error:
                        custody_error(error);break
                    if not readable:
                        natural=True;break
                select.select([pipes[index] for index in readable], [], [], min(.02, max(0, deadline-time.monotonic())))
        except BaseException as error:
            if proc is None and type(error) in (OSError,PermissionError):
                number=OSError.errno.__get__(error)
                if type(number) is int:launch_code=_ERRNO_CODES.get(number)
            failure = 'TOOL_FAILURE'
            if not isinstance(error, OSError):
                pending = error
        finally:
            if proc is not None:
                # Recheck the certificate at the last pre-signal point.
                if natural and failure is None and pending is None and not overflow and time.monotonic()<deadline:
                    try:_natural_terminal(proc.pid)
                    except BaseException as error:natural=False;custody_error(error)
                else:natural=False
                if not natural:
                    # Rescue is physical cleanup only, never successful work.
                    try:os.waitid(os.P_PID,proc.pid,os.WEXITED|os.WNOHANG|os.WNOWAIT)
                    except BaseException as error:
                        failure='COMMAND_CUSTODY';custody_error(error)
                    else:
                        group_term_attempts+=1
                        try:os.killpg(proc.pid,signal.SIGTERM)
                        except ProcessLookupError:pass
                        except BaseException as error:custody_error(error)
                if not nonblocking:
                    for pipe in pipes:
                        try:
                            pipe.close()
                        except BaseException as error:
                            custody_error(error)
                start = time.monotonic()
                term, killed = set(), set()
                ids = None
                while True:
                    if nonblocking:
                        try:
                            drain()
                        except BaseException as error:
                            custody_error(error)
                    try:
                        if proc.returncode is None:
                            proc.poll()
                        ids = _reap_adopted() if proc.returncode is not None else _children()
                    except BaseException as error:
                        ids = None  # Unknown never establishes settlement.
                        custody_error(error)
                    for pid in ids or ():
                        # These direct/adopted children remain unreaped while signalled.
                        if pid != proc.pid and pid not in term:
                            adopted_term_attempts+=1
                            try:
                                os.kill(pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                            except BaseException as error:
                                custody_error(error)
                            term.add(pid)
                        if time.monotonic() - start >= _TERM_SECONDS and pid not in killed:
                            kill_attempts+=1
                            try:
                                os.kill(pid, signal.SIGKILL)
                            except ProcessLookupError:
                                pass
                            except BaseException as error:
                                custody_error(error)
                            killed.add(pid)
                    if proc.returncode is not None and ids == []:
                        # Reaping establishes custody settlement, not pipe EOF.
                        # Keep bounded drain turns until every retained tail is read.
                        if not readable:
                            break
                        if time.monotonic() - start >= _CLEANUP_SECONDS:
                            failure = failure or 'OUTPUT_INCOMPLETE'
                            break
                    if time.monotonic() - start >= _CLEANUP_SECONDS:
                        self._unsettled = True
                        self._last = _Outcome(*captured(), proc.returncode,
                                              'COMMAND_UNSETTLED', False,
                                              tuple(ids) if ids is not None else (proc.pid,),
                                              natural=False,stdout_eof=0 not in readable,stderr_eof=1 not in readable,
                                              group_term_attempts=group_term_attempts,adopted_term_attempts=adopted_term_attempts,kill_attempts=kill_attempts)
                        break
                    try:
                        time.sleep(.01)
                    except BaseException as error:
                        custody_error(error)
                for pipe in pipes:
                    try:
                        pipe.close()
                    except BaseException as error:
                        custody_error(error)
            else:
                # A launcher can raise before returning its Popen custody.
                # Only a fresh post-exception census can establish emptiness.
                try:
                    ids = _children()
                except BaseException:
                    ids = None
                if ids != []:
                    self._unsettled = True
                    self._last = _Outcome(*captured(), None, 'COMMAND_UNSETTLED',
                                          False, tuple(ids) if ids is not None else None)
            if not self._unsettled:
                if lease_deadline is not None and time.monotonic() >= lease_deadline and failure is None:
                    failure = 'COMMAND_TIMEOUT'
                if (group_term_attempts or adopted_term_attempts or kill_attempts) and failure is None:
                    failure='COMMAND_CUSTODY'
                natural=bool(natural and failure is None and pending is None and not readable)
                self._last = _Outcome(*captured(),None if proc is None else proc.returncode,
                                      'OUTPUT_LIMIT' if overflow else failure,True,launch_code=launch_code,
                                      natural=natural,stdout_eof=0 not in readable,stderr_eof=1 not in readable,
                                      group_term_attempts=group_term_attempts,adopted_term_attempts=adopted_term_attempts,kill_attempts=kill_attempts)
        if self._unsettled:
            raise _CommandError('COMMAND_UNSETTLED',summary=_failure_summary(self._last,self._limits)) from None
        if pending is not None:
            raise pending
        if self._last.failure or self._last.exit_code != 0:
            raise _CommandError(self._last.failure or 'TOOL_FAILURE',summary=_failure_summary(self._last,self._limits),
                                _outcome=self._last) from None
        return _Streams(self._last.stdout, self._last.stderr)
