"""Internal owned-child mechanics for fixed trusted SELinux observers.

Not a CLI or public command runner. A fresh, single-threaded verifier owns all
children; its caller imposes the complete verifier's external hard deadline.
No resources or subreaper state change merely by importing this module.
"""
import ctypes
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


@dataclass(frozen=True)
class _Limits:
    execution_seconds: float
    output_bytes: int

    def __post_init__(self):
        if (type(self.execution_seconds) not in (int, float)
                or not math.isfinite(self.execution_seconds)
                or not (0 < self.execution_seconds <= 15 or
                        (self.execution_seconds == 60 and self.output_bytes == 4096) or
                        (self.execution_seconds == 75 and self.output_bytes == 1024 * 1024))
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
    unreaped: tuple[int, ...] = ()


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
        if deadline is not None and (type(deadline) not in (int, float) or not math.isfinite(deadline)):
            raise _CommandError('COMMAND_INPUT')
        lease_deadline = deadline
        now = time.monotonic()
        deadline = min(now + self._limits.execution_seconds, deadline) if deadline is not None else now + self._limits.execution_seconds
        if deadline <= now:
            self._last = _Outcome(b'', b'', None, 'COMMAND_TIMEOUT', True)
            raise _CommandError('COMMAND_TIMEOUT')
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

        def custody_error(error):
            nonlocal failure, pending
            failure = failure or 'COMMAND_CUSTODY'
            if not isinstance(error, (OSError, ValueError)):
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
                if failure or ended is not None:
                    break
                select.select([pipes[index] for index in readable], [], [], min(.02, max(0, deadline-time.monotonic())))
        except BaseException as error:
            failure = 'TOOL_FAILURE'
            if not isinstance(error, OSError):
                pending = error
        finally:
            if proc is not None:
                # Verify the child is still waitable immediately before using
                # its group ID. Failed ownership proof never permits killpg.
                try:
                    os.waitid(os.P_PID, proc.pid,
                              os.WEXITED | os.WNOHANG | os.WNOWAIT)
                except BaseException as error:
                    failure = 'COMMAND_CUSTODY'
                    custody_error(error)
                else:
                    # Exactly one group signal, before any poll/wait reaps it.
                    try:
                        os.killpg(proc.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    except BaseException as error:
                        custody_error(error)
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
                            try:
                                os.kill(pid, signal.SIGTERM)
                            except ProcessLookupError:
                                pass
                            except BaseException as error:
                                custody_error(error)
                            term.add(pid)
                        if time.monotonic() - start >= _TERM_SECONDS and pid not in killed:
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
                                              tuple(ids) if ids is not None else (proc.pid,))
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
            if not self._unsettled:
                if lease_deadline is not None and time.monotonic() >= lease_deadline and failure is None:
                    failure = 'COMMAND_TIMEOUT'
                self._last = _Outcome(*captured(), None if proc is None else proc.returncode,
                                      'OUTPUT_LIMIT' if overflow else failure, True)
        if self._unsettled:
            raise _CommandError('COMMAND_UNSETTLED') from None
        if pending is not None:
            raise pending
        if self._last.failure or self._last.exit_code != 0:
            raise _CommandError(self._last.failure or 'TOOL_FAILURE') from None
        return _Streams(self._last.stdout, self._last.stderr)
