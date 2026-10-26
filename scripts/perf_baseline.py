#!/usr/bin/env python3
"""Owned PTY CPU, scheduling, traffic and latency baseline for qsh and qshd.

Linux only. Each run starts a private `qshd serve`, a private UDP relay and
`qsh` on its own pseudo-terminal, all with generated keys and isolated
HOME/XDG/shell startup state, then measures one workload. Every run is
retained as raw JSON next to a manifest recording the binaries' identity, the
host and the run order. `summarize` reads only those files.

This is a measurement procedure, not a test: it sets no thresholds and does
not belong in ordinary CI. See docs/performance-baseline.md.
"""

import argparse
import collections
import ctypes
import datetime
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import pwd
import random
import re
import select
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time


TOOL_VERSION = 4
WORKLOADS = ("idle", "typing", "redraw", "saturation", "reconnect", "retained", "busy")
CLOCK_TICKS = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
COLS, ROWS = 120, 40
SETTLE = 2.0
SETUP_TIMEOUT = 20.0
LOG_TAIL = 4096
# Timestamped terminal reads and client datagrams kept for latency lookups.
EVENT_HISTORY = 65536
# Rendered text may be interleaved with cursor and attribute sequences.
SCAN_OVERLAP = 4096
KEYS = b"qwertyuiop"
# The renderer ends every presented frame by setting cursor visibility.
FRAME_MARKERS = (b"\x1b[?25h", b"\x1b[?25l")
ESCAPE = re.compile(rb"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")
PR_SET_CHILD_SUBREAPER = 36
PARENT_ENVIRONMENT = ("PATH",)
RUNTIME_WORKERS = re.compile(r"runtime workers (\d+)")
# The system mode's diagnostic log, a fixed path (qshd's SYSTEM_LOG_DIR).
SYSTEM_LOG = Path("/var/log/qshd/qshd.log")
# Set only on a disposable machine, as for qshd's own system-mode suites.
DISPOSABLE_HOST_VAR = "QSHD_TEST_DISPOSABLE_HOST"

REDRAW_SCRIPT = """\
import sys, time
fps, seconds, cols, rows = (int(value) for value in sys.argv[1:5])
out = sys.stdout.buffer
for frame in range(fps * seconds):
    start = time.monotonic()
    lines = []
    for row in range(rows):
        text = f"{frame:06d} {row:03d} "
        lines.append((text * (cols // len(text) + 1))[:cols])
    out.write(b"\\x1b[H" + "\\r\\n".join(lines).encode())
    out.flush()
    time.sleep(max(0.0, 1.0 / fps - (time.monotonic() - start)))
"""


class SetupError(Exception):
    """The run could not be prepared or a process misbehaved."""


class Incomplete(SetupError):
    """The workload ran but did not produce every intended sample."""

    def __init__(self, message, result):
        super().__init__(message)
        self.result = result


class Interrupted(BaseException):
    """A termination signal; raised so every cleanup path still runs."""


def interrupt(signum, _frame):
    raise Interrupted(signal.Signals(signum).name)


def install_signal_handlers():
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, interrupt)


# --- /proc accounting -------------------------------------------------------

def parse_stat(text):
    """Fields of /proc/<pid>/stat after the parenthesised command name."""
    fields = text.rsplit(")", 1)[1].split()
    return {
        "ppid": int(fields[1]),
        "cpu_ticks": int(fields[11]) + int(fields[12]),
        "threads": int(fields[17]),
        "start_ticks": int(fields[19]),
    }


def status_fields(text):
    values = {}
    for line in text.splitlines():
        key, _, value = line.partition(":")
        if key in ("voluntary_ctxt_switches", "nonvoluntary_ctxt_switches", "VmHWM", "VmRSS"):
            values[key] = int(value.split()[0])
    return values


def parse_switches(text):
    values = status_fields(text)
    return values.get("voluntary_ctxt_switches", 0), values.get("nonvoluntary_ctxt_switches", 0)


def parse_schedstat(text):
    run_ns, wait_ns, timeslices = (int(value) for value in text.split()[:3])
    return run_ns, wait_ns, timeslices


def read(path):
    with open(path, encoding="ascii", errors="replace") as source:
        return source.read()


def sample_process(pid):
    """Process CPU (exited threads included) and per-live-thread counters."""
    stat = parse_stat(read(f"/proc/{pid}/stat"))
    memory = status_fields(read(f"/proc/{pid}/status"))
    threads = {}
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            run_ns, wait_ns, timeslices = parse_schedstat(read(f"/proc/{pid}/task/{tid}/schedstat"))
            voluntary, involuntary = parse_switches(read(f"/proc/{pid}/task/{tid}/status"))
        except (OSError, ValueError, IndexError):
            continue
        threads[tid] = (run_ns, wait_ns, timeslices, voluntary, involuntary)
    return {"cpu_ticks": stat["cpu_ticks"], "start_ticks": stat["start_ticks"], "threads": threads,
            "peak_rss_kib": memory.get("VmHWM"), "rss_kib": memory.get("VmRSS")}


def process_delta(before, after, seconds):
    """Window counters. Thread counters cover only threads alive throughout."""
    if before["start_ticks"] != after["start_ticks"]:
        raise SetupError("a measured process was replaced during the window")
    common = before["threads"].keys() & after["threads"].keys()
    sums = [0, 0, 0, 0, 0]
    for tid in common:
        for index in range(5):
            sums[index] += after["threads"][tid][index] - before["threads"][tid][index]
    cpu_s = (after["cpu_ticks"] - before["cpu_ticks"]) / CLOCK_TICKS
    return {
        "cpu_s": round(cpu_s, 3),
        "cpu_percent": round(100 * cpu_s / seconds, 3),
        "run_s_live_threads": round(sums[0] / 1e9, 4),
        "runqueue_wait_s_live_threads": round(sums[1] / 1e9, 4),
        "timeslices_per_s": round(sums[2] / seconds, 2),
        "voluntary_switches_per_s": round(sums[3] / seconds, 2),
        "involuntary_switches_per_s": round(sums[4] / seconds, 2),
        "threads_start": len(before["threads"]),
        "threads_end": len(after["threads"]),
        "threads_exited": len(before["threads"].keys() - after["threads"].keys()),
        "threads_created": len(after["threads"].keys() - before["threads"].keys()),
        # Peak resident memory since exec, read at the end of the window.
        "peak_rss_kib": after.get("peak_rss_kib"),
        "rss_kib": after.get("rss_kib"),
    }


# --- Builds and host identity ----------------------------------------------

def elf_identity(path):
    """Static/dynamic linkage, interpreter name and .comment strings."""
    data = Path(path).read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return {"elf": False}
    phoff, shoff = struct.unpack_from("<QQ", data, 0x20)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x36)
    interpreter = None
    for index in range(phnum):
        p_type, _, p_offset, _, _, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + index * phentsize)
        if p_type == 3:
            interpreter = data[p_offset:p_offset + p_filesz].rstrip(b"\0").decode(errors="replace")
    comments = []
    if shnum and shstrndx < shnum:
        def section(index):
            name, _, _, _, offset, size = struct.unpack_from("<IIQQQQ", data, shoff + index * shentsize)
            return name, offset, size
        _, names_offset, _ = section(shstrndx)
        for index in range(shnum):
            name, offset, size = section(index)
            end = data.index(b"\0", names_offset + name)
            if data[names_offset + name:end] == b".comment":
                comments = [item.decode(errors="replace") for item in data[offset:offset + size].split(b"\0") if item]
    return {
        "elf": True,
        "linkage": "dynamic" if interpreter else "static",
        "interpreter": os.path.basename(interpreter) if interpreter else None,
        "comment": sorted(set(comments)),
    }


def binary_identity(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return {
        "sha256": digest.hexdigest(),
        "bytes": os.path.getsize(path),
        "version": version_of(path),
        **elf_identity(path),
    }


def version_of(path):
    """First line of `path --version`, run on an owned pseudo-terminal."""
    with tempfile.TemporaryDirectory(prefix="qsh-perf-version-") as home:
        terminal = Terminal(COLS, ROWS)
        owned = None
        try:
            owned = Owned(spawn_on(terminal, [str(path), "--version"], minimal_environment(home), home))
            terminal.start()
            if not owned.wait(10):
                raise SetupError(f"{path.name} --version did not exit")
            # The read side ends once the last holder of the slave is gone.
            terminal.thread.join(5)
            text = ESCAPE.sub(b"", terminal.text_since(0)).decode("utf-8", "backslashreplace")
        finally:
            if owned:
                owned.stop()
            if not terminal.close():
                raise SetupError(f"the terminal reader of {path.name} --version did not stop")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if owned.status != 0:
        raise SetupError(f"{path.name} --version exited with {owned.status}: {lines[-1:]}")
    return lines[:1]


def host_identity():
    model = None
    try:
        for line in read("/proc/cpuinfo").splitlines():
            if line.startswith("model name"):
                model = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    governor = None
    try:
        governor = read("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor").strip()
    except OSError:
        pass
    uname = os.uname()
    return {
        "system": uname.sysname,
        "kernel": uname.release,
        "machine": uname.machine,
        "cpu_model": model,
        "online_cpus": os.cpu_count(),
        "scaling_governor": governor,
        "clock_ticks": CLOCK_TICKS,
        "python": sys.version.split()[0],
    }


def build_spec(text):
    name, separator, directory = text.partition("=")
    if not separator or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not directory:
        raise argparse.ArgumentTypeError(f"expected NAME=DIRECTORY, got {text!r}")
    return name, Path(directory)


def cpu_list(text):
    """A Linux CPU list such as `0`, `0-1` or `0,2-3`, as a sorted list."""
    cpus = set()
    for part in text.split(","):
        first, separator, last = part.partition("-")
        if not first.isdigit() or (separator and not last.isdigit()):
            raise argparse.ArgumentTypeError(f"expected a CPU list such as 0-1,3, got {text!r}")
        cpus.update(range(int(first), int(last if separator else first) + 1))
    if not cpus:
        raise argparse.ArgumentTypeError(f"empty CPU list {text!r}")
    return sorted(cpus)


def cpu_text(cpus):
    return ",".join(str(cpu) for cpu in cpus)


def variant_spec(text):
    """NAME=BUILD[,system][,cpus=LIST][,threads=N]: a build, whether qshd
    runs in the system mode, the CPUs it may run on, and how many async
    runtime workers it is told to run."""
    name, separator, rest = text.partition("=")
    fields = re.fullmatch(r"([A-Za-z0-9_.-]+)(,system)?(?:,cpus=([0-9,-]+?))?(?:,threads=([0-9]+))?", rest)
    if not separator or not re.fullmatch(r"[A-Za-z0-9_.-]+", name) or not fields:
        raise argparse.ArgumentTypeError(f"expected NAME=BUILD[,system][,cpus=LIST][,threads=N], got {text!r}")
    build, system, cpus, threads = fields.groups()
    if threads is not None and int(threads) < 1:
        raise argparse.ArgumentTypeError(f"threads must be at least 1, got {text!r}")
    return name, {"build": build, "mode": "system" if system else "personal",
                  "qshd_cpus": cpu_list(cpus) if cpus else None,
                  "runtime_threads": int(threads) if threads else None}


# --- Ordering and statistics -------------------------------------------------

def schedule(builds, workloads, repetitions, order, seed):
    """(repetition, workload, build) for every run, each exactly once.

    `interleaved` alternates the build order every repetition (ABBA...), so
    neither build always runs first; `random` shuffles all runs by `seed`.
    """
    runs = []
    for repetition in range(repetitions):
        for workload in workloads:
            names = list(builds)
            if repetition % 2:
                names.reverse()
            runs.extend((repetition, workload, name) for name in names)
    if order == "random":
        random.Random(seed).shuffle(runs)
    return runs


def describe(values):
    values = sorted(values)
    if not values:
        return None
    if len(values) == 1:
        p25 = p75 = values[0]
    else:
        p25, _, p75 = statistics.quantiles(values, n=4, method="inclusive")
    return {"n": len(values), "median": statistics.median(values), "p25": p25, "p75": p75,
            "min": values[0], "max": values[-1]}


def percentile(values, fraction):
    values = sorted(values)
    if not values:
        return None
    position = (len(values) - 1) * fraction
    low = int(position)
    high = min(low + 1, len(values) - 1)
    return values[low] + (values[high] - values[low]) * (position - low)


def flatten(prefix, value, into):
    if isinstance(value, dict):
        for key, item in value.items():
            flatten(f"{prefix}.{key}" if prefix else key, item, into)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        into[prefix] = value
    return into


# --- Isolated processes -------------------------------------------------------

def minimal_environment(home, extra=()):
    """A fresh environment: nothing inherited except PATH.

    The account name comes from the password database, as qsh claims it.
    """
    env = {key: os.environ[key] for key in PARENT_ENVIRONMENT if key in os.environ}
    env.setdefault("PATH", "/usr/bin:/bin")
    account = pwd.getpwuid(os.getuid()).pw_name
    env.update({
        "USER": account,
        "LOGNAME": account,
        "HOME": str(home),
        "XDG_CONFIG_HOME": f"{home}/.config",
        "XDG_CACHE_HOME": f"{home}/.cache",
        "XDG_DATA_HOME": f"{home}/.local/share",
        "XDG_STATE_HOME": f"{home}/.local/state",
        "XDG_RUNTIME_DIR": f"{home}/.runtime",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "TZ": "UTC",
        "HISTFILE": "/dev/null",
    })
    env.update(extra)
    return env


def private_home(path):
    path.mkdir(mode=0o700)
    for directory in (".config", ".cache", ".local/share", ".local/state", ".runtime"):
        (path / directory).mkdir(mode=0o700, parents=True)
    # Same startup isolation as the integration fixtures: present, empty
    # files, so no shell reads the invoking account's own startup state.
    for name, contents in ((".zshenv", "unsetopt GLOBAL_RCS\n"), (".zshrc", ""), (".bashrc", ""),
                           (".bash_profile", ""), (".profile", "")):
        (path / name).write_text(contents, encoding="utf-8")
    return path


def become_subreaper():
    """Orphaned descendants are reparented to this process and reaped here."""
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER)")


def children_of(pid):
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdigit():
            try:
                stat = parse_stat(read(f"/proc/{entry}/stat"))
            except (OSError, ValueError, IndexError):
                continue
            if stat["ppid"] == pid:
                found.append((int(entry), stat["start_ticks"]))
    return found


def reap_owned(deadline):
    """Kill and reap every remaining child of this process; return leftovers."""
    me = os.getpid()
    while True:
        try:
            while os.waitpid(-1, os.WNOHANG)[0]:
                pass
        except ChildProcessError:
            pass
        remaining = children_of(me)
        if not remaining or time.monotonic() > deadline:
            return [pid for pid, _ in remaining]
        for pid, start in remaining:
            try:
                if parse_stat(read(f"/proc/{pid}/stat"))["start_ticks"] == start:
                    os.kill(pid, signal.SIGKILL)
            except (OSError, ValueError, IndexError):
                pass
        time.sleep(0.05)


class Owned:
    """A session-leading child, reaped with its lifetime resource usage.

    wait4 accounts every thread the process ever ran, exited ones included.
    Its ru_maxrss is not recorded: a forked child starts with the harness's
    own resident size as its high-water mark.
    """

    def __init__(self, process):
        self.process = process
        self.pid = process.pid
        self.status = None
        self.rusage = None

    def wait(self, timeout):
        deadline = time.monotonic() + timeout
        while self.status is None:
            pid, status, rusage = os.wait4(self.pid, os.WNOHANG)
            if pid:
                self.status = os.waitstatus_to_exitcode(status)
                self.process.returncode = self.status
                self.rusage = {"user_s": round(rusage.ru_utime, 3), "system_s": round(rusage.ru_stime, 3),
                               "voluntary_switches": rusage.ru_nvcsw,
                               "involuntary_switches": rusage.ru_nivcsw}
                break
            if time.monotonic() > deadline:
                return False
            time.sleep(0.02)
        return True

    def stop(self):
        """Terminate the whole session, escalating to SIGKILL."""
        if self.status is not None:
            return
        for signum in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(self.pid, signum)
            except ProcessLookupError:
                pass
            if self.wait(5):
                return


class Daemon(Owned):
    def __init__(self, command, env, log, cwd):
        self.log = log
        with open(log, "ab") as output:
            super().__init__(subprocess.Popen(command, env=env, cwd=cwd, stdout=output, stderr=output,
                                              stdin=subprocess.DEVNULL, start_new_session=True))

    def tail(self):
        """The bounded end of the daemon's own output."""
        try:
            with open(self.log, "rb") as source:
                source.seek(max(0, os.path.getsize(self.log) - LOG_TAIL))
                return source.read().decode("utf-8", "backslashreplace")
        except OSError:
            return ""


class Terminal:
    """The client's pseudo-terminal: output is drained, counted and timestamped.

    Every descriptor is owned from openpty on. The drain thread is the only
    reader of the master, and it touches the descriptors only while it holds
    custody: it takes custody on entry unless close() has begun, and close()
    waits for it to give custody back before releasing them. However a start
    is interrupted, no read can reach a number reused by a later run.
    """

    def __init__(self, cols, rows):
        self.master, self.slave = os.openpty()
        self.wake_read = self.wake_write = None
        self.released = False
        self.custody = threading.Condition()
        self.closing = False
        self.reading = False
        try:
            fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
            self.wake_read, self.wake_write = os.pipe()
        except BaseException:
            self.release()
            raise
        self.lock = threading.Lock()
        self.buffer = bytearray()
        self.total = 0
        self.frames = 0
        # (stream offset after a read, monotonic time the read returned)
        self.reads = collections.deque(maxlen=EVENT_HISTORY)
        self.closed = False
        self.thread = threading.Thread(target=self.drain, daemon=True)

    def start(self):
        """Drop this process's slave descriptor, then start draining."""
        os.close(self.slave)
        self.slave = None
        self.thread.start()

    def drain(self):
        with self.custody:
            if self.closing:
                return
            self.reading = True
        try:
            self.pump()
        finally:
            with self.custody:
                self.reading = False
                self.custody.notify_all()

    def pump(self):
        poller = select.poll()
        poller.register(self.master, select.POLLIN)
        poller.register(self.wake_read, select.POLLIN)
        carry = b""
        while True:
            if any(fd == self.wake_read for fd, _ in poller.poll()):
                break
            try:
                data = os.read(self.master, 65536)
            except OSError:
                data = b""
            now = time.monotonic()
            if not data:
                break
            window = carry + data
            frames = sum(window.count(marker) for marker in FRAME_MARKERS)
            frames -= sum(carry.count(marker) for marker in FRAME_MARKERS)
            carry = window[-5:]
            with self.lock:
                self.total += len(data)
                self.reads.append((self.total, now))
                self.frames += frames
                self.buffer += data
                if len(self.buffer) > 1 << 20:
                    del self.buffer[:len(self.buffer) - (1 << 19)]
        with self.lock:
            self.closed = True

    def counters(self):
        with self.lock:
            return self.total, self.frames

    def text_since(self, offset):
        return self.snapshot_since(offset)[1]

    def snapshot_since(self, offset):
        """(stream offset of the first retained byte, bytes from there on,
        the reads that ended after it)."""
        with self.lock:
            start = max(0, len(self.buffer) - (self.total - offset))
            base = self.total - (len(self.buffer) - start)
            reads = [read for read in self.reads if read[0] > base]
            return base, bytes(self.buffer[start:]), reads

    def write(self, data):
        os.write(self.master, data)

    def wait_for(self, needle, timeout, offset=0):
        """When the read completing `needle` in escape-free output after
        `offset` returned in the drain thread.

        The time is taken where the bytes arrive, so it does not depend on
        when this poll observes them. Each poll scans only new output plus an
        overlap, so the harness's own CPU stays small while a workload
        streams output.
        """
        deadline = time.monotonic() + timeout
        start = offset
        while time.monotonic() < deadline:
            base, data, reads = self.snapshot_since(start)
            if needle in ESCAPE.sub(b"", data):
                for end, at in reads:
                    if needle in ESCAPE.sub(b"", data[:end - base]):
                        return at
                raise SetupError(f"the read that completed {needle!r} is no longer retained")
            start = max(start, base + len(data) - SCAN_OVERLAP)
            time.sleep(0.005)
        raise SetupError(f"timed out waiting for {needle!r}")

    def close(self, timeout=5):
        """Stop the reader, then release every descriptor; idempotent.

        Returns False, keeping every descriptor open, if the reader still
        holds custody after `timeout`.
        """
        if self.released:
            return True
        with self.custody:
            self.closing = True
            if self.reading:
                os.write(self.wake_write, b"x")
                if not self.custody.wait_for(lambda: not self.reading, timeout):
                    return False
        self.release()
        return True

    def release(self):
        self.released = True
        for name in ("slave", "master", "wake_read", "wake_write"):
            descriptor = getattr(self, name)
            if descriptor is not None:
                setattr(self, name, None)
                os.close(descriptor)


def spawn_on(terminal, command, env, cwd):
    """Start `command` as a session leader with `terminal` as its controlling
    terminal, without a preexec hook in this threaded process."""
    launcher = ("import fcntl, os, sys, termios; os.setsid(); "
                "fcntl.ioctl(0, termios.TIOCSCTTY, 0); os.execv(sys.argv[1], sys.argv[1:])")
    return subprocess.Popen([sys.executable, "-I", "-c", launcher, *command], env=env, cwd=cwd,
                            stdin=terminal.slave, stdout=terminal.slave, stderr=terminal.slave)


class Relay:
    """UDP relay between the clients and the daemon: exact per-run traffic.

    Each client address gets its own socket toward the daemon, so the
    daemon sees every client at an address of its own and each reply goes
    back to the client it was sent to.
    """

    def __init__(self, daemon_port):
        self.daemon_port = daemon_port
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.port = self.front.getsockname()[1]
        # Client address -> its socket toward the daemon, and back.
        self.backs = {}
        self.clients = {}
        self.cut = False
        self.stopping = False
        self.condition = threading.Condition()
        self.counts = {"c2s_datagrams": 0, "c2s_bytes": 0, "s2c_datagrams": 0, "s2c_bytes": 0,
                       "dropped_datagrams": 0}
        # Monotonic arrival times of client datagrams, oldest first.
        self.c2s_arrivals = collections.deque(maxlen=EVENT_HISTORY)
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def back_for(self, client):
        back = self.backs.get(client)
        if back is None:
            back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            back.connect(("127.0.0.1", self.daemon_port))
            self.backs[client] = back
            self.clients[back] = client
        return back

    def loop(self):
        while not self.stopping:
            ready, _, _ = select.select([self.front, *self.clients], [], [], 0.1)
            for sock in ready:
                try:
                    data, source = sock.recvfrom(65536)
                except OSError:
                    continue
                now = time.monotonic()
                with self.condition:
                    if self.cut:
                        self.counts["dropped_datagrams"] += 1
                        continue
                    if sock is self.front:
                        self.counts["c2s_datagrams"] += 1
                        self.counts["c2s_bytes"] += len(data)
                        self.c2s_arrivals.append(now)
                        self.condition.notify_all()
                    else:
                        self.counts["s2c_datagrams"] += 1
                        self.counts["s2c_bytes"] += len(data)
                try:
                    if sock is self.front:
                        self.back_for(source).send(data)
                    else:
                        self.front.sendto(data, self.clients[sock])
                except OSError:
                    pass

    def snapshot(self):
        with self.condition:
            return dict(self.counts)

    def first_client_datagram_from(self, boundary, timeout):
        """Arrival time of the first client datagram received at or after
        `boundary` (monotonic), even when more have arrived since; None if
        none arrives in time."""
        deadline = time.monotonic() + timeout
        with self.condition:
            while True:
                first = None
                for at in reversed(self.c2s_arrivals):
                    if at < boundary:
                        break
                    first = at
                if first is not None:
                    if len(self.c2s_arrivals) == self.c2s_arrivals.maxlen and self.c2s_arrivals[0] == first:
                        raise SetupError("the first client datagram after the boundary is no longer retained")
                    return first
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self.condition.wait(remaining)

    def set_cut(self, cut):
        with self.condition:
            self.cut = cut

    def close(self):
        self.stopping = True
        self.thread.join(2)
        self.front.close()
        for back in self.backs.values():
            back.close()


def udp_inodes(port):
    """Inodes of every IPv4 and IPv6 UDP socket bound to local `port`."""
    found = set()
    for table in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            lines = read(table).splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) > 9 and int(fields[1].rsplit(":", 1)[1], 16) == port:
                found.add(int(fields[9]))
    return found


def socket_inodes(pid):
    found = set()
    for descriptor in os.listdir(f"/proc/{pid}/fd"):
        try:
            target = os.readlink(f"/proc/{pid}/fd/{descriptor}")
        except OSError:
            continue
        if target.startswith("socket:["):
            found.add(int(target[8:-1]))
    return found


def holds_port(owned, port, also=()):
    """Whether the owned, still running process holds `port`.

    Fails when the process has exited, or when any socket bound to the port
    belongs to another process: traffic must never reach a foreign listener.
    The process is unreaped while its descriptors are read, so its PID
    cannot have been reused. `also` names its own children, such as the
    system mode's worker, that may hold the port too.
    """
    if owned.wait(0):
        raise SetupError(f"qshd exited with {owned.status}")
    bound = udp_inodes(port)
    if not bound:
        return False
    held = socket_inodes(owned.pid)
    for pid in also:
        try:
            held |= socket_inodes(pid)
        except OSError:
            raise SetupError(f"qshd's worker {pid} is gone") from None
    if bound - held:
        raise SetupError(f"UDP port {port} is bound by a process other than the owned qshd")
    return True


def write_as(account, path, data, mode):
    """Write a file in an account's home, owned by that account."""
    path.parent.mkdir(mode=0o700, exist_ok=True)
    os.chown(path.parent, account.pw_uid, account.pw_gid)
    path.write_bytes(data)
    os.chown(path, account.pw_uid, account.pw_gid)
    os.chmod(path, mode)


def uid_of(pid):
    for line in read(f"/proc/{pid}/status").splitlines():
        if line.startswith("Uid:"):
            return int(line.split()[1])
    raise SetupError(f"no Uid line for {pid}")


def free_udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


# --- One run ---------------------------------------------------------------

class Rig:
    def __init__(self, variant, root):
        self.build = variant["directory"]
        self.variant = variant
        self.root = root
        self.daemon = None
        self.daemon_facts = {}
        self.relay = None
        self.port = None
        self.terminals = []
        self.clients = []
        self.server_home = private_home(root / "server")
        self.key = self.server_home / "id_ed25519"
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "qsh-bench", "-f", str(self.key)],
                       check=True, capture_output=True, timeout=30,
                       env=minimal_environment(self.server_home))
        public = (self.server_home / "id_ed25519.pub").read_bytes()
        # The system mode serves an existing account: its sessions start in
        # that account's home, and its helper reads that account's keys.
        self.system = variant.get("mode") == "system"
        self.worker = None
        self.log_offset = 0
        if self.system:
            self.account = pwd.getpwnam(variant["system_account"])
            self.session_home = Path(self.account.pw_dir)
            write_as(self.account, self.session_home / ".ssh" / "authorized_keys", public, 0o600)
            write_as(self.account, self.session_home / "redraw.py", REDRAW_SCRIPT.encode(), 0o644)
        else:
            self.session_home = self.server_home
            (self.server_home / "authorized_keys").write_bytes(public)
            (self.server_home / "redraw.py").write_text(REDRAW_SCRIPT, encoding="utf-8")

    def start_daemon(self):
        port = free_udp_port()
        env = minimal_environment(self.server_home, {"SHELL": "/bin/sh", "ZDOTDIR": str(self.server_home),
                                                     "BASH_ENV": "/dev/null", "ENV": "/dev/null"})
        cpus, threads = self.variant["effective_qshd_cpus"], self.variant["runtime_threads"]
        # taskset sets the CPUs before it executes qshd, in the same process,
        # so the runtime sizes its default from them.
        command = (["taskset", "-c", cpu_text(cpus)] if cpus else []) + [
            str(self.build / "qshd"), "serve", "--port", str(port),
            "--host-key", str(self.server_home / "host_key")]
        if self.system:
            command += ["--system", "--worker-user", self.variant["worker_user"],
                        "--authorized-keys-template", "%h/.ssh/authorized_keys"]
            self.log_offset = SYSTEM_LOG.stat().st_size if SYSTEM_LOG.exists() else 0
        else:
            command += ["--authorized-keys", str(self.server_home / "authorized_keys")]
        if threads is not None:
            command += ["--runtime-threads", str(threads)]
        self.daemon = Daemon(command, env, self.root / "qshd.log", self.server_home)
        deadline = time.monotonic() + SETUP_TIMEOUT
        while self.system and self.worker is None:
            self.worker = self.find_worker()
            if self.worker is None:
                if self.daemon.wait(0) or time.monotonic() > deadline:
                    raise SetupError("qshd started no worker")
                time.sleep(0.05)
        while not holds_port(self.daemon, port, self.also()):
            if time.monotonic() > deadline:
                raise SetupError("qshd did not bind its port")
            time.sleep(0.05)
        self.port = port
        self.daemon_facts = self.daemon_identity(deadline)
        self.relay = Relay(port)

    def also(self):
        return [self.worker] if self.worker else []

    def runtime_pid(self):
        """The process that runs the async runtime: the system mode's
        worker, or the personal daemon itself."""
        return self.worker or self.daemon.pid

    def find_worker(self):
        """The system mode's worker: the helper's child that has dropped to
        the worker account."""
        worker_uid = pwd.getpwnam(self.variant["worker_user"]).pw_uid
        found = []
        for pid, _ in children_of(self.daemon.pid):
            try:
                if uid_of(pid) == worker_uid:
                    found.append(pid)
            except OSError:
                continue
        if len(found) > 1:
            raise SetupError(f"qshd has {len(found)} worker processes")
        return found[0] if found else None

    def session_processes(self):
        return [child for child in children_of(self.daemon.pid) if child[0] != self.worker]

    def daemon_identity(self, deadline):
        """The CPUs the running qshd may use and the runtime workers its log
        reports, checked against what the variant asked for."""
        status = dict(line.partition(":")[::2] for line in read(f"/proc/{self.runtime_pid()}/status").splitlines())
        allowed = cpu_list(status["Cpus_allowed_list"].strip())
        cpus, threads = self.variant["effective_qshd_cpus"], self.variant["runtime_threads"]
        if cpus and allowed != cpus:
            raise SetupError(f"qshd runs on CPUs {cpu_text(allowed)}, expected {cpu_text(cpus)}")
        log = SYSTEM_LOG if self.system else self.server_home / ".cache" / "qsh" / "qshd.log"
        workers = None
        while workers is None:
            try:
                with open(log, "rb") as source:
                    source.seek(self.log_offset)
                    found = RUNTIME_WORKERS.search(source.read().decode("utf-8", "replace"))
            except FileNotFoundError:
                found = None
            if found:
                workers = int(found.group(1))
            elif threads is None or time.monotonic() > deadline:
                # Builds without the log line report nothing; that is only
                # an error when a worker count was asked for.
                break
            else:
                time.sleep(0.05)
        if threads is not None and workers != threads:
            raise SetupError(f"qshd reports {workers} runtime workers, expected {threads}")
        facts = {"allowed_cpus": allowed, "runtime_workers": workers}
        if self.system:
            facts["mode"] = "system"
        return facts

    def start_client(self, name, options=()):
        if not holds_port(self.daemon, self.port, self.also()):
            raise SetupError("qshd no longer holds its port")
        home = private_home(self.root / name)
        terminal = Terminal(COLS, ROWS)
        self.terminals.append(terminal)
        env = minimal_environment(home, {"TERM": "xterm-256color", "HTTPS_PROXY": "http://127.0.0.1:1",
                                         "https_proxy": "http://127.0.0.1:1", "NO_PROXY": "", "no_proxy": ""})
        target = f"{self.account.pw_name}@127.0.0.1" if self.system else "127.0.0.1"
        command = [str(self.build / "qsh"), "--port", str(self.relay.port), "-i", str(self.key), *options, target]
        client = Client(spawn_on(terminal, command, env, home), terminal)
        self.clients.append(client)
        terminal.start()
        terminal.wait_for(b"Key fingerprint", SETUP_TIMEOUT)
        terminal.write(b"yes\n")
        offset = terminal.counters()[0]
        terminal.write(b"echo READY-$((6*7))\n")
        terminal.wait_for(b"READY-42", SETUP_TIMEOUT, offset)
        return client

    def snapshot(self, client=None):
        state = {"t": time.monotonic(), "qshd": sample_process(self.runtime_pid()), "relay": self.relay.snapshot()}
        if self.system:
            # The privileged helper: sessions, PAM and verdicts.
            state["qshd_helper"] = sample_process(self.daemon.pid)
        if client is not None:
            state["qsh"] = sample_process(client.pid)
            state["terminal"] = client.terminal.counters()
        return state

    def close(self):
        failures = []
        for client in self.clients:
            client.stop()
        if self.daemon:
            self.daemon.stop()
        if self.relay:
            self.relay.close()
        leftovers = reap_owned(time.monotonic() + 10)
        if leftovers:
            failures.append(f"could not reap {len(leftovers)} owned processes")
        stuck = sum(not terminal.close() for terminal in self.terminals)
        if stuck:
            failures.append(f"{stuck} terminal readers did not stop; their descriptors were kept open")
        return failures


class Client(Owned):
    def __init__(self, process, terminal):
        super().__init__(process)
        self.terminal = terminal


def window(before, after):
    seconds = after["t"] - before["t"]
    result = {"seconds": round(seconds, 3), "qshd": process_delta(before["qshd"], after["qshd"], seconds)}
    if "qshd_helper" in before:
        result["qshd_helper"] = process_delta(before["qshd_helper"], after["qshd_helper"], seconds)
    relay = {key: after["relay"][key] - before["relay"][key] for key in before["relay"]}
    relay.update({f"{key}_per_s": round(value / seconds, 2) for key, value in list(relay.items())})
    result["relay"] = relay
    if "qsh" in before:
        result["qsh"] = process_delta(before["qsh"], after["qsh"], seconds)
        result["terminal"] = {"bytes": after["terminal"][0] - before["terminal"][0],
                              "presented_frames": after["terminal"][1] - before["terminal"][1]}
        result["terminal"]["presented_frames_per_s"] = round(result["terminal"]["presented_frames"] / seconds, 2)
    return result


def run_idle(rig, settings):
    client = rig.start_client("client")
    time.sleep(SETTLE)
    before = rig.snapshot(client)
    time.sleep(settings.window)
    return {"window": window(before, rig.snapshot(client))}


def run_typing(rig, settings):
    """Per key: when its echo was read from the terminal, and when the next
    client datagram reached the relay. Both are taken where they arrive and
    measured from `start`, taken just before the key is written.

    The datagram cannot be correlated with the key, because traffic is
    encrypted: it is the first one the relay received at or after `start`,
    whatever it carries.
    """
    client = rig.start_client("client", ("--predict", "never", "--status", "off"))
    client.terminal.write(b"stty -icanon; cat > /dev/null\n")
    time.sleep(SETTLE)
    datagram, echo = [], []
    before = rig.snapshot(client)
    for index in range(settings.keystrokes):
        key = KEYS[index % len(KEYS):index % len(KEYS) + 1]
        offset = client.terminal.counters()[0]
        start = time.monotonic()
        client.terminal.write(key)
        try:
            echo.append((client.terminal.wait_for(key, 2.0, offset) - start) * 1000)
        except SetupError:
            pass
        sent = rig.relay.first_client_datagram_from(start, 2.0)
        if sent is not None:
            datagram.append((sent - start) * 1000)
        time.sleep(max(0.0, settings.key_interval - (time.monotonic() - start)))
    result = {"window": window(before, rig.snapshot(client)), "keystrokes": settings.keystrokes,
              "missing_echoes": settings.keystrokes - len(echo),
              "missing_datagrams": settings.keystrokes - len(datagram)}
    for name, values in (("stdin_to_next_datagram_ms", datagram), ("echo_ms", echo)):
        result[name] = {"p50": percentile(values, 0.5), "p90": percentile(values, 0.9),
                        "max": max(values) if values else None, "samples": [round(v, 3) for v in values]}
    if result["missing_echoes"] or result["missing_datagrams"]:
        raise Incomplete(f"{len(echo)} of {settings.keystrokes} echoes and {len(datagram)} of "
                         f"{settings.keystrokes} datagrams observed", result)
    return result


def run_remote_command(rig, client, command, marker, timeout):
    offset = client.terminal.counters()[0]
    before = rig.snapshot(client)
    client.terminal.write(command + b"; echo " + marker + b"-$((6*7))\n")
    client.terminal.wait_for(marker + b"-42", timeout, offset)
    return window(before, rig.snapshot(client))


def run_redraw(rig, settings):
    client = rig.start_client("client")
    time.sleep(SETTLE)
    command = f"python3 ~/redraw.py {settings.redraw_fps} {settings.window} {COLS} {ROWS - 1}".encode()
    return {"window": run_remote_command(rig, client, command, b"REDRAWN", settings.window + 60),
            "frames_requested": settings.redraw_fps * settings.window}


def run_saturation(rig, settings):
    client = rig.start_client("client")
    time.sleep(SETTLE)
    command = f"seq 1 {settings.saturation_lines}".encode()
    result = run_remote_command(rig, client, command, b"SATURATED", 600)
    return {"window": result, "lines": settings.saturation_lines, "completion_s": result["seconds"]}


def run_reconnect(rig, settings):
    client = rig.start_client("client")
    time.sleep(SETTLE)
    rig.relay.set_cut(True)
    before = rig.snapshot(client)
    time.sleep(settings.window)
    outage = window(before, rig.snapshot(client))
    offset = client.terminal.counters()[0]
    rig.relay.set_cut(False)
    restored = time.monotonic()
    client.terminal.write(b"echo BACK-$((6*7))\n")
    back = client.terminal.wait_for(b"BACK-42", 60, offset)
    return {"outage": outage, "recovery_s": round(back - restored, 3)}


def run_retained(rig, settings):
    for index in range(settings.retained_sessions):
        client = rig.start_client(f"client-{index}")
        client.terminal.write(b"\x1d.")
        if not client.wait(SETUP_TIMEOUT):
            raise SetupError(f"client {index} did not leave after Ctrl-] .")
    time.sleep(SETTLE)
    shells = len(rig.session_processes())
    if shells != settings.retained_sessions:
        raise SetupError(f"{shells} session processes under qshd, expected {settings.retained_sessions}")
    before = rig.snapshot()
    time.sleep(settings.window)
    return {"window": window(before, rig.snapshot()), "sessions": settings.retained_sessions}


def run_busy(rig, settings):
    """Echo latency of one typing session while `busy_sessions` others
    redraw their whole screen, all through the same qshd.

    Only echoes are measured: with several clients behind the relay, the
    next client datagram need not be the typing client's.
    """
    probe = rig.start_client("probe", ("--predict", "never", "--status", "off"))
    probe.terminal.write(b"stty -icanon; cat > /dev/null\n")
    seconds = math.ceil(settings.keystrokes * settings.key_interval + 3 * SETTLE + 5)
    busy = [rig.start_client(f"busy-{index}") for index in range(settings.busy_sessions)]
    launches = []
    for client in busy:
        launches.append((client.terminal.counters()[0], time.monotonic()))
        client.terminal.write(f"python3 ~/redraw.py {settings.redraw_fps} {seconds} {COLS} {ROWS - 1}; "
                              f"echo BUSY-$((6*7))\n".encode())
    time.sleep(SETTLE)
    echo = []
    before = rig.snapshot(probe)
    bytes_before = sum(client.terminal.counters()[0] for client in busy)
    for index in range(settings.keystrokes):
        key = KEYS[index % len(KEYS):index % len(KEYS) + 1]
        offset = probe.terminal.counters()[0]
        start = time.monotonic()
        probe.terminal.write(key)
        try:
            echo.append((probe.terminal.wait_for(key, 2.0, offset) - start) * 1000)
        except SetupError:
            pass
        time.sleep(max(0.0, settings.key_interval - (time.monotonic() - start)))
    result = {"window": window(before, rig.snapshot(probe)), "sessions": settings.busy_sessions + 1,
              "keystrokes": settings.keystrokes, "missing_echoes": settings.keystrokes - len(echo)}
    delivered = sum(client.terminal.counters()[0] for client in busy) - bytes_before
    result["busy_terminal_bytes_per_s"] = round(delivered / result["window"]["seconds"])
    result["echo_ms"] = {"p50": percentile(echo, 0.5), "p90": percentile(echo, 0.9),
                         "max": max(echo) if echo else None, "samples": [round(v, 3) for v in echo]}
    # Each redraw paces itself and runs `seconds` when its output is never
    # held back; how much longer it took is how far qshd fell behind.
    overrun = [client.terminal.wait_for(b"BUSY-42", seconds + 60, offset) - launched - seconds
               for client, (offset, launched) in zip(busy, launches)]
    result["busy_overrun_s"] = {"median": round(statistics.median(overrun), 3), "max": round(max(overrun), 3)}
    if result["missing_echoes"]:
        raise Incomplete(f"{len(echo)} of {settings.keystrokes} echoes observed", result)
    return result


RUNNERS = {"idle": run_idle, "typing": run_typing, "redraw": run_redraw, "saturation": run_saturation,
           "reconnect": run_reconnect, "retained": run_retained, "busy": run_busy}


def run_one(variant, workload, settings, root):
    record = {"workload": workload, "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "ok": False}
    harness_before = os.times()
    rig = None
    try:
        rig = Rig(variant, root)
        rig.start_daemon()
        record["qshd"] = rig.daemon_facts
        record["result"] = RUNNERS[workload](rig, settings)
        record["ok"] = True
    except Incomplete as error:
        # Kept for diagnosis; a failed run never contributes to a summary.
        record["result"] = error.result
        record["error"] = str(error)
    except (SetupError, OSError, subprocess.SubprocessError) as error:
        record["error"] = str(error)
    finally:
        if rig is not None:
            problems = rig.close()
            if problems:
                record["ok"] = False
                record["error"] = "; ".join(filter(None, [record.get("error"), *problems]))
            record["lifetime"] = {"qshd": rig.daemon.rusage if rig.daemon else None,
                                  "clients": [client.rusage for client in rig.clients]}
            if not record["ok"]:
                record["diagnostics"] = {
                    "qshd_log_tail": rig.daemon.tail() if rig.daemon else "",
                    "client_output_tail": [client.terminal.text_since(max(0, client.terminal.total - LOG_TAIL))
                                           .decode("utf-8", "backslashreplace") for client in rig.clients],
                }
    harness_after = os.times()
    record["harness_cpu_s"] = round((harness_after.user + harness_after.system)
                                    - (harness_before.user + harness_before.system), 3)
    return record


# --- Commands ----------------------------------------------------------------

def command_run(args):
    if sys.platform != "linux":
        sys.exit("perf_baseline.py measures through /proc and runs on Linux only")
    out = args.out
    out.mkdir(parents=True, exist_ok=False)
    (out / "runs").mkdir()
    # Children run in private directories, so relative paths would not resolve.
    builds = {name: directory.resolve() for name, directory in args.build}
    if len(builds) != len(args.build):
        sys.exit("build names must be unique")
    for name, directory in builds.items():
        for binary in ("qsh", "qshd"):
            if not os.access(directory / binary, os.X_OK):
                sys.exit(f"{name}: {binary} is not an executable in the given directory")
    variants = dict(args.variant or [])
    if len(variants) != len(args.variant or []):
        sys.exit("variant names must be unique")
    if not variants:
        variants = {name: {"build": name, "mode": "personal", "qshd_cpus": None, "runtime_threads": None}
                    for name in builds}
    allowed = sorted(os.sched_getaffinity(0))
    if any(variant.get("mode") == "system" for variant in variants.values()):
        # It writes the account's authorized_keys and runs qshd as root.
        if os.geteuid() != 0 or os.environ.get(DISPOSABLE_HOST_VAR) != "1":
            sys.exit(f"system-mode variants run only as root on a disposable host ({DISPOSABLE_HOST_VAR}=1)")
        if not args.system_account:
            sys.exit("system-mode variants need --system-account")
        for account in (args.system_account, args.worker_user):
            try:
                pwd.getpwnam(account)
            except KeyError:
                sys.exit(f"no account named {account}")
    for name, variant in variants.items():
        variant.setdefault("mode", "personal")
        if variant["mode"] == "system":
            variant.update(system_account=args.system_account, worker_user=args.worker_user)
        if variant["build"] not in builds:
            sys.exit(f"variant {name}: no build named {variant['build']}")
        if not set(variant["qshd_cpus"] or []) <= set(allowed):
            sys.exit(f"variant {name}: CPUs {cpu_text(variant['qshd_cpus'])} are not all available")
        if (variant["qshd_cpus"] or args.harness_cpus) and not shutil.which("taskset"):
            sys.exit("placing qshd on CPUs needs taskset")
        # A qshd without CPUs of its own keeps every CPU the harness had.
        variant["effective_qshd_cpus"] = variant["qshd_cpus"] or (allowed if args.harness_cpus else None)
    if args.harness_cpus:
        if not set(args.harness_cpus) <= set(allowed):
            sys.exit(f"harness CPUs {cpu_text(args.harness_cpus)} are not all available")
        # Before any thread or child exists, so all of them inherit it.
        os.sched_setaffinity(0, args.harness_cpus)
    become_subreaper()
    install_signal_handlers()
    workloads = args.workloads.split(",")
    unknown = sorted(set(workloads) - set(WORKLOADS))
    if unknown:
        sys.exit(f"unknown workloads: {', '.join(unknown)}")
    if "busy" in workloads and args.busy_sessions < 1:
        sys.exit("the busy workload needs at least one busy session")
    order = schedule(variants, workloads, args.repetitions, args.order, args.seed)
    manifest = {
        "tool_version": TOOL_VERSION,
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "source": {"commit": args.source_commit, "note": args.note},
        "host": dict(host_identity(), allowed_cpus=allowed),
        "settings": {key: getattr(args, key) for key in ("repetitions", "order", "seed", "window", "keystrokes",
                                                         "key_interval", "redraw_fps", "saturation_lines",
                                                         "retained_sessions", "busy_sessions", "harness_cpus")},
        "terminal": {"cols": COLS, "rows": ROWS},
        "workloads": workloads,
        "builds": identify(builds),
        "variants": variants,
        "order": [{"index": index, "repetition": rep, "workload": workload, "build": name}
                  for index, (rep, workload, name) in enumerate(order)],
    }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    failed = 0
    try:
        with tempfile.TemporaryDirectory(prefix="qsh-perf-") as scratch:
            failed = run_all(order, {name: dict(variant, directory=builds[variant["build"]])
                                     for name, variant in variants.items()}, args, Path(scratch), out)
    except Interrupted as signal_name:
        leftovers = reap_owned(time.monotonic() + 10)
        print(f"interrupted by {signal_name}; completed runs are in {out}"
              + (f"; {len(leftovers)} processes could not be reaped" if leftovers else ""), file=sys.stderr)
        return 130
    print(f"{len(order) - failed} of {len(order)} runs succeeded; raw results in {out}")
    return 1 if failed else 0


def identify(builds):
    try:
        return {name: {"label": name, "qsh": binary_identity(directory / "qsh"),
                       "qshd": binary_identity(directory / "qshd")} for name, directory in builds.items()}
    except (SetupError, OSError, subprocess.SubprocessError) as error:
        sys.exit(f"cannot identify the builds: {error}")


def run_all(order, variants, args, scratch, out):
    failed = 0
    for index, (repetition, workload, name) in enumerate(order):
        root = scratch / f"{index:04d}"
        root.mkdir(mode=0o700)
        record = run_one(variants[name], workload, args, root)
        record.update({"index": index, "repetition": repetition, "build": name})
        path = out / "runs" / f"{index:04d}-{name}-{workload}-{repetition}.json"
        path.write_text(json.dumps(record, indent=1) + "\n", encoding="utf-8")
        failed += not record["ok"]
        print(f"[{index + 1}/{len(order)}] {name} {workload} #{repetition}: "
              f"{'ok' if record['ok'] else 'FAILED: ' + record.get('error', '')}", flush=True)
    return failed


def load(out):
    manifest = json.loads((out / "manifest.json").read_text(encoding="utf-8"))
    runs = [json.loads(path.read_text(encoding="utf-8")) for path in sorted((out / "runs").glob("*.json"))]
    return manifest, runs


def summary(manifest, runs):
    """Per workload, metric and build: dispersion over successful runs."""
    table = {}
    failures = {}
    for run in runs:
        if not run["ok"]:
            failures.setdefault((run["workload"], run["build"]), 0)
            failures[(run["workload"], run["build"])] += 1
            continue
        metrics = flatten("", run["result"], {})
        for metric, value in metrics.items():
            if ".samples" in metric:
                continue
            table.setdefault(run["workload"], {}).setdefault(metric, {}).setdefault(run["build"], []).append(
                (run["repetition"], value))
    rows = []
    builds = columns(manifest)
    for workload in manifest["workloads"]:
        for metric, per_build in sorted(table.get(workload, {}).items()):
            row = {"workload": workload, "metric": metric, "builds": {}}
            for build in builds:
                values = [value for _, value in per_build.get(build, [])]
                row["builds"][build] = describe(values)
            if len(builds) == 2 and all(row["builds"][b] for b in builds):
                first, second = (dict(per_build[b]) for b in builds)
                pairs = [(first[r], second[r]) for r in sorted(first.keys() & second.keys())]
                base = row["builds"][builds[0]]["median"]
                row["comparison"] = {
                    "ratio_of_medians": round(row["builds"][builds[1]]["median"] / base, 4) if base else None,
                    "pairs": len(pairs),
                    "pairs_second_lower": sum(1 for a, b in pairs if b < a),
                    "pairs_tied": sum(1 for a, b in pairs if b == a),
                }
            rows.append(row)
    return {"rows": rows, "failed_runs": [{"workload": w, "build": b, "count": c}
                                          for (w, b), c in sorted(failures.items())]}


def number(value):
    if value is None:
        return "-"
    if abs(value) >= 100 or float(value).is_integer():
        return f"{value:.0f}"
    return f"{value:.3g}"


def columns(manifest):
    """Variants are what runs are named after; manifests before version 4
    name runs after their builds."""
    return list(manifest.get("variants") or manifest["builds"])


def markdown(manifest, result, metrics=None):
    lines = []
    builds = columns(manifest)
    header = "| Workload | Metric | " + " | ".join(f"{b} median (p25-p75, n)" for b in builds) + " |"
    if len(builds) == 2:
        header += f" {builds[1]}/{builds[0]} | pairs with {builds[1]} lower (tied) |"
    lines.append(header)
    lines.append("|" + "---|" * (header.count("|") - 1))
    for row in result["rows"]:
        if metrics and not any(re.fullmatch(pattern, row["metric"]) for pattern in metrics):
            continue
        cells = []
        for build in builds:
            stats = row["builds"][build]
            cells.append("-" if not stats else
                         f"{number(stats['median'])} ({number(stats['p25'])}-{number(stats['p75'])}, {stats['n']})")
        line = f"| {row['workload']} | {row['metric']} | " + " | ".join(cells) + " |"
        if len(builds) == 2:
            comparison = row.get("comparison")
            line += (f" {number(comparison['ratio_of_medians'])} | "
                     f"{comparison['pairs_second_lower']}/{comparison['pairs']} ({comparison['pairs_tied']}) |"
                     ) if comparison else " - | - |"
        lines.append(line)
    for failure in result["failed_runs"]:
        lines.append(f"\nFailed runs: {failure['build']} {failure['workload']}: {failure['count']}")
    return "\n".join(lines)


def command_summarize(args):
    manifest, runs = load(args.out)
    result = summary(manifest, runs)
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print(markdown(manifest, result, args.metric))
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="measure builds and retain raw results")
    run.add_argument("--build", action="append", type=build_spec, required=True, metavar="NAME=DIRECTORY",
                     help="directory containing qsh and qshd; repeat to compare builds")
    run.add_argument("--out", type=Path, required=True, help="new directory for the manifest and raw runs")
    run.add_argument("--workloads", default=",".join(WORKLOADS))
    run.add_argument("--repetitions", type=int, default=5)
    run.add_argument("--order", choices=("interleaved", "random"), default="interleaved")
    run.add_argument("--seed", type=int, default=1)
    run.add_argument("--window", type=int, default=10, help="measurement window in seconds")
    run.add_argument("--keystrokes", type=int, default=100)
    run.add_argument("--key-interval", type=float, default=0.1)
    run.add_argument("--redraw-fps", type=int, default=20)
    run.add_argument("--saturation-lines", type=int, default=2_000_000)
    run.add_argument("--retained-sessions", type=int, default=8)
    run.add_argument("--busy-sessions", type=int, default=4, help="redrawing sessions beside the typing one")
    run.add_argument("--variant", action="append", type=variant_spec,
                     metavar="NAME=BUILD[,system][,cpus=LIST][,threads=N]",
                     help="run a build with qshd on these CPUs and with this many runtime workers; "
                          "repeat to compare (default: each build as it is)")
    run.add_argument("--harness-cpus", type=cpu_list, metavar="LIST",
                     help="CPUs for the harness, its relay and the clients; qshd keeps its own")
    run.add_argument("--system-account", help="existing account the system-mode variants log in as")
    run.add_argument("--worker-user", default="nobody", help="--worker-user for system-mode variants")
    run.add_argument("--source-commit", help="source commit the builds were made from")
    run.add_argument("--note", help="free-form build description, such as the toolchain")
    run.set_defaults(handler=command_run)
    summarize = commands.add_parser("summarize", help="dispersion tables from retained raw results")
    summarize.add_argument("out", type=Path)
    summarize.add_argument("--json", action="store_true")
    summarize.add_argument("--metric", action="append", help="regular expression selecting metrics")
    summarize.set_defaults(handler=command_summarize)
    args = parser.parse_args()
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())
