#!/usr/bin/env python3
"""Opt-in Linux three-channel functional qualification; importing does not execute."""
import argparse
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import threading
import time

CAP = 65536
GRACE = 120
EVIDENCE_CAP = 256 * 1024**2
RESERVE = 12 * 1024**3

def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024*1024), b''):
            h.update(chunk)
    return h.hexdigest()


def dump(path, value):
    with path.open('x') as f:
        json.dump(value, f, indent=2)
        f.write('\n')


def private_dir(path):
    s = path.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
        raise ValueError('expected current-owned real 0700 directory: '+str(path))


def children():
    return [int(x) for x in Path(f'/proc/{os.getpid()}/task/{os.getpid()}/children').read_text().split()]


def subreaper():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), 'subreaper setup')


def observe(proc):
    # Called only after direct Popen wait has reaped its own child.
    while True:
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return []
        if not pid:
            return children()


def run_owned(command, env, deadline, request, grace=GRACE, overrun=lambda ids: None):
    """Own one new session through settlement. Output is bounded at producer pipe+capture."""
    if children():
        raise RuntimeError('runner must have no prior children')
    if request or time.monotonic() >= deadline:
        return {'owner_pid': None, 'exit_code': None, 'reason': request[0] if request else 'total deadline exceeded',
                'output': '', 'cleanup_overrun': False, 'settled': True}
    proc = None
    output = bytearray()
    nonblocking = False
    reason, overflow, cleanup_overrun = None, False, False
    try:
        proc = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
        os.set_blocking(proc.stdout.fileno(), False)
        nonblocking = True
        while True:
            # Limit each turn's drain so a continuous writer cannot starve the deadline.
            for _ in range(16):
                try:
                    chunk = os.read(proc.stdout.fileno(), 4096)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                room = CAP - len(output)
                output.extend(chunk[:room])
                overflow |= len(chunk) > room
            ended = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if overflow:
                reason = 'output cap exceeded'
            elif request:
                reason = request[0]
            elif time.monotonic() >= deadline:
                reason = 'total deadline exceeded'
            if reason or ended is not None:
                break
            select.select([proc.stdout], [], [], 0.02)
    except BaseException as error:
        reason = 'supervisor exception '+type(error).__name__
        if proc is None:
            return {'exit_code': None, 'reason': reason, 'output': '', 'cleanup_overrun': False, 'settled': True}
    finally:
        if proc is not None:
            # The unreaped session leader anchors the group identity even if it exited.
            # No Popen.poll/wait has run before this one group signal.
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except OSError as error:
                reason = reason or 'group termination error '+type(error).__name__
            if not nonblocking:
                try:
                    proc.stdout.close()
                except OSError:
                    reason = reason or 'pipe-close error'
            end = time.monotonic() + grace
            reported = False
            signalled = set()
            while True:
                # Bounded discard/capture also prevents a child-held pipe blocking cleanup.
                for _ in range(16) if nonblocking else ():
                    try:
                        chunk = os.read(proc.stdout.fileno(), 4096)
                    except (BlockingIOError, OSError):
                        break
                    if not chunk:
                        break
                    room = CAP - len(output)
                    output.extend(chunk[:room])
                    overflow |= len(chunk) > room
                try:
                    if proc.returncode is None:
                        proc.poll()
                    ids = observe(proc) if proc.returncode is not None else children()
                except BaseException as error:
                    reason = reason or 'cleanup observation error '+type(error).__name__
                    ids = None  # Unknown is never evidence of settlement.
                # All direct/adopted children are ours: preflight forbids previous children.
                # They remain unreaped while checked/signalled, preventing PID reuse.
                for pid in ids or ():
                    if pid != proc.pid and pid not in signalled:
                        try:
                            os.kill(pid, signal.SIGTERM)
                        except OSError as error:
                            reason = reason or 'adopted termination error '+type(error).__name__
                        signalled.add(pid)
                if proc.returncode is not None and ids == []:
                    break
                if time.monotonic() >= end and not reported:
                    reported = True
                    cleanup_overrun = True
                    try:
                        overrun(ids if ids is not None else [proc.pid])
                    except BaseException:
                        # Diagnostic failure must never surrender custody.
                        pass
                time.sleep(1 if reported else 0.01)
            proc.stdout.close()
    if overflow:
        reason = reason or 'output cap exceeded'
    if cleanup_overrun:
        reason = reason or 'cleanup overrun'
    return {'owner_pid': proc.pid, 'exit_code': proc.returncode, 'reason': reason,
            'output': output.decode('utf-8', 'replace'), 'cleanup_overrun': cleanup_overrun, 'settled': True}


def validate(result, expected_case="no-loss"):
    if (result["exit_code"] != 0 or result["reason"] is not None
            or result["cleanup_overrun"] or result["settled"] is not True):
        raise ValueError("owned execution failed")
    records = []
    for line in result["output"].splitlines():
        if line.startswith("{"):
            records.append(json.loads(line))
    if len(records) != 1 or records[0].get("phase") != "complete":
        raise ValueError("missing/duplicate/overrun result")
    x = records[0]
    s = x["summary"]
    if x.get("ok") is not True or x.get("error") is not None:
        raise ValueError("functional failure")
    for field in ("driver_joined", "manager_joined", "registered_cleanup_settled"):
        if x.get(field) is not True:
            raise ValueError("missing native settlement " + field)
    if x.get("raw_bytes_retained") != 0 or s["held_bytes"] != 0:
        raise ValueError("retained raw ownership")
    for field in ("released", "final_state_marker", "bulk_exited", "echo_exited", "screen_exited"):
        if s.get(field) is not True:
            raise ValueError("missing phase " + field)
    if s["bulk_bytes"] != 4 * 1024**2 or s["echo_responses"] != 32:
        raise ValueError("fixed work incomplete")
    for field in ("blocked_sequence", "release_sequence", "credit_recovered_sequence", "raw_processed"):
        if type(s.get(field)) is not int or s[field] <= 0:
            raise ValueError("missing positive witness " + field)
    if not s["blocked_sequence"] <= s["release_sequence"] < s["credit_recovered_sequence"]:
        raise ValueError("credit phase ordering")
    if s["raw_processed"] < s["bulk_bytes"]:
        raise ValueError("raw processing incomplete")
    if x.get("case") != expected_case or x.get("relay_joined") is not True:
        raise ValueError("missing selected case or relay join")
    relay = x.get("relay")
    if not isinstance(relay, dict) or not isinstance(relay.get("receipt"), dict):
        raise ValueError("missing relay receipt object")
    receipt = relay["receipt"]
    for key in ("server_after_arm", "dropped", "held", "reordered", "held_bytes", "held_high_water", "canceled_held"):
        if type(receipt.get(key)) is not int or receipt[key] < 0:
            raise ValueError("invalid relay counter " + key)
    if relay.get("error") is not None or receipt.get("armed") is not True:
        raise ValueError("relay failed or was not armed")
    if receipt.get("held_bytes") != 0 or receipt.get("canceled_held") != 0:
        raise ValueError("incomplete relay custody")
    if type(receipt.get("server_after_arm")) is not int or receipt["server_after_arm"] <= 0:
        raise ValueError("no post-arm relay traffic")
    faults = tuple(receipt.get(key) for key in ("dropped", "held", "reordered"))
    high = receipt.get("held_high_water")
    if expected_case == "loss-reorder":
        if faults != (1, 1, 1) or receipt["server_after_arm"] < 8 or type(high) is not int or not 0 < high <= 65536:
            raise ValueError("fixed drop/reorder schedule did not complete")
    elif expected_case != "no-loss" or faults != (0, 0, 0) or high != 0:
        raise ValueError("unexpected no-loss relay fault")
    return x


def create_state(root):
    """Never overwrite a previous run, including a dangling symlink."""
    root.mkdir(mode=0o700)
    for name in ("home", "config", "cache", "tmp"):
        (root / name).mkdir(mode=0o700)
    for directory in (root, *(root / n for n in ("home", "config", "cache", "tmp"))):
        private_dir(directory)


def resource_reason(root):
    used = sum(p.lstat().st_blocks * 512 for p in [root, *root.rglob("*")] if not p.is_symlink())
    if used > EVIDENCE_CAP:
        return "evidence cap"
    space = os.statvfs(root)
    if space.f_bavail * space.f_frsize < RESERVE:
        return "free reserve"
    return None


def watch_resources(root, request, stop):
    while not stop.is_set():
        try:
            reason = resource_reason(root)
        except OSError:
            reason = "resource observation failed"
        if reason:
            request.append(reason)
            return
        stop.wait(0.5)


def source_identity():
    source = Path(__file__).resolve().parent.parent
    def git(*args):
        return subprocess.check_output(["git", "-C", str(source), *args], text=True).strip()
    if git("status", "--porcelain", "--untracked-files=no"):
        raise ValueError("tracked source is dirty; commit the reviewed fixture before execution")
    return dict(commit=git("rev-parse", "HEAD"), tree=git("rev-parse", "HEAD^{tree}"),
                lock_sha256=sha(source / "Cargo.lock"), script_sha256=sha(Path(__file__).resolve()))


def execute(binary, root, selected_case="no-loss"):
    if sys.platform != "linux":
        raise ValueError("this owned fixture requires Linux /proc and subreaper support")
    os.umask(0o077)
    binary = binary.resolve(strict=True)
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("binary must be an existing executable")
    root = root.absolute()
    # The parent is declared owned fixture state too; avoid public or personal ancestors.
    private_dir(root.parent)
    identity = source_identity()
    identity.update(binary_sha256=sha(binary), binary_bytes=binary.stat().st_size)
    if children():
        raise ValueError("prior children forbid this custody scope")
    space = os.statvfs(root.parent)
    if space.f_bavail * space.f_frsize < RESERVE:
        raise ValueError("free reserve")
    create_state(root)
    # This private root is unique, so its lock cannot conflict with another run.
    lockfd = os.open(root / "owner.lock", os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(lockfd, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        dump(root / "provenance.json", dict(identity=identity,
             scope="one functional case; hashes do not attest build provenance",
             case=selected_case,
             limits=dict(hold_seconds=5, internal_work_seconds=30, outer_seconds=40,
                         cleanup_grace_seconds=120, capture_bytes=CAP,
                         sampled_evidence_bytes=EVIDENCE_CAP, free_reserve_bytes=RESERVE)))
        request = []
        previous_handlers = {}
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous_handlers[sig] = signal.signal(sig, lambda n, _: request.append("supervisor signal " + str(n)))
        env = dict(PATH="/usr/bin:/bin", LANG="C.UTF-8", LC_ALL="C.UTF-8",
                   HOME=str(root / "home"), XDG_CONFIG_HOME=str(root / "config"),
                   XDG_CACHE_HOME=str(root / "cache"), TMPDIR=str(root / "tmp"),
                   SHELL="/bin/sh", HISTFILE="/dev/null")
        subreaper()
        started = time.monotonic()
        stop = threading.Event()
        watcher = threading.Thread(target=watch_resources, args=(root, request, stop), name="owned-resource")
        old = Path.cwd()
        watcher.start()
        try:
            os.chdir(root / "tmp")
            result = run_owned([str(binary), "--run-owned-functional", str(root), "--case", selected_case], env,
                               started + 40, request, grace=120,
                               overrun=lambda ids: dump(root / "cleanup-overrun.json",
                                   dict(owned_children=ids, custody_retained=True)))
        finally:
            stop.set()
            watcher.join()
            os.chdir(old)
            for sig, handler in previous_handlers.items():
                signal.signal(sig, handler)
        with (root / "output.log").open("x") as output:
            output.write(result["output"])
        reasons = list(request)
        record = None
        try:
            record = validate(result, selected_case)
        except (ValueError, KeyError, TypeError) as error:
            reasons.append(str(error))
        try:
            reason = resource_reason(root)
            if reason:
                reasons.append(reason)
        except OSError:
            reasons.append("resource verification failed after execution")
        no_children = not children()
        if not no_children:
            reasons.append("owned children remain")
        try:
            if sha(binary) != identity["binary_sha256"]:
                reasons.append("binary changed during execution")
        except OSError:
            reasons.append("binary verification failed after execution")
        try:
            if source_identity() != {k: identity[k] for k in ("commit", "tree", "lock_sha256", "script_sha256")}:
                reasons.append("source changed during execution")
        except (OSError, ValueError, subprocess.SubprocessError):
            reasons.append("source verification failed after execution")
        dump(root / "result.json", dict(ok=not reasons, stop_reasons=reasons, native=result,
             record=record, no_children=no_children, elapsed_s=time.monotonic() - started))
        return 1 if reasons else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path,
                        help="new state directory below an existing owned 0700 parent")
    parser.add_argument("--case", choices=("no-loss", "loss-reorder"), default="no-loss")
    args = parser.parse_args()
    return execute(args.binary, args.root, args.case)


if __name__ == "__main__":
    raise SystemExit(main())
