#!/usr/bin/env python3
"""Run bounded libFuzzer smoke checks from owned corpus copies.

Every target runs, even after another one fails. A target fails on a nonzero
or signal exit, a wall-clock timeout, a missing completion marker, a retained
artifact or a failure marker anywhere in its log; each reason is reported
together with a bounded tail of the log. Seed directories are only read: their
files are copied into a fresh work directory, without the manifest.
"""

import argparse
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import time


FUZZER_OPTIONS = (
    "-seed=1",
    "-timeout=2",
    "-rss_limit_mb=512",
    "-malloc_limit_mb=64",
    "-print_final_stats=1",
)
# A complete line may end right after DONE; within a longer line's bounded
# prefix, an actual delimiter byte must follow it.
COMPLETION = re.compile(rb"#\d+\s+DONE(?![A-Za-z0-9_])")
COMPLETION_IN_PREFIX = re.compile(rb"#\d+\s+DONE(?=[^A-Za-z0-9_])")
FAILURE_MARKERS = (b"ERROR:", b"SUMMARY: AddressSanitizer", b"panicked at", b"deadly signal")
TARGET = re.compile(r"([a-z0-9_]+)=([1-9][0-9]*)")
LOG_LIMIT = 4 * 1024 * 1024
MINIMUM_LOG_LIMIT = 1024
SCAN_CHUNK = 64 * 1024
LINE_HEAD = 256
TAIL_LINES = 200
TAIL_BYTES = 64 * 1024
POLL_INTERVAL = 0.05


def target_spec(text):
    match = TARGET.fullmatch(text)
    if not match:
        raise argparse.ArgumentTypeError(f"expected TARGET=MAX_LEN, got {text!r}")
    return match.group(1), int(match.group(2))


def log_limit(text):
    value = int(text)
    if value < MINIMUM_LOG_LIMIT:
        raise argparse.ArgumentTypeError(f"the log limit must be at least {MINIMUM_LOG_LIMIT}")
    return value


def printable(text):
    """Escape every character that could end a line or hide in output."""
    def escape(character):
        code = ord(character)
        if code < 0x100:
            return f"\\x{code:02x}"
        if code < 0x10000:
            return f"\\u{code:04x}"
        return f"\\U{code:08x}"
    return "".join(c if c.isprintable() else escape(c) for c in text)


def command_data(text):
    """Encode a workflow-command message value."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def prepare(seeds, work):
    """Create the owned run directory and copy the seeds, never the manifest."""
    work.mkdir(parents=True, exist_ok=False)
    corpus = work / "corpus"
    artifacts = work / "artifacts"
    corpus.mkdir()
    artifacts.mkdir()
    for path in sorted(seeds.iterdir()):
        if path.name == "manifest.json":
            continue
        if not stat.S_ISREG(path.lstat().st_mode):
            raise ValueError(f"seed is not a regular file: {path.name}")
        shutil.copyfile(path, corpus / path.name, follow_symlinks=False)
    return corpus, artifacts


def exited_unreaped(pid, deadline):
    """Wait until `pid` exits, without reaping it; False at the deadline."""
    while os.waitid(os.P_PID, pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(POLL_INTERVAL, remaining))
    return True


def run(command, log, wall_timeout):
    """Return the exit status, or None after a wall-clock timeout.

    The session leader is reaped only after its process group was signaled:
    an unreaped leader keeps its process-group ID from being reused.
    """
    deadline = time.monotonic() + wall_timeout
    with log.open("wb") as output:
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    finished = exited_unreaped(process.pid, deadline)
    # The session is ours alone: clear anything still running in it.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    status = process.wait()
    return status if finished else None


def completion_in(head, whole):
    """Whether a line starting with `head` is a completion line.

    `whole` means `head` is the entire line, ended by its newline or by the
    end of the log. Otherwise `head` is a bounded prefix of a longer line,
    and the end of that prefix is not a word boundary.
    """
    return (COMPLETION if whole else COMPLETION_IN_PREFIX).match(head) is not None


def scan(log, chunk=SCAN_CHUNK):
    """Find the completion and failure markers in the whole log.

    At most `chunk` bytes are held at a time; a marker split across reads is
    still found. Completion counts only at the start of a line and within
    its first LINE_HEAD bytes, which are collected with one byte more so the
    byte that follows DONE is known.
    """
    overlap = max(len(marker) for marker in FAILURE_MARKERS) - 1
    completed = False
    found = set()
    carry = b""
    head = b""
    length = 0
    with log.open("rb") as source:
        while piece := source.readline(chunk):
            ended = piece.endswith(b"\n")
            length += len(piece)
            if head is not None:
                head += piece[:LINE_HEAD + 1 - len(head)]
                if ended or len(head) > LINE_HEAD:
                    completed |= completion_in(head, whole=ended and length == len(head))
                    head = None
            if ended:
                head = b""
                length = 0
            window = carry + piece
            found.update(marker for marker in FAILURE_MARKERS if marker in window)
            carry = window[-overlap:]
    if head:
        completed |= completion_in(head, whole=length == len(head))
    return completed, [marker for marker in FAILURE_MARKERS if marker in found]


def bound_log(log, limit):
    """Keep the end of the log; the file, notice included, fits in `limit`."""
    size = log.stat().st_size
    if size <= limit:
        return
    note = f"[run_smoke: log of {size} bytes truncated to its last {limit} bytes]\n".encode()
    kept = limit - len(note)
    with log.open("rb") as source:
        source.seek(size - kept)
        data = source.read(kept)
    log.write_bytes(note + data)


def problems_of(status, wall_timeout, completed, markers, artifacts):
    problems = []
    if status is None:
        problems.append(f"did not finish within {wall_timeout} s; its process group was killed")
    elif status < 0:
        problems.append(f"terminated by signal {-status}")
    elif status != 0:
        problems.append(f"exited with status {status}")
    if not completed:
        problems.append("no completion marker (#N DONE) in the log")
    for marker in markers:
        problems.append(f"failure marker in the log: {marker.decode()}")
    for path in sorted(artifacts.iterdir()):
        problems.append(f"unexpected artifact: {path.name} ({path.lstat().st_size} bytes)")
    return problems


def tail(log):
    with log.open("rb") as source:
        source.seek(max(0, log.stat().st_size - TAIL_BYTES))
        lines = source.read().splitlines()[-TAIL_LINES:]
    return "\n".join(line.decode("utf-8", "backslashreplace") for line in lines)


def report(name, problems, log, annotate):
    print(f"{name}: FAILED")
    if annotate:
        for problem in problems:
            print(f"::error title=fuzz smoke {name}::{command_data(printable(problem))}")
    # Diagnostics carry file names, paths and fuzzed bytes: none of them may
    # become a workflow command.
    token = secrets.token_hex(16) if annotate else None
    if token:
        print(f"::stop-commands::{token}")
    for problem in problems:
        print(f"  {printable(problem)}")
    if log is not None and log.exists():
        print(f"  last lines of {printable(str(log))}:")
        print(tail(log))
    if token:
        print(f"::{token}::")


def smoke(name, max_len, args):
    work = args.work / name
    log = None
    try:
        corpus, artifacts = prepare(args.seeds_root / name, work)
        log = work / "run.log"
        command = [
            str(args.binaries / name), str(corpus), f"-artifact_prefix={artifacts}/",
            f"-max_len={max_len}", f"-runs={args.runs}",
            f"-max_total_time={args.max_total_time}", *FUZZER_OPTIONS,
        ]
        status = run(command, log, args.wall_timeout)
        # Classify the complete output before only its end is retained.
        completed, markers = scan(log)
        bound_log(log, args.log_limit)
        problems = problems_of(status, args.wall_timeout, completed, markers, artifacts)
    except (OSError, ValueError) as error:
        problems = [f"could not run: {error}"]
    return problems, log


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True,
                        help="directory with the built fuzz target executables")
    parser.add_argument("--seeds-root", type=Path, required=True,
                        help="directory with one seed directory per target")
    parser.add_argument("--work", type=Path, required=True,
                        help="owned directory for corpus copies, logs and artifacts")
    parser.add_argument("--runs", type=int, default=1000)
    parser.add_argument("--max-total-time", type=int, default=10)
    parser.add_argument("--wall-timeout", type=int, default=120)
    parser.add_argument("--log-limit", type=log_limit, default=LOG_LIMIT, help=argparse.SUPPRESS)
    parser.add_argument("targets", nargs="+", type=target_spec, metavar="TARGET=MAX_LEN")
    args = parser.parse_args()
    annotate = os.environ.get("GITHUB_ACTIONS") == "true"

    failed = []
    for name, max_len in args.targets:
        problems, log = smoke(name, max_len, args)
        if problems:
            failed.append(name)
            report(name, problems, log, annotate)
        else:
            print(f"{name}: ok")
        sys.stdout.flush()
    if failed:
        print(f"Fuzz smoke failed for: {', '.join(failed)}; "
              f"results are under {printable(str(args.work))}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
