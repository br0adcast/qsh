"""Smoke-runner checks use synthetic stand-in targets, never a fuzz runtime."""

import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock


RUNNER = Path(__file__).with_name("run_smoke.py")
SPEC = importlib.util.spec_from_file_location("run_smoke", RUNNER)
run_smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(run_smoke)

# Each stand-in target is selected by its executable name and receives the
# same arguments as a libFuzzer binary.
STAND_IN = """\
import os, signal, subprocess, sys, time
name = os.path.basename(sys.argv[0])
corpus = sys.argv[1]
prefix = next(a.split("=", 1)[1] for a in sys.argv if a.startswith("-artifact_prefix="))
print("seeds:", ",".join(sorted(os.listdir(corpus))), flush=True)
print("args:", " ".join(sys.argv[2:]), flush=True)
done = "#1000\\tDONE   cov: 1 ft: 1 corp: 2/3b exec/s: 0 rss: 1Mb"
if name == "passing":
    print(done)
elif name == "crashing":
    print("::warning::from fuzzed bytes")
    print("==1== ERROR: libFuzzer: deadly signal")
    with open(prefix + "crash-0123", "wb") as artifact:
        artifact.write(b"boom")
    sys.exit(77)
elif name == "hanging":
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    print("pids:", os.getpid(), child.pid, flush=True)
    time.sleep(60)
elif name == "unfinished":
    pass
elif name == "leaving":
    print(done)
    with open(prefix + "leak-1", "wb") as artifact:
        artifact.write(b"x")
elif name == "panicking":
    print("thread '<unnamed>' panicked at src/lib.rs:1:1:")
    print(done)
elif name == "noisy":
    for line in range(1000):
        print("line", line)
    print(done)
elif name == "early":
    print("==1==ERROR: AddressSanitizer: heap-buffer-overflow")
    for line in range(1000):
        print("line", line)
    print(done)
elif name == "early_done":
    print(done)
    for line in range(1000):
        print("line", line)
elif name == "signaled":
    os.kill(os.getpid(), signal.SIGTERM)
elif name == "hostile":
    print(done)
    with open(prefix + "crash\\n::error::injected-artifact", "wb") as artifact:
        artifact.write(b"x")
"""

STAND_INS = ["passing", "crashing", "hanging", "unfinished", "leaving", "panicking",
             "noisy", "early", "early_done", "signaled", "hostile"]


def outside_suppression(stdout):
    """Lines GitHub Actions would still read as workflow commands."""
    lines, token = [], None
    for line in stdout.splitlines():
        if token is None and line.startswith("::stop-commands::"):
            token = line.split("::")[2]
        elif token is not None:
            if line == f"::{token}::":
                token = None
        else:
            lines.append(line)
    return lines


class SmokeRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qsh-smoke-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binaries = self.root / "bin"
        self.seeds = self.root / "seeds"
        self.work = self.root / "work"
        self.binaries.mkdir()
        self.seeds.mkdir()
        for name in STAND_INS:
            target = self.binaries / name
            target.write_text(f"#!{sys.executable}\n{STAND_IN}", encoding="utf-8")
            target.chmod(0o700)
            seeds = self.seeds / name
            seeds.mkdir()
            (seeds / "first").write_bytes(b"1")
            (seeds / "second").write_bytes(b"22")
            (seeds / "manifest.json").write_text("{}", encoding="utf-8")

    def run_smoke(self, *targets, options=(), environment=None):
        env = dict(os.environ)
        env.pop("GITHUB_ACTIONS", None)
        env.update(environment or {})
        return subprocess.run(
            [sys.executable, str(RUNNER), "--binaries", str(self.binaries),
             "--seeds-root", str(self.seeds), "--work", str(self.work), *options,
             *targets],
            capture_output=True, text=True, timeout=30, env=env,
        )

    def assert_failed(self, result, *diagnostics):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for diagnostic in diagnostics:
            self.assertIn(diagnostic, result.stdout)
        self.assertNotIn("Traceback", result.stdout + result.stderr)

    def test_passing_target_runs_an_owned_copy_without_the_manifest(self):
        before = sorted((path.name, path.read_bytes()) for path in (self.seeds / "passing").iterdir())
        result = self.run_smoke("passing=64")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "passing: ok\n")
        log = (self.work / "passing" / "run.log").read_text(encoding="utf-8")
        self.assertIn("seeds: first,second\n", log)
        self.assertIn("-max_len=64 -runs=1000 -max_total_time=10 -seed=1", log)
        after = sorted((path.name, path.read_bytes()) for path in (self.seeds / "passing").iterdir())
        self.assertEqual(before, after)

    def test_failing_exit_is_reported_with_artifact_and_log(self):
        result = self.run_smoke("crashing=64")
        self.assert_failed(result, "crashing: FAILED", "exited with status 77",
                           "unexpected artifact: crash-0123 (4 bytes)",
                           "failure marker in the log: deadly signal",
                           "==1== ERROR: libFuzzer: deadly signal")
        self.assertTrue((self.work / "crashing" / "artifacts" / "crash-0123").is_file())

    def test_wall_timeout_kills_the_whole_process_group(self):
        result = self.run_smoke("hanging=64", options=["--wall-timeout", "1"])
        self.assert_failed(result, "did not finish within 1 s",
                           "no completion marker")
        log = (self.work / "hanging" / "run.log").read_text(encoding="utf-8")
        pids = [int(pid) for pid in log.split("pids:", 1)[1].split()[:2]]
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            alive = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    alive.append(pid)
                except ProcessLookupError:
                    pass
            if not alive:
                break
            time.sleep(0.05)
        self.assertEqual(alive, [])

    def test_missing_completion_marker_fails_a_zero_exit(self):
        self.assert_failed(self.run_smoke("unfinished=64"), "no completion marker")

    def test_artifact_fails_a_completed_run(self):
        self.assert_failed(self.run_smoke("leaving=64"), "unexpected artifact: leak-1 (1 bytes)")

    def test_failure_marker_fails_a_completed_run(self):
        self.assert_failed(self.run_smoke("panicking=64"), "failure marker in the log: panicked at")

    def test_every_target_runs_after_a_failure(self):
        result = self.run_smoke("crashing=64", "passing=64")
        self.assert_failed(result, "crashing: FAILED", "passing: ok",
                           "Fuzz smoke failed for: crashing;")

    def test_existing_work_directory_is_refused(self):
        (self.work / "passing").mkdir(parents=True)
        result = self.run_smoke("passing=64")
        self.assert_failed(result, "could not run:")
        self.assertFalse((self.work / "passing" / "run.log").exists())

    def test_non_regular_seed_is_refused(self):
        (self.seeds / "passing" / "first").unlink()
        (self.seeds / "passing" / "first").symlink_to(self.root / "outside")
        self.assert_failed(self.run_smoke("passing=64"), "seed is not a regular file: first")

    def test_missing_target_is_reported(self):
        self.assert_failed(self.run_smoke("absent=64"), "absent: FAILED", "could not run:")

    def test_log_is_bounded_including_its_notice(self):
        result = self.run_smoke("noisy=64", options=["--log-limit", "1024"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        log = (self.work / "noisy" / "run.log").read_bytes()
        self.assertTrue(log.startswith(b"[run_smoke: log of "), log[:80])
        self.assertEqual(len(log), 1024)
        self.assertTrue(log.endswith(b"rss: 1Mb\n"))

    def test_early_failure_marker_survives_truncation(self):
        result = self.run_smoke("early=64", options=["--log-limit", "1024"])
        self.assert_failed(result, "early: FAILED", "failure marker in the log: ERROR:")
        log = (self.work / "early" / "run.log").read_bytes()
        self.assertLessEqual(len(log), 1024)
        self.assertNotIn(b"ERROR:", log)

    def test_early_completion_survives_truncation(self):
        result = self.run_smoke("early_done=64", options=["--log-limit", "1024"])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(b"DONE", (self.work / "early_done" / "run.log").read_bytes())

    def test_log_limit_below_minimum_is_a_usage_error(self):
        result = self.run_smoke("passing=64", options=["--log-limit", "100"])
        self.assertEqual(result.returncode, 2)
        self.assertIn("the log limit must be at least", result.stderr)

    def test_signal_exit_is_reported(self):
        self.assert_failed(self.run_smoke("signaled=64"), "terminated by signal 15")

    def test_artifact_names_cannot_inject_workflow_commands(self):
        result = self.run_smoke("hostile=64", environment={"GITHUB_ACTIONS": "true"})
        self.assert_failed(result, "unexpected artifact: crash\\x0a::error::injected-artifact")
        for line in outside_suppression(result.stdout):
            if line.startswith("::"):
                self.assertTrue(line.startswith("::error title=fuzz smoke hostile::"), line)
        self.assertIn("::error title=fuzz smoke hostile::unexpected artifact: "
                      "crash\\x0a::error::injected-artifact (1 bytes)", result.stdout)

    def test_untrusted_names_are_escaped_outside_actions(self):
        result = self.run_smoke("hostile=64")
        self.assert_failed(result, "  unexpected artifact: crash\\x0a::error::injected-artifact")
        self.assertNotIn("::error::injected-artifact (1 bytes)", result.stdout.splitlines())

    def test_exception_text_cannot_inject_workflow_commands(self):
        (self.seeds / "passing" / "bad\n::error::injected-seed").symlink_to(self.root / "outside")
        result = self.run_smoke("passing=64", environment={"GITHUB_ACTIONS": "true"})
        self.assert_failed(result, "seed is not a regular file: bad\\x0a::error::injected-seed")
        for line in outside_suppression(result.stdout):
            self.assertFalse(line.startswith("::error::"), line)

    def test_logged_workflow_commands_are_disabled(self):
        result = self.run_smoke("crashing=64", environment={"GITHUB_ACTIONS": "true"})
        self.assert_failed(result, "::error title=fuzz smoke crashing::exited with status 77")
        lines = result.stdout.splitlines()
        start = next(i for i, line in enumerate(lines) if line.startswith("::stop-commands::"))
        token = lines[start].split("::")[2]
        self.assertGreaterEqual(len(token), 32)
        injected = lines.index("::warning::from fuzzed bytes")
        resume = lines.index(f"::{token}::")
        self.assertLess(start, injected)
        self.assertLess(injected, resume)

    def test_invalid_target_specification_is_a_usage_error(self):
        result = self.run_smoke("passing")
        self.assertEqual(result.returncode, 2)
        self.assertIn("expected TARGET=MAX_LEN", result.stderr)


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qsh-smoke-scan-")
        self.addCleanup(self.temporary.cleanup)
        self.log = Path(self.temporary.name) / "run.log"

    def scan(self, data, chunk):
        self.log.write_bytes(data)
        return run_smoke.scan(self.log, chunk=chunk)

    def test_markers_split_across_reads_are_found(self):
        completed, markers = self.scan(b"xx deadly signal yy\n#9 DONE cov: 1\n", chunk=4)
        self.assertTrue(completed)
        self.assertEqual(markers, [b"deadly signal"])

    def test_completion_at_end_without_newline_is_found(self):
        self.assertEqual(self.scan(b"line\n#12 DONE", chunk=3), (True, []))

    def scan_all_chunkings(self, data):
        """scan() results for read sizes around every relevant boundary."""
        head = run_smoke.LINE_HEAD
        return {self.scan(data, chunk=chunk)[0]
                for chunk in (1, 3, 4, 8, head - 1, head, head + 1, head + 2, 64 * 1024)}

    def test_word_continuing_after_done_is_not_completion(self):
        # DONE ends exactly at the end of the bounded line prefix.
        padding = b" " * (run_smoke.LINE_HEAD - len(b"#1DONE"))
        for data in [b"#1" + padding + b"DONEX\n", b"#1" + padding + b"DONEX",
                     b"#1" + padding + b"DONE_" + b"x" * 500 + b"\n",
                     b"#9 DONEX\n", b"#9 DONE_\n", b"#9 DONEX"]:
            with self.subTest(data=data[-12:]):
                self.assertEqual(self.scan_all_chunkings(data), {False})

    def test_real_delimiter_or_end_after_done_is_completion(self):
        padding = b" " * (run_smoke.LINE_HEAD - len(b"#1DONE"))
        for data in [b"#1" + padding + b"DONE\n", b"#1" + padding + b"DONE",
                     b"#1" + padding + b"DONE cov: 1" + b"x" * 500 + b"\n",
                     b"#1" + padding + b"DONE\t" + b"x" * 500,
                     b"#9 DONE\n", b"#9 DONE", b"line\n#1000\tDONE   cov: 2 ft: 3\n"]:
            with self.subTest(data=data[-12:]):
                self.assertEqual(self.scan_all_chunkings(data), {True})

    def test_completion_beyond_the_bounded_prefix_is_not_accepted(self):
        # Fails closed: the marker must lie within the first LINE_HEAD bytes.
        padding = b" " * (run_smoke.LINE_HEAD - len(b"#1DONE") + 1)
        self.assertEqual(self.scan_all_chunkings(b"#1" + padding + b"DONE\n"), {False})

    def test_completion_counts_only_at_a_line_start(self):
        completed, markers = self.scan(b"note #9 DONE\n" + b"a" * 20 + b"#9 DONE\n", chunk=8)
        self.assertFalse(completed)
        self.assertEqual(markers, [])


class GroupCleanupOrderTests(unittest.TestCase):
    """The leader must still be unreaped when its process group is signaled."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qsh-smoke-order-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def run_ordered(self, code, wall_timeout):
        signaled = []
        real_killpg = os.killpg

        def recording_killpg(pgid, signum):
            # Raises ChildProcessError if the leader was already reaped.
            state = os.waitid(os.P_PID, pgid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            signaled.append((pgid, signum, state is not None))
            return real_killpg(pgid, signum)

        with mock.patch.object(run_smoke.os, "killpg", side_effect=recording_killpg):
            status = run_smoke.run([sys.executable, "-c", code], self.root / "run.log",
                                   wall_timeout)
        self.assertEqual(len(signaled), 1)
        self.assertEqual(signaled[0][1], signal.SIGKILL)
        return status, signaled[0][2]

    def test_normal_exit(self):
        self.assertEqual(self.run_ordered("pass", 10), (0, True))

    def test_signal_exit(self):
        code = "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"
        self.assertEqual(self.run_ordered(code, 10), (-signal.SIGTERM, True))

    def test_timeout(self):
        self.assertEqual(self.run_ordered("import time; time.sleep(60)", 1), (None, False))


if __name__ == "__main__":
    unittest.main()
