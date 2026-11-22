"""Synthetic parser controls, never evidence that Rust/runtime fixtures executed."""
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
ALLOWED = (
    "drop_worker_privileges_refuses_without_root",
    "own_capability_sets_parses_and_reports_none_for_an_ordinary_process",
    "an_undeliverable_signal_is_reported_to_the_helper",
    "a_rotation_that_cannot_rename_is_reported_and_bounds_file_growth",
)


def library_gate():
    lines = (ROOT / ".github/workflows/ci.yml").read_text().splitlines()
    starts = [i for i, line in enumerate(lines)
              if line.strip().startswith("run_suite lib qshd --ignored ")]
    if len(starts) != 1:
        raise AssertionError("expected exactly one System library gate")
    block = []
    for line in lines[starts[0]:]:
        block.append(line.strip().removesuffix("\\"))
        if not line.rstrip().endswith("\\"):
            break
    args = shlex.split(" ".join(block))[3:]
    required = []
    ignored = None
    while args and args[0] in ("--ignored", "--require"):
        flag, value, *args = args
        if flag == "--ignored":
            ignored = int(value)
        else:
            required.append(value)
    return ignored, required, args


def synthetic_log(required, *, missing=None, renamed=None, ignored=None,
                  failed=None, body_count=75, filtered=0):
    """Well-counted synthetic outcomes isolate each gate's refusal condition."""
    outcomes = []
    for name in required:
        if name == missing:
            continue
        if name == renamed:
            name += "_renamed"
        status = "ignored" if name == ignored else "FAILED" if name == failed else "ok"
        outcomes.append((name, status))
    # A required ignored wrapper replaces one synthetic ignored body, so the
    # total remains 75: rejection cannot depend only on a count mismatch.
    bodies = body_count - sum(status == "ignored" for _, status in outcomes)
    outcomes.extend((f"synthetic_parser_body_{i}", "ignored") for i in range(bodies))
    passed = sum(status == "ok" for _, status in outcomes)
    failures = sum(status == "FAILED" for _, status in outcomes)
    skipped = sum(status == "ignored" for _, status in outcomes)
    result = "FAILED" if failures else "ok"
    return "\n".join([
        *(f"test {name} ... {status}" for name, status in outcomes),
        f"test result: {result}. {passed} passed; {failures} failed; {skipped} ignored; "
        f"0 measured; {filtered} filtered out; finished in 0.00s", "",
    ])


class NoSilentSkipsControls(unittest.TestCase):
    parser_invocations = 0

    @classmethod
    def tearDownClass(cls):
        print(f"Synthetic parser invocations: {cls.parser_invocations}")

    def setUp(self):
        _, required, _ = library_gate()
        self.required = tuple(dict.fromkeys(required))

    def check_log(self, log, required=None):
        required = self.required if required is None else required
        with tempfile.TemporaryDirectory(prefix="parser-controls-") as directory:
            path = Path(directory) / "synthetic.log"
            path.write_text(log)
            env = os.environ.copy()
            env.update(HOME=directory, XDG_CONFIG_HOME=directory,
                       XDG_CACHE_HOME=directory, TMPDIR=directory, HISTFILE="/dev/null")
            env.pop("SSH_AUTH_SOCK", None)
            env.pop("SSH_AGENT_PID", None)
            args = ["sh", str(ROOT / "scripts/no-silent-skips.sh"), str(path), "--ignored", "75"]
            for name in required:
                args.extend(["--require", name])
            args.extend(ALLOWED)
            result = subprocess.run(args, env=env, text=True, capture_output=True, timeout=10)
            type(self).parser_invocations += 1
            return result

    def test_workflow_requires_exact_reviewed_union(self):
        ignored, required, allowed = library_gate()
        self.assertEqual(ignored, 75)
        self.assertTrue(required, "the System library gate requires its wrappers")
        self.assertEqual(tuple(allowed), ALLOWED)
        self.assertIn("python3 -I -B scripts/tests/test_no_silent_skips.py -v",
                      (ROOT / ".github/workflows/ci.yml").read_text())

    def test_complete_nonzero_union_passes(self):
        result = self.check_log(synthetic_log(self.required))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_each_missing_wrapper_refuses(self):
        for name in self.required:
            with self.subTest(wrapper=name):
                self.assertNotEqual(self.check_log(synthetic_log(self.required, missing=name)).returncode, 0)

    def test_each_renamed_wrapper_refuses(self):
        for name in self.required:
            with self.subTest(wrapper=name):
                self.assertNotEqual(self.check_log(synthetic_log(self.required, renamed=name)).returncode, 0)

    def test_each_ignored_wrapper_refuses_with_correct_total(self):
        for name in self.required:
            with self.subTest(wrapper=name):
                self.assertNotEqual(self.check_log(synthetic_log(self.required, ignored=name)).returncode, 0)

    def test_each_failed_wrapper_refuses(self):
        for name in self.required:
            with self.subTest(wrapper=name):
                self.assertNotEqual(self.check_log(synthetic_log(self.required, failed=name)).returncode, 0)

    def test_wrong_ignored_count_refuses(self):
        for count in (44, 74, 76, 102, 119):
            self.assertNotEqual(self.check_log(synthetic_log(self.required, body_count=count)).returncode, 0)

    def test_zero_passed_refuses_without_requiring_a_wrapper(self):
        self.assertNotEqual(self.check_log(synthetic_log(()), required=()).returncode, 0)

    def test_unexpected_runtime_skip_refuses(self):
        self.assertNotEqual(self.check_log("SKIPPED unexpected_parser_control: synthetic\n" +
                                         synthetic_log(self.required)).returncode, 0)

    def test_any_filtered_out_refuses(self):
        self.assertNotEqual(self.check_log(synthetic_log(self.required, filtered=1)).returncode, 0)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(__import__(__name__))
    count = suite.countTestCases()
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if count > 0 and result.wasSuccessful() and not result.skipped else 1)
