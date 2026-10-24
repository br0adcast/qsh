"""The disposable shell tier must reject successful-but-unexecuted suites."""
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location(
    "shell_fixture_output", Path(__file__).parents[1] / "check-shell-fixture-output.py"
)
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)


def summary(passed=2, failed=0, ignored=0, filtered=0):
    return (f"test result: ok. {passed} passed; {failed} failed; {ignored} ignored; "
            f"0 measured; {filtered} filtered out; finished in 0.01s\n")


class OutputControls(unittest.TestCase):
    def test_accepts_every_expected_assertion_executed(self):
        checker.check("running 2 tests\ntest one ... ok\ntest two ... ok\n" + summary(), 2, 0)

    def test_rejects_zero_execution_even_on_success(self):
        with self.assertRaises(ValueError):
            checker.check(summary(passed=0), 2, 0)

    def test_rejects_ignored_tests_even_on_success(self):
        with self.assertRaises(ValueError):
            checker.check(summary(passed=0, ignored=2), 2, 0)

    def test_rejects_runtime_skip_even_with_successful_summary(self):
        with self.assertRaises(ValueError):
            checker.check("SKIPPED: required sshd absent\n" + summary(), 2, 0)

    def test_rejects_failure_status_even_with_successful_summary(self):
        with self.assertRaises(ValueError):
            checker.check(summary(), 2, 101)

    def test_rejects_partial_filtered_or_failed_summaries(self):
        for output in [summary(passed=1), summary(filtered=1), summary(failed=1), summary() * 2, ""]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                checker.check(output, 2, 0)


if __name__ == "__main__":
    unittest.main()
