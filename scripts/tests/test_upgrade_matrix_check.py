import importlib.util
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "upgrade-matrix-check.py"
SPEC = importlib.util.spec_from_file_location("upgrade_matrix_check", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC is not None and SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class UpgradeMatrixCheckTest(unittest.TestCase):
    def test_parse_single_test_pass_accepts_exact_pass(self):
        out = (
            "running 1 test\n"
            "test upgrade_matrix_tests::scenario3_managed_daemon_never_prompts_idle_or_busy ... ok\n\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 1.23s\n"
        )
        self.assertTrue(
            MODULE.parse_single_test_pass(
                out,
                "upgrade_matrix_tests::scenario3_managed_daemon_never_prompts_idle_or_busy",
            )
        )

    def test_parse_single_test_pass_rejects_filtered_zero_or_mismatch(self):
        zero = "running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 99 filtered out; finished in 0.00s\n"
        self.assertFalse(MODULE.parse_single_test_pass(zero, "upgrade_matrix_tests::x"))
        other = (
            "running 1 test\n"
            "test upgrade_matrix_tests::other ... ok\n"
            "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n"
        )
        self.assertFalse(MODULE.parse_single_test_pass(other, "upgrade_matrix_tests::x"))

    def test_format_table_contains_all_rows(self):
        table = MODULE.format_table(
            [
                {"layer": "L1-qsh", "name": "s1-busy", "seconds": 4.2, "status": "PASS"},
                {"layer": "L2-v0.5.0", "name": "released-peer", "seconds": 12.0, "status": "FAIL"},
            ]
        )
        self.assertIn("s1-busy", table)
        self.assertIn("4.2s", table)
        self.assertIn("PASS", table)
        self.assertIn("FAIL", table)


if __name__ == "__main__":
    unittest.main()
