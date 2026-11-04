"""Synthetic byte and nm controls; never build or inspect a real product."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_paths", ROOT / "scripts/check-native-verifier-paths.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
PREFIXES = ("PRIVATE_WORKSPACE_CANARY", "PRIVATE_CARGO_CANARY", "PRIVATE_TEMP_CANARY")


class NativeVerifierPathTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="native-path-control-")
        self.addCleanup(self.directory.cleanup)
        self.binary = Path(self.directory.name) / "PRIVATE_BINARY_CANARY"

    def invoke(self, data, *, prefixes=PREFIXES, platform="linux", tool=None, args=None):
        self.binary.write_bytes(data)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(checker.sys, "platform", platform), \
                mock.patch.object(checker.subprocess, "run", side_effect=tool) as run, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = checker.main(args if args is not None else [str(self.binary), *prefixes])
        public = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("PRIVATE_", public)
        self.assertLess(len(public), 2048)
        self.assertEqual(stdout.getvalue(), "")
        report = json.loads(stderr.getvalue()) if stderr.getvalue().startswith("{") else None
        return status, report, run, public

    @staticmethod
    def nm_result(rows=b"", status=0):
        def run(command, **kwargs):
            assert command[:2] == ["/usr/bin/nm", "-pa"] and len(command) == 3
            assert kwargs["stdin"] == subprocess.DEVNULL
            assert kwargs["stderr"] == subprocess.DEVNULL
            assert kwargs["timeout"] == 15 and kwargs["env"]["LC_ALL"] == "C"
            kwargs["stdout"].write(rows)
            return subprocess.CompletedProcess(command, status)
        return run

    def test_matched_artifact_reports_only_bounded_metadata(self):
        data = b"\0" + PREFIXES[0].encode() + b"\xff"
        status, report, run, _ = self.invoke(data)
        self.assertEqual(status, 1)
        self.assertIsNotNone(report, "matched artifact lacked bounded category metadata")
        self.assertEqual(report, {
            "binary_sha256": hashlib.sha256(data).hexdigest(), "binary_bytes": len(data),
            "workspace_occurrences": 1, "cargo_home_occurrences": 0,
            "runner_temp_occurrences": 0, "nm_status": "not_requested",
            "oso_records": None, "unparsed_rows": None,
            "oso_records_with_prefix": None, "other_symbol_records_with_prefix": None})
        run.assert_not_called()

    def test_clean_artifact_does_not_launch_nm_even_on_darwin(self):
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform):
                status, report, run, public = self.invoke(b"\0\xffclean", platform=platform)
                self.assertEqual((status, report, public), (0, None, ""))
                run.assert_not_called()

    def test_each_category_repeated_and_overlapping_prefixes(self):
        for index, category in enumerate(checker.CATEGORIES):
            with self.subTest(category=category):
                status, report, _, _ = self.invoke(b"\0" + (PREFIXES[index].encode() + b"\xff") * 2)
                self.assertEqual(status, 1)
                self.assertEqual(report[category + "_occurrences"], 2)
        status, report, _, _ = self.invoke(b"ababa", prefixes=("aba", "ab", "aba"))
        self.assertEqual(status, 1)
        self.assertEqual([report[c + "_occurrences"] for c in checker.CATEGORIES], [1, 2, 1])

    def test_nontext_fsencoded_prefix_is_scanned_byte_for_byte(self):
        prefix = os.fsdecode(b"PRIVATE_NON_TEXT_\xff")
        status, report, _, _ = self.invoke(b"\0" + os.fsencode(prefix), prefixes=(prefix, *PREFIXES[1:]))
        self.assertEqual(status, 1)
        self.assertEqual(report["workspace_occurrences"], 1)

    def test_structural_oso_and_other_symbols_with_spaces_in_names(self):
        work, cargo, temp = (p.encode() for p in PREFIXES)
        rows = (b"0000000000000000 - 03 0001   OSO " + work + b"/one object.o\n"
                b"0000000000000001 - 03 0001   OSO " + cargo + b"/two.o\n"
                b"0000000000000002 - 00 0000    SO " + temp + b"/source.rs\n"
                b"0000000000000003 T _OSO_in_symbol_name_" + work + b"/with spaces\n"
                b"                 U _undefined\n")
        status, report, run, _ = self.invoke(work + cargo + temp, platform="darwin", tool=self.nm_result(rows))
        self.assertEqual(status, 1)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0][2], str(self.binary))
        self.assertEqual(report["nm_status"], "ok")
        self.assertEqual(report["oso_records"], 2)
        self.assertEqual(report["oso_records_with_prefix"], {"workspace": 1, "cargo_home": 1, "runner_temp": 0})
        self.assertEqual(report["other_symbol_records_with_prefix"], {"workspace": 1, "cargo_home": 0, "runner_temp": 1})
        self.assertEqual(report["unparsed_rows"], 0)

    def test_symbol_categories_count_equal_prefixes_independently(self):
        prefix = PREFIXES[0]
        rows = b"0000000000000000 - 03 0001   OSO " + prefix.encode() + b"/object.o\n"
        status, report, _, _ = self.invoke(prefix.encode(), prefixes=(prefix, prefix, prefix),
                                           platform="darwin", tool=self.nm_result(rows))
        self.assertEqual(status, 1)
        self.assertEqual(report["oso_records"], 1)
        self.assertEqual(report["oso_records_with_prefix"], dict.fromkeys(checker.CATEGORIES, 1))

    def test_zero_oso_does_not_allow_binary_match_outside_symbols(self):
        for rows in (b"", b"0000000000000000 T _symbol_named_OSO\n"):
            with self.subTest(empty=not rows):
                status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=self.nm_result(rows))
                self.assertEqual(status, 1)
                self.assertEqual(report["nm_status"], "ok")
                self.assertEqual(report["oso_records"], 0)
                self.assertEqual(report["oso_records_with_prefix"]["workspace"], 0)

    def test_malformed_unsupported_and_partial_rows_are_not_complete_attribution(self):
        invalid = [b"PRIVATE_MALFORMED_CANARY\n", b"0000000000000000 - zz 0001 OSO PRIVATE_SYMBOL_CANARY\n",
                   b"0000000000000000 - 03 0001 UNKNOWN PRIVATE_SYMBOL_CANARY\n"]
        valid = b"0000000000000000 - 03 0001   OSO " + PREFIXES[0].encode() + b"/object.o\n"
        for rows in invalid + [valid + invalid[0]]:
            with self.subTest(partial=rows.startswith(valid)):
                status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=self.nm_result(rows))
                self.assertEqual(status, 1)
                self.assertEqual(report["nm_status"], "partial")
                self.assertEqual(report["unparsed_rows"], 1)

    def test_nm_failures_are_fixed_statuses_and_never_allow_a_match(self):
        cases = [(self.nm_result(b"PRIVATE_STDOUT_CANARY", 2), "failed"),
                 (FileNotFoundError("PRIVATE_EXCEPTION_CANARY"), "unavailable"),
                 (PermissionError("PRIVATE_EXCEPTION_CANARY"), "io_error"),
                 (subprocess.TimeoutExpired("PRIVATE_COMMAND_CANARY", 15,
                                            output=b"PRIVATE_OUTPUT_CANARY", stderr=b"PRIVATE_STDERR_CANARY"), "timeout")]
        for tool, expected in cases:
            with self.subTest(status=expected):
                status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=tool)
                self.assertEqual(status, 1)
                self.assertEqual(report["nm_status"], expected)
                for key in ("oso_records", "unparsed_rows", "oso_records_with_prefix", "other_symbol_records_with_prefix"):
                    self.assertIsNone(report[key])

    def test_oversize_output_is_not_read_or_attributed(self):
        def oversize(command, **kwargs):
            kwargs["stdout"].truncate(checker.MAX_NM_BYTES + 1)
            return subprocess.CompletedProcess(command, 0)
        status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=oversize)
        self.assertEqual(status, 1)
        self.assertEqual(report["nm_status"], "oversize")
        self.assertIsNone(report["oso_records"])

    def test_private_nm_files_are_closed_on_every_outcome(self):
        original = checker.tempfile.TemporaryFile
        def oversize(command, **kwargs):
            kwargs["stdout"].truncate(checker.MAX_NM_BYTES + 1)
            return subprocess.CompletedProcess(command, 0)
        for tool in (self.nm_result(), self.nm_result(b"PRIVATE_MALFORMED_CANARY"),
                     self.nm_result(status=2), oversize, FileNotFoundError("PRIVATE_EXCEPTION_CANARY"),
                     PermissionError("PRIVATE_EXCEPTION_CANARY"),
                     subprocess.TimeoutExpired("PRIVATE_COMMAND_CANARY", 15)):
            opened = []
            def temporary(*args, **kwargs):
                stream = original(*args, dir=self.directory.name, **kwargs)
                self.assertEqual(os.fstat(stream.fileno()).st_mode & 0o777, 0o600)
                opened.append(stream)
                return stream
            with mock.patch.object(checker.tempfile, "TemporaryFile", side_effect=temporary):
                status, _, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=tool)
            self.assertEqual(status, 1)
            self.assertEqual(len(opened), 1)
            self.assertTrue(opened[0].closed)
            self.assertEqual(list(Path(self.directory.name).iterdir()), [self.binary])

    def test_private_file_creation_failure_keeps_fixed_refusal(self):
        for error in (OSError("PRIVATE_TEMP_CANARY"), FileNotFoundError("PRIVATE_TEMP_CANARY")):
            with mock.patch.object(checker.tempfile, "TemporaryFile", side_effect=error):
                status, report, run, _ = self.invoke(PREFIXES[0].encode(), platform="darwin")
            self.assertEqual(status, 1)
            self.assertEqual(report["nm_status"], "io_error")
            run.assert_not_called()

    def test_invalid_arguments_and_unreadable_artifacts_do_not_leak(self):
        cases = [[], ["PRIVATE_ARG_CANARY"], [str(self.binary), "", *PREFIXES[1:]],
                 [str(self.binary), *PREFIXES, "PRIVATE_EXTRA_CANARY"],
                 [str(self.binary) + "PRIVATE_MISSING_CANARY", *PREFIXES],
                 [str(self.binary.parent), *PREFIXES], ["PRIVATE_NUL_CANARY\0", *PREFIXES]]
        for args in cases:
            with self.subTest(argc=len(args)):
                status, report, run, public = self.invoke(b"clean", args=args)
                self.assertEqual(status, 1)
                self.assertIsNone(report)
                self.assertIn(public, ("release verifier path check refused: invalid_input\n",
                                       "release verifier path check refused: unreadable_artifact\n"))
                run.assert_not_called()

    def real_tool_control(self, body, *, timeout=None):
        # Redirect the private subprocess seam to our owned harmless Python child.
        # Production still requests only the fixed nm command; no product is run.
        original_run, original_popen = subprocess.run, subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            children.append(child)
            return child
        def tool(command, **kwargs):
            self.assertEqual(command, ["/usr/bin/nm", "-pa", str(self.binary)])
            self.assertEqual(kwargs["timeout"], 15)
            if timeout is not None:
                kwargs["timeout"] = timeout
            return original_run([sys.executable, "-I", "-B", "-c", body], **kwargs)
        with mock.patch.object(subprocess, "Popen", side_effect=spawn):
            status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=tool)
        self.assertEqual(status, 1)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)
        return report

    def test_real_tool_stdout_stderr_are_private_and_child_is_reaped(self):
        report = self.real_tool_control(
            "import os; os.write(1, b'0000000000000000 - 03 0001   OSO PRIVATE_SYMBOL_CANARY\\n'); "
            "os.write(2, b'PRIVATE_STDERR_CANARY')")
        self.assertEqual(report["nm_status"], "ok")
        self.assertEqual(report["oso_records"], 1)

    def test_real_timeout_kills_and_reaps_only_the_owned_child(self):
        report = self.real_tool_control("import time; canary='PRIVATE_TIMEOUT_CANARY'; time.sleep(60)", timeout=0.05)
        self.assertEqual(report["nm_status"], "timeout")

    def test_old_and_new_whole_byte_predicates_are_equivalent(self):
        for data in (b"", b"\0\xff", *(p.encode() for p in PREFIXES),
                     b"\0" + PREFIXES[0].encode() + b"\xff" + PREFIXES[2].encode()):
            expected = int(any(os.fsencode(path) in data for path in PREFIXES))
            with self.subTest(size=len(data)):
                status, _, run, _ = self.invoke(data)
                self.assertEqual(status, expected)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
