"""Controls for ordinary nextest reporting; no workspace tests are launched."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

SCRIPTS = Path(__file__).resolve().parents[1]


def load_module():
    spec = importlib.util.spec_from_file_location("nextest_report", SCRIPTS / "nextest_report.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.module = load_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.report = Path(self.temp.name) / "report.xml"
        self.expected = {("qshd", "tests::root"): {"reason": "needs root", "owner": "system container"}}

    def write(self, cases):
        root = ET.Element("testsuites", tests=str(len(cases)), failures="0", errors="0")
        suite = ET.SubElement(root, "testsuite", name="qshd", tests=str(len(cases)), failures="0", errors="0")
        for name, state, output in cases:
            case = ET.SubElement(suite, "testcase", classname="qshd", name=name)
            if state in ("stdout", "stderr"):
                ET.SubElement(case, "system-out").text = output if state == "stdout" else ""
                ET.SubElement(case, "system-err").text = output if state == "stderr" else ""
            elif state == "pass":
                ET.SubElement(case, "system-out").text = ""
                ET.SubElement(case, "system-err").text = ""
            else:
                ET.SubElement(case, state, message=output)
        ET.ElementTree(root).write(self.report, encoding="utf-8", xml_declaration=True)

    def check(self, cases, expected=None):
        self.write(cases)
        return self.module.check_report(self.report, self.expected if expected is None else expected)

    def test_cache_authority_privilege_exclusion_has_exact_owner_and_identity(self):
        expected = self.module.load_exclusions(SCRIPTS / "nextest-exclusions.json")
        key = ("qsh::release_cache_authority_privilege", "release_cache_root_readonly_and_foreign_owner_boundaries")
        self.assertEqual(expected[key]["owner"], "CI container job: run_suite test release_cache_authority_privilege")
        self.assertEqual([entry for entry in expected if "release_cache_authority" in entry[0]], [key])
        expression = self.module.exclusion_filter({key: expected[key]})
        self.assertIn("binary_id(=qsh::release_cache_authority_privilege)", expression)
        self.assertIn("test(=release_cache_root_readonly_and_foreign_owner_boundaries)", expression)

    def test_ssh_host_authority_exclusion_has_one_exact_root_owner(self):
        expected = self.module.load_exclusions(SCRIPTS / "nextest-exclusions.json")
        key = ("qsh::ssh_known_hosts_authority_privilege", "ssh_known_hosts_real_owner_read_and_append_boundaries")
        self.assertEqual([item for item in expected if item[0] == key[0]], [key])
        self.assertEqual(expected[key]["owner"], "CI container job: run_suite test ssh_known_hosts_authority_privilege")
        self.assertEqual(self.module.exclusion_filter({key: expected[key]}),
                         "not ((binary_id(=qsh::ssh_known_hosts_authority_privilege) & test(=ssh_known_hosts_real_owner_read_and_append_boundaries)))")

    def test_expected_exclusions_are_distinct_from_executed_tests(self):
        result = self.check([("tests::root", "skipped", self.module.FILTER_REASON),
                             ("tests::safe", "stdout", "<&> ordinary output"),
                             ("tests::body", "skipped", self.module.IGNORE_REASON)])
        self.assertEqual(result, (1, [("qshd", "tests::root")], [("qshd", "tests::body")]))

    def test_qsh_pin_privilege_has_one_exact_disposable_owner(self):
        expected = self.module.load_exclusions(SCRIPTS / "nextest-exclusions.json")
        binary = "sshauth::qsh_pin_authority_privilege"
        name = "qsh_pin_real_account_root_read_and_mutation_boundaries"
        matches = {key: value for key, value in expected.items() if key[0] == binary}
        self.assertEqual(list(matches), [(binary, name)])
        self.assertEqual(matches[(binary, name)]["owner"], "CI container job: QSH pin ownership boundary")
        self.assertIn(f"(binary_id(={binary}) & test(={name}))", self.module.exclusion_filter(expected))
        root = ET.Element("testsuites", tests="2", failures="0", errors="0")
        suite = ET.SubElement(root, "testsuite", name=binary, tests="2", failures="0", errors="0")
        case = ET.SubElement(suite, "testcase", classname=binary, name=name)
        skip = ET.SubElement(case, "skipped", message=self.module.FILTER_REASON)
        ordinary = ET.SubElement(suite, "testcase", classname=binary, name="ordinary")
        ET.SubElement(ordinary, "system-out").text = ""
        ET.SubElement(ordinary, "system-err").text = ""
        ET.ElementTree(root).write(self.report)
        self.assertEqual(self.module.check_report(self.report, matches), (1, [(binary, name)], []))
        skip.set("message", self.module.IGNORE_REASON)
        ET.ElementTree(root).write(self.report)
        with self.assertRaises(ValueError):
            self.module.check_report(self.report, matches)

    def test_successful_runtime_skips_fail_with_actual_identity(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                self.write([("tests::safe", stream, "SKIPPED tests::root: deception")])
                with self.assertRaisesRegex(ValueError, "qshd.*tests::safe.*SKIPPED"):
                    self.module.check_report(self.report, {})

    def test_malformed_or_unknown_marker_is_not_allowed(self):
        for marker in ("SKIPPED:", "SKIPPED unknown", "beforeSKIPPEDafter"):
            with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, "SKIPPED"):
                self.check([("tests::safe", "stderr", marker)], {})

    def test_exclusion_must_be_present_and_filtered_not_passed_or_ignored(self):
        for cases in ([('tests::safe', 'pass', '')],
                      [('tests::root', 'pass', '')],
                      [('tests::root', 'skipped', self.module.IGNORE_REASON)]):
            with self.subTest(cases=cases), self.assertRaises(ValueError):
                self.check(cases)

    def test_unreviewed_exclusion_and_unknown_skip_reason_fail(self):
        for reason in (self.module.FILTER_REASON, "Skipped: arbitrary"):
            with self.subTest(reason=reason), self.assertRaises(ValueError):
                self.check([("tests::safe", "pass", ""), ("tests::other", "skipped", reason)], {})

    def test_failure_error_and_retried_failure_fail(self):
        for state in ("failure", "error", "rerunFailure", "flakyFailure"):
            with self.subTest(state=state), self.assertRaises(ValueError):
                self.check([("tests::safe", state, "failed")], {})

    def test_missing_capture_cannot_pass(self):
        self.write([("tests::safe", "pass", "")])
        root = ET.parse(self.report)
        root.find(".//testcase").remove(root.find(".//system-out"))
        root.write(self.report)
        with self.assertRaisesRegex(ValueError, "captur"):
            self.module.check_report(self.report, {})

    def test_duplicate_and_misleading_classname_fail(self):
        with self.assertRaises(ValueError):
            self.check([("tests::safe", "pass", ""), ("tests::safe", "pass", "")], {})
        self.write([("tests::safe", "pass", "")])
        tree = ET.parse(self.report)
        tree.find(".//testcase").set("classname", "forged")
        tree.write(self.report)
        with self.assertRaises(ValueError):
            self.module.check_report(self.report, {})

    def test_missing_malformed_empty_and_zero_execution_fail(self):
        for content in (None, "", "<broken", "<testsuites/>", '<testsuites><testsuite name="x"/></testsuites>'):
            with self.subTest(content=content):
                if content is None:
                    self.report.unlink(missing_ok=True)
                else:
                    self.report.write_text(content)
                with self.assertRaises(ValueError):
                    self.module.check_report(self.report, {})

    def test_summary_failure_cannot_disagree_with_cases(self):
        self.write([("tests::safe", "pass", "")])
        tree = ET.parse(self.report)
        tree.getroot().set("failures", "1")
        tree.write(self.report)
        with self.assertRaises(ValueError):
            self.module.check_report(self.report, {})


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.report = self.root / "report.xml"
        self.manifest = self.root / "manifest.json"
        self.manifest.write_text(json.dumps({"exclusions": []}))
        self.fake = self.root / "runner.py"
        self.fake.write_text('''import pathlib,sys,tomllib
args=sys.argv[1:]
assert "--ignore-default-filter" in args, "runner must own the entire ordinary filter"
config=pathlib.Path(args[args.index("--tool-config-file")+1].split(":",1)[1])
path=pathlib.Path(tomllib.loads(config.read_text())["profile"]["ci"]["junit"]["path"])
with path.with_suffix(".calls").open("a") as f: f.write("call\\n")
mode=args[0]
if mode != "missing":
 path.write_text('<testsuites><testsuite name="fixture" tests="1" failures="0" errors="0"><testcase name="safe" classname="fixture"><system-out>'+('SKIPPED injected' if mode == 'skip' else '')+'</system-out><system-err/></testcase></testsuite></testsuites>')
sys.exit(7 if mode == "fail" else 0)
''')

    def run_wrapper(self, mode):
        return subprocess.run([sys.executable, str(SCRIPTS / "run-nextest-ci.py"),
                               "--report", str(self.report), "--manifest", str(self.manifest), "--",
                               sys.executable, str(self.fake), mode], capture_output=True, text=True)

    def test_runner_executes_once(self):
        result = self.run_wrapper("pass")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.report.with_suffix(".calls").read_text(), "call\n")
        self.assertIn("1 executed", result.stdout)

    def test_runner_failure_survives_valid_report(self):
        result = self.run_wrapper("fail")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("runner exited 7", result.stderr)

    def test_successful_skip_fails_wrapper(self):
        result = self.run_wrapper("skip")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("SKIPPED", result.stderr)

    def test_stale_report_is_removed_before_missing_report_run(self):
        self.run_wrapper("pass")
        result = self.run_wrapper("missing")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.report.exists())


@unittest.skipUnless(os.environ.get("QSH_TEST_NEXTEST"), "set QSH_TEST_NEXTEST to run the pinned executable control")
class PinnedNextestTests(unittest.TestCase):
    def test_real_success_output_detects_skip_without_repeating_or_serializing_tests(self):
        with tempfile.TemporaryDirectory(prefix="qsh-nextest-control-") as temp:
            root = Path(temp)
            (root / "src").mkdir()
            (root / "Cargo.toml").write_text('[package]\nname="skip-fixture"\nversion="0.0.0"\nedition="2021"\n')
            (root / "src/lib.rs").write_text(r'''use std::{fs, thread, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};
fn run(name: &str) {
    let dir = std::env::var("QSH_FIXTURE_TRACE").unwrap();
    let start = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    fs::write(format!("{dir}/{name}.ready"), b"ready").unwrap();
    let peer = if name == "one" { "two" } else { "one" };
    let deadline = Instant::now() + Duration::from_secs(10);
    while !std::path::Path::new(&format!("{dir}/{peer}.ready")).exists() {
        assert!(Instant::now() < deadline, "peer test must run concurrently");
        thread::yield_now();
    }
    let end = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    use std::io::Write;
    let mut f = fs::OpenOptions::new().create(true).append(true).open(format!("{dir}/{name}")).unwrap();
    writeln!(f, "{start} {end}").unwrap();
}
#[test] fn one() { run("one"); println!("ordinary <&> stdout"); }
#[test] fn two() { run("two"); eprintln!("SKIPPED excluded: injected unexpected runtime skip"); }
#[test] fn excluded() { panic!("must not execute"); }
#[test] #[ignore = "owned subprocess fixture"] fn body() {}
''')
            # This fixture asserts the pinned CLI summary as plain text;
            # scope color selection to its subprocesses, independent of CI.
            env = dict(os.environ, HISTFILE="/dev/null", QSH_FIXTURE_TRACE=str(root),
                       CARGO_TERM_COLOR="never")
            env["CARGO_HOME"] = os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))
            env["RUSTUP_HOME"] = os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup"))
            env.update(HOME=str(root), XDG_CONFIG_HOME=str(root / "config"), XDG_CACHE_HOME=str(root / "cache"))
            subprocess.run(["rustc", "--test", str(root / "src/lib.rs"), "-o", str(root / "fixture")], check=True, env=env, capture_output=True)
            metadata = subprocess.run(["cargo", "metadata", "--manifest-path", str(root / "Cargo.toml"),
                                       "--format-version", "1", "--no-deps"], env=env, check=True, capture_output=True, text=True)
            (root / "cargo.json").write_text(metadata.stdout)
            package = json.loads(metadata.stdout)["packages"][0]["id"]
            binaries = {"rust-build-meta": {"target-directory": str(root / "target"),
                        "base-output-directories": ["debug"], "non-test-binaries": {}, "linked-paths": []},
                        "rust-binaries": {"skip-fixture": {"binary-id": "skip-fixture", "binary-name": "skip_fixture",
                        "package-id": package, "kind": "lib", "binary-path": str(root / "fixture"), "build-platform": "target"}}}
            (root / "binaries.json").write_text(json.dumps(binaries))
            (root / "nextest.toml").write_text('[profile.ci]\ntest-threads=4\nretries=0\nfail-fast=false\ndefault-filter="none()"\n')
            (root / "manifest.json").write_text(json.dumps({"exclusions": [{"binary": "skip-fixture", "tests": ["excluded"],
                                                      "reason": "fixture exclusion", "owner": "fixture control"}]}))
            command = [sys.executable, str(SCRIPTS / "run-nextest-ci.py"), "--manifest", str(root / "manifest.json"),
                       "--report", str(root / "report.xml"), "--", os.environ["QSH_TEST_NEXTEST"], "nextest", "run",
                       "--cargo-metadata", str(root / "cargo.json"), "--binaries-metadata", str(root / "binaries.json"),
                       "--config-file", str(root / "nextest.toml"), "--user-config-file", "none", "--profile", "ci"]
            result = subprocess.run(command, env=env, capture_output=True, text=True, cwd=root)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("2 passed", result.stderr)
            self.assertIn("skip-fixture / two: unexpected runtime SKIPPED", result.stderr)
            self.assertNotIn("runner exited", result.stderr)
            intervals = []
            for name in ("one", "two"):
                lines = (root / name).read_text().splitlines()
                self.assertEqual(len(lines), 1, "each selected fixture must execute once")
                intervals.append(tuple(map(int, lines[0].split())))
            self.assertLess(max(start for start, _ in intervals), min(end for _, end in intervals),
                            "fixture executions must overlap")
            report = ET.parse(root / "report.xml")
            skip = {case.get("name"): case.find("skipped").get("message")
                    for case in report.findall(".//testcase") if case.find("skipped") is not None}
            module = load_module()
            self.assertEqual(skip, {"excluded": module.FILTER_REASON, "body": module.IGNORE_REASON})


if __name__ == "__main__":
    unittest.main()
