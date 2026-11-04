#!/usr/bin/env python3
"""Run ordinary nextest once, then reject runtime skips in captured output."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import os
import re
import xml.etree.ElementTree as ET

from nextest_report import check_report, exclusion_filter, load_exclusions


INSTALL_FIXTURES = tuple("install_fixture_tests::" + name for name in (
    "accept_installs_and_opens_shell", "enter_accepts_installation_and_opens_shell",
    "approval_does_not_authorize_another_host", "ctrl_c_during_install_restores_tty"))

def require_install_fixtures(report):
    """Require all four actual Linux fixture parents, never an empty child hook."""
    root = ET.parse(report).getroot()
    for name in INSTALL_FIXTURES:
        cases = [case for suite in root.findall("testsuite") if suite.get("name") == "qsh"
                 for case in suite.findall("testcase") if case.get("name") == name]
        if len(cases) != 1 or any(cases[0].find(tag) is not None for tag in ("skipped", "failure", "error")):
            raise ValueError(f"required Linux CLI fixture did not execute successfully: {name}")
    return len(INSTALL_FIXTURES)

def daemon_artifact(path):
    """Read the exact executable from this runner's Cargo JSON, with no globs/builds in tests."""
    manifest = Path(__file__).resolve().parents[1] / "qshd/Cargo.toml"
    candidates = set()
    for line in path.read_text().splitlines():
        row = json.loads(line)
        if (row.get("reason") == "compiler-artifact" and row.get("manifest_path") == str(manifest)
                and row.get("target", {}).get("name") == "qshd"
                and row.get("target", {}).get("kind") == ["bin"]
                and row.get("profile", {}).get("test") is False and row.get("executable")):
            candidates.add(row["executable"])
    if len(candidates) != 1:
        raise ValueError("expected one exact qshd executable in owned Cargo JSON")
    daemon = Path(candidates.pop())
    if not daemon.is_absolute() or not daemon.is_file() or not os.access(daemon, os.X_OK):
        raise ValueError("owned Cargo qshd artifact is not an absolute executable file")
    return daemon


def check_exact_libtest(path, name):
    """Validate one deliberately selected library case; unrelated tests stay filtered."""
    text = path.read_text()
    if re.search(r"\bSKIPPED\b", text, re.IGNORECASE):
        raise ValueError("exact library fixture reported a runtime skip")
    headers = re.findall(r"^running (\d+) tests?$", text, re.MULTILINE)
    summaries = re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out; finished in .+$", text, re.MULTILINE)
    outcomes = re.findall(r"^test (.+) \.\.\. (.+)$", text, re.MULTILINE)
    if (headers != ["1"] or len(summaries) != 1
            or tuple(map(int, summaries[0][:4])) != (1, 0, 0, 0)
            or outcomes != [(name, "ok")]):
        raise ValueError(f"exact library fixture must execute only {name}, once, successfully")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-exact-libtest", type=Path, help="validate a focused one-case library test log")
    parser.add_argument("--require-exact-test", help="fully qualified required library test name")
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("nextest-exclusions.json"))
    parser.add_argument("--daemon-artifacts", type=Path, help="Cargo JSON from the immediately preceding owned qshd build")
    parser.add_argument("--require-install-fixtures", action="store_true", help="require all four Linux CLI/SSH fixture cases")
    parser.add_argument("--report", type=Path, default=Path("target/nextest/ci/junit.xml"))
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="command after --; must run nextest with --profile ci")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if args.check_exact_libtest or args.require_exact_test:
        if not (args.check_exact_libtest and args.require_exact_test) or command:
            parser.error("exact libtest checking requires a log/name and no nextest command")
        try:
            check_exact_libtest(args.check_exact_libtest, args.require_exact_test)
            return 0
        except (OSError, ValueError) as error:
            print(f"exact library fixture check failed: {error}", file=sys.stderr)
            return 1
    if not command:
        parser.error("a nextest command is required after --")
    try:
        environment = dict(os.environ)
        if args.daemon_artifacts:
            environment["QSH_TEST_QSHD"] = str(daemon_artifact(args.daemon_artifacts))
        expected = load_exclusions(args.manifest)
        report = args.report.resolve()
        report.parent.mkdir(parents=True, exist_ok=True)
        # A failed or interrupted new run must never reuse a passing old report.
        report.unlink(missing_ok=True)
        with tempfile.TemporaryDirectory(prefix="qsh-nextest-") as temporary:
            config = Path(temporary) / "report.toml"
            config.write_text('[profile.ci.junit]\n'
                              f'path = {json.dumps(str(report))}\n'
                              'store-success-output = true\n'
                              'store-failure-output = true\n'
                              'report-skipped = "all"\n')
            start = time.monotonic()
            result = subprocess.run(command + ["--ignore-default-filter",
                                                "--tool-config-file", f"qsh:{config}",
                                                "--filterset", exclusion_filter(expected)], env=environment)
            run_time = time.monotonic() - start
        if result.returncode:
            print(f"nextest runner exited {result.returncode}", file=sys.stderr)
        start = time.monotonic()
        executed, excluded, ignored = check_report(report, expected)
        if args.require_install_fixtures:
            fixtures = require_install_fixtures(report)
            print(f"Linux CLI fixture coverage: {fixtures} required cases executed")
        check_time = time.monotonic() - start
        for key in excluded:
            item = expected[key]
            print(f"EXPECTED EXCLUSION {key[0]} / {key[1]}: {item['reason']}; owner: {item['owner']}")
        for binary, name in ignored:
            print(f"SOURCE-DECLARED IGNORE {binary} / {name}")
        print(f"nextest coverage: {executed} executed, {len(excluded)} expected environment exclusions, "
              f"{len(ignored)} source-declared ignores")
        print(f"nextest report: {report.stat().st_size} bytes; checker {check_time:.3f}s; runner {run_time:.3f}s")
        return 1 if result.returncode else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"nextest coverage check failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
