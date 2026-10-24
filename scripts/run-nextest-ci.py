#!/usr/bin/env python3
"""Run ordinary nextest once, then reject runtime skips in captured output."""
import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time

from nextest_report import check_report, exclusion_filter, load_exclusions


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("nextest-exclusions.json"))
    parser.add_argument("--report", type=Path, default=Path("target/nextest/ci/junit.xml"))
    parser.add_argument("command", nargs=argparse.REMAINDER,
                        help="command after --; must run nextest with --profile ci")
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a nextest command is required after --")
    try:
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
                                                "--filterset", exclusion_filter(expected)])
            run_time = time.monotonic() - start
        if result.returncode:
            print(f"nextest runner exited {result.returncode}", file=sys.stderr)
        start = time.monotonic()
        executed, excluded, ignored = check_report(report, expected)
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
