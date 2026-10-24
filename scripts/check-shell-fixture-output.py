#!/usr/bin/env python3
"""Require actual execution, not just a successful fixture test process."""
import argparse
from pathlib import Path
import re
import sys


def check(output: str, expected: int, status: int) -> None:
    if status != 0:
        raise ValueError(f"fixture exited with status {status}")
    if expected <= 0:
        raise ValueError("expected fixture count must be positive")
    if re.search(r"\bSKIPPED\b", output, re.IGNORECASE):
        raise ValueError("fixture reported a runtime skip")
    summaries = re.findall(
        r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored; "
        r"(\d+) measured; (\d+) filtered out; finished in .+$",
        output, re.MULTILINE,
    )
    if len(summaries) != 1 or tuple(map(int, summaries[0])) != (expected, 0, 0, 0, 0):
        raise ValueError("fixture must report every listed test passed with no ignored or filtered tests")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("expected", type=int)
    parser.add_argument("status", type=int)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        check(args.log.read_text(), args.expected, args.status)
    except (OSError, ValueError) as error:
        print(f"shell fixture acceptance failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
