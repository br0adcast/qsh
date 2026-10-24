#!/usr/bin/env python3
"""Validate captured nextest 0.9.148 JUnit output for ordinary CI.

Explicit Rust #[ignore] declarations are reported separately. Every filter
exclusion must match the reviewed manifest; executed tests may never emit the
reserved SKIPPED control, even when the name in its text claims an exemption.
"""
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET

FILTER_REASON = "Skipped: test does not match the provided expression filters"
IGNORE_REASON = "Skipped: test does not match the run-ignored option"
IDENTIFIER = re.compile(r"[A-Za-z0-9_:./-]+\Z")


def load_exclusions(path):
    """Return exact (binary-id, full Rust test name) keys with their owners."""
    data = json.loads(Path(path).read_text())
    expected = {}
    for group in data["exclusions"]:
        if not group["reason"] or not group["owner"] or not group["tests"]:
            raise ValueError("each exclusion requires tests, a reason and an owning tier")
        for name in group["tests"]:
            key = (group["binary"], name)
            if not all(IDENTIFIER.fullmatch(part) for part in key):
                raise ValueError(f"invalid exact exclusion identity: {key}")
            if key in expected:
                raise ValueError(f"duplicate exclusion identity: {key}")
            expected[key] = {"reason": group["reason"], "owner": group["owner"]}
    return expected


def exclusion_filter(expected):
    if not expected:
        return "all()"
    return "not (" + " | ".join(
        f"(binary_id(={binary}) & test(={name}))" for binary, name in sorted(expected)
    ) + ")"


def check_report(path, expected):
    """Return executed count, expected exclusions, and source-declared ignores.

    The caller owns report freshness and runner status. Only nextest's structured
    identities are trusted, not names or libtest control lines in test output.
    """
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as error:
        raise ValueError(f"missing or malformed nextest report: {error}") from error
    if root.tag != "testsuites":
        raise ValueError("expected nextest testsuites report")
    seen, excluded, ignored = set(), [], []
    executed = 0
    for summary in [root, *root.findall("testsuite")]:
        for attr in ("failures", "errors"):
            try:
                if int(summary.get(attr, "0")) != 0:
                    raise ValueError(f"report records {attr}")
            except ValueError as error:
                raise ValueError(f"invalid or failing report {attr}") from error
    for suite in root.findall("testsuite"):
        cases = suite.findall("testcase")
        if "tests" in suite.attrib and suite.get("tests") != str(len(cases)):
            raise ValueError(f"incomplete suite: {suite.get('name')}")
        for case in cases:
            key = (suite.get("name"), case.get("name"))
            label = f"{key[0]} / {key[1]}"
            if not all(key) or case.get("classname") != key[0] or key in seen:
                raise ValueError(f"duplicate or invalid test identity: {label}")
            seen.add(key)
            if any(case.find(f".//{tag}") is not None
                   for tag in ("failure", "error", "rerunFailure", "rerunError", "flakyFailure", "flakyError")):
                raise ValueError(f"test failed or retried: {label}")
            for output in case.iter():
                if output.tag in ("system-out", "system-err") and "SKIPPED" in (output.text or ""):
                    raise ValueError(f"{label}: unexpected runtime SKIPPED control")
            skips = case.findall("skipped")
            if skips:
                if len(skips) != 1:
                    raise ValueError(f"invalid skipped status: {label}")
                reason = skips[0].get("message")
                if key in expected and reason == FILTER_REASON:
                    excluded.append(key)
                elif key not in expected and reason == IGNORE_REASON:
                    ignored.append(key)
                else:
                    raise ValueError(f"unexpected exclusion: {label}: {reason}")
            else:
                if key in expected:
                    raise ValueError(f"expected exclusion executed: {label}")
                for stream in ("system-out", "system-err"):
                    node = case.find(stream)
                    if node is None or node.text == f"({stream.replace('system-', 'std')} not captured)":
                        raise ValueError(f"missing captured {stream}: {label}")
                executed += 1
    missing = set(expected) - set(excluded)
    if missing:
        raise ValueError(f"expected exclusions absent from report: {sorted(missing)}")
    if not executed:
        raise ValueError("nextest report contains zero executed tests")
    if "tests" in root.attrib and root.get("tests") != str(len(seen)):
        raise ValueError("incomplete nextest report")
    return executed, sorted(excluded), sorted(ignored)
