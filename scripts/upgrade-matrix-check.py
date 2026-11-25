#!/usr/bin/env python3
"""Pre-release upgrade and protocol-compatibility matrix runner for qsh / qshd.

Runs Layer 1 (deterministic PTY & protocol matrix in `cli/src/upgrade_matrix_tests.rs`
and `cli/src/daemon_update_fixture_tests.rs`) and optionally Layer 2 (real-binary
released-peer checks via `scripts/released-peer-acceptance.py`), printing a compact
Pass/Fail summary table.

All spawned processes use private temporary HOME/XDG directories and HISTFILE=/dev/null.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

WORKSPACE = Path(__file__).resolve().parents[1]

LAYER1_TESTS = (
    ("s1-busy-preserve-old-client", "upgrade_matrix_tests::scenario1_busy_same_proto_preserving_updates_once_and_preserves_old_client_session"),
    ("s1-busy-decline-disrupt", "upgrade_matrix_tests::scenario1_busy_same_proto_declining_disrupt_keeps_old_daemon_and_client"),
    ("s1-busy-decline-initial", "upgrade_matrix_tests::scenario1_busy_same_proto_declining_initial_prompt_skips_download_and_disrupt_prompt"),
    ("s1-multi-endpoint-dedup", "upgrade_matrix_tests::scenario1_multi_endpoint_deduplicates_dialog_and_updates_at_most_once"),
    ("s1-ssh-busy-dialog-matrix", "upgrade_matrix_tests::scenario1_ssh_busy_dialog_matrix_covers_protocol_preservation_and_activity"),
    ("s1-legacy-without-about-os", "daemon_update::tests::legacy_ssh_fallback_respects_ssh_availability_and_tty_answer"),
    ("s2-newer-compat-vs-incompat", "upgrade_matrix_tests::scenario2_newer_server_compatible_vs_incompatible_policy_and_presentations"),
    ("s2-newer-no-downgrade", "upgrade_matrix_tests::scenario2_newer_compatible_daemon_never_prompts_daemon_downgrade"),
    ("s2-newer-incompat-2-endpoints", "upgrade_matrix_tests::scenario2_newer_incompatible_server_deduplicates_diagnostic_across_two_endpoints"),
    ("s3-idle-update-idempotent", "upgrade_matrix_tests::scenario3_idle_older_personal_daemon_omits_busy_prompts_and_is_idempotent"),
    ("s3-managed-never-prompts", "upgrade_matrix_tests::scenario3_managed_daemon_never_prompts_idle_or_busy"),
)


def clean_env(jobs: int) -> dict[str, str]:
    env = os.environ.copy()
    env["HISTFILE"] = "/dev/null"
    env["CARGO_BUILD_JOBS"] = str(jobs)
    env.pop("TMUX", None)
    return env


def run_step(cmd: list[str], env: dict[str, str], timeout_s: int) -> tuple[int, str, float]:
    started = time.monotonic()
    proc = subprocess.run(
        cmd,
        cwd=WORKSPACE,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        timeout=timeout_s,
    )
    return proc.returncode, proc.stdout, time.monotonic() - started


def build_qshd_artifact(env: dict[str, str], jobs: int, timeout_s: int) -> tuple[int, str | None, str]:
    rc, out, _ = run_step(
        [
            "cargo",
            "build",
            "-p",
            "qshd",
            "--bin",
            "qshd",
            "--message-format=json",
            "-j",
            str(jobs),
        ],
        env,
        max(timeout_s, 300),
    )
    if rc != 0:
        return rc, None, out
    executable = None
    for line in out.splitlines():
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            msg.get("reason") == "compiler-artifact"
            and msg.get("target", {}).get("name") == "qshd"
            and "bin" in msg.get("target", {}).get("kind", [])
            and msg.get("executable")
        ):
            executable = msg["executable"]
    return (0 if executable else 1), executable, out


def parse_single_test_pass(output: str, test_name: str) -> bool:
    return bool(
        re.search(rf"^test {re.escape(test_name)} \.\.\. ok$", output, re.MULTILINE)
        and re.search(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", output, re.MULTILINE)
    )


def format_table(rows: list[dict[str, object]]) -> str:
    headers = ("Layer", "Scenario", "Duration", "Status")
    widths = [len(h) for h in headers]
    rendered = []
    for row in rows:
        cols = (
            str(row["layer"]),
            str(row["name"]),
            f"{row['seconds']:.1f}s",
            str(row["status"]),
        )
        rendered.append(cols)
        for i, col in enumerate(cols):
            widths[i] = max(widths[i], len(col))
    sep = " | ".join("-" * w for w in widths)
    lines = [" | ".join(h.ljust(widths[i]) for i, h in enumerate(headers)), sep]
    for cols in rendered:
        lines.append(" | ".join(cols[i].ljust(widths[i]) for i in range(len(headers))))
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jobs", type=int, default=2, help="Cargo build parallelism (default: 2)")
    parser.add_argument(
        "--with-released-peers",
        action="store_true",
        help="Also run Layer 2 real v0.5.0 released-peer acceptance checks",
    )
    parser.add_argument(
        "--evidence-dir",
        type=Path,
        default=None,
        help="Directory for released-peer acceptance evidence (required if --with-released-peers)",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=None,
        help="Optional path (outside the repository) to write a JSON summary report",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=180,
        help="Per-scenario timeout in seconds (default: 180)",
    )
    args = parser.parse_args(argv)

    env = clean_env(args.jobs)
    rows: list[dict[str, object]] = []
    failed = False

    print("Building qshd and qsh test harness...", flush=True)
    rc, qshd_bin, out = build_qshd_artifact(env, args.jobs, args.timeout)
    if rc != 0 or not qshd_bin:
        print(out, file=sys.stderr)
        return rc or 1
    env["QSH_TEST_QSHD"] = qshd_bin
    rc, out, secs = run_step(
        ["cargo", "test", "-p", "qsh", "--lib", "--no-run", "-j", str(args.jobs)],
        env,
        max(args.timeout, 300),
    )
    if rc != 0:
        print(out, file=sys.stderr)
        return rc

    for label, test_name in LAYER1_TESTS:
        cmd = [
            "cargo",
            "test",
            "-p",
            "qsh",
            "--lib",
            "--",
            "--exact",
            test_name,
            "--test-threads=1",
        ]
        rc, out, secs = run_step(cmd, env, args.timeout)
        ok = rc == 0 and parse_single_test_pass(out, test_name)
        status = "PASS" if ok else "FAIL"
        rows.append({"layer": "L1-qsh", "name": label, "test": test_name, "seconds": secs, "status": status})
        print(f"[{status}] L1-qsh  {label} ({secs:.1f}s)", flush=True)
        if not ok:
            failed = True
            print(out, file=sys.stderr)

    if args.with_released_peers:
        evidence = args.evidence_dir
        if evidence is None:
            print("--evidence-dir is required with --with-released-peers", file=sys.stderr)
            return 2
        cmd = [
            sys.executable,
            str(WORKSPACE / "scripts/released-peer-acceptance.py"),
            "--evidence",
            str(evidence),
        ]
        rc, out, secs = run_step(cmd, env, max(args.timeout * 4, 600))
        ok = rc == 0
        status = "PASS" if ok else "FAIL"
        rows.append({"layer": "L2-v0.5.0", "name": "released-peer-acceptance", "seconds": secs, "status": status})
        print(f"[{status}] L2-v0.5.0  released-peer-acceptance ({secs:.1f}s)", flush=True)
        if not ok:
            failed = True
            print(out, file=sys.stderr)

    print("\n" + format_table(rows))
    if args.report is not None:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({"failed": failed, "rows": rows}, indent=2) + "\n", encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
