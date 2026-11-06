"""Offline controls: no compiler, helper or native test is launched."""
import importlib.util
from pathlib import Path
import unittest
import struct
import contextlib
import io
import json
import os
import re
import tempfile
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("pty_control", ROOT / "scripts/qualify-pty-eof-control.py")
owner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(owner)

class RouteTests(unittest.TestCase):
    def test_closed_event_mode_truth_table(self):
        for event in ("push", "pull_request", "workflow_call"):
            for mode in ("", "qualification", "pty-eof-build", "pty-eof-control", "unknown"):
                self.assertEqual(owner.route(event, mode), "qualification")
        for mode in ("", "qualification"):
            self.assertEqual(owner.route("workflow_dispatch", mode), "qualification")
        for mode in ("pty-eof-build", "pty-eof-control"):
            self.assertEqual(owner.route("workflow_dispatch", mode), mode)
        with self.assertRaises(ValueError): owner.route("workflow_dispatch", "unknown")

    def test_exact_selection_and_count_refusals(self):
        text = owner.SELECTOR + ": test\n\n1 test, 0 benchmarks\n"
        owner.admit_list(text, [owner.SELECTOR])
        for bad in ("0 tests, 0 benchmarks\n", text + text, text.replace(owner.SELECTOR, "other")):
            with self.assertRaises(ValueError): owner.admit_list(bad, [owner.SELECTOR])
        owner.admit_results("test " + owner.SELECTOR + " ... ok\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n", [owner.SELECTOR])
        with self.assertRaises(ValueError): owner.admit_results("test result: ok. 0 passed; 0 failed; 0 ignored;", [owner.SELECTOR])

    def test_current_target_libc_selection_refuses_duplicates_and_wrong_source(self):
        import json
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); target = root / 'target'; arch = 'aarch64-apple-darwin'
            deps = target / arch / 'debug/deps'; deps.mkdir(parents=True)
            libroot = root / 'registry/libc'; libroot.mkdir(parents=True)
            (libroot / '.cargo-checksum.json').write_text(json.dumps({'package': owner.LIBC_CHECKSUM}))
            image = deps / 'qshd-image'; image.write_bytes(b'inert'); image.chmod(0o700)
            lib = deps / 'liblibc-current.rlib'; lib.write_bytes(b'inert')
            test = dict(reason='compiler-artifact', target=dict(name='qshd', kind=['lib'], src_path=str(root / 'qshd/src/lib.rs')), executable=str(image), profile=dict(test=True), manifest_path=str(root / 'qshd/Cargo.toml'), features=['test-build-labels', 'test-darwin-keeper'])
            libc = dict(reason='compiler-artifact', target=dict(name='libc', kind=['lib']), package_id='registry+local#libc@0.2.189', filenames=[str(lib)], manifest_path=str(libroot / 'Cargo.toml'))
            host_libc = dict(libc, filenames=[str(target / 'debug/deps/liblibc-host.rlib')])
            self.assertEqual(owner.select_artifacts([test, libc, host_libc], root, target, arch), (image, lib))
            for rows in ([test, test, libc], [test, libc, libc], [test, host_libc], [dict(test, features=[]), libc], [dict(test, manifest_path=str(root / 'other/Cargo.toml')), libc]):
                with self.assertRaises(ValueError): owner.select_artifacts(rows, root, target, arch)
            (libroot / '.cargo-checksum.json').write_text(json.dumps({'package': '0' * 64}))
            with self.assertRaises(ValueError): owner.select_artifacts([test, libc], root, target, arch)

    def test_fixture_copies_are_literal(self):
        owner.verify_copies(ROOT)

    def test_build_mode_has_no_native_launch(self):
        self.assertFalse(owner.launch_native("pty-eof-build"))
        self.assertTrue(owner.launch_native("pty-eof-control"))
        with self.assertRaises(ValueError): owner.launch_native("qualification")

    def test_artifact_ambiguity_refuses(self):
        with self.assertRaises(ValueError): owner.select_artifacts([], ROOT, ROOT / "target", "aarch64-apple-darwin")

    def test_workflow_closed_modes_and_preserved_filters(self):
        text = (ROOT / ".github/workflows/native-crypto.yml").read_text()
        self.assertIn("options: [qualification, pty-eof-build, pty-eof-control]", text)
        self.assertIn("PTY EOF build", text); self.assertIn("PTY EOF control", text)
        for selector in ("darwin_process_scope::native_tests::darwin223_native_", "darwin_process_scope::keeper_tests::keeper_native_", "darwin_process_scope::keeper_integration_tests::keeper_integrated_"):
            self.assertIn(selector, text)
        diagnostic = text.split("  pty-eof-diagnostic:", 1)[1]
        self.assertNotIn("--include-ignored", diagnostic)
        self.assertNotIn("upload-artifact", diagnostic)
        for block in diagnostic.split("        run: |\n")[1:]:
            shell = block.split("\n      - ", 1)[0]
            self.assertNotIn("${{ inputs.mode }}", shell)

def synthetic_capture(disagreement=False, wait_entries=None):
    # Synthetic byte records only. These are never native observations.
    lines = []
    for index, (arm, direct, normalized) in enumerate(owner.LABELS):
        boolean = lambda x: str(x).lower()
        lines.append(f"arm_binding arm={arm} direct={boolean(direct)} normalized={boolean(normalized)} pid=100 nonce={'4e' * 16} control=40 slave=41 dev=1 rdev=2 ino=3 mode={0o020600}")
        lines.append("arm_begin synthetic=true")
        seq = cmdseq = 0
        def record(op, fd, mode=0o020600, command=False):
            nonlocal seq, cmdseq
            b = bytearray(128); b[:4] = b'PEF1'; b[4:20] = b'N' * 16
            b[20:23] = bytes((arm, op, 1 if command else 2))
            struct.pack_into('<IiiQQQIiii', b, 24, cmdseq if command else seq, fd, 0, 1, 2, 3, mode, 100, 100, 100)
            if command: cmdseq += 1
            else: seq += 1
            lines.append(('command_attempt=' if command else 'helper_receipt=') + b.hex())
        def scan(fds):
            record(17, 50, 0o040700)
            for fd in fds: record(1, fd, 0o140600 if fd == 40 else 0o020600)
            record(2, 50, 0o040700)
        scan([40, 41]); record(14, 41)
        if arm >= 2: record(15, 41); record(16, 41)
        if arm == 3: record(11, 0); record(12, 0)
        if arm == 4: record(13, 42)
        record(3, 41)
        lines.append("parent_slave_drop_returned syscall_close_result=not_exposed")
        record(4, -1, command=True); record(5, 41)
        scan([40, 42] if arm == 4 else [40])
        if arm == 4:
            record(6, -1, command=True); record(7, 42); scan([40])
        record(8, -1, command=True); record(9, 40)
        if wait_entries is not None and (arm, direct, normalized) in wait_entries:
            lines.append(wait_entries[(arm, direct, normalized)])
        before = 'would_block' if arm >= 3 or disagreement and index == 0 else 'zero'
        after = 'zero' if arm == 4 else 'none'
        agreement = not (disagreement and index == 0)
        lines.append(f"arm_settled synthetic=true normal_wait=true fallback=false pending=false bundle_drop_returned=true agreement={boolean(agreement)} natural=true")
        lines.append(f"contrast arm={arm} direct={boolean(direct)} normalized={boolean(normalized)} before={before} after={after} post=zero normal_wait=true fallback=false pending=false bundle_drop_returned=true agreement={boolean(agreement)} natural=true")
    lines.append(f"campaign_complete attempted=8 settled=8 disagreements={int(disagreement)} failed={str(disagreement).lower()} current_pending=false")
    return ('\n'.join(lines) + '\n').encode()


def producer_wait_entries():
    """Use the real portable formatter output when leased; otherwise its source literal.

    This is finite synthetic formatting evidence, never an actual Darwin wait.
    """
    source = (ROOT / 'qshd/src/darwin_process_scope/keeper_pty_eof_tests.rs').read_text()
    template = re.search(r'format!\(\s*"(consuming_wait_enter [^"]+)"', source)[1]
    normal = [template.format(pid=100, arm=arm, direct=str(direct).lower(), normalized=str(normalized).lower()) for arm, direct, normalized in owner.LABELS]
    pending = re.search(r'format!\(\s*"(pending_child_wait [^"]+)"', source)[1]
    negative = [pending.replace('{pid}', '100').replace('{label:?}', '(2, true, false)').replace('{expired}', expired) for expired in ('true', 'false', 'false')]
    fixture = os.environ.get('QSH_PTY_EOF_PORTABLE_WAIT_FIXTURE')
    if fixture:
        actual = owner.bounded(Path(fixture), 4096).decode('ascii').splitlines()
        if actual != normal + negative: raise AssertionError('actual Rust formatter differs from source-coupled records')
        normal, negative = actual[:8], actual[8:]
    return dict(zip(owner.LABELS, normal)), negative


class AdmissionTests(unittest.TestCase):
    def test_actual_producer_normal_wait_entry_after_released_completes_eight(self):
        entries, _ = producer_wait_entries()
        self.assertEqual(len(owner.admit_capture(synthetic_capture(wait_entries=entries))), 8)

    def test_actual_producer_expired_failed_or_unreleased_wait_refuses(self):
        _, negatives = producer_wait_entries()
        for record in negatives:
            with self.assertRaises(ValueError): owner.admit_capture(synthetic_capture(wait_entries={owner.LABELS[1]: record}))

    def test_wait_entry_requires_eventual_settlement_and_exact_owner_order(self):
        entries, _ = producer_wait_entries()
        data = synthetic_capture(wait_entries=entries)
        first = entries[owner.LABELS[0]].encode()
        for bad in (data[:data.index(first) + len(first)] + b'\n', data.replace(first, first.replace(b'pid=100', b'pid=101'), 1), data.replace(first, first.replace(b'arm=1', b'arm=2'), 1), data.replace(first, first.replace(b'direct=true', b'direct=false'), 1), data.replace(first, first + b'\n' + first, 1)):
            with self.assertRaises(ValueError): owner.admit_capture(bad)
        lines = data.decode().splitlines()
        entry = lines.pop(lines.index(first.decode()))
        # Insert before the Released receipt; the wire phase is only7 here.
        index = next(i for i, line in enumerate(lines) if line.startswith('helper_receipt=') and bytes.fromhex(line.split('=', 1)[1])[21] == 9)
        lines.insert(index, entry)
        with self.assertRaises(ValueError): owner.admit_capture(('\n'.join(lines) + '\n').encode())

    def test_settled_disagreement_keeps_all_eight_through_actual_wait_formatter(self):
        entries, _ = producer_wait_entries()
        result = owner.admit_capture(synthetic_capture(True, wait_entries=entries))
        self.assertEqual(len(result), 8)
        self.assertEqual(sum(not r['agreement'] for r in result), 1)

    def test_full_fixed_matrix_and_settled_disagreement(self):
        for disagreement in (False, True):
            result = owner.admit_capture(synthetic_capture(disagreement))
            self.assertEqual(len(result), 8)
            self.assertEqual(sum(not r['agreement'] for r in result), int(disagreement))
            public = str(result)
            for private in ('pid', 'nonce', 'control', 'slave', 'rdev', 'ino'):
                self.assertNotIn(private, public)

    def test_partial_pending_fallback_and_inconsistent_prediction_refuse(self):
        data = synthetic_capture()
        for bad in (data[:100], data + b'pending_child_wait\n', data.replace(b'fallback=false', b'fallback=true', 1), data.replace(b'agreement=true', b'agreement=false', 1), data.replace(b'natural=true', b'natural=false', 1), data.replace(b'current_pending=false', b'current_pending=true')):
            with self.assertRaises(ValueError): owner.admit_capture(bad)

    def test_wrong_parent_identity_refuses_actual_ready(self):
        data = synthetic_capture().replace(b'dev=1 rdev=2 ino=3', b'dev=1 rdev=99 ino=3', 1)
        with self.assertRaises(ValueError): owner.admit_capture(data)

    def test_real_fd_zero_close_and_retained_refusal(self):
        data = synthetic_capture()
        # Arm 3's actual complete synthetic prefix contains matching fd0 open/close.
        self.assertEqual(len(owner.admit_capture(data)), 8)
        a = owner.Admission(b'N' * 16, 2, control_fd=40, slave_fd=41, expected_pid=100)
        raw = bytearray(128); raw[:4] = b'PEF1'; raw[4:20] = b'N' * 16
        raw[20:23] = bytes((2, 10, 2)); struct.pack_into('<ii', raw, 28, 0, 9); struct.pack_into('<i', raw, 64, 100)
        with self.assertRaises(ValueError): a.accept(raw)
        self.assertEqual(a.records, [bytes(raw)])

    def test_mocked_build_route_stops_without_native_or_helper_execution(self):
        self.mocked_route('pty-eof-build', disagreement=False)

    def test_mocked_control_preserves_all_settled_disagreement_summaries(self):
        self.mocked_route('pty-eof-control', disagreement=True)

    def mocked_route(self, mode, disagreement):
        # Inert file/argv doubles only. No compiler or native image is executed.
        calls = []
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            image, libc, compiler = (base / n for n in ('inert-test', 'inert-libc', 'inert-rustc'))
            for path in (image, libc, compiler): path.write_bytes(b'inert')
            crypto = base / 'crypto'; crypto.mkdir()
            (crypto / 'manifest.json').write_text(json.dumps({'identity': {'target': 'aarch64-apple-darwin'}}))
            class FakeOwner:
                def __init__(self, root, runtime, env): self.env = env
                def command(self, argv, **kwargs):
                    calls.append(argv)
                    if argv[:2] == ['git', 'rev-parse']: return 0, b'a' * 40 + b'\n'
                    if argv == ['rustc', '-vV']: return 0, b'host: aarch64-apple-darwin\n'
                    if argv == ['rustup', 'which', 'rustc']: return 0, str(compiler).encode() + b'\n'
                    if argv[0] in ('/usr/sbin/sysctl', '/usr/bin/xcrun'): return 0, b'synthetic\n'
                    if argv[0] == 'cargo': return 0, b''
                    if argv[0] == 'rustc':
                        Path(argv[argv.index('-o') + 1]).write_bytes(b'inert-helper')
                        return 0, b''
                    if argv[0] == str(image):
                        if '--list' in argv:
                            names = [owner.SELECTOR] if '--ignored' in argv else owner.PORTABLE
                            return 0, ('\n'.join(n + ': test' for n in names) + f'\n\n{len(names)} test' + ('s' if len(names) != 1 else '') + ', 0 benchmarks\n').encode()
                        if '--ignored' in argv:
                            Path(self.env['QSH_PTY_EOF_CAPTURE']).write_bytes(synthetic_capture(disagreement))
                            return 1, ('running 1 test\ntest ' + owner.SELECTOR + ' ... FAILED\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n').encode()
                        return 0, ('\n'.join('test ' + n + ' ... ok' for n in owner.PORTABLE) + '\ntest result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 1 filtered out; finished in 0.01s\n').encode()
                    raise AssertionError('unexpected executable')
            environ = dict(GITHUB_EVENT_NAME='workflow_dispatch', PTY_EOF_MODE=mode, GITHUB_SHA='a' * 40, RUNNER_TEMP=str(base), OPENSSL_DIR=str(crypto))
            output = io.StringIO()
            with mock.patch.dict(owner.os.environ, environ, clear=True), mock.patch.object(owner.sys, 'argv', ['owner', mode, 'aarch64-apple-darwin']), mock.patch.object(owner.sys, 'platform', 'darwin'), mock.patch.object(owner.platform, 'machine', return_value='arm64'), mock.patch.object(owner, 'Owner', FakeOwner), mock.patch.object(owner, 'select_artifacts', return_value=(image, libc)), contextlib.redirect_stdout(output):
                status = owner.main()
            summary = json.loads(output.getvalue())
            self.assertEqual(status, int(disagreement))
            self.assertEqual(summary['portable_passed'], 7)
            self.assertEqual(summary['native_executed'], int(disagreement))
            executions = [a for a in calls if a[0] == str(image) and '--ignored' in a and '--list' not in a]
            self.assertEqual(len(executions), int(disagreement))
            self.assertFalse(any(Path(a[0]).name == 'helper' for a in calls))
            self.assertNotIn(str(base), output.getvalue())
            if disagreement:
                self.assertEqual(summary['status'], 'settled_disagreement')
                self.assertEqual(len(summary['contrasts']), 8)
                self.assertTrue(summary['controller_waited'])
            else: self.assertEqual(summary['status'], 'build_passed')

    def test_owner_waits_through_interruption_without_kill(self):
        with tempfile.TemporaryDirectory() as directory:
            process = mock.Mock(); process.wait.side_effect = [KeyboardInterrupt(), 0]
            with mock.patch.object(owner.subprocess, 'Popen', return_value=process), mock.patch.object(owner.time, 'sleep'):
                with self.assertRaises(ValueError): owner.Owner(ROOT, Path(directory), {}).command(['inert'])
            self.assertEqual(process.wait.call_count, 2)
            process.kill.assert_not_called(); process.terminate.assert_not_called()


if __name__ == "__main__": unittest.main()

