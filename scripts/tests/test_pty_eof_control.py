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
            image = deps / 'qshd-image'; image.write_bytes(b'inert'); image.chmod(0o700)
            lib = deps / 'liblibc-current.rlib'; lib.write_bytes(b'inert')
            test = dict(reason='compiler-artifact', target=dict(name='qshd', kind=['lib'], src_path=str(root / 'qshd/src/lib.rs')), executable=str(image), profile=dict(test=True), manifest_path=str(root / 'qshd/Cargo.toml'), features=['test-build-labels', 'test-darwin-keeper'])
            libc = dict(reason='compiler-artifact', target=dict(name='libc', kind=['lib']), package_id='registry+https://github.com/rust-lang/crates.io-index#libc@0.2.189', filenames=[str(lib)], manifest_path=str(libroot / 'Cargo.toml'))
            host_libc = dict(libc, filenames=[str(target / 'debug/deps/liblibc-host.rlib')])
            self.assertEqual(owner.select_artifacts([test, libc, host_libc], root, target, arch), (image, lib))
            for rows in ([test, test, libc], [test, libc, libc], [test, host_libc], [dict(test, features=[]), libc], [dict(test, manifest_path=str(root / 'other/Cargo.toml')), libc]):
                with self.assertRaises(ValueError): owner.select_artifacts(rows, root, target, arch)
            outsider = root / 'outside-image'; outsider.write_bytes(b'inert')
            for rows, reason in (([], 'artifact_ambiguity'),
                                 ([dict(test, features=[]), libc], 'artifact_features'),
                                 ([dict(test, manifest_path=str(root / 'other')), libc], 'artifact_source'),
                                 ([dict(test, executable=str(outsider)), libc], 'artifact_placement'),
                                 ([test, dict(libc, filenames=[str(lib), str(deps / 'second.rlib')])], 'libc_artifact'),
                                 ([test, dict(libc, package_id='registry+https://github.com/rust-lang/crates.io-index#libc@0.2.188')], 'libc_version')):
                with self.assertRaises(owner.Refusal) as caught: owner.select_artifacts(rows, root, target, arch)
                self.assertEqual(caught.exception.reason, reason)
            with self.assertRaises(owner.Refusal) as caught: owner.select_artifacts([test, libc], root, target, 'unknown')
            self.assertEqual(caught.exception.reason, 'artifact_target')
            image.chmod(0o600)
            with self.assertRaises(owner.Refusal) as caught: owner.select_artifacts([test, libc], root, target, arch)
            self.assertEqual(caught.exception.reason, 'artifact_executable')
            image.chmod(0o700)
            # Irrelevant marker bytes cannot confer or remove registry authority.
            (libroot / '.cargo-checksum.json').write_text('PRIVATE_MARKER_CANARY')
            self.assertEqual(owner.select_artifacts([test, libc], root, target, arch), (image, lib))
            for bad in ('path+file:///private#libc@0.2.189', 'registry+https://alternate.invalid/index#libc@0.2.189', owner.LIBC_PACKAGE_ID + 'suffix', owner.LIBC_PACKAGE_ID + '.0'):
                with self.assertRaises(owner.Refusal) as caught:
                    owner.select_artifacts([test, dict(libc, package_id=bad)], root, target, arch)
                self.assertEqual(caught.exception.reason, 'libc_version' if bad.startswith(owner.LIBC_SOURCE + '#libc@') else 'artifact_source')
            lib.unlink()
            with self.assertRaises(owner.Refusal) as caught: owner.select_artifacts([test, libc], root, target, arch)
            self.assertEqual(caught.exception.reason, 'artifact_placement')

    def test_exact_locked_libc_tuple_and_closed_refusals(self):
        valid = dict(name='libc', version='0.2.189', source=owner.LIBC_SOURCE, checksum=owner.LIBC_CHECKSUM)
        owner.validate_locked_libc({'package': [valid]})
        cases = [({}, 'libc_version'), ({'package': []}, 'libc_version'),
                 ({'package': [valid, valid]}, 'libc_version'),
                 ({'package': [None]}, 'libc_version')]
        for key, values, reason in [('version', ['0.2.188', None], 'libc_version'),
                                    ('source', ['git+PRIVATE_CANARY', None], 'artifact_source'),
                                    ('checksum', ['0' * 64, None], 'libc_checksum')]:
            for value in values:
                row = dict(valid)
                if value is None: row.pop(key)
                else: row[key] = value
                cases.append(({'package': [row]}, reason))
        for lock, reason in cases:
            with self.subTest(lock=lock):
                with self.assertRaises(owner.Refusal) as caught: owner.validate_locked_libc(lock)
                self.assertEqual(caught.exception.reason, reason)
                self.assertNotIn('PRIVATE_CANARY', str(caught.exception))

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

    def test_invalid_lock_main_refuses_before_build(self):
        self.mocked_route('pty-eof-build', False, invalid_lock=True)

    def test_mocked_control_preserves_all_settled_disagreement_summaries(self):
        self.mocked_route('pty-eof-control', disagreement=True)

    def mocked_route(self, mode, disagreement, fail_substage=None, invalid_lock=False):
        # Inert file/argv doubles only. No compiler or native image is executed.
        calls = []
        ActualOwner = owner.Owner
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
                    actual_substage = ('clippy' if argv[1] == 'clippy' else 'test_compile') if argv[0] == 'cargo' else ('helper_compile' if argv[0] == 'rustc' and '-o' in argv else None)
                    if fail_substage is not None and actual_substage == fail_substage:
                        process = mock.Mock(); process.wait.return_value = 1
                        def start(command, **options):
                            diagnostic = dict(level='error', code=dict(code='E0308'), message='PRIVATE_SECRET_CANARY', spans=[])
                            record = dict(reason='compiler-message', message=diagnostic) if actual_substage != 'helper_compile' else dict(diagnostic, **{'$message_type': 'diagnostic'})
                            options['stdout'].write((json.dumps(record) + '\n').encode()); options['stdout'].flush()
                            return process
                        with mock.patch.object(owner.subprocess, 'Popen', side_effect=start):
                            return ActualOwner(ROOT, base, self.env).command(argv, **kwargs)
                    if argv[:2] == ['git', 'rev-parse']: return 0, b'a' * 40 + b'\n'
                    if argv == ['rustc', '-vV']: return 0, b'host: aarch64-apple-darwin\n'
                    if argv == ['rustup', 'which', 'rustc']: return 0, str(compiler).encode() + b'\n'
                    if argv[0] in ('/usr/sbin/sysctl', '/usr/bin/xcrun'): return 0, b'synthetic\n'
                    if argv[0] == 'cargo':
                        if argv[1] == 'clippy':
                            assert '--message-format=json' in argv
                        if fail_substage == 'cargo_records' and argv[1] == 'test':
                            return 0, b'{broken PRIVATE_RECORD_CANARY'
                        return 0, b''
                    if argv[0] == 'rustc':
                        assert '--error-format=json' in argv
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
            actual_digest, actual_chmod = owner.digest, Path.chmod
            actual_bounded = owner.bounded
            def bounded(path, limit):
                if invalid_lock and Path(path) == ROOT / 'Cargo.lock':
                    return b'[[package]]\nname="libc"\nversion="0.2.189"\nsource="registry+https://github.com/rust-lang/crates.io-index"\nchecksum="PRIVATE_LOCK_CANARY"\n'
                return actual_bounded(path, limit)
            def select(*args):
                if fail_substage == 'artifact_select': raise owner.Refusal('artifact_ambiguity')
                return image, libc
            def artifact_digest(path):
                if fail_substage == 'artifact_hashes' and Path(path).name == 'helper':
                    raise OSError('PRIVATE_HASH_CANARY')
                return actual_digest(path)
            def chmod(path, mode, **kwargs):
                if fail_substage == 'helper_permissions' and path.name == 'helper':
                    raise OSError('PRIVATE_PERMISSION_CANARY')
                return actual_chmod(path, mode, **kwargs)
            with mock.patch.object(owner, 'bounded', side_effect=bounded), mock.patch.object(owner, 'digest', side_effect=artifact_digest), mock.patch.object(Path, 'chmod', chmod), mock.patch.dict(owner.os.environ, environ, clear=True), mock.patch.object(owner.sys, 'argv', ['owner', mode, 'aarch64-apple-darwin']), mock.patch.object(owner.sys, 'platform', 'darwin'), mock.patch.object(owner.platform, 'machine', return_value='arm64'), mock.patch.object(owner, 'Owner', FakeOwner), mock.patch.object(owner, 'select_artifacts', side_effect=select), contextlib.redirect_stdout(output):
                status = owner.main()
            summary = json.loads(output.getvalue())
            if invalid_lock:
                self.assertEqual(status, 1)
                self.assertEqual(summary['reason'], 'libc_checksum')
                self.assertFalse(any(a[0] in ('cargo', 'rustc') for a in calls))
                self.assertNotIn('PRIVATE_LOCK_CANARY', output.getvalue())
                self.assertNotIn(str(base), output.getvalue())
                return summary
            if fail_substage is not None:
                self.assertEqual(status, 1)
                self.assertEqual(summary['substage'], fail_substage)
                self.assertEqual(summary['build_completed'], list(owner.BUILD_SUBSTAGES[:owner.BUILD_SUBSTAGES.index(fail_substage)]))
                if fail_substage in owner.COMPILER_SUBSTAGES:
                    self.assertEqual(summary['reason'], 'command_nonzero')
                    self.assertEqual(summary['command_status'], {'kind': 'exit', 'value': 1})
                    self.assertEqual(summary['diagnostics']['records'][0]['code'], 'E0308')
                else:
                    self.assertEqual(summary['reason'], {'cargo_records': 'compiler_json', 'artifact_select': 'artifact_ambiguity'}.get(fail_substage, 'internal_refusal'))
                    self.assertNotIn('command_status', summary)
                self.assertNotIn('PRIVATE_SECRET_CANARY', output.getvalue())
                self.assertNotIn(str(base), output.getvalue())
                return summary
            self.assertEqual(status, int(disagreement))
            self.assertEqual(summary['build_completed'], list(owner.BUILD_SUBSTAGES))
            self.assertEqual(summary['portable_passed'], 7)
            self.assertEqual(summary['artifacts']['libc_rlib_sha256'], actual_digest(libc))
            self.assertEqual(summary['artifacts']['libc_package_sha256'], owner.LIBC_CHECKSUM)
            self.assertEqual(summary['artifacts']['libc_integrity_basis'], 'cargo_locked_registry')
            helper_argv = next(a for a in calls if a[0] == 'rustc' and '-o' in a)
            self.assertEqual(helper_argv[helper_argv.index('--extern') + 1], 'libc=' + str(libc))
            self.assertEqual(helper_argv[helper_argv.index('-L') + 1], 'dependency=' + str(libc.parent))
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


class BuildDiagnosticTests(unittest.TestCase):
    def test_main_actual_owner_failures_identify_three_compiler_substages(self):
        controller = AdmissionTests()
        for stage in ('clippy', 'test_compile', 'helper_compile'):
            controller.mocked_route('pty-eof-build', False, fail_substage=stage)

    def test_main_noncommand_failures_identify_exact_fixed_substage(self):
        controller = AdmissionTests()
        for stage in ('cargo_records', 'artifact_select', 'helper_permissions', 'artifact_hashes'):
            controller.mocked_route('pty-eof-build', False, fail_substage=stage)

    def test_actual_owner_failure_retains_closed_status_and_private_capture(self):
        with tempfile.TemporaryDirectory() as directory:
            process = mock.Mock(); process.wait.return_value = 1
            def start(argv, **kwargs):
                kwargs['stdout'].write(b'{"reason":"compiler-message","message":{"level":"error","code":{"code":"E0308"},"message":"PRIVATE_SECRET_CANARY","spans":[]}}\n')
                kwargs['stdout'].flush()
                return process
            with mock.patch.object(owner.subprocess, 'Popen', side_effect=start):
                with self.assertRaises(ValueError) as caught:
                    owner.Owner(ROOT, Path(directory), {}).command(['inert-compiler'])
            self.assertEqual(getattr(caught.exception, 'reason', None), 'command_nonzero')
            self.assertEqual(caught.exception.status, 1)
            self.assertTrue(caught.exception.capture.is_file())
            process.wait.assert_called_once()
            projected = owner.project_diagnostics(caught.exception.capture, ROOT, {'qshd/src/lib.rs'}, 'cargo')
            self.assertEqual(projected['records'][0]['code'], 'E0308')
            self.assertNotIn('PRIVATE_SECRET_CANARY', json.dumps(projected))


    def test_actual_owner_start_capture_and_interrupt_failures_stay_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(owner.subprocess, 'Popen', side_effect=OSError('PRIVATE_START_CANARY')):
                with self.assertRaises(owner.CommandFailure) as caught:
                    owner.Owner(ROOT, Path(directory), {}).command(['inert'])
            self.assertEqual(caught.exception.reason, 'command_start')
            self.assertEqual(owner.closed_status(caught.exception.status), {'kind': 'unavailable'})
        for failure, reason in ((ValueError('PRIVATE_LIMIT_CANARY'), 'capture_limit'), (OSError('PRIVATE_READ_CANARY'), 'capture_read')):
            with tempfile.TemporaryDirectory() as directory:
                process = mock.Mock(); process.wait.return_value = 0
                with mock.patch.object(owner.subprocess, 'Popen', return_value=process), mock.patch.object(owner, 'bounded', side_effect=failure):
                    with self.assertRaises(owner.CommandFailure) as caught:
                        owner.Owner(ROOT, Path(directory), {}).command(['inert'])
                self.assertEqual(caught.exception.reason, reason)
                process.wait.assert_called_once()
                self.assertNotIn('PRIVATE', str(caught.exception))

    def project(self, records, dialect='cargo'):
        with tempfile.TemporaryDirectory() as directory:
            capture = Path(directory) / 'private-capture'
            capture.write_bytes(records)
            return owner.project_diagnostics(capture, ROOT, {'qshd/src/lib.rs'}, dialect)

    @staticmethod
    def diagnostic(path='qshd/src/lib.rs', code='E0308', **extra):
        span = dict(file_name=path, is_primary=True, line_start=2, line_end=2, column_start=1, column_end=5,
                    text=[dict(text='PRIVATE_SNIPPET_CANARY')], label='PRIVATE_LABEL_CANARY', suggested_replacement='PRIVATE_REPLACEMENT_CANARY', expansion={'span': {'file_name': '/private/EXPANSION_CANARY'}})
        return dict(level='error', code=dict(code=code), message='PRIVATE_MESSAGE_CANARY', rendered='PRIVATE_RENDERED_CANARY', spans=[span], children=[dict(message='PRIVATE_CHILD_CANARY')], environment={'PRIVATE_ENV_CANARY': 'PRIVATE_VALUE_CANARY'}, fd=99123, pid=99124, nonce='PRIVATE_NONCE_CANARY', url='https://PRIVATE_URL_CANARY.invalid', **extra)

    def test_closed_projection_remaps_only_exact_allowlisted_sources(self):
        paths = ('qshd/src/lib.rs', str(ROOT) + '/qshd/src/lib.rs', '/qsh/qshd/src/lib.rs',
                 '/private/SECRET_PATH_CANARY', '/qsh-lookalike/qshd/src/lib.rs', 'qshd/../qshd/src/lib.rs',
                 str(ROOT) + '-lookalike/qshd/src/lib.rs', 'qshd/src/lib.rs\x00', 'qshd/src/not-allowlisted.rs')
        for index, path in enumerate(paths):
            result = self.project((json.dumps(dict(reason='compiler-message', message=self.diagnostic(path))) + '\n').encode())
            location = result['records'][0]['primary_spans'][0]
            self.assertEqual(location['source'], 'qshd/src/lib.rs' if index < 3 else 'external_or_unknown')
            public = json.dumps(result)
            for forbidden in ('CANARY', str(ROOT), 'rendered', 'message', 'children', 'suggested', 'expansion', '"environment"', '"fd"', '"pid"', '"nonce"', '"url"'):
                self.assertNotIn(forbidden, public)

    def test_codes_levels_spans_and_rustc_schema_are_closed(self):
        for code, expected in [('E0308', 'E0308'), ('unused_imports', 'unused_imports'),
                               ('clippy::SECRET_LINT_CANARY', 'unknown_code'), ('E12345', 'unknown_code')]:
            d = self.diagnostic(code=code)
            d.update({'$message_type': 'diagnostic'})
            result = self.project((json.dumps(d) + '\n').encode(), 'rustc')
            self.assertEqual(result['records'][0]['code'], expected)
            self.assertNotIn('CANARY', json.dumps(result))
        d = self.diagnostic(); d['level'] = 'PRIVATE_LEVEL_CANARY'; d['code'] = None
        d['spans'] = d['spans'] * 9
        result = self.project((json.dumps(dict(reason='compiler-message', message=d)) + '\n').encode())
        self.assertEqual(result['records'][0]['level'], 'other')
        self.assertEqual(result['records'][0]['code'], 'none')
        self.assertEqual(len(result['records'][0]['primary_spans']), 4)
        self.assertEqual(result['truncated_spans'], 5)

    def test_projection_input_record_and_public_caps(self):
        line = (json.dumps(dict(reason='compiler-message', message=self.diagnostic())) + '\n').encode()
        data = line * 40 + b'plain PRIVATE_STDERR_CANARY\n{broken PRIVATE_CANARY\n' + b'{' + b'x' * (1024 * 1024) + b'\n' + b'{"reason":"PRIVATE_UNKNOWN_CANARY"}\n' + b'{'
        result = self.project(data)
        self.assertEqual(len(result['records']), 32)
        self.assertEqual(result['oversized'], 1)
        self.assertGreaterEqual(result['malformed'], 2)
        self.assertEqual(result['unknown_records'], 1)
        self.assertGreaterEqual(result['truncated'], 9)
        self.assertLessEqual(len(json.dumps(result).encode()), 64 * 1024)
        self.assertNotIn('CANARY', json.dumps(result))
        with mock.patch.object(owner, 'bounded', side_effect=ValueError('PRIVATE_CANARY')):
            self.assertEqual(owner.project_diagnostics(Path('inert'), ROOT, {}, 'cargo')['capture'], 'limit')
        for value in (-1000, 1000, None, True):
            self.assertEqual(owner.closed_status(value), {'kind': 'unavailable'})
        self.assertEqual(owner.closed_status(-9), {'kind': 'signal', 'value': 9})

    def test_actual_private_capture_limit_and_bounded_counters(self):
        with tempfile.TemporaryDirectory() as directory:
            process = mock.Mock(); process.wait.return_value = 1
            def start(argv, **kwargs):
                kwargs['stdout'].truncate(32 * 1024 * 1024 + 1)
                return process
            with mock.patch.object(owner.subprocess, 'Popen', side_effect=start):
                with self.assertRaises(owner.CommandFailure) as caught:
                    owner.Owner(ROOT, Path(directory), {}).command(['inert'])
            self.assertEqual(caught.exception.reason, 'capture_limit')
            self.assertEqual(process.wait.call_count, 1)
            self.assertEqual(owner.project_diagnostics(caught.exception.capture, ROOT, {}, 'cargo')['capture'], 'limit')
        self.assertEqual(self.project(b'PRIVATE_CANARY\n' * 70000)['unstructured'], 65535)
        raw = ('{"reason":"compiler-message","message":' + '{"nested":' * 2000 + '0' + '}' * 2000 + '}').encode()
        self.assertNotIn('nested', json.dumps(self.project(raw)))
        for value in (0, True, '2', 1_000_001):
            span = self.diagnostic()['spans'][0]; span['line_start'] = value
            self.assertEqual(owner.public_span(span, ROOT, {'qshd/src/lib.rs'}), {'source': 'external_or_unknown'})

    def test_malformed_cargo_records_refuse_without_private_text(self):
        for raw in (b'{"PRIVATE_SECRET_CANARY":', b'{' + b'x' * (1024 * 1024)):
            with self.assertRaises(owner.Refusal) as caught: owner.cargo_records(raw)
            self.assertEqual(caught.exception.reason, 'compiler_json')
            self.assertNotIn('PRIVATE', str(caught.exception))

    def test_fixed_public_manifest_rejects_symlink_without_diagnostic_reads(self):
        self.assertIn('qshd/tests/fixtures/pty_eof/helper.rs', owner.PUBLIC_RUST_SOURCES)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / 'outside'; target.write_bytes(b'inert')
            path = root / 'qshd/src/lib.rs'; path.parent.mkdir(parents=True); path.symlink_to(target)
            with mock.patch.object(owner, 'PUBLIC_RUST_SOURCES', ('qshd/src/lib.rs',)):
                self.assertEqual(owner.public_source_manifest(root), {})


if __name__ == "__main__": unittest.main()

