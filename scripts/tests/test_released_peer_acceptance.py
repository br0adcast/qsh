"""Fail-closed controls for the focused released-peer gate; no product builds."""
from contextlib import redirect_stdout
import ast
import fnmatch
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'released-peer-acceptance.py'
spec = importlib.util.spec_from_file_location('peer_acceptance', SCRIPT)
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)


class AcceptanceTests(unittest.TestCase):
    def archive(self, root, members):
        archive = root / 'fixture.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, kind in members:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = 1 if kind == tarfile.REGTYPE else 0
                info.linkname = '/bin/sh' if kind == tarfile.SYMTYPE else ''
                tar.addfile(info, io.BytesIO(b'x') if info.size else None)
        return archive

    def test_verified_pair_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root, [(peer.PREFIX + '/' + name, tarfile.REGTYPE)
                                          for name in ('qsh', 'qshd')])
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            pair = peer.extract_pair(archive, root / 'out', digest)
            self.assertEqual([p.read_bytes() for p in pair], [b'x', b'x'])
            self.assertTrue(all(p.stat().st_mode & 0o100 for p in pair))

    def test_bad_digest_precedes_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root, [(peer.PREFIX + '/qsh', tarfile.REGTYPE)])
            with self.assertRaisesRegex(ValueError, 'checksum'):
                peer.extract_pair(archive, root / 'out', '0' * 64)
            self.assertFalse((root / 'out').exists())

    def test_missing_symlink_duplicate_and_traversal_rejected(self):
        for members in (
            [(peer.PREFIX + '/qsh', tarfile.REGTYPE)],
            [(peer.PREFIX + '/qsh', tarfile.SYMTYPE), (peer.PREFIX + '/qshd', tarfile.REGTYPE)],
            [(peer.PREFIX + '/qsh', tarfile.REGTYPE)] * 2,
            [('../qsh', tarfile.REGTYPE)],
            [(peer.PREFIX + '/qsh', tarfile.REGTYPE),
             (peer.PREFIX + '/qshd', tarfile.REGTYPE),
             (peer.PREFIX + '/README.md', tarfile.SYMTYPE)],
            [(peer.PREFIX + '/qsh', tarfile.REGTYPE),
             (peer.PREFIX + '/qshd', tarfile.REGTYPE),
             (peer.PREFIX + '/extra', tarfile.REGTYPE)],
        ):
            with self.subTest(members=members), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = self.archive(root, members)
                with self.assertRaises(ValueError):
                    peer.extract_pair(archive, root / 'out', hashlib.sha256(archive.read_bytes()).hexdigest())
                self.assertFalse((root / 'out').exists())

    def test_download_failure_is_not_a_fallback(self):
        with mock.patch.object(peer.subprocess, 'run', side_effect=subprocess.CalledProcessError(22, 'curl')):
            with self.assertRaises(subprocess.CalledProcessError):
                peer.download(Path('/unused'))

    def test_exact_one_pass_and_no_skip(self):
        text = 'running 1 test\ntest wanted ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.01s\n'
        peer.check_result('wanted', text, 0)
        for output, status in (
            (text, 1), (text.replace('wanted', 'other'), 0),
            (text.replace('1 passed', '0 passed'), 0),
            (text.replace('0 ignored', '1 ignored'), 0),
            (text.replace('1 passed', '2 passed'), 0),
            (text + 'test extra ... ok\n', 0),
            (text + 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n', 0),
            (text + '\nSKIPPED: missing prerequisite\n', 0),
            ('running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;', 0),
        ):
            with self.subTest(output=output, status=status), self.assertRaises(ValueError):
                peer.check_result('wanted', output, status)

    def test_case_failure_retains_evidence_and_fails(self):
        result = subprocess.CompletedProcess([], 23, 'the fixture failed before its test ran\n')
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp)
            with mock.patch.object(peer.subprocess, 'run', return_value=result), redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):
                    peer.run_case('qsh', 'wanted', True, {}, evidence)
            self.assertEqual((evidence / 'wanted.log').read_text(), result.stdout)

    def test_busy_legacy_shell_scenario_is_selected_with_existing_cases(self):
        self.assertEqual(len(peer.CASES), 7)
        self.assertIn(('qsh', 'current_ensure_reports_busy_published_v050_without_interrupting_shell', True), peer.CASES)
        self.assertIn(('qsh', 'protocol2_client_cannot_mutate_published_v050_daemon', True), peer.CASES)
        self.assertEqual(len(set(peer.CASES)), len(peer.CASES))

    def test_pull_request_changes_run_the_real_gate_without_every_patch(self):
        workflow = (SCRIPT.parents[1] / '.github/workflows/released-peer-acceptance.yml').read_text()
        trigger = re.search(r'^  pull_request:\n    paths:\n((?:      - .*\n)+)', workflow, re.MULTILINE)
        self.assertIsNotNone(trigger, 'PR acceptance changes must execute the actual seven-case gate')
        paths = [ast.literal_eval(line.strip()[2:]) for line in trigger.group(1).splitlines()]
        for changed in ('.github/workflows/released-peer-acceptance.yml',
                        '.github/workflows/release.yml',
                        'scripts/released-peer-acceptance.py',
                        'scripts/tests/test_released_peer_acceptance.py',
                        'cli/tests/mixed_versions.rs', 'qshd/tests/mixed_versions.rs',
                        'crates/daemon-bootstrap-protocol/src/lib.rs',
                        'crates/bringup/src/ensure.rs', 'crates/bringup/src/install.rs',
                        'qshd/src/main.rs', 'qshd/src/control.rs', 'qshd/src/control/path.rs',
                        'qshd/src/transport_daemon.rs', 'qshd/src/destructive_restart.rs',
                        'qshd/src/modern_restart.rs', 'cli/src/ssh_step.rs',
                        'cli/src/busy_daemon.rs', 'cli/src/climb.rs'):
            self.assertTrue(any(fnmatch.fnmatchcase(changed, pattern) for pattern in paths), changed)
        self.assertFalse(any(fnmatch.fnmatchcase('README.md', pattern) for pattern in paths))
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('python3 scripts/released-peer-acceptance.py --evidence', workflow)
        release = (SCRIPT.parents[1] / '.github/workflows/release.yml').read_text()
        self.assertRegex(release, r'needs: \[release, ordinary-ci, released-peer-acceptance, release-verifier\]')


class LibtestRecordTests(unittest.TestCase):
    SUMMARY = ('test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; '
               '0 filtered out; finished in 0.01s\n')

    def test_real_rust_libtest_with_synchronous_noisy_child(self):
        source_text = r"""
#[test]
fn noisy_child() {
    let status = std::process::Command::new("/bin/sh")
        .args(["-c", "printf 'owned child diagnostic\n' >&2"])
        .status().expect("owned diagnostic child");
    assert!(status.success(), "owned diagnostic child failed");
}
#[test]
fn quiet_inline() {}
"""
        previous_umask = os.umask(0o077)
        try:
            with tempfile.TemporaryDirectory(prefix='libtest-record-') as temp:
                root = Path(temp)
                env = os.environ.copy()
                env['CARGO_HOME'] = env.get('CARGO_HOME', str(Path.home() / '.cargo'))
                env['RUSTUP_HOME'] = env.get('RUSTUP_HOME', str(Path.home() / '.rustup'))
                for key, folder in (('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'),
                                    ('XDG_CACHE_HOME', 'cache'), ('TMPDIR', 'tmp')):
                    (root / folder).mkdir(mode=0o700)
                    env[key] = str(root / folder)
                env['HISTFILE'] = '/dev/null'
                env.pop('SSH_AUTH_SOCK', None)
                env.pop('SSH_AGENT_PID', None)
                source = root / 'records.rs'
                binary = root / 'records'
                source.write_text(source_text)
                version = subprocess.run(['rustc', '--version'], env=env,
                                         text=True, capture_output=True, check=True, timeout=30)
                self.assertTrue(version.stdout.startswith('rustc '), version.stdout)
                compile_command = ['rustc', '--test', str(source), '-o', str(binary)]
                subprocess.run(compile_command, env=env, text=True, capture_output=True,
                               check=True, timeout=30)
                results = []
                for name in ('noisy_child', 'quiet_inline'):
                    command = [str(binary), name, '--exact', '--nocapture',
                               '--test-threads=1', '--color=never']
                    result = subprocess.run(command, env=env, stdin=subprocess.DEVNULL,
                                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                            text=True, timeout=30)
                    self.assertEqual(result.returncode, 0, result.stdout)
                    self.assertRegex(result.stdout, r'test result: ok\. 1 passed; 0 failed; 0 ignored;')
                    print(f'REAL_LIBTEST_BEGIN {name}', flush=True)
                    print(result.stdout, end='', flush=True)
                    print(f'REAL_LIBTEST_END {name}', flush=True)
                    results.append((name, result))
                self.assertRegex(results[0][1].stdout,
                                 r'(?m)^test noisy_child \.\.\. owned child diagnostic$')
                self.assertRegex(results[0][1].stdout, r'(?m)^ok$')
                self.assertRegex(results[1][1].stdout, r'(?m)^test quiet_inline \.\.\. ok$')
                print('REAL_LIBTEST_RECEIPT ' + json.dumps({
                    'compiler': version.stdout.strip(), 'compile_command': compile_command,
                    'source_sha256': hashlib.sha256(source.read_bytes()).hexdigest(),
                    'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'actual_test_bodies': 2, 'owned_child_wait': 'Rust Command.status returned success',
                    'outputs': {name: hashlib.sha256(result.stdout.encode()).hexdigest()
                                for name, result in results},
                }, sort_keys=True), flush=True)
                for name, result in results:
                    peer.check_result(name, result.stdout, result.returncode)
        finally:
            os.umask(previous_umask)

    def test_multiline_record_keeps_ordinary_diagnostics(self):
        for announcement in ('test wanted ...', 'test wanted ... child diagnostic'):
            with self.subTest(announcement=announcement):
                text = (announcement + '\nordinary detail\n\nok\n' + self.SUMMARY +
                        'ordinary completion diagnostic\n')
                peer.check_result('wanted', text, 0)

    def test_missing_and_ambiguous_outcomes_refuse(self):
        records = (
            'test wanted ...\nordinary detail\n',
            'ok\n',
            'test wanted ...\nok\nok\n',
            'test wanted ...\nFAILED\n',
            'test wanted ...\nignored\n',
            'test wanted ... FAILED\n',
            'test wanted ... ignored\n',
            'test wanted ... ok extra\n',
            'test wanted ...\nok extra\nok\n',
            'test wanted ...\n  ok\n',
            'test wanted ... test forged ... ok\nok\n',
            'test wanted ...\ntest forged ... ok\nok\n',
            'test wanted ... ok\ntest wanted ... ok\n',
            'test other ... child diagnostic\nok\n',
        )
        for record in records:
            with self.subTest(record=record), self.assertRaises(ValueError):
                peer.check_result('wanted', record + self.SUMMARY, 0)

    def test_records_after_or_before_the_summary_refuse(self):
        complete = 'test wanted ... ok\n'
        for text in (self.SUMMARY + complete, complete + self.SUMMARY + 'ok\n',
                     'test wanted ...\n' + self.SUMMARY + 'ok\n',
                     complete + self.SUMMARY + 'test forged ... ok\n',
                     complete + self.SUMMARY + self.SUMMARY,
                     self.SUMMARY):
            with self.subTest(text=text), self.assertRaises(ValueError):
                peer.check_result('wanted', text, 0)

    def test_multiline_does_not_relax_summary_exit_or_skip_policy(self):
        complete = 'test wanted ... child diagnostic\nok\n' + self.SUMMARY
        for text, status in (
            (complete, 1),
            (complete.replace('1 passed', '0 passed'), 0),
            (complete.replace('0 ignored', '1 ignored'), 0),
            (complete.replace('0 failed', '1 failed'), 0),
            (complete + 'SKIPPED fixture prerequisite\n', 0),
        ):
            with self.subTest(text=text, status=status), self.assertRaises(ValueError):
                peer.check_result('wanted', text, status)

    def test_optional_header_never_opens_a_second_run(self):
        record = 'test wanted ... ok\n'
        peer.check_result('wanted', record + self.SUMMARY, 0)
        for text in (
            'running 0 tests\n' + record + self.SUMMARY,
            'running 1 test\nrunning 1 test\n' + record + self.SUMMARY,
            'test wanted ...\nrunning 1 test\nok\n' + self.SUMMARY,
            record + self.SUMMARY + 'running 1 test\n',
        ):
            with self.subTest(text=text), self.assertRaises(ValueError):
                peer.check_result('wanted', text, 0)
