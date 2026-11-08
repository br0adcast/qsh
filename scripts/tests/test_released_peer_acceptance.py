"""Fail-closed controls for the focused released-peer gate; no product builds."""
from contextlib import redirect_stdout
import ast
import fnmatch
import hashlib
import importlib.util
import io
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

    def test_native_fixture_selection_and_manifest_are_explicit(self):
        expected = {
            ('Linux', 'x86_64'): ('qsh-0.5.0-x86_64-unknown-linux-musl', peer.SHA256, 6282319),
            ('Darwin', 'arm64'): ('qsh-0.5.0-aarch64-apple-darwin', 'db31e4a123459a9fd8151585301f7e0142c340cd1d9473a8e86d1f5be3f072cb', 5433857),
            ('Darwin', 'x86_64'): ('qsh-0.5.0-x86_64-apple-darwin', '38b40b631ebd0a4fce856c7763cf4793c55e625cb404e2a93c4a3d391786d599', 5866506),
        }
        for host, fixture in expected.items():
            self.assertEqual(peer.fixture_for_host(*host), fixture)
        for host in [('Darwin', 'unknown'), ('Linux', 'aarch64'), ('Windows', 'AMD64')]:
            with self.assertRaises(ValueError):
                peer.fixture_for_host(*host)
        prefix, digest, _ = expected['Darwin', 'arm64']
        data = (digest + '  ' + prefix + '.tar.gz\n').encode()
        with mock.patch.object(peer, 'MANIFEST_SIZE', len(data)), mock.patch.object(peer, 'MANIFEST_SHA256', hashlib.sha256(data).hexdigest()):
            peer.verify_published_manifest(data, prefix, digest)
            for changed, selected, checksum in [(data+b'x', prefix, digest), (data, prefix+'-other', digest), (data, prefix, '00'*32)]:
                with self.assertRaises(ValueError):
                    peer.verify_published_manifest(changed, selected, checksum)

    def test_platform_archive_prefix_cannot_be_confused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            prefix='qsh-0.5.0-aarch64-apple-darwin'
            archive=self.archive(root, [(prefix+'/'+name,tarfile.REGTYPE) for name in ('qsh','qshd')])
            digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                peer.extract_pair(archive,root/'wrong',digest)
            pair=peer.extract_pair(archive,root/'correct',digest,prefix)
            self.assertTrue(all(path.read_bytes()==b'x' for path in pair))

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
        self.assertEqual(len(peer.CASES), 8)
        self.assertIn(('qsh', 'current_ensure_reports_busy_published_v050_without_interrupting_shell', True), peer.CASES)
        self.assertIn(('qsh', 'published_v050_force_restarts_account_service_even_after_instance_change', True), peer.CASES)
        self.assertIn(('qsh', 'protocol2_client_cannot_mutate_published_v050_daemon', True), peer.CASES)
        self.assertEqual(len(set(peer.CASES)), len(peer.CASES))

    def test_pull_request_changes_run_the_real_gate_without_every_patch(self):
        workflow = (SCRIPT.parents[1] / '.github/workflows/released-peer-acceptance.yml').read_text()
        trigger = re.search(r'^  pull_request:\n    paths:\n((?:      - .*\n)+)', workflow, re.MULTILINE)
        self.assertIsNotNone(trigger, 'PR acceptance changes must execute the actual eight-case gate')
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
                        'qshd/src/modern_restart.rs', 'qshd/src/service_restart.rs',
                        'qshd/src/control_service_tests.rs', 'cli/src/ssh_step.rs',
                        'cli/src/busy_daemon.rs', 'cli/src/climb.rs'):
            self.assertTrue(any(fnmatch.fnmatchcase(changed, pattern) for pattern in paths), changed)
        self.assertFalse(any(fnmatch.fnmatchcase('README.md', pattern) for pattern in paths))
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('python3 scripts/released-peer-acceptance.py --evidence', workflow)
        release = (SCRIPT.parents[1] / '.github/workflows/release.yml').read_text()
        self.assertRegex(release, r'needs: \[release, ordinary-ci, released-peer-acceptance, release-verifier\]')
