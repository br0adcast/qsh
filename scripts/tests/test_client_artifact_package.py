"""Package boundary controls; no artifact executable or installation on host."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('installed_acceptance', ROOT / 'packaging/client-acceptance-inside.py')
inside = importlib.util.module_from_spec(spec)
spec.loader.exec_module(inside)


class ClientPackageTests(unittest.TestCase):
    def test_exact_payloads_and_changed_installed_bytes(self):
        with tempfile.TemporaryDirectory(prefix='qsh-payload-boundary-') as tmp:
            paths = [Path(tmp) / name for name in ('package', 'archive', 'installed')]
            for path in paths:
                path.write_bytes(b'owned fixture payload')
            self.assertEqual(len(inside.equal_payloads(*paths)), 64)
            paths[-1].write_bytes(b'different installed payload')
            with self.assertRaisesRegex(ValueError, 'payload differs'):
                inside.equal_payloads(*paths)

    def test_payload_alias_and_missing_layout_are_rejected(self):
        with tempfile.TemporaryDirectory(prefix='qsh-layout-boundary-') as tmp:
            root = Path(tmp)
            (root / 'source').write_bytes(b'fixture')
            (root / 'alias').symlink_to(root / 'source')
            with self.assertRaisesRegex(ValueError, 'regular file'):
                inside.equal_payloads(root / 'source', root / 'alias')
            with self.assertRaises(FileNotFoundError):
                inside.equal_payloads(root / 'missing', root / 'source')

    def test_wrong_payload_or_layout_cannot_reach_installation(self):
        for wrong in ('payload', 'layout'):
            with self.subTest(wrong=wrong), tempfile.TemporaryDirectory(prefix='qsh-install-gate-') as tmp:
                root = Path(tmp)
                commands = []
                def checked(command):
                    commands.append(command)
                    if command == ['getconf', 'GNU_LIBC_VERSION']:
                        return 'glibc 2.28'
                    self.fail('preflight failure reached an installation/DB command')
                def archive(_archive, directory, *_args):
                    (directory / 'qsh').write_bytes(b'archive fixture')
                def extract(_package, _fmt, directory):
                    target = directory / 'usr/bin' / ('elsewhere' if wrong == 'layout' else 'qsh')
                    target.parent.mkdir(parents=True)
                    target.write_bytes(b'wrong package fixture')
                with mock.patch.object(inside.sys, 'platform', 'linux'), \
                     mock.patch.object(inside.os, 'geteuid', return_value=0), \
                     mock.patch.object(inside.platform, 'machine', return_value='x86_64'), \
                     mock.patch.object(inside, 'module', return_value=mock.Mock()), \
                     mock.patch.object(inside, 'checked', side_effect=checked), \
                     mock.patch.object(inside, 'archive_inputs', side_effect=archive), \
                     mock.patch.object(inside, 'extract_package', side_effect=extract), \
                     mock.patch.object(inside.tempfile, 'mkdtemp', return_value=str(root)):
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        inside.run('/artifacts/qsh-0.5.0-1.x86_64.rpm', '/artifacts/input.tar.gz',
                                   '0.5.0', 'x86_64-unknown-linux-musl', '2.28')
                self.assertEqual(commands, [['getconf', 'GNU_LIBC_VERSION']])

    def test_internal_bootstrap_refuses_standalone_before_effects(self):
        result = subprocess.run([sys.executable, str(ROOT / 'packaging/client-acceptance-inside.py')],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'internal bootstrap', result.stderr)


if __name__ == '__main__':
    unittest.main()
