"""Bootstrap trust controls use local executable fixtures, never the network."""
import hashlib
import importlib.util
import json
import os
import shutil
import sys
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('bootstrap_rust', ROOT / 'packaging/bootstrap/install-rust.py')
bootstrap = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bootstrap)


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.marker = self.root / 'executed'
        self.installer = self.root / 'installer'
        self.installer.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$BOOTSTRAP_MARKER"\n')
        self.pin = {'version': '1.29.0', 'host': 'x86_64-unknown-linux-gnu',
                    'sha256': hashlib.sha256(self.installer.read_bytes()).hexdigest()}
        self.environment = os.environ.copy()
        self.environment.update(HOME=str(self.root), XDG_CACHE_HOME=str(self.root / 'cache'),
                                XDG_CONFIG_HOME=str(self.root / 'config'), HISTFILE='/dev/null',
                                BOOTSTRAP_MARKER=str(self.marker))

    def install(self):
        bootstrap.install_verified(self.installer, self.pin, self.environment)

    def test_verified_installer_executes_only_after_verification(self):
        self.install()
        self.assertEqual(self.marker.read_text().splitlines(),
                         ['-y', '--no-modify-path', '--profile', 'minimal',
                          '--default-toolchain', 'none'])

    def test_complete_entrypoint_disables_self_update_before_installing_fixed_toolchain(self):
        bundle = self.root / 'bundle'
        bundle.mkdir()
        shutil.copyfile(str(ROOT / 'packaging/bootstrap/install-rust.py'), str(bundle / 'install-rust.py'))
        rustup = self.root / 'fixture-rustup'
        rustup.write_text('#!/bin/sh\n'
                          'if [ "$1 $2 $3" = "set auto-self-update disable" ]; then\n'
                          '  touch "$CARGO_HOME/self-update-disabled"\n'
                          'else\n'
                          '  test -f "$CARGO_HOME/self-update-disabled" || exit 91\n'
                          'fi\n'
                          'printf "%s\\n" "$*" >> "$BOOTSTRAP_MARKER"\n')
        rustup.chmod(0o700)
        self.installer.write_text('#!/bin/sh\nmkdir -p "$CARGO_HOME/bin"\n'
                                  'cp "$FIXTURE_RUSTUP" "$CARGO_HOME/bin/rustup"\n')
        checksum = hashlib.sha256(self.installer.read_bytes()).hexdigest()
        (bundle / 'rustup.json').write_text(json.dumps({'version': '1.29.0', 'hosts': {
            'x86_64-unknown-linux-gnu': checksum, 'aarch64-unknown-linux-gnu': checksum}}))
        environment = dict(self.environment, CARGO_HOME=str(self.root / 'cargo'),
                           RUSTUP_HOME=str(self.root / 'rustup'), FIXTURE_RUSTUP=str(rustup))
        subprocess.run([sys.executable, str(bundle / 'install-rust.py'), '--archive', str(self.installer)],
                       env=environment, check=True)
        self.assertEqual(self.marker.read_text().splitlines(), [
            'set auto-self-update disable', 'toolchain install 1.98.1 --profile minimal',
            'default 1.98.1',
            'target add --toolchain 1.98.1 x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu'])

    def test_changed_bytes_never_execute(self):
        self.installer.write_text(self.installer.read_text() + '# changed\n')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            self.install()
        self.assertFalse(self.marker.exists())

    def test_missing_input_never_executes(self):
        self.installer.unlink()
        with self.assertRaises((ValueError, OSError)):
            self.install()
        self.assertFalse(self.marker.exists())

    def test_directory_and_symlink_inputs_are_rejected(self):
        self.installer.unlink()
        for kind in ['symlink', 'directory']:
            if kind == 'symlink':
                self.installer.symlink_to('/dev/null')
            else:
                self.installer.mkdir()
            with self.subTest(kind=kind):
                with self.assertRaisesRegex(ValueError, 'regular file'):
                    self.install()
                self.assertFalse(self.marker.exists())
            if kind == 'symlink':
                self.installer.unlink()

    def test_failed_download_never_executes_partial_bytes(self):
        destination = self.root / 'download'
        def failed(command, **kwargs):
            Path(command[-1]).write_bytes(self.installer.read_bytes())
            raise subprocess.CalledProcessError(22, command)
        with mock.patch.object(bootstrap.subprocess, 'run', side_effect=failed):
            with self.assertRaises(subprocess.CalledProcessError):
                bootstrap.download(self.pin, destination)
        self.assertFalse(self.marker.exists())

    def test_unsupported_host_is_rejected_before_download(self):
        for system, machine in [('Windows', 'AMD64'), ('Linux', 'riscv64')]:
            with self.subTest(system=system, machine=machine):
                with self.assertRaisesRegex(ValueError, 'unsupported build host'):
                    bootstrap.host_tuple(system, machine)

    def test_both_supported_host_architectures_select_their_own_installer(self):
        self.assertEqual(bootstrap.host_tuple('Linux', 'x86_64'), 'x86_64-unknown-linux-gnu')
        self.assertEqual(bootstrap.host_tuple('Linux', 'aarch64'), 'aarch64-unknown-linux-gnu')

    def test_invalid_or_unreviewed_pin_is_rejected(self):
        for mutation in [{'version': 'latest'}, {'sha256': 'x' * 64},
                         {'host': 'other'}, {'url': 'https://example.invalid/installer'}]:
            pin = dict(self.pin, **mutation)
            with self.subTest(mutation=mutation):
                with self.assertRaises(ValueError):
                    bootstrap.validate_pin(pin)


if __name__ == '__main__':
    unittest.main()
