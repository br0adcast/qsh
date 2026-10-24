#!/usr/bin/env python3
"""Real RPM 4.14 controls, run in the existing Rocky packaging image offline."""
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

import rpm

SPEC = importlib.util.spec_from_file_location('sysroot_install', Path(__file__).with_name('install-sysroot.py'))
sysroot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sysroot)

# Lua prints are captured to a private file by the real RPM subprocess. Unlike
# a warn-only scriptlet error, these directly establish whether a body ran.
SENTINEL_PREFIX = 'QSH_RPM_EXECUTED:'
SCRIPT_KINDS = {'pretrans', 'pre', 'post', 'posttrans'}
TRIGGER_KINDS = {'triggerin', 'filetriggerin', 'transfiletriggerin'}


class SysrootTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix='qsh-rpm-controls-')
        cls.root = Path(cls.temporary.name)
        cls.home = cls.root / 'home'
        cls.home.mkdir(mode=0o700)
        cls.environment = dict(os.environ, HOME=str(cls.home), GNUPGHOME=str(cls.home),
                               XDG_CONFIG_HOME=str(cls.home), XDG_CACHE_HOME=str(cls.home),
                               HISTFILE='/dev/null')
        cls.original = os.environ.copy()
        os.environ.update(cls.environment)
        cls.keys = []
        for name in ['trusted', 'other']:
            subprocess.run(['gpg', '--batch', '--pinentry-mode', 'loopback', '--passphrase', '',
                            '--quick-generate-key', 'Disposable qsh ' + name, 'rsa2048', 'sign', '0'],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            keys = subprocess.check_output(['gpg', '--batch', '--with-colons', '--list-keys', name])
            fingerprint = next(line.split(b':')[9].decode() for line in keys.splitlines()
                               if line.startswith(b'fpr:'))
            public = cls.root / (name + '.asc')
            public.write_bytes(subprocess.check_output(['gpg', '--batch', '--armor', '--export', fingerprint]))
            cls.keys.append((public, fingerprint))
        rpm.addMacro('_gpg_path', str(cls.home))
        rpm.addMacro('__gpg', '/usr/bin/gpg')
        cls.package = cls.build('qsh-trust-fixture', scripts=True)
        cls.unsigned = cls.root / 'unsigned.rpm'
        shutil.copyfile(str(cls.package), str(cls.unsigned))
        rpm.addMacro('_gpg_name', cls.keys[0][1])
        rpm.addSign(str(cls.package))
        cls.other = cls.build('qsh-other-fixture')
        rpm.addMacro('_gpg_name', cls.keys[1][1])
        rpm.addSign(str(cls.other))
        cls.dependent = cls.build('qsh-dependent-fixture', requires='qsh-missing-provider = 1')
        rpm.addMacro('_gpg_name', cls.keys[0][1])
        rpm.addSign(str(cls.dependent))
        cls.library = cls.build('qsh-early-library', library=True)
        rpm.addSign(str(cls.library))
        cls.filesystem = cls.build('filesystem', requires='qsh-early-library = 1', layout=True)
        rpm.addSign(str(cls.filesystem))

    @classmethod
    def tearDownClass(cls):
        subprocess.run(['gpgconf', '--homedir', str(cls.home), '--kill', 'all'],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        os.environ.clear()
        os.environ.update(cls.original)
        cls.temporary.cleanup()

    @classmethod
    def build(cls, name, scripts=False, requires=None, layout=False, library=False):
        top = cls.root / name
        for directory in ['SPECS', 'SOURCES', 'BUILD', 'BUILDROOT', 'RPMS', 'SRPMS']:
            (top / directory).mkdir(parents=True)
        extra_install = ''
        extra_files = ''
        if layout:
            for alias in ['bin', 'sbin', 'lib', 'lib64']:
                extra_install += 'mkdir -p %{{buildroot}}/usr/{0}\nln -s usr/{0} %{{buildroot}}/{0}\n'.format(alias)
                extra_files += '/' + alias + '\n'
        if library:
            extra_install += 'mkdir -p %{buildroot}/lib64\nprintf library > %{buildroot}/lib64/qsh-trust-library\n'
            extra_files += '/lib64/qsh-trust-library\n'
        spec = top / 'SPECS/fixture.spec'
        spec.write_text('''Name: {name}
Version: 1
Release: 1
Summary: Disposable local verification fixture
License: MIT
BuildArch: noarch
{requires}
%description
Disposable test fixture; never distributed.
%install
mkdir -p %{{buildroot}}/usr/share/{name}
printf fixture > %{{buildroot}}/usr/share/{name}/payload
{extra_install}
{scripts}
%files
/usr/share/{name}/payload
{extra_files}
'''.format(name=name, extra_install=extra_install, extra_files=extra_files, requires=('Requires: ' + requires) if requires else '', scripts='''%pretrans -p <lua>
print("QSH_RPM_EXECUTED:pretrans")
%pre -p <lua>
print("QSH_RPM_EXECUTED:pre")
%post -p <lua>
print("QSH_RPM_EXECUTED:post")
%posttrans -p <lua>
print("QSH_RPM_EXECUTED:posttrans")
%triggerin -p <lua> -- qsh-trust-fixture
print("QSH_RPM_EXECUTED:triggerin")
%filetriggerin -p <lua> -- /usr/share
print("QSH_RPM_EXECUTED:filetriggerin")
%transfiletriggerin -p <lua> -- /usr/share
print("QSH_RPM_EXECUTED:transfiletriggerin")
''' if scripts else ''))
        subprocess.run(['rpmbuild', '--define', '_topdir ' + str(top), '-bb', str(spec)],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return next((top / 'RPMS').glob('*/*.rpm'))

    def setUp(self):
        self.case = Path(tempfile.mkdtemp(dir=str(self.root)))
        self.target = self.case / 'sysroot'

    def install(self, packages, key=None):
        key, fingerprint = key or self.keys[0]
        return sysroot.install_packages(packages, key, self.target, fingerprint)

    def install_observed(self, enabled=()):
        output = self.case / 'transaction-output'
        real_run = subprocess.run
        with output.open('wb') as capture:
            def observe(command, **kwargs):
                if command[0] == 'rpm' and '--install' in command:
                    command = [part for part in command if part not in enabled]
                # check_output retains its PIPE; all inherited scriptlet output
                # goes to this owned file rather than relying on RPM's status.
                kwargs.setdefault('stdout', capture)
                kwargs.setdefault('stderr', capture)
                return real_run(command, **kwargs)
            with mock.patch.object(sysroot.subprocess, 'run', side_effect=observe):
                self.install([self.package])
        return {line[len(SENTINEL_PREFIX):] for line in output.read_text().splitlines()
                if line.startswith(SENTINEL_PREFIX)}

    def test_trusted_package_installs_without_any_scriptlets(self):
        observed = self.install_observed()
        self.assertEqual(observed, set(), 'package bodies ran: ' + repr(observed))
        self.assertEqual((self.target / 'usr/share/qsh-trust-fixture/payload').read_bytes(), b'fixture')

    def test_enabled_transaction_observes_every_script_and_trigger_kind(self):
        # RPM 4.14's --noscripts also suppresses triggers: explicitly enable
        # both families, rather than assuming removal of --notriggers suffices.
        observed = self.install_observed(enabled={'--noscripts', '--notriggers'})
        self.assertEqual(observed, SCRIPT_KINDS | TRIGGER_KINDS)
        self.assertEqual((self.target / 'usr/share/qsh-trust-fixture/payload').read_bytes(), b'fixture')

    def test_verified_filesystem_layout_precedes_library_payloads(self):
        self.install([self.filesystem, self.library])
        for alias in ['bin', 'sbin', 'lib', 'lib64']:
            self.assertEqual(os.readlink(str(self.target / alias)), 'usr/' + alias)
        self.assertEqual((self.target / 'usr/lib64/qsh-trust-library').read_bytes(), b'library')

    def test_unsigned_package_cannot_install_even_with_valid_digests(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.install([self.unsigned])
        self.assertFalse((self.target / 'usr').exists())

    def test_other_signer_cannot_install_any_payload(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.install([self.package, self.other])
        self.assertFalse((self.target / 'usr').exists())

    def test_tampered_and_truncated_package_cannot_install(self):
        for content in [self.package.read_bytes()[:-1] + b'X', b'not an rpm']:
            package = self.case / 'bad.rpm'
            package.write_bytes(content)
            with self.subTest(size=len(content)):
                with self.assertRaises(subprocess.CalledProcessError):
                    self.install([package])
                self.assertFalse((self.target / 'usr').exists())

    def test_unreviewed_primary_key_cannot_grant_trust(self):
        with self.assertRaisesRegex(ValueError, 'fingerprint'):
            sysroot.install_packages([self.other], self.keys[1][0], self.target, self.keys[0][1])
        self.assertFalse(self.target.exists())

    def test_missing_dependency_stops_the_offline_transaction(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self.install([self.dependent])
        self.assertFalse((self.target / 'usr').exists())

    def test_altered_private_input_after_verification_is_rejected_again(self):
        real_run = subprocess.run
        def alter_before_install(command, **kwargs):
            if command[0] == 'rpm' and '--install' in command:
                package = Path(command[-1])
                content = package.read_bytes()
                package.write_bytes(content[:-1] + bytes([content[-1] ^ 1]))
            return real_run(command, **kwargs)
        with mock.patch.object(sysroot.subprocess, 'run', side_effect=alter_before_install):
            with self.assertRaises(subprocess.CalledProcessError):
                self.install([self.package])
        self.assertFalse((self.target / 'usr').exists())

    def test_existing_or_redirected_destination_preserves_its_contents(self):
        existing = self.case / 'existing'
        existing.mkdir()
        marker = existing / 'owned'
        marker.write_text('preserve')
        self.target.symlink_to(existing)
        with self.assertRaisesRegex(ValueError, 'new or empty'):
            self.install([self.package])
        self.assertEqual(marker.read_text(), 'preserve')
        self.target.unlink()
        self.target.mkdir()
        (self.target / 'owned').write_text('preserve')
        with self.assertRaisesRegex(ValueError, 'new or empty'):
            self.install([self.package])
        self.assertEqual((self.target / 'owned').read_text(), 'preserve')

    def test_empty_set_is_not_a_valid_sysroot(self):
        with self.assertRaisesRegex(ValueError, 'no packages'):
            self.install([])
        self.assertFalse(self.target.exists())


if __name__ == '__main__':
    unittest.main()
