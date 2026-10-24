#!/usr/bin/env python3
"""Build the link-only Rocky 8 ARM sysroot without executing foreign scripts."""
import argparse
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

FINGERPRINT = '7051C470A929F454CEBE37B715AF5DAC6D745A60'
KEY = Path('/etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-8')
TARGET = Path('/usr/aarch64-linux-gnu/sys-root')
QUERY = '%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n'


def checked_output(command):
    return subprocess.check_output(command).decode('utf-8').splitlines()


def verify_key(key, fingerprint, work):
    if not re.fullmatch(r'[A-F0-9]{40}', fingerprint):
        raise ValueError('invalid expected primary fingerprint')
    home = work / 'gnupg'
    home.mkdir(mode=0o700)
    lines = checked_output(['gpg', '--batch', '--no-options', '--no-autostart',
                            '--homedir', str(home), '--with-colons', '--show-keys', str(key)])
    primaries = []
    primary = False
    for line in lines:
        fields = line.split(':')
        if fields[0] == 'pub':
            primary = True
        elif fields[0] == 'sub':
            primary = False
        elif fields[0] == 'fpr' and primary:
            primaries.append(fields[9])
            primary = False
    if primaries != [fingerprint]:
        raise ValueError('Rocky signing key primary fingerprint mismatch')


def seed_layout(packages, database, target):
    aliases = {'/' + name: 'usr/' + name for name in ['bin', 'sbin', 'lib', 'lib64']}
    filesystems = [package for package in packages
                   if checked_output(['rpm', '--dbpath', str(database), '--query', '--package',
                                      '--queryformat', '%{NAME}\n', package]) == ['filesystem']]
    if not filesystems:
        return
    if len(filesystems) != 1:
        raise ValueError('resolved set contains multiple filesystem packages')
    links = {}
    for line in checked_output(['rpm', '--dbpath', str(database), '--query', '--package',
                                '--queryformat', '[%{FILENAMES}\t%{FILELINKTOS}\n]', filesystems[0]]):
        name, link = line.split('\t')
        if name in aliases:
            links[name] = link
    if links != aliases:
        raise ValueError('verified filesystem package has unexpected usr-merge layout')
    # filesystem's foreign %pretrans normally creates these before libgcc's
    # /lib64 payload. Seed only its authenticated, explicitly allowed aliases;
    # RPM still installs the full filesystem payload and owns its attributes.
    for name, link in sorted(links.items()):
        (target / link).mkdir(parents=True, exist_ok=True)
        (target / name.lstrip('/')).symlink_to(link)


def install_packages(packages, key, target, fingerprint=FINGERPRINT):
    if not packages:
        raise ValueError('no packages in resolved sysroot set')
    if target.is_symlink() or (target.exists() and any(target.iterdir())):
        raise ValueError('sysroot destination must be new or empty')
    with tempfile.TemporaryDirectory(prefix='qsh-sysroot-') as temporary:
        work = Path(temporary)
        public = work / 'key.asc'
        shutil.copyfile(str(key), str(public))
        verify_key(public, fingerprint, work)
        copies = []
        for index, package in enumerate(packages):
            if package.is_symlink() or not package.is_file():
                raise ValueError('RPM input is not a regular file')
            copy = work / ('package-{}.rpm'.format(index))
            shutil.copyfile(str(package), str(copy))
            copies.append(str(copy))
        database = work / 'rpmdb'
        database.mkdir()
        subprocess.run(['rpmkeys', '--dbpath', str(database), '--import', str(public)], check=True)
        # RPM 4.14 otherwise permits unsigned packages with valid ordinary digests.
        subprocess.run(['rpmkeys', '--dbpath', str(database), '--define',
                        '_pkgverify_level signature', '--checksig', *copies], check=True)
        expected = set()
        for package in copies:
            expected.update(checked_output(['rpm', '--dbpath', str(database), '--query',
                                            '--package', '--queryformat', QUERY, package]))
        if len(expected) != len(copies):
            raise ValueError('duplicate package identity in resolved sysroot set')
        target.mkdir(parents=True, exist_ok=True)
        seed_layout(copies, database, target)
        subprocess.run(['rpmkeys', '--root', str(target), '--import', str(public)], check=True)
        # Checked offline transaction: repeat mandatory verification while consuming
        # the same private copies, check dependencies, skip all script/trigger kinds.
        subprocess.run(['rpm', '--root', str(target), '--define', '_pkgverify_level signature',
                        '--ignorearch', '--noscripts', '--notriggers', '--install', *copies], check=True)
        installed = set(checked_output(['rpm', '--root', str(target), '--query', '--all',
                                        '--queryformat', QUERY]))
        installed = {name for name in installed if not name.startswith('gpg-pubkey-')}
        if installed != expected:
            raise ValueError('installed sysroot package inventory differs from verified set')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--packages', type=Path, help='offline resolved RPM set; signatures and dependencies still checked')
    args = parser.parse_args()
    if TARGET.is_symlink() or (TARGET.exists() and any(TARGET.iterdir())):
        parser.error('sysroot destination must be new or empty')
    with tempfile.TemporaryDirectory(prefix='qsh-sysroot-download-') as temporary:
        work = Path(temporary)
        # Validate the fixed certificate before any repository key import.
        key = work / 'key.asc'
        shutil.copyfile(str(KEY), str(key))
        verify_key(key, FINGERPRINT, work)
        packages = args.packages
        if packages is None:
            packages = work / 'packages'
            packages.mkdir()
            subprocess.run(['dnf', '-y', '--installroot=' + str(work / 'resolve'),
                            '--forcearch=aarch64', '--releasever=8', '--disablerepo=*',
                            '--enablerepo=baseos,appstream,extras',
                            '--setopt=module_platform_id=platform:el8',
                            '--setopt=install_weak_deps=False', '--setopt=gpgcheck=True',
                            '--setopt=localpkg_gpgcheck=True', '--downloadonly',
                            '--downloaddir=' + str(packages), 'install',
                            'glibc-devel', 'libgcc', 'pam-devel', 'glibc-headers'], check=True)
        install_packages(sorted(packages.glob('*.rpm')), key, TARGET)
    # The sysroot is link-only; none of its foreign executables were run.
    shutil.rmtree(str(TARGET / 'var/lib/rpm'))
    (TARGET / 'usr/lib64/libgcc_s.so').symlink_to('libgcc_s.so.1')


if __name__ == '__main__':
    main()
