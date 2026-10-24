#!/usr/bin/env python3
"""Install the reviewed rustup bootstrap; retain the qualified Rust toolchain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile

HOSTS = ('x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu')
TOOLCHAIN = '1.98.1'


def host_tuple(system, machine):
    hosts = {'x86_64': HOSTS[0], 'aarch64': HOSTS[1]}
    if system != 'Linux' or machine not in hosts:
        raise ValueError('unsupported build host: {} {}'.format(system, machine))
    return hosts[machine]


def validate_pin(pin):
    if (set(pin) != {'version', 'host', 'sha256'} or pin['host'] not in HOSTS
            or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', pin['version'])
            or not re.fullmatch(r'[0-9a-f]{64}', pin['sha256'])):
        raise ValueError('invalid reviewed bootstrap pin')


def download(pin, destination):
    validate_pin(pin)
    url = 'https://static.rust-lang.org/rustup/archive/{}/{}/rustup-init'.format(
        pin['version'], pin['host'])
    subprocess.run(['curl', '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2',
                    '--fail', '--location', '--silent', '--show-error', url,
                    '--output', str(destination)], check=True)


def install_verified(archive, pin, environment):
    validate_pin(pin)
    if archive.is_symlink() or not archive.is_file():
        raise ValueError('bootstrap input is not a regular file')
    with tempfile.TemporaryDirectory(prefix='qsh-rustup-') as temporary:
        executable = Path(temporary) / 'rustup-init'
        # Execute a private copy, never a potentially replaced cache pathname.
        with archive.open('rb') as source, executable.open('xb') as target:
            shutil.copyfileobj(source, target)
        with executable.open('rb') as source:
            checksum = hashlib.sha256()
            for chunk in iter(lambda: source.read(65536), b''):
                checksum.update(chunk)
        if checksum.hexdigest() != pin['sha256']:
            raise ValueError('bootstrap SHA-256 mismatch')
        executable.chmod(0o700)
        subprocess.run([str(executable), '-y', '--no-modify-path', '--profile', 'minimal',
                        '--default-toolchain', 'none'], env=environment, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='local installer; still checked against committed pin')
    args = parser.parse_args()
    host = host_tuple(platform.system(), platform.machine())
    manifest = json.loads((Path(__file__).resolve().parent / 'rustup.json').read_text())
    pin = {'version': manifest['version'], 'host': host, 'sha256': manifest['hosts'][host]}
    validate_pin(pin)
    environment = os.environ.copy()
    # Retain the official distribution trust domain even in a modified build environment.
    environment.update(RUSTUP_DIST_SERVER='https://static.rust-lang.org',
                       RUSTUP_UPDATE_ROOT='https://static.rust-lang.org/rustup',
                       RUSTUP_VERSION=pin['version'])
    cargo = Path(environment['CARGO_HOME'])
    with tempfile.TemporaryDirectory(prefix='qsh-rustup-download-') as temporary:
        archive = args.archive
        if archive is None:
            archive = Path(temporary) / 'rustup-init'
            download(pin, archive)
        install_verified(archive, pin, environment)
    rustup = str(cargo / 'bin/rustup')
    subprocess.run([rustup, 'set', 'auto-self-update', 'disable'], env=environment, check=True)
    subprocess.run([rustup, 'toolchain', 'install', TOOLCHAIN, '--profile', 'minimal'],
                   env=environment, check=True)
    subprocess.run([rustup, 'default', TOOLCHAIN], env=environment, check=True)
    subprocess.run([rustup, 'target', 'add', '--toolchain', TOOLCHAIN, *HOSTS],
                   env=environment, check=True)


if __name__ == '__main__':
    main()
