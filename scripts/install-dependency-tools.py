#!/usr/bin/env python3
"""Verify pinned Linux CI tools before publishing or executing their binaries."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import tempfile
import urllib.request


PINS = Path(__file__).with_name('dependency-tools.json')


def load_pins():
    pins = json.loads(PINS.read_text())
    if {pin['name'] for pin in pins} != {'cargo-audit', 'cargo-deny'} or len(pins) != 2:
        raise ValueError('expected exactly the reviewed audit and deny tools')
    return pins


def verify_tool(pin, binary):
    if hashlib.sha256(binary.read_bytes()).hexdigest() != pin['binary_sha256']:
        raise ValueError(f"binary checksum mismatch: {pin['name']}")
    result = subprocess.run([str(binary), '--version'], env=dict(os.environ, CARGO_TERM_COLOR='never'),
                            capture_output=True, text=True,
                            timeout=30, check=True)
    if result.stdout.strip() != pin['version_output'] or result.stderr:
        raise ValueError(f"unexpected tool version: {pin['name']}")


def install_archive(pin, archive, directory):
    if hashlib.sha256(archive.read_bytes()).hexdigest() != pin['sha256']:
        raise ValueError(f"archive checksum mismatch: {pin['name']}")
    with tarfile.open(archive, 'r:gz') as tar:
        matches = [entry for entry in tar.getmembers() if entry.name == pin['entry']]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError(f"expected one regular tool binary: {pin['name']}")
        body = tar.extractfile(matches[0]).read()
    if hashlib.sha256(body).hexdigest() != pin['binary_sha256']:
        raise ValueError(f"binary checksum mismatch: {pin['name']}")
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.verified-tool-', dir=directory) as staging:
        binary = Path(staging) / pin['name']
        binary.write_bytes(body)
        binary.chmod(0o700)
        verify_tool(pin, binary)
        os.replace(binary, directory / pin['name'])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, required=True)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('these pinned CI tools require Linux x86_64')
    with tempfile.TemporaryDirectory(prefix='qsh-dependency-download-') as staging:
        for pin in load_pins():
            archive = Path(staging) / (pin['name'] + '.tar.gz')
            with urllib.request.urlopen(pin['url'], timeout=120) as response:
                archive.write_bytes(response.read())
            install_archive(pin, archive, args.directory.resolve())
            print(pin['version_output'] + ': archive, binary and version verified')


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f'dependency tool verification failed: {error}', file=sys.stderr)
        sys.exit(1)
