#!/usr/bin/env python3
"""Exercise an exact Linux client archive or installed package in its owned floor namespace.

The selected version is mandatory; release CI supplies its existing checked
RELEASE_VERSION. This entry never builds product binaries or runs them on host.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import platform
import re
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def owner_module():
    spec = importlib.util.spec_from_file_location('artifact_namespace',
        ROOT / 'scripts' / 'client-artifact-namespace.py')
    owner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(owner)
    return owner


def floor_definition(fmt):
    text = (ROOT / 'packaging' / ('Dockerfile.build-' + fmt)).read_text()
    images = re.findall(r'^FROM ([^\s]+)$', text, re.M)
    floors = re.findall(r'^ENV QSHD_GLIBC_FLOOR=([0-9]+\.[0-9]+)$', text, re.M)
    if len(images) != 1 or '@sha256:' not in images[0] or len(floors) != 1:
        raise ValueError('package floor must have one pinned source declaration')
    return images[0], floors[0]


def prepare_image(fmt):
    base, floor = floor_definition(fmt)
    # Harness prerequisites only; neither the package nor product source is
    # present in this build context. Offline installation follows separately.
    command = ('apt-get update && apt-get install -y --no-install-recommends '
               'python3 openssh-client && rm -rf /var/lib/apt/lists/*') if fmt == 'deb' else (
               'dnf -y install python3 openssh-clients cpio && dnf clean all')
    with tempfile.TemporaryDirectory(prefix='qsh-client-floor-') as tmp:
        root = Path(tmp)
        (root / 'Dockerfile').write_text('FROM ' + base + '\nRUN ' + command + '\n')
        iid = root / 'image-id'
        result = subprocess.run(['docker', 'build', '--iidfile', str(iid), str(root)],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=300)
        if len(result.stdout) > 131072:
            raise ValueError('floor prerequisite build output exceeded limit')
        if result.returncode != 0:
            raise ValueError('floor prerequisite image failed: ' + result.stdout[-4096:].decode('utf8', 'replace'))
        image = iid.read_text().strip()
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', image):
            raise ValueError('floor prerequisite build returned invalid image identity')
    return image, floor


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package', type=Path, help='omit for archive-only acceptance')
    parser.add_argument('--archive', required=True, type=Path)
    parser.add_argument('--version', required=True)
    parser.add_argument('--target', required=True,
                        choices=('x86_64-unknown-linux-musl', 'aarch64-unknown-linux-musl'))
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != args.target.split('-')[0]:
        raise ValueError('installed client acceptance requires a matching native Linux runner')
    fmt = args.package.suffix[1:] if args.package is not None else 'deb'
    if fmt not in ('deb', 'rpm'):
        raise ValueError('client acceptance requires a DEB or RPM package')
    if not args.archive.is_file() or (args.package is not None and not args.package.is_file()):
        raise ValueError('explicit package and matching archive are required')
    image, floor = prepare_image(fmt)
    print(json.dumps({'floor_source': floor_definition(fmt)[0], 'floor_image': image,
                      'target': args.target, 'version': args.version}, sort_keys=True), flush=True)
    owner = owner_module()
    if args.package is None:
        owner.run_archive(args.archive, args.version, args.target, floor, image)
    else:
        owner.run_installed(args.package, args.archive, args.version, args.target, floor, image)


if __name__ == '__main__':
    main()
