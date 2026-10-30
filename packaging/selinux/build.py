#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Compile the reviewed policy with explicit, signed old-floor inputs.

Run inside the pinned build environment; never installs or loads policy.
"""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile

HERE = Path(__file__).resolve().parent
QUALIFIED = {
    'qshd.te': '7221989093de7c5e7e015e613446d78f869c14001cedf79dac44303758a02f09',
    'qshd.fc': '563b0c6804699187eeea5dd98f737025685c25d5e178c61221f5e2f9c2e06317',
    'qshd.if': hashlib.sha256(b'\n').hexdigest(),
}


BUNDLE_SOURCE_FILES = ('qshd.te', 'qshd.fc', 'qshd.if', 'build.py',
                       'inputs.json', 'artifact.json', 'README.md', 'GPL-3.0.txt',
                       'Dockerfile')


def bundle_source_files(source):
    return {'packaging/selinux/' + name: source / name
            for name in BUNDLE_SOURCE_FILES}


def compile_environment(work, epoch):
    # Never inherit make macros, loader settings, shell startup hooks or PATH.
    return dict(PATH='/usr/bin:/usr/sbin:/bin:/sbin', LC_ALL='C', LANG='C',
                TZ='UTC', SOURCE_DATE_EPOCH=str(epoch), HOME=str(work / 'home'),
                XDG_CACHE_HOME=str(work / 'cache'), XDG_CONFIG_HOME=str(work / 'config'),
                HISTFILE='/dev/null')


def compile_command(share):
    return ['/usr/bin/make', '-f', str(share / 'devel/Makefile'),
            'SHAREDIR=' + str(share), 'NAME=targeted', 'TYPE=mcs',
            'M4=/usr/bin/m4', 'AWK=/usr/bin/gawk', 'DIRECT_INITRC=n', 'qshd.pp']


def canonical(data):
    return ('\n'.join(line.strip() for line in data.decode().splitlines()
                      if line.strip() and not line.lstrip().startswith('#')) + '\n').encode()


def validate_sources(source):
    for name, expected in QUALIFIED.items():
        if hashlib.sha256(canonical((source / name).read_bytes())).hexdigest() != expected:
            raise ValueError('source differs from qualified policy: ' + name)


def validate_paths(source, work, output):
    paths = [path.resolve() for path in (source, work, output)]
    for index, path in enumerate(paths):
        for other in paths[index + 1:]:
            if path == other or path in other.parents or other in path.parents:
                raise ValueError('source, work and output paths overlap')
    if work.exists() or output.exists():
        raise ValueError('work/output paths must not exist (stale output)')


def validate_package(data, expected_contexts):
    """Read libsepol PP v1/module headers, requiring the qualified format floor."""
    try:
        magic, version, count, module_start, context_start = struct.unpack_from('<5I', data)
        if (magic, version, count, module_start) != (0xf97cff8f, 1, 2, 20):
            raise ValueError('unexpected policy package format')
        if not 20 < context_start < len(data):
            raise ValueError('invalid package section offsets')
        module = data[module_start:context_start]
        magic, length = struct.unpack_from('<2I', module)
        if magic != 0xf97cff8d or module[8:8 + length] != b'SE Linux Module':
            raise ValueError('unexpected module format')
        offset = 8 + length
        kind, policy_version, flags, symbols, contexts = struct.unpack_from('<5I', module, offset)
        if (kind, policy_version, flags, symbols, contexts) != (2, 19, 1, 8, 0):
            raise ValueError('module is outside the qualified format floor')
        offset += 20
        for expected in (b'qshd', b'0.2.0'):
            length = struct.unpack_from('<I', module, offset)[0]
            offset += 4
            if module[offset:offset + length] != expected:
                raise ValueError('unexpected module name/version')
            offset += length
        if struct.unpack_from('<I', data, context_start)[0] != 0xf97cff90:
            raise ValueError('missing file-context section')
        if canonical(data[context_start + 4:]) != canonical(expected_contexts):
            raise ValueError('unexpected embedded file contexts')
    except (struct.error, UnicodeError) as error:
        raise ValueError('truncated or invalid policy package') from error


def source_bundle(output, files, epoch):
    """Archive exact build inputs with stable order, ownership and timestamps."""
    with output.open('xb') as raw:
        with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=epoch) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.PAX_FORMAT) as archive:
                for name, path in sorted(files.items()):
                    data = path.read_bytes()
                    info = tarfile.TarInfo(name)
                    info.size, info.mtime, info.mode = len(data), epoch, 0o644
                    info.uid = info.gid = 0
                    archive.addfile(info, io.BytesIO(data))


def run(command, **kwargs):
    return subprocess.run(command, check=True, **kwargs)


def workspace_version(manifest):
    # Python 3.6 in the old-floor environment has no tomllib. Restrict the read
    # to the explicit workspace.package section rather than guessing a version.
    section = re.search(r'^\[workspace\.package\]\s*$(.*?)(?=^\[|\Z)',
                        manifest.read_text(), re.MULTILINE | re.DOTALL)
    match = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*$',
                      section.group(1) if section else '', re.MULTILINE)
    if not match:
        raise ValueError('missing explicit workspace package version')
    return match.group(1)


def build(args):
    source, work, output = HERE, args.work.resolve(), args.output.resolve()
    validate_paths(source, work, output)
    validate_sources(source)
    if args.epoch < 0 or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+', args.version):
        raise ValueError('explicit source epoch and workspace version are required')
    if args.version != workspace_version(HERE.parents[1] / 'Cargo.toml'):
        raise ValueError('requested version differs from source workspace version')
    pins = json.loads((HERE / 'inputs.json').read_text())
    files = {}
    # Verify all inputs before extraction. A caller-selected RPM key database must
    # contain only the reviewed distribution key; do not import keys here.
    for name, expected in pins['rpms'].items():
        path = args.inputs.resolve() / name
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('input checksum mismatch: ' + name)
        receipt = run(['rpmkeys', '--dbpath', str(args.keyring.resolve()), '--checksig', str(path)],
                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT).stdout.decode()
        if 'signatures OK' not in receipt or 'NOT OK' in receipt or 'NOKEY' in receipt:
            raise ValueError('input signature was not verified: ' + name)
        # Compiler executables are external tools, not incorporated policy.
        # Do not redistribute their binary RPMs in the policy source bundle.
        if name in (pins['policy_devel'], pins['policy_source']):
            files['inputs/' + name] = path
    for package, expected in pins['installed_tools'].items():
        version = run(['rpm', '-q', '--qf', '%{VERSION}-%{RELEASE}.%{ARCH}', package],
                      stdout=subprocess.PIPE).stdout.decode()
        if version != expected:
            raise ValueError('compiler/tool floor mismatch: ' + package)
    os.umask(0o022)
    work.mkdir()
    extract, compile_dir = work / 'extract', work / 'compile'
    extract.mkdir()
    compile_dir.mkdir()
    policy_rpm = args.inputs.resolve() / pins['policy_devel']
    # The pinned RPM is trusted only after signature and digest verification.
    with (work / 'policy.cpio').open('xb') as stream:
        run(['rpm2cpio', str(policy_rpm)], stdout=stream)
    with (work / 'policy.cpio').open('rb') as stream:
        run(['cpio', '-idm', '--quiet', '--no-absolute-filenames'], cwd=extract, stdin=stream)
    share = extract / 'usr/share/selinux'
    if not (share / 'devel/include/Makefile').is_file():
        raise ValueError('selected old-floor include tree is missing')
    for name in QUALIFIED:
        shutil.copyfile(source / name, compile_dir / name)
    run(compile_command(share), cwd=compile_dir,
        env=compile_environment(work, args.epoch))
    contexts = b'\n'.join(line.replace(b'gen_context(', b'').replace(b',s0)', b':s0')
                           for line in canonical((source / 'qshd.fc').read_bytes()).splitlines()) + b'\n'
    pp = (compile_dir / 'qshd.pp').read_bytes()
    validate_package(pp, contexts)
    output.mkdir()
    (output / 'qshd.pp').write_bytes(pp)
    (output / 'qshd.fc').write_bytes(contexts)
    files.update(bundle_source_files(source))
    files['LICENSE'] = HERE.parents[1] / 'LICENSE'
    files['Cargo.toml'] = HERE.parents[1] / 'Cargo.toml'
    source_bundle(output / ('qshd-selinux-' + args.version + '-source.tar.gz'), files, args.epoch)
    for path in output.iterdir():
        path.chmod(0o644)
        os.utime(path, (args.epoch, args.epoch))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--keyring', type=Path, required=True)
    parser.add_argument('--work', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--epoch', type=int, required=True)
    parser.add_argument('--version', required=True, help='source workspace version; no release bump')
    args = parser.parse_args()
    try:
        build(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, 'policy build failed: ' + str(error) + '\n')


if __name__ == '__main__':
    main()
