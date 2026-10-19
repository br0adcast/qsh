#!/usr/bin/env python3
"""Build the pinned OpenSSL source; print only its verified prefix to stdout."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import subprocess
import sys
import tarfile
import tempfile

TARGETS = {
    'x86_64-unknown-linux-musl': 'linux-x86_64',
    'aarch64-unknown-linux-musl': 'linux-aarch64',
    'x86_64-unknown-linux-gnu': 'linux-x86_64',
    'aarch64-unknown-linux-gnu': 'linux-aarch64',
    'x86_64-apple-darwin': 'darwin64-x86_64-cc',
    'aarch64-apple-darwin': 'darwin64-arm64-cc',
}
OPTIONS = ['no-shared', 'no-tests', 'no-module', 'no-dso', 'no-engine',
           'no-async', 'no-zlib', '--libdir=lib', '--prefix=/qsh-openssl',
           '--openssldir=/qsh-openssl']
PIN_DIR = Path(__file__).resolve().parent / 'openssl'


def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def run(command, **kwargs):
    # Each subprocess group is ours, including make/compiler grandchildren.
    # Cancellation stops that group and reaps the direct child before cleanup.
    data = kwargs.pop('input', None)
    with subprocess.Popen(command, start_new_session=True, **kwargs) as child:
        try:
            stdout, stderr = child.communicate(data)
        except BaseException:
            # Kill before reaping the group leader: after wait its numeric
            # identity could be reused. These are disposable build processes,
            # not a service requiring a graceful shutdown protocol.
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            child.wait()
            raise
        result = subprocess.CompletedProcess(command, child.returncode, stdout, stderr)
        result.check_returncode()
        return result


def output(command, **kwargs):
    return run(command, stdout=subprocess.PIPE, universal_newlines=True, **kwargs).stdout.strip()


def verify_source(archive, pin, temporary):
    if not archive.is_file():
        raise ValueError('archive is not a regular file')
    if digest(archive) != pin['sha256']:
        raise ValueError('archive SHA-256 mismatch')
    for filename, field in [('release-key.asc', 'key_sha256'),
                            ('source.tar.gz.asc', 'signature_sha256')]:
        if digest(PIN_DIR / filename) != pin[field]:
            raise ValueError('pinned signature material mismatch: ' + filename)
    key_home = temporary / 'gnupg'
    key_home.mkdir(mode=0o700)
    base = ['gpg', '--batch', '--no-options', '--no-autostart',
            '--homedir', str(key_home)]
    run(base + ['--import', str(PIN_DIR / 'release-key.asc')],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    status = run(base + ['--status-fd', '1', '--verify',
                         str(PIN_DIR / 'source.tar.gz.asc'), str(archive)],
                 stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout
    # GPG notation payloads can contain arbitrary bytes; only the ASCII
    # VALIDSIG record and pinned primary fingerprint grant trust.
    if not any(line.startswith(b'[GNUPG:] VALIDSIG ') and
               line.split()[-1] == pin['signer'].encode('ascii')
               for line in status.splitlines()):
        raise ValueError('release signature does not match pinned primary key')


def tool_identity(name):
    path = shutil.which(name)
    if path is None:
        raise ValueError('native tool is not executable: ' + name)
    path = str(Path(path).absolute())
    return {'path': path, 'sha256': digest(Path(path))}


def compiler(args):
    name = args.cc or ('musl-gcc' if args.target.endswith('-musl') else 'cc')
    path = shutil.which(name)
    if path is None:
        raise ValueError('compiler is not executable: ' + name)
    path = str(Path(path).absolute())
    flags = list(args.cflag)
    if args.target.endswith('-apple-darwin'):
        arch = 'arm64' if args.target.startswith('aarch64-') else 'x86_64'
        flags += ['-arch', arch, '-isysroot', output(['xcrun', '--show-sdk-path'])]
    # Explicit argv, never eval/shell parsing of a compiler command string.
    macros = output([path, *flags, '-dM', '-E', '-include', 'features.h', '-'],
                    input='') if '-linux-' in args.target else output(
                        [path, *flags, '-dM', '-E', '-'], input='')
    expected = '__aarch64__' if args.target.startswith('aarch64-') else '__x86_64__'
    if expected not in macros:
        raise ValueError('compiler architecture does not match target')
    if '-linux-' in args.target:
        if '__linux__' not in macros:
            raise ValueError('compiler operating system does not match target')
        if ('__GLIBC__' in macros) != args.target.endswith('-gnu'):
            raise ValueError('compiler libc does not match target (a GNU compiler is not musl)')
    elif '__APPLE__' not in macros:
        raise ValueError('compiler operating system does not match target')
    identity = {'path': path, 'sha256': digest(Path(path)),
                'version': output([path, '--version']), 'macros': macros,
                'flags': flags, 'toolchain_id': args.toolchain_id}
    return path, flags, identity


def extract(archive, destination, version):
    root = 'openssl-' + version
    with tarfile.open(archive, 'r:gz') as source:
        members = source.getmembers()
        for member in members:
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or path.parts[0] != root:
                raise ValueError('source archive contains an unsafe path')
            # Upstream release source has ordinary files/directories only.
            # Refuse links/devices rather than following one during extraction.
            if not (member.isfile() or member.isdir()):
                raise ValueError('source archive contains a non-regular entry')
        source.extractall(destination, members=members)
    return destination / root


def artifact_hashes(prefix):
    required = ['lib/libcrypto.a', 'lib/libssl.a', 'include/openssl/crypto.h',
                'include/openssl/opensslv.h']
    if prefix.is_symlink() or any(not (prefix / path).is_file() for path in required):
        raise ValueError('incomplete native prefix')
    paths = sorted(path for path in prefix.rglob('*') if path.is_file())
    if any(path.is_symlink() for path in prefix.rglob('*')):
        raise ValueError('native cache must not contain symlinks')
    return {str(path.relative_to(prefix)): digest(path) for path in paths
            if path.name != 'manifest.json'}


def private_path_check(prefix, stage):
    forbidden = [str(stage).encode(), str(Path.home()).encode()]
    for name in ['lib/libcrypto.a', 'lib/libssl.a', 'version-probe']:
        data = (prefix / name).read_bytes()
        if any(path != b'/' and path in data for path in forbidden):
            raise ValueError('native artifact contains an absolute build/home path: ' + name)


def relative_toolchain(source, cc, flags):
    directory = source / '.qsh-toolchain'
    directory.mkdir()
    (directory / 'cc').symlink_to(cc)
    result = []
    for index, flag in enumerate(flags):
        # Explicit SDK/UAPI/sysroot paths become relative aliases. OpenSSL's
        # version metadata records compiler flags verbatim, outside __FILE__
        # remapping; putting private paths in those flags is insufficient.
        lead, path = '', flag
        for candidate in ['--sysroot=', '-I', '-L']:
            if flag.startswith(candidate) and flag[len(candidate):].startswith('/'):
                lead, path = candidate, flag[len(candidate):]
                break
        if Path(path).is_absolute():
            alias = directory / ('input-' + str(index))
            alias.symlink_to(path)
            result.append(lead + str(alias.relative_to(source)))
        else:
            result.append(flag)
    return './.qsh-toolchain/cc', result


def validate_cache(prefix, identity):
    try:
        manifest = json.loads((prefix / 'manifest.json').read_text())
    except (OSError, ValueError) as error:
        raise ValueError('incomplete native cache; remove only this failed prefix') from error
    if manifest['identity'] != identity:
        raise ValueError('cache identity mismatch')
    if manifest['artifacts'] != artifact_hashes(prefix):
        raise ValueError('cache artifact mismatch')


def link_probe(prefix, cc, flags, target, version, directory):
    major, minor, patch = map(int, version.split('.'))
    source = directory / 'version.c'
    source.write_text('''#include <openssl/crypto.h>
#include <openssl/opensslv.h>
#if OPENSSL_VERSION_MAJOR != %d || OPENSSL_VERSION_MINOR != %d || OPENSSL_VERSION_PATCH != %d
#error wrong OpenSSL headers
#endif
int main(void) { return OpenSSL_version_num() == 0x%08xUL ? 0 : 1; }
''' % (major, minor, patch, (major << 28) | (minor << 20) | (patch << 4)))
    binary = directory / 'version-probe'
    command = [cc, *flags, '-I' + str(prefix / 'include'), str(source),
               str(prefix / 'lib/libcrypto.a'), '-pthread', '-o', str(binary)]
    if '-linux-' in target:
        command += ['-ldl']
    if target.endswith('-musl'):
        command += ['-static']
    run(command, stdout=sys.stderr)
    if '-linux-' in target:
        details = output(['readelf', '-d', str(binary)])
        if ('libcrypto' in details or 'libssl' in details or
                (target.endswith('-musl') and '(NEEDED)' in details)):
            raise ValueError('unexpected dynamic native dependency')
    else:
        details = output(['otool', '-L', str(binary)])
        if 'libcrypto' in details or 'libssl' in details:
            raise ValueError('unexpected dynamic native dependency')
    # Cross targets are linked and inspected here; qualification runs the probe
    # on its architecture (or an explicitly selected emulator).
    shutil.copy2(binary, prefix / 'version-probe')


def build(args, archive, pin, temporary):
    cc, flags, cc_identity = compiler(args)
    identity = {'source': pin, 'target': args.target, 'compiler': cc_identity,
                'options': OPTIONS, 'builder': digest(Path(__file__)),
                'ar': tool_identity(args.ar), 'ranlib': tool_identity(args.ranlib)}
    key = hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()
    args.cache.mkdir(parents=True, exist_ok=True)
    prefix = args.cache / (args.target + '-' + key)
    if prefix.exists():
        validate_cache(prefix, identity)
        return prefix
    lock = prefix.with_suffix('.lock')
    try:
        lock.mkdir()
    except FileExistsError as error:
        raise ValueError('native build already owns this cache entry') from error
    try:
        # Check again after acquiring ownership, without replacing a completed
        # prefix published between the first check and our lock acquisition.
        if prefix.exists():
            validate_cache(prefix, identity)
            return prefix
        with tempfile.TemporaryDirectory(prefix='.stage-', dir=args.cache) as stage_name:
            stage = Path(stage_name)
            source = extract(archive, stage, pin['version'])
            destdir = stage / 'install'
            installed = destdir / 'qsh-openssl'
            build_cc, build_flags = relative_toolchain(source, cc, flags)
            for name in ['ar', 'ranlib']:
                (source / '.qsh-toolchain' / name).symlink_to(identity[name]['path'])
            env = dict(os.environ)
            # Caller flags must be explicit cache inputs, not inherited flags
            # silently consumed by Configure or make.
            for name in ['CFLAGS', 'CPPFLAGS', 'CXXFLAGS', 'LDFLAGS', 'CROSS_COMPILE',
                         'CONFIGURE_ARGS', 'MAKEFLAGS', 'MFLAGS', 'DESTDIR',
                         'CPATH', 'C_INCLUDE_PATH', 'CPLUS_INCLUDE_PATH', 'LIBRARY_PATH',
                         'SDKROOT', 'MACOSX_DEPLOYMENT_TARGET']:
                env.pop(name, None)
            remap = '-ffile-prefix-map=.=/qsh-openssl-build'
            env.update(CC=build_cc, AR='./.qsh-toolchain/ar',
                       RANLIB='./.qsh-toolchain/ranlib',
                       CFLAGS=' '.join(shlex.quote(flag) for flag in [*build_flags, remap]),
                       SOURCE_DATE_EPOCH='1790690724')
            run(['perl', 'Configure', TARGETS[args.target], *OPTIONS],
                cwd=source, env=env, stdout=sys.stderr)
            run(['make', '-j' + str(args.jobs)], cwd=source, env=env, stdout=sys.stderr)
            run(['make', 'install_sw', 'DESTDIR=' + str(destdir)],
                cwd=source, env=env, stdout=sys.stderr)
            link_probe(installed, cc, flags, args.target, pin['version'], stage)
            private_path_check(installed, stage)
            shutil.copy2(source / 'LICENSE.txt', installed / 'LICENSE.txt')
            manifest = {'identity': identity, 'artifacts': artifact_hashes(installed)}
            (installed / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
            installed.rename(prefix)
        return prefix
    finally:
        lock.rmdir()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', required=True)
    parser.add_argument('--cache', required=True, type=Path)
    parser.add_argument('--archive', type=Path, help='verified local source, no network when supplied')
    parser.add_argument('--cc')
    parser.add_argument('--ar', default='ar')
    parser.add_argument('--ranlib', default='ranlib')
    parser.add_argument('--cflag', action='append', default=[])
    parser.add_argument('--toolchain-id', default='', help='qualified sysroot/SDK image identity')
    parser.add_argument('--jobs', type=int, default=int(os.environ.get('CARGO_BUILD_JOBS', '2')))
    args = parser.parse_args()
    if args.target not in TARGETS:
        raise ValueError('unsupported target: ' + args.target)
    if not 1 <= args.jobs <= 2:
        raise ValueError('native jobs must be 1 or 2')
    args.cache = args.cache.absolute()
    pin = json.loads((PIN_DIR / 'source.json').read_text())
    if args.archive is not None and not args.archive.is_file():
        raise ValueError('archive is not a regular file')
    with tempfile.TemporaryDirectory(prefix='qsh-openssl-source-') as directory:
        temporary = Path(directory)
        archive = args.archive.absolute() if args.archive else temporary / 'source.tar.gz'
        if args.archive is None:
            run(['curl', '--proto', '=https', '--tlsv1.2', '--fail', '--location',
                 '--retry', '3', '--output', str(archive), pin['url']], stdout=sys.stderr)
        verify_source(archive, pin, temporary)
        print(build(args, archive, pin, temporary))


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise InterruptedError('build interrupted by signal ' + str(signum))

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    try:
        main()
    except (OSError, ValueError, subprocess.CalledProcessError, tarfile.TarError) as error:
        print('native OpenSSL: ' + str(error), file=sys.stderr)
        sys.exit(1)
