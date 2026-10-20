#!/usr/bin/env python3
"""Check versions and identities of the release pipeline's own built outputs."""
import argparse
import errno
import hashlib
import importlib.util
import os
from pathlib import Path
import re
import select
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location(
    'release_version', Path(__file__).with_name('check-release-version.py'))
_version = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_version)
LIMIT = 8192


def parse_version(data, program, expected=None):
    if len(data) > LIMIT:
        raise ValueError('version output exceeds limit')
    try:
        first = data.decode('utf-8').splitlines()[0]
    except (UnicodeError, IndexError):
        raise ValueError('invalid version output')
    pattern = r'qsh ([^ ]+)' if program == 'qsh' else r'qshd ([^ ]+) \(build [^\r\n]+\)'
    match = re.fullmatch(pattern, first)
    if match is None or not _version.valid_version(match.group(1)):
        raise ValueError('invalid program/version first line')
    version = match.group(1)
    if expected is not None and version != expected:
        raise ValueError('binary version differs from selected release version')
    return version


def check_binary(path, program, version, timeout=10):
    # --version exits before either product starts sessions or descendants.
    # This owner keeps its exact direct child through timeout/interrupt cleanup.
    path = Path(path).resolve()
    with tempfile.TemporaryDirectory(prefix='qsh-release-version-') as home:
        env = os.environ.copy()
        env.update(HOME=home, XDG_CACHE_HOME=home + '/cache',
                   XDG_CONFIG_HOME=home + '/config', HISTFILE='/dev/null')
        env.pop('SSH_AUTH_SOCK', None)
        master, slave = os.openpty()
        child = None
        try:
            os.set_blocking(master, False)
            deadline = time.monotonic() + timeout
            child = subprocess.Popen([str(path), '--version'], stdin=slave,
                                     stdout=slave, stderr=slave, env=env,
                                     start_new_session=True)
            os.close(slave)
            slave = None
            captured = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError('binary version probe timed out')
                ready, _, _ = select.select([master], [], [], remaining)
                if not ready:
                    raise ValueError('binary version probe timed out')
                try:
                    chunk = os.read(master, 4096)
                except BlockingIOError:
                    continue
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    break  # PTY slave closed; still wait for the owned child.
                if not chunk:
                    break
                if len(captured) + len(chunk) > LIMIT:
                    raise ValueError('version output exceeds limit')
                captured.extend(chunk)
            try:
                status = child.wait(timeout=max(0, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                raise ValueError('binary version probe timed out')
            if status != 0:
                raise ValueError('binary version probe exited unsuccessfully')
            return parse_version(bytes(captured), program, version)
        finally:
            if child is not None:
                if child.poll() is None:
                    child.kill()
                child.wait()
            if slave is not None:
                os.close(slave)
            os.close(master)


def digest(stream):
    result = hashlib.sha256()
    for chunk in iter(lambda: stream.read(65536), b''):
        result.update(chunk)
    return result.digest()


def check_archive(path, inputs, version, target):
    root = 'qsh-' + version + '-' + target
    if Path(path).name != root + '.tar.gz':
        raise ValueError('archive filename differs from selected version/target')
    with tarfile.open(str(path), 'r:gz') as archive:
        members = archive.getmembers()
        names = set()
        for member in members:
            # A normal directory header may end in '/'. Alternate spellings
            # must not overwrite the canonical program after its digest check.
            # Release inputs are regular files/directories; no link aliases.
            name = member.name[:-1] if member.isdir() and member.name.endswith('/') else member.name
            parts = name.split('/')
            if (not (member.isfile() or member.isdir())
                    or parts[0] != root or any(part in ('', '.', '..') for part in parts)
                    or name in names or (name == root and not member.isdir())):
                raise ValueError('archive member paths are not canonical and unique')
            names.add(name)
        for program in ('qsh', 'qshd'):
            matches = [member for member in members if member.name == root + '/' + program]
            if len(matches) != 1 or not matches[0].isfile():
                raise ValueError('archive must contain one regular file for each program')
            source = Path(inputs) / program
            with source.open('rb') as stream:
                before = digest(stream)
            check_binary(source, program, version)
            with source.open('rb') as stream:
                after = digest(stream)
            with archive.extractfile(matches[0]) as stream:
                archived = digest(stream)
            if before != after or before != archived:
                raise ValueError('archive payload differs from the probed binary')


def debian_version(version):
    # cargo-deb 3.8.0 parse/manifest.rs::manifest_version_string, default
    # revision 1. Preserve its conditional prerelease mapping, not a new policy.
    main, separator, pre = version.partition('-')
    if separator and any(c.isdigit() for c in pre) and any(not c.isdigit() for c in pre):
        version = main + '~' + pre
    return version + '-1'


def check_fields(fmt, fields, filename, program, version, arch):
    if fmt == 'deb':
        package_version = debian_version(version)
        expected = [program, package_version, arch]
        name = '{}_{}_{}.deb'.format(program, package_version, arch)
    else:
        # cargo-generate-rpm 0.21.0 passes the raw version, Release defaults
        # to 1. Its pinned rpm library rejects '-' rather than normalizing it.
        expected = [program, version, '1', arch]
        name = '{}-{}-1.{}.rpm'.format(program, version, arch)
    if fields != expected or Path(filename).name != name:
        raise ValueError('package metadata or filename differs from selected version/identity')


def package_fields(path, fmt):
    if fmt == 'deb':
        command = ['dpkg-deb', '-f', str(path), 'Package', 'Version', 'Architecture']
    else:
        command = ['rpm', '-qp', '--qf', '%{NAME}\n%{VERSION}\n%{RELEASE}\n%{ARCH}\n', str(path)]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            universal_newlines=True, timeout=10, check=True)
    lines = result.stdout.splitlines()
    if fmt == 'deb':
        prefixes = ['Package: ', 'Version: ', 'Architecture: ']
        if len(lines) != 3 or any(not line.startswith(prefix) for line, prefix in zip(lines, prefixes)):
            raise ValueError('invalid Debian package metadata')
        lines = [line[len(prefix):] for line, prefix in zip(lines, prefixes)]
    return lines


def check_package(path, fmt, program, version, arch, probe=False):
    path = Path(path).resolve()
    check_fields(fmt, package_fields(path, fmt), path.name, program, version, arch)
    if probe:
        with tempfile.TemporaryDirectory(prefix='qsh-release-package-') as directory:
            # Inputs are the pipeline's own packages, never downloaded user data.
            if fmt == 'deb':
                subprocess.run(['dpkg-deb', '-x', str(path), directory],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                               timeout=10, check=True)
            else:
                producer = subprocess.Popen(['rpm2cpio', str(path)], stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL)
                try:
                    subprocess.run(['cpio', '-idm', '--quiet'], cwd=directory,
                                   stdin=producer.stdout, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, timeout=10, check=True)
                    if producer.wait(timeout=10) != 0:
                        raise ValueError('RPM payload extraction failed')
                finally:
                    producer.stdout.close()
                    if producer.poll() is None:
                        producer.kill()
                    producer.wait()
            check_binary(Path(directory) / 'usr/bin' / program, program, version)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command')
    for name in ('archive', 'package', 'text', 'fields'):
        command = sub.add_parser(name)
        command.add_argument('--version', required=name != 'text')
        if name != 'archive':
            command.add_argument('--program', choices=('qsh', 'qshd'), required=True)
        if name in ('package', 'fields'):
            command.add_argument('--format', choices=('deb', 'rpm'), required=True)
            command.add_argument('--arch', required=True)
            command.add_argument('path')
        if name == 'archive':
            command.add_argument('--inputs', required=True)
            command.add_argument('--target', required=True)
            command.add_argument('path')
        if name == 'package':
            command.add_argument('--probe', action='store_true')
    args = parser.parse_args()
    if args.command is None:
        parser.error('a command is required')
    try:
        if args.version is not None and not _version.valid_version(args.version):
            raise ValueError('invalid selected version')
        if args.command == 'archive':
            check_archive(args.path, args.inputs, args.version, args.target)
        elif args.command == 'package':
            check_package(args.path, args.format, args.program, args.version, args.arch, args.probe)
        else:
            data = sys.stdin.buffer.read(LIMIT + 1)
            if len(data) > LIMIT:
                raise ValueError('output exceeds limit')
            if args.command == 'text':
                print(parse_version(data, args.program, args.version))
            else:
                fields = data.decode('utf-8').splitlines()
                check_fields(args.format, fields, args.path, args.program, args.version, args.arch)
    except UnicodeError:
        print('release output: invalid encoded metadata', file=sys.stderr)
        return 1
    except ValueError as error:
        # These are fixed diagnostics, never binary/tool output or paths.
        print('release output: ' + str(error), file=sys.stderr)
        return 1
    except OSError:
        print('release output: tool/target execution unavailable; check architecture prerequisites',
              file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('release output: interrupted; owned probe cleanup completed', file=sys.stderr)
        return 130
    except (subprocess.SubprocessError, tarfile.TarError):
        print('release output: package/archive validation failed', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
