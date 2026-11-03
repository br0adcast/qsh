#!/usr/bin/env python3
"""Generate canonical offline authority from final transformed build inputs.

Caller owns immutable input routes and an exclusive output parent. This is not
RPM verification, installed-file trust or permission to migrate a legacy PAM.
A rename attempt begins an outcome-uncertain boundary; never retry blindly.
"""
import argparse
from contextlib import ExitStack
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import stat
import sys
import uuid

# Fixed repository code only, never a path selected by build metadata.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'packaging/selinux'))
from qshd_selinux_rpm_query import ConsumerRpmAuthority, RpmFileAuthority, RpmPackage
from qshd_selinux_files import PAM_SHA256

MAX_BINARY = 128 * 1024**2
MAX_DOCUMENT = 16384
MAX_PAM = 4096
CHUNK = 65536
_BINARY = '/usr/bin/qshd'
_PAM = '/etc/pam.d/qshd'
_NAMES = ('consumer-rpm.json', 'generation-receipt.json')


class GenerationError(ValueError):
    """Fixed safe category, never source paths, metadata or operating errors."""


class PublicationUncertain(GenerationError):
    """Rename was attempted; preserve evidence and inspect before retrying."""


def _fail(category):
    raise GenerationError(category)


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False)+'\n').encode('ascii')


def _identity(value):
    return value.st_dev, value.st_ino, stat.S_IFMT(value.st_mode)


def _binding(value):
    return (_identity(value), value.st_mode, value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


class _Route:
    """Retain nofollow directory descriptors; recheck each named edge."""

    def __init__(self, path, stack):
        absolute = os.path.abspath(os.fspath(path))
        # Do not silently collapse an ambiguous caller route before admission.
        if '..' in Path(os.fspath(path)).parts:
            _fail('ROUTE')
        parts = Path(absolute).parts
        if len(parts) < 2:
            _fail('ROUTE')
        self.name = parts[-1]
        self.edges = []
        fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        stack.callback(os.close, fd)
        for name in parts[1:-1]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                            dir_fd=fd)
            stack.callback(os.close, child)
            identity = _identity(os.fstat(child))
            self.edges.append((fd, name, child, identity))
            fd = child
        self.fd = fd

    def check(self):
        for parent, name, fd, expected in self.edges:
            if (_identity(os.fstat(fd)) != expected
                    or _identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != expected):
                _fail('ROUTE_CHANGED')

    def exists(self):
        try:
            os.stat(self.name, dir_fd=self.fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True


class _Source:
    def __init__(self, path, limit, stack):
        self.route = _Route(path, stack)
        self.fd = os.open(self.route.name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=self.route.fd)
        stack.callback(os.close, self.fd)
        value = os.fstat(self.fd)
        if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or value.st_size > limit:
            _fail('SOURCE')
        self.expected = _binding(value)
        self.limit = limit
        self.check()

    def check(self):
        self.route.check()
        if (_binding(os.fstat(self.fd)) != self.expected
                or _binding(os.stat(self.route.name, dir_fd=self.route.fd,
                                    follow_symlinks=False)) != self.expected):
            _fail('SOURCE_CHANGED')

    def read(self, *, retain=False):
        digest = hashlib.sha256()
        data = bytearray()
        count = 0
        while True:
            block = os.read(self.fd, min(CHUNK, self.limit + 1 - count))
            if not block:
                break
            count += len(block)
            if count > self.limit:
                _fail('SOURCE_SIZE')
            digest.update(block)
            if retain:
                data.extend(block)
        self.check()
        if count != self.expected[3]:
            _fail('SOURCE_CHANGED')
        return count, digest.hexdigest(), bytes(data)


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail('DUPLICATE_KEY')
        result[key] = value
    return result


def _keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        _fail('METADATA')


def _metadata(raw, binary, pam):
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                       parse_constant=lambda unused: _fail('METADATA'))
    _keys(value, ('schema', 'package', 'files'))
    _keys(value['package'], ('name', 'epoch', 'version', 'release', 'arch'))
    package = RpmPackage(**value['package'])
    if package.name != 'qshd' or package.arch not in ('x86_64', 'aarch64'):
        _fail('PACKAGE')
    rows = value['files']
    if type(rows) is not list or len(rows) != 2:
        _fail('FILES')
    authorities = []
    for row, path, mode, flags, measured in zip(rows, (_PAM, _BINARY),
                                               (0o100644, 0o100755), (17, 0), (pam, binary)):
        _keys(row, ('path', 'mode', 'owner', 'group', 'flags'))
        authority = RpmFileAuthority(size=measured[0], sha256=measured[1], **row)
        if (authority.path != path or authority.mode != mode or authority.flags != flags
                or authority.owner != 'root' or authority.group != 'root'):
            _fail('SELECTED_METADATA')
        authorities.append(authority)
    result = ConsumerRpmAuthority(value['schema'], package, tuple(authorities))
    return result, _canonical(value)


def _sync(fd):
    os.fsync(fd)


def _write(directory, name, data, mode, owned):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 mode, dir_fd=directory)
    try:
        owned[name] = _identity(os.fstat(fd))
        os.fchmod(fd, mode)
        view = memoryview(data)
        while view:
            written = os.write(fd, view)
            if written <= 0:
                _fail('WRITE')
            view = view[written:]
        _sync(fd)
    finally:
        os.close(fd)


def _cleanup(parent, stage, directory, stage_identity, owned):
    # Never follow or recursively remove unknown paths, even after a fault.
    for name, expected in owned.items():
        try:
            actual = os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            continue
        if _identity(actual) != expected:
            _fail('CLEANUP_CHANGED')
        os.unlink(name, dir_fd=directory)
    if _identity(os.stat(stage, dir_fd=parent, follow_symlinks=False)) != stage_identity:
        _fail('CLEANUP_CHANGED')
    os.rmdir(stage, dir_fd=parent)


def generate(binary, pam, metadata, output_directory):
    """Publish two deterministic build-evidence files into a fresh directory."""
    stage = None
    directory = None
    owned = {}
    publishing = False
    try:
        with ExitStack() as stack:
            sources = (_Source(binary, MAX_BINARY, stack), _Source(pam, MAX_PAM, stack),
                       _Source(metadata, MAX_DOCUMENT, stack))
            if len({_identity(os.fstat(s.fd)) for s in sources}) != 3:
                _fail('ALIASED_INPUT')
            output = _Route(output_directory, stack)
            if output.exists():
                _fail('OUTPUT_EXISTS')
            measured = (sources[0].read(), sources[1].read(retain=True), sources[2].read(retain=True))
            if measured[0][0] == 0 or measured[1][1] != PAM_SHA256:
                _fail('CANONICAL_INPUT')
            authority, normalized = _metadata(measured[2][2], measured[0], measured[1])
            manifest = _canonical(asdict(authority))
            receipt = _canonical({'schema': 1, 'package': asdict(authority.package),
                                  'files': [{'path': v.path, 'size': v.size, 'sha256': v.sha256}
                                            for v in authority.files],
                                  'build_metadata_sha256': hashlib.sha256(normalized).hexdigest(),
                                  'manifest_sha256': hashlib.sha256(manifest).hexdigest()})
            if len(manifest) > MAX_DOCUMENT or len(receipt) > MAX_DOCUMENT:
                _fail('OUTPUT_SIZE')
            output.check()
            stage = '.consumer-authority-'+uuid.uuid4().hex
            os.mkdir(stage, 0o700, dir_fd=output.fd)
            stage_identity = None
            try:
                stage_identity = _identity(os.stat(stage, dir_fd=output.fd, follow_symlinks=False))
                # mkdir applies umask before an fd can be acquired. The parent is exclusive.
                os.chmod(stage, 0o700, dir_fd=output.fd, follow_symlinks=False)
                directory = os.open(stage, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                    dir_fd=output.fd)
                stack.callback(os.close, directory)
                stage_identity = _identity(os.fstat(directory))
                os.fchmod(directory, 0o700)
                _write(directory, _NAMES[0], manifest, 0o644, owned)
                _write(directory, _NAMES[1], receipt, 0o600, owned)
                _sync(directory)
                for source in sources:
                    source.check()
                output.check()
                if output.exists():
                    _fail('OUTPUT_EXISTS')
                if _identity(os.stat(stage, dir_fd=output.fd, follow_symlinks=False)) != stage_identity:
                    _fail('STAGE_CHANGED')
                # Caller-exclusive parent; portable rename is not adversarial NOREPLACE.
                publishing = True
                os.rename(stage, output.name, src_dir_fd=output.fd, dst_dir_fd=output.fd)
                _sync(output.fd)
                output.check()
            except BaseException:
                if not publishing and stage_identity is not None:
                    if directory is not None:
                        _cleanup(output.fd, stage, directory, stage_identity, owned)
                    elif _identity(os.stat(stage, dir_fd=output.fd, follow_symlinks=False)) == stage_identity:
                        os.rmdir(stage, dir_fd=output.fd)
                raise
    except BaseException as error:
        if publishing:
            raise PublicationUncertain('PUBLICATION_UNCERTAIN') from None
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(error, GenerationError):
            raise
        raise GenerationError('GENERATION') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', required=True)
    parser.add_argument('--pam', required=True)
    parser.add_argument('--build-metadata', required=True)
    parser.add_argument('--output-directory', required=True)
    args = parser.parse_args()
    try:
        generate(args.binary, args.pam, args.build_metadata, args.output_directory)
    except GenerationError as error:
        print(str(error), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
