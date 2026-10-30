"""Canonical managed-prestart file/PAM evidence, never start authorization.

Caller holds package/context exclusion and one native required_observation
window. Accept only after recheck, normal status exit and all lease cleanup.
No policy/filesystem writes, private-content reads or effective-unit proof.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat

from qshd_selinux_fs import SafeFiles, Conflict, MAX_XATTRS

PAM_SHA256 = '61dc7f9dc6ada9a612a66b1bfda1f8d1802ec9734a9325edc4f600b0e55622c7'
_E = 'system_u:object_r:qshd_exec_t:s0'
_C = 'system_u:object_r:qshd_config_t:s0'
_L = 'system_u:object_r:qshd_log_t:s0'
_R = 'system_u:object_r:qshd_runtime_t:s0'
# path, native kind, expected raw label (None means deliberately not checked),
# required presence, consumer authority role. No caller-selected inventory.
_PATHS = (
    ('/usr/bin/qshd', stat.S_IFREG, _E, True, 'binary'),
    ('/etc/pam.d/qshd', stat.S_IFREG, None, True, 'pam'),
    ('/etc/qshd', stat.S_IFDIR, _C, False, 'directory'),
    ('/etc/qshd/host_key', stat.S_IFREG, _C, False, 'key'),
    ('/var/log/qshd', stat.S_IFDIR, _L, False, 'directory'),
    ('/var/log/qshd/qshd.log', stat.S_IFREG, _L, False, 'private'),
    ('/var/log/qshd/qshd.log.1', stat.S_IFREG, _L, False, 'private'),
    ('/run/qshd', stat.S_IFDIR, _R, True, 'runtime'),
    ('/run/qshd/helper-status.sock', stat.S_IFSOCK, None, False, 'absent'),
    ('/run/qshd/helper-status.sock.lock', stat.S_IFREG, _R, False, 'private'),
)


class FilesError(ValueError):
    """Fixed bounded refusal, excluding paths, PAM and private contents."""


def _fail(code):
    raise FilesError(code)


@dataclass(frozen=True)
class PathObservation:
    path: str
    kind: int
    present: bool
    metadata: tuple | None
    default_context: str | None
    actual_context: str | None
    pam_sha256: str | None


@dataclass(frozen=True)
class FilesObservation:
    """Current-window partial evidence; no private bytes or durable readiness."""
    phase: str
    paths: tuple[PathObservation, ...]


def production(expected_pam, api):
    """Trusted caller supplies canonical expected bytes, never installed trust.

    Native api must be the caller's existing bounded SelinuxApi. This factory
    neither opens a second status scope nor authenticates caller orchestration.
    """
    if type(expected_pam) is not bytes or hashlib.sha256(expected_pam).hexdigest() != PAM_SHA256:
        _fail('EXPECTED_PAM')
    if os.geteuid() != 0:
        _fail('ROOT_REQUIRED')
    from qshd_selinux_api import SelinuxApi
    if type(api) is not SelinuxApi:
        _fail('NATIVE_API')
    return Files(expected_pam, api)


def _testing(expected_pam, root, api, uid):
    return Files(expected_pam, api, _root=root, _uid=uid)


class Files:
    """Fixed-phase production factory output; private roots only for tests."""
    def __init__(self, expected_pam, api, *, _root='/', _uid=0):
        if type(expected_pam) is not bytes or not 1 <= len(expected_pam) <= 65536:
            _fail('EXPECTED_PAM')
        self._pam = bytes(expected_pam)
        self._api = api
        self._root = Path(_root)
        self._uid = _uid
        self._active = False

    @contextmanager
    def inspection(self):
        if self._active:
            _fail('NESTED_LEASE')
        self._active = True
        lease = _Inspection(self)
        try:
            try:
                lease._setup()
                yield lease
                if lease._state != 'checked':
                    _fail('FINAL_RECHECK_REQUIRED')
            except (OSError, Conflict):
                raise FilesError('FILESYSTEM') from None
        finally:
            try:
                lease._close()
            finally:
                self._active = False


class _Inspection(SafeFiles):
    def __init__(self, files):
        self.anchor = files._root
        self.uid = files._uid
        self.anchors, self.routes, self._acquired = [], [], []
        self.hook = lambda event: None
        self._api, self._pam = files._api, files._pam
        self._parents, self._objects = {}, {}
        self._state = 'open'
        self._baseline = None

    def _dir_mode(self, fd):
        super()._dir_mode(fd)
        info = os.fstat(fd)
        if info.st_mode & 0o7000 or not info.st_mode & 0o100:
            _fail('DIRECTORY_AUTHORITY')

    def _setup(self):
        for path in ('/usr/bin', '/etc/pam.d', '/etc', '/var/log', '/run'):
            self._parents[path] = self._directory(self.anchor / path[1:])

    def _metadata(self, fd, parent, name, kind, role):
        info = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if ((info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                or stat.S_IFMT(info.st_mode) != kind or info.st_uid != self.uid
                or info.st_mode & 0o7000):
            _fail('OBJECT_BINDING')
        mode = stat.S_IMODE(info.st_mode)
        if kind == stat.S_IFDIR:
            self._dir_mode(fd)
            if role == 'runtime' and mode != 0o700:
                _fail('RUNTIME_MODE')
        else:
            self._bound(parent, name, fd)
            if role == 'binary' and (mode & 0o022 or mode & 0o500 != 0o500):
                _fail('BINARY_MODE')
            if role == 'pam' and (mode & 0o022 or not mode & 0o400):
                _fail('PAM_MODE')
            if role == 'key' and (mode not in (0o400, 0o600) or info.st_size != 64):
                _fail('KEY_METADATA')
            if role == 'private' and mode != 0o600:
                _fail('PRIVATE_MODE')
        names = os.listxattr(fd)
        if len(names) > MAX_XATTRS:
            _fail('XATTR_LIMIT')
        attrs = []
        for key in sorted(names):
            value = os.getxattr(fd, key)
            if len(key) > 255 or len(value) > 65536:
                _fail('XATTR_LIMIT')
            attrs.append((key, value))
        return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns, tuple(attrs))

    def _sample(self, initial):
        self._validate_directory_routes()
        result = []
        with self._api.file_defaults() as defaults:
            for path, kind, expected, required, role in _PATHS:
                default = defaults.lookup(path, kind) if expected is not None else None
                if default != expected:
                    _fail('DEFAULT_CONTEXT')
                parent_path, name = str(Path(path).parent), Path(path).name
                parent = self._parents[parent_path]
                if parent is None:
                    # Its optional generated parent has a retained named absence
                    # observation earlier in this fixed traversal order.
                    if required:
                        _fail('REQUIRED_MISSING')
                    result.append(PathObservation(path, kind, False, None, default, None, None))
                    continue
                try:
                    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    if required:
                        _fail('REQUIRED_MISSING')
                    if kind == stat.S_IFDIR:
                        self._parents[path] = None
                    result.append(PathObservation(path, kind, False, None, default, None, None))
                    continue
                if role == 'absent':
                    _fail('UNSUPPORTED_SOCKET_PRESENT')
                if initial:
                    if kind == stat.S_IFDIR:
                        fd = self._directory(self.anchor / path[1:])
                        self._parents[path] = fd
                    else:
                        fd = self._open(parent, name)
                        self._acquired.append(fd)
                    self._objects[path] = fd
                else:
                    if path not in self._objects:
                        _fail('PRESENCE_DRIFT')
                    fd = self._objects[path]
                before = self._metadata(fd, parent, name, kind, role)
                actual = self._api.file_context(fd) if expected is not None else None
                if actual != expected:
                    _fail('ACTUAL_CONTEXT')
                pam_hash = None
                if role == 'pam':
                    value = self._read(parent, name, limit=65536)
                    if (tuple(value['inode']) != before[:2] or value['data'] != self._pam):
                        _fail('PAM_BYTES')
                    pam_hash = hashlib.sha256(value['data']).hexdigest()
                after = self._metadata(fd, parent, name, kind, role)
                if before != after:
                    _fail('READ_DRIFT')
                result.append(PathObservation(path, kind, True, after, default, actual, pam_hash))
        self._validate_directory_routes()
        return FilesObservation('managed-prestart', tuple(result))

    def capture(self):
        return self._observe(None)

    def recheck(self, observation):
        if observation is None:
            self._state = 'failed'
            _fail('FOREIGN_OBSERVATION')
        self._observe(observation)

    def _observe(self, observation):
        if self._state != ('open' if observation is None else 'captured') or (observation is not None and observation is not self._baseline):
            self._state = 'failed'
            _fail('LEASE_STATE')
        self._state = 'failed'
        try:
            current = self._sample(observation is None)
            if observation is None:
                self._baseline = current
                self._state = 'captured'
                return current
            if current != observation:
                _fail('OBSERVATION_DRIFT')
            self._state = 'checked'
        except FilesError:
            raise
        except Exception:
            raise FilesError('OBSERVATION') from None

    def _close(self):
        failed = False
        self._state = 'closed'
        descriptors = self._acquired + self.anchors + [route[2] for route in self.routes]
        for fd in reversed(list(dict.fromkeys(descriptors))):
            try:
                os.close(fd)
            except BaseException:
                failed = True
        if failed:
            _fail('DESCRIPTOR_CLEANUP')
