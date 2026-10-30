"""Cooperative package exclusion and activation-layout prerequisites only.

No policy/context calls, recovery, readiness documents or package hooks. The
trusted caller excludes legacy writers and accepts partial-init refusal. Keep
this outer lease around lifecycle work, but never hold activation/context locks
across the fresh prestart child. Accept only after normal outer scope exit.
"""
from contextlib import contextmanager
import errno
import fcntl
import os
from pathlib import Path
import stat

from qshd_selinux_fs import SafeFiles, Conflict, identity
from qshd_selinux_activation_state import LIMIT as ACTIVATION_LIMIT


class PackageStateError(Conflict):
    """Fixed refusal; unknown objects and partial state are preserved."""


def _fail(code):
    raise PackageStateError(code)


def _translate(error):
    if isinstance(error, PackageStateError):
        raise error
    if isinstance(error, Conflict):
        raise PackageStateError(str(error)) from None
    if isinstance(error, FileNotFoundError):
        raise PackageStateError('PARTIAL_STATE') from None
    raise PackageStateError('FILESYSTEM') from None


class PackageState(SafeFiles):
    """Trusted fixture seam; production() fixes all actual paths/authority."""

    def __init__(self, common, *, uid=0, anchor=None, hook=None):
        try:
            self.common = Path(common)
            self.anchor = Path(anchor) if anchor is not None else self.common.parent
            for path in (self.common, self.anchor):
                if not path.is_absolute() or '\0' in str(path) or str(path) != os.path.normpath(path) or '..' in path.parts:
                    _fail('INVALID_PATH')
            if self.common == self.anchor:
                _fail('INVALID_PATH')
            self.common.relative_to(self.anchor)
        except (TypeError, ValueError):
            _fail('INVALID_PATH')
        if type(uid) is not int or uid < 0 or (hook is not None and not callable(hook)):
            _fail('INVALID_INPUT')
        self.uid = uid
        self.hook = hook or (lambda event: None)
        self._busy = self._poisoned = False
        self._unclosed = ()

    def _own(self, fd):
        # Ownership precedes every later fallible fstat/binding/metadata check.
        self._extra.append(fd)
        return fd

    def _directory_leaf(self, parent, name, *, exact, label):
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            fresh = True
        except FileExistsError:
            fresh = False
        expected = None
        if fresh:
            self.hook(label + '_mkdir')
            created = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if not stat.S_ISDIR(created.st_mode) or created.st_uid != self.uid:
                _fail('DIRECTORY_AUTHORITY')
            expected = identity(created)
        fd = self._own(os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent))
        self.routes.append((parent, name, fd))
        self._dir_mode(fd)
        if expected is not None and identity(os.fstat(fd)) != expected:
            _fail('DIRECTORY_BINDING')
        self._validate_directory_routes()
        if fresh:
            os.fchmod(fd, 0o700)
        if (exact or fresh) and stat.S_IMODE(os.fstat(fd).st_mode) != 0o700:
            _fail('STATE_MODE')
        if fresh:
            os.fsync(fd)
            os.fsync(parent)
        return fd, fresh

    def _lock_file(self, parent, name, *, create, existing=True):
        if create:
            try:
                fd = self._own(os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                       0o600, dir_fd=parent))
            except FileExistsError:
                if not existing:
                    _fail('PARTIAL_STATE')
            else:
                self._bound(parent, name, fd)
                os.fchmod(fd, 0o600)
                self._bound(parent, name, fd, state=True)
                os.fsync(fd)
                os.fsync(parent)
                return fd
        return self._own(self._open(parent, name, state=True))

    def _activation_metadata(self):
        self._bound(self._activation, 'lock', self._activation_lock, state=True)
        # At most two recognized names; never recursively scan foreign state.
        with os.scandir(self._activation) as entries:
            for entry in entries:
                if entry.name not in ('lock', 'activation.json'):
                    _fail('PARTIAL_STATE')
        try:
            os.stat('activation.json', dir_fd=self._activation, follow_symlinks=False)
        except FileNotFoundError:
            return
        fd = self._own(self._open(self._activation, 'activation.json', state=True))
        if self._bound(self._activation, 'activation.json', fd, state=True).st_size > ACTIVATION_LIMIT:
            _fail('STATE_LIMIT')
        # Deliberately no content read/parse, activation lock or currentness claim.

    def _validate(self, initializing):
        self._validate_directory_routes()
        self._bound(self._common, 'selinux-package.lock', self._package_lock, state=True)
        if initializing:
            if stat.S_IMODE(os.fstat(self._activation).st_mode) != 0o700:
                _fail('STATE_MODE')
            self._activation_metadata()

    def _close(self):
        fds = self._extra + self.anchors + [fd for route in self.routes for fd in (route[0], route[2])]
        failed = []
        for fd in reversed(list(dict.fromkeys(fds))):
            try:
                os.close(fd)
            except OSError:
                failed.append(fd)
        self._extra, self.anchors, self.routes = [], [], []
        if failed:
            # Do not retry uncertain numeric FDs or reuse this scope after failure.
            self._unclosed = tuple(failed)
            self._poisoned = True
            _fail('CLOSE_FAILED')

    @contextmanager
    def _lease(self, initializing):
        if self._busy:
            _fail('LEASE_ACTIVE')
        if self._poisoned:
            _fail('CLOSE_FAILED')
        self._busy = True
        self.anchors, self.routes, self._extra = [], [], []
        try:
            try:
                parent = self._directory(self.common.parent)
                if initializing:
                    self._common, _ = self._directory_leaf(parent, self.common.name, exact=False, label='common')
                else:
                    self._common = self._directory(self.common)
                self._package_lock = self._lock_file(self._common, 'selinux-package.lock', create=initializing)
                try:
                    fcntl.flock(self._package_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    if error.errno in (errno.EAGAIN, errno.EACCES):
                        _fail('BUSY')
                    raise
                self._validate_directory_routes()
                self._bound(self._common, 'selinux-package.lock', self._package_lock, state=True)
                if initializing:
                    self._activation, fresh = self._directory_leaf(self._common, 'selinux-activation',
                                                                   exact=True, label='activation')
                    self._activation_lock = self._lock_file(self._activation, 'lock', create=fresh, existing=False)
                    self._validate(True)
                    # Also finish a retry of an already complete fixed layout.
                    os.fsync(self._activation_lock)
                    os.fsync(self._activation)
                    os.fsync(self._package_lock)
                    os.fsync(self._common)
                    os.fsync(parent)
                self._validate(initializing)
            except (OSError, Conflict) as error:
                _translate(error)
            yield self
            try:
                self._validate(initializing)
            except (OSError, Conflict) as error:
                _translate(error)
        finally:
            try:
                self._close()
            finally:
                self._busy = False

    def initialize(self):
        return self._lease(True)

    def operation(self):
        return self._lease(False)


def production():
    if os.geteuid() != 0:
        _fail('ROOT_REQUIRED')
    return PackageState('/var/lib/qshd', anchor='/')
