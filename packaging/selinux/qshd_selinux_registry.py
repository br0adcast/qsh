"""Current fixed targeted context inventory, not standalone readiness evidence.

Compose with required context inspection: that layer rejects journal/receipt
keys outside the derived map and verifies current source/owned-row semantics.
Discovery never bootstraps, repairs or accepts policy/account readiness. Hold the
outer package lock, retain this lease through context lock/status finalization,
and capture/recheck inside one caller-owned required_observation window.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import time

import qshd_selinux_contexts as pure
from qshd_selinux_fs import SafeFiles, Conflict

BASE = '/etc/selinux/targeted/contexts'
OWNERS = ('selinux-policy-targeted', 'container-selinux')
MAX_CANDIDATES = 128
MAX_TARGETS = 16
MAX_OUTPUT = 4 * 1024 * 1024
MAX_FILES = 16384
MAX_PATH = 4096
MAX_LINE = 24578
NAME_FORMAT = '%{NAME:json}\n'
MANIFEST_FORMAT = '%{NAME:json}\n[%{FILENAMES:json}\n]'


class RegistryError(ValueError):
    """Bounded stable error without native diagnostics or file contents."""


def _fail(code):
    raise RegistryError(code)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def _strings(data, limit):
    if type(data) is not bytes or not data or len(data) > limit or not data.endswith(b'\n'):
        _fail('RPM_OUTPUT')
    lines = data[:-1].split(b'\n')
    if len(lines) > MAX_FILES + 1:
        _fail('RPM_OUTPUT')
    result = []
    for line in lines:
        if not line or len(line) > MAX_LINE or not line.startswith(b'"') or not line.endswith(b'"'):
            _fail('RPM_OUTPUT')
        try:
            value = json.loads(line.decode('ascii'))
        except (ValueError, UnicodeError, RecursionError):
            raise RegistryError('RPM_OUTPUT') from None
        if type(value) is not str:
            _fail('RPM_OUTPUT')
        result.append(value)
    return result


def parse_owner(data: bytes) -> str:
    """Decode one JSON NAME line; nonzero command status is never unowned."""
    values = _strings(data, 256)
    if len(values) != 1 or values[0] not in OWNERS:
        _fail('UNSUPPORTED_OWNER')
    return values[0]


def parse_manifest(data: bytes, owner: str) -> tuple[str, ...]:
    """Decode JSON-string filename records; reject delimiter injection/duplicates."""
    if owner not in OWNERS:
        _fail('UNSUPPORTED_OWNER')
    values = _strings(data, MAX_OUTPUT)
    if values[0] != owner or len(values) < 2:
        _fail('RPM_MANIFEST')
    files = values[1:]
    for path in files:
        if (not path or len(path) > MAX_PATH or not path.startswith('/') or
                path.startswith('//') or posixpath.normpath(path) != path or
                any(not 32 <= ord(c) < 127 for c in path)):
            _fail('RPM_MANIFEST')
    if len(files) != len(set(files)):
        _fail('RPM_MANIFEST')
    return tuple(sorted(files))


@dataclass(frozen=True)
class RegistryObservation:
    """Partial evidence valid only for one live lease and composed observers."""

    registry_bytes: bytes
    registry_sha256: str
    candidates: tuple[tuple[str, bytes], ...]
    directories: tuple[bytes, ...]
    owners: tuple[tuple[str, str], ...]
    manifests: tuple[tuple[str, tuple[str, ...]], ...]


class Registry(SafeFiles):
    """Injected paths/uid/process owner are for trusted callers/disposable tests."""

    def __init__(self, contexts, *, anchor, uid, owner, clock=time.monotonic):
        self.contexts = Path(contexts)
        self.anchor = Path(anchor)
        if (not self.contexts.is_absolute() or not self.anchor.is_absolute() or
                str(self.contexts) != os.path.normpath(str(self.contexts)) or
                str(self.anchor) != os.path.normpath(str(self.anchor))):
            _fail('REGISTRY_ROOT')
        try:
            self.contexts.relative_to(self.anchor)
        except ValueError:
            raise RegistryError('REGISTRY_ROOT') from None
        self.uid, self._owner, self._clock = uid, owner, clock
        self.hook = lambda event: None
        self.routes, self.anchors = [], []
        self._active = False

    @contextmanager
    def inspection(self):
        """No context lock: caller orders package lock, routing, context, status.

        Sixty-second total includes setup, all commands, capture and final
        rechecks. No scope guarantees stability after directory/lock release.
        """
        if self._active:
            _fail('REGISTRY_ACTIVE')
        started = self._clock()
        self._active = True
        lease = None
        try:
            self._context_fd = self._directory(self.contexts)
            self._users_fd = self._directory(self.contexts / 'users')
            lease = _Lease(self, started)
            lease._check()
            yield lease
        except OSError:
            raise RegistryError('REGISTRY_FILESYSTEM') from None
        finally:
            if lease is not None:
                lease._active = False
            for fd in set(self.anchors + [part for route in self.routes for part in (route[0], route[2])]):
                os.close(fd)
            self.anchors, self.routes = [], []
            self._active = False

    def _inventory(self):
        self._validate_directory_routes()
        names = []
        with os.scandir(self._users_fd) as entries:
            for entry in entries:
                if len(names) >= MAX_CANDIDATES - 1:
                    _fail('CANDIDATE_LIMIT')
                name = entry.name
                if re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', name) is None:
                    _fail('CANDIDATE_NAME')
                names.append(name)
        candidates = []
        for path, parent, name in [(BASE + '/default_contexts', self._context_fd, 'default_contexts')] + [
                (BASE + '/users/' + n, self._users_fd, n) for n in sorted(names)]:
            snap = self._read(parent, name)
            if snap['mode'] & 0o022:
                _fail('CANDIDATE_AUTHORITY')
            packed = dict(snap, data=snap['data'].hex())
            candidates.append((path, _canonical(packed)))
        directories = []
        for fd in (self._context_fd, self._users_fd):
            st = os.fstat(fd)
            directories.append(_canonical([st.st_dev, st.st_ino, st.st_uid, st.st_gid,
                                           st.st_mode, st.st_mtime_ns, st.st_ctime_ns]))
        self._validate_directory_routes()
        return tuple(candidates), tuple(directories)


class _Lease:
    def __init__(self, files, started):
        self._files, self._started = files, started
        self._active, self._failed = True, False
        self._routing, self._baseline = None, None

    def _check(self):
        if not self._active or self._failed:
            _fail('REGISTRY_CLOSED')
        if self._files._clock() - self._started >= 60:
            self._failed = True
            _fail('REGISTRY_DEADLINE')

    def _query(self, argv):
        self._check()
        try:
            # The shared trusted RPM owner enforces its five-second command
            # profile and combined output cap; no shell or dynamic command API.
            output = self._files._owner._run(tuple(argv), str(self._files.contexts),
                                                  deadline=self._started + 60)
        except Exception:
            raise RegistryError('RPM_COMMAND') from None
        self._check()
        if output.stderr or type(output.stdout) is not bytes or len(output.stdout) > MAX_OUTPUT:
            _fail('RPM_COMMAND')
        return output.stdout

    def _observe(self):
        self._check()
        files = self._files
        candidates, directories = files._inventory()
        relevant = []
        for path, data in candidates:
            content = bytes.fromhex(json.loads(data)['data'])
            if pure.context_relevant(content):
                relevant.append(path)
        if not 0 < len(relevant) <= MAX_TARGETS:
            _fail('TARGET_COUNT')
        manifests, owners, identities = {}, [], {}
        for path in relevant:
            owner = parse_owner(self._query(('/usr/bin/rpm', '-qf', '--qf', NAME_FORMAT, '--', path)))
            if owner not in manifests:
                manifests[owner] = parse_manifest(self._query(
                    ('/usr/bin/rpm', '-q', '--qf', MANIFEST_FORMAT, '--', owner)), owner)
            if path not in manifests[owner]:
                _fail('OWNER_MEMBERSHIP')
            owners.append((path, owner))
            identities[path] = dict(path=path, source_type='sshd_t', original_package=owner)
        for path in relevant:
            if sum(path in manifest for manifest in manifests.values()) != 1:
                _fail('OWNER_CONFLICT')
        if files._inventory() != (candidates, directories):
            _fail('REGISTRY_DRIFT')
        self._check()
        registry = _canonical(identities)
        return RegistryObservation(registry, hashlib.sha256(registry).hexdigest(),
                                   candidates, directories, tuple(owners), tuple(sorted(manifests.items())))

    def _guarded(self, action):
        self._check()
        try:
            return action()
        except BaseException:
            self._failed = True
            raise

    def routing(self):
        """One setup-only routing map, never accepted current-window evidence."""
        def route():
            if self._routing is not None:
                _fail('REGISTRY_ROUTED')
            self._routing = self._observe().registry_bytes
            return self._routing
        return self._guarded(route)

    def capture(self):
        """Redo every observer inside the caller's one required status window."""
        def capture():
            if self._routing is None or self._baseline is not None:
                _fail('REGISTRY_CAPTURE')
            observed = self._observe()
            if observed.registry_bytes != self._routing:
                _fail('REGISTRY_DRIFT')
            self._baseline = observed
            return observed
        return self._guarded(capture)

    def recheck(self, observation):
        """Only exact same live baseline; fresh RPM cache, no failed reset."""
        def recheck():
            if self._baseline is None or observation is not self._baseline:
                _fail('REGISTRY_OBSERVATION')
            if self._observe() != observation:
                _fail('REGISTRY_DRIFT')
        return self._guarded(recheck)


def _process_owner():
    # One shared implementation; trusted fixed RPM profile, no fallback runner.
    from qshd_selinux_process import _Limits, _Owner
    return _Owner(_Limits(5.0, MAX_OUTPUT))


def production():
    """Fresh bounded verifier process only; no arbitrary production root/owner."""
    if os.geteuid() != 0:
        _fail('ROOT_REQUIRED')
    return Registry(BASE, anchor='/', uid=0, owner=_process_owner())
