"""Bounded Fedora44 RPM6 selected-store observations, never erase permission.

Caller trusts installed RPM/configuration and explicit build authority, retains
package/administrator maintenance exclusion and supplies an external hard owner.
Header records do not bind live leaves, signatures or transaction origin. No
other database's absence, byte-immutable SQLite or lifecycle readiness is proved.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import re
import stat
import time

from qshd_selinux_fs import SafeFiles
from qshd_selinux_process import _Limits, _Owner, _Streams

_MAX_OUTPUT = 4 * 1024**2
_MAX_ROWS = 16384
_PATHS = ('/usr/bin/qshd', '/etc/pam.d/qshd')
_PREFIX = ('/usr/bin/rpm', '--root', '/', '--dbpath', '/usr/lib/sysimage/rpm',
           '--define', '_db_backend sqlite')
_P = r'P\t%{NAME:json}\t%|EPOCH?{%{EPOCH}}:{0}|\t%{VERSION:json}\t%{RELEASE:json}\t%{ARCH:json}\n'
_F = _P + r'A\t%{FILEDIGESTALGO}\n[F\t%{FILENAMES:json}\t%{FILESIZES}\t%{FILEMODES}\t%{FILEFLAGS}\t%{FILEUSERNAME:json}\t%{FILEGROUPNAME:json}\t%{FILEDIGESTS:json}\t%{FILELINKTOS:json}\t%{FILESTATES}\n]E\n'
_INVENTORY = _PREFIX + ('-qa', '--queryformat', _P)


class RpmQueryError(ValueError):
    """Fixed categories only; no inventory, metadata or caller paths in errors."""


def _fail(code):
    raise RpmQueryError(code)


def _text(value, limit=256, *, empty=False):
    if (type(value) is not str or (not empty and not value)
            or len(value) > limit or any(ord(c) < 32 or ord(c) > 126 for c in value)
            or value in ('(none)', '(null)') or '%{' in value):
        _fail('TEXT')
    return value


def _path(value):
    _text(value, 4096)
    if (not value.startswith('/') or '//' in value or '..' in value.split('/')
            or '.' in value.split('/') or os.path.normpath(value) != value):
        _fail('PATH')
    return value


def _integer(value, maximum):
    if type(value) is not int or not 0 <= value <= maximum:
        _fail('NUMBER')
    return value


def _decimal(value, maximum):
    if len(value) > 20 or re.fullmatch(r'0|[1-9][0-9]*', value) is None:
        _fail('NUMBER')
    return _integer(int(value), maximum)


def _digest(value, *, empty=False):
    if type(value) is not str or not ((empty and value == '') or re.fullmatch('[0-9a-f]{64}', value)):
        _fail('DIGEST')
    return value


def _string(value):
    try:
        decoded = json.loads(value)
    except (ValueError, RecursionError):
        _fail('STRING')
    if type(decoded) is not str:
        _fail('STRING')
    return decoded


@dataclass(frozen=True)
class RpmPackage:
    name: str
    epoch: int
    version: str
    release: str
    arch: str

    def __post_init__(self):
        for value in (self.name, self.version, self.release, self.arch):
            _text(value)
        _integer(self.epoch, 2**32 - 1)


@dataclass(frozen=True)
class RpmFileAuthority:
    path: str
    size: int
    sha256: str
    mode: int
    owner: str
    group: str
    flags: int

    def __post_init__(self):
        _path(self.path)
        if self.path not in _PATHS:
            _fail('AUTHORITY_PATH')
        _integer(self.size, 2**64 - 1)
        _digest(self.sha256)
        _integer(self.mode, 65535)
        if not stat.S_ISREG(self.mode):
            _fail('AUTHORITY_TYPE')
        _text(self.owner)
        _text(self.group)
        _integer(self.flags, 2**32 - 1)


@dataclass(frozen=True)
class ConsumerRpmAuthority:
    """Independent reviewed build input, never constructed from query output."""

    schema: int
    package: RpmPackage
    files: tuple[RpmFileAuthority, ...]

    def __post_init__(self):
        if type(self.schema) is not int or self.schema != 1 or type(self.package) is not RpmPackage:
            _fail('AUTHORITY')
        self.package.__post_init__()
        if self.package.name != 'qshd' or type(self.files) is not tuple or len(self.files) != 2:
            _fail('AUTHORITY')
        for value in self.files:
            if type(value) is not RpmFileAuthority:
                _fail('AUTHORITY')
            value.__post_init__()
        if tuple(sorted(value.path for value in self.files)) != tuple(sorted(_PATHS)):
            _fail('AUTHORITY')


@dataclass(frozen=True)
class _FileRecord:
    authority: RpmFileAuthority
    state: int
    link: str

    @property
    def path(self):
        return self.authority.path


@dataclass(frozen=True)
class _Observation:
    package: RpmPackage | None
    files: tuple[_FileRecord, ...]


def _lines(raw):
    if type(raw) is not bytes or len(raw) > _MAX_OUTPUT or (raw and not raw.endswith(b'\n')):
        _fail('OUTPUT')
    try:
        text = raw.decode('ascii')
    except UnicodeError:
        _fail('ASCII')
    lines = text[:-1].split('\n') if text else []
    if any(not line or len(line) > 32768 for line in lines):
        _fail('LINE')
    return lines


def _package(line):
    fields = line.split('\t')
    if len(fields) != 6 or fields[0] != 'P':
        _fail('PACKAGE_ROW')
    return RpmPackage(_string(fields[1]), _decimal(fields[2], 2**32 - 1),
                      *(_string(value) for value in fields[3:]))


def _inventory(raw):
    lines = _lines(raw)
    if len(lines) > _MAX_ROWS:
        _fail('ROWS')
    return tuple(_package(line) for line in lines)


def _owner_records(raw, selected):
    lines = _lines(raw)
    if not 3 <= len(lines) <= _MAX_ROWS + 3 or lines[-1] != 'E':
        _fail('GROUP')
    package = _package(lines[0])
    algorithm = lines[1].split('\t')
    if len(algorithm) != 2 or algorithm[0] != 'A' or _decimal(algorithm[1], 2**32 - 1) != 8:
        _fail('ALGORITHM')
    found = None
    paths = set()
    for line in lines[2:-1]:
        fields = line.split('\t')
        if len(fields) != 10 or fields[0] != 'F':
            _fail('FILE_ROW')
        path = _path(_string(fields[1]))
        if path in paths:
            _fail('DUPLICATE_PATH')
        paths.add(path)
        size = _decimal(fields[2], 2**64 - 1)
        mode = _decimal(fields[3], 65535)
        flags = _decimal(fields[4], 2**32 - 1)
        owner, group = (_text(_string(value)) for value in fields[5:7])
        digest = _digest(_string(fields[7]), empty=True)
        link = _text(_string(fields[8]), 4096, empty=True)
        state = _decimal(fields[9], 2**32 - 1)
        if path == selected:
            value = RpmFileAuthority(path, size, digest, mode, owner, group, flags)
            if state != 0 or link:
                _fail('SELECTED_FILE')
            found = _FileRecord(value, state, link)
    if found is None:
        _fail('MISSING_FILE')
    return package, found


def _deadline(value):
    try:
        valid = type(value) in (int, float) and math.isfinite(value)
    except (OverflowError, ValueError):
        valid = False
    if not valid:
        _fail('DEADLINE')
    return value


def production_query():
    """Fixed-store production factory; administrator RPM/config trust required."""
    if os.geteuid() != 0:
        _fail('ROOT_REQUIRED')
    return RpmQuery()


class RpmQuery:
    """No lock acquisition: caller continuously owns package/maintenance exclusion.

    Underscored construction seams are for trusted disposable source controls.
    This does not authenticate live binary/PAM leaves or an RPM transaction.
    """

    def __init__(self, *, _root='/', _uid=0, _owner=None, _clock=time.monotonic):
        try:
            root = Path(_root)
            if not root.is_absolute() or '..' in root.parts or '\0' in str(root):
                _fail('ROOT')
        except (TypeError, ValueError):
            _fail('ROOT')
        if type(_uid) is not int or _uid < 0:
            _fail('UID')
        self._root = root
        self._uid = _uid
        self._owner = _owner
        self._clock = _clock
        self._active = False

    @contextmanager
    def inspection(self, *, deadline):
        if self._active:
            _fail('LEASE_ACTIVE')
        deadline = _deadline(deadline)
        self._active = True
        lease = _Lease(self, deadline)
        normal = False
        try:
            lease._open_routes()
            yield lease
            lease._guard()
            lease._check()
            if lease._state != 'checked':
                _fail('RECHECK_REQUIRED')
            normal = True
        except Exception as error:
            if isinstance(error, RpmQueryError):
                raise
            raise RpmQueryError('OBSERVATION') from None
        finally:
            try:
                lease._close()
            finally:
                self._active = False
            if normal:
                lease._check()


class _Lease(SafeFiles):
    def __init__(self, query, deadline):
        self.anchor = query._root
        self.uid = query._uid
        self.anchors = []
        self.routes = []
        self.hook = lambda event: None
        self._clock = query._clock
        self._end = deadline
        self._owner = query._owner
        self._dirs = {}
        self._baseline = None
        self._state = 'opening'
        self._remaining = 0
        self._observed = None
        self._authority = None

    def _check(self, reserve=0):
        if self._clock() + reserve >= self._end:
            _fail('DEADLINE')

    def _leaf(self, parent, name, *, executable=False):
        fd = self._open(parent, name)
        try:
            value = self._bound(parent, name, fd)
            if (value.st_size <= 0 or value.st_mode & 0o022
                    or (executable and not value.st_mode & stat.S_IXUSR)):
                _fail('LEAF_AUTHORITY')
            # SQLite normal housekeeping may alter bytes/size/timestamps. Bind
            # only the admitted inode/type/uid/gid/mode, never a database hash.
            return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)
        finally:
            os.close(fd)

    def _guard(self):
        self._validate_directory_routes()
        current = (self._leaf(self._dirs['bin'], 'rpm', executable=True),
                   self._leaf(self._dirs['database'], 'rpmdb.sqlite'))
        if self._baseline is not None and current != self._baseline:
            _fail('ROUTE_DRIFT')
        return current

    def _open_routes(self):
        self._check(10)
        self._dirs['bin'] = self._directory(self.anchor / 'usr/bin')
        self._dirs['database'] = self._directory(self.anchor / 'usr/lib/sysimage/rpm')
        self._baseline = self._guard()
        self._check(10)
        if self._owner is None:
            self._owner = _Owner(_Limits(15, _MAX_OUTPUT))
        self._state = 'open'

    def _run(self, argv):
        self._guard()
        self._check(self._remaining * 15 + 10)
        self._remaining -= 1
        streams = self._owner._run(argv, '/', deadline=self._end - 10)
        outcome = self._owner._last
        if (type(streams) is not _Streams
                or type(streams.stdout) is not bytes or type(streams.stderr) is not bytes
                or len(streams.stdout) + len(streams.stderr) > _MAX_OUTPUT):
            _fail('QUERY_STREAMS')
        if (outcome is None or outcome.failure is not None
                or type(outcome.exit_code) is not int or outcome.exit_code != 0
                or outcome.settled is not True or outcome.unreaped != ()
                or streams.stderr != b''):
            _fail('QUERY_OUTCOME')
        self._guard()
        self._check()
        return streams.stdout

    def _sample(self):
        packages = _inventory(self._run(_INVENTORY))
        selected = tuple(value for value in packages if value.name == 'qshd')
        if self._authority is None:
            if selected:
                _fail('CONSUMER_PRESENT')
            return _Observation(None, ())
        if len(selected) != 1 or selected[0] != self._authority.package:
            _fail('PACKAGE_MISMATCH')
        records = []
        expected = {value.path: value for value in self._authority.files}
        for path in _PATHS:
            package, record = _owner_records(self._run(_PREFIX + ('-qf', '--queryformat', _F, path)), path)
            if package != selected[0] or record.authority != expected[path]:
                _fail('FILE_MISMATCH')
            records.append(record)
        return _Observation(selected[0], tuple(records))

    def _capture(self, authority):
        if self._state != 'open':
            self._state = 'failed'
            _fail('LEASE_ORDER')
        self._state = 'failed'
        try:
            if authority is not None:
                if type(authority) is not ConsumerRpmAuthority:
                    _fail('AUTHORITY')
                authority.__post_init__()
            self._authority = authority
            self._remaining = 2 if authority is None else 6
            self._observed = self._sample()
            self._state = 'captured'
            return self._observed
        except Exception:
            raise RpmQueryError('CAPTURE_REFUSED') from None

    def capture_absent(self):
        return self._capture(None)

    def capture_owned(self, authority):
        if authority is None:
            self._state = 'failed'
            _fail('AUTHORITY')
        return self._capture(authority)

    def recheck(self, observation):
        valid = self._state == 'captured' and observation is self._observed
        self._state = 'failed'
        if not valid:
            _fail('LEASE_OBSERVATION')
        try:
            if self._sample() != observation:
                _fail('OBSERVATION_DRIFT')
            self._check()
            self._state = 'checked'
        except Exception:
            raise RpmQueryError('RECHECK_REFUSED') from None

    def _close(self):
        self._state = 'closed'
        self._observed = None
        descriptors = set(self.anchors + list(self._dirs.values())
                          + [fd for route in self.routes for fd in (route[0], route[2])])
        failed = False
        try:
            for fd in descriptors:
                try:
                    os.close(fd)
                except OSError:
                    failed = True
        finally:
            self.anchors = []
            self.routes = []
            self._dirs = {}
        if failed:
            _fail('CLEANUP')


def _manifest_pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail('MANIFEST_DUPLICATE')
        result[key] = value
    return result


def _manifest_constant(value):
    _fail('MANIFEST_JSON')


def _authority_document(raw):
    """Schema-shape parsing only: never canonical-PAM or package authentication."""
    if type(raw) is not bytes or not 0 < len(raw) <= 16384:
        _fail('MANIFEST_SIZE')
    try:
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_manifest_pairs,
                           parse_constant=_manifest_constant)
        if type(value) is not dict or set(value) != {'schema', 'package', 'files'}:
            _fail('MANIFEST_SCHEMA')
        package = value['package']
        files = value['files']
        if (type(package) is not dict
                or set(package) != {'name', 'epoch', 'version', 'release', 'arch'}
                or type(files) is not list or len(files) != 2):
            _fail('MANIFEST_SCHEMA')
        for record in files:
            if (type(record) is not dict or set(record) !=
                    {'path', 'size', 'sha256', 'mode', 'owner', 'group', 'flags'}):
                _fail('MANIFEST_SCHEMA')
        if [record['path'] for record in files] != sorted(_PATHS):
            _fail('MANIFEST_ORDER')
        authority = ConsumerRpmAuthority(value['schema'], RpmPackage(**package),
                                        tuple(RpmFileAuthority(**record) for record in files))
        canonical = json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii') + b'\n'
        if raw != canonical:
            _fail('MANIFEST_CANONICAL')
        return authority
    except RpmQueryError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        raise RpmQueryError('MANIFEST_JSON') from None


def production_consumer_authority():
    """Fixed protected input, under caller-owned package/maintenance exclusion.

    Trusted reviewed installation supplies authority; root metadata/self-hashes
    alone do not authenticate arbitrary contents. No canonical PAM eligibility,
    live leaf binding, query, package lock or lifecycle permission is provided.
    """
    if os.geteuid() != 0:
        _fail('ROOT_REQUIRED')
    return ConsumerAuthorityReader()


class ConsumerAuthorityReader:
    """Single-use read-only manifest scope; private seams serve disposable tests.

    A caller retains its one package lease and original hard phase owner through
    capture, use, explicit recheck and normal closure. Never reuse old authority
    across payload replacement. Filesystem calls are not physically timed here.
    """

    def __init__(self, *, _root='/', _uid=0, _gid=0, _clock=time.monotonic):
        try:
            root = Path(_root)
            if not root.is_absolute() or '..' in root.parts or '\0' in str(root):
                _fail('MANIFEST_ROOT')
        except (TypeError, ValueError):
            _fail('MANIFEST_ROOT')
        if any(type(value) is not int or value < 0 for value in (_uid, _gid)):
            _fail('MANIFEST_IDS')
        self._root = root
        self._uid = _uid
        self._gid = _gid
        self._clock = _clock
        self._used = False

    @contextmanager
    def inspection(self, *, deadline):
        if self._used:
            _fail('MANIFEST_USED')
        self._used = True
        deadline = _deadline(deadline)
        lease = _AuthorityLease(self, deadline)
        normal = False
        try:
            lease._open_routes()
            yield lease
            if lease._state != 'checked':
                _fail('MANIFEST_RECHECK_REQUIRED')
            lease.recheck(lease._observed)
            normal = True
        except Exception as error:
            if isinstance(error, RpmQueryError):
                raise
            raise RpmQueryError('MANIFEST_REFUSED') from None
        finally:
            lease._close()
            if normal:
                lease._check()


class _AuthorityLease(SafeFiles):
    def __init__(self, reader, deadline):
        self.anchor = reader._root
        self.uid = reader._uid
        self._gid = reader._gid
        self._clock = reader._clock
        self._end = deadline
        self.anchors = []
        self.routes = []
        self.hook = lambda event: None
        self._state = 'new'
        self._observed = None
        self._snapshot = None

    def _check(self):
        if self._clock() >= self._end:
            _fail('MANIFEST_DEADLINE')

    def _open_routes(self):
        self._check()
        self._parent = self._directory(self.anchor / 'usr/share/qshd')
        self._validate_directory_routes()
        self._check()
        self._state = 'open'

    def _sample(self):
        self._check()
        self._validate_directory_routes()
        snapshot = self._read(self._parent, 'consumer-rpm.json', limit=16384)
        if snapshot['uid'] != self.uid or snapshot['gid'] != self._gid or snapshot['mode'] != 0o644:
            _fail('MANIFEST_AUTHORITY')
        self._validate_directory_routes()
        authority = _authority_document(snapshot['data'])
        self._check()
        return authority, snapshot

    def capture(self):
        if self._state != 'open':
            if self._state != 'closed':
                self._state = 'failed'
            _fail('MANIFEST_ORDER')
        self._state = 'failed'
        try:
            value, before = self._sample()
            again, after = self._sample()
            if value != again or not self._same(after, before, times=True):
                _fail('MANIFEST_DRIFT')
            self._check()
            self._observed = value
            self._snapshot = before
            self._state = 'captured'
            return value
        except Exception:
            raise RpmQueryError('MANIFEST_CAPTURE') from None

    def recheck(self, authority):
        valid = self._state in ('captured', 'checked') and authority is self._observed
        if self._state != 'closed':
            self._state = 'failed'
        if not valid:
            _fail('MANIFEST_OBSERVATION')
        try:
            value, snapshot = self._sample()
            if value != authority or not self._same(snapshot, self._snapshot, times=True):
                _fail('MANIFEST_DRIFT')
            self._check()
            self._state = 'checked'
        except Exception:
            raise RpmQueryError('MANIFEST_RECHECK') from None

    def _close(self):
        self._state = 'closed'
        self._observed = None
        self._snapshot = None
        descriptors = list(dict.fromkeys(self.anchors + [fd for route in self.routes for fd in (route[0], route[2])]))
        self.anchors = []
        self.routes = []
        first_error = None
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except BaseException as error:
                if first_error is None:
                    first_error = error
        if first_error is not None:
            if not isinstance(first_error, Exception):
                raise first_error
            _fail('MANIFEST_CLOSE')
