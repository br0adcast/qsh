"""Linux context-file forward transactions, for cooperating privileged writers.

This is a library seam, not a package hook. Production callers use production().
Content mtime may change; inode/ctime are not preservation guarantees. An
incomplete initial provision refuses and requires administrator resolution.
"""
import base64
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import stat
import uuid

import qshd_selinux_contexts as pure

MAX_FILE = pure.MAX_CONTENT
MAX_STATE = 16 * MAX_FILE
MAX_TARGETS = 16
MAX_XATTRS = 128


class Conflict(ValueError):
    """Bounded refusal; existing evidence is retained."""


def fail(code):
    raise Conflict(code)


def identity(st):
    return [st.st_dev, st.st_ino]


def encode(data):
    return base64.b64encode(data).decode('ascii')


def decode(data):
    try:
        return base64.b64decode(data, validate=True)
    except (ValueError, TypeError):
        fail('ENCODING')


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':')).encode()


def pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail('DUPLICATE_KEY')
        result[key] = value
    return result


class Transaction:
    """Injected roots are for trusted library callers and disposable tests only."""

    def __init__(self, state, targets, *, uid=0, hook=None, anchor=None):
        if any(not Path(p).is_absolute() or str(Path(p)) != os.path.normpath(str(p)) or '..' in Path(p).parts for p in [state, *targets.values()]):
            fail('ROOT_PATH')
        self.state = Path(state)
        self.targets = {key: Path(value) for key, value in targets.items()}
        if not 0 < len(targets) <= MAX_TARGETS:
            fail('TARGET_COUNT')
        for key in targets:
            pure._identity({'path': key, 'source_type': 'sshd_t', 'original_package': 'validation'})
        self.uid = uid
        self.anchor = Path(anchor or os.path.commonpath([self.state.parent, *[p.parent for p in self.targets.values()]]))
        self.hook = hook or (lambda event: None)
        self.routes = []
        self.anchors = []
        self.fds = {}
        self.journal = None

    def _directory(self, path):
        relative = path.relative_to(self.anchor)
        fd = os.open(self.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.anchors.append(fd)
        self._dir_mode(fd)
        for part in relative.parts:
            new = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            self.routes.append((fd, part, new))
            self._dir_mode(new)
            fd = new
        return fd

    def _dir_mode(self, fd):
        st = os.fstat(fd)
        if st.st_uid != self.uid or st.st_mode & 0o022:
            fail('DIRECTORY_AUTHORITY')

    def _validate_routes(self):
        for fd in self.anchors:
            if identity(os.stat(self.anchor, follow_symlinks=False)) != identity(os.fstat(fd)):
                fail('ANCHOR_BINDING')
        for parent, name, fd in self.routes:
            self._dir_mode(parent)
            self._dir_mode(fd)
            if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(os.fstat(fd)):
                fail('DIRECTORY_BINDING')
        self._bound(self.state_fd, 'lock', self.lock_fd, state=True)

    def _bound(self, parent, name, fd, *, state=False):
        st = os.fstat(fd)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if identity(st) != identity(named) or not stat.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != self.uid:
            fail('FILE_BINDING')
        if st.st_mode & 0o7000 or (state and stat.S_IMODE(st.st_mode) != 0o600):
            fail('FILE_MODE')
        return st

    def _open(self, parent, name, *, state=False):
        # O_PATH validates type without opening devices or blocking on FIFOs.
        probe = os.open(name, os.O_PATH | os.O_NOFOLLOW, dir_fd=parent)
        try:
            self._bound(parent, name, probe, state=state)
            fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
            if identity(os.fstat(probe)) != identity(os.fstat(fd)):
                os.close(fd)
                fail('OPEN_BINDING')
            self._bound(parent, name, fd, state=state)
            return fd
        finally:
            os.close(probe)

    def _read(self, parent, name, *, state=False, limit=MAX_FILE):
        fd = self._open(parent, name, state=state)
        try:
            before = self._bound(parent, name, fd, state=state)
            data = bytearray()
            while len(data) <= limit:
                chunk = os.read(fd, min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
            if len(data) > limit:
                fail('FILE_LIMIT')
            names = os.listxattr(fd)
            if len(names) > MAX_XATTRS:
                fail('XATTR_LIMIT')
            attrs = {}
            for key in names:
                value = os.getxattr(fd, key)
                if len(key) > 255 or len(value) > 65536:
                    fail('XATTR_LIMIT')
                attrs[key] = encode(value)
            after = self._bound(parent, name, fd, state=state)
            if (before.st_mtime_ns, before.st_ctime_ns) != (after.st_mtime_ns, after.st_ctime_ns):
                fail('READ_DRIFT')
            return {'inode': identity(after), 'data': bytes(data), 'uid': after.st_uid,
                    'gid': after.st_gid, 'mode': stat.S_IMODE(after.st_mode),
                    'xattrs': attrs, 'mtime': after.st_mtime_ns, 'ctime': after.st_ctime_ns}
        finally:
            os.close(fd)

    def _create(self, parent, data, metadata):
        name = '.qshd-' + uuid.uuid4().hex
        fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
        own = identity(os.fstat(fd))
        try:
            view = memoryview(data)
            while view:
                n = os.write(fd, view)
                if n <= 0:
                    fail('SHORT_WRITE')
                view = view[n:]
            os.fchown(fd, metadata['uid'], metadata['gid'])
            os.fchmod(fd, metadata['mode'])
            for key in os.listxattr(fd):
                if key not in metadata['xattrs']:
                    os.removexattr(fd, key)
            for key, value in metadata['xattrs'].items():
                os.setxattr(fd, key, decode(value))
            os.fsync(fd)
            self.hook('stage_file_sync')
            os.fsync(parent)
            self.hook('stage_directory_sync')
            result = self._read(parent, name, limit=MAX_STATE)
            if not self._same(result, dict(metadata, data=data), inode=False):
                fail('STAGE_METADATA')
            result['name'] = name
            return result
        except BaseException:
            # Never remove a substituted name, even on failed metadata application.
            try:
                if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) == own:
                    os.unlink(name, dir_fd=parent)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(fd)

    @staticmethod
    def _same(actual, expected, *, inode=True, times=False):
        fields = ['data', 'uid', 'gid', 'mode', 'xattrs']
        if inode:
            fields.append('inode')
        if times:
            fields.extend(['mtime', 'ctime'])
        return all(actual[key] == expected[key] for key in fields)

    @contextmanager
    def locked(self, *, provision=True):
        opened = []
        try:
            parent = self._directory(self.state.parent)
            opened.append(parent)
            try:
                if not provision:
                    os.stat(self.state.name, dir_fd=parent, follow_symlinks=False)
                    fresh = False
                else:
                    os.mkdir(self.state.name, 0o700, dir_fd=parent)
                    fresh = True
            except FileExistsError:
                fresh = False
            self.state_fd = self._directory(self.state)
            opened.append(self.state_fd)
            if stat.S_IMODE(os.fstat(self.state_fd).st_mode) != 0o700:
                fail('STATE_MODE')
            if fresh:
                for name, data in [('lock', b''), ('receipts', b'{}')]:
                    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=self.state_fd)
                    try:
                        os.write(fd, data)
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                os.fsync(self.state_fd)
                os.fsync(parent)
            self.lock_fd = self._open(self.state_fd, 'lock', state=True)
            opened.append(self.lock_fd)
            fcntl.flock(self.lock_fd, fcntl.LOCK_EX)
            self._validate_routes()
            self._read(self.state_fd, 'receipts', state=True, limit=MAX_STATE)
            for key, path in self.targets.items():
                fd = self._directory(path.parent)
                opened.append(fd)
                self.fds[key] = (fd, path.name)
            yield self
        except (OSError, ValueError) as error:
            if isinstance(error, (Conflict, pure.ReconcileError)):
                raise
            raise Conflict('FILESYSTEM_' + str(getattr(error, 'errno', 'INVALID'))) from error
        finally:
            for fd in set(opened + self.anchors + [part for route in self.routes for part in (route[0], route[2])]):
                os.close(fd)
            self.routes = []
            self.anchors = []
            self.fds = {}

    def snapshot(self, key):
        self._validate_routes()
        return self._read(*self.fds[key])

    def stage(self, key, data, metadata):
        self._validate_routes()
        return self._create(self.fds[key][0], data, metadata)

    @staticmethod
    def _pack(snapshot):
        result = dict(snapshot)
        result['sha256'] = hashlib.sha256(result['data']).hexdigest()
        result['data'] = encode(result['data'])
        return result

    @staticmethod
    def _unpack(value):
        required = {'inode', 'data', 'sha256', 'uid', 'gid', 'mode', 'xattrs', 'mtime', 'ctime'}
        if not isinstance(value, dict) or set(value) not in (required, required | {'name'}):
            fail('SNAPSHOT_SCHEMA')
        if not isinstance(value['inode'], list) or len(value['inode']) != 2 or any(type(v) is not int or v < 0 for v in value['inode']):
            fail('SNAPSHOT_INODE')
        if any(type(value[k]) is not int or value[k] < 0 for k in ('uid', 'gid', 'mode', 'mtime', 'ctime')) or value['mode'] > 0o777:
            fail('SNAPSHOT_METADATA')
        attrs = value['xattrs']
        if not isinstance(attrs, dict) or len(attrs) > MAX_XATTRS:
            fail('XATTR_LIMIT')
        for key, data in attrs.items():
            if not isinstance(key, str) or not key or '\0' in key or len(key) > 255 or len(decode(data)) > 65536:
                fail('XATTR_LIMIT')
        if 'name' in value and (not isinstance(value['name'], str) or not value['name'].startswith('.qshd-') or len(value['name']) != 38 or any(c not in '0123456789abcdef' for c in value['name'][6:])):
            fail('STAGE_NAME')
        result = dict(value, data=decode(value['data']))
        if hashlib.sha256(result['data']).hexdigest() != result['sha256']:
            fail('SNAPSHOT_DIGEST')
        if len(result['data']) > MAX_STATE:
            fail('SNAPSHOT_LIMIT')
        return result

    def _receipts(self, data):
        result = self._json(data)
        if not isinstance(result, dict) or len(result) > MAX_TARGETS or not set(result) <= self.targets.keys():
            fail('RECEIPT_PATHS')
        for key, receipt in result.items():
            pure._receipt(receipt)
            if receipt['identity']['path'] != key:
                fail('RECEIPT_IDENTITY')
        if json_bytes(result) != data:
            fail('RECEIPTS_NONCANONICAL')
        return result

    @staticmethod
    def _json(data):
        if len(data) > MAX_STATE:
            fail('STATE_LIMIT')
        try:
            return json.loads(data, object_pairs_hook=pairs)
        except (ValueError, UnicodeError, RecursionError):
            fail('JSON_INVALID')

    def _journal_load(self):
        try:
            snap = self._read(self.state_fd, 'journal', state=True, limit=MAX_STATE)
        except FileNotFoundError:
            self.journal = None
            return None
        value = self._json(snap['data'])
        if not isinstance(value, dict) or set(value) != {'version', 'id', 'kind', 'entries'} or type(value['version']) is not int or value['version'] != 1:
            fail('JOURNAL_SCHEMA')
        if value['kind'] not in ('reconcile', 'remove', 'update', 'internal') or not isinstance(value['id'], str) or len(value['id']) != 32 or any(c not in '0123456789abcdef' for c in value['id']):
            fail('JOURNAL_OPERATION')
        entries = value['entries']
        if not isinstance(entries, list) or not 1 <= len(entries) <= MAX_TARGETS + 1:
            fail('JOURNAL_ENTRIES')
        keys = []
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {'key', 'before', 'after', 'sha256', 'stage'}:
                fail('ENTRY_SCHEMA')
            key = entry['key']
            if not isinstance(key, str) or (key != '@receipts' and key not in self.targets):
                fail('ENTRY_PATH')
            keys.append(key)
            before = self._unpack(entry['before'])
            after = decode(entry['after'])
            limit = MAX_STATE if key == '@receipts' else MAX_FILE
            if len(before['data']) > limit or len(after) > limit or hashlib.sha256(after).hexdigest() != entry['sha256']:
                fail('ENTRY_DATA')
            if before['uid'] != self.uid:
                fail('ENTRY_OWNER')
            if key == '@receipts':
                self._receipts(before['data'])
                self._receipts(after)
                if before['mode'] != 0o600:
                    fail('RECEIPT_MODE')
            stage = entry['stage']
            if stage is not None:
                stage = self._unpack(stage)
                if 'name' not in stage or not self._same(stage, dict(before, data=after), inode=False):
                    fail('STAGE_SCHEMA')
        if keys[-1] != '@receipts' or keys[:-1] != sorted(set(keys[:-1])) or len(set(keys)) != len(keys):
            fail('ENTRY_ORDER')
        self.journal = snap
        return value

    def _journal_write(self, value):
        self._validate_routes()
        if self.journal is None:
            try:
                os.stat('journal', dir_fd=self.state_fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                fail('JOURNAL_APPEARED')
        else:
            current = self._read(self.state_fd, 'journal', state=True, limit=MAX_STATE)
            if not self._same(current, self.journal, times=True):
                fail('JOURNAL_BINDING')
        data = json_bytes(value)
        if len(data) > MAX_STATE:
            fail('JOURNAL_LIMIT')
        metadata = {'uid': self.uid, 'gid': os.fstat(self.state_fd).st_gid, 'mode': 0o600, 'xattrs': {}}
        staged = self._create(self.state_fd, data, metadata)
        self.hook('journal_stage_sync')
        self._validate_routes()
        # Recheck authority after all staging hooks and before replacement.
        if self.journal is not None:
            current = self._read(self.state_fd, 'journal', state=True, limit=MAX_STATE)
            if not self._same(current, self.journal, times=True):
                fail('JOURNAL_BINDING')
        elif os.path.lexists(self.state / 'journal'):
            fail('JOURNAL_APPEARED')
        current_stage = self._read(self.state_fd, staged['name'], state=True, limit=MAX_STATE)
        if not self._same(current_stage, staged, times=True):
            fail('JOURNAL_STAGE_BINDING')
        os.rename(staged['name'], 'journal', src_dir_fd=self.state_fd, dst_dir_fd=self.state_fd)
        self.hook('journal_rename')
        os.fsync(self.state_fd)
        self.journal = self._read(self.state_fd, 'journal', state=True, limit=MAX_STATE)
        self.hook('journal_directory_sync')

    def _entry_location(self, entry):
        return (self.state_fd, 'receipts') if entry['key'] == '@receipts' else self.fds[entry['key']]

    def _classify(self, entry):
        parent, name = self._entry_location(entry)
        current = self._read(parent, name, state=entry['key'] == '@receipts', limit=MAX_STATE)
        before = self._unpack(entry['before'])
        after = decode(entry['after'])
        stage = self._unpack(entry['stage']) if entry['stage'] is not None else None
        if self._same(current, before, times=True):
            result = 'unchanged' if before['data'] == after else 'before'
        elif stage and self._same(current, stage):
            result = 'after'
        else:
            fail('TARGET_CONFLICT')
        if stage is not None:
            try:
                sibling = self._read(parent, stage['name'], limit=MAX_STATE)
            except FileNotFoundError:
                sibling = None
            if sibling is not None and not self._same(sibling, stage, times=True):
                fail('STAGE_CONFLICT')
            if result == 'after' and sibling is not None:
                fail('STAGE_DUPLICATE')
        return result

    def commit(self, changes, receipts, kind='internal', expected=None):
        """Internal complete plan seam. Public operations compute pure plans first."""
        self.recover()
        self._receipts(json_bytes(receipts))
        entries = []
        for key in sorted(changes):
            if key not in self.targets or not isinstance(changes[key], bytes) or len(changes[key]) > MAX_FILE:
                fail('PLAN_INVALID')
            before = self.snapshot(key)
            if expected is not None and not self._same(before, expected[key], times=True):
                fail('PLAN_DRIFT')
            entries.append({'key': key, 'before': self._pack(before), 'after': encode(changes[key]),
                            'sha256': hashlib.sha256(changes[key]).hexdigest(), 'stage': None})
        before = self._read(self.state_fd, 'receipts', state=True, limit=MAX_STATE)
        self._receipts(before['data'])
        data = json_bytes(receipts)
        entries.append({'key': '@receipts', 'before': self._pack(before), 'after': encode(data),
                        'sha256': hashlib.sha256(data).hexdigest(), 'stage': None})
        if all(decode(e['after']) == self._unpack(e['before'])['data'] for e in entries):
            return False
        value = {'version': 1, 'id': uuid.uuid4().hex, 'kind': kind, 'entries': entries}
        self._journal_write(value)
        self._complete(value)
        return True

    def _complete(self, value):
        # Preflight the entire set before resuming any publication.
        for entry in value['entries']:
            self._classify(entry)
        for entry in value['entries']:
            self._validate_routes()
            state = self._classify(entry)
            parent, name = self._entry_location(entry)
            if state == 'unchanged':
                continue
            if state == 'before':
                before = self._unpack(entry['before'])
                stage = self._unpack(entry['stage']) if entry['stage'] else None
                if stage is not None:
                    try:
                        self._read(parent, stage['name'], limit=MAX_STATE)
                    except FileNotFoundError:
                        stage = None
                if stage is None:
                    stage = self._create(parent, decode(entry['after']), before)
                    entry['stage'] = self._pack(stage)
                    self._journal_write(value)
                    self.hook('stage_recorded')
                self._validate_routes()
                if self._classify(entry) != 'before':
                    fail('PUBLICATION_DRIFT')
                os.rename(stage['name'], name, src_dir_fd=parent, dst_dir_fd=parent)
                self.hook('receipt_rename' if entry['key'] == '@receipts' else 'target_rename')
            os.fsync(parent)
            self.hook('receipt_directory_sync' if entry['key'] == '@receipts' else 'target_directory_sync')
            if self._classify(entry) != 'after':
                fail('PUBLICATION_VERIFY')
        for entry in value['entries']:
            if self._classify(entry) not in ('unchanged', 'after'):
                fail('FINAL_VERIFY')
        self._validate_routes()
        current = self._read(self.state_fd, 'journal', state=True, limit=MAX_STATE)
        if not self._same(current, self.journal, times=True):
            fail('JOURNAL_BINDING')
        self.hook('before_journal_retire')
        os.unlink('journal', dir_fd=self.state_fd)
        self.hook('journal_retire')
        os.fsync(self.state_fd)
        self.journal = None
        self.hook('retire_directory_sync')

    def recover(self):
        """Finish recognized before/after states; preserve evidence on conflict."""
        self._validate_routes()
        value = self._journal_load()
        if value is None:
            return False
        self._complete(value)
        return True

    def _operation(self, kind, identities=None):
        with self.locked():
            self.recover()
            receipts = self._receipts(self._read(self.state_fd, 'receipts', state=True, limit=MAX_STATE)['data'])
            if kind != 'remove':
                if not isinstance(identities, dict) or set(identities) != set(self.targets):
                    fail('IDENTITY_PATHS')
                for key, value in identities.items():
                    pure._identity(value)
                    if value['path'] != key:
                        fail('IDENTITY_PATH')
            snapshots = {key: self.snapshot(key) for key in sorted(self.targets)}
            changes, new_receipts = {}, {}
            for key, snapshot in snapshots.items():
                current = snapshot['data']
                old = receipts.get(key)
                if kind in ('remove', 'update'):
                    current, _ = pure.plan_remove(current, old)
                if kind != 'remove':
                    current, receipt = pure.plan_reconcile(current, None if kind == 'update' else old, identities[key])
                    new_receipts[key] = receipt
                changes[key] = current
            return self.commit(changes, new_receipts, kind, expected=snapshots)

    def reconcile(self, identities):
        """Plan every target before publishing; ordinary source drift refuses."""
        return self._operation('reconcile', identities)

    def remove(self):
        """Retire owned rows and receipts while retaining unrelated admin bytes."""
        return self._operation('remove')

    def update(self, identities):
        """Explicit source update, publishing current directly to final bytes."""
        return self._operation('update', identities)

    def status(self, identities):
        """Read-only inspection: never provision, recover, adopt or publish."""
        with self.locked(provision=False):
            pending = self._journal_load() is not None
            receipts = self._receipts(self._read(self.state_fd, 'receipts', state=True, limit=MAX_STATE)['data'])
            if not isinstance(identities, dict) or set(identities) != set(self.targets):
                fail('IDENTITY_PATHS')
            result = {}
            for key in sorted(self.targets):
                if identities[key].get('path') != key:
                    fail('IDENTITY_PATH')
                result[key] = pure.check_current(self.snapshot(key)['data'], receipts.get(key), identities[key])
            return {'pending': pending, 'targets': result}

    def resume(self):
        """Public recovery call; refuses uninitialized state."""
        with self.locked(provision=False):
            return self.recover()


def production(paths):
    """Root lifecycle caller supplies policy-owned files; no CLI or discovery.

    Only default_contexts and direct users/ leaves in the fixed targeted policy
    are supported. The lifecycle caller must qualify the installed file set.
    """
    if os.geteuid() != 0:
        fail('ROOT_REQUIRED')
    base = '/etc/selinux/targeted/contexts'
    if not isinstance(paths, (list, tuple)) or not 0 < len(paths) <= MAX_TARGETS or len(set(paths)) != len(paths):
        fail('PRODUCTION_PATHS')
    for path in paths:
        if not isinstance(path, str) or '\0' in path:
            fail('PRODUCTION_PATH')
        try:
            pure._identity({'path': path, 'source_type': 'sshd_t', 'original_package': 'validation'})
        except pure.ReconcileError:
            fail('PRODUCTION_PATH')
        if path != base + '/default_contexts' and (str(Path(path).parent) != base + '/users' or Path(path).name in ('.', '..')):
            fail('PRODUCTION_PATH')
    return Transaction('/var/lib/qshd/selinux-contexts', {path: path for path in paths}, anchor='/')
