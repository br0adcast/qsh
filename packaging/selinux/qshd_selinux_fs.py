"""Internal filesystem primitives shared by trusted packaging library callers.

SafeFiles is a mixin, not a resource/lock lifecycle. Callers initialize uid,
anchor, anchors, routes and hook, and retain their existing descriptor scopes.
No target registry, provisioning, recovery or readiness policy is defined here.
"""
import base64
import os
import stat
import uuid

import qshd_selinux_contexts as pure

MAX_FILE = pure.MAX_CONTENT
MAX_STATE = 16 * MAX_FILE
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


class SafeFiles:
    """Reuse checks without taking ownership of caller directory scopes."""

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

    def _validate_directory_routes(self):
        for fd in self.anchors:
            if identity(os.stat(self.anchor, follow_symlinks=False)) != identity(os.fstat(fd)):
                fail('ANCHOR_BINDING')
        for parent, name, fd in self.routes:
            self._dir_mode(parent)
            self._dir_mode(fd)
            if identity(os.stat(name, dir_fd=parent, follow_symlinks=False)) != identity(os.fstat(fd)):
                fail('DIRECTORY_BINDING')

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
        fd = None
        try:
            try:
                self._bound(parent, name, probe, state=state)
                fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=parent)
                if identity(os.fstat(probe)) != identity(os.fstat(fd)):
                    fail('OPEN_BINDING')
                self._bound(parent, name, fd, state=state)
            finally:
                os.close(probe)
        except BaseException:
            if fd is not None:
                os.close(fd)
            raise
        return fd

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

    def _create(self, parent, data, metadata, *, state=False):
        """Targets copy exact metadata; new state retains validated kernel defaults."""
        if metadata is None and not state:
            fail('STAGE_METADATA')
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
            os.fchown(fd, metadata['uid'] if metadata is not None else self.uid,
                      metadata['gid'] if metadata is not None else os.fstat(parent).st_gid)
            os.fchmod(fd, metadata['mode'] if metadata is not None else 0o600)
            if metadata is None:
                metadata = self._read(parent, name, state=True, limit=MAX_STATE)
                if metadata['inode'] != own:
                    fail('STAGE_BINDING')
            for key in os.listxattr(fd):
                if key not in metadata['xattrs']:
                    os.removexattr(fd, key)
            for key, value in metadata['xattrs'].items():
                desired = decode(value)
                if not state or key not in os.listxattr(fd) or os.getxattr(fd, key) != desired:
                    os.setxattr(fd, key, desired)
            os.fsync(fd)
            self.hook('stage_file_sync')
            os.fsync(parent)
            self.hook('stage_directory_sync')
            self._bound(parent, name, fd, state=state)
            result = self._read(parent, name, state=state, limit=MAX_STATE)
            if result['inode'] != own:
                fail('STAGE_BINDING')
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
