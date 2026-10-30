"""Read-only libselinux queries for a bounded readiness observation.

This adapter does not certify a complete policy. Native calls can block; the
caller must impose a deadline on the complete verifier in a separate process.
Status observations detect cooperative policy/mode changes, not hostile races.
"""
import ctypes as C
from contextlib import contextmanager
import re
import stat


class SelinuxError(RuntimeError):
    """Bounded diagnostics deliberately exclude raw security contexts."""

    def __init__(self, operation, name='query', errno=0):
        self.operation = operation[:80]
        self.name = name[:80]
        self.errno = errno
        super().__init__(f'{self.operation}: {self.name} (errno={errno})')


class AvDecision(C.Structure):
    _fields_ = [(name, C.c_uint32) for name in
                ('allowed', 'decided', 'auditallow', 'auditdeny', 'seqno', 'flags')]


# The 4096-byte bound includes the terminating NUL.
_CONTEXT_LIMIT = 4096
_NAME = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')
_COMPONENT = re.compile(r'[A-Za-z0-9_]+\Z')


def _context(value):
    if not isinstance(value, str):
        raise SelinuxError('input', 'context')
    try:
        raw = value.encode('ascii')
    except UnicodeError:
        raise SelinuxError('input', 'context') from None
    parts = value.split(':', 3)
    if (len(raw) >= _CONTEXT_LIMIT or len(parts) != 4
            or not all(_COMPONENT.fullmatch(p) for p in parts[:3])
            or not parts[3] or any(b < 33 or b > 126 for b in raw)):
        raise SelinuxError('input', 'context')
    return raw


def _name(value):
    if not isinstance(value, str) or not _NAME.fullmatch(value):
        raise SelinuxError('input', 'name')
    return value.encode('ascii')


class SelinuxApi:
    """Explicit native ABI bindings; injection is reserved for isolated tests."""

    def __init__(self, library=None):
        try:
            self._lib = library if library is not None else C.CDLL('libselinux.so.1', use_errno=True)
        except OSError:
            raise SelinuxError('load', 'libselinux.so.1', C.get_errno()) from None
        context = C.c_char_p
        cls = C.c_ushort
        output = C.POINTER(C.c_void_p)
        signatures = {
            'security_check_context_raw': ([context], C.c_int),
            'string_to_security_class': ([context], cls),
            'string_to_av_perm': ([cls, context], C.c_uint32),
            'security_compute_av_flags_raw': ([context, context, cls, C.c_uint32, C.POINTER(AvDecision)], C.c_int),
            'security_compute_create_raw': ([context, context, cls, output], C.c_int),
            'security_compute_relabel_raw': ([context, context, cls, output], C.c_int),
            'security_validatetrans_raw': ([context, context, cls, context], C.c_int),
            'freecon': ([C.c_void_p], None),
            'selabel_open': ([C.c_uint, C.c_void_p, C.c_uint], C.c_void_p),
            'selabel_close': ([C.c_void_p], None),
            'selabel_lookup_raw': ([C.c_void_p, output, context, C.c_int], C.c_int),
            'fgetfilecon_raw': ([C.c_int, output], C.c_int),
            'selinux_status_open': ([C.c_int], C.c_int),
            'selinux_status_close': ([], None),
            'selinux_status_updated': ([], C.c_int),
            'selinux_status_getenforce': ([], C.c_int),
            'selinux_status_policyload': ([], C.c_int),
        }
        if C.sizeof(AvDecision) != 24:
            raise SelinuxError('bind', 'av_decision')
        for name, (args, result) in signatures.items():
            try:
                function = getattr(self._lib, name)
                if not callable(function):
                    raise TypeError()
                function.argtypes = args
                function.restype = result
                if function.argtypes != args or function.restype != result:
                    raise TypeError()
            except (AttributeError, TypeError, ValueError):
                raise SelinuxError('bind', name) from None
        self._observing = False

    def _call(self, name, *args):
        C.set_errno(0)
        result = getattr(self._lib, name)(*args)
        saved_errno = C.get_errno()
        if result < 0:
            raise SelinuxError(name, errno=saved_errno)
        return result

    def _class(self, name):
        result = self._call('string_to_security_class', _name(name))
        if result == 0:
            raise SelinuxError('class', name)
        return result

    def check_context(self, raw):
        self._call('security_check_context_raw', _context(raw))

    def require_av(self, source, target, class_name, permissions):
        source, target = _context(source), _context(target)
        cls = self._class(class_name)
        if isinstance(permissions, (str, bytes)):
            raise SelinuxError('permissions', 'invalid sequence')
        try:
            names = tuple(permissions)
        except TypeError:
            raise SelinuxError('permissions', 'invalid sequence') from None
        if not names or len(names) > 32:
            raise SelinuxError('permissions', 'invalid count')
        encoded = [_name(name) for name in names]
        if len(set(encoded)) != len(encoded):
            raise SelinuxError('permissions', 'duplicate')
        requested = 0
        for name in encoded:
            bit = self._call('string_to_av_perm', cls, name)
            if bit == 0 or bit & (bit - 1) or requested & bit:
                raise SelinuxError('permission', name.decode())
            requested |= bit
        decision = AvDecision()
        self._call('security_compute_av_flags_raw', source, target, cls, requested, C.byref(decision))
        if decision.allowed & requested != requested or decision.flags & 1:
            raise SelinuxError('access', class_name)

    def _raw_output(self, operation, pointer):
        # libselinux owns a valid NUL-terminated allocation. Inspect only
        # through its first NUL; fixed-size copies can overread strdup.
        data = bytearray()
        for offset in range(_CONTEXT_LIMIT):
            byte = C.c_ubyte.from_address(pointer.value + offset).value
            if byte == 0:
                try:
                    result = data.decode('ascii')
                except UnicodeError:
                    raise SelinuxError(operation, 'output encoding') from None
                _context(result)
                return result
            data.append(byte)
        raise SelinuxError(operation, 'output length')

    def _compute(self, operation, source, target, class_name):
        source, target = _context(source), _context(target)
        cls = self._class(class_name)
        pointer = C.c_void_p()
        try:
            self._call(operation, source, target, cls, C.byref(pointer))
            if not pointer.value:
                raise SelinuxError(operation, 'null output')
            return self._raw_output(operation, pointer)
        finally:
            if pointer.value:
                self._lib.freecon(pointer)

    def file_defaults(self):
        """One default file-backend scope; create a new scope at each endpoint.

        Fresh handles refresh backend contents, not global configuration path
        selection, nor an atomic snapshot of every configuration source file.
        """
        return _FileDefaults(self)

    def file_context(self, fd):
        """Return a raw label from a borrowed FD; never closes the caller's FD."""
        if type(fd) is not int or not 0 <= fd <= (1 << (8 * C.sizeof(C.c_int) - 1)) - 1:
            raise SelinuxError('input', 'file descriptor')
        pointer = C.c_void_p()
        try:
            result = self._call('fgetfilecon_raw', fd, C.byref(pointer))
            if result == 0 or not pointer.value:
                raise SelinuxError('fgetfilecon_raw', 'invalid output')
            raw = self._raw_output('fgetfilecon_raw', pointer)
            self.check_context(raw)
            return raw
        finally:
            if pointer.value:
                self._lib.freecon(pointer)

    def compute_create(self, source, target, class_name):
        return self._compute('security_compute_create_raw', source, target, class_name)

    def compute_relabel(self, source, target, class_name):
        return self._compute('security_compute_relabel_raw', source, target, class_name)

    def validate_transition(self, old_context, new_context, class_name, task_context):
        old, new, task = map(_context, (old_context, new_context, task_context))
        self._call('security_validatetrans_raw', old, new, self._class(class_name), task)

    @contextmanager
    def status_observation(self):
        """Require enforcing and no observed policy/mode change within a window."""
        if self._observing:
            raise SelinuxError('status', 'nested observation')
        self._observing = True
        opened = False
        try:
            result = self._call('selinux_status_open', 0)
            opened = True
            if result != 0:  # Refuse netlink fallback and abnormal results.
                raise SelinuxError('status', 'open fallback')
            self._call('selinux_status_updated')  # Consume initial indication.
            if self._call('selinux_status_getenforce') != 1:
                raise SelinuxError('status', 'not enforcing')
            counter = self._call('selinux_status_policyload')
            yield
            updated = self._call('selinux_status_updated')
            enforcing = self._call('selinux_status_getenforce')
            current = self._call('selinux_status_policyload')
            if updated != 0 or enforcing != 1 or current != counter:
                raise SelinuxError('status', 'observation changed')
        finally:
            try:
                if opened:
                    self._lib.selinux_status_close()
            finally:
                self._observing = False


class _FileDefaults:
    """One single-use native default backend, owned by its explicit scope."""

    def __init__(self, api):
        self._api = api
        self._used = False
        self._handle = None

    def __enter__(self):
        if self._used:
            raise SelinuxError('file defaults', 'scope reused')
        self._used = True
        C.set_errno(0)
        handle = self._api._lib.selabel_open(0, None, 0)
        saved_errno = C.get_errno()
        if not handle:
            raise SelinuxError('selabel_open', errno=saved_errno)
        self._handle = handle
        return self

    def lookup(self, path, kind):
        if self._handle is None:
            raise SelinuxError('file defaults', 'scope closed')
        if type(path) is not str:
            raise SelinuxError('input', 'file path')
        try:
            encoded = path.encode('ascii')
        except UnicodeError:
            raise SelinuxError('input', 'file path') from None
        if (not 1 <= len(encoded) < 4096 or not path.startswith('/')
                or any(byte < 32 or byte > 126 for byte in encoded)
                or (path != '/' and any(part in ('', '.', '..') for part in path[1:].split('/')))):
            raise SelinuxError('input', 'file path')
        if type(kind) is not int or kind not in (stat.S_IFREG, stat.S_IFDIR):
            raise SelinuxError('input', 'file kind')
        api = self._api
        pointer = C.c_void_p()
        try:
            result = api._call('selabel_lookup_raw', self._handle, C.byref(pointer), encoded, kind)
            if result != 0 or not pointer.value:
                raise SelinuxError('selabel_lookup_raw', 'invalid output')
            raw = api._raw_output('selabel_lookup_raw', pointer)
            api.check_context(raw)
            return raw
        finally:
            if pointer.value:
                api._lib.freecon(pointer)

    def __exit__(self, kind, value, traceback):
        if self._handle is None:
            raise SelinuxError('file defaults', 'scope closed')
        handle, self._handle = self._handle, None
        self._api._lib.selabel_close(handle)
        return False
