"""Read-only libselinux queries for a bounded readiness observation.

This adapter does not certify a complete policy. Native calls can block; the
caller must impose a deadline on the complete verifier in a separate process.
Status observations detect cooperative policy/mode changes, not hostile races.
"""
import ctypes as C
from contextlib import contextmanager
import re


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

    def _compute(self, operation, source, target, class_name):
        source, target = _context(source), _context(target)
        cls = self._class(class_name)
        pointer = C.c_void_p()
        try:
            self._call(operation, source, target, cls, C.byref(pointer))
            if not pointer.value:
                raise SelinuxError(operation, 'null output')
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
