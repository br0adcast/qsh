"""Read-only adapter tests: native calls are always synthetic."""
import ctypes as C
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[2] / 'packaging/selinux/qshd_selinux_api.py'


class Function:
    def __init__(self, impl=lambda *args: 0):
        self.impl = impl
    def __call__(self, *args):
        return self.impl(*args)


class Library:
    def __init__(self):
        names = ('security_check_context_raw string_to_security_class '
                 'string_to_av_perm security_compute_av_flags_raw '
                 'security_compute_create_raw security_compute_relabel_raw '
                 'security_validatetrans_raw freecon selinux_status_open '
                 'selinux_status_close selinux_status_updated '
                 'selinux_status_getenforce selinux_status_policyload').split()
        for name in names:
            setattr(self, name, Function())
        self.string_to_security_class.impl = lambda name: 7
        self.string_to_av_perm.impl = lambda cls, name: {b'read': 1, b'write': 2}.get(name, 0)
        self.selinux_status_getenforce.impl = lambda: 1
        self.freed = []
        self.freecon.impl = lambda ptr: self.freed.append(ptr.value)
        self.buffer = C.create_string_buffer(b'user:role:type:s0')
        self.output_rc = 0
        def output(source, target, cls, ptr):
            C.cast(ptr, C.POINTER(C.c_void_p))[0] = C.addressof(self.buffer)
            C.set_errno(13)
            return self.output_rc
        self.security_compute_create_raw.impl = output
        self.security_compute_relabel_raw.impl = output
        self.allowed = 3
        self.flags = 0
        def av(source, target, cls, requested, ptr):
            decision = C.cast(ptr, C.POINTER(api.AvDecision)).contents
            decision.allowed = self.allowed
            decision.flags = self.flags
            return 0
        self.security_compute_av_flags_raw.impl = av


try:
    spec = importlib.util.spec_from_file_location('qshd_selinux_api', PATH)
    api = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(api)
except FileNotFoundError:
    api = None


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(api, 'read-only adapter is missing')
        self.lib = Library()
        self.adapter = api.SelinuxApi(self.lib)

    def test_bindings_and_layout(self):
        self.assertEqual(C.sizeof(api.AvDecision), 24)
        for i, name in enumerate(('allowed', 'decided', 'auditallow', 'auditdeny', 'seqno', 'flags')):
            self.assertEqual(getattr(api.AvDecision, name).offset, 4 * i)
        self.assertEqual(self.lib.security_validatetrans_raw.argtypes,
                         [C.c_char_p, C.c_char_p, C.c_ushort, C.c_char_p])
        self.assertEqual(self.lib.freecon.argtypes, [C.c_void_p])
        self.assertIsNone(self.lib.freecon.restype)
        with patch.object(api.C, 'CDLL', return_value=Library()) as loader:
            api.SelinuxApi()
        loader.assert_called_once_with('libselinux.so.1', use_errno=True)
        del self.lib.freecon
        with self.assertRaises(api.SelinuxError):
            api.SelinuxApi(self.lib)

    def test_every_required_symbol_is_mandatory(self):
        for name in vars(Library()):
            if not isinstance(getattr(Library(), name), Function):
                continue
            lib = Library()
            delattr(lib, name)
            with self.subTest(name=name), self.assertRaises(api.SelinuxError):
                api.SelinuxApi(lib)
        lib = Library()
        lib.freecon = 0
        with self.assertRaises(api.SelinuxError):
            api.SelinuxApi(lib)

    def test_status_open_refusal_and_initial_indication(self):
        for result in (-1, 1):
            lib = Library()
            closed = []
            lib.selinux_status_open.impl = lambda fallback: result
            lib.selinux_status_close.impl = lambda: closed.append(True)
            with self.assertRaises(api.SelinuxError):
                with api.SelinuxApi(lib).status_observation():
                    self.fail('failed open must not enter window')
            self.assertEqual(closed, [] if result == -1 else [True])
        calls = iter((1, 0))
        self.lib.selinux_status_updated.impl = lambda: next(calls)
        with self.adapter.status_observation():
            with self.assertRaises(api.SelinuxError):
                with self.adapter.status_observation(): pass
        self.lib.selinux_status_updated.impl = lambda: 0
        self.lib.selinux_status_getenforce.impl = lambda: 0
        closed = []
        self.lib.selinux_status_close.impl = lambda: closed.append(True)
        with self.assertRaises(api.SelinuxError):
            with self.adapter.status_observation(): pass
        self.assertEqual(closed, [True])

    def test_context_and_name_validation_precedes_native_calls(self):
        for value in ('', 'type', 'u:r:t:', 'u:r:t:s0\n', 'u:r:t:s0\x00', 'u:r:t:' + 'x' * 4096):
            with self.subTest(value=value[:20]), self.assertRaises(api.SelinuxError):
                self.adapter.check_context(value)
        self.adapter.check_context('u:r:t:s0:c0.c3')
        for cls, perms in (('', ['read']), ('file\x00', ['read']), ('file', []),
                           ('file', ['read', 'read']), ('file', ['unknown'])):
            with self.assertRaises(api.SelinuxError):
                self.adapter.require_av('u:r:t:s0', 'u:r:t:s0', cls, perms)
        self.lib.string_to_security_class.impl = lambda _: 0
        with self.assertRaises(api.SelinuxError):
            self.adapter.compute_create('u:r:t:s0', 'u:r:t:s0', 'file')

    def test_av_requires_every_bit_and_rejects_permissive(self):
        for allowed, flags, valid in ((0, 0, False), (1, 0, False), (2, 0, False),
                                      (7, 0, True), (3, 1, False)):
            self.lib.allowed, self.lib.flags = allowed, flags
            if valid:
                self.adapter.require_av('u:r:t:s0', 'u:r:t:s0', 'file', ['read', 'write'])
            else:
                with self.assertRaises(api.SelinuxError):
                    self.adapter.require_av('u:r:t:s0', 'u:r:t:s0', 'file', ['read', 'write'])

    def test_outputs_exact_and_freed_even_on_failure(self):
        for method in (self.adapter.compute_create, self.adapter.compute_relabel):
            self.assertEqual(method('u:r:t:s0', 'u:r:t:s0', 'file'), 'user:role:type:s0')
        self.assertEqual(self.lib.freed, [C.addressof(self.lib.buffer)] * 2)
        self.lib.output_rc = -1
        def free_after_error(ptr):
            self.lib.freed.append(ptr.value)
            C.set_errno(99)
        self.lib.freecon.impl = free_after_error
        with self.assertRaises(api.SelinuxError) as caught:
            self.adapter.compute_create('u:r:t:s0', 'u:r:t:s0', 'file')
        self.assertEqual(caught.exception.errno, 13)
        self.assertEqual(self.lib.freed, [C.addressof(self.lib.buffer)] * 3)

    def test_output_bounds_null_encoding_and_no_fixed_read(self):
        for raw, valid in ((b'u:r:t:s0', True), (b'u:r:t:' + b'x' * 4089, True),
                           (b'u:r:t:' + b'x' * 4090, False), (b'u:r:t:\xff', False), (b'type', False)):
            self.lib.buffer = C.create_string_buffer(raw)
            with patch.object(api.C, 'string_at', side_effect=AssertionError('unsafe string copy')):
                if valid:
                    self.assertEqual(self.adapter.compute_relabel('u:r:t:s0', 'u:r:t:s0', 'file'), raw.decode())
                else:
                    with self.assertRaises(api.SelinuxError):
                        self.adapter.compute_relabel('u:r:t:s0', 'u:r:t:s0', 'file')
            self.assertEqual(self.lib.freed[-1], C.addressof(self.lib.buffer))
        self.lib.security_compute_create_raw.impl = lambda *args: 0
        with self.assertRaises(api.SelinuxError):
            self.adapter.compute_create('u:r:t:s0', 'u:r:t:s0', 'file')

    def test_transition_argument_semantics(self):
        received = []
        self.lib.security_validatetrans_raw.impl = lambda *args: received.append(args) or 0
        self.adapter.validate_transition('u:r:old:s0', 'u:r:new:s0', 'chr_file', 'u:r:task:s0')
        self.assertEqual(received, [(b'u:r:old:s0', b'u:r:new:s0', 7, b'u:r:task:s0')])

    def test_names_resolve_fresh_for_each_operation(self):
        self.adapter.require_av('u:r:t:s0', 'u:r:t:s0', 'file', ['read'])
        self.lib.string_to_av_perm.impl = lambda cls, name: 0
        with self.assertRaises(api.SelinuxError):
            self.adapter.require_av('u:r:t:s0', 'u:r:t:s0', 'file', ['read'])
        self.lib.string_to_security_class.impl = lambda name: 0
        with self.assertRaises(api.SelinuxError):
            self.adapter.compute_relabel('u:r:t:s0', 'u:r:t:s0', 'file')

    def test_native_errors(self):
        def fail(*args):
            C.set_errno(5)
            return -1
        for name, call in (
            ('security_check_context_raw', lambda: self.adapter.check_context('u:r:t:s0')),
            ('security_compute_av_flags_raw', lambda: self.adapter.require_av('u:r:t:s0', 'u:r:t:s0', 'file', ['read'])),
            ('security_validatetrans_raw', lambda: self.adapter.validate_transition('u:r:t:s0', 'u:r:t:s0', 'file', 'u:r:t:s0'))):
            getattr(self.lib, name).impl = fail
            with self.assertRaises(api.SelinuxError) as caught:
                call()
            self.assertEqual(caught.exception.errno, 5)

    def test_status_observation_cleanup_and_changes(self):
        for change in ('none', 'updated', 'reload', 'permissive', 'body', 'error'):
            events = []
            self.lib.selinux_status_open.impl = lambda fallback: events.append(('open', fallback)) or 0
            self.lib.selinux_status_close.impl = lambda: events.append(('close',))
            self.lib.selinux_status_updated.impl = lambda: 0
            self.lib.selinux_status_policyload.impl = lambda: 42
            self.lib.selinux_status_getenforce.impl = lambda: 1
            def observe():
                with self.adapter.status_observation():
                    if change == 'updated': self.lib.selinux_status_updated.impl = lambda: 1
                    if change == 'reload': self.lib.selinux_status_policyload.impl = lambda: 43
                    if change == 'permissive': self.lib.selinux_status_getenforce.impl = lambda: 0
                    if change == 'error': self.lib.selinux_status_updated.impl = lambda: -1
                    if change == 'body': raise RuntimeError('body')
            if change == 'none': observe()
            else:
                with self.assertRaises(RuntimeError if change == 'body' else api.SelinuxError): observe()
            self.assertEqual(events, [('open', 0), ('close',)])
        for name in ('selinux_status_updated', 'selinux_status_getenforce', 'selinux_status_policyload'):
            lib = Library()
            closes = []
            lib.selinux_status_close.impl = lambda: closes.append(True)
            getattr(lib, name).impl = lambda: -1
            with self.assertRaises(api.SelinuxError):
                with api.SelinuxApi(lib).status_observation(): pass
            self.assertEqual(closes, [True])


if __name__ == '__main__':
    unittest.main()
