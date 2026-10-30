"""Byte-only context ownership regressions; no host policy is accessed."""
import copy
import importlib.util
from pathlib import Path
import unittest

SPEC = importlib.util.spec_from_file_location('rows', Path(__file__).resolve().parents[2] / 'packaging/selinux/qshd_selinux_contexts.py')
rows = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rows)
I = dict(path='/etc/selinux/targeted/contexts/default_contexts', source_type='sshd_t', original_package='policy-1-1.noarch')
SOURCE = b'# custom\nsystem_r:sshd_t:s0-s0:c0.c1023 user_r:user_t:s0 staff_r:staff_t:s0\n'

class ContextRows(unittest.TestCase):
    def install(self):
        return rows.plan_reconcile(SOURCE, None, I)

    def test_install_check_idempotence_remove(self):
        out, receipt = self.install()
        self.assertIn(b'system_r:qshd_t:s0-s0:c0.c1023\tuser_r:user_t:s0 staff_r:staff_t:s0\n', out)
        self.assertEqual(rows.plan_reconcile(out, receipt, I), (out, receipt))
        self.assertTrue(rows.check_current(out, receipt, I))
        self.assertFalse(rows.check_current(SOURCE, None, I))
        self.assertEqual(rows.plan_remove(out, receipt), (SOURCE, None))
        self.assertEqual(rows.plan_remove(SOURCE, None), (SOURCE, None))

    def test_outside_bytes_survive(self):
        out, receipt = self.install()
        edited = b'# new\xff\n' + out + b'# tail'
        self.assertTrue(rows.check_current(edited, receipt, I))
        self.assertEqual(rows.plan_remove(edited, receipt), (b'# new\xff\n' + SOURCE + b'# tail', None))

    def test_admin_row_preserved_without_source(self):
        custom = b'system_r:qshd_t:s0 user_r:user_t:s0\n'
        out, receipt = rows.plan_reconcile(custom, None, I)
        self.assertEqual(out, custom)
        edited = b'# new\n' + out
        self.assertTrue(rows.check_current(edited, receipt, I))
        self.assertEqual(rows.plan_remove(edited, receipt), (edited, None))
        self.assertEqual(rows.plan_remove(custom, None), (custom, None))

    def test_drift_and_missing_ownership_refused(self):
        out, receipt = self.install()
        cases = [(out, None, I), (SOURCE, receipt, I),
                 (out.replace(b'user_r:user_t:s0', b'user_r:other_t:s0', 1), receipt, I),
                 (out, receipt, dict(I, original_package='policy-2')),
                 (out.replace(b'\tuser_r:', b'\tother_r:'), receipt, I),
                 (out + b'# qshd-context-row end orphan\n', receipt, I)]
        for content, state, identity in cases:
            with self.subTest(content=content, identity=identity), self.assertRaises(rows.ReconcileError):
                rows.plan_reconcile(content, state, identity)
        changed = out.replace(b'system_r:sshd_t:s0-s0:c0.c1023', b'system_r:sshd_t:s0')
        self.assertEqual(rows.plan_remove(changed, receipt)[0], SOURCE.replace(b'system_r:sshd_t:s0-s0:c0.c1023', b'system_r:sshd_t:s0'))

    def test_bad_rows_and_markers(self):
        for content in (SOURCE + SOURCE, SOURCE + b'system_r:qshd_t:s0 bad\n',
                        SOURCE + b'# qshd-context-row begin orphan\n',
                        SOURCE + b'system_r:qshd_t:s0 user_r:user_t:s0\n' * 2,
                        SOURCE.replace(b'user_r:user_t:s0', b'bad'), SOURCE.rstrip(b'\n'),
                        SOURCE.replace(b'\n', b'\r\n')):
            with self.subTest(content=content), self.assertRaises(rows.ReconcileError):
                rows.plan_reconcile(content, None, I)

    def test_fixed_source_identity_and_missing_source(self):
        for identity in (dict(I, source_type=None), dict(I, source_type='remote_login_t'),
                         dict(I, path='/etc/../other'), dict(I, extra=True)):
            with self.subTest(identity=identity), self.assertRaises(rows.ReconcileError):
                rows.plan_reconcile(SOURCE, None, identity)
        with self.assertRaises(rows.ReconcileError):
            rows.plan_reconcile(b'# no source\n', None, I)

    def test_mcs_order_and_other_source_are_preserved(self):
        source = (b'system_r:remote_login_t:s0 other_r:other_t:s0\n' +
                  SOURCE.replace(b'staff_r:staff_t:s0', b'staff_r:staff_t:s0:c0.c2'))
        out, receipt = rows.plan_reconcile(source, None, I)
        self.assertIn(b'user_r:user_t:s0 staff_r:staff_t:s0:c0.c2\n', out)
        self.assertEqual(rows.plan_remove(out, receipt), (source, None))

    def test_explicit_remove_then_reconcile_accepts_update(self):
        out, receipt = self.install()
        changed = out.replace(b'system_r:sshd_t:s0-s0:c0.c1023', b'system_r:sshd_t:s0')
        clean, retired = rows.plan_remove(changed, receipt)
        updated = dict(I, original_package='policy-2')
        proposed, new = rows.plan_reconcile(clean, retired, updated)
        self.assertIn(b'system_r:qshd_t:s0\t', proposed)
        self.assertTrue(rows.check_current(proposed, new, updated))

    def test_edited_admin_row_and_oversized_input_refused(self):
        custom = b'system_r:qshd_t:s0 user_r:user_t:s0\n'
        _, receipt = rows.plan_reconcile(custom, None, I)
        for content in (custom.replace(b'user_t', b'other_t'), b'# removed\n'):
            with self.assertRaises(rows.ReconcileError):
                rows.plan_reconcile(content, receipt, I)
        with self.assertRaises(rows.ReconcileError):
            rows.plan_reconcile(b'#' * (rows.MAX_CONTENT + 1), None, I)

    def test_maximum_input_refuses_oversized_installation(self):
        source = b'system_r:sshd_t:s0 user_r:user_t:s0\n'
        content = b'#' + b'x' * (rows.MAX_CONTENT - len(source) - 2) + b'\n' + source
        original_identity = copy.deepcopy(I)
        self.assertEqual(len(content), rows.MAX_CONTENT)
        with self.assertRaises(rows.ReconcileError) as caught:
            rows.plan_reconcile(content, None, I)
        self.assertEqual(caught.exception.code, 'CONTENT_INVALID')
        self.assertEqual(content, b'#' + b'x' * (rows.MAX_CONTENT - len(source) - 2) + b'\n' + source)
        self.assertEqual(I, original_identity)
        self.assertEqual(rows.plan_remove(content, None), (content, None))

    def test_maximum_installed_output_roundtrips(self):
        source = b'system_r:sshd_t:s0 user_r:user_t:s0\n'
        # Two marker lines and the derived row add exactly 126 bytes.
        content = b'#' + b'x' * (rows.MAX_CONTENT - 126 - len(source) - 2) + b'\n' + source
        out, receipt = rows.plan_reconcile(content, None, I)
        self.assertEqual(len(out), rows.MAX_CONTENT)
        self.assertTrue(rows.check_current(out, receipt, I))
        self.assertEqual(rows.plan_reconcile(out, receipt, I), (out, receipt))
        self.assertEqual(rows.plan_remove(out, receipt), (content, None))
        with self.assertRaises(rows.ReconcileError) as caught:
            rows.plan_reconcile(b'#' + content, None, I)
        self.assertEqual(caught.exception.code, 'CONTENT_INVALID')

    def test_strict_receipt_validation_and_recovery_intent(self):
        out, receipt = self.install()
        import hashlib
        self.assertEqual(receipt['original_sha256'], hashlib.sha256(SOURCE).hexdigest())
        self.assertEqual(receipt['after_sha256'], hashlib.sha256(out).hexdigest())
        mutations = [dict(receipt, schema_version=True), dict(receipt, extra=1),
                     dict(receipt, block_sha256='0' * 64), dict(receipt, marker_id='bad'),
                     dict(receipt, source_row='bad'), dict(receipt, identity=[]),
                     dict(receipt, identity=dict(I, path='/another/file'))]
        for key in receipt:
            state = copy.deepcopy(receipt)
            del state[key]
            mutations.append(state)
        for state in mutations:
            for action in (lambda: rows.plan_reconcile(out, state, I), lambda: rows.plan_remove(out, state)):
                with self.subTest(state=state), self.assertRaises(rows.ReconcileError):
                    action()
        with self.assertRaises(rows.ReconcileError):
            rows.plan_remove(out, None)

if __name__ == '__main__':
    unittest.main()
