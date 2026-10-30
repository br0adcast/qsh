"""Disposable filesystem tests; no host policy or package operations."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest

MODULES = Path(__file__).resolve().parents[2] / 'packaging/selinux'
sys.path.insert(0, str(MODULES))
import qshd_selinux_transaction as tx


class FilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / 'contexts'
        self.target.write_bytes(b'system_r:sshd_t:s0 user_r:user_t:s0\n')
        self.target.chmod(0o640)

    def engine(self, hook=None):
        return tx.Transaction(self.root / 'state', {'/contexts': self.target}, uid=os.geteuid(), hook=hook)

    def test_stage_preserves_mode_and_user_xattrs(self):
        os.setxattr(self.target, 'user.qsh-test', b'preserved')
        with self.engine().locked() as engine:
            snapshot = engine.snapshot('/contexts')
            stage = engine.stage('/contexts', b'new', snapshot)
            self.assertEqual(stage['mode'], 0o640)
            self.assertEqual(stage['xattrs'], snapshot['xattrs'])
            self.assertEqual(self.target.read_bytes(), snapshot['data'])

    def test_symlink_and_hardlink_refused(self):
        self.target.unlink()
        self.target.symlink_to(self.root / 'absent')
        with self.assertRaises(tx.Conflict):
            with self.engine().locked() as engine:
                engine.snapshot('/contexts')
        self.target.unlink()
        self.target.write_bytes(b'a')
        os.link(self.target, self.root / 'link')
        with self.assertRaises(tx.Conflict):
            with self.engine().locked() as engine:
                engine.snapshot('/contexts')

    def test_incomplete_bootstrap_refused(self):
        (self.root / 'state').mkdir(mode=0o700)
        with self.assertRaises(tx.Conflict):
            with self.engine().locked():
                pass

    def test_fifo_does_not_block(self):
        self.target.unlink()
        os.mkfifo(self.target)
        with self.assertRaises(tx.Conflict):
            with self.engine().locked() as engine:
                engine.snapshot('/contexts')

    def test_parent_and_lock_substitution_refused(self):
        with self.engine().locked() as engine:
            (self.root / 'state/lock').rename(self.root / 'old-lock')
            (self.root / 'state/lock').write_bytes(b'')
            (self.root / 'state/lock').chmod(0o600)
            with self.assertRaises(tx.Conflict):
                engine.snapshot('/contexts')

    def test_metadata_failure_leaves_original_and_cleans_owned_stage(self):
        with self.engine().locked() as engine:
            snap = engine.snapshot('/contexts')
            snap['xattrs']['invalid.attribute'] = tx.encode(b'value')
            with self.assertRaises(OSError):
                engine.stage('/contexts', b'new', snap)
            self.assertEqual(self.target.read_bytes(), snap['data'])
            self.assertEqual(list(self.root.glob('.qshd-*')), [])

    def test_recover_rename_before_progress_in_fresh_instance(self):
        def stop(event):
            if event == 'target_rename':
                raise RuntimeError('interrupted')
        before = self.target.read_bytes()
        with self.assertRaises(RuntimeError):
            with self.engine(stop).locked() as engine:
                engine.commit({'/contexts': b'new'}, {})
        self.assertEqual(self.target.read_bytes(), b'new')
        with self.engine().locked() as engine:
            self.assertTrue(engine.recover())
            self.assertFalse(engine.recover())
        self.assertNotEqual(before, self.target.read_bytes())
        self.assertFalse((self.root / 'state/journal').exists())

    def test_recovery_refuses_identical_byte_unknown_inode(self):
        def stop(event):
            if event == 'journal_directory_sync':
                raise RuntimeError('interrupted')
        with self.assertRaises(RuntimeError):
            with self.engine(stop).locked() as engine:
                engine.commit({'/contexts': b'new'}, {})
        replacement = self.root / 'replacement'
        replacement.write_bytes(self.target.read_bytes())
        replacement.chmod(0o640)
        replacement.replace(self.target)
        with self.assertRaises(tx.Conflict):
            with self.engine().locked() as engine:
                engine.recover()
        self.assertTrue((self.root / 'state/journal').exists())

    def test_all_publication_boundaries_restart(self):
        events = ('stage_file_sync', 'stage_directory_sync', 'journal_stage_sync',
                  'journal_rename', 'journal_directory_sync', 'stage_recorded',
                  'target_rename', 'target_directory_sync', 'receipt_rename',
                  'receipt_directory_sync', 'before_journal_retire',
                  'journal_retire', 'retire_directory_sync')
        for event in events:
            with self.subTest(event=event), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / 'context'
                target.write_bytes(b'system_r:sshd_t:s0 user_r:user_t:s0\n')
                identity = {'path': '/contexts', 'source_type': 'sshd_t', 'original_package': 'fixture-1'}
                content, receipt = tx.pure.plan_reconcile(target.read_bytes(), None, identity)
                fired = []
                def stop(actual):
                    if actual == event and not fired:
                        fired.append(actual)
                        raise RuntimeError('interrupted')
                def engine(hook=None):
                    return tx.Transaction(root / 'state', {'/contexts': target}, uid=os.geteuid(), hook=hook)
                with self.assertRaises(RuntimeError):
                    with engine(stop).locked() as transaction:
                        transaction.commit({'/contexts': content}, {'/contexts': receipt})
                self.assertEqual(fired, [event])
                with engine().locked() as transaction:
                    transaction.recover()
                    # Pre-journal interruption leaves no authorized transaction.
                    if not (root / 'state/journal').exists() and target.read_bytes() != content:
                        transaction.commit({'/contexts': content}, {'/contexts': receipt})
                    self.assertFalse(transaction.recover())
                self.assertEqual(target.read_bytes(), content)

    def test_duplicate_json_journal_refused(self):
        with self.engine().locked():
            pass
        journal = self.root / 'state/journal'
        journal.write_bytes(b'{"version":1,"version":1}')
        journal.chmod(0o600)
        with self.assertRaises(tx.Conflict):
            with self.engine().locked() as engine:
                engine.recover()

    def test_missing_receipts_refused_after_initialization(self):
        with self.engine().locked():
            pass
        (self.root / 'state/receipts').unlink()
        with self.assertRaises(tx.Conflict):
            with self.engine().locked():
                pass

    def test_reconcile_status_remove_preserves_admin_edits(self):
        engine = self.engine()
        identities = {'/contexts': {'path': '/contexts', 'source_type': 'sshd_t', 'original_package': 'fixture-1'}}
        original = self.target.read_bytes()
        self.assertTrue(engine.reconcile(identities))
        self.assertFalse(engine.reconcile(identities))
        self.assertTrue(engine.status(identities)['targets']['/contexts'])
        with self.target.open('ab') as stream:
            stream.write(b'# administrator addition\n')
        self.assertTrue(engine.remove())
        self.assertEqual(self.target.read_bytes(), original + b'# administrator addition\n')
        self.assertEqual((self.root / 'state/receipts').read_bytes(), b'{}')
        self.assertFalse(engine.remove())

    def test_explicit_update_publishes_only_final_content(self):
        identities = {'/contexts': {'path': '/contexts', 'source_type': 'sshd_t', 'original_package': 'fixture-1'}}
        self.engine().reconcile(identities)
        changed = {'/contexts': dict(identities['/contexts'], original_package='fixture-2')}
        with self.assertRaises(tx.pure.ReconcileError):
            self.engine().reconcile(changed)
        publications = []
        self.engine(lambda event: publications.append(self.target.read_bytes()) if event == 'target_rename' else None).update(changed)
        self.assertEqual(len(publications), 1)
        self.assertIn(b'qshd_t', publications[0])
