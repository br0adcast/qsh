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

    def test_recorded_missing_stage_restages_but_substitution_refuses(self):
        for substitute in (False, True):
            with self.subTest(substitute=substitute), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                target = root / 'context'
                target.write_bytes(b'before')
                def instance(hook=None):
                    return tx.Transaction(root / 'state', {'/contexts': target}, uid=os.geteuid(), hook=hook)
                def stop(event):
                    if event == 'stage_recorded':
                        raise RuntimeError('interrupted')
                with self.assertRaises(RuntimeError):
                    with instance(stop).locked() as engine:
                        engine.commit({'/contexts': b'after'}, {})
                value = tx.Transaction._json((root / 'state/journal').read_bytes())
                stage = root / value['entries'][0]['stage']['name']
                stage.unlink()
                if substitute:
                    stage.write_bytes(b'after')
                    with self.assertRaises(tx.Conflict):
                        instance().resume()
                    self.assertEqual(stage.read_bytes(), b'after')
                    self.assertEqual(target.read_bytes(), b'before')
                else:
                    self.assertTrue(instance().resume())
                    self.assertEqual(target.read_bytes(), b'after')

    def test_multifile_all_plans_before_write(self):
        second = self.root / 'second'
        second.write_bytes(b'invalid source\n')
        engine = tx.Transaction(self.root / 'state', {'/contexts': self.target, '/second': second}, uid=os.geteuid())
        identities = {path: {'path': path, 'source_type': 'sshd_t', 'original_package': 'fixture-1'} for path in ('/contexts', '/second')}
        original = self.target.read_bytes()
        with self.assertRaises(tx.pure.ReconcileError):
            engine.reconcile(identities)
        self.assertEqual(self.target.read_bytes(), original)
        self.assertEqual((self.root / 'state/receipts').read_bytes(), b'{}')
        self.assertFalse((self.root / 'state/journal').exists())

    def test_partial_io_failure_retains_journal_and_recovers(self):
        second = self.root / 'second'
        second.write_bytes(b'before2')
        fired = []
        def stop(event):
            if event == 'target_directory_sync' and not fired:
                fired.append(event)
                raise OSError(28, 'injected ENOSPC')
        def instance(hook=None):
            return tx.Transaction(self.root / 'state', {'/contexts': self.target, '/second': second}, uid=os.geteuid(), hook=hook)
        with self.assertRaises(tx.Conflict):
            with instance(stop).locked() as engine:
                engine.commit({'/contexts': b'after1', '/second': b'after2'}, {})
        self.assertTrue((self.root / 'state/journal').exists())
        self.assertEqual(second.read_bytes(), b'before2')
        instance().resume()
        self.assertEqual(self.target.read_bytes(), b'after1')
        self.assertEqual(second.read_bytes(), b'after2')

    def test_receipt_only_adoption_preserves_context_inode(self):
        self.target.write_bytes(self.target.read_bytes() + b'system_r:qshd_t:s0 user_r:user_t:s0\n')
        inode = self.target.stat().st_ino
        identities = {'/contexts': {'path': '/contexts', 'source_type': 'sshd_t', 'original_package': 'fixture-1'}}
        self.assertTrue(self.engine().reconcile(identities))
        self.assertEqual(self.target.stat().st_ino, inode)
        self.assertTrue(self.engine().remove())
        self.assertEqual(self.target.stat().st_ino, inode)
        self.assertIn(b'qshd_t', self.target.read_bytes())

    def test_pending_metadata_drift_refuses_recovery(self):
        def stop(event):
            if event == 'stage_recorded':
                raise RuntimeError('interrupted')
        with self.assertRaises(RuntimeError):
            with self.engine(stop).locked() as engine:
                engine.commit({'/contexts': b'new'}, {})
        self.target.chmod(0o600)
        with self.assertRaises(tx.Conflict):
            self.engine().resume()
        self.assertNotEqual(self.target.read_bytes(), b'new')

    def test_status_does_not_initialize(self):
        with self.assertRaises(tx.Conflict):
            self.engine().status({})
        self.assertFalse((self.root / 'state').exists())

    def test_subprocess_lock_serialization(self):
        import subprocess
        import select
        with self.engine().locked():
            code = "import sys; sys.path.insert(0,sys.argv[1]); import qshd_selinux_transaction as t; import os; from pathlib import Path; print('ready',flush=True); e=t.Transaction(Path(sys.argv[2])/'state', {'/contexts':Path(sys.argv[2])/'contexts'},uid=os.geteuid());\nwith e.locked(): print('locked',flush=True)"
            process = subprocess.Popen([sys.executable, '-c', code, str(MODULES), str(self.root)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=dict(os.environ, HISTFILE='/dev/null', HOME=str(self.root), XDG_CONFIG_HOME=str(self.root), XDG_CACHE_HOME=str(self.root)))
            try:
                self.assertEqual(process.stdout.readline().strip(), 'ready')
                self.assertFalse(select.select([process.stdout], [], [], 0.15)[0])
            except BaseException:
                process.kill()
                process.communicate()
                raise
        stdout, stderr = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, stderr)
        self.assertEqual(stdout.strip(), 'locked')

    def test_production_factory_validates_explicit_registry_without_opening_paths(self):
        from unittest.mock import patch
        with patch.object(tx.os, 'geteuid', return_value=0):
            good = '/etc/selinux/targeted/contexts/users/staff_u'
            engine = tx.production([good])
            self.assertEqual(set(engine.targets), {good})
            for bad in ('/tmp/context', '/etc/selinux/targeted/contexts/users/../default_contexts', '/etc/selinux/targeted/contexts/users/nested/file'):
                with self.assertRaises(tx.Conflict):
                    tx.production([bad])
        with patch.object(tx.os, 'geteuid', return_value=1000):
            with self.assertRaises(tx.Conflict):
                tx.production([good])

    def test_rewritten_journal_interruptions(self):
        for event in ('journal_stage_sync', 'journal_rename', 'journal_directory_sync'):
            for occurrence in (2, 3):
                with self.subTest(event=event, occurrence=occurrence), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    target = root / 'context'
                    target.write_bytes(b'before')
                    identities = {'/contexts': {'path': '/contexts', 'source_type': 'sshd_t', 'original_package': 'fixture-1'}}
                    target.write_bytes(b'system_r:sshd_t:s0 user_r:user_t:s0\n')
                    count = []
                    def stop(actual):
                        if actual == event:
                            count.append(actual)
                            if len(count) == occurrence:
                                raise RuntimeError('interrupted')
                    def instance(hook=None):
                        return tx.Transaction(root / 'state', {'/contexts': target}, uid=os.geteuid(), hook=hook)
                    with self.assertRaises(RuntimeError):
                        instance(stop).reconcile(identities)
                    instance().resume()
                    self.assertTrue(instance().status(identities)['targets']['/contexts'])

    def test_parent_rebinding_and_symlinked_parent_refuse(self):
        nested = self.root / 'nested'
        nested.mkdir(mode=0o700)
        target = nested / 'context'
        target.write_bytes(b'before')
        engine = tx.Transaction(self.root / 'state', {'/contexts': target}, uid=os.geteuid())
        with engine.locked():
            nested.rename(self.root / 'old-nested')
            nested.mkdir(mode=0o700)
            (nested / 'context').write_bytes(b'before')
            with self.assertRaises(tx.Conflict):
                engine.snapshot('/contexts')
        (nested / 'context').unlink()
        nested.rmdir()
        nested.symlink_to(self.root / 'old-nested')
        with self.assertRaises(tx.Conflict):
            with engine.locked():
                pass

    def test_hardlinked_receipt_and_wrong_state_mode_refuse(self):
        with self.engine().locked():
            pass
        os.link(self.root / 'state/receipts', self.root / 'receipt-link')
        with self.assertRaises(tx.Conflict):
            with self.engine().locked():
                pass
        (self.root / 'receipt-link').unlink()
        (self.root / 'state').chmod(0o755)
        with self.assertRaises(tx.Conflict):
            with self.engine().locked():
                pass

    def test_cleanup_keeps_substituted_stage(self):
        replacement = []
        def substitute(event):
            if event == 'stage_file_sync':
                path = next(self.root.glob('.qshd-*'))
                path.rename(self.root / 'owned-old')
                path.write_bytes(b'administrator replacement')
                replacement.append(path)
                raise RuntimeError('interrupted')
        with self.engine(substitute).locked() as engine:
            snapshot = engine.snapshot('/contexts')
            with self.assertRaises(RuntimeError):
                engine.stage('/contexts', b'new', snapshot)
        self.assertEqual(replacement[0].read_bytes(), b'administrator replacement')

    def test_refused_directory_does_not_leak_descriptors(self):
        nested = self.root / 'writable'
        nested.mkdir(mode=0o777)
        nested.chmod(0o777)
        engine = tx.Transaction(self.root / 'state', {'/contexts': nested / 'context'}, uid=os.geteuid())
        count = len(list(Path('/proc/self/fd').iterdir()))
        for _ in range(5):
            with self.assertRaises(tx.Conflict):
                with engine.locked():
                    pass
        self.assertEqual(len(list(Path('/proc/self/fd').iterdir())), count)
