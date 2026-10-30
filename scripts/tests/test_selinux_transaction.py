"""Disposable filesystem tests; no host policy or package operations."""
from contextlib import contextmanager
import errno
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

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

    def test_final_open_binding_failure_closes_read_descriptor(self):
        with self.engine().locked() as engine:
            before = set(os.listdir('/proc/self/fd'))
            original_bound = engine._bound
            read_fds = []
            count = 0
            def bound(parent, name, fd, *, state=False):
                nonlocal count
                count += 1
                if count == 2:
                    read_fds.append(fd)
                    raise tx.Conflict('INJECTED_FINAL_BINDING')
                return original_bound(parent, name, fd, state=state)
            try:
                with patch.object(engine, '_bound', side_effect=bound):
                    with self.assertRaisesRegex(tx.Conflict, '^INJECTED_FINAL_BINDING$'):
                        engine._open(engine.state_fd, 'receipts', state=True)
                self.assertEqual(count, 2)
                self.assertEqual(len(read_fds), 1)
                with self.assertRaises(OSError) as caught:
                    os.fstat(read_fds[0])
                self.assertEqual(caught.exception.errno, errno.EBADF)
                self.assertEqual(set(os.listdir('/proc/self/fd')), before)
            finally:
                # Keep the intentionally failing pre-fix run from leaking an FD.
                for fd in read_fds:
                    try: os.close(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF: raise

    def test_successful_open_transfers_read_descriptor_to_caller(self):
        with self.engine().locked() as engine:
            before = set(os.listdir('/proc/self/fd'))
            fd = engine._open(engine.state_fd, 'receipts', state=True)
            try:
                self.assertEqual(os.read(fd, 2), b'{}')
                self.assertEqual(set(os.listdir('/proc/self/fd')), before | {str(fd)})
            finally:
                os.close(fd)
            self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_open_mismatch_closes_each_descriptor_once(self):
        with self.engine().locked() as engine:
            original_identity = tx.identity
            original_open, original_close = os.open, os.close
            opened, closed = [], []
            count = 0
            def identity(info):
                nonlocal count
                count += 1
                return ['injected mismatch'] if count == 4 else original_identity(info)
            def tracked_open(*args, **kwargs):
                fd = original_open(*args, **kwargs); opened.append(fd); return fd
            def tracked_close(fd):
                closed.append(fd); original_close(fd)
            with patch.object(tx, 'identity', side_effect=identity), \
                 patch.object(tx.os, 'open', side_effect=tracked_open), \
                 patch.object(tx.os, 'close', side_effect=tracked_close):
                with self.assertRaisesRegex(tx.Conflict, '^OPEN_BINDING$'):
                    engine._open(engine.state_fd, 'receipts', state=True)
            self.assertEqual(len(opened), 2)
            self.assertCountEqual(closed, opened)
            self.assertEqual(len(closed), 2)

    def test_probe_close_error_does_not_transfer_or_leak_read_descriptor(self):
        with self.engine().locked() as engine:
            before = set(os.listdir('/proc/self/fd'))
            original_open, original_close = os.open, os.close
            opened, closed = [], []
            def tracked_open(*args, **kwargs):
                fd = original_open(*args, **kwargs); opened.append(fd); return fd
            def close_then_refuse(fd):
                closed.append(fd); original_close(fd)
                if fd == opened[0]:
                    raise OSError(errno.EIO, 'injected probe cleanup error')
            try:
                with patch.object(tx.os, 'open', side_effect=tracked_open), \
                     patch.object(tx.os, 'close', side_effect=close_then_refuse):
                    with self.assertRaises(OSError) as caught:
                        engine._open(engine.state_fd, 'receipts', state=True)
                self.assertEqual(caught.exception.errno, errno.EIO)
                self.assertEqual(len(opened), 2)
                self.assertCountEqual(closed, opened)
                self.assertEqual(len(closed), 2)
                self.assertEqual(set(os.listdir('/proc/self/fd')), before)
            finally:
                for fd in opened:
                    try: original_close(fd)
                    except OSError as error:
                        if error.errno != errno.EBADF: raise

    @contextmanager
    def mandatory_labels(self):
        """Model kernel labels on disposable files, without host SELinux calls."""
        original = {name: getattr(os, name) for name in
                    ('listxattr', 'getxattr', 'setxattr', 'removexattr')}
        label = 'security.selinux'
        backing = 'user.qsh-test-label'
        default = b'system_u:object_r:var_lib_t:s0\0'
        def names(fd):
            return [key for key in original['listxattr'](fd) if key != backing] + [label]
        def get(fd, key):
            if key == label:
                try:
                    return original['getxattr'](fd, backing)
                except OSError as error:
                    if error.errno != errno.ENODATA:
                        raise
                    return default
            return original['getxattr'](fd, key)
        def set_value(fd, key, value):
            if key == label:
                if value == get(fd, key):
                    raise PermissionError(errno.EACCES, 'mandatory label mutation')
                return original['setxattr'](fd, backing, value)
            return original['setxattr'](fd, key, value)
        def remove(fd, key):
            if key == label:
                raise PermissionError(errno.EACCES, 'mandatory label removal')
            return original['removexattr'](fd, key)
        with patch.multiple(tx.os, listxattr=names, getxattr=get,
                            setxattr=set_value, removexattr=remove):
            yield default

    def test_state_defaults_survive_publication_receipts_and_fresh_recovery(self):
        identities = {'/contexts': {'path': '/contexts', 'source_type': 'sshd_t', 'original_package': 'fixture-1'}}
        custom = b'system_u:object_r:custom_context_t:s0\0'
        os.setxattr(self.target, 'user.qsh-test-label', custom)
        def stop(event):
            if event == 'journal_directory_sync':
                raise RuntimeError('interrupted')
        with self.mandatory_labels() as default:
            with self.assertRaises(RuntimeError):
                self.engine(stop).reconcile(identities)
            journal = self.root / 'state/journal'
            os.setxattr(journal, 'user.qsh-state', b'trusted journal metadata')
            journal_labels = []
            def observe(event):
                if event == 'journal_directory_sync':
                    journal_labels.append((os.getxattr(journal, 'security.selinux'),
                                           os.getxattr(journal, 'user.qsh-state')))
            self.assertTrue(self.engine(observe).resume())
            self.assertTrue(journal_labels)
            self.assertTrue(all(item == (default, b'trusted journal metadata') for item in journal_labels))
            receipt = self.root / 'state/receipts'
            os.setxattr(receipt, 'user.qsh-state', b'trusted receipt metadata')
            self.assertTrue(self.engine().remove())
            self.assertEqual(os.getxattr(receipt, 'security.selinux'), default)
            self.assertEqual(os.getxattr(receipt, 'user.qsh-state'), b'trusted receipt metadata')
            self.assertEqual(os.getxattr(self.target, 'security.selinux'), custom)
            for name in ('lock', 'receipts'):
                self.assertEqual((self.root / 'state' / name).stat().st_mode & 0o7777, 0o600)

    def test_state_differing_label_is_applied_or_refused(self):
        custom = b'system_u:object_r:custom_state_t:s0\0'
        with self.mandatory_labels(), self.engine().locked() as engine:
            metadata = engine._read(engine.state_fd, 'receipts', state=True)
            metadata['xattrs']['security.selinux'] = tx.encode(custom)
            stage = engine._create(engine.state_fd, b'{}', metadata, state=True)
            self.assertEqual(stage['xattrs'], metadata['xattrs'])
            os.unlink(stage['name'], dir_fd=engine.state_fd)
            original = os.setxattr
            def refuse(fd, key, value):
                if key == 'security.selinux':
                    raise PermissionError(errno.EACCES, 'label update denied')
                return original(fd, key, value)
            with patch.object(tx.os, 'setxattr', side_effect=refuse):
                with self.assertRaises(PermissionError):
                    engine._create(engine.state_fd, b'{}', metadata, state=True)
            self.assertEqual(list((self.root / 'state').glob('.qshd-*')), [])

    def test_target_exact_metadata_still_refuses_mandatory_label_removal(self):
        with self.mandatory_labels(), self.engine().locked() as engine:
            snapshot = engine.snapshot('/contexts')
            del snapshot['xattrs']['security.selinux']
            with self.assertRaises(PermissionError):
                engine.stage('/contexts', b'new', snapshot)
            self.assertEqual(self.target.read_bytes(), snapshot['data'])
            self.assertEqual(list(self.root.glob('.qshd-*')), [])

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

    def test_same_content_stage_substitution_is_not_adopted(self):
        replacements = []
        def substitute(event):
            if event == 'stage_directory_sync' and not replacements:
                path = next(self.root.glob('.qshd-*'))
                other = self.root / 'replacement'
                other.write_bytes(path.read_bytes())
                other.chmod(0o640)
                other.replace(path)
                replacements.append(path)
        with self.engine(substitute).locked() as engine:
            snapshot = engine.snapshot('/contexts')
            with self.assertRaises(tx.Conflict):
                engine.stage('/contexts', b'new', snapshot)
        self.assertEqual(replacements[0].read_bytes(), b'new')

    def test_journal_rebinding_before_retire_is_preserved(self):
        def substitute(event):
            if event == 'before_journal_retire':
                path = self.root / 'state/journal'
                other = self.root / 'replacement'
                other.write_bytes(path.read_bytes())
                other.chmod(0o600)
                other.replace(path)
        with self.assertRaises(tx.Conflict):
            with self.engine(substitute).locked() as engine:
                engine.commit({'/contexts': b'new'}, {})
        self.assertTrue((self.root / 'state/journal').exists())
