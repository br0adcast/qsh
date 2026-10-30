"""Synthetic control fixtures, not Fedora runtime qualification."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import os
import sys

SOURCE = Path(__file__).resolve().parents[2] / 'packaging/selinux/stop_guard.py'

class GuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('stop_guard', SOURCE)
        cls.g = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.g)

    def snapshot(self, **changes):
        values = dict(Id='qshd.service', LoadState='loaded', ActiveState='inactive',
                      SubState='dead', MainPID='0', ControlPID='0', ControlGroup='',
                      Slice='system.slice', Job='')
        values.update(changes)
        return ''.join(f'{k}={v}\n' for k, v in values.items())

    def test_strict_stopped_snapshot(self):
        self.g.snapshot(self.snapshot())
        self.g.snapshot(self.snapshot(ActiveState='failed', SubState='failed'))
        self.g.snapshot(self.snapshot(LoadState='masked'))
        for changes in [dict(Job=x) for x in ['0', '1', ' ', '(0, /)']] + [
            dict(MainPID='1'), dict(ControlPID='1'), dict(MainPID='00'),
            dict(Id='other.service'), dict(Slice='other.slice'),
            dict(ControlGroup='/system.slice/../x'), dict(ActiveState='active'),
            dict(SubState='auto-restart'), dict(LoadState='not-found'),
            *[dict(ActiveState=x) for x in ('activating', 'deactivating', 'reloading', 'maintenance')],
            dict(LoadState='error'), dict(ControlGroup='/system.slice//qshd.service')]:
            with self.subTest(changes=changes), self.assertRaises(self.g.Refusal):
                self.g.snapshot(self.snapshot(**changes))
        for text in [self.snapshot().replace('Job=\n', ''), self.snapshot()+'Job=\n',
                     self.snapshot()+'Unknown=x\n', self.snapshot()[:-1]]:
            with self.assertRaises(self.g.Refusal):
                self.g.snapshot(text)

    def test_snapshot_requires_literal_lf_records(self):
        # Synthetic malformed records, not captured Fedora manager output.
        for control in map(chr, [*range(10), *range(11, 32), 127, 133, 8232, 8233]):
            text = self.snapshot().replace('\n', control, 1)
            with self.subTest(control=repr(control)), self.assertRaises(self.g.Refusal):
                self.g.snapshot(text)
        self.assertEqual(self.g.snapshot(self.snapshot())['Job'], '')

    def test_events_require_literal_lf_records(self):
        # Preserve the final LF so only internal record framing is malformed.
        for control in map(chr, [*range(10), *range(11, 32), 127, 133, 8232, 8233]):
            with self.subTest(control=repr(control)), self.assertRaises(self.g.Refusal):
                self.g.events('populated 0' + control + 'frozen 0\n')
        for text in ('populated 0\r\n', 'populated 0\n\n', 'populated 0'):
            with self.subTest(text=repr(text)), self.assertRaises(self.g.Refusal):
                self.g.events(text)

    def test_absence_is_explicit_not_phase_automatic(self):
        text = self.snapshot(LoadState='not-found', Slice='')
        self.g.snapshot(text, allow_absent=True)
        with self.assertRaises(self.g.Refusal):
            self.g.snapshot(text)

    def test_hierarchical_events(self):
        self.g.events('populated 0\nfrozen 0\n')
        for text in ['populated 1\n', 'populated 2\n', 'populated -1\n',
                     'populated x\n', 'frozen 0\n', 'populated 0\npopulated 0\n']:
            with self.assertRaises(self.g.Refusal):
                self.g.events(text)

    def test_two_observations_and_residue(self):
        class Evidence:
            def __init__(self): self.reads = 0
            def preflight(self): pass
            def empty(self): self.reads += 1
        fs = Evidence()
        records = iter([self.snapshot(), self.snapshot()])
        self.g.check(fs, lambda: next(records))
        self.assertEqual(fs.reads, 2)
        records = iter([self.snapshot(), self.snapshot(Job='9')])
        with self.assertRaises(self.g.Refusal): self.g.check(fs, lambda: next(records))

    def test_real_descriptor_traversal(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cg = root/'system.slice/qshd.service'
            cg.mkdir(parents=True)
            (cg/'cgroup.events').write_text('populated 0\n')
            (cg/'cgroup.procs').write_text('')
            fs = self.g.Cgroup(root, lambda fd: 7, 7)
            fs.empty()
            (cg/'cgroup.events').write_text('populated 1\n')
            with self.assertRaises(self.g.Refusal): fs.empty()
            (cg/'cgroup.events').unlink()
            (cg/'cgroup.events').symlink_to('/dev/null')
            with self.assertRaises(self.g.Refusal): fs.empty()
            (cg/'cgroup.events').unlink()
            (cg/'cgroup.procs').unlink()
            cg.rmdir()
            fs.empty()
            cg.symlink_to(root, target_is_directory=True)
            with self.assertRaises(self.g.Refusal): fs.empty()

    def test_io_failures_and_foreign_mount_are_not_absence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cg = root/'system.slice/qshd.service'
            cg.mkdir(parents=True)
            fs = self.g.Cgroup(root, lambda fd: 7, 7)
            with self.assertRaises(self.g.Refusal): fs.empty()  # missing events
            for number in (5, 13):
                original = os.open
                def opening(path, *args, **kwargs):
                    if path == 'cgroup.events': raise OSError(number, 'synthetic refusal')
                    return original(path, *args, **kwargs)
                with patch.object(self.g.os, 'open', side_effect=opening):
                    with self.assertRaises(self.g.Refusal): fs.empty()
            with self.assertRaises(self.g.Refusal):
                self.g.Cgroup(root, lambda fd: 8, 7).empty()

    def test_recreation_after_second_snapshot_refuses(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root/'system.slice').mkdir()
            fs = self.g.Cgroup(root, lambda fd: 7, 7)
            class Evidence:
                def preflight(self): pass
                def empty(self): fs.empty()
            calls = 0
            def runner():
                nonlocal calls
                calls += 1
                if calls == 2:
                    cg = root/'system.slice/qshd.service'
                    cg.mkdir()
                    (cg/'cgroup.events').write_text('populated 1\n')
                return self.snapshot()
            with self.assertRaises(self.g.Refusal): self.g.check(Evidence(), runner)
            self.assertEqual(calls, 2)

    def test_mount_parser_refuses_foreign_layout(self):
        good = '7 1 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n'
        self.assertEqual(self.g.mount(good), 7)
        for text in [good+good, good.replace('cgroup2', 'cgroup'),
                     good.replace(' / /sys', ' /delegated /sys'),
                     good+'8 7 0:2 / /sys/fs/cgroup/system.slice rw - tmpfs tmpfs rw\n']:
            with self.assertRaises(self.g.Refusal): self.g.mount(text)

    def test_mount_records_reject_noncanonical_controls(self):
        good = '7 1 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n'
        for control in ('\v', '\f', '\x1c', '\x1d', '\x1e', '\r', '\x7f'):
            with self.subTest(control=repr(control)), self.assertRaises(self.g.Refusal):
                self.g.mount(good[:-1] + control + '\n')

    def test_mount_identity_requires_literal_lf_records(self):
        for control in ('\v', '\f', '\x1c', '\x1d', '\x1e', '\r', '\x7f'):
            with self.subTest(control=repr(control)), \
                 patch.object(self.g, 'read', return_value='pos:\t0' + control + 'mnt_id:\t7\n'), \
                 self.assertRaises(self.g.Refusal):
                self.g.mount_id(99)
        with patch.object(self.g, 'read', return_value='pos:\t0\nmnt_id:\t7\n'):
            self.assertEqual(self.g.mount_id(99), 7)

class RunnerTests(unittest.TestCase):
    setUpClass = GuardTests.__dict__['setUpClass']
    def test_bounded_read_only_runner(self):
        command = [sys.executable, '-c', 'import os; print(os.environ.get("DBUS_SYSTEM_BUS_ADDRESS", "cleared"))']
        with patch.dict(os.environ, {'DBUS_SYSTEM_BUS_ADDRESS': 'untrusted', 'SYSTEMD_HOST': 'remote'}):
            self.assertEqual(self.g.run_command(command), 'cleared\n')
        for program in ['import sys; sys.exit(1)', 'import sys; print("error", file=sys.stderr)',
                        'print("x"*20000)', 'import time; time.sleep(2)']:
            with self.subTest(program=program), self.assertRaises(self.g.Refusal):
                self.g.run_command([sys.executable, '-c', program], timeout=0.1)
        self.assertEqual(self.g.COMMAND[:5], ('/usr/bin/systemctl', '--system', '--no-pager', 'show', 'qshd.service'))

    def test_preflight_refuses_foreign_identity_without_manager_query(self):
        values = {'/usr/lib/os-release': 'ID=fedora\nVERSION_ID=44\n',
                  '/proc/self/mountinfo': '7 1 0:1 / /sys/fs/cgroup rw - cgroup2 cgroup rw\n'}
        def read(path): return values[path]
        def stat(path): return 2 if 'self/ns/mnt' in path else 1
        with patch.object(self.g, 'read', side_effect=read), \
             patch.object(self.g.os, 'geteuid', return_value=0), \
             patch.object(self.g.os, 'readlink', return_value='/usr/lib/systemd/systemd'), \
             patch.object(self.g.os, 'stat', side_effect=stat), \
             patch.object(self.g.Path, 'is_dir', return_value=True), \
             patch.object(self.g.Path, 'exists', return_value=False), \
             patch.object(self.g, 'run_command', side_effect=AssertionError('no manager command')):
            with self.assertRaisesRegex(self.g.Refusal, 'namespace'):
                self.g.Host().preflight()
            with patch.object(self.g.os, 'stat', return_value=1):
                self.g.Host().preflight()
            values['/usr/lib/os-release'] = 'ID=other\nVERSION_ID=44\n'
            with self.assertRaisesRegex(self.g.Refusal, 'Fedora'):
                self.g.Host().preflight()

if __name__ == '__main__': unittest.main()
