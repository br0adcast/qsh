"""Deterministic opt-in client-history qualification controls; no qsh required."""
import importlib.util
import os
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'perf_baseline.py'
spec = importlib.util.spec_from_file_location('perf_history', SCRIPT)
perf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(perf)


class HistoryParsers(unittest.TestCase):
    def test_defaults_are_unchanged_and_history_is_opt_in(self):
        self.assertEqual(perf.WORKLOADS, ('idle', 'typing', 'redraw', 'saturation', 'reconnect', 'retained', 'busy'))
        self.assertIn('history', perf.RUNNERS)

    def test_memory_names_have_explicit_lifetime_and_endpoint_meaning(self):
        text = 'Rss: 1234 kB\nPss: 1000 kB\nPrivate_Clean: 10 kB\nPrivate_Dirty: 20 kB\n'
        self.assertEqual(perf.parse_rollup(text), {'pss_kib': 1000, 'private_kib': 30})
        for invalid in ['Pss: -1 kB\n', 'Pss: x kB\n', 'Pss: 1 MB\n']:
            with self.assertRaises(perf.SetupError):
                perf.parse_rollup(invalid)

    def test_positive_history_snapshot_requires_status_and_old_row(self):
        full = b'\x1b[2J\x1b[1;1HHROW-00001950\x1b[40;1H scroll: 39/2002 \x1b[?25l'
        result = perf.parse_history_snapshot(full, expected_total=None)
        self.assertEqual((result['offset'], result['total']), (39, 2002))
        self.assertIn(1950, result['rows'])
        for invalid in [b'HROW-00001950', b'scroll: 0/2002 HROW-00001950', b'scroll: 39/2002']:
            with self.assertRaises(perf.SetupError):
                perf.parse_history_snapshot(invalid)
        with self.assertRaises(perf.SetupError):
            perf.parse_history_snapshot(full, expected_total=4000)

    def test_pinned_identity_is_positive_and_cap_uses_refreshed_snapshot(self):
        old = {'offset': 39, 'total': 2002, 'rows': [1950, 1951]}
        pinned = {'offset': 3999, 'total': 4000, 'rows': [1950, 1951]}
        perf.require_pinned(old, pinned)
        with self.assertRaises(perf.SetupError):
            perf.require_pinned(old, {**pinned, 'rows': [7950, 7951]})
        with self.assertRaises(perf.SetupError):
            perf.require_pinned(old, {**pinned, 'offset': 0})

    def test_control_is_owned_nonblocking_and_closes_on_failure(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'control'
            os.mkfifo(path, 0o600)
            with self.assertRaises(perf.SetupError):
                perf.HistoryControl(path, timeout=0)
            reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
            try:
                with perf.HistoryControl(path, timeout=1) as control:
                    descriptor = control.fd
                    control.send('partial')
                    self.assertEqual(os.read(reader, 64), b'partial\n')
                    with self.assertRaises(ValueError):
                        control.send('unbounded or unknown')
                with self.assertRaises(OSError):
                    os.fstat(descriptor)
            finally:
                os.close(reader)

    def test_snapshot_uses_only_latest_complete_full_repaint(self):
        first = b'\x1b[2JHROW-00001950 scroll: 39/2002 \x1b[?25l'
        second = b'\x1b[2JHROW-00004001 scroll: 4000/4000 \x1b[?25l'
        self.assertEqual(perf.parse_history_snapshot(first + second)['rows'], [4001])
        with self.assertRaises(perf.SetupError):
            perf.parse_history_snapshot(first + b'\x1b[2JHROW-00004001 scroll: 4000/4000')
        with self.assertRaises(perf.SetupError):
            perf.parse_history_snapshot(b'HROW-00001950 scroll: 39/2002 \x1b[?25l')


    def test_finite_producer_orders_phases_and_eof_releases_it(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'control'
            checkpoint = Path(root) / 'checkpoint'
            os.mkfifo(path, 0o600)
            process = subprocess.Popen([sys.executable, '-I', '-c', perf.HISTORY_SCRIPT,
                                        str(path), str(checkpoint), '2', '3', '2', '20'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with perf.HistoryControl(path) as control:
                    control.send('partial')
                    perf.history_checkpoint(checkpoint, 'partial')
                    control.send('cap')
                    perf.history_checkpoint(checkpoint, 'cap')
                    control.send('repaint')
                    perf.history_checkpoint(checkpoint, 'repaint')
                    control.send('finish')
                    perf.history_checkpoint(checkpoint, 'finish')
                output, error = process.communicate(timeout=2)
                self.assertEqual(process.returncode, 0, error)
                self.assertIn(b'HROW-00000001', output)
                self.assertIn(b'HROW-00000005', output)
                self.assertIn(b'HISTORY-FINAL-DONE', output)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=2)
            # Closing an owning controller on failure releases an otherwise
            # blocked producer; no extra command/remote input is required.
            process = subprocess.Popen([sys.executable, '-I', '-c', perf.HISTORY_SCRIPT,
                                        str(path), str(checkpoint), '2', '3', '2', '20'],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                with self.assertRaisesRegex(RuntimeError, 'deliberate'):
                    with perf.HistoryControl(path):
                        raise RuntimeError('deliberate fixture failure')
                process.communicate(timeout=2)
                self.assertEqual(process.returncode, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=2)

    def test_oversized_or_incomplete_checkpoint_fails_boundedly(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / 'checkpoint'
            path.write_bytes(b'x' * 33)
            with self.assertRaisesRegex(perf.SetupError, 'oversized'):
                perf.history_checkpoint(path, 'cap', timeout=1)
            path.write_bytes(b'cap')
            with self.assertRaisesRegex(perf.SetupError, 'incomplete'):
                perf.history_checkpoint(path, 'cap', timeout=0)

    def test_client_memory_rejects_exited_or_replaced_client(self):
        client = mock.Mock(pid=123)
        client.wait.return_value = True
        with self.assertRaises(perf.SetupError):
            perf.client_memory(client)
        client.wait.return_value = False
        with mock.patch.object(perf, 'sample_process', return_value={
                'rss_kib': 100, 'peak_rss_kib': 200, 'start_ticks': 7}), \
             mock.patch.object(perf, 'read', side_effect=[
                 'Pss: 90 kB\nPrivate_Clean: 3 kB\nPrivate_Dirty: 4 kB\n',
                 '(ignored) identity']), \
             mock.patch.object(perf, 'parse_stat', return_value={'start_ticks': 8}):
            with self.assertRaisesRegex(perf.SetupError, 'identity'):
                perf.client_memory(client)

    def test_producer_rejects_out_of_budget_parameters_before_open(self):
        for arguments in [('0', '3', '2', '20'), ('2', '6001', '2', '20'), ('2', '3', '201', '20')]:
            with mock.patch.object(sys, 'argv', ['history.py', '/not-opened', '/not-written', *arguments]), \
                 mock.patch.object(Path, 'open', side_effect=AssertionError('opened before bounds')):
                with self.assertRaisesRegex(SystemExit, 'bounds'):
                    exec(compile(perf.HISTORY_SCRIPT, 'owned_history_producer', 'exec'), {})

    def test_snapshot_positively_reprobes_until_client_has_ingested_cap(self):
        client = mock.Mock(pid=123)
        client.wait.return_value = False
        client.terminal.counters.return_value = (0, 0)
        sent = []
        clock = [0.0]
        def snapshot(_):
            total = 4000 if len(sent) >= 2 else 2002
            data = (b'\x1b[2JHROW-00001950 scroll: 39/' + str(total).encode()
                    + b' \x1b[?25l')
            return 0, data, [(len(data), clock[0])]
        client.terminal.snapshot_since.side_effect = snapshot
        with mock.patch.object(perf.os, 'kill', side_effect=lambda *args: sent.append(args)), \
             mock.patch.object(perf.fcntl, 'ioctl', return_value=perf.struct.pack('HHHH', 40, 120, 0, 0)), \
             mock.patch.object(perf.time, 'monotonic', side_effect=lambda: clock[0]), \
             mock.patch.object(perf.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0]+seconds)), \
             mock.patch.object(perf, 'SETUP_TIMEOUT', 2):
            observed = perf.history_snapshot(client, 4000)
        self.assertEqual(observed['total'], 4000)
        self.assertEqual(sent, [(123, signal) for signal in [perf.signal.SIGWINCH]*2])
        self.assertTrue(all(call.args == (0,) for call in client.wait.call_args_list))

    def test_history_failure_uses_existing_run_cleanup_and_is_not_a_success(self):
        rig = mock.Mock()
        rig.clients = []
        rig.daemon = None
        rig.daemon_facts = {}
        rig.close.return_value = []
        with mock.patch.object(perf, 'Rig', return_value=rig), \
             mock.patch.dict(perf.RUNNERS, {'history': mock.Mock(side_effect=perf.SetupError('missing positive history oracle'))}):
            record = perf.run_one(None, 'history', None, Path('/unused'))
        self.assertFalse(record['ok'])
        self.assertIn('missing positive history oracle', record['error'])
        rig.close.assert_called_once()

    def test_phase_sampling_includes_delayed_completion_and_rejects_truncation(self):
        client = mock.Mock()
        for complete_at, succeeds in [(12, True), (None, False)]:
            clock = [0.0]
            def checkpoint(_):
                return 'repaint' if complete_at is not None and clock[0] >= complete_at else 'cap'
            with mock.patch.object(perf, 'read_history_checkpoint', side_effect=checkpoint, create=True), \
                 mock.patch.object(perf, 'client_memory', return_value={'rss_kib': 10}), \
                 mock.patch.object(perf.time, 'monotonic', side_effect=lambda: clock[0]), \
                 mock.patch.object(perf.time, 'sleep', side_effect=lambda _: clock.__setitem__(0, clock[0]+1)):
                if succeeds:
                    samples, completed = perf.sample_history_phase(Path('/not-read'), client, 10)
                    self.assertGreaterEqual(completed, 12)
                    self.assertGreaterEqual(samples[-1]['seconds'], 11)
                else:
                    with self.assertRaisesRegex(perf.SetupError, 'incomplete'):
                        perf.sample_history_phase(Path('/not-read'), client, 10)

    def test_late_complete_checkpoint_cannot_beat_phase_budget(self):
        for moments in [(0, 31), (0, 29, 31)]:
            with mock.patch.object(perf.time, 'monotonic', side_effect=moments), \
                 mock.patch.object(perf, 'read_history_checkpoint', return_value='repaint'):
                with self.assertRaisesRegex(perf.SetupError, 'incomplete'):
                    perf.sample_history_phase(Path('/not-read'), mock.Mock(), 10)

    def test_marker_observation_uses_full_repaint_not_retained_prefix_bytes(self):
        # Captured pilot fragment: the H terminating CUP is not payload. The
        # physical leading H remains from HROW, so escape stripping sees ISTORY.
        fragment = b'\x1b[39;2HISTORY-PARTIAL-DONE\x1b[?25h'
        self.assertNotIn(b'HISTORY-PARTIAL-DONE', perf.ESCAPE.sub(b'', fragment))
        with self.assertRaises(perf.SetupError):
            perf.parse_repaint_marker(fragment, b'HISTORY-PARTIAL-DONE')
        full = b'\x1b[2J\x1b[39;1HHISTORY-PARTIAL-DONE\x1b[?25h'
        self.assertTrue(perf.parse_repaint_marker(full, b'HISTORY-PARTIAL-DONE'))
        with self.assertRaises(perf.SetupError):
            perf.parse_repaint_marker(full[:-6], b'HISTORY-PARTIAL-DONE')
        with self.assertRaises(perf.SetupError):
            perf.parse_repaint_marker(full, b'HISTORY-FINAL-DONE')

    def test_repaint_marker_uses_completing_read_timestamp(self):
        client = mock.Mock(pid=123)
        client.wait.return_value = False
        client.terminal.counters.return_value = (100, 0)
        data = b'\x1b[2JHISTORY-FINAL-DONE\x1b[?25h'
        client.terminal.snapshot_since.return_value = (
            100, data, [(100+len(data)-1, 1.0), (100+len(data), 1.5)])
        with mock.patch.object(perf.os, 'kill') as notify, \
             mock.patch.object(perf.fcntl, 'ioctl', return_value=perf.struct.pack('HHHH', 40, 120, 0, 0)):
            self.assertEqual(perf.repaint_marker(client, b'HISTORY-FINAL-DONE'), 1.5)
        notify.assert_called_once_with(123, perf.signal.SIGWINCH)
