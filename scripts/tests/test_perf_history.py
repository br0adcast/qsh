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


class HistoryOracleCorrection(unittest.TestCase):
    def simulation(self, final_first=1213, fail_phase=None):
        """Controlled runner trace only; no qsh/PTY/process is started."""
        import contextlib
        stack = contextlib.ExitStack()
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        rig = mock.Mock(server_home=root, daemon_facts={})
        rig.daemon = mock.Mock(rusage={'user_s': 0, 'system_s': 0})
        rig.daemon.tail.return_value = ''
        rig.close.return_value = []
        client = mock.Mock(rusage={'user_s': 0, 'system_s': 0})
        client.terminal.total = 0
        client.terminal.text_since.return_value = b''
        rig.clients = [client]
        rig.start_client.return_value = client
        rig.snapshot.side_effect = lambda _: {'t': 1.0}
        state = {'phase': None, 'live': False}
        chosen = {'offset': 39, 'total': 1966, 'rows': [1928, 1929]}
        initial = {'offset': 1966, 'total': 1966, 'rows': [1, 2]}
        capped = {'offset': 4000, 'total': 4000, 'rows': chosen['rows']}
        final = {'offset': 4000, 'total': 4000, 'rows': [final_first, final_first+1]}
        producer = mock.Mock()
        producer.send.side_effect = lambda phase: state.__setitem__('phase', phase)
        controller = mock.Mock()
        controller.__enter__ = mock.Mock(return_value=producer)
        controller.__exit__ = mock.Mock(return_value=False)
        snapshots = []
        rig.history_snapshots = snapshots
        def snapshot(_, expected_total=None, **requirements):
            snapshots.append((expected_total, requirements))
            if state['live']:
                return final
            if requirements.get('oldest'):
                return initial
            return capped if state['phase'] in ('cap', 'repaint') else chosen
        def marker(_, name):
            if name == b'HISTORY-FINAL-DONE':
                state['live'] = True
            return 2.0
        def checkpoint(_, phase):
            if phase == fail_phase:
                raise perf.SetupError('deliberate incomplete ' + phase)
        def sample_phase(*_, sample_sink=None):
            samples = [{'seconds': 0.0, 'rss_kib': 10}]
            if sample_sink is not None:
                sample_sink.extend(samples)
            if fail_phase == 'sample':
                raise perf.SetupError('deliberate incomplete sample')
            return samples, 10.0
        for name, value in [('HistoryControl', mock.Mock(return_value=controller)),
                            ('history_snapshot', mock.Mock(side_effect=snapshot)),
                            ('repaint_marker', mock.Mock(side_effect=marker)),
                            ('history_checkpoint', mock.Mock(side_effect=checkpoint)),
                            ('client_memory', mock.Mock(return_value={'rss_kib': 10})),
                            ('sample_history_phase', mock.Mock(side_effect=sample_phase)),
                            ('window', mock.Mock(return_value={'seconds': 10, 'relay': {'s2c_bytes': 1}}))]:
            stack.enter_context(mock.patch.object(perf, name, value))
        stack.enter_context(mock.patch.object(perf.time, 'sleep'))
        return stack, rig, controller

    def test_valid_observed_oldest_advance_does_not_require_producer_threshold(self):
        stack, rig, _ = self.simulation()
        with stack:
            result = perf.run_history(rig, type('Settings', (), {'window': 10, 'redraw_fps': 20})())
        self.assertEqual(result['history_observations']['initial_oldest']['rows'][0], 1)
        self.assertEqual(result['history_observations']['top_after_return']['rows'][0], 1213)
        calls = rig.history_snapshots
        self.assertEqual([entry[1].get('oldest', False) for entry in calls],
                         [False, True, False, False, False, True])
        self.assertEqual(calls[2][1]['expected_view'], result['history_observations']['selected'])
        self.assertEqual(calls[-1][0], 4000)
        writes = [call.args[0] for call in rig.clients[0].terminal.write.call_args_list]
        self.assertEqual(writes[2:4], [b'g', b'G\x1b[5~'])
        self.assertEqual(writes[-2:], [b'\x1d[g', b'q'])

    def test_no_oldest_advance_is_still_a_failure(self):
        stack, rig, _ = self.simulation(final_first=1)
        with stack, self.assertRaises(perf.Incomplete):
            perf.run_history(rig, type('Settings', (), {'window': 10, 'redraw_fps': 20})())

    def test_failure_retains_already_observed_phases_and_closes_control(self):
        stack, rig, controller = self.simulation(fail_phase='cap')
        with stack, mock.patch.object(perf, 'Rig', return_value=rig):
            result = perf.run_one(None, 'history', type('Settings', (), {'window': 10, 'redraw_fps': 20})(), Path('/unused'))
        self.assertFalse(result['ok'])
        self.assertIn('filled_live', result['result']['phases'])
        self.assertIn('initial_oldest', result['result']['history_observations'])
        rig.close.assert_called_once()
        controller.__exit__.assert_called_once()

    def test_failed_sampler_keeps_its_collected_samples(self):
        stack, rig, _ = self.simulation(fail_phase='sample')
        with stack, self.assertRaises(perf.Incomplete) as failure:
            perf.run_history(rig, type('Settings', (), {'window': 10, 'redraw_fps': 20})())
        self.assertEqual(failure.exception.result['memory_samples'][0]['rss_kib'], 10)

    def test_oldest_counterexamples_keep_cap_top_and_witness_strict(self):
        initial = {'offset': 1966, 'total': 1966, 'rows': [1, 2]}
        valid = {'offset': 4000, 'total': 4000, 'rows': [1213, 1214]}
        perf.require_oldest_advance(initial, valid)
        for invalid in [dict(valid, total=3999, offset=3999), dict(valid, offset=39),
                        dict(valid, rows=[1, 2]), dict(valid, rows=[0, 1]),
                        dict(valid, rows=[]), dict(valid, rows=[1214, 1213])]:
            with self.assertRaises(perf.SetupError):
                perf.require_oldest_advance(initial, invalid)
        with self.assertRaises(perf.SetupError):
            perf.require_oldest_advance(dict(initial, offset=39), valid)

    def test_navigation_requirements_wait_inside_bounded_repaint_observation(self):
        chosen = {'offset': 39, 'total': 1966, 'rows': [1928, 1929]}
        top = {'offset': 1966, 'total': 1966, 'rows': [1, 2]}
        for requirement, before, after in [({'oldest': True}, chosen, top),
                                           ({'expected_view': chosen}, top, chosen)]:
            client = mock.Mock(pid=123)
            client.wait.return_value = False
            client.terminal.counters.return_value = (0, 0)
            sent, clock = [], [0.0]
            def snapshot(_):
                view = after if len(sent) >= 2 else before
                data = (b'\x1b[2J' + b' '.join(f'HROW-{row:08d}'.encode() for row in view['rows'])
                        + f" scroll: {view['offset']}/{view['total']} ".encode() + b'\x1b[?25l')
                return 0, data, [(len(data), clock[0])]
            client.terminal.snapshot_since.side_effect = snapshot
            with mock.patch.object(perf.os, 'kill', side_effect=lambda *args: sent.append(args)), \
                 mock.patch.object(perf.fcntl, 'ioctl', return_value=perf.struct.pack('HHHH', 40, 120, 0, 0)), \
                 mock.patch.object(perf.time, 'monotonic', side_effect=lambda: clock[0]), \
                 mock.patch.object(perf.time, 'sleep', side_effect=lambda seconds: clock.__setitem__(0, clock[0]+seconds)), \
                 mock.patch.object(perf, 'SETUP_TIMEOUT', 2):
                observed = perf.history_snapshot(client, **requirement)
            self.assertEqual(observed, after)
            self.assertEqual(len(sent), 2)

    def test_actual_sampler_preserves_first_sample_when_next_read_fails(self):
        sink = []
        with mock.patch.object(perf.time, 'monotonic', return_value=0.0), \
             mock.patch.object(perf.time, 'sleep'), \
             mock.patch.object(perf, 'read_history_checkpoint', return_value='cap'), \
             mock.patch.object(perf, 'client_memory', side_effect=[{'rss_kib': 10}, perf.SetupError('sample failed')]):
            with self.assertRaises(perf.SetupError):
                perf.sample_history_phase(Path('/unused'), mock.Mock(), 10, sample_sink=sink)
        self.assertEqual(sink, [{'seconds': 0.0, 'rss_kib': 10}])

    def test_cleanup_failure_overrides_completed_history(self):
        stack, rig, _ = self.simulation()
        rig.close.return_value = ['deliberate cleanup failure']
        with stack, mock.patch.object(perf, 'Rig', return_value=rig):
            record = perf.run_one(None, 'history', type('Settings', (), {'window': 10, 'redraw_fps': 20})(), Path('/unused'))
        self.assertTrue(record['result']['history_complete'])
        self.assertFalse(record['ok'])
        self.assertIn('cleanup failure', record['error'])

    def test_rejected_navigation_candidates_are_recorded_before_requirement_failure(self):
        data = b'\x1b[2JHROW-00001928 HROW-00001929 scroll: 39/1966 \x1b[?25l'
        for requirements in [{'oldest': True}, {'expected_total': 4000},
                             {'expected_view': {'offset': 40, 'total': 1966, 'rows': [1928, 1929]}}]:
            observed = []
            def repaint(_, inspect):
                inspect(data)
            with mock.patch.object(perf, 'observe_full_repaint', side_effect=repaint):
                with self.assertRaises(perf.SetupError):
                    perf.history_snapshot(mock.Mock(), observed=observed.append, **requirements)
            self.assertEqual(observed[0]['offset'], 39)
            self.assertEqual(observed[0]['rows'], [1928, 1929])
