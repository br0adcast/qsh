"""Benchmark-harness accounting, ordering and isolation controls; no qsh binaries required."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/perf_baseline.py'
SPEC = importlib.util.spec_from_file_location('perf_baseline', SCRIPT)
perf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(perf)


def stat_line(pid, comm, ppid=1, utime=0, stime=0, threads=1, start=100):
    fields = ['S', str(ppid)] + ['0'] * 9 + [str(utime), str(stime), '0', '0', '0', '0', str(threads), '0',
                                              str(start)] + ['0'] * 30
    return f'{pid} ({comm}) ' + ' '.join(fields)


def sample(cpu_ticks, threads, start=100):
    return {'cpu_ticks': cpu_ticks, 'start_ticks': start, 'threads': threads, 'peak_rss_kib': 900,
            'rss_kib': 800}


def is_open(descriptor):
    try:
        os.fstat(descriptor)
        return True
    except OSError:
        return False


BIND_AND_SLEEP = ('import socket, sys, time; s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); '
                  's.bind(("127.0.0.1", int(sys.argv[1]))); time.sleep(30)')


class ProcAccountingTests(unittest.TestCase):
    def test_stat_command_names_may_contain_spaces_and_parentheses(self):
        stat = perf.parse_stat(stat_line(7, 'qsh) (x y', ppid=3, utime=12, stime=8, threads=4, start=55))
        self.assertEqual(stat, {'ppid': 3, 'cpu_ticks': 20, 'threads': 4, 'start_ticks': 55})

    def test_switches_and_schedstat(self):
        status = 'Name:\tqsh\nvoluntary_ctxt_switches:\t41\nnonvoluntary_ctxt_switches:\t2\n'
        self.assertEqual(perf.parse_switches(status), (41, 2))
        self.assertEqual(perf.status_fields('VmHWM:\t  2048 kB\nVmRSS:\t 1024 kB\n'), {'VmHWM': 2048, 'VmRSS': 1024})
        self.assertEqual(perf.parse_schedstat('1000 20 7\n'), (1000, 20, 7))

    def test_process_cpu_includes_exited_threads_while_thread_counters_do_not(self):
        before = sample(100, {'1': (0, 0, 10, 5, 1), '2': (0, 0, 10, 5, 1)})
        # Thread 2 exited and thread 3 appeared; process CPU still counts both.
        after = sample(100 + 2 * perf.CLOCK_TICKS, {'1': (2_000_000_000, 0, 30, 25, 3), '3': (0, 0, 1, 1, 0)})
        delta = perf.process_delta(before, after, 10)
        self.assertEqual(delta['cpu_s'], 2)
        self.assertEqual(delta['cpu_percent'], 20)
        self.assertEqual(delta['run_s_live_threads'], 2)
        self.assertEqual(delta['timeslices_per_s'], 2)
        self.assertEqual(delta['voluntary_switches_per_s'], 2)
        self.assertEqual(delta['involuntary_switches_per_s'], 0.2)
        self.assertEqual((delta['threads_exited'], delta['threads_created']), (1, 1))
        self.assertEqual((delta['peak_rss_kib'], delta['rss_kib']), (900, 800))

    def test_replaced_process_is_rejected(self):
        with self.assertRaises(perf.SetupError):
            perf.process_delta(sample(0, {}, start=1), sample(0, {}, start=2), 1)

    def test_live_sample_of_this_process(self):
        state = perf.sample_process(os.getpid())
        self.assertGreaterEqual(len(state['threads']), 1)
        self.assertGreater(state['start_ticks'], 0)
        self.assertGreater(state['peak_rss_kib'], 0)


class OrderingAndStatisticsTests(unittest.TestCase):
    def test_interleaved_order_alternates_which_build_runs_first(self):
        order = perf.schedule(['a', 'b'], ['idle', 'typing'], 3, 'interleaved', 1)
        self.assertEqual(order[:4], [(0, 'idle', 'a'), (0, 'idle', 'b'), (0, 'typing', 'a'), (0, 'typing', 'b')])
        self.assertEqual(order[4:6], [(1, 'idle', 'b'), (1, 'idle', 'a')])
        self.assertEqual(len(order), 12)

    def test_random_order_is_reproducible_and_complete(self):
        first = perf.schedule(['a', 'b'], ['idle', 'redraw'], 4, 'random', 7)
        self.assertEqual(first, perf.schedule(['a', 'b'], ['idle', 'redraw'], 4, 'random', 7))
        self.assertNotEqual(first, perf.schedule(['a', 'b'], ['idle', 'redraw'], 4, 'interleaved', 7))
        self.assertEqual(sorted(first), sorted(perf.schedule(['a', 'b'], ['idle', 'redraw'], 4, 'interleaved', 7)))

    def test_dispersion(self):
        self.assertEqual(perf.describe([4, 1, 3, 2, 5]),
                         {'n': 5, 'median': 3, 'p25': 2, 'p75': 4, 'min': 1, 'max': 5})
        self.assertEqual(perf.describe([2])['p75'], 2)
        self.assertIsNone(perf.describe([]))
        self.assertEqual(perf.percentile([10, 20, 30, 40], 0.5), 25)

    def test_summary_pairs_runs_by_repetition(self):
        manifest = {'builds': {'a': {}, 'b': {}}, 'workloads': ['idle']}
        runs = [{'ok': True, 'workload': 'idle', 'build': build, 'repetition': rep,
                 'result': {'window': {'qsh': {'cpu_percent': value}}}}
                for build, rep, value in [('a', 0, 2.0), ('b', 0, 1.0), ('a', 1, 4.0), ('b', 1, 5.0)]]
        runs.append({'ok': False, 'workload': 'idle', 'build': 'b', 'repetition': 2, 'error': 'x'})
        result = perf.summary(manifest, runs)
        row = next(r for r in result['rows'] if r['metric'] == 'window.qsh.cpu_percent')
        self.assertEqual(row['builds']['a']['median'], 3.0)
        self.assertEqual(row['comparison'], {'ratio_of_medians': 1.0, 'pairs': 2, 'pairs_second_lower': 1,
                                             'pairs_tied': 0})
        self.assertEqual(result['failed_runs'], [{'workload': 'idle', 'build': 'b', 'count': 1}])
        self.assertIn('| idle | window.qsh.cpu_percent | 3 (2.5-3.5, 2) | 3 (2-4, 2) | 1 | 1/2 (0) |',
                      perf.markdown(manifest, result))

    def test_build_specification(self):
        self.assertEqual(perf.build_spec('musl=/x/y'), ('musl', Path('/x/y')))
        for bad in ['musl', '=dir', 'a b=dir', 'name=']:
            with self.subTest(bad=bad), self.assertRaises(Exception):
                perf.build_spec(bad)

    def test_variant_specification(self):
        self.assertEqual(perf.variant_spec('one=main,cpus=0-1,3,threads=2'),
                         ('one', {'build': 'main', 'mode': 'personal', 'qshd_cpus': [0, 1, 3], 'runtime_threads': 2}))
        self.assertEqual(perf.variant_spec('plain=main'),
                         ('plain', {'build': 'main', 'mode': 'personal', 'qshd_cpus': None, 'runtime_threads': None}))
        self.assertEqual(perf.variant_spec('t=main,threads=1')[1]['runtime_threads'], 1)
        self.assertEqual(perf.variant_spec('s=main,system,cpus=0')[1],
                         {'build': 'main', 'mode': 'system', 'qshd_cpus': [0], 'runtime_threads': None})
        self.assertEqual(perf.cpu_text(perf.cpu_list('3,0-1')), '0,1,3')
        for bad in ['main', 'a=', 'a=main,threads=0', 'a=main,cpus=', 'a=main,cpus=x', 'a=main,other=1',
                    'a=main,threads=2,cpus=0', 'a=main,cpus=0,system']:
            with self.subTest(bad=bad), self.assertRaises(argparse.ArgumentTypeError):
                perf.variant_spec(bad)

    def test_summary_columns_are_variants_or_older_builds(self):
        runs = [{'ok': True, 'workload': 'idle', 'build': name, 'repetition': 0,
                 'result': {'window': {'qshd': {'cpu_percent': value}}}}
                for name, value in [('one', 1.0), ('two', 2.0), ('three', 4.0)]]
        manifest = {'builds': {'main': {}}, 'workloads': ['idle'],
                    'variants': {'one': {}, 'two': {}, 'three': {}}}
        row = perf.summary(manifest, runs)['rows'][0]
        self.assertEqual({name: stats['median'] for name, stats in row['builds'].items()},
                         {'one': 1.0, 'two': 2.0, 'three': 4.0})
        self.assertIn('| idle | window.qshd.cpu_percent | 1 (1-1, 1) | 2 (2-2, 1) | 4 (4-4, 1) |',
                      perf.markdown(manifest, perf.summary(manifest, runs)))
        older = {'builds': {'one': {}, 'two': {}}, 'workloads': ['idle']}
        self.assertEqual(perf.columns(older), ['one', 'two'])


class IdentityTests(unittest.TestCase):
    def elf(self, interpreter=None, comment=b''):
        """A minimal ELF64 file with an optional PT_INTERP and .comment."""
        header_size, phentsize, shentsize = 64, 56, 64
        interp = interpreter.encode() + b'\0' if interpreter else b''
        names = b'\0.shstrtab\0.comment\0'
        phnum = 1 if interp else 0
        data_offset = header_size + phnum * phentsize
        interp_offset = data_offset
        comment_offset = interp_offset + len(interp)
        names_offset = comment_offset + len(comment)
        shoff = names_offset + len(names)
        header = bytearray(b'\x7fELF\x02\x01\x01' + b'\0' * 9)
        header += struct.pack('<HHIQQQIHHHHHH', 2, 62, 1, 0, header_size if phnum else 0, shoff, 0,
                              header_size, phentsize, phnum, shentsize, 3, 1)
        program = struct.pack('<IIQQQQQQ', 3, 4, interp_offset, 0, 0, len(interp), len(interp), 1) if phnum else b''
        sections = struct.pack('<IIQQQQIIQQ', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        sections += struct.pack('<IIQQQQIIQQ', 1, 3, 0, 0, names_offset, len(names), 0, 0, 1, 0)
        sections += struct.pack('<IIQQQQIIQQ', 11, 1, 0, 0, comment_offset, len(comment), 0, 0, 1, 1)
        return bytes(header) + program + interp + comment + names + sections

    def identity(self, data):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'binary'
            path.write_bytes(data)
            return perf.elf_identity(path)

    def test_static_binary_with_toolchain_comment(self):
        identity = self.identity(self.elf(comment=b'rustc version 1.98.1\0GCC: (x) 1\0rustc version 1.98.1\0'))
        self.assertEqual(identity, {'elf': True, 'linkage': 'static', 'interpreter': None,
                                    'comment': ['GCC: (x) 1', 'rustc version 1.98.1']})

    def test_dynamic_binary_records_only_the_interpreter_name(self):
        identity = self.identity(self.elf('/lib64/ld-linux-x86-64.so.2'))
        self.assertEqual((identity['linkage'], identity['interpreter']), ('dynamic', 'ld-linux-x86-64.so.2'))

    def test_non_elf(self):
        self.assertEqual(self.identity(b'#!/bin/sh\n'), {'elf': False})

    def test_host_identity_has_no_host_name(self):
        identity = perf.host_identity()
        self.assertNotIn(os.uname().nodename, json.dumps(identity))


class IsolationTests(unittest.TestCase):
    def test_environment_inherits_only_path(self):
        saved = dict(os.environ)
        try:
            os.environ.update(SSH_AUTH_SOCK='/agent', DISPLAY=':0', ZDOTDIR='/mine', LD_PRELOAD='x.so',
                              PATH='/custom/bin')
            env = perf.minimal_environment('/private/home', {'TERM': 'dumb'})
        finally:
            os.environ.clear()
            os.environ.update(saved)
        for name in ['SSH_AUTH_SOCK', 'DISPLAY', 'ZDOTDIR', 'LD_PRELOAD']:
            self.assertNotIn(name, env)
        self.assertEqual(env['PATH'], '/custom/bin')
        self.assertEqual(env['HOME'], '/private/home')
        self.assertEqual(env['XDG_CONFIG_HOME'], '/private/home/.config')
        self.assertEqual((env['HISTFILE'], env['TERM']), ('/dev/null', 'dumb'))
        import pwd
        self.assertEqual(env['USER'], pwd.getpwuid(os.getuid()).pw_name)
        self.assertEqual(env['LOGNAME'], env['USER'])

    def test_private_home_has_empty_shell_startup_files(self):
        with tempfile.TemporaryDirectory() as directory:
            home = perf.private_home(Path(directory) / 'home')
            self.assertEqual(home.stat().st_mode & 0o777, 0o700)
            self.assertEqual((home / '.zshenv').read_text(), 'unsetopt GLOBAL_RCS\n')
            for name in ['.zshrc', '.bashrc', '.bash_profile', '.profile']:
                self.assertEqual((home / name).read_text(), '')

    def test_owned_descendants_are_killed_and_reaped(self):
        # A subreaper in a child process, so this test process is unaffected.
        code = textwrap.dedent('''
            import importlib.util, os, subprocess, sys, time
            spec = importlib.util.spec_from_file_location('perf_baseline', sys.argv[1])
            perf = importlib.util.module_from_spec(spec); spec.loader.exec_module(perf)
            perf.become_subreaper()
            # The intermediate exits at once; its sleeping child is orphaned.
            subprocess.run([sys.executable, '-c',
                'import subprocess, sys; p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"]);'
                ' print(p.pid, flush=True)'], check=True, stdout=open(sys.argv[2], 'w'))
            orphan = int(open(sys.argv[2]).read())
            time.sleep(0.2)
            assert any(pid == orphan for pid, _ in perf.children_of(os.getpid())), 'orphan was not adopted'
            print('leftovers', perf.reap_owned(time.monotonic() + 5), flush=True)
            try:
                os.kill(orphan, 0)
                print('alive')
            except ProcessLookupError:
                print('gone')
        ''')
        with tempfile.TemporaryDirectory() as directory:
            result = subprocess.run([sys.executable, '-I', '-c', code, str(SCRIPT), str(Path(directory) / 'pid')],
                                    capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.split(), ['leftovers', '[]', 'gone'])


    def test_termination_signal_runs_cleanup_and_stops_owned_sessions(self):
        code = textwrap.dedent('''
            import importlib.util, sys, tempfile, time
            from pathlib import Path
            spec = importlib.util.spec_from_file_location('perf_baseline', sys.argv[1])
            perf = importlib.util.module_from_spec(spec); spec.loader.exec_module(perf)
            perf.become_subreaper()
            perf.install_signal_handlers()
            scratch = tempfile.mkdtemp()
            daemon = perf.Daemon([sys.executable, '-c', 'import time; time.sleep(60)'], {}, Path(scratch) / 'log',
                                 scratch)
            print(daemon.pid, scratch, flush=True)
            try:
                time.sleep(30)
            except perf.Interrupted as name:
                print('interrupted', name, flush=True)
            finally:
                daemon.stop()
                print('stopped', daemon.status, flush=True)
        ''')
        process = subprocess.Popen([sys.executable, '-I', '-c', code, str(SCRIPT)], stdout=subprocess.PIPE, text=True)
        try:
            child, scratch = process.stdout.readline().split()
            process.send_signal(signal.SIGTERM)
            output = process.communicate(timeout=30)[0]
        finally:
            process.kill()
            process.wait()
        self.assertEqual(output.split(), ['interrupted', 'SIGTERM', 'stopped', str(-signal.SIGTERM)])
        with self.assertRaises(ProcessLookupError):
            os.kill(int(child), 0)
        self.assertFalse(issubclass(perf.Interrupted, Exception))
        import shutil
        shutil.rmtree(scratch, ignore_errors=True)


class RelayAndTerminalTests(unittest.TestCase):
    def test_relay_counts_each_direction_and_drops_during_a_cut(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0))
        server.settimeout(2)
        relay = perf.Relay(server.getsockname()[1])
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(2)
        try:
            start = time.monotonic()
            client.sendto(b'ping', ('127.0.0.1', relay.port))
            data, source = server.recvfrom(100)
            self.assertEqual(data, b'ping')
            self.assertGreaterEqual(relay.first_client_datagram_from(start, 2), start)
            server.sendto(b'pong!', source)
            self.assertEqual(client.recvfrom(100)[0], b'pong!')
            relay.set_cut(True)
            client.sendto(b'lost', ('127.0.0.1', relay.port))
            deadline = time.monotonic() + 2
            while relay.snapshot()['dropped_datagrams'] < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIsNone(relay.first_client_datagram_from(time.monotonic(), 0.1))
            self.assertEqual(relay.snapshot(), {'c2s_datagrams': 1, 'c2s_bytes': 4, 's2c_datagrams': 1,
                                                's2c_bytes': 5, 'dropped_datagrams': 1})
        finally:
            relay.close()
            client.close()
            server.close()

    def test_relay_keeps_each_client_apart_toward_the_daemon_and_back(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0))
        server.settimeout(2)
        relay = perf.Relay(server.getsockname()[1])
        clients = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(2)]
        try:
            sources = []
            for index, client in enumerate(clients):
                client.settimeout(2)
                client.sendto(b'from %d' % index, ('127.0.0.1', relay.port))
                data, source = server.recvfrom(100)
                self.assertEqual(data, b'from %d' % index)
                sources.append(source)
            self.assertNotEqual(sources[0], sources[1])
            # Replies in the opposite order still reach their own clients.
            for index in (1, 0):
                server.sendto(b'to %d' % index, sources[index])
            for index, client in enumerate(clients):
                self.assertEqual(client.recvfrom(100)[0], b'to %d' % index)
        finally:
            relay.close()
            for client in clients:
                client.close()
            server.close()

    def test_relay_returns_the_first_datagram_from_the_boundary_when_observed_late(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(('127.0.0.1', 0))
        server.settimeout(2)
        relay = perf.Relay(server.getsockname()[1])
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # Received before the boundary: never attributed, although a
            # count snapshot taken before it would have selected it.
            snapshot = relay.snapshot()['c2s_datagrams']
            client.sendto(b'earlier', ('127.0.0.1', relay.port))
            server.recvfrom(100)
            self.assertEqual(relay.snapshot()['c2s_datagrams'], snapshot + 1)
            boundary = time.monotonic()
            client.sendto(b'first', ('127.0.0.1', relay.port))
            server.recvfrom(100)
            between = time.monotonic()
            client.sendto(b'second', ('127.0.0.1', relay.port))
            server.recvfrom(100)
            # The observer looks only now, after both arrivals.
            time.sleep(0.1)
            observed = time.monotonic()
            arrival = relay.first_client_datagram_from(boundary, 2)
            self.assertGreaterEqual(arrival, boundary)
            self.assertLess(arrival, between)
            self.assertLess(arrival, observed - 0.09)
            second = relay.first_client_datagram_from(between, 2)
            self.assertGreaterEqual(second, between)
            self.assertLess(second, observed - 0.09)
            self.assertIsNone(relay.first_client_datagram_from(observed, 0.1))
        finally:
            relay.close()
            client.close()
            server.close()

    def test_terminal_counts_frames_split_across_reads_and_strips_escapes(self):
        terminal = perf.Terminal(80, 24)
        slave = terminal.slave
        writer = os.dup(slave)
        terminal.start()
        try:
            os.write(writer, b'\x1b[1;1Hab\x1b[?2')
            time.sleep(0.1)
            os.write(writer, b'5hq\x1b[?25l')
            terminal.wait_for(b'abq', 2)
            # Scanning restarts near the end; a marker in later output is found.
            os.write(writer, b'x' * 20000 + b'\x1b[2;1HMARK\x1b[0mER')
            terminal.wait_for(b'MARKER', 2, offset=0)
            self.assertEqual(terminal.counters()[1], 2)
            with self.assertRaises(perf.SetupError):
                terminal.wait_for(b'missing', 0.1)
        finally:
            os.close(writer)
            terminal.close()

    def test_echo_time_is_when_the_completing_read_arrived(self):
        terminal = perf.Terminal(80, 24)
        writer = os.dup(terminal.slave)
        terminal.start()
        try:
            os.write(writer, b'unrelated ')
            time.sleep(0.05)
            after_unrelated = time.monotonic()
            os.write(writer, b'NEE')
            time.sleep(0.05)
            after_prefix = time.monotonic()
            os.write(writer, b'\x1b[0mDLE')
            time.sleep(0.2)
            # The observer polls late; the recorded time is still the arrival.
            observed = time.monotonic()
            needle = terminal.wait_for(b'NEEDLE', 2)
            self.assertGreaterEqual(needle, after_prefix)
            self.assertLess(needle, observed - 0.15)
            # An earlier needle in the same output keeps its own, earlier read.
            self.assertLess(terminal.wait_for(b'unrelated', 2), after_unrelated)
            # The offset excludes output that was already there.
            offset = terminal.counters()[0]
            with self.assertRaises(perf.SetupError):
                terminal.wait_for(b'unrelated', 0.1, offset)
        finally:
            os.close(writer)
            terminal.close()

    def test_close_stops_a_blocked_reader_before_releasing_the_master(self):
        terminal = perf.Terminal(80, 24)
        # Another holder of the slave: the reader never sees end of file.
        writer = os.dup(terminal.slave)
        terminal.start()
        master = terminal.master
        reading_at_release = self.watch_release(terminal)
        try:
            os.write(writer, b'x')
            terminal.wait_for(b'x', 2)
            self.assertTrue(terminal.reading)
            self.assertTrue(terminal.close())
            self.assertEqual(reading_at_release, [False])
            self.assertFalse(is_open(master))
            self.assertTrue(terminal.close())
            self.assertEqual(reading_at_release, [False])
        finally:
            os.close(writer)
            self.stop_fixture_thread(terminal)

    def test_reader_that_does_not_give_custody_back_keeps_the_descriptors_open(self):
        terminal = perf.Terminal(80, 24)
        descriptors = [terminal.master, terminal.slave, terminal.wake_read, terminal.wake_write]
        # A reader that holds custody and never answers the wake-up.
        terminal.reading = True
        self.assertFalse(terminal.close(timeout=0.1))
        self.assertEqual([is_open(fd) for fd in descriptors], [True] * 4)
        with terminal.custody:
            terminal.reading = False
        self.assertTrue(terminal.close())
        self.assertEqual([is_open(fd) for fd in descriptors], [False] * 4)

    def watch_release(self, terminal):
        """Whether the reader held custody each time the descriptors were
        released. The contract is custody given back, not a finished thread:
        the thread may still be unwinding after it gave custody back."""
        seen = []
        release = terminal.release

        def watched():
            with terminal.custody:
                seen.append(terminal.reading)
            release()

        terminal.release = watched
        return seen

    def stop_fixture_thread(self, terminal):
        """Stop and join the reader thread, then release, whatever the test
        asserted."""
        if not terminal.released:
            os.write(terminal.wake_write, b'x')
        terminal.thread.join(5)
        self.assertFalse(terminal.thread.is_alive())
        self.assertTrue(terminal.close())

    def test_release_follows_custody_even_while_the_thread_is_still_unwinding(self):
        terminal = perf.Terminal(80, 24)
        writer = os.dup(terminal.slave)
        master = terminal.master
        drained, gate = threading.Event(), threading.Event()
        drain = terminal.drain

        def drain_then_pause():
            drain()
            drained.set()
            gate.wait(5)

        terminal.thread = threading.Thread(target=drain_then_pause, daemon=True)
        alive_at_release = []
        release = terminal.release
        terminal.release = lambda: (alive_at_release.append(terminal.thread.is_alive()), release())
        try:
            terminal.start()
            deadline = time.monotonic() + 5
            while not terminal.reading:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.001)
            # The reader gives custody back but its thread has not exited.
            os.write(terminal.wake_write, b'x')
            self.assertTrue(drained.wait(5))
            self.assertTrue(terminal.close(timeout=0.1))
            self.assertEqual(alive_at_release, [True])
            self.assertFalse(terminal.reading)
            self.assertFalse(is_open(master))
        finally:
            gate.set()
            os.close(writer)
            terminal.thread.join(5)
            self.assertFalse(terminal.thread.is_alive())
            self.assertTrue(terminal.close())

    def interrupted_start(self, terminal, entered):
        """Start the reader for real, then raise a termination signal before
        start() returns -- after the reader took custody when `entered`, while
        it has not run yet otherwise."""
        start = terminal.thread.start

        def start_then_interrupt():
            start()
            deadline = time.monotonic() + 5
            while entered and not terminal.reading:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.001)
            raise perf.Interrupted('SIGTERM')

        terminal.thread.start = start_then_interrupt
        with self.assertRaises(perf.Interrupted):
            terminal.start()

    def test_start_interrupted_before_the_reader_runs_never_lets_it_touch_the_descriptors(self):
        terminal = perf.Terminal(80, 24)
        gate = threading.Event()
        drain = terminal.drain
        terminal.thread = threading.Thread(target=lambda: (gate.wait(5), drain()), daemon=True)
        pumped = []
        terminal.pump = lambda: pumped.append(True)
        master = terminal.master
        self.interrupted_start(terminal, entered=False)
        self.assertTrue(terminal.close())
        self.assertFalse(is_open(master))
        # The reader runs only now, after the release, and finds close() begun.
        gate.set()
        terminal.thread.join(5)
        self.assertFalse(terminal.thread.is_alive())
        self.assertEqual(pumped, [])

    def test_start_interrupted_after_the_reader_took_custody_waits_for_it(self):
        terminal = perf.Terminal(80, 24)
        writer = os.dup(terminal.slave)
        master = terminal.master
        reading_at_release = self.watch_release(terminal)
        try:
            self.interrupted_start(terminal, entered=True)
            self.assertTrue(terminal.close())
            self.assertEqual(reading_at_release, [False])
            self.assertFalse(is_open(master))
        finally:
            os.close(writer)
            self.stop_fixture_thread(terminal)

    def test_terminal_setup_failure_closes_both_descriptors(self):
        opened = []
        real_openpty = os.openpty

        def openpty():
            opened.extend(real_openpty())
            return tuple(opened)

        with mock.patch.object(perf.os, 'openpty', openpty), \
                mock.patch.object(perf.fcntl, 'ioctl', side_effect=OSError('ioctl')):
            with self.assertRaises(OSError):
                perf.Terminal(80, 24)
        self.assertEqual(len(opened), 2)
        self.assertEqual([is_open(fd) for fd in opened], [False, False])

    def test_reader_start_failure_releases_every_descriptor(self):
        terminal = perf.Terminal(80, 24)
        descriptors = [terminal.master, terminal.slave, terminal.wake_read, terminal.wake_write]
        with mock.patch.object(terminal.thread, 'start', side_effect=RuntimeError('no thread')):
            with self.assertRaises(RuntimeError):
                terminal.start()
        self.assertTrue(terminal.close())
        self.assertEqual([is_open(fd) for fd in descriptors], [False] * 4)


class OwnershipTests(unittest.TestCase):
    def daemon(self, directory, code, *args):
        return perf.Daemon([sys.executable, '-I', '-c', code, *args], {}, Path(directory) / 'log', directory)

    def test_port_is_ready_only_when_held_by_the_owned_process(self):
        port = perf.free_udp_port()
        with tempfile.TemporaryDirectory() as directory:
            daemon = self.daemon(directory, BIND_AND_SLEEP, str(port))
            try:
                deadline = time.monotonic() + 10
                while not perf.holds_port(daemon, port):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
            finally:
                daemon.stop()

    def test_competing_bind_fails_closed(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as foreign, tempfile.TemporaryDirectory() as directory:
            foreign.bind(('127.0.0.1', 0))
            daemon = self.daemon(directory, 'import time; time.sleep(30)')
            try:
                with self.assertRaisesRegex(perf.SetupError, 'other than the owned qshd'):
                    perf.holds_port(daemon, foreign.getsockname()[1])
            finally:
                daemon.stop()

    def test_exited_owner_fails_even_when_the_port_is_bound_elsewhere(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as foreign, tempfile.TemporaryDirectory() as directory:
            foreign.bind(('127.0.0.1', 0))
            daemon = self.daemon(directory, 'raise SystemExit(3)')
            self.assertTrue(daemon.wait(10))
            with self.assertRaisesRegex(perf.SetupError, 'exited with 3'):
                perf.holds_port(daemon, foreign.getsockname()[1])

    def test_a_named_worker_may_hold_the_port_and_nothing_else_may(self):
        port = perf.free_udp_port()
        with tempfile.TemporaryDirectory() as directory:
            daemon = self.daemon(directory, 'import time; time.sleep(30)')
            worker = self.daemon(directory, BIND_AND_SLEEP, str(port))
            try:
                deadline = time.monotonic() + 10
                while not perf.udp_inodes(port):
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.02)
                self.assertTrue(perf.holds_port(daemon, port, [worker.pid]))
                with self.assertRaisesRegex(perf.SetupError, 'other than the owned qshd'):
                    perf.holds_port(daemon, port)
            finally:
                worker.stop()
                daemon.stop()

    def test_system_variants_need_root_on_a_disposable_host(self):
        with tempfile.TemporaryDirectory() as directory:
            build = Path(directory) / 'build'
            build.mkdir()
            for binary in ('qsh', 'qshd'):
                (build / binary).write_text('#!/bin/sh\n')
                (build / binary).chmod(0o700)
            args = argparse.Namespace(out=Path(directory) / 'out', build=[('main', build)],
                                      variant=[perf.variant_spec('s=main,system')], harness_cpus=None,
                                      system_account='bench', worker_user='nobody', workloads='idle')
            for euid, disposable in ((1000, '1'), (0, None)):
                environment = {} if disposable is None else {perf.DISPOSABLE_HOST_VAR: disposable}
                with self.subTest(euid=euid), mock.patch.object(perf.os, 'geteuid', return_value=euid), \
                        mock.patch.dict(os.environ, environment), \
                        self.assertRaisesRegex(SystemExit, 'only as root on a disposable host'):
                    if disposable is None:
                        os.environ.pop(perf.DISPOSABLE_HOST_VAR, None)
                    perf.command_run(args)
                (Path(directory) / 'out' / 'runs').rmdir()
                (Path(directory) / 'out').rmdir()

    def test_rig_owns_a_terminal_whose_client_never_started(self):
        rig = perf.Rig.__new__(perf.Rig)
        rig.build, rig.daemon, rig.relay, rig.port = Path('/nonexistent'), None, None, 1
        rig.root, rig.key, rig.terminals, rig.clients = None, Path('/nonexistent/key'), [], []
        rig.system, rig.worker = False, None
        rig.relay = argparse.Namespace(port=1, close=lambda: None)
        opened = []
        real_openpty = os.openpty

        def openpty():
            opened.extend(real_openpty())
            return tuple(opened)

        with tempfile.TemporaryDirectory() as directory:
            rig.root = Path(directory)
            with mock.patch.object(perf, 'holds_port', return_value=True), \
                    mock.patch.object(perf.os, 'openpty', openpty), \
                    mock.patch.object(perf.subprocess, 'Popen', side_effect=OSError('spawn')):
                with self.assertRaises(OSError):
                    rig.start_client('client')
            self.assertEqual(rig.clients, [])
            with mock.patch.object(perf, 'reap_owned', return_value=[]):
                self.assertEqual(rig.close(), [])
        self.assertEqual([is_open(fd) for fd in opened], [False, False])

    def test_version_is_read_on_an_owned_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'qsh'
            fake.write_text('#!/bin/sh\nif [ -t 0 ] && [ -t 1 ]; then echo "qsh 9.9.9 on a terminal"; '
                            'else echo "no terminal"; fi\n')
            fake.chmod(0o700)
            self.assertEqual(perf.version_of(fake), ['qsh 9.9.9 on a terminal'])
            fake.write_text('#!/bin/sh\necho "unknown option"\nexit 2\n')
            with self.assertRaisesRegex(perf.SetupError, r"exited with 2: \['unknown option'\]"):
                perf.version_of(fake)

    def test_version_fails_when_its_terminal_reader_does_not_stop(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = Path(directory) / 'qsh'
            fake.write_text('#!/bin/sh\necho "qsh 9.9.9"\n')
            fake.chmod(0o700)
            close = perf.Terminal.close
            kept = []

            def stuck(terminal, timeout=5):
                kept.append(terminal)
                return False

            with mock.patch.object(perf.Terminal, 'close', stuck):
                with self.assertRaisesRegex(perf.SetupError, 'did not stop'):
                    perf.version_of(fake)
            for terminal in kept:
                self.assertTrue(close(terminal))


class FakeTerminal:
    def __init__(self, echo):
        self.echo = echo
        self.total = 0

    def counters(self):
        return self.total, 0

    def write(self, data):
        self.total += len(data)

    def wait_for(self, needle, timeout, offset=0):
        # Only key echoes go missing; command markers still arrive.
        if not self.echo and len(needle) == 1:
            raise perf.SetupError(f'timed out waiting for {needle!r}')
        return time.monotonic()

    def text_since(self, offset):
        return b''


class FakeRelay:
    def __init__(self, datagrams):
        self.datagrams = datagrams

    def snapshot(self):
        return {'c2s_datagrams': 0, 'c2s_bytes': 0, 's2c_datagrams': 0, 's2c_bytes': 0, 'dropped_datagrams': 0}

    def first_client_datagram_from(self, boundary, timeout):
        return time.monotonic() if self.datagrams else None


class FakeRig:
    def __init__(self, echo=True, datagrams=True):
        self.client = argparse.Namespace(terminal=FakeTerminal(echo), rusage=None)
        self.relay = FakeRelay(datagrams)
        self.daemon = None
        self.daemon_facts = {'allowed_cpus': [0], 'runtime_workers': 1}
        self.clients = [self.client]

    def start_daemon(self):
        pass

    def start_client(self, name, options=()):
        return self.client

    def snapshot(self, client=None):
        time.sleep(0.001)
        return {'t': time.monotonic(), 'qshd': sample(0, {}), 'relay': self.relay.snapshot(), 'qsh': sample(0, {}),
                'terminal': (0, 0)}

    def close(self):
        return []


class TypingQualificationTests(unittest.TestCase):
    settings = argparse.Namespace(keystrokes=4, key_interval=0)

    def run_one(self, rig):
        with mock.patch.object(perf, 'SETTLE', 0), mock.patch.object(perf, 'Rig', lambda build, root: rig):
            return perf.run_one(None, 'typing', self.settings, None)

    def test_complete_typing_run_succeeds(self):
        record = self.run_one(FakeRig())
        self.assertTrue(record['ok'], record.get('error'))
        self.assertEqual((record['result']['missing_echoes'], record['result']['missing_datagrams']), (0, 0))
        self.assertEqual(len(record['result']['echo_ms']['samples']), 4)

    def test_absent_echoes_fail_the_run(self):
        record = self.run_one(FakeRig(echo=False))
        self.assertFalse(record['ok'])
        self.assertIn('0 of 4 echoes', record['error'])
        self.assertEqual(record['result']['missing_echoes'], 4)

    def test_absent_datagrams_fail_the_run(self):
        record = self.run_one(FakeRig(datagrams=False))
        self.assertFalse(record['ok'])
        self.assertIn('0 of 4 datagrams', record['error'])
        self.assertEqual(record['result']['missing_datagrams'], 4)

    def test_the_record_names_the_running_qshd(self):
        self.assertEqual(self.run_one(FakeRig())['qshd'], {'allowed_cpus': [0], 'runtime_workers': 1})

    def test_incomplete_runs_never_reach_a_summary(self):
        manifest = {'builds': {'a': {}}, 'workloads': ['typing']}
        record = self.run_one(FakeRig(echo=False))
        record.update(build='a', repetition=0)
        result = perf.summary(manifest, [record])
        self.assertEqual(result['rows'], [])
        self.assertEqual(result['failed_runs'], [{'workload': 'typing', 'build': 'a', 'count': 1}])


class BusyQualificationTests(unittest.TestCase):
    settings = argparse.Namespace(keystrokes=4, key_interval=0, busy_sessions=2, redraw_fps=1)

    def run_one(self, rig):
        with mock.patch.object(perf, 'SETTLE', 0), mock.patch.object(perf, 'Rig', lambda build, root: rig):
            return perf.run_one(None, 'busy', self.settings, None)

    def test_complete_busy_run_succeeds(self):
        record = self.run_one(FakeRig())
        self.assertTrue(record['ok'], record.get('error'))
        result = record['result']
        self.assertEqual((result['sessions'], result['missing_echoes'], len(result['echo_ms']['samples'])), (3, 0, 4))
        self.assertEqual(set(result['busy_overrun_s']), {'median', 'max'})
        self.assertIn('busy_terminal_bytes_per_s', result)

    def test_absent_echoes_fail_the_busy_run(self):
        record = self.run_one(FakeRig(echo=False))
        self.assertFalse(record['ok'])
        self.assertIn('0 of 4 echoes', record['error'])


FAKE_QSHD = """\
import os, socket, sys, time
args = sys.argv[1:]
port = int(args[args.index("--port") + 1])
threads = args[args.index("--runtime-threads") + 1] if "--runtime-threads" in args else "4"
reported = os.environ.get("FAKE_WORKERS", threads)
log = os.path.join(os.environ["XDG_CACHE_HOME"], "qsh", "qshd.log")
os.makedirs(os.path.dirname(log), exist_ok=True)
with open(log, "a") as out:
    out.write(f"INFO qshd: runtime workers {reported}\\n")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("127.0.0.1", port))
time.sleep(30)
"""


@unittest.skipUnless(sys.platform == 'linux' and perf.shutil.which('taskset'), 'needs Linux and taskset')
class VariantDaemonTests(unittest.TestCase):
    def rig(self, directory, cpus, threads):
        build = Path(directory) / 'build'
        build.mkdir()
        qshd = build / 'qshd'
        qshd.write_text(f'#!{sys.executable} -I\n' + FAKE_QSHD, encoding='utf-8')
        qshd.chmod(0o700)
        root = Path(directory) / 'run'
        root.mkdir()
        return perf.Rig({'directory': build, 'effective_qshd_cpus': cpus, 'runtime_threads': threads}, root)

    def start(self, rig):
        try:
            rig.start_daemon()
        finally:
            if rig.relay:
                rig.relay.close()
                rig.relay = None

    def test_qshd_runs_on_the_variant_cpus_with_the_requested_workers(self):
        cpu = min(os.sched_getaffinity(0))
        with tempfile.TemporaryDirectory() as directory:
            rig = self.rig(directory, [cpu], 2)
            try:
                self.start(rig)
                self.assertEqual(rig.daemon_facts, {'allowed_cpus': [cpu], 'runtime_workers': 2})
                self.assertEqual(os.sched_getaffinity(rig.daemon.pid), {cpu})
            finally:
                rig.daemon.stop()

    def test_a_different_worker_count_fails_the_run(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.dict(os.environ, {'FAKE_WORKERS': '3'}), \
                mock.patch.object(perf, 'PARENT_ENVIRONMENT', ('PATH', 'FAKE_WORKERS')):
            rig = self.rig(directory, None, 2)
            try:
                with self.assertRaisesRegex(perf.SetupError, 'reports 3 runtime workers, expected 2'):
                    self.start(rig)
            finally:
                rig.daemon.stop()

    def test_other_cpus_fail_the_run(self):
        with tempfile.TemporaryDirectory() as directory:
            rig = self.rig(directory, [min(os.sched_getaffinity(0))], None)
            real_read = perf.read

            def read(path):
                text = real_read(path)
                return text + 'Cpus_allowed_list:\t0-1\n' if path.endswith('/status') else text

            try:
                with mock.patch.object(perf, 'read', read), \
                        self.assertRaisesRegex(perf.SetupError, 'qshd runs on CPUs 0,1, expected'):
                    self.start(rig)
            finally:
                rig.daemon.stop()


if __name__ == '__main__':
    unittest.main()
