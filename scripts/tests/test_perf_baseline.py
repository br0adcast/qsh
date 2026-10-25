"""Benchmark-harness accounting, ordering and isolation controls; no qsh binaries required."""
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
import time
import unittest

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
            self.assertGreaterEqual(relay.next_client_datagram(0, 2), start)
            server.sendto(b'pong!', source)
            self.assertEqual(client.recvfrom(100)[0], b'pong!')
            relay.set_cut(True)
            client.sendto(b'lost', ('127.0.0.1', relay.port))
            deadline = time.monotonic() + 2
            while relay.snapshot()['dropped_datagrams'] < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertIsNone(relay.next_client_datagram(1, 0.1))
            self.assertEqual(relay.snapshot(), {'c2s_datagrams': 1, 'c2s_bytes': 4, 's2c_datagrams': 1,
                                                's2c_bytes': 5, 'dropped_datagrams': 1})
        finally:
            relay.close()
            client.close()
            server.close()

    def test_udp_bound(self):
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind(('127.0.0.1', 0))
            self.assertTrue(perf.udp_bound(sock.getsockname()[1]))

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


if __name__ == '__main__':
    unittest.main()
