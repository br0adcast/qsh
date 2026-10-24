"""Build orchestration tests; all input and cache state belongs to each test."""
import json
import os
import signal
import sys
import time
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/build-openssl.sh'


def bounded_diagnostic(output, fixture):
    if isinstance(output, bytes):
        output = output.decode('utf-8', errors='replace')
    output = (output or '').replace(str(fixture), '<fixture>')
    output = output.replace(str(ROOT), '<checkout>')
    output = ''.join(c if c in '\n\t' or c.isprintable() else '?' for c in output)
    return output[-4096:]


def run_owned_build(command, env, fixture, timeout=20):
    """The result deadline fails the test; cleanup keeps its process owner."""
    child = subprocess.Popen(command, env=env, text=True,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = child.communicate(timeout=timeout)
    except BaseException as failure:
        # The builder owns separately sessioned commands. Killing its process
        # group cannot replace its SIGTERM handler and command/staging cleanup.
        try:
            print('Native fixture cancelled; graceful cleanup pending.', file=sys.stderr)
            if isinstance(failure, subprocess.TimeoutExpired):
                for label, output in [('stdout', failure.stdout), ('stderr', failure.stderr)]:
                    print(label + ' tail: ' + bounded_diagnostic(output, fixture), file=sys.stderr)
                from native_timeout_diagnostics import timeout_snapshot
                snapshot = timeout_snapshot(child.pid, command, env, fixture, ROOT)
                for label, value in snapshot.items():
                    print('Native fixture timeout ' + label + ': ' +
                          bounded_diagnostic(json.dumps(value), fixture), file=sys.stderr)
        except BaseException:
            # A broken diagnostic sink or second interrupt cannot drop custody
            # or replace the original deadline/interruption failure.
            pass
        finally:
            while child.returncode is None:
                try:
                    child.terminate()
                    break
                except ProcessLookupError:
                    break
                except (KeyboardInterrupt, InterruptedError):
                    continue
            while True:
                try:
                    stdout, stderr = child.communicate()
                    break
                except (KeyboardInterrupt, InterruptedError):
                    # Do not unwind TemporaryDirectory cleanup while this child
                    # still owns native commands, staging or the cache lock.
                    continue
        if isinstance(failure, subprocess.TimeoutExpired):
            raise subprocess.TimeoutExpired(
                [bounded_diagnostic(str(arg), fixture) for arg in command], timeout,
                output=bounded_diagnostic(stdout, fixture),
                stderr=bounded_diagnostic(stderr, fixture)) from None
        raise
    return subprocess.CompletedProcess(command, child.returncode, stdout, stderr)


def reap_owned_children(force):
    """Only for a dedicated Linux regression subprocess with one waiter."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if force:
            children = Path('/proc/self/task/' + str(os.getpid()) + '/children')
            for pid in children.read_text().split():
                # These are direct/adopted, unreaped children of this owner.
                # Signal before wait; no unrelated or reused PID is eligible.
                try:
                    os.kill(int(pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass
        try:
            pid, _ = os.waitpid(-1, os.WNOHANG)
        except ChildProcessError:
            return True
        if pid == 0:
            time.sleep(0.01)
    return False


@unittest.skipUnless(sys.platform == 'linux', 'owned process diagnostics use Linux procfs')
class TimeoutDiagnosticTests(unittest.TestCase):
    def test_snapshot_excludes_arguments_environment_and_unrelated_processes(self):
        from native_timeout_diagnostics import timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            code = 'import time; time.sleep(60)'
            child = subprocess.Popen([sys.executable, '-c', code, 'PRIVATE_ARG'],
                                     env=dict(os.environ, PRIVATE_ENV='PRIVATE_VALUE'))
            unrelated = subprocess.Popen([sys.executable, '-c', code])
            try:
                report = timeout_snapshot(child.pid, [], {}, root, ROOT)
                text = json.dumps(report)
                self.assertEqual([p['pid'] for p in report['processes']], [child.pid])
                self.assertNotIn(unrelated.pid, [p['pid'] for p in report['processes']])
                for private in ['PRIVATE_ARG', 'PRIVATE_ENV', 'PRIVATE_VALUE', code]:
                    self.assertNotIn(private, text)
                self.assertIn('executable', report['processes'][0])
                self.assertIn('state', report['processes'][0])
            finally:
                child.terminate()
                unrelated.terminate()
                child.wait()
                unrelated.wait()

    def test_tool_resolution_records_owned_alias_without_dumping_environment(self):
        from native_timeout_diagnostics import timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            tool = root / 'owned-ar'
            tool.write_text('#!/bin/sh\nexit 93\n')
            tool.chmod(0o755)
            alias = root / 'ar'
            alias.symlink_to(tool)
            report = timeout_snapshot(os.getpid(), ['--ar', str(alias)],
                                      {'PATH': str(root), 'PRIVATE_ENV': 'PRIVATE_VALUE'}, root, ROOT)
            selected = report['tools']['selected_ar']
            self.assertEqual(selected['path'], '<fixture>/ar')
            self.assertEqual(selected['resolved'], '<fixture>/owned-ar')
            self.assertEqual(report['tools']['path_ar']['resolved'], selected['resolved'])
            self.assertNotIn('PRIVATE_VALUE', json.dumps(report))

    def test_default_musl_compiler_identity_matches_the_builder(self):
        from native_timeout_diagnostics import timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            compiler = root / 'musl-gcc'
            compiler.write_text('#!/bin/sh\nexit 0\n')
            compiler.chmod(0o755)
            report = timeout_snapshot(os.getpid(), ['--target', 'x86_64-unknown-linux-musl'],
                                      {'PATH': str(root)}, root, ROOT)
            self.assertEqual(report['tools']['selected_cc']['path'], '<fixture>/musl-gcc')

    def test_missing_root_is_explicit_and_never_scans_other_processes(self):
        from native_timeout_diagnostics import timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            report = timeout_snapshot(123, [], {}, root, ROOT, proc=root)
            self.assertEqual(report['processes'], [])
            self.assertIn('unavailable', report['process_status'])


    @staticmethod
    def fake_process(proc, pid, parent, children=(), started=1):
        directory = proc / str(pid)
        directory.mkdir(parents=True, exist_ok=True)
        fields = ['0'] * 20
        fields[0], fields[1], fields[2], fields[3] = 'S', str(parent), str(pid), str(pid)
        fields[19] = str(started)
        (directory / 'stat').write_text(str(pid) + ' (ar) ' + ' '.join(fields))
        (directory / 'wchan').write_text('pipe_read')
        if not (directory / 'exe').is_symlink():
            (directory / 'exe').symlink_to('/usr/bin/ar')
        task = directory / 'task' / str(pid)
        task.mkdir(parents=True, exist_ok=True)
        (task / 'children').write_text(' '.join(map(str, children)))

    def test_descendants_are_bounded_and_parent_mismatch_is_omitted(self):
        from native_timeout_diagnostics import MAX_PROCESSES, timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_process(root, 100, 1, range(101, 121))
            self.fake_process(root, 101, 999)
            for pid in range(102, 121):
                self.fake_process(root, pid, 100)
            report = timeout_snapshot(100, [], {}, root, ROOT, proc=root)
            self.assertEqual(len(report['processes']), MAX_PROCESSES)
            self.assertNotIn(101, [p['pid'] for p in report['processes']])
            self.assertIn('limit', report['process_status'])
            self.assertTrue(all(p['executable'] == '/usr/bin/ar' for p in report['processes']))

    def test_changed_ancestor_identity_omits_its_descendants(self):
        import native_timeout_diagnostics as diagnostic
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_process(root, 100, 1, [101])
            self.fake_process(root, 101, 100)
            readlink = os.readlink
            def changed(path):
                if Path(path) == root / '101/exe':
                    self.fake_process(root, 100, 1, [101], started=2)
                return readlink(path)
            with patch.object(diagnostic.os, 'readlink', side_effect=changed):
                report = diagnostic.timeout_snapshot(100, [], {}, root, ROOT, proc=root)
            self.assertEqual([p['pid'] for p in report['processes']], [100])

    def test_exited_owned_root_remains_visible_when_executable_is_unavailable(self):
        from native_timeout_diagnostics import timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_process(root, 100, 1)
            stat = root / '100/stat'
            stat.write_text(stat.read_text().replace('(ar) S', '(ar) Z'))
            (root / '100/exe').unlink()
            report = timeout_snapshot(100, [], {}, root, ROOT, proc=root)
            self.assertEqual(report['processes'][0]['state'], 'Z')
            self.assertEqual(report['processes'][0]['executable'], 'unavailable')

    def fake_syscall(self, root, number=0, arguments=None, machine=62, elf_class=2):
        self.fake_process(root, 100, 1)
        executable = root / 'fixture-elf'
        executable.write_bytes(b'\x7fELF' + bytes([elf_class, 1, 1]) + bytes(11) + machine.to_bytes(2, 'little'))
        (root / '100/exe').unlink()
        (root / '100/exe').symlink_to(executable)
        arguments = arguments or ['0x3', '0xfeed', '0x10', '0', '0', '0']
        (root / '100/syscall').write_text(str(number) + ' ' + ' '.join(arguments) + ' 0xdead 0xbeef')
        (root / '100/fd').mkdir()
        (root / '100/fdinfo').mkdir()
        target = root / 'object.o'
        target.write_text('PRIVATE_BUFFER_CONTENT')
        (root / '100/fd/3').symlink_to(target)
        (root / '100/fd/4').symlink_to(root / 'UNRELATED_FD_PATH')
        (root / '100/fdinfo/3').write_text('pos: 42\nflags: 0100000\nmnt_id: 9\nino: 17\nsecret: PRIVATE_FDINFO\n')

    def test_syscall_descriptor_metadata_does_not_read_buffers_or_other_fds(self):
        from native_timeout_diagnostics import timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_syscall(root)
            report = timeout_snapshot(100, [], {}, root, ROOT, proc=root)
            call = report['processes'][0]['syscall']
            self.assertEqual((call['number'], call['name'], call['abi']), (0, 'read', 'Linux x86_64 ELF64'))
            self.assertEqual(call['descriptor']['number'], 3)
            self.assertEqual(call['descriptor']['target'], '<fixture>/object.o')
            self.assertEqual(call['descriptor']['metadata'], {'pos': 42, 'flags': 32768, 'mnt_id': 9, 'ino': 17})
            encoded = json.dumps(report)
            for private in ['PRIVATE_BUFFER_CONTENT', 'PRIVATE_FDINFO', 'UNRELATED_FD_PATH', 'feed', 'dead', 'beef']:
                self.assertNotIn(private, encoded)

    def test_mmap_uses_its_fd_argument_and_unsupported_abi_is_not_guessed(self):
        from native_timeout_diagnostics import timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_syscall(root, 9, ['0', '0x1000', '1', '2', '3', '0'])
            call = timeout_snapshot(100, [], {}, root, ROOT, proc=root)['processes'][0]['syscall']
            self.assertEqual((call['name'], call['descriptor']['number']), ('mmap', 3))
            self.assertEqual(call['descriptor']['target'], '<fixture>/object.o')
            executable = root / 'fixture-elf'
            executable.write_bytes(b'\x7fELF' + bytes([1, 1, 1]) + bytes(11) + (3).to_bytes(2, 'little'))
            call = timeout_snapshot(100, [], {}, root, ROOT, proc=root)['processes'][0]['syscall']
            self.assertEqual(call['number'], 9)
            self.assertEqual(call['status'], 'unsupported or unavailable executable ABI; fd not decoded')
            self.assertNotIn('descriptor', call)
            executable.unlink()
            call = timeout_snapshot(100, [], {}, root, ROOT, proc=root)['processes'][0]['syscall']
            self.assertEqual(call['number'], 9)
            self.assertNotIn('descriptor', call)

    def test_anonymous_mmap_does_not_sample_a_positive_ignored_descriptor(self):
        import native_timeout_diagnostics as diagnostic
        from unittest.mock import patch
        for flags in ['0x22', '290']:
            with self.subTest(flags=flags), tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
                root = Path(temp)
                self.fake_syscall(root, 9, ['0', '0x1000', '1', flags, '3', '0'])
                with patch.object(diagnostic, '_fd_metadata', wraps=diagnostic._fd_metadata) as sample:
                    call = diagnostic.timeout_snapshot(100, [], {}, root, ROOT, proc=root)['processes'][0]['syscall']
                sample.assert_not_called()
                self.assertEqual((call['number'], call['name']), (9, 'mmap'))
                self.assertNotIn('descriptor', call)
                self.assertNotIn('object.o', json.dumps(call))

    def test_openat_does_not_sample_a_potentially_ignored_directory_descriptor(self):
        import native_timeout_diagnostics as diagnostic
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_syscall(root, 257, ['3', '0xfeed', '0', '0', '0', '0'])
            with patch.object(diagnostic, '_fd_metadata', wraps=diagnostic._fd_metadata) as sample:
                call = diagnostic.timeout_snapshot(100, [], {}, root, ROOT, proc=root)['processes'][0]['syscall']
            sample.assert_not_called()
            self.assertEqual(call['number'], 257)
            self.assertNotIn('descriptor', call)
            self.assertNotIn('object.o', json.dumps(call))

    def test_running_outside_syscall_and_unknown_numbers_never_dump_registers(self):
        from native_timeout_diagnostics import timeout_snapshot
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_syscall(root)
            for value in ['running', '-1 0xfeed 0xdead', '9999 3 0xfeed 0 0 0 0 0xdead 0xbeef']:
                (root / '100/syscall').write_text(value)
                call = timeout_snapshot(100, [], {}, root, ROOT, proc=root)['processes'][0]['syscall']
                self.assertNotIn('descriptor', call)
                for address in ['feed', 'dead', 'beef']:
                    self.assertNotIn(address, json.dumps(call))

    def test_syscall_change_discards_sampled_descriptor_path(self):
        import native_timeout_diagnostics as diagnostic
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_syscall(root)
            read = diagnostic._read
            def changed(path, limit=4096):
                result = read(path, limit)
                if path == root / '100/fdinfo/3':
                    (root / '100/syscall').write_text('running')
                return result
            with patch.object(diagnostic, '_read', side_effect=changed):
                call = diagnostic.timeout_snapshot(100, [], {}, root, ROOT, proc=root)['processes'][0]['syscall']
            self.assertEqual(call['status'], 'changed during snapshot; fd metadata omitted')
            self.assertNotIn('descriptor', call)
            self.assertNotIn('object.o', json.dumps(call))

    def test_fd_link_change_omits_stale_path(self):
        import native_timeout_diagnostics as diagnostic
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            self.fake_syscall(root)
            read = diagnostic._read
            def changed(path, limit=4096):
                result = read(path, limit)
                if path == root / '100/fdinfo/3':
                    (root / '100/fd/3').unlink()
                    (root / '100/fd/3').symlink_to(root / 'replacement')
                return result
            with patch.object(diagnostic, '_read', side_effect=changed):
                call = diagnostic.timeout_snapshot(100, [], {}, root, ROOT, proc=root)['processes'][0]['syscall']
            self.assertEqual(call['descriptor']['status'], 'changed during snapshot')
            self.assertNotIn('target', call['descriptor'])

    @unittest.skipUnless(sys.platform == 'linux' and os.uname().machine == 'x86_64', 'fd decoder covers Linux x86_64 ELF64 only')
    def test_actual_owned_pipe_read_reports_only_its_descriptor_metadata(self):
        self.assert_owned_pipe_read()

    def assert_owned_pipe_read(self):
        from native_timeout_diagnostics import timeout_snapshot
        read, write = os.pipe()
        child = subprocess.Popen([sys.executable, '-c', 'import os,sys; os.read(int(sys.argv[1]), 1)', str(read)],
                                 pass_fds=(read,))
        try:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                report = timeout_snapshot(child.pid, [], {}, Path('/unused-fixture'), ROOT)
                process = next((p for p in report['processes'] if p['pid'] == child.pid), {})
                call = process.get('syscall', {})
                if call.get('number') == 0 and call.get('descriptor', {}).get('number') == read:
                    break
                time.sleep(0.01)
            else:
                self.fail('owned pipe reader did not reach its blocking read')
            self.assertEqual((call['number'], call['name']), (0, 'read'))
            self.assertEqual(call['descriptor']['number'], read)
            self.assertTrue(call['descriptor']['target'].startswith('pipe:['))
        finally:
            os.close(read)
            os.close(write)
            child.terminate()
            child.wait()

    @unittest.skipUnless(sys.platform == 'linux' and os.uname().machine == 'x86_64', 'fd decoder covers Linux x86_64 ELF64 only')
    def test_renamed_pipe_wait_symbol_does_not_change_owned_readiness(self):
        import native_timeout_diagnostics as diagnostic
        from unittest.mock import patch
        original_text = Path.read_text
        original_read = diagnostic._read
        observed = []
        def renamed_text(path, *args, **kwargs):
            if path.name == 'wchan' and path.parents[1] == Path('/proc'):
                return 'anon_pipe_read'
            return original_text(path, *args, **kwargs)
        def renamed_read(path, limit=4096):
            if path.name == 'wchan' and path.parents[1] == Path('/proc'):
                observed.append('anon_pipe_read')
                return 'anon_pipe_read'
            return original_read(path, limit)
        with patch.object(Path, 'read_text', renamed_text), patch.object(diagnostic, '_read', renamed_read):
            self.assert_owned_pipe_read()
        self.assertTrue(observed, 'real owned snapshot did not observe the renamed wait symbol')

    def test_original_timeout_emits_diagnostics_without_changing_failure(self):
        import contextlib
        import io
        with tempfile.TemporaryDirectory(prefix='qsh-timeout-diagnostic-') as temp:
            root = Path(temp)
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                with self.assertRaises(subprocess.TimeoutExpired) as failure:
                    run_owned_build([sys.executable, '-c', 'import time; time.sleep(60)'],
                                    dict(os.environ), root, timeout=0.05)
            self.assertEqual(failure.exception.timeout, 0.05)
            self.assertIn('Native fixture timeout tools:', output.getvalue())
            self.assertIn('Native fixture timeout processes:', output.getvalue())



class NativeBuildTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qsh-native-build-test-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cache = self.root / 'cache'
        self.archive = self.root / 'source.tar.gz'
        self.archive.write_bytes(b'not the pinned upstream archive\n')

    def run_build(self, *extra):
        env = dict(os.environ, HISTFILE='/dev/null', CARGO_BUILD_JOBS='2')
        return run_owned_build(
            ['bash', str(SCRIPT), '--target', 'x86_64-unknown-linux-musl',
             '--cache', str(self.cache), '--archive', str(self.archive), *extra],
            env=env, fixture=self.root)

    def test_corrupt_archive_is_rejected_before_build_or_cache_publication(self):
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0, 'corrupt native source was accepted')
        self.assertIn('archive SHA-256 mismatch', result.stderr)
        self.assertEqual(list(self.cache.glob('*/manifest.json')), [])

    def test_unrecognized_target_is_rejected_without_a_host_fallback(self):
        result = self.run_build('--target', 'unrecognized-unknown-target')
        self.assertNotEqual(result.returncode, 0, 'unknown target was accepted')
        self.assertIn('unsupported target', result.stderr)
        self.assertFalse(self.cache.exists())

    def test_offline_missing_archive_does_not_download_or_create_cache(self):
        self.archive.unlink()
        result = self.run_build()
        self.assertNotEqual(result.returncode, 0, 'missing offline archive was accepted')
        self.assertIn('archive is not a regular file', result.stderr)
        self.assertFalse(self.cache.exists())

# Native cryptography is qualified separately against the signed upstream source.
# This generated miniature project exercises the real archive/build/cache paths
# quickly; its isolated metadata and fake verifier never alter repository pins.
class BuildCacheTests(NativeBuildTests):
    def setUp(self):
        super().setUp()
        import hashlib
        import shutil
        import tarfile
        self.tools = self.root / 'tools'
        self.tools.mkdir()
        self.scripts = self.root / 'scripts'
        shutil.copytree(ROOT / 'scripts/openssl', self.scripts / 'openssl')
        shutil.copy(ROOT / 'scripts/build_openssl.py', self.scripts)
        shutil.copy(ROOT / 'scripts/build-openssl.sh', self.scripts)
        source = self.root / 'openssl-3.5.9'
        source.mkdir()
        (source / 'Configure').write_text(r'''#!/usr/bin/env perl
use strict;
use warnings;
my ($prefix) = map { /^--prefix=(.*)$/ ? $1 : () } @ARGV;
open my $in, '<', 'Makefile.in' or die $!;
open my $out, '>', 'Makefile' or die $!;
while (<$in>) { s/INSTALL_PREFIX/$prefix/g; print $out $_; }
''')
        (source / 'Makefile.in').write_text(r'''all:
	@test -z "$$QSH_TEST_BUILD_FAIL"
	@if [ -n "$$QSH_TEST_BUILD_HOLD" ]; then echo held >&2; cat "$$QSH_TEST_BUILD_HOLD"; fi
	@echo build >> "$$QSH_TEST_BUILD_COUNT"
install_sw:
	mkdir -p $(DESTDIR)INSTALL_PREFIX/include/openssl $(DESTDIR)INSTALL_PREFIX/lib
	printf '#define OPENSSL_VERSION_MAJOR 3\n#define OPENSSL_VERSION_MINOR 5\n#define OPENSSL_VERSION_PATCH 9\n' > $(DESTDIR)INSTALL_PREFIX/include/openssl/opensslv.h
	printf 'unsigned long OpenSSL_version_num(void);\n' > $(DESTDIR)INSTALL_PREFIX/include/openssl/crypto.h
	printf 'unsigned long OpenSSL_version_num(void){return 0x30500090UL;} const char *configured_prefix = "INSTALL_PREFIX";\n' > version.c
	$(CC) -c version.c -o version.o
	$(AR) rcs $(DESTDIR)INSTALL_PREFIX/lib/libcrypto.a version.o
	$(AR) rcs $(DESTDIR)INSTALL_PREFIX/lib/libssl.a version.o
''')
        (source / 'LICENSE.txt').write_text('Generated test fixture; no upstream code.\n')
        with tarfile.open(self.archive, 'w:gz') as archive:
            archive.add(source, arcname=source.name)
        pin = self.scripts / 'openssl/source.json'
        metadata = json.loads(pin.read_text())
        metadata['sha256'] = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        pin.write_text(json.dumps(metadata))
        verifier = self.tools / 'gpg'
        verifier.write_text('#!/bin/sh\ncase " $* " in *" --verify "*) echo "[GNUPG:] VALIDSIG TEST 0 0 0 0 0 0 0 0 ' + metadata['signer'] + '";; esac\n')
        verifier.chmod(0o755)
        self.count = self.root / 'build-count'

    def run_build(self, *extra, **overrides):
        env = dict(os.environ, HISTFILE='/dev/null', CARGO_BUILD_JOBS='2',
                   PATH=str(self.tools) + os.pathsep + os.environ['PATH'],
                   QSH_TEST_BUILD_COUNT=str(self.count))
        env.update(overrides)
        return run_owned_build(
            ['bash', str(self.scripts / 'build-openssl.sh'),
             '--target', 'x86_64-unknown-linux-gnu', '--cache', str(self.cache),
             '--archive', str(self.archive), '--cc', 'cc', *extra],
            env=env, fixture=self.root)

    # These are tested against the real pinned metadata in the first class.
    def test_corrupt_archive_is_rejected_before_build_or_cache_publication(self):
        self.archive.write_bytes(b'corrupt')
        super().test_corrupt_archive_is_rejected_before_build_or_cache_publication()

    def test_signature_status_accepts_binary_notation_but_requires_valid_fingerprint(self):
        verifier = self.tools / 'gpg'
        verifier.write_text(verifier.read_text() + "printf '\\377\\n'\n")
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        verifier.write_text(verifier.read_text().replace('VALIDSIG', 'BADSIG'))
        rejected = self.run_build()
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn('release signature does not match', rejected.stderr)

    def test_native_archive_does_not_embed_private_staging_prefix(self):
        result = self.run_build()
        self.assertEqual(result.returncode, 0, result.stderr)
        archive = Path(result.stdout.strip()) / 'lib/libcrypto.a'
        self.assertNotIn(str(self.root).encode(), archive.read_bytes())

    def test_success_is_atomic_and_reusable(self):
        first = self.run_build()
        self.assertEqual(first.returncode, 0, first.stderr)
        prefix = Path(first.stdout.strip())
        self.assertTrue((prefix / 'manifest.json').is_file(), first.stdout)
        second = self.run_build()
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(second.stdout, first.stdout)
        self.assertEqual(self.count.read_text().splitlines(), ['build'])
        self.assertEqual(list(self.cache.glob('.stage-*')), [])

    def test_failed_build_preserves_unrelated_state_and_publishes_nothing(self):
        self.cache.mkdir()
        sentinel = self.cache / 'unrelated'
        sentinel.write_text('keep')
        result = self.run_build(QSH_TEST_BUILD_FAIL='1')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(sentinel.read_text(), 'keep')
        self.assertEqual(list(self.cache.glob('*/manifest.json')), [])
        self.assertEqual(list(self.cache.glob('.stage-*')), [])
        self.assertEqual(list(self.cache.glob('*.lock')), [])

    def test_changed_compiler_flags_get_a_separate_cache_identity(self):
        first = self.run_build()
        second = self.run_build('--cflag=-DQSH_CACHE_CONTROL=1')
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(first.stdout, second.stdout)
        self.assertEqual(len(self.count.read_text().splitlines()), 2)

    def test_changed_archiver_at_the_same_path_gets_a_new_cache_identity(self):
        import shlex
        import shutil
        archiver = self.tools / 'owned-ar'
        calls = self.root / 'archiver-calls'
        actual = shutil.which('ar')
        self.assertIsNotNone(actual)
        archiver.write_text('#!/bin/sh\nprintf "%s\\n" "$2" >> ' +
                            shlex.quote(str(calls)) + '\nexec ' +
                            shlex.quote(actual) + ' "$@"\n')
        archiver.chmod(0o755)
        first = self.run_build('--ar', str(archiver))
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue(calls.is_file(), 'selected archiver was not executed')
        archives = ['libcrypto.a', 'libssl.a']
        self.assertEqual([Path(line).name for line in calls.read_text().splitlines()], archives)
        archiver.write_text(archiver.read_text() + '# changed toolchain wrapper\n')
        second = self.run_build('--ar', str(archiver))
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(first.stdout, second.stdout)
        self.assertEqual(len(self.count.read_text().splitlines()), 2)
        self.assertEqual([Path(line).name for line in calls.read_text().splitlines()], archives * 2)
        cached = self.run_build('--ar', str(archiver))
        self.assertEqual(cached.returncode, 0, cached.stderr)
        self.assertEqual(cached.stdout, second.stdout)
        self.assertEqual(len(self.count.read_text().splitlines()), 2)
        self.assertEqual([Path(line).name for line in calls.read_text().splitlines()], archives * 2)

    def test_selected_archiver_failure_publishes_nothing(self):
        import shlex
        archiver = self.tools / 'failing-ar'
        calls = self.root / 'archiver-calls'
        archiver.write_text('#!/bin/sh\nprintf "%s\\n" called > ' +
                            shlex.quote(str(calls)) +
                            '\nprintf "%s\\n" "selected archiver failure" >&2\nexit 93\n')
        archiver.chmod(0o755)
        self.cache.mkdir()
        sentinel = self.cache / 'unrelated'
        sentinel.write_text('keep')
        result = self.run_build('--ar', str(archiver))
        self.assertNotEqual(result.returncode, 0, 'selected archiver failure was ignored')
        self.assertEqual(calls.read_text().splitlines(), ['called'])
        self.assertIn('selected archiver failure', result.stderr)
        self.assertEqual(list(self.cache.glob('*/manifest.json')), [])
        self.assertEqual(list(self.cache.glob('.stage-*')), [])
        self.assertEqual(list(self.cache.glob('*.lock')), [])
        self.assertEqual(sentinel.read_text(), 'keep')

    def test_modified_archive_in_completed_cache_is_rejected(self):
        first = self.run_build()
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertTrue((Path(first.stdout.strip()) / 'manifest.json').is_file())
        (Path(first.stdout.strip()) / 'lib/libcrypto.a').write_bytes(b'wrong library')
        second = self.run_build()
        self.assertNotEqual(second.returncode, 0)
        self.assertIn('cache artifact mismatch', second.stderr)
        self.assertEqual(len(self.count.read_text().splitlines()), 1)

    def test_incomplete_cache_and_wrong_identity_are_not_reused(self):
        first = self.run_build()
        self.assertEqual(first.returncode, 0, first.stderr)
        manifest = Path(first.stdout.strip()) / 'manifest.json'
        complete = manifest.read_text()
        metadata = json.loads(complete)
        metadata['identity']['target'] = 'aarch64-unknown-linux-gnu'
        manifest.write_text(json.dumps(metadata))
        wrong = self.run_build()
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn('cache identity mismatch', wrong.stderr)
        manifest.unlink()
        incomplete = self.run_build()
        self.assertNotEqual(incomplete.returncode, 0)
        self.assertIn('incomplete native cache', incomplete.stderr)
        self.assertEqual(self.count.read_text().splitlines(), ['build'])

    def test_modified_headers_cannot_reuse_a_completed_cache(self):
        first = self.run_build()
        self.assertEqual(first.returncode, 0, first.stderr)
        header = Path(first.stdout.strip()) / 'include/openssl/opensslv.h'
        header.write_text(header.read_text().replace('PATCH 9', 'PATCH 8'))
        changed = self.run_build()
        self.assertNotEqual(changed.returncode, 0)
        self.assertIn('cache artifact mismatch', changed.stderr)

    def test_failed_signature_cannot_use_even_a_completed_cache(self):
        first = self.run_build()
        self.assertEqual(first.returncode, 0, first.stderr)
        verifier = self.tools / 'gpg'
        verifier.write_text('#!/bin/sh\nexit 1\n')
        failed = self.run_build()
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.count.read_text().splitlines(), ['build'])

    @unittest.skipUnless(hasattr(__import__('socket'), 'AF_UNIX'), 'requires Unix socket barrier')
    def test_timeout_retains_fixture_until_graceful_cleanup_finishes(self):
        import socket
        import threading
        from unittest import mock
        address = self.root / 'cleanup.sock'
        program = self.root / 'held-cleanup.py'
        program.write_text("""import signal
import socket
import sys
s = socket.socket(socket.AF_UNIX)
s.connect(sys.argv[1])
def stop(_signal, _frame):
    s.sendall(b'T')
    assert s.recv(1) == b'R'
    sys.exit(0)
signal.signal(signal.SIGTERM, stop)
s.sendall(b'S')
while True:
    signal.pause()
""")
        result = []
        def invoke():
            try:
                # Even an interrupted diagnostic write must retain cleanup.
                with mock.patch('builtins.print', side_effect=KeyboardInterrupt):
                    run_owned_build([sys.executable, str(program), str(address)],
                                    dict(os.environ), self.root, timeout=2)
            except BaseException as error:
                result.append(error)
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(address))
            listener.listen(1)
            listener.settimeout(5)
            worker = threading.Thread(target=invoke)
            worker.start()
            connection = None
            try:
                connection, _ = listener.accept()
                connection.settimeout(5)
                self.assertEqual(connection.recv(1), b'S', 'handler was not installed')
                self.assertEqual(connection.recv(1), b'T', 'TERM did not start cleanup')
                self.assertTrue(worker.is_alive(), 'timeout dropped its process owner')
                self.assertTrue(program.is_file(), 'fixture removed during cleanup')
                self.assertEqual(result, [], 'timeout returned before cleanup release')
            finally:
                if connection is not None:
                    connection.sendall(b'R')
                    connection.close()
                # Deliberately retain ownership if graceful cleanup is pending.
                worker.join()
        self.assertEqual(len(result), 1)
        self.assertIsInstance(result[0], subprocess.TimeoutExpired)
        self.assertEqual(result[0].timeout, 2, 'cleanup exit0 must still fail the deadline')

    @unittest.skipUnless(sys.platform == 'linux', 'owned timeout oracle uses Linux prctl')
    def test_timed_out_build_finishes_owned_cleanup_before_raising(self):
        if os.environ.get('QSH_TEST_TIMEOUT_OWNER') != '1':
            child = subprocess.Popen([
                sys.executable, '-B', str(Path(__file__).resolve()),
                'BuildCacheTests.test_timed_out_build_finishes_owned_cleanup_before_raising'],
                env=dict(os.environ, QSH_TEST_TIMEOUT_OWNER='1'),
                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                stdout, stderr = child.communicate()
            finally:
                if child.returncode is None:
                    child.terminate()
                    child.communicate()
            self.assertEqual(child.returncode, 0, stderr + stdout)
            return
        import ctypes
        self.assertEqual(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0), 0)
        # An interrupted regression owner still runs its child-reaping finally.
        def interrupted(_signal, _frame):
            raise InterruptedError('owned timeout regression cancelled')
        signal.signal(signal.SIGTERM, interrupted)
        hold = self.root / 'hold'
        os.mkfifo(hold)
        self.cache.mkdir()
        sentinel = self.cache / 'unrelated'
        sentinel.write_text('keep')
        try:
            with self.assertRaises(subprocess.TimeoutExpired) as timed_out:
                self.run_build(QSH_TEST_BUILD_HOLD=str(hold))
            self.assertEqual(timed_out.exception.timeout, 20)
            output = timed_out.exception.stderr or b''
            if isinstance(output, str):
                output = output.encode()
            self.assertIn(b'held', output, 'timeout must follow real make readiness')
            self.assertTrue(reap_owned_children(False), 'timeout returned with live native children')
            self.assertEqual(list(self.cache.glob('.stage-*')), [])
            self.assertEqual(list(self.cache.glob('*.lock')), [])
            self.assertEqual(list(self.cache.glob('*/manifest.json')), [])
            self.assertEqual(sentinel.read_text(), 'keep')
        finally:
            self.assertTrue(reap_owned_children(True), 'owned regression descendants were not reaped')

    @unittest.skipUnless(sys.platform == 'linux', 'owned subreaper oracle uses Linux prctl')
    def test_cancelled_build_reaps_its_children_and_removes_only_its_staging(self):
        if os.environ.get('QSH_TEST_REAP_OWNER') != '1':
            # Only this owned subprocess becomes a subreaper; the suite's
            # process and unrelated tests retain their ordinary wait ownership.
            result = subprocess.run([
                sys.executable, str(Path(__file__).resolve()),
                'BuildCacheTests.test_cancelled_build_reaps_its_children_and_removes_only_its_staging'],
                env=dict(os.environ, QSH_TEST_REAP_OWNER='1'),
                text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return
        import ctypes
        self.assertEqual(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0), 0)

        hold = self.root / 'hold'
        os.mkfifo(hold)
        env = dict(os.environ, HISTFILE='/dev/null', CARGO_BUILD_JOBS='2',
                   PATH=str(self.tools) + os.pathsep + os.environ['PATH'],
                   QSH_TEST_BUILD_HOLD=str(hold), QSH_TEST_BUILD_COUNT=str(self.count))
        child = subprocess.Popen(
            ['bash', str(self.scripts / 'build-openssl.sh'), '--target',
             'x86_64-unknown-linux-gnu', '--cache', str(self.cache),
             '--archive', str(self.archive), '--cc', 'cc'], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            start_new_session=True)
        try:
            # Readiness is a real make recipe event, not a delay assumption.
            import select
            deadline = time.monotonic() + 10
            while True:
                self.assertGreater(deadline - time.monotonic(), 0, 'build did not reach barrier')
                ready, _, _ = select.select([child.stderr], [], [], 1)
                if ready:
                    line = child.stderr.readline()
                    self.assertTrue(line, 'build ended before barrier')
                    if line.strip() == 'held':
                        break
            child.terminate()
            child.wait(timeout=10)
            self.assertNotEqual(child.returncode, 0)
            self.assertTrue(reap_owned_children(False), "native descendants survived cancellation")
            self.assertEqual(list(self.cache.glob('.stage-*')), [])
            self.assertEqual(list(self.cache.glob('*.lock')), [])
            self.assertEqual(list(self.cache.glob('*/manifest.json')), [])
        finally:
            # The outer owner also cleans up a failing implementation. Do not
            # signal a numeric group after its leader has already been reaped.
            if child.returncode is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.communicate(timeout=10)
            self.assertTrue(reap_owned_children(True), 'owned fixture descendants were not reaped')


class QualificationIsolationTests(unittest.TestCase):
    def test_native_commands_use_owned_home_and_explicit_empty_config(self):
        import shutil
        with tempfile.TemporaryDirectory(prefix='qsh-qualifier-test-') as name:
            root = Path(name)
            scripts = root / 'scripts'
            scripts.mkdir()
            shutil.copy(ROOT / 'scripts/qualify_openssl.py', scripts)
            prefix = root / 'native'
            (prefix / 'bin').mkdir(parents=True)
            (prefix / 'manifest.json').write_text(json.dumps({'identity': {
                'source': {'version': '3.5.9'}, 'target': 'controlled-test'}}))
            builder = scripts / 'build-openssl.sh'
            builder.write_text('#!/bin/sh\nprintf "%s\\n" "' + str(prefix) + '"\n')
            probe = prefix / 'version-probe'
            probe.write_text('#!/bin/sh\nexit 0\n')
            probe.chmod(0o755)
            executable = prefix / 'bin/openssl'
            executable.write_text('''#!/bin/sh
set -eu
case "$HOME" in */qsh-native-qualification-*/home) ;; *) exit 72 ;; esac
[ -d "$XDG_CONFIG_HOME" ] && [ -d "$XDG_CACHE_HOME" ]
[ -z "${SSH_AUTH_SOCK+x}" ]
[ -f "$OPENSSL_CONF" ] && [ ! -s "$OPENSSL_CONF" ]
case "$1" in
  version) echo 'OpenSSL 3.5.9 controlled test' ;;
  dgst) case "$*" in *-verify*changed*) exit 1 ;; esac ;;
esac
''')
            executable.chmod(0o755)
            env = dict(os.environ, HOME='/unowned-home-must-not-be-used',
                       SSH_AUTH_SOCK='/unowned-agent-must-not-be-used',
                       OPENSSL_CONF='/unowned-config-must-not-be-used')
            result = subprocess.run(['python3', str(scripts / 'qualify_openssl.py')],
                                    env=env, text=True, capture_output=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('Qualified: controlled-test', result.stdout)

    @unittest.skipUnless(sys.platform == 'linux', 'owned subreaper oracle uses Linux prctl')
    def test_qualifier_cancellation_waits_for_owned_builder_cleanup(self):
        if os.environ.get('QSH_TEST_QUALIFY_OWNER') != '1':
            result = subprocess.run([
                sys.executable, str(Path(__file__).resolve()),
                'QualificationIsolationTests.test_qualifier_cancellation_waits_for_owned_builder_cleanup'],
                env=dict(os.environ, QSH_TEST_QUALIFY_OWNER='1'),
                text=True, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr)
            return
        import ctypes
        import select
        import shutil
        self.assertEqual(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0), 0)
        with tempfile.TemporaryDirectory(prefix='qsh-qualifier-cancel-') as name:
            root = Path(name)
            shutil.copy(ROOT / 'scripts/qualify_openssl.py', root)
            marker = root / 'cleanup'
            child_pid = root / 'builder-pid'
            builder = root / 'builder.py'
            builder.write_text('import os,signal,sys\nfrom pathlib import Path\n'
                + 'def stop(*args):\n    Path(' + repr(str(marker)) + ').write_text("clean")\n    sys.exit(0)\n'
                + 'signal.signal(signal.SIGTERM, stop)\n'
                + 'Path(' + repr(str(child_pid)) + ').write_text(str(os.getpid()))\n'
                + 'print("builder-ready", file=sys.stderr, flush=True)\nsignal.pause()\n')
            (root / 'build-openssl.sh').write_text('#!/bin/sh\nexec python3 "' + str(builder) + '"\n')
            child = subprocess.Popen([sys.executable, str(root / 'qualify_openssl.py')],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                ready, _, _ = select.select([child.stderr], [], [], 10)
                self.assertTrue(ready, 'builder did not become ready')
                self.assertEqual(child.stderr.readline().strip(), 'builder-ready')
                child.terminate()
                child.wait(timeout=15)
                self.assertTrue(marker.exists(), 'qualifier abandoned its builder before cleanup')
            finally:
                if child.returncode is None:
                    child.terminate()
                child.wait(timeout=15)
                if child_pid.exists():
                    pid = int(child_pid.read_text())
                    try:
                        reaped, _ = os.waitpid(pid, os.WNOHANG)
                    except ChildProcessError:
                        pass  # The qualifier already reaped its child.
                    else:
                        if reaped == 0:
                            os.kill(pid, signal.SIGTERM)  # Our live, un-reaped adopted child.
                            os.waitpid(pid, 0)
                child.communicate(timeout=5)


class ProductEntrypointTests(unittest.TestCase):
    def test_product_callers_execute_the_nonexecutable_checkout_wrapper(self):
        import re
        import shutil
        callers = {
            '.github/workflows/ci.yml': 3,
            '.github/workflows/native-crypto.yml': 1,
            '.github/workflows/release.yml': 2,
            'packaging/build-server-packages.sh': 1,
            'packaging/acceptance.sh': 1,
        }
        # Execute each real prefix assignment, not a reconstructed command.
        # Only the Python backend is replaced: no download, crypto or build.
        pattern = re.compile(
            r'(?m)^[ \t]*(?P<name>(?:native_)?prefix)=\$\('
            r'(?P<command>[^\n]*build-openssl\.sh[\s\S]*?)\)')
        with tempfile.TemporaryDirectory(prefix='qsh-native-entrypoint-') as temp:
            root = Path(temp) / 'checkout with spaces'
            scripts = root / 'scripts'
            scripts.mkdir(parents=True)
            wrapper = scripts / 'build-openssl.sh'
            shutil.copyfile(SCRIPT, wrapper)
            wrapper.chmod(0o644)  # The tracked mode, including a fresh CI checkout.
            record = root / 'arguments.json'
            (scripts / 'build_openssl.py').write_text(
                'import json,os,sys\nfrom pathlib import Path\n'
                'Path(os.environ["QSH_TEST_ARGUMENTS"]).write_text(json.dumps(sys.argv[1:]))\n'
                'print(os.environ["QSH_TEST_PREFIX"])\n')
            expected = str(root / 'qualified prefix')
            target = 'x86_64-unknown-linux-gnu'
            env = dict(os.environ, HISTFILE='/dev/null', root=str(root),
                       target=target, triple=target, client_target=target,
                       NATIVE_TARGET=target, RUNNER_TEMP=temp, ImageOS='fixture',
                       ImageVersion='1', fmt='deb', target_dir=temp,
                       native_uapi=temp, uapi=temp, CARGO_TARGET_DIR=temp,
                       QSH_TEST_ARGUMENTS=str(record), QSH_TEST_PREFIX=expected)
            for caller, count in callers.items():
                assignments = list(pattern.finditer((ROOT / caller).read_text()))
                self.assertEqual(len(assignments), count, caller)
                for index, assignment in enumerate(assignments):
                    with self.subTest(caller=caller, invocation=index):
                        record.unlink(missing_ok=True)
                        script = ('set -euo pipefail\nargs=()\nnative_args=()\n'
                                  + assignment.group(0).strip()
                                  + '\nprintf "%s" "$' + assignment['name'] + '"\n')
                        result = subprocess.run(['bash', '-c', script], cwd=root,
                                                env=env, text=True, capture_output=True,
                                                timeout=10)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        self.assertEqual(result.stdout, expected)
                        argv = json.loads(record.read_text())
                        self.assertEqual(argv[:2], ['--target', target])
                        self.assertIn('--cache', argv)


if __name__ == '__main__':
    unittest.main()
