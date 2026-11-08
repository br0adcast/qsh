"""Fail-closed controls for the focused released-peer gate; no product builds."""
from contextlib import redirect_stdout
import ast
import fnmatch
import hashlib
import importlib.util
import io
import json
import os
import sys
import threading
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'released-peer-acceptance.py'
spec = importlib.util.spec_from_file_location('peer_acceptance', SCRIPT)
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)


class AcceptanceTests(unittest.TestCase):
    def archive(self, root, members):
        archive = root / 'fixture.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            for name, kind in members:
                info = tarfile.TarInfo(name)
                info.type = kind
                info.size = 1 if kind == tarfile.REGTYPE else 0
                info.linkname = '/bin/sh' if kind == tarfile.SYMTYPE else ''
                tar.addfile(info, io.BytesIO(b'x') if info.size else None)
        return archive

    def test_verified_pair_only(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root, [(peer.PREFIX + '/' + name, tarfile.REGTYPE)
                                          for name in ('qsh', 'qshd')])
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            pair = peer.extract_pair(archive, root / 'out', digest)
            self.assertEqual([p.read_bytes() for p in pair], [b'x', b'x'])
            self.assertTrue(all(p.stat().st_mode & 0o100 for p in pair))

    def test_native_fixture_selection_and_manifest_are_explicit(self):
        expected = {
            ('Linux', 'x86_64'): ('qsh-0.5.0-x86_64-unknown-linux-musl', peer.SHA256, 6282319),
            ('Darwin', 'arm64'): ('qsh-0.5.0-aarch64-apple-darwin', 'db31e4a123459a9fd8151585301f7e0142c340cd1d9473a8e86d1f5be3f072cb', 5433857),
            ('Darwin', 'x86_64'): ('qsh-0.5.0-x86_64-apple-darwin', '38b40b631ebd0a4fce856c7763cf4793c55e625cb404e2a93c4a3d391786d599', 5866506),
        }
        for host, fixture in expected.items():
            self.assertEqual(peer.fixture_for_host(*host), fixture)
        for host in [('Darwin', 'unknown'), ('Linux', 'aarch64'), ('Windows', 'AMD64')]:
            with self.assertRaises(ValueError):
                peer.fixture_for_host(*host)
        prefix, digest, _ = expected['Darwin', 'arm64']
        data = (digest + '  ' + prefix + '.tar.gz\n').encode()
        with mock.patch.object(peer, 'MANIFEST_SIZE', len(data)), mock.patch.object(peer, 'MANIFEST_SHA256', hashlib.sha256(data).hexdigest()):
            peer.verify_published_manifest(data, prefix, digest)
            for changed, selected, checksum in [(data+b'x', prefix, digest), (data, prefix+'-other', digest), (data, prefix, '00'*32)]:
                with self.assertRaises(ValueError):
                    peer.verify_published_manifest(changed, selected, checksum)

    def test_platform_archive_prefix_cannot_be_confused(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            prefix='qsh-0.5.0-aarch64-apple-darwin'
            archive=self.archive(root, [(prefix+'/'+name,tarfile.REGTYPE) for name in ('qsh','qshd')])
            digest=hashlib.sha256(archive.read_bytes()).hexdigest()
            with self.assertRaises(ValueError):
                peer.extract_pair(archive,root/'wrong',digest)
            pair=peer.extract_pair(archive,root/'correct',digest,prefix)
            self.assertTrue(all(path.read_bytes()==b'x' for path in pair))

    def test_bad_digest_precedes_extraction(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self.archive(root, [(peer.PREFIX + '/qsh', tarfile.REGTYPE)])
            with self.assertRaisesRegex(ValueError, 'checksum'):
                peer.extract_pair(archive, root / 'out', '0' * 64)
            self.assertFalse((root / 'out').exists())

    def test_missing_symlink_duplicate_and_traversal_rejected(self):
        for members in (
            [(peer.PREFIX + '/qsh', tarfile.REGTYPE)],
            [(peer.PREFIX + '/qsh', tarfile.SYMTYPE), (peer.PREFIX + '/qshd', tarfile.REGTYPE)],
            [(peer.PREFIX + '/qsh', tarfile.REGTYPE)] * 2,
            [('../qsh', tarfile.REGTYPE)],
            [(peer.PREFIX + '/qsh', tarfile.REGTYPE),
             (peer.PREFIX + '/qshd', tarfile.REGTYPE),
             (peer.PREFIX + '/README.md', tarfile.SYMTYPE)],
            [(peer.PREFIX + '/qsh', tarfile.REGTYPE),
             (peer.PREFIX + '/qshd', tarfile.REGTYPE),
             (peer.PREFIX + '/extra', tarfile.REGTYPE)],
        ):
            with self.subTest(members=members), tempfile.TemporaryDirectory() as temp:
                root = Path(temp)
                archive = self.archive(root, members)
                with self.assertRaises(ValueError):
                    peer.extract_pair(archive, root / 'out', hashlib.sha256(archive.read_bytes()).hexdigest())
                self.assertFalse((root / 'out').exists())

    def test_download_failure_is_not_a_fallback(self):
        with mock.patch.object(peer.subprocess, 'run', side_effect=subprocess.CalledProcessError(22, 'curl')):
            with self.assertRaises(subprocess.CalledProcessError):
                peer.download(Path('/unused'))

    def test_exact_one_pass_and_no_skip(self):
        text = 'running 1 test\ntest wanted ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 4 filtered out; finished in 0.01s\n'
        peer.check_result('wanted', text, 0)
        for output, status in (
            (text, 1), (text.replace('wanted', 'other'), 0),
            (text.replace('1 passed', '0 passed'), 0),
            (text.replace('0 ignored', '1 ignored'), 0),
            (text.replace('1 passed', '2 passed'), 0),
            (text + 'test extra ... ok\n', 0),
            (text + 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n', 0),
            (text + '\nSKIPPED: missing prerequisite\n', 0),
            ('running 0 tests\ntest result: ok. 0 passed; 0 failed; 0 ignored;', 0),
            ('Finished test profile\nExecutable tests/mixed_versions (owned)\n', 0),
        ):
            with self.subTest(output=output, status=status), self.assertRaises(ValueError):
                peer.check_result('wanted', output, status)

    def test_case_failure_retains_evidence_and_fails(self):
        result = subprocess.CompletedProcess([], 23, 'the fixture failed before its test ran\n')
        with tempfile.TemporaryDirectory() as temp:
            evidence = Path(temp)
            def failed(command, env, path):
                path.write_text(result.stdout)
                return result.returncode
            with mock.patch.object(peer, 'stream_command', side_effect=failed), redirect_stdout(io.StringIO()):
                with self.assertRaises(ValueError):
                    peer.run_case('qsh', 'wanted', True, {}, evidence)
            phases = [json.loads(line) for line in (evidence/'phases.jsonl').read_text().splitlines()]
            self.assertEqual(phases[-1]['status'], 23)
            self.assertEqual((evidence / 'wanted.log').read_text(), result.stdout)

    def test_busy_legacy_shell_scenario_is_selected_with_existing_cases(self):
        self.assertEqual(len(peer.CASES), 8)
        self.assertIn(('qsh', 'current_ensure_reports_busy_published_v050_without_interrupting_shell', True), peer.CASES)
        self.assertIn(('qsh', 'published_v050_force_restarts_account_service_even_after_instance_change', True), peer.CASES)
        self.assertIn(('qsh', 'protocol2_client_cannot_mutate_published_v050_daemon', True), peer.CASES)
        self.assertEqual(len(set(peer.CASES)), len(peer.CASES))

    def test_pull_request_changes_run_the_real_gate_without_every_patch(self):
        workflow = (SCRIPT.parents[1] / '.github/workflows/released-peer-acceptance.yml').read_text()
        trigger = re.search(r'^  pull_request:\n    paths:\n((?:      - .*\n)+)', workflow, re.MULTILINE)
        self.assertIsNotNone(trigger, 'PR acceptance changes must execute the actual eight-case gate')
        paths = [ast.literal_eval(line.strip()[2:]) for line in trigger.group(1).splitlines()]
        for changed in ('.github/workflows/released-peer-acceptance.yml',
                        '.github/workflows/release.yml',
                        'scripts/released-peer-acceptance.py',
                        'scripts/tests/test_released_peer_acceptance.py',
                        'cli/tests/mixed_versions.rs', 'qshd/tests/mixed_versions.rs',
                        'crates/daemon-bootstrap-protocol/src/lib.rs',
                        'crates/bringup/src/ensure.rs', 'crates/bringup/src/install.rs',
                        'qshd/src/main.rs', 'qshd/src/control.rs', 'qshd/src/control/path.rs',
                        'qshd/src/transport_daemon.rs', 'qshd/src/destructive_restart.rs',
                        'qshd/src/modern_restart.rs', 'qshd/src/service_restart.rs',
                        'qshd/src/control_service_tests.rs', 'cli/src/ssh_step.rs',
                        'cli/src/busy_daemon.rs', 'cli/src/climb.rs'):
            self.assertTrue(any(fnmatch.fnmatchcase(changed, pattern) for pattern in paths), changed)
        self.assertFalse(any(fnmatch.fnmatchcase('README.md', pattern) for pattern in paths))
        self.assertIn('ref: ${{ github.sha }}', workflow)
        self.assertIn('python3 scripts/released-peer-acceptance.py --evidence', workflow)
        release = (SCRIPT.parents[1] / '.github/workflows/release.yml').read_text()
        self.assertRegex(release, r'needs: \[release, ordinary-ci, released-peer-acceptance, release-verifier\]')


class PreparationTests(unittest.TestCase):

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='peer-preparation-control-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.evidence = self.root / 'evidence'
        self.evidence.mkdir()
        for package, folder in [('qsh', 'cli'), ('qshd', 'qshd')]:
            directory = self.root / folder
            directory.mkdir()
            (directory / 'Cargo.toml').write_text(f'[package]\nname="{package}"\nversion="1.0.0"\n')
            (directory / 'src').mkdir()
            (directory / 'src/main.rs').write_text('')
            (directory / 'tests').mkdir()
            (directory / 'tests/mixed_versions.rs').write_text('')
        self.commands = []

    def record(self, package, kind):
        folder = 'cli' if package == 'qsh' else 'qshd'
        name = package if kind == 'bin' else 'mixed_versions'
        exe = self.root / 'target/debug' / (name if kind == 'bin' else Path('deps') / (package + '-mixed'))
        exe.parent.mkdir(parents=True, exist_ok=True)
        exe.write_bytes(package.encode())
        exe.chmod(448)
        return dict(reason='compiler-artifact', package_id='path+' + (self.root / folder).as_uri() + f'#{package}@1.0.0', manifest_path=str(self.root / folder / 'Cargo.toml'), features=[], target=dict(name=name, kind=[kind], src_path=str(self.root / folder / ('src/main.rs' if kind == 'bin' else 'tests/mixed_versions.rs'))), profile=dict(test=kind == 'test'), executable=str(exe))

    def runner(self, command, env, path, **kwargs):
        self.commands.append(command)
        if command[0] == 'rustc':
            text = 'rustc 1.98.1\nhost: x86_64-unknown-linux-gnu\n'
        elif command[1] == 'build':
            text = '\n'.join((json.dumps(self.record(package, 'bin')) for package in ['qsh', 'qshd'])) + '\n'
        else:
            text = json.dumps(self.record(command[command.index('-p') + 1], 'test')) + '\n'
        path.write_text(text)
        return 0

    def preparation(self, cases=None):
        with (
            mock.patch.object(peer, 'WORKSPACE', self.root),
            mock.patch.object(peer, 'current_source', return_value='ab' * 20),
            mock.patch.object(peer, 'stream_command', side_effect=self.runner),
            redirect_stdout(io.StringIO()),
        ):
            return peer.prepare(cases or peer.CASES[-2:], {}, self.evidence)

    def test_shared_test_profile_and_one_current_harness_per_selected_package(self):
        prepared = self.preparation()
        pair = next((command for command in self.commands if command[1] == 'build'))
        self.assertIn('--profile', pair)
        self.assertEqual(pair[pair.index('--profile') + 1], 'test')
        self.assertNotIn('--features', pair)
        self.assertNotIn('--all-features', pair)
        harnesses = [command for command in self.commands if '--no-run' in command]
        self.assertEqual(len(harnesses), 1)
        self.assertEqual(harnesses[0][harnesses[0].index('-p') + 1], 'qsh')
        self.assertNotIn('--ignored', harnesses[0])
        self.assertNotIn('--exact', harnesses[0])
        metadata = json.loads((self.evidence / 'prepared.json').read_text())
        self.assertEqual(metadata['source'], 'ab' * 20)
        self.assertEqual(len(metadata['pair']), 2)
        self.assertEqual(len(metadata['harnesses']), 1)
        self.assertEqual(prepared.cases, peer.CASES[-2:])

    def test_full_selection_prepares_each_unique_harness_once(self):
        self.preparation(peer.CASES)
        self.assertEqual([command[command.index('-p') + 1] for command in self.commands if '--no-run' in command], ['qsh', 'qshd'])

    def test_artifact_mismatch_is_refused_before_runtime(self):
        for change in ['missing', 'duplicate', 'package', 'kind', 'profile', 'features', 'source', 'absent', 'nonadjacent']:
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                log = Path(directory) / 'cargo.jsonl'
                record = self.record('qsh', 'bin')
                if change == 'package':
                    record['package_id'] = 'registry+https://example.invalid/index#other@1.0.0'
                if change == 'kind':
                    record['target']['kind'] = ['lib']
                if change == 'profile':
                    record['profile']['test'] = True
                if change == 'features':
                    record['features'] = ['test-darwin-keeper']
                if change == 'source':
                    record['target']['src_path'] = str(self.root / 'foreign.rs')
                if change == 'absent':
                    Path(record['executable']).unlink()
                if change == 'nonadjacent':
                    foreign = self.root / 'foreign/qsh'
                    foreign.parent.mkdir(exist_ok=True)
                    foreign.write_bytes(b'other')
                    foreign.chmod(448)
                    record['executable'] = str(foreign)
                records = [] if change == 'missing' else [record] * (2 if change == 'duplicate' else 1)
                log.write_text('\n'.join(map(json.dumps, records)) + '\n')
                with mock.patch.object(peer, 'WORKSPACE', self.root), self.assertRaises(ValueError):
                    peer.select_artifact(log, 'qsh', 'bin', {})

    def test_changed_source_or_selection_refuses_after_preparation(self):
        prepared = self.preparation()
        with (
            mock.patch.object(peer, 'current_source', return_value='changed'),
            self.assertRaises(ValueError),
        ):
            prepared.verify(peer.CASES[-2:], {})
        with (
            mock.patch.object(peer, 'current_source', return_value='ab' * 20),
            self.assertRaises(ValueError),
        ):
            prepared.verify(peer.CASES, {})
        with (
            mock.patch.object(peer, 'current_source', return_value='ab' * 20),
            self.assertRaises(ValueError),
        ):
            prepared.verify(peer.CASES[-2:], {'RUSTFLAGS': 'changed'})

    def test_preparation_failures_keep_phase_and_never_write_pass_receipt(self):
        for failed in ['pair', 'harness-qsh']:
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                evidence = Path(directory)

                def runner(command, env, path, **kwargs):
                    fail = command[1] == 'build' if failed == 'pair' else '--no-run' in command
                    if fail:
                        path.write_text('compile prefix\n')
                        return 19
                    return self.runner(command, env, path, **kwargs)
                with (
                    mock.patch.object(peer, 'WORKSPACE', self.root),
                    mock.patch.object(peer, 'current_source', return_value='ab' * 20),
                    mock.patch.object(peer, 'stream_command', side_effect=runner),
                    redirect_stdout(io.StringIO()),
                    self.assertRaises(subprocess.CalledProcessError),
                ):
                    peer.prepare(peer.CASES[-2:], {}, evidence)
                self.assertFalse((evidence / 'passed.txt').exists())
                self.assertFalse((evidence / 'prepared.json').exists())
                phases = [json.loads(line) for line in (evidence / 'phases.jsonl').read_text().splitlines()]
                self.assertEqual(phases[-1]['event'], 'end')
                self.assertEqual(phases[-1]['status'], 19)

class StreamingTests(unittest.TestCase):

    def test_prefix_stderr_and_partial_line_are_visible_before_child_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            barrier = root / 'barrier'
            os.mkfifo(barrier)
            log = root / 'output.log'
            visible = threading.Event()

            class Output(io.StringIO):

                def write(self, text):
                    result = super().write(text)
                    if 'error-prefix' in self.getvalue():
                        visible.set()
                    return result
            output = Output()
            results = []
            errors = []
            script = "import os,sys;os.write(1,b'prefix\\n');os.write(2,b'error-prefix\\n');open(sys.argv[1],'rb').read(1);os.write(1,b'last-partial')"

            def run():
                try:
                    results.append(peer.stream_command([sys.executable, '-c', script, str(barrier)], os.environ.copy(), log))
                except BaseException as error:
                    errors.append(error)
            with redirect_stdout(output):
                thread = threading.Thread(target=run)
                thread.start()
                try:
                    self.assertTrue(visible.wait(5))
                    self.assertTrue(thread.is_alive())
                    self.assertIn(b'error-prefix', log.read_bytes())
                finally:
                    if thread.is_alive():
                        with barrier.open('wb') as release:
                            release.write(b'x')
                    thread.join(5)
            self.assertFalse(thread.is_alive())
            self.assertEqual(errors, [])
            self.assertEqual(results, [0])
            self.assertTrue(log.read_bytes().endswith(b'last-partial'))
            self.assertIn('last-partial', output.getvalue())

    def test_timeout_cap_and_interrupt_reap_owned_subprocess_and_keep_prefix(self):
        for failure in ['timeout', 'cap', 'interrupt']:
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                log = root / 'command.log'
                children = []
                original = subprocess.Popen

                def spawn(*args, **kwargs):
                    child = original(*args, **kwargs)
                    children.append(child)
                    return child
                script = "import os,time;os.write(1,b'owned-prefix\\n'+b'x'*2048);time.sleep(30)"
                options = {'timeout': 0.15} if failure == 'timeout' else {'limit': 32}
                context = peer.Evidence('ab' * 20, (), os.environ.copy(), root)
                capture = io.StringIO()
                with (
                    mock.patch.object(peer.subprocess, 'Popen', side_effect=spawn),
                    redirect_stdout(capture),
                ):
                    if failure == 'interrupt':
                        with (
                            mock.patch.object(peer, 'forward', side_effect=KeyboardInterrupt),
                            self.assertRaises(KeyboardInterrupt),
                            context.phase('controlled-command'),
                        ):
                            peer.stream_command([sys.executable, '-c', script], os.environ.copy(), log)
                    else:
                        with (
                            self.assertRaises((subprocess.TimeoutExpired, ValueError)),
                            context.phase('controlled-command'),
                        ):
                            peer.stream_command([sys.executable, '-c', script], os.environ.copy(), log, **options)
                self.assertEqual(len(children), 1)
                self.assertIsNotNone(children[0].poll())
                self.assertTrue(log.read_bytes().startswith(b'owned-prefix'))
                phases = [json.loads(line) for line in (root / 'phases.jsonl').read_text().splitlines()]
                self.assertEqual(phases[-1]['event'], 'end')
                self.assertLess(phases[-1]['status'], 0)
                self.assertTrue((root / 'command.log.failure.json').is_file())
                self.assertFalse((root / 'passed.txt').exists())
                self.assertNotIn('ACCEPTED', capture.getvalue())

class OrchestrationTests(unittest.TestCase):

    def test_runtime_remains_cargo_driven_exact_and_compilation_is_not_a_pass(self):
        name = 'wanted'
        good = f'running 1 test\ntest {name} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s\n'
        for transcript in [good, 'Finished test profile\nExecutable mixed_versions\n']:
            with self.subTest(transcript=transcript), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                commands = []
                capture = io.StringIO()

                def runner(command, env, path):
                    commands.append(command)
                    path.write_text(transcript)
                    return 0
                with (
                    mock.patch.object(peer, 'stream_command', side_effect=runner),
                    mock.patch.object(peer, 'current_source', return_value='ab' * 20),
                    redirect_stdout(capture),
                ):
                    if transcript == good:
                        peer.run_case('qsh', name, True, {}, root)
                    else:
                        with self.assertRaises(ValueError):
                            peer.run_case('qsh', name, True, {}, root)
                self.assertEqual(commands, [['cargo', 'test', '--locked', '-p', 'qsh', '--test', 'mixed_versions', name, '--', '--exact', '--nocapture', '--test-threads=1', '--color=never', '--ignored']])
                self.assertEqual('ACCEPTED' in capture.getvalue(), transcript == good)
                self.assertFalse((root / 'passed.txt').exists())

    def test_main_prepares_before_two_exact_cases_and_only_complete_run_writes_receipt(self):
        for failed in [False, True]:
            with self.subTest(failed=failed), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                evidence = root / 'evidence'
                events = []

                def prepare(cases, env, destination, context):
                    self.assertEqual(cases, peer.CASES[-2:])
                    events.append('prepare')
                    return context

                def run_case(package, name, ignored, env, destination, context):
                    events.append(name)
                    if failed:
                        raise ValueError('controlled runtime failure')
                args = [str(SCRIPT), '--service-only', '--archive', str(root / 'old.tar.gz'), '--evidence', str(evidence)]
                with (
                    mock.patch.object(peer.sys if hasattr(peer, 'sys') else sys, 'argv', args),
                    mock.patch.object(peer, 'current_source', return_value='ab' * 20),
                    mock.patch.object(peer, 'fixture_for_host', return_value=(peer.PREFIX, peer.SHA256, peer.ARCHIVE_SIZE)),
                    mock.patch.object(peer.platform, 'system', return_value='Linux'),
                    mock.patch.object(peer, 'extract_pair', return_value=(root / 'old-qsh', root / 'old-qshd')),
                    mock.patch.object(peer, 'prepare', side_effect=prepare),
                    mock.patch.object(peer, 'run_case', side_effect=run_case),
                    redirect_stdout(io.StringIO()),
                ):
                    if failed:
                        with self.assertRaises(ValueError):
                            peer.main()
                    else:
                        peer.main()
                self.assertEqual(events[0], 'prepare')
                if failed:
                    self.assertFalse((evidence / 'passed.txt').exists())
                else:
                    self.assertEqual(events[1:], [case[1] for case in peer.CASES[-2:]])
                    self.assertEqual((evidence / 'passed.txt').read_text(), '2 selected tests; 2 passed; 0 skipped\n')


STUBBORN_COMMAND = r'''
import os
from pathlib import Path
import signal
import sys
root = Path(sys.argv[1])
variant = sys.argv[2]
read_fd, write_fd = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(read_fd)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (root/'descendant.pid').write_text(str(os.getpid()))
    os.write(write_fd, b'R')
    os.close(write_fd)
    while True:
        signal.pause()
os.close(write_fd)
assert os.read(read_fd, 1) == b'R'
os.close(read_fd)
os.write(1, b'owned-stubborn-ready\n')
if variant == 'already-exited':
    os._exit(0)
while True:
    signal.pause()
'''


GROUP_CLEANUP_CONTROL = r'''
from contextlib import redirect_stdout
import ctypes
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
# Linux orphans belong only to this isolated control process, never to the
# shared unittest runner. macOS launchd reaps its non-child zombies normally.
if sys.platform.startswith('linux'):
    assert ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0
spec = importlib.util.spec_from_file_location('controlled_peer', sys.argv[1])
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
fixture, variant, root = sys.argv[2], sys.argv[3], Path(sys.argv[4])
original = subprocess.Popen
leaders = []
descendant = None
sentinel = original([sys.executable, '-c', 'import time; time.sleep(60)'],
                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, start_new_session=True)

def state(pid):
    if sys.platform.startswith('linux'):
        try:
            return Path(f'/proc/{pid}/stat').read_text().rsplit(')', 1)[1].split()[0]
        except FileNotFoundError:
            return None
    probe = original(['/bin/ps', '-o', 'stat=', '-p', str(pid)],
                     stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    output, _ = probe.communicate(timeout=2)
    return output.decode().strip()[:1] or None

def running(pid):
    return state(pid) not in (None, 'Z', 'X')

def until(predicate, seconds=3):
    deadline = time.monotonic()+seconds
    while not predicate():
        assert time.monotonic() < deadline, 'owned readiness/exit deadline'
        time.sleep(0.01)

def spawn(command, **kwargs):
    assert command[0:2] == ['cargo', 'test']
    child = original([sys.executable, '-u', fixture, str(root), variant], **kwargs)
    leaders.append(child)
    return child

def trigger(text):
    global descendant
    capture.write(text)
    if 'owned-stubborn-ready' in text:
        descendant = int((root/'descendant.pid').read_text())
        assert running(descendant), 'descendant must be live after ignore/barrier'
        if variant == 'already-exited':
            # Observe without waitpid/poll: retain the unreaped leader's PID
            # reservation throughout the group escalation being qualified.
            until(lambda: state(leaders[0].pid) == 'Z')
        else:
            assert running(leaders[0].pid)
        raise KeyboardInterrupt('controlled failure after descendant readiness')

result = {}
capture = io.StringIO()
peer.subprocess.Popen = spawn
peer.forward = trigger
peer.current_source = lambda: 'controlled-source'
peer.current_input = lambda: 'controlled-input'
started = time.monotonic()
try:
    with redirect_stdout(capture):
        try:
            peer.run_case('qsh', 'controlled_group', True, os.environ.copy(), root)
        except KeyboardInterrupt:
            pass
        else:
            raise AssertionError('controlled stream failure was not propagated')
    returned = time.monotonic()-started
    assert len(leaders) == 1
    child = leaders[0]
    assert descendant is not None
    elapsed = time.monotonic()-started
    result = dict(variant=variant, descendant_not_running=not running(descendant),
                  direct_child_reaped=child.returncode is not None,
                  unrelated_sentinel_alive=sentinel.poll() is None,
                  elapsed=elapsed, cleanup_returned=returned, prefix_retained='owned-stubborn-ready' in
                  (root/'controlled_group.log').read_text(),
                  failure_retained=(root/'controlled_group.log.failure.json').is_file(),
                  no_pass=not (root/'passed.txt').exists() and 'ACCEPTED' not in capture.getvalue())
    try:
        until(lambda: not running(descendant))
    finally:
        result['descendant_not_running'] = not running(descendant)
        result['elapsed'] = time.monotonic()-started
    assert result['descendant_not_running'], 'stubborn owned descendant still running'
    assert result['direct_child_reaped']
    try:
        os.waitpid(child.pid, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        raise AssertionError('direct child wait was not consumed')
    assert result['unrelated_sentinel_alive']
    assert returned < 5, 'bounded TERM grace plus KILL/reap exceeded'
    assert elapsed < 5, 'owned descendant exit observation exceeded bound'
    assert result['prefix_retained'] and result['failure_retained'] and result['no_pass']
    phases = [json.loads(line) for line in (root/'phases.jsonl').read_text().splitlines()]
    assert phases[-1]['event'] == 'end' and phases[-1]['failure'] == 'KeyboardInterrupt'
finally:
    # Out-of-band test custody is independent of the function under test.
    # In expected RED, the ignoring descendant is deliberately still alive.
    if descendant is None and (root/'descendant.pid').exists():
        descendant = int((root/'descendant.pid').read_text())
    if descendant is not None:
        if running(descendant):
            os.kill(descendant, signal.SIGKILL)
        until(lambda: not running(descendant))
    for child in leaders:
        if child.returncode is None:
            child.kill()
            child.wait(timeout=2)
    if descendant is not None and sys.platform.startswith('linux'):
        # Only the explicitly recorded adopted descendant can be reaped here.
        until(lambda: os.waitpid(descendant, os.WNOHANG)[0] == descendant)
    sentinel.kill()
    sentinel.wait(timeout=2)
    result['test_owned_fallback_completed'] = True
    print(json.dumps(result, sort_keys=True), flush=True)
'''


class OwnedGroupCleanupTests(unittest.TestCase):
    def test_stubborn_descendant_is_killed_after_leader_exit_without_touching_sentinel(self):
        for variant in ('exit-on-term', 'already-exited'):
            with self.subTest(variant=variant), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fixture = root/'command.py'
                fixture.write_text(STUBBORN_COMMAND)
                worker = root/'control.py'
                worker.write_text(GROUP_CLEANUP_CONTROL)
                result = subprocess.run(
                    [sys.executable, '-u', str(worker), str(SCRIPT), str(fixture), variant, str(root)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, timeout=15,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                receipt = json.loads(result.stdout.splitlines()[-1])
                self.assertTrue(receipt['descendant_not_running'])
                self.assertTrue(receipt['direct_child_reaped'])
                self.assertTrue(receipt['unrelated_sentinel_alive'])
                self.assertTrue(receipt['test_owned_fallback_completed'])
                print('OWNED_GROUP_CLEANUP '+json.dumps(receipt, sort_keys=True), flush=True)


COMPLETION_CONTROL = r'''
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
spec = importlib.util.spec_from_file_location('completion_peer', sys.argv[1])
peer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(peer)
mode, root = sys.argv[2], Path(sys.argv[3])
# Emulate the supported Python3.11 macOS capability boundary on Linux too.
if hasattr(os, 'waitid'):
    del os.waitid
original_spawn, original_waitpid, original_killpg = subprocess.Popen, os.waitpid, os.killpg
old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})
initial_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
children, signals = [], []
injected = False
capture = io.StringIO()
script = "import os,sys;os.write(1,b'completion-prefix\\n');sys.exit(7)"
if mode == 'zero-result':
    script = "import os,signal;os.write(1,b'completion-prefix\\n');os.close(1);os.close(2);signal.pause()"
elif mode == 'consumed':
    script = "import os;os.write(1,b'completion-prefix\\n')"

def spawn(command, **kwargs):
    # The temporary cancellation mask must never be inherited at launch.
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == initial_mask
    child = original_spawn(command, **kwargs)
    children.append(child)
    return child

def waitpid(pid, flags):
    global injected
    result = original_waitpid(pid, flags)
    wanted = (mode == 'zero-result' and result[0] == 0) or (mode == 'consumed' and result[0] == pid)
    if not injected and wanted and children and pid == children[0].pid and flags == os.WNOHANG:
        injected = True
        mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        assert {signal.SIGINT, signal.SIGTERM} <= mask, 'completion probe was not masked'
        # A real cancellation is pending at the exact real syscall result.
        os.kill(os.getpid(), signal.SIGINT if mode == 'zero-result' else signal.SIGTERM)
    return result

def killpg(pid, sig):
    signals.append((pid, sig))
    return original_killpg(pid, sig)

peer.subprocess.Popen, peer.os.waitpid, peer.os.killpg = spawn, waitpid, killpg
peer.current_source = lambda: 'controlled-source'
peer.current_input = lambda: 'controlled-input'
context = peer.Evidence('controlled', (), os.environ.copy(), root)
result = {}
try:
    with redirect_stdout(capture), peer.termination_as_interrupt():
        if mode == 'normal':
            status = peer.stream_command([sys.executable, '-u', '-c', script], os.environ.copy(), root/'command.log', timeout=1)
            assert status == 7
        else:
            try:
                with context.phase('completion-'+mode):
                    peer.stream_command([sys.executable, '-u', '-c', script], os.environ.copy(), root/'command.log', timeout=1)
            except KeyboardInterrupt:
                pass
            else:
                raise AssertionError('boundary cancellation did not propagate')
    assert len(children) == 1 and children[0].returncode is not None
    try:
        original_waitpid(children[0].pid, os.WNOHANG)
    except ChildProcessError:
        pass
    else:
        raise AssertionError('direct child status was not consumed exactly once')
    assert signal.pthread_sigmask(signal.SIG_BLOCK, set()) == initial_mask
    if mode == 'zero-result':
        assert injected and [sig for _, sig in signals] == [signal.SIGTERM, signal.SIGKILL]
    elif mode == 'consumed':
        assert injected and signals == [], 'reaped identity was signaled after completion commit'
    else:
        assert signals == []
    assert not (root/'passed.txt').exists() and 'ACCEPTED' not in capture.getvalue()
    if mode != 'normal':
        assert (root/'command.log.failure.json').is_file()
        phases = [json.loads(line) for line in (root/'phases.jsonl').read_text().splitlines()]
        assert phases[-1]['failure'] == 'KeyboardInterrupt'
    assert 'completion-prefix' in (root/'command.log').read_text()
    result = dict(mode=mode, child_reaped=True, mask_restored=True,
                  no_cancellation_mask_at_launch=True, waitid_absent=True,
                  group_signal_count=len(signals), no_pass=True)
finally:
    for child in children:
        if child.returncode is None:
            child.kill()
            child.wait(timeout=2)
    signal.pthread_sigmask(signal.SIG_SETMASK, old_mask)
    print(json.dumps(result, sort_keys=True), flush=True)
'''


class CompletionBoundaryTests(unittest.TestCase):
    def test_waitid_absent_and_real_cancellation_at_completion_boundaries(self):
        for mode in ('normal', 'zero-result', 'consumed'):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                worker = root/'completion.py'
                worker.write_text(COMPLETION_CONTROL)
                result = subprocess.run(
                    [sys.executable, '-u', str(worker), str(SCRIPT), mode, str(root)],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT, text=True, timeout=12,
                )
                self.assertEqual(result.returncode, 0, result.stdout)
                receipt = json.loads(result.stdout.splitlines()[-1])
                self.assertTrue(receipt['mask_restored'])
                self.assertTrue(receipt['child_reaped'])
                self.assertTrue(receipt['waitid_absent'])
                print('OWNED_COMPLETION '+json.dumps(receipt, sort_keys=True), flush=True)
