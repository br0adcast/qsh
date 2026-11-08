#!/usr/bin/env python3
"""Focused protocol-2 release gate against the reviewed, unchanged v0.5.0 pair.

The committed archive digest is the trust anchor, not a downloaded manifest.
CLI rejection proves zero shell starts; the transport-ensure negative additionally
checks zero connections on the old daemon. Neither proves absence of every
internal transient side effect. A future protocol boundary needs explicit tests.
"""
import argparse
import hashlib
import codecs
import errno
from contextlib import contextmanager
import json
import os
import platform
from pathlib import Path
import re
import selectors
import signal
import subprocess
import tarfile
import tempfile
import time
import tomllib
from urllib.parse import unquote, urlsplit

PREFIX = 'qsh-0.5.0-x86_64-unknown-linux-musl'
URL = 'https://github.com/br0adcast/qsh/releases/download/v0.5.0/' + PREFIX + '.tar.gz'
SHA256 = '2ef2a26a955797a414030ca55b742c3da826805c423523921d08917ed3869d62'
ARCHIVE_SIZE = 6282319
# Explicitly bounded even for a corrupt local input. The pinned digest also
# authenticates all uncompressed member sizes before any data is written.
MAX_ARCHIVE_SIZE = 8 * 1024 * 1024
MAX_MEMBER_SIZE = 32 * 1024 * 1024
MANIFEST_SHA256 = 'fb5b751b3830bbc2aeb6c3d0cde2e23b8b0b9eb26703df2699be8cc1e9930b96'
MANIFEST_SIZE = 1140
DARWIN_FIXTURES = {
    'arm64': ('aarch64-apple-darwin', 'db31e4a123459a9fd8151585301f7e0142c340cd1d9473a8e86d1f5be3f072cb', 5433857),
    'x86_64': ('x86_64-apple-darwin', '38b40b631ebd0a4fce856c7763cf4793c55e625cb404e2a93c4a3d391786d599', 5866506),
}


def fixture_for_host(system=None, machine=None):
    system = platform.system() if system is None else system
    machine = platform.machine() if machine is None else machine
    if system == 'Linux' and machine == 'x86_64':
        return PREFIX, SHA256, ARCHIVE_SIZE
    if system == 'Darwin' and machine in DARWIN_FIXTURES:
        target, digest, size = DARWIN_FIXTURES[machine]
        return 'qsh-0.5.0-' + target, digest, size
    raise ValueError('no pinned released-peer fixture for this platform')


def verify_published_manifest(data, prefix, digest):
    if len(data) != MANIFEST_SIZE or hashlib.sha256(data).hexdigest() != MANIFEST_SHA256:
        raise ValueError('published checksum manifest mismatch')
    entries = [line.split() for line in data.decode('ascii').splitlines()]
    matches = [entry for entry in entries if len(entry) == 2 and entry[1] == prefix + '.tar.gz']
    if matches != [[digest, prefix + '.tar.gz']]:
        raise ValueError('published archive does not match pinned manifest entry')


CASES = (
    ('qsh', 'published_v050_pair_is_a_real_shell_start_positive_control', True),
    ('qsh', 'published_v050_client_cannot_mutate_protocol2_daemon', True),
    ('qsh', 'protocol2_client_cannot_mutate_published_v050_daemon', True),
    ('qsh', 'this_qsh_follows_a_flood_as_screen_repaints_with_the_header_under_aead', False),
    ('qsh', 'current_qsh_pastes_a_megabyte_into_current_daemon', False),
    ('qshd', 'protocol2_client_cannot_allocate_a_connection_on_published_v050', True),
    ('qsh', 'current_ensure_reports_busy_published_v050_without_interrupting_shell', True),
    ('qsh', 'published_v050_force_restarts_account_service_even_after_instance_change', True),
)


def download(destination, fixture=None):
    prefix, _, size = fixture or (PREFIX, SHA256, ARCHIVE_SIZE)
    url = URL.rsplit("/", 1)[0] + "/" + prefix + ".tar.gz"
    subprocess.run(['curl', '--fail', '--location', '--retry', '3',
                    '--connect-timeout', '20', '--max-time', '180',
                    '--max-filesize', str(MAX_ARCHIVE_SIZE),
                    url, '--output', str(destination)], check=True)
    if destination.stat().st_size != size:
        raise ValueError('published archive length mismatch')


def extract_pair(archive, destination, digest=SHA256, prefix=PREFIX):
    if archive.stat().st_size > MAX_ARCHIVE_SIZE:
        raise ValueError('archive exceeds size bound')
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise ValueError('published archive checksum mismatch')
    expected = {prefix + '/' + name for name in
                ('qsh', 'qshd', 'README.md', 'LICENSE', 'CHANGELOG.md')}
    binaries = {prefix + '/qsh', prefix + '/qshd'}
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        seen = set()
        for member in members:
            name = member.name
            if name in seen:
                raise ValueError('duplicate archive member')
            seen.add(name)
            if name == prefix and member.isdir():
                continue
            if name not in expected or not member.isfile() or not 0 < member.size <= MAX_MEMBER_SIZE:
                raise ValueError('unexpected archive layout or member type/size')
        if not binaries <= seen:
            raise ValueError('archive is missing a peer executable')
        # No tar extraction API: write just authenticated regular binary bytes,
        # after validating every member, into a newly created private directory.
        destination.mkdir(mode=0o700)
        for name in ('qsh', 'qshd'):
            member = tar.getmember(prefix + '/' + name)
            with tar.extractfile(member) as source, (destination / name).open('xb') as output:
                output.write(source.read())
            (destination / name).chmod(0o700)
    return destination / 'qsh', destination / 'qshd'


def check_result(name, output, returncode):
    summaries = re.findall(r'^test result: (.*)$', output, re.MULTILINE)
    expected_summary = r'ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s'
    tests = re.findall(r'^test (\S+) \.\.\. (.*)$', output, re.MULTILINE)
    if (returncode != 0 or tests != [(name, 'ok')] or len(summaries) != 1
            or not re.fullmatch(expected_summary, summaries[0])
            or re.search(r'\bskip(?:ped|ping)?\b', output, re.IGNORECASE)):
        raise ValueError(f'{name}: expected exactly one actual pass, no skips, and exit zero')


# Every command is spooled to disk before forwarding, with an explicit bound.
MAX_COMMAND_OUTPUT = 64 * 1024 * 1024
WORKSPACE = Path(__file__).resolve().parents[1]
BUILD_ENVIRONMENT = ('CARGO_BUILD_TARGET', 'CARGO_TARGET_DIR', 'RUSTUP_TOOLCHAIN',
                     'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_JOBS',
                     'OPENSSL_DIR', 'OPENSSL_STATIC', 'AWS_LC_SYS_USE_SYSTEM',
                     'AWS_LC_SYS_CFLAGS', 'CARGO_HOME', 'RUSTUP_HOME',
                     'CARGO_INCREMENTAL', 'RUSTC', 'RUSTC_WRAPPER',
                     'RUSTC_WORKSPACE_WRAPPER', 'MACOSX_DEPLOYMENT_TARGET', 'SDKROOT')


def current_source():
    return subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()


def current_input():
    # Include local tracked changes in local qualification; a CI checkout is
    # normally clean. The digest is evidence, never a published patch payload.
    return hashlib.sha256(subprocess.check_output(['git', 'diff', '--binary', 'HEAD'])).hexdigest()


def forward(text):
    print(text, end='', flush=True)


TERM_GRACE = 2
KILL_REAP_TIMEOUT = 2
CANCELLATION_SIGNALS = {signal.SIGINT, signal.SIGTERM}


class OwnedCleanupError(RuntimeError):
    def __init__(self, report):
        self.report = report
        super().__init__('owned cleanup: '+json.dumps(report, sort_keys=True))


def cleanup_error(operation, error):
    return {'operation': operation, 'failure': type(error).__name__,
            'errno': getattr(error, 'errno', None), 'reason': str(error)[:1024]}


def parse_zombie_group(output, leader):
    if type(leader) is not int or leader <= 0:
        raise ValueError('invalid owned group')
    text = output.decode('ascii')
    if not text or not text.endswith('\n'):
        raise ValueError('incomplete group census')
    rows = text[:-1].split('\n')
    seen = set()
    for row in rows:
        # Documented Darwin ps state modifiers only; an unknown byte refuses
        # classification instead of being discarded or treated as a zombie.
        match = re.fullmatch(r'[ \t]*([1-9][0-9]*)[ \t]+([1-9][0-9]*)[ \t]+(Z[+<AELNSsVWX>]*)[ \t]*', row)
        if match is None:
            raise ValueError('malformed or non-zombie group row')
        pid, group = int(match[1]), int(match[2])
        if pid in seen or group != leader:
            raise ValueError('duplicate or foreign group row')
        seen.add(pid)
    if leader not in seen:
        raise ValueError('owned leader missing from group census')
    return len(seen)


def observe_zombie_group(leader, cleanup_deadline):
    # Reserve observer kill/reap inside its one-second cap and leave the
    # remainder of the unchanged post-KILL deadline for the group leader.
    deadline = min(cleanup_deadline-0.1, time.monotonic()+1)
    read_deadline = deadline-0.1
    report = {'classification': 'unknown', 'rows': 0, 'observer_reaped': False,
              'status': None, 'stdout_bytes': 0, 'stderr_bytes': 0, 'errors': []}
    observer = None
    buffers = {'stdout': bytearray(), 'stderr': bytearray()}
    try:
        if type(leader) is not int or leader <= 0:
            raise ValueError('invalid owned group')
        if time.monotonic() >= read_deadline:
            raise TimeoutError('no group census budget remains')
        environment = os.environ.copy()
        environment.update(LC_ALL='C', COMMAND_MODE='unix2003')
        observer = subprocess.Popen(
            ['/bin/ps', '-x', '-g', str(leader), '-o', 'pid=,pgid=,stat='],
            env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # The observer may inherit cleanup's deferred INT/TERM mask. It is
        # exclusively owned and is killed directly with SIGKILL on failure.
        with selectors.DefaultSelector() as selector:
            selector.register(observer.stdout, selectors.EVENT_READ, ('stdout', 65536))
            selector.register(observer.stderr, selectors.EVENT_READ, ('stderr', 4096))
            while selector.get_map():
                remaining = read_deadline-time.monotonic()
                if remaining <= 0:
                    raise TimeoutError('group census exceeded one second')
                for key, _ in selector.select(remaining):
                    name, cap = key.data
                    data = os.read(key.fileobj.fileno(), min(4096, cap-len(buffers[name])+1))
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    remaining_cap = cap-len(buffers[name])
                    buffers[name].extend(data[:remaining_cap])
                    if len(data) > remaining_cap:
                        raise ValueError('group census '+name+' exceeds bound')
        observer.wait(timeout=max(0, read_deadline-time.monotonic()))
        report['status'] = observer.returncode
        if observer.returncode != 0 or buffers['stderr']:
            raise ValueError('group census failed or wrote stderr')
        report['rows'] = parse_zombie_group(bytes(buffers['stdout']), leader)
        report['classification'] = 'zombie-only'
    except BaseException as error:
        report['errors'].append(cleanup_error('census', error))
    finally:
        if observer is not None:
            if observer.returncode is None:
                try:
                    observer.kill()  # Only this unreaped direct observer PID.
                except OSError as error:
                    report['errors'].append(cleanup_error('observer-kill', error))
                try:
                    observer.wait(timeout=max(0, deadline-time.monotonic()))
                except BaseException as error:
                    report['errors'].append(cleanup_error('observer-reap', error))
            report['status'] = observer.returncode
            report['observer_reaped'] = observer.returncode is not None
            for pipe in (observer.stdout, observer.stderr):
                try:
                    pipe.close()
                except BaseException as error:
                    report['errors'].append(cleanup_error('observer-pipe-close', error))
        report['stdout_bytes'] = len(buffers['stdout'])
        report['stderr_bytes'] = len(buffers['stderr'])
        if report['errors'] or not report['observer_reaped']:
            report['classification'] = 'unknown'
    return report


def stop_owned(child, report=None):
    # Sole-reaper custody reserves the original start_new_session group until
    # final escalation and any census finish. Never poll/reap before KILL.
    if report is None:
        report = {}
    report.update(outcome='unresolved', signals=[], census=None,
                  leader_reaped=False, status=child.returncode, errors=[])
    if child.returncode is not None:
        raise OwnedCleanupError(report)
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, CANCELLATION_SIGNALS)
    try:
        try:
            os.killpg(child.pid, signal.SIGTERM)
            report['signals'].append({'operation': 'TERM', 'errno': None})
        except OSError as error:
            report['signals'].append(cleanup_error('TERM', error))
        try:
            time.sleep(TERM_GRACE)
        except BaseException as error:
            report['errors'].append(cleanup_error('TERM-grace', error))
        deadline = time.monotonic()+KILL_REAP_TIMEOUT
        try:
            os.killpg(child.pid, signal.SIGKILL)
            report['signals'].append({'operation': 'KILL', 'errno': None})
            report['outcome'] = 'group-kill-sent'
        except ProcessLookupError as error:
            report['signals'].append(cleanup_error('KILL', error))
            report['outcome'] = 'group-absent'
        except OSError as error:
            report['signals'].append(cleanup_error('KILL', error))
            if error.errno == errno.EPERM and platform.system() == 'Darwin':
                report['census'] = observe_zombie_group(child.pid, deadline)
                if report['census']['classification'] == 'zombie-only':
                    report['outcome'] = 'observed-zombie-only'
        finally:
            try:
                child.wait(timeout=max(0, deadline-time.monotonic()))
            except BaseException as error:
                report['errors'].append(cleanup_error('leader-reap', error))
            report['status'] = child.returncode
            report['leader_reaped'] = child.returncode is not None
    finally:
        try:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)
        except BaseException as error:
            report['errors'].append(cleanup_error('mask-restore', error))
    if report['outcome'] == 'unresolved' or not report['leader_reaped'] or report['errors']:
        raise OwnedCleanupError(report)
    return report


def stream_command(command, env, path, *, timeout=None, limit=MAX_COMMAND_OUTPUT):
    for primitive in ('waitpid', 'WNOHANG', 'waitstatus_to_exitcode'):
        if not hasattr(os, primitive):
            raise RuntimeError('owned commands require Unix '+primitive)
    if not hasattr(signal, 'pthread_sigmask'):
        raise RuntimeError('owned commands require Unix pthread_sigmask')
    started = time.monotonic()
    child = None
    consumed = False
    completed = False
    completion_mask = None
    decoder = codecs.getincrementaldecoder('utf-8')(errors='replace')
    total = 0
    primary = None
    primary_traceback = None
    secondary = []
    cleanup = None
    log = path.open('xb')
    try:
        child = subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            while True:
                remaining = None if timeout is None else timeout - (time.monotonic() - started)
                if remaining is not None and remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                events = selector.select(0.1 if remaining is None else min(remaining, 0.1))
                if not events:
                    continue
                chunk = os.read(child.stdout.fileno(), 64 * 1024)
                if not chunk:
                    break
                retained = chunk[:max(0, limit-total)]
                log.write(retained)
                log.flush()
                total += len(chunk)
                forward(decoder.decode(retained))
                if total > limit:
                    raise ValueError(f'command output exceeds {limit} byte evidence limit')
        forward(decoder.decode(b'', final=True))
        # EOF need not mean exit; retain the same optional command budget.
        while not completed:
            previous = signal.pthread_sigmask(signal.SIG_BLOCK, CANCELLATION_SIGNALS)
            try:
                pid, status = os.waitpid(child.pid, os.WNOHANG)
                if pid == child.pid:
                    # From this consuming boundary onward, no exception or
                    # finally path may signal the old numeric group ID.
                    completion_mask = previous
                    consumed = True
                    child.returncode = os.waitstatus_to_exitcode(status)
                    completed = True
            finally:
                if not consumed:
                    # A pending signal here still owns the unreaped group
                    # and must enter the failure/escalation path below.
                    signal.pthread_sigmask(signal.SIG_SETMASK, previous)
            if not completed:
                remaining = None if timeout is None else timeout-(time.monotonic()-started)
                if remaining is not None and remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                time.sleep(0.05 if remaining is None else min(remaining, 0.05))
    except BaseException as error:
        primary, primary_traceback = error, error.__traceback__
        if child is not None and not consumed:
            cleanup = {}
            try:
                stop_owned(child, cleanup)
            except BaseException as cleanup_failure:
                secondary.append(cleanup_failure)
                cleanup.setdefault('outcome', 'unresolved')
                cleanup.setdefault('errors', []).append(cleanup_error('cleanup', cleanup_failure))
    finally:
        # Housekeeping and receipt failures are secondary to the command's
        # original exception. Nothing here can restart group escalation.
        for pipe in (None if child is None else child.stdout, log):
            if pipe is not None:
                try:
                    pipe.close()
                except BaseException as error:
                    if primary is None:
                        primary, primary_traceback = error, error.__traceback__
                    else:
                        secondary.append(error)
        if consumed:
            try:
                # Restore outside the escalation scope after completion commit.
                signal.pthread_sigmask(signal.SIG_SETMASK, completion_mask)
            except BaseException as error:
                if primary is None:
                    primary, primary_traceback = error, error.__traceback__
                else:
                    secondary.append(error)
    if primary is not None:
        primary.returncode = None if child is None else child.returncode
        record = {
            'failure': type(primary).__name__, 'reason': str(primary),
            'status': primary.returncode,
            'leader_reaped': child is not None and child.returncode is not None,
            'output_bytes': min(total, limit), 'cleanup': cleanup,
            'secondary_errors': [cleanup_error('secondary', error) for error in secondary]}
        try:
            path.with_suffix(path.suffix+'.failure.json').write_text(json.dumps(record, sort_keys=True)+'\n')
        except BaseException as error:
            secondary.append(error)
        if secondary:
            primary.add_note('Owned command secondary failures: '+json.dumps(
                [cleanup_error('secondary', error) for error in secondary], sort_keys=True))
            raise primary.with_traceback(primary_traceback) from secondary[0]
        raise primary.with_traceback(primary_traceback)
    return child.returncode


class Evidence:
    def __init__(self, source, cases, env, directory):
        self.source = source
        self.input_digest = current_input()
        self.cases = tuple(cases)
        self.selection = tuple(CASES)
        self.environment = {key: env.get(key) for key in BUILD_ENVIRONMENT}
        self.directory = directory
        self.phases = []
        self.artifacts = {}

    def verify(self, cases, env):
        if (current_source() != self.source or current_input() != self.input_digest
                or tuple(cases) != self.cases
                or tuple(CASES) != self.selection
                or {key: env.get(key) for key in BUILD_ENVIRONMENT} != self.environment):
            raise ValueError('source, selection or build configuration changed after preparation')

    def emit(self, record):
        record = dict(source=self.source, platform=platform.system(),
                      machine=platform.machine(), **record)
        with (self.directory/'phases.jsonl').open('a') as log:
            log.write(json.dumps(record, sort_keys=True)+'\n')
            log.flush()
        print('PHASE '+json.dumps(record, sort_keys=True), flush=True)
        self.phases.append(record)

    @contextmanager
    def phase(self, name, command=None):
        started = time.monotonic()
        self.emit(dict(phase=name, event='start', monotonic=started, command=command))
        outcome = {'status': None}
        try:
            yield outcome
        except BaseException as error:
            self.emit(dict(phase=name, event='end', elapsed=time.monotonic()-started,
                           status=getattr(error, 'returncode', outcome['status']), failure=type(error).__name__))
            raise
        else:
            self.emit(dict(phase=name, event='end', elapsed=time.monotonic()-started, status=0))

    def command(self, name, command, env):
        self.verify(self.cases, env)
        path = self.directory/(name+'.log')
        with self.phase(name, command):
            status = stream_command(command, env, path)
            if status != 0:
                raise subprocess.CalledProcessError(status, command)
        return path


def select_artifact(log, package, kind, env, *, optional=False):
    folder = WORKSPACE/('cli' if package == 'qsh' else 'qshd')
    manifest = (folder/'Cargo.toml').resolve(strict=True)
    name = package if kind == 'bin' else 'mixed_versions'
    candidates = []
    for line in log.read_text(errors='replace').splitlines():
        try:
            record = json.loads(line)
        except ValueError:
            continue  # Cargo's combined stderr includes rendered progress.
        if (isinstance(record, dict) and record.get('reason') == 'compiler-artifact'
                and record.get('target', {}).get('name') == name
                and record.get('target', {}).get('kind') == [kind]
                and Path(record.get('manifest_path', '')).resolve() == manifest):
            candidates.append(record)
    if not candidates and optional:
        return None
    if len(candidates) != 1:
        raise ValueError(f'{package}/{name}: expected one current Cargo artifact')
    record = candidates[0]
    package_manifest = tomllib.loads(manifest.read_text())['package']
    version = package_manifest['version']
    if isinstance(version, dict):
        version = tomllib.loads((WORKSPACE/'Cargo.toml').read_text())['workspace']['package']['version']
    identity = record.get('package_id', '')
    parsed = urlsplit(identity.removeprefix('path+'))
    expected_fragment = {package+'@'+version}
    if folder.name == package:
        expected_fragment.add(version)
    source = folder/('src/main.rs' if kind == 'bin' else 'tests/mixed_versions.rs')
    executable = Path(record.get('executable') or '')
    target_root = Path(env.get('CARGO_TARGET_DIR') or WORKSPACE/'target').resolve()
    target = env.get('CARGO_BUILD_TARGET')
    profile_dir = target_root/target/'debug' if target else target_root/'debug'
    if (package_manifest['name'] != package or not identity.startswith('path+file:')
            or parsed.scheme != 'file' or Path(unquote(parsed.path)).resolve() != folder.resolve()
            or parsed.fragment not in expected_fragment or record.get('features') != []
            or record.get('profile', {}).get('test') is not (kind == 'test')
            or Path(record.get('target', {}).get('src_path', '')).resolve() != source.resolve()
            or not executable.is_absolute() or not executable.is_file()
            or not os.access(executable, os.X_OK)
            or executable.resolve().parent != (profile_dir if kind == 'bin' else profile_dir/'deps').resolve()
            or (kind == 'bin' and executable.name != package)):
        raise ValueError(f'{package}/{name}: unexpected current artifact identity or location')
    return dict(package=package, target=name, kind=kind, command_log=log.name,
                executable=str(executable), bytes=executable.stat().st_size,
                sha256=hashlib.sha256(executable.read_bytes()).hexdigest(), record=record)


def prepare(cases, env, evidence, context=None):
    context = context or Evidence(current_source(), cases, env, evidence)
    context.verify(cases, env)
    toolchain = context.command('toolchain', ['rustc', '-vV'], env).read_text()
    if not re.search(r'^host: \S+$', toolchain, re.MULTILINE):
        raise ValueError('rustc did not identify its actual host')
    pair = context.command('pair', ['cargo', 'build', '--locked', '--profile', 'test',
                           '-p', 'qsh', '-p', 'qshd', '--bins',
                           '--message-format=json-render-diagnostics'], env)
    with context.phase('pair-artifacts'):
        pair_records = {package: select_artifact(pair, package, 'bin', env)
                        for package in ('qsh', 'qshd')}
    harnesses = []
    for package in dict.fromkeys(case[0] for case in cases):
        log = context.command('harness-'+package, ['cargo', 'test', '--locked', '-p', package,
                              '--test', 'mixed_versions', '--no-run',
                              '--message-format=json-render-diagnostics'], env)
        with context.phase('harness-artifacts-'+package):
            harnesses.append(select_artifact(log, package, 'test', env))
            # A test preparation may refresh its adjacent ordinary binary. Prefer
            # its latest current command record, never a guessed deps/cache path.
            for selected in ('qsh', 'qshd'):
                record = select_artifact(log, selected, 'bin', env, optional=True)
                if record is not None:
                    pair_records[selected] = record
    context.verify(cases, env)
    pair = list(pair_records.values())
    if Path(pair[0]['executable']).parent != Path(pair[1]['executable']).parent:
        raise ValueError('current pair is not adjacent')
    for artifact in pair+harnesses:
        if hashlib.sha256(Path(artifact['executable']).read_bytes()).hexdigest() != artifact['sha256']:
            raise ValueError('prepared artifact changed during preparation')
    context.artifacts = dict(pair=pair, harnesses=harnesses)
    (evidence/'prepared.json').write_text(json.dumps(dict(source=context.source,
        tracked_input_sha256=context.input_digest, cases=cases, profile='test', toolchain=toolchain,
        target=env.get('CARGO_BUILD_TARGET') or re.search(r'^host: (\S+)$', toolchain, re.MULTILINE)[1],
        explicit_features=[], configuration=context.environment, phases=context.phases,
        **context.artifacts), indent=2)+'\n')
    return context


def run_case(package, name, ignored, env, evidence, context=None):
    command = ['cargo', 'test', '--locked', '-p', package, '--test', 'mixed_versions',
               name, '--', '--exact', '--nocapture', '--test-threads=1', '--color=never']
    if ignored:
        command.append('--ignored')
    context = context or Evidence(current_source(), ((package, name, ignored),), env, evidence)
    context.verify(context.cases, env)
    if (package, name, ignored) not in context.cases:
        raise ValueError('runtime case differs from prepared selection')
    with context.phase('runtime-'+name, command) as outcome:
        path = evidence/(name+'.log')
        status = stream_command(command, env, path)
        outcome['status'] = status
        check_result(name, path.read_text(errors='replace'), status)
    context.verify(context.cases, env)
    print(f'ACCEPTED {package}::{name}: 1 passed; exit 0', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='already downloaded archive; still verified against the committed digest')
    parser.add_argument('--evidence', type=Path, required=True, help='new evidence directory outside the source tree')
    parser.add_argument('--service-only', action='store_true', help='run the two actual personal-service scenarios in an existing native lane')
    args = parser.parse_args()
    fixture = fixture_for_host()
    prefix, digest, _ = fixture
    fixture_url = URL.rsplit("/", 1)[0] + "/" + prefix + ".tar.gz"
    cases = CASES[-2:] if args.service_only else CASES
    source = current_source()
    args.evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
    (args.evidence / 'identity.txt').write_text(f'source={source}\nfixture={fixture_url}\nsha256={digest}\n')
    print(f'Source: {source}\nFixture SHA-256: {digest}', flush=True)
    with tempfile.TemporaryDirectory(prefix='qsh-released-peer-') as runtime:
        root = Path(runtime)
        archive = args.archive
        env = os.environ.copy()
        env['CARGO_HOME'] = env.get('CARGO_HOME', str(Path.home() / '.cargo'))
        env['RUSTUP_HOME'] = env.get('RUSTUP_HOME', str(Path.home() / '.rustup'))
        context = Evidence(source, cases, env, args.evidence)
        with context.phase('fixture'):
            if archive is None:
                archive = root / 'published.tar.gz'
                download(archive, fixture)
            if platform.system() == 'Darwin':
                manifest = root / 'SHA256SUMS'
                subprocess.run(['curl', '--fail', '--location', '--retry', '3',
                                '--connect-timeout', '20', '--max-time', '180', '--max-filesize', '4096',
                                URL.rsplit('/', 1)[0] + '/SHA256SUMS', '--output', str(manifest)], check=True)
                verify_published_manifest(manifest.read_bytes(), prefix, digest)
            old_qsh, old_qshd = extract_pair(archive, root / 'old', digest, prefix)
        for key, folder in (('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'), ('XDG_CACHE_HOME', 'cache')):
            (root / folder).mkdir(mode=0o700)
            env[key] = str(root / folder)
        env.update(HISTFILE='/dev/null', QSH_OLD_QSH=str(old_qsh), QSH_OLD_QSHD=str(old_qshd), CARGO_TERM_COLOR='never')
        env.pop('SSH_AUTH_SOCK', None)
        env.pop('SSH_AGENT_PID', None)
        # HOME changes do not alter the captured compiler/build configuration.
        context = prepare(cases, env, args.evidence, context)
        for case in cases:
            run_case(*case, env, args.evidence, context)
    (args.evidence / 'passed.txt').write_text(f'{len(cases)} selected tests; {len(cases)} passed; 0 skipped\n')


@contextmanager
def termination_as_interrupt():
    def interrupt(signum, frame):
        raise KeyboardInterrupt('termination requested')
    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == '__main__':
    with termination_as_interrupt():
        main()
