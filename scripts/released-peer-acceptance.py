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
import math
import os
import platform
from pathlib import Path
import re
import selectors
import shutil
import stat
import uuid
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
    path.with_suffix(path.suffix+'.completion.json').write_text(json.dumps(dict(
        status=child.returncode, child_reaped=consumed, output_eof=True, mask_restored=True), sort_keys=True)+'\n')
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
            or record.get('profile', {}).get('opt_level') != '1'
            or Path(record.get('target', {}).get('src_path', '')).resolve() != source.resolve()
            or not executable.is_absolute() or not executable.is_file()
            or not os.access(executable, os.X_OK)
            or executable.resolve().parent != (profile_dir if kind == 'bin' else profile_dir/'deps').resolve()
            or (kind == 'bin' and executable.name != package)):
        raise ValueError(f'{package}/{name}: unexpected current artifact identity or location')
    identity = file_identity(executable, MAX_ARTIFACT_BYTES)
    return dict(package=package, target=name, kind=kind, command_log=log.name,
                executable=str(executable), bytes=identity['bytes'],
                sha256=identity['sha256'], record=record)


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
        if file_identity(artifact['executable'], MAX_ARTIFACT_BYTES)['sha256'] != artifact['sha256']:
            raise ValueError('prepared artifact changed during preparation')
    context.artifacts = dict(pair=pair, harnesses=harnesses)
    artifact_custody(context.artifacts, env, evidence)
    (evidence/'prepared.json').write_text(json.dumps(dict(source=context.source,
        tracked_input_sha256=context.input_digest, cases=cases, profile='test', toolchain=toolchain,
        target=env.get('CARGO_BUILD_TARGET') or re.search(r'^host: (\S+)$', toolchain, re.MULTILINE)[1],
        explicit_features=[], configuration=context.environment, phases=context.phases,
        **context.artifacts), indent=2)+'\n')
    return context


def run_case(package, name, ignored, env, evidence, context=None):
    if context is None or not hasattr(context, 'artifacts'):
        raise ValueError('runtime requires verified prepared artifacts')
    context.verify(context.cases, env)
    if (package, name, ignored) not in context.cases:
        raise ValueError('runtime case differs from prepared selection')
    if hasattr(context, 'validate_prepared'):
        context.validate_prepared()
    else:
        validate_artifacts(context.artifacts, env)
    harnesses = [a for a in context.artifacts['harnesses'] if a['package'] == package]
    if len(harnesses) != 1:
        raise ValueError('runtime requires one exact prepared harness')
    command = [harnesses[0]['executable'], name, '--exact', '--nocapture',
               '--test-threads=1', '--color=never']
    if ignored:
        command.append('--ignored')
    with context.phase('runtime-'+name, command) as outcome:
        path = evidence/(name+'.log')
        status = stream_command(command, env, path)
        outcome['status'] = status
        check_result(name, path.read_text(errors='replace'), status)
    context.verify(context.cases, env)
    if hasattr(context, 'validate_prepared'):
        context.validate_prepared()
    print(f'ACCEPTED {package}::{name}: 1 passed; exit 0', flush=True)


BUNDLE_SCHEMA = 2
CI_IDENTITY = ('GITHUB_REPOSITORY', 'GITHUB_RUN_ID', 'GITHUB_JOB', 'GITHUB_RUN_ATTEMPT')
MAX_ARTIFACT_BYTES = 512 * 1024 * 1024
# Two bundle pathname spellings, each up to 4095 filesystem bytes and up to
# six JSON bytes per escaped byte: 49140 bytes, leaving >16KiB for the fixed
# bundle/parent/runtime identity fields. This is bounded metadata, not an
# artifact-size allowance; supported filesystem PATH_MAX still applies.
MAX_ALLOCATION_RECORD_BYTES = 64 * 1024


def directory_identity(path):
    path = Path(path).absolute()
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700 or path.is_symlink()):
        raise ValueError('prepared backing is not a private owned directory')
    return dict(path=str(path), resolved=str(path.resolve(strict=True)),
                device=info.st_dev, inode=info.st_ino, uid=info.st_uid, mode=stat.S_IMODE(info.st_mode))


def file_identity(path, limit=MAX_ARTIFACT_BYTES):
    path = Path(path).absolute()
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or before.st_mode & 0o022 or before.st_size > limit):
        raise ValueError('prepared file is not bounded regular owned backing')
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        opened = os.fstat(source.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError('prepared file changed while opening')
        for chunk in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(chunk)
        after = os.fstat(source.fileno())
    facts = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns, st.st_mode, st.st_uid)
    if facts(before) != facts(after) or facts(path.lstat()) != facts(after):
        raise ValueError('prepared file changed while hashing')
    return dict(path=str(path), resolved=str(path.resolve(strict=True)), device=after.st_dev,
                inode=after.st_ino, uid=after.st_uid, mode=stat.S_IMODE(after.st_mode),
                bytes=after.st_size, mtime_ns=after.st_mtime_ns, ctime_ns=after.st_ctime_ns,
                sha256=digest.hexdigest())


def atomic_record(path, record):
    temporary = path.with_name('.'+path.name+'-'+uuid.uuid4().hex)
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(record, output, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, path)


def create_bundle(path):
    path = Path(path).absolute()
    path = path.parent.resolve(strict=True) / path.name
    if path.is_relative_to(WORKSPACE.resolve()):
        raise ValueError('prepared bundle must be outside the source tree')
    path.mkdir(mode=0o700)
    directory_identity(path)
    return path


def runtime_parent():
    if platform.system() not in ('Linux', 'Darwin'):
        raise ValueError('unsupported short runtime platform')
    return Path('/tmp').resolve(strict=True)


def shared_parent_identity(path):
    path = Path(path).absolute()
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o1777 or path.is_symlink()):
        raise ValueError('short runtime parent must be root-owned sticky shared backing')
    return dict(path=str(path), resolved=str(path.resolve(strict=True)),
                device=info.st_dev, inode=info.st_ino, uid=info.st_uid, mode=stat.S_IMODE(info.st_mode))


def validate_runtime_budget(root):
    # Selected fixtures add at most 45 bytes to TMPDIR on Darwin (30 Linux),
    # including tempfile's .tmp+six chars and a ten-digit positive PID.
    for spelling in (Path(root).absolute(), Path(root).resolve(strict=True)):
        if len(os.fsencode(spelling / 'tmp')) > 58:
            raise ValueError('selected fixture runtime TMPDIR exceeds 58-byte socket budget')


def validate_allocation(allocation):
    if set(allocation) != {'bundle', 'parent', 'root'}:
        raise ValueError('malformed short runtime allocation')
    parent, root = allocation['parent'], allocation['root']
    path = Path(root['path'])
    if (Path(parent['path']) != runtime_parent()
            or shared_parent_identity(parent['path']) != parent
            or path.parent != Path(parent['path'])
            or not re.fullmatch('q5-[0-9a-f]{32}', path.name)
            or directory_identity(path) != root):
        raise ValueError('short runtime allocation binding changed')
    validate_runtime_budget(path)
    return path


def allocation_record(bundle):
    marker = bundle / 'runtime-allocation.json'
    file_identity(marker, MAX_ALLOCATION_RECORD_BYTES)
    descriptor = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        data = source.read(MAX_ALLOCATION_RECORD_BYTES + 1)
    if len(data) > MAX_ALLOCATION_RECORD_BYTES:
        raise ValueError('allocation record exceeds bounded metadata ceiling')
    allocation = json.loads(data)
    if allocation.get('bundle') != directory_identity(bundle):
        raise ValueError('runtime allocation belongs to a different bundle')
    validate_allocation(allocation)
    return allocation


def allocate_runtime(bundle):
    if (any(not hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC'))
            or os.mkdir not in os.supports_dir_fd or os.open not in os.supports_dir_fd):
        raise ValueError('platform lacks short runtime allocation primitives')
    captured_bundle = directory_identity(bundle)
    descriptors, primary = [], None
    try:
        bundle_fd = open_captured_directory(bundle, captured_bundle)
        descriptors.append(bundle_fd)
        parent = shared_parent_identity(runtime_parent())
        parent_fd = open_captured_directory(parent['path'], parent, shared=True)
        descriptors.append(parent_fd)
        if shared_parent_identity(runtime_parent()) != parent:
            raise ValueError('short runtime parent changed before allocation')
        name = 'q5-'+uuid.uuid4().hex
        # No ambient TMPDIR, alternate parent, collision reuse or fallback.
        os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        root = Path(parent['path']) / name
        allocation = dict(bundle=captured_bundle, parent=parent, root=directory_identity(root))
        runtime_fd = open_captured_directory(name, allocation['root'], dir_fd=parent_fd)
        descriptors.append(runtime_fd)
        # Record retained backing immediately; complete remains unpublished.
        if directory_identity(bundle) != captured_bundle:
            raise ValueError('bundle changed during runtime allocation')
        atomic_record_at(bundle_fd, 'runtime-allocation.json', allocation)
        validate_allocation(allocation)
        if directory_identity(bundle) != captured_bundle:
            raise ValueError('bundle changed after runtime allocation')
        return allocation
    except BaseException as error:
        if 'allocation' in locals():
            error.runtime_allocation = allocation
        primary = error
        raise
    finally:
        errors = []
        while descriptors:
            descriptor = descriptors.pop()
            try:
                os.close(descriptor)
            except BaseException as error:
                errors.append(error)
        if errors:
            if primary is not None:
                for error in errors: primary.add_note('allocation descriptor close failed: '+type(error).__name__)
            else:
                if 'allocation' in locals():
                    errors[0].runtime_allocation = allocation
                raise errors[0]


def artifact_custody(artifacts, env, directory):
    for artifact in artifacts['pair'] + artifacts['harnesses']:
        artifact['identity'] = file_identity(artifact['executable'])
        artifact['command_path'] = str((directory / artifact['command_log']).absolute())
        artifact['command_identity'] = file_identity(artifact['command_path'], MAX_COMMAND_OUTPUT)
    validate_artifacts(artifacts, env)


def validate_artifacts(artifacts, env):
    if (len(artifacts['pair']) != 2
            or {a['package'] for a in artifacts['pair']} != {'qsh', 'qshd'}
            or len({a['package'] for a in artifacts['harnesses']}) != len(artifacts['harnesses'])):
        raise ValueError('ambiguous prepared artifact set')
    if (any(a['kind'] != 'bin' for a in artifacts['pair'])
            or any(a['kind'] != 'test' for a in artifacts['harnesses'])):
        raise ValueError('prepared normal binary and harness roles differ')
    for artifact in artifacts['pair'] + artifacts['harnesses']:
        if (file_identity(artifact['executable']) != artifact['identity']
                or file_identity(artifact['command_path'], MAX_COMMAND_OUTPUT) != artifact['command_identity']):
            raise ValueError('prepared artifact or Cargo record backing changed')
        selected = select_artifact(Path(artifact['command_path']), artifact['package'], artifact['kind'], env)
        if any(selected[key] != artifact[key] for key in selected):
            raise ValueError('prepared Cargo artifact identity changed')
    if len({Path(a['executable']).resolve().parent for a in artifacts['pair']}) != 1:
        raise ValueError('prepared pair is not adjacent')


def validate_preparation_phases(record, cases):
    expected = [('toolchain', ['rustc', '-vV']),
                ('pair', ['cargo', 'build', '--locked', '--profile', 'test', '-p', 'qsh', '-p', 'qshd',
                          '--bins', '--message-format=json-render-diagnostics']),
                ('pair-artifacts', None)]
    for package in dict.fromkeys(case[0] for case in cases):
        expected += [('harness-'+package, ['cargo', 'test', '--locked', '-p', package, '--test',
                                          'mixed_versions', '--no-run', '--message-format=json-render-diagnostics']),
                     ('harness-artifacts-'+package, None)]
    phases = record['phases']
    if phases and phases[0].get('phase') == 'fixture':
        expected.insert(0, ('fixture', None))
    if len(phases) != 2 * len(expected):
        raise ValueError('incomplete preparation phase receipts')
    for index, (name, command) in enumerate(expected):
        start, end = phases[2*index:2*index+2]
        elapsed = end.get('elapsed')
        if (start.get('phase') != name or start.get('event') != 'start' or start.get('command') != command
                or end.get('phase') != name or end.get('event') != 'end'
                or type(end.get('status')) is not int or end['status'] != 0
                or type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0
                or any(phase.get(key) != record[key] for phase in (start, end)
                       for key in ('source', 'platform', 'machine'))):
            raise ValueError('preparation phase identity or completion differs')


def seal_bundle(context, bundle, runtime, old_pair, env):
    root = directory_identity(bundle)
    runtime = Path(runtime)
    allocation = allocation_record(bundle)
    if runtime != Path(allocation['root']['path']):
        raise ValueError('prepared runtime differs from its captured allocation')
    context.verify(context.cases, env)
    records = bundle / 'records'
    records.mkdir(mode=0o700)
    for artifact in context.artifacts['pair'] + context.artifacts['harnesses']:
        source = Path(artifact['command_path'])
        destination = records / source.name
        if not destination.exists():
            # Logs were already output-bounded by the owned command runner.
            with destination.open('xb') as output:
                output.write(source.read_bytes())
            destination.chmod(0o600)
        artifact['command_path'] = str(destination)
        artifact['command_identity'] = file_identity(destination, MAX_COMMAND_OUTPUT)
    validate_artifacts(context.artifacts, env)
    if [Path(p) for p in old_pair] != [runtime / 'old/qsh', runtime / 'old/qshd']:
        raise ValueError('released pair is outside owned backing')
    shim = runtime / 'no-build'
    shim.write_text('#!/bin/sh\nprintf "%s\\n" "prepared runtime forbids build fallback" >&2\nexit 125\n')
    shim.chmod(0o700)
    toolchain = (context.directory / 'toolchain.log').read_text()
    host = re.search(r'^host: (\S+)$', toolchain, re.MULTILINE)
    if host is None:
        raise ValueError('prepared toolchain lacks a host')
    target = env.get('CARGO_BUILD_TARGET') or host[1]
    machine = {'arm64': 'aarch64'}.get(platform.machine(), platform.machine())
    if target.split('-')[0] != machine:
        raise ValueError('prepared target does not match native machine')
    fixture = fixture_for_host()
    record = dict(schema=BUNDLE_SCHEMA, identity=uuid.uuid4().hex, root=root, allocation=allocation,
                  source=context.source, tracked_input_sha256=context.input_digest,
                  cases=context.cases, registry=CASES, environment=context.environment,
                  ci={key: env.get(key) for key in CI_IDENTITY}, platform=platform.system(),
                  machine=platform.machine(), target=target, toolchain=toolchain,
                  profile='test', explicit_features=[], phases=context.phases,
                  artifacts=context.artifacts,
                  fixture=dict(prefix=fixture[0], archive_sha256=fixture[1],
                               files=[file_identity(path) for path in old_pair]),
                  shim=file_identity(shim),
                  backing=[directory_identity(path) for path in
                           [runtime, records] + [runtime / name for name in ('home', 'config', 'cache', 'tmp', 'old')]])
    validate_preparation_phases(record, context.cases)
    # Complete is the last publication, never an executable partial preparation.
    atomic_record(bundle / 'complete.json', record)
    return record


def load_record(bundle):
    directory_identity(bundle)
    marker = bundle / 'complete.json'
    file_identity(marker, 4 * 1024 * 1024)
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError('ambiguous prepared marker')
            result[key] = value
        return result
    return json.loads(marker.read_text(), object_pairs_hook=unique)


def verify_bundle(bundle, record, cases, env, context):
    if (record.get('schema') != BUNDLE_SCHEMA
            or not re.fullmatch('[0-9a-f]{32}', record.get('identity', ''))
            or record.get('root') != directory_identity(bundle)
            or record.get('source') != current_source()
            or record.get('tracked_input_sha256') != current_input()
            or record.get('cases') != [list(case) for case in cases]
            or record.get('registry') != [list(case) for case in CASES]
            or record.get('environment') != {key: env.get(key) for key in BUILD_ENVIRONMENT}
            or record.get('ci') != {key: env.get(key) for key in CI_IDENTITY}
            or record.get('platform') != platform.system() or record.get('machine') != platform.machine()
            or record.get('profile') != 'test' or record.get('explicit_features') != []):
        raise ValueError('foreign or stale prepared bundle binding')
    validate_preparation_phases(record, cases)
    toolchain = context.command('runtime-toolchain-'+str(len(context.phases)), ['rustc', '-vV'], env).read_text()
    host = re.search(r'^host: (\S+)$', toolchain, re.MULTILINE)
    if (toolchain != record['toolchain'] or host is None
            or record['target'] != (env.get('CARGO_BUILD_TARGET') or host[1])):
        raise ValueError('prepared toolchain or target changed')
    if allocation_record(bundle) != record['allocation']:
        raise ValueError('prepared runtime allocation marker changed')
    runtime = validate_allocation(record['allocation'])
    expected_backing = [runtime, bundle / 'records'] + [runtime / name for name in ('home', 'config', 'cache', 'tmp', 'old')]
    if [item['path'] for item in record['backing']] != list(map(str, expected_backing)):
        raise ValueError('foreign prepared backing paths')
    for artifact in record['artifacts']['pair'] + record['artifacts']['harnesses']:
        name = artifact['command_log']
        if name not in ('pair.log', 'harness-qsh.log', 'harness-qshd.log') or artifact['command_path'] != str(bundle / 'records' / name):
            raise ValueError('foreign prepared Cargo log path')
    for backing in record['backing']:
        if directory_identity(backing['path']) != backing:
            raise ValueError('prepared directory backing changed')
    if record['backing'][0] != record['allocation']['root']:
        raise ValueError('prepared runtime backing identity is foreign')
    fixture = fixture_for_host()
    if (record['fixture']['prefix'], record['fixture']['archive_sha256']) != fixture[:2]:
        raise ValueError('prepared released fixture authority changed')
    for path, captured in zip((runtime / 'old/qsh', runtime / 'old/qshd'), record['fixture']['files'], strict=True):
        if file_identity(path) != captured:
            raise ValueError('prepared released fixture changed')
    if file_identity(runtime / 'no-build') != record['shim']:
        raise ValueError('prepared build refusal backing changed')
    if {a['package'] for a in record['artifacts']['harnesses']} != {case[0] for case in cases}:
        raise ValueError('prepared harness selection differs from actual cases')
    validate_artifacts(record['artifacts'], env)


def claim_bundle(bundle, record):
    if directory_identity(bundle) != record['root']:
        raise ValueError('refusing execution claim on substituted backing')
    try:
        descriptor = os.open(bundle / 'execution.claim', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise ValueError('prepared execution is already claimed') from error
    with os.fdopen(descriptor, 'w') as output:
        output.write(record['identity']+'\n')
    return file_identity(bundle / 'execution.claim')


class CleanupUnresolved(ValueError):
    """Owned payload/namespace completion could not be established."""


def require_captured_directory(info, captured):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700
            or any(actual != captured[key] for key, actual in
                   [('device', info.st_dev), ('inode', info.st_ino),
                    ('uid', info.st_uid), ('mode', stat.S_IMODE(info.st_mode))])):
        raise CleanupUnresolved('cleanup descriptor differs from captured directory')


def open_captured_directory(path, captured, *, dir_fd=None, shared=False):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                         dir_fd=dir_fd)
    try:
        if shared:
            info = os.fstat(descriptor)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o1777
                    or (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) !=
                       (captured['device'], captured['inode'], captured['uid'], captured['mode'])):
                raise CleanupUnresolved('shared parent descriptor differs from captured directory')
        else:
            require_captured_directory(os.fstat(descriptor), captured)
    except BaseException as primary:
        try:
            closing, descriptor = descriptor, None
            os.close(closing)
        except BaseException as secondary:
            primary.add_note('cleanup descriptor close failed: '+type(secondary).__name__)
        raise
    return descriptor


def atomic_record_at(directory_fd, name, record):
    # The already verified directory capability, not a newly resolved ancestor,
    # supplies authority for every marker creation and atomic publication.
    temporary = '.'+name+'-'+uuid.uuid4().hex
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=directory_fd)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(record, output, sort_keys=True)
        output.write('\n')
        output.flush()
        os.fsync(output.fileno())
    os.replace(temporary, name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)


def verify_cleanup_namespace(bundle, record, bundle_fd, runtime_fd=None, parent_fd=None):
    require_captured_directory(os.fstat(bundle_fd), record['root'])
    if record['allocation']['bundle'] != record['root']:
        raise CleanupUnresolved('runtime allocation belongs to a different captured bundle')
    if runtime_fd is not None:
        require_captured_directory(os.fstat(runtime_fd), record['backing'][0])
    try:
        if directory_identity(bundle) != record['root']:
            raise CleanupUnresolved('captured cleanup bundle namespace changed')
        runtime = validate_allocation(record['allocation'])
        if record['backing'][0] != record['allocation']['root']:
            raise CleanupUnresolved('captured runtime identity differs from allocation')
        if parent_fd is not None:
            parent = record['allocation']['parent']
            info = os.fstat(parent_fd)
            if (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode)) != (
                    parent['device'], parent['inode'], parent['uid'], parent['mode']):
                raise CleanupUnresolved('captured shared parent changed')
            require_captured_directory(os.stat(runtime.name, dir_fd=parent_fd, follow_symlinks=False),
                                       record['backing'][0])
    except OSError as error:
        raise CleanupUnresolved('captured cleanup namespace is unavailable') from error


def dispose_runtime_payload(bundle, record, completions):
    # Public fd-relative operations are mandatory. A pathname-only fallback
    # would turn a concurrent rename into authority over a different directory.
    if (not shutil.rmtree.avoids_symlink_attacks
            or any(not hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW', 'O_CLOEXEC'))
            or os.open not in os.supports_dir_fd or os.stat not in os.supports_dir_fd
            or os.stat not in os.supports_follow_symlinks or os.listdir not in os.supports_fd):
        raise CleanupUnresolved('platform lacks captured-descriptor cleanup primitives')
    descriptors = []
    primary = None
    disposition = None
    try:
        bundle_fd = open_captured_directory(bundle, record['root'])
        descriptors.append(bundle_fd)
        parent = record['allocation']['parent']
        parent_fd = open_captured_directory(parent['path'], parent, shared=True)
        descriptors.append(parent_fd)
        runtime_fd = open_captured_directory(Path(record['allocation']['root']['path']).name,
                                             record['backing'][0], dir_fd=parent_fd)
        descriptors.append(runtime_fd)
        verify_cleanup_namespace(bundle, record, bundle_fd, runtime_fd, parent_fd)
        atomic_record_at(bundle_fd, 'settled.json', dict(identity=record['identity'], commands=completions))
        verify_cleanup_namespace(bundle, record, bundle_fd, runtime_fd, parent_fd)
        dot_refusal = False
        def final_dot_only(function, path, exception_info):
            nonlocal dot_refusal
            error = exception_info[1]
            # EINVAL for final '.' is documented by rmdir(2). The public
            # callback identifies the exact operation; no other failure is
            # suppressed, including the same errno on a descendant operation.
            if (function is not os.rmdir or path != '.' or not isinstance(error, OSError)
                    or error.errno != errno.EINVAL or error.filename != '.' or dot_refusal):
                raise error.with_traceback(exception_info[2])
            verify_cleanup_namespace(bundle, record, bundle_fd, runtime_fd, parent_fd)
            if os.listdir(runtime_fd):
                raise CleanupUnresolved('captured runtime is not empty at final dot refusal') from error
            dot_refusal = True
        # '.' cannot be redirected by replacing runtime or any pathname ancestor.
        # Its final alias is deliberately never removed without atomic inode authority.
        shutil.rmtree('.', dir_fd=runtime_fd, onerror=final_dot_only)
        verify_cleanup_namespace(bundle, record, bundle_fd, runtime_fd, parent_fd)
        if not dot_refusal or os.listdir(runtime_fd):
            raise CleanupUnresolved('captured runtime payload disposal is incomplete')
        descriptors.remove(runtime_fd)
        os.close(runtime_fd)
        disposition = dict(identity=record['identity'], payload_disposed=True,
                           retained_owned_metadata=record['backing'][0],
                           state='payload-disposed-owned-metadata-retained',
                           runtime_descriptor_closed=True, commands_settled=len(completions))
        verify_cleanup_namespace(bundle, record, bundle_fd, parent_fd=parent_fd)
        atomic_record_at(bundle_fd, 'payload-disposition.json', disposition)
        verify_cleanup_namespace(bundle, record, bundle_fd, parent_fd=parent_fd)
        # Publication remains anchored to captured bundle custody. Its descriptor
        # closes below, and only then may execute_bundle publish acceptance.
    except BaseException as error:
        primary = error
        raise
    finally:
        close_errors = []
        while descriptors:
            descriptor = descriptors.pop()  # Invalidate numeric authority before close, even on EINTR.
            try:
                os.close(descriptor)
            except BaseException as error:
                close_errors.append(error)
        if close_errors:
            if primary is not None:
                for error in close_errors:
                    primary.add_note('cleanup descriptor close failed: '+type(error).__name__)
            else:
                raise close_errors[0]
    return dict(**disposition, cleanup_directory_descriptors_closed=True)


def execute_bundle(bundle, cases, env, evidence):
    bundle = Path(bundle).absolute()
    bundle = bundle.parent.resolve(strict=True) / bundle.name
    try:
        record = load_record(bundle)
        context = Evidence(current_source(), cases, env, evidence)
        verify_bundle(bundle, record, cases, env, context)
        # Claim only an already verified exact directory; never follow a claim link.
        claim_identity = claim_bundle(bundle, record)
    except (OSError, KeyError, TypeError) as error:
        raise ValueError('prepared bundle is incomplete, unavailable or already claimed') from error
    marker_hash = file_identity(bundle / 'complete.json', 4 * 1024 * 1024)
    runtime = Path(record['allocation']['root']['path'])
    runtime_env = env.copy()
    runtime_env.update(HOME=str(runtime / 'home'), XDG_CONFIG_HOME=str(runtime / 'config'),
                       XDG_CACHE_HOME=str(runtime / 'cache'), TMPDIR=str(runtime / 'tmp'),
                       HISTFILE='/dev/null', CARGO=str(runtime / 'no-build'),
                       QSH_OLD_QSH=str(runtime / 'old/qsh'), QSH_OLD_QSHD=str(runtime / 'old/qshd'))
    runtime_env.pop('SSH_AUTH_SOCK', None)
    runtime_env.pop('SSH_AGENT_PID', None)
    context.artifacts = record['artifacts']
    def verify():
        if (file_identity(bundle / 'execution.claim') != claim_identity
                or file_identity(bundle / 'complete.json', 4 * 1024 * 1024) != marker_hash):
            raise ValueError('prepared marker changed after execution claim')
        verify_bundle(bundle, record, cases, runtime_env, context)
    context.validate_prepared = verify
    try:
        for case in cases:
            run_case(*case, runtime_env, evidence, context)
        verify()
        completions = []
        for _, name, _ in cases:
            receipt = json.loads((evidence / (name+'.log.completion.json')).read_text())
            if receipt != dict(status=0, child_reaped=True, output_eof=True, mask_restored=True):
                raise ValueError('runtime command custody is unresolved')
            completions.append(dict(case=name, **receipt))
        # Exact command waits/pipe EOF/mask restoration precede payload disposal.
        disposition = dispose_runtime_payload(bundle, record, completions)
        atomic_record(evidence / 'cleanup-completion.json', disposition)
    except BaseException as error:
        # Never replace a primary command/cleanup error with diagnostic trouble.
        try:
            atomic_record(evidence / 'retained.json', dict(identity=record['identity'],
                          state='retained-unresolved', failure=type(error).__name__,
                          runtime=str(runtime), root=record['root']))
        except BaseException as secondary:
            error.add_note('retained-state receipt failed: '+type(secondary).__name__)
        raise
    (evidence / 'passed.txt').write_text(f'{len(cases)} selected tests; {len(cases)} passed; 0 skipped\n')


def prepare_bundle(bundle, cases, env, evidence, archive=None):
    fixture = fixture_for_host()
    prefix, digest, _ = fixture
    source = current_source()
    context = Evidence(source, cases, env, evidence)
    (evidence / 'identity.txt').write_text(f'source={source}\nfixture={prefix}\nsha256={digest}\n')
    print(f'Source: {source}\nFixture SHA-256: {digest}', flush=True)
    try:
        allocation = allocate_runtime(bundle)
        root = Path(allocation['root']['path'])
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
            old_pair = extract_pair(archive, root / 'old', digest, prefix)
        runtime_env = env.copy()
        for key, folder in (('HOME', 'home'), ('XDG_CONFIG_HOME', 'config'),
                            ('XDG_CACHE_HOME', 'cache'), ('TMPDIR', 'tmp')):
            (root / folder).mkdir(mode=0o700)
            runtime_env[key] = str(root / folder)
        runtime_env.update(HISTFILE='/dev/null', QSH_OLD_QSH=str(old_pair[0]),
                           QSH_OLD_QSHD=str(old_pair[1]), CARGO_TERM_COLOR='never')
        runtime_env.pop('SSH_AUTH_SOCK', None)
        runtime_env.pop('SSH_AGENT_PID', None)
        context = prepare(cases, runtime_env, evidence, context)
        record = seal_bundle(context, bundle, root, old_pair, runtime_env)
        print('PREPARED '+record['identity']+'; runtime acceptance still required', flush=True)
        return record
    except BaseException as error:
        try:
            atomic_record(evidence / 'preparation-retained.json', dict(
                state='partial-preparation-retained', root=directory_identity(bundle),
                allocation=locals().get('allocation', getattr(error, 'runtime_allocation', None)),
                failure=type(error).__name__))
        except BaseException as secondary:
            error.add_note('partial preparation receipt failed: '+type(secondary).__name__)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, help='already downloaded archive; still authenticated')
    parser.add_argument('--evidence', type=Path, required=True, help='new private evidence directory outside source')
    parser.add_argument('--service-only', action='store_true', help='select the two actual personal-service scenarios')
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--prepare-only', action='store_true', help='prepare without claiming runtime acceptance')
    modes.add_argument('--execute-prepared', type=Path, help='consume one verified same-job prepared bundle')
    parser.add_argument('--prepared-bundle', type=Path, help='new private retained backing for --prepare-only')
    args = parser.parse_args()
    if (args.prepare_only != (args.prepared_bundle is not None)
            or (args.execute_prepared is not None and args.archive is not None)):
        parser.error('prepare-only requires prepared-bundle; execution cannot take an archive')
    previous_umask = os.umask(0o077)
    try:
        evidence = args.evidence.absolute()
        if evidence.resolve().is_relative_to(WORKSPACE.resolve()):
            raise ValueError('evidence must be outside the source tree')
        evidence.mkdir(mode=0o700, parents=True, exist_ok=False)
        directory_identity(evidence)
        cases = CASES[-2:] if args.service_only else CASES
        env = os.environ.copy()
        env['CARGO_HOME'] = env.get('CARGO_HOME', str(Path.home() / '.cargo'))
        env['RUSTUP_HOME'] = env.get('RUSTUP_HOME', str(Path.home() / '.rustup'))
        if args.execute_prepared is not None:
            execute_bundle(args.execute_prepared, cases, env, evidence)
            return
        path = args.prepared_bundle or Path(tempfile.gettempdir()) / ('qsh-prepared-'+uuid.uuid4().hex)
        bundle = create_bundle(path)
        (evidence / 'bundle-path.txt').write_text(str(bundle)+'\n')
        prepare_bundle(bundle, cases, env, evidence, args.archive)
        if not args.prepare_only:
            execute_bundle(bundle, cases, env, evidence)
    finally:
        os.umask(previous_umask)


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
