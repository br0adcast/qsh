#!/usr/bin/env python3
"""Finite disposable Fedora pair acceptance. Importing this module runs nothing.

This fixture is not production admission authority. Its CLI requires a frozen
input manifest and a one-shot host grant; only explicit root-leased guests may
execute it. Public evidence is a fixed projection of private owned observations.
"""
import argparse
import base64
import ctypes
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import pwd
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time


ARCHES = ('x86_64', 'aarch64')
CASES = ('lifecycle', 'preowned-transfer', 'custom-pam-consumer', 'custom-pam-provider',
         'rpmnew', 'rpmsave', 'missing-pair', 'mixed-pair', 'pending-post',
         'loaded-new-pending', 'admin-row', 'custom-label', 'default-override', 'partial-erase')
SESSIONS = tuple((stage, account) for stage in ('initial-A', 'upgraded-B', 'reinstalled-B')
                 for account in ('first', 'second'))
REQUEST_KEYS = frozenset(('schema', 'attempt_nonce', 'case', 'arch', 'sequence', 'stage',
                          'account', 'session_nonce', 'expected_uid', 'daemon_fingerprint'))
OBSERVATION_KEYS = frozenset(('identity_matched', 'shell_nonce_seen', 'uid_matched',
                              'native_architecture_matched', 'tty_seen', 'resize_seen', 'normal_exit'))
RESCUE_KEYS = frozenset(('group_term_attempts', 'adopted_term_attempts', 'kill_attempts'))
RESULT_KEYS = REQUEST_KEYS | frozenset(('request_sha256', 'client_sha256', 'observations',
                                       'exit_code', 'pty_eof', 'reaped', 'rescue'))
START_KEYS = frozenset(('schema', 'type', 'attempt_nonce', 'case', 'arch', 'manifest_sha256',
                       'guest_work_budget_ms'))
PAM = '/etc/pam.d/qshd'
PHASE = '/usr/libexec/qshd-selinux/qshd_selinux_phase.py'
ACTIVATION = '/var/lib/qshd/selinux-activation/activation.json'
PAM_SHA256 = '61dc7f9dc6ada9a612a66b1bfda1f8d1802ec9734a9325edc4f600b0e55622c7'
MAX_FRAME = 4096
MAX_COMMAND = 1024 * 1024
MAX_EVIDENCE = 256 * 1024 * 1024
_cancel_requests = 0


def _request_cancel(signum, frame):
    # Record-only through launch registration and failure settlement. Repeated
    # signals must never interrupt physical cleanup or create another owner.
    global _cancel_requests
    _cancel_requests += 1


def _check_cancel():
    if _cancel_requests:
        fail('CANCELLED')
DAEMON_IDENTITY_CONTRACT = dict(schema=1, kind='first-service-generated-x25519',
    path='/etc/qshd/host_key', layout='private32-public32', observation='fixed-public-pread32-at32',
    initial_state='absent-before-initial-A-start', continuity='same-public-key-all-six-sessions')


def _metadata(value):
    names = ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtime_ns', 'ctime_ns')
    result = {name: getattr(value, 'st_' + name) for name in names}
    if any(type(item) is not int for item in result.values()):
        fail('DAEMON_METADATA')
    return result


@contextmanager
def _daemon_parents(*, allow_missing=False):
    """Fixed descriptor traversal; no caller-selected route or UID override."""
    fds, edges = [], []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open('/', flags); fds.append(fd)
        initial_root = _metadata(os.fstat(fd))
        for name in ('etc', 'qshd'):
            parent = fd
            try:
                fd = os.open(name, flags, dir_fd=parent)
            except FileNotFoundError:
                if name != 'qshd' or not allow_missing:
                    raise
                edges.append((parent, name, None, None)); fd = None; break
            fds.append(fd)
            edges.append((parent, name, fd, _metadata(os.fstat(fd))))
        def check():
            if _metadata(os.fstat(fds[0])) != initial_root:
                fail('DAEMON_PARENT_CHANGED')
            for opened in fds:
                value = os.fstat(opened)
                if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
                    fail('DAEMON_PARENT')
            for parent, name, opened, before in edges:
                if opened is None:
                    try: os.stat(name, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError: continue
                    fail('DAEMON_PARENT_APPEARED')
                if (_metadata(os.stat(name, dir_fd=parent, follow_symlinks=False)) != before
                        or _metadata(os.fstat(opened)) != before):
                    fail('DAEMON_PARENT_CHANGED')
        check()
        yield fd, check
    finally:
        close_failed = False
        for opened in reversed(fds):
            try: os.close(opened)
            except OSError: close_failed = True
        if close_failed: fail('DAEMON_PARENT_CLOSE')


def observe_daemon_public_key():
    """Read exactly public32 at offset32; never read/hash the private half."""
    try:
        with _daemon_parents() as (parent, recheck):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
            fd = os.open('host_key', flags, dir_fd=parent)
            try:
                before = _metadata(os.fstat(fd))
                if (not stat.S_ISREG(before['mode']) or before['uid'] != 0
                        or stat.S_IMODE(before['mode']) != 0o600 or before['nlink'] != 1 or before['size'] != 64
                        or _metadata(os.stat('host_key', dir_fd=parent, follow_symlinks=False)) != before):
                    fail('DAEMON_KEY_METADATA')
                public = os.pread(fd, 32, 32)
                if len(public) != 32:
                    fail('DAEMON_KEY_SHORT_READ')
                if (_metadata(os.fstat(fd)) != before
                        or _metadata(os.stat('host_key', dir_fd=parent, follow_symlinks=False)) != before):
                    fail('DAEMON_KEY_CHANGED')
                recheck()
                fingerprint = 'SHA256:' + base64.b64encode(hashlib.sha256(public).digest()).decode('ascii').rstrip('=')
                record = dict(schema=1, public_key_hex=public.hex(), daemon_fingerprint=fingerprint, metadata=before)
                if len(canonical(record)) > MAX_FRAME:
                    fail('DAEMON_RECORD_SIZE')
                return record
            finally:
                os.close(fd)
    except OSError:
        fail('DAEMON_PUBLIC_OBSERVATION')


def require_daemon_key_absent():
    """Metadata-only initial absence; never remove or repair a prior identity."""
    try:
        with _daemon_parents(allow_missing=True) as (parent, recheck):
            if parent is not None:
                try: os.stat('host_key', dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError: pass
                else: fail('DAEMON_KEY_ALREADY_PRESENT')
            recheck()
            return dict(schema=1, absent=True)
    except OSError:
        fail('DAEMON_ABSENCE_OBSERVATION')


class Refused(ValueError):
    """Closed fixture refusal; never raw command, secret, path or native output."""


def fail(code):
    raise Refused(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def canonical(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                          allow_nan=False).encode('ascii') + b'\n'
    except (ValueError, TypeError, UnicodeError, RecursionError):
        fail('JSON')


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            fail('DUPLICATE_KEY')
        result[key] = value
    return result


def parse_frame(raw, keys):
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_FRAME:
        fail('FRAME_SIZE')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
                           parse_constant=lambda unused: fail('JSON_CONSTANT'))
    except (ValueError, UnicodeError, RecursionError):
        fail('FRAME_JSON')
    if type(value) is not dict or set(value) != set(keys) or canonical(value) != raw:
        fail('FRAME_SCHEMA')
    return value


def _hex(value, length=64):
    return type(value) is str and re.fullmatch('[0-9a-f]{' + str(length) + '}', value) is not None


def _integer(value, low, high):
    return type(value) is int and low <= value <= high


def _request_shape(value):
    if (set(value) != REQUEST_KEYS or type(value['schema']) is not int or value['schema'] != 1
            or not _hex(value['attempt_nonce'], 32) or value['case'] != 'lifecycle'
            or value['arch'] not in ARCHES or not _integer(value['sequence'], 1, 6)
            or (value['stage'], value['account']) != SESSIONS[value['sequence'] - 1]
            or not _hex(value['session_nonce'], 32) or not _integer(value['expected_uid'], 1, 2147483647)
            or type(value['daemon_fingerprint']) is not str
            or re.fullmatch(r'SHA256:[A-Za-z0-9+/]{43}', value['daemon_fingerprint']) is None):
        fail('PTY_REQUEST')


def validate_pty_request(raw, expected):
    value = parse_frame(raw, REQUEST_KEYS)
    _request_shape(value)
    if value != expected:
        fail('PTY_BINDING')
    return value


def validate_pty_result(raw, request, client_sha256):
    value = parse_frame(raw, RESULT_KEYS)
    selected = {key: value[key] for key in REQUEST_KEYS}
    _request_shape(selected)
    if (selected != request or not _hex(client_sha256)
            or value['request_sha256'] != digest(canonical(request))
            or value['client_sha256'] != client_sha256
            or type(value['observations']) is not dict or set(value['observations']) != OBSERVATION_KEYS
            or any(item is not True for item in value['observations'].values())
            or type(value['exit_code']) is not int or value['exit_code'] != 0
            or value['pty_eof'] is not True or value['reaped'] is not True
            or type(value['rescue']) is not dict or set(value['rescue']) != RESCUE_KEYS
            or any(type(item) is not int or item != 0 for item in value['rescue'].values())):
        fail('PTY_RESULT')
    return value


def validate_sessions(requests):
    if type(requests) is not list or len(requests) != 6:
        fail('PTY_INVENTORY')
    for index, value in enumerate(requests, 1):
        _request_shape(value)
        if value['sequence'] != index:
            fail('PTY_ORDER')
    if len({r['session_nonce'] for r in requests}) != 6:
        fail('PTY_NONCE_REUSE')
    for key in ('attempt_nonce', 'case', 'arch', 'daemon_fingerprint'):
        if len({r[key] for r in requests}) != 1: fail('PTY_SESSION_BINDING')
    for account in ('first', 'second'):
        if len({r['expected_uid'] for r in requests if r['account'] == account}) != 1:
            fail('PTY_UID_CHANGED')


def host_remaining_ms(end_ns, now_ns):
    if type(end_ns) is not int or type(now_ns) is not int or now_ns >= end_ns:
        fail('HOST_EXPIRED')
    return (end_ns - now_ns) // 1000000


def guest_grant_ms(case, host_end_ns, host_now_ns, reserve_ms):
    if case not in CASES or not _integer(reserve_ms, 190000, 310000):
        fail('HOST_RESERVE')
    remaining = host_remaining_ms(host_end_ns, host_now_ns) - reserve_ms
    if remaining <= 0:
        fail('HOST_EXPIRED')
    return min(10800000 if case == 'lifecycle' else 3600000, remaining)


class GuestBudget:
    """One relative admission; only this machine's monotonic_ns enters its end."""
    def __init__(self, expected, marker, *, clock_ns=time.monotonic_ns):
        self.expected = dict(expected)
        self.marker = Path(marker)
        self.clock_ns = clock_ns
        self.end_ns = None

    def admit(self, raw):
        value = parse_frame(raw, START_KEYS)
        ceiling = 10800000 if self.expected['case'] == 'lifecycle' else 3600000
        if (self.end_ns is not None or value['schema'] != 1 or type(value['schema']) is not int
                or value['type'] != 'guest-start'
                or any(value[key] != item for key, item in self.expected.items())
                or not _integer(value['guest_work_budget_ms'], 1, ceiling)):
            fail('GUEST_ADMISSION')
        try:
            with self.marker.open('xb') as stream:
                stream.write(canonical(value))
        except OSError:
            fail('GUEST_ALREADY_ATTEMPTED')
        self.start_ns = self.clock_ns()
        self.end_ns = self.start_ns + value['guest_work_budget_ms'] * 1000000
        return value

    def check(self, operation_end_ns=None):
        _check_cancel()
        end = self.end_ns if operation_end_ns is None else min(self.end_ns or 0, operation_end_ns)
        if end is None or self.clock_ns() >= end:
            fail('GUEST_EXPIRED')

    def operation_end(self, cap_ms):
        self.check()
        if not _integer(cap_ms, 1, 10800000):
            fail('OPERATION_BUDGET')
        return min(self.end_ns, self.clock_ns() + cap_ms * 1000000)


def verify_input(descriptor):
    if type(descriptor) is not dict or set(descriptor) != {'path', 'size', 'sha256'}:
        fail('INPUT_SCHEMA')
    path = Path(descriptor['path'])
    if not path.is_absolute() or '..' in path.parts or not _hex(descriptor['sha256']):
        fail('INPUT_PATH')
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not _integer(descriptor['size'], 1, 128 * 1024**2) or before.st_size != descriptor['size']):
            fail('INPUT_FILE')
        data = path.read_bytes()
        after = path.lstat()
    except OSError:
        fail('INPUT_FILE')
    fields = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
    if any(getattr(before, key) != getattr(after, key) for key in fields) or digest(data) != descriptor['sha256']:
        fail('INPUT_IDENTITY')
    return data


def validate_architecture(expected, actual):
    if expected not in ARCHES or actual != expected:
        fail('ARCHITECTURE')


def validate_hooks(records, expected):
    if len(records) != len(expected):
        fail('HOOK_INVENTORY')
    for record, row in zip(records, expected):
        if (tuple(record.get(k) for k in ('role', 'artifact', 'hook', 'count_class')) != tuple(row)
                or record.get('executed') is not True or record.get('normal') is not True
                or 'count' in record or not _hex(record.get('script_sha256'))):
            fail('HOOK_EXECUTION')


def parse_rpm_execution(raw, context):
    """Require real RPM debug start/exec/wait boundaries, never body echoes.

    The caller supplies independently admitted package/script identities.
    No count or argv is measured here. Native RPM grammar is an input gate:
    unsupported diagnostics refuse instead of manufacturing execution records.
    """
    if (type(raw) is not bytes or len(raw) > MAX_COMMAND or type(context) is not dict
            or raw and not raw.endswith(b'\n')):
        fail('RPM_TRACE')
    try:
        lines = raw.decode('utf-8').splitlines()
    except UnicodeError:
        fail('RPM_TRACE')
    events = []; seen = set()
    active = None
    prefix = r'^D:\s+%(prein|post|preun|postun)\(([^)]+)\): '
    for line in lines:
        start = re.fullmatch(prefix + r'scriptlet start', line)
        execute = re.fullmatch(prefix + r'execv\(([^)]+)\) pid ([1-9][0-9]*)', line)
        finish = re.fullmatch(prefix + r'waitpid\(([1-9][0-9]*)\) rc ([0-9]+) status ([0-9a-fA-F]+)', line)
        if start:
            hook, nevra = start.groups()
            hook = 'postin' if hook == 'post' else hook
            if active is not None or nevra not in context or (hook, nevra) in seen:
                fail('RPM_HOOK_START')
            seen.add((hook, nevra))
            binding = context[nevra]
            if (set(binding) != {'role', 'artifact', 'scripts', 'interpreter', 'flags'}
                    or binding['role'] not in ('provider', 'consumer') or binding['artifact'] not in ('A', 'B')
                    or binding['interpreter'] != '/bin/sh' or type(binding['flags']) is not int or binding['flags'] != 0
                    or not _hex(binding['scripts'].get(hook))):
                fail('RPM_CALLBACK_AUTHORITY')
            active = dict(role=binding['role'], artifact=binding['artifact'], hook=hook,
                          script_sha256=binding['scripts'][hook], nevra=nevra, pid=None,
                          interpreter=binding['interpreter'], flags=binding['flags'], phase_frames=[])
        elif execute:
            hook, nevra, interpreter, pid = execute.groups()
            hook = 'postin' if hook == 'post' else hook
            if (active is None or (active['hook'], active['nevra']) != (hook, nevra)
                    or active['pid'] is not None or interpreter != active['interpreter']):
                fail('RPM_HOOK_EXEC')
            active['pid'] = int(pid)
        elif finish:
            hook, nevra, pid, returned, status = finish.groups()
            hook = 'postin' if hook == 'post' else hook
            if (active is None or (active['hook'], active['nevra'], active['pid']) != (hook, nevra, int(pid))
                    or int(returned) != int(pid)):
                fail('RPM_HOOK_WAIT')
            wait_status = int(status, 16)
            if not os.WIFEXITED(wait_status):
                fail('RPM_HOOK_SIGNAL')
            active.update(executed=True, normal=True, script_exit=os.WEXITSTATUS(wait_status))
            events.append(active)
            active = None
        elif re.match(r'^D:\s+%(?:prein|postin|post|preun|postun)\(', line):
            fail('RPM_UNKNOWN_GRAMMAR')
    if active is not None or not events:
        fail('RPM_HOOK_INCOMPLETE')
    return events


RPM_SOURCE_FILES = frozenset(('lib/psm.cc', 'lib/rpmdb.cc', 'lib/rpminstall.cc', 'lib/rpmscript.cc',
                              'lib/rpmte.cc', 'lib/transaction.cc', 'rpmio/rpmlog.cc'))
RPM_ADMISSION_KEYS = frozenset(('schema', 'status', 'rpm_nevra', 'source_rpm', 'source_rpm_sha256',
    'fedora_patchset_sha256', 'review_receipt_sha256', 'source_files', 'runtime'))
LITERAL_ERASE_HOOKS = {
    ('provider', 'preun'): '3be75997766007143b6abf8d59fac42ce3d9238ffc7dab14a5eee4bf2d770205',
    ('consumer', 'preun'): '86bcc4c12b2106edc672b559d26f52285fb0daf019769cda0c3598ccd4876634',
    ('provider', 'postun'): '1b9bf018c7dae525fbcec22eaf9e4045df65940536f70045124f20a239577dc7',
    ('consumer', 'postun'): '2033fc276f50c390bbbfadf241d8dd428c358183336904f106be7b7abf8661f7'}


def validate_rpm_admission(value, actual_runtime, arch=None):
    """Root-reviewed Fedora correspondence, not an upstream research hash.

    Root independently verifies the signed SRPM, applied Fedora patches and
    reviewed source/runtime correspondence before freezing this receipt. Guest
    admission additionally rechecks every frozen executable/library byte hash.
    Synthetic offline receipts do not qualify an actual Fedora environment.
    """
    if (type(value) is not dict or set(value) != RPM_ADMISSION_KEYS
            or type(value['schema']) is not int or value['schema'] != 1
            or value['status'] != 'ROOT_REVIEWED_FEDORA44_RPM6_SOURCE_RUNTIME'
            or value['rpm_nevra'] not in ('rpm-6.0.2-1.fc44.x86_64', 'rpm-6.0.2-1.fc44.aarch64')
            or arch is not None and (arch not in ARCHES or value['rpm_nevra'] != 'rpm-6.0.2-1.fc44.' + arch)
            or value['source_rpm'] != 'rpm-6.0.2-1.fc44.src.rpm'
            or any(not _hex(value[key]) for key in ('source_rpm_sha256', 'fedora_patchset_sha256', 'review_receipt_sha256'))
            or type(value['source_files']) is not dict or set(value['source_files']) != RPM_SOURCE_FILES
            or any(not _hex(item) for item in value['source_files'].values())
            or type(value['runtime']) is not dict or not 3 <= len(value['runtime']) <= 64
            or '/usr/bin/rpm' not in value['runtime']
            or not any(p.startswith('/usr/lib64/librpm.so.') for p in value['runtime'])
            or not any(p.startswith('/usr/lib64/librpmio.so.') for p in value['runtime'])
            or any(not p.startswith(('/usr/lib64/', '/usr/bin/')) or '..' in Path(p).parts or not _hex(item)
                   for p, item in value['runtime'].items())
            or type(actual_runtime) is not dict or actual_runtime != value['runtime']):
        fail('RPM_SOURCE_RUNTIME_NOT_ADMITTED')
    return digest(canonical(value))


def classify_rpm_branches(records, success_frames, failure_frames, identities, before, after,
                          admission, actual_runtime, *, capture, operation):
    """Count classes with explicit direct/elimination/same-PSM provenance."""
    admission_sha = validate_rpm_admission(admission, actual_runtime)
    if capture != {'normal': True, 'stdout_eof': True, 'stderr_eof': True}:
        fail('RPM_CAPTURE_INCOMPLETE')
    used = set(); used_failure = set(); result = []
    routes = {
        ('provider', 'prein'): {'provider-pre-fresh': 'one', 'provider-pre-owned': 'two-or-more'},
        ('provider', 'postin'): {'provider-post-pristine': 'one', 'provider-post-owned': 'two-or-more'},
        ('consumer', 'prein'): {'consumer-pre-fresh': 'one', 'consumer-pre-installed': 'two-or-more'},
        ('consumer', 'postin'): {'consumer-post-owned': 'positive'},
        ('provider', 'preun'): {'provider-preun-final': 'zero'},
        ('consumer', 'preun'): {'consumer-preun-final': 'zero'}}
    for index, event in enumerate(records):
        event = dict(event)
        if (event.get('executed') is not True or event.get('normal') is not True
                or 'count' in event or 'count_class' in event or 'count_provenance' in event
                or event.get('role') not in ('provider', 'consumer') or event.get('artifact') not in ('A', 'B')
                or event.get('hook') not in ('prein', 'postin', 'preun', 'postun')
                or not _hex(event.get('script_sha256')) or not _integer(event.get('script_exit'), 0, 255)):
            fail('RPM_UNCLASSIFIED_EXECUTION')
        role, artifact, hook = (event[key] for key in ('role', 'artifact', 'hook'))
        allowed = routes.get((role, hook), {})
        matches = []
        for number, (raw, frame) in enumerate(success_frames):
            phase = frame.get('phase')
            if phase not in allowed: continue
            identity = identities[artifact]
            validate_phase(raw, _phase_request(phase, identity), identity)
            matches.append((number, allowed[phase], 'direct-phase-route', digest(raw), phase))
        for number, (raw, frame) in enumerate(failure_frames):
            phase = frame.get('request', {}).get('phase')
            if phase not in allowed: continue
            _phase_refusal(raw, _phase_request(phase, identities[artifact]))
            matches.append((number, allowed[phase], 'direct-request-bound-refusal', digest(raw), phase))
        if len(matches) > 1: fail('RPM_PHASE_AMBIGUOUS')
        if matches:
            number, branch, provenance, frame_sha, phase = matches[0]
            inventory = used_failure if provenance == 'direct-request-bound-refusal' else used
            if number in inventory: fail('RPM_PHASE_REUSED')
            inventory.add(number)
            event.update(count_class=branch, count_provenance=provenance, phase_sha256=frame_sha, phase=phase)
        elif hook == 'preun':
            # Exact literal branches either exec final helper (and emit a
            # bound success/refusal frame) or return0 for positive count.
            state = after.get('activation')
            if (event['script_exit'] != 0 or event['script_sha256'] != LITERAL_ERASE_HOOKS[(role, hook)]
                    or operation not in ('upgrade', 'upgrade-skipped-post')
                    or before['packages'][role] != [event['nevra']]
                    or len(after['packages'][role]) != 1 or after['packages'][role] == before['packages'][role]
                    or not state or state.get('artifact') != identities['B']):
                fail('OLD_PREUN_BRANCH_UNKNOWN')
            expected_pair = [identities['B']['core_pp_sha256'], identities['B']['contexts_pp_sha256']]
            if operation == 'upgrade':
                if state.get('state') != 'COMPLETE' or state.get('basis') is not None or after['pair'] != expected_pair:
                    fail('OLD_PREUN_DID_NOT_PRESERVE_NEW_PAIR')
            elif (state.get('state') != 'PENDING' or not isinstance(state.get('basis'), dict)
                    or state['basis'].get('artifact') != identities['A'] or after['pair'] != before['pair']):
                fail('POST_SKIPPED_SCOPE')
            event.update(count_class='positive', count_provenance='exact-literal-branch-elimination',
                         preservation_scope=operation)
        elif hook == 'postun':
            previous = [r for r in result if (r['role'], r['artifact'], r['hook']) == (role, artifact, 'preun')]
            if (len(previous) != 1 or event['script_sha256'] != LITERAL_ERASE_HOOKS[(role, hook)]
                    or 'count' in event or previous[0]['count_class'] not in ('zero', 'positive')):
                fail('POSTUN_CLASS_NOT_DERIVED')
            event.update(count_class=previous[0]['count_class'], count_provenance='source-backed-same-psm',
                         basis_event=result.index(previous[0]))
        else:
            fail('RPM_PHASE_MISSING')
        if role == 'consumer' and hook == 'postin':
            previous = [r for r in result if (r['role'], r['artifact'], r['hook']) == (role, artifact, 'prein')]
            if len(previous) != 1 or previous[0]['count_class'] not in ('one', 'two-or-more'):
                fail('CONSUMER_POST_CLASS_UNKNOWN')
            event.update(direct_phase_class='positive', count_class=previous[0]['count_class'],
                         count_provenance='direct-positive-plus-source-backed-same-psm', basis_event=result.index(previous[0]))
        event['source_admission_sha256'] = admission_sha
        result.append(event)
    if len(used) != len(success_frames) or len(used_failure) != len(failure_frames):
        fail('RPM_UNMATCHED_PHASE')
    return result


def validate_pair_change(a, b):
    for name in ('core_pp_sha256', 'contexts_pp_sha256'):
        if not _hex(a.get(name)) or not _hex(b.get(name)) or a[name] == b[name]:
            fail('PAIR_NOT_CHANGED')


def validate_phase(raw, request, artifact):
    phase = request['phase']
    if phase == 'provider-pre-fresh':
        frame = parse_frame(raw, {'schema', 'phase', 'request_sha256', 'operation_id', 'state'})
        if (type(frame['schema']) is not int or frame['schema'] != 2 or frame['phase'] != phase
                or frame['request_sha256'] != digest(canonical(request).rstrip(b'\n'))
                or not _hex(frame['operation_id'], 32) or frame['state'] != 'PENDING'
                or request.get('artifact') != artifact):
            fail('FRESH_PHASE_BINDING')
        return frame
    expected_states = {'provider-pre-owned': 'PENDING', 'provider-post-owned': 'COMPLETE',
                       'provider-post-pristine': 'COMPLETE', 'consumer-pre-fresh': 'PENDING',
                       'consumer-pre-installed': 'PENDING', 'consumer-post-owned': 'COMPLETE',
                       'consumer-preun-final': 'PENDING', 'provider-preun-final': 'ERASED'}
    field = 'result' if phase == 'provider-preun-final' else 'state'
    frame = parse_frame(raw, {'schema', 'phase', 'request_sha256', 'operation_id', 'artifact', field})
    if (type(frame['schema']) is not int or frame['schema'] != 2 or frame['phase'] != phase
            or frame['request_sha256'] != digest(canonical(request).rstrip(b'\n'))
            or not _hex(frame['operation_id'], 32) or frame['artifact'] != artifact
            or frame[field] != expected_states.get(phase)):
        fail('PHASE_BINDING')
    return frame


def validate_ready(snapshot):
    if (snapshot.get('state') != 'COMPLETE' or snapshot.get('managed_prestart') is not True
            or snapshot.get('current_pair') != snapshot.get('expected_pair')
            or not isinstance(snapshot.get('current_pair'), list) or len(snapshot['current_pair']) != 2):
        fail('NOT_READY')


def validate_preserved(before, after, keys):
    if any(key not in before or key not in after or before[key] != after[key] for key in keys):
        fail('PRESERVATION')


def validate_matrix(rows):
    expected = {(arch, case) for arch in ARCHES for case in CASES}
    if (type(rows) is not list or len(rows) != len(expected)
            or {(r.get('arch'), r.get('case')) for r in rows} != expected
            or any(r.get('result') != 'PASS' or not _hex(r.get('nonce'), 32) for r in rows)
            or len({r['nonce'] for r in rows}) != len(rows)):
        fail('ARCHITECTURE_MATRIX')


def validate_outcome(value):
    if (any(value.get(key) is not True for key in ('natural', 'stdout_eof', 'stderr_eof', 'settled'))
            or value.get('unreaped') not in ([], ()) or value.get('failure') is not None
            or any(type(value.get(key)) is not int or value[key] != 0 for key in RESCUE_KEYS)
            or type(value.get('exit_code')) is not int
            or type(value.get('cancellation_requests', 0)) is not int or value.get('cancellation_requests', 0) != 0):
        fail('CHILD_CUSTODY')


def public_projection(record):
    keys = ('schema', 'arch', 'case', 'result', 'nonce', 'hashes', 'count')
    value = {key: record[key] for key in keys}
    # Private preservation/key/log digests never become public correlation
    # handles. Only independently public source/artifact roles are projected.
    roles = {'source', 'driver', 'provider_a', 'provider_b', 'consumer_a', 'consumer_b', 'client'}
    value['hashes'] = {key: item for key, item in record['hashes'].items() if key in roles}
    if (value['schema'] != 1 or value['arch'] not in ARCHES or value['case'] not in CASES
            or value['result'] not in ('PASS', 'FAIL') or not _hex(value['nonce'], 32)
            or not _integer(value['count'], 0, 4096) or type(value['hashes']) is not dict
            or any(not re.fullmatch('[a-z][a-z0-9_-]{0,31}', key) or not _hex(item)
                   for key, item in value['hashes'].items())):
        fail('PUBLIC_PROJECTION')
    return value


MANIFEST_KEYS = frozenset(('schema', 'attempt_nonce', 'case', 'arch', 'source_commit', 'inputs',
    'artifacts', 'accounts', 'client', 'sessions', 'fault', 'expected_initial', 'output_limit',
    'retained_paths', 'registry_paths', 'rpm_callback_contract', 'daemon_identity_contract'))
INPUT_ROLES = frozenset(('driver', 'owner', 'api', 'A-provider', 'A-consumer', 'A-core', 'A-contexts',
                         'B-provider', 'B-consumer', 'B-core', 'B-contexts', 'first-public', 'second-public'))
HOOKS = ('prein', 'postin', 'preun', 'postun')
ARTIFACT_KEYS = frozenset(('provider_version', 'manifest_sha256', 'core_pp_sha256', 'contexts_pp_sha256'))
RUNTIME_MODULES = tuple('qshd_selinux_' + name + '.py' for name in (
    'activation', 'activation_state', 'contexts', 'transaction', 'fs', 'registry', 'process',
    'modules', 'module_observer', 'api', 'queries', 'files', 'retained_labels', 'observer',
    'reference_loader', 'package_state', 'module_install', 'first_activation', 'consumer_activation',
    'provider_erase', 'phase', 'rpm_query')) + ('stop_guard.py',)
PROVIDER_RUNTIME = frozenset('/usr/libexec/qshd-selinux/' + name for name in RUNTIME_MODULES) | frozenset(
    '/usr/share/qshd-selinux/' + name for name in ('qshd.pp', 'qshd_contexts.pp', 'artifact.json',
                                                'qshd.fedora-selinux', 'reference.json'))
CONSUMER_FILES = frozenset(('/usr/share/qshd/consumer-rpm.json', '/usr/bin/qshd',
    '/usr/lib/systemd/system/qshd.service', '/usr/lib/systemd/user/qshd.service', PAM,
    '/usr/share/doc/qshd/README.md', '/usr/share/doc/qshd/CHANGELOG.md',
    '/usr/share/doc/qshd/LICENSE', '/usr/share/doc/qshd/LICENSE-OPENSSL.txt'))


def _document(path, limit=MAX_COMMAND):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= limit:
        fail('DOCUMENT')
    raw = path.read_bytes()
    if _metadata(path.lstat()) != _metadata(before):
        fail('DOCUMENT_CHANGED')
    try:
        value = json.loads(raw.decode('ascii'), object_pairs_hook=_pairs,
                           parse_constant=lambda unused: fail('JSON_CONSTANT'))
    except (ValueError, UnicodeError, RecursionError):
        fail('DOCUMENT_JSON')
    return raw, value


def load_manifest(path, case):
    raw, value = _document(path)
    if (type(value) is not dict or set(value) != MANIFEST_KEYS or value['schema'] != 1
            or type(value['schema']) is not int or value['case'] != case or case not in CASES
            or value['arch'] not in ARCHES or not _hex(value['attempt_nonce'], 32)
            or not _hex(value['source_commit'], 40) or value['expected_initial'] != 'pristine'
            or value['output_limit'] != MAX_COMMAND or type(value['output_limit']) is not int
            or canonical(value['daemon_identity_contract']) != canonical(DAEMON_IDENTITY_CONTRACT)):
        fail('MANIFEST_SCHEMA')
    if type(value['inputs']) is not dict or set(value['inputs']) != INPUT_ROLES:
        fail('INPUT_INVENTORY')
    input_root = Path(path).parent
    seen = set()
    for descriptor in value['inputs'].values():
        content = verify_input(descriptor)
        selected = Path(descriptor['path'])
        if selected.parent != input_root or selected in seen:
            fail('INPUT_ROOT')
        seen.add(selected)
    if Path(value['inputs']['driver']['path']) != Path(__file__).resolve():
        fail('DRIVER_IDENTITY')
    if type(value['artifacts']) is not dict or set(value['artifacts']) != {'A', 'B'}:
        fail('ARTIFACT_INVENTORY')
    for name, artifact in value['artifacts'].items():
        if (type(artifact) is not dict or set(artifact) != {'identity', 'nevra', 'scripts', 'files'}
                or type(artifact['identity']) is not dict or set(artifact['identity']) != ARTIFACT_KEYS
                or artifact['identity']['provider_version'] != '0.3.0'
                or any(not _hex(artifact['identity'][key]) for key in ARTIFACT_KEYS - {'provider_version'})):
            fail('ARTIFACT_SCHEMA')
        for role in ('provider', 'consumer'):
            if (set(artifact['scripts']) != {'provider', 'consumer'}
                    or set(artifact['scripts'][role]) != set(HOOKS)
                    or any(not _hex(item) for item in artifact['scripts'][role].values())):
                fail('SCRIPT_INVENTORY')
            release = '1' if name == 'A' else '2'
            expected = ('qshd-selinux-' if role == 'provider' else 'qshd-')
            arch = 'noarch' if role == 'provider' else value['arch']
            if not re.fullmatch(re.escape(expected) + r'[0-9]+\.[0-9]+\.[0-9]+-' + release + r'\.fc44\.' + arch,
                                artifact['nevra'][role]):
                fail('PACKAGE_NEVRA')
            files = artifact['files'][role]
            if not isinstance(files, dict) or len(files) != (32 if role == 'provider' else 9):
                fail('FILE_INVENTORY')
            if role == 'provider' and not PROVIDER_RUNTIME <= set(files) or role == 'consumer' and set(files) != CONSUMER_FILES:
                fail('FILE_CLOSURE')
            for selected, row in files.items():
                if (not selected.startswith(('/usr/', '/etc/pam.d/')) or '..' in Path(selected).parts
                        or set(row) != {'size', 'sha256', 'mode', 'flags'} or not _hex(row['sha256'])
                        or not _integer(row['size'], 0, 128 * 1024**2)
                        or not _integer(row['mode'], 0, 0o177777) or not _integer(row['flags'], 0, 255)):
                    fail('FILE_INVENTORY')
            if role == 'consumer' and (files[PAM]['sha256'] != PAM_SHA256 or files[PAM]['flags'] != 17
                    or files['/usr/share/qshd/consumer-rpm.json']['mode'] != 0o100644):
                fail('CONSUMER_AUTHORITY')
        for role in ('core', 'contexts'):
            if value['inputs'][name + '-' + role]['sha256'] != artifact['identity'][role + '_pp_sha256']:
                fail('PP_AUTHORITY')
    validate_pair_change(value['artifacts']['A']['identity'], value['artifacts']['B']['identity'])
    for role, leaf in [('owner', 'qshd_selinux_process.py'), ('api', 'qshd_selinux_api.py')]:
        for artifact in value['artifacts'].values():
            if value['inputs'][role]['sha256'] != artifact['files']['provider']['/usr/libexec/qshd-selinux/' + leaf]['sha256']:
                fail('FIXTURE_PRIMITIVE_SOURCE')
    if set(value['accounts']) != {'first', 'second'} or set(value['client']) != {'sha256'} or not _hex(value['client']['sha256']):
        fail('CLIENT_ACCOUNT_SCHEMA')
    for index, account in enumerate(('first', 'second')):
        if value['accounts'][account] != {'name': 'qsh57' + account, 'uid': 21001 + index}:
            fail('ACCOUNT_IDENTITY')
    expected_sessions = SESSIONS if case == 'lifecycle' else ()
    if type(value['sessions']) is not list or len(value['sessions']) != len(expected_sessions):
        fail('SESSION_INVENTORY')
    for session, pair in zip(value['sessions'], expected_sessions):
        if (type(session) is not dict or set(session) != {'stage', 'account', 'session_nonce'}
                or (session['stage'], session['account']) != pair or not _hex(session['session_nonce'], 32)):
            fail('SESSION_INVENTORY')
    if len({r['session_nonce'] for r in value['sessions']}) != len(expected_sessions):
        fail('SESSION_NONCES')
    paths = value['retained_paths']
    if (type(paths) is not list or not 3 <= len(paths) <= 32 or len(paths) != len(set(paths))
            or '/etc/qshd/host_key' not in paths or any(type(p) is not str or '..' in Path(p).parts
                or not (p == '/etc/qshd' or p.startswith('/etc/qshd/') or p == '/var/log/qshd'
                        or p.startswith('/var/log/qshd/')) for p in paths)):
        fail('RETAINED_INVENTORY')
    contract = value['rpm_callback_contract']
    # Structural check here; actual executable and library bytes are rechecked
    # before any package operation in Native.pristine and again at final exit.
    validate_rpm_admission(contract, contract.get('runtime') if type(contract) is dict else None, value['arch'])
    registry = value['registry_paths']
    if (type(registry) is not list or not 1 <= len(registry) <= 16 or len(registry) != len(set(registry))
            or any(type(p) is not str or not p.startswith('/etc/selinux/targeted/contexts/')
                   or '..' in Path(p).parts for p in registry)):
        fail('REGISTRY_INVENTORY')
    if type(value['fault']) is not dict:
        fail('FAULT_SCHEMA')
    return raw, value


def _load_module(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class _LocalEnd:
    """Internal same-guest child deadline; no new grant or host timestamp."""
    def __init__(self, end_ns):
        self.end_ns = end_ns
    def check(self):
        if time.monotonic_ns() >= self.end_ns:
            fail('GUEST_EXPIRED')
    def operation_end(self, cap_ms):
        self.check()
        return min(self.end_ns, time.monotonic_ns() + cap_ms * 1000000)


class OwnedCommands:
    """Private fixed-operation backend. The CLI accepts no command/argv field."""
    def __init__(self, owner_descriptor, budget, evidence):
        verify_input(owner_descriptor)
        self.module = _load_module(owner_descriptor['path'], 'qsh57_fixture_owned_process')
        self.budget = budget
        self.root = Path(evidence)
        self.root.mkdir(mode=0o700, exist_ok=True)
        self.records = []

    def run(self, argv, *, seconds=60, cwd='/', allow_nonzero=False):
        self.budget.check()
        end = self.budget.operation_end(int(seconds * 1000))
        # Campaign transactions contain several unchanged production phases;
        # their outer watchdog is deliberately not a production _Limits mode.
        record = _campaign_command(self.module, tuple(map(str, argv)), str(cwd), end)
        number = len(self.records)
        output, errors = record['stdout'], record['stderr']
        for name, data in (('stdout', output), ('stderr', errors)):
            with (self.root / (str(number) + '.' + name)).open('xb') as stream:
                stream.write(data)
        record.pop('stdout'); record.pop('stderr')
        record.update(argv=list(map(str, argv)), stdout_sha256=digest(output), stderr_sha256=digest(errors))
        with (self.root / (str(number) + '.json')).open('xb') as stream:
            stream.write(canonical(record))
        self.records.append(record)
        with (self.root.parent / 'commands.jsonl').open('ab') as stream:
            stream.write(canonical(record))
        total = 0
        for index, path in enumerate(self.root.parent.rglob('*')):
            if index > 4096:
                fail('EVIDENCE_FILES')
            if path.is_file(): total += path.stat().st_size
        if total > MAX_EVIDENCE:
            fail('EVIDENCE_LIMIT')
        validate_outcome(record)
        self.budget.check()
        if record['exit_code'] != 0 and not allow_nonzero:
            fail('NATIVE_TOOL_EXIT')
        return record['exit_code'], output, errors


def _proc_identity(pid):
    try:
        data = Path('/proc/' + str(pid) + '/stat').read_bytes()
    except FileNotFoundError:
        return None
    if len(data) > 4096:
        fail('CHILD_CENSUS')
    fields = data.rsplit(b') ', 1)[-1].split()
    if len(fields) < 20:
        fail('CHILD_CENSUS')
    return dict(pid=pid, ppid=int(fields[1]), start=int(fields[19]), state=fields[0])


def _campaign_command(primitives, argv, cwd, end_ns):
    """Dedicated fixture owner, one child/wait and no successful rescue.

    Only a fixed operation in this module chooses argv. Native production
    owners/limits are neither patched nor bypassed. The reused primitives are
    admitted source bytes; the longer campaign watchdog is fixture-only.
    """
    primitives._preconditions(); primitives._subreaper()
    if (type(argv) is not tuple or not argv or any(type(x) is not str or '\0' in x for x in argv)
            or not Path(cwd).is_absolute() or type(end_ns) is not int or time.monotonic_ns() >= end_ns):
        fail('CHILD_ARGUMENTS')
    proc = None; selector = selectors.DefaultSelector()
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    eof = {'stdout': False, 'stderr': False}
    known = {}; reaped = set(); failure = None; normal = False; code = None
    counters = {name: 0 for name in RESCUE_KEYS}
    original_handlers = {number: signal.getsignal(number) for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)}
    for number in original_handlers: signal.signal(number, _request_cancel)
    def census(enforce=True):
        table = {}
        for index, entry in enumerate(Path('/proc').iterdir()):
            if index > 65536: fail('CHILD_CENSUS')
            if entry.name.isdecimal():
                item = _proc_identity(int(entry.name))
                if item is not None: table[item['pid']] = item
        owned = {proc.pid} if proc is not None and proc.pid not in reaped else set()
        owned |= {pid for pid, item in table.items() if item['ppid'] == os.getpid()}
        changed = True
        while changed:
            new = {pid for pid, item in table.items() if item['ppid'] in owned}
            changed = bool(new - owned); owned |= new
        current = {pid: table[pid] for pid in owned if pid in table}
        if enforce and len(current) > 128: fail('CHILD_LIMIT')
        for pid, item in current.items(): known[pid] = item['start']
        return current
    def pump(timeout):
        for key, unused in selector.select(timeout):
            block = os.read(key.fileobj.fileno(), 65536)
            if not block:
                eof[key.data] = True; selector.unregister(key.fileobj)
            elif len(output[key.data]) + len(block) <= MAX_COMMAND:
                output[key.data].extend(block)
            else:
                fail('CHILD_OUTPUT_LIMIT')
    def send(pid, sig, counter):
        if pid in reaped: return
        current = census(False)
        if pid not in current: return
        item = _proc_identity(pid)
        if item is None or item['start'] != known.get(pid): return
        try:
            os.kill(pid, sig); counters[counter] += 1
        except ProcessLookupError: pass
    try:
        env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME=cwd,
                   XDG_CACHE_HOME=cwd, XDG_CONFIG_HOME=cwd, TMPDIR=cwd, HISTFILE='/dev/null',
                   PYTHONDONTWRITEBYTECODE='1')
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, cwd=cwd, env=env, close_fds=True, start_new_session=True)
        for pipe, name in ((proc.stdout, 'stdout'), (proc.stderr, 'stderr')):
            os.set_blocking(pipe.fileno(), False); selector.register(pipe, selectors.EVENT_READ, name)
        while True:
            if _cancel_requests: fail('CHILD_CANCELLED')
            if time.monotonic_ns() >= end_ns: fail('CHILD_TIMEOUT')
            census()
            pump(min(.05, max(0, (end_ns-time.monotonic_ns())/1000000000)))
            if _cancel_requests: fail('CHILD_CANCELLED')
            status = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if status is not None and all(eof.values()):
                # Holds the direct zombie unreaped until fresh custody and
                # descendant/EOF certificates have all passed.
                primitives._natural_terminal(proc.pid)
                if set(census()) != {proc.pid}: fail('CHILD_DESCENDANTS')
                if _cancel_requests: fail('CHILD_CANCELLED')
                code = proc.wait(timeout=max(.001, (end_ns-time.monotonic_ns())/1000000000))
                reaped.add(proc.pid)
                if primitives._children(): fail('CHILD_DESCENDANTS')
                if _cancel_requests: fail('CHILD_CANCELLED')
                normal = True; break
    except BaseException as error:
        failure = str(error) if isinstance(error, Refused) else 'CHILD_CANCELLED' if isinstance(error, (KeyboardInterrupt, SystemExit)) else 'CHILD_CUSTODY'
    finally:
        if proc is not None and not normal:
            # Failure settlement is never work time or a successful outcome.
            cleanup_end = time.monotonic() + 10
            try:
                census(False)
                item = _proc_identity(proc.pid)
                if proc.pid not in reaped and item and item['start'] == known.get(proc.pid):
                    try: os.killpg(proc.pid, signal.SIGTERM); counters['group_term_attempts'] += 1
                    except ProcessLookupError: pass
                for pid in list(known):
                    if pid != proc.pid: send(pid, signal.SIGTERM, 'adopted_term_attempts')
                killed = False
                term_end = min(cleanup_end, time.monotonic()+1)
                while time.monotonic() < cleanup_end:
                    current = census(False)
                    for pid in primitives._children():
                        try: waited, status = os.waitpid(pid, os.WNOHANG)
                        except ChildProcessError: continue
                        if waited:
                            reaped.add(pid)
                            if pid == proc.pid: proc.returncode = os.waitstatus_to_exitcode(status); code = proc.returncode
                    if not primitives._children() and not current: break
                    if not killed and time.monotonic() >= term_end:
                        for pid in list(known): send(pid, signal.SIGKILL, 'kill_attempts')
                        killed = True
                    try: pump(.01)
                    except Refused: pass
            except BaseException:
                failure = 'CHILD_SETTLEMENT'
        selector.close()
        if proc is not None:
            proc.stdout.close(); proc.stderr.close()
        for number, handler in original_handlers.items(): signal.signal(number, handler)
    remaining = primitives._children()
    return dict(stdout=bytes(output['stdout']), stderr=bytes(output['stderr']), exit_code=code,
                natural=normal, stdout_eof=eof['stdout'], stderr_eof=eof['stderr'], settled=not remaining,
                unreaped=list(remaining), failure=failure, cancellation_requests=_cancel_requests, **counters)


class FrameChannel:
    def read(self, end_ns):
        result = bytearray()
        fd = sys.stdin.fileno()
        with selectors.DefaultSelector() as selector:
            selector.register(fd, selectors.EVENT_READ)
            while len(result) <= MAX_FRAME:
                _check_cancel()
                remaining = (end_ns - time.monotonic_ns()) / 1000000000
                if remaining <= 0 or not selector.select(min(.1, remaining)):
                    if remaining <= 0: fail('CONTROL_TIMEOUT')
                    continue
                chunk = os.read(fd, 1)
                if not chunk: fail('CONTROL_EOF')
                result += chunk
                if chunk == b'\n': return bytes(result)
        fail('FRAME_SIZE')

    def write(self, value, end_ns):
        raw = canonical(value)
        if len(raw) > MAX_FRAME: fail('FRAME_SIZE')
        fd = sys.stdout.fileno()
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        try:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            with selectors.DefaultSelector() as selector:
                selector.register(fd, selectors.EVENT_WRITE)
                offset = 0
                while offset < len(raw):
                    _check_cancel()
                    remaining = (end_ns-time.monotonic_ns())/1000000000
                    if remaining <= 0: fail('CONTROL_TIMEOUT')
                    if selector.select(min(.1, remaining)):
                        offset += os.write(fd, raw[offset:])
        finally:
            fcntl.fcntl(fd, fcntl.F_SETFL, flags)


def _private_file_facts(path, api):
    """Private preservation only, separate from public identity acquisition.

    The disposable fixture may hash retained secret bytes for preservation;
    this function never returns those bytes and is never an identity source.
    """
    path = Path(path)
    try: before = path.lstat()
    except FileNotFoundError: return dict(present=False)
    if not (stat.S_ISREG(before.st_mode) or stat.S_ISDIR(before.st_mode)) or before.st_nlink < 1:
        fail('SNAPSHOT_KIND')
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOCTTY
    fd = os.open(path, flags)
    try:
        if _metadata(os.fstat(fd)) != _metadata(before): fail('SNAPSHOT_CHANGED')
        result = dict(present=True, metadata=_metadata(before), label=api.file_context(fd))
        with api.file_defaults() as defaults:
            result['default_label'] = defaults.lookup(str(path), stat.S_IFMT(before.st_mode))
        if stat.S_ISREG(before.st_mode):
            if before.st_size > 128 * 1024**2: fail('SNAPSHOT_LIMIT')
            h = hashlib.sha256()
            while True:
                block = os.read(fd, 65536)
                if not block: break
                h.update(block)
            result['sha256'] = h.hexdigest()
        result['xattrs'] = {name: digest(os.getxattr(fd, name)) for name in sorted(os.listxattr(fd))}
        if _metadata(os.fstat(fd)) != _metadata(before) or _metadata(path.lstat()) != _metadata(before):
            fail('SNAPSHOT_CHANGED')
        return result
    finally:
        os.close(fd)


def _selected_modules(raw):
    if len(raw) > MAX_COMMAND or (raw and not raw.endswith(b'\n')):
        fail('MODULE_LISTING')
    selected = {}; unrelated = []
    for line in raw.splitlines():
        if line == b'No modules.': continue
        fields = line.split()
        if (len(fields) not in (3, 4) or len(fields) == 4 and fields[3] != b'disabled'
                or re.fullmatch(rb'[1-9][0-9]{0,2}', fields[0]) is None):
            fail('MODULE_LISTING')
        if fields[1] in (b'qshd', b'qshd_contexts'):
            name = fields[1].decode('ascii')
            if name in selected or int(fields[0]) != 400 or fields[2] != b'pp' or len(fields) != 3:
                fail('MODULE_ROLE')
            selected[name] = 400
        else: unrelated.append(line)
    return selected, digest(b'\n'.join(sorted(unrelated)))


def _strict_self_mac_admin(api, api_module):
    context = Path('/proc/self/attr/current').read_bytes().rstrip(b'\0\n')
    if not 0 < len(context) < 4096: fail('SELF_CONTEXT')
    api.check_context(context.decode('ascii'))
    cls = api._class('capability2')
    permission = api._call('string_to_av_perm', cls, b'mac_admin')
    if not permission or permission & (permission - 1): fail('MAC_ADMIN_UNKNOWN')
    decision = api_module.AvDecision()
    api._call('security_compute_av_flags_raw', context, context, cls, permission, ctypes.byref(decision))
    if decision.allowed & permission or decision.flags & 1: fail('MAC_ADMIN_NOT_DENIED')
    return dict(result='DENY', source_sha256=digest(context), flags=decision.flags)


def _service_facts(commands):
    fields = ('LoadState', 'ActiveState', 'SubState', 'UnitFileState', 'MainPID', 'InvocationID',
              'ControlGroup', 'ExecStartPre', 'ExecMainCode', 'ExecMainStatus', 'ExecMainStartTimestampMonotonic')
    argv = ['/usr/bin/systemctl', 'show', 'qshd.service', '--no-pager']
    for field in fields: argv += ['--property', field]
    code, output, errors = commands.run(argv, allow_nonzero=True)
    if code not in (0, 1, 4): fail('SERVICE_QUERY')
    result = {}
    for line in output.decode('utf-8').splitlines():
        key, separator, value = line.partition('=')
        if separator and key in fields:
            if key in result: fail('SERVICE_QUERY')
            result[key] = value
    pid_text = result.get('MainPID', '0')
    if not re.fullmatch('[0-9]+', pid_text): fail('SERVICE_PID')
    pid = int(pid_text)
    result['process'] = None
    if pid:
        before = _proc_identity(pid)
        executable = Path('/proc/' + str(pid) + '/exe')
        if os.readlink(executable) != '/usr/bin/qshd': fail('SERVICE_ELF_ROUTE')
        raw = executable.read_bytes()
        label = Path('/proc/' + str(pid) + '/attr/current').read_text().rstrip('\0\n')
        if before != _proc_identity(pid) or len(label.split(':')) < 4 or label.split(':')[2] != 'qshd_t':
            fail('SERVICE_DOMAIN')
        result['process'] = dict(pid=pid, identity=before, elf_sha256=digest(raw), domain=label)
    cgroup = result.get('ControlGroup', '')
    if cgroup and (not cgroup.startswith('/system.slice/') or '..' in Path(cgroup).parts):
        fail('SERVICE_CGROUP')
    members = Path('/sys/fs/cgroup' + cgroup + '/cgroup.procs') if cgroup else None
    result['cgroup_pids'] = [] if members is None or not members.exists() else [int(x) for x in members.read_text().split()]
    listeners = []
    for name in ('udp', 'udp6'):
        for line in Path('/proc/net/' + name).read_text().splitlines()[1:]:
            fields = line.split()
            if len(fields) > 1 and fields[1].rsplit(':', 1)[-1] == format(60022, '04X'):
                listeners.append(name)
    result['listeners'] = listeners
    return result


def native_observation(manifest_path, end_ns, evidence):
    """Only the fixed owned child calls this read-only native adapter."""
    raw, manifest = _document(manifest_path)
    verify_input(manifest['inputs']['api'])
    api_module = _load_module(manifest['inputs']['api']['path'], 'qsh57_fixture_selinux_api')
    api = api_module.SelinuxApi()
    commands = OwnedCommands(manifest['inputs']['owner'], _LocalEnd(end_ns), Path(evidence) / 'children')
    selected = {}; pair = []; prefix = ('/usr/bin/semodule', '--store-path', '/var/lib/selinux', '-s', 'targeted')
    with api.status_observation():
        code, listing, errors = commands.run(prefix + ('-lfull',), seconds=15)
        if errors: fail('MODULE_STDERR')
        selected, unrelated = _selected_modules(listing)
        for name in ('qshd', 'qshd_contexts'):
            if name not in selected: pair.append(None); continue
            scratch = Path(evidence) / name; scratch.mkdir(mode=0o700)
            commands.run(prefix + ('-X', '400', '--hll', '-E', name), seconds=15, cwd=scratch)
            extracted = scratch / (name + '.pp')
            info = extracted.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 16*1024**2:
                fail('HLL_FILE')
            pair.append(digest(extracted.read_bytes()))
        if commands.run(prefix + ('-lfull',), seconds=15)[1] != listing: fail('MODULE_CHANGED')
        files = sorted(set().union(*(set(a['files'][role]) for a in manifest['artifacts'].values()
                                     for role in ('provider', 'consumer'))))
        payload = {path: _private_file_facts(path, api) for path in files}
        service = _service_facts(commands)
        active = service.get('ActiveState') == 'active' or service['process'] is not None
        retained = {}
        for path in manifest['retained_paths']:
            if not active:
                retained[path] = _private_file_facts(path, api)
                continue
            # Active logs legitimately change; metadata here is a live fact,
            # never a retained-content preservation baseline.
            try: info = Path(path).lstat()
            except FileNotFoundError: retained[path] = dict(present=False, active_unstable=True)
            else: retained[path] = dict(present=True, active_unstable=True, metadata=_metadata(info))
        registry = {path: _private_file_facts(path, api) for path in manifest['registry_paths']}
        sidecars = {path: _private_file_facts(path, api) for path in (PAM + '.rpmnew', PAM + '.rpmsave')}
        layout = {path: _private_file_facts(path, api) for path in
                  ('/var/lib/qshd/selinux-activation', '/var/lib/qshd/selinux-activation/lock')}
        try: state_raw, activation = _document(ACTIVATION, 65536)
        except FileNotFoundError: activation = None; state_raw = b''
        denial = _strict_self_mac_admin(api, api_module)
    packages = {}
    for role, name in [('provider', 'qshd-selinux'), ('consumer', 'qshd')]:
        code, output, errors = commands.run(('/usr/bin/rpm', '-q', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n', name), allow_nonzero=True)
        if code == 0:
            values = output.decode('ascii').splitlines()
            if not values or len(values) > 2: fail('RPMDB_QUERY')
            packages[role] = values
        elif code == 1 and not errors: packages[role] = []
        else: fail('RPMDB_QUERY')
    snapshot = dict(arch=os.uname().machine, pair=pair, unrelated_modules=unrelated,
        payload=payload, retained=retained, retained_scope='active-metadata-only' if active else 'stopped-private-preservation',
        registry=registry, sidecars=sidecars, layout=layout, activation=activation,
        activation_sha256=digest(state_raw), service=service, packages=packages, mac_admin=denial)
    data = canonical(snapshot)
    if len(data) > MAX_COMMAND: fail('SNAPSHOT_OUTPUT')
    sys.stdout.buffer.write(data)


def _retained_content(snapshot):
    result = {}
    for path, value in snapshot['retained'].items():
        if value.get('active_unstable'): fail('ACTIVE_PRESERVATION_BASELINE')
        if not value['present']: continue
        metadata = value['metadata']
        result[path] = dict(sha256=value.get('sha256'), metadata={name: metadata[name]
            for name in ('dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size')},
            xattrs={key: item for key, item in value['xattrs'].items() if key != 'security.selinux'})
    return result


def _phase_for(role, hook, count):
    if hook == 'postun' or hook == 'preun' and count > 0:
        return None
    if role == 'provider':
        if hook == 'prein': return 'provider-pre-owned' if count > 1 else 'provider-pre-fresh'
        if hook == 'postin': return 'provider-post-owned' if count > 1 else 'provider-post-pristine'
        if hook == 'preun': return 'provider-preun-final'
    if role == 'consumer':
        if hook == 'prein': return 'consumer-pre-installed' if count > 1 else 'consumer-pre-fresh'
        if hook == 'postin': return 'consumer-post-owned'
        if hook == 'preun': return 'consumer-preun-final'
    fail('HOOK_KIND')


def _phase_request(phase, artifact):
    value = dict(schema=2, phase=phase)
    if phase in ('provider-pre-owned', 'provider-pre-fresh'): value['artifact'] = artifact
    return value


def _json_lines(raw):
    result = []
    for line in raw.splitlines(keepends=True):
        if line.startswith(b'{'):
            if not line.endswith(b'\n') or len(line) > MAX_FRAME: fail('PHASE_FRAME')
            try: value = json.loads(line, object_pairs_hook=_pairs)
            except (ValueError, RecursionError): fail('PHASE_FRAME')
            if canonical(value) != line: fail('PHASE_FRAME')
            result.append((line, value))
    return result


def _phase_refusal(raw, request):
    value = parse_frame(raw, {'version', 'request', 'codes', 'command'})
    if (value['version'] != 1 or type(value['version']) is not int or value['request'] != request
            or type(value['codes']) is not list or not 1 <= len(value['codes']) <= 8
            or request['phase'] != 'managed-prestart' and not any(
                type(code) is str and code.startswith('COORDINATOR_') for code in value['codes'])
            or any(type(code) is not str or re.fullmatch('[A-Z_]{1,64}', code) is None for code in value['codes'])
            or any(code.startswith(('COMMAND_', 'PROCESS_')) or code in ('OUTPUT_LIMIT', 'OUTPUT_INCOMPLETE', 'TOOL_FAILURE')
                   for code in value['codes']) or value['command'] is not None):
        fail('ABNORMAL_PHASE_REFUSAL')
    return value


class Native:
    """Fixed guest operations; all mutations occur only through explicit cases."""
    def __init__(self, manifest, manifest_path, budget, evidence, channel):
        self.m = manifest; self.manifest_path = Path(manifest_path); self.budget = budget
        self.root = Path(evidence); self.channel = channel
        self.commands = OwnedCommands(manifest['inputs']['owner'], budget, self.root / 'commands')
        self.events = []; self.snapshots = []; self.pty_results = []; self.public_observations = []
        self.first_public = None
        for name in ('events.jsonl', 'snapshots.jsonl', 'commands.jsonl', 'rpm.log'):
            with (self.root / name).open('xb'): pass

    def event(self, kind, **facts):
        record = dict(kind=kind, **facts)
        self.events.append(record)
        with (self.root / 'events.jsonl').open('ab') as stream: stream.write(canonical(record))

    def run(self, argv, **kwargs):
        return self.commands.run(argv, cwd=self.root, **kwargs)

    def snapshot(self, label):
        self.budget.check()
        scratch = self.root / ('observe-' + str(len(self.snapshots)))
        scratch.mkdir(mode=0o700)
        code = ('import runpy,sys; m=runpy.run_path(sys.argv[1]); '
                'm["native_observation"](sys.argv[2],int(sys.argv[3]),sys.argv[4])')
        end = self.budget.operation_end(60000)
        status, out, err = self.run(('/usr/bin/python3', '-I', '-B', '-c', code,
            str(Path(__file__).resolve()), str(self.manifest_path), str(end), str(scratch)), seconds=60)
        if err: fail('SNAPSHOT_STDERR')
        try: value = json.loads(out, object_pairs_hook=_pairs)
        except (ValueError, RecursionError): fail('SNAPSHOT_JSON')
        if canonical(value) != out: fail('SNAPSHOT_JSON')
        validate_architecture(self.m['arch'], value['arch'])
        self.snapshots.append(value)
        with (self.root / 'snapshots.jsonl').open('ab') as stream:
            stream.write(canonical(dict(label=label, facts=value)))
        return value

    def pristine(self):
        if (os.geteuid() != 0 or Path('/proc/1/comm').read_text().strip() != 'systemd'
                or '\nVERSION_ID=44\n' not in '\n' + Path('/etc/os-release').read_text()):
            fail('NATIVE_ENVIRONMENT')
        validate_architecture(self.m['arch'], os.uname().machine)
        self.actual_runtime = {path: digest(Path(path).read_bytes()) for path in self.m['rpm_callback_contract']['runtime']}
        validate_rpm_admission(self.m['rpm_callback_contract'], self.actual_runtime, self.m['arch'])
        code, out, err = self.run(('/usr/bin/rpm', '-q', '--qf', '%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n', 'rpm'))
        if err or out.decode('ascii').strip() != self.m['rpm_callback_contract']['rpm_nevra']:
            fail('RPM_TOOL_BINDING')
        self.event('initial-daemon-key-absence', observation=require_daemon_key_absent())
        value = self.snapshot('pristine')
        if (any(value['packages'].values()) or value['pair'] != [None, None] or value['activation'] is not None
                or value['service']['process'] is not None or value['service']['listeners']
                or any(row['present'] for row in value['payload'].values())
                or any(row['present'] for row in value['retained'].values())
                or any(row['present'] for row in value['sidecars'].values())):
            fail('NOT_PRISTINE')
        return value

    def _input(self, name):
        return self.m['inputs'][name]['path']

    def _script(self, artifact, role, hook, *, installed=False):
        tag = dict(prein='PREIN', postin='POSTIN', preun='PREUN', postun='POSTUN')[hook]
        selector = self.m['artifacts'][artifact]['nevra'][role] if installed else self._input(artifact + '-' + role)
        mode = '-q' if installed else '-qp'
        code, raw, err = self.run(('/usr/bin/rpm', mode, '--nosignature', '--qf', '%{' + tag + '}', selector))
        if err or digest(raw) != self.m['artifacts'][artifact]['scripts'][role][hook]:
            fail('SCRIPT_BYTE_BINDING')
        query = '[%{' + tag + 'PROG}\\n]%|' + tag + 'FLAGS?{%{' + tag + 'FLAGS}}:{0}|\\n'
        code, metadata, errors = self.run(('/usr/bin/rpm', mode, '--nosignature', '--qf', query, selector))
        if errors or metadata.splitlines() != [b'/bin/sh', b'0']:
            fail('SCRIPT_INTERPRETER_OR_FLAGS')
        return raw

    def transaction(self, kind, artifact, roles, *, installed=None, refuse=False, skip_post=False):
        before = self.snapshot('before-' + kind)
        self.verify_helpers(before)
        context = {}; expected = []
        for role in roles:
            rows = before['packages'][role]
            if len(rows) > 1 or kind == 'install' and rows or kind != 'install' and len(rows) != 1:
                fail('RPMDB_TRANSITION')
            incoming = self.m['artifacts'][artifact]
            old = self.m['artifacts'][installed] if installed else None
            if old and rows != [old['nevra'][role]]: fail('OLD_PACKAGE_BINDING')
            hooks = ('preun', 'postun') if kind == 'erase' else ('prein', 'postin')
            for hook in hooks: self._script(artifact, role, hook, installed=kind == 'erase')
            context[incoming['nevra'][role]] = dict(role=role, artifact=artifact,
                scripts=incoming['scripts'][role], interpreter='/bin/sh', flags=0)
            if kind == 'erase':
                expected += [(role, artifact, 'preun', 'zero'), (role, artifact, 'postun', 'zero')]
            else:
                branch = 'one' if not rows else 'two-or-more'
                expected.append((role, artifact, 'prein', branch))
                if not skip_post: expected.append((role, artifact, 'postin', branch))
                if old:
                    for hook in ('preun', 'postun'): self._script(installed, role, hook, installed=True)
                    context[old['nevra'][role]] = dict(role=role, artifact=installed,
                        scripts=old['scripts'][role], interpreter='/bin/sh', flags=0)
                    expected += [(role, installed, 'preun', 'positive'), (role, installed, 'postun', 'positive')]
        if kind == 'erase':
            argv = ['/usr/bin/rpm', '-evv', '--'] + ['qshd-selinux' if r == 'provider' else 'qshd' for r in roles]
        else:
            argv = ['/usr/bin/rpm', '-Uvv'] + (['--nopost'] if skip_post else []) + ['--']
            # Real fresh install lists the consumer first to test dependency sorting.
            argv += [self._input(artifact + '-' + role) for role in reversed(roles)]
        if refuse: expected = expected[:1]
        # These expected route classes determine the watchdog only. They do NOT
        # supply a measured count or establish which native hook executed.
        route_value = {'one': 1, 'two-or-more': 2, 'positive': 1, 'zero': 0}
        phases = [_phase_for(r, h, route_value[c]) for r, a, h, c in expected]
        ordinary = sum(phase not in (None, 'provider-pre-fresh') for phase in phases)
        fresh = phases.count('provider-pre-fresh')
        noop = len(expected) - ordinary - fresh
        metadata = sum(r == 'consumer' and h == 'postin' for r, a, h, c in expected)
        seconds = 50 + 450*ordinary + 40*fresh + 20*(noop + metadata)
        code, out, err = self.run(argv, seconds=seconds, allow_nonzero=refuse)
        command_index = len(self.commands.records) - 1
        capture_record = self.commands.records[command_index]
        with (self.root / 'rpm.log').open('ab') as log:
            log.write(canonical(dict(kind='BEGIN', command=command_index, stdout_sha256=digest(out), stderr_sha256=digest(err))))
            log.write(out); log.write(err); log.write(canonical(dict(kind='END', command=command_index)))
        records = parse_rpm_execution(err, context)
        frames = _json_lines(out)
        failures = [(raw, value) for raw, value in _json_lines(err) if 'codes' in value]
        if refuse:
            if code == 0 or len(records) != 1 or records[0]['script_exit'] == 0 or frames or len(failures) != 1:
                fail('EXPECTED_PRE_REFUSAL')
        elif code != 0 or failures or any(row['script_exit'] != 0 for row in records):
            fail('RPM_HOOK_STATUS')
        after = self.snapshot('after-' + kind)
        self.verify_helpers(after)
        records = classify_rpm_branches(records, frames, failures,
            {name: data['identity'] for name, data in self.m['artifacts'].items()}, before, after,
            self.m['rpm_callback_contract'], self.actual_runtime,
            capture=dict(normal=capture_record['natural'], stdout_eof=capture_record['stdout_eof'],
                         stderr_eof=capture_record['stderr_eof']),
            operation='upgrade-skipped-post' if skip_post else kind)
        validate_hooks(records, expected)
        self.event('rpm-transaction', kind_scope='actual-rpm-post-skipped' if skip_post else 'actual-rpm',
            operation=kind, artifact=artifact, callbacks=records,
            stdout_phase_frames=[value for raw, value in frames],
            stderr_refusal_frames=[value for raw, value in failures], command=command_index,
            ordering_basis='native-debug-stderr sequence and independent stdout phase sequence; no cross-stream order')
        return after

    def verify_helpers(self, snapshot):
        if not snapshot['packages']['provider']: return
        for name in RUNTIME_MODULES:
            path = '/usr/libexec/qshd-selinux/' + name
            expected = self.m['artifacts']['A']['files']['provider'][path]
            actual = snapshot['payload'][path]
            if (not actual['present'] or actual['sha256'] != expected['sha256']
                    or actual['metadata']['mode'] != expected['mode'] or actual['metadata']['uid'] != 0):
                fail('EXECUTING_HELPER_SOURCE')

    def payload(self, snapshot, provider, consumer):
        for role, artifact in (('provider', provider), ('consumer', consumer)):
            if artifact is None:
                if snapshot['packages'][role]: fail('PACKAGE_REMAINS')
                paths = set().union(*(set(a['files'][role]) for a in self.m['artifacts'].values()))
                if any(snapshot['payload'][path]['present'] for path in paths): fail('PACKAGE_FILES_REMAIN')
                continue
            package = self.m['artifacts'][artifact]
            if snapshot['packages'][role] != [package['nevra'][role]]: fail('PACKAGE_IDENTITY')
            for path, expected in package['files'][role].items():
                actual = snapshot['payload'][path]
                if (not actual['present'] or actual.get('sha256') != expected['sha256']
                        or actual['metadata']['mode'] != expected['mode']
                        or actual['metadata']['uid'] != 0 or actual['metadata']['gid'] != 0):
                    fail('INSTALLED_PAYLOAD')

    def inactive(self, snapshot, *, disabled=False):
        service = snapshot['service']
        if (service.get('ActiveState') not in ('inactive', 'failed', None, '') or service['process'] is not None
                or service['listeners'] or service['cgroup_pids']
                or disabled and service.get('UnitFileState') != 'disabled'):
            fail('NOT_DRAINED')

    def ready(self, artifact):
        code, raw, err = self.run(('/usr/bin/python3', '-I', '-B', PHASE, 'managed-prestart'), seconds=450)
        if err: fail('START_GATE_STDERR')
        frame = parse_frame(raw, {'schema', 'phase', 'request_sha256', 'profile', 'registry_sha256', 'receipts_sha256'})
        request = dict(schema=2, phase='managed-prestart')
        if (type(frame['schema']) is not int or frame['schema'] != 2 or frame['phase'] != request['phase']
                or frame['request_sha256'] != digest(canonical(request).rstrip(b'\n'))
                or frame['profile'] != 'fedora44-targeted-pair-v2'
                or not _hex(frame['registry_sha256']) or not _hex(frame['receipts_sha256'])):
            fail('START_GATE_FRAME')
        snapshot = self.snapshot('ready-' + artifact)
        state = snapshot['activation']; identity = self.m['artifacts'][artifact]['identity']
        if (not state or state.get('artifact') != identity or state.get('basis') is not None
                or state.get('completion', {}).get('contexts') != {key: frame[key] for key in ('registry_sha256', 'receipts_sha256')}):
            fail('START_STATE_BINDING')
        validate_ready(dict(state=state.get('state'), current_pair=snapshot['pair'],
            expected_pair=[identity['core_pp_sha256'], identity['contexts_pp_sha256']], managed_prestart=True))
        self.event('managed-prestart', frame=frame)
        return snapshot

    def gate_refuses(self):
        code, out, err = self.run(('/usr/bin/python3', '-I', '-B', PHASE, 'managed-prestart'), seconds=450, allow_nonzero=True)
        if code == 0 or out: fail('EXPECTED_START_REFUSAL')
        _phase_refusal(err, dict(schema=2, phase='managed-prestart'))
        self.event('managed-prestart-refusal', stderr_sha256=digest(err))

    def staged(self, hook, count, *, refuse=False):
        raw = self._script('B', 'provider', hook)
        path = self.root / ('staged-' + hook + '-' + str(count)); path.write_bytes(raw); path.chmod(0o600)
        code, out, err = self.run(('/bin/sh', str(path), str(count)), seconds=450 if count != 1 else 40,
                                  allow_nonzero=refuse)
        phase = _phase_for('provider', hook, count)
        if refuse:
            if code == 0 or out: fail('EXPECTED_STAGED_REFUSAL')
            if count == 1:
                if err != b'PROVIDER_PRE_REFUSED\n': fail('FRESH_REFUSAL_EVIDENCE')
            elif phase is not None: _phase_refusal(err, _phase_request(phase, self.m['artifacts']['B']['identity']))
        else:
            if code != 0 or err or phase is None: fail('STAGED_HOOK')
            validate_phase(out, _phase_request(phase, self.m['artifacts']['B']['identity']), self.m['artifacts']['B']['identity'])
        self.event('staged-hook', kind_scope='explicit-staged-not-rpm', hook=hook, count=count,
                   script_sha256=digest(raw), refused=refuse)

    def prepare_accounts(self):
        for slot in ('first', 'second'):
            identity = self.m['accounts'][slot]; name = identity['name']; uid = identity['uid']
            for key in (name, str(uid)):
                code, output, errors = self.run(('/usr/bin/getent', 'passwd', key), allow_nonzero=True)
                if code != 2 or output or errors: fail('FIXTURE_ACCOUNT_COLLISION')
            home = Path('/home') / name
            if home.exists() or home.is_symlink(): fail('FIXTURE_HOME_COLLISION')
            self.run(('/usr/sbin/useradd', '--create-home', '--user-group', '--uid', str(uid), '--shell', '/bin/bash', name))
            # No password login is used: the isolated guest's SSH configuration
            # permits fixture keys only, and qsh uses its actual public-key path.
            self.run(('/usr/bin/passwd', '--delete', name))
            code, output, errors = self.run(('/usr/bin/getent', 'passwd', name))
            fields = output.decode('ascii').strip().split(':')
            if len(fields) != 7 or int(fields[2]) != uid or fields[5] != str(home) or fields[6] != '/bin/bash':
                fail('FIXTURE_ACCOUNT')
            gid = int(fields[3])
            public = verify_input(self.m['inputs'][slot + '-public'])
            if len(public) > 4096 or len(public.splitlines()) != 1 or not public.startswith(b'ssh-ed25519 '):
                fail('FIXTURE_PUBLIC_KEY')
            ssh = home / '.ssh'; ssh.mkdir(mode=0o700); os.chown(ssh, uid, gid)
            rc = b"unset PROMPT_COMMAND\nPS1='QSH57_READY_" + slot.encode() + b"> '\nexport PS1\n"
            for path, data, mode in ((ssh / 'authorized_keys', public, 0o600),
                                     (home / '.bashrc', rc, 0o644),
                                     (home / '.bash_profile', b'. "$HOME/.bashrc"\n', 0o644)):
                # useradd may copy these two skeleton dotfiles; only these
                # newly owned fixture-account leaves may be replaced.
                if path.name.startswith('.bash') and path.is_file() and not path.is_symlink(): path.unlink()
                with path.open('xb') as stream: stream.write(data)
                path.chmod(mode); os.chown(path, uid, gid)
            keys = Path('/etc/qshd/keys')
            if not keys.is_dir() or keys.is_symlink(): fail('SYSTEM_KEYS_DIRECTORY')
            selected = keys / name
            with selected.open('xb') as stream: stream.write(public)
            selected.chmod(0o600)
            # Exact newly created fixture leaves only, never retained product
            # key/log repair or a broad user-tree restoration.
            for path in (home, ssh, ssh / 'authorized_keys', home / '.bashrc', home / '.bash_profile', selected):
                self.run(('/usr/sbin/restorecon', '-F', '--', str(path)))
            self.event('fixture-account-created', account=slot, uid=uid, public_key_sha256=digest(public))

    def start(self, artifact, *, first=False):
        self.ready(artifact)
        if first: self.event('before-first-service-absence', observation=require_daemon_key_absent())
        self.run(('/usr/bin/systemctl', 'start', 'qshd.service'), seconds=480)
        value = self.snapshot('running-' + artifact)
        process = value['service']['process']
        expected = self.m['artifacts'][artifact]['files']['consumer']['/usr/bin/qshd']['sha256']
        if (value['service'].get('ActiveState') != 'active' or process is None
                or process['elf_sha256'] != expected or not value['service']['listeners']):
            fail('SERVICE_START')
        self.event('explicit-service-start', artifact=artifact, process=process)
        return value

    def sessions(self, stage):
        # The owner separately proves pinned-SSH login for both fixture users.
        # These requests exercise the real direct qsh/PAM path only.
        for account in ('first', 'second'):
            sequence = len(self.pty_results) + 1
            if sequence > 6 or SESSIONS[sequence-1] != (stage, account): fail('PTY_SEQUENCE')
            slot = self.m['sessions'][sequence-1]
            public = observe_daemon_public_key()
            if self.first_public is None: self.first_public = public['public_key_hex']
            if public['public_key_hex'] != self.first_public: fail('DAEMON_KEY_REGENERATED')
            request = dict(schema=1, attempt_nonce=self.m['attempt_nonce'], case='lifecycle', arch=self.m['arch'],
                sequence=sequence, stage=stage, account=account, session_nonce=slot['session_nonce'],
                expected_uid=self.m['accounts'][account]['uid'], daemon_fingerprint=public['daemon_fingerprint'])
            _request_shape(request)
            pending_end = self.budget.operation_end(120000)
            self.channel.write(request, pending_end)
            result = self.channel.read(pending_end)
            self.budget.check(pending_end)
            parsed = validate_pty_result(result, request, self.m['client']['sha256'])
            self.pty_results.append(parsed)
            self.public_observations.append(dict(sequence=sequence, stage=stage, account=account,
                request_sha256=digest(canonical(request)), observation=public))
            self.event('host-pty-session', sequence=sequence, stage=stage, account=account,
                       request_sha256=digest(canonical(request)), result_sha256=digest(result))
            after = self.snapshot('after-session-' + str(sequence))
            # Only the permanent helper/worker may remain after a clean shell
            # exit. Helper status is queried below before stopping the service.
            if after['service'].get('ActiveState') != 'active': fail('SESSION_SERVICE')
            self.drain()

    def drain(self):
        end = self.budget.operation_end(60000)
        counters = frozenset(('admitted', 'provisional', 'retiring', 'retiring_pending', 'charged',
            'unconfirmed', 'missing_monitor', 'wait_lost', 'monitor_failed', 'receipt_lost',
            'retired_slots', 'wait_outstanding', 'receipt_outstanding'))
        while time.monotonic_ns() < end:
            code, raw, err = self.run(('/usr/bin/qshd', 'helper-status', '--socket', '/run/qshd/helper-status.sock'),
                seconds=min(15, (end-time.monotonic_ns())/1000000000))
            try: value = json.loads(raw, object_pairs_hook=_pairs)
            except (ValueError, RecursionError): fail('HELPER_STATUS')
            if (time.monotonic_ns() >= end or code != 0 or err or len(raw) > 4096 or type(value) is not dict or set(value) != {'schema', 'phase', 'capacity', 'limit', 'counts'}
                    or type(value['schema']) is not int or value['schema'] != 2 or value['phase'] != 'serving'
                    or value['capacity'] != 'available' or not _integer(value['limit'], 1, 65535)
                    or type(value['counts']) is not dict or set(value['counts']) != counters | {'pam', 'cleanup_failure'}):
                fail('HELPER_STATUS')
            counts = value['counts']
            if any(not _integer(counts[key], 0, 65535) for key in counters) or counts['cleanup_failure'] is not None:
                fail('HELPER_CLEANUP')
            if any(counts[key] for key in ('unconfirmed', 'missing_monitor', 'wait_lost', 'monitor_failed', 'receipt_lost')):
                fail('HELPER_CLEANUP_LOST')
            busy = any(counts[key] for key in counters)
            pam = counts['pam']
            transient = type(pam) is dict and pam == {'state': 'not_opened'}
            finished = (type(pam) is dict and set(pam) == {'state', 'close_session', 'delete_cred', 'end'}
                        and pam['state'] == 'finished'
                        and all(pam[key] == 'ok' for key in ('close_session', 'delete_cred', 'end')))
            if not finished and not (transient and busy):
                fail('PAM_CLEANUP')
            if not busy:
                self.event('actual-pam-session-drain', snapshot=value)
                return
            time.sleep(min(.05, max(0, (end-time.monotonic_ns())/1000000000)))
        fail('DRAIN_DEADLINE')

    def stop(self):
        self.run(('/usr/bin/systemctl', 'stop', 'qshd.service'), seconds=60)
        value = self.snapshot('stopped')
        self.inactive(value)
        self.event('explicit-service-stop', service=value['service'])
        return value

    def refused_start(self):
        before = self.snapshot('before-refused-managed-start')
        try:
            code, out, err = self.run(('/usr/bin/systemctl', 'start', 'qshd.service'), seconds=480, allow_nonzero=True)
        finally:
            # Cancel scheduled Restart immediately after the first start result,
            # before slow HLL/private snapshots can allow a scheduled retry.
            after = self.stop()
        service = after['service']; pre = service.get('ExecStartPre', '')
        started = service.get('ExecMainStartTimestampMonotonic')
        previous = before['service'].get('ExecMainStartTimestampMonotonic')
        if (code == 0 or service['process'] is not None or service['listeners']
                or 'code=exited' not in pre or re.search(r'status=[1-9][0-9]*', pre) is None
                or started not in ('0', '', previous) or after['activation'] != before['activation']):
            fail('MANAGED_START_WAS_NOT_REFUSED')
        self.event('managed-unit-refusal', service=service, first_start_stderr_sha256=digest(err))

    def fault(self, name):
        fault = self.m['fault']
        prefix = ('/usr/bin/semodule', '--store-path', '/var/lib/selinux', '-s', 'targeted', '-X', '400')
        if name in ('custom-pam-consumer', 'custom-pam-provider'):
            if fault: fail('FAULT_SCHEMA')
            with Path(PAM).open('ab') as stream: stream.write(b'# qsh57 synthetic administrator PAM change\n')
        elif name in ('rpmnew', 'rpmsave'):
            if fault: fail('FAULT_SCHEMA')
            with Path(PAM + '.' + name).open('xb') as stream: stream.write(b'qsh57 synthetic administrator sidecar\n')
        elif name in ('missing-pair', 'partial-erase'):
            if fault: fail('FAULT_SCHEMA')
            self.run(prefix + ('-r', 'qshd_contexts'), seconds=450)
        elif name == 'mixed-pair':
            if fault: fail('FAULT_SCHEMA')
            self.run(prefix + ('-i', self._input('B-core')), seconds=450)
        elif name == 'loaded-new-pending':
            if fault: fail('FAULT_SCHEMA')
            self.run(prefix + ('-i', self._input('B-core'), '-i', self._input('B-contexts')), seconds=450)
        elif name == 'pending-post':
            if fault: fail('FAULT_SCHEMA')
            Path('/usr/share/qshd-selinux/qshd.pp').chmod(0)
        elif name == 'admin-row':
            if set(fault) != {'path', 'before_sha256', 'old_row', 'new_row'} or fault['path'] not in self.m['registry_paths']:
                fail('ADMIN_ROW_SCHEMA')
            path = Path(fault['path']); data = path.read_bytes()
            old, new = fault['old_row'].encode('ascii'), fault['new_row'].encode('ascii')
            if (len(data) > MAX_COMMAND or digest(data) != fault['before_sha256'] or data.count(old) != 1
                    or not 0 < len(old) <= 4096 or not 0 < len(new) <= 4096
                    or old.count(b'\n') != 1 or new.count(b'\n') != 1 or not old.endswith(b'\n') or not new.endswith(b'\n')
                    or old not in data.splitlines(keepends=True)
                    or b':qshd_t:' not in old.split()[0] or b':qshd_t:' not in new.split()[0] or old == new):
                fail('ADMIN_ROW_INPUT')
            with path.open('r+b') as stream:
                stream.write(data.replace(old, new)); stream.truncate()
        elif name in ('custom-label', 'default-override'):
            if set(fault) != {'path', 'value'} or fault['path'] not in self.m['retained_paths']:
                fail('LABEL_FAULT_SCHEMA')
            path = Path(fault['path'])
            if not stat.S_ISREG(path.lstat().st_mode) or path.is_symlink(): fail('LABEL_FAULT_TARGET')
            if name == 'custom-label':
                if not re.fullmatch('[A-Za-z0-9_:,.-]{1,4095}', fault['value']) or ':qshd_' in fault['value']:
                    fail('LABEL_FAULT_VALUE')
                self.run(('/usr/bin/chcon', '--', fault['value'], str(path)))
            else:
                if not re.fullmatch('[a-z][a-z0-9_]{0,127}_t', fault['value']) or fault['value'].startswith('qshd_'):
                    fail('DEFAULT_FAULT_VALUE')
                self.run(('/usr/sbin/semanage', 'fcontext', '-a', '-f', 'f', '-t', fault['value'], re.escape(str(path)) + '$'))
        else:
            fail('FAULT_KIND')
        self.event('explicit-fixture-mutation', case=name, input_sha256=digest(canonical(fault)))


class CaseDriver:
    """One finite case in one pristine overlay. No repair or retry route."""
    def __init__(self, native):
        self.n = native
        self.m = native.m
        self.generations = set()

    def complete(self, artifact):
        value = self.n.ready(artifact)
        operation = value['activation']['operation_id']
        if operation in self.generations: fail('OPERATION_REUSED')
        self.generations.add(operation)
        return value

    def setup(self):
        self.initial = self.n.pristine()
        value = self.n.transaction('install', 'A', ('provider', 'consumer'))
        self.n.payload(value, 'A', 'A'); self.n.inactive(value, disabled=True)
        self.n.prepare_accounts()
        self.complete('A')
        return value

    def pending(self, value, target, basis):
        state = value['activation']
        if (not state or state.get('state') != 'PENDING'
                or state.get('artifact') != self.m['artifacts'][target]['identity']
                or not isinstance(state.get('basis'), dict)
                or state['basis'].get('artifact') != self.m['artifacts'][basis]['identity']
                or state.get('completion') is not None):
            fail('PENDING_BASIS')

    def preserved(self, before, after, *, payload=False, registry=False):
        if _retained_content(before) != _retained_content(after): fail('PRIVATE_CONTENT_CHANGED')
        if payload: validate_preserved(before, after, ('payload', 'packages', 'retained', 'sidecars'))
        if registry: validate_preserved(before, after, ('registry',))

    def erased(self, value, baseline):
        self.n.payload(value, None, None); self.n.inactive(value)
        if value['pair'] != [None, None] or value['activation'] is not None:
            fail('PAIR_OR_ACTIVATION_REMAINS')
        if any(row['present'] for row in value['sidecars'].values()): fail('PAM_SIDECAR_REMAINS')
        for path, expected_mode in (('/var/lib/qshd/selinux-activation', 0o040700),
                                    ('/var/lib/qshd/selinux-activation/lock', 0o100600)):
            actual = value['layout'][path]
            if (not actual['present'] or actual['metadata']['mode'] != expected_mode
                    or actual['metadata']['uid'] != 0 or actual['metadata']['gid'] != 0
                    or stat.S_ISREG(expected_mode) and (actual['metadata']['nlink'] != 1 or actual['metadata']['size'] != 0)):
                fail('RETIRED_LAYOUT')
        if value['unrelated_modules'] != self.initial['unrelated_modules']:
            fail('UNRELATED_MODULES_CHANGED')
        # Context transaction may replace its own registry file inode. Content,
        # owner/mode and unrelated rows must return to the pristine baseline.
        for path, initial in self.initial['registry'].items():
            current = value['registry'][path]
            if (current['sha256'] != initial['sha256'] or any(current['metadata'][key] != initial['metadata'][key]
                    for key in ('uid', 'gid', 'mode'))):
                fail('CONTEXT_ROWS_REMAIN')
        self.preserved(baseline, value)
        for retained in value['retained'].values():
            if retained['present'] and retained['label'] != retained['default_label']:
                fail('RETAINED_DEFAULT_LABEL')

    def run(self):
        case = self.m['case']
        if case not in CASES: fail('CASE')
        self.setup()
        if case == 'lifecycle':
            if self.m['fault']: fail('FAULT_SCHEMA')
            self.n.start('A', first=True); self.n.sessions('initial-A')
            stopped = self.n.stop()
            upgraded = self.n.transaction('upgrade', 'B', ('provider',), installed='A')
            self.n.payload(upgraded, 'B', 'A'); self.n.inactive(upgraded, disabled=True)
            self.preserved(stopped, upgraded)
            self.complete('B')
            consumer = self.n.transaction('upgrade', 'B', ('consumer',), installed='A')
            self.n.payload(consumer, 'B', 'B'); self.n.inactive(consumer, disabled=True)
            self.preserved(stopped, consumer)
            # The provider refresh and consumer install each own a new operation.
            self.complete('B')
            self.n.start('B'); self.n.sessions('upgraded-B'); baseline = self.n.stop()
            removed = self.n.transaction('erase', 'B', ('consumer',), installed='B')
            self.n.payload(removed, 'B', None); self.pending(removed, 'B', 'B')
            self.preserved(baseline, removed); self.n.gate_refuses()
            erased = self.n.transaction('erase', 'B', ('provider',), installed='B')
            self.erased(erased, baseline)
            reinstalled = self.n.transaction('install', 'B', ('provider', 'consumer'))
            self.n.payload(reinstalled, 'B', 'B'); self.n.inactive(reinstalled, disabled=True)
            self.preserved(baseline, reinstalled); self.complete('B')
            self.n.start('B'); self.n.sessions('reinstalled-B'); final_baseline = self.n.stop()
            removed = self.n.transaction('erase', 'B', ('consumer',), installed='B')
            self.pending(removed, 'B', 'B'); self.preserved(final_baseline, removed)
            erased = self.n.transaction('erase', 'B', ('provider',), installed='B')
            self.erased(erased, final_baseline)
            validate_sessions([{key: row[key] for key in REQUEST_KEYS} for row in self.n.pty_results])
            return erased
        # Negative setup is a real valid A installation, explicit normal start
        # and stop, so retained data comes from the product, not fabricated keys.
        self.n.start('A', first=True); baseline = self.n.stop()
        if case == 'preowned-transfer':
            if self.m['fault']: fail('FAULT_SCHEMA')
            self.n.staged('prein', 2)
            after = self.n.snapshot('staged-A-to-B-pending')
            self.pending(after, 'B', 'A'); self.n.payload(after, 'A', 'A')
            if after['pair'] != baseline['pair']: fail('STAGED_PRE_LOADED_POLICY')
            self.preserved(baseline, after, payload=True, registry=True)
            return after
        if case in ('pending-post', 'loaded-new-pending'):
            before_fault = self.n.transaction('upgrade', 'B', ('provider',), installed='A', skip_post=True)
            self.pending(before_fault, 'B', 'A')
            self.n.fault(case)
            fault = self.n.snapshot('post-payload-fault')
            self.n.staged('postin', 2, refuse=True)
            after = self.n.snapshot('refused-post')
            self.pending(after, 'B', 'A'); self.preserved(fault, after, payload=True)
            if after['pair'] != fault['pair']: fail('POST_REPAIRED_POLICY')
            self.n.gate_refuses(); self.n.refused_start()
            return after
        if case == 'partial-erase':
            before_fault = self.n.transaction('erase', 'A', ('consumer',), installed='A')
            self.pending(before_fault, 'A', 'A')
            self.n.fault(case)
            fault = self.n.snapshot('partial-pair-pending')
            after = self.n.transaction('upgrade', 'B', ('provider',), installed='A', refuse=True)
            self.preserved(fault, after, payload=True, registry=True)
            self.n.staged('prein', 1, refuse=True)
            self.n.gate_refuses(); self.n.refused_start()
            return after
        if case in ('custom-label', 'default-override'):
            consumer_gone = self.n.transaction('erase', 'A', ('consumer',), installed='A')
            self.pending(consumer_gone, 'A', 'A')
            self.n.fault(case)
            fault = self.n.snapshot('admitted-final-erase-fault')
            selected = fault['retained'][self.m['fault']['path']]
            if case == 'custom-label':
                if selected['label'] != self.m['fault']['value'] or selected['label'] == selected['default_label']:
                    fail('CUSTOM_LABEL_NOT_DISTINCT')
            elif selected['default_label'].split(':')[2] != self.m['fault']['value']:
                fail('DEFAULT_OVERRIDE_NOT_OBSERVED')
            after = self.n.transaction('erase', 'A', ('provider',), installed='A', refuse=True)
            self.preserved(fault, after, payload=True, registry=True)
            if after['pair'] != fault['pair']: fail('ERASE_REPAIRED_POLICY')
            return after
        self.n.fault(case)
        fault = self.n.snapshot('admitted-fault')
        role = 'consumer' if case in ('custom-pam-consumer', 'rpmnew', 'rpmsave') else 'provider'
        after = self.n.transaction('upgrade', 'B', (role,), installed='A', refuse=True)
        self.preserved(fault, after, payload=True, registry=True)
        if after['pair'] != fault['pair']: fail('PRE_REPAIRED_POLICY')
        if case == 'admin-row':
            # This second PRE is legitimate only if the first refused before
            # invalidation; otherwise preserve evidence and request a split.
            if after['activation'] != fault['activation']: fail('ADMIN_ROW_CASE_REQUIRES_SPLIT')
            second = self.n.transaction('upgrade', 'B', ('consumer',), installed='A', refuse=True)
            self.preserved(fault, second, payload=True, registry=True)
        if case in ('missing-pair', 'mixed-pair'):
            self.n.gate_refuses(); self.n.refused_start()
        return after


def _guest_resources(case):
    cpu = 13200 if case == 'lifecycle' else 4800
    for key, value in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_AS, 8*1024**3),
                       (resource.RLIMIT_CPU, cpu), (resource.RLIMIT_NOFILE, 128),
                       (resource.RLIMIT_FSIZE, 16*1024**2)):
        soft, hard = resource.getrlimit(key)
        if hard != resource.RLIM_INFINITY and hard < value: fail('GUEST_RESOURCE_LIMIT')
        resource.setrlimit(key, (value, value))


def main(arguments=None):
    parser = argparse.ArgumentParser(description='Explicit disposable-guest Fedora pair acceptance')
    parser.add_argument('--manifest', required=True, type=Path)
    parser.add_argument('--case', required=True, choices=CASES)
    parser.add_argument('--evidence', required=True, type=Path)
    args = parser.parse_args(arguments)
    lock = None
    try:
        if (not args.manifest.is_absolute() or not args.evidence.is_absolute()
                or '..' in args.evidence.parts or args.evidence.exists() or args.evidence.is_symlink()):
            fail('EVIDENCE_ROOT')
        _guest_resources(args.case)
        raw, manifest = load_manifest(args.manifest, args.case)
        args.evidence.mkdir(mode=0o700)
        lock = os.open(args.evidence / 'owner.lock', os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in ('home', 'config', 'cache', 'tmp'):
            (args.evidence / name).mkdir(mode=0o700)
        os.environ.update(HOME=str(args.evidence/'home'), XDG_CONFIG_HOME=str(args.evidence/'config'),
            XDG_CACHE_HOME=str(args.evidence/'cache'), TMPDIR=str(args.evidence/'tmp'),
            HISTFILE='/dev/null', PYTHONDONTWRITEBYTECODE='1')
        os.environ.pop('PYTHONPATH', None); os.environ.pop('PYTHONHOME', None)
        expected = dict(attempt_nonce=manifest['attempt_nonce'], case=args.case, arch=manifest['arch'], manifest_sha256=digest(raw))
        budget = GuestBudget(expected, args.evidence / 'attempted')
        channel = FrameChannel()
        budget.admit(channel.read(time.monotonic_ns()+120000000000))
        with (args.evidence / 'guest-budget.json').open('xb') as stream:
            stream.write(canonical(dict(domain='guest-monotonic-ns', start_ns=budget.start_ns, end_ns=budget.end_ns)))
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT): signal.signal(number, _request_cancel)
        native = Native(manifest, args.manifest, budget, args.evidence, channel)
        CaseDriver(native).run()
        budget.check()
        # Revalidate all immutable input bytes, including this driver's source.
        if args.manifest.read_bytes() != raw: fail('MANIFEST_CHANGED')
        for descriptor in manifest['inputs'].values(): verify_input(descriptor)
        validate_rpm_admission(manifest['rpm_callback_contract'],
            {path:digest(Path(path).read_bytes()) for path in manifest['rpm_callback_contract']['runtime']}, manifest['arch'])
        result = dict(schema=1, attempt_nonce=manifest['attempt_nonce'], case=args.case, arch=manifest['arch'],
            manifest_sha256=digest(raw), status='NATIVE_ACCEPTED', normal=True,
            host_pty_results=native.pty_results, daemon_public_observations=native.public_observations,
            command_count=len(native.commands.records), evidence_sha256={name:digest((args.evidence/(name+'.jsonl')).read_bytes())
                for name in ('events', 'snapshots', 'commands')})
        with (args.evidence / 'result.json').open('xb') as stream: stream.write(canonical(result))
        return 0
    except (Refused, OSError, ValueError, KeyError, TypeError, KeyboardInterrupt):
        sys.stderr.write('PAIR_ACCEPTANCE_REFUSED\n')
        return 1
    finally:
        if lock is not None: os.close(lock)


if __name__ == '__main__':
    raise SystemExit(main())
