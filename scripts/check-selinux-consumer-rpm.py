#!/usr/bin/env python3
"""Build-only selected RPM consistency; no install, extraction or origin proof.

Trusted native tools define package semantics. Their normalized CPIO metadata
is not independent proof of original payload headers. Caller owns immutable
inputs and trusts system RPM configuration. Native work shares one hard owner.
"""
import time
_ENTRY = time.monotonic()

import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import asdict
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import sys
import tempfile

_REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / 'packaging/selinux'))
from qshd_selinux_rpm_query import _authority_document
from qshd_selinux_files import PAM_SHA256
from qshd_selinux_process import _Owner, _Limits, _Streams, _children, _subreaper, _preconditions

# Reuse admitted ordinary-build-user routes/streaming source bindings, not
# root-only installed-file rules. Never import code from an input directory.
_spec = importlib.util.spec_from_file_location('_qsh_consumer_generator',
                                              _REPO / 'scripts/generate-selinux-consumer-authority.py')
_generator = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_generator)

_MAX_RPM = 256 * 1024**2
_MAX_STREAM = 256 * 1024**2
_MAX_HEADER = 4 * 1024**2
_MAX_ROWS = 16384
_MAX_NAME = 4096
_MAX_SMALL = 16384
_MAX_STDERR = 65536
_BINARY = '/usr/bin/qshd'
_PAM = '/etc/pam.d/qshd'
_MANIFEST = '/usr/share/qshd/consumer-rpm.json'
_FORMAT = (r'P\t%{NAME:json}\t%|EPOCH?{%{EPOCH}}:{0}|\t%{VERSION:json}\t%{RELEASE:json}\t%{ARCH:json}\n'
           r'A\t%{FILEDIGESTALGO}\n'
           r'[F\t%{FILENAMES:json}\t%{FILESIZES}\t%{FILEMODES}\t%{FILEFLAGS}\t%{FILEUSERNAME:json}\t%{FILEGROUPNAME:json}\t%{FILEDIGESTS:json}\t%{FILELINKTOS:json}\n]E\n')
_TOOLS = ('/usr/bin/rpm', '/usr/bin/rpm2cpio')


class CheckError(ValueError):
    """Safe fixed refusal category, without source paths or native output."""


def _fail(code):
    raise CheckError(code)


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True,
                       allow_nan=False)+'\n').encode('ascii')


def _digest(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        _fail('DIGEST')
    return value


def _paths(paths):
    if len(paths) != 3:
        _fail('INPUTS')
    result = []
    for value in paths:
        value = os.fspath(value)
        if (type(value) is not str or '\0' in value or '..' in Path(value).parts
                or len(os.fsencode(value)) > 4096):
            _fail('INPUTS')
        result.append(os.path.abspath(value))
    return tuple(result)


def _request(paths):
    return hashlib.sha256(_canonical(list(_paths(paths)))).hexdigest()


def _check_time(deadline, clock):
    if type(deadline) not in (int, float) or not math.isfinite(deadline) or clock() >= deadline:
        _fail('DEADLINE')


def _resources():
    """Only a dedicated CLI/test-helper process may irreversibly lower limits."""
    for key, wanted in ((resource.RLIMIT_CORE, 0), (resource.RLIMIT_FSIZE, 16*1024**2),
                        (resource.RLIMIT_AS, 1024**3), (resource.RLIMIT_NOFILE, 128),
                        (resource.RLIMIT_CPU, 70)):
        _, hard = resource.getrlimit(key)
        if hard != resource.RLIM_INFINITY and hard < wanted:
            _fail('RESOURCE_LIMITS')
        resource.setrlimit(key, (wanted, wanted))


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            _fail('DUPLICATE_KEY')
        value[key] = item
    return value


def _json(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                      parse_constant=lambda unused: _fail('JSON'))


def _authority(manifest, receipt):
    authority = _authority_document(manifest)
    if authority.package.arch not in ('x86_64', 'aarch64'):
        _fail('PRODUCT')
    for entry, path, mode, flags, maximum in zip(authority.files, (_PAM, _BINARY),
                                                 (0o100644, 0o100755), (17, 0),
                                                 (4096, 128*1024**2)):
        if (entry.path != path or entry.mode != mode or entry.flags != flags
                or entry.owner != 'root' or entry.group != 'root'
                or not 0 < entry.size <= maximum):
            _fail('PRODUCT')
    if authority.files[0].sha256 != PAM_SHA256:
        _fail('PAM')
    document = _json(receipt)
    if (type(document) is not dict or set(document) !=
            {'schema', 'package', 'files', 'build_metadata_sha256', 'manifest_sha256'}
            or type(document['schema']) is not int or document['schema'] != 1
            or document['package'] != asdict(authority.package)
            or document['files'] != [{'path': entry.path, 'size': entry.size, 'sha256': entry.sha256}
                                      for entry in authority.files]
            or document['manifest_sha256'] != hashlib.sha256(manifest).hexdigest()
            or _canonical(document) != receipt):
        _fail('RECEIPT')
    _digest(document['build_metadata_sha256'])
    # Python equality alone equates bools with integers. Compare the complete
    # expected typed encoding too, including normalized package/file records.
    expected = dict(document, schema=1, package=asdict(authority.package),
                    files=[{'path': entry.path, 'size': entry.size, 'sha256': entry.sha256}
                           for entry in authority.files])
    if _canonical(expected) != receipt:
        _fail('RECEIPT')
    return authority


def _path(value):
    if (type(value) is not str or not value.startswith('/')
            or len(value.encode('utf-8')) > _MAX_NAME or '\0' in value
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(part in ('', '.', '..') for part in value[1:].split('/'))):
        _fail('PATH')
    return value


def _number(value, maximum=2**64-1):
    if len(value) > 20 or re.fullmatch('0|[1-9][0-9]*', value) is None:
        _fail('NUMBER')
    result = int(value)
    if result > maximum:
        _fail('NUMBER')
    return result


def _string(value):
    result = _json(value.encode('utf-8'))
    if type(result) is not str or result in ('(none)', '(null)'):
        _fail('STRING')
    return result


def _header(raw, authority, manifest):
    if not raw.endswith(b'\n'):
        _fail('HEADER')
    lines = raw.decode('utf-8').splitlines()
    if not 4 <= len(lines) <= _MAX_ROWS + 3 or lines[-1] != 'E':
        _fail('HEADER')
    p = lines[0].split('\t')
    if (len(p) != 6 or p[0] != 'P' or
            [_string(p[1]), _number(p[2], 2**32-1), *(_string(v) for v in p[3:])] !=
            list(asdict(authority.package).values()) or lines[1] != 'A\t8'):
        _fail('PACKAGE')
    files = {}
    for line in lines[2:-1]:
        fields = line.split('\t')
        if len(fields) != 9 or fields[0] != 'F':
            _fail('HEADER_ROW')
        path = _path(_string(fields[1]))
        if path in files:
            _fail('DUPLICATE_PATH')
        size, mode, flags = _number(fields[2]), _number(fields[3], 65535), _number(fields[4], 2**32-1)
        owner, group, digest, link = map(_string, fields[5:])
        kind = stat.S_IFMT(mode)
        if kind not in (stat.S_IFREG, stat.S_IFDIR, stat.S_IFLNK) or flags & 64:
            _fail('HEADER_TYPE')
        if (not owner or not group or len(owner) > 256 or len(group) > 256
                or len(link.encode('utf-8')) > _MAX_NAME):
            _fail('HEADER_ROW')
        if kind == stat.S_IFREG:
            _digest(digest)
            if link:
                _fail('HEADER_LINK')
        elif digest or (kind == stat.S_IFDIR and (size or link)):
            _fail('HEADER_ROW')
        files[path] = dict(path=path, size=size, mode=mode, flags=flags, owner=owner,
                           group=group, sha256=digest, link=link)
    expected = {entry.path: asdict(entry) for entry in authority.files}
    expected[_MANIFEST] = dict(path=_MANIFEST, size=len(manifest),
                               sha256=hashlib.sha256(manifest).hexdigest(), mode=0o100644,
                               owner='root', group='root', flags=0)
    for path, entry in expected.items():
        if path not in files or {k: files[path][k] for k in entry} != entry or files[path]['link']:
            _fail('SELECTED_HEADER')
    return files


class _Cpio:
    """Bounded normalized newc stream; never extract, seek or retain binary data."""
    def __init__(self, headers, manifest):
        self.headers = headers
        self.manifest = manifest
        self.buffer = bytearray()
        self.state = 'header'
        self.need = 110
        self.total = 0
        self.padding = 0
        self.seen = set()
        self.selected = {}

    def feed(self, data):
        self.total += len(data)
        if self.total > _MAX_STREAM:
            _fail('STREAM_LIMIT')
        self.buffer.extend(data)
        while self.buffer:
            if self.state == 'end':
                self.padding += len(self.buffer)
                if self.padding > 65536 or any(self.buffer):
                    _fail('TRAILING')
                self.buffer.clear()
                return
            if self.state == 'data':
                count = min(self.need, len(self.buffer))
                block = self.buffer[:count]
                del self.buffer[:count]
                if self.hash is not None:
                    self.hash.update(block)
                if self.small is not None:
                    self.small.extend(block)
                self.need -= count
                if self.need:
                    return
                if self.hash is not None:
                    self.selected[self.name] = (self.hash.hexdigest(), bytes(self.small) if self.small is not None else None)
                self.state, self.need = 'data-pad', (-self.size) % 4
            elif self.need and len(self.buffer) < self.need:
                return
            elif self.state == 'header':
                raw = bytes(self.buffer[:110]); del self.buffer[:110]
                if raw[:6] != b'070701' or re.fullmatch(b'[0-9a-fA-F]{104}', raw[6:]) is None:
                    _fail('CPIO_HEADER')
                fields = [int(raw[index:index+8], 16) for index in range(6, 110, 8)]
                self.mode, self.nlink, self.size, self.namesize = fields[1], fields[4], fields[6], fields[11]
                if not 1 < self.namesize <= _MAX_NAME+1 or fields[12] != 0:
                    _fail('CPIO_HEADER')
                self.state, self.need = 'name', self.namesize
            elif self.state == 'name':
                raw = bytes(self.buffer[:self.need]); del self.buffer[:self.need]
                if raw[-1:] != b'\0' or b'\0' in raw[:-1]:
                    _fail('CPIO_NAME')
                name = raw[:-1].decode('utf-8')
                self.trailer = name == 'TRAILER!!!'
                if self.trailer:
                    if self.size:
                        _fail('CPIO_TRAILER')
                else:
                    self.name = _path('/'+name[2:] if name.startswith('./') else name)
                    if self.name in self.seen or len(self.seen) >= _MAX_ROWS:
                        _fail('CPIO_DUPLICATE')
                    self.seen.add(self.name)
                    entry = self.headers.get(self.name)
                    if (entry is None or self.size != entry['size'] or stat.S_IFMT(self.mode) != stat.S_IFMT(entry['mode'])
                            or self.nlink < 1 or (not stat.S_ISDIR(self.mode) and self.nlink != 1)
                            or self.size > _MAX_STREAM):
                        _fail('CPIO_MEMBER')
                    if stat.S_ISDIR(self.mode) and self.size:
                        _fail('CPIO_MEMBER')
                    if stat.S_ISLNK(self.mode) and self.size > _MAX_NAME:
                        _fail('CPIO_MEMBER')
                    self.hash = hashlib.sha256() if self.name in (_BINARY, _PAM, _MANIFEST) else None
                    self.small = bytearray() if self.name in (_PAM, _MANIFEST) or stat.S_ISLNK(self.mode) else None
                self.state, self.need = 'name-pad', (-(110+self.namesize)) % 4
            elif self.state in ('name-pad', 'data-pad'):
                if any(self.buffer[:self.need]):
                    _fail('CPIO_PADDING')
                del self.buffer[:self.need]
                if self.state == 'data-pad':
                    if stat.S_ISLNK(self.mode) and bytes(self.small) != self.headers[self.name]['link'].encode('utf-8'):
                        _fail('CPIO_LINK')
                    self.state, self.need = 'header', 110
                elif self.trailer:
                    self.state, self.need = 'end', 0
                else:
                    self.state, self.need = 'data', self.size
            else:
                _fail('CPIO_STATE')

    def finish(self):
        # Advance zero-sized transitions even if the final chunk ended there.
        self.feed(b'')
        if self.state != 'end' or self.seen != set(self.headers) or set(self.selected) != {_BINARY, _PAM, _MANIFEST}:
            _fail('CPIO_INCOMPLETE')
        for path, (digest, data) in self.selected.items():
            if digest != self.headers[path]['sha256']:
                _fail('PAYLOAD_DIGEST')
            if path == _PAM and digest != PAM_SHA256:
                _fail('PAM')
            if path == _MANIFEST and data != self.manifest:
                _fail('MANIFEST_BYTES')


def _tool(argv, source_fd, *, payload, consume, deadline, clock):
    _check_time(deadline, clock)
    env = {key: os.environ.get(key, '/') for key in ('HOME', 'XDG_CONFIG_HOME', 'XDG_CACHE_HOME')}
    env.update(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HISTFILE='/dev/null')
    proc = subprocess.Popen(argv, stdin=source_fd if payload else subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd='/', env=env,
                            close_fds=True, pass_fds=() if payload else (source_fd,))
    stderr = 0
    try:
        with selectors.DefaultSelector() as selector:
            for pipe, label in ((proc.stdout, 'out'), (proc.stderr, 'err')):
                os.set_blocking(pipe.fileno(), False)
                selector.register(pipe, selectors.EVENT_READ, label)
            while selector.get_map():
                _check_time(deadline, clock)
                for key, unused in selector.select(min(.05, max(0, deadline-clock()))):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                    elif key.data == 'err':
                        stderr += len(block)
                        if stderr > _MAX_STDERR:
                            _fail('TOOL_STDERR_LIMIT')
                    else:
                        consume(block)
            _check_time(deadline, clock)
            code = proc.wait(timeout=max(0, deadline-clock()))
            _check_time(deadline, clock)
            if code != 0 or stderr:
                _fail('TOOL_EXIT')
    finally:
        proc.stdout.close()
        proc.stderr.close()
    if _children():
        _fail('TOOL_CHILDREN')


def _worker(rpm, manifest, receipt, *, deadline, request_sha256, _tools=_TOOLS, _clock=time.monotonic):
    try:
        paths = _paths((rpm, manifest, receipt))
        if _request(paths) != _digest(request_sha256):
            _fail('REQUEST')
        if type(_tools) is not tuple or len(_tools) != 2 or any(not Path(tool).is_absolute() for tool in _tools):
            _fail('TOOLS')
        _check_time(deadline, _clock)
        _preconditions()
        _subreaper()
        with ExitStack() as stack:
            sources = tuple(_generator._Source(path, limit, stack) for path, limit in
                            zip(paths, (_MAX_RPM, _MAX_SMALL, _MAX_SMALL)))
            if len({_generator._identity(os.fstat(source.fd)) for source in sources}) != 3:
                _fail('ALIASED_INPUT')
            rpm_read = sources[0].read()
            manifest_read = sources[1].read(retain=True)
            receipt_read = sources[2].read(retain=True)
            authority = _authority(manifest_read[2], receipt_read[2])
            header = bytearray()
            def append(block):
                if len(header)+len(block) > _MAX_HEADER:
                    _fail('HEADER_LIMIT')
                header.extend(block)
            argv = (_tools[0], '--rcfile', '/dev/null', '--macros', '/dev/null', '--noplugins',
                    '--nosignature', '--query', '--package', '--nomanifest', '--noglob',
                    '--queryformat', _FORMAT, '/proc/self/fd/'+str(sources[0].fd))
            _tool(argv, sources[0].fd, payload=False, consume=append, deadline=deadline, clock=_clock)
            headers = _header(bytes(header), authority, manifest_read[2])
            stream = _Cpio(headers, manifest_read[2])
            os.lseek(sources[0].fd, 0, os.SEEK_SET)
            _tool((_tools[1],), sources[0].fd, payload=True, consume=stream.feed, deadline=deadline, clock=_clock)
            stream.finish()
            for source in sources:
                source.check()
            _check_time(deadline, _clock)
            result = _canonical(dict(schema=1, result='verified', request_sha256=request_sha256,
                                     rpm_sha256=rpm_read[1], manifest_sha256=manifest_read[1],
                                     receipt_sha256=receipt_read[1]))
        if _children():
            _fail('CHILDREN')
        _check_time(deadline, _clock)
        return result
    except CheckError:
        raise
    except Exception:
        raise CheckError('CHECK_REFUSED') from None


def _validate(raw, request):
    if type(raw) is not bytes or len(raw) > 4096:
        _fail('VERDICT')
    value = _json(raw)
    if (type(value) is not dict or set(value) != {'schema', 'result', 'request_sha256', 'rpm_sha256', 'manifest_sha256', 'receipt_sha256'}
            or type(value['schema']) is not int or value['schema'] != 1 or value['result'] != 'verified'
            or value['request_sha256'] != request or _canonical(value) != raw):
        _fail('VERDICT')
    for key in ('request_sha256', 'rpm_sha256', 'manifest_sha256', 'receipt_sha256'):
        _digest(value[key])
    return raw


@contextmanager
def _cancellation():
    """Defer parent cancellation until existing owned work has settled.

    Never raise across Popen acquisition or change dispositions to SIG_IGN:
    caught handlers reset on child exec, leaving worker/native TERM effective.
    """
    requests = []
    signals = (signal.SIGTERM, signal.SIGHUP, signal.SIGINT)
    previous = {sig: signal.getsignal(sig) for sig in signals}
    def interrupted(signum, unused):
        if not requests:
            requests.append(signum)
    try:
        for sig in signals:
            signal.signal(sig, interrupted)
        yield requests
    finally:
        for sig in signals:
            signal.signal(sig, previous[sig])


def _emit(raw):
    sys.stdout.buffer.write(raw)
    sys.stdout.buffer.flush()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('rpm', 'manifest', 'receipt'):
        parser.add_argument('--'+name, required=True)
    parser.add_argument('--_worker', action='store_true', help=argparse.SUPPRESS)
    parser.add_argument('--_deadline', type=float, help=argparse.SUPPRESS)
    parser.add_argument('--_request', help=argparse.SUPPRESS)
    args = parser.parse_args()
    try:
        paths = _paths((args.rpm, args.manifest, args.receipt))
        request = _request(paths)
        _resources()
        if args._worker:
            raw = _worker(*paths, deadline=args._deadline, request_sha256=args._request)
        else:
            deadline = _ENTRY+60
            _check_time(deadline, time.monotonic)
            with _cancellation() as requests:
                with tempfile.TemporaryDirectory(prefix='qsh-consumer-rpm-') as home:
                    if requests:
                        _fail('CANCELLED')
                    owner = _Owner(_Limits(60, 4096))
                    argv = (sys.executable, '-B', str(Path(__file__).resolve()), '--rpm', paths[0],
                            '--manifest', paths[1], '--receipt', paths[2], '--_worker',
                            '--_deadline', str(deadline), '--_request', request)
                    if requests:
                        _fail('CANCELLED')
                    streams = owner._run(argv, home, deadline=deadline)
                    outcome = owner._last
                    if (type(streams) is not _Streams or type(streams.stdout) is not bytes
                            or type(streams.stderr) is not bytes or streams.stderr
                            or outcome is None or not outcome.settled or outcome.unreaped
                            or outcome.failure is not None or outcome.exit_code != 0):
                        _fail('OWNER')
                    raw = _validate(streams.stdout, request)
                _check_time(deadline, time.monotonic)
                if requests:
                    _fail('CANCELLED')
                _emit(raw)
                if requests:
                    _fail('CANCELLED')
                return 0
        _emit(raw)
        return 0
    except Exception:
        print('CONSUMER_RPM_REFUSED', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
