#!/usr/bin/env python3
"""Exercise explicit release binaries on an isolated controlling terminal.

Internal module for scripts/tests/run_client_artifact_smoke.py, whose Docker
owner establishes Linux containment. Import alone is not containment proof.
Package installation/release wiring are separate; no binary is found or rebuilt.
"""
import array
import base64
import ctypes
import errno
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import select
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time

sys.dont_write_bytecode = True
LIMIT = 65536


class SmokeError(Exception):
    pass


def isolated(home):
    env = os.environ.copy()
    env.update(HOME=str(home), XDG_CACHE_HOME=str(home / 'cache'),
               XDG_CONFIG_HOME=str(home / 'config'), HISTFILE='/dev/null',
               TERM='xterm-256color')
    for name in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'QSH_LOG', 'RUST_LOG'):
        env.pop(name, None)
    return env


class Child:
    """One exclusive direct-child waiter; loss never becomes signal authority."""
    def __init__(self, args, **kwargs):
        self.process = subprocess.Popen(args, **kwargs)
        self.status = None
        self.lost = False

    def poll(self):
        if self.status is not None:
            return self.status
        if self.lost:
            raise SmokeError('direct child wait authority was lost')
        try:
            pid, status = os.waitpid(self.process.pid, os.WNOHANG)
        except InterruptedError:
            return None
        except ChildProcessError:
            self.lost = True
            raise SmokeError('direct child wait authority was lost')
        if pid:
            self.status = (os.WEXITSTATUS(status) if os.WIFEXITED(status)
                           else -os.WTERMSIG(status))
            self.process.returncode = self.status
        return self.status

    def finish(self):
        if self.poll() is None:
            # This exact child is still reserved by our exclusive wait owner.
            os.kill(self.process.pid, signal.SIGCONT)
            os.kill(self.process.pid, signal.SIGKILL)
            while self.status is None:
                try:
                    _, status = os.waitpid(self.process.pid, 0)
                except InterruptedError:
                    continue
                except ChildProcessError:
                    self.lost = True
                    raise SmokeError('cleanup lost direct child wait authority')
                self.status = (os.WEXITSTATUS(status) if os.WIFEXITED(status)
                               else -os.WTERMSIG(status))
                self.process.returncode = self.status
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None:
                stream.close()


def open_self_pidfd():
    """Only the executing process opens its own identity; no peer-PID reopen."""
    libc = ctypes.CDLL(None, use_errno=True)
    if hasattr(libc, 'pidfd_open'):
        fd = libc.pidfd_open(os.getpid(), 0)
    else:
        if os.uname().machine not in ('x86_64', 'aarch64'):
            raise SmokeError('unsupported Linux pidfd syscall architecture')
        fd = libc.syscall(434, os.getpid(), 0)
    if fd < 0:
        raise SmokeError('self pidfd unavailable')
    return fd


def send_self_record(sock, nonce):
    fd = open_self_pidfd()
    try:
        record = (str(os.getpid())+' '+nonce+'\n').encode('ascii')
        sent = sock.sendmsg([record], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                       array.array('i', [fd]))])
        if sent != len(record):
            raise SmokeError('incomplete controlled leaf record')
    finally:
        os.close(fd)


class ExitObserver:
    """Consumes one transferred self-pidfd, including validation failure."""
    def __init__(self, fd, peer_pid):
        self.fd = fd
        self.exited = False
        try:
            if not fcntl.fcntl(fd, fcntl.F_GETFD) & fcntl.FD_CLOEXEC:
                raise SmokeError('transferred descriptor lacks close-on-exec')
            if os.readlink('/proc/self/fd/'+str(fd)) != 'anon_inode:[pidfd]':
                raise SmokeError('controlled leaf transferred a non-pidfd')
            with open('/proc/self/fdinfo/'+str(fd), 'rb') as info:
                data = info.read(4097)
            match = re.search(rb'^Pid:\s*(-?[0-9]+)$', data, re.M)
            if len(data) > 4096 or match is None:
                raise SmokeError('invalid transferred pidfd metadata')
            pid = int(match.group(1))
            if pid != peer_pid and not (pid < 0 and self.ready()):
                raise SmokeError('transferred pidfd does not match controlled peer')
        except BaseException:
            self.close()
            raise

    def ready(self):
        if self.fd is None:
            raise SmokeError('leaf observer was already closed')
        self.exited = self.exited or bool(select.select([self.fd], [], [], 0)[0])
        return self.exited

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)


def receive_leaf(sock, nonce, before_observer=None):
    # One atomic packet, bounded bytes/rights, every received fd owned immediately.
    data, ancillary, flags, _ = sock.recvmsg(
        128, socket.CMSG_SPACE(16*array.array('i').itemsize), socket.MSG_CMSG_CLOEXEC)
    rights = []
    invalid = False
    try:
        for level, kind, payload in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                ints = array.array('i')
                whole = len(payload) - len(payload) % ints.itemsize
                ints.frombytes(payload[:whole])
                rights.extend(ints)
                invalid |= whole != len(payload)
            else:
                invalid = True
        if invalid or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or len(rights) != 1:
            raise SmokeError('invalid or truncated leaf descriptor record')
        values = data.split()
        if len(values) != 2 or values[1] != nonce.encode('ascii'):
            raise SmokeError('controlled leaf identity mismatch')
        try:
            pid = int(values[0])
        except ValueError:
            raise SmokeError('invalid controlled leaf PID metadata')
        peer_pid, peer_uid, _ = struct.unpack('3i', sock.getsockopt(
            socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if pid != peer_pid or peer_uid != os.getuid():
            raise SmokeError('controlled leaf peer mismatch')
        if before_observer is not None:
            before_observer()
        # Constructor consumes even rejected descriptors; temporary list no
        # longer owns this one, so there is no second close on that error path.
        return ExitObserver(rights.pop(), peer_pid)
    finally:
        for fd in set(rights):
            os.close(fd)


def acknowledge_leaf(observer, sock):
    if observer.ready():
        raise SmokeError('controlled leaf exited before startup ACK')
    sock.sendall(b'A')


# The selected SHELL is this nonforking program, not a user's login shell.
# It has its own absolute deadline, including the pre-observer ACK wait.
LEAF = r'''#!{python}
import hashlib,importlib.util,os,select,socket,sys,time
end={deadline!r}
s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
s.settimeout(max(0.001,end-time.monotonic()))
try:
 s.connect({control!r})
 spec=importlib.util.spec_from_file_location('owned_smoke_leaf', {helper!r})
 helper=importlib.util.module_from_spec(spec)
 spec.loader.exec_module(helper)
 helper.send_self_record(s,{nonce!r})
 if s.recv(1)!=b'A':sys.exit(42)
 s.setblocking(False)
 data=bytearray()
 while time.monotonic()<end:
  ready,_,_=select.select([s,0],[],[],min(0.05,max(0,end-time.monotonic())))
  if s in ready:
   if not s.recv(1):sys.exit(42)
  if 0 in ready:
   chunk=os.read(0,4096)
   if not chunk:sys.exit(42)
   data.extend(chunk)
   if len(data)>4096:sys.exit(43)
   if b'\n' in data:
    challenge=bytes(data).split(b'\n',1)[0].rstrip(b'\r')
    print('digest:'+hashlib.sha256(challenge).hexdigest(),flush=True)
    sys.exit(37)
 sys.exit(42)
finally:
 s.close()
'''


def drain_exited_pty(fd, output):
    # Actual client exit fences future writes; drain all available bounded tail.
    while True:
        try:
            chunk = os.read(fd, 4096)
        except BlockingIOError:
            return
        except OSError as error:
            if error.errno == errno.EIO:
                return
            raise
        if not chunk:
            return
        if len(output) + len(chunk) > LIMIT:
            raise SmokeError('artifact smoke output exceeded its limit')
        output.extend(chunk)


def bounded_read(fd, output):
    try:
        chunk = os.read(fd, 4096)
    except BlockingIOError:
        return True
    except OSError as error:
        if error.errno != errno.EIO:
            raise
        return False
    if not chunk:
        return False
    if len(output) + len(chunk) > LIMIT:
        raise SmokeError('artifact smoke output exceeded its limit')
    output.extend(chunk)
    return True


def version_check(client, daemon, version):
    spec = importlib.util.spec_from_file_location(
        'release_output', Path(__file__).with_name('check-release-output.py'))
    output = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(output)
    output.check_binary(client, 'qsh', version)
    output.check_binary(daemon, 'qshd', version)


def smoke(client, daemon, version, timeout=20, _after_observer=None,
          _before_observer=None, _receipt=None):
    if not sys.platform.startswith('linux'):
        raise SmokeError('Darwin runtime custody is not qualified by this tranche')
    client, daemon = Path(client), Path(daemon)
    if not client.is_absolute() or not daemon.is_absolute():
        raise SmokeError('explicit absolute artifact paths are required')
    if not 0 < timeout <= 60:
        raise SmokeError('smoke deadline must be positive and at most 60 seconds')
    version_check(client, daemon, version)
    deadline = time.monotonic() + timeout
    children = []
    observer = None
    leaf = None
    master = slave = None
    control = None
    app = None
    server = None
    result = {} if _receipt is None else _receipt
    with tempfile.TemporaryDirectory(prefix='qsh-artifact-smoke-') as tmp:
        root = Path(tmp)
        client_home, daemon_home = root / 'client', root / 'daemon'
        client_home.mkdir(mode=0o700)
        daemon_home.mkdir(mode=0o700)
        # Unix paths remain below the portable sockaddr_un length limit.
        control = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        control.bind(str(root / 'control'))
        control.listen(1)
        control.setblocking(False)
        key = root / 'identity'
        try:
            keygen = Child(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(key)],
                           env=isolated(client_home), stdin=subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            children.append(keygen)
            key_output = bytearray()
            os.set_blocking(keygen.process.stdout.fileno(), False)
            while keygen.poll() is None:
                if time.monotonic() >= deadline:
                    raise SmokeError('fixture key creation timed out')
                if select.select([keygen.process.stdout], [], [], 0.05)[0]:
                    bounded_read(keygen.process.stdout.fileno(), key_output)
            if keygen.status != 0:
                raise SmokeError('fixture key creation failed')
            authorized = daemon_home / 'authorized_keys'
            authorized.write_bytes(key.with_suffix('.pub').read_bytes())
            authorized.chmod(0o600)
            nonce = os.urandom(16).hex()
            shell = root / 'fixture-shell'
            shell.write_text(LEAF.format(python=sys.executable, deadline=deadline,
                                        control=str(root / 'control'), nonce=nonce,
                                        helper=str(Path(__file__).resolve())))
            shell.chmod(0o700)
            udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            udp.bind(('127.0.0.1', 0))
            port = udp.getsockname()[1]
            udp.close()
            env = isolated(daemon_home)
            env['SHELL'] = str(shell)
            server = Child([str(daemon), 'serve', '--port', str(port),
                            '--authorized-keys', str(authorized), '--host-key',
                            str(daemon_home / 'host_key')], env=env,
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE)
            children.append(server)
            streams = {server.process.stdout.fileno(): bytearray(),
                       server.process.stderr.fileno(): bytearray()}
            for fd in streams:
                os.set_blocking(fd, False)
            fingerprint = None
            while fingerprint is None:
                if time.monotonic() >= deadline or server.poll() is not None:
                    raise SmokeError('artifact daemon did not publish post-bind readiness')
                ready, _, _ = select.select(list(streams), [], [], 0.05)
                for fd in ready:
                    if not bounded_read(fd, streams[fd]):
                        raise SmokeError('artifact daemon closed before readiness')
                stdout = streams[server.process.stdout.fileno()]
                public = re.search(rb'^server-pubkey: ([A-Za-z0-9+/=]+)\r?$', stdout, re.M)
                shown = re.search(rb'^host-key-fingerprint: (SHA256:[^\s]+)\r?$', stdout, re.M)
                if public and shown:
                    raw = base64.b64decode(public.group(1), validate=True)
                    # The owned daemon supplies two consistency-checked values.
                    if len(raw) != 32:
                        raise SmokeError('artifact daemon published malformed key')
                    expected_fingerprint = b'SHA256:' + base64.b64encode(hashlib.sha256(raw).digest()).rstrip(b'=')
                    if shown.group(1) != expected_fingerprint:
                        raise SmokeError('artifact daemon key/fingerprint mismatch')
                    fingerprint = shown.group(1)
            master, slave = os.openpty()
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 24, 80, 0, 0))
            os.set_blocking(master, False)
            def terminal():
                os.setsid()
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            app = Child([str(client), '-i', str(key), '-p', str(port),
                         '127.0.0.1,nossh'], env=isolated(client_home),
                        stdin=slave, stdout=slave, stderr=slave, preexec_fn=terminal)
            children.append(app)
            os.close(slave)
            slave = None
            streams[master] = bytearray()
            challenge = os.urandom(24).hex().encode('ascii')
            expected = b'digest:' + hashlib.sha256(challenge).hexdigest().encode('ascii')
            pending = bytearray()
            trusted = sent = False
            while True:
                if time.monotonic() >= deadline:
                    raise SmokeError('artifact connection smoke timed out')
                readers = list(streams) + ([control] if leaf is None else [])
                if leaf is not None and observer is None:
                    readers.append(leaf)
                ready, writable, _ = select.select(readers, [master] if pending else [], [], 0.05)
                for fd in ready:
                    if fd is control:
                        leaf, _ = control.accept()
                        leaf.setblocking(False)
                    elif fd is leaf:
                        observer = receive_leaf(leaf, nonce, _before_observer)
                        if _after_observer is not None:
                            _after_observer()
                        acknowledge_leaf(observer, leaf)
                    else:
                        if not bounded_read(fd, streams[fd]):
                            # Keep final output for the digest, stop polling EOF.
                            if fd == master:
                                break
                            raise SmokeError('artifact daemon closed during connection')
                output = bytes(streams[master])
                if not trusted and b'Key fingerprint' in output and fingerprint in output:
                    pending.extend(b'yes\n')
                    trusted = True
                if observer is not None and not sent:
                    pending.extend(challenge + b'\n')
                    sent = True
                if writable:
                    try:
                        n = os.write(master, pending)
                        del pending[:n]
                    except BlockingIOError:
                        pass
                status = app.poll()
                if status is not None:
                    drain_exited_pty(master, streams[master])
                    output = bytes(streams[master])
                    if status != 37 or expected not in output or not trusted or not sent:
                        raise SmokeError('artifact failed authenticated response/remote exit37: status={} trusted={} sent={} terminal={!r}'.format(status, trusted, sent, output[-4096:]))
                    if observer is None or not observer.ready():
                        raise SmokeError('client exit lacked actual leaf exit observation')
                    result.update(remote_status=status, leaf_observed=True)
                    break
        finally:
            # Leaf owns no descendants and treats private EOF/deadline as exit.
            # Its actual exit must precede daemon termination, not just a signal.
            if app is not None:
                app.finish()
                if observer is None:
                    # An admitted Open can produce a leaf after client exit.
                    # Only the enclosing owned PID namespace can settle that
                    # unregistered obligation; this is never helper success.
                    result['containment_required'] = True
            if leaf is not None:
                leaf.close()
            if observer is not None:
                while not observer.ready():
                    select.select([observer.fd], [], [], 0.05)
                result['leaf_observed'] = True
                observer.close()
            for child in reversed(children):
                child.finish()
            result.update(client_joined=app is not None and app.status is not None,
                          daemon_joined=server is not None and server.status is not None)
            for fd in (slave, master):
                if fd is not None:
                    os.close(fd)
            control.close()
    return result


if __name__ == '__main__':
    # This module is an internal implementation of the contained runtime suite.
    # Import is not containment proof. Only the owned runner establishes it.
    sys.exit('use scripts/tests/run_client_artifact_smoke.py; standalone runtime is refused')
