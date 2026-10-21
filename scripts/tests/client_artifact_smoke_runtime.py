"""Runtime controls for the explicit shipped-client smoke helper."""
import importlib.util
import os
from pathlib import Path
import tempfile
import array
import select
import socket
import subprocess
import time
import unittest

SOURCE = Path(__file__).resolve().parents[1] / 'client-artifact-smoke.py'


def helper_module():
    spec = importlib.util.spec_from_file_location('artifact_smoke', SOURCE)
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    return helper


class ArtifactSmoke(unittest.TestCase):
    def test_exact_release_pair_authenticates_and_returns_remote_status(self):
        helper = helper_module()
        result = helper.smoke(os.environ['QSH_SMOKE_CLIENT'],
                              os.environ['QSH_SMOKE_DAEMON'], '0.5.0', 20)
        self.assertEqual(result['remote_status'], 37)
        self.assertTrue(result['leaf_observed'])
        self.assertTrue(result['client_joined'] and result['daemon_joined'])


    def test_registered_held_leaf_exits_before_failure_cleanup_returns(self):
        helper = helper_module()
        receipt = {}
        def cancel():
            raise helper.SmokeError('owned cancellation after observer, before ACK')
        with self.assertRaisesRegex(helper.SmokeError, 'owned cancellation'):
            helper.smoke(os.environ['QSH_SMOKE_CLIENT'],
                         os.environ['QSH_SMOKE_DAEMON'], '0.5.0', 20,
                         _after_observer=cancel, _receipt=receipt)
        self.assertTrue(receipt['leaf_observed'])
        self.assertTrue(receipt['client_joined'] and receipt['daemon_joined'])

    def test_version_correct_broken_client_is_not_runtime_success(self):
        helper = helper_module()
        with tempfile.TemporaryDirectory(prefix='qsh-broken-artifact-') as tmp:
            client = Path(tmp) / 'qsh'
            client.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo "qsh 0.5.0"; exit 0; fi\nexit 23\n')
            client.chmod(0o700)
            receipt = {}
            with self.assertRaisesRegex(helper.SmokeError, 'authenticated response'):
                helper.smoke(str(client), os.environ['QSH_SMOKE_DAEMON'],
                             '0.5.0', 20, _receipt=receipt)
            self.assertTrue(receipt['client_joined'] and receipt['daemon_joined'])
            self.assertNotIn('leaf_observed', receipt)

    def test_echo_only_exit37_is_not_authenticated_remote_success(self):
        helper = helper_module()
        with tempfile.TemporaryDirectory(prefix='qsh-echo-artifact-') as tmp:
            client = Path(tmp) / 'qsh'
            client.write_text('#!/bin/sh\nif [ "$1" = --version ]; then echo "qsh 0.5.0"; exit 0; fi\nprintf "%s\\n" "$@"\nexit 37\n')
            client.chmod(0o700)
            receipt = {}
            with self.assertRaisesRegex(helper.SmokeError, 'authenticated response'):
                helper.smoke(str(client), os.environ['QSH_SMOKE_DAEMON'],
                             '0.5.0', 20, _receipt=receipt)
            self.assertTrue(receipt['client_joined'] and receipt['daemon_joined'])
            self.assertTrue(receipt['containment_required'])

    def test_malformed_executable_cannot_pass_version_guard(self):
        helper = helper_module()
        with tempfile.TemporaryDirectory(prefix='qsh-malformed-artifact-') as tmp:
            client = Path(tmp) / 'qsh'
            client.write_bytes(b'not an executable image\n')
            client.chmod(0o700)
            receipt = {}
            with self.assertRaises(OSError):
                helper.smoke(str(client), os.environ['QSH_SMOKE_DAEMON'],
                             '0.5.0', 20, _receipt=receipt)
            self.assertEqual(receipt, {}, 'rejection precedes daemon/runtime startup')

    def test_cancel_before_descriptor_adoption_requires_namespace_fence(self):
        helper = helper_module()
        receipt = {}
        def cancel():
            raise helper.SmokeError('owned cancellation before descriptor adoption')
        with self.assertRaisesRegex(helper.SmokeError, 'before descriptor adoption'):
            helper.smoke(os.environ['QSH_SMOKE_CLIENT'],
                         os.environ['QSH_SMOKE_DAEMON'], '0.5.0', 20,
                         _before_observer=cancel, _receipt=receipt)
        self.assertTrue(receipt['client_joined'] and receipt['daemon_joined'])
        self.assertTrue(receipt['containment_required'])
        self.assertNotIn('leaf_observed', receipt)

    def test_wrong_selected_version_fails_before_runtime(self):
        helper = helper_module()
        with self.assertRaisesRegex(ValueError, 'version'):
            helper.smoke(os.environ['QSH_SMOKE_CLIENT'],
                         os.environ['QSH_SMOKE_DAEMON'], '9.9.9', 20)

    def test_client_output_flood_is_bounded_failure(self):
        helper = helper_module()
        with tempfile.TemporaryDirectory(prefix='qsh-noisy-artifact-') as tmp:
            client = Path(tmp) / 'qsh'
            client.write_text('#!'+os.sys.executable+'\nimport sys\nif "--version" in sys.argv: print("qsh 0.5.0")\nelse:\n while True: print("x"*4096,flush=True)\n')
            client.chmod(0o700)
            receipt = {}
            with self.assertRaisesRegex(helper.SmokeError, 'output exceeded'):
                helper.smoke(str(client), os.environ['QSH_SMOKE_DAEMON'],
                             '0.5.0', 20, _receipt=receipt)
            self.assertTrue(receipt['client_joined'] and receipt['daemon_joined'])
            self.assertTrue(receipt['containment_required'])

    def test_standalone_helper_refuses_before_version_or_runtime_effects(self):
        entries = [(SOURCE, True), (Path(__file__).resolve(), False)]
        for entry, arguments in entries:
            with self.subTest(entry=entry.name), tempfile.TemporaryDirectory(prefix='qsh-entry-refusal-') as tmp:
                marker = Path(tmp) / 'called'
                fake = Path(tmp) / 'qsh'
                fake.write_text('#!'+os.sys.executable+'\nfrom pathlib import Path\nPath('+repr(str(marker))+').touch()\nprint("qsh 0.5.0")\n')
                fake.chmod(0o700)
                env = os.environ.copy()
                env.update(QSH_SMOKE_CLIENT=str(fake), QSH_SMOKE_DAEMON=str(fake))
                args = [os.sys.executable, str(entry)]
                if arguments:
                    args += ['--client', str(fake), '--daemon', str(fake), '--version', '0.5.0']
                child = helper_module().Child(args, env=env,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                try:
                    end = time.monotonic() + 3
                    while child.poll() is None and time.monotonic() < end:
                        select.select([], [], [], 0.01)
                    status = child.poll()
                finally:
                    child.finish()
                self.assertIsNotNone(status)
                self.assertNotEqual(status, 0)
                self.assertFalse(marker.exists(), 'standalone entry must refuse before version probes')

    def test_transferred_self_pidfd_survives_sender_exit_and_actual_reap(self):
        helper = helper_module()
        with tempfile.TemporaryDirectory(prefix='qsh-self-pidfd-') as tmp:
            address = str(Path(tmp) / 'control')
            with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
                listener.bind(address)
                listener.listen(1)
                listener.settimeout(3)
                code = ('import importlib.util,socket,sys;'
                        's=importlib.util.spec_from_file_location("h",sys.argv[1]);'
                        'h=importlib.util.module_from_spec(s);s.loader.exec_module(h);'
                        'c=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET);'
                        'c.connect(sys.argv[2]);h.send_self_record(c,"owned-nonce");c.close()')
                child = helper.Child([os.sys.executable, '-c', code, str(SOURCE), address])
                peer = None
                observer = None
                try:
                    peer, _ = listener.accept()
                    end = time.monotonic() + 3
                    while child.poll() is None and time.monotonic() < end:
                        select.select([], [], [], 0.01)
                    self.assertEqual(child.poll(), 0, 'sender actually reaped before record receive')
                    observer = helper.receive_leaf(peer, 'owned-nonce')
                    self.assertTrue(observer.ready(), 'received exact descriptor observes old exited sender')
                    with self.assertRaisesRegex(helper.SmokeError, 'exited before startup ACK'):
                        helper.acknowledge_leaf(observer, peer)
                finally:
                    if observer is not None:
                        observer.close()
                    if peer is not None:
                        peer.close()
                    child.finish()

    def test_rejected_ancillary_records_close_all_received_rights(self):
        helper = helper_module()
        cases = [('missing-fd', 0, 0, False), ('wrong-pid', 1, 0, False), ('wrong-type', 1, 0, False), ('extra', 2, 0, False),
                 ('truncated-rights', 24, 0, False), ('truncated-data', 1, 256, False),
                 ('unknown-ancillary', 1, 0, True), ('bad-nonce', 1, 0, False)]
        for name, count, padding, credentials in cases:
            with self.subTest(case=name):
                a, b = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
                sentinel = os.open('/dev/null', os.O_RDONLY)
                try:
                    if credentials:
                        b.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                    pid = os.getpid()+1 if name == 'wrong-pid' else os.getpid()
                    data = (str(pid)+' owned-nonce\n').encode('ascii') + b'x'*padding
                    a.sendmsg([data], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                       array.array('i', [sentinel]*count))])
                    before = len(os.listdir('/proc/self/fd'))
                    with self.assertRaises(helper.SmokeError):
                        helper.receive_leaf(b, 'different' if name == 'bad-nonce' else 'owned-nonce')
                    self.assertEqual(len(os.listdir('/proc/self/fd')), before)
                    os.fstat(sentinel)  # received duplicate closure must not close sender's fd
                finally:
                    os.close(sentinel)
                    a.close()
                    b.close()

    def test_actual_exited_pty_has_unread_tail_beyond_first_chunk(self):
        helper = helper_module()
        marker = b'OWNED_TRAILING_MARKER'
        master, slave = os.openpty()
        os.set_blocking(master, False)
        child = helper.Child([os.sys.executable, '-c',
            'import os;data=b"x"*8192+b"OWNED_TRAILING_MARKER";'
            '\nwhile data:\n n=os.write(1,data);data=data[n:]'],
            stdin=subprocess.DEVNULL, stdout=slave, stderr=slave)
        os.close(slave)
        captured = bytearray()
        try:
            end = time.monotonic() + 3
            # One real bounded read frees writer room but deliberately leaves
            # the tail. Child's actual exit, never a sleep, is the next fence.
            self.assertTrue(select.select([master], [], [], 3)[0])
            captured.extend(os.read(master, 4096))
            while child.poll() is None and time.monotonic() < end:
                select.select([], [], [], 0.01)
            self.assertEqual(child.poll(), 0, 'actual writer exit while output remains unread')
            self.assertNotIn(marker, captured)
            helper.drain_exited_pty(master, captured)
            self.assertIn(marker, captured)
        finally:
            child.finish()
            os.close(master)

    def test_exited_pty_tail_cannot_exceed_accumulated_output_cap(self):
        helper = helper_module()
        master, slave = os.openpty()
        os.set_blocking(master, False)
        child = helper.Child([os.sys.executable, '-c', 'import os;os.write(1,b"tail-bytes")'],
                             stdout=slave, stderr=slave, stdin=subprocess.DEVNULL)
        os.close(slave)
        try:
            end = time.monotonic() + 3
            while child.poll() is None and time.monotonic() < end:
                select.select([], [], [], 0.01)
            self.assertEqual(child.poll(), 0, 'actual exited writer before cap assertion')
            capture = bytearray(b'x'*(helper.LIMIT-4))
            with self.assertRaisesRegex(helper.SmokeError, 'output exceeded'):
                helper.drain_exited_pty(master, capture)
            self.assertEqual(len(capture), helper.LIMIT-4)
        finally:
            child.finish()
            os.close(master)

def held_unregistered():
    # Imported only by the owned runner's in-container bootstrap. No flag here
    # purports to authenticate namespace ownership.
    def held():
        print('ARTIFACT_UNREGISTERED_LEAF_HELD', flush=True)
        while True:
            time.sleep(0.05)
    helper_module().smoke(os.environ['QSH_SMOKE_CLIENT'],
                          os.environ['QSH_SMOKE_DAEMON'], '0.5.0', 20,
                          _before_observer=held)
    raise AssertionError('held fixture unexpectedly completed')


if __name__ == '__main__':
    os.sys.exit('use the owned runner; standalone runtime controls are refused')
