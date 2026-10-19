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
        return subprocess.run(
            ['bash', str(SCRIPT), '--target', 'x86_64-unknown-linux-musl',
             '--cache', str(self.cache), '--archive', str(self.archive), *extra],
            env=env, text=True, capture_output=True, timeout=20)

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
	ar rcs $(DESTDIR)INSTALL_PREFIX/lib/libcrypto.a version.o
	ar rcs $(DESTDIR)INSTALL_PREFIX/lib/libssl.a version.o
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
        return subprocess.run(
            ['bash', str(self.scripts / 'build-openssl.sh'),
             '--target', 'x86_64-unknown-linux-gnu', '--cache', str(self.cache),
             '--archive', str(self.archive), '--cc', 'cc', *extra],
            env=env, text=True, capture_output=True, timeout=20)

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
        import shutil
        archiver = self.tools / 'owned-ar'
        actual = shutil.which('ar')
        archiver.write_text('#!/bin/sh\nexec "' + actual + '" "$@"\n')
        archiver.chmod(0o755)
        first = self.run_build('--ar', str(archiver))
        self.assertEqual(first.returncode, 0, first.stderr)
        archiver.write_text(archiver.read_text() + '# changed toolchain wrapper\n')
        second = self.run_build('--ar', str(archiver))
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertNotEqual(first.stdout, second.stdout)
        self.assertEqual(len(self.count.read_text().splitlines()), 2)

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

        def reap_descendants(force):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if force:
                    children = Path('/proc/self/task/' + str(os.getpid()) + '/children')
                    for pid in children.read_text().split():
                        # Only our adopted children, not yet waited/reaped by
                        # anyone else, can appear here. Never signal after wait.
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
            self.assertTrue(reap_descendants(False), "native descendants survived cancellation")
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
            self.assertTrue(reap_descendants(True), 'owned fixture descendants were not reaped')


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


if __name__ == '__main__':
    unittest.main()
