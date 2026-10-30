"""Owned output fixtures exercise release validation without compiling products."""
import importlib.util
import json
import hashlib
import io
import os
import shutil
import signal
import threading
import time
import subprocess
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('release_output', ROOT / 'scripts/check-release-output.py')
output = importlib.util.module_from_spec(spec)
spec.loader.exec_module(output)


class ReleaseOutputTests(unittest.TestCase):
    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix='qsh-release-output-')
        self.addCleanup(self.fixture.cleanup)
        self.root = Path(self.fixture.name)

    def executable(self, name, body):
        path = self.root / name
        path.write_text('#!' + sys.executable + '\n' + body)
        path.chmod(0o700)
        return path

    def test_binary_uses_pty_and_isolated_state(self):
        program = self.executable('fixture',
            'import os\n'
            'assert all(os.isatty(fd) for fd in (0, 1, 2))\n'
            'assert os.environ["HOME"] != ' + repr(str(Path.home())) + '\n'
            'assert os.environ["XDG_CONFIG_HOME"].startswith(os.environ["HOME"])\n'
            'assert os.environ["XDG_CACHE_HOME"].startswith(os.environ["HOME"])\n'
            'assert os.environ["HISTFILE"] == "/dev/null"\n'
            'assert "SSH_AUTH_SOCK" not in os.environ\n'
            'print("qsh 0.5.0")\n')
        output.check_binary(program, 'qsh', '0.5.0')

    def test_wrong_identity_version_exit_or_first_line_refused(self):
        for text, status in [('qshd 0.5.0 (build fixture)', 0), ('qsh 0.4.0', 0),
                             ('notice\\nqsh 0.5.0', 0), ('qsh 0.5.0 suffix', 0),
                             ('qsh 0.5.0', 1)]:
            with self.subTest(text=text, status=status):
                program = self.executable('fixture', 'print(' + repr(text.replace('\\n', '\n'))
                                          + ')\nraise SystemExit(' + str(status) + ')\n')
                with self.assertRaises(ValueError):
                    output.check_binary(program, 'qsh', '0.5.0')

    def test_daemon_requires_build_stamp_and_exact_selected_version(self):
        self.assertEqual(output.parse_version(b'qshd 0.5.0 (build fixture)\r\nLicense\r\n',
                                               'qshd', '0.5.0'), '0.5.0')
        for text in [b'qshd 0.5.0\n', b'qshd 0.5.0 (build )\n',
                     b'qshd 0.4.0 (build fixture)\n', b'qshd 0.5.0 (build x) suffix\n']:
            with self.subTest(text=text), self.assertRaises(ValueError):
                output.parse_version(text, 'qshd', '0.5.0')

    def test_standalone_version_parser_preserves_raw_semver(self):
        self.assertEqual(output.parse_version(b'qshd 0.6.0-rc.1+build.2 (build fixture)\n',
                                               'qshd'), '0.6.0-rc.1+build.2')
        for text in [b'qshd 0.6 (build x)\n', b'', b'\xff', b'qsh 0.5.0\n' + b'x' * 8192]:
            with self.subTest(text=text[:30]), self.assertRaises(ValueError):
                output.parse_version(text, 'qshd')

    def test_timeout_and_overflow_reap_exact_child(self):
        for body, timeout, reason in [
                ('import time\ntime.sleep(60)\n', 0.3, 'timed out'),
                ('import os\nos.write(1, b"x" * 20000)\n', 10, 'exceeds limit')]:
            program = self.executable('fixture', body)
            created = []
            real_popen = subprocess.Popen

            def spawn(*args, **kwargs):
                child = real_popen(*args, **kwargs)
                created.append(child)
                return child

            # Observe the real owner, without a marker/startup scheduling race.
            with self.subTest(body=body), mock.patch.object(output.subprocess, 'Popen', spawn):
                with self.assertRaisesRegex(ValueError, reason):
                    output.check_binary(program, 'qsh', '0.5.0', timeout=timeout)
            self.assertEqual(len(created), 1)
            self.assertIsNotNone(created[0].returncode)
            # ECHILD proves an actual wait, not merely a termination signal.
            with self.assertRaises(ChildProcessError):
                os.waitpid(created[0].pid, os.WNOHANG)

    def test_actual_sigint_retains_child_until_reaped(self):
        record = self.root / 'interrupt-pid'
        program = self.executable('fixture',
            'import os, time\nfrom pathlib import Path\nPath(' + repr(str(record))
            + ').with_suffix(".pending").write_text(str(os.getpid()))\nPath(' + repr(str(record))
            + ').with_suffix(".pending").replace(' + repr(str(record)) + ')\ntime.sleep(60)\n')
        cancel = threading.Event()
        delivered = threading.Event()

        def interrupt_owner():
            deadline = time.monotonic() + 5
            while not cancel.is_set() and time.monotonic() < deadline:
                if record.exists():
                    delivered.set()
                    os.kill(os.getpid(), signal.SIGINT)  # This owned test process only.
                    return
                cancel.wait(0.01)

        previous = signal.signal(signal.SIGINT, signal.default_int_handler)
        sender = threading.Thread(target=interrupt_owner)
        sender.start()
        try:
            with self.assertRaises(KeyboardInterrupt):
                output.check_binary(program, 'qsh', '0.5.0')
        finally:
            cancel.set()
            sender.join()
            signal.signal(signal.SIGINT, previous)
        self.assertTrue(delivered.is_set())
        with self.assertRaises(ChildProcessError):
            os.waitpid(int(record.read_text()), os.WNOHANG)

    def archive(self, suffix='', swapped=False, link=False, traversal=False, extra=None, root_directory=False, directory_alias=False):
        directory = self.root / 'products'
        directory.mkdir(exist_ok=True)
        for program in ['qsh', 'qshd']:
            first = 'qsh 0.5.0' if program == 'qsh' else 'qshd 0.5.0 (build fixture)'
            source = self.executable(program, 'print(' + repr(first) + ')\n')
            (directory / program).write_bytes(source.read_bytes())
            (directory / program).chmod(0o700)
        stage = 'qsh-0.5.0-fixture-target'
        archive = self.root / (stage + suffix + '.tar.gz')
        with tarfile.open(str(archive), 'w:gz') as tar:
            if root_directory:
                info = tarfile.TarInfo(stage + '/')
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            if traversal:
                info = tarfile.TarInfo(stage + '/../outside')
                tar.addfile(info, io.BytesIO(b''))
            for program in ['qsh', 'qshd']:
                if swapped and program == 'qshd':
                    data = b'wrong payload'
                    info = tarfile.TarInfo(stage + '/' + program)
                    info.size = len(data)
                    tar.addfile(info, io.BytesIO(data))
                elif link and program == 'qshd':
                    info = tarfile.TarInfo(stage + '/' + program)
                    info.type = tarfile.SYMTYPE
                    info.linkname = 'qsh'
                    tar.addfile(info)
                else:
                    tar.add(str(directory / program), arcname=stage + '/' + program)
            if directory_alias:
                info = tarfile.TarInfo(stage + '/alias')
                info.type = tarfile.SYMTYPE
                info.linkname = '.'
                tar.addfile(info)
                extra = '/alias/qsh'
            if extra is not None:
                data = b'overwrites the canonical program when extracted'
                info = tarfile.TarInfo(stage + extra)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
        return archive, directory

    def test_archive_carries_exact_probed_pair(self):
        archive, inputs = self.archive(root_directory=True)
        output.check_archive(archive, inputs, '0.5.0', 'fixture-target')
        # Also qualify the production tar invocation, including its directory
        # header spelling, rather than only Python's synthetic tar writer.
        stage = self.root / 'qsh-0.5.0-fixture-target'
        shutil.copytree(str(inputs), str(stage))
        subprocess.run(['tar', 'czf', str(archive), stage.name], cwd=str(self.root),
                       capture_output=True, timeout=10, check=True)
        output.check_archive(archive, stage, '0.5.0', 'fixture-target')

    def test_archive_wrong_name_payload_or_link_refused(self):
        for kwargs in [{'suffix': '-wrong'}, {'swapped': True}, {'link': True}, {'traversal': True}]:
            with self.subTest(kwargs=kwargs):
                archive, inputs = self.archive(**kwargs)
                with self.assertRaises(ValueError):
                    output.check_archive(archive, inputs, '0.5.0', 'fixture-target')

    def test_archive_aliases_cannot_overwrite_probed_member(self):
        for alias in ['/./qsh', '//qsh', '/qsh']:
            with self.subTest(alias=alias):
                archive, inputs = self.archive(extra=alias)
                with self.assertRaises(ValueError):
                    output.check_archive(archive, inputs, '0.5.0', 'fixture-target')

    def test_archive_directory_symlink_cannot_alias_probed_program(self):
        archive, inputs = self.archive(directory_alias=True)
        with self.assertRaises(ValueError):
            output.check_archive(archive, inputs, '0.5.0', 'fixture-target')

    @unittest.skipUnless(shutil.which('dpkg-deb'), 'native Debian fixture tool unavailable')
    def test_actual_debian_metadata_and_extracted_client_version(self):
        payload = self.root / 'payload'
        (payload / 'DEBIAN').mkdir(parents=True)
        (payload / 'usr/bin').mkdir(parents=True)
        path = self.root / 'qsh_0.5.0-1_amd64.deb'
        for metadata_version, binary_version, accepted in [
                ('0.5.0-1', '0.5.0', True),
                ('0.4.0-1', '0.5.0', False),
                ('0.5.0-1', '0.4.0', False)]:
            (payload / 'DEBIAN/control').write_text(
                'Package: qsh\nVersion: ' + metadata_version + '\nArchitecture: amd64\n'
                'Maintainer: Fixture <fixture@example.invalid>\nDescription: Owned release fixture\n')
            binary = payload / 'usr/bin/qsh'
            binary.write_text('#!' + sys.executable + '\nprint("qsh ' + binary_version + '")\n')
            binary.chmod(0o755)
            subprocess.run(['dpkg-deb', '--build', '--root-owner-group', str(payload), str(path)],
                           capture_output=True, timeout=10, check=True)
            with self.subTest(metadata=metadata_version, binary=binary_version):
                if accepted:
                    output.check_package(path, 'deb', 'qsh', '0.5.0', 'amd64', probe=True)
                else:
                    with self.assertRaises(ValueError):
                        output.check_package(path, 'deb', 'qsh', '0.5.0', 'amd64', probe=True)

    def test_installed_text_and_fields_cli_contract(self):
        script = str(ROOT / 'scripts/check-release-output.py')
        for expected, accepted in [('0.5.0', True), ('0.4.0', False), (None, True)]:
            command = [sys.executable, script, 'text', '--program', 'qshd']
            if expected is not None:
                command += ['--version', expected]
            result = subprocess.run(command, input=b'qshd 0.5.0 (build fixture)\n',
                                    capture_output=True, timeout=5)
            with self.subTest(expected=expected):
                self.assertEqual(result.returncode == 0, accepted)
                self.assertEqual(result.stdout, b'0.5.0\n' if accepted else b'')
        result = subprocess.run(
            [sys.executable, script, 'fields', '--format', 'deb', '--program', 'qshd',
             '--version', '0.5.0', '--arch', 'arm64', 'qshd_0.5.0-1_arm64.deb'],
            input=b'qshd\n0.5.0-1\narm64\n', capture_output=True, timeout=5)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b'', b''))

    def test_pinned_debian_format_is_not_naive_hyphen_split(self):
        for raw, expected in [('0.5.0', '0.5.0-1'), ('0.6.0-rc.1', '0.6.0~rc.1-1'),
                              ('0.6.0-rc', '0.6.0-rc-1'), ('0.6.0-1', '0.6.0-1-1'),
                              ('0.6.0+build.1', '0.6.0+build.1-1')]:
            with self.subTest(raw=raw):
                self.assertEqual(output.debian_version(raw), expected)

    def test_package_fields_and_filename_must_both_match(self):
        for fmt, fields, filename, arch in [
                ('deb', ['qsh', '0.5.0-1', 'amd64'], 'qsh_0.5.0-1_amd64.deb', 'amd64'),
                ('rpm', ['qshd', '0.5.0', '1', 'aarch64'], 'qshd-0.5.0-1.aarch64.rpm', 'aarch64')]:
            program = fields[0]
            output.check_fields(fmt, fields, filename, program, '0.5.0', arch)
            for index in range(len(fields)):
                changed = fields[:]
                changed[index] += '-wrong'
                with self.subTest(fmt=fmt, field=index), self.assertRaises(ValueError):
                    output.check_fields(fmt, changed, filename, program, '0.5.0', arch)
            with self.subTest(fmt=fmt, filename=True), self.assertRaises(ValueError):
                output.check_fields(fmt, fields, 'wrong-' + filename, program, '0.5.0', arch)


class DarwinMetadataTests(unittest.TestCase):
    # Synthetic Apple-tool text, not an observed runner/artifact qualification.
    MODERN=b"/Users/PRIVATE/build/qsh:\nLoad command 0\n cmd LC_RPATH\n path /Users/PRIVATE/secret\nLoad command 1\n cmd LC_BUILD_VERSION\n cmdsize 32\n platform 1\n minos 11.0\n sdk 15.4\n ntools 1\n tool 3\n version 1115.7.3\n"
    LEGACY=b"/private/path:\nLoad command 0\n cmd LC_VERSION_MIN_MACOSX\n cmdsize 16\n version 10.12\n sdk n/a\n"

    def setUp(self):
        self.helper=ReleaseOutputTests();self.helper.setUp();self.addCleanup(self.helper.doCleanups)
        self.root=self.helper.root

    def test_modern_legacy_fields_and_private_decoys(self):
        modern=output.parse_darwin_load_commands(self.MODERN)
        self.assertEqual(modern,dict(kind='LC_BUILD_VERSION',platform='macos',minos='11.0',sdk='15.4'))
        self.assertEqual(output.parse_darwin_load_commands(self.LEGACY),dict(kind='LC_VERSION_MIN_MACOSX',platform='macos',minos='10.12',sdk=None))
        self.assertNotIn('PRIVATE',json.dumps(modern))
        for bad in (b'',self.MODERN+self.LEGACY,self.MODERN.replace(b'platform 1',b'platform 2'),self.MODERN.replace(b'minos 11.0',b'minos /Users/PRIVATE'),self.MODERN.replace(b'sdk 15.4',b'sdk 15.4\n sdk 15.4'),b'x'*65537):
            with self.subTest(bad=bad[:20]),self.assertRaises(ValueError):output.parse_darwin_load_commands(bad)

    def fixture(self,target='aarch64-apple-darwin'):
        archive,inputs=self.helper.archive()
        renamed=self.root/('qsh-0.5.0-'+target+'.tar.gz')
        with tarfile.open(archive,'r:gz') as old,tarfile.open(renamed,'w:gz') as new:
            for member in old:
                member.name=member.name.replace('fixture-target',target)
                new.addfile(member,old.extractfile(member) if member.isfile() else None)
        prefix=self.root/'native';prefix.mkdir()
        (prefix/'version-probe').write_bytes(b'PUBLIC SYNTHETIC NATIVE PROBE')
        self.sdk=self.root/'SDK';self.sdk.mkdir()
        self.native=dict(identity=dict(source=dict(version='3.5.9'),target=target,compiler=dict(sha256='b'*64,version='Apple clang version 17.0.0\nInstalledDir: /Users/PRIVATE/clang',flags=['-arch','arm64' if target.startswith('aarch64') else 'x86_64','-isysroot',str(self.sdk)],macros='#define __APPLE__ 1\n#define __arm64__ 1\n#define __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ 150400\n#define PRIVATE "/Users/PRIVATE/secret"\n',path='/Users/PRIVATE/clang')),artifacts={'version-probe':hashlib.sha256((prefix/'version-probe').read_bytes()).hexdigest()})
        (prefix/'manifest.json').write_text(json.dumps(self.native))
        return renamed,inputs,prefix

    def command(self,argv):
        values={('/usr/bin/uname','-m'):b'arm64\n',('/usr/bin/sw_vers','-productVersion'):b'15.4\n',('/usr/bin/sw_vers','-buildVersion'):b'24E248\n',('/usr/bin/xcodebuild','-version'):b'Xcode 16.4\nBuild version 16F6\n',('/usr/bin/xcrun','--show-sdk-path'):(str(self.sdk)+'\n').encode(),('/usr/bin/xcrun','--show-sdk-version'):b'15.4\n',('rustc','--version','--verbose'):b'rustc 1.99.1\nbinary: rustc\ncommit-hash: '+b'c'*40+b'\nhost: aarch64-apple-darwin\nrelease: 1.99.1\n',('/usr/bin/xcrun','--find','otool'):b'/usr/bin/otool\n',('/usr/bin/xcrun','--find','lipo'):b'/usr/bin/lipo\n'}
        if argv[:2]==['/usr/bin/otool','-l']:return self.MODERN
        if argv[:2]==['/usr/bin/lipo','-archs']:return b'arm64\n'
        if argv[:2]==['rustc','--print=deployment-target']:return b'MACOSX_DEPLOYMENT_TARGET=11.0\n'
        return values[tuple(argv)]

    def context(self):
        return mock.patch.dict(os.environ,dict(GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',ImageVersion='20261025.1'),clear=True)

    def test_archive_metadata_has_exact_five_bound_records_and_no_private_paths(self):
        archive,inputs,prefix=self.fixture();destination=self.root/'evidence.json'
        with self.context(),mock.patch.object(output.sys,'platform','darwin'),mock.patch.object(output,'metadata_command',side_effect=self.command):
            output.check_archive(archive,inputs,'0.5.0','aarch64-apple-darwin',darwin_metadata=destination,native_prefix=prefix)
        raw=destination.read_text();value=json.loads(raw)
        self.assertEqual(len(value['binaries']),5)
        self.assertEqual(value['native']['flags'],['-arch','arm64','-isysroot','<SDK>'])
        self.assertEqual(value['rust']['reported_deployment_target'],'11.0')
        self.assertLess(len(raw.encode()),32768)
        for forbidden in ('PRIVATE','/Users/',str(self.root),'InstalledDir'):self.assertNotIn(forbidden,raw)
        self.assertEqual(value['binaries'][0]['sha256'],value['binaries'][1]['sha256'])
        self.assertEqual(value['binaries'][2]['sha256'],value['binaries'][3]['sha256'])

    def test_metadata_cannot_rebind_the_already_version_probed_identity(self):
        archive,inputs,prefix=self.fixture();destination=self.root/'evidence.json'
        native_binary=output._darwin_binary;native_digest=output.digest;changed=False
        def binary(*args,**kwargs):
            nonlocal changed
            value=native_binary(*args,**kwargs)
            if value['role'] in ('staged','extracted'):
                changed=True;value['sha256']='f'*64
            return value
        def digest(stream):
            # Simulate a coherent later archive/staging generation. It must not
            # replace the version-probed baseline, even if later hashes agree.
            if changed and isinstance(stream,tarfile.ExFileObject):return bytes.fromhex('f'*64)
            return native_digest(stream)
        with self.context(),mock.patch.object(output.sys,'platform','darwin'),mock.patch.object(output,'metadata_command',side_effect=self.command),mock.patch.object(output,'_darwin_binary',side_effect=binary),mock.patch.object(output,'digest',side_effect=digest),self.assertRaises(ValueError):
            output.check_archive(archive,inputs,'0.5.0','aarch64-apple-darwin',darwin_metadata=destination,native_prefix=prefix)
        self.assertFalse(destination.exists())

    def test_metadata_failure_never_creates_completed_evidence(self):
        archive,inputs,prefix=self.fixture();destination=self.root/'evidence.json'
        for failure in ('probe','arch','sdk','flag','command'):
            (prefix/'manifest.json').write_text(json.dumps(self.native))
            def command(argv):
                if failure=='command':raise ValueError('fixed tool refusal')
                if failure=='arch' and argv[:2]==['/usr/bin/lipo','-archs']:return b'x86_64\n'
                return self.command(argv)
            if failure=='probe':
                changed=json.loads(json.dumps(self.native));changed['artifacts']['version-probe']='0'*64;(prefix/'manifest.json').write_text(json.dumps(changed))
            if failure=='sdk':
                changed=json.loads(json.dumps(self.native));changed['identity']['compiler']['flags'][-1]=str(self.root/'other');(prefix/'manifest.json').write_text(json.dumps(changed))
            if failure=='flag':
                changed=json.loads(json.dumps(self.native));changed['identity']['compiler']['flags'].append('-I/Users/PRIVATE/include');(prefix/'manifest.json').write_text(json.dumps(changed))
            with self.subTest(failure=failure),self.context(),mock.patch.object(output.sys,'platform','darwin'),mock.patch.object(output,'metadata_command',side_effect=command),self.assertRaises(ValueError):
                output.check_archive(archive,inputs,'0.5.0','aarch64-apple-darwin',darwin_metadata=destination,native_prefix=prefix)
            self.assertFalse(destination.exists())

    def test_metadata_tool_timeout_overflow_and_exact_direct_child_reap(self):
        for body,timeout in [('import time;time.sleep(30)',.1),('import os;os.write(1,b"x"*70000)',10),('import sys;sys.stderr.write("PRIVATE")',10)]:
            program=self.helper.executable('tool',body+'\n');children=[];native=subprocess.Popen
            def spawn(*args,**kwargs):
                child=native(*args,**kwargs);children.append(child);return child
            with self.subTest(body=body),mock.patch.object(output.subprocess,'Popen',side_effect=spawn),self.assertRaises(ValueError):output.metadata_command([str(program)],timeout=timeout)
            self.assertEqual(len(children),1);self.assertIsNotNone(children[0].returncode)
            with self.assertRaises(ChildProcessError):os.waitpid(children[0].pid,os.WNOHANG)

    def test_metadata_direct_tool_interrupt_still_reaps_owned_child(self):
        record=self.root/'metadata-tool-pid'
        program=self.helper.executable('metadata-tool',
            'import os,time\nfrom pathlib import Path\np=Path('+repr(str(record))+')\np.with_suffix(".pending").write_text(str(os.getpid()))\np.with_suffix(".pending").replace(p)\ntime.sleep(30)\n')
        cancelled=threading.Event();delivered=threading.Event()
        def interrupt():
            deadline=time.monotonic()+5
            while not cancelled.is_set() and time.monotonic()<deadline:
                if record.exists():delivered.set();os.kill(os.getpid(),signal.SIGINT);return
                cancelled.wait(.01)
        previous=signal.signal(signal.SIGINT,signal.default_int_handler);sender=threading.Thread(target=interrupt);sender.start()
        try:
            with self.assertRaises(KeyboardInterrupt):output.metadata_command([str(program)])
        finally:cancelled.set();sender.join();signal.signal(signal.SIGINT,previous)
        self.assertTrue(delivered.is_set())
        with self.assertRaises(ChildProcessError):os.waitpid(int(record.read_text()),os.WNOHANG)

    def test_metadata_argument_pair_existing_output_and_changed_binary_refuse(self):
        archive,inputs,prefix=self.fixture();destination=self.root/'evidence.json'
        for args in (dict(darwin_metadata=destination),dict(native_prefix=prefix)):
            with self.subTest(args=sorted(args)),self.assertRaises(ValueError):output.check_archive(archive,inputs,'0.5.0','aarch64-apple-darwin',**args)
        destination.write_text('PUBLIC EXISTING EVIDENCE')
        with self.assertRaises(ValueError):output.check_archive(archive,inputs,'0.5.0','aarch64-apple-darwin',darwin_metadata=destination,native_prefix=prefix)
        self.assertEqual(destination.read_text(),'PUBLIC EXISTING EVIDENCE');destination.unlink()
        def changed(argv):
            result=self.command(argv)
            if argv[:2]==['/usr/bin/otool','-l']:
                path=Path(argv[-1]);path.write_bytes(path.read_bytes()+b'\n# public mutation\n')
            return result
        with self.context(),mock.patch.object(output.sys,'platform','darwin'),mock.patch.object(output,'metadata_command',side_effect=changed),self.assertRaises(ValueError):
            output.check_archive(archive,inputs,'0.5.0','aarch64-apple-darwin',darwin_metadata=destination,native_prefix=prefix)
        self.assertFalse(destination.exists())

    def test_collector_preserves_exact_release_set_and_excludes_ci_only_evidence(self):
        workflow=(ROOT/'.github/workflows/release.yml').read_text()
        command=next(line.strip() for line in workflow.splitlines() if line.strip().startswith('find artifacts -type f'))
        artifacts=self.root/'artifacts';artifacts.mkdir();(self.root/'dist').mkdir()
        expected={'qsh-0.5.0-'+target+'.tar.gz' for target in ('x86_64-unknown-linux-musl','aarch64-unknown-linux-musl','aarch64-apple-darwin','x86_64-apple-darwin')}
        for program in ('qsh','qshd'):
            expected.update(program+'_0.5.0-1_'+arch+'.deb' for arch in ('amd64','arm64'))
            expected.update(program+'-0.5.0-1.'+arch+'.rpm' for arch in ('x86_64','aarch64'))
        self.assertEqual(len(expected),12)
        for name in expected:
            path=artifacts/'producer'/name;path.parent.mkdir(exist_ok=True);path.write_bytes(b'public')
        private=artifacts/'darwin-producer-evidence';private.mkdir();(private/'arm.json').write_text('{}');(private/'intel.json').write_text('{}')
        subprocess.run(['sh','-c',command],cwd=self.root,check=True,capture_output=True,timeout=5)
        self.assertEqual({p.name for p in (self.root/'dist').iterdir()},expected)
        self.assertEqual(workflow.count('name: darwin-producer-evidence'),1)
        self.assertIn('retention-days: 7',workflow)


if __name__ == '__main__':
    unittest.main()
