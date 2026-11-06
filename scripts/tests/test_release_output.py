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
import tomllib
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
            for document in output.DOCUMENTS:
                data = (ROOT / 'docs/licenses' / output.NOTICES[document]).read_bytes() if document in output.NOTICES else b'inert document'
                (directory / document).write_bytes(data)
                info = tarfile.TarInfo(stage + '/' + document); info.size = len(data); info.mode = 0o644
                tar.addfile(info, io.BytesIO(data))
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
        (payload / 'DEBIAN').chmod(0o755)
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

    def rust_tools(self, *, explicit=False):
        """Harmless fixtures model rustup HOME lookup without personal tools."""
        home=self.root/'original-home';home.mkdir()
        cargo=self.root/'selected-cargo' if explicit else home/'.cargo'
        rustup=self.root/'selected-rustup' if explicit else home/'.rustup'
        cargo.mkdir();rustup.mkdir()
        compiler=rustup/'toolchains/1.99.1/bin/rustc';compiler.parent.mkdir(parents=True)
        record=self.root/'compiler-calls.jsonl'
        compiler.write_text('#!'+sys.executable+'\nimport json,os,sys\n'
            'assert os.environ["RUSTUP_AUTO_INSTALL"]=="0"\n'
            'assert os.environ["HOME"]!='+repr(str(home))+'\n'
            'assert "RUSTUP_HOME" not in os.environ and "CARGO_HOME" not in os.environ\n'
            'with open('+repr(str(record))+',"a") as f:f.write(json.dumps(sys.argv)+"\\n")\n'
            'if sys.argv[1:]==["--version","--verbose"]:print("rustc 1.99.1\\nrelease: 1.99.1\\ncommit-hash: '+ 'c'*40+'\\nhost: aarch64-apple-darwin")\n'
            'elif sys.argv[1:]==["--print=deployment-target","--target","aarch64-apple-darwin"]:print("MACOSX_DEPLOYMENT_TARGET=11.0")\n'
            'else:raise SystemExit(4)\n')
        compiler.chmod(0o700)
        resolver_record=self.root/'resolver-calls'
        resolver=self.helper.executable('rustup','import os,sys\nfrom pathlib import Path\n'
            'assert os.environ["RUSTUP_AUTO_INSTALL"]=="0"\n'
            'assert sys.argv[1:]==["which","--toolchain","1.99.1","rustc"]\n'
            'assert os.environ["CARGO_HOME"]=='+repr(str(cargo))+'\n'
            'with open('+repr(str(resolver_record))+',"a") as f:f.write("resolved\\n")\n'
            'path=Path(os.environ.get("RUSTUP_HOME",str(Path.home()/".rustup")))/"toolchains/1.99.1/bin/rustc"\n'
            'if not path.is_file():raise SystemExit(2)\nprint(path)\n')
        proxy=self.helper.executable('rustc','import os,sys\nfrom pathlib import Path\n'
            'path=Path(os.environ.get("RUSTUP_HOME",str(Path.home()/".rustup")))/"toolchains/1.99.1/bin/rustc"\n'
            'if not path.is_file():raise SystemExit(2)\n'
            'os.execv(str(path),[str(path),*sys.argv[1:]])\n')
        env=dict(HOME=str(home),PATH=str(self.root),RUSTUP_TOOLCHAIN='1.99.1',RUSTUP_AUTO_INSTALL='0',GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1')
        if explicit:
            env.update(RUSTUP_HOME=str(rustup),CARGO_HOME=str(cargo))
            decoy=home/'.rustup/toolchains/1.99.1/bin';decoy.mkdir(parents=True)
            (decoy/'rustc').write_text('DECOY MUST NOT BE SELECTED')
        return env,proxy,resolver,compiler,record,resolver_record

    def test_rustup_proxy_home_isolation_uses_one_resolved_compiler(self):
        self.fixture();env,proxy,resolver,compiler,record,resolver_record=self.rust_tools()
        with mock.patch.dict(os.environ,env,clear=True):
            with self.assertRaises(ValueError):output.metadata_command([str(proxy),'--version','--verbose'])
            original=output.metadata_command
            def command(argv,**kwargs):
                if argv[0]=='rustc':return original([str(proxy),*argv[1:]],**kwargs)
                if argv[0] in (str(resolver),str(compiler)):return original(argv,**kwargs)
                return self.command(argv,**kwargs)
            with mock.patch.object(output.sys,'platform','darwin'),mock.patch.object(output,'metadata_command',side_effect=command):
                value,tools,probe=output._darwin_context(self.root/'native','aarch64-apple-darwin')
        self.assertEqual(resolver_record.read_text(),'resolved\n')
        calls=[json.loads(line) for line in record.read_text().splitlines()]
        self.assertEqual([row[0] for row in calls],[str(compiler)]*2)
        self.assertEqual(value['rust']['reported_deployment_target'],'11.0')
        self.assertNotIn(str(self.root),json.dumps(value))

    def test_rustc_explicit_homes_framing_missing_and_mutation_refuse(self):
        self.fixture();env,proxy,resolver,compiler,record,resolver_record=self.rust_tools(explicit=True)
        with mock.patch.dict(os.environ,env,clear=True):
            self.assertEqual(output._metadata_rustc(),compiler)
            alias=self.root/'rustup-hardlink';os.link(resolver,alias)
            for raw in (str(alias).encode()+b'\n',b'relative\n',b'/absent/PRIVATE\n',str(resolver).encode()+b'\n',str(compiler).encode()+b'\nextra\n',b'\xff'):
                with self.subTest(raw=raw):
                    with mock.patch.object(output,'metadata_command',return_value=raw),self.assertRaises(ValueError) as error:output._metadata_rustc()
                    self.assertNotIn('PRIVATE',str(error.exception));self.assertNotIn(str(self.root),str(error.exception))
            compiler.chmod(0o600)
            with self.assertRaises(ValueError):output._metadata_rustc()
            compiler.chmod(0o700)
            original=output.metadata_command
            def command(argv,**kwargs):
                if argv[0]==str(resolver):return original(argv,**kwargs)
                if argv[0]==str(compiler):
                    raw=original(argv,**kwargs)
                    if '--version' in argv:
                        with compiler.open('a') as stream:stream.write('# mutation\n')
                    return raw
                return self.command(argv,**kwargs)
            destination=self.root/'evidence.json'
            with mock.patch.object(output.sys,'platform','darwin'),mock.patch.object(output,'metadata_command',side_effect=command),self.assertRaisesRegex(ValueError,'^Darwin metadata rust-toolchain: invalid output$'):output.check_archive(self.root/'qsh-0.5.0-aarch64-apple-darwin.tar.gz',self.root/'inputs','0.5.0','aarch64-apple-darwin',darwin_metadata=destination,native_prefix=self.root/'native')
            self.assertFalse(destination.exists())
            compiler.unlink()
            with self.assertRaises(ValueError):output._metadata_rustc()
        for key in ('HOME','RUSTUP_HOME','CARGO_HOME','RUSTUP_TOOLCHAIN'):
            bad=dict(env);bad[key]='relative' if key!='RUSTUP_TOOLCHAIN' else 'PRIVATE/invalid'
            with self.subTest(key=key),mock.patch.dict(os.environ,bad,clear=True),mock.patch.object(output.subprocess,'Popen') as spawn,self.assertRaises(ValueError):output._metadata_rustc()
            spawn.assert_not_called()

    def test_completed_metadata_refusals_keep_only_status_and_stderr_presence(self):
        # Synthetic canaries exercise hostile output, not real credentials.
        stdout=b'/synthetic/private/stdout-canary\n'
        stderr=b'/synthetic/private/stderr-canary\nTOKEN=synthetic-only\n'
        for status,err,want in ((7,b'','status=7 stderr_present=false'),
                                (7,stderr,'status=7 stderr_present=true'),
                                (0,stderr,'status=0 stderr_present=true')):
            program=self.helper.executable('private-tool-canary',
                'import os\nos.write(1,'+repr(stdout)+')\nos.write(2,'+repr(err)+')\nraise SystemExit('+str(status)+')\n')
            children=[];native=subprocess.Popen
            def spawn(*args,**kwargs):
                child=native(*args,**kwargs);children.append(child);return child
            public_out=io.StringIO();public_err=io.StringIO()
            with self.subTest(status=status,stderr_present=bool(err)):
                with mock.patch.object(output.subprocess,'Popen',side_effect=spawn), \
                        mock.patch.object(output.sys,'stdout',public_out), \
                        mock.patch.object(output.sys,'stderr',public_err), \
                        self.assertRaises(ValueError) as error:
                    output.metadata_command([str(program)],category='rust-toolchain')
                self.assertEqual(str(error.exception),'Darwin metadata rust-toolchain: tool refused '+want)
                self.assertEqual(public_out.getvalue(),'');self.assertEqual(public_err.getvalue(),'')
                for canary in (stdout.decode(),stderr.decode(),str(program)):
                    self.assertNotIn(canary,str(error.exception)+repr(error.exception))
                self.assertEqual(len(children),1)
                self.assertIsNotNone(children[0].returncode)
                with self.assertRaises(ChildProcessError):os.waitpid(children[0].pid,os.WNOHANG)
        program=self.helper.executable('success-tool','import os\nos.write(1,'+repr(stdout)+')\n')
        self.assertEqual(output.metadata_command([str(program)]),stdout)

    def test_metadata_refusal_formatter_bounds_status_and_closes_inputs(self):
        class Hostile:
            def __str__(self):raise AssertionError('must not stringify untrusted status')
        for status,want in ((-2147483648,'-2147483648'),(2147483647,'2147483647'),
                            (-9,'-9'),(0,'0'),(True,'unknown'),(False,'unknown'),
                            (-2147483649,'unknown'),(2147483648,'unknown'),
                            (None,'unknown'),('7','unknown'),(Hostile(),'unknown')):
            with self.subTest(want=want):
                error=output._MetadataRefusal('rust-toolchain',status,True)
                self.assertIsInstance(error,ValueError)
                self.assertEqual(str(error),'Darwin metadata rust-toolchain: tool refused status='+want+' stderr_present=true')
        for category,present in (('private-category',True),('rust-toolchain',1),
                                 ('rust-toolchain','private-stderr'),(Hostile(),True)):
            with self.assertRaisesRegex(ValueError,'^invalid Darwin metadata refusal fields$'):
                output._MetadataRefusal(category,7,present)

    def test_metadata_query_category_diagnostics_are_private_and_causal(self):
        for body,category,reason,timeout in (
            ('import time;time.sleep(30)','xcode-version','timed out',.1),
            ('import os;os.write(1,b"x"*70000)','binary-load-commands','output limit',10),
            ('import sys;sys.stderr.write("PRIVATE");raise SystemExit(2)','rust-version','tool refused status=2 stderr_present=true',10),
            ('import os;os.write(1,b"\\xff")','sdk-path','invalid output',10)):
            program=self.helper.executable('PRIVATE-tool',body+'\n')
            with self.subTest(category=category),self.assertRaises(ValueError) as error:
                if reason=='invalid output':output._metadata_text([str(program)],category=category)
                else:output.metadata_command([str(program)],timeout=timeout,category=category)
            self.assertEqual(str(error.exception),'Darwin metadata '+category+': '+reason)
        binary=self.helper.executable('binary-fixture','pass\n')
        with mock.patch.object(output,'_metadata_text',return_value='arm64'),mock.patch.object(output,'metadata_command',return_value=b'\xffPRIVATE'),self.assertRaisesRegex(ValueError,'^Darwin metadata binary-load-commands: invalid output$'):
            output._darwin_binary(binary,'staged','qsh','aarch64-apple-darwin',{'lipo':'unused','otool':'unused'})
        with self.assertRaisesRegex(ValueError,'^Darwin metadata lipo-path: tool unavailable$'):output.metadata_command([str(self.root/'PRIVATE-missing')],category='lipo-path')
        for kwargs in (dict(category='PRIVATE'),dict(category='sdk-path',toolchain_homes={}),dict(category='rust-toolchain',toolchain_homes={'PRIVATE':'value'})):
            with mock.patch.object(output.subprocess,'Popen') as spawn,self.assertRaises(ValueError) as error:output.metadata_command(['PRIVATE'],**kwargs)
            spawn.assert_not_called();self.assertNotIn('PRIVATE',str(error.exception))

    def fixture(self,target='aarch64-apple-darwin'):
        self.categories=[]
        archive,inputs=self.helper.archive()
        renamed=self.root/('qsh-0.5.0-'+target+'.tar.gz')
        with tarfile.open(archive,'r:gz') as old,tarfile.open(renamed,'w:gz') as new:
            for member in old:
                member.name=member.name.replace('fixture-target',target)
                new.addfile(member,old.extractfile(member) if member.isfile() else None)
        prefix=self.root/'native';prefix.mkdir()
        (prefix/'version-probe').write_bytes(b'PUBLIC SYNTHETIC NATIVE PROBE')
        self.sdk=self.root/'SDK';self.sdk.mkdir()
        self.rustup=self.helper.executable('rustup','raise SystemExit(9)\n')
        self.rustc=self.helper.executable('rustc','raise SystemExit(9)\n')
        self.native=dict(identity=dict(source=dict(version='3.5.9'),target=target,compiler=dict(sha256='b'*64,version='Apple clang version 17.0.0\nInstalledDir: /Users/PRIVATE/clang',flags=['-arch','arm64' if target.startswith('aarch64') else 'x86_64','-isysroot',str(self.sdk)],macros='#define __APPLE__ 1\n#define __arm64__ 1\n#define __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ 150400\n#define PRIVATE "/Users/PRIVATE/secret"\n',path='/Users/PRIVATE/clang')),artifacts={'version-probe':hashlib.sha256((prefix/'version-probe').read_bytes()).hexdigest()})
        (prefix/'manifest.json').write_text(json.dumps(self.native))
        return renamed,inputs,prefix

    def command(self,argv,**kwargs):
        self.categories.append(kwargs.get('category'))
        if argv[0]==str(self.rustup):return (str(self.rustc)+'\n').encode()
        values={('/usr/bin/uname','-m'):b'arm64\n',('/usr/bin/sw_vers','-productVersion'):b'15.4\n',('/usr/bin/sw_vers','-buildVersion'):b'24E248\n',('/usr/bin/xcodebuild','-version'):b'Xcode 16.4\nBuild version 16F6\n',('/usr/bin/xcrun','--show-sdk-path'):(str(self.sdk)+'\n').encode(),('/usr/bin/xcrun','--show-sdk-version'):b'15.4\n',(str(self.rustc),'--version','--verbose'):b'rustc 1.99.1\nbinary: rustc\ncommit-hash: '+b'c'*40+b'\nhost: aarch64-apple-darwin\nrelease: 1.99.1\n',('/usr/bin/xcrun','--find','otool'):b'/usr/bin/otool\n',('/usr/bin/xcrun','--find','lipo'):b'/usr/bin/lipo\n'}
        if argv[:2]==['/usr/bin/otool','-l']:return self.MODERN
        if argv[:2]==['/usr/bin/lipo','-archs']:return b'arm64\n'
        if argv[:2]==[str(self.rustc),'--print=deployment-target']:return b'MACOSX_DEPLOYMENT_TARGET=11.0\n'
        return values[tuple(argv)]

    def context(self):
        return mock.patch.dict(os.environ,dict(GITHUB_SHA='a'*40,GITHUB_RUN_ID='123',GITHUB_RUN_ATTEMPT='1',ImageVersion='20261025.1',HOME=str(self.root),PATH=str(self.root),RUSTUP_TOOLCHAIN='1.99.1'),clear=True)

    def test_archive_metadata_has_exact_five_bound_records_and_no_private_paths(self):
        archive,inputs,prefix=self.fixture();destination=self.root/'evidence.json'
        with self.context(),mock.patch.object(output.sys,'platform','darwin'),mock.patch.object(output,'metadata_command',side_effect=self.command):
            output.check_archive(archive,inputs,'0.5.0','aarch64-apple-darwin',darwin_metadata=destination,native_prefix=prefix)
        raw=destination.read_text();value=json.loads(raw)
        self.assertEqual(len(value['binaries']),5)
        self.assertEqual(set(self.categories),output.METADATA_CATEGORIES-{'static-tool'})
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
            def command(argv,**kwargs):
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
        def changed(argv,**kwargs):
            result=self.command(argv)
            if argv[:2]==['/usr/bin/otool','-l']:
                path=Path(argv[-1]);path.write_bytes(path.read_bytes()+b'\n# public mutation\n')
            return result
        with self.context(),mock.patch.object(output.sys,'platform','darwin'),mock.patch.object(output,'metadata_command',side_effect=changed),self.assertRaises(ValueError):
            output.check_archive(archive,inputs,'0.5.0','aarch64-apple-darwin',darwin_metadata=destination,native_prefix=prefix)
        self.assertFalse(destination.exists())

    def test_collector_preserves_exact_release_set_and_excludes_ci_only_evidence(self):
        workflow=(ROOT/'.github/workflows/release.yml').read_text()
        step=workflow.split('      - name: Collect and checksum\n',1)[1]
        before,body=step.split('        run: |\n',1)
        self.assertIn('RELEASE_VERSION: ${{ needs.server-packages.outputs.version }}',before)
        lines=[]
        for line in body.splitlines():
            if line and not line.startswith('          '):break
            lines.append(line[10:])
        command='\n'.join(lines)
        products={
            'linux-x86_64-unknown-linux-musl':('qsh-0.5.0-x86_64-unknown-linux-musl.tar.gz','qsh_0.5.0-1_amd64.deb','qsh-0.5.0-1.x86_64.rpm'),
            'linux-aarch64-unknown-linux-musl':('qsh-0.5.0-aarch64-unknown-linux-musl.tar.gz','qsh_0.5.0-1_arm64.deb','qsh-0.5.0-1.aarch64.rpm'),
            'macos-aarch64-apple-darwin':('qsh-0.5.0-aarch64-apple-darwin.tar.gz',),
            'macos-x86_64-apple-darwin':('qsh-0.5.0-x86_64-apple-darwin.tar.gz',),
            'server-packages':('qshd_0.5.0-1_amd64.deb','qshd_0.5.0-1_arm64.deb','qshd-0.5.0-1.x86_64.rpm','qshd-0.5.0-1.aarch64.rpm')}
        artifacts=self.root/'artifacts';artifacts.mkdir();expected={}
        for producer,names in products.items():
            directory=artifacts/producer;directory.mkdir()
            for name in names:
                data=('PUBLIC SYNTHETIC '+producer+'/'+name+'\n').encode()
                (directory/name).write_bytes(data);expected[name]=data
        self.assertEqual(len(expected),12);self.assertFalse((self.root/'dist').exists())
        for target in ('aarch64-apple-darwin','x86_64-apple-darwin'):
            private=artifacts/('darwin-producer-evidence-'+target);private.mkdir()
            (private/(target+'.json')).write_text('{}')
        scripts=self.root/'scripts';scripts.mkdir()
        for name in ('assemble-release-assets.py','check-release-version.py','check-release-output.py'):
            shutil.copyfile(ROOT/'scripts'/name,scripts/name)
        env=os.environ|dict(RELEASE_VERSION='0.5.0',HOME=str(self.root/'home'),
            XDG_CONFIG_HOME=str(self.root/'config'),XDG_CACHE_HOME=str(self.root/'cache'),HISTFILE='/dev/null')
        subprocess.run(['bash','-e','-c',command],cwd=self.root,env=env,check=True,capture_output=True,timeout=5)
        dist=self.root/'dist'
        self.assertEqual({p.name for p in dist.iterdir()},set(expected)|{'SHA256SUMS'})
        for name,data in expected.items():self.assertEqual((dist/name).read_bytes(),data)
        manifest=''.join(hashlib.sha256(expected[name]).hexdigest()+'  '+name+'\n' for name in sorted(expected))
        self.assertEqual((dist/'SHA256SUMS').read_text(),manifest)
        self.assertEqual(workflow.count('name: darwin-producer-evidence-${{ matrix.target }}'),1)
        upload=workflow.split('          name: darwin-producer-evidence-${{ matrix.target }}\n',1)[1]
        upload_lines=[]
        for line in upload.splitlines():
            if line and not line.startswith('          '):break
            upload_lines.append(line.strip())
        self.assertIn('retention-days: 7',upload_lines)
        self.assertIn('path: ${{ runner.temp }}/darwin-producer-evidence/*.json',upload_lines)


CLIENT_NOTICES = {'LICENSE-AWS-LC-RS.txt': 'aws-lc-rs.txt', 'LICENSE-AWS-LC.txt': 'aws-lc.txt'}


def notice_checker():
    spec = importlib.util.spec_from_file_location('release_notice_output', ROOT / 'scripts/check-release-output.py')
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


class ReleaseNoticeTests(unittest.TestCase):
    def test_archive_notice_validation_has_no_new_repository_resource_dependency(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, inputs = self.archive(Path(directory))
            value = notice_checker()
            with mock.patch.object(value, 'check_binary'), mock.patch.object(Path, 'read_bytes',
                    side_effect=AssertionError('isolated checker has no repository notice files')):
                value.check_archive(archive, inputs, '0.5.0', 'fixture-target')

    @unittest.skipUnless(shutil.which('cargo-deb') and shutil.which('dpkg-deb'),
                         'native Debian packaging fixture tools unavailable')
    def test_generated_client_deb_contains_exact_maintained_notices(self):
        # Use the actual client metadata with an inert file, never a Rust build
        # or executable. The small wrapper has no dependencies or build script.
        with tempfile.TemporaryDirectory(prefix='qsh-notice-package-') as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            (root / 'src/main.rs').write_text('fn main() {}\n')
            binary = root / 'inert-client'
            binary.write_bytes(b'controlled non-executable client package fixture\0')
            manifest = (ROOT / 'cli/Cargo.toml').read_text()
            section = manifest.split('[package.metadata.deb]', 1)[1].split('[package.metadata.deb.variants.qshd]', 1)[0]
            section = section.replace('"target/release/qsh"', json.dumps(str(binary)))
            metadata = tomllib.loads(manifest)['package']['metadata']['deb']
            for source in [asset[0] for asset in metadata['assets']] + [metadata['license-file'][0]]:
                if source.startswith('../'):
                    section = section.replace(json.dumps(source), json.dumps(str((ROOT / 'cli' / source).resolve())))
            (root / 'Cargo.toml').write_text('[package]\nname="qsh"\nversion="0.5.0"\nedition="2021"\nlicense="AGPL-3.0-only"\n[package.metadata.deb]\n' + section)
            package = root / 'qsh_0.5.0-1_fixture.deb'
            result = subprocess.run(['cargo', 'deb', '--manifest-path', str(root / 'Cargo.toml'),
                                     '--no-build', '--no-strip', '--no-dbgsym', '--offline',
                                     '--output', str(package)], cwd=root, capture_output=True, timeout=30)
            self.assertEqual(result.returncode, 0, result.stderr.decode()[-1500:])
            header = subprocess.run(['dpkg-deb', '-f', str(package), 'Package', 'Version', 'Architecture'],
                                    capture_output=True, check=True, timeout=10).stdout.decode()
            self.assertIn('Package: qsh\n', header)
            self.assertIn('Version: 0.5.0-1\n', header)
            self.assertRegex(header, r'Architecture: (?:amd64|arm64)\n')
            payload = subprocess.run(['dpkg-deb', '--fsys-tarfile', str(package)], capture_output=True,
                                     check=True, timeout=10).stdout
            self.assertLess(len(payload), 4 * 1024**2)
            with tarfile.open(fileobj=io.BytesIO(payload), mode='r:') as data:
                for filename, source in CLIENT_NOTICES.items():
                    members = [m for m in data.getmembers() if m.name.removeprefix('./') == 'usr/share/doc/qsh/' + filename]
                    self.assertEqual(len(members), 1)
                    self.assertEqual((members[0].mode, members[0].uid, members[0].gid), (0o644, 0, 0))
                    self.assertEqual(data.extractfile(members[0]).read(), (ROOT / 'docs/licenses' / source).read_bytes())

    def test_pinned_archive_notice_digests_match_maintained_files(self):
        value = notice_checker()
        self.assertEqual(set(value.NOTICE_SHA256), set(value.NOTICES))
        for filename, source in value.NOTICES.items():
            self.assertEqual(value.NOTICE_SHA256[filename], hashlib.sha256((ROOT / 'docs/licenses' / source).read_bytes()).hexdigest())

    def test_both_notices_are_client_only_deb_and_rpm_assets(self):
        package = tomllib.loads((ROOT / 'cli/Cargo.toml').read_text())['package']['metadata']
        for filename, source in CLIENT_NOTICES.items():
            self.assertIn(['../docs/licenses/' + source, 'usr/share/doc/qsh/' + filename, '644'], package['deb']['assets'])
            self.assertIn({'source': '../docs/licenses/' + source, 'dest': '/usr/share/doc/qsh/' + filename,
                           'mode': '644', 'doc': True}, package['generate-rpm']['assets'])
            for fmt in ('deb', 'generate-rpm'):
                self.assertNotIn(source, str(package[fmt]['variants']['qshd']['assets']))

    def archive(self, root, *, omit=None, alter=None, extra=None):
        stage = 'qsh-0.5.0-fixture-target'
        inputs = root / 'inputs'; inputs.mkdir()
        entries = {'qsh': b'inert client', 'qshd': b'inert server',
                   'README.md': b'inert readme', 'LICENSE': b'inert license', 'CHANGELOG.md': b'inert changes'}
        for filename, source in dict({'LICENSE-OPENSSL.txt': 'openssl.txt'}, **CLIENT_NOTICES).items():
            entries[filename] = (ROOT / 'docs/licenses' / source).read_bytes()
        if alter is not None: entries[alter] += b'altered notice'
        if extra is not None: entries[extra] = b'unexpected bytes'
        archive = root / (stage + '.tar.gz')
        with tarfile.open(archive, 'w:gz', format=tarfile.USTAR_FORMAT) as out:
            directory = tarfile.TarInfo(stage); directory.type = tarfile.DIRTYPE; out.addfile(directory)
            for name, raw in entries.items():
                (inputs / name).write_bytes(raw)
                if name == omit: continue
                info = tarfile.TarInfo(stage + '/' + name); info.size = len(raw)
                info.mode = 0o755 if name in ('qsh', 'qshd') else 0o644
                out.addfile(info, io.BytesIO(raw))
        return archive, inputs

    def test_current_notices_in_archive_are_exact_source_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, inputs = self.archive(Path(directory))
            value = notice_checker()
            with mock.patch.object(value, 'check_binary'):
                value.check_archive(archive, inputs, '0.5.0', 'fixture-target')
            with tarfile.open(archive) as data:
                for filename, source in CLIENT_NOTICES.items():
                    self.assertEqual(data.extractfile('qsh-0.5.0-fixture-target/' + filename).read(),
                                     (ROOT / 'docs/licenses' / source).read_bytes())

    def test_missing_or_altered_crypto_notice_is_refused(self):
        for filename in CLIENT_NOTICES:
            for option in ('omit', 'alter'):
                with self.subTest(filename=filename, option=option), tempfile.TemporaryDirectory() as directory:
                    archive, inputs = self.archive(Path(directory), **{option: filename})
                    value = notice_checker()
                    with mock.patch.object(value, 'check_binary'), self.assertRaises(ValueError):
                        value.check_archive(archive, inputs, '0.5.0', 'fixture-target')

    def test_notice_inventory_does_not_admit_extra_archive_members(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, inputs = self.archive(Path(directory), extra='LICENSE-UNREVIEWED.txt')
            value = notice_checker()
            with mock.patch.object(value, 'check_binary'), self.assertRaises(ValueError):
                value.check_archive(archive, inputs, '0.5.0', 'fixture-target')


if __name__ == '__main__':
    unittest.main()
