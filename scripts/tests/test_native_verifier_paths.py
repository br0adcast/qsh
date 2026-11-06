"""Whole-byte controls and literal workflow shells over inert products only."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("native_paths", ROOT / "scripts/check-native-verifier-paths.py")
checker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(checker)
PREFIXES = ("PRIVATE_WORKSPACE_CANARY", "PRIVATE_CARGO_CANARY", "PRIVATE_TEMP_CANARY")


class NativeVerifierPathTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="native-path-control-")
        self.addCleanup(self.directory.cleanup)
        self.binary = Path(self.directory.name) / "PRIVATE_BINARY_CANARY"

    def invoke(self, data, *, prefixes=PREFIXES, platform="linux", tool=None, args=None):
        self.binary.write_bytes(data)
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(checker.sys, "platform", platform), \
                mock.patch.object(checker.subprocess, "run", side_effect=tool) as run, \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = checker.main(args if args is not None else [str(self.binary), *prefixes])
        public = stdout.getvalue() + stderr.getvalue()
        self.assertNotIn("PRIVATE_", public)
        self.assertLess(len(public), 2048)
        self.assertEqual(stdout.getvalue(), "")
        report = json.loads(stderr.getvalue()) if stderr.getvalue().startswith("{") else None
        return status, report, run, public

    @staticmethod
    def nm_result(rows=b"", status=0):
        def run(command, **kwargs):
            assert command[:2] == ["/usr/bin/nm", "-pa"] and len(command) == 3
            assert kwargs["stdin"] == subprocess.DEVNULL
            assert kwargs["stderr"] == subprocess.DEVNULL
            assert kwargs["timeout"] == 15 and kwargs["env"]["LC_ALL"] == "C"
            kwargs["stdout"].write(rows)
            return subprocess.CompletedProcess(command, status)
        return run

    def test_matched_artifact_reports_only_bounded_metadata(self):
        data = b"\0" + PREFIXES[0].encode() + b"\xff"
        status, report, run, _ = self.invoke(data)
        self.assertEqual(status, 1)
        self.assertIsNotNone(report, "matched artifact lacked bounded category metadata")
        self.assertEqual(report, {
            "binary_sha256": hashlib.sha256(data).hexdigest(), "binary_bytes": len(data),
            "workspace_occurrences": 1, "cargo_home_occurrences": 0,
            "runner_temp_occurrences": 0, "nm_status": "not_requested",
            "oso_records": None, "unparsed_rows": None,
            "oso_records_with_prefix": None, "other_symbol_records_with_prefix": None})
        run.assert_not_called()

    def test_clean_artifact_does_not_launch_nm_even_on_darwin(self):
        for platform in ("linux", "darwin"):
            with self.subTest(platform=platform):
                status, report, run, public = self.invoke(b"\0\xffclean", platform=platform)
                self.assertEqual((status, report, public), (0, None, ""))
                run.assert_not_called()

    def test_each_category_repeated_and_overlapping_prefixes(self):
        for index, category in enumerate(checker.CATEGORIES):
            with self.subTest(category=category):
                status, report, _, _ = self.invoke(b"\0" + (PREFIXES[index].encode() + b"\xff") * 2)
                self.assertEqual(status, 1)
                self.assertEqual(report[category + "_occurrences"], 2)
        status, report, _, _ = self.invoke(b"ababa", prefixes=("aba", "ab", "aba"))
        self.assertEqual(status, 1)
        self.assertEqual([report[c + "_occurrences"] for c in checker.CATEGORIES], [1, 2, 1])

    def test_nontext_fsencoded_prefix_is_scanned_byte_for_byte(self):
        prefix = os.fsdecode(b"PRIVATE_NON_TEXT_\xff")
        status, report, _, _ = self.invoke(b"\0" + os.fsencode(prefix), prefixes=(prefix, *PREFIXES[1:]))
        self.assertEqual(status, 1)
        self.assertEqual(report["workspace_occurrences"], 1)

    def test_structural_oso_and_other_symbols_with_spaces_in_names(self):
        work, cargo, temp = (p.encode() for p in PREFIXES)
        rows = (b"0000000000000000 - 03 0001   OSO " + work + b"/one object.o\n"
                b"0000000000000001 - 03 0001   OSO " + cargo + b"/two.o\n"
                b"0000000000000002 - 00 0000    SO " + temp + b"/source.rs\n"
                b"0000000000000003 T _OSO_in_symbol_name_" + work + b"/with spaces\n"
                b"                 U _undefined\n")
        status, report, run, _ = self.invoke(work + cargo + temp, platform="darwin", tool=self.nm_result(rows))
        self.assertEqual(status, 1)
        run.assert_called_once()
        self.assertEqual(run.call_args.args[0][2], str(self.binary))
        self.assertEqual(report["nm_status"], "ok")
        self.assertEqual(report["oso_records"], 2)
        self.assertEqual(report["oso_records_with_prefix"], {"workspace": 1, "cargo_home": 1, "runner_temp": 0})
        self.assertEqual(report["other_symbol_records_with_prefix"], {"workspace": 1, "cargo_home": 0, "runner_temp": 1})
        self.assertEqual(report["unparsed_rows"], 0)

    def test_symbol_categories_count_equal_prefixes_independently(self):
        prefix = PREFIXES[0]
        rows = b"0000000000000000 - 03 0001   OSO " + prefix.encode() + b"/object.o\n"
        status, report, _, _ = self.invoke(prefix.encode(), prefixes=(prefix, prefix, prefix),
                                           platform="darwin", tool=self.nm_result(rows))
        self.assertEqual(status, 1)
        self.assertEqual(report["oso_records"], 1)
        self.assertEqual(report["oso_records_with_prefix"], dict.fromkeys(checker.CATEGORIES, 1))

    def test_zero_oso_does_not_allow_binary_match_outside_symbols(self):
        for rows in (b"", b"0000000000000000 T _symbol_named_OSO\n"):
            with self.subTest(empty=not rows):
                status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=self.nm_result(rows))
                self.assertEqual(status, 1)
                self.assertEqual(report["nm_status"], "ok")
                self.assertEqual(report["oso_records"], 0)
                self.assertEqual(report["oso_records_with_prefix"]["workspace"], 0)

    def test_malformed_unsupported_and_partial_rows_are_not_complete_attribution(self):
        invalid = [b"PRIVATE_MALFORMED_CANARY\n", b"0000000000000000 - zz 0001 OSO PRIVATE_SYMBOL_CANARY\n",
                   b"0000000000000000 - 03 0001 UNKNOWN PRIVATE_SYMBOL_CANARY\n"]
        valid = b"0000000000000000 - 03 0001   OSO " + PREFIXES[0].encode() + b"/object.o\n"
        for rows in invalid + [valid + invalid[0]]:
            with self.subTest(partial=rows.startswith(valid)):
                status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=self.nm_result(rows))
                self.assertEqual(status, 1)
                self.assertEqual(report["nm_status"], "partial")
                self.assertEqual(report["unparsed_rows"], 1)

    def test_nm_failures_are_fixed_statuses_and_never_allow_a_match(self):
        cases = [(self.nm_result(b"PRIVATE_STDOUT_CANARY", 2), "failed"),
                 (FileNotFoundError("PRIVATE_EXCEPTION_CANARY"), "unavailable"),
                 (PermissionError("PRIVATE_EXCEPTION_CANARY"), "io_error"),
                 (subprocess.TimeoutExpired("PRIVATE_COMMAND_CANARY", 15,
                                            output=b"PRIVATE_OUTPUT_CANARY", stderr=b"PRIVATE_STDERR_CANARY"), "timeout")]
        for tool, expected in cases:
            with self.subTest(status=expected):
                status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=tool)
                self.assertEqual(status, 1)
                self.assertEqual(report["nm_status"], expected)
                for key in ("oso_records", "unparsed_rows", "oso_records_with_prefix", "other_symbol_records_with_prefix"):
                    self.assertIsNone(report[key])

    def test_oversize_output_is_not_read_or_attributed(self):
        def oversize(command, **kwargs):
            kwargs["stdout"].truncate(checker.MAX_NM_BYTES + 1)
            return subprocess.CompletedProcess(command, 0)
        status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=oversize)
        self.assertEqual(status, 1)
        self.assertEqual(report["nm_status"], "oversize")
        self.assertIsNone(report["oso_records"])

    def test_private_nm_files_are_closed_on_every_outcome(self):
        original = checker.tempfile.TemporaryFile
        def oversize(command, **kwargs):
            kwargs["stdout"].truncate(checker.MAX_NM_BYTES + 1)
            return subprocess.CompletedProcess(command, 0)
        for tool in (self.nm_result(), self.nm_result(b"PRIVATE_MALFORMED_CANARY"),
                     self.nm_result(status=2), oversize, FileNotFoundError("PRIVATE_EXCEPTION_CANARY"),
                     PermissionError("PRIVATE_EXCEPTION_CANARY"),
                     subprocess.TimeoutExpired("PRIVATE_COMMAND_CANARY", 15)):
            opened = []
            def temporary(*args, **kwargs):
                stream = original(*args, dir=self.directory.name, **kwargs)
                self.assertEqual(os.fstat(stream.fileno()).st_mode & 0o777, 0o600)
                opened.append(stream)
                return stream
            with mock.patch.object(checker.tempfile, "TemporaryFile", side_effect=temporary):
                status, _, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=tool)
            self.assertEqual(status, 1)
            self.assertEqual(len(opened), 1)
            self.assertTrue(opened[0].closed)
            self.assertEqual(list(Path(self.directory.name).iterdir()), [self.binary])

    def test_private_file_creation_failure_keeps_fixed_refusal(self):
        for error in (OSError("PRIVATE_TEMP_CANARY"), FileNotFoundError("PRIVATE_TEMP_CANARY")):
            with mock.patch.object(checker.tempfile, "TemporaryFile", side_effect=error):
                status, report, run, _ = self.invoke(PREFIXES[0].encode(), platform="darwin")
            self.assertEqual(status, 1)
            self.assertEqual(report["nm_status"], "io_error")
            run.assert_not_called()

    def test_invalid_arguments_and_unreadable_artifacts_do_not_leak(self):
        cases = [[], ["PRIVATE_ARG_CANARY"], [str(self.binary), "", *PREFIXES[1:]],
                 [str(self.binary), *PREFIXES, "PRIVATE_EXTRA_CANARY"],
                 [str(self.binary) + "PRIVATE_MISSING_CANARY", *PREFIXES],
                 [str(self.binary.parent), *PREFIXES], ["PRIVATE_NUL_CANARY\0", *PREFIXES]]
        for args in cases:
            with self.subTest(argc=len(args)):
                status, report, run, public = self.invoke(b"clean", args=args)
                self.assertEqual(status, 1)
                self.assertIsNone(report)
                self.assertIn(public, ("release verifier path check refused: invalid_input\n",
                                       "release verifier path check refused: unreadable_artifact\n"))
                run.assert_not_called()

    def real_tool_control(self, body, *, timeout=None):
        # Redirect the private subprocess seam to our owned harmless Python child.
        # Production still requests only the fixed nm command; no product is run.
        original_run, original_popen = subprocess.run, subprocess.Popen
        children = []
        def spawn(*args, **kwargs):
            child = original_popen(*args, **kwargs)
            children.append(child)
            return child
        def tool(command, **kwargs):
            self.assertEqual(command, ["/usr/bin/nm", "-pa", str(self.binary)])
            self.assertEqual(kwargs["timeout"], 15)
            if timeout is not None:
                kwargs["timeout"] = timeout
            return original_run([sys.executable, "-I", "-B", "-c", body], **kwargs)
        with mock.patch.object(subprocess, "Popen", side_effect=spawn):
            status, report, _, _ = self.invoke(PREFIXES[0].encode(), platform="darwin", tool=tool)
        self.assertEqual(status, 1)
        self.assertEqual(len(children), 1)
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)
        return report

    def test_real_tool_stdout_stderr_are_private_and_child_is_reaped(self):
        report = self.real_tool_control(
            "import os; os.write(1, b'0000000000000000 - 03 0001   OSO PRIVATE_SYMBOL_CANARY\\n'); "
            "os.write(2, b'PRIVATE_STDERR_CANARY')")
        self.assertEqual(report["nm_status"], "ok")
        self.assertEqual(report["oso_records"], 1)

    def test_real_timeout_kills_and_reaps_only_the_owned_child(self):
        report = self.real_tool_control("import time; canary='PRIVATE_TIMEOUT_CANARY'; time.sleep(60)", timeout=0.05)
        self.assertEqual(report["nm_status"], "timeout")

    def test_old_and_new_whole_byte_predicates_are_equivalent(self):
        for data in (b"", b"\0\xff", *(p.encode() for p in PREFIXES),
                     b"\0" + PREFIXES[0].encode() + b"\xff" + PREFIXES[2].encode()):
            expected = int(any(os.fsencode(path) in data for path in PREFIXES))
            with self.subTest(size=len(data)):
                status, _, run, _ = self.invoke(data)
                self.assertEqual(status, expected)
                run.assert_not_called()


class NativeProductWorkflowTests(unittest.TestCase):
    TARGETS = (
        ('ubuntu-24.04', 'x86_64-unknown-linux-musl'),
        ('ubuntu-24.04-arm', 'aarch64-unknown-linux-musl'),
        ('macos-15', 'aarch64-apple-darwin'),
        ('macos-15-intel', 'x86_64-apple-darwin'),
    )
    NATIVE = 'Qualify the linked products and generated RSA operations'
    LINUX = 'Build the pinned native backend and products'
    DARWIN = ('aarch64-apple-darwin', 'x86_64-apple-darwin')

    @staticmethod
    def body(workflow, job, step):
        # Scope both job and exact step; preserve the literal shell indentation.
        lines = (ROOT / '.github/workflows' / workflow).read_text().splitlines()
        start = lines.index('  ' + job + ':') + 1
        end = next((i for i in range(start, len(lines))
                    if lines[i].startswith('  ') and not lines[i].startswith('   ')
                    and lines[i].strip() and not lines[i].lstrip().startswith('#')), len(lines))
        lines = lines[start:end]
        start = lines.index('      - name: ' + step) + 1
        end = next((i for i in range(start, len(lines)) if lines[i].startswith('      - ')), len(lines))
        lines = lines[start:end]
        start = lines.index('        run: |') + 1
        result = []
        for line in lines[start:]:
            if line and not line.startswith('          '):
                break
            result.append(line[10:] if line else '')
        if not result:
            raise AssertionError('missing literal workflow shell')
        return '\n'.join(result) + '\n'

    @contextlib.contextmanager
    def fixture(self, target, *, explicit_cargo=True, before='', after=''):
        with tempfile.TemporaryDirectory(prefix='product-shell-control-') as directory:
            work = Path(directory) / 'work'
            work.mkdir()
            scripts = work / 'scripts'
            scripts.mkdir()
            # The actual scanner, unchanged, handles every byte decision.
            scanner = ROOT / 'scripts/check-native-verifier-paths.py'
            (scripts / scanner.name).write_bytes(scanner.read_bytes())
            (scripts / 'build-openssl.sh').write_text('printf "%s\\n" "$FIXTURE_NATIVE_PREFIX"\n')
            tools = Path(directory) / 'tools'
            tools.mkdir()
            shim = tools / 'shim'
            shim.write_text('#!' + sys.executable + ' -I\n' + r'''
import hashlib, json, os
from pathlib import Path
import sys
name = Path(sys.argv[0]).name
args = sys.argv[1:]
keys = ('RUSTFLAGS', 'AWS_LC_SYS_USE_SYSTEM', 'AWS_LC_SYS_CFLAGS', 'CC',
        'OPENSSL_DIR', 'OPENSSL_STATIC', 'AARCH64_APPLE_DARWIN_OPENSSL_DIR',
        'AARCH64_APPLE_DARWIN_OPENSSL_STATIC', 'X86_64_APPLE_DARWIN_OPENSSL_DIR',
        'X86_64_APPLE_DARWIN_OPENSSL_STATIC')
entry = {'tool': name, 'args': args, 'env': {k: os.environ.get(k) for k in keys}}
if name == 'python3':
    scanner = next((a for a in args if a.endswith('/check-native-verifier-paths.py')), None)
    if scanner:
        index = args.index(scanner)
        entry['data_sha256'] = hashlib.sha256(Path(args[index + 1]).read_bytes()).hexdigest()
    else:
        entry = None
if entry:
    with open(os.environ['FIXTURE_LOG'], 'a') as output:
        output.write(json.dumps(entry) + '\n')
if name == 'cargo' and args[0] == 'build':
    target = args[args.index('--target') + 1]
    profile = 'release' if '--release' in args else 'debug'
    for role in ('qsh', 'qshd'):
        path = Path('target') / target / profile / role
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'inert-unstripped-' + role.encode() +
                         (os.fsencode(os.environ['GITHUB_WORKSPACE']) if os.environ['FIXTURE_BEFORE'] == role and target == os.environ['FIXTURE_FAULT_TARGET'] else b''))
elif name == 'strip':
    for arg in args:
        path = Path(arg)
        path.write_bytes(b'inert-stripped-' + path.name.encode() +
                         (os.fsencode(os.environ['GITHUB_WORKSPACE']) if os.environ['FIXTURE_AFTER'] == path.name and path.parts[1] == os.environ['FIXTURE_FAULT_TARGET'] else b''))
elif name == 'gcc':
    print('fixture-unknown-linux-gnu')
elif name == 'python3':
    os.execv(sys.executable, [sys.executable, *args])
''')
            shim.chmod(0o700)
            for name in ('cargo', 'readelf', 'otool', 'strip', 'gcc', 'python3'):
                (tools / name).symlink_to(shim)
            env = dict(os.environ)
            for key in ('RUSTFLAGS', 'AWS_LC_SYS_USE_SYSTEM', 'AWS_LC_SYS_CFLAGS', 'CC',
                        'CARGO_HOME', 'CARGO_TARGET_DIR', 'SSH_AUTH_SOCK', 'SSH_AGENT_PID'):
                env.pop(key, None)
            home, temp = Path(directory) / 'home', Path(directory) / 'temp'
            home.mkdir()
            temp.mkdir()
            env.update(HOME=str(home), XDG_CACHE_HOME=str(home / 'cache'),
                       XDG_CONFIG_HOME=str(home / 'config'), TMPDIR=str(temp),
                       HISTFILE='/dev/null', PATH=str(tools) + os.pathsep + os.environ['PATH'],
                       GITHUB_WORKSPACE=str(work), RUNNER_TEMP=str(temp), NATIVE_TARGET=target,
                       RUNNER_OS='macOS' if 'darwin' in target else 'Linux',
                       FIXTURE_LOG=str(Path(directory) / 'calls.jsonl'),
                       FIXTURE_BEFORE=before, FIXTURE_AFTER=after, FIXTURE_FAULT_TARGET=target,
                       FIXTURE_NATIVE_PREFIX=str(Path(directory) / 'native'),
                       OPENSSL_DIR=str(Path(directory) / 'native'), OPENSSL_STATIC='1')
            for arch in self.DARWIN:
                scoped = arch.upper().replace('-', '_')
                env[scoped + '_OPENSSL_DIR'] = str(Path(directory) / arch)
                env[scoped + '_OPENSSL_STATIC'] = '1'
            if explicit_cargo:
                env['CARGO_HOME'] = str(Path(directory) / 'cargo')
            yield work, env

    def execute(self, body, work, env):
        # The marker represents the next step, never an executable or packager.
        result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c',
                                 body + '\nprintf complete > "$GITHUB_WORKSPACE/completed"\n'],
                                cwd=work, env=env, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
        log = Path(env['FIXTURE_LOG'])
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        records = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
        return result, calls, records

    def environment(self, calls, env, targets, *, linux, deny_warnings=False):
        builds = [c for c in calls if c['tool'] == 'cargo' and c['args'][0] == 'build']
        self.assertEqual(len(builds), len(targets))
        cargo_home = env.get('CARGO_HOME', env['HOME'] + '/.cargo')
        rust = (f'--remap-path-prefix={env["GITHUB_WORKSPACE"]}=/qsh '
                f'--remap-path-prefix={cargo_home}=/cargo '
                f'--remap-path-prefix={env["RUNNER_TEMP"]}=/build')
        if not linux:
            rust += f' -C link-arg=-Wl,-oso_prefix,{env["GITHUB_WORKSPACE"]}/'
        if deny_warnings:
            rust += ' -Dwarnings'
        cflags = (f'-ffile-prefix-map={env["GITHUB_WORKSPACE"]}=/qsh '
                  f'-ffile-prefix-map={cargo_home}=/cargo '
                  f'-ffile-prefix-map={env["RUNNER_TEMP"]}=/build')
        for build, target in zip(builds, targets):
            self.assertEqual(build['args'], ['build', '--release', '--locked', '-p', 'qsh', '-p', 'qshd', '--target', target])
            self.assertEqual(build['env']['RUSTFLAGS'], rust)
            self.assertEqual(build['env']['AWS_LC_SYS_CFLAGS'], cflags)
            self.assertEqual(build['env']['AWS_LC_SYS_USE_SYSTEM'], '0')
            self.assertEqual(build['env']['CC'], 'musl-gcc' if linux else None)
            if linux:
                self.assertEqual(build['env']['OPENSSL_DIR'], env['FIXTURE_NATIVE_PREFIX'])
                self.assertEqual(build['env']['OPENSSL_STATIC'], '1')
            else:
                for arch in self.DARWIN:
                    for suffix in ('_OPENSSL_DIR', '_OPENSSL_STATIC'):
                        key = arch.upper().replace('-', '_') + suffix
                        self.assertEqual(build['env'][key], env[key])

    def products(self, calls, records, work, env, targets, kind, *, linkage=False):
        paths = [f'target/{target}/release/{role}' for target in targets for role in ('qsh', 'qshd')]
        scans = [c for c in calls if c['tool'] == 'python3']
        self.assertEqual(len(scans), 2 * len(paths))
        effective_home = env.get('CARGO_HOME', env['HOME'] + '/.cargo')
        for call, path in zip(scans, paths * 2):
            self.assertEqual(call['args'], ['-I', '-B', 'scripts/check-native-verifier-paths.py', path,
                                           env['GITHUB_WORKSPACE'], effective_home, env['RUNNER_TEMP']])
        stripped = [arg for c in calls if c['tool'] == 'strip' for arg in c['args']]
        self.assertEqual(stripped, paths)
        first_strip = next(i for i, c in enumerate(calls) if c['tool'] == 'strip')
        self.assertEqual(sum(c['tool'] == 'python3' for c in calls[:first_strip]), len(paths))
        last_strip = max(i for i, c in enumerate(calls) if c['tool'] == 'strip')
        self.assertEqual(sum(c['tool'] == 'python3' for c in calls[last_strip + 1:]), len(paths))
        self.assertEqual(len(records), len(paths))
        for record, path in zip(records, paths):
            data = (work / path).read_bytes()
            self.assertEqual(scans[len(paths) + paths.index(path)]['data_sha256'], hashlib.sha256(data).hexdigest())
            self.assertNotEqual(scans[paths.index(path)]['data_sha256'], hashlib.sha256(data).hexdigest())
            self.assertEqual(record, dict(schema=1, kind=kind, target=Path(path).parts[1],
                                          program=Path(path).name, profile='release', stage='stripped',
                                          sha256=hashlib.sha256(data).hexdigest(), bytes=len(data)))
        if linkage:
            links = [c for c in calls if c['tool'] in ('readelf', 'otool')]
            self.assertEqual(len(links), 1)
            self.assertEqual(links[0]['tool'], 'readelf' if env['RUNNER_OS'] == 'Linux' else 'otool')
            self.assertEqual(links[0]['args'], ['-d' if env['RUNNER_OS'] == 'Linux' else '-L', *paths])

    def test_native_product_build_receives_scoped_release_environment(self):
        body = self.body('native-crypto.yml', 'portable', self.NATIVE)
        for index, (_, target) in enumerate(self.TARGETS):
            with self.subTest(target=target), self.fixture(target, explicit_cargo=index % 2 == 0) as (work, env):
                result, calls, _ = self.execute(body, work, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.environment(calls, env, [target], linux='linux' in target,
                                 deny_warnings=(target == 'x86_64-apple-darwin'))
                tests = [c['args'] for c in calls if c['tool'] == 'cargo' and c['args'][0] == 'test']
                self.assertEqual(tests, [['test', '--locked', '-p', 'sshauth', '--target', target,
                                         '--test', 'rsa_file_signing', '--test', 'native_rsa_backend', '--', '--include-ignored']])
                test_call = next(c for c in calls if c['tool'] == 'cargo' and c['args'][0] == 'test')
                build_call = next(c for c in calls if c['tool'] == 'cargo' and c['args'][0] == 'build')
                cargo_home = env.get('CARGO_HOME', env['HOME'] + '/.cargo')
                baseline = (f'--remap-path-prefix={env["GITHUB_WORKSPACE"]}=/qsh '
                            f'--remap-path-prefix={cargo_home}=/cargo '
                            f'--remap-path-prefix={env["RUNNER_TEMP"]}=/build')
                if 'linux' not in target:
                    baseline += f' -C link-arg=-Wl,-oso_prefix,{env["GITHUB_WORKSPACE"]}/'
                self.assertEqual(test_call['env']['RUSTFLAGS'], baseline)
                self.assertEqual({key: value for key, value in test_call['env'].items() if key != 'RUSTFLAGS'},
                                 {key: value for key, value in build_call['env'].items() if key != 'RUSTFLAGS'})

    def test_native_product_checks_cover_both_roles_before_and_after_strip(self):
        body = self.body('native-crypto.yml', 'portable', self.NATIVE)
        for _, target in self.TARGETS:
            with self.subTest(target=target), self.fixture(target) as (work, env):
                result, calls, records = self.execute(body, work, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.products(calls, records, work, env, [target], 'native-product-path-qualification', linkage=True)

    def refusal(self, body, target, *, prepopulate=()):
        for stage in ('before', 'after'):
            for role in ('qsh', 'qshd'):
                with self.subTest(target=target, stage=stage, role=role), self.fixture(target, **{stage: role}) as (work, env):
                    for arch in prepopulate:
                        for program in ('qsh', 'qshd'):
                            p = work / 'target' / arch / 'release' / program
                            p.parent.mkdir(parents=True, exist_ok=True)
                            p.write_bytes(b'inert-unstripped' + (os.fsencode(env['GITHUB_WORKSPACE']) if stage == 'before' and role == program and arch == target else b''))
                    result, calls, records = self.execute(body, work, env)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse((work / 'completed').exists())
                    self.assertEqual(records, [])
                    diagnostic = json.loads(result.stderr.splitlines()[-1])
                    self.assertGreater(diagnostic['workspace_occurrences'], 0)
                    self.assertNotIn(env['GITHUB_WORKSPACE'], result.stdout + result.stderr)
                    if stage == 'before':
                        self.assertFalse(any(c['tool'] == 'strip' for c in calls))

    def test_native_product_path_refusal_stops_step(self):
        body = self.body('native-crypto.yml', 'portable', self.NATIVE)
        for _, target in self.TARGETS:
            self.refusal(body, target)

    def test_release_builds_receive_same_scoped_environment(self):
        for _, target in self.TARGETS[:2]:
            with self.subTest(target=target), self.fixture(target, explicit_cargo=False) as (work, env):
                result, calls, _ = self.execute(self.body('release.yml', 'linux', self.LINUX), work, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.environment(calls, env, [target], linux=True)
        for target in self.DARWIN:
            with self.fixture(target) as (work, env):
                result, calls, _ = self.execute(self.body('release.yml', 'macos', 'Build the native pair'), work, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.environment(calls, env, [target], linux=False)

    def test_release_poststrip_path_refusal_precedes_packaging(self):
        for _, target in self.TARGETS[:2]:
            body = self.body('release.yml', 'linux', self.LINUX)
            with self.subTest(target=target), self.fixture(target, explicit_cargo=False) as (work, env):
                result, calls, records = self.execute(body, work, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.products(calls, records, work, env, [target], 'release-product-path-qualification', linkage=True)
                self.assertTrue((work / 'completed').exists())
            self.refusal(body, target)
        body = self.body('release.yml', 'macos', 'Strip')
        for target in self.DARWIN:
            with self.fixture(target, explicit_cargo=False) as (work, env):
                for role in ('qsh', 'qshd'):
                    path = work / 'target' / target / 'release' / role
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b'inert-unstripped')
                result, calls, records = self.execute(body, work, env)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.products(calls, records, work, env, [target], 'release-product-path-qualification')
                self.assertTrue((work / 'completed').exists())
            self.refusal(body, target, prepopulate=[target])

    def test_darwin_archive_gate_runs_fixed_native_target_and_failure_blocks_upload(self):
        release = (ROOT / '.github/workflows/release.yml').read_text()
        job = release.split('  macos:\n',1)[1].split('  server-packages:\n',1)[0]
        self.assertIn('needs: [native-crypto]',job)
        for runner,target in self.TARGETS[2:]:
            self.assertIn('runner: '+runner+'\n            target: '+target,job)
        smoke=self.body('release.yml','macos','Authenticate the exact extracted native archive')
        self.assertLess(job.index('- name: Package'),job.index('- name: Authenticate the exact'))
        self.assertLess(job.index('- name: Authenticate the exact'),job.index('name: macos-${{ matrix.target }}'))
        self.assertNotIn('continue-on-error',job);self.assertNotIn('if: always()',job);self.assertNotIn('|| true',smoke)
        self.assertNotIn('--features',smoke);self.assertNotIn('--release',smoke)
        self.assertIn('--no-run',smoke);self.assertIn('--message-format=json',smoke)
        for target in self.DARWIN:
            for status in (0,17):
                with self.subTest(target=target,status=status),self.fixture(target) as (work,env):
                    # Execute the literal shell with an inert fixed driver. Its
                    # nonzero result must prevent the next upload-step marker.
                    driver=work/'scripts/darwin-artifact-smoke.py'
                    driver.write_text('import os,sys\nfrom pathlib import Path\n'
                        'Path(os.environ["FIXTURE_DRIVER_ARGS"]).write_text("\\n".join(sys.argv[1:]))\n'
                        'raise SystemExit(int(os.environ["FIXTURE_DRIVER_STATUS"]))\n')
                    env.update(RELEASE_VERSION='0.5.0',GITHUB_SHA='a'*40,
                               FIXTURE_DRIVER_ARGS=str(work/'driver-args'),FIXTURE_DRIVER_STATUS=str(status))
                    # Use fixture-owned tmp storage; no product is executed.
                    body=smoke.replace('/tmp/qsh185.XXXXXXXX',str(work/'qsh185.XXXXXXXX'))
                    result,_,_=self.execute(body,work,env)
                    self.assertEqual(result.returncode,status,result.stderr)
                    args=(work/'driver-args').read_text().splitlines()
                    self.assertEqual(args[0],'run-archive')
                    self.assertEqual(args[args.index('--target')+1],target)
                    self.assertEqual(args[args.index('--source-commit')+1],'a'*40)
                    self.assertEqual(args[args.index('--archive')+1],'dist/qsh-0.5.0-'+target+'.tar.gz')
                    self.assertEqual((work/'completed').exists(),status==0)

    def test_intel_owner_has_independent_budget_and_required_setup(self):
        native = (ROOT / '.github/workflows/native-crypto.yml').read_text()
        self.assertIn('  darwin-owner-intel:\n', native, 'Intel ownership needs its independent budget')
        job = native.split('  darwin-owner-intel:\n', 1)[1].split('\n  system-floors:', 1)[0]
        for required in ('name: Native Intel Darwin process owner', 'runs-on: macos-15-intel',
                         'timeout-minutes: 45', 'NATIVE_TARGET: x86_64-apple-darwin',
                         'ref: ${{ github.sha }}', 'checkout_sha=$(git rev-parse HEAD)',
                         'test "$checkout_sha" = "$GITHUB_SHA"',
                         '"$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT"',
                         'key: native-owner-x86_64-apple-darwin'):
            self.assertIn(required, job)
        for forbidden in ('needs:', 'continue-on-error:', 'if: success()', 'download-artifact',
                          'Qualify offline release authentication', self.NATIVE,
                          'cargo test --locked -p sshauth'):
            self.assertNotIn(forbidden, job)
        ordered = ['Bind the Intel owner checkout', 'Observe the Intel Darwin runtime',
                   'Install native owner prerequisites', 'Build and execute the pinned owner backend',
                   'Install qualified Rust for owner checks', 'Swatinem/rust-cache@',
                   'Qualify the production Intel Darwin process owner']
        self.assertEqual(sorted(ordered, key=job.index), ordered)
        backend = self.body('native-crypto.yml', 'darwin-owner-intel', 'Build and execute the pinned owner backend')
        for required in ('scripts/qualify-openssl.sh --target "$NATIVE_TARGET"',
                         'scripts/build-openssl.sh --target "$NATIVE_TARGET"',
                         '--cache "$RUNNER_TEMP/native-crypto"', '--toolchain-id "$ImageOS/$ImageVersion"',
                         'echo "OPENSSL_DIR=$prefix" >> "$GITHUB_ENV"',
                         "echo 'OPENSSL_STATIC=1' >> \"$GITHUB_ENV\""):
            self.assertIn(required, backend)
        rust = self.body('native-crypto.yml', 'darwin-owner-intel', 'Install qualified Rust for owner checks')
        self.assertIn('rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal', rust)
        self.assertIn('rustup target add "$NATIVE_TARGET"', rust)
        self.assertIn('scripts/check-qualified-rust.sh', rust)
        portable = native.split('  portable:\n', 1)[1].split('\n  darwin-owner-intel:', 1)[0]
        self.assertIn('timeout-minutes: 35', portable)
        self.assertNotIn('Qualify the production Intel Darwin process owner', portable)
        self.assertNotIn('Observe the Intel Darwin runtime', portable)

    def test_corrected_terminal_contract_literal_admission(self):
        command = 'keeper223 terminal kind=Command screen={screen} real_eof_delivered_alive=true actual_retiring_poll=Running screen_lifetime=EOF process_slot=after_IO_joins terminal=37 session=0 rescue=false'
        shell = 'keeper223 terminal kind=Shell screen={screen} eof_contract=normal_completion real_eof_delivered=true reader_join_held=true cleanup_receipts=true screen_lifetime=EOF process_slot=after_IO_joins terminal=37 session=0 rescue=false'
        records = [template.format(screen=screen) for template in (command, shell) for screen in ('false', 'true')]
        blocks = []
        for workflow, job, step in (
                ('ci.yml', 'macos', 'Qualify the production Darwin process owner'),
                ('native-crypto.yml', 'darwin-owner-intel', 'Qualify the production Intel Darwin process owner')):
            owner = self.body(workflow, job, step)
            start = owner.index('for screen in false true')
            stop = owner.index('test "$(grep -Fc \'keeper223 open_executor', start)
            block = owner[start:stop]
            blocks.append(block)
            good = '\n'.join(records) + '\n'
            variants = [(good, True)]
            for row in records:
                variants.extend([(good.replace(row + '\n', ''), False), (good + row + '\n', False)])
            variants.append(('\n'.join(command.format(screen=screen).replace('kind=Command', 'kind=' + kind)
                                       for kind in ('Shell', 'Command') for screen in ('false', 'true')) + '\n', False))
            for before, after in (('kind=Shell', 'kind=Other'), ('screen=false', 'screen=other'),
                                  ('real_eof_delivered=true', 'real_eof_delivered=false'),
                                  ('reader_join_held=true', 'reader_join_held=false'),
                                  ('cleanup_receipts=true', 'cleanup_receipts=false'),
                                  ('terminal=37', 'terminal=0'), ('session=0', 'session=1'),
                                  ('rescue=false', 'rescue=true')):
                variants.append((good.replace(before, after), False))
            variants.extend([(good + 'keeper223 terminal extra=true\n', False),
                             (good + 'keeper223 settlement boundary=failure_rescue_entry\n', False),
                             (good + 'SKIPPED\n', False)])
            with tempfile.TemporaryDirectory(prefix='terminal-contract-inert-') as directory:
                env = os.environ.copy(); env['runtime'] = directory
                for output, accepted in variants:
                    (Path(directory) / 'keeper-integrated-results.log').write_text(output)
                    result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' + block],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, accepted, output + result.stdout + result.stderr)
        self.assertEqual(blocks[0], blocks[1])
        source = (ROOT / 'qshd/src/darwin_process_scope/keeper_integration_tests.rs').read_text()
        terminal = source.split('fn terminal_run(command_only: bool)', 1)[1].split('pub(super) fn cancel_setup()', 1)[0]
        branches = terminal.split('match kind {', 1)[1]
        command, shell = branches.split('ChannelKind::Shell => {', 1)
        shell = shell.split('assert!(registry.retiring_count()', 1)[0]
        self.assertIn('TerminalEofContract::LiveApplication', command)
        self.assertLess(command.index('terminal_eof_until_contract'), command.index('snapshot.app_status.is_none()'))
        self.assertIn('for kind in [ChannelKind::Shell,ChannelKind::Command]', terminal)
        release = 'exclusive(&path.join("release"),nonce.as_bytes());'
        self.assertLess(shell.index('KEEPER_RESIZED'), shell.index(release))
        self.assertLess(shell.index('snapshot.app_status.is_none()'), shell.index(release))
        self.assertLess(shell.index(release), shell.index('TerminalEofContract::NormalCompletion'))
        self.assertLess(shell.index('TerminalEofContract::NormalCompletion'), shell.index('s.app_status==Some(37)'))
        self.assertIn('!s.custody_lost&&s.app_status==Some(37)&&s.session_wait==Some(0)&&s.drained&&s.broker_terminal&&s.census&&s.consumed', shell)
        self.assertIn('let fence=registry.begin_restart_fence().unwrap();assert!(fence.wait_until(Instant::now()).is_none(),"reader has not joined");', terminal)
        self.assertLess(terminal.index('reader has not joined'), terminal.index('observation.io.release_reader()'))

    def test_command_contrast_literal_gate_executes_only_inert_harness(self):
        selector = 'darwin_process_scope::keeper_integration_tests::keeper_command_terminal_contrast'
        blocks = []
        for workflow, job, step in (
                ('ci.yml', 'macos', 'Qualify the production Darwin process owner'),
                ('native-crypto.yml', 'darwin-owner-intel', 'Qualify the production Intel Darwin process owner')):
            owner = self.body(workflow, job, step)
            self.assertEqual(owner.count('timed command-terminal-contrast '), 1)
            start = owner.index('timed command-terminal-contrast ')
            stop = owner.index('verify_harness "$feature_harness"', start)
            block = owner[start:stop]
            blocks.append(block)
            self.assertIn('--ignored --exact ' + selector, block)
            self.assertLess(start, owner.index('timed integrated-runtime '))
            self.assertEqual(owner.count('verify_harness "$feature_harness"'), 2)
            with tempfile.TemporaryDirectory(prefix='contrast-inert-') as directory:
                runtime = Path(directory)
                harness = runtime / 'inert-harness'
                harness.write_text('#!/bin/bash\ntest "$*" = "--ignored --exact ' + selector + ' --nocapture --test-threads=1" || exit 9\ncat "$runtime/inert-output"\nexit "$inert_status"\n')
                harness.chmod(0o700)
                good = ('running 1 test\n' + 'test ' + selector + ' ... observing\nok\n'
                        'keeper223 terminal kind=Command screen=false real_eof_delivered_alive=true actual_retiring_poll=Running screen_lifetime=EOF process_slot=after_IO_joins terminal=37 session=0 rescue=false\n'
                        'keeper223 connected_join=normal registry=0 screen_credits=0 two_io_joins=terminal_certificate rescue=false\n'
                        'test result: ok. 1 passed; 0 failed; 0 ignored;\n')
                variants = [(good, '0', True), (good, '7', False),
                            (good.replace('running 1 test', 'running 0 tests'), '0', False),
                            (good.replace('1 passed', '0 passed'), '0', False),
                            (good.replace(selector, selector + '_wrong'), '0', False),
                            (good + 'test ' + selector + ' ... ok\n', '0', False),
                            (good.replace('connected_join=normal', 'connected_join=absent'), '0', False),
                            (good + 'test unexpected ... ok\n', '0', False),
                            (good + 'keeper223 settlement boundary=failure_rescue_entry\n', '0', False)]
                for output, status, accepted in variants:
                    (runtime / 'inert-output').write_text(output)
                    env = os.environ.copy()
                    env.update(runtime=directory, feature_harness=str(harness), inert_status=status)
                    result = subprocess.run(['bash', '-c', 'set -euo pipefail\ntimed() { shift; "$@"; }\n' + block],
                                            env=env, capture_output=True, text=True)
                    self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)
                (runtime / 'inert-output').write_text(good)
                env['inert_status'] = '0'
                for mutation in (block.replace('--exact ', ''), block.replace('--ignored ', ''),
                                 block.replace('--exact ' + selector, '--exact wrong_selector')):
                    result = subprocess.run(['bash', '-c', 'set -euo pipefail\n' +
                                             'timed() { shift; "$@"; }\n' + mutation],
                                            env=env, capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)

        self.assertEqual(blocks[0], blocks[1])
        source = (ROOT / 'qshd/src/darwin_process_scope/keeper_integration_tests.rs').read_text()
        self.assertIn('#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]\n'
                      '#[test]\n#[ignore = "requires exact owned native qualification"]\n'
                      'fn keeper_command_terminal_contrast() {\n    native::terminal_command_contrast();\n}', source)
        self.assertIn('pub(super) fn terminal() {\n        terminal_run(false);\n    }', source)
        self.assertIn('pub(super) fn terminal_command_contrast() {\n        terminal_run(true);\n    }', source)
        self.assertEqual(source.count('fn terminal_run(command_only: bool)'), 1)
        self.assertIn('s.app_status==Some(37)&&s.session_wait==Some(0)&&s.drained&&s.broker_terminal&&s.census&&s.consumed', source)
        self.assertIn('settlement("terminal_release_entry",body_ok);release.release();settlement("terminal_release_return",body_ok);c.finish(body_ok).await;result.unwrap();', source)
        self.assertNotIn('keeper_integrated_', selector)
        self.assertNotIn('keeper_native_', selector)
        for path in (ROOT / '.github/workflows').glob('*.yml'):
            for line in path.read_text().splitlines():
                if 'nextest run' in line or 'run-nextest-ci.py' in line:
                    self.assertNotIn('--include-ignored', line)
        self.assertNotIn('--include-ignored', (ROOT / 'scripts/run-nextest-ci.py').read_text())

    def test_intel_owner_preserves_artifact_and_acceptance_contract(self):
        native = (ROOT / '.github/workflows/native-crypto.yml').read_text()
        self.assertIn('  darwin-owner-intel:\n', native, 'independent Intel owner job is missing')
        owner = self.body('native-crypto.yml', 'darwin-owner-intel', 'Qualify the production Intel Darwin process owner')
        arm = self.body('ci.yml', 'macos', 'Qualify the production Darwin process owner')
        import re
        names = lambda body: re.findall(r'^  (darwin_process_scope::\S+)\s*\\?$', body, re.MULTILINE)
        self.assertEqual(len(names(owner)), 20)
        self.assertEqual(names(owner), [
            'darwin_process_scope::native_tests::darwin223_native_noncooperative_token_exec_and_bound_exit',
            'darwin_process_scope::native_tests::darwin223_native_signaled_leader_scope_uses_portable_code_one',
            'darwin_process_scope::native_tests::darwin223_native_already_zombie_handshake_child_keeps_reserved_leader',
            'darwin_process_scope::native_tests::darwin223_native_classification_bracket_refuses_exec_and_one_sided_zombie',
            'darwin_process_scope::native_tests::darwin223_native_silent_pty_leader_first_other_group_and_real_io_joins',
            'darwin_process_scope::native_tests::darwin223_native_connected_close_stop_rebind_and_fresh_session',
            'darwin_process_scope::native_tests::darwin223_native_exit_before_binding_exclusion_zombie_and_last_fork',
            'darwin_process_scope::native_tests::darwin223_native_term_and_interrupt_join_real_manager_and_workers',
            'darwin_process_scope::native_tests::darwin223_native_partial_descriptor_failure_retains_real_process_owner',
            'darwin_process_scope::native_tests::darwin223_native_actual_daemon_replacement_reaps_parked_scope_and_fresh_session',
            'darwin_process_scope::keeper_tests::keeper_native_exit37_and_pty_eof',
            'darwin_process_scope::keeper_tests::keeper_native_session_death_late_fork',
            'darwin_process_scope::keeper_tests::keeper_native_broker_group_intrusion',
            'darwin_process_scope::keeper_tests::keeper_native_cancel_before_admit_no_application',
            'darwin_process_scope::keeper_integration_tests::keeper_integrated_terminal_status_and_io',
            'darwin_process_scope::keeper_integration_tests::keeper_integrated_open_cancel_and_setup_failure',
            'darwin_process_scope::keeper_integration_tests::keeper_integrated_close_stop_rebind_and_fresh_session',
            'darwin_process_scope::keeper_integration_tests::keeper_integrated_term_interrupt_join',
            'darwin_process_scope::keeper_integration_tests::keeper_integrated_actual_daemon_replacement',
            'darwin_process_scope::keeper_integration_tests::keeper_integrated_foreign_sid_retains_debt',
        ])
        self.assertEqual(names(owner), names(arm))
        for count in (10, 4, 6):
            self.assertIn(f'test result: ok. {count} passed; 0 failed; 0 ignored;', owner)
        self.assertEqual(owner.count('cargo test -p qshd --lib'), 2)
        self.assertEqual(owner.count('--no-run --message-format=json-render-diagnostics'), 2)
        self.assertEqual(owner.count('--bin qshd --profile test'), 2)
        self.assertEqual(owner.count('verify_harness "$ordinary_harness"'), 2)
        self.assertEqual(owner.count('verify_harness "$feature_harness"'), 2)
        for required in ('--features test-build-labels', '--features test-darwin-keeper',
                         'timed feature-check cargo check', 'timed feature-clippy cargo clippy',
                         '-- -D warnings', '--target "$NATIVE_TARGET"',
                         "assert len(records) == 1", "assert set(record['features']) == features",
                         "record['manifest_path']", "record['target']['src_path']",
                         'hashlib.sha256(executable.read_bytes()).hexdigest()',
                         'test -z "${CARGO_ENCODED_RUSTFLAGS:-}"', '-Dwarnings',
                         '--remap-path-prefix=$GITHUB_WORKSPACE=/qsh', '-Wl,-oso_prefix,$GITHUB_WORKSPACE/',
                         'export AWS_LC_SYS_USE_SYSTEM=0', 'export AWS_LC_SYS_CFLAGS=',
                         'export HOME="$runtime/home"', 'XDG_CONFIG_HOME="$runtime/config"',
                         'XDG_CACHE_HOME="$runtime/cache"', 'HISTFILE=/dev/null',
                         "trap 'rm -rf \"$runtime\"' EXIT", 'set -euo pipefail',
                         'SKIPPED', 'rescue=true', 'seen == 1 && passed == 1',
                         'real_eof_delivered_alive=true', 'keeper223 open_executor mode=',
                         'ledger_before_setsid=true pending_interval=true refund=false replacement_refused=true foreign_signal=false voluntary_exit=true rescue=false',
                         'wire_STOP=ack_then_actual_exit_watch_and_consumed_wait', 'keeper223 replacement_routes old_image='):
            self.assertIn(required, owner)
        self.assertLess(owner.index('timed modern-runtime'), owner.index('timed keeper-runtime'))
        self.assertLess(owner.index('timed keeper-runtime'), owner.index('timed integrated-runtime'))

    def test_reusable_native_qualification_defaults_for_release_dispatch(self):
        # Source/interface simulation of Release's no-input manual caller, not
        # a GitHub execution. Read the callee default rather than inventing one.
        native = (ROOT / '.github/workflows/native-crypto.yml').read_text()
        called = native.split('  workflow_call:\n', 1)[1].split('\npermissions:', 1)[0]
        fields = dict(line.strip().split(': ', 1) for line in called.splitlines()
                      if line.startswith('        ') and ': ' in line)
        release = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('  workflow_dispatch:\n\nenv:', release)
        caller = release.split('  native-crypto:\n', 1)[1].split('\n  linux:', 1)[0]
        self.assertEqual(caller.strip(), 'uses: ./.github/workflows/native-crypto.yml')
        validator = self.body('native-crypto.yml', 'dispatch-mode', 'Refuse unknown manual modes')
        with self.fixture('x86_64-unknown-linux-musl') as (work, env):
            env['PTY_EOF_MODE'] = fields.get('default', '')
            result, calls, records = self.execute(validator, work, env)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertTrue((work / 'completed').is_file())
            self.assertEqual((calls, records), ([], []))
        self.assertIn('    inputs:\n      mode:\n', called)
        self.assertEqual(fields, {'type': 'string', 'required': 'false', 'default': 'qualification'})

    def test_native_manual_mode_contract(self):
        native = (ROOT / '.github/workflows/native-crypto.yml').read_text()
        direct = native.split('  workflow_dispatch:\n', 1)[1].split('  workflow_call:', 1)[0]
        for declaration in ('type: choice', 'required: true', 'default: qualification',
                            'options: [qualification, pty-eof-build, pty-eof-control]'):
            self.assertIn(declaration, direct)
        validator = self.body('native-crypto.yml', 'dispatch-mode', 'Refuse unknown manual modes')
        for mode, accepted in (('qualification', True), ('pty-eof-build', True),
                               ('pty-eof-control', True), ('', False), ('unknown', False)):
            with self.subTest(mode=mode), self.fixture('x86_64-unknown-linux-musl') as (work, env):
                env['PTY_EOF_MODE'] = mode
                result, calls, records = self.execute(validator, work, env)
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)
                self.assertEqual((work / 'completed').exists(), accepted)
                self.assertEqual((calls, records), ([], []))
        selection = "github.event_name == 'workflow_dispatch' && (inputs.mode == 'pty-eof-build' || inputs.mode == 'pty-eof-control')"
        for job in ('portable', 'darwin-owner-intel', 'system-floors', 'pty-eof-diagnostic'):
            condition = native.split('  ' + job + ':\n', 1)[1].splitlines()
            condition = next(line for line in condition if line.startswith('    if:'))
            expected = selection if job == 'pty-eof-diagnostic' else '!(' + selection + ')'
            self.assertEqual(condition, '    if: ${{ ' + expected + ' }}')
        dispatch = native.split('  dispatch-mode:\n', 1)[1].split('  pty-eof-diagnostic:', 1)[0]
        self.assertIn("    if: github.event_name == 'workflow_dispatch'\n", dispatch)
        # Truth table for the exact literal predicate checked above, not an
        # expression interpreter. Invalid manual modes still fail validation.
        for event, mode, diagnostic in (('workflow_dispatch', 'qualification', False),
                                       ('workflow_dispatch', 'pty-eof-build', True),
                                       ('workflow_dispatch', 'pty-eof-control', True),
                                       ('pull_request', '', False), ('push', '', False),
                                       ('pull_request', 'pty-eof-build', False)):
            with self.subTest(event=event, mode=mode):
                selected = event == 'workflow_dispatch' and mode in ('pty-eof-build', 'pty-eof-control')
                self.assertEqual(selected, diagnostic)
                self.assertEqual(not selected, not diagnostic)

    def test_four_native_targets_and_required_workflow_consumers_remain_wired(self):
        native = (ROOT / '.github/workflows/native-crypto.yml').read_text()
        import re
        portable = native.split('  portable:\n', 1)[1].split('\n  darwin-owner-intel:', 1)[0]
        diagnostic = native.split('  pty-eof-diagnostic:\n', 1)[1]
        pairs = r'          - runner: (\S+)\n            target: (\S+)'
        self.assertEqual(re.findall(pairs, portable), list(self.TARGETS))
        self.assertEqual(re.findall(pairs, diagnostic), list(self.TARGETS[2:]))
        selection = "github.event_name == 'workflow_dispatch' && (inputs.mode == 'pty-eof-build' || inputs.mode == 'pty-eof-control')"
        for job in ('portable', 'darwin-owner-intel', 'system-floors'):
            beginning = native.split('  ' + job + ':\n', 1)[1].split('\n', 1)[0]
            self.assertEqual(beginning, "    if: ${{ !(" + selection + ") }}")
        self.assertIn("    if: ${{ " + selection + " }}", diagnostic)
        self.assertIn('options: [qualification, pty-eof-build, pty-eof-control]', native)
        self.assertIn('ref: ${{ github.sha }}', diagnostic)
        self.assertIn('scripts/qualify-pty-eof-control.py "$PTY_EOF_MODE" "$NATIVE_TARGET"', diagnostic)
        for forbidden in ('--include-ignored', 'native_tests::', 'keeper_tests::', 'keeper_integration_tests::', 'upload-artifact'):
            self.assertNotIn(forbidden, diagnostic)
        self.assertEqual(native.count("      - 'cli/Cargo.toml'"), 2)
        helper = self.body('native-crypto.yml', 'portable', 'Qualify offline release authentication')
        self.assertIn('-p test_native_verifier_paths.py', helper)
        self.assertIn('scripts/check-native-verifier-paths.py', helper)
        product = self.body('native-crypto.yml', 'portable', self.NATIVE)
        self.assertNotIn('/debug/', product)
        self.assertIn('/release/', product)
        release = (ROOT / '.github/workflows/release.yml').read_text()
        self.assertIn('    uses: ./.github/workflows/native-crypto.yml', release)
        linux = release.split('  linux:\n', 1)[1].split('  macos:\n', 1)[0]
        macos = release.split('  macos:\n', 1)[1].split('  server-packages:\n', 1)[0]
        self.assertLess(linux.index('- name: ' + self.LINUX), linux.index('- name: Package'))
        self.assertLess(macos.index('- name: Build the native pair'), macos.index('- name: Strip'))
        self.assertLess(macos.index('- name: Strip'), macos.index('- name: Package'))


if __name__ == "__main__":
    unittest.main()
