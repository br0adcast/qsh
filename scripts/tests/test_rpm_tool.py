"""Offline preparation controls and optional generated RPM header checks.

Set QSH_RPM_TOOL to an absolute prepared generator path to run header checks;
the test suite never downloads, compiles, installs, or runs packaged payloads.
"""
import hashlib
import importlib.util
import io
import os
import shlex
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("rpm_prepare", ROOT / "packaging/rpm-tool/prepare.py")
prepare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(prepare)


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / "fixture.crate"

    def archive_with(self, name="fixture-1/src/lib.rs", kind=None):
        with tarfile.open(str(self.archive), "w:gz") as archive:
            member = tarfile.TarInfo(name)
            if kind is None:
                content = b"before\n"
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
            else:
                member.type = kind
                member.linkname = "/outside"
                archive.addfile(member)
        return hashlib.sha256(self.archive.read_bytes()).hexdigest()

    def test_checksum_rejection_creates_no_extracted_source(self):
        self.archive_with()
        target = self.root / "out"
        with self.assertRaisesRegex(ValueError, "checksum"):
            prepare.extract_source(self.archive, "0" * 64, "fixture-1", target)
        self.assertFalse(target.exists())

    def test_verified_source_is_extracted_and_real_patch_applied(self):
        digest = self.archive_with()
        target = self.root / "out"
        prepare.extract_source(self.archive, digest, "fixture-1", target)
        patch = self.root / "change.patch"
        patch.write_text("--- a/fixture-1/src/lib.rs\n+++ b/fixture-1/src/lib.rs\n@@ -1 +1 @@\n-before\n+after\n")
        prepare.apply_patch(target, patch)
        self.assertEqual((target / "fixture-1/src/lib.rs").read_text(), "after\n")
        with self.assertRaises(subprocess.CalledProcessError):
            prepare.apply_patch(target, patch)
        self.assertEqual((target / "fixture-1/src/lib.rs").read_text(), "after\n")

    def test_verified_archive_rejects_escape_and_links(self):
        for name, kind in [("fixture-1/../outside", None), ("other/src", None),
                           ("fixture-1/link", tarfile.SYMTYPE), ("fixture-1/hard", tarfile.LNKTYPE)]:
            with self.subTest(name=name):
                digest = self.archive_with(name, kind)
                target = self.root / ("out" + str(len(name)) + str(kind))
                with self.assertRaisesRegex(ValueError, "archive member"):
                    prepare.extract_source(self.archive, digest, "fixture-1", target)
                self.assertFalse(target.exists())

    def test_installer_checksum_failure_never_invokes_cargo(self):
        digest = self.archive_with()
        self.assertNotEqual(digest, prepare.SOURCES[0][1])
        commands = self.root / "commands"
        commands.mkdir()
        marker = self.root / "cargo-called"
        curl = commands / "curl"
        curl.write_text("#!/bin/sh\nwhile [ \"$1\" != --output ]; do shift; done\ncp \"$BAD_ARCHIVE\" \"$2\"\n")
        cargo = commands / "cargo"
        cargo.write_text("#!/bin/sh\ntouch \"$CARGO_MARKER\"\nexit 99\n")
        curl.chmod(0o755)
        cargo.chmod(0o755)
        environment = os.environ.copy()
        environment.update(PATH=str(commands) + os.pathsep + environment["PATH"],
                           BAD_ARCHIVE=str(self.archive), CARGO_MARKER=str(marker),
                           TMPDIR=str(self.root))
        result = subprocess.run(["bash", str(ROOT / "packaging/rpm-tool/install.sh")],
                                env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"source checksum mismatch", result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(list(self.root.glob("tmp.*")), [])

    def test_installer_runs_fresh_binary_checks_and_propagates_failure(self):
        # Stand in for downloading/building only; execute the real installer
        # and real header tests. A stale PATH binary must never be selected.
        bundle = self.root / "bundle"
        bundle.mkdir()
        for name in ["install.sh", "test_child_reaping.py", "test_dependencies.py"]:
            source = ROOT / "packaging/rpm-tool" / name
            (bundle / name).write_bytes(source.read_bytes())
        (bundle / "prepare.py").write_text("import pathlib, sys\npathlib.Path(sys.argv[1]).mkdir()\n")
        commands = self.root / "commands"
        commands.mkdir()
        cargo = commands / "cargo"
        cargo.write_text("""#!/bin/sh
mkdir -p "$CARGO_INSTALL_ROOT/bin"
cat > "$CARGO_INSTALL_ROOT/bin/cargo-generate-rpm" <<'TOOL'
#!/bin/sh
echo fresh-tool >&2
exit 17
TOOL
chmod +x "$CARGO_INSTALL_ROOT/bin/cargo-generate-rpm"
""")
        cargo.chmod(0o755)
        stale = commands / "cargo-generate-rpm"
        stale.write_text('#!/bin/sh\necho stale-tool >&2\nexit 18\n')
        stale.chmod(0o755)
        environment = os.environ.copy()
        environment.update(PATH=str(commands) + os.pathsep + environment["PATH"],
                           CARGO_INSTALL_ROOT=str(self.root / "installed"),
                           QSH_RPM_TOOL=str(stale))
        result = subprocess.run(["bash", str(bundle / "install.sh")], env=environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"fresh-tool", result.stderr)
        self.assertNotIn(b"stale-tool", result.stderr)

    def test_installer_child_gate_uses_fresh_absolute_tool_and_stops_on_failure(self):
        for exit_code in (0, 23):
            with self.subTest(exit_code=exit_code):
                root = self.root / str(exit_code); root.mkdir()
                bundle = root / 'bundle'; bundle.mkdir()
                (bundle / 'install.sh').write_bytes((ROOT / 'packaging/rpm-tool/install.sh').read_bytes())
                (bundle / 'prepare.py').write_text('import pathlib,sys;pathlib.Path(sys.argv[1]).mkdir()\n')
                record = root / 'gate-tool'; later = root / 'dependencies-called'
                (bundle / 'test_child_reaping.py').write_text(
                    'import pathlib,sys\npathlib.Path(' + repr(str(record))
                    + ').write_text(sys.argv[1]);sys.exit(' + str(exit_code) + ')\n')
                (bundle / 'test_dependencies.py').write_text(
                    'import pathlib,sys\nassert pathlib.Path(' + repr(str(record))
                    + ').read_text()==sys.argv[1]\npathlib.Path(' + repr(str(later)) + ').touch()\n')
                commands = root / 'commands'; commands.mkdir()
                cargo = commands / 'cargo'
                cargo.write_text('#!/bin/sh\nmkdir -p "$CARGO_INSTALL_ROOT/bin"\n'
                                 'printf "#!/bin/sh\\nexit 0\\n" > "$CARGO_INSTALL_ROOT/bin/cargo-generate-rpm"\n'
                                 'chmod +x "$CARGO_INSTALL_ROOT/bin/cargo-generate-rpm"\n')
                cargo.chmod(0o755)
                environment = dict(os.environ, PATH=str(commands) + os.pathsep + os.environ['PATH'],
                                   CARGO_INSTALL_ROOT=str(root / 'installed'), QSH_RPM_TOOL='/stale/tool')
                result = subprocess.run(['bash', str(bundle / 'install.sh')], env=environment,
                                        capture_output=True, timeout=10)
                self.assertEqual(result.returncode, exit_code, result.stderr)
                self.assertEqual(record.read_text(), str(root / 'installed/bin/cargo-generate-rpm'))
                self.assertEqual(later.exists(), exit_code == 0)

    def test_child_observer_rejects_adoption_after_natural_owned_reaping(self):
        # Only this subprocess becomes a subreaper; no state leaks to unittest.
        import json
        import sys
        code = r"""
import importlib.util,json,os,subprocess,sys,time
spec=importlib.util.spec_from_file_location('child_gate',sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
m.enable_subreaper()
producer='import os;pid=os.fork();os._exit(23) if pid==0 else print(pid)'
result=subprocess.run([sys.executable,'-B','-c',producer],capture_output=True,check=True)
pid=int(result.stdout)
observation=m.collect_owned_children(time.monotonic()+5)
assert pid in observation['adopted']
assert any(row['pid']==pid and os.waitstatus_to_exitcode(row['status'])==23 for row in observation['waits'])
try:m.require_no_adoption(observation)
except AssertionError:pass
else:raise AssertionError('adoption was accepted')
assert not m.collect_owned_children(time.monotonic()+5)['adopted']
print(json.dumps(observation))
"""
        result = subprocess.run([sys.executable, '-B', '-c', code,
                                 str(ROOT / 'packaging/rpm-tool/test_child_reaping.py')],
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertEqual(len(observed['adopted']), 1)
        self.assertEqual(len(observed['waits']), 1)
        self.assertFalse(observed['emergency_cleanup'])

    def test_reaping_patch_is_registered_without_changing_archive_pins(self):
        self.assertEqual(prepare.SOURCES, (
            ('cargo-generate-rpm-0.21.0', '3187e19f0e00274b3b24f017559038722388889bd1a2ecd2281cd748e7d52ec6'),
            ('rpm-0.23.2', 'cf5c92939a06adb261d757e43f49bcdb121d62c6fe8e859b1006ce37f81e6d7f')))
        name = 'cargo-generate-rpm-0.21.0-reap-ldd.patch'
        self.assertEqual(prepare.PATCHES[-1], name)
        self.assertTrue((ROOT / 'packaging/rpm-tool' / name).is_file())

    def test_package_floor_copy_sources_exist_in_both_actual_contexts(self):
        native = (ROOT / ".github/workflows/native-crypto.yml").read_text()
        native_line = next(line for line in native.splitlines()
                           if "run: docker build -f" in line)
        native_context = ROOT / shlex.split(native_line.split("run: ", 1)[1])[-1]
        server = (ROOT / "packaging/build-server-packages.sh").read_text()
        server_line = next(line for line in server.splitlines()
                           if '\"$docker\" build -f' in line)
        server_context = Path(shlex.split(server_line)[-1].replace("$root", str(ROOT)))
        for context in [native_context, server_context]:
            for family in ["deb", "rpm"]:
                dockerfile = ROOT / ("packaging/Dockerfile.build-" + family)
                for line in dockerfile.read_text().splitlines():
                    if line.startswith(("COPY ", "ADD ")):
                        source = shlex.split(line)[1]
                        self.assertTrue((context / source).exists(),
                                        "missing {} in {} context for {}".format(source, context, family))

    def test_wrong_patch_context_does_not_modify_source(self):
        digest = self.archive_with()
        target = self.root / "out"
        prepare.extract_source(self.archive, digest, "fixture-1", target)
        patch = self.root / "bad.patch"
        patch.write_text("--- a/fixture-1/src/lib.rs\n+++ b/fixture-1/src/lib.rs\n@@ -1 +1 @@\n-unexpected\n+after\n")
        with self.assertRaises(subprocess.CalledProcessError):
            prepare.apply_patch(target, patch)
        self.assertEqual((target / "fixture-1/src/lib.rs").read_text(), "before\n")


DEPENDENCY_SPEC = importlib.util.spec_from_file_location(
    "rpm_dependencies", ROOT / "packaging/rpm-tool/test_dependencies.py")
dependencies = importlib.util.module_from_spec(DEPENDENCY_SPEC)
DEPENDENCY_SPEC.loader.exec_module(dependencies)


@unittest.skipUnless(os.environ.get("QSH_RPM_TOOL"), "set QSH_RPM_TOOL to the prepared generator binary")
class GeneratedDependencyTests(dependencies.GeneratedDependencyTests):
    tool = os.environ.get("QSH_RPM_TOOL")


if __name__ == "__main__":
    unittest.main()
