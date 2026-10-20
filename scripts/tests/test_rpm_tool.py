"""Preparation controls; no network or packaging-tool compilation."""
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


if __name__ == "__main__":
    unittest.main()
