"""Small ELF fixtures for the package's read-only libselinux ABI guard."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "scripts/check-selinux-linkage.sh"


class SelinuxLinkageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="qsh-selinux-linkage-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)

    def build(self, version=None, link=True):
        (self.work / "lib.c").write_text("int is_selinux_enabled(void) { return 0; }\n")
        (self.work / "main.c").write_text(
            "extern int is_selinux_enabled(void);\n"
            "int main(void) { return is_selinux_enabled(); }\n" if link
            else "int main(void) { return 0; }\n")
        flags = []
        if version:
            (self.work / "lib.map").write_text(
                f"{version} {{ global: is_selinux_enabled; }};\n")
            flags.append(f"-Wl,--version-script={self.work / 'lib.map'}")
        subprocess.run(["cc", "-shared", "-fPIC", "-Wl,-soname,libselinux.so.1",
                        *flags, "-o", str(self.work / "libselinux.so.1"),
                        str(self.work / "lib.c")], check=True, capture_output=True)
        if not (self.work / "libselinux.so").exists():
            (self.work / "libselinux.so").symlink_to("libselinux.so.1")
        command = ["cc", "-o", str(self.work / "qshd"), str(self.work / "main.c")]
        if link:
            command += [f"-L{self.work}", "-lselinux"]
        subprocess.run(command, check=True, capture_output=True)
        return self.work / "qshd"

    def check(self, binary, env=None):
        return subprocess.run(["bash", str(CHECK), str(binary)], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_unversioned_old_floor_and_known_node_pass(self):
        for node in [None, "LIBSELINUX_1.0"]:
            with self.subTest(node=node):
                binary = self.build(node)
                result = self.check(binary)
                self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_needed_and_newer_node_fail(self):
        for node, link in [(None, False), ("LIBSELINUX_1.1", True)]:
            with self.subTest(node=node, link=link):
                binary = self.build(node, link)
                result = self.check(binary)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"No such file or directory", result.stderr)

    def test_newer_symbol_even_with_known_verneed_fails(self):
        binary = self.build("LIBSELINUX_1.0")
        wrapper = self.work / "nm"
        wrapper.write_text("#!/bin/sh\n" +
                           f"'{shutil.which('nm')}' \"$@\" | sed 's/@LIBSELINUX_1[.]0/@LIBSELINUX_1.1/g'\n")
        wrapper.chmod(0o755)
        env = dict(os.environ, PATH=f"{self.work}:{os.environ['PATH']}")
        result = self.check(binary, env)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b"No such file or directory", result.stderr)

    def test_readelf_and_nm_errors_fail(self):
        binary = self.build()
        for tool, flag in [("readelf", "-d"), ("readelf", "-V"), ("nm", None)]:
            with self.subTest(tool=tool, flag=flag):
                wrapper = self.work / tool
                wrapper.write_text(
                    "#!/bin/sh\n" +
                    (f"if [ \"$1\" = '{flag}' ]; then exit 7; fi\n"
                     f"exec '{shutil.which(tool)}' \"$@\"\n" if flag else "exit 7\n"))
                wrapper.chmod(0o755)
                env = dict(os.environ, PATH=f"{self.work}:{os.environ['PATH']}")
                result = self.check(binary, env)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn(b"No such file or directory", result.stderr)
                wrapper.unlink()


if __name__ == "__main__":
    unittest.main()
