"""Exercise the real package-header acceptance filter; no product build."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECK = ROOT / "packaging/check-maintainer-dependencies.sh"
RUNTIME_CHECK = ROOT / "packaging/check-runtime-dependencies.sh"


class DependencyHeaderTests(unittest.TestCase):
    def check(self, family, header):
        return subprocess.run(["bash", str(CHECK), family], input=header.encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_debian_requires_a_direct_useradd_provider(self):
        for header in ["libc6 (>= 2.30), passwd, libpam0g", "passwd (>= 1), libc6"]:
            self.assertEqual(self.check("deb", header).returncode, 0)
        for header in ["libc6, libpam0g", "not-passwd", "other | passwd", "passwd | other"]:
            with self.subTest(header=header):
                self.assertNotEqual(self.check("deb", header).returncode, 0)

    def test_rpm_requires_real_post_bits_for_both_command_files(self):
        result = self.check("rpm", "/usr/bin/getent\t1024\n/usr/sbin/useradd\t1024\nlibc.so.6()(64bit)\t0\n")
        self.assertEqual(result.returncode, 0, result.stderr)
        for flags in ["0", "2048", "post", "-1"]:
            with self.subTest(flags=flags):
                result = self.check("rpm", "/usr/bin/getent\t1024\n/usr/sbin/useradd\t" + flags + "\n")
                self.assertNotEqual(result.returncode, 0)

    def test_rpm_fake_capability_name_cannot_replace_script_phase(self):
        for header in ["shadow-utils(post)\t0\n/usr/bin/getent\t1024\n",
                       "/usr/sbin/useradd\t1024\n", ""]:
            self.assertNotEqual(self.check("rpm", header).returncode, 0)

    def test_unknown_format_is_rejected(self):
        self.assertNotEqual(self.check("unknown", "passwd").returncode, 0)


class RuntimeDependencyTests(unittest.TestCase):
    def check(self, family, header):
        return subprocess.run(["bash", str(RUNTIME_CHECK), family], input=header.encode(),
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_debian_requires_direct_libselinux_provider(self):
        for header in ["libc6 (>= 2.31), libselinux1, libpam0g",
                       "libselinux1 (>= 2.0), libc6"]:
            with self.subTest(header=header):
                result = self.check("deb", header)
                self.assertEqual(result.returncode, 0, result.stderr)
        for header in ["libc6, libpam0g", "not-libselinux1", "libselinux1-fake",
                       "other | libselinux1", "libselinux1 | other"]:
            with self.subTest(header=header):
                self.assertNotEqual(self.check("deb", header).returncode, 0)

    def test_rpm_requires_exact_libselinux_capability(self):
        for header in ["libselinux.so.1()(64bit)\nlibpam.so.0()(64bit)\n",
                       "libselinux.so.1\n", "libselinux.so.1(LIBSELINUX_1.0)(64bit)\n"]:
            with self.subTest(header=header):
                result = self.check("rpm", header)
                self.assertEqual(result.returncode, 0, result.stderr)
        for header in ["libpam.so.0()(64bit)\n", "not-libselinux.so.1()(64bit)\n",
                       "libselinux.so.10()(64bit)\n", "libselinux.so.1-fake\n",
                       "libselinux.so.1(LIBSELINUX_1.1)(64bit)\n"]:
            with self.subTest(header=header):
                self.assertNotEqual(self.check("rpm", header).returncode, 0)

    def test_unknown_format_is_rejected(self):
        self.assertNotEqual(self.check("unknown", "libselinux1").returncode, 0)


if __name__ == "__main__":
    unittest.main()
