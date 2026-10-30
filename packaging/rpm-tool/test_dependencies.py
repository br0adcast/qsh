"""Generate real RPMs and check dependency headers; never execute payloads."""
import argparse
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest


class GeneratedDependencyTests(unittest.TestCase):
    tool = None

    def generate(self, metadata):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            elf_source = Path("/bin/true")
            (root / "payload").write_bytes(elf_source.read_bytes())
            (root / "payload").chmod(0o755)
            (root / "Cargo.toml").write_text(
                '[package]\nname="phase-test"\nversion="1.0.0"\nlicense="MIT"\n'
                'description="RPM phase test"\n[package.metadata.generate-rpm]\n'
                'assets=[{source="payload", dest="/usr/bin/phase-test", mode="755"}]\n'
                + metadata)
            output = root / "test.rpm"
            result = subprocess.run([self.tool, "--auto-req", "builtin",
                                     "--output", str(output)], cwd=root,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if result.returncode:
                return result, None
            data = output.read_bytes()
            def header(offset):
                self.assertEqual(data[offset:offset + 3], b"\x8e\xad\xe8")
                count, size = struct.unpack_from(">II", data, offset + 8)
                store = offset + 16 + count * 16
                entries = {}
                for index in range(count):
                    tag, kind, start, length = struct.unpack_from(">IIII", data, offset + 16 + index * 16)
                    if kind == 8:
                        entries[tag] = data[store + start:].split(b"\0", length)[:length]
                    elif kind == 4:
                        entries[tag] = struct.unpack_from(">" + "I" * length, data, store + start)
                return entries, store + size
            _, end = header(96)
            entries, _ = header((end + 7) & ~7)
            return result, list(zip(entries[1049], entries[1048], entries[1050]))

    def test_pre_post_and_automatic_elf_requirements(self):
        result, dependencies = self.generate(
            '[package.metadata.generate-rpm.requires]\n"pre-provider"=">= 3"\n'
            '[package.metadata.generate-rpm.requires-pre]\n"pre-provider"=" * "\n'
            '[package.metadata.generate-rpm.requires-post]\n"post-provider"=""\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn((b"pre-provider", 1 << 9, b""), dependencies)
        self.assertIn((b"pre-provider", 12, b"3"), dependencies)
        self.assertIn((b"post-provider", 1 << 10, b""), dependencies)
        self.assertTrue(any(name.startswith(b"libc.so.6") for name, _, _ in dependencies))
        self.assertFalse(any(b"(pre)" in name for name, _, _ in dependencies))

    def test_absent_and_empty_pre_metadata_preserve_dependencies(self):
        result, absent = self.generate("")
        self.assertEqual(result.returncode, 0, result.stderr)
        result, empty = self.generate('[package.metadata.generate-rpm.requires-pre]\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(absent, empty)
        self.assertTrue(absent)

    def test_pre_rejects_versions_and_non_strings(self):
        for value in ['">= 1"', '1']:
            with self.subTest(value=value):
                result, _ = self.generate(
                    '[package.metadata.generate-rpm.requires-pre]\nprovider=' + value + '\n')
                self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", type=Path, help="absolute freshly installed generator path")
    arguments = parser.parse_args()
    if not arguments.tool.is_absolute() or not arguments.tool.is_file():
        parser.error("tool must be an existing absolute binary path")
    GeneratedDependencyTests.tool = str(arguments.tool)
    unittest.main(argv=[__file__])
