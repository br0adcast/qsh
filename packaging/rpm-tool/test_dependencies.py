"""Generate real RPMs and check dependency headers; never execute payloads."""
import argparse
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


_HEADER_TAGS = frozenset((1023, 1024, 1025, 1026, 1048, 1049, 1050,
                          1085, 1086, 1087, 1088, 5020, 5021, 5022, 5023))


def read_main_header(data):
    """Read selected test header fields, retaining absent tags and actual types."""
    if type(data) is not bytes or not 112 <= len(data) <= 64 * 1024**2:
        raise ValueError("RPM input bound")

    def header(offset, decode):
        if offset < 96 or offset > len(data) - 16:
            raise ValueError("RPM header extent")
        if data[offset:offset + 8] != b"\x8e\xad\xe8\x01\0\0\0\0":
            raise ValueError("RPM header magic")
        count, size = struct.unpack_from(">II", data, offset + 8)
        if count > (len(data) - offset - 16) // 16:
            raise ValueError("RPM entry table extent")
        store = offset + 16 + count * 16
        if size > len(data) - store:
            raise ValueError("RPM store extent")
        end = store + size
        entries = {}
        for index in range(count):
            tag, kind, start, length = struct.unpack_from(
                ">IIII", data, offset + 16 + index * 16)
            if start > size:
                raise ValueError("RPM entry offset")
            if not decode or tag not in _HEADER_TAGS:
                continue
            if tag in entries:
                raise ValueError("RPM duplicate selected tag")
            position = store + start
            if kind == 4:
                if length > (end - position) // 4:
                    raise ValueError("RPM integer extent")
                values = struct.unpack_from(">" + "I" * length, data, position)
            elif kind in (6, 8):
                if kind == 6 and length != 1:
                    raise ValueError("RPM STRING count")
                if length > end - position:
                    raise ValueError("RPM string count")
                values = []
                for _ in range(length):
                    terminator = data.find(b"\0", position, end)
                    if terminator < 0:
                        raise ValueError("RPM unterminated string")
                    values.append(data[position:terminator])
                    position = terminator + 1
                values = tuple(values)
            else:
                raise ValueError("RPM selected tag type")
            entries[tag] = dict(kind=kind, count=length, values=values)
        return entries, end

    _, signature_end = header(96, False)
    entries, _ = header((signature_end + 7) & ~7, True)
    return entries


class GeneratedDependencyTests(unittest.TestCase):
    tool = None

    def generate(self, metadata, *, inspect_header=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # Rocky minimal images expose /bin/true as a coreutils shebang
            # script. The running interpreter is a native ELF on our Linux
            # packaging hosts, so it exercises automatic library requirements.
            elf_source = Path(sys.executable).resolve()
            payload = elf_source.read_bytes()
            self.assertEqual(payload[:4], b"\x7fELF", str(elf_source))
            (root / "payload").write_bytes(payload)
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
            entries = read_main_header(output.read_bytes())
            if inspect_header is not None:
                inspect_header(entries)
            names, flags, versions = (entries[tag] for tag in (1049, 1048, 1050))
            if (names['kind'] != 8 or flags['kind'] != 4 or versions['kind'] != 8
                    or len({entry['count'] for entry in (names, flags, versions)}) != 1):
                raise ValueError("RPM dependency vectors")
            return result, list(zip(names['values'], flags['values'], versions['values']))

    def test_pre_post_preun_and_automatic_elf_requirements(self):
        result, dependencies = self.generate(
            '[package.metadata.generate-rpm.requires]\n"pre-provider"=">= 3"\n'
            '"policy-abi"="= 2"\n'
            '[package.metadata.generate-rpm.requires-pre]\n"pre-provider"=" * "\n'
            '[package.metadata.generate-rpm.requires-post]\n"post-provider"=""\n'
            '[package.metadata.generate-rpm.requires-preun]\n'
            '"policy-abi"=" * "\n"preun-empty"=""\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn((b"pre-provider", 1 << 9, b""), dependencies)
        self.assertIn((b"pre-provider", 12, b"3"), dependencies)
        self.assertIn((b"post-provider", 1 << 10, b""), dependencies)
        self.assertIn((b"policy-abi", 8, b"2"), dependencies)
        self.assertIn((b"policy-abi", 1 << 11, b""), dependencies)
        self.assertIn((b"preun-empty", 1 << 11, b""), dependencies)
        self.assertFalse(any(b"(preun)" in name for name, _, _ in dependencies))
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

    def test_absent_and_empty_preun_metadata_preserve_dependencies(self):
        result, absent = self.generate("")
        self.assertEqual(result.returncode, 0, result.stderr)
        result, empty = self.generate('[package.metadata.generate-rpm.requires-preun]\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(absent, empty)
        self.assertTrue(absent)

    def test_preun_rejects_versions_and_non_strings(self):
        for value in ['">= 1"', '"= 2"', '1', 'true', '[]', '{}']:
            with self.subTest(value=value):
                result, _ = self.generate(
                    '[package.metadata.generate-rpm.requires-preun]\nprovider=' + value + '\n')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"Invalid dependency version specified for provider", result.stderr)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", type=Path, help="absolute freshly installed generator path")
    arguments = parser.parse_args()
    if not arguments.tool.is_absolute() or not arguments.tool.is_file():
        parser.error("tool must be an existing absolute binary path")
    GeneratedDependencyTests.tool = str(arguments.tool)
    unittest.main(argv=[__file__])
