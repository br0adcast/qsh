"""Validate the policy source/build boundary without accessing host SELinux."""
import importlib.util
from pathlib import Path
import os
import json
from unittest import mock
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / 'packaging/selinux/build.py'


class PolicyBuildTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BUILDER.is_file(), 'maintained policy builder is missing')
        spec = importlib.util.spec_from_file_location('policy_build', BUILDER)
        self.build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.build)

    def test_qualified_rules_have_no_debug_or_permissive_switch(self):
        self.build.validate_sources(ROOT / 'packaging/selinux')
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ('qshd.te', 'qshd.fc', 'qshd.if'):
                (directory / name).write_bytes((ROOT / 'packaging/selinux' / name).read_bytes())
            with (directory / 'qshd.te').open('a') as stream:
                stream.write('\npermissive qshd_t;\n')
            with self.assertRaisesRegex(ValueError, 'qualified'):
                self.build.validate_sources(directory)

    def test_source_changes_cannot_silently_add_privilege(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in ('qshd.te', 'qshd.fc', 'qshd.if'):
                (directory / name).write_bytes((ROOT / 'packaging/selinux' / name).read_bytes())
            with (directory / 'qshd.te').open('a') as stream:
                stream.write('\nallow qshd_t self:capability sys_admin;\n')
            with self.assertRaisesRegex(ValueError, 'qualified'):
                self.build.validate_sources(directory)

    def test_workspace_version_is_read_without_release_bump(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / 'Cargo.toml'
            manifest.write_text('[workspace.package]\nversion = \"0.5.0\"\n[other]\nversion = \"9.9.9\"\n')
            self.assertEqual(self.build.workspace_version(manifest), '0.5.0')

    def test_paths_reject_stale_outputs_and_overlapping_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'
            source.mkdir()
            self.build.validate_paths(source, base / 'work', base / 'out')
            (base / 'out').mkdir()
            with self.assertRaisesRegex(ValueError, 'exist'):
                self.build.validate_paths(source, base / 'work', base / 'out')
            with self.assertRaisesRegex(ValueError, 'overlap'):
                self.build.validate_paths(source, source / 'work', base / 'other')

    def test_module_parser_rejects_wrong_format_name_version_and_contexts(self):
        # Minimal header fixture uses the documented libsepol PP and module layout.
        text = b'SE Linux Module'
        module = struct.pack('<II', 0xf97cff8d, len(text)) + text
        module += struct.pack('<5I', 2, 19, 1, 8, 0)
        module += struct.pack('<I', 4) + b'qshd' + struct.pack('<I', 5) + b'0.2.0'
        contexts = b'/usr/bin/qshd -- system_u:object_r:qshd_exec_t:s0\n'
        offset = 20 + len(module)
        package = struct.pack('<5I', 0xf97cff8f, 1, 2, 20, offset) + module + struct.pack('<I', 0xf97cff90) + contexts
        self.build.validate_package(package, contexts)
        for bad in (b'bad', package.replace(b'qshd', b'evil', 1),
                    package.replace(b'0.2.0', b'0.3.0'),
                    package[:47] + struct.pack('<I', 21) + package[51:]):
            with self.subTest(bad=bad[:20]):
                with self.assertRaises(ValueError):
                    self.build.validate_package(bad, contexts)
        with self.assertRaises(ValueError):
            self.build.validate_package(package, contexts + b'extra')

    def test_compile_environment_ignores_ambient_make_and_loader_overrides(self):
        with mock.patch.dict(os.environ, {'M4': 'evil', 'M4PARAM': '-D evil',
                'AWK': 'evil', 'DIRECT_INITRC': 'y', 'MAKEFLAGS': '-e',
                'LD_PRELOAD': 'evil', 'PATH': '/evil'}, clear=True):
            env = self.build.compile_environment(Path('/work'), 123)
        self.assertEqual(env['PATH'], '/usr/bin:/usr/sbin:/bin:/sbin')
        self.assertEqual(env['SOURCE_DATE_EPOCH'], '123')
        self.assertFalse(set(env) & {'M4', 'M4PARAM', 'AWK', 'DIRECT_INITRC',
                                    'MAKEFLAGS', 'LD_PRELOAD'})
        command = self.build.compile_command(Path('/include'))
        self.assertEqual(command[0], '/usr/bin/make')
        self.assertIn('M4=/usr/bin/m4', command)
        self.assertIn('AWK=/usr/bin/gawk', command)
        self.assertIn('DIRECT_INITRC=n', command)
        self.assertNotIn('M4PARAM=', command)  # retain pinned Makefile's mcs flags

    def test_source_bundle_members_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            for name in self.build.BUNDLE_SOURCE_FILES:
                (source / name).write_text('source')
            (source / 'private-note.txt').write_text('must not ship')
            files = self.build.bundle_source_files(source)
            self.assertEqual(set(files), {'packaging/selinux/' + name
                                         for name in self.build.BUNDLE_SOURCE_FILES})
            self.assertNotIn('packaging/selinux/private-note.txt', files)

    def test_environment_recipe_is_obtainable_and_bundled(self):
        pins = json.loads((ROOT / 'packaging/selinux/inputs.json').read_text())
        self.assertRegex(pins['base_image'], r'^rockylinux/rockylinux:8@sha256:[0-9a-f]{64}$')
        self.assertIn('Dockerfile', self.build.BUNDLE_SOURCE_FILES)
        recipe = (ROOT / 'packaging/selinux/Dockerfile').read_text()
        self.assertIn(pins['base_image'], recipe)
        self.assertIn(pins['signing_key_sha256'], recipe)
        for name, version in pins['installed_tools'].items():
            self.assertIn(name + '-' + version, recipe)
        self.assertIn('--disablerepo=\'*\'', recipe)
        self.assertIn('timeout 600', recipe)
        self.assertIn('gpgcheck=1', recipe)
        # The pinned devel Makefile discovers interface layers with find.
        self.assertRegex(recipe, r'\bfindutils\b')

    def test_source_bundle_is_deterministic_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'
            source.mkdir()
            (source / 'notice').write_text('upstream notice\n')
            self.build.source_bundle(base / 'a.tar.gz', {'sources/notice': source / 'notice'}, 123)
            self.build.source_bundle(base / 'b.tar.gz', {'sources/notice': source / 'notice'}, 123)
            self.assertEqual((base / 'a.tar.gz').read_bytes(), (base / 'b.tar.gz').read_bytes())


if __name__ == '__main__':
    unittest.main()
