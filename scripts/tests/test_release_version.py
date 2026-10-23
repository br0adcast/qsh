"""Release selection controls using resolved metadata from owned Cargo workspaces."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/check-release-version.py'


class ReleaseVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # No dependencies, compilation, network or shared Cargo target needed.
        cls.fixture = tempfile.TemporaryDirectory(prefix='qsh-release-version-')
        cls.addClassCleanup(cls.fixture.cleanup)
        root = Path(cls.fixture.name)
        (root / 'Cargo.toml').write_text(
            '[workspace]\nmembers=["cli","daemon"]\nresolver="2"\n'
            '[workspace.package]\nversion="0.6.0"\n')
        for directory, name, version in [
                ('cli', 'qsh', 'version.workspace=true'),
                ('daemon', 'qshd', 'version="0.5.0"')]:
            package = root / directory
            package.mkdir()
            (package / 'Cargo.toml').write_text(
                '[package]\nname="' + name + '"\n' + version + '\n'
                'edition="2021"\n[lib]\npath="lib.rs"\n')
            (package / 'lib.rs').write_text('')
        env = os.environ.copy()
        env.update(HOME=str(root), XDG_CACHE_HOME=str(root / 'cache'),
                   XDG_CONFIG_HOME=str(root / 'config'), HISTFILE='/dev/null',
                   CARGO_HOME=os.environ.get('CARGO_HOME', str(Path.home() / '.cargo')),
                   RUSTUP_HOME=os.environ.get('RUSTUP_HOME', str(Path.home() / '.rustup')))
        env.pop('SSH_AUTH_SOCK', None)
        result = subprocess.run(
            ['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'],
            cwd=root, env=env, capture_output=True, text=True, timeout=20, check=True)
        cls.mismatch = json.loads(result.stdout)
        daemon_manifest = root / 'daemon/Cargo.toml'
        daemon_manifest.write_text(daemon_manifest.read_text().replace(
            'version="0.5.0"', 'version.workspace=true'))
        result = subprocess.run(
            ['cargo', 'metadata', '--format-version', '1', '--no-deps', '--offline'],
            cwd=root, env=env, capture_output=True, text=True, timeout=20, check=True)
        cls.matching = json.loads(result.stdout)

    def select(self, metadata, ref_type='tag', ref_name='v0.6.0'):
        return subprocess.run(
            [sys.executable, str(SCRIPT), '--ref-type', ref_type, '--ref-name', ref_name],
            input=json.dumps(metadata), capture_output=True, text=True, timeout=5)

    def require_refusal(self, metadata, ref_type='tag', ref_name='v0.6.0'):
        result = self.select(metadata, ref_type, ref_name)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertTrue(result.stderr.startswith('release version: '), result.stderr)

    def test_actual_cargo_metadata_mismatch_refuses_tag_and_branch(self):
        self.assertEqual({p['name']: p['version'] for p in self.mismatch['packages']},
                         {'qsh': '0.6.0', 'qshd': '0.5.0'})
        for ref_type in ['tag', 'branch']:
            with self.subTest(ref_type=ref_type):
                self.require_refusal(self.mismatch, ref_type)

    def test_matching_pair_selects_exact_tag_version(self):
        result = self.select(self.matching)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '0.6.0\n', ''))

    def test_branch_ignores_version_like_name(self):
        result = self.select(self.matching, 'branch', 'v9.9.9')
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, '0.6.0\n', ''))

    def test_wrong_or_unprefixed_tag_refused(self):
        for tag in ['v0.5.0', '0.6.0', 'vv0.6.0', 'v0.6.0\n']:
            with self.subTest(tag=tag):
                self.require_refusal(self.matching, ref_name=tag)

    def test_workspace_membership_required_not_package_name_alone(self):
        metadata = copy.deepcopy(self.matching)
        daemon = next(p for p in metadata['packages'] if p['name'] == 'qshd')
        metadata['workspace_members'].remove(daemon['id'])
        self.require_refusal(metadata)

    def test_external_same_named_package_cannot_override_member(self):
        metadata = copy.deepcopy(self.matching)
        external = copy.deepcopy(metadata['packages'][0])
        external.update(id='external-package', version='9.9.9')
        metadata['packages'].append(external)
        result = self.select(metadata)
        self.assertEqual((result.returncode, result.stdout), (0, '0.6.0\n'))

    def test_duplicate_or_missing_member_package_refused(self):
        for change in ['duplicate-id', 'missing-package', 'duplicate-name', 'duplicate-member']:
            metadata = copy.deepcopy(self.matching)
            if change == 'duplicate-id':
                metadata['packages'].append(copy.deepcopy(metadata['packages'][0]))
            elif change == 'missing-package':
                metadata['packages'].pop()
            elif change == 'duplicate-name':
                metadata['packages'][0]['name'] = metadata['packages'][1]['name']
            else:
                metadata['workspace_members'].append(metadata['workspace_members'][0])
            with self.subTest(change=change):
                self.require_refusal(metadata)

    def test_malformed_metadata_refused_coherently(self):
        for metadata in [None, [], {}, {'packages': [], 'workspace_members': []},
                         {'packages': 'invalid', 'workspace_members': []},
                         {'packages': [None], 'workspace_members': ['member']}]:
            with self.subTest(metadata=metadata):
                self.require_refusal(metadata)
        result = subprocess.run([sys.executable, str(SCRIPT), '--ref-type', 'branch',
                                 '--ref-name', 'main'], input='{', capture_output=True,
                                text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertEqual(result.stderr, 'release version: invalid Cargo metadata\n')

    def test_malformed_versions_refused_without_echoing_input(self):
        for version in [None, 1, '', '0.6', '00.6.0', '0.6.0\n', '0.6.0-01',
                        '0.6.0-', '0.6.0+bad space', '0.6.0-α', 'v0.6.0']:
            metadata = copy.deepcopy(self.matching)
            for package in metadata['packages']:
                package['version'] = version
            with self.subTest(version=version):
                result = self.select(metadata, 'branch', 'main')
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'release version: invalid package version\n')

    def test_prerelease_and_build_metadata_preserved(self):
        for version in ['0.6.0-rc.1', '0.6.0-0+build.01', '0.5.0']:
            metadata = copy.deepcopy(self.matching)
            for package in metadata['packages']:
                package['version'] = version
            with self.subTest(version=version):
                result = self.select(metadata, ref_name='v' + version)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, version + '\n', ''))


if __name__ == '__main__':
    unittest.main()
