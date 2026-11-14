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

    def with_version(self, version):
        metadata = copy.deepcopy(self.matching)
        for package in metadata['packages']:
            package['version'] = version
        return metadata

    def test_prerelease_and_build_metadata_preserved(self):
        for version, ref_type in [('0.6.0-rc.1', 'tag'), ('0.6.0-rc.2+build.01', 'tag'),
                                  ('0.5.0', 'tag'), ('0.6.0-0+build.01', 'branch')]:
            with self.subTest(version=version):
                result = self.select(self.with_version(version), ref_type, 'v' + version)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, version + '\n', ''))

    def test_release_tags_spell_prereleases_with_a_dotted_number(self):
        for version in ['0.6.0-alpha.0', '0.6.0-beta.11', '0.6.0-rc.2', '0.6.0']:
            with self.subTest(version=version):
                result = self.select(self.with_version(version), ref_name='v' + version)
                self.assertEqual((result.returncode, result.stdout), (0, version + '\n'))
        # SemVer orders rc10 before rc2 and every rc.N before rc1. Branch package
        # builds keep any valid version; only release tags are restricted.
        for version in ['0.6.0-rc1', '0.6.0-rc10', '0.6.0-rc', '0.6.0-rc.1.1',
                        '0.6.0-rc.x', '0.6.0-RC.1', '0.6.0-preview.1', '0.6.0-0']:
            with self.subTest(version=version):
                result = self.select(self.with_version(version), ref_name='v' + version)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'release version: release prerelease '
                                 'must be alpha.N, beta.N or rc.N\n')
                result = self.select(self.with_version(version), 'branch', 'main')
                self.assertEqual((result.returncode, result.stdout), (0, version + '\n'))

    def order(self, ref_name, tags, ref_type='tag', releases=()):
        """`releases` holds (tag, draft, immutable) rows as the job lists them."""
        with tempfile.TemporaryDirectory(prefix='qsh-release-tags-') as directory:
            path = Path(directory) / 'tags'
            path.write_text(''.join(tag + '\n' for tag in tags))
            listing = Path(directory) / 'releases'
            listing.write_text(''.join('\t'.join(row) + '\n' for row in releases))
            return subprocess.run(
                [sys.executable, str(SCRIPT), '--ref-type', ref_type, '--ref-name', ref_name,
                 '--existing-tags', str(path), '--releases', str(listing)],
                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)

    def test_retry_of_a_published_immutable_release_follows_newer_tags(self):
        # An older published tag stays retryable after a newer one exists.
        published = [('v0.6.0-rc.2', 'false', 'true'), ('v0.6.0-rc.3', 'false', 'true')]
        for ref_name, tags in [
                ('v0.6.0-rc.2', ['v0.6.0-rc.2', 'v0.6.0-rc.3']),
                ('v0.6.0-rc.2', ['v0.6.0-rc.2', 'v0.6.0-rc.3', 'v0.6.0']),
                ('v0.6.0-rc.3', ['v0.6.0-rc.2', 'v0.6.0-rc.3'])]:
            with self.subTest(ref_name=ref_name, tags=tags):
                result = self.order(ref_name, tags, releases=published)
                self.assertEqual((result.returncode, result.stdout), (0, ref_name[1:] + '\n'))
                self.assertEqual(result.stderr, 'release version: retrying published '
                                 'immutable release ' + ref_name + '\n')

    def test_new_publication_below_a_newer_tag_is_refused(self):
        # Without its own published immutable release, rc.2 would be a new
        # lower-precedence publication, whatever other releases exist.
        tags = ['v0.6.0-rc.2', 'v0.6.0-rc.3']
        for releases in [
                [],
                [('v0.6.0-rc.3', 'false', 'true')],
                # A draft left by an interrupted run is still unpublished.
                [('v0.6.0-rc.2', 'true', 'false'), ('v0.6.0-rc.3', 'false', 'true')],
                [('v0.6.0-rc.2', 'true', 'true')],
                # Published before immutable releases: its assets could change.
                [('v0.6.0-rc.2', 'false', 'false')],
                # The tag must match exactly.
                [('v0.6.0-rc.2+1', 'false', 'true'), ('0.6.0-rc.2', 'false', 'true')]]:
            with self.subTest(releases=releases):
                result = self.order('v0.6.0-rc.2', tags, releases=releases)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'release version: release tag does not '
                                 'follow existing tag v0.6.0-rc.3\n')

    def test_release_listing_must_be_well_formed(self):
        tags = ['v0.6.0-rc.2']
        for releases, error in [
                ([('v0.6.0-rc.2', 'false')], 'invalid release listing'),
                ([('v0.6.0-rc.2', 'false', 'true', 'x')], 'invalid release listing'),
                ([('v0.6.0-rc.2', 'False', 'true')], 'invalid release listing'),
                ([('v0.6.0-rc.2', 'false', 'null')], 'invalid release listing'),
                ([('v0.6.0-rc.2', 'false', '')], 'invalid release listing'),
                ([('v0.6.0-rc.2', 'false', 'true'), ('v0.6.0-rc.2', 'true', 'false')],
                 'several releases use the release tag')]:
            with self.subTest(releases=releases):
                result = self.order('v0.6.0-rc.2', tags, releases=releases)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'release version: ' + error + '\n')

    def test_release_tag_follows_existing_tags_of_its_version(self):
        for ref_name, tags in [
                ('v0.6.0-rc.2', ['v0.5.0', 'v0.6.0-rc.2']),
                ('v0.6.0-rc.10', ['v0.6.0-rc.2', 'v0.6.0-rc.9', 'v0.6.0-rc.10']),
                ('v0.6.0-beta.1', ['v0.6.0-alpha.3', 'v0.6.0-beta.1']),
                ('v0.6.0', ['v0.6.0-rc.3', 'v0.6.0']),
                # Patch releases of an older line and prereleases of another
                # version are unconstrained by other versions' tags.
                ('v0.5.1', ['v0.5.0', 'v0.6.0', 'v0.5.1']),
                ('v0.7.0-rc.1', ['v0.6.1-rc.4', 'v0.8.0', 'v0.7.0-rc.1']),
                # A re-run keeps its own tag; non-version tags are ignored.
                ('v0.6.0-rc.2', ['vnext', 'release', 'v0.6', 'v0.6.0-rc.2'])]:
            with self.subTest(ref_name=ref_name, tags=tags):
                result = self.order(ref_name, tags)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, ref_name[1:] + '\n', ''))

    def test_release_tag_below_an_existing_tag_of_its_version_refused(self):
        for ref_name, tags, existing in [
                # The withdrawn v0.6.0-rc1 orders above every 0.6.0-rc.N.
                ('v0.6.0-rc.2', ['v0.6.0-rc1', 'v0.6.0-rc.2'], 'v0.6.0-rc1'),
                ('v0.6.0-rc.2', ['v0.6.0-rc.3', 'v0.6.0-rc.2'], 'v0.6.0-rc.3'),
                ('v0.6.0-alpha.9', ['v0.6.0-beta.1', 'v0.6.0-alpha.9'], 'v0.6.0-beta.1'),
                ('v0.6.0-rc.4', ['v0.6.0', 'v0.6.0-rc.4'], 'v0.6.0'),
                # Build metadata does not change precedence.
                ('v0.6.0-rc.2', ['v0.6.0-rc.2+1', 'v0.6.0-rc.2'], 'v0.6.0-rc.2+1')]:
            with self.subTest(ref_name=ref_name, tags=tags):
                result = self.order(ref_name, tags)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'release version: release tag does not '
                                 'follow existing tag ' + existing + '\n')

    def test_tag_order_requires_a_listed_release_tag(self):
        for ref_type, ref_name, tags, error in [
                ('branch', 'v0.6.0-rc.2', ['v0.6.0-rc.2'], 'tag order applies only to a release tag'),
                ('tag', '0.6.0-rc.2', ['0.6.0-rc.2'], 'invalid release tag'),
                ('tag', 'v0.6.0-rc.02', ['v0.6.0-rc.02'], 'invalid release tag'),
                ('tag', 'v0.6.0-rc2', ['v0.6.0-rc2'],
                 'release prerelease must be alpha.N, beta.N or rc.N'),
                ('tag', 'v0.6.0-rc.2', ['v0.5.0'], 'release tag is missing from the existing tags')]:
            with self.subTest(ref_type=ref_type, ref_name=ref_name):
                result = self.order(ref_name, tags, ref_type)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertEqual(result.stderr, 'release version: ' + error + '\n')
        missing = str(Path(self.fixture.name) / 'missing')
        with tempfile.TemporaryDirectory(prefix='qsh-release-tags-') as directory:
            present = Path(directory) / 'present'
            present.write_text('v0.6.0-rc.2\n')
            for files, error in [((missing, str(present)), 'unreadable existing tags'),
                                 ((str(present), missing), 'unreadable release listing')]:
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), '--ref-type', 'tag', '--ref-name',
                     'v0.6.0-rc.2', '--existing-tags', files[0], '--releases', files[1]],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (1, '', 'release version: ' + error + '\n'))
            # The release listing is required: without it a retry and a new
            # publication look alike.
            for option in ('--existing-tags', '--releases'):
                result = subprocess.run(
                    [sys.executable, str(SCRIPT), '--ref-type', 'tag', '--ref-name',
                     'v0.6.0-rc.2', option, str(present)],
                    stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5)
                self.assertEqual((result.returncode, result.stdout), (2, ''))
                self.assertIn('--existing-tags and --releases go together', result.stderr)


class TagOrderWorkflowTests(unittest.TestCase):
    def run_step(self, ref_name, listing, git_status=0, releases=(), gh_status=0):
        # Execute the publish job's actual step body with a fake git that
        # prints a fixed ls-remote listing and a fake gh that prints the
        # release rows its --jq filter would.
        workflow = (ROOT / '.github/workflows/release.yml').read_text()
        block = workflow.split("      - name: Require the tag to follow its version's existing tags\n", 1)[1]
        block = block.split('        run: |\n', 1)[1]
        lines = []
        for line in block.splitlines():
            if line and not line.startswith('          '):
                break
            lines.append(line[10:])
        with tempfile.TemporaryDirectory(prefix='qsh-tag-order-') as directory:
            base = Path(directory)
            (base / 'bin').mkdir()
            (base / 'listing').write_text(''.join(
                '{:040x}\trefs/tags/{}\n'.format(i, tag) for i, tag in enumerate(listing)))
            fake = base / 'bin/git'
            fake.write_text(
                '#!/bin/sh\n'
                'test "$*" = "ls-remote --tags --refs https://github.com/example/project.git '
                'refs/tags/v*" || exit 2\n'
                'cat "$LISTING"\nexit "$GIT_STATUS"\n')
            fake.chmod(0o755)
            (base / 'releases').write_text(''.join('\t'.join(row) + '\n' for row in releases))
            fake = base / 'bin/gh'
            fake.write_text(
                '#!/bin/sh\n'
                'test "$*" = "api --paginate repos/example/project/releases --jq '
                '.[] | [.tag_name, (.draft | tostring), (.immutable | tostring)] | @tsv" '
                '|| exit 2\n'
                'cat "$RELEASES"\nexit "$GH_STATUS"\n')
            fake.chmod(0o755)
            env = dict(PATH=str(base / 'bin') + os.pathsep + os.environ['PATH'],
                       HOME=directory, HISTFILE='/dev/null', RUNNER_TEMP=directory,
                       LISTING=str(base / 'listing'), GIT_STATUS=str(git_status),
                       RELEASES=str(base / 'releases'), GH_STATUS=str(gh_status),
                       GITHUB_REPOSITORY='example/project', GITHUB_REF_TYPE='tag',
                       GITHUB_REF_NAME=ref_name)
            return subprocess.run(['bash', '-c', '\n'.join(lines)], cwd=ROOT, env=env,
                                  stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                  timeout=10)

    def test_actual_step_accepts_a_tag_that_follows_its_version(self):
        result = self.run_step('v0.6.0-rc.2', ['v0.5.0', 'v0.6.0-rc.2'])
        self.assertEqual((result.returncode, result.stderr), (0, ''))
        self.assertEqual(result.stdout, '0.6.0-rc.2\n')

    def test_actual_step_refuses_an_out_of_order_tag(self):
        result = self.run_step('v0.6.0-rc.2', ['v0.5.0', 'v0.6.0-rc1', 'v0.6.0-rc.2'])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, 'release version: release tag does not follow '
                         'existing tag v0.6.0-rc1\n')

    def test_actual_step_fails_when_the_tag_listing_fails(self):
        result = self.run_step('v0.6.0-rc.2', ['v0.6.0-rc.2'], git_status=128)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')

    def test_actual_step_retries_a_published_immutable_release_below_a_newer_tag(self):
        tags = ['v0.5.0', 'v0.6.0-rc.2', 'v0.6.0-rc.3']
        published = [('v0.6.0-rc.2', 'false', 'true'), ('v0.6.0-rc.3', 'false', 'true')]
        result = self.run_step('v0.6.0-rc.2', tags, releases=published)
        self.assertEqual((result.returncode, result.stdout), (0, '0.6.0-rc.2\n'))
        self.assertEqual(result.stderr, 'release version: retrying published immutable '
                         'release v0.6.0-rc.2\n')
        # The same tag as a draft is a new publication below rc.3.
        draft = [('v0.6.0-rc.2', 'true', 'false'), ('v0.6.0-rc.3', 'false', 'true')]
        result = self.run_step('v0.6.0-rc.2', tags, releases=draft)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stderr, 'release version: release tag does not follow '
                         'existing tag v0.6.0-rc.3\n')

    def test_actual_step_fails_when_the_release_listing_fails(self):
        published = [('v0.6.0-rc.2', 'false', 'true')]
        result = self.run_step('v0.6.0-rc.2', ['v0.6.0-rc.2', 'v0.6.0-rc.3'],
                               releases=published, gh_status=1)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
