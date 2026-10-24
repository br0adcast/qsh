import copy
import datetime
import importlib.util
import json
import hashlib
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def load_script(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_maintenance_exception():
    # Owned local data, not an official advisory or a production exception.
    identity = ('unmaintained', 'RUSTSEC-2026-9004', 'owned-maintenance', '1.0.0')
    return {identity: {
        'kind': identity[0], 'id': identity[1], 'package': identity[2], 'version': identity[3],
        'owner': 'Owned fixture', 'review_by': '2027-01-24',
        'tracking': 'https://example.invalid/maintenance',
        'reason': 'Synthetic local maintenance disposition for identity and kind controls.',
    }}


def receipt(lock, database, count=2, extra=''):
    return ("    Fetching advisory database from `https://github.com/RustSec/advisory-db.git`\n"
            + f"      Loaded 1 security advisories (from {database})\n"
            + "    Updating crates.io index\n"
            + f"    Scanning {lock} for vulnerabilities ({count} crate dependencies)\n" + extra)


class AdvisoryGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate = load_script('check-dependencies')

    def setUp(self):
        self.today = datetime.date(2026, 10, 24)
        self.exceptions = self.gate.load_exceptions(ROOT / 'scripts/dependency-exceptions.json', self.today)
        self.lock, self.database = Path('/owned/Cargo.lock'), Path('/owned/advisories')

    def test_review_date_is_inclusive_and_expired_exceptions_fail(self):
        path = ROOT / 'scripts/dependency-exceptions.json'
        self.gate.load_exceptions(path, datetime.date(2027, 1, 24))
        with self.assertRaisesRegex(ValueError, 'expired'):
            self.gate.load_exceptions(path, datetime.date(2027, 1, 25))

    def test_missing_metadata_duplicate_or_ranged_exception_is_rejected(self):
        entries = json.loads((ROOT / 'scripts/dependency-exceptions.json').read_text())
        for mutate in ['owner', 'duplicate', 'range']:
            changed = copy.deepcopy(entries)
            if mutate == 'owner':
                del changed[0]['owner']
            elif mutate == 'duplicate':
                changed.append(changed[0])
            else:
                changed[0]['version'] = '>=0.10'
            with tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'exceptions.json'
                path.write_text(json.dumps(changed))
                with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                    self.gate.load_exceptions(path, self.today)

    def test_ignore_scope_requires_every_locked_version_to_match(self):
        packages = [{'name': 'rsa', 'version': '0.10.0-rc.18'}]
        self.gate.validate_exception_versions(self.exceptions, packages)
        for changed in [packages[1:], packages + [{'name': 'rsa', 'version': '0.10.0-rc.19'}],
                        [dict(packages[0], version='0.10.0-rc.19')]]:
            with self.subTest(changed=changed), self.assertRaisesRegex(ValueError, 'locked'):
                self.gate.validate_exception_versions(self.exceptions, changed)

    def test_ignored_advisory_identity_kind_and_metadata_must_match_fresh_database(self):
        exceptions = {**self.exceptions, **synthetic_maintenance_exception()}
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory)
            for kind, identifier, package, _ in exceptions:
                path = database / 'crates' / package / (identifier + '.md')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('```toml\n[advisory]\n' + f'id="{identifier}"\npackage="{package}"\n'
                                + (f'informational="{kind}"\n' if kind != 'vulnerability' else '')
                                + '```\n\n# Owned fixture\n')
            self.gate.validate_exception_advisories(exceptions, database)
            path = database / 'crates/owned-maintenance/RUSTSEC-2026-9004.md'
            original = path.read_text()
            for value in [original.replace('owned-maintenance', 'other'), original.replace('unmaintained', 'unsound'),
                          original.replace('RUSTSEC-2026-9004', 'RUSTSEC-2026-9001'),
                          original.replace('informational="unmaintained"', ''), 'missing TOML fence']:
                path.write_text(value)
                with self.subTest(value=value), self.assertRaises(ValueError):
                    self.gate.validate_exception_advisories(exceptions, database)
            path.unlink()
            with self.assertRaises(ValueError):
                self.gate.validate_exception_advisories(exceptions, database)

    def test_success_requires_exact_fetch_index_and_lock_receipt(self):
        text = receipt(self.lock, self.database)
        result = subprocess.CompletedProcess([], 0, '', text)
        self.assertTrue(self.gate.audit_passed(result, self.lock, self.database, 2))
        bad = ['', text.replace('    Updating crates.io index\n', ''), text + 'unexpected diagnostic\n',
               text.replace('crate dependencies)', 'dependencies)'), text.replace('2 crate', '3 crate'),
               text.replace(str(self.lock), '/other/Cargo.lock'), text.replace('RustSec', 'other'),
               text + text, text.replace('    Updating', '    Scanning', 1)]
        for stderr in bad:
            with self.subTest(stderr=stderr), self.assertRaises(ValueError):
                self.gate.audit_passed(subprocess.CompletedProcess([], 0, '', stderr),
                                       self.lock, self.database, 2)

    def test_index_errors_and_unknown_warning_fail_even_when_tool_exits_zero(self):
        for message in ["warning: couldn't update crates.io index: unavailable\n",
                        "error: couldn't check if the package is yanked: timeout\n",
                        'warning: something else\n']:
            result = subprocess.CompletedProcess([], 0, '', receipt(self.lock, self.database) + message)
            with self.subTest(message=message), self.assertRaises(ValueError):
                self.gate.audit_passed(result, self.lock, self.database, 2)

    def test_findings_remain_rejected_and_exit_status_must_agree(self):
        for summary in ['error: 1 vulnerability found!\n', 'error: 2 denied warnings found!\n']:
            text = receipt(self.lock, self.database, extra=summary)
            self.assertFalse(self.gate.audit_passed(subprocess.CompletedProcess([], 1, 'findings', text),
                                                  self.lock, self.database, 2))
            with self.assertRaises(ValueError):
                self.gate.audit_passed(subprocess.CompletedProcess([], 0, 'findings', text),
                                       self.lock, self.database, 2)
        for code in [1, 2]:
            with self.subTest(code=code), self.assertRaises(ValueError):
                self.gate.audit_passed(subprocess.CompletedProcess([], code, '',
                                       receipt(self.lock, self.database)), self.lock, self.database, 2)

    def test_only_matching_notice_summary_is_allowed_and_notice_remains_visible(self):
        stdout = 'Crate:     owned-fixture\nWarning:   notice\n'
        stderr = receipt(self.lock, self.database, extra='warning: 1 allowed warning found\n')
        self.assertTrue(self.gate.audit_passed(subprocess.CompletedProcess([], 0, stdout, stderr),
                                              self.lock, self.database, 2))
        for output in ['', stdout.replace('notice', 'yanked'), stdout + stdout]:
            with self.subTest(output=output), self.assertRaises(ValueError):
                self.gate.audit_passed(subprocess.CompletedProcess([], 0, output, stderr),
                                       self.lock, self.database, 2)
        with self.assertRaises(ValueError):
            self.gate.audit_passed(subprocess.CompletedProcess([], 0, stdout,
                                   receipt(self.lock, self.database)), self.lock, self.database, 2)

    def test_policy_tool_failure_or_missing_check_summary_cannot_pass(self):
        for code, fields in [(0, {'licenses': {'errors': 0}}),
                             (2, {name: {'errors': 0} for name in ['licenses', 'sources', 'bans']}),
                             (0, {name: {'errors': 1} for name in ['licenses', 'sources', 'bans']})]:
            result = subprocess.CompletedProcess([], code, '',
                      json.dumps({'type': 'summary', 'fields': fields}) + '\n')
            with self.subTest(code=code, fields=fields), self.assertRaises(ValueError):
                self.gate.policy_passed(result)


class ToolInstallationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.installer = load_script('install-dependency-tools')

    def fixture(self, root, output='fixture-tool 1.0.0', link=False):
        marker = root / 'executed'
        body = f'#!/bin/sh\nprintf executed > "{marker}"\nprintf "%s\\n" "{output}"\n'.encode()
        archive = root / 'tool.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            entry = tarfile.TarInfo('owned/fixture-tool')
            if link:
                entry.type = tarfile.SYMTYPE
                entry.linkname = '/bin/sh'
                tar.addfile(entry)
            else:
                entry.size = len(body)
                entry.mode = 0o755
                tar.addfile(entry, io.BytesIO(body))
        pin = {'name': 'fixture-tool', 'version_output': 'fixture-tool 1.0.0',
               'entry': 'owned/fixture-tool', 'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
               'binary_sha256': hashlib.sha256(body).hexdigest()}
        return archive, pin, marker

    def test_bad_archive_hash_prevents_execution_or_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, pin, marker = self.fixture(root)
            pin['sha256'] = '0' * 64
            with self.assertRaisesRegex(ValueError, 'archive checksum'):
                self.installer.install_archive(pin, archive, root / 'tools')
            self.assertFalse(marker.exists())
            self.assertFalse((root / 'tools/fixture-tool').exists())

    def test_archive_entry_must_be_regular_and_binary_hash_is_checked_before_execution(self):
        for mutation in ['symlink', 'binary-hash']:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive, pin, marker = self.fixture(root, link=mutation == 'symlink')
                if mutation == 'binary-hash':
                    pin['binary_sha256'] = '0' * 64
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    self.installer.install_archive(pin, archive, root / 'tools')
                self.assertFalse(marker.exists())
                self.assertFalse((root / 'tools/fixture-tool').exists())

    def test_wrong_version_is_not_published_and_verified_version_is(self):
        for output, accepted in [('fixture-tool 9.0.0', False), ('fixture-tool 1.0.0', True)]:
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                archive, pin, marker = self.fixture(root, output=output)
                if accepted:
                    self.installer.install_archive(pin, archive, root / 'tools')
                    self.assertTrue((root / 'tools/fixture-tool').is_file())
                else:
                    with self.assertRaisesRegex(ValueError, 'version'):
                        self.installer.install_archive(pin, archive, root / 'tools')
                    self.assertFalse((root / 'tools/fixture-tool').exists())
                self.assertTrue(marker.exists())


class RealToolPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gate = load_script('check-dependencies')
        installer = load_script('install-dependency-tools')
        cls.tools = Path(os.environ['QSH_TEST_DEPENDENCY_TOOLS']).resolve()
        for pin in installer.load_pins():
            installer.verify_tool(pin, cls.tools / pin['name'])

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qsh-policy-fixture-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.env = dict(os.environ, HOME=str(self.root), XDG_CONFIG_HOME=str(self.root / 'config'),
                        XDG_CACHE_HOME=str(self.root / 'cache'), HISTFILE='/dev/null',
                        CARGO_CACHE_RUSTC_INFO='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null')
        self.env['CARGO_HOME'] = os.environ.get('CARGO_HOME', str(Path.home() / '.cargo'))
        self.env['RUSTUP_HOME'] = os.environ.get('RUSTUP_HOME', str(Path.home() / '.rustup'))

    def run_owned(self, command):
        return subprocess.run([str(arg) for arg in command], cwd=self.root, env=self.env,
                              capture_output=True, text=True, timeout=60)

    def metadata(self, name='owned-dependency', version='1.0.0', license='MIT', duplicate=False):
        dependencies = [('dependency', name, version, license)]
        if duplicate:
            dependencies.append(('second', name, '2.0.0', license))
        (self.root / 'src').mkdir()
        (self.root / 'src/lib.rs').write_text('// Owned metadata-only fixture; never compiled.\n')
        manifest = '[package]\nname="owned-root"\nversion="1.0.0"\nlicense="MIT"\nedition="2021"\n'
        manifest += '[workspace]\nexclude=["dependency", "second"]\n[dependencies]\n'
        lock = 'version=4\n[[package]]\nname="owned-root"\nversion="1.0.0"\ndependencies=['
        lock += ','.join(json.dumps(name + ' ' + v) if duplicate else json.dumps(name)
                         for _, name, v, _ in dependencies) + ']\n'
        for alias, dep_name, dep_version, dep_license in dependencies:
            path = self.root / alias
            (path / 'src').mkdir(parents=True)
            (path / 'src/lib.rs').write_text('// Owned fixture.\n')
            (path / 'Cargo.toml').write_text('[package]\n' + f'name={json.dumps(dep_name)}\n'
                                           + f'version={json.dumps(dep_version)}\n'
                                           + f'license={json.dumps(dep_license)}\nedition="2021"\n')
            manifest += f'{alias}={{path="{alias}",package={json.dumps(dep_name)}}}\n'
            lock += f'[[package]]\nname={json.dumps(dep_name)}\nversion={json.dumps(dep_version)}\n'
        (self.root / 'Cargo.toml').write_text(manifest)
        (self.root / 'Cargo.lock').write_text(lock)
        return self.read_metadata()

    def read_metadata(self):
        result = self.run_owned(['cargo', 'metadata', '--all-features', '--locked', '--offline',
                                 '--format-version', '1'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / 'target').exists(), 'metadata must not allocate a Cargo target')
        return json.loads(result.stdout)

    def policy(self, metadata, config=None):
        path = self.root / 'metadata.json'
        path.write_text(json.dumps(metadata))
        result = self.run_owned(self.gate.policy_command(self.tools / 'cargo-deny',
                               self.root / 'Cargo.toml', config or ROOT / 'deny.toml', path))
        diagnostics = [json.loads(line) for line in result.stderr.splitlines() if line.startswith('{')]
        codes = [row['fields'].get('code') for row in diagnostics]
        return result, codes

    def test_allowed_owned_graph_passes_and_denied_license_is_a_real_policy_failure(self):
        metadata = self.metadata(license='GPL-3.0-only')
        result, codes = self.policy(metadata)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('rejected', codes)
        manifest = self.root / 'dependency/Cargo.toml'
        manifest.write_text(manifest.read_text().replace('GPL-3.0-only', 'MIT'))
        metadata = self.read_metadata()
        result, _ = self.policy(metadata)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_existing_mpl_exception_is_package_and_version_scoped(self):
        metadata = self.metadata(name='option-ext', version='0.2.0', license='MPL-2.0')
        result, _ = self.policy(metadata)
        self.assertEqual(result.returncode, 0, result.stderr)
        for path in [self.root / 'dependency/Cargo.toml', self.root / 'Cargo.lock']:
            path.write_text(path.read_text().replace('0.2.0', '0.2.1'))
        metadata = self.read_metadata()
        result, codes = self.policy(metadata)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('rejected', codes)

    def test_unreviewed_registry_is_rejected_without_fetching_it(self):
        metadata = self.metadata()
        dependency = next(package for package in metadata['packages'] if package['name'] == 'owned-dependency')
        old = dependency['id']
        new = 'registry+https://registry.example.invalid/index#owned-dependency@1.0.0'
        # Change the source identity of owned metadata, never contact that registry.
        metadata = json.loads(json.dumps(metadata).replace(old, new))
        next(package for package in metadata['packages'] if package['name'] == 'owned-dependency')['source'] = \
            'registry+https://registry.example.invalid/index'
        result, codes = self.policy(metadata)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('source-not-allowed', codes)
        self.assertIn('registry.example.invalid', result.stderr)

    def test_bans_are_executed_and_duplicates_remain_visible_warnings(self):
        metadata = self.metadata(duplicate=True)
        result, codes = self.policy(metadata)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('duplicate', codes)
        config = self.root / 'deny.toml'
        config.write_text((ROOT / 'deny.toml').read_text().replace('[bans]',
                          '[bans]\ndeny = ["owned-dependency@1.0.0"]'))
        result, codes = self.policy(metadata, config)
        self.assertNotEqual(result.returncode, 0, result.stderr)
        self.assertIn('banned', codes)

    def local_advisory_result(self, identifier, package, version, kind=None, exceptions=None, index=False):
        database = self.root / 'advisories'
        advisory = database / 'crates' / package / (identifier + '.md')
        advisory.parent.mkdir(parents=True, exist_ok=True)
        text = f'```toml\n[advisory]\nid="{identifier}"\npackage="{package}"\ndate="2026-10-24"\n'
        if kind:
            text += f'informational="{kind}"\n'
        text += '[versions]\npatched=[]\n```\n\n# Owned fixture advisory\n\nSynthetic local test data.\n'
        advisory.write_text(text)
        if not (database / '.git').exists():
            self.assertEqual(self.run_owned(['git', 'init', '-q', database]).returncode, 0)
        self.assertEqual(self.run_owned(['git', '-C', database, 'add', str(advisory)]).returncode, 0)
        commit = self.run_owned(['git', '-C', database, '-c', 'user.name=Owned fixture',
                                '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgsign=false',
                                'commit', '--allow-empty', '-qm', 'Owned local advisory fixture'])
        self.assertEqual(commit.returncode, 0, commit.stderr)
        lock = self.root / 'advisory.lock'
        lock.write_text('version=4\n[[package]]\n' + f'name="{package}"\nversion="{version}"\n'
                        + 'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                        + 'checksum="' + '0' * 64 + '"\n')
        command = self.gate.audit_command(self.tools / 'cargo-audit', lock, database, exceptions or {})
        # Only owned fixtures disable fetching/index access; production exposes no such switch.
        return self.run_owned(command + ['--no-fetch'] + ([] if index else ['--no-yanked']))

    def reviewed(self, name):
        exceptions = self.gate.load_exceptions(ROOT / 'scripts/dependency-exceptions.json',
                                               datetime.date(2026, 10, 24))
        return {identity: entry for identity, entry in exceptions.items() if identity[2] == name}

    def test_real_audit_accepts_reviewed_rsa_and_rejects_new_id_or_wrong_version(self):
        exceptions = self.reviewed('rsa')
        result = self.local_advisory_result('RUSTSEC-2023-0071', 'rsa', '0.10.0-rc.18',
                                            exceptions=exceptions)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '')
        self.gate.validate_exception_advisories(exceptions, self.root / 'advisories')
        with self.assertRaises(ValueError):
            self.gate.validate_exception_versions(exceptions, [{'name': 'rsa', 'version': '0.10.0-rc.19'}])
        result = self.local_advisory_result('RUSTSEC-2023-0071', 'rsa', '0.10.0-rc.19')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('RUSTSEC-2023-0071', result.stdout)
        result = self.local_advisory_result('RUSTSEC-2026-9001', 'owned-fixture', '1.0.0',
                                            exceptions=exceptions)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('RUSTSEC-2026-9001', result.stdout)

    def test_real_maintenance_exception_cannot_hide_new_kind_or_unrelated_warning(self):
        exceptions = synthetic_maintenance_exception()
        result = self.local_advisory_result('RUSTSEC-2026-9004', 'owned-maintenance', '1.0.0', 'unmaintained', exceptions)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.gate.validate_exception_advisories(exceptions, self.root / 'advisories')
        result = self.local_advisory_result('RUSTSEC-2026-9004', 'owned-maintenance', '1.0.0', 'unsound', exceptions)
        self.assertEqual(result.returncode, 0, result.stderr)  # Tool ignore alone is too broad.
        with self.assertRaisesRegex(ValueError, 'metadata no longer matches'):
            self.gate.validate_exception_advisories(exceptions, self.root / 'advisories')
        for category in ['unmaintained', 'unsound']:
            result = self.local_advisory_result('RUSTSEC-2026-9002', 'owned-fixture', '1.0.0', category, exceptions)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn(category, result.stdout)

    def test_real_missing_index_is_rejected_even_when_audit_exits_zero(self):
        cargo_home = self.root / 'unusable-cargo-home'
        cargo_home.write_text('Owned failure fixture: CARGO_HOME must be a directory.')
        self.env['CARGO_HOME'] = str(cargo_home)
        result = self.local_advisory_result('RUSTSEC-2023-0071', 'rsa', '0.10.0-rc.18',
                                            exceptions=self.reviewed('rsa'), index=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("warning: couldn't open crates.io index", result.stderr)
        with self.assertRaises(ValueError):
            self.gate.audit_passed(result, self.root / 'advisory.lock', self.root / 'advisories', 1)

    def test_real_notice_stays_visible_and_is_not_a_denied_warning(self):
        result = self.local_advisory_result('RUSTSEC-2026-9003', 'owned-fixture', '1.0.0', 'notice')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Warning:   notice', result.stdout)
        self.assertIn('warning: 1 allowed warning found\n', result.stderr)


if __name__ == '__main__':
    unittest.main()
