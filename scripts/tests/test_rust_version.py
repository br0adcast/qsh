"""Effective Cargo Rust-version policy controls; no builds or network required."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/check-rust-version.py'


def metadata(names=('transport', 'qshd')):
    packages = [{'id': 'path+file:///fixture/' + name + '#' + name + '@0.5.0',
                 'name': name, 'rust_version': '1.98.1'} for name in names]
    return {'packages': packages, 'workspace_members': [p['id'] for p in packages]}


class RustVersionTests(unittest.TestCase):
    def check(self, value):
        return subprocess.run([sys.executable, str(SCRIPT)], input=json.dumps(value),
                              text=True, capture_output=True, timeout=5)

    def test_effective_floor_accepts_variable_workspace_size(self):
        for names in [('transport',), ('transport', 'qshd'), ('transport', 'qshd', 'future-member')]:
            with self.subTest(names=names):
                result = self.check(metadata(names))
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(str(len(names)) + ' workspace', result.stdout)

    def test_excluded_dependency_does_not_receive_workspace_policy(self):
        value = metadata()
        value['packages'].append({'id': 'registry+fixture#vte@0.15.0', 'name': 'vte',
                                  'rust_version': '1.62.1'})
        result = self.check(value)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_or_wrong_effective_version_names_the_member(self):
        for version in [None, '1.98', '1.99.1']:
            value = metadata()
            value['packages'][0]['rust_version'] = version
            with self.subTest(version=version):
                result = self.check(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('transport', result.stderr)
                self.assertIn('1.98.1', result.stderr)
        value = metadata()
        del value['packages'][0]['rust_version']
        self.assertNotEqual(self.check(value).returncode, 0)

    def test_missing_member_record_is_not_ignored(self):
        value = metadata()
        value['packages'].pop()
        result = self.check(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('qshd', result.stderr)
        self.assertIn('record', result.stderr)

    def test_duplicate_records_or_members_are_rejected(self):
        for change in ['record', 'member']:
            value = metadata()
            if change == 'record':
                value['packages'].append(copy.deepcopy(value['packages'][0]))
            else:
                value['workspace_members'].append(value['workspace_members'][0])
            with self.subTest(change=change):
                self.assertNotEqual(self.check(value).returncode, 0)

    def test_malformed_or_empty_metadata_cannot_pass(self):
        for value in [None, [], {}, {'packages': [], 'workspace_members': []},
                      {'packages': [None], 'workspace_members': ['member']},
                      {'packages': 'invalid', 'workspace_members': []}]:
            with self.subTest(value=value):
                result = self.check(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertIn('Rust support floor:', result.stderr)
        result = subprocess.run([sys.executable, str(SCRIPT)], input='{',
                                text=True, capture_output=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')
        self.assertIn('invalid Cargo metadata', result.stderr)


if __name__ == '__main__':
    unittest.main()
