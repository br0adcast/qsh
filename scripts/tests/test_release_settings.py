"""Release authority settings check against modelled GitHub API answers (#553)."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/check-release-settings.py'
REPO = 'br0adcast/qsh'


def _load():
    spec = importlib.util.spec_from_file_location('release_settings', HELPER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


settings = _load()

RULESET = {'id': 7, 'name': 'release tags', 'target': 'tag', 'enforcement': 'active',
           'conditions': {'ref_name': {'include': ['refs/tags/v*'], 'exclude': []}},
           'rules': [{'type': 'creation'}, {'type': 'update'}, {'type': 'deletion'}]}
ENVIRONMENT = {'name': 'release', 'protection_rules': [
    {'id': 1, 'type': 'required_reviewers', 'prevent_self_review': False,
     'reviewers': [{'type': 'User', 'reviewer': {'login': 'br0adcast'}}]}]}


class Api:
    """The read-only GitHub answers the check asks for, as a dictionary."""
    def __init__(self, rulesets, environment):
        self.rulesets = {r['id']: r for r in rulesets}
        self.environment = environment
        self.endpoints = []

    def get(self, endpoint):
        self.endpoints.append(endpoint)
        if endpoint == f'repos/{REPO}/environments/release':
            return self.environment
        prefix = f'repos/{REPO}/rulesets/'
        if endpoint.startswith(prefix):
            return self.rulesets.get(int(endpoint[len(prefix):]))
        raise AssertionError(endpoint)

    def list(self, endpoint):
        self.endpoints.append(endpoint)
        assert endpoint == f'repos/{REPO}/rulesets?targets=tag&includes_parents=true', endpoint
        return [{'id': r['id'], 'name': r['name'], 'target': r['target'],
                 'enforcement': r['enforcement']} for r in self.rulesets.values()]


def check(rulesets=(RULESET,), environment=ENVIRONMENT):
    api = Api(copy.deepcopy(list(rulesets)), copy.deepcopy(environment))
    settings.check(REPO, api_get=api.get, api_list=api.list)
    return api


def changed(base, **fields):
    value = copy.deepcopy(base)
    value.update(fields)
    return value


class SettingsTests(unittest.TestCase):
    def refused(self, message, **kwargs):
        with self.assertRaisesRegex(settings.SettingsError, message):
            check(**kwargs)

    def test_owner_settings_pass_and_read_only_endpoints(self):
        api = check()
        self.assertEqual(api.endpoints, [f'repos/{REPO}/rulesets?targets=tag&includes_parents=true',
                                         f'repos/{REPO}/rulesets/7', f'repos/{REPO}/environments/release'])

    def test_broad_include_patterns_cover_release_tags(self):
        for include in (['~ALL'], ['refs/tags/*'], ['refs/tags/other', 'refs/tags/v*']):
            with self.subTest(include=include):
                check(rulesets=[changed(RULESET, conditions={'ref_name': {'include': include, 'exclude': []}})])

    def test_rules_may_come_from_several_rulesets(self):
        first = changed(RULESET, id=1, rules=[{'type': 'creation'}, {'type': 'deletion'}])
        second = changed(RULESET, id=2, rules=[{'type': 'update'}, {'type': 'non_fast_forward'}])
        check(rulesets=[first, second])

    def test_missing_or_inactive_or_narrow_rulesets_are_refused(self):
        cases = {
            'none': [],
            'evaluate': [changed(RULESET, enforcement='evaluate')],
            'disabled': [changed(RULESET, enforcement='disabled')],
            'branch': [changed(RULESET, target='branch')],
            'narrow': [changed(RULESET, conditions={'ref_name': {'include': ['refs/tags/v1*'], 'exclude': []}})],
            # Matches the sample tag, but not every release tag.
            'narrow sample': [changed(RULESET, conditions={'ref_name': {'include': ['refs/tags/v0*'], 'exclude': []}})],
            'other tags': [changed(RULESET, conditions={'ref_name': {'include': ['refs/tags/release-*'], 'exclude': []}})],
            'exclusion': [changed(RULESET, conditions={'ref_name': {'include': ['refs/tags/v*'],
                                                                    'exclude': ['refs/tags/v9*']}})],
            'no condition': [changed(RULESET, conditions={})],
        }
        for name, rulesets in cases.items():
            with self.subTest(name):
                self.refused('creation, deletion, update', rulesets=rulesets)

    def test_each_missing_tag_rule_is_named(self):
        for missing in ('creation', 'update', 'deletion'):
            rules = [{'type': t} for t in ('creation', 'update', 'deletion') if t != missing]
            with self.subTest(missing=missing):
                self.refused('restricts: ' + missing + '$', rulesets=[changed(RULESET, rules=rules)])

    def test_environment_must_exist_and_require_a_reviewer(self):
        self.refused('does not exist', environment=None)
        for rules in ([], [{'type': 'wait_timer', 'wait_timer': 30}],
                      [{'type': 'required_reviewers', 'reviewers': []}],
                      [{'type': 'branch_policy'}]):
            with self.subTest(rules=rules):
                self.refused('requires no reviewer', environment=changed(ENVIRONMENT, protection_rules=rules))

    def test_malformed_answers_fail_closed(self):
        for rulesets, environment in [
                ([changed(RULESET, rules=None)], ENVIRONMENT),
                ([changed(RULESET, rules=['creation'])], ENVIRONMENT),
                ([changed(RULESET, conditions={'ref_name': {'include': 'refs/tags/v*'}})], ENVIRONMENT),
                ([RULESET], changed(ENVIRONMENT, protection_rules=None)),
                ([RULESET], [])]:
            with self.subTest(rulesets=rulesets, environment=environment):
                with self.assertRaises(settings.SettingsError):
                    check(rulesets=rulesets, environment=environment)
        with self.assertRaisesRegex(settings.SettingsError, 'ruleset record'):
            settings.check(REPO, api_get=lambda e: None, api_list=lambda e: [{'id': 'seven'}])
        with self.assertRaisesRegex(settings.SettingsError, 'could not be read'):
            settings.check(REPO, api_get=lambda e: None, api_list=lambda e: [{'id': 7}])


FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
answers = json.loads(open(os.environ['FAKE_ANSWERS']).read())
args = sys.argv[1:]
assert args[:4] == ['api', '--include', '--method', 'GET'], args
endpoint = args[4].split('?')[0] + ('?' + args[4].split('?')[1].split('&per_page')[0] if '?' in args[4] else '')
code, body = answers.get(endpoint, [404, {'message': 'Not Found'}])
sys.stdout.write(f'HTTP/2.0 {code} X\r\ncontent-type: application/json\r\n\r\n' + json.dumps(body))
sys.exit(0 if code == 200 else 1)
'''


class CommandTests(unittest.TestCase):
    def run_check(self, answers):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            (base / 'gh').write_text(FAKE_GH)
            (base / 'gh').chmod(0o755)
            (base / 'answers.json').write_text(json.dumps(answers))
            env = dict(os.environ, PATH=str(base) + os.pathsep + os.environ['PATH'],
                       FAKE_ANSWERS=str(base / 'answers.json'), HOME=str(base),
                       XDG_CONFIG_HOME=str(base / 'config'), XDG_CACHE_HOME=str(base / 'cache'),
                       HISTFILE='/dev/null', PYTHONDONTWRITEBYTECODE='1')
            return subprocess.run([sys.executable, str(HELPER), '--repo', REPO],
                                  env=env, capture_output=True, text=True, timeout=60)

    def answers(self, environment=(200, ENVIRONMENT)):
        result = {f'repos/{REPO}/rulesets?targets=tag&includes_parents=true': [200, [RULESET]],
                  f'repos/{REPO}/rulesets/7': [200, RULESET]}
        if environment is not None:
            result[f'repos/{REPO}/environments/release'] = list(environment)
        return result

    def test_command_reads_through_gh_and_reports(self):
        result = self.run_check(self.answers())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('tag ruleset and release environment are in place', result.stdout)

    def test_command_refuses_missing_settings_and_api_failures(self):
        for answers, message in [
                (self.answers(environment=None), 'environment does not exist'),
                (self.answers(environment=(500, {})), 'HTTP 500'),
                ({}, 'listing was not found')]:
            with self.subTest(message=message):
                result = self.run_check(answers)
                self.assertEqual(result.returncode, 1)
                self.assertIn('release settings: ', result.stderr)
                self.assertIn(message, result.stderr)


if __name__ == '__main__':
    unittest.main()
