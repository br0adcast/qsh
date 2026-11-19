#!/usr/bin/env python3
"""Refuse publication when the repository settings that limit release authority are missing.

The publish job runs this before it can request a signature. It reads, through
`gh api` and changing nothing:

ruleset      An active tag ruleset covering every `v*` tag that restricts
             creation, update and deletion of those tags.
environment  The `release` environment requires at least one reviewer.

Immutable releases cannot be read with the workflow token; the uploader
checks that the published release reports `immutable` instead.

This detects a settings regression in an honest release run. It is not the
boundary itself: the workflow comes from the tagged commit, so whoever can
create a `v*` tag can also remove this check. The tag ruleset is what limits
that (#553).
"""
import argparse
import fnmatch
import importlib.util
from pathlib import Path
import sys

ENVIRONMENT = 'release'
TAG_RULES = frozenset({'creation', 'update', 'deletion'})
# Any name a release tag can have: `v`, then a version.
SAMPLE_TAG = 'refs/tags/v0.0.0-rc.0'


def _sibling(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'),
                                                  Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_github = _sibling('prepare-release-attestation')


class SettingsError(Exception):
    """A fixed diagnostic naming the missing setting; never an API body."""


def _matches(patterns, ref):
    if not isinstance(patterns, list) or any(not isinstance(p, str) for p in patterns):
        raise SettingsError('unexpected tag ruleset condition')
    return any(p == '~ALL' or fnmatch.fnmatchcase(ref, p) for p in patterns)


def covers_release_tags(ruleset):
    """True if this ruleset applies, actively, to every tag named `v*`."""
    if ruleset.get('target') != 'tag' or ruleset.get('enforcement') != 'active':
        return False
    names = (ruleset.get('conditions') or {}).get('ref_name')
    if not isinstance(names, dict):
        return False
    # Only patterns that match every `v*` tag count, and any exclusion could
    # leave some release tags uncovered, so none is accepted.
    include, exclude = names.get('include', []), names.get('exclude', [])
    if exclude or not _matches(include, SAMPLE_TAG):
        return False
    return any(p in ('~ALL', 'refs/tags/*', 'refs/tags/v*') for p in include)


def restricted_rules(ruleset):
    rules = ruleset.get('rules')
    if not isinstance(rules, list) or any(not isinstance(r, dict) for r in rules):
        raise SettingsError('unexpected tag ruleset rules')
    return {rule.get('type') for rule in rules} & TAG_RULES


def check_ruleset(repo, api_get, api_list):
    summaries = api_list(f'repos/{repo}/rulesets?targets=tag&includes_parents=true')
    restricted = set()
    for summary in summaries:
        if not isinstance(summary, dict) or type(summary.get('id')) is not int:
            raise SettingsError('unexpected repository ruleset record')
        ruleset = api_get(f'repos/{repo}/rulesets/{summary["id"]}')
        if not isinstance(ruleset, dict):
            raise SettingsError('repository ruleset could not be read')
        if covers_release_tags(ruleset):
            restricted |= restricted_rules(ruleset)
    missing = sorted(TAG_RULES - restricted)
    if missing:
        raise SettingsError('no active tag ruleset for v* restricts: ' + ', '.join(missing))


def check_environment(repo, api_get):
    environment = api_get(f'repos/{repo}/environments/{ENVIRONMENT}')
    if environment is None:
        raise SettingsError(f'the {ENVIRONMENT} environment does not exist')
    rules = environment.get('protection_rules') if isinstance(environment, dict) else None
    if not isinstance(rules, list):
        raise SettingsError(f'unexpected {ENVIRONMENT} environment record')
    if not any(isinstance(rule, dict) and rule.get('type') == 'required_reviewers'
               and isinstance(rule.get('reviewers'), list) and rule['reviewers']
               for rule in rules):
        raise SettingsError(f'the {ENVIRONMENT} environment requires no reviewer')


def check(repo, api_get=None, api_list=None):
    api_get = api_get or _github.api_get
    api_list = api_list or _github.api_list
    check_ruleset(repo, api_get, api_list)
    check_environment(repo, api_get)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument('--repo', required=True)
    args = parser.parse_args()
    try:
        check(args.repo)
    except (SettingsError, _github.AttestationError) as error:
        print('release settings: ' + str(error), file=sys.stderr)
        return 1
    print('release settings: tag ruleset and release environment are in place')
    return 0


if __name__ == '__main__':
    sys.exit(main())
