"""Controlled selections of the CI lane selector over the real tree (#609).

Each scenario commits a synthetic change on top of a copy of this checkout
in an owned temporary repository and selects lanes for it, exactly as the
`Select CI lanes` job would.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('qsh_ci_select', ROOT / 'scripts/ci-select.py')
select = importlib.util.module_from_spec(spec)
spec.loader.exec_module(select)

POLICY = select.load_policy(ROOT)
ALL = set(POLICY['lanes'])
DEPENDENT = {'check', 'container', 'macos', 'native', 'intel-legacy'}
DAEMON = DEPENDENT | {'intel-owner', 'floors'}
BOUNDARY = {'check', 'container'}
EMAIL = '986942+br0adcast@users.noreply.github.com'


class Repository:
    """A copy of this checkout's tracked files in an owned Git repository."""

    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qsh-ci-select-')
        top = Path(self.temp.name)
        self.root = top / 'repository'
        self.root.mkdir()
        for name in ('home', 'config', 'cache', 'tmp'):
            (top / name).mkdir()
        self.env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME=str(top / 'home'),
                        XDG_CONFIG_HOME=str(top / 'config'), XDG_CACHE_HOME=str(top / 'cache'),
                        TMPDIR=str(top / 'tmp'), HISTFILE='/dev/null', GIT_CONFIG_NOSYSTEM='1',
                        GIT_CONFIG_GLOBAL='/dev/null', GIT_AUTHOR_NAME='CI fixture',
                        GIT_COMMITTER_NAME='CI fixture', GIT_AUTHOR_EMAIL=EMAIL, GIT_COMMITTER_EMAIL=EMAIL)
        listed = subprocess.run(['git', '-C', str(ROOT), 'ls-files', '-z', '--cached', '--others',
                                 '--exclude-standard'], capture_output=True,
                                check=True, timeout=60).stdout
        for raw in listed.split(b'\0'):
            if not raw:
                continue
            name = raw.decode('utf-8')
            source = ROOT / name
            if source.is_symlink() or not source.is_file():
                continue
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        self.git('init', '--quiet', '--initial-branch=main')
        self.git('add', '-A')
        self.git('commit', '--quiet', '-m', 'Base fixture')
        self.base = self.git('rev-parse', 'HEAD')

    def close(self):
        self.temp.cleanup()

    def git(self, *args):
        result = subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', *args], cwd=self.root,
                                env=self.env, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError('fixture git failed: ' + result.stderr[-800:])
        return result.stdout.strip()

    def commit(self, edits=(), removals=(), renames=()):
        self.git('checkout', '--quiet', '--detach', self.base)
        self.git('reset', '--quiet', '--hard', self.base)
        for old, new in renames:
            (self.root / new).parent.mkdir(parents=True, exist_ok=True)
            self.git('mv', old, new)
        for name in removals:
            self.git('rm', '--quiet', name)
        for name, change in edits:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            text = path.read_text() if path.exists() else ''
            path.write_text(change(text) if callable(change) else change)
        self.git('add', '-A')
        self.git('commit', '--quiet', '--allow-empty', '-m', 'Scenario')
        return self.git('rev-parse', 'HEAD')

    def merge(self, head):
        tree = self.git('rev-parse', head + '^{tree}')
        merge = self.git('commit-tree', tree, '-p', self.base, '-p', head, '-m', 'PR merge fixture')
        self.git('checkout', '--quiet', '--detach', merge)
        return merge


def append(line):
    return lambda text: text + line


class SelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repository()
        cls.cache = {}

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()

    def lanes(self, **change):
        head = self.repo.commit(**change)
        git = select.Git(self.repo.root)
        selector = select.Selector(POLICY, git, self.repo.base, head, cache=self.cache)
        self.last = selector
        reasons = selector.select(git.changes(self.repo.base, head))
        return set(reasons)

    # Boundary crates: the reviewed fast path.
    def test_render_body_edit_selects_linux_boundary(self):
        self.assertEqual(self.lanes(edits=[('crates/render/src/lib.rs', append('\n// render edit\n'))]), BOUNDARY)

    def test_prediction_edit_selects_linux_boundary(self):
        self.assertEqual(self.lanes(edits=[('crates/prediction/src/engine.rs', append('\n// edit\n'))]), BOUNDARY)

    def test_new_render_test_case_selects_linux_boundary(self):
        case = '\n#[test]\nfn boundary_fixture_case() { assert_eq!(1 + 1, 2); }\n'
        self.assertEqual(self.lanes(edits=[('crates/render/tests/round_trip.rs', append(case))]), BOUNDARY)

    def test_render_platform_tripwire_revokes_the_boundary(self):
        for planted in ('\nfn now() -> std::time::Instant { std::time::Instant::now() }\n',
                        '\n#[cfg(target_os = "macos")]\nfn mac() {}\n',
                        '\nuse std::{fs, mem};\n',
                        '\nconst X: &str = env!("HOME");\n',
                        '\nextern "C" { fn abs(x: i32) -> i32; }\n'):
            with self.subTest(planted=planted):
                lanes = self.lanes(edits=[('crates/render/src/sgr.rs', append(planted))])
                self.assertEqual(lanes, DEPENDENT)
                self.assertIn('REVOKED_TRIPWIRE', ' '.join(r for v in self.last.reasons.values() for r in v))

    def test_removing_forbid_unsafe_revokes_the_boundary(self):
        lanes = self.lanes(edits=[('crates/render/src/lib.rs',
                                   lambda text: text.replace('#![forbid(unsafe_code)]\n', '', 1))])
        self.assertEqual(lanes, DEPENDENT)

    def test_render_with_client_code_takes_the_union(self):
        lanes = self.lanes(edits=[('crates/render/src/lib.rs', append('\n// a\n')),
                                  ('cli/src/tty.rs', append('\n// b\n'))])
        self.assertEqual(lanes, DEPENDENT)

    def test_planted_dependency_edges_select_full_and_revoke(self):
        for manifest, line in (('qshd/Cargo.toml', 'render = { path = "../crates/render" }\n'),
                               ('crates/bringup/Cargo.toml', 'render = { path = "../render" }\n')):
            with self.subTest(manifest=manifest):
                def plant(text):
                    return text.replace('[dependencies]\n', '[dependencies]\n' + line, 1)
                lanes = self.lanes(edits=[(manifest, plant), ('crates/render/src/lib.rs', append('\n//\n'))])
                self.assertEqual(lanes, ALL)
                self.assertNotEqual(self.last.boundary('render'), 'BOUNDARY')

    def test_planted_external_include_revokes_the_boundary(self):
        include = '\nconst FIXTURE: &str = include_str!("../../crates/render/src/sgr.rs");\n'
        lanes = self.lanes(edits=[('crates/render/src/sgr.rs', append('\n// edit\n')),
                                  ('cli/src/tty.rs', append(include))])
        self.assertEqual(lanes, DEPENDENT)
        self.assertEqual(self.last.boundary('render'), 'REVOKED_EXTERNAL_INCLUDE')

    # Counterexamples keep dependent coverage.
    def test_time_driven_client_keeps_dependent_lanes(self):
        self.assertEqual(self.lanes(edits=[('crates/client/src/lib.rs', append('\n// edit\n'))]), DEPENDENT)

    def test_session_authority_keeps_dependent_lanes(self):
        self.assertEqual(self.lanes(edits=[('cli/src/sessions.rs', append('\n// edit\n'))]), DEPENDENT)

    def test_auth_inside_daemon_closure_selects_daemon_and_fuzz_lanes(self):
        self.assertEqual(self.lanes(edits=[('crates/sshauth/src/keyfile.rs', append('\n// edit\n'))]),
                         DAEMON | {'fuzz'})

    def test_daemon_control_selects_released_peers(self):
        self.assertEqual(self.lanes(edits=[('qshd/src/control.rs', append('\n// edit\n'))]), DAEMON | {'peers'})

    def test_vendored_terminal_reaches_daemon_and_fuzz(self):
        lanes = self.lanes(edits=[('vendor/vte/src/lib.rs', append('\n// edit\n'))])
        self.assertEqual(lanes, DAEMON | {'fuzz'})

    def test_fuzz_only_change_selects_fuzz(self):
        self.assertEqual(self.lanes(edits=[('fuzz/README.md', append('\nedit\n'))]), {'fuzz'})

    # Documents.
    def test_prose_document_selects_docs(self):
        for name in ('docs/protocol.md', '.github/pull_request_template.md', 'CONTRIBUTING.md'):
            with self.subTest(name=name):
                self.assertEqual(self.lanes(edits=[(name, append('\nedit\n'))]), {'docs'})

    def test_prose_document_with_planted_consumer_selects_full(self):
        lanes = self.lanes(edits=[('docs/protocol.md', append('\nedit\n')),
                                  ('scripts/shell-fixture-acceptance.sh', append('\n# cat docs/protocol.md\n'))])
        self.assertEqual(lanes, ALL)

    def test_reviewed_mention_does_not_exempt_an_include(self):
        include = '\nconst DOC: &str = include_str!("../../docs/qshd-service.md");\n'
        lanes = self.lanes(edits=[('docs/qshd-service.md', append('\nedit\n')), ('qshd/src/serve.rs', append(include))])
        self.assertEqual(lanes, ALL)

    def test_readme_and_changelog_select_docs_and_assembly_controls(self):
        for name in ('README.md', 'CHANGELOG.md'):
            with self.subTest(name=name):
                self.assertEqual(self.lanes(edits=[(name, append('\nedit\n'))]), {'docs', 'check'})

    def test_licenses_select_assembly_controls(self):
        self.assertEqual(self.lanes(edits=[('docs/licenses/openssl.txt', append('\n'))]), {'check'})

    # Scripts and packaging by their consumers.
    def test_darwin_script_selects_its_consumer_lanes(self):
        lanes = self.lanes(edits=[('scripts/qualify-darwin-direct-child.sh', append('\n# edit\n'))])
        self.assertEqual(lanes, {'check', 'macos'})

    def test_native_verifier_script_selects_native(self):
        lanes = self.lanes(edits=[('scripts/check-native-verifier-paths.py', append('\n# edit\n'))])
        self.assertTrue({'check', 'native'} <= lanes and lanes != ALL, lanes)

    def test_peer_acceptance_script_selects_peers(self):
        lanes = self.lanes(edits=[('scripts/released-peer-acceptance.py', append('\n# edit\n'))])
        self.assertTrue({'check', 'peers', 'macos', 'intel-legacy'} <= lanes, lanes)

    def test_packaging_selects_floors(self):
        lanes = self.lanes(edits=[('packaging/selinux/README.md', append('\nedit\n'))])
        self.assertTrue({'check', 'floors'} <= lanes, lanes)

    # Paths and identities.
    def test_rename_classifies_both_paths(self):
        lanes = self.lanes(renames=[('docs/protocol.md', 'docs/protocol-moved.md')])
        self.assertEqual(lanes, ALL)

    def test_deletion_is_classified_by_the_old_path(self):
        self.assertEqual(self.lanes(removals=['crates/render/src/sgr.rs']), BOUNDARY | set())

    def test_move_between_crates_counts_for_both(self):
        lanes = self.lanes(renames=[('crates/render/src/sgr.rs', 'cli/src/sgr_moved.rs')])
        self.assertEqual(lanes, DEPENDENT)

    def test_unknown_and_policy_paths_select_full(self):
        for name in ('notes.txt', 'scripts/ci-selection.json', '.github/workflows/ci.yml', 'Cargo.lock',
                     '.config/nextest.toml', 'crates/render/build.rs'):
            with self.subTest(name=name):
                self.assertEqual(self.lanes(edits=[(name, append('\n'))]), ALL)

    def test_empty_change_is_uncertain(self):
        head = self.repo.commit()
        git = select.Git(self.repo.root)
        selector = select.Selector(POLICY, git, self.repo.base, head, cache=self.cache)
        with self.assertRaises(select.Uncertain):
            selector.select(git.changes(self.repo.base, head))

    def test_every_tracked_path_has_a_rule(self):
        git = select.Git(self.repo.root)
        selector = select.Selector(POLICY, git, self.repo.base, self.repo.base, cache=self.cache)
        unknown = []
        for path in sorted(selector.head_tree.paths()):
            selector.reasons = {}
            selector.classify(path)
            if any('UNKNOWN_PATH' in reason for reasons in selector.reasons.values() for reason in reasons):
                unknown.append(path)
        self.assertEqual(unknown, [])

    def test_boundary_reviewed_dependents_match_the_tree(self):
        git = select.Git(self.repo.root)
        selector = select.Selector(POLICY, git, self.repo.base, self.repo.base, cache=self.cache)
        for crate in POLICY['boundary']['crates']:
            self.assertEqual(selector.boundary(crate), 'BOUNDARY', crate)


class DecisionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo = Repository()

    @classmethod
    def tearDownClass(cls):
        cls.repo.close()

    def env(self, event_name='pull_request', event=None, source=None, ref=None, caller=None, job_ref=None,
            declared=''):
        top = Path(self.repo.temp.name)
        ref = ref or ('refs/pull/7/merge' if event_name == 'pull_request' else 'refs/heads/main')
        self.events = getattr(self, 'events', 0) + 1
        path = top / ('event-' + str(self.events) + '.json')
        path.write_text(json.dumps(event or {}))
        return {'GITHUB_REPOSITORY': 'br0adcast/qsh', 'GITHUB_EVENT_NAME': event_name, 'GITHUB_REF': ref,
                'GITHUB_SHA': source or self.repo.git('rev-parse', 'HEAD'), 'GITHUB_EVENT_PATH': str(path),
                'GITHUB_WORKFLOW_REF': caller or 'br0adcast/qsh/.github/workflows/ci.yml@' + ref,
                'QSH_JOB_WORKFLOW_REF': job_ref or 'br0adcast/qsh/.github/workflows/ci.yml@' + ref,
                'QSH_CALLER_RUNS': declared, 'GITHUB_RUN_ID': '1', 'GITHUB_RUN_ATTEMPT': '1'}

    def pull_request(self, head, merge):
        return {'number': 7, 'pull_request': {'head': {'sha': head}, 'base': {'sha': self.repo.base}}}

    def decide(self, env):
        return select.decide(env, root=self.repo.root, git=select.Git(self.repo.root))[1]

    def test_pull_request_selects_from_the_merge_against_its_first_parent(self):
        head = self.repo.commit(edits=[('crates/render/src/lib.rs', append('\n//\n'))])
        merge = self.repo.merge(head)
        record = self.decide(self.env(event=self.pull_request(head, merge), source=merge))
        self.assertEqual((record['mode'], set(record['lanes'])), ('selected', BOUNDARY))
        self.assertEqual((record['source'], record['api_head'], record['base']), (merge, head, self.repo.base))

    def test_stale_event_base_is_recorded_not_trusted(self):
        head = self.repo.commit(edits=[('docs/protocol.md', append('\nedit\n'))])
        merge = self.repo.merge(head)
        event = {'number': 7, 'pull_request': {'head': {'sha': head}, 'base': {'sha': 'f' * 40}}}
        record = self.decide(self.env(event=event, source=merge))
        self.assertEqual((record['base'], record['event_base'], record['lanes']), (self.repo.base, 'f' * 40, ['docs']))

    def test_invalid_identities_fail_selection(self):
        head = self.repo.commit(edits=[('docs/protocol.md', append('\nedit\n'))])
        merge = self.repo.merge(head)
        good = self.pull_request(head, merge)
        cases = {
            'other head': self.env(event={'number': 7, 'pull_request': {'head': {'sha': self.repo.base}}}, source=merge),
            'checkout': self.env(event=good, source=head),
            'ref': self.env(event=good, source=merge, ref='refs/pull/8/merge'),
            'top-level declaring a caller': self.env(event=good, source=merge, declared='native peers fuzz'),
            'job not in ci.yml': self.env(event=good, source=merge,
                                          job_ref='br0adcast/qsh/.github/workflows/release.yml@refs/pull/7/merge'),
            'repository': dict(self.env(event=good, source=merge), GITHUB_REPOSITORY='someone/qsh'),
            'malformed event': self.env(event={'number': 7, 'pull_request': 'x'}, source=merge),
        }
        for name, env in cases.items():
            with self.subTest(case=name), self.assertRaises(select.InvalidIdentity):
                self.decide(env)

    def test_called_run_requires_the_exact_declaration(self):
        self.repo.git('checkout', '--quiet', '--detach', self.repo.base)
        caller = 'br0adcast/qsh/.github/workflows/release.yml@refs/tags/v9.9.9'
        job_ref = 'br0adcast/qsh/.github/workflows/ci.yml@refs/tags/v9.9.9'
        for declared in ('', 'native peers', 'native peers fuzz extra'):
            with self.subTest(declared=declared), self.assertRaises(select.InvalidIdentity):
                self.decide(self.env('push', ref='refs/tags/v9.9.9', caller=caller, job_ref=job_ref, declared=declared))
        record = self.decide(self.env('push', ref='refs/tags/v9.9.9', caller=caller, job_ref=job_ref,
                                      declared='native peers fuzz'))
        self.assertEqual(record['mode'], 'called')
        self.assertEqual(set(record['lanes']), {'check', 'container', 'docs', 'macos'})
        self.assertEqual(set(record['delegated']), ALL - {'check', 'container', 'docs', 'macos'})

    def test_main_push_runs_linux_smoke_and_defers_the_rest(self):
        head = self.repo.commit(edits=[('crates/sshauth/src/keyfile.rs', append('\n//\n'))])
        self.repo.git('checkout', '--quiet', '--detach', head)
        record = self.decide(self.env('push', event={'before': self.repo.base, 'after': head,
                                                     'ref': 'refs/heads/main'}, source=head))
        self.assertEqual((record['mode'], record['lanes']), ('smoke', ['check', 'container']))
        self.assertEqual(set(record['deferred']), ALL - {'check', 'container'})

    def test_docs_only_main_push_runs_docs(self):
        head = self.repo.commit(edits=[('docs/protocol.md', append('\nedit\n'))])
        self.repo.git('checkout', '--quiet', '--detach', head)
        record = self.decide(self.env('push', event={'before': self.repo.base, 'after': head}, source=head))
        self.assertEqual(record['lanes'], ['docs'])

    def test_unknown_push_base_runs_the_whole_linux_smoke(self):
        head = self.repo.commit(edits=[('docs/protocol.md', append('\nedit\n'))])
        self.repo.git('checkout', '--quiet', '--detach', head)
        record = self.decide(self.env('push', event={'before': '0' * 40, 'after': head}, source=head))
        self.assertEqual(record['lanes'], ['check', 'container', 'docs'])

    def test_dispatch_selects_every_lane(self):
        self.repo.git('checkout', '--quiet', '--detach', self.repo.base)
        record = self.decide(self.env('workflow_dispatch', ref='refs/heads/feature'))
        self.assertEqual((record['mode'], set(record['lanes'])), ('full', ALL))

    def test_unreadable_head_manifest_selects_every_lane(self):
        head = self.repo.commit(edits=[('crates/render/Cargo.toml', append('\n[broken\n'))])
        merge = self.repo.merge(head)
        record = self.decide(self.env(event=self.pull_request(head, merge), source=merge))
        self.assertEqual(set(record['lanes']), ALL)

    def test_outputs_are_canonical(self):
        values = select.outputs(POLICY, {'lanes': ['native', 'check', 'floors', 'peers'], 'x': 1})
        self.assertEqual(values['lanes'], '["check","floors","native","peers"]')
        self.assertEqual(values['native_lanes'], '["floors","portable"]')
        self.assertEqual(values['calls'], '["native-crypto","released-peer-acceptance"]')
        empty = select.outputs(POLICY, {'lanes': ['docs']})
        self.assertEqual((empty['native_lanes'], empty['calls']), ('[]', '[]'))
        with self.assertRaises(ValueError):
            select.outputs(POLICY, {'lanes': ['Check']})


class TripwireTests(unittest.TestCase):
    def test_allowed_and_refused_sources(self):
        allowed = set(POLICY['boundary']['std_modules'])
        self.assertFalse(select.tripwire('use std::mem;\n#[cfg(test)]\nmod t {}\n#[cfg(not(test))]\nfn f() {}\n',
                                         allowed))
        self.assertFalse(select.tripwire('#![forbid(unsafe_code)]\n// std::fs in a comment\n', allowed))
        for source in ('use std::io::Write;', 'use std::{mem, process};', 'let t = SystemTime::now();',
                       '#[cfg_attr(test, derive(Debug))]', '#[cfg(unix)]', 'if cfg!(windows) {}',
                       'unsafe { }', 'core::arch::asm!("nop");', 'include_bytes!("x")',
                       'option_env!("X")', 'file!()', '#[link(name = "c")]'):
            with self.subTest(source=source):
                self.assertTrue(select.tripwire(source, allowed))


if __name__ == '__main__':
    unittest.main()
