"""Pure controls for the actual inline container receipt; no native commands run."""
from contextlib import redirect_stderr, redirect_stdout
import ast
import copy
import hashlib
import io
import json
import os
import re
import shutil
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

WORKFLOW = Path(__file__).resolve().parents[2] / '.github/workflows/ci.yml'
# Frozen exact execution contract from actual main90031dd; never read from the workflow under test.
M_POLICY = '          run_suite lib qshd --ignored 85 \\\n            --require helper::server::tests::host_policy::host529_policy_bad_bounds_wrong_nonce_and_shared_child_cap_refuse_before_fork \\\n            --require helper::server::tests::host_policy::host529_policy_cancelled_consumer_and_deadline_retain_real_child_until_wait \\\n            --require helper::server::tests::host_policy::host529_policy_current_account_and_root_restrictions_are_rechecked \\\n            --require helper::server::tests::host_policy::host529_policy_forged_signature_and_wrong_key_refuse \\\n            --require helper::server::tests::host_policy::host529_policy_key_revocation_between_issue_and_consume_is_current \\\n            --require helper::server::tests::host_policy::host529_policy_late_real_verdict_after_cancel_or_revocation_cannot_grant \\\n            --require helper::server::tests::host_policy::host529_policy_nonce_cannot_be_redirected_to_legacy_login \\\n            --require helper::server::tests::host_policy::host529_policy_nonce_replay_expiry_shared_capacity_and_recovery \\\n            --require helper::server::tests::host_policy::host529_policy_real_auth_and_two_policy_checks_do_not_create_logins \\\n            --require helper::server::tests::host_policy::host529_policy_verdict_before_reap_lost_consumer_stays_charged \\\n            --require process_scope::observation::tests::native_observer_retains_unrelated_process_in_another_session \\\n            --require control::peer_tests::control_peer_root_client_rejects_foreign_server \\\n            --require control::peer_tests::control_peer_foreign_client_rejects_root_server \\\n            --require transport_daemon::peer_tests::control_peer_root_server_rejects_foreign_client \\\n            --require transport_daemon::peer_tests::control_peer_foreign_server_rejects_root_client \\\n            --require serve::tests::the_system_flag_is_accepted_and_moves_the_host_key \\\n            --require helper::monitor::tests::pam_access_matches_ipv4_source_cidrs_with_explicit_fallbacks \\\n            --require helper::monitor::tests::pam_access_matches_ipv6_source_cidrs_with_explicit_fallbacks \\\n            --require log::tests::path_diagnostics_relative_preparation_rotates_after_detach_cwd_change \\\n            --require log::tests::path_diagnostics_foreground_failure_warns_once_and_survives_in_status \\\n            --require helper::server::tests::worker_parent::worker508_pre_stage_stop_is_retained_without_publication \\\n            --require helper::server::tests::worker_parent::worker508_init_failure_before_stage_acceptance_settles \\\n            --require helper::server::tests::worker_parent::worker508_post_stage_unread_stop_settles_failed \\\n            --require helper::server::tests::worker_parent::worker508_terminal_before_pending_send_suppresses_stop \\\n            drop_worker_privileges_refuses_without_root \\\n            own_capability_sets_parses_and_reports_none_for_an_ordinary_process \\\n            an_undeliverable_signal_is_reported_to_the_helper \\\n            a_rotation_that_cannot_rename_is_reported_and_bounds_file_growth'
# Reviewed union: immutable actual main90031dd policy plus the sole root launch requirement.
ROOT_LAUNCH = 'session_owner::inherited_launch::native_tests::launch529_root_and_foreign_entry_refuse_before_setup'
BASELINE_POLICY = M_POLICY.replace('--ignored 85', '--ignored 102').replace(
    '            drop_worker_privileges_refuses_without_root',
    '            --require ' + ROOT_LAUNCH + ' ' + chr(92) + '\n' +
    '            drop_worker_privileges_refuses_without_root')
PORTABLE_LAUNCH = ('session_owner::inherited_launch::tests::launch529_cancel_before_and_after_start_wins_late_admission', 'session_owner::inherited_launch::tests::launch529_deadline_is_absolute_across_partial_setup', 'session_owner::inherited_launch::tests::launch529_foreign_handle_cannot_cancel_or_settle', 'session_owner::inherited_launch::tests::launch529_frontend_transfer_cannot_restore_host_or_owner', 'session_owner::inherited_launch::tests::launch529_handle_drop_keeps_physical_custody', 'session_owner::inherited_launch::tests::launch529_known_extra_local_copy_is_pending_not_unknown', 'session_owner::inherited_launch::tests::launch529_known_prefix_deadline_does_not_refresh_final_bytes', 'session_owner::inherited_launch::tests::launch529_lost_wait_and_uncertain_close_never_refund', 'session_owner::inherited_launch::tests::launch529_poisoned_registry_keeps_exact_capsule_and_debt', 'session_owner::inherited_launch::tests::launch529_prefix_stall_and_dribble_retire_without_reply', 'session_owner::inherited_launch::tests::launch529_private_marker_routing_is_exact', 'session_owner::inherited_launch::tests::launch529_record_exact_shape_and_binding', 'session_owner::inherited_launch::tests::launch529_record_rejects_every_unsupported_field', 'session_owner::inherited_launch::tests::launch529_registry_drop_quarantines_unsettled_debt', 'session_owner::inherited_launch::tests::launch529_setup_sockets_refuse_stall_extra_cancel_and_invalid_types', 'session_owner::inherited_launch::tests::launch529_transferred_end_stays_charged', 'session_owner::inherited_launch::tests::launch529_wait_and_eof_are_independent_receipts')
NATIVE_LAUNCH = ('session_owner::inherited_launch::native_tests::launch529_eof_wait_and_extra_reference_order', 'session_owner::inherited_launch::native_tests::launch529_exec_admits_only_the_designated_frontend', 'session_owner::inherited_launch::native_tests::launch529_exec_failure_and_cancel_keep_exact_custody', 'session_owner::inherited_launch::native_tests::launch529_foreign_or_invalid_inheritance_refuses')

BASELINE_DOCKER = '            if docker run --rm --init --cap-add=SYS_PTRACE "${network_caps[@]}" "${fixture_env[@]}" \\\n              -e QSHD_TEST_DISPOSABLE_HOST=1 \\\n              -v "$GITHUB_WORKSPACE:$GITHUB_WORKSPACE:ro" -w "$GITHUB_WORKSPACE" \\\n              ubuntu:24.04 sh -c \'exec "$@" 2>&1\' sh "$bin" --test-threads=1 --nocapture \\\n              2>&1 | tee "$logs/$name.log"'
BASELINE_BUILD = '          cargo test --workspace --features qshd/system --locked --no-run \\\n            --message-format=json > "$RUNNER_TEMP/build.json"'

CANARY = '/private/RECEIPT_CANARY/hidden-command-output'
BASE = 'a' * 40
HEAD = 'b' * 40
MERGE = 'c' * 40
TREE = 'd' * 40
WORKFLOW_SHA = 'e' * 40


def helper_source():
    workflow = WORKFLOW.read_text()
    marker = "<<'PYRECEIPT'\n"
    if marker not in workflow:
        raise ValueError('receipt helper is missing')
    return textwrap.dedent(workflow.split(marker, 1)[1].split('\n          PYRECEIPT', 1)[0])


class Fixture:
    def __init__(self, directory):
        self.root = Path(directory) / 'workspace'
        self.runtime = Path(directory) / 'runtime'
        self.root.mkdir()
        (self.runtime / 'tier').mkdir(parents=True)
        self.tracked = ['Cargo.lock', '.github/workflows/ci.yml',
                        'qshd/Cargo.toml', 'qshd/src/lib.rs', 'tracked.txt']
        for name in self.tracked:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('fixture ' + name)
        self.binary = self.root / 'target/debug/deps/qshd-fixture'
        self.binary.parent.mkdir(parents=True)
        self.binary.write_bytes(b'never execute this placeholder')
        self.binary.chmod(0o700)
        self.selected = self.binary
        self.package = {'name': 'qshd', 'id': 'fixture-qshd'}
        self.metadata = {'packages': [self.package], 'workspace_members': ['fixture-qshd']}
        self.artifact = {'reason': 'compiler-artifact', 'package_id': 'fixture-qshd',
                         'profile': {'test': True, 'opt_level': '2', 'debuginfo': 1},
                         'target': {'name': 'qshd', 'kind': ['lib'],
                                    'src_path': str(self.root / 'qshd/src/lib.rs')},
                         'manifest_path': str(self.root / 'qshd/Cargo.toml'),
                         'features': ['system'], 'executable': str(self.binary)}
        self.artifacts = [self.artifact]
        self.event = {'pull_request': {'base': {'sha': BASE}, 'head': {'sha': HEAD}}}
        self.event_path = self.runtime / 'event.json'
        self.env = {'GITHUB_WORKSPACE': str(self.root), 'RUNNER_TEMP': str(self.runtime),
                    'GITHUB_EVENT_PATH': str(self.event_path), 'GITHUB_EVENT_NAME': 'pull_request',
                    'GITHUB_SHA': MERGE, 'GITHUB_WORKFLOW_SHA': WORKFLOW_SHA,
                    'GITHUB_RUN_ID': '123', 'GITHUB_RUN_ATTEMPT': '1', 'GITHUB_JOB': 'container'}
        self.parents = [BASE, HEAD]
        self.actual_head = MERGE
        self.tree = TREE
        self.compiler = 'rustc 1.98.1 (48a229cea 2026-09-01)\nrelease: 1.98.1\n'
        self.image = [{'Id': 'sha256:' + '1' * 64,
                       'RepoDigests': ['ubuntu@sha256:' + '2' * 64]}]
        self.policy = ['--ignored', '102', '--require', 'fixture_required', 'ordinary_only']
        self.calls = []
        self.failure = None
        self.sync()

    @property
    def prior(self):
        return self.runtime / 'tier/qshd-library-before.json'

    def sync(self):
        (self.runtime / 'workspace.json').write_text(json.dumps(self.metadata))
        (self.runtime / 'build.json').write_text('\n'.join(map(json.dumps, self.artifacts)))
        self.event_path.write_text(json.dumps(self.event))

    def output(self, argv, **kwargs):
        self.calls.append(('output', argv, kwargs))
        if self.failure == 'output':
            raise subprocess.CalledProcessError(1, [CANARY], output=CANARY, stderr=CANARY)
        if argv[:3] == ['git', '-C', str(self.root)]:
            args = argv[3:]
            if args == ['rev-parse', 'HEAD']:
                return self.actual_head
            if args == ['rev-parse', 'HEAD^{tree}']:
                return self.tree
            if args == ['cat-file', '-p', 'HEAD']:
                return ('tree ' + self.tree + '\n' +
                        ''.join('parent ' + sha + '\n' for sha in self.parents) +
                        'author ' + CANARY + '\ncommitter ' + CANARY + '\n\n' +
                        CANARY + '\nparent ' + 'f' * 40 + '\n')
            if args == ['ls-files', '-z']:
                return '\0'.join(self.tracked) + '\0'
        if argv == ['rustc', '-vV']:
            return self.compiler
        if argv == ['docker', 'image', 'inspect', 'ubuntu:24.04']:
            return json.dumps(self.image)
        raise AssertionError('unexpected mocked command')

    def run(self, argv, **kwargs):
        self.calls.append(('run', argv, kwargs))
        if self.failure == 'run':
            raise subprocess.CalledProcessError(1, [CANARY], output=CANARY, stderr=CANARY)
        if argv != ['git', '-C', str(self.root), 'diff', 'HEAD', '--quiet']:
            raise AssertionError('unexpected mocked run')
        return subprocess.CompletedProcess(argv, 0)

    def invoke(self, stage='before', optimize=0):
        stdout, stderr = io.StringIO(), io.StringIO()
        code = compile(helper_source(), '<inline-receipt>', 'exec', optimize=optimize)
        status = 0
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(sys, 'argv', ['receipt', stage, str(self.selected), *self.policy]), \
                mock.patch('subprocess.check_output', side_effect=self.output), \
                mock.patch('subprocess.run', side_effect=self.run), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                exec(code, {'__name__': '__main__'})
            except SystemExit as error:
                status = error.code
        return status, stdout.getvalue(), stderr.getvalue()


class LibraryReceiptTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory(prefix='qshd-receipt-pure-')
        self.addCleanup(temp.cleanup)
        return Fixture(temp.name)

    def success(self, fixture, stage='before'):
        status, out, err = fixture.invoke(stage)
        self.assertEqual((status, err), (0, ''))
        lines = out.splitlines()
        self.assertEqual(len(lines), 1)
        self.assertTrue(lines[0].startswith('qshd_library_receipt '))
        self.assertNotIn(str(fixture.root), out)
        self.assertNotIn(CANARY, out)
        return json.loads(lines[0].split(' ', 1)[1])

    def refused(self, fixture, stage='before', optimize=0):
        status, out, err = fixture.invoke(stage, optimize)
        self.assertEqual(status, 1)
        self.assertEqual(out, '')
        self.assertRegex(err, r'^qshd_library_receipt_error [a-z0-9-]+\n$')
        for private in ('Traceback', CANARY, str(fixture.root), str(fixture.runtime)):
            self.assertNotIn(private, out + err)

    def test_current_artifact_has_sanitized_stable_before_after_receipts(self):
        fx = self.fixture()
        before = self.success(fx)
        retained = fx.prior.read_bytes()
        after = self.success(fx, 'after')
        self.assertEqual({k: v for k, v in before.items() if k != 'stage'},
                         {k: v for k, v in after.items() if k != 'stage'})
        self.assertEqual(fx.prior.read_bytes(), retained)
        self.assertEqual(before['features'], ['system'])
        self.assertEqual(before['profile'], fx.artifact['profile'])
        self.assertEqual(before['source_parents'], [BASE, HEAD])
        self.assertEqual(before['synthetic_merge'], MERGE)
        self.assertEqual(before['workflow_commit'], WORKFLOW_SHA)
        self.assertEqual(before['no_skip_argv'], fx.policy)
        self.assertEqual(before['test_argv'], ['target/debug/deps/qshd-fixture',
                                               '--test-threads=1', '--nocapture'])
        self.assertEqual(before['executable_sha256'], hashlib.sha256(fx.binary.read_bytes()).hexdigest())
        self.assertEqual(before['lock_sha256'], hashlib.sha256((fx.root / 'Cargo.lock').read_bytes()).hexdigest())
        self.assertEqual(before['workflow_sha256'], hashlib.sha256((fx.root / '.github/workflows/ci.yml').read_bytes()).hexdigest())
        sources = {name: hashlib.sha256((fx.root / name).read_bytes()).hexdigest() for name in fx.tracked}
        serialized = json.dumps(sources, sort_keys=True, separators=(',', ':')).encode()
        self.assertEqual(before['source_manifest_sha256'], hashlib.sha256(serialized).hexdigest())
        fx = self.fixture()
        fx.env['GITHUB_EVENT_NAME'] = 'push'
        receipt = self.success(fx)
        self.assertIsNone(receipt['pr_head'])
        self.assertIsNone(receipt['pr_base'])
        self.assertIsNone(receipt['synthetic_merge'])

    def test_artifact_selection_rejects_missing_duplicate_and_mismatched_inputs(self):
        cases = ['no-package', 'no-member', 'duplicate-package', 'no-record', 'duplicate-record',
                 'package', 'target', 'kind', 'profile', 'profile-number', 'absent-executable',
                 'null-executable', 'missing-executable',
                 'nonexecutable', 'selected', 'outside', 'manifest', 'source', 'no-features', 'extra-features']
        for case in cases:
            with self.subTest(case=case):
                fx = self.fixture()
                if case == 'no-package': fx.metadata['packages'] = []
                elif case == 'no-member': fx.metadata['workspace_members'] = []
                elif case == 'duplicate-package': fx.metadata['packages'].append(copy.deepcopy(fx.package))
                elif case == 'no-record': fx.artifacts = []
                elif case == 'duplicate-record': fx.artifacts.append(copy.deepcopy(fx.artifact))
                elif case == 'package': fx.artifact['package_id'] = 'other'
                elif case == 'target': fx.artifact['target']['name'] = 'other'
                elif case == 'kind': fx.artifact['target']['kind'] = ['bin']
                elif case == 'profile': fx.artifact['profile']['test'] = False
                elif case == 'profile-number': fx.artifact['profile']['test'] = 1
                elif case == 'absent-executable': fx.artifact.pop('executable')
                elif case == 'null-executable': fx.artifact['executable'] = None
                elif case == 'missing-executable': fx.binary.unlink()
                elif case == 'nonexecutable': fx.binary.chmod(0o600)
                elif case == 'selected': fx.selected = fx.root / 'different'
                elif case == 'outside':
                    outside = fx.runtime / 'outside'
                    outside.write_bytes(b'outside')
                    outside.chmod(0o700)
                    fx.selected = outside
                    fx.artifact['executable'] = str(outside)
                elif case == 'manifest': fx.artifact['manifest_path'] = str(fx.root / 'wrong.toml')
                elif case == 'source': fx.artifact['target']['src_path'] = str(fx.root / 'wrong.rs')
                elif case == 'no-features': fx.artifact['features'] = []
                elif case == 'extra-features': fx.artifact['features'].append('test-build-labels')
                fx.sync()
                self.refused(fx)
        fx = self.fixture()
        unrelated = copy.deepcopy(fx.artifact)
        unrelated['package_id'] = 'unrelated'
        fx.artifacts.append(unrelated)
        fx.sync()
        self.success(fx)

    def test_after_rejects_changed_identity_or_missing_before(self):
        cases = ['binary', 'source', 'image-id', 'image-digest', 'profile', 'policy', 'run',
                 'attempt', 'job', 'workflow', 'compiler', 'path', 'pr', 'event', 'tree', 'commit',
                 'missing-before', 'malformed-before', 'wrong-prior-stage']
        for case in cases:
            with self.subTest(case=case):
                fx = self.fixture()
                self.success(fx)
                prior = fx.prior.read_bytes()
                if case == 'binary': fx.binary.write_bytes(b'changed binary')
                elif case == 'source': (fx.root / 'tracked.txt').write_text('changed source')
                elif case == 'image-id': fx.image[0]['Id'] = 'sha256:' + '3' * 64
                elif case == 'image-digest': fx.image[0]['RepoDigests'] = ['ubuntu@sha256:' + '4' * 64]
                elif case == 'profile': fx.artifact['profile']['opt_level'] = '3'
                elif case == 'policy': fx.policy.append('changed-policy')
                elif case == 'run': fx.env['GITHUB_RUN_ID'] = '124'
                elif case == 'attempt': fx.env['GITHUB_RUN_ATTEMPT'] = '2'
                elif case == 'job': fx.env['GITHUB_JOB'] = 'another-job'
                elif case == 'workflow': fx.env['GITHUB_WORKFLOW_SHA'] = 'f' * 40
                elif case == 'compiler': fx.compiler += 'host: changed\n'
                elif case == 'path':
                    alternate = fx.binary.with_name('qshd-other')
                    alternate.write_bytes(fx.binary.read_bytes())
                    alternate.chmod(0o700)
                    fx.artifact['executable'] = str(alternate)
                    fx.selected = alternate
                elif case == 'pr':
                    fx.event['pull_request']['head']['sha'] = 'f' * 40
                    fx.parents = [BASE, 'f' * 40]
                elif case == 'event': fx.env['GITHUB_EVENT_NAME'] = 'push'
                elif case == 'tree': fx.tree = 'f' * 40
                elif case == 'commit':
                    fx.actual_head = 'f' * 40
                    fx.env['GITHUB_SHA'] = fx.actual_head
                elif case == 'missing-before': fx.prior.unlink()
                elif case == 'malformed-before': fx.prior.write_text(CANARY)
                elif case == 'wrong-prior-stage':
                    changed = json.loads(prior)
                    changed['stage'] = 'after'
                    fx.prior.write_text(json.dumps(changed))
                fx.sync()
                self.refused(fx, 'after')
                if case not in ('missing-before', 'malformed-before', 'wrong-prior-stage'):
                    self.assertEqual(fx.prior.read_bytes(), prior)
        fx = self.fixture()
        self.refused(fx, 'invalid-stage')
        self.assertFalse(fx.prior.exists())
        self.assertFalse((fx.runtime / 'tier/qshd-source-manifest.json').exists())

    def test_errors_do_not_leak_paths_or_command_output(self):
        for failure in ('output', 'run', 'json', 'missing-file', 'hash', 'path',
                        'image-empty', 'image-digests'):
            with self.subTest(failure=failure):
                fx = self.fixture()
                if failure in ('output', 'run'): fx.failure = failure
                elif failure == 'json': fx.event_path.write_text(CANARY)
                elif failure == 'missing-file': fx.event_path.unlink()
                elif failure == 'path': fx.selected = CANARY + '\0'
                elif failure == 'image-empty': fx.image = []
                elif failure == 'image-digests': fx.image[0]['RepoDigests'] = []
                if failure == 'hash':
                    with mock.patch.object(Path, 'read_bytes', side_effect=OSError(CANARY)):
                        self.refused(fx)
                else: self.refused(fx)
        fx = self.fixture()
        self.success(fx)
        for kind, _argv, kwargs in fx.calls:
            self.assertEqual(kwargs.get('stderr'), subprocess.PIPE)
            if kind == 'run': self.assertEqual(kwargs.get('stdout'), subprocess.PIPE)
        fx = self.fixture()
        fx.artifact['features'] = []
        fx.sync()
        self.refused(fx, optimize=2)
        self.assertFalse(any(isinstance(node, ast.Assert) for node in ast.walk(ast.parse(helper_source()))))

    def test_pr_receipt_requires_exact_merge_provenance(self):
        fx = self.fixture()
        receipt = self.success(fx)
        self.assertEqual(receipt['source_parents'], [BASE, HEAD])
        self.assertNotIn(CANARY, json.dumps(receipt))
        self.assertTrue(any(argv[-3:] == ['cat-file', '-p', 'HEAD'] for _, argv, _ in fx.calls))
        self.assertFalse(any('%P' in str(argv) or 'show' in argv for _, argv, _ in fx.calls))
        for case in ('workflow', 'base', 'head', 'head-mismatch', 'wrong-parents', 'reordered',
                     'run', 'attempt', 'job', 'event'):
            with self.subTest(case=case):
                fx = self.fixture()
                if case == 'workflow': fx.env.pop('GITHUB_WORKFLOW_SHA')
                elif case in ('base', 'head'): fx.event['pull_request'][case].pop('sha')
                elif case == 'head-mismatch': fx.actual_head = 'f' * 40
                elif case == 'wrong-parents': fx.parents = [BASE]
                elif case == 'reordered': fx.parents = [HEAD, BASE]
                elif case == 'run': fx.env['GITHUB_RUN_ID'] = ''
                elif case == 'attempt': fx.env.pop('GITHUB_RUN_ATTEMPT')
                elif case == 'job': fx.env['GITHUB_JOB'] = ''
                elif case == 'event': fx.env.pop('GITHUB_EVENT_NAME')
                fx.sync()
                self.refused(fx)

    def test_workflow_preserves_library_execution_and_policy(self):
        workflow = WORKFLOW.read_text()
        step = workflow.split('      - name: Run the root-gated suites, one binary per fresh container\n', 1)[1]
        self.assertIn(BASELINE_DOCKER, step)
        self.assertIn(BASELINE_POLICY, step)
        self.assertEqual(BASELINE_POLICY.count('--require '), 25)
        self.assertIn(BASELINE_BUILD, workflow)
        before = step.index('qshd_library_receipt before "$bin" "$@"')
        run = step.index(BASELINE_DOCKER)
        after = step.index('qshd_library_receipt after "$bin" "$@" || bad=1')
        no_skip = step.index('scripts/no-silent-skips.sh "$logs/$name.log" "$@" || bad=1')
        self.assertLess(before, run)
        self.assertLess(run, after)
        self.assertLess(after, no_skip)
        self.assertIn('bad=1\n            fi\n            if [ "$kind/$name" = lib/qshd ]; then', step)
        self.assertIn('failures=$((failures + bad))', step)
        self.assertIn('[ "$failures" -eq 0 ] || {', step)
        self.assertIn('failures=$((failures + 1))\n                echo "::endgroup::"\n                return', step)

    def test_launch_policy_is_exact_and_rejects_stale_cardinality(self):
        self.assertEqual(M_POLICY.count('--require '), 24)
        self.assertEqual(BASELINE_POLICY.count('--require '), 25)
        self.assertIn('--require ' + ROOT_LAUNCH, BASELINE_POLICY)
        for count in ('85', '101', '103'):
            fx = self.fixture()
            fx.policy[1] = count
            self.refused(fx)

    def test_launch_ordinary_selectors_are_complete_and_never_select_the_body(self):
        workflow = WORKFLOW.read_text()
        blocks = workflow.split('# launch529 BEGIN controlled ordinary\n')[1:]
        self.assertEqual(len(blocks), 2)
        for text in blocks:
            block = text.split('# launch529 END controlled ordinary', 1)[0]
            self.assertIn('test "${#portable_names[@]}" -eq 17', block)
            self.assertIn('test "${#native_names[@]}" -eq 4', block)
            for name in PORTABLE_LAUNCH + NATIVE_LAUNCH:
                self.assertEqual(block.count('            ' + name + '\n'), 1, name)
            self.assertNotIn(ROOT_LAUNCH, block)
            self.assertNotIn('launch529_isolated_child_body', block)
            self.assertIn('--check-exact-libtest', block)
            self.assertIn('--require-exact-test "$name"', block)
            self.assertIn('launch_artifacts before', block)
            self.assertIn('launch_artifacts after', block)
            self.assertIn('"$harness" --include-ignored --exact "$name"', block)
            self.assertIn('--show-output --test-threads=1 --color=never', block)
    def test_launch_selector_mutations_are_rejected(self):
        original = WORKFLOW.read_text()
        cases = [original.replace(PORTABLE_LAUNCH[0], 'removed_portable_case', 1),
                 original.replace(NATIVE_LAUNCH[0], 'removed_native_case', 1),
                 original.replace('test "${#portable_names[@]}" -eq 17', 'test "${#portable_names[@]}" -eq 16', 1),
                 original.replace('test "${#native_names[@]}" -eq 4', 'test "${#native_names[@]}" -eq 3', 1),
                 original.replace(NATIVE_LAUNCH[0], 'session_owner::inherited_launch::native_tests::launch529_isolated_child_body', 1)]
        for mutated in cases:
            with mock.patch.object(Path, 'read_text', return_value=mutated):
                with self.assertRaises(AssertionError):
                    self.test_launch_ordinary_selectors_are_complete_and_never_select_the_body()


class LaunchArtifactReceiptTests(unittest.TestCase):
    def fixture(self):
        directory = tempfile.TemporaryDirectory(prefix='launch-receipt-pure-')
        self.addCleanup(directory.cleanup)
        fx = Fixture(directory.name)
        fx.tracked.append('qshd/src/main.rs')
        (fx.root / 'qshd/src/main.rs').write_text('fixture main')
        fx.daemon = fx.root / 'target/debug/qshd-fixture'
        fx.daemon.write_bytes(b'never execute daemon placeholder')
        fx.daemon.chmod(0o700)
        fx.bins = [copy.deepcopy(fx.artifact)]
        fx.bins[0].update(executable=str(fx.daemon), profile={'test': False, 'opt_level': '1'},
                          target={'name': 'qshd', 'kind': ['bin'], 'src_path': str(fx.root / 'qshd/src/main.rs')})
        fx.bin_json = fx.runtime / 'daemon.jsonl'
        fx.prefix = fx.runtime / 'launch'
        return fx

    def invoke(self, fx, stage='before', optimize=0):
        workflow = WORKFLOW.read_text()
        bodies = workflow.split("<<'PYLAUNCH'\n")[1:]
        self.assertEqual(len(bodies), 3)
        sources = [textwrap.dedent(body.split('\n          PYLAUNCH', 1)[0]) for body in bodies]
        self.assertEqual(sources, [sources[0]] * 3)
        fx.sync()
        fx.bin_json.write_text('\n'.join(map(json.dumps, fx.bins)))
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ['launch', stage, str(fx.runtime / 'workspace.json'), str(fx.bin_json),
                str(fx.runtime / 'build.json'), str(fx.prefix), 'system']
        status = 0
        with mock.patch.dict(os.environ, fx.env, clear=True), mock.patch.object(sys, 'argv', args), \
                mock.patch('subprocess.check_output', side_effect=fx.output), \
                mock.patch('subprocess.run', side_effect=fx.run), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                exec(compile(sources[0], '<launch-receipt>', 'exec', optimize=optimize), {'__name__': '__main__'})
            except SystemExit as error:
                status = error.code
        return status, stdout.getvalue(), stderr.getvalue()

    def refused(self, fx, stage='before', optimize=0):
        status, out, err = self.invoke(fx, stage, optimize)
        self.assertEqual((status, out), (1, ''))
        self.assertRegex(err, r'^launch529_artifact_error [a-z0-9-]+\n$')
        for private in (CANARY, str(fx.root), str(fx.runtime), 'Traceback'):
            self.assertNotIn(private, err)

    def test_exact_current_pair_is_immutable_and_sanitized(self):
        fx = self.fixture()
        status, out, err = self.invoke(fx)
        self.assertEqual((status, err), (0, ''))
        self.assertEqual(len(out.splitlines()), 1)
        receipt = json.loads(out.split(' ', 1)[1])
        self.assertEqual(set(receipt['artifacts']), {'bin', 'lib'})
        self.assertEqual(receipt['features'], ['system'])
        self.assertEqual(receipt['artifacts']['bin']['sha256'], hashlib.sha256(fx.daemon.read_bytes()).hexdigest())
        self.assertEqual(receipt['artifacts']['lib']['sha256'], hashlib.sha256(fx.binary.read_bytes()).hexdigest())
        self.assertEqual(fx.prefix.with_suffix('.paths').read_text().splitlines(), [str(fx.daemon), str(fx.binary)])
        saved = fx.prefix.with_suffix('.json').read_bytes()
        status, after, err = self.invoke(fx, 'after')
        self.assertEqual((status, err), (0, ''))
        self.assertEqual(saved, fx.prefix.with_suffix('.json').read_bytes())
        self.assertNotIn(str(fx.root), out + after)
        self.assertNotIn(CANARY, out + after)

    def test_wrong_artifact_or_compiler_fails_without_assert_dependency(self):
        for case in ('missing', 'duplicate', 'test-daemon', 'foreign-source', 'foreign-manifest', 'features', 'compiler', 'output-error'):
            for optimize in (0, 2):
                with self.subTest(case=case, optimize=optimize):
                    fx = self.fixture()
                    if case == 'missing': fx.bins.clear()
                    elif case == 'duplicate': fx.bins *= 2
                    elif case == 'test-daemon': fx.bins[0]['profile']['test'] = True
                    elif case == 'foreign-source': fx.bins[0]['target']['src_path'] = CANARY
                    elif case == 'foreign-manifest': fx.bins[0]['manifest_path'] = CANARY
                    elif case == 'features': fx.bins[0]['features'] = []
                    elif case == 'compiler': fx.compiler = 'release: 1.99.1\n'
                    elif case == 'output-error': fx.failure = 'output'
                    self.refused(fx, optimize=optimize)

    def test_after_requires_unchanged_actual_source_and_both_executables(self):
        for case in ('missing-before', 'daemon', 'harness', 'lock', 'workflow', 'profile', 'source'):
            with self.subTest(case=case):
                fx = self.fixture()
                if case != 'missing-before': self.assertEqual(self.invoke(fx)[0], 0)
                if case == 'daemon': fx.daemon.write_bytes(b'changed')
                elif case == 'harness': fx.binary.write_bytes(b'changed')
                elif case == 'lock': (fx.root / 'Cargo.lock').write_text('changed')
                elif case == 'workflow': (fx.root / '.github/workflows/ci.yml').write_text('changed')
                elif case == 'source': (fx.root / 'qshd/src/main.rs').write_text('changed')
                elif case == 'profile': fx.bins[0]['profile']['opt_level'] = '2'
                self.refused(fx, 'after')

# These extracted-shell controls use synthetic executable/data fixtures only.
# A passing control is not native execution or a Cargo/compiler qualification.
_DRIVER_TOOL = r'''#!__PYTHON__
import json, os, pathlib, subprocess, sys
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
root = pathlib.Path(os.environ['LAUNCH_CONTROL_ROOT'])
fault = os.environ.get('LAUNCH_CONTROL_FAULT', '')
with pathlib.Path(os.environ['LAUNCH_CONTROL_LEDGER']).open('a') as out:
    out.write(json.dumps({'tool': name, 'argv': args, 'daemon_name': pathlib.Path(os.environ.get('QSH_TEST_QSHD', '')).name}) + '\n')
if name == 'cargo':
    if args[:1] == ['metadata']:
        if fault == 'metadata': sys.exit(73)
        print(json.dumps({'packages': [{'name':'qshd','id':'synthetic-qshd'}], 'workspace_members':['synthetic-qshd']}))
    else:
        kind = 'bin' if args[:1] == ['build'] else 'lib'
        if (kind == 'bin' and fault == 'daemon-build') or (kind == 'lib' and fault == 'harness-build'): sys.exit(73)
        if kind == 'lib' and '--no-run' not in args: sys.exit(99)
        features = ['system'] if '--features' in args else []
        configuration = 'system' if features else 'default'
        print(json.dumps({'reason':'compiler-artifact','package_id':'synthetic-qshd',
            'profile':{'test':kind == 'lib','opt_level':'1','debuginfo':1}, 'features':features,
            'target':{'name':'qshd','kind':[kind], 'src_path':str(root / ('qshd/src/main.rs' if kind == 'bin' else 'qshd/src/lib.rs'))},
            'manifest_path':str(root / 'qshd/Cargo.toml'),
            'executable':str(root / 'target' / (('daemon-' if kind == 'bin' else 'harness-') + configuration))}))
elif name == 'git':
    tail = args[2:]
    if tail == ['rev-parse','HEAD']: print('c' * 40)
    elif tail == ['rev-parse','HEAD^{tree}']: print('d' * 40)
    elif tail == ['ls-files','-z']: sys.stdout.write('\0'.join(json.loads(os.environ['LAUNCH_CONTROL_TRACKED'])) + '\0')
    elif tail != ['diff','HEAD','--quiet']: sys.exit(99)
elif name == 'rustc':
    print('synthetic compiler control\nrelease: 1.98.1')
elif name == 'sed':
    if fault == 'path-substitution': sys.exit(73)
    if fault == 'empty-path': sys.exit(0)
    if fault == 'missing-path': print(root / 'absent-synthetic-executable')
    elif fault == 'invalid-path': print(root / 'tracked.txt')
    else: os.execv('/usr/bin/sed', ['/usr/bin/sed', *args])
elif name == 'tee':
    if fault in ('tee-failure', 'empty-log'):
        sys.stdin.buffer.read()
        if args: pathlib.Path(args[0]).write_bytes(b'')
        sys.exit(73 if fault == 'tee-failure' else 0)
    os.execv('/usr/bin/tee', ['/usr/bin/tee', *args])
elif name == 'python3':
    if args and args[0] == 'scripts/run-nextest-ci.py' and fault == 'exact-parser': sys.exit(73)
    stage = args[1] if len(args) > 1 and args[0] == '-' else None
    if (stage == 'before' and fault == 'before-helper') or (stage == 'after' and fault == 'after-helper'): sys.exit(73)
    if stage in ('before', 'after') and fault in ('missing-before-output', 'duplicate-before-output', 'missing-after-output', 'duplicate-after-output'):
        result = subprocess.run([sys.executable, *args], input=sys.stdin.buffer.read(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sys.stderr.buffer.write(result.stderr)
        data = result.stdout
        if fault == 'missing-' + stage + '-output': data = b''
        if fault == 'duplicate-' + stage + '-output': data += data
        sys.stdout.buffer.write(data)
        sys.exit(result.returncode)
    os.execv(sys.executable, [sys.executable, *args])
elif name.startswith('harness-'):
    if '--exact' not in args: sys.exit(99)
    selected = args[args.index('--exact') + 1]
    if '--list' in args:
        if fault == 'list-failure': sys.exit(73)
        if fault in ('list-zero','list-missing'): print('0 tests, 0 benchmarks')
        elif fault == 'list-duplicate': print(selected + ': test\n' + selected + ': test\n\n2 tests, 0 benchmarks')
        elif fault == 'list-wrong': print('synthetic::wrong: test\n\n1 test, 0 benchmarks')
        else: print(selected + ': test\n\n1 test, 0 benchmarks')
    else:
        if fault == 'changed-artifact':
            with pathlib.Path(sys.argv[0]).open('a') as out: out.write('\n# synthetic identity mutation\n')
        if fault == 'body-zero': print('running 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s')
        else:
            actual = 'synthetic::wrong' if fault == 'body-wrong' else selected
            result = 'ignored' if fault == 'body-ignored' else 'ok'
            passed, ignored = (0, 1) if fault == 'body-ignored' else (1, 0)
            print('running 1 test\ntest ' + actual + ' ... ' + result)
            summary = f'test result: ok. {passed} passed; 0 failed; {ignored} ignored; 0 measured; 0 filtered out; finished in 0.00s'
            print('\n' + summary)
            if fault == 'body-duplicate': print(summary)
            if fault == 'body-skipped': print('SKIPPED synthetic control')
        if fault == 'body-nonzero': sys.exit(73)
else:
    sys.exit(99)  # The synthetic daemon is never an executable test owner.
'''


class LaunchDriverFixture:
    def __init__(self, directory, block, fault='', mutation=None, conditional=False):
        self.fx = Fixture(directory)
        self.root = self.fx.root
        self.ledger = Path(directory) / 'invocations.jsonl'
        self.tools = Path(directory) / 'synthetic-tools'
        self.tools.mkdir(mode=0o700)
        self.fx.tracked.append('qshd/src/main.rs')
        (self.root / 'qshd/src/main.rs').write_text('synthetic source fixture')
        scripts = self.root / 'scripts'
        scripts.mkdir(mode=0o700)
        for name in ('run-nextest-ci.py', 'nextest_report.py'):
            shutil.copyfile(WORKFLOW.parents[2] / 'scripts' / name, scripts / name)
        tool = _DRIVER_TOOL.replace('__PYTHON__', sys.executable)
        for name in ('cargo', 'git', 'rustc', 'sed', 'tee', 'python3'):
            path = self.tools / name
            path.write_text(tool)
            path.chmod(0o700)
        for configuration in ('default', 'system'):
            for kind in ('daemon', 'harness'):
                path = self.root / 'target' / (kind + '-' + configuration)
                path.write_text(tool)
                path.chmod(0o700)
        isolated = Path(directory) / 'isolated'
        isolated.mkdir(mode=0o700)
        for name in ('home', 'config', 'cache', 'tmp', 'runner'):
            (isolated / name).mkdir(mode=0o700)
        for path in self.root.rglob('*'):
            if path.is_dir(): path.chmod(0o700)
        self.root.chmod(0o700)
        self.fx.runtime.chmod(0o700)
        self.env = dict(self.fx.env, PATH=str(self.tools) + ':/usr/bin:/bin',
                        HOME=str(isolated / 'home'), XDG_CONFIG_HOME=str(isolated / 'config'),
                        XDG_CACHE_HOME=str(isolated / 'cache'), TMPDIR=str(isolated / 'tmp'),
                        RUNNER_TEMP=str(isolated / 'runner'), HISTFILE='/dev/null',
                        GITHUB_SHA='c' * 40, LAUNCH_CONTROL_ROOT=str(self.root),
                        LAUNCH_CONTROL_LEDGER=str(self.ledger), LAUNCH_CONTROL_TRACKED=json.dumps(self.fx.tracked),
                        LAUNCH_CONTROL_FAULT=fault)
        self.text = block
        if mutation == 'early-zero':
            self.text, count = re.subn(r'(?m)^(\s*)(cargo metadata .+)$', r'\1exit 0\n\1\2', self.text, count=1)
            if count != 1: raise AssertionError('metadata mutation anchor missing')
        elif mutation == 'omit-case':
            anchor = 'for name in "${portable_names[@]}" "${native_names[@]}"; do'
            if anchor not in self.text: raise AssertionError('case mutation anchor missing')
            self.text = self.text.replace(anchor, anchor + '\n  [ "$name" != "' + NATIVE_LAUNCH[-1] + '" ] || continue', 1)
        elif mutation == 'omit-system':
            self.text, count = re.subn(r'for configuration in [^\n]+; do', 'for configuration in default; do', self.text, count=1)
            if count != 1: raise AssertionError('configuration mutation anchor missing')
        if conditional:
            self.text = 'if (\n' + self.text + '\n); then exit 0; else exit $?; fi\n'

    def invoke(self):
        result = subprocess.run(['/bin/bash', '-c', self.text], cwd=self.root, env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=40)
        calls = [json.loads(line) for line in self.ledger.read_text().splitlines()] if self.ledger.exists() else []
        return result, calls


class LaunchDriverExecutionTests(unittest.TestCase):
    def blocks(self):
        workflow = WORKFLOW.read_text()
        values = workflow.split('# launch529 BEGIN controlled ordinary\n')[1:]
        self.assertEqual(len(values), 2)
        return [textwrap.dedent(value.split('          # launch529 END controlled ordinary', 1)[0]) for value in values]

    def run_driver(self, block, fault='', mutation=None, conditional=False):
        directory = tempfile.TemporaryDirectory(prefix='launch-driver-synthetic-')
        self.addCleanup(directory.cleanup)
        return LaunchDriverFixture(directory.name, block, fault, mutation, conditional).invoke()

    def refused(self, block, fault='', mutation=None, conditional=False):
        result, calls = self.run_driver(block, fault, mutation, conditional)
        self.assertNotEqual(result.returncode, 0, (fault, mutation, 'must fail closed'))
        self.assertNotIn('launch529_execution_complete ', result.stdout)
        return calls

    def test_launch_driver_executes_exact_configurations_and_cases(self):
        expected = set(PORTABLE_LAUNCH + NATIVE_LAUNCH)
        for index, block in enumerate(self.blocks()):
            with self.subTest(driver=index):
                result, calls = self.run_driver(block, conditional=True)
                self.assertEqual(result.returncode, 0, 'valid synthetic extracted driver')
                configurations = ('default',) if index == 0 else ('default', 'system')
                for configuration in configurations:
                    harness = [c for c in calls if c['tool'] == 'harness-' + configuration]
                    bodies = [c for c in harness if '--list' not in c['argv']]
                    lists = [c for c in harness if '--list' in c['argv']]
                    selected = lambda values: [c['argv'][c['argv'].index('--exact') + 1] for c in values]
                    self.assertEqual(len(bodies), 21)
                    self.assertEqual(set(selected(bodies)), expected)
                    self.assertEqual(len(lists), 21, 'each body requires exact positive membership first')
                    self.assertEqual(set(selected(lists)), expected)
                    for body in bodies:
                        self.assertEqual(body['daemon_name'], 'daemon-' + configuration)
                        self.assertEqual(body['argv'], ['--include-ignored', '--exact', selected([body])[0], '--show-output', '--test-threads=1', '--color=never'])
                builds = [c['argv'] for c in calls if c['tool'] == 'cargo' and c['argv'][0] != 'metadata']
                self.assertEqual(len(builds), 2 * len(configurations))
                expected_builds = []
                for configuration in configurations:
                    feature_args = ['--features', 'system'] if configuration == 'system' else []
                    expected_builds += [
                        ['build', '-p', 'qshd', '--bin', 'qshd', '--profile', 'test', '--locked', *feature_args, '--message-format=json-render-diagnostics'],
                        ['test', '-p', 'qshd', '--lib', '--locked', '--no-run', *feature_args, '--message-format=json-render-diagnostics']]
                self.assertEqual(builds, expected_builds)
                self.assertEqual(sum('--features' in argv for argv in builds), 0 if index == 0 else 2)
                for argv in builds:
                    if '--features' in argv: self.assertEqual(argv[argv.index('--features') + 1], 'system')
                    self.assertIn('--locked', argv)
                    self.assertIn('--message-format=json-render-diagnostics', argv)
                receipts = [json.loads(line.split(' ', 1)[1]) for line in result.stdout.splitlines() if line.startswith('launch529_artifact_receipt ')]
                self.assertEqual(len(receipts), 2 * len(configurations))
                complete = [json.loads(line.split(' ', 1)[1]) for line in result.stdout.splitlines() if line.startswith('launch529_execution_complete ')]
                self.assertEqual(len(complete), 1, 'parent positive execution audit is mandatory')
                self.assertEqual(complete[0]['case_executions'], 21 * len(configurations))

    def test_launch_driver_propagates_build_artifact_and_substitution_failures(self):
        for index, block in enumerate(self.blocks()):
            for fault in ('metadata', 'daemon-build', 'harness-build', 'before-helper', 'path-substitution',
                          'invalid-path', 'missing-path', 'empty-path', 'after-helper', 'changed-artifact'):
                with self.subTest(driver=index, fault=fault):
                    self.refused(block, fault, conditional=True)

    def test_launch_driver_requires_exact_list_and_body_evidence(self):
        for index, block in enumerate(self.blocks()):
            for fault in ('list-failure', 'list-zero', 'list-missing', 'list-duplicate', 'list-wrong',
                          'body-nonzero', 'body-zero', 'body-ignored', 'body-wrong', 'body-duplicate',
                          'body-skipped', 'tee-failure', 'empty-log', 'exact-parser'):
                with self.subTest(driver=index, fault=fault):
                    calls = self.refused(block, fault, conditional=True)
                    if fault.startswith('list-'):
                        self.assertFalse(any(c['tool'].startswith('harness-') and '--list' not in c['argv'] for c in calls), 'invalid membership must prevent body execution')

    def test_launch_driver_rejects_early_subshell_success_without_receipts(self):
        for index, block in enumerate(self.blocks()):
            for mutation in ('early-zero', 'omit-case') + (('omit-system',) if index else ()):
                with self.subTest(driver=index, mutation=mutation):
                    self.refused(block, mutation=mutation, conditional=True)
            for fault in ('missing-before-output', 'duplicate-before-output', 'missing-after-output', 'duplicate-after-output'):
                with self.subTest(driver=index, fault=fault):
                    self.refused(block, fault, conditional=True)


if __name__ == '__main__':
    unittest.main()
