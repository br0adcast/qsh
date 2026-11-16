"""Exercise actual workflow policy with owned Git fixtures and inert native calls."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import textwrap
import unittest

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / '.github/workflows/ci.yml'
POLICY_TEST = '\n'.join([
    "python3 -I -B - <<'PY_PACKAGE_SCOPE_TESTS'",
    'import unittest',
    "suite = unittest.defaultTestLoader.discover('scripts/tests', pattern='test_ci_package_scope.py')",
    'count = suite.countTestCases()',
    'result = unittest.TextTestRunner(verbosity=2).run(suite)',
    'raise SystemExit(0 if count > 0 and result.wasSuccessful() and not result.skipped else 1)',
    'PY_PACKAGE_SCOPE_TESTS']) + '\n'
NATIVE = 'python3 -I -B scripts/tests/test_selinux_consumer_rpm_check.py --native -v'
DECISION = 'Determine native package fixture applicability'
NATIVE_STEP = 'Native package fixture controls'

# Frozen from actual main before this policy existed, independent of the helper.
ORIGINAL_CONTROLS = (
    'sh -n scripts/install.sh',
    "python3 -B -m unittest discover -s scripts/tests -p 'test_client_install_bootstrap.py'",
    "python3 -I -B scripts/tests/test_no_silent_skips.py -v",
    "python3 -m unittest discover -s scripts/tests -p 'test_build_openssl.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_release_version.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_rust_version.py'",
    "python3 -B -m unittest discover -s scripts/tests -p 'test_git_build_metadata.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_released_peer_acceptance.py'",
    "python3 -B -m unittest discover -s scripts/tests -p 'test_qshd_library_receipt.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_release_output.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_darwin_artifact_smoke.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_release_assembly.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_release_upload.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_release_settings.py'",
    "python3 -B -m unittest discover -s scripts/tests -p 'test_release_verification_docs.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_rpm_tool.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_bootstrap_tools.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_package_dependencies.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_linkage.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_modules.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_module_process.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_provider_pre.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_provider_pre_delivery.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_module_observer.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_module_install.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_context_rows.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_registry.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_inspection.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_first_activation.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_consumer_activation.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_phase.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_rpm_query.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_consumer_authority_generator.py'",
    "python3 -B -m unittest discover -s scripts/tests -p 'test_selinux_consumer_rpm_check.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_policy_build.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_api.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_files.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_observer.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_payload.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_references.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_queries.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_transaction.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_activation.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_activation_state.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_selinux_package_state.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_qshd_stop_guard.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_embed_stop_guard.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_shell_fixture_output.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_perf_baseline.py'",
    "python3 -m unittest discover -s scripts/tests -p 'test_perf_history.py'",
    'python3 -I -B scripts/test_three_channel_functional.py',
    "QSH_TEST_NEXTEST=cargo-nextest python3 -m unittest discover -s scripts/tests -p 'test_nextest_report.py'",
)


SYSTEM_OLD_ROOT = '          run_suite lib qshd --ignored 102 \\\n            --require helper::server::tests::host_policy::host529_policy_bad_bounds_wrong_nonce_and_shared_child_cap_refuse_before_fork \\\n            --require helper::server::tests::host_policy::host529_policy_cancelled_consumer_and_deadline_retain_real_child_until_wait \\\n            --require helper::server::tests::host_policy::host529_policy_current_account_and_root_restrictions_are_rechecked \\\n            --require helper::server::tests::host_policy::host529_policy_forged_signature_and_wrong_key_refuse \\\n            --require helper::server::tests::host_policy::host529_policy_key_revocation_between_issue_and_consume_is_current \\\n            --require helper::server::tests::host_policy::host529_policy_late_real_verdict_after_cancel_or_revocation_cannot_grant \\\n            --require helper::server::tests::host_policy::host529_policy_nonce_cannot_be_redirected_to_legacy_login \\\n            --require helper::server::tests::host_policy::host529_policy_nonce_replay_expiry_shared_capacity_and_recovery \\\n            --require helper::server::tests::host_policy::host529_policy_real_auth_and_two_policy_checks_do_not_create_logins \\\n            --require helper::server::tests::host_policy::host529_policy_verdict_before_reap_lost_consumer_stays_charged \\\n            --require process_scope::observation::tests::native_observer_retains_unrelated_process_in_another_session \\\n            --require control::peer_tests::control_peer_root_client_rejects_foreign_server \\\n            --require control::peer_tests::control_peer_foreign_client_rejects_root_server \\\n            --require transport_daemon::peer_tests::control_peer_root_server_rejects_foreign_client \\\n            --require transport_daemon::peer_tests::control_peer_foreign_server_rejects_root_client \\\n            --require serve::tests::the_system_flag_is_accepted_and_moves_the_host_key \\\n            --require helper::monitor::tests::pam_access_matches_ipv4_source_cidrs_with_explicit_fallbacks \\\n            --require helper::monitor::tests::pam_access_matches_ipv6_source_cidrs_with_explicit_fallbacks \\\n            --require log::tests::path_diagnostics_relative_preparation_rotates_after_detach_cwd_change \\\n            --require log::tests::path_diagnostics_foreground_failure_warns_once_and_survives_in_status \\\n            --require helper::server::tests::worker_parent::worker508_pre_stage_stop_is_retained_without_publication \\\n            --require helper::server::tests::worker_parent::worker508_init_failure_before_stage_acceptance_settles \\\n            --require helper::server::tests::worker_parent::worker508_post_stage_unread_stop_settles_failed \\\n            --require helper::server::tests::worker_parent::worker508_terminal_before_pending_send_suppresses_stop \\\n            --require endpoint::tests::private_parent_foreign_owner_refused \\\n            --require session_owner::inherited_launch::native_tests::launch529_root_and_foreign_entry_refuse_before_setup \\\n            drop_worker_privileges_refuses_without_root \\\n            own_capability_sets_parses_and_reports_none_for_an_ordinary_process \\\n            an_undeliverable_signal_is_reported_to_the_helper \\\n            a_rotation_that_cannot_rename_is_reported_and_bounds_file_growth\n'
SYSTEM_NEW_ROOT = '          run_suite lib qshd --ignored 119 \\\n            --require helper::server::tests::host_policy::host529_policy_bad_bounds_wrong_nonce_and_shared_child_cap_refuse_before_fork \\\n            --require helper::server::tests::host_policy::host529_policy_cancelled_consumer_and_deadline_retain_real_child_until_wait \\\n            --require helper::server::tests::host_policy::host529_policy_current_account_and_root_restrictions_are_rechecked \\\n            --require helper::server::tests::host_policy::host529_policy_forged_signature_and_wrong_key_refuse \\\n            --require helper::server::tests::host_policy::host529_policy_key_revocation_between_issue_and_consume_is_current \\\n            --require helper::server::tests::host_policy::host529_policy_late_real_verdict_after_cancel_or_revocation_cannot_grant \\\n            --require helper::server::tests::host_policy::host529_policy_nonce_cannot_be_redirected_to_legacy_login \\\n            --require helper::server::tests::host_policy::host529_policy_nonce_replay_expiry_shared_capacity_and_recovery \\\n            --require helper::server::tests::host_policy::host529_policy_real_auth_and_two_policy_checks_do_not_create_logins \\\n            --require helper::server::tests::host_policy::host529_policy_verdict_before_reap_lost_consumer_stays_charged \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_cancel_submitted_retains_real_child_until_wait \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_cancel_unsubmitted_cleans_only_exact_nonce \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_cap_before_spend_cleans_exact_remaining_nonce \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_close_loses_sink_without_releasing_real_child \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_coalesced_requests_keep_ordered_replies \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_current_policy_rejects_other_real_seam \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_deadline_and_partial_input_expire_inert \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_eof_retires_real_admitted_frontend \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_eof_submitted_drops_sink_not_physical_custody \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_forged_signature_and_unlisted_key_refuse \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_full_sink_stale_real_result_cannot_approve_twin \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_global_nonce_saturation_is_shared \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_host_pending_capacity_is_global \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_late_real_verdict_after_deadline_is_not_applied \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_real_signed_proof_and_current_revocation \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_replay_and_cross_seam_do_not_touch_other_ticket \\\n            --require helper::server::tests::system_dispatch::authdispatch529_system_wrong_method_report_and_host_refuse \\\n            --require process_scope::observation::tests::native_observer_retains_unrelated_process_in_another_session \\\n            --require control::peer_tests::control_peer_root_client_rejects_foreign_server \\\n            --require control::peer_tests::control_peer_foreign_client_rejects_root_server \\\n            --require transport_daemon::peer_tests::control_peer_root_server_rejects_foreign_client \\\n            --require transport_daemon::peer_tests::control_peer_foreign_server_rejects_root_client \\\n            --require serve::tests::the_system_flag_is_accepted_and_moves_the_host_key \\\n            --require helper::monitor::tests::pam_access_matches_ipv4_source_cidrs_with_explicit_fallbacks \\\n            --require helper::monitor::tests::pam_access_matches_ipv6_source_cidrs_with_explicit_fallbacks \\\n            --require log::tests::path_diagnostics_relative_preparation_rotates_after_detach_cwd_change \\\n            --require log::tests::path_diagnostics_foreground_failure_warns_once_and_survives_in_status \\\n            --require helper::server::tests::worker_parent::worker508_pre_stage_stop_is_retained_without_publication \\\n            --require helper::server::tests::worker_parent::worker508_init_failure_before_stage_acceptance_settles \\\n            --require helper::server::tests::worker_parent::worker508_post_stage_unread_stop_settles_failed \\\n            --require helper::server::tests::worker_parent::worker508_terminal_before_pending_send_suppresses_stop \\\n            --require endpoint::tests::private_parent_foreign_owner_refused \\\n            --require session_owner::inherited_launch::native_tests::launch529_root_and_foreign_entry_refuse_before_setup \\\n            drop_worker_privileges_refuses_without_root \\\n            own_capability_sets_parses_and_reports_none_for_an_ordinary_process \\\n            an_undeliverable_signal_is_reported_to_the_helper \\\n            a_rotation_that_cannot_rename_is_reported_and_bounds_file_growth\n'

def check_job(source):
    matches = list(re.finditer(r'(?m)^  check:\n', source))
    if len(matches) != 1:
        raise AssertionError('exactly one check job required')
    start = matches[0].end()
    following = re.search(r'(?m)^  [a-z][a-z0-9_-]*:\n', source[start:])
    return source[start:start + following.start()] if following else source[start:]


def step(source, name):
    job = check_job(source)
    matches = list(re.finditer(r'(?m)^      - name: ' + re.escape(name) + r'\n', job))
    if len(matches) != 1:
        raise AssertionError('missing or duplicate workflow step: ' + name)
    start = matches[0].start()
    following = re.search(r'(?m)^      - ', job[matches[0].end():])
    end = matches[0].end() + following.start() if following else len(job)
    return job[start:end]


def run_block(block):
    marker = '        run: |\n'
    if block.count(marker) != 1:
        raise AssertionError('expected one literal shell block')
    lines = []
    for line in block.split(marker, 1)[1].splitlines():
        if line.strip() and not line.startswith('          '):
            break
        lines.append(line)
    return textwrap.dedent('\n'.join(lines)).rstrip() + '\n'


def semantic_step(block):
    lines = []
    for line in block.splitlines():
        if line.strip() and (not line.startswith('      ') or line.startswith('      #')):
            break
        lines.append(line)
    return '\n'.join(lines).rstrip() + '\n'


def actual_helper(source):
    block = step(source, DECISION)
    begin, end = '          # BEGIN_PACKAGE_SCOPE\n', '          # END_PACKAGE_SCOPE\n'
    if block.count(begin) != 1 or block.count(end) != 1:
        raise AssertionError('missing or duplicate actual applicability helper')
    return textwrap.dedent(block.split(begin, 1)[1].split(end, 1)[0])


class GitFixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qsh-ci-package-scope-')
        self.directory = Path(self.temp.name)
        self.root = self.directory / 'repository'
        self.root.mkdir()
        for name in ('home', 'cache', 'config', 'tmp'):
            (self.directory / name).mkdir()
        self.env = dict(PATH='/usr/bin:/bin', LANG='C', LC_ALL='C', HOME=str(self.directory / 'home'),
                        XDG_CONFIG_HOME=str(self.directory / 'config'),
                        XDG_CACHE_HOME=str(self.directory / 'cache'),
                        TMPDIR=str(self.directory / 'tmp'), HISTFILE='/dev/null',
                        GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='CI fixture',
                        GIT_COMMITTER_NAME='CI fixture',
                        GIT_AUTHOR_EMAIL='986942+br0adcast@users.noreply.github.com',
                        GIT_COMMITTER_EMAIL='986942+br0adcast@users.noreply.github.com')
        for name in ('SSH_AUTH_SOCK', 'SSH_AGENT_PID', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE'):
            self.env.pop(name, None)
        self.paths = set()
        self.git('init', '--quiet', '--initial-branch=main')

    def close(self):
        self.temp.cleanup()

    def git(self, *args, input=None):
        result = subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', *args],
                                cwd=self.root, env=self.env, input=input, text=True,
                                capture_output=True, timeout=10)
        if result.returncode:
            raise AssertionError('owned Git fixture failed: ' + result.stderr[-1000:])
        return result.stdout.strip()

    def write(self, name, content='authored inert fixture\n'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        self.paths.add(name)

    def commit(self):
        self.git('add', '--', *sorted(self.paths))
        self.git('commit', '--quiet', '--allow-empty', '-m', 'Authored CI scope fixture')
        return self.git('rev-parse', 'HEAD')

    def execute(self, helper, base, head, *, event_name='pull_request', event=None,
                caller=None, source=None, extra_env=None):
        if event_name == 'pull_request':
            tree = self.git('rev-parse', head + '^{tree}')
            merge = self.git('commit-tree', tree, '-p', base, '-p', head,
                             '-m', 'Authored PR merge fixture')
            self.git('checkout', '--quiet', '--detach', merge)
            ref = 'refs/pull/605/merge'
            default_event = {'number': 605, 'pull_request': {
                'base': {'sha': base}, 'head': {'sha': head}}}
        else:
            merge = head
            self.git('checkout', '--quiet', '--detach', head)
            ref = 'refs/heads/main'
            default_event = {'before': base, 'after': head, 'ref': ref}
        event_path = self.directory / 'event.json'
        event_path.write_text(json.dumps(default_event if event is None else event))
        output = self.directory / 'output'
        output.unlink(missing_ok=True)
        env = dict(self.env, GITHUB_EVENT_PATH=str(event_path), GITHUB_OUTPUT=str(output),
                   GITHUB_EVENT_NAME=event_name, GITHUB_SHA=source or merge,
                   GITHUB_REF=ref, GITHUB_REPOSITORY='br0adcast/qsh',
                   GITHUB_WORKFLOW_REF=caller or 'br0adcast/qsh/.github/workflows/ci.yml@' + ref)
        env.update(extra_env or {})
        result = subprocess.run(['/usr/bin/python3', '-I', '-B', '-'], input=helper,
                                cwd=self.root, env=env, text=True, capture_output=True, timeout=20)
        fields = dict(line.split('=', 1) for line in output.read_text().splitlines()) if output.exists() else {}
        return result, fields


class PackageScopeTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text()

    def fixture(self, changes, *, initial=None, workflow=None):
        fixture = GitFixture()
        self.addCleanup(fixture.close)
        fixture.write('.github/workflows/ci.yml', workflow or self.source)
        fixture.write('scripts/tests/test_ci_package_scope.py', '# authored policy fixture\n')
        for name in initial or ():
            fixture.write(name)
        base = fixture.commit()
        for name in changes:
            fixture.write(name, 'changed authored fixture\n')
        head = fixture.commit()
        return fixture, base, head

    def decision(self, changes, **kwargs):
        helper = actual_helper(self.source)
        fixture, base, head = self.fixture(changes)
        result, fields = fixture.execute(helper, base, head, **kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(fields.get('required'), ('true', 'false'), result.stdout)
        return fields['required']

    def old_workflow(self):
        # Independently reverse only the approved relocation, not the classifier.
        source = self.source
        decision = semantic_step(step(source, DECISION))
        native = semantic_step(step(source, NATIVE_STEP))
        doc = semantic_step(step(source, 'Doc tests'))
        start = source.index(doc, source.index('\n  check:\n')) + len(doc)
        end = source.index(native, start) + len(native)
        self.assertEqual(source[start:end], '\n' + decision + '\n' + native)
        source = source[:start] + source[end:]
        source = source.replace(''.join('          ' + line + '\n' for line in POLICY_TEST.splitlines()), '')
        following = "          python3 -m unittest discover -s scripts/tests -p 'test_selinux_policy_build.py'\n"
        self.assertEqual(source.count(following), 1)
        source = source.replace(following, '          ' + NATIVE + '\n' + following)
        return source.replace('          fetch-depth: 0\n', '', 1)

    def policy_decision(self, *, old=False, changed=None, extra=None, event_name='pull_request',
                        expected_reason=None, relocate=None, event_factory=None, **execute_kwargs):
        fixture = GitFixture()
        self.addCleanup(fixture.close)
        fixture.write('.github/workflows/ci.yml', self.old_workflow() if old else self.source)
        if not old:
            fixture.write('scripts/tests/test_ci_package_scope.py', '# authored policy fixture\n')
        if relocate:
            fixture.write(relocate[0])
        base = fixture.commit()
        fixture.write('.github/workflows/ci.yml', self.source if changed is None else changed)
        fixture.write('scripts/tests/test_ci_package_scope.py', '# changed authored policy fixture\n')
        for name in extra or ():
            fixture.write(name)
        if relocate:
            (fixture.root / relocate[0]).unlink()
            if relocate[1]:
                fixture.write(relocate[1])
        head = fixture.commit()
        if event_factory is not None:
            execute_kwargs['event'] = event_factory(base, head)
        result, fields = fixture.execute(actual_helper(self.source), base, head,
                                        event_name=event_name, **execute_kwargs)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(fields.get('required'), ('true', 'false'), result.stdout)
        if expected_reason is not None:
            self.assertIn(' reason=' + expected_reason + '\n', result.stdout)
        return fields['required']

    def system_baseline(self):
        source = self.source
        pairs = (
            (SYSTEM_NEW_ROOT, SYSTEM_OLD_ROOT),
            ("              require(policy[:2] == ['--ignored', '119'], 'library-policy')\n",
             "              require(policy[:2] == ['--ignored', '102'], 'library-policy')\n"),
            ('          # `--ignored 119` is the exact compiled system-library ignored count:\n'
             '          # Plus seventeen isolated System bridge bodies, each required through its wrapper.\n',
             '          # `--ignored 102` is the exact compiled system-library ignored count:\n'),
            ('          python3 -I -B scripts/tests/test_no_silent_skips.py -v\n', ''),
        )
        for current, prior in pairs:
            # These literals also occur inside the actual helper as escaped source.
            self.assertEqual(source.count(current), 1)
            source = source.replace(current, prior, 1)
        return source

    def system_decision(self, changed=None, *, reverse=False, event='pull_request', extra=(), remove=None):
        fixture = GitFixture()
        self.addCleanup(fixture.close)
        fixture.write('.github/workflows/ci.yml', self.source if reverse else self.system_baseline())
        for path in ('scripts/tests/test_ci_package_scope.py', 'scripts/tests/test_no_silent_skips.py',
                     'scripts/tests/test_qshd_library_receipt.py'):
            fixture.write(path)
        base = fixture.commit()
        fixture.write('.github/workflows/ci.yml', self.system_baseline() if reverse else changed or self.source)
        for path in ('qshd/src/helper/local_auth_dispatch.rs', 'qshd/src/helper/local_auth_dispatch_tests.rs',
                     'qshd/src/helper/server.rs', 'scripts/tests/test_no_silent_skips.py',
                     'scripts/tests/test_qshd_library_receipt.py', *extra):
            fixture.write(path, '# changed authored fixture\n')
        if remove:
            (fixture.root / remove).unlink()
        head = fixture.commit()
        result, fields = fixture.execute(actual_helper(self.source), base, head, event_name=event)
        self.assertEqual(result.returncode, 0, result.stderr)
        return fields.get('required')

    def test_exact_system_transition_admits_pr_and_push_with_current_core_paths(self):
        for event in ('pull_request', 'push'):
            for extra in ((), ('crates/transport/src/lib.rs',), ('.github/workflows/native-crypto.yml',)):
                with self.subTest(event=event, extra=extra):
                    self.assertEqual(self.system_decision(event=event, extra=extra), 'false')

    def test_system_transition_refuses_downgrade_package_dependency_unknown_and_deleted_controls(self):
        self.assertEqual(self.system_decision(reverse=True), 'true')
        for path in ('packaging/selinux/new-input', 'qshd/Cargo.toml', 'scripts/unclassified.py'):
            self.assertEqual(self.system_decision(extra=(path,)), 'true')
        for path in ('scripts/tests/test_no_silent_skips.py', 'scripts/tests/test_qshd_library_receipt.py',
                     'scripts/tests/test_ci_package_scope.py'):
            self.assertEqual(self.system_decision(remove=path), 'true')

    def test_system_transition_rejects_every_changed_requirement_and_allowance(self):
        for line in SYSTEM_NEW_ROOT.splitlines(True)[1:]:
            with self.subTest(obligation=line.strip()):
                self.assertEqual(self.system_decision(changed=self.source.replace(line, '', 1)), 'true')
        first = SYSTEM_NEW_ROOT.splitlines(True)[1]
        self.assertEqual(self.system_decision(changed=self.source.replace(first, first + first, 1)), 'true')
        lines = SYSTEM_NEW_ROOT.splitlines(True)
        swapped = ''.join([lines[0], lines[2], lines[1], *lines[3:]])
        self.assertEqual(self.system_decision(changed=self.source.replace(SYSTEM_NEW_ROOT, swapped)), 'true')

    def test_system_transition_rejects_changed_prefix_count_comment_and_command(self):
        mutations = [self.source.replace('run_suite lib qshd --ignored 119', 'run_suite lib qshd --ignored ' + count)
                     for count in ('85', '102', '118', '120')]
        mutations += [self.source.replace("              require(policy[:2] == ['--ignored', '119']",
                                          "              require(policy[:2] == ['--ignored', '118']"),
                      self.source.replace('# `--ignored 119`', '# `--ignored 118`')]
        command = '          python3 -I -B scripts/tests/test_no_silent_skips.py -v\n'
        mutations += [self.source.replace(command, ''), self.source.replace(command, command * 2),
                      self.source.replace(command, command.replace(' -I', '')),
                      self.source.replace(command, '').replace('          sh -n scripts/install.sh\n',
                                                                command + '          sh -n scripts/install.sh\n')]
        mutations += list(self.protected_workflow_mutations().values())
        for i, changed in enumerate(mutations):
            with self.subTest(mutation=i):
                self.assertNotEqual(changed, self.source)
                self.assertEqual(self.system_decision(changed=changed), 'true')

    def test_no_skip_module_runner_refuses_empty_skipped_failed_and_accepts_positive(self):
        module = (ROOT / 'scripts/tests/test_no_silent_skips.py').read_text()
        marker = 'if __name__ == "__main__":\n'
        self.assertEqual(module.count(marker), 1)
        runner = module.split(marker)[1]
        for state, body in [('empty', ''), ('skip', '@unittest.skip("inert")\n'),
                            ('fail', ''), ('pass', '')]:
            with self.subTest(state=state), tempfile.TemporaryDirectory(prefix='qsh-noskip-runner-') as temp:
                path = Path(temp) / 'fixture.py'
                fixture = 'import unittest\n'
                if state != 'empty':
                    fixture += 'class Fixture(unittest.TestCase):\n'
                    if body: fixture += '    ' + body
                    fixture += '    def test_case(self): ' + ('self.fail("inert")' if state == 'fail' else 'pass') + '\n'
                path.write_text(fixture + marker + runner)
                result = subprocess.run(['/usr/bin/python3', '-I', '-B', str(path)],
                                        text=True, capture_output=True, timeout=10)
                self.assertEqual(result.returncode == 0, state == 'pass', result.stderr)

    def test_initial_policy_only_delta_requires_protected_contract(self):
        self.assertEqual(self.policy_decision(old=True), 'false')

    def test_later_policy_only_delta_requires_protected_contract(self):
        self.assertEqual(self.policy_decision(), 'false')

    def test_policy_only_main_push_requires_the_same_protected_contract(self):
        self.assertEqual(self.policy_decision(old=True, event_name='push'), 'false')
        self.assertEqual(self.policy_decision(event_name='push'), 'false')

    def test_policy_and_package_mixed_delta_requires_native(self):
        self.assertEqual(self.policy_decision(old=True, extra=['packaging/selinux/new-input']), 'true')

    def test_protected_policy_and_core_compositions_keep_native_optional(self):
        paths = ('qshd/src/helper/server.rs', 'crates/transport/src/lib.rs',
                 '.github/workflows/native-crypto.yml', 'scripts/tests/test_build_openssl.py',
                 'scripts/tests/test_native_verifier_paths.py',
                 'scripts/tests/test_released_peer_acceptance.py')
        for old in (True, False):
            for event in ('pull_request', 'push'):
                for path in paths:
                    with self.subTest(old=old, event=event, path=path):
                        self.assertEqual(self.policy_decision(old=old, extra=[path],
                            event_name=event), 'false')

    def test_policy_core_composition_reports_its_distinct_protected_reason(self):
        self.assertEqual(self.policy_decision(extra=['qshd/src/helper/server.rs'],
            expected_reason='PROTECTED_POLICY_AND_CORE'), 'false')

    def test_policy_core_compositions_preserve_package_dependency_and_unknown_refusals(self):
        for old in (True, False):
            for event in ('pull_request', 'push'):
                for path in ('packaging/selinux/new-input', 'scripts/check-selinux-consumer-rpm.py',
                             'qshd/Cargo.toml', 'crates/toolchain/rust-toolchain.toml',
                             'scripts/unclassified.py', 'unclassified/new-input'):
                    with self.subTest(old=old, event=event, path=path):
                        self.assertEqual(self.policy_decision(old=old, event_name=event,
                            extra=['qshd/src/helper/server.rs', path]), 'true')

    def test_policy_core_compositions_retain_renamed_deleted_and_missing_input_guards(self):
        for old in (True, False):
            for event in ('pull_request', 'push'):
                for move in (('packaging/old-input', None),
                             ('packaging/old-input', 'qshd/moved-input'),
                             ('qshd/old-input', 'packaging/moved-input'),
                             ('scripts/tests/test_ci_package_scope.py', None)):
                    with self.subTest(old=old, event=event, move=move):
                        self.assertEqual(self.policy_decision(old=old, event_name=event,
                            extra=['qshd/src/helper/server.rs'], relocate=move), 'true')

    def test_policy_core_compositions_still_require_protected_workflow(self):
        for name, changed in self.protected_workflow_mutations().items():
            for old in (True, False):
                with self.subTest(old=old, mutation=name):
                    self.assertNotEqual(changed, self.source)
                    self.assertEqual(self.policy_decision(old=old, changed=changed,
                        extra=['qshd/src/helper/server.rs']), 'true')

    def test_policy_core_compositions_keep_event_and_caller_binding(self):
        for old in (True, False):
            for kwargs in ({'event': {}}, {'source': '1' * 40},
                           {'event_factory': lambda base, head: {'number': 605, 'pull_request': {
                               'base': {'sha': head}, 'head': {'sha': head}}}},
                           {'caller': 'br0adcast/qsh/.github/workflows/release.yml@refs/pull/605/merge'}):
                with self.subTest(old=old, context=kwargs):
                    self.assertEqual(self.policy_decision(old=old,
                        extra=['qshd/src/helper/server.rs'], **kwargs), 'true')

    def test_original_core_controls_and_job_contract_are_unconditional(self):
        body = run_block(step(self.source, 'Build and release script controls'))
        self.assertTrue(body.endswith(POLICY_TEST))
        self.assertEqual(body.count(POLICY_TEST), 1)
        commands = [line for line in body.removesuffix(POLICY_TEST).splitlines()
                    if line.strip() and not line.lstrip().startswith('#')]
        self.assertEqual(tuple(commands), ORIGINAL_CONTROLS)
        self.assertNotIn(NATIVE, commands)
        bundle = step(self.source, 'Build and release script controls')
        self.assertNotIn('\n        if:', bundle)
        job = check_job(self.source)
        header = job.split('    steps:\n', 1)[0]
        self.assertIn('    runs-on: ubuntu-latest\n', header)
        self.assertIn('    timeout-minutes: 30\n', header)
        self.assertEqual(re.findall(r'^      ([A-Z_]+): (.*)$', header, re.M), [
            ('HISTFILE', '/dev/null'), ('CARGO_PROFILE_TEST_DEBUG', 'line-tables-only')])
        self.assertIn('actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1', job)
        self.assertIn('          ref: ${{ github.sha }}\n          fetch-depth: 0\n', job)
        self.assertEqual(step(self.source, 'Install integration test dependencies').split('        run: ', 1)[1].strip(),
            'sudo apt-get update && sudo apt-get install -y libpam0g-dev libselinux1-dev binutils patch zsh rpm rpm2cpio')
        names = ('Build and release script controls', 'Release attestation controls',
                 'Prepare the pinned native backend', 'Formatting', 'Clippy',
                 'Build the exact test daemon artifact', 'Unit and integration tests',
                 'Portable dormant host endpoint contracts', 'Doc tests', DECISION, NATIVE_STEP)
        positions = [job.index('      - name: ' + name + '\n') for name in names]
        self.assertEqual(positions, sorted(positions))
        self.assertIn('        run: cargo fmt --all --check\n', step(self.source, 'Formatting'))
        self.assertIn('cargo clippy --workspace --all-targets --locked --features qshd/system -- -D warnings',
                      step(self.source, 'Clippy'))
        ordinary = step(self.source, 'Unit and integration tests')
        self.assertIn('--require-install-fixtures', ordinary)
        self.assertIn('cargo nextest run --profile ci --workspace --lib --bins --tests --example three_channel305', ordinary)
        self.assertIn('        run: cargo test --workspace --doc --locked\n', step(self.source, 'Doc tests'))

    def test_deleted_and_renamed_package_inputs_require_native(self):
        for old, new in (('packaging/old-input', None), ('packaging/old-input', 'qshd/moved-input'),
                         ('qshd/old-input', 'packaging/moved-input')):
            with self.subTest(old=old, new=new):
                fixture, base, _ = self.fixture([], initial=[old])
                (fixture.root / old).unlink()
                if new:
                    fixture.write(new)
                head = fixture.commit()
                result, fields = fixture.execute(actual_helper(self.source), base, head)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(fields.get('required'), 'true')

    def test_invalid_event_identities_and_empty_delta_require_native(self):
        fixture, base, head = self.fixture(['qshd/src/lib.rs'])
        good = {'number': 605, 'pull_request': {'base': {'sha': base}, 'head': {'sha': head}}}
        events = [{}, [], {'number': 605, 'pull_request': {}},
                  {'number': 605, 'pull_request': {'base': {'sha': '0' * 40}, 'head': {'sha': head}}},
                  {'number': 605, 'pull_request': {'base': {'sha': '--help'}, 'head': {'sha': head}}},
                  {'number': 605, 'pull_request': {'base': {'sha': '1' * 40}, 'head': {'sha': head}}},
                  {'number': 605, 'pull_request': {'base': {'sha': fixture.git('rev-parse', head + '^{tree}')},
                                                  'head': {'sha': head}}},
                  {'number': 605, 'pull_request': {'base': {'sha': head}, 'head': {'sha': head}}},
                  {'number': True, 'pull_request': good['pull_request']}]
        for event in events:
            with self.subTest(event=event):
                result, fields = fixture.execute(actual_helper(self.source), base, head, event=event)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(fields.get('required'), 'true')
        for extra in ({'GITHUB_WORKFLOW_REF': ''}, {'GITHUB_REPOSITORY': 'unrelated/repository'},
                      {'GITHUB_EVENT_PATH': str(fixture.directory / 'missing-event')}):
            with self.subTest(extra=extra):
                result, fields = fixture.execute(actual_helper(self.source), base, head, extra_env=extra)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(fields.get('required'), 'true')
        result, fields = fixture.execute(actual_helper(self.source), base, head, source=head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fields.get('required'), 'true')
        result, fields = fixture.execute(actual_helper(self.source), base, head, event_name='push',
            event={'before': base, 'after': base, 'ref': 'refs/heads/main'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fields.get('required'), 'true')
        empty, base, head = self.fixture([])
        result, fields = empty.execute(actual_helper(self.source), base, head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fields.get('required'), 'true')

    def test_tag_and_other_branch_pushes_require_native(self):
        for ref in ('refs/tags/v0.0.0', 'refs/heads/another-branch'):
            fixture, base, head = self.fixture(['qshd/src/lib.rs'])
            result, fields = fixture.execute(actual_helper(self.source), base, head, event_name='push',
                event={'before': base, 'after': head, 'ref': ref},
                extra_env={'GITHUB_REF': ref, 'GITHUB_WORKFLOW_REF':
                           'br0adcast/qsh/.github/workflows/ci.yml@' + ref})
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(fields.get('required'), 'true')

    def test_git_errors_and_malformed_nul_diff_require_native(self):
        for data in (None, b'qshd/missing-terminator', b'qshd/empty\0\0', b'qshd/\xff\0'):
            with self.subTest(diff=data):
                fixture, base, head = self.fixture(['qshd/src/lib.rs'])
                tools = fixture.directory / 'tools'
                tools.mkdir()
                shim = tools / 'git'
                if data is None:
                    shim.write_text('#!/bin/sh\nexit 3\n')
                else:
                    raw = tools / 'diff-output'
                    raw.write_bytes(data)
                    shim.write_text('#!/bin/sh\ncase " $* " in\n'
                        '  *" diff "*) cat "' + str(raw) + '"; exit 0 ;;\n'
                        'esac\nexec /usr/bin/git "$@"\n')
                shim.chmod(0o700)
                result, fields = fixture.execute(actual_helper(self.source), base, head,
                    extra_env={'PATH': str(tools) + ':/usr/bin:/bin'})
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(fields.get('required'), 'true')

    def protected_workflow_mutations(self):
        native = semantic_step(step(self.source, NATIVE_STEP))
        mutations = {
            'native argv': self.source.replace(native, native.replace(' --native -v', ' --native'), 1),
            'native environment': self.source.replace(native, native.replace('        run: |\n',
                '        env:\n          LANG: changed\n        run: |\n'), 1),
            'native shell': self.source.replace(native, native.replace('        run: |\n',
                '        shell: sh\n        run: |\n'), 1),
            'masked failure': self.source.replace(native, native.replace(NATIVE, NATIVE + ' || true'), 1),
            'continue on error': self.source.replace(native, native.replace('        run: |\n',
                '        continue-on-error: true\n        run: |\n'), 1),
            'wrong condition': self.source.replace(native, native.replace("!= 'false'", "== 'false'"), 1),
            'runner': self.source.replace('    runs-on: ubuntu-latest\n', '    runs-on: changed-runner\n', 1),
            'job environment': self.source.replace('      CARGO_PROFILE_TEST_DEBUG: line-tables-only\n',
                '      CARGO_PROFILE_TEST_DEBUG: changed\n', 1),
            'setup': self.source.replace('zsh rpm rpm2cpio\n', 'zsh rpm\n', 1),
            'policy invocation removed': self.source.replace(
                ''.join('          ' + line + '\n' for line in POLICY_TEST.splitlines()), '', 1),
            'marker duplicate': self.source.replace('          # BEGIN_PACKAGE_SCOPE\n',
                '          # BEGIN_PACKAGE_SCOPE\n          # BEGIN_PACKAGE_SCOPE\n', 1),
            'native missing': self.source.replace(native, '', 1),
        }
        before_doc = self.source.replace(native, '', 1)
        mutations['native before core completion'] = before_doc.replace(
            '      - name: Doc tests\n', native + '\n      - name: Doc tests\n', 1)
        return mutations

    def test_protected_workflow_contract_rejects_residual_mutations(self):
        for name, source in self.protected_workflow_mutations().items():
            with self.subTest(mutation=name):
                self.assertNotEqual(source, self.source)
                self.assertEqual(self.policy_decision(changed=source), 'true')

    def test_deleted_policy_control_module_requires_native(self):
        fixture, base, _ = self.fixture([])
        (fixture.root / 'scripts/tests/test_ci_package_scope.py').unlink()
        head = fixture.commit()
        result, fields = fixture.execute(actual_helper(self.source), base, head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fields.get('required'), 'true')

    def test_scope_reporting_never_prints_changed_filenames_or_invalid_payload(self):
        canary = 'PRIVATE_SCOPE_CANARY'
        fixture, base, head = self.fixture(['unclassified/' + canary])
        result, fields = fixture.execute(actual_helper(self.source), base, head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(fields.get('required'), 'true')
        self.assertNotIn(canary, result.stdout + result.stderr)

    def test_output_publication_failure_cannot_be_a_successful_omission(self):
        fixture, base, head = self.fixture(['qshd/src/lib.rs'])
        result, fields = fixture.execute(actual_helper(self.source), base, head,
            extra_env={'GITHUB_OUTPUT': str(fixture.directory / 'missing-parent' / 'output')})
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(fields.get('required'), 'false')

    def test_policy_control_runner_refuses_empty_skipped_or_failed_selection(self):
        actual = run_block(step(self.source, 'Build and release script controls'))
        self.assertTrue(actual.endswith(POLICY_TEST))
        runner = actual[-len(POLICY_TEST):]
        cases = {
            'empty': '# authored module with no selected tests\n',
            'skipped': 'import unittest\nclass Fixture(unittest.TestCase):\n'
                       '    @unittest.skip("authored fixture")\n    def test_case(self): pass\n',
            'failed': 'import unittest\nclass Fixture(unittest.TestCase):\n'
                      '    def test_case(self): self.fail("authored fixture")\n',
            'passed': 'import unittest\nclass Fixture(unittest.TestCase):\n'
                      '    def test_case(self): pass\n',
        }
        for name, module in cases.items():
            with self.subTest(selection=name), tempfile.TemporaryDirectory(prefix='qsh-policy-runner-') as temp:
                root = Path(temp)
                tests = root / 'scripts/tests'
                tests.mkdir(parents=True)
                (tests / 'test_ci_package_scope.py').write_text(module)
                result = subprocess.run(['bash', '-e', '-c', runner], cwd=root,
                    env={'PATH': '/usr/bin:/bin', 'HOME': str(root), 'HISTFILE': '/dev/null'},
                    text=True, capture_output=True, timeout=10)
                if name == 'passed':
                    self.assertEqual(result.returncode, 0, result.stderr)
                else:
                    self.assertNotEqual(result.returncode, 0, result.stderr)

    def test_exact_cli_fixture_alone_and_with_core_admits_pr_and_push(self):
        cli = 'cli/src/climb_bootstrap_tests.rs'
        for event in ('pull_request', 'push'):
            for paths in ([cli], [cli, 'qshd/src/session_owner/host_engine_tests.rs']):
                with self.subTest(event=event, paths=paths):
                    self.assertEqual(self.decision(paths, event_name=event), 'false')

    def test_exact_cli_fixture_policy_amendment_preserves_main_contract(self):
        cli = 'cli/src/climb_bootstrap_tests.rs'
        prior = self.source
        for current, previous in (
            ("                           'scripts/tests/test_qshd_library_receipt.py',\n"
             "                           'cli/src/climb_bootstrap_tests.rs'}",
             "                           'scripts/tests/test_qshd_library_receipt.py'}"),
            ("                              'scripts/tests/test_qshd_library_receipt.py',\n"
             "                              'cli/src/climb_bootstrap_tests.rs'}:",
             "                              'scripts/tests/test_qshd_library_receipt.py'}:"),
        ):
            self.assertEqual(prior.count(current), 1)
            prior = prior.replace(current, previous, 1)
        for event in ('pull_request', 'push'):
            with self.subTest(event=event):
                fixture = GitFixture()
                self.addCleanup(fixture.close)
                fixture.write('.github/workflows/ci.yml', prior)
                fixture.write('scripts/tests/test_ci_package_scope.py')
                base = fixture.commit()
                fixture.write('.github/workflows/ci.yml', self.source)
                fixture.write('scripts/tests/test_ci_package_scope.py', '# changed policy control\n')
                fixture.write(cli)
                fixture.write('qshd/src/session_owner/host_engine_tests.rs')
                head = fixture.commit()
                result, fields = fixture.execute(actual_helper(self.source), base, head,
                                                event_name=event)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(fields.get('required'), 'false')
                self.assertIn(' reason=PROTECTED_POLICY_AND_CORE\n', result.stdout)

    def test_exact_cli_fixture_keeps_neighbor_package_dependency_and_unknown_required(self):
        cli = 'cli/src/climb_bootstrap_tests.rs'
        for event in ('pull_request', 'push'):
            for other in ('cli/src/climb.rs', 'cli/src/neighbor_tests.rs',
                          'packaging/selinux/new-input', 'cli/Cargo.toml',
                          'scripts/check-selinux-consumer-rpm.py', 'unknown/new-input'):
                with self.subTest(event=event, other=other):
                    self.assertEqual(self.decision([cli, other], event_name=event), 'true')
                    self.assertEqual(self.policy_decision(extra=[cli, other],
                                                         event_name=event), 'true')

    def test_exact_cli_fixture_missing_renamed_and_nonregular_entries_require_native(self):
        cli = 'cli/src/climb_bootstrap_tests.rs'
        for event in ('pull_request', 'push'):
            for mutation in ('delete', 'rename', 'executable', 'symlink', 'empty', 'invalid-utf8'):
                with self.subTest(event=event, mutation=mutation):
                    fixture, base, _ = self.fixture([], initial=[cli])
                    path = fixture.root / cli
                    if mutation in ('delete', 'rename', 'symlink'):
                        path.unlink()
                    if mutation == 'rename':
                        fixture.write('qshd/moved-fixture.rs')
                    elif mutation == 'executable':
                        path.chmod(0o755)
                    elif mutation == 'symlink':
                        path.symlink_to('neighbor_tests.rs')
                    elif mutation == 'empty':
                        path.write_text('')
                    elif mutation == 'invalid-utf8':
                        path.write_bytes(bytes([255]))
                    head = fixture.commit()
                    result, fields = fixture.execute(actual_helper(self.source), base, head,
                                                    event_name=event)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(fields.get('required'), 'true')

    def test_nonpackage_pr_omits_native(self):
        self.assertEqual(self.decision(['qshd/src/session_owner/engine.rs']), 'false')

    def test_positive_nonpackage_paths_and_push(self):
        for name in ('crates/transport/src/lib.rs', 'qshd/src/channel_backend.rs',
                     '.github/workflows/native-crypto.yml', 'scripts/tests/test_build_openssl.py',
                     'scripts/tests/test_native_verifier_paths.py',
                     'scripts/tests/test_released_peer_acceptance.py'):
            with self.subTest(path=name):
                self.assertEqual(self.decision([name]), 'false')
        self.assertEqual(self.decision(['qshd/src/lib.rs'], event_name='push'), 'false')

    def test_package_dependency_unknown_and_mixed_paths_require_native(self):
        for names in (['packaging/selinux/qshd_selinux_process.py'],
                      ['scripts/check-selinux-consumer-rpm.py'],
                      ['scripts/generate-selinux-consumer-authority.py'],
                      ['scripts/tests/test_selinux_consumer_rpm_check.py'],
                      ['packaging/pam.d/qshd.fedora-selinux'], ['Cargo.lock'],
                      ['unclassified/new-input'], ['qshd/src/lib.rs', 'packaging/new-file']):
            with self.subTest(paths=names):
                self.assertEqual(self.decision(names), 'true')

    def test_dependency_manifests_inside_core_folders_require_native(self):
        for name in ('qshd/Cargo.toml', 'crates/transport/Cargo.toml',
                     'crates/toolchain/rust-toolchain.toml', 'crates/fixtures/requirements.txt'):
            with self.subTest(dependency=name):
                self.assertEqual(self.decision([name]), 'true')

    def test_other_events_and_reusable_callers_require_native(self):
        for event in ('workflow_dispatch', 'workflow_call', 'release', 'unknown'):
            with self.subTest(event=event):
                self.assertEqual(self.decision(['qshd/src/lib.rs'], event_name=event), 'true')
        for event, ref in (('push', 'refs/heads/main'), ('pull_request', 'refs/pull/605/merge')):
            with self.subTest(caller=event):
                self.assertEqual(self.decision(['qshd/src/lib.rs'], event_name=event,
                    caller='br0adcast/qsh/.github/workflows/release.yml@' + ref), 'true')

    def test_native_block_executes_exact_command_and_preserves_failure(self):
        block = step(self.source, NATIVE_STEP)
        body = run_block(block)
        self.assertEqual(body.strip(), NATIVE)
        self.assertEqual(semantic_step(block), '      - name: ' + NATIVE_STEP
            + "\n        if: ${{ steps.package_scope.outputs.required != 'false' }}"
            + '\n        run: |\n          ' + NATIVE + '\n')
        self.assertIn("if: ${{ steps.package_scope.outputs.required != 'false' }}", block)
        self.assertNotIn('continue-on-error', block)
        self.assertNotIn('timeout-minutes', block)
        self.assertGreater(self.source.index('      - name: ' + NATIVE_STEP),
                           self.source.index('      - name: Doc tests\n', self.source.index('\n  check:\n')))
        with tempfile.TemporaryDirectory(prefix='qsh-ci-native-recorder-') as temp:
            root = Path(temp)
            recorder = root / 'python3'
            recorder.write_text('#!/usr/bin/python3\nimport json,os,sys\nfrom pathlib import Path\n'
                'p=Path(os.environ["QSH_RECORD"])\n'
                'p.write_text(json.dumps({"argv":sys.argv[1:],"inherited":os.environ.get("OPENSSL_STATIC")}))\n'
                'sys.exit(int(os.environ["QSH_EXIT"]))\n')
            recorder.chmod(0o700)
            for code in (0, 23):
                record = root / 'record.json'
                record.unlink(missing_ok=True)
                result = subprocess.run(['bash', '-e', '-c', body], cwd=root,
                    env=dict(os.environ, PATH=str(root) + ':/usr/bin:/bin', HISTFILE='/dev/null',
                             OPENSSL_STATIC='1', QSH_RECORD=str(record), QSH_EXIT=str(code)),
                    capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, code, result.stderr)
                self.assertEqual(json.loads(record.read_text()), {'argv': [
                    '-I', '-B', 'scripts/tests/test_selinux_consumer_rpm_check.py', '--native', '-v'],
                    'inherited': '1'})


if __name__ == '__main__':
    unittest.main()
