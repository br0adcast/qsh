"""CI gate accounting over recorded and constructed jobs-API payloads (#609).

Recorded payloads in ci-fixtures/ come from real runs of this repository and
keep only job identity, attempt, status, conclusion and timing fields.
"""
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / 'ci-fixtures'
spec = importlib.util.spec_from_file_location('qsh_ci_gate', ROOT / 'scripts/ci-gate.py')
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
select = gate.select
POLICY = select.load_policy(ROOT)
DIGEST = select.policy_digest(ROOT)
REPO = 'br0adcast/qsh'
H, S, B = 'a' * 40, 'b' * 40, 'c' * 40
RUN = 9001


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


def job(name, conclusion='success', attempt=1, status='completed', started='2026-11-16T10:00:00Z',
        completed='2026-11-16T10:10:00Z', head=H, number=[0]):
    number[0] += 1
    return {'id': number[0], 'run_id': RUN, 'run_attempt': attempt, 'name': name, 'status': status,
            'conclusion': conclusion if status == 'completed' else None, 'started_at': started,
            'completed_at': completed if status == 'completed' else None, 'head_sha': head}


class FakeApi:
    def __init__(self, run, latest, history=None, artifacts=None, runs=None, archives=None, fail=False):
        self.run, self.latest, self.history = run, latest, history if history is not None else latest
        self.artifacts, self.runs, self.archives, self.fail = artifacts or {}, runs, archives or {}, fail
        self.calls = []

    def get(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        if self.fail:
            raise gate.GateError('API status 502')
        if path.endswith('/jobs'):
            source = self.latest if params['filter'] == 'latest' else self.history
            jobs = source() if callable(source) else source
            page, size = params['page'], params['per_page']
            return {'total_count': len(jobs), 'jobs': jobs[(page - 1) * size:page * size]}
        if path.endswith('/artifacts'):
            return {'artifacts': self.artifacts.get(path.split('/')[-2], [])}
        if path.endswith('/actions/runs'):
            return self.runs
        return self.run

    def download(self, path):
        return self.archives[path.split('/')[-2]]


def lane_cells(lanes, prefix=''):
    names = []
    for lane in sorted(lanes):
        for cell in POLICY['lanes'][lane]['cells']:
            spec_ = POLICY['lanes'][lane]
            call = '' if spec_['workflow'] == gate.CI else next(
                c for c in gate.CALLS if gate.CALLERS[c] == spec_['workflow']) + ' / '
            names.append(prefix + call + cell if (prefix or call) else cell)
    return names


class GateHarness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qsh-ci-gate-')
        self.addCleanup(self.temp.cleanup)
        event = Path(self.temp.name) / 'event.json'
        event.write_text(json.dumps({'number': 7, 'pull_request': {'head': {'sha': H}, 'base': {'sha': B}}}))
        self.env = {'GITHUB_REPOSITORY': REPO, 'GITHUB_RUN_ID': str(RUN), 'GITHUB_RUN_ATTEMPT': '1',
                    'GITHUB_EVENT_NAME': 'pull_request', 'GITHUB_EVENT_PATH': str(event),
                    'GITHUB_SHA': S, 'QSH_GATE_VISIBILITY_SECONDS': '0',
                    'QSH_JOB_WORKFLOW_REF': REPO + '/.github/workflows/ci.yml@refs/pull/7/merge'}

    def record(self, lanes, **extra):
        value = {'schema': 1, 'policy_digest': DIGEST, 'context': 'top-level', 'mode': 'selected',
                 'lanes': sorted(lanes), 'source': S, 'api_head': H, 'base': B, 'deferred': [],
                 'delegated': []}
        value.update(extra)
        return json.dumps(value)

    def needs(self, lanes, called=False, **override):
        result = {'select': 'success', 'policy': 'success'}
        for lane, spec_ in POLICY['lanes'].items():
            if spec_['workflow'] == gate.CI:
                result[spec_['job']] = 'success' if lane in lanes else 'skipped'
        for call in gate.CALLS:
            wanted = any(POLICY['lanes'][lane]['workflow'] == gate.CALLERS[call] for lane in lanes)
            result[call] = 'success' if wanted and not called else 'skipped'
        result.update(override)
        return json.dumps({key: {'result': value, 'outputs': {}} for key, value in result.items()})

    def pr_jobs(self, lanes, overrides=None):
        jobs = [job('Select CI lanes'), job('Selection policy controls'),
                job('CI gate', status='in_progress')]
        for lane in ('check', 'container', 'docs'):
            name = POLICY['lanes'][lane]['cells'][0]
            jobs.append(job(name, 'success' if lane in lanes else 'skipped'))
        if 'macos' in lanes:
            jobs += [job(cell) for cell in POLICY['lanes']['macos']['cells']]
        else:
            # GitHub reports a skipped job named by one whole expression by
            # that bare expression (CI run 44271528690).
            jobs.append(job('matrix.name', 'skipped'))
        native = [lane for lane in lanes if POLICY['lanes'][lane]['workflow'] == gate.CALLERS['native-crypto']]
        if native:
            jobs += [job('native-crypto / Validate native lanes'), job('native-crypto / Validate manual mode', 'skipped'),
                     job("native-crypto / PTY EOF ${{ (((inputs.mode == 'pty-eof-build') && 'build') || 'control') }}"
                         " (${{ matrix.target }})", 'skipped')]
            for lane in ('native', 'intel-owner', 'intel-legacy', 'floors'):
                if lane in lanes:
                    jobs += [job('native-crypto / ' + cell) for cell in POLICY['lanes'][lane]['cells']]
                else:
                    template = {'native': 'Native ${{ matrix.target }}', 'floors':
                                'Native system floor (${{ matrix.format }})'}.get(lane, 'matrix.name')
                    jobs.append(job('native-crypto / ' + template, 'skipped'))
        else:
            jobs.append(job('native-crypto', 'skipped'))
        jobs.append(job('released-peer-acceptance / released-peers') if 'peers' in lanes
                    else job('released-peer-acceptance', 'skipped'))
        jobs.append(job('fuzz / Build and smoke the parser fuzz targets') if 'fuzz' in lanes else job('fuzz', 'skipped'))
        for name, value in (overrides or {}).items():
            for item in jobs:
                if item['name'] == name:
                    item.update(value)
        return jobs

    def run_payload(self, path='.github/workflows/ci.yml', event='pull_request', head=H, attempt=1):
        return {'id': RUN, 'run_attempt': attempt, 'event': event, 'head_sha': head, 'path': path,
                'workflow_id': 1, 'repository': {'full_name': REPO}}

    def gate_run(self, context, api, record, needs, source=(S, [B, H])):
        env = dict(self.env, QSH_GATE_RECORD=record, QSH_GATE_NEEDS=needs)
        return gate.Gate(context, env, api, sleep=lambda seconds: None, source=source).run()


class PullRequestGateTests(GateHarness):
    def test_selected_boundary_lanes_pass_with_head_and_merge_identities_distinct(self):
        lanes = {'check', 'container'}
        result = self.gate_run('ci', FakeApi(self.run_payload(), self.pr_jobs(lanes)), self.record(lanes), self.needs(lanes))
        self.assertEqual(result['result'], 'PASS', result['failures'])
        self.assertEqual((result['source'], result['api_head'], result['base']), (S, H, B))
        self.assertEqual(result['lanes']['macos'], 'NOT_APPLICABLE')
        self.assertEqual({cell['name'] for cell in result['cells']} >= {'check', 'container'}, True)

    def test_comparing_api_head_with_the_merge_would_be_wrong(self):
        lanes = {'check', 'container'}
        api = FakeApi(self.run_payload(head=S), self.pr_jobs(lanes))
        with self.assertRaises(gate.GateError):
            self.gate_run('ci', api, self.record(lanes), self.needs(lanes))

    def test_full_pull_request_selection_passes(self):
        lanes = set(POLICY['lanes'])
        result = self.gate_run('ci', FakeApi(self.run_payload(), self.pr_jobs(lanes)), self.record(lanes, mode='full'),
                               self.needs(lanes))
        self.assertEqual(result['result'], 'PASS', result['failures'])
        self.assertEqual(len(result['cells']), sum(len(s['cells']) for s in POLICY['lanes'].values()))

    def test_failed_cancelled_and_missing_required_cells_fail(self):
        lanes = {'check', 'container', 'macos'}
        for change in ({'conclusion': 'failure'}, {'conclusion': 'cancelled'}, {'conclusion': 'skipped'}):
            with self.subTest(change=change):
                jobs = self.pr_jobs(lanes, {'macOS 26 portable tests': change})
                result = self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))
                self.assertEqual(result['result'], 'FAIL')
        jobs = [j for j in self.pr_jobs(lanes) if j['name'] != 'macOS 26 portable tests']
        result = self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))
        self.assertIn('UNRESOLVED macOS 26 portable tests', result['failures'])

    def test_required_skipped_template_fails_and_non_required_template_passes(self):
        lanes = {'check', 'container', 'native', 'intel-owner'}
        jobs = self.pr_jobs(lanes - {'intel-owner'})
        result = self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))
        self.assertEqual(result['result'], 'FAIL')
        self.assertTrue(any(f.startswith('UNRESOLVED native-crypto / Native Intel Darwin process owner')
                            for f in result['failures']), result['failures'])

    def test_unknown_jobs_fail_inside_and_outside_owned_prefixes(self):
        lanes = {'check', 'container'}
        for name in ('surprise', 'native-crypto / surprise', 'elsewhere / job'):
            with self.subTest(name=name):
                jobs = self.pr_jobs(lanes) + [job(name)]
                result = self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))
                self.assertIn('UNKNOWN_JOB ' + name, result['failures'])

    def test_duplicate_cell_fails(self):
        lanes = {'check', 'container'}
        jobs = self.pr_jobs(lanes) + [job('check')]
        result = self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))
        self.assertIn('DUPLICATE check', result['failures'])

    def test_not_required_lane_that_ran_must_succeed(self):
        lanes = {'check', 'container'}
        jobs = self.pr_jobs(lanes, {'Documentation controls': {'conclusion': 'failure'}})
        result = self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))
        self.assertIn('NOT_REQUIRED_BUT_FAILED Documentation controls', result['failures'])

    def test_selection_and_policy_failures_fail(self):
        lanes = {'check', 'container'}
        api = FakeApi(self.run_payload(), self.pr_jobs(lanes))
        for record, needs in ((self.record(lanes), self.needs(lanes, select='failure')),
                              ('', self.needs(lanes)), ('{bad', self.needs(lanes)),
                              (self.record(lanes, policy_digest='0' * 64), self.needs(lanes)),
                              (self.record(lanes, source=H), self.needs(lanes)),
                              (self.record(lanes), self.needs(lanes, policy='failure')),
                              (self.record(lanes), self.needs(lanes, docs='success'))):
            with self.subTest(record=record[:40], needs=needs[:60]):
                self.assertEqual(self.gate_run('ci', api, record, needs)['result'], 'FAIL')

    def test_in_progress_record_past_the_budget_is_unresolved(self):
        lanes = {'check', 'container'}
        jobs = self.pr_jobs(lanes, {'container': {'status': 'in_progress', 'conclusion': None}})
        result = self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))
        self.assertIn('UNRESOLVED container', result['failures'])

    def test_late_visibility_resolves_within_the_budget(self):
        lanes = {'check', 'container'}
        snapshots = [self.pr_jobs(lanes, {'container': {'status': 'in_progress', 'conclusion': None}}),
                     self.pr_jobs(lanes)]
        state = {'n': 0}

        def latest():
            state['n'] += 1
            return snapshots[0] if state['n'] == 1 else snapshots[1]
        env = dict(self.env, QSH_GATE_RECORD=self.record(lanes), QSH_GATE_NEEDS=self.needs(lanes),
                   QSH_GATE_VISIBILITY_SECONDS='60')
        api = FakeApi(self.run_payload(), latest, history=lambda: snapshots[1])
        result = gate.Gate('ci', env, api, sleep=lambda seconds: None, source=(S, [B, H])).run()
        self.assertEqual(result['result'], 'PASS', result['failures'])

    def test_completed_record_without_a_conclusion_is_still_pending(self):
        # GitHub can list a job as completed before its conclusion is visible.
        lanes = {'check', 'container'}
        unsettled = {'container': {'status': 'completed', 'conclusion': None}}
        snapshots = [self.pr_jobs(lanes, unsettled), self.pr_jobs(lanes)]
        state = {'n': 0}

        def latest():
            state['n'] += 1
            return snapshots[0] if state['n'] == 1 else snapshots[1]
        env = dict(self.env, QSH_GATE_RECORD=self.record(lanes), QSH_GATE_NEEDS=self.needs(lanes),
                   QSH_GATE_VISIBILITY_SECONDS='60')
        api = FakeApi(self.run_payload(), latest, history=lambda: snapshots[1])
        result = gate.Gate('ci', env, api, sleep=lambda seconds: None, source=(S, [B, H])).run()
        self.assertEqual(result['result'], 'PASS', result['failures'])
        self.assertGreater(state['n'], 1)
        # A conclusion that never appears stays unresolved, never a pass.
        env = dict(env, QSH_GATE_VISIBILITY_SECONDS='0')
        stuck = self.pr_jobs(lanes, unsettled)
        result = gate.Gate('ci', env, FakeApi(self.run_payload(), stuck), sleep=lambda seconds: None,
                           source=(S, [B, H])).run()
        self.assertEqual(result['result'], 'FAIL')
        self.assertIn('UNRESOLVED container', result['failures'])
        self.assertFalse(any(f.startswith('FAILED container') for f in result['failures']))

    def test_pagination_reads_every_page_and_refuses_truncation(self):
        lanes = {'check', 'container'}
        jobs = self.pr_jobs(lanes)
        api = FakeApi(self.run_payload(), jobs)
        self.assertEqual(len(gate.all_jobs(api, REPO, RUN, 'latest')), len(jobs))

        class Truncated(FakeApi):
            def get(self, path, params=None):
                payload = super().get(path, params)
                if path.endswith('/jobs'):
                    payload['total_count'] += 1
                return payload
        with self.assertRaises(gate.GateError):
            gate.all_jobs(Truncated(self.run_payload(), jobs), REPO, RUN, 'latest')
        many = [job('x' + str(n)) for n in range(230)]
        self.assertEqual(len(gate.all_jobs(FakeApi(self.run_payload(), many), REPO, RUN, 'all')), 230)

    def test_api_failure_fails_the_gate(self):
        env = dict(self.env, QSH_GATE_RECORD=self.record({'check'}), QSH_GATE_NEEDS=self.needs({'check'}))
        with self.assertRaises(gate.GateError):
            gate.Gate('ci', env, FakeApi(None, [], fail=True), source=(S, [B, H])).run()

    def test_run_from_another_workflow_or_head_fails(self):
        lanes = {'check', 'container'}
        for payload in (self.run_payload(path='.github/workflows/release.yml'), self.run_payload(attempt=2),
                        self.run_payload(event='push')):
            with self.subTest(payload=payload), self.assertRaises(gate.GateError):
                self.gate_run('ci', FakeApi(payload, self.pr_jobs(lanes)), self.record(lanes), self.needs(lanes))
        jobs = self.pr_jobs(lanes)
        jobs[0]['head_sha'] = S
        with self.assertRaises(gate.GateError):
            self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))

    def test_gate_job_must_be_defined_by_its_workflow(self):
        lanes = {'check', 'container'}
        env = dict(self.env, QSH_GATE_RECORD=self.record(lanes), QSH_GATE_NEEDS=self.needs(lanes),
                   QSH_JOB_WORKFLOW_REF=REPO + '/.github/workflows/other.yml@refs/pull/7/merge')
        with self.assertRaises(gate.GateError):
            gate.Gate('ci', env, FakeApi(self.run_payload(), self.pr_jobs(lanes)), source=(S, [B, H])).run()

    def test_merge_parents_must_name_the_event_head(self):
        lanes = {'check', 'container'}
        with self.assertRaises(gate.GateError):
            self.gate_run('ci', FakeApi(self.run_payload(), self.pr_jobs(lanes)), self.record(lanes),
                          self.needs(lanes), source=(S, [B, 'd' * 40]))


class RerunTests(GateHarness):
    """Partial reruns, from CI run 43700703996 where only container re-ran."""

    def test_recorded_rerun_distinguishes_retained_and_new_executions(self):
        latest = fixture('jobs-ci-rerun-latest.json')['jobs']
        history = fixture('jobs-ci-rerun-all.json')['jobs']
        gate.check_history(latest, history, 2)
        cells = {item['name']: gate.cell_record('x', item['name'], item, history) for item in latest}
        self.assertEqual((cells['container']['retained'], cells['container']['executed_in_attempt']), (False, 2))
        for name in ('check', 'macOS portable tests', 'macOS 26 portable tests'):
            self.assertEqual((cells[name]['retained'], cells[name]['executed_in_attempt']), (True, 1), name)

    def test_recorded_rerun_rejects_an_older_attempt_view(self):
        latest = fixture('jobs-ci-rerun-latest.json')['jobs']
        history = fixture('jobs-ci-rerun-all.json')['jobs']
        with self.assertRaises(gate.GateError):
            gate.check_history(latest, history, 1)
        older = [dict(item, run_attempt=1) if item['name'] == 'container' else item for item in latest]
        with self.assertRaises(gate.GateError):
            gate.check_history(older, history, 2)

    def test_newer_failure_wins_over_an_older_success(self):
        lanes = {'check', 'container'}
        first = self.pr_jobs(lanes)
        second = self.pr_jobs(lanes, {'container': {'conclusion': 'failure', 'started_at': '2026-11-16T11:00:00Z'}})
        for item in second:
            item['run_attempt'] = 2
        env = dict(self.env, GITHUB_RUN_ATTEMPT='2', QSH_GATE_RECORD=self.record(lanes), QSH_GATE_NEEDS=self.needs(lanes))
        api = FakeApi(self.run_payload(attempt=2), second, history=first + second)
        result = gate.Gate('ci', env, api, sleep=lambda s: None, source=(S, [B, H])).run()
        self.assertIn('FAILED container failure', result['failures'])
        # The failed cell stays in the record with the attempt that executed it.
        cells = {cell['name']: cell for cell in result['cells']}
        self.assertEqual((cells['container']['conclusion'], cells['container']['retained'],
                          cells['container']['executed_in_attempt']), ('failure', False, 2))
        self.assertEqual((cells['check']['retained'], cells['check']['executed_in_attempt']), (True, 1))

    def test_rerun_with_retained_successes_passes_and_reports_them(self):
        lanes = {'check', 'container'}
        first = self.pr_jobs(lanes, {'container': {'conclusion': 'failure'}})
        second = self.pr_jobs(lanes, {'container': {'started_at': '2026-11-16T11:00:00Z'}})
        for item in second:
            item['run_attempt'] = 2
        env = dict(self.env, GITHUB_RUN_ATTEMPT='2', QSH_GATE_RECORD=self.record(lanes), QSH_GATE_NEEDS=self.needs(lanes))
        api = FakeApi(self.run_payload(attempt=2), second, history=first + second)
        result = gate.Gate('ci', env, api, sleep=lambda s: None, source=(S, [B, H])).run()
        self.assertEqual(result['result'], 'PASS', result['failures'])
        cells = {cell['name']: cell for cell in result['cells']}
        self.assertEqual((cells['check']['retained'], cells['check']['executed_in_attempt']), (True, 1))
        self.assertEqual((cells['container']['retained'], cells['container']['executed_in_attempt']), (False, 2))


class RecordedNamingTests(GateHarness):
    def test_recorded_native_names_match_the_policy_and_normalized_templates(self):
        jobs = fixture('jobs-native-pull-request.json')['jobs']
        texts = {path: (ROOT / path).read_text() for path in set(gate.CALLERS.values())}
        expected = gate.Expectation(POLICY, gate.CALLERS['native-crypto'], texts,
                                    {'native', 'intel-owner', 'intel-legacy', 'floors'})
        groups = {'native-crypto': expected}
        prefixed = [dict(item, name='native-crypto / ' + item['name'], head_sha=H) for item in jobs]
        failures, pending, cells = gate.evaluate(groups, prefixed, prefixed, 1, ('', 'none'), set(), False)
        self.assertEqual(failures, [])
        self.assertEqual(pending, [])
        self.assertEqual(len(cells), 10)

    def test_recorded_main_smoke_accounts_for_the_bare_skipped_macos_matrix(self):
        recorded = fixture('jobs-ci-main-smoke.json')['jobs']
        self.assertIn(('matrix.name', 'skipped'), [(item['name'], item['conclusion']) for item in recorded])
        source, run_id = recorded[0]['head_sha'], recorded[0]['run_id']
        jobs = [dict(item, status='in_progress', conclusion=None, completed_at=None)
                if item['name'] == 'CI gate' else item for item in recorded]
        smoke = {'check', 'container', 'docs'}
        record = self.record(smoke, mode='smoke', source=source, api_head=source, base=None,
                             deferred=sorted(set(POLICY['lanes']) - smoke))
        env = dict(self.env, GITHUB_EVENT_NAME='push', GITHUB_SHA=source, GITHUB_RUN_ID=str(run_id),
                   QSH_JOB_WORKFLOW_REF=REPO + '/.github/workflows/ci.yml@refs/heads/main',
                   QSH_GATE_RECORD=record, QSH_GATE_NEEDS=self.needs(smoke))
        run = dict(self.run_payload(event='push', head=source), id=run_id)
        result = gate.Gate('ci', env, FakeApi(run, jobs), sleep=lambda s: None, source=(source, [B])).run()
        self.assertEqual(result['result'], 'PASS', result['failures'])
        self.assertEqual(result['lanes']['macos'], 'DEFERRED_TO_NIGHTLY')
        self.assertEqual({cell['name'] for cell in result['cells']}, {'check', 'container', 'Documentation controls'})

    def test_whole_expression_templates_accept_only_skipped_bare_records_of_their_group(self):
        lanes = {'check', 'container', 'native'}
        jobs = self.pr_jobs(lanes)
        self.assertEqual([item['name'] for item in jobs].count('native-crypto / matrix.name'), 2)
        result = self.gate_run('ci', FakeApi(self.run_payload(), jobs), self.record(lanes), self.needs(lanes))
        self.assertEqual(result['result'], 'PASS', result['failures'])
        braced = [dict(item, name='native-crypto / ${{ matrix.name }}') if item['name'] == 'native-crypto / matrix.name'
                  else item for item in jobs]
        result = self.gate_run('ci', FakeApi(self.run_payload(), braced), self.record(lanes), self.needs(lanes))
        self.assertEqual(result['result'], 'PASS', result['failures'])
        cases = (
            (jobs + [job('native-crypto / matrix.name', 'skipped')], 'DUPLICATE_TEMPLATE native-crypto / …'),
            (self.pr_jobs(lanes, {'native-crypto / matrix.name': {'conclusion': 'success'}}),
             'TEMPLATE_NOT_SKIPPED native-crypto / …'),
            (jobs + [job('native-crypto / matrix.other', 'skipped')], 'UNKNOWN_JOB native-crypto / matrix.other'),
            (jobs + [job('fuzz / matrix.name', 'skipped')], 'UNKNOWN_JOB fuzz / matrix.name'),
        )
        for changed, failure in cases:
            with self.subTest(failure=failure):
                result = self.gate_run('ci', FakeApi(self.run_payload(), changed), self.record(lanes), self.needs(lanes))
                self.assertIn(failure, result['failures'])

    def test_recorded_release_dispatch_skips_the_ordinary_ci_call_by_name(self):
        jobs = fixture('jobs-release-branch-dispatch.json')['jobs']
        self.assertIn(('ordinary-ci', 'skipped'), [(item['name'], item['conclusion']) for item in jobs])
        template = [item['name'] for item in jobs if 'PTY EOF' in item['name']][0]
        admin = POLICY['administrative'][gate.CALLERS['native-crypto']]['pty-eof-diagnostic']['name']
        self.assertEqual(gate.shape(template), gate.shape('native-crypto / ' + admin))


class ReleaseGateTests(GateHarness):
    def release_jobs(self, overrides=None):
        lanes = set(POLICY['lanes'])
        jobs = [job('linux (ubuntu-24.04, x86_64-unknown-linux-musl)'), job('release'), job('publish', 'skipped'),
                job('Release qualification', status='in_progress'),
                job('ordinary-ci / Select CI lanes'), job('ordinary-ci / Selection policy controls'),
                job('ordinary-ci / CI gate'), job('ordinary-ci / native-crypto', 'skipped'),
                job('ordinary-ci / released-peer-acceptance', 'skipped'), job('ordinary-ci / fuzz', 'skipped'),
                job('native-crypto / Validate native lanes'), job('native-crypto / Validate manual mode', 'skipped'),
                job("native-crypto / PTY EOF ${{ (((inputs.mode == 'pty-eof-build') && 'build') || 'control') }}"
                    " (${{ matrix.target }})", 'skipped')]
        for lane in sorted(lanes):
            prefix = {gate.CI: 'ordinary-ci / '}.get(POLICY['lanes'][lane]['workflow']) or next(
                c for c in gate.CALLS if gate.CALLERS[c] == POLICY['lanes'][lane]['workflow']) + ' / '
            jobs += [job(prefix + cell, head=S) for cell in POLICY['lanes'][lane]['cells']]
        for item in jobs:
            item['head_sha'] = S
            item.update((overrides or {}).get(item['name'], {}))
        return jobs

    def release_env(self):
        record = json.dumps({'schema': 1, 'policy_digest': DIGEST, 'context': 'called', 'mode': 'called',
                             'lanes': ['check', 'container', 'docs', 'macos'], 'source': S, 'api_head': S})
        needs = json.dumps({call: {'result': 'success'} for call in gate.CALLERS})
        return dict(self.env, GITHUB_EVENT_NAME='push', QSH_GATE_RECORD=record, QSH_GATE_NEEDS=needs,
                    QSH_JOB_WORKFLOW_REF=REPO + '/.github/workflows/release.yml@refs/tags/v9.9.9')

    def run_release(self, jobs, env=None):
        api = FakeApi(self.run_payload('.github/workflows/release.yml', 'push', S), jobs)
        return gate.Gate('release', env or self.release_env(), api, sleep=lambda s: None, source=(S, [B])).run()

    def test_full_release_qualification_passes_and_ignores_release_build_jobs(self):
        result = self.run_release(self.release_jobs())
        self.assertEqual(result['result'], 'PASS', result['failures'])
        self.assertEqual(result['mode'], 'full')
        self.assertEqual(len(result['cells']), sum(len(s['cells']) for s in POLICY['lanes'].values()))

    def test_every_missing_or_failed_cell_blocks_release(self):
        for lane, spec_ in POLICY['lanes'].items():
            prefix = 'ordinary-ci / ' if spec_['workflow'] == gate.CI else next(
                c for c in gate.CALLS if gate.CALLERS[c] == spec_['workflow']) + ' / '
            name = prefix + spec_['cells'][-1]
            with self.subTest(lane=lane):
                failed = self.run_release(self.release_jobs({name: {'conclusion': 'failure'}}))
                self.assertEqual(failed['result'], 'FAIL')
                missing = self.run_release([j for j in self.release_jobs() if j['name'] != name])
                self.assertIn('UNRESOLVED ' + name, missing['failures'])

    def test_called_ci_gate_and_records_are_required(self):
        failed = self.run_release(self.release_jobs({'ordinary-ci / CI gate': {'conclusion': 'failure'}}))
        self.assertEqual(failed['result'], 'FAIL')
        env = self.release_env()
        env['QSH_GATE_RECORD'] = json.dumps({'schema': 1, 'policy_digest': DIGEST, 'context': 'top-level',
                                             'lanes': ['check'], 'source': S})
        self.assertIn('CALLED_CI_RECORD_INVALID', self.run_release(self.release_jobs(), env)['failures'])
        env = self.release_env()
        env['QSH_GATE_NEEDS'] = json.dumps(dict({c: {'result': 'success'} for c in gate.CALLERS},
                                                fuzz={'result': 'skipped'}))
        self.assertIn('NEEDS_NOT_SUCCESSFUL fuzz skipped', self.run_release(self.release_jobs(), env)['failures'])

    def test_called_ci_gate_owns_only_its_prefix(self):
        record = json.dumps({'schema': 1, 'policy_digest': DIGEST, 'context': 'called', 'mode': 'called',
                             'lanes': ['check', 'container', 'docs', 'macos'], 'source': S, 'api_head': S,
                             'delegated': ['fuzz', 'peers']})
        needs = {'select': 'success', 'policy': 'success', 'docs': 'success', 'check': 'success',
                 'container': 'success', 'macos': 'success', 'native-crypto': 'skipped',
                 'released-peer-acceptance': 'skipped', 'fuzz': 'skipped'}
        jobs = self.release_jobs({'ordinary-ci / CI gate': {'status': 'in_progress', 'conclusion': None},
                                  'Release qualification': {'status': 'queued', 'conclusion': None,
                                                            'name': 'Release qualification'}})
        jobs = [j for j in jobs if j['name'] != 'Release qualification'] + [job('Release qualification', 'skipped', head=S)]
        env = dict(self.env, GITHUB_EVENT_NAME='push', QSH_GATE_RECORD=record,
                   QSH_GATE_NEEDS=json.dumps({k: {'result': v} for k, v in needs.items()}))
        api = FakeApi(self.run_payload('.github/workflows/release.yml', 'push', S), jobs)
        result = gate.Gate('ci', env, api, sleep=lambda s: None, source=(S, [B])).run()
        self.assertEqual(result['result'], 'PASS', result['failures'])
        self.assertEqual(result['lanes']['fuzz'], 'DELEGATED_TO_CALLER')
        self.assertEqual({c['name'] for c in result['cells']},
                         {'ordinary-ci / ' + c for lane in ('check', 'container', 'docs', 'macos')
                          for c in POLICY['lanes'][lane]['cells']})


class FreshnessTests(GateHarness):
    def receipt(self, **change):
        cells = []
        for lane, spec_ in POLICY['lanes'].items():
            prefix = 'ordinary-ci / ' if spec_['workflow'] == gate.CI else next(
                c for c in gate.CALLS if gate.CALLERS[c] == spec_['workflow']) + ' / '
            cells += [{'lane': lane, 'name': prefix + cell, 'conclusion': 'success'} for cell in spec_['cells']]
        value = {'schema': 1, 'kind': 'qsh-ci-qualification', 'context': 'nightly', 'mode': 'full', 'result': 'PASS',
                 'policy_digest': DIGEST, 'source': S, 'repository': REPO, 'run_id': 77, 'run_attempt': 1,
                 'workflow_path': '.github/workflows/nightly.yml', 'cells': cells}
        value.update(change)
        return value

    def api(self, receipt, run=None, name='nightly-qualification-77-1', files=('qualification.json',)):
        run = run or {'id': 77, 'run_attempt': 1, 'path': '.github/workflows/nightly.yml', 'event': 'schedule',
                      'conclusion': 'success', 'head_sha': S, 'repository': {'full_name': REPO},
                      'head_repository': {'full_name': REPO}}
        data = io.BytesIO()
        with zipfile.ZipFile(data, 'w') as archive:
            for item in files:
                archive.writestr(item, json.dumps(receipt))
        return FakeApi(None, [], runs={'workflow_runs': [run]},
                       artifacts={'77': [{'id': 5, 'name': name, 'expired': False}]}, archives={'5': data.getvalue()})

    def find(self, api):
        return gate.trusted_evidence(POLICY, api, REPO, S, DIGEST)

    def test_trusted_full_evidence_is_reused(self):
        evidence = self.find(self.api(self.receipt()))
        self.assertEqual(evidence['run_id'], 77)

    def test_reduced_or_untrusted_evidence_is_refused(self):
        refusals = {
            'selected PR gate': self.api(self.receipt(mode='selected')),
            'main smoke': self.api(self.receipt(mode='smoke')),
            'reused record': self.api(self.receipt(mode='reused')),
            'failed result': self.api(self.receipt(result='FAIL')),
            'policy digest': self.api(self.receipt(policy_digest='0' * 64)),
            'other source': self.api(self.receipt(source=H)),
            'other run': self.api(self.receipt(run_id=78)),
            'other attempt': self.api(self.receipt(run_attempt=2)),
            'missing cell': self.api(self.receipt(cells=self.receipt()['cells'][1:])),
            'pull request event': self.api(self.receipt(), run={'id': 77, 'run_attempt': 1, 'event': 'pull_request',
                                                                 'path': '.github/workflows/nightly.yml',
                                                                 'conclusion': 'success', 'head_sha': S,
                                                                 'repository': {'full_name': REPO},
                                                                 'head_repository': {'full_name': REPO}}),
            'fork head': self.api(self.receipt(), run={'id': 77, 'run_attempt': 1, 'event': 'schedule',
                                                        'path': '.github/workflows/nightly.yml',
                                                        'conclusion': 'success', 'head_sha': S,
                                                        'repository': {'full_name': REPO},
                                                        'head_repository': {'full_name': 'fork/qsh'}}),
            'untrusted workflow': self.api(self.receipt(), run={'id': 77, 'run_attempt': 1, 'event': 'schedule',
                                                                 'path': '.github/workflows/other.yml',
                                                                 'conclusion': 'success', 'head_sha': S,
                                                                 'repository': {'full_name': REPO},
                                                                 'head_repository': {'full_name': REPO}}),
            'artifact for another attempt': self.api(self.receipt(), name='nightly-qualification-77-2'),
            'extra archive member': self.api(self.receipt(), files=('qualification.json', 'other')),
        }
        for name, api in refusals.items():
            with self.subTest(case=name):
                self.assertIsNone(self.find(api))

    def test_manual_nightly_and_api_errors_run_the_matrix(self):
        env = dict(self.env, GITHUB_EVENT_NAME='workflow_dispatch')
        self.assertEqual(gate.freshness(env, self.api(self.receipt()), POLICY), (None, 'MANUAL_RUN'))
        env = dict(self.env, GITHUB_EVENT_NAME='schedule')
        evidence, reason = gate.freshness(env, FakeApi(None, [], fail=True), POLICY)
        self.assertIsNone(evidence)
        self.assertTrue(reason.startswith('EVIDENCE_UNAVAILABLE'))


if __name__ == '__main__':
    unittest.main()
