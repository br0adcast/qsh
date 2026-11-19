"""Workflow contract of the CI lane selection (#609).

Text controls over the actual workflow files: canonical lane conditions,
cell names rendered from matrices, triggers, concurrency, permissions, the
release and nightly call graphs, and the native lane validator executed
against the input values whose meaning the review fixed.
"""
import importlib.util
import itertools
import json
from pathlib import Path
import re
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('qsh_ci_select', ROOT / 'scripts/ci-select.py')
select = importlib.util.module_from_spec(spec)
spec.loader.exec_module(select)
POLICY = select.load_policy(ROOT)
WORKFLOWS = ROOT / '.github/workflows'
CI, NATIVE = '.github/workflows/ci.yml', '.github/workflows/native-crypto.yml'
PEERS, FUZZ = '.github/workflows/released-peer-acceptance.yml', '.github/workflows/fuzz.yml'
RELEASE, NIGHTLY = '.github/workflows/release.yml', '.github/workflows/nightly.yml'
GUARD = "github.event_name == 'workflow_dispatch' && (inputs.mode == 'pty-eof-build' || inputs.mode == 'pty-eof-control')"
FULL_NATIVE = '["floors","intel-legacy","intel-owner","portable"]'
CALLS = {'native-crypto': NATIVE, 'released-peer-acceptance': PEERS, 'fuzz': FUZZ}


def text(path):
    return (ROOT / path).read_text()


def jobs(path):
    return select.workflow_jobs(text(path))


def code(body):
    return [line for line in body.splitlines() if line.strip() and not line.strip().startswith('#')]


def header(body, key):
    found = re.findall(r'(?m)^    ' + re.escape(key) + r': (.*)$', body)
    return found[0] if len(found) == 1 else None


def triggers(source):
    block = source.split('\non:\n', 1)[1].split('\n\n', 1)[0]
    return re.findall(r'(?m)^  ([a-z_]+):', block)


def matrix(body):
    """Combinations of a job's matrix: `include` items or scalar lists."""
    found = re.search(r'(?m)^      matrix:\n((?:        .*\n|\s*\n|\s*#.*\n)+)', body)
    if not found:
        return [{}]
    block = found.group(1)
    if '        include:\n' in block:
        items, current = [], None
        for line in block.split('        include:\n', 1)[1].splitlines():
            item = re.match(r'^          - ([a-z_]+): (.*)$', line)
            field = re.match(r'^            ([a-z_]+): (.*)$', line)
            if item:
                current = {item.group(1): item.group(2)}
                items.append(current)
            elif field and current is not None:
                current[field.group(1)] = field.group(2)
        return items
    axes = re.findall(r'(?m)^        ([a-z_]+): \[(.*)\]$', block)
    names = [name for name, _ in axes]
    values = [[v.strip() for v in raw.split(',')] for _, raw in axes]
    return [dict(zip(names, combination)) for combination in itertools.product(*values)]


def render(template, values):
    return re.sub(r'\$\{\{ matrix\.([a-z_]+) \}\}', lambda m: values[m.group(1)], template)


class LaneContractTests(unittest.TestCase):
    def test_policy_cells_are_the_rendered_matrix_names(self):
        for lane, spec_ in POLICY['lanes'].items():
            with self.subTest(lane=lane):
                body = jobs(spec_['workflow'])[spec_['job']]
                name = header(body, 'name') or spec_['job']
                rendered = [render(name, values) for values in matrix(body)]
                self.assertEqual(sorted(rendered), sorted(spec_['cells']))
                self.assertEqual(len(set(rendered)), len(rendered))

    def test_every_job_of_a_lane_workflow_is_a_lane_call_or_administrative(self):
        for path in {spec_['workflow'] for spec_ in POLICY['lanes'].values()}:
            lane_jobs = {spec_['job'] for spec_ in POLICY['lanes'].values() if spec_['workflow'] == path}
            admin = set(POLICY['administrative'][path])
            calls = set(CALLS) if path == CI else set()
            self.assertEqual(set(jobs(path)), lane_jobs | admin | calls, path)
            for job, spec_ in POLICY['administrative'][path].items():
                self.assertEqual(header(jobs(path)[job], 'name'), spec_['name'], job)

    def test_ci_lane_and_call_conditions_are_canonical(self):
        ci = jobs(CI)
        for lane, spec_ in POLICY['lanes'].items():
            if spec_['workflow'] == CI:
                body = ci[spec_['job']]
                self.assertEqual(header(body, 'needs'), 'select')
                self.assertEqual(header(body, 'if'),
                                 "${{ contains(fromJSON(needs.select.outputs.lanes), '" + lane + "') }}")
        for call, path in CALLS.items():
            body = ci[call]
            self.assertEqual(header(body, 'if'), "${{ contains(fromJSON(needs.select.outputs.calls), '" + call + "') }}")
            self.assertEqual(header(body, 'uses'), './' + path)
        self.assertIn('      lanes: ${{ needs.select.outputs.native_lanes }}\n', ci['native-crypto'])
        readers = {job for job, body in ci.items() if 'needs.select.outputs.' in body}
        lane_jobs = {spec_['job'] for spec_ in POLICY['lanes'].values() if spec_['workflow'] == CI}
        self.assertEqual(readers, lane_jobs | set(CALLS) | {'gate'})
        self.assertEqual(re.findall(r'needs\.select\.outputs\.(\w+)', ci['gate']), ['record'])
        for job in ('select', 'policy'):
            self.assertIsNone(header(ci[job], 'if'), job)
            self.assertIsNone(header(ci[job], 'needs'), job)

    def test_native_lane_conditions_and_inputs_are_canonical(self):
        native = jobs(NATIVE)
        for lane, spec_ in POLICY['lanes'].items():
            if spec_['workflow'] == NATIVE:
                self.assertEqual(native[spec_['job']].splitlines()[0],
                                 "    if: ${{ !(" + GUARD + ") && contains(fromJSON(inputs.lanes), '"
                                 + spec_['input'] + "') }}")
                self.assertIsNone(header(native[spec_['job']], 'needs'))
        readers = {job for job, body in native.items() if 'inputs.lanes' in body}
        self.assertEqual(readers, {POLICY['lanes'][l]['job'] for l in POLICY['lanes']
                                   if POLICY['lanes'][l]['workflow'] == NATIVE} | {'lanes'})
        source = text(NATIVE)
        for entry in ('workflow_dispatch', 'workflow_call'):
            block = source.split('  ' + entry + ':\n', 1)[1].split('\n  workflow_', 1)[0].split('\npermissions:', 1)[0]
            lanes = re.search(r'(?m)^      lanes:\n((?:        .*\n)+)', block + '\n').group(1)
            self.assertIn("        default: '" + FULL_NATIVE + "'\n", lanes)
            self.assertIn('        type: string\n        required: false\n', lanes)
        self.assertEqual(json.loads(FULL_NATIVE), sorted(spec_['input'] for spec_ in POLICY['lanes'].values()
                                                         if 'input' in spec_))

    def test_native_lane_validator_meanings(self):
        body = jobs(NATIVE)['lanes']
        script = body.split("python3 -I -B - <<'PY_LANES'\n", 1)[1].split('          PY_LANES', 1)[0]
        script = '\n'.join(line[10:] for line in script.splitlines())
        cases = {FULL_NATIVE: True, '[]': True, '["portable"]': True, '["floors","portable"]': True,
                 '': False, 'true': False, 'null': False, '["Portable"]': False, '["portabl"]': False,
                 '["portable","portable"]': False, '["portable","floors"]': False, '{"portable":1}': False,
                 '[ "portable" ]': False, '["portable",': False}
        for value, accepted in cases.items():
            with self.subTest(value=value):
                result = subprocess.run(['python3', '-I', '-B', '-c', script], capture_output=True, text=True,
                                        env={'PATH': '/usr/bin:/bin', 'QSH_NATIVE_LANES': value}, timeout=20)
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)

    def test_called_workflows_have_no_independent_branch_triggers(self):
        self.assertEqual(triggers(text(NATIVE)), ['workflow_dispatch', 'workflow_call'])
        self.assertEqual(triggers(text(PEERS)), ['workflow_dispatch', 'workflow_call'])
        self.assertEqual(triggers(text(FUZZ)), ['workflow_dispatch', 'workflow_call'])
        self.assertEqual(triggers(text(CI)), ['push', 'pull_request', 'workflow_dispatch', 'workflow_call'])
        self.assertEqual(triggers(text(NIGHTLY)), ['schedule', 'workflow_dispatch'])

    def test_drift_cargo_packages_stay_inside_each_lane_consumer_set(self):
        git = select.Git(ROOT)
        workspace = select.Workspace(select.Tree(git, 'HEAD'))
        for lane, spec_ in POLICY['lanes'].items():
            body = jobs(spec_['workflow'])[spec_['job']]
            commands = re.findall(r'cargo (?:\+\S+ )?(?:build|test|check|clippy|run|nextest run|deb|generate-rpm)\b[^\n]*', body)
            packages = set(re.findall(r'(?:-p|--package)\s+([A-Za-z0-9_-]+)', '\n'.join(commands)))
            rule = spec_['rust']
            with self.subTest(lane=lane):
                if rule.startswith('closure:'):
                    root = rule.split(':', 1)[1]
                    allowed = workspace.closure(workspace.names['fuzz'] if root == 'fuzz' else root)
                    self.assertTrue(packages <= allowed, packages - allowed)
                    self.assertNotIn('--workspace', '\n'.join(commands))
                elif rule in ('none', 'paths'):
                    self.assertEqual(packages, set())

    def test_gate_accounts_for_every_job_and_always_runs(self):
        ci = jobs(CI)
        gate = ci['gate']
        self.assertEqual(header(gate, 'if'), '${{ always() }}')
        needs = header(gate, 'needs').strip('[]').split(', ')
        self.assertEqual(sorted(needs), sorted(set(ci) - {'gate'}))
        self.assertIn('      actions: read\n', gate)
        self.assertIn('python3 -I -B scripts/ci-gate.py ci', gate)
        for name in ('select', 'policy', 'docs'):
            self.assertIn('persist-credentials: false', ci[name])

    def test_caller_declaration_and_record_output(self):
        source = text(CI)
        call = source.split('  workflow_call:\n', 1)[1].split('\nenv:', 1)[0]
        self.assertIn('      caller-runs:\n        type: string\n        required: false\n        default: \'\'\n', call)
        self.assertIn('        value: ${{ jobs.select.outputs.record }}\n', call)
        select_job = jobs(CI)['select']
        self.assertIn('QSH_CALLER_RUNS: ${{ inputs.caller-runs }}', select_job)
        self.assertIn('QSH_JOB_WORKFLOW_REF: ${{ job.workflow_ref }}', select_job)
        self.assertIn('fetch-depth: 0', select_job)


class ConcurrencyTests(unittest.TestCase):
    def test_groups_are_namespaced_and_only_top_level_pull_requests_cancel(self):
        ci = text(CI)
        self.assertIn("concurrency:\n  group: qsh-ci-${{ github.workflow }}-${{ github.event_name }}-${{ github.ref }}\n"
                      "  cancel-in-progress: ${{ github.event_name == 'pull_request' && github.workflow == 'CI' }}\n", ci)
        for path in (NATIVE, PEERS, FUZZ):
            self.assertNotIn('concurrency:', text(path), path)
        self.assertIn('concurrency:\n  group: qsh-nightly-${{ github.ref }}\n  cancel-in-progress: false\n', text(NIGHTLY))
        groups = []
        for path in sorted(WORKFLOWS.glob('*.yml')):
            groups += re.findall(r'(?m)^\s+group: (\S+)', path.read_text())
        prefixes = [re.match(r'(qsh-[a-z]+-)', group).group(1) for group in groups]
        self.assertEqual(len(prefixes), len(set(prefixes)), groups)


class ReleaseAndNightlyTests(unittest.TestCase):
    def test_release_qualifies_the_exact_tag_before_publication(self):
        release = jobs(RELEASE)
        ordinary = release['ordinary-ci']
        self.assertEqual(header(ordinary, 'if'), "github.ref_type == 'tag'")
        self.assertIn('    with:\n      caller-runs: ' + POLICY['caller_runs'] + '\n', ordinary)
        self.assertIn('    permissions:\n      contents: read\n      actions: read\n', ordinary)
        self.assertEqual(code(release['native-crypto']), ['    uses: ./.github/workflows/native-crypto.yml'])
        self.assertEqual(header(release['fuzz'], 'if'), "github.ref_type == 'tag'")
        self.assertEqual(header(release['fuzz'], 'uses'), './' + FUZZ)
        qualification = release['release-qualification']
        self.assertEqual(header(qualification, 'name'), 'Release qualification')
        self.assertEqual(header(qualification, 'if'), "github.ref_type == 'tag'")
        self.assertEqual(header(qualification, 'needs'), '[ordinary-ci, native-crypto, released-peer-acceptance, fuzz]')
        self.assertIn('python3 -I -B scripts/ci-gate.py release', qualification)
        publish = release['publish']
        self.assertEqual(header(publish, 'needs'),
                         '[release, ordinary-ci, released-peer-acceptance, release-verifier, release-qualification]')
        condition = header(publish, 'if')
        for status in ('always()', 'cancelled()', 'failure()', 'success()'):
            self.assertNotIn(status, condition)

    def test_nightly_calls_every_lane_workflow_after_freshness(self):
        nightly = jobs(NIGHTLY)
        for call, path in dict(CALLS, **{'ordinary-ci': CI}).items():
            body = nightly[call]
            self.assertEqual(header(body, 'needs'), 'freshness')
            self.assertEqual(header(body, 'if'), "${{ needs.freshness.outputs.run == 'true' }}")
            self.assertEqual(header(body, 'uses'), './' + path)
        self.assertIn('    with:\n      caller-runs: ' + POLICY['caller_runs'] + '\n', nightly['ordinary-ci'])
        self.assertNotIn('with:', nightly['native-crypto'])
        qualification = nightly['qualification']
        self.assertEqual(header(qualification, 'if'), '${{ always() }}')
        self.assertEqual(header(qualification, 'needs'),
                         '[freshness, ordinary-ci, native-crypto, released-peer-acceptance, fuzz]')
        self.assertIn('python3 -I -B scripts/ci-gate.py nightly', qualification)
        self.assertIn('python3 -I -B scripts/ci-gate.py freshness', nightly['freshness'])


if __name__ == '__main__':
    unittest.main()
