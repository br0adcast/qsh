#!/usr/bin/env python3
"""Account for every CI cell by the jobs API (#609).

Contexts:
  ci         the CI gate: the selected lanes of this run, or the CI-owned
             lanes when Release or Nightly called CI;
  release    Release qualification: every lane of the exact tag source;
  nightly    Nightly qualification: every lane, or an explicit REUSED record;
  freshness  whether a scheduled Nightly may reuse trusted full evidence.

The jobs API names a pull request's head commit H while the checkout tests
the synthetic merge S. Both identities are verified and recorded: API records
bind to H and this run, the tested source binds to S and its ordered parents.
"""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location('qsh_ci_select', Path(__file__).resolve().parent / 'ci-select.py')
select = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(select)

CI = '.github/workflows/ci.yml'
CALLERS = {'ordinary-ci': CI, 'native-crypto': '.github/workflows/native-crypto.yml',
           'released-peer-acceptance': '.github/workflows/released-peer-acceptance.yml',
           'fuzz': '.github/workflows/fuzz.yml'}
WORKFLOW_PATHS = {'ci': CI, 'release': '.github/workflows/release.yml',
                  'nightly': '.github/workflows/nightly.yml'}
OWN_NAMES = {'ci': 'CI gate', 'release': 'Release qualification', 'nightly': 'Nightly qualification'}
CALLS = ('native-crypto', 'released-peer-acceptance', 'fuzz')
TRUSTED_EVIDENCE = {'.github/workflows/nightly.yml': ('nightly', ('schedule', 'workflow_dispatch')),
                    CI: ('ci', ('workflow_dispatch',)),
                    '.github/workflows/release.yml': ('release', ('push',))}
MAX_ARTIFACT = 1024 * 1024
SHAPE = re.compile(r'\$\{\{.*?\}\}')
# A skipped job whose whole name is one expression is reported by its bare
# expression text: `${{ matrix.name }}` arrives as `matrix.name`.
WHOLE = re.compile(r'\$\{\{\s*(.*?)\s*\}\}')


class GateError(Exception):
    pass


def shape(name):
    return SHAPE.sub('\0', name)


def bare(name):
    """The reported name of a skipped job named by one whole expression, or None."""
    found = WHOLE.fullmatch(name)
    return found.group(1) if found else None


class Api:
    """Minimal authenticated GitHub REST client with bounded retries."""

    def __init__(self, env):
        self.base = env.get('GITHUB_API_URL', 'https://api.github.com').rstrip('/')
        self.token = env.get('GH_TOKEN', '')
        if not self.token:
            raise GateError('no token for the jobs API')

    def request(self, url, *, accept='application/vnd.github+json', auth=True):
        headers = {'Accept': accept, 'User-Agent': 'qsh-ci-gate', 'X-GitHub-Api-Version': '2022-11-28'}
        if auth:
            headers['Authorization'] = 'Bearer ' + self.token
        opener = urllib.request.build_opener(NoRedirect)
        for attempt in range(4):
            try:
                with opener.open(urllib.request.Request(url, headers=headers), timeout=30) as response:
                    return response.status, response.headers, response.read(16 * 1024 * 1024)
            except urllib.error.HTTPError as error:
                if error.code in (301, 302, 303, 307, 308):
                    return error.code, error.headers, b''
                if error.code < 500 and error.code != 429:
                    raise GateError('API status ' + str(error.code)) from None
            except (urllib.error.URLError, TimeoutError, OSError):
                pass
            time.sleep(2 ** attempt)
        raise GateError('API unavailable')

    def get(self, path, params=None):
        url = self.base + path + ('?' + urllib.parse.urlencode(params) if params else '')
        status, _headers, body = self.request(url)
        if status != 200:
            raise GateError('API status ' + str(status))
        try:
            return json.loads(body)
        except ValueError:
            raise GateError('API payload malformed') from None

    def download(self, path):
        status, headers, body = self.request(self.base + path)
        if status in (301, 302, 303, 307, 308):
            location = headers.get('Location', '')
            if not location.startswith('https://'):
                raise GateError('artifact redirect refused')
            status, _headers, body = self.request(location, accept='*/*', auth=False)
        if status != 200 or len(body) > MAX_ARTIFACT:
            raise GateError('artifact unavailable')
        return body


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def all_jobs(api, repository, run_id, view):
    jobs, page = [], 1
    while True:
        payload = api.get('/repos/' + repository + '/actions/runs/' + str(run_id) + '/jobs',
                          {'filter': view, 'per_page': 100, 'page': page})
        if type(payload) is not dict or type(payload.get('jobs')) is not list or type(payload.get('total_count')) is not int:
            raise GateError('jobs payload malformed')
        jobs.extend(payload['jobs'])
        if len(jobs) >= payload['total_count'] or not payload['jobs']:
            break
        page += 1
        if page > 20:
            raise GateError('jobs pagination unbounded')
    if len(jobs) != payload['total_count']:
        raise GateError('jobs pagination truncated')
    for job in jobs:
        if (type(job) is not dict or type(job.get('name')) is not str or type(job.get('run_attempt')) is not int
                or job.get('status') not in ('queued', 'in_progress', 'completed', 'waiting', 'pending', 'requested')):
            raise GateError('job record malformed')
    return jobs


def job_name(workflow_text, job):
    body = select.workflow_jobs(workflow_text).get(job)
    if body is None:
        raise GateError('workflow job missing: ' + job)
    found = re.search(r'(?m)^    name: (.+)$', body)
    return found.group(1).strip() if found else job


class Expectation:
    """What one owned group (a workflow under a caller prefix) may contain."""

    def __init__(self, policy, workflow, texts, required, call_ids=()):
        self.workflow = workflow
        self.cells, self.templates, self.admin, self.bare = {}, {}, {}, {}
        for lane, spec in policy['lanes'].items():
            if spec['workflow'] != workflow:
                continue
            for cell in spec['cells']:
                self.cells[cell] = lane
            name = job_name(texts[workflow], spec['job'])
            if '${{' in name:
                self.templates.setdefault(shape(name), []).append(lane)
                if bare(name) is not None:
                    self.bare[bare(name)] = shape(name)
        for job, spec in policy['administrative'].get(workflow, {}).items():
            self.admin[shape(spec['name']) if '${{' in spec['name'] else spec['name']] = (job, spec['accept'])
        self.calls = set(call_ids)
        self.required = set(required)


def settled(record):
    """A completed record can briefly lack its conclusion; that is still pending."""
    return record['status'] == 'completed' and record.get('conclusion') is not None


def evaluate(groups, latest, history, attempt, own, required_admin, strict):
    """Return (failures, pending, cells) for one jobs snapshot.

    `strict` rejects names outside the owned prefixes too: a top-level CI run
    contains nothing else. Release and Nightly own only their called groups.
    """
    failures, pending, cells = [], [], []
    seen = {}
    for job in latest:
        if job['run_attempt'] != attempt:
            failures.append('STALE_OR_SUPERSEDED_ATTEMPT ' + job['name'])
            continue
        prefix, local = (job['name'].split(' / ', 1) if ' / ' in job['name'] else ('', job['name']))
        if (prefix, local) == own:
            continue
        if prefix not in groups:
            if strict:
                failures.append('UNKNOWN_JOB ' + job['name'])
            continue
        expected = groups[prefix]
        key = shape(local) if '${{' in local else expected.bare.get(local, local)
        seen.setdefault((prefix, key), []).append(job)
        if local in expected.cells:
            continue
        if key in expected.templates and key != local:
            continue
        if key in expected.admin or local in expected.calls:
            continue
        failures.append('UNKNOWN_JOB ' + job['name'])
    for prefix, expected in sorted(groups.items()):
        label = (prefix + ' / ') if prefix else ''
        for cell, lane in expected.cells.items():
            records = seen.get((prefix, cell), [])
            if len(records) > 1:
                failures.append('DUPLICATE ' + label + cell)
                continue
            record = records[0] if records else None
            if lane in expected.required:
                if record is None or not settled(record):
                    pending.append(label + cell)
                    continue
                if record.get('conclusion') != 'success':
                    failures.append('FAILED ' + label + cell + ' ' + str(record.get('conclusion')))
            elif record is not None:
                if not settled(record):
                    pending.append(label + cell)
                    continue
                if record.get('conclusion') not in ('success', 'skipped'):
                    failures.append('NOT_REQUIRED_BUT_FAILED ' + label + cell)
            if record is not None:
                cells.append(cell_record(lane, label + cell, record, history))
        for template, lanes in expected.templates.items():
            records = seen.get((prefix, template), [])
            if len(records) > len(lanes):
                failures.append('DUPLICATE_TEMPLATE ' + label + template.replace('\0', '…'))
            for record in records:
                if record['status'] == 'completed' and record.get('conclusion') is None:
                    pending.append(label + template.replace('\0', '…'))
                elif record['status'] != 'completed' or record.get('conclusion') != 'skipped':
                    failures.append('TEMPLATE_NOT_SKIPPED ' + label + template.replace('\0', '…'))
        for key, (job, accept) in expected.admin.items():
            records = seen.get((prefix, key), [])
            if len(records) > 1:
                failures.append('DUPLICATE ' + label + key)
            for record in records:
                if not settled(record):
                    pending.append(label + key)
                elif record.get('conclusion') not in accept:
                    failures.append('ADMINISTRATIVE_FAILED ' + label + key.replace('\0', '…'))
            if (prefix, job) in required_admin and not records:
                pending.append(label + key)
        for call in expected.calls:
            for record in seen.get((prefix, call), []):
                if not settled(record):
                    pending.append(label + call)
                elif record.get('conclusion') != 'skipped':
                    failures.append('CALL_NOT_RUN ' + label + call + ' ' + str(record.get('conclusion')))
    return failures, pending, cells


def cell_record(lane, name, record, history):
    retained = None
    for older in history:
        if (older.get('name') == record['name'] and older.get('run_attempt', 0) < record['run_attempt']
                and older.get('started_at') == record.get('started_at')
                and older.get('completed_at') == record.get('completed_at')
                and older.get('conclusion') == record.get('conclusion')):
            retained = older['run_attempt'] if retained is None else min(retained, older['run_attempt'])
    return {'lane': lane, 'name': name, 'job_id': record.get('id'), 'run_attempt': record['run_attempt'],
            'executed_in_attempt': retained or record['run_attempt'], 'retained': retained is not None,
            'head_sha': record.get('head_sha'), 'conclusion': record.get('conclusion')}


def check_history(latest, history, attempt):
    newest = {}
    for job in history:
        if job['run_attempt'] > attempt:
            raise GateError('a newer run attempt exists')
        name = job['name']
        newest[name] = max(newest.get(name, 0), job['run_attempt'])
    for job in latest:
        if newest.get(job['name'], 0) != job['run_attempt']:
            raise GateError('latest view is not the newest attempt for ' + job['name'])


def git(*args):
    result = subprocess.run(['git', '--no-pager', *args], cwd=ROOT, capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise GateError('git ' + args[0] + ' failed')
    return result.stdout.decode('ascii', 'replace')


def tested_source(env):
    """Verify the checkout is GITHUB_SHA; return (source, ordered parents)."""
    source = env.get('GITHUB_SHA', '')
    if not select.SHA.fullmatch(source) or git('rev-parse', 'HEAD').strip() != source:
        raise GateError('checkout differs from GITHUB_SHA')
    headers = git('cat-file', '-p', source).split('\n\n', 1)[0].splitlines()
    return source, [line[7:] for line in headers if line.startswith('parent ')]


def expected_api_head(env, source, parents):
    if env.get('GITHUB_EVENT_NAME') == 'pull_request':
        event = json.loads(Path(env['GITHUB_EVENT_PATH']).read_text())
        head = event.get('pull_request', {}).get('head', {}).get('sha')
        if type(head) is not str or len(parents) != 2 or parents[1] != head:
            raise GateError('pull request merge parents do not name the event head')
        return head, parents[0]
    return source, None


def needs_result(needs, job):
    entry = needs.get(job)
    return entry.get('result') if isinstance(entry, dict) else None


class Gate:
    def __init__(self, context, env, api, policy=None, texts=None, sleep=time.sleep, source=None):
        self.context, self.env, self.api, self.sleep = context, env, api, sleep
        self.source = source
        self.policy = policy or select.load_policy(ROOT)
        self.texts = texts or {path: (ROOT / path).read_text() for path in set(CALLERS.values()) | {CI}}
        self.failures, self.result = [], {}
        self.budget = float(env.get('QSH_GATE_VISIBILITY_SECONDS', '300'))

    def fail(self, reason):
        self.failures.append(reason)

    def run(self):
        env, policy = self.env, self.policy
        repository = env.get('GITHUB_REPOSITORY', '')
        run_id, attempt = env.get('GITHUB_RUN_ID', ''), env.get('GITHUB_RUN_ATTEMPT', '')
        if repository != policy['repository'] or not run_id.isdigit() or not attempt.isdigit():
            raise GateError('run identity')
        run_id, attempt = int(run_id), int(attempt)
        defining = WORKFLOW_PATHS[self.context]
        if not env.get('QSH_JOB_WORKFLOW_REF', '').startswith(repository + '/' + defining + '@'):
            raise GateError('this gate job is not defined by ' + defining)
        digest = select.policy_digest(ROOT)
        lanes = set(policy['lanes'])
        ci_lanes = {lane for lane, spec in policy['lanes'].items() if spec['workflow'] == CI}
        needs = json.loads(env.get('QSH_GATE_NEEDS') or '{}')
        if type(needs) is not dict:
            raise GateError('needs malformed')
        record = self.selection_record(digest)
        source, parents = self.source or tested_source(env)
        api_head, base = expected_api_head(env, source, parents)
        out = self.result
        out.update(schema=1, kind='qsh-ci-qualification', context=self.context, policy_digest=digest,
                   repository=repository, run_id=run_id, run_attempt=attempt,
                   event=env.get('GITHUB_EVENT_NAME'), source=source, source_parents=parents,
                   api_head=api_head, base=base, lanes={}, cells=[])
        if self.context == 'ci':
            if needs_result(needs, 'select') != 'success' or record is None:
                self.fail('SELECTION_UNAVAILABLE')
                record = {}
            elif record.get('source') != source or record.get('api_head') != api_head:
                self.fail('SELECTION_IDENTITY_DIFFERS')
            if needs_result(needs, 'policy') != 'success':
                self.fail('POLICY_CONTROLS_NOT_SUCCESSFUL')
            required = set(record.get('lanes', [])) & lanes
            delegated = set(record.get('delegated', [])) & lanes
            deferred = set(record.get('deferred', [])) & lanes
            called = record.get('context') == 'called'
            if called and required != ci_lanes:
                self.fail('CALLED_SELECTION_NOT_FULL')
            out['mode'] = record.get('mode', 'unavailable')
            jobs = {spec['job']: lane in required for lane, spec in policy['lanes'].items()
                    if spec['workflow'] == CI}
            for call in CALLS:
                jobs[call] = any(policy['lanes'][lane]['workflow'] == CALLERS[call] for lane in required)
            for job, wanted in sorted(jobs.items()):
                result = needs_result(needs, job)
                if wanted and result != 'success':
                    self.fail('NEEDS_NOT_SUCCESSFUL ' + job + ' ' + str(result))
                if not wanted and result != 'skipped':
                    self.fail('NEEDS_NOT_SKIPPED ' + job + ' ' + str(result))
        else:
            required, delegated, deferred, called = set(lanes), set(), set(), False
            out['mode'] = 'full'
            if self.context == 'nightly' and needs_result(needs, 'freshness') != 'success':
                self.fail('FRESHNESS_NOT_SUCCESSFUL')
            for call in CALLERS:
                if needs_result(needs, call) != 'success':
                    self.fail('NEEDS_NOT_SUCCESSFUL ' + call + ' ' + str(needs_result(needs, call)))
            if (record is None or record.get('context') != 'called' or sorted(record.get('lanes', []))
                    != sorted(ci_lanes) or record.get('source') != source):
                self.fail('CALLED_CI_RECORD_INVALID')
        out['required'] = sorted(required)
        run = self.api.get('/repos/' + repository + '/actions/runs/' + str(run_id))
        if (type(run) is not dict or run.get('id') != run_id or run.get('run_attempt') != attempt
                or run.get('event') != env.get('GITHUB_EVENT_NAME') or run.get('head_sha') != api_head
                or (run.get('repository') or {}).get('full_name') != repository):
            raise GateError('run payload does not match this run')
        path = str(run.get('path', '')).split('@', 1)[0]
        if self.context == 'ci' and called:
            if path not in (WORKFLOW_PATHS['release'], WORKFLOW_PATHS['nightly']):
                raise GateError('called CI from an unexpected workflow')
        elif path != WORKFLOW_PATHS[self.context]:
            raise GateError('run workflow path differs')
        out['workflow_path'], out['workflow_id'] = path, run.get('workflow_id')
        deadline = time.monotonic() + self.budget
        delay, groups = 5, None
        while True:
            latest = all_jobs(self.api, repository, run_id, 'latest')
            history = all_jobs(self.api, repository, run_id, 'all')
            check_history(latest, history, attempt)
            for job in latest:
                if job.get('run_id', run_id) != run_id or job.get('head_sha') != api_head:
                    raise GateError('job record from another run or head')
            own = self.own(latest)
            if groups is None:
                groups, required_admin, strict = self.groups(own[0], required, called)
            failures, pending, cells = evaluate(groups, latest, history, attempt, own, required_admin, strict)
            if failures or not pending or time.monotonic() >= deadline:
                break
            self.sleep(min(delay, max(0.0, deadline - time.monotonic())))
            delay = min(delay * 2, 60)
        self.failures.extend(failures)
        self.failures.extend('UNRESOLVED ' + item for item in pending)
        out['cells'] = cells
        for lane in sorted(lanes):
            out['lanes'][lane] = ('DELEGATED_TO_CALLER' if lane in delegated else 'DEFERRED_TO_NIGHTLY'
                                  if lane in deferred else 'REQUIRED' if lane in required else 'NOT_APPLICABLE')
        return self.finish()

    def selection_record(self, digest):
        raw = self.env.get('QSH_GATE_RECORD', '')
        if not raw:
            return None
        try:
            record = json.loads(raw)
        except ValueError:
            self.fail('SELECTION_RECORD_MALFORMED')
            return None
        if type(record) is not dict or record.get('schema') != 1 or record.get('policy_digest') != digest:
            self.fail('SELECTION_RECORD_INVALID')
            return None
        return record

    def groups(self, own_prefix, required, called):
        """Owned groups by caller prefix, required administrative jobs, strictness."""
        policy, texts, calls = self.policy, self.texts, tuple(CALLS)
        if self.context == 'ci' and not called:
            groups = {'': Expectation(policy, CI, texts, required, calls)}
            for call in CALLS:
                groups[call] = Expectation(policy, CALLERS[call], texts, required)
            admin = {('', 'select'), ('', 'policy')}
            if any(policy['lanes'][lane]['workflow'] == CALLERS['native-crypto'] for lane in required):
                admin.add(('native-crypto', 'lanes'))
            return groups, admin, True
        if self.context == 'ci':
            if not own_prefix:
                raise GateError('called gate without a caller prefix')
            groups = {own_prefix: Expectation(policy, CI, texts, required, calls)}
            return groups, {(own_prefix, 'select'), (own_prefix, 'policy')}, False
        groups = {call: Expectation(policy, path, texts, required, calls if path == CI else ())
                  for call, path in CALLERS.items()}
        admin = {('ordinary-ci', 'select'), ('ordinary-ci', 'policy'), ('ordinary-ci', 'gate'),
                 ('native-crypto', 'lanes')}
        return groups, admin, False

    def own(self, latest):
        name = OWN_NAMES[self.context]
        mine = [job for job in latest if job['status'] != 'completed'
                and (job['name'] == name or job['name'].endswith(' / ' + name))]
        if len(mine) != 1:
            raise GateError('cannot identify this gate job')
        return tuple(mine[0]['name'].split(' / ', 1)) if ' / ' in mine[0]['name'] else ('', mine[0]['name'])

    def finish(self):
        self.result['failures'] = sorted(set(self.failures))
        self.result['result'] = 'FAIL' if self.failures else 'PASS'
        return self.result


def full_cells(policy):
    expected = set()
    for lane, spec in policy['lanes'].items():
        call = next(c for c, path in CALLERS.items() if path == spec['workflow'])
        for cell in spec['cells']:
            expected.add((lane, call + ' / ' + cell))
    return expected


def trusted_evidence(policy, api, repository, sha, digest, runs=None):
    """Return the newest trusted full qualification of `sha`, or None."""
    payload = runs or api.get('/repos/' + repository + '/actions/runs',
                              {'head_sha': sha, 'status': 'success', 'per_page': 100})
    expected = full_cells(policy)
    for run in sorted(payload.get('workflow_runs', []), key=lambda r: -int(r.get('id', 0))):
        path = str(run.get('path', '')).split('@', 1)[0]
        if path not in TRUSTED_EVIDENCE:
            continue
        kind, events = TRUSTED_EVIDENCE[path]
        if (run.get('head_sha') != sha or run.get('conclusion') != 'success' or run.get('event') not in events
                or (run.get('repository') or {}).get('full_name') != repository
                or (run.get('head_repository') or {}).get('full_name') != repository):
            continue
        name = kind + '-qualification-' + str(run['id']) + '-' + str(run.get('run_attempt'))
        artifacts = api.get('/repos/' + repository + '/actions/runs/' + str(run['id']) + '/artifacts',
                            {'name': name, 'per_page': 10})
        found = [a for a in artifacts.get('artifacts', []) if a.get('name') == name and not a.get('expired')]
        if len(found) != 1:
            continue
        try:
            archive = zipfile.ZipFile(io.BytesIO(api.download(
                '/repos/' + repository + '/actions/artifacts/' + str(found[0]['id']) + '/zip')))
            names = archive.namelist()
            if names != ['qualification.json']:
                continue
            receipt = json.loads(archive.read('qualification.json'))
        except (zipfile.BadZipFile, ValueError, KeyError, GateError):
            continue
        cells = {(cell.get('lane'), cell.get('name')) for cell in receipt.get('cells', [])
                 if cell.get('conclusion') == 'success'}
        if kind == 'ci':
            cells = {(lane, (name if name.split(' / ', 1)[0] in CALLERS else 'ordinary-ci / ' + name))
                     for lane, name in cells}
        if (receipt.get('schema') == 1 and receipt.get('kind') == 'qsh-ci-qualification'
                and receipt.get('result') == 'PASS' and receipt.get('mode') == 'full'
                and receipt.get('context') == kind and receipt.get('policy_digest') == digest
                and receipt.get('source') == sha and receipt.get('repository') == repository
                and receipt.get('run_id') == run['id'] and receipt.get('run_attempt') == run.get('run_attempt')
                and receipt.get('workflow_path') == path and expected <= cells):
            return {'run_id': run['id'], 'run_attempt': run.get('run_attempt'), 'workflow_path': path,
                    'source': sha, 'policy_digest': digest}
    return None


def freshness(env, api, policy=None):
    policy = policy or select.load_policy(ROOT)
    sha = env.get('GITHUB_SHA', '')
    if env.get('GITHUB_EVENT_NAME') != 'schedule':
        return None, 'MANUAL_RUN'
    try:
        evidence = trusted_evidence(policy, api, env['GITHUB_REPOSITORY'], sha, select.policy_digest(ROOT))
    except GateError as error:
        return None, 'EVIDENCE_UNAVAILABLE ' + str(error)
    return evidence, 'REUSED' if evidence else 'NO_TRUSTED_EVIDENCE'


def write_outputs(env, values):
    with open(env['GITHUB_OUTPUT'], 'a', encoding='utf-8') as handle:
        for key, value in values.items():
            if '\n' in value:
                raise SystemExit('multiline output refused')
            handle.write(key + '=' + value + '\n')


def summary(env, lines):
    path = env.get('GITHUB_STEP_SUMMARY')
    if path:
        with open(path, 'a', encoding='utf-8') as handle:
            handle.write('\n'.join(lines) + '\n')


def report(result):
    lines = ['### ' + result['context'] + ' qualification: ' + result['result'],
             '', 'mode ' + str(result.get('mode')) + '; tested source ' + str(result.get('source'))
             + '; API head ' + str(result.get('api_head')) + '; run ' + str(result.get('run_id'))
             + ' attempt ' + str(result.get('run_attempt')), '', '| Lane | State |', '|---|---|']
    for lane, state in result.get('lanes', {}).items():
        lines.append('| ' + lane + ' | ' + state + ' |')
    lines += ['', '| Cell | Conclusion | Executed in attempt |', '|---|---|---|']
    for cell in result.get('cells', []):
        lines.append('| ' + cell['name'] + ' | ' + str(cell['conclusion']) + ' | '
                     + str(cell['executed_in_attempt']) + (' (retained)' if cell['retained'] else '') + ' |')
    for failure in result.get('failures', []):
        lines.append('- ' + failure)
    return lines


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('context', choices=('ci', 'release', 'nightly', 'freshness'))
    parser.add_argument('--output')
    args = parser.parse_args(argv)
    env = dict(os.environ)
    try:
        api = Api(env)
    except GateError as error:
        api, startup = None, str(error)
    if args.context == 'freshness':
        evidence, reason = freshness(env, api) if api else (None, 'NO_TOKEN')
        write_outputs(env, {'run': 'false' if evidence else 'true',
                            'reused': json.dumps(evidence, sort_keys=True, separators=(',', ':')) if evidence else ''})
        print('Nightly freshness: ' + reason + (' run ' + str(evidence['run_id']) if evidence else ''))
        summary(env, ['### Nightly freshness', '', reason + ((' ' + env.get('GITHUB_SHA', '') + ' run '
                      + str(evidence['run_id'])) if evidence else '')])
        return 0
    result = None
    try:
        if api is None:
            raise GateError(startup)
        if args.context == 'nightly' and env.get('QSH_GATE_REUSED'):
            result = reused(env, api)
        else:
            result = Gate(args.context, env, api).run()
    except (GateError, ValueError, KeyError, OSError, subprocess.SubprocessError) as error:
        result = {'schema': 1, 'kind': 'qsh-ci-qualification', 'context': args.context, 'result': 'FAIL',
                  'failures': ['GATE_ERROR ' + str(error)[:200]], 'lanes': {}, 'cells': []}
    if args.output:
        Path(args.output).write_text(json.dumps(result, sort_keys=True, indent=1) + '\n')
    for line in report(result):
        print(line)
    summary(env, report(result))
    return 0 if result['result'] == 'PASS' else 1


def reused(env, api):
    """A scheduled Nightly that reuses evidence must still find it, now."""
    policy = select.load_policy(ROOT)
    claimed = json.loads(env['QSH_GATE_REUSED'])
    needs = json.loads(env.get('QSH_GATE_NEEDS') or '{}')
    evidence, reason = freshness(env, api, policy)
    failures = []
    if needs_result(needs, 'freshness') != 'success':
        failures.append('FRESHNESS_NOT_SUCCESSFUL')
    if evidence is None or evidence != claimed:
        failures.append('REUSED_EVIDENCE_NOT_CONFIRMED ' + reason)
    for call in CALLERS:
        if needs_result(needs, call) != 'skipped':
            failures.append('REUSED_RUN_EXECUTED ' + call)
    return {'schema': 1, 'kind': 'qsh-ci-qualification', 'context': 'nightly', 'mode': 'reused',
            'result': 'FAIL' if failures else 'PASS', 'failures': failures, 'evidence': claimed,
            'source': env.get('GITHUB_SHA'), 'run_id': int(env.get('GITHUB_RUN_ID', '0') or 0),
            'run_attempt': int(env.get('GITHUB_RUN_ATTEMPT', '0') or 0), 'lanes': {}, 'cells': [],
            'policy_digest': select.policy_digest(ROOT), 'repository': env.get('GITHUB_REPOSITORY')}


if __name__ == '__main__':
    sys.exit(main())
