"""Release-manifest signing orchestration against a local, strict gh boundary.

Two verifiers are used. STUB_VERIFIER is an orchestration stub, not a
cryptographic verifier: it accepts only a fixed synthetic bundle naming the
manifest digest and commit, so signing, reuse and retry decisions can be
driven offline. RealVerifierTests run the release-auth `verify-release`
example named by QSH_TEST_RELEASE_VERIFIER and show that real evidence that
does not authenticate this release is rejected. The cryptographic tests of
that verifier stay in crates/release-auth.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/prepare-release-attestation.py'
UPLOADER = ROOT / 'scripts/upload-release-assets.py'
WORKFLOW = ROOT / '.github/workflows/release.yml'
REPO = 'br0adcast/qsh'
VERSION = '0.6.0'
TAG = 'v' + VERSION
COMMIT = '0123456789abcdef0123456789abcdef01234567'
OTHER_COMMIT = 'fedcba9876543210fedcba9876543210fedcba98'
PUBLIC_FIXTURE = ROOT / 'crates/release-auth/tests/data/conda-attestation.sigstore.json'


def _load(name):
    spec = importlib.util.spec_from_file_location(name.replace('-', '_'), ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PRODUCTS = sorted(name for names in _load('assemble-release-assets').expected_products(VERSION).values()
                  for name in names)

# GitHub's REST API, as `gh api` presents it, over a JSON state file. Reads
# are answered with `--include` headers; HTTP errors exit 1 like gh does.
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, pathlib, re, sys
p = pathlib.Path(os.environ['FAKE_STATE'])
s = json.loads(p.read_text())
a = sys.argv[1:]
s['calls'].append(a)
def save(): p.write_text(json.dumps(s))
save()
def answer(code, body):
    if code == 'network': sys.exit(1)
    reason = {200: 'OK', 401: 'Unauthorized', 403: 'Forbidden', 404: 'Not Found', 500: 'Internal Server Error', 502: 'Bad Gateway'}[code]
    sys.stdout.write(f'HTTP/2.0 {code} {reason}\nContent-Type: application/json\r\nX-Github-Request-Id: 0000\r\n\r\n')
    sys.stdout.write(json.dumps(body) if not isinstance(body, str) else body)
    sys.exit(0 if code == 200 and not s.get('exit_after_ok') else 1)
def injected(endpoint):
    for prefix, code in s.get('errors', {}).items():
        if endpoint.startswith(prefix): return code
def release_list():
    return [{'id': 1, 'tag_name': s['tag_name']}] if s['release'] else []
def asset_list():
    out = []
    for i, asset in enumerate(s['assets']):
        out.append({'id': i + 1, 'name': asset['name'], 'state': asset.get('state', 'uploaded'),
                    'size': asset.get('size', len(asset['content'].encode('latin1'))),
                    'content_type': asset.get('content_type', 'application/octet-stream')})
        out[-1].update(asset.get('override', {}))
    return out
repo = 'repos/br0adcast/qsh/'
if a[:4] == ['api', '--include', '--method', 'GET']:
    endpoint = a[4]
    code = injected(endpoint)
    if code: answer(code, {'message': 'injected'})
    if s.get('malformed') == endpoint.split('?')[0]: answer(200, '{not json')
    path, _, query = endpoint.partition('?')
    page = int(dict(q.split('=') for q in query.split('&')).get('page', '1')) if query else 1
    if path == repo + 'git/ref/tags/' + s['tag_name']:
        if s['tag'] is None: answer(404, {'message': 'Not Found'})
        answer(200, {'ref': 'refs/tags/' + s['tag_name'], 'object': s['tag']})
    if path.startswith(repo + 'git/tags/'):
        answer(200, {'object': s['annotated'][path.rsplit('/', 1)[1]]})
    if path == repo + 'releases':
        answer(200, release_list() if page == 1 else [])
    if path == repo + 'releases/1/assets':
        if s.get('pages'): answer(200, asset_list()[:1] * 100)
        answer(200, asset_list() if page == 1 else [])
    if path.startswith(repo + 'git/ref/tags/'): answer(404, {'message': 'Not Found'})
    raise AssertionError(a)
elif a[:2] == ['api', '--paginate']:
    endpoint = a[-1]
    if endpoint == repo + 'releases': print(json.dumps([release_list()]))
    elif endpoint == repo + 'releases/1/assets': print(json.dumps([asset_list()]))
    else: raise AssertionError(a)
elif a[:3] == ['api', '-H', 'Accept: application/octet-stream']:
    if s.get('download') == 'fail': sys.exit(1)
    asset = s['assets'][int(a[3].rsplit('/', 1)[1]) - 1]
    data = asset['content'].encode('latin1')
    mode = s.get('download')
    sys.stdout.buffer.write(data + b'x' if mode == 'long' else data[:-1] if mode == 'short' else data)
elif a[:2] == ['release', 'create']:
    assert not s['release']
    s['release'] = True; s['mutations'].append('create'); save()
elif a[:2] == ['release', 'upload']:
    name = pathlib.Path(a[5]).name
    race = s.get('race', {})
    if name in race:
        s['assets'].append({'name': name, 'content': race.pop(name)}); save(); sys.exit(1)
    if any(asset['name'] == name for asset in s['assets']): sys.exit(1)
    s['assets'].append({'name': name, 'content': pathlib.Path(a[5]).read_bytes().decode('latin1')})
    s['mutations'].append('upload:' + name); save()
else: raise AssertionError(a)
'''

# ORCHESTRATION STUB -- not a cryptographic verifier. It accepts exactly the
# synthetic bundle stub_bundle() makes for the given manifest and commit.
STUB_VERIFIER = r'''#!/usr/bin/env python3
import hashlib, json, os, pathlib, sys
a = sys.argv[1:]
assert a[0::2] == ['--version', '--manifest', '--bundle', '--expected-source-commit'], a
version, manifest, bundle, commit = a[1::2]
with open(os.environ['STUB_LOG'], 'a') as log: log.write(pathlib.Path(bundle).name + '\n')
digest = hashlib.sha256(pathlib.Path(manifest).read_bytes()).hexdigest()
expected = json.dumps({'stub-bundle-for': digest, 'commit': commit}).encode() + b'\n'
if pathlib.Path(bundle).read_bytes() != expected:
    print('release metadata: release authentication failed', file=sys.stderr); sys.exit(1)
print(f'verified release {version} source {commit}')
'''


def stub_bundle(manifest, commit=COMMIT):
    digest = hashlib.sha256(manifest).hexdigest()
    return json.dumps({'stub-bundle-for': digest, 'commit': commit}).encode() + b'\n'


class Harness(unittest.TestCase):
    verifier = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='qsh-release-attestation-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base / 'bin').mkdir()
        (self.base / 'bin/gh').write_text(FAKE_GH)
        (self.base / 'bin/gh').chmod(0o755)
        (self.base / 'stub-verifier').write_text(STUB_VERIFIER)
        (self.base / 'stub-verifier').chmod(0o755)
        self.dist = self.base / 'dist'
        self.dist.mkdir()
        lines = []
        for name in PRODUCTS:
            data = ('PUBLIC SYNTHETIC PRODUCT ' + name + '\n').encode()
            (self.dist / name).write_bytes(data)
            lines.append(hashlib.sha256(data).hexdigest() + '  ' + name + '\n')
        self.manifest = ''.join(lines).encode()
        (self.dist / 'SHA256SUMS').write_bytes(self.manifest)
        self.state = self.base / 'state.json'
        self.output = self.base / 'github-output'
        self.stub_log = self.base / 'stub.log'
        self.env = dict(os.environ, PATH=str(self.base / 'bin') + os.pathsep + os.environ['PATH'],
                        HOME=str(self.base), XDG_CACHE_HOME=str(self.base / 'cache'),
                        XDG_CONFIG_HOME=str(self.base / 'config'), HISTFILE='/dev/null',
                        FAKE_STATE=str(self.state), STUB_LOG=str(self.stub_log))
        self.set_remote()

    def set_remote(self, release=False, assets=(), tag='commit', **extra):
        tags = {'commit': {'type': 'commit', 'sha': COMMIT},
                'other': {'type': 'commit', 'sha': OTHER_COMMIT},
                'annotated': {'type': 'tag', 'sha': 'a' * 40}, None: None}
        state = dict(tag_name=TAG, tag=tags[tag], annotated={'a' * 40: {'type': 'commit', 'sha': COMMIT}},
                     release=release, assets=[dict(a) for a in assets], calls=[], mutations=[])
        state.update(extra)
        self.state.write_text(json.dumps(state))

    def remote(self):
        return json.loads(self.state.read_text())

    def run_helper(self, command, *extra, version=VERSION, tag=TAG, repo=REPO, commit=COMMIT,
                   work=None, verifier=None):
        args = [sys.executable, '-I', '-B', str(HELPER), command, '--repo', repo, '--tag', tag,
                '--version', version, '--source-commit', commit, '--dist', str(self.dist),
                '--verifier', str(verifier or self.verifier or self.base / 'stub-verifier')]
        if command != 'final':
            args += ['--work', str(work or self.base / 'work')]
        if command == 'preflight':
            args += ['--github-output', str(self.output)]
        return subprocess.run(args + list(extra), env=self.env, capture_output=True, text=True, timeout=60)

    def outputs(self):
        if not self.output.exists():
            return {}
        return dict(line.split('=', 1) for line in self.output.read_text().splitlines())

    def assert_refused(self, result, message):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(message, result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertFalse((self.dist / 'SHA256SUMS.sigstore.json').exists())
        self.assertEqual(self.remote()['mutations'], [])
        self.assertEqual(self.outputs(), {})

    def assert_read_only(self):
        for call in self.remote()['calls']:
            self.assertTrue(call[:4] == ['api', '--include', '--method', 'GET']
                            or call[:3] == ['api', '-H', 'Accept: application/octet-stream'], call)

    def attest_output(self, data):
        """What actions/attest leaves at its bundle-path output."""
        path = self.base / 'attest' / 'attestation.json'
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(data)
        return path


class PreflightTests(Harness):
    def test_without_a_release_it_asks_for_one_signature_of_the_exact_statement(self):
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        out = self.outputs()
        self.assertEqual(set(out), {'sign', 'digest', 'predicate'})
        self.assertEqual(out['sign'], 'true')
        self.assertEqual(out['digest'], hashlib.sha256(self.manifest).hexdigest())
        self.assertRegex(out['digest'], r'^[0-9a-f]{64}$')
        predicate = Path(out['predicate']).read_bytes()
        self.assertEqual(predicate, (
            '{"manifest_format":"qsh-sha256sums-v1","version":"0.6.0","tag":"v0.6.0",'
            '"source_commit":"' + COMMIT + '"}\n').encode())
        self.assertEqual(list(json.loads(predicate)), ['manifest_format', 'version', 'tag', 'source_commit'])
        self.assertEqual(Path(out['predicate']).parent, self.base / 'work')
        self.assertEqual(os.stat(self.base / 'work').st_mode & 0o777, 0o700)
        self.assertFalse((self.dist / 'SHA256SUMS.sigstore.json').exists())
        self.assert_read_only()
        self.assertEqual(self.remote()['mutations'], [])

    def test_a_release_without_metadata_is_signed(self):
        self.set_remote(release=True, assets=[{'name': PRODUCTS[0], 'content': 'x'}])
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.outputs()['sign'], 'true')

    def test_a_published_manifest_alone_must_match_and_is_then_signed(self):
        self.set_remote(release=True, assets=[{'name': 'SHA256SUMS', 'content': self.manifest.decode()}])
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.outputs()['sign'], 'true')

    def test_a_valid_published_bundle_is_reused_byte_for_byte(self):
        bundle = stub_bundle(self.manifest)
        self.set_remote(release=True, assets=[
            {'name': 'SHA256SUMS.sigstore.json', 'content': bundle.decode()},
            {'name': 'SHA256SUMS', 'content': self.manifest.decode()}])
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.outputs(), {'sign': 'false'})
        self.assertEqual((self.dist / 'SHA256SUMS.sigstore.json').read_bytes(), bundle)
        self.assertFalse((self.base / 'work/predicate.json').exists())
        self.assertEqual(self.stub_log.read_text(), 'candidate-SHA256SUMS.sigstore.json\n')
        self.assert_read_only()

    def test_an_interrupted_upload_with_the_bundle_but_no_manifest_reuses_the_bundle(self):
        bundle = stub_bundle(self.manifest)
        self.set_remote(release=True, assets=[
            {'name': PRODUCTS[0], 'content': 'x'},
            {'name': 'SHA256SUMS.sigstore.json', 'content': bundle.decode()}])
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.outputs(), {'sign': 'false'})
        self.assertEqual((self.dist / 'SHA256SUMS.sigstore.json').read_bytes(), bundle)

    def test_invalid_published_evidence_is_a_hard_stop(self):
        for bundle in [stub_bundle(self.manifest, OTHER_COMMIT), stub_bundle(b'other manifest'),
                       b'{"not": "a bundle"}\n']:
            with self.subTest(bundle=bundle):
                shutil.rmtree(self.base / 'work', ignore_errors=True)
                self.set_remote(release=True, assets=[
                    {'name': 'SHA256SUMS.sigstore.json', 'content': bundle.decode()}])
                self.assert_refused(self.run_helper('preflight'), 'native verifier rejected the bundle')

    def test_a_conflicting_published_manifest_is_a_hard_stop(self):
        bundle = stub_bundle(self.manifest)
        self.set_remote(release=True, assets=[
            {'name': 'SHA256SUMS.sigstore.json', 'content': bundle.decode()},
            {'name': 'SHA256SUMS', 'content': self.manifest.decode().replace('0', '1', 1)}])
        self.assert_refused(self.run_helper('preflight'), 'published manifest differs')
        self.assertFalse(self.stub_log.exists(), 'the bundle was not even looked at')

    def test_duplicate_incomplete_and_oversized_assets_are_refused(self):
        cases = [
            ([{'name': 'SHA256SUMS', 'content': 'a'}, {'name': 'SHA256SUMS', 'content': 'a'}], 'duplicate published asset'),
            ([{'name': PRODUCTS[0], 'content': 'a'}, {'name': PRODUCTS[0], 'content': 'a'}], 'duplicate published asset'),
            ([{'name': 'SHA256SUMS', 'content': 'a', 'state': 'starter'}], 'incomplete published asset'),
            ([{'name': 'SHA256SUMS.sigstore.json', 'content': 'a', 'size': 256 * 1024 + 1}], 'size is out of bounds'),
            ([{'name': 'SHA256SUMS', 'content': 'a', 'size': 1024 * 1024 + 1}], 'size is out of bounds'),
            ([{'name': 'SHA256SUMS', 'content': '', 'size': 0}], 'size is out of bounds'),
            ([{'name': 'SHA256SUMS', 'content': 'a', 'override': {'size': '1'}}], 'unexpected GitHub asset entry'),
            ([{'name': 'SHA256SUMS', 'content': 'a', 'override': {'id': None}}], 'unexpected GitHub asset entry'),
            ([{'name': 'SHA256SUMS', 'content': 'a', 'override': {'content_type': 7}}], 'unexpected GitHub asset entry'),
        ]
        for assets, message in cases:
            with self.subTest(message=message, assets=assets):
                shutil.rmtree(self.base / 'work', ignore_errors=True)
                self.set_remote(release=True, assets=assets)
                self.assert_refused(self.run_helper('preflight'), message)

    def test_a_download_that_fails_or_differs_in_size_is_refused(self):
        for mode in ['fail', 'long', 'short']:
            for name, content in [('SHA256SUMS', self.manifest), ('SHA256SUMS.sigstore.json', stub_bundle(self.manifest))]:
                with self.subTest(mode=mode, name=name):
                    shutil.rmtree(self.base / 'work', ignore_errors=True)
                    self.set_remote(release=True, download=mode, assets=[
                        {'name': name, 'content': content.decode()}])
                    result = self.run_helper('preflight')
                    self.assert_refused(result, 'published asset could not be read in full: ' + name)

    def test_api_auth_and_network_failures_are_not_taken_for_absence(self):
        endpoints = ['repos/br0adcast/qsh/git/ref/tags/', 'repos/br0adcast/qsh/releases?',
                     'repos/br0adcast/qsh/releases/1/assets']
        for endpoint in endpoints:
            for code in [401, 403, 500, 502, 'network']:
                with self.subTest(endpoint=endpoint, code=code):
                    shutil.rmtree(self.base / 'work', ignore_errors=True)
                    self.set_remote(release=True, errors={endpoint: code})
                    message = 'without an HTTP answer' if code == 'network' else f'HTTP {code}'
                    self.assert_refused(self.run_helper('preflight'), message)

    def test_a_missing_listing_is_a_failure_not_an_empty_one(self):
        for endpoint in ['repos/br0adcast/qsh/releases?', 'repos/br0adcast/qsh/releases/1/assets']:
            with self.subTest(endpoint=endpoint):
                shutil.rmtree(self.base / 'work', ignore_errors=True)
                self.set_remote(release=True, errors={endpoint: 404})
                self.assert_refused(self.run_helper('preflight'), 'listing was not found')

    def test_malformed_and_unbounded_answers_are_refused(self):
        shutil.rmtree(self.base / 'work', ignore_errors=True)
        self.set_remote(release=True, malformed='repos/br0adcast/qsh/releases')
        self.assert_refused(self.run_helper('preflight'), 'malformed JSON')
        shutil.rmtree(self.base / 'work', ignore_errors=True)
        self.set_remote(release=True, pages=True, assets=[{'name': PRODUCTS[0], 'content': 'a'}])
        self.assert_refused(self.run_helper('preflight'), 'page limit')
        shutil.rmtree(self.base / 'work', ignore_errors=True)
        self.set_remote(release=True, exit_after_ok=True)
        self.assert_refused(self.run_helper('preflight'), 'failed after an HTTP answer')

    def test_the_tag_must_exist_and_name_the_source_commit(self):
        for tag, message in [(None, 'release tag is absent'), ('other', 'does not point at the source commit')]:
            with self.subTest(tag=tag):
                shutil.rmtree(self.base / 'work', ignore_errors=True)
                self.set_remote(tag=tag)
                self.assert_refused(self.run_helper('preflight'), message)
        shutil.rmtree(self.base / 'work', ignore_errors=True)
        self.set_remote(tag='annotated')
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_gates_refuse_before_any_api_call(self):
        cases = [
            (dict(repo='someone/qsh'), 'signed only for br0adcast/qsh'),
            (dict(tag='v0.6.1'), 'differs from the validated version'),
            (dict(version='0.6', tag='v0.6'), 'differs from the validated version'),
            (dict(commit=COMMIT.upper()), '40 lowercase hex'),
            (dict(commit=COMMIT[:39]), '40 lowercase hex'),
        ]
        for options, message in cases:
            with self.subTest(options=options):
                self.set_remote()
                self.assert_refused(self.run_helper('preflight', **options), message)
                self.assertEqual(self.remote()['calls'], [])

    def test_the_legacy_unsigned_release_is_never_backfilled(self):
        self.set_remote(release=True, assets=[{'name': 'SHA256SUMS', 'content': 'legacy'}])
        for command in ['preflight', 'capture', 'final']:
            with self.subTest(command=command):
                extra = ['--bundle-path', str(self.attest_output(b'{}\n'))] if command == 'capture' else []
                r = self.run_helper(command, *extra, version='0.5.0', tag='v0.5.0')
                self.assert_refused(r, 'v0.5.0 was published unsigned and is never backfilled')
                self.assertEqual(self.remote()['calls'], [])

    def test_the_local_set_must_be_the_thirteen_assembled_files(self):
        def unchanged():
            pass

        def extra_file():
            (self.dist / 'verify-release').write_bytes(b'tool')

        def early_bundle():
            (self.dist / 'SHA256SUMS.sigstore.json').write_bytes(b'{}')

        def missing():
            (self.dist / PRODUCTS[3]).unlink()

        def changed():
            (self.dist / PRODUCTS[5]).write_bytes(b'changed')

        def symlink():
            (self.dist / PRODUCTS[2]).unlink()
            (self.dist / PRODUCTS[2]).symlink_to(self.dist / PRODUCTS[1])

        for change, message in [(extra_file, 'exactly 13 files'), (missing, 'exactly 13 files'),
                                (changed, 'does not match the release products'),
                                (symlink, 'must be regular files'), (unchanged, None)]:
            with self.subTest(change=change.__name__):
                self.setUp()
                change()
                r = self.run_helper('preflight')
                if message is None:
                    self.assertEqual(r.returncode, 0, r.stderr)
                else:
                    self.assert_refused(r, message)
                    self.assertEqual(self.remote()['calls'], [])
        self.setUp()
        early_bundle()
        r = self.run_helper('preflight')
        self.assertIn('exactly 13 files', r.stderr)

    def test_an_existing_work_directory_is_refused(self):
        (self.base / 'work').mkdir()
        self.assert_refused(self.run_helper('preflight'), 'work directory must not exist')


class CaptureTests(Harness):
    def prepared(self):
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.outputs()['sign'], 'true')
        # The workflow has read these outputs; capture writes none.
        self.output.unlink()

    def test_the_one_new_bundle_is_verified_and_kept_verbatim(self):
        self.prepared()
        bundle = stub_bundle(self.manifest)
        r = self.run_helper('capture', '--bundle-path', str(self.attest_output(bundle)))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.dist / 'SHA256SUMS.sigstore.json').read_bytes(), bundle)
        self.assertEqual(self.stub_log.read_text(), 'candidate-SHA256SUMS.sigstore.json\n')

    def test_anything_but_exactly_one_bundle_is_refused(self):
        bundle = stub_bundle(self.manifest)
        cases = [(bundle + bundle, 'exactly one bundle'), (bundle[:-1], 'exactly one bundle'),
                 (b'\n', 'exactly one bundle'), (b'[' + bundle, 'exactly one bundle'),
                 (b'{' + b' ' * (256 * 1024) + b'}\n', 'size limit')]
        for data, message in cases:
            with self.subTest(data=data[:40]):
                self.setUp()
                self.prepared()
                r = self.run_helper('capture', '--bundle-path', str(self.attest_output(data)))
                self.assert_refused(r, message)

    def test_a_signature_the_verifier_rejects_never_reaches_the_release_directory(self):
        self.prepared()
        r = self.run_helper('capture', '--bundle-path',
                            str(self.attest_output(stub_bundle(self.manifest, OTHER_COMMIT))))
        self.assert_refused(r, 'native verifier rejected the bundle')

    def test_a_symlinked_or_missing_bundle_path_is_refused(self):
        self.prepared()
        real = self.attest_output(stub_bundle(self.manifest))
        link = self.base / 'link.json'
        link.symlink_to(real)
        for path in [link, self.base / 'missing.json']:
            with self.subTest(path=path.name):
                self.assert_refused(self.run_helper('capture', '--bundle-path', str(path)),
                                    'readable regular file')


class FinalTests(Harness):
    def signed(self):
        (self.dist / 'SHA256SUMS.sigstore.json').write_bytes(stub_bundle(self.manifest))

    def test_the_fourteen_paths_end_with_the_bundle_and_then_the_manifest(self):
        self.signed()
        r = self.run_helper('final')
        self.assertEqual(r.returncode, 0, r.stderr)
        paths = r.stdout.splitlines()
        self.assertEqual(len(paths), 14)
        self.assertEqual([Path(p).name for p in paths],
                         PRODUCTS + ['SHA256SUMS.sigstore.json', 'SHA256SUMS'])
        self.assertTrue(all(Path(p).parent == self.dist for p in paths))
        self.assertEqual(self.stub_log.read_text(), 'SHA256SUMS.sigstore.json\n')

    def test_no_other_file_becomes_a_release_asset(self):
        for name in ['verify-release', 'trusted_root.json', 'attestation.json', 'test.log']:
            with self.subTest(name=name):
                self.setUp()
                self.signed()
                (self.dist / name).write_bytes(b'not a release asset')
                r = self.run_helper('final')
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('exactly 14 files', r.stderr)
                self.assertEqual(r.stdout, '')

    def test_a_missing_or_rejected_bundle_or_a_changed_product_stops_it(self):
        r = self.run_helper('final')
        self.assertIn('exactly 14 files', r.stderr)
        (self.dist / 'SHA256SUMS.sigstore.json').write_bytes(stub_bundle(self.manifest, OTHER_COMMIT))
        r = self.run_helper('final')
        self.assertIn('native verifier rejected the bundle', r.stderr)
        self.signed()
        (self.dist / PRODUCTS[0]).write_bytes(b'changed after signing')
        r = self.run_helper('final')
        self.assertIn('does not match the release products', r.stderr)
        self.assertEqual(r.stdout, '')


class PublicationTests(Harness):
    """The workflow's own publish shell, the uploader and the fake gh."""

    def publish_body(self):
        workflow = WORKFLOW.read_text()
        block = workflow.split('      - name: Publish the release\n', 1)[1]
        body = block.split('        run: |\n', 1)[1]
        lines = []
        for line in body.splitlines():
            if line and not line.startswith('          '):
                break
            lines.append(line[10:])
        return '\n'.join(lines)

    def publish(self):
        (self.base / 'scripts').mkdir(exist_ok=True)
        for name in ['prepare-release-attestation.py', 'upload-release-assets.py',
                     'assemble-release-assets.py', 'check-release-version.py', 'check-release-output.py']:
            shutil.copyfile(ROOT / 'scripts' / name, self.base / 'scripts' / name)
        (self.base / 'notes.md').write_text('notes')
        env = dict(self.env, GITHUB_REPOSITORY=REPO, GITHUB_REF_NAME=TAG, GITHUB_SHA=COMMIT,
                   RELEASE_VERSION=VERSION, RELEASE_VERIFIER=str(self.base / 'stub-verifier'))
        return subprocess.run(['bash', '-e', '-c', self.publish_body()], cwd=self.base,
                              env=env, capture_output=True, text=True, timeout=60)

    def test_a_first_publication_uploads_the_fourteen_files_manifest_last(self):
        (self.dist / 'SHA256SUMS.sigstore.json').write_bytes(stub_bundle(self.manifest))
        r = self.publish()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.remote()['mutations'], ['create'] + ['upload:' + n for n in PRODUCTS]
                         + ['upload:SHA256SUMS.sigstore.json', 'upload:SHA256SUMS'])

    def test_an_interrupted_upload_is_completed_by_reusing_the_published_bundle(self):
        bundle = stub_bundle(self.manifest)
        published = [{'name': n, 'content': (self.dist / n).read_bytes().decode('latin1')} for n in PRODUCTS]
        self.set_remote(release=True, assets=published + [
            {'name': 'SHA256SUMS.sigstore.json', 'content': bundle.decode()}])
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.outputs(), {'sign': 'false'})
        r = self.publish()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.remote()['mutations'], ['upload:SHA256SUMS'])

    def test_a_concurrent_publication_cannot_replace_the_bundle(self):
        # Another run signed and uploaded its own bundle after this run's
        # preflight. The upload of this run's bundle collides and fails
        # without replacing anything; a retry reuses the published one.
        mine = stub_bundle(self.manifest)
        theirs = b'{"stub-bundle-for": "%s", "commit": "%s", "run": 2}\n' % (
            hashlib.sha256(self.manifest).hexdigest().encode(), COMMIT.encode())
        (self.dist / 'SHA256SUMS.sigstore.json').write_bytes(mine)
        self.set_remote(race={'SHA256SUMS.sigstore.json': theirs.decode()})
        r = self.publish()
        self.assertNotEqual(r.returncode, 0)
        remote = self.remote()
        self.assertEqual([a['name'] for a in remote['assets']][-1], 'SHA256SUMS.sigstore.json')
        self.assertEqual(remote['assets'][-1]['content'], theirs.decode())
        self.assertNotIn('upload:SHA256SUMS', remote['mutations'])
        # A retry: the stub rejects the competitor's bundle, so it is
        # invalid evidence for this run and a hard stop.
        (self.dist / 'SHA256SUMS.sigstore.json').unlink()
        self.output.unlink(missing_ok=True)
        before = self.remote()['assets']
        r = self.run_helper('preflight')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('native verifier rejected the bundle', r.stderr)
        self.assertEqual(self.remote()['assets'], before)

    def test_a_concurrent_valid_bundle_is_adopted_on_retry(self):
        mine = stub_bundle(self.manifest)
        (self.dist / 'SHA256SUMS.sigstore.json').write_bytes(mine)
        # The competitor's bundle is valid for the same manifest and commit.
        self.set_remote(race={'SHA256SUMS.sigstore.json': mine.decode()})
        r = self.publish()
        self.assertNotEqual(r.returncode, 0)
        (self.dist / 'SHA256SUMS.sigstore.json').unlink()
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.outputs(), {'sign': 'false'})
        r = self.publish()
        self.assertEqual(r.returncode, 0, r.stderr)
        names = [a['name'] for a in self.remote()['assets']]
        self.assertEqual(sorted(names), sorted(PRODUCTS + ['SHA256SUMS', 'SHA256SUMS.sigstore.json']))
        self.assertEqual(len(names), 14)

    def test_a_conflicting_published_product_stops_before_any_upload(self):
        (self.dist / 'SHA256SUMS.sigstore.json').write_bytes(stub_bundle(self.manifest))
        self.set_remote(release=True, assets=[{'name': PRODUCTS[-1], 'content': 'different'}])
        r = self.publish()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('Conflicting release asset: ' + PRODUCTS[-1], r.stderr)
        self.assertEqual(self.remote()['mutations'], [])


class WorkflowTests(unittest.TestCase):
    """The release workflow's gates, permissions and signing inputs, as text."""

    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text()
        jobs = cls.text.split('\njobs:\n', 1)[1]
        cls.jobs = dict(re.findall(r'(?ms)^  ([a-z0-9-]+):\n(.*?)(?=^  [a-z0-9-]+:\n|\Z)', jobs))

    def step(self, job, name):
        block = self.jobs[job].split(f'      - name: {name}\n', 1)[1]
        return re.split(r'\n      - ', block, maxsplit=1)[0]

    def test_only_publish_may_sign_or_write(self):
        self.assertIn('\npermissions:\n  contents: read\n\njobs:', self.text)
        for job, body in self.jobs.items():
            with self.subTest(job=job):
                if job == 'publish':
                    self.assertIn('    permissions:\n      contents: write\n      id-token: write\n'
                                  '      attestations: write\n', body)
                else:
                    self.assertNotRegex(body, r'id-token|attestations|contents: write')
        self.assertIn('    permissions:\n      contents: read\n', self.jobs['release'])
        self.assertIn('    permissions:\n      contents: read\n', self.jobs['release-verifier'])

    def test_publish_gates_dependencies_and_concurrency(self):
        body = self.jobs['publish']
        self.assertIn("    if: github.ref_type == 'tag' && github.repository == 'br0adcast/qsh'\n", body)
        self.assertIn('    needs: [release, ordinary-ci, released-peer-acceptance, release-verifier]\n', body)
        self.assertIn('    concurrency:\n      group: qsh-release-${{ github.ref }}\n'
                      '      cancel-in-progress: false\n', body)
        self.assertNotRegex(self.text, r'always\(\)|continue-on-error')
        gate = self.step('publish', 'Require the release repository and tag')
        for check in ['test "$GITHUB_REPOSITORY" = br0adcast/qsh', 'test "$GITHUB_REF_TYPE" = tag',
                      'test "$GITHUB_REF" = "refs/tags/v$RELEASE_VERSION"']:
            self.assertIn(check, gate)
        self.assertIn("    if: github.ref_type == 'tag' && github.repository == 'br0adcast/qsh'\n",
                      self.jobs['release-verifier'])

    def test_privileged_checkouts_are_exact_and_keep_no_credentials(self):
        for job in ['publish', 'release-verifier']:
            with self.subTest(job=job):
                self.assertIn('        with:\n          ref: ${{ github.sha }}\n'
                              '          persist-credentials: false\n', self.jobs[job])
                self.assertIn('test "$actual" = "$GITHUB_SHA"', self.jobs[job])
                self.assertNotIn('rust-cache', self.jobs[job])

    def test_the_signature_step_has_the_exact_pinned_inputs(self):
        step = self.step('publish', 'Sign the release manifest')
        self.assertEqual(step.strip(), '''id: attest
        if: steps.preflight.outputs.sign == 'true'
        uses: actions/attest@1e69f48acb82d1966a394da916b4c1698aa569d6 # v4.2.2
        with:
          subject-name: SHA256SUMS
          subject-digest: sha256:${{ steps.preflight.outputs.digest }}
          predicate-type: https://github.com/br0adcast/qsh/release-manifest/v1
          predicate-path: ${{ steps.preflight.outputs.predicate }}''')
        self.assertEqual(self.text.count('actions/attest@'), 1)

    def test_steps_run_in_order_and_publish_passes_explicit_files(self):
        body = self.jobs['publish']
        order = ['Require the release repository and tag', 'name: dist', 'name: release-verifier',
                 'Check the published release metadata', 'Sign the release manifest',
                 'Verify the new signature', 'Check release metadata for secrets', 'Publish the release']
        positions = [body.index(marker) for marker in order]
        self.assertEqual(positions, sorted(positions))
        publish = self.step('publish', 'Publish the release')
        self.assertIn('test "${#assets[@]}" -eq 14', publish)
        self.assertIn('"${assets[@]}"', publish)
        self.assertNotIn('dist/*', publish)
        self.assertIn('if: steps.preflight.outputs.sign == \'true\'',
                      self.step('publish', 'Verify the new signature'))

    def test_the_verifier_is_built_locked_from_this_checkout_and_scanned_metadata_is_explicit(self):
        build = self.step('release-verifier', 'Build the native release verifier')
        self.assertIn('cargo build --locked -p release-auth --example verify-release', build)
        self.assertIn('CARGO_TARGET_DIR: ${{ runner.temp }}/release-verifier-build', build)
        self.assertIn('scripts/check-release-version.py',
                      self.step('release-verifier', 'Validate the shipped pair version'))
        self.assertIn('RELEASE_VERSION: ${{ needs.release-verifier.outputs.version }}', self.jobs['publish'])
        scan = self.step('publish', 'Check release metadata for secrets')
        self.assertIn('cp dist/SHA256SUMS dist/SHA256SUMS.sigstore.json "$audit/"', scan)
        self.assertIn('551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb', scan)

    def test_branch_assembly_keeps_thirteen_unsigned_files(self):
        release = self.jobs['release']
        self.assertNotIn('sigstore', release)
        self.assertNotIn('prepare-release-attestation', release)
        self.assertIn('scripts/assemble-release-assets.py', release)


@unittest.skipUnless(os.environ.get('QSH_TEST_RELEASE_VERIFIER'),
                     'set QSH_TEST_RELEASE_VERIFIER to the built verify-release example')
class RealVerifierTests(Harness):
    """The real native verifier refuses evidence that does not authenticate this release."""

    verifier = os.environ.get('QSH_TEST_RELEASE_VERIFIER')

    def test_a_published_public_sigstore_bundle_for_another_artifact_is_a_hard_stop(self):
        # A genuine public-good bundle, signed by another project's workflow.
        bundle = PUBLIC_FIXTURE.read_bytes()
        self.set_remote(release=True, assets=[{'name': 'SHA256SUMS.sigstore.json',
                                               'content': bundle.decode('latin1')}])
        self.assert_refused(self.run_helper('preflight'), 'native verifier rejected the bundle')

    def test_invalid_and_synthetic_evidence_is_refused(self):
        for data in [stub_bundle(self.manifest), b'{}\n', b'{"mediaType":"x"}\n']:
            with self.subTest(data=data[:30]):
                self.setUp()
                self.set_remote(release=True, assets=[{'name': 'SHA256SUMS.sigstore.json',
                                                       'content': data.decode()}])
                self.assert_refused(self.run_helper('preflight'), 'native verifier rejected the bundle')

    def test_a_captured_bundle_that_does_not_authenticate_is_refused(self):
        r = self.run_helper('preflight')
        self.assertEqual(r.returncode, 0, r.stderr)
        self.output.unlink()
        r = self.run_helper('capture', '--bundle-path', str(self.attest_output(PUBLIC_FIXTURE.read_bytes())))
        self.assert_refused(r, 'native verifier rejected the bundle')

    def test_final_refuses_a_bundle_that_does_not_authenticate(self):
        shutil.copyfile(PUBLIC_FIXTURE, self.dist / 'SHA256SUMS.sigstore.json')
        r = self.run_helper('final')
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('native verifier rejected the bundle', r.stderr)
        self.assertEqual(r.stdout, '')


if __name__ == '__main__':
    unittest.main()
