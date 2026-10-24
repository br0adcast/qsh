"""Exercise the production uploader against a local, strict gh command boundary."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
HELPER = ROOT / 'scripts/upload-release-assets.py'
FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
p = pathlib.Path(os.environ['FAKE_STATE'])
s = json.loads(p.read_text())
a = sys.argv[1:]
def save(): p.write_text(json.dumps(s))
def fail(): sys.exit(1)
if a[:2] == ['api', '--paginate']:
    if s.get('error') == 'query': fail()
    if s.get('error') == 'malformed':
        print('{}'); sys.exit(0)
    endpoint = a[-1]
    if endpoint == 'repos/example/project/releases':
        print(json.dumps([[{'id': 1, 'tag_name': 'v1.2.3-rc1'}] if s['exists'] else []]))
    elif endpoint == 'repos/example/project/releases/1/assets':
        if s.get('error') == 'assets': fail()
        print(json.dumps([[{'id': i+1, 'name': n}] for i,n in enumerate(s['assets'])]))
    else: raise AssertionError(a)
elif a[:3] == ['api', '-H', 'Accept: application/octet-stream']:
    if s.get('error') == 'download': fail()
    idx = int(a[-1].rsplit('/',1)[1])-1
    sys.stdout.buffer.write(list(s['assets'].values())[idx].encode('latin1'))
elif a[:2] == ['release', 'create']:
    assert a == ['release','create','v1.2.3-rc1','--repo','example/project','--verify-tag','--title','qsh 1.2.3-rc1','--notes-file',os.environ['FAKE_NOTES'],'--prerelease'], a
    if s.get('error') == 'create': fail()
    assert not s['exists']
    s['exists'] = True
    s['metadata'] = {'title':'qsh 1.2.3-rc1', 'notes':'release notes', 'prerelease':True}
    s['mutations'].append('create'); save()
elif a[:2] == ['release', 'upload']:
    assert a[:5] == ['release','upload','v1.2.3-rc1','--repo','example/project'], a
    assert len(a) == 6, a
    f = pathlib.Path(a[5])
    if s.get('race'):
        s['assets'][f.name] = s['race']; save(); fail()
    if s.get('error') == 'upload' or f.name in s['assets']: fail()
    s['assets'][f.name] = f.read_bytes().decode('latin1')
    s['mutations'].append('upload:'+f.name); save()
else: raise AssertionError(a)
'''


class ReleaseUploadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        (self.base/'gh').write_text(FAKE)
        (self.base/'gh').chmod(0o755)
        self.notes = self.base/'notes.md'
        self.notes.write_text('release notes')
        self.state = self.base/'state.json'
        self.env = dict(os.environ, PATH=str(self.base)+os.pathsep+os.environ['PATH'],
                        HOME=str(self.base), XDG_CACHE_HOME=str(self.base/'cache'),
                        XDG_CONFIG_HOME=str(self.base/'config'), HISTFILE='/dev/null',
                        FAKE_STATE=str(self.state), FAKE_NOTES=str(self.notes))

    def run_upload(self, assets=None, exists=True, files=None, **extra):
        initial = dict(exists=exists, assets=assets or {}, mutations=[],
                       metadata={'title':'keep', 'notes':'keep', 'prerelease':False}, **extra)
        self.state.write_text(json.dumps(initial))
        paths = []
        for name, content in (files or {'a.tar.gz':'aaa','b.deb':'bbb'}).items():
            path = self.base/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content.encode('latin1'))
            paths.append(str(path))
        result = subprocess.run([sys.executable,str(HELPER),'--repo','example/project',
                                 '--tag','v1.2.3-rc1','--notes-file',str(self.notes),*paths],
                                env=self.env, capture_output=True, text=True)
        return result, json.loads(self.state.read_text()), initial

    def test_first_publication(self):
        r, s, _ = self.run_upload(exists=False)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(s['assets'], {'a.tar.gz':'aaa','b.deb':'bbb'})
        self.assertEqual(s['mutations'], ['create','upload:a.tar.gz','upload:b.deb'])

    def test_binary_identical_retry_and_same_size_conflict(self):
        for remote, success in [('\x00\xffa', True), ('\x00\xffb', False)]:
            with self.subTest(success=success):
                r, s, initial = self.run_upload({'a.tar.gz':remote}, files={'a.tar.gz':'\x00\xffa'})
                self.assertEqual(r.returncode == 0, success, r.stderr)
                self.assertEqual(s, initial)

    def test_identical_retry_preserves_everything(self):
        r, s, initial = self.run_upload({'a.tar.gz':'aaa','b.deb':'bbb'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(s, initial)

    def test_partial_retry_adds_only_missing(self):
        r, s, initial = self.run_upload({'a.tar.gz':'aaa'})
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(s['mutations'], ['upload:b.deb'])
        self.assertEqual(s['metadata'], initial['metadata'])

    def test_later_conflict_prevents_earlier_missing_upload(self):
        r, s, initial = self.run_upload({'b.deb':'different'})
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('b.deb', r.stderr)
        self.assertEqual(s, initial)

    def test_errors_are_fatal(self):
        for error in ['query','assets','malformed','download','upload','create']:
            with self.subTest(error=error):
                r, s, initial = self.run_upload({'a.tar.gz':'aaa'}, exists=error!='create', error=error)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(s, initial)

    def test_competing_upload_cannot_replace_bytes(self):
        for content in ['aaa','competitor']:
            with self.subTest(content=content):
                r, s, _ = self.run_upload(race=content)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(s['assets'], {'a.tar.gz':content})
                self.assertEqual(s['mutations'], [])
                retry, retried, _ = self.run_upload(s['assets'], files={'a.tar.gz':'aaa'})
                self.assertEqual(retry.returncode == 0, content == 'aaa', retry.stderr)
                self.assertEqual(retried['assets'], s['assets'])
                self.assertEqual(retried['mutations'], [])

    def test_workflow_publish_command_uses_immutable_helper(self):
        # Execute the workflow's actual shell body with the same local boundary.
        workflow = (ROOT/'.github/workflows/release.yml').read_text()
        block = workflow.split('      - name: Publish the release\n', 1)[1]
        command = block.split('        run: |\n', 1)[1]
        command = '\n'.join(line[10:] for line in command.splitlines())
        (self.base/'scripts').symlink_to(ROOT/'scripts', target_is_directory=True)
        (self.base/'dist').mkdir()
        (self.base/'dist/a.tar.gz').write_text('aaa')
        initial = dict(exists=True, assets={'a.tar.gz':'different'}, mutations=[], metadata={})
        self.state.write_text(json.dumps(initial))
        env = dict(self.env, GITHUB_REPOSITORY='example/project', GITHUB_REF_NAME='v1.2.3-rc1')
        result = subprocess.run(['bash','-e','-c',command], cwd=self.base,
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Conflicting release asset: a.tar.gz', result.stderr)
        self.assertEqual(json.loads(self.state.read_text()), initial)

    def test_missing_directory_and_empty_inputs_fail_before_mutation(self):
        initial = dict(exists=False, assets={}, mutations=[], metadata={})
        (self.base/'directory').mkdir()
        for paths in [[], [str(self.base/'missing')], [str(self.base/'directory')]]:
            with self.subTest(paths=paths):
                self.state.write_text(json.dumps(initial))
                r = subprocess.run([sys.executable,str(HELPER),'--repo','example/project',
                                    '--tag','v1.2.3-rc1','--notes-file',str(self.notes),*paths],
                                   env=self.env, capture_output=True, text=True)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(json.loads(self.state.read_text()), initial)

    def test_invalid_names_and_duplicates_fail_before_mutation(self):
        for files in [{'bad#label':'x'}, {'one/a':'x','two/a':'y'}]:
            with self.subTest(files=files):
                r, s, initial = self.run_upload(files=files)
                self.assertNotEqual(r.returncode, 0)
                self.assertEqual(s, initial)


if __name__ == '__main__':
    unittest.main()
