"""Offline bootstrap fixtures; downloaded executable is a shell stub, never qsh."""
import io
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/install.sh'

class BootstrapTests(unittest.TestCase):
    def run_fixture(self, args=(), system='Linux', arch='x86_64', old=False, fail=False, hostile=False):
        with tempfile.TemporaryDirectory(prefix='qsh-bootstrap-fixture-') as temp:
            root = Path(temp)
            tools = root / 'tools'; tools.mkdir()
            record = root / 'record'
            target = {'Linux': 'unknown-linux-musl', 'Darwin': 'apple-darwin'}.get(system, 'unknown')
            cpu = {'arm64': 'aarch64', 'aarch64': 'aarch64'}.get(arch, arch)
            version = args[args.index('--version')+1] if '--version' in args and len(args)>args.index('--version')+1 else '0.6.0'
            stem = f'qsh-{version}-{cpu}-{target}'
            stub = ('#!/bin/sh\nif [ "$2" = --help ]; then\n' +
                    ('echo "old help"\n' if old else 'echo "Usage: qsh --self-install [--version VERSION] [--prefix PATH]"\n') +
                    'exit 0\nfi\nprintf "%s\\n" "$@" > "$FIXTURE_RECORD"\n').encode()
            archive = root / 'fixture.tar.gz'
            with tarfile.open(archive, 'w:gz') as tar:
                item = tarfile.TarInfo(stem + '/qsh'); item.size=len(stub); item.mode=0o755
                tar.addfile(item, io.BytesIO(stub))
                if hostile:
                    item=tarfile.TarInfo('../escape' if hostile is True else stem+'/qsh')
                    if hostile == 'invalid':
                        pass
                    elif hostile == 'link':
                        item.type=tarfile.SYMTYPE; item.linkname='/fixture/victim'; tar.addfile(item)
                    elif hostile == 'duplicate':
                        item.size=1; tar.addfile(item, io.BytesIO(b'x'))
                    else:
                        item.size=1; tar.addfile(item, io.BytesIO(b'x'))
            def tool(name, body):
                path=tools/name; path.write_text('#!/bin/sh\n'+body); path.chmod(0o755)
            tool('uname', f'case "$1" in -s) echo {system};; -m) echo {arch};; esac\n')
            tool('curl', 'printf "%s\\n" "$*" >> "$FIXTURE_URLS"\n' + ('exit 22\n' if fail else
                'case "$*" in *url_effective*) printf "https://github.com/br0adcast/qsh/releases/tag/v0.6.0";; *) while [ "$#" -gt 0 ]; do if [ "$1" = --output ]; then cp "$FIXTURE_ARCHIVE" "$2"; exit; fi; shift; done; exit 1;; esac\n'))
            if hostile == 'invalid': archive.write_bytes(b'not gzip')
            env=dict(os.environ, PATH=str(tools)+':'+os.environ['PATH'], HOME=str(root), TMPDIR=str(root), HISTFILE='/dev/null', FIXTURE_RECORD=str(record), FIXTURE_ARCHIVE=str(archive), FIXTURE_URLS=str(root/'urls'))
            result=subprocess.run(['sh',str(SCRIPT),*args],env=env,capture_output=True,text=True,timeout=5)
            return result, record.read_text() if record.exists() else '', (root/'urls').read_text() if (root/'urls').exists() else '', list(root.glob('qsh-install.*'))

    def test_four_targets_default_stable_and_cleanup(self):
        for system, arch in [('Linux','x86_64'),('Linux','aarch64'),('Darwin','x86_64'),('Darwin','arm64')]:
            with self.subTest(system=system, arch=arch):
                result, record, urls, leftovers=self.run_fixture(system=system,arch=arch)
                self.assertEqual(result.returncode,0,result.stderr)
                self.assertEqual(record,'--self-install\n--version\n0.6.0\n')
                self.assertIn('/releases/latest',urls)
                self.assertIn('--proto =https --proto-redir =https', urls)
                self.assertIn('--max-time 120', urls); self.assertEqual(leftovers,[])
    def test_exact_rc_and_prefix_spaces(self):
        result,record,urls,leftovers=self.run_fixture(['--version','0.6.0-rc.2','--prefix','/fixture/home path'])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(record,'--self-install\n--version\n0.6.0-rc.2\n--prefix\n/fixture/home path\n')
        self.assertNotIn('/releases/latest',urls); self.assertEqual(leftovers,[])
    def test_published_rc_spellings(self):
        for version in ('0.6.0-rc1', '0.6.0-rc10', '0.6.0-beta.2'):
            result, record, urls, leftovers=self.run_fixture(['--version',version])
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertIn(version+'\n',record)
            self.assertIn('/download/v'+version+'/',urls)
            self.assertEqual(leftovers,[])
    def test_help_does_not_fetch(self):
        result, record, urls, leftovers=self.run_fixture(['--help'])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('Usage:',result.stdout)
        self.assertEqual((record,urls,leftovers), ('','',[]))
    def test_invalid_exact_versions_refuse_before_fetch(self):
        cases = [
            ['--version', ''],
            ['--version', '', '--version', '0.6.0'],
            ['--version', '0.6.0', '--version', '0.7.0'],
            ['--version', '0.6.0\n0.7.0'],
            ['--version', '\n0.6.0'],
            ['--version', '0.6.0\n'],
            ['--version', '0.6.0\r'],
            ['--version', '0.6.0\t'],
            ['--version', '0.6.0\x1b'],
        ]
        for args in cases:
            with self.subTest(args=args):
                result, record, urls, leftovers=self.run_fixture(args=args)
                self.assertNotEqual(result.returncode,0)
                self.assertEqual((record,urls,leftovers), ('','',[]))
    def test_refusals_do_not_invoke_engine_and_cleanup(self):
        for options in [dict(old=True),dict(fail=True),dict(hostile=True),dict(hostile='link'),dict(hostile='duplicate'),dict(hostile='invalid'),dict(system='Other'),dict(args=['--version','../bad']),dict(args=['--prefix']),dict(args=['--yes'])]:
            with self.subTest(options=options):
                result,record,urls,leftovers=self.run_fixture(**options)
                self.assertNotEqual(result.returncode,0); self.assertEqual(record,''); self.assertEqual(leftovers,[])

if __name__ == '__main__': unittest.main()
