"""The documented manual verification recipes, pasted into interactive shells.

`curl` and `gh` are stubs on PATH; `awk`, `sha256sum` and `tar` are real. The
archive's `qsh` is a stub that records its arguments, so a run shows whether
anything was extracted or executed.
"""

import hashlib
import io
import os
import pathlib
import pty
import re
import select
import shutil
import signal
import tarfile
import tempfile
import time
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
VERSION = '0.6.0'
STEM = f'qsh-{VERSION}-x86_64-unknown-linux-musl'
SHELLS = (('bash', '--norc', '--noprofile', '-i'), ('dash', '-i'), ('zsh', '-f', '-i'))
PROMPT = 'qsh-recipe-ready> '

CURL = '''#!/bin/sh
echo "$@" >> "$RECIPE_LOG/curl.args"
[ -z "$CURL_FAIL" ] || exit 22
while [ $# -gt 0 ]; do
  if [ "$1" = -O ]; then cp "$RECIPE_SERVED/${2##*/}" . || exit 22; shift; fi
  shift
done
'''
GH = '''#!/bin/sh
echo "$@" >> "$RECIPE_LOG/gh.args"
exit "${GH_EXIT:-0}"
'''
QSH = '''#!/bin/sh
echo "$@" >> "$RECIPE_LOG/qsh.args"
'''


def sh_block(document, after):
    """The first ```sh block after the text `after` in `document`."""
    text = (ROOT / document).read_text(encoding='utf-8')
    rest = text[text.index(after):]
    match = re.search(r'^```sh\n(.*?)^```$', rest, re.S | re.M)
    return match.group(1), rest[match.end():]


def archive():
    member = tarfile.TarInfo(f'{STEM}/qsh')
    member.mode = 0o755
    body = QSH.encode()
    member.size = len(body)
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode='w:gz') as tar:
        tar.addfile(member, io.BytesIO(body))
    return data.getvalue()


def manifest(entries):
    return ''.join(f'{digest}  {name}\n' for name, digest in sorted(entries.items())).encode()


def installed_shells():
    shells = [shell for shell in SHELLS if shutil.which(shell[0])]
    if not any(shell[0] == 'bash' for shell in shells):
        raise unittest.SkipTest('bash is not installed')
    return shells


class Run:
    def __init__(self, status, output, log, work):
        self.status, self.output, self.log, self.work = status, output, log, work

    def args(self, tool):
        path = self.log / f'{tool}.args'
        return path.read_text().splitlines() if path.exists() else []


def paste(shell, text, served, scratch, env_extra=()):
    """Types `text` into an interactive `shell` on a PTY, after its first
    prompt, and returns the status it reports."""
    scratch = pathlib.Path(scratch)
    bin_dir, log, tmp, home = (scratch / name for name in ('bin', 'log', 'tmp', 'home'))
    for directory in (bin_dir, log, tmp, home):
        directory.mkdir()
    for name, body in (('curl', CURL), ('gh', GH)):
        (bin_dir / name).write_text(body)
        (bin_dir / name).chmod(0o755)
    env = {
        'PATH': f'{bin_dir}:/usr/bin:/bin',
        'HOME': str(home),
        'TMPDIR': str(tmp),
        'HISTFILE': '/dev/null',
        'PS1': PROMPT,
        'TERM': 'dumb',
        'LC_ALL': 'C',
        'RECIPE_LOG': str(log),
        'RECIPE_SERVED': str(served),
        **dict(env_extra),
    }
    argv = [shutil.which(shell[0]), *shell[1:]]
    pid, fd = pty.fork()
    if pid == 0:
        try:
            os.chdir(home)
            os.execve(argv[0], argv, env)
        finally:
            os._exit(127)
    output = b''
    sent = False
    deadline = time.monotonic() + 60
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([fd], [], [], max(0, deadline - time.monotonic()))
            if not ready:
                continue
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                break
            if not chunk:
                break
            output += chunk
            # Paste only once the shell is reading, as a person would.
            if not sent and PROMPT.encode() in output:
                os.write(fd, (text + 'echo "DONE:$?"\nexit\n').encode())
                sent = True
    finally:
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        os.waitpid(pid, 0)
        os.close(fd)
    decoded = output.decode(errors='replace')
    status = re.findall(r'DONE:(\d+)', decoded)
    if len(status) != 1:
        raise AssertionError(f'{shell[0]} reported no status: {decoded}')
    work = [path for path in tmp.iterdir() if path.is_dir()]
    return Run(int(status[0]), decoded, log, work)


class FirstInstallRecipe(unittest.TestCase):
    def setUp(self):
        self.recipe, self.after = sh_block('docs/release-security.md',
                                           '### First installation from a verified archive')
        self.served_dir = tempfile.TemporaryDirectory()
        self.served = pathlib.Path(self.served_dir.name)
        self.addCleanup(self.served_dir.cleanup)
        self.archive = archive()
        self.entries = {
            f'{STEM}.tar.gz': hashlib.sha256(self.archive).hexdigest(),
            f'qsh_{VERSION}-1_amd64.deb': '0' * 64,
        }

    def serve(self, entries=None, archive_bytes=None):
        (self.served / 'SHA256SUMS').write_bytes(manifest(self.entries if entries is None else entries))
        (self.served / 'SHA256SUMS.sigstore.json').write_bytes(b'{"bundle": "stub"}\n')
        (self.served / f'{STEM}.tar.gz').write_bytes(self.archive if archive_bytes is None else archive_bytes)

    def run_recipe(self, shell, **env):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        run = paste(shell, self.recipe, self.served, scratch.name, env.items())
        self.assertEqual(len(run.work), 1, run.output)
        return run

    def assert_not_extracted(self, run):
        self.assertNotEqual(run.status, 0, run.output)
        self.assertEqual(run.args('qsh'), [], run.output)
        self.assertFalse((run.work[0] / STEM).exists(), run.output)

    def test_block_has_no_comments_for_interactive_zsh(self):
        # zsh without INTERACTIVE_COMMENTS runs `#` as a command.
        self.assertNotIn('#', self.recipe)

    def test_verified_archive_is_extracted_and_installs(self):
        self.serve()
        for shell in installed_shells():
            with self.subTest(shell=shell[0]):
                run = self.run_recipe(shell)
                self.assertEqual(run.status, 0, run.output)
                self.assertEqual(run.args('qsh'), [f'--self-install --version {VERSION}'])
                self.assertEqual(run.args('gh'), [
                    'attestation verify SHA256SUMS --bundle SHA256SUMS.sigstore.json '
                    '--repo br0adcast/qsh --cert-identity '
                    'https://github.com/br0adcast/qsh/.github/workflows/release.yml'
                    f'@refs/tags/v{VERSION} '
                    '--predicate-type https://github.com/br0adcast/qsh/release-manifest/v1 '
                    '--deny-self-hosted-runners'])
                base = f'https://github.com/br0adcast/qsh/releases/download/v{VERSION}'
                self.assertEqual(run.args('curl'), [
                    "--fail --location --proto =https --proto-redir =https "
                    f"-O {base}/SHA256SUMS -O {base}/SHA256SUMS.sigstore.json "
                    f"-O {base}/{STEM}.tar.gz"])

    def test_failed_download_extracts_and_runs_nothing(self):
        self.serve()
        for shell in installed_shells():
            with self.subTest(shell=shell[0]):
                run = self.run_recipe(shell, CURL_FAIL='1')
                self.assert_not_extracted(run)
                self.assertEqual(run.args('gh'), [])

    def test_failed_attestation_extracts_and_runs_nothing(self):
        self.serve()
        for shell in installed_shells():
            with self.subTest(shell=shell[0]):
                run = self.run_recipe(shell, GH_EXIT='1')
                self.assert_not_extracted(run)
                self.assertEqual(len(run.args('gh')), 1)

    def test_archive_not_matching_the_manifest_extracts_and_runs_nothing(self):
        self.serve(archive_bytes=self.archive + b'\0')
        for shell in installed_shells():
            with self.subTest(shell=shell[0]):
                run = self.run_recipe(shell)
                self.assert_not_extracted(run)
                self.assertIn('FAILED', run.output)

    def test_archive_missing_from_the_manifest_extracts_and_runs_nothing(self):
        entries = dict(self.entries)
        del entries[f'{STEM}.tar.gz']
        self.serve(entries=entries)
        for shell in installed_shells():
            with self.subTest(shell=shell[0]):
                self.assert_not_extracted(self.run_recipe(shell))

    def test_archive_listed_twice_extracts_and_runs_nothing(self):
        twice = manifest(self.entries) + manifest({f'{STEM}.tar.gz': self.entries[f'{STEM}.tar.gz']})
        self.serve()
        (self.served / 'SHA256SUMS').write_bytes(twice)
        for shell in installed_shells():
            with self.subTest(shell=shell[0]):
                self.assert_not_extracted(self.run_recipe(shell))


class ReadmeChecksumLookup(unittest.TestCase):
    """The README's per-file lookup accepts only a single exact manifest line."""

    def setUp(self):
        verify, _ = sh_block('README.md', 'Verify downloads in two steps.')
        lookup, _ = sh_block('README.md', 'Then check each downloaded file by its exact name.')
        self.assertNotIn('#', verify + lookup)
        self.blocks = verify + lookup

    def check(self, files, entries):
        """Runs the README blocks in a directory holding `files`."""
        results = []
        for shell in installed_shells():
            with tempfile.TemporaryDirectory() as here, tempfile.TemporaryDirectory() as scratch:
                here = pathlib.Path(here)
                for name, body in files.items():
                    (here / name).write_bytes(body)
                (here / 'SHA256SUMS').write_bytes(manifest(entries))
                (here / 'SHA256SUMS.sigstore.json').write_bytes(b'{}\n')
                run = paste(shell, f'cd {here}\n' + self.blocks, here, scratch)
                results.append((shell[0], run))
        self.assertTrue(results)
        return results

    def test_listed_file_passes(self):
        body = b'package'
        name = f'qsh_{VERSION}-1_amd64.deb'
        for shell, run in self.check({name: body}, {name: hashlib.sha256(body).hexdigest()}):
            self.assertEqual(run.status, 0, (shell, run.output))

    def test_unlisted_or_changed_file_fails(self):
        name = f'qsh_{VERSION}-1_amd64.deb'
        for entries in ({'other.deb': '0' * 64}, {name: '0' * 64}):
            for shell, run in self.check({name: b'package'}, entries):
                self.assertNotEqual(run.status, 0, (shell, entries, run.output))


if __name__ == '__main__':
    unittest.main()
