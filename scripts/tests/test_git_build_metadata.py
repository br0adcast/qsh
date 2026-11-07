"""Observe real Cargo freshness and stamps through both production build scripts."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
import tomllib

ROOT = Path(__file__).resolve().parents[2]
CC_STUB = '''#[allow(dead_code)]
mod cc {
    pub struct Build;
    impl Build {
        pub fn new() -> Self { Self }
        pub fn file(&mut self, _: &str) -> &mut Self { self }
        pub fn flag_if_supported(&mut self, _: &str) -> &mut Self { self }
        pub fn warnings(&mut self, _: bool) -> &mut Self { self }
        pub fn extra_warnings(&mut self, _: bool) -> &mut Self { self }
        pub fn compile(&mut self, _: &str) {}
    }
}
'''


class GitBuildMetadataTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='qsh-git-build-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.env = dict(os.environ)
        self.env.update(CARGO_HOME=os.environ.get('CARGO_HOME', str(Path.home()/'.cargo')),
                        RUSTUP_HOME=os.environ.get('RUSTUP_HOME', str(Path.home()/'.rustup')),
                        HOME=str(self.base/'home'), XDG_CONFIG_HOME=str(self.base/'config'),
                        XDG_CACHE_HOME=str(self.base/'cache'), HISTFILE='/dev/null',
                        GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_AUTHOR_NAME='Fixture', GIT_COMMITTER_NAME='Fixture',
                        GIT_AUTHOR_EMAIL='fixture@example.invalid',
                        GIT_COMMITTER_EMAIL='fixture@example.invalid',
                        CARGO_TARGET_DIR=str(self.base/'target'),
                        RUSTUP_TOOLCHAIN=tomllib.loads((ROOT/'rust-toolchain.toml').read_text())['toolchain']['channel'])
        for key in ['GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'SSH_AUTH_SOCK',
                    'QSH_OFFICIAL_RELEASE', 'GITHUB_SHA']:
            self.env.pop(key, None)
        self.epoch = 1700000000

    def command(self, args, cwd, **env):
        result = subprocess.run(args, cwd=cwd, env=dict(self.env, **env),
                                capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        return result.stdout+result.stderr

    def git(self, root, *args):
        return self.command(['git', '-C', str(root), *args], self.base)

    def commit(self, root):
        self.epoch += 100
        self.command(['git', '-C', str(root), 'commit', '--allow-empty', '-m', 'fixture'],
                     self.base, GIT_AUTHOR_DATE=f'{self.epoch} +0000',
                     GIT_COMMITTER_DATE=f'{self.epoch} +0000')
        return str(self.epoch)

    def repository(self, name='repo'):
        root = self.base/name
        root.mkdir()
        self.git(root, 'init', '-b', 'main')
        self.commit(root)
        return root

    def probes(self, root):
        # Include real product scripts; only the unused native compiler boundary
        # is stubbed, keeping this Cargo fixture dependency-free and offline.
        helper = ROOT/'build-support/git_metadata.rs'
        if helper.exists():
            (root/'build-support').mkdir(exist_ok=True)
            shutil.copyfile(helper, root/'build-support/git_metadata.rs')
        (root/'Cargo.toml').write_text('[workspace]\nmembers=["cli", "qshd"]\nresolver="2"\n')
        for name, stamp in [('cli', 'QSH_BUILD'), ('qshd', 'QSHD_BUILD')]:
            package = root/name
            (package/'src').mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT/name/'build.rs', package/'product.rs')
            (package/'Cargo.toml').write_text(
                f'[package]\nname="probe-{name}"\nversion="0.0.0"\nedition="2021"\n')
            (package/'src/main.rs').write_text(f'fn main() {{ println!("{{}}", env!("{stamp}")); }}\n')
            (package/'build.rs').write_text(CC_STUB + '''
#[allow(dead_code)]
mod product { #[allow(unused_imports)] use crate::cc; include!("product.rs"); pub fn run() { main(); } }
fn main() {
    let path = std::path::PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("runs");
    let count: u64 = std::fs::read_to_string(&path).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    std::fs::write(path, (count + 1).to_string()).unwrap();
    product::run();
}
''')

    def build(self, root):
        output = self.command(['cargo', 'build', '--workspace', '--offline', '-vv'], root)
        for metadata in (self.base/'target/debug/build').glob('*/output'):
            for line in metadata.read_text().splitlines():
                if line.startswith('cargo:rerun-if-changed='):
                    watched = Path(line.split('=', 1)[1])
                    # Absolute Git paths and package-relative source paths.
                    if not watched.is_absolute():
                        package = 'cli' if 'probe-cli-' in str(metadata) else 'qshd'
                        watched = root/package/watched
                    self.assertTrue(watched.exists(), line)
                    self.assertNotEqual(watched.resolve(), root.resolve(), line)
                    self.assertFalse((self.base/'target').resolve().is_relative_to(watched.resolve()), line)
        counters = sorted(int(p.read_text()) for p in (self.base/'target/debug/build').glob('*/out/runs'))
        stamps = [self.command([str(self.base/'target/debug'/f'probe-{name}')], root).strip()
                  for name in ['cli', 'qshd']]
        return counters, stamps, output

    def fresh(self, root, expected=None):
        before, stamps, _ = self.build(root)
        after, repeated, output = self.build(root)
        self.assertEqual(len(before), 2)
        self.assertEqual(before, after, output)
        self.assertEqual(stamps, repeated)
        self.assertIn('Fresh probe-cli', output)
        self.assertIn('Fresh probe-qshd', output)
        if expected is not None:
            self.assertEqual(stamps, [expected, expected])
        return after

    def changed(self, root, previous, expected):
        counters, stamps, _ = self.build(root)
        self.assertEqual(counters, [n+1 for n in previous])
        self.assertEqual(stamps, [expected, expected])
        self.assertEqual(self.fresh(root, expected), counters)
        return counters

    def exercise(self, root):
        self.probes(root)
        counts = self.fresh(root, self.git(root, 'log', '-1', '--format=%ct').strip())
        self.assertEqual(counts, [1, 1])
        counts = self.changed(root, counts, self.commit(root))
        self.git(root, 'branch', 'other')
        counts = self.changed(root, counts, str(self.epoch))
        self.git(root, 'checkout', 'other')
        counts = self.changed(root, counts, str(self.epoch))
        counts = self.changed(root, counts, self.commit(root))
        self.git(root, 'checkout', '--detach', 'HEAD~1')
        counts = self.changed(root, counts, str(self.epoch-100))
        self.git(root, 'checkout', 'other')
        counts = self.changed(root, counts, str(self.epoch))
        self.git(root, 'pack-refs', '--all', '--prune')
        counts = self.changed(root, counts, str(self.epoch))
        # A new commit recreates a loose current ref after packing it away.
        counts = self.changed(root, counts, self.commit(root))
        # Custom symbolic HEAD chain outside refs/heads remains observable.
        self.git(root, 'update-ref', 'refs/custom/current', 'HEAD~1')
        self.git(root, 'symbolic-ref', 'refs/custom/alias', 'refs/custom/current')
        self.git(root, 'symbolic-ref', 'HEAD', 'refs/custom/alias')
        counts = self.changed(root, counts, str(self.epoch-100))
        self.git(root, 'update-ref', 'refs/custom/current', 'other')
        self.changed(root, counts, str(self.epoch))

    def test_ordinary_checkout(self):
        self.exercise(self.repository())

    def test_linked_worktree(self):
        source = self.repository('source')
        root = self.base/'linked'
        self.git(source, 'worktree', 'add', '-b', 'fixture', str(root))
        self.exercise(root)

    def test_absorbed_submodule(self):
        source = self.repository('source')
        parent = self.repository('parent')
        self.git(parent, '-c', 'protocol.file.allow=always', 'submodule', 'add', str(source), 'module')
        self.git(parent, 'submodule', 'absorbgitdirs')
        root = parent/'module'
        self.assertTrue((root/'.git').is_file())
        self.exercise(root)

    def test_unborn_repository_and_first_ref_creation(self):
        root = self.base/'unborn'
        root.mkdir()
        self.git(root, 'init', '-b', 'main')
        self.probes(root)
        counts = self.fresh(root)
        self.changed(root, counts, self.commit(root))

    def test_git_unavailable_keeps_existing_marker_fresh(self):
        root = self.repository()
        self.probes(root)
        tools = self.base/'tools'
        tools.mkdir()
        unavailable = tools/'git'
        unavailable.write_text('#!/bin/sh\nexit 127\n')
        unavailable.chmod(0o700)
        self.env['PATH'] = str(tools)+os.pathsep+self.env['PATH']
        self.fresh(root)
        _, stamps, _ = self.build(root)
        self.assertNotEqual(stamps, [str(self.epoch), str(self.epoch)])

    def test_git_unavailable_worktree_still_observes_metadata_changes(self):
        source = self.repository('source')
        root = self.base/'linked'
        self.git(source, 'worktree', 'add', '-b', 'fixture', str(root))
        self.probes(root)
        tools = self.base/'tools'
        tools.mkdir()
        unavailable = tools/'git'
        unavailable.write_text('#!/bin/sh\nexit 127\n')
        unavailable.chmod(0o700)
        original_path = self.env['PATH']
        self.env['PATH'] = str(tools)+os.pathsep+original_path
        before = self.fresh(root)
        self.env['PATH'] = original_path
        self.commit(root)
        self.env['PATH'] = str(tools)+os.pathsep+original_path
        after, _, _ = self.build(root)
        self.assertEqual(after, [n+1 for n in before])
        self.assertEqual(self.fresh(root), after)

    def test_archive(self):
        root = self.base/'archive'
        root.mkdir()
        self.probes(root)
        self.fresh(root)

    def test_archive_nested_in_unrelated_repository(self):
        parent = self.repository('unrelated')
        root = parent/'archive'
        root.mkdir()
        self.probes(root)
        self.fresh(root)
        _, stamps, _ = self.build(root)
        self.assertNotEqual(stamps, [str(self.epoch), str(self.epoch)])


if __name__ == '__main__':
    unittest.main()
