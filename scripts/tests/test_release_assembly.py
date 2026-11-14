"""Generated public payloads model assembly only; never execute package contents."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
PEER_NAMES=('identity.txt','passed.txt','current_qsh_pastes_a_megabyte_into_current_daemon.log',
    'protocol2_client_cannot_allocate_a_connection_on_published_v050.log',
    'protocol2_client_cannot_mutate_published_v050_daemon.log',
    'published_v050_client_cannot_mutate_protocol2_daemon.log',
    'published_v050_pair_is_a_real_shell_start_positive_control.log',
    'this_qsh_follows_a_flood_as_screen_repaints_with_the_header_under_aead.log')


def names(version='0.5.0'):
    # Published names carry the release version, never the package metadata's '~'.
    result={}
    for target,deb_arch,rpm_arch in [('x86_64-unknown-linux-musl','amd64','x86_64'),('aarch64-unknown-linux-musl','arm64','aarch64')]:
        result['linux-'+target]=(f'qsh-{version}-{target}.tar.gz',f'qsh_{version}-1_{deb_arch}.deb',f'qsh-{version}-1.{rpm_arch}.rpm')
    result['macos']=tuple(f'qsh-{version}-{target}.tar.gz' for target in ('aarch64-apple-darwin','x86_64-apple-darwin'))
    result['server-packages']=tuple(f'qshd_{version}-1_{a}.deb' for a in ('amd64','arm64'))+tuple(f'qshd-{version}-1.{a}.rpm' for a in ('x86_64','aarch64'))
    return result


class Layout(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='qsh-release-assembly-');self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.artifacts=self.root/'artifacts';self.artifacts.mkdir()
        self.expected={}
        for producer,files in names().items():
            directory=self.artifacts/producer;directory.mkdir()
            for name in files:
                data=('PUBLIC SYNTHETIC PAYLOAD '+producer+'/'+name+'\n').encode()
                (directory/name).write_bytes(data);self.expected[name]=data
        peer=self.artifacts/'released-peer-evidence';peer.mkdir()
        for name in PEER_NAMES:(peer/name).write_bytes(b'PUBLIC SYNTHETIC EVIDENCE; NOT A PRODUCT\n')
        for directory in ('darwin-producer-evidence','native-evidence','future-evidence'):
            path=self.artifacts/directory;path.mkdir();(path/'evidence.json').write_text('{}')
        (self.artifacts/'future-evidence'/next(iter(self.expected))).write_bytes(b'WRONG COLLISION')
        self.dest=self.root/'dist'

    def verify(self,destination=None):
        destination=destination or self.dest
        self.assertEqual({p.name for p in destination.iterdir()},set(self.expected)|{'SHA256SUMS'})
        self.assertTrue(all(p.is_file() and not p.is_symlink() for p in destination.iterdir()))
        expected=''.join(hashlib.sha256(self.expected[name]).hexdigest()+'  '+name+'\n' for name in sorted(self.expected))
        self.assertEqual((destination/'SHA256SUMS').read_text(),expected)
        for name,data in self.expected.items():self.assertEqual((destination/name).read_bytes(),data)

    def workflow_body(self):
        text=(ROOT/'.github/workflows/release.yml').read_text();block=text.split('      - name: Collect and checksum\n',1)[1]
        before,body=block.split('        run: |\n',1)
        lines=[]
        for line in body.splitlines():
            if line and not line.startswith('          '):break
            lines.append(line[10:])
        return before,'\n'.join(lines)

    def shell(self,version='0.5.0'):
        scripts=self.root/'scripts';scripts.mkdir(exist_ok=True)
        for name in ('assemble-release-assets.py','check-release-version.py','check-release-output.py'):
            if (ROOT/'scripts'/name).exists():shutil.copyfile(ROOT/'scripts'/name,scripts/name)
        before,body=self.workflow_body()
        env=os.environ|dict(RELEASE_VERSION=version,HOME=str(self.root/'home'),XDG_CONFIG_HOME=str(self.root/'config'),XDG_CACHE_HOME=str(self.root/'cache'),HISTFILE='/dev/null')
        return subprocess.run(['bash','-e','-c',body],cwd=self.root,env=env,capture_output=True,timeout=10)


class PrereleaseProducts(unittest.TestCase):
    def test_rpm_prerelease_names_keep_archives_and_debian_versions(self):
        spec=importlib.util.spec_from_file_location('assembly',ROOT/'scripts/assemble-release-assets.py')
        assembly=importlib.util.module_from_spec(spec);spec.loader.exec_module(assembly)
        products=assembly.expected_products('0.6.0-rc1')
        self.assertIn('qsh-0.6.0-rc1-x86_64-unknown-linux-musl.tar.gz', products['linux-x86_64-unknown-linux-musl'])
        self.assertIn('qsh_0.6.0-rc1-1_amd64.deb', products['linux-x86_64-unknown-linux-musl'])
        self.assertIn('qsh-0.6.0-rc1-1.x86_64.rpm', products['linux-x86_64-unknown-linux-musl'])
        self.assertIn('qshd-0.6.0-rc1-1.aarch64.rpm', products['server-packages'])

    def test_every_product_name_survives_github_upload_unchanged(self):
        spec=importlib.util.spec_from_file_location('assembly',ROOT/'scripts/assemble-release-assets.py')
        assembly=importlib.util.module_from_spec(spec);spec.loader.exec_module(assembly)
        for version in ('0.6.0','0.6.0-rc.2','1.0.0-beta.10'):
            with self.subTest(version=version):
                names=[name for values in assembly.expected_products(version).values() for name in values]
                self.assertEqual(len(set(names)),12)
                self.assertTrue(all(assembly._output.github_safe_name(name) for name in names))
                self.assertFalse(any('~' in name for name in names))
        with self.assertRaisesRegex(assembly.AssemblyError,'renamed on upload'):
            assembly.expected_products('0.6.0+build.1')


class ClientAcceptanceWorkflowTests(unittest.TestCase):
    def test_actual_acceptance_block_selects_existing_stable_and_prerelease_products(self):
        workflow=(ROOT/'.github/workflows/release.yml').read_text()
        step=workflow.split('      - name: Exercise shipped Linux clients before upload\n',1)[1]
        block=step.split('        run: |\n',1)[1]
        lines=[]
        for line in block.splitlines():
            if line and not line.startswith('          '):break
            lines.append(line[10:])
        body='\n'.join(lines)
        for version in ['0.6.0','0.6.0-rc1']:
            for cpu,deb_arch in [('x86_64','amd64'),('aarch64','arm64')]:
                with self.subTest(version=version,cpu=cpu), tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);(root/'scripts').mkdir();(root/'packaging').mkdir();(root/'dist').mkdir()
                    for name in ('check-release-output.py','check-release-version.py'):
                        shutil.copyfile(ROOT/'scripts'/name,root/'scripts'/name)
                    target=cpu+'-unknown-linux-musl'
                    archive=f'dist/qsh-{version}-{target}.tar.gz'
                    deb=f'dist/qsh_{version}-1_{deb_arch}.deb'
                    rpm=f'dist/qsh-{version}-1.{cpu}.rpm'
                    for name in (archive,deb,rpm):(root/name).write_text('Synthetic selection fixture\n')
                    (root/'packaging/client-acceptance.py').write_text(
                        'import json,os,pathlib,sys\n'
                        'args=sys.argv[1:]\n'
                        'assert args[args.index("--version")+1]==os.environ["RELEASE_VERSION"]\n'
                        'assert args[args.index("--target")+1]==os.environ["NATIVE_TARGET"]\n'
                        'assert pathlib.Path(args[args.index("--archive")+1]).is_file()\n'
                        'if "--package" in args: assert pathlib.Path(args[args.index("--package")+1]).is_file()\n'
                        'with open("calls.jsonl","a") as output: output.write(json.dumps(args)+"\\n")\n')
                    env=dict(os.environ,RELEASE_VERSION=version,NATIVE_TARGET=target,
                             HOME=str(root/'home'),XDG_CONFIG_HOME=str(root/'config'),
                             XDG_CACHE_HOME=str(root/'cache'),HISTFILE='/dev/null',PYTHONDONTWRITEBYTECODE='1')
                    result=subprocess.run(['bash','-e','-c',body],cwd=root,env=env,capture_output=True,timeout=10)
                    self.assertEqual(result.returncode,0,result.stderr.decode())
                    calls=[json.loads(line) for line in (root/'calls.jsonl').read_text().splitlines()]
                    self.assertEqual(len(calls),3)
                    self.assertEqual([args[args.index('--package')+1] for args in calls if '--package' in args],[deb,rpm])
                    self.assertTrue(all(args[args.index('--archive')+1]==archive for args in calls))


class PackageStepTests(unittest.TestCase):
    """Run the workflow's actual Package body with fake generators and checks."""
    STUB=('import json,runpy,sys\n'
          'if sys.argv[1] in ("archive","package"):\n'
          '    open("checks.jsonl","a").write(json.dumps(sys.argv[1:])+"\\n");sys.exit(0)\n'
          'sys.argv[0]="scripts/real-check-release-output.py"\n'
          'runpy.run_path(sys.argv[0],run_name="__main__")\n')
    CARGO=('#!/usr/bin/env python3\n'
           'import os,pathlib,sys\n'
           'args=sys.argv[1:];target=args[args.index("--target")+1]\n'
           'kind="debian" if args[0]=="deb" else "generate-rpm"\n'
           'directory=pathlib.Path("target",target,kind);directory.mkdir(parents=True,exist_ok=True)\n'
           'for name in os.environ["FAKE_"+args[0].replace("-","_").upper()].split():\n'
           '    (directory/name).write_text("generated "+name)\n')

    def body(self):
        workflow=(ROOT/'.github/workflows/release.yml').read_text()
        block=workflow.split('      - name: Package\n',1)[1].split('        run: |\n',1)[1]
        lines=[]
        for line in block.splitlines():
            if line and not line.startswith('          '):break
            lines.append(line[10:])
        return '\n'.join(lines)

    def run_step(self,root,version,target,deb,rpm):
        for path in ('README.md','LICENSE','CHANGELOG.md','docs/licenses/openssl.txt',
                     'docs/licenses/aws-lc-rs.txt','docs/licenses/aws-lc.txt',
                     f'target/{target}/release/qsh',f'target/{target}/release/qshd'):
            (root/path).parent.mkdir(parents=True,exist_ok=True);(root/path).write_text('fixture')
        (root/'scripts').mkdir()
        for name in ('check-release-version.py','check-release-output.py'):
            shutil.copyfile(ROOT/'scripts'/name,root/'scripts'/name)
        (root/'scripts/check-release-output.py').rename(root/'scripts/real-check-release-output.py')
        (root/'scripts/check-release-output.py').write_text(self.STUB)
        (root/'bin').mkdir();(root/'bin/cargo').write_text(self.CARGO);(root/'bin/cargo').chmod(0o755)
        env=dict(os.environ,PATH=str(root/'bin')+os.pathsep+os.environ['PATH'],RELEASE_VERSION=version,
                 NATIVE_TARGET=target,FAKE_DEB=deb,FAKE_GENERATE_RPM=rpm,HOME=str(root/'home'),
                 XDG_CONFIG_HOME=str(root/'config'),XDG_CACHE_HOME=str(root/'cache'),
                 HISTFILE='/dev/null',PYTHONDONTWRITEBYTECODE='1')
        result=subprocess.run(['bash','-e','-c',self.body()],cwd=root,env=env,capture_output=True,timeout=20)
        checks=root/'checks.jsonl'
        calls=[json.loads(line) for line in checks.read_text().splitlines()] if checks.exists() else []
        return result,calls

    def test_generator_names_are_published_under_release_version_names(self):
        for version,deb,rpm in [('0.6.0-rc.2','0.6.0~rc.2-1','0.6.0~rc.2'),('0.6.0','0.6.0-1','0.6.0')]:
            for cpu,deb_arch in [('x86_64','amd64'),('aarch64','arm64')]:
                with self.subTest(version=version,cpu=cpu),tempfile.TemporaryDirectory() as directory:
                    root=Path(directory);target=cpu+'-unknown-linux-musl'
                    built_deb=f'qsh_{deb}_{deb_arch}.deb';built_rpm=f'qsh-{rpm}-1.{cpu}.rpm'
                    result,calls=self.run_step(root,version,target,built_deb,built_rpm)
                    self.assertEqual(result.returncode,0,result.stderr.decode())
                    published=[f'qsh_{version}-1_{deb_arch}.deb',f'qsh-{version}-1.{cpu}.rpm']
                    self.assertEqual(sorted(p.name for p in (root/'dist').iterdir()),
                                     sorted([f'qsh-{version}-{target}.tar.gz',*published]))
                    self.assertEqual((root/'dist'/published[0]).read_text(),'generated '+built_deb)
                    self.assertEqual((root/'dist'/published[1]).read_text(),'generated '+built_rpm)
                    packages=[call for call in calls if call[0]=='package']
                    self.assertEqual([call[-1] for call in packages],['dist/'+name for name in published])
                    self.assertTrue(all('--probe' in call and call[call.index('--version')+1]==version
                                        for call in packages))

    def test_an_unexpected_generator_output_count_fails_before_publication(self):
        for deb,rpm in [('qsh_0.6.0-1_amd64.deb qsh_0.5.0-1_amd64.deb','qsh-0.6.0-1.x86_64.rpm'),
                        ('qsh_0.6.0-1_amd64.deb','')]:
            with self.subTest(deb=deb,rpm=rpm),tempfile.TemporaryDirectory() as directory:
                root=Path(directory)
                result,calls=self.run_step(root,'0.6.0','x86_64-unknown-linux-musl',deb,rpm)
                self.assertNotEqual(result.returncode,0)
                self.assertIn(b'expected exactly one built',result.stderr)
                published=[call[-1] for call in calls if call[0]=='package']
                self.assertEqual(published,[] if ' ' in deb else ['dist/qsh_0.6.0-1_amd64.deb'])


class WorkflowTests(Layout):
    def test_actual_workflow_shell_excludes_real_shape_and_future_evidence(self):
        result=self.shell();self.assertEqual(result.returncode,0,result.stderr.decode());self.verify()
        before,body=self.workflow_body();self.assertIn('RELEASE_VERSION: ${{ needs.server-packages.outputs.version }}',before)
        self.assertIn('--version "$RELEASE_VERSION"',body)

    def test_actual_workflow_shell_propagates_invalid_version_and_missing_input(self):
        result=self.shell('not-a-version');self.assertNotEqual(result.returncode,0);self.assertFalse(self.dest.exists())
        (self.artifacts/'macos'/names()['macos'][0]).unlink()
        result=self.shell();self.assertNotEqual(result.returncode,0);self.assertFalse(self.dest.exists())


class AssemblerTests(Layout):
    def setUp(self):
        super().setUp()
        spec=importlib.util.spec_from_file_location('assembly',ROOT/'scripts/assemble-release-assets.py');self.module=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.module)

    def assemble(self):self.module.assemble(self.artifacts,'0.5.0',self.dest)

    def refuse(self):
        with self.assertRaises(self.module.AssemblyError):self.assemble()
        self.assertFalse(self.dest.exists());self.assertEqual(list(self.root.glob('.release-assets-*')),[])

    def test_exact_products_deterministic_manifest_and_ignored_evidence(self):
        self.assemble();self.verify()
        first=(self.dest/'SHA256SUMS').read_bytes();shutil.rmtree(self.dest)
        for producer,files in names().items():
            for name in reversed(files):
                path=self.artifacts/producer/name;data=path.read_bytes();path.unlink();path.write_bytes(data)
        self.assemble();self.verify();self.assertEqual((self.dest/'SHA256SUMS').read_bytes(),first)

    def test_each_missing_product_or_producer_refuses_before_output(self):
        for producer,files in names().items():
            for name in files:
                path=self.artifacts/producer/name;data=path.read_bytes();path.unlink()
                with self.subTest(product=name):self.refuse()
                path.write_bytes(data)
            path=self.artifacts/producer;hidden=self.root/'held';path.rename(hidden)
            with self.subTest(producer=producer):self.refuse()
            hidden.rename(path)

    def test_extra_nested_wrong_version_arch_and_duplicate_placement_refuse(self):
        producer=self.artifacts/'macos'
        for extra,directory in [('qsh-0.4.0-aarch64-apple-darwin.tar.gz',False),('qsh-0.5.0-wrong.tar.gz',False),('nested',True),(names()['server-packages'][0],False)]:
            path=producer/extra
            if directory:path.mkdir();(path/names()['macos'][0]).write_bytes(b'nested')
            else:path.write_bytes(b'extra')
            with self.subTest(extra=extra):self.refuse()
            if directory:shutil.rmtree(path)
            else:path.unlink()

    def test_symlink_root_producer_and_file_refuse_without_touching_targets(self):
        path=self.artifacts/'macos';hidden=self.root/'original';path.rename(hidden);path.symlink_to(hidden,target_is_directory=True);self.refuse();path.unlink();hidden.rename(path)
        leaf=path/names()['macos'][0];data=leaf.read_bytes();leaf.unlink();target=self.root/'target';target.write_bytes(data);leaf.symlink_to(target);self.refuse();self.assertEqual(target.read_bytes(),data)
        alias=self.root/'alias';alias.symlink_to(self.artifacts,target_is_directory=True)
        with self.assertRaises(self.module.AssemblyError):self.module.assemble(alias,'0.5.0',self.dest)

    @unittest.skipUnless(hasattr(os,'mkfifo'),'Unix FIFO fixture')
    def test_fifo_and_directory_input_refuse_without_blocking(self):
        path=self.artifacts/'macos'/names()['macos'][0];path.unlink();os.mkfifo(path)
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/assemble-release-assets.py'),'--artifacts',str(self.artifacts),'--version','0.5.0','--output',str(self.dest)],capture_output=True,timeout=2)
        self.assertNotEqual(result.returncode,0);self.assertFalse(self.dest.exists())
        path.unlink();path.mkdir();self.refuse()

    def test_preexisting_output_and_parent_alias_nesting_refuse_without_mutation(self):
        self.dest.mkdir();sentinel=self.dest/'keep';sentinel.write_bytes(b'preserve')
        with self.assertRaises(self.module.AssemblyError):self.assemble()
        self.assertEqual(sentinel.read_bytes(),b'preserve');shutil.rmtree(self.dest)
        for path in (self.artifacts/'dist',self.artifacts/'macos'/'dist',self.artifacts):
            with self.subTest(output=path),self.assertRaises(self.module.AssemblyError):self.module.assemble(self.artifacts,'0.5.0',path)
        alias=self.root/'input-alias';alias.symlink_to(self.artifacts,target_is_directory=True)
        with self.assertRaises(self.module.AssemblyError):self.module.assemble(self.artifacts,'0.5.0',alias/'dist')
        self.assertFalse((self.artifacts/'dist').exists())

    def test_copy_failure_cleans_only_private_staging_and_closes_fds(self):
        before=len(list(Path('/proc/self/fd').iterdir())) if Path('/proc/self/fd').exists() else None
        with mock.patch.object(self.module,'_copy_file',side_effect=OSError('PRIVATE')):self.refuse()
        if before is not None:self.assertEqual(len(list(Path('/proc/self/fd').iterdir())),before)
        for producer,files in names().items():
            for name in files:self.assertEqual((self.artifacts/producer/name).read_bytes(),self.expected[name])

    def test_opened_input_metadata_failure_closes_every_acquired_descriptor(self):
        original=self.module.os.fstat;descriptors=[]
        def fail(descriptor):
            info=original(descriptor);descriptors.append(descriptor)
            if stat.S_ISREG(info.st_mode):raise OSError('PRIVATE')
            return info
        with mock.patch.object(self.module.os,'fstat',side_effect=fail):self.refuse()
        self.assertGreaterEqual(len(descriptors),3)
        for descriptor in descriptors:
            with self.assertRaises(OSError):original(descriptor)

    def test_input_symlink_loop_and_cli_private_version_refuse_safely(self):
        loop=self.root/'loop';loop.symlink_to(loop)
        with self.assertRaises(self.module.AssemblyError):self.module.assemble(loop,'0.5.0',self.dest)
        result=subprocess.run([sys.executable,'-B',str(ROOT/'scripts/assemble-release-assets.py'),'--artifacts',str(self.artifacts),'--version','../PRIVATE','--output',str(self.dest)],capture_output=True,timeout=2)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stderr,b'release assembly: invalid release version\n');self.assertFalse(self.dest.exists())

    def test_input_close_failure_cannot_publish_a_completed_destination(self):
        original=self.module.os.close;failed=False
        def close(descriptor):
            nonlocal failed
            original(descriptor)
            if not failed:
                failed=True;raise OSError('PRIVATE close failure')
        with mock.patch.object(self.module.os,'close',side_effect=close):self.refuse()
        self.assertTrue(failed)

    def test_publish_is_complete_sibling_staging_and_rename_failure_cleans(self):
        original=self.module.os.rename;seen=[]
        def rename(source,dest):
            self.assertEqual(Path(source).parent,self.dest.parent);self.verify(Path(source));self.assertFalse(Path(dest).exists());seen.append(True);return original(source,dest)
        with mock.patch.object(self.module.os,'rename',side_effect=rename):self.assemble()
        self.assertEqual(seen,[True]);self.verify();shutil.rmtree(self.dest)
        with mock.patch.object(self.module.os,'rename',side_effect=OSError('PRIVATE')):self.refuse()

    def test_invalid_version_and_published_package_names(self):
        for version in ('','../PRIVATE','01.2.3','1.2.3-01','1.2.3-rc.1+build.7'):
            with self.subTest(version=version),self.assertRaises(self.module.AssemblyError):self.module.assemble(self.artifacts,version,self.dest)
            self.assertFalse(self.dest.exists())
        for version in ('1.2.3','1.2.3-rc.1','1.2.3-123','1.2.3-foo'):
            with self.subTest(version=version):self.assertEqual(self.module.expected_products(version),names(version))


if __name__=='__main__':unittest.main()
