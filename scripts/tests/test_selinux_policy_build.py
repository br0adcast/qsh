"""Validate the policy source/build boundary without accessing host SELinux."""
import importlib.util
from pathlib import Path
import os
import json
from unittest import mock
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BUILDER = ROOT / 'packaging/selinux/build.py'


class PolicyBuildTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(BUILDER.is_file(), 'maintained policy builder is missing')
        spec = importlib.util.spec_from_file_location('policy_build', BUILDER)
        self.build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.build)

    def test_qualified_rules_have_no_debug_or_permissive_switch(self):
        self.build.validate_sources(ROOT / 'packaging/selinux')
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in self.build.QUALIFIED:
                (directory / name).write_bytes((ROOT / 'packaging/selinux' / name).read_bytes())
            with (directory / 'qshd.te').open('a') as stream:
                stream.write('\npermissive qshd_t;\n')
            with self.assertRaisesRegex(ValueError, 'qualified'):
                self.build.validate_sources(directory)

    def test_source_changes_cannot_silently_add_privilege(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            for name in self.build.QUALIFIED:
                (directory / name).write_bytes((ROOT / 'packaging/selinux' / name).read_bytes())
            with (directory / 'qshd.te').open('a') as stream:
                stream.write('\nallow qshd_t self:capability sys_admin;\n')
            with self.assertRaisesRegex(ValueError, 'qualified'):
                self.build.validate_sources(directory)

    def test_pair_sources_preserve_rules_and_move_only_mappings(self):
        source=ROOT/'packaging/selinux'
        self.assertEqual(self.build.canonical((source/'qshd.fc').read_bytes()),b'\n')
        contexts=self.build.canonical((source/'qshd_contexts.fc').read_bytes())
        self.assertEqual(len(contexts.splitlines()),5)
        self.assertIn(b'policy_module(qshd, 0.3.0)',(source/'qshd.te').read_bytes())
        required=(source/'qshd_contexts.te').read_text()
        self.assertEqual(required.count('gen_require('),1)
        for name in ('qshd_exec_t','qshd_config_t','qshd_log_t','qshd_runtime_t'):
            self.assertIn('type '+name+';',required)
        self.assertNotRegex(required,r'(?m)^\s*(allow|type_transition|permissive|optional_policy)\b')
        self.assertEqual(self.build.canonical((source/'qshd_contexts.if').read_bytes()),b'\n')

    def test_workspace_version_is_read_without_release_bump(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / 'Cargo.toml'
            manifest.write_text('[workspace.package]\nversion = \"0.5.0\"\n[other]\nversion = \"9.9.9\"\n')
            self.assertEqual(self.build.workspace_version(manifest), '0.5.0')

    def test_paths_reject_stale_outputs_and_overlapping_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'
            source.mkdir()
            self.build.validate_paths(source, base / 'work', base / 'out')
            (base / 'out').mkdir()
            with self.assertRaisesRegex(ValueError, 'exist'):
                self.build.validate_paths(source, base / 'work', base / 'out')
            with self.assertRaisesRegex(ValueError, 'overlap'):
                self.build.validate_paths(source, source / 'work', base / 'other')

    @staticmethod
    def package(name,contexts,version=b'0.3.0',flags=1):
        text=b'SE Linux Module'
        module=struct.pack('<II',0xf97cff8d,len(text))+text+struct.pack('<5I',2,19,flags,8,0)
        module+=struct.pack('<I',len(name))+name+struct.pack('<I',len(version))+version
        return struct.pack('<5I',0xf97cff8f,1,2,20,20+len(module))+module+struct.pack('<I',0xf97cff90)+contexts

    def test_module_parser_rejects_wrong_format_name_version_and_contexts(self):
        for role,name,contexts in (('core',b'qshd',b'\n\t'),('contexts',b'qshd_contexts',self.build.expanded_contexts())):
            package=self.package(name,contexts)
            self.build.validate_package(package,role=role,expected_contexts=contexts)
            for bad in (b'bad',self.package(b'foreign',contexts),self.package(name,contexts,b'0.2.0'),
                        self.package(name,contexts,flags=0),package[:-1],package+b'# changed\n'):
                with self.subTest(role=role,bad=bad[:20]),self.assertRaises(ValueError):
                    self.build.validate_package(bad,role=role,expected_contexts=contexts)
            with self.assertRaises(ValueError):
                self.build.validate_package(package,role=role,expected_contexts=contexts+b'extra')
            other='core' if role=='contexts' else 'contexts'
            with self.assertRaises(ValueError):self.build.validate_package(package,role=other,expected_contexts=contexts)
        # Actual MCS builder comments/whitespace are explicit expected bytes, not
        # a global canonical comparison that silently accepts altered comments.
        empty=b'# Reviewed support output\n\n'
        self.build.validate_package(self.package(b'qshd',empty),role='core',expected_contexts=empty)
        with self.assertRaises(ValueError):
            self.build.validate_package(self.package(b'qshd',empty+b'# foreign\n'),role='core',expected_contexts=empty)
        contexts=self.build.expanded_contexts()
        with self.assertRaises(ValueError):
            self.build.validate_package(self.package(b'qshd',contexts),role='core',expected_contexts=contexts)
        for role in ('unknown',None,True):
            with self.assertRaises(ValueError):self.build.validate_package(b'',role=role,expected_contexts=b'')

    def test_companion_require_and_source_offer_are_closed(self):
        import shutil
        source=ROOT/'packaging/selinux'
        with tempfile.TemporaryDirectory() as tmp:
            copy=Path(tmp)
            for name in self.build.QUALIFIED:shutil.copyfile(source/name,copy/name)
            path=copy/'qshd_contexts.te';original=path.read_bytes()
            for changed in (original.replace(b'type qshd_exec_t;',b'type foreign_t;'),
                            original+b'\nallow qshd_t self:process signal;\n',
                            original.replace(b'gen_require(',b'optional_policy(')):
                path.write_bytes(changed)
                with self.assertRaises(ValueError):self.build.validate_sources(copy)
            path.write_bytes(original)
            for name in ('qshd_contexts.te','qshd_contexts.fc','qshd_contexts.if'):
                self.assertIn(name,self.build.BUNDLE_SOURCE_FILES)
            command=self.build.compile_command(Path('/reviewed/share'))
            self.assertEqual(command[-2:],['qshd.pp','qshd_contexts.pp'])


    def test_build_retains_expanded_fc_through_actual_make_cleanup(self):
        # Real GNU make discovers and deletes implicit intermediates. Only its
        # compiler recipes are harmless synthetic header/data emitters here.
        import argparse
        import hashlib
        import shutil
        import subprocess
        import sys
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);repo=root/'repo';source=repo/'packaging/selinux';source.mkdir(parents=True)
            for name, original in self.build.bundle_source_files(ROOT/'packaging/selinux').items():
                target=repo/name;target.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(original,target)
            (repo/'LICENSE').write_text('Synthetic orchestration fixture only\n')
            (repo/'Cargo.toml').write_text('[workspace.package]\nversion = "0.5.0"\n')
            inputs=root/'inputs';inputs.mkdir();rpm=inputs/'fixture.rpm';rpm.write_bytes(b'harmless fixture input')
            pins=dict(rpms={rpm.name:hashlib.sha256(rpm.read_bytes()).hexdigest()},
                      policy_devel=rpm.name,policy_source=rpm.name,installed_tools={})
            (source/'inputs.json').write_text(json.dumps(pins))
            emitter=root/'emit.py'
            emitter.write_text("""import pathlib,struct,sys
kind,name,output=sys.argv[1:]
if kind=='fc':
    data=b'# Reviewed fake compiler support comment\\n\\n' if name=='qshd' else """+repr(self.build.expanded_contexts())+"""
else:
    fc=pathlib.Path('tmp/'+name+'.mod.fc').read_bytes()
    signature=b'SE Linux Module';identity=name.encode()
    module=struct.pack('<II',0xf97cff8d,len(signature))+signature+struct.pack('<5I',2,19,1,8,0)
    module+=struct.pack('<I',len(identity))+identity+struct.pack('<I',5)+b'0.3.0'
    data=struct.pack('<5I',0xf97cff8f,1,2,20,20+len(module))+module+struct.pack('<I',0xf97cff90)+fc
pathlib.Path(output).write_bytes(data)
""")
            args=argparse.Namespace(work=root/'work',output=root/'output',inputs=inputs,keyring=root/'keyring',epoch=123,version='0.5.0')
            actual_make=[]
            def run(command,**kwargs):
                if command[0]=='rpmkeys':
                    return subprocess.CompletedProcess(command,0,stdout=b'fixture: signatures OK')
                if command[0]=='rpm2cpio':
                    kwargs['stdout'].write(b'harmless cpio fixture');return subprocess.CompletedProcess(command,0)
                if command[0]=='cpio':
                    share=Path(kwargs['cwd'])/'usr/share/selinux/devel';(share/'include').mkdir(parents=True)
                    (share/'include/Makefile').write_text('# Fixture presence marker\n')
                    # Same relevant implicit graph as the pinned devel rules:
                    # neither .SECONDARY nor .PRECIOUS suppresses deletion.
                    (share/'Makefile').write_text(
                        'tmp/%.mod: %.te\n\tmkdir -p tmp\n\tprintf harmless > $@\n'
                        'tmp/%.mod.fc: %.fc\n\tmkdir -p tmp\n\t/usr/bin/python3 -I -B '+str(emitter)+' fc $* $@\n'
                        '%.pp: tmp/%.mod tmp/%.mod.fc\n\t/usr/bin/python3 -I -B '+str(emitter)+' pp $* $@\n')
                    return subprocess.CompletedProcess(command,0)
                self.assertEqual(command[0],'/usr/bin/make')
                result=subprocess.run(command,**kwargs,check=True,capture_output=True)
                actual_make.append(result)
                return result
            with mock.patch.object(self.build,'HERE',source),mock.patch.object(self.build,'run',side_effect=run):
                self.build.build(args)
            self.assertEqual(len(actual_make),1)
            self.assertEqual(actual_make[0].returncode,0)
            self.assertIn(b'rm tmp/',actual_make[0].stdout)  # real intermediate cleanup occurred
            for name,role in (('qshd','core'),('qshd_contexts','contexts')):
                expanded=(args.work/'compile/tmp'/(name+'.mod.fc')).read_bytes()
                package=(args.output/(name+'.pp')).read_bytes()
                self.build.validate_package(package,role=role,expected_contexts=expanded)
            self.assertEqual((args.output/'qshd_contexts.fc').read_bytes(),self.build.expanded_contexts())
            self.assertTrue((args.output/'qshd-selinux-0.5.0-source.tar.gz').is_file())

    def test_compile_environment_ignores_ambient_make_and_loader_overrides(self):
        with mock.patch.dict(os.environ, {'M4': 'evil', 'M4PARAM': '-D evil',
                'AWK': 'evil', 'DIRECT_INITRC': 'y', 'MAKEFLAGS': '-e',
                'LD_PRELOAD': 'evil', 'PATH': '/evil'}, clear=True):
            env = self.build.compile_environment(Path('/work'), 123)
        self.assertEqual(env['PATH'], '/usr/bin:/usr/sbin:/bin:/sbin')
        self.assertEqual(env['SOURCE_DATE_EPOCH'], '123')
        self.assertFalse(set(env) & {'M4', 'M4PARAM', 'AWK', 'DIRECT_INITRC',
                                    'MAKEFLAGS', 'LD_PRELOAD'})
        command = self.build.compile_command(Path('/include'))
        self.assertEqual(command[0], '/usr/bin/make')
        self.assertIn('M4=/usr/bin/m4', command)
        self.assertIn('AWK=/usr/bin/gawk', command)
        self.assertIn('DIRECT_INITRC=n', command)
        self.assertNotIn('M4PARAM=', command)  # retain pinned Makefile's mcs flags

    def test_source_bundle_members_are_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp)
            for name in self.build.BUNDLE_SOURCE_FILES:
                path=source/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('source')
            (source / 'private-note.txt').write_text('must not ship')
            files = self.build.bundle_source_files(source)
            self.assertEqual(set(files), {'packaging/selinux/' + name
                                         for name in self.build.BUNDLE_SOURCE_FILES} | set(self.build.BUNDLE_REPOSITORY_FILES))
            self.assertNotIn('packaging/selinux/private-note.txt', files)

    def test_environment_recipe_is_obtainable_and_bundled(self):
        pins = json.loads((ROOT / 'packaging/selinux/inputs.json').read_text())
        self.assertRegex(pins['base_image'], r'^rockylinux/rockylinux:8@sha256:[0-9a-f]{64}$')
        self.assertIn('Dockerfile', self.build.BUNDLE_SOURCE_FILES)
        recipe = (ROOT / 'packaging/selinux/Dockerfile').read_text()
        self.assertIn(pins['base_image'], recipe)
        self.assertIn(pins['signing_key_sha256'], recipe)
        for name, version in pins['installed_tools'].items():
            self.assertIn(name + '-' + version, recipe)
        self.assertIn('--disablerepo=\'*\'', recipe)
        self.assertIn('timeout 600', recipe)
        self.assertIn('gpgcheck=1', recipe)
        # The pinned devel Makefile discovers interface layers with find.
        self.assertRegex(recipe, r'\bfindutils\b')

    def test_source_offer_contains_exact_helper_and_recipe_closure_as_bytes(self):
        import ast
        import tarfile
        source = ROOT / 'packaging/selinux'
        files = self.build.bundle_source_files(source)
        required = {'packaging/selinux/' + name for name in (
            'qshd_selinux_' + suffix + '.py' for suffix in (
                'activation', 'activation_state', 'contexts', 'transaction', 'fs', 'registry',
                'process', 'modules', 'module_observer', 'api', 'queries', 'files',
                'retained_labels', 'observer', 'reference_loader', 'package_state',
                'module_install', 'first_activation', 'consumer_activation', 'provider_erase',
                'phase', 'rpm_query', 'provider_pre'))}
        required.update({'packaging/selinux/' + name for name in (
            'stop_guard.py', 'assemble_payload.py', 'embed_provider_pre.py', 'embed_stop_guard.py',
            'qshd-selinux.spec', 'build-fedora-packages.sh', 'qshd-fedora-system.service')})
        required.update('packaging/selinux/maintainer/' + name for name in (
            'provider-pre', 'provider-post', 'provider-preun', 'provider-postun',
            'consumer-pre', 'consumer-post', 'consumer-preun', 'consumer-postun'))
        required.update(('scripts/generate-selinux-consumer-authority.py',
                         'scripts/check-selinux-consumer-rpm.py', 'cli/Cargo.toml',
                         'packaging/pam.d/qshd.fedora-selinux', 'LICENSE', 'Cargo.toml'))
        self.assertTrue(required <= set(files), sorted(required - set(files)))
        self.assertFalse(any('__pycache__' in name or name.endswith('.pyc') for name in files))
        # The floor builder must read modern helpers as bytes, never import them.
        ast.parse((source / 'build.py').read_text(), feature_version=(3, 6))
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / 'offer.tar.gz'
            self.build.source_bundle(archive, files, 123)
            with tarfile.open(archive) as stream:
                self.assertEqual(stream.getnames(), sorted(files))
                for member in stream:
                    self.assertTrue(member.isfile())
                    self.assertEqual((member.mode, member.uid, member.gid, member.mtime), (0o644, 0, 0, 123))
                    self.assertEqual(stream.extractfile(member).read(), files[member.name].read_bytes())

    def test_source_bundle_is_deterministic_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = base / 'source'
            source.mkdir()
            (source / 'notice').write_text('upstream notice\n')
            self.build.source_bundle(base / 'a.tar.gz', {'sources/notice': source / 'notice'}, 123)
            self.build.source_bundle(base / 'b.tar.gz', {'sources/notice': source / 'notice'}, 123)
            self.assertEqual((base / 'a.tar.gz').read_bytes(), (base / 'b.tar.gz').read_bytes())


if __name__ == '__main__':
    unittest.main()
