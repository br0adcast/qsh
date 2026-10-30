"""Offline staging checks; synthetic PP bytes are never loaded or qualified."""
import ast
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[2]
TOOL=ROOT/'packaging/selinux/assemble_payload.py'
NAMES=tuple('qshd_selinux_'+x+'.py' for x in ('activation','activation_state','contexts','transaction','fs','registry','process','modules','module_observer','api','queries','files','observer','reference_loader'))


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(TOOL.is_file(),'offline staging assembler missing')
        spec=importlib.util.spec_from_file_location('payload',TOOL)
        self.m=importlib.util.module_from_spec(spec);spec.loader.exec_module(self.m)
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.source=self.base/'source';self.source.mkdir()
        for name in NAMES:shutil.copy2(ROOT/'packaging/selinux'/name,self.source/name)
        self.pp=self.base/'qshd.pp';self.pp.write_bytes(b'PUBLIC SYNTHETIC PP FOR INTEGRITY ONLY\n')
        self.artifact=self.base/'artifact.json';shutil.copy2(ROOT/'packaging/selinux/artifact.json',self.artifact)
        self.pam=self.base/'qshd.fedora-selinux';shutil.copy2(ROOT/'packaging/pam.d/qshd.fedora-selinux',self.pam)
        self.expected={name:hashlib.sha256((self.source/name).read_bytes()).hexdigest() for name in NAMES}
        self.expected.update({p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (self.pp,self.artifact,self.pam)})
        self.output=self.base/'out'

    def assemble(self,output=None,expected=None,epoch=1000000000):
        return self.m.assemble_payload(self.source,self.pp,self.artifact,self.pam,self.expected if expected is None else expected,self.output if output is None else output,epoch)

    def tree(self,root):
        return {str(p.relative_to(root)):(p.read_bytes(),p.stat().st_mode&0o777,int(p.stat().st_mtime)) for p in root.rglob('*') if p.is_file()}

    def test_exact_deterministic_tree_references_and_input_preservation(self):
        (self.source/'AGENTS_LOCAL.md').write_text('PRIVATE DECOY DO NOT COPY')
        (self.source/'__pycache__').mkdir();(self.source/'__pycache__/cache.pyc').write_bytes(b'decoy')
        before={p:(p.read_bytes(),p.stat().st_mode) for p in self.source.iterdir() if p.is_file()}
        inventory=self.assemble();other=self.base/'second';self.assertEqual(inventory,self.assemble(other))
        tree=self.tree(self.output);self.assertEqual(tree,self.tree(other));self.assertEqual(len(tree),18)
        prefix='usr/libexec/qshd-selinux/'
        for name in NAMES:self.assertEqual(tree[prefix+name][0],(self.source/name).read_bytes())
        for path in (self.pp,self.artifact,self.pam):self.assertEqual(tree['usr/share/qshd-selinux/'+path.name][0],path.read_bytes())
        generated=tree['usr/share/qshd-selinux/reference.json'][0]
        constants=json.loads(generated)
        self.assertEqual(set(constants),{'provider_version','manifest_sha256','pp_sha256','pam_sha256','expected_pam'})
        self.assertEqual(constants['provider_version'],'0.2.0')
        self.assertEqual(constants['manifest_sha256'],self.expected['artifact.json'])
        self.assertEqual(constants['pp_sha256'],self.expected['qshd.pp'])
        self.assertEqual(constants['pam_sha256'],hashlib.sha256(self.pam.read_bytes()).hexdigest())
        self.assertEqual(constants['expected_pam'].encode('utf-8'),self.pam.read_bytes())
        self.assertNotIn(prefix+'qshd_selinux_reference.py',tree)
        self.assertEqual(generated,json.dumps(constants,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')+b'\n')
        self.assertTrue(all(mode==0o644 and epoch==1000000000 for _,mode,epoch in tree.values()))
        for path in [self.output,*[p for p in self.output.rglob('*') if p.is_dir()]]:
            self.assertEqual(path.stat().st_mode&0o777,0o755);self.assertEqual(int(path.stat().st_mtime),1000000000)
        for p,value in before.items():self.assertEqual((p.read_bytes(),p.stat().st_mode),value)
        self.assertNotIn(str(self.base).encode(),generated)
        self.assertNotIn('PRIVATE',str(inventory));self.assertNotIn('AGENTS_LOCAL',str(tree))

    def test_invalid_hash_unknown_keys_and_missing_input_refuse_before_output(self):
        for expected in (self.expected|{'unknown.py':'a'*64},self.expected|{'qshd.pp':'0'*64},{k:v for k,v in self.expected.items() if k!='artifact.json'}):
            with self.subTest(expected=sorted(expected)),self.assertRaises(ValueError):self.assemble(expected=expected)
            self.assertFalse(self.output.exists())
        (self.source/NAMES[0]).unlink()
        with self.assertRaises(ValueError):self.assemble()
        self.assertFalse(self.output.exists())

    def test_schema_imports_and_noncanonical_pam_refuse(self):
        raw=self.artifact.read_bytes();value=json.loads(raw);value['extra']='not maintained'
        self.artifact.write_text(json.dumps(value));self.expected['artifact.json']=hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):self.assemble()
        self.assertFalse(self.output.exists());self.artifact.write_bytes(raw);self.expected['artifact.json']=hashlib.sha256(raw).hexdigest()
        p=self.source/NAMES[0];original=p.read_bytes();p.write_bytes(original+b'\nimport qshd_selinux_unreviewed\n');self.expected[p.name]=hashlib.sha256(p.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):self.assemble()
        self.assertFalse(self.output.exists());p.write_bytes(original);self.expected[p.name]=hashlib.sha256(original).hexdigest()
        self.pam.write_bytes(b'CUSTOM');self.expected[self.pam.name]=hashlib.sha256(self.pam.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):self.assemble()
        self.assertFalse(self.output.exists())

    def test_output_existing_overlap_and_symlink_ancestor_into_input_refuse(self):
        self.output.mkdir()
        with self.assertRaises(ValueError):self.assemble()
        self.output.rmdir()
        with self.assertRaises(ValueError):self.assemble(self.source/'out')
        alias=self.base/'alias';alias.symlink_to(self.source,target_is_directory=True)
        with self.assertRaises(ValueError):self.assemble(alias/'out')
        self.assertFalse((self.source/'out').exists())
        self.output.symlink_to(self.base/'missing')
        with self.assertRaises(ValueError):self.assemble()
        self.assertTrue(self.output.is_symlink())

    def test_symlink_oversize_and_changed_read_refuse(self):
        path=self.source/NAMES[0];original=path.read_bytes();path.unlink();path.symlink_to(self.artifact)
        with self.assertRaises(ValueError):self.assemble()
        path.unlink();path.write_bytes(b'#'*(65536+1));self.expected[path.name]=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError):self.assemble()
        path.write_bytes(original);self.expected[path.name]=hashlib.sha256(original).hexdigest()
        read=self.m.os.read;changed=False
        def drift(fd,size):
            nonlocal changed
            result=read(fd,size)
            if not changed:path.write_bytes(original+b'\n');changed=True
            return result
        with mock.patch.object(self.m.os,'read',side_effect=drift),self.assertRaises(ValueError):self.assemble()
        self.assertFalse(self.output.exists())

    def test_restrictive_umask_and_cli_do_not_mutate_process_globals(self):
        expected=self.base/'expected.json';expected.write_text(json.dumps(self.expected))
        code="import os,runpy,sys;os.umask(0o077);sys.argv=sys.argv[1:];runpy.run_path(sys.argv[0],run_name='__main__')"
        p=subprocess.run([sys.executable,'-I','-B','-c',code,str(TOOL),'--source',str(self.source),'--pp',str(self.pp),'--artifact',str(self.artifact),'--pam',str(self.pam),'--expected',str(expected),'--output',str(self.output),'--epoch','1000000000'],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(len(json.loads(p.stdout)),18)
        self.assertTrue(all(v[1]==0o644 for v in self.tree(self.output).values()))
        self.assertTrue(all(p.stat().st_mode&0o777==0o755 for p in [self.output,*[p for p in self.output.rglob('*') if p.is_dir()]]))

    def test_bad_epoch_and_duplicate_expected_json_refuse_without_output(self):
        for epoch in (-1,True,2147483648):
            with self.subTest(epoch=epoch),self.assertRaises(ValueError):self.assemble(epoch=epoch)
            self.assertFalse(self.output.exists())
        expected=self.base/'expected.json';expected.write_text('{"qshd.pp":"'+('a'*64)+'","qshd.pp":"'+('b'*64)+'"}')
        p=subprocess.run([sys.executable,'-I','-B',str(TOOL),'--source',str(self.source),'--pp',str(self.pp),'--artifact',str(self.artifact),'--pam',str(self.pam),'--expected',str(expected),'--output',str(self.output),'--epoch','1000000000'],capture_output=True,text=True,timeout=10)
        self.assertEqual(p.returncode,1);self.assertEqual(p.stdout,'')
        self.assertEqual(p.stderr,'PAYLOAD_ASSEMBLY_REFUSED\n');self.assertFalse(self.output.exists())

    def test_late_write_failure_preserves_partial_and_never_adopts_it(self):
        original=self.m._write_file;count=0
        def fail(path,data,epoch):
            nonlocal count
            original(path,data,epoch);count+=1
            if count==2:raise OSError('synthetic write failure')
        with mock.patch.object(self.m,'_write_file',side_effect=fail),self.assertRaises(ValueError):self.assemble()
        self.assertTrue(self.output.is_dir());self.assertTrue(any(self.output.rglob('*.py')))
        with self.assertRaises(ValueError):self.assemble()


if __name__=='__main__':unittest.main()
