"""Offline capsule binding controls, no host manager/policy execution."""
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import os
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'packaging/selinux'))
import qshd_selinux_activation as model
import embed_provider_pre as embed

class RenderTests(unittest.TestCase):
    def setUp(self):
        self.root=Path(__file__).resolve().parents[2]/'packaging/selinux'
        self.sources={name:(self.root/(name+'.py')).read_bytes() for name in embed.MODULES}
        self.artifact=(self.root/'artifact.json').read_bytes();self.pp=b'explicit synthetic PP, never loaded'
        self.contexts_pp=b'explicit synthetic CONTEXTS PP, never loaded'
        self.trusted=model.TrustedArtifact('0.3.0',hashlib.sha256(self.artifact).hexdigest(),hashlib.sha256(self.pp).hexdigest(),hashlib.sha256(self.contexts_pp).hexdigest())
    def render(self,sources=None):return embed.render(self.sources if sources is None else sources,self.trusted,artifact_bytes=self.artifact,core_pp_bytes=self.pp,contexts_pp_bytes=self.contexts_pp)
    def test_deterministic_bound_source_and_child_limit(self):
        a=self.render();self.assertEqual(a,self.render());compile(a,'capsule','exec')
        self.assertLessEqual(len(embed._child_source(self.sources,embed._request(self.trusted)).encode()),98304)
    def test_extra_missing_invalid_sources_refuse(self):
        for changed in ({},dict(self.sources,extra=b'x'),dict(self.sources,qshd_selinux_contexts=b'\0'),dict(self.sources,qshd_selinux_contexts=b'\xff')):
            with self.assertRaises(ValueError):self.render(changed)
    def test_wrong_authority_refuses(self):
        with self.assertRaises(ValueError):embed.render(self.sources,self.trusted,artifact_bytes=self.artifact+b' ',core_pp_bytes=self.pp,contexts_pp_bytes=self.contexts_pp)
        with self.assertRaises(ValueError):embed.render(self.sources,self.trusted,artifact_bytes=self.artifact,core_pp_bytes=self.pp+b'x',contexts_pp_bytes=self.contexts_pp)

    def test_distinct_paired_authority_inputs_are_independently_bound(self):
        request=json.loads(embed._request(self.trusted))
        self.assertEqual(request['schema'],2)
        self.assertEqual(set(request['artifact']),{'provider_version','manifest_sha256','core_pp_sha256','contexts_pp_sha256'})
        for core,contexts in ((self.pp+b'x',self.contexts_pp),(self.pp,self.contexts_pp+b'x'),(self.contexts_pp,self.pp)):
            with self.subTest(core=core,contexts=contexts),self.assertRaises(ValueError):
                embed.render(self.sources,self.trusted,artifact_bytes=self.artifact,core_pp_bytes=core,contexts_pp_bytes=contexts)

    def test_actual_owned_success_and_bad_frame(self):
        request=embed._request(self.trusted)
        frame=dict(schema=2,phase='provider-pre-fresh',request_sha256=hashlib.sha256(request).hexdigest(),operation_id='a'*32,state='PENDING')
        line=json.dumps(frame,sort_keys=True,separators=(',',':'))+'\n'
        for child,expected in (("print("+repr(line[:-1])+")",0),("print('bad')",1)):
            harness="import sys;sys.path.insert(0,"+repr(str(self.root))+");import qshd_selinux_provider_pre as p;p.os.geteuid=lambda:0;raise SystemExit(p.run_embedded_pre("+repr(child)+","+repr(request)+"))"
            result=subprocess.run([sys.executable,'-I','-B','-c',harness],capture_output=True,timeout=15)
            self.assertEqual(result.returncode,expected,result.stderr)
            if expected==0:self.assertEqual(result.stdout,line.encode())
            else:self.assertEqual(result.stdout,b'')


    def test_actual_isolated_capsule_without_installed_imports(self):
        sources=dict(self.sources)
        # Explicit test-only generated substitution: no manager/state action.
        sources['qshd_selinux_provider_pre']+=b"\nos.geteuid=lambda:0\ndef invalidate_fresh_provider_pre(trusted_artifact,*,deadline):\n    import sys,resource\n    assert [resource.getrlimit(k) for k in (resource.RLIMIT_CORE,resource.RLIMIT_FSIZE,resource.RLIMIT_AS,resource.RLIMIT_NOFILE,resource.RLIMIT_CPU)]==[(0,0),(16777216,16777216),(1073741824,1073741824),(128,128),(40,40)]\n    for name in ('qshd_selinux_contexts','qshd_selinux_fs','qshd_selinux_activation','qshd_selinux_activation_state','qshd_selinux_package_state','qshd_selinux_process','stop_guard','qshd_selinux_provider_pre'):\n        assert sys.modules[name].__file__=='<qshd-provider-pre:'+name+':'+dict((n,d) for n,d,e in sys.modules['__main__']._entries)[name]+'>'\n    return model.Activation(2,'PENDING','a'*32,'fedora44-targeted-pair-v2',2,1,trusted_artifact,model.ModulePair(model.ModuleIdentity('qshd',400,'targeted','pp'),model.ModuleIdentity('qshd_contexts',400,'targeted','pp')),'provider-fresh',None,None)\n"
        rendered=self.render(sources)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'qshd_selinux_activation.py').write_text("raise AssertionError('poisoned filesystem import')")
            capsule=root/'capsule.py';capsule.write_bytes(rendered)
            env=dict(os.environ,PYTHONPATH=directory,HOME=directory,XDG_CONFIG_HOME=directory,XDG_CACHE_HOME=directory,HISTFILE='/dev/null')
            result=subprocess.run([sys.executable,'-I','-B',str(capsule)],cwd=root,env=env,capture_output=True,timeout=15)
            self.assertEqual(result.returncode,0,result.stderr)
            value=json.loads(result.stdout);self.assertEqual(value['operation_id'],'a'*32)
            self.assertEqual(value['request_sha256'],hashlib.sha256(embed._request(self.trusted)).hexdigest())

    def test_import_only_loader_changes_no_resources_or_children(self):
        source="import resource,os,ctypes;ctypes.CDLL=lambda *a,**k:(_ for _ in ()).throw(AssertionError('import called native'));before=[resource.getrlimit(k) for k in (resource.RLIMIT_CORE,resource.RLIMIT_FSIZE,resource.RLIMIT_AS,resource.RLIMIT_CPU)];\n"+embed._loader(self.sources)+"\nassert before==[resource.getrlimit(k) for k in (resource.RLIMIT_CORE,resource.RLIMIT_FSIZE,resource.RLIMIT_AS,resource.RLIMIT_CPU)];assert not sys.modules['qshd_selinux_process']._children()"
        result=subprocess.run([sys.executable,'-I','-B','-c',source],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,0,result.stderr)


    def owned_control(self,child,*,short=False):
        request=embed._request(self.trusted)
        harness="import sys,time,os;sys.path.insert(0,"+repr(str(self.root))+");import qshd_selinux_provider_pre as p;p.os.geteuid=lambda:0;"
        if short:harness+="p._ENTRY_STARTED=time.monotonic()-29.6;"
        harness+="code=p.run_embedded_pre("+repr(child)+","+repr(request)+");from qshd_selinux_process import _children;assert not _children();"
        harness+="\ntry:os.waitpid(-1,os.WNOHANG)\nexcept ChildProcessError:pass\nelse:raise AssertionError('owned child not reaped')\nraise SystemExit(code)"
        return subprocess.run([sys.executable,'-I','-B','-c',harness],capture_output=True,timeout=15)

    def test_actual_owner_overflow_nonzero_stderr_and_invalid_frame(self):
        for source in ("print('x'*5000)","raise SystemExit(1)","import sys;sys.stderr.write('diagnostic')", "print('{}')", "print('{}\\n{}')"):
            with self.subTest(source=source):
                result=self.owned_control(source)
                self.assertEqual(result.returncode,1,result.stderr)
                self.assertEqual(result.stdout,b'');self.assertEqual(result.stderr,b'PROVIDER_PRE_REFUSED\n')

    def test_actual_timeout_and_pipe_retaining_descendant_settle(self):
        for source in ("import time;time.sleep(60)",
            "import os,time;pid=os.fork();\nif pid==0:os.setsid();time.sleep(60)\nelse:raise SystemExit(0)"):
            with self.subTest(source=source):
                result=self.owned_control(source,short=True)
                self.assertEqual(result.returncode,1,result.stderr)
                self.assertEqual(result.stderr,b'PROVIDER_PRE_REFUSED\n')

    def test_actual_parent_signal_settles_before_return(self):
        for signum in ('SIGTERM','SIGHUP','SIGINT'):
            result=self.owned_control("import os,signal,time;os.kill(os.getppid(),signal."+signum+");time.sleep(60)")
            self.assertEqual(result.returncode,1,result.stderr)
            self.assertEqual(result.stderr,b'PROVIDER_PRE_REFUSED\n')

    def test_actual_blocking_activation_lock_is_bounded(self):
        import fcntl
        with tempfile.TemporaryDirectory() as directory:
            lock=Path(directory)/'lock';fd=os.open(lock,os.O_RDWR|os.O_CREAT,0o600)
            try:
                fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
                source="import os,fcntl;fd=os.open("+repr(str(lock))+",os.O_RDONLY);fcntl.flock(fd,fcntl.LOCK_EX)"
                result=self.owned_control(source,short=True)
                self.assertEqual(result.returncode,1,result.stderr)
                # Test-owned exclusion remains; only the waiting child was killed.
                probe=os.open(lock,os.O_RDONLY)
                try:
                    with self.assertRaises(BlockingIOError):fcntl.flock(probe,fcntl.LOCK_EX|fcntl.LOCK_NB)
                finally:os.close(probe)
            finally:os.close(fd)


    def test_protocol_duplicate_noncanonical_wrong_binding_and_extra_refuse(self):
        request=embed._request(self.trusted)
        frame=dict(schema=2,phase='provider-pre-fresh',request_sha256=hashlib.sha256(request).hexdigest(),operation_id='a'*32,state='PENDING')
        canonical=json.dumps(frame,sort_keys=True,separators=(',',':'))
        wrong=dict(frame,request_sha256='b'*64)
        for line in (canonical.replace('"schema":2','"schema":2,"schema":2'),
                     json.dumps(frame),json.dumps(wrong,sort_keys=True,separators=(',',':')),
                     canonical+'\n'+canonical,canonical+' trailing'):
            with self.subTest(line=line):
                result=self.owned_control('print('+repr(line)+')')
                self.assertEqual(result.returncode,1,result.stderr)
                self.assertEqual(result.stdout,b'')

    def test_source_hash_tamper_refuses_before_exec(self):
        loader=embed._loader(self.sources)
        digest=hashlib.sha256(self.sources[embed.MODULES[0]]).hexdigest()
        changed=loader.replace(digest,'0'*64,1)
        result=subprocess.run([sys.executable,'-I','-B','-c',changed],capture_output=True,timeout=15)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'CAPSULE_SOURCE_HASH',result.stderr)

    def test_incompressible_encoded_child_oversize_refuses_no_fallback(self):
        import base64
        changed=dict(self.sources)
        changed['qshd_selinux_contexts']+=b'\n#'+base64.b85encode(os.urandom(80000))+b'\n'
        with self.assertRaisesRegex(ValueError,'CHILD_SIZE'):self.render(changed)


    def test_incompatible_inherited_hard_limit_refuses_before_child(self):
        request=embed._request(self.trusted)
        harness="import resource,sys;resource.setrlimit(resource.RLIMIT_FSIZE,(1024,1024));sys.path.insert(0,"+repr(str(self.root))+");import qshd_selinux_provider_pre as p;p.os.geteuid=lambda:0;raise SystemExit(p.run_embedded_pre("+repr("raise AssertionError('child launched')")+", "+repr(request)+"))"
        result=subprocess.run([sys.executable,'-I','-B','-c',harness],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,1);self.assertEqual(result.stderr,b'PROVIDER_PRE_REFUSED\n')

    def test_synthetic_unsettled_outcome_cannot_become_success(self):
        request=embed._request(self.trusted)
        frame=json.dumps(dict(schema=2,phase='provider-pre-fresh',request_sha256=hashlib.sha256(request).hexdigest(),operation_id='a'*32,state='PENDING'),sort_keys=True,separators=(',',':'))
        harness="import sys;from dataclasses import replace;sys.path.insert(0,"+repr(str(self.root))+");import qshd_selinux_provider_pre as p;p.os.geteuid=lambda:0\n"
        harness+="class RefuseOutcome(p._Owner):\n def _run(self,*args,**kwargs):\n  streams=super()._run(*args,**kwargs);self._last=replace(self._last,settled=False);return streams\n"
        harness+="p._Owner=RefuseOutcome;raise SystemExit(p.run_embedded_pre("+repr('print('+repr(frame)+')')+","+repr(request)+"))"
        result=subprocess.run([sys.executable,'-I','-B','-c',harness],capture_output=True,timeout=15)
        self.assertEqual(result.returncode,1,result.stderr);self.assertEqual(result.stdout,b'')

class NormalForwardingTests(unittest.TestCase):
    setUp=RenderTests.setUp
    def test_rescued_or_incomplete_outcomes_never_forward_valid_capsule_frame(self):
        request=embed._request(self.trusted)
        frame=json.dumps(dict(schema=2,phase='provider-pre-fresh',request_sha256=hashlib.sha256(request).hexdigest(),operation_id='a'*32,state='PENDING'),sort_keys=True,separators=(',',':'))
        for change in ({'natural':False},{'stdout_eof':False},{'stderr_eof':False},
                       {'group_term_attempts':1},{'adopted_term_attempts':1},{'kill_attempts':1}):
            harness="import sys;from dataclasses import replace;sys.path.insert(0,"+repr(str(self.root))+");import qshd_selinux_provider_pre as p;p.os.geteuid=lambda:0\n"
            harness+="class ChangedOutcome(p._Owner):\n def _run(self,*args,**kwargs):\n  streams=super()._run(*args,**kwargs);self._last=replace(self._last,**"+repr(change)+");return streams\n"
            harness+="p._Owner=ChangedOutcome;raise SystemExit(p.run_embedded_pre("+repr('print('+repr(frame)+')')+","+repr(request)+"))"
            with self.subTest(change=change):
                result=subprocess.run([sys.executable,'-I','-B','-c',harness],capture_output=True,timeout=15)
                self.assertEqual(result.returncode,1,result.stderr);self.assertEqual(result.stdout,b'')
                self.assertEqual(result.stderr,b'PROVIDER_PRE_REFUSED\n')


if __name__=='__main__':unittest.main()
