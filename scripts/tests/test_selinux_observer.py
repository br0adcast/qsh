"""Managed-prestart composition contracts; no host native/policy operations."""
import base64
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[2]/'packaging/selinux'
sys.path.insert(0,str(ROOT))

class ProtocolTests(unittest.TestCase):
    def test_public_request_is_canonical_and_strict(self):
        import qshd_selinux_observer as m
        from qshd_selinux_activation import TrustedArtifact
        trust=TrustedArtifact('0.2.0','a'*64,'b'*64)
        pam=(ROOT.parent/'pam.d/qshd.fedora-selinux').read_bytes()
        encoded=m._request(trust,pam)
        self.assertLessEqual(len(encoded),8192)
        self.assertEqual(m._parse_request(encoded),(trust,pam))
        for bad in (encoded+'=',base64.b64encode(b'{"schema":1,"schema":1}').decode(),'x'*8193):
            with self.assertRaises(m.ObserverError):m._parse_request(bad)
        with self.assertRaises(m.ObserverError):m._request(trust,b'installed bytes')



    def test_response_binding_shape_and_custody_categories(self):
        import qshd_selinux_observer as m
        from types import SimpleNamespace as N
        from unittest.mock import patch
        trust=m.TrustedArtifact('0.2.0','a'*64,'b'*64)
        pam=(ROOT.parent/'pam.d/qshd.fedora-selinux').read_bytes()
        request=m._request(trust,pam);binding=m.ContextBinding('c'*64,'d'*64)
        response=m._response(request,binding)
        self.assertEqual(m._parse_response(response,request).contexts,binding)
        for bad in (response+response,response.rstrip(),b'{}',response.replace(b'"schema":1',b'"schema":true'),response.replace(b'"phase":',b'"unknown":')):
            with self.assertRaises(m.ObserverError):m._parse_response(bad,request)
        with self.assertRaises(m.ObserverError):m._parse_response(response,request+'changed')
        for code,expected in (('COMMAND_CUSTODY','CUSTODY'),('COMMAND_UNSETTLED','CUSTODY'),('PROCESS_THREADS','CALLER_PROCESS'),('COMMAND_TIMEOUT','DEADLINE')):
            with patch.object(m,'_Owner',side_effect=m._CommandError(code)),self.assertRaisesRegex(m.ObserverError,'^'+expected+'$'):
                m.observe_managed_prestart(trust,pam)
        owner=N(_last=N(settled=True,unreaped=()),_run=lambda *args,**kwargs:N(stdout=response,stderr=b'PRIVATE'))
        with patch.object(m,'_Owner',return_value=owner),self.assertRaisesRegex(m.ObserverError,'^OBSERVATION_REFUSED$'):
            m.observe_managed_prestart(trust,pam)

# Private sibling production-factory fixtures run through the real fixed child.
COMMON=r'''
from contextlib import contextmanager
import fcntl,json,os,time
from pathlib import Path
from types import SimpleNamespace as N
from qshd_selinux_activation import *
ROOT=Path(__file__).parent
CASE=(ROOT/'case').read_text()
TRUST=TrustedArtifact('0.2.0','a'*64,'b'*64)
ROUTING=b'{"/fixed":"owner"}'
def event(s):
 with (ROOT/'events').open('a') as f:f.write(s+'\n')
class Lease:
 def __init__(self,name):self.name=name;self.baseline=None
 def __enter__(self):
  event('enter-'+self.name)
  if CASE=='enter-'+self.name:raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
  if CASE=='setup' and self.name=='slot':time.sleep(30)
  if CASE=='lock' and self.name=='slot':
   self.fd=os.open(ROOT/'lock',os.O_RDWR);fcntl.flock(self.fd,fcntl.LOCK_EX)
  return self
 def __exit__(self,*exc):
  event('exit-'+self.name)
  if hasattr(self,'fd'):os.close(self.fd)
  if CASE=='exit-'+self.name:raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
 def inspection(self,*args):return self
 def routing(self):event('routing');return ROUTING
 def capture(self):
  event('capture-'+self.name)
  if CASE=='capture-'+self.name:raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
  if self.name=='slot':
   binding=ContextBinding('c'*64,'d'*64)
   rec=Activation(1,'PENDING' if CASE=='pending' else 'COMPLETE','a'*32,'fedora44-targeted-v1',1,1,TRUST,ModuleIdentity('qshd',400,'targeted','pp'),None if CASE=='pending' else Completion('normal-install-reload-v1','b'*64,binding))
   result=N(record=rec)
  elif self.name in ('registry','context'):result=N(registry_bytes=b'{}' if CASE=='drift' else ROUTING,registry_sha256='c'*64,receipts_sha256='d'*64)
  else:result=object()
  assert self.baseline is None;self.baseline=result;return result
 def recheck(self,baseline):
  event('recheck-'+self.name);assert baseline is self.baseline
  if CASE=='recheck-'+self.name:raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
@contextmanager
def window(api):
 event('enter-window')
 try:yield object()
 finally:event('exit-window')
 if CASE=='exit-window':raise RuntimeError('DO_NOT_EXPOSE_PRIVATE_DETAIL')
'''
HARNESS=r'''
import json,pathlib,resource,sys,time
root=pathlib.Path(sys.argv[1]);sys.path.insert(0,str(root))
resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_FSIZE,(16*1024**2,16*1024**2));resource.setrlimit(resource.RLIMIT_CPU,(10,10));resource.setrlimit(resource.RLIMIT_AS,(512*1024**2,512*1024**2))
import qshd_selinux_observer as m
from qshd_selinux_process import _children
trust=m.TrustedArtifact('0.2.0','a'*64,'b'*64)
if (root/'case').read_text() in ('setup','lock'):m._SECONDS=.25
started=time.monotonic()
try:
 result=m.observe_managed_prestart(trust,(root/'pam').read_bytes());value={'ok':True,'profile':result.profile}
except m.ObserverError as e:value={'ok':False,'error':str(e)}
assert _children()==[]
value['elapsed']=time.monotonic()-started
print(json.dumps(value))
'''

class ChildTests(unittest.TestCase):
    def run_child(self,case):
        import fcntl,os,shutil,subprocess,tempfile
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name in ('qshd_selinux_observer.py','qshd_selinux_activation.py','qshd_selinux_process.py'):
                shutil.copy2(ROOT/name,root/name)
            # Only this disposable copy substitutes UID admission; all filesystem/native factories below are private fixtures.
            path=root/'qshd_selinux_observer.py'
            path.write_text('import os\nos.geteuid=lambda:'+('1' if case=='rootgate' else '0')+'\n'+path.read_text())
            if case=='child-thread':
                path.write_text("import sys\nif len(sys.argv)>1 and sys.argv[1]=='_managed_prestart_v1':\n import threading,time\n threading.Thread(target=lambda:time.sleep(30),daemon=True).start()\n"+path.read_text())
            (root/'case').write_text(case);(root/'common.py').write_text(COMMON)
            (root/'pam').write_bytes((ROOT.parent/'pam.d/qshd.fedora-selinux').read_bytes())
            modules={
                'qshd_selinux_activation_state':'from common import *\ndef production():return Lease("slot")\n',
                'qshd_selinux_registry':'from common import *\ndef production():return Lease("registry")\n',
                'qshd_selinux_transaction':'from common import *\ndef production(paths):\n assert paths==["/fixed"]\n return Lease("context")\n',
                'qshd_selinux_module_observer':'from common import *\ndef production_observer(trust):\n assert trust==TRUST\n return Lease("module")\n',
                'qshd_selinux_files':'from common import *\ndef production(pam,api):\n assert type(pam)is bytes\n return Lease("files")\n',
                'qshd_selinux_queries':'from common import *\nrequired_observation=window\n',
                'qshd_selinux_api':'class SelinuxApi:pass\n'}
            for name,value in modules.items():(root/(name+'.py')).write_text(value)
            fd=os.open(root/'lock',os.O_RDWR|os.O_CREAT,0o600)
            try:
                if case=='lock':fcntl.flock(fd,fcntl.LOCK_EX)
                p=subprocess.run([sys.executable,'-I','-B','-c',HARNESS,str(root)],capture_output=True,text=True,timeout=15)
            finally:os.close(fd)
            self.assertEqual(p.returncode,0,p.stderr)
            self.assertNotIn('DO_NOT_EXPOSE',p.stdout+p.stderr)
            value=json.loads(p.stdout)
            events=(root/'events').read_text().splitlines() if (root/'events').exists() else []
            return value,events

    def test_child_root_gate_precedes_production_setup(self):
        for case in ('rootgate','child-thread'):
            with self.subTest(case=case):
                result,events=self.run_child(case)
                self.assertFalse(result['ok'])
                self.assertEqual(events,[])

    def test_real_child_all_scopes_before_success(self):
        result,events=self.run_child('normal')
        self.assertTrue(result['ok'])
        self.assertEqual(events[:6],['enter-slot','enter-registry','routing','enter-context','enter-module','enter-files'])
        start=events.index('enter-window');end=events.index('exit-window')
        for name in ('slot','registry','context','module','files'):
            self.assertLess(start,events.index('capture-'+name));self.assertLess(events.index('recheck-'+name),end)
        self.assertEqual(events[-6:],['exit-window','exit-files','exit-module','exit-context','exit-registry','exit-slot'])

    def test_real_child_pending_drift_and_every_finalizer_refuse(self):
        for case in ('pending','drift','enter-slot','enter-registry','enter-context','enter-module','enter-files','exit-window','exit-files','exit-module','exit-context','exit-registry','exit-slot','capture-module','recheck-files'):
            with self.subTest(case=case):
                result,_=self.run_child(case);self.assertFalse(result['ok'])

    def test_real_child_blocked_setup_and_actual_lock_are_deadline_bounded(self):
        for case in ('setup','lock'):
            with self.subTest(case=case):
                result,events=self.run_child(case)
                self.assertEqual(result['error'],'DEADLINE')
                self.assertLess(result['elapsed'],5)
                self.assertNotIn('capture-slot',events)
