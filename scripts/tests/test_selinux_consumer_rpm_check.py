"""Synthetic selected-content controls; native route requires explicit --native.

Default discovery never invokes installed rpm/rpmbuild or executes a candidate.
"""
import importlib.util
import base64
import hashlib
import json
import os
import shutil
import signal
import io
from contextlib import redirect_stdout, redirect_stderr
import stat
import subprocess
import tempfile
import time
from unittest.mock import patch
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / 'scripts/check-selinux-consumer-rpm.py'


def checker():
    assert CHECKER.is_file(), 'selected-content checker implementation missing'
    spec = importlib.util.spec_from_file_location('qsh_test_consumer_rpm_checker', CHECKER)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def canonical(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')+b'\n'


def generated_fixture(root):
    spec=importlib.util.spec_from_file_location('qsh_fixture_generator',ROOT/'scripts/generate-selinux-consumer-authority.py')
    module=importlib.util.module_from_spec(spec)
    sys.modules[spec.name]=module
    spec.loader.exec_module(module)
    binary=root/'binary'
    binary.write_bytes(b'opaque non-executable final binary\x00\xff')
    pam=root/'pam'
    pam.write_bytes((ROOT/'packaging/pam.d/qshd.fedora-selinux').read_bytes())
    metadata=root/'metadata.json'
    metadata.write_bytes(canonical({'schema':1,'package':{'name':'qshd','epoch':0,'version':'0.5.0','release':'1','arch':'x86_64'},
        'files':[{'path':'/etc/pam.d/qshd','mode':0o100644,'owner':'root','group':'root','flags':17},
                 {'path':'/usr/bin/qshd','mode':0o100755,'owner':'root','group':'root','flags':0}]}))
    output=root/'generated'
    module.generate(binary,pam,metadata,output)
    manifest=output/'consumer-rpm.json'
    receipt=output/'generation-receipt.json'
    values=json.loads(manifest.read_bytes())
    rows=[dict(row) for row in values['files']]
    rows.append({'path':'/usr/share/qshd/consumer-rpm.json','size':len(manifest.read_bytes()),
                 'sha256':hashlib.sha256(manifest.read_bytes()).hexdigest(),'mode':0o100644,'owner':'root','group':'root','flags':0})
    blobs={'/usr/bin/qshd':binary.read_bytes(),'/etc/pam.d/qshd':pam.read_bytes(),
           '/usr/share/qshd/consumer-rpm.json':manifest.read_bytes()}
    return binary,pam,manifest,receipt,values,rows,blobs


def header(rows, package=None):
    package=package or {'name':'qshd','epoch':0,'version':'0.5.0','release':'1','arch':'x86_64'}
    quote=lambda value:json.dumps(value,ensure_ascii=True)
    result='P\t'+quote(package['name'])+'\t'+str(package['epoch'])+'\t'+quote(package['version'])+'\t'+quote(package['release'])+'\t'+quote(package['arch'])+'\nA\t8\n'
    for row in rows:
        result+='F\t'+quote(row['path'])+'\t'+str(row['size'])+'\t'+str(row['mode'])+'\t'+str(row['flags'])+'\t'+quote(row['owner'])+'\t'+quote(row['group'])+'\t'+quote(row['sha256'])+'\t'+quote(row.get('link',''))+'\n'
    return result.encode('ascii')+b'E\n'


def cpio_entry(name,data=b'',*,mode=0o100644,nlink=1,uid=123,gid=456):
    encoded=name.encode('utf-8')+b'\0'
    fields=(1,mode,uid,gid,nlink,0,len(data),0,0,0,0,len(encoded),0)
    prefix=b'070701'+b''.join(f'{value:08x}'.encode() for value in fields)
    return prefix+encoded+b'\0'*((-(110+len(encoded)))%4)+data+b'\0'*((-len(data))%4)


def payload(blobs):
    return b''.join(cpio_entry('.'+path,data) for path,data in blobs.items())+cpio_entry('TRAILER!!!',mode=0)+b'\0'*32


def tools(root,header_bytes,payload_bytes,*,query_tail='',decode_tail='',query_prefix='',decode_prefix='',chunk=65536):
    paths=[]
    for name,raw,prefix,tail in (('rpm',header_bytes,query_prefix,query_tail),('rpm2cpio',payload_bytes,decode_prefix,decode_tail)):
        data=root/(name+'.bytes')
        data.write_bytes(raw)
        script=root/name
        argv_check="""expected=['--rcfile','/dev/null','--macros','/dev/null','--noplugins','--nosignature','--query','--package','--nomanifest','--noglob','--queryformat']
assert sys.argv[1:-2]==expected
assert sys.argv[-1].startswith('/proc/self/fd/')
with open(sys.argv[-1],'rb') as source:assert source.read(64).startswith(b'synthetic RPM sentinel')
""" if name=='rpm' else "assert len(sys.argv)==1\nassert sys.stdin.buffer.read(64).startswith(b'synthetic RPM sentinel')\n"
        script.write_text('#!/usr/bin/python3\nimport os,sys,time,signal\n'+argv_check+prefix+'\n'+
            'with open('+repr(str(data))+",'rb') as source:\n while True:\n  block=source.read("+str(chunk)+")\n  if not block:break\n  while block:\n   block=block[os.write(1,block):]\n"+tail+'\n')
        script.chmod(0o755)
        paths.append(str(script))
    return tuple(paths)


def isolated_environment(root):
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE='1',HISTFILE='/dev/null')
    for key,name in (('HOME','home'),('XDG_CONFIG_HOME','config'),('XDG_CACHE_HOME','cache'),('TMPDIR','tmp')):
        path=root/name
        path.mkdir(mode=0o700,exist_ok=True)
        path.chmod(0o700)
        env[key]=str(path)
    return env


def source_worker(config, deadline):
    module=checker()
    module._resources()
    request=module._request(config['paths'])
    if 'cancel_signal' in config:
        assert config['cancel_signal'] in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT)
        os.kill(os.getppid(),config['cancel_signal'])
    try:
        result=module._worker(*config['paths'],deadline=deadline, request_sha256=request,
            **({'_tools':tuple(config['tools'])} if 'tools' in config else {}))
    except module.CheckError as error:
        category=str(error)
        assert category and len(category)<=64 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ_' for c in category)
        sys.stderr.write('CHECK_REFUSED '+category+'\n')
        return 1
    sys.stdout.buffer.write(result)
    return 0


def owned_source(config_path):
    config=json.loads(Path(config_path).read_bytes())
    module=checker()
    module._resources()
    from qshd_selinux_process import _Owner,_Limits,_CommandError
    seconds=config.get('owner_seconds',5)
    deadline=time.monotonic()+min(seconds,config.get('seconds',seconds))
    owner=_Owner(_Limits(seconds,4096))
    try:
        argv=tuple(config['argv']) if 'argv' in config else ('/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),config.get('worker','--_source-worker'),config_path,str(deadline))
        streams=owner._run(argv,str(Path(config_path).parent),deadline=deadline)
    except _CommandError:
        streams=None
    outcome=owner._last
    assert outcome is not None and outcome.settled and not outcome.unreaped
    print(json.dumps({'exit':outcome.exit_code,'failure':outcome.failure,'settled':outcome.settled,
        'unreaped':list(outcome.unreaped),'stdout':base64.b64encode(outcome.stdout).decode(),
        'stderr':base64.b64encode(outcome.stderr).decode()}))
    return 0


class SourceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix='qsh-rpm-check-source-')
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.binary,self.pam,self.manifest,self.receipt,self.value,self.rows,self.blobs=generated_fixture(self.root)
        self.rpm=self.root/'candidate.rpm'
        self.rpm.write_bytes(b'synthetic RPM sentinel, never an executable')

    def run_worker(self, raw_header=None, raw_payload=None, **options):
        self.assertTrue(CHECKER.is_file(),'selected-content checker implementation missing')
        seconds=options.pop('seconds',5)
        selected=tools(self.root,header(self.rows) if raw_header is None else raw_header,
                       payload(self.blobs) if raw_payload is None else raw_payload,**options)
        config=self.root/'source-config.json'
        config.write_bytes(canonical({'paths':[str(self.rpm),str(self.manifest),str(self.receipt)],'tools':selected,'seconds':seconds}))
        result=subprocess.run(['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--_owned-source',str(config)],
            cwd=self.root,env=isolated_environment(self.root),stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=20)
        self.assertEqual(result.returncode,0,result.stderr[-1000:])
        self.assertLessEqual(len(result.stdout),16384)
        outcome=json.loads(result.stdout)
        self.assertTrue(outcome['settled'])
        self.assertEqual(outcome['unreaped'],[])
        return outcome

    def assert_refused(self, **options):
        result=self.run_worker(**options)
        self.assertNotEqual(result['exit'],0,'worker returned a success before all required evidence')
        self.assertEqual(base64.b64decode(result['stdout']),b'')
        return result

    def test_selected_content_and_header_succeed_under_actual_owner(self):
        outcome=self.run_worker()
        self.assertEqual(outcome['exit'],0)
        self.assertIsNone(outcome['failure'])
        result=base64.b64decode(outcome['stdout'])
        value=json.loads(result)
        self.assertEqual(result,canonical(value))
        self.assertEqual(set(value),{'schema','result','request_sha256','rpm_sha256','manifest_sha256','receipt_sha256'})
        self.assertEqual(value['result'],'verified')
        self.assertEqual(value['rpm_sha256'],hashlib.sha256(self.rpm.read_bytes()).hexdigest())
        self.assertEqual(base64.b64decode(outcome['stderr']),b'')

    def test_exact_trailer_without_optional_padding_accepts_tiny_stream_chunks(self):
        stream=b''.join(cpio_entry('.'+path,data) for path,data in self.blobs.items())+cpio_entry('TRAILER!!!',mode=0)
        result=self.run_worker(raw_payload=stream,chunk=1)
        self.assertEqual(result['exit'],0,'exact trailer boundary must complete without extra padding')
        self.assertEqual(json.loads(base64.b64decode(result['stdout']))['result'],'verified')

    def test_receipt_boolean_epoch_is_not_integer_authority(self):
        value=json.loads(self.receipt.read_bytes())
        value['package']['epoch']=False
        self.receipt.write_bytes(canonical(value))
        self.assert_refused()

    def test_zero_padding_empty_regular_member_and_exact_trailer(self):
        rows=self.rows+[{'path':'/abcd','size':0,'sha256':hashlib.sha256(b'').hexdigest(),'mode':0o100644,'owner':'root','group':'root','flags':0}]
        stream=b''.join(cpio_entry('.'+path,data) for path,data in self.blobs.items())+cpio_entry('/abcd')+cpio_entry('TRAILER!!!',mode=0)
        result=self.run_worker(raw_header=header(rows),raw_payload=stream,chunk=1)
        self.assertEqual(result['exit'],0)

    def test_changed_selected_bytes_refuse_even_when_header_still_matches_authority(self):
        for path in self.blobs:
            changed=dict(self.blobs)
            changed[path]=bytes([changed[path][0]^1])+changed[path][1:]
            with self.subTest(path=path):self.assert_refused(raw_payload=payload(changed))

    def test_self_consistent_candidate_header_and_bytes_cannot_replace_reviewed_authority(self):
        changed=dict(self.blobs)
        changed['/usr/bin/qshd']=bytes([changed['/usr/bin/qshd'][0]^1])+changed['/usr/bin/qshd'][1:]
        rows=[dict(row) for row in self.rows]
        for row in rows:
            if row['path']=='/usr/bin/qshd':row['sha256']=hashlib.sha256(changed[row['path']]).hexdigest()
        self.assert_refused(raw_header=header(rows),raw_payload=payload(changed))

    def test_package_epoch_evr_arch_and_selected_header_metadata_refuse(self):
        for key,value in (('epoch',1),('version','0.5.1'),('release','2'),('arch','aarch64'),('name','foreign')):
            package=dict(self.value['package'],**{key:value})
            with self.subTest(key=key):self.assert_refused(raw_header=header(self.rows,package))
        for key,value in (('mode',0o100600),('owner','foreign'),('group','foreign'),('flags',0),('size',1),('sha256','b'*64),('link','elsewhere')):
            rows=[dict(row) for row in self.rows]
            rows[0][key]=value
            with self.subTest(key=key):self.assert_refused(raw_header=header(rows))
        rows=[dict(row) for row in self.rows]
        rows[-1]['flags']=17
        self.assert_refused(raw_header=header(rows))

    def test_header_grammar_duplicates_missing_and_malformed_tail_refuse(self):
        good=header(self.rows)
        cases=[good[:-1],good.replace(b'E\n',b''),good+good,good.replace(b'A\t8',b'A\t1'),
               header(self.rows+[self.rows[0]]),header(self.rows[:-1]),good.replace(b'E\n',b'F\t"truncated"\nE\n'),
               good.replace(b'"root"\t"root"',b'"root"',1),good.replace(b'F\t"/etc/pam.d/qshd"',b'F\t"/etc/../pam.d/qshd"')]
        for index,raw in enumerate(cases):
            with self.subTest(case=index):self.assert_refused(raw_header=raw)

    def test_emitted_inventory_duplicate_missing_alias_and_links_refuse(self):
        normal=[cpio_entry('.'+path,data) for path,data in self.blobs.items()]
        trailer=cpio_entry('TRAILER!!!',mode=0)
        cases=[b''.join(normal[:-1])+trailer,b''.join(normal)+normal[0]+trailer,
               b''.join(normal)+cpio_entry('/unmatched',b'unknown')+trailer,
               cpio_entry('./etc/../pam.d/qshd',self.blobs['/etc/pam.d/qshd'])+b''.join(normal)+trailer,
               cpio_entry('./usr/bin/qshd',self.blobs['/usr/bin/qshd'],nlink=2)+b''.join(normal[1:])+trailer,
               cpio_entry('./usr/bin/qshd',b'link',mode=0o120777)+b''.join(normal[1:])+trailer]
        for index,raw in enumerate(cases):
            with self.subTest(case=index):self.assert_refused(raw_payload=raw)

    def test_truncated_and_nonzero_tail_or_excess_padding_refuse(self):
        raw=payload(self.blobs)
        for cut in (1,109,110,len(raw)-40):
            with self.subTest(cut=cut):self.assert_refused(raw_payload=raw[:cut])
        self.assert_refused(raw_payload=raw+b'nonzero')
        self.assert_refused(raw_payload=raw+b'\0'*65537)
        self.assert_refused(raw_payload=raw.replace(b'070701',b'070702',1))

    def test_tools_must_exit_normally_before_verdict(self):
        for option in ({'query_tail':'raise SystemExit(1)'},{'decode_tail':'raise SystemExit(7)'},
                       {'decode_tail':'os.kill(os.getpid(),signal.SIGTERM)'},
                       {'decode_tail':'time.sleep(0.1)\nraise SystemExit(1)'}):
            with self.subTest(option=option):
                result=self.assert_refused(**option)
                self.assertEqual(result['exit'],1)
                self.assertIsNone(result['failure'])

    def test_stderr_pressure_and_header_output_caps_refuse(self):
        self.assert_refused(query_prefix='os.write(2,b"x"*65537)')
        self.assert_refused(decode_prefix='os.write(2,b"x"*65537)')
        self.assert_refused(raw_header=b'x'*(4*1024**2+1))

    def test_orphan_helper_with_closed_pipes_refuses_before_success(self):
        orphan="""child=os.fork()
if child==0:
 for fd in (0,1,2):
  try:os.close(fd)
  except OSError:pass
 time.sleep(3)
 os._exit(0)
"""
        result=self.assert_refused(decode_prefix=orphan)
        self.assertEqual(result['exit'],1)
        self.assertIsNone(result['failure'],'must refuse adopted helper rather than rely on outer timeout')

    def test_source_drift_and_original_worker_deadline_refuse(self):
        self.assert_refused(query_tail='with open('+repr(str(self.rpm))+',"ab") as target:target.write(b"changed")')
        self.rpm.write_bytes(b'synthetic RPM sentinel, never an executable')
        self.assert_refused(decode_prefix='time.sleep(0.25)',seconds=0.1)

    def test_receipt_and_manifest_unknown_duplicate_bool_or_hash_mismatch_refuse(self):
        original=self.receipt.read_bytes()
        for kind in ('hash','extra','duplicate','size-bool'):
            value=json.loads(original)
            if kind=='hash':value['manifest_sha256']='c'*64
            elif kind=='extra':value['extra']=1
            elif kind=='size-bool':value['files'][0]['size']=True
            raw=canonical(value)
            if kind=='duplicate':raw=raw.replace(b'"schema":1',b'"schema":1,"schema":1')
            self.receipt.write_bytes(raw)
            with self.subTest(kind=kind):self.assert_refused()
        self.receipt.write_bytes(original)
        self.manifest.write_bytes(self.manifest.read_bytes()+b'\n')
        self.assert_refused()

    def test_large_unselected_stream_is_consumed_without_payload_stdout(self):
        data=b'x'*(8*1024**2)
        blobs=dict(self.blobs)
        blobs['/unselected']=data
        rows=self.rows+[{'path':'/unselected','size':len(data),'sha256':hashlib.sha256(data).hexdigest(),
            'mode':0o100644,'owner':'root','group':'root','flags':0}]
        result=self.run_worker(raw_header=header(rows),raw_payload=payload(blobs),chunk=997)
        self.assertEqual(result['exit'],0)
        self.assertLess(len(base64.b64decode(result['stdout'])),4096)



    def test_public_parent_defers_cancellation_until_actual_worker_settlement(self):
        selected=tools(self.root,header(self.rows),payload(self.blobs))
        for number in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):
            with self.subTest(signal=number):
                config=self.root/'cancel-config.json'
                config.write_bytes(canonical({'paths':[str(self.rpm),str(self.manifest),str(self.receipt)],
                                              'tools':selected,'cancel_signal':number}))
                result=subprocess.run(['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),
                                       '--_cancel-parent',str(config)],cwd=self.root,
                                      env=isolated_environment(self.root),stdout=subprocess.PIPE,
                                      stderr=subprocess.PIPE,timeout=15)
                self.assertEqual(result.returncode,0,'public parent terminated before owned settlement')
                value=json.loads(result.stdout)
                self.assertEqual(value,{'code':1,'stdout':'','stderr':'CONSUMER_RPM_REFUSED\n',
                                        'child_exit':0,'settled':True,'unreaped':[],
                                        'failure':None,'handlers_restored':True})



def cancel_parent(config_path):
    module=checker()
    config=json.loads(Path(config_path).read_bytes())
    original=module._Owner
    observed=[]
    class BoundOwner(original):
        def _run(self, argv, cwd, *, deadline):
            result=super()._run(('/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),
                                '--_source-worker',config_path,str(deadline)),cwd,deadline=deadline)
            observed.append(self._last)
            return result
    numbers=(signal.SIGTERM,signal.SIGHUP,signal.SIGINT)
    before=[signal.getsignal(number) for number in numbers]
    stdout=io.TextIOWrapper(io.BytesIO(),encoding='utf-8')
    stderr=io.StringIO()
    args=[str(CHECKER),'--rpm',config['paths'][0],'--manifest',config['paths'][1],
          '--receipt',config['paths'][2]]
    with patch.object(module,'_Owner',BoundOwner),patch.object(sys,'argv',args),redirect_stdout(stdout),redirect_stderr(stderr):
        code=module.main()
    stdout.flush()
    assert len(observed)==1
    outcome=observed[0]
    print(json.dumps({'code':code,'stdout':stdout.buffer.getvalue().decode(),'stderr':stderr.getvalue(),
                      'child_exit':outcome.exit_code,'failure':outcome.failure,'settled':outcome.settled,
                      'unreaped':list(outcome.unreaped),
                      'handlers_restored':before==[signal.getsignal(number) for number in numbers]}))
    return 0

def builder_worker(config, deadline):
    """Authored fixture builder under the maintained owner, never a candidate run."""
    module=checker()
    module._resources()
    module._preconditions()
    module._subreaper()
    output=bytearray()
    def consume(block):
        output.extend(block)
        if len(output)>4096:
            raise module.CheckError('BUILD_OUTPUT')
    with open(config['spec'],'rb') as source:
        module._tool(('/usr/bin/rpmbuild','--quiet','--define','_topdir '+config['top'],
                      '--define','_buildhost fixture.invalid','--define','_binary_filedigest_algorithm 8',
                      '--define','_binary_payload w9.gzdio','--define','__os_install_post %{nil}',
                      '--define','debug_package %{nil}','--define','_tmppath '+config['top']+'/TMP','-bb',config['spec']),source.fileno(),
                     payload=False,consume=consume,deadline=deadline,clock=time.monotonic)
    if module._children() or time.monotonic()>=deadline:
        raise module.CheckError('BUILD_CUSTODY')
    sys.stdout.buffer.write(b'BUILT\n')
    return 0


class NativeTests(unittest.TestCase):
    """Required real-tool route: four builds and four checks, never skipped."""
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='qsh-rpm-check-native-')
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root=Path(cls.temp.name)
        cls.end=time.monotonic()+900
        for tool in ('rpm','rpm2cpio','rpmbuild'):
            path=Path('/usr/bin')/tool
            if not path.is_file() or not os.access(path,os.X_OK):
                raise AssertionError('required native tool unavailable: '+tool)
        cls.evidence={'schema':1,'os_release':Path('/etc/os-release').read_text(),
                      'python':sys.version,'environment':{'LANG':'C','LC_ALL':'C','HOME':'private temporary',
                      'XDG_CONFIG_HOME':'private temporary','XDG_CACHE_HOME':'private temporary'},'tools':{},'owners':[]}
        for name in ('rpm','rpm2cpio','rpmbuild'):
            path=Path('/usr/bin')/name
            cls.evidence['tools'][name]={'realpath':str(path.resolve()),
                                        'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        for name in ('rpm','rpmbuild'):
            outcome=cls.invoke({'argv':['/usr/bin/'+name,'--version']},'version-'+name)
            if outcome['exit']!=0 or base64.b64decode(outcome['stderr']):
                raise AssertionError('native version command refused: '+name)
            cls.evidence['tools'][name]['version']=base64.b64decode(outcome['stdout']).decode('ascii').strip()
        cls.fixture=cls.root/'authority'
        cls.fixture.mkdir(mode=0o700)
        cls.binary,cls.pam,cls.manifest,cls.receipt,_,_,_=generated_fixture(cls.fixture)

    @classmethod
    def tearDownClass(cls):
        # Fixed bounded diagnostics in the CI log; no workspace paths or raw RPM metadata.
        print('NATIVE_RPM_EVIDENCE '+json.dumps(cls.evidence,sort_keys=True,separators=(',',':')))

    @classmethod
    def invoke(cls, config, label):
        if cls.end-time.monotonic()<=100:
            raise AssertionError('native suite original budget exhausted')
        run=cls.root/label
        run.mkdir(mode=0o700)
        config=dict(config,owner_seconds=60)
        path=run/'config.json'
        path.write_bytes(canonical(config))
        result=subprocess.run(['/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),'--_owned-source',str(path)],
                              cwd=run,env=isolated_environment(run),stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,timeout=75)
        if result.returncode!=0 or len(result.stdout)>16384:
            raise AssertionError('native owned helper failed: '+label)
        outcome=json.loads(result.stdout)
        if not outcome['settled'] or outcome['unreaped'] or outcome['failure'] is not None:
            raise AssertionError('native custody failed: '+label)
        cls.evidence['owners'].append({'label':label,'exit':outcome['exit'],
                                       'settled':outcome['settled'],'unreaped':outcome['unreaped'],
                                       'stdout_sha256':hashlib.sha256(base64.b64decode(outcome['stdout'])).hexdigest()})
        if len(cls.evidence['owners'])>10:
            raise AssertionError('native owner count exceeded')
        return outcome

    def build(self, label, *, binary_change=False, version='0.5.0', manifest_change=False):
        top=self.root/('build-'+label)
        for directory in ('BUILD','BUILDROOT','RPMS','SOURCES','SPECS','SRPMS','TMP'):
            (top/directory).mkdir(parents=True,mode=0o700)
        blobs={'binary':self.binary.read_bytes(),'pam':self.pam.read_bytes(),'manifest':self.manifest.read_bytes()}
        if binary_change:
            blobs['binary']=bytes([blobs['binary'][0]^1])+blobs['binary'][1:]
        if manifest_change:
            blobs['manifest']=blobs['manifest'].replace(b'"schema":1',b'"schema":2')
        for name,data in blobs.items():
            (top/'SOURCES'/name).write_bytes(data)
        spec=top/'SPECS/fixture.spec'
        spec.write_text('Name: qshd\nEpoch: 0\nVersion: '+version+'\nRelease: 1\n'
            'Summary: Synthetic selected-content fixture\nLicense: MIT\nBuildArch: x86_64\nAutoReqProv: no\n'
            '%description\nOpaque non-executable regression fixture.\n%install\n'
            'mkdir -p "%{buildroot}/usr/bin" "%{buildroot}/etc/pam.d" "%{buildroot}/usr/share/qshd"\n'
            'cp "%{_sourcedir}/binary" "%{buildroot}/usr/bin/qshd"\n'
            'cp "%{_sourcedir}/pam" "%{buildroot}/etc/pam.d/qshd"\n'
            'cp "%{_sourcedir}/manifest" "%{buildroot}/usr/share/qshd/consumer-rpm.json"\n'
            '%files\n%defattr(-,root,root,-)\n%attr(0755,root,root) /usr/bin/qshd\n'
            '%config(noreplace) %attr(0644,root,root) /etc/pam.d/qshd\n'
            '%attr(0644,root,root) /usr/share/qshd/consumer-rpm.json\n')
        outcome=self.invoke({'worker':'--_builder-worker','spec':str(spec),'top':str(top)},'builder-'+label)
        self.assertEqual(outcome['exit'],0)
        self.assertEqual(base64.b64decode(outcome['stdout']),b'BUILT\n')
        self.assertEqual(base64.b64decode(outcome['stderr']),b'')
        rpms=list((top/'RPMS').glob('*/*.rpm'))
        self.assertEqual(len(rpms),1)
        self.assertLess(rpms[0].stat().st_size,16*1024**2)
        return rpms[0]

    def check(self, rpm, label, category=None):
        paths=[str(rpm),str(self.manifest),str(self.receipt)]
        if category is None:
            config={'argv':['/usr/bin/python3','-I','-B',str(CHECKER),'--rpm',paths[0],
                            '--manifest',paths[1],'--receipt',paths[2]]}
        else:
            config={'paths':paths}  # Actual fixed native tools: no private tool override.
        outcome=self.invoke(config,'checker-'+label)
        if category is None:
            self.assertEqual(outcome['exit'],0)
            module=checker()
            module._validate(base64.b64decode(outcome['stdout']),module._request(paths))
            self.assertEqual(base64.b64decode(outcome['stderr']),b'')
            print('NATIVE_RPM_PUBLIC_SUCCESS')
        else:
            self.assertEqual(outcome['exit'],1)
            self.assertEqual(base64.b64decode(outcome['stdout']),b'')
            self.assertEqual(base64.b64decode(outcome['stderr']),('CHECK_REFUSED '+category+'\n').encode())
            print('NATIVE_RPM_CAUSAL_REFUSAL '+category)

    def test_01_real_fixture_public_checker_success(self):
        self.check(self.build('baseline'),'baseline')

    def test_02_real_changed_binary_refuses_reviewed_header(self):
        self.check(self.build('binary',binary_change=True),'binary','SELECTED_HEADER')

    def test_03_real_evr_mismatch_refuses_package(self):
        self.check(self.build('evr',version='0.5.1'),'evr','PACKAGE')

    def test_04_real_embedded_manifest_mismatch_refuses_bytes(self):
        self.check(self.build('manifest',manifest_change=True),'manifest','SELECTED_HEADER')


NATIVE=False

def load_tests(loader, tests, pattern):
    suite=loader.loadTestsFromTestCase(NativeTests if NATIVE else SourceTests)
    expected=4 if NATIVE else 17
    declared=unittest.TestLoader().loadTestsFromTestCase(NativeTests if NATIVE else SourceTests).countTestCases()
    if declared!=expected or not 0<suite.countTestCases()<=expected:
        raise AssertionError('required RPM checker test count drift')
    return suite


if __name__=='__main__':
    if '--native' in sys.argv:
        sys.argv.remove('--native')
        NATIVE=True
    if len(sys.argv)==3 and sys.argv[1]=='--_cancel-parent':
        raise SystemExit(cancel_parent(sys.argv[2]))
    if len(sys.argv)==4 and sys.argv[1]=='--_builder-worker':
        raise SystemExit(builder_worker(json.loads(Path(sys.argv[2]).read_bytes()),float(sys.argv[3])))
    if len(sys.argv)==4 and sys.argv[1]=='--_source-worker':
        raise SystemExit(source_worker(json.loads(Path(sys.argv[2]).read_bytes()),float(sys.argv[3])))
    if len(sys.argv)==3 and sys.argv[1]=='--_owned-source':
        raise SystemExit(owned_source(sys.argv[2]))
    program=unittest.main(exit=False)
    expected=4 if NATIVE else 17
    raise SystemExit(0 if program.result.wasSuccessful() and program.result.testsRun==expected and not program.result.skipped else 1)
