"""Inert fixed-layout archives; no product or native process is executed."""
import hashlib
import gzip
import copy
import stat
from unittest.mock import patch
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[2]
SCRIPT=ROOT/'scripts/darwin-artifact-smoke.py'
TARGET='aarch64-apple-darwin'
VERSION='0.6.0'


def digest(data):return hashlib.sha256(data).hexdigest()


def metadata(programs):
    version=dict(kind='LC_BUILD_VERSION',platform='macos',minos='14.0',sdk='15.0')
    records=[dict(role=role,program=program,sha256=digest(data),arch='arm64',version_command=version)
             for program,data in programs.items() for role in ('staged','extracted')]
    records.append(dict(role='native-probe',program='version-probe',sha256='c'*64,arch='arm64',version_command=version))
    return dict(schema=1,target=TARGET,source=dict(sha='a'*40,run_id='1',run_attempt='1'),
                host=dict(arch='arm64',macos_version='15.0',macos_build='24A1',image_version=None),
                sdk=dict(version='15.0',xcode_version='16.0',xcode_build='16A1'),
                rust={'release':'1.93.0','commit-hash':'b'*40,'host':TARGET,
                      'reported_deployment_target':'14.0','explicit_deployment_target':None},
                native=dict(version='3.6.0',manifest_sha256='d'*64,compiler_sha256='e'*64,
                            compiler_version='17.0.0',flags=['-arch','arm64','-isysroot','<SDK>'],macros={'__APPLE__':'1'}),
                binaries=records)


class PrepareTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.root.chmod(0o700)
        self.programs={'qsh':b'inert client bytes','qshd':b'inert daemon bytes'}
        self.stage='qsh-'+VERSION+'-'+TARGET
        self.archive=self.root/(self.stage+'.tar.gz')
        self.meta=self.root/'metadata.json'
        self.meta.write_text(json.dumps(metadata(self.programs),sort_keys=True,separators=(',',':'))+'\n')
        self.destination=self.root/'staged'

    def adapter(self):
        self.assertTrue(SCRIPT.is_file(),'pure Darwin archive adapter is missing')
        spec=importlib.util.spec_from_file_location('darwin_smoke',SCRIPT)
        value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value)
        return value

    def archive_bytes(self,extra=None,omit=None):
        buffer=io.BytesIO()
        with tarfile.open(fileobj=buffer,mode='w:gz',format=tarfile.USTAR_FORMAT) as archive:
            root=tarfile.TarInfo(self.stage);root.type=tarfile.DIRTYPE;root.mode=0o755;archive.addfile(root)
            entries=dict(self.programs)
            entries.update({'README.md':b'inert readme','LICENSE':b'inert license',
                            'CHANGELOG.md':b'inert changes'})
            for name,source in self.adapter().NOTICES.items():
                entries[name]=(ROOT/'docs/licenses'/source).read_bytes()
            for name,data in entries.items():
                if name==omit:continue
                info=tarfile.TarInfo(self.stage+'/'+name);info.size=len(data);info.mode=0o755 if name in self.programs else 0o644
                archive.addfile(info,io.BytesIO(data))
            if extra is not None:
                info,data=extra;archive.addfile(info,io.BytesIO(data))
        return buffer.getvalue()

    def test_valid_inert_archive_stages_only_two_private_executables_without_processes(self):
        import subprocess
        adapter=self.adapter();raw=self.archive_bytes();self.archive.write_bytes(raw)
        with patch.object(subprocess,'Popen',side_effect=AssertionError('no subprocess')):
            receipt=adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertEqual(set(p.name for p in self.destination.iterdir()),{'qsh','qshd'})
        for name,data in self.programs.items():
            self.assertEqual((self.destination/name).read_bytes(),data)
            self.assertEqual((self.destination/name).stat().st_mode&0o777,0o700)
            self.assertEqual(receipt['binaries'][name],dict(sha256=digest(data),bytes=len(data)))
        self.assertEqual(self.destination.stat().st_mode&0o777,0o700)
        self.assertEqual(receipt['archive_sha256'],digest(raw))
        self.assertEqual(receipt['metadata_sha256'],digest(self.meta.read_bytes()))
        self.assertEqual(adapter._prepared(adapter.canonical(receipt)),receipt)
        self.assertNotIn(str(self.root).encode(),adapter.canonical(receipt))
        second=adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.root/'second',source_commit='a'*40)
        self.assertNotEqual(receipt['request_id'],second['request_id'])
        self.assertNotEqual(receipt['challenge'],second['challenge'])

    def test_exact_member_set_rejects_duplicate_missing_unknown_alias_and_special_types(self):
        adapter=self.adapter()
        for kind in ('duplicate','missing','unknown','absolute','dot','link','symlink','device','fifo','pax','global-pax','gnu-long','sparse'):
            extra=tarfile.TarInfo(self.stage+'/unknown');extra.size=0
            if kind=='duplicate':extra.name=self.stage+'/qsh'
            elif kind=='absolute':extra.name='/'+self.stage+'/unknown'
            elif kind=='dot':extra.name=self.stage+'/./qsh'
            elif kind=='link':extra.type=tarfile.LNKTYPE;extra.linkname=self.stage+'/qsh'
            elif kind=='symlink':extra.type=tarfile.SYMTYPE;extra.linkname='qsh'
            elif kind=='device':extra.type=tarfile.CHRTYPE
            elif kind=='fifo':extra.type=tarfile.FIFOTYPE
            elif kind=='pax':extra.type=tarfile.XHDTYPE
            elif kind=='global-pax':extra.type=tarfile.XGLTYPE
            elif kind=='gnu-long':extra.type=tarfile.GNUTYPE_LONGNAME
            elif kind=='sparse':extra.type=tarfile.GNUTYPE_SPARSE
            raw=self.archive_bytes(omit='LICENSE') if kind=='missing' else self.archive_bytes((extra,b''))
            self.archive.write_bytes(raw)
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
            self.assertFalse(self.destination.exists())

    def test_pinned_notice_hashes_equal_maintained_source(self):
        adapter=self.adapter()
        self.assertEqual(set(adapter.NOTICE_SHA256),set(adapter.NOTICES))
        for filename,source in adapter.NOTICES.items():
            self.assertEqual(adapter.NOTICE_SHA256[filename],digest((ROOT/'docs/licenses'/source).read_bytes()))

    def test_each_required_client_notice_is_present_and_exact(self):
        adapter=self.adapter()
        for filename in ('LICENSE-AWS-LC-RS.txt','LICENSE-AWS-LC.txt'):
            self.archive.write_bytes(self.archive_bytes(omit=filename))
            with self.subTest(filename=filename,kind='missing'),self.assertRaisesRegex(ValueError,'^TAR_MEMBERS$'):
                adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
            raw=gzip.decompress(self.archive_bytes())
            source=(ROOT/'docs/licenses'/adapter.NOTICES[filename]).read_bytes()
            self.assertIn(source,raw)
            self.archive.write_bytes(gzip.compress(raw.replace(source,b'x'+source[1:],1)))
            with self.subTest(filename=filename,kind='altered'),self.assertRaisesRegex(ValueError,'^NOTICE_BYTES$'):
                adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
            self.assertFalse(self.destination.exists())

    def test_header_bounds_checksum_truncation_end_blocks_and_gzip_trailer(self):
        adapter=self.adapter();raw=gzip.decompress(self.archive_bytes())
        end=512+sum(512+((len(data)+511)//512)*512 for data in list(self.programs.values())+
                    [b'inert readme',b'inert license',b'inert changes']+
                    [(ROOT/'docs/licenses'/source).read_bytes() for source in self.adapter().NOTICES.values()])
        changed=bytearray(raw);changed[0]^=1
        variants=[gzip.compress(raw[:111]),gzip.compress(bytes(changed)),gzip.compress(raw[:end+512]),
                  gzip.compress(raw[:end]+bytes(1024)+b'x'),gzip.compress(raw[:end]+bytes(1024+65537)),
                  self.archive_bytes()[:-4]]
        for archive in variants:
            self.archive.write_bytes(archive)
            with self.subTest(bytes=len(archive)),self.assertRaises(ValueError):
                adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
            self.assertFalse(self.destination.exists())
        # Exactly bounded zero tail remains supported and fully consumed.
        self.archive.write_bytes(gzip.compress(raw[:end]+bytes(1024+65536)))
        adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)

    def test_caps_and_extension_declarations_refuse_before_large_body(self):
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes())
        for name,value in (('ARCHIVE_LIMIT',len(self.archive.read_bytes())-1),('EXPANDED_LIMIT',1024),
                           ('EXECUTABLE_LIMIT',1),('DOCUMENT_LIMIT',1)):
            with self.subTest(cap=name),patch.object(adapter,name,value),self.assertRaises(ValueError):
                adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
            self.assertFalse(self.destination.exists())
        header=tarfile.TarInfo(self.stage+'/extension');header.type=tarfile.XHDTYPE;header.size=1024**3
        self.archive.write_bytes(gzip.compress(header.tobuf(format=tarfile.USTAR_FORMAT)))
        with self.assertRaisesRegex(ValueError,'^TAR_UNSUPPORTED$'):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertFalse(self.destination.exists())

    def test_invalid_octal_base256_and_format_headers_refuse(self):
        adapter=self.adapter();raw=gzip.decompress(self.archive_bytes())
        for start,stop,value in ((108,116,b'-1'+bytes(6)),(124,136,b'\x80'+bytes(11)),
                                 (108,116,b'8'+bytes(7)),(257,265,b'not-ustar')):
            changed=bytearray(raw);changed[start:stop]=value
            changed[148:156]=b' '*8
            changed[148:156]=('%06o'%sum(changed[:512])).encode()+b'\0 '
            self.archive.write_bytes(gzip.compress(changed))
            with self.subTest(field=start),self.assertRaises(ValueError):
                adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
            self.assertFalse(self.destination.exists())

    def test_existing_destination_and_symlink_inputs_are_not_overwritten(self):
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes())
        self.destination.mkdir(mode=0o700);sentinel=self.destination/'user-file';sentinel.write_bytes(b'preserve')
        with self.assertRaises(ValueError):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertEqual(sentinel.read_bytes(),b'preserve')
        sentinel.unlink();self.destination.rmdir()
        for path in (self.archive,self.meta):
            held=path.with_name(path.name+'.held');path.rename(held);path.symlink_to(held.name)
            try:
                with self.subTest(input=path.name),self.assertRaises(ValueError):
                    adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
                self.assertFalse(self.destination.exists())
            finally:path.unlink();held.rename(path)
        self.destination.symlink_to('absent')
        with self.assertRaises(ValueError):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertTrue(self.destination.is_symlink())

    def test_wrong_selection_source_metadata_and_payload_hash_refuse(self):
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes())
        for version,target,source in (('0.6','aarch64-apple-darwin','a'*40),
                                      (VERSION,'x86_64-apple-darwin','a'*40),
                                      (VERSION,TARGET,'b'*40)):
            with self.subTest(version=version,target=target),self.assertRaises(ValueError):
                adapter.prepare(self.archive,self.meta,version,target,self.destination,source_commit=source)
            self.assertFalse(self.destination.exists())
        value=json.loads(self.meta.read_bytes())
        for record in value['binaries']:
            if record['program']=='qsh':record['sha256']='f'*64
        self.meta.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError,'^PAYLOAD_DIGEST$'):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertFalse(self.destination.exists())

    def test_source_mutation_and_same_bytes_name_swap_refuse_and_clean(self):
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes());write=adapter._write_all
        for kind in ('mtime','swap'):
            fired=[]
            def mutate(fd,data):
                write(fd,data)
                if not fired:
                    fired.append(True)
                    if kind=='mtime':
                        info=self.archive.stat();os.utime(self.archive,ns=(info.st_atime_ns,info.st_mtime_ns+1))
                    else:
                        raw=self.archive.read_bytes();self.archive.rename(self.root/'held-archive')
                        self.archive.write_bytes(raw)
            with self.subTest(kind=kind),patch.object(adapter,'_write_all',side_effect=mutate),self.assertRaises(ValueError):
                adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
            self.assertTrue(fired);self.assertFalse(self.destination.exists())

    def test_partial_write_and_close_failure_remove_only_owned_files(self):
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes());write=adapter._write_all
        before=len(os.listdir('/proc/self/fd'));calls=[]
        def refuse_second(fd,data):
            calls.append(True)
            if len(calls)==2:raise OSError('synthetic write failure')
            write(fd,data)
        with patch.object(adapter,'_write_all',side_effect=refuse_second),self.assertRaises(ValueError):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertFalse(self.destination.exists());self.assertEqual(len(os.listdir('/proc/self/fd')),before)
        close=adapter.os.close;failed=[]
        def close_after_real_close(fd):
            info=os.fstat(fd);close(fd)
            if not failed and stat.S_ISREG(info.st_mode) and info.st_mode&0o777==0o700:
                failed.append(True);raise OSError('synthetic close acknowledgement failure')
        with patch.object(adapter.os,'close',side_effect=close_after_real_close),self.assertRaises(ValueError):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertTrue(failed);self.assertFalse(self.destination.exists())
        self.assertEqual(len(os.listdir('/proc/self/fd')),before)

    def test_stage_close_acknowledgement_failure_cleans_known_outputs(self):
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes());close=adapter.os.close;failed=[]
        def refuse_stage_close(fd):
            held=os.fstat(fd)
            selected=self.destination.exists() and (held.st_dev,held.st_ino)==(self.destination.stat().st_dev,self.destination.stat().st_ino)
            close(fd)
            if selected and not failed:
                failed.append(True);raise OSError('synthetic stage close acknowledgement')
        with patch.object(adapter.os,'close',side_effect=refuse_stage_close),self.assertRaises((ValueError,OSError)):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertTrue(failed);self.assertFalse(self.destination.exists())

    def test_staging_swap_never_removes_foreign_tree(self):
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes());write=adapter._write_all;fired=[]
        moved=self.root/'moved-private-stage'
        def swap(fd,data):
            write(fd,data)
            if not fired:
                fired.append(True);self.destination.rename(moved);self.destination.mkdir(mode=0o700)
                (self.destination/'foreign').write_bytes(b'preserve foreign')
        with patch.object(adapter,'_write_all',side_effect=swap),self.assertRaises(ValueError):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertEqual((self.destination/'foreign').read_bytes(),b'preserve foreign')
        self.assertTrue(moved.is_dir());self.assertEqual(list(moved.iterdir()),[])

    def test_post_prehash_growth_is_bounded_across_empty_members_and_optional_headers(self):
        adapter=self.adapter();original=self.archive_bytes();empty=gzip.compress(b'',mtime=0)
        optional=empty[:3]+b'\x08'+empty[4:10]+b'n'*2048+b'\0'+empty[10:]
        for suffix in (empty*64,optional):
            self.archive.write_bytes(original);consumed=[];scan=adapter._scan
            class Counted:
                def __init__(self,stream):self.stream=stream
                def read(self,size=-1):
                    data=self.stream.read(size);consumed.append(len(data));return data
            def grow_then_scan(stream,*args,**kwargs):
                with self.archive.open('ab') as writer:writer.write(suffix)
                return scan(Counted(stream),*args,**kwargs)
            with self.subTest(suffix_bytes=len(suffix)):
                with patch.object(adapter,'_scan',side_effect=grow_then_scan),self.assertRaises(ValueError):
                    adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
                self.assertFalse(self.destination.exists())
                self.assertLessEqual(sum(consumed),len(original)+1,
                                     'gzip consumed beyond admitted compressed bytes before refusal')

    def test_hash_pass_reads_no_more_than_admitted_size_and_one_excess_byte(self):
        adapter=self.adapter();path=self.root/'growing-source';path.write_bytes(b'x'*8192)
        fd=os.open(path,os.O_RDONLY);read=adapter.os.read;consumed=[]
        def counted(selected,size):
            data=read(selected,size)
            if selected==fd:consumed.append(len(data))
            return data
        try:
            with patch.object(adapter.os,'read',side_effect=counted),self.assertRaises(ValueError):
                adapter._hash_fd(fd,10)
        finally:os.close(fd)
        self.assertEqual(sum(consumed),11)

    def test_metadata_limit_duplicate_and_during_read_mutation_refuse(self):
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes());original=self.meta.read_bytes()
        for raw in (b'x'*65537,original.replace(b'"schema":1',b'"schema":1,"schema":1')):
            self.meta.write_bytes(raw)
            with self.assertRaises(ValueError):
                adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
            self.assertFalse(self.destination.exists())
        self.meta.write_bytes(original);read=adapter.os.read;fired=[];identity=self.meta.stat().st_ino
        def mutate(fd,size):
            data=read(fd,size)
            if os.fstat(fd).st_ino==identity and not fired:
                fired.append(True);info=self.meta.stat();os.utime(self.meta,ns=(info.st_atime_ns,info.st_mtime_ns+1))
            return data
        with patch.object(adapter.os,'read',side_effect=mutate),self.assertRaises(ValueError):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertTrue(fired);self.assertFalse(self.destination.exists())

    def test_fixed_cli_prepares_and_verifies_synthetic_consistency_without_spawning(self):
        import sys
        import subprocess
        from types import SimpleNamespace
        adapter=self.adapter();self.archive.write_bytes(self.archive_bytes())
        output=io.BytesIO();errors=io.StringIO()
        args=['prepare','--archive',str(self.archive),'--metadata',str(self.meta),'--version',VERSION,
              '--target',TARGET,'--destination',str(self.destination),'--source-commit','a'*40]
        with patch.object(sys,'stdout',SimpleNamespace(buffer=output)),patch.object(sys,'stderr',errors),                patch.object(subprocess,'Popen',side_effect=AssertionError('no process')):
            self.assertEqual(adapter.main(args),0)
        prepared=json.loads(output.getvalue());self.assertEqual(output.getvalue(),encoded(prepared))
        self.assertEqual(errors.getvalue(),'')
        prepared_path=self.root/'prepared.json';prepared_path.write_bytes(output.getvalue())
        native=native_fixture(prepared);native_path=self.root/'native.json';native_path.write_bytes(encoded(native))
        output=io.BytesIO()
        with patch.object(sys,'stdout',SimpleNamespace(buffer=output)),patch.object(sys,'stderr',errors):
            self.assertEqual(adapter.main(['verify-result','--prepared',str(prepared_path),'--native',str(native_path)]),0)
        self.assertEqual(output.getvalue(),encoded(native))
        output=io.BytesIO();errors=io.StringIO()
        with patch.object(sys,'stdout',SimpleNamespace(buffer=output)),patch.object(sys,'stderr',errors):
            self.assertEqual(adapter.main(['private-invalid-canary']),1)
        self.assertEqual(output.getvalue(),b'');self.assertEqual(errors.getvalue(),'DARWIN_SMOKE_REFUSED\n')

    def test_existing_producer_metadata_schema_and_all_five_records(self):
        adapter=self.adapter()
        source,hashes=adapter._metadata(self.meta.read_bytes(),TARGET)
        self.assertEqual(source,'a'*40)
        self.assertEqual(hashes,{name:digest(data) for name,data in self.programs.items()})
        original=json.loads(self.meta.read_bytes())
        import copy
        variants=[]
        for change in ('projection','duplicate','wrong-target','wrong-hash','unknown'):
            value=copy.deepcopy(original)
            if change=='projection':value['binaries']=value['binaries'][:2]
            elif change=='duplicate':value['binaries'][1]=value['binaries'][0]
            elif change=='wrong-target':value['target']='x86_64-apple-darwin'
            elif change=='wrong-hash':value['binaries'][0]['sha256']='f'*64
            else:value['source']['private_path']='/private/synthetic'
            variants.append(value)
        for value in variants:
            with self.subTest(value=value['target']),self.assertRaises(ValueError):
                adapter._metadata(json.dumps(value).encode(),TARGET)

    def test_escape_member_refuses_without_leaving_destination(self):
        extra=tarfile.TarInfo(self.stage+'/../escape');extra.size=4
        self.archive.write_bytes(self.archive_bytes((extra,b'evil')))
        adapter=self.adapter()
        with self.assertRaises(ValueError):
            adapter.prepare(self.archive,self.meta,VERSION,TARGET,self.destination,source_commit='a'*40)
        self.assertFalse(self.destination.exists())
        self.assertFalse((self.root/'escape').exists())


def encoded(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode()+b'\n'


def prepared_fixture():
    challenge='1'*48
    return dict(schema=1,kind='darwin-archive-prepared',request_id='2'*32,source_commit='a'*40,
                version=VERSION,target=TARGET,archive_sha256='b'*64,metadata_sha256='c'*64,
                binaries={name:dict(sha256=digest(data),bytes=len(data)) for name,data in
                          {'qsh':b'inert client bytes','qshd':b'inert daemon bytes'}.items()},
                challenge=challenge,expected_output_digest=digest(challenge.encode()))


def native_fixture(prepared):
    value={key:prepared[key] for key in ('request_id','source_commit','version','target','archive_sha256','metadata_sha256','binaries')}
    value.update(schema=1,kind='darwin-archive-smoke',prepared_sha256=digest(encoded(prepared)),
                 host=dict(arch='arm64',darwin_release='24.0.0',os_version='15.0',os_build='24A1',
                           kernel_version='Darwin Kernel Version fixture',execution='native'),
                 status='passed',failure=None,client_exit=37,daemon_exit=0,output_digest=prepared['expected_output_digest'],
                 ownership=dict(direct_children_started=3,direct_children_waited=3,command_exit_observed=True,
                                remaining_children=0,unresolved_owners=0,rescue_used=False,
                                harness_io_joined=True,daemon_shutdown_completed=True))
    return value


class ReceiptTests(unittest.TestCase):
    def adapter(self):
        spec=importlib.util.spec_from_file_location('darwin_receipt_smoke',SCRIPT)
        module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
        return module

    def test_synthetic_consistency_accepts_only_complete_native_receipt(self):
        # Parser consistency only: this synthetic JSON is not native execution evidence.
        adapter=self.adapter();prepared=prepared_fixture();native=native_fixture(prepared)
        self.assertEqual(adapter.verify_result(encoded(prepared),encoded(native)),native)
        native['ownership']['rescue_used']=True
        with self.assertRaises(ValueError):adapter.verify_result(encoded(prepared),encoded(native))


    def test_missing_unknown_duplicate_noncanonical_and_oversized_receipts_refuse(self):
        adapter=self.adapter();prepared=prepared_fixture();native=native_fixture(prepared)
        for name,original in (('prepared',prepared),('native',native)):
            for key in original:
                value=dict(original);del value[key]
                with self.subTest(document=name,missing=key),self.assertRaises(ValueError):
                    adapter.verify_result(encoded(value) if name=='prepared' else encoded(prepared),
                                          encoded(value) if name=='native' else encoded(native))
            bad=dict(original,unknown='synthetic')
            raws=[encoded(bad),json.dumps(original).encode()+b'\n',encoded(original).rstrip(),
                  encoded(original).replace(b'"schema":1',b'"schema":1,"schema":1'),b'x'*16385,b'\xff']
            for raw in raws:
                with self.subTest(document=name,raw=raw[:10]),self.assertRaises(ValueError):
                    adapter.verify_result(raw if name=='prepared' else encoded(prepared),
                                          raw if name=='native' else encoded(native))

    def test_each_native_binding_and_completion_fact_is_required(self):
        import copy
        adapter=self.adapter();prepared=prepared_fixture();base=native_fixture(prepared)
        changes=[('request_id','3'*32),('prepared_sha256','0'*64),('source_commit','f'*40),
                 ('version','0.6.1'),('target','x86_64-apple-darwin'),('archive_sha256','0'*64),
                 ('metadata_sha256','0'*64),('client_exit',0),('client_exit',True),('daemon_exit',-15),
                 ('daemon_exit',None),('output_digest','0'*64),('output_digest',None),
                 ('status','failed'),('failure','UNKNOWN')]
        for key,value in changes:
            native=copy.deepcopy(base);native[key]=value
            with self.subTest(field=key,value=value),self.assertRaises(ValueError):
                adapter.verify_result(encoded(prepared),encoded(native))
        for key,value in (('direct_children_started',1),('direct_children_waited',2),
                          ('remaining_children',1),('unresolved_owners',1),('rescue_used',True),
                          ('command_exit_observed',False),('harness_io_joined',False),
                          ('daemon_shutdown_completed',False),('direct_children_started',True),
                          ('rescue_used',0)):
            native=copy.deepcopy(base);native['ownership'][key]=value
            with self.subTest(ownership=key),self.assertRaises(ValueError):
                adapter.verify_result(encoded(prepared),encoded(native))
        for key,value in (('execution','translated'),('arch','x86_64'),('os_build','private\ncanary')):
            native=copy.deepcopy(base);native['host'][key]=value
            with self.subTest(host=key),self.assertRaises(ValueError):
                adapter.verify_result(encoded(prepared),encoded(native))
        for field in ('host','ownership','binaries'):
            for key in base[field]:
                native=copy.deepcopy(base);del native[field][key]
                with self.subTest(nested=field,missing=key),self.assertRaises(ValueError):
                    adapter.verify_result(encoded(prepared),encoded(native))
            native=copy.deepcopy(base);native[field]['unknown']=True
            with self.subTest(nested=field),self.assertRaises(ValueError):
                adapter.verify_result(encoded(prepared),encoded(native))

    def test_prepared_challenge_hash_types_and_swapped_binary_inputs_refuse(self):
        import copy
        adapter=self.adapter();prepared=prepared_fixture();native=native_fixture(prepared)
        for key,value in (('schema',True),('request_id','bad'),('challenge','f'*48),
                          ('version','0.6'),('expected_output_digest','0'*64)):
            changed=copy.deepcopy(prepared);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                adapter.verify_result(encoded(changed),encoded(native))
        for value in (True,0,268435457,1.0):
            changed=copy.deepcopy(prepared);changed['binaries']['qsh']['bytes']=value
            with self.subTest(bytes=value),self.assertRaises(ValueError):
                adapter.verify_result(encoded(changed),encoded(native))
        changed=copy.deepcopy(native);changed['binaries']['qsh']['sha256']='f'*64
        with self.assertRaises(ValueError):adapter.verify_result(encoded(prepared),encoded(changed))


class RuntimeDriverTests(unittest.TestCase):
    """Producer-coupled controls use inert executables and a fixed fake runner."""
    setUp=PrepareTests.setUp
    adapter=PrepareTests.adapter
    archive_bytes=PrepareTests.archive_bytes

    def setup_run(self):
        self.archive.write_bytes(self.archive_bytes())
        self.harness=self.root/'harness';self.harness.write_bytes(b'inert harness');self.harness.chmod(0o700)
        return self.adapter()

    def test_output_limit_requests_owned_cancellation_and_waits_before_refusing(self):
        import subprocess
        adapter=self.setup_run();owned=[]
        script="""#!/usr/bin/python3
import os,time
from pathlib import Path
root=Path(os.environ['QSH_DARWIN185_REQUEST']).parent
print('x'*70000,flush=True)
end=time.monotonic()+2
while time.monotonic()<end:
    if (root/'cancel').exists():
        (root/'settled').touch();break
    time.sleep(.005)
"""
        self.harness.write_text(script)
        original=subprocess.Popen
        def spawn(*args,**kwargs):
            child=original(*args,**kwargs);owned.append(child);return child
        try:
            with patch.object(subprocess,'Popen',side_effect=spawn),self.assertRaises(ValueError):
                adapter._invoke_fixed(self.harness,dict(directory=str(self.root)),'failure')
            self.assertTrue((self.root/'failure'/'settled').is_file())
            self.assertIsNotNone(owned[0].returncode)
        finally:
            for child in owned:child.wait(timeout=3)

    def test_success_projection_excludes_private_binding_but_retains_receipt_hash(self):
        adapter=self.setup_run();raw_native=[]
        def invoke(harness,request,mode):
            if mode=='failure':
                return dict(schema=1,kind='darwin-archive-controlled-failure',prepared_sha256=request['prepared_sha256'],
                            bound=True,actor_exit=True,daemon_exit=0,waited=True,io_joined=True,rescue=False,unresolved=0)
            native=native_fixture(request['prepared']);raw_native.append(native);return native
        with patch.object(adapter,'_native_host',return_value=dict(arch='arm64',execution='native',os_version='15.0')), \
                patch.object(adapter,'_invoke_fixed',side_effect=invoke):
            result=adapter.run_archive(self.archive,self.meta,VERSION,TARGET,self.root/'run',self.harness,source_commit='a'*40)
        self.assertNotIn('request_id',result['native'])
        self.assertEqual(result['native']['receipt_sha256'],digest(adapter.canonical(raw_native[0])))
        self.assertNotIn(str(self.root).encode(),adapter.canonical(result))
        private=raw_native[0]['request_id']
        self.assertNotIn(private.encode(),adapter.canonical(result))

    def test_source_symlink_or_pair_drift_prevents_execution_or_positive_transition(self):
        for mutation in ('source','symlink','pair'):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as tmp:
                adapter=self.setup_run();calls=[]
                harness=self.harness
                if mutation=='symlink':
                    harness=self.root/'link';harness.symlink_to(self.harness)
                def invoke(harness,request,mode):
                    calls.append(mode);Path(request['client']).write_bytes(b'changed extracted payload')
                    return dict(schema=1,kind='darwin-archive-controlled-failure',prepared_sha256=request['prepared_sha256'],
                                bound=True,actor_exit=True,daemon_exit=0,waited=True,io_joined=True,rescue=False,unresolved=0)
                with patch.object(adapter,'_native_host',return_value=dict(arch='arm64',execution='native',os_version='15.0')), \
                        patch.object(adapter,'_invoke_fixed',side_effect=invoke),self.assertRaises(ValueError):
                    adapter.run_archive(self.archive,self.meta,VERSION,TARGET,self.root/('run-'+mutation),harness,
                                        source_commit='b'*40 if mutation=='source' else 'a'*40)
                self.assertEqual(calls,['failure'] if mutation=='pair' else [])

    def test_cargo_selection_refuses_stale_ambiguous_features_and_nonobject_records(self):
        adapter=self.setup_run();root=self.root/TARGET/'debug'/'deps';root.mkdir(parents=True)
        selected=root/'qshd-inert'
        record=dict(reason='compiler-artifact',executable=str(selected),target=dict(name='qshd',kind=['lib']),
                    profile=dict(test=True),fresh=False,features=[],manifest_path=str(ROOT/'qshd/Cargo.toml'))
        messages=self.root/'cargo.json'
        messages.write_bytes(adapter.canonical(record));self.assertEqual(adapter.select_harness(messages,root,TARGET),selected)
        for records in ([dict(record,fresh=True)],[record,record],[dict(record,features=['test-darwin-keeper'])], [dict(record,executable=True)], [dict(record,manifest_path=3)], [[]]):
            messages.write_bytes(b''.join(adapter.canonical(item) for item in records))
            with self.subTest(records=records),self.assertRaises(ValueError):adapter.select_harness(messages,root,TARGET)

    def test_linux_helper_keeps_darwin_refusal_before_any_version_process(self):
        spec=importlib.util.spec_from_file_location('linux_smoke_guard',ROOT/'scripts/client-artifact-smoke.py')
        helper=importlib.util.module_from_spec(spec);spec.loader.exec_module(helper)
        with patch.object(helper.sys,'platform','darwin'),patch.object(helper,'version_check') as version, \
                self.assertRaises(helper.SmokeError):
            helper.smoke('/inert/qsh','/inert/qshd',VERSION)
        version.assert_not_called()

    def test_runtime_refuses_host_before_any_executor(self):
        adapter=self.setup_run()
        for host in (dict(arch='x86_64',execution='native',os_version='15.0'),
                     dict(arch='arm64',execution='translated',os_version='15.0'),
                     dict(arch='arm64',execution='native',os_version='14.0')):
            with self.subTest(host=host),patch.object(adapter,'_native_host',return_value=host), \
                    patch.object(adapter,'_invoke_fixed') as invoke,self.assertRaises(ValueError):
                adapter.run_archive(self.archive,self.meta,VERSION,TARGET,self.root/'run',
                                    self.harness,source_commit='a'*40)
            invoke.assert_not_called()

    def test_fixed_failure_must_settle_before_positive_and_archive_is_rechecked(self):
        adapter=self.setup_run();calls=[]
        def invoke(harness,request,mode):
            calls.append(mode)
            self.assertEqual(request['client'],str(self.root/'run'/'pair'/'qsh'))
            self.assertEqual(request['daemon'],str(self.root/'run'/'pair'/'qshd'))
            self.assertEqual(request['harness_sha256'],digest(b'inert harness'))
            if mode=='failure':
                return dict(schema=1,kind='darwin-archive-controlled-failure',
                            prepared_sha256=request['prepared_sha256'],bound=True,actor_exit=True,
                            daemon_exit=0,waited=True,io_joined=True,rescue=False,unresolved=0)
            self.archive.write_bytes(b'drift after synthetic observation')
            return native_fixture(request['prepared'])
        with patch.object(adapter,'_native_host',return_value=dict(arch='arm64',execution='native',os_version='15.0')), \
                patch.object(adapter,'_invoke_fixed',side_effect=invoke),self.assertRaises(ValueError):
            adapter.run_archive(self.archive,self.meta,VERSION,TARGET,self.root/'run',self.harness,source_commit='a'*40)
        self.assertEqual(calls,['failure','positive'])

    def test_incomplete_controlled_failure_never_starts_positive(self):
        adapter=self.setup_run();calls=[]
        def invoke(harness,request,mode):
            calls.append(mode)
            return dict(schema=1,kind='darwin-archive-controlled-failure',
                        prepared_sha256=request['prepared_sha256'],bound=True,actor_exit=True,
                        daemon_exit=0,waited=True,io_joined=False,rescue=False,unresolved=0)
        with patch.object(adapter,'_native_host',return_value=dict(arch='arm64',execution='native',os_version='15.0')), \
                patch.object(adapter,'_invoke_fixed',side_effect=invoke),self.assertRaises(ValueError):
            adapter.run_archive(self.archive,self.meta,VERSION,TARGET,self.root/'run',self.harness,source_commit='a'*40)
        self.assertEqual(calls,['failure'])


if __name__=='__main__':unittest.main()
