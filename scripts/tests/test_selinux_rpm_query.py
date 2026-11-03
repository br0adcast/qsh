"""Controlled RPM text and temporary route tests; never execute rpm."""
import dataclasses
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'packaging/selinux'))
from qshd_selinux_process import _Streams


def adapter():
    assert (Path(__file__).resolve().parents[2] / 'packaging/selinux/qshd_selinux_rpm_query.py').is_file(), 'RPM query adapter missing'
    import qshd_selinux_rpm_query
    return qshd_selinux_rpm_query


def package(name='qshd', epoch='0', version='0.5.0'):
    return f'P\t{json.dumps(name)}\t{epoch}\t{json.dumps(version)}\t"1"\t"x86_64"\n'.encode()


def row(path, *, size=3, mode=0o100755, flags=0, digest='a'*64, link='', state=0):
    return ('F\t'+json.dumps(path)+f'\t{size}\t{mode}\t{flags}\t"root"\t"root"\t'+json.dumps(digest)+'\t'+json.dumps(link)+f'\t{state}\n').encode()


def files(path, **changes):
    return package()+b'A\t8\n'+row('/usr', size=0, mode=0o40755, digest='')+row('/lib-link', size=0, mode=0o120777, digest='', link='usr/lib')+row(path, **changes)+b'E\n'


class ParserTests(unittest.TestCase):
    def test_complete_inventory_and_owner_grammar(self):
        m=adapter()
        self.assertEqual(m._inventory(b''), ())
        self.assertEqual(m._inventory(package())[0].epoch, 0)
        selected=m._owner_records(files('/usr/bin/qshd'), '/usr/bin/qshd')
        self.assertEqual(selected[1].path, '/usr/bin/qshd')
        for raw in (package()+b'bad\n', package(epoch='00'), package(epoch='-1'), package()[:-1]):
            with self.subTest(raw=raw[:40]), self.assertRaises(m.RpmQueryError):
                m._inventory(raw)

    def test_selected_directory_symlink_empty_digest_or_state_refuse(self):
        m=adapter()
        for changes in ({'mode':0o40755,'digest':''}, {'mode':0o120777,'digest':'','link':'usr/lib'}, {'digest':''}, {'state':1}):
            with self.subTest(changes=changes), self.assertRaises(m.RpmQueryError):
                m._owner_records(files('/usr/bin/qshd', **changes), '/usr/bin/qshd')


class ControlledOwner:
    def __init__(self, outputs):
        self.outputs=list(outputs)
        self.calls=[]
        self._last=None
        self.after=None

    def _run(self, argv, cwd, *, deadline):
        self.calls.append((argv,cwd,deadline))
        value=self.outputs.pop(0)
        self._last=SimpleNamespace(failure=None,exit_code=0,settled=True,unreaped=())
        if self.after:
            self.after()
        if isinstance(value, Exception):
            raise value
        return _Streams(value,b'')


class LeaseTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        for path in ('usr/bin','usr/lib/sysimage/rpm'):
            (self.root/path).mkdir(parents=True,exist_ok=True)
        for directory in self.root.rglob('*'):
            if directory.is_dir():
                directory.chmod(0o755)
        self.tool=self.root/'usr/bin/rpm'
        self.tool.write_bytes(b'inert test executable; never run')
        self.tool.chmod(0o755)
        self.db=self.root/'usr/lib/sysimage/rpm/rpmdb.sqlite'
        self.db.write_bytes(b'synthetic database sentinel; never read')
        self.db.chmod(0o644)
        self.clock=lambda:100.0

    def query(self, owner):
        m=adapter()
        return m.RpmQuery(_root=self.root,_uid=os.geteuid(),_owner=owner,_clock=self.clock)

    def authority(self):
        m=adapter()
        return m.ConsumerRpmAuthority(1,m.RpmPackage('qshd',0,'0.5.0','1','x86_64'),tuple(
            m.RpmFileAuthority(path,3,'a'*64,0o100755,'root','root',0)
            for path in ('/usr/bin/qshd','/etc/pam.d/qshd')))

    def expect_capture_refusal(self, owner, *, owned=False, deadline=300.0):
        m=adapter()
        returned=[]
        with self.assertRaises(m.RpmQueryError):
            with self.query(owner).inspection(deadline=deadline) as lease:
                returned.append(lease.capture_owned(self.authority()) if owned else lease.capture_absent())
        # A missing recheck at context exit must never mask an admitted capture.
        self.assertEqual(returned,[], 'forbidden capture returned an observation')

    def test_absence_requires_two_normal_complete_inventory_commands(self):
        m=adapter()
        owner=ControlledOwner([package('unrelated'), package('another')])
        with self.query(owner).inspection(deadline=300.0) as lease:
            record=lease.capture_absent()
            self.assertIsNone(record.package)
            lease.recheck(record)
        self.assertEqual(owner.calls,[(m._INVENTORY,'/',290.0)]*2)
        with self.assertRaises(m.RpmQueryError):lease.recheck(record)

    def test_presence_binds_three_fixed_commands_per_capture_and_recheck(self):
        m=adapter()
        outputs=[package(),files('/usr/bin/qshd'),files('/etc/pam.d/qshd')]
        owner=ControlledOwner(outputs*2)
        with self.query(owner).inspection(deadline=300.0) as lease:
            record=lease.capture_owned(self.authority())
            self.assertEqual(record.package,self.authority().package)
            lease.recheck(record)
        expected=[m._INVENTORY]+[m._PREFIX+('-qf','--queryformat',m._F,path) for path in m._PATHS]
        self.assertEqual([call[0] for call in owner.calls],expected*2)
        self.assertTrue(all(call[1:] == ('/',290.0) for call in owner.calls))

    def test_nonzero_empty_or_convincing_output_never_proves_absence(self):
        m=adapter()
        for output in (b'', package('unrelated')):
            owner=ControlledOwner([output])
            owner.after=lambda: setattr(owner._last,'exit_code',1)
            with self.subTest(output=output):
                self.expect_capture_refusal(owner)
            self.assertEqual(len(owner.calls),1)

    def test_custody_failure_and_stderr_refuse_without_retry(self):
        m=adapter()
        for change in ({'failure':'TOOL_FAILURE'},{'settled':False},{'unreaped':(42,)},{'exit_code':True}):
            owner=ControlledOwner([b''])
            owner.after=lambda: vars(owner._last).update(change)
            with self.subTest(change=change):
                self.expect_capture_refusal(owner)
            self.assertEqual(len(owner.calls),1)
        owner=ControlledOwner([b''])
        def warning(*args,**kwargs):
            owner._last=SimpleNamespace(failure=None,exit_code=0,settled=True,unreaped=())
            return _Streams(b'',b'fallback warning')
        with patch.object(owner,'_run',side_effect=warning), self.assertRaises(m.RpmQueryError):
            with self.query(owner).inspection(deadline=300.0) as lease:
                lease.capture_absent()

    def test_only_exact_typed_streams_and_bytes_are_accepted(self):
        for streams in (SimpleNamespace(stdout=b'',stderr=b''),
                        _Streams(b'',bytearray()),
                        _Streams(bytearray(),b''),
                        _Streams(b'', ''),
                        _Streams(b'x'*(4*1024**2+1),b'')):
            with self.subTest(kind=type(streams),stderr=type(streams.stderr)):
                owner=ControlledOwner([])
                def run(*args,**kwargs):
                    owner._last=SimpleNamespace(failure=None,exit_code=0,settled=True,unreaped=())
                    return streams
                with patch.object(owner,'_run',side_effect=run):
                    self.expect_capture_refusal(owner)

    def test_missing_configured_database_refuses_before_owner_construction(self):
        m=adapter()
        self.db.unlink()
        with patch.object(m,'_Owner',side_effect=AssertionError('must not construct owner')):
            query=m.RpmQuery(_root=self.root,_uid=os.geteuid(),_clock=self.clock)
            with self.assertRaises(m.RpmQueryError):
                with query.inspection(deadline=300.0):self.fail('missing database admitted')
        self.assertFalse(self.db.exists())

    def test_post_command_equal_content_database_replacement_is_not_absence(self):
        m=adapter()
        owner=ControlledOwner([b''])
        def replace():
            replacement=self.root/'replacement'
            replacement.write_bytes(self.db.read_bytes())
            replacement.chmod(0o644)
            replacement.replace(self.db)
        owner.after=replace
        self.expect_capture_refusal(owner)
        self.assertEqual(len(owner.calls),1)

    def test_normal_sqlite_housekeeping_does_not_require_byte_or_time_identity(self):
        owner=ControlledOwner([b'',b''])
        owner.after=lambda: self.db.write_bytes(b'ordinary synthetic SQLite housekeeping')
        with self.query(owner).inspection(deadline=300.0) as lease:
            token=lease.capture_absent()
            lease.recheck(token)
        self.assertEqual(len(owner.calls),2)

    def test_missing_unsafe_symlink_hardlink_or_empty_leaves_refuse_without_query(self):
        m=adapter()
        saved=self.db.read_bytes()
        for kind in ('empty','writable','symlink','hardlink','directory','unsafe-parent'):
            with self.subTest(kind=kind):
                if kind=='empty':self.db.write_bytes(b'')
                elif kind=='writable':self.db.chmod(0o666)
                elif kind=='symlink':
                    self.db.unlink()
                    self.db.symlink_to(self.root/'missing')
                elif kind=='hardlink':os.link(self.db,self.root/'other-link')
                elif kind=='directory':
                    self.db.unlink()
                    self.db.mkdir()
                else:self.db.parent.chmod(0o777)
                owner=ControlledOwner([])
                with self.assertRaises(m.RpmQueryError):
                    with self.query(owner).inspection(deadline=300.0):self.fail('unsafe layout admitted')
                self.assertEqual(owner.calls,[])
                if kind=='hardlink':(self.root/'other-link').unlink()
                if self.db.is_dir():self.db.rmdir()
                elif self.db.is_symlink():self.db.unlink()
                self.db.write_bytes(saved)
                self.db.chmod(0o644)
                self.db.parent.chmod(0o755)

    def test_original_reserves_and_end_minus_ten_are_not_reset(self):
        m=adapter()
        for owned,end in ((False,140.0),(True,200.0)):
            owner=ControlledOwner([])
            self.expect_capture_refusal(owner,owned=owned,deadline=end)
            self.assertEqual(owner.calls,[])
        now=[100.0]
        self.clock=lambda:now[0]
        owner=ControlledOwner([b''])
        owner.after=lambda:now.__setitem__(0,120.0)
        with self.assertRaises(m.RpmQueryError):
            with self.query(owner).inspection(deadline=145.0) as lease:
                token=lease.capture_absent()
                lease.recheck(token)
        self.assertEqual(len(owner.calls),1)
        self.assertEqual(owner.calls[0][2],135.0)
        for value in (float('nan'),float('inf'),True,10**1000):
            with self.subTest(value=type(value)), self.assertRaises(m.RpmQueryError):
                with self.query(ControlledOwner([])).inspection(deadline=value):pass

    def test_package_selection_epoch_and_exact_file_metadata_are_authority(self):
        m=adapter()
        mutations=[package()+package(),package(epoch='1'),package(version='different')]
        for inventory in mutations:
            owner=ControlledOwner([inventory])
            self.expect_capture_refusal(owner,owned=True)
            self.assertEqual(len(owner.calls),1)
        for change in ({'digest':'b'*64},{'size':4},{'mode':0o100644},{'flags':1},{'state':1}):
            owner=ControlledOwner([package(),files('/usr/bin/qshd',**change)])
            with self.subTest(change=change):
                self.expect_capture_refusal(owner,owned=True)
            self.assertEqual(len(owner.calls),2)

    def test_exact_token_drift_poison_and_required_normal_exit(self):
        m=adapter()
        owner=ControlledOwner([b''])
        query=self.query(owner)
        with self.assertRaises(m.RpmQueryError):
            with query.inspection(deadline=300.0) as lease:
                token=lease.capture_absent()
                with self.assertRaises(m.RpmQueryError):
                    with query.inspection(deadline=300.0):pass
                with self.assertRaises(m.RpmQueryError):lease.recheck(dataclasses.replace(token))
                with self.assertRaises(m.RpmQueryError):lease.recheck(token)
        with self.assertRaises(m.RpmQueryError):lease.recheck(token)
        owner=ControlledOwner([b'',package()])
        with self.assertRaises(m.RpmQueryError):
            with self.query(owner).inspection(deadline=300.0) as lease:
                token=lease.capture_absent()
                with self.assertRaises(m.RpmQueryError):lease.recheck(token)
                with self.assertRaises(m.RpmQueryError):lease.capture_absent()

    def test_cleanup_attempts_all_descriptors_and_resets_active_after_close_error(self):
        m=adapter()
        before=set(os.listdir('/proc/self/fd'))
        query=self.query(ControlledOwner([b'',b'']))
        real_close=os.close
        closed=[]
        def failed_close(fd):
            real_close(fd)
            closed.append(fd)
            if len(closed)==1:raise OSError('injected close-after-close')
        with self.assertRaises(m.RpmQueryError):
            with query.inspection(deadline=300.0) as lease:
                token=lease.capture_absent()
                lease.recheck(token)
                # Patch only scope finalization, not query-time leaf cleanup.
                finalizer=patch.object(m.os,'close',side_effect=failed_close)
                finalizer.start()
                self.addCleanup(finalizer.stop)
        finalizer.stop()
        self.assertGreater(len(closed),1)
        self.assertEqual(set(os.listdir('/proc/self/fd')),before)
        self.assertFalse(query._active)

    def test_malformed_tail_and_owner_package_group_mismatch_refuse(self):
        m=adapter()
        for inventory in (package('unrelated')+b'malformed tail\n',package('qshd')+b'malformed tail\n'):
            owner=ControlledOwner([inventory])
            self.expect_capture_refusal(owner)
        for output in (files('/usr/bin/qshd').replace(package(),package(version='different')),
                       files('/usr/bin/qshd')+files('/usr/bin/qshd'),
                       files('/usr/bin/qshd').replace(b'"root"\t"root"',b'"foreign"\t"root"'),
                       files('/usr/bin/qshd',link='nonempty')):
            owner=ControlledOwner([package(),output])
            self.expect_capture_refusal(owner,owned=True)

    def test_fixed_profile_prefix_and_no_database_content_read(self):
        m=adapter()
        owner=ControlledOwner([b'',b''])
        factory=[]
        def construct(limits):
            factory.append((limits.execution_seconds,limits.output_bytes))
            return owner
        with patch.object(m,'_Owner',side_effect=construct),patch.object(m.os,'read',side_effect=AssertionError('database content read')),\
             patch.dict(os.environ,{'RPM_CONFIGDIR':'/untrusted','RPM_DBPATH':'/untrusted'}):
            query=m.RpmQuery(_root=self.root,_uid=os.geteuid(),_clock=self.clock)
            with query.inspection(deadline=300.0) as lease:
                token=lease.capture_absent()
                lease.recheck(token)
        self.assertEqual(factory,[(15,4*1024**2)])
        self.assertTrue(all(call[0][:8]==('/usr/bin/rpm','--root','/','--dbpath','/usr/lib/sysimage/rpm','--define','_db_backend sqlite','-qa') for call in owner.calls))

    def test_recheck_owner_metadata_drift_and_foreign_token_refuse(self):
        m=adapter()
        capture=[package(),files('/usr/bin/qshd'),files('/etc/pam.d/qshd')]
        owner=ControlledOwner(capture+[package(),files('/usr/bin/qshd',flags=1)])
        with self.assertRaises(m.RpmQueryError):
            with self.query(owner).inspection(deadline=300.0) as lease:
                token=lease.capture_owned(self.authority())
                lease.recheck(token)
        with self.assertRaises(m.RpmQueryError):
            with self.query(ControlledOwner([])).inspection(deadline=300.0) as foreign:
                foreign.recheck(token)


    def test_final_route_drift_cannot_return_success(self):
        m=adapter()
        with self.assertRaises(m.RpmQueryError):
            with self.query(ControlledOwner([b'',b''])).inspection(deadline=300.0) as lease:
                token=lease.capture_absent()
                lease.recheck(token)
                self.db.chmod(0o600)

    def test_late_descriptor_cleanup_cannot_return_success(self):
        m=adapter()
        now=[100.0]
        self.clock=lambda:now[0]
        real_close=os.close
        def late_close(fd):
            real_close(fd)
            now[0]=301.0
        with self.assertRaises(m.RpmQueryError):
            with self.query(ControlledOwner([b'',b''])).inspection(deadline=300.0) as lease:
                token=lease.capture_absent()
                lease.recheck(token)
                original=lease._close
                def late_finalizer():
                    with patch.object(m.os,'close',side_effect=late_close):
                        original()
                lease._close=late_finalizer



class StrictParserTests(unittest.TestCase):
    def test_whole_group_truncation_duplicates_placeholders_and_unsafe_paths(self):
        m=adapter()
        good=files('/usr/bin/qshd')
        cases=[good[:-1],good.replace(b'E\n',b''),good+good,good.replace(b'A\t8',b'A\t1'),
               good.replace(b'A\t8',b'A\t%{FILEDIGESTALGO}'),
               good.replace(b'E\n',row('/usr/bin/qshd')+b'E\n'),
               good.replace(b'F\t"/usr"',b'F\t"//usr"'),
               good.replace(b'F\t"/usr"',b'F\t"/usr/../etc"'),
               good.replace(b'F\t"/usr"',b'F\t"/usr/"'),
               good.replace(b'F\t"/usr"',b'F\t"/usr\\tbad"'),
               good.replace(b'F\t"/usr"',b'F\t"/usr\\u0080"'),
               good.replace(b'"root"\t"root"',b'"root"',1),
               good.replace(b'F\t"/usr"',b'F\t%{FILENAMES:json}'),
               good.replace(b'E\n',b'F\t"incomplete"\nE\n')]
        for raw in cases:
            with self.subTest(raw=raw[-70:]),self.assertRaises(m.RpmQueryError):
                m._owner_records(raw,'/usr/bin/qshd')

    def test_scalar_numeric_and_digest_ranges_are_strict(self):
        m=adapter()
        good=files('/usr/bin/qshd')
        for value in ('-1','+1','01','1.0','1e0','true',str(2**64),'9'*100):
            raw=good.replace(b'F\t"/usr/bin/qshd"\t3',b'F\t"/usr/bin/qshd"\t'+value.encode())
            with self.subTest(value=value[:30]),self.assertRaises(m.RpmQueryError):
                m._owner_records(raw,'/usr/bin/qshd')
        for change in ({'mode':65536},{'flags':2**32},{'digest':'A'*64},{'state':2**32}):
            with self.subTest(change=change),self.assertRaises(m.RpmQueryError):
                m._owner_records(files('/usr/bin/qshd',**change),'/usr/bin/qshd')
        for raw in (package().replace(b'"qshd"',b'null'),package().replace(b'"qshd"',b'false'),
                    package(epoch=str(2**32)),package().replace(b'"qshd"',b'"\\u0000"'),
                    package().replace(b'"qshd"',b'"(none)"')):
            with self.assertRaises(m.RpmQueryError):m._inventory(raw)

    def test_capacity_edges_and_escaped_printable_path(self):
        m=adapter()
        self.assertEqual(len(m._inventory(package('other')*16384)),16384)
        with self.assertRaises(m.RpmQueryError):m._inventory(package('other')*16385)
        raw=package()+b'A\t8\n'+row('/'+'x'*4095,mode=0o40755,digest='')+row('/usr/bin/qshd')+b'E\n'
        self.assertEqual(m._owner_records(raw,'/usr/bin/qshd')[1].path,'/usr/bin/qshd')
        with self.assertRaises(m.RpmQueryError):m._owner_records(raw.replace(b'x'*4095,b'x'*4096),'/usr/bin/qshd')
        escaped=package()+b'A\t8\n'+row('/unselected"quote',mode=0o40755,digest='')+row('/usr/bin/qshd')+b'E\n'
        self.assertEqual(m._owner_records(escaped,'/usr/bin/qshd')[1].path,'/usr/bin/qshd')
        for raw in (b'x'*32769+b'\n',b'x'*(4*1024**2+1),b'\xff\n',b'\n'):
            with self.assertRaises(m.RpmQueryError):m._inventory(raw)

    def test_owner_row_count_boundary_validates_every_unselected_row(self):
        m=adapter()
        rows=b''.join(row('/entry/'+str(number),mode=0o40755,digest='') for number in range(16383))
        raw=package()+b'A\t8\n'+rows+row('/usr/bin/qshd')+b'E\n'
        self.assertLess(len(raw),4*1024**2)
        self.assertEqual(m._owner_records(raw,'/usr/bin/qshd')[1].path,'/usr/bin/qshd')
        with self.assertRaises(m.RpmQueryError):
            m._owner_records(raw[:-2]+row('/one-too-many',mode=0o40755,digest='')+b'E\n','/usr/bin/qshd')

    def test_typed_authority_is_immutable_explicit_and_not_an_rpm_result(self):
        m=adapter()
        package_identity=m.RpmPackage('qshd',0,'0.5.0','1','x86_64')
        values=tuple(m.RpmFileAuthority(path,3,'a'*64,0o100755,'root','root',0) for path in m._PATHS)
        authority=m.ConsumerRpmAuthority(1,package_identity,values)
        with self.assertRaises(dataclasses.FrozenInstanceError):authority.schema=2
        for schema,package_value,file_values in ((True,package_identity,values),(1,dataclasses.replace(package_identity,name='foreign'),values),
                                                (1,package_identity,list(values)),(1,package_identity,(values[0],values[0]))):
            with self.assertRaises(m.RpmQueryError):m.ConsumerRpmAuthority(schema,package_value,file_values)
        for change in ({'sha256':''},{'mode':0o120777},{'size':True},{'flags':-1},{'path':'/arbitrary'}):
            with self.assertRaises(m.RpmQueryError):dataclasses.replace(values[0],**change)
