"""First install only: settled tool success is never current-policy readiness.

Trusted caller holds package exclusion, has stopped/drained service with the
administrator stop guard, and has published fresh durable PENDING. No automatic
adoption, update, removal, rollback, COMPLETE publication or package hooks.
An outer fresh process must impose the hard wall deadline on filesystem calls.
"""
from dataclasses import dataclass
import hashlib
import math
import os
from pathlib import Path
import secrets
import stat
import time

from qshd_selinux_activation import TrustedArtifact, ActivationError
from qshd_selinux_fs import SafeFiles, Conflict, identity
from qshd_selinux_modules import MAX_HLL, ModuleError, parse_full_listing
from qshd_selinux_module_observer import _protected_file, _store_readlock, ObserverError
from qshd_selinux_process import _Owner, _Limits, _CommandError, _Streams

_PREFIX = ('/usr/bin/semodule','--store-path','/var/lib/selinux','-s','targeted')
_LIST = _Limits(15,1024*1024)
_INSTALL = _Limits(75,1024*1024)


class InstallError(RuntimeError):
    """Bounded refusal. A failed attempt may have changed the policy store."""


def _fail(code):
    raise InstallError(code)


@dataclass(frozen=True)
class InstallResult:
    """Successful normal tool completion only; no readiness evidence."""
    artifact: TrustedArtifact
    pp_sha256: str


def _routes(uid, anchor):
    value=SafeFiles()
    value.uid=uid;value.anchor=anchor;value.anchors=[];value.routes=[]
    value.hook=lambda event:None
    return value


def _close_routes(value):
    errors=False
    fds=value.anchors+[item for route in value.routes for item in (route[0],route[2])]
    for fd in reversed(list(dict.fromkeys(fds))):
        try:os.close(fd)
        except BaseException:errors=True
    value.anchors=[];value.routes=[]
    if errors:_fail('CLEANUP')


def production_installer(trusted_artifact, pp_bytes):
    if os.geteuid()!=0:_fail('ROOT_REQUIRED')
    return FirstInstall(trusted_artifact,pp_bytes)


class FirstInstall(SafeFiles):
    """Single use; underscored injection is only for trusted disposable tests."""
    def __init__(self, trusted_artifact, pp_bytes, *, _root=None, _uid=0,
                 _owner=None, _clock=time.monotonic):
        if type(trusted_artifact) is not TrustedArtifact:_fail('TRUSTED_ARTIFACT')
        try:trusted_artifact.__post_init__()
        except ActivationError:raise InstallError('TRUSTED_ARTIFACT') from None
        if type(pp_bytes) is not bytes or not 0<len(pp_bytes)<=MAX_HLL:_fail('PP_INPUT')
        if hashlib.sha256(pp_bytes).hexdigest()!=trusted_artifact.pp_sha256:_fail('PP_IDENTITY')
        self._trusted=TrustedArtifact(trusted_artifact.provider_version,
                                     trusted_artifact.manifest_sha256,trusted_artifact.pp_sha256)
        self._pp=pp_bytes
        self.anchor=Path('/') if _root is None else Path(_root)
        if not self.anchor.is_absolute():_fail('ANCHOR')
        self.uid=_uid;self.hook=lambda event:None
        self.anchors=[];self.routes=[];self._fds=[];self._dirs={};self._files={}
        self._injected=_owner;self._owner=None;self._clock=_clock;self._used=False
        self._scratch=None;self._file=None;self._uncertain=False

    def _time(self):
        if self._clock()>=self._end:_fail('DEADLINE')

    def _guard(self):
        self._time();self._validate_directory_routes()
        for key,parent,name,limit in [('executable','bin','semodule',MAX_HLL),
                                      ('config','config','semanage.conf',65536),
                                      ('platform','platform','os-release',8192)]:
            value=_protected_file(self,self._dirs[parent],name,limit,executable=key=='executable')
            if not self._same(value,self._files[key],times=True):_fail('INPUT_DRIFT')
        if _store_readlock(self,self._dirs['store'])!=self._lock:_fail('LOCK_DRIFT')
        if self._scratch is not None:
            entry=self._scratch
            if entry['identity'] is None or entry['fd'] is None:_fail('SCRATCH_PARTIAL')
            named=os.stat(entry['name'],dir_fd=self._dirs['run'],follow_symlinks=False)
            held=os.fstat(entry['fd'])
            if identity(named)!=identity(held) or identity(held)!=entry['identity']:_fail('SCRATCH_BINDING')
            if not stat.S_ISDIR(held.st_mode) or held.st_uid!=self.uid or stat.S_IMODE(held.st_mode)!=0o700:_fail('SCRATCH_AUTHORITY')
        if self._file is not None:
            self._bound(self._scratch['fd'],'qshd.pp',self._file,state=True)
            value=self._read(self._scratch['fd'],'qshd.pp',state=True,limit=MAX_HLL)
            if value['data']!=self._pp:_fail('PP_DRIFT')
        self._time()

    def _active(self):
        # Normal load may replace this tree. Never retain its old routes as a
        # post-mutation identity requirement; re-admit canonical names instead.
        files=_routes(self.uid,self.anchor)
        try:
            files._directory(self.anchor/'var/lib/selinux/targeted/active/modules')
            files._validate_directory_routes()
        finally:_close_routes(files)
        self._time()

    def _admit(self):
        for key,path in [('bin','usr/bin'),('config','etc/selinux'),
                         ('platform','usr/lib'),('store','var/lib/selinux/targeted'),('run','run')]:
            self._dirs[key]=self._directory(self.anchor/path);self._time()
        for key,parent,name,limit in [('executable','bin','semodule',MAX_HLL),
                                      ('config','config','semanage.conf',65536),
                                      ('platform','platform','os-release',8192)]:
            self._files[key]=_protected_file(self,self._dirs[parent],name,limit,executable=key=='executable')
        fields=self._files['platform']['data'].splitlines()
        if ([x for x in fields if x.startswith(b'ID=')]!=[b'ID=fedora'] or
                [x for x in fields if x.startswith(b'VERSION_ID=')]!=[b'VERSION_ID=44']):_fail('PLATFORM')
        self._lock=_store_readlock(self,self._dirs['store'])
        self._active();self._guard()

    def _make_scratch(self):
        name='qshd-install-'+secrets.token_hex(16)
        os.mkdir(name,0o700,dir_fd=self._dirs['run'])
        self._scratch={'name':name,'fd':None,'identity':None}
        made=os.stat(name,dir_fd=self._dirs['run'],follow_symlinks=False)
        self._scratch['identity']=identity(made)
        fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self._dirs['run'])
        self._fds.append(fd);self._scratch['fd']=fd
        if identity(os.fstat(fd))!=identity(made):_fail('SCRATCH_BINDING')
        os.fchmod(fd,0o700);self._guard()
        leaf=os.open('qshd.pp',os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
        self._fds.append(leaf);self._file=leaf
        self._bound(fd,'qshd.pp',leaf)
        os.fchmod(leaf,0o600)
        view=memoryview(self._pp)
        while view:
            written=os.write(leaf,view)
            if written<=0:_fail('PP_WRITE')
            view=view[written:];self._time()
        os.fsync(leaf);os.fsync(fd);self._guard()

    def _command(self, argv, limits):
        self._guard()
        if self._clock()>=self._end-10:_fail('DEADLINE')
        owner=self._injected if self._injected is not None else _Owner(limits)
        self._owner=owner
        try:
            streams=owner._run(argv,self.anchor/'run'/self._scratch['name'],deadline=self._end-10)
        finally:
            outcome=getattr(owner,'_last',None)
            self._uncertain=(bool(getattr(owner,'_unsettled',False)) or
                             (outcome is not None and (not outcome.settled or bool(outcome.unreaped))))
        outcome=getattr(owner,'_last',None)
        if (type(streams) is not _Streams or outcome is None or not outcome.settled or
                outcome.unreaped or outcome.failure is not None or outcome.exit_code!=0):_fail('TOOL_FAILURE')
        if len(streams.stdout)+len(streams.stderr)>limits.output_bytes:_fail('OUTPUT_LIMIT')
        self._time()
        return streams

    def _cleanup(self):
        errors=False
        entry=self._scratch
        if entry is not None:
            try:
                self._validate_directory_routes()
                if self._uncertain or entry['fd'] is None or entry['identity'] is None:_fail('CLEANUP')
                named=os.stat(entry['name'],dir_fd=self._dirs['run'],follow_symlinks=False)
                held=os.fstat(entry['fd'])
                if identity(named)!=entry['identity'] or identity(held)!=entry['identity']:_fail('CLEANUP')
                if not stat.S_ISDIR(held.st_mode) or held.st_uid!=self.uid or stat.S_IMODE(held.st_mode)!=0o700:_fail('CLEANUP')
                names=os.listdir(entry['fd'])
                expected=[] if self._file is None else ['qshd.pp']
                if sorted(names)!=expected:_fail('CLEANUP')
                if self._file is not None:
                    self._bound(entry['fd'],'qshd.pp',self._file,state=True)
                    os.unlink('qshd.pp',dir_fd=entry['fd'])
                os.rmdir(entry['name'],dir_fd=self._dirs['run'])
            except BaseException:errors=True
        for fd in reversed(self._fds):
            try:os.close(fd)
            except BaseException:errors=True
        self._fds=[]
        try:_close_routes(self)
        except BaseException:errors=True
        if errors:_fail('CLEANUP')

    def install(self, *, deadline):
        if self._used:_fail('INSTALL_USED')
        self._used=True
        if type(deadline) not in (int,float) or not math.isfinite(deadline):_fail('DEADLINE')
        self._end=min(deadline,self._clock()+110)
        if self._end-self._clock()<=10:_fail('DEADLINE')
        try:
            try:
                self._admit();self._make_scratch()
                listing=self._command(_PREFIX+('-lfull',),_LIST)
                if any(row.name=='qshd' for row in parse_full_listing(listing.stdout)):_fail('MODULE_EXISTS')
                self._guard();self._active()
                path=str(self.anchor/'run'/self._scratch['name']/'qshd.pp')
                self._command(_PREFIX+('-X','400','-i',path),_INSTALL)
                self._active();self._guard()
            except (OSError,Conflict,ObserverError,ModuleError,_CommandError):
                raise InstallError('INSTALL_REFUSED') from None
        finally:self._cleanup()
        self._time()
        return InstallResult(self._trusted,self._trusted.pp_sha256)
