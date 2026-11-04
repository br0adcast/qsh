"""Strict install/reload and distinct exact-owned removal; none proves readiness.

Trusted caller holds package exclusion, has stopped/drained service with the
administrator stop guard, and has published fresh durable PENDING. No automatic
adoption, arbitrary update, rollback, COMPLETE publication or hooks.
Removal returns only normal completion and finite all-priority absence evidence.
An outer fresh process must impose the hard wall deadline on filesystem calls.
"""
from dataclasses import dataclass
from contextlib import ExitStack
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
from qshd_selinux_module_observer import (
    _protected_file, _store_readlock, ObserverError, production_observer)
from qshd_selinux_process import _Owner, _Limits, _CommandError, _Streams, _normal_outcome

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
    core_pp_sha256: str
    contexts_pp_sha256: str


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


def production_installer(trusted_artifact,core_pp_bytes,contexts_pp_bytes):
    if os.geteuid()!=0:_fail('ROOT_REQUIRED')
    return FirstInstall(trusted_artifact,core_pp_bytes,contexts_pp_bytes)


class _InstallFiles(SafeFiles):
    """Single use; underscored injection is only for trusted disposable tests."""
    def __init__(self,trusted_artifact,core_pp_bytes,contexts_pp_bytes,*,_root=None,_uid=0,
                 _owner=None, _clock=time.monotonic):
        if type(trusted_artifact) is not TrustedArtifact:_fail('TRUSTED_ARTIFACT')
        try:trusted_artifact.__post_init__()
        except ActivationError:raise InstallError('TRUSTED_ARTIFACT') from None
        self._pp={}
        for role,data,digest in (('core',core_pp_bytes,trusted_artifact.core_pp_sha256),
                                  ('contexts',contexts_pp_bytes,trusted_artifact.contexts_pp_sha256)):
            if type(data) is not bytes or not 0<len(data)<=MAX_HLL:_fail('PP_INPUT')
            if hashlib.sha256(data).hexdigest()!=digest:_fail('PP_IDENTITY')
            self._pp[role]=data
        self._trusted=TrustedArtifact(trusted_artifact.provider_version,trusted_artifact.manifest_sha256,
                                      trusted_artifact.core_pp_sha256,trusted_artifact.contexts_pp_sha256)
        self.anchor=Path('/') if _root is None else Path(_root)
        if not self.anchor.is_absolute():_fail('ANCHOR')
        self.uid=_uid;self.hook=lambda event:None
        self.anchors=[];self.routes=[];self._fds=[];self._dirs={};self._files={}
        self._injected=_owner;self._owner=None;self._clock=_clock;self._used=False
        self._scratch=None;self._file={};self._uncertain=False

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
        for role,fd in self._file.items():
            name='qshd.pp' if role=='core' else 'qshd_contexts.pp'
            self._bound(self._scratch['fd'],name,fd,state=True)
            value=self._read(self._scratch['fd'],name,state=True,limit=MAX_HLL)
            if value['data']!=self._pp[role]:_fail('PP_DRIFT')
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
        for role,name in (('core','qshd.pp'),('contexts','qshd_contexts.pp')):
            leaf=os.open(name,os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=fd)
            self._fds.append(leaf);self._file[role]=leaf
            self._bound(fd,name,leaf);os.fchmod(leaf,0o600)
            view=memoryview(self._pp[role])
            while view:
                written=os.write(leaf,view)
                if written<=0:_fail('PP_WRITE')
                view=view[written:];self._time()
            os.fsync(leaf);self._guard()
        os.fsync(fd);self._guard()

    def _command(self,argv,limits,*,reserve,cwd=None):
        self._guard()
        if self._clock()+reserve>=self._end:_fail('DEADLINE')
        owner=self._injected if self._injected is not None else _Owner(limits)
        self._owner=owner
        if self._clock()+reserve>=self._end:_fail('DEADLINE')
        try:
            directory=cwd if cwd is not None else self.anchor/'run'/self._scratch['name']
            streams=owner._run(argv,directory,deadline=self._end-10)
        finally:
            outcome=getattr(owner,'_last',None)
            self._uncertain=(bool(getattr(owner,'_unsettled',False)) or
                             (outcome is not None and (not outcome.settled or bool(outcome.unreaped))))
        outcome=getattr(owner,'_last',None)
        if (type(streams) is not _Streams or type(streams.stdout) is not bytes or type(streams.stderr) is not bytes
                or not _normal_outcome(outcome) or outcome.exit_code!=0):_fail('TOOL_FAILURE')
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
                expected=['qshd.pp' if role=='core' else 'qshd_contexts.pp' for role in self._file]
                if sorted(names)!=sorted(expected):_fail('CLEANUP')
                for role,fd in self._file.items():
                    name='qshd.pp' if role=='core' else 'qshd_contexts.pp'
                    self._bound(entry['fd'],name,fd,state=True)
                for name in expected:os.unlink(name,dir_fd=entry['fd'])
                os.rmdir(entry['name'],dir_fd=self._dirs['run'])
            except BaseException:errors=True
        for fd in reversed(self._fds):
            try:os.close(fd)
            except BaseException:errors=True
        self._fds=[]
        try:_close_routes(self)
        except BaseException:errors=True
        if errors:_fail('CLEANUP')


def _finite_deadline(value):
    try:return type(value) in (int,float) and math.isfinite(value)
    except OverflowError:return False


class FirstInstall(_InstallFiles):
    """Both names absent at all priorities; one authenticated pair install."""
    def install(self,*,deadline):
        if self._used:_fail('INSTALL_USED')
        self._used=True
        if not _finite_deadline(deadline):_fail('DEADLINE')
        self._end=deadline
        # list15 + load75 + subsequent pair90 + local40 + closure10.
        if self._clock()+230>=self._end:_fail('DEADLINE')
        try:
            try:
                self._admit();self._make_scratch()
                listing=self._command(_PREFIX+('-lfull',),_LIST,reserve=230)
                if any(x.name in ('qshd','qshd_contexts') for x in parse_full_listing(listing.stdout)):_fail('MODULE_EXISTS')
                self._guard();self._active()
                paths=tuple(str(self.anchor/'run'/self._scratch['name']/name) for name in ('qshd.pp','qshd_contexts.pp'))
                self._command(_PREFIX+('-X','400','-i')+paths,_INSTALL,reserve=215)
                self._active();self._guard()
            except (OSError,Conflict,ObserverError,ModuleError,_CommandError) as error:
                raise InstallError('INSTALL_REFUSED') from error
        finally:self._cleanup()
        self._time()
        return InstallResult(self._trusted,self._trusted.core_pp_sha256,self._trusted.contexts_pp_sha256)


class _DeadlineOwner:
    """Keep an existing command owner inside its caller's original end."""
    def __init__(self,owner,deadline):self._owner=owner;self._deadline=deadline
    @property
    def _last(self):return self._owner._last
    def _run(self,operation,cwd,*,deadline=None):
        end=self._deadline if deadline is None else min(self._deadline,deadline)
        return self._owner._run(operation,cwd,deadline=end)


def production_owned_reloader(owned_artifact,incoming_artifact,core_pp_bytes,contexts_pp_bytes):
    if os.geteuid()!=0:_fail('ROOT_REQUIRED')
    return OwnedReload(owned_artifact,incoming_artifact,core_pp_bytes,contexts_pp_bytes)


class OwnedReload(_InstallFiles):
    """Independently admit old pair A, then install exact incoming pair B once."""
    def __init__(self,owned_artifact,incoming_artifact,core_pp_bytes,contexts_pp_bytes,*,
                 _root=None,_uid=0,_owner=None,_clock=time.monotonic,_observer=None):
        super().__init__(incoming_artifact,core_pp_bytes,contexts_pp_bytes,_root=_root,_uid=_uid,_owner=_owner,_clock=_clock)
        if type(owned_artifact) is not TrustedArtifact:_fail('TRUSTED_ARTIFACT')
        owned_artifact.__post_init__();self._owned=owned_artifact
        self._observer=production_observer if _observer is None else _observer

    def reload(self,*,deadline):
        from qshd_selinux_api import SelinuxApi, SelinuxError
        if self._used:_fail('RELOAD_USED')
        self._used=True
        if not _finite_deadline(deadline):_fail('DEADLINE')
        self._end=deadline
        # Admission pair90 + load75 + subsequent pair90 + local40 + close10.
        if self._clock()+305>=self._end:_fail('DEADLINE')
        try:
            try:
                self._admit()
                with self._observer(self._owned,mode='pair',deadline=self._end) as observer:
                    with SelinuxApi().status_observation():
                        observed=observer.capture();self._time();observer.recheck(observed);self._time()
                self._time();self._guard();self._active();self._make_scratch()
                paths=tuple(str(self.anchor/'run'/self._scratch['name']/name) for name in ('qshd.pp','qshd_contexts.pp'))
                self._command(_PREFIX+('-X','400','-i')+paths,_INSTALL,reserve=215)
                self._active();self._guard()
            except (OSError,Conflict,ObserverError,ModuleError,_CommandError,SelinuxError) as error:
                raise InstallError('RELOAD_REFUSED') from error
        finally:self._cleanup()
        self._time()
        return InstallResult(self._trusted,self._trusted.core_pp_sha256,self._trusted.contexts_pp_sha256)


class _Admission:
    __slots__=()
    def __reduce__(self):raise TypeError('nonserializable admission')


class _RestorationAdmission(_Admission):
    __slots__=()


# Exactly the module portion of the reviewed20-call erase schedule.
_ERASE=(('list',15),('extract-core',15),('extract-contexts',15))*2+(('remove-contexts',75),)+(('list',15),('extract-core',15))*2+(('remove-core',75),)+(('list',15),)*2


class _CountedOwner:
    def __init__(self,session,owner):self.session=session;self.owner=owner
    @property
    def _last(self):return self.owner._last
    def _run(self,operation,cwd,*,deadline):
        self.session._ticket(operation)
        return self.owner._run(operation,cwd,deadline=deadline)


class _RemovalObservation:
    def __init__(self,session,mode):
        self._session=session;self._mode=mode;self._stack=ExitStack()
        self._token=None;self._restored=None;self._checked=False;self._closed=False;self._ready=False;self._restoration_attempted=False
    def __enter__(self):
        s=self._session
        if s._live is not None or s._phase!={'pair':'new','core-only':'contexts-removed','absent':'core-removed'}[self._mode]:s._poison();_fail('SESSION_ORDER')
        s._live=self
        try:
            s._time()
            self._observer=self._stack.enter_context(s._observer(s._trusted,mode=self._mode,deadline=s._end))
            if self._observer._owner is not None:
                self._observer._owner=_CountedOwner(s,self._observer._owner)
            else:
                original=self._observer._injected
                def counted(operation,cwd,*,deadline):
                    s._ticket(operation)
                    return original(operation,cwd,deadline=deadline)
                self._observer._injected=counted
            self._status_token=self._stack.enter_context(s._window())
            s._time();return self
        except BaseException:
            s._poison();self._stack.__exit__(*__import__('sys').exc_info());raise
    @property
    def status_token(self):
        s=self._session
        if self._closed or s._live is not self or s._phase=='failed':
            s._poison();_fail('ADMISSION_TOKEN')
        return self._status_token
    def capture(self):
        s=self._session
        if self._closed or s._phase=='failed' or self._token is not None or s._live is not self:s._poison();_fail('ADMISSION_TOKEN')
        try:
            s._time();self._observed=self._observer.capture();s._time()
            self._token=_Admission();return self._token
        except BaseException:s._poison();raise
    def recheck(self,token):
        s=self._session
        if self._closed or s._phase=='failed' or type(token) is not _Admission or token is not self._token or self._checked or s._live is not self:s._poison();_fail('ADMISSION_TOKEN')
        try:
            s._time();self._observer.recheck(self._observed);s._time();self._checked=True
        except BaseException:s._poison();raise
    def recheck_restoration(self,token,check_restored):
        s=self._session
        if (self._closed or s._phase=='failed' or self._restoration_attempted or self._mode!='core-only' or s._live is not self or token is not self._token
                or not self._checked or self._restored is not None or not callable(check_restored)):
            s._poison();_fail('RESTORATION_ADMISSION')
        self._restoration_attempted=True
        try:
            s._time()
            if check_restored() is not None:_fail('RESTORATION_ADMISSION')
            s._time();self._restored=_RestorationAdmission();return self._restored
        except BaseException:s._poison();raise
    def __exit__(self,kind,value,traceback):
        s=self._session
        if self._closed:s._poison();_fail('ADMISSION_TOKEN')
        self._closed=True
        try:
            try:
                if kind is None:
                    s._time()
                    if not self._checked:_fail('FINAL_RECHECK_REQUIRED')
                    if self._mode=='core-only' and self._restored is None:_fail('RESTORATION_ADMISSION')
            except BaseException:
                self._stack.__exit__(*__import__('sys').exc_info());raise
            self._stack.__exit__(kind,value,traceback)
            if kind is not None:s._poison();return False
            s._time()
            if s._phase=='failed':_fail('SESSION_FAILED')
            self._ready=True;s._admitted=self;s._phase={'pair':'pair-ready','core-only':'core-ready','absent':'absent-ready'}[self._mode]
        except BaseException:s._poison();raise
        finally:s._live=None
        return False


def production_removal_session(trusted_artifact,core_pp_bytes,contexts_pp_bytes,*,deadline):
    if os.geteuid()!=0:_fail('ROOT_REQUIRED')
    return PairRemovalSession(trusted_artifact,core_pp_bytes,contexts_pp_bytes,deadline=deadline)


class PairRemovalSession(_InstallFiles):
    """Continuous trusted erase coordinator custody, never a complete erasure."""
    def __init__(self,trusted_artifact,core_pp_bytes,contexts_pp_bytes,*,deadline,
                 _root=None,_uid=0,_owner=None,_clock=time.monotonic,_observer=None,_window=None):
        super().__init__(trusted_artifact,core_pp_bytes,contexts_pp_bytes,_root=_root,_uid=_uid,_owner=_owner,_clock=_clock)
        if not _finite_deadline(deadline):_fail('DEADLINE')
        self._end=deadline;self._phase='new';self._index=0;self._live=None;self._admitted=None
        self._observer=production_observer if _observer is None else _observer
        if _window is None:
            def window():
                from qshd_selinux_api import SelinuxApi
                return SelinuxApi().status_observation()
            self._window=window
        else:self._window=_window
    def _poison(self):self._phase='failed'
    def _ticket(self,operation):
        if self._phase=='failed' or self._index>=len(_ERASE) or operation!=_ERASE[self._index][0]:self._poison();_fail('COMMAND_BUDGET')
        reserve=sum(x[1] for x in _ERASE[self._index:])+50
        if self._clock()+reserve>=self._end:self._poison();_fail('DEADLINE')
        self._index+=1
    def __enter__(self):
        if self._used:_fail('SESSION_USED')
        self._used=True
        try:
            if self._clock()+380>=self._end:_fail('DEADLINE')
            self._admit();return self
        except BaseException:self._poison();self._cleanup();raise
    def observation(self,mode):
        if type(mode) is not str or mode not in ('pair','core-only','absent'):self._poison();_fail('MODE')
        if not self._used or self._phase=='failed':_fail('SESSION_ORDER')
        return _RemovalObservation(self,mode)
    def _remove(self,role,token,restored=None):
        scope=self._admitted;expected='pair-ready' if role=='contexts' else 'core-ready'
        if (self._phase!=expected or self._live is not None or scope is None or not scope._ready
                or token is not scope._token or type(token) is not _Admission
                or role=='core' and (restored is not scope._restored or type(restored) is not _RestorationAdmission)):
            self._poison();_fail('ADMISSION_TOKEN')
        self._phase='mutating';scope._ready=False
        try:
            self._guard();self._active();self._ticket('remove-'+role)
            name='qshd_contexts' if role=='contexts' else 'qshd'
            self._command(_PREFIX+('-X','400','-r',name),_INSTALL,reserve=75+sum(x[1] for x in _ERASE[self._index:])+50,cwd='/')
            self._active();self._guard();self._phase='contexts-removed' if role=='contexts' else 'core-removed'
        except BaseException:self._poison();raise
    def remove_contexts(self,admitted_pair):self._remove('contexts',admitted_pair)
    def remove_core(self,admitted_core,restored_token):self._remove('core',admitted_core,restored_token)
    def __exit__(self,kind,value,traceback):
        try:
            if kind is None:
                self._time()
                if self._phase!='absent-ready' or self._index!=14 or self._live is not None:_fail('SESSION_INCOMPLETE')
        finally:
            self._poison()
            try:
                if self._live is not None:self._live.__exit__(InstallError,InstallError('SESSION_INCOMPLETE'),None)
            finally:self._cleanup()
        self._time();return False
