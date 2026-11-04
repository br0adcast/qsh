"""Finite retained-label restoration; unused until native erase qualification.

Caller owns maintenance exclusion, policy removal and the original hard owner.
Private contents are never read. Successful return requires normal scope exit.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import math
import os
from pathlib import Path
import stat
import sys
import time

from qshd_selinux_fs import SafeFiles, MAX_XATTRS
from qshd_selinux_api import SelinuxApi, _context

_CONFIG='system_u:object_r:qshd_config_t:s0'
_LOG='system_u:object_r:qshd_log_t:s0'
_RUNTIME='system_u:object_r:qshd_runtime_t:s0'
_ITEMS=(('/etc/qshd',stat.S_IFDIR,'directory',_CONFIG),
        ('/etc/qshd/host_key',stat.S_IFREG,'key',_CONFIG),
        ('/var/log/qshd',stat.S_IFDIR,'directory',_LOG),
        ('/var/log/qshd/qshd.log',stat.S_IFREG,'private',_LOG),
        ('/var/log/qshd/qshd.log.1',stat.S_IFREG,'private',_LOG),
        ('/run/qshd',stat.S_IFDIR,'runtime',_RUNTIME),
        ('/run/qshd/helper-status.sock.lock',stat.S_IFREG,'private',_RUNTIME))
_CHILDREN={'/etc/qshd':frozenset(('host_key',)),
           '/var/log/qshd':frozenset(('qshd.log','qshd.log.1')),
           '/run/qshd':frozenset(('helper-status.sock.lock',))}
_LABEL='security.selinux'
_NO_TOKEN=object()
_RAW_ROLES={'/etc/qshd':'CONFIG_DIR','/etc/qshd/host_key':'HOST_KEY',
            '/var/log/qshd':'LOG_DIR','/var/log/qshd/qshd.log':'LOG_CURRENT',
            '/var/log/qshd/qshd.log.1':'LOG_ROTATED','/run/qshd':'RUNTIME_DIR',
            '/run/qshd/helper-status.sock.lock':'STATUS_LOCK'}
_RAW_REASONS=frozenset(('ABSENT','INVALID_TYPE','OVERSIZE','UNLABELED_LITERAL','OTHER_BYTES'))


class RetainedLabelError(ValueError):
    """Fixed refusal category; no protected content or native diagnostic."""


class RetainedLabelRawError(RetainedLabelError):
    """Closed sampled-byte category; never raw bytes or a kernel-cause claim."""
    def __init__(self,role,reason):
        if (type(role) is not str or role not in _RAW_ROLES.values()
                or type(reason) is not str or reason not in _RAW_REASONS):_fail()
        super().__init__('RAW_LABEL_REFUSED',role,reason)


class RetainedLabelOutcomeUncertain(RetainedLabelError):
    """At least one label setter was attempted; no rollback is claimed."""


def _fail():raise RetainedLabelError('RETAINED_LABEL_REFUSED')


def _stat(value):
    return (value.st_dev,value.st_ino,value.st_uid,value.st_gid,value.st_mode,
            value.st_nlink,value.st_size,value.st_mtime_ns,value.st_ctime_ns)


@dataclass(frozen=True)
class RetainedPath:
    path: str
    present: bool
    metadata: tuple | None
    raw_label: bytes | None


@dataclass(frozen=True)
class RetainedLabelObservation:
    paths: tuple[RetainedPath, ...]
    alias: tuple


@dataclass(frozen=True)
class RestoredLabelObservation:
    paths: tuple[RetainedPath, ...]
    alias: tuple
    targets: tuple[tuple[str,str], ...]


def production():
    if os.geteuid()!=0:_fail()
    return RetainedLabels()


class RetainedLabels:
    def __init__(self,*,_root='/',_uid=0,_api_factory=SelinuxApi,_clock=time.monotonic,
                 _getxattr=os.getxattr,_listxattr=os.listxattr,_setxattr=os.setxattr):
        self._root=Path(_root);self._uid=_uid;self._api_factory=_api_factory
        self._clock=_clock;self._get=_getxattr;self._list=_listxattr;self._set=_setxattr
        self._used=False

    def managed_inspection(self,*,deadline):
        return self._borrowed(deadline,False)

    def pristine_install(self,*,deadline):
        return self._borrowed(deadline,True)

    @contextmanager
    def _borrowed(self,deadline,pristine):
        if self._used:_fail()
        self._used=True
        try:valid=type(deadline) in (int,float) and math.isfinite(deadline)
        except OverflowError:valid=False
        if not valid:_fail()
        scope=_PristineInstall(self,deadline) if pristine else _ManagedInspection(self,deadline)
        try:
            scope._setup()
            yield scope
            scope._finish()
        except BaseException as error:
            scope._state='failed'
            if scope._attempted:raise RetainedLabelOutcomeUncertain('RETAINED_LABEL_OUTCOME_UNCERTAIN') from None
            if not isinstance(error,Exception):raise
            raise RetainedLabelError('RETAINED_LABEL_REFUSED') from None
        finally:
            pending=sys.exc_info()[1]
            if scope._close():
                if pending is not None:pending.add_note('RETAINED_LABEL_CLEANUP_FAILED')
                elif scope._attempted:raise RetainedLabelOutcomeUncertain('RETAINED_LABEL_OUTCOME_UNCERTAIN') from None
                else:raise RetainedLabelError('RETAINED_LABEL_REFUSED') from None

    @contextmanager
    def inspection(self,*,deadline):
        if self._used:_fail()
        self._used=True
        try:valid=type(deadline) in (int,float) and math.isfinite(deadline)
        except OverflowError:valid=False
        if not valid:_fail()
        scope=_Inspection(self,deadline)
        try:
            scope._setup()
            yield scope
            scope._finish()
        except BaseException as error:
            scope._state='failed'
            if scope._attempted:raise RetainedLabelOutcomeUncertain('RETAINED_LABEL_OUTCOME_UNCERTAIN') from None
            if not isinstance(error,Exception):raise
            raise RetainedLabelError('RETAINED_LABEL_REFUSED') from None
        finally:
            pending=sys.exc_info()[1]
            if scope._close():
                if pending is not None:
                    pending.add_note('RETAINED_LABEL_CLEANUP_FAILED')
                elif scope._attempted:
                    raise RetainedLabelOutcomeUncertain('RETAINED_LABEL_OUTCOME_UNCERTAIN') from None
                else:
                    raise RetainedLabelError('RETAINED_LABEL_REFUSED') from None


class _Inspection(SafeFiles):
    def __init__(self,factory,deadline):
        self.anchor=factory._root;self.uid=factory._uid;self.anchors=[];self.routes=[]
        self.hook=lambda event:None
        self._factory=factory;self._end=deadline;self._fds=[];self._parents={};self._objects={}
        self._state='open';self._observed=None;self._restored=None;self._expected=None
        self._attempted=False;self._post=None;self._post_api=None

    def _check(self):
        if self._factory._clock()>=self._end:_fail()

    def _setup(self):
        self._check()
        for path in ('/etc','/var','/var/log','/run'):
            self._parents[path]=self._directory(self.anchor/path[1:]);self._check()

    def _alias(self):
        self._check();parent=self._parents['/var']
        before=os.stat('run',dir_fd=parent,follow_symlinks=False)
        if not stat.S_ISLNK(before.st_mode) or before.st_uid!=self.uid:_fail()
        text=os.readlink('run',dir_fd=parent)
        if text not in ('/run','../run'):_fail()
        after=os.stat('run',dir_fd=parent,follow_symlinks=False)
        if _stat(before)!=_stat(after):_fail()
        self._check();return (_stat(after),text)

    def _membership(self):
        self._check();self._validate_directory_routes()
        for path,allowed in _CHILDREN.items():
            fd=self._parents.get(path)
            if fd is None:continue
            count=0
            with os.scandir(fd) as entries:
                for item in entries:
                    count+=1
                    if count>2 or item.name not in allowed:_fail()
                    self._check()
        self._check()

    def _metadata(self,fd,parent,name,kind,role):
        self._check();before=os.fstat(fd);named=os.stat(name,dir_fd=parent,follow_symlinks=False)
        if (_stat(before)!=_stat(named) or stat.S_IFMT(before.st_mode)!=kind
                or before.st_uid!=self.uid or before.st_mode & 0o7000):_fail()
        mode=stat.S_IMODE(before.st_mode)
        if kind==stat.S_IFDIR:
            self._dir_mode(fd)
            if not mode & 0o100 or (role=='runtime' and mode!=0o700):_fail()
        else:
            self._bound(parent,name,fd)
            if (role=='key' and (mode not in (0o400,0o600) or before.st_size!=64)
                    or role=='private' and mode!=0o600):_fail()
        names=self._factory._list(fd);self._check()
        if len(names)>MAX_XATTRS or len(names)!=len(set(names)):_fail()
        attrs=[];total=0
        for key in sorted(names):
            if type(key) is not str or not 0<len(key)<=255:_fail()
            value=self._factory._get(fd,key);self._check()
            if type(value) is not bytes or len(value)>65536:_fail()
            total+=len(value)
            if total>8*1024**2:_fail()
            attrs.append((key,value))
        if _stat(before)!=_stat(os.fstat(fd)) or _stat(before)!=_stat(os.stat(name,dir_fd=parent,follow_symlinks=False)):_fail()
        return _stat(before)+(tuple(attrs),)

    @staticmethod
    def _raw(metadata,context,role):
        if type(role) is not str or role not in _RAW_ROLES.values():_fail()
        values=dict(metadata[-1]);raw=values.get(_LABEL)
        expected=context.encode('ascii')
        if type(raw) is not bytes or len(raw)>4096 or raw not in (expected,expected+b'\0'):
            if _LABEL not in values:reason='ABSENT'
            elif type(raw) is not bytes:reason='INVALID_TYPE'
            elif len(raw)>4096:reason='OVERSIZE'
            elif raw in (b'system_u:object_r:unlabeled_t:s0',b'system_u:object_r:unlabeled_t:s0\0'):
                reason='UNLABELED_LITERAL'
            else:reason='OTHER_BYTES'
            raise RetainedLabelRawError(role,reason)
        return raw

    def _sample(self,*,initial=False,api=None,targets=None):
        self._check();self._validate_directory_routes();alias=self._alias();result=[]
        for path,kind,role,managed in _ITEMS:
            self._check();parent_path,name=str(Path(path).parent),Path(path).name
            parent=self._parents[parent_path]
            if parent is None:
                result.append(RetainedPath(path,False,None,None));continue
            try:named=os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:
                if kind==stat.S_IFDIR:self._parents[path]=None
                result.append(RetainedPath(path,False,None,None));continue
            if initial:
                if kind==stat.S_IFDIR:
                    fd=self._directory(self.anchor/path[1:]);self._parents[path]=fd
                else:
                    fd=self._open(parent,name);self._fds.append(fd)
                self._objects[path]=fd
            else:
                if path not in self._objects:_fail()
                fd=self._objects[path]
            before=self._metadata(fd,parent,name,kind,role)
            context=(targets(path,kind,managed) if callable(targets) else targets[path]) if targets is not None else managed
            raw=self._raw(before,context,_RAW_ROLES[path])
            if api is not None:
                if api.file_context(fd)!=context:_fail()
                self._check()
            after=self._metadata(fd,parent,name,kind,role)
            if before!=after:_fail()
            result.append(RetainedPath(path,True,after,raw))
        self._membership();self._check()
        return tuple(result),alias

    def _operation(self,required,token=_NO_TOKEN):
        self._check()
        if self._state!=required or (token is not _NO_TOKEN and token is not self._observed):_fail()
        self._state='failed'

    @contextmanager
    def _errors(self):
        try:yield
        except BaseException as error:
            self._state='failed'
            if self._attempted:raise RetainedLabelOutcomeUncertain('RETAINED_LABEL_OUTCOME_UNCERTAIN') from None
            if not isinstance(error,Exception):raise
            raise RetainedLabelError('RETAINED_LABEL_REFUSED') from None

    def _old(self,*,initial=False):
        api=self._factory._api_factory();self._check()
        with api.status_observation():
            self._check()
            with api.file_defaults() as defaults:
                paths,alias=self._sample(initial=initial,api=api)
                for item in paths:
                    if item.present:
                        path,kind,role,managed=next(row for row in _ITEMS if row[0]==item.path)
                        if defaults.lookup(path,kind)!=managed:_fail()
                        self._check()
            self._check()
        self._check();return RetainedLabelObservation(paths,alias)

    def capture(self):
        with self._errors():
            self._operation('open');value=self._old(initial=True)
            self._observed=value;self._expected=value;self._state='captured';return value

    def recheck_before_removal(self,observation):
        with self._errors():
            self._operation('captured',observation)
            if self._old()!=observation:_fail()
            self._state='checked-before'

    def _targets(self,api,paths):
        result={}
        with api.file_defaults() as defaults:
            for item in paths:
                if not item.present:continue
                self._check();kind=next(row[1] for row in _ITEMS if row[0]==item.path)
                target=defaults.lookup(item.path,kind);raw=_context(target)
                if raw.decode('ascii').split(':',3)[2].startswith('qshd_'):_fail()
                api.check_context(target);self._check();result[item.path]=target
        self._check();return result

    @staticmethod
    def _preserved(before,after):
        # Only ctime and security.selinux may change; bytes are never read/written.
        return (before[:-2]==after[:-2]
                and tuple(pair for pair in before[-1] if pair[0]!=_LABEL)
                ==tuple(pair for pair in after[-1] if pair[0]!=_LABEL))

    def restore_defaults(self,observation):
        with self._errors():
            self._operation('checked-before',observation);self._state='restoring'
            api=self._factory._api_factory();self._check();self._post_api=api
            post=api.status_observation();post.__enter__();self._post=post;self._check()
            paths,alias=self._sample()
            if RetainedLabelObservation(paths,alias)!=observation:_fail()
            targets=self._targets(api,paths)
            current=observation
            active_targets={item.path:next(row[3] for row in _ITEMS if row[0]==item.path)
                            for item in paths if item.present}
            for index,item in enumerate(paths):
                if not item.present:continue
                if RetainedLabelObservation(*self._sample(targets=active_targets))!=current:_fail()
                self._check();self._attempted=True
                fd=self._objects[item.path]
                self._factory._set(fd,_LABEL,targets[item.path].encode('ascii')+b'\0',os.XATTR_REPLACE)
                self._check()
                parent=self._parents[str(Path(item.path).parent)];name=Path(item.path).name
                kind,role=next((row[1],row[2]) for row in _ITEMS if row[0]==item.path)
                updated=self._metadata(fd,parent,name,kind,role)
                raw=self._raw(updated,targets[item.path],_RAW_ROLES[item.path])
                if not self._preserved(item.metadata,updated) or api.file_context(fd)!=targets[item.path]:_fail()
                self._check();os.fsync(fd);self._check()
                if self._metadata(fd,parent,name,kind,role)!=updated:_fail()
                new_item=RetainedPath(item.path,True,updated,raw)
                current=RetainedLabelObservation(current.paths[:index]+(new_item,)+current.paths[index+1:],alias)
                self._expected=current;active_targets[item.path]=targets[item.path]
            self._check();result=RestoredLabelObservation(current.paths,alias,tuple(targets.items()))
            self._restored=result;self._expected=result;self._state='restored';return result

    def recheck_restored(self,restored):
        with self._errors():
            self._check()
            if self._state!='restored' or restored is not self._restored:_fail()
            self._state='failed';targets=dict(restored.targets)
            if self._targets(self._post_api,restored.paths)!=targets:_fail()
            if self._sample(api=self._post_api,targets=targets)!=(restored.paths,restored.alias):_fail()
            post=self._post;self._post=None;post.__exit__(None,None,None);self._check()
            self._state='checked-after'

    def _finish(self):
        with self._errors():
            self._check()
            if self._state!='checked-after':_fail()
            if self._sample(targets=dict(self._restored.targets))!=(self._restored.paths,self._restored.alias):_fail()
            self._check()

    def _close(self):
        failure=False
        if self._post is not None:
            post=self._post;self._post=None
            try:post.__exit__(RetainedLabelError,RetainedLabelError('REFUSED'),None)
            except BaseException:failure=True
        self._state='closed'
        descriptors=list(dict.fromkeys(self._fds+self.anchors+[row[2] for row in self.routes]))
        self._fds=[];self.anchors=[];self.routes=[]
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException:failure=True
        try:self._check()
        except BaseException:failure=True
        self._cleanup_failed=failure
        return failure


class _ManagedInspection(_Inspection):
    """Held finite descriptors; native status custody belongs only to the caller."""
    def __init__(self,factory,deadline):
        super().__init__(factory,deadline)
        self._status=None;self._final_status=None;self._current_targets=None

    def _borrow(self,status):
        from qshd_selinux_api import _StatusToken
        if type(status) is not _StatusToken:_fail()
        api=status.require_open();self._check()
        return api

    def _read(self,status,*,initial=False,pristine=False):
        api=self._borrow(status);targets={}
        with api.file_defaults() as defaults:
            def target(path,kind,managed):
                value=defaults.lookup(path,kind);raw=_context(value)
                name=raw.decode('ascii').split(':',3)[2]
                if pristine:
                    if name.startswith('qshd_') or name=='unlabeled_t':_fail()
                elif value!=managed:_fail()
                api.check_context(value);self._check();targets[path]=value
                return value
            paths,alias=self._sample(initial=initial,api=api,targets=target)
        if self._borrow(status) is not api:_fail()
        return RetainedLabelObservation(paths,alias),targets

    def capture(self,*,status):
        with self._errors():
            self._operation('open')
            value,targets=self._read(status,initial=True)
            self._observed=value;self._expected=value;self._current_targets=targets
            self._state='captured';return value

    def recheck(self,token,*,status):
        with self._errors():
            if self._state not in ('captured','checked') or token is not self._observed:_fail()
            self._state='failed'
            value,targets=self._read(status)
            if value!=token or targets!=self._current_targets:_fail()
            self._final_status=status;self._state='checked'

    def _finish(self):
        with self._errors():
            if self._state!='checked' or self._final_status is None:_fail()
            self._final_status.require_closed()
            if self._sample(targets=self._current_targets)!=(self._expected.paths,self._expected.alias):_fail()
            self._check()


class _PristineInstall(_ManagedInspection):
    """Finite default-to-managed transition with complete target admission first."""
    def capture_defaults(self,*,status):
        with self._errors():
            self._operation('open')
            value,targets=self._read(status,initial=True,pristine=True)
            self._observed=value;self._expected=value;self._current_targets=targets
            self._state='pristine';return value

    def recheck_defaults(self,token,*,status):
        with self._errors():
            if self._state not in ('pristine','pristine-checked') or token is not self._observed:_fail()
            self._state='failed'
            value,targets=self._read(status,pristine=True)
            if value!=token or targets!=self._current_targets:_fail()
            self._status=status;self._state='pristine-checked'

    def apply_managed(self,token,*,status):
        with self._errors():
            self._operation('pristine-checked',token)
            self._status.require_closed();api=self._borrow(status)
            paths,alias=self._sample(api=api,targets=self._current_targets)
            if (paths,alias)!=(token.paths,token.alias):_fail()
            targets={}
            # Admit the entire target vector before the first setter attempt.
            with api.file_defaults() as defaults:
                for item in paths:
                    if not item.present:continue
                    kind,managed=next((row[1],row[3]) for row in _ITEMS if row[0]==item.path)
                    target=defaults.lookup(item.path,kind)
                    if target!=managed:_fail()
                    _context(target);api.check_context(target);self._check();targets[item.path]=target
            self._borrow(status)
            active=dict(self._current_targets);current=token
            for index,item in enumerate(paths):
                if not item.present:continue
                if self._sample(api=api,targets=active)!=(current.paths,current.alias):_fail()
                self._borrow(status);self._attempted=True
                fd=self._objects[item.path]
                self._factory._set(fd,_LABEL,targets[item.path].encode('ascii')+b'\0',os.XATTR_REPLACE)
                self._check()
                parent=self._parents[str(Path(item.path).parent)];name=Path(item.path).name
                kind,role=next((row[1],row[2]) for row in _ITEMS if row[0]==item.path)
                updated=self._metadata(fd,parent,name,kind,role)
                raw=self._raw(updated,targets[item.path],_RAW_ROLES[item.path])
                if not self._preserved(item.metadata,updated) or api.file_context(fd)!=targets[item.path]:_fail()
                os.fsync(fd);self._check()
                if self._metadata(fd,parent,name,kind,role)!=updated:_fail()
                replacement=RetainedPath(item.path,True,updated,raw)
                current=RetainedLabelObservation(current.paths[:index]+(replacement,)+current.paths[index+1:],alias)
                active[item.path]=targets[item.path]
            self._borrow(status)
            result=RestoredLabelObservation(current.paths,alias,tuple(targets.items()))
            self._restored=result;self._expected=result;self._current_targets=targets
            self._state='managed';return result

    def recheck_managed(self,result,*,status):
        with self._errors():
            if self._state not in ('managed','checked') or result is not self._restored:_fail()
            self._state='failed'
            value,targets=self._read(status)
            if (value.paths,value.alias)!=(result.paths,result.alias) or targets!=self._current_targets:_fail()
            self._final_status=status;self._state='checked'
