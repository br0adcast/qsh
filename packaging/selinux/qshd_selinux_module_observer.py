"""Bounded selected-store PP evidence for a cooperating Fedora44 verifier.

Use production_observer only in a fresh resource-bounded process, under package
exclusion and inside the caller's single native status window. Accept evidence
only after final recheck, normal status exit and normal observer cleanup. This
neither authenticates loaded kernel policy nor establishes complete readiness.
Fixed path/mode gates still require supported-platform runtime qualification.
"""
import hashlib
import os
from pathlib import Path
import secrets
import stat
import math
import time
from dataclasses import dataclass

from qshd_selinux_activation import TrustedArtifact
from qshd_selinux_fs import SafeFiles, Conflict
from qshd_selinux_modules import ModuleEntry, HllIdentity, ModuleError, parse_full_listing, select_owned, verify_hll, MAX_HLL
from qshd_selinux_process import _CommandError, _Limits, _Owner, _Streams, _normal_outcome


_LIMITS = _Limits(15, 1024 * 1024)
_PREFIX = ('/usr/bin/semodule', '--store-path', '/var/lib/selinux', '-s', 'targeted')
_COMMANDS = {'list': _PREFIX + ('-lfull',),
             'extract-core': _PREFIX + ('-X', '400', '--hll', '-E', 'qshd'),
             'extract-contexts': _PREFIX + ('-X','400','--hll','-E','qshd_contexts')}


class _SemoduleOwner:
    """Only the future trusted observer selects these two fixed operations."""

    def __init__(self,mode='pair'):
        if type(mode) is not str or mode not in ('pair','core-only','absent'):raise _CommandError('COMMAND_KIND')
        self._mode=mode
        self._budget={'pair':6,'core-only':4,'absent':2}[mode]
        self._owner = _Owner(_LIMITS)
        self._calls = 0

    @property
    def _last(self):
        return self._owner._last

    def _run(self, operation, cwd, *, deadline=None):
        if type(operation) is not str or operation not in _COMMANDS:
            raise _CommandError('COMMAND_KIND')
        if operation!='list' and (self._mode=='absent' or self._mode=='core-only' and operation=='extract-contexts'):
            raise _CommandError('COMMAND_KIND')
        if self._calls >= self._budget:
            raise _CommandError('COMMAND_BUDGET')
        self._calls += 1
        streams = self._owner._run(_COMMANDS[operation], cwd, deadline=deadline)
        if (type(streams) is not _Streams or type(streams.stdout) is not bytes or type(streams.stderr) is not bytes
                or not _normal_outcome(self._last) or self._last.exit_code!=0):raise _CommandError('COMMAND_CUSTODY')
        if streams.stderr:
            raise _CommandError('COMMAND_STDERR')
        output = streams.stdout
        if operation != 'list' and output:
            raise _CommandError('COMMAND_OUTPUT')
        return output


class ObserverError(ValueError):
    """Bounded observation/cleanup refusal without raw paths or command output."""


def _fail(code):
    raise ObserverError(code)


def _frozen(value):
    if isinstance(value, dict):
        return tuple((key, _frozen(item)) for key, item in sorted(value.items()))
    if isinstance(value, list):
        return tuple(map(_frozen, value))
    return value


def _protected_file(files, parent, name, limit, *, mode=None, executable=False):
    value = files._read(parent, name, limit=limit)
    if value['mode'] & 0o022 or (mode is not None and value['mode'] != mode):
        _fail('PROTECTED_MODE')
    if executable and not value['mode'] & 0o100:
        _fail('EXECUTABLE_MODE')
    return value

def _store_readlock(files, store):
    value = _protected_file(files, store, 'semanage.read.LOCK', 0, mode=0o600)
    return _frozen({key: value[key] for key in ('inode','uid','gid','mode','xattrs')})


@dataclass(frozen=True)
class ModuleComponent:
    entry: ModuleEntry
    hll: HllIdentity


@dataclass(frozen=True)
class ModuleObservation:
    mode: str
    core: ModuleComponent | None
    contexts: ModuleComponent | None
    artifact: TrustedArtifact
    bindings: tuple


def production_observer(trusted_artifact,*,mode='pair',deadline):
    """Caller supplies independent pair authority and original absolute end."""
    if os.geteuid()!=0:_fail('ROOT_REQUIRED')
    return ModuleObserver(trusted_artifact,mode=mode,deadline=deadline)


def _testing_observer(trusted_artifact,root,runner,*,mode='pair',deadline=None,_clock=time.monotonic):
    if deadline is None:deadline=_clock()+110
    return ModuleObserver(trusted_artifact,mode=mode,deadline=deadline,_root=root,_runner=runner,_uid=os.getuid(),_clock=_clock)


class ModuleObserver(SafeFiles):
    """One capture and one recheck; all failures permanently invalidate a lease.

    Underscored injection arguments are exclusively for trusted disposable tests.
    Construct production callers through production_observer.
    """

    def __init__(self,trusted_artifact,*,mode='pair',deadline,_root=None,_runner=None,_uid=0,_clock=time.monotonic):
        if type(trusted_artifact) is not TrustedArtifact:
            _fail('TRUSTED_ARTIFACT')
        trusted_artifact.__post_init__()
        self._trusted = TrustedArtifact(trusted_artifact.provider_version,
                                       trusted_artifact.manifest_sha256,
                                       trusted_artifact.core_pp_sha256,trusted_artifact.contexts_pp_sha256)
        if type(mode) is not str or mode not in ('pair','core-only','absent'):_fail('MODE')
        try:finite=type(deadline) in (int,float) and math.isfinite(deadline)
        except OverflowError:finite=False
        if not finite:_fail('DEADLINE')
        self._mode=mode;self._end=deadline;self._clock=_clock;self._calls=0
        self._budget={'pair':6,'core-only':4,'absent':2}[mode]
        self.anchor = Path('/') if _root is None else Path(_root)
        if not self.anchor.is_absolute():
            _fail('ANCHOR')
        self.uid = _uid
        self.anchors, self.routes = [], []
        self.hook = lambda event: None
        self._injected = _runner
        self._owner = None
        self._state = 'new'
        self._closed = False
        self._observation = None
        self._files = {}
        self._dirs = {}
        self._scratch = []
        self._output = []
        self._acquired = []

    def _time(self):
        if self._clock()>=self._end:_fail('DEADLINE')

    def _protected(self, parent, name, limit, *, mode=None, executable=False):
        return _protected_file(self, parent, name, limit, mode=mode, executable=executable)

    def __enter__(self):
        if self._state != 'new':
            _fail('LEASE_STATE')
        self._state = 'failed'
        try:
            self._time()
            for key, relative in (('bin','usr/bin'), ('config','etc/selinux'),
                                  ('store','var/lib/selinux/targeted'),
                                  ('active','var/lib/selinux/targeted/active'),
                                  ('modules','var/lib/selinux/targeted/active/modules'),
                                  ('run','run')):
                self._dirs[key] = self._directory(self.anchor / relative)
            self._files['executable'] = self._protected(self._dirs['bin'], 'semodule', MAX_HLL, executable=True)
            self._files['config'] = self._protected(self._dirs['config'], 'semanage.conf', 65536)
            self._lock = self._lock_snapshot()
            if self._injected is None:
                self._dirs['platform'] = self._directory(Path('/usr/lib'))
                self._files['platform'] = self._protected(self._dirs['platform'], 'os-release', 8192)
                release = self._files['platform']['data']
                fields = release.splitlines()
                if ([line for line in fields if line.startswith(b'ID=')] != [b'ID=fedora']
                        or [line for line in fields if line.startswith(b'VERSION_ID=')] != [b'VERSION_ID=44']):
                    _fail('PLATFORM')
                self._owner = _SemoduleOwner(self._mode)
            self._guard()
            self._new_scratch(self._dirs['run'], 'qshd-module-' + secrets.token_hex(16))
            self._work = self._scratch[0][2]
            self._state = 'open'
            return self
        except BaseException as error:
            self._close()
            if isinstance(error, (OSError, Conflict, ModuleError, _CommandError)):
                raise ObserverError('ADMISSION') from None
            raise

    def _lock_snapshot(self):
        return _store_readlock(self, self._dirs['store'])

    def _guard(self):
        self._time()
        self._validate_directory_routes()
        specs = [('executable','bin','semodule',MAX_HLL),
                 ('config','config','semanage.conf',65536)]
        if 'platform' in self._files:
            specs.append(('platform','platform','os-release',8192))
        for key, parent, name, bound in specs:
            current = self._protected(self._dirs[parent], name, bound, executable=key=='executable')
            if not self._same(current, self._files[key], times=True):
                _fail('INPUT_DRIFT')
        if self._lock_snapshot() != self._lock:
            _fail('LOCK_DRIFT')
        for parent, name, fd, path in self._scratch:
            current = os.stat(name, dir_fd=parent, follow_symlinks=False)
            held = os.fstat(fd)
            if ((current.st_dev,current.st_ino) != (held.st_dev,held.st_ino)
                    or not stat.S_ISDIR(current.st_mode)
                    or current.st_uid != self.uid or stat.S_IMODE(current.st_mode) != 0o700):
                _fail('SCRATCH_BINDING')

    def _new_scratch(self, parent, name):
        os.mkdir(name, 0o700, dir_fd=parent)
        # Record the created identity before later admission can fail.
        made = os.stat(name, dir_fd=parent, follow_symlinks=False)
        try:
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        except BaseException:
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if (made.st_dev,made.st_ino) != (named.st_dev,named.st_ino):
                _fail('CLEANUP_BINDING')
            os.rmdir(name,dir_fd=parent)
            raise
        self._acquired.append(fd)
        opened = os.fstat(fd)
        if (made.st_dev,made.st_ino) != (opened.st_dev,opened.st_ino):
            _fail('SCRATCH_BINDING')
        base = self.anchor / 'run' if not self._scratch else self._scratch[0][3]
        self._scratch.append((parent,name,fd,base/name))
        self._guard()
        return self._scratch[-1]

    def _command(self, operation, directory):
        self._guard()
        if self._calls>=self._budget:_fail('COMMAND_BUDGET')
        if self._clock()+15*(self._budget-self._calls)+10>=self._end:_fail('DEADLINE')
        self._calls+=1
        try:
            if self._owner is None:
                result=self._injected(operation,directory,deadline=self._end-10)
            else:
                result=self._owner._run(operation,directory,deadline=self._end-10)
        finally:
            self._guard()
        if type(result) is not bytes:
            _fail('COMMAND_RESULT')
        return result

    def _extract(self,role):
        name={'core':'qshd','contexts':'qshd_contexts'}[role]+'.pp'
        parent,leaf,fd,path=self._new_scratch(self._work,'extract-'+role+'-'+secrets.token_hex(16))
        if os.listdir(fd):_fail('SCRATCH_NOT_EMPTY')
        output=self._command('extract-'+role,path)
        if name not in os.listdir(fd):_fail('HLL_MISSING')
        value=self._protected(fd,name,MAX_HLL,mode=0o600)
        held=self._open(fd,name);self._acquired.append(held)
        if (os.fstat(held).st_dev,os.fstat(held).st_ino)!=tuple(value['inode']):_fail('HLL_BINDING')
        self._output.append((fd,name,held))
        if output or sorted(os.listdir(fd))!=[name]:_fail('EXTRACTION_CONTENTS')
        digest=self._trusted.core_pp_sha256 if role=='core' else self._trusted.contexts_pp_sha256
        return verify_hll(value['data'],digest)

    def _sample(self):
        entries=parse_full_listing(self._command('list',self._scratch[0][3]))
        if self._mode=='absent':
            if any(x.name in ('qshd','qshd_contexts') for x in entries):_fail('MODULE_REMAINS')
            return None,None
        if self._mode=='core-only' and any(x.name=='qshd_contexts' for x in entries):_fail('CONTEXTS_REMAINS')
        core=select_owned(entries,role='core')
        contexts=select_owned(entries,role='contexts') if self._mode=='pair' else None
        core=ModuleComponent(core,self._extract('core'))
        contexts=ModuleComponent(contexts,self._extract('contexts')) if contexts is not None else None
        self._guard()
        return core,contexts

    def capture(self):
        return self._observe(None)

    def recheck(self, observation):
        if observation is None:
            self._state = 'failed'
            _fail('LEASE_STATE')
        self._observe(observation)

    def _observe(self, observation):
        allowed = self._state == ('open' if observation is None else 'captured')
        if not allowed or (observation is not None and observation is not self._observation):
            self._state = 'failed'
            _fail('LEASE_STATE')
        self._state = 'failed'
        try:
            if observation is None:
                # Installed updates completed before capture form this window's
                # fresh baseline; no later retry/reset can replace it.
                self._validate_directory_routes()
                self._files['executable'] = self._protected(self._dirs['bin'],'semodule',MAX_HLL,executable=True)
                self._files['config'] = self._protected(self._dirs['config'],'semanage.conf',65536)
                self._lock = self._lock_snapshot()
            core,contexts = self._sample()
            if observation is None:
                files = {key: dict(value, data=hashlib.sha256(value['data']).hexdigest())
                         for key,value in self._files.items()}
                directories = {key: (os.fstat(fd).st_dev,os.fstat(fd).st_ino)
                               for key,fd in self._dirs.items()}
                bindings = _frozen({'files': files, 'lock': self._lock,
                                    'directories': directories})
                self._observation = ModuleObservation(self._mode,core,contexts,self._trusted,bindings)
                self._state = 'captured'
                return self._observation
            if (core,contexts)!=(observation.core,observation.contexts):
                _fail('MODULE_DRIFT')
            self._state = 'checked'
        except (OSError, Conflict, ModuleError, _CommandError):
            raise ObserverError('OBSERVATION') from None

    def _close(self):
        if self._closed:
            _fail('LEASE_STATE')
        self._closed = True
        errors = False
        try:
            self._validate_directory_routes()
        except BaseException:
            errors = True
        unresolved = (self._owner is not None and self._owner._last is not None
                      and not self._owner._last.settled)
        if not unresolved:
            for parent,name,held in reversed(self._output):
                try:
                    st = os.stat(name,dir_fd=parent,follow_symlinks=False)
                    own = os.fstat(held)
                    if (st.st_dev,st.st_ino) != (own.st_dev,own.st_ino):
                        _fail('CLEANUP_BINDING')
                    os.unlink(name,dir_fd=parent)
                except BaseException:
                    errors = True
            for parent,name,fd,path in reversed(self._scratch):
                try:
                    named = os.stat(name,dir_fd=parent,follow_symlinks=False)
                    held = os.fstat(fd)
                    if (named.st_dev,named.st_ino) != (held.st_dev,held.st_ino):
                        _fail('CLEANUP_BINDING')
                    os.rmdir(name,dir_fd=parent)
                except BaseException:
                    errors = True
        else:
            errors = True
        # Includes descriptors acquired before later validation could fail,
        # even when no safe output/directory cleanup identity was admitted.
        descriptors = self._acquired.copy()
        descriptors += self.anchors + [item[2] for item in self.routes]
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except BaseException:
                errors = True
        self._state = 'closed'
        if errors:
            _fail('CLEANUP')

    def __exit__(self, kind, value, traceback):
        checked = self._state == 'checked'
        try:
            if kind is None:self._time()
        finally:
            try:self._close()
            except ObserverError:raise ObserverError('CLEANUP') from None
        if kind is None:
            self._time()
            if not checked:_fail('FINAL_RECHECK_REQUIRED')
        return False
