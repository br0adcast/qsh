"""Fresh incoming-provider invalidation; no installed payload or readiness claim.

The trusted caller supplies reviewed incoming authority and excludes privileged
writers, drains/stops manual daemons and prevents concurrent starts. A successful
manager observation is not that exclusion. Failure may leave initialized state;
after publication is attempted, failure does not prove the slot stayed absent.
"""
from dataclasses import asdict
import json
import math
import os
import secrets
import time

import qshd_selinux_activation as model
import qshd_selinux_activation_state as state
import qshd_selinux_package_state as package
from qshd_selinux_process import _Owner, _Limits, _preconditions
import stop_guard

class PreError(RuntimeError):
    """Fixed bounded category, never raw command output or caller data."""


def _json(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


class _Bindings:
    def preconditions(self):
        if os.geteuid()!=0:raise PreError('ROOT_REQUIRED')
        _preconditions()
    def package(self):return package.production()
    def slot(self):return state.production()
    def guard(self,deadline):
        owner=_Owner(_Limits(5,16384))
        def run():
            streams=owner._run(stop_guard.COMMAND,'/',deadline=deadline)
            outcome=owner._last
            if (outcome is None or outcome.failure is not None or outcome.exit_code!=0
                    or not outcome.settled or outcome.unreaped or streams.stderr):
                raise PreError('GUARD_REFUSED')
            return streams.stdout.decode('utf-8','strict')
        stop_guard.check(stop_guard.Host(),run,allow_absent=True)


class _Coordinator:
    def __init__(self,bindings,*,clock=time.monotonic):
        self._bindings=bindings;self._clock=clock;self._used=False
    def invalidate(self,trusted_artifact,*,deadline):
        if self._used:raise PreError('SINGLE_USE')
        self._used=True;attempted=False
        try:
            start=self._clock()
            if (type(trusted_artifact) is not model.TrustedArtifact or
                    type(deadline) not in (int,float) or not math.isfinite(deadline)):
                raise PreError('INVALID_INPUT')
            model.TrustedArtifact(trusted_artifact.provider_version,
                trusted_artifact.manifest_sha256,trusted_artifact.pp_sha256)
            end=min(deadline,start+30)
            def check():
                if self._clock()>=end:raise PreError('DEADLINE')
            check();self._bindings.preconditions();check()
            self._bindings.guard(end);check()
            with self._bindings.package().initialize():
                check()
                slot=self._bindings.slot()
                with slot.writer() as writer:
                    check();initial=writer.capture_current()
                    if initial.record is not None:raise PreError('EXISTING_RECORD')
                    self._bindings.guard(end);check()
                    pending=model.Activation(1,'PENDING',secrets.token_hex(16),
                        'fedora44-targeted-v1',1,1,trusted_artifact,
                        model.ModuleIdentity('qshd',400,'targeted','pp'),None)
                    document=_json(asdict(pending))
                    attempted=True
                    writer.begin_pending(document,initial)
                    check()
                check()
                with slot.inspection() as reader:
                    observed=reader.capture()
                    if observed.record!=pending or observed.document!=document:
                        raise PreError('READBACK')
                    reader.recheck(observed);check()
                check()
            check();return pending
        except BaseException as error:
            if attempted:raise PreError('STATE_UNCERTAIN') from None
            if not isinstance(error,Exception):raise
            if isinstance(error,PreError):raise
            raise PreError('PRE_REFUSED') from None


def invalidate_fresh_provider_pre(trusted_artifact,*,deadline):
    return _Coordinator(_Bindings()).invalidate(trusted_artifact,deadline=deadline)

# Explicit capsule entry only; importing this module never changes resources.
_ENTRY_STARTED=None


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise PreError('FRAME')
        result[key]=value
    return result


def _request_artifact(request):
    if type(request) is not bytes or not 0<len(request)<=1024:raise PreError('REQUEST')
    try:
        value=json.loads(request,object_pairs_hook=_pairs)
        if (type(value) is not dict or set(value)!={'schema','phase','artifact'} or
                type(value['schema']) is not int or value['schema']!=1 or
                value['phase']!='provider-pre-fresh' or _json(value)!=request or
                type(value['artifact']) is not dict or
                set(value['artifact'])!={'provider_version','manifest_sha256','pp_sha256'}):
            raise PreError('REQUEST')
        return model.TrustedArtifact(**value['artifact'])
    except (ValueError,TypeError,RecursionError):raise PreError('REQUEST') from None


def _frame(request,operation):
    import hashlib
    return _json(dict(schema=1,phase='provider-pre-fresh',
        request_sha256=hashlib.sha256(request).hexdigest(),operation_id=operation,state='PENDING'))+b'\n'


def _require_frame(data,request):
    import re
    try:
        value=json.loads(data,object_pairs_hook=_pairs)
        if (type(value) is not dict or set(value)!=
                {'schema','phase','request_sha256','operation_id','state'} or
                type(value['operation_id']) is not str or
                re.fullmatch('[0-9a-f]{32}',value['operation_id']) is None or
                _frame(request,value['operation_id'])!=data):raise PreError('FRAME')
    except (ValueError,TypeError,RecursionError):raise PreError('FRAME') from None


def _resources(*,configure):
    import resource
    import signal
    from qshd_selinux_process import _children
    from pathlib import Path
    if (os.geteuid()!=0 or len(list(Path('/proc/self/task').iterdir()))!=1 or
            signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL or _children()):
        raise PreError('PROCESS')
    limits=((resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,16*1024**2),
        (resource.RLIMIT_AS,1024**3),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_CPU,40))
    for key,target in limits:
        soft,hard=resource.getrlimit(key)
        if configure:
            if hard!=resource.RLIM_INFINITY and hard<target:raise PreError('LIMITS')
            resource.setrlimit(key,(target,target))
        elif (soft,hard)!=(target,target):raise PreError('LIMITS')
    _preconditions()


def _child_main(request,args):
    import sys
    try:
        if len(args)!=1:raise PreError('ARGUMENTS')
        deadline=float(args[0])
        if not math.isfinite(deadline) or deadline<=time.monotonic():raise PreError('DEADLINE')
        trusted=_request_artifact(request)
        _resources(configure=False)
        record=invalidate_fresh_provider_pre(trusted,deadline=deadline)
        if time.monotonic()>=deadline:raise PreError('DEADLINE')
        sys.stdout.buffer.write(_frame(request,record.operation_id));sys.stdout.buffer.flush()
        return 0
    except BaseException:
        sys.stderr.write('PROVIDER_PRE_REFUSED\n');return 1


class _Interrupted(BaseException):pass


def run_embedded_pre(child_source,fixed_request):
    """Dedicated fresh-process entry; accepts only reviewed generated capsule input."""
    import signal
    import sys
    start=time.monotonic() if _ENTRY_STARTED is None else _ENTRY_STARTED
    handlers={}
    try:
        if (type(start) not in (int,float) or not math.isfinite(start) or
                type(child_source) is not str or '\0' in child_source or
                not 0<len(child_source.encode('utf-8'))<=98304):raise PreError('CAPSULE')
        _request_artifact(fixed_request)
        _resources(configure=True)
        def interrupted(signum,frame):raise _Interrupted()
        for signum in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):
            handlers[signum]=signal.signal(signum,interrupted)
        if time.monotonic()>=start+30:raise PreError('DEADLINE')
        owner=_Owner(_Limits(30,4096))
        streams=owner._run(('/usr/bin/python3','-I','-B','-c',child_source,str(start+30)),
                           '/',deadline=start+30)
        outcome=owner._last
        if (outcome is None or outcome.failure is not None or outcome.exit_code!=0 or
                not outcome.settled or outcome.unreaped or streams.stderr or
                time.monotonic()>=start+40):raise PreError('OWNER')
        _require_frame(streams.stdout,fixed_request)
        sys.stdout.buffer.write(streams.stdout);sys.stdout.buffer.flush()
        return 0
    except BaseException:
        sys.stderr.write('PROVIDER_PRE_REFUSED\n');return 1
    finally:
        for signum,handler in handlers.items():signal.signal(signum,handler)
