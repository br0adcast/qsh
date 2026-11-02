"""Fixed installed maintenance phases; no scriptlets or start authorization.

Installation authority, administrator drain/stop and exclusion of concurrent
starts/privileged writers are caller prerequisites. Imports change no process
resources or custody. Only explicit execution configures its dedicated owner.
"""
import time
_ENTRY_STARTED=time.monotonic() if __name__=='__main__' else None

import hashlib
import importlib.abc
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import sys

_MODULES=tuple('qshd_selinux_'+name for name in (
    'activation','activation_state','contexts','transaction','fs','registry',
    'process','modules','module_observer','api','queries','files','observer',
    'reference_loader','package_state','module_install','first_activation',
    'consumer_activation','phase'))+('stop_guard',)
_PHASES={'provider-post-pristine':'COMPLETE','consumer-pre-fresh':'PENDING',
         'consumer-pre-installed':'PENDING','consumer-post-owned':'COMPLETE'}
_SCRIPT='/usr/libexec/qshd-selinux/qshd_selinux_phase.py'
_CHILD='_phase_child_v1'


class PhaseError(RuntimeError):
    """Fixed protocol category, never raw protected content or tool output."""


class _Interrupted(BaseException):pass


def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _pairs(items):
    value={}
    for key,item in items:
        if key in value:raise PhaseError('PROTOCOL')
        value[key]=item
    return value


class _FixedFinder(importlib.abc.MetaPathFinder):
    def __init__(self,root):self._paths={name:root/(name+'.py') for name in _MODULES}
    def find_spec(self,fullname,path=None,target=None):
        if fullname in self._paths:
            return importlib.util.spec_from_file_location(fullname,self._paths[fullname])
        if (fullname.startswith('qshd_selinux_') or fullname=='qshd_selinux'
                or fullname.startswith('qshd_selinux.') or fullname=='stop_guard'
                or fullname.startswith('stop_guard.')):
            raise ModuleNotFoundError('fixed installed module required')
        return None


def _install_loader():
    root=Path(__file__).resolve().parent
    own=sys.modules.get(__name__)
    if own is None:raise PhaseError('ENTRY')
    for name in _MODULES:
        existing=sys.modules.get(name)
        if existing is not None and not (name=='qshd_selinux_phase' and existing is own):
            raise PhaseError('MODULE_PRESENT')
    sys.modules['qshd_selinux_phase']=own
    sys.meta_path.insert(0,_FixedFinder(root))


def _request(phase):
    if type(phase) is not str or phase not in _PHASES:raise PhaseError('PHASE')
    return _json(dict(schema=1,phase=phase))


def _parse_request(raw):
    if type(raw) is not bytes or not 0<len(raw)<=256:raise PhaseError('REQUEST')
    try:
        value=json.loads(raw,object_pairs_hook=_pairs)
        if (type(value) is not dict or set(value)!={'schema','phase'}
                or type(value['schema']) is not int or value['schema']!=1
                or _request(value['phase'])!=raw):raise PhaseError('REQUEST')
        return value
    except (ValueError,TypeError,RecursionError):raise PhaseError('REQUEST') from None


def _parse_response(raw,request):
    if type(raw) is not bytes or not 0<len(raw)<=4096:raise PhaseError('RESPONSE')
    expected=_parse_request(request)
    try:
        from qshd_selinux_activation import TrustedArtifact
        value=json.loads(raw,object_pairs_hook=_pairs)
        if (type(value) is not dict or set(value)!=
                {'schema','phase','request_sha256','operation_id','state','artifact'}
                or type(value['schema']) is not int or value['schema']!=1
                or value['phase']!=expected['phase'] or value['state']!=_PHASES[expected['phase']]
                or value['request_sha256']!=hashlib.sha256(request).hexdigest()
                or type(value['operation_id']) is not str or re.fullmatch('[0-9a-f]{32}',value['operation_id']) is None
                or type(value['artifact']) is not dict or set(value['artifact'])!=
                   {'provider_version','manifest_sha256','pp_sha256'}
                or _json(value)+b'\n'!=raw):raise PhaseError('RESPONSE')
        TrustedArtifact(**value['artifact'])
        return value
    except (ValueError,TypeError,RecursionError,UnicodeError):raise PhaseError('RESPONSE') from None


def _response(record,request):
    from dataclasses import asdict
    from qshd_selinux_activation import Activation
    phase=_parse_request(request)['phase']
    if type(record) is not Activation or record.state!=_PHASES[phase]:raise PhaseError('RESULT')
    record.__post_init__()
    raw=_json(dict(schema=1,phase=phase,request_sha256=hashlib.sha256(request).hexdigest(),
        operation_id=record.operation_id,state=record.state,artifact=asdict(record.artifact)))+b'\n'
    _parse_response(raw,request)
    return raw


def _resources(*,configure):
    import resource
    from qshd_selinux_process import _children,_preconditions
    if (os.geteuid()!=0 or len(list(Path('/proc/self/task').iterdir()))!=1
            or signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL or _children()):raise PhaseError('PROCESS')
    for key,target in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,16*1024**2),
                       (resource.RLIMIT_AS,1024**3),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_CPU,260)):
        soft,hard=resource.getrlimit(key)
        if configure:
            if hard!=resource.RLIM_INFINITY and hard<target:raise PhaseError('LIMITS')
            resource.setrlimit(key,(target,target))
        elif (soft,hard)!=(target,target):raise PhaseError('LIMITS')
    _preconditions()


def _dispatch(phase,*,deadline):
    _request(phase)
    import qshd_selinux_consumer_activation as consumer
    if phase=='provider-post-pristine':
        from qshd_selinux_first_activation import activate_installed_pristine_pending_first
        consumer._Production().guard(deadline)
        return activate_installed_pristine_pending_first(deadline=deadline)
    if phase in ('consumer-pre-fresh','consumer-pre-installed'):
        return consumer.invalidate_installed_consumer_pre(fresh=phase=='consumer-pre-fresh',deadline=deadline)
    return consumer.finalize_installed_owned_pending_consumer(deadline=deadline)


def _owner():
    from qshd_selinux_process import _Owner,_Limits
    return _Owner(_Limits(250,4096))


def _child_main(args):
    if len(args)!=3:raise PhaseError('ARGUMENTS')
    try:
        request=args[0].encode('ascii');_parse_request(request)
        started=float(args[1]);work_end=float(args[2]);now=time.monotonic()
        if (not math.isfinite(started) or not math.isfinite(work_end)
                or started<0 or started>now or work_end!=started+240 or now>=work_end):
            raise PhaseError('DEADLINE')
    except (ValueError,UnicodeError):raise PhaseError('ARGUMENTS') from None
    _resources(configure=False)
    if time.monotonic()>=work_end:raise PhaseError('DEADLINE')
    record=_dispatch(_parse_request(request)['phase'],deadline=work_end)
    raw=_response(record,request)
    if time.monotonic()>=work_end:raise PhaseError('DEADLINE')
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    return 0


def _parent(phase,started):
    request=_request(phase);_resources(configure=True)
    handlers={}
    try:
        def interrupted(signum,frame):raise _Interrupted()
        for signum in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):
            handlers[signum]=signal.signal(signum,interrupted)
        if time.monotonic()>=started+240:raise PhaseError('DEADLINE')
        owner=_owner()
        if time.monotonic()>=started+240:raise PhaseError('DEADLINE')
        streams=owner._run(('/usr/bin/python3','-I','-B',_SCRIPT,_CHILD,
            request.decode('ascii'),repr(started),repr(started+240)),'/',deadline=started+250)
        outcome=owner._last
        if (outcome is None or outcome.failure is not None or outcome.exit_code!=0
                or not outcome.settled or outcome.unreaped or streams.stderr):raise PhaseError('OWNER')
        _parse_response(streams.stdout,request)
        if time.monotonic()>=started+250:raise PhaseError('DEADLINE')
        sys.stdout.buffer.write(streams.stdout);sys.stdout.buffer.flush()
        return 0
    finally:
        for signum,handler in handlers.items():signal.signal(signum,handler)


def main():
    started=time.monotonic() if _ENTRY_STARTED is None else _ENTRY_STARTED
    try:
        args=sys.argv[1:]
        if args and args[0]==_CHILD:
            if len(args)!=4:raise PhaseError('ARGUMENTS')
            _parse_request(args[1].encode('ascii'));_install_loader()
            return _child_main(args[1:])
        if len(args)!=1:raise PhaseError('ARGUMENTS')
        _request(args[0]);_install_loader()
        return _parent(args[0],started)
    except BaseException:
        sys.stderr.write('PHASE_REFUSED\n');return 1


if __name__=='__main__':raise SystemExit(main())
