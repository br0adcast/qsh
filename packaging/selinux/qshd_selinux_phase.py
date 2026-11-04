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
    'process','modules','module_observer','api','queries','files','retained_labels','observer',
    'reference_loader','package_state','module_install','first_activation',
    'consumer_activation','phase','rpm_query'))+('stop_guard',)
_PHASES={'provider-pre-owned':'PENDING','provider-post-owned':'COMPLETE','provider-post-pristine':'COMPLETE','consumer-pre-fresh':'PENDING',
         'consumer-pre-installed':'PENDING','consumer-post-owned':'COMPLETE',
         'consumer-preun-final':'PENDING'}
_INTENTS={'provider-pre-owned':'provider-refresh','provider-post-owned':'provider-refresh','provider-post-pristine':'provider-fresh','consumer-pre-fresh':'consumer-install',
          'consumer-pre-installed':'consumer-install','consumer-post-owned':'consumer-install',
          'consumer-preun-final':'consumer-erase'}
_SCRIPT='/usr/libexec/qshd-selinux/qshd_selinux_phase.py'
_CHILD='_phase_child_pair_v2'


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


def _artifact(value):
    from qshd_selinux_activation import TrustedArtifact
    if (type(value) is not dict or set(value)!=
            {'provider_version','manifest_sha256','core_pp_sha256','contexts_pp_sha256'}):
        raise PhaseError('REQUEST')
    return TrustedArtifact(**value)


def _request(phase,incoming_artifact=None):
    if type(phase) is not str or phase not in _PHASES:raise PhaseError('PHASE')
    value=dict(schema=2,phase=phase)
    if phase=='provider-pre-owned':
        from dataclasses import asdict
        from qshd_selinux_activation import TrustedArtifact
        if type(incoming_artifact) is not TrustedArtifact:raise PhaseError('REQUEST')
        try:incoming_artifact.__post_init__()
        except (ValueError,TypeError):raise PhaseError('REQUEST') from None
        value['artifact']=asdict(incoming_artifact)
    elif incoming_artifact is not None:raise PhaseError('REQUEST')
    raw=_json(value)
    if len(raw)>1024:raise PhaseError('REQUEST')
    return raw


def _parse_request(raw):
    if type(raw) is not bytes or not 0<len(raw)<=1024:raise PhaseError('REQUEST')
    try:
        value=json.loads(raw,object_pairs_hook=_pairs)
        if (type(value) is not dict or type(value.get('schema')) is not int
                or value['schema']!=2 or type(value.get('phase')) is not str):raise PhaseError('REQUEST')
        incoming=None
        if value['phase']=='provider-pre-owned':
            if set(value)!={'schema','phase','artifact'}:raise PhaseError('REQUEST')
            incoming=_artifact(value['artifact'])
        elif set(value)!={'schema','phase'}:raise PhaseError('REQUEST')
        if _request(value['phase'],incoming)!=raw:raise PhaseError('REQUEST')
        return value
    except (ValueError,TypeError,RecursionError,UnicodeError):raise PhaseError('REQUEST') from None


def _incoming_argument(raw):
    if type(raw) is not str or not 0<len(raw)<=1024:raise PhaseError('ARGUMENTS')
    try:
        data=raw.encode('ascii');value=json.loads(data,object_pairs_hook=_pairs)
        if _json(value)!=data:raise PhaseError('ARGUMENTS')
        return _artifact(value)
    except (ValueError,TypeError,RecursionError,UnicodeError):raise PhaseError('ARGUMENTS') from None


def _parse_response(raw,request):
    if type(raw) is not bytes or not 0<len(raw)<=4096:raise PhaseError('RESPONSE')
    expected=_parse_request(request)
    try:
        from qshd_selinux_activation import TrustedArtifact
        value=json.loads(raw,object_pairs_hook=_pairs)
        if (type(value) is not dict or set(value)!=
                {'schema','phase','request_sha256','operation_id','state','artifact'}
                or type(value['schema']) is not int or value['schema']!=2
                or value['phase']!=expected['phase'] or value['state']!=_PHASES[expected['phase']]
                or value['request_sha256']!=hashlib.sha256(request).hexdigest()
                or type(value['operation_id']) is not str or re.fullmatch('[0-9a-f]{32}',value['operation_id']) is None
                or type(value['artifact']) is not dict or set(value['artifact'])!=
                   {'provider_version','manifest_sha256','core_pp_sha256','contexts_pp_sha256'}
                or _json(value)+b'\n'!=raw):raise PhaseError('RESPONSE')
        TrustedArtifact(**value['artifact'])
        if expected['phase']=='provider-pre-owned' and value['artifact']!=expected['artifact']:
            raise PhaseError('RESPONSE')
        return value
    except (ValueError,TypeError,RecursionError,UnicodeError):raise PhaseError('RESPONSE') from None


def _response(record,request):
    from dataclasses import asdict
    from qshd_selinux_activation import Activation
    phase=_parse_request(request)['phase']
    if type(record) is not Activation or (record.state!=_PHASES[phase] or record.intent!=_INTENTS[phase]):raise PhaseError('RESULT')
    record.__post_init__()
    raw=_json(dict(schema=2,phase=phase,request_sha256=hashlib.sha256(request).hexdigest(),
        operation_id=record.operation_id,state=record.state,artifact=asdict(record.artifact)))+b'\n'
    _parse_response(raw,request)
    return raw


_STAGES=frozenset(('INPUT','PROCESS','PACKAGE','REFERENCES','ACTIVATION','ROUTING','PENDING',
    'CONTEXT_PRISTINE','INSTALL','RECONCILE','OBSERVATION','COMPLETE','FINALIZE','PREFLIGHT',
    'POLICY','CONSUMER','RPM','RPM_RECHECK','FILES','RELOAD','GUARD',
    'AUTHORITY','ERASE_FILES','OWNED_CONTEXTS','POLICY_CONTEXT','READBACK'))
_COMMAND_CODES=frozenset(('COMMAND_TIMEOUT','OUTPUT_LIMIT','COMMAND_CUSTODY','TOOL_FAILURE','COMMAND_UNSETTLED',
    'OUTPUT_INCOMPLETE','PROCESS_THREADS','PROCESS_SIGNALS','PROCESS_CHILDREN','PROCESS_LIMITS',
    'PROCESS_SUBREAPER','PROCESS_OWNER','COMMAND_LIMITS','COMMAND_INPUT','COMMAND_KIND',
    'COMMAND_BUDGET','COMMAND_STDERR','COMMAND_OUTPUT'))
_CODES=_COMMAND_CODES|frozenset('COORDINATOR_'+name for name in _STAGES)|frozenset((
    'UNKNOWN','INSTALL_REFUSED','REGISTRY_REFUSED','CONTEXT_REFUSED','SLOT_REFUSED','SELINUX_REFUSED'))


def _parse_failure(raw,request):
    from qshd_selinux_process import _ERRNO_CODES
    codes=_CODES|frozenset(_ERRNO_CODES.values())
    if type(raw) is not bytes or not 0<len(raw)<=1024:raise PhaseError('FAILURE')
    expected=_parse_request(request)
    try:
        value=json.loads(raw,object_pairs_hook=_pairs)
        if (type(value) is not dict or set(value)!={'version','request','codes','command'}
                or type(value['version']) is not int or value['version']!=1
                or value['request']!=expected or type(value['request']) is not dict
                or _json(value['request'])!=request
                or type(value['codes']) is not list or not 1<=len(value['codes'])<=8
                or any(type(code) is not str or code not in codes for code in value['codes'])
                or _json(value)+b'\n'!=raw):raise PhaseError('FAILURE')
        command=value['command']
        if command is not None:
            from qshd_selinux_process import _FailureSummary
            if type(command) is not dict or set(command)!={'profile','failure','exit_code','settled','unreaped'}:
                raise PhaseError('FAILURE')
            _FailureSummary(**command)
        return value
    except (ValueError,TypeError,RecursionError,UnicodeError):raise PhaseError('FAILURE') from None


def _failure(error,request):
    from dataclasses import asdict
    from qshd_selinux_process import _CommandError,_FailureSummary,_ERRNO_CODES
    from qshd_selinux_first_activation import CoordinatorError as FirstError
    from qshd_selinux_consumer_activation import CoordinatorError as ConsumerError
    from qshd_selinux_module_install import InstallError
    from qshd_selinux_registry import RegistryError
    from qshd_selinux_fs import Conflict
    from qshd_selinux_activation_state import SlotError,OutcomeUncertain
    from qshd_selinux_api import SelinuxError
    codes=[];command=None;seen=set()
    while error is not None and len(codes)<8 and id(error) not in seen:
        seen.add(id(error));kind=type(error);code='UNKNOWN'
        if kind in (OSError,PermissionError):
            number=OSError.errno.__get__(error)
            if type(number) is int:code=_ERRNO_CODES.get(number,'UNKNOWN')
        elif kind in (FirstError,ConsumerError):
            args=BaseException.args.__get__(error)
            if len(args)==1 and type(args[0]) is str and args[0] in _STAGES:code='COORDINATOR_'+args[0]
        elif kind is _CommandError:
            args=BaseException.args.__get__(error)
            if len(args)==1 and type(args[0]) is str and args[0] in _COMMAND_CODES:code=args[0]
            launch_code=error.launch_code
            if type(launch_code) is str and launch_code in _ERRNO_CODES.values():code=launch_code
            summary=error.summary
            if command is None and type(summary) is _FailureSummary:
                try:summary.__post_init__();command=asdict(summary)
                except ValueError:pass
        elif kind is InstallError:code='INSTALL_REFUSED'
        elif kind is RegistryError:code='REGISTRY_REFUSED'
        elif kind in (SlotError,OutcomeUncertain):code='SLOT_REFUSED'
        elif kind is Conflict:code='CONTEXT_REFUSED'
        elif kind is SelinuxError:code='SELINUX_REFUSED'
        codes.append(code)
        cause=BaseException.__cause__.__get__(error)
        error=cause if cause is not None else BaseException.__context__.__get__(error)
    raw=_json(dict(version=1,request=_parse_request(request),codes=codes or ['UNKNOWN'],command=command))+b'\n'
    _parse_failure(raw,request)
    return raw


def _resources(*,configure):
    import resource
    from qshd_selinux_process import _children,_preconditions
    if (os.geteuid()!=0 or len(list(Path('/proc/self/task').iterdir()))!=1
            or signal.getsignal(signal.SIGCHLD)!=signal.SIG_DFL or _children()):raise PhaseError('PROCESS')
    for key,target in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,16*1024**2),
                       (resource.RLIMIT_AS,1024**3),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_CPU,450)):
        soft,hard=resource.getrlimit(key)
        if configure:
            if hard!=resource.RLIM_INFINITY and hard<target:raise PhaseError('LIMITS')
            resource.setrlimit(key,(target,target))
        elif (soft,hard)!=(target,target):raise PhaseError('LIMITS')
    _preconditions()


def _dispatch(phase,*,deadline,incoming_artifact=None):
    _request(phase,incoming_artifact)
    if phase=='provider-pre-owned':
        from qshd_selinux_first_activation import invalidate_installed_provider_upgrade
        return invalidate_installed_provider_upgrade(incoming_artifact,deadline=deadline)
    if phase=='provider-post-owned':
        from qshd_selinux_first_activation import activate_installed_owned_provider
        return activate_installed_owned_provider(deadline=deadline)
    import qshd_selinux_consumer_activation as consumer
    if phase=='provider-post-pristine':
        from qshd_selinux_first_activation import activate_installed_pristine_pending_first
        return activate_installed_pristine_pending_first(deadline=deadline)
    if phase in ('consumer-pre-fresh','consumer-pre-installed'):
        return consumer.invalidate_installed_consumer_pre(fresh=phase=='consumer-pre-fresh',deadline=deadline)
    if phase=='consumer-post-owned':
        return consumer.finalize_installed_owned_pending_consumer(deadline=deadline)
    if phase=='consumer-preun-final':
        # The coordinator owns the guard and leases; final removal is not here.
        return consumer.invalidate_installed_consumer_erase(deadline=deadline)
    raise PhaseError('PHASE')


def _owner():
    from qshd_selinux_process import _Owner,_Limits
    return _Owner(_Limits(440,4096))


def _child_main(args):
    if len(args)!=3:raise PhaseError('ARGUMENTS')
    try:
        request=args[0].encode('ascii');parsed=_parse_request(request)
        started=float(args[1]);work_end=float(args[2]);now=time.monotonic()
        if (not math.isfinite(started) or not math.isfinite(work_end)
                or started<0 or started>now or work_end!=started+430 or now>=work_end):
            raise PhaseError('DEADLINE')
    except (ValueError,UnicodeError):raise PhaseError('ARGUMENTS') from None
    _resources(configure=False)
    if time.monotonic()>=work_end:raise PhaseError('DEADLINE')
    dispatch_args=dict(deadline=work_end)
    if parsed['phase']=='provider-pre-owned':dispatch_args['incoming_artifact']=_artifact(parsed['artifact'])
    try:record=_dispatch(parsed['phase'],**dispatch_args)
    except BaseException as error:
        if not isinstance(error,Exception):raise
        raw=_failure(error,request)
        if time.monotonic()>=work_end:raise PhaseError('DEADLINE')
        sys.stderr.buffer.write(raw);sys.stderr.buffer.flush()
        return 1
    raw=_response(record,request)
    if time.monotonic()>=work_end:raise PhaseError('DEADLINE')
    sys.stdout.buffer.write(raw);sys.stdout.buffer.flush()
    return 0


def _parent(phase,started,*,incoming_artifact=None):
    request=_request(phase,incoming_artifact);_resources(configure=True)
    handlers={}
    try:
        def interrupted(signum,frame):raise _Interrupted()
        for signum in (signal.SIGTERM,signal.SIGHUP,signal.SIGINT):
            handlers[signum]=signal.signal(signum,interrupted)
        if time.monotonic()>=started+430:raise PhaseError('DEADLINE')
        owner=_owner()
        if time.monotonic()>=started+430:raise PhaseError('DEADLINE')
        from qshd_selinux_process import _CommandError,_Outcome,_Streams,_normal_outcome
        try:
            streams=owner._run(('/usr/bin/python3','-I','-B',_SCRIPT,_CHILD,
                request.decode('ascii'),repr(started),repr(started+430)),'/',deadline=started+440)
        except _CommandError as error:
            outcome=owner._last
            if (error.args!=('TOOL_FAILURE',) or type(outcome) is not _Outcome
                    or outcome.failure is not None or type(outcome.exit_code) is not int or outcome.exit_code!=1
                    or not _normal_outcome(outcome) or outcome.settled is not True or type(outcome.unreaped) is not tuple or outcome.unreaped or type(outcome.stdout) is not bytes or outcome.stdout
                    or type(outcome.stderr) is not bytes or time.monotonic()>=started+440):
                raise PhaseError('OWNER') from None
            _parse_failure(outcome.stderr,request)
            if time.monotonic()>=started+440:raise PhaseError('DEADLINE')
            sys.stderr.buffer.write(outcome.stderr);sys.stderr.buffer.flush()
            return 1
        outcome=owner._last
        if (type(streams) is not _Streams or type(streams.stdout) is not bytes or type(streams.stderr) is not bytes
                or not _normal_outcome(outcome) or outcome.exit_code!=0
                or not outcome.settled or outcome.unreaped or streams.stderr):raise PhaseError('OWNER')
        _parse_response(streams.stdout,request)
        if time.monotonic()>=started+440:raise PhaseError('DEADLINE')
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
            _install_loader();_parse_request(args[1].encode('ascii'))
            return _child_main(args[1:])
        if not args or args[0] not in _PHASES:raise PhaseError('ARGUMENTS')
        if len(args)!=(2 if args[0]=='provider-pre-owned' else 1):raise PhaseError('ARGUMENTS')
        _install_loader()
        if args[0]=='provider-pre-owned':
            incoming=_incoming_argument(args[1]);_request(args[0],incoming)
            return _parent(args[0],started,incoming_artifact=incoming)
        _request(args[0])
        return _parent(args[0],started)
    except BaseException:
        sys.stderr.write('PHASE_REFUSED\n');return 1


if __name__=='__main__':raise SystemExit(main())
