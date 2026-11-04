"""Owned managed-prestart partial evidence; no package hooks or state writes.

Trusted caller supplies independent artifact/PAM authority and holds outer package
exclusion through return. It must satisfy the shared owner's single-thread,
child-free, finite-resource/default-SIGCHLD contract and permit subreaper setup.
It must not hold activation/context leases needed by the fresh child. Evidence
ends at lock release; this API never authorizes startup or package installation.
"""
import time
_ENTRY_STARTED=time.monotonic() if __name__=='__main__' else None

import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time

if __name__=='__main__':
    sys.path.insert(0,str(Path(__file__).resolve().parent))

from qshd_selinux_activation import TrustedArtifact, ContextBinding, ActivationError, require_complete
from qshd_selinux_process import _Owner, _Limits, _CommandError, _preconditions, _normal_outcome, _Streams

_PROFILE='fedora44-targeted-pair-v2'
_MODE='_managed_prestart_pair_v2'
_SECONDS=120
_WORK=110
_PAM_SHA='61dc7f9dc6ada9a612a66b1bfda1f8d1802ec9734a9325edc4f600b0e55622c7'


class ObserverError(ValueError):
    """Bounded refusal without paths, child output or private contents."""


def _fail(code):raise ObserverError(code)


def _finite(value):
    try:return type(value) in (int,float) and math.isfinite(value)
    except OverflowError:return False


def _check(deadline):
    if time.monotonic()>=deadline:_fail('DEADLINE')


def _bounds(deadline,started):
    now=time.monotonic();started=now if started is None else started
    if not _finite(started) or started<0 or started>now:_fail('DEADLINE')
    if deadline is not None and (not _finite(deadline) or started+_SECONDS+10>=deadline):_fail('DEADLINE')
    if now>=started+_WORK:_fail('DEADLINE')
    return started,started+_WORK


def _child_end(args):
    if len(args)!=2:_fail('PROTOCOL')
    try:started,end=map(float,args)
    except (ValueError,TypeError):_fail('PROTOCOL')
    if (not _finite(started) or not _finite(end) or started<0 or started>time.monotonic()
            or end!=started+_WORK):_fail('DEADLINE')
    _check(end);return end


from contextlib import contextmanager
@contextmanager
def _within(scope,deadline):
    _check(deadline)
    with scope as value:
        _check(deadline);yield value;_check(deadline)
    _check(deadline)


class _PendingRefusal(Exception):
    """Only require_complete may select this after successful outer exits."""


def _pending_record(encoded):
    return _json(dict(schema=2,error='ACTIVATION_PENDING',
        request_sha256=hashlib.sha256(encoded.encode('ascii')).hexdigest()))+b'\n'



def _json(value):return json.dumps(value,sort_keys=True,separators=(',',':')).encode('ascii')


def _pairs(pairs):
    result={}
    for key,value in pairs:
        if key in result:_fail('PROTOCOL')
        result[key]=value
    return result


def _trusted(trust,pam):
    if type(trust) is not TrustedArtifact or type(pam) is not bytes or len(pam)>4096:
        _fail('TRUSTED_INPUT')
    if hashlib.sha256(pam).hexdigest()!=_PAM_SHA:_fail('TRUSTED_INPUT')


def _request(trust,pam):
    _trusted(trust,pam)
    encoded=base64.b64encode(_json(dict(schema=2,artifact=asdict(trust),pam_base64=base64.b64encode(pam).decode('ascii')))).decode('ascii')
    if len(encoded)>8192:_fail('PROTOCOL')
    return encoded


def _parse_request(encoded):
    try:
        if type(encoded) is not str or len(encoded)>8192:_fail('PROTOCOL')
        raw=base64.b64decode(encoded,validate=True)
        if base64.b64encode(raw).decode('ascii')!=encoded:_fail('PROTOCOL')
        value=json.loads(raw,object_pairs_hook=_pairs)
        if type(value) is not dict or set(value)!={'schema','artifact','pam_base64'} or type(value['schema']) is not int or value['schema']!=2:
            _fail('PROTOCOL')
        artifact=value['artifact']
        if type(artifact) is not dict or set(artifact)!={'provider_version','manifest_sha256','core_pp_sha256','contexts_pp_sha256'}:_fail('PROTOCOL')
        trust=TrustedArtifact(**artifact)
        pam=base64.b64decode(value['pam_base64'],validate=True)
        if _request(trust,pam)!=encoded:_fail('PROTOCOL')
        return trust,pam
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):_fail('PROTOCOL')


@dataclass(frozen=True)
class ManagedPrestartObservation:
    profile: str
    contexts: ContextBinding


def _response(encoded,binding):
    return _json(dict(schema=2,phase='managed-prestart',profile=_PROFILE,
        request_sha256=hashlib.sha256(encoded.encode('ascii')).hexdigest(),
        registry_sha256=binding.registry_sha256,receipts_sha256=binding.receipts_sha256))+b'\n'


def _parse_response(data,encoded):
    try:
        if type(data) is not bytes or len(data)>4096:_fail('RESPONSE')
        value=json.loads(data,object_pairs_hook=_pairs)
        if type(value) is not dict or set(value)!={'schema','phase','profile','request_sha256','registry_sha256','receipts_sha256'}:
            _fail('RESPONSE')
        if type(value['schema']) is not int or value['schema']!=2 or value['phase']!='managed-prestart' or value['profile']!=_PROFILE:
            _fail('RESPONSE')
        binding=ContextBinding(value['registry_sha256'],value['receipts_sha256'])
        if data!=_response(encoded,binding):_fail('RESPONSE')
        return ManagedPrestartObservation(_PROFILE,binding)
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):_fail('RESPONSE')


def observe_installed_managed_prestart(*,deadline):
    """Observe installed references while owning one existing package lease.

    The finite caller deadline also needs an external hard owner. Parent clock
    checks cannot interrupt filesystem calls. More than 130 seconds must remain
    before the 120-second child and its 10-second settlement allowance.
    Activation/context leases belong to that child, never this parent scope.
    """
    if not _finite(deadline):_fail('DEADLINE')
    started=time.monotonic()
    def check(reserve=0):
        if time.monotonic()+reserve>=deadline:_fail('DEADLINE')
    check(130)
    try:
        _preconditions()
        from qshd_selinux_package_state import production
        from qshd_selinux_reference_loader import production_references
        pending=False
        with production().operation():
            with production_references() as reader:
                check(130)
                captured=reader.capture()
                check(130)
                try:
                    result=observe_managed_prestart(captured.artifact,captured.expected_pam,deadline=deadline,_started=started)
                except ObserverError as error:
                    if str(error)!='ACTIVATION_PENDING':raise
                    pending=True
                check()
                reader.recheck(captured)
                check()
        check()
        if pending:_fail('ACTIVATION_PENDING')
        return result
    except ObserverError:raise
    except _CommandError as error:
        raise ObserverError('CALLER_PROCESS') from error
    except Exception as error:
        raise ObserverError('INSTALLED_REFUSED') from error


def observe_managed_prestart(trusted_artifact,expected_pam,*,deadline=None,_started=None):
    """Real fixed child; caller authority/exclusion is an explicit precondition.

    The deterministic request digest correlates public input only. Fresh owned
    process/pipes supply invocation binding; this is no durable replay receipt.
    """
    started,work_end=_bounds(deadline,_started)
    encoded=_request(trusted_artifact,expected_pam)
    owner=None
    try:
        owner=_Owner(_Limits(120,4096))
        streams=owner._run(('/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),_MODE,encoded,repr(started),repr(work_end)),
                           '/',deadline=started+_SECONDS)
        last=owner._last
        if (type(streams) is not _Streams or type(streams.stdout) is not bytes or type(streams.stderr) is not bytes
                or not _normal_outcome(last) or last.exit_code!=0 or streams.stderr):_fail('OBSERVATION_REFUSED')
        result=_parse_response(streams.stdout,encoded)
        if time.monotonic()>=started+_SECONDS:_fail('DEADLINE')
        return result
    except _CommandError as error:
        code=str(error)
        if code=='TOOL_FAILURE' and owner is not None:
            # A normal exit1 has no recorded owner failure. Parent-side OSError
            # may use TOOL_FAILURE provenance and must never be reclassified.
            if time.monotonic()>=started+_SECONDS:_fail('DEADLINE')
            outcome=owner._last
            if (_normal_outcome(outcome) and outcome.exit_code==1
                    and outcome.settled and not outcome.unreaped and outcome.stdout==b''
                    and outcome.stderr==_pending_record(encoded)):
                if time.monotonic()>=started+_SECONDS:_fail('DEADLINE')
                _fail('ACTIVATION_PENDING')
        if code=='COMMAND_TIMEOUT':_fail('DEADLINE')
        if code in ('COMMAND_CUSTODY','COMMAND_UNSETTLED','OUTPUT_INCOMPLETE','PROCESS_OWNER'):_fail('CUSTODY')
        if code.startswith('PROCESS_'):_fail('CALLER_PROCESS')
        _fail('CHILD_REFUSED')
    except OSError:_fail('CHILD_REFUSED')


def _compose(trust,pam,*,deadline):
    # Imports instantiate no policy engine until the explicit child mode runs.
    import qshd_selinux_activation_state as state
    import qshd_selinux_registry as registry_module
    import qshd_selinux_transaction as transaction
    import qshd_selinux_module_observer as modules
    import qshd_selinux_files as files
    import qshd_selinux_queries as queries
    from qshd_selinux_api import SelinuxApi
    api=SelinuxApi()
    pending=False
    with _within(state.production().inspection(),deadline) as slot:
        with _within(registry_module.production().inspection(),deadline) as registry:
            routing=registry.routing()
            identities=json.loads(routing,object_pairs_hook=_pairs)
            with _within(transaction.production(list(identities)).inspection(identities),deadline) as contexts:
                with _within(modules.production_observer(trust,deadline=deadline),deadline) as module:
                    with _within(files.production(pam,api).inspection(),deadline) as current_files:
                        with _within(queries.required_observation(api),deadline):
                            activation=slot.capture()
                            discovered=registry.capture()
                            context=contexts.capture()
                            selected=module.capture()
                            installed=current_files.capture()
                            if discovered.registry_bytes!=routing or context.registry_bytes!=routing:
                                _fail('REGISTRY_BINDING')
                            binding=ContextBinding(context.registry_sha256,context.receipts_sha256)
                            try:require_complete(activation.record,trust,binding)
                            except ActivationError as error:
                                if str(error)!='ACTIVATION_PENDING':raise
                                pending=True
                            slot.recheck(activation)
                            module.recheck(selected)
                            current_files.recheck(installed)
                            registry.recheck(discovered)
                            contexts.recheck(context)
    # Deferred refusal lets native post-yield checks and every finalizer run
    # normally. Any failure there supersedes the selected pending diagnostic.
    _check(deadline)
    if pending:raise _PendingRefusal()
    return binding


def _main():
    try:
        if len(sys.argv)!=5 or sys.argv[1]!=_MODE:_fail('PROTOCOL')
        trust,pam=_parse_request(sys.argv[2])
        # Refuse before constructing native state or touching production paths.
        if os.geteuid()!=0:_fail('ROOT_REQUIRED')
        _preconditions()
        end=_child_end(sys.argv[3:]);binding=_compose(trust,pam,deadline=end)
        sys.stdout.buffer.write(_response(sys.argv[2],binding));sys.stdout.buffer.flush()
    except _PendingRefusal:
        sys.stderr.buffer.write(_pending_record(sys.argv[2]));sys.stderr.buffer.flush()
        return 1
    except Exception:
        sys.stderr.write('OBSERVATION_REFUSED\n')
        return 1
    return 0


_POLICY_MODE='_consumer_preinstall_pair_v2'


@dataclass(frozen=True)
class PolicyContextObservation:
    profile: str
    contexts: ContextBinding


def _policy_request(trust):
    if type(trust) is not TrustedArtifact:_fail('TRUSTED_INPUT')
    trust.__post_init__()
    encoded=base64.b64encode(_json(dict(schema=2,phase='consumer-preinstall',artifact=asdict(trust)))).decode('ascii')
    if len(encoded)>8192:_fail('PROTOCOL')
    return encoded


def _parse_policy_request(encoded):
    try:
        if type(encoded) is not str or len(encoded)>8192:_fail('PROTOCOL')
        raw=base64.b64decode(encoded,validate=True)
        if base64.b64encode(raw).decode('ascii')!=encoded:_fail('PROTOCOL')
        value=json.loads(raw,object_pairs_hook=_pairs)
        if (type(value) is not dict or set(value)!={'schema','phase','artifact'}
                or type(value['schema']) is not int or value['schema']!=2
                or value['phase']!='consumer-preinstall'):_fail('PROTOCOL')
        artifact=value['artifact']
        if type(artifact) is not dict or set(artifact)!={'provider_version','manifest_sha256','core_pp_sha256','contexts_pp_sha256'}:_fail('PROTOCOL')
        trust=TrustedArtifact(**artifact)
        if _policy_request(trust)!=encoded:_fail('PROTOCOL')
        return trust
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):_fail('PROTOCOL')


def _policy_response(encoded,binding):
    return _json(dict(schema=2,phase='consumer-preinstall',profile=_PROFILE,
        request_sha256=hashlib.sha256(encoded.encode('ascii')).hexdigest(),
        registry_sha256=binding.registry_sha256,receipts_sha256=binding.receipts_sha256))+b'\n'


def _parse_policy_response(data,encoded):
    try:
        if type(data) is not bytes or len(data)>4096:_fail('RESPONSE')
        value=json.loads(data,object_pairs_hook=_pairs)
        if type(value) is not dict or set(value)!={'schema','phase','profile','request_sha256','registry_sha256','receipts_sha256'}:
            _fail('RESPONSE')
        if (type(value['schema']) is not int or value['schema']!=2
                or value['phase']!='consumer-preinstall' or value['profile']!=_PROFILE):_fail('RESPONSE')
        binding=ContextBinding(value['registry_sha256'],value['receipts_sha256'])
        if data!=_policy_response(encoded,binding):_fail('RESPONSE')
        return PolicyContextObservation(_PROFILE,binding)
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):_fail('RESPONSE')


def observe_installed_policy_context(*,deadline):
    """Observe policy/context prerequisites, permitting absent consumer files.

    The finite caller deadline also needs an external hard owner. Parent clock
    checks cannot interrupt filesystem calls. More than 130 seconds must remain
    before the 120-second child and its 10-second settlement allowance.
    No deployed-file/default/local-override readiness is established. Result
    ends at package lock release: future mutation phases must retain their own
    single lease, not nest this public gate or reuse its stale return value.
    Activation/context leases belong to that child, never this parent scope.
    """
    if not _finite(deadline):_fail('DEADLINE')
    started=time.monotonic()
    def check(reserve=0):
        if time.monotonic()+reserve>=deadline:_fail('DEADLINE')
    check(130)
    try:
        _preconditions()
        from qshd_selinux_package_state import production
        from qshd_selinux_reference_loader import production_references
        pending=False
        with production().operation():
            with production_references() as reader:
                check(130)
                captured=reader.capture()
                check(130)
                try:
                    result=_observe_policy_context(captured.artifact,deadline=deadline,_started=started)
                except ObserverError as error:
                    if str(error)!='ACTIVATION_PENDING':raise
                    pending=True
                check()
                reader.recheck(captured)
                check()
        check()
        if pending:_fail('ACTIVATION_PENDING')
        return result
    except ObserverError:raise
    except _CommandError as error:
        raise ObserverError('CALLER_PROCESS') from error
    except Exception as error:
        raise ObserverError('INSTALLED_REFUSED') from error


def _observe_policy_context(trusted_artifact,*,deadline=None,_started=None):
    """Real fixed child; caller authority/exclusion is an explicit precondition.

    The deterministic request digest correlates public input only. Fresh owned
    process/pipes supply invocation binding; this is no durable replay receipt.
    """
    started,work_end=_bounds(deadline,_started)
    encoded=_policy_request(trusted_artifact)
    owner=None
    try:
        owner=_Owner(_Limits(120,4096))
        streams=owner._run(('/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),_POLICY_MODE,encoded,repr(started),repr(work_end)),
                           '/',deadline=started+_SECONDS)
        last=owner._last
        if (type(streams) is not _Streams or type(streams.stdout) is not bytes or type(streams.stderr) is not bytes
                or not _normal_outcome(last) or last.exit_code!=0 or streams.stderr):_fail('OBSERVATION_REFUSED')
        result=_parse_policy_response(streams.stdout,encoded)
        if time.monotonic()>=started+_SECONDS:_fail('DEADLINE')
        return result
    except _CommandError as error:
        code=str(error)
        if code=='TOOL_FAILURE' and owner is not None:
            # A normal exit1 has no recorded owner failure. Parent-side OSError
            # may use TOOL_FAILURE provenance and must never be reclassified.
            if time.monotonic()>=started+_SECONDS:_fail('DEADLINE')
            outcome=owner._last
            if (_normal_outcome(outcome) and outcome.exit_code==1
                    and outcome.settled and not outcome.unreaped and outcome.stdout==b''
                    and outcome.stderr==_pending_record(encoded)):
                if time.monotonic()>=started+_SECONDS:_fail('DEADLINE')
                _fail('ACTIVATION_PENDING')
        if code=='COMMAND_TIMEOUT':_fail('DEADLINE')
        if code in ('COMMAND_CUSTODY','COMMAND_UNSETTLED','OUTPUT_INCOMPLETE','PROCESS_OWNER'):_fail('CUSTODY')
        if code.startswith('PROCESS_'):_fail('CALLER_PROCESS')
        _fail('CHILD_REFUSED')
    except OSError:_fail('CHILD_REFUSED')

def _compose_policy_context(trust,*,deadline):
    # Imports instantiate no policy engine until the explicit child mode runs.
    import qshd_selinux_activation_state as state
    import qshd_selinux_registry as registry_module
    import qshd_selinux_transaction as transaction
    import qshd_selinux_module_observer as modules
    import qshd_selinux_queries as queries
    from qshd_selinux_api import SelinuxApi
    api=SelinuxApi()
    pending=False
    with _within(state.production().inspection(),deadline) as slot:
        with _within(registry_module.production().inspection(),deadline) as registry:
            routing=registry.routing()
            identities=json.loads(routing,object_pairs_hook=_pairs)
            with _within(transaction.production(list(identities)).inspection(identities),deadline) as contexts:
                with _within(modules.production_observer(trust,deadline=deadline),deadline) as module:
                    with _within(queries.required_observation(api),deadline):
                        activation=slot.capture()
                        discovered=registry.capture()
                        context=contexts.capture()
                        selected=module.capture()
                        if discovered.registry_bytes!=routing or context.registry_bytes!=routing:
                            _fail('REGISTRY_BINDING')
                        binding=ContextBinding(context.registry_sha256,context.receipts_sha256)
                        try:require_complete(activation.record,trust,binding)
                        except ActivationError as error:
                            if str(error)!='ACTIVATION_PENDING':raise
                            pending=True
                        slot.recheck(activation)
                        module.recheck(selected)
                        registry.recheck(discovered)
                        contexts.recheck(context)
    # Deferred refusal lets native post-yield checks and every finalizer run
    # normally. Any failure there supersedes the selected pending diagnostic.
    _check(deadline)
    if pending:raise _PendingRefusal()
    return binding


def _policy_main():
    try:
        if len(sys.argv)!=5 or sys.argv[1]!=_POLICY_MODE:_fail('PROTOCOL')
        trust=_parse_policy_request(sys.argv[2])
        if os.geteuid()!=0:_fail('ROOT_REQUIRED')
        _preconditions()
        end=_child_end(sys.argv[3:]);binding=_compose_policy_context(trust,deadline=end)
        sys.stdout.buffer.write(_policy_response(sys.argv[2],binding));sys.stdout.buffer.flush()
    except _PendingRefusal:
        sys.stderr.buffer.write(_pending_record(sys.argv[2]));sys.stderr.buffer.flush()
        return 1
    except Exception:
        sys.stderr.write('OBSERVATION_REFUSED\n')
        return 1
    return 0



if __name__=='__main__':
    if len(sys.argv)==5 and sys.argv[1]==_POLICY_MODE:raise SystemExit(_policy_main())
    raise SystemExit(_main())
