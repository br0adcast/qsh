"""Owned managed-prestart partial evidence; no package hooks or state writes.

Trusted caller supplies independent artifact/PAM authority and holds outer package
exclusion through return. It must satisfy the shared owner's single-thread,
child-free, finite-resource/default-SIGCHLD contract and permit subreaper setup.
It must not hold activation/context leases needed by the fresh child. Evidence
ends at lock release; this API never authorizes startup or package installation.
"""
import base64
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import sys
import time

if __name__=='__main__':
    sys.path.insert(0,str(Path(__file__).resolve().parent))

from qshd_selinux_activation import TrustedArtifact, ContextBinding, ActivationError, require_complete
from qshd_selinux_process import _Owner, _Limits, _CommandError, _preconditions

_PROFILE='fedora44-targeted-v1'
_MODE='_managed_prestart_v1'
_SECONDS=60
_PAM_SHA='61dc7f9dc6ada9a612a66b1bfda1f8d1802ec9734a9325edc4f600b0e55622c7'


class ObserverError(ValueError):
    """Bounded refusal without paths, child output or private contents."""


def _fail(code):raise ObserverError(code)


class _PendingRefusal(Exception):
    """Only require_complete may select this after successful outer exits."""


def _pending_record(encoded):
    return _json(dict(schema=1,error='ACTIVATION_PENDING',
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
    encoded=base64.b64encode(_json(dict(schema=1,artifact=asdict(trust),pam_base64=base64.b64encode(pam).decode('ascii')))).decode('ascii')
    if len(encoded)>8192:_fail('PROTOCOL')
    return encoded


def _parse_request(encoded):
    try:
        if type(encoded) is not str or len(encoded)>8192:_fail('PROTOCOL')
        raw=base64.b64decode(encoded,validate=True)
        if base64.b64encode(raw).decode('ascii')!=encoded:_fail('PROTOCOL')
        value=json.loads(raw,object_pairs_hook=_pairs)
        if type(value) is not dict or set(value)!={'schema','artifact','pam_base64'} or type(value['schema']) is not int or value['schema']!=1:
            _fail('PROTOCOL')
        artifact=value['artifact']
        if type(artifact) is not dict or set(artifact)!={'provider_version','manifest_sha256','pp_sha256'}:_fail('PROTOCOL')
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
    return _json(dict(schema=1,phase='managed-prestart',profile=_PROFILE,
        request_sha256=hashlib.sha256(encoded.encode('ascii')).hexdigest(),
        registry_sha256=binding.registry_sha256,receipts_sha256=binding.receipts_sha256))+b'\n'


def _parse_response(data,encoded):
    try:
        if type(data) is not bytes or len(data)>4096:_fail('RESPONSE')
        value=json.loads(data,object_pairs_hook=_pairs)
        if type(value) is not dict or set(value)!={'schema','phase','profile','request_sha256','registry_sha256','receipts_sha256'}:
            _fail('RESPONSE')
        if type(value['schema']) is not int or value['schema']!=1 or value['phase']!='managed-prestart' or value['profile']!=_PROFILE:
            _fail('RESPONSE')
        binding=ContextBinding(value['registry_sha256'],value['receipts_sha256'])
        if data!=_response(encoded,binding):_fail('RESPONSE')
        return ManagedPrestartObservation(_PROFILE,binding)
    except (ValueError,TypeError,KeyError,UnicodeError,RecursionError):_fail('RESPONSE')


def observe_managed_prestart(trusted_artifact,expected_pam):
    """Real fixed child; caller authority/exclusion is an explicit precondition.

    The deterministic request digest correlates public input only. Fresh owned
    process/pipes supply invocation binding; this is no durable replay receipt.
    """
    started=time.monotonic()
    encoded=_request(trusted_artifact,expected_pam)
    owner=None
    try:
        owner=_Owner(_Limits(60,4096))
        streams=owner._run(('/usr/bin/python3','-I','-B',str(Path(__file__).resolve()),_MODE,encoded),
                           '/',deadline=started+_SECONDS)
        last=owner._last
        if last is None or not last.settled or last.unreaped or streams.stderr:_fail('OBSERVATION_REFUSED')
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
            if (outcome is not None and outcome.failure is None and outcome.exit_code==1
                    and outcome.settled and not outcome.unreaped and outcome.stdout==b''
                    and outcome.stderr==_pending_record(encoded)):
                if time.monotonic()>=started+_SECONDS:_fail('DEADLINE')
                _fail('ACTIVATION_PENDING')
        if code=='COMMAND_TIMEOUT':_fail('DEADLINE')
        if code in ('COMMAND_CUSTODY','COMMAND_UNSETTLED','OUTPUT_INCOMPLETE','PROCESS_OWNER'):_fail('CUSTODY')
        if code.startswith('PROCESS_'):_fail('CALLER_PROCESS')
        _fail('CHILD_REFUSED')
    except OSError:_fail('CHILD_REFUSED')


def _compose(trust,pam):
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
    with state.production().inspection() as slot:
        with registry_module.production().inspection() as registry:
            routing=registry.routing()
            identities=json.loads(routing,object_pairs_hook=_pairs)
            with transaction.production(list(identities)).inspection(identities) as contexts:
                with modules.production_observer(trust) as module:
                    with files.production(pam,api).inspection() as current_files:
                        with queries.required_observation(api):
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
    if pending:raise _PendingRefusal()
    return binding


def _main():
    try:
        if len(sys.argv)!=3 or sys.argv[1]!=_MODE:_fail('PROTOCOL')
        trust,pam=_parse_request(sys.argv[2])
        # Refuse before constructing native state or touching production paths.
        if os.geteuid()!=0:_fail('ROOT_REQUIRED')
        _preconditions()
        binding=_compose(trust,pam)
        sys.stdout.buffer.write(_response(sys.argv[2],binding));sys.stdout.buffer.flush()
    except _PendingRefusal:
        sys.stderr.buffer.write(_pending_record(sys.argv[2]));sys.stderr.buffer.flush()
        return 1
    except Exception:
        sys.stderr.write('OBSERVATION_REFUSED\n')
        return 1
    return 0


if __name__=='__main__':
    raise SystemExit(_main())
