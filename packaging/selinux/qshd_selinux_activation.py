"""Strict pair historical evidence, never current installed-state readiness.

Signed provider references supply independent identities. Parsing and matching a
record do not observe modules, files, contexts or a stable native status window.
"""
from dataclasses import dataclass
import json
import re


class ActivationError(ValueError):
    """Stable bounded category without caller values or JSON excerpts."""


def _fail(code):raise ActivationError(code)


def _hash(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None:_fail('INVALID_DIGEST')


def _fixed(value,expected):
    if type(value) is not type(expected) or value!=expected:_fail('UNSUPPORTED_PROFILE')


def _object(value,keys):
    if type(value) is not dict or set(value)!=set(keys.split()):_fail('INVALID_SCHEMA')
    return value


@dataclass(frozen=True)
class TrustedArtifact:
    provider_version: str
    manifest_sha256: str
    core_pp_sha256: str
    contexts_pp_sha256: str

    def __post_init__(self):
        if type(self.provider_version) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}',self.provider_version) is None:_fail('INVALID_VERSION')
        for value in (self.manifest_sha256,self.core_pp_sha256,self.contexts_pp_sha256):_hash(value)


@dataclass(frozen=True)
class ContextBinding:
    registry_sha256: str
    receipts_sha256: str

    def __post_init__(self):
        _hash(self.registry_sha256);_hash(self.receipts_sha256)


@dataclass(frozen=True)
class ModuleIdentity:
    name: str
    priority: int
    store: str
    format: str

    def __post_init__(self):
        if type(self.name) is not str or self.name not in ('qshd','qshd_contexts'):_fail('UNSUPPORTED_PROFILE')
        for actual,expected in ((self.priority,400),(self.store,'targeted'),(self.format,'pp')):_fixed(actual,expected)


@dataclass(frozen=True)
class ModulePair:
    core: ModuleIdentity
    contexts: ModuleIdentity

    def __post_init__(self):
        for value,name in ((self.core,'qshd'),(self.contexts,'qshd_contexts')):
            if type(value) is not ModuleIdentity or value.name!=name:_fail('INVALID_MODULE_ROLE')


@dataclass(frozen=True)
class PairDigests:
    core: str
    contexts: str

    def __post_init__(self):
        _hash(self.core);_hash(self.contexts)


@dataclass(frozen=True)
class Completion:
    load: str
    extracted_hll_sha256: PairDigests
    contexts: ContextBinding

    def __post_init__(self):
        _fixed(self.load,'normal-pair-install-reload-v2')
        if type(self.extracted_hll_sha256) is not PairDigests or type(self.contexts) is not ContextBinding:_fail('INVALID_SCHEMA')


def _matching(completion,artifact):
    if completion.extracted_hll_sha256!=PairDigests(artifact.core_pp_sha256,artifact.contexts_pp_sha256):_fail('HLL_MISMATCH')


@dataclass(frozen=True)
class HistoricalBasis:
    artifact: TrustedArtifact
    completion: Completion

    def __post_init__(self):
        if type(self.artifact) is not TrustedArtifact or type(self.completion) is not Completion:_fail('INVALID_BASIS')
        _matching(self.completion,self.artifact)


_INTENTS=('provider-fresh','provider-refresh','consumer-install','consumer-erase','provider-erase')


@dataclass(frozen=True)
class Activation:
    schema: int
    state: str
    operation_id: str
    profile: str
    abi: int
    query_profile: int
    artifact: TrustedArtifact
    modules: ModulePair
    intent: str
    basis: HistoricalBasis | None
    completion: Completion | None

    def __post_init__(self):
        for actual,expected in ((self.schema,2),(self.profile,'fedora44-targeted-pair-v2'),(self.abi,2),(self.query_profile,1)):_fixed(actual,expected)
        if type(self.operation_id) is not str or re.fullmatch('[0-9a-f]{32}',self.operation_id) is None:_fail('INVALID_OPERATION')
        if type(self.artifact) is not TrustedArtifact or type(self.modules) is not ModulePair:_fail('INVALID_SCHEMA')
        if type(self.intent) is not str or self.intent not in _INTENTS:_fail('INVALID_INTENT')
        if type(self.state) is not str or self.state not in ('PENDING','COMPLETE'):_fail('INVALID_STATE')
        if self.state=='PENDING':
            if self.completion is not None:_fail('INVALID_COMPLETION')
            if self.intent=='provider-fresh':
                if self.basis is not None:_fail('INVALID_BASIS')
            elif type(self.basis) is not HistoricalBasis:_fail('INVALID_BASIS')
        else:
            if self.basis is not None:_fail('INVALID_BASIS')
            if type(self.completion) is not Completion:_fail('INVALID_COMPLETION')
            _matching(self.completion,self.artifact)


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:_fail('DUPLICATE_KEY')
        result[key]=value
    return result


def _constant(_):_fail('INVALID_JSON')


def _artifact(value):return TrustedArtifact(**_object(value,'provider_version manifest_sha256 core_pp_sha256 contexts_pp_sha256'))


def _completion(value):
    value=_object(value,'load extracted_hll_sha256 contexts')
    return Completion(value['load'],PairDigests(**_object(value['extracted_hll_sha256'],'core contexts')),
                      ContextBinding(**_object(value['contexts'],'registry_sha256 receipts_sha256')))


def parse_activation(data: bytes) -> Activation:
    """Parse bounded strict schema2; reject legacy evidence without migration."""
    if type(data) is not bytes or len(data)>65536:_fail('DOCUMENT_LIMIT')
    try:value=json.loads(data.decode('utf-8'),object_pairs_hook=_pairs,parse_constant=_constant)
    except (UnicodeError,json.JSONDecodeError,RecursionError,ValueError) as error:
        if isinstance(error,ActivationError):raise
        raise ActivationError('INVALID_JSON') from None
    root=_object(value,'schema state operation_id profile abi query_profile artifact modules intent basis completion')
    artifact=_artifact(root['artifact'])
    roles=_object(root['modules'],'core contexts')
    modules=ModulePair(*(ModuleIdentity(**_object(roles[role],'name priority store format')) for role in ('core','contexts')))
    completion=None if root['completion'] is None else _completion(root['completion'])
    basis=root['basis']
    if basis is not None:
        basis=_object(basis,'artifact completion')
        basis=HistoricalBasis(_artifact(basis['artifact']),_completion(basis['completion']))
    return Activation(root['schema'],root['state'],root['operation_id'],root['profile'],root['abi'],root['query_profile'],artifact,modules,root['intent'],basis,completion)


def require_complete(record: Activation,trusted_artifact: TrustedArtifact,trusted_context_binding: ContextBinding) -> Activation:
    """Match partial historical evidence only; PENDING never becomes readiness."""
    if type(record) is not Activation:_fail('INVALID_RECORD')
    if record.state=='PENDING':_fail('ACTIVATION_PENDING')
    if type(trusted_artifact) is not TrustedArtifact or type(trusted_context_binding) is not ContextBinding:_fail('INVALID_TRUSTED_INPUT')
    if record.artifact!=trusted_artifact:_fail('ARTIFACT_MISMATCH')
    if record.completion.contexts!=trusted_context_binding:_fail('CONTEXT_BINDING_MISMATCH')
    _matching(record.completion,trusted_artifact)
    return record
