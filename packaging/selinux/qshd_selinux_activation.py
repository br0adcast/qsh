"""Pure historical controlled-load evidence, never a readiness decision.

Receipt parsing validates no current module, kernel, context, file authority or
status window. Future trusted package readers supply independent identities;
filesystem persistence, exclusion and observation belong to later integration.
"""
from dataclasses import dataclass
import json
import re


class ActivationError(ValueError):
    """Stable bounded category without caller values or JSON excerpts."""


def _fail(code):
    raise ActivationError(code)


def _hash(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        _fail('INVALID_DIGEST')


@dataclass(frozen=True)
class TrustedArtifact:
    provider_version: str
    manifest_sha256: str
    pp_sha256: str

    def __post_init__(self):
        if type(self.provider_version) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.+_-]{0,79}', self.provider_version) is None:
            _fail('INVALID_VERSION')
        _hash(self.manifest_sha256)
        _hash(self.pp_sha256)


@dataclass(frozen=True)
class ContextBinding:
    registry_sha256: str
    receipts_sha256: str

    def __post_init__(self):
        _hash(self.registry_sha256)
        _hash(self.receipts_sha256)


@dataclass(frozen=True)
class ModuleIdentity:
    name: str
    priority: int
    store: str
    format: str

    def __post_init__(self):
        for actual, expected in ((self.name, 'qshd'), (self.priority, 400),
                                 (self.store, 'targeted'), (self.format, 'pp')):
            _fixed(actual, expected)


@dataclass(frozen=True)
class Completion:
    load: str
    extracted_hll_sha256: str
    contexts: ContextBinding

    def __post_init__(self):
        _fixed(self.load, 'normal-install-reload-v1')
        _hash(self.extracted_hll_sha256)
        if type(self.contexts) is not ContextBinding:
            _fail('INVALID_SCHEMA')


@dataclass(frozen=True)
class Activation:
    schema: int
    state: str
    operation_id: str
    profile: str
    abi: int
    query_profile: int
    artifact: TrustedArtifact
    module: ModuleIdentity
    completion: Completion | None

    def __post_init__(self):
        for actual, expected in ((self.schema, 1), (self.profile, 'fedora44-targeted-v1'),
                                 (self.abi, 1), (self.query_profile, 1)):
            _fixed(actual, expected)
        if type(self.operation_id) is not str or re.fullmatch('[0-9a-f]{32}', self.operation_id) is None:
            _fail('INVALID_OPERATION')
        if type(self.artifact) is not TrustedArtifact or type(self.module) is not ModuleIdentity:
            _fail('INVALID_SCHEMA')
        if type(self.state) is not str or self.state not in ('PENDING', 'COMPLETE'):
            _fail('INVALID_STATE')
        if self.state == 'PENDING':
            if self.completion is not None:
                _fail('INVALID_COMPLETION')
        elif type(self.completion) is not Completion:
            _fail('INVALID_COMPLETION')
        elif self.completion.extracted_hll_sha256 != self.artifact.pp_sha256:
            _fail('HLL_MISMATCH')


def _object(value, keys):
    if type(value) is not dict or set(value) != set(keys.split()):
        _fail('INVALID_SCHEMA')
    return value


def _fixed(value, expected):
    if type(value) is not type(expected) or value != expected:
        _fail('UNSUPPORTED_PROFILE')


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            _fail('DUPLICATE_KEY')
        result[key] = value
    return result


def _constant(_):
    _fail('INVALID_JSON')


def parse_activation(data: bytes) -> Activation:
    """Parse bounded UTF8 evidence; does not observe any live or stored state."""
    if type(data) is not bytes or len(data) > 65536:
        _fail('DOCUMENT_LIMIT')
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=_constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        if isinstance(error, ActivationError):
            raise
        raise ActivationError('INVALID_JSON') from None
    root = _object(value, 'schema state operation_id profile abi query_profile artifact module completion')
    for key, expected in (('schema', 1), ('profile', 'fedora44-targeted-v1'),
                          ('abi', 1), ('query_profile', 1)):
        _fixed(root[key], expected)
    if type(root['state']) is not str or root['state'] not in ('PENDING', 'COMPLETE'):
        _fail('INVALID_STATE')
    if type(root['operation_id']) is not str or re.fullmatch('[0-9a-f]{32}', root['operation_id']) is None:
        _fail('INVALID_OPERATION')
    artifact = TrustedArtifact(**_object(root['artifact'], 'provider_version manifest_sha256 pp_sha256'))
    module = _object(root['module'], 'name priority store format')
    for key, expected in (('name', 'qshd'), ('priority', 400), ('store', 'targeted'), ('format', 'pp')):
        _fixed(module[key], expected)
    completion = root['completion']
    if root['state'] == 'PENDING':
        if completion is not None:
            _fail('INVALID_COMPLETION')
    else:
        completion = _object(completion, 'load extracted_hll_sha256 contexts')
        _fixed(completion['load'], 'normal-install-reload-v1')
        _hash(completion['extracted_hll_sha256'])
        if completion['extracted_hll_sha256'] != artifact.pp_sha256:
            _fail('HLL_MISMATCH')
        binding = ContextBinding(**_object(completion['contexts'], 'registry_sha256 receipts_sha256'))
        completion = Completion(completion['load'], completion['extracted_hll_sha256'], binding)
    return Activation(root['schema'], root['state'], root['operation_id'], root['profile'],
                      root['abi'], root['query_profile'], artifact,
                      ModuleIdentity(**module), completion)


def require_complete(record: Activation, trusted_artifact: TrustedArtifact,
                     trusted_context_binding: ContextBinding) -> Activation:
    """Return partial historical evidence, never current-state authority/readiness.

    PENDING dominates even a matching artifact. No promotion, repair or fallback.
    Caller must supply a parsed record and independent validated trusted values.
    """
    if type(record) is not Activation:
        _fail('INVALID_RECORD')
    if record.state == 'PENDING':
        _fail('ACTIVATION_PENDING')
    if type(trusted_artifact) is not TrustedArtifact or type(trusted_context_binding) is not ContextBinding:
        _fail('INVALID_TRUSTED_INPUT')
    if record.artifact != trusted_artifact:
        _fail('ARTIFACT_MISMATCH')
    if record.completion.contexts != trusted_context_binding:
        _fail('CONTEXT_BINDING_MISMATCH')
    if record.completion.load != 'normal-install-reload-v1' or record.completion.extracted_hll_sha256 != trusted_artifact.pp_sha256:
        _fail('INVALID_COMPLETION')
    return record
