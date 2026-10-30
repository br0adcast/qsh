"""Internal representative query profile, pending Fedora query-output qualification.

This is partial query evidence, not a complete readiness gate or startup proof.
Existing I/D/E/U/T runtime witnesses retain their exact observed values. P and
computed outputs still require Fedora qualification before publication. No
receipt, store, label, PAM or package lifecycle admission is implemented here.
The caller must finish its other observers inside required_observation and
accept only after normal context-manager exit. One fresh process/adapter owns
the status window; this library cannot impose a hard native-call timeout.
"""
from contextlib import contextmanager
from dataclasses import dataclass
import re

_PROFILE_VERSION = 1
_CONTEXTS = (('I', 'system_u:system_r:init_t:s0'),
    ('D', 'system_u:system_r:qshd_t:s0'),
    ('E', 'system_u:object_r:qshd_exec_t:s0'),
    ('C', 'system_u:object_r:qshd_config_t:s0'),
    ('L', 'system_u:object_r:qshd_log_t:s0'),
    ('R', 'system_u:object_r:qshd_runtime_t:s0'),
    ('P', 'system_u:object_r:qshd_devpts_t:s0'),
    ('U', 'user_u:user_r:user_t:s0'),
    ('T', 'user_u:object_r:user_devpts_t:s0'),
    ('S', 'system_u:object_r:shell_exec_t:s0'),
    ('V', 'system_u:object_r:devpts_t:s0'))

# ID, adapter operation, symbolic operands, exact expected context symbol.
_QUERIES = (('launch-result', 'compute_create', ('I', 'E', 'process'), 'D'),
    ('launch-transition', 'require_av', ('I', 'D', 'process', ('transition',)), None),
    ('launch-execute', 'require_av', ('I', 'E', 'file', ('getattr', 'open', 'read', 'execute')), None),
    ('launch-entry', 'require_av', ('D', 'E', 'file', ('entrypoint',)), None),
    ('pam-self', 'require_av', ('D', 'D', 'process', ('setexec', 'setkeycreate', 'setsched')), None),
    ('helper-caps',
     'require_av',
     ('D', 'D', 'capability', ('setuid', 'setgid', 'chown', 'kill', 'fowner')),
     None),
    ('helper-process',
     'require_av',
     ('D', 'D', 'process', ('fork', 'sigchld', 'signal', 'sigkill', 'setpgid')),
     None),
    ('helper-socketpair',
     'require_av',
     ('D', 'D', 'unix_stream_socket', ('create', 'connectto', 'read', 'write', 'setopt', 'shutdown')),
     None),
    ('udp-self',
     'require_av',
     ('D', 'D', 'udp_socket', ('create', 'bind', 'getattr', 'read', 'write', 'getopt', 'setopt')),
     None),
    ('session-transition', 'require_av', ('D', 'U', 'process', ('transition',)), None),
    ('session-execute',
     'require_av',
     ('D', 'S', 'file', ('getattr', 'open', 'read', 'execute')),
     None),
    ('session-entry', 'require_av', ('U', 'S', 'file', ('entrypoint',)), None),
    ('pty-create-result', 'compute_create', ('D', 'V', 'chr_file'), 'P'),
    # devpts allocates the slave internally; ordinary mknod/create AV permission
    # is not required. The separate compute_create row checks its exact label.
    ('pty-owned',
     'require_av',
     ('D',
      'P',
      'chr_file',
      ('open', 'read', 'write', 'getattr', 'ioctl', 'setattr', 'relabelfrom', 'relabelto')),
     None),
    ('pty-user',
     'require_av',
     ('D',
      'T',
      'chr_file',
      ('open', 'read', 'write', 'getattr', 'ioctl', 'setattr', 'relabelfrom', 'relabelto')),
     None),
    ('pty-select-result', 'compute_relabel', ('U', 'P', 'chr_file'), 'T'),
    ('pty-select-valid', 'validate_transition', ('P', 'T', 'chr_file', 'D'), None),
    ('pty-restore-valid', 'validate_transition', ('T', 'P', 'chr_file', 'D'), None),
    ('config-dir',
     'require_av',
     ('D',
      'C',
      'dir',
      ('create', 'open', 'read', 'getattr', 'search', 'write', 'add_name', 'remove_name')),
     None),
    ('config-file',
     'require_av',
     ('D', 'C', 'file', ('create', 'open', 'read', 'write', 'getattr', 'setattr', 'rename', 'unlink')),
     None),
    ('log-dir',
     'require_av',
     ('D',
      'L',
      'dir',
      ('create', 'open', 'read', 'getattr', 'search', 'write', 'add_name', 'remove_name')),
     None),
    ('log-file',
     'require_av',
     ('D',
      'L',
      'file',
      ('create', 'open', 'read', 'write', 'append', 'getattr', 'setattr', 'rename', 'unlink')),
     None),
    ('runtime-dir',
     'require_av',
     ('D',
      'R',
      'dir',
      ('create', 'open', 'read', 'getattr', 'search', 'write', 'add_name', 'remove_name', 'rmdir')),
     None),
    ('runtime-file',
     'require_av',
     ('D', 'R', 'file', ('create', 'open', 'read', 'write', 'getattr', 'setattr', 'unlink', 'lock')),
     None),
    ('runtime-socket-file',
     'require_av',
     ('D',
      'R',
      'sock_file',
      ('create', 'open', 'read', 'write', 'getattr', 'setattr', 'rename', 'unlink')),
     None))


class QueryError(RuntimeError):
    """Fixed profile ID and category; never includes native exception text."""

    def __init__(self, query_id, category):
        self.query_id = query_id
        self.category = category
        super().__init__(f'{query_id}: {category}')


@dataclass(frozen=True)
class QueryObservation:
    """Immutable partial evidence; valid only after normal observation exit."""

    profile_version: int
    context_ids: tuple[str, ...]
    query_ids: tuple[str, ...]


def _validate_profile():
    """Check internal invariants before the first native/status operation."""
    name = re.compile(r'[A-Za-z_][A-Za-z0-9_]{0,127}\Z')
    identifier = re.compile(r'[a-z][a-z0-9-]{0,79}\Z')
    contexts = dict(_CONTEXTS)
    valid = len(contexts) == len(_CONTEXTS) and bool(contexts)
    for symbol, raw in _CONTEXTS:
        valid = valid and isinstance(symbol, str) and bool(name.fullmatch(symbol))
        valid = valid and isinstance(raw, str) and len(raw) < 4096
        valid = valid and raw.isascii() and all(32 < ord(c) < 127 for c in raw)
        parts = raw.split(':', 3)
        valid = valid and len(parts) == 4 and all(parts)
    seen = set()
    for query_id, operation, args, expected in _QUERIES:
        valid = valid and isinstance(query_id, str) and bool(identifier.fullmatch(query_id))
        valid = valid and query_id not in seen
        seen.add(query_id)
        valid = valid and operation in ('require_av', 'compute_create', 'compute_relabel', 'validate_transition')
        valid = valid and len(args) == (4 if operation in ('require_av', 'validate_transition') else 3)
        if len(args) < 3:
            raise QueryError('profile', 'invalid-profile')
        source, target, cls = args[:3]
        valid = valid and source in contexts and target in contexts
        valid = valid and isinstance(cls, str) and bool(name.fullmatch(cls))
        if operation == 'require_av':
            permissions = args[3] if len(args) == 4 else ()
            valid = valid and isinstance(permissions, tuple) and bool(permissions)
            valid = valid and len(set(permissions)) == len(permissions)
            valid = valid and all(isinstance(p, str) and name.fullmatch(p) for p in permissions)
        if operation == 'validate_transition':
            valid = valid and len(args) == 4 and args[3] in contexts
        if operation in ('compute_create', 'compute_relabel'):
            valid = valid and expected in contexts
        else:
            valid = valid and expected is None
    if not valid or not seen:
        raise QueryError('profile', 'invalid-profile')
    return contexts


@contextmanager
def required_observation(api):
    """Query once, then keep caller observers in the same required status window.

    The yielded record never means readiness. Caller and status-exit failures
    propagate; callers must not commit acceptance until this scope exits.
    """
    contexts = _validate_profile()
    with api.status_observation():
        for symbol, raw in _CONTEXTS:
            try:
                api.check_context(raw)
            except Exception:
                raise QueryError('context-' + symbol, 'query-error') from None
        for query_id, operation, args, expected in _QUERIES:
            source, target, cls = args[:3]
            actual_args = (contexts[source], contexts[target], cls)
            if operation == 'require_av':
                actual_args += (args[3],)
            elif operation == 'validate_transition':
                # Native semantic order: old object, new object, class, task.
                actual_args += (contexts[args[3]],)
            try:
                result = getattr(api, operation)(*actual_args)
            except Exception:
                raise QueryError(query_id, 'query-error') from None
            if expected is not None and result != contexts[expected]:
                raise QueryError(query_id, 'unexpected-context')
        yield QueryObservation(
            _PROFILE_VERSION,
            tuple('context-' + symbol for symbol, _ in _CONTEXTS),
            tuple(query[0] for query in _QUERIES),
        )
