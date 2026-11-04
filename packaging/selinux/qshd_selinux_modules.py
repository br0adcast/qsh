"""Pure plain semodule full-list/HLL evidence, never loaded-policy readiness.

No commands, paths, ownership checks, extraction or kernel observation occur.
The caller must separately establish trusted store/files and one bounded window.
CIL checksums and compiler-cache behavior are intentionally outside this model.
"""
from dataclasses import dataclass
import hashlib
import re

MAX_LISTING = 1024 * 1024
MAX_ROWS = 4096
MAX_ROW = 1024
MAX_HLL = 16 * 1024 * 1024


class ModuleError(ValueError):
    """Stable bounded category, without caller values or output excerpts."""


def _fail(code):
    raise ModuleError(code)


def _token(value):
    if type(value) is not str or re.fullmatch(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}', value) is None:
        _fail('INVALID_TOKEN')


def _digest(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        _fail('INVALID_DIGEST')


@dataclass(frozen=True)
class ModuleEntry:
    priority: int
    name: str
    language: str
    enabled: bool

    def __post_init__(self):
        if type(self.priority) is not int or not 1 <= self.priority <= 999:
            _fail('INVALID_PRIORITY')
        _token(self.name)
        _token(self.language)
        if type(self.enabled) is not bool:
            _fail('INVALID_ENABLED')


@dataclass(frozen=True)
class HllIdentity:
    byte_length: int
    sha256: str

    def __post_init__(self):
        if type(self.byte_length) is not int or not 1 <= self.byte_length <= MAX_HLL:
            _fail('HLL_LIMIT')
        _digest(self.sha256)


def parse_full_listing(data: bytes) -> tuple[ModuleEntry, ...]:
    """Parse complete plain 3.10 -lfull rows, never checksum-bearing output."""
    if type(data) is not bytes or len(data) > MAX_LISTING:
        _fail('LISTING_LIMIT')
    if data in (b'', b'No modules.\n'):
        return ()
    if not data.endswith(b'\n'):
        _fail('INCOMPLETE_LINE')
    if any(byte not in (9, 10) and not 32 <= byte <= 126 for byte in data):
        _fail('INVALID_ENCODING')
    lines = data[:-1].split(b'\n')
    if len(lines) > MAX_ROWS:
        _fail('ROW_LIMIT')
    entries, seen = [], set()
    for line in lines:
        if not line or len(line) > MAX_ROW:
            _fail('ROW_LIMIT')
        fields = line.split()
        if len(fields) not in (3, 4) or (len(fields) == 4 and fields[3] != b'disabled'):
            _fail('INVALID_ROW')
        if re.fullmatch(rb'[1-9][0-9]{0,2}', fields[0]) is None:
            _fail('INVALID_PRIORITY')
        entry = ModuleEntry(int(fields[0]), fields[1].decode('ascii'),
                            fields[2].decode('ascii'), len(fields) == 3)
        key = (entry.priority, entry.name)
        if key in seen:
            _fail('DUPLICATE_MODULE')
        seen.add(key)
        entries.append(entry)
    return tuple(entries)


def select_owned(entries, *, role) -> ModuleEntry:
    """Select a closed pair role, rejecting conflicts on either reserved name."""
    if type(entries) not in (list, tuple) or len(entries) > MAX_ROWS:
        _fail('INVALID_ENTRIES')
    roles={'core':'qshd','contexts':'qshd_contexts'}
    if type(role) is not str or role not in roles:_fail('INVALID_ROLE')
    seen, owned = set(), []
    reserved={name:[] for name in roles.values()}
    for entry in entries:
        if type(entry) is not ModuleEntry:
            _fail('INVALID_ENTRY')
        # Validate direct input records too, rather than silently ignoring others.
        entry.__post_init__()
        key = (entry.priority, entry.name)
        if key in seen:
            _fail('DUPLICATE_MODULE')
        seen.add(key)
        if entry.name in reserved:reserved[entry.name].append(entry)
        if entry.name==roles[role]:owned.append(entry)
    for values in reserved.values():
        if len(values)>1 or values and (values[0].priority!=400 or values[0].language!='pp' or not values[0].enabled):
            _fail('OWNED_MODULE_CONFLICT')
    if len(owned) != 1:
        _fail('OWNED_MODULE_COUNT')
    entry = owned[0]
    if entry.priority != 400 or entry.language != 'pp' or not entry.enabled:
        _fail('OWNED_MODULE_CONFLICT')
    return entry


def verify_hll(data: bytes, expected_pp_sha256: str) -> HllIdentity:
    """Hash exact supplied HLL bytes; no filename, store or loaded-policy proof."""
    if type(data) is not bytes or not 1 <= len(data) <= MAX_HLL:
        _fail('HLL_LIMIT')
    _digest(expected_pp_sha256)
    actual = hashlib.sha256(data).hexdigest()
    if actual != expected_pp_sha256:
        _fail('HLL_MISMATCH')
    return HllIdentity(len(data), actual)
