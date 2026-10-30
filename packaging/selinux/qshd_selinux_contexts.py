"""Pure SELinux context-row plans. Callers own locking, journals and file metadata.

Receipts describe ownership, not authenticity. Persist a durable before/after
journal before applying a plan; never infer recovery from orphan marker blocks.
Source or package drift requires explicit removal followed by reconciliation.
"""
from hashlib import sha256
import json
import posixpath
import re

MAX_CONTENT = 1024 * 1024
PREFIX = b'# qshd-context-row '


class ReconcileError(ValueError):
    """A conflict that leaves the supplied bytes and receipt unchanged."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _fail(code):
    raise ReconcileError(code)


def _digest(value):
    return sha256(value).hexdigest()


def _identity(value):
    if not isinstance(value, dict) or set(value) != {'path', 'source_type', 'original_package'}:
        _fail('IDENTITY_INVALID')
    if any(not isinstance(v, str) or not v or len(v) > 4096 or any(ord(c) < 32 for c in v) for v in value.values()):
        _fail('IDENTITY_INVALID')
    path = value['path']
    if not path.startswith('/') or path.startswith('//') or path == '/' or posixpath.normpath(path) != path or value['source_type'] != 'sshd_t':
        _fail('IDENTITY_INVALID')


def _lines(content):
    if not isinstance(content, bytes) or len(content) > MAX_CONTENT:
        _fail('CONTENT_INVALID')
    return content.splitlines(keepends=True)


def _rows(content, kind):
    result = []
    for index, line in enumerate(_lines(content)):
        fields = line.strip().split()
        if not fields or fields[0].startswith(b'#'):
            continue
        parts = fields[0].split(b':')
        if len(parts) >= 2 and parts[:2] == [b'system_r', kind]:
            if b'\r' in line or len(fields) < 2:
                _fail('ROW_MALFORMED')
            for field in fields:
                if not re.fullmatch(rb'[A-Za-z0-9_]+:[A-Za-z0-9_]+:[A-Za-z0-9_.,:-]+', field):
                    _fail('ROW_MALFORMED')
            result.append((index, line, fields))
    if len(result) > 1:
        _fail('ROW_DUPLICATE')
    return result


def _new_row(source):
    fields = source.strip().split()
    return b'system_r:qshd_t:' + fields[0].split(b':', 2)[2] + b'\t' + b' '.join(fields[1:]) + b'\n'


def _marker(identity, original_sha256, row):
    encoded = json.dumps(identity, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return _digest(encoded + b'\0' + original_sha256.encode('ascii') + b'\0' + row)[:20]


def _block(marker, row):
    return PREFIX + b'begin ' + marker.encode('ascii') + b'\n' + row + PREFIX + b'end ' + marker.encode('ascii') + b'\n'


def _receipt(receipt):
    if not isinstance(receipt, dict):
        _fail('RECEIPT_INVALID')
    base = {'schema_version', 'owner', 'identity'}
    owner = receipt.get('owner')
    fields = {'row', 'row_sha256'} if owner == 'administrator' else {'block', 'block_sha256', 'source_row', 'source_row_sha256', 'original_sha256', 'after_sha256', 'marker_id'}
    if owner not in ('administrator', 'qshd') or set(receipt) != base | fields or type(receipt.get('schema_version')) is not int or receipt['schema_version'] != 1:
        _fail('RECEIPT_INVALID')
    _identity(receipt['identity'])
    for key in fields:
        value = receipt[key]
        if not isinstance(value, str) or not value or len(value) > MAX_CONTENT:
            _fail('RECEIPT_INVALID')
        if key.endswith('sha256') and not re.fullmatch('[0-9a-f]{64}', value):
            _fail('RECEIPT_INVALID')
    try:
        if owner == 'administrator':
            row = receipt['row'].encode('ascii')
            found = _rows(row, b'qshd_t')
            if len(found) != 1 or found[0][1] != row or len(_lines(row)) != 1 or _digest(row) != receipt['row_sha256']:
                _fail('RECEIPT_INVALID')
        else:
            source = receipt['source_row'].encode('ascii')
            block = receipt['block'].encode('ascii')
            found = _rows(source, b'sshd_t')
            if len(found) != 1 or found[0][1] != source or len(_lines(source)) != 1 or not source.endswith(b'\n'):
                _fail('RECEIPT_INVALID')
            if receipt['marker_id'] != _marker(receipt['identity'], receipt['original_sha256'], _new_row(source)) or block != _block(receipt['marker_id'], _new_row(source)) or _digest(block) != receipt['block_sha256'] or _digest(source) != receipt['source_row_sha256']:
                _fail('RECEIPT_INVALID')
    except UnicodeError:
        _fail('RECEIPT_INVALID')


def _owned(content, receipt):
    """Validate all reserved markers and the exact owned block, if any."""
    markers = [line for line in _lines(content) if PREFIX.strip() in line]
    if receipt is None or receipt['owner'] == 'administrator':
        if markers:
            _fail('OWNED_RECEIPT_MISSING')
        return
    block = receipt['block'].encode('ascii')
    expected = [line for line in _lines(block) if PREFIX.strip() in line]
    if markers != expected or content.count(block) != 1:
        _fail('OWNED_BLOCK_CHANGED')
    found = _rows(content, b'qshd_t')
    if len(found) != 1 or found[0][1] != _new_row(receipt['source_row'].encode('ascii')):
        _fail('OWNED_BLOCK_CHANGED')


def plan_reconcile(content: bytes, receipt: dict | None, identity: dict) -> tuple[bytes, dict]:
    """Plan installation or verify unchanged ownership; refuse implicit updates."""
    _identity(identity)
    _lines(content)
    if receipt is not None:
        _receipt(receipt)
        if receipt['identity'] != identity:
            _fail('IDENTITY_CHANGED')
    _owned(content, receipt)
    current = _rows(content, b'qshd_t')
    if current and (receipt is None or receipt['owner'] == 'administrator'):
        row = current[0][1]
        if receipt is not None and receipt['row_sha256'] != _digest(row):
            _fail('ADMIN_ROW_CHANGED')
        return content, {'schema_version': 1, 'owner': 'administrator', 'identity': dict(identity), 'row': row.decode('ascii'), 'row_sha256': _digest(row)}
    if receipt is not None and receipt['owner'] == 'administrator':
        _fail('ADMIN_ROW_MISSING')
    source = _rows(content, b'sshd_t')
    if not source:
        _fail('SOURCE_ROW_MISSING')
    index, source_line, _ = source[0]
    if receipt is not None:
        if _digest(source_line) != receipt['source_row_sha256']:
            _fail('SOURCE_ROW_CHANGED')
        return content, receipt
    if not content.endswith(b'\n') or b'\r' in source_line:
        _fail('FINAL_NEWLINE_REQUIRED')
    row = _new_row(source_line)
    marker = _marker(identity, _digest(content), row)
    block = _block(marker, row)
    lines = _lines(content)
    lines.insert(index + 1, block)
    after = b''.join(lines)
    return after, dict(schema_version=1, owner='qshd', identity=dict(identity), block=block.decode('ascii'), block_sha256=_digest(block), source_row=source_line.decode('ascii'), source_row_sha256=_digest(source_line), marker_id=marker, original_sha256=_digest(content), after_sha256=_digest(after))


def plan_remove(content: bytes, receipt: dict | None) -> tuple[bytes, None]:
    """Remove only an exact receipt-owned block; preserve all unowned bytes."""
    _lines(content)
    if receipt is not None:
        _receipt(receipt)
    _owned(content, receipt)
    if receipt is None:
        return content, None
    if receipt['owner'] == 'administrator':
        current = _rows(content, b'qshd_t')
        if len(current) != 1 or _digest(current[0][1]) != receipt['row_sha256']:
            _fail('ADMIN_ROW_CHANGED')
        return content, None
    return content.replace(receipt['block'].encode('ascii'), b'', 1), None


def check_current(content: bytes, receipt: dict | None, identity: dict) -> bool:
    """Read-only coverage verification; conflicts raise ReconcileError."""
    proposed, _ = plan_reconcile(content, receipt, identity)
    return proposed == content
