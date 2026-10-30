#!/usr/bin/python3
"""Deterministic literal shell embedding; no package lifecycle policy is inferred.

Callers decide whether independently established unit absence is permissible.
Provider upgrade preun must be skipped by the package integrator. Rendered bytes
are shell input, not an RPM spec: macro handling belongs to package assembly.
"""
import argparse
import hashlib
from pathlib import Path
import re
import sys

PHASES = ('provider-pre', 'consumer-pre', 'provider-preun')


def delimiter(source):
    return 'QSHD_STOP_GUARD_' + hashlib.sha256(source).hexdigest()


def embed(source, phase, allow_absent=False, *, delimiter_override=None):
    if phase not in PHASES or not isinstance(allow_absent, bool):
        raise ValueError('invalid guard arguments')
    if not source or not source.endswith(b'\n') or b'\x00' in source:
        raise ValueError('source must be nonempty newline-terminated Python bytes')
    source.decode('utf-8', errors='strict')
    marker = delimiter_override if delimiter_override is not None else delimiter(source)
    if not re.fullmatch(r'[A-Z0-9_]+', marker):
        # SHA-256 uses lowercase hex; permit it only in the generated marker.
        if delimiter_override is not None or marker != delimiter(source):
            raise ValueError('invalid delimiter')
    marker_bytes = marker.encode('ascii')
    if marker_bytes in source.splitlines():
        raise ValueError('heredoc delimiter collision')
    arguments = '--phase ' + phase + (' --allow-unit-absent' if allow_absent else '')
    prefix = f"/usr/bin/python3 - {arguments} <<'{marker}'\n".encode('ascii')
    suffix = marker_bytes + b'\nqshd_guard_status=$?\nif [ "$qshd_guard_status" -ne 0 ]; then\n    exit "$qshd_guard_status"\nfi\n'
    rendered = prefix + source + suffix
    if hashlib.sha256(rendered[len(prefix):len(prefix)+len(source)]).digest() != hashlib.sha256(source).digest():
        raise ValueError('embedded source digest mismatch')
    return rendered


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--phase', required=True, choices=PHASES)
    parser.add_argument('--allow-unit-absent', action='store_true')
    args = parser.parse_args()
    source = Path(__file__).with_name('stop_guard.py').read_bytes()
    sys.stdout.buffer.write(embed(source, args.phase, args.allow_unit_absent))


if __name__ == '__main__':
    main()
