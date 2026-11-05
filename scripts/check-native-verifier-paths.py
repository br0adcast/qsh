#!/usr/bin/env python3
"""Reject build prefixes in whole verifier bytes; report only fixed metadata."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

CATEGORIES = ("workspace", "cargo_home", "runner_temp")
MAX_NM_BYTES = 32 * 1024 * 1024
STAB_TYPES = frozenset(
    b"GSYM FNAME FUN STSYM LCSYM BNSYM PC AST OPT RSYM SLINE ENSYM SSYM SO OSO LIB "
    b"LSYM BINCL SOL PARAM VERS OLEV PSYM EINCL ENTRY LBRAC EXCL RBRAC BCOMM ECOMM ECOML LENG".split())
# BSD debugger rows expose section, descriptor and STAB type before the name.
STAB_ROW = re.compile(rb"^[0-9a-fA-F]{8}(?:[0-9a-fA-F]{8})?[ \t]+-[ \t]+[0-9a-fA-F]{2}[ \t]+[0-9a-fA-F]{4}[ \t]+([A-Z]+)(?: (.*))?$")
SYMBOL_ROW = re.compile(rb"^(?:[0-9a-fA-F]{8}(?:[0-9a-fA-F]{8})?|[ \t]+)[ \t]+[A-Za-z] (.*)$")


def _nm_status(status):
    return {"nm_status": status, "oso_records": None, "unparsed_rows": None,
            "oso_records_with_prefix": None, "other_symbol_records_with_prefix": None}


def _parse_nm(data, prefixes):
    oso, other = dict.fromkeys(CATEGORIES, 0), dict.fromkeys(CATEGORIES, 0)
    records = unparsed = 0
    for line in data.split(b"\n"):
        if not line.strip():
            continue
        match = STAB_ROW.fullmatch(line)
        if match and match[1] in STAB_TYPES:
            is_oso = match[1] == b"OSO"
            name = match[2] or b""
            records += int(is_oso)
        else:
            match = SYMBOL_ROW.fullmatch(line)
            if not match:
                unparsed += 1
                continue
            is_oso, name = False, match[1]
        counts = oso if is_oso else other
        for category, prefix in zip(CATEGORIES, prefixes):
            counts[category] += int(prefix in name)
    # Counts describe recognized records only; partial output is not complete
    # attribution. Symbol records and whole-artifact byte occurrences differ.
    return {"nm_status": "partial" if unparsed else "ok", "oso_records": records,
            "unparsed_rows": unparsed, "oso_records_with_prefix": oso,
            "other_symbol_records_with_prefix": other}


def _nm_diagnostics(binary, prefixes):
    try:
        # An unnamed/private file is closed and removed on every return/exception.
        # Never send nm output, symbol names or exception details to either stream.
        with tempfile.TemporaryFile(mode="w+b") as output:
            try:
                result = subprocess.run(["/usr/bin/nm", "-pa", binary], stdin=subprocess.DEVNULL,
                                        stdout=output, stderr=subprocess.DEVNULL, timeout=15,
                                        env={**os.environ, "LC_ALL": "C"}, check=False)
            except FileNotFoundError:
                return _nm_status("unavailable")
            if result.returncode != 0:
                return _nm_status("failed")
            if os.fstat(output.fileno()).st_size > MAX_NM_BYTES:
                return _nm_status("oversize")
            output.seek(0)
            return _parse_nm(output.read(MAX_NM_BYTES), prefixes)
    except subprocess.TimeoutExpired:
        # subprocess.run kills and waits for its direct child before raising.
        return _nm_status("timeout")
    except OSError:
        return _nm_status("io_error")


def main(args=None):
    args = sys.argv[1:] if args is None else args
    if len(args) != 4 or any(not arg for arg in args):
        print("release verifier path check refused: invalid_input", file=sys.stderr)
        return 1
    try:
        prefixes = tuple(os.fsencode(prefix) for prefix in args[1:])
    except (ValueError, UnicodeError):
        print("release verifier path check refused: invalid_input", file=sys.stderr)
        return 1
    try:
        data = Path(args[0]).read_bytes()
    except (OSError, ValueError):
        print("release verifier path check refused: unreadable_artifact", file=sys.stderr)
        return 1
    # This whole-artifact predicate is independent of all symbol diagnostics.
    # Each category is independent, including equal/overlapping prefixes.
    counts = {category + "_occurrences": data.count(prefix)
              for category, prefix in zip(CATEGORIES, prefixes)}
    if not any(counts.values()):
        return 0
    report = {"binary_sha256": hashlib.sha256(data).hexdigest(), "binary_bytes": len(data), **counts}
    report.update(_nm_diagnostics(args[0], prefixes) if sys.platform == "darwin"
                  else _nm_status("not_requested"))
    print(json.dumps(report, sort_keys=True, separators=(",", ":")), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
