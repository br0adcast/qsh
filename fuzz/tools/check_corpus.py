#!/usr/bin/env python3
"""Check the checked-in seed inventory without executing a fuzz target."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat


def check(manifest_path, corpus_path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise ValueError("invalid manifest: expected an object")
    for field in ("maximum_seed_files", "maximum_total_bytes"):
        if type(manifest.get(field)) is not int or manifest[field] < 0:
            raise ValueError(f"invalid manifest: {field} must be a nonnegative integer")
    entries = manifest.get("files")
    if not isinstance(entries, list):
        raise ValueError("invalid manifest: files must be a list")
    expected = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid manifest: file entry must be an object")
        name = entry.get("name")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name):
            raise ValueError("invalid seed name: expected a single filename")
        if name in expected:
            raise ValueError(f"duplicate seed name: {name}")
        size = entry.get("bytes")
        digest = entry.get("sha256")
        if type(size) is not int or size < 0:
            raise ValueError(f"invalid manifest: bytes for {name}")
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError(f"invalid manifest: SHA-256 for {name}")
        expected[name] = entry
    if len(expected) > manifest["maximum_seed_files"]:
        raise ValueError("file count exceeds manifest budget")
    if sum(entry["bytes"] for entry in expected.values()) > manifest["maximum_total_bytes"]:
        raise ValueError("total bytes exceed manifest budget")
    actual = {path.name for path in corpus_path.iterdir() if path.name != "manifest.json"}
    if actual != set(expected):
        raise ValueError("file inventory mismatch")
    for name, entry in expected.items():
        path = corpus_path / name
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"not a regular file: {name}")
        if metadata.st_size != entry["bytes"]:
            raise ValueError(f"size mismatch: {name}")
        # Limit the read even if a file changes after the size check.
        with path.open("rb") as source:
            data = source.read(entry["bytes"] + 1)
        if len(data) != entry["bytes"]:
            raise ValueError(f"size mismatch: {name}")
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError(f"SHA-256 mismatch: {name}")
    return len(expected)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    try:
        count = check(args.manifest, args.corpus)
    except (OSError, ValueError) as error:
        parser.exit(1, f"Corpus check failed: {error}\n")
    print(f"Verified {count} corpus files")


if __name__ == "__main__":
    main()
