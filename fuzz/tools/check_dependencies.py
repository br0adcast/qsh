"""Check the locked fuzz graph against product source/version identities.

Features intentionally differ: fuzz disables transport defaults and adds the
libFuzzer harness, whereas the product enables runtime and platform features.
Every fuzz package shared with the product must still use a product identity.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


FUZZ_ONLY = {"qsh-channel-fuzz", "libfuzzer-sys", "arbitrary", "jobserver"}


def identity(package):
    source = package["source"]
    if source is None:
        source = str(Path(package["manifest_path"]).resolve())
    return package["version"], source


def compare(product, fuzz):
    product_ids = {}
    for package in product["packages"]:
        product_ids.setdefault(package["name"], set()).add(identity(package))
    errors = []
    for package in fuzz["packages"]:
        name = package["name"]
        if name not in product_ids:
            if name not in FUZZ_ONLY:
                errors.append(f"Unreviewed fuzz-only dependency: {name}")
        elif identity(package) not in product_ids[name]:
            errors.append(f"Product source/version mismatch: {name} {identity(package)}")
    return errors


def lock_hashes(root):
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in (root / "Cargo.lock", root / "fuzz/Cargo.lock")}


def metadata(root, manifest, offline):
    command = ["cargo", "metadata", "--format-version", "1", "--locked",
               "--manifest-path", str(root / manifest)]
    if offline:
        command.append("--offline")
    return json.loads(subprocess.check_output(command, cwd=root))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--offline", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    before = lock_hashes(root)
    product = metadata(root, "Cargo.toml", args.offline)
    fuzz = metadata(root, "fuzz/Cargo.toml", args.offline)
    errors = compare(product, fuzz)
    if lock_hashes(root) != before:
        errors.append("Cargo metadata changed a lockfile")
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    print("Locked fuzz dependencies match product source/version identities.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
