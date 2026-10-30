"""Prepare the two pinned RPM-tool crates; never build or edit package bytes."""
import argparse
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile

SOURCES = (
    ("cargo-generate-rpm-0.21.0", "3187e19f0e00274b3b24f017559038722388889bd1a2ecd2281cd748e7d52ec6"),
    ("rpm-0.23.2", "cf5c92939a06adb261d757e43f49bcdb121d62c6fe8e859b1006ce37f81e6d7f"),
)
PATCHES = (
    "rpm-0.23.2-archive-size.patch",
    "cargo-generate-rpm-0.21.0-local-rpm.patch",
    "cargo-generate-rpm-0.21.0-requires-post.patch",
    "cargo-generate-rpm-0.21.0-requires-pre.patch",
)


def extract_source(archive, checksum, name, destination):
    with archive.open("rb") as source:
        digest = hashlib.sha256()
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    if digest.hexdigest() != checksum:
        raise ValueError("source checksum mismatch: " + name)
    with tarfile.open(str(archive)) as source:
        members = source.getmembers()
        seen = set()
        for member in members:
            parts = member.name.split("/")
            if (parts[0] != name or any(part in ("", ".", "..") for part in parts)
                    or not (member.isfile() or member.isdir()) or member.name in seen):
                raise ValueError("unexpected source archive member")
            seen.add(member.name)
        destination.mkdir(parents=True, exist_ok=True)
        # Full archive checksum and the complete member list were checked first.
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with source.extractfile(member) as data, target.open("xb") as output:
                    shutil.copyfileobj(data, output)
                target.chmod(member.mode & 0o777)


def apply_patch(destination, patch):
    subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "--no-backup-if-mismatch",
                    "-p1", "-i", str(patch.resolve())], cwd=str(destination), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--cache", type=Path, help="existing crate archives, still checksum-verified")
    args = parser.parse_args()
    destination = args.destination.resolve()
    if destination.exists():
        parser.error("destination must not already exist")
    for tool in ("patch", "curl") if args.cache is None else ("patch",):
        if shutil.which(tool) is None:
            parser.error("required command not found: " + tool)
    destination.mkdir(parents=True)
    for name, checksum in SOURCES:
        if args.cache is not None:
            archive = args.cache / (name + ".crate")
        else:
            archive = destination / (name + ".crate")
            crate = name.rsplit("-", 1)[0]
            url = "https://static.crates.io/crates/{}/{}.crate".format(crate, name)
            subprocess.run(["curl", "--proto", "=https", "--tlsv1.2", "--fail", "--location",
                            "--silent", "--show-error", url, "--output", str(archive)], check=True)
        extract_source(archive, checksum, name, destination)
    for patch in PATCHES:
        apply_patch(destination, Path(__file__).resolve().parent / patch)
    print(destination / "cargo-generate-rpm-0.21.0")


if __name__ == "__main__":
    main()
