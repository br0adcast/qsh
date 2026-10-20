# Pinned RPM packaging tool

`install.sh` installs `cargo-generate-rpm 0.21.0` with a narrow source patch
for its locked `rpm 0.23.2` dependency. Client and daemon packaging must use
this same installer. It requires Bash, Python 3.6 or newer, curl, GNU patch,
and the selected Rust toolchain. It preserves `CARGO_HOME` and Cargo's normal
installation directory.

The upstream V4 builder already counts finalized uncompressed CPIO bytes,
including entry alignment and the trailer, but does not write that archive
size into the signature header. RPM 4.18.2's `rpm2cpio` compares this field
with its decoded byte count and fails when the field is missing. The patch
writes the 32-bit legacy size or its 64-bit counterpart, preserves the value
when rebuilding signatures, and leaves V6 metadata unchanged. It does not
rewrite generated RPM bytes or relax decoder, digest, or payload checks.

The installer verifies both published crate archives against their SHA-256
pins before extracting them. GNU patch applies the checked-in patches with
zero fuzz and fails on changed context or repeated application. The local
Cargo patch changes only the source of `rpm 0.23.2`; all other locked versions,
dependencies and checksums remain unchanged. Installation uses `--locked` and
`--force` so an existing unpatched binary with the same version cannot satisfy
the installation step.
Replace this patch with a reviewed pinned upstream fix when one is available;
updating unrelated tools is not part of this correction.

To inspect sources without compiling or installing anything:

```sh
bash packaging/rpm-tool/install.sh --prepare /tmp/new-rpm-tool-sources
```

An existing crate archive directory can be supplied with `--cache DIRECTORY`;
these archives receive the same checksum checks. The destination must not
already exist. Preparation failure leaves an incomplete destination for
inspection, never a successfully installed unpatched tool. Normal installation
uses an owned temporary directory and removes it on exit.

The patch contains focused Rust controls for complete CPIO length, the
32-/64-bit boundary without allocating a huge payload, signature rebuilding,
and V6 omission. Run them against the prepared `rpm` source before qualifying
a patch update:

```sh
cargo test --manifest-path /tmp/new-rpm-tool-sources/rpm-0.23.2/Cargo.toml \
  --locked --lib --no-default-features --features payload archive_size_tests
```

Lightweight preparation tests run without downloads or tool compilation:

```sh
python3 -m unittest discover -s scripts/tests -p test_rpm_tool.py
```

Actual qualification must also generate small and larger RPM fixtures and
check declared size against decoded bytes, payload identity, digest verification
and strict decoding with RPM 4.14 and 4.18. Corrupted, truncated and deliberately
wrong-size fixtures must stay rejected. Release-package CI qualifies both
client and daemon products; preparation controls alone do not qualify packages.

Source references: [pinned rpm-rs builder](https://github.com/rpm-rs/rpm/blob/v0.23.2/src/rpm/builder.rs),
[pinned signature builder](https://github.com/rpm-rs/rpm/blob/v0.23.2/src/rpm/headers/signatures.rs),
and [RPM 4.18.2 decoder](https://github.com/rpm-software-management/rpm/blob/rpm-4.18.2-release/rpm2cpio.c).
The checked-in patches retain the downloaded crates' license and provenance files.
