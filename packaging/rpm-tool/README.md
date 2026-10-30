# Pinned RPM packaging tool

`install.sh` installs `cargo-generate-rpm 0.21.0` with a narrow source patch
for its locked `rpm 0.23.2` dependency. Client and daemon packaging must use
this same installer. It requires Bash, Python 3.6 or newer, curl, GNU patch,
and the selected Rust toolchain. It preserves `CARGO_HOME`. Installation
explicitly selects `CARGO_INSTALL_ROOT`, then `$CARGO_HOME` (defaulting to `$HOME/.cargo`), so qualification checks the
fresh binary by absolute path. Cargo config `install.root` is not consulted;
set `CARGO_INSTALL_ROOT` to override the destination.

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

Every installation runs the shared `test_dependencies.py` checks against the
freshly installed binary. They generate RPMs and inspect numeric PRE/POST flags,
ordinary version constraints, automatic ELF requirements, and invalid PRE
metadata rejection. Failure stops both hosted release packaging and the RPM
floor image build, without a second tool build or separate CI job. Payloads
are never executed. Run the same checks against an existing prepared tool:

```sh
python3 packaging/rpm-tool/test_dependencies.py /absolute/path/to/cargo-generate-rpm
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

## Post-install command dependencies

The same pinned tool has a small metadata extension for the daemon variant:

```toml
requires-post = { "/usr/bin/getent" = "*", "/usr/sbin/useradd" = "*" }
```

The table maps unversioned package or file capabilities to genuine RPM
`SCRIPT_POST` dependencies using `rpm::Dependency::script_post`. Empty and
`"*"` values are supported; version expressions and non-string values fail.
This is separate from ordinary `requires` and automatic ELF requirements,
which stay enabled for the daemon. A capability named `shadow-utils(post)`
would not express a script-phase dependency and is not used.

Debian's server variant keeps automatic library dependencies and adds an
ordinary `Depends: passwd` for `postinst configure`. Essential tools need no
new explicit dependency. `systemctl` remains optional; account attributes,
upgrade behavior and service activation policy do not change.

Installed-package acceptance queries actual Debian Depends or numeric RPM
flags before installation, using `check-maintainer-dependencies.sh`. The
required RPM command-file entries must carry bit 1024 (`SCRIPT_POST`), not
merely look like a post-script dependency in a manifest. Controlled minimal
installation additionally proves package-manager resolution with the
user-management provider initially absent; stock-image tool presence alone
cannot establish that property.
