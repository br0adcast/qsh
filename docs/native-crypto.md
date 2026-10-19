# Native crypto build prerequisite

The native build helper prepares a verified OpenSSL prefix for the planned RSA
backend migration. It currently adds no OpenSSL dependency to the Rust products
and does not resolve the RustCrypto RSA timing advisory by itself. Correct
signatures and reproducible source selection do not establish constant-time
execution.

## Source and provenance

`scripts/openssl/source.json` pins OpenSSL 3.5.9, its archive URL and SHA-256,
the release signature, and the signing certificate's primary fingerprint.
`release-key.asc` is an upstream **public** release certificate;
`source.tar.gz.asc` is the detached signature for that exact release. Neither
file is an application identity or secret fixture.

The helper checks the archive digest and verifies the detached signature in a
new temporary GnuPG home, using only the checked-in certificate. It also checks
the certificate and signature digests before invoking GnuPG. A failed check
cannot fall back to another source, installed system library, or cached prefix.
With `--archive`, a missing or incorrect local file fails without downloading.
Without it, the helper downloads only the pinned HTTPS archive.

Review pin updates against the [OpenSSL source page](https://openssl-library.org/source/)
and [security advisories](https://openssl-library.org/news/vulnerabilities/).
Verify the release certificate and signature independently, update all metadata
together, and qualify every release target before accepting the update. Keep
upstream `LICENSE.txt` with a built prefix and any eventual redistribution.

## Local qualification

Required tools are Python 3, Bash, Perl, make, GnuPG, curl, a target C compiler,
and its archiver/ranlib. Linux additionally uses `readelf`; macOS uses `xcrun`
and `otool`. This is a POSIX build helper for the existing Linux/macOS release
matrix, not a new Windows release target.

A native GNU example is:

```sh
CARGO_BUILD_JOBS=2 bash scripts/qualify-openssl.sh \
  --target x86_64-unknown-linux-gnu \
  --cache "$PWD/target/native-crypto" \
  --toolchain-id local-qualified-toolchain
```

For musl, install the architecture's musl compiler and kernel UAPI headers.
Do not add all of `/usr/include` to musl's include search path: that also imports
incompatible glibc headers. The workflow shows the small UAPI-only directory
and explicit `--cflag=-idirafter --cflag=...` arguments used for both native
Linux architectures. `--cc`, `--ar`, and `--ranlib` each name one executable;
flags are repeated `--cflag` arguments, never a shell command string.

The helper checks architecture and libc using the selected compiler. A GNU
compiler is rejected for a musl target. Native jobs are limited to one or two.
The qualifier generates an ephemeral RSA key in private temporary storage and
runs SHA-1, SHA-256, and SHA-512 sign/verify checks, each with a changed-message
rejection control. Native commands get temporary HOME/XDG directories, an
explicit empty OpenSSL config, and no SSH agent socket. This SHA-1 native
capability check does not expand QSH's SHA-2-only authentication policy.

For a cross GNU target, select the matching compiler/archiver/ranlib and pass
`--runner` plus repeated `--runner-arg` for an explicit emulator. No foreign
binary is executed merely because a cross build succeeded.

## Cache and downstream contract

`scripts/build-openssl.sh` prints only the validated absolute prefix to stdout;
build diagnostics go to stderr. Its cache identity includes the source pin,
target, explicit options/flags, compiler path/digest/version/macros, archiver
and ranlib path/digests, build-helper digest, and `--toolchain-id`. Use that last
field to identify the qualified SDK/sysroot or container image, and change it
when those inputs change: the helper does not hash an entire SDK or every
transitive compiler program. Do not share a mutable toolchain under one identity.

Cache reuse checks the manifest and all installed file digests. Incomplete,
modified, or mismatched prefixes fail explicitly; the helper does not silently
repair them. Delete only the reported failed prefix after investigating it.
A per-entry lock rejects concurrent ownership; publication is an atomic rename
from a private staging directory. Build failure or handled cancellation removes
that staging directory and lock, preserving unrelated entries. An uncatchable
process or host failure can leave a stale lock/stage for explicit cleanup.

OpenSSL uses a fixed logical `/qsh-openssl` prefix with staged installation.
Relative compiler/input aliases and source-path remapping avoid embedding the
private staging path in archives. A link probe checks headers/runtime version
and rejects dynamic OpenSSL linkage; musl additionally rejects any dynamic
library dependency. The helper scans native archives and the probe for its
staging/home paths. The manifest contains local toolchain paths as provenance
and is not a release artifact.

The prefix exposes `include`, `lib/libcrypto.a`, `lib/libssl.a`, the version
probe, and the qualification CLI. A subsequent production integration must use
this exact prefix explicitly, with static linking and vendored downloading
**disabled** in Cargo; it must not discover arbitrary system OpenSSL instead.
Use the prefix directly (for example the appropriate target-specific
`OPENSSL_DIR` contract) rather than its logical-prefix pkg-config files. That
Rust integration is a separate reviewed change, including application key
handling and cancellation tests.

## CI and release qualification

Ordinary CI runs the generated miniature-build orchestration tests:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_build_openssl.py'
```

They exercise rejection, cache identity/integrity, failed and cancelled builds,
owned process cleanup, and qualifier isolation. Their isolated fake signature
verifier and generated C archives test orchestration only; they do not replace
real signed-source qualification.

The `Native crypto prerequisite` workflow runs for changes to these scripts,
source metadata, package build images, or relevant workflows, and can run
manually. The release workflow calls the same qualification and requires its
success before publication. Unrelated pull requests do not run the full native
matrix.

Qualification covers native x86_64/aarch64 musl Linux and Intel/Apple Silicon
macOS, plus both GNU architectures in each existing Debian/RPM package-floor
image. GNU ARM probes run through explicit QEMU with that image's target
sysroot. Qualification emits no new release artifact and publishes no release.
Passing one local target is not evidence that the complete CI matrix passed.
