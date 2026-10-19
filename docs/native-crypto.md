# Native crypto build prerequisite

The native build helper prepares the verified OpenSSL prefix used for local RSA
private operations. The shared key owner and bounded SSH workers use that
backend without a RustCrypto private fallback. Public verification and external
signers remain separate. Correct signatures and reproducible source selection
alone do not establish constant-time execution.

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

For ARM musl, the helper selects inline baseline ARMv8 atomics with
[`-mno-outline-atomics`](https://gcc.gnu.org/onlinedocs/gcc/AArch64-Options.html).
This avoids GNU libgcc helpers that can require glibc symbols when a distribution's
`musl-gcc` wrapper reuses them, without requiring ARMv8.1 LSE instructions.

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
probe, and the qualification CLI. Rust products use this prefix explicitly:

```sh
native_prefix=$(bash scripts/build-openssl.sh \
  --target "$(rustc -vV | sed -n 's/^host: //p')" \
  --cache "$PWD/target/native-crypto" --jobs 2)
export OPENSSL_DIR="$native_prefix" OPENSSL_STATIC=1
cargo build --locked -p qsh -p qshd
```

Cross builds use the target-prefixed environment variables, for example
`X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_DIR` and
`X86_64_UNKNOWN_LINUX_MUSL_OPENSSL_STATIC=1`. The shared adapter rejects a missing
manifest, changed artifact, different target/source pin, native version mismatch,
Cargo-vendored replacement, or library/include overrides. It does not discover a
system fallback. Use the prefix directly rather than its logical-prefix
pkg-config files. Packaged products carry the upstream OpenSSL license.

RSA keys are validated once per loaded owner and signed by this native backend.
Plain PKCS1/PKCS8 use upstream native decoders; OpenSSH/PPK components use secure
BigNums and the upstream builder. No application CRT computation, private DER
serializer, or RustCrypto private fallback is involved. Existing two-prime
acceptance remains unchanged. SSH retains SHA-1/SHA-256/SHA-512 negotiation;
QSH retains its explicit SHA-2-only policy and signs file proofs with SHA-512.
Public verification and external/agent signing remain separate; an agent is
not certified timing-safe by this change.

SSH decrypts, prepares and signs local keys on two process-owned workers with
four queued places. Cancellation closes the result receiver; an active native
operation retains its place and secrets until completion, and a cancelled queued
operation is dropped before entering cryptography. Connection runtime teardown
does not join the native operation. Saturation returns typed `CryptoBusy` for
the caller's existing retry policy; it does not try another credential or
create a new timer. Initial discovery may still reject an unusable configured
candidate and continue with independently configured candidates. After PK_OK,
a local preparation or signing failure terminates authentication without
selecting another identity. Existing wrong or missing passphrase handling is
unchanged. This limits accepted worker jobs, not all key-file bytes or
all application memory. OpenSSL's secure BigNums do not imply that a locked
secure heap has been configured.

## CI and release qualification

Ordinary CI prepares its host prefix and runs product checks plus the generated
miniature-build orchestration tests:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_build_openssl.py'
```

They exercise rejection, cache identity/integrity, failed and cancelled builds,
owned process cleanup, and qualifier isolation. Their isolated fake signature
verifier and generated C archives test orchestration only; they do not replace
real signed-source qualification.

The `Native crypto prerequisite` workflow runs for changes to these scripts,
source metadata, native adapter/worker code, package build images, or relevant
workflows, and can run manually. Portable jobs also build the actual products
and execute generated RSA key-format and digest checks, including the large-key
envelope, against the qualified prefix. The release workflow calls the same qualification and requires its
success before publication. Unrelated pull requests do not run the full native
matrix.

Qualification covers native x86_64/aarch64 musl Linux and Intel/Apple Silicon
macOS, plus both GNU architectures in each existing Debian/RPM package-floor
image. GNU ARM probes run through explicit QEMU with that image's target
sysroot. Each floor job also runs the existing server package builder for both
architectures, including linked system-daemon, glibc and PAM checks. Generated
qualification packages stay within that job; no release is published.
Passing one local target is not evidence that the complete CI matrix passed.
