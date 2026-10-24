# Packaging bootstrap trust

The Debian and RPM floor images share `install-rust.py` and `rustup.json`.
The helper downloads the direct **versioned** rustup-init executable for the
Linux x86_64 or aarch64 build host, verifies a private copy against its
committed SHA-256, and only then executes it. A local `--archive` receives the
same verification. There is no URL, digest, or version override in the CLI.
Unsupported build hosts fail before downloading or executing anything.

Rustup 1.29.0 was selected from the upstream stable release dated 2026-03-05.
The initial installer bytes were obtained from the official Rust HTTPS archive
and compared with its published adjacent `.sha256` files. The x86_64 executable
reported `rustup-init 1.29.0 (28d1352db 2026-03-05)` in the existing Rocky 8
floor. Initial provenance therefore relies on upstream HTTPS and review;
this is **not** a claim of independent detached-signature authentication.
The committed reviewed digest is the independent build-time anchor: builds
never download a checksum to decide which executable to trust.

Upstream references:

- [Versioned rustup installer URLs and checksums](https://rust-lang.github.io/rustup/installation/other.html)
- [Rustup 1.29.0 release changelog](https://github.com/rust-lang/rustup/blob/1.29.0/CHANGELOG.md)
- [Rustup 1.29.0 installation implementation](https://github.com/rust-lang/rustup/blob/1.29.0/src/cli/self_update.rs)
- [Rust installation methods and signature-verification distinction](https://forge.rust-lang.org/infra/other-installation-methods.html)

Installation first installs the verified rustup executable without a toolchain,
then disables automatic self-update, installs the existing qualified Rust
1.98.1 toolchain, selects it as the default, and adds both existing GNU targets.
The installed manager remains the verified executable. Compiler components
retain rustup's official distribution checks; this change does not introduce a
separate detached-signature policy for every Rust component. The existing
base-image digests, compiler allowlist, and OpenSSL digest/signature
verification remain prerequisites.

## Rocky cross sysroot

`install-sysroot.py` resolves the complete aarch64 dependency set for
`glibc-devel`, `libgcc`, `pam-devel`, and `glibc-headers`, using only the existing
Rocky 8 BaseOS, AppStream, and Extras repositories. It copies the release
certificate from the digest-pinned base and checks its full primary fingerprint
before repository work. Only the Rocky 8 release certificate is imported into
its private verification database:

```text
7051C470A929F454CEBE37B715AF5DAC6D745A60
```

The [official Rocky signing-key page](https://rockylinux.org/resources/gpg-key-info)
is the review reference. Native EPEL compiler installation does not expand the
foreign sysroot's signing trust. Testing keys and arbitrary neighboring key
files are not imported.

Every resolved RPM is copied into private temporary storage and checked with
RPM 4.14's `_pkgverify_level signature` policy before any payload is installed.
An unsigned RPM with valid ordinary digests is insufficient. A second checked,
offline RPM transaction consumes these same copies, requires signatures again,
checks dependencies, and disables package scripts and every trigger kind with
`--noscripts --notriggers`. There is no ignored transaction failure or
`--nodeps`. The installed package inventory must exactly match the authenticated
input identities before the link-only RPM database is removed. `--packages`
accepts an offline resolved set with identical signature/dependency checks.

Skipping `filesystem`'s foreign `%pretrans` requires preparing its usr-merge
layout before an earlier library payload can create `/lib64` as a directory.
The helper accepts only the four exact aliases `/bin`, `/sbin`, `/lib`, and
`/lib64` to their corresponding `usr/` directories, read from the already
verified `filesystem` package metadata. The destination must be new or empty.
RPM then installs the complete filesystem payload and owns its attributes.
`glibc-headers` is installed in the same checked transaction, so its foreign
`%pre` cannot prevent header installation. The existing library, header-floor,
architecture, and PAM link probes still run in the Dockerfile.

This validates package origin and integrity. It does not promise a repository
snapshot, package freshness, rollback prevention, or byte-identical rebuilds.
Do not silently disable checks when a package, key, or repository changes.

## Updating the inputs

1. Review the selected upstream rustup release and its compatibility with both
   build hosts and the existing floor images. Obtain each versioned executable
   and its published digest from the official archive. Record how the initial
   bytes were authenticated; a checksum fetched beside an asset is not an
   additional independent authenticity channel.
2. Compare the bytes with the published hashes, inspect their host architecture
   and version, and update both committed host digests together. Review any
   available stronger upstream authentication evidence explicitly. Never replace
   the pin with a mutable `dist` URL or an unchecked shell installer.
3. For a Rocky key rotation or base change, independently review the complete
   primary fingerprint against official Rocky information. Update the explicit
   trust policy deliberately; never import an unknown key merely because a
   download requests it. Retain package-signature rejection controls and inspect
   changed filesystem layout before accepting new aliases or package behavior.
4. Run the local controls, both floor-image builds, native/cross GNU package
   qualification, and the existing installed-package acceptance jobs before
   accepting an update. Do not change compiler versions, libc/PAM floors,
   packaging-tool pins, or qualified OpenSSL inputs as incidental cleanup.

Local bootstrap tests use executable fixtures without network access:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover \
  -s scripts/tests -p test_bootstrap_tools.py
```

The real RPM controls run inside the existing Rocky floor image with network
access disabled, temporary key/database homes, and ephemeral local signing
keys. They require no fixture credentials or downloaded test packages:

```sh
docker run --rm --network none --read-only \
  --tmpfs /tmp:rw,exec,nosuid --tmpfs /var/tmp:rw,exec,nosuid \
  --tmpfs /var/log:rw,noexec,nosuid --tmpfs /run:rw,noexec,nosuid \
  -e HISTFILE=/dev/null -e PYTHONDONTWRITEBYTECODE=1 \
  -v "$PWD/packaging/bootstrap:/bootstrap:ro" qshd-build-rpm:local \
  /usr/libexec/platform-python /bootstrap/test-sysroot.py
```

These controls reject unsigned, wrong-signer, damaged, and truncated inputs,
unreviewed keys, missing dependencies, and bytes altered after initial
verification. A signed ordering fixture verifies the usr-merge preparation;
Lua scriptlets and all configured trigger kinds emit execution sentinels;
the production transaction must emit none, while an enabled control observes
every kind through the same private output capture. The
native-crypto workflow runs these same controls in its newly built RPM image,
then qualifies both GNU architectures and actual server packages.
