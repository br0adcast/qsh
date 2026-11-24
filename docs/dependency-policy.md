# Dependency security and policy checks

Ordinary Linux CI checks the locked Rust dependencies once, before product
compilation. It uses cargo-audit for advisories and cargo-deny for licenses,
sources and bans. Release CI reuses ordinary CI; other platforms do not repeat
the same graph checks. These checks do not compile products, replace native
qualification or establish that an advisory is reachable in qsh.

## Tools and local execution

Python 3.11+, Cargo and Git are required. The installer supports the existing
Linux x86_64 CI host and downloads the exact official release archives in
`scripts/dependency-tools.json`. It verifies archive and extracted-binary
SHA-256 values before executing the binary's version command, then publishes
only the expected version. It does not use `cargo install` or mutable Actions.
The checker verifies each binary and version again before use.

Run from the workspace root, using an owned temporary directory:

```sh
work=$(mktemp -d)
python3 scripts/install-dependency-tools.py --directory "$work/tools"
QSH_TEST_DEPENDENCY_TOOLS="$work/tools" PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest -v scripts.tests.test_dependency_policy
python3 scripts/check-dependencies.py --tools-directory "$work/tools" \
  --output-directory "$work/report"
```

The report directory contains raw audit/policy output and the fetched RustSec
commit. Keep it for diagnosis before removing the owned temporary directory.
Tool/network failures, malformed output, missing check summaries and unexpected
exit statuses fail the check. CI also rejects skipped or empty fixture suites.

The audit fetches the current official RustSec database and checks a fresh
registry index, with its own temporary HOME/Cargo configuration. Fetch failures
are fatal; there is no stale/offline fallback or severity/target filter.
Vulnerabilities and unmaintained, unsound and yanked findings are denied.
Informational notices remain visible. The tool receives only the reviewed
advisory ID after the checker verifies that every locked version of the named
package matches the exact reviewed version. After the same audit pass, the checker
verifies each ignored advisory's ID, package and informational kind in the
freshly fetched database. Changed identity/kind or a second package version
fails the check.

The pinned audit runs in terminal mode with color disabled. Its JSON mode can
hide registry-index initialization failures, so JSON output and an exit status
alone cannot establish a completed yanked scan. The checker requires the exact
fetch, database-load, index-update and lockfile-scan receipt, rejects unknown or
index-error diagnostics even when the tool exits zero, and checks finding/notice
summaries against the exit status and visible notices. It preserves both raw
output streams and the database commit. A tool upgrade must qualify this pinned
format contract and the real missing-index regression before changing the pin.
The pinned upstream [output configuration](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/src/config.rs)
and [index error handling](https://github.com/rustsec/rustsec/blob/cargo-audit/v0.22.2/cargo-audit/src/auditor.rs)
explain this requirement.

The policy pass keeps every workspace member, all features, development/build
dependencies and local path packages. It accepts crates.io and denies unknown
registries/Git sources. Duplicate versions and path-only wildcard requirements
remain visible warnings; their presence is not by itself a dependency bug.
`vendor/vte` remains included, with its existing upstream/patch provenance.
The AWS-LC C sources that `aws-lc-sys` builds are covered by its crate's
provenance; there is no other native source outside Cargo.

## Existing license baseline

`deny.toml` records the current declarations. The common set is MIT, Apache-2.0,
BSD-3-Clause, ISC, Unicode-3.0 and Zlib. Additional rules apply only to the
sixteen named workspace packages at 0.6.0-alpha.3 (AGPL-3.0-only), option-ext 0.2.0
(MPL-2.0), and webpki-roots/webpki-root-certs 1.0.12
(CDLA-Permissive-2.0). Workspace/private/path
packages are not skipped, and no content-free license clarification is used.

These rules record existing dependencies and declared licenses. They do not
introduce dependencies, change qsh's license, grant commercial rights or make
a legal-compliance determination. Review changed license declarations, source
origins and notices when updating dependencies. Do not broaden a package rule
to a license family merely to make a new finding pass.

## Reviewed advisory dispositions

The repository maintainer owns the exact entries in
`scripts/dependency-exceptions.json`. Each entry must include its advisory ID,
package, exact version, finding kind, rationale, tracking and review date.
The check fails after the inclusive review date, for malformed/duplicate entries
or when any locked version of a named package differs from the reviewed
version. A different ID, package, version or kind is not accepted by an existing
entry. Yanked packages have no
exception. Remove obsolete entries rather than leaving broad ignores behind.

| Exact finding | Rationale and required boundary | Follow-up/review |
| --- | --- | --- |
| RUSTSEC-2026-0543, chrono 0.4.45, unmaintained | Transitive only: russh-sftp 3.0.1 uses chrono in `FileAttributes::from(&Metadata)` and `protocol::File::new`/`longname`, which the qsh SFTP upload (`RawSftpSession` init/open/write/close with explicit attributes) does not call; russh-util 0.52.0 depends on it only for wasm32. Not a vulnerability disposition; a new SFTP operation or callsite reopens it. | #618; maintainer review by 2027-02-17 |

The refresh to stable `rsa 0.10.0` removes the previous exact prerelease
exception for [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html).
RustSec marks `>=0.10.0` as patched; the
resolved product and fuzz graphs must contain no affected older RSA copy.
Local RSA private operations run on this `rsa` (#668), which replaced the
native OpenSSL backend adopted while the advisory had no fix (#59): one
validated, precomputed key per owner, PKCS#1 v1.5 signatures with blinding.

Review active entries on any related pin, callsite, startup-thread, RSA
backend or advisory change, even before the date. Do not remove RSA support,
disable verification or suppress another advisory in the same dependency
family to satisfy a scanner. Other patchable findings require their own fixes
and review; they do not inherit this disposition.

Ordinary CI's existing RSA boundary tests remain required, including
`rsa_route_is_observed_on_the_real_file_signer`,
`rsa_failure_cannot_fall_back_to_a_successful_file_proof`, and
`rsa_cancel_drops_connection_runtime_while_owned_signing_is_held`.
Keep parsing, ownership/cancellation and release-platform checks alongside
these tests. Passing signatures or a scanner alone do not establish
constant-time execution or safety of a whole dependency.

## Fixture provenance

The Python controls generate tiny owned crates, metadata, lockfiles and local
advisory Git repositories in temporary directories. Synthetic advisory records
are local test data, including records that reuse an exception ID to test exact
matching; they are never submitted to RustSec. `example.invalid` addresses and
registry URLs are reserved fixture values. The source-policy fixture changes
owned metadata and never contacts that registry. No real identities, keys,
credentials or vulnerable external packages are downloaded for the controls.
They run the verified real tools, demonstrate accepted and rejected policies,
and do not compile fixture or product crates or create Cargo target directories.

## Offline release authentication

`release-auth` pins Sigstore 0.16.0 with default features disabled and only
its AWS-LC crypto provider enabled. Runtime TUF, signing and online clients
are absent from this verifier's feature graph. The embedded production roots
and public interoperability fixtures have provenance in
[`crates/release-auth/README.md`](../crates/release-auth/README.md).

AWS-LC adds a native C build through `aws-lc-sys`; its complete upstream
license and notices are retained in [`licenses/aws-lc.txt`](licenses/aws-lc.txt),
with the Rust wrapper's license in [`licenses/aws-lc-rs.txt`](licenses/aws-lc-rs.txt).
Sigstore's Apache-2.0 license accompanies the roots and fixtures. These notices
must accompany distributions containing this code. Native qualification runs
real offline crypto fixtures on the four shipping client targets, keeps static
musl linkage checks, and remaps native C source paths as well as Rust paths.


Release HTTPS uses reqwest 0.13.5 with default features disabled and
`rustls-no-provider`. Its preconfigured Rustls client selects Ring explicitly,
uses the Mozilla trust anchors from webpki-roots 1.0.12, and advertises HTTP/1.1.
It preserves safe TLS 1.2/1.3, SNI, ordinary WebPKI hostname/signature validation,
no client authentication and no key logging. It installs no global provider
and uses no platform-root fallback. The platform-verifier dependency remains
in reqwest's feature graph but is bypassed by this explicit configuration.
Its target-specific webpki-root-certs 1.0.12 bundle uses the same CDLA license
text as webpki-roots; each package has its own exact-version allowance.
Tests inject their complete fixture root store rather than adding roots after
preconfiguration. HTTPS-only downloads, redirect limits, byte/deadline limits,
cancellation and offline-cache failure classification remain enforced.
