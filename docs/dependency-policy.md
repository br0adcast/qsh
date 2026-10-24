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
Informational notices remain visible. The tool receives only the two reviewed
IDs after the checker verifies that every locked version of each named package
matches the exact reviewed version. After the same audit pass, the checker
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
Native OpenSSL source/version/artifact review and platform qualification remain
required separately; Cargo policy checks do not cover that native source.

## Existing license baseline

`deny.toml` records the current declarations. The common set is MIT, Apache-2.0,
BSD-3-Clause, ISC, Unicode-3.0 and Zlib. Additional rules apply only to the
fourteen named workspace packages at 0.5.0 (AGPL-3.0-only), option-ext 0.2.0
(MPL-2.0), and webpki-roots 1.0.10 (CDLA-Permissive-2.0). Workspace/private/path
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
| RUSTSEC-2023-0071, rsa 0.10.0-rc.18, vulnerability | Local RSA preparation and signing use the qualified native backend without a RustCrypto private fallback, completed in #59/#121. Upstream formats/public verification and external signers remain separate boundaries. | #62; maintainer review by 2027-01-24 |
| RUSTSEC-2025-0069, daemonize 0.5.0, unmaintained | The sole `Daemonize::new().execute()` call precedes the runtime and does not call the `privileged_action` builder containing the cited transmute. Maintenance risk remains; this is not a whole-library safety claim. | #248 tracks bounded replacement and parent-status handling; maintainer review by 2027-01-24 |

Review these entries on any related pin, callsite, startup-thread, native
backend or advisory change, even before the date. Do not remove RSA support,
disable verification or suppress another advisory in the same dependency
family to satisfy a scanner. Other patchable findings require their own fixes
and review; they do not inherit either disposition.

Ordinary CI's existing native boundary tests remain required, including
`native_rsa_route_is_observed_on_the_real_file_signer`,
`native_rsa_failure_cannot_fall_back_to_a_successful_file_proof`, and
`native_rsa_cancel_drops_connection_runtime_while_owned_signing_is_held`.
Keep native parsing, ownership/cancellation and release-platform qualification
alongside these tests. Keep real daemonization/ensure ownership tests while
the maintenance disposition exists. Passing signatures or a scanner alone do
not establish constant-time execution or safety of a whole dependency.

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
