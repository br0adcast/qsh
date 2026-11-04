# Offline release metadata authentication

`verify_manifest` authenticates original `SHA256SUMS` bytes using a single
Sigstore v0.3 DSSE in-toto statement. Only the compiled public qsh repository,
immutable repository ID, release workflow, exact tag/version and source commit
policy can issue `VerifiedManifest`. The library performs no network, cache,
HOME lookup, TUF refresh, or signing. Its private crypto helper takes an explicit
root and identity only so unit tests can exercise public upstream evidence.

The statement, duplicate-member, depth and object-count limits are enforced
before expensive verification. After full certificate/SCT/tlog/signature/time
verification, qsh authorizes the authenticated certificate claims and validates
its exact statement schema and canonical twelve-product manifest. The CI tool
also compares the authenticated commit with its explicit expected checkout.
This does not independently pin a downloader's source commit: an authorized
workflow remains within the trust boundary.

This crate alone does not change downloader behavior or sign a qsh release.
A public upstream positive fixture proves interoperability with this dependency;
it does not prove any qsh release was signed. The four shipping-target fixture
runs and static linkage checks are in the existing native crypto workflow.

## Embedded production trust

`roots/production.json` is copied byte-for-byte from `src/trusted_root.json` in
[`sigstore-trust-root 0.15.1`](https://crates.io/crates/sigstore-trust-root/0.15.1),
release source commit `fc308a2f0bcef92f10c199c6d75fa72441b329f7`.
SHA-256: `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66`.
The crate archive SHA-256 is
`d9a49e390a5f52e0b05f1a17820be5ac747a3890bb9f54156d8a1147508420a7`.
No private-instance or staging anchor is compiled into production policy.

Root changes require a reviewed client update from an upstream/TUF-validated
production snapshot, with old/new anchors and validity windows recorded in the
review. This snapshot retains the 2021 historical CA (through 2022), the 2022
current CA, 2021/2025 Rekor keys, historical/current CT keys (2021/2022), and the
2025 TSA. The JSON contains the exact key IDs, certificates and validity windows.
Routine rotation retains historical anchors needed for old signatures. Removing
a compromised anchor invalidates corresponding evidence on the updated client;
unknown anchors fail with a client-update diagnostic. Offline evidence and old
clients provide no automatic revocation/freshness guarantee. Tests exercise
historical expired-leaf verification, root additions retaining an old anchor,
unknown/replacement roots and explicit anchor removal through real crypto.

The root and fixtures are from the Apache-2.0 upstream project. Its exact
[license](roots/LICENSE.sigstore) has SHA-256 `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4` and comes
from that pinned commit's `LICENSE` (Git blob
`261eeb9e9f8b2b4b0d119366dda99c6fd7d35c64`). AWS-LC native and Rust-wrapper
notices are retained in `docs/licenses/` and described in the dependency policy.

## Public interoperability fixtures

The three files below are unmodified from
[`sigstore-verify 0.15.1/test_data/bundles`](https://github.com/sigstore/sigstore-rust/tree/fc308a2f0bcef92f10c199c6d75fa72441b329f7/crates/sigstore-verify/test_data/bundles).
The downloaded crate archive SHA-256 is
`465f37d73c80fc6a2fa519d1337befab2026fce47f490181f72842aa56d401e1`.
The staging root is unmodified from the same release's trust-root crate
`src/trusted_root_staging.json`. It is included only in `cfg(test)` code.

| Fixture | SHA-256 |
| --- | --- |
| `conda-attestation-rekor2.sigstore.json` | `490cc3ca8f3c216c5c836e6c7d9dad6b0d8a2dff91003eb383ad1000675fa8e5` |
| `conda-attestation.sigstore.json` | `3b68ceda769879104c48b3bf0eb444accb470008c6be29393714922d533ab171` |
| `signed-package-2.1.0-hb0f4dca_0.conda` | `54303491a8418fbed24344b513546182c29b43bf282ceb433af65e2299f9271f` |
| `staging-root.json` | `44deb991d4bbf2150751ccee235d9810bce4434383c26d8898c1bcadbace6ed8` |

The production bundle authenticates a public `prefix-dev/sigstore-example`
GitHub Actions workflow and an empty Conda test package; the archive contains
package metadata/recipes and no executable payload. The second bundle uses the
public staging infrastructure and an upstream author's published certificate
email (`jku@goto.fi`), retained because changing it would invalidate the signed
fixture. That identity is an upstream test identity, not a qsh owner identity.
The staging fixture is needed to prove unknown/replacement-root behavior.
No private keys, generated credentials or full upstream test corpus are included.
Do not exempt this directory from content-specific privacy review.

Run `cargo test --locked -p release-auth --all-targets` for the full offline
fixture, crypto-tampering, authorization, schema, bound and file-input controls.
The example `verify-release` accepts `--version`, `--manifest`, `--bundle` and
optional `--expected-source-commit`; all file inputs must be bounded regular
files. It prints only the validated release version and source commit.
