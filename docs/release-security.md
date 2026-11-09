# Release authentication

Automatic daemon downloads require signed metadata for the exact requested client
version. qsh authenticates the original `SHA256SUMS` bytes using the adjacent
`SHA256SUMS.sigstore.json` before fetching or selecting an archive. Archive hashes
come only from the authenticated twelve-product manifest; extraction, size, layout
and daemon-image checks still apply.

## Client bootstrap trust

Managed console installation uses `scripts/install.sh` from the official raw
GitHub HTTPS endpoint. The script downloads an exact platform archive from the
official GitHub release and executes only its temporary `qsh` member. Initial
trust covers both the script and that executable through GitHub HTTPS; neither
checksums served beside it nor its later signature verification can authenticate
that executable before it runs. There is no downloaded verifier or mutable root
bootstrap. To authenticate that executable yourself before it runs, use the
[first-installation recipe](#first-installation-from-a-verified-archive).

The temporary client delegates to the Rust installation engine. That engine
re-downloads and authenticates the selected release manifest and bundle under
the compiled production policy before persistent installation. The installation
receipt records ownership and hashes, not independent signature authority.
Latest-stable discovery is release selection, not artifact authentication. Exact
`--version` selection is forwarded unchanged, including an explicitly chosen RC.

Activation requires a later release containing `--self-install` and
`--self-update`; published `0.6.0-rc.1` lacks those commands. Old bootstraps fail
closed. The shell script stays on GitHub and is not an additional asset in the
fixed twelve-product signed manifest. Release validation must check the safe
`--self-install --help` capability probe and exercise first installation from
the exact candidate artifacts before claiming live bootstrap support. Existing
published tags and assets must remain unchanged.

## Independent verification

A person can authenticate a release without qsh. The
[README recipe](../README.md#installing) runs `gh attestation verify` on the
local bundle. GitHub CLI checks the certificate chain, transparency-log entry and
signature against its own Sigstore trust root, not qsh's compiled roots. It
requires:

- issuer `https://token.actions.githubusercontent.com`;
- SAN `https://github.com/br0adcast/qsh/.github/workflows/release.yml@refs/tags/v<VERSION>`,
  that is, the release workflow at the exact tag;
- repository `br0adcast/qsh` and a GitHub-hosted runner;
- predicate type `https://github.com/br0adcast/qsh/release-manifest/v1`.

It does not check the repository ID, or that the predicate's version, tag and
source commit agree with the certificate; qsh's verifier does. To check them,
add this to the same command:

```sh
--format json --jq '.[].verificationResult | [.signature.certificate.sourceRepositoryIdentifier,
  .statement.predicate.version, .statement.predicate.tag,
  .statement.predicate.source_commit, .signature.certificate.sourceRepositoryDigest] | @tsv'
```

Expect `1423663657`, `<VERSION>`, `v<VERSION>` and two equal commit hashes.
A file is authenticated only through its line in the verified `SHA256SUMS`.

### First installation from a verified archive

This replaces the bootstrap script. The first executable is then trusted through
the verified manifest rather than GitHub HTTPS alone. It requires an
installer-capable release (see [Client bootstrap trust](#client-bootstrap-trust)).

```sh
VERSION=0.6.0
TARGET=x86_64-unknown-linux-musl   # or aarch64-unknown-linux-musl, aarch64-apple-darwin, x86_64-apple-darwin
STEM=qsh-$VERSION-$TARGET
base=https://github.com/br0adcast/qsh/releases/download/v$VERSION
curl --fail --location --proto '=https' --proto-redir '=https' \
  -O "$base/SHA256SUMS" -O "$base/SHA256SUMS.sigstore.json" -O "$base/$STEM.tar.gz"
# Authenticate SHA256SUMS and check $STEM.tar.gz as in the README.
tar xzf "$STEM.tar.gz"
"$STEM/qsh" --self-install --version "$VERSION"
```

The installation engine then downloads and authenticates the release again under
the compiled policy, as it does for the script. `--prefix PATH` works as with the
script.

## Authority

Authenticated running-server discovery selects an update candidate, not a
release signing authority. The independent Noise bootstrap uses the pinned qsh
identity and a fresh challenge; SSH fallback requires verified host keys,
authentication, a fresh echoed challenge and the expected qsh public key. Only
metadata matching an admitted process generation may describe an attached
connection. Unknown or stale metadata supplies no age or compatibility claim.
The selected exact SemVer release loses build metadata only when forming its
artifact tag. Explicit user consent is required before the existing managed
updater performs release I/O; receipt, ownership and signature verification are
repeated at execution. Source builds never offer or download a replacement.

The authority is the public `br0adcast/qsh` GitHub Actions release workflow. The
compiled policy requires issuer `https://token.actions.githubusercontent.com`,
SAN URI `https://github.com/br0adcast/qsh/.github/workflows/release.yml@refs/tags/v<VERSION>`,
repository URI `https://github.com/br0adcast/qsh`, immutable repository ID
`1423663657`, public visibility and the exact tag ref. The statement binds the
manifest digest, requested version/tag and source commit to verified certificate
claims. Certificate, SCT, transparency inclusion/checkpoint, signature and
verified-signing-time checks must all succeed.

A downloader has no separately pinned expected source commit for a release. An
authorized workflow signing different contents for that version remains within
this trust boundary. Repository-ID pinning prevents repository-name reuse from
silently acquiring the authority. HTTPS validation remains a separate requirement.
There is no unsigned mode, public-key substitute, environment trust override,
downloaded-root override or runtime dependency on GitHub CLI.

## Network failures and cache

| Metadata result | Allowed cache behavior |
| --- | --- |
| Manifest temporarily unavailable before any body byte | Reauthenticate exact-version/target stored evidence before use. |
| Manifest interrupted after a body byte | Refuse; do not select cache. |
| Complete manifest, bundle temporarily unavailable or interrupted | Reauthenticate stored evidence and require its original manifest bytes to equal the received manifest exactly. A matching selected archive hash alone is insufficient. |
| Missing metadata, TLS rejection, size limit, malformed evidence, bad signature/identity/root/manifest | Refuse, even with a previously usable cache. |
| Authenticated metadata, matching cached archive | Rehash and verify the archive/image against authenticated metadata. |
| Authenticated metadata, archive download fails or hash differs | Refuse; do not select another cached generation. |

Cancellation always refuses publication. Both metadata transfers share one
network deadline. Synchronous local cryptography is bounded by admitted sizes
and object counts; callers check cancellation and local expiry immediately before
and after verification, rather than claiming hard preemption of crypto work.

A cache generation retains original manifest and bundle bytes with archive,
image and receipt. Every offline load reauthenticates the evidence under the
current compiled policy and binds the exact request, target, receipt, archive
and image. The receipt, a remembered success or a matching archive digest never
provides authentication. Partial evidence is not a usable generation.

Old unsigned generations are cache misses, with no receipt-based migration.
Fresh authenticated metadata can qualify an existing matching archive only by
rehashing it and publishing complete signed evidence through the normal safe
publication path. A corrupt cache cannot be an offline success.

## Historical evidence and root updates

Offline authentication proves historical signed evidence under this client's
compiled roots. It does not prove latest version, current revocation status or
that a release has not been withdrawn. An expired leaf can remain valid at its
authenticated signing time. The verifier performs no network TUF refresh, HOME
lookup or root-cache update.

Root changes are reviewed client updates using an upstream/TUF-validated
production snapshot. Review old/new anchors and validity windows; routine
rotation retains historical anchors needed for admitted signatures. Removing a
compromised anchor invalidates its evidence on the updated client. Unknown new
anchors fail and require an updated client. Old clients cannot acquire automatic
revocation or freshness guarantees. Root provenance and actual cryptographic
controls are documented in [release-auth](../crates/release-auth/README.md).

## Compatibility and publication

The existing unsigned v0.5.0 release is not backfilled, replaced or exempted.
New automatic loaders refuse it and unsigned preexisting cache generations.
Older released clients retain their previous behavior. An already supplied or
installed daemon follows its existing explicit source policy; it is not selected
to hide a metadata authentication error.

Branch assembly remains twelve products plus `SHA256SUMS`. Tag publication adds
only the bundle, for fourteen release assets total. The next separately authorized
release must include the signing workflow before distributing an enforcing client.
Its first real qsh attestation must pass the production verifier, including exact
checkout-commit binding, before upload. Public upstream fixtures and synthetic
loader/CLI fixtures do not prove that a qsh release was signed. Do not create or
move a tag merely to validate this change. See [Actions maintenance](actions-maintenance.md).
