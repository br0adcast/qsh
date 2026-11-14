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
bootstrap.

The temporary client delegates to the Rust installation engine. That engine
re-downloads and authenticates the selected release manifest and bundle under
the compiled production policy before persistent installation. The installation
receipt records ownership and hashes, not independent signature authority.
Latest-stable discovery is release selection, not artifact authentication. Exact
`--version` selection is forwarded unchanged, including an explicitly chosen RC.

Activation requires a later release containing `--self-install` and
`--self-update`; no published release has those commands, and neither did the
withdrawn `0.6.0-rc1`. Old bootstraps fail closed. The shell script stays on GitHub and is not an additional asset in the
fixed twelve-product signed manifest. Release validation must check the safe
`--self-install --help` capability probe and exercise first installation from
the exact candidate artifacts before claiming live bootstrap support. Existing
published tags and assets must remain unchanged; the owner's withdrawal of
`v0.6.0-rc1` (see [Release versions](#release-versions)) is the only exception.

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
this trust boundary; [release authority settings](#release-authority-settings)
limit who can start one. Repository-ID pinning prevents repository-name reuse from
silently acquiring the authority. HTTPS validation remains a separate requirement.
There is no unsigned mode, public-key substitute, environment trust override,
downloaded-root override or runtime dependency on GitHub CLI.

## Release authority settings

Anyone who can run `release.yml` from a `v*` tag obtains a manifest every
client accepts for that version. The workflow file comes from the tagged commit,
so these repository settings are part of the trust boundary:

| Setting | Required state | Checked by |
| --- | --- | --- |
| Tag ruleset | Active; targets tags; includes `refs/tags/v*` or all tags, with no exclusions; restricts creations, updates and deletions; bypass list only the repository admin role | `scripts/check-release-settings.py` before signing, except the bypass list |
| `release` environment | The owner is a required reviewer; deployment limited to `v*` tags | the same script, reviewer only |
| Immutable releases | Enabled | the uploader, on the published release |

The script does not inspect the ruleset bypass list, so keeping it to the
owner is a manual duty. The immutability setting needs administration access,
which the workflow token never has; the published release's `immutable` field
is read instead.

These checks detect a settings regression in an honest release run. They do
not constrain a run someone else started: a tagged commit can delete both the
check and the job's `environment:` line. Only the tag ruleset prevents that, for
everyone outside its bypass list. Repository administrators can change all of
these settings and remain inside the boundary.

Publication creates a draft release, uploads the fourteen assets and only then
publishes it, because GitHub refuses new assets on a published immutable
release. An interrupted run leaves the draft, and a rerun completes it. A
published release that lacks assets, or that does not report itself immutable,
stops the run.

To configure the settings in the GitHub web interface:

1. **Settings → Rules → Rulesets → New ruleset → New tag ruleset.** Name it
   `release tags` and set enforcement to Active. Add Repository admin to the
   bypass list. Under target tags, include by pattern `v*`. Enable Restrict
   creations, Restrict updates and Restrict deletions.
2. **Settings → Environments → New environment** named `release`. Add the owner
   as a required reviewer and leave self-review allowed. Under deployment
   branches and tags, choose selected branches and tags and add the tag pattern
   `v*`.
3. **Settings → General → Releases:** enable release immutability.

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

## Release versions

Release tags are `v` followed by the SemVer version of the shipped pair. A
prerelease is spelled `alpha.N`, `beta.N` or `rc.N`, where `N` is a numeric
identifier, for example `v0.6.0-rc.2`. SemVer compares a dot-separated number
numerically but an attached one as text, so `rc10` orders before `rc2` and every
`rc.N` before `rc1`. Update offers, the managed installer's downgrade refusal
and the remote daemon cache selection all use SemVer precedence.

On a tag run, every job that validates the shipped pair version refuses another
prerelease spelling. Before signing, the publish job also lists the repository's
version tags and releases. It refuses the tag unless it has greater precedence
than every other tag of the same `major.minor.patch`, including that version's
final release. Tags of other versions do not constrain it, so a patch release of an
older line remains possible.

A re-run of a tag whose release is already published and immutable is a retry,
not a new publication, so it is accepted even after a newer tag of its version
exists. It cannot change the release: it reuses the published signature only
after native verification and only if the assembled `SHA256SUMS` equals the
published one, the uploader compares the digest of every published asset, and
a published immutable release cannot gain assets. A tag without a release, or
whose release is still a draft or is not immutable, is a new publication and
must outrank every other tag of its version. A draft left by an interrupted run
can therefore be completed only while no newer tag of its version exists.

`v0.6.0-rc1` was published before this rule. The owner withdrew it and deleted
its release and tag, because it orders above every `0.6.0-rc.N` and its tag
would refuse each of them. A host that still caches
`~/.cache/qsh/qshd-0.6.0-rc1-<arch>` (with a `-darwin` suffix on macOS) keeps
selecting it over a later `0.6.0-rc.N` until that file is removed. Distribution
packages are unaffected: `dpkg` and `rpm` order `0.6.0~rc.2` above `0.6.0~rc1`.

## Compatibility and publication

The existing unsigned v0.5.0 release is not backfilled, replaced or exempted.
New automatic loaders refuse it and unsigned preexisting cache generations.
Older released clients retain their previous behavior. An already supplied or
installed daemon follows its existing explicit source policy; it is not selected
to hide a metadata authentication error.

Branch assembly remains twelve products plus `SHA256SUMS`. Tag publication adds
only the bundle, for fourteen release assets total.

Product names carry the release version exactly as in the tag, for example
`qsh_0.6.0-rc.2-1_amd64.deb`; only package metadata uses `0.6.0~rc.2`. A
version whose names GitHub would rewrite, such as one with build metadata, can
be neither assembled nor authenticated. The client's manifest contract and
release assembly are tested against each other by running assembly.

Manifests that name packages with the earlier `~` spelling are refused, so each
version has one manifest layout. This is a deliberate compatibility break for
the only signed manifest with that spelling, the withdrawn `v0.6.0-rc1`: a
client with this rule cannot authenticate any rc1 product, including its four
archives, whether downloaded or from cached evidence. rc1's client predates
managed installation, so no managed generation holds rc1 evidence. Stable names
are unchanged. rc1's assets, signature and release notes were never rewritten;
the owner withdrew rc1 by deleting its release and tag before `v0.6.0-rc.2`. The next separately authorized
release must include the signing workflow before distributing an enforcing client.
Its first real qsh attestation must pass the production verifier, including exact
checkout-commit binding, before upload. Public upstream fixtures and synthetic
loader/CLI fixtures do not prove that a qsh release was signed. Do not create or
move a tag merely to validate this change. See [Actions maintenance](actions-maintenance.md).
