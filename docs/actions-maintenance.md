# Updating GitHub Actions

External actions in `.github/workflows/` use full commit IDs. A nearby version
comment identifies the reviewed release; it does not replace the immutable
reference. Local reusable workflows use their repository paths.

## Review the revision

1. Start from the action's upstream repository and release notes. Resolve the
   selected release to its full commit ID, dereferencing annotated tags when
   necessary. Verify that the commit belongs to that upstream repository.
2. Compare the current and proposed revisions, including `action.yml` or
   `action.yaml`, executable code and bundled JavaScript. Check runtime and
   runner requirements, changed inputs, defaults, outputs and post-job cleanup.
   For composite actions, inspect their nested dependencies too.
3. Check the behavior qsh relies on: checkout credentials and container access,
   cache keys and restore behavior, artifact names and directory layout, and
   compatibility between artifact upload and download versions. Use upstream
   migration notes when changing a major version.
4. Update every affected reference and its version comment in one focused PR.
   Preserve workflow triggers, permissions, runner matrices, conditions and
   inputs unless a reviewed migration requires a separate change.

GitHub's [secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use#using-third-party-actions)
explains revision verification and source review. Pinning identifies the code
being run; it does not establish that the code or its fetched dependencies are
safe. Runtime deprecation warnings call for reviewing an update, not suppressing
the warning.

## Validate the proposed commit

Run the affected PR checks and inspect complete job logs, including post-job
steps, for runtime warnings and changed behavior. Record the proposed commit
and run links in the PR; passing checks for an older commit are not evidence
for a newer revision.

For actions used by packaging, also run
[the Release workflow](../.github/workflows/release.yml) against the PR's
**branch** using `workflow_dispatch`. Confirm the run's commit matches the
proposed changes. A branch run builds packages, checks installation on both
architectures, collects checksums, scans artifacts and uploads `dist`; its
tag-only publication steps must remain skipped.

Check that the resulting artifacts are present and retain the expected names
and layout. For upload/download migrations, verify both sides in the same
workflow, including package consumption and the final `dist` artifact.
Do not create or move a release tag or replace published assets to validate an
action update.

Keep failed checks visible and investigate them before merging. If a failure
is independently shown to be unrelated, record that evidence and any diagnostic
rerun explicitly. Include upstream revisions, relevant migration decisions and
completed validation in the PR so the next update has a traceable starting point.

## CI lane selection

A pull request runs only the lanes its change can reach (#609). The `Select CI
lanes` job of [CI](../.github/workflows/ci.yml) classifies every changed path
with [`scripts/ci-selection.json`](../scripts/ci-selection.json); the `CI gate`
job is the single result to watch.

| Lane | Cells |
|---|---|
| `docs` | `Documentation controls`: release verification recipes with bash, dash and zsh |
| `check` | Linux formatting, Clippy, nextest, doctests and script controls |
| `container` | floor compiler and the privileged disposable tier |
| `macos` | macOS 15 and macOS 26 portable tests |
| `native` | the four native product targets |
| `intel-owner`, `intel-legacy` | Intel Darwin process owner and legacy service, macOS 15 and 26 |
| `floors` | deb and rpm system package floors |
| `peers` | released-peer acceptance |
| `fuzz` | fuzz smoke |

How a path selects lanes:

- **Full matrix:** workflows, the selection policy and its controls, every
  Cargo manifest and lock file, toolchain files, `.config/`, `deny.toml`,
  `build-support/`, every `build.rs`, the dependency-policy and
  nextest runner inputs, an unknown path, and any uncertainty about the change
  set (an unreadable manifest, a malformed diff, an empty change).
- **Rust crates:** every lane whose jobs build the crate. The dependency
  closure comes from the manifests at both base and head, with every edge kind.
  `intel-owner` and `floors` build only the `qshd` closure, and `fuzz` only the
  fuzz crate's closure. The other Rust lanes build the whole workspace.
- **Reviewed boundary crates** (`render`, `prediction`) select `check` and
  `container`. `check` runs their tests and every dependent workspace test.
  The boundary is revoked, and the crate takes its dependent lanes again, if:
  - the crate enters the `qshd` closure;
  - its dependents or dependencies differ from the reviewed sets;
  - a file outside the crate includes one of its files;
  - a tripwire finds a platform surface: a `cfg` other than `test`, a `std`
    module outside the reviewed list, `Instant`, `SystemTime`, `unsafe`,
    `extern`, `asm!`, `env!`, `file!` or an include;
  - a tripwire finds a path it cannot follow: an alias or bare use of `std`,
    `core` or `alloc` (`use std as p`, `std::{self as p}`, `std::*`, a root
    handed to a macro or call), a nested or computed `std::` path,
    `macro_rules!`, or a `#[path]` other than a plain file name.

  Tripwires read the code with its comments removed by a Rust lexer, so a
  line such as `*out = …` stays code and `std /* */ :: fs` is still `std::fs`.
  Doc comments count as code for platform names, because doctests compile them.
  Source the lexer cannot follow revokes the boundary.
  Tripwires only revoke the boundary; membership is a reviewed policy change.
  The residual risk is platform-specific output volume or timing; Nightly and
  release qualification still run every lane.
- **Scripts and packaging:** `check` (and `floors` for `packaging/`), plus
  every lane whose job, script, test or crate reads the file, transitively. A
  file that only mentions another is counted as reading it, so this side
  errs broad.
- **Documents:**
  - `README.md` and `CHANGELOG.md` select `docs` and `check`, which runs the
    release assembly and output controls. Package and artifact acceptance
    stay with release qualification. Release notes extraction from
    `CHANGELOG.md` runs only in `publish`.
  - Licenses select `check`.
  - The listed prose files select `docs`, unless a file outside the reviewed
    mentions reads them or a Rust file includes them; then the full matrix
    runs.

A push to `main` runs the Linux smoke: `check` and `container`, or `docs` for
a documentation-only push. The other lanes are reported as
`DEFERRED_TO_NIGHTLY`. [Nightly](../.github/workflows/nightly.yml) runs every
lane for main's commit. A scheduled run reuses evidence only when it finds a
completed, successful full qualification of the same commit under the same
policy digest: a release, a Nightly or a top-level CI dispatch with its
`qualification.json`. It then reports `REUSED`. A reduced PR gate or main
smoke never qualifies. A failed Nightly stays failed and the next schedule runs
again.

To qualify any branch or commit in full, dispatch CI (`workflow_dispatch`) or
Nightly on it.

The `CI gate` reads the jobs API for its own run (`actions: read` only). The
jobs API names a pull request's head commit, while the checkout tests the
synthetic merge; both are verified and recorded. The gate fails when:

- a selected cell is missing, duplicated, not successful, or still unresolved
  after five minutes (a job listed as completed without a conclusion yet
  counts as unresolved, not failed);
- a job it does not know appears in its run;
- a skipped job keeps a lane template that the lane needed;
- the selection record is missing or names another source;
- a not-selected lane ran and failed.

On a partial rerun, each job's newest execution counts. Successes kept from
an earlier attempt are reported as retained, with the attempt that executed
them.

`main` has no required checks. Making `CI gate` required is a separate,
reviewed settings change.

## Release source qualification

Tag publication requires the complete ordinary CI workflow at the release run's
exact commit: macOS 15 and macOS 26 portable tests; formatting, Clippy,
workspace unit and integration tests, and separate doctests; and the privileged
disposable container tier with its required-test and silent-skip checks. Native
crypto, released peers, fuzz smoke, package builds and installed-package
acceptance remain required independently.

`Release qualification` accounts for every expected cell of every lane by the
jobs API before `publish` may start; a called workflow's success cannot hide a
skipped cell. Release calls CI with `caller-runs: native peers fuzz`: CI then
runs only its own lanes and reports the rest as delegated to the caller.

The release workflow calls the local reusable CI definition from its own
commit. Source checkouts use `github.sha` and log and verify the actual checked
out commit, run ID and attempt. A rerun retains the original event's SHA; it
does not qualify the current tip of a branch or tag instead. A previous main
or PR merge-ref success is not substituted for this qualification.

Branch package dispatches still assemble, scan and upload artifacts without
running another full ordinary suite. They cannot publish. Only the separate
tag-only publication job has `contents: write`, `id-token: write` and
`attestations: write`, and it requires successful ordinary CI and artifact
assembly. Failed or skipped qualification prevents publication; do not add
`always()` or `continue-on-error` to bypass that gate. An ordinary CI dispatch
can qualify a branch explicitly without packaging.

## Signed release manifest

A tag publication adds one asset to the twelve products and `SHA256SUMS`:
`SHA256SUMS.sigstore.json`, a Sigstore bundle for the manifest's exact bytes.
The `release-verifier` job builds the `release-auth` example `verify-release`
from the tag's commit with `--locked`, without signing authority or a restored
cache. The `publish` job then runs `scripts/prepare-release-attestation.py`:

- **Preflight.** It reads the tag, the release and both metadata assets and
  changes nothing.
  - A published manifest must equal the assembled one.
  - A published bundle is reused, byte for byte, if the verifier accepts it for
    that manifest and the tag's commit.
  - Otherwise `actions/attest` signs the manifest once, and the new bundle is
    verified before anything else uses it.
- **Hard stops.** Any of these stops publication, and nothing is deleted or
  replaced: invalid evidence, a conflicting manifest, a duplicate, incomplete or
  oversized asset, or a GitHub API, authentication or network failure. An API
  failure is never read as an absent asset.
- **Upload.** The uploader gets exactly fourteen files, with the bundle before
  the manifest.

A publication interrupted after the bundle was uploaded is completed by
rerunning the failed jobs of the same run. That reuses its `dist` artifact, and
so its manifest bytes. A new run rebuilds the products, and its different
manifest conflicts with what is published.

A second publication of the same tag waits until a running one finishes instead
of racing it, and a running publication is never cancelled. GitHub keeps only
one waiting publication per tag: a newer one replaces an older waiting one.

`v0.5.0` was published before this signing existed. Its release is refused
rather than signed after the fact, and its tag and assets are left as they are.


## Enforcing clients and packaged notices

Automatic loaders require the signed manifest/bundle for the exact version;
[release authentication](release-security.md) describes outage, cache and legacy
compatibility rules. Before distributing an enforcing client, the next separately
authorized tag must pass production verification of its own signed evidence before
upload. Do not publish a checksum-only exception for v0.5.0 or replace its assets.

Combined client/daemon archives and client DEB/RPM packages must retain the exact
`LICENSE-AWS-LC-RS.txt` and `LICENSE-AWS-LC.txt` notices, in addition to existing
notices. Server-only packages do not gain the client's AWS-LC edge. Archive checks
require the fixed document inventory and original maintained notice bytes; this
does not change the twelve-product allowlist or fourteen-asset publication set.
Qualify the actual qsh client on all four shipping targets, including native
linkage, complete artifact path scanning and notice layout. A successful verifier
example alone is only a prerequisite for those product checks.
