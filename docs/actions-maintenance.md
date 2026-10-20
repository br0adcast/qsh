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

## Release source qualification

Tag publication requires the complete ordinary CI workflow at the release
run's exact commit: macOS portable tests; formatting, Clippy, workspace unit
and integration tests, and separate doctests; and the privileged disposable
container tier with its required-test and silent-skip checks. Native crypto,
package builds and installed-package acceptance remain required independently.

The release workflow calls the local reusable CI definition from its own
commit. Source checkouts use `github.sha` and log and verify the actual checked
out commit, run ID and attempt. A rerun retains the original event's SHA; it
does not qualify the current tip of a branch or tag instead. A previous main
or PR merge-ref success is not substituted for this qualification.

Branch package dispatches still assemble, scan and upload artifacts without
running another full ordinary suite. They cannot publish. Only the separate
tag-only publication job has `contents: write`, and it requires successful
ordinary CI and artifact assembly. Failed or skipped qualification prevents
publication; do not add `always()` or `continue-on-error` to bypass that gate.
An ordinary CI dispatch can qualify a branch explicitly without packaging.
