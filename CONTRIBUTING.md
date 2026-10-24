# Contributing

File bugs and suggestions under Issues; send changes as a pull request.

## Rust and native setup

Rust **1.98.1** is the intentional minimum supported version for every workspace
member. This is a support floor, not a claim that older compilers cannot compile
the source. The checkout selects it through `rust-toolchain.toml`, whose minimal
profile also requests rustfmt and Clippy. Ordinary Linux CI uses **1.99.1** for
current-toolchain quality and runtime checks; portable macOS and the existing
Linux container job cover the floor.

1. Install the floor toolchain and the current CI toolchain when reproducing
   those quality checks. Installation does not change the global rustup default:

   ```sh
   rustup toolchain install 1.98.1 --profile minimal --component rustfmt,clippy
   rustup toolchain install 1.99.1 --profile minimal --component rustfmt,clippy
   ```

2. Install a C compiler and binutils, Perl, make, GnuPG, Python 3, Bash, and curl.
   macOS needs the Xcode command-line tools/SDK (`xcrun` and `otool`). Linux
   `qshd/system` builds also require PAM development libraries. Integration tests
   need the OpenSSH server and client tools described below.

3. Prepare the verified static native RSA backend **before** any Rust product
   build, then export its prefix:

   ```sh
   target=$(rustc -vV | sed -n 's/^host: //p')
   native_prefix=$(bash scripts/build-openssl.sh --target "$target" \
     --cache "$PWD/target/native-crypto" --jobs 2)
   export OPENSSL_DIR="$native_prefix" OPENSSL_STATIC=1
   ```

   Follow [native crypto](docs/native-crypto.md) for source verification, target
   selection, cross builds, and qualification. Cross builds use the documented
   target-prefixed variables. A system OpenSSL installation is not a substitute
   for the qualified source/version/target manifest. CI and package builds use
   the same helper.

4. Check the effective floor declarations and compile the supported feature
   boundaries with the existing lockfile:

   ```sh
   cargo metadata --no-deps --format-version 1 --locked \
     | python3 scripts/check-rust-version.py
   cargo build -p qshd --bin qshd --locked
   cargo check -p transport --lib --no-default-features --locked
   # Linux system-mode workspace targets:
   cargo test --workspace --features qshd/system --locked --no-run
   ```

   These commands use the checkout's 1.98.1 toolchain unless explicitly
   overridden. They compile the default personal daemon, independent sans-IO
   transport library, and, on Linux, the complete workspace with the system
   feature. The existing portable macOS CI selection covers its native surface.
   They do not replace the current-toolchain runtime checks below.

The Cargo support floor and the exact compiler qualification for terminal
allocation bounds are separate. A newer compiler satisfying `rust-version`
does not extend [the resource qualification](docs/terminal-resources.md), whose
release/hash guard remains in place. Do not bypass a failing floor check by
ignoring `rust-version`, silently choosing another compiler, or changing the
lockfile outside a reviewed dependency update.

## Contribution licensing terms

qsh is dual-licensed: AGPLv3 for everyone, plus a commercial license from
the copyright holder. For that to keep working, everyone who submits a
change grants the copyright holder a perpetual, worldwide, non-exclusive,
royalty-free, irrevocable, sublicensable right to use, reproduce, modify,
distribute, and license the contribution to third parties on any terms,
including terms other than AGPLv3.

Without that grant, an accepted contribution would permanently tie those
lines to AGPLv3, and the copyright holder would lose the ability to cover
them under a commercial license. Contributions that don't agree to this
term unfortunately cannot be accepted.

Copyright in a contribution stays with its author.

**By opening a pull request, you confirm that you agree to the terms in
this section.**

## Requirements for changes

- Install [cargo-nextest](https://nexte.st/docs/installation/pre-built-binaries/)
  (CI pins version 0.9.148), then run the same ordinary-user test commands as CI:

  ```sh
  RUSTUP_TOOLCHAIN=1.99.1 QSH_TEST_QSHD="$PWD/target/debug/qshd" \
    python3 scripts/run-nextest-ci.py -- \
      cargo nextest run --profile ci --workspace --lib --bins --tests --locked \
      --features qshd/system
  RUSTUP_TOOLCHAIN=1.99.1 cargo test --workspace --doc --locked
  ```

  Run this from the workspace root. The explicit `QSH_TEST_QSHD` path makes
  shared bringup fixtures use the daemon produced by this workspace build,
  without rebuilding it with different features during the test run. If you
  change the Cargo target directory or build profile, set the matching absolute
  executable path. An invalid override fails without a build fallback. Omit the
  override for standalone bringup tests that should build a fresh daemon.

  Nextest runs each test in its own process, including tests that exercise PAM
  and change process-wide descriptor state. `.config/nextest.toml` limits
  concurrency and serializes daemon integration suites whose port-selection
  mutexes otherwise protect only one process. Keep those groups when adding
  tests that share resources; do not enable retries to hide failures.
  Doctests run separately because nextest does not execute them.
  `--features qshd/system` is required: without it, system-mode code and tests
  are compiled out. Tests requiring root still run in CI's
  separate disposable containers, with the existing checks for silent skips.

  The ordinary runner executes the suite once and checks nextest's captured
  JUnit report, including successful stdout/stderr. Any runtime `SKIPPED`
  control fails the job. `scripts/nextest-exclusions.json` names exact test
  identities that belong to the disposable tier, with their reasons and owners;
  each must appear as excluded, and other filter exclusions fail. The runner
  overrides the profile default filter so this manifest owns ordinary selection.
  Safe tests in
  those same binaries still execute. The IPv6 PAM CIDR case belongs to the
  disposable tier with `NET_ADMIN`; the supplementary-group assertion stays
  mandatory in ordinary CI and requires the runner to have groups.
  Source-declared `#[ignore]` tests are listed separately, including subprocess
  bodies exercised by their owning wrappers, manual measurements and explicit
  key qualification. They are not counted as executed assertions. The existing
  container checks still verify their ignored-body count and required tests.
  The report remains at `target/nextest/ci/junit.xml`; the runner prints its size
  and checking time. With a custom target directory, pass `--report PATH` before
  `--` to place the report there too. To run the isolated pinned-nextest control,
  use `QSH_TEST_NEXTEST=cargo-nextest python3 -m unittest discover -s scripts/tests
  -p 'test_nextest_report.py'` (the control compiles only a tiny temporary fixture).
- The integration tests need an OpenSSH server at
  `/usr/sbin/sshd`, which they start on their own. Without `sshd` those
  tests fail rather than pass having checked nothing; `QSH_NO_SSHD=1`
  skips them instead, and each skip says so.
- Reproduce ordinary Linux CI's formatting and Clippy checks with its selected
  compiler (after the native setup above):

  ```sh
  RUSTUP_TOOLCHAIN=1.99.1 cargo fmt --all --check
  RUSTUP_TOOLCHAIN=1.99.1 cargo clippy --workspace --all-targets --locked \
    --features qshd/system -- -D warnings
  ```
- Changes to the native crypto build prerequisite follow
  [its source verification and qualification procedure](docs/native-crypto.md).
- Changes to GitHub Actions follow
  [the revision review and validation procedure](docs/actions-maintenance.md).
- A change to how `qshd` uses Linux-PAM (`qshd/src/helper/pam.rs`, the
  `system` feature) keeps `scripts/check-pam-linkage.sh` passing; its header
  says what it checks, and when only `--featureless-only` applies.
