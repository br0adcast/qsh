# Contributing

File bugs and suggestions under Issues; send changes as a pull request.

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
  QSH_TEST_QSHD="$PWD/target/debug/qshd" \
    cargo nextest run --profile ci --workspace --lib --bins --tests --locked \
      --features qshd/system
  cargo test --workspace --doc --locked
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
- The integration tests need an OpenSSH server at
  `/usr/sbin/sshd`, which they start on their own. Without `sshd` those
  tests fail rather than pass having checked nothing; `QSH_NO_SSHD=1`
  skips them instead, and each skip says so.
- `cargo fmt` and `cargo clippy` are clean on the files you changed.
- A change to how `qshd` uses Linux-PAM (`qshd/src/helper/pam.rs`, the
  `system` feature) keeps `scripts/check-pam-linkage.sh` passing; its header
  says what it checks, and when only `--featureless-only` applies.
