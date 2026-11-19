# Isolated fuzz tooling provenance

The selected tool source is official `cargo-fuzz 0.13.2`; the runtime dependency is exact
`libfuzzer-sys 0.4.13`, with pinned `nightly-2026-10-24`. Verify the archive and lock hashes below before installation. Official sources:

- https://github.com/rust-fuzz/cargo-fuzz/tree/0.13.2
- https://github.com/rust-fuzz/libfuzzer/tree/0.4.13
- https://static.rust-lang.org/dist/2026-10-24/channel-rust-nightly.toml

`cargo-fuzz` and its Rust wrappers declare MIT OR Apache-2.0. The published
`libfuzzer-sys` manifest declares `(MIT OR Apache-2.0) AND NCSA`; its packaged
C++ headers declare `Apache-2.0 WITH LLVM-exception`. Preserve both declarations,
the archive's original MIT/Apache notices and the corresponding full LLVM
license/exception/legacy NCSA attribution when distributing a fuzz binary.
The corresponding LLVM source license is:
https://github.com/llvm/llvm-project/blob/a47b42eb9f9b/LICENSE.TXT .
No bundled C++ implementation is copied into this repository. The fuzz-local
license exceptions apply only to this graph; product license policy is unchanged.

The tool's official shipped lock contains `RUSTSEC-2026-0190`
(`anyhow 1.0.102`), `RUSTSEC-2026-0204` (`crossbeam-epoch 0.9.18`), and
`RUSTSEC-2026-0486` (`rustix 1.1.4`). These are development-tool findings,
not demonstrated product defects. The reviewed tool-only lock at
`tools/cargo-fuzz-0.13.2.Cargo.lock` changes exactly those packages to
`anyhow 1.0.103`, `crossbeam-epoch 0.9.20`, and `rustix 1.1.6`.
The other 98 complete package records and their dependency edges remain
unchanged from the verified release archive. This preserves the release-based
installation graph instead of broadly refreshing it. The rustix repair follows
the advisory's patched range without an exception; no vulnerability reproducer
is run. Fresh strict advisory, yank, license, source and ban checks qualify the
current reviewed lock; they remain time-sensitive.

Reproduce installation only from the verified official 0.13.2 crate archive
(SHA-256 `5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2`),
with that reviewed lock copied over its shipped Cargo.lock. Use
`cargo install --path OWNED_SOURCE --locked --root OWNED_TOOL_ROOT` with owned
HOME/CARGO_HOME and the selected toolchain. Registry installation with
`--version 0.13.2 --locked` would restore the affected shipped lock and is not
the reviewed procedure. The current source-and-reviewed-lock installation and
version check use pinned `nightly-2026-10-24`
(`rustc 1.101.0-nightly`, commit `48f4b0553`,
LLVM 23.1.4). Use `rustup toolchain install nightly-2026-10-24 --profile minimal
--no-self-update` with owned `RUSTUP_HOME` and `CARGO_HOME`; this does not require
installing or updating rustup globally.

The separate fuzz graph keeps every package shared with the product lock at
the exact product-lock version and source. Its root `[patch.crates-io]` mirrors
the product's local `vte`, `alacritty_terminal` and `ssh-key` maintenance sources;
patches are not inherited from a dependency's workspace root. Relative to the
product lock, the fuzz graph adds only
`arbitrary 1.5.0`, `libfuzzer-sys 0.4.13` and the local
`qsh-channel-fuzz` package. `libfuzzer-sys` builds bundled C++17 through
`cc`/`ar`. The graph now links `sshauth` and `terminal`, so the pinned native
OpenSSL prefix from `scripts/build-openssl.sh` is required for the
`authorized_keys` target; the target calls only the in-memory listing parser
with a fixed public key and never performs a private RSA operation.

Historical qualification, before the 2026-11-17 dependency refresh: ordinary
library tests compiled the C++ dependency using GCC 13.3 and GNU ar 2.42. The
six ASAN targets used Rust address-sanitizer and coverage instrumentation. All
101 fixed seeds replayed successfully, and six bounded mutation smoke runs
completed without a reported failure. A temporary harness-only fault control
produced a retained reproducer and was minimized without reducing it. See
`README.md` for the measured build, replay, mutation and control results and
their limits. Current graph, security and build checks are recorded separately
for the refreshed dependencies.

`cargo-fuzz 0.13.2` does not forward `--locked` to its internal Cargo commands.
The approved procedure uses locked metadata preflight, committed lock hashes
before/after, and offline build/run. This detects lock drift; it is not command-
level locked enforcement. Advisory audits still require a fresh official
RustSec database/index and never use offline/stale fallback.

The reviewed tool lock SHA-256 is
`656496a435dc3df885bf60ad416fa989bf427465c4359abb95ea7b8b528e7f59`.
The standalone fuzz lock SHA-256 is
`fd25eba2062c9ca270a182f566c3fa9e50a3b9e39f3b91b022d6afcbdf046288`.
The preserved tool lock and refreshed fuzz lock contain 101 and 189 package
records respectively (2026-11-18).

Repeat security checks using the repository's pinned `cargo-audit 0.22.2` and
`cargo-deny 0.20.2`, normal network index updates and the official advisory DB:

```sh
cargo audit --file fuzz/Cargo.lock \
  --deny unmaintained --deny unsound --deny yanked
cargo audit --file fuzz/tools/cargo-fuzz-0.13.2.Cargo.lock \
  --deny unmaintained --deny unsound --deny yanked
cargo deny --manifest-path fuzz/Cargo.toml --config fuzz/deny.toml --locked check licenses sources bans
```

The refreshed fuzz graph contains exactly `rsa 0.10.0`. RustSec marks this
stable release as patched for RUSTSEC-2023-0071, so the previous prerelease
exception and audit ignore are removed. The targets still perform no private
RSA operation and use no real key. A different advisory or affected version
requires its own review.

Also run the license/source/ban check against the verified cargo-fuzz source
manifest with its reviewed lock substituted, using the same fuzz-local config.
Inspect the full diagnostics: an exit code alone is insufficient if registry
checks report incomplete requests. The 2026-11-18 refresh qualification fetched RustSec DB commit
`233155b4025b854c68a4b199c0e32d7fd53291a2`; a future check must fetch current
data, rather than force that snapshot or disable yank checks.

## LLVM exception attribution

The following exception text is reproduced verbatim from the LLVM Project's
[LICENSE.TXT at a47b42eb9f9b](https://github.com/llvm/llvm-project/blob/a47b42eb9f9b/LICENSE.TXT),
SHA-256 `8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`.
It accompanies the bundled libFuzzer headers' `Apache-2.0 WITH LLVM-exception`
notices; the manifest's NCSA declaration and original MIT/Apache notices also
remain relevant. This repository adds a local development harness, not a
distributed fuzz binary or a copy of LLVM's implementation. Any future binary
distribution must preserve the applicable upstream notices and license texts.

```text
---- LLVM Exceptions to the Apache 2.0 License ----

As an exception, if, as a result of your compiling your source code, portions
of this Software are embedded into an Object form of such source code, you
may redistribute such embedded portions in such Object form without complying
with the conditions of Sections 4(a), 4(b) and 4(d) of the License.

In addition, if you combine or link compiled forms of this Software with
software that is licensed under the GPLv2 ("Combined Software") and if a
court of competent jurisdiction determines that the patent provision (Section
3), the indemnity provision (Section 9) or other Section of the License
conflicts with the conditions of the GPLv2, you may retroactively and
prospectively choose to deem waived or otherwise exclude such Section(s) of
the License, but only in their entirety and only with respect to the Combined
Software.
```
