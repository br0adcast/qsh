# qsh vte maintenance patch

This is the buildable source subset of crates.io `vte` **0.15.0**, from
<https://crates.io/api/v1/crates/vte/0.15.0/download> (upstream:
<https://github.com/alacritty/vte>, tag `v0.15.0`). The SHA-256 of the upstream
`.crate` archive is:

```
a5924018406ce0063cd67f8e008104968b74b563ee1b85dde3ed1f7cb87d3dbd
```

The upstream source and Apache-2.0/MIT license files are retained. The normalized
registry manifest has only the omitted README reference and example target
removed. Source unit tests remain inline; the archive's `tests/demo.vte` is
example input, unused by these tests, and is omitted along with upstream
examples, CI, benchmarks, docs, registry metadata and generated files.

`qsh.patch` records the source/manifest changes relative to that archive. The
standard-library parser counts OSC data bytes, including parameter separators,
before appending and accepts at most 8192 bytes. An oversized OSC is discarded
in full, with no OSC callback, through its existing BEL, ESC, CAN or SUB state
transition. ESC still begins a fresh escape sequence, so split ST and fresh ESC
recovery retain the upstream behavior. Ignored C0 controls do not occupy OSC
storage. The no-std fixed-buffer behavior is unchanged. Tests cover boundaries,
split termination, repeated overflows, separators and subsequent commands/text.

The patch also fixes a dropped character after a split UTF-8 sequence
(qsh #354, upstream alacritty/vte#159). When a sequence is split between two
`advance` calls, `advance_partial_utf8` completes it from the next bytes. In
upstream 0.15.0 the arm that finds a valid prefix followed by an incomplete
sequence printed only the prefix's first character but reported the whole
prefix as consumed. A split two-byte character, an ASCII character and the
lead byte of another multi-byte character lost that ASCII character, such as
the space between two Cyrillic words. The arm now reports only the first
character's bytes, as the arm for a fully valid buffer already does.
The same completion printed a C1 control (U+0080 to U+009F) that unsplit
input executes (upstream alacritty/vte#156). It now goes through the
dispatch unsplit text uses.

Dependency review on 2026-11-18 compared published 0.15.0 with upstream
snapshot `89c9c22f5b8fcc3feba0a9d9f50a020801e74acc`. Retain each functional hunk:

| Local change | Published release and inspected upstream disposition |
| --- | --- |
| Bound standard-library OSC data and discard an oversized sequence | Both still bound only the no-std buffer; standard-library pushes and OSC dispatch lack an equivalent cap/discard policy. |
| Count only the emitted character after a split UTF-8 prefix | Both still print the first character but report the whole valid prefix as consumed in the incomplete-tail arm. |
| Dispatch a completed split C1 character consistently | Both partial UTF-8 success arms still call `print` directly rather than the ordinary control/text dispatch path. |

Keep the manifest's source-subset normalization and associated unit coverage.
The latest published version remains 0.15.0; an unreleased snapshot is not a
replacement for a qualified release. Remove a functional hunk only after a
release supplies an equivalent correction and ordinary split/dispatch and
bounded-storage qualification succeeds. Historical issue closure alone does
not establish equivalence.

The workspace root selects this exact source with `[patch.crates-io]`. Cargo
patches apply only from the consuming workspace root: downstream workspaces
must explicitly carry the patch during integration. Keep this patch minimal and
recheck it against upstream on dependency upgrades.

Validation:

```sh
cargo test --manifest-path vendor/vte/Cargo.toml --features ansi
cargo check --manifest-path vendor/vte/Cargo.toml --no-default-features
cargo tree -i vte
```
