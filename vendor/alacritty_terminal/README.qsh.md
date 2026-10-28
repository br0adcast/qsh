# qsh Alacritty terminal maintenance patch

This is the buildable source subset of crates.io `alacritty_terminal` **0.26.0**,
from <https://crates.io/api/v1/crates/alacritty_terminal/0.26.0/download>.
Upstream is <https://github.com/alacritty/alacritty>; the published archive records
commit `94e7c8874e526b1e67b349d9ba30ddf81669119e` and path `alacritty_terminal`.
The SHA-256 of the exact upstream `.crate` archive is:

```
bda177466b9524d59f1b12f0dd30b68696788e9992a7e959021c4a0ed96fcf59
```

The upstream source, README and Apache-2.0 license are retained. The normalized
registry manifest has only its standalone `ref` integration-test target removed.
Its approximately 46 MiB of reference recordings under `tests/ref` are omitted
along with that target, registry metadata, generated files, upstream changelog
and lockfile. Source library/grid tests remain buildable; no upstream library test body
has been removed or skipped.

`qsh.patch` records all source and manifest differences from that archive.
Width growth converts pending wrap into the next insertion column for the live
cursor even on a grid without reflow, and for the saved cursor on both grids.
The flag is cleared and the column advances by one, matching existing primary
live-cursor growth behavior. Height-only resize, unchanged dimensions and width
shrink retain their existing behavior. Grid tests cover current/saved cursors
with and without reflow and the unchanged resize controls. Product tests cover
primary/alternate transitions, save/restore, blank/wide cells and repaint
continuations, including preservation of prior inactive saved state.

Scrolling a region which starts below the top row leaves the history viewport
anchored: it does not add history, so it must not advance `display_offset`.
Top-origin scrolling keeps its existing offset and capacity behavior. Product
regressions cover partial and whole-region deletion, frame extraction while
scrolled to the oldest row, an in-range history anchor, and genuine history
growth through the configured cap.

Overwriting a wrapped wide character damages the previous row's leading spacer
only when that flag actually changes. Visible grid cells use bounded cell damage;
a changed history spacer while history is displayed forces full invalidation,
since the damage array cannot address negative history lines. When the viewport
is at the live bottom, history changes do not force full invalidation. Ordinary terminal workspace tests cover
both wide-character halves, absent spacers and consumed history invalidation.

The product and fuzz workspace roots select this same directory with
`[patch.crates-io]`. Downstream workspaces must explicitly carry this patch and
the separate `vte` patch during integration. Keep the patch minimal and review
it against the published upstream archive on upgrades.

The vendored crate is excluded from workspace membership so blanket workspace
formatting does not rewrite upstream source. Validate product behavior with
`cargo test --locked -p terminal`. Standalone upstream library/grid testing can
use an owned source copy and its own lockfile with an explicit local `vte`
patch; record that test graph separately from the product and fuzz lockfiles.
