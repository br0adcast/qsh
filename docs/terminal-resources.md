# Terminal resource policy

qsh accepts logical terminals with **2–512 columns and 1–256 rows**, at most
131,072 cells. Network OPEN and RESIZE_REQUEST reject invalid geometry before
model or PTY allocation. A no-PTY channel does not create a terminal model or lease.
Local display sizes are adapted to these limits. A zero-sized physical display
suppresses wire resizes; one-column displays clip the two-column logical model.
Larger displays show a bounded top-left viewport (at most 512×257 including the
chrome row), without allocating for the full physical size. Desired window size
and committed remote geometry are separate: prediction and terminal parsing use
the committed geometry, while rendering crops/pads it into the current viewport.
A pending or refused resize does not reshape the authoritative model.

Daemon replay models have zero scrollback from construction. Client history is
limited to min(requested lines, 10,000, floor(1,048,576 / columns)); width growth
reduces that limit before resizing. That is a logical history policy: the
history-zero backing proof below does **not** describe client retained capacity.

## Admission and failure

A daemon-wide pool charges all screen models, including disconnected sessions.
Authenticated aliases sharing a uid share its owner pool. Limits are independent:

| Resource | Global | Per uid |
|---|---:|---:|
| Models | 64 | 16 |
| Cell backing slots | 33,554,432 | 8,388,608 |
| Row backing slots | 8,388,608 | 2,097,152 |

An OPEN reserves before allocating. A resize reserves the new retained envelope
and scratch before changing the PTY or emulator; cancellation releases the
provisional reservation. Commit releases scratch only. Shrinking does not refund
historical capacity. Installed model destruction releases its lease. An uninstalled
open retains its model lease until cleanup is proved, as described below. Refused OPEN/RESIZE_REQUEST
requests leave existing models intact and report the refusal. A shrink can need more
scratch than a grow, and valid dimensions do not guarantee budget admission.
These are finite storage reservations, **not practical host-memory limits**.

## Outstanding channel creation

Before scheduling a blocking constructor, the daemon admits at most **32 open
jobs globally and 8 per authenticated numeric uid**. Aliases of the same uid
share that limit. A session counts installed channels and unresolved opens
together against its eight-channel limit. Saturation refuses immediately;
there is no queue of tasks waiting for capacity. Construction and uninstalled
cleanup do not block the session loop or another session's control traffic.

A cancelled, failed or abandoned constructor keeps its capacity, child custody,
model and single screen lease until its owner proves either that no child was
created or that the exact child was reaped. A timeout, EOF, failed response,
process exit notification or Close request is not that proof. Unknown cleanup
therefore remains charged across runner replacement; it can reduce available
capacity indefinitely. The helper separately bounds live plus retired login
accounting to 256 entries, with at most 16 channel lifecycles per login. A retired
entry keeps the receipt route until cleanup is proved; it is not an unbounded
history of login IDs.

A daemon restart cancels uninstalled jobs and fences new admission and adoption.
The actual exec barrier shares the existing drain deadline and refuses replacement
while any such cleanup remains unresolved, even with no running session loop.
Successful adoption transfers ownership once to the installed channel; these
rules do not add a broader process-group shutdown guarantee for installed jobs.

## Resize outcomes and retained output

A resize first reserves and prepares the new model and scratch, then performs
the PTY ioctl, and only on success commits the model and stored request. Failure
releases provisional ownership and emits a correlated refusal with unchanged
geometry. Geometry shares the ordered output stream with DATA: old output is
parsed/rendered before the boundary and new output afterward. The CLI shows a
bounded live refusal notice even with `--status off`; that notice does not reduce
the remote geometry or generate another resize. A refused desired revision stays
latched across repaint and warm reconnect. Changing away and back allows retry.
The client keeps one request in flight and coalesces newer intent; reconnect
transfers intent/refusal state only to the same channel instance.

At the default uid limit, an initially 512×255 screen can refuse growth to
512×256 while remaining usable. A subsequent same-width shrink to 512×254 uses
2,097,136 simultaneous row slots, within the 2,097,152 limit. Acceptance tests
check the real PTY, authoritative outcome, repaint after warm reconnect and
addressed/wrapped rendering. A refusal is not evidence that all smaller sizes
will fit: retained high water and scratch still determine admission.

SSH resize has a different observable result: successfully sending a
`window-change` request is **Unconfirmed**, because SSH provides no remote ioctl
acknowledgement for it. A write failure is returned as an error; it is never
reported as confirmed remote geometry.

Each channel has one metadata budget shared by its producer and retained-output
bridge: 128 ordinary entries / 8192 declared bytes, plus a fixed lifecycle
allowance of 8 entries / 256 bytes (the concrete marker inventory uses 8 / 218).
DATA retains its existing per-channel output-gate charge.
Permits and DATA charges move with ownership through producer, bridge and bounded
transport admission; queue insertion or serialization alone does not release
them. The initial allowance includes both gap and bootstrap Geometry. Only Screen
DATA records may be sliced or replaced by a newer snapshot. NoScreen DATA requires
full-record admission and retains its bytes when credit is insufficient.

Stream identity maps are bounded by the 240 application stream IDs, not by an
append-only generation history. Teardown cannot debit a replacement instance.
Ended Screen output cannot regenerate from a destroyed model: its bounded final
snapshot/prefix and completion marker remain owned across attachment, together
with active/draining lifecycle metadata. Abandoning an unacknowledged DATA
frontier emits OutputGap: delivery to the application is uncertain, not proven
lost. Metadata replacement alone does not create a gap. Repeated attach preserves
an unacknowledged gap even without new DATA. Transport ACK is not application
display.

Before metadata/initial geometry, client retention is at most 64 KiB of DATA
payload / 256 events per channel. Unclassified channels additionally share a
512 KiB declared-byte / 2048-event limit across at most 240 unknown IDs. Declared
length checks precede bulk parser allocations. Active snapshot entries are at
most eight, but ended draining entries can occupy all remaining IDs. A partial
output record survives an early Exit until drained; replacing an instance retires
its parser, and repeated metadata cannot resurrect a completed instance.

These declared queue charges exclude heap wrappers and allocator overhead. The
model lease below does not bound all retained output, transport buffers, client
history or process RSS. Broad queue/RSS accounting and stronger abandoned-tail
continuity remain separate work; bounded retention is not exactly-once replay.

## Qualified storage implementation

The claim concerns requested allocation layouts of a history-zero leased model
and the explicitly counted simultaneous operations. It assumes ordinary
Global/System allocation, pinned alacritty_terminal 0.26.0, the workspace's
patched vte 0.15.0, and these exact Rust implementations:

| Release | Full compiler commit |
|---|---|
| 1.98.1 | `48a229ceaefd4985c50990b14116b6d856af0985` |
| 1.99.1 | `58cf8f9c35b355199727627d07ae34a4e2846d67` |

Rust's stable Vec API does not promise a growth factor. The audited RawVec
implementation grows to max(2×old capacity, required length, minimum capacity).
The minimum is eight elements for bytes/bools and four for the Cell/Row sizes
used here. Exact-length cloning/collection requests the slice/iterator length.
Drain/Rev collection in shrink_columns allocates a separate exact-length Vec;
its source backing remains alive during collection. The relevant alloc sources
are equivalent between the two qualified releases for these operations.

The checkout, package images, portable macOS CI and Linux container CI select
1.98.1; ordinary Linux CI and direct releases select 1.99.1. Cargo's declared
1.98.1 support floor is a source/toolchain policy, not an expansion of the two
exact compiler implementations qualified above. A newer compiler meeting that
floor does not automatically establish these allocation bounds. The existing
container CI job runs the focused observer on its 1.98.1 host compiler. `scripts/check-qualified-rust.sh` asks Cargo to invoke its
selected compiler on a temporary dependency-free probe and checks its actual
release/hash. Cargo resolves inherited configuration, including dotted and
quoted compiler keys; the guard does not infer the compiler from `PATH` alone.
Environment compiler/wrapper overrides are rejected in qualified entrypoints.
Installing a toolchain alone does not select it; entrypoints set
`RUSTUP_TOOLCHAIN`. This does not change a developer's global rustup default.
Downstream builds on other compilers meeting the support floor are permitted
but outside this qualification.
A consuming workspace must propagate the vte patch at its own Cargo root.

On a compiler, dependency, parser, or serializer upgrade: recheck the source
operations and copy lifetimes below, revise the named formulas, run the isolated
observer on every qualified compiler and target layout, then run normal CI.
Update the allowlist only after that evidence. Do not substitute an observed
multiplier for the source proof.

## Retained grid and resize derivation

Let W and R be maximum-ever columns and rows. Let K=1000 after any height
increase, otherwise K=0. All three are monotone until model drop. Source:
`qshd/src/screen_budget.rs` and Alacritty's grid/{storage,row,resize}.rs.

A reflow row contains at most an old row plus a remainder shorter than its new
width, at most 2W cells. The audited Vec growth gives at most 4W capacity.
Zero-history grids retain at most R+K row objects each: output alone creates no
history, but height growth initializes at least 1000 cached rows. Thus both grids
retain cell slots `C = 8W(R+K)`.

For shrink to width n≥2, charge each source cell once as content and once as a
possible wide spacer, plus W cursor-padding cells. Each full output row consumes
at least n−1 positions; allow R partial rows:

```
B(n) = R + ceil(((2R+1)W)/(n-1))
Bmax = R + (2R+1)W
M = 4(Bmax + R + K)
```

M bounds the outer row-vector capacities of both grids, including discarded
reflow rows whose metadata backing persists. Old cached values are truncated
before width reflow, but dropping values need not shrink capacity. Both grids
can have previously been primary; neither gets a visible-only allowance.

Width-change scratch is `S_cells = 4W(B+R+1)`, `S_rows = 4B+2R`, with B=B(n)
for shrink and B=R for growth. B covers split tails/destinations, R old buffers,
and one pending row; row slots cover two grown destination vectors and source
metadata. Height change reserves the new C/M again for initialization and realloc
coexistence. Mixed changes sum these allowances. The old retained reservation
remains charged; only one grid reflows at a time.

At 80×24 before height growth, C=15,360 and M=15,872. At maximum-ever 80×25
with K=1000, C=656,000 and M=20,520. On the tested x86_64 layout `Cell` is 24 bytes and
`Row<Cell>` is 32 bytes, that latter backing envelope is 16,400,640 bytes. Eight
such models reserve 5,248,000 cells and 164,160 rows, fitting the owner pools.
At maximum-ever 512×256, C=5,144,576 and M=1,056,672; a subsequent severe
narrow reflow can be refused. These envelopes intentionally exceed usual usage.

## Payload and ancillary ledger

Write A(T) for the padded allocation layout of two AtomicUsize Arc counters
followed by T. Use actual target sizes, not just sizeof(T) for an Arc. The observer
uses real CellExtra/Row/Cell types; HyperlinkInner is a reviewed two-String
structural mirror. A conservative extra allowance per materialized cell is:

```
E = A(CellExtra) + 32*sizeof(char) + A([String;2]) + 4097
retained = C*sizeof(Cell) + M*sizeof(Row<Cell>) + (C+4)*E + ancillary
```

C overcounts materialized cells by including spare slots; four are the two
grids' cursor templates. Distinct hyperlinks are not interned. Arc clones share
the strings; make_mut can temporarily allocate one more extra and combining Vec.
Do not multiply shared hyperlink payloads by every temporary grid clone.

| Storage | Retained requested-byte allowance / behavior |
|---|---|
| Combining characters | At most 16 scalars per cell; Vec capacity ≤32 chars even after clone and growth. Excess marks are discarded; REP input state is still tracked. |
| Hyperlinks | Accepted id+URI length ≤4096; over-limit links clear the pen. Fresh copies discard arbitrary incoming capacity. Missing id reserves 19 length bytes; upstream generated id capacity can be 20, so combined backing ≤4097. |
| Current title | UTF-8 prefix ≤1024 bytes, capacity ≤2048 because upstream clone_from can grow retained storage. |
| Saved titles | ≤4096 entries, each fresh clone ≤1024 bytes; outer Vec ≤8192 Option<String> slots. |
| Sync parser | One eager 2,097,152-byte buffer. Flush moves it temporarily; it does not clone it. |
| Live OSC parser | Raw data including separators capped at 8192 before append/dispatch; overflow discarded until termination/cancellation. Allow 16,384 capacity conservatively. |
| Pending replay tail | Sliced input ≤4096, geometric checks capped at 1,048,576; pretrim length L≤1,052,672, capacity ≤2L, including after clearing. An overlong unfinished sequence loses replay tail until fresh ESC. |
| Classification parser | Separate OSC capacity ≤16,384 only during classification. Callback recorder is a fixed inline array of three entries; initial-feed callbacks are ignored. |
| Tab vectors | Two bool vectors, each ≤max(8,2W) bytes; bool is not bit-packed. |
| Damage | ≤2R LineDamageBounds slots. |
| Configuration | Default semantic_escape_chars String length; other fixed state is inline in the model. |

The `ancillary` function in the observer sums exactly these retained terms.
Inline stack-owned models are not charged again as heap allocations. If a caller
boxes the model it must add its layout. Kitty keyboard support remains disabled
by Config; enabling it requires another stack audit. In this upstream version
the full keyboard-stack path removes title_stack entries instead of keyboard
entries, so this document makes no enabled-kitty-stack claim.

The separate `feed_scratch` sum counts the classification parser; unhandled OSC
formatting (≤10 bytes per raw byte plus three delimiters per ≤16 parameters,
then doubled capacity); title parameter descriptors, joined and trimmed strings;
reconstructed URI and id; adapter copies and generated id growth; bounded title
input/event copies; OSC52 decoded bytes; xparse_color's slash collector; a
ColorRequest closure/prefix/terminator; fixed CSI replies (≤64 output bytes,
doubled backing); and one copy-on-write extra. These are mutually exclusive in
places, but adding them is conservative. VoidListener drops events synchronously;
callback bodies are not executed. External logger/consumer allocations are not
model storage. No unbounded input-sized formatting allowance is assumed.

For resize peak add backing(S), `(S_cells+4)*E`, feed scratch, and another
ancillary allowance to the new retained bound. This deliberately counts shared
extras again in scratch and permits old/new auxiliary backing coexistence.

## Replay and copies

For c columns, r rows, and tail length t≤L:

```
B = replay_max_len(c,r,t) = 2r(153c+555) + 12c + 6956 + t
```

The following primitive byte bounds derive from `crates/terminal/src/replay.rs`:
CUP U=10; SGR S=74 (reset, six flags, underline style, three RGBs);
printed glyph+16 combining scalars G=68; put P=S+G=142; erase_row Erow=87;
reprint_last_column J=162 including dropped-mark repair; designate D=12;
place=248; rewrap=142; set_last_printed Q=183. The saturated last-column search
uses a refused wide glyph and emits at most 22 bytes; it returns after its first
candidate. It does not emit on every scanned cell.

Each paint visits at most c own-row cells per row, plus one next-row wrap put.
Charge row entry U, tail S+3, and leading-wide-placeholder repair
2Erow+U+S+G independently. This gives r(142c+555). Each fix_tabs visits at most
rc cells with CUP+TAB=11 bytes. There are at most two paints and two fix_tabs.

| Top-level write section outside those loops | Maximum bytes |
|---|---:|
| Initial reset/preparation | 37 |
| Optional primary cursor/alternate entry | 408 |
| Active saved-cursor preparation (exclusive branches) | 395 |
| Palette: four resets, 256 indexed and three dynamic colors | 5454 |
| Tab reset and at most c tab stops | 4+12c |
| Last printed restoration | 183 |
| Modes and cursor style | 111 |
| Scroll region | 10 |
| Origin mode | 5 |
| Final cursor restoration | 253 |
| Insert/LNM/designation/charset/pen | 96 |
| Parser tail | t |

The fixed entries sum to 6956. Coordinates, including scroll-region restoration,
have at most three decimal digits. Indexed palette entries are ≤21 bytes,
dynamic entries ≤18. At maximum geometry/tail B=41,457,964 bytes; this is an
arithmetic check, not a stress fixture or typical output size.

Replay Vec capacity ≤max(8,2B). A replay while alternate is active temporarily
clones the **entire retained alternate Grid**, including cached rows; charge C/M
again for its backing, but its extras/links share Arcs. A conservative source
peak allows 4B for old/new output realloc backing, B+5 for an encoded record,
one copy-on-write extra, and formatting strings ≤148 SGR /24 palette bytes.
The observer cannot see allocator-internal old/new realloc residency; these
analytic allowances are separate from its observed live-request counter.
`encode_record` requests exactly replay.len()+5 while replay remains alive.

A frame owns exactly c×r public Cells plus A(Palette). Public `terminal::Cell`
keeps its base `ch` and up to 16 zero-width scalars in an inline `CombiningMarks`
value; no cell suffix allocates. Cells remain `Copy`, and copying or moving a
cell preserves its complete text. On the qualified x86-64 build, a public Cell
is 92 bytes (previously 24): cell backing is 176,640 bytes for 80×24, 1,104,000
for 200×60, and 12,058,624 for the 512×256 maximum, plus the palette allocation.
These sizes are target/compiler observations; the observer uses `size_of` rather
than assuming the layout. Model geometry limits and reservations are unchanged.
This increases caller-retained frame memory, not the daemon's model charge.

Public consumers constructing exhaustive Cell literals must initialize
`combining` (or use `..Cell::blank()`). Read the complete text as `ch` followed
by `combining.as_slice()`; `set_char` replaces text and clears the suffix.
`FLAG_HIDDEN` carries SGR 8 concealment through rendering. Concealment controls
appearance only: the text remains in frames, replay and terminal output.

A snapshot owns up to two
visible pictures: 2cr CellStates, 2r row Vec descriptors, at most 16 chars per
cell and three cursor pens, c tab bools, and 259 optional RGB entries. Its
primary capture can overlap the retained alternate Grid clone. Private snapshot
CellState layout is a reviewed same-field-type structural mirror in the observer.

Resize and replay require exclusive access to one model, so do not sum their
peaks for that model. Independent backends may overlap; model count and independent
cell/row pools bound the sum of their model reservations. The upper bound is
large: distinct capped hyperlinks at maximum geometry can require gigabytes.
Do not interpret finite requested storage as a guarantee of allocation success.

## Regression evidence and exclusions

Run the isolated observer with:

```sh
RUSTUP_TOOLCHAIN=1.98.1 cargo test -p qshd --lib screen_budget::allocation_bounds -- --nocapture
RUSTUP_TOOLCHAIN=1.99.1 cargo test -p qshd --lib screen_budget::allocation_bounds -- --nocapture
```

It lives beside ScreenEnvelope to consume production retained/scratch formulas
without a terminal-to-daemon dependency or a production API made only for tests.
It spawns an exact-filter, single-test subprocess. Constant thread-local counters
exclude unrelated harness threads; no model work moves between threads. Hooks
allocate nothing. Successful realloc replaces the old requested size; failure
preserves it. A controlled allocation/grow/shrink/drop and an intentionally too
small bound validate the observer. Fixtures precede metering and final model drop
must return live requested bytes to zero. These tests supplement the source
proof; optimizations can eliminate allocations, and small fixtures are not proof
of every possible input history.

The claim excludes RSS, allocator headers/bins/fragmentation/mappings, arbitrary
caller-retained snapshots/frames/replays, and queued transport records. In
particular the transport gate alone does not bound repeated repaint enqueues;
queue multiplicity is tracked separately in issue #26. Neither the cell pool nor
this ledger is a full-process memory ceiling. Client scrollback, caller-owned
input fixtures, daemon infrastructure, external logs and other tasks have their
own storage lifetimes outside this per-model bound.

These bounds apply to executables with the same terminal policy. Older clients
can retain additional combining marks; replay repair preserves cursor position
and the last input scalar but cannot impose a new memory policy on another
executable. Protocol-1 clients cannot establish QSH sessions with the current
protocol-2 daemon.

## Keyboard input during opening and recovery

The CLI retains unsent input while opening the shell channel, reconnecting, or
waiting for the retained channel to be announced. One compact FIFO spans these
states; channel readiness transfers its bytes to one guarded send action. Input
already admitted by a previous transport driver never enters this FIFO and is
never replayed. Confirmed loss of the previous shell discards its unsent input
with a notice.

Keyboard source custody and recovery storage have separate bounds:

- Source input retains at most 64 KiB of original bytes and 64 KiB of original
  allocation capacity across the reader, queued UI events, parser aliases and
  actions. Each nonempty read consumes byte credit, so there are at most 65,536
  original read permits. Read count itself does not terminate the client.
  Provenance aggregation deduplicates permit identities with ordered lookup.
- Recovery storage owns at most one 64 KiB allocation and reservation per client
  session, including an emitted action still holding that allocation. Its FIFO
  metadata does not grow with the number of historical reads. Copying into this
  FIFO does not refund source credit until every actual source alias drops.
- The reader additionally owns one fixed 4096-byte scratch read. Existing parser
  and action copies retain source provenance; these phase allowances and heap
  wrappers are distinct from the source and recovery allocation bounds above.
  These limits do not describe total process RSS or transport retention.

At exactly full recovery storage, local escape commands such as `Ctrl-] .`
remain available through the source phase. An append exceeding the actual byte
limit is rejected whole. Source saturation that remains after earlier input has
been processed also fails explicitly. Either local failure reports undelivered
input, discards unsent commands and exits nonzero without closing the remote
session. No partial command is silently clipped or replayed on a later attach.
Bracketed paste keeps its existing literal escape-prefix semantics.
