//! Requested bytes, not RSS. See docs/terminal-resources.md for the source proof.
//! Kept beside the private admission implementation to use its actual formulas.
use super::*;
use alacritty_terminal::grid::Row;
use alacritty_terminal::term::cell::{Cell, CellExtra};
use alacritty_terminal::term::{Config, LineDamageBounds};
use alacritty_terminal::vte::ansi::Color;
use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell as Counter;
use std::hint::black_box;
use std::sync::atomic::AtomicUsize;
use terminal::{Palette, TerminalCore, TerminalOptions};

#[derive(Clone, Copy, Default, Debug)]
struct Counts {
    enabled: bool,
    live: isize,
    peak: isize,
}
thread_local! {
    // Constant TLS initialization and Copy state: hooks never allocate or lock.
    static COUNTS: Counter<Counts> = const { Counter::new(Counts { enabled: false, live: 0, peak: 0 }) };
}
fn allocator_backing() -> &'static dyn GlobalAlloc {
    #[cfg(feature = "system")]
    {
        crate::test_allocator::backing()
    }
    #[cfg(not(feature = "system"))]
    {
        &std::alloc::System
    }
}

struct Meter;
#[global_allocator]
static ALLOCATOR: Meter = Meter;
fn account(old: usize, new: usize, success: bool) {
    if !success {
        return;
    }
    let _ = COUNTS.try_with(|counter| {
        let mut s = counter.get();
        if s.enabled {
            s.live += new as isize - old as isize;
            s.peak = s.peak.max(s.live);
            counter.set(s);
        }
    });
}
// SAFETY: each method forwards the exact pointer/layout contract to the backing
// allocator, selected once per process (System in the observer child);
// accounting neither touches allocated memory nor changes allocation results.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { allocator_backing().alloc(layout) };
        account(0, layout.size(), !p.is_null());
        p
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { allocator_backing().alloc_zeroed(layout) };
        account(0, layout.size(), !p.is_null());
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        unsafe { allocator_backing().dealloc(p, layout) };
        account(layout.size(), 0, true);
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, n: usize) -> *mut u8 {
        let next = unsafe { allocator_backing().realloc(p, layout, n) };
        account(layout.size(), n, !next.is_null());
        next
    }
}
fn observe<T>(f: impl FnOnce() -> T) -> (T, Counts) {
    COUNTS.with(|c| {
        let mut s = c.get();
        s.enabled = true;
        s.peak = s.live;
        c.set(s);
    });
    let value = f();
    let counts = COUNTS.with(|c| {
        let mut s = c.get();
        s.enabled = false;
        c.set(s);
        s
    });
    (value, counts)
}
fn check(label: &str, counts: Counts, retained: usize, peak: usize) {
    eprintln!(
        "{label}: live={} peak={} bounds={retained}/{peak}",
        counts.live, counts.peak
    );
    assert!(within(counts, retained, peak), "{label}: {counts:?}");
}
fn within(s: Counts, retained: usize, peak: usize) -> bool {
    s.live >= 0 && s.live as usize <= retained && s.peak as usize <= peak
}
fn sum(terms: &[usize]) -> usize {
    terms
        .iter()
        .try_fold(0usize, |a, b| a.checked_add(*b))
        .unwrap()
}
fn times(a: usize, b: usize) -> usize {
    a.checked_mul(b).unwrap()
}
fn arc<T>() -> usize {
    Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<T>())
        .unwrap()
        .0
        .pad_to_align()
        .size()
}
fn backing(s: BackingSlots) -> usize {
    sum(&[
        times(s.cells, size_of::<Cell>()),
        times(s.rows, size_of::<Row<Cell>>()),
    ])
}
const OSC: usize = 8192;
const TAIL: usize = (1 << 20) + 4096;
const SYNC: usize = 2 << 20;
const TITLE: usize = 1024;
const TITLE_DEPTH: usize = 4096;
// HyperlinkInner in alacritty_terminal 0.26.0 has exactly two Strings.
// A generated id can have capacity 20, URI <=4077; explicit total <=4096.
fn extra() -> usize {
    sum(&[
        arc::<CellExtra>(),
        32 * size_of::<char>(),
        arc::<[String; 2]>(),
        4097,
    ])
}
fn ancillary(w: usize, r: usize) -> usize {
    sum(&[
        SYNC,
        2 * OSC,
        2 * TAIL,
        2 * TITLE,
        TITLE_DEPTH * TITLE,
        2 * TITLE_DEPTH * size_of::<Option<String>>(),
        times(2, (2 * w).max(8)),
        times(2 * r, size_of::<LineDamageBounds>()),
        Config::default().semantic_escape_chars.len(),
    ])
}
fn retained(e: ScreenEnvelope) -> usize {
    let slots = e.charge().unwrap();
    sum(&[
        backing(slots),
        times(slots.cells + 4, extra()),
        ancillary(e.max_cols as usize, e.max_rows as usize),
    ])
}
// Finite parser/handler scratch; sum alternatives rather than assuming overlap.
fn feed_scratch() -> usize {
    sum(&[
        2 * OSC,                           // classification's independent raw OSC Vec
        2 * (10 * OSC + 3 * 16),           // unhandled OSC: escaped byte <=10, brackets <=3/param
        2 * 16 * size_of::<&str>(),        // title's filtered param collector
        2 * OSC,                           // joined title and trimmed owned copy
        2 * OSC + OSC,                     // reconstructed URI and explicit id
        2 * 4096 + 20,                     // adapter copies and generated id realloc
        2 * TITLE, // bounded title input/event; current/stack already retained
        OSC,       // decoded clipboard bytes (String takes same Vec)
        2 * OSC * size_of::<&str>(), // xparse_color split('/') collector
        arc::<[String; 2]>() + 2 + 2 * 16, // ColorRequest closure/prefix/terminator
        2 * 64,    // fixed CSI replies: <=64 output bytes, geometric String backing
        extra(),   // Arc::make_mut old/new extra coexistence
    ])
}
fn resize_peak(e: ScreenEnvelope, scratch: BackingSlots) -> usize {
    sum(&[
        retained(e),
        backing(scratch),
        times(scratch.cells + 4, extra()),
        feed_scratch(),
        ancillary(e.max_cols as usize, e.max_rows as usize),
    ])
}
fn replay_len(c: usize, r: usize, tail: usize) -> Option<usize> {
    if !(2..=512).contains(&c) || !(1..=256).contains(&r) || tail > TAIL {
        return None;
    }
    // Two paints: row*(142*c+555), two fix_tabs: row*11*c;
    // top-level table totals 6956 plus 12 per tab stop (see resource doc).
    153usize
        .checked_mul(c)?
        .checked_add(555)?
        .checked_mul(r)?
        .checked_mul(2)?
        .checked_add(12usize.checked_mul(c)?)?
        .checked_add(6956)?
        .checked_add(tail)
}
fn replay_peak(e: ScreenEnvelope, size: TerminalSize) -> usize {
    let b = replay_len(size.cols() as usize, size.rows() as usize, TAIL).unwrap();
    sum(&[
        retained(e),
        backing(e.charge().unwrap()),
        4 * b,
        b + 5,
        2 * 74,
        2 * 12,
        extra(),
        feed_scratch(), // replay first flushes any synchronized update
    ])
}
// Structural mirror of private replay::CellState; same Rust field types.
#[allow(dead_code)]
struct SnapshotCell {
    c: char,
    fg: Color,
    bg: Color,
    flags: u16,
    zerowidth: Vec<char>,
    underline: Option<Color>,
}
fn snapshot_bytes(size: TerminalSize) -> usize {
    sum(&[
        times(
            2 * size.cells(),
            size_of::<SnapshotCell>() + 16 * size_of::<char>(),
        ),
        times(2 * size.rows() as usize, size_of::<Vec<SnapshotCell>>()),
        3 * 16 * size_of::<char>(),
        size.cols() as usize,
        259 * size_of::<Option<(u8, u8, u8)>>(),
    ])
}
fn frame_bytes(size: TerminalSize) -> usize {
    sum(&[
        times(size.cells(), size_of::<terminal::Cell>()),
        arc::<Palette>(),
    ])
}
fn model(size: TerminalSize) -> TerminalCore {
    TerminalCore::with_options(
        size,
        TerminalOptions {
            history_lines: 0,
            replay: true,
        },
    )
}
fn size(c: u16, r: u16) -> TerminalSize {
    TerminalSize::new(c, r).unwrap()
}

#[test]
fn requested_storage() {
    const CHILD: &str = "QSH_ALLOCATION_OBSERVER_CHILD";
    if std::env::var_os(CHILD).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "screen_budget::allocation_bounds::requested_storage",
                "--test-threads=1",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env_remove("QSHD_TEST_OFFSET_ALLOCATIONS")
            .output()
            .unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr);
        eprint!("{stderr}");
        assert!(
            output.status.success(),
            "isolated allocation observer failed"
        );
        assert!(
            stderr
                .lines()
                .any(|line| line == "allocation observer completed"),
            "exact-filter child did not execute the observer"
        );
        return;
    }
    assert!(
        std::env::var_os("QSHD_TEST_OFFSET_ALLOCATIONS").is_none(),
        "qualification must use ordinary System backing"
    );
    #[cfg(feature = "system")]
    assert!(!crate::test_allocator::offset_allocations());
    // Direct allocator calls cannot be optimized away like an unused Box.
    let (_, s) = observe(|| unsafe {
        let layout = Layout::from_size_align(31, 8).unwrap();
        let p = ALLOCATOR.alloc_zeroed(layout);
        assert!(!p.is_null());
        let p = ALLOCATOR.realloc(p, layout, 101);
        assert!(!p.is_null());
        // Safely inject only the accounting result of failure, never ask for OOM.
        account(101, 999, false);
        let p = ALLOCATOR.realloc(p, Layout::from_size_align(101, 8).unwrap(), 13);
        assert!(!p.is_null());
        ALLOCATOR.dealloc(p, Layout::from_size_align(13, 8).unwrap());
    });
    assert_eq!((s.live, s.peak), (0, 101));
    assert!(
        !within(s, 0, 100),
        "negative control must reject a low peak bound"
    );
    let max = replay_len(512, 256, TAIL).unwrap();
    assert_eq!(max, 41_457_964);
    assert_eq!(replay_len(1, 1, 0), None);
    assert_eq!(replay_len(512, 257, 0), None);
    assert_eq!(replay_len(2, 1, usize::MAX), None);
    let max_e = ScreenEnvelope {
        max_cols: 512,
        max_rows: 256,
        grew_rows: true,
    };
    // Arithmetic only: never instantiate this worst-case payload fixture.
    eprintln!(
        "layouts Cell={} Row={} CellExtra={} extra={} maximum retained={} global model-sum={}",
        size_of::<Cell>(),
        size_of::<Row<Cell>>(),
        size_of::<CellExtra>(),
        extra(),
        retained(max_e),
        times(64, retained(max_e))
    );

    // Fixtures are caller-owned, built before metering, never dropped in a phase.
    let dense = "ab界".repeat(4096);
    let styled = format!(
        "\x1b[1;2;3;4:5;7;8;9;38;2;255;255;255;48;2;255;255;255;58;2;255;255;255m界{}",
        "\u{301}".repeat(17)
    );
    let title = format!("\x1b]2;{}\x07", "t".repeat(TITLE));
    let link = format!("\x1b]8;id=x;{}\x07x", "u".repeat(4095));
    let no_id_link = format!("\x1b]8;;{}\x07x", "u".repeat(4077));
    let pending = format!("\x1bP{}", "p".repeat(TAIL + 4096));
    let osc = format!("\x1b]999;{}\x07", "z".repeat(OSC + 1));
    let sync = format!("\x1b[?2026h{}\x1b[?2026l", "a".repeat(SYNC + 4096));
    let palette: String = (0..256)
        .map(|i| format!("\x1b]4;{i};rgb:ff/ee/dd\x07"))
        .collect();
    let mut current = size(80, 24);
    let mut envelope = ScreenEnvelope::new(current);
    let (mut t, s) = observe(|| model(current));
    check(
        "construct",
        s,
        retained(envelope),
        retained(envelope) + feed_scratch(),
    );
    for (label, input) in [
        ("output", dense.as_bytes()),
        ("style/combining", styled.as_bytes()),
        ("palette/tabs", palette.as_bytes()),
        ("tabs", b"\t\x1bH\t\x1b7".as_slice()),
    ] {
        let (_, s) = observe(|| t.feed(input));
        check(
            label,
            s,
            retained(envelope),
            retained(envelope) + feed_scratch(),
        );
    }
    assert_eq!(t.history_size(), 0);
    for next in [
        size(80, 25),
        size(80, 24),
        size(512, 24),
        size(2, 24),
        size(8, 2),
        size(4, 3),
    ] {
        let (new_e, scratch) = envelope.prepare_charge(current, next).unwrap();
        let (_, s) = observe(|| t.resize_to(next));
        check("resize", s, retained(new_e), resize_peak(new_e, scratch));
        envelope = new_e;
        current = next;
        let (_, s) = observe(|| t.feed(dense.as_bytes()));
        check(
            "dense after resize",
            s,
            retained(envelope),
            retained(envelope) + feed_scratch(),
        );
    }
    let (_, s) = observe(|| drop(t));
    assert_eq!(s.live, 0);
    current = size(4, 3);
    envelope = ScreenEnvelope::new(current);
    let (mut t, s) = observe(|| model(current));
    check(
        "tiny payload model",
        s,
        retained(envelope),
        retained(envelope) + feed_scratch(),
    );
    for (label, input) in [
        ("alternate", b"\x1b[?1049h".as_slice()),
        ("wide", dense.as_bytes()),
        ("payload", styled.as_bytes()),
        ("palette", palette.as_bytes()),
        ("saved cursor", b"\x1b[1;3H\x1b7\x1b[3;1H".as_slice()),
        ("explicit links", link.as_bytes()),
        ("generated links", no_id_link.as_bytes()),
        ("title", title.as_bytes()),
        ("OSC overflow", osc.as_bytes()),
        ("pending boundary", pending.as_bytes()),
        ("sync overflow", sync.as_bytes()),
    ] {
        let (_, s) = observe(|| t.feed(input));
        check(
            label,
            s,
            retained(envelope),
            retained(envelope) + feed_scratch(),
        );
    }
    let (_, s) = observe(|| {
        for _ in 0..current.cells() {
            t.feed(link.as_bytes());
        }
        t.feed(styled.as_bytes());
        t.feed(palette.as_bytes());
        t.feed(b"\x1b[1;3H\x1b7\x1b[3;1H");
    });
    check(
        "distinct links and styled replay state",
        s,
        retained(envelope),
        retained(envelope) + feed_scratch(),
    );
    let (_, s) = observe(|| {
        for _ in 0..TITLE_DEPTH + 1 {
            t.feed(b"\x1b[22;0t");
        }
    });
    check(
        "title stack",
        s,
        retained(envelope),
        retained(envelope) + feed_scratch(),
    );
    // Exercise both pictures, saved-cursor sharing, a retained near-limit tail,
    // and replay's synchronized-update flush rather than only explicit sync end.
    for (label, input) in [
        ("primary replay", b"\x1b[?1049l\x1b[1;1H\x1b7".as_slice()),
        ("alternate replay", b"\x1b[?1049h".as_slice()),
        ("pending tail replay", &pending.as_bytes()[..1 << 20]),
        ("sync flush replay", &sync.as_bytes()[..4096]),
    ] {
        let (_, s) = observe(|| t.feed(input));
        check(
            label,
            s,
            retained(envelope),
            retained(envelope) + feed_scratch(),
        );
        let ((len, capacity), s) = observe(|| {
            let output = t.replay().unwrap();
            (output.len(), output.capacity())
        });
        let b = replay_len(current.cols() as usize, current.rows() as usize, TAIL).unwrap();
        assert!(len <= b && capacity <= 2 * b);
        check(label, s, retained(envelope), replay_peak(envelope, current));
    }
    let (replay, s) = observe(|| t.replay().unwrap());
    let b = replay_len(current.cols() as usize, current.rows() as usize, TAIL).unwrap();
    assert!(replay.len() <= b && replay.capacity() <= 2 * b);
    check(
        "replay",
        s,
        retained(envelope) + 2 * b,
        replay_peak(envelope, current),
    );
    let (record, s) = observe(|| {
        transport::shell_frame::encode_record(transport::shell_frame::REC_DATA, &replay)
    });
    assert_eq!(record.capacity(), replay.len() + 5);
    check(
        "record coexistence",
        s,
        retained(envelope) + 3 * b + 5,
        replay_peak(envelope, current),
    );
    observe(|| {
        drop(record);
        drop(replay);
    });
    let (snapshot, s) = observe(|| t.snapshot().unwrap());
    check(
        "snapshot",
        s,
        retained(envelope) + snapshot_bytes(current),
        retained(envelope)
            + snapshot_bytes(current)
            + backing(envelope.charge().unwrap())
            + extra(),
    );
    observe(|| drop(snapshot));
    let (frame, s) = observe(|| black_box(t.frame()));
    check(
        "frame",
        s,
        retained(envelope) + frame_bytes(current),
        retained(envelope) + frame_bytes(current),
    );
    observe(|| drop(frame));
    let (_, s) = observe(|| drop(t));
    assert_eq!(s.live, 0, "all model allocations must be released");

    let e = ScreenEnvelope::new(size(80, 24));
    let (models, s) = observe(|| std::array::from_fn::<_, 8, _>(|_| model(size(80, 24))));
    check(
        "eight ordinary models",
        s,
        times(8, retained(e)),
        times(8, retained(e)) + feed_scratch(),
    );
    let (_, s) = observe(|| drop(models));
    assert_eq!(s.live, 0);
    eprintln!("allocation observer completed");
}
