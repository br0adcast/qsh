//! Deterministic presentation storage costs; no timing or process-wide counts.
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell as LocalCell;
use terminal::{Cell, Frame};
use terminal_size::ViewportSize;

struct CountingAllocator;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Allocations {
    calls: usize,
    bytes: usize,
}
thread_local! {
    static MEASURED: LocalCell<Option<Allocations>> = const { LocalCell::new(None) };
    static GRID_SIZES: LocalCell<(usize, usize)> = const { LocalCell::new((0, 0)) };
    static GRID_CALLS: LocalCell<usize> = const { LocalCell::new(0) };
    static LARGEST: LocalCell<usize> = const { LocalCell::new(0) };
}
fn note(bytes: usize) {
    let _ = MEASURED.try_with(|slot| {
        if let Some(mut count) = slot.get() {
            let sizes = GRID_SIZES.get();
            if bytes == sizes.0 || bytes == sizes.1 {
                GRID_CALLS.set(GRID_CALLS.get() + 1);
            }
            count.calls += 1;
            count.bytes += bytes;
            slot.set(Some(count));
            LARGEST.set(LARGEST.get().max(bytes));
        }
    });
}
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            note(layout.size());
        }
        pointer
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            note(layout.size());
        }
        pointer
    }
    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let pointer = unsafe { System.realloc(pointer, layout, size) };
        if !pointer.is_null() {
            note(size);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;
fn measured<T>(operation: impl FnOnce() -> T) -> (T, Allocations) {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            MEASURED.set(None);
            GRID_SIZES.set((0, 0));
        }
    }
    assert!(MEASURED.get().is_none());
    MEASURED.set(Some(Allocations::default()));
    let reset = Reset;
    let output = operation();
    let count = MEASURED.get().unwrap();
    drop(reset);
    (output, count)
}

#[test]
fn padded_projection_uses_only_the_final_cell_buffer() {
    let source = Frame::blank(80, 24);
    for size in [
        ViewportSize::new(80, 24),
        ViewportSize::new(90, 30),
        ViewportSize::new(17, 30),
    ] {
        let (output, cost) = measured(|| qsh::viewport::project_padded(&source, size));
        assert_eq!(
            cost,
            Allocations {
                calls: 1,
                bytes: output.cells.len() * size_of::<Cell>()
            }
        );
    }
}

#[test]
fn cropped_projection_allocates_only_output_cell_storage() {
    let source = Frame::blank(80, 24);
    let (output, cost) = measured(|| qsh::viewport::project(&source, ViewportSize::new(17, 5)));
    assert_eq!(
        cost,
        Allocations {
            calls: 1,
            bytes: output.cells.len() * size_of::<Cell>()
        }
    );
    let (empty, cost) =
        measured(|| qsh::viewport::project_padded(&source, ViewportSize::new(0, 0)));
    assert!(empty.cells.is_empty());
    assert_eq!(cost, Allocations::default());
}

#[test]
fn the_measurement_gate_detects_a_deliberate_extra_full_frame_allocation() {
    let source = Frame::blank(40, 10);
    let size = ViewportSize::new(40, 10);
    let (_, normal) = measured(|| qsh::viewport::project_padded(&source, size));
    let (_, extra) = measured(|| {
        let output = qsh::viewport::project_padded(&source, size);
        let copy = std::hint::black_box(output.cells.clone());
        std::hint::black_box((&output, &copy));
        (output, copy)
    });
    assert_eq!(extra.calls, normal.calls + 1);
    assert_eq!(
        extra.bytes,
        normal.bytes + source.cells.len() * size_of::<Cell>()
    );
}

#[test]
fn owned_composition_and_box_paint_keep_the_existing_cell_buffer() {
    for boxed in [
        None,
        Some(qsh::window::Boxed {
            top: 1,
            left: 2,
            lines: vec![vec![Cell::blank(); 3]],
        }),
    ] {
        let source = Frame::blank(80, 24);
        let expected = qsh::overlay::compose(&source, None, None, boxed.as_ref());
        let pointer = source.cells.as_ptr();
        let capacity = source.cells.capacity();
        let (output, cost) =
            measured(|| qsh::overlay::compose_owned(source, None, None, boxed.as_ref()));
        assert_eq!(output, expected);
        assert_eq!(
            (output.cells.as_ptr(), output.cells.capacity()),
            (pointer, capacity)
        );
        assert_eq!(cost, Allocations::default());
    }
}

#[test]
fn owned_plate_preserves_storage_while_retaining_borrowed_compatibility() {
    let source = Frame::blank(80, 24);
    let expected = qsh::status::overlay(&source, "界e\u{301} reconnecting");
    let pointer = source.cells.as_ptr();
    let (output, cost) = measured(|| qsh::status::overlay_owned(source, "界e\u{301} reconnecting"));
    assert_eq!(output, expected);
    assert_eq!(output.cells.as_ptr(), pointer);
    assert!(
        cost.bytes < output.cells.len() * size_of::<Cell>(),
        "plate text may allocate; the full grid must not: {cost:?}"
    );
}

#[test]
fn owned_inactive_prediction_transfers_storage_without_allocation() {
    let mut engine = prediction::PredictionEngine::new(prediction::DisplayPreference::Never);
    let source = Frame::blank(80, 24);
    let saved = source.clone();
    let pointer = source.cells.as_ptr();
    let (output, cost) = measured(|| engine.apply_owned(source));
    assert_eq!(output, saved);
    assert_eq!(output.cells.as_ptr(), pointer);
    assert_eq!(cost, Allocations::default());
}

#[test]
fn history_repaint_has_no_transient_retained_frame_copy() {
    use qsh::session::{Chrome, Session, UiEvent};
    let mut session = Session::new(
        40,
        6,
        render::TermCaps::truecolor(),
        qsh::args::PredictMode::Never,
        Chrome {
            prefix: qsh::escape::DEFAULT_PREFIX,
            line: true,
            glyphs: qsh::window::Glyphs {
                utf8: true,
                colour: true,
            },
        },
    );
    session.handle(UiEvent::Link(transport::LinkState::Live), 0);
    session.on_channel_ready(16, 0);
    let text: String = (1..=40).map(|n| format!("line{n:03}\r\n")).collect();
    session.handle(
        UiEvent::Stream0(transport::shell_frame::encode_record(
            transport::shell_frame::REC_DATA,
            text.as_bytes(),
        )),
        1,
    );
    let input = qsh::input_ingress::IngressBudget::default()
        .admit_slice(b"\x1d[")
        .unwrap();
    session.handle(UiEvent::Stdin(input), 2);
    session.handle(UiEvent::Link(transport::LinkState::PathDown), 3);
    GRID_CALLS.set(0);
    GRID_SIZES.set((40 * 5 * size_of::<Cell>(), 40 * 6 * size_of::<Cell>()));
    let (actions, _) = measured(|| session.handle(UiEvent::Tick, 1003));
    assert!(actions
        .iter()
        .all(|action| !matches!(action, qsh::session::Action::Write(_))));
    // The idle tick has no due work and deliberately constructs no frames.
    assert_eq!(GRID_CALLS.get(), 0);

    // Real live output still requires presentation against the pinned history
    // frame. No newline means history size and its status label stay unchanged.
    let output = transport::shell_frame::encode_record(transport::shell_frame::REC_DATA, b"X");
    GRID_CALLS.set(0);
    GRID_SIZES.set((40 * 5 * size_of::<Cell>(), 40 * 6 * size_of::<Cell>()));
    let (actions, cost) = measured(|| session.handle(UiEvent::Stream0(output), 1004));
    assert!(actions
        .iter()
        .all(|action| !matches!(action, qsh::session::Action::Write(_))));
    // The authoritative snapshot, the padded projection of the pinned view
    // and the status-row insertion all reuse storage of earlier frames, and
    // the unchanged view does not reach Renderer retention.
    assert_eq!(GRID_CALLS.get(), 0);
    assert!(cost.bytes < 40 * 5 * size_of::<Cell>(), "{cost:?}");
    session.handle(
        UiEvent::Stats(transport::Stats {
            silent_secs: 4,
            ..Default::default()
        }),
        1004,
    );
    GRID_CALLS.set(0);
    GRID_SIZES.set((40 * 5 * size_of::<Cell>(), 40 * 6 * size_of::<Cell>()));
    let (actions, cost) = measured(|| session.handle(UiEvent::Tick, 2004));
    assert!(actions
        .iter()
        .any(|action| matches!(action, qsh::session::Action::Write(bytes) if !bytes.is_empty())));
    // A dirty presentation also updates Renderer's retained frame, in place.
    assert_eq!(GRID_CALLS.get(), 0);
    assert!(cost.bytes < 40 * 5 * size_of::<Cell>(), "{cost:?}");
}

#[test]
fn owned_presentation_matches_explicit_complete_frames_and_rendered_bytes() {
    for color in [
        render::ColorDepth::Truecolor,
        render::ColorDepth::Indexed256,
        render::ColorDepth::Basic16,
        render::ColorDepth::Mono,
    ] {
        let caps = render::TermCaps { color };
        let mut actual_renderer = render::Renderer::new(caps);
        let mut expected_renderer = render::Renderer::new(caps);
        let mut displayed = terminal::TerminalCore::new(8, 4);
        let mut terminal = terminal::TerminalCore::new(6, 2);
        terminal.feed(b"\x1b[?1h\x1b=\x1b[?1002h\x1b[?1006h\x1b[?2004h\x1b[31m");
        terminal.feed("e\u{301}界\u{302}\x1b[8m🦀\u{304}\x1b[0m".as_bytes());
        let line = vec![
            Cell {
                ch: '>',
                flags: terminal::FLAG_REVERSE,
                ..Cell::blank()
            };
            8
        ];
        let mut prediction =
            prediction::PredictionEngine::new(prediction::DisplayPreference::Never);
        for step in 0..3 {
            if step == 1 {
                terminal.feed(b"\x1b[H\x1b[32mX\x1b[0m");
            }
            if step == 2 {
                actual_renderer.invalidate();
                expected_renderer.invalidate();
            }
            let mut source = terminal.frame();
            std::sync::Arc::make_mut(&mut source.palette).entries[1] = 0x123456;
            let saved = source.clone();
            let mut expected = source.clone();
            expected.cols = 8;
            expected.rows = 3;
            expected.cells = vec![Cell::blank(); 24];
            expected.cells[..6].copy_from_slice(&source.cells[..6]);
            expected.cells[8..14].copy_from_slice(&source.cells[6..12]);
            let chrome = (step > 0).then_some(line.as_slice());
            if chrome.is_some() {
                expected.cells.splice(..0, line.iter().copied());
                expected.rows += 1;
                expected.cursor_row += 1;
            }
            let snapshot = prediction.apply_owned(source.clone());
            let projected = qsh::viewport::project_padded(&snapshot, ViewportSize::new(8, 3));
            let actual = qsh::overlay::compose_owned(projected, chrome, None, None);
            assert_eq!(actual, expected);
            let bytes = actual_renderer.render(&actual);
            assert_eq!(bytes, expected_renderer.render(&expected));
            // Concealment is SGR8, not removal of underlying character bytes.
            displayed.feed(&bytes);
            let shown = displayed.frame();
            let hidden = shown.cell(u16::from(chrome.is_some()), 3);
            assert_ne!(hidden.flags & terminal::FLAG_HIDDEN, 0);
            assert_eq!(hidden.ch, '🦀');
            assert_eq!(hidden.combining, source.cell(0, 3).combining);
            assert_eq!(source, saved);
        }
    }
}

/// After a warm-up, a presented step reuses the storage of earlier frames:
/// no allocation in a step is as large as one grid, whether the primary screen
/// scrolls under the status line, a full-screen application redraws
/// combining-heavy content on the alternate screen, the history view pages,
/// or the status line is off.
#[test]
fn steady_presentation_allocates_no_grid() {
    use qsh::session::{Action, Chrome, Session, UiEvent};
    let data = |bytes: &[u8]| {
        UiEvent::Stream0(transport::shell_frame::encode_record(
            transport::shell_frame::REC_DATA,
            bytes,
        ))
    };
    let keys = |bytes: &[u8]| {
        UiEvent::Stdin(
            qsh::input_ingress::IngressBudget::default()
                .admit_slice(bytes)
                .unwrap(),
        )
    };
    let redraw = |n: usize| {
        let mut text = String::from("\x1b[H");
        for row in 0..11 {
            text.push_str(&format!("\x1b[{};1H\x1b[3{}m", row + 1, (row + n) % 8));
            for col in 0..40 {
                text.push(char::from(b'a' + ((row + col + n) % 26) as u8));
                text.push_str("\u{301}\u{302}");
            }
        }
        text
    };
    for (name, line, prepare, step) in [
        (
            "primary scroll",
            true,
            Vec::new(),
            Box::new(move |n: usize| vec![data(format!("line {n} 界\r\n").as_bytes())])
                as Box<dyn Fn(usize) -> Vec<UiEvent>>,
        ),
        (
            "alternate combining",
            true,
            vec![data(b"\x1b[?1049h")],
            Box::new(move |n| vec![data(redraw(n).as_bytes())]),
        ),
        (
            "history paging",
            true,
            vec![
                data(
                    (0..200)
                        .map(|n| format!("old {n}\r\n"))
                        .collect::<String>()
                        .as_bytes(),
                ),
                keys(b"\x1d["),
            ],
            Box::new(move |n| {
                vec![keys(if n.is_multiple_of(2) {
                    b"\x1b[5~"
                } else {
                    b"\x1b[6~"
                })]
            }),
        ),
        (
            "no status line",
            false,
            Vec::new(),
            Box::new(move |n| vec![data(format!("line {n}\r\n").as_bytes())]),
        ),
    ] {
        let mut session = Session::new(
            40,
            12,
            render::TermCaps::truecolor(),
            qsh::args::PredictMode::Never,
            Chrome {
                prefix: qsh::escape::DEFAULT_PREFIX,
                line,
                glyphs: qsh::window::Glyphs {
                    utf8: true,
                    colour: true,
                },
            },
        );
        session.handle(UiEvent::Link(transport::LinkState::Live), 0);
        session.on_channel_ready(16, 0);
        let mut now = 1;
        for event in prepare {
            session.handle(event, now);
            now += 1;
        }
        let grid = 40 * 11 * size_of::<Cell>();
        for n in 0..24 {
            for event in step(n) {
                now += 1;
                LARGEST.set(0);
                let ((immediate, due), cost) = measured(|| {
                    let immediate = session.handle(event, now);
                    // Include staged storage and the actual projection/render
                    // at its fixed deadline in the same allocation boundary.
                    let due = if let Some(deadline) = session.ui_deadlines().presentation_ms {
                        now = deadline;
                        session.handle(UiEvent::Tick, now)
                    } else {
                        Vec::new()
                    };
                    (immediate, due)
                });
                assert!(
                    immediate
                        .iter()
                        .chain(due.iter())
                        .any(|action| matches!(action, Action::Write(bytes) if !bytes.is_empty())),
                    "{name} step {n} presented nothing"
                );
                // The emulator's own per-cell storage for combining marks is
                // many small allocations; only a grid-sized one is a frame.
                if n >= 4 {
                    assert!(LARGEST.get() < grid, "{name} step {n}: {cost:?}");
                }
            }
        }
    }
}
