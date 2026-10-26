//! Reused frame storage: `frame_into` and `Frame::clone_from` must give
//! exactly what a fresh frame or copy gives, whatever the reused frame held,
//! and must never make two frames share cells.

use super::*;

/// A frame holding something different in every field: another size, cells
/// with a full combining suffix, every flag and direct colors, every mode
/// on, the cursor elsewhere, and a palette of its own shared with a copy.
fn poisoned(cols: u16, rows: u16) -> (Frame, Arc<Palette>) {
    let mut frame = Frame::blank(cols, rows);
    for cell in &mut frame.cells {
        *cell = Cell {
            ch: 'Z',
            combining: CombiningMarks::from_slice(&['\u{301}'; MAX_COMBINING_MARKS]),
            fg: Color::Rgb(0x010203),
            bg: Color::Rgb(0x040506),
            flags: u16::MAX,
        };
    }
    frame.cursor_col = cols.saturating_sub(1);
    frame.cursor_row = rows.saturating_sub(1);
    frame.cursor_visible = false;
    frame.app_cursor = true;
    frame.app_keypad = true;
    frame.origin_mode = true;
    frame.mouse_tracking = MouseTracking::Motion;
    frame.mouse_sgr = true;
    frame.bracketed_paste = true;
    frame.alt_screen = true;
    let palette = Arc::make_mut(&mut frame.palette);
    palette.entries[7] = 0xabcdef;
    palette.default_bg = 0x123456;
    let shared = Arc::clone(&frame.palette);
    (frame, shared)
}

/// The terminal states a reused frame must reproduce: content with
/// combining marks and wide characters, scrolled into history, the
/// alternate screen with input modes, a changed palette, and resizes to a
/// smaller and a larger grid.
fn states() -> Vec<(&'static str, TerminalCore)> {
    let mut states = Vec::new();
    let mut t = TerminalCore::new(12, 4);
    t.feed("e\u{301}\u{302}\u{303} 界 😀\u{fe0f}\r\n".as_bytes());
    t.feed(format!("a{}", "\u{301}".repeat(MAX_COMBINING_MARKS)).as_bytes());
    states.push(("combining and wide", t));

    let mut t = TerminalCore::new(10, 3);
    for n in 0..20 {
        t.feed(format!("line {n}\r\n").as_bytes());
    }
    t.scroll(5);
    assert!(t.display_offset() > 0);
    states.push(("scrolled into history", t));

    let mut t = TerminalCore::new(10, 3);
    t.feed(b"primary\x1b[?1049h\x1b[?1h\x1b=\x1b[?1002h\x1b[?1006h\x1b[?2004h\x1b[?25l");
    t.feed(b"\x1b[2;3H\x1b[31;44;1;4;7mapp");
    states.push(("alternate screen with modes", t));

    let mut t = TerminalCore::new(10, 3);
    t.feed(b"\x1b]4;1;rgb:12/34/56\x07\x1b]10;rgb:aa/bb/cc\x07\x1b[31mred");
    states.push(("changed palette", t));

    let mut t = TerminalCore::new(40, 10);
    t.feed("wide 界界 text e\u{301}".as_bytes());
    t.resize(7, 2);
    states.push(("resized smaller", t));

    let mut t = TerminalCore::new(7, 2);
    t.feed("e\u{301}\u{302}x".as_bytes());
    t.resize(60, 20);
    states.push(("resized larger", t));
    states
}

#[test]
fn frame_into_replaces_everything_a_reused_frame_held() {
    for (name, t) in states() {
        let expected = t.frame();
        for (cols, rows) in [(1, 1), (5, 2), (12, 4), (80, 24)] {
            let (mut reused, shared) = poisoned(cols, rows);
            let saved = (*shared).clone();
            t.frame_into(&mut reused);
            assert_eq!(reused, expected, "{name} into a {cols}x{rows} frame");
            assert_eq!(reused.cells.len(), expected.cells.len());
            // The palette another frame shares is never written through.
            assert_eq!(*shared, saved, "{name}");
        }
    }
}

#[test]
fn frame_into_reuses_storage_and_an_unchanged_palette() {
    let mut t = TerminalCore::new(20, 5);
    t.feed(b"first");
    let mut frame = t.frame();
    let (pointer, palette) = (frame.cells.as_ptr(), Arc::clone(&frame.palette));
    t.feed("\r\nsecond e\u{301}".as_bytes());
    t.frame_into(&mut frame);
    assert_eq!(frame, t.frame());
    assert_eq!(frame.cells.as_ptr(), pointer);
    assert!(Arc::ptr_eq(&frame.palette, &palette));

    // A palette change replaces the shared snapshot rather than writing
    // into it: the copy taken before keeps the old colors.
    let before = (*palette).clone();
    t.feed(b"\x1b]4;2;rgb:01/02/03\x07");
    t.frame_into(&mut frame);
    assert_eq!(frame, t.frame());
    assert_eq!(*palette, before);
    assert!(!Arc::ptr_eq(&frame.palette, &palette));

    // With nothing else holding it, a changed palette is written in place.
    drop(palette);
    let owned = Arc::as_ptr(&frame.palette);
    t.feed(b"\x1b]4;3;rgb:04/05/06\x07");
    t.frame_into(&mut frame);
    assert_eq!(frame, t.frame());
    assert_eq!(Arc::as_ptr(&frame.palette), owned);
}

#[test]
fn reused_frames_stay_independent_of_the_model_and_each_other() {
    let mut t = TerminalCore::new(10, 3);
    t.feed("one e\u{301}".as_bytes());
    let first = t.frame();
    let kept = first.clone();
    let mut second = first.clone();
    t.feed("\r\ntwo 界\x1b[?1049h".as_bytes());
    t.frame_into(&mut second);
    assert_eq!(first, kept);
    assert_ne!(second, first);
    assert_ne!(first.cells.as_ptr(), second.cells.as_ptr());

    let mut copy = Frame::blank(10, 3);
    copy.clone_from(&second);
    assert_eq!(copy, second);
    second.cells[0].ch = 'X';
    second.cells[1].combining = CombiningMarks::from_slice(&['\u{302}']);
    assert_ne!(copy.cells[0].ch, 'X');
    assert!(copy.cells[1].combining.is_empty());
}

#[test]
fn clone_from_matches_clone_and_bounds_retained_storage() {
    let mut t = TerminalCore::new(30, 6);
    t.feed("text 界 e\u{301}\x1b[?2004h".as_bytes());
    let source = t.frame();
    for (cols, rows) in [(1, 1), (30, 6), (31, 6), (60, 6)] {
        let (mut target, _) = poisoned(cols, rows);
        let pointer = target.cells.as_ptr();
        let capacity = target.cells.capacity();
        target.clone_from(&source);
        assert_eq!(target, source.clone());
        let needed = source.cells.len();
        if capacity >= needed && capacity <= 2 * needed {
            assert_eq!(target.cells.as_ptr(), pointer, "{cols}x{rows} kept");
        }
        assert!(target.cells.capacity() <= 2 * needed, "{cols}x{rows}");
    }

    // Storage left over from a much larger screen is not held on to.
    let (mut target, _) = poisoned(512, 256);
    target.clone_from(&source);
    assert_eq!(target, source);
    assert!(target.cells.capacity() <= 2 * source.cells.len());
    let mut reused = poisoned(512, 256).0;
    t.frame_into(&mut reused);
    assert_eq!(reused, source);
    assert!(reused.cells.capacity() <= 2 * source.cells.len());
}

#[test]
fn fit_cells_keeps_storage_up_to_twice_the_need() {
    let mut cells = vec![Cell::blank(); 100];
    let pointer = cells.as_ptr();
    fit_cells(&mut cells, 50);
    assert!(cells.is_empty());
    assert_eq!(cells.as_ptr(), pointer);
    fit_cells(&mut cells, 49);
    assert!(cells.capacity() < 100);
    fit_cells(&mut cells, 0);
    assert_eq!(cells.capacity(), 0);
}
