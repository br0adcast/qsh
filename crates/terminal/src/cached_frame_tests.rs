use super::*;

#[test]
fn cached_frames_equal_full_and_remain_independent() {
    let mut core = TerminalCore::new(24, 8);
    for input in ["initial", "\x1b[2;2He\u{301}界", "\x1b[3;2Hchanged"] {
        core.feed(input.as_bytes());
        let expected = core.frame();
        let mut actual = core.frame_cached();
        assert_eq!(actual, expected);
        actual.cells.fill(Cell::blank());
        Arc::make_mut(&mut actual.palette).default_bg = 0xabcdef;
        let mut reused = Frame::blank(2, 1);
        core.frame_into_cached(&mut reused);
        assert_eq!(reused, core.frame());
    }
}

#[test]
fn large_geometry_uses_full_without_retaining_cells() {
    let mut core = TerminalCore::new(512, 256);
    for input in [b"full".as_slice(), b"\x1b[2;2Hx"] {
        core.feed(input);
        assert_eq!(core.frame_cached(), core.frame());
    }
}

fn check(core: &mut TerminalCore, out: &mut Frame) {
    let expected = core.frame();
    core.frame_into_cached(out);
    assert_eq!(*out, expected);
    out.cells.fill(Cell::blank());
    out.cursor_col = u16::MAX;
    Arc::make_mut(&mut out.palette).default_fg = 0xabcdef;
    if let Some(cache) = &core.frame_cache {
        assert!(
            cache.frame.cells.capacity() * std::mem::size_of::<Cell>()
                <= frame_cache::MAX_CELL_BYTES
        );
    }
}

fn prime(core: &mut TerminalCore, out: &mut Frame) {
    check(core, out);
    core.feed(b"\x1b[2;2Ha");
    check(core, out);
    core.feed(b"\x1b[3;2Hb");
    check(core, out);
    assert!(core.cache_counts.partial > 0);
}

#[test]
fn cached_cap_geometry_capacity_and_immediate_shrink_release() {
    let size = std::mem::size_of::<Cell>();
    let rows = (frame_cache::MAX_CELL_BYTES / size / 200) as u16;
    assert!((2..256).contains(&rows));
    let mut core = TerminalCore::new(200, rows);
    let mut out = Frame::blank(2, 1);
    prime(&mut core, &mut out);
    core.frame_cache
        .as_mut()
        .unwrap()
        .frame
        .cells
        .reserve(frame_cache::MAX_CELL_BYTES / size);
    core.feed(b"\x1b[2;2Hc");
    check(&mut core, &mut out);
    core.resize(80, 24);
    assert!(core.frame_cache.is_none());
    let _ = core.frame();
    assert!(core.frame_cache.is_none());
    prime(&mut core, &mut out);
    assert!(core.frame_cache.as_ref().unwrap().frame.cells.capacity() <= 80 * 24);
    core.resize(512, 256);
    assert!(core.frame_cache.is_none());
    check(&mut core, &mut out);
    assert!(core.frame_cache.is_none());
    core.resize(200, rows + 1);
    core.feed(b"\x1b[2;2Hx");
    check(&mut core, &mut out);
    assert!(core.frame_cache.is_none());
    core.resize(200, rows);
    prime(&mut core, &mut out);
}

#[test]
fn oversized_cached_read_does_not_consume_damage() {
    use alacritty_terminal::term::TermDamage;
    let mut core = TerminalCore::new(512, 256);
    core.term.reset_damage();
    core.feed(b"\x1b[2;2Hx\x1b[1;1H");
    assert_eq!(core.frame_cached(), core.frame());
    let TermDamage::Partial(rows) = core.term.damage() else {
        panic!("expected retained partial damage");
    };
    assert!(rows.into_iter().any(|row| row.line == 1));
    assert!(core.frame_cache.is_none());
}

#[test]
fn all_rows_promote_then_rebuild_and_geometry_growth_does_not_latch() {
    let mut core = TerminalCore::new(12, 5);
    let mut out = Frame::blank(2, 1);
    prime(&mut core, &mut out);
    let rebuilds = core.cache_counts.rebuilds;
    for row in 1..=5 {
        core.feed(format!("\x1b[{row};1Hchanged").as_bytes());
    }
    check(&mut core, &mut out);
    assert!(core.cache_counts.promoted > 0);
    assert!(!core.frame_cache.as_ref().unwrap().fresh);
    core.feed(b"\x1b[2;2Hc");
    check(&mut core, &mut out);
    assert_eq!(core.cache_counts.rebuilds, rebuilds + 1);
    let partial = core.cache_counts.partial;
    core.feed(b"\x1b[3;2Hd");
    check(&mut core, &mut out);
    assert_eq!(core.cache_counts.partial, partial + 1);
    core.resize(20, 7);
    assert!(core.frame_cache.is_none());
    check(&mut core, &mut out);
    core.feed(b"\x1b[2;2He");
    check(&mut core, &mut out);
    assert!(core.frame_cache.as_ref().unwrap().fresh);
    let partial = core.cache_counts.partial;
    core.feed(b"\x1b[3;2Hf");
    check(&mut core, &mut out);
    assert_eq!(core.cache_counts.partial, partial + 1);
}

#[test]
fn stale_zero_visible_history_damage_does_not_allocate() {
    let mut core = TerminalCore::new(12, 5);
    let mut out = Frame::blank(2, 1);
    core.feed(&b"line\r\n".repeat(20));
    core.scroll(10);
    check(&mut core, &mut out);
    check(&mut core, &mut out);
    assert!(core.frame_cache.is_none());
    assert_eq!(core.cache_counts.rebuilds, 0);
}

#[test]
fn complete_color_inputs_and_palette_rebuild_are_observed() {
    use alacritty_terminal::term::color::COUNT;
    use alacritty_terminal::vte::ansi::{Handler, Rgb};
    let mut core = TerminalCore::new(12, 5);
    let mut out = Frame::blank(2, 1);
    prime(&mut core, &mut out);
    for index in 0..COUNT {
        let cache = core.frame_cache.as_ref().unwrap();
        let mut changed = *core.term.colors();
        changed[index] = Some(Rgb { r: 1, g: 2, b: 3 });
        assert!(
            !cache.colors_match(&changed),
            "conversion input {index} omitted"
        );
        core.term.set_color(index, Rgb { r: 1, g: 2, b: 3 });
        check(&mut core, &mut out);
        assert!(!core.frame_cache.as_ref().unwrap().fresh);
        core.feed(b"\x1b[2;2Hx");
        check(&mut core, &mut out);
        assert!(core.frame_cache.as_ref().unwrap().fresh);
        let partial = core.cache_counts.partial;
        core.feed(b"\x1b[3;2Hy");
        check(&mut core, &mut out);
        assert_eq!(core.cache_counts.partial, partial + 1);
    }
    assert!(core.cache_counts.colors_changed > 0);
}

#[test]
fn no_op_bottom_scroll_keeps_cache_but_history_and_replay_invalidate() {
    let mut core = TerminalCore::with_replay(24, 8);
    let mut out = Frame::blank(2, 1);
    prime(&mut core, &mut out);
    core.scroll_to_bottom();
    assert!(core.frame_cache.as_ref().unwrap().fresh);
    core.set_history_limit(20);
    assert!(!core.frame_cache.as_ref().unwrap().fresh);
    core.feed(b"\x1b[2;2Hc");
    check(&mut core, &mut out);
    core.replay().unwrap();
    assert!(!core.frame_cache.as_ref().unwrap().fresh);
    check(&mut core, &mut out);
    core.feed(b"\x1b[3;2Hd");
    check(&mut core, &mut out);
    core.snapshot().unwrap();
    assert!(!core.frame_cache.as_ref().unwrap().fresh);
    check(&mut core, &mut out);
    core.clear_history();
    check(&mut core, &mut out);
}

#[test]
fn cache_never_executes_buffered_sync_or_changes_reply_ownership() {
    let mut full = TerminalCore::new(24, 8);
    let mut cached = TerminalCore::new(24, 8);
    let mut out = Frame::blank(2, 1);
    prime(&mut cached, &mut out);
    full.feed(b"\x1b[2;2Ha\x1b[3;2Hb");
    let bytes = b"\x1b[?2026h\x1b[2;2Hnew\x1b[6n";
    assert_eq!(
        full.feed_with_replies(bytes).unwrap(),
        cached.feed_with_replies(bytes).unwrap()
    );
    let deadline = cached.sync_deadline();
    assert!(deadline.is_some());
    check(&mut cached, &mut out);
    assert_eq!(cached.sync_deadline(), deadline);
    assert_eq!(
        full.flush_with_replies().unwrap(),
        cached.flush_with_replies().unwrap()
    );
    check(&mut cached, &mut out);
    assert_eq!(cached.frame(), full.frame());
}

#[test]
fn missed_changing_row_negative_detects_a_real_partial_path() {
    let mut core = TerminalCore::new(12, 5);
    let mut out = Frame::blank(2, 1);
    prime(&mut core, &mut out);
    core.feed(b"\x1b[2;2Hx\x1b[4;2Hy");
    core.cache_omit_row = Some(3);
    let before = core.cache_counts.partial;
    let expected = core.frame();
    core.frame_into_cached(&mut out);
    assert_eq!(core.cache_counts.partial, before + 1);
    assert_ne!(
        out, expected,
        "equivalence oracle must detect missing changing row"
    );
    core.cache_omit_row = None;
    core.invalidate_frame_cache();
    check(&mut core, &mut out);
}

#[test]
fn bounded_two_thousand_operation_differential_frames() {
    let mut core = TerminalCore::new(24, 8);
    let mut out = Frame::blank(2, 1);
    prime(&mut core, &mut out);
    let mut seed = 0x306cafeu64;
    for operation in 0..2000 {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
        let row = 1 + seed as usize % usize::from(core.size().rows());
        let col = 1 + (seed >> 16) as usize % usize::from(core.size().cols());
        match (seed >> 32) % 16 {
            0 => core.feed(format!("\x1b[{row};{col}Htext").as_bytes()),
            1 => core.feed("界e\u{301}😀".as_bytes()),
            2 => core.feed(b"\x1b[2J\x1b[H"),
            3 => core.feed(b"\x1b[2;4r\x1b[2;2H\x1b[2M\x1b[r"),
            4 => core.feed(b"\x1b[2P\x1b[3@\x1b[2L\x1b[2X"),
            5 => core.feed(b"\x1b[?1049hA\x1b[?1049l"),
            6 => core.feed(b"\x1b[?1h\x1b=\x1b[?6h\x1b[?1002h\x1b[?1006h\x1b[?2004h"),
            7 => core.feed(b"\x1b[?1l\x1b>\x1b[?6l\x1b[?1002l\x1b[?1006l\x1b[?2004l\x1b[?25l"),
            8 => core.feed(b"\x1b]4;1;#123456\x07\x1b]10;#abcdef\x07"),
            9 => core.resize(14 + (seed % 27) as u16, 4 + ((seed >> 12) % 9) as u16),
            10 => core.scroll((seed % 9) as i32 - 4),
            11 => core.scroll_to_bottom(),
            12 => core.set_history_limit((seed % 100) as usize),
            13 => core.feed(b"\x1bc\x1b[3J\t\x1b[3b"),
            14 => {
                let mut text = String::from("m");
                text.extend(std::iter::repeat_n('\u{301}', 16));
                core.feed(text.as_bytes());
            }
            _ => core.feed(format!("\x1b[1;{}H界\x1b[2;1Hx", core.size().cols()).as_bytes()),
        }
        let expected = core.frame();
        core.frame_into_cached(&mut out);
        assert_eq!(out, expected, "operation {operation}, seed {seed}");
        if operation % 3 == 0 {
            let mut full = Frame::blank(2, 1);
            core.frame_into(&mut full);
            assert_eq!(full, expected);
        }
        out.cells.fill(Cell::blank());
        out.alt_screen = !out.alt_screen;
        Arc::make_mut(&mut out.palette).default_bg = 0xabcdef;
    }
    assert!(core.cache_counts.partial > 0);
}
