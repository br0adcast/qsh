use super::*;

fn retained_bytes(e: &PredictionEngine) -> usize {
    e.overlays.capacity() * std::mem::size_of::<ConditionalOverlayRow>()
        + e.cursors.capacity() * std::mem::size_of::<ConditionalCursorMove>()
        + e.overlays
            .iter()
            .map(|row| {
                row.overlay_cells.capacity() * std::mem::size_of::<ConditionalOverlayCell>()
                    + row
                        .overlay_cells
                        .iter()
                        .map(|cell| cell.original_contents.capacity() * std::mem::size_of::<Cell>())
                        .sum::<usize>()
            })
            .sum::<usize>()
}

fn pending(e: &mut PredictionEngine, fb: &Frame, unit: &[u8], n: usize) {
    e.set_local_frame_sent(n as i64);
    for byte in unit.iter().copied().cycle().take(n) {
        e.new_user_byte(byte, fb, 1000);
    }
    e.cull(fb, 1000);
}

// Removing a total capacity guard retains tens of MiB on this 4KiB edit.
#[test]
fn no_ack_edit_has_bounded_owned_backing_and_releases_fallback_cache() {
    let mut e = PredictionEngine::new(DisplayPreference::Adaptive);
    let fb = Frame::blank(80, 24);
    pending(&mut e, &fb, b"p\x7f", 4096);
    assert!(
        retained_bytes(&e) <= 4 * 1024 * 1024,
        "owned bytes={}",
        retained_bytes(&e)
    );
    assert_eq!(
        retained_bytes(&e),
        0,
        "fallback must free capacity, not only lengths"
    );
    assert!(!e.active());
    assert_eq!(e.apply(&fb), fb);
}

// A history-only limit misses the growing pending cursor list.
#[test]
fn no_ack_unicode_has_bounded_pending_cursors() {
    let mut e = PredictionEngine::new(DisplayPreference::Adaptive);
    pending(&mut e, &Frame::blank(8, 3), "p界e\u{301}".as_bytes(), 2048);
    assert!(e.cursors.len() <= 64, "pending cursors={}", e.cursors.len());
}

// Without a cumulative work allowance, small chunks keep rescanning pending state.
#[test]
fn no_ack_small_chunks_do_not_restart_prediction_work_allowance() {
    let mut e = PredictionEngine::new(DisplayPreference::Adaptive);
    let fb = Frame::blank(8, 3);
    for offset in 1..=2048 {
        e.set_local_frame_sent(offset);
        e.new_user_byte(b'p', &fb, 1000);
        e.cull(&fb, 1000);
    }
    assert!(
        e.observed_work.cells + e.observed_work.cursors <= 65536,
        "validity visits={}",
        e.observed_work.cells + e.observed_work.cursors
    );
}

// Partial ACK and mode/geometry changes must not lift the fallback fence.
#[test]
fn only_full_ack_consumed_with_authoritative_frame_restores_prediction() {
    let mut e = PredictionEngine::new(DisplayPreference::Always);
    let fb = Frame::blank(80, 24);
    pending(&mut e, &fb, b"p\x7f", 4096);
    assert_eq!(retained_bytes(&e), 0);
    e.set_echo_ack(2048);
    e.set_display_preference(DisplayPreference::Never);
    e.set_display_preference(DisplayPreference::Always);
    e.reset(); // Visual/geometry resets do not change the input-offset namespace.
    let resized = Frame::blank(79, 23);
    e.cull(&resized, 2000);
    e.set_local_frame_sent(4097);
    e.new_user_byte(b'x', &resized, 2000);
    assert_eq!(
        retained_bytes(&e),
        0,
        "partial ACK/resize/mode must preserve fence"
    );
    e.set_echo_ack(4096);
    e.cull(&resized, 2001);
    assert_eq!(retained_bytes(&e), 0, "new input extends the fence");
    e.set_echo_ack(4097);
    e.cull(&resized, 2002);
    e.set_local_frame_sent(4098);
    e.new_user_byte(b'y', &resized, 2003);
    assert!(
        retained_bytes(&e) > 0,
        "ordinary typing must resume after complete ACK"
    );
}

#[test]
fn backing_limit_applies_before_first_row_allocation() {
    let mut e = PredictionEngine::new(DisplayPreference::Always);
    e.budget.limits.bytes = 8192;
    e.set_local_frame_sent(1);
    e.new_user_byte(b'x', &Frame::blank(80, 24), 0);
    assert_eq!(e.budget.bytes, 0);
    assert!(
        e.budget.peak_bytes <= 8192,
        "allocation must be refused before crossing the backing ceiling"
    );
    assert_eq!(e.overlays.capacity(), 0);
    assert!(e.suppressed_until.is_some());
}

#[test]
fn cursor_limit_applies_independently_of_history_or_work_limits() {
    let mut e = PredictionEngine::new(DisplayPreference::Always);
    e.budget.limits.cursors = 2;
    e.set_local_frame_sent(6);
    let fb = Frame::blank(8, 3);
    for &byte in b"p\rp\rp\r" {
        e.new_user_byte(byte, &fb, 0);
    }
    assert!(e.suppressed_until.is_some());
    assert_eq!(e.budget.bytes, 0);
}

#[test]
fn work_limit_applies_before_memory_and_cursor_limits() {
    let mut e = PredictionEngine::new(DisplayPreference::Always);
    e.budget.limits.work = 128;
    e.set_local_frame_sent(16);
    let fb = Frame::blank(2, 1);
    for _ in 0..16 {
        e.new_user_byte(b'p', &fb, 0);
    }
    assert!(e.suppressed_until.is_some());
    assert!(e.budget.used <= 128);
    assert_eq!(e.budget.bytes, 0);
}

#[test]
fn rendering_cannot_rescan_speculation_without_spending_work() {
    let mut e = PredictionEngine::new(DisplayPreference::Always);
    super::tests::warm_up(&mut e);
    let fb = Frame::blank(20, 1);
    e.set_local_frame_sent(2);
    e.new_user_byte(b'h', &fb, 1);
    assert!(e.active());
    assert_eq!(e.apply(&fb).cell(0, 0).ch, 'h');
    for _ in 0..4096 {
        e.apply(&fb);
    }
    assert_eq!(e.apply(&fb), fb);
    assert_eq!(e.budget.bytes, 0);
    assert!(!e.active());
}

fn suppressed() -> (PredictionEngine, Frame) {
    let mut e = PredictionEngine::new(DisplayPreference::Always);
    let fb = Frame::blank(20, 1);
    e.budget.limits.work = 128;
    e.set_local_frame_sent(100);
    for _ in 0..100 {
        e.new_user_byte(b'p', &fb, 0);
    }
    assert!(e.suppressed_until.is_some());
    e.budget.limits.work = 65536;
    (e, fb)
}

#[test]
fn utf8_prefix_is_preserved_when_full_ack_arrives_mid_character() {
    let (mut e, fb) = suppressed();
    e.set_local_frame_sent(101);
    e.new_user_byte(0xe2, &fb, 1);
    e.set_echo_ack(101);
    e.cull(&fb, 2);
    for (offset, byte) in [(102, 0x82), (103, 0xac)] {
        e.set_local_frame_sent(offset);
        e.new_user_byte(byte, &fb, 3);
    }
    assert_eq!(e.overlays[0].overlay_cells[0].replacement.ch, '€');
    assert_eq!(e.cursor().base.col, 1);
}

#[test]
fn application_cursor_prefix_is_normalized_across_recovery() {
    let (mut e, fb) = suppressed();
    e.set_local_frame_sent(101);
    e.new_user_byte(0x1b, &fb, 1);
    e.set_echo_ack(101);
    e.cull(&fb, 2);
    e.set_local_frame_sent(103);
    e.new_user_byte(b'O', &fb, 3);
    e.new_user_byte(b'C', &fb, 3);
    assert_eq!(
        e.cursor().base.col,
        1,
        "ESC O C must remain a single right arrow"
    );
    assert!(e.overlays.is_empty());
}

#[test]
fn disabled_prediction_preserves_utf8_for_later_enabled_input() {
    let mut e = PredictionEngine::new(DisplayPreference::Never);
    let fb = Frame::blank(20, 1);
    e.set_local_frame_sent(1);
    e.new_user_byte(0xe2, &fb, 0);
    e.set_echo_ack(1);
    e.cull(&fb, 1);
    e.set_display_preference(DisplayPreference::Always);
    e.set_local_frame_sent(3);
    e.new_user_byte(0x82, &fb, 2);
    e.new_user_byte(0xac, &fb, 2);
    assert_eq!(e.overlays[0].overlay_cells[0].replacement.ch, '€');
}

#[test]
fn constant_time_active_count_matches_activation_and_retirement() {
    let mut e = PredictionEngine::new(DisplayPreference::Always);
    let mut fb = Frame::blank(8, 3);
    for (idx, byte) in b"pq\x7f\rX\x1b[DZ".iter().copied().enumerate() {
        e.set_local_frame_sent(idx as i64 + 1);
        e.new_user_byte(byte, &fb, 0);
        assert_eq!(
            e.active_cells,
            e.overlays
                .iter()
                .flat_map(|r| &r.overlay_cells)
                .filter(|c| c.base.active)
                .count()
        );
    }
    e.set_echo_ack(20);
    fb.cursor_col = 1;
    e.cull(&fb, 2);
    assert_eq!(
        e.active_cells,
        e.overlays
            .iter()
            .flat_map(|r| &r.overlay_cells)
            .filter(|c| c.base.active)
            .count()
    );
    e.reset();
    assert_eq!(e.active_cells, 0);
    assert!(!e.active());
}

#[test]
fn complete_ack_finishes_episode_even_when_validation_needs_fallback() {
    for allowance in [128, 256, 512, 1024] {
        for unit in [b"p\rp\x7f".as_slice(), "p界e\u{301}".as_bytes()] {
            let mut e = PredictionEngine::new(DisplayPreference::Always);
            e.budget.limits.work = allowance;
            let fb = Frame::blank(8, 3);
            e.set_local_frame_sent(64);
            for byte in unit.iter().copied().cycle().take(64) {
                e.new_user_byte(byte, &fb, 0);
            }
            e.set_echo_ack(64);
            e.cull(&fb, 1);
            assert!(
                e.suppressed_until.is_none(),
                "complete consumed ACK must close the old episode"
            );
            e.budget.limits.work = 65536;
            e.set_local_frame_sent(65);
            e.new_user_byte(b'x', &fb, 2);
            assert!(e.budget.bytes > 0);
        }
    }
}

#[test]
fn ordinary_echo_confirmation_restores_visible_typing_after_fallback() {
    let (mut e, mut fb) = suppressed();
    e.set_echo_ack(100);
    e.cull(&fb, 1);
    e.set_local_frame_sent(101);
    e.new_user_byte(b'h', &fb, 2);
    // Fallback starts an unconfirmed episode, like a new connection. An
    // actual echo confirms it; no-echo input must not create false confidence.
    fb.cell_mut(0, 0).set_char('h');
    fb.cursor_col = 1;
    e.set_echo_ack(101);
    e.cull(&fb, 3);
    e.set_local_frame_sent(102);
    e.new_user_byte(b'i', &fb, 4);
    assert!(e.active());
    assert_eq!(e.apply(&fb).cell(0, 1).ch, 'i');
}
