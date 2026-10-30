use super::*;
use transport::shell_frame::{encode_record, REC_DATA, REC_ECHO_ACK};

fn assert_authoritative(state: &mut ShellState, actual: terminal::Frame) {
    assert_eq!(actual, state.terminal.frame());
    let mut poisoned = actual;
    poisoned.cells.fill(terminal::Cell::blank());
    poisoned.cursor_col = u16::MAX;
    state.recycle(poisoned);
    assert_eq!(state.snapshot(), state.terminal.frame());
}

#[test]
fn cached_snapshots_preserve_real_shell_events_and_recycled_storage() {
    let mut state = ShellState::new(24, 8, prediction::DisplayPreference::Never, false);
    for (index, bytes) in [
        b"first".as_slice(),
        "\x1b[2;2He\u{301}界".as_bytes(),
        b"\x1b[3;2Hchanged",
        b"\x1b]4;1;#123456\x07",
        b"\x1b[?1049hnew\x1b[?1049l",
        b"\x1b[?1h\x1b[?2004h\x1b[?1006h",
        b"\x1b[?25l\x1b[?1l",
    ]
    .into_iter()
    .enumerate()
    {
        let actual = state.on_stream0(&encode_record(REC_DATA, bytes), index as i64 * 100, 20);
        assert_authoritative(&mut state, actual);
    }
    for (cols, rows) in [(40, 12), (12, 4), (512, 256), (24, 8)] {
        let actual = state.geometry_frame(cols, rows, 2000);
        assert_authoritative(&mut state, actual);
    }
}

#[test]
fn cached_reset_history_and_reattach_preserve_the_authoritative_view() {
    let mut state = ShellState::new(24, 8, prediction::DisplayPreference::Never, false);
    state.on_stream0(&encode_record(REC_DATA, &b"history\r\n".repeat(20)), 0, 20);
    state.set_history_view(true);
    let actual = state.scroll_frame(10, 100, 20);
    assert_authoritative(&mut state, actual);
    let actual = state.on_reset();
    assert_authoritative(&mut state, actual);
    let actual = state.on_reattach();
    assert_authoritative(&mut state, actual);
}

#[test]
fn predicted_and_recycled_outputs_do_not_modify_the_cached_authority() {
    let mut state = ShellState::new(24, 8, prediction::DisplayPreference::Always, false);
    state.on_stream0(&encode_record(REC_DATA, b"\x1b[2;2Ha"), 0, 20);
    state.on_stream0(&encode_record(REC_DATA, b"\x1b[3;2Hb"), 10, 20);
    // One real echo/ACK establishes the predictor's confirmation epoch.
    state.on_input(b"h", 1000, 100);
    let mut echo = encode_record(REC_DATA, b"h");
    echo.extend(encode_record(REC_ECHO_ACK, &1u64.to_be_bytes()));
    state.on_stream0(&echo, 1050, 100);
    let authority = state.terminal.frame();
    let mut predicted = state.on_input(b"i", 1100, 100);
    assert_eq!(state.terminal.frame(), authority);
    assert!(
        predicted != authority,
        "the ownership control must exercise actual prediction"
    );
    predicted.cells.fill(terminal::Cell::blank());
    state.recycle(predicted);
    assert_eq!(state.snapshot(), authority);
}
