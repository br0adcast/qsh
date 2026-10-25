//! Raw terminal robustness and bounded semantic scenes shared with libFuzzer.
//!
//! The first four bytes select a bounded initial and post-feed geometry;
//! every remaining byte is fed to the real emulator. Input is capped so one
//! iteration stays cheap even with escape-sequence state carried across
//! chunks. The property checks that the emulator neither panics nor reports
//! a frame whose dimensions disagree with its model after a resize.
use terminal::{TerminalCore, TerminalOptions};
use terminal_size::TerminalSize;

/// The largest input retained. Four prefix bytes plus at most 8 KiB of
/// terminal bytes per mutation.
pub const MAX_INPUT: usize = 8196;

const HISTORY_LINES: usize = 128;

fn size(first: u8, second: u8) -> TerminalSize {
    let cols = 2 + u16::from(first) % (80 - 2 + 1);
    let rows = 1 + u16::from(second) % 24;
    TerminalSize::new(cols, rows).expect("bounded dimensions are valid")
}

/// Feed one input in two halves separated by a resize. The model's frame
/// must match its own size, and indexing the frame must stay in bounds.
pub fn exercise(input: &[u8]) {
    if input.len() > MAX_INPUT || input.len() < 4 {
        return;
    }
    super::terminal_semantics::exercise(input);
    let initial = size(input[0], input[1]);
    let resized = size(input[2], input[3]);
    let mut terminal = TerminalCore::with_options(
        initial,
        TerminalOptions {
            history_lines: HISTORY_LINES,
            replay: false,
        },
    );
    let bytes = &input[4..];
    let half = bytes.len() / 2;
    terminal.feed(&bytes[..half]);
    terminal.resize(resized.cols(), resized.rows());
    terminal.feed(&bytes[half..]);
    terminal.flush_pending_output();

    let model = terminal.size();
    let frame = terminal.frame();
    assert_eq!(frame.width(), model.cols());
    assert_eq!(frame.height(), model.rows());
    if frame.width() > 0 && frame.height() > 0 {
        let cell = frame.cell(frame.height() - 1, frame.width() - 1);
        let _ = cell.ch;
    }
}

fn prefixed(cols: u8, rows: u8, new_cols: u8, new_rows: u8, bytes: &[u8]) -> Vec<u8> {
    let mut input = vec![cols, rows, new_cols, new_rows];
    input.extend_from_slice(bytes);
    input
}

/// Synthetic public terminal streams. No recorded session is used.
pub fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let mut cases = vec![
        ("empty", prefixed(80, 24, 80, 24, b"")),
        ("ascii", prefixed(80, 24, 40, 12, b"hello world\n")),
        ("cursor", prefixed(80, 24, 80, 24, b"\x1b[10;20H\x1b[2J")),
        ("sgr", prefixed(80, 24, 80, 24, b"\x1b[1;31;44mred\x1b[0m")),
        (
            "alt-screen",
            prefixed(80, 24, 80, 24, b"\x1b[?1049hfullscreen\x1b[?1049l"),
        ),
        (
            "wide-combining",
            prefixed(40, 12, 80, 24, "a\u{0301}界🙂\n".as_bytes()),
        ),
        (
            "osc-title",
            prefixed(80, 24, 80, 24, b"\x1b]0;title\x07text"),
        ),
        (
            "sync-update",
            prefixed(80, 24, 80, 24, b"\x1b[?2026htext\x1b[?2026l"),
        ),
        (
            "invalid-utf8",
            prefixed(80, 24, 80, 24, &[0xff, 0xfe, 0x1b, 0x00]),
        ),
        (
            "control-bytes",
            prefixed(20, 5, 20, 5, &[0x00, 0x07, 0x08, 0x0a, 0x0d, 0x1b, 0x7f]),
        ),
        (
            "resize-boundaries",
            prefixed(0xff, 0xff, 0x00, 0x00, b"boundary"),
        ),
        (
            "scrollback",
            prefixed(10, 3, 20, 6, b"line\r\n".repeat(40).as_slice()),
        ),
        (
            "bracketed-paste",
            prefixed(80, 24, 80, 24, b"\x1b[200~pasted\x1b[201~"),
        ),
        ("charset", prefixed(80, 24, 80, 24, b"\x1b(0lqqk\x1b(B")),
        (
            "deterministic-junk",
            prefixed(
                80,
                24,
                80,
                24,
                &(0..256u16).map(|i| (i % 251) as u8).collect::<Vec<_>>(),
            ),
        ),
    ];
    for (name, kind, parameter) in [
        ("semantic-csi-lf", 0, 0),
        ("semantic-alt-grow", 11, 0),
        ("semantic-saved-grow", 13, 0),
        ("semantic-wide-grow", 15, 0),
        ("semantic-repeat-resize", 16, 2),
        ("semantic-max-geometry", 17, 2),
        ("semantic-sync-cut", 9, 0),
        ("semantic-osc-below", 18, 0),
        ("semantic-osc-at", 18, 1),
        ("semantic-osc-over", 18, 2),
        ("semantic-osc-st", 18, 6),
    ] {
        cases.push((name, vec![kind, parameter, 3, 0]));
    }
    cases
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_oversized_inputs_are_normal_inputs() {
        for input in [&[][..], &[80][..], &[80, 24, 40][..]] {
            exercise(input);
        }
        exercise(&vec![0xab; MAX_INPUT + 1]);
    }

    #[test]
    fn all_synthetic_streams_leave_a_consistent_frame() {
        for (_, bytes) in cases() {
            exercise(&bytes);
        }
    }

    #[test]
    fn synthetic_corpus_matches_encoder_recipes_and_bounds() {
        let cases = cases();
        assert!(cases.len() <= 32);
        assert!(cases.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() <= 256 * 1024);
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/terminal_feed_resize");
        for (name, bytes) in cases {
            assert!(bytes.len() <= MAX_INPUT);
            assert_eq!(
                std::fs::read(directory.join(name)).unwrap(),
                bytes,
                "{name}"
            );
            exercise(&bytes);
        }
    }
}
