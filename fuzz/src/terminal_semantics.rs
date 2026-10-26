//! Supported daemon repaint scenes; arbitrary bytes stay in the robustness lane.
use terminal::{TerminalCore, TerminalOptions};
use terminal_size::TerminalSize;

pub(super) const SCENES: u8 = 27;
const MAX_GENERATED_BYTES: usize = 16_384;

fn model(size: TerminalSize) -> TerminalCore {
    TerminalCore::with_options(
        size,
        TerminalOptions {
            history_lines: 0,
            replay: true,
        },
    )
}

fn equivalent(a: &mut TerminalCore, b: &mut TerminalCore) {
    let mut left = a.frame();
    let mut right = b.frame();
    assert_eq!(
        (left.cols, left.rows),
        (right.cols, right.rows),
        "repaint/continuation frame size"
    );
    for (index, (want, got)) in left.cells.iter().zip(&right.cells).enumerate() {
        assert_eq!(want, got, "repaint/continuation frame cell {index}");
    }
    // Avoid dumping a maximum-geometry grid on failure; still compare every
    // public non-cell field, including cursor, modes and palette.
    left.cells.clear();
    right.cells.clear();
    assert_eq!(left, right, "repaint/continuation frame metadata");
    assert!(a.snapshot() == b.snapshot(), "repaint/continuation state");
    assert_eq!(a.history_size(), 0);
    assert_eq!(b.history_size(), 0);
}

struct Scene {
    size: TerminalSize,
    before: Vec<u8>,
    resizes: Vec<TerminalSize>,
    live: Vec<u8>,
}
fn size(cols: u16, rows: u16) -> TerminalSize {
    TerminalSize::new(cols, rows).unwrap()
}
fn scene(kind: u8, parameter: u8) -> Scene {
    let mut s = Scene {
        size: size(10, 3),
        before: Vec::new(),
        resizes: Vec::new(),
        live: b"next".to_vec(),
    };
    let (before, live): (&[u8], &[u8]) = match kind {
        0 => (b"abc\x1b[1\n", b"Cnext"),
        1 => (b"abc\x1b\x08", b"Dnext"),
        2 => (b"top\r\nmid\r\nbot\x1b[\n", b"Cnext"),
        3 => (b"abc\x1b]0;t\n", b"itle\x07next"),
        4 => (b"abc\x1bP1\n;2qdata\n", b"\x1b\\next"),
        5 => (b"abc\x1b[1\x18", b"next"),
        6 => (b"abc\x1b[1\x1a", b"next"),
        7 => (b"price:\xe2\x82", b"\xac next"),
        8 => (b"abc\x1b(\n", b"0qqq\x1b(B"),
        9 => (b"\x1b[?2026hbefore\x1b[3", b"1m\x1b[?2026hafter"),
        10 => (
            b"\x1b[?2004h\x1b[?1h\x1b[31;44mabc\x1b7\x1b[2;1H",
            b"\x1b8X\x1b[0m",
        ),
        11..=16 => {
            s.size = size(2, 5);
            s.resizes.push(size(8, 7));
            match kind {
                11 => (b"\x1b[?1049h3 ", b"x"),
                12 => (b"3 ", b"x"),
                13 => (b"\x1b[?1049h3 \x1b7\x1b[2;1H", b"\x1b8x"),
                14 => (b"3 \x1b7\x1b[2;1H", b"\x1b8x"),
                15 => ("\x1b[?1049h界".as_bytes(), b"x"),
                _ => {
                    s.resizes = match parameter % 4 {
                        0 => vec![size(2, 5), size(2, 7)],
                        1 => vec![size(8, 7), size(4, 7)],
                        2 => vec![size(8, 7), size(2, 5), size(8, 7)],
                        _ => vec![size(2, 3), size(2, 5)],
                    };
                    (b"\x1b[?1049h  ", b"x")
                }
            }
        }
        17 => {
            // One supported boundary per iteration, not a cross-product.
            s.size = match parameter % 3 {
                0 => size(512, 1),
                1 => size(2, 256),
                _ => size(512, 256),
            };
            (b"a", b"b")
        }
        18 => {
            let payload = 8191 + usize::from(parameter % 3);
            s.before = osc(payload, parameter & 4 != 0);
            s.before.extend_from_slice(b"OK\x1b[1\n");
            s.live = b"Cnext".to_vec();
            return s;
        }
        19 => (b"abc\x1b[1 \n", b"qnext"),
        20 => (b"abc\x1b[1 2\n", b"Cnext"),
        21 => (b"abc\x1b\r", b"Dnext"),
        22 => (b"abc\x1b[1\t", b"Cnext"),
        23 => (b"abc\x1bP1\n;", b"2qdata\n\x1b\\X"),
        24 => (b"abc\x1bP1 \n", b"qdata\x1b\\X"),
        25 => (b"abc\x1b]0;t\x18", b"X"),
        26 => (b"abc\x1bPqdata\x1a", b"X"),
        _ => unreachable!(),
    };
    s.before = before.to_vec();
    s.live = live.to_vec();
    s
}

/// Parameters only select bounded recipes; never filter the raw VT bytes.
pub(super) fn exercise(input: &[u8]) {
    let kind = input.first().copied().unwrap_or(0) % SCENES;
    let parameter = input.get(1).copied().unwrap_or(0);
    let cut = usize::from(input.get(2).copied().unwrap_or(0));
    check(scene(kind, parameter), cut);
    if kind == 18 {
        check_osc(parameter);
    }
}
fn check(scene: Scene, cut: usize) {
    assert!(scene.before.len() + scene.live.len() <= MAX_GENERATED_BYTES);
    assert!(scene.resizes.len() <= 3);
    let mut source = model(scene.size);
    let mut prior = model(scene.size);
    let cut = cut % (scene.before.len() + 1);
    // Different feed chunking also exercises partial UTF-8 and ESC prefixes.
    source.feed(&scene.before[..cut]);
    source.feed(&scene.before[cut..]);
    prior.feed(&scene.before[..cut]);
    for &geometry in &scene.resizes {
        source.resize_to(geometry);
        prior.resize_to(geometry);
    }
    let mut fresh = model(source.size());
    let repaint = source.replay().unwrap(); // Deliberate source sync flush.
    prior.feed(&repaint);
    fresh.feed(&repaint);
    equivalent(&mut source, &mut fresh);
    equivalent(&mut source, &mut prior);
    for core in [&mut source, &mut fresh, &mut prior] {
        core.feed(&scene.live);
    }
    equivalent(&mut source, &mut fresh);
    equivalent(&mut source, &mut prior);
    for core in [&mut source, &mut fresh, &mut prior] {
        core.flush_pending_output();
    }
    equivalent(&mut source, &mut fresh);
    equivalent(&mut source, &mut prior);
}

fn osc(payload: usize, st: bool) -> Vec<u8> {
    assert!((8191..=8193).contains(&payload));
    let mut bytes = b"\x1b]0;".to_vec();
    bytes.resize(2 + payload, b'x'); // 0; counts; ESC] does not.
    bytes.extend_from_slice(if st { b"\x1b\\" } else { b"\x07" });
    bytes
}
#[derive(Default)]
struct OscObserver {
    commands: Vec<Vec<Vec<u8>>>,
    printed: String,
}
impl vte::Perform for OscObserver {
    fn osc_dispatch(&mut self, params: &[&[u8]], _bell: bool) {
        self.commands
            .push(params.iter().map(|p| p.to_vec()).collect());
    }
    fn print(&mut self, c: char) {
        self.printed.push(c);
    }
}
fn check_osc(parameter: u8) {
    let payload = 8191 + usize::from(parameter % 3);
    let mut bytes = osc(payload, parameter & 4 != 0);
    bytes.extend_from_slice(b"SENTINEL");
    // Includes introducer, payload threshold, and ST splits. No clock needed.
    let splits = [0, 1, 2, 8193, 8194, bytes.len() - 9, bytes.len()];
    for cut in splits {
        let mut parser = vte::Parser::new();
        let mut observed = OscObserver::default();
        parser.advance(&mut observed, &bytes[..cut]);
        parser.advance(&mut observed, &bytes[cut..]);
        assert_eq!(observed.printed, "SENTINEL");
        if payload <= 8192 {
            assert_eq!(
                observed.commands,
                vec![vec![b"0".to_vec(), vec![b'x'; payload - 2]]]
            );
        } else {
            assert!(
                observed.commands.is_empty(),
                "overlimit OSC must be discarded"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[should_panic(expected = "repaint/continuation frame")]
    fn oracle_detects_changed_cell() {
        let mut a = model(size(10, 3));
        let mut b = model(size(10, 3));
        b.feed(b"x");
        equivalent(&mut a, &mut b);
    }
    #[test]
    #[should_panic(expected = "repaint/continuation frame")]
    fn oracle_detects_changed_cursor() {
        let mut a = model(size(10, 3));
        let mut b = model(size(10, 3));
        b.feed(b"\x1b[2C");
        equivalent(&mut a, &mut b);
    }
    #[test]
    #[should_panic(expected = "repaint/continuation frame")]
    fn oracle_detects_changed_mode() {
        let mut a = model(size(10, 3));
        let mut b = model(size(10, 3));
        b.feed(b"\x1b[?2004h");
        equivalent(&mut a, &mut b);
    }
    #[test]
    fn every_supported_scene_and_parameter_boundary_executes() {
        for kind in 0..SCENES {
            for parameter in 0..8 {
                for cut in [0, 1, 2, 3, 10, 255] {
                    exercise(&[kind, parameter, cut]);
                }
            }
        }
    }
    #[test]
    fn osc_payload_and_introducer_limits_are_distinct() {
        for parameter in 0..8 {
            check_osc(parameter);
        }
    }
    #[test]
    fn literal_resize_insertion_and_executed_control_regressions() {
        for kind in [11, 12, 13, 14, 15] {
            let s = scene(kind, 0);
            let mut source = model(s.size);
            source.feed(&s.before);
            for geometry in s.resizes {
                source.resize_to(geometry);
            }
            source.feed(&s.live);
            let f = source.frame();
            assert_eq!((f.cursor_row, f.cursor_col), (0, 3));
            assert_eq!(f.cell(0, 2).ch, 'x');
        }
        let mut source = model(size(10, 3));
        source.feed(b"abc\x1b[1\n");
        assert_eq!(
            (source.frame().cursor_row, source.frame().cursor_col),
            (1, 3)
        );
        let mut target = model(size(10, 3));
        target.feed(&source.replay().unwrap());
        assert_eq!(
            (target.frame().cursor_row, target.frame().cursor_col),
            (1, 3)
        );
        equivalent(&mut source, &mut target);
    }
    #[test]
    fn inactive_alternate_saved_cursor_requires_preserved_prior_state() {
        let mut source = model(size(2, 5));
        let mut client = model(size(2, 5));
        for core in [&mut source, &mut client] {
            core.feed(b"\x1b[?1049h3 \x1b7\x1b[?1049l");
            core.resize_to(size(8, 7));
        }
        client.feed(&source.replay().unwrap());
        for core in [&mut source, &mut client] {
            core.feed(b"\x1b[?1049h\x1b8");
            assert_eq!(core.frame().cursor_col, 2);
            core.feed(b"x");
            assert_eq!(core.frame().cell(0, 2).ch, 'x');
        }
        equivalent(&mut source, &mut client);
    }
    #[test]
    fn synchronized_live_output_remains_buffered_until_explicit_flush() {
        let mut source = model(size(10, 3));
        source.feed(b"\x1b[?2026hX");
        assert_eq!(source.frame().cell(0, 0).ch, ' ');
        source.flush_pending_output();
        assert_eq!(source.frame().cell(0, 0).ch, 'X');
    }
    #[test]
    fn orphan_trailing_wide_spacer_is_characterized_separately() {
        let mut source = model(size(4, 2));
        source.feed("界\r\x1b[P".as_bytes());
        let f = source.frame();
        assert_eq!(f.cursor_col, 0);
        assert_ne!(f.cell(0, 0).flags & terminal::FLAG_WIDE_SPACER, 0);
        // This malformed wide pair is outside the strict scene language;
        // never strip wide flags from the strict comparator to admit it.
        let mut target = model(size(4, 2));
        target.feed(&source.replay().unwrap());
        // Exact characterization for this one malformed pair: only the
        // orphan trailing-spacer flag disappears. No global normalizer.
        assert_eq!(f.cell(0, 0).flags, terminal::FLAG_WIDE_SPACER);
        assert_eq!(target.frame().cell(0, 0).flags, 0);
        let mut expected = f;
        expected.cell_mut(0, 0).flags = 0;
        assert_eq!(expected, target.frame());
        source.feed(b"X");
        target.feed(b"X");
        assert_eq!(source.frame().cell(0, 0).ch, 'X');
        assert_eq!(target.frame().cell(0, 0).ch, 'X');
    }
}
