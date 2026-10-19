//! Mouse reports from the local terminal: moved up under the status line on
//! their way to the shell, and kept away from the client's own windows.
//!
//! With the status line shown, the shell's screen starts one row below the
//! terminal's top, so a click the terminal reports at row `y` is at row
//! `y - 1` of the shell's screen. A press on the line itself belongs to no
//! one; a release or a motion there lands on the shell's top row, so a drag
//! that ends on the line still reaches the application with its release.
//! Both report forms carry the row: SGR (`ESC [ < b ; x ; y M` or `m`,
//! xterm's mode 1006) and the older X10 form (`ESC [ M` and three bytes,
//! each value plus 32). Pasted text is never rewritten: inside
//! `ESC [ 200 ~` ... `ESC [ 201 ~` a report-shaped run is text.

const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

/// The motion bit of a report's button code.
const MOTION: u32 = 32;

/// Rewrites mouse reports on their way to the shell, and strips them (with
/// pastes) from input meant for a window. Remembers whether a paste is under
/// way, so a paste split across reads is followed either way, and the
/// unfinished end of the last read on the way to the shell.
#[derive(Debug, Default)]
pub struct MouseShift {
    in_paste: bool,
    /// The end of the last `apply` that may be a paste marker or a report
    /// cut in two, read again in front of the next bytes -- whichever of
    /// `apply` and `strip` gets them. Without it the end of a large paste,
    /// split by a read inside `ESC [ 201 ~`, would leave `in_paste` set
    /// until the next paste, and no click would be moved up again.
    held: Vec<u8>,
}

/// One whole report at the start of a byte run.
struct Report<'a> {
    len: usize,
    form: Form<'a>,
    /// The button code, without the X10 offset.
    button: u32,
    release: bool,
    y: u32,
}

enum Form<'a> {
    /// `b` and `x` as they came, and the final byte (`M` or `m`).
    Sgr { b: &'a [u8], x: &'a [u8], last: u8 },
    /// The first two value bytes as they came.
    X10 { c1: u8, c2: u8 },
}

impl Report<'_> {
    /// Whether this is a press (a button going down, a wheel turn), rather
    /// than a release or a motion.
    fn is_press(&self) -> bool {
        !self.release && self.button & MOTION == 0
    }

    /// The report with its row set to `y`.
    fn at_row(&self, y: u32) -> Vec<u8> {
        match self.form {
            Form::Sgr { b, x, last } => {
                let mut out = b"\x1b[<".to_vec();
                out.extend_from_slice(b);
                out.push(b';');
                out.extend_from_slice(x);
                out.push(b';');
                out.extend_from_slice(y.to_string().as_bytes());
                out.push(last);
                out
            }
            // `y` is at most the row it came with, so it still fits.
            Form::X10 { c1, c2 } => vec![0x1b, b'[', b'M', c1, c2, (y + 32) as u8],
        }
    }
}

impl MouseShift {
    pub fn new() -> MouseShift {
        MouseShift::default()
    }

    /// Shift reports and discard coordinates outside the visible shell.
    /// Releases on the status line retain the ordinary drag-to-top behavior.
    pub fn apply_bounded(&mut self, input: &[u8], shift: u16, cols: u16, rows: u16) -> Vec<u8> {
        self.apply_inside(input, shift, Some((cols, rows)))
    }

    /// `bytes` with every mouse report moved up by `shift` rows: a press at
    /// or above row `shift` is dropped, a release or a motion there lands on
    /// row 1. With `shift == 0` nothing changes, though a paste is still
    /// followed. A paste marker or a report cut off by the end of `bytes`
    /// waits for the next call, and goes as it is when the bytes after it
    /// show it is neither.
    ///
    /// One cut start is not held: a bare `ESC [` outside a paste. That is
    /// also a whole key (`Alt-[`), which must not wait for the next key to
    /// be sent. A paste start marker cut right there goes unseen -- the
    /// paste's text is then not kept from being moved, which is all it
    /// costs: the end marker still ends the paste.
    pub fn apply(&mut self, input: &[u8], shift: u16) -> Vec<u8> {
        self.apply_inside(input, shift, None)
    }

    fn apply_inside(&mut self, input: &[u8], shift: u16, bounds: Option<(u16, u16)>) -> Vec<u8> {
        let shift = u32::from(shift);
        let mut bytes = std::mem::take(&mut self.held);
        bytes.extend_from_slice(input);
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let rest = &bytes[i..];
            if let Some(len) = self.paste_marker(rest) {
                out.extend_from_slice(&rest[..len]);
                i += len;
                continue;
            }
            if self.unfinished(rest) && (self.in_paste || rest != b"\x1b[") {
                self.held = rest.to_vec();
                break;
            }
            if (shift > 0 || bounds.is_some()) && !self.in_paste {
                if let Some(r) = report(rest) {
                    let x = match r.form {
                        Form::Sgr { x, .. } => std::str::from_utf8(x)
                            .ok()
                            .and_then(|x| x.parse::<u32>().ok())
                            .unwrap_or(0),
                        Form::X10 { c2, .. } => u32::from(c2).saturating_sub(32),
                    };
                    if bounds.is_some_and(|(cols, rows)| {
                        x == 0
                            || x > u32::from(cols)
                            || r.y == 0
                            || r.y > shift + u32::from(rows)
                            || rows == 0
                    }) {
                        i += r.len;
                        continue;
                    }
                    if r.y > shift {
                        out.extend(r.at_row(r.y - shift));
                    } else if !r.is_press() {
                        out.extend(r.at_row(1));
                    }
                    i += r.len;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        }
        out
    }

    /// Input for a window: `bytes` without whole mouse reports and without
    /// pastes (their markers included) -- neither is a key press. The second
    /// part is an unfinished report, paste marker or `ESC [` at the end,
    /// for the caller to hand back in front of the next read; a lone `ESC`
    /// at the end is the Esc key and is kept -- except inside a paste,
    /// where it is the start of the end marker. A tail `apply` held goes in
    /// front of `bytes`.
    pub fn strip(&mut self, input: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut bytes = std::mem::take(&mut self.held);
        bytes.extend_from_slice(input);
        let mut out = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            let rest = &bytes[i..];
            if let Some(len) = self.paste_marker(rest) {
                i += len;
                continue;
            }
            if self.unfinished(rest) {
                return (out, rest.to_vec());
            }
            if self.in_paste {
                i += 1;
                continue;
            }
            if let Some(r) = report(rest) {
                i += r.len;
                continue;
            }
            out.push(bytes[i]);
            i += 1;
        }
        (out, Vec::new())
    }

    /// Takes back an unfinished tail `strip` returned that its caller will
    /// not read (a window closed): it goes in front of the next bytes,
    /// whichever of `apply` and `strip` gets them.
    pub fn hand_back(&mut self, mut tail: Vec<u8>) {
        tail.append(&mut self.held);
        self.held = tail;
    }

    /// The length of a paste marker at the start of `rest`, following it.
    fn paste_marker(&mut self, rest: &[u8]) -> Option<usize> {
        if rest.starts_with(PASTE_START) {
            self.in_paste = true;
            Some(PASTE_START.len())
        } else if rest.starts_with(PASTE_END) {
            self.in_paste = false;
            Some(PASTE_END.len())
        } else {
            None
        }
    }

    /// Whether `rest` (the end of a read) may be the start of a paste marker
    /// or of a report, cut off. A lone `ESC` is one only inside a paste;
    /// outside it is the Esc key.
    fn unfinished(&self, rest: &[u8]) -> bool {
        if rest.first() != Some(&0x1b) {
            return false;
        }
        if self.in_paste {
            return PASTE_END.starts_with(rest);
        }
        if rest.len() < 2 {
            return false;
        }
        PASTE_START.starts_with(rest)
            || PASTE_END.starts_with(rest)
            || rest
                .strip_prefix(b"\x1b[<")
                .is_some_and(|p| p.iter().all(|b| b.is_ascii_digit() || *b == b';'))
            || (rest.starts_with(b"\x1b[M") && rest.len() < 6)
    }
}

/// A whole report, SGR or X10, at the start of `rest`.
fn report(rest: &[u8]) -> Option<Report<'_>> {
    sgr(rest).or_else(|| x10(rest))
}

fn sgr(rest: &[u8]) -> Option<Report<'_>> {
    let body = rest.strip_prefix(b"\x1b[<")?;
    let end = body
        .iter()
        .position(|b| !(b.is_ascii_digit() || *b == b';'))?;
    let last = body[end];
    if last != b'M' && last != b'm' {
        return None;
    }
    let mut fields = body[..end].split(|b| *b == b';');
    let (b, x, y) = (fields.next()?, fields.next()?, fields.next()?);
    if fields.next().is_some() || b.is_empty() || x.is_empty() || y.is_empty() {
        return None;
    }
    let number = |f: &[u8]| -> Option<u32> { std::str::from_utf8(f).ok()?.parse().ok() };
    Some(Report {
        len: 3 + end + 1,
        form: Form::Sgr { b, x, last },
        button: number(b)?,
        release: last == b'm',
        y: number(y)?,
    })
}

/// `ESC [ M` and exactly three bytes, the row last. A release is button
/// code 3 in the low bits.
fn x10(rest: &[u8]) -> Option<Report<'_>> {
    let body = rest.strip_prefix(b"\x1b[M")?;
    let &[c1, c2, c3, ..] = body else {
        return None;
    };
    let button = u32::from(c1).checked_sub(32)?;
    Some(Report {
        len: 6,
        form: Form::X10 { c1, c2 },
        button,
        release: button & 3 == 3,
        y: u32::from(c3).checked_sub(32)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mouse_reports_outside_shell_bounds_are_excluded() {
        let mut m = MouseShift::new();
        assert_eq!(
            m.apply_bounded(b"a\x1b[<0;2;2M\x1b[<0;1;3M\x1b[<0;1;2Mb", 1, 1, 1),
            b"a\x1b[<0;1;1Mb"
        );
        assert_eq!(m.apply_bounded(b"\x1b[<0;0;2M", 1, 1, 1), b"");
    }

    #[test]
    fn sgr_reports_move_up_one_row() {
        let mut m = MouseShift::new();
        assert_eq!(
            m.apply(b"a\x1b[<0;10;5Mb\x1b[<0;10;5m", 1),
            b"a\x1b[<0;10;4Mb\x1b[<0;10;4m"
        );
    }

    #[test]
    fn a_press_on_the_status_line_goes_nowhere() {
        let mut m = MouseShift::new();
        assert_eq!(m.apply(b"x\x1b[<0;3;1My", 1), b"xy");
        assert_eq!(m.apply(&[0x1b, b'[', b'M', 32, 40, 33], 1), b"");
        assert_eq!(m.apply(b"\x1b[<64;3;1M", 1), b"", "a wheel turn is a press");
    }

    /// A drag that ends on the line still reaches the application with its
    /// release: release and motion on the line land on the shell's top row.
    #[test]
    fn a_release_or_a_drag_on_the_line_lands_on_the_top_row() {
        let mut m = MouseShift::new();
        assert_eq!(m.apply(b"\x1b[<0;3;1m", 1), b"\x1b[<0;3;1m");
        assert_eq!(m.apply(b"\x1b[<32;3;1M", 1), b"\x1b[<32;3;1M");
        assert_eq!(m.apply(b"\x1b[<0;3;2m", 1), b"\x1b[<0;3;1m");
        // X10: release is button code 3; motion has bit 32 (code + 32 on the wire).
        assert_eq!(
            m.apply(&[0x1b, b'[', b'M', 32 + 3, 40, 33], 1),
            vec![0x1b, b'[', b'M', 35, 40, 33]
        );
        assert_eq!(
            m.apply(&[0x1b, b'[', b'M', 32 + 32, 40, 33], 1),
            vec![0x1b, b'[', b'M', 64, 40, 33]
        );
        // A shift past the report's own row still lands on row 1.
        assert_eq!(m.apply(b"\x1b[<0;3;2m", 3), b"\x1b[<0;3;1m");
    }

    /// For a window: whole reports and pastes go, the rest stays.
    #[test]
    fn strip_drops_reports_and_pastes() {
        let mut m = MouseShift::new();
        let (kept, tail) = m.strip(b"a\x1b[<0;10;2Mb\x1b[M 2qc\x1b[200~2\r\x1b[201~d");
        assert_eq!(kept, b"abcd");
        assert!(tail.is_empty());
    }

    #[test]
    fn strip_follows_a_paste_across_reads() {
        let mut m = MouseShift::new();
        assert_eq!(m.strip(b"x\x1b[200~12"), (b"x".to_vec(), Vec::new()));
        assert_eq!(m.strip(b"\r3"), (Vec::new(), Vec::new()));
        assert_eq!(m.strip(b"\x1b[20"), (Vec::new(), b"\x1b[20".to_vec()));
        assert_eq!(m.strip(b"\x1b[201~y"), (b"y".to_vec(), Vec::new()));
    }

    /// The unfinished start of a report is handed back to be read again with
    /// the next bytes; a lone `ESC` is the Esc key and is kept.
    #[test]
    fn strip_hands_back_an_unfinished_report() {
        let mut m = MouseShift::new();
        assert_eq!(
            m.strip(b"x\x1b[<0;1"),
            (b"x".to_vec(), b"\x1b[<0;1".to_vec())
        );
        assert_eq!(m.strip(b"\x1b[M 2"), (Vec::new(), b"\x1b[M 2".to_vec()));
        assert_eq!(m.strip(b"\x1b["), (Vec::new(), b"\x1b[".to_vec()));
        assert_eq!(m.strip(b"\x1b"), (b"\x1b".to_vec(), Vec::new()));
        assert_eq!(m.strip(b"\x1b[A"), (b"\x1b[A".to_vec(), Vec::new()));
    }

    #[test]
    fn x10_reports_move_up_one_row() {
        let mut m = MouseShift::new();
        assert_eq!(
            m.apply(&[0x1b, b'[', b'M', 32, 40, 38], 1),
            vec![0x1b, b'[', b'M', 32, 40, 37]
        );
    }

    #[test]
    fn a_paste_is_never_rewritten() {
        let mut m = MouseShift::new();
        let paste = b"\x1b[200~\x1b[<0;1;1M\x1b[201~";
        assert_eq!(m.apply(paste, 1), paste.to_vec());
        assert_eq!(m.apply(b"\x1b[200~ab", 1), b"\x1b[200~ab");
        assert_eq!(
            m.apply(b"\x1b[<0;1;1M\x1b[201~", 1),
            b"\x1b[<0;1;1M\x1b[201~",
            "still inside"
        );
    }

    #[test]
    fn without_a_shift_nothing_changes() {
        let mut m = MouseShift::new();
        assert_eq!(m.apply(b"\x1b[<0;3;1M", 0), b"\x1b[<0;3;1M");
    }

    /// A cut report waits; when the next bytes show it is no report, it
    /// goes as it is, in front of them.
    #[test]
    fn a_broken_report_passes_as_it_is() {
        let mut m = MouseShift::new();
        assert_eq!(m.apply(b"\x1b[<0;3", 1), b"");
        assert_eq!(m.apply(b"x", 1), b"\x1b[<0;3x");
        assert_eq!(m.apply(b"a\x1b[20", 1), b"a");
        assert_eq!(m.apply(b"5~", 1), b"\x1b[205~");
    }

    /// A report cut in two by a read is still moved up.
    #[test]
    fn a_report_split_across_reads_is_moved_up() {
        let report = b"\x1b[<0;10;5M";
        for cut in 3..report.len() {
            let mut m = MouseShift::new();
            let mut out = m.apply(&report[..cut], 1);
            out.extend(m.apply(&report[cut..], 1));
            assert_eq!(out, b"\x1b[<0;10;4M", "cut at {cut}");
        }
    }

    /// The end of a paste cut by a read at any place still ends it: what
    /// was pasted goes through untouched, and the next click is moved up.
    #[test]
    fn a_paste_end_split_across_reads_still_ends_the_paste() {
        for cut in 1..PASTE_END.len() {
            let mut m = MouseShift::new();
            let mut first = b"\x1b[200~ab".to_vec();
            first.extend_from_slice(&PASTE_END[..cut]);
            let mut out = m.apply(&first, 1);
            out.extend(m.apply(&PASTE_END[cut..], 1));
            let mut whole = b"\x1b[200~ab".to_vec();
            whole.extend_from_slice(PASTE_END);
            assert_eq!(out, whole, "cut at {cut}");
            assert_eq!(
                m.apply(b"\x1b[<0;10;5M", 1),
                b"\x1b[<0;10;4M",
                "a click after the paste is moved again (cut at {cut})"
            );
        }
    }

    /// The Esc key and `Alt-[` go at once: neither waits for the next key.
    #[test]
    fn the_esc_key_and_alt_bracket_are_not_held() {
        let mut m = MouseShift::new();
        assert_eq!(m.apply(b"\x1b", 1), b"\x1b");
        assert_eq!(m.apply(b"\x1b[", 1), b"\x1b[");
    }

    /// For a window, too, a paste end cut at any place -- a lone `ESC`
    /// included -- ends the paste; keys after it are kept again.
    #[test]
    fn strip_follows_a_paste_end_split_at_any_place() {
        for cut in 1..PASTE_END.len() {
            let mut m = MouseShift::new();
            let mut first = b"\x1b[200~2\r".to_vec();
            first.extend_from_slice(&PASTE_END[..cut]);
            let (kept, tail) = m.strip(&first);
            assert!(kept.is_empty(), "cut at {cut}: {kept:?}");
            let mut next = tail;
            next.extend_from_slice(&PASTE_END[cut..]);
            next.push(b'q');
            assert_eq!(m.strip(&next), (b"q".to_vec(), Vec::new()), "cut at {cut}");
        }
    }

    /// A tail `apply` held is read by `strip` when a window opened in
    /// between.
    #[test]
    fn a_tail_held_on_the_way_to_the_shell_is_read_by_the_window() {
        let mut m = MouseShift::new();
        assert_eq!(m.apply(b"\x1b[200~ab\x1b[20", 1), b"\x1b[200~ab");
        assert_eq!(m.strip(b"1~q"), (b"q".to_vec(), Vec::new()));
    }
}
