//! Parses OUTGOING keystrokes (what the user types) into coarse classes that
//! are sufficient for prediction: printable character, C0 control, start of
//! an escape sequence, and CSI with a final byte. A full VT parser isn't
//! needed -- only these classes. UTF-8 is accumulated until a full character.

/// Class of an outgoing keystroke. A port of the subset of mosh's parser
/// actions that we need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAction {
    /// A printable character (including `0x7f` -- backspace is handled by
    /// the engine).
    Print(char),
    /// A C0 control byte (e.g. CR `0x0d`).
    Execute(char),
    /// The start of an escape sequence (not CSI) -- the engine marks it
    /// tentative.
    Esc,
    /// A CSI sequence with a final byte (we care about the `C`/`D` arrows).
    Csi(char),
}

/// Parser state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Ground,
    /// Got ESC, waiting for the next byte.
    Esc,
    /// Inside a CSI sequence (after `ESC [`): accumulating parameters until
    /// the final byte.
    Csi,
}

/// Parses a stream of outgoing keystrokes. Holds state across bytes (UTF-8
/// and escape sequences arrive piecemeal).
pub struct KeystrokeParser {
    state: State,
    /// How many more UTF-8 continuation bytes we're waiting for (0 -- not in
    /// the middle of a character).
    utf8_remaining: u8,
    /// Accumulated UTF-8 code point value.
    utf8_acc: u32,
}

impl KeystrokeParser {
    /// A new parser in its initial state.
    pub fn new() -> Self {
        KeystrokeParser {
            state: State::Ground,
            utf8_remaining: 0,
            utf8_acc: 0,
        }
    }

    /// Feed one byte; returns the recognized actions (usually 0 or 1).
    pub fn input(&mut self, byte: u8) -> Vec<KeyAction> {
        // The middle of a UTF-8 character takes priority over the state.
        if self.utf8_remaining > 0 {
            return self.feed_utf8_continuation(byte);
        }
        match self.state {
            State::Ground => self.ground(byte),
            State::Esc => self.esc(byte),
            State::Csi => self.csi(byte),
        }
    }

    fn ground(&mut self, byte: u8) -> Vec<KeyAction> {
        match byte {
            0x1b => {
                self.state = State::Esc;
                Vec::new()
            }
            0x7f => vec![KeyAction::Print('\u{7f}')],
            b if b < 0x20 => vec![KeyAction::Execute(b as char)],
            b if b < 0x80 => vec![KeyAction::Print(b as char)],
            // Start of a multi-byte UTF-8 sequence.
            b => self.begin_utf8(b),
        }
    }

    fn esc(&mut self, byte: u8) -> Vec<KeyAction> {
        if byte == 0x1b {
            // A repeated ESC starts a new escape instead of dispatching the old one.
            Vec::new()
        } else if byte == b'[' {
            self.state = State::Csi;
            Vec::new()
        } else {
            // Any other escape -- we don't predict it, the engine will mark
            // it tentative.
            self.state = State::Ground;
            vec![KeyAction::Esc]
        }
    }

    fn csi(&mut self, byte: u8) -> Vec<KeyAction> {
        // ESC abandons the partial CSI and introduces a fresh escape sequence.
        // Other CSI finals remain 0x40..=0x7e, after parameters/intermediates.
        if byte == 0x1b {
            self.state = State::Esc;
            Vec::new()
        } else if (0x40..=0x7e).contains(&byte) {
            self.state = State::Ground;
            vec![KeyAction::Csi(byte as char)]
        } else {
            Vec::new()
        }
    }

    fn begin_utf8(&mut self, byte: u8) -> Vec<KeyAction> {
        // Determine the length from the high bits of the leading byte.
        let (remaining, acc) = if byte & 0xe0 == 0xc0 {
            (1u8, u32::from(byte & 0x1f))
        } else if byte & 0xf0 == 0xe0 {
            (2u8, u32::from(byte & 0x0f))
        } else if byte & 0xf8 == 0xf0 {
            (3u8, u32::from(byte & 0x07))
        } else {
            // Invalid leading byte -- ignore it.
            return Vec::new();
        };
        self.utf8_remaining = remaining;
        self.utf8_acc = acc;
        Vec::new()
    }

    fn feed_utf8_continuation(&mut self, byte: u8) -> Vec<KeyAction> {
        if byte & 0xc0 != 0x80 {
            // UTF-8 violation -- reset the accumulator.
            self.utf8_remaining = 0;
            return Vec::new();
        }
        self.utf8_acc = (self.utf8_acc << 6) | u32::from(byte & 0x3f);
        self.utf8_remaining -= 1;
        if self.utf8_remaining == 0 {
            if let Some(ch) = char::from_u32(self.utf8_acc) {
                return vec![KeyAction::Print(ch)];
            }
        }
        Vec::new()
    }
}

impl Default for KeystrokeParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{KeyAction, KeystrokeParser};

    fn run(bytes: &[u8]) -> Vec<KeyAction> {
        let mut p = KeystrokeParser::new();
        let mut out = Vec::new();
        for &b in bytes {
            out.extend(p.input(b));
        }
        out
    }

    #[test]
    fn printable_ascii_is_print() {
        assert_eq!(run(b"a"), vec![KeyAction::Print('a')]);
    }

    #[test]
    fn carriage_return_is_execute() {
        assert_eq!(run(b"\r"), vec![KeyAction::Execute('\r')]);
    }

    #[test]
    fn del_byte_is_print() {
        assert_eq!(run(&[0x7f]), vec![KeyAction::Print('\u{7f}')]);
    }

    #[test]
    fn arrow_right_is_csi_c() {
        // ESC [ C -- right arrow.
        assert_eq!(run(b"\x1b[C"), vec![KeyAction::Csi('C')]);
    }

    #[test]
    fn utf8_two_byte_is_single_print() {
        // U+00E9 (e-acute) in UTF-8 = 0xC3 0xA9 -- a single Print action.
        assert_eq!(run(&[0xc3, 0xa9]), vec![KeyAction::Print('\u{e9}')]);
    }

    #[test]
    fn lone_esc_letter_is_esc_dispatch() {
        // ESC followed by a printable char (not '[') -- an escape sequence.
        assert_eq!(run(b"\x1bM"), vec![KeyAction::Esc]);
    }

    #[test]
    fn interrupted_csi_restarts_at_the_latest_escape() {
        for bytes in [
            &b"\x1b[1;\x1b[C"[..],
            &b"\x1b[ \x1b[C"[..],
            &b"\x1b[\x1b\x1b[C"[..],
        ] {
            assert_eq!(run(bytes), vec![KeyAction::Csi('C')], "{bytes:?}");
        }
        assert_eq!(
            run(b"\x1b\x1b[Dtext"),
            vec![
                KeyAction::Csi('D'),
                KeyAction::Print('t'),
                KeyAction::Print('e'),
                KeyAction::Print('x'),
                KeyAction::Print('t'),
            ]
        );
    }

    #[test]
    fn every_valid_csi_final_including_h_remains_a_control() {
        for final_byte in 0x40..=0x7e {
            assert_eq!(
                run(&[0x1b, b'[', final_byte]),
                vec![KeyAction::Csi(final_byte as char)]
            );
        }
    }
}
