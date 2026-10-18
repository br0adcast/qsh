//! The escape prefix (spec §8.3): `Ctrl-]` by default, `--escape ^X` to pick
//! another control key, `--escape none` for none at all. After the prefix
//! one key is a command; the prefix twice sends the prefix itself; any other
//! key is swallowed with it. Esc cancels the prefix without consuming the
//! next ordinary key; CSI/SS3 keys and mouse reports are swallowed whole.
//! Bracketed paste is literal input, never a source of local commands.

/// The escape byte every multi-byte key starts with.
const ESC: u8 = 0x1b;
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Prefix {
    Key(u8),
    None,
}

/// `Ctrl-]`: typed the same way on every keyboard layout that matters, and
/// without Shift on a Mac, unlike `Ctrl-^`.
pub const DEFAULT_PREFIX: Prefix = Prefix::Key(0x1d);

pub fn parse_prefix(spec: &str) -> Result<Prefix, String> {
    if spec == "none" {
        return Ok(Prefix::None);
    }
    let b = spec.as_bytes();
    if b.len() == 2 && b[0] == b'^' {
        let c = b[1].to_ascii_uppercase();
        if (b'@'..=b'_').contains(&c) {
            return Ok(Prefix::Key(c & 0x1f));
        }
    }
    Err("expected ^X (from ^@ to ^_) or none".into())
}

impl Prefix {
    /// How a person names it, or `None` when there is no prefix.
    pub fn name(self) -> Option<String> {
        match self {
            Prefix::None => None,
            Prefix::Key(k) => Some(format!("Ctrl-{}", (k | 0x40) as char)),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Command {
    /// `.`: leave; the session stays on the server.
    Leave,
    /// `s`: the connection-state window.
    Window,
    /// `h`: hide or show the status line.
    ToggleLine,
    /// `r`: reconnect now.
    Reconnect,
    /// `?`: the key help.
    Help,
    /// `[`: browse the client's history.
    Scroll,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Piece {
    Input(Vec<u8>),
    Command(Command),
}

/// How far `Escape` is into a prefix command.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum State {
    Plain,
    /// A prefix arrived and its key has not yet.
    Prefix,
    /// Esc cancelled the prefix; only an explicit CSI/SS3 continuation is
    /// still part of that key. Ordinary input must not be eaten as Alt.
    Escape,
    CsiStart,
    CsiParameters,
    CsiIntermediates,
    Ss3,
    X10(u8),
}

pub struct Escape {
    prefix: Prefix,
    state: State,
    in_paste: bool,
    /// Length of a matched start/end marker prefix; never a growing buffer.
    marker_len: usize,
    /// A possible start intercepted by local-command state is replayed if
    /// disproved. Otherwise its bytes go out immediately as ordinary input.
    marker_held: bool,
}

/// The length of the key sequence at the start of `bytes`, which starts with
/// `ESC`, or `None` when `bytes` ends before it does:
///   * `ESC [`, parameters (`0x30`-`0x3F`), intermediates (`0x20`-`0x2F`)
///     and one final byte (`0x40`-`0x7E`) -- an arrow with modifiers, a
///     function key, an SGR mouse report; `ESC [ M` and the three bytes an
///     X10 mouse report carries after it;
///   * `ESC O` and one byte -- an arrow or a keypad key in application mode;
///   * `ESC` and any other byte -- a key with `Alt`.
///
/// A byte that fits no place in a `ESC [` sequence ends it before itself:
/// it is not part of the key.
pub fn sequence_len(bytes: &[u8]) -> Option<usize> {
    debug_assert_eq!(bytes.first(), Some(&ESC));
    match *bytes.get(1)? {
        b'[' => {
            if bytes.get(2) == Some(&b'M') {
                return (bytes.len() >= 6).then_some(6);
            }
            let mut i = 2;
            while bytes.get(i).is_some_and(|b| (0x30..=0x3f).contains(b)) {
                i += 1;
            }
            while bytes.get(i).is_some_and(|b| (0x20..=0x2f).contains(b)) {
                i += 1;
            }
            match *bytes.get(i)? {
                0x40..=0x7e => Some(i + 1),
                _ => Some(i),
            }
        }
        b'O' => bytes.get(2).map(|_| 3),
        _ => Some(2),
    }
}

impl Escape {
    pub fn new(prefix: Prefix) -> Escape {
        Escape {
            prefix,
            state: State::Plain,
            in_paste: false,
            marker_len: 0,
            marker_held: false,
        }
    }

    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// Splits keyboard bytes into plain input and commands, in order. A
    /// prefix at the end of `bytes`, or the start of a key sequence after
    /// it, waits for the next call. Paste framing is followed across calls
    /// before interpreting local keys. With ESC as the configured prefix,
    /// ESC [ is ambiguous with a paste start: history waits for the next
    /// byte to disprove that marker, independent of read boundaries.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Piece> {
        let mut out = Vec::new();
        let mut plain = Vec::new();
        for &b in bytes {
            if self.in_paste {
                plain.push(b);
                self.marker_len = if b == PASTE_END[self.marker_len] {
                    self.marker_len + 1
                } else {
                    usize::from(b == ESC)
                };
                if self.marker_len == PASTE_END.len() {
                    self.in_paste = false;
                    self.marker_len = 0;
                }
                continue;
            }
            if self.marker_len > 0 {
                if b == PASTE_START[self.marker_len] {
                    if !self.marker_held {
                        plain.push(b);
                    }
                    self.marker_len += 1;
                    if self.marker_len == PASTE_START.len() {
                        if self.marker_held {
                            plain.extend_from_slice(PASTE_START);
                        }
                        self.state = State::Plain;
                        self.in_paste = true;
                        self.marker_len = 0;
                    }
                    continue;
                }
                let matched = std::mem::take(&mut self.marker_len);
                if self.marker_held {
                    for &held in &PASTE_START[..matched] {
                        self.key_byte(held, &mut out, &mut plain);
                    }
                }
                // The mismatch may itself begin a new marker or command.
            }
            if b == ESC && !(self.prefix == Prefix::Key(ESC) && self.state == State::Prefix) {
                self.marker_len = 1;
                self.marker_held = self.state != State::Plain || self.prefix == Prefix::Key(ESC);
                if !self.marker_held {
                    plain.push(b);
                }
                continue;
            }
            self.key_byte(b, &mut out, &mut plain);
            if b == ESC {
                // A doubled ESC prefix already sent one literal ESC. It
                // can also be the first byte of a paste following the
                // pending prefix; observe it without sending it twice.
                self.marker_len = 1;
                self.marker_held = false;
            }
        }
        flush(&mut out, &mut plain);
        out
    }

    /// Consumes one non-paste byte, with fixed-size state for discarded
    /// sequences. Invalid/cancelling bytes fall through exactly once.
    fn key_byte(&mut self, b: u8, out: &mut Vec<Piece>, plain: &mut Vec<u8>) {
        let Prefix::Key(key) = self.prefix else {
            plain.push(b);
            return;
        };
        let state = std::mem::replace(&mut self.state, State::Plain);
        match state {
            State::Prefix => {
                let command = match b {
                    b'.' => Some(Command::Leave),
                    b's' => Some(Command::Window),
                    b'h' => Some(Command::ToggleLine),
                    b'r' => Some(Command::Reconnect),
                    b'?' => Some(Command::Help),
                    b'[' => Some(Command::Scroll),
                    _ => None,
                };
                if let Some(command) = command {
                    flush(out, plain);
                    out.push(Piece::Command(command));
                } else if b == key {
                    plain.push(b);
                } else if b == ESC {
                    self.state = State::Escape;
                }
                return;
            }
            State::Escape if b == b'[' || b == b'O' => {
                self.state = if b == b'[' {
                    State::CsiStart
                } else {
                    State::Ss3
                };
                return;
            }
            State::CsiStart | State::CsiParameters | State::CsiIntermediates => {
                self.state = match b {
                    b'M' if state == State::CsiStart => State::X10(3),
                    0x30..=0x3f if state != State::CsiIntermediates => State::CsiParameters,
                    0x20..=0x2f => State::CsiIntermediates,
                    0x40..=0x7e => return,
                    _ => State::Plain,
                };
                if self.state != State::Plain {
                    return;
                }
            }
            State::Ss3 if (0x40..=0x7e).contains(&b) => return,
            State::X10(left) if b >= 0x20 => {
                if left > 1 {
                    self.state = State::X10(left - 1);
                }
                return;
            }
            _ => {}
        }
        if b == key {
            self.state = State::Prefix;
        } else {
            plain.push(b);
        }
    }
}

fn flush(out: &mut Vec<Piece>, plain: &mut Vec<u8>) {
    if !plain.is_empty() {
        out.push(Piece::Input(std::mem::take(plain)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P: u8 = 0x1d;

    #[test]
    fn the_prefix_is_read_like_a_control_key() {
        assert_eq!(parse_prefix("^]"), Ok(Prefix::Key(0x1d)));
        assert_eq!(parse_prefix("^a"), Ok(Prefix::Key(0x01)));
        assert_eq!(parse_prefix("^@"), Ok(Prefix::Key(0x00)));
        assert_eq!(parse_prefix("^_"), Ok(Prefix::Key(0x1f)));
        assert_eq!(parse_prefix("none"), Ok(Prefix::None));
        for bad in ["", "^", "]", "^]]", "^`", "ctrl-]", "^1"] {
            assert!(parse_prefix(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_prefix_has_a_human_name() {
        assert_eq!(Prefix::Key(0x1d).name().as_deref(), Some("Ctrl-]"));
        assert_eq!(Prefix::Key(0x00).name().as_deref(), Some("Ctrl-@"));
        assert_eq!(Prefix::None.name(), None);
        assert_eq!(DEFAULT_PREFIX, Prefix::Key(0x1d));
    }

    #[test]
    fn commands_follow_the_prefix() {
        let mut e = Escape::new(Prefix::Key(P));
        assert_eq!(
            e.feed(&[b'a', P, b'.', b'b', P, b's', P, b'h', P, b'r', P, b'?']),
            vec![
                Piece::Input(b"a".to_vec()),
                Piece::Command(Command::Leave),
                Piece::Input(b"b".to_vec()),
                Piece::Command(Command::Window),
                Piece::Command(Command::ToggleLine),
                Piece::Command(Command::Reconnect),
                Piece::Command(Command::Help),
            ]
        );
    }

    #[test]
    fn the_prefix_twice_sends_one_and_waits_for_nothing() {
        let mut e = Escape::new(Prefix::Key(P));
        assert_eq!(e.feed(&[P, P, b'.']), vec![Piece::Input(vec![P, b'.'])]);
    }

    #[test]
    fn any_other_key_is_swallowed_with_the_prefix() {
        let mut e = Escape::new(Prefix::Key(P));
        assert_eq!(
            e.feed(&[b'x', P, b'z', b'y']),
            vec![Piece::Input(b"xy".to_vec())]
        );
    }

    #[test]
    fn the_prefix_waits_across_reads() {
        let mut e = Escape::new(Prefix::Key(P));
        assert_eq!(e.feed(&[b'l', P]), vec![Piece::Input(b"l".to_vec())]);
        assert_eq!(e.feed(b"."), vec![Piece::Command(Command::Leave)]);
    }

    /// A key the terminal sends as a sequence is swallowed whole after the
    /// prefix: an arrow, an arrow with modifiers, a function key,
    /// an application-mode arrow and both forms of a mouse report.
    #[test]
    fn a_sequence_after_the_prefix_is_swallowed_whole() {
        let keys: [&[u8]; 6] = [
            b"\x1b[A",
            b"\x1b[1;5A",
            b"\x1b[15~",
            b"\x1bOA",
            b"\x1b[<0;10;5M",
            &[0x1b, b'[', b'M', 32, 40, 38],
        ];
        for key in keys {
            let mut e = Escape::new(Prefix::Key(P));
            let mut bytes = vec![b'a', P];
            bytes.extend_from_slice(key);
            bytes.push(b'b');
            assert_eq!(
                e.feed(&bytes),
                vec![Piece::Input(b"ab".to_vec())],
                "{key:?}"
            );
        }
    }

    /// Split by a read at any place, the sequence is still swallowed whole,
    /// and what follows it is input again.
    #[test]
    fn a_sequence_after_the_prefix_is_swallowed_across_reads() {
        let key = b"\x1b[1;5A";
        for cut in 0..=key.len() {
            let mut e = Escape::new(Prefix::Key(P));
            let mut first = vec![P];
            first.extend_from_slice(&key[..cut]);
            let mut second = key[cut..].to_vec();
            second.push(b'z');
            let mut pieces = e.feed(&first);
            pieces.extend(e.feed(&second));
            assert_eq!(pieces, vec![Piece::Input(b"z".to_vec())], "cut at {cut}");
        }
    }

    /// A byte that cannot be part of the sequence ends it and is read as
    /// what it is: here the prefix, starting a command.
    #[test]
    fn a_broken_sequence_after_the_prefix_ends_at_the_byte_that_breaks_it() {
        let mut e = Escape::new(Prefix::Key(P));
        assert_eq!(
            e.feed(&[P, 0x1b, b'[', b'1', P, b'.']),
            vec![Piece::Command(Command::Leave)]
        );
    }

    #[test]
    fn sequence_lengths() {
        assert_eq!(sequence_len(b"\x1b[A"), Some(3));
        assert_eq!(sequence_len(b"\x1b[1;5Ax"), Some(6));
        assert_eq!(sequence_len(b"\x1b[15~"), Some(5));
        assert_eq!(sequence_len(b"\x1b[ q"), Some(4), "an intermediate");
        assert_eq!(sequence_len(b"\x1bOBx"), Some(3));
        assert_eq!(sequence_len(b"\x1bxy"), Some(2));
        assert_eq!(sequence_len(&[0x1b, b'[', b'M', 32, 40, 38, 1]), Some(6));
        assert_eq!(sequence_len(b"\x1b[1\r"), Some(3), "CR is not part of it");
        for cut in [&b"\x1b"[..], b"\x1b[", b"\x1b[1;5", b"\x1bO", b"\x1b[M ("] {
            assert_eq!(sequence_len(cut), None, "{cut:?}");
        }
    }

    #[test]
    fn without_a_prefix_everything_is_input() {
        let mut e = Escape::new(Prefix::None);
        assert_eq!(e.feed(&[P, b'.']), vec![Piece::Input(vec![P, b'.'])]);
    }

    #[test]
    fn esc_after_prefix_preserves_the_next_ordinary_key() {
        for next in *b"x.s" {
            let bytes = [P, ESC, next];
            for cut in 0..=bytes.len() {
                let mut escape = Escape::new(DEFAULT_PREFIX);
                let mut pieces = escape.feed(&bytes[..cut]);
                pieces.extend(escape.feed(&bytes[cut..]));
                assert_eq!(pieces, vec![Piece::Input(vec![next])], "cut {cut}");
            }
        }
    }

    #[test]
    fn bracketed_paste_preserves_local_command_bytes_across_reads() {
        let bytes = b"\x1b[200~\x1d.\x1ds\x1dh\x1dr\x1d?\x1d[\x1d\x1d\x1b[201~";
        for cut in 0..=bytes.len() {
            let mut escape = Escape::new(DEFAULT_PREFIX);
            let mut pieces = escape.feed(&bytes[..cut]);
            pieces.extend(escape.feed(&bytes[cut..]));
            let mut input = Vec::new();
            for piece in pieces {
                match piece {
                    Piece::Input(bytes) => input.extend(bytes),
                    Piece::Command(command) => panic!("pasted command at cut {cut}: {command:?}"),
                }
            }
            assert_eq!(input, bytes, "cut {cut}");
        }
    }

    fn joined(pieces: impl IntoIterator<Item = Piece>) -> Vec<Piece> {
        let mut out = Vec::new();
        for piece in pieces {
            if let Piece::Input(bytes) = &piece {
                if let Some(Piece::Input(previous)) = out.last_mut() {
                    previous.extend(bytes);
                    continue;
                }
            }
            out.push(piece);
        }
        out
    }

    fn across_reads(prefix: Prefix, bytes: &[u8], expected: &[Piece]) {
        for cut in 0..=bytes.len() {
            let mut escape = Escape::new(prefix);
            let mut pieces = escape.feed(&bytes[..cut]);
            pieces.extend(escape.feed(&bytes[cut..]));
            assert_eq!(joined(pieces), expected, "cut {cut}, prefix {prefix:?}");
        }
        let mut escape = Escape::new(prefix);
        let pieces = bytes.iter().flat_map(|b| escape.feed(&[*b]));
        assert_eq!(joined(pieces), expected, "one byte per read, {prefix:?}");
    }

    #[test]
    fn paste_is_literal_for_every_prefix_and_commands_resume_after_its_end() {
        for key in [P, 0x00, 0x02, ESC, 0x0d] {
            let mut paste = b"\x1b[200~".to_vec();
            for command in b".shr?[" {
                paste.extend([key, *command]);
            }
            paste.extend([key, key]);
            paste.extend_from_slice(b"\x1b[201~");
            let mut bytes = paste.clone();
            bytes.extend([key, b'.']);
            across_reads(
                Prefix::Key(key),
                &bytes,
                &[Piece::Input(paste), Piece::Command(Command::Leave)],
            );
            across_reads(Prefix::None, &bytes, &[Piece::Input(bytes.clone())]);
        }
    }

    #[test]
    fn paste_cancels_a_pending_prefix_without_losing_its_start_marker() {
        for key in [P, 0x02, ESC] {
            let mut paste = b"\x1b[200~".to_vec();
            paste.extend([key, b'.']);
            paste.extend_from_slice(b"\x1b[201~");
            let mut bytes = vec![key];
            bytes.extend(&paste);
            bytes.extend([key, b'?']);
            across_reads(
                Prefix::Key(key),
                &bytes,
                &[Piece::Input(paste), Piece::Command(Command::Help)],
            );
        }
    }

    #[test]
    fn incomplete_and_false_paste_ends_keep_prefixes_literal() {
        let bytes = b"\x1b[200~\x1b[20\x1d.\x18\x1a\x1b[201x\x1dr\x1b[200~\x1d?\x1b\x1b[201~";
        across_reads(DEFAULT_PREFIX, bytes, &[Piece::Input(bytes.to_vec())]);
        let mut escape = Escape::new(DEFAULT_PREFIX);
        assert_eq!(
            escape.feed(b"\x1b[200~text\x1b[20"),
            vec![Piece::Input(b"\x1b[200~text\x1b[20".to_vec())]
        );
        assert_eq!(escape.feed(&[P, b'.']), vec![Piece::Input(vec![P, b'.'])]);
    }

    #[test]
    fn invalid_swallowed_sequences_dispatch_the_breaking_byte_once() {
        for sequence in [&b"\x1b[12"[..], b"\x1b[ ", b"\x1bO", b"\x1b[M "] {
            for cancel in [0x18, 0x1a, b'\r'] {
                let mut bytes = vec![P];
                bytes.extend(sequence);
                bytes.extend([cancel, b'x', P, b'.']);
                across_reads(
                    DEFAULT_PREFIX,
                    &bytes,
                    &[
                        Piece::Input(vec![cancel, b'x']),
                        Piece::Command(Command::Leave),
                    ],
                );
            }
        }
        across_reads(
            DEFAULT_PREFIX,
            b"\x1d\x1b[1\x1bx",
            &[Piece::Input(b"\x1bx".to_vec())],
        );
    }

    #[test]
    fn plain_escape_is_prompt_and_false_paste_starts_preserve_input() {
        let mut escape = Escape::new(DEFAULT_PREFIX);
        assert_eq!(escape.feed(&[ESC]), vec![Piece::Input(vec![ESC])]);
        for bytes in [&b"\x1b[20x\x1d."[..], b"\x1b\x1b[20x\x1d."] {
            across_reads(
                DEFAULT_PREFIX,
                bytes,
                &[
                    Piece::Input(bytes[..bytes.len() - 2].to_vec()),
                    Piece::Command(Command::Leave),
                ],
            );
        }
    }

    #[test]
    fn escape_prefix_history_waits_for_paste_disambiguation() {
        let mut escape = Escape::new(Prefix::Key(ESC));
        assert!(escape.feed(b"\x1b[").is_empty());
        assert_eq!(
            escape.feed(b"x"),
            vec![Piece::Command(Command::Scroll), Piece::Input(b"x".to_vec())]
        );
        assert_eq!(escape.feed(b"\x1b\x1b"), vec![Piece::Input(vec![ESC])]);
        across_reads(
            Prefix::Key(ESC),
            b"\x1bs\x1bh\x1br\x1b?\x1b.",
            &[
                Piece::Command(Command::Window),
                Piece::Command(Command::ToggleLine),
                Piece::Command(Command::Reconnect),
                Piece::Command(Command::Help),
                Piece::Command(Command::Leave),
            ],
        );
    }
}
