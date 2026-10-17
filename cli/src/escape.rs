//! The escape prefix (spec §8.3): `Ctrl-]` by default, `--escape ^X` to pick
//! another control key, `--escape none` for none at all. After the prefix
//! one key is a command; the prefix twice sends the prefix itself; any other
//! key is swallowed with it -- the whole key, even one the terminal sends as
//! an escape sequence (an arrow, `Alt-x`, a mouse report).

/// The escape byte every multi-byte key starts with.
const ESC: u8 = 0x1b;

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
#[derive(Clone, PartialEq, Eq, Debug)]
enum State {
    Plain,
    /// A prefix arrived and its key has not yet.
    Prefix,
    /// The key after the prefix is an escape sequence, and these are its
    /// bytes so far: they go nowhere, and neither does the rest of it.
    Swallowing(Vec<u8>),
}

pub struct Escape {
    prefix: Prefix,
    state: State,
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
        }
    }

    pub fn prefix(&self) -> Prefix {
        self.prefix
    }

    /// Splits keyboard bytes into plain input and commands, in order. A
    /// prefix at the end of `bytes`, or the start of a key sequence after
    /// it, waits for the next call.
    pub fn feed(&mut self, bytes: &[u8]) -> Vec<Piece> {
        let key = match self.prefix {
            Prefix::Key(k) => Some(k),
            Prefix::None => None,
        };
        let mut out = Vec::new();
        let mut plain = Vec::new();
        for &b in bytes {
            match std::mem::replace(&mut self.state, State::Plain) {
                State::Swallowing(mut seq) => {
                    seq.push(b);
                    match sequence_len(&seq) {
                        None => {
                            self.state = State::Swallowing(seq);
                            continue;
                        }
                        Some(len) if len == seq.len() => continue,
                        // `b` ended the sequence without being part of it:
                        // it is read afresh below.
                        Some(_) => {}
                    }
                }
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
                        flush(&mut out, &mut plain);
                        out.push(Piece::Command(command));
                    } else if Some(b) == key {
                        plain.push(b);
                    } else if b == ESC {
                        self.state = State::Swallowing(vec![b]);
                    }
                    // Any other key goes nowhere, and the prefix with it.
                    continue;
                }
                State::Plain => {}
            }
            if Some(b) == key {
                self.state = State::Prefix;
                continue;
            }
            plain.push(b);
        }
        flush(&mut out, &mut plain);
        out
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
    /// prefix: an arrow, an arrow with modifiers, a function key, `Alt-x`,
    /// an application-mode arrow and both forms of a mouse report.
    #[test]
    fn a_sequence_after_the_prefix_is_swallowed_whole() {
        let keys: [&[u8]; 7] = [
            b"\x1b[A",
            b"\x1b[1;5A",
            b"\x1b[15~",
            b"\x1bx",
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
}
