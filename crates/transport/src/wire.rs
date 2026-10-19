//! Datagram wire framing and the anti-replay window (sans-IO).
//!
//! The module does no I/O: it only encodes/parses datagram bytes and decides
//! whether to accept the next transport counter, without letting replays
//! through. Delivering bytes over the network is the caller's job.
//!
//! Wire header layout: `version(1) | kind(1)`, and for `Kind::Transport` it's
//! followed by `session_id(8, big-endian) | counter(8, big-endian) | aead`.
//! The first 18 bytes (version, kind, session_id, counter) are the AEAD's
//! associated data when the connection negotiated `header-aad`
//! (`crate::features`); otherwise the associated data is empty.

use std::fmt;

/// Datagram kind in the header (second byte).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    HandshakeInit = 0x00,
    HandshakeResp = 0x01,
    Transport = 0x02,
    /// A client asking an unknown server for its static public key, so it can
    /// start a Noise IK handshake (which needs that key up front). Carries no
    /// secret and is not authenticated -- see `encode_key_request`.
    KeyRequest = 0x03,
    /// The server's answer to `KeyRequest`: its static public key.
    KeyOffer = 0x04,
    /// A daemon's answer to a msg1 while it is under load (spec §4.16): a
    /// cookie to send that msg1 again behind -- proof that the sender
    /// receives at the address it names. Smaller than the request it
    /// answers. See `crate::cookie`.
    CookieReply = 0x05,
    /// msg1 again, behind the cookie a `CookieReply` handed out:
    /// `cookie(16) | Noise msg1`. Sent only to a daemon that sent one.
    HandshakeInitCookie = 0x06,
}

/// Wire format version, fixed for the whole project.
pub const VERSION: u8 = 0x02;

/// Length of the transport datagram header: version(1) + kind(1) +
/// session_id(8) + counter(8). The associated data of the AEAD when
/// `header-aad` is negotiated (spec §4.9).
pub const TRANSPORT_HEADER_LEN: usize = 18;

/// The Poly1305 tag every sealed payload ends with.
pub const AEAD_TAG_LEN: usize = 16;

/// The largest transport datagram a sender builds (spec §3.2, §4.11):
/// QUIC's minimum, which IPv6's 1280-byte floor and ordinary tunnels carry
/// whole. A full DATA segment (1066 bytes on the wire) fits with room to
/// spare.
pub const MAX_DATAGRAM: usize = 1200;

/// What a transport datagram of `MAX_DATAGRAM` bytes holds in the clear.
pub const MAX_PLAINTEXT: usize = MAX_DATAGRAM - TRANSPORT_HEADER_LEN - AEAD_TAG_LEN;

const _: () = assert!(MAX_PLAINTEXT == 1166);

/// A datagram parse error. The input comes from the network and is
/// untrusted, so `parse` returns a `Result` rather than panicking.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WireError {
    /// The datagram is shorter than the minimum allowed length for its kind.
    TooShort,
    /// The header's first byte doesn't match the supported version.
    BadVersion,
    /// The header's second byte doesn't match any known `Kind`.
    BadKind,
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            WireError::TooShort => "datagram is shorter than the expected header",
            WireError::BadVersion => "unsupported wire format version",
            WireError::BadKind => "unknown datagram kind",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for WireError {}

/// A parsed datagram.
#[derive(Debug, PartialEq, Eq)]
pub enum Frame<'a> {
    /// A handshake message: the body is everything after the first two bytes.
    Handshake { kind: Kind, body: &'a [u8] },
    /// A transport message: `aead` is the encrypted payload with the AEAD
    /// tag, `aad` is the first 18 header bytes -- the AEAD's associated data
    /// when the connection negotiated `header-aad`.
    Transport {
        session_id: u64,
        counter: u64,
        aead: &'a [u8],
        aad: &'a [u8; TRANSPORT_HEADER_LEN],
    },
}

/// The 18-byte header of a transport datagram: `version | kind | session_id
/// (8, BE) | counter (8, BE)`. What the datagram carries in the clear, and
/// -- when the connection negotiated `header-aad` -- the AEAD's associated
/// data.
pub fn transport_header(session_id: u64, counter: u64) -> [u8; TRANSPORT_HEADER_LEN] {
    let mut header = [0u8; TRANSPORT_HEADER_LEN];
    header[0] = VERSION;
    header[1] = Kind::Transport as u8;
    header[2..10].copy_from_slice(&session_id.to_be_bytes());
    header[10..18].copy_from_slice(&counter.to_be_bytes());
    header
}

/// Assemble a transport datagram: `header` ([`transport_header`]) + an
/// already-encrypted payload with the AEAD tag. The sender passes the very
/// header it sealed under, so the header sent is the one authenticated.
pub fn encode_transport(header: &[u8; TRANSPORT_HEADER_LEN], aead: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSPORT_HEADER_LEN + aead.len());
    out.extend_from_slice(header);
    out.extend_from_slice(aead);
    out
}

/// Assemble a handshake datagram: `version | kind | body`.
pub fn encode_handshake(kind: Kind, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + body.len());
    out.push(VERSION);
    out.push(kind as u8);
    out.extend_from_slice(body);
    out
}

/// Minimum size of a discovery request datagram. The reply is 35 bytes
/// (2 header + version + 32-byte key); padding the request past that keeps the
/// amplification factor at or below one, so this endpoint cannot be used to
/// bounce traffic at a spoofed victim.
pub const KEY_REQUEST_MIN_LEN: usize = 64;

/// Build a discovery request: a version byte plus padding to
/// [`KEY_REQUEST_MIN_LEN`].
pub fn encode_key_request() -> Vec<u8> {
    let mut out = encode_handshake(Kind::KeyRequest, &[VERSION]);
    out.resize(KEY_REQUEST_MIN_LEN, 0);
    out
}

/// Read a server's static public key out of a `KeyOffer` body, or `None` if
/// the body is malformed.
pub fn parse_key_offer(body: &[u8]) -> Option<[u8; 32]> {
    if body.len() < 33 || body[0] != VERSION {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&body[1..33]);
    Some(key)
}

/// Build the body of a `KeyOffer` for `server_pub`.
pub fn encode_key_offer_body(server_pub: &[u8; 32]) -> Vec<u8> {
    let mut body = Vec::with_capacity(33);
    body.push(VERSION);
    body.extend_from_slice(server_pub);
    body
}

/// Length of a return-address cookie (spec §4.16): a BLAKE2s-128 MAC.
pub const COOKIE_LEN: usize = 16;

/// How much of the msg1's ephemeral key a `CookieReply` echoes: what tells
/// the client the reply answers ITS msg1, so no one off the path can make
/// it send a cookie retry.
pub const COOKIE_ECHO_LEN: usize = 16;

/// The version byte of a `CookieReply` body.
pub const COOKIE_VERSION: u8 = 0x01;

/// A whole `CookieReply` datagram: header, version, echo, cookie.
pub const COOKIE_REPLY_LEN: usize = 2 + 1 + COOKIE_ECHO_LEN + COOKIE_LEN;

/// The smallest Noise IK msg1 body: the ephemeral key (32), the encrypted
/// static key (32 + 16), an empty payload's tag (16). A handshake datagram
/// shorter than this cannot be a msg1 and is not answered at all.
pub const MIN_MSG1_BODY: usize = 96;

// An answer never outweighs the smallest request it answers (spec §4.16).
const _: () = assert!(COOKIE_REPLY_LEN <= 2 + MIN_MSG1_BODY);

/// A `CookieReply` datagram: `0x01 | 0x05 | COOKIE_VERSION | echo | cookie`.
pub fn encode_cookie_reply(echo: &[u8; COOKIE_ECHO_LEN], cookie: &[u8; COOKIE_LEN]) -> Vec<u8> {
    let mut body = Vec::with_capacity(1 + COOKIE_ECHO_LEN + COOKIE_LEN);
    body.push(COOKIE_VERSION);
    body.extend_from_slice(echo);
    body.extend_from_slice(cookie);
    encode_handshake(Kind::CookieReply, &body)
}

/// The echo and the cookie of a `CookieReply` body, or `None` for one of
/// another length (the reply is fixed-size) or another version.
pub fn parse_cookie_reply(body: &[u8]) -> Option<([u8; COOKIE_ECHO_LEN], [u8; COOKIE_LEN])> {
    if body.len() != 1 + COOKIE_ECHO_LEN + COOKIE_LEN || body[0] != COOKIE_VERSION {
        return None;
    }
    let mut echo = [0u8; COOKIE_ECHO_LEN];
    echo.copy_from_slice(&body[1..1 + COOKIE_ECHO_LEN]);
    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&body[1 + COOKIE_ECHO_LEN..1 + COOKIE_ECHO_LEN + COOKIE_LEN]);
    Some((echo, cookie))
}

/// A `HandshakeInitCookie` datagram: msg1 behind its cookie.
pub fn encode_handshake_init_cookie(cookie: &[u8; COOKIE_LEN], msg1: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(COOKIE_LEN + msg1.len());
    body.extend_from_slice(cookie);
    body.extend_from_slice(msg1);
    encode_handshake(Kind::HandshakeInitCookie, &body)
}

/// The cookie and the msg1 of a `HandshakeInitCookie` body, or `None` for
/// one too short to hold a cookie.
pub fn split_cookie_init(body: &[u8]) -> Option<([u8; COOKIE_LEN], &[u8])> {
    if body.len() < COOKIE_LEN {
        return None;
    }
    let mut cookie = [0u8; COOKIE_LEN];
    cookie.copy_from_slice(&body[..COOKIE_LEN]);
    Some((cookie, &body[COOKIE_LEN..]))
}

/// Parse a datagram received from the network. Checks length and version
/// before reading fields; returns a `WireError` on malformed input rather
/// than panicking.
pub fn parse(bytes: &[u8]) -> Result<Frame<'_>, WireError> {
    if bytes.len() < 2 {
        return Err(WireError::TooShort);
    }
    if bytes[0] != VERSION {
        return Err(WireError::BadVersion);
    }
    match bytes[1] {
        x if x == Kind::HandshakeInit as u8 => Ok(Frame::Handshake {
            kind: Kind::HandshakeInit,
            body: &bytes[2..],
        }),
        x if x == Kind::HandshakeResp as u8 => Ok(Frame::Handshake {
            kind: Kind::HandshakeResp,
            body: &bytes[2..],
        }),
        x if x == Kind::KeyRequest as u8 => Ok(Frame::Handshake {
            kind: Kind::KeyRequest,
            body: &bytes[2..],
        }),
        x if x == Kind::KeyOffer as u8 => Ok(Frame::Handshake {
            kind: Kind::KeyOffer,
            body: &bytes[2..],
        }),
        x if x == Kind::CookieReply as u8 => Ok(Frame::Handshake {
            kind: Kind::CookieReply,
            body: &bytes[2..],
        }),
        x if x == Kind::HandshakeInitCookie as u8 => Ok(Frame::Handshake {
            kind: Kind::HandshakeInitCookie,
            body: &bytes[2..],
        }),
        x if x == Kind::Transport as u8 => {
            let Some((aad, aead)) = bytes.split_first_chunk::<TRANSPORT_HEADER_LEN>() else {
                return Err(WireError::TooShort);
            };
            let session_id = u64::from_be_bytes(aad[2..10].try_into().unwrap());
            let counter = u64::from_be_bytes(aad[10..18].try_into().unwrap());
            Ok(Frame::Transport {
                session_id,
                counter,
                aead,
                aad,
            })
        }
        _ => Err(WireError::BadKind),
    }
}

/// Words in the anti-replay bitmap. A power of two, so a counter's word is
/// its high bits masked (RFC 6479).
const REPLAY_WORDS: usize = 512;

/// Bits in the bitmap: 32 768, 4 KiB per connection.
const REPLAY_WINDOW_BITS: u64 = REPLAY_WORDS as u64 * 64;

/// How far behind the maximum a counter may be and still be accepted: one
/// word of the bitmap is held in reserve, as RFC 6479 does, so the window in
/// effect is 32 704 positions. Sized for the difference of two roads' round
/// trips (at most the 3 s `rto` ceiling) at about 10 900 datagrams/s -- see
/// `docs/protocol.md` §1.3.
pub const REPLAY_WINDOW: u64 = REPLAY_WINDOW_BITS - 64;

/// A sliding anti-replay window over a strictly increasing transport
/// counter: the highest accepted counter and a ring of `REPLAY_WORDS` 64-bit
/// words, one bit per counter (RFC 6479). Moving the maximum forward zeroes
/// whole words and never shifts bits.
///
/// `accept` contract: a replay (an already-seen counter) is rejected; a new
/// counter at most `REPLAY_WINDOW` behind the maximum, or ahead of it, is
/// accepted; anything further behind is rejected as too old.
pub struct ReplayWindow {
    max: u64,
    words: Box<[u64]>,
    seen_any: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow {
            max: 0,
            words: vec![0u64; REPLAY_WORDS].into_boxed_slice(),
            seen_any: false,
        }
    }
}

impl ReplayWindow {
    /// Whether this counter would become the window's new maximum: it beats
    /// the current maximum, or the window is still empty. Mutates nothing --
    /// must be checked BEFORE `accept`, which moves the window. Used as the
    /// address-migration condition: the peer only migrates on a packet with
    /// a new maximum, not on any fresh-in-window packet (a late packet from
    /// a dead address must not roll it back).
    pub fn is_new_max(&self, counter: u64) -> bool {
        !self.seen_any || counter > self.max
    }

    /// Check and record the next counter. Returns `true` if the datagram
    /// should be accepted, `false` if it's a replay or too old relative to
    /// the already-accepted maximum.
    pub fn accept(&mut self, counter: u64) -> bool {
        if !self.seen_any {
            self.seen_any = true;
            self.max = counter;
            self.words.fill(0);
            self.mark(counter);
            return true;
        }
        if counter > self.max {
            // Zero every word between the old maximum's and the new one's --
            // all of them at most, when the jump is past the whole bitmap.
            let from = self.max >> 6;
            let to = counter >> 6;
            let clear = (to - from).min(REPLAY_WORDS as u64);
            for i in 1..=clear {
                self.words[Self::slot(from + i)] = 0;
            }
            self.max = counter;
            self.mark(counter);
            return true;
        }
        if self.max - counter > REPLAY_WINDOW {
            return false; // too old
        }
        let (word, bit) = (Self::word(counter), Self::bit(counter));
        if self.words[word] & bit != 0 {
            return false; // already seen -- the maximum itself included
        }
        self.words[word] |= bit;
        true
    }

    /// The ring word holding `counter`'s bit.
    fn word(counter: u64) -> usize {
        Self::slot(counter >> 6)
    }

    /// Where the 64-counter word numbered `word_number` lives in the ring.
    fn slot(word_number: u64) -> usize {
        (word_number as usize) & (REPLAY_WORDS - 1)
    }

    fn bit(counter: u64) -> u64 {
        1u64 << (counter & 63)
    }

    fn mark(&mut self, counter: u64) {
        let word = Self::word(counter);
        self.words[word] |= Self::bit(counter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_roundtrip_header() {
        let dg = encode_transport(&transport_header(0xABCD, 5), &[9, 9, 9]);
        assert_eq!(dg[0], 0x02); // protocol 2
        assert_eq!(dg[1], 0x02); // kind=Transport
        match parse(&dg).unwrap() {
            Frame::Transport {
                session_id,
                counter,
                aead,
                aad,
            } => {
                assert_eq!(session_id, 0xABCD);
                assert_eq!(counter, 5);
                assert_eq!(aead, vec![9, 9, 9]);
                assert_eq!(aad, &dg[0..18]);
            }
            _ => panic!("expected Transport"),
        }
    }

    /// The header a sender seals under is the header the datagram carries
    /// and the one `parse` hands the receiver.
    #[test]
    fn the_transport_header_is_the_first_18_bytes_on_the_wire() {
        let header = transport_header(0xABCD, 5);
        let dg = encode_transport(&header, &[9, 9, 9]);
        assert_eq!(header[..], dg[..TRANSPORT_HEADER_LEN]);
        match parse(&dg).unwrap() {
            Frame::Transport { aad, .. } => assert_eq!(aad, &header),
            _ => panic!("expected Transport"),
        }
    }

    #[test]
    fn rejects_bad_version_and_short() {
        assert!(parse(&[0x99, 0x02]).is_err());
        assert!(parse(&[0x01]).is_err());
    }

    /// A transport datagram needs its whole 18-byte header; the payload may
    /// be empty (the tag check refuses it later).
    #[test]
    fn a_transport_datagram_shorter_than_its_header_is_refused() {
        let header = transport_header(0xABCD, 5);
        for len in 2..TRANSPORT_HEADER_LEN {
            assert_eq!(
                parse(&header[..len]),
                Err(WireError::TooShort),
                "{len} bytes"
            );
        }
        match parse(&header).unwrap() {
            Frame::Transport { aad, aead, .. } => {
                assert_eq!(aad, &header);
                assert!(aead.is_empty());
            }
            _ => panic!("expected Transport"),
        }
    }

    /// A discovery request must be at least as big as the answer it draws, or
    /// the server becomes an amplifier: a spoofed source address would get a
    /// bigger reply than the attacker paid for.
    #[test]
    fn a_discovery_request_is_padded_to_the_size_of_its_answer() {
        let req = encode_key_request();
        assert!(req.len() >= KEY_REQUEST_MIN_LEN);
        let offer = encode_handshake(Kind::KeyOffer, &{
            let mut body = vec![VERSION];
            body.extend_from_slice(&[7u8; 32]);
            body
        });
        assert!(
            req.len() >= offer.len(),
            "request {} must not be smaller than reply {}",
            req.len(),
            offer.len()
        );
    }

    #[test]
    fn a_key_offer_round_trips() {
        let mut body = vec![VERSION];
        body.extend_from_slice(&[5u8; 32]);
        let dgram = encode_handshake(Kind::KeyOffer, &body);
        match parse(&dgram).expect("valid frame") {
            Frame::Handshake { kind, body } => {
                assert_eq!(kind, Kind::KeyOffer);
                assert_eq!(parse_key_offer(body).unwrap(), [5u8; 32]);
            }
            _ => panic!("expected a handshake-kind frame"),
        }
        assert!(parse_key_offer(&[VERSION, 1, 2]).is_none(), "truncated");
        assert!(parse_key_offer(&[0x99; 33]).is_none(), "bad version");
    }

    /// Spec §4.16: the two new kinds parse as handshake datagrams, and a
    /// cookie reply and a retry come apart into what went in.
    #[test]
    fn a_cookie_reply_and_a_retry_round_trip() {
        let echo = [3u8; COOKIE_ECHO_LEN];
        let cookie = [9u8; COOKIE_LEN];
        let reply = encode_cookie_reply(&echo, &cookie);
        assert_eq!(reply.len(), COOKIE_REPLY_LEN);
        match parse(&reply).expect("valid") {
            Frame::Handshake {
                kind: Kind::CookieReply,
                body,
            } => assert_eq!(parse_cookie_reply(body), Some((echo, cookie))),
            other => panic!("a cookie reply, not {other:?}"),
        }
        let msg1 = vec![7u8; MIN_MSG1_BODY];
        let again = encode_handshake_init_cookie(&cookie, &msg1);
        match parse(&again).expect("valid") {
            Frame::Handshake {
                kind: Kind::HandshakeInitCookie,
                body,
            } => assert_eq!(split_cookie_init(body), Some((cookie, &msg1[..]))),
            other => panic!("a retry, not {other:?}"),
        }
        assert_eq!(parse_cookie_reply(&[COOKIE_VERSION; 10]), None, "cut short");
        assert_eq!(parse_cookie_reply(&[0x02; 33]), None, "another version");
        let mut longer = reply[2..].to_vec();
        longer.extend_from_slice(&[0; 8]);
        assert_eq!(
            parse_cookie_reply(&longer),
            None,
            "a reply is exactly its fixed length"
        );
        assert_eq!(split_cookie_init(&[0u8; COOKIE_LEN - 1]), None);
    }

    /// Spec §4.16: an answer never outweighs the request it answers -- at
    /// most 36 % of the smallest msg1 the daemon answers at all (98 bytes, a
    /// msg1 with an empty payload), 29 % of the 121 bytes this build's
    /// clients send. A forged source gets back far less than was sent in
    /// its name. Checked when the tests compile.
    #[test]
    fn a_cookie_reply_is_at_most_36_percent_of_any_msg1_it_answers() {
        const {
            assert!(
                COOKIE_REPLY_LEN * 100 <= (2 + MIN_MSG1_BODY) * 36,
                "a cookie reply outweighs 36 % of the smallest msg1 it answers"
            )
        };
    }

    #[test]
    fn replay_window_basics() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(1));
        assert!(w.accept(2));
        assert!(!w.accept(2)); // replay
        assert!(w.accept(5)); // jumping ahead is fine
        assert!(w.accept(3)); // within the window, not yet seen
        assert!(!w.accept(3)); // now a replay

        // Shift the window far ahead: a counter more than REPLAY_WINDOW behind
        // is rejected as too old.
        assert!(w.accept(200 + REPLAY_WINDOW));
        assert!(!w.accept(100));
    }

    /// Spec §4.4 / §9.2 (defect 3): the window in effect is 32 704 positions
    /// behind the maximum -- one 64-bit word of the 32 768 is kept in reserve,
    /// as in RFC 6479.
    #[test]
    fn the_window_reaches_exactly_32704_behind_the_maximum() {
        let mut w = ReplayWindow::default();
        let max = 100_000;
        assert!(w.accept(max));
        assert!(w.accept(max - REPLAY_WINDOW), "32 704 behind is inside");
        assert!(
            !w.accept(max - REPLAY_WINDOW - 1),
            "32 705 behind is too old"
        );
        assert!(
            !w.accept(max - REPLAY_WINDOW),
            "a repeat inside it is a replay"
        );
        assert!(w.accept(max - 1));
        assert!(!w.accept(max - 1));
        assert!(!w.accept(max), "the maximum itself is a replay");
    }

    /// A long stream in small steps wraps the ring three times, so every word
    /// is reused while it still holds the bits of the counters 32 768 earlier.
    /// Every seventh counter is skipped and sent late: inside the window it is
    /// accepted once, outside it is too old. The counter 32 768 before a
    /// skipped one was accepted (32 768 is 1 modulo 7), so a word left
    /// uncleared on a small advance reads the late one as a replay.
    #[test]
    fn small_advances_clear_each_reused_word_across_the_wrap() {
        let skipped = |c: u64| c % 7 == 3;
        let mut w = ReplayWindow::default();
        for n in 1..=100_000u64 {
            if skipped(n) {
                continue;
            }
            assert!(w.accept(n), "counter {n} in order");
            assert!(!w.accept(n), "counter {n} again");
            if n % 1000 != 0 || n < 2 * REPLAY_WINDOW_BITS {
                continue;
            }
            // Late, well inside the window: accepted once.
            let inside = (0..7)
                .map(|d| n - 32_000 - d)
                .find(|&c| skipped(c))
                .unwrap();
            assert!(w.accept(inside), "{inside} is {} behind {n}", n - inside);
            assert!(!w.accept(inside), "{inside} a second time");
            // Late, at the far edge of the window: still accepted.
            let edge = (0..7)
                .map(|d| n - REPLAY_WINDOW + d)
                .find(|&c| skipped(c))
                .unwrap();
            assert!(w.accept(edge), "{edge} is {} behind {n}", n - edge);
            // Late, just past the edge: too old.
            let outside = (1..8)
                .map(|d| n - REPLAY_WINDOW - d)
                .find(|&c| skipped(c))
                .unwrap();
            assert!(
                !w.accept(outside),
                "{outside} is {} behind {n}",
                n - outside
            );
            // Old counters that did arrive stay replays in a reused word.
            let seen = (100..107).map(|d| n - d).find(|&c| !skipped(c)).unwrap();
            assert!(!w.accept(seen), "{seen} was already seen");
        }
    }

    /// Advancing the maximum zeroes whole words ahead of it and keeps the
    /// oldest word still inside the window.
    #[test]
    fn advancing_by_whole_words_keeps_the_oldest_word() {
        let mut w = ReplayWindow::default();
        assert!(w.accept(1_000));
        assert!(w.accept(1_000 + REPLAY_WINDOW));
        assert!(
            !w.accept(1_000),
            "still inside the window, and already seen"
        );
        assert!(w.accept(1_001), "inside the window, never seen");
        assert!(!w.accept(999), "one past the window");
    }

    /// A jump by more than the whole window forgets everything before it.
    #[test]
    fn a_jump_past_the_whole_window_forgets_everything_before_it() {
        let mut w = ReplayWindow::default();
        for c in 1..=100 {
            assert!(w.accept(c));
        }
        let far = 100 + REPLAY_WINDOW_BITS * 3;
        assert!(w.accept(far));
        assert!(!w.accept(50), "far too old");
        for back in [1, 63, 64, 65, 1_000, REPLAY_WINDOW] {
            assert!(w.accept(far - back), "{back} behind a fresh jump is new");
        }
    }
}
