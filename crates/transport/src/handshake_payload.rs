//! Versioned Noise handshake payload encoding/parsing (sans-IO).
//!
//! This module encodes and parses the versioned payloads for Noise protocol
//! handshake messages: msg1 carries the protocol version, handshake start kind
//! (Cold/Warm), a session token, the authentication method and the features
//! the client offers; msg2 carries the version, the session ID the server
//! allocated, whether it resumed, the handshake nonce and the features it
//! enabled (spec §5.1). Every field after the first ones was appended after
//! the format shipped, and a parser reads each only when it is there in
//! full: a peer built before it sends none, and means none.

use std::fmt;

use crate::auth::AUTH_NONCE_LEN;
use crate::features::Features;

/// Handshake protocol version.
pub const HS_VERSION: u8 = 0x02;

/// Length of the session token in msg1.
pub const SESSION_TOKEN_LEN: usize = 16;

/// msg1 up to and including the method byte: what every client built
/// before negotiation sends.
const MSG1_BASE_LEN: usize = 19;

/// msg2 up to and including the nonce: what every server built before
/// negotiation sends.
const MSG2_BASE_LEN: usize = 26;

/// The features field after either base: a `u32`, big-endian.
const FEATURES_LEN: usize = 4;

/// The kind of handshake start (initiator state).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StartKind {
    /// A fresh connection (no prior state).
    Cold = 0x00,
    /// Resuming after a network change or reattach.
    Warm = 0x01,
}

impl StartKind {
    /// Parse a byte into a `StartKind`, or `None` if unrecognized.
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(StartKind::Cold),
            0x01 => Some(StartKind::Warm),
            _ => None,
        }
    }
}

/// How the client proves it is allowed in. The byte travels in msg1 so the
/// server knows which policy to apply before it decides anything else.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AuthMethod {
    /// The client's static key is on the server's allowlist, put there out of
    /// band (the SSH bootstrap: `transport-ensure --client-pubkey`). Nothing
    /// further is required after the handshake.
    Allowlist = 0x00,
    /// The client will prove its identity with an SSH-key signature over the
    /// handshake hash, on the auth stream, right after the handshake
    /// (see `crate::auth`).
    SshSignature = 0x01,
}

impl AuthMethod {
    fn from_u8(b: u8) -> Option<Self> {
        match b {
            0x00 => Some(AuthMethod::Allowlist),
            0x01 => Some(AuthMethod::SshSignature),
            _ => None,
        }
    }
}

/// Handshake payload for msg1 (client to server during Noise).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Msg1Payload {
    /// The kind of handshake start.
    pub start_kind: StartKind,
    /// Session token (16 bytes).
    pub token: [u8; 16],
    /// The authentication method the client announces.
    pub method: AuthMethod,
    /// The features the client can use (spec §5.2). `NONE` from a client
    /// built before negotiation.
    pub offered: Features,
}

/// Error in parsing a handshake payload.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HsPayloadError {
    /// The first byte doesn't match `HS_VERSION`.
    BadVersion,
    /// The message is shorter than the expected length.
    TooShort,
    /// The `start_kind` byte is not recognized.
    BadStartKind,
    /// The `method` byte is not recognized.
    BadAuthMethod,
}

impl fmt::Display for HsPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let msg = match self {
            HsPayloadError::BadVersion => "unsupported handshake version",
            HsPayloadError::TooShort => "handshake payload is too short",
            HsPayloadError::BadStartKind => "unknown handshake start kind",
            HsPayloadError::BadAuthMethod => "unknown authentication method",
        };
        f.write_str(msg)
    }
}

impl std::error::Error for HsPayloadError {}

/// msg1 as every client before negotiation writes it:
/// `[HS_VERSION | start_kind | token(16) | method]`, 19 bytes, `offered` not
/// written. What a test that plays such a client sends.
pub fn encode_msg1_without_tail(p: &Msg1Payload) -> Vec<u8> {
    let mut out = Vec::with_capacity(MSG1_BASE_LEN + FEATURES_LEN);
    out.push(HS_VERSION);
    out.push(p.start_kind as u8);
    out.extend_from_slice(&p.token);
    out.push(p.method as u8);
    out
}

/// Encode a msg1 payload:
/// `[HS_VERSION | start_kind | token(16) | method | offered(u32, BE)]`
/// (23 bytes). The method byte and `offered` were appended after the format
/// shipped; see `parse_msg1` for how their absence reads.
pub fn encode_msg1(p: &Msg1Payload) -> Vec<u8> {
    let mut out = encode_msg1_without_tail(p);
    out.extend_from_slice(&p.offered.bits().to_be_bytes());
    out
}

/// Parse a msg1 payload: version, start_kind, token, and (if present)
/// method and offered features.
pub fn parse_msg1(bytes: &[u8]) -> Result<Msg1Payload, HsPayloadError> {
    if bytes.is_empty() || bytes[0] != HS_VERSION {
        return Err(HsPayloadError::BadVersion);
    }
    if bytes.len() < 18 {
        return Err(HsPayloadError::TooShort);
    }
    let start_kind = StartKind::from_u8(bytes[1]).ok_or(HsPayloadError::BadStartKind)?;
    let mut token = [0u8; 16];
    token.copy_from_slice(&bytes[2..18]);
    let method = match bytes.get(18) {
        // A client built before the field existed would send 18 bytes; no client
        // built from this tree does -- encode_msg1 below always writes the byte.
        // This is a compatibility floor, not a shape any current peer produces.
        None => AuthMethod::Allowlist,
        Some(&b) => AuthMethod::from_u8(b).ok_or(HsPayloadError::BadAuthMethod)?,
    };
    Ok(Msg1Payload {
        start_kind,
        token,
        method,
        // Every client before negotiation sends 19 bytes: it offers nothing.
        offered: read_features(bytes, MSG1_BASE_LEN),
    })
}

/// msg2 as every server before negotiation writes it:
/// `[HS_VERSION | session_id(8, big-endian) | resumed(1) | nonce(16)]`, 26
/// bytes, `enabled` not written. What a test that plays such a server sends.
pub fn encode_msg2_without_tail(
    session_id: u64,
    resumed: bool,
    nonce: &[u8; AUTH_NONCE_LEN],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(MSG2_BASE_LEN + FEATURES_LEN);
    out.push(HS_VERSION);
    out.extend_from_slice(&session_id.to_be_bytes());
    out.push(u8::from(resumed));
    out.extend_from_slice(nonce);
    out
}

/// Encode a msg2 payload:
/// `[HS_VERSION | session_id(8, big-endian) | resumed(1) | nonce(16) | enabled(u32, BE)]`
/// (30 bytes).
pub fn encode_msg2(
    session_id: u64,
    resumed: bool,
    nonce: &[u8; AUTH_NONCE_LEN],
    enabled: Features,
) -> Vec<u8> {
    let mut out = encode_msg2_without_tail(session_id, resumed, nonce);
    out.extend_from_slice(&enabled.bits().to_be_bytes());
    out
}

/// What the server answered with in msg2.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Msg2 {
    pub session_id: u64,
    /// Whether this handshake landed on the session the client asked for by
    /// token (`StartKind::Warm` and the server still had it), rather than a
    /// fresh one. The client cannot infer this: an unknown token gets a new
    /// session silently, which is the right behavior but indistinguishable
    /// from a resume unless the server says so.
    pub resumed: bool,
    /// The server's nonce for this handshake, to be echoed back under the
    /// signature in a version 2 auth record. `None` from a server too old
    /// to send one -- the client then falls back to a version 1 record.
    pub nonce: Option<[u8; AUTH_NONCE_LEN]>,
    /// The features this connection uses (spec §5.2). `NONE` from a server
    /// built before negotiation -- every such server sends 26 bytes.
    pub enabled: Features,
}

/// Parse a msg2 payload: version, session_id (big-endian u64), and -- from a
/// server new enough to send them -- whether the session was resumed and the
/// per-handshake nonce.
///
/// A payload of exactly nine bytes comes from a server that predates the
/// resume flag; `resumed: false` is the honest reading of it, and also the
/// safe one: a client that believes it resumed when it did not would wait
/// for a channel list that is never coming. A payload of ten bytes, or one
/// cut off partway through the nonce, comes from a server that predates the
/// nonce; `nonce: None` is the honest reading of that, too -- the client then
/// falls back to a version 1 auth record. A payload shorter than 30 bytes
/// enables nothing.
pub fn parse_msg2(bytes: &[u8]) -> Result<Msg2, HsPayloadError> {
    if bytes.is_empty() || bytes[0] != HS_VERSION {
        return Err(HsPayloadError::BadVersion);
    }
    if bytes.len() < 9 {
        return Err(HsPayloadError::TooShort);
    }
    let mut session_id_bytes = [0u8; 8];
    session_id_bytes.copy_from_slice(&bytes[1..9]);
    // `get(10..26)` is `None` for a nine-byte payload, a ten-byte payload,
    // and one cut off partway through the nonce -- exactly the three
    // "no nonce" cases above.
    let nonce = bytes.get(10..26).map(|slice| {
        let mut out = [0u8; AUTH_NONCE_LEN];
        out.copy_from_slice(slice);
        out
    });
    Ok(Msg2 {
        session_id: u64::from_be_bytes(session_id_bytes),
        resumed: bytes.get(9).is_some_and(|b| *b == 1),
        nonce,
        enabled: read_features(bytes, MSG2_BASE_LEN),
    })
}

/// The features field at `at`, or `NONE` unless all four bytes are there. A
/// field cut short is a peer that predates it; bytes after it are for fields
/// not invented yet.
fn read_features(bytes: &[u8], at: usize) -> Features {
    bytes
        .get(at..at + FEATURES_LEN)
        .map(|b| Features::from_bits(u32::from_be_bytes([b[0], b[1], b[2], b[3]])))
        .unwrap_or(Features::NONE)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The build before negotiation (`ab40ae6`): its msg1 and msg2 parsers,
    /// verbatim but for their return types (its structs had no feature
    /// fields). What an old peer does with the bytes this build writes.
    mod before_negotiation {
        use super::super::{AuthMethod, HsPayloadError, StartKind, HS_VERSION};
        use crate::auth::AUTH_NONCE_LEN;

        pub fn parse_msg1(
            bytes: &[u8],
        ) -> Result<(StartKind, [u8; 16], AuthMethod), HsPayloadError> {
            if bytes.is_empty() || bytes[0] != HS_VERSION {
                return Err(HsPayloadError::BadVersion);
            }
            if bytes.len() < 18 {
                return Err(HsPayloadError::TooShort);
            }
            let start_kind = StartKind::from_u8(bytes[1]).ok_or(HsPayloadError::BadStartKind)?;
            let mut token = [0u8; 16];
            token.copy_from_slice(&bytes[2..18]);
            let method = match bytes.get(18) {
                None => AuthMethod::Allowlist,
                Some(&b) => AuthMethod::from_u8(b).ok_or(HsPayloadError::BadAuthMethod)?,
            };
            Ok((start_kind, token, method))
        }

        pub fn parse_msg2(
            bytes: &[u8],
        ) -> Result<(u64, bool, Option<[u8; AUTH_NONCE_LEN]>), HsPayloadError> {
            if bytes.is_empty() || bytes[0] != HS_VERSION {
                return Err(HsPayloadError::BadVersion);
            }
            if bytes.len() < 9 {
                return Err(HsPayloadError::TooShort);
            }
            let mut session_id_bytes = [0u8; 8];
            session_id_bytes.copy_from_slice(&bytes[1..9]);
            let nonce = bytes.get(10..26).map(|slice| {
                let mut out = [0u8; AUTH_NONCE_LEN];
                out.copy_from_slice(slice);
                out
            });
            Ok((
                u64::from_be_bytes(session_id_bytes),
                bytes.get(9).is_some_and(|b| *b == 1),
                nonce,
            ))
        }
    }

    fn sample_msg1(offered: Features) -> Msg1Payload {
        Msg1Payload {
            start_kind: StartKind::Warm,
            token: [7u8; 16],
            method: AuthMethod::SshSignature,
            offered,
        }
    }

    /// Spec §5.1: msg1 is the old 19 bytes, then `offered`, big-endian.
    #[test]
    fn msg1_carries_what_the_client_offers_after_the_old_bytes() {
        let p = sample_msg1(Features::HEADER_AAD | Features::OFFSET_WRAP);
        let bytes = encode_msg1(&p);
        assert_eq!(bytes.len(), 23);
        assert_eq!(bytes[..19], encode_msg1_without_tail(&p)[..]);
        assert_eq!(bytes[19..], [0u8, 0, 0, 0x05]);
        assert_eq!(parse_msg1(&bytes).unwrap(), p);
    }

    /// Spec §5.2: a server built before negotiation reads the new msg1
    /// exactly as it read the old one.
    #[test]
    fn an_old_server_reads_the_new_msg1_as_before() {
        let bytes = encode_msg1(&sample_msg1(Features::from_bits(u32::MAX)));
        assert_eq!(
            before_negotiation::parse_msg1(&bytes),
            Ok((StartKind::Warm, [7u8; 16], AuthMethod::SshSignature))
        );
    }

    /// Spec §5.2: a msg1 without the whole field offers nothing -- the 19
    /// bytes every client before negotiation sends, the 18 of the oldest,
    /// and one cut off inside the field.
    #[test]
    fn a_msg1_without_its_whole_tail_offers_nothing() {
        let full = encode_msg1(&sample_msg1(Features::HEADER_AAD));
        for len in [18, 19, 20, 22] {
            assert_eq!(
                parse_msg1(&full[..len]).unwrap().offered,
                Features::NONE,
                "{len} bytes"
            );
        }
    }

    /// Spec §5.2: unknown bits are kept, not refused, and bytes after the
    /// field belong to fields not invented yet.
    #[test]
    fn unknown_bits_and_trailing_bytes_do_not_spoil_msg1() {
        let mut bytes = encode_msg1(&sample_msg1(Features::from_bits(0x8000_0001)));
        bytes.extend_from_slice(b"a later field");
        let parsed = parse_msg1(&bytes).unwrap();
        assert_eq!(parsed.offered.bits(), 0x8000_0001);
        assert_eq!(parsed.token, [7u8; 16]);
    }

    /// Spec §5.1: msg2 is the old 26 bytes, then `enabled`, big-endian.
    #[test]
    fn msg2_carries_what_the_server_enabled_after_the_old_bytes() {
        let nonce = [11u8; AUTH_NONCE_LEN];
        let bytes = encode_msg2(0xDEAD_BEEF, true, &nonce, Features::HEADER_AAD);
        assert_eq!(bytes.len(), 30);
        assert_eq!(
            bytes[..26],
            encode_msg2_without_tail(0xDEAD_BEEF, true, &nonce)[..]
        );
        assert_eq!(bytes[26..], [0u8, 0, 0, 0x01]);
        assert_eq!(
            parse_msg2(&bytes).unwrap(),
            Msg2 {
                session_id: 0xDEAD_BEEF,
                resumed: true,
                nonce: Some(nonce),
                enabled: Features::HEADER_AAD,
            }
        );
    }

    /// Spec §5.2: a client built before negotiation reads the new msg2
    /// exactly as it read the old one.
    #[test]
    fn an_old_client_reads_the_new_msg2_as_before() {
        let nonce = [11u8; AUTH_NONCE_LEN];
        let bytes = encode_msg2(77, true, &nonce, Features::from_bits(u32::MAX));
        assert_eq!(
            before_negotiation::parse_msg2(&bytes),
            Ok((77, true, Some(nonce)))
        );
    }

    /// Spec §5.2: a msg2 without the whole field enables nothing -- the 26
    /// bytes every server before negotiation sends, and shorter.
    #[test]
    fn a_msg2_without_its_whole_tail_enables_nothing() {
        let full = encode_msg2(5, false, &[3u8; AUTH_NONCE_LEN], Features::HEADER_AAD);
        for len in [9, 10, 26, 29] {
            assert_eq!(
                parse_msg2(&full[..len]).unwrap().enabled,
                Features::NONE,
                "{len} bytes"
            );
        }
    }

    #[test]
    fn msg1_roundtrips() {
        let p = Msg1Payload {
            start_kind: StartKind::Warm,
            token: [7u8; 16],
            method: AuthMethod::Allowlist,
            offered: Features::NONE,
        };
        let bytes = encode_msg1(&p);
        assert_eq!(bytes.len(), 23);
        assert_eq!(bytes[0], HS_VERSION);
        assert_eq!(bytes[1], StartKind::Warm as u8);
        assert_eq!(parse_msg1(&bytes).unwrap(), p);
    }

    #[test]
    fn msg1_rejects_bad_version_len_kind() {
        assert_eq!(parse_msg1(&[0x99, 0, 0]), Err(HsPayloadError::BadVersion));
        assert_eq!(parse_msg1(&[HS_VERSION, 0]), Err(HsPayloadError::TooShort));
        let mut bad = encode_msg1(&Msg1Payload {
            start_kind: StartKind::Cold,
            token: [0u8; 16],
            method: AuthMethod::Allowlist,
            offered: Features::NONE,
        });
        bad[1] = 0x7f; // unknown start_kind
        assert_eq!(parse_msg1(&bad), Err(HsPayloadError::BadStartKind));
    }

    #[test]
    fn msg1_carries_the_auth_method() {
        let p = Msg1Payload {
            start_kind: StartKind::Cold,
            token: [3u8; 16],
            method: AuthMethod::SshSignature,
            offered: Features::NONE,
        };
        let bytes = encode_msg1(&p);
        assert_eq!(bytes.len(), 23, "version + kind + token + method + offered");
        assert_eq!(parse_msg1(&bytes).unwrap(), p);
    }

    /// An 18-byte msg1 predates the method field: it must keep working and
    /// mean "allowlist".
    #[test]
    fn msg1_without_the_method_byte_means_allowlist() {
        let mut old = Vec::new();
        old.push(HS_VERSION);
        old.push(StartKind::Warm as u8);
        old.extend_from_slice(&[9u8; 16]);
        assert_eq!(old.len(), 18);
        let parsed = parse_msg1(&old).unwrap();
        assert_eq!(parsed.method, AuthMethod::Allowlist);
        assert_eq!(parsed.start_kind, StartKind::Warm);
    }

    #[test]
    fn msg1_rejects_an_unknown_method() {
        let mut bad = encode_msg1(&Msg1Payload {
            start_kind: StartKind::Cold,
            token: [0u8; 16],
            method: AuthMethod::Allowlist,
            offered: Features::NONE,
        });
        bad[18] = 0x7f;
        assert_eq!(parse_msg1(&bad), Err(HsPayloadError::BadAuthMethod));
    }

    #[test]
    fn msg2_roundtrips() {
        let nonce = [11u8; AUTH_NONCE_LEN];
        for resumed in [false, true] {
            let bytes = encode_msg2(0xDEAD_BEEF, resumed, &nonce, Features::NONE);
            assert_eq!(bytes.len(), 30);
            assert_eq!(bytes[0], HS_VERSION);
            assert_eq!(
                parse_msg2(&bytes).unwrap(),
                Msg2 {
                    session_id: 0xDEAD_BEEF,
                    resumed,
                    nonce: Some(nonce),
                    enabled: Features::NONE,
                }
            );
        }
        assert_eq!(parse_msg2(&[0x99]), Err(HsPayloadError::BadVersion));
    }

    /// A server that predates the resume flag sends nine bytes. Reading that
    /// as "not resumed" is both what it meant and the safe way to be wrong:
    /// a client that believed it had resumed would sit waiting for a channel
    /// list no such server will ever send.
    #[test]
    fn a_msg2_without_the_resume_flag_reads_as_a_fresh_session() {
        let mut nine = vec![HS_VERSION];
        nine.extend_from_slice(&0xDEAD_BEEFu64.to_be_bytes());
        assert_eq!(nine.len(), 9);
        assert_eq!(
            parse_msg2(&nine).unwrap(),
            Msg2 {
                session_id: 0xDEAD_BEEF,
                resumed: false,
                nonce: None,
                enabled: Features::NONE,
            }
        );
    }

    #[test]
    fn msg2_round_trips_with_a_nonce() {
        let nonce = [5u8; AUTH_NONCE_LEN];
        let bytes = encode_msg2(77, true, &nonce, Features::NONE);
        let parsed = parse_msg2(&bytes).expect("parses");
        assert_eq!(parsed.session_id, 77);
        assert!(parsed.resumed);
        assert_eq!(parsed.nonce, Some(nonce));
    }

    /// A ten-byte payload comes from a server that predates the nonce. Reading
    /// it as "no nonce" is the honest answer, and the one that keeps such a
    /// server usable: the client then sends a version 1 record.
    #[test]
    fn a_payload_without_a_nonce_parses_as_none() {
        let mut ten = vec![HS_VERSION];
        ten.extend_from_slice(&42u64.to_be_bytes());
        ten.push(1);
        let parsed = parse_msg2(&ten).expect("parses");
        assert_eq!(parsed.session_id, 42);
        assert!(parsed.resumed);
        assert_eq!(parsed.nonce, None);
    }

    /// A payload cut off inside the nonce is not a nonce.
    #[test]
    fn a_half_written_nonce_is_not_read() {
        let mut short = vec![HS_VERSION];
        short.extend_from_slice(&42u64.to_be_bytes());
        short.push(0);
        short.extend_from_slice(&[9u8; 15]);
        assert_eq!(parse_msg2(&short).expect("parses").nonce, None);
    }
}
