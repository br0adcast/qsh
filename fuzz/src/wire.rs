//! Datagram framing and small fixed handshake bodies, shared by tests and
//! libFuzzer.
use transport::wire::{
    encode_cookie_reply, encode_handshake, encode_handshake_init_cookie, encode_key_offer_body,
    encode_key_request, encode_transport, parse, parse_cookie_reply, parse_key_offer,
    split_cookie_init, Frame, Kind, COOKIE_ECHO_LEN, COOKIE_LEN, VERSION,
};

/// The largest input retained; larger datagrams are outside this target.
pub const MAX_INPUT: usize = 2048;

fn handshake_body(input: &[u8]) -> Option<&[u8]> {
    let frame = parse(input).ok()?;
    match frame {
        Frame::Handshake { body, .. } => Some(body),
        Frame::Transport { .. } => None,
    }
}

/// Parse a datagram. A successful frame must survive re-encoding with the
/// same kind and bytes. The three fixed-size handshake bodies are parsed
/// both as a whole datagram body and as raw input, because callers validate
/// them in both shapes.
pub fn exercise(input: &[u8]) {
    if input.len() > MAX_INPUT {
        return;
    }
    if let Ok(frame) = parse(input) {
        match &frame {
            Frame::Handshake { kind, body } => {
                let encoded = encode_handshake(*kind, body);
                assert_eq!(parse(&encoded), Ok(frame));
            }
            Frame::Transport {
                session_id: _,
                counter: _,
                aead,
                aad,
            } => {
                let encoded = encode_transport(aad, aead);
                assert_eq!(parse(&encoded), Ok(frame));
            }
        }
    }

    if let Some(body) = handshake_body(input) {
        check_bodies(body);
    }
    check_bodies(input);
}

fn check_bodies(bytes: &[u8]) {
    if let Some(key) = parse_key_offer(bytes) {
        assert_eq!(parse_key_offer(&encode_key_offer_body(&key)), Some(key));
    }
    if let Some((echo, cookie)) = parse_cookie_reply(bytes) {
        let encoded = encode_cookie_reply(&echo, &cookie);
        assert_eq!(parse_cookie_reply(&encoded[2..]), Some((echo, cookie)));
    }
    if let Some((cookie, msg1)) = split_cookie_init(bytes) {
        let encoded = encode_handshake_init_cookie(&cookie, msg1);
        assert_eq!(split_cookie_init(&encoded[2..]), Some((cookie, msg1)));
    }
}

/// Synthetic public datagrams and bodies. No captured traffic is used.
pub fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let key = [0x33; 32];
    let echo = [0x44; COOKIE_ECHO_LEN];
    let cookie = [0x55; COOKIE_LEN];
    let mut cookie_init = encode_handshake_init_cookie(&cookie, &[0x66; 96]);
    cookie_init.truncate(2 + COOKIE_LEN + 96);
    let frame = |kind, body| encode_handshake(kind, body);
    vec![
        ("empty", vec![]),
        ("one-byte", vec![VERSION]),
        ("wrong-version", vec![0xff, Kind::HandshakeInit as u8]),
        ("bad-kind", vec![VERSION, 0xff]),
        ("handshake-init-empty", frame(Kind::HandshakeInit, &[])),
        ("handshake-resp-body", frame(Kind::HandshakeResp, b"body")),
        ("key-request", encode_key_request()),
        (
            "key-offer-datagram",
            frame(Kind::KeyOffer, &encode_key_offer_body(&key)),
        ),
        ("key-offer-body", encode_key_offer_body(&key)),
        ("key-offer-short", [&[VERSION][..], &key[..31]].concat()),
        (
            "cookie-reply-datagram",
            frame(Kind::CookieReply, &encode_cookie_reply(&echo, &cookie)[2..]),
        ),
        (
            "cookie-reply-body",
            encode_cookie_reply(&echo, &cookie)[2..].to_vec(),
        ),
        ("cookie-init-datagram", cookie_init),
        (
            "cookie-init-body",
            encode_handshake_init_cookie(&cookie, &[0x66; 96])[2..].to_vec(),
        ),
        (
            "transport-empty",
            encode_transport(&transport::wire::transport_header(7, 9), &[]),
        ),
        (
            "transport-aead",
            encode_transport(
                &transport::wire::transport_header(u64::MAX, u64::MAX),
                &[0x77; 16],
            ),
        ),
        (
            "transport-short",
            vec![VERSION, Kind::Transport as u8, 0, 0],
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_truncated_datagrams_are_normal_inputs() {
        for input in [&[][..], &[VERSION][..], &[VERSION, 0xff][..]] {
            exercise(input);
        }
        for len in 0..=256 {
            exercise(&vec![0xab; len]);
        }
        exercise(&vec![0xab; MAX_INPUT + 1]);
    }

    #[test]
    fn canonical_reencoding_preserves_semantics() {
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
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/wire_datagram");
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
