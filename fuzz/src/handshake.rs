//! Versioned Noise handshake payload parsing, shared by tests and libFuzzer.
use transport::auth::AUTH_NONCE_LEN;
use transport::features::Features;
use transport::handshake_payload::{
    encode_msg1, encode_msg2, parse_msg1, parse_msg2, AuthMethod, Msg2, StartKind, HS_VERSION,
};

/// Handshake payloads are short; anything longer is outside this target.
pub const MAX_INPUT: usize = 512;

/// Both public payload parsers are independent. A successful parse must
/// survive canonical re-encoding without changing its meaning; trailing
/// bytes belong to fields this version does not know and are not compared.
pub fn exercise(input: &[u8]) {
    if input.len() > MAX_INPUT {
        return;
    }
    if let Ok(msg1) = parse_msg1(input) {
        let encoded = encode_msg1(&msg1);
        assert_eq!(parse_msg1(&encoded), Ok(msg1));
    }
    if let Ok(msg2) = parse_msg2(input) {
        let nonce = msg2.nonce.unwrap_or([0; AUTH_NONCE_LEN]);
        let canonical = Msg2 {
            nonce: Some(nonce),
            ..msg2
        };
        let encoded = encode_msg2(
            canonical.session_id,
            canonical.resumed,
            &nonce,
            canonical.enabled,
        );
        assert_eq!(parse_msg2(&encoded), Ok(canonical));
    }
}

/// Synthetic public payloads. No recorded handshake bytes are used.
pub fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let msg1 = |start_kind, method, offered| {
        encode_msg1(&transport::handshake_payload::Msg1Payload {
            start_kind,
            token: [0x11; 16],
            method,
            offered,
        })
    };
    let nonce = [0x22; AUTH_NONCE_LEN];
    let msg2 = |resumed, enabled| encode_msg2(0x0102_0304_0506_0708, resumed, &nonce, enabled);
    let mut msg1_tail = msg1(StartKind::Warm, AuthMethod::SshSignature, Features::NONE);
    msg1_tail.extend_from_slice(b"a later field");
    let mut msg2_tail = msg2(false, Features::NONE);
    msg2_tail.extend_from_slice(b"a later field");
    let all_features = Features::from_bits(u32::MAX);
    vec![
        ("empty", vec![]),
        ("version-only", vec![HS_VERSION]),
        ("wrong-version", vec![0xff; 19]),
        (
            "msg1-short",
            msg1(StartKind::Cold, AuthMethod::Allowlist, Features::NONE)[..18].to_vec(),
        ),
        (
            "msg1-cold-allowlist",
            msg1(StartKind::Cold, AuthMethod::Allowlist, Features::NONE),
        ),
        (
            "msg1-warm-signature",
            msg1(StartKind::Warm, AuthMethod::SshSignature, Features::NONE),
        ),
        (
            "msg1-all-features",
            msg1(StartKind::Cold, AuthMethod::SshSignature, all_features),
        ),
        ("msg1-unknown-start", {
            let mut bytes = msg1(StartKind::Cold, AuthMethod::Allowlist, Features::NONE);
            bytes[1] = 0xff;
            bytes
        }),
        ("msg1-unknown-method", {
            let mut bytes = msg1(StartKind::Cold, AuthMethod::Allowlist, Features::NONE);
            bytes[18] = 0xff;
            bytes
        }),
        ("msg1-tail", msg1_tail),
        ("msg2-short", msg2(false, Features::NONE)[..8].to_vec()),
        ("msg2-base", msg2(false, Features::NONE)[..26].to_vec()),
        ("msg2-resumed", msg2(true, Features::NONE)),
        ("msg2-all-features", msg2(false, all_features)),
        ("msg2-tail", msg2_tail),
        ("msg2-wrong-version", {
            let mut bytes = msg2(false, Features::NONE);
            bytes[0] = 0xff;
            bytes
        }),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_truncated_payloads_are_normal_inputs() {
        for input in [
            &[][..],
            &[HS_VERSION][..],
            &[0xff; 24][..],
            &[HS_VERSION, 0xff][..],
        ] {
            exercise(input);
        }
        for len in 0..=MAX_INPUT {
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
    fn accepted_tail_is_not_byte_equality() {
        let (_, tail) = cases()
            .into_iter()
            .find(|(name, _)| *name == "msg1-tail")
            .unwrap();
        let canonical = encode_msg1(&parse_msg1(&tail).unwrap());
        assert_ne!(canonical, tail);
        assert_eq!(parse_msg1(&canonical), parse_msg1(&tail));
    }

    #[test]
    fn synthetic_corpus_matches_encoder_recipes_and_bounds() {
        let cases = cases();
        assert!(cases.len() <= 32);
        assert!(cases.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() <= 256 * 1024);
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/handshake_payload");
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
