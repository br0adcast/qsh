//! Semantic parser properties shared by ordinary tests and libFuzzer.
pub mod auth_keys;
pub mod deframe;
pub mod handshake;
pub mod seeds;
pub mod terminal;
pub mod wire;

use transport::{
    channel,
    shell_frame::{RawRecord, RecordDeframer, CONTROL_RECORD_MAX},
};

pub const MAX_INPUT: usize = CONTROL_RECORD_MAX + 1;

fn canonical(encoded: &[u8]) -> RawRecord {
    assert!(encoded.len() <= CONTROL_RECORD_MAX + 5);
    let mut deframer = RecordDeframer::for_control();
    let mut records = deframer.push(encoded);
    assert!(!deframer.overflowed());
    assert_eq!(deframer.buffered_len(), 0);
    assert_eq!(records.len(), 1);
    records.remove(0)
}

fn verify_client(value: &channel::ClientRecord, encoded: &[u8]) {
    assert_eq!(value, &channel::decode_client(&canonical(encoded)).unwrap());
}

fn verify_server(value: &channel::ServerRecord, encoded: &[u8]) {
    assert_eq!(value, &channel::decode_server(&canonical(encoded)).unwrap());
}

/// Ignore ordinary malformed/unknown records; successful decodes must roundtrip.
/// Oversized inputs are refused before allocating their payload.
pub fn exercise(input: &[u8]) {
    if input.len() > MAX_INPUT {
        return;
    }
    let Some((&kind, payload)) = input.split_first() else {
        return;
    };
    let raw = RawRecord {
        kind,
        payload: payload.to_vec(),
    };
    if let Ok(value) = channel::decode_client(&raw) {
        verify_client(&value, &channel::encode_client(&value));
    }
    if let Ok(value) = channel::decode_server(&raw) {
        verify_server(&value, &channel::encode_server(&value));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn client_oracle_detects_semantic_corruption() {
        verify_client(
            &channel::ClientRecord::Close { stream: 16 },
            &channel::encode_client(&channel::ClientRecord::Close { stream: 17 }),
        );
    }

    #[test]
    #[should_panic(expected = "assertion `left == right` failed")]
    fn server_oracle_detects_semantic_corruption() {
        verify_server(
            &channel::ServerRecord::Opened { stream: 16 },
            &channel::encode_server(&channel::ServerRecord::Opened { stream: 17 }),
        );
    }

    #[test]
    fn accepted_extension_body_is_semantic_not_byte_equality() {
        let raw = RawRecord {
            kind: 0x14,
            payload: vec![1, 2, 3],
        };
        assert_eq!(
            channel::decode_client(&raw).unwrap(),
            channel::ClientRecord::AboutRequest
        );
        assert_ne!(
            channel::encode_client(&channel::ClientRecord::AboutRequest),
            transport::shell_frame::encode_record(raw.kind, &raw.payload)
        );
        exercise(&[0x14, 1, 2, 3]);
    }

    #[test]
    fn synthetic_corpus_matches_encoder_recipes_and_bounds() {
        let cases = crate::seeds::cases();
        assert!(cases.len() <= 32);
        assert!(cases.iter().map(|(_, bytes)| bytes.len()).sum::<usize>() <= 256 * 1024);
        let directory =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/channel_codec");
        let seed_count = std::fs::read_dir(&directory)
            .unwrap()
            .filter(|entry| entry.as_ref().unwrap().file_name() != "manifest.json")
            .count();
        assert_eq!(seed_count, cases.len());
        for (name, bytes) in cases {
            assert!(bytes.len() <= MAX_INPUT);
            assert_eq!(
                std::fs::read(directory.join(name)).unwrap(),
                bytes,
                "{name}"
            );
            if let Some((&kind, payload)) = bytes.split_first() {
                let raw = RawRecord {
                    kind,
                    payload: payload.to_vec(),
                };
                let client = channel::decode_client(&raw);
                let server = channel::decode_server(&raw);
                match name {
                    "unknown" | "resize-zero-ids" | "truncated-open" | "invalid-utf8-term" => {
                        assert!(client.is_err() && server.is_err(), "{name}");
                    }
                    name if name.starts_with("about-") && name != "about-request-extension" => {
                        assert!(server.is_ok(), "{name}");
                    }
                    _ => assert!(client.is_ok() || server.is_ok(), "{name}"),
                }
            }
            exercise(&bytes);
        }
    }

    #[test]
    fn malformed_unknown_and_size_bounds_are_normal_inputs() {
        for input in [&[][..], &[0xff][..], &[0x10][..], &[0x13, 0xff][..]] {
            exercise(input);
        }
        exercise(&vec![0xff; MAX_INPUT]);
        exercise(&vec![0xff; MAX_INPUT + 1]);
    }
}
