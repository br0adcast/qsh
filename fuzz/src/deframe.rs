//! Record deframing and shell-stream decoding, shared by tests and libFuzzer.
//!
//! The property is chunk invariance: feeding the same byte stream in any
//! chunking must produce the same records, overflow state, buffered tail and
//! sticky decode error. A completed record must also re-encode identically.
use transport::channel_geometry::{
    ChannelInstance, GeometryOutcome, GeometryRecord, ResizeRefusal,
};
use transport::shell_frame::{
    decode_shell, encode_record, encode_shell, RawRecord, RecordDeframer, ShellCodecError,
    ShellDeframer, ShellRecord, CONTROL_RECORD_MAX, REC_DATA, REC_ECHO_ACK, REC_GEOMETRY,
    REC_OUTPUT_GAP,
};

/// The largest input retained; larger streams are outside this target.
pub const MAX_INPUT: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
struct RawOutcome {
    records: Vec<RawRecord>,
    overflowed: bool,
    buffered: usize,
}

#[derive(Debug, PartialEq, Eq)]
struct ShellOutcome {
    records: Vec<ShellRecord>,
    error: Option<ShellCodecError>,
    overflowed: bool,
}

fn raw_run(chunks: &[&[u8]], control: bool) -> RawOutcome {
    let mut deframer = if control {
        RecordDeframer::for_control()
    } else {
        RecordDeframer::new()
    };
    let mut records = Vec::new();
    for chunk in chunks {
        records.extend(deframer.push(chunk));
    }
    RawOutcome {
        records,
        overflowed: deframer.overflowed(),
        buffered: deframer.buffered_len(),
    }
}

fn shell_run(chunks: &[&[u8]]) -> ShellOutcome {
    let mut deframer = ShellDeframer::new();
    let mut records = Vec::new();
    for chunk in chunks {
        records.extend(deframer.push(chunk));
    }
    ShellOutcome {
        records,
        error: deframer.error(),
        overflowed: deframer.overflowed(),
    }
}

fn chunkings(input: &[u8]) -> Vec<Vec<&[u8]>> {
    let mut out = vec![vec![input]];
    if input.len() > 1 {
        out.push(vec![&input[..1], &input[1..]]);
        let half = input.len() / 2;
        out.push(vec![&input[..half], &input[half..]]);
    }
    if input.len() <= 512 {
        out.push(input.chunks(1).collect());
    }
    out
}

/// Feed the same stream in several chunkings and require identical framing.
/// The shell deframer's sticky failure and overflow must be chunk-invariant
/// too. Successfully decoded records are re-encoded and decoded again.
pub fn exercise(input: &[u8]) {
    if input.len() > MAX_INPUT {
        return;
    }
    let layouts = chunkings(input);
    for control in [true, false] {
        let expected = raw_run(&layouts[0], control);
        for layout in &layouts[1..] {
            assert_eq!(raw_run(layout, control), expected);
        }
    }

    let expected = shell_run(&layouts[0]);
    for layout in &layouts[1..] {
        assert_eq!(shell_run(layout), expected);
    }
    for record in &expected.records {
        let encoded = encode_shell(record).expect("decoded records have a canonical encoding");
        let raw = decode_shell(encoded_to_raw(&encoded)).expect("canonical encoding decodes");
        assert_eq!(&raw, record);
    }
}

fn encoded_to_raw(encoded: &[u8]) -> RawRecord {
    assert!(encoded.len() >= 5);
    let len = u32::from_be_bytes(encoded[1..5].try_into().unwrap()) as usize;
    assert_eq!(encoded.len(), 5 + len);
    RawRecord {
        kind: encoded[0],
        payload: encoded[5..].to_vec(),
    }
}

/// Synthetic public streams. No recorded traffic is used.
pub fn cases() -> Vec<(&'static str, Vec<u8>)> {
    let data = encode_record(REC_DATA, b"hello");
    let mut data_ack = data.clone();
    data_ack.extend(encode_record(REC_ECHO_ACK, &7u64.to_be_bytes()));
    let mut two_data = data.clone();
    two_data.extend(encode_record(REC_DATA, b"world"));
    let mut unknown_then_data = encode_record(9, b"???");
    unknown_then_data.extend(data.clone());
    let mut malformed_then_data = encode_record(REC_ECHO_ACK, &[0u8; 4]);
    malformed_then_data.extend(data.clone());
    let geometry = encode_shell(&ShellRecord::Geometry(GeometryRecord {
        instance: ChannelInstance::new(1).unwrap(),
        request_id: 1,
        outcome: GeometryOutcome::Applied,
        cols: 80,
        rows: 24,
    }))
    .unwrap();
    let refused = encode_shell(&ShellRecord::Geometry(GeometryRecord {
        instance: ChannelInstance::new(2).unwrap(),
        request_id: 2,
        outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
        cols: 511,
        rows: 24,
    }))
    .unwrap();
    let gap = encode_shell(&ShellRecord::OutputGap {
        instance: ChannelInstance::new(3).unwrap(),
        cause: transport::channel_geometry::OutputGapCause::PreviousConnectionOutputUnconfirmed,
    })
    .unwrap();
    let mut huge = vec![REC_DATA];
    huge.extend_from_slice(&u32::MAX.to_be_bytes());
    huge.extend_from_slice(&[0xaa; 8]);
    let mut partial_payload = vec![REC_DATA, 0, 0, 0, 4, 0xbb, 0xcc];
    partial_payload.shrink_to_fit();
    vec![
        ("empty", vec![]),
        ("partial-header", vec![REC_DATA, 0, 0]),
        ("data", data),
        ("data-ack", data_ack),
        ("two-data", two_data),
        ("unknown-then-data", unknown_then_data),
        ("malformed-then-data", malformed_then_data),
        ("geometry-applied", geometry),
        ("geometry-refused", refused),
        ("output-gap", gap),
        ("partial-payload", partial_payload),
        ("huge-length", huge),
        ("control-limit", {
            let mut bytes = vec![0x20];
            bytes.extend_from_slice(&u32::try_from(CONTROL_RECORD_MAX + 1).unwrap().to_be_bytes());
            bytes
        }),
        ("deterministic-junk", (0u8..64).collect()),
        (
            "known-kind-wrong-size",
            [
                vec![REC_GEOMETRY, 0, 0, 0, 21],
                vec![0u8; 21],
                vec![REC_OUTPUT_GAP, 0, 0, 0, 8],
                vec![0u8; 8],
            ]
            .concat(),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn malformed_and_truncated_streams_are_normal_inputs() {
        for input in [&[][..], &[REC_DATA][..], &[0xff; 5][..]] {
            exercise(input);
        }
        for len in 0..=512 {
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
        let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus/deframer");
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
