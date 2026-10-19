//! Encoding of the `server->client` shell stream into records. Stream 0
//! carries PTY output (DATA) and input acknowledgments (ECHO_ACK)
//! interleaved; for the client to tell them apart and know which point in
//! the output an acknowledgment refers to, both record kinds travel on the
//! SAME reliable ordered stream. An ECHO_ACK sent right after its DATA is
//! guaranteed to be applied by the client only after the corresponding
//! output has already been fed to the emulator -- there's no "acked before
//! shown" race.
//!
//! Record format: `type(1) | len(u32 BE) | payload[len]`.

use crate::channel_geometry::{
    ChannelInstance, GeometryOutcome, GeometryRecord, OutputGapCause, ResizeRefusal,
};

/// An authoritative geometry boundary on the channel output stream.
pub const REC_GEOMETRY: u8 = 2;
/// Typed disclosure that channel output continuity could not be preserved.
pub const REC_OUTPUT_GAP: u8 = 3;

/// A data record: raw PTY output bytes.
pub const REC_DATA: u8 = 0;

/// An input acknowledgment record: payload = offset of input bytes consumed
/// by the server (`u64` BE).
pub const REC_ECHO_ACK: u8 = 1;

/// A parsed shell-stream record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellRecord {
    Geometry(GeometryRecord),
    OutputGap {
        instance: ChannelInstance,
        cause: OutputGapCause,
    },
    /// PTY output bytes -> into the terminal emulator.
    Data(Vec<u8>),
    /// Acknowledgment: the server has consumed this many input bytes (offset).
    EchoAck(u64),
}

/// Unknown extensions can be skipped; malformed known records cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellCodecError {
    UnknownKind(u8),
    Malformed,
    /// A decoder owner has not negotiated/implemented this known record.
    UnsupportedKind(u8),
}

/// Decode one envelope, retaining the distinction between unknown and broken.
/// Geometry also requires `GeometryRecord::validate_for_open` at the owner.
pub fn decode_shell(raw: RawRecord) -> Result<ShellRecord, ShellCodecError> {
    let p = raw.payload;
    match raw.kind {
        REC_DATA => Ok(ShellRecord::Data(p)),
        REC_ECHO_ACK => {
            let bytes: [u8; 8] = p
                .as_slice()
                .try_into()
                .map_err(|_| ShellCodecError::Malformed)?;
            Ok(ShellRecord::EchoAck(u64::from_be_bytes(bytes)))
        }
        REC_GEOMETRY => {
            if p.len() != 22 {
                return Err(ShellCodecError::Malformed);
            }
            let instance = ChannelInstance::new(u64::from_be_bytes(p[0..8].try_into().unwrap()))
                .ok_or(ShellCodecError::Malformed)?;
            let request_id = u64::from_be_bytes(p[8..16].try_into().unwrap());
            let outcome = match (p[16], p[17]) {
                (0, 0) => GeometryOutcome::Established,
                (1, 0) => GeometryOutcome::Applied,
                (2, reason) => GeometryOutcome::Refused(
                    ResizeRefusal::from_wire(reason).ok_or(ShellCodecError::Malformed)?,
                ),
                _ => return Err(ShellCodecError::Malformed),
            };
            let record = GeometryRecord {
                instance,
                request_id,
                outcome,
                cols: u16::from_be_bytes(p[18..20].try_into().unwrap()),
                rows: u16::from_be_bytes(p[20..22].try_into().unwrap()),
            };
            record.validate().map_err(|_| ShellCodecError::Malformed)?;
            Ok(ShellRecord::Geometry(record))
        }
        REC_OUTPUT_GAP => {
            if p.len() != 9 {
                return Err(ShellCodecError::Malformed);
            }
            let instance = ChannelInstance::new(u64::from_be_bytes(p[0..8].try_into().unwrap()))
                .ok_or(ShellCodecError::Malformed)?;
            let cause = OutputGapCause::from_wire(p[8]).ok_or(ShellCodecError::Malformed)?;
            Ok(ShellRecord::OutputGap { instance, cause })
        }
        kind => Err(ShellCodecError::UnknownKind(kind)),
    }
}

/// Encode one shell record. Reject inconsistent locally constructed geometry.
pub fn encode_shell(record: &ShellRecord) -> Result<Vec<u8>, ShellCodecError> {
    Ok(match record {
        ShellRecord::Data(bytes) => encode_record(REC_DATA, bytes),
        ShellRecord::EchoAck(offset) => encode_record(REC_ECHO_ACK, &offset.to_be_bytes()),
        ShellRecord::Geometry(record) => {
            record.validate().map_err(|_| ShellCodecError::Malformed)?;
            let mut p = [0; 22];
            p[0..8].copy_from_slice(&record.instance.get().to_be_bytes());
            p[8..16].copy_from_slice(&record.request_id.to_be_bytes());
            let (outcome, reason) = match record.outcome {
                GeometryOutcome::Established => (0, 0),
                GeometryOutcome::Applied => (1, 0),
                GeometryOutcome::Refused(reason) => (2, reason as u8),
            };
            p[16] = outcome;
            p[17] = reason;
            p[18..20].copy_from_slice(&record.cols.to_be_bytes());
            p[20..22].copy_from_slice(&record.rows.to_be_bytes());
            encode_record(REC_GEOMETRY, &p)
        }
        ShellRecord::OutputGap { instance, cause } => {
            let mut p = [0; 9];
            p[0..8].copy_from_slice(&instance.get().to_be_bytes());
            p[8] = *cause as u8;
            encode_record(REC_OUTPUT_GAP, &p)
        }
    })
}

/// Record header: type (1) + payload length (4).
const HEADER_LEN: usize = 5;

/// Assemble a record: `type | len(u32 BE) | payload`.
pub fn encode_record(rec_type: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(rec_type);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// A record envelope as it sits on any stream: a type byte and its payload.
/// Both the shell stream (`ShellRecord`) and the session control stream
/// (`crate::channel`) are built out of these, so the envelope is parsed in
/// exactly one place.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRecord {
    pub kind: u8,
    pub payload: Vec<u8>,
}

/// The longest record the session-control stream carries (spec §4.16,
/// QSH-06), from the record dictionary: its longest record, a `CHANNELS`
/// list of `MAX_CHANNELS` commands at `MAX_COMMAND_LEN`, is 32 841 bytes
/// (`channel.rs`'s test holds it under three quarters of this); the rest is
/// room for what a later version adds.
pub const CONTROL_RECORD_MAX: usize = 64 * 1024;

/// The longest record any other stream carries: the longest there is, a
/// channel's repaint (both screens, combining marks pushing some cells past
/// the roughly 44-bytes-a-cell estimate for one character and a full
/// truecolor pen) -- far past any real terminal's repaint, a 1000 x 1000
/// screen included.
pub const RECORD_MAX: usize = 64 * 1024 * 1024;

/// Envelope parser with a buffer for the unfinished tail. Yields records in
/// arrival order; an unfinished tail stays buffered until the next call.
///
/// A declared length past `max_payload` cannot be trusted to find the next
/// record either, so the parser does not try to skip past it: it stops
/// framing for good (`overflowed`) and drops everything pushed after that
/// (spec §4.16, QSH-06).
pub struct RecordDeframer {
    buf: Vec<u8>,
    max_payload: usize,
    overflowed: bool,
}

impl RecordDeframer {
    pub fn new() -> Self {
        Self::with_max_payload(RECORD_MAX)
    }

    /// A deframer for the session-control stream ([`CONTROL_RECORD_MAX`]).
    pub fn for_control() -> Self {
        Self::with_max_payload(CONTROL_RECORD_MAX)
    }

    /// A deframer that takes no record declaring more than `max_payload`.
    pub fn with_max_payload(max_payload: usize) -> Self {
        RecordDeframer {
            buf: Vec::new(),
            max_payload,
            overflowed: false,
        }
    }

    /// Whether a record declared more than the limit: from then on nothing
    /// is framed -- the length that would find the next record is the lie
    /// -- and everything pushed is dropped (spec §4.16, QSH-06).
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Bytes held for an unfinished record.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    pub fn push(&mut self, data: &[u8]) -> Vec<RawRecord> {
        if self.overflowed {
            return Vec::new();
        }
        self.buf.extend_from_slice(data);
        let mut out = Vec::new();
        let mut consumed = 0;
        loop {
            if self.buf.len() - consumed < HEADER_LEN {
                break;
            }
            let len = u32::from_be_bytes([
                self.buf[consumed + 1],
                self.buf[consumed + 2],
                self.buf[consumed + 3],
                self.buf[consumed + 4],
            ]) as usize;
            if len > self.max_payload {
                self.overflowed = true;
                self.buf = Vec::new();
                return out;
            }
            if self.buf.len() - consumed - HEADER_LEN < len {
                break;
            }
            let start = consumed + HEADER_LEN;
            out.push(RawRecord {
                kind: self.buf[consumed],
                payload: self.buf[start..start + len].to_vec(),
            });
            consumed = start + len;
        }
        self.buf.drain(..consumed);
        out
    }
}

impl Default for RecordDeframer {
    fn default() -> Self {
        Self::new()
    }
}

/// A record-stream parser with a buffer for the unfinished tail.
pub struct ShellDeframer {
    inner: RecordDeframer,
    error: Option<ShellCodecError>,
}

impl ShellDeframer {
    /// A new parser with an empty buffer.
    pub fn new() -> Self {
        ShellDeframer {
            inner: RecordDeframer::new(),
            error: None,
        }
    }

    /// Feed in newly arrived bytes and return all complete records. An
    /// unfinished tail stays in the buffer until the next call.
    pub fn push(&mut self, data: &[u8]) -> Vec<ShellRecord> {
        if self.error.is_some() {
            return Vec::new();
        }
        let mut records = Vec::new();
        for raw in self.inner.push(data) {
            match decode_shell(raw) {
                Ok(record) => records.push(record),
                Err(ShellCodecError::UnknownKind(_)) => {}
                Err(error) => {
                    self.error = Some(error);
                    // Do not retain a partial suffix after a failed boundary.
                    self.inner = RecordDeframer::new();
                    break;
                }
            }
        }
        records
    }

    /// A sticky failure. The owner must propagate it; subsequent pushes emit
    /// nothing. A new parser starts a new stream/attachment decoding scope.
    pub fn error(&self) -> Option<ShellCodecError> {
        self.error
    }

    /// Stop at a known record the owner cannot apply. The owner must also stop
    /// consuming its current batch; records after this boundary are invalid.
    pub fn reject_unsupported(&mut self, kind: u8) {
        self.error
            .get_or_insert(ShellCodecError::UnsupportedKind(kind));
        self.inner = RecordDeframer::new();
    }

    /// Whether a record declared past [`RECORD_MAX`] stopped this parser
    /// for good (spec §4.16, QSH-06) -- see [`RecordDeframer::overflowed`].
    /// Only a broken or hostile peer reaches this: a real repaint is far
    /// under the limit.
    pub fn overflowed(&self) -> bool {
        self.inner.overflowed()
    }
}

impl Default for ShellDeframer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        encode_record, RecordDeframer, ShellDeframer, ShellRecord, CONTROL_RECORD_MAX, REC_DATA,
        REC_ECHO_ACK,
    };

    #[test]
    fn encodes_data_record() {
        let r = encode_record(REC_DATA, b"hi");
        assert_eq!(r, vec![0x00, 0x00, 0x00, 0x00, 0x02, b'h', b'i']);
    }

    #[test]
    fn roundtrips_data_and_echo_ack() {
        let mut d = ShellDeframer::new();
        let mut stream = encode_record(REC_DATA, b"out");
        stream.extend(encode_record(REC_ECHO_ACK, &7u64.to_be_bytes()));
        let recs = d.push(&stream);
        assert_eq!(recs.len(), 2);
        assert!(matches!(&recs[0], ShellRecord::Data(v) if v == b"out"));
        assert!(matches!(recs[1], ShellRecord::EchoAck(7)));
    }

    #[test]
    fn holds_partial_record_until_complete() {
        let mut d = ShellDeframer::new();
        let full = encode_record(REC_DATA, b"abcd");
        // Only part of the header+body arrives.
        assert!(d.push(&full[..3]).is_empty());
        // The rest arrives -- the record is complete.
        let recs = d.push(&full[3..]);
        assert_eq!(recs.len(), 1);
        assert!(matches!(&recs[0], ShellRecord::Data(v) if v == b"abcd"));
    }

    #[test]
    fn coalesced_records_all_parsed() {
        let mut d = ShellDeframer::new();
        let mut s = encode_record(REC_DATA, b"a");
        s.extend(encode_record(REC_DATA, b"b"));
        s.extend(encode_record(REC_ECHO_ACK, &1u64.to_be_bytes()));
        let recs = d.push(&s);
        assert_eq!(recs.len(), 3);
    }

    #[test]
    fn skips_unknown_record_type_by_length_header() {
        // An unknown record type (9) is consumed by its explicit length
        // header, without desync: the valid DATA record following it is
        // parsed normally.
        let mut d = ShellDeframer::new();
        let mut s = encode_record(9, b"???");
        s.extend(encode_record(REC_DATA, b"ok"));
        let recs = d.push(&s);
        assert_eq!(recs.len(), 1);
        assert!(matches!(&recs[0], ShellRecord::Data(v) if v == b"ok"));
    }

    #[test]
    fn malformed_echo_ack_stops_before_following_data() {
        let mut d = ShellDeframer::new();
        let mut s = encode_record(REC_ECHO_ACK, &[0u8; 4]);
        s.extend(encode_record(REC_DATA, b"ok"));
        assert!(d.push(&s).is_empty());
        assert_eq!(d.error(), Some(super::ShellCodecError::Malformed));
    }

    #[test]
    fn fragmented_input_reassembles_byte_by_byte() {
        // Byte-by-byte delivery (worst case of reliable-stream
        // fragmentation): every `push` contains exactly one byte. No
        // intermediate call should either lose data or assemble a record
        // early -- both records are ready only once the last byte of their
        // payload arrives.
        let mut d = ShellDeframer::new();
        let mut stream = encode_record(REC_DATA, b"out");
        stream.extend(encode_record(REC_ECHO_ACK, &7u64.to_be_bytes()));

        let mut collected = Vec::new();
        for byte in &stream {
            collected.extend(d.push(&[*byte]));
        }

        assert_eq!(collected.len(), 2);
        assert!(matches!(&collected[0], ShellRecord::Data(v) if v == b"out"));
        assert!(matches!(collected[1], ShellRecord::EchoAck(7)));
    }

    #[test]
    fn a_huge_declared_length_stops_the_deframer_without_panicking() {
        // A garbage length (clearly unreachable in practice, and well past
        // RECORD_MAX) must not crash the parser via overflow/panic. It is
        // also past the deframer's max_payload, so this stops it for good
        // (spec §4.16, QSH-06) rather than leaving it "incomplete" waiting
        // for bytes that would never arrive in sufficient quantity.
        let mut d = ShellDeframer::new();
        let mut header = vec![REC_DATA];
        header.extend_from_slice(&u32::MAX.to_be_bytes());
        let recs = d.push(&header);
        assert!(recs.is_empty(), "a record past the limit yields nothing");

        // Nothing after it is framed either -- the deframer stopped for good.
        let recs2 = d.push(b"still not nearly enough bytes to complete it");
        assert!(recs2.is_empty());
    }

    /// Spec §4.16 (QSH-06): a record that declares more than its stream can
    /// carry stops the deframer for good -- the length that would find the
    /// next record is the lie -- and nothing of it is held. Records before
    /// it are kept.
    #[test]
    fn a_record_declared_past_the_limit_stops_the_deframer_and_holds_nothing() {
        let mut d = RecordDeframer::for_control();
        let mut bytes = encode_record(0x20, &[16]);
        bytes.push(0x10);
        bytes.extend_from_slice(&u32::try_from(CONTROL_RECORD_MAX + 1).unwrap().to_be_bytes());
        bytes.extend(vec![0u8; 1024]);
        let raws = d.push(&bytes);
        assert_eq!(raws.len(), 1, "the record before the lie");
        assert!(d.overflowed());
        assert_eq!(d.buffered_len(), 0);
        assert!(
            d.push(&encode_record(0x20, &[17])).is_empty(),
            "nothing after it"
        );
        assert_eq!(d.buffered_len(), 0);
    }

    /// A record exactly at the limit is read.
    #[test]
    fn a_record_at_the_limit_is_read() {
        let mut d = RecordDeframer::for_control();
        let raws = d.push(&encode_record(0x20, &vec![1u8; CONTROL_RECORD_MAX]));
        assert_eq!(raws.len(), 1);
        assert!(!d.overflowed());
    }
}

#[cfg(test)]
mod geometry_codec_tests {
    use super::*;

    #[test]
    fn geometry_data_ack_order() {
        let geometry = [
            0x02, 0, 0, 0, 22, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 80, 0, 24,
        ];
        let gap = [0x03, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 1, 1];
        let mut bytes = encode_record(REC_DATA, b"before");
        bytes.extend(geometry);
        bytes.extend(encode_record(REC_DATA, b"after"));
        bytes.extend(encode_record(REC_ECHO_ACK, &7u64.to_be_bytes()));
        bytes.extend(gap);
        for split in 0..=bytes.len() {
            let mut parser = ShellDeframer::new();
            let mut records = parser.push(&bytes[..split]);
            records.extend(parser.push(&bytes[split..]));
            assert_eq!(records.len(), 5, "geometry and gap cannot disappear");
            assert_eq!(records[0], ShellRecord::Data(b"before".to_vec()));
            assert!(matches!(
                records[1],
                ShellRecord::Geometry(GeometryRecord {
                    request_id: 1,
                    outcome: GeometryOutcome::Applied,
                    cols: 80,
                    rows: 24,
                    ..
                })
            ));
            assert!(matches!(
                records[4],
                ShellRecord::OutputGap {
                    cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
                    ..
                }
            ));
            assert_eq!(records[2], ShellRecord::Data(b"after".to_vec()));
            assert_eq!(records[3], ShellRecord::EchoAck(7));
        }
    }
}

#[cfg(test)]
mod geometry_validation_tests {
    use super::*;

    fn geometry_payload() -> Vec<u8> {
        vec![
            1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 6, 5, 4, 3, 2, 1, 2, 3, 1, 255, 0, 24,
        ]
    }

    #[test]
    fn geometry_exact_wire_and_splits() {
        let payload = geometry_payload();
        let bytes = [vec![2, 0, 0, 0, 22], payload].concat();
        let expected = ShellRecord::Geometry(GeometryRecord {
            instance: ChannelInstance::new(0x0102030405060708).unwrap(),
            request_id: 0x0807060504030201,
            outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
            cols: 511,
            rows: 24,
        });
        assert_eq!(encode_shell(&expected).unwrap(), bytes);
        for split in 0..=bytes.len() {
            let mut parser = ShellDeframer::new();
            let mut records = parser.push(&bytes[..split]);
            records.extend(parser.push(&bytes[split..]));
            assert_eq!(records, vec![expected.clone()]);
            assert_eq!(parser.error(), None);
        }
    }

    #[test]
    fn geometry_rejects_invalid_fields() {
        let valid = geometry_payload();
        let mut cases = Vec::new();
        for len in 0..22 {
            cases.push(valid[..len].to_vec());
        }
        cases.push([valid.clone(), vec![0]].concat());
        for (field, value) in [(16, 3), (17, 0), (17, 6), (18, 3), (20, 2)] {
            let mut p = valid.clone();
            p[field] = value;
            cases.push(p);
        }
        for range in [0..8, 8..16] {
            let mut p = valid.clone();
            p[range].fill(0);
            cases.push(p);
        }
        // Established cannot carry correlation or a reason; Applied has no reason.
        for (outcome, reason) in [(0, 0), (0, 3), (1, 3)] {
            let mut p = valid.clone();
            p[16] = outcome;
            p[17] = reason;
            cases.push(p);
        }
        for payload in cases {
            assert_eq!(
                decode_shell(RawRecord { kind: 2, payload }),
                Err(ShellCodecError::Malformed)
            );
        }
        for reason in 1..=5 {
            let mut payload = valid.clone();
            payload[17] = reason;
            assert!(decode_shell(RawRecord { kind: 2, payload }).is_ok());
        }
        let mut established = valid;
        established[8..18].fill(0);
        assert!(decode_shell(RawRecord {
            kind: 2,
            payload: established
        })
        .is_ok());
        assert_eq!(
            decode_shell(RawRecord {
                kind: 0xff,
                payload: vec![]
            }),
            Err(ShellCodecError::UnknownKind(0xff))
        );
    }

    #[test]
    fn gap_exact_wire_and_rejects_unknown_cause_or_zero_instance() {
        let expected = ShellRecord::OutputGap {
            instance: ChannelInstance::new(0x0102030405060708).unwrap(),
            cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
        };
        let bytes = [3, 0, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 1];
        assert_eq!(encode_shell(&expected).unwrap(), bytes);
        for split in 0..=bytes.len() {
            let mut parser = ShellDeframer::new();
            let mut records = parser.push(&bytes[..split]);
            records.extend(parser.push(&bytes[split..]));
            assert_eq!(records, vec![expected.clone()]);
        }
        let valid = bytes[5..].to_vec();
        let mut invalid = vec![];
        for len in 0..9 {
            invalid.push(valid[..len].to_vec());
        }
        invalid.push([valid.clone(), vec![0]].concat());
        for cause in [0, 3, 255] {
            let mut p = valid.clone();
            p[8] = cause;
            invalid.push(p);
        }
        invalid.push(vec![0, 0, 0, 0, 0, 0, 0, 0, 1]);
        for payload in invalid {
            assert_eq!(
                decode_shell(RawRecord { kind: 3, payload }),
                Err(ShellCodecError::Malformed)
            );
        }
    }

    #[test]
    fn malformed_boundary_preserves_prefix_and_blocks_suffix_until_new_parser() {
        for kind in [REC_GEOMETRY, REC_OUTPUT_GAP] {
            let bytes = [
                encode_record(REC_DATA, b"prefix"),
                encode_record(kind, &[]),
                encode_record(REC_DATA, b"suffix"),
            ]
            .concat();
            for split in 0..=bytes.len() {
                let mut parser = ShellDeframer::new();
                let mut records = parser.push(&bytes[..split]);
                records.extend(parser.push(&bytes[split..]));
                assert_eq!(records, vec![ShellRecord::Data(b"prefix".to_vec())]);
                assert_eq!(parser.error(), Some(ShellCodecError::Malformed));
                assert!(parser.push(&encode_record(REC_DATA, b"later")).is_empty());
                parser = ShellDeframer::new();
                assert_eq!(parser.error(), None);
                assert_eq!(
                    parser.push(&encode_record(REC_DATA, b"new")),
                    vec![ShellRecord::Data(b"new".to_vec())]
                );
            }
        }
    }

    #[test]
    fn unknown_extension_does_not_poison_a_geometry_boundary() {
        let bytes = [
            encode_record(255, b"extension"),
            encode_record(2, &geometry_payload()),
        ]
        .concat();
        let mut parser = ShellDeframer::new();
        assert!(matches!(
            &parser.push(&bytes)[..],
            [ShellRecord::Geometry(_)]
        ));
        assert_eq!(parser.error(), None);
    }
}

#[cfg(test)]
mod terminal_reply_failure_tests {
    use super::*;

    #[test]
    fn reply44_failure_is_a_distinct_exact_gap_record_and_unknown_causes_stay_invalid() {
        let payload = vec![0, 0, 0, 0, 0, 0, 0, 7, 2];
        let decoded = decode_shell(RawRecord {
            kind: REC_OUTPUT_GAP,
            payload,
        });
        assert!(
            decoded.is_ok(),
            "terminal reply failure must remain an ordered continuity disclosure: {decoded:?}"
        );
        let decoded = decoded.unwrap();
        assert!(
            matches!(&decoded, ShellRecord::OutputGap { instance, cause } if instance.get() == 7 && *cause as u8 == 2)
        );
        assert_eq!(
            encode_shell(&decoded).unwrap(),
            vec![3, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 7, 2]
        );
        for cause in [0, 3, 255] {
            assert_eq!(
                decode_shell(RawRecord {
                    kind: REC_OUTPUT_GAP,
                    payload: vec![0, 0, 0, 0, 0, 0, 0, 7, cause],
                }),
                Err(ShellCodecError::Malformed)
            );
        }
        let old = ShellRecord::OutputGap {
            instance: ChannelInstance::new(7).unwrap(),
            cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
        };
        assert_eq!(
            encode_shell(&old).unwrap(),
            vec![3, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 7, 1]
        );
    }
}
