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

/// A data record: raw PTY output bytes.
pub const REC_DATA: u8 = 0;

/// An input acknowledgment record: payload = offset of input bytes consumed
/// by the server (`u64` BE).
pub const REC_ECHO_ACK: u8 = 1;

/// A parsed shell-stream record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShellRecord {
    /// PTY output bytes -> into the terminal emulator.
    Data(Vec<u8>),
    /// Acknowledgment: the server has consumed this many input bytes (offset).
    EchoAck(u64),
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
}

impl ShellDeframer {
    /// A new parser with an empty buffer.
    pub fn new() -> Self {
        ShellDeframer {
            inner: RecordDeframer::new(),
        }
    }

    /// Feed in newly arrived bytes and return all complete records. An
    /// unfinished tail stays in the buffer until the next call.
    pub fn push(&mut self, data: &[u8]) -> Vec<ShellRecord> {
        self.inner
            .push(data)
            .into_iter()
            .filter_map(|raw| match raw.kind {
                REC_DATA => Some(ShellRecord::Data(raw.payload)),
                REC_ECHO_ACK if raw.payload.len() == 8 => {
                    let mut n = [0u8; 8];
                    n.copy_from_slice(&raw.payload);
                    Some(ShellRecord::EchoAck(u64::from_be_bytes(n)))
                }
                // Unknown type or malformed ECHO_ACK -- the envelope was
                // still well-formed and is consumed by its declared length
                // (no desync possible since the length is explicit), we
                // just drop the record.
                _ => None,
            })
            .collect()
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
    fn skips_malformed_echo_ack_by_length_header() {
        // An ECHO_ACK with a payload that isn't 8 bytes (here 4) doesn't
        // match the u64 format, so it's consumed by its length and ignored
        // rather than crashing the parser; the following valid DATA record
        // arrives normally.
        let mut d = ShellDeframer::new();
        let mut s = encode_record(REC_ECHO_ACK, &[0u8; 4]);
        s.extend(encode_record(REC_DATA, b"ok"));
        let recs = d.push(&s);
        assert_eq!(recs.len(), 1);
        assert!(matches!(&recs[0], ShellRecord::Data(v) if v == b"ok"));
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
