//! Ordered QSH channel framing. ChannelSession owns lifecycle and geometry;
//! this substrate owns only per-stream decoding and the outbound wire mapping.
//! Exit does not retire a deframer: the owner first releases prior received
//! output and any partial record. Channel reuse starts with fresh framing.

use std::collections::HashMap;
#[path = "qsh_input.rs"]
mod input;
use input::Input;

pub use crate::channel::ChannelProtocolError as QshProtocolError;
use crate::channel::{
    ChannelId, ChannelSubstrate, InputLimits, InputUsage, ResizeSemantics, SubstrateEvent,
};
use transport::channel::{
    decode_server, encode_client, ChannelCodecError, ClientRecord, OpenRequest, ServerRecord,
    CONTROL_STREAM, FIRST_CHANNEL_STREAM,
};
use transport::channel_geometry::{ChannelInstance, ResizeRequestId};
// Only the tests build an `OpenRequest` directly; production code merely
// clones one handed to it by `crate::channel`, so keep this out of a
// non-test build.
#[cfg(test)]
use transport::channel::ChannelKind;
#[cfg(test)]
use transport::channel_geometry::ProtocolErrorCode;
#[cfg(test)]
use transport::shell_frame::REC_GEOMETRY;
use transport::shell_frame::{decode_shell, ShellCodecError, ShellRecord};

/// Lays [`crate::channel::ChannelSession`] onto a qsh connection: session
/// control records travel framed on [`CONTROL_STREAM`], and each channel's
/// bytes travel framed (`Data`/`EchoAck`) on the stream that is the
/// channel's own identity.
pub struct QshSubstrate<F: FnMut(u8, Vec<u8>)> {
    /// Where every outgoing frame is handed to, as `(stream, bytes)`.
    sink: F,
    protocol_error: Option<QshProtocolError>,
    /// Deframer for `CONTROL_STREAM`: session-control records only.
    control: Input,
    /// Partial input remains owned here until explicit retirement or reset.
    channels: HashMap<ChannelId, Input>,
    /// Where a malformed `CONTROL_STREAM` record is reported, if the owner
    /// asked to know -- see [`Self::on_malformed_control`]. This crate has
    /// no logging of its own (the host may already own the terminal), so it
    /// never writes anywhere on its own; a no-op default means every test
    /// in this file, and any owner indifferent to this, pays nothing for
    /// the field.
    on_malformed_control: Box<dyn FnMut(&str) + Send>,
}

impl<F: FnMut(u8, Vec<u8>)> QshSubstrate<F> {
    /// A fresh substrate with no channels open yet, handing every outgoing
    /// frame to `send` as `(stream, bytes)`.
    pub fn new(send: F) -> Self {
        QshSubstrate {
            sink: send,
            protocol_error: None,
            control: Input::default(),
            channels: HashMap::new(),
            on_malformed_control: Box::new(|_| {}),
        }
    }

    /// Forgets everything half-read, on every stream: the session is now on
    /// a NEW connection, whose streams all start from the beginning.
    pub fn reset_link(&mut self) {
        self.protocol_error = None;
        self.control = Input::default();
        self.channels.clear();
    }

    /// Sticky failure until the owner starts a new attachment. ChannelSession
    /// emits the corresponding typed terminal failure, never a fake Exit.
    pub fn protocol_error(&self) -> Option<QshProtocolError> {
        self.protocol_error
    }

    fn fail_protocol(&mut self, error: QshProtocolError) {
        if self.protocol_error.is_none() {
            self.protocol_error = Some(error);
            self.channels.clear();
            self.control = Input::default();
            (self.on_malformed_control)(&format!("qsh protocol error: {error:?}"));
        }
    }

    /// Reports a malformed `CONTROL_STREAM` record through `f` instead of
    /// dropping it in silence -- see [`Self::on_stream`]'s own docs for why
    /// that silence is worth fixing. The owner decides where it goes: the
    /// console client points it at its own file log (`cli/src/log.rs`),
    /// since this crate has none of its own to reach for.
    pub fn on_malformed_control(mut self, f: impl FnMut(&str) + Send + 'static) -> Self {
        self.on_malformed_control = Box::new(f);
        self
    }

    /// Conservative standalone decoding, bounded to one early-input batch.
    /// ChannelSession instead uses on_bytes_step, recomputing budgets after each
    /// event and allowing bounded DATA chunks once the channel is ready.
    pub fn on_stream(&mut self, stream: u8, bytes: &[u8]) -> Vec<SubstrateEvent> {
        let mut remaining = bytes;
        let mut out = Vec::new();
        let mut payload = 0usize;
        let mut retained = 0usize;
        while !remaining.is_empty() {
            let mut limits = InputLimits {
                payload: (64 * 1024usize).saturating_sub(payload),
                bytes: (512 * 1024usize).saturating_sub(retained),
                events: 256usize.saturating_sub(out.len()),
            };
            for (&ch, parser) in &self.channels {
                if ch != stream {
                    let used = parser.usage();
                    limits.bytes = limits.bytes.saturating_sub(used.bytes);
                    limits.events = limits.events.saturating_sub(used.events);
                }
            }
            let (used, events) = self.step(stream, remaining, limits);
            for event in &events {
                let bytes = match event {
                    SubstrateEvent::Data { bytes, .. } => {
                        payload += bytes.len();
                        bytes.len() + 5
                    }
                    SubstrateEvent::Snapshot(snapshot) => snapshot.payload_len() + 5,
                    SubstrateEvent::Refused { reason, .. } => reason.len() + 8,
                    _ => 27,
                };
                retained += bytes;
            }
            out.extend(events);
            if used == 0 {
                break;
            }
            remaining = &remaining[used..];
        }
        out
    }

    fn step(
        &mut self,
        stream: u8,
        bytes: &[u8],
        limits: InputLimits,
    ) -> (usize, Vec<SubstrateEvent>) {
        if self.protocol_error.is_some()
            || (stream != CONTROL_STREAM && stream < FIRST_CHANNEL_STREAM)
        {
            return (bytes.len(), Vec::new());
        }
        let control = stream == CONTROL_STREAM;
        let parser = if control {
            &mut self.control
        } else {
            self.channels.entry(stream).or_default()
        };
        let parsed = parser.step(bytes, limits, control);
        let error = match parsed {
            Err(error) => error,
            Ok((used, None)) => return (used, Vec::new()),
            Ok((used, Some(raw))) => {
                let event = if control {
                    match decode_server(&raw) {
                        Ok(record) => Ok(self.translate_control(record)),
                        Err(ChannelCodecError::UnknownKind(_)) => Ok(None),
                        Err(ChannelCodecError::Malformed) => {
                            Err(QshProtocolError::UnexpectedRecord(raw.kind))
                        }
                    }
                } else {
                    match decode_shell(raw) {
                        Ok(ShellRecord::Data(bytes)) => {
                            Ok(Some(SubstrateEvent::Data { ch: stream, bytes }))
                        }
                        Ok(ShellRecord::EchoAck(offset)) => {
                            Ok(Some(SubstrateEvent::InputConsumed { ch: stream, offset }))
                        }
                        Ok(ShellRecord::Geometry(record)) => {
                            Ok(Some(SubstrateEvent::Geometry { ch: stream, record }))
                        }
                        Ok(ShellRecord::OutputGap { instance, cause }) => {
                            Ok(Some(SubstrateEvent::OutputGap {
                                ch: stream,
                                instance,
                                cause,
                            }))
                        }
                        Err(ShellCodecError::UnknownKind(_)) => Ok(None),
                        Err(error) => Err(QshProtocolError::Shell(error)),
                    }
                };
                match event {
                    Ok(event) => return (used, event.into_iter().collect()),
                    Err(error) => error,
                }
            }
        };
        self.fail_protocol(error);
        (bytes.len(), vec![SubstrateEvent::ProtocolFailure(error)])
    }

    /// Control lifecycle metadata does not itself authorize ordered output.
    fn translate_control(&mut self, rec: ServerRecord) -> Option<SubstrateEvent> {
        Some(match rec {
            ServerRecord::ProtocolError { code } => {
                self.fail_protocol(QshProtocolError::Remote(code));
                return Some(SubstrateEvent::ProtocolFailure(QshProtocolError::Remote(
                    code,
                )));
            }
            ServerRecord::Opened { stream } => SubstrateEvent::Opened(stream),
            ServerRecord::Refused { stream, reason } => {
                self.end_channel(stream);
                SubstrateEvent::Refused { ch: stream, reason }
            }
            ServerRecord::Exit { stream, code } => SubstrateEvent::Exit { ch: stream, code },
            ServerRecord::Channels(_) => {
                self.fail_protocol(QshProtocolError::UnsupportedProfile);
                SubstrateEvent::ProtocolFailure(QshProtocolError::UnsupportedProfile)
            }
            ServerRecord::ChannelSnapshot(snapshot) => SubstrateEvent::Snapshot(snapshot),
            // The daemon talking about itself: handed up as it came.
            record @ (ServerRecord::About(_)
            | ServerRecord::UpdateAnswer(_)
            | ServerRecord::UpdateResult(_)
            | ServerRecord::Restarting) => SubstrateEvent::Daemon(record),
        })
    }

    /// Explicit owner retirement, refusal, or close releases partial framing.
    fn end_channel(&mut self, ch: ChannelId) {
        self.channels.remove(&ch);
    }
}

impl<F: FnMut(u8, Vec<u8>) + Send> ChannelSubstrate for QshSubstrate<F> {
    fn input_usage(&self, ch: ChannelId) -> InputUsage {
        self.channels
            .get(&ch)
            .map_or_else(InputUsage::default, Input::usage)
    }
    fn on_bytes_step(
        &mut self,
        stream: u8,
        bytes: &[u8],
        limits: InputLimits,
    ) -> (usize, Vec<SubstrateEvent>) {
        self.step(stream, bytes, limits)
    }
    fn resize_semantics(&self) -> ResizeSemantics {
        ResizeSemantics::ConfirmedOrdered
    }
    fn resize_correlated(
        &mut self,
        ch: ChannelId,
        instance: ChannelInstance,
        request_id: ResizeRequestId,
        cols: u16,
        rows: u16,
    ) -> Result<(), QshProtocolError> {
        if let Some(error) = self.protocol_error {
            return Err(error);
        }
        (self.sink)(
            CONTROL_STREAM,
            encode_client(&ClientRecord::ResizeRequest {
                stream: ch,
                instance,
                request_id,
                cols,
                rows,
            }),
        );
        Ok(())
    }
    fn retire_channel(&mut self, ch: ChannelId) {
        self.end_channel(ch);
    }
    fn has_partial_input(&self, ch: ChannelId) -> bool {
        self.channels
            .get(&ch)
            .is_some_and(|parser| parser.partial())
    }
    fn reset_attachment(&mut self) {
        self.reset_link();
    }
    fn protocol_failed(&mut self, error: QshProtocolError) {
        self.fail_protocol(error);
    }

    fn open(&mut self, req: &OpenRequest) {
        (self.sink)(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(req.clone())),
        );
    }

    /// Channel input goes out raw, on the channel's own stream: the whole
    /// stream belongs to it, so it needs no envelope of its own.
    fn send(&mut self, ch: ChannelId, data: &[u8]) {
        (self.sink)(ch, data.to_vec());
    }

    fn announce_term(&mut self, term: &str) {
        (self.sink)(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Term(term.to_string())),
        );
    }

    fn resize(&mut self, _ch: ChannelId, _cols: u16, _rows: u16) {
        self.fail_protocol(QshProtocolError::UnsupportedProfile);
    }

    fn close(&mut self, ch: ChannelId) {
        (self.sink)(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Close { stream: ch }),
        );
        self.end_channel(ch);
    }

    /// The trait's inbound half, so a `ChannelSession` can own the only
    /// instance of this substrate instead of a caller keeping a second one
    /// just to decode incoming bytes. Delegates to [`Self::on_stream`]
    /// rather than duplicating its body.
    fn on_bytes(&mut self, stream: u8, bytes: &[u8]) -> Vec<SubstrateEvent> {
        self.on_stream(stream, bytes)
    }

    /// Drops channel `ch`'s deframer, WITHOUT ending the channel: for a
    /// wire-level stream reset (the peer's backlog on this specific stream
    /// was dropped; a repaint follows on the same stream), where the
    /// channel keeps running and only whatever partial record its deframer
    /// was mid-way through needs discarding -- that record's byte offset
    /// belongs to a stream position the peer has now abandoned, and
    /// keeping it would splice the repaint's first bytes onto a leftover
    /// that no longer means anything.
    ///
    /// Same removal as [`Self::end_channel`], different reason -- callers
    /// should reach for this one, not that one, when the channel is not
    /// actually ending: recreating the WHOLE substrate to achieve the same
    /// effect would also discard `CONTROL_STREAM`'s own in-flight state,
    /// for no reason connected to this channel at all.
    fn reset_stream(&mut self, ch: ChannelId) {
        self.channels.remove(&ch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use transport::channel::encode_server;
    use transport::shell_frame::{encode_record, CONTROL_RECORD_MAX, REC_DATA, REC_ECHO_ACK};

    /// What `substrate()` recorded the fake wire receiving: `(stream, bytes)`
    /// per outgoing frame, in order.
    type Sent = Arc<Mutex<Vec<(u8, Vec<u8>)>>>;

    fn substrate() -> (QshSubstrate<impl FnMut(u8, Vec<u8>)>, Sent) {
        let sent: Sent = Arc::new(Mutex::new(Vec::new()));
        let s = sent.clone();
        (
            QshSubstrate::new(move |stream, data| s.lock().unwrap().push((stream, data))),
            sent,
        )
    }

    /// Control records go out on the control stream and channel bytes on the
    /// channel's own. Getting this backwards is exactly the mistake the
    /// stream layout exists to prevent.
    #[test]
    fn control_and_channel_bytes_go_on_their_own_streams() {
        let (mut sub, sent) = substrate();
        sub.open(&OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: true,
            command: Vec::new(),
        });
        sub.send(16, b"ls\r");

        let sent = sent.lock().unwrap();
        assert_eq!(
            sent[0].0, CONTROL_STREAM,
            "the open goes on the control stream"
        );
        assert_eq!(
            sent[1],
            (16u8, b"ls\r".to_vec()),
            "channel input goes raw on its own stream"
        );
    }

    /// A malformed `CONTROL_STREAM` record -- a known kind whose payload does
    /// not parse, not an unrecognised one -- is reported through
    /// `on_malformed_control` rather than dropped in silence: see
    /// `on_stream`'s own docs for what silently swallowing it used to cost
    /// (a channel stuck `Opening` forever with no evidence why).
    #[test]
    fn a_malformed_control_record_is_reported_not_silently_dropped() {
        let reports: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let r = reports.clone();
        let mut sub = QshSubstrate::new(|_, _| {})
            .on_malformed_control(move |msg| r.lock().unwrap().push(msg.to_string()));

        // `0x20` is `REC_OPENED` (a known kind), whose payload must be
        // exactly one byte (the stream number) -- an empty one is
        // malformed, not unrecognised.
        let malformed = encode_record(0x20, &[]);
        let events = sub.on_stream(CONTROL_STREAM, &malformed);

        assert_eq!(
            events,
            vec![SubstrateEvent::ProtocolFailure(
                QshProtocolError::UnexpectedRecord(0x20)
            )]
        );
        assert_eq!(
            reports.lock().unwrap().len(),
            1,
            "exactly one report for the one malformed record"
        );
    }

    /// An unrecognised record kind is the codec's own forward-compatibility
    /// mechanism, not a broken promise, and must not be reported as one.
    #[test]
    fn an_unknown_control_record_kind_is_not_reported() {
        let reports: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let r = reports.clone();
        let mut sub = QshSubstrate::new(|_, _| {})
            .on_malformed_control(move |msg| r.lock().unwrap().push(msg.to_string()));

        let unknown = encode_record(0x7f, b"a kind from a newer peer");
        let events = sub.on_stream(CONTROL_STREAM, &unknown);

        assert!(events.is_empty());
        assert!(
            reports.lock().unwrap().is_empty(),
            "an unrecognised kind is the codec's own forward-compatibility mechanism, not a broken promise"
        );
    }

    /// A control-stream header that lies about its length: an unknown kind,
    /// declaring one byte past `CONTROL_RECORD_MAX`. The overflow check
    /// reads only the header (spec §4.16, QSH-06), so no payload bytes are
    /// needed to trip it -- and this fails to trip at all if `control` were
    /// built with `RecordDeframer::new()` (a 64 MiB cap) instead of
    /// `for_control()` (64 KiB), which is exactly what this pins.
    fn control_overflow_lie() -> Vec<u8> {
        let mut lie = vec![0xffu8];
        lie.extend_from_slice(&u32::try_from(CONTROL_RECORD_MAX + 1).unwrap().to_be_bytes());
        lie
    }

    /// Spec §4.16 (QSH-06): a control stream that overflows is reported
    /// exactly once, not once per byte pushed after it -- pins
    /// `QshSubstrate::new`'s `for_control()` cap and `control_overflow_reported`'s
    /// stickiness.
    #[test]
    fn a_control_overflow_is_reported_exactly_once() {
        let reports: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let r = reports.clone();
        let mut sub = QshSubstrate::new(|_, _| {})
            .on_malformed_control(move |msg| r.lock().unwrap().push(msg.to_string()));

        let lie = control_overflow_lie();
        assert_eq!(
            sub.on_stream(CONTROL_STREAM, &lie),
            vec![SubstrateEvent::ProtocolFailure(
                QshProtocolError::EarlyOutputOverflow
            )]
        );
        assert_eq!(
            reports.lock().unwrap().len(),
            1,
            "the first overflow is reported"
        );

        // More bytes on the same (now-dead) control stream must not report
        // again.
        assert!(sub
            .on_stream(CONTROL_STREAM, &encode_record(0x20, &[17]))
            .is_empty());
        assert_eq!(
            reports.lock().unwrap().len(),
            1,
            "still just the one report -- not once per byte pushed after the lie"
        );
    }

    /// `reset_link` puts the control stream on a brand new connection: its
    /// overflow report must be able to fire again there, not stay
    /// permanently silenced by the old connection's one report. Pins
    /// `reset_link` rebuilding `control` with `for_control()` (not
    /// `new()`) and clearing `control_overflow_reported`.
    #[test]
    fn a_reset_link_lets_the_control_overflow_report_again() {
        let reports: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let r = reports.clone();
        let mut sub = QshSubstrate::new(|_, _| {})
            .on_malformed_control(move |msg| r.lock().unwrap().push(msg.to_string()));

        let lie = control_overflow_lie();
        sub.on_stream(CONTROL_STREAM, &lie);
        assert_eq!(reports.lock().unwrap().len(), 1);

        sub.reset_link();
        sub.on_stream(CONTROL_STREAM, &lie);
        assert_eq!(
            reports.lock().unwrap().len(),
            2,
            "a new connection's control stream can overflow and report again"
        );
    }

    /// Spec §4.16 (QSH-06): a CHANNEL stream that overflows must not freeze
    /// silently -- it is reported once, through the same hook as the
    /// control stream (Minor 4 of the task 6 review).
    #[test]
    fn a_channel_overflow_is_reported_once_through_the_same_hook() {
        let reports: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let r = reports.clone();
        let mut sub = QshSubstrate::new(|_, _| {})
            .on_malformed_control(move |msg| r.lock().unwrap().push(msg.to_string()));

        let mut lie = vec![0xffu8];
        lie.extend_from_slice(&u32::MAX.to_be_bytes());
        assert_eq!(
            sub.on_stream(16, &lie),
            vec![SubstrateEvent::ProtocolFailure(
                QshProtocolError::EarlyOutputOverflow
            )]
        );
        assert_eq!(
            reports.lock().unwrap().len(),
            1,
            "a channel stream that stops for good is reported, not silently frozen"
        );

        // More bytes on the same dead channel stream report nothing further.
        assert!(sub
            .on_stream(16, &encode_record(REC_DATA, b"more"))
            .is_empty());
        assert_eq!(
            reports.lock().unwrap().len(),
            1,
            "still just the one report"
        );
    }

    /// Each channel is deframed on its own: a record split across two
    /// deliveries on one channel must not disturb another. One shared
    /// deframer would interleave the two channels' bytes into nonsense.
    #[test]
    fn each_channel_is_deframed_on_its_own() {
        let (mut sub, _) = substrate();
        let a = encode_record(REC_DATA, b"first half second half");
        let b = encode_record(REC_DATA, b"other channel");

        // Channel 16 gets half a record, then channel 17 gets a whole one,
        // then channel 16 gets its tail.
        let split = a.len() / 2;
        assert!(
            sub.on_stream(16, &a[..split]).is_empty(),
            "half a record yields nothing"
        );
        assert_eq!(
            sub.on_stream(17, &b),
            vec![SubstrateEvent::Data {
                ch: 17,
                bytes: b"other channel".to_vec()
            }]
        );
        assert_eq!(
            sub.on_stream(16, &a[split..]),
            vec![SubstrateEvent::Data {
                ch: 16,
                bytes: b"first half second half".to_vec()
            }],
            "the interrupted channel resumes exactly where it stopped"
        );
    }

    /// An acknowledgment record becomes `InputConsumed` -- the offset
    /// prediction confirms against. A substrate that dropped it would leave
    /// every prediction pending forever.
    #[test]
    fn an_acknowledgment_becomes_an_input_consumed_event() {
        let (mut sub, _) = substrate();
        let wire = encode_record(REC_ECHO_ACK, &1234u64.to_be_bytes());
        assert_eq!(
            sub.on_stream(16, &wire),
            vec![SubstrateEvent::InputConsumed {
                ch: 16,
                offset: 1234
            }]
        );
    }

    /// A channel that exits with a record only half delivered must not
    /// leave its half-eaten deframer behind: `crate::channel`'s free-stream
    /// policy reuses the lowest freed stream number once every untouched
    /// one is gone, so a fresh channel opened later on the same number
    /// would otherwise inherit that stray tail and splice it onto its own
    /// first bytes -- exactly the corruption
    /// `each_channel_is_deframed_on_its_own` rules out for two channels open
    /// at once, just stretched out in time instead.
    #[test]
    fn owner_retirement_after_exit_discards_deframer_for_reused_stream() {
        let (mut sub, _) = substrate();

        // Half a record lands on channel 16, then the server reports the
        // channel exited before the other half ever arrives.
        let stray = encode_record(REC_DATA, b"first half second half");
        let split = stray.len() / 2;
        assert!(sub.on_stream(16, &stray[..split]).is_empty());
        let exit = encode_server(&ServerRecord::Exit {
            stream: 16,
            code: 0,
        });
        assert_eq!(
            sub.on_stream(CONTROL_STREAM, &exit),
            vec![SubstrateEvent::Exit { ch: 16, code: 0 }]
        );

        // Stream 16 is reused by a brand new channel, which gets a whole
        // record of its own.
        assert!(
            sub.has_partial_input(16),
            "Exit cannot discard prior received partial output"
        );
        sub.retire_channel(16);
        let fresh = encode_record(REC_DATA, b"brand new");
        assert_eq!(
            sub.on_stream(16, &fresh),
            vec![SubstrateEvent::Data {
                ch: 16,
                bytes: b"brand new".to_vec()
            }],
            "the reused stream must not inherit the old channel's half-eaten record"
        );
    }

    /// Same corruption, reached through a server `Refused` instead of an
    /// `Exit`: a channel can be torn down before it ever opens.
    #[test]
    fn a_channels_deframer_is_dropped_on_refusal_so_a_reused_stream_starts_clean() {
        let (mut sub, _) = substrate();

        let stray = encode_record(REC_DATA, b"first half second half");
        let split = stray.len() / 2;
        assert!(sub.on_stream(16, &stray[..split]).is_empty());
        let refused = encode_server(&ServerRecord::Refused {
            stream: 16,
            reason: "busy".to_string(),
        });
        sub.on_stream(CONTROL_STREAM, &refused);

        let fresh = encode_record(REC_DATA, b"brand new");
        assert_eq!(
            sub.on_stream(16, &fresh),
            vec![SubstrateEvent::Data {
                ch: 16,
                bytes: b"brand new".to_vec()
            }],
            "the reused stream must not inherit the refused channel's half-eaten record"
        );
    }

    /// Same corruption again, reached through the local `close()` call
    /// rather than a server-initiated event: closing a channel must clean
    /// up just as thoroughly as the server ending it does.
    #[test]
    fn closing_a_channel_drops_its_deframer_so_a_reused_stream_starts_clean() {
        let (mut sub, _) = substrate();

        let stray = encode_record(REC_DATA, b"first half second half");
        let split = stray.len() / 2;
        assert!(sub.on_stream(16, &stray[..split]).is_empty());
        sub.close(16);

        let fresh = encode_record(REC_DATA, b"brand new");
        assert_eq!(
            sub.on_stream(16, &fresh),
            vec![SubstrateEvent::Data {
                ch: 16,
                bytes: b"brand new".to_vec()
            }],
            "the reused stream must not inherit the closed channel's half-eaten record"
        );
    }

    /// A session that moved to a new link must read that link's control
    /// stream from its first byte, not splice it onto the old link's half.
    #[test]
    fn a_reset_link_forgets_a_half_read_control_record() {
        let (mut sub, _) = substrate();
        let rec = encode_server(&ServerRecord::Opened { stream: 16 });
        assert!(sub.on_stream(CONTROL_STREAM, &rec[..3]).is_empty());
        sub.reset_link();
        assert_eq!(
            sub.on_stream(CONTROL_STREAM, &rec),
            vec![SubstrateEvent::Opened(16)],
            "the new link's first record is read from its own first byte"
        );
    }

    /// A wire-level reset of one channel's stream must clean up just that
    /// channel's half-eaten record -- not force the caller to recreate the
    /// WHOLE substrate (losing `CONTROL_STREAM`'s own in-flight state along
    /// with it) just to achieve the same thing for one stream.
    #[test]
    fn reset_stream_drops_only_the_named_channels_deframer() {
        let (mut sub, _) = substrate();

        let stray = encode_record(REC_DATA, b"first half second half");
        let split = stray.len() / 2;
        assert!(sub.on_stream(16, &stray[..split]).is_empty());
        sub.reset_stream(16);

        let fresh = encode_record(REC_DATA, b"brand new");
        assert_eq!(
            sub.on_stream(16, &fresh),
            vec![SubstrateEvent::Data {
                ch: 16,
                bytes: b"brand new".to_vec()
            }],
            "the reset channel's stream must not inherit its own half-eaten record"
        );
    }

    /// A stream below the channel range (1..=15, where the auth stream
    /// lives) can never legitimately carry channel data. Bytes arriving
    /// there are dropped outright rather than starting a deframer for a
    /// stream number that was never a channel's to begin with.
    #[test]
    fn bytes_on_a_reserved_stream_below_the_channel_range_are_dropped() {
        let (mut sub, _) = substrate();
        let wire = encode_record(REC_DATA, b"should never happen");
        assert!(
            sub.on_stream(FIRST_CHANNEL_STREAM - 1, &wire).is_empty(),
            "a stream just below the channel range yields no event"
        );
    }

    /// The substrate's inbound half is reachable through the trait, so the
    /// session can own the only instance.
    #[test]
    fn bytes_arrive_through_the_trait_method() {
        let (mut sub, _) = substrate();
        let wire = encode_record(REC_DATA, b"through the trait");
        assert_eq!(
            ChannelSubstrate::on_bytes(&mut sub, 16, &wire),
            vec![SubstrateEvent::Data {
                ch: 16,
                bytes: b"through the trait".to_vec()
            }],
        );
    }

    /// The daemon talking about itself has nothing to do with a channel: the
    /// record goes up as it came, for whoever asked.
    #[test]
    fn a_daemon_record_is_handed_up_as_it_is() {
        let (mut sub, _) = substrate();
        let wire = encode_server(&ServerRecord::UpdateResult(
            transport::channel::UpdateResult::Restarting,
        ));
        assert_eq!(
            sub.on_stream(CONTROL_STREAM, &wire),
            vec![SubstrateEvent::Daemon(ServerRecord::UpdateResult(
                transport::channel::UpdateResult::Restarting
            ))]
        );
    }
}

#[cfg(test)]
mod geometry_profile_tests {
    use super::*;
    use transport::channel_geometry::{GeometryOutcome, GeometryRecord, OutputGapCause};
    use transport::shell_frame::{encode_record, encode_shell, REC_DATA};

    #[test]
    fn atomic_snapshot_preserves_draining_and_rejects_malformed_at_every_split() {
        let snapshot = transport::channel::ChannelSnapshot::new(
            Vec::new(),
            vec![transport::channel::DrainingChannel {
                stream: 16,
                instance: ChannelInstance::new(1).unwrap(),
                open: transport::channel::OpenClassification {
                    kind: ChannelKind::Command,
                    cols: 0,
                    rows: 24,
                    screen: false,
                },
            }],
        )
        .unwrap();
        for (bytes, expected) in [
            (snapshot.encode_record(), SubstrateEvent::Snapshot(snapshot)),
            (
                encode_record(transport::channel::REC_CHANNEL_SNAPSHOT, &[9]),
                SubstrateEvent::ProtocolFailure(QshProtocolError::UnexpectedRecord(
                    transport::channel::REC_CHANNEL_SNAPSHOT,
                )),
            ),
        ] {
            for split in 0..=bytes.len() {
                let mut sub = QshSubstrate::new(|_, _| {});
                let mut events = sub.on_stream(CONTROL_STREAM, &bytes[..split]);
                events.extend(sub.on_stream(CONTROL_STREAM, &bytes[split..]));
                assert_eq!(events, vec![expected.clone()]);
            }
        }
    }
    #[test]
    fn geometry_and_gap_keep_order_at_every_split() {
        let instance = ChannelInstance::new(1).unwrap();
        let geometry = GeometryRecord {
            instance,
            request_id: 0,
            outcome: GeometryOutcome::Established,
            cols: 80,
            rows: 24,
        };
        for (record, event) in [
            (
                ShellRecord::Geometry(geometry),
                SubstrateEvent::Geometry {
                    ch: 16,
                    record: geometry,
                },
            ),
            (
                ShellRecord::OutputGap {
                    instance,
                    cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
                },
                SubstrateEvent::OutputGap {
                    ch: 16,
                    instance,
                    cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
                },
            ),
        ] {
            let bytes = [
                encode_record(REC_DATA, b"before"),
                encode_shell(&record).unwrap(),
                encode_record(REC_DATA, b"after"),
            ]
            .concat();
            for split in 0..=bytes.len() {
                let mut sub = QshSubstrate::new(|_, _| {});
                let mut events = sub.on_stream(16, &bytes[..split]);
                events.extend(sub.on_stream(16, &bytes[split..]));
                assert_eq!(
                    events,
                    vec![
                        SubstrateEvent::Data {
                            ch: 16,
                            bytes: b"before".to_vec()
                        },
                        event.clone(),
                        SubstrateEvent::Data {
                            ch: 16,
                            bytes: b"after".to_vec()
                        }
                    ]
                );
                assert_eq!(sub.protocol_error(), None);
            }
        }
    }
    #[test]
    fn malformed_geometry_and_remote_protocol_error_are_explicit_and_terminal() {
        let mut sub = QshSubstrate::new(|_, _| {});
        let error = QshProtocolError::Shell(ShellCodecError::Malformed);
        assert_eq!(
            sub.on_stream(16, &encode_record(REC_GEOMETRY, &[])),
            vec![SubstrateEvent::ProtocolFailure(error)]
        );
        assert_eq!(sub.protocol_error(), Some(error));
        sub.reset_stream(16);
        assert_eq!(sub.protocol_error(), Some(error));
        assert!(sub
            .on_stream(16, &encode_record(REC_DATA, b"late"))
            .is_empty());
        sub.reset_link();
        assert_eq!(sub.protocol_error(), None);
        let mut bytes = transport::channel::encode_server(&ServerRecord::ProtocolError {
            code: ProtocolErrorCode::ResizePipelineOverflow,
        });
        bytes.extend(transport::channel::encode_server(&ServerRecord::Opened {
            stream: 16,
        }));
        let error = QshProtocolError::Remote(ProtocolErrorCode::ResizePipelineOverflow);
        assert_eq!(
            sub.on_stream(CONTROL_STREAM, &bytes),
            vec![SubstrateEvent::ProtocolFailure(error)]
        );
        assert_eq!(sub.protocol_error(), Some(error));
    }
}
