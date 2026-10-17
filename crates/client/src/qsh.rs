//! The qsh substrate: lays the channel session model (`crate::channel`) onto
//! a real qsh connection.
//!
//! Two decisions live here and nowhere else. Which wire stream a byte goes
//! on: session-control records always go out on `CONTROL_STREAM`, while a
//! channel's own bytes go out raw on the stream that IS the channel's
//! identity. And how a channel's stream is deframed back into records: each
//! channel keeps its own deframer, dropped the moment the channel ends (an
//! explicit close, a refusal, or an exit), so a record split across two
//! deliveries on one channel never disturbs another AND a stream number
//! reused for a later channel never inherits a dead one's half-eaten
//! leftovers. An acknowledgment record becomes `SubstrateEvent::InputConsumed`
//! instead of being dropped -- a substrate with no output framing has no
//! acknowledgment to hand back, which is exactly why prediction cannot run
//! over SSH, whose substrate has none to give.

use std::collections::{HashMap, HashSet};

use crate::channel::{ChannelId, ChannelSubstrate, SubstrateEvent};
use transport::channel::{
    decode_server, encode_client, ChannelCodecError, ClientRecord, OpenRequest, ServerRecord,
    CONTROL_STREAM, FIRST_CHANNEL_STREAM,
};
// Only the tests build an `OpenRequest` directly; production code merely
// clones one handed to it by `crate::channel`, so keep this out of a
// non-test build.
#[cfg(test)]
use transport::channel::ChannelKind;
use transport::shell_frame::{RecordDeframer, ShellDeframer, ShellRecord};

/// Lays [`crate::channel::ChannelSession`] onto a qsh connection: session
/// control records travel framed on [`CONTROL_STREAM`], and each channel's
/// bytes travel framed (`Data`/`EchoAck`) on the stream that is the
/// channel's own identity.
pub struct QshSubstrate<F: FnMut(u8, Vec<u8>)> {
    /// Where every outgoing frame is handed to, as `(stream, bytes)`.
    sink: F,
    /// Deframer for `CONTROL_STREAM`: session-control records only.
    control: RecordDeframer,
    /// One deframer per channel's own stream, removed the moment the
    /// channel ends (see [`Self::end_channel`]). A single shared deframer
    /// would interleave two channels' bytes into nonsense the moment a
    /// record from each is in flight at once -- see
    /// `each_channel_is_deframed_on_its_own` below; leaving a dead
    /// channel's entry behind causes the same nonsense stretched out in
    /// time, once `crate::channel`'s free-stream policy reuses its stream
    /// number for a new channel -- see
    /// `a_channels_deframer_is_dropped_on_exit_so_a_reused_stream_starts_clean`.
    channels: HashMap<ChannelId, ShellDeframer>,
    /// Where a malformed `CONTROL_STREAM` record is reported, if the owner
    /// asked to know -- see [`Self::on_malformed_control`]. This crate has
    /// no logging of its own (the host may already own the terminal), so it
    /// never writes anywhere on its own; a no-op default means every test
    /// in this file, and any owner indifferent to this, pays nothing for
    /// the field.
    on_malformed_control: Box<dyn FnMut(&str) + Send>,
    /// Whether [`Self::on_malformed_control`] has already been told about
    /// the control stream overflowing (spec §4.16, QSH-06): reported once
    /// per connection, like the daemon's own log line, not once per byte
    /// pushed after it.
    control_overflow_reported: bool,
    /// Which channels' overflow has already been told to
    /// [`Self::on_malformed_control`] (spec §4.16, QSH-06): a channel whose
    /// deframer stops for good is reported once, like the control stream,
    /// so a frozen channel is not a silent one. Cleared per channel when
    /// its entry in `channels` is (the same three occasions), so a stream
    /// number reused for a later channel starts able to report again.
    channel_overflow_reported: HashSet<ChannelId>,
}

impl<F: FnMut(u8, Vec<u8>)> QshSubstrate<F> {
    /// A fresh substrate with no channels open yet, handing every outgoing
    /// frame to `send` as `(stream, bytes)`.
    pub fn new(send: F) -> Self {
        QshSubstrate {
            sink: send,
            control: RecordDeframer::for_control(),
            channels: HashMap::new(),
            on_malformed_control: Box::new(|_| {}),
            control_overflow_reported: false,
            channel_overflow_reported: HashSet::new(),
        }
    }

    /// Forgets everything half-read, on every stream: the session is now on
    /// a NEW connection, whose streams all start from the beginning.
    pub fn reset_link(&mut self) {
        self.control = RecordDeframer::for_control();
        self.channels.clear();
        self.control_overflow_reported = false;
        self.channel_overflow_reported.clear();
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

    /// Bytes newly arrived on `stream`, turned into the events they carry.
    /// `CONTROL_STREAM` yields session-control events (`Opened`, `Refused`,
    /// `Exit`, `Announced`); a stream in `FIRST_CHANNEL_STREAM..=255` is a
    /// channel's own and yields `Data`/`InputConsumed`. Anything below
    /// `FIRST_CHANNEL_STREAM` (the reserved range that holds the auth
    /// stream) is not a channel and never will be, so it is dropped
    /// outright rather than starting a deframer for a stream number that
    /// could never legitimately carry channel data.
    pub fn on_stream(&mut self, stream: u8, bytes: &[u8]) -> Vec<SubstrateEvent> {
        if stream == CONTROL_STREAM {
            let raws = self.control.push(bytes);
            if self.control.overflowed() && !self.control_overflow_reported {
                self.control_overflow_reported = true;
                (self.on_malformed_control)(
                    "a control record declared a length past the control limit -- \
                     the control stream is ignored from here on",
                );
            }
            let mut events = Vec::with_capacity(raws.len());
            for raw in raws {
                match decode_server(&raw) {
                    // `UnknownKind` is a newer peer's record this build
                    // doesn't recognize -- dropping it silently is the
                    // codec's own documented behavior: the envelope already
                    // kept the stream in sync regardless of whether the
                    // type is understood.
                    Ok(rec) => events.push(self.translate_control(rec)),
                    Err(ChannelCodecError::UnknownKind(_)) => {}
                    // `Malformed`, in contrast, is a *known* kind whose
                    // payload didn't parse -- a broken promise, not an
                    // evolution -- and every record on this stream is
                    // one-shot: losing a malformed `Opened` or `Refused`
                    // here leaves that channel stuck `Opening` forever, so
                    // it is reported through `on_malformed_control` rather
                    // than dropped in silence.
                    Err(ChannelCodecError::Malformed) => {
                        (self.on_malformed_control)(&format!(
                            "malformed control record (kind {:#04x}, {} bytes) -- \
                             the channel it named may hang open forever",
                            raw.kind,
                            raw.payload.len()
                        ));
                    }
                }
            }
            events
        } else if stream < FIRST_CHANNEL_STREAM {
            Vec::new()
        } else {
            let deframer = self.channels.entry(stream).or_default();
            let recs = deframer.push(bytes);
            // A channel's own stream stopping for good (QSH-06) must not be
            // a silent freeze: report it once, like the control stream --
            // see the module docs and `channel_overflow_reported`'s own.
            if deframer.overflowed() && self.channel_overflow_reported.insert(stream) {
                (self.on_malformed_control)(&format!(
                    "channel {stream}: a record declared a length past the limit -- \
                     its stream is ignored from here on"
                ));
            }
            recs.into_iter()
                .map(|rec| Self::translate_channel(stream, rec))
                .collect()
        }
    }

    /// One control record translated into the session event it means.
    /// `Refused` and `Exit` both end the channel for good, so its deframer
    /// is dropped right here -- see [`Self::end_channel`].
    fn translate_control(&mut self, rec: ServerRecord) -> SubstrateEvent {
        match rec {
            ServerRecord::Opened { stream } => SubstrateEvent::Opened(stream),
            ServerRecord::Refused { stream, reason } => {
                self.end_channel(stream);
                SubstrateEvent::Refused { ch: stream, reason }
            }
            ServerRecord::Exit { stream, code } => {
                self.end_channel(stream);
                SubstrateEvent::Exit { ch: stream, code }
            }
            ServerRecord::Channels(list) => SubstrateEvent::Announced(list),
            // The daemon talking about itself: handed up as it came.
            record @ (ServerRecord::About(_)
            | ServerRecord::UpdateAnswer(_)
            | ServerRecord::UpdateResult(_)
            | ServerRecord::Restarting) => SubstrateEvent::Daemon(record),
        }
    }

    /// One record off channel `ch`'s own stream translated into the event
    /// it means. `EchoAck` becomes `InputConsumed` -- the acknowledgment
    /// prediction confirms against; a substrate that dropped it would leave
    /// every prediction pending forever.
    fn translate_channel(ch: ChannelId, rec: ShellRecord) -> SubstrateEvent {
        match rec {
            ShellRecord::Data(bytes) => SubstrateEvent::Data { ch, bytes },
            ShellRecord::EchoAck(offset) => SubstrateEvent::InputConsumed { ch, offset },
        }
    }

    /// Drops channel `ch`'s deframer and whatever record is still buffered
    /// inside it. Called on every event that ends a channel for good: an
    /// explicit `close()`, a server `Refused`, or a server `Exit` --
    /// symmetric with how the server side (`channel_server.rs`) removes its
    /// own per-channel state on the same three occasions. Skipping this
    /// would let a stray, half-eaten record sit under `ch`'s number until
    /// `crate::channel`'s free-stream policy reuses that number for a new
    /// channel (the lowest freed number, once every untouched one is gone),
    /// at which point the new channel's first bytes would be parsed as a
    /// continuation of the old, dead channel's leftover record.
    fn end_channel(&mut self, ch: ChannelId) {
        self.channels.remove(&ch);
        self.channel_overflow_reported.remove(&ch);
    }
}

impl<F: FnMut(u8, Vec<u8>) + Send> ChannelSubstrate for QshSubstrate<F> {
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

    fn resize(&mut self, ch: ChannelId, cols: u16, rows: u16) {
        (self.sink)(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Resize {
                stream: ch,
                cols,
                rows,
            }),
        );
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
        self.channel_overflow_reported.remove(&ch);
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

        assert!(events.is_empty(), "a malformed record yields no event");
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
        assert!(sub.on_stream(CONTROL_STREAM, &lie).is_empty());
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
        assert!(sub.on_stream(16, &lie).is_empty());
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
    fn a_channels_deframer_is_dropped_on_exit_so_a_reused_stream_starts_clean() {
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
