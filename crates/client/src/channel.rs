//! The client-side session model: a handful of channels multiplexed over one
//! seam, [`ChannelSubstrate`]. The model owns channel lifecycle -- which
//! stream a channel gets, whether it is confirmed, when it is gone -- and
//! nothing about how bytes actually travel. The qsh transport implements the
//! substrate in `crate::qsh`; the SSH library implements the same interface.
//! Neither transport implementation is visible from here.

use std::collections::{HashMap, HashSet};

use transport::channel::{
    ChannelKind, OpenRequest, ServerRecord, FIRST_CHANNEL_STREAM, MAX_COMMAND_LEN,
};

#[path = "channel_ordered.rs"]
mod ordered;
pub use ordered::{
    AttachmentIntent, ChannelProtocolError, ResizeDisposition, ResizeRejection, ResizeSemantics,
};
use transport::channel_geometry::{
    ChannelInstance, GeometryRecord, OutputGapCause, ResizeRefusal, ResizeRequestId,
};

/// A channel's identity, which is also the transport stream it uses.
pub type ChannelId = u8;

/// Capacity available to one not-yet-decoded record. Reservations in other
/// streams and decoded early events have already been subtracted by the owner.
#[derive(Clone, Copy)]
pub struct InputLimits {
    pub payload: usize,
    pub bytes: usize,
    pub events: usize,
}
impl InputLimits {
    pub const UNLIMITED: Self = Self {
        payload: usize::MAX,
        bytes: usize::MAX,
        events: usize::MAX,
    };
}
#[derive(Clone, Copy, Default)]
pub struct InputUsage {
    pub bytes: usize,
    pub events: usize,
}

/// What the session needs from whatever carries the bytes. Implemented for
/// qsh in `crate::qsh` and for SSH in the SSH library.
pub trait ChannelSubstrate: Send {
    fn input_usage(&self, _ch: ChannelId) -> InputUsage {
        InputUsage::default()
    }
    /// Ordered substrates decode at most one envelope, so owner admission runs
    /// before allocating the next record. Unframed substrates use one delivery.
    fn on_bytes_step(
        &mut self,
        stream: u8,
        bytes: &[u8],
        _limits: InputLimits,
    ) -> (usize, Vec<SubstrateEvent>) {
        (bytes.len(), self.on_bytes(stream, bytes))
    }
    fn resize_semantics(&self) -> ResizeSemantics {
        ResizeSemantics::Unconfirmed
    }
    fn resize_correlated(
        &mut self,
        _ch: ChannelId,
        _instance: ChannelInstance,
        _id: ResizeRequestId,
        _cols: u16,
        _rows: u16,
    ) -> Result<(), ChannelProtocolError> {
        Err(ChannelProtocolError::UnsupportedProfile)
    }
    /// The owner retires framing only after its final ordered output is released.
    fn retire_channel(&mut self, _ch: ChannelId) {}
    fn has_partial_input(&self, _ch: ChannelId) -> bool {
        false
    }
    fn reset_attachment(&mut self) {}
    fn protocol_failed(&mut self, _error: ChannelProtocolError) {}

    fn open(&mut self, req: &OpenRequest);
    /// Tell the far side what terminal this client's emulator is, for every
    /// channel opened after this. SSH carries the same fact in `pty-req`;
    /// a substrate whose transport has nowhere to put it does nothing, and
    /// the far side keeps whatever default it had.
    fn announce_term(&mut self, _term: &str) {}
    fn send(&mut self, ch: ChannelId, data: &[u8]);
    fn resize(&mut self, ch: ChannelId, cols: u16, rows: u16);
    fn close(&mut self, ch: ChannelId);
    /// Bytes that arrived on `stream`, and what they turned out to mean.
    /// The substrate owns whatever framing its transport uses: qsh deframes
    /// records here, and a substrate with no framing (SSH) simply reports
    /// the bytes as data -- which is precisely why prediction cannot run
    /// there, since it has no acknowledgments to give.
    fn on_bytes(&mut self, stream: u8, bytes: &[u8]) -> Vec<SubstrateEvent>;

    /// Forget whatever partial state this substrate holds for `ch`'s
    /// stream, because the transport just told us the stream restarted at
    /// a new offset and anything half-read is now nonsense. A substrate
    /// with no framing has no such state, so the default does nothing --
    /// an SSH substrate never overrides this.
    fn reset_stream(&mut self, _ch: ChannelId) {}
}

/// What comes back from the substrate. `InputConsumed` is the acknowledgment
/// prediction needs; a substrate with no output framing (SSH) never produces
/// it, which is exactly why prediction cannot run there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubstrateEvent {
    Geometry {
        ch: ChannelId,
        record: GeometryRecord,
    },
    OutputGap {
        ch: ChannelId,
        instance: ChannelInstance,
        cause: OutputGapCause,
    },
    Snapshot(transport::channel::ChannelSnapshot),
    ProtocolFailure(ChannelProtocolError),
    Opened(ChannelId),
    Refused {
        ch: ChannelId,
        reason: String,
    },
    Data {
        ch: ChannelId,
        bytes: Vec<u8>,
    },
    /// SSH extended output. Type 1 is stderr; other types retain their identity.
    /// Consumers must choose a stream policy explicitly. PTY process output is
    /// already merged by the remote terminal driver and arrives as `Data`.
    ExtendedData {
        ch: ChannelId,
        data_type: u32,
        bytes: Vec<u8>,
    },
    InputConsumed {
        ch: ChannelId,
        offset: u64,
    },
    Exit {
        ch: ChannelId,
        code: i32,
    },
    Announced(Vec<OpenRequest>),
    /// A record in which the daemon talks about itself (`About`, an update's
    /// answer or result, `Restarting`). Not about any channel.
    Daemon(ServerRecord),
}

/// What the session tells its owner after taking an event in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    Geometry {
        ch: ChannelId,
        record: GeometryRecord,
    },
    ResizeRefused {
        ch: ChannelId,
        request_id: ResizeRequestId,
        requested: terminal_size::TerminalSize,
        reason: ResizeRefusal,
    },
    DrainingReady(ChannelId),
    OutputContinuityLost {
        ch: ChannelId,
        instance: ChannelInstance,
        cause: OutputGapCause,
    },
    ProtocolFailure(ChannelProtocolError),
    Ready(ChannelId),
    Refused {
        ch: ChannelId,
        reason: String,
    },
    Data {
        ch: ChannelId,
        bytes: Vec<u8>,
    },
    /// SSH extended output. Type 1 is stderr; other types retain their identity.
    /// Consumers must choose a stream policy explicitly. PTY process output is
    /// already merged by the remote terminal driver and arrives as `Data`.
    ExtendedData {
        ch: ChannelId,
        data_type: u32,
        bytes: Vec<u8>,
    },
    InputConsumed {
        ch: ChannelId,
        offset: u64,
    },
    Exit {
        ch: ChannelId,
        code: i32,
    },
    /// A warm reattach listed the live channels and this one was not among
    /// them. Distinct from `Exit`, which carries a code because the server
    /// simply no longer knows the channel.
    Vanished {
        ch: ChannelId,
    },
    /// The far side announced what it is already running, which happens once
    /// per warm reattach and never on a cold start. Emitted BEFORE the
    /// per-channel `Ready`/`Vanished` events it implies, and emitted even
    /// when the list is EMPTY -- "the session is yours and it has nothing
    /// running" is an answer, and a client that waits for its channels to be
    /// announced would otherwise wait forever for it.
    Announced {
        active: Vec<ChannelId>,
        draining: Vec<ChannelId>,
    },
    /// The daemon talking about itself -- see [`SubstrateEvent::Daemon`].
    Daemon(ServerRecord),
}

/// Bound on `ChannelState::Opening`'s buffered output (`buffered_bytes`
/// below): the channel's own stream and the control stream travel
/// independently, so output can arrive before the confirmation that makes
/// it deliverable -- ordinarily for one packet's worth of jitter, but
/// nothing here can force the far side to ever answer `Opened` or
/// `Refused` at all. Past this many bytes of combined `Data`/`ExtendedData` payload, further
/// output for a still-unconfirmed channel is dropped rather than held
/// without bound.
const MAX_BUFFERED_BEFORE_READY: usize = 64 * 1024;

/// Where a channel sits in its lifecycle. `Opening` and `Ready` both keep
/// the request the channel was opened with -- `Opening` because a warm
/// reattach later needs to compare it against an announced channel (not
/// handled by this crate), `Ready` because resize needs `cols`/`rows` to
/// build a fresh request the same way. `Gone` carries nothing: nobody needs
/// to know what a closed channel used to be.
enum ChannelState {
    Opening {
        request: OpenRequest,
        /// `Data`/`ExtendedData`/`InputConsumed` decoded before the far side confirmed
        /// this channel, held here and delivered, in order, right after
        /// `Ready` -- see [`MAX_BUFFERED_BEFORE_READY`] for the bound.
        buffered: Vec<SessionEvent>,
        /// Running total of `buffered`'s ordinary and extended payload bytes, kept
        /// alongside it so the cap is a comparison, not a re-sum of the
        /// whole queue on every arrival.
        buffered_bytes: usize,
    },
    Ready(OpenRequest),
    Gone,
}

/// A session made of channels, over a substrate seam.
///
/// The model runs unchanged over qsh and SSH, allowing the terminal and
/// prediction engine to share the same channel lifecycle.
pub struct ChannelSession<S: ChannelSubstrate> {
    substrate: S,
    channels: HashMap<ChannelId, ChannelState>,
    ordered: Option<ordered::OrderedSession>,
    failure: Option<ChannelProtocolError>,
    admission_started: bool,
}

impl<S: ChannelSubstrate> ChannelSession<S> {
    pub fn new(substrate: S) -> Self {
        let ordered = (substrate.resize_semantics() == ResizeSemantics::ConfirmedOrdered)
            .then(ordered::OrderedSession::default);
        ChannelSession {
            substrate,
            channels: HashMap::new(),
            ordered,
            failure: None,
            admission_started: false,
        }
    }

    /// Picks a free stream, marks it `Opening` and asks the substrate to
    /// open it. `None` means every stream number from `FIRST_CHANNEL_STREAM`
    /// to 255 is currently in use (open or not yet reused after closing) --
    /// this library is linked into a long-lived host application, so it
    /// must never panic over a resource it can simply decline to hand out.
    /// Announce the client's terminal type. Call it before opening any
    /// channel: the far side spawns each channel's process with whatever it
    /// knew at that moment, so an announcement after the fact reaches
    /// nothing that is already running.
    ///
    /// A name the far side refuses (anything that is not a terminfo name)
    /// leaves it on its own default -- the caller cannot tell, and does not
    /// need to: the terminal type is an optimisation of key encoding, never
    /// a precondition for the channel.
    pub fn announce_term(&mut self, term: &str) {
        self.substrate.announce_term(term);
    }

    pub fn open_shell(&mut self, cols: u16, rows: u16) -> Option<ChannelId> {
        self.open(ChannelKind::Shell, Vec::new(), cols, rows)
    }

    /// See [`Self::open_shell`]. Also `None` if `command` is longer than
    /// [`MAX_COMMAND_LEN`] -- the wire's own length field is not the place
    /// to discover that (see [`Self::open`]'s doc).
    ///
    /// A command channel is opened with no screen model (no `screen` in the
    /// request's channel type), so its backlog is never dropped after a long
    /// absence: the server declares a stream resyncable only when the channel
    /// that owns it has a screen to repaint from (the server responds with a
    /// screen model in `ServerRecord::Opened` if the peer has one), and a
    /// command channel has none. Latent only because nothing calls this yet
    /// (the console client opens a shell channel only).
    pub fn open_command(&mut self, command: &[u8], cols: u16, rows: u16) -> Option<ChannelId> {
        self.open(ChannelKind::Command, command.to_vec(), cols, rows)
    }

    /// Common to [`Self::open_shell`]/[`Self::open_command`]. `None` if
    /// every stream number is spoken for ([`Self::free_stream`]), or if
    /// `command` is longer than [`MAX_COMMAND_LEN`] -- rejected here,
    /// before it ever reaches the substrate, rather than let a record the
    /// far side's `take_open` will call `Malformed` go out over the wire:
    /// that record's channel would sit `Opening` forever, since a malformed
    /// `OPEN` gets no `REFUSED` in reply (there is no channel number the
    /// server ever associated it with).
    fn open(
        &mut self,
        kind: ChannelKind,
        command: Vec<u8>,
        cols: u16,
        rows: u16,
    ) -> Option<ChannelId> {
        self.admission_started = true;
        if self.failure.is_some() || command.len() > MAX_COMMAND_LEN {
            return None;
        }
        // Zero OPEN dimensions retain their no-PTY meaning. Nonzero local
        // dimensions use the same adapter as the shell model.
        let (cols, rows) = if cols != 0 && rows != 0 {
            let size = terminal_size::TerminalSize::for_viewport(cols, rows);
            (size.cols(), size.rows())
        } else {
            (cols, rows)
        };
        let ch = self
            .ordered
            .as_ref()
            .map_or_else(|| self.free_stream(), |state| state.free_stream())?;
        let req = OpenRequest {
            stream: ch,
            kind,
            cols,
            rows,
            screen: matches!(kind, ChannelKind::Shell),
            command,
        };
        self.substrate.open(&req);
        if let Some(state) = &mut self.ordered {
            state.open(req);
            return Some(ch);
        }
        self.channels.insert(
            ch,
            ChannelState::Opening {
                request: req,
                buffered: Vec::new(),
                buffered_bytes: 0,
            },
        );
        Some(ch)
    }

    /// A stream number to open a new channel on, or `None` if every number
    /// in the valid range (`FIRST_CHANNEL_STREAM..=255`) is currently
    /// spoken for.
    ///
    /// A stream that has never been used at all is always preferred over
    /// reusing one whose channel went `Gone`: the substrate below may still
    /// have bytes in flight that belong to the old channel (a straggling
    /// data record, a `close` racing a late server message) when the new
    /// one opens, and handing out an untouched number is a cheap way to
    /// keep those from ever being mistaken for the new channel's own. Only
    /// once no untouched number remains does the lowest `Gone` number get
    /// reused -- a `Gone` entry is kept in the map (never deleted) for
    /// exactly this: to still know it is available, rather than forgetting
    /// about it and eventually running out of numbers to hand out.
    fn free_stream(&self) -> Option<ChannelId> {
        (FIRST_CHANNEL_STREAM..=u8::MAX)
            .find(|s| !self.channels.contains_key(s))
            .or_else(|| {
                (FIRST_CHANNEL_STREAM..=u8::MAX)
                    .filter(|s| matches!(self.channels.get(s), Some(ChannelState::Gone)))
                    .min()
            })
    }

    /// Whether the far side has confirmed this channel.
    pub fn is_ready(&self, ch: ChannelId) -> bool {
        if let Some(state) = &self.ordered {
            return state.is_ready(ch);
        }
        if self.failure.is_some() {
            return false;
        }
        matches!(self.channels.get(&ch), Some(ChannelState::Ready(_)))
    }

    /// A no-op unless `ch` is `Ready`: bytes for a channel the far side has
    /// not confirmed yet (or has already ended) would reach a stream that
    /// does not exist there, and be dropped in silence -- the same barrier
    /// `on_event` already enforces for data arriving the other way.
    pub fn send(&mut self, ch: ChannelId, data: &[u8]) {
        if self.is_ready(ch) {
            self.substrate.send(ch, data);
        }
    }

    /// Update physical intent without making it eligible for a wire request.
    /// Ordered channels also accept this before metadata/initial readiness;
    /// unconfirmed substrates reject it without sending anything.
    pub fn defer_resize(&mut self, ch: ChannelId, cols: u16, rows: u16) -> ResizeDisposition {
        self.ordered.as_mut().map_or(
            ResizeDisposition::Rejected(ResizeRejection::NotReady),
            |state| state.defer_resize(ch, cols, rows),
        )
    }

    pub fn resize(&mut self, ch: ChannelId, cols: u16, rows: u16) -> ResizeDisposition {
        if let Some(state) = &mut self.ordered {
            return state.resize(&mut self.substrate, ch, cols, rows);
        }
        if self.failure.is_some() {
            return ResizeDisposition::Rejected(ResizeRejection::Failed);
        }
        if cols == 0 || rows == 0 {
            return ResizeDisposition::Rejected(ResizeRejection::ZeroViewport);
        }
        if let Some(ChannelState::Ready(req)) = self.channels.get_mut(&ch) {
            if req.cols == 0 || req.rows == 0 {
                return ResizeDisposition::Rejected(ResizeRejection::NoPty);
            }
            let size = terminal_size::TerminalSize::for_viewport(cols, rows);
            let (cols, rows) = (size.cols(), size.rows());
            req.cols = cols;
            req.rows = rows;
            self.substrate.resize(ch, cols, rows);
            return ResizeDisposition::Sent;
        }
        ResizeDisposition::Rejected(ResizeRejection::NotReady)
    }

    /// A no-op unless `ch` is `Ready`, for the same reason as [`Self::send`].
    /// A channel still `Opening` has no substrate-side handle to close yet;
    /// there is no way here to cancel an in-flight open, so closing one
    /// before it is confirmed is simply ignored rather than left to race
    /// with a later `Opened`.
    pub fn close(&mut self, ch: ChannelId) {
        if let Some(state) = &mut self.ordered {
            state.close(&mut self.substrate, ch);
            return;
        }
        if self.is_ready(ch) {
            self.substrate.close(ch);
            self.channels.insert(ch, ChannelState::Gone);
        }
    }

    /// Feed bytes that arrived on `stream` and get back what they meant for
    /// this session. The session owns the substrate, so a caller needs no
    /// second instance of it.
    pub fn on_bytes(&mut self, stream: u8, bytes: &[u8]) -> Vec<SessionEvent> {
        self.admission_started |= !bytes.is_empty();
        if let Some(state) = &mut self.ordered {
            if state.ignore_input(stream) {
                return Vec::new();
            }
            let mut out = Vec::new();
            let mut remaining = bytes;
            while !remaining.is_empty() {
                let limits = state.input_limits(&self.substrate, stream);
                let (used, events) = self.substrate.on_bytes_step(stream, remaining, limits);
                for event in events {
                    out.extend(state.on_event(&mut self.substrate, event));
                }
                if used == 0 {
                    break;
                }
                remaining = &remaining[used..];
            }
            out.extend(state.finish_exits(&mut self.substrate));
            return out;
        }
        let events = self.substrate.on_bytes(stream, bytes);
        events.into_iter().flat_map(|e| self.on_event(e)).collect()
    }

    /// Forwards a wire-level reset of `ch`'s own stream to the substrate --
    /// see `ChannelSubstrate::reset_stream`'s own doc for what it does and
    /// why. A thin pass-through, deliberately: a caller reaches the
    /// substrate only through calls the seam itself defines, never the
    /// concrete type's whole surface.
    pub fn reset_stream(&mut self, ch: ChannelId) {
        self.substrate.reset_stream(ch);
        if let Some(state) = &mut self.ordered {
            state.reset_stream(ch);
        }
    }

    /// True after a disclosed output gap, including after real process Exit.
    pub fn continuity_lost(&self, ch: ChannelId) -> bool {
        self.ordered
            .as_ref()
            .is_some_and(|state| state.continuity_lost(ch))
    }
    pub fn committed_geometry(&self, ch: ChannelId) -> Option<GeometryRecord> {
        self.ordered.as_ref().and_then(|state| state.committed(ch))
    }
    /// Consume this attachment and retain only same-instance user intent.
    /// Pending IDs, lifecycle authority and framing never cross this boundary.
    pub fn into_attachment_intent(self) -> AttachmentIntent {
        self.ordered
            .map_or_else(AttachmentIntent::default, |state| state.into_intent())
    }
    /// Import portable intent before any local OPEN or received metadata.
    pub fn import_attachment_intent(
        &mut self,
        intent: AttachmentIntent,
    ) -> Result<(), ChannelProtocolError> {
        if self.admission_started {
            return Err(ChannelProtocolError::Metadata);
        }
        let Some(state) = &mut self.ordered else {
            return Err(ChannelProtocolError::UnsupportedProfile);
        };
        state.import_intent(intent);
        self.admission_started = true;
        Ok(())
    }

    /// Start a fresh attachment; wire metadata must re-establish each instance.
    pub fn with_attachment_intent(substrate: S, intent: AttachmentIntent) -> Self {
        let mut session = Self::new(substrate);
        if let Some(state) = &mut session.ordered {
            state.import_intent(intent);
            session.admission_started = true;
        }
        session
    }
    /// Start a new attachment on this substrate, retaining only portable intent.
    /// Hot per-stream reset is separate and preserves current pending IDs.
    pub fn reset_attachment(&mut self) {
        self.substrate.reset_attachment();
        if let Some(state) = &mut self.ordered {
            state.reset_attachment();
        }
        self.failure = None;
        self.admission_started = false;
    }

    /// Access for substrate-specific operations. Attachment transitions must
    /// use reset_attachment or transfer AttachmentIntent into a new session;
    /// clearing framing alone would leave stale resize correlation alive.
    pub fn substrate_mut(&mut self) -> &mut S {
        &mut self.substrate
    }

    /// Marks a channel `Gone` and reports `event`, but only if the channel
    /// is currently `Opening` or `Ready`. A channel already `Gone`, or a
    /// stream this session never opened, means `event` is a duplicate or a
    /// stale echo of a terminal condition already handled (or never
    /// applicable) -- reporting it again would be a second notification for
    /// something that already happened once, so it is dropped instead,
    /// mirroring the idempotence [`Self::on_event`] already keeps for a
    /// stale `Opened`.
    fn terminate(&mut self, ch: ChannelId, event: SessionEvent) -> Vec<SessionEvent> {
        match self.channels.get(&ch) {
            Some(ChannelState::Opening { .. }) | Some(ChannelState::Ready(_)) => {
                self.channels.insert(ch, ChannelState::Gone);
                vec![event]
            }
            _ => Vec::new(),
        }
    }

    /// Early payload and event wrappers share explicit limits. A failed
    /// attachment cannot later publish Ready or a truncated successful prefix.
    fn buffer_before_ready(&mut self, ch: ChannelId, mut event: SessionEvent) -> Vec<SessionEvent> {
        if let Some(ChannelState::Opening {
            buffered,
            buffered_bytes,
            ..
        }) = self.channels.get_mut(&ch)
        {
            let event_bytes = match &event {
                SessionEvent::Data { bytes, .. } | SessionEvent::ExtendedData { bytes, .. } => {
                    bytes.len()
                }
                _ => 0,
            };
            if event_bytes > MAX_BUFFERED_BEFORE_READY.saturating_sub(*buffered_bytes)
                || buffered.len() >= ordered::EARLY_EVENTS
            {
                return self.fail_unconfirmed(ChannelProtocolError::EarlyOutputOverflow);
            }
            if let SessionEvent::Data { bytes, .. } | SessionEvent::ExtendedData { bytes, .. } =
                &mut event
            {
                *bytes = std::mem::take(bytes).into_boxed_slice().into_vec();
            }
            *buffered_bytes += event_bytes;
            buffered.push(event);
        }
        Vec::new()
    }
    fn fail_unconfirmed(&mut self, error: ChannelProtocolError) -> Vec<SessionEvent> {
        if self.failure.is_some() {
            return Vec::new();
        }
        self.failure = Some(error);
        self.channels.clear();
        self.substrate.protocol_failed(error);
        vec![SessionEvent::ProtocolFailure(error)]
    }

    /// Takes an event from the substrate and says what it means.
    pub fn on_event(&mut self, event: SubstrateEvent) -> Vec<SessionEvent> {
        self.admission_started = true;
        if let Some(state) = &mut self.ordered {
            let mut out = state.on_event(&mut self.substrate, event);
            out.extend(state.finish_exits(&mut self.substrate));
            return out;
        }
        if self.failure.is_some() {
            return Vec::new();
        }
        match event {
            SubstrateEvent::Geometry { .. }
            | SubstrateEvent::OutputGap { .. }
            | SubstrateEvent::Snapshot(_) => {
                self.fail_unconfirmed(ChannelProtocolError::UnsupportedProfile)
            }
            SubstrateEvent::ProtocolFailure(error) => self.fail_unconfirmed(error),
            SubstrateEvent::Opened(ch) => {
                // `get_mut` never removes the entry, so a stale or duplicate
                // `Opened` for a channel that is not `Opening` (already
                // `Ready`, already `Gone`, or a stream we never opened)
                // leaves it untouched instead of vanishing from the map.
                // The bug this replaced used `remove` unconditionally and
                // dropped the entry on the floor whenever the removed value
                // did not match the pattern.
                match self.channels.get_mut(&ch) {
                    Some(slot @ ChannelState::Opening { .. }) => {
                        let ChannelState::Opening {
                            request, buffered, ..
                        } = std::mem::replace(slot, ChannelState::Gone)
                        else {
                            unreachable!()
                        };
                        *slot = ChannelState::Ready(request);
                        // `Ready` first, then whatever arrived before the
                        // confirmation did, in the order it arrived --
                        // never the other way around.
                        std::iter::once(SessionEvent::Ready(ch))
                            .chain(buffered)
                            .collect()
                    }
                    _ => Vec::new(),
                }
            }
            SubstrateEvent::Refused { ch, reason } => {
                self.terminate(ch, SessionEvent::Refused { ch, reason })
            }
            SubstrateEvent::Data { ch, bytes } => {
                if self.is_ready(ch) {
                    vec![SessionEvent::Data { ch, bytes }]
                } else {
                    // Not ready yet: buffer it if `ch` is still `Opening`
                    // (a no-op for `Gone` or an unknown stream, same as
                    // every other call this session cannot yet act on).
                    self.buffer_before_ready(ch, SessionEvent::Data { ch, bytes })
                }
            }
            SubstrateEvent::ExtendedData {
                ch,
                data_type,
                bytes,
            } => {
                let event = SessionEvent::ExtendedData {
                    ch,
                    data_type,
                    bytes,
                };
                if self.is_ready(ch) {
                    vec![event]
                } else {
                    self.buffer_before_ready(ch, event)
                }
            }
            SubstrateEvent::InputConsumed { ch, offset } => {
                if self.is_ready(ch) {
                    vec![SessionEvent::InputConsumed { ch, offset }]
                } else {
                    self.buffer_before_ready(ch, SessionEvent::InputConsumed { ch, offset })
                }
            }
            SubstrateEvent::Exit { ch, code } => {
                self.terminate(ch, SessionEvent::Exit { ch, code })
            }
            SubstrateEvent::Announced(list) => {
                // Anything the client still thinks is running, but that
                // this list does not name, is gone: the server has nothing
                // left to send its input to, and would drop it in silence
                // forever if this channel stayed `Ready`.
                let announced: HashSet<ChannelId> = list.iter().map(|req| req.stream).collect();
                let vanished: Vec<ChannelId> = self
                    .channels
                    .iter()
                    .filter_map(|(&ch, state)| {
                        let live =
                            matches!(state, ChannelState::Opening { .. } | ChannelState::Ready(_));
                        (live && !announced.contains(&ch)).then_some(ch)
                    })
                    .collect();
                let mut events: Vec<SessionEvent> = vec![SessionEvent::Announced {
                    draining: Vec::new(),
                    active: {
                        let mut live: Vec<ChannelId> = announced.iter().copied().collect();
                        live.sort_unstable();
                        live
                    },
                }];
                events.extend(vanished.into_iter().map(|ch| {
                    self.channels.insert(ch, ChannelState::Gone);
                    SessionEvent::Vanished { ch }
                }));
                events.extend(list.into_iter().map(|req| {
                    let ch = req.stream;
                    self.channels.insert(ch, ChannelState::Ready(req));
                    SessionEvent::Ready(ch)
                }));
                events
            }
            SubstrateEvent::Daemon(record) => vec![SessionEvent::Daemon(record)],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use transport::channel::ServerRecord;

    /// Records what the session asked the substrate to do. That record IS
    /// the assertion surface: the session's whole job is deciding which
    /// calls to make and when. `opens` additionally keeps the full
    /// `OpenRequest` of every `open` call, for the tests that need to
    /// inspect a field beyond the stream number the `calls` log carries.
    #[derive(Default)]
    struct FakeSubstrate {
        calls: Arc<Mutex<Vec<String>>>,
        opens: Arc<Mutex<Vec<OpenRequest>>>,
    }

    impl ChannelSubstrate for FakeSubstrate {
        fn resize_semantics(&self) -> ResizeSemantics {
            ResizeSemantics::Unconfirmed
        }
        fn open(&mut self, req: &OpenRequest) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("open {}", req.stream));
            self.opens.lock().unwrap().push(req.clone());
        }
        fn send(&mut self, ch: ChannelId, data: &[u8]) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("send {ch} {}", String::from_utf8_lossy(data)));
        }
        fn resize(&mut self, ch: ChannelId, cols: u16, rows: u16) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("resize {ch} {cols}x{rows}"));
        }
        fn close(&mut self, ch: ChannelId) {
            self.calls.lock().unwrap().push(format!("close {ch}"));
        }
        fn on_bytes(&mut self, stream: u8, bytes: &[u8]) -> Vec<SubstrateEvent> {
            self.calls.lock().unwrap().push(format!(
                "on_bytes {stream} {}",
                String::from_utf8_lossy(bytes)
            ));
            vec![SubstrateEvent::Data {
                ch: stream,
                bytes: bytes.to_vec(),
            }]
        }
        fn reset_stream(&mut self, ch: ChannelId) {
            self.calls
                .lock()
                .unwrap()
                .push(format!("reset_stream {ch}"));
        }
    }

    fn session() -> (ChannelSession<FakeSubstrate>, Arc<Mutex<Vec<String>>>) {
        let sub = FakeSubstrate::default();
        let calls = sub.calls.clone();
        (ChannelSession::new(sub), calls)
    }

    /// Like [`session`], but hands back the full `OpenRequest` log instead
    /// of the terse `calls` strings -- for tests that need to inspect a
    /// field of the request itself, not just which stream it named.
    fn session_recording_opens() -> (ChannelSession<FakeSubstrate>, Arc<Mutex<Vec<OpenRequest>>>) {
        let sub = FakeSubstrate::default();
        let opens = sub.opens.clone();
        (ChannelSession::new(sub), opens)
    }

    #[test]
    fn ordered_qsh_opened_alone_does_not_release_ready() {
        let mut session = ChannelSession::new(crate::qsh::QshSubstrate::new(|_, _| {}));
        let ch = session.open_shell(80, 24).unwrap();
        let events = session.on_bytes(
            transport::channel::CONTROL_STREAM,
            &transport::channel::encode_server(&ServerRecord::Opened { stream: ch }),
        );
        assert!(events.is_empty(), "lifecycle confirmation cannot release output before authoritative geometry: {events:?}");
        assert!(!session.is_ready(ch));
    }

    #[test]
    fn ordered_qsh_resize_does_not_commit_before_a_correlated_result() {
        use transport::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord};
        let mut session = ChannelSession::new(crate::qsh::QshSubstrate::new(|_, _| {}));
        let ch = session.open_shell(80, 24).unwrap();
        session.on_bytes(
            transport::channel::CONTROL_STREAM,
            &transport::channel::encode_server(&ServerRecord::Opened { stream: ch }),
        );
        session.on_bytes(
            ch,
            &transport::shell_frame::encode_shell(&transport::shell_frame::ShellRecord::Geometry(
                GeometryRecord {
                    instance: ChannelInstance::new(1).unwrap(),
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols: 80,
                    rows: 24,
                },
            ))
            .unwrap(),
        );
        session.resize(ch, 100, 30);
        assert!(session.is_ready(ch));
        let geometry = session.committed_geometry(ch).unwrap();
        assert_eq!(
            (geometry.cols, geometry.rows),
            (80, 24),
            "queuing a request cannot claim that the remote geometry changed"
        );
    }

    #[test]
    fn local_shell_adapts_open_and_resize_but_never_sends_zero_resize() {
        let substrate = FakeSubstrate::default();
        let opens = substrate.opens.clone();
        let calls = substrate.calls.clone();
        let mut s = ChannelSession::new(substrate);
        let ch = s.open_shell(1, 2).unwrap();
        let req = opens.lock().unwrap()[0].clone();
        assert_eq!((req.cols, req.rows), (2, 2));
        s.on_event(SubstrateEvent::Opened(ch));
        calls.lock().unwrap().clear();
        s.resize(ch, 0, 0);
        assert!(calls.lock().unwrap().is_empty());
        s.resize(ch, 1, 65535);
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[format!("resize {ch} 2x256")]
        );
    }

    /// The session reports a channel usable only once the far side has
    /// confirmed it. Anything sent before that would reach a stream the
    /// server has not created yet, and be dropped in silence.
    #[test]
    fn a_channel_is_not_usable_until_it_is_confirmed() {
        let (mut s, calls) = session();
        let ch = s
            .open_shell(80, 24)
            .expect("a fresh session always has a free stream");
        assert_eq!(calls.lock().unwrap().as_slice(), &["open 16".to_string()]);
        assert!(!s.is_ready(ch), "not usable before the server confirms");

        let events = s.on_event(SubstrateEvent::Opened(ch));
        assert_eq!(events, vec![SessionEvent::Ready(ch)]);
        assert!(s.is_ready(ch), "usable once confirmed");
    }

    /// A command past `MAX_COMMAND_LEN` never reaches the substrate: `open`
    /// refuses it outright rather than let it become a wire record the far
    /// side's `take_open` will call `Malformed` -- which leaves the channel
    /// stuck `Opening` forever, since a malformed `OPEN` gets no `REFUSED`
    /// in reply. `open_command` reports the same way `free_stream`
    /// exhaustion already does: `None`, no panic, no channel inserted.
    #[test]
    fn a_command_longer_than_the_cap_is_refused_without_reaching_the_substrate() {
        let (mut s, calls) = session();
        let oversized = vec![b'x'; transport::channel::MAX_COMMAND_LEN + 1];

        assert_eq!(s.open_command(&oversized, 80, 24), None);
        assert!(
            calls.lock().unwrap().is_empty(),
            "the substrate must never see an open() call for an oversized command"
        );
    }

    /// The channel's own stream and the control stream travel independently
    /// -- a single dropped datagram carrying `Opened` is enough for the
    /// channel's first output to reach this session before its
    /// confirmation does. That output must not be lost: it is buffered and
    /// delivered, in order, right after `Ready`.
    #[test]
    fn data_and_echo_before_opened_is_buffered_and_delivered_once_ready() {
        let (mut s, _) = session();
        let ch = s
            .open_shell(80, 24)
            .expect("a fresh session always has a free stream");

        let early_data = s.on_event(SubstrateEvent::Data {
            ch,
            bytes: b"early".to_vec(),
        });
        let early_ack = s.on_event(SubstrateEvent::InputConsumed { ch, offset: 3 });
        assert!(early_data.is_empty(), "not ready yet: nothing surfaces");
        assert!(early_ack.is_empty(), "not ready yet: nothing surfaces");

        let events = s.on_event(SubstrateEvent::Opened(ch));
        assert_eq!(
            events,
            vec![
                SessionEvent::Ready(ch),
                SessionEvent::Data {
                    ch,
                    bytes: b"early".to_vec()
                },
                SessionEvent::InputConsumed { ch, offset: 3 },
            ],
            "buffered output reaches the caller, in order, right after Ready"
        );

        // Ordinary post-ready delivery still works, unaffected.
        let after = s.on_event(SubstrateEvent::Data {
            ch,
            bytes: b"later".to_vec(),
        });
        assert_eq!(
            after,
            vec![SessionEvent::Data {
                ch,
                bytes: b"later".to_vec()
            }]
        );
    }

    #[test]
    fn unconfirmed_early_combined_overflow_is_terminal_instead_of_truncated() {
        let (mut session, _) = session();
        let ch = session.open_command(b"command", 0, 0).unwrap();
        assert!(session
            .on_event(SubstrateEvent::Data {
                ch,
                bytes: vec![0; MAX_BUFFERED_BEFORE_READY]
            })
            .is_empty());
        assert_eq!(
            session.on_event(SubstrateEvent::ExtendedData {
                ch,
                data_type: 77,
                bytes: vec![1]
            }),
            vec![SessionEvent::ProtocolFailure(
                ChannelProtocolError::EarlyOutputOverflow
            )]
        );
        assert!(session.on_event(SubstrateEvent::Opened(ch)).is_empty());
        assert!(!session.is_ready(ch));
        assert_eq!(
            session.open_shell(80, 24),
            None,
            "failed attempt cannot open another channel"
        );
    }
    #[test]
    fn unconfirmed_early_zero_payload_events_are_bounded() {
        let (mut session, _) = session();
        let ch = session.open_shell(80, 24).unwrap();
        for offset in 0..256 {
            assert!(session
                .on_event(SubstrateEvent::InputConsumed { ch, offset })
                .is_empty());
        }
        assert_eq!(
            session.on_event(SubstrateEvent::InputConsumed { ch, offset: 256 }),
            vec![SessionEvent::ProtocolFailure(
                ChannelProtocolError::EarlyOutputOverflow
            )]
        );
        assert!(session.on_event(SubstrateEvent::Opened(ch)).is_empty());
    }

    #[test]
    fn extended_data_keeps_type_order_and_shared_pre_ready_limit() {
        let (mut session, _) = session();
        let ch = session.open_command(b"command", 0, 0).unwrap();
        assert!(session
            .on_event(SubstrateEvent::Data {
                ch,
                bytes: vec![b'a'; MAX_BUFFERED_BEFORE_READY - 1]
            })
            .is_empty());
        assert!(session
            .on_event(SubstrateEvent::ExtendedData {
                ch,
                data_type: 1,
                bytes: b"b".to_vec()
            })
            .is_empty());
        let events = session.on_event(SubstrateEvent::Opened(ch));
        assert_eq!(events.len(), 3);
        assert_eq!(events[0], SessionEvent::Ready(ch));
        assert!(
            matches!(&events[1], SessionEvent::Data { bytes, .. } if bytes.len() == MAX_BUFFERED_BEFORE_READY - 1)
        );
        assert_eq!(
            events[2],
            SessionEvent::ExtendedData {
                ch,
                data_type: 1,
                bytes: b"b".to_vec()
            }
        );
        assert_eq!(
            session.on_event(SubstrateEvent::ExtendedData {
                ch,
                data_type: 77,
                bytes: b"unknown-type".to_vec()
            }),
            vec![SessionEvent::ExtendedData {
                ch,
                data_type: 77,
                bytes: b"unknown-type".to_vec()
            }]
        );
        session.on_event(SubstrateEvent::Exit { ch, code: 0 });
        for ch in [ch, 255] {
            assert!(session
                .on_event(SubstrateEvent::ExtendedData {
                    ch,
                    data_type: 1,
                    bytes: b"late".to_vec()
                })
                .is_empty());
        }
    }

    /// A channel stuck `Opening` -- the far side never answers `Opened` or
    /// `Refused` -- must not accumulate output without bound.
    #[test]
    fn buffered_output_before_ready_is_capped() {
        let (mut s, _) = session();
        let ch = s
            .open_shell(80, 24)
            .expect("a fresh session always has a free stream");

        let chunk = vec![b'x'; 4096];
        for i in 0..32 {
            let events = s.on_event(SubstrateEvent::Data {
                ch,
                bytes: chunk.clone(),
            });
            if i == 16 {
                assert_eq!(
                    events,
                    vec![SessionEvent::ProtocolFailure(
                        ChannelProtocolError::EarlyOutputOverflow
                    )]
                );
            } else {
                assert!(events.is_empty());
            }
        }
        assert!(s.on_event(SubstrateEvent::Opened(ch)).is_empty());
        assert!(!s.is_ready(ch));
    }

    /// A refusal preserves the original reason; terminal-safe formatting belongs
    /// to the presentation layer, not this machine-level event.
    #[test]
    fn a_refusal_carries_the_servers_reason() {
        let (mut s, _) = session();
        let ch = s
            .open_shell(80, 24)
            .expect("a fresh session always has a free stream");
        let reason = "shell not found\x1b]0;test title\x07\nretry — résumé";
        let events = s.on_event(SubstrateEvent::Refused {
            ch,
            reason: reason.to_string(),
        });
        assert_eq!(
            events,
            vec![SessionEvent::Refused {
                ch,
                reason: reason.to_string()
            }]
        );
        assert!(!s.is_ready(ch), "a refused channel is not usable");
    }

    /// An announcement with nothing in it still reaches the owner. A warm
    /// reattach to a session whose channels have all ended announces an
    /// EMPTY list, and a client that reads "no events" as "no answer yet"
    /// would wait for a shell nobody is going to announce.
    #[test]
    fn an_empty_announcement_is_still_an_announcement() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let opens = Arc::new(Mutex::new(Vec::new()));
        let mut s = ChannelSession::new(FakeSubstrate {
            calls: calls.clone(),
            opens: opens.clone(),
        });
        let events = s.on_event(SubstrateEvent::Announced(Vec::new()));
        assert_eq!(
            events,
            vec![SessionEvent::Announced {
                active: Vec::new(),
                draining: Vec::new()
            }],
            "an empty list is an answer, not silence"
        );
    }

    /// After a warm reattach the session binds to the announced channels
    /// instead of opening new ones. If it opened, the server would end up
    /// running a second copy of everything after every roam.
    #[test]
    fn an_announced_channel_is_bound_not_reopened() {
        let (mut s, calls) = session();
        let announced = OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 100,
            rows: 30,
            screen: true,
            command: Vec::new(),
        };
        let events = s.on_event(SubstrateEvent::Announced(vec![announced]));

        assert_eq!(
            events,
            vec![
                SessionEvent::Announced {
                    active: vec![16],
                    draining: Vec::new()
                },
                SessionEvent::Ready(16)
            ],
            "the announcement itself is reported, then what it implies"
        );
        assert!(s.is_ready(16));
        assert!(
            calls.lock().unwrap().is_empty(),
            "binding must not ask the substrate to open anything: {:?}",
            calls.lock().unwrap()
        );
    }

    /// A stale or duplicate `Opened` for a channel that is already `Ready`
    /// must not evict it from the map. The bug this guards against removed
    /// the map entry unconditionally before matching on it, so whenever the
    /// removed value was not `Opening` (e.g. it was already `Ready`), the
    /// entry was gone for good: `is_ready` would start lying (`false` for a
    /// channel that is, in fact, still running), and every later `Data` for
    /// it would be dropped forever with no event telling anyone why.
    #[test]
    fn a_stale_opened_event_does_not_evict_an_already_ready_channel() {
        let (mut s, _) = session();
        let ch = s
            .open_shell(80, 24)
            .expect("a fresh session always has a free stream");
        assert_eq!(
            s.on_event(SubstrateEvent::Opened(ch)),
            vec![SessionEvent::Ready(ch)]
        );
        assert!(s.is_ready(ch));

        // A second, stale `Opened` for the same channel: not news, so no
        // event -- but the channel must still be there afterwards.
        let events = s.on_event(SubstrateEvent::Opened(ch));
        assert!(events.is_empty(), "a duplicate confirmation is not news");
        assert!(
            s.is_ready(ch),
            "the channel must survive a stale re-confirmation"
        );

        let data = s.on_event(SubstrateEvent::Data {
            ch,
            bytes: b"hi".to_vec(),
        });
        assert_eq!(
            data,
            vec![SessionEvent::Data {
                ch,
                bytes: b"hi".to_vec()
            }],
            "the channel must still deliver data after surviving the stale event"
        );
    }

    /// An exit marks the channel gone, and data arriving afterwards is
    /// dropped rather than handed to a consumer that no longer exists.
    #[test]
    fn data_after_an_exit_goes_nowhere() {
        let (mut s, _) = session();
        let ch = s
            .open_shell(80, 24)
            .expect("a fresh session always has a free stream");
        s.on_event(SubstrateEvent::Opened(ch));

        let events = s.on_event(SubstrateEvent::Exit { ch, code: 0 });
        assert_eq!(events, vec![SessionEvent::Exit { ch, code: 0 }]);
        assert!(!s.is_ready(ch));

        let late = s.on_event(SubstrateEvent::Data {
            ch,
            bytes: b"too late".to_vec(),
        });
        assert!(late.is_empty(), "data for a finished channel is dropped");
    }

    /// `send`, `resize` and `close` are a no-op for a channel that is not
    /// `Ready` (still `Opening`, or a stream nobody ever opened): the
    /// substrate is never called, symmetrically with how `on_event` already
    /// drops incoming data for a channel that is not `Ready`. Sending
    /// before confirmation would reach a stream the far side has not
    /// created yet, and vanish there in silence -- the barrier belongs on
    /// both sides of the seam, not just the receiving one.
    #[test]
    fn send_resize_and_close_are_no_ops_for_a_channel_that_is_not_ready() {
        let (mut s, calls) = session();
        let opening = s
            .open_shell(80, 24)
            .expect("a fresh session always has a free stream");
        let unknown: ChannelId = 200;

        for ch in [opening, unknown] {
            calls.lock().unwrap().clear();
            s.send(ch, b"nope");
            s.resize(ch, 100, 40);
            s.close(ch);
            assert!(
                calls.lock().unwrap().is_empty(),
                "no substrate call for a channel that is not ready: {:?}",
                calls.lock().unwrap()
            );
        }
        assert!(
            !s.is_ready(opening),
            "close on a not-yet-ready channel must not fake readiness"
        );
    }

    /// A second `Exit` for a channel that is already `Gone` produces no
    /// event and no state change: it is a duplicate or a stale echo of a
    /// terminal condition already handled, not fresh news. The same must
    /// hold for a terminal event naming a stream the session never opened.
    #[test]
    fn a_second_terminal_event_for_an_already_gone_channel_is_silent() {
        let (mut s, _) = session();
        let ch = s
            .open_shell(80, 24)
            .expect("a fresh session always has a free stream");
        s.on_event(SubstrateEvent::Opened(ch));
        assert_eq!(
            s.on_event(SubstrateEvent::Exit { ch, code: 0 }),
            vec![SessionEvent::Exit { ch, code: 0 }]
        );

        // The channel is already `Gone`; a second exit is not news.
        let repeat = s.on_event(SubstrateEvent::Exit { ch, code: 1 });
        assert!(
            repeat.is_empty(),
            "an exit for an already-gone channel must not surface again"
        );

        // A refusal for a totally unknown stream is likewise silent.
        let unknown = s.on_event(SubstrateEvent::Refused {
            ch: 201,
            reason: "unknown channel".to_string(),
        });
        assert!(
            unknown.is_empty(),
            "a terminal event for a channel that was never opened is dropped"
        );
    }

    /// `open_shell` asks for a screen model (a shell should get its screen
    /// repainted after a long absence); `open_command` does not (a line
    /// protocol like `tmux -C attach` would have its conversation corrupted
    /// by a repaint). This is exactly the flag that silently flips under an
    /// unrelated edit with nothing here to catch it -- pin it down.
    #[test]
    fn open_shell_requests_a_screen_and_open_command_does_not() {
        let (mut s, opens) = session_recording_opens();
        s.open_shell(80, 24)
            .expect("a fresh session always has a free stream");
        s.open_command(b"tmux -C attach", 0, 0)
            .expect("a fresh session always has a free stream");

        let opens = opens.lock().unwrap();
        assert_eq!(opens.len(), 2);
        assert!(opens[0].screen, "a shell channel must ask for a screen");
        assert!(
            !opens[1].screen,
            "a command channel must not ask for a screen"
        );
    }

    /// Repeatedly opening and closing a SINGLE channel must never panic,
    /// however many cycles it goes through -- a long-lived session that
    /// reopens the same kind of channel after every internal reconnect will
    /// run through many more than a handful of cycles over its lifetime.
    /// Forty is well past the old bug's threshold: it panicked on the 33rd
    /// cycle, because `Gone` streams were never released and the search
    /// gave up after 32 candidates. Each cycle here also lands on a stream
    /// nothing has used before, since a `Gone` number stays in reserve
    /// while an untouched one is still available.
    #[test]
    fn forty_open_close_cycles_of_one_channel_do_not_panic() {
        let (mut s, opens) = session_recording_opens();
        for _ in 0..40 {
            let ch = s
                .open_shell(80, 24)
                .expect("forty cycles must not exhaust the stream range");
            s.on_event(SubstrateEvent::Opened(ch));
            s.close(ch);
        }
        let mut streams: Vec<u8> = opens.lock().unwrap().iter().map(|r| r.stream).collect();
        let total = streams.len();
        streams.sort_unstable();
        streams.dedup();
        assert_eq!(
            streams.len(),
            total,
            "each cycle prefers a stream nothing has used before"
        );
    }

    /// Once every stream number in the valid range is open, `open_shell`
    /// (and `open_command`) return `None` instead of panicking -- the old
    /// bug's `.expect()` would have crashed the host application here.
    #[test]
    fn every_stream_in_the_valid_range_being_open_yields_none() {
        let (mut s, _) = session();
        let mut opened = 0u32;
        while s.open_shell(80, 24).is_some() {
            opened += 1;
            assert!(opened <= 1000, "must terminate well within the u8 range");
        }
        assert_eq!(
            opened,
            u32::from(u8::MAX - FIRST_CHANNEL_STREAM) + 1,
            "every stream from FIRST_CHANNEL_STREAM to 255 got handed out"
        );
        assert!(
            s.open_command(b"tmux -C attach", 0, 0).is_none(),
            "no stream numbers remain for a command channel either"
        );
    }

    /// Once every stream number has been used at least once, the LOWEST
    /// `Gone` number is reused rather than `open_shell` returning `None`
    /// forever: a `Gone` entry stays in the map (never deleted) precisely so
    /// this reuse remains possible once the untouched pool runs dry.
    #[test]
    fn once_every_stream_has_been_used_the_lowest_gone_one_is_reused() {
        let (mut s, _) = session();
        let mut streams = Vec::new();
        while let Some(ch) = s.open_shell(80, 24) {
            streams.push(ch);
        }
        assert!(
            s.open_shell(80, 24).is_none(),
            "sanity check: the range must be exhausted here"
        );

        // Mark every channel `Gone` via a real terminal event: these
        // channels were never confirmed `Ready`, and `close` is a no-op for
        // anything else (see `send_resize_and_close_are_no_ops_...`).
        for &ch in &streams {
            s.on_event(SubstrateEvent::Exit { ch, code: 0 });
        }

        let reused = s
            .open_shell(80, 24)
            .expect("a Gone stream must be reusable once every number has been used");
        assert_eq!(
            reused, FIRST_CHANNEL_STREAM,
            "the LOWEST Gone stream is reused first"
        );
    }

    /// The session takes bytes in, hands them to its substrate, and reports
    /// what came back -- so a caller needs one substrate, not two. Holding a
    /// second one for the inbound half is what let a closed channel's
    /// deframer outlive the channel.
    ///
    /// The fake substrate does no framing of its own: framing belongs to a
    /// real substrate, and what is under test here is the session's
    /// delegation and its mapping of substrate events to session events.
    #[test]
    fn the_session_hands_bytes_to_its_substrate_and_reports_what_came_back() {
        let (mut s, calls) = session();
        let ch = s
            .open_shell(80, 24)
            .expect("a fresh session has a free stream");
        s.on_event(SubstrateEvent::Opened(ch));

        // The fake answers any bytes with one Data event carrying them back.
        assert_eq!(
            s.on_bytes(ch, b"from the channel"),
            vec![SessionEvent::Data {
                ch,
                bytes: b"from the channel".to_vec()
            }],
        );
        assert!(
            calls
                .lock()
                .unwrap()
                .iter()
                .any(|c| c == "on_bytes 16 from the channel"),
            "the bytes must reach the substrate, not be interpreted by the session: {:?}",
            calls.lock().unwrap()
        );
    }

    /// A warm reattach lists what is still running. A channel the server
    /// did NOT list is gone: leaving it Ready would send its input into
    /// nothing, silently, for the rest of the session.
    #[test]
    fn a_channel_missing_from_the_announced_list_stops_being_ready() {
        let (mut s, _) = session();
        let kept = OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: true,
            command: Vec::new(),
        };
        // Two channels are running as far as the client knows.
        s.on_event(SubstrateEvent::Announced(vec![
            kept.clone(),
            OpenRequest {
                stream: 17,
                kind: ChannelKind::Command,
                ..kept.clone()
            },
        ]));
        assert!(s.is_ready(16) && s.is_ready(17));

        // The server reattaches and lists only one of them.
        s.on_event(SubstrateEvent::Announced(vec![kept]));

        assert!(s.is_ready(16), "the announced channel stays usable");
        assert!(
            !s.is_ready(17),
            "a channel the server no longer lists must stop being usable"
        );
    }

    /// A daemon record is not about any channel, so it passes straight
    /// through, whatever state the channels are in.
    #[test]
    fn a_daemon_record_passes_straight_through() {
        let (mut s, _) = session();
        assert_eq!(
            s.on_event(SubstrateEvent::Daemon(ServerRecord::Restarting)),
            vec![SessionEvent::Daemon(ServerRecord::Restarting)]
        );
    }

    /// A wire-level reset of one channel's stream must reach the substrate
    /// for exactly that channel -- not silently drop, and not touch any
    /// other channel's own state along the way.
    #[test]
    fn reset_stream_reaches_the_substrate_for_the_named_channel_only() {
        let (mut s, calls) = session();
        let a = s
            .open_shell(80, 24)
            .expect("a fresh session has a free stream");
        let b = s
            .open_shell(80, 24)
            .expect("a fresh session has a free stream");
        calls.lock().unwrap().clear();

        s.reset_stream(a);

        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[format!("reset_stream {a}")],
            "only the named channel's own reset must reach the substrate, not {b}'s"
        );
    }
}

#[cfg(test)]
#[path = "channel_ordered_tests.rs"]
mod ordered_tests;
