//! Client authority for the ordered channel profile. SSH does not use this state.
use super::*;
use std::collections::{BTreeMap, VecDeque};
use terminal_size::TerminalSize;
use transport::channel::{ChannelSnapshot, OpenClassification, CHANNEL_IDENTITIES};
use transport::channel_geometry::{GeometryOutcome, ProtocolErrorCode};
use transport::shell_frame::ShellCodecError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeSemantics {
    ConfirmedOrdered,
    Unconfirmed,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeRejection {
    ZeroViewport,
    NoPty,
    NotReady,
    Ended,
    Failed,
    RequestIdExhausted,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResizeDisposition {
    Sent,
    Coalesced,
    Unchanged,
    Rejected(ResizeRejection),
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelProtocolError {
    Shell(ShellCodecError),
    UnexpectedRecord(u8),
    Remote(ProtocolErrorCode),
    UnsupportedProfile,
    EarlyOutputOverflow,
    Metadata,
    Correlation,
    Instance,
    GeometryRequired,
    RequestIdExhausted,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExitOutcome {
    Code(i32),
    Unavailable,
}
impl ExitOutcome {
    fn event(self, ch: ChannelId) -> SessionEvent {
        match self {
            Self::Code(code) => SessionEvent::Exit { ch, code },
            Self::Unavailable => SessionEvent::ExitStatusUnavailable { ch },
        }
    }
}

pub(super) const EARLY_EVENTS: usize = 256;
pub(super) const UNKNOWN_BYTES: usize = 512 * 1024;
pub(super) const UNKNOWN_EVENTS: usize = 2048;

#[derive(Clone, Copy)]
struct Desired {
    size: TerminalSize,
    revision: u64,
    eligible: bool,
}
#[derive(Clone, Copy)]
struct Pending {
    id: ResizeRequestId,
    intent: Desired,
}
#[derive(Clone, Copy)]
struct Intent {
    instance: ChannelInstance,
    desired: Option<Desired>,
    refused: Option<Desired>,
    continuity_lost: bool,
}
/// Portable intent only: never lifecycle authority or an old attachment's result.
#[derive(Default)]
pub struct AttachmentIntent {
    entries: BTreeMap<ChannelId, Intent>,
}

impl AttachmentIntent {
    /// Physical changes while detached retain their revision and refusal scope.
    pub fn defer_resize(&mut self, ch: ChannelId, cols: u16, rows: u16) -> ResizeDisposition {
        let Some(intent) = self.entries.get_mut(&ch) else {
            return ResizeDisposition::Rejected(ResizeRejection::NotReady);
        };
        match OrderedSession::update_desired(&mut intent.desired, cols, rows, false) {
            Ok(()) => ResizeDisposition::Coalesced,
            Err(reason) => ResizeDisposition::Rejected(reason),
        }
    }
}

struct Entry {
    request: Option<OpenRequest>,
    classification: Option<OpenClassification>,
    confirmed: bool,
    instance: Option<ChannelInstance>,
    // One monotonic retirement frontier per stream, including local OPEN reuse.
    retired_through: Option<ChannelInstance>,
    committed: Option<GeometryRecord>,
    desired: Option<Desired>,
    pending: Option<Pending>,
    completed: Option<GeometryRecord>,
    refused: Option<Desired>,
    next_id: Option<ResizeRequestId>,
    ready: bool,
    ready_reported: bool,
    draining: bool,
    gone: bool,
    continuity_lost: bool,
    buffer: VecDeque<SubstrateEvent>,
    payload_bytes: usize,
    retained_bytes: usize,
    exit: Option<ExitOutcome>,
}
impl Default for Entry {
    fn default() -> Self {
        Self {
            request: None,
            classification: None,
            confirmed: false,
            instance: None,
            retired_through: None,
            committed: None,
            desired: None,
            pending: None,
            completed: None,
            refused: None,
            next_id: ResizeRequestId::new(1),
            ready: false,
            ready_reported: false,
            draining: false,
            gone: false,
            continuity_lost: false,
            buffer: VecDeque::new(),
            payload_bytes: 0,
            retained_bytes: 0,
            exit: None,
        }
    }
}
impl Entry {
    fn from_open(request: OpenRequest) -> Self {
        let classification = OpenClassification::from_open(&request);
        let desired = TerminalSize::new(request.cols, request.rows)
            .ok()
            .map(|size| Desired {
                size,
                revision: 0,
                eligible: true,
            });
        Self {
            request: Some(request),
            classification: Some(classification),
            desired,
            ..Self::default()
        }
    }
    fn retire(&mut self) {
        *self = Self {
            gone: true,
            instance: self.instance,
            retired_through: self.instance.or(self.retired_through),
            continuity_lost: self.continuity_lost,
            ..Self::default()
        };
    }
    fn writable(&self) -> bool {
        self.confirmed && self.ready && !self.draining && !self.gone
    }
    fn retained_events(&self) -> usize {
        self.buffer.len() + usize::from(self.exit.is_some())
    }
    fn all_retained_bytes(&self) -> usize {
        // Reserve the larger numeric Exit size for either terminal status.
        self.retained_bytes + 10 * usize::from(self.exit.is_some())
    }
}

#[derive(Default)]
pub(super) struct OrderedSession {
    entries: BTreeMap<ChannelId, Entry>,
    imported: BTreeMap<ChannelId, Intent>,
    failure: Option<ChannelProtocolError>,
}
impl OrderedSession {
    pub(super) fn ignore_input(&self, ch: ChannelId) -> bool {
        ch >= FIRST_CHANNEL_STREAM
            && (self.failure.is_some() || self.entries.get(&ch).is_some_and(|e| e.gone))
    }
    pub(super) fn input_limits<S: ChannelSubstrate>(
        &self,
        substrate: &S,
        ch: ChannelId,
    ) -> InputLimits {
        if ch < FIRST_CHANNEL_STREAM {
            return InputLimits::UNLIMITED;
        }
        let entry = self.entries.get(&ch);
        let classified = entry.is_some_and(|e| e.classification.is_some());
        let ready = entry.is_some_and(|e| e.ready);
        let mut limits = InputLimits {
            payload: if ready {
                usize::MAX
            } else {
                MAX_BUFFERED_BEFORE_READY.saturating_sub(entry.map_or(0, |e| e.payload_bytes))
            },
            bytes: usize::MAX,
            events: if ready {
                usize::MAX
            } else {
                EARLY_EVENTS.saturating_sub(entry.map_or(0, Entry::retained_events))
            },
        };
        if !classified {
            let (mut bytes, mut events) = self.unknown_usage();
            for other in FIRST_CHANNEL_STREAM..=255 {
                if other != ch
                    && !self
                        .entries
                        .get(&other)
                        .is_some_and(|e| e.classification.is_some() || e.gone)
                {
                    let usage = substrate.input_usage(other);
                    bytes += usage.bytes;
                    events += usage.events;
                }
            }
            limits.bytes = UNKNOWN_BYTES.saturating_sub(bytes);
            limits.events = limits.events.min(UNKNOWN_EVENTS.saturating_sub(events));
        }
        limits
    }
    pub(super) fn free_stream(&self) -> Option<ChannelId> {
        if self.failure.is_some() {
            return None;
        }
        (FIRST_CHANNEL_STREAM..=255)
            .find(|ch| !self.entries.contains_key(ch))
            .or_else(|| {
                self.entries
                    .iter()
                    .find_map(|(&ch, e)| e.gone.then_some(ch))
            })
    }
    pub(super) fn open(&mut self, request: OpenRequest) {
        let ch = request.stream;
        let retired_through = self.entries.get(&ch).and_then(|e| e.retired_through);
        let mut entry = Entry::from_open(request);
        entry.retired_through = retired_through;
        self.entries.insert(ch, entry);
    }
    pub(super) fn is_ready(&self, ch: ChannelId) -> bool {
        self.failure.is_none() && self.entries.get(&ch).is_some_and(Entry::writable)
    }
    pub(super) fn continuity_lost(&self, ch: ChannelId) -> bool {
        self.entries
            .get(&ch)
            .is_some_and(|entry| entry.continuity_lost)
    }
    pub(super) fn committed(&self, ch: ChannelId) -> Option<GeometryRecord> {
        self.entries.get(&ch).and_then(|entry| entry.committed)
    }
    pub(super) fn close<S: ChannelSubstrate>(&mut self, substrate: &mut S, ch: ChannelId) {
        if self.is_ready(ch) || self.entries.get(&ch).is_some_and(|e| e.draining && !e.gone) {
            substrate.close(ch);
            substrate.retire_channel(ch);
            self.entries.get_mut(&ch).expect("known channel").retire();
        }
    }
    pub(super) fn into_intent(mut self) -> AttachmentIntent {
        for (ch, entry) in self.entries {
            if !entry.gone {
                if let Some(instance) = entry.instance {
                    self.imported.insert(
                        ch,
                        Intent {
                            instance,
                            desired: entry.desired,
                            refused: entry.refused,
                            continuity_lost: entry.continuity_lost,
                        },
                    );
                }
            }
        }
        AttachmentIntent {
            entries: self.imported,
        }
    }
    pub(super) fn import_intent(&mut self, intent: AttachmentIntent) {
        self.imported = intent.entries;
    }
    pub(super) fn reset_attachment(&mut self) {
        let intent = std::mem::take(self).into_intent();
        self.import_intent(intent);
    }
    pub(super) fn reset_stream(&mut self, ch: ChannelId) {
        if let Some(entry) = self.entries.get_mut(&ch) {
            entry.ready = false;
            entry.buffer.clear();
            entry.payload_bytes = 0;
            entry.retained_bytes = 0;
        }
    }
    fn fail<S: ChannelSubstrate>(
        &mut self,
        substrate: &mut S,
        error: ChannelProtocolError,
    ) -> Vec<SessionEvent> {
        if self.failure.is_some() {
            return Vec::new();
        }
        self.failure = Some(error);
        for entry in self.entries.values_mut() {
            entry.buffer.clear();
            entry.payload_bytes = 0;
            entry.retained_bytes = 0;
            entry.exit = None;
        }
        substrate.protocol_failed(error);
        vec![SessionEvent::ProtocolFailure(error)]
    }
    pub(super) fn resize<S: ChannelSubstrate>(
        &mut self,
        substrate: &mut S,
        ch: ChannelId,
        cols: u16,
        rows: u16,
    ) -> ResizeDisposition {
        if self.failure.is_some() {
            return ResizeDisposition::Rejected(ResizeRejection::Failed);
        }
        if cols == 0 || rows == 0 {
            return ResizeDisposition::Rejected(ResizeRejection::ZeroViewport);
        }
        let Some(entry) = self.entries.get_mut(&ch) else {
            return ResizeDisposition::Rejected(ResizeRejection::NotReady);
        };
        if entry.gone || entry.draining {
            return ResizeDisposition::Rejected(ResizeRejection::Ended);
        }
        if entry
            .classification
            .is_some_and(|c| c.cols == 0 || c.rows == 0)
        {
            return ResizeDisposition::Rejected(ResizeRejection::NoPty);
        }
        if !entry.writable() && entry.pending.is_none() {
            return ResizeDisposition::Rejected(ResizeRejection::NotReady);
        }
        if let Err(reason) = Self::update_desired(&mut entry.desired, cols, rows, true) {
            return ResizeDisposition::Rejected(reason);
        }
        Self::send_desired(substrate, ch, entry)
    }
    fn update_desired(
        desired: &mut Option<Desired>,
        cols: u16,
        rows: u16,
        eligible: bool,
    ) -> Result<(), ResizeRejection> {
        if cols == 0 || rows == 0 {
            if let Some(desired) = desired {
                desired.eligible = false;
            }
            return Err(ResizeRejection::ZeroViewport);
        }
        let size = TerminalSize::for_viewport(cols, rows);
        let revision = match *desired {
            Some(old) if old.size == size => old.revision,
            Some(old) => old
                .revision
                .checked_add(1)
                .ok_or(ResizeRejection::RequestIdExhausted)?,
            None => 0,
        };
        *desired = Some(Desired {
            size,
            revision,
            eligible,
        });
        Ok(())
    }
    pub(super) fn defer_resize(
        &mut self,
        ch: ChannelId,
        cols: u16,
        rows: u16,
    ) -> ResizeDisposition {
        if self.failure.is_some() {
            return ResizeDisposition::Rejected(ResizeRejection::Failed);
        }
        let desired = if let Some(entry) = self.entries.get_mut(&ch) {
            if entry.gone || entry.draining {
                return ResizeDisposition::Rejected(ResizeRejection::Ended);
            }
            if entry
                .classification
                .is_some_and(|c| c.cols == 0 || c.rows == 0)
            {
                return ResizeDisposition::Rejected(ResizeRejection::NoPty);
            }
            // Early output may create a provisional entry before Snapshot. The
            // imported intent still owns its revision/refusal basis until that
            // snapshot establishes identity; do not start a second desired state.
            // A local OPEN has its own request and must keep its own intent.
            match self
                .imported
                .get_mut(&ch)
                .filter(|_| entry.instance.is_none() && entry.request.is_none())
            {
                Some(intent) => &mut intent.desired,
                None => &mut entry.desired,
            }
        } else if let Some(intent) = self.imported.get_mut(&ch) {
            &mut intent.desired
        } else {
            return ResizeDisposition::Rejected(ResizeRejection::NotReady);
        };
        match Self::update_desired(desired, cols, rows, false) {
            Ok(()) => ResizeDisposition::Coalesced,
            Err(reason) => ResizeDisposition::Rejected(reason),
        }
    }
    fn send_desired<S: ChannelSubstrate>(
        substrate: &mut S,
        ch: ChannelId,
        entry: &mut Entry,
    ) -> ResizeDisposition {
        if entry.pending.is_some() {
            return ResizeDisposition::Coalesced;
        }
        if !entry.writable() {
            return ResizeDisposition::Rejected(ResizeRejection::NotReady);
        }
        let Some(desired) = entry.desired else {
            return ResizeDisposition::Unchanged;
        };
        if !desired.eligible {
            return ResizeDisposition::Coalesced;
        }
        let committed = entry.committed.expect("ready has geometry");
        if (committed.cols, committed.rows) == (desired.size.cols(), desired.size.rows())
            || entry
                .refused
                .is_some_and(|old| old.revision == desired.revision && old.size == desired.size)
        {
            return ResizeDisposition::Unchanged;
        }
        let Some(id) = entry.next_id else {
            return ResizeDisposition::Rejected(ResizeRejection::RequestIdExhausted);
        };
        if substrate
            .resize_correlated(
                ch,
                committed.instance,
                id,
                desired.size.cols(),
                desired.size.rows(),
            )
            .is_err()
        {
            return ResizeDisposition::Rejected(ResizeRejection::Failed);
        }
        entry.pending = Some(Pending {
            id,
            intent: desired,
        });
        entry.next_id = id.checked_next();
        ResizeDisposition::Sent
    }
    fn inherit_intent(&mut self, ch: ChannelId, entry: &mut Entry, instance: ChannelInstance) {
        if let Some(intent) = self
            .imported
            .remove(&ch)
            .filter(|intent| intent.instance == instance)
        {
            entry.desired = intent.desired;
            entry.refused = intent.refused;
            entry.continuity_lost = intent.continuity_lost;
        }
    }
    fn geometry<S: ChannelSubstrate>(
        &mut self,
        substrate: &mut S,
        ch: ChannelId,
        entry: &mut Entry,
        record: GeometryRecord,
        out: &mut Vec<SessionEvent>,
    ) -> Result<(), ChannelProtocolError> {
        let classification = entry.classification.ok_or(ChannelProtocolError::Metadata)?;
        record
            .validate_for_open(classification.cols, classification.rows)
            .map_err(|_| ChannelProtocolError::Metadata)?;
        if entry
            .instance
            .is_some_and(|instance| instance != record.instance)
            || entry
                .retired_through
                .is_some_and(|retired| record.instance.get() <= retired.get())
        {
            return Err(ChannelProtocolError::Instance);
        }
        entry.instance = Some(record.instance);
        self.inherit_intent(ch, entry, record.instance);
        let mut refusal = None;
        if record.outcome != GeometryOutcome::Established {
            if let Some(pending) = entry
                .pending
                .filter(|pending| pending.id.get() == record.request_id)
            {
                if record.outcome == GeometryOutcome::Applied
                    && (record.cols, record.rows)
                        != (pending.intent.size.cols(), pending.intent.size.rows())
                {
                    return Err(ChannelProtocolError::Correlation);
                }
                entry.pending = None;
                entry.completed = Some(record);
                if let GeometryOutcome::Refused(reason) = record.outcome {
                    entry.refused = Some(pending.intent);
                    refusal = Some((pending, reason));
                }
            } else if entry.completed != Some(record) {
                return Err(ChannelProtocolError::Correlation);
            }
        }
        entry.committed = Some(record);
        if entry.desired.is_none() {
            entry.desired = TerminalSize::new(record.cols, record.rows)
                .ok()
                .map(|size| Desired {
                    size,
                    revision: 0,
                    eligible: true,
                });
        }
        entry.ready = true;
        out.push(SessionEvent::Geometry { ch, record });
        if !entry.ready_reported {
            entry.ready_reported = true;
            out.push(if entry.draining {
                SessionEvent::DrainingReady(ch)
            } else {
                SessionEvent::Ready(ch)
            });
        }
        if let Some((pending, reason)) = refusal {
            out.push(SessionEvent::ResizeRefused {
                ch,
                request_id: pending.id,
                requested: pending.intent.size,
                reason,
            });
        }
        Self::send_desired(substrate, ch, entry);
        Ok(())
    }
    fn event_cost(event: &SubstrateEvent) -> (usize, usize) {
        match event {
            SubstrateEvent::Data { bytes, .. } | SubstrateEvent::ExtendedData { bytes, .. } => {
                (bytes.len(), bytes.len() + 5)
            }
            SubstrateEvent::Geometry { .. } => (0, 27),
            SubstrateEvent::OutputGap { .. } => (0, 14),
            SubstrateEvent::InputConsumed { .. } => (0, 13),
            _ => (0, 10),
        }
    }
    fn unknown_usage(&self) -> (usize, usize) {
        self.entries
            .values()
            .filter(|e| e.classification.is_none() && !e.gone)
            .fold((0, 0), |(bytes, events), e| {
                (bytes + e.all_retained_bytes(), events + e.retained_events())
            })
    }
    fn buffer<S: ChannelSubstrate>(
        &self,
        substrate: &S,
        ch: ChannelId,
        entry: &mut Entry,
        event: SubstrateEvent,
    ) -> Result<(), ChannelProtocolError> {
        let (payload, bytes) = Self::event_cost(&event);
        if entry.retained_events() + substrate.input_usage(ch).events >= EARLY_EVENTS
            || payload > MAX_BUFFERED_BEFORE_READY.saturating_sub(entry.payload_bytes)
        {
            return Err(ChannelProtocolError::EarlyOutputOverflow);
        }
        if entry.classification.is_none() {
            let (mut other_bytes, mut other_events) = self.unknown_usage();
            for other in FIRST_CHANNEL_STREAM..=255 {
                if !self
                    .entries
                    .get(&other)
                    .is_some_and(|e| e.classification.is_some() || e.gone)
                {
                    let raw = substrate.input_usage(other);
                    other_bytes += raw.bytes;
                    other_events += raw.events;
                }
            }
            if bytes > UNKNOWN_BYTES.saturating_sub(other_bytes + entry.all_retained_bytes())
                || other_events + entry.retained_events() >= UNKNOWN_EVENTS
            {
                return Err(ChannelProtocolError::EarlyOutputOverflow);
            }
        }
        entry.payload_bytes += payload;
        entry.retained_bytes += bytes;
        entry.buffer.push_back(event);
        Ok(())
    }
    fn flush<S: ChannelSubstrate>(
        &mut self,
        substrate: &mut S,
        ch: ChannelId,
        entry: &mut Entry,
        out: &mut Vec<SessionEvent>,
    ) -> Result<(), ChannelProtocolError> {
        if !entry.confirmed {
            return Ok(());
        }
        while let Some(event) = entry.buffer.pop_front() {
            let (payload, bytes) = Self::event_cost(&event);
            entry.payload_bytes -= payload;
            entry.retained_bytes -= bytes;
            match event {
                SubstrateEvent::Geometry { record, .. } => {
                    self.geometry(substrate, ch, entry, record, out)?
                }
                _ if !entry.ready => return Err(ChannelProtocolError::GeometryRequired),
                SubstrateEvent::Data { bytes, .. } => out.push(SessionEvent::Data { ch, bytes }),
                SubstrateEvent::ExtendedData {
                    data_type, bytes, ..
                } => out.push(SessionEvent::ExtendedData {
                    ch,
                    data_type,
                    bytes,
                }),
                SubstrateEvent::InputConsumed { offset, .. } => {
                    out.push(SessionEvent::InputConsumed { ch, offset })
                }
                SubstrateEvent::OutputGap {
                    instance, cause, ..
                } => {
                    if entry.instance != Some(instance) {
                        return Err(ChannelProtocolError::Instance);
                    }
                    entry.continuity_lost = true;
                    out.push(SessionEvent::OutputContinuityLost {
                        ch,
                        instance,
                        cause,
                    });
                }
                _ => return Err(ChannelProtocolError::Metadata),
            }
        }
        Ok(())
    }
    fn compatible(a: OpenClassification, b: OpenClassification) -> bool {
        a.kind == b.kind
            && a.screen == b.screen
            && if a.cols == 0 || a.rows == 0 || b.cols == 0 || b.rows == 0 {
                (a.cols, a.rows) == (b.cols, b.rows)
            } else {
                true
            }
    }
    fn snapshot<S: ChannelSubstrate>(
        &mut self,
        substrate: &mut S,
        snapshot: ChannelSnapshot,
    ) -> Result<Vec<SessionEvent>, ChannelProtocolError> {
        let (active, draining) = snapshot.into_parts();
        let mut present = [false; 256];
        let mut out = Vec::new();
        let mut accepted_active = Vec::new();
        let mut accepted_draining = Vec::new();
        for (ch, instance, request, classification, ended) in active
            .into_iter()
            .map(|e| {
                let class = OpenClassification::from_open(&e.request);
                (e.request.stream, e.instance, Some(e.request), class, false)
            })
            .chain(
                draining
                    .into_iter()
                    .map(|e| (e.stream, e.instance, None, e.open, true)),
            )
        {
            present[ch as usize] = true;
            let previous = self.entries.entry(ch).or_default();
            if previous
                .instance
                .is_some_and(|old| instance.get() < old.get())
                || previous
                    .retired_through
                    .is_some_and(|old| instance.get() < old.get())
            {
                return Err(ChannelProtocolError::Instance);
            }
            if previous.retired_through == Some(instance) {
                if !ended {
                    return Err(ChannelProtocolError::Metadata);
                }
                // A repeated terminal snapshot cannot reopen an output lifecycle.
                // Keep the tombstone (or a pending local OPEN) and its frontier.
                continue;
            }
            let replacement = previous.gone || previous.instance.is_some_and(|old| old != instance);
            let mut entry = if replacement {
                // The admitted identity changes framing ownership as well as state.
                // Same-instance metadata must retain a partially received exit tail.
                substrate.retire_channel(ch);
                Entry {
                    retired_through: previous.instance.or(previous.retired_through),
                    ..Entry::default()
                }
            } else {
                self.entries.remove(&ch).unwrap_or_default()
            };
            if entry
                .classification
                .is_some_and(|old| !Self::compatible(old, classification))
                || (entry.draining && !ended)
            {
                self.entries.insert(ch, entry);
                return Err(ChannelProtocolError::Metadata);
            }
            if let (Some(old), Some(new)) = (&entry.request, &request) {
                if old.command != new.command {
                    self.entries.insert(ch, entry);
                    return Err(ChannelProtocolError::Metadata);
                }
            }
            entry.instance = Some(instance);
            entry.classification = Some(classification);
            entry.request = request;
            entry.confirmed = true;
            entry.draining |= ended;
            self.inherit_intent(ch, &mut entry, instance);
            let result = self.flush(substrate, ch, &mut entry, &mut out);
            self.entries.insert(ch, entry);
            result?;
            if ended {
                accepted_draining.push(ch);
            } else {
                accepted_active.push(ch);
            }
        }
        for (&ch, entry) in &mut self.entries {
            if entry.confirmed && !entry.gone && !present[ch as usize] {
                entry.retire();
                substrate.retire_channel(ch);
                out.push(SessionEvent::Vanished { ch });
            }
        }
        out.insert(
            0,
            SessionEvent::Announced {
                active: accepted_active,
                draining: accepted_draining,
            },
        );
        Ok(out)
    }
    pub(super) fn on_event<S: ChannelSubstrate>(
        &mut self,
        substrate: &mut S,
        event: SubstrateEvent,
    ) -> Vec<SessionEvent> {
        if self.failure.is_some() {
            return Vec::new();
        }
        match event {
            SubstrateEvent::ProtocolFailure(error) => self.fail(substrate, error),
            SubstrateEvent::Snapshot(snapshot) => match self.snapshot(substrate, snapshot) {
                Ok(out) => out,
                Err(error) => self.fail(substrate, error),
            },
            SubstrateEvent::Announced(_) => {
                self.fail(substrate, ChannelProtocolError::UnsupportedProfile)
            }
            SubstrateEvent::Daemon(record) => vec![SessionEvent::Daemon(record)],
            event => {
                let ch = match &event {
                    SubstrateEvent::Opened(ch) => *ch,
                    SubstrateEvent::Refused { ch, .. }
                    | SubstrateEvent::Data { ch, .. }
                    | SubstrateEvent::ExtendedData { ch, .. }
                    | SubstrateEvent::InputConsumed { ch, .. }
                    | SubstrateEvent::Exit { ch, .. }
                    | SubstrateEvent::ExitStatusUnavailable { ch }
                    | SubstrateEvent::Geometry { ch, .. }
                    | SubstrateEvent::OutputGap { ch, .. } => *ch,
                    _ => unreachable!(),
                };
                if ch < FIRST_CHANNEL_STREAM
                    || (!self.entries.contains_key(&ch) && self.entries.len() == CHANNEL_IDENTITIES)
                {
                    return self.fail(substrate, ChannelProtocolError::Metadata);
                }
                let mut entry = self.entries.remove(&ch).unwrap_or_default();
                if entry.gone {
                    self.entries.insert(ch, entry);
                    return Vec::new();
                }
                let mut out = Vec::new();
                let result = match event {
                    SubstrateEvent::Opened(_) => {
                        if entry.request.is_none() {
                            Err(ChannelProtocolError::Metadata)
                        } else {
                            entry.confirmed = true;
                            self.flush(substrate, ch, &mut entry, &mut out)
                        }
                    }
                    SubstrateEvent::Refused { reason, .. } => {
                        entry.retire();
                        substrate.retire_channel(ch);
                        out.push(SessionEvent::Refused { ch, reason });
                        Ok(())
                    }
                    event @ (SubstrateEvent::Exit { .. }
                    | SubstrateEvent::ExitStatusUnavailable { .. }) => {
                        let outcome = match &event {
                            SubstrateEvent::Exit { code, .. } => ExitOutcome::Code(*code),
                            SubstrateEvent::ExitStatusUnavailable { .. } => {
                                ExitOutcome::Unavailable
                            }
                            _ => unreachable!(),
                        };
                        if entry.exit.is_some_and(|old| old != outcome) {
                            Err(ChannelProtocolError::Metadata)
                        } else {
                            let admission = if entry.exit.is_none() {
                                self.buffer(substrate, ch, &mut entry, event).map(|()| {
                                    entry.buffer.pop_back();
                                    entry.retained_bytes -= 10;
                                })
                            } else {
                                Ok(())
                            };
                            admission.map(|()| {
                                entry.exit = Some(outcome);
                                entry.draining = true;
                            })
                        }
                    }
                    event => self
                        .buffer(substrate, ch, &mut entry, event)
                        .and_then(|()| self.flush(substrate, ch, &mut entry, &mut out)),
                };
                self.entries.insert(ch, entry);
                match result {
                    Ok(()) => out,
                    Err(error) => self.fail(substrate, error),
                }
            }
        }
    }
    pub(super) fn finish_exits<S: ChannelSubstrate>(
        &mut self,
        substrate: &mut S,
    ) -> Vec<SessionEvent> {
        if self.failure.is_some() {
            return Vec::new();
        }
        let mut out = Vec::new();
        for (&ch, entry) in &mut self.entries {
            if entry.confirmed
                && entry.ready
                && entry.buffer.is_empty()
                && !substrate.has_partial_input(ch)
            {
                if let Some(code) = entry.exit {
                    entry.retire();
                    substrate.retire_channel(ch);
                    out.push(code.event(ch));
                }
            }
        }
        out
    }
}

#[cfg(test)]
mod exhaustion_tests {
    use super::*;
    #[test]
    fn retirement_frontier_keeps_one_entry_across_many_instances() {
        use transport::channel::{encode_server, DrainingChannel, ServerRecord, CONTROL_STREAM};
        use transport::shell_frame::{encode_shell, ShellRecord};
        let mut s = ChannelSession::new(crate::qsh::QshSubstrate::new(|_, _| {}));
        for id in 1..=1024 {
            let instance = ChannelInstance::new(id).unwrap();
            let snapshot = ChannelSnapshot::new(
                vec![],
                vec![DrainingChannel {
                    stream: 16,
                    instance,
                    open: OpenClassification {
                        kind: ChannelKind::Shell,
                        screen: true,
                        cols: 80,
                        rows: 24,
                    },
                }],
            )
            .unwrap();
            s.on_bytes(CONTROL_STREAM, &snapshot.encode_record());
            let record = GeometryRecord {
                instance,
                request_id: 0,
                outcome: GeometryOutcome::Established,
                cols: 80,
                rows: 24,
            };
            s.on_bytes(16, &encode_shell(&ShellRecord::Geometry(record)).unwrap());
            assert_eq!(
                s.on_bytes(
                    CONTROL_STREAM,
                    &encode_server(&ServerRecord::Exit {
                        stream: 16,
                        code: 0,
                    })
                ),
                vec![SessionEvent::Exit { ch: 16, code: 0 }]
            );
            let state = s.ordered.as_ref().unwrap();
            assert_eq!(state.entries.len(), 1);
            assert!(state.imported.is_empty());
            let retired = &state.entries[&16];
            assert!(retired.gone);
            assert_eq!(retired.retired_through, Some(instance));
            assert!(retired.buffer.is_empty());
            let usage = s.substrate.input_usage(16);
            assert_eq!((usage.bytes, usage.events), (0, 0));
        }
        assert_eq!(std::mem::size_of::<Option<ChannelInstance>>(), 8);
    }
    #[test]
    fn last_request_id_is_used_once_and_never_wraps() {
        let mut s = ChannelSession::new(crate::qsh::QshSubstrate::new(|_, _| {}));
        let ch = s.open_shell(80, 24).unwrap();
        s.on_event(SubstrateEvent::Opened(ch));
        let record = GeometryRecord {
            instance: ChannelInstance::new(1).unwrap(),
            request_id: 0,
            outcome: GeometryOutcome::Established,
            cols: 80,
            rows: 24,
        };
        s.on_event(SubstrateEvent::Geometry { ch, record });
        s.ordered
            .as_mut()
            .unwrap()
            .entries
            .get_mut(&ch)
            .unwrap()
            .next_id = ResizeRequestId::new(u64::MAX);
        assert_eq!(s.resize(ch, 100, 30), ResizeDisposition::Sent);
        let record = GeometryRecord {
            request_id: u64::MAX,
            outcome: GeometryOutcome::Applied,
            cols: 100,
            rows: 30,
            ..record
        };
        s.on_event(SubstrateEvent::Geometry { ch, record });
        assert_eq!(
            s.resize(ch, 120, 40),
            ResizeDisposition::Rejected(ResizeRejection::RequestIdExhausted)
        );
        assert_eq!(s.committed_geometry(ch), Some(record));
    }
}
