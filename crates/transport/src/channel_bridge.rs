//! Owned channel output between the runner and bounded Connection admission.
use super::*;
use crate::channel::{ChannelCodecError, ChannelSnapshot, DrainingChannel};
use crate::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord, OutputGapCause};
use crate::channel_timeline::{TimelineBudget, TimelinePermit, GEOMETRY_BYTES};
use crate::shell_frame::{encode_shell, ShellRecord};

const TURN_RECORDS: usize = 32;
const TURN_BYTES: usize = 64 * 1024;

pub(super) struct ReservedSnapshot {
    snapshot: ChannelSnapshot,
    prefix: u64,
    source: crate::control_budget::ResponsePermit,
    merged: crate::control_budget::ResponsePermit,
    wire: crate::control_budget::ResponsePermit,
}
impl ReservedSnapshot {
    // Standalone runner fixtures consume custody to inspect the DTO. This is
    // deliberately not a peer ACK or production delivery path.
    #[cfg(any(test, feature = "testnet"))]
    pub(super) fn into_fixture_snapshot(self) -> ChannelSnapshot {
        self.snapshot
    }
}
struct PendingSnapshot {
    snapshot: ChannelSnapshot,
    _merged: crate::control_budget::ResponsePermit,
    // Once source DTO storage is gone, its independent allowance covers the
    // encoded scratch Vec until the consuming sender call destroys that Vec.
    _scratch: crate::control_budget::ResponsePermit,
    wire: crate::control_budget::ResponseOwner,
}
impl std::ops::Deref for PendingSnapshot {
    type Target = ChannelSnapshot;
    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}
#[derive(Debug)]
pub(super) enum SnapshotError {
    Capacity(crate::control_budget::CapacityError),
    Codec,
}
#[derive(Default)]
struct SnapshotSlot {
    generation: Option<u64>,
    minimum_generation: u64,
    notification_pending: bool,
    produced: u64,
    observed: u64,
    value: Option<ReservedSnapshot>,
}
pub(super) struct SnapshotPublication {
    pub published: bool,
    pub notify: bool,
}
impl SnapshotPublication {
    const STALE: Self = Self {
        published: false,
        notify: false,
    };
}
#[derive(Clone, Default)]
pub(super) struct SnapshotMailbox(Arc<Mutex<SnapshotSlot>>);
impl SnapshotMailbox {
    pub(super) fn publish(
        &self,
        generation: u64,
        budget: &crate::control_budget::SessionBudget,
        build: impl FnOnce() -> Result<ChannelSnapshot, ChannelCodecError>,
    ) -> Result<SnapshotPublication, SnapshotError> {
        let old = {
            let mut slot = self.0.lock().expect("resume snapshot");
            if generation < slot.minimum_generation
                || slot.generation.is_some_and(|old| old >= generation)
            {
                return Ok(SnapshotPublication::STALE);
            }
            slot.generation = Some(generation);
            slot.value.take()
        };
        // Destroy obsolete storage and refund outside the mailbox lock before
        // admitting the next independent source/merge/wire representations.
        drop(old);
        let [source, merged, wire] = budget.reserve_snapshot().map_err(SnapshotError::Capacity)?;
        let snapshot = build().map_err(|_| SnapshotError::Codec)?;
        let mut replacement = Some(ReservedSnapshot {
            snapshot,
            prefix: 0,
            source,
            merged,
            wire,
        });
        let published = {
            let mut slot = self.0.lock().expect("resume snapshot");
            if generation >= slot.minimum_generation && slot.generation == Some(generation) {
                debug_assert!(slot.value.is_none());
                replacement.as_mut().expect("one source snapshot").prefix = slot.produced;
                slot.value = replacement.take();
                let notify = !slot.notification_pending;
                slot.notification_pending = true;
                SnapshotPublication {
                    published: true,
                    notify,
                }
            } else {
                SnapshotPublication::STALE
            }
        };
        // A newer publication may have superseded a synchronous builder on a
        // different thread. Its older custody is never dropped under the lock.
        drop(replacement);
        Ok(published)
    }
    // Position assignment and successful queue publication commit under one
    // short lock, so concurrent producers cannot invert a snapshot prefix.
    // Failed messages (and their permits) are destroyed after releasing it.
    pub(super) fn send_ordered(
        &self,
        sender: &mpsc::UnboundedSender<SessionOutbound>,
        mut message: SessionOutbound,
    ) -> bool {
        let (overflow, rejected) = {
            let mut slot = self.0.lock().expect("resume snapshot");
            match slot.produced.checked_add(1) {
                Some(next) => {
                    message.assign_channel_position(next);
                    match sender.send(message) {
                        Ok(()) => {
                            slot.produced = next;
                            (false, None)
                        }
                        Err(error) => (false, Some(error.0)),
                    }
                }
                None => (true, Some(message)),
            }
        };
        drop(rejected);
        !overflow
    }
    fn observed(&self, position: u64) {
        if position == 0 {
            return;
        } // Direct fixture, not a queued publication.
        let mut slot = self.0.lock().expect("resume snapshot");
        assert_eq!(
            slot.observed.checked_add(1),
            Some(position),
            "typed output processed in source queue order"
        );
        slot.observed = position;
    }
    pub(super) fn discard_before(&self, generation: u64) {
        let old = {
            let mut slot = self.0.lock().expect("resume snapshot");
            slot.minimum_generation = slot.minimum_generation.max(generation);
            if slot.generation.is_some_and(|old| old < generation) {
                slot.value.take()
            } else {
                None
            }
        };
        drop(old);
    }
    // A wake carries no generation. Consume its latch and take payload only
    // for the exact bridge target. A future payload stays parked until attach;
    // attach may take it without consuming a still-queued wake's latch.
    fn take(&self, generation: Option<u64>, consume_wake: bool) -> Option<ReservedSnapshot> {
        let mut slot = self.0.lock().expect("resume snapshot");
        if consume_wake {
            slot.notification_pending = false;
        }
        (slot.generation == generation
            && generation.is_some()
            && slot
                .value
                .as_ref()
                .is_some_and(|value| value.prefix <= slot.observed))
        .then(|| slot.value.take())
        .flatten()
    }
    #[cfg(any(test, feature = "testnet"))]
    pub(super) fn take_fixture(&self) -> Option<(u64, ChannelSnapshot)> {
        let (generation, value) = {
            let mut slot = self.0.lock().expect("resume snapshot");
            slot.notification_pending = false;
            (slot.generation, slot.value.take())
        };
        generation
            .zip(value)
            .map(|(generation, value)| (generation, value.into_fixture_snapshot()))
    }
}

struct Queued {
    origin: AttachmentContext,
    output: Item,
    charge: Option<OutputCharge>,
    offset: usize,
    bound: Option<u64>,
}
enum Item {
    Record(ChannelOutput),
    Exit(
        Option<i32>,
        crate::channel::OpenClassification,
        TimelinePermit,
        Option<ControlDelivery>,
    ),
}
struct Stream {
    instance: ChannelInstance,
    gate: Arc<SendGate>,
    budget: TimelineBudget,
    // One reserved gap/bootstrap representation, reused after each handoff.
    _gap_reserve: TimelinePermit,
    gap_charge: Option<OutputCharge>,
    bootstrap_charge: Option<OutputCharge>,
    fifo: VecDeque<Queued>,
    // Original final marker ownership survives its delivery notification until
    // Exit or scoped teardown. Attach reuses it for fresh delivery proof.
    delivered_marker: Option<Queued>,
    // One terminal failure disclosure survives sender admission and ACK until
    // scoped teardown. A new attachment must learn why no repaint is possible.
    terminal_gap: Option<Queued>,
    terminal_gap_seen: bool,
    frontier: Option<GeometryRecord>,
    data_end: u64,
    // The last admitted continuity warning remains owed until this frontier is ACKed.
    gap_end: u64,
    bootstrap: bool,
    abandoned_data: bool,
    screened: bool,
    ended: bool,
    waiting_geometry: bool,
    hot_blocked: bool,
}
#[derive(Default)]
pub(super) struct ChannelBridge {
    pub(super) snapshots: SnapshotMailbox,
    pending_snapshot: Option<PendingSnapshot>,
    snapshot_failed: bool,
    streams: BTreeMap<u8, Stream>,
    declarations: BTreeMap<u8, bool>,
    retired: BTreeMap<u8, u64>, // u8 namespace bounds tombstones, no per-Attach history.
    generation: u64,
    target: Option<u64>,
    cursor: u8,
    ready: BTreeMap<u8, ChannelInstance>,
    delivered: BTreeMap<u8, (ChannelInstance, u64)>,
    hot_sequence: u64,
    hot_target: Option<u64>,
    hot_sent: Option<u64>,
    repaint_request: Option<SessionInbound>,
}
fn established(mut geometry: GeometryRecord) -> GeometryRecord {
    geometry.request_id = 0;
    geometry.outcome = GeometryOutcome::Established;
    geometry
}
fn charge(gate: &Arc<SendGate>, bytes: usize) -> OutputCharge {
    gate.admit(bytes as u64);
    OutputCharge {
        gate: gate.clone(),
        bytes: bytes as u64,
    }
}
impl ChannelBridge {
    pub(super) fn observe_discards(&mut self, conn: &mut Connection) {
        for (stream, instance) in conn.take_discarded_output() {
            if let Some(state) = self
                .streams
                .get_mut(&stream)
                .filter(|state| state.instance == instance)
            {
                state.abandoned_data = true;
                state.data_end = 0;
                state.gap_end = 0;
            }
        }
    }
    pub(super) fn seal_ended(&mut self, conn: &mut Connection) {
        self.observe_discards(conn);
        for (&stream, state) in self.streams.iter_mut().filter(|(_, state)| state.ended) {
            if conn.retain_stream_output(stream) {
                state.bootstrap = true;
                Self::rearm_final_marker(state);
                Self::rearm_terminal_gap(state);
                for queued in &mut state.fifo {
                    queued.bound = None;
                }
            }
        }
    }
    pub(super) fn repaint_barrier(&mut self, generation: u64, sequence: u64) {
        if generation != self.generation || self.hot_sent != Some(sequence) {
            return;
        }
        self.repaint_request = None;
        if self.hot_target != Some(sequence) {
            if let Some(latest) = self.hot_target {
                self.hot_sent = Some(latest);
                self.repaint_request = Some(SessionInbound::RepaintCutover {
                    generation,
                    sequence: latest,
                });
            }
            return;
        }
        self.hot_target = None;
        self.hot_sent = None;
        for state in self.streams.values_mut().filter(|state| state.hot_blocked) {
            state.hot_blocked = false;
            if state.ended {
                state.bootstrap = true;
                Self::rearm_final_marker(state);
                Self::rearm_terminal_gap(state);
                for queued in &mut state.fifo {
                    queued.bound = None;
                }
            } else {
                state.fifo.clear();
                state.waiting_geometry = true;
                state.bootstrap = false;
                state.data_end = 0;
                state.gap_end = 0;
                state.abandoned_data = false;
                state.gap_charge = None;
                state.bootstrap_charge = None;
            }
        }
    }
    pub(super) fn hot_reset(&mut self) -> bool {
        // At most one ordered request is in flight. Repeated resets replace only
        // the latest target; the old barrier schedules the newest request.
        let Some(sequence) = self.hot_sequence.checked_add(1) else {
            return false;
        };
        self.hot_sequence = sequence;
        self.hot_target = Some(self.hot_sequence);
        for state in self.streams.values_mut().filter(|state| state.screened) {
            state.hot_blocked = true;
        }
        if self.hot_sent.is_none() {
            self.hot_sent = self.hot_target;
            self.repaint_request = Some(SessionInbound::RepaintCutover {
                generation: self.generation,
                sequence: self.hot_sequence,
            });
        }
        true
    }

    pub(super) fn declare(&mut self, stream: u8, screened: bool) {
        self.declarations.insert(stream, screened);
        if let Some(state) = self.streams.get_mut(&stream) {
            state.screened = screened;
        }
    }
    pub(super) fn push(&mut self, message: SessionOutbound) {
        let position = message.channel_position();
        self.push_inner(message);
        if let Some(position) = position {
            // Even discarded old attachment/instance output satisfied its
            // queue prefix. Never wait while blocking this same input queue.
            self.snapshots.observed(position);
            self.prepare_snapshot(false);
        }
    }
    fn push_inner(&mut self, message: SessionOutbound) {
        match message {
            SessionOutbound::ChannelOutput {
                position: _,
                stream,
                instance,
                origin,
                output,
                charge,
                gap_reserve,
            } => {
                if self
                    .retired
                    .get(&stream)
                    .is_some_and(|old| *old >= instance.get())
                {
                    return;
                }
                if let Some(old) = self.streams.get(&stream) {
                    if old.instance.get() > instance.get() {
                        return;
                    }
                    if old.instance != instance {
                        self.streams.remove(&stream);
                        self.ready.remove(&stream);
                        self.delivered.remove(&stream);
                    }
                }
                if !self.streams.contains_key(&stream) {
                    let Some(reserve) = gap_reserve else {
                        return;
                    };
                    self.streams.insert(
                        stream,
                        Stream {
                            instance,
                            gate: charge.gate.clone(),
                            budget: reserve.budget(),
                            _gap_reserve: reserve,
                            gap_charge: None,
                            bootstrap_charge: None,
                            fifo: VecDeque::new(),
                            delivered_marker: None,
                            terminal_gap: None,
                            terminal_gap_seen: false,
                            frontier: None,
                            data_end: 0,
                            gap_end: 0,
                            bootstrap: self.target.is_some(),
                            abandoned_data: false,
                            screened: self.declarations.get(&stream).copied().unwrap_or(false),
                            ended: false,
                            waiting_geometry: false,
                            hot_blocked: self.hot_target.is_some()
                                && self.declarations.get(&stream).copied().unwrap_or(false),
                        },
                    );
                }
                let state = self.streams.get_mut(&stream).unwrap();
                if state.waiting_geometry {
                    match &output {
                        ChannelOutput::Geometry(record, ..) => {
                            // A failed model cannot supply a repaint. If its
                            // committed checkpoint was capacity-blocked, use
                            // that actual late checkpoint for the bootstrap;
                            // keep the original event and permit in FIFO order.
                            if state.terminal_gap_seen
                                && state.bootstrap
                                && state.frontier.is_none()
                            {
                                state.frontier = Some(established(*record));
                            }
                            state.waiting_geometry = false;
                        }
                        ChannelOutput::Data(_) | ChannelOutput::EchoAck(..) => return,
                        ChannelOutput::DeliveryMarker(..) | ChannelOutput::OutputGap(..) => {}
                    }
                }
                if matches!(output, ChannelOutput::OutputGap(..)) {
                    if state.terminal_gap_seen {
                        return; // Drop only the duplicate event's permit/charge.
                    }
                    state.terminal_gap_seen = true;
                    state.bootstrap |= state.waiting_geometry;
                    // Its model is no longer a valid replay source, even while
                    // the reader is still draining toward actual EOF.
                    state.ended = true;
                }
                if matches!(output, ChannelOutput::DeliveryMarker(..)) {
                    state.ended = true;
                }
                if origin.generation < self.generation
                    && matches!(output, ChannelOutput::EchoAck(..))
                {
                    return;
                }
                let mut queued = Queued {
                    origin,
                    output: Item::Record(output),
                    charge: Some(charge),
                    offset: 0,
                    bound: None,
                };
                Self::rebase(&mut queued, self.generation);
                Self::append(state, queued);
            }
            SessionOutbound::ChannelExit {
                position: _,
                stream,
                instance,
                origin,
                code,
                open,
                permit,
                control,
            } => {
                if let Some(state) = self
                    .streams
                    .get_mut(&stream)
                    .filter(|s| s.instance == instance)
                {
                    state.ended = true;
                    state.fifo.push_back(Queued {
                        origin,
                        output: Item::Exit(code, open, permit, Some(control)),
                        charge: None,
                        offset: 0,
                        bound: None,
                    });
                }
            }
            SessionOutbound::ChannelClosed {
                stream, instance, ..
            } => {
                self.retired
                    .entry(stream)
                    .and_modify(|old| *old = (*old).max(instance.get()))
                    .or_insert(instance.get());
                if self
                    .streams
                    .get(&stream)
                    .is_some_and(|s| s.instance == instance)
                {
                    self.streams.remove(&stream);
                    self.ready.remove(&stream);
                    self.delivered.remove(&stream);
                }
            }
            SessionOutbound::ResumeSnapshotReady => self.prepare_snapshot(true),
            SessionOutbound::RepaintBarrier {
                generation,
                sequence,
            } => self.repaint_barrier(generation, sequence),
            _ => unreachable!("only typed channel messages enter this owner"),
        }
    }
    fn rebase(queued: &mut Queued, generation: u64) {
        if queued.origin.generation < generation {
            if let Item::Record(ChannelOutput::Geometry(g, _)) = &mut queued.output {
                *g = established(*g);
            }
        }
    }
    fn append(state: &mut Stream, queued: Queued) {
        if matches!(&queued.output,Item::Record(ChannelOutput::Geometry(g,_)) if g.request_id==0)
            && state.fifo.back().is_some_and(|q|matches!(&q.output,Item::Record(ChannelOutput::Geometry(g,_)) if g.request_id==0)) {
            state.fifo.pop_back();
        }
        state.fifo.push_back(queued);
    }
    fn rearm_final_marker(state: &mut Stream) {
        if let Some(mut marker) = state.delivered_marker.take() {
            marker.bound = None;
            state.fifo.push_front(marker);
        }
    }
    fn rearm_terminal_gap(state: &mut Stream) {
        if let Some(mut gap) = state.terminal_gap.take() {
            debug_assert!(gap.charge.is_none(), "admitted gap transferred its charge");
            gap.bound = None;
            gap.charge = Some(charge(&state.gate, 14));
            // The original permit stays owned. A delivered final marker was
            // rearmed first, so this warning precedes its new ACK boundary.
            state.fifo.push_front(gap);
        }
    }
    pub(super) fn attach(&mut self, conn: &Connection, generation: u64) {
        self.pending_snapshot = None;
        self.snapshots.discard_before(generation);
        self.snapshot_failed = false;
        self.generation = generation;
        self.target = Some(generation);
        self.hot_target = None;
        self.hot_sent = None;
        self.repaint_request = None;
        self.hot_sequence = 0;
        self.ready.clear();
        self.delivered.clear();
        for (&stream, state) in &mut self.streams {
            let progress = conn.stream_progress(stream);
            let acknowledged = progress.queued.saturating_sub(progress.unacked);
            state.abandoned_data |= state.data_end > acknowledged || state.gap_end > acknowledged;
            state.data_end = 0;
            state.gap_end = 0;
            state.bootstrap = true;
            state.hot_blocked = false;
            Self::rearm_final_marker(state);
            Self::rearm_terminal_gap(state);
            let old = std::mem::take(&mut state.fifo);
            for mut queued in old {
                if matches!(queued.output, Item::Record(ChannelOutput::EchoAck(..))) {
                    continue;
                }
                Self::rebase(&mut queued, generation);
                queued.bound = None;
                Self::append(state, queued);
            }
            // Old sender ownership is abandoned, while pending FIFO charges stay.
            state.gate.update(0);
        }
        self.prepare_snapshot(false);
    }
    fn prepare_snapshot(&mut self, consume_wake: bool) {
        let Some(snapshot) = self.snapshots.take(self.target, consume_wake) else {
            return;
        };
        let ReservedSnapshot {
            snapshot,
            prefix: _,
            source,
            merged,
            wire,
        } = snapshot;
        let (active, old_draining) = snapshot.into_parts();
        for (stream, instance, ended) in active
            .iter()
            .map(|entry| (entry.request.stream, entry.instance, false))
            .chain(
                old_draining
                    .iter()
                    .map(|entry| (entry.stream, entry.instance, true)),
            )
        {
            let Some(state) = self.streams.get_mut(&stream) else {
                self.snapshot_failed = true;
                return;
            };
            if state.instance != instance || (state.ended && !ended) {
                self.snapshot_failed = true;
                return;
            }
            state.ended |= ended;
        }
        // A fixed upper capacity avoids geometric Vec growth beyond the finite
        // identity namespace while adding bridge-owned queued Exit descriptors.
        let mut draining = Vec::with_capacity(crate::channel::CHANNEL_IDENTITIES);
        draining.extend(old_draining);
        for (&stream, state) in &self.streams {
            for queued in &state.fifo {
                let Item::Exit(_, open, _, _) = queued.output else {
                    continue;
                };
                let entry = DrainingChannel {
                    stream,
                    instance: state.instance,
                    open,
                };
                if active.iter().any(|a| a.request.stream == stream) {
                    self.snapshot_failed = true;
                    return;
                }
                if let Some(existing) = draining.iter().find(|d| d.stream == stream) {
                    if *existing != entry {
                        self.snapshot_failed = true;
                        return;
                    }
                } else if active.len() + draining.len() < crate::channel::CHANNEL_IDENTITIES {
                    draining.push(entry);
                } else {
                    self.snapshot_failed = true;
                    return;
                }
            }
        }
        match ChannelSnapshot::new(active, draining) {
            Ok(snapshot) => {
                self.pending_snapshot = Some(PendingSnapshot {
                    snapshot,
                    _merged: merged,
                    _scratch: source,
                    wire: wire.into_owner(),
                })
            }
            Err(_) => self.snapshot_failed = true,
        }
    }
    pub(super) fn receive_fenced(&self) -> bool {
        self.pending_snapshot.is_some()
    }
    fn release_barrier(&mut self, generation: u64) {
        if self.target != Some(generation) {
            return;
        }
        self.target = None;
        for state in self.streams.values_mut() {
            if state.screened && !state.ended {
                state.fifo.retain(|q| q.origin.generation >= generation);
                state.abandoned_data = false;
                state.bootstrap = false;
                state.frontier = None;
                state.waiting_geometry = true;
                state.gap_charge = None;
                state.bootstrap_charge = None;
            }
        }
    }
    pub(super) fn refresh(&mut self, conn: &Connection, parked: bool) {
        for (&stream, state) in &mut self.streams {
            let progress = conn.stream_progress(stream);
            if state.gap_end <= progress.queued.saturating_sub(progress.unacked) {
                state.gap_end = 0;
            }
            // Parked tails are frozen, not artificially opened. Attach removes
            // their charge; pending bytes and metadata holds remain authoritative.
            let opened = state.gate.update(conn.stream_progress(stream).unacked);
            if opened && !parked {
                self.ready.insert(stream, state.instance);
            }
        }
    }
    pub(super) fn notifications(&mut self) -> Vec<SessionInbound> {
        let mut events = Vec::new();
        if let Some(request) = self.repaint_request.take() {
            events.push(request);
        }
        for (stream, instance) in std::mem::take(&mut self.ready) {
            if self.streams.get(&stream).is_some_and(|state| {
                state.instance == instance
                    && state.budget.mark_output_ready(instance, self.generation)
            }) {
                events.push(SessionInbound::OutputReady {
                    stream,
                    instance,
                    generation: self.generation,
                });
            }
        }
        for (stream, (instance, token)) in std::mem::take(&mut self.delivered) {
            if self
                .streams
                .get(&stream)
                .is_some_and(|s| s.instance == instance)
            {
                events.push(SessionInbound::Delivered {
                    stream,
                    token,
                    generation: self.generation,
                });
            }
        }
        events
    }
    pub(super) fn drain(
        &mut self,
        conn: &mut Connection,
        now: Instant,
        parked: bool,
        out: &mut Vec<Datagram>,
        control_delivery: &mut crate::control_budget::ControlLedger,
    ) -> bool {
        synchronize_control_delivery(conn, self.generation, control_delivery);
        self.seal_ended(conn);
        if self.snapshot_failed {
            out.extend(conn.close(now));
            return false;
        }
        if parked || conn.state() != LinkState::Live {
            return false;
        }
        let mut records = 0;
        let mut bytes = 0;
        if let Some(snapshot) = &mut self.pending_snapshot {
            let n = snapshot.payload_len() + 5;
            if !Self::offset_fits(conn, crate::channel::CONTROL_STREAM, n)
                || conn.stream_write_room(
                    crate::channel::CONTROL_STREAM,
                    crate::send_gate::PIPE_HIGH as usize,
                ) < n
            {
                return false;
            }
            // The former source DTO lease now covers encoded scratch, while
            // merged DTO and reliable copy have separate leases. The helper
            // destroys scratch before returning success; a blocked returned
            // Vec is destroyed before this PendingSnapshot can refund it.
            let encoded = snapshot.encode_record();
            let start = conn.stream_progress(crate::channel::CONTROL_STREAM).queued;
            let Ok(datagrams) = conn.try_send_consuming_bounded(
                now,
                crate::channel::CONTROL_STREAM,
                encoded,
                crate::send_gate::PIPE_HIGH as usize,
            ) else {
                return false;
            };
            let part = snapshot
                .wire
                .take_record(n)
                .expect("one bounded snapshot wire record");
            assert!(
                control_delivery
                    .register(
                        self.generation,
                        start,
                        conn.stream_progress(crate::channel::CONTROL_STREAM).queued,
                        part
                    )
                    .is_ok(),
                "whole snapshot enqueue and reservation length diverged"
            );
            out.extend(datagrams);
            self.pending_snapshot = None;
            self.release_barrier(self.generation);
            records = 1;
            bytes = n;
        }
        if self.target.is_some() {
            return false;
        }
        // The map's u8 key bounds the full namespace, including draining
        // streams. Refresh each round after removals without heap scratch.
        let mut keys = [0u8; u8::MAX as usize + 1];
        loop {
            let count = self.streams.len();
            for (index, &stream) in self.streams.keys().enumerate() {
                keys[index] = stream;
            }
            // Freeze the round's order before Step updates self.cursor.
            let cursor = self.cursor;
            let pivot = keys[..count].partition_point(|&stream| stream <= cursor);
            let mut progressed = false;
            for stream in keys[pivot..count].iter().chain(&keys[..pivot]).copied() {
                if records == TURN_RECORDS || bytes == TURN_BYTES {
                    return true;
                }
                let state = self.streams.get_mut(&stream).unwrap();
                if state.hot_blocked {
                    continue;
                }
                match Self::step(
                    state,
                    stream,
                    conn,
                    now,
                    TURN_BYTES - bytes,
                    out,
                    (self.generation, &mut *control_delivery),
                ) {
                    Step::Blocked => {}
                    Step::Sent(n) => {
                        bytes += n;
                        records += 1;
                        progressed = true;
                        self.cursor = stream;
                        self.ready.insert(stream, state.instance);
                    }
                    Step::Delivered(token) => {
                        records += 1;
                        progressed = true;
                        self.cursor = stream;
                        self.delivered.insert(stream, (state.instance, token));
                    }
                    Step::Exited(n) => {
                        bytes += n;
                        records += 1;
                        progressed = true;
                        self.cursor = stream;
                        self.retired.insert(stream, state.instance.get());
                        self.streams.remove(&stream);
                        self.ready.remove(&stream);
                    }
                }
            }
            if !progressed {
                // A record can fit a fresh turn but not this turn's remainder.
                // One extra wake after progress also safely rechecks ACK waits;
                // a wholly blocked turn has bytes == 0 and cannot spin.
                return bytes > 0
                    && self.streams.values().any(|state| {
                        !state.fifo.is_empty() || state.bootstrap || state.abandoned_data
                    });
            }
        }
    }
    fn offset_fits(conn: &mut Connection, stream: u8, bytes: usize) -> bool {
        if conn.stream_offset_room(stream) < bytes as u64 {
            // Same retained-session recovery as the legacy offset exhaustion event.
            // Ownership stays here until Attach or explicit teardown.
            conn.abandon();
            false
        } else {
            true
        }
    }
    fn step(
        state: &mut Stream,
        stream: u8,
        conn: &mut Connection,
        now: Instant,
        remaining: usize,
        out: &mut Vec<Datagram>,
        delivery: (u64, &mut crate::control_budget::ControlLedger),
    ) -> Step {
        let (generation, control_delivery) = delivery;
        conn.declare_channel_output(stream, state.instance);
        if state.bootstrap {
            if matches!(
                state.fifo.front().map(|q| &q.output),
                Some(Item::Record(ChannelOutput::Geometry(..)))
            ) {
                state.bootstrap = false;
                state.bootstrap_charge = None;
            } else if let Some(geometry) = state.frontier {
                if !Self::offset_fits(conn, stream, GEOMETRY_BYTES) {
                    return Step::Blocked;
                }
                if remaining < GEOMETRY_BYTES {
                    return Step::Blocked;
                }
                let encoded = encode_shell(&ShellRecord::Geometry(established(geometry))).unwrap();
                state
                    .bootstrap_charge
                    .get_or_insert_with(|| charge(&state.gate, GEOMETRY_BYTES));
                let Ok(datagrams) = conn.try_send_bounded(
                    now,
                    stream,
                    &encoded,
                    crate::send_gate::PIPE_HIGH as usize,
                ) else {
                    return Step::Blocked;
                };
                out.extend(datagrams);
                state
                    .bootstrap_charge
                    .take()
                    .unwrap()
                    .transfer(conn.stream_progress(stream).unacked);
                state.bootstrap = false;
                return Step::Sent(GEOMETRY_BYTES);
            } else {
                return Step::Blocked;
            }
        }
        // Establish framing/geometry first, then disclose the gap before DATA.
        let front_geometry = matches!(
            state.fifo.front().map(|q| &q.output),
            Some(Item::Record(ChannelOutput::Geometry(..)))
        );
        if state.abandoned_data && !front_geometry {
            if !Self::offset_fits(conn, stream, 14) {
                return Step::Blocked;
            }
            if remaining < 14 {
                return Step::Blocked;
            }
            let bytes = encode_shell(&ShellRecord::OutputGap {
                instance: state.instance,
                cause: OutputGapCause::PreviousConnectionOutputUnconfirmed,
            })
            .unwrap();
            let pending = state
                .gap_charge
                .get_or_insert_with(|| charge(&state.gate, 14));
            match conn.try_send_bounded(now, stream, &bytes, crate::send_gate::PIPE_HIGH as usize) {
                Ok(datagrams) => {
                    out.extend(datagrams);
                    let _ = pending;
                    state
                        .gap_charge
                        .take()
                        .unwrap()
                        .transfer(conn.stream_progress(stream).unacked);
                    state.gap_end = conn.stream_progress(stream).queued;
                    conn.track_channel_continuity_end(stream, state.instance, state.gap_end);
                    state.abandoned_data = false;
                    return Step::Sent(14);
                }
                Err(_) => return Step::Blocked,
            }
        }
        let Some(front) = state.fifo.front_mut() else {
            return Step::Blocked;
        };
        if let Item::Record(ChannelOutput::DeliveryMarker(marker, _)) = &front.output {
            let progress = conn.stream_progress(stream);
            let bound = *front.bound.get_or_insert(progress.queued);
            if progress.queued.saturating_sub(progress.unacked) < bound {
                return Step::Blocked;
            }
            let token = marker.token;
            debug_assert!(
                state.delivered_marker.is_none(),
                "one final marker per instance"
            );
            state.delivered_marker = state.fifo.pop_front();
            return Step::Delivered(token);
        }
        let target = if matches!(front.output, Item::Exit(..)) {
            crate::channel::CONTROL_STREAM
        } else {
            stream
        };
        let minimum = match &front.output {
            Item::Record(ChannelOutput::Data(data)) => {
                if state.screened {
                    5 + usize::from(front.offset < data.len())
                } else {
                    5 + data.len()
                }
            }
            Item::Record(ChannelOutput::Geometry(..)) => 27,
            Item::Record(ChannelOutput::EchoAck(..)) => 13,
            Item::Record(ChannelOutput::OutputGap(..)) => 14,
            Item::Exit(..) => 10,
            Item::Record(ChannelOutput::DeliveryMarker(..)) => unreachable!(),
        };
        if !Self::offset_fits(conn, target, minimum) {
            return Step::Blocked;
        }
        let room = conn
            .stream_write_room(target, crate::send_gate::PIPE_HIGH as usize)
            .min(remaining);
        let encoded = match &front.output {
            Item::Record(ChannelOutput::Data(data)) => {
                if room <= 5 {
                    return Step::Blocked;
                }
                let available = data.len() - front.offset;
                let n = if state.screened {
                    available.min(room - 5)
                } else {
                    // Reader chunks (at most 8192 bytes) retain one ownership
                    // boundary through credit pressure, turn limits and Attach.
                    debug_assert_eq!(front.offset, 0);
                    if room < available + 5 {
                        return Step::Blocked;
                    }
                    available
                };
                crate::shell_frame::encode_record(
                    crate::shell_frame::REC_DATA,
                    &data[front.offset..front.offset + n],
                )
            }
            Item::Record(ChannelOutput::Geometry(g, _)) => {
                if room < 27 {
                    return Step::Blocked;
                }
                encode_shell(&ShellRecord::Geometry(*g)).unwrap()
            }
            Item::Record(ChannelOutput::EchoAck(n, _)) => {
                if room < 13 {
                    return Step::Blocked;
                }
                encode_shell(&ShellRecord::EchoAck(*n)).unwrap()
            }
            Item::Record(ChannelOutput::OutputGap(cause, _)) => {
                if room < 14 {
                    return Step::Blocked;
                }
                encode_shell(&ShellRecord::OutputGap {
                    instance: state.instance,
                    cause: *cause,
                })
                .unwrap()
            }
            Item::Exit(code, _, _, _) => {
                if room < 10 || conn.stream_progress(stream).unacked != 0 {
                    return Step::Blocked;
                }
                let record = match code {
                    Some(code) => crate::channel::ServerRecord::Exit {
                        stream,
                        code: *code,
                    },
                    None => crate::channel::ServerRecord::ExitStatusUnavailable { stream },
                };
                crate::channel::encode_server(&record)
            }
            Item::Record(ChannelOutput::DeliveryMarker(..)) => unreachable!(),
        };
        let n = encoded.len();
        let start = conn.stream_progress(target).queued;
        let sent = if matches!(front.output, Item::Exit(..)) {
            // Independent timeline custody covers the encoded terminal scratch;
            // its control delivery lease covers the simultaneous reliable copy.
            conn.try_send_consuming_bounded(
                now,
                target,
                encoded,
                crate::send_gate::PIPE_HIGH as usize,
            )
            .map_err(|(reason, _)| reason)
        } else {
            conn.try_send_bounded(now, target, &encoded, crate::send_gate::PIPE_HIGH as usize)
        };
        let Ok(datagrams) = sent else {
            return Step::Blocked;
        };
        if let Item::Exit(_, _, _, control) = &mut front.output {
            let delivery = control.take().expect("one terminal control delivery");
            let end = conn.stream_progress(target).queued;
            if let Some(charge) = delivery.charge {
                charge.transfer(conn.stream_progress(target).unacked);
            }
            assert!(
                control_delivery
                    .register(generation, start, end, delivery.part)
                    .is_ok(),
                "whole terminal control enqueue and reserved length diverged"
            );
        }
        out.extend(datagrams);
        let tail = conn.stream_progress(stream).unacked;
        match &front.output {
            Item::Record(ChannelOutput::Geometry(g, _)) => state.frontier = Some(*g),
            Item::Record(ChannelOutput::Data(data)) => {
                state.data_end = conn.stream_progress(stream).queued;
                conn.track_channel_continuity_end(stream, state.instance, state.data_end);
                front.offset += n - 5;
                if front.offset < data.len() {
                    let charge = front.charge.as_mut().unwrap();
                    charge.gate.transfer(n as u64, tail);
                    charge.bytes -= n as u64;
                    // The next independently framed slice owns one extra header.
                    charge.gate.admit(5);
                    charge.bytes += 5;
                    return Step::Sent(n);
                }
            }
            Item::Record(ChannelOutput::OutputGap(..)) => {
                conn.track_channel_continuity_end(
                    stream,
                    state.instance,
                    conn.stream_progress(stream).queued,
                );
            }
            Item::Exit(_, _, permit, _) => {
                let _ = permit;
            }
            _ => {}
        }
        let exited = matches!(front.output, Item::Exit(..));
        let terminal_gap = matches!(front.output, Item::Record(ChannelOutput::OutputGap(..)));
        let mut retired = state.fifo.pop_front().unwrap();
        if let Some(charge) = retired.charge.take() {
            charge.transfer(tail);
        }
        if terminal_gap {
            retired.bound = Some(conn.stream_progress(stream).queued);
            state.terminal_gap = Some(retired);
        }
        if exited {
            Step::Exited(n)
        } else {
            Step::Sent(n)
        }
    }
}
enum Step {
    Blocked,
    Sent(usize),
    Delivered(u64),
    Exited(usize),
}

#[cfg(test)]
#[path = "channel_bridge_tests.rs"]
mod tests;
