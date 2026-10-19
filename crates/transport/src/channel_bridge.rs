//! Owned channel output between the runner and bounded Connection admission.
use super::*;
use crate::channel::{ChannelCodecError, ChannelSnapshot, DrainingChannel};
use crate::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord, OutputGapCause};
use crate::channel_timeline::{TimelineBudget, TimelinePermit, GEOMETRY_BYTES};
use crate::shell_frame::{encode_shell, ShellRecord};

const TURN_RECORDS: usize = 32;
const TURN_BYTES: usize = 64 * 1024;

#[derive(Default)]
struct SnapshotSlot {
    generation: Option<u64>,
    value: Option<ChannelSnapshot>,
}
#[derive(Clone, Default)]
pub(super) struct SnapshotMailbox(Arc<Mutex<SnapshotSlot>>);
impl SnapshotMailbox {
    pub(super) fn publish(
        &self,
        generation: u64,
        build: impl FnOnce() -> Result<ChannelSnapshot, ChannelCodecError>,
    ) -> Result<bool, ChannelCodecError> {
        let mut slot = self.0.lock().expect("resume snapshot");
        if slot.generation.is_some_and(|old| old >= generation) {
            return Ok(false);
        }
        // Release the old command storage before constructing a replacement.
        // Together with the bridge admission slot, at most two snapshots live.
        slot.value = None;
        slot.generation = Some(generation);
        slot.value = Some(build()?);
        Ok(true)
    }
    pub(super) fn take(&self, generation: u64) -> Option<ChannelSnapshot> {
        let mut slot = self.0.lock().expect("resume snapshot");
        (slot.generation == Some(generation))
            .then(|| slot.value.take())
            .flatten()
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
    pending_snapshot: Option<ChannelSnapshot>,
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
        match message {
            SessionOutbound::ChannelOutput {
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
                stream,
                instance,
                origin,
                code,
                open,
                permit,
            } => {
                if let Some(state) = self
                    .streams
                    .get_mut(&stream)
                    .filter(|s| s.instance == instance)
                {
                    state.ended = true;
                    state.fifo.push_back(Queued {
                        origin,
                        output: Item::Exit(code, open, permit),
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
            SessionOutbound::ResumeBarrier { generation } => self.prepare_snapshot(generation),
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
    }
    fn prepare_snapshot(&mut self, generation: u64) {
        if self.target != Some(generation) {
            return;
        }
        let Some(snapshot) = self.snapshots.take(generation) else {
            self.snapshot_failed = true;
            return;
        };
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
                let Item::Exit(_, open, _) = queued.output else {
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
            Ok(snapshot) => self.pending_snapshot = Some(snapshot),
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
    ) -> bool {
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
        if let Some(snapshot) = &self.pending_snapshot {
            let n = snapshot.payload_len() + 5;
            if !Self::offset_fits(conn, crate::channel::CONTROL_STREAM, n)
                || conn.stream_write_room(
                    crate::channel::CONTROL_STREAM,
                    crate::send_gate::PIPE_HIGH as usize,
                ) < n
            {
                return false;
            }
            let encoded = snapshot.encode_record();
            let Ok(datagrams) = conn.try_send_bounded(
                now,
                crate::channel::CONTROL_STREAM,
                &encoded,
                crate::send_gate::PIPE_HIGH as usize,
            ) else {
                return false;
            };
            out.extend(datagrams);
            self.pending_snapshot = None;
            self.release_barrier(self.generation);
            records = 1;
            bytes = n;
        }
        if self.target.is_some() {
            return false;
        }
        loop {
            let keys: Vec<_> = self.streams.keys().copied().collect();
            let mut progressed = false;
            for stream in keys
                .iter()
                .copied()
                .filter(|s| *s > self.cursor)
                .chain(keys.iter().copied().filter(|s| *s <= self.cursor))
                .collect::<Vec<_>>()
            {
                if records == TURN_RECORDS || bytes == TURN_BYTES {
                    return true;
                }
                let state = self.streams.get_mut(&stream).unwrap();
                if state.hot_blocked {
                    continue;
                }
                match Self::step(state, stream, conn, now, TURN_BYTES - bytes, out) {
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
    ) -> Step {
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
            Item::Exit(code, _, _) => {
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
        let Ok(datagrams) =
            conn.try_send_bounded(now, target, &encoded, crate::send_gate::PIPE_HIGH as usize)
        else {
            return Step::Blocked;
        };
        out.extend(datagrams);
        let n = encoded.len();
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
            Item::Exit(_, _, permit) => {
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
mod tests {
    use super::*;
    use crate::channel_timeline::{EntryClass, BRIDGE_LIFECYCLE_BYTES};
    use crate::shell_frame::ShellDeframer;
    const STREAM: u8 = 16;
    struct Rig {
        bridge: ChannelBridge,
        server: Connection,
        client: Connection,
        now: Instant,
        peer: SocketAddr,
        generation: u64,
        io: SessionIo,
        outbound: mpsc::UnboundedReceiver<SessionOutbound>,
        gate: Arc<SendGate>,
        budget: TimelineBudget,
        frames: ShellDeframer,
        records: Vec<ShellRecord>,
        control_frames: crate::shell_frame::RecordDeframer,
        control_records: Vec<crate::channel::ServerRecord>,
        other_frames: BTreeMap<u8, ShellDeframer>,
        other_records: BTreeMap<u8, Vec<ShellRecord>>,
    }
    impl Rig {
        fn new() -> Self {
            let peer = "192.0.2.1:41000".parse().unwrap();
            let (client, server) = Self::pair(peer);
            let (io, _, outbound) = SessionIo::test_pair();
            let gate = io.send_gate(STREAM, crate::send_gate::GateKind::Pipe);
            Self {
                bridge: ChannelBridge::default(),
                server,
                client,
                now: Instant::now(),
                peer,
                generation: 0,
                io,
                outbound,
                gate,
                budget: TimelineBudget::new(ChannelInstance::new(1).unwrap(), 0, |_| {}),
                frames: ShellDeframer::new(),
                records: Vec::new(),
                control_frames: crate::shell_frame::RecordDeframer::for_control(),
                control_records: Vec::new(),
                other_frames: BTreeMap::new(),
                other_records: BTreeMap::new(),
            }
        }
        fn pair(peer: SocketAddr) -> (Connection, Connection) {
            let kp = crate::handshake::generate_keypair();
            let (mut client, server, out) = super::super::tests::accepted_connection_with(
                &kp,
                [1; 16],
                peer,
                crate::Features::SUPPORTED | crate::Features::CHANNEL_GEOMETRY,
            );
            for dg in out {
                client.on_datagram(Instant::now(), peer, &dg.bytes);
            }
            (client, server)
        }
        fn origin(&self) -> AttachmentContext {
            AttachmentContext {
                generation: self.generation,
                session_id: self.server.session_id(),
                features: crate::Features::CHANNEL_GEOMETRY,
            }
        }
        fn emit(&mut self, output: ChannelOutput, gap: Option<TimelinePermit>) {
            self.io.send_channel_output(
                STREAM,
                ChannelInstance::new(1).unwrap(),
                self.origin(),
                self.gate.clone(),
                output,
                gap,
            );
            while let Ok(message) = self.outbound.try_recv() {
                self.bridge.push(message);
            }
        }
        fn geometry(&mut self, cols: u16, request_id: u64) {
            let gap = if request_id == 0 && self.generation == 0 {
                self.budget
                    .try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES)
            } else {
                None
            };
            let permit = self.budget.try_reserve(EntryClass::Ordinary, 27).unwrap();
            self.emit(
                ChannelOutput::Geometry(
                    GeometryRecord {
                        instance: ChannelInstance::new(1).unwrap(),
                        request_id,
                        outcome: if request_id == 0 {
                            GeometryOutcome::Established
                        } else {
                            GeometryOutcome::Applied
                        },
                        cols,
                        rows: 24,
                    },
                    permit,
                ),
                gap,
            );
        }
        fn data(&mut self, bytes: &[u8]) {
            self.emit(ChannelOutput::Data(bytes.to_vec()), None);
        }
        fn attach(&mut self) {
            self.generation += 1;
            self.bridge.attach(&self.server, self.generation);
            (self.client, self.server) = Self::pair(self.peer);
            self.frames = ShellDeframer::new();
            self.records.clear();
            self.control_frames = crate::shell_frame::RecordDeframer::for_control();
            self.control_records.clear();
            self.other_frames.clear();
            self.other_records.clear();
            self.budget
                .reset_attachment(ChannelInstance::new(1).unwrap(), self.generation);
        }
        fn drain(&mut self, parked: bool) -> bool {
            let mut out = Vec::new();
            let again = self
                .bridge
                .drain(&mut self.server, self.now, parked, &mut out);
            self.pump(out);
            again
        }
        fn pump(&mut self, mut out: Vec<Datagram>) {
            for _ in 0..100 {
                for dg in std::mem::take(&mut out) {
                    for ack in self.client.on_datagram(self.now, self.peer, &dg.bytes) {
                        out.extend(self.server.on_datagram(self.now, self.peer, &ack.bytes));
                    }
                }
                for ev in self.client.poll_events() {
                    if let Event::StreamData { stream_id, data } = ev {
                        if stream_id == STREAM {
                            self.records.extend(self.frames.push(&data));
                        } else if stream_id == crate::channel::CONTROL_STREAM {
                            self.control_records.extend(
                                self.control_frames.push(&data).iter().filter_map(|raw| {
                                    match crate::channel::decode_server(raw) {
                                        Ok(record) => Some(record),
                                        Err(crate::channel::ChannelCodecError::UnknownKind(_)) => {
                                            None
                                        }
                                        Err(error) => panic!("malformed test control: {error:?}"),
                                    }
                                }),
                            );
                        } else {
                            self.other_records.entry(stream_id).or_default().extend(
                                self.other_frames.entry(stream_id).or_default().push(&data),
                            );
                        }
                    }
                }
                self.now += std::time::Duration::from_millis(20);
                let acks = self.client.on_timeout(self.now);
                for ack in acks {
                    out.extend(self.server.on_datagram(self.now, self.peer, &ack.bytes));
                }
                out.extend(self.server.on_timeout(self.now));
                if out.is_empty() && self.server.stream_progress(STREAM).unacked == 0 {
                    break;
                }
            }
        }
    }
    // Decode lifecycle metadata on a new Connection, without carrying any
    // previous client's OPEN state across the attachment.
    async fn fresh_attach_after_retained_runner_output(
        ended_count: u8,
        queue_exit: bool,
        eof_held: bool,
    ) -> Vec<crate::channel::ServerRecord> {
        use crate::channel::{
            encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord, CONTROL_STREAM,
        };
        let ended = ended_count != 0;
        let count = ended_count.max(1);
        let mut rig = Rig::new();
        rig.client.set_default_consumption(Consumption::Explicit);
        let occupied = crate::shell_frame::encode_record(
            crate::shell_frame::REC_DATA,
            &vec![0; crate::reliability::STREAM_WINDOW as usize - 5],
        );
        let datagrams = rig.server.send(rig.now, STREAM, &occupied);
        rig.pump(datagrams);
        assert_eq!(
            rig.server
                .stream_write_room(STREAM, crate::send_gate::PIPE_HIGH as usize),
            0
        );
        let spawner = crate::channel_server::tests::FakeSpawner::new();
        let (io, inbound, mut outbound) = SessionIo::test_pair();
        rig.bridge.snapshots = io.resume_snapshots.clone();
        let runner = tokio::spawn(crate::channel_server::run_channel_session(
            io,
            spawner.clone(),
        ));
        let observed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            inbound
                .send(SessionInbound::Live(rig.origin()))
                .await
                .unwrap();
            let mut held = Vec::new();
            for stream in STREAM..STREAM + count {
                inbound
                    .send(SessionInbound::Data(StreamData {
                        stream_id: CONTROL_STREAM,
                        data: encode_client(&ClientRecord::Open(OpenRequest {
                            stream,
                            kind: ChannelKind::Command,
                            cols: if eof_held { 80 } else { 0 },
                            rows: 24,
                            screen: eof_held,
                            command: b"fixture-command".to_vec(),
                        })),
                    }))
                    .await
                    .unwrap();
                loop {
                    let message = outbound.recv().await.unwrap();
                    let saw_data = matches!(&message, SessionOutbound::ChannelOutput {
                    output: ChannelOutput::Data(bytes), ..
                } if bytes == b"hello from the shell");
                    if matches!(message, SessionOutbound::ChannelOutput { .. }) {
                        rig.bridge.push(message);
                    }
                    if saw_data {
                        break;
                    }
                }
                if ended {
                    if eof_held {
                        let state = &rig.bridge.streams[&stream];
                        while let Some(permit) = state.budget.try_reserve(EntryClass::Ordinary, 27)
                        {
                            held.push(permit);
                        }
                        assert!(state.gate.is_open());
                        rig.bridge.declare(stream, true);
                    }
                    spawner.end_channel(stream);
                    if eof_held {
                        while rig.bridge.streams[&stream].gate.is_open() {
                            tokio::task::yield_now().await;
                        }
                        // EOF's final checkpoint cannot reserve an ordinary slot,
                        // so the real runner still owns Channel, not PendingExit.
                        assert_eq!(
                            rig.bridge.streams[&stream]
                                .budget
                                .usage(EntryClass::Ordinary)
                                .0,
                            128
                        );
                        continue;
                    }
                    loop {
                        let message = outbound.recv().await.unwrap();
                        let saw_marker = matches!(
                            message,
                            SessionOutbound::ChannelOutput {
                                output: ChannelOutput::DeliveryMarker(..),
                                ..
                            }
                        );
                        if matches!(message, SessionOutbound::ChannelOutput { .. }) {
                            rig.bridge.push(message);
                        }
                        if saw_marker {
                            break;
                        }
                    }
                }
            }
            assert!(
                !rig.drain(count > 1),
                "old output stays credit-blocked or parked"
            );
            let retained = &rig.bridge.streams[&STREAM];
            assert_eq!(retained.ended, ended && !eof_held);
            assert!(retained.fifo.iter().any(|q| matches!(
                &q.output, Item::Record(ChannelOutput::Data(bytes))
                if bytes == b"hello from the shell" && q.charge.as_ref().unwrap().bytes > 0
            )));
            if queue_exit {
                assert_eq!(ended_count, 1);
                let credit = rig.client.on_consumed(
                    rig.now,
                    STREAM,
                    crate::reliability::STREAM_WINDOW as usize,
                );
                let mut out = Vec::new();
                for dg in credit {
                    out.extend(rig.server.on_datagram(rig.now, rig.peer, &dg.bytes));
                }
                rig.pump(out);
                rig.drain(false);
                rig.drain(false);
                let delivered = rig
                    .bridge
                    .notifications()
                    .into_iter()
                    .find(|event| matches!(event, SessionInbound::Delivered { stream: STREAM, .. }))
                    .expect("the final prefix is acknowledged before the runner transfers Exit");
                let fill = crate::shell_frame::encode_record(
                    0x7f,
                    &vec![0; crate::reliability::STREAM_WINDOW as usize - 5],
                );
                let out = rig.server.send(rig.now, CONTROL_STREAM, &fill);
                rig.pump(out);
                inbound.send(delivered).await.unwrap();
                loop {
                    let message = outbound.recv().await.unwrap();
                    if matches!(message, SessionOutbound::ChannelExit { .. }) {
                        rig.bridge.push(message);
                        break;
                    }
                }
                let held = rig.bridge.streams[&STREAM]
                    .budget
                    .usage(EntryClass::Lifecycle);
                assert!(!rig.drain(false));
                assert_eq!(
                    rig.bridge.streams[&STREAM]
                        .budget
                        .usage(EntryClass::Lifecycle),
                    held
                );
                assert!(matches!(
                    rig.bridge.streams[&STREAM].fifo.front().unwrap().output,
                    Item::Exit(Some(0), _, _)
                ));
            }
            rig.attach();
            inbound
                .send(SessionInbound::ResumeReset(rig.origin()))
                .await
                .unwrap();
            loop {
                match outbound.recv().await.unwrap() {
                    message @ (SessionOutbound::ChannelOutput { .. }
                    | SessionOutbound::ResumeBarrier { .. }) => rig.bridge.push(message),
                    SessionOutbound::Data(data) if data.stream_id == CONTROL_STREAM => {
                        let datagrams = rig.server.send(rig.now, CONTROL_STREAM, &data.data);
                        rig.pump(datagrams);
                    }
                    _ => {}
                }
                rig.drain(false);
                if rig
                    .control_records
                    .iter()
                    .any(|r| matches!(r, ServerRecord::ChannelSnapshot(_)))
                {
                    break;
                }
            }
            rig.drain(false);
            assert!(matches!(rig.records.first(), Some(ShellRecord::Geometry(g))
                if g.cols == if eof_held { 80 } else { 0 } && g.rows == 24));
            if !queue_exit {
                assert!(rig.records.iter().any(
                    |r| matches!(r, ShellRecord::Data(bytes) if bytes == b"hello from the shell")
                ));
                for stream in STREAM + 1..STREAM + count {
                    assert!(rig.other_records[&stream].iter().any(|r|
                        matches!(r, ShellRecord::Data(bytes) if bytes == b"hello from the shell")
                    ));
                }
            } else {
                assert!(rig.control_records.iter().any(|r| matches!(
                    r,
                    ServerRecord::Exit {
                        stream: STREAM,
                        code: 0
                    }
                )));
            }
            if eof_held {
                assert!(rig.bridge.streams[&STREAM].ended);
                assert!(!held.is_empty());
            }
            rig.control_records.clone()
        })
        .await;
        // Cleanup precedes the intentional RED assertion in the calling test.
        drop(inbound);
        spawner.end_channel(STREAM);
        runner.await.unwrap();
        observed.expect("runner and fresh connection reached the resume snapshot")
    }

    #[tokio::test]
    async fn fresh_attach_active_output_has_open_classification() {
        let records = fresh_attach_after_retained_runner_output(0, false, false).await;
        assert!(records.iter().any(|r| matches!(r,
            crate::channel::ServerRecord::ChannelSnapshot(snapshot) if snapshot.draining().is_empty() && snapshot.active().iter().any(|entry| { let req = &entry.request;
                req.stream == STREAM && req.cols == 0 && req.rows == 24
                && req.kind == crate::channel::ChannelKind::Command
                && req.command == b"fixture-command"
            })
        )));
    }

    #[tokio::test]
    async fn fresh_attach_retained_final_output_requires_open_classification() {
        let records = fresh_attach_after_retained_runner_output(1, false, false).await;
        let classification = records.iter().find_map(|r| match r {
            crate::channel::ServerRecord::ChannelSnapshot(snapshot) => {
                assert!(snapshot.active().is_empty(), "ended process is not active");
                snapshot
                    .draining()
                    .iter()
                    .find(|entry| entry.stream == STREAM)
            }
            _ => None,
        });
        assert!(
            classification.is_some(),
            "fresh attachment received retained final GEOMETRY/DATA but no lifecycle OPEN classification: {records:?}"
        );
        let entry = classification.unwrap();
        assert_eq!(entry.instance, ChannelInstance::new(1).unwrap());
        assert_eq!(entry.open.kind, crate::channel::ChannelKind::Command);
        assert_eq!((entry.open.cols, entry.open.rows), (0, 24));
    }

    #[tokio::test]
    async fn fresh_attach_eof_before_pending_exit_is_draining_while_checkpoint_blocked() {
        let records = fresh_attach_after_retained_runner_output(1, false, true).await;
        assert!(records.iter().any(|record| matches!(record,
            crate::channel::ServerRecord::ChannelSnapshot(snapshot)
                if snapshot.active().is_empty() && snapshot.draining().len() == 1
                    && snapshot.draining()[0].open.cols == 80
                    && snapshot.draining()[0].open.rows == 24
                    && snapshot.draining()[0].open.screen
        )));
    }

    #[test]
    fn resume_snapshot_mailbox_has_one_latest_exact_generation() {
        let mailbox = SnapshotMailbox::default();
        for generation in 1..=300 {
            assert!(mailbox
                .publish(generation, || ChannelSnapshot::new(Vec::new(), Vec::new()))
                .unwrap());
            assert!(mailbox.take(generation - 1).is_none());
            assert!(mailbox.0.lock().unwrap().value.is_some());
        }
        assert!(!mailbox
            .publish(299, || panic!("obsolete builder must not allocate"))
            .unwrap());
        assert!(mailbox.take(300).is_some());
        assert!(mailbox.take(300).is_none());
        assert!(!mailbox
            .publish(300, || panic!("same generation is consumed once"))
            .unwrap());
    }

    #[tokio::test]
    async fn fresh_attach_nine_ended_channels_are_not_limited_to_eight_live_slots() {
        let records = fresh_attach_after_retained_runner_output(9, false, false).await;
        let snapshot = records
            .iter()
            .find_map(|r| match r {
                crate::channel::ServerRecord::ChannelSnapshot(snapshot) => Some(snapshot),
                _ => None,
            })
            .unwrap();
        assert!(snapshot.active().is_empty());
        assert_eq!(
            snapshot
                .draining()
                .iter()
                .map(|e| e.stream)
                .collect::<Vec<_>>(),
            (16..25).collect::<Vec<_>>()
        );
        assert!(snapshot
            .draining()
            .iter()
            .all(|e| e.open.cols == 0 && e.open.rows == 24));
    }

    #[tokio::test]
    async fn fresh_attach_runner_transferred_exit_keeps_classification_in_bridge() {
        let records = fresh_attach_after_retained_runner_output(1, true, false).await;
        assert!(
            matches!(records.first(), Some(crate::channel::ServerRecord::ChannelSnapshot(snapshot))
            if snapshot.active().is_empty() && snapshot.draining().len() == 1)
        );
        assert_eq!(
            records
                .iter()
                .filter(|r| matches!(
                    r,
                    crate::channel::ServerRecord::Exit {
                        stream: STREAM,
                        code: 0
                    }
                ))
                .count(),
            1
        );
    }

    fn queued_terminal_snapshot_survives_control_block_and_second_attach(code: Option<i32>) {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.drain(false);
        let open = crate::channel::OpenClassification {
            kind: crate::channel::ChannelKind::Command,
            cols: 80,
            rows: 24,
            screen: false,
        };
        let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 10).unwrap();
        rig.bridge.push(SessionOutbound::ChannelExit {
            stream: STREAM,
            instance: ChannelInstance::new(1).unwrap(),
            origin: rig.origin(),
            code,
            open,
            permit,
        });
        for generation in 1..=2 {
            rig.attach();
            rig.client.set_default_consumption(Consumption::Explicit);
            let occupied = crate::shell_frame::encode_record(
                0x7f,
                &vec![0; crate::reliability::STREAM_WINDOW as usize - 5],
            );
            let datagrams = rig
                .server
                .send(rig.now, crate::channel::CONTROL_STREAM, &occupied);
            // Rig's pump parses control bytes; reset the framing after all fill
            // bytes have arrived, before observing actual snapshot records.
            rig.pump(datagrams);
            assert!(rig.client.unconsumed_streams().contains(&(
                crate::channel::CONTROL_STREAM,
                crate::reliability::STREAM_WINDOW
            )));
            rig.control_frames = crate::shell_frame::RecordDeframer::for_control();
            rig.control_records.clear();
            rig.bridge
                .snapshots
                .publish(generation, || ChannelSnapshot::new(Vec::new(), Vec::new()))
                .unwrap();
            rig.bridge
                .push(SessionOutbound::ResumeBarrier { generation });
            assert!(rig.bridge.receive_fenced());
            let held = rig.budget.usage(EntryClass::Lifecycle);
            assert!(!rig.drain(false));
            assert_eq!(rig.budget.usage(EntryClass::Lifecycle), held);
            assert!(rig.bridge.receive_fenced());
            assert_eq!(
                rig.bridge.pending_snapshot.as_ref().unwrap().draining(),
                &[DrainingChannel {
                    stream: STREAM,
                    instance: ChannelInstance::new(1).unwrap(),
                    open,
                }]
            );
        }
        let credit = rig.client.on_consumed(
            rig.now,
            crate::channel::CONTROL_STREAM,
            crate::reliability::STREAM_WINDOW as usize,
        );
        let mut out = Vec::new();
        for dg in credit {
            out.extend(rig.server.on_datagram(rig.now, rig.peer, &dg.bytes));
        }
        rig.pump(out);
        rig.drain(false);
        rig.drain(false);
        assert!(!rig.bridge.receive_fenced());
        assert!(matches!(
            rig.control_records.first(),
            Some(crate::channel::ServerRecord::ChannelSnapshot(_))
        ));
        let expected = match code {
            Some(code) => crate::channel::ServerRecord::Exit {
                stream: STREAM,
                code,
            },
            None => crate::channel::ServerRecord::ExitStatusUnavailable { stream: STREAM },
        };
        assert_eq!(
            rig.control_records
                .iter()
                .filter(|r| **r == expected)
                .count(),
            1
        );
        assert!(rig.bridge.streams.is_empty());
    }

    #[test]
    fn queued_exit_snapshot_survives_control_block_and_second_attach() {
        queued_terminal_snapshot_survives_control_block_and_second_attach(Some(42));
    }

    #[test]
    fn unavailable_exit_snapshot_survives_control_block_and_second_attach() {
        queued_terminal_snapshot_survives_control_block_and_second_attach(None);
    }

    #[test]
    fn pending_noscreen_output_survives_two_attaches() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.data(b"retained");
        rig.attach();
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.drain(false);
        assert!(
            rig.records.is_empty(),
            "obsolete barrier must not release prefix"
        );
        rig.bridge.release_barrier(2);
        rig.drain(false);
        assert_eq!(rig.records.len(), 2);
        assert!(
            matches!(&rig.records[0],ShellRecord::Geometry(g) if g.cols==80 && g.request_id==0)
        );
        assert_eq!(rig.records[1], ShellRecord::Data(b"retained".to_vec()));
    }
    #[test]
    fn noscreen_geometry_timeline_survives_cutover() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.data(b"A");
        rig.geometry(100, 1);
        rig.data(b"B");
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.geometry(100, 0);
        rig.drain(false);
        assert_eq!(rig.records.len(), 5);
        assert!(
            matches!(&rig.records[2],ShellRecord::Geometry(g) if g.cols==100 && g.request_id==0)
        );
        assert_eq!(rig.records[1], ShellRecord::Data(b"A".to_vec()));
        assert_eq!(rig.records[3], ShellRecord::Data(b"B".to_vec()));
    }
    #[test]
    fn parked_pipe_keeps_pending_charge() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        for _ in 0..(crate::send_gate::PIPE_HIGH / 8192) {
            rig.data(&[7; 8192]);
        }
        rig.drain(true);
        assert!(!rig.gate.is_open());
        assert_eq!(rig.budget.usage(EntryClass::Ordinary), (1, 27));
        assert_eq!(rig.server.stream_progress(STREAM).queued, 0);
    }
    #[test]
    fn full_screen_and_noscreen_fifos_drain_while_producer_gated() {
        for screened in [false, true] {
            let mut rig = Rig::new();
            rig.bridge.declare(STREAM, screened);
            rig.geometry(80, 0);
            if screened {
                rig.data(&vec![7; crate::send_gate::PIPE_HIGH as usize]);
            } else {
                for _ in 0..(crate::send_gate::PIPE_HIGH / 8192) {
                    rig.data(&[7; 8192]);
                }
            }
            assert!(!rig.gate.is_open());
            let mut turns = 0;
            while rig.drain(false) {
                turns += 1;
                assert!(turns < 100);
            }
            assert!(turns > 0, "bounded turn must schedule continuation");
            assert_eq!(
                rig.records
                    .iter()
                    .filter_map(|r| if let ShellRecord::Data(b) = r {
                        Some(b.len())
                    } else {
                        None
                    })
                    .sum::<usize>(),
                crate::send_gate::PIPE_HIGH as usize
            );
            if !screened {
                assert!(rig
                    .records
                    .iter()
                    .filter_map(|r| match r {
                        ShellRecord::Data(bytes) => Some(bytes.len()),
                        _ => None,
                    })
                    .all(|n| n == 8192));
            }
        }
    }
    #[test]
    fn metadata_only_tail_does_not_report_gap() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        let mut out = Vec::new();
        rig.bridge.drain(&mut rig.server, rig.now, false, &mut out);
        assert_eq!(rig.server.stream_progress(STREAM).queued, 27);
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.geometry(80, 0);
        rig.drain(false);
        assert!(!rig
            .records
            .iter()
            .any(|r| matches!(r, ShellRecord::OutputGap { .. })));
        assert!(!rig.records.is_empty());
    }
    #[test]
    fn gap_then_retained_prefix_then_exit() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.data(b"abandoned");
        let mut out = Vec::new();
        rig.bridge.drain(&mut rig.server, rig.now, false, &mut out);
        rig.data(b"prefix");
        let marker = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
        rig.emit(
            ChannelOutput::DeliveryMarker(DeliveryMarker { token: 1 }, marker),
            None,
        );
        let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 10).unwrap();
        rig.bridge.push(SessionOutbound::ChannelExit {
            stream: STREAM,
            instance: ChannelInstance::new(1).unwrap(),
            origin: rig.origin(),
            code: Some(0),
            open: crate::channel::OpenClassification {
                kind: crate::channel::ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
            },
            permit,
        });
        rig.attach();
        rig.attach();
        rig.bridge.release_barrier(2);
        rig.drain(false);
        assert!(matches!(&rig.records[0],ShellRecord::Geometry(g) if g.request_id==0));
        assert!(matches!(&rig.records[1], ShellRecord::OutputGap { .. }));
        assert_eq!(rig.records[2], ShellRecord::Data(b"prefix".to_vec()));
        assert_eq!(
            rig.server
                .stream_progress(crate::channel::CONTROL_STREAM)
                .queued,
            0,
            "Exit waits for prefix delivery"
        );
        rig.drain(false);
        assert_eq!(
            rig.server
                .stream_progress(crate::channel::CONTROL_STREAM)
                .queued,
            10
        );
    }
    #[test]
    fn idle_pipe_progress_emits_output_ready_once_until_consumed() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.data(b"idle");
        rig.drain(false);
        let events = rig.bridge.notifications();
        assert_eq!(
            events
                .iter()
                .filter(|e| matches!(e, SessionInbound::OutputReady { .. }))
                .count(),
            1
        );
        rig.data(b"next");
        rig.drain(false);
        assert!(
            rig.bridge.notifications().is_empty(),
            "a pending notification coalesces all progress"
        );
        assert!(rig
            .budget
            .take_notification(ChannelInstance::new(1).unwrap(), 0));
        rig.data(b"last");
        rig.drain(false);
        assert_eq!(rig.bridge.notifications().len(), 1);
    }
    #[test]
    fn ended_screen_snapshot_survives_attach_without_new_producer_output() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.data(b"final snapshot");
        let marker = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
        rig.emit(
            ChannelOutput::DeliveryMarker(DeliveryMarker { token: 1 }, marker),
            None,
        );
        rig.attach();
        rig.attach();
        rig.bridge.release_barrier(2);
        rig.drain(false);
        assert_eq!(
            rig.records[1],
            ShellRecord::Data(b"final snapshot".to_vec())
        );
        assert!(!rig
            .bridge
            .notifications()
            .iter()
            .any(|e| matches!(e, SessionInbound::Delivered { .. })));
        rig.drain(false);
        assert!(rig.bridge.notifications().iter().any(|e| matches!(
            e,
            SessionInbound::Delivered {
                generation: 2,
                token: 1,
                ..
            }
        )));
    }
    #[test]
    fn delivered_final_marker_survives_attach_until_the_child_exit_arrives() {
        for consume_old_callback in [false, true] {
            let mut rig = Rig::new();
            rig.geometry(80, 0);
            rig.data(b"last process output");
            let marker = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
            rig.emit(
                ChannelOutput::DeliveryMarker(DeliveryMarker { token: 1 }, marker),
                None,
            );
            let held = rig.budget.usage(EntryClass::Lifecycle);
            rig.drain(false);
            rig.drain(false);
            if consume_old_callback {
                assert!(rig.bridge.notifications().iter().any(|event| matches!(
                    event,
                    SessionInbound::Delivered {
                        generation: 0,
                        token: 1,
                        ..
                    }
                )));
            }
            // No Exit yet: the actual child is still alive after output EOF.
            // In either callback ordering, a new attachment owes fresh proof.
            for generation in 1..=3 {
                rig.attach();
                rig.bridge.release_barrier(generation);
                assert!(!rig
                    .bridge
                    .notifications()
                    .iter()
                    .any(|event| matches!(event, SessionInbound::Delivered { .. })));
                let mut pending = Vec::new();
                rig.bridge
                    .drain(&mut rig.server, rig.now, false, &mut pending);
                assert!(!pending.is_empty(), "fresh geometry bootstrap must be sent");
                assert!(
                    !rig.bridge
                        .notifications()
                        .iter()
                        .any(|event| matches!(event, SessionInbound::Delivered { .. })),
                    "fresh bootstrap must be acknowledged before delivery proof"
                );
                rig.pump(pending);
                rig.drain(false);
                assert!(rig.bridge.notifications().iter().any(|event| matches!(event,
                SessionInbound::Delivered { generation: found, token: 1, .. } if *found == generation)),
                "the original final marker must produce proof for the new attachment");
                assert_eq!(
                    rig.budget.usage(EntryClass::Lifecycle),
                    held,
                    "the original marker permit remains held while waiting for child reap"
                );
                assert!(!rig.drain(false), "delivered marker must not spin");
                assert!(
                    !rig.bridge
                        .notifications()
                        .iter()
                        .any(|event| matches!(event, SessionInbound::Delivered { .. })),
                    "one callback per attachment"
                );
            }
            let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 10).unwrap();
            rig.bridge.push(SessionOutbound::ChannelExit {
                stream: STREAM,
                instance: ChannelInstance::new(1).unwrap(),
                origin: rig.origin(),
                code: Some(7),
                open: crate::channel::OpenClassification {
                    kind: crate::channel::ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                },
                permit,
            });
            rig.drain(false);
            assert_eq!(
                rig.control_records
                    .iter()
                    .filter(|record| **record
                        == crate::channel::ServerRecord::Exit {
                            stream: STREAM,
                            code: 7
                        })
                    .count(),
                1
            );
            assert!(rig.bridge.streams.is_empty());
            assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
        }
    }

    #[test]
    fn live_screen_replaces_obsolete_snapshot() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.data(b"obsolete");
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.geometry(100, 0);
        rig.data(b"current");
        rig.drain(false);
        assert_eq!(rig.records.len(), 2);
        assert_eq!(rig.records[1], ShellRecord::Data(b"current".to_vec()));
    }
    #[test]
    fn old_origin_close_retires_same_instance_across_attach() {
        let mut rig = Rig::new();
        let origin = rig.origin();
        rig.geometry(80, 0);
        rig.data(b"closed");
        rig.attach();
        rig.bridge.push(SessionOutbound::ChannelClosed {
            stream: STREAM,
            instance: ChannelInstance::new(1).unwrap(),
            origin,
        });
        rig.bridge.release_barrier(1);
        rig.drain(false);
        assert!(rig.records.is_empty());
        assert_eq!(rig.budget.usage(EntryClass::Ordinary), (0, 0));
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
    }
    #[test]
    fn finite_screen_drain_rearms_when_next_record_exceeds_remaining_turn_bytes() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.data(&vec![1; TURN_BYTES - 27 - 10 - 5]);
        rig.geometry(100, 1);
        let mut out = Vec::new();
        assert!(
            rig.bridge.drain(&mut rig.server, rig.now, false, &mut out),
            "remaining record needs an internal continuation, not a network event"
        );
        assert_eq!(
            rig.server.stream_progress(STREAM).queued,
            (TURN_BYTES - 10) as u64
        );
    }
    #[test]
    fn zero_credit_keeps_permit_and_charge_until_real_admission() {
        let mut rig = Rig::new();
        rig.client.set_default_consumption(Consumption::Explicit);
        let payload = vec![9; crate::reliability::STREAM_WINDOW as usize - 5];
        let encoded = crate::shell_frame::encode_record(crate::shell_frame::REC_DATA, &payload);
        let out = rig.server.send(rig.now, STREAM, &encoded);
        rig.pump(out);
        assert_eq!(rig.server.stream_progress(STREAM).unacked, 0);
        assert_eq!(
            rig.server
                .stream_write_room(STREAM, crate::send_gate::PIPE_HIGH as usize),
            0
        );
        rig.records.clear();
        rig.geometry(80, 0);
        rig.data(b"blocked");
        let before = rig.server.stream_progress(STREAM);
        assert!(!rig.drain(false));
        assert_eq!(rig.server.stream_progress(STREAM), before);
        assert_eq!(rig.budget.usage(EntryClass::Ordinary), (1, 27));
        assert!(rig.records.is_empty());
        let updates =
            rig.client
                .on_consumed(rig.now, STREAM, crate::reliability::STREAM_WINDOW as usize);
        for dg in updates {
            rig.server.on_datagram(rig.now, rig.peer, &dg.bytes);
        }
        rig.drain(false);
        assert_eq!(rig.records.len(), 2);
        assert_eq!(rig.budget.usage(EntryClass::Ordinary), (0, 0));
    }
    #[test]
    fn stale_delivery_and_close_cannot_finish_reused_stream() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.data(b"old");
        let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
        rig.emit(
            ChannelOutput::DeliveryMarker(DeliveryMarker { token: 1 }, permit),
            None,
        );
        rig.drain(false);
        rig.drain(false); // old delivery is queued, not handed over
        assert_eq!(
            rig.budget.usage(EntryClass::Lifecycle),
            (2, BRIDGE_LIFECYCLE_BYTES + 32)
        );
        let newer = ChannelInstance::new(2).unwrap();
        let budget = TimelineBudget::new(newer, 0, |_| {});
        let gate = Arc::new(SendGate::new(crate::send_gate::GateKind::Pipe));
        rig.io.send_channel_output(
            STREAM,
            newer,
            rig.origin(),
            gate.clone(),
            ChannelOutput::Geometry(
                GeometryRecord {
                    instance: newer,
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols: 100,
                    rows: 24,
                },
                budget.try_reserve(EntryClass::Lifecycle, 27).unwrap(),
            ),
            budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES),
        );
        rig.bridge.push(rig.outbound.try_recv().unwrap());
        assert_eq!(
            rig.budget.usage(EntryClass::Lifecycle),
            (0, 0),
            "new instance retires the old delivered marker exactly once"
        );
        rig.bridge.push(SessionOutbound::ChannelClosed {
            stream: STREAM,
            instance: ChannelInstance::new(1).unwrap(),
            origin: rig.origin(),
        });
        assert!(!rig
            .bridge
            .notifications()
            .iter()
            .any(|e| matches!(e, SessionInbound::Delivered { token: 1, .. })));
        rig.drain(false);
        assert!(matches!(rig.records.last(),Some(ShellRecord::Geometry(g)) if g.instance==newer));
        assert_eq!(
            budget.usage(EntryClass::Lifecycle),
            (1, BRIDGE_LIFECYCLE_BYTES)
        );
    }

    #[test]
    fn snapshot_close_reuse_never_resurrects_old_exit_or_debits_replacement_gate() {
        use crate::channel::{
            ActiveChannel, ChannelKind, OpenClassification, OpenRequest, ServerRecord,
        };
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        let old_origin = rig.origin();
        let old_instance = ChannelInstance::new(1).unwrap();
        rig.bridge.push(SessionOutbound::ChannelExit {
            stream: STREAM,
            instance: old_instance,
            origin: old_origin,
            code: Some(42),
            open: OpenClassification {
                kind: ChannelKind::Command,
                cols: 0,
                rows: 24,
                screen: false,
            },
            permit: rig.budget.try_reserve(EntryClass::Lifecycle, 10).unwrap(),
        });
        rig.attach();
        // Close belongs to its channel instance even though its attachment was
        // replaced. It must release the old Exit descriptor and permit.
        rig.bridge.push(SessionOutbound::ChannelClosed {
            stream: STREAM,
            instance: old_instance,
            origin: old_origin,
        });
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
        assert_eq!(rig.budget.usage(EntryClass::Ordinary), (0, 0));
        let instance = ChannelInstance::new(2).unwrap();
        let budget = TimelineBudget::new(instance, rig.generation, |_| {});
        let gate = Arc::new(SendGate::new(crate::send_gate::GateKind::Pipe));
        rig.io.send_channel_output(
            STREAM,
            instance,
            rig.origin(),
            gate.clone(),
            ChannelOutput::Geometry(
                GeometryRecord {
                    instance,
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols: 100,
                    rows: 30,
                },
                budget
                    .try_reserve(EntryClass::Ordinary, GEOMETRY_BYTES)
                    .unwrap(),
            ),
            budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES),
        );
        rig.bridge.push(rig.outbound.try_recv().unwrap());
        for _ in 0..2 {
            rig.bridge
                .snapshots
                .publish(rig.generation, || {
                    ChannelSnapshot::new(
                        vec![ActiveChannel {
                            instance,
                            request: OpenRequest {
                                stream: STREAM,
                                kind: ChannelKind::Shell,
                                cols: 100,
                                rows: 30,
                                screen: false,
                                command: vec![],
                            },
                        }],
                        vec![],
                    )
                })
                .unwrap();
            rig.bridge.push(SessionOutbound::ResumeBarrier {
                generation: rig.generation,
            });
            let before = budget.usage(EntryClass::Lifecycle);
            rig.bridge.push(SessionOutbound::ChannelClosed {
                stream: STREAM,
                instance: old_instance,
                origin: old_origin,
            });
            assert_eq!(budget.usage(EntryClass::Lifecycle), before);
            assert_eq!(rig.bridge.streams[&STREAM].instance, instance);
            rig.drain(false);
            assert!(
                matches!(rig.control_records.as_slice(), [ServerRecord::ChannelSnapshot(snapshot)]
                if snapshot.draining().is_empty() && snapshot.active().len() == 1 && snapshot.active()[0].instance == instance)
            );
            assert!(rig.records.iter().any(
                |record| matches!(record, ShellRecord::Geometry(g) if g.instance == instance)
            ));
            rig.attach();
        }
        assert_eq!(rig.bridge.streams.len(), 1);
        assert_eq!(rig.bridge.retired.len(), 1);
        rig.bridge.push(SessionOutbound::ChannelClosed {
            stream: STREAM,
            instance,
            origin: rig.origin(),
        });
        assert_eq!(budget.usage(EntryClass::Lifecycle), (0, 0));
        assert_eq!(budget.usage(EntryClass::Ordinary), (0, 0));
        assert!(gate.is_open());
    }

    #[test]
    fn repeated_stream_reuse_releases_original_owners_without_history_growth() {
        let mut rig = Rig::new();
        for id in 1..=300 {
            let instance = ChannelInstance::new(id).unwrap();
            let budget = TimelineBudget::new(instance, 0, |_| {});
            let gate = Arc::new(SendGate::new(crate::send_gate::GateKind::Pipe));
            rig.io.send_channel_output(
                STREAM,
                instance,
                rig.origin(),
                gate.clone(),
                ChannelOutput::Geometry(
                    GeometryRecord {
                        instance,
                        request_id: 0,
                        outcome: GeometryOutcome::Established,
                        cols: 80,
                        rows: 24,
                    },
                    budget.try_reserve(EntryClass::Lifecycle, 27).unwrap(),
                ),
                budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES),
            );
            rig.bridge.push(rig.outbound.try_recv().unwrap());
            rig.io.send_channel_output(
                STREAM,
                instance,
                rig.origin(),
                gate.clone(),
                ChannelOutput::Data(vec![3; crate::send_gate::PIPE_HIGH as usize]),
                None,
            );
            rig.bridge.push(rig.outbound.try_recv().unwrap());
            assert!(!gate.is_open());
            rig.bridge.push(SessionOutbound::ChannelClosed {
                stream: STREAM,
                instance,
                origin: rig.origin(),
            });
            assert!(
                gate.is_open(),
                "unsent charge released on its original gate"
            );
            assert_eq!(budget.usage(EntryClass::Lifecycle), (0, 0));
            assert!(rig.bridge.streams.is_empty());
            assert_eq!(rig.bridge.retired.len(), 1);
        }
    }
    #[test]
    fn finite_turn_visits_other_stream_before_draining_busy_metadata_stream() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        for i in 0..70 {
            let permit = rig.budget.try_reserve(EntryClass::Ordinary, 13).unwrap();
            rig.emit(ChannelOutput::EchoAck(i, permit), None);
        }
        let instance = ChannelInstance::new(2).unwrap();
        let budget = TimelineBudget::new(instance, 0, |_| {});
        let gate = Arc::new(SendGate::new(crate::send_gate::GateKind::Pipe));
        rig.io.send_channel_output(
            17,
            instance,
            rig.origin(),
            gate,
            ChannelOutput::Geometry(
                GeometryRecord {
                    instance,
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols: 0,
                    rows: 0,
                },
                budget.try_reserve(EntryClass::Lifecycle, 27).unwrap(),
            ),
            budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES),
        );
        rig.bridge.push(rig.outbound.try_recv().unwrap());
        let mut out = Vec::new();
        assert!(rig.bridge.drain(&mut rig.server, rig.now, false, &mut out));
        assert_eq!(rig.server.stream_progress(17).queued, 27);
        assert_eq!(
            rig.budget.usage(EntryClass::Ordinary).0,
            40,
            "exactly 31 records from stream16 plus one from stream17"
        );
        assert!(
            std::mem::size_of::<Queued>() <= 192,
            "wrapper overhead is separate from wire accounting"
        );
    }
    #[tokio::test]
    async fn malicious_zero_credit_resize_pipeline_keeps_one_shared_budget() {
        use crate::channel::{
            encode_client, ChannelKind, ClientRecord, OpenRequest, CONTROL_STREAM,
        };
        let mut rig = Rig::new();
        rig.client.set_default_consumption(Consumption::Explicit);
        let encoded = crate::shell_frame::encode_record(
            crate::shell_frame::REC_DATA,
            &vec![0; crate::reliability::STREAM_WINDOW as usize - 5],
        );
        let out = rig.server.send(rig.now, STREAM, &encoded);
        rig.pump(out);
        assert_eq!(
            rig.server
                .stream_write_room(STREAM, crate::send_gate::PIPE_HIGH as usize),
            0
        );
        let spawner = crate::channel_server::tests::FakeSpawner::new();
        let (io, inbound, mut outbound) = SessionIo::test_pair();
        let runner = tokio::spawn(crate::channel_server::run_channel_session(
            io,
            spawner.clone(),
        ));
        inbound
            .send(SessionInbound::Live(rig.origin()))
            .await
            .unwrap();
        let open = encode_client(&ClientRecord::Open(OpenRequest {
            stream: STREAM,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        }));
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: open,
            }))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let message = outbound.recv().await.unwrap();
                if matches!(message, SessionOutbound::ChannelOutput { .. }) {
                    rig.bridge.push(message);
                    break;
                }
            }
        })
        .await
        .unwrap();
        let mut batch = Vec::new();
        for id in 1..=135 {
            batch.extend(encode_client(&ClientRecord::ResizeRequest {
                stream: STREAM,
                instance: ChannelInstance::new(1).unwrap(),
                request_id: crate::channel_geometry::ResizeRequestId::new(id).unwrap(),
                cols: 80 + id as u16,
                rows: 24,
            }));
        }
        let len = batch.len();
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: batch,
            }))
            .await
            .unwrap();
        let failures = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut failures = 0;
            loop {
                match outbound.recv().await.unwrap() {
                    message @ SessionOutbound::ChannelOutput { .. } => {
                        rig.bridge.push(message);
                        assert!(!rig.drain(false));
                    }
                    SessionOutbound::ProtocolFailure { .. } => failures += 1,
                    SessionOutbound::Consumed {
                        stream_id: CONTROL_STREAM,
                        n,
                    } if n == len => break failures,
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(failures, 1);
        assert_eq!(spawner.sizes.lock().unwrap().len(), 128);
        assert_eq!(
            rig.bridge.streams[&STREAM]
                .budget
                .usage(EntryClass::Ordinary),
            (128, 128 * 27)
        );
        assert_eq!(
            rig.server.stream_progress(STREAM).queued,
            crate::reliability::STREAM_WINDOW
        );
        drop(inbound);
        spawner.end_channel(STREAM);
        runner.await.unwrap();
    }
    #[test]
    fn hot_screen_reset_waits_for_fresh_geometry_before_forwarding() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.drain(false);
        rig.records.clear();
        rig.data(b"obsolete queued representation");
        rig.bridge.hot_reset();
        rig.data(b"reader won select before Repaint");
        rig.drain(false);
        assert!(
            rig.records.is_empty(),
            "new transport framing must not start with DATA"
        );
        rig.bridge.repaint_barrier(0, 1);
        rig.geometry(80, 0);
        rig.data(b"authoritative repaint");
        rig.drain(false);
        assert_eq!(rig.records.len(), 2);
        assert!(matches!(rig.records[0], ShellRecord::Geometry(_)));
        assert_eq!(
            rig.records[1],
            ShellRecord::Data(b"authoritative repaint".to_vec())
        );
    }

    #[test]
    fn geometry_screen_eof_marker_after_hot_reset_preserves_final_prefix() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.drain(false);
        rig.records.clear();
        rig.data(b"final snapshot queued before marker");
        rig.bridge.hot_reset();
        let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
        rig.emit(
            ChannelOutput::DeliveryMarker(DeliveryMarker { token: 1 }, permit),
            None,
        );
        rig.bridge.repaint_barrier(0, 1);
        rig.drain(false);
        assert_eq!(rig.records.len(), 2);
        assert!(matches!(rig.records[0], ShellRecord::Geometry(_)));
        assert_eq!(
            rig.records[1],
            ShellRecord::Data(b"final snapshot queued before marker".to_vec())
        );
        assert!(!rig
            .bridge
            .notifications()
            .iter()
            .any(|e| matches!(e, SessionInbound::Delivered { .. })));
        rig.drain(false);
        assert!(rig
            .bridge
            .notifications()
            .iter()
            .any(|e| matches!(e, SessionInbound::Delivered { token: 1, .. })));
    }
    #[test]
    fn bootstrap_progresses_when_all_lifecycle_entries_are_owned() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.drain(false);
        rig.data(b"retained prefix");
        let held: Vec<_> = (0..7)
            .map(|_| rig.budget.try_reserve(EntryClass::Lifecycle, 27).unwrap())
            .collect();
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle).0, 8);
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.drain(false);
        assert_eq!(
            rig.records.len(),
            2,
            "bootstrap cannot wait for a ninth lifecycle entry"
        );
        assert!(matches!(rig.records[0], ShellRecord::Geometry(_)));
        assert_eq!(
            rig.records[1],
            ShellRecord::Data(b"retained prefix".to_vec())
        );
        drop(held);
    }

    #[test]
    fn hot_cutovers_coalesce_and_attach_retires_old_barriers() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.bridge.hot_reset();
        let request = rig.bridge.notifications();
        assert!(matches!(
            request.as_slice(),
            [SessionInbound::RepaintCutover {
                generation: 0,
                sequence: 1
            }]
        ));
        rig.bridge.hot_reset();
        rig.bridge.hot_reset();
        assert!(rig.bridge.notifications().is_empty());
        rig.bridge.repaint_barrier(0, 1);
        assert!(matches!(
            rig.bridge.notifications().as_slice(),
            [SessionInbound::RepaintCutover {
                generation: 0,
                sequence: 3
            }]
        ));
        rig.drain(false);
        assert!(rig.records.is_empty());
        rig.attach();
        rig.attach();
        rig.bridge.repaint_barrier(0, 3);
        rig.bridge.release_barrier(1);
        rig.drain(false);
        assert!(rig.records.is_empty());
        rig.bridge.release_barrier(2);
        rig.geometry(100, 0);
        rig.data(b"current snapshot");
        rig.drain(false);
        assert_eq!(rig.records.len(), 2);
        assert!(matches!(&rig.records[0], ShellRecord::Geometry(g) if g.cols == 100));
        assert_eq!(
            rig.records[1],
            ShellRecord::Data(b"current snapshot".to_vec())
        );
    }

    #[test]
    fn discarded_eof_data_reports_one_gap_but_metadata_does_not() {
        for submitted_data in [false, true] {
            let mut rig = Rig::new();
            rig.bridge.declare(STREAM, true);
            rig.server.set_stream_resyncable(STREAM, true);
            rig.geometry(80, 0);
            if submitted_data {
                rig.data(b"lost final DATA");
            }
            let mut abandoned = Vec::new();
            rig.bridge
                .drain(&mut rig.server, rig.now, false, &mut abandoned);
            rig.now += std::time::Duration::from_secs(11);
            rig.server.on_timeout(rig.now);
            assert_eq!(rig.server.state(), crate::LinkState::PathDown);
            rig.bridge.observe_discards(&mut rig.server);
            // The authenticated return queues the repaint before EOF's marker
            // is processed, although the model already produced its final prefix.
            for dg in rig.client.send(rig.now, 0, b"return") {
                rig.server.on_datagram(rig.now, rig.peer, &dg.bytes);
            }
            assert!(rig
                .server
                .poll_events()
                .iter()
                .any(|e| matches!(e, Event::OutputResync)));
            rig.bridge.hot_reset();
            rig.data(b"final retained checkpoint");
            let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
            rig.emit(
                ChannelOutput::DeliveryMarker(DeliveryMarker { token: 9 }, permit),
                None,
            );
            rig.bridge.seal_ended(&mut rig.server);
            rig.bridge.repaint_barrier(0, 1);
            rig.attach();
            rig.attach();
            rig.bridge.release_barrier(2);
            rig.drain(false);
            assert!(matches!(rig.records[0], ShellRecord::Geometry(_)));
            assert_eq!(
                rig.records
                    .iter()
                    .filter(|r| matches!(r, ShellRecord::OutputGap { .. }))
                    .count(),
                usize::from(submitted_data)
            );
            assert_eq!(
                rig.records.last(),
                Some(&ShellRecord::Data(b"final retained checkpoint".to_vec()))
            );
            rig.drain(false);
            assert_eq!(
                rig.bridge
                    .notifications()
                    .iter()
                    .filter(|e| matches!(e, SessionInbound::Delivered { token: 9, .. }))
                    .count(),
                1
            );
            assert!(rig.bridge.notifications().is_empty());
            assert_eq!(rig.bridge.streams[&STREAM].fifo.len(), 0);
            assert!(rig.gate.is_open());
        }
    }

    #[test]
    fn exit_keeps_its_permit_until_control_credit_admits_it() {
        let mut rig = Rig::new();
        let control = crate::channel::CONTROL_STREAM;
        rig.client.set_default_consumption(Consumption::Explicit);
        let out = rig.server.send(
            rig.now,
            control,
            &vec![0; crate::reliability::STREAM_WINDOW as usize],
        );
        rig.pump(out);
        assert_eq!(
            rig.server
                .stream_write_room(control, crate::send_gate::PIPE_HIGH as usize),
            0
        );
        rig.geometry(80, 0);
        rig.drain(false);
        let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 10).unwrap();
        rig.bridge.push(SessionOutbound::ChannelExit {
            stream: STREAM,
            instance: ChannelInstance::new(1).unwrap(),
            origin: rig.origin(),
            code: Some(42),
            open: crate::channel::OpenClassification {
                kind: crate::channel::ChannelKind::Command,
                cols: 0,
                rows: 24,
                screen: false,
            },
            permit,
        });
        let held = rig.budget.usage(EntryClass::Lifecycle);
        assert!(!rig.drain(false));
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), held);
        assert_eq!(rig.bridge.streams[&STREAM].fifo.len(), 1);
        assert!(matches!(
            rig.bridge.streams[&STREAM].fifo[0].output,
            Item::Exit(
                Some(42),
                crate::channel::OpenClassification {
                    kind: crate::channel::ChannelKind::Command,
                    cols: 0,
                    rows: 24,
                    screen: false,
                },
                _
            )
        ));
        for dg in
            rig.client
                .on_consumed(rig.now, control, crate::reliability::STREAM_WINDOW as usize)
        {
            rig.server.on_datagram(rig.now, rig.peer, &dg.bytes);
        }
        rig.drain(false);
        assert!(!rig.bridge.streams.contains_key(&STREAM));
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
        assert_eq!(
            rig.server.stream_progress(control).queued,
            crate::reliability::STREAM_WINDOW + 10
        );
    }

    #[test]
    fn repeated_discards_before_observation_keep_real_data_loss() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.server.set_stream_resyncable(STREAM, true);
        rig.geometry(80, 0);
        rig.data(b"lost DATA");
        let mut out = Vec::new();
        rig.bridge.drain(&mut rig.server, rig.now, false, &mut out);
        rig.now += std::time::Duration::from_secs(11);
        rig.server.on_timeout(rig.now);
        for dg in rig.client.send(rig.now, 0, b"return") {
            rig.server.on_datagram(rig.now, rig.peer, &dg.bytes);
        }
        // A later metadata-only discard must not overwrite earlier DATA loss.
        rig.server.send(
            rig.now,
            STREAM,
            &encode_shell(&ShellRecord::EchoAck(1)).unwrap(),
        );
        rig.now += std::time::Duration::from_secs(11);
        rig.server.on_timeout(rig.now);
        rig.bridge.observe_discards(&mut rig.server);
        let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
        rig.emit(
            ChannelOutput::DeliveryMarker(DeliveryMarker { token: 1 }, permit),
            None,
        );
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.drain(false);
        assert_eq!(
            rig.records
                .iter()
                .filter(|r| matches!(r, ShellRecord::OutputGap { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn mixed_screen_pipe_and_command_survive_two_attaches_without_process_output() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.data(b"obsolete Screen");
        let mut budgets = Vec::new();
        for stream in [17, 18] {
            rig.bridge.declare(stream, false);
            let instance = ChannelInstance::new(u64::from(stream)).unwrap();
            let budget = TimelineBudget::new(instance, 0, |_| {});
            let gate = rig.io.send_gate(stream, crate::send_gate::GateKind::Pipe);
            let geometries: &[u16] = if stream == 17 { &[80, 100] } else { &[0] };
            for (i, &cols) in geometries.iter().enumerate() {
                rig.io.send_channel_output(
                    stream,
                    instance,
                    rig.origin(),
                    gate.clone(),
                    ChannelOutput::Geometry(
                        GeometryRecord {
                            instance,
                            request_id: i as u64,
                            outcome: GeometryOutcome::Established,
                            cols,
                            rows: if cols == 0 { 0 } else { 24 },
                        },
                        budget.try_reserve(EntryClass::Ordinary, 27).unwrap(),
                    ),
                    if i == 0 {
                        budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES)
                    } else {
                        None
                    },
                );
                rig.io.send_channel_output(
                    stream,
                    instance,
                    rig.origin(),
                    gate.clone(),
                    ChannelOutput::Data(if stream == 18 {
                        b"command output".to_vec()
                    } else if i == 0 {
                        b"old width".to_vec()
                    } else {
                        b"new width".to_vec()
                    }),
                    None,
                );
            }
            budgets.push(budget);
        }
        while let Ok(message) = rig.outbound.try_recv() {
            rig.bridge.push(message);
        }
        rig.attach();
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.drain(false);
        assert!(rig.records.is_empty() && rig.other_records.is_empty());
        rig.bridge.release_barrier(2);
        // The live model can repaint on reset without any new process bytes.
        rig.geometry(80, 0);
        rig.data(b"current Screen checkpoint");
        while rig.drain(false) {}
        assert_eq!(rig.records.len(), 2);
        assert_eq!(
            rig.records[1],
            ShellRecord::Data(b"current Screen checkpoint".to_vec())
        );
        let pipe = &rig.other_records[&17];
        assert_eq!(pipe.len(), 4);
        assert!(matches!(&pipe[0], ShellRecord::Geometry(g) if g.cols == 80 && g.request_id == 0));
        assert_eq!(pipe[1], ShellRecord::Data(b"old width".to_vec()));
        assert!(matches!(&pipe[2], ShellRecord::Geometry(g) if g.cols == 100 && g.request_id == 0));
        assert_eq!(pipe[3], ShellRecord::Data(b"new width".to_vec()));
        let command = &rig.other_records[&18];
        assert_eq!(command.len(), 2);
        assert!(matches!(&command[0], ShellRecord::Geometry(g) if g.cols == 0 && g.rows == 0));
        assert_eq!(command[1], ShellRecord::Data(b"command output".to_vec()));
        assert!(budgets
            .iter()
            .all(|budget| budget.usage(EntryClass::Ordinary) == (0, 0)));
    }

    #[test]
    fn exhausted_offset_parks_connection_without_releasing_pending_geometry() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.server.limit_channel_offset_for_test(STREAM, 2);
        let before = rig.server.stream_progress(STREAM);
        assert!(!rig.drain(false));
        assert_eq!(rig.server.state(), crate::LinkState::Closed);
        assert!(!rig.server.closed_gracefully());
        assert_eq!(rig.server.stream_progress(STREAM), before);
        assert_eq!(rig.budget.usage(EntryClass::Ordinary), (1, 27));
        assert_eq!(rig.bridge.streams[&STREAM].fifo.len(), 1);
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.drain(false);
        assert!(matches!(rig.records.as_slice(), [ShellRecord::Geometry(_)]));
        assert_eq!(rig.budget.usage(EntryClass::Ordinary), (0, 0));
    }
    #[test]
    fn submitted_gap_survives_attach_until_its_ack_frontier() {
        for acknowledge_gap in [false, true] {
            let mut rig = Rig::new();
            rig.geometry(80, 0);
            rig.data(b"lost before first Attach");
            let mut abandoned = Vec::new();
            rig.bridge
                .drain(&mut rig.server, rig.now, false, &mut abandoned);
            rig.attach();
            rig.bridge.release_barrier(1);
            let mut gap_datagrams = Vec::new();
            rig.bridge
                .drain(&mut rig.server, rig.now, false, &mut gap_datagrams);
            assert_eq!(rig.server.stream_progress(STREAM).queued, 41);
            assert_eq!(
                rig.bridge.streams[&STREAM].data_end, 0,
                "no intermediate DATA"
            );
            if acknowledge_gap {
                rig.pump(gap_datagrams);
            }
            rig.attach();
            rig.bridge.release_barrier(2);
            rig.data(b"final retained output");
            let marker = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
            rig.emit(
                ChannelOutput::DeliveryMarker(DeliveryMarker { token: 1 }, marker),
                None,
            );
            rig.drain(false);
            assert!(matches!(rig.records[0], ShellRecord::Geometry(_)));
            assert_eq!(
                rig.records
                    .iter()
                    .filter(|r| matches!(r, ShellRecord::OutputGap { .. }))
                    .count(),
                usize::from(!acknowledge_gap)
            );
            assert_eq!(
                rig.records.last(),
                Some(&ShellRecord::Data(b"final retained output".to_vec()))
            );
            assert!(!rig
                .bridge
                .notifications()
                .iter()
                .any(|event| matches!(event, SessionInbound::Delivered { .. })));
            rig.drain(false);
            assert_eq!(
                rig.bridge
                    .notifications()
                    .iter()
                    .filter(|event| matches!(
                        event,
                        SessionInbound::Delivered {
                            token: 1,
                            generation: 2,
                            ..
                        }
                    ))
                    .count(),
                1
            );
            assert_eq!(
                rig.budget.usage(EntryClass::Lifecycle),
                (2, BRIDGE_LIFECYCLE_BYTES + 32)
            );
            rig.bridge.push(SessionOutbound::ChannelClosed {
                stream: STREAM,
                instance: ChannelInstance::new(1).unwrap(),
                origin: rig.origin(),
            });
            assert_eq!(
                rig.budget.usage(EntryClass::Lifecycle),
                (0, 0),
                "Close releases the retained final marker and bridge reserve"
            );
        }
    }

    #[test]
    fn submitted_gap_is_retired_with_its_channel_instance() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.data(b"old instance lost DATA");
        let mut abandoned = Vec::new();
        rig.bridge
            .drain(&mut rig.server, rig.now, false, &mut abandoned);
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.bridge
            .drain(&mut rig.server, rig.now, false, &mut abandoned);
        assert_eq!(rig.server.stream_progress(STREAM).queued, 41);
        let newer = ChannelInstance::new(2).unwrap();
        let budget = TimelineBudget::new(newer, 1, |_| {});
        let gate = Arc::new(SendGate::new(crate::send_gate::GateKind::Pipe));
        rig.io.send_channel_output(
            STREAM,
            newer,
            rig.origin(),
            gate.clone(),
            ChannelOutput::Geometry(
                GeometryRecord {
                    instance: newer,
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols: 100,
                    rows: 24,
                },
                budget.try_reserve(EntryClass::Lifecycle, 27).unwrap(),
            ),
            budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES),
        );
        rig.io.send_channel_output(
            STREAM,
            newer,
            rig.origin(),
            gate,
            ChannelOutput::Data(b"new instance".to_vec()),
            None,
        );
        while let Ok(message) = rig.outbound.try_recv() {
            rig.bridge.push(message);
        }
        rig.attach();
        rig.bridge.release_barrier(2);
        rig.drain(false);
        assert_eq!(rig.records.len(), 2);
        assert!(matches!(rig.records[0], ShellRecord::Geometry(g) if g.instance == newer));
        assert_eq!(rig.records[1], ShellRecord::Data(b"new instance".to_vec()));
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
        assert_eq!(rig.bridge.streams.len(), 1);
    }

    #[test]
    fn noscreen_record_retains_full_ownership_below_complete_credit() {
        for attach in [false, true] {
            let mut rig = Rig::new();
            rig.client.set_default_consumption(Consumption::Explicit);
            rig.geometry(80, 0);
            rig.drain(false);
            let padding = crate::shell_frame::encode_record(
                crate::shell_frame::REC_DATA,
                &vec![0; crate::reliability::STREAM_WINDOW as usize - 27 - 6 - 5],
            );
            let out = rig.server.send(rig.now, STREAM, &padding);
            rig.pump(out);
            assert_eq!(
                rig.server
                    .stream_write_room(STREAM, crate::send_gate::PIPE_HIGH as usize),
                6
            );
            rig.records.clear();
            let payload = vec![7; 8192];
            rig.data(&payload);
            let before = rig.server.stream_progress(STREAM);
            assert!(!rig.drain(false));
            assert_eq!(
                rig.server.stream_progress(STREAM),
                before,
                "no partial NoScreen DATA admission"
            );
            let retained = rig.bridge.streams[&STREAM].fifo.front().unwrap();
            assert_eq!(retained.offset, 0);
            assert_eq!(retained.charge.as_ref().unwrap().bytes, 8197);
            if attach {
                rig.attach();
                rig.bridge.release_barrier(1);
            } else {
                for dg in rig.client.on_consumed(
                    rig.now,
                    STREAM,
                    crate::reliability::STREAM_WINDOW as usize - 6,
                ) {
                    rig.server.on_datagram(rig.now, rig.peer, &dg.bytes);
                }
            }
            // Six unused credit bytes mean the receiver may delay its CREDIT
            // until the service timer, unlike an exactly exhausted window.
            rig.now += std::time::Duration::from_millis(20);
            for dg in rig.client.on_timeout(rig.now) {
                rig.server.on_datagram(rig.now, rig.peer, &dg.bytes);
            }
            assert!(
                rig.server
                    .stream_write_room(STREAM, crate::send_gate::PIPE_HIGH as usize)
                    >= 8197
            );
            rig.drain(false);
            let data: Vec<_> = rig
                .records
                .iter()
                .filter_map(|record| match record {
                    ShellRecord::Data(bytes) => Some(bytes),
                    _ => None,
                })
                .collect();
            assert_eq!(data.len(), 1, "attach={attach}");
            assert_eq!(data[0], &payload);
            assert!(rig.bridge.streams[&STREAM].fifo.is_empty());
            assert!(!rig
                .records
                .iter()
                .any(|record| matches!(record, ShellRecord::OutputGap { .. })));
        }
    }

    #[test]
    fn noscreen_record_retains_full_ownership_at_turn_remainder() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.drain(false);
        for byte in 0..8 {
            rig.data(&vec![byte; 8192]);
        }
        let before = rig.server.stream_progress(STREAM).queued;
        let mut abandoned = Vec::new();
        assert!(rig
            .bridge
            .drain(&mut rig.server, rig.now, false, &mut abandoned));
        assert_eq!(rig.server.stream_progress(STREAM).queued - before, 7 * 8197);
        let retained = rig.bridge.streams[&STREAM].fifo.front().unwrap();
        assert_eq!(retained.offset, 0);
        assert_eq!(retained.charge.as_ref().unwrap().bytes, 8197);
        rig.attach();
        rig.bridge.release_barrier(1);
        rig.drain(false);
        assert_eq!(rig.records.len(), 3);
        assert!(matches!(rig.records[0], ShellRecord::Geometry(_)));
        assert!(matches!(rig.records[1], ShellRecord::OutputGap { .. }));
        assert_eq!(rig.records[2], ShellRecord::Data(vec![7; 8192]));
    }

    #[test]
    fn noscreen_offset_exhaustion_preserves_the_whole_pending_record() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.drain(false);
        rig.data(&vec![7; 8192]);
        rig.server.limit_channel_offset_for_test(STREAM, 8196);
        let before = rig.server.stream_progress(STREAM);
        let mut out = Vec::new();
        rig.bridge.drain(&mut rig.server, rig.now, false, &mut out);
        assert_eq!(rig.server.state(), crate::LinkState::Closed);
        assert_eq!(rig.server.stream_progress(STREAM), before);
        let retained = rig.bridge.streams[&STREAM].fifo.front().unwrap();
        assert_eq!(retained.offset, 0);
        assert_eq!(retained.charge.as_ref().unwrap().bytes, 8197);
    }

    #[test]
    fn exit_records_count_toward_the_same_turn_byte_limit() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        let mut budgets = Vec::new();
        for stream in [17, 18] {
            let instance = ChannelInstance::new(u64::from(stream)).unwrap();
            let budget = TimelineBudget::new(instance, 0, |_| {});
            let gate = rig.io.send_gate(stream, crate::send_gate::GateKind::Pipe);
            rig.io.send_channel_output(
                stream,
                instance,
                rig.origin(),
                gate,
                ChannelOutput::Geometry(
                    GeometryRecord {
                        instance,
                        request_id: 0,
                        outcome: GeometryOutcome::Established,
                        cols: 80,
                        rows: 24,
                    },
                    budget.try_reserve(EntryClass::Lifecycle, 27).unwrap(),
                ),
                budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES),
            );
            budgets.push(budget);
        }
        while let Ok(message) = rig.outbound.try_recv() {
            rig.bridge.push(message);
        }
        rig.drain(false);
        for (stream, budget) in [17, 18].into_iter().zip(&budgets) {
            assert_eq!(rig.server.stream_progress(stream).unacked, 0);
            rig.bridge.push(SessionOutbound::ChannelExit {
                stream,
                instance: ChannelInstance::new(u64::from(stream)).unwrap(),
                origin: rig.origin(),
                code: Some(0),
                open: crate::channel::OpenClassification {
                    kind: crate::channel::ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                },
                permit: budget.try_reserve(EntryClass::Lifecycle, 10).unwrap(),
            });
        }
        rig.data(&vec![7; TURN_BYTES - 15 - 5]);
        rig.bridge.cursor = 15;
        let before = rig.server.stream_progress(STREAM).queued;
        let mut out = Vec::new();
        let again = rig.bridge.drain(&mut rig.server, rig.now, false, &mut out);
        let data_bytes = rig.server.stream_progress(STREAM).queued - before;
        let exit_bytes = rig
            .server
            .stream_progress(crate::channel::CONTROL_STREAM)
            .queued;
        assert_eq!(data_bytes, (TURN_BYTES - 15) as u64);
        assert_eq!(exit_bytes, 10, "the second Exit does not fit this turn");
        assert!(data_bytes + exit_bytes <= TURN_BYTES as u64);
        assert!(again, "remaining Exit gets one internal continuation");
        assert_eq!(budgets[0].usage(EntryClass::Lifecycle), (0, 0));
        assert_eq!(
            budgets[1].usage(EntryClass::Lifecycle),
            (2, BRIDGE_LIFECYCLE_BYTES + 10)
        );
        rig.bridge.drain(&mut rig.server, rig.now, false, &mut out);
        assert_eq!(
            rig.server
                .stream_progress(crate::channel::CONTROL_STREAM)
                .queued,
            20
        );
        assert_eq!(budgets[1].usage(EntryClass::Lifecycle), (0, 0));
    }

    #[test]
    fn repeated_gap_only_attaches_keep_one_frontier_and_allowance() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        rig.data(b"initial lost DATA");
        let mut abandoned = Vec::new();
        rig.bridge
            .drain(&mut rig.server, rig.now, false, &mut abandoned);
        for _ in 0..32 {
            rig.attach();
            rig.bridge.release_barrier(rig.generation);
            abandoned.clear();
            rig.bridge
                .drain(&mut rig.server, rig.now, false, &mut abandoned);
            assert_eq!(rig.server.stream_progress(STREAM).queued, 41);
            let state = &rig.bridge.streams[&STREAM];
            assert_eq!(state.gap_end, 41);
            assert_eq!(state.data_end, 0);
            assert!(
                !state.abandoned_data
                    && state.gap_charge.is_none()
                    && state.bootstrap_charge.is_none()
            );
            assert!(state.fifo.is_empty());
            assert_eq!(rig.bridge.streams.len(), 1);
            assert_eq!(
                rig.budget.usage(EntryClass::Lifecycle),
                (1, BRIDGE_LIFECYCLE_BYTES)
            );
        }
        rig.bridge.push(SessionOutbound::ChannelClosed {
            stream: STREAM,
            instance: ChannelInstance::new(1).unwrap(),
            origin: rig.origin(),
        });
        assert!(rig.bridge.streams.is_empty());
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
    }
    fn reply44_gap(rig: &mut Rig) {
        let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 14).unwrap();
        rig.emit(
            ChannelOutput::OutputGap(OutputGapCause::TerminalReplyFailure, permit),
            None,
        );
    }
    fn reply44_marker(rig: &mut Rig) {
        let permit = rig.budget.try_reserve(EntryClass::Lifecycle, 32).unwrap();
        rig.emit(
            ChannelOutput::DeliveryMarker(DeliveryMarker { token: 1 }, permit),
            None,
        );
    }
    fn reply44_gap_count(rig: &Rig) -> usize {
        rig.records
            .iter()
            .filter(|record| {
                matches!(record, ShellRecord::OutputGap {
            instance, cause: OutputGapCause::TerminalReplyFailure,
        } if instance.get() == 1)
            })
            .count()
    }

    #[test]
    fn reply44_terminal_gap_waits_for_credit_and_precedes_final_delivery() {
        let mut rig = Rig::new();
        rig.client.set_default_consumption(Consumption::Explicit);
        let occupied = crate::shell_frame::encode_record(
            crate::shell_frame::REC_DATA,
            &vec![0; crate::reliability::STREAM_WINDOW as usize - 5],
        );
        let out = rig.server.send(rig.now, STREAM, &occupied);
        rig.pump(out);
        rig.records.clear();
        rig.geometry(80, 0);
        rig.data(b"retained before failure");
        reply44_gap(&mut rig);
        reply44_marker(&mut rig);
        let held = rig.budget.usage(EntryClass::Lifecycle);
        assert_eq!(held, (3, 87));
        let before = rig.server.stream_progress(STREAM);
        for _ in 0..3 {
            assert!(!rig.drain(false));
            assert_eq!(rig.server.stream_progress(STREAM), before);
            assert_eq!(rig.budget.usage(EntryClass::Lifecycle), held);
            assert!(rig.records.is_empty());
            assert!(!rig
                .bridge
                .notifications()
                .iter()
                .any(|e| matches!(e, SessionInbound::Delivered { .. })));
        }
        let updates =
            rig.client
                .on_consumed(rig.now, STREAM, crate::reliability::STREAM_WINDOW as usize);
        for dg in updates {
            rig.server.on_datagram(rig.now, rig.peer, &dg.bytes);
        }
        let mut pending = Vec::new();
        rig.bridge
            .drain(&mut rig.server, rig.now, false, &mut pending);
        assert!(!rig
            .bridge
            .notifications()
            .iter()
            .any(|e| matches!(e, SessionInbound::Delivered { .. })));
        rig.pump(pending);
        rig.drain(false);
        assert_eq!(rig.records.len(), 3);
        assert!(matches!(rig.records[0], ShellRecord::Geometry(_)));
        assert_eq!(
            rig.records[1],
            ShellRecord::Data(b"retained before failure".to_vec())
        );
        assert_eq!(reply44_gap_count(&rig), 1);
        assert!(rig
            .bridge
            .notifications()
            .iter()
            .any(|e| matches!(e, SessionInbound::Delivered { token: 1, .. })));
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), held);
        rig.bridge.push(SessionOutbound::ChannelClosed {
            stream: STREAM,
            instance: ChannelInstance::new(1).unwrap(),
            origin: rig.origin(),
        });
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
    }

    #[test]
    fn reply44_acknowledged_gap_survives_warm_attach_while_child_reap_is_pending() {
        for consume_old_callback in [false, true] {
            let mut rig = Rig::new();
            rig.bridge.declare(STREAM, true);
            rig.geometry(80, 0);
            rig.data(b"before failure");
            reply44_gap(&mut rig);
            reply44_marker(&mut rig);
            rig.drain(false);
            rig.drain(false);
            assert_eq!(reply44_gap_count(&rig), 1);
            if consume_old_callback {
                assert!(rig
                    .bridge
                    .notifications()
                    .iter()
                    .any(|e| matches!(e, SessionInbound::Delivered { token: 1, .. })));
            }
            let held = rig.budget.usage(EntryClass::Lifecycle);
            assert_eq!(held, (3, 87));
            for generation in 1..=3 {
                rig.attach();
                rig.bridge.release_barrier(generation);
                let mut pending = Vec::new();
                rig.bridge
                    .drain(&mut rig.server, rig.now, false, &mut pending);
                assert!(!rig
                    .bridge
                    .notifications()
                    .iter()
                    .any(|e| matches!(e, SessionInbound::Delivered { .. })));
                rig.pump(pending);
                rig.drain(false);
                assert_eq!(
                    reply44_gap_count(&rig),
                    1,
                    "each new client learns the retained cause"
                );
                assert!(matches!(rig.records[0], ShellRecord::Geometry(_)));
                assert!(
                    rig.bridge.notifications().iter().any(|e| matches!(e,
                    SessionInbound::Delivered { token: 1, generation: g, .. } if *g == generation))
                );
                assert_eq!(rig.budget.usage(EntryClass::Lifecycle), held);
                assert!(!rig.drain(false));
                assert_eq!(
                    reply44_gap_count(&rig),
                    1,
                    "ACK must not queue another same-attachment warning"
                );
            }
            rig.bridge.push(SessionOutbound::ChannelExit {
                stream: STREAM,
                instance: ChannelInstance::new(1).unwrap(),
                origin: rig.origin(),
                code: Some(7),
                open: crate::channel::OpenClassification {
                    kind: crate::channel::ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: true,
                },
                permit: rig.budget.try_reserve(EntryClass::Lifecycle, 10).unwrap(),
            });
            rig.drain(false);
            assert!(!rig.bridge.streams.contains_key(&STREAM));
            assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
        }
    }

    #[test]
    fn reply44_hot_reset_before_eof_keeps_output_and_failure_without_model_repaint() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.data(b"already admitted before poisoned screen");
        reply44_gap(&mut rig);
        assert!(rig.bridge.hot_reset());
        let barrier = rig
            .bridge
            .notifications()
            .into_iter()
            .find_map(|e| match e {
                SessionInbound::RepaintCutover {
                    generation,
                    sequence,
                } => Some((generation, sequence)),
                _ => None,
            })
            .unwrap();
        // The poisoned model supplies no replacement geometry/data. The ordered
        // runner barrier must preserve the already-admitted records by itself.
        rig.bridge.repaint_barrier(barrier.0, barrier.1);
        rig.drain(false);
        assert!(rig.records.contains(&ShellRecord::Data(
            b"already admitted before poisoned screen".to_vec()
        )));
        assert_eq!(reply44_gap_count(&rig), 1);
        assert!(!rig
            .bridge
            .notifications()
            .iter()
            .any(|e| matches!(e, SessionInbound::Delivered { .. })));
        reply44_marker(&mut rig); // Only actual reader EOF grants this marker.
        rig.drain(false);
        rig.drain(false);
        assert!(rig
            .bridge
            .notifications()
            .iter()
            .any(|e| matches!(e, SessionInbound::Delivered { token: 1, .. })));
    }

    #[test]
    fn reply44_duplicate_failure_and_stream_reuse_keep_one_scoped_owner() {
        let mut rig = Rig::new();
        rig.geometry(80, 0);
        reply44_gap(&mut rig);
        let held = rig.budget.usage(EntryClass::Lifecycle);
        for _ in 0..3 {
            reply44_gap(&mut rig);
        }
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), held);
        rig.drain(false);
        assert_eq!(reply44_gap_count(&rig), 1);
        let newer = ChannelInstance::new(2).unwrap();
        let budget = TimelineBudget::new(newer, 0, |_| {});
        let gate = Arc::new(SendGate::new(crate::send_gate::GateKind::Pipe));
        rig.io.send_channel_output(
            STREAM,
            newer,
            rig.origin(),
            gate.clone(),
            ChannelOutput::Geometry(
                GeometryRecord {
                    instance: newer,
                    request_id: 0,
                    outcome: GeometryOutcome::Established,
                    cols: 100,
                    rows: 24,
                },
                budget.try_reserve(EntryClass::Ordinary, 27).unwrap(),
            ),
            budget.try_reserve(EntryClass::Lifecycle, BRIDGE_LIFECYCLE_BYTES),
        );
        rig.bridge.push(rig.outbound.try_recv().unwrap());
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
        rig.records.clear();
        reply44_gap(&mut rig); // A late message from the replaced instance.
        rig.drain(false);
        assert_eq!(reply44_gap_count(&rig), 0);
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (0, 0));
        assert_eq!(rig.bridge.streams[&STREAM].instance, newer);
        assert!(!rig.bridge.streams[&STREAM].ended);
        rig.bridge.push(SessionOutbound::ChannelClosed {
            stream: STREAM,
            instance: newer,
            origin: rig.origin(),
        });
        assert_eq!(budget.usage(EntryClass::Lifecycle), (0, 0));
    }
    #[test]
    fn reply44_failure_after_hot_barrier_bootstraps_the_retained_committed_geometry() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.drain(false);
        rig.records.clear();
        assert!(rig.bridge.hot_reset());
        let barrier = rig
            .bridge
            .notifications()
            .into_iter()
            .find_map(|e| match e {
                SessionInbound::RepaintCutover {
                    generation,
                    sequence,
                } => Some((generation, sequence)),
                _ => None,
            })
            .unwrap();
        rig.bridge.repaint_barrier(barrier.0, barrier.1);
        reply44_gap(&mut rig);
        rig.drain(false);
        assert!(
            matches!(rig.records.first(), Some(ShellRecord::Geometry(g)) if g.cols == 80 && g.request_id == 0)
        );
        assert_eq!(reply44_gap_count(&rig), 1);
    }

    #[test]
    fn reply44_failure_waits_for_a_late_warm_checkpoint_without_bypassing_geometry() {
        let mut rig = Rig::new();
        rig.bridge.declare(STREAM, true);
        rig.geometry(80, 0);
        rig.drain(false);
        rig.attach();
        rig.bridge.release_barrier(rig.generation);
        // The active warm barrier requires a fresh checkpoint; the producer
        // may still be waiting for its bounded metadata slot when parsing fails.
        reply44_gap(&mut rig);
        assert!(
            !rig.drain(false),
            "a failure gap cannot bypass missing geometry"
        );
        assert!(rig.records.is_empty());
        rig.geometry(80, 0); // Capacity returned; committed geometry needs no model replay.
        rig.drain(false);
        assert!(
            matches!(rig.records.first(), Some(ShellRecord::Geometry(g)) if g.cols == 80 && g.request_id == 0)
        );
        assert_eq!(reply44_gap_count(&rig), 1);
        assert_eq!(rig.budget.usage(EntryClass::Ordinary), (0, 0));
        assert_eq!(rig.budget.usage(EntryClass::Lifecycle), (2, 55));
    }
}
