//! Send gates (spec §4.7.2, §4.7.3): how a producer above a `Connection`
//! learns that one of its streams has enough queued.
//!
//! A gate watches one stream's tail -- what the connection holds for it,
//! queued and not yet acknowledged, as `Connection::stream_progress` reports
//! it -- plus what a producer has handed over and the driver has not taken
//! yet: on the client a bounded producer's bytes on their way to the driver
//! thread, on the daemon a backend's on their way to the bridge. It closes
//! at the high mark and opens again at the low one (hysteresis: a repaint
//! or a refill does not follow every freed segment). Whoever drives the
//! connection (the daemon's bridge, the client's driver thread) refreshes
//! the gates after every wake-up; whoever produces looks at them or waits
//! on them. Std only: the waiting side is a blocking task or a plain
//! thread, and a critical section is a few integers.

use std::collections::BTreeMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

/// A screen channel's marks: how much stale output may stand in front of a
/// Ctrl-C -- ~130 ms at 1 MB/s -- and a quarter of that to reopen, so a
/// repaint does not follow every segment that leaves (spec §3.2).
pub const SCREEN_HIGH: u64 = 128 * 1024;
pub const SCREEN_LOW: u64 = 32 * 1024;
/// A line channel's and a client producer's marks: twice the 256 KiB a
/// stream may have in flight, so at the low mark the whole window can still
/// be in flight and the producer refills it before it runs dry (spec §3.2).
pub const PIPE_HIGH: u64 = 512 * 1024;
pub const PIPE_LOW: u64 = 256 * 1024;

/// What a gate is for, and so its marks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateKind {
    /// A channel with a screen model: its producer never waits; behind a
    /// closed gate it drops output and repaints once the gate opens, which
    /// it hears of as `SessionInbound::Writable`.
    Screen,
    /// A stream without one (a line protocol like `tmux -C`, a daemon image):
    /// its producer waits for the gate before producing more.
    Pipe,
}

impl GateKind {
    /// `(high, low)`.
    pub fn marks(self) -> (u64, u64) {
        match self {
            GateKind::Screen => (SCREEN_HIGH, SCREEN_LOW),
            GateKind::Pipe => (PIPE_HIGH, PIPE_LOW),
        }
    }

    fn wants_writable(self) -> bool {
        matches!(self, GateKind::Screen)
    }
}

/// How a wait on a gate ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GateWait {
    Open,
    TimedOut,
    /// The stream is gone (its channel closed, the session or the driver
    /// ended): it will never open again.
    Closed,
}

#[derive(Debug)]
struct GateState {
    open: bool,
    closed: bool,
    tail: u64,
    pending: u64,
    metadata_blocked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ClientAdmission {
    Admitted,
    Full,
    Closed,
}

/// One stream's gate. Shared (`Arc`) between whoever refreshes it and
/// whoever produces.
#[derive(Debug)]
pub struct SendGate {
    kind: GateKind,
    state: Mutex<GateState>,
    changed: Condvar,
}

impl SendGate {
    pub fn new(kind: GateKind) -> SendGate {
        SendGate {
            kind,
            state: Mutex::new(GateState {
                open: true,
                closed: false,
                tail: 0,
                pending: 0,
                metadata_blocked: false,
            }),
            changed: Condvar::new(),
        }
    }

    /// Hold new producer reads for metadata admission independently of byte
    /// hysteresis. Does not prevent draining already charged output. Returns
    /// whether the effective producer gate just opened.
    pub fn set_metadata_blocked(&self, blocked: bool) -> bool {
        let mut st = self.state.lock().expect("send gate");
        let was_open = Self::effective_open(&st);
        st.metadata_blocked = blocked;
        self.recompute_bytes(&mut st);
        self.notify_opened(&st, was_open)
    }

    #[cfg(any(test, feature = "testnet"))]
    pub(crate) fn qualification_state(&self) -> (bool, bool, bool, u64) {
        let state = self.state.lock().expect("send gate");
        (
            state.open,
            state.closed,
            state.metadata_blocked,
            state.pending,
        )
    }

    #[cfg(test)]
    pub(crate) fn pending_for_test(&self) -> u64 {
        self.state.lock().unwrap().pending
    }

    pub fn kind(&self) -> GateKind {
        self.kind
    }

    /// Open and not closed for good.
    pub fn is_open(&self) -> bool {
        let st = self.state.lock().expect("send gate");
        Self::effective_open(&st)
    }

    /// Block until the gate opens (`true`) or closes for good (`false`).
    pub fn wait_open(&self) -> bool {
        let mut st = self.state.lock().expect("send gate");
        while (!st.open || st.metadata_blocked) && !st.closed {
            st = self.changed.wait(st).expect("send gate");
        }
        !st.closed
    }

    /// [`SendGate::wait_open`], at most `timeout`.
    pub fn wait_open_for(&self, timeout: Duration) -> GateWait {
        // A timeout past what an `Instant` can hold is no timeout at all.
        let Some(deadline) = Instant::now().checked_add(timeout) else {
            return if self.wait_open() {
                GateWait::Open
            } else {
                GateWait::Closed
            };
        };
        let mut st = self.state.lock().expect("send gate");
        loop {
            if st.closed {
                return GateWait::Closed;
            }
            if Self::effective_open(&st) {
                return GateWait::Open;
            }
            let now = Instant::now();
            if now >= deadline {
                return GateWait::TimedOut;
            }
            st = self
                .changed
                .wait_timeout(st, deadline - now)
                .expect("send gate")
                .0;
        }
    }

    /// A producer handed `n` bytes over; they count until the driver takes
    /// them ([`SendGate::transfer`]).
    pub fn admit(&self, n: u64) {
        let mut st = self.state.lock().expect("send gate");
        st.pending += n;
        self.recompute(&mut st);
    }

    /// Check and debit a client record under this one gate lock. The outer
    /// client command mutex orders this with its global reservation/publication.
    pub(crate) fn admit_client(&self, n: u64, bounded: bool) -> ClientAdmission {
        let mut st = self.state.lock().expect("send gate");
        if st.closed {
            return ClientAdmission::Closed;
        }
        // The hysteresis gate controls when to start a whole chunk, not its
        // size or remote credit. A chunk may cross the high mark; its exact
        // byte/entry bound was already reserved from the shared client budget.
        if bounded && !Self::effective_open(&st) {
            return ClientAdmission::Full;
        }
        st.pending += n;
        self.recompute(&mut st);
        ClientAdmission::Admitted
    }

    /// The driver took `n` admitted bytes into the connection, whose tail on
    /// this stream is now `tail`. In one step, so the gate never sees the
    /// bytes in neither place. Returns whether the gate just opened.
    pub fn transfer(&self, n: u64, tail: u64) -> bool {
        let mut st = self.state.lock().expect("send gate");
        st.pending = st.pending.saturating_sub(n);
        st.tail = tail;
        self.recompute(&mut st)
    }

    /// `n` admitted bytes will never reach the driver -- the hand-over
    /// failed: they stop counting.
    pub fn withdraw(&self, n: u64) {
        let mut st = self.state.lock().expect("send gate");
        st.pending = st.pending.saturating_sub(n);
        self.recompute(&mut st);
    }

    /// The stream's tail is now `tail`. Returns whether the gate just opened.
    pub fn update(&self, tail: u64) -> bool {
        let mut st = self.state.lock().expect("send gate");
        st.tail = tail;
        self.recompute(&mut st)
    }

    /// Open whatever the tail: the connection behind it is gone (parked) or
    /// brand new (an `Attach`). Returns whether it was shut.
    pub fn force_open(&self) -> bool {
        let mut st = self.state.lock().expect("send gate");
        st.tail = 0;
        let was_open = Self::effective_open(&st);
        st.open = true;
        self.notify_opened(&st, was_open)
    }

    /// Close for good and wake every waiter.
    pub fn close(&self) {
        let mut st = self.state.lock().expect("send gate");
        st.closed = true;
        self.changed.notify_all();
    }

    fn effective_open(st: &GateState) -> bool {
        st.open && !st.closed && !st.metadata_blocked
    }

    fn recompute_bytes(&self, st: &mut GateState) {
        let (high, low) = self.kind.marks();
        let load = st.tail.saturating_add(st.pending);
        if st.open && load >= high {
            st.open = false;
        } else if !st.open && load <= low {
            st.open = true;
        }
    }

    fn notify_opened(&self, st: &GateState, was_open: bool) -> bool {
        let opened = !was_open && Self::effective_open(st);
        if opened {
            self.changed.notify_all();
        }
        opened
    }

    fn recompute(&self, st: &mut GateState) -> bool {
        let was_open = Self::effective_open(st);
        self.recompute_bytes(st);
        self.notify_opened(st, was_open)
    }
}

#[derive(Debug, Default)]
struct TableState {
    gates: BTreeMap<u8, Arc<SendGate>>,
    closed: bool,
}

/// A session's gates, one per stream that asked for one. Made with the
/// session (daemon: `cold_create`; client: `StdClient::connect`) and kept
/// across warm reattaches.
#[derive(Debug, Default)]
pub struct GateTable {
    inner: Mutex<TableState>,
}

impl GateTable {
    pub fn new() -> GateTable {
        GateTable::default()
    }

    /// `stream`'s gate, made with `kind`'s marks on first use. A later call
    /// returns the same gate whatever kind it names. A table already closed
    /// hands out a gate that is closed too, and keeps nothing.
    pub fn gate(&self, stream: u8, kind: GateKind) -> Arc<SendGate> {
        let mut t = self.inner.lock().expect("gate table");
        if let Some(g) = t.gates.get(&stream) {
            return Arc::clone(g);
        }
        let g = Arc::new(SendGate::new(kind));
        if t.closed {
            g.close();
        } else {
            t.gates.insert(stream, Arc::clone(&g));
        }
        g
    }

    /// Forget `stream`'s gate and wake whoever waits on it.
    pub fn remove(&self, stream: u8) {
        let gate = self.inner.lock().expect("gate table").gates.remove(&stream);
        if let Some(g) = gate {
            g.close();
        }
    }

    /// Close every gate for good: the session or the driver is ending.
    pub fn close_all(&self) {
        let gates = {
            let mut t = self.inner.lock().expect("gate table");
            t.closed = true;
            std::mem::take(&mut t.gates)
        };
        for g in gates.into_values() {
            g.close();
        }
    }

    /// Whether [`GateTable::close_all`] has run: nothing behind these gates
    /// will ever send again.
    pub fn is_closed(&self) -> bool {
        self.inner.lock().expect("gate table").closed
    }

    /// A producer hands `n` bytes for `stream` over: they count on the
    /// stream's gate, if it has one, until [`GateTable::transfer`] -- the
    /// gate, so a hand-over that fails can [`SendGate::withdraw`] them. A
    /// stream without a gate gets none. The daemon's `SessionIo::send`: what
    /// waits in the queue to the bridge is part of the load the gate bounds
    /// (spec §4.7.2), as a client producer's bytes are (§4.7.3).
    pub fn admit(&self, stream: u8, n: u64) -> Option<Arc<SendGate>> {
        let gate = self
            .inner
            .lock()
            .expect("gate table")
            .gates
            .get(&stream)
            .cloned()?;
        gate.admit(n);
        Some(gate)
    }

    /// `n` bytes handed over for `stream` were taken -- into the connection,
    /// whose tail on it is now `tail`, or thrown away. Returns whether that
    /// opened a screen gate, as [`GateTable::refresh`] reports one. Bytes
    /// the gate never counted -- handed over before it was made, or for an
    /// earlier gate of a stream number used again -- may leave it counting
    /// less than waits, for a moment: never less than nothing, and exact
    /// again once none of its own bytes wait.
    pub fn transfer(&self, stream: u8, n: u64, tail: u64) -> bool {
        let gate = self
            .inner
            .lock()
            .expect("gate table")
            .gates
            .get(&stream)
            .cloned();
        gate.is_some_and(|g| g.transfer(n, tail) && g.kind().wants_writable())
    }

    /// Refresh every gate from its stream's tail. `tail_of` runs without the
    /// table locked. Returns the screen streams whose gate just opened: their
    /// producers want a `Writable`.
    pub fn refresh(&self, tail_of: impl Fn(u8) -> u64) -> Vec<u8> {
        let gates = self.snapshot();
        gates
            .into_iter()
            .filter(|(s, g)| g.update(tail_of(*s)) && g.kind().wants_writable())
            .map(|(s, _)| s)
            .collect()
    }

    /// Open every gate (see [`SendGate::force_open`]); the screen streams
    /// that were shut, as [`GateTable::refresh`] reports them.
    pub fn open_all(&self) -> Vec<u8> {
        let gates = self.snapshot();
        gates
            .into_iter()
            .filter(|(_, g)| g.force_open() && g.kind().wants_writable())
            .map(|(s, _)| s)
            .collect()
    }

    fn snapshot(&self) -> Vec<(u8, Arc<SendGate>)> {
        self.inner
            .lock()
            .expect("gate table")
            .gates
            .iter()
            .map(|(s, g)| (*s, Arc::clone(g)))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn metadata_release_wakes_idle_producer_but_keeps_pending_byte_hold() {
        let gate = Arc::new(SendGate::new(GateKind::Pipe));
        gate.admit(PIPE_HIGH);
        gate.set_metadata_blocked(true);
        assert!(!gate.set_metadata_blocked(false));
        assert!(!gate.is_open());
        gate.withdraw(PIPE_HIGH);
        assert!(gate.is_open());
        gate.set_metadata_blocked(true);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let other = gate.clone();
        let waiter = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            other.wait_open_for(Duration::from_secs(2))
        });
        ready_rx.recv().unwrap();
        assert!(gate.set_metadata_blocked(false));
        assert_eq!(waiter.join().unwrap(), GateWait::Open);
    }

    #[test]
    fn metadata_hold_does_not_open_pipe_early() {
        let g = SendGate::new(GateKind::Pipe);
        g.set_metadata_blocked(true);
        assert!(!g.is_open());
        assert_eq!(g.wait_open_for(Duration::ZERO), GateWait::TimedOut);
        g.update(PIPE_HIGH);
        g.set_metadata_blocked(false);
        assert!(
            !g.is_open(),
            "metadata release cannot bypass byte hysteresis"
        );
        g.update(PIPE_LOW + 1);
        assert!(!g.is_open());
        g.update(PIPE_LOW);
        assert!(g.is_open());
        g.set_metadata_blocked(true);
        assert!(
            !g.force_open(),
            "legacy force-open cannot remove a metadata hold"
        );
        assert!(!g.is_open());
        g.set_metadata_blocked(false);
        assert!(g.is_open());
        g.close();
        g.set_metadata_blocked(true);
        g.set_metadata_blocked(false);
        assert_eq!(g.wait_open_for(Duration::ZERO), GateWait::Closed);
    }

    #[test]
    fn a_screen_gate_closes_at_128_kib_and_opens_again_at_32_kib() {
        let g = SendGate::new(GateKind::Screen);
        assert!(g.is_open());
        assert!(!g.update(100 * 1024));
        assert!(g.is_open());
        assert!(!g.update(128 * 1024));
        assert!(!g.is_open(), "closed at the high mark");
        assert!(!g.update(64 * 1024));
        assert!(!g.is_open(), "hysteresis: still closed above the low mark");
        assert!(g.update(32 * 1024), "the transition to open is reported");
        assert!(g.is_open());
        assert!(!g.update(0), "already open: nothing to report");
    }

    /// Plan correction 4: bytes a producer handed over and the driver has not
    /// taken yet count, or a fast producer outruns the driver's next pass.
    #[test]
    fn bytes_admitted_but_not_yet_taken_count_against_the_pipe_gate() {
        let g = SendGate::new(GateKind::Pipe);
        for _ in 0..7 {
            g.admit(64 * 1024);
        }
        assert!(g.is_open());
        g.admit(64 * 1024);
        assert!(!g.is_open(), "512 KiB admitted");
        assert!(
            !g.transfer(64 * 1024, 64 * 1024),
            "moved from pending to tail: same load"
        );
        assert!(!g.is_open());
        // The driver takes the rest; the tail stays at 64 KiB (acknowledged
        // as fast as it came). The load falls 448, 384, 320, 256 KiB: the
        // gate opens at the fourth step, once, and stays open.
        let mut opened = 0;
        for _ in 0..7 {
            opened += usize::from(g.transfer(64 * 1024, 64 * 1024));
        }
        assert_eq!(opened, 1, "opened once, when the load fell to the low mark");
        assert!(g.is_open());
    }

    /// A hand-over that never reached the driver stops counting.
    #[test]
    fn a_withdrawn_hand_over_no_longer_counts() {
        let g = SendGate::new(GateKind::Pipe);
        g.admit(PIPE_HIGH);
        assert!(!g.is_open());
        g.withdraw(PIPE_HIGH);
        assert!(g.is_open());
    }

    /// Final review of slice 2, Minor 4: the daemon's backends hand bytes
    /// to the bridge over a queue the connection's tail does not see. The
    /// table counts them on the stream's own gate -- a stream without one
    /// gets none -- until the bridge takes them, and says when that opened a
    /// screen gate, as `refresh` does.
    #[test]
    fn the_table_counts_a_hand_over_on_the_streams_gate_until_it_is_taken() {
        let table = GateTable::new();
        assert!(
            table.admit(7, 1024 * 1024).is_none(),
            "no gate, nothing kept"
        );
        assert!(!table.transfer(7, 1024 * 1024, 0));
        assert!(table.snapshot().is_empty(), "and none made");

        let screen = table.gate(20, GateKind::Screen);
        let admitted = table.admit(20, SCREEN_HIGH).expect("the stream's gate");
        assert!(Arc::ptr_eq(&admitted, &screen));
        assert!(!screen.is_open(), "handed over, not yet taken: it counts");
        assert!(
            !table.transfer(20, SCREEN_HIGH, SCREEN_HIGH),
            "taken into a connection that holds it: the same load"
        );
        assert!(!screen.is_open());
        let _ = table.admit(20, SCREEN_LOW);
        assert!(
            table.transfer(20, SCREEN_LOW, 0),
            "taken where it is gone at once: the screen gate opened"
        );
        assert!(screen.is_open());

        let pipe = table.gate(21, GateKind::Pipe);
        let _ = table.admit(21, PIPE_HIGH);
        assert!(
            !table.transfer(21, PIPE_HIGH, 0),
            "a pipe gate wants no Writable"
        );
        assert!(pipe.is_open());
    }

    #[test]
    fn a_waiter_wakes_when_the_gate_opens() {
        let g = Arc::new(SendGate::new(GateKind::Pipe));
        let _ = g.update(PIPE_HIGH);
        let waiter = {
            let g = Arc::clone(&g);
            thread::spawn(move || g.wait_open())
        };
        thread::sleep(Duration::from_millis(50));
        assert!(!waiter.is_finished());
        assert!(g.update(0));
        assert!(
            waiter.join().expect("the waiter"),
            "woke with the gate open"
        );
    }

    /// A waiter with a timeout is woken by the opening itself, long before
    /// its timeout would have ended the wait.
    #[test]
    fn a_timed_waiter_wakes_when_the_gate_opens() {
        let g = Arc::new(SendGate::new(GateKind::Pipe));
        let _ = g.update(PIPE_HIGH);
        let waiter = {
            let g = Arc::clone(&g);
            thread::spawn(move || {
                let started = Instant::now();
                (g.wait_open_for(Duration::from_secs(30)), started.elapsed())
            })
        };
        thread::sleep(Duration::from_millis(50));
        assert!(!waiter.is_finished());
        assert!(g.update(PIPE_LOW));
        let (how, took) = waiter.join().expect("the waiter");
        assert_eq!(how, GateWait::Open);
        assert!(
            took < Duration::from_secs(10),
            "woken by the opening, not by the timeout: {took:?}"
        );
    }

    #[test]
    fn a_closed_gate_wakes_its_waiters_for_good() {
        let g = Arc::new(SendGate::new(GateKind::Pipe));
        let _ = g.update(PIPE_HIGH);
        let waiter = {
            let g = Arc::clone(&g);
            thread::spawn(move || g.wait_open())
        };
        thread::sleep(Duration::from_millis(50));
        g.close();
        assert!(
            !waiter.join().expect("the waiter"),
            "woke with the gate closed"
        );
        assert_eq!(g.wait_open_for(Duration::from_secs(1)), GateWait::Closed);
    }

    #[test]
    fn waiting_on_a_shut_gate_times_out() {
        let g = SendGate::new(GateKind::Pipe);
        let _ = g.update(PIPE_HIGH);
        let started = Instant::now();
        assert_eq!(
            g.wait_open_for(Duration::from_millis(100)),
            GateWait::TimedOut
        );
        assert!(started.elapsed() >= Duration::from_millis(100));
        let _ = g.update(0);
        assert_eq!(g.wait_open_for(Duration::ZERO), GateWait::Open);
    }

    /// A timeout no `Instant` can reach is a wait without one, not a panic.
    #[test]
    fn an_unreachable_timeout_waits_without_one() {
        let g = SendGate::new(GateKind::Pipe);
        assert_eq!(g.wait_open_for(Duration::MAX), GateWait::Open);
        g.close();
        assert_eq!(g.wait_open_for(Duration::MAX), GateWait::Closed);
    }

    #[test]
    fn the_table_reports_only_screen_gates_that_just_opened() {
        let table = GateTable::new();
        let screen = table.gate(20, GateKind::Screen);
        let pipe = table.gate(21, GateKind::Pipe);
        assert!(
            Arc::ptr_eq(&screen, &table.gate(20, GateKind::Pipe)),
            "one gate per stream"
        );
        assert!(table.refresh(|_| 1024 * 1024).is_empty());
        assert!(!screen.is_open() && !pipe.is_open());
        assert_eq!(table.refresh(|_| 0), vec![20]);
        assert!(screen.is_open() && pipe.is_open());
        let _ = table.refresh(|_| 1024 * 1024);
        assert_eq!(table.open_all(), vec![20]);
    }

    #[test]
    fn a_removed_gate_and_a_closed_table_wake_their_waiters() {
        let table = GateTable::new();
        let g = table.gate(20, GateKind::Pipe);
        table.remove(20);
        assert_eq!(g.wait_open_for(Duration::ZERO), GateWait::Closed);
        let h = table.gate(21, GateKind::Pipe);
        assert!(!table.is_closed());
        table.close_all();
        assert!(table.is_closed());
        assert_eq!(h.wait_open_for(Duration::ZERO), GateWait::Closed);
        assert_eq!(
            table.gate(22, GateKind::Pipe).wait_open_for(Duration::ZERO),
            GateWait::Closed,
            "a gate asked of a closed table is born closed"
        );
    }
}
