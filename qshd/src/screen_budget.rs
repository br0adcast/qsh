//! Shared daemon admission for source-qualified terminal backing storage.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use terminal_size::TerminalSize;

/// Independent limits for retained backing slots, transient slots and models.
#[derive(Clone, Copy, Debug)]
pub struct BudgetLimits {
    pub global_cells: usize,
    pub owner_cells: usize,
    pub global_rows: usize,
    pub owner_rows: usize,
    pub global_models: usize,
    pub owner_models: usize,
}

impl Default for BudgetLimits {
    fn default() -> Self {
        Self {
            global_cells: 33_554_432,
            owner_cells: 8_388_608,
            global_rows: 8_388_608,
            owner_rows: 2_097_152,
            global_models: 64,
            owner_models: 16,
        }
    }
}

/// Requested Vec backing slots, independently charged in each dimension.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BackingSlots {
    pub cells: usize,
    pub rows: usize,
}

fn overflow() -> String {
    "terminal screen budget arithmetic overflow".to_string()
}
fn add(a: usize, b: usize) -> Result<usize, String> {
    a.checked_add(b).ok_or_else(overflow)
}
fn mul(a: usize, b: usize) -> Result<usize, String> {
    a.checked_mul(b).ok_or_else(overflow)
}

impl BackingSlots {
    fn plus(self, other: Self) -> Result<Self, String> {
        Ok(Self {
            cells: add(self.cells, other.cells)?,
            rows: add(self.rows, other.rows)?,
        })
    }
    fn delta(self, old: Self) -> Self {
        Self {
            cells: self
                .cells
                .checked_sub(old.cells)
                .expect("monotone cell charge"),
            rows: self
                .rows
                .checked_sub(old.rows)
                .expect("monotone row charge"),
        }
    }
}

/// Historical maxima, never current logical grid size or measured capacity.
///
/// Bounds qualify alacritty_terminal 0.26.0 and the qualified Rust releases' alloc/Vec
/// growth and collect implementation, using ordinary Global/System allocation.
/// See docs/terminal-resources.md; requalify storage behavior on upgrades; these are not RSS limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScreenEnvelope {
    max_cols: u16,
    max_rows: u16,
    grew_rows: bool,
}

impl ScreenEnvelope {
    fn new(size: TerminalSize) -> Self {
        Self {
            max_cols: size.cols(),
            max_rows: size.rows(),
            grew_rows: false,
        }
    }

    pub fn charge(self) -> Result<BackingSlots, String> {
        let w = usize::from(self.max_cols);
        let r = usize::from(self.max_rows);
        let k = if self.grew_rows { 1000 } else { 0 };
        let bmax = add(r, mul(add(mul(2, r)?, 1)?, w)?)?;
        Ok(BackingSlots {
            cells: mul(mul(8, w)?, add(r, k)?)?,
            rows: mul(4, add(add(bmax, r)?, k)?)?,
        })
    }

    /// Retained envelope and extra scratch for one resize. `old` is the
    /// actual current geometry: a grow after shrink can initialize caches
    /// even when neither historical maximum increases.
    pub fn prepare_charge(
        self,
        old: TerminalSize,
        new: TerminalSize,
    ) -> Result<(Self, BackingSlots), String> {
        let envelope = Self {
            max_cols: self.max_cols.max(new.cols()),
            max_rows: self.max_rows.max(new.rows()),
            grew_rows: self.grew_rows || new.rows() > old.rows(),
        };
        let mut scratch = BackingSlots::default();
        if old.rows() != new.rows() {
            scratch = envelope.charge()?;
        }
        if old.cols() != new.cols() {
            let w = usize::from(envelope.max_cols);
            let r = usize::from(envelope.max_rows);
            let b = if new.cols() < old.cols() {
                let positions = mul(add(mul(2, r)?, 1)?, w)?;
                let divisor = usize::from(new.cols()) - 1;
                add(r, add(positions, divisor - 1)? / divisor)?
            } else {
                r
            };
            scratch = scratch.plus(BackingSlots {
                cells: mul(mul(4, w)?, add(add(b, r)?, 1)?)?,
                rows: add(mul(4, b)?, mul(2, r)?)?,
            })?;
        }
        Ok((envelope, scratch))
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Usage {
    pub(crate) cells: usize,
    pub(crate) rows: usize,
    pub(crate) models: usize,
}

impl Usage {
    fn plus(self, slots: BackingSlots, models: usize) -> Result<Self, String> {
        Ok(Self {
            cells: add(self.cells, slots.cells)?,
            rows: add(self.rows, slots.rows)?,
            models: add(self.models, models)?,
        })
    }
    fn release(&mut self, slots: BackingSlots, models: usize) {
        self.cells = self
            .cells
            .checked_sub(slots.cells)
            .expect("owned cell reservation");
        self.rows = self
            .rows
            .checked_sub(slots.rows)
            .expect("owned row reservation");
        self.models = self
            .models
            .checked_sub(models)
            .expect("owned model reservation");
    }
}

#[derive(Default)]
struct State {
    global: Usage,
    owners: HashMap<u32, Usage>,
}

/// One pool for all sessions and authenticated uid aliases of a daemon.
/// No lock survives admission; resize tokens can cross PTY operations safely.
pub struct ScreenBudget {
    limits: BudgetLimits,
    state: Mutex<State>,
}

impl ScreenBudget {
    pub fn new(limits: BudgetLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(State::default()),
        }
    }

    fn acquire(&self, uid: u32, slots: BackingSlots, models: usize) -> Result<(), String> {
        let mut state = self.state.lock().expect("screen budget lock poisoned");
        let global = state.global.plus(slots, models)?;
        let owner = state
            .owners
            .get(&uid)
            .copied()
            .unwrap_or_default()
            .plus(slots, models)?;
        let l = self.limits;
        if global.cells > l.global_cells
            || global.rows > l.global_rows
            || global.models > l.global_models
        {
            return Err("global terminal screen budget exhausted".to_string());
        }
        if owner.cells > l.owner_cells || owner.rows > l.owner_rows || owner.models > l.owner_models
        {
            return Err("owner terminal screen budget exhausted".to_string());
        }
        state.global = global;
        state.owners.insert(uid, owner);
        Ok(())
    }

    fn release(&self, uid: u32, slots: BackingSlots, models: usize) {
        let mut state = self.state.lock().expect("screen budget lock poisoned");
        state.global.release(slots, models);
        let owner = state
            .owners
            .get_mut(&uid)
            .expect("reservation owner exists");
        owner.release(slots, models);
        if *owner == Usage::default() {
            state.owners.remove(&uid);
        }
    }

    pub fn reserve(self: &Arc<Self>, uid: u32, size: TerminalSize) -> Result<ScreenLease, String> {
        let envelope = ScreenEnvelope::new(size);
        let charge = envelope.charge()?;
        self.acquire(uid, charge, 1)?;
        Ok(ScreenLease {
            budget: Arc::clone(self),
            uid,
            envelope,
            current: size,
            charge,
        })
    }

    #[cfg(test)]
    pub(crate) fn used(&self) -> Usage {
        self.state.lock().unwrap().global
    }
}

/// Holds the retained charge and one model slot through reconnect until Drop.
pub struct ScreenLease {
    budget: Arc<ScreenBudget>,
    uid: u32,
    envelope: ScreenEnvelope,
    current: TerminalSize,
    charge: BackingSlots,
}

impl ScreenLease {
    pub fn prepare(&mut self, size: TerminalSize) -> Result<ResizeReservation<'_>, String> {
        let (envelope, scratch) = self.envelope.prepare_charge(self.current, size)?;
        let charge = envelope.charge()?;
        let pending = charge.delta(self.charge).plus(scratch)?;
        self.budget.acquire(self.uid, pending, 0)?;
        let budget = Arc::clone(&self.budget);
        let uid = self.uid;
        Ok(ResizeReservation {
            budget,
            uid,
            lease: self,
            envelope,
            size,
            charge,
            pending,
            scratch,
            committed: false,
        })
    }
}

impl Drop for ScreenLease {
    fn drop(&mut self) {
        self.budget.release(self.uid, self.charge, 1);
    }
}

/// Cancels provisional delta and scratch on Drop; commit releases only scratch.
/// Owns its pool Arc and provisional counters; never holds a mutex guard.
pub struct ResizeReservation<'a> {
    budget: Arc<ScreenBudget>,
    uid: u32,
    lease: &'a mut ScreenLease,
    envelope: ScreenEnvelope,
    size: TerminalSize,
    charge: BackingSlots,
    pending: BackingSlots,
    scratch: BackingSlots,
    committed: bool,
}

impl ResizeReservation<'_> {
    pub fn commit(mut self) {
        self.lease.envelope = self.envelope;
        self.lease.current = self.size;
        self.lease.charge = self.charge;
        self.budget.release(self.uid, self.scratch, 0);
        self.committed = true;
    }
}

impl Drop for ResizeReservation<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.budget.release(self.uid, self.pending, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use terminal_size::TerminalSize;

    fn size(cols: u16, rows: u16) -> TerminalSize {
        TerminalSize::new(cols, rows).unwrap()
    }

    fn limits(cells: usize, rows: usize, models: usize) -> BudgetLimits {
        BudgetLimits {
            global_cells: cells,
            owner_cells: cells,
            global_rows: rows,
            owner_rows: rows,
            global_models: models,
            owner_models: models,
        }
    }

    #[test]
    fn screen_budget_source_qualified_width_and_mixed_scratch_formulas() {
        let envelope = ScreenEnvelope {
            max_cols: 80,
            max_rows: 25,
            grew_rows: true,
        };
        assert_eq!(
            envelope.charge().unwrap(),
            BackingSlots {
                cells: 656000,
                rows: 20520
            }
        );
        let (same, scratch) = envelope.prepare_charge(size(80, 25), size(79, 25)).unwrap();
        assert_eq!(same, envelope);
        assert_eq!(
            scratch,
            BackingSlots {
                cells: 33280,
                rows: 362
            }
        );
        let (_, scratch) = envelope.prepare_charge(size(80, 25), size(2, 25)).unwrap();
        assert_eq!(
            scratch,
            BackingSlots {
                cells: 1321920,
                rows: 16470
            }
        );
        let (_, mixed) = envelope.prepare_charge(size(80, 25), size(79, 24)).unwrap();
        assert_eq!(
            mixed,
            envelope
                .charge()
                .unwrap()
                .plus(BackingSlots {
                    cells: 33280,
                    rows: 362
                })
                .unwrap()
        );
        let (_, growth) = envelope.prepare_charge(size(2, 25), size(80, 25)).unwrap();
        assert_eq!(
            growth,
            BackingSlots {
                cells: 16320,
                rows: 150
            }
        );
    }

    #[test]
    fn screen_budget_width_high_water_and_cache_use_survive_every_shrink() {
        let budget = Arc::new(ScreenBudget::new(BudgetLimits::default()));
        let mut lease = budget.reserve(1, size(4, 2)).unwrap();
        lease.prepare(size(2, 1)).unwrap().commit();
        // Height growth from current1 to2 initializes the cache even though
        // the historical maximum remains2.
        lease.prepare(size(2, 2)).unwrap().commit();
        let used = budget.used();
        assert_eq!(
            used,
            Usage {
                cells: 32064,
                rows: 4096,
                models: 1
            }
        );
        for _ in 0..3 {
            lease.prepare(size(4, 1)).unwrap().commit();
            lease.prepare(size(2, 2)).unwrap().commit();
            assert_eq!(budget.used(), used);
        }
    }

    #[test]
    fn screen_budget_concurrent_admissions_are_atomic() {
        let budget = Arc::new(ScreenBudget::new(limits(32, 64, 2)));
        let start = Arc::new(std::sync::Barrier::new(8));
        let finish = Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|uid| {
                let budget = budget.clone();
                let start = start.clone();
                let finish = finish.clone();
                std::thread::spawn(move || {
                    start.wait();
                    let lease = budget.reserve(uid, size(2, 1));
                    finish.wait();
                    lease.is_ok()
                })
            })
            .collect();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| usize::from(t.join().unwrap()))
                .sum::<usize>(),
            2
        );
        assert_eq!(budget.used(), Usage::default());
    }

    #[test]
    fn screen_budget_owner_and_global_are_one_atomic_admission() {
        // 2x1 retains 16 cell slots and 32 row slots per model.
        let budget = Arc::new(ScreenBudget::new(BudgetLimits {
            owner_cells: 32,
            global_cells: 48,
            owner_rows: 64,
            global_rows: 96,
            owner_models: 8,
            global_models: 8,
        }));
        let a = budget.reserve(1, size(2, 1)).unwrap();
        let b = budget.reserve(1, size(2, 1)).unwrap();
        assert!(budget.reserve(1, size(2, 1)).is_err());
        let c = budget.reserve(2, size(2, 1)).unwrap();
        assert!(budget.reserve(3, size(2, 1)).is_err());
        drop((a, b, c));
        assert_eq!(budget.used(), Usage::default());
        assert!(budget.reserve(1, size(2, 1)).is_ok());
    }

    #[test]
    fn screen_budget_same_size_at_full_capacity_needs_no_scratch() {
        let budget = Arc::new(ScreenBudget::new(limits(16, 32, 1)));
        let mut lease = budget.reserve(1, size(2, 1)).unwrap();
        lease.prepare(size(2, 1)).unwrap().commit();
        assert_eq!(
            budget.used(),
            Usage {
                cells: 16,
                rows: 32,
                models: 1
            }
        );
    }

    #[test]
    fn screen_budget_cancel_and_commit_keep_distinct_retained_and_scratch() {
        let budget = Arc::new(ScreenBudget::new(BudgetLimits::default()));
        let mut lease = budget.reserve(1, size(2, 1)).unwrap();
        let old = budget.used();
        {
            let pending = lease.prepare(size(2, 2)).unwrap();
            assert_eq!(
                budget.used(),
                Usage {
                    cells: 32064,
                    rows: 8112,
                    models: 1
                }
            );
            drop(pending);
        }
        assert_eq!(budget.used(), old);
        lease.prepare(size(2, 2)).unwrap().commit();
        let retained = Usage {
            cells: 16032,
            rows: 4056,
            models: 1,
        };
        assert_eq!(budget.used(), retained);
        lease.prepare(size(2, 1)).unwrap().commit();
        assert_eq!(budget.used(), retained);
        lease.prepare(size(2, 2)).unwrap().commit();
        assert_eq!(budget.used(), retained);
        drop(lease);
        assert_eq!(budget.used(), Usage::default());
    }

    #[test]
    fn screen_budget_each_independent_dimension_can_refuse_without_leaking() {
        for cap in [
            limits(15, usize::MAX, 8),
            limits(usize::MAX, 31, 8),
            limits(usize::MAX, usize::MAX, 0),
        ] {
            let budget = Arc::new(ScreenBudget::new(cap));
            assert!(budget.reserve(1, size(2, 1)).is_err());
            assert_eq!(budget.used(), Usage::default());
        }
        let budget = Arc::new(ScreenBudget::new(limits(16032, 4056, 1)));
        let mut lease = budget.reserve(1, size(2, 1)).unwrap();
        assert!(
            lease.prepare(size(2, 2)).is_err(),
            "retained fits but scratch does not"
        );
        assert_eq!(
            budget.used(),
            Usage {
                cells: 16,
                rows: 32,
                models: 1
            }
        );
    }

    #[test]
    fn screen_budget_model_slots_are_shared_and_held_until_drop() {
        let budget = Arc::new(ScreenBudget::new(BudgetLimits {
            global_models: 3,
            owner_models: 2,
            ..BudgetLimits::default()
        }));
        let retained = budget.reserve(1, size(2, 1)).unwrap();
        let b = budget.reserve(1, size(2, 2)).unwrap();
        assert!(budget.reserve(1, size(2, 1)).is_err());
        let c = budget.reserve(2, size(2, 1)).unwrap();
        assert!(budget.reserve(3, size(2, 1)).is_err());
        drop((b, c));
        assert_eq!(budget.used().models, 1, "retained reconnect owns its lease");
        drop(retained);
        assert_eq!(budget.used(), Usage::default());
    }

    #[test]
    fn screen_budget_repeated_grow_shrink_never_recovers_retained_credits() {
        let budget = Arc::new(ScreenBudget::new(BudgetLimits::default()));
        let mut a = budget.reserve(1, size(2, 1)).unwrap();
        let mut b = budget.reserve(1, size(2, 1)).unwrap();
        for lease in [&mut a, &mut b] {
            for _ in 0..3 {
                lease.prepare(size(2, 2)).unwrap().commit();
                lease.prepare(size(2, 1)).unwrap().commit();
            }
        }
        assert_eq!(
            budget.used(),
            Usage {
                cells: 32064,
                rows: 8112,
                models: 2
            }
        );
        drop((a, b));
        assert_eq!(budget.used(), Usage::default());
    }

    #[test]
    fn screen_budget_eight_ordinary_screens_and_growth_fit_defaults() {
        let budget = Arc::new(ScreenBudget::new(BudgetLimits::default()));
        let mut leases: Vec<_> = (0..8)
            .map(|_| budget.reserve(1, size(80, 24)).unwrap())
            .collect();
        assert_eq!(
            budget.used(),
            Usage {
                cells: 122880,
                rows: 126976,
                models: 8
            }
        );
        for lease in &mut leases {
            lease.prepare(size(80, 25)).unwrap().commit();
        }
        assert_eq!(
            budget.used(),
            Usage {
                cells: 5248000,
                rows: 164160,
                models: 8
            }
        );
        leases[0].prepare(size(2, 25)).unwrap().commit();
        assert_eq!(
            budget.used(),
            Usage {
                cells: 5248000,
                rows: 164160,
                models: 8
            }
        );
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use std::io::{self, Read};
    use std::sync::mpsc;
    use transport::auth::Principal;
    use transport::channel::{
        decode_server, encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord,
        CONTROL_STREAM,
    };
    use transport::channel_server::{
        run_channel_session, ChannelSpawner, ChannelWait, SpawnedChannel,
    };
    use transport::session_manager::{
        LoginId, SessionInbound, SessionIo, SessionOutbound, StreamData,
    };
    use transport::shell_frame::RecordDeframer;
    use transport::shell_server::ResizeHandle;

    type Feed = Arc<Mutex<Option<mpsc::Sender<bool>>>>;
    struct Reader(mpsc::Receiver<bool>);
    impl Read for Reader {
        fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
            if self.0.recv().unwrap_or(false) {
                Err(io::Error::other("reader failed"))
            } else {
                Ok(0)
            }
        }
    }
    struct Wait(Feed);
    impl ChannelWait for Wait {
        fn kill(&mut self) {
            self.0.lock().unwrap().take();
        }
        fn wait(self: Box<Self>) -> i32 {
            self.0.lock().unwrap().take();
            0
        }
    }
    struct Resize;
    impl ResizeHandle for Resize {
        fn try_resize(&self, _cols: u16, _rows: u16) -> Result<(), String> {
            Ok(())
        }
    }
    struct Spawner {
        budget: Arc<ScreenBudget>,
        feed: Feed,
    }
    impl ChannelSpawner for Spawner {
        fn spawn(
            &self,
            owner: &Principal,
            _login: LoginId,
            req: &OpenRequest,
            _term: Option<&str>,
        ) -> Result<SpawnedChannel, String> {
            let screen = crate::channel_backend::make_screen(req, owner, self.budget.clone())?;
            let (tx, rx) = mpsc::channel();
            *self.feed.lock().unwrap() = Some(tx);
            Ok(SpawnedChannel {
                reader: Box::new(Reader(rx)),
                writer: Box::new(io::sink()),
                resize: Box::new(Resize),
                screen,
                wait: Box::new(Wait(self.feed.clone())),
            })
        }
    }
    fn owner(uid: u32, name: &str) -> Principal {
        Principal {
            uid,
            name: name.into(),
            identity: name.into(),
            incarnation: 0,
        }
    }
    fn control(record: ClientRecord) -> SessionInbound {
        SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: encode_client(&record),
        })
    }
    fn open() -> SessionInbound {
        control(ClientRecord::Open(OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 2,
            rows: 1,
            screen: true,
            command: vec![],
        }))
    }
    async fn next(rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>) -> ServerRecord {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut records = RecordDeframer::for_control();
            loop {
                if let Some(SessionOutbound::Data(data)) = rx.recv().await {
                    if data.stream_id == CONTROL_STREAM {
                        if let Some(raw) = records.push(&data.data).first() {
                            return decode_server(raw).unwrap();
                        }
                    }
                }
            }
        })
        .await
        .expect("control reply before deadline")
    }
    async fn zero(budget: &ScreenBudget) {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while budget.used() != Usage::default() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all resources released");
    }

    #[tokio::test]
    async fn screen_budget_sessions_retain_on_reconnect_and_release_on_teardown() {
        let budget = Arc::new(ScreenBudget::new(BudgetLimits {
            global_models: 2,
            owner_models: 1,
            ..BudgetLimits::default()
        }));
        let mut sessions = Vec::new();
        for (uid, name, accepted) in [
            (1, "first", true),
            (1, "alias", false),
            (2, "other", true),
            (3, "global", false),
        ] {
            let (io, tx, mut rx) = SessionIo::test_pair_for(owner(uid, name), [uid as u8; 16]);
            let spawner = Arc::new(Spawner {
                budget: budget.clone(),
                feed: Arc::new(Mutex::new(None)),
            });
            let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
            tx.send(open()).await.unwrap();
            let reply = next(&mut rx).await;
            assert_eq!(
                matches!(reply, ServerRecord::Opened { .. }),
                accepted,
                "{name}: {reply:?}"
            );
            sessions.push((tx, rx, runner, spawner));
        }
        assert_eq!(
            budget.used(),
            Usage {
                cells: 32,
                rows: 64,
                models: 2
            }
        );
        sessions[0]
            .0
            .send(SessionInbound::ResumeReset)
            .await
            .unwrap();
        assert!(
            matches!(next(&mut sessions[0].1).await,ServerRecord::Channels(ref c) if c.len()==1)
        );
        assert_eq!(
            budget.used().models,
            2,
            "warm reconnect holds the same leases"
        );
        // The manager evicts/GCs a backend by dropping its inbound sender.
        // Reader tasks end through ChannelWait::kill when the runner tears down.
        for (tx, _rx, runner, _spawner) in sessions {
            drop(tx);
            runner.await.unwrap();
        }
        zero(&budget).await;
    }

    #[tokio::test]
    async fn screen_budget_close_exit_and_reader_failure_return_leases() {
        for outcome in ["close", "exit", "reader failure"] {
            let budget = Arc::new(ScreenBudget::new(BudgetLimits::default()));
            let (io, tx, mut rx) = SessionIo::test_pair_for(owner(1, "owner"), [0; 16]);
            let spawner = Arc::new(Spawner {
                budget: budget.clone(),
                feed: Arc::new(Mutex::new(None)),
            });
            let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
            tx.send(open()).await.unwrap();
            assert_eq!(next(&mut rx).await, ServerRecord::Opened { stream: 16 });
            assert_eq!(budget.used().models, 1);
            if outcome == "close" {
                tx.send(control(ClientRecord::Close { stream: 16 }))
                    .await
                    .unwrap();
            } else {
                spawner
                    .feed
                    .lock()
                    .unwrap()
                    .as_ref()
                    .unwrap()
                    .send(outcome == "reader failure")
                    .unwrap();
                // Exit is withheld until the transport acknowledges final
                // output delivery. The lease must already be gone before that.
                zero(&budget).await;
            }
            zero(&budget).await;
            drop(tx);
            runner.await.unwrap();
        }
    }
}

#[cfg(test)]
mod allocation_bounds;
