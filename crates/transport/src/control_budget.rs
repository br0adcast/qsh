//! Reservation ownership for control replies and daemon callback work.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};
use tokio::sync::{futures::Notified, Notify};

use crate::channel::{CHANNEL_IDENTITIES, CHANNEL_SNAPSHOT_MAX, MAX_CHANNELS};
use crate::channel_timeline::ORDINARY_ENTRIES;
use crate::session_manager::{MAX_SESSIONS_PER_OWNER, MAX_SESSIONS_TOTAL};
use crate::shell_frame::CONTROL_RECORD_MAX;

pub(crate) const MAX_RECORD: usize = CONTROL_RECORD_MAX + 5;
const MAX_SNAPSHOT: usize = CHANNEL_SNAPSHOT_MAX + 5;
const UPDATE_ENVELOPE: usize = 6 + 6 + MAX_RECORD;
// Derived maxima: 1,422,427 charged bytes/session, 182,070,656 globally,
// and 48,768 response entries. These logical/copy bounds are not RSS bounds.
// Generic response envelopes conservatively retain both queued source and
// simultaneous reliable copy allowance through ACK. Snapshot has three
// independent DTO/scratch/wire leases; terminal scratch has its timeline lease.
const COPY_WEIGHT: [usize; 6] = [2, 2, 2, 1, 2, 1];
pub(crate) const SESSION_BYTES: usize = 2
    * (MAX_RECORD + MAX_CHANNELS * MAX_RECORD + UPDATE_ENVELOPE + 5)
    + 3 * MAX_SNAPSHOT
    + CHANNEL_IDENTITIES * 10;
const GLOBAL_BYTES: usize = MAX_SESSIONS_TOTAL * SESSION_BYTES;
// Entry accounting also bounds tiny reply permits across retired owners;
// the byte envelope alone cannot bound their object/Arc/container overhead.
pub(crate) const GLOBAL_RESPONSE_ENTRIES: usize =
    MAX_SESSIONS_TOTAL * (ORDINARY_ENTRIES + MAX_CHANNELS + 1 + 3 + 1 + CHANNEL_IDENTITIES);
// Each About job additionally owns <=160 logical bytes of validated retained
// metadata + per-waiter clone (not arbitrary allocations inside the provider).
// This job cap includes retired sessions and remains held through result drop:
// <=40,960 additional bytes globally, or <=160 for one current session.
// Combined response/copy + About metadata: 182,111,616 globally, 1,422,587 for
// one current session. Struct/container and allocator overhead remain separate.
const GLOBAL_JOBS: usize = 2 * MAX_SESSIONS_TOTAL;
const PRINCIPAL_JOBS: usize = 2 * MAX_SESSIONS_PER_OWNER;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CapacityError {
    InvalidSize,
    Retired,
    Session,
    Principal,
    Global,
}

#[derive(Clone, Copy)]
pub(crate) enum Response {
    Ordinary(usize),
    Open,
    Update,
    Snapshot,
    Restart,
    Terminal,
}
impl Response {
    fn charge(self) -> (usize, usize) {
        match self {
            Self::Ordinary(n) => (0, n),
            Self::Open => (1, MAX_RECORD),
            Self::Update => (2, UPDATE_ENVELOPE),
            Self::Snapshot => (3, MAX_SNAPSHOT),
            Self::Restart => (4, 5),
            Self::Terminal => (5, 10),
        }
    }
}
#[derive(Clone, Copy)]
pub(crate) enum Job {
    About,
    Update,
}
impl Job {
    fn index(self) -> usize {
        match self {
            Self::About => 0,
            Self::Update => 1,
        }
    }
}

#[derive(Default)]
struct GlobalState {
    bytes: usize,
    response_entries: usize,
    jobs: usize,
    principals: BTreeMap<u32, usize>,
}
#[derive(Default, Clone)]
pub(crate) struct GlobalBudget(Arc<Mutex<GlobalState>>, Arc<Notify>);
#[derive(Default)]
struct SessionState {
    retired: bool,
    entries: [usize; 6],
    bytes: [usize; 6],
    jobs: [bool; 2],
}
#[derive(Clone)]
pub(crate) struct SessionBudget {
    global: GlobalBudget,
    state: Arc<Mutex<SessionState>>,
    uid: u32,
}
impl GlobalBudget {
    /// Register and enable this waiter before checking admission, then keep
    /// servicing the runner while waiting. Refunds wake all registered owners;
    /// there is no accumulated queue of capacity events.
    pub(crate) fn changed(&self) -> Notified<'_> {
        self.1.notified()
    }
    #[cfg(test)]
    pub(crate) fn retained_for_test(&self) -> (usize, usize, usize) {
        let state = self.0.lock().unwrap();
        (state.bytes, state.response_entries, state.jobs)
    }
    pub(crate) fn session(&self, uid: u32) -> SessionBudget {
        SessionBudget {
            global: self.clone(),
            state: Arc::new(Mutex::new(SessionState::default())),
            uid,
        }
    }
}
impl SessionBudget {
    #[cfg(any(test, feature = "testnet"))]
    pub(crate) fn qualification_retired(&self) -> bool {
        self.state.lock().map_or(true, |state| state.retired)
    }
    pub(crate) fn retire(&self) {
        self.state.lock().unwrap().retired = true;
    }
    pub(crate) fn reserve(&self, response: Response) -> Result<ResponsePermit, CapacityError> {
        self.reserve_batch([response]).map(|[permit]| permit)
    }

    /// Both future obligations exist before any factory effects. Rejection
    /// changes no counters and emits no provisional-refund wake.
    pub(crate) fn reserve_open(&self) -> Result<[ResponsePermit; 2], CapacityError> {
        self.reserve_batch([Response::Open, Response::Terminal])
    }

    /// Independent custody for source DTO, merged DTO, and owned wire bytes.
    pub(crate) fn reserve_snapshot(&self) -> Result<[ResponsePermit; 3], CapacityError> {
        self.reserve_batch([Response::Snapshot; 3])
    }

    fn reserve_batch<const N: usize>(
        &self,
        responses: [Response; N],
    ) -> Result<[ResponsePermit; N], CapacityError> {
        let charges = responses.map(Response::charge);
        let mut entries = [0usize; 6];
        let mut bytes = [0usize; 6];
        let mut total = 0usize;
        for &(class, amount) in &charges {
            if class == 0 && (amount == 0 || amount > MAX_RECORD) {
                return Err(CapacityError::InvalidSize);
            }
            let charged = amount
                .checked_mul(COPY_WEIGHT[class])
                .ok_or(CapacityError::InvalidSize)?;
            entries[class] += 1;
            bytes[class] = bytes[class]
                .checked_add(charged)
                .ok_or(CapacityError::InvalidSize)?;
            total = total
                .checked_add(charged)
                .ok_or(CapacityError::InvalidSize)?;
        }
        let mut global = self.global.0.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        if state.retired {
            return Err(CapacityError::Retired);
        }
        let entry_limits = [ORDINARY_ENTRIES, MAX_CHANNELS, 1, 3, 1, CHANNEL_IDENTITIES];
        let byte_limits = [
            2 * MAX_RECORD,
            2 * MAX_CHANNELS * MAX_RECORD,
            2 * UPDATE_ENVELOPE,
            3 * MAX_SNAPSHOT,
            2 * 5,
            CHANNEL_IDENTITIES * 10,
        ];
        for class in 0..entries.len() {
            if entries[class] > entry_limits[class].saturating_sub(state.entries[class])
                || bytes[class] > byte_limits[class].saturating_sub(state.bytes[class])
            {
                return Err(CapacityError::Session);
            }
        }
        if N > GLOBAL_RESPONSE_ENTRIES.saturating_sub(global.response_entries)
            || total > GLOBAL_BYTES.saturating_sub(global.bytes)
        {
            return Err(CapacityError::Global);
        }
        global.bytes += total;
        global.response_entries += N;
        for class in 0..entries.len() {
            state.entries[class] += entries[class];
            state.bytes[class] += bytes[class];
        }
        drop(state);
        drop(global);
        Ok(charges.map(|(class, bytes)| ResponsePermit {
            session: self.clone(),
            class,
            bytes,
        }))
    }
    pub(crate) fn job(&self, job: Job) -> Result<JobPermit, CapacityError> {
        let mut global = self.global.0.lock().unwrap();
        let mut state = self.state.lock().unwrap();
        if state.retired {
            return Err(CapacityError::Retired);
        }
        if state.jobs[job.index()] {
            return Err(CapacityError::Session);
        }
        if global.principals.get(&self.uid).copied().unwrap_or(0) >= PRINCIPAL_JOBS {
            return Err(CapacityError::Principal);
        }
        if global.jobs >= GLOBAL_JOBS {
            return Err(CapacityError::Global);
        }
        global.jobs += 1;
        *global.principals.entry(self.uid).or_default() += 1;
        state.jobs[job.index()] = true;
        Ok(JobPermit {
            session: self.clone(),
            class: job.index(),
        })
    }
}
#[must_use = "keep the permit with the reply until ACK or scoped teardown"]
pub(crate) struct ResponsePermit {
    session: SessionBudget,
    class: usize,
    bytes: usize,
}
/// One future obligation plus a fixed number of wire records share an envelope.
/// Neither owner nor record handles can be cloned by callers.
#[must_use = "retain the owner until no future outcome can be produced"]
pub(crate) struct ResponseOwner {
    permit: Arc<ResponsePermit>,
    records_left: usize,
    issued_bytes: usize,
}
#[must_use = "move the record lease through queued bytes to cumulative ACK"]
pub(crate) struct ResponsePart {
    // Linear custody keeps the reservation alive; callers never clone it.
    _permit: Arc<ResponsePermit>,
    bytes: usize,
}

impl ResponsePermit {
    /// Before issuing any record lease, refund conservative ordinary preflight
    /// bytes. Mandatory envelopes retain their future outcome allowance.
    pub(crate) fn shrink_ordinary(&mut self, bytes: usize) -> Result<(), CapacityError> {
        if self.class != 0 || bytes == 0 || bytes > self.bytes {
            return Err(CapacityError::InvalidSize);
        }
        let refund = (self.bytes - bytes) * COPY_WEIGHT[self.class];
        if refund == 0 {
            return Ok(());
        }
        let mut global = self.session.global.0.lock().unwrap();
        let mut state = self.session.state.lock().unwrap();
        global.bytes -= refund;
        state.bytes[self.class] -= refund;
        self.bytes = bytes;
        drop(state);
        drop(global);
        self.session.global.1.notify_waiters();
        Ok(())
    }
    pub(crate) fn into_owner(self) -> ResponseOwner {
        let records_left = match self.class {
            2 => 3, // Accept, Restarting, and a final failure.
            _ => 1,
        };
        ResponseOwner {
            permit: Arc::new(self),
            records_left,
            issued_bytes: 0,
        }
    }
}
impl ResponseOwner {
    pub(crate) fn take_record(&mut self, bytes: usize) -> Option<ResponsePart> {
        let total = self.issued_bytes.checked_add(bytes)?;
        if bytes == 0 || self.records_left == 0 || total > self.permit.bytes {
            return None;
        }
        self.records_left -= 1;
        self.issued_bytes = total;
        Some(ResponsePart {
            _permit: Arc::clone(&self.permit),
            bytes,
        })
    }
}
impl ResponsePart {
    pub(crate) fn encoded_bytes(&self) -> usize {
        self.bytes
    }
}

/// Delivery custody for one exact connection generation. Entries are bounded
/// by the finite record leases issued from the shared response-entry ceiling.
pub(crate) struct ControlLedger {
    generation: u64,
    last_end: u64,
    pending: VecDeque<(u64, ResponsePart)>,
}
impl ControlLedger {
    pub(crate) fn new(generation: u64, queued: u64) -> Self {
        Self {
            generation,
            last_end: queued,
            pending: VecDeque::new(),
        }
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Register only after the whole record has entered this connection.
    /// Failure returns custody to the caller rather than discarding an outcome.
    pub(crate) fn register(
        &mut self,
        generation: u64,
        start: u64,
        end: u64,
        part: ResponsePart,
    ) -> Result<(), ResponsePart> {
        if generation != self.generation
            || start < self.last_end
            || end.checked_sub(start) != Some(part.bytes as u64)
        {
            return Err(part);
        }
        self.last_end = end;
        self.pending.push_back((end, part));
        Ok(())
    }

    /// `offset` must come from the connection's validated cumulative ACK base,
    /// never from queued/sent byte counts or an unvalidated peer frame.
    pub(crate) fn acknowledge(&mut self, generation: u64, offset: u64) {
        if generation != self.generation {
            return;
        }
        while self.pending.front().is_some_and(|(end, _)| *end <= offset) {
            self.pending.pop_front();
        }
    }
}

impl Drop for ResponsePermit {
    fn drop(&mut self) {
        let mut global = self.session.global.0.lock().unwrap();
        let mut state = self.session.state.lock().unwrap();
        global.bytes -= self.bytes * COPY_WEIGHT[self.class];
        global.response_entries -= 1;
        state.entries[self.class] -= 1;
        state.bytes[self.class] -= self.bytes * COPY_WEIGHT[self.class];
        drop(state);
        drop(global);
        self.session.global.1.notify_waiters();
    }
}
/// Shared only by the finite job owner and registered callback/completion
/// leases. Receiver loss cannot refund running work; callback custody lasts
/// through actual blocking join and manager reaping. A chain owner also retains
/// capacity for its future callback phases.
#[must_use = "keep the permit in the supervisor until the actual worker joins"]
pub(crate) struct JobPermit {
    session: SessionBudget,
    class: usize,
}
impl Drop for JobPermit {
    fn drop(&mut self) {
        let mut global = self.session.global.0.lock().unwrap();
        let mut state = self.session.state.lock().unwrap();
        global.jobs -= 1;
        let count = global.principals.get_mut(&self.session.uid).unwrap();
        *count -= 1;
        if *count == 0 {
            global.principals.remove(&self.session.uid);
        }
        state.jobs[self.class] = false;
        drop(state);
        drop(global);
        self.session.global.1.notify_waiters();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("control_budget_wire_tests.rs");
    include!("control_budget_refund_tests.rs");
    include!("control_budget_open_tests.rs");
    include!("control_budget_copy_tests.rs");

    #[test]
    fn mandatory_envelopes_have_finite_nonclone_record_leases() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        for (response, records) in [
            (Response::Ordinary(6), vec![6]),
            (Response::Open, vec![6]),
            (Response::Terminal, vec![10]),
            (Response::Update, vec![6, 6, MAX_RECORD]),
            (Response::Snapshot, vec![MAX_SNAPSHOT]),
            (Response::Restart, vec![5]),
        ] {
            let mut owner = session.reserve(response).unwrap().into_owner();
            let parts: Vec<_> = records
                .into_iter()
                .map(|bytes| owner.take_record(bytes).unwrap())
                .collect();
            assert!(
                owner.take_record(1).is_none(),
                "an envelope cannot mint extra record handles"
            );
            drop((owner, parts));
        }
        assert_eq!(global.0.lock().unwrap().response_entries, 0);
    }

    #[test]
    fn mandatory_envelope_waits_for_future_obligation_and_last_retired_record() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let [decision, terminal] = session.reserve_open().unwrap();
        let mut decision = decision.into_owner();
        let mut terminal = terminal.into_owner();
        let opened = decision.take_record(6).unwrap();
        drop(decision);
        drop(opened);
        assert_eq!(global.retained_for_test(), (10, 1, 0));
        let terminal_record = terminal.take_record(10).unwrap();
        session.retire();
        drop((terminal, session));
        assert_eq!(global.retained_for_test(), (10, 1, 0));
        drop(terminal_record);
        assert_eq!(global.retained_for_test(), (0, 0, 0));
    }

    #[test]
    fn capacity_accounting_envelope_checks_total_encoded_bytes_before_issuing_record_custody() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let mut owner = session.reserve(Response::Update).unwrap().into_owner();
        let first = owner.take_record(UPDATE_ENVELOPE - 1).unwrap();
        assert!(
            owner.take_record(2).is_none(),
            "simultaneously retained records exceed envelope"
        );
        let last = owner.take_record(1).unwrap();
        drop((first, last, owner));
        let mut owner = session.reserve(Response::Open).unwrap().into_owner();
        assert!(owner.take_record(0).is_none());
        assert!(owner.take_record(MAX_RECORD + 1).is_none());
        assert!(owner.take_record(usize::MAX).is_none());
        let full = owner.take_record(MAX_RECORD).unwrap();
        drop((full, owner));
        let mut owner = session.reserve(Response::Update).unwrap().into_owner();
        let accept = owner.take_record(6).unwrap();
        let restarting = owner.take_record(6).unwrap();
        assert!(owner.take_record(MAX_RECORD + 1).is_none());
        let final_result = owner.take_record(MAX_RECORD).unwrap();
        drop((accept, restarting, final_result, owner));
        assert_eq!(global.0.lock().unwrap().bytes, 0);
        assert_eq!(global.0.lock().unwrap().response_entries, 0);
    }

    #[test]
    fn control_ledger_releases_only_whole_records_at_the_exact_cumulative_ack() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let mut ledger = ControlLedger::new(7, 0);
        for (bytes, end) in [(6, 6), (10, 16)] {
            let mut owner = session
                .reserve(Response::Ordinary(bytes))
                .unwrap()
                .into_owner();
            assert!(ledger
                .register(
                    7,
                    end - bytes as u64,
                    end,
                    owner.take_record(bytes).unwrap()
                )
                .is_ok());
        }
        session.retire();
        drop(session);
        ledger.acknowledge(6, 16);
        assert_eq!(global.0.lock().unwrap().bytes, 32, "stale generation ACK");
        ledger.acknowledge(7, 5);
        assert_eq!(global.0.lock().unwrap().bytes, 32, "partial record ACK");
        ledger.acknowledge(7, 6);
        assert_eq!(global.0.lock().unwrap().bytes, 20);
        assert_eq!(global.0.lock().unwrap().response_entries, 1);
        ledger.acknowledge(7, 6);
        ledger.acknowledge(7, 5);
        ledger.acknowledge(7, 15);
        assert_eq!(
            global.0.lock().unwrap().bytes,
            20,
            "duplicate/stale/partial ACK"
        );
        ledger.acknowledge(7, 16);
        assert_eq!(global.0.lock().unwrap().bytes, 0);
        assert_eq!(global.0.lock().unwrap().response_entries, 0);
    }

    #[test]
    fn control_ledger_rejects_foreign_or_reordered_registration_without_losing_custody() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let mut owner = session.reserve(Response::Ordinary(6)).unwrap().into_owner();
        let part = owner.take_record(6).unwrap();
        drop(owner);
        let mut ledger = ControlLedger::new(8, 10);
        let part = match ledger.register(7, 10, 16, part) {
            Err(part) => part,
            Ok(()) => panic!("foreign generation"),
        };
        let part = match ledger.register(8, 4, 10, part) {
            Err(part) => part,
            Ok(()) => panic!("nonadvancing end"),
        };
        assert_eq!(global.0.lock().unwrap().bytes, 12);
        assert!(ledger.register(8, 10, 16, part).is_ok());
        drop(ledger); // Exact connection teardown destroys its delivery representation.
        assert_eq!(global.0.lock().unwrap().bytes, 0);
    }

    #[test]
    fn control_ledger_ack_or_teardown_cannot_refund_a_future_terminal_obligation() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let mut owner = session.reserve(Response::Update).unwrap().into_owner();
        let mut ledger = ControlLedger::new(9, 0);
        assert!(ledger
            .register(9, 0, 6, owner.take_record(6).unwrap())
            .is_ok());
        ledger.acknowledge(9, 6);
        assert_eq!(global.0.lock().unwrap().bytes, 2 * UPDATE_ENVELOPE);
        assert!(ledger
            .register(9, 6, 16, owner.take_record(10).unwrap())
            .is_ok());
        session.retire();
        drop(ledger);
        assert_eq!(global.0.lock().unwrap().bytes, 2 * UPDATE_ENVELOPE);
        drop(owner);
        assert_eq!(global.0.lock().unwrap().bytes, 0);
    }

    fn full_session(session: &SessionBudget) -> Vec<ResponsePermit> {
        let mut permits = vec![session.reserve(Response::Ordinary(MAX_RECORD)).unwrap()];
        for _ in 0..MAX_CHANNELS {
            permits.push(session.reserve(Response::Open).unwrap());
        }
        permits.push(session.reserve(Response::Update).unwrap());
        for _ in 0..3 {
            permits.push(session.reserve(Response::Snapshot).unwrap());
        }
        permits.push(session.reserve(Response::Restart).unwrap());
        for _ in 0..CHANNEL_IDENTITIES {
            permits.push(session.reserve(Response::Terminal).unwrap());
        }
        permits
    }

    #[test]
    fn ordinary_bytes_and_entries_reject_independently_without_spending_mandatory_room() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let full = session.reserve(Response::Ordinary(MAX_RECORD)).unwrap();
        assert!(matches!(
            session.reserve(Response::Ordinary(1)),
            Err(CapacityError::Session)
        ));
        let open = session.reserve(Response::Open).unwrap();
        let update = session.reserve(Response::Update).unwrap();
        drop((full, open, update));
        let entries: Vec<_> = (0..ORDINARY_ENTRIES)
            .map(|_| session.reserve(Response::Ordinary(1)).unwrap())
            .collect();
        assert!(matches!(
            session.reserve(Response::Ordinary(1)),
            Err(CapacityError::Session)
        ));
        drop(entries);
        assert!(matches!(
            session.reserve(Response::Ordinary(0)),
            Err(CapacityError::InvalidSize)
        ));
        assert!(matches!(
            session.reserve(Response::Ordinary(usize::MAX)),
            Err(CapacityError::InvalidSize)
        ));
        assert_eq!(global.0.lock().unwrap().bytes, 0);
    }

    #[test]
    fn retired_owners_keep_global_debt_until_last_moved_permit_drops() {
        let global = GlobalBudget::default();
        let mut held = Vec::new();
        for uid in 0..MAX_SESSIONS_TOTAL as u32 {
            let session = global.session(uid);
            held.extend(full_session(&session));
            session.retire();
        }
        assert_eq!(global.0.lock().unwrap().bytes, GLOBAL_BYTES);
        let replacement = global.session(0);
        assert!(matches!(
            replacement.reserve(Response::Ordinary(1)),
            Err(CapacityError::Global)
        ));
        let last = held.pop().unwrap();
        drop(last);
        let moved = replacement.reserve(Response::Ordinary(5)).unwrap();
        drop(held);
        assert_eq!(global.0.lock().unwrap().bytes, 10);
        drop(moved);
        assert_eq!(global.0.lock().unwrap().bytes, 0);
    }

    #[test]
    fn open_update_and_snapshot_envelopes_are_finite_and_retirement_rejects_new_work() {
        let global = GlobalBudget::default();
        let session = global.session(1);
        let held = full_session(&session);
        for response in [
            Response::Open,
            Response::Update,
            Response::Snapshot,
            Response::Restart,
            Response::Terminal,
        ] {
            assert!(matches!(
                session.reserve(response),
                Err(CapacityError::Session)
            ));
        }
        session.retire();
        drop(held);
        assert!(matches!(
            session.reserve(Response::Open),
            Err(CapacityError::Retired)
        ));
        assert!(matches!(
            session.job(Job::About),
            Err(CapacityError::Retired)
        ));
        assert_eq!(global.0.lock().unwrap().bytes, 0);
    }

    #[test]
    fn callback_limits_include_retired_sessions_until_last_worker_permit_drops() {
        let global = GlobalBudget::default();
        let mut workers = Vec::new();
        for uid in 0..MAX_SESSIONS_TOTAL as u32 {
            let session = global.session(uid);
            workers.push(session.job(Job::About).unwrap());
            workers.push(session.job(Job::Update).unwrap());
            session.retire();
        }
        let replacement = global.session(999);
        assert!(matches!(
            replacement.job(Job::About),
            Err(CapacityError::Global)
        ));
        drop(workers.pop());
        let job = replacement.job(Job::About).unwrap();
        assert!(matches!(
            replacement.job(Job::About),
            Err(CapacityError::Session)
        ));
        drop(workers);
        assert_eq!(global.0.lock().unwrap().jobs, 1);
        drop(job);
        let state = global.0.lock().unwrap();
        assert_eq!(state.jobs, 0);
        assert!(state.principals.is_empty());
    }

    #[test]
    fn one_principal_cannot_spend_other_principals_callback_room() {
        let global = GlobalBudget::default();
        let mut held = Vec::new();
        for _ in 0..MAX_SESSIONS_PER_OWNER {
            let s = global.session(7);
            held.push(s.job(Job::About).unwrap());
            held.push(s.job(Job::Update).unwrap());
        }
        assert_eq!(held.len(), PRINCIPAL_JOBS);
        assert!(matches!(
            global.session(7).job(Job::About),
            Err(CapacityError::Principal)
        ));
        assert!(global.session(8).job(Job::About).is_ok());
        drop(held);
    }
    #[test]
    fn competing_sessions_cannot_exceed_the_shared_callback_ceiling() {
        let global = GlobalBudget::default();
        std::thread::scope(|scope| {
            let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(8);
            // Sender destruction releases each participant even on an early
            // assertion/timeout. No barrier can strand a participant on panic.
            let mut releases = Vec::new();
            let mut handles = Vec::new();
            for participant in 0..8 {
                let global = global.clone();
                let ready = ready_tx.clone();
                let (release, wait) = std::sync::mpsc::sync_channel::<()>(0);
                releases.push(release);
                handles.push(scope.spawn(move || {
                    let mut held = Vec::new();
                    for index in 0..32 {
                        let session = global.session(participant * 32 + index);
                        for kind in [Job::About, Job::Update] {
                            match session.job(kind) {
                                Ok(permit) => held.push(permit),
                                Err(CapacityError::Global) => {}
                                Err(other) => panic!("unexpected admission failure: {other:?}"),
                            }
                        }
                        session.retire();
                    }
                    let _ = ready.send(held.len());
                    let _ = wait.recv();
                    drop(held);
                }));
            }
            drop(ready_tx);
            let mut admitted = 0;
            for _ in 0..8 {
                admitted += ready_rx
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("every participant completed its admission attempts");
            }
            let observed = global.0.lock().unwrap().jobs;
            // Release and join participants before checking their outcome.
            drop(releases);
            for handle in handles {
                handle.join().unwrap();
            }
            assert_eq!(admitted, GLOBAL_JOBS);
            assert_eq!(observed, GLOBAL_JOBS);
            let state = global.0.lock().unwrap();
            assert_eq!(state.jobs, 0);
            assert!(state.principals.is_empty());
        });
    }
    #[test]
    fn retired_tiny_replies_cannot_exceed_the_global_entry_ceiling() {
        const EXPECTED_LIMIT: usize =
            MAX_SESSIONS_TOTAL * (ORDINARY_ENTRIES + MAX_CHANNELS + 1 + 3 + 1 + CHANNEL_IDENTITIES);
        let global = GlobalBudget::default();
        let mut held = Vec::new();
        for _ in 0..EXPECTED_LIMIT / ORDINARY_ENTRIES {
            let session = global.session(1);
            for _ in 0..ORDINARY_ENTRIES {
                // Six bytes is a complete OPENED reply. Byte capacity must
                // remain plentiful when entry/owner capacity runs out.
                held.push(session.reserve(Response::Ordinary(6)).unwrap());
            }
            session.retire();
        }
        assert_eq!(EXPECTED_LIMIT, 48_768);
        assert_eq!(GLOBAL_RESPONSE_ENTRIES, EXPECTED_LIMIT);
        assert_eq!(held.len(), EXPECTED_LIMIT);
        assert_eq!(global.0.lock().unwrap().response_entries, EXPECTED_LIMIT);
        assert!(global.0.lock().unwrap().bytes < GLOBAL_BYTES / 100);
        let replacement = global.session(1);
        let rejected = matches!(
            replacement.reserve(Response::Ordinary(6)),
            Err(CapacityError::Global)
        );
        // Drop everything before the RED assertion; this test has no workers.
        let last = held.pop().unwrap();
        drop(last);
        let moved = replacement.reserve(Response::Ordinary(6)).unwrap();
        let rejected_again = matches!(
            replacement.reserve(Response::Ordinary(6)),
            Err(CapacityError::Global)
        );
        drop(held);
        assert_eq!(global.0.lock().unwrap().bytes, 12);
        assert_eq!(global.0.lock().unwrap().response_entries, 1);
        drop(moved);
        assert_eq!(global.0.lock().unwrap().bytes, 0);
        assert_eq!(global.0.lock().unwrap().response_entries, 0);
        assert!(
            rejected,
            "retired owners exhausted entries while byte room remained"
        );
        assert!(
            rejected_again,
            "dropping one permit refunds exactly one global entry"
        );
    }
}
