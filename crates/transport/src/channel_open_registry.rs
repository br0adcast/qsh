//! Factory-owned custody registrations. This owner survives individual runners.

use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[path = "channel_open_executor.rs"]
mod executor;
pub use executor::*;

use crate::auth::Principal;
use crate::channel::OpenRequest;
use crate::channel_geometry::ChannelInstance;
use crate::channel_server::reaping::{Capsule as ReapCapsule, ObservationFailure};
use crate::session_manager::LoginId;

#[derive(Debug, Clone, Copy)]
pub struct OpenLimits {
    pub global: usize,
    pub per_uid: usize,
}
impl Default for OpenLimits {
    fn default() -> Self {
        Self {
            global: 32,
            per_uid: 8,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionOpenId(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct OpenJobId(u64);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpenIdentity {
    pub session: SessionOpenId,
    pub instance: ChannelInstance,
    pub stream: u8,
    pub generation: u64,
    pub invalidation_epoch: u64,
}
pub struct OpenRequestSnapshot {
    pub owner: Principal,
    pub login: LoginId,
    pub request: OpenRequest,
    pub term: Option<String>,
    pub identity: OpenIdentity,
}

pub struct SessionOpenLedger {
    id: SessionOpenId,
    occupied: AtomicUsize,
    registry: Weak<ChannelOpenRegistry>,
    ready: Arc<tokio::sync::Notify>,
}
impl SessionOpenLedger {
    pub async fn notified(&self) {
        self.ready.notified().await;
    }
    pub fn id(&self) -> SessionOpenId {
        self.id
    }
    pub fn occupied(&self) -> usize {
        self.occupied.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRefusal {
    Restarting,
    Capacity,
    InvalidIdentity,
    Exhausted,
}

struct Registration {
    request: OpenRequestSnapshot,
    session: Arc<SessionOpenLedger>,
    custody: OpenCustody,
    submitted: AtomicBool,
    outcome: Mutex<Option<OpenOutcome>>,
    worker: Mutex<Option<tokio::task::JoinHandle<()>>>,
}
struct Retiring {
    owner: Arc<ReapCapsule>,
    uid: u32,
}
struct RegistryState {
    observations: [usize; 3],
    invalid_projection: bool,
    retiring: HashMap<usize, Retiring>,
    jobs: HashMap<OpenJobId, Arc<Registration>>,
    uids: HashMap<u32, usize>,
    next_job: u64,
    next_session: u64,
    next_fence: u64,
    fence: Option<u64>,
}
/// Read-only registered personal-channel custody, not global process cleanup.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CleanupSnapshot {
    pub healthy_pending_opens: usize,
    pub canceled_opens: usize,
    pub retiring_channels: usize,
    pub observed_unconfirmed_owners: usize,
    pub unique_cleanup_debt: usize,
    pub leader_unconfirmed: bool,
    pub cleanup_unconfirmed: bool,
    pub observation_panicked: bool,
}
impl CleanupSnapshot {
    pub fn has_cleanup_debt(&self) -> bool {
        self.unique_cleanup_debt != 0
    }
}

pub struct ChannelOpenRegistry {
    state: Mutex<RegistryState>,
    limits: OpenLimits,
    changed: Condvar,
}

pub struct OpenJob {
    id: OpenJobId,
    registration: Arc<Registration>,
    registry: Arc<ChannelOpenRegistry>,
}
impl OpenJob {
    pub fn cancel(&self) {
        self.registration.custody.cancel();
    }
    pub fn take_outcome(&self) -> Option<OpenOutcome> {
        self.registration.outcome.lock().ok()?.take()
    }
    pub fn take_worker(&self) -> Option<tokio::task::JoinHandle<()>> {
        self.registration
            .worker
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
    }
    pub fn id(&self) -> OpenJobId {
        self.id
    }
    pub fn custody(&self) -> &OpenCustody {
        &self.registration.custody
    }
    pub fn request(&self) -> &OpenRequestSnapshot {
        &self.registration.request
    }
    pub fn cleanup(&self) -> CleanupStatus {
        self.registry.cleanup(self.id)
    }
    #[cfg(any(test, feature = "testnet"))]
    pub fn adopt(
        self,
        channel: UninstalledChannel,
    ) -> Result<(SpawnedChannel, InstalledSlot), UninstalledChannel> {
        let Ok(mut state) = self.registry.state.lock() else {
            return Err(channel);
        };
        if state.fence.is_some()
            || !state.jobs.contains_key(&self.id)
            || !Arc::ptr_eq(&channel.custody.inner, &self.registration.custody.inner)
        {
            return Err(channel);
        }
        let spawned = channel.adopt()?;
        let removed = state.jobs.remove(&self.id).expect("registered adoption");
        release_uid(&mut state, removed.request.owner.uid);
        let slot = InstalledSlot {
            session: removed.session.clone(),
            uid: removed.request.owner.uid,
        };
        drop(state);
        drop(removed);
        Ok((spawned, slot))
    }
}
/// Preparation capability; ownership remains in the registered capsule until commit.
pub(crate) struct AdoptedOpen {
    job: OpenJob,
    channel: UninstalledChannel,
}
impl OpenJob {
    pub(crate) fn try_adopt(self, channel: UninstalledChannel) -> Option<AdoptedOpen> {
        {
            let state = self.registry.state.lock().ok()?;
            if state.fence.is_some()
                || !state
                    .jobs
                    .get(&self.id)
                    .is_some_and(|entry| Arc::ptr_eq(entry, &self.registration))
                || !Arc::ptr_eq(&channel.custody.inner, &self.registration.custody.inner)
                || channel.custody.is_cancelled()
            {
                return None;
            }
        }
        Some(AdoptedOpen { job: self, channel })
    }
}
impl AdoptedOpen {
    pub(crate) fn commit(
        self,
        epoch: &IdleEpochGuard<'_>,
        expected: &OpenIdentity,
        installation: crate::channel_server::PreparedInstallation<'_>,
    ) -> Option<crate::channel_server::InstalledBridges> {
        let mut state = self.job.registry.state.lock().ok()?;
        let registered = state.jobs.get(&self.job.id)?;
        if state.fence.is_some()
            || !Arc::ptr_eq(registered, &self.job.registration)
            || registered.request.identity != *expected
            || expected.invalidation_epoch != epoch.epoch()
            || !installation.matches(expected)
            || !Arc::ptr_eq(&self.channel.custody.inner, &registered.custody.inner)
        {
            return None;
        }
        // The watch read guard remains held by the caller. Registry -> capsule
        // serializes this complete move with fence cancellation and proof cleanup.
        let spawned = self.channel.adopt().ok()?;
        let slot = InstalledSlot {
            session: registered.session.clone(),
            uid: registered.request.owner.uid,
        };
        let bridges = installation.commit(spawned, slot);
        let removed = state.jobs.remove(&self.job.id);
        release_uid(&mut state, self.job.registration.request.owner.uid);
        drop(state);
        drop(removed);
        Some(bridges)
    }
}

impl Drop for OpenJob {
    fn drop(&mut self) {
        self.registration.custody.cancel();
    }
}

pub struct InstalledSlot {
    session: Arc<SessionOpenLedger>,
    uid: u32,
}
impl InstalledSlot {
    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }
    pub(crate) fn belongs_to(&self, registry: &Arc<ChannelOpenRegistry>) -> bool {
        Weak::ptr_eq(&self.session.registry, &Arc::downgrade(registry))
    }
}
impl Drop for InstalledSlot {
    fn drop(&mut self) {
        self.session.occupied.fetch_sub(1, Ordering::SeqCst);
        self.session.ready.notify_one();
    }
}

fn release_uid(state: &mut RegistryState, uid: u32) {
    if let Some(count) = state.uids.get_mut(&uid) {
        *count -= 1;
        if *count == 0 {
            state.uids.remove(&uid);
        }
    }
}

impl ChannelOpenRegistry {
    pub fn new(limits: OpenLimits) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(RegistryState {
                observations: [0; 3],
                invalid_projection: false,
                jobs: HashMap::new(),
                retiring: HashMap::new(),
                uids: HashMap::new(),
                next_job: 1,
                next_session: 1,
                next_fence: 1,
                fence: None,
            }),
            limits,
            changed: Condvar::new(),
        })
    }
    pub fn session(self: &Arc<Self>) -> Result<Arc<SessionOpenLedger>, OpenRefusal> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OpenRefusal::InvalidIdentity)?;
        let id = SessionOpenId(state.next_session);
        state.next_session = state
            .next_session
            .checked_add(1)
            .ok_or(OpenRefusal::Exhausted)?;
        Ok(Arc::new(SessionOpenLedger {
            id,
            occupied: AtomicUsize::new(0),
            registry: Arc::downgrade(self),
            ready: Arc::new(tokio::sync::Notify::new()),
        }))
    }
    pub fn try_reserve(
        self: &Arc<Self>,
        session: &Arc<SessionOpenLedger>,
        request: OpenRequestSnapshot,
    ) -> Result<OpenJob, OpenRefusal> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OpenRefusal::InvalidIdentity)?;
        if state.fence.is_some() {
            return Err(OpenRefusal::Restarting);
        }
        if request.identity.stream != request.request.stream
            || !Weak::ptr_eq(&session.registry, &Arc::downgrade(self))
            || request.identity.session != session.id
        {
            return Err(OpenRefusal::InvalidIdentity);
        }
        let uid = request.owner.uid;
        if state.jobs.len() + state.retiring.len() >= self.limits.global
            || state.uids.get(&uid).copied().unwrap_or(0) >= self.limits.per_uid
            || session.occupied() >= crate::channel::MAX_CHANNELS
        {
            return Err(OpenRefusal::Capacity);
        }
        let id = OpenJobId(state.next_job);
        state.next_job = state
            .next_job
            .checked_add(1)
            .ok_or(OpenRefusal::Exhausted)?;
        let registration = Arc::new(Registration {
            request,
            session: session.clone(),
            custody: OpenCustody::new(),
            submitted: AtomicBool::new(false),
            outcome: Mutex::new(None),
            worker: Mutex::new(None),
        });
        registration.custody.bind_registration(self, id);
        state.jobs.insert(id, registration.clone());
        *state.uids.entry(uid).or_default() += 1;
        session.occupied.fetch_add(1, Ordering::SeqCst);
        Ok(OpenJob {
            id,
            registration,
            registry: self.clone(),
        })
    }
    /// A blocking metadata read for update preparation. Never invokes cleanup.
    pub fn cleanup_snapshot(&self) -> Option<CleanupSnapshot> {
        self.snapshot(false)
    }
    /// STATUS abandons the whole observation on contention or inconsistency.
    pub fn try_cleanup_snapshot(&self) -> Option<CleanupSnapshot> {
        self.snapshot(true)
    }
    fn snapshot(&self, nonblocking: bool) -> Option<CleanupSnapshot> {
        let state = metadata_lock(&self.state, nonblocking)?;
        if state.invalid_projection {
            return None;
        }
        let mut result = CleanupSnapshot::default();
        for entry in state.jobs.values() {
            if entry.custody.canceled_snapshot(nonblocking)? {
                result.canceled_opens = result.canceled_opens.checked_add(1)?;
            } else {
                result.healthy_pending_opens = result.healthy_pending_opens.checked_add(1)?;
            }
        }
        let mut overlap = [0usize; 3];
        for entry in state.retiring.values() {
            if !entry.owner.belongs_to(self) {
                return None;
            }
            if let Some(kind) = entry.owner.observation_state(nonblocking)?.observation {
                overlap[kind.index()] = overlap[kind.index()].checked_add(1)?;
            }
        }
        for (overlap, total) in overlap.iter().zip(state.observations) {
            total.checked_sub(*overlap)?;
            result.observed_unconfirmed_owners =
                result.observed_unconfirmed_owners.checked_add(total)?;
        }
        let overlap = overlap.into_iter().try_fold(0usize, usize::checked_add)?;
        result.retiring_channels = state.retiring.len();
        result.unique_cleanup_debt = result
            .canceled_opens
            .checked_add(result.retiring_channels)?
            .checked_add(result.observed_unconfirmed_owners)?
            .checked_sub(overlap)?;
        result.leader_unconfirmed = state.observations[0] != 0;
        result.cleanup_unconfirmed = state.observations[1] != 0;
        result.observation_panicked = state.observations[2] != 0;
        Some(result)
    }
    // Registry -> one capsule, with no backend callback or resource transfer.
    pub(crate) fn record_observation(&self, owner: &Arc<ReapCapsule>, kind: ObservationFailure) {
        if !owner.belongs_to(self) {
            return;
        }
        let mut state = self.state.lock().unwrap_or_else(|e| {
            let mut state = e.into_inner();
            state.invalid_projection = true;
            state
        });
        let Some(mut capsule) = owner.observation_state(false) else {
            state.invalid_projection = true;
            return;
        };
        if capsule.observation.is_some() || capsule.terminal.is_some() {
            return;
        }
        let Some(count) = state.observations[kind.index()].checked_add(1) else {
            state.invalid_projection = true;
            return;
        };
        capsule.observation = Some(kind);
        state.observations[kind.index()] = count;
    }
    pub fn outstanding(&self) -> usize {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.jobs.len() + state.retiring.len()
    }
    pub fn retiring_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retiring
            .len()
    }
    pub(crate) fn register_reap(&self, owner: Arc<ReapCapsule>, uid: u32) {
        let stop = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            let key = Arc::as_ptr(&owner) as usize;
            assert!(state
                .retiring
                .insert(
                    key,
                    Retiring {
                        owner: owner.clone(),
                        uid
                    }
                )
                .is_none());
            // These children were already admitted. Retirement cannot fail when
            // several healthy installed children exceed the pending-open cap;
            // the charge prevents further unresolved-retirement churn.
            *state.uids.entry(uid).or_default() += 1;
            state.fence.is_some()
        };
        if stop {
            owner.stop();
        }
    }
    pub(crate) fn finish_reap(&self, owner: &Arc<ReapCapsule>) {
        let mut state = self.state.lock().unwrap_or_else(|e| {
            let mut state = e.into_inner();
            state.invalid_projection = true;
            state
        });
        if !owner.belongs_to(self) {
            return;
        }
        // Metadata poisoning makes observation unavailable, but must not
        // prevent the existing proved resource/capacity settlement.
        let (mut capsule, poisoned) = owner.completion_state();
        state.invalid_projection |= poisoned;
        if capsule.terminal.is_none() {
            return;
        }
        if let Some(kind) = capsule.observation.take() {
            match state.observations[kind.index()].checked_sub(1) {
                Some(count) => state.observations[kind.index()] = count,
                None => state.invalid_projection = true,
            }
        }
        drop(capsule);
        let key = Arc::as_ptr(owner) as usize;
        let Some(entry) = state.retiring.get(&key) else {
            return;
        };
        if !Arc::ptr_eq(&entry.owner, owner) {
            return;
        }
        let removed = state.retiring.remove(&key).expect("exact registered reap");
        release_uid(&mut state, removed.uid);
        self.changed.notify_all();
        drop(state);
        drop(removed);
    }
    pub fn cleanup(&self, id: OpenJobId) -> CleanupStatus {
        let registration = self
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .jobs
            .get(&id)
            .cloned();
        let Some(registration) = registration else {
            return CleanupStatus::Unknown;
        };
        let status = registration.custody.cleanup();
        if let CleanupStatus::Confirmed(ref proof) = status {
            self.finish_cleanup(id, proof);
        }
        status
    }
    pub fn finish_cleanup(&self, id: OpenJobId, proof: &CleanupProof) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        let Some(registration) = state.jobs.get(&id) else {
            return false;
        };
        if !Weak::ptr_eq(&proof.owner, &Arc::downgrade(&registration.custody.inner)) {
            return false;
        }
        let removed = state.jobs.remove(&id).expect("validated registration");
        release_uid(&mut state, removed.request.owner.uid);
        removed.session.occupied.fetch_sub(1, Ordering::SeqCst);
        removed.session.ready.notify_one();
        self.changed.notify_all();
        drop(state);
        drop(removed);
        true
    }
}

/// Factory-owned barrier for uninstalled opens across restart preparation.
/// Dropping an uncommitted rollback owner leaves admission closed.
pub struct RestartOpenFence {
    registry: Arc<ChannelOpenRegistry>,
    id: u64,
}
/// Cannot be manufactured without an empty, still-fenced registry. Borrowing
/// the fence prevents its explicit reopen while exec consumes this authority.
pub struct OpenExecPermit<'a> {
    _fence: &'a RestartOpenFence,
}
impl ChannelOpenRegistry {
    pub fn begin_restart_fence(self: &Arc<Self>) -> Result<RestartOpenFence, OpenRefusal> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| OpenRefusal::InvalidIdentity)?;
        if state.fence.is_some() {
            return Err(OpenRefusal::Restarting);
        }
        let id = state.next_fence;
        state.next_fence = id.checked_add(1).ok_or(OpenRefusal::Exhausted)?;
        state.fence = Some(id);
        // Registry -> custody; cancellation is only a state change and wake.
        // No backend cleanup, task scheduling or descriptor operation runs here.
        for registration in state.jobs.values() {
            registration.custody.cancel();
        }
        let retiring: Vec<_> = state
            .retiring
            .values()
            .map(|entry| entry.owner.clone())
            .collect();
        drop(state);
        for owner in retiring {
            owner.stop();
        }
        Ok(RestartOpenFence {
            registry: self.clone(),
            id,
        })
    }
}
impl RestartOpenFence {
    pub fn wait_until(&self, deadline: std::time::Instant) -> Option<OpenExecPermit<'_>> {
        let mut state = self.registry.state.lock().ok()?;
        loop {
            if state.fence != Some(self.id) {
                return None;
            }
            if state.jobs.is_empty() && state.retiring.is_empty() {
                return Some(OpenExecPermit { _fence: self });
            }
            let remaining = deadline.checked_duration_since(std::time::Instant::now())?;
            let (next, _) = self.registry.changed.wait_timeout(state, remaining).ok()?;
            state = next;
        }
    }
    pub fn reopen(self) {
        if let Ok(mut state) = self.registry.state.lock() {
            if state.fence == Some(self.id) {
                state.fence = None;
                self.registry.changed.notify_all();
            }
        }
    }
}

#[cfg(test)]
mod counter_tests {
    use super::*;

    #[test]
    fn open24_fence_exhaustion_never_wraps_or_reopens() {
        let registry = ChannelOpenRegistry::new(Default::default());
        registry.state.lock().unwrap().next_fence = u64::MAX;
        assert!(matches!(
            registry.begin_restart_fence(),
            Err(OpenRefusal::Exhausted)
        ));
        assert!(registry.state.lock().unwrap().fence.is_none());
        assert_eq!(registry.state.lock().unwrap().next_fence, u64::MAX);
    }

    #[test]
    fn open24_stale_fence_cannot_issue_permit_or_reopen_new_fence() {
        let registry = ChannelOpenRegistry::new(Default::default());
        let first = registry.begin_restart_fence().unwrap();
        let stale_id = first.id;
        first.reopen();
        let current = registry.begin_restart_fence().unwrap();
        let stale = RestartOpenFence {
            registry: registry.clone(),
            id: stale_id,
        };
        assert!(stale.wait_until(std::time::Instant::now()).is_none());
        stale.reopen();
        assert_eq!(registry.state.lock().unwrap().fence, Some(current.id));
        assert!(current.wait_until(std::time::Instant::now()).is_some());
        current.reopen();
    }
}

#[cfg(test)]
mod cleanup143_tests {
    use super::*;

    #[test]
    fn cleanup143_unavailable_never_returns_partial_or_clean_counts() {
        let registry = ChannelOpenRegistry::new(Default::default());
        let held = registry.state.lock().unwrap();
        assert!(registry.try_cleanup_snapshot().is_none());
        drop(held);
        registry.state.lock().unwrap().invalid_projection = true;
        assert!(registry.cleanup_snapshot().is_none());
        registry.state.lock().unwrap().invalid_projection = false;
        registry.state.lock().unwrap().observations = [usize::MAX, 1, 0];
        assert!(registry.cleanup_snapshot().is_none());
        registry.state.lock().unwrap().observations = [0; 3];
        assert_eq!(
            registry.cleanup_snapshot().unwrap(),
            CleanupSnapshot::default()
        );
        let poisoned = registry.clone();
        assert!(std::thread::spawn(move || {
            let _guard = poisoned.state.lock().unwrap();
            panic!("owned poison fixture");
        })
        .join()
        .is_err());
        assert!(registry.try_cleanup_snapshot().is_none());
        assert!(registry.cleanup_snapshot().is_none());
    }
}
