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
struct RegistryState {
    jobs: HashMap<OpenJobId, Arc<Registration>>,
    uids: HashMap<u32, usize>,
    next_job: u64,
    next_session: u64,
    next_fence: u64,
    fence: Option<u64>,
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
}
impl Drop for InstalledSlot {
    fn drop(&mut self) {
        self.session.occupied.fetch_sub(1, Ordering::SeqCst);
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
                jobs: HashMap::new(),
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
        if state.jobs.len() >= self.limits.global
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
    pub fn outstanding(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .jobs
            .len()
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
            if state.jobs.is_empty() {
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
