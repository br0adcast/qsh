//! Factory-owned custody registrations. This owner survives individual runners.

use super::*;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

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
}
impl SessionOpenLedger {
    pub fn id(&self) -> SessionOpenId {
        self.id
    }
    pub fn occupied(&self) -> usize {
        self.occupied.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenRefusal {
    Capacity,
    InvalidIdentity,
    Exhausted,
}

struct Registration {
    request: OpenRequestSnapshot,
    session: Arc<SessionOpenLedger>,
    custody: OpenCustody,
}
struct RegistryState {
    jobs: HashMap<OpenJobId, Arc<Registration>>,
    uids: HashMap<u32, usize>,
    next_job: u64,
    next_session: u64,
}
pub struct ChannelOpenRegistry {
    state: Mutex<RegistryState>,
    limits: OpenLimits,
}

pub struct OpenJob {
    id: OpenJobId,
    registration: Arc<Registration>,
    registry: Arc<ChannelOpenRegistry>,
}
impl OpenJob {
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
    pub fn adopt(
        self,
        channel: UninstalledChannel,
    ) -> Result<(SpawnedChannel, InstalledSlot), UninstalledChannel> {
        let Ok(mut state) = self.registry.state.lock() else {
            return Err(channel);
        };
        if !state.jobs.contains_key(&self.id)
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
            }),
            limits,
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
        if !Weak::ptr_eq(&session.registry, &Arc::downgrade(self))
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
        drop(state);
        drop(removed);
        true
    }
}
