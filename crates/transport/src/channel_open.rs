//! Custody of a channel which has not yet been installed in a session.
//!
//! The registry/adapter must retain an OpenCustody until adoption or exact cleanup
//! proof. Capabilities and notifications are not the last resource owner.

use std::io::{Read, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};

use crate::channel_server::{ChannelWait, SpawnedChannel};
use crate::shell_server::{ResizeHandle, SessionScreen};

#[path = "channel_open_registry.rs"]
mod registry;
pub use registry::*;

// Metadata reads never recover a poisoned or partial observation.
pub(crate) fn metadata_lock<T>(mutex: &Mutex<T>, nonblocking: bool) -> Option<MutexGuard<'_, T>> {
    if nonblocking {
        mutex.try_lock().ok()
    } else {
        mutex.lock().ok()
    }
}

/// Holds the watch read guard across admission/final commit. The epoch alone
/// is not authority: a registry fence must also agree at final adoption.
pub struct IdleEpochGuard<'a> {
    _signal: Option<tokio::sync::watch::Ref<'a, crate::channel_server::RestartSignal>>,
    epoch: u64,
}
impl<'a> IdleEpochGuard<'a> {
    pub(crate) fn from_signal(
        signal: tokio::sync::watch::Ref<'a, crate::channel_server::RestartSignal>,
    ) -> Result<Self, OpenRefusal> {
        if signal.phase != crate::channel_server::RestartPhase::Idle {
            return Err(OpenRefusal::Restarting);
        }
        let epoch = signal.invalidation_epoch;
        Ok(Self {
            _signal: Some(signal),
            epoch,
        })
    }
    pub(crate) fn initial() -> Self {
        Self {
            _signal: None,
            epoch: 0,
        }
    }
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProofKind {
    NoChild,
    Reaped,
}

/// A proof names its exact custody cell; an unrelated job cannot spend it.
#[derive(Debug)]
pub struct CleanupProof {
    owner: Weak<Capsule>,
    kind: ProofKind,
}

/// Only the exclusive cleanup call receives this proof-producing authority.
/// Backends may report Reaped only after their exact child/receipt establishes it.
pub struct CleanupAuthority<'a> {
    owner: &'a Arc<Capsule>,
}

impl CleanupAuthority<'_> {
    pub fn reaped(&self) -> CleanupStatus {
        CleanupStatus::Confirmed(CleanupProof {
            owner: Arc::downgrade(self.owner),
            kind: ProofKind::Reaped,
        })
    }
    /// For an internal helper receipt that proves creation never happened.
    pub fn no_child(&self) -> CleanupStatus {
        CleanupStatus::Confirmed(CleanupProof {
            owner: Arc::downgrade(self.owner),
            kind: ProofKind::NoChild,
        })
    }
}

#[derive(Debug)]
pub enum CleanupStatus {
    Confirmed(CleanupProof),
    Unknown,
}

struct Resources {
    wait: Box<dyn ChannelWait>,
    screen: Box<dyn SessionScreen>,
    io: Option<PreparedIo>,
}
struct PreparedIo {
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    resize: Box<dyn ResizeHandle>,
}
#[derive(Default)]
struct State {
    resources: Option<Resources>,
    constructing: bool,
    cancelled: bool,
    ready: bool,
    leased: bool,
    retry_requested: bool,
    #[cfg(test)]
    worker_waiting: bool,
    terminal: Option<ProofKind>,
    adopted: bool,
}
#[derive(Default)]
struct Capsule {
    state: Mutex<State>,
    resolved: Condvar,
    registration: OnceLock<(Weak<ChannelOpenRegistry>, OpenJobId)>,
}
impl std::fmt::Debug for Capsule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenCustody")
    }
}

/// Shared capsule handle. The registration owner outlives worker/runner stacks.
#[derive(Clone, Default)]
pub struct OpenCustody {
    inner: Arc<Capsule>,
}

impl OpenCustody {
    pub(crate) fn canceled_snapshot(&self, nonblocking: bool) -> Option<bool> {
        Some(metadata_lock(&self.inner.state, nonblocking)?.cancelled)
    }
    pub fn new() -> Self {
        Self::default()
    }

    pub fn protect(
        &self,
        wait: Box<dyn ChannelWait>,
        screen: Box<dyn SessionScreen>,
    ) -> ConstructionGuard {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            state.resources.is_none()
                && !state.leased
                && !state.adopted
                && state.terminal.is_none(),
            "one construction per admitted open"
        );
        state.constructing = true;
        state.resources = Some(Resources {
            wait,
            screen,
            io: None,
        });
        ConstructionGuard {
            custody: self.clone(),
            armed: true,
        }
    }

    pub fn is_cancelled(&self) -> bool {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancelled
    }

    pub fn cancel(&self) {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .cancelled = true;
        self.inner.resolved.notify_all();
    }

    fn wait_for_resolution(&self) -> bool {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        while !state.cancelled && !state.adopted {
            #[cfg(test)]
            {
                state.worker_waiting = true;
            }
            state = self
                .inner
                .resolved
                .wait(state)
                .unwrap_or_else(|e| e.into_inner());
        }
        #[cfg(test)]
        {
            state.worker_waiting = false;
        }
        state.adopted
    }

    /// The backend has established that no possibly creating operation ran.
    pub fn refuse_before_creation(&self, reason: String) -> SpawnFailure {
        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.resources.is_none() && !state.leased && !state.adopted {
            state.terminal = Some(ProofKind::NoChild);
            SpawnFailure {
                reason,
                cleanup: SpawnCleanup::NoChild(CleanupProof {
                    owner: Arc::downgrade(&self.inner),
                    kind: ProofKind::NoChild,
                }),
            }
        } else {
            drop(state);
            self.failure(reason)
        }
    }

    pub fn failure(&self, reason: String) -> SpawnFailure {
        self.cancel();
        SpawnFailure {
            reason,
            cleanup: SpawnCleanup::Pending(CleanupTicket {
                custody: self.clone(),
            }),
        }
    }

    /// Retry after a backend records an exact terminal cleanup receipt.
    pub fn retry_cleanup(&self) -> CleanupStatus {
        let status = self.cleanup();
        if let CleanupStatus::Confirmed(ref proof) = status {
            if let Some((registry, job)) = self.inner.registration.get() {
                if let Some(registry) = registry.upgrade() {
                    registry.finish_cleanup(*job, proof);
                }
            }
        }
        status
    }

    /// The receipt ticket stores only this weak notification handle. Keeping
    /// a strong capsule inside its own wait object would create a custody cycle.
    pub fn cleanup_notifier(&self) -> CleanupNotifier {
        CleanupNotifier {
            inner: Arc::downgrade(&self.inner),
        }
    }

    fn bind_registration(&self, registry: &Arc<ChannelOpenRegistry>, job: OpenJobId) {
        self.inner
            .registration
            .set((Arc::downgrade(registry), job))
            .unwrap_or_else(|_| panic!("custody is registered exactly once"));
    }

    /// Called by the blocking resource owner, never by Drop or the async loop.
    pub fn cleanup(&self) -> CleanupStatus {
        // Explicit cleanup also releases a worker parked on this capsule.
        // Receipt tickets call this only once cleanup was requested, never merely
        // because a healthy short-lived command supplied an early receipt.
        self.cancel();
        loop {
            let resources = {
                let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                state.cancelled = true;
                if let Some(kind) = state.terminal {
                    return CleanupStatus::Confirmed(CleanupProof {
                        owner: Arc::downgrade(&self.inner),
                        kind,
                    });
                }
                if state.constructing || state.adopted {
                    return CleanupStatus::Unknown;
                }
                if state.leased {
                    state.retry_requested = true;
                    return CleanupStatus::Unknown;
                }
                let Some(resources) = state.resources.take() else {
                    return CleanupStatus::Unknown;
                };
                state.leased = true;
                state.retry_requested = false;
                resources
            };
            let mut lease = ResourceLease {
                custody: self.clone(),
                resources: Some(resources),
            };
            let resources = lease.resources.as_mut().expect("exclusive resource lease");
            // Descriptor teardown precedes termination; the model/lease stays owned.
            if let Some(io) = resources.io.take() {
                drop(io.writer);
                drop(io.reader);
                drop(io.resize);
            }
            let authority = CleanupAuthority { owner: &self.inner };
            match resources.wait.cleanup_uninstalled(&authority) {
                CleanupStatus::Confirmed(proof)
                    if Weak::ptr_eq(&proof.owner, &Arc::downgrade(&self.inner)) =>
                {
                    {
                        let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                        state.terminal = Some(proof.kind);
                        state.leased = false;
                    }
                    // No backend destructor runs under the capsule lock.
                    drop(lease.resources.take());
                    return CleanupStatus::Confirmed(proof);
                }
                _ => {
                    // Restore first, then observe a receipt which arrived during
                    // backend cleanup. No notification can fall into the gap:
                    // after restoration a new notifier can take its own lease.
                    drop(lease);
                    let mut state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
                    if !std::mem::take(&mut state.retry_requested) {
                        return CleanupStatus::Unknown;
                    }
                }
            }
        }
    }
}

/// A backend records its receipt before invoking this, outside ticket locks.
/// Cleanup can run backend code; a helper's confirmed-receipt path must not do
/// socket I/O. Construction/another cleanup in progress returns Unknown.
#[derive(Clone)]
pub struct CleanupNotifier {
    inner: Weak<Capsule>,
}
impl CleanupNotifier {
    pub fn retry_cleanup(&self) -> CleanupStatus {
        match self.inner.upgrade() {
            Some(inner) => OpenCustody { inner }.retry_cleanup(),
            None => CleanupStatus::Unknown,
        }
    }
}

/// Restores resources on error or unwind; blocking backend work never owns the
/// only unregistered handle and never runs under the capsule mutex.
struct ResourceLease {
    custody: OpenCustody,
    resources: Option<Resources>,
}
impl Drop for ResourceLease {
    fn drop(&mut self) {
        if let Some(resources) = self.resources.take() {
            let mut state = self
                .custody
                .inner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            state.resources = Some(resources);
            state.leased = false;
        }
    }
}

pub struct ConstructionGuard {
    custody: OpenCustody,
    armed: bool,
}
impl ConstructionGuard {
    pub fn finish(
        mut self,
        reader: Box<dyn Read + Send>,
        writer: Box<dyn Write + Send>,
        resize: Box<dyn ResizeHandle>,
    ) -> UninstalledChannel {
        let mut state = self
            .custody
            .inner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state.resources.as_mut().unwrap().io = Some(PreparedIo {
            reader,
            writer,
            resize,
        });
        state.ready = true;
        state.constructing = false;
        drop(state);
        self.armed = false;
        UninstalledChannel {
            custody: self.custody.clone(),
            armed: true,
        }
    }
}
impl Drop for ConstructionGuard {
    fn drop(&mut self) {
        if self.armed {
            let mut state = self
                .custody
                .inner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            state.constructing = false;
            state.cancelled = true;
        }
    }
}

/// Single capability to a prepared result; resources remain in the capsule.
pub struct UninstalledChannel {
    custody: OpenCustody,
    armed: bool,
}
impl UninstalledChannel {
    /// Ownership transfer only. The runner's final adoption critical section
    /// must validate its registry fence, identity and restart epoch around this.
    pub(crate) fn adopt(mut self) -> Result<SpawnedChannel, Self> {
        let inner = self.custody.inner.clone();
        let Ok(mut state) = inner.state.lock() else {
            return Err(self);
        };
        if state.cancelled || !state.ready || state.leased || state.adopted {
            drop(state);
            return Err(self);
        }
        let Some(mut resources) = state.resources.take() else {
            drop(state);
            return Err(self);
        };
        let Some(io) = resources.io.take() else {
            state.resources = Some(resources);
            drop(state);
            return Err(self);
        };
        state.adopted = true;
        self.armed = false;
        drop(state);
        self.custody.inner.resolved.notify_all();
        Ok(SpawnedChannel {
            reader: io.reader,
            writer: io.writer,
            resize: io.resize,
            screen: resources.screen,
            wait: resources.wait,
        })
    }
}
impl Drop for UninstalledChannel {
    fn drop(&mut self) {
        if self.armed {
            self.custody.cancel();
        }
    }
}

/// A failure still owns its cleanup capability. Error text is not a proof.
pub struct SpawnFailure {
    pub reason: String,
    pub cleanup: SpawnCleanup,
}
pub enum SpawnCleanup {
    NoChild(CleanupProof),
    Pending(CleanupTicket),
}
pub struct CleanupTicket {
    custody: OpenCustody,
}
impl CleanupTicket {
    pub fn cleanup(&self) -> CleanupStatus {
        self.custody.cleanup()
    }
}
impl Drop for CleanupTicket {
    fn drop(&mut self) {
        self.custody.cancel();
    }
}
impl std::fmt::Debug for SpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnFailure")
            .field("reason", &self.reason)
            .finish_non_exhaustive()
    }
}
impl std::fmt::Display for SpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.reason.fmt(f)
    }
}
impl std::error::Error for SpawnFailure {}

#[cfg(test)]
#[path = "channel_open_tests.rs"]
mod tests;
