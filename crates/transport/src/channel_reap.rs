//! Exact-instance child waits with factory-owned custody while proof is absent.

use super::{ChannelWait, ChildStatus, LeaderStatus};
use crate::channel_open::{ChannelOpenRegistry, InstalledSlot};
use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::Notify;

/// Portable status observation interval, never a termination deadline.
const STATUS_POLL: Duration = Duration::from_millis(20);

/// A backend may wake only its exact installed owner when new evidence arrives.
/// Call outside backend/receipt locks; this can schedule a blocking observation.
#[derive(Clone)]
pub struct ReapNotifier(Weak<Capsule>);
impl ReapNotifier {
    pub fn notify(&self) {
        if let Some(owner) = self.0.upgrade() {
            owner.notify();
        }
    }
}

/// Only actual backend observation failures are retained, never normal waiting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservationFailure {
    Leader,
    Cleanup,
    Panic,
}
impl ObservationFailure {
    pub(crate) fn index(self) -> usize {
        match self {
            Self::Leader => 0,
            Self::Cleanup => 1,
            Self::Panic => 2,
        }
    }
}

struct Resources {
    child: Option<Box<dyn ChannelWait>>,
    _slot: Option<InstalledSlot>,
    notifier_installed: bool,
}
pub(crate) struct State {
    pub(crate) observation: Option<ObservationFailure>,
    resources: Option<Resources>,
    leased: bool,
    retry: bool,
    stop: bool,
    stop_seen: bool,
    signal_allowed: bool,
    active_poll: bool,
    pub(crate) terminal: Option<Option<i32>>,
    published: bool,
    retiring: bool,
    registering: bool,
    leader_status: Option<Option<i32>>,
    leader_published: bool,
}

/// Registry-owned before any callback or worker can run. A task owns only an
/// exclusive lease; dropping that task restores the resources to this capsule.
pub(crate) struct Capsule {
    stream: u8,
    instance: u64,
    uid: u32,
    state: Mutex<State>,
    changed: Condvar,
    ready: Arc<Notify>,
    runtime: Handle,
    registry: Weak<ChannelOpenRegistry>,
}
impl Capsule {
    pub(crate) fn belongs_to(&self, registry: &ChannelOpenRegistry) -> bool {
        std::ptr::eq(self.registry.as_ptr(), registry)
    }
    pub(crate) fn observation_state(
        &self,
        nonblocking: bool,
    ) -> Option<std::sync::MutexGuard<'_, State>> {
        crate::channel_open::metadata_lock(&self.state, nonblocking)
    }
    pub(crate) fn completion_state(&self) -> (std::sync::MutexGuard<'_, State>, bool) {
        match self.state.lock() {
            Ok(state) => (state, false),
            Err(error) => (error.into_inner(), true),
        }
    }
    fn notify(self: &Arc<Self>) {
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.terminal.is_some() {
                return;
            }
            state.retry = true;
            self.changed.notify_all();
        }
        self.dispatch();
    }

    pub(crate) fn stop(self: &Arc<Self>) {
        self.retire(true);
    }

    fn retire(self: &Arc<Self>, stop_now: bool) {
        let register = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.terminal.is_some() {
                return;
            }
            state.stop |= stop_now;
            self.changed.notify_all();
            if state.retiring {
                false
            } else if state.registering {
                return;
            } else {
                state.registering = true;
                true
            }
        };
        if register {
            // No backend lease can start final cleanup until the factory owns
            // retirement. register_reap may synchronously request stop at a
            // restart fence, so no capsule mutex is held across registration.
            let registry = self
                .registry
                .upgrade()
                .expect("factory outlives its session owner");
            registry.register_reap(self.clone(), self.uid);
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            state.retiring = true;
            state.registering = false;
            state.retry = true;
            self.changed.notify_all();
        }
        let schedule = {
            let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            register || state.retry || (state.signal_allowed && !state.stop_seen)
        };
        if schedule {
            self.dispatch();
        }
    }

    fn observe_active(self: &Arc<Self>) {
        {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !state.active_poll
                || state.retiring
                || state.registering
                || state.terminal.is_some()
                || !state.signal_allowed
            {
                return;
            }
            state.retry = true;
        }
        self.dispatch();
    }

    fn take_lease(self: &Arc<Self>) -> Option<Lease> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.leased || state.registering || state.terminal.is_some() {
            return None;
        }
        let resources = state.resources.take()?;
        state.leased = true;
        state.retry = false;
        Some(Lease {
            owner: self.clone(),
            resources: Some(resources),
        })
    }

    fn dispatch(self: &Arc<Self>) {
        let Some(lease) = self.take_lease() else {
            return;
        };
        let runtime = self.runtime.clone();
        // A cancelled queued task drops its captured lease. Scheduling failure
        // likewise cannot move the last resource owner out of the registry.
        if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(runtime.spawn_blocking(move || lease.run()));
        }))
        .is_err()
        {
            log::warn!("channel wait scheduling failed; custody remains retained");
        }
    }

    fn take_leader_status(&self) -> Option<Option<i32>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if state.leader_published {
            return None;
        }
        let code = state.leader_status?;
        state.leader_published = true;
        Some(code)
    }

    fn terminal(&self) -> Option<Option<i32>> {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        state.published.then_some(state.terminal).flatten()
    }
}

struct Lease {
    owner: Arc<Capsule>,
    resources: Option<Resources>,
}
impl Lease {
    fn unknown(&self, kind: ObservationFailure, detail: &str) {
        self.owner
            .state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .signal_allowed = false;
        if let Some(registry) = self.owner.registry.upgrade() {
            registry.record_observation(&self.owner, kind);
        }
        log::warn!(
            "channel {}/{} termination is unconfirmed: {detail}",
            self.owner.stream,
            self.owner.instance
        );
    }

    fn run(mut self) {
        let observation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.observe()));
        match observation {
            Ok(Some(code)) => {
                // Latch proof before releasing the child or exposing completion:
                // a later Close/Drop must never signal a possibly reused PID.
                {
                    let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
                    state.terminal = Some(code);
                    state.leased = false;
                }
                // Even a backend destructor panic cannot erase an already
                // established proof or leave the factory charge stranded.
                if std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    drop(self.resources.take());
                }))
                .is_err()
                {
                    log::warn!("confirmed channel wait destructor panicked");
                }
                if let Some(registry) = self.owner.registry.upgrade() {
                    registry.finish_reap(&self.owner);
                }
                self.owner
                    .state
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .published = true;
                self.owner.ready.notify_one();
            }
            Ok(None) => {}
            Err(_) => self.unknown(ObservationFailure::Panic, "backend observation panicked"),
        }
        // Unknown/panic returns the exclusive resources through Drop, freeing
        // this worker. An evidence notification racing that return is retained.
    }

    fn observe(&mut self) -> Option<Option<i32>> {
        let resources = self.resources.as_mut().expect("exclusive child lease");
        if !resources.notifier_installed {
            let policy = resources
                .child
                .as_ref()
                .expect("owned child")
                .active_observation();
            self.owner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .active_poll = policy == super::ActiveObservation::Poll;
            resources
                .child
                .as_mut()
                .expect("owned child")
                .set_reap_notifier(ReapNotifier(Arc::downgrade(&self.owner)));
            resources.notifier_installed = true;
        }
        loop {
            if let Some(status) = resources
                .child
                .as_mut()
                .expect("owned child")
                .poll_leader_status()
            {
                match status {
                    LeaderStatus::Running => {}
                    LeaderStatus::Exited { code } => {
                        let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
                        if state.leader_status.is_none() {
                            state.leader_status = Some(code);
                            self.owner.ready.notify_one();
                        }
                    }
                    LeaderStatus::Unknown(detail) => {
                        self.unknown(ObservationFailure::Leader, &detail);
                        return None;
                    }
                }
            }
            if !self
                .owner
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .retiring
            {
                // Live observation is one shot. Only polling backends use the
                // active observer deadline; notified backends park without a
                // periodic fallback or a retained blocking worker.
                return None;
            }
            match resources.child.as_mut().expect("owned child").poll_exit() {
                ChildStatus::Reaped { code } => return Some(code),
                ChildStatus::Unknown(detail) => {
                    self.unknown(ObservationFailure::Cleanup, &detail);
                    return None;
                }
                // The child receipt is latched by IoOwnedWait. Its workers
                // notify this exact capsule after actual joins; a notification
                // before lease return remains sticky in state.retry.
                ChildStatus::WaitingForWorkers => return None,
                ChildStatus::Running => {}
            }
            let stop = {
                let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
                if state.stop && !state.stop_seen && state.signal_allowed {
                    state.stop_seen = true;
                    true
                } else {
                    false
                }
            };
            if stop {
                resources.child.as_mut().expect("owned child").kill();
                // kill can itself observe/reap the child. Poll the same owned
                // handle again; no independent killer exists in this design.
                continue;
            }
            let state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
            if state.stop && !state.stop_seen && state.signal_allowed {
                continue;
            }
            drop(self.owner.changed.wait_timeout(state, STATUS_POLL));
        }
    }
}
impl Drop for Lease {
    fn drop(&mut self) {
        let Some(resources) = self.resources.take() else {
            return;
        };
        let retry = {
            let mut state = self.owner.state.lock().unwrap_or_else(|e| e.into_inner());
            debug_assert!(state.resources.is_none());
            state.resources = Some(resources);
            state.leased = false;
            std::mem::take(&mut state.retry)
        };
        if retry {
            self.owner.dispatch();
        }
    }
}

pub(super) struct Completion {
    pub stream: u8,
    pub instance: u64,
    pub code: Option<i32>,
}

pub(super) enum ReapEvent {
    LeaderExited(Completion),
    Complete(Completion),
}

pub(super) struct ReapSet {
    registry: Arc<ChannelOpenRegistry>,
    owners: HashMap<u64, Arc<Capsule>>,
    ready: Arc<Notify>,
}
#[cfg(test)]
impl Default for ReapSet {
    fn default() -> Self {
        Self::new(ChannelOpenRegistry::new(Default::default()))
    }
}
impl ReapSet {
    pub fn new(registry: Arc<ChannelOpenRegistry>) -> Self {
        Self {
            registry,
            owners: HashMap::new(),
            ready: Arc::new(Notify::new()),
        }
    }
    pub fn is_empty(&self) -> bool {
        self.owners.is_empty()
    }
    pub fn start(
        &mut self,
        stream: u8,
        instance: u64,
        child: Box<dyn ChannelWait>,
        slot: Option<InstalledSlot>,
        stop_now: bool,
    ) {
        self.insert_owner(stream, instance, child, slot, stop_now, false);
    }
    pub fn start_active(
        &mut self,
        stream: u8,
        instance: u64,
        child: Box<dyn ChannelWait>,
        slot: Option<InstalledSlot>,
    ) {
        self.insert_owner(stream, instance, child, slot, false, true);
    }
    pub fn attach_workers(
        &self,
        instance: u64,
        workers: [crate::session_manager::WorkerReceipt; 2],
    ) {
        let owner = self.owners.get(&instance).expect("registered active owner");
        // Installation is synchronous and has not published/scheduled this
        // capsule yet. Never hold its mutex across worker/backend callbacks.
        let mut lease = owner.take_lease().expect("unpublished active custody");
        let resources = lease.resources.as_mut().expect("exclusive child lease");
        let child = resources.child.take().expect("owned child");
        resources.child = Some(Box::new(super::IoOwnedWait {
            child,
            reaped: None,
            workers,
        }));
        // Return exclusive resources before scheduling. This initial one-shot
        // installs backend/worker notification capabilities even with no timer.
        drop(lease);
        owner.observe_active();
    }
    pub fn retire(&self, instance: u64) {
        if let Some(owner) = self.owners.get(&instance) {
            owner.retire(false);
        }
    }
    pub fn needs_active_observation(&self) -> bool {
        self.owners.values().any(|owner| {
            let state = owner
                .state
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            state.active_poll
                && !state.retiring
                && !state.registering
                && state.terminal.is_none()
                && state.signal_allowed
        })
    }
    pub fn observe_active(&self) {
        for owner in self.owners.values() {
            owner.observe_active();
        }
    }
    fn insert_owner(
        &mut self,
        stream: u8,
        instance: u64,
        child: Box<dyn ChannelWait>,
        slot: Option<InstalledSlot>,
        stop_now: bool,
        active: bool,
    ) {
        if let Some(slot) = &slot {
            assert!(
                slot.belongs_to(&self.registry),
                "installed owner belongs to this factory"
            );
        }
        let uid = slot.as_ref().map_or(0, InstalledSlot::uid);
        // At most one proved completion per finite stream plus unresolved
        // charged owners. Reuse cannot append an unbounded completed history.
        self.owners
            .retain(|_, owner| owner.stream != stream || owner.terminal().is_none());
        let owner = Arc::new(Capsule {
            stream,
            instance,
            uid,
            ready: self.ready.clone(),
            runtime: Handle::current(),
            registry: Arc::downgrade(&self.registry),
            changed: Condvar::new(),
            state: Mutex::new(State {
                resources: Some(Resources {
                    child: Some(child),
                    _slot: slot,
                    notifier_installed: false,
                }),
                leased: false,
                retry: false,
                stop: stop_now,
                stop_seen: false,
                signal_allowed: true,
                active_poll: true,
                observation: None,
                terminal: None,
                published: false,
                retiring: false,
                registering: false,
                leader_status: None,
                leader_published: false,
            }),
        });
        assert!(
            !self.owners.contains_key(&instance),
            "one retirement per exact instance"
        );
        self.owners.insert(instance, owner.clone());
        if !active {
            owner.retire(stop_now);
        }
    }
    pub fn stop(&self, instance: u64) {
        if let Some(owner) = self.owners.get(&instance) {
            owner.stop();
        }
    }
    pub fn stop_all(&self) {
        for owner in self.owners.values() {
            owner.stop();
        }
    }
    pub async fn next(&mut self) -> Completion {
        loop {
            if let ReapEvent::Complete(done) = self.next_event().await {
                return done;
            }
        }
    }
    pub async fn next_event(&mut self) -> ReapEvent {
        loop {
            let ready = self.ready.notified();
            // Publish independent status without removing the exact owner or
            // refunding its slot. Full cleanup may still own descendants/I/O.
            if let Some(status) = self.owners.values().find_map(|owner| {
                owner.take_leader_status().map(|code| Completion {
                    stream: owner.stream,
                    instance: owner.instance,
                    code,
                })
            }) {
                return ReapEvent::LeaderExited(status);
            }
            let done = self.owners.iter().find_map(|(&instance, owner)| {
                owner.terminal().map(|code| (instance, owner.stream, code))
            });
            if let Some((instance, stream, code)) = done {
                self.owners.remove(&instance);
                return ReapEvent::Complete(Completion {
                    stream,
                    instance,
                    code,
                });
            }
            ready.await;
        }
    }
}
impl Drop for ReapSet {
    fn drop(&mut self) {
        self.stop_all();
        // The registry already owns every unresolved capsule. Dropping a
        // runner or its notification capability cannot refund that custody.
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    struct UnknownWait(mpsc::SyncSender<()>);
    impl ChannelWait for UnknownWait {
        fn poll_exit(&mut self) -> ChildStatus {
            let _ = self.0.try_send(());
            ChildStatus::Unknown("controlled missing proof".into())
        }
        fn kill(&mut self) {
            panic!("unknown identity must not be signalled");
        }
        fn wait(self: Box<Self>) -> i32 {
            panic!("must poll the owned child");
        }
        fn cleanup_uninstalled(
            &mut self,
            _: &crate::channel_open::CleanupAuthority<'_>,
        ) -> crate::channel_open::CleanupStatus {
            crate::channel_open::CleanupStatus::Unknown
        }
    }

    #[test]
    fn reap32_unknown_releases_the_blocking_worker_without_releasing_custody() {
        // Run this exact test in its own libtest process for the baseline RED:
        // the defective owner parks a thread forever. It owns no OS child;
        // shutdown_background allows the failed test process to exit/reap.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        let (entered, observed) = mpsc::sync_channel(1);
        let mut reaps = ReapSet::default();
        runtime.block_on(async {
            reaps.start(16, 1, Box::new(UnknownWait(entered)), None, false);
        });
        observed.recv_timeout(Duration::from_secs(5)).unwrap();
        let (done, progress) = mpsc::sync_channel(1);
        runtime.spawn_blocking(move || {
            let _ = done.send(());
        });
        let progressed = progress.recv_timeout(Duration::from_secs(2)).is_ok();
        assert!(!reaps.is_empty(), "Unknown must retain its exact owner");
        drop(reaps);
        runtime.shutdown_background();
        assert!(
            progressed,
            "Unknown occupied the only blocking worker indefinitely"
        );
    }
    use crate::channel_open::{
        OpenIdentity, OpenLimits, OpenRefusal, OpenRequestSnapshot, SessionOpenLedger,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    type DropGate = (mpsc::SyncSender<()>, mpsc::Receiver<()>);

    #[derive(Default)]
    struct Control {
        mode: AtomicUsize,
        polls: AtomicUsize,
        kills: AtomicUsize,
        drops: AtomicUsize,
        notifier: Mutex<Option<ReapNotifier>>,
        notify_during_unknown: AtomicBool,
        drop_gate: Mutex<Option<DropGate>>,
        panic_drop: AtomicBool,
    }
    impl Control {
        fn prove(&self) {
            self.mode.store(1, Ordering::SeqCst);
            let notifier = self.notifier.lock().unwrap().clone().unwrap();
            notifier.notify();
        }
    }
    struct ControlledWait(Arc<Control>);
    impl Drop for ControlledWait {
        fn drop(&mut self) {
            if let Some((entered, release)) = self.0.drop_gate.lock().unwrap().take() {
                entered.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(5)).unwrap();
            }
            self.0.drops.fetch_add(1, Ordering::SeqCst);
            assert!(
                !self.0.panic_drop.load(Ordering::SeqCst),
                "controlled destructor panic"
            );
        }
    }
    impl ChannelWait for ControlledWait {
        fn set_reap_notifier(&mut self, notifier: ReapNotifier) {
            *self.0.notifier.lock().unwrap() = Some(notifier);
        }
        fn poll_exit(&mut self) -> ChildStatus {
            self.0.polls.fetch_add(1, Ordering::SeqCst);
            match self.0.mode.load(Ordering::SeqCst) {
                1 => ChildStatus::Reaped { code: Some(42) },
                2 => {
                    self.0.mode.store(0, Ordering::SeqCst);
                    panic!("controlled observation unwind");
                }
                _ => {
                    if self.0.notify_during_unknown.swap(false, Ordering::SeqCst) {
                        self.0.prove();
                    }
                    ChildStatus::Unknown("controlled absent receipt".into())
                }
            }
        }
        fn kill(&mut self) {
            self.0.kills.fetch_add(1, Ordering::SeqCst);
        }
        fn wait(self: Box<Self>) -> i32 {
            panic!("blocking wait bypassed poll owner");
        }
        fn cleanup_uninstalled(
            &mut self,
            _: &crate::channel_open::CleanupAuthority<'_>,
        ) -> crate::channel_open::CleanupStatus {
            crate::channel_open::CleanupStatus::Unknown
        }
    }
    struct Resize;
    impl crate::shell_server::ResizeHandle for Resize {
        fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
            Ok(())
        }
    }
    fn request(session: &SessionOpenLedger, uid: u32, instance: u64) -> OpenRequestSnapshot {
        OpenRequestSnapshot {
            owner: crate::auth::Principal {
                uid,
                name: "reap-fixture".into(),
                identity: "fixture".into(),
                incarnation: 0,
            },
            login: [0; 16],
            term: None,
            request: crate::channel::OpenRequest {
                stream: 16,
                kind: crate::channel::ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            identity: OpenIdentity {
                session: session.id(),
                instance: crate::channel_geometry::ChannelInstance::new(instance).unwrap(),
                stream: 16,
                generation: 0,
                invalidation_epoch: 0,
            },
        }
    }
    fn installed(
        registry: &Arc<ChannelOpenRegistry>,
        session: &Arc<SessionOpenLedger>,
        control: Arc<Control>,
        instance: u64,
    ) -> (Box<dyn ChannelWait>, InstalledSlot) {
        let job = registry
            .try_reserve(session, request(session, 7, instance))
            .unwrap();
        let ready = job
            .custody()
            .protect(
                Box::new(ControlledWait(control)),
                Box::new(crate::shell_server::NoScreen),
            )
            .finish(
                Box::new(std::io::empty()),
                Box::new(std::io::sink()),
                Box::new(Resize),
            );
        let (channel, slot) = job
            .adopt(ready)
            .unwrap_or_else(|_| panic!("fixture adoption"));
        (channel.wait, slot)
    }
    async fn parked(owner: &Arc<Capsule>, control: &Control) {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let parked = {
                    let state = owner.state.lock().unwrap();
                    !state.leased && state.resources.is_some()
                };
                if control.polls.load(Ordering::SeqCst) > 0 && parked {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("observation parked its owned resources");
    }
    async fn completed(reaps: &mut ReapSet) -> Completion {
        tokio::time::timeout(Duration::from_secs(5), reaps.next())
            .await
            .expect("exact receipt completes")
    }

    #[tokio::test]
    async fn reap32_factory_retains_unknown_after_runner_drop_until_exact_receipt() {
        let registry = ChannelOpenRegistry::new(OpenLimits {
            global: 2,
            per_uid: 1,
        });
        let session = registry.session().unwrap();
        let control = Arc::new(Control::default());
        let (child, slot) = installed(&registry, &session, control.clone(), 1);
        assert_eq!(
            registry.outstanding(),
            0,
            "healthy installed is not pending work"
        );
        let mut reaps = ReapSet::new(registry.clone());
        reaps.start(16, 1, child, Some(slot), false);
        let owner = reaps.owners[&1].clone();
        parked(&owner, &control).await;
        assert_eq!(registry.retiring_count(), 1);
        assert_eq!(session.occupied(), 1);
        assert!(matches!(
            registry.try_reserve(&session, request(&session, 7, 2)),
            Err(OpenRefusal::Capacity)
        ));
        let other = registry
            .try_reserve(&session, request(&session, 8, 2))
            .unwrap();
        assert!(matches!(
            registry.try_reserve(&session, request(&session, 9, 3)),
            Err(OpenRefusal::Capacity)
        ));
        let refusal = other
            .custody()
            .refuse_before_creation("fixture cleanup".into());
        let crate::channel_open::SpawnCleanup::NoChild(proof) = refusal.cleanup else {
            panic!("no child");
        };
        assert!(registry.finish_cleanup(other.id(), &proof));
        drop(other);
        reaps.stop(1);
        drop(reaps);
        assert_eq!(
            control.kills.load(Ordering::SeqCst),
            0,
            "Unknown never permits a blind PID signal"
        );
        assert_eq!(control.drops.load(Ordering::SeqCst), 0);
        let fence = registry.begin_restart_fence().unwrap();
        assert!(fence.wait_until(std::time::Instant::now()).is_none());
        control.prove();
        tokio::time::timeout(Duration::from_secs(5), async {
            while registry.outstanding() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(fence.wait_until(std::time::Instant::now()).is_some());
        assert_eq!(session.occupied(), 0);
        assert_eq!(control.drops.load(Ordering::SeqCst), 1);
        assert_eq!(control.kills.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reap32_notification_during_unknown_return_is_not_lost() {
        let control = Arc::new(Control::default());
        control.notify_during_unknown.store(true, Ordering::SeqCst);
        let mut reaps = ReapSet::default();
        reaps.start(
            16,
            1,
            Box::new(ControlledWait(control.clone())),
            None,
            false,
        );
        let done = completed(&mut reaps).await;
        assert_eq!((done.stream, done.instance, done.code), (16, 1, Some(42)));
        assert_eq!(control.polls.load(Ordering::SeqCst), 2);
        assert_eq!(control.drops.load(Ordering::SeqCst), 1);
        assert_eq!(reaps.registry.outstanding(), 0);
    }

    #[tokio::test]
    async fn reap32_panicked_observation_restores_custody_for_exact_late_receipt() {
        let control = Arc::new(Control::default());
        control.mode.store(2, Ordering::SeqCst);
        let mut reaps = ReapSet::default();
        reaps.start(
            16,
            1,
            Box::new(ControlledWait(control.clone())),
            None,
            false,
        );
        parked(&reaps.owners[&1], &control).await;
        assert_eq!(reaps.registry.outstanding(), 1);
        assert_eq!(control.drops.load(Ordering::SeqCst), 0);
        reaps.stop(1);
        control.prove();
        assert_eq!(completed(&mut reaps).await.code, Some(42));
        assert_eq!(control.kills.load(Ordering::SeqCst), 0);
        assert_eq!(control.drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reap32_cancelled_queued_task_restores_exclusive_lease() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap();
        runtime.block_on(async {
            let control = Arc::new(Control::default());
            let mut reaps = ReapSet::default();
            reaps.start(
                16,
                1,
                Box::new(ControlledWait(control.clone())),
                None,
                false,
            );
            let owner = reaps.owners[&1].clone();
            parked(&owner, &control).await;
            let (release, held) = mpsc::sync_channel(1);
            let (entered, started) = tokio::sync::oneshot::channel();
            let blocker = tokio::task::spawn_blocking(move || {
                entered.send(()).unwrap();
                held.recv_timeout(Duration::from_secs(5)).unwrap();
            });
            started.await.unwrap();
            let lease = owner.take_lease().unwrap();
            let queued = tokio::task::spawn_blocking(move || lease.run());
            queued.abort();
            release.send(()).unwrap();
            blocker.await.unwrap();
            assert!(queued.await.unwrap_err().is_cancelled());
            assert!(owner.state.lock().unwrap().resources.is_some());
            assert_eq!(reaps.registry.outstanding(), 1);
            assert_eq!(control.drops.load(Ordering::SeqCst), 0);
            control.prove();
            assert_eq!(completed(&mut reaps).await.code, Some(42));
            assert_eq!(control.drops.load(Ordering::SeqCst), 1);
        });
    }

    #[tokio::test]
    async fn reap32_completion_is_published_only_after_installed_slot_release() {
        let registry = ChannelOpenRegistry::new(Default::default());
        let session = registry.session().unwrap();
        let control = Arc::new(Control::default());
        let (entered, started) = mpsc::sync_channel(1);
        let (release, held) = mpsc::sync_channel(1);
        *control.drop_gate.lock().unwrap() = Some((entered, held));
        control.mode.store(1, Ordering::SeqCst);
        let (child, slot) = installed(&registry, &session, control.clone(), 1);
        let mut reaps = ReapSet::new(registry.clone());
        reaps.start(16, 1, child, Some(slot), false);
        started.recv_timeout(Duration::from_secs(5)).unwrap();
        let early = reaps.owners[&1].terminal();
        reaps.stop(1);
        assert_eq!(session.occupied(), 1);
        release.send(()).unwrap();
        let done = completed(&mut reaps).await;
        assert_eq!(early, None, "completion preceded slot cleanup");
        assert_eq!(done.code, Some(42));
        assert_eq!(session.occupied(), 0);
        assert_eq!(registry.outstanding(), 0);
        assert_eq!(control.kills.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reap32_confirmed_destructor_panic_still_releases_exact_slot_once() {
        let registry = ChannelOpenRegistry::new(Default::default());
        let session = registry.session().unwrap();
        let control = Arc::new(Control::default());
        control.mode.store(1, Ordering::SeqCst);
        control.panic_drop.store(true, Ordering::SeqCst);
        let (child, slot) = installed(&registry, &session, control.clone(), 1);
        let mut reaps = ReapSet::new(registry.clone());
        reaps.start(16, 1, child, Some(slot), false);
        assert_eq!(completed(&mut reaps).await.code, Some(42));
        assert_eq!(session.occupied(), 0);
        assert_eq!(registry.outstanding(), 0);
        control.prove();
        assert_eq!(control.drops.load(Ordering::SeqCst), 1);
        assert_eq!(control.kills.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn reap32_reused_stream_bounds_completions_and_stale_receipt_cannot_release_replacement()
    {
        let mut reaps = ReapSet::default();
        let first = Arc::new(Control::default());
        first.mode.store(1, Ordering::SeqCst);
        reaps.start(16, 1, Box::new(ControlledWait(first.clone())), None, false);
        for instance in 2..=20 {
            tokio::time::timeout(Duration::from_secs(5), async {
                while reaps.owners[&(instance - 1)].terminal().is_none() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let next = Arc::new(Control::default());
            if instance != 20 {
                next.mode.store(1, Ordering::SeqCst);
            }
            reaps.start(
                16,
                instance,
                Box::new(ControlledWait(next.clone())),
                None,
                false,
            );
            assert_eq!(
                reaps.owners.len(),
                1,
                "no per-generation completion history"
            );
            if instance == 20 {
                parked(&reaps.owners[&instance], &next).await;
                first.prove();
                assert_eq!(reaps.registry.outstanding(), 1);
                assert_eq!(next.drops.load(Ordering::SeqCst), 0);
                next.prove();
            }
        }
        let done = completed(&mut reaps).await;
        assert_eq!((done.instance, done.code), (20, Some(42)));
        assert_eq!(reaps.registry.outstanding(), 0);
    }

    #[test]
    fn reap32_runtime_shutdown_cannot_refund_factory_custody() {
        let registry = ChannelOpenRegistry::new(Default::default());
        let session = registry.session().unwrap();
        let control = Arc::new(Control::default());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (child, slot) = installed(&registry, &session, control.clone(), 1);
            let mut reaps = ReapSet::new(registry.clone());
            reaps.start(16, 1, child, Some(slot), false);
            parked(&reaps.owners[&1], &control).await;
        });
        drop(runtime);
        assert_eq!(registry.retiring_count(), 1);
        assert_eq!(session.occupied(), 1);
        assert_eq!(control.drops.load(Ordering::SeqCst), 0);
        assert_eq!(control.kills.load(Ordering::SeqCst), 0);
        // This fixture owns no OS child. Dropping the factory ends its lifetime;
        // orderly process/runtime shutdown cleanup is the separate #39 contract.
        drop(registry);
        assert_eq!(control.drops.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
#[path = "channel_reap_active_tests.rs"]
mod active_tests;
