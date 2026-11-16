//! Test-only observations from the original exclusively owned wait backend.
use std::sync::{Arc, Mutex};
use std::time::Instant;
use transport::channel_open::{CleanupAuthority, CleanupStatus};
use transport::channel_server::{
    ActiveObservation, ChannelWait, ChildStatus, LeaderStatus, ReapNotifier,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservedLeader {
    NotObserved,
    Running,
    Exited(Option<i32>),
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Snapshot {
    pub(crate) leader: ObservedLeader,
    pub(crate) kill_entered: bool,
    pub(crate) cleanup_entered: bool,
    pub(crate) bound: bool,
}
impl Snapshot {
    pub(crate) fn voluntary_zero(self) -> bool {
        self.bound
            && !self.kill_entered
            && !self.cleanup_entered
            && self.leader == ObservedLeader::Exited(Some(0))
    }
    fn failed(self) -> bool {
        !self.bound
            || self.kill_entered
            || self.cleanup_entered
            || self.leader == ObservedLeader::Unknown
            || matches!(self.leader, ObservedLeader::Exited(code) if code != Some(0))
    }
}
struct State {
    snapshot: Snapshot,
    notifier: Option<ReapNotifier>,
}
#[derive(Clone)]
pub(crate) struct FixtureLeaderObserver {
    expected_stream: u8,
    state: Arc<Mutex<State>>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ObservationFailure {
    Invalid,
    Deadline,
}
/// One registration, acquired before creation, moving only the same inner wait.
pub(super) struct Registration(FixtureLeaderObserver);
impl FixtureLeaderObserver {
    pub(crate) fn new(expected_stream: u8) -> Self {
        Self {
            expected_stream,
            state: Arc::new(Mutex::new(State {
                snapshot: Snapshot {
                    leader: ObservedLeader::NotObserved,
                    kill_entered: false,
                    cleanup_entered: false,
                    bound: false,
                },
                notifier: None,
            })),
        }
    }
    pub(super) fn claim(&self, stream: u8) -> Result<Registration, ObservationFailure> {
        let mut state = self.state.lock().map_err(|_| ObservationFailure::Invalid)?;
        if stream != self.expected_stream
            || state.snapshot.bound
            || state.snapshot.leader == ObservedLeader::Unknown
        {
            state.snapshot.leader = ObservedLeader::Unknown;
            return Err(ObservationFailure::Invalid);
        }
        state.snapshot.bound = true;
        Ok(Registration(self.clone()))
    }
    pub(crate) fn snapshot(&self) -> Snapshot {
        self.state.lock().map(|s| s.snapshot).unwrap_or(Snapshot {
            leader: ObservedLeader::Unknown,
            kill_entered: false,
            cleanup_entered: false,
            bound: false,
        })
    }
    fn record(&self, returned: &Option<LeaderStatus>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let next = match returned {
            Some(LeaderStatus::Running) => ObservedLeader::Running,
            Some(LeaderStatus::Exited { code }) => ObservedLeader::Exited(*code),
            None | Some(LeaderStatus::Unknown(_)) => ObservedLeader::Unknown,
        };
        let old = state.snapshot.leader;
        state.snapshot.leader = if old == ObservedLeader::Unknown
            || matches!(old, ObservedLeader::Exited(_)) && next != old
        {
            ObservedLeader::Unknown
        } else {
            next
        };
    }
    fn destructive(&self, kill: bool) {
        if let Ok(mut state) = self.state.lock() {
            if kill {
                state.snapshot.kill_entered = true;
            } else {
                state.snapshot.cleanup_entered = true;
            }
        }
    }
    pub(crate) fn request_observation(&self) -> bool {
        let notifier = self.state.lock().ok().and_then(|state| {
            if state.snapshot.failed() || matches!(state.snapshot.leader, ObservedLeader::Exited(_))
            {
                None
            } else {
                state.notifier.clone()
            }
        });
        // Dispatch can immediately schedule the original backend. No lock crosses it.
        if let Some(notifier) = notifier {
            notifier.notify();
            true
        } else {
            false
        }
    }
    pub(crate) async fn wait_for_terminal(
        &self,
        until: Instant,
    ) -> Result<Snapshot, ObservationFailure> {
        loop {
            let snapshot = self.snapshot();
            if snapshot.voluntary_zero() {
                return Ok(snapshot);
            }
            if snapshot.failed() {
                return Err(ObservationFailure::Invalid);
            }
            if Instant::now() >= until {
                return Err(ObservationFailure::Deadline);
            }
            self.request_observation();
            tokio::task::yield_now().await;
        }
    }
}
impl Registration {
    pub(super) fn wrap(self, inner: Box<dyn ChannelWait>) -> Box<dyn ChannelWait> {
        Box::new(ObservedWait {
            inner,
            observer: self.0,
        })
    }
}
struct ObservedWait {
    inner: Box<dyn ChannelWait>,
    observer: FixtureLeaderObserver,
}
impl ChannelWait for ObservedWait {
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        let returned = self.inner.poll_leader_status();
        self.observer.record(&returned);
        returned
    }
    fn poll_exit(&mut self) -> ChildStatus {
        self.observer.destructive(false);
        self.inner.poll_exit()
    }
    fn active_observation(&self) -> ActiveObservation {
        self.inner.active_observation()
    }
    fn set_reap_notifier(&mut self, notifier: ReapNotifier) {
        if let Ok(mut state) = self.observer.state.lock() {
            if state.notifier.is_some() {
                state.snapshot.leader = ObservedLeader::Unknown;
            } else {
                state.notifier = Some(notifier.clone());
            }
        }
        self.inner.set_reap_notifier(notifier);
    }
    fn kill(&mut self) {
        self.observer.destructive(true);
        self.inner.kill();
    }
    fn wait(self: Box<Self>) -> i32 {
        self.observer.destructive(false);
        self.inner.wait()
    }
    fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
        self.observer.destructive(false);
        self.inner.cleanup_uninstalled(authority)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::pin::Pin;
    use std::sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Condvar,
    };
    use std::task::{Context, Poll};
    use std::time::Duration;
    use transport::auth::Principal;
    use transport::channel::{ChannelKind, OpenRequest};
    use transport::channel_geometry::ChannelInstance;
    use transport::channel_open::{ChannelOpenRegistry, OpenIdentity, OpenRequestSnapshot};
    use transport::channel_owner::RetainedChannelSet;
    use transport::channel_server::RestartSignal;
    use transport::shell_server::{NoScreen, ResizeHandle};

    #[derive(Clone, Copy)]
    enum Answer {
        Unsupported,
        Running,
        Exited(Option<i32>),
        Unknown,
    }
    struct Backend {
        answer: Mutex<Answer>,
        counts: [AtomicUsize; 7],
        cleanup_ready: AtomicBool,
        zero_returns: AtomicUsize,
        notifier: Mutex<Option<ReapNotifier>>,
    }
    impl Backend {
        fn new(answer: Answer) -> Arc<Self> {
            Arc::new(Self {
                answer: Mutex::new(answer),
                counts: std::array::from_fn(|_| AtomicUsize::new(0)),
                cleanup_ready: AtomicBool::new(false),
                zero_returns: AtomicUsize::new(0),
                notifier: Mutex::new(None),
            })
        }
        fn count(&self, index: usize) -> usize {
            self.counts[index].load(Ordering::SeqCst)
        }
    }
    struct InertWait(Arc<Backend>);
    impl ChannelWait for InertWait {
        fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
            self.0.counts[0].fetch_add(1, Ordering::SeqCst);
            match *self.0.answer.lock().unwrap() {
                Answer::Unsupported => None,
                Answer::Running => Some(LeaderStatus::Running),
                Answer::Exited(code) => {
                    if code == Some(0) {
                        self.0.zero_returns.fetch_add(1, Ordering::SeqCst);
                    }
                    Some(LeaderStatus::Exited { code })
                }
                Answer::Unknown => Some(LeaderStatus::Unknown("inert backend observation".into())),
            }
        }
        fn poll_exit(&mut self) -> ChildStatus {
            self.0.counts[1].fetch_add(1, Ordering::SeqCst);
            if self.0.cleanup_ready.load(Ordering::SeqCst) {
                ChildStatus::Reaped { code: Some(0) }
            } else {
                ChildStatus::Unknown("inert cleanup not ready".into())
            }
        }
        fn active_observation(&self) -> ActiveObservation {
            self.0.counts[2].fetch_add(1, Ordering::SeqCst);
            ActiveObservation::Notification
        }
        fn set_reap_notifier(&mut self, notifier: ReapNotifier) {
            self.0.counts[3].fetch_add(1, Ordering::SeqCst);
            *self.0.notifier.lock().unwrap() = Some(notifier);
        }
        fn kill(&mut self) {
            self.0.counts[4].fetch_add(1, Ordering::SeqCst);
        }
        fn wait(self: Box<Self>) -> i32 {
            self.0.counts[5].fetch_add(1, Ordering::SeqCst);
            37
        }
        fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
            self.0.counts[6].fetch_add(1, Ordering::SeqCst);
            authority.reaped()
        }
    }
    fn wrapped(answer: Answer) -> (FixtureLeaderObserver, Box<dyn ChannelWait>, Arc<Backend>) {
        let observer = FixtureLeaderObserver::new(16);
        let backend = Backend::new(answer);
        let wait = observer
            .claim(16)
            .unwrap()
            .wrap(Box::new(InertWait(backend.clone())));
        (observer, wait, backend)
    }
    #[test]
    fn screen601_only_returned_exact_zero_can_qualify() {
        for answer in [
            Answer::Unsupported,
            Answer::Running,
            Answer::Exited(None),
            Answer::Exited(Some(1)),
            Answer::Unknown,
        ] {
            let (observer, mut wait, backend) = wrapped(answer);
            assert_eq!(observer.snapshot().leader, ObservedLeader::NotObserved);
            let _ = wait.poll_leader_status();
            assert!(!observer.snapshot().voluntary_zero());
            assert_eq!(backend.count(0), 1);
        }
        let (observer, mut wait, backend) = wrapped(Answer::Exited(Some(0)));
        assert!(!observer.snapshot().voluntary_zero());
        assert!(matches!(
            wait.poll_leader_status(),
            Some(LeaderStatus::Exited { code: Some(0) })
        ));
        assert!(observer.snapshot().voluntary_zero());
        assert_eq!(backend.count(0), 1);
        *backend.answer.lock().unwrap() = Answer::Running;
        let _ = wait.poll_leader_status();
        assert_eq!(observer.snapshot().leader, ObservedLeader::Unknown);
    }
    #[test]
    fn screen601_forwarding_never_turns_cleanup_into_leader_proof() {
        let (observer, mut wait, backend) = wrapped(Answer::Exited(Some(0)));
        assert_eq!(wait.active_observation(), ActiveObservation::Notification);
        assert_eq!(backend.count(2), 1);
        assert!(
            matches!(wait.poll_exit(), ChildStatus::Unknown(detail) if detail == "inert cleanup not ready")
        );
        assert_eq!(backend.count(1), 1);
        assert_eq!(observer.snapshot().leader, ObservedLeader::NotObserved);
        let _ = wait.poll_leader_status();
        assert!(!observer.snapshot().voluntary_zero());
        let (observer, mut wait, backend) = wrapped(Answer::Exited(Some(0)));
        wait.kill();
        let _ = wait.poll_leader_status();
        assert_eq!(backend.count(4), 1);
        assert!(!observer.snapshot().voluntary_zero());
        let (observer, wait, backend) = wrapped(Answer::Exited(Some(0)));
        assert_eq!(wait.wait(), 37);
        assert_eq!(backend.count(5), 1);
        assert!(observer.snapshot().cleanup_entered);
        let (observer, wait, backend) = wrapped(Answer::Exited(Some(0)));
        let custody = transport::channel_open::OpenCustody::new();
        let _channel = custody.protect(wait, Box::new(NoScreen)).finish(
            Box::new(std::io::empty()),
            Box::new(std::io::sink()),
            Box::new(Resize),
        );
        assert!(matches!(custody.cleanup(), CleanupStatus::Confirmed(_)));
        assert_eq!(backend.count(6), 1);
        assert!(observer.snapshot().cleanup_entered && !observer.snapshot().voluntary_zero());
    }
    #[test]
    fn screen601_unknown_poison_and_registration_conflict_fail_closed() {
        let (observer, mut wait, backend) = wrapped(Answer::Unknown);
        let _ = wait.poll_leader_status();
        *backend.answer.lock().unwrap() = Answer::Exited(Some(0));
        let _ = wait.poll_leader_status();
        assert_eq!(observer.snapshot().leader, ObservedLeader::Unknown);
        assert!(!observer.request_observation());
        let (observer, mut wait, backend) = wrapped(Answer::Exited(Some(0)));
        assert!(observer.claim(16).is_err());
        let _ = wait.poll_leader_status();
        assert!(!observer.snapshot().voluntary_zero());
        assert_eq!(backend.count(0), 1);
        let observer = FixtureLeaderObserver::new(16);
        assert!(observer.claim(17).is_err());
        assert!(!observer.snapshot().voluntary_zero());
        let (observer, mut wait, backend) = wrapped(Answer::Exited(Some(0)));
        let poison = observer.clone();
        assert!(std::panic::catch_unwind(move || {
            let _guard = poison.state.lock().unwrap();
            panic!("inert observer poison");
        })
        .is_err());
        let _ = wait.poll_leader_status();
        assert_eq!(
            backend.count(0),
            1,
            "observer failure never prevents inner forwarding"
        );
        assert!(!observer.snapshot().voluntary_zero());
    }
    struct Resize;
    impl ResizeHandle for Resize {
        fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
            Ok(())
        }
    }
    #[derive(Clone, Default)]
    struct Gate(Arc<(Mutex<bool>, Condvar)>);
    impl Gate {
        fn release(&self) {
            let (lock, ready) = &*self.0;
            *lock.lock().unwrap() = true;
            ready.notify_all();
        }
        fn wait(&self) {
            let (lock, ready) = &*self.0;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = ready.wait(released).unwrap();
            }
        }
    }
    struct ReleaseOnDrop(Gate);
    impl Drop for ReleaseOnDrop {
        fn drop(&mut self) {
            self.0.release();
        }
    }
    type Panic = Box<dyn std::any::Any + Send>;
    struct Catch<F: Future>(Pin<Box<F>>);
    impl<F: Future> Future for Catch<F> {
        type Output = Result<F::Output, Panic>;
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.0.as_mut().poll(cx)
            })) {
                Ok(Poll::Ready(value)) => Poll::Ready(Ok(value)),
                Ok(Poll::Pending) => Poll::Pending,
                Err(panic) => Poll::Ready(Err(panic)),
            }
        }
    }
    async fn yield_until(mut predicate: impl FnMut() -> bool) {
        let until = Instant::now() + Duration::from_secs(3);
        while !predicate() {
            assert!(Instant::now() < until, "owned fixture observation deadline");
            tokio::task::yield_now().await;
        }
    }
    enum Primary {
        Passed,
        Panic(Panic),
        Timeout,
    }
    struct Outcome {
        primary: Primary,
        cleanup: bool,
    }
    impl Outcome {
        fn assert_passed(self) {
            match self.primary {
                Primary::Passed => assert!(self.cleanup, "finite owned cleanup must complete"),
                Primary::Panic(panic) => {
                    if !self.cleanup {
                        eprintln!("screen601 fixture_cleanup=unconfirmed");
                    }
                    std::panic::resume_unwind(panic);
                }
                Primary::Timeout => panic!(
                    "owned fixture primary deadline; cleanup_confirmed={}",
                    self.cleanup
                ),
            }
        }
    }
    async fn owned_fixture(mode: u8) -> Outcome {
        let observer = FixtureLeaderObserver::new(16);
        let backend = Backend::new(Answer::Running);
        let registry = ChannelOpenRegistry::new(Default::default());
        let session = registry.session().unwrap();
        let identity = OpenIdentity {
            session: session.id(),
            instance: ChannelInstance::new(1).unwrap(),
            stream: 16,
            generation: 1,
            invalidation_epoch: 0,
        };
        let job = registry
            .try_reserve(
                &session,
                OpenRequestSnapshot {
                    owner: Principal {
                        uid: 1234,
                        name: "inert-fixture".into(),
                        identity: "inert".into(),
                        incarnation: 1,
                    },
                    login: [1; 16],
                    request: OpenRequest {
                        stream: 16,
                        kind: ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: false,
                        command: vec![],
                    },
                    term: None,
                    identity,
                },
            )
            .unwrap();
        let wait = observer
            .claim(16)
            .unwrap()
            .wrap(Box::new(InertWait(backend.clone())));
        let channel = job.custody().protect(wait, Box::new(NoScreen)).finish(
            Box::new(std::io::empty()),
            Box::new(std::io::sink()),
            Box::new(Resize),
        );
        let mut owner = RetainedChannelSet::new(registry);
        let (_tx, restart) = tokio::sync::watch::channel(RestartSignal::IDLE);
        owner.install(job, channel, identity, &restart).unwrap();
        let gate = Gate::default();
        let _release_on_all_exits = ReleaseOnDrop(gate.clone());
        let read_gate = gate.clone();
        let write_gate = gate.clone();
        owner
            .start_workers(
                identity.instance,
                move |mut reader| {
                    read_gate.wait();
                    let mut byte = [0];
                    assert_eq!(reader.read(&mut byte).unwrap(), 0);
                },
                move |mut writer| {
                    write_gate.wait();
                    writer.write_all(b"").unwrap();
                },
            )
            .unwrap();
        let exercise = async {
            yield_until(|| observer.snapshot().leader == ObservedLeader::Running).await;
            assert_eq!(backend.count(3), 1, "same original notifier forwarded once");
            assert!(backend.notifier.lock().unwrap().is_some());
            if mode == 1 {
                panic!("primary fixture assertion");
            }
            if mode == 2 {
                std::future::pending::<()>().await;
            }
            // Mock delivered/committed FINISH is deliberately not a status write.
            let finish_committed = true;
            assert!(finish_committed && !observer.snapshot().voluntary_zero());
            assert_eq!(
                observer.wait_for_terminal(Instant::now()).await,
                Err(ObservationFailure::Deadline)
            );
            let old_polls = backend.count(0);
            assert!(
                observer.request_observation(),
                "same owned notifier must be retained for progress"
            );
            for _ in 0..4 {
                observer.request_observation();
            }
            yield_until(|| backend.count(0) > old_polls).await;
            assert!(
                !observer.snapshot().voluntary_zero(),
                "notifications with Running are not terminal proof"
            );
            *backend.answer.lock().unwrap() = Answer::Exited(Some(0));
            // A queued owner notification may already observe the new backend value.
            // Success still requires an actual returned zero, never the input update.
            let proof = observer
                .wait_for_terminal(Instant::now() + Duration::from_secs(3))
                .await
                .expect("forwarded notifier must schedule the original owned backend");
            assert!(proof.voluntary_zero());
            assert!(backend.zero_returns.load(Ordering::SeqCst) > 0);
            assert_eq!(backend.count(4), 0);
            assert_eq!(
                backend.count(1),
                0,
                "clean completion is observed before destructive close"
            );
        };
        let limit = if mode == 2 {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(6)
        };
        let primary = match tokio::time::timeout(limit, Catch(Box::pin(exercise))).await {
            Ok(Ok(())) => Primary::Passed,
            Ok(Err(panic)) => Primary::Panic(panic),
            Err(_) => Primary::Timeout,
        };
        // Release both inert owned I/O gates even after the original assertion/timeout.
        gate.release();
        backend.cleanup_ready.store(true, Ordering::SeqCst);
        owner.close_all();
        let cleanup = tokio::time::timeout(Duration::from_secs(3), async {
            let receipt = owner.next_cleanup().await;
            let joined = owner.join_workers().await.is_ok();
            receipt.stream() == identity.stream
                && receipt.instance() == identity.instance
                && receipt.code() == Some(0)
                && receipt.workers_joined()
                && joined
                && session.occupied() == 0
        })
        .await
        .unwrap_or(false);
        Outcome { primary, cleanup }
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn screen601_exact_owner_notification_gates_finish_and_close() {
        owned_fixture(0).await.assert_passed();
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn screen601_primary_panic_releases_and_joins_owned_workers() {
        let outcome = owned_fixture(1).await;
        assert!(outcome.cleanup);
        let Primary::Panic(panic) = outcome.primary else {
            panic!("primary assertion was lost");
        };
        assert_eq!(
            panic.downcast_ref::<&str>(),
            Some(&"primary fixture assertion")
        );
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn screen601_primary_timeout_releases_and_joins_owned_workers() {
        let outcome = owned_fixture(2).await;
        assert!(outcome.cleanup && matches!(outcome.primary, Primary::Timeout));
    }
}
