use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[derive(Default)]
struct Observation {
    waits: AtomicUsize,
    wait_drops: AtomicUsize,
    screen_drops: AtomicUsize,
    confirmed: AtomicBool,
    panic_cleanup: AtomicBool,
}

struct Wait(Arc<Observation>);
impl Drop for Wait {
    fn drop(&mut self) {
        self.0.wait_drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl ChannelWait for Wait {
    fn poll_exit(&mut self) -> crate::channel_server::ChildStatus {
        crate::channel_server::ChildStatus::Reaped { code: None }
    }
    fn kill(&mut self) {}
    fn wait(self: Box<Self>) -> i32 {
        -1
    }
    fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
        self.0.waits.fetch_add(1, Ordering::SeqCst);
        assert!(
            !self.0.panic_cleanup.swap(false, Ordering::SeqCst),
            "injected cleanup unwind"
        );
        if self.0.confirmed.load(Ordering::SeqCst) {
            authority.reaped()
        } else {
            CleanupStatus::Unknown
        }
    }
}

struct Screen(Arc<Observation>);
impl Drop for Screen {
    fn drop(&mut self) {
        self.0.screen_drops.fetch_add(1, Ordering::SeqCst);
    }
}
impl SessionScreen for Screen {
    fn absorb(&mut self, _: &[u8]) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
        Ok(Vec::new())
    }
    fn flush_pending_output(&mut self) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
        Ok(Vec::new())
    }
    fn prepare_resize(
        &mut self,
        _: terminal_size::TerminalSize,
    ) -> Result<
        Box<dyn crate::shell_server::PreparedScreenResize + '_>,
        crate::shell_server::ScreenPreparationError,
    > {
        Err(crate::shell_server::ScreenPreparationError::PreparationFailed("unused".into()))
    }
    fn repaint(
        &mut self,
    ) -> Result<crate::shell_server::ScreenRepaint, crate::shell_server::ScreenReplyError> {
        Ok(crate::shell_server::ScreenRepaint {
            bytes: Vec::new(),
            replies: Vec::new(),
        })
    }
}
struct Resize;
impl ResizeHandle for Resize {
    fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
        Ok(())
    }
}

fn protected() -> (OpenCustody, ConstructionGuard, Arc<Observation>) {
    let observation = Arc::new(Observation::default());
    let custody = OpenCustody::new();
    let guard = custody.protect(
        Box::new(Wait(observation.clone())),
        Box::new(Screen(observation.clone())),
    );
    (custody, guard, observation)
}

#[test]
fn open24_cleanup_error_retains_capsule() {
    let (custody, guard, observation) = protected();
    drop(guard);
    assert!(matches!(custody.cleanup(), CleanupStatus::Unknown));
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 0);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 0);
    observation.confirmed.store(true, Ordering::SeqCst);
    assert!(matches!(custody.cleanup(), CleanupStatus::Confirmed(_)));
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 1);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 1);
}

#[test]
fn open24_unwind_after_child_creation_retains_custody() {
    let observation = Arc::new(Observation::default());
    let custody = OpenCustody::new();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = custody.protect(
            Box::new(Wait(observation.clone())),
            Box::new(Screen(observation.clone())),
        );
        panic!("injected descriptor preparation unwind");
    }));
    assert!(result.is_err());
    assert!(custody.is_cancelled());
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 0);
    observation.confirmed.store(true, Ordering::SeqCst);
    assert!(matches!(custody.cleanup(), CleanupStatus::Confirmed(_)));
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 1);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 1);
}

#[test]
fn open24_dropped_success_is_cancelled_not_discarded() {
    let (custody, guard, observation) = protected();
    let success = guard.finish(
        Box::new(std::io::empty()),
        Box::new(std::io::sink()),
        Box::new(Resize),
    );
    assert!(!custody.is_cancelled());
    drop(success);
    assert!(custody.is_cancelled());
    assert_eq!(
        observation.waits.load(Ordering::SeqCst),
        0,
        "Drop must not wait on an async thread"
    );
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 0);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 0);
    observation.confirmed.store(true, Ordering::SeqCst);
    assert!(matches!(custody.cleanup(), CleanupStatus::Confirmed(_)));
    assert_eq!(observation.waits.load(Ordering::SeqCst), 1);
}

#[test]
fn open24_cleanup_unwind_restores_the_exclusive_resource_lease() {
    let (custody, guard, observation) = protected();
    drop(guard);
    observation.panic_cleanup.store(true, Ordering::SeqCst);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| custody.cleanup())).is_err());
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 0);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 0);
    observation.confirmed.store(true, Ordering::SeqCst);
    assert!(matches!(custody.cleanup(), CleanupStatus::Confirmed(_)));
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 1);
}

fn request(session: &SessionOpenLedger, uid: u32, instance: u64) -> OpenRequestSnapshot {
    OpenRequestSnapshot {
        owner: crate::auth::Principal {
            uid,
            name: format!("alias-{instance}"),
            identity: "fixture".into(),
            incarnation: 0,
        },
        login: [0; 16],
        request: crate::channel::OpenRequest {
            stream: 16,
            kind: crate::channel::ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        },
        term: None,
        identity: OpenIdentity {
            session: session.id(),
            stream: 16,
            instance: crate::channel_geometry::ChannelInstance::new(instance).unwrap(),
            generation: 0,
            invalidation_epoch: 0,
        },
    }
}

#[test]
fn open24_registry_bounds_global_and_numeric_uid_before_work() {
    let registry = ChannelOpenRegistry::new(OpenLimits::default());
    let mut jobs = Vec::new();
    for uid in 1..=4 {
        for instance in 1..=8 {
            let session = registry.session().unwrap();
            jobs.push(
                registry
                    .try_reserve(&session, request(&session, uid, instance))
                    .unwrap(),
            );
        }
        let session = registry.session().unwrap();
        assert!(
            registry
                .try_reserve(&session, request(&session, uid, 9))
                .is_err(),
            "aliases of one numeric UID share eight jobs"
        );
    }
    let session = registry.session().unwrap();
    assert!(
        registry
            .try_reserve(&session, request(&session, 5, 1))
            .is_err(),
        "32 admitted jobs exhaust the global budget"
    );
    assert_eq!(registry.outstanding(), 32);
    drop(jobs);
    assert_eq!(
        registry.outstanding(),
        32,
        "dropping callers cannot refund unknown jobs"
    );
}

#[test]
fn open24_registry_unknown_survives_caller_drop_until_exact_proof() {
    let registry = ChannelOpenRegistry::new(OpenLimits {
        global: 1,
        per_uid: 1,
    });
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 7, 1))
        .unwrap();
    let id = job.id();
    let observation = Arc::new(Observation::default());
    drop(job.custody().protect(
        Box::new(Wait(observation.clone())),
        Box::new(Screen(observation.clone())),
    ));
    drop(job);
    assert!(matches!(registry.cleanup(id), CleanupStatus::Unknown));
    assert_eq!(session.occupied(), 1);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 0);
    assert!(registry
        .try_reserve(&session, request(&session, 7, 2))
        .is_err());
    let unrelated = OpenCustody::new().refuse_before_creation("unrelated".into());
    let SpawnCleanup::NoChild(proof) = unrelated.cleanup else {
        unreachable!()
    };
    assert!(
        !registry.finish_cleanup(id, &proof),
        "a different capsule cannot release this job"
    );
    observation.confirmed.store(true, Ordering::SeqCst);
    let CleanupStatus::Confirmed(proof) = registry.cleanup(id) else {
        panic!("exact reap expected")
    };
    assert!(
        !registry.finish_cleanup(id, &proof),
        "duplicate receipt cannot refund twice"
    );
    assert_eq!(registry.outstanding(), 0);
    assert_eq!(session.occupied(), 0);
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 1);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 1);
    assert!(registry
        .try_reserve(&session, request(&session, 7, 2))
        .is_ok());
}

#[test]
fn open24_registry_session_cap_counts_cancelled_unresolved_jobs() {
    let registry = ChannelOpenRegistry::new(OpenLimits {
        global: 32,
        per_uid: 32,
    });
    let session = registry.session().unwrap();
    for instance in 1..=8 {
        drop(
            registry
                .try_reserve(&session, request(&session, 1, instance))
                .unwrap(),
        );
    }
    assert_eq!(session.occupied(), 8);
    assert!(registry
        .try_reserve(&session, request(&session, 2, 9))
        .is_err());
}

#[test]
fn open24_registry_adoption_transfers_slot_without_refunding_it() {
    let registry = ChannelOpenRegistry::new(OpenLimits {
        global: 1,
        per_uid: 1,
    });
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 1, 1))
        .unwrap();
    let observation = Arc::new(Observation::default());
    let ready = job
        .custody()
        .protect(
            Box::new(Wait(observation.clone())),
            Box::new(Screen(observation.clone())),
        )
        .finish(
            Box::new(std::io::empty()),
            Box::new(std::io::sink()),
            Box::new(Resize),
        );
    let (channel, slot) = match job.adopt(ready) {
        Ok(value) => value,
        Err(_) => panic!("live ready job adopts"),
    };
    assert_eq!(registry.outstanding(), 0);
    assert_eq!(session.occupied(), 1);
    let next = registry
        .try_reserve(&session, request(&session, 1, 2))
        .unwrap();
    assert_eq!(session.occupied(), 2);
    let failure = next
        .custody()
        .refuse_before_creation("fixture refusal".into());
    let SpawnCleanup::NoChild(proof) = failure.cleanup else {
        unreachable!()
    };
    assert!(registry.finish_cleanup(next.id(), &proof));
    assert_eq!(session.occupied(), 1);
    drop((channel, slot));
    assert_eq!(session.occupied(), 0);
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 1);
}

#[test]
fn open24_cleanup_does_not_take_resources_during_construction() {
    let (custody, guard, observation) = protected();
    observation.confirmed.store(true, Ordering::SeqCst);
    assert!(matches!(custody.cleanup(), CleanupStatus::Unknown));
    assert_eq!(observation.waits.load(Ordering::SeqCst), 0);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 0);
    drop(guard);
    assert!(matches!(custody.cleanup(), CleanupStatus::Confirmed(_)));
    assert_eq!(observation.waits.load(Ordering::SeqCst), 1);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 1);
}

#[test]
fn open24_late_receipt_retry_releases_the_exact_retained_registration() {
    let registry = ChannelOpenRegistry::new(OpenLimits {
        global: 1,
        per_uid: 1,
    });
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 9, 1))
        .unwrap();
    let observation = Arc::new(Observation::default());
    let custody = job.custody().clone();
    drop(custody.protect(
        Box::new(Wait(observation.clone())),
        Box::new(Screen(observation.clone())),
    ));
    let receipt = custody.cleanup_notifier();
    drop(job);
    assert!(matches!(receipt.retry_cleanup(), CleanupStatus::Unknown));
    assert_eq!(registry.outstanding(), 1);
    observation.confirmed.store(true, Ordering::SeqCst);
    assert!(matches!(
        receipt.retry_cleanup(),
        CleanupStatus::Confirmed(_)
    ));
    assert_eq!(registry.outstanding(), 0);
    assert_eq!(session.occupied(), 0);
    assert!(matches!(
        receipt.retry_cleanup(),
        CleanupStatus::Confirmed(_)
    ));
    assert_eq!(
        session.occupied(),
        0,
        "duplicate receipt cannot refund twice"
    );
}

#[test]
fn open24_receipt_during_cleanup_is_retried_before_returning_unknown() {
    use std::sync::mpsc;
    struct RacingWait {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
        first: bool,
    }
    impl ChannelWait for RacingWait {
        fn poll_exit(&mut self) -> crate::channel_server::ChildStatus {
            crate::channel_server::ChildStatus::Reaped { code: None }
        }
        fn kill(&mut self) {}
        fn wait(self: Box<Self>) -> i32 {
            -1
        }
        fn cleanup_uninstalled(&mut self, authority: &CleanupAuthority<'_>) -> CleanupStatus {
            if self.first {
                self.first = false;
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                CleanupStatus::Unknown
            } else {
                authority.reaped()
            }
        }
    }
    let registry = ChannelOpenRegistry::new(OpenLimits {
        global: 1,
        per_uid: 1,
    });
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 9, 1))
        .unwrap();
    let (entered, entered_rx) = mpsc::channel();
    let (release, release_rx) = mpsc::channel();
    let notifier = job.custody().cleanup_notifier();
    drop(job.custody().protect(
        Box::new(RacingWait {
            entered,
            release: release_rx,
            first: true,
        }),
        Box::new(crate::shell_server::NoScreen),
    ));
    let worker = std::thread::spawn(move || job.cleanup());
    let did_enter = entered_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .is_ok();
    let concurrent = if did_enter {
        notifier.retry_cleanup()
    } else {
        CleanupStatus::Unknown
    };
    let _ = release.send(());
    let result = worker.join().unwrap();
    assert!(did_enter);
    assert!(matches!(concurrent, CleanupStatus::Unknown));
    assert!(matches!(result, CleanupStatus::Confirmed(_)));
    assert_eq!(registry.outstanding(), 0);
    assert_eq!(session.occupied(), 0);
}

#[tokio::test(flavor = "current_thread")]
async fn open24_executor_does_not_block_runtime_while_spawn_is_entered() {
    use crate::channel_server::ChannelSpawner;
    use std::sync::{mpsc, Condvar};
    struct BlockingSpawn {
        registry: Arc<ChannelOpenRegistry>,
        entered: mpsc::Sender<()>,
        entered_async: Arc<tokio::sync::Notify>,
        release: Arc<(Mutex<bool>, Condvar)>,
        observation: Arc<Observation>,
    }
    impl ChannelSpawner for BlockingSpawn {
        fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            _: &crate::auth::Principal,
            _: crate::session_manager::LoginId,
            _: &crate::channel::OpenRequest,
            _: Option<&str>,
            custody: &OpenCustody,
        ) -> Result<UninstalledChannel, SpawnFailure> {
            self.entered.send(()).unwrap();
            self.entered_async.notify_one();
            let (lock, wake) = &*self.release;
            let mut released = lock.lock().unwrap();
            while !*released {
                released = wake.wait(released).unwrap();
            }
            drop(released);
            Ok(custody
                .protect(
                    Box::new(Wait(self.observation.clone())),
                    Box::new(Screen(self.observation.clone())),
                )
                .finish(
                    Box::new(std::io::empty()),
                    Box::new(std::io::sink()),
                    Box::new(Resize),
                ))
        }
    }
    let registry = ChannelOpenRegistry::new(OpenLimits {
        global: 1,
        per_uid: 1,
    });
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 9, 1))
        .unwrap();
    let (entered, entered_rx) = mpsc::channel();
    let entered_async = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new((Mutex::new(false), Condvar::new()));
    let observation = Arc::new(Observation::default());
    observation.confirmed.store(true, Ordering::SeqCst);
    let executor = ChannelOpenExecutor::new(
        Arc::new(BlockingSpawn {
            registry: registry.clone(),
            entered,
            entered_async: entered_async.clone(),
            release: release.clone(),
            observation,
        }),
        registry.clone(),
    );
    let (heartbeat_tx, heartbeat_rx) = mpsc::channel();
    let heartbeat = tokio::spawn(async move {
        entered_async.notified().await;
        let _ = heartbeat_tx.send(());
    });
    let watchdog = std::thread::spawn(move || {
        let entered = entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .is_ok();
        let progressed = entered
            && heartbeat_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .is_ok();
        let (lock, wake) = &*release;
        *lock.lock().unwrap() = true;
        wake.notify_all();
        (entered, progressed)
    });
    executor.submit(&job).unwrap();
    // Joining a std thread directly here would itself block this current-thread runtime.
    let observed = tokio::task::spawn_blocking(move || watchdog.join().unwrap())
        .await
        .unwrap();
    heartbeat.await.unwrap();
    job.cancel();
    if let Some(worker) = job.take_worker() {
        worker.await.unwrap();
    }
    job.cleanup();
    assert_eq!(registry.outstanding(), 0);
    assert_eq!(observed, (true, true));
}

struct ExecutorSpawn {
    registry: Arc<ChannelOpenRegistry>,
    observation: Arc<Observation>,
    calls: Arc<AtomicUsize>,
    panic_after_protect: bool,
}
impl crate::channel_server::ChannelSpawner for ExecutorSpawn {
    fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
        self.registry.clone()
    }
    fn spawn(
        &self,
        _: &crate::auth::Principal,
        _: crate::session_manager::LoginId,
        _: &crate::channel::OpenRequest,
        _: Option<&str>,
        custody: &OpenCustody,
    ) -> Result<UninstalledChannel, SpawnFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let guard = custody.protect(
            Box::new(Wait(self.observation.clone())),
            Box::new(Screen(self.observation.clone())),
        );
        assert!(
            !self.panic_after_protect,
            "injected constructor panic after custody"
        );
        Ok(guard.finish(
            Box::new(std::io::empty()),
            Box::new(std::io::sink()),
            Box::new(Resize),
        ))
    }
}
fn executor_fixture(
    panic_after_protect: bool,
) -> (
    Arc<ChannelOpenRegistry>,
    ChannelOpenExecutor,
    OpenJob,
    Arc<Observation>,
    Arc<AtomicUsize>,
) {
    let registry = ChannelOpenRegistry::new(OpenLimits {
        global: 1,
        per_uid: 1,
    });
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 9, 1))
        .unwrap();
    let observation = Arc::new(Observation::default());
    let calls = Arc::new(AtomicUsize::new(0));
    let executor = ChannelOpenExecutor::new(
        Arc::new(ExecutorSpawn {
            registry: registry.clone(),
            observation: observation.clone(),
            calls: calls.clone(),
            panic_after_protect,
        }),
        registry.clone(),
    );
    (registry, executor, job, observation, calls)
}
async fn worker_is_parked(job: &OpenJob) {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            // Reading under the same mutex proves the worker released it in Condvar::wait.
            if job.custody().inner.state.lock().unwrap().worker_waiting {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("worker reached its adoption/cancellation wait");
}

#[tokio::test(flavor = "current_thread")]
async fn open24_executor_receipt_wakes_the_parked_resource_owner() {
    let (registry, executor, job, observation, _) = executor_fixture(false);
    executor.submit(&job).unwrap();
    worker_is_parked(&job).await;
    let mut worker = job.take_worker().unwrap();
    observation.confirmed.store(true, Ordering::SeqCst);
    let receipt = job.custody().cleanup_notifier();
    assert!(matches!(
        receipt.retry_cleanup(),
        CleanupStatus::Confirmed(_)
    ));
    let completed = tokio::time::timeout(std::time::Duration::from_secs(2), &mut worker).await;
    let finished_without_second_signal = completed.is_ok();
    if let Ok(result) = completed {
        result.unwrap();
    } else {
        job.cancel();
        worker.await.unwrap();
    }
    assert_eq!(registry.outstanding(), 0);
    assert!(
        finished_without_second_signal,
        "receipt freed accounting but stranded its blocking worker"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn open24_executor_constructor_panic_keeps_unknown_until_late_receipt() {
    let (registry, executor, job, observation, calls) = executor_fixture(true);
    let receipt = job.custody().cleanup_notifier();
    executor.submit(&job).unwrap();
    job.take_worker().unwrap().await.unwrap();
    assert!(
        matches!(job.take_outcome(), Some(OpenOutcome::Failed(reason)) if reason == "channel creation failed")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(registry.outstanding(), 1);
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 0);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 0);
    drop(job);
    observation.confirmed.store(true, Ordering::SeqCst);
    assert!(matches!(
        receipt.retry_cleanup(),
        CleanupStatus::Confirmed(_)
    ));
    assert_eq!(registry.outstanding(), 0);
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 1);
}

#[tokio::test(flavor = "current_thread")]
async fn open24_executor_ready_receiver_drop_reaps_without_orphaning_result() {
    let (registry, executor, job, observation, _) = executor_fixture(false);
    observation.confirmed.store(true, Ordering::SeqCst);
    executor.submit(&job).unwrap();
    worker_is_parked(&job).await;
    let worker = job.take_worker().unwrap();
    drop(job);
    worker.await.unwrap();
    assert_eq!(registry.outstanding(), 0);
    assert_eq!(observation.screen_drops.load(Ordering::SeqCst), 1);
    assert_eq!(observation.wait_drops.load(Ordering::SeqCst), 1);
}

#[test]
fn open24_executor_queued_cancellation_never_calls_backend() {
    use std::sync::mpsc;
    struct Release(Option<mpsc::Sender<()>>);
    impl Drop for Release {
        fn drop(&mut self) {
            if let Some(tx) = self.0.take() {
                let _ = tx.send(());
            }
        }
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap();
    runtime.block_on(async {
        let (registry, executor, job, _, calls) = executor_fixture(false);
        let (entered, entered_rx) = mpsc::channel();
        let (release, release_rx) = mpsc::channel();
        let release = Release(Some(release));
        let occupant = tokio::task::spawn_blocking(move || {
            entered.send(()).unwrap();
            release_rx.recv().unwrap();
        });
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        executor.submit(&job).unwrap();
        assert!(
            executor.submit(&job).is_err(),
            "one admitted job cannot schedule twice"
        );
        job.cancel();
        assert_eq!(registry.outstanding(), 1);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        drop(release);
        occupant.await.unwrap();
        job.take_worker().unwrap().await.unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(registry.outstanding(), 0);
    });
}

#[test]
fn open24_factory_fence_stops_admission_and_cancels_existing_jobs() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 1, 1))
        .unwrap();
    let fence = registry.begin_restart_fence().unwrap();
    let cancelled = job.custody().is_cancelled();
    let next = registry.try_reserve(&session, request(&session, 2, 2));
    let refused = matches!(next, Err(OpenRefusal::Restarting));
    if let Ok(next) = next {
        next.custody()
            .refuse_before_creation("fixture cleanup".into());
        next.cleanup();
    }
    job.custody()
        .refuse_before_creation("fixture cleanup".into());
    job.cleanup();
    fence.reopen();
    assert!(refused, "factory accepted admission after its fence");
    assert!(cancelled, "factory fence left a pending constructor live");
}

#[test]
fn open24_factory_fence_refuses_exec_until_exact_receipt() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 1, 1))
        .unwrap();
    let observation = Arc::new(Observation::default());
    drop(job.custody().protect(
        Box::new(Wait(observation.clone())),
        Box::new(Screen(observation.clone())),
    ));
    let id = job.id();
    drop(job); // The runner/receiver is gone; the factory still owns cleanup.
    let fence = registry.begin_restart_fence().unwrap();
    assert!(matches!(registry.cleanup(id), CleanupStatus::Unknown));
    let premature_permit = fence.wait_until(std::time::Instant::now()).is_some();
    let still_charged = (registry.outstanding(), session.occupied());
    observation.confirmed.store(true, Ordering::SeqCst);
    registry.cleanup(id);
    assert!(fence.wait_until(std::time::Instant::now()).is_some());
    fence.reopen();
    assert_eq!(still_charged, (1, 1));
    assert!(!premature_permit, "unknown cleanup granted an exec permit");
}

#[test]
fn open24_factory_fence_rejects_ready_adoption_before_watch_publication() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 1, 1))
        .unwrap();
    let id = job.id();
    let observation = Arc::new(Observation::default());
    let ready = job
        .custody()
        .protect(
            Box::new(Wait(observation.clone())),
            Box::new(Screen(observation.clone())),
        )
        .finish(
            Box::new(std::io::empty()),
            Box::new(std::io::sink()),
            Box::new(Resize),
        );
    let fence = registry.begin_restart_fence().unwrap();
    // No watch announcement exists. The factory fence must itself refuse this move.
    let refused = match job.adopt(ready) {
        Err(ready) => {
            drop(ready);
            true
        }
        Ok((channel, slot)) => {
            drop((channel, slot));
            false
        }
    };
    observation.confirmed.store(true, Ordering::SeqCst);
    registry.cleanup(id);
    fence.reopen();
    assert!(refused, "ready job adopted across the factory fence");
}

#[test]
fn cleanup143_snapshot_preserves_healthy_construction_and_exact_canceled_charge() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 7, 1))
        .unwrap();
    let observation = Arc::new(Observation::default());
    let guard = job.custody().protect(
        Box::new(Wait(observation.clone())),
        Box::new(Screen(observation.clone())),
    );
    for _ in 0..3 {
        let snapshot = registry.cleanup_snapshot().unwrap();
        assert_eq!(snapshot.healthy_pending_opens, 1);
        assert!(!snapshot.has_cleanup_debt());
        assert!(!job.custody().is_cancelled());
    }
    assert_eq!(observation.waits.load(Ordering::SeqCst), 0);
    drop(guard);
    let snapshot = registry.cleanup_snapshot().unwrap();
    assert_eq!(snapshot.canceled_opens, 1);
    assert_eq!(snapshot.unique_cleanup_debt, 1);
    assert_eq!(session.occupied(), 1);
    observation.confirmed.store(true, Ordering::SeqCst);
    assert!(matches!(job.cleanup(), CleanupStatus::Confirmed(_)));
    assert_eq!(registry.cleanup_snapshot().unwrap().unique_cleanup_debt, 0);
    assert_eq!(session.occupied(), 0);
}

#[test]
fn cleanup143_try_snapshot_discards_partial_counts_on_capsule_contention() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(&session, request(&session, 7, 1))
        .unwrap();
    let held = job.custody().inner.state.lock().unwrap();
    assert!(registry.try_cleanup_snapshot().is_none());
    drop(held);
    assert_eq!(
        registry
            .try_cleanup_snapshot()
            .unwrap()
            .healthy_pending_opens,
        1
    );
    let failure = job.custody().refuse_before_creation("owned fixture".into());
    let SpawnCleanup::NoChild(proof) = failure.cleanup else {
        unreachable!()
    };
    assert!(registry.finish_cleanup(job.id(), &proof));
}
