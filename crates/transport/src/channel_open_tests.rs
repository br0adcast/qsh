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
    fn absorb(&mut self, _: &[u8]) {}
    fn prepare_resize(
        &mut self,
        _: terminal_size::TerminalSize,
    ) -> Result<
        Box<dyn crate::shell_server::PreparedScreenResize + '_>,
        crate::shell_server::ScreenPreparationError,
    > {
        Err(crate::shell_server::ScreenPreparationError::PreparationFailed("unused".into()))
    }
    fn repaint(&mut self) -> Vec<u8> {
        Vec::new()
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
