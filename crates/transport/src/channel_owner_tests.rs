use super::*;
use crate::auth::Principal;
use crate::channel::{ChannelKind, OpenRequest};
use crate::channel_geometry::ChannelInstance;
use crate::channel_server::{ChannelWait, ChildStatus};
use crate::shell_server::{NoScreen, ResizeHandle};
use std::sync::atomic::{AtomicBool, Ordering};

struct Wait(Arc<AtomicBool>);
impl ChannelWait for Wait {
    fn poll_exit(&mut self) -> ChildStatus {
        if self.0.load(Ordering::SeqCst) {
            ChildStatus::Reaped { code: Some(0) }
        } else {
            ChildStatus::Running
        }
    }
    fn kill(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn wait(self: Box<Self>) -> i32 {
        panic!("must use exact observation")
    }
    fn cleanup_uninstalled(
        &mut self,
        a: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus {
        self.0.store(true, Ordering::SeqCst);
        a.reaped()
    }
}
#[derive(Clone)]
struct StatusFixture {
    phase: Arc<std::sync::atomic::AtomicUsize>,
    seen: Arc<std::sync::atomic::AtomicUsize>,
    notifier: Arc<std::sync::Mutex<Option<crate::channel_server::ReapNotifier>>>,
}
struct StatusWait {
    inner: Wait,
    status: StatusFixture,
}
impl ChannelWait for StatusWait {
    fn poll_leader_status(&mut self) -> Option<crate::channel_server::LeaderStatus> {
        let phase = self.status.phase.load(Ordering::SeqCst);
        self.status.seen.store(phase, Ordering::SeqCst);
        Some(match phase {
            1 => crate::channel_server::LeaderStatus::Exited { code: Some(7) },
            2 => crate::channel_server::LeaderStatus::Unknown("synthetic unknown".into()),
            _ => crate::channel_server::LeaderStatus::Running,
        })
    }
    fn poll_exit(&mut self) -> ChildStatus {
        self.inner.poll_exit()
    }
    fn kill(&mut self) {
        self.inner.kill();
    }
    fn wait(self: Box<Self>) -> i32 {
        panic!("exact observation only")
    }
    fn set_reap_notifier(&mut self, n: crate::channel_server::ReapNotifier) {
        *self.status.notifier.lock().unwrap() = Some(n);
    }
    fn cleanup_uninstalled(
        &mut self,
        a: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus {
        self.inner.cleanup_uninstalled(a)
    }
}
struct Resize;
impl ResizeHandle for Resize {
    fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
        Ok(())
    }
}
fn ready(
    registry: &Arc<ChannelOpenRegistry>,
    epoch: u64,
) -> (
    OpenJob,
    UninstalledChannel,
    Arc<crate::channel_open::SessionOpenLedger>,
    Arc<AtomicBool>,
) {
    ready_status(registry, epoch, None)
}
fn ready_status(
    registry: &Arc<ChannelOpenRegistry>,
    epoch: u64,
    status: Option<StatusFixture>,
) -> (
    OpenJob,
    UninstalledChannel,
    Arc<crate::channel_open::SessionOpenLedger>,
    Arc<AtomicBool>,
) {
    let session = registry.session().unwrap();
    let request = OpenRequest {
        stream: 16,
        kind: ChannelKind::Shell,
        cols: 80,
        rows: 24,
        screen: false,
        command: vec![],
    };
    let job = registry
        .try_reserve(
            &session,
            crate::channel_open::OpenRequestSnapshot {
                owner: Principal {
                    uid: 1234,
                    name: "fixture".into(),
                    identity: "synthetic".into(),
                    incarnation: 1,
                },
                login: [1; 16],
                request,
                term: None,
                identity: OpenIdentity {
                    session: session.id(),
                    instance: ChannelInstance::new(1).unwrap(),
                    stream: 16,
                    generation: 1,
                    invalidation_epoch: epoch,
                },
            },
        )
        .unwrap();
    let reaped = Arc::new(AtomicBool::new(false));
    let wait: Box<dyn ChannelWait> = match status {
        Some(status) => Box::new(StatusWait {
            inner: Wait(reaped.clone()),
            status,
        }),
        None => Box::new(Wait(reaped.clone())),
    };
    let channel = job.custody().protect(wait, Box::new(NoScreen)).finish(
        Box::new(std::io::empty()),
        Box::new(std::io::sink()),
        Box::new(Resize),
    );
    (job, channel, session, reaped)
}
#[tokio::test]
async fn channel_owner_post_adoption_panic_retains_exact_custody() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut owner = RetainedChannelSet::new(registry.clone());
    let (job, channel, session, reaped) = ready(&registry, 0);
    let identity = job.request().identity;
    let (_tx, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert!(owner.install(job, channel, identity, &watch).is_ok());
        panic!("after successful adoption, before worker scheduling");
    }));
    assert!(panic.is_err());
    assert_eq!(session.occupied(), 1);
    assert!(!reaped.load(Ordering::SeqCst));
    assert_eq!(owner.channels(), 1);
    owner.close_all();
    let done = tokio::time::timeout(std::time::Duration::from_secs(3), owner.next_cleanup())
        .await
        .unwrap();
    assert_eq!(done.instance(), identity.instance);
    assert!(reaped.load(Ordering::SeqCst));
    assert_eq!(session.occupied(), 0);
}
#[tokio::test]
async fn channel_owner_rejects_stale_epoch_without_installing() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut owner = RetainedChannelSet::new(registry.clone());
    let (job, channel, session, reaped) = ready(&registry, 1);
    let identity = job.request().identity;
    let id = job.id();
    let (_tx, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
    assert!(owner.install(job, channel, identity, &watch).is_err());
    registry.cleanup(id);
    assert!(reaped.load(Ordering::SeqCst));
    assert_eq!(session.occupied(), 0);
    assert_eq!(owner.channels(), 0);
}

#[tokio::test]
async fn channel_owner_stopped_worker_cannot_publish_opened() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut owner = RetainedChannelSet::new(registry.clone());
    let (job, channel, session, _) = ready(&registry, 0);
    let identity = job.request().identity;
    let (_tx, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
    owner.install(job, channel, identity, &watch).unwrap();
    owner.start_workers(identity.instance, drop, drop).unwrap();
    owner.join_workers().await.unwrap();
    assert!(!owner.ready_to_publish(identity.instance));
    assert_eq!(session.occupied(), 1);
    owner.close_all();
    tokio::time::timeout(std::time::Duration::from_secs(3), owner.next_cleanup())
        .await
        .unwrap();
    assert_eq!(session.occupied(), 0);
}

#[tokio::test]
async fn channel_owner_wrong_registry_and_identity_keep_registered_cleanup() {
    for wrong_registry in [true, false] {
        let registry = ChannelOpenRegistry::new(Default::default());
        let target = if wrong_registry {
            ChannelOpenRegistry::new(Default::default())
        } else {
            registry.clone()
        };
        let mut owner = RetainedChannelSet::new(target);
        let (job, channel, session, reaped) = ready(&registry, 0);
        let id = job.id();
        let mut identity = job.request().identity;
        if !wrong_registry {
            identity.instance = ChannelInstance::new(2).unwrap();
        }
        let (_tx, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
        assert!(owner.install(job, channel, identity, &watch).is_err());
        assert_eq!(owner.channels(), 0);
        assert_eq!(session.occupied(), 1);
        assert!(!reaped.load(Ordering::SeqCst));
        assert!(matches!(
            registry.cleanup(id),
            crate::channel_open::CleanupStatus::Confirmed(_)
        ));
        assert_eq!(session.occupied(), 0);
    }
}
#[tokio::test]
async fn channel_owner_wrong_capsule_never_cross_installs() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut owner = RetainedChannelSet::new(registry.clone());
    let (one, channel_one, session_one, reaped_one) = ready(&registry, 0);
    let (two, channel_two, session_two, reaped_two) = ready(&registry, 0);
    let id_one = one.id();
    let id_two = two.id();
    let identity = one.request().identity;
    let (_tx, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
    assert!(owner.install(one, channel_two, identity, &watch).is_err());
    drop(channel_one);
    drop(two);
    assert_eq!(owner.channels(), 0);
    assert!(matches!(
        registry.cleanup(id_one),
        crate::channel_open::CleanupStatus::Confirmed(_)
    ));
    assert!(matches!(
        registry.cleanup(id_two),
        crate::channel_open::CleanupStatus::Confirmed(_)
    ));
    assert_eq!(session_one.occupied() + session_two.occupied(), 0);
    assert!(reaped_one.load(Ordering::SeqCst) && reaped_two.load(Ordering::SeqCst));
}
#[tokio::test]
async fn channel_owner_cancelled_ready_and_final_install_preserve_custody() {
    for cancel_after_preparation in [false, true] {
        let registry = ChannelOpenRegistry::new(Default::default());
        let mut owner = RetainedChannelSet::new(registry.clone());
        let (job, channel, session, reaped) = ready(&registry, 0);
        let id = job.id();
        let identity = job.request().identity;
        let custody = job.custody().clone();
        if !cancel_after_preparation {
            job.cancel();
            let (_tx, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
            assert!(owner.install(job, channel, identity, &watch).is_err());
        } else {
            let adopted = job.try_adopt(channel).unwrap();
            owner.channels.try_reserve(1).unwrap();
            let std::collections::hash_map::Entry::Vacant(entry) =
                owner.channels.entry(identity.stream)
            else {
                unreachable!()
            };
            let reap = owner
                .reaps
                .prepare_active(identity.stream, identity.instance.get(), 1234)
                .unwrap();
            let prepared = PreparedRetainedInstallation {
                identity,
                registry: registry.clone(),
                job_id: id,
                entry,
                reap,
            };
            custody.cancel();
            assert!(adopted
                .commit_retained(&IdleEpochGuard::initial(), &identity, prepared)
                .is_none());
        }
        assert_eq!(owner.channels(), 0);
        assert_eq!(session.occupied(), 1);
        assert!(!reaped.load(Ordering::SeqCst));
        assert!(matches!(
            registry.cleanup(id),
            crate::channel_open::CleanupStatus::Confirmed(_)
        ));
        assert_eq!(session.occupied(), 0);
    }
}
#[tokio::test]
async fn channel_owner_final_fence_wins_over_prepared_retained_target() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut owner = RetainedChannelSet::new(registry.clone());
    let (job, channel, session, _) = ready(&registry, 0);
    let id = job.id();
    let identity = job.request().identity;
    let adopted = job.try_adopt(channel).unwrap();
    owner.channels.try_reserve(1).unwrap();
    let std::collections::hash_map::Entry::Vacant(entry) = owner.channels.entry(identity.stream)
    else {
        unreachable!()
    };
    let reap = owner
        .reaps
        .prepare_active(identity.stream, identity.instance.get(), 1234)
        .unwrap();
    let prepared = PreparedRetainedInstallation {
        identity,
        registry: registry.clone(),
        job_id: id,
        entry,
        reap,
    };
    let _fence = registry.begin_restart_fence().unwrap();
    assert!(adopted
        .commit_retained(&IdleEpochGuard::initial(), &identity, prepared)
        .is_none());
    assert_eq!(owner.channels(), 0);
    assert!(matches!(
        registry.cleanup(id),
        crate::channel_open::CleanupStatus::Confirmed(_)
    ));
    assert_eq!(session.occupied(), 0);
}

struct Spawner {
    registry: Arc<ChannelOpenRegistry>,
    calls: Arc<std::sync::atomic::AtomicUsize>,
    reaped: Arc<AtomicBool>,
}
impl crate::channel_server::ChannelSpawner for Spawner {
    fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
        self.registry.clone()
    }
    fn spawn(
        &self,
        _: &Principal,
        _: crate::session_manager::LoginId,
        _: &OpenRequest,
        _: Option<&str>,
        custody: &crate::channel_open::OpenCustody,
    ) -> Result<UninstalledChannel, crate::channel_open::SpawnFailure> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(custody
            .protect(Box::new(Wait(self.reaped.clone())), Box::new(NoScreen))
            .finish(
                Box::new(std::io::empty()),
                Box::new(std::io::sink()),
                Box::new(Resize),
            ))
    }
}
#[tokio::test]
async fn channel_owner_executor_cancel_before_creation_never_calls_backend() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let (job, channel, session, _) = ready(&registry, 0);
    // Use only its request; this first protected fixture is cleaned exactly.
    let snapshot = crate::channel_open::OpenRequestSnapshot {
        owner: job.request().owner.clone(),
        login: job.request().login,
        request: job.request().request.clone(),
        term: None,
        identity: job.request().identity,
    };
    let old = job.id();
    drop(channel);
    drop(job);
    registry.cleanup(old);
    let fresh = registry.try_reserve(&session, snapshot).unwrap();
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let executor = crate::channel_open::ChannelOpenExecutor::new(
        Arc::new(Spawner {
            registry: registry.clone(),
            calls: calls.clone(),
            reaped: Arc::new(AtomicBool::new(false)),
        }),
        registry.clone(),
    );
    fresh.cancel();
    executor.submit(&fresh).unwrap();
    fresh.take_worker().unwrap().await.unwrap();
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert_eq!(session.occupied(), 0);
    assert_eq!(registry.outstanding(), 0);
}

#[tokio::test]
async fn channel_owner_catalog_requires_observed_running_and_latches_exit_unknown_exact_instance() {
    use std::sync::{atomic::AtomicUsize, Condvar, Mutex};
    for refused in [1, 2] {
        let registry = ChannelOpenRegistry::new(Default::default());
        let mut owner = RetainedChannelSet::new(registry.clone());
        let status = StatusFixture {
            phase: Arc::new(AtomicUsize::new(0)),
            seen: Arc::new(AtomicUsize::new(99)),
            notifier: Arc::new(Mutex::new(None)),
        };
        let (job, channel, _, reaped) = ready_status(&registry, 0, Some(status.clone()));
        let identity = job.request().identity;
        let (_, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
        owner.install(job, channel, identity, &watch).unwrap();
        assert!(!owner.catalog_active(identity.instance));
        let held = Arc::new((Mutex::new(false), Condvar::new()));
        let read = held.clone();
        let write = held.clone();
        owner
            .start_workers(
                identity.instance,
                move |_reader| {
                    let mut done = read.0.lock().unwrap();
                    while !*done {
                        done = read.1.wait(done).unwrap();
                    }
                },
                move |_writer| {
                    let mut done = write.0.lock().unwrap();
                    while !*done {
                        done = write.1.wait(done).unwrap();
                    }
                },
            )
            .unwrap();
        let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while !owner.catalog_active(identity.instance) {
            assert!(std::time::Instant::now() < until);
            tokio::task::yield_now().await;
        }
        assert!(!owner.catalog_active(ChannelInstance::new(2).unwrap()));
        status.phase.store(refused, Ordering::SeqCst);
        status.notifier.lock().unwrap().as_ref().unwrap().notify();
        while status.seen.load(Ordering::SeqCst) != refused
            || owner.catalog_active(identity.instance)
        {
            assert!(std::time::Instant::now() < until);
            tokio::task::yield_now().await;
        }
        status.phase.store(3, Ordering::SeqCst);
        status.notifier.lock().unwrap().as_ref().unwrap().notify();
        while status.seen.load(Ordering::SeqCst) != 3 {
            assert!(std::time::Instant::now() < until);
            tokio::task::yield_now().await;
        }
        assert!(
            !owner.catalog_active(identity.instance),
            "late Running overwrote a latched refusal"
        );
        reaped.store(true, Ordering::SeqCst);
        *held.0.lock().unwrap() = true;
        held.1.notify_all();
        owner.close_all();
        tokio::time::timeout(std::time::Duration::from_secs(3), owner.next_cleanup())
            .await
            .unwrap();
        owner.join_workers().await.unwrap();
        assert!(!owner.catalog_active(identity.instance));
    }
}

#[tokio::test]
async fn channel_owner_prepared_target_retains_registered_resources_until_guarded_commit() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut owner = RetainedChannelSet::new(registry.clone());
    let (job, channel, session, reaped) = ready(&registry, 0);
    let identity = job.request().identity;
    let prepared = owner.prepare(job, channel, identity).unwrap();
    assert_eq!(session.occupied(), 1);
    assert!(!reaped.load(Ordering::SeqCst));
    let (_, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
    let epoch = installation_epoch(&watch).unwrap();
    prepared.commit(&epoch).unwrap();
    drop(epoch);
    assert_eq!(owner.channels(), 1);
    assert_eq!(session.occupied(), 1);
    owner.close_all();
    tokio::time::timeout(std::time::Duration::from_secs(2), owner.next_cleanup())
        .await
        .unwrap();
    assert_eq!(session.occupied(), 0);
}

#[tokio::test]
async fn channel_owner_model_transfer_is_one_time_exact_and_does_not_extract_custody() {
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut owner = RetainedChannelSet::new(registry.clone());
    let (job, channel, session, reaped) = ready(&registry, 0);
    let identity = job.request().identity;
    let (_, watch) = tokio::sync::watch::channel(RestartSignal::IDLE);
    owner.install(job, channel, identity, &watch).unwrap();
    let mut wrong = identity;
    wrong.generation += 1;
    assert!(owner.take_model(wrong).is_err());
    let (model, resize) = owner.take_model(identity).unwrap();
    assert!(!model.has_screen());
    assert!(owner.take_model(identity).is_err());
    assert_eq!(session.occupied(), 1);
    assert!(!reaped.load(Ordering::SeqCst));
    drop(model);
    drop(resize);
    owner.close_all();
    owner.next_cleanup().await;
    assert_eq!(session.occupied(), 0);
    assert!(reaped.load(Ordering::SeqCst));
}
