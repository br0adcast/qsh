use super::*;
use crate::channel_server::LeaderStatus;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};

struct ActiveWait {
    complete: Arc<AtomicBool>,
    entered: mpsc::SyncSender<()>,
}
impl ChannelWait for ActiveWait {
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        let _ = self.entered.try_send(());
        Some(LeaderStatus::Running)
    }
    fn poll_exit(&mut self) -> ChildStatus {
        let _ = self.entered.try_send(());
        if self.complete.load(Ordering::SeqCst) {
            ChildStatus::Reaped { code: Some(0) }
        } else {
            ChildStatus::Running
        }
    }
    fn kill(&mut self) {
        self.complete.store(true, Ordering::SeqCst);
    }
    fn wait(self: Box<Self>) -> i32 {
        panic!("exclusive polling owner required")
    }
    fn cleanup_uninstalled(
        &mut self,
        _: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus {
        crate::channel_open::CleanupStatus::Unknown
    }
}
fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(1)
        .build()
        .unwrap()
}

#[test]
fn active39_observation_keeps_pending_credit_and_releases_blocking_worker() {
    let runtime = runtime();
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut reaps = ReapSet::new(registry.clone());
    let complete = Arc::new(AtomicBool::new(false));
    let (entered, observed) = mpsc::sync_channel(1);
    runtime.block_on(async {
        reaps.start_active(
            16,
            1,
            Box::new(ActiveWait {
                complete: complete.clone(),
                entered,
            }),
            None,
        );
        reaps.observe_active();
    });
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    let pending = registry.outstanding();
    let (finished, progress) = mpsc::sync_channel(1);
    runtime.spawn_blocking(move || {
        let _ = finished.send(());
    });
    let progressed = progress.recv_timeout(Duration::from_millis(250)).is_ok();
    // Cleanup precedes assertions even on the defective permanent-worker path.
    complete.store(true, Ordering::SeqCst);
    reaps.stop_all();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), reaps.next())
            .await
            .unwrap();
    });
    drop(reaps);
    runtime.shutdown_timeout(Duration::from_secs(2));
    assert_eq!(
        pending, 0,
        "a live installed observer must not consume pending-open credit"
    );
    assert!(
        progressed,
        "a live installed observer retained the only blocking worker"
    );
}

#[test]
fn active39_restart_fence_does_not_stop_live_channel_before_retirement() {
    let runtime = runtime();
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut reaps = ReapSet::new(registry.clone());
    let complete = Arc::new(AtomicBool::new(false));
    let (entered, observed) = mpsc::sync_channel(1);
    runtime.block_on(async {
        reaps.start_active(
            16,
            1,
            Box::new(ActiveWait {
                complete: complete.clone(),
                entered,
            }),
            None,
        );
        reaps.observe_active();
    });
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    let fence = registry.begin_restart_fence().unwrap();
    std::thread::sleep(Duration::from_millis(30));
    let killed_before_retirement = complete.load(Ordering::SeqCst);
    let prepared = fence.wait_until(std::time::Instant::now()).is_some();
    complete.store(true, Ordering::SeqCst);
    reaps.stop_all();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), reaps.next())
            .await
            .unwrap();
    });
    drop(reaps);
    drop(fence);
    runtime.shutdown_timeout(Duration::from_secs(2));
    assert!(
        !killed_before_retirement,
        "announcement must not stop an active installed channel"
    );
    assert!(
        prepared,
        "active ownership must not become pending-open preparation debt"
    );
}

struct ExitedLeaderWait(ActiveWait);
impl ChannelWait for ExitedLeaderWait {
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        let _ = self.0.entered.try_send(());
        Some(LeaderStatus::Exited { code: Some(7) })
    }
    fn poll_exit(&mut self) -> ChildStatus {
        self.0.poll_exit()
    }
    fn kill(&mut self) {}
    fn wait(self: Box<Self>) -> i32 {
        panic!("exclusive polling owner required")
    }
    fn cleanup_uninstalled(
        &mut self,
        _: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus {
        crate::channel_open::CleanupStatus::Unknown
    }
}

#[test]
fn active39_leader_status_precedes_held_cleanup_without_refunding_owner() {
    let runtime = runtime();
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut reaps = ReapSet::new(registry.clone());
    let complete = Arc::new(AtomicBool::new(false));
    let (entered, observed) = mpsc::sync_channel(1);
    runtime.block_on(async {
        reaps.start_active(
            16,
            1,
            Box::new(ExitedLeaderWait(ActiveWait {
                complete: complete.clone(),
                entered,
            })),
            None,
        );
        reaps.observe_active();
    });
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    let status = runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(250), reaps.next_event()).await
    });
    let valid_status = matches!(
        status,
        Ok(ReapEvent::LeaderExited(Completion {
            stream: 16,
            instance: 1,
            code: Some(7),
        }))
    );
    let retained_after_status = !reaps.is_empty();
    reaps.stop_all();
    let debt_while_held = registry.outstanding();
    let early_completion = runtime.block_on(async {
        tokio::time::timeout(Duration::from_millis(40), reaps.next())
            .await
            .is_ok()
    });
    // Release and join the exact fake owner before assertions, including RED.
    complete.store(true, Ordering::SeqCst);
    let completion = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), reaps.next())
            .await
            .unwrap()
    });
    let fully_refunded = reaps.is_empty() && registry.outstanding() == 0;
    drop(reaps);
    runtime.shutdown_timeout(Duration::from_secs(2));
    assert!(
        valid_status,
        "natural leader status waited for final cleanup"
    );
    assert!(retained_after_status, "leader status released full custody");
    assert_eq!(
        debt_while_held, 1,
        "retiring cleanup lost its factory charge"
    );
    assert!(!early_completion, "held cleanup was reported complete");
    assert_eq!(completion.code, Some(0));
    assert!(
        fully_refunded,
        "proved completion did not refund exact owner"
    );
}

struct LostWait(ActiveWait);
impl ChannelWait for LostWait {
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        let _ = self.0.entered.try_send(());
        Some(if self.0.complete.load(Ordering::SeqCst) {
            LeaderStatus::Running
        } else {
            LeaderStatus::Unknown("owned fixture observation unavailable".into())
        })
    }
    fn poll_exit(&mut self) -> ChildStatus {
        if self.0.complete.load(Ordering::SeqCst) {
            ChildStatus::Reaped { code: None }
        } else {
            ChildStatus::Unknown("owned fixture cleanup unavailable".into())
        }
    }
    fn kill(&mut self) {
        panic!("unknown owner must never be signaled")
    }
    fn wait(self: Box<Self>) -> i32 {
        panic!("exclusive polling required")
    }
    fn cleanup_uninstalled(
        &mut self,
        _: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus {
        crate::channel_open::CleanupStatus::Unknown
    }
}

#[test]
fn cleanup143_active_loss_without_retirement_is_retained_deduplicated_and_exactly_cleared() {
    let runtime = runtime();
    let registry = ChannelOpenRegistry::new(Default::default());
    let other_registry = ChannelOpenRegistry::new(Default::default());
    let mut reaps = ReapSet::new(registry.clone());
    let mut receipts = Vec::new();
    for instance in 1..=2 {
        let complete = Arc::new(AtomicBool::new(false));
        let (entered, observed) = mpsc::sync_channel(1);
        runtime.block_on(async {
            reaps.start_active(
                15 + instance as u8,
                instance,
                Box::new(LostWait(ActiveWait {
                    complete: complete.clone(),
                    entered,
                })),
                None,
            );
            reaps.observe_active();
        });
        observed.recv_timeout(Duration::from_secs(2)).unwrap();
        runtime.block_on(async {
            runtime.spawn_blocking(|| ()).await.unwrap();
        });
        receipts.push(complete);
    }
    assert_eq!(registry.retiring_count(), 0);
    let snapshot = registry.cleanup_snapshot().unwrap();
    assert_eq!(snapshot.observed_unconfirmed_owners, 2);
    assert_eq!(snapshot.unique_cleanup_debt, 2);
    assert!(snapshot.leader_unconfirmed);
    let owner = reaps.owners.get(&1).unwrap().clone();
    registry.record_observation(&owner, ObservationFailure::Panic);
    other_registry.record_observation(&owner, ObservationFailure::Panic);
    other_registry.finish_reap(&owner);
    registry.finish_reap(&owner); // No terminal proof: cannot clear even this exact owner.
    assert_eq!(registry.cleanup_snapshot().unwrap(), snapshot);
    assert_eq!(
        other_registry
            .cleanup_snapshot()
            .unwrap()
            .unique_cleanup_debt,
        0
    );
    reaps.retire(1);
    let overlap = registry.cleanup_snapshot().unwrap();
    assert_eq!(overlap.retiring_channels, 1);
    assert_eq!(overlap.unique_cleanup_debt, 2);
    receipts[0].store(true, Ordering::SeqCst);
    owner.notify();
    let completed = runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), reaps.next())
            .await
            .unwrap()
    });
    assert_eq!(completed.instance, 1);
    assert_eq!(
        completed.code, None,
        "unknown exit code is confirmed cleanup"
    );
    registry.finish_reap(&owner); // Duplicate cannot clear the other capsule.
    assert_eq!(
        registry
            .cleanup_snapshot()
            .unwrap()
            .observed_unconfirmed_owners,
        1
    );
    receipts[1].store(true, Ordering::SeqCst);
    reaps.stop_all();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), reaps.next())
            .await
            .unwrap();
    });
    assert_eq!(registry.cleanup_snapshot().unwrap().unique_cleanup_debt, 0);
    drop(reaps);
    runtime.shutdown_timeout(Duration::from_secs(2));
}

struct TypedFailureWait {
    kind: ObservationFailure,
    complete: Arc<AtomicBool>,
}
impl ChannelWait for TypedFailureWait {
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        assert!(
            self.kind != ObservationFailure::Panic || self.complete.load(Ordering::SeqCst),
            "owned observation panic fixture"
        );
        None
    }
    fn poll_exit(&mut self) -> ChildStatus {
        if self.complete.load(Ordering::SeqCst) {
            ChildStatus::Reaped { code: None }
        } else {
            ChildStatus::Unknown("owned cleanup observation fixture".into())
        }
    }
    fn kill(&mut self) {
        panic!("unconfirmed owner must not be signaled")
    }
    fn wait(self: Box<Self>) -> i32 {
        panic!("exclusive polling required")
    }
    fn cleanup_uninstalled(
        &mut self,
        _: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus {
        crate::channel_open::CleanupStatus::Unknown
    }
}

#[test]
fn cleanup143_cleanup_failure_and_backend_panic_keep_typed_first_observation() {
    for kind in [ObservationFailure::Cleanup, ObservationFailure::Panic] {
        let runtime = runtime();
        let registry = ChannelOpenRegistry::new(Default::default());
        let mut reaps = ReapSet::new(registry.clone());
        let complete = Arc::new(AtomicBool::new(false));
        runtime.block_on(async {
            reaps.start(
                16,
                1,
                Box::new(TypedFailureWait {
                    kind,
                    complete: complete.clone(),
                }),
                None,
                false,
            );
            runtime.spawn_blocking(|| ()).await.unwrap();
        });
        let snapshot = registry.cleanup_snapshot().unwrap();
        assert_eq!(snapshot.unique_cleanup_debt, 1);
        assert_eq!(snapshot.observed_unconfirmed_owners, 1);
        assert_eq!(
            snapshot.cleanup_unconfirmed,
            kind == ObservationFailure::Cleanup
        );
        assert_eq!(
            snapshot.observation_panicked,
            kind == ObservationFailure::Panic
        );
        let owner = reaps.owners.get(&1).unwrap();
        registry.record_observation(owner, ObservationFailure::Leader);
        assert_eq!(registry.cleanup_snapshot().unwrap(), snapshot);
        complete.store(true, Ordering::SeqCst);
        owner.notify();
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(2), reaps.next())
                .await
                .unwrap();
        });
        assert_eq!(registry.cleanup_snapshot().unwrap().unique_cleanup_debt, 0);
        drop(reaps);
        runtime.shutdown_timeout(Duration::from_secs(2));
    }
}

#[test]
fn cleanup143_exact_completion_clears_observation_even_without_a_retiring_map_entry() {
    let runtime = runtime();
    let registry = ChannelOpenRegistry::new(Default::default());
    let mut reaps = ReapSet::new(registry.clone());
    let complete = Arc::new(AtomicBool::new(false));
    let (entered, observed) = mpsc::sync_channel(1);
    runtime.block_on(async {
        reaps.start_active(
            16,
            1,
            Box::new(LostWait(ActiveWait {
                complete: complete.clone(),
                entered,
            })),
            None,
        );
        reaps.observe_active();
    });
    observed.recv_timeout(Duration::from_secs(2)).unwrap();
    runtime.block_on(async {
        runtime.spawn_blocking(|| ()).await.unwrap();
    });
    let owner = reaps.owners.get(&1).unwrap().clone();
    assert_eq!(
        registry
            .cleanup_snapshot()
            .unwrap()
            .observed_unconfirmed_owners,
        1
    );
    // Deliberately omit registry retirement in this private metadata control.
    // The real exclusive lease still must obtain actual child proof and settle
    // its resources; clearing must not depend on a retiring-map lookup.
    owner.state.lock().unwrap().retiring = true;
    complete.store(true, Ordering::SeqCst);
    owner.notify();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), reaps.next())
            .await
            .unwrap();
    });
    assert_eq!(registry.retiring_count(), 0);
    assert_eq!(
        registry
            .cleanup_snapshot()
            .unwrap()
            .observed_unconfirmed_owners,
        0
    );
    drop(reaps);
    runtime.shutdown_timeout(Duration::from_secs(2));
}

include!("channel_reap_deadline_tests.rs");
