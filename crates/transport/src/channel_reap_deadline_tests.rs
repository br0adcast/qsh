#[test]
fn deadlines302_worker_attachment_bootstraps_active_notifier_without_a_timer() {
    let runtime = runtime();
    let mut reaps = ReapSet::default();
    let complete = Arc::new(AtomicBool::new(false));
    let (entered, observed) = mpsc::sync_channel(1);
    let (io, _input, _output) = crate::session_manager::SessionIo::test_pair();
    let mut bootstrapped = false;
    runtime.block_on(crate::session_manager::fixture::drive_backend(io, |io| {
        let reaps = &mut reaps;
        let bootstrapped = &mut bootstrapped;
        let complete = complete.clone();
        async move {
            let workers = [
                io.spawn_blocking_owned(|| {}),
                io.spawn_blocking_owned(|| {}),
            ];
            reaps.start_active(
                16,
                1,
                Box::new(ActiveWait {
                    complete: complete.clone(),
                    entered,
                }),
                None,
            );
            reaps.attach_workers(1, workers);
            *bootstrapped = observed.recv_timeout(Duration::from_secs(1)).is_ok();
            complete.store(true, Ordering::SeqCst);
        }
    }));
    reaps.stop_all();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), reaps.next())
            .await
            .unwrap();
    });
    drop(reaps);
    runtime.shutdown_timeout(Duration::from_secs(2));
    assert!(
        bootstrapped,
        "without bootstrap no notification-only backend can install its wake capability"
    );
}

#[test]
fn deadlines302_native_observation_remains_armed_while_lease_holds_resources() {
    let runtime = runtime();
    let mut reaps = ReapSet::default();
    let complete = Arc::new(AtomicBool::new(true));
    let (entered, _) = mpsc::sync_channel(1);
    runtime.block_on(async {
        reaps.start_active(16, 1, Box::new(ActiveWait { complete, entered }), None);
    });
    let lease = reaps.owners[&1].take_lease().unwrap();
    assert!(reaps.owners[&1].state.lock().unwrap().resources.is_none());
    assert!(
        reaps.needs_active_observation(),
        "leased resource absence cannot cancel native observation"
    );
    drop(lease);
    reaps.stop_all();
    assert!(!reaps.needs_active_observation());
    runtime.block_on(reaps.next());
    drop(reaps);
    runtime.shutdown_timeout(Duration::from_secs(2));
}

struct NotificationWait {
    mode: Arc<std::sync::atomic::AtomicU8>,
    notifier: Arc<std::sync::Mutex<Option<ReapNotifier>>>,
    installed: mpsc::SyncSender<()>,
    panic_policy: Arc<AtomicBool>,
    dropped: Arc<AtomicBool>,
}
impl Drop for NotificationWait {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}
impl ChannelWait for NotificationWait {
    fn active_observation(&self) -> super::super::ActiveObservation {
        assert!(
            !self.panic_policy.load(Ordering::SeqCst),
            "controlled policy panic"
        );
        super::super::ActiveObservation::Notification
    }
    fn set_reap_notifier(&mut self, notifier: ReapNotifier) {
        *self.notifier.lock().unwrap() = Some(notifier.clone());
        let _ = self.installed.try_send(());
        if self.mode.load(Ordering::SeqCst) != 0 {
            notifier.notify();
        }
    }
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        Some(if self.mode.load(Ordering::SeqCst) == 0 {
            LeaderStatus::Running
        } else {
            LeaderStatus::Exited { code: Some(7) }
        })
    }
    fn poll_exit(&mut self) -> ChildStatus {
        if self.mode.load(Ordering::SeqCst) == 2 {
            ChildStatus::Reaped { code: Some(7) }
        } else {
            ChildStatus::Running
        }
    }
    fn kill(&mut self) {
        assert_eq!(
            self.mode.load(Ordering::SeqCst),
            2,
            "unknown policy custody must not signal"
        );
    }
    fn wait(self: Box<Self>) -> i32 {
        panic!("exclusive lease required")
    }
    fn cleanup_uninstalled(
        &mut self,
        _: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus {
        crate::channel_open::CleanupStatus::Unknown
    }
}

#[test]
fn deadlines302_notification_only_leader_progresses_before_or_after_install_without_timer() {
    for before_install in [false, true] {
        let runtime = runtime();
        let mut reaps = ReapSet::default();
        let mode = Arc::new(std::sync::atomic::AtomicU8::new(u8::from(before_install)));
        let notifier = Arc::new(std::sync::Mutex::new(None));
        let (installed, ready) = mpsc::sync_channel(1);
        let dropped = Arc::new(AtomicBool::new(false));
        let (io, _inbound, _outbound) = crate::session_manager::SessionIo::test_pair();
        runtime.block_on(crate::session_manager::fixture::drive_backend(io, |io| {
            let reaps = &mut reaps;
            let mode = mode.clone();
            let notifier = notifier.clone();
            let dropped = dropped.clone();
            async move {
                let workers = [
                    io.spawn_blocking_owned(|| {}),
                    io.spawn_blocking_owned(|| {}),
                ];
                reaps.start_active(
                    16,
                    1,
                    Box::new(NotificationWait {
                        mode: mode.clone(),
                        notifier: notifier.clone(),
                        installed,
                        panic_policy: Arc::new(AtomicBool::new(false)),
                        dropped,
                    }),
                    None,
                );
                reaps.attach_workers(1, workers);
                ready.recv_timeout(Duration::from_secs(2)).unwrap();
                assert!(!reaps.needs_active_observation());
                if !before_install {
                    mode.store(1, Ordering::SeqCst);
                    let wake = notifier.lock().unwrap().clone().unwrap();
                    wake.notify();
                }
                let event = tokio::time::timeout(Duration::from_secs(2), reaps.next_event())
                    .await
                    .unwrap();
                assert!(matches!(
                    event,
                    ReapEvent::LeaderExited(Completion { code: Some(7), .. })
                ));
                assert!(
                    reaps.owners[&1].state.lock().unwrap().terminal.is_none(),
                    "leader status is not cleanup proof"
                );
                mode.store(2, Ordering::SeqCst);
                reaps.retire(1);
                tokio::time::timeout(Duration::from_secs(2), reaps.next())
                    .await
                    .unwrap();
            }
        }));
        assert!(dropped.load(Ordering::SeqCst));
        drop(reaps);
        runtime.shutdown_timeout(Duration::from_secs(2));
    }
}

#[test]
fn deadlines302_policy_panic_parks_exact_custody_without_signalling_or_drop() {
    let runtime = runtime();
    let mut reaps = ReapSet::default();
    let mode = Arc::new(std::sync::atomic::AtomicU8::new(0));
    let panic_policy = Arc::new(AtomicBool::new(true));
    let dropped = Arc::new(AtomicBool::new(false));
    let (installed, _) = mpsc::sync_channel(1);
    runtime.block_on(async {
        reaps.start_active(
            16,
            1,
            Box::new(NotificationWait {
                mode: mode.clone(),
                notifier: Arc::default(),
                installed,
                panic_policy: panic_policy.clone(),
                dropped: dropped.clone(),
            }),
            None,
        );
        reaps.observe_active();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if reaps.owners[&1].state.lock().unwrap().observation
                    == Some(ObservationFailure::Panic)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    });
    assert!(!dropped.load(Ordering::SeqCst));
    assert!(!reaps.needs_active_observation());
    panic_policy.store(false, Ordering::SeqCst);
    mode.store(2, Ordering::SeqCst);
    reaps.stop_all();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), reaps.next())
            .await
            .unwrap();
    });
    assert!(dropped.load(Ordering::SeqCst));
    drop(reaps);
    runtime.shutdown_timeout(Duration::from_secs(2));
}
