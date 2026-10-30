#[test]
fn shutdown_checkpoint_reports_retained_obligations_without_changing_them() {
    use super::shutdown_checkpoint::{Note, Phase, SeamEnd};
    let mut shutdown = HelperShutdown::new(empty_state());
    let owner = MonitorOwner {
        login: [73; 16],
        incarnation: 7,
    };
    let missing = MonitorOwner {
        login: [74; 16],
        incarnation: 8,
    };
    let (seam, _peer) = super::channel::pair().expect("owned pair");
    shutdown.state.monitors.insert(
        owner,
        Monitor {
            process: MonitorProcess::Controlled(seam),
            pid: Pid::from_raw(i32::MAX),
            reaped: false,
            write_closed: false,
            stop_attempted: false,
            refusal_seal: Some(RefusalSeal::Pending {
                until: Instant::now(),
                packet: Vec::new(),
            }),
            refusal_budget: STARTUP_REPORT_TIMEOUT,
            completion: None,
            seam_closed: false,
            wait_lost: true,
            failure: Some(MonitorFailure::Stream),
            #[cfg(target_os = "linux")]
            signal_failure: None,
        },
    );
    shutdown.state.retired.extend([owner, missing]);
    shutdown.state.live.insert(1, ChannelSlot::Running(owner));
    shutdown.state.orphans.push(Pid::from_raw(i32::MAX));
    shutdown.first_monitor_failure = Some(MonitorShutdownFailure::MissingOwner);
    let note = Note::default();
    note.publish(Phase::BeforePass, Some(SeamEnd::ChannelEof), &shutdown);
    let snapshot = *note.inner.lock().expect("observation");
    assert_eq!(
        (
            snapshot.monitors,
            snapshot.retired,
            snapshot.live,
            snapshot.orphans
        ),
        (1, 2, 1, 1)
    );
    assert_eq!(
        (
            snapshot.missing_completion,
            snapshot.not_reaped,
            snapshot.wait_lost,
            snapshot.monitor_failure
        ),
        (1, 1, 1, 1)
    );
    assert_eq!(
        (
            snapshot.missing_owner,
            snapshot.retired_live,
            snapshot.seal_pending
        ),
        (1, 1, 1)
    );
    assert!(snapshot.sticky_monitor_failure);
    assert_eq!(
        (snapshot.phase, snapshot.seam_end, snapshot.sequence),
        (Phase::BeforePass, SeamEnd::ChannelEof, 1)
    );
    // Observation neither settles nor clears any stored custody evidence.
    assert_eq!(shutdown.state.monitors.len(), 1);
    assert_eq!(shutdown.state.live.len(), 1);
    assert_eq!(shutdown.state.retired.len(), 2);
    assert!(shutdown.state.monitors[&owner].wait_lost);
    let monitor = shutdown.state.monitors.get_mut(&owner).unwrap();
    monitor.refusal_seal = Some(RefusalSeal::Sent);
    monitor.completion = Some(PamCompletion::NotOpened);
    monitor.reaped = true;
    monitor.wait_lost = false;
    monitor.failure = None;
    note.publish(Phase::AfterPass, None, &shutdown);
    let completed = *note.inner.lock().unwrap();
    assert_eq!(
        (
            completed.seal_pending,
            completed.seal_sent,
            completed.missing_completion,
            completed.not_reaped,
            completed.wait_lost,
            completed.monitor_failure
        ),
        (0, 1, 0, 0, 0, 0)
    );
    assert_eq!(completed.seam_end, SeamEnd::ChannelEof);
    assert_eq!(
        (shutdown.state.live.len(), shutdown.state.retired.len()),
        (1, 2)
    );
    shutdown
        .state
        .monitors
        .get_mut(&owner)
        .unwrap()
        .refusal_seal = Some(RefusalSeal::Failed);
    note.publish(Phase::AfterPass, None, &shutdown);
    assert_eq!(note.inner.lock().unwrap().seal_failed, 1);
}

#[test]
fn shutdown_checkpoint_try_lock_never_blocks_producer_or_timeout_reader() {
    use super::shutdown_checkpoint::{Note, Phase};
    use std::sync::{mpsc, Arc};
    let note = Arc::new(Note::default());
    let held = note.inner.lock().expect("held observation");
    let other = note.clone();
    let (done, completion) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let shutdown = HelperShutdown::new(empty_state());
        other.publish(Phase::BeforePass, None, &shutdown);
        done.send(other.receipt()).expect("observer result");
    });
    let early = completion.recv_timeout(Duration::from_millis(100));
    drop(held);
    thread.join().expect("owned observer thread joined");
    assert!(early.is_ok(), "diagnostics must not block on a held cell");
    assert!(early.unwrap().contains("unavailable-busy"));
}

#[test]
fn shutdown_checkpoint_poison_and_unobserved_are_explicit() {
    use super::shutdown_checkpoint::{Note, Phase};
    let note = std::sync::Arc::new(Note::default());
    assert!(note.receipt().contains("not-observed"));
    let other = note.clone();
    assert!(std::thread::spawn(move || {
        let _held = other.inner.lock().unwrap();
        panic!("controlled observation poison");
    })
    .join()
    .is_err());
    note.publish(Phase::BeforePass, None, &HelperShutdown::new(empty_state()));
    assert!(note.receipt().contains("unavailable-poisoned"));
}

#[test]
fn shutdown_checkpoint_timeout_keeps_failure_and_owned_thread_settlement() {
    use super::shutdown_checkpoint::{Note, Phase, SeamEnd};
    let note = Note::default();
    note.publish(
        Phase::BeforePass,
        Some(SeamEnd::AuthEof),
        &HelperShutdown::new(empty_state()),
    );
    let (release, held) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || held.recv().expect("release owned thread"));
    let expired = !wait_for_thread(&thread, Instant::now() + Duration::from_millis(20));
    let message = timeout_message("controlled shutdown", Some(&note));
    release.send(()).expect("release before assertion");
    thread.join().expect("owned timeout control joined");
    assert!(
        expired,
        "a checkpoint must never convert an unfinished join to success"
    );
    assert!(message.contains(&note.receipt()));
    assert_eq!(message.matches("checkpoint=").count(), 1);
}

#[test]
fn shutdown_checkpoint_receipt_bound_covers_maximum_counter_width() {
    use super::shutdown_checkpoint::{Note, Phase, SeamEnd, Snapshot};
    let note = Note::default();
    *note.inner.lock().unwrap() = Snapshot {
        sequence: u64::MAX,
        phase: Phase::BeforePass,
        seam_end: SeamEnd::ChannelFailed,
        monitors: usize::MAX,
        retired: usize::MAX,
        live: usize::MAX,
        verifying: usize::MAX,
        orphans: usize::MAX,
        missing_completion: usize::MAX,
        not_reaped: usize::MAX,
        wait_lost: usize::MAX,
        monitor_failure: usize::MAX,
        missing_owner: usize::MAX,
        retired_live: usize::MAX,
        seal_pending: usize::MAX,
        seal_sent: usize::MAX,
        seal_failed: usize::MAX,
        sticky_monitor_failure: true,
        cleanup_failure: true,
    };
    assert!(
        note.receipt().len() <= 1024,
        "fixed observation must fit one bounded receipt"
    );
}

#[test]
fn shutdown_checkpoint_actual_seam_exit_categories_survive_final_return() {
    use super::shutdown_checkpoint::{Note, Phase, SeamEnd};
    for (auth_seam, malformed, expected) in [
        (false, false, SeamEnd::ChannelEof),
        (true, false, SeamEnd::AuthEof),
        (false, true, SeamEnd::ChannelFailed),
        (true, true, SeamEnd::AuthFailed),
    ] {
        let note = std::sync::Arc::new(Note::default());
        let observe = note.clone();
        let ((channels, auth), (helper_channels, helper_auth)) = seams_for_test();
        if malformed {
            let seam = if auth_seam { &auth } else { &channels };
            super::channel::send(seam, b"malformed fixed test packet", None)
                .expect("queued packet");
        }
        let thread = std::thread::spawn(move || {
            let _ = serve_inner(
                helper_channels,
                helper_auth,
                test_config(),
                HashMap::new(),
                UNPRIVILEGED,
                None,
                #[cfg(target_os = "linux")]
                None,
                Some(observe),
            );
        });
        // Keep the other seam open so only the selected observation can end the loop.
        if auth_seam {
            drop(auth);
        } else {
            drop(channels);
        }
        join_within(thread, "empty diagnosed loop must settle");
        let latest = *note.inner.lock().expect("observation");
        assert_eq!(latest.seam_end, expected);
        assert_eq!(latest.phase, Phase::Returned);
        assert!(latest.sequence >= 4);
        assert_eq!((latest.monitors, latest.retired, latest.live), (0, 0, 0));
    }
}
