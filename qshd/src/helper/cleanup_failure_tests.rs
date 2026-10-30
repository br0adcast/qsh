#[test]
fn selinux57_failed_cleanup_preserves_physical_receipt_and_retires_charge() {
    for kind in [
        super::super::protocol::CleanupKind::Reaped,
        super::super::protocol::CleanupKind::NoChild,
    ] {
        let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(true);
        let seams = DirectSeam::new();
        state.live.insert(5701, ChannelSlot::Cleaning(owner));
        let failure = CleanupFailure::PtyLabelRestore { errno: 13 };
        let foreign = MonitorOwner {
            incarnation: owner.incarnation + 1,
            ..owner
        };
        dispatch_monitor_event(
            seams.seams(),
            &mut state,
            foreign,
            MonitorEvent::CleanupFailed {
                id: 5701,
                kind,
                failure,
            },
        );
        assert_eq!(
            state.cleanup_failure, None,
            "foreign owner cannot poison cleanup"
        );
        dispatch_monitor_event(
            seams.seams(),
            &mut state,
            owner,
            MonitorEvent::CleanupFailed {
                id: 5701,
                kind,
                failure,
            },
        );
        let (bytes, fd) = channel::recv(&seams.worker).unwrap().unwrap();
        assert!(fd.is_none());
        assert_eq!(
            decode::<Response>(&bytes).unwrap(),
            Response::CleanupFailed {
                id: 5701,
                kind,
                failure,
            }
        );
        assert!(!state.live.contains_key(&5701));
        assert_eq!(state.cleanup_failure, Some(failure));
        assert!(state.monitors[&owner].failure.is_none());
        dispatch_monitor_event(
            seams.seams(),
            &mut state,
            owner,
            MonitorEvent::CleanupComplete { id: 5701, kind },
        );
        dispatch_monitor_event(
            seams.seams(),
            &mut state,
            owner,
            MonitorEvent::SessionClosed {
                result: PamCompletion::NotOpened,
                request_failure: None,
                cleanup_failure: None,
            },
        );
        assert!(state.retired.is_empty());
        assert!(state.monitors.is_empty());
        let counts = capacity_snapshot(&state).unwrap();
        assert_eq!(
            (
                counts.charged,
                counts.unconfirmed,
                counts.wait_outstanding,
                counts.receipt_outstanding
            ),
            (0, 0, 0, 0)
        );
        assert_eq!(
            counts.cleanup_failure,
            Some(failure),
            "clean PAM/duplicates cannot erase semantic failure"
        );
        let snapshot: crate::helper_status::Snapshot =
            serde_json::from_slice(&helper_status_snapshot(&state)).unwrap();
        assert_eq!(snapshot.schema, crate::helper_status::SCHEMA);
        assert_eq!(
            snapshot.counts.unwrap().cleanup_failure,
            Some(crate::helper_status::CleanupFailure::PtyLabelRestore { errno: 13 })
        );
    }
}

#[test]
fn selinux57_final_summary_retains_failure_without_channel_event() {
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(true);
    let seams = DirectSeam::new();
    let failure = CleanupFailure::PtyLabelRestore { errno: 5 };
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened,
            request_failure: None,
            cleanup_failure: Some(failure),
        },
    );
    assert!(state.retired.is_empty());
    assert_eq!(state.cleanup_failure, Some(failure));
    assert_eq!(state.pam_cleanup, PamCompletion::NotOpened);
}

#[cfg(target_os = "linux")]
#[test]
fn selinux57_physical_outcome_is_settled_but_failed_for_label_restore() {
    let mut outcome = HelperPhysicalOutcome {
        worker: WorkerPhysicalOutcome {
            first_failure: None,
            signal_failure: None,
            terminal_received: true,
            native_exit: 0,
            requested: true,
        },
        pam_received: PamCompletion::NotOpened,
        cleanup_failure: None,
        missing_pam: 0,
        channel_receipts: ChannelReceiptDebt::default(),
        pending_requests: false,
        monitor_failure: None,
        adoption_failed: false,
        forced_worker: false,
        required_publication: None,
    };
    assert_eq!(outcome.service_exit_code(), 0);
    outcome.cleanup_failure = Some(CleanupFailure::PtyLabelRestore { errno: 5 });
    assert_eq!(outcome.service_exit_code(), 1);
    assert_eq!(outcome.worker.native_exit, 0);
    assert!(!outcome.channel_receipts.any());
    assert!(outcome.pam_received.succeeded());
}

#[test]
fn selinux57_failed_reap_before_exit_keeps_error_until_worker_receipt() {
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(true);
    let seams = DirectSeam::new();
    let failure = CleanupFailure::PtyLabelRestore { errno: 5 };
    state.live.insert(5701, ChannelSlot::Running(owner));
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::CleanupFailed {
            id: 5701,
            kind: super::super::protocol::CleanupKind::Reaped,
            failure,
        },
    );
    assert!(matches!(
        state.live[&5701],
        ChannelSlot::ReapedRunning(_, Some(_))
    ));
    // Duplicate success cannot erase an error held with the physical fact.
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::CleanupComplete {
            id: 5701,
            kind: super::super::protocol::CleanupKind::Reaped,
        },
    );
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::Exited { id: 5701, code: 7 },
    );
    let (first, _) = channel::recv(&seams.worker).unwrap().unwrap();
    let (second, _) = channel::recv(&seams.worker).unwrap().unwrap();
    assert_eq!(
        decode::<Response>(&first).unwrap(),
        Response::Exited { id: 5701, code: 7 }
    );
    assert_eq!(
        decode::<Response>(&second).unwrap(),
        Response::CleanupFailed {
            id: 5701,
            kind: super::super::protocol::CleanupKind::Reaped,
            failure
        }
    );
    assert!(!state.live.contains_key(&5701));
}
