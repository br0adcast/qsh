// Synthetic registered helper tables, with only a few controlled sockets.
// No native process ownership or account transition is fabricated by these tests.
fn capacity143_fill_provisional(state: &mut LoopState, count: usize) {
    let account = my_account();
    state.verified.insert(account.uid, account.clone());
    for n in 0..count {
        ensure_login(state, login_token(n), &account, String::new()).unwrap();
    }
}

fn capacity143_refused_diagnostic(state: &mut LoopState) -> String {
    let account = my_account();
    let first = state.logins[&login_token(0)].incarnation;
    assert_eq!(
        ensure_login(state, login_token(0), &account, String::new()),
        Ok(first),
        "warm reattach must still precede the capacity check"
    );
    let before = (
        state.logins.len(),
        state.retired.len(),
        state.next_incarnation,
    );
    let reason =
        ensure_login(state, login_token(MAX_LOGINS + 1), &account, String::new()).unwrap_err();
    assert_eq!(reason, LoginRefusal::Capacity);
    let diagnostic = login_refusal_diagnostic(state, reason);
    assert_eq!(
        before,
        (
            state.logins.len(),
            state.retired.len(),
            state.next_incarnation
        )
    );
    diagnostic
}

#[test]
fn cleanup143_capacity_diagnostic_distinguishes_healthy_pending_and_unconfirmed() {
    let mut healthy = empty_state();
    capacity143_fill_provisional(&mut healthy, MAX_LOGINS);
    let healthy = capacity143_refused_diagnostic(&mut healthy);

    let (mut pending, owner, _pending_peer) = pam40_controlled_retiring_monitor(false);
    pending.next_incarnation = owner.incarnation + 1;
    capacity143_fill_provisional(&mut pending, MAX_LOGINS - 1);
    let pending = capacity143_refused_diagnostic(&mut pending);

    let (mut lost, owner, _lost_peer) = pam40_controlled_retiring_monitor(false);
    lost.next_incarnation = owner.incarnation + 1;
    let monitor = lost.monitors.get_mut(&owner).unwrap();
    monitor.wait_lost = true;
    monitor.failure = Some(MonitorFailure::Wait(nix::libc::ECHILD));
    capacity143_fill_provisional(&mut lost, MAX_LOGINS - 1);
    let lost = capacity143_refused_diagnostic(&mut lost);

    eprintln!("healthy: {healthy}\npending: {pending}\nunconfirmed: {lost}");
    assert_ne!(
        healthy, pending,
        "local capacity diagnostics must distinguish ordinary retirement from healthy admitted use"
    );
    assert_ne!(
        pending, lost,
        "missing-yet-pending receipt/wait must differ from explicitly lost authority"
    );
    assert!(healthy.contains("charged=256 limit=256 admitted=256 provisional=256 retiring=0"));
    assert!(healthy.contains("unconfirmed=0"));
    assert!(pending.contains("retiring=1 retiring_pending=1 unconfirmed=0"));
    assert!(pending.contains("wait_outstanding=1 receipt_outstanding=1"));
    assert!(lost.contains("retiring=1 retiring_pending=0 unconfirmed=1"));
    assert!(lost.contains("wait_lost=1 monitor_failed=1"));
}

#[test]
fn cleanup143_capacity_healthy_established_monitor_needs_no_final_receipt() {
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(false);
    state.retired.clear();
    state.next_incarnation = owner.incarnation + 1;
    let mut entry = login_entry(&my_account(), Instant::now(), true, &[]);
    entry.incarnation = owner.incarnation;
    state.logins.insert(owner.login, entry);
    capacity143_fill_provisional(&mut state, MAX_LOGINS - 1);
    let diagnostic = capacity143_refused_diagnostic(&mut state);
    assert!(diagnostic.contains("admitted=256 provisional=255 retiring=0"));
    assert!(diagnostic.contains("unconfirmed=0 missing_monitor=0"));
    assert!(diagnostic.contains("wait_outstanding=0 receipt_outstanding=0"));
}

#[test]
fn cleanup143_capacity_other_refusal_text_remains_unchanged() {
    let mut state = empty_state();
    capacity143_fill_provisional(&mut state, 1);
    let mut other = my_account();
    other.name.push_str("-different-fixture-account");
    let bound = ensure_login(&mut state, login_token(0), &other, String::new()).unwrap_err();
    assert_eq!(bound, LoginRefusal::AccountBinding);
    assert_eq!(
        login_refusal_diagnostic(&state, bound),
        "its login is already bound to a different account"
    );
    state.next_incarnation = u64::MAX;
    let exhausted =
        ensure_login(&mut state, login_token(1), &my_account(), String::new()).unwrap_err();
    assert_eq!(exhausted, LoginRefusal::IdentityExhausted);
    assert_eq!(
        login_refusal_diagnostic(&state, exhausted),
        "login identity exhausted"
    );
}

fn capacity143_add_retiring_monitor(
    state: &mut LoopState,
    owner: MonitorOwner,
    reaped: bool,
) -> UnixStream {
    let (seam, peer) = channel::pair().unwrap();
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    state.monitors.insert(
        owner,
        Monitor {
            process: MonitorProcess::Controlled(seam),
            #[cfg(target_os = "linux")]
            signal_failure: None,
            pid: Pid::this(),
            reaped,
            write_closed: false,
            stop_attempted: false,
            completion: None,
            seam_closed: false,
            wait_lost: false,
            failure: None,
        },
    );
    state.retired.insert(owner);
    state.next_incarnation = state.next_incarnation.max(owner.incarnation + 1);
    peer
}

#[test]
fn cleanup143_capacity_classification_deduplicates_exact_owners_and_obligations() {
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(false);
    #[cfg(target_os = "linux")]
    {
        state.monitors.get_mut(&owner).unwrap().signal_failure =
            Some((nix::libc::SIGKILL, nix::libc::EPERM));
    }
    let pending = capacity_snapshot(&state).unwrap();
    assert_eq!(
        (
            pending.charged,
            pending.retiring_pending,
            pending.unconfirmed
        ),
        (1, 1, 0)
    );
    assert_eq!(
        (pending.wait_outstanding, pending.receipt_outstanding),
        (1, 1)
    );
    let monitor = state.monitors.get_mut(&owner).unwrap();
    monitor.reaped = true;
    monitor.wait_lost = true;
    monitor.failure = Some(MonitorFailure::Stream);
    monitor.seam_closed = true;
    state.live.insert(101, ChannelSlot::ReapedRunning(owner));
    let lost = capacity_snapshot(&state).unwrap();
    assert_eq!(
        (lost.charged, lost.unconfirmed, lost.retiring_pending),
        (1, 1, 0)
    );
    assert_eq!(
        (lost.wait_lost, lost.monitor_failed, lost.receipt_lost),
        (1, 1, 1)
    );
    assert_eq!(
        (
            lost.retired_slots,
            lost.wait_outstanding,
            lost.receipt_outstanding
        ),
        (1, 0, 1)
    );
    state.monitors.remove(&owner);
    let missing = capacity_snapshot(&state).unwrap();
    assert_eq!(
        (
            missing.unconfirmed,
            missing.missing_monitor,
            missing.retired_slots
        ),
        (1, 1, 1)
    );
    assert_eq!(
        (missing.wait_outstanding, missing.receipt_outstanding),
        (0, 0),
        "missing metadata cannot fabricate present-monitor facts"
    );

    // One token can legitimately have an old retired and a new admitted life.
    let mut entry = login_entry(&my_account(), Instant::now(), false, &[]);
    entry.incarnation = owner.incarnation + 1;
    state.logins.insert(owner.login, entry);
    let both = capacity_snapshot(&state).unwrap();
    assert_eq!(
        (
            both.admitted,
            both.provisional,
            both.retiring,
            both.charged,
            both.unconfirmed
        ),
        (1, 1, 1, 2, 1)
    );
    let current = owner_for(&state, owner.login);
    state.live.insert(102, ChannelSlot::Starting(current));
    let current_missing = capacity_snapshot(&state).unwrap();
    assert_eq!(
        (current_missing.unconfirmed, current_missing.missing_monitor),
        (2, 2),
        "an active startup slot requires its own monitor evidence"
    );
}

fn capacity143_expect_unavailable(state: &LoopState) {
    assert!(capacity_snapshot(state).is_none());
    let diagnostic = login_refusal_diagnostic(state, LoginRefusal::Capacity);
    assert!(diagnostic.ends_with("helper_capacity=unavailable"));
    assert!(
        !diagnostic.contains("charged="),
        "no partial clean-looking counters"
    );
}

#[test]
fn cleanup143_capacity_inconsistent_links_and_bounds_are_wholly_unavailable() {
    let mut overlap = empty_state();
    capacity143_fill_provisional(&mut overlap, 1);
    overlap.retired.insert(owner_for(&overlap, login_token(0)));
    capacity143_expect_unavailable(&overlap);

    let (mut orphan_monitor, _, _peer) = pam40_controlled_retiring_monitor(false);
    orphan_monitor.retired.clear();
    capacity143_expect_unavailable(&orphan_monitor);
    let mut orphan_slot = empty_state();
    orphan_slot.live.insert(
        1,
        ChannelSlot::Cleaning(MonitorOwner {
            login: [90; 16],
            incarnation: 9,
        }),
    );
    capacity143_expect_unavailable(&orphan_slot);

    let mut excessive = empty_state();
    for n in 0..=MAX_LOGINS {
        let mut entry = login_entry(&my_account(), Instant::now(), false, &[]);
        entry.incarnation = n as u64 + 1;
        excessive.logins.insert(login_token(n), entry);
    }
    capacity143_expect_unavailable(&excessive);
    let mut excessive_slots = empty_state();
    capacity143_fill_provisional(&mut excessive_slots, 1);
    let owner = owner_for(&excessive_slots, login_token(0));
    for id in 0..=MAX_LOGINS * MAX_CHANNELS_PER_LOGIN {
        excessive_slots
            .live
            .insert(id as u64, ChannelSlot::Starting(owner));
    }
    capacity143_expect_unavailable(&excessive_slots);
}

#[test]
fn cleanup143_capacity_snapshots_preserve_registered_state_age_and_socket_custody() {
    use std::os::fd::AsRawFd;
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    peer.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
    state.next_incarnation = owner.incarnation + 1;
    capacity143_fill_provisional(&mut state, 1);
    let old = Instant::now() - LOGIN_GRACE * 2;
    state.logins.get_mut(&login_token(0)).unwrap().created_at = old;
    state.live.insert(101, ChannelSlot::Cleaning(owner));
    let before = (
        state.logins.len(),
        state.retired.clone(),
        state.live.len(),
        state.monitors.len(),
        state.next_incarnation,
        state.pam_cleanup,
    );
    let monitor = &state.monitors[&owner];
    let fd = monitor.seam().as_raw_fd();
    let flags = (
        monitor.reaped,
        monitor.wait_lost,
        monitor.write_closed,
        monitor.stop_attempted,
        monitor.seam_closed,
        monitor.completion,
        monitor.failure,
    );
    let first = capacity_snapshot(&state).unwrap().to_string();
    for _ in 0..4 {
        assert_eq!(capacity_snapshot(&state).unwrap().to_string(), first);
        assert!(login_refusal_diagnostic(&state, LoginRefusal::Capacity).contains(&first));
    }
    assert_eq!(
        before,
        (
            state.logins.len(),
            state.retired.clone(),
            state.live.len(),
            state.monitors.len(),
            state.next_incarnation,
            state.pam_cleanup
        )
    );
    assert_eq!(
        state.logins[&login_token(0)].created_at,
        old,
        "observation never runs the separate provisional age sweep"
    );
    assert!(matches!(state.live[&101], ChannelSlot::Cleaning(actual) if actual == owner));
    let monitor = &state.monitors[&owner];
    assert_eq!(monitor.seam().as_raw_fd(), fd);
    assert_eq!(
        (
            monitor.reaped,
            monitor.wait_lost,
            monitor.write_closed,
            monitor.stop_attempted,
            monitor.seam_closed,
            monitor.completion,
            monitor.failure
        ),
        flags
    );
    channel::send(monitor.seam(), b"retained-custody", None).unwrap();
    let (bytes, descriptor) = channel::recv(&peer).unwrap().unwrap();
    assert_eq!(bytes, b"retained-custody");
    assert!(descriptor.is_none());
}

#[test]
fn cleanup143_capacity_exact_receipt_wait_settlement_keeps_failed_pam_outcomes() {
    use crate::helper::pam_completion::PamStep::{Attempted, Skipped};
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    let newer = MonitorOwner {
        login: owner.login,
        incarnation: owner.incarnation + 1,
    };
    let newer_peer = capacity143_add_retiring_monitor(&mut state, newer, true);
    let seams = DirectSeam::new();
    channel::send(
        &newer_peer,
        &encode(&MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened,
        })
        .unwrap(),
        None,
    )
    .unwrap();
    serve_ready_monitors(seams.seams(), &mut state, &[newer]);
    assert!(!state.retired.contains(&newer));
    assert!(
        state.retired.contains(&owner),
        "a different incarnation's receipt settles only its exact charge"
    );
    let remaining = capacity_snapshot(&state).unwrap();
    assert_eq!(
        (
            remaining.charged,
            remaining.retiring_pending,
            remaining.unconfirmed,
            remaining.wait_outstanding,
            remaining.receipt_outstanding
        ),
        (1, 1, 0, 1, 1)
    );
    let failed = PamCompletion::Finished {
        close_session: Attempted(0),
        delete_cred: Attempted(17),
        end: Skipped,
    };
    channel::send(
        &peer,
        &encode(&MonitorEvent::SessionClosed { result: failed }).unwrap(),
        None,
    )
    .unwrap();
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    let receipt_only = capacity_snapshot(&state).unwrap();
    assert_eq!(
        (
            receipt_only.charged,
            receipt_only.retiring_pending,
            receipt_only.unconfirmed,
            receipt_only.wait_outstanding,
            receipt_only.receipt_outstanding
        ),
        (1, 1, 0, 1, 0)
    );
    assert!(receipt_only
        .to_string()
        .contains("pam=finished pam_close=ok pam_delete_cred=failed pam_end=skipped"));
    state.monitors.get_mut(&owner).unwrap().reaped = true;
    let ready_but_retained = capacity_snapshot(&state).unwrap();
    assert_eq!(
        (
            ready_but_retained.charged,
            ready_but_retained.retiring_pending,
            ready_but_retained.wait_outstanding
        ),
        (1, 1, 0),
        "observation cannot refund even evidence-ready custody"
    );
    finish_retired(&mut state, owner);
    let settled = capacity_snapshot(&state).unwrap();
    assert_eq!((settled.charged, settled.unconfirmed), (0, 0));
    assert!(!settled.pam.succeeded());
    assert!(settled.to_string().contains("pam_delete_cred=failed"));
    let final_owner = MonitorOwner {
        login: owner.login,
        incarnation: owner.incarnation + 2,
    };
    let _last_peer = capacity143_add_retiring_monitor(&mut state, final_owner, true);
    state.monitors.get_mut(&final_owner).unwrap().completion = Some(PamCompletion::Finished {
        close_session: Attempted(0),
        delete_cred: Attempted(0),
        end: Attempted(0),
    });
    finish_retired(&mut state, final_owner);
    assert!(state.retired.is_empty());
    assert!(state.monitors.is_empty());
    assert!(capacity_snapshot(&state)
        .unwrap()
        .to_string()
        .contains("pam_delete_cred=failed"));
}

#[test]
fn cleanup143_capacity_format_is_bounded_private_and_normalizes_pam_codes() {
    use crate::helper::pam_completion::PamStep::{Attempted, Skipped};
    let mut dense = empty_state();
    for n in 0..MAX_LOGINS {
        let owner = MonitorOwner {
            login: login_token(n),
            incarnation: n as u64 + 1,
        };
        dense.retired.insert(owner);
        for slot in 0..MAX_CHANNELS_PER_LOGIN {
            dense.live.insert(
                (n * MAX_CHANNELS_PER_LOGIN + slot + 1) as u64,
                ChannelSlot::Cleaning(owner),
            );
        }
    }
    dense.next_incarnation = MAX_LOGINS as u64 + 1;
    dense.highest_channel_id = (MAX_LOGINS * MAX_CHANNELS_PER_LOGIN) as u64;
    dense.pam_cleanup = PamCompletion::Finished {
        close_session: Attempted(123456),
        delete_cred: Skipped,
        end: Attempted(0),
    };
    let snapshot = capacity_snapshot(&dense).unwrap();
    assert_eq!(
        (
            snapshot.charged,
            snapshot.unconfirmed,
            snapshot.missing_monitor,
            snapshot.retired_slots
        ),
        (256, 256, 256, 4096)
    );
    let diagnostic = login_refusal_diagnostic(&dense, LoginRefusal::Capacity);
    assert!(
        diagnostic.len() <= 512,
        "fixed bounded numeric/category schema"
    );
    assert!(!diagnostic.contains("123456"));
    assert!(diagnostic.contains("pam_close=failed pam_delete_cred=skipped pam_end=ok"));

    let mut private = empty_state();
    let mut entry = login_entry(&my_account(), Instant::now(), false, &[]);
    entry.account.name = "fixture-private-account".into();
    entry.rhost = "fixture-private-origin.invalid".into();
    entry.incarnation = 9_876_543_210;
    private.logins.insert([0xc7; 16], entry);
    let diagnostic = login_refusal_diagnostic(&private, LoginRefusal::Capacity);
    for secret in [
        "fixture-private-account",
        "fixture-private-origin.invalid",
        "9876543210",
        "c7c7c7c7",
    ] {
        assert!(!diagnostic.contains(secret));
    }
    assert!(diagnostic.contains("pam=not_opened"));
    private.pam_cleanup = PamCompletion::Finished {
        close_session: Skipped,
        delete_cred: Skipped,
        end: Skipped,
    };
    assert!(login_refusal_diagnostic(&private, LoginRefusal::Capacity)
        .contains("pam=finished pam_close=skipped pam_delete_cred=skipped pam_end=skipped"));

    let (mut first, owner, _peer1) = pam40_controlled_retiring_monitor(false);
    let (mut second, _, _peer2) = pam40_controlled_retiring_monitor(false);
    first.pam_cleanup = PamCompletion::Finished {
        close_session: Attempted(17),
        delete_cred: Skipped,
        end: Attempted(0),
    };
    second.pam_cleanup = PamCompletion::Finished {
        close_session: Attempted(29),
        delete_cred: Skipped,
        end: Attempted(0),
    };
    first.monitors.get_mut(&owner).unwrap().completion = Some(second.pam_cleanup);
    second.monitors.get_mut(&owner).unwrap().completion = Some(first.pam_cleanup);
    let first = capacity_snapshot(&first).unwrap();
    let second = capacity_snapshot(&second).unwrap();
    assert_ne!(
        first.pam, second.pam,
        "different first nonzero numeric codes are retained internally"
    );
    assert_eq!(
        first.to_string(),
        second.to_string(),
        "operator categories cannot depend on which nonzero code was merged first"
    );
    assert_eq!(
        (first.unconfirmed, second.unconfirmed),
        (0, 0),
        "an unsuccessful PAM outcome alone is not lost custody"
    );
}

#[test]
fn helper_status143_serialized_snapshot_preserves_registered_custody() {
    let mut state = empty_state();
    capacity143_fill_provisional(&mut state, 3);
    let before = (
        state.logins.len(),
        state.retired.len(),
        state.next_incarnation,
    );
    let bytes = helper_status_snapshot(&state);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["schema"], 1);
    assert_eq!(value["phase"], "serving");
    assert_eq!(value["capacity"], "available");
    assert_eq!(value["counts"]["charged"], 3);
    assert_eq!(value["counts"]["provisional"], 3);
    assert!(value.get("cleanup_complete").is_none());
    assert_eq!(
        before,
        (
            state.logins.len(),
            state.retired.len(),
            state.next_incarnation
        )
    );
    state.stopping = true;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&helper_status_snapshot(&state)).unwrap()
            ["phase"],
        "stopping"
    );
    state.retired.insert(MonitorOwner {
        login: login_token(0),
        incarnation: state.logins[&login_token(0)].incarnation,
    });
    let unavailable: serde_json::Value =
        serde_json::from_slice(&helper_status_snapshot(&state)).unwrap();
    assert_eq!(unavailable["capacity"], "unavailable");
    assert!(unavailable.get("counts").is_none());
}

#[cfg(target_os = "linux")]
#[test]
fn helper_status143_legacy_drain_answers_pending_and_queries_do_not_hold_exit() {
    use std::io::Read;
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join("status.sock");
    let endpoint =
        crate::helper_status::Endpoint::bind_for(&path, nix::unistd::geteuid().as_raw()).unwrap();
    let (state, _owner, peer) = pam40_controlled_retiring_monitor(true);
    let thread = std::thread::spawn(move || {
        let seams = DirectSeam::new();
        let mut shutdown = HelperShutdown::new(state);
        shutdown.status = Some(endpoint);
        shutdown.end_the_monitors(seams.seams(), &test_config());
        assert!(shutdown.state.retired.is_empty());
    });
    let result = (|| -> std::io::Result<Vec<u8>> {
        let client = UnixStream::connect(&path)?;
        client.set_read_timeout(Some(Duration::from_secs(2)))?;
        let mut bytes = Vec::new();
        client
            .take((crate::helper_status::MAX_RESPONSE + 1) as u64)
            .read_to_end(&mut bytes)?;
        Ok(bytes)
    })();
    let queued: Vec<_> = (0..4)
        .map(|_| UnixStream::connect(&path).unwrap())
        .collect();
    // Release the exact controlled final receipt even if the query failed.
    let sent = channel::send(
        &peer,
        &encode(&MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened,
        })
        .unwrap(),
        None,
    );
    thread.join().unwrap();
    sent.unwrap();
    drop(queued);
    let snapshot: serde_json::Value = serde_json::from_slice(&result.unwrap()).unwrap();
    assert_eq!(snapshot["phase"], "stopping");
    assert_eq!(snapshot["counts"]["retiring_pending"], 1);
    assert_eq!(snapshot["counts"]["receipt_outstanding"], 1);
    assert!(
        !path.exists(),
        "query clients do not retain endpoint custody"
    );
}

#[test]
fn helper_status143_serializes_overlapping_uncertainty_and_pam_after_exact_release() {
    let (mut lost, owner, _peer) = pam40_controlled_retiring_monitor(false);
    let monitor = lost.monitors.get_mut(&owner).unwrap();
    monitor.wait_lost = true;
    monitor.failure = Some(MonitorFailure::Wait(nix::libc::ECHILD));
    monitor.seam_closed = true;
    let before = (
        lost.logins.len(),
        lost.retired.len(),
        lost.monitors.len(),
        lost.live.len(),
    );
    let bytes = helper_status_snapshot(&lost);
    let snapshot: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(snapshot["counts"]["charged"], 1);
    assert_eq!(
        snapshot["counts"]["unconfirmed"], 1,
        "overlapping reasons count one owner"
    );
    for reason in ["wait_lost", "monitor_failed", "receipt_lost"] {
        assert_eq!(snapshot["counts"][reason], 1);
    }
    assert_eq!(snapshot["counts"]["retiring_pending"], 0);
    assert_eq!(bytes, helper_status_snapshot(&lost));
    assert_eq!(
        before,
        (
            lost.logins.len(),
            lost.retired.len(),
            lost.monitors.len(),
            lost.live.len()
        )
    );

    let (mut settled, owner, _peer) = pam40_controlled_retiring_monitor(true);
    settled.monitors.get_mut(&owner).unwrap().completion = Some(PamCompletion::Finished {
        close_session: super::super::pam_completion::PamStep::Attempted(17),
        delete_cred: super::super::pam_completion::PamStep::Skipped,
        end: super::super::pam_completion::PamStep::Attempted(0),
    });
    finish_retired(&mut settled, owner);
    let after: serde_json::Value =
        serde_json::from_slice(&helper_status_snapshot(&settled)).unwrap();
    assert_eq!(after["counts"]["charged"], 0);
    assert_eq!(after["counts"]["retiring"], 0);
    assert_eq!(after["counts"]["pam"]["state"], "finished");
    assert_eq!(after["counts"]["pam"]["close_session"], "failed");
    assert_eq!(after["counts"]["pam"]["delete_cred"], "skipped");
    assert_eq!(after["counts"]["pam"]["end"], "ok");
}
