#[test]
fn pam40_shutdown_tail_reads_queued_final_receipt_after_modeled_wait() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(true);
    let result = PamCompletion::Finished {
        close_session: super::super::pam_completion::PamStep::Attempted(17),
        delete_cred: super::super::pam_completion::PamStep::Attempted(0),
        end: super::super::pam_completion::PamStep::Attempted(0),
    };
    channel::send(
        &peer,
        &encode(&MonitorEvent::SessionClosed { result }).unwrap(),
        None,
    )
    .unwrap();
    // This fixture models a completed child wait. Its final protocol record is
    // queued in a real readable seam and must survive entry into teardown.
    let seams = DirectSeam::new();
    let mut shutdown = HelperShutdown::new(state);
    shutdown.end_the_monitors(seams.seams(), &test_config());
    state = shutdown.state;
    assert_eq!(
        state.pam_cleanup, result,
        "the shutdown tail must consume the final PAM receipt"
    );
    assert!(!state.monitors.contains_key(&owner));
    assert!(
        !state.retired.contains(&owner),
        "only complete cleanup refunds admission"
    );
}

#[test]
fn pam40_never_opened_login_ends_without_fabricating_pam_cleanup_debt() {
    let login = [41; 16];
    let mut state = state_with_login(&my_account(), login);
    let owner = MonitorOwner {
        login,
        incarnation: 1,
    };
    let seams = DirectSeam::new();
    retire_login(&seams.helper, &mut state, owner);
    assert!(!state.logins.contains_key(&login));
    assert!(
        !state.retired.contains(&owner),
        "no monitor or shell was ever acquired"
    );
    assert_eq!(state.pam_cleanup, PamCompletion::NotOpened);

    // An already retained obligation cannot be retroactively declared NotOpened.
    state.retired.insert(owner);
    retire_login(&seams.helper, &mut state, owner);
    assert!(state.retired.contains(&owner));
}

#[test]
fn pam40_shutdown_send_failure_retains_owner_without_numeric_escalation() {
    let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
        "helper::server::tests::pam40_shutdown_send_failure_retains_owner_without_numeric_escalation_body",
    );
    assert!(
        status.success(),
        "owned shutdown send failure control failed ({status}):\n{stdout}\n{stderr}"
    );
}

#[test]
#[ignore = "runs only through the owned shutdown send failure subprocess"]
fn pam40_shutdown_send_failure_retains_owner_without_numeric_escalation_body() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    state.live.insert(401, ChannelSlot::Cleaning(owner));
    drop(peer);
    let seams = DirectSeam::new();
    let mut shutdown = HelperShutdown::new(state);
    // The controlled target is THIS owned subprocess, never the test parent
    // or an unrelated numeric PID. A legacy escalation kills only this body.
    shutdown.begin_monitor_stop(seams.seams());
    assert!(shutdown.state.monitors.contains_key(&owner));
    assert!(shutdown.state.retired.contains(&owner));
    assert!(shutdown.state.live.contains_key(&401));
    assert!(matches!(
        shutdown.state.monitors[&owner].failure,
        Some(MonitorFailure::Send(_))
    ));
}

#[test]
fn pam40_monitor_shutdown_latches_first_observed_ownership_failure() {
    let (state, owner, _peer) = pam40_controlled_retiring_monitor(true);
    let mut shutdown = HelperShutdown::new(state);
    shutdown.state.monitors.get_mut(&owner).unwrap().failure = Some(MonitorFailure::Stream);
    shutdown.observe_monitor_failures();
    shutdown.state.monitors.get_mut(&owner).unwrap().failure =
        Some(MonitorFailure::Wait(nix::libc::ECHILD));
    shutdown.observe_monitor_failures();
    assert_eq!(
        shutdown.first_monitor_failure,
        Some(MonitorShutdownFailure::Monitor(MonitorFailure::Stream))
    );
}
