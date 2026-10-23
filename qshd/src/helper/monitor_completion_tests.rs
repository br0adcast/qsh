fn pam40_controlled_retiring_monitor(reaped: bool) -> (LoopState, MonitorOwner, UnixStream) {
    let mut state = empty_state();
    let owner = MonitorOwner {
        login: [40; 16],
        incarnation: 40,
    };
    let (seam, peer) = channel::pair().unwrap();
    seam.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
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
    (state, owner, peer)
}

#[test]
fn pam40_final_receipt_and_actual_wait_are_independent_obligations() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    let seams = DirectSeam::new();
    let result = PamCompletion::Finished {
        close_session: super::super::pam_completion::PamStep::Attempted(0),
        delete_cred: super::super::pam_completion::PamStep::Attempted(17),
        end: super::super::pam_completion::PamStep::Attempted(0),
    };
    channel::send(
        &peer,
        &encode(&MonitorEvent::SessionClosed { result }).unwrap(),
        None,
    )
    .unwrap();
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    assert!(
        state.monitors.contains_key(&owner),
        "receipt alone cannot prove actual child wait"
    );
    assert!(state.retired.contains(&owner));
    // The controlled wait fact is independent of the final protocol message.
    state.monitors.get_mut(&owner).unwrap().reaped = true;
    finish_retired(&mut state, owner);
    assert!(
        !state.monitors.contains_key(&owner),
        "receipt plus actual wait releases physical custody"
    );
    assert!(!state.retired.contains(&owner));
    assert_eq!(
        state.pam_cleanup, result,
        "an exit0 cannot erase failed PAM cleanup"
    );
}

#[test]
fn pam40_queued_final_receipt_survives_reap_before_socket_read() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(true);
    let seams = DirectSeam::new();
    channel::send(
        &peer,
        &encode(&MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened,
        })
        .unwrap(),
        None,
    )
    .unwrap();
    finish_retired(&mut state, owner);
    assert!(
        state.monitors.contains_key(&owner),
        "wait alone cannot discard queued receipt"
    );
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    assert!(!state.monitors.contains_key(&owner));
    assert!(state.retired.is_empty());
}

#[test]
fn pam40_eof_without_final_receipt_retains_failed_owner() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(true);
    let seams = DirectSeam::new();
    drop(peer);
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    let monitor = state
        .monitors
        .get(&owner)
        .expect("EOF cannot release unresolved PAM owner");
    assert!(state.retired.contains(&owner));
    assert!(monitor.seam_closed);
    assert_eq!(monitor.failure, Some(MonitorFailure::Stream));
    assert_eq!(monitor.completion, None);
}

#[test]
fn pam40_failed_half_shutdown_latches_once_and_retains_owner() {
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(true);
    let mut attempts = 0;
    for _ in 0..2 {
        request_monitor_end_using(state.monitors.get_mut(&owner).unwrap(), |_| {
            attempts += 1;
            Err(std::io::Error::from_raw_os_error(nix::libc::EPERM))
        });
    }
    let monitor = &state.monitors[&owner];
    assert_eq!(attempts, 1, "hard shutdown failure must not spin");
    assert!(!monitor.write_closed);
    assert_eq!(
        monitor.failure,
        Some(MonitorFailure::Shutdown(nix::libc::EPERM))
    );
    assert!(state.retired.contains(&owner));
}

#[test]
fn pam40_monitor_wait_loss_retires_authentication_and_cannot_be_repaired_by_receipt() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    state.retired.clear();
    let account = my_account();
    let mut login = login_entry(&account, Instant::now(), true, &[]);
    login.incarnation = owner.incarnation;
    state.logins.insert(owner.login, login);
    state.verified.insert(account.uid, account);
    let seams = DirectSeam::new();
    // This is a socket model, not OS custody. Inject its lost-wait result;
    // Linux production must never wait or signal the model's diagnostic PID.
    assert!(!poll_monitor_wait_using(
        state.monitors.get_mut(&owner).unwrap(),
        || Err(nix::Error::ECHILD),
    ));
    reap(&seams.helper, &mut state);
    assert!(state.monitors[&owner].wait_lost);
    assert_eq!(
        state.monitors[&owner].failure,
        Some(MonitorFailure::Wait(nix::libc::ECHILD))
    );
    assert!(!monitor_signal_authority(&state.monitors[&owner]));
    assert!(
        !state.logins.contains_key(&owner.login),
        "lost wait custody must stop new login admission"
    );
    assert!(state.retired.contains(&owner));
    channel::send(
        &peer,
        &encode(&MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened,
        })
        .unwrap(),
        None,
    )
    .unwrap();
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    state.monitors.get_mut(&owner).unwrap().reaped = true;
    finish_retired(&mut state, owner);
    assert!(
        state.monitors.contains_key(&owner),
        "later status cannot repair released wait authority"
    );
    assert!(!monitor_signal_authority(&state.monitors[&owner]));
}

#[test]
fn pam40_monitor_duplicate_final_receipt_cannot_release_failed_owner() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    let seams = DirectSeam::new();
    let bytes = encode(&MonitorEvent::SessionClosed {
        result: PamCompletion::NotOpened,
    })
    .unwrap();
    channel::send(&peer, &bytes, None).unwrap();
    channel::send(&peer, &bytes, None).unwrap();
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    state.monitors.get_mut(&owner).unwrap().reaped = true;
    finish_retired(&mut state, owner);
    assert_eq!(
        state.monitors[&owner].failure,
        Some(MonitorFailure::DuplicateCompletion)
    );
    assert!(state.retired.contains(&owner));
}

#[test]
fn pam40_interrupted_half_shutdown_yields_then_retries_without_failure() {
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(true);
    let mut attempts = 0;
    request_monitor_end_using(state.monitors.get_mut(&owner).unwrap(), |_| {
        attempts += 1;
        Err(std::io::Error::from(std::io::ErrorKind::Interrupted))
    });
    assert_eq!(attempts, 1, "one syscall attempt per bounded pass");
    assert_eq!(
        state.monitors[&owner].failure, None,
        "interruption is not hard shutdown loss"
    );
    request_monitor_end_using(state.monitors.get_mut(&owner).unwrap(), |seam| {
        attempts += 1;
        seam.shutdown(std::net::Shutdown::Write)
    });
    assert_eq!(attempts, 2);
    assert!(state.monitors[&owner].write_closed);
    assert_eq!(state.monitors[&owner].failure, None);
}

#[test]
fn pam40_ordering_completed_owner_never_attempts_new_half_shutdown() {
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(true);
    state.monitors.get_mut(&owner).unwrap().completion = Some(PamCompletion::NotOpened);
    let mut attempts = 0;
    finish_retired_using(&mut state, owner, |_| {
        attempts += 1;
        Err(std::io::Error::from_raw_os_error(nix::libc::EPERM))
    });
    assert_eq!(
        attempts, 0,
        "settled receipt+wait must be retired before unrelated shutdown"
    );
    assert!(!state.monitors.contains_key(&owner));
    assert!(!state.retired.contains(&owner));
}

#[test]
fn pam40_ordering_interrupted_wait_yields_without_losing_authority() {
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(false);
    let monitor = state.monitors.get_mut(&owner).unwrap();
    let mut attempts = 0;
    let gone = poll_monitor_wait_using(monitor, || {
        attempts += 1;
        if attempts <= 2 {
            Err(nix::Error::EINTR)
        } else {
            Ok(nix::sys::wait::WaitStatus::StillAlive)
        }
    });
    assert!(!gone);
    assert_eq!(
        attempts, 1,
        "interrupted wait yields after one attempt per pass"
    );
    assert!(!monitor.wait_lost);
    assert_eq!(monitor.failure, None);
    assert!(monitor_signal_authority(monitor));
}

#[test]
fn pam40_ordering_eof_after_final_receipt_keeps_pending_wait_valid() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    let seams = DirectSeam::new();
    channel::send(
        &peer,
        &encode(&MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened,
        })
        .unwrap(),
        None,
    )
    .unwrap();
    drop(peer);
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    assert!(state.monitors[&owner].seam_closed);
    assert_eq!(
        state.monitors[&owner].failure, None,
        "expected EOF cannot poison a received final result"
    );
    assert!(state.retired.contains(&owner));
    state.monitors.get_mut(&owner).unwrap().reaped = true;
    finish_retired(&mut state, owner);
    assert!(!state.monitors.contains_key(&owner));
}
