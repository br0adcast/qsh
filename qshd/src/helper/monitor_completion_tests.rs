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
            refusal_seal: None,
            refusal_budget: STARTUP_REPORT_TIMEOUT,
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
        &encode(&MonitorEvent::SessionClosed {
            request_failure: None,
            cleanup_failure: None,
            result,
        })
        .unwrap(),
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
            request_failure: None,
            cleanup_failure: None,
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
            request_failure: None,
            cleanup_failure: None,
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
        request_failure: None,
        cleanup_failure: None,
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
            request_failure: None,
            cleanup_failure: None,
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

#[test]
fn refusal406_late_refusal_revokes_only_exact_known_incarnation() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    state.retired.clear();
    state.logins.insert(
        owner.login,
        LoginState::provisional(my_account(), String::new(), owner.incarnation),
    );
    state.verified.insert(my_uid(), my_account());
    let seams = DirectSeam::new();
    // Original channel no longer exists, but the known producer still revokes its admission.
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::Refused {
            id: 1,
            why: "denied".into(),
        },
    );
    assert!(!state.logins.contains_key(&owner.login));
    assert!(!state.verified.contains_key(&my_uid()));
    assert!(state.retired.contains(&owner));
    assert!(state.live.is_empty());
    progress_refusal_seals(&mut state, Instant::now());
    assert!(matches!(
        state.monitors[&owner].refusal_seal,
        Some(RefusalSeal::Sent)
    ));
    let (bytes, fd) = channel::recv_once(&peer).unwrap().unwrap();
    assert!(
        fd.is_none()
            && matches!(
                decode::<MonitorRequest>(&bytes).unwrap(),
                MonitorRequest::SealRefused
            )
    );
    let fresh = owner.incarnation + 1;
    state.logins.insert(
        owner.login,
        LoginState::provisional(my_account(), String::new(), fresh),
    );
    state.verified.insert(my_uid(), my_account());
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::Refused {
            id: 2,
            why: "late".into(),
        },
    );
    assert_eq!(state.logins[&owner.login].incarnation, fresh);
    assert!(state.verified.contains_key(&my_uid()));
    let unknown = MonitorOwner {
        login: owner.login,
        incarnation: fresh,
    };
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        unknown,
        MonitorEvent::Refused {
            id: 3,
            why: "unknown".into(),
        },
    );
    assert_eq!(state.logins[&owner.login].incarnation, fresh);
    assert!(!state.retired.contains(&unknown));
}

#[test]
fn refusal406_failed_drain_preserves_pam_and_never_refunds_owner() {
    use super::super::{pam_completion::PamStep, protocol::RequestDrainFailure};
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(true);
    let seams = DirectSeam::new();
    let pam = PamCompletion::Finished {
        close_session: PamStep::Skipped,
        delete_cred: PamStep::Skipped,
        end: PamStep::Attempted(11),
    };
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::SessionClosed {
            result: pam,
            cleanup_failure: Some(CleanupFailure::PtyLabelRestore { errno: 13 }),
            request_failure: Some(RequestDrainFailure::Protocol),
        },
    );
    assert_eq!(state.pam_cleanup, pam);
    assert_eq!(
        state.cleanup_failure,
        Some(CleanupFailure::PtyLabelRestore { errno: 13 })
    );
    assert_eq!(
        state.monitors[&owner].failure,
        Some(MonitorFailure::Request(RequestDrainFailure::Protocol))
    );
    finish_retired(&mut state, owner);
    assert!(state.monitors.contains_key(&owner) && state.retired.contains(&owner));
}

#[test]
fn refusal406_pending_marker_does_not_block_event_reads_or_reset_deadline() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    let packet = encode(&MonitorRequest::SealRefused).unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    state.monitors.get_mut(&owner).unwrap().refusal_seal =
        Some(RefusalSeal::Pending { until, packet });
    state.live.insert(406, ChannelSlot::Cleaning(owner));
    let mut blocked = false;
    for _ in 0..4096 {
        match channel::try_send_once(state.monitors[&owner].seam(), &[b'x'; 8192]) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                blocked = true;
                break;
            }
            other => panic!("unexpected fill result {other:?}"),
        }
    }
    assert!(blocked);
    channel::send(
        &peer,
        &encode(&MonitorEvent::CleanupComplete {
            id: 406,
            kind: super::super::protocol::CleanupKind::NoChild,
        })
        .unwrap(),
        None,
    )
    .unwrap();
    let seams = DirectSeam::new();
    serve_ready_monitors(seams.seams(), &mut state, &[owner]);
    assert!(
        !state.live.contains_key(&406),
        "event receipt progresses while marker write blocked"
    );
    assert!(
        matches!(state.monitors[&owner].refusal_seal, Some(RefusalSeal::Pending { until: observed, .. }) if observed==until)
    );
    peer.set_nonblocking(true).unwrap();
    while channel::recv_once(&peer).is_ok() {}
    progress_refusal_seals(&mut state, Instant::now());
    assert!(matches!(
        state.monitors[&owner].refusal_seal,
        Some(RefusalSeal::Sent)
    ));
    let (bytes, fd) = channel::recv_once(&peer).unwrap().unwrap();
    assert!(
        fd.is_none()
            && matches!(
                decode::<MonitorRequest>(&bytes).unwrap(),
                MonitorRequest::SealRefused
            )
    );
    state.monitors.get_mut(&owner).unwrap().refusal_seal = Some(RefusalSeal::Pending {
        until: Instant::now(),
        packet: encode(&MonitorRequest::SealRefused).unwrap(),
    });
    progress_refusal_seals(&mut state, Instant::now());
    assert!(matches!(
        state.monitors[&owner].failure,
        Some(MonitorFailure::Request(
            super::super::protocol::RequestDrainFailure::Deadline
        ))
    ));
}

#[test]
fn refusal406_terminal_close_cannot_create_new_escalation_debt() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    state.monitors.get_mut(&owner).unwrap().refusal_seal = Some(RefusalSeal::Sent);
    state.live.insert(406, ChannelSlot::Cleaning(owner));
    state.live.insert(405, ChannelSlot::Cleaning(owner));
    let old_deadline = Instant::now() + MONITOR_GRACE_PERIOD;
    state.closing.insert(405, old_deadline);
    let seams = DirectSeam::new();
    channel::send(
        &seams.worker,
        &encode(&Request::Close { id: 406 }).unwrap(),
        None,
    )
    .unwrap();
    assert!(matches!(
        serve_channel_seam(&seams.helper, &mut state, &test_config(), UNPRIVILEGED),
        Next::Continue
    ));
    assert!(
        !state.closing.contains_key(&406),
        "an unsent terminal Close must not start escalation"
    );
    assert_eq!(
        state.closing[&405], old_deadline,
        "real preterminal obligations stay retained"
    );
    assert!(state.live.contains_key(&406));
    peer.set_nonblocking(true).unwrap();
    assert!(
        matches!(channel::recv_once(&peer), Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn refusal406_legacy_wait_preserves_physical_fact_without_clean_refund() {
    for code in [0, 75, 19] {
        let (mut signaled, signaled_owner, _signal_peer) = pam40_controlled_retiring_monitor(false);
        let monitor = signaled.monitors.get_mut(&signaled_owner).unwrap();
        assert!(monitor.refusal_seal.is_none());
        assert!(poll_monitor_wait_using(monitor, || Ok(
            nix::sys::wait::WaitStatus::Signaled(
                Pid::this(),
                nix::sys::signal::Signal::SIGKILL,
                false
            )
        )));
        monitor.reaped = true;
        assert!(
            !monitor.wait_lost
                && matches!(
                    monitor.failure,
                    Some(MonitorFailure::Request(
                        super::super::protocol::RequestDrainFailure::Exit
                    ))
                )
        );
        let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(false);
        let monitor = state.monitors.get_mut(&owner).unwrap();
        monitor.refusal_seal = Some(RefusalSeal::Sent);
        monitor.completion = Some(PamCompletion::NotOpened);
        assert!(poll_monitor_wait_using(monitor, || Ok(
            nix::sys::wait::WaitStatus::Exited(Pid::this(), code)
        )));
        monitor.reaped = true;
        assert!(!monitor.wait_lost);
        finish_retired(&mut state, owner);
        assert_eq!(state.monitors.contains_key(&owner), code != 0);
        if code != 0 {
            assert_eq!(
                state.monitors[&owner].failure,
                Some(MonitorFailure::Request(
                    super::super::protocol::RequestDrainFailure::Exit
                ))
            );
            assert_eq!(
                state.monitors[&owner].completion,
                Some(PamCompletion::NotOpened)
            );
        }
    }
    let (mut state, owner, _peer) = pam40_controlled_retiring_monitor(false);
    let monitor = state.monitors.get_mut(&owner).unwrap();
    monitor.refusal_seal = Some(RefusalSeal::Sent);
    monitor.completion = Some(PamCompletion::NotOpened);
    assert!(!poll_monitor_wait_using(monitor, || Err(
        nix::Error::ECHILD
    )));
    assert!(monitor.wait_lost && !monitor.reaped);
    finish_retired(&mut state, owner);
    assert!(state.monitors.contains_key(&owner));
}

#[test]
fn refusal406_legacy_wait_before_buffered_refusal_keeps_exit_failure() {
    let (mut state, owner, peer) = pam40_controlled_retiring_monitor(false);
    state.live.insert(406, ChannelSlot::Starting(owner));
    state.pending.insert(Pending {
        deadline: Instant::now() + Duration::from_secs(1),
        what: PendingWhat::Channel {
            id: 406,
            master: tempfile::tempfile().unwrap().into(),
            login: owner.login,
            uid: my_uid(),
            cancelled: false,
        },
    });
    let monitor = state.monitors.get_mut(&owner).unwrap();
    assert!(monitor.refusal_seal.is_none());
    assert!(poll_monitor_wait_using(monitor, || Ok(
        nix::sys::wait::WaitStatus::Exited(Pid::this(), 75)
    )));
    monitor.reaped = true;
    let seams = DirectSeam::new();
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::Refused {
            id: 406,
            why: "buffered denial".into(),
        },
    );
    progress_refusal_seals(&mut state, Instant::now());
    let (marker, fd) = channel::recv_once(&peer).unwrap().unwrap();
    assert!(
        fd.is_none()
            && matches!(
                decode::<MonitorRequest>(&marker).unwrap(),
                MonitorRequest::SealRefused
            )
    );
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::CleanupComplete {
            id: 406,
            kind: super::super::protocol::CleanupKind::NoChild,
        },
    );
    dispatch_monitor_event(
        seams.seams(),
        &mut state,
        owner,
        MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened,
            cleanup_failure: None,
            request_failure: None,
        },
    );
    let retained = state
        .monitors
        .get(&owner)
        .expect("early nonzero wait cannot be forgotten by buffered clean records");
    assert!(retained.reaped && !retained.wait_lost && retained.completion.is_some());
    assert_eq!(
        retained.failure,
        Some(MonitorFailure::Request(
            super::super::protocol::RequestDrainFailure::Exit
        ))
    );
}
