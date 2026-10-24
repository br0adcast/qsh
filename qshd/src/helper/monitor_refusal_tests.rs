#[cfg(target_os = "linux")]
mod queued_refusal {
    use super::*;
    use std::os::unix::process::CommandExt;

    #[test]
    fn refusal209_queued_refusal_survives_native_exit_before_first_receive() {
        let diagnostic = std::env::var_os("QSH_TEST_REFUSAL209_REPORT");
        let outcome = crate::test_borrowed_scope::run_exact(
            "helper::server::tests::queued_refusal::refusal209_queued_refusal_survives_native_exit_before_first_receive",
            0,
            || queued_refusal_body("refused"),
        );
        if let Some(path) = diagnostic {
            eprintln!(
                "queued refusal evidence: {}",
                std::fs::read_to_string(path).unwrap_or_default()
            );
        }
        outcome.assert_clean(0);
    }

    #[test]
    fn refusal209_queued_started_cannot_reopen_a_retired_login() {
        crate::test_borrowed_scope::run_exact(
            "helper::server::tests::queued_refusal::refusal209_queued_started_cannot_reopen_a_retired_login",
            0, || queued_refusal_body("started"),
        ).assert_clean(0);
    }

    #[test]
    fn refusal209_missing_outcome_settles_before_inherited_seam_eof() {
        crate::test_borrowed_scope::run_exact(
            "helper::server::tests::queued_refusal::refusal209_missing_outcome_settles_before_inherited_seam_eof",
            0, || queued_refusal_body("missing-held"),
        ).assert_clean(0);
    }

    #[test]
    fn pam258_notification_failure_after_exit_does_not_hide_complete_proof() {
        crate::test_borrowed_scope::run_exact(
            "helper::server::tests::queued_refusal::pam258_notification_failure_after_exit_does_not_hide_complete_proof",
            0,
            || queued_refusal_body("refused-gated"),
        ).assert_clean(0);
    }

    #[test]
    fn pam258_active_retirement_close_failure_does_not_hide_complete_proof() {
        crate::test_borrowed_scope::run_exact(
            "helper::server::tests::queued_refusal::pam258_active_retirement_close_failure_does_not_hide_complete_proof",
            0,
            || queued_refusal_body_with_stop("refused-gated", false),
        ).assert_clean(0);
    }

    #[test]
    fn pam258_stale_close_preserves_real_failure_and_receipt_debt() {
        crate::test_borrowed_scope::run_exact(
            "helper::server::tests::queued_refusal::pam258_stale_close_preserves_real_failure_and_receipt_debt",
            0,
            || {
                for mode in ["refused-gated-missing", "refused-gated-malformed", "refused-gated-prior", "refused-gated-running", "refused-gated-open", "refused-gated-unknown"] {
                    queued_refusal_body_with_stop(mode, true);
                }
            },
        ).assert_clean(0);
    }

    #[test]
    fn pam258_only_close_epipe_rechecks_native_terminal_state() {
        let close = MonitorRequest::Close { id: 258 };
        let open = MonitorRequest::Open {
            id: 258,
            term: None,
            shell: false,
            command: "true".into(),
        };
        assert!(close_pipe_error(&close, nix::libc::EPIPE));
        for errno in [nix::libc::EPERM, nix::libc::EAGAIN, nix::libc::EIO] {
            assert!(!close_pipe_error(&close, errno));
        }
        assert!(!close_pipe_error(&open, nix::libc::EPIPE));
    }

    #[test]
    fn refusal209_malformed_outcome_never_becomes_a_specific_pam_refusal() {
        crate::test_borrowed_scope::run_exact(
            "helper::server::tests::queued_refusal::refusal209_malformed_outcome_never_becomes_a_specific_pam_refusal",
            0, || queued_refusal_body("malformed-outcome"),
        ).assert_clean(0);
    }

    fn queued_refusal_body(mode: &str) {
        queued_refusal_body_with_stop(mode, true);
    }

    fn queued_refusal_body_with_stop(mode: &str, stopping: bool) {
        let view = crate::process_scope::prepare().unwrap();
        let (parent, producer) = super::super::super::worker_control::pair().unwrap();
        let raw = producer.as_raw_fd();
        let gated = mode.starts_with("refused-gated");
        let (mut gate, gate_child) = UnixStream::pair().unwrap();
        gate.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let gate_raw = gate_child.as_raw_fd();
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "helper::monitor_owner::tests::monitor40_private_producer_body",
                "--ignored",
                "--test-threads=1",
            ])
            .env("QSH_TEST_MONITOR_OWNER_MODE", mode)
            .env("QSH_TEST_MONITOR_OWNER_FD", raw.to_string())
            .env("QSH_TEST_MONITOR_GATE_FD", gate_raw.to_string())
            .env(
                "QSH_TEST_MONITOR_OWNER_PARENT",
                std::process::id().to_string(),
            )
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if nix::libc::fcntl(raw, nix::libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if gated && nix::libc::fcntl(gate_raw, nix::libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        drop(gate_child);
        let mut native = super::super::super::monitor_owner::NativeMonitor::new(
            std::num::NonZeroU32::new(child.id()).unwrap(),
            view,
            parent,
        );
        if gated {
            use std::io::{Read as _, Write as _};
            let mut stage_sent = [0u8; 1];
            gate.read_exact(&mut stage_sent).unwrap();
            assert_eq!(&stage_sent, b"S");
            let stage = native.advance(Instant::now());
            assert_eq!(
                stage.leader,
                crate::process_scope::scope::LeaderStatus::Running
            );
            assert!(stage.failure.is_none() && stage.event.is_none());
            assert!(!native.leader_exited());
            if !mode.ends_with("-running") {
                gate.write_all(b"X").unwrap();
            }
        }
        // Retain the peer in the missing-outcome control: original-producer
        // exit must settle its queue even if an inherited writer prevents EOF.
        let inherited_writer = (mode == "missing-held").then_some(producer);
        let deadline = Instant::now() + Duration::from_secs(3);
        // Nonreaping observation: all records must be queued before the first
        // receive, while the original process remains exclusively waitable.
        while if gated && mode.ends_with("-running") {
            false
        } else if gated {
            use nix::sys::wait::{waitid, Id, WaitPidFlag, WaitStatus};
            // Observe this exact waitable child without consuming its wait or
            // refreshing NativeMonitor's prior Running observation.
            matches!(
                waitid(
                    Id::Pid(Pid::from_raw(child.id() as i32)),
                    WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG
                )
                .unwrap(),
                WaitStatus::StillAlive
            )
        } else {
            native.leader() == crate::process_scope::scope::LeaderStatus::Running
        } {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        if mode.ends_with("-unknown") {
            assert!(child.wait().unwrap().success(), "controlled stolen wait");
        }
        let login = [209; 16];
        let mut state = state_with_login(&my_account(), login);
        let owner = owner_for(&state, login);
        state.live.insert(209, ChannelSlot::Starting(owner));
        state.pending.insert(Pending {
            deadline,
            what: PendingWhat::Channel {
                id: 209,
                master: tempfile::tempfile().unwrap().into(),
                login,
                uid: my_uid(),
                cancelled: false,
            },
        });
        state.monitors.insert(
            owner,
            Monitor {
                process: MonitorProcess::Native(native),
                pid: Pid::from_raw(child.id() as i32),
                reaped: false,
                write_closed: false,
                stop_attempted: false,
                completion: None,
                seam_closed: false,
                wait_lost: false,
                failure: None,
                signal_failure: None,
            },
        );
        let (channels, receiver) = channel::pair().unwrap();
        let (auth, _auth_peer) = channel::pair().unwrap();
        let seams = Seams {
            channels: &channels,
            auth: &auth,
        };
        if gated {
            let mut shutdown = HelperShutdown::new(state);
            if mode.ends_with("-prior") {
                shutdown.state.monitors.get_mut(&owner).unwrap().failure =
                    Some(MonitorFailure::DuplicateCompletion);
                shutdown.observe_monitor_failures();
            }
            if mode.ends_with("-open") {
                tell_monitor(
                    seams.channels,
                    &mut shutdown.state,
                    owner,
                    &MonitorRequest::Open {
                        id: 209,
                        term: None,
                        shell: false,
                        command: "true".into(),
                    },
                );
            }
            if stopping {
                shutdown.begin_monitor_stop(seams);
            } else {
                retire_login(seams.channels, &mut shutdown.state, owner);
            }
            if mode.ends_with("-running") {
                use std::io::Write as _;
                assert!(matches!(
                    shutdown.state.monitors[&owner].failure,
                    Some(MonitorFailure::Send(nix::libc::EPIPE))
                ));
                gate.write_all(b"X").unwrap();
            }
            if mode.ends_with("-unknown") {
                while shutdown.state.monitors[&owner].completion.is_none() {
                    assert!(
                        Instant::now() < deadline,
                        "unknown owner lost its queued final receipt"
                    );
                    shutdown.monitor_pass(seams, &test_config());
                }
                let retained = &shutdown.state.monitors[&owner];
                assert!(retained.wait_lost && !retained.reaped);
                assert!(retained.failure.is_some() && shutdown.first_monitor_failure.is_some());
                assert!(shutdown.state.retired.contains(&owner));
                assert!(
                    child.try_wait().unwrap().is_some(),
                    "controlled stolen wait already consumed the exact child"
                );
                return;
            }
            while shutdown
                .state
                .monitors
                .get(&owner)
                .is_some_and(|monitor| !monitor.reaped)
            {
                assert!(
                    Instant::now() < deadline,
                    "native phase producer did not settle"
                );
                shutdown.monitor_pass(seams, &test_config());
            }
            let product_waited = matches!(child.try_wait(), Err(error) if error.raw_os_error()==Some(nix::libc::ECHILD));
            assert!(product_waited && shutdown.state.live.is_empty());
            if mode != "refused-gated" {
                let retained = shutdown
                    .state
                    .monitors
                    .get(&owner)
                    .expect("real failure or missing receipt remains retained");
                assert!(retained.reaped && shutdown.state.retired.contains(&owner));
                if mode.ends_with("-missing") || mode.ends_with("-malformed") {
                    assert_eq!(retained.completion, None);
                } else {
                    assert_eq!(retained.completion, Some(PamCompletion::NotOpened));
                }
                assert!(retained.failure.is_some() && shutdown.first_monitor_failure.is_some());
                if mode.ends_with("-prior") {
                    assert_eq!(retained.failure, Some(MonitorFailure::DuplicateCompletion));
                    assert_eq!(
                        shutdown.first_monitor_failure,
                        Some(MonitorShutdownFailure::Monitor(
                            MonitorFailure::DuplicateCompletion
                        ))
                    );
                }
            } else {
                assert!(shutdown.state.retired.is_empty() && shutdown.state.monitors.is_empty(), "notification failure cannot hide complete proof: live={} retired={} monitors={} first_failure={:?}", shutdown.state.live.len(),shutdown.state.retired.len(),shutdown.state.monitors.len(),shutdown.first_monitor_failure);
                assert_eq!(shutdown.state.pam_cleanup, PamCompletion::NotOpened);
                assert_eq!(shutdown.first_monitor_failure, None);
            }
            return;
        }
        serve_ready_monitors(seams, &mut state, &[]);
        let revoked_after_stage = !state.logins.contains_key(&login);
        let retained_after_stage = !state.pending.is_empty();
        while state
            .monitors
            .get(&owner)
            .is_some_and(|monitor| !monitor.reaped)
        {
            assert!(
                Instant::now() < deadline,
                "actual native producer wait did not settle"
            );
            serve_ready_monitors(seams, &mut state, &[]);
            std::thread::sleep(Duration::from_millis(1));
        }
        let product_waited = matches!(child.try_wait(), Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD));
        let mut answer = None;
        let mut opened = false;
        let mut received_fd = false;
        receiver.set_nonblocking(true).unwrap();
        while let Ok(Some((bytes, fd))) = channel::recv_once(&receiver) {
            received_fd |= fd.is_some();
            let response = decode::<Response>(&bytes).unwrap();
            opened |= matches!(response, Response::Opened { .. });
            if let Response::Failed { id: 209, reason } = response {
                answer = Some((reason, fd.is_none()));
            }
        }
        if let Some(path) = std::env::var_os("QSH_TEST_REFUSAL209_REPORT") {
            std::fs::write(path, format!("product_waited={product_waited}, revoked_after_stage={revoked_after_stage}, answer={answer:?}, pending_empty={}, live={}", state.pending.is_empty(), state.live.len())).unwrap();
        }
        let peer_still_open = state
            .monitors
            .get(&owner)
            .is_some_and(|monitor| !monitor.seam_closed);
        drop(inherited_writer);
        assert!(product_waited && revoked_after_stage && retained_after_stage);
        assert!(
            !opened && !received_fd,
            "retired login cannot admit any terminal"
        );
        if mode == "refused" {
            assert_eq!(
                answer,
                Some((REFUSED_REASON.into(), true)),
                "queued PAM refusal must precede generic retirement cancellation"
            );
            assert!(state.pending.is_empty() && state.live.is_empty());
        } else {
            let (reason, no_fd) = answer.expect("retired startup must fail");
            assert!(no_fd && reason != REFUSED_REASON);
            assert!(state.pending.is_empty());
            if mode == "missing-held" {
                assert!(
                    peer_still_open,
                    "WouldBlock, not inherited EOF, settled the original queue"
                );
                assert!(
                    state.live.contains_key(&209),
                    "missing cleanup evidence remains debt"
                );
            }
        }
    }
}
