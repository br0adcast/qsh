mod required_reply {
    use super::*;

    fn saturated_pair() -> (UnixStream, UnixStream, usize) {
        let (sender, receiver) = channel::pair().unwrap();
        sender.set_nonblocking(true).unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut sent = 0;
        loop {
            match channel::send(&sender, &[b'f'; 1], None) {
                Ok(()) => {
                    sent += 1;
                    assert!(sent < 4096);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                other => panic!("unexpected filler result: {other:?}"),
            }
        }
        assert!(sent > 0);
        (sender, receiver, sent)
    }
    fn drain_filler(receiver: &UnixStream, expected: usize) {
        for _ in 0..expected {
            let (bytes, fd) = channel::recv_once(receiver).unwrap().unwrap();
            assert_eq!(bytes, vec![b'f'; 1]);
            assert!(fd.is_none());
        }
        assert!(
            matches!(channel::recv_once(receiver), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock)
        );
    }
    #[test]
    fn required40_exited_eagain_stays_failed_after_real_cleanup_publication() {
        let failure = exited_failure();
        assert!(matches!(failure.kind, RequiredPublication::Exited));
    }
    pub(super) fn exited_failure() -> RequiredPublicationFailure {
        let (sender, receiver, count) = saturated_pair();
        let mut state = empty_state();
        let owner = MonitorOwner {
            login: [40; 16],
            incarnation: 1,
        };
        state.live.insert(1, ChannelSlot::Running(owner));
        report_exit(&sender, &mut state, 1, 23);
        drain_filler(&receiver, count);
        complete_cleanup(
            &sender,
            &mut state,
            owner,
            1,
            crate::helper::protocol::CleanupKind::Reaped,
        );
        let (bytes, _) = channel::recv_once(&receiver).unwrap().unwrap();
        assert!(matches!(
            decode::<Response>(&bytes),
            Ok(Response::CleanupComplete { id: 1, .. })
        ));
        assert!(
            state.live.is_empty(),
            "actual cleanup debt is independently settled"
        );
        state
            .required_publication
            .expect("failed Exited must survive successful cleanup publication")
    }

    #[test]
    fn required40_cleanup_eagain_retains_failure_after_physical_slot_release() {
        let (sender, receiver, count) = saturated_pair();
        let mut state = empty_state();
        let owner = MonitorOwner {
            login: [40; 16],
            incarnation: 1,
        };
        state.live.insert(2, ChannelSlot::Cleaning(owner));
        complete_cleanup(
            &sender,
            &mut state,
            owner,
            2,
            crate::helper::protocol::CleanupKind::NoChild,
        );
        drain_filler(&receiver, count);
        assert!(state.live.is_empty());
        assert!(matches!(
            state.required_publication,
            Some(RequiredPublicationFailure {
                kind: RequiredPublication::Cleanup,
                error: PublicationError::Send(nix::libc::EAGAIN)
            })
        ));
    }

    #[test]
    fn required40_opened_fd_eagain_retains_exact_cleanup_slot() {
        let (sender, receiver, count) = saturated_pair();
        let account = my_account();
        let owner = MonitorOwner {
            login: [40; 16],
            incarnation: 1,
        };
        let mut state = state_with_login(&account, owner.login);
        state.live.insert(3, ChannelSlot::Starting(owner));
        apply_channel_verdict(
            &sender,
            &mut state,
            PendingWhat::Channel {
                id: 3,
                master: std::fs::File::open("/dev/null").unwrap().into(),
                login: owner.login,
                uid: account.uid,
                cancelled: false,
            },
            StartupReport::Started,
        );
        drain_filler(&receiver, count);
        assert!(
            matches!(state.live.get(&3), Some(ChannelSlot::Running(actual)) if *actual == owner)
        );
        assert!(matches!(
            state.required_publication,
            Some(RequiredPublicationFailure {
                kind: RequiredPublication::Opened,
                ..
            })
        ));
    }

    #[test]
    fn required40_refusal_and_nochild_eagain_keep_first_publication_failure() {
        let (sender, receiver, count) = saturated_pair();
        let mut state = empty_state();
        refuse_open(&sender, &mut state, 4, "fixture refused".into(), true);
        drain_filler(&receiver, count);
        assert!(state.live.is_empty());
        assert!(matches!(
            state.required_publication,
            Some(RequiredPublicationFailure {
                kind: RequiredPublication::Refused,
                ..
            })
        ));
    }

    #[test]
    fn required40_loginended_eagain_does_not_restore_authentication() {
        let (sender, receiver, count) = saturated_pair();
        let account = my_account();
        let owner = MonitorOwner {
            login: [40; 16],
            incarnation: 1,
        };
        let mut state = state_with_login(&account, owner.login);
        retire_login(&sender, &mut state, owner);
        drain_filler(&receiver, count);
        assert!(state.logins.is_empty() && state.verified.is_empty());
        assert!(matches!(
            state.required_publication,
            Some(RequiredPublicationFailure {
                kind: RequiredPublication::LoginEnded,
                ..
            })
        ));
    }

    #[test]
    fn required40_successful_lifecycle_publications_stay_clean() {
        let (sender, receiver) = channel::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut state = empty_state();
        let owner = MonitorOwner {
            login: [40; 16],
            incarnation: 1,
        };
        state.live.insert(1, ChannelSlot::Running(owner));
        report_exit(&sender, &mut state, 1, 0);
        complete_cleanup(
            &sender,
            &mut state,
            owner,
            1,
            crate::helper::protocol::CleanupKind::Reaped,
        );
        for expected in [
            Response::Exited { id: 1, code: 0 },
            Response::CleanupComplete {
                id: 1,
                kind: crate::helper::protocol::CleanupKind::Reaped,
            },
        ] {
            let (bytes, fd) = channel::recv_once(&receiver).unwrap().unwrap();
            assert_eq!(decode::<Response>(&bytes).unwrap(), expected);
            assert!(fd.is_none());
        }
        assert!(state.required_publication.is_none() && state.live.is_empty());
    }

    #[test]
    fn required40_optional_nonce_answer_and_release_do_not_acquire_cleanup_debt() {
        let (sender, receiver, count) = saturated_pair();
        let (channels, _peer) = channel::pair().unwrap();
        let seams = Seams {
            channels: &channels,
            auth: &sender,
        };
        let mut state = empty_state();
        channel::send(
            &receiver,
            &encode(&AuthRequest {
                id: 1,
                body: Request::Nonce,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        assert!(matches!(
            serve_auth_seam(seams, &mut state, &test_config(), UNPRIVILEGED),
            Next::Continue
        ));
        assert!(state.required_publication.is_none());
        let nonce = *state
            .nonces
            .keys()
            .next()
            .expect("nonce issued despite lost optional reply");
        channel::send(
            &receiver,
            &encode(&AuthRequest {
                id: 2,
                body: Request::ReleaseNonce { nonce },
            })
            .unwrap(),
            None,
        )
        .unwrap();
        assert!(matches!(
            serve_auth_seam(seams, &mut state, &test_config(), UNPRIVILEGED),
            Next::Continue
        ));
        drain_filler(&receiver, count);
        assert!(
            state.required_publication.is_none()
                && state.nonces.is_empty()
                && state.live.is_empty()
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn required40_cleanup_loss_settles_real_worker_after_safe_monitor_boundary() {
        super::adoption_native::run_case(Some("required_reply_cleanup"));
    }

    #[cfg(target_os = "linux")]
    pub(super) fn helper_body(dir: &Path, control: UnixStream) {
        let adoption = AdoptionRuntime::prepare().unwrap();
        let (owner, mut child) = super::adoption_pump::spawn_worker(dir);
        let (sender, receiver, count) = saturated_pair();
        let mut state = empty_state();
        let monitor = MonitorOwner {
            login: [40; 16],
            incarnation: 1,
        };
        state.live.insert(1, ChannelSlot::Cleaning(monitor));
        complete_cleanup(
            &sender,
            &mut state,
            monitor,
            1,
            crate::helper::protocol::CleanupKind::NoChild,
        );
        drain_filler(&receiver, count);
        let mut shutdown = HelperShutdown::new(state);
        shutdown.adoption = Some(adoption);
        shutdown.worker = Some(WorkerDomain::new(owner));
        let worker = shutdown.worker.as_mut().unwrap();
        worker.advance(); // consumes the actual established-stage record before Stop
        begin_owned_stop(
            &sender,
            &mut shutdown.state,
            worker,
            crate::helper::worker_protocol::StopReason::Requested,
        );
        worker.send_stop();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !dir.join("stopped").exists() {
            assert!(
                Instant::now() < deadline,
                "real held manager did not receive Stop"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(monitor_and_verifier_domains_settled(&shutdown.state));
        assert!(shutdown.state.live.is_empty());
        shutdown
            .worker
            .as_mut()
            .unwrap()
            .observe_required_publication(&shutdown.state);
        assert_eq!(
            shutdown.worker.as_ref().unwrap().stop_reason,
            Some(crate::helper::worker_protocol::StopReason::Requested)
        );
        shutdown.progress_adopted_children();
        let forced = shutdown.forced_worker;
        if !forced {
            std::fs::write(dir.join("release"), b"release").unwrap();
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while !(shutdown.worker.as_ref().unwrap().settled()
            && shutdown.adoption.as_ref().unwrap().complete)
        {
            assert!(
                Instant::now() < deadline,
                "owned worker/adoption failed to settle"
            );
            shutdown.worker.as_mut().unwrap().advance();
            shutdown.progress_adopted_children();
            std::thread::sleep(Duration::from_millis(1));
        }
        let native = shutdown.worker.as_ref().unwrap().physical_outcome();
        let reaped =
            matches!(child.try_wait(), Err(e) if e.raw_os_error() == Some(nix::libc::ECHILD));
        drop(child);
        assert!(reaped);
        assert!(forced, "undeliverable required cleanup must not strand cooperative worker after safe cleanup boundary");
        assert!(
            !native.terminal_received,
            "forced exit cannot fabricate a joined receipt"
        );
        std::fs::write(
            dir.join("helper-result"),
            "required_cleanup_failed=true, no_children=true",
        )
        .unwrap();
        channel::send(&control, b"done", None).unwrap();
    }
    #[cfg(target_os = "linux")]
    pub(super) fn drive(control: &UnixStream) -> Vec<super::adoption_native::Pin> {
        control
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        assert_eq!(channel::recv(control).unwrap().unwrap().0, b"done");
        Vec::new()
    }

    #[test]
    fn required40_encoding_failure_remains_failed_when_nochild_packet_delivers() {
        let (sender, receiver) = channel::pair().unwrap();
        receiver.set_nonblocking(true).unwrap();
        let mut state = empty_state();
        refuse_open(
            &sender,
            &mut state,
            7,
            "x".repeat(crate::helper::protocol::MAX_MESSAGE_LEN),
            true,
        );
        let (bytes, _) = channel::recv_once(&receiver).unwrap().unwrap();
        assert!(matches!(
            decode::<Response>(&bytes),
            Ok(Response::CleanupComplete {
                id: 7,
                kind: crate::helper::protocol::CleanupKind::NoChild
            })
        ));
        assert!(matches!(
            state.required_publication,
            Some(RequiredPublicationFailure {
                kind: RequiredPublication::Refused,
                error: PublicationError::Encode
            })
        ));
    }

    #[test]
    fn required40_publication_failure_closes_admission_before_next_pump_turn() {
        let (sender, receiver, count) = saturated_pair();
        let account = my_account();
        let login = [40; 16];
        let mut state = state_with_login(&account, login);
        refuse_open(&sender, &mut state, 1, "fixture refusal".into(), true);
        drain_filler(&receiver, count);
        assert!(!state.stopping && state.required_publication.is_some());
        channel::send(
            &receiver,
            &encode(&open_request(2, account.uid.as_raw(), login)).unwrap(),
            None,
        )
        .unwrap();
        assert!(matches!(
            serve_channel_seam(&sender, &mut state, &test_config(), UNPRIVILEGED),
            Next::Continue
        ));
        for _ in 0..2 {
            channel::recv_once(&receiver).unwrap().unwrap();
        }
        let (auth, peer) = channel::pair().unwrap();
        channel::send(
            &peer,
            &encode(&AuthRequest {
                id: 9,
                body: Request::Nonce,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        assert!(matches!(
            serve_auth_seam(
                Seams {
                    channels: &sender,
                    auth: &auth
                },
                &mut state,
                &test_config(),
                UNPRIVILEGED
            ),
            Next::Continue
        ));
        let (bytes, _) = channel::recv_once(&peer).unwrap().unwrap();
        assert!(matches!(
            decode::<AuthResponse>(&bytes),
            Ok(AuthResponse {
                id: 9,
                body: Response::NonceUnavailable
            })
        ));
        assert!(state.live.is_empty() && state.monitors.is_empty() && state.nonces.is_empty());
    }

    #[test]
    fn required40_pending_verdict_cannot_admit_after_same_pass_publication_failure() {
        let (sender, receiver, count) = saturated_pair();
        let mut state = empty_state();
        refuse_open(&sender, &mut state, 1, "fixture refusal".into(), true);
        drain_filler(&receiver, count);
        assert!(!state.stopping && state.required_publication.is_some());
        let seam = DirectSeam::new();
        publish_verification(
            seam.seams(),
            &mut state,
            VerificationReply {
                id: 40,
                login: "controlled",
                login_id: [44; 16],
                rhost: "fixture",
            },
            Some(Verdict::Admitted {
                account: distinctive_account(),
                identity: "SHA256:controlled".into(),
                algorithm: "ED25519".into(),
            }),
            WhyFinished::Spoke,
        );
        let response = next_answer(&seam.worker_auth);
        assert!(
            matches!(response.body, Response::Refused { .. }),
            "pending verdict cannot file a new login after required publication failed"
        );
        assert!(state.logins.is_empty() && state.verified.is_empty());
    }
}
