// Proof keys are freshly generated for isolated temporary authorized_keys fixtures.
// They never authorize a real account or service; peer admission remains a test-only
// capability until the separate authenticated local-channel integration.
mod host_policy {
    use super::super::policy_check::*;
    use super::*;
    use crate::session_owner::authorization::{AuthenticatedPeer, AuthenticationAttempt, HostMode};
    use crate::session_owner::host::{HostDecision, HostLimits, HostState};
    use crate::session_owner::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
    use std::sync::mpsc::{sync_channel, Receiver};
    use transport::auth::AuthRecord;

    fn host() -> (
        HostState,
        crate::session_owner::authorization::FrontendAdmission,
    ) {
        let bytes = ByteLimits {
            channel_bytes: 1024,
            session_bytes: 2048,
            account_bytes: 4096,
            global_bytes: 8192,
        };
        let limits = HostLimits::new(
            ResourceLimits {
                max_reservations: 128,
                screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default())
                    .unwrap(),
                snapshot_transfer: bytes,
                control_queue: bytes,
            },
            4,
            4,
            4,
            4,
            1000,
        )
        .unwrap();
        let mut host = HostState::new(HostMode::System, limits).unwrap();
        let frontend = host
            .admit_frontend(AuthenticatedPeer::for_test(
                host.instance(),
                HostMode::System,
            ))
            .unwrap();
        (host, frontend)
    }
    fn make_key() -> PrivateKey {
        PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .unwrap()
    }
    fn proof(key: &PrivateKey, nonce: [u8; 16]) -> AuthRecord {
        let Request::Verify {
            login,
            public_key,
            signature,
            nonce,
            ..
        } = proof_for_login(key, &my_login(), [7; 32], nonce, [9; 16])
        else {
            unreachable!()
        };
        AuthRecord {
            public_key,
            signature,
            v2: Some(AuthV2 { login, nonce }),
        }
    }
    fn submit_auth(
        state: &mut LoopState,
        host: &mut HostState,
        frontend: crate::session_owner::authorization::FrontendAdmission,
        key: &PrivateKey,
        config: &HelperConfig,
        now: u64,
    ) -> Receiver<crate::session_owner::authorization::PolicyResult> {
        let intent = host
            .begin_authentication(frontend, now, now + 10_000)
            .unwrap();
        let ticket = issue_nonce_for_host(state, intent, now).unwrap();
        let record = proof(key, ticket.nonce());
        let (tx, rx) = sync_channel(1);
        start_authentication(
            state,
            ticket,
            HostProof {
                record,
                handshake_hash: [7; 32],
            },
            tx,
            config,
            UNPRIVILEGED,
            now,
        )
        .unwrap();
        rx
    }
    fn authenticate(
        state: &mut LoopState,
        seams: &DirectSeam,
        host: &mut HostState,
        frontend: crate::session_owner::authorization::FrontendAdmission,
        key: &PrivateKey,
        config: &HelperConfig,
    ) -> AuthenticationAttempt {
        let rx = submit_auth(state, host, frontend, key, config, 0);
        seams.settle(state, config);
        let HostDecision::Authenticated(a) = host
            .apply_policy_result(rx.recv_timeout(TEST_RECV_TIMEOUT).unwrap(), 1)
            .unwrap()
        else {
            panic!()
        };
        a
    }
    fn isolated(body: &str) {
        let name = format!("helper::server::tests::host_policy::{body}");
        let (status, stdout, stderr) = super::super::super::spawner::tests::run_isolated(&name);
        assert!(
            status.success(),
            "isolated {body} failed {status}:\n{stdout}\n{stderr}"
        );
    }
    #[test]
    fn host529_policy_real_auth_and_two_policy_checks_do_not_create_logins() {
        isolated("real_auth_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn real_auth_body() {
        let key = make_key();
        let dir = tempfile::tempdir().unwrap();
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seams = DirectSeam::new();
        let (mut host, frontend) = host();
        let a = authenticate(&mut state, &seams, &mut host, frontend, &key, &config);
        assert!(state.nonces.is_empty());
        let locator = host.create_session(a, 2).unwrap();
        let intent = host.begin_issue(a, locator, 3, 10_000).unwrap();
        let (tx, rx) = sync_channel(1);
        start_policy_check(&mut state, intent, tx, &config, UNPRIVILEGED, 3).unwrap();
        seams.settle(&mut state, &config);
        let HostDecision::GrantIssued(g) = host.apply_policy_result(rx.recv().unwrap(), 4).unwrap()
        else {
            panic!()
        };
        let intent = host
            .begin_consume(a, g.grant(), g.binding(), 5, 10_000)
            .unwrap();
        let (tx, rx) = sync_channel(1);
        start_policy_check(&mut state, intent, tx, &config, UNPRIVILEGED, 5).unwrap();
        seams.settle(&mut state, &config);
        assert!(matches!(
            host.apply_policy_result(rx.recv().unwrap(), 6),
            Ok(HostDecision::GrantConsumed(_))
        ));
        assert!(state.logins.is_empty());
        assert!(state.verified.is_empty());
        assert!(state.monitors.is_empty());
        assert_eq!(state.next_incarnation, 1);
        assert!(matches!(state.pam_cleanup, PamCompletion::NotOpened));
        assert!(
            state.nonces.is_empty(),
            "policy-only jobs never issue/spend another nonce"
        );
        assert!(state.pending.is_empty());
    }
    #[test]
    fn host529_policy_key_revocation_between_issue_and_consume_is_current() {
        isolated("revocation_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn revocation_body() {
        let key = make_key();
        let dir = tempfile::tempdir().unwrap();
        for remove_before_issue in [false, true] {
            let config = trusting_config(dir.path(), &key);
            let mut state = empty_state();
            let seams = DirectSeam::new();
            let (mut host, frontend) = host();
            let a = authenticate(&mut state, &seams, &mut host, frontend, &key, &config);
            let locator = host.create_session(a, 2).unwrap();
            if remove_before_issue {
                std::fs::write(&config.authorized_keys_template, "").unwrap();
            }
            let intent = host.begin_issue(a, locator, 3, 10_000).unwrap();
            let (tx, rx) = sync_channel(1);
            start_policy_check(&mut state, intent, tx, &config, UNPRIVILEGED, 3).unwrap();
            seams.settle(&mut state, &config);
            let result = host.apply_policy_result(rx.recv().unwrap(), 4);
            if remove_before_issue {
                assert!(result.is_err());
            } else {
                let HostDecision::GrantIssued(g) = result.unwrap() else {
                    panic!()
                };
                std::fs::write(&config.authorized_keys_template, "").unwrap();
                let intent = host
                    .begin_consume(a, g.grant(), g.binding(), 5, 10_000)
                    .unwrap();
                let (tx, rx) = sync_channel(1);
                start_policy_check(&mut state, intent, tx, &config, UNPRIVILEGED, 5).unwrap();
                seams.settle(&mut state, &config);
                assert!(host.apply_policy_result(rx.recv().unwrap(), 6).is_err());
            }
            assert_eq!(host.catalog_len(), 1);
            assert!(state.logins.is_empty());
            assert!(state.monitors.is_empty());
        }
    }
    #[test]
    fn host529_policy_forged_signature_and_wrong_key_refuse() {
        isolated("forgery_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn forgery_body() {
        let key = make_key();
        let stranger = make_key();
        let dir = tempfile::tempdir().unwrap();
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seams = DirectSeam::new();
        let (mut host, frontend) = host();
        for (round, wrong_key) in [false, true].into_iter().enumerate() {
            let now = round as u64 * 2;
            let intent = host.begin_authentication(frontend, now, 10_000).unwrap();
            let ticket = issue_nonce_for_host(&mut state, intent, now).unwrap();
            let nonce = ticket.nonce();
            let mut record = proof(if wrong_key { &stranger } else { &key }, nonce);
            if !wrong_key {
                record.signature[0] ^= 1;
            }
            let (tx, rx) = sync_channel(1);
            start_authentication(
                &mut state,
                ticket,
                HostProof {
                    record,
                    handshake_hash: [7; 32],
                },
                tx,
                &config,
                UNPRIVILEGED,
                now,
            )
            .unwrap();
            seams.settle(&mut state, &config);
            assert!(host
                .apply_policy_result(rx.recv().unwrap(), now + 1)
                .is_err());
            assert!(!state.nonces.contains_key(&nonce));
        }
        assert!(state.logins.is_empty());
        assert!(state.verified.is_empty());
    }
    #[test]
    fn host529_policy_nonce_cannot_be_redirected_to_legacy_login() {
        isolated("nonce_destination_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn nonce_destination_body() {
        let key = make_key();
        let dir = tempfile::tempdir().unwrap();
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seams = DirectSeam::new();
        let (mut host, frontend) = host();
        let intent = host.begin_authentication(frontend, 0, 10_000).unwrap();
        let ticket = issue_nonce_for_host(&mut state, intent, 0).unwrap();
        // A captured signed proof must not select the legacy login destination.
        let request = proof_for_login(&key, &my_login(), [7; 32], ticket.nonce(), [8; 16]);
        seams.serve_auth(&mut state, request, &config, UNPRIVILEGED);
        seams.settle(&mut state, &config);
        assert!(matches!(
            next_answer(&seams.worker_auth).body,
            Response::Refused { .. }
        ));
        assert!(state.logins.is_empty());
        assert!(state.verified.is_empty());
        seams.serve_auth(
            &mut state,
            Request::ReleaseNonce {
                nonce: ticket.nonce(),
            },
            &config,
            UNPRIVILEGED,
        );
        assert!(
            state.host_nonces.contains_key(&ticket.nonce()),
            "legacy release cannot cancel host authority"
        );
        let record = proof(&key, ticket.nonce());
        let (tx, rx) = sync_channel(1);
        start_authentication(
            &mut state,
            ticket,
            HostProof {
                record,
                handshake_hash: [7; 32],
            },
            tx,
            &config,
            UNPRIVILEGED,
            0,
        )
        .unwrap();
        seams.settle(&mut state, &config);
        assert!(matches!(
            host.apply_policy_result(rx.recv().unwrap(), 1),
            Ok(HostDecision::Authenticated(_))
        ));
        assert!(state.logins.is_empty());
    }

    #[test]
    fn host529_policy_nonce_replay_expiry_shared_capacity_and_recovery() {
        isolated("nonce_lifecycle_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn nonce_lifecycle_body() {
        let key = make_key();
        let dir = tempfile::tempdir().unwrap();
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seams = DirectSeam::new();
        let (mut host, frontend) = host();
        let intent = host.begin_authentication(frontend, 0, 10_000).unwrap();
        let ticket = issue_nonce_for_host(&mut state, intent, 0).unwrap();
        let replay = ticket.duplicate_for_test();
        let record = proof(&key, ticket.nonce());
        let (tx, rx) = sync_channel(1);
        start_authentication(
            &mut state,
            ticket,
            HostProof {
                record: record.clone(),
                handshake_hash: [7; 32],
            },
            tx,
            &config,
            UNPRIVILEGED,
            0,
        )
        .unwrap();
        seams.settle(&mut state, &config);
        assert!(matches!(
            host.apply_policy_result(rx.recv().unwrap(), 1),
            Ok(HostDecision::Authenticated(_))
        ));
        let (tx, rx) = sync_channel(1);
        assert!(start_authentication(
            &mut state,
            replay,
            HostProof {
                record,
                handshake_hash: [7; 32]
            },
            tx,
            &config,
            UNPRIVILEGED,
            1
        )
        .is_err());
        assert!(host.apply_policy_result(rx.recv().unwrap(), 1).is_err());
        assert!(state.pending.is_empty());
        let intent = host.begin_authentication(frontend, 2, 10_000).unwrap();
        let ticket = issue_nonce_for_host(&mut state, intent, 2).unwrap();
        state
            .host_nonces
            .insert(ticket.nonce(), Instant::now() - NONCE_LIFETIME);
        let record = proof(&key, ticket.nonce());
        let (tx, rx) = sync_channel(1);
        assert!(start_authentication(
            &mut state,
            ticket,
            HostProof {
                record,
                handshake_hash: [7; 32]
            },
            tx,
            &config,
            UNPRIVILEGED,
            2
        )
        .is_err());
        assert!(host.apply_policy_result(rx.recv().unwrap(), 3).is_err());
        assert!(state.host_nonces.is_empty());
        for _ in 0..MAX_OUTSTANDING_NONCES - 1 {
            issue_nonce(&mut state.nonces).unwrap();
        }
        let intent = host.begin_authentication(frontend, 4, 10_000).unwrap();
        let ticket = issue_nonce_for_host(&mut state, intent, 4).unwrap();
        assert_eq!(
            state.nonces.len() + state.host_nonces.len(),
            MAX_OUTSTANDING_NONCES
        );
        assert!(!state.nonces.contains_key(&ticket.nonce()));
        seams.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        assert!(matches!(
            next_answer(&seams.worker_auth).body,
            Response::NonceUnavailable
        ));
        let intent = host.begin_authentication(frontend, 5, 10_000).unwrap();
        assert!(issue_nonce_for_host(&mut state, intent, 5).is_err());
        state
            .host_nonces
            .insert(ticket.nonce(), Instant::now() - NONCE_LIFETIME);
        reap(&seams.helper, &mut state);
        assert!(state.host_nonces.is_empty());
        assert_eq!(state.nonces.len(), MAX_OUTSTANDING_NONCES - 1);
        seams.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        assert!(matches!(
            next_answer(&seams.worker_auth).body,
            Response::Nonce { .. }
        ));
    }
    fn changed_uid(login: &str) -> Result<Account, AccountError> {
        let mut a = super::super::account::lookup(login)?;
        a.uid = Uid::from_raw(a.uid.as_raw() + 1);
        Ok(a)
    }
    fn changed_name(login: &str) -> Result<Account, AccountError> {
        let mut a = super::super::account::lookup(login)?;
        a.name.push_str("-changed");
        Ok(a)
    }
    fn root_alias(login: &str) -> Result<Account, AccountError> {
        let mut a = super::super::account::lookup(login)?;
        a.uid = Uid::from_raw(0);
        Ok(a)
    }
    #[test]
    fn host529_policy_current_account_and_root_restrictions_are_rechecked() {
        isolated("account_policy_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn account_policy_body() {
        let key = make_key();
        let dir = tempfile::tempdir().unwrap();
        let mut config = trusting_config(dir.path(), &key);
        for lookup in [
            changed_uid as fn(&str) -> Result<Account, AccountError>,
            changed_name as fn(&str) -> Result<Account, AccountError>,
        ] {
            let mut state = empty_state();
            let seams = DirectSeam::new();
            let (mut host, frontend) = host();
            let a = authenticate(&mut state, &seams, &mut host, frontend, &key, &config);
            let s = host.create_session(a, 2).unwrap();
            let intent = host.begin_issue(a, s, 3, 10_000).unwrap();
            let (tx, rx) = sync_channel(1);
            start_policy_check(
                &mut state,
                intent,
                tx,
                &config,
                AccountSwitches {
                    lookup,
                    ..UNPRIVILEGED
                },
                3,
            )
            .unwrap();
            seams.settle(&mut state, &config);
            assert!(host.apply_policy_result(rx.recv().unwrap(), 4).is_err());
            assert_eq!(host.catalog_len(), 1);
            assert!(state.logins.is_empty());
        }
        // UID-based root policy also applies to an alias whose name is not root.
        let mut state = empty_state();
        let seams = DirectSeam::new();
        let (mut host, frontend) = host();
        config.permit_root = true;
        let switches = AccountSwitches {
            lookup: root_alias,
            ..UNPRIVILEGED
        };
        let intent = host.begin_authentication(frontend, 0, 10_000).unwrap();
        let ticket = issue_nonce_for_host(&mut state, intent, 0).unwrap();
        let record = proof(&key, ticket.nonce());
        let (tx, rx) = sync_channel(1);
        start_authentication(
            &mut state,
            ticket,
            HostProof {
                record,
                handshake_hash: [7; 32],
            },
            tx,
            &config,
            switches,
            0,
        )
        .unwrap();
        seams.settle(&mut state, &config);
        let HostDecision::Authenticated(a) =
            host.apply_policy_result(rx.recv().unwrap(), 1).unwrap()
        else {
            panic!()
        };
        let s = host.create_session(a, 2).unwrap();
        config.permit_root = false;
        let intent = host.begin_issue(a, s, 3, 10_000).unwrap();
        let (tx, rx) = sync_channel(1);
        start_policy_check(&mut state, intent, tx, &config, switches, 3).unwrap();
        seams.settle(&mut state, &config);
        assert!(host.apply_policy_result(rx.recv().unwrap(), 4).is_err());
        assert!(state.monitors.is_empty());
    }
    #[test]
    fn host529_policy_cancelled_consumer_and_deadline_retain_real_child_until_wait() {
        isolated("cancellation_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn cancellation_body() {
        let key = make_key();
        let dir = tempfile::tempdir().unwrap();
        let config = HelperConfig {
            verify_timeout: Duration::from_millis(80),
            ..trusting_config(dir.path(), &key)
        };
        let mut state = empty_state();
        let seams = DirectSeam::new();
        let (mut host, frontend) = host();
        let intent = host.begin_authentication(frontend, 0, 10_000).unwrap();
        let attempt = intent.attempt();
        let ticket = issue_nonce_for_host(&mut state, intent, 0).unwrap();
        let record = proof(&key, ticket.nonce());
        let (tx, rx) = sync_channel(1);
        start_authentication(
            &mut state,
            ticket,
            HostProof {
                record,
                handshake_hash: [7; 32],
            },
            tx,
            &config,
            AccountSwitches {
                read_keys: read_keys_that_never_finishes,
                ..UNPRIVILEGED
            },
            0,
        )
        .unwrap();
        #[cfg(target_os = "linux")]
        let mut pinned = helper40_pin_verification(&mut state);
        host.cancel_attempt(attempt).unwrap();
        drop(rx);
        assert_eq!(
            state.pending.verifying(),
            1,
            "logical cancellation cannot refund the real child"
        );
        seams.settle(&mut state, &config);
        assert_eq!(state.pending.verifying(), 0);
        assert!(state.orphans.is_empty());
        assert!(state.logins.is_empty());
        #[cfg(target_os = "linux")]
        assert!(matches!(
            pinned.observe(&mut crate::process_scope::Native),
            crate::process_scope::Evidence::Exited
        ));
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn host529_policy_verdict_before_reap_lost_consumer_stays_charged() {
        isolated("verdict_debt_body");
    }
    #[test]
    #[cfg(target_os = "linux")]
    #[ignore = "isolated exact-child custody fixture; refusal does not assert crypto"]
    fn verdict_debt_body() {
        let (mut host, frontend) = host();
        let intent = host.begin_authentication(frontend, 0, 10_000).unwrap();
        let attempt = intent.attempt();
        let (tx, rx) = sync_channel(1);
        let destination = HostPolicyDestination::refusal_for_test(intent, tx);
        let record = encode_verdict(&Verdict::Refused {
            reason: "controlled refusal".into(),
            unknown_account: false,
        });
        let mut fixture = Helper40VerificationFixture::new(record, false);
        let mut pending = fixture.pending(Instant::now() + Duration::from_secs(2), 99);
        if let PendingWhat::Verify {
            destination: target,
            ..
        } = &mut pending.what
        {
            *target = VerificationDestination::HostPolicy(Some(Box::new(destination)));
        } else {
            panic!()
        }
        let mut state = empty_state();
        let seams = DirectSeam::new();
        state.pending.insert(pending);
        let mut pinned = helper40_pin_verification(&mut state);
        let fd = state.pending.verification_fds()[0];
        host.cancel_attempt(attempt).unwrap();
        drop(rx);
        let pending = state.pending.take_ready(fd).unwrap();
        finish_pending(
            seams.seams(),
            &mut state,
            &test_config(),
            pending,
            WhyFinished::Spoke,
        );
        assert_eq!(
            state.pending.verifying(),
            1,
            "a published/lost refusal still owes physical child cleanup"
        );
        assert!(state.orphans.is_empty());
        seams.settle(&mut state, &test_config());
        assert!(state.pending.is_empty());
        assert!(matches!(
            pinned.observe(&mut crate::process_scope::Native),
            crate::process_scope::Evidence::Exited
        ));
        drop(state);
        drop(fixture);
    }

    #[test]
    fn host529_policy_late_real_verdict_after_cancel_or_revocation_cannot_grant() {
        isolated("late_verdict_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn late_verdict_body() {
        let key = make_key();
        let dir = tempfile::tempdir().unwrap();
        let config = trusting_config(dir.path(), &key);
        for revoke in [false, true] {
            let mut state = empty_state();
            let seams = DirectSeam::new();
            let (mut host, frontend) = host();
            let a = authenticate(&mut state, &seams, &mut host, frontend, &key, &config);
            let locator = host.create_session(a, 2).unwrap();
            let intent = host.begin_issue(a, locator, 3, 10_000).unwrap();
            let (tx, rx) = sync_channel(1);
            start_policy_check(&mut state, intent, tx, &config, UNPRIVILEGED, 3).unwrap();
            if revoke {
                host.revoke_account(my_uid().as_raw()).unwrap();
            } else {
                host.cancel_attempt(a).unwrap();
            }
            assert_eq!(
                state.pending.verifying(),
                1,
                "publication cancellation retains the physical job"
            );
            seams.settle(&mut state, &config);
            assert!(host.apply_policy_result(rx.recv().unwrap(), 4).is_err());
            assert_eq!(host.catalog_len(), 1);
            assert!(state.logins.is_empty());
            assert!(state.monitors.is_empty());
        }
    }
    #[test]
    fn host529_policy_bad_bounds_wrong_nonce_and_shared_child_cap_refuse_before_fork() {
        isolated("bounds_body");
    }
    #[test]
    #[ignore = "isolated single-threaded verifier fixture"]
    fn bounds_body() {
        let key = make_key();
        let dir = tempfile::tempdir().unwrap();
        let config = trusting_config(dir.path(), &key);
        for bad in 0..4 {
            let mut state = empty_state();
            let (mut host, frontend) = host();
            let intent = host.begin_authentication(frontend, 0, 10_000).unwrap();
            let ticket = issue_nonce_for_host(&mut state, intent, 0).unwrap();
            let mut record = proof(&key, ticket.nonce());
            match bad {
                0 => record.v2.as_mut().unwrap().nonce[0] ^= 1,
                1 => {
                    record.public_key = vec![0; super::super::super::protocol::MAX_MESSAGE_LEN + 1]
                }
                2 => record.v2 = None,
                _ => record.v2.as_mut().unwrap().login = "x".repeat(256),
            }
            let (tx, rx) = sync_channel(1);
            assert!(start_authentication(
                &mut state,
                ticket,
                HostProof {
                    record,
                    handshake_hash: [7; 32]
                },
                tx,
                &config,
                UNPRIVILEGED,
                0
            )
            .is_err());
            assert!(host.apply_policy_result(rx.recv().unwrap(), 1).is_err());
            assert!(state.pending.is_empty());
            assert!(state.host_nonces.is_empty());
        }
        let mut state = empty_state();
        let (mut host, frontend) = host();
        for _ in 0..MAX_VERIFYING {
            state.pending.insert(fake_verify_pending(
                Instant::now() + Duration::from_secs(30),
            ));
        }
        let intent = host.begin_authentication(frontend, 0, 10_000).unwrap();
        let ticket = issue_nonce_for_host(&mut state, intent, 0).unwrap();
        let cancellation = ticket.duplicate_for_test();
        let nonce = ticket.nonce();
        let record = proof(&key, nonce);
        let (tx, rx) = sync_channel(1);
        assert!(start_authentication(
            &mut state,
            ticket,
            HostProof {
                record,
                handshake_hash: [7; 32]
            },
            tx,
            &config,
            UNPRIVILEGED,
            0
        )
        .is_err());
        assert!(
            state.host_nonces.contains_key(&nonce),
            "physical cap is checked before nonce spend"
        );
        assert_eq!(state.pending.verifying(), MAX_VERIFYING);
        assert!(host.apply_policy_result(rx.recv().unwrap(), 1).is_err());
        drop(cancel_nonce_for_host(&mut state, cancellation));
        assert!(state.host_nonces.is_empty());
    }
}
