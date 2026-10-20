// Real signed proofs and verification children, with explicit NSS/key-read
// identity mocks. Monitors, private PAM sessions and command channels are real.
mod account_binding {
    use super::*;

    const ALIAS: &str = "qshd-binding-alias";

    struct OwnedState(LoopState);
    impl Drop for OwnedState {
        fn drop(&mut self) {
            stop_monitors(&mut self.0);
        }
    }

    fn lookup_alias(login: &str) -> Result<Account, AccountError> {
        let mut account = my_account();
        if login == ALIAS {
            account.name = ALIAS.into();
        } else if login != account.name {
            return Err(AccountError::NoSuchAccount);
        }
        Ok(account)
    }

    fn prove(
        seam: &DirectSeam,
        state: &mut LoopState,
        config: &HelperConfig,
        key: &PrivateKey,
        name: &str,
        token: LoginId,
    ) -> Response {
        let switches = AccountSwitches {
            lookup: lookup_alias,
            ..UNPRIVILEGED
        };
        seam.serve_auth(state, Request::Nonce, config, switches);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(key, name, [7; 32], nonce, token);
        let id = seam.serve_auth(state, request, config, switches);
        seam.settle(state, config);
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the verdict belongs to this exact proof");
        answer.body
    }

    fn observe(
        seam: &DirectSeam,
        state: &mut LoopState,
        config: &HelperConfig,
        id: ChannelId,
        token: LoginId,
    ) -> String {
        let mut request = open_request(id, my_uid().as_raw(), token);
        if let Request::Open { command, name, .. } = &mut request {
            *name = state.logins[&token].account.name.clone();
            *command =
                "printf '%s|%s|%s|%s|BINDING-DONE\\n' \"$USER\" \"$LOGNAME\" \"$HOME\" \"$SHELL\""
                    .into();
        }
        seam.serve(state, &request, config, keep_identity);
        seam.settle(state, config);
        let (response, fd, _) = answer_to(&seam.worker, id);
        assert!(matches!(response, Response::Opened { .. }), "{response:?}");
        read_until_or_timeout(
            &mut std::fs::File::from(fd.expect("terminal")),
            "BINDING-DONE",
        )
    }

    #[test]
    fn repeated_identity_pair_retains_the_original_account_snapshot() {
        let original = my_account();
        let token = [74; 16];
        let mut state = state_with_login(&original, token);
        let created = state.logins[&token].created_at;
        let incarnation = state.logins[&token].incarnation;
        let changed_policy = Account {
            home: "/not-the-bound-home".into(),
            shell: "/not-the-bound-shell".into(),
            groups: Vec::new(),
            ..original.clone()
        };
        assert_eq!(
            ensure_login(&mut state, token, &changed_policy, "new-rhost".into()),
            Ok(incarnation)
        );
        assert_eq!(state.logins[&token].account, original);
        assert_eq!(state.logins[&token].created_at, created);
        let other_uid = Account {
            uid: Uid::from_raw(original.uid.as_raw() + 1),
            ..original.clone()
        };
        assert!(ensure_login(&mut state, token, &other_uid, String::new()).is_err());
        assert_eq!(state.logins[&token].account, original);
        assert_eq!(state.logins[&token].incarnation, incarnation);
    }

    #[test]
    fn an_open_cannot_name_a_same_uid_alias_under_another_accounts_token() {
        let account = my_account();
        let token = [73; 16];
        let mut owned = OwnedState(state_with_login(&account, token));
        let state = &mut owned.0;
        let seam = DirectSeam::new();
        let config = test_config();
        // Inject the name at the actual wire seam. This regression also ran
        // before Open's typed protocol carried it, when it was ignored.
        let mut request =
            serde_json::to_value(open_request(1, account.uid.as_raw(), token)).unwrap();
        request["Open"]["name"] = ALIAS.into();
        channel::send(&seam.worker, &serde_json::to_vec(&request).unwrap(), None).unwrap();
        serve_channel_seam(&seam.helper, state, &config, UNPRIVILEGED);
        seam.settle(state, &config);
        let (response, fd, _) = answer_to(&seam.worker, 1);
        assert!(
            matches!(&response, Response::Failed { reason, .. } if reason == REFUSED_REASON),
            "UID equality must not admit an Open under another name: {response:?}"
        );
        assert!(fd.is_none());
        assert!(state.live.is_empty() && state.monitors.is_empty() && state.pending.is_empty());
        assert_eq!(state.logins[&token].account, account);
        let seen = observe(&seam, state, &config, 2, token);
        assert!(
            seen.contains(&format!("{}|{}|", account.name, account.name)),
            "{seen}"
        );
    }

    #[test]
    fn signed_same_uid_alias_is_refused_without_displacing_the_bound_account() {
        for established in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let key = PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .unwrap();
            let marker = dir.path().join("pam-users");
            let script = dir.path().join("record-pam-user");
            write_script(
                &script,
                &format!(
                    "if [ \"$PAM_TYPE\" = open_session ]; then echo \"$PAM_USER\" >> {}; fi",
                    marker.display()
                ),
            );
            write_stack(dir.path(), "qshd-binding-test", &format!(
                "auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_exec.so {}\nsession required pam_permit.so\n", script.display()));
            let config = HelperConfig {
                pam_service: "qshd-binding-test".into(),
                pam_confdir: Some(dir.path().into()),
                ..trusting_config(dir.path(), &key)
            };
            let seam = DirectSeam::new();
            let mut owned = OwnedState(empty_state());
            let state = &mut owned.0;
            let first = my_account();
            assert_ne!(first.name, ALIAS);
            let token = [71; 16];
            let admitted = prove(&seam, state, &config, &key, &first.name, token);
            let Response::Verified { incarnation, .. } = admitted else {
                panic!("first proof: {admitted:?}")
            };
            if established {
                let seen = observe(&seam, state, &config, 1, token);
                assert!(
                    seen.contains(&format!("{}|{}|", first.name, first.name)),
                    "{seen}"
                );
            }
            let created = state.logins[&token].created_at;
            let refused = prove(&seam, state, &config, &key, ALIAS, token);
            assert!(
                matches!(&refused, Response::Refused { reason } if reason == REFUSED_REASON),
                "same UID is not the same account name: {refused:?}"
            );
            assert_eq!(state.logins[&token].account, first);
            assert_eq!(
                state.verified[&first.uid], first,
                "refusal must not replace the admission cache"
            );
            let repeat = prove(&seam, state, &config, &key, &first.name, token);
            assert!(
                matches!(repeat, Response::Verified { incarnation: again, .. } if again == incarnation)
            );
            assert_eq!(state.logins[&token].created_at, created);
            assert_eq!(state.logins[&token].established, established);
            assert_eq!(state.logins[&token].account, first);
            let expected = |name: &str| {
                format!(
                    "{name}|{name}|{}|{}|BINDING-DONE",
                    first.home.display(),
                    first.shell.display()
                )
            };
            let seen = observe(&seam, state, &config, 2, token);
            assert!(
                seen.contains(&expected(&first.name)),
                "A remains usable: {seen}"
            );
            let other = [72; 16];
            let admitted = prove(&seam, state, &config, &key, ALIAS, other);
            assert!(matches!(admitted, Response::Verified { ref name, .. } if name == ALIAS));
            let seen = observe(&seam, state, &config, 3, other);
            assert!(
                seen.contains(&expected(ALIAS)),
                "B's distinct token: {seen}"
            );
            let seen = observe(&seam, state, &config, 4, token);
            assert!(
                seen.contains(&expected(&first.name)),
                "A after B's UID cache update: {seen}"
            );
            assert_eq!(
                std::fs::read_to_string(&marker).unwrap(),
                format!("{}\n{ALIAS}\n", first.name),
                "each token opens one PAM session under its exact bound name"
            );
        }
    }
}
