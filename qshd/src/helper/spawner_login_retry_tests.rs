#[cfg(target_os = "linux")]
mod composed_login_retry {
    use super::*;
    use std::os::fd::{AsFd, FromRawFd};
    use std::os::unix::fs::PermissionsExt;
    use std::sync::{Condvar, OnceLock};

    #[derive(Default)]
    struct Sends {
        fail_end: bool,
        failed: usize,
        events: Vec<(&'static str, u64)>,
    }
    fn controller() -> &'static (Mutex<Sends>, Condvar) {
        static STATE: OnceLock<(Mutex<Sends>, Condvar)> = OnceLock::new();
        STATE.get_or_init(Default::default)
    }
    fn sending(sock: &UnixStream, bytes: &[u8]) -> io::Result<()> {
        let request = decode::<AuthRequest>(bytes).unwrap();
        let kind = match request.body {
            Request::LoginEnded { .. } => "end",
            Request::Nonce => "nonce",
            Request::Verify { .. } => "verify",
            _ => "other",
        };
        let (state, ready) = controller();
        let mut state = state.lock().unwrap();
        if kind == "end" && state.fail_end {
            state.failed += 1;
            ready.notify_all();
            return Err(io::Error::from_raw_os_error(nix::libc::EAGAIN));
        }
        drop(state);
        send_request(sock, bytes)?;
        state = controller().0.lock().unwrap();
        state.events.push((kind, request.id));
        ready.notify_all();
        Ok(())
    }
    fn await_sends(predicate: impl Fn(&Sends) -> bool) {
        let (state, ready) = controller();
        let mut state = state.lock().unwrap();
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while !predicate(&state) {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(!left.is_zero(), "actual sender barrier did not arrive");
            state = ready.wait_timeout(state, left).unwrap().0;
        }
    }
    fn native_exited(fd: &OwnedFd) -> bool {
        use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
        let mut fds = [PollFd::new(fd.as_fd(), PollFlags::POLLIN)];
        poll(&mut fds, PollTimeout::ZERO).unwrap();
        fds[0].revents().unwrap().contains(PollFlags::POLLIN)
    }
    fn pin_marker(path: &std::path::Path) -> OwnedFd {
        let pid = std::fs::read_to_string(path)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "pin actual PAM monitor");
        unsafe { OwnedFd::from_raw_fd(fd as i32) }
    }
    fn operate(
        channel: &mut SpawnedChannel,
        path: &std::path::Path,
        nonce: &str,
        home: &std::path::Path,
    ) {
        channel
            .writer
            .write_all(format!("{nonce}\n").as_bytes())
            .unwrap();
        channel.writer.flush().unwrap();
        wait_for("real shell command", &|| {
            std::fs::read_to_string(path).ok().as_deref() == Some(&format!("{nonce}\n"))
        });
        assert_eq!(
            std::fs::read_to_string(path.with_extension("environment")).unwrap(),
            format!("{0}\n{0}\n/bin/sh\n", home.display()),
            "shell received the isolated HOME, cwd, and executable before assignments"
        );
    }
    fn join_channel(channel: &mut Option<SpawnedChannel>, kill: bool) -> Result<(), String> {
        use transport::channel_server::ChildStatus;
        let Some(owned) = channel.as_mut() else {
            return Ok(());
        };
        if kill {
            owned.wait.kill();
        }
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            match owned.wait.poll_exit() {
                ChildStatus::Reaped { .. } => {
                    drop(channel.take());
                    return Ok(());
                }
                ChildStatus::Unknown(reason) => {
                    return Err(format!("actual cleanup receipt unknown: {reason}"))
                }
                ChildStatus::Running | ChildStatus::WaitingForWorkers => {}
            }
            if Instant::now() >= deadline {
                return Err("actual cleanup Reaped receipt timed out".into());
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    fn shell_quote(value: &std::path::Path) -> String {
        format!(
            "'{}'",
            value
                .to_str()
                .expect("fixture UTF-8 path")
                .replace('\'', "'\"'\"'")
        )
    }
    fn request(path: &std::path::Path, home: &std::path::Path) -> OpenRequest {
        let mut request = shell_request();
        request.kind = ChannelKind::Command;
        // Check the environment and cwd received at exec before assigning any
        // shell variables. No account login/profile startup is requested.
        request.command = format!(
            "printf '%s\\n' \"$HOME\" \"$PWD\" \"$SHELL\" > {environment}; test \"$HOME\" = {home} && test \"$PWD\" = {home} && test \"$SHELL\" = /bin/sh || exit 97; XDG_CONFIG_HOME=\"$HOME/config\"; XDG_CACHE_HOME=\"$HOME/cache\"; HISTFILE=/dev/null; ENV=/dev/null; export XDG_CONFIG_HOME XDG_CACHE_HOME HISTFILE ENV; while IFS= read -r line; do printf '%s\\n' \"$line\" > {path}; done",
            home = shell_quote(home),
            path = shell_quote(path),
            environment = shell_quote(&path.with_extension("environment")),
        ).into_bytes();
        request
    }
    #[test]
    fn login39_actual_retry_precedes_same_token_reauthentication() {
        run("helper::spawner::tests::composed_login_retry::login39_actual_retry_precedes_same_token_reauthentication", true, false);
    }
    #[test]
    fn login39_still_failing_end_never_sends_a_fresh_proof() {
        run("helper::spawner::tests::composed_login_retry::login39_still_failing_end_never_sends_a_fresh_proof", true, true);
    }
    #[test]
    fn login39_no_stuck_end_allows_real_same_token_reuse() {
        run("helper::spawner::tests::composed_login_retry::login39_no_stuck_end_allows_real_same_token_reuse", false, false);
    }
    fn run(name: &str, fail_end: bool, keep_failing: bool) {
        crate::test_borrowed_scope::run_exact(name, 0, || body(fail_end, keep_failing))
            .assert_clean(0);
    }
    fn body(fail_end: bool, keep_failing: bool) {
        *controller().0.lock().unwrap() = Sends::default();
        let dir = tempfile::Builder::new()
            .prefix("qsh-login39-")
            .tempdir_in("/tmp")
            .unwrap();
        let opened = dir.path().join("opened");
        let closed = dir.path().join("closed");
        let script = dir.path().join("pam.sh");
        std::fs::write(&script, format!("#!/bin/sh\nif [ \"$PAM_TYPE\" = open_session ]; then marker={}; else marker={}; fi\npending=$(mktemp \"$marker.XXXXXX\") || exit $?\nprintf '%s\\n' \"$PPID\" > \"$pending\" && mv \"$pending\" \"$marker\"\n", shell_quote(&opened), shell_quote(&closed))).unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(dir.path().join("qshd-retry"), format!("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_exec.so {}\nsession required pam_permit.so\n", script.display())).unwrap();
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .unwrap();
        let TestHelper {
            channels,
            auth,
            thread,
            dir: keys,
            me,
            ..
        } = super::super::super::server::tests::helper_trusting_pam(
            &key,
            running_as_root(),
            dir.path(),
            "qshd-retry",
        );
        channels.set_read_timeout(None).unwrap();
        let mut auth = HelperAuth::build(
            auth,
            HELPER_ANSWER_TIMEOUT,
            verify_answer_timeout(&test_config()),
            Box::new(|| {}),
            ignore_the_end(),
            channel::recv,
            sending,
        )
        .unwrap();
        let mut auth_threads = auth.take_auxiliary();
        let (reporter, mut reports) = login_end_channel(MAX_QUEUED_LOGIN_ENDS);
        let mut spawner = HelperChannelSpawner::with_login_ended_sink(
            channels,
            Box::new(move |login, incarnation| reporter.report(login, incarnation).unwrap()),
        )
        .unwrap();
        let mut channel_threads = spawner.take_auxiliary();
        let mut old: Option<SpawnedChannel> = None;
        let mut fresh: Option<SpawnedChannel> = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let token = [39; 16];
            let hash = [93; 32];
            let nonce = auth.issue().unwrap();
            let owner = auth
                .verify(
                    &hash,
                    &record_for(&key, &me, &hash, nonce),
                    token,
                    PROOF_RHOST,
                )
                .unwrap();
            let old_path = dir.path().join("old-command");
            old = Some(
                spawner
                    .spawn(
                        &owner,
                        token,
                        &request(&old_path, &keys.path().join("home")),
                        Some("xterm-256color"),
                    )
                    .unwrap(),
            );
            operate(
                old.as_mut().unwrap(),
                &old_path,
                "old-live",
                &keys.path().join("home"),
            );
            let old_monitor = pin_marker(&opened);
            assert!(!native_exited(&old_monitor));
            let blocked_nonce = auth.issue().unwrap();
            controller().0.lock().unwrap().fail_end = fail_end;
            LoginSink::login_ended(&auth, token);
            if fail_end {
                await_sends(|state| state.failed > 0);
                // The send callback returned: under the actual sender lock its
                // failure must now have put the old tell back on the queue.
                drop(auth.seam.lock_sender());
                assert!(auth.seam.login_end_stuck.load(Ordering::SeqCst));
                for _ in 0..if keep_failing { 2 } else { 1 } {
                    assert!(matches!(
                        auth.verify(
                            &hash,
                            &record_for(&key, &me, &hash, blocked_nonce),
                            token,
                            PROOF_RHOST
                        ),
                        Err(AuthError::Backend(_))
                    ));
                    assert_eq!(
                        controller()
                            .0
                            .lock()
                            .unwrap()
                            .events
                            .iter()
                            .filter(|(kind, _)| *kind == "verify")
                            .count(),
                        1,
                        "no fresh Verify sent ahead of the queued end"
                    );
                    assert!(!native_exited(&old_monitor));
                }
                operate(
                    old.as_mut().unwrap(),
                    &old_path,
                    "old-still-live",
                    &keys.path().join("home"),
                );
            }
            controller().0.lock().unwrap().fail_end = false;
            await_sends(|state| state.events.iter().any(|(kind, _)| *kind == "end"));
            drop(auth.seam.lock_sender());
            assert!(!auth.seam.login_end_stuck.load(Ordering::SeqCst));
            join_channel(&mut old, false).expect("old lifetime actually Reaped before reuse");
            wait_for("old monitor actual exit", &|| native_exited(&old_monitor));
            assert_eq!(
                std::fs::read_to_string(&closed).unwrap(),
                std::fs::read_to_string(&opened).unwrap()
            );
            let nonce = auth.issue().unwrap();
            let new_owner = auth
                .verify(
                    &hash,
                    &record_for(&key, &me, &hash, nonce),
                    token,
                    PROOF_RHOST,
                )
                .unwrap();
            assert!(new_owner.incarnation > owner.incarnation);
            let new_path = dir.path().join("new-command");
            fresh = Some(
                spawner
                    .spawn(
                        &new_owner,
                        token,
                        &request(&new_path, &keys.path().join("home")),
                        Some("xterm-256color"),
                    )
                    .unwrap(),
            );
            operate(
                fresh.as_mut().unwrap(),
                &new_path,
                "new-live",
                &keys.path().join("home"),
            );
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let ended = runtime.block_on(async {
                tokio::time::timeout(TEST_RECV_TIMEOUT, reports.recv())
                    .await
                    .unwrap()
                    .unwrap()
            });
            assert_eq!(
                ended,
                (token, owner.incarnation),
                "actual old helper report retains its incarnation after token reuse"
            );
            // This exercises the typed report route, not Router::end_login;
            // its existing replaced-login regression covers stale application.
            operate(
                fresh.as_mut().unwrap(),
                &new_path,
                "new-after-old-report",
                &keys.path().join("home"),
            );
            let state = controller().0.lock().unwrap();
            let end = state
                .events
                .iter()
                .position(|(kind, _)| *kind == "end")
                .unwrap();
            let verify = state
                .events
                .iter()
                .rposition(|(kind, _)| *kind == "verify")
                .unwrap();
            assert!(
                end < verify
                    && state.events[end + 1..verify]
                        .iter()
                        .any(|(kind, _)| *kind == "nonce")
            );
        }));
        controller()
            .0
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .fail_end = false;
        let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut receipt_failures = Vec::new();
            for channel in [&mut old, &mut fresh] {
                if let Err(error) = join_channel(channel, true) {
                    receipt_failures.push(error);
                }
            }
            let auth_joined = auth_threads.stop_and_join();
            let channel_joined = channel_threads.stop_and_join();
            drop(auth);
            drop(spawner);
            let helper_joined = thread.join();
            // Unknown custody is retained through helper teardown, never
            // credited as completed merely because a leader exited.
            drop((old.take(), fresh.take()));
            helper_joined.expect("actual helper join");
            assert!(receipt_failures.is_empty(), "{receipt_failures:?}");
            assert_eq!(auth_joined.started, auth_joined.joined);
            assert_eq!((auth_joined.failed, auth_joined.panicked), (0, 0));
            assert_eq!(channel_joined.started, channel_joined.joined);
            assert_eq!((channel_joined.failed, channel_joined.panicked), (0, 0));
            drop(keys);
        }));
        if let Err(failure) = result {
            std::panic::resume_unwind(failure);
        }
        cleanup.unwrap();
    }
}
