#[cfg(target_os = "linux")]
mod owned_signal {
    use super::*;
    use crate::helper::stop_signal::StopOwner;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::ffi::OsStringExt;

    #[test]
    fn signal40_checked_rollback_restores_the_complete_prior_mask() {
        super::adoption_native::run_case(Some("signal_rollback"));
    }
    #[test]
    fn signal40_child_handoff_closes_inherited_fd_before_reuse_and_restores_mask() {
        super::adoption_native::run_case(Some("signal_child_mask"));
    }
    #[test]
    fn signal40_term_and_int_are_pollable_and_repeat_without_changing_prior_mask() {
        super::adoption_native::run_case(Some("signal_pending"));
    }
    #[test]
    fn signal40_descriptor_failure_rolls_back_actual_blocking_before_return() {
        super::adoption_native::run_case(Some("signal_prepare_failure"));
    }
    #[test]
    fn signal40_verifier_restores_mask_before_actual_account_lookup_and_closes_stop_fd() {
        super::adoption_native::run_case(Some("signal_verifier_mask"));
    }
    #[test]
    fn signal40_monitor_restores_mask_before_actual_session_setup_and_closes_stop_fd() {
        super::adoption_native::run_case(Some("signal_monitor_mask"));
    }
    fn checking_session_groups(_: &[Gid]) -> nix::Result<()> {
        assert_restored_child();
        std::fs::write(
            std::env::var_os("QSH_TEST_MASK_MARKER").unwrap(),
            b"actual_session_setup_restored_mask_and_no_stop_fd",
        )
        .unwrap();
        // Refuse before PAM: this control tests the monitor's entry boundary,
        // while real PAM-hook inheritance is covered by the service controls.
        Err(nix::errno::Errno::EPERM)
    }
    fn monitor_mask_body(dir: &Path, control: UnixStream) {
        let stop = StopOwner::prepare().unwrap();
        let marker = dir.join("actual-session-setup");
        std::env::set_var("QSH_TEST_MASK_MARKER", &marker);
        let config = test_config();
        let plan = MonitorPlan {
            child_mask: Some(stop.child_mask()),
            account: my_account(),
            login: [40; 16],
            tty: "/dev/pts/0".into(),
            rhost: PROOF_RHOST.into(),
            pam_service: config.pam_service,
            pam_confdir: config.pam_confdir,
            become_account: UNPRIVILEGED.become_account,
            session_group_ops: monitor::SessionGroupOps {
                install: checking_session_groups,
                capture: UNPRIVILEGED.session_group_ops.capture,
            },
            fd_limit: max_open_descriptors(),
            session_budget: Duration::from_secs(2),
            session_close_budget: Duration::from_secs(2),
        };
        let monitor = fork_monitor(plan).unwrap();
        let pin = super::adoption_native::Pin::new(monitor.pid.as_raw());
        monitor
            .seam()
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let first = channel::recv(monitor.seam()).unwrap().unwrap();
        assert!(matches!(
            decode::<MonitorEvent>(&first.0).unwrap(),
            MonitorEvent::SessionEstablished { .. }
        ));
        let pty = nix::pty::openpty(None, None).unwrap();
        channel::send(
            monitor.seam(),
            &encode(&MonitorRequest::Open {
                id: 4040,
                term: None,
                shell: false,
                command: "/bin/true".into(),
            })
            .unwrap(),
            Some(pty.slave.as_fd()),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let receive = |phase| {
            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(!remaining.is_zero(), "{phase}: monitor event deadline");
            monitor.seam().set_read_timeout(Some(remaining)).unwrap();
            let (bytes, fd) = channel::recv(monitor.seam())
                .unwrap_or_else(|error| panic!("{phase}: receive failed: {error}"))
                .unwrap_or_else(|| panic!("{phase}: unexpected monitor EOF"));
            assert!(fd.is_none(), "{phase}: unexpected descriptor");
            decode::<MonitorEvent>(&bytes).unwrap()
        };
        assert!(matches!(
            receive("refusal"),
            MonitorEvent::Refused { id: 4040, .. }
        ));
        channel::try_send_before(
            monitor.seam(),
            &encode(&MonitorRequest::SealRefused).unwrap(),
            deadline,
        )
        .unwrap();
        assert!(matches!(
            receive("channel cleanup"),
            MonitorEvent::CleanupComplete {
                id: 4040,
                kind: super::super::super::protocol::CleanupKind::NoChild,
            }
        ));
        assert!(matches!(
            receive("normal completion"),
            MonitorEvent::SessionClosed {
                result: PamCompletion::NotOpened,
                request_failure: None,
                cleanup_failure: None,
            }
        ));
        while !pin.exited() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        // Producer-only control: consume this exact exited child's wait, without
        // claiming the product monitor reader received a successful PAM receipt.
        let mut status = 0;
        assert_eq!(
            unsafe { nix::libc::waitpid(monitor.pid.as_raw(), &mut status, 0) },
            monitor.pid.as_raw()
        );
        assert_eq!(status, 0);
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"actual_session_setup_restored_mask_and_no_stop_fd"
        );
        drop(monitor);
        stop.rollback().unwrap();
        std::fs::write(
            dir.join("helper-result"),
            "actual_monitor_session_setup=true, actual_native_wait=true, no_children=true",
        )
        .unwrap();
        channel::send(&control, b"done", None).unwrap();
    }
    fn assert_restored_child() {
        let current = mask();
        assert!(current.contains(&nix::libc::SIGUSR1));
        assert!(!current.contains(&nix::libc::SIGTERM));
        assert!(!current.contains(&nix::libc::SIGINT));
        for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
            if let Ok(target) = std::fs::read_link(entry.unwrap().path()) {
                assert_ne!(
                    target.as_os_str(),
                    std::ffi::OsStr::new("anon_inode:[signalfd]")
                );
            }
        }
    }
    fn checking_lookup(marker: &str) -> Result<Account, AccountError> {
        assert_restored_child();
        std::fs::write(marker, b"actual_lookup_restored_mask_and_no_stop_fd").unwrap();
        Err(AccountError::NoSuchAccount)
    }
    fn verifier_mask_body(dir: &Path, control: UnixStream) {
        let stop = StopOwner::prepare().unwrap();
        let marker = dir.join("actual-lookup");
        let mut switches = UNPRIVILEGED;
        switches.lookup = checking_lookup;
        let mut start = fork_verification(
            marker.to_str().unwrap(),
            &[],
            &[],
            &[0; 32],
            &[0; AUTH_NONCE_LEN],
            &test_config(),
            switches,
            Some(stop.child_mask()),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut verdict = None;
        loop {
            let progress = start.custody.poll(&start.report, false, Instant::now());
            if let Some(result) = progress.result {
                verdict = Some(result);
            }
            if matches!(
                progress.cleanup,
                crate::process_scope::scope::Progress::Complete { .. }
            ) {
                break;
            }
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(verdict.is_some_and(|result| result.is_ok()));
        assert_eq!(
            std::fs::read(&marker).unwrap(),
            b"actual_lookup_restored_mask_and_no_stop_fd"
        );
        stop.rollback().unwrap();
        std::fs::write(
            dir.join("helper-result"),
            "actual_verifier_lookup=true, actual_native_cleanup=true, no_children=true",
        )
        .unwrap();
        channel::send(&control, b"done", None).unwrap();
    }
    fn mask() -> Vec<i32> {
        let mut set = unsafe { std::mem::zeroed::<nix::libc::sigset_t>() };
        assert_eq!(
            unsafe { nix::libc::sigprocmask(nix::libc::SIG_SETMASK, std::ptr::null(), &mut set) },
            0
        );
        (1..=nix::libc::SIGRTMAX())
            .filter(|sig| unsafe { nix::libc::sigismember(&set, *sig) } == 1)
            .collect()
    }
    pub(super) fn helper_body(dir: &Path, control: UnixStream, mode: &str) {
        // Only the dedicated post-fork fixture changes its signal mask.
        let mut prior = nix::sys::signal::SigSet::empty();
        prior.add(nix::sys::signal::Signal::SIGUSR1);
        prior.thread_block().unwrap();
        let original = mask();
        if mode == "signal_monitor_mask" {
            monitor_mask_body(dir, control);
            return;
        }
        if mode == "signal_verifier_mask" {
            verifier_mask_body(dir, control);
            return;
        }
        if mode.starts_with("signal_pump_") {
            parent_pump_body(dir, control, mode);
            return;
        }
        if mode == "signal_prepare_failure" {
            let result = StopOwner::prepare_with(|_| {
                Err(std::io::Error::from_raw_os_error(nix::libc::EMFILE))
            });
            assert!(matches!(result, Err(e) if e.raw_os_error()==Some(nix::libc::EMFILE)));
            assert_eq!(mask(), original);
            std::fs::write(
                dir.join("helper-result"),
                "descriptor_failure=true, prior_mask_restored=true, no_children=true",
            )
            .unwrap();
            channel::send(&control, b"done", None).unwrap();
            return;
        }
        let owner = StopOwner::prepare().unwrap();
        let fd = owner.fd().as_raw_fd();
        let descriptor_flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) };
        let status_flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        assert!(descriptor_flags >= 0 && descriptor_flags & nix::libc::FD_CLOEXEC != 0);
        assert!(status_flags >= 0 && status_flags & nix::libc::O_NONBLOCK != 0);
        assert!(mask().contains(&nix::libc::SIGTERM) && mask().contains(&nix::libc::SIGINT));
        match mode {
            "signal_rollback" => {
                owner.rollback().unwrap();
                assert_eq!(mask(), original);
                assert_eq!(unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) }, -1);
            }
            "signal_child_mask" => {
                let saved = owner.into_child_mask_close_fd();
                assert_eq!(unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFD) }, -1);
                let replacement = std::fs::File::open("/dev/null").unwrap();
                assert_eq!(
                    replacement.as_raw_fd(),
                    fd,
                    "fixture must exercise actual descriptor reuse"
                );
                saved.restore().unwrap();
                assert_eq!(mask(), original);
                assert!(
                    unsafe { nix::libc::fcntl(replacement.as_raw_fd(), nix::libc::F_GETFD) } >= 0
                );
            }
            "signal_pending" => {
                channel::send(&control, b"prepared", None).unwrap();
                assert_eq!(channel::recv(&control).unwrap().unwrap().0, b"sent");
                let mut poll = nix::libc::pollfd {
                    fd,
                    events: nix::libc::POLLIN,
                    revents: 0,
                };
                assert_eq!(unsafe { nix::libc::poll(&mut poll, 1, 0) }, 1);
                assert_ne!(poll.revents & nix::libc::POLLIN, 0);
                assert!(owner.receive_requested().unwrap());
                assert!(!owner.receive_requested().unwrap());
                channel::send(&control, b"again", None).unwrap();
                assert_eq!(channel::recv(&control).unwrap().unwrap().0, b"sent");
                let mut received = 0;
                while owner.receive_requested().unwrap() {
                    received += 1;
                    assert!(received <= 2);
                }
                assert!(received >= 1);
                owner.rollback().unwrap();
                assert_eq!(mask(), original);
            }
            other => panic!("unknown owned signal fixture: {other}"),
        }
        std::fs::write(
            dir.join("helper-result"),
            format!("mode={mode}, prior_mask_restored=true, no_children=true"),
        )
        .unwrap();
        channel::send(&control, b"done", None).unwrap();
    }
    pub(super) fn drive(
        control: &UnixStream,
        helper: &super::adoption_native::Pin,
        mode: &str,
    ) -> Vec<super::adoption_native::Pin> {
        if mode.starts_with("signal_pump_") {
            return parent_pump_drive(control, helper, mode);
        }
        control
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        if mode == "signal_pending" {
            assert_eq!(channel::recv(control).unwrap().unwrap().0, b"prepared");
            helper.signal(nix::libc::SIGTERM);
            channel::send(control, b"sent", None).unwrap();
            assert_eq!(channel::recv(control).unwrap().unwrap().0, b"again");
            helper.signal(nix::libc::SIGTERM);
            helper.signal(nix::libc::SIGINT);
            channel::send(control, b"sent", None).unwrap();
        }
        assert_eq!(channel::recv(control).unwrap().unwrap().0, b"done");
        Vec::new()
    }

    #[test]
    fn signal40_parent_pump_accepts_both_seam_eofs_before_actual_drained() {
        super::adoption_native::run_case(Some("signal_pump_eof_first"));
    }
    #[test]
    fn signal40_parent_pump_keeps_eof_routes_after_actual_drained() {
        super::adoption_native::run_case(Some("signal_pump_drained_first"));
    }
    #[test]
    fn signal40_requested_stop_never_hides_actual_late_protocol_failure() {
        super::adoption_native::run_case(Some("signal_pump_protocol_fault"));
    }
    fn parent_pump_body(dir: &Path, control: UnixStream, mode: &str) {
        let adoption = AdoptionRuntime::prepare().unwrap();
        let (channels, producer_channels) = channel::pair().unwrap();
        let (auth, producer_auth) = channel::pair().unwrap();
        let stop = StopOwner::prepare().unwrap();
        let (worker, child) = super::adoption_pump::spawn_worker(dir);
        channel::send(&control, b"channels", Some(producer_channels.as_fd())).unwrap();
        channel::send(&control, b"auth", Some(producer_auth.as_fd())).unwrap();
        channel::send(&control, child.id().to_string().as_bytes(), None).unwrap();
        channel::send(&control, dir.as_os_str().as_encoded_bytes(), None).unwrap();
        drop(producer_channels);
        drop(producer_auth);
        let outcome = match serve_inner(
            channels,
            auth,
            test_config(),
            HashMap::new(),
            UNPRIVILEGED,
            None,
            Some(OwnedParent {
                status_socket: None,
                status_gate: None,
                worker,
                adoption: Some(adoption),
                stop: Some(stop),
            }),
        ) {
            HelperLoopExit::HelperPhysicallyExited(outcome) => outcome,
            _ => panic!("signal pump returned an unqualified result"),
        };
        assert_eq!(
            outcome.service_exit_code(),
            i32::from(mode == "signal_pump_protocol_fault")
        );
        assert!(outcome.worker.terminal_received && outcome.worker.native_exit == 0);
        assert!(!outcome.forced_worker && !outcome.adoption_failed);
        std::fs::write(dir.join("helper-result"),format!("mode={mode}, actual_native_zero=true, actual_drained=true, exit={}, no_children=true",outcome.service_exit_code())).unwrap();
        drop(child); // product native owner already consumed its exact wait
        channel::send(&control, b"done", None).unwrap();
    }
    fn parent_pump_drive(
        control: &UnixStream,
        helper: &super::adoption_native::Pin,
        mode: &str,
    ) -> Vec<super::adoption_native::Pin> {
        control
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        let (label, fd) = channel::recv(control).unwrap().unwrap();
        assert_eq!(label, b"channels");
        let channels = UnixStream::from(fd.unwrap());
        let (label, fd) = channel::recv(control).unwrap().unwrap();
        assert_eq!(label, b"auth");
        let auth = UnixStream::from(fd.unwrap());
        channels
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        auth.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let (bytes, _) = channel::recv(control).unwrap().unwrap();
        let pid = std::str::from_utf8(&bytes).unwrap().parse::<i32>().unwrap();
        let worker = super::adoption_native::Pin::new(pid);
        // Helper private fixtures use the supervisor's shared directory.
        let (bytes, _) = channel::recv(control).unwrap().unwrap();
        let dir = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        helper.signal(nix::libc::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(3);
        while !dir.join("stopped").exists() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(
            !helper.exited() && !worker.exited(),
            "requested stop must retain actual held manager"
        );
        channel::send(
            &auth,
            &encode(&AuthRequest {
                id: 40,
                body: Request::Nonce,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        assert!(matches!(
            next_answer(&auth),
            AuthResponse {
                id: 40,
                body: Response::NonceUnavailable
            }
        ));
        helper.signal(nix::libc::SIGTERM);
        helper.signal(nix::libc::SIGINT);
        if mode == "signal_pump_protocol_fault" {
            channel::send(&auth, b"invalid-json", None).unwrap();
        }
        if mode == "signal_pump_drained_first" {
            std::fs::write(dir.join("release"), b"release").unwrap();
            while !worker.exited() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(
                !helper.exited(),
                "worker exit cannot replace retained producer EOF routes"
            );
            drop(channels);
            drop(auth);
        } else {
            drop(channels);
            drop(auth);
            assert!(!worker.exited());
            std::fs::write(dir.join("release"), b"release").unwrap();
        }
        assert_eq!(channel::recv(control).unwrap().unwrap().0, b"done");
        vec![worker]
    }
}
