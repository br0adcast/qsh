#[cfg(target_os = "linux")]
mod adoption_pump {
    use super::*;
    use crate::helper::{worker_control, worker_owner::WorkerOwner};
    use std::{
        num::NonZeroU32,
        os::{fd::AsRawFd, unix::process::CommandExt},
        process::{Command, Stdio},
    };

    #[test]
    fn adoption40_parent_pump_forces_failed_missing_cleanup_only_after_monitor_settles() {
        super::adoption_native::run_case(Some("missing_cleanup"));
    }
    #[test]
    fn adoption40_parent_pump_missing_pam_only_keeps_worker_cooperative() {
        super::adoption_native::run_case(Some("pam_only"));
    }
    #[test]
    fn adoption40_parent_pump_real_healthy_pam_receipts_never_force_worker() {
        super::adoption_native::run_case(Some("healthy"));
    }

    #[test]
    fn adoption40_parent_pump_lost_login_end_reply_preserves_actual_failure() {
        super::adoption_native::run_case(Some("healthy_reply_lost"));
    }

    #[test]
    fn adoption40_parent_pump_joins_separate_shell_session_after_monitor_loss() {
        super::adoption_native::run_case(Some("shell_missing"));
    }
    #[test]
    fn adoption40_parent_pump_immediate_login_end_preserves_actual_pam_close() {
        super::adoption_native::run_case(Some("close_hook"));
    }
    #[test]
    fn adoption40_parent_pump_received_failed_pam_still_joins_cooperatively() {
        super::adoption_native::run_case(Some("close_failed"));
    }

    pub(super) fn spawn_worker(dir: &Path) -> (WorkerOwner, std::process::Child) {
        let view = crate::process_scope::prepare().unwrap();
        let (private, child_private) = worker_control::pair().unwrap();
        let fd = child_private.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "helper::server::tests::worker_parent::worker40_parent_held_child_body",
                "--ignored",
                "--test-threads=1",
            ])
            .env("QSH_TEST_PARENT_CONTROL", fd.to_string())
            .env("QSH_TEST_PARENT_DIR", dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: only the exact fixture's private descriptor survives exec.
        unsafe {
            command.pre_exec(move || {
                if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        // First successful-spawn parent action reserves this exact worker.
        let worker = WorkerOwner::new(
            NonZeroU32::new(child.id()).unwrap(),
            view,
            private,
            Instant::now() + Duration::from_secs(3),
        );
        drop(child_private);
        let ready = Instant::now() + Duration::from_secs(2);
        while !dir.join("ready").exists() {
            assert!(Instant::now() < ready);
            std::thread::sleep(Duration::from_millis(1));
        }
        (worker, child)
    }

    pub(super) fn helper_body(dir: &Path, control: UnixStream, mode: &str) {
        let adoption = AdoptionRuntime::prepare().expect("qualify before any helper child");
        let (worker, child) = spawn_worker(dir);
        let marker = dir.join("pump-jobs");
        let fifo = dir.join("pump-barrier");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let script = dir.join("pump-pam.sh");
        let should_hold = if mode == "pam_only" {
            "[ \"$PAM_TYPE\" = close_session ] || exit 0"
        } else {
            "[ \"$PAM_TYPE\" = open_session ] || exit 0"
        };
        write_script(&script,&format!("{should_hold}\nexec /bin/bash -c 'trap \"\" HUP; /usr/bin/setsid /bin/sleep 60 & member=$!; printf \"%s %s %s pump-adoption-40\\n\" \"$$\" \"$member\" \"$PPID\" > \"{}\"; IFS= read -r unused < \"{}\"'",marker.display(),fifo.display()));
        if matches!(mode, "close_hook" | "close_failed") {
            write_script(
                &script,
                &format!(
                    "if [ \"$PAM_TYPE\" = close_session ]; then printf close > '{}'; exit {}; fi",
                    dir.join("pam-closed").display(),
                    if mode == "close_failed" { 7 } else { 0 }
                ),
            );
        }
        let stack = if matches!(mode, "healthy" | "healthy_reply_lost" | "shell_missing") {
            "auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n".to_string()
        } else {
            format!("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_exec.so {}\nsession required pam_permit.so\n",script.display())
        };
        write_stack(dir, "qshd-adoption-pump", &stack);
        let mut config = test_config();
        config.pam_service = "qshd-adoption-pump".into();
        config.pam_confdir = Some(dir.to_path_buf());
        // This ordinary monitor PAM budget chooses failure/escalation, never
        // completion. The owned outer supervisor separately bounds the test.
        config.startup_timeout = Duration::from_secs(2);
        let (channels, worker_channels) = channel::pair().unwrap();
        let (auth, worker_auth) = channel::pair().unwrap();
        channel::send(&control, b"channels", Some(worker_channels.as_fd())).unwrap();
        channel::send(&control, b"auth", Some(worker_auth.as_fd())).unwrap();
        drop(worker_channels);
        drop(worker_auth);
        drop(control);
        let account = my_account();
        let login = [40; 16];
        let exit = serve_inner(
            channels,
            auth,
            config,
            HashMap::from([(login, account)]),
            UNPRIVILEGED,
            None,
            Some(OwnedParent {
                worker,
                adoption: Some(adoption),
                stop: None,
            }),
        );
        let outcome = match exit {
            HelperLoopExit::HelperPhysicallyExited(outcome) => outcome,
            _ => panic!("qualified pump returned an unqualified result"),
        };
        let receipt = format!(
            "forced_worker={}, required_publication={:?}, channel_receipts={:?}, missing_pam={}, pam_received={:?}, monitor_failure={:?}",
            outcome.forced_worker,
            outcome.required_publication,
            outcome.channel_receipts,
            outcome.missing_pam,
            outcome.pam_received,
            outcome.monitor_failure,
        );
        std::fs::write(dir.join("helper-result"), &receipt).unwrap();
        assert!(!outcome.adoption_failed);
        if mode == "healthy_reply_lost" {
            assert!(outcome.forced_worker && outcome.failed(), "{receipt}");
            assert!(
                matches!(
                    outcome.required_publication,
                    Some(RequiredPublicationFailure {
                        kind: RequiredPublication::LoginEnded,
                        error: PublicationError::Send(nix::libc::EPIPE),
                    })
                ),
                "actual closed receiver must retain the required LoginEnded failure: {receipt}"
            );
            assert!(outcome.pam_received.succeeded(), "{receipt}");
            assert_eq!(outcome.missing_pam, 0, "{receipt}");
            assert!(!outcome.channel_receipts.any(), "{receipt}");
            assert!(outcome.monitor_failure.is_none(), "{receipt}");
            assert!(!outcome.worker.terminal_received);
            assert!(!dir.join("finished").exists());
        } else if matches!(mode, "missing_cleanup" | "shell_missing") {
            assert!(outcome.forced_worker && outcome.failed());
            assert!(outcome.missing_pam > 0 && outcome.channel_receipts.cleanup > 0);
            assert!(
                !outcome.worker.terminal_received,
                "forced process exit is not manager/auxiliary join proof"
            );
            assert!(!dir.join("finished").exists());
            if mode == "missing_cleanup" {
                assert!(dir.join("stopped").exists());
            }
        } else {
            assert!(outcome.required_publication.is_none(), "{receipt}");
            assert!(
                !outcome.forced_worker,
                "PAM failure alone/healthy cleanup cannot force worker: {receipt}"
            );
            assert!(!outcome.channel_receipts.any());
            assert!(outcome.worker.terminal_received && dir.join("finished").exists());
            assert_eq!(outcome.missing_pam, usize::from(mode == "pam_only"));
            if matches!(mode, "close_hook" | "close_failed") {
                assert_eq!(std::fs::read(dir.join("pam-closed")).unwrap(), b"close");
                assert_eq!(outcome.pam_received.succeeded(), mode == "close_hook");
                use crate::helper::pam_completion::PamStep::Attempted;
                match outcome.pam_received {
                    PamCompletion::Finished {
                        close_session: Attempted(close),
                        delete_cred: Attempted(delete),
                        end: Attempted(end),
                    } => {
                        assert_eq!(close == 0, mode == "close_hook");
                        assert_eq!((delete, end), (0, 0));
                    }
                    other => panic!("required PAM steps were not all attempted: {other:?}"),
                }
            }
            if mode == "healthy" {
                assert!(outcome.pam_received.succeeded());
            }
        }
        let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                nix::libc::waitid(
                    nix::libc::P_ALL,
                    0,
                    &mut info,
                    nix::libc::WEXITED
                        | nix::libc::WNOWAIT
                        | nix::libc::WNOHANG
                        | nix::libc::__WALL,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::ECHILD)
        );
        drop(child); // Native owner already performed the actual exclusive wait.
        std::fs::write(
            dir.join("helper-result"),
            format!(
                "mode={mode}, no_children=true, shell_before_adoption={:?}, outcome={outcome:?}",
                std::fs::read_to_string(dir.join("shell-proof")).ok()
            ),
        )
        .unwrap();
    }

    pub(super) fn drive(
        control: &UnixStream,
        dir: &Path,
        helper: &super::adoption_native::Pin,
        helper_pid: i32,
        mode: &str,
    ) -> Vec<super::adoption_native::Pin> {
        control
            .set_read_timeout(Some(Duration::from_secs(3)))
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
        let mut request = open_request(4040, my_uid().as_raw(), [40; 16]);
        if mode == "shell_missing" {
            let script = format!("set -m; trap '' HUP; /bin/sleep 60 & member=$!; printf '%s %s %s pump-adoption-40\\n' \"$$\" \"$member\" \"$PPID\" > '{}'; IFS= read -r nonce; printf '%s %s %s %s\\n' \"$nonce\" \"$$\" \"$member\" \"$PPID\" > '{}'; wait", dir.join("pump-jobs").display(), dir.join("shell-ack").display());
            if let Request::Open { command, .. } = &mut request {
                *command = format!("exec /bin/bash -c '{}'", script.replace('\'', "'\\''"));
            }
        }
        channel::send(&channels, &encode(&request).unwrap(), None).unwrap();
        let mut master = None;
        if mode != "missing_cleanup" {
            let mut opened = false;
            let mut cleanup = false;
            while !opened || (mode != "shell_missing" && !cleanup) {
                let (bytes, fd) = channel::recv(&channels).unwrap().unwrap();
                match decode::<Response>(&bytes).unwrap() {
                    Response::Opened { id: 4040 } => {
                        assert!(fd.is_some());
                        master = fd;
                        opened = true;
                    }
                    Response::CleanupComplete {
                        id: 4040,
                        kind: crate::helper::protocol::CleanupKind::Reaped,
                    } => cleanup = true,
                    Response::Exited { id: 4040, .. } => {}
                    other => panic!("unexpected owned pump reply: {other:?}"),
                }
            }
            if mode != "shell_missing" {
                // LoginEnded is an authentication-seam tell, not a channel request.
                if mode == "healthy_reply_lost" {
                    // The required response cannot reach this owned receiver.
                    channels.shutdown(std::net::Shutdown::Read).unwrap();
                }
                tell(&auth, Request::LoginEnded { login: [40; 16] });
                if mode != "healthy_reply_lost" {
                    // The tell returning proves only its send. Keep the required
                    // reply route alive until the helper retires this incarnation.
                    let (bytes, fd) = channel::recv(&channels).unwrap().unwrap();
                    assert!(fd.is_none(), "LoginEnded cannot carry a descriptor");
                    assert!(
                        matches!(decode::<Response>(&bytes).unwrap(),
                            Response::LoginEnded { login, incarnation: 1 } if login == [40; 16]),
                        "actual LoginEnded for the seeded login must precede peer close"
                    );
                }
            }
        }
        let mut observed = Vec::new();
        if matches!(mode, "missing_cleanup" | "pam_only" | "shell_missing") {
            let deadline = Instant::now() + Duration::from_secs(3);
            let ids = loop {
                if let Ok(text) = std::fs::read_to_string(dir.join("pump-jobs")) {
                    let fields: Vec<_> = text.split_whitespace().collect();
                    if text.ends_with('\n') && fields.len() == 4 && fields[3] == "pump-adoption-40"
                    {
                        break fields[..3]
                            .iter()
                            .map(|x| x.parse::<i32>().unwrap())
                            .collect::<Vec<_>>();
                    }
                }
                assert!(Instant::now() < deadline, "private PAM barrier missing");
                std::thread::sleep(Duration::from_millis(1));
            };
            for pid in &ids[..2] {
                observed.push(super::adoption_native::Pin::new(*pid));
            }
            while std::fs::read_link(format!("/proc/{}/exe", ids[1]))
                .ok()
                .and_then(|p| p.file_name().map(|n| n == "sleep"))
                != Some(true)
            {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(unsafe { nix::libc::getsid(ids[0]) }, ids[0]);
            if mode == "shell_missing" {
                assert_eq!(unsafe { nix::libc::getsid(ids[1]) }, ids[0]);
                assert_ne!(unsafe { nix::libc::getpgid(ids[0]) }, unsafe {
                    nix::libc::getpgid(ids[1])
                });
            } else {
                assert_eq!(unsafe { nix::libc::getsid(ids[1]) }, ids[1]);
            }
            assert_ne!(ids[0], ids[1]);
            let parent_of = |pid| {
                let text = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
                text.lines()
                    .find_map(|line| line.strip_prefix("PPid:"))
                    .unwrap()
                    .trim()
                    .parse::<i32>()
                    .unwrap()
            };
            assert_eq!(parent_of(ids[0]), ids[2]);
            assert_eq!(parent_of(ids[1]), ids[0]);
            let mut ancestor = ids[2];
            let mut depth = 0;
            while ancestor != helper_pid {
                assert!(depth < 8, "unexpected private PAM ancestry");
                observed.push(super::adoption_native::Pin::new(ancestor));
                ancestor = parent_of(ancestor);
                depth += 1;
            }
            assert!(observed.iter().all(|pin| !pin.exited()));
            if mode == "shell_missing" {
                // Fresh PTY input authenticates the held shell after capture.
                let nonce = format!("owned-{}", helper_pid);
                let input = format!("{nonce}\n");
                assert_eq!(
                    nix::unistd::write(master.as_ref().unwrap(), input.as_bytes()).unwrap(),
                    input.len()
                );
                let ack = format!("{nonce} {} {} {}\n", ids[0], ids[1], ids[2]);
                while std::fs::read_to_string(dir.join("shell-ack"))
                    .ok()
                    .as_deref()
                    != Some(ack.as_str())
                {
                    assert!(Instant::now() < deadline);
                    std::thread::sleep(Duration::from_millis(1));
                }
                let monitor = super::adoption_native::Pin::new(ids[2]);
                monitor.signal_kill(); // Exact captured monitor only, never a numeric signal.
                while !monitor.exited() || Path::new(&format!("/proc/{}", ids[2])).exists() {
                    assert!(
                        Instant::now() < deadline,
                        "helper did not exclusively reap native monitor"
                    );
                    std::thread::sleep(Duration::from_millis(1));
                }
                // The direct shell has SIGKILL PDEATHSIG; its ordinary
                // sibling-PGID child is not covered by monitor SID completion.
                assert!(
                    !observed[1].exited(),
                    "sibling-PGID job must remain live before global adoption"
                );
                std::fs::write(
                    dir.join("shell-proof"),
                    format!(
                        "monitor_reaped=true, leader_exited={}, sibling_live=true",
                        observed[0].exited()
                    ),
                )
                .unwrap();
            }
            if std::env::var_os("QSH_TEST_ADOPTION_DRIVER_FAIL").is_some() {
                panic!("injected owned driver failure after private actors pinned");
            }
        }
        if !matches!(
            mode,
            "missing_cleanup" | "shell_missing" | "healthy_reply_lost"
        ) {
            std::fs::write(dir.join("release"), b"release").unwrap();
        }
        drop(channels);
        drop(auth); // Actual EOF initiates sticky parent stopping.
        if mode == "missing_cleanup" {
            let deadline = Instant::now() + Duration::from_secs(1);
            while !dir.join("stopped").exists() {
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(1));
            }
            // Bounded negative observation only; final success below still
            // requires real native waits and final adoption ECHILD.
            std::thread::sleep(Duration::from_millis(50));
            assert!(
                !helper.exited(),
                "helper cannot return while PAM/manager roots are active"
            );
            assert!(observed.iter().all(|pin| !pin.exited()));
        }
        observed
    }
}
