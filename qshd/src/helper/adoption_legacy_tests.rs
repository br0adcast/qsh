// Original forced-monitor regressions, through the qualified isolated parent.
#[cfg(target_os = "linux")]
mod adoption_legacy {
    use super::adoption_native::Pin;
    use super::*;

    pub(super) fn helper_body(dir: &Path, control: UnixStream, mode: &str) {
        let adoption = AdoptionRuntime::prepare().expect("qualify before any child");
        let (worker, child) = super::adoption_pump::spawn_worker(dir);
        let mut config = test_config();
        config.pam_service = "qshd-legacy-owned".into();
        config.pam_confdir = Some(dir.to_path_buf());
        let blocked = matches!(mode, "legacy_pam_open" | "legacy_pam_close");
        config.startup_timeout = if blocked {
            Duration::from_millis(300) // Original real PAM deadline regression budget.
        } else {
            Duration::from_secs(2)
        };
        let stack = if blocked {
            let fifo = dir.join("legacy-pam-barrier");
            nix::unistd::mkfifo(
                &fifo,
                nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
            )
            .unwrap();
            let script = dir.join("legacy-pam.sh");
            let phase = if mode == "legacy_pam_close" {
                "close_session"
            } else {
                "open_session"
            };
            write_script(&script, &format!(
                "[ \"$PAM_TYPE\" = {phase} ] || exit 0\nexec /bin/bash -c 'trap \"\" HUP; /usr/bin/setsid /bin/sleep 60 & member=$!; printf \"%s %s %s owned-pam-40\\n\" \"$$\" \"$member\" \"$PPID\" > \"{}\"; IFS= read -r unused < \"{}\"'",
                dir.join("legacy-pam-jobs").display(), fifo.display()));
            format!("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_exec.so {}\nsession required pam_permit.so\n",script.display())
        } else {
            "auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n".into()
        };
        write_stack(dir, "qshd-legacy-owned", &stack);
        let (channels, worker_channels) = channel::pair().unwrap();
        let (auth, worker_auth) = channel::pair().unwrap();
        channel::send(&control, b"channels", Some(worker_channels.as_fd())).unwrap();
        channel::send(&control, b"auth", Some(worker_auth.as_fd())).unwrap();
        drop(worker_channels);
        drop(worker_auth);
        drop(control);
        let exit = serve_inner(
            channels,
            auth,
            config,
            HashMap::from([([40; 16], my_account())]),
            UNPRIVILEGED,
            None,
            Some(OwnedParent {
                status_socket: None,
                status_gate: None,
                worker,
                adoption: Some(adoption),
                stop: None,
            }),
        );
        assert_ne!(
            mode, "legacy_helper_death",
            "the exact helper was supposed to be killed, not return"
        );
        let outcome = match exit {
            HelperLoopExit::HelperPhysicallyExited(outcome) => outcome,
            _ => panic!("qualified legacy fixture returned an unqualified tail"),
        };
        assert!(!outcome.adoption_failed);
        assert!(outcome.failed() && outcome.missing_pam > 0);
        if mode == "legacy_pam_close" {
            assert!(!outcome.forced_worker && outcome.worker.terminal_received);
            assert!(!outcome.channel_receipts.any());
        } else {
            assert!(outcome.forced_worker && !outcome.worker.terminal_received);
            assert!(outcome.channel_receipts.cleanup > 0);
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
        drop(child); // Product native custody performed the exclusive worker wait.
        std::fs::write(
            dir.join("helper-result"),
            format!(
                "mode={mode}, all_original_oracles=true, no_children=true, outcome={outcome:?}"
            ),
        )
        .unwrap();
    }

    fn parent_of(pid: i32) -> i32 {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap()
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    }
    fn wait_until(deadline: Instant, what: &str, mut ready: impl FnMut() -> bool) {
        while !ready() {
            assert!(Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn wait_stopped(pid: i32, pin: &Pin) {
        wait_until(
            Instant::now() + Duration::from_secs(2),
            "exact monitor did not enter SIGSTOP",
            || {
                assert!(!pin.exited());
                std::fs::read_to_string(format!("/proc/{pid}/status"))
                    .unwrap()
                    .lines()
                    .any(|line| {
                        line.starts_with("State:") && line.split_whitespace().nth(1) == Some("T")
                    })
            },
        );
    }
    struct Shell {
        monitor: i32,
        pin: Pin,
        monitor_pin: Pin,
        master: OwnedFd,
    }
    fn open_shell(channels: &UnixStream, dir: &Path, helper_pid: i32, id: u64) -> Shell {
        let ids = dir.join(format!("shell-{id}"));
        let ack = dir.join(format!("shell-ack-{id}"));
        let script=format!("printf '%s %s\\n' \"$$\" \"$PPID\" > '{}'; IFS= read -r nonce; printf '%s %s %s\\n' \"$nonce\" \"$$\" \"$PPID\" > '{}'; exec /bin/sleep 60",ids.display(),ack.display());
        let mut request = open_request(id, my_uid().as_raw(), [40; 16]);
        if let Request::Open { command, .. } = &mut request {
            *command = format!("exec /bin/bash -c '{}'", script.replace('\'', "'\\''"));
        }
        channel::send(channels, &encode(&request).unwrap(), None).unwrap();
        let (response, master) = answer_to_or_fail(channels, id, "owned shell must open");
        assert_eq!(response, Response::Opened { id });
        let master = master.unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut numbers = None;
        wait_until(deadline, "owned direct shell marker missing", || {
            let Ok(text) = std::fs::read_to_string(&ids) else {
                return false;
            };
            let fields: Vec<_> = text.split_whitespace().collect();
            if !text.ends_with('\n') || fields.len() != 2 {
                return false;
            }
            numbers = Some((
                fields[0].parse::<i32>().unwrap(),
                fields[1].parse::<i32>().unwrap(),
            ));
            true
        });
        let (pid, monitor) = numbers.unwrap();
        let pin = Pin::new(pid);
        let monitor_pin = Pin::new(monitor);
        assert_eq!(parent_of(pid), monitor);
        assert_eq!(parent_of(monitor), helper_pid);
        assert_eq!(unsafe { nix::libc::getsid(pid) }, pid);
        assert_eq!(unsafe { nix::libc::getsid(monitor) }, monitor);
        let nonce = format!("owned-{helper_pid}-{id}");
        let input = format!("{nonce}\n");
        assert_eq!(
            nix::unistd::write(&master, input.as_bytes()).unwrap(),
            input.len()
        );
        let expected = format!("{nonce} {pid} {monitor}\n");
        wait_until(deadline, "fresh PTY nonce was not acknowledged", || {
            std::fs::read_to_string(&ack).ok().as_deref() == Some(expected.as_str())
        });
        wait_until(deadline, "owned shell did not exec sleep", || {
            std::fs::read_link(format!("/proc/{pid}/exe"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n == "sleep"))
                == Some(true)
        });
        assert!(!pin.exited() && !monitor_pin.exited());
        Shell {
            monitor,
            pin,
            monitor_pin,
            master,
        }
    }
    fn wait_dead(pin: &Pin, what: &str) {
        wait_until(Instant::now() + TEST_RECV_TIMEOUT, what, || pin.exited());
    }
    fn into_pins(shell: Shell) -> Vec<Pin> {
        drop(shell.master); // Each caller first proves the original exit oracle.
        vec![shell.pin, shell.monitor_pin]
    }
    fn pam_actors(dir: &Path, helper_pid: i32) -> (i32, Vec<Pin>) {
        let mut ids = None;
        wait_until(
            Instant::now() + Duration::from_secs(2),
            "actual blocked PAM phase not entered",
            || {
                let Ok(text) = std::fs::read_to_string(dir.join("legacy-pam-jobs")) else {
                    return false;
                };
                let f: Vec<_> = text.split_whitespace().collect();
                if !text.ends_with('\n') || f.len() != 4 || f[3] != "owned-pam-40" {
                    return false;
                }
                ids = Some(
                    f[..3]
                        .iter()
                        .map(|p| p.parse::<i32>().unwrap())
                        .collect::<Vec<_>>(),
                );
                true
            },
        );
        let ids = ids.unwrap();
        let pins = ids.iter().map(|pid| Pin::new(*pid)).collect::<Vec<_>>();
        wait_until(
            Instant::now() + Duration::from_secs(2),
            "nested PAM job did not enter sleep",
            || {
                std::fs::read_link(format!("/proc/{}/exe", ids[1]))
                    .ok()
                    .and_then(|path| path.file_name().map(|name| name == "sleep"))
                    == Some(true)
            },
        );
        assert_eq!(parent_of(ids[0]), ids[2]);
        assert_eq!(parent_of(ids[1]), ids[0]);
        assert_eq!(parent_of(ids[2]), helper_pid);
        assert_eq!(unsafe { nix::libc::getsid(ids[0]) }, ids[0]);
        assert_eq!(unsafe { nix::libc::getsid(ids[1]) }, ids[1]);
        assert!(pins.iter().all(|pin| !pin.exited()));
        (ids[2], pins)
    }
    pub(super) fn drive(
        control: &UnixStream,
        dir: &Path,
        helper: &Pin,
        helper_pid: i32,
        mode: &str,
    ) -> Vec<Pin> {
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
        auth.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut observed = Vec::new();
        if mode == "legacy_pam_open" {
            channel::send(
                &channels,
                &encode(&open_request(4040, my_uid().as_raw(), [40; 16])).unwrap(),
                None,
            )
            .unwrap();
            let (_monitor, pins) = pam_actors(dir, helper_pid);
            tell_login_ended(&auth, [40; 16]);
            // No external monitor signal: its real PAM opening budget must fire.
            wait_dead(&pins[2], "PAM opening monitor outlived its login");
            observed.extend(pins);
        } else {
            let first = open_shell(&channels, dir, helper_pid, 4040);
            match mode {
                "legacy_killed" => {
                    let second = open_shell(&channels, dir, helper_pid, 4041);
                    assert_eq!(
                        first.monitor, second.monitor,
                        "both direct shells need one monitor"
                    );
                    first.monitor_pin.signal_kill();
                    wait_dead(&first.pin, "first direct shell outlived killed monitor");
                    wait_dead(&second.pin, "second direct shell outlived killed monitor");
                    observed.extend(into_pins(second));
                }
                "legacy_no_second" => {
                    first.monitor_pin.signal_kill();
                    // The original Exited read was a notice barrier before
                    // checking account revocation. Use its explicit, matching
                    // LoginEnded instead; missing shell status stays failed.
                    let deadline = Instant::now() + Duration::from_secs(3);
                    loop {
                        let remaining = deadline
                            .checked_duration_since(Instant::now())
                            .expect("monitor loss did not revoke the original login");
                        channels.set_read_timeout(Some(remaining)).unwrap();
                        let (bytes, fd) = channel::recv(&channels).unwrap().unwrap();
                        assert!(fd.is_none());
                        match decode::<Response>(&bytes).unwrap() {
                            Response::LoginEnded { login, incarnation } if login == [40; 16] => {
                                assert_eq!(incarnation, 1, "only the original login was retired");
                                break;
                            }
                            Response::Exited { id: 4040, .. } => {}
                            other => panic!("unexpected monitor-loss notification: {other:?}"),
                        }
                    }
                    channels
                        .set_read_timeout(Some(Duration::from_secs(3)))
                        .unwrap();
                    wait_dead(&first.pin, "direct shell outlived its killed monitor");
                    let (again, fd) = open_result_with_fd(&channels, 4041, my_uid(), [40; 16]);
                    assert!(
                        matches!(&again,Response::Failed{id:4041,reason} if reason==UNVERIFIED_ACCOUNT_REASON),
                        "{again:?}"
                    );
                    assert!(fd.is_none());
                }
                "legacy_close_stopped" => {
                    first.monitor_pin.signal(nix::libc::SIGSTOP);
                    wait_stopped(first.monitor, &first.monitor_pin);
                    channel::send(
                        &channels,
                        &encode(&Request::Close { id: 4040 }).unwrap(),
                        None,
                    )
                    .unwrap();
                    // Real helper grace runs; the driver never kills the monitor.
                    wait_dead(
                        &first.monitor_pin,
                        "monitor ignored Close beyond its real grace",
                    );
                    wait_dead(&first.pin, "stopped monitor's direct shell stayed alive");
                    let (again, fd) = open_result_with_fd(&channels, 4041, my_uid(), [40; 16]);
                    assert!(
                        matches!(again, Response::Failed { id: 4041, .. }),
                        "{again:?}"
                    );
                    assert!(fd.is_none());
                }
                "legacy_pam_close" => {
                    tell_login_ended(&auth, [40; 16]);
                    let (monitor, pins) = pam_actors(dir, helper_pid);
                    assert_eq!(monitor, first.monitor);
                    wait_dead(&pins[2], "PAM closing monitor outlived its login");
                    wait_dead(&first.pin, "closing monitor's direct shell stayed alive");
                    observed.extend(pins);
                    std::fs::write(dir.join("release"), b"release").unwrap();
                }
                "legacy_helper_death" => {
                    first.monitor_pin.signal(nix::libc::SIGSTOP);
                    wait_stopped(first.monitor, &first.monitor_pin);
                    // Permit the fixture's controlled worker to finish on EOF;
                    // this is not a successful manager/PAM receipt from a dead helper.
                    std::fs::write(dir.join("release"), b"release").unwrap();
                    helper.signal_kill();
                    wait_dead(
                        &first.monitor_pin,
                        "SIGSTOP monitor survived its actual helper death",
                    );
                    wait_dead(&first.pin, "direct shell survived helper/monitor death");
                    assert!(helper.exited());
                }
                _ => panic!("unknown owned legacy scenario"),
            }
            observed.extend(into_pins(first));
        }
        drop(channels);
        drop(auth);
        observed
    }
}
