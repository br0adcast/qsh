// Native helper acceptance uses private PAM configuration and exact fixture
// identities. It changes neither the parent signal disposition nor subreaping.
#[cfg(target_os = "linux")]
#[test]
fn helper39_monitor_joins_sibling_jobs_before_receipt_and_pam_close() {
    use super::super::protocol::CleanupKind;
    use nix::libc;
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};

    struct Pin(OwnedFd);
    impl Pin {
        fn new(pid: i32) -> Self {
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
            assert!(fd >= 0, "pin the held fixture process");
            Self(unsafe { OwnedFd::from_raw_fd(fd as i32) })
        }
        fn exited(&self) -> bool {
            let mut fd = libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                let result = unsafe { libc::poll(&mut fd, 1, 0) };
                if result >= 0 {
                    return fd.revents & libc::POLLIN != 0;
                }
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR)
                );
            }
        }
        fn stop(&self) {
            if !self.exited() {
                let _ = unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        self.0.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                };
            }
            // A timeout could not prove cleanup. The exact retained process
            // remains owned until all its threads actually exit.
            while !self.exited() {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        fn reap_if_child(&self) {
            loop {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    libc::waitid(
                        libc::P_PIDFD,
                        self.0.as_raw_fd() as u32,
                        &mut info,
                        libc::WEXITED | libc::WNOHANG,
                    )
                };
                if rc == 0 {
                    if unsafe { info.si_pid() } != 0 {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                    continue;
                }
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::ECHILD) => return,
                    other => panic!("exact fixture wait unavailable: {other:?}"),
                }
            }
        }
    }
    struct Jobs {
        leader: Pin,
        member: Pin,
        monitor: Pin,
    }
    struct Case {
        helper: Option<TestHelper>,
        jobs: Option<Jobs>,
        master: Option<OwnedFd>,
        joined: bool,
    }
    impl Case {
        fn helper(&self) -> &TestHelper {
            self.helper.as_ref().unwrap()
        }
        fn finish(&mut self) -> bool {
            if let Some(jobs) = &self.jobs {
                jobs.leader.stop();
                jobs.member.stop();
            }
            if let Some(helper) = self.helper.take() {
                let TestHelper {
                    channels,
                    auth,
                    thread,
                    dir,
                    ..
                } = helper;
                drop(channels);
                drop(auth);
                // Keep the fixture and every worker until actual completion.
                // No timed join may detach a helper on a failing assertion.
                self.joined = thread.join().is_ok();
                drop(dir);
            }
            if let Some(jobs) = self.jobs.take() {
                jobs.monitor.stop();
                // The helper thread is already joined: no competing product
                // waiter can lose numeric-PID authority to fixture cleanup.
                jobs.monitor.reap_if_child();
                jobs.leader.reap_if_child();
                jobs.member.reap_if_child();
            }
            self.master = None;
            self.joined
        }
    }
    impl Drop for Case {
        fn drop(&mut self) {
            self.finish();
        }
    }

    // Fixture-only APIs are qualified before any helper or shell is created.
    // This does not establish or change the daemon's supported kernel floor.
    let self_pin = Pin::new(unsafe { libc::getpid() });
    self_pin.reap_if_child();
    drop(self_pin);

    for mode in ["close", "leader-first", "login-ended"] {
        let dir = tempfile::tempdir().unwrap();
        let ids = dir.path().join("ids");
        let ack = dir.path().join("ack");
        let closed = dir.path().join("closed");
        let pam_script = dir.path().join("pam.sh");
        write_script(&pam_script, &format!(
            "if [ \"$PAM_TYPE\" = close_session ]; then printf close > '{p}.pending'; mv '{p}.pending' '{p}'; fi",
            p = closed.display()));
        write_stack(dir.path(), "qshd-test-owned-scope", &format!(
            "auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_exec.so {}\nsession required pam_permit.so\n", pam_script.display()));
        let mut case = Case {
            helper: Some(helper_with_pam_confdir(dir.path(), "qshd-test-owned-scope")),
            jobs: None,
            master: None,
            joined: false,
        };
        let ending = if mode == "leader-first" {
            "exit 0"
        } else {
            "wait"
        };
        // Bash builtin read supplies the barrier without spawning transient
        // sleeps: this fixture creates exactly one known sibling-PGID job.
        let script = format!("set -m; trap '' HUP; /bin/sleep inf & member=$!; printf '%s %s %s\\n' \"$$\" \"$member\" \"$PPID\" > '{}'; IFS= read -r nonce; printf '%s %s %s %s\\n' \"$nonce\" \"$$\" \"$member\" \"$PPID\" > '{}'; {ending}", ids.display(), ack.display());
        let command = format!("exec /bin/bash -c '{}'", script.replace('\'', "'\\''"));
        let (opened, master) = open_command_with_fd(
            &case.helper().channels,
            391,
            my_uid(),
            case.helper().login,
            &command,
        );
        case.master = master;
        assert!(matches!(opened, Response::Opened { id: 391 }));
        let deadline = Instant::now() + Duration::from_secs(2);
        let numbers = loop {
            if let Ok(text) = std::fs::read_to_string(&ids) {
                let pids: Vec<i32> = text
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if text.ends_with('\n') && pids.len() == 3 && pids.iter().all(|p| *p > 0) {
                    break pids;
                }
            }
            assert!(
                Instant::now() < deadline,
                "owned helper jobs did not reach their barrier"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        // Both jobs are held before release, so their IDs cannot be recycled
        // during exact capture or the membership observation that follows it.
        let jobs = Jobs {
            leader: Pin::new(numbers[0]),
            member: Pin::new(numbers[1]),
            monitor: Pin::new(numbers[2]),
        };
        assert!(!jobs.leader.exited() && !jobs.member.exited() && !jobs.monitor.exited());
        while std::fs::read_link(format!("/proc/{}/exe", numbers[1]))
            .ok()
            .and_then(|p| p.file_name().map(|s| s == "sleep"))
            != Some(true)
        {
            assert!(
                Instant::now() < deadline,
                "fixture member did not exec sleep"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(unsafe { libc::getsid(numbers[0]) }, numbers[0]);
        assert_eq!(unsafe { libc::getsid(numbers[1]) }, numbers[0]);
        assert_ne!(unsafe { libc::getpgid(numbers[1]) }, unsafe {
            libc::getpgid(numbers[0])
        });
        let mut status = String::new();
        std::fs::File::open(format!("/proc/{}/status", numbers[0]))
            .unwrap()
            .take(4096)
            .read_to_string(&mut status)
            .unwrap();
        let parent = status
            .lines()
            .find_map(|line| line.strip_prefix("PPid:"))
            .unwrap()
            .trim()
            .parse::<i32>()
            .unwrap();
        assert_eq!(
            parent, numbers[2],
            "captured monitor is the live actor's kernel parent"
        );
        assert!(!jobs.leader.exited() && !jobs.member.exited() && !jobs.monitor.exited());
        let started = Instant::now();
        let nonce = format!(
            "owned-{}",
            dir.path().file_name().unwrap().to_string_lossy()
        );
        let input = format!("{nonce}\n");
        assert_eq!(
            nix::unistd::write(case.master.as_ref().unwrap(), input.as_bytes()).unwrap(),
            input.len()
        );
        let expected = format!("{nonce} {} {} {}\n", numbers[0], numbers[1], numbers[2]);
        let ack_deadline = Instant::now() + Duration::from_secs(2);
        while std::fs::read_to_string(&ack).ok().as_deref() != Some(expected.as_str()) {
            assert!(
                Instant::now() < ack_deadline,
                "owned PTY actor did not authenticate captured identities"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // Fresh input reached the still-owned PTY and the marker's original
        // actor answered AFTER capture. Together with captured SID membership
        // this excludes stale PID reuse before assigning any stop authority.
        case.jobs = Some(jobs);
        case.helper().channels.set_nonblocking(true).unwrap();
        if mode == "close" {
            channel::send(
                &case.helper().channels,
                &encode(&Request::Close { id: 391 }).unwrap(),
                None,
            )
            .unwrap();
        } else if mode == "login-ended" {
            tell_login_ended(&case.helper().auth, case.helper().login);
        }
        let deadline = started + Duration::from_secs(5);
        let mut exited = None;
        let mut receipt = false;
        let mut early_close = false;
        let mut receipt_with_live_member = false;
        while Instant::now() < deadline && !receipt {
            let jobs = case.jobs.as_ref().unwrap();
            early_close |= closed.exists() && !jobs.member.exited();
            match channel::recv(&case.helper().channels) {
                Ok(Some((bytes, fd))) => {
                    assert!(fd.is_none());
                    match decode::<Response>(&bytes).unwrap() {
                        Response::Exited { id: 391, code } => {
                            exited = Some(code);
                        }
                        Response::CleanupComplete {
                            id: 391,
                            kind: CleanupKind::Reaped,
                        } => {
                            receipt = true;
                            receipt_with_live_member = !jobs.member.exited();
                        }
                        Response::LoginEnded { .. } => {}
                        other => panic!("unexpected owned helper event: {other:?}"),
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(1))
                }
                other => panic!("helper scope receipt unavailable ({mode}): {other:?}"),
            }
        }
        let member_product_exited = case.jobs.as_ref().unwrap().member.exited();
        if mode == "login-ended" {
            // This case isolates scope-before-PAM ordering while the helper
            // remains alive. Immediate helper exit while a retired monitor
            // closes its transaction is separate shutdown-coordination coverage.
            while (!closed.exists() || !case.jobs.as_ref().unwrap().monitor.exited())
                && Instant::now() < deadline
            {
                early_close |= !case.jobs.as_ref().unwrap().member.exited() && closed.exists();
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let elapsed = started.elapsed();
        let joined = case.finish(); // exact-instance cleanup and real join precede assertions
        eprintln!("owned helper acceptance {mode}: receipt={receipt}, member_exited={member_product_exited}, closed={}, joined={joined}", closed.exists());
        assert!(joined, "the owned helper thread must actually join");
        assert!(
            receipt && exited.is_some(),
            "missing scope receipt/exit in mode {mode}"
        );
        assert!(
            !receipt_with_live_member && member_product_exited,
            "scope receipt outlived its sibling-PGID member in mode {mode}"
        );
        assert!(
            !early_close,
            "PAM closed while the owned member was alive in mode {mode}"
        );
        assert!(
            closed.exists(),
            "PAM close must run after ordinary helper teardown ({mode})"
        );
        assert!(elapsed < Duration::from_secs(5));
        if mode == "leader-first" {
            assert_eq!(exited, Some(0));
        }
    }
}
