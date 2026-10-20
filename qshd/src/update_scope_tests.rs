// Linux verification fixtures run in an owned self-reexec, never changing the
// parent test process's subreaper or signal disposition.
#[cfg(target_os = "linux")]
#[test]
fn verification39_scope_joins_same_session_jobs_before_returning() {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    const MODE: &str = "QSH_TEST_VERIFY_SCOPE";
    const PARENT: &str = "QSH_TEST_VERIFY_SCOPE_PARENT";
    const TEST: &str =
        "update::tests::verification39_scope_joins_same_session_jobs_before_returning";
    fn exited(fd: &OwnedFd) -> bool {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(
            unsafe { libc::poll(&mut poll, 1, 0) },
            i32::from(poll.revents != 0)
        );
        poll.revents & libc::POLLIN != 0
    }
    struct Descendant {
        pid: i32,
        fd: Option<OwnedFd>,
    }
    impl Descendant {
        fn finish(&mut self) {
            let Some(fd) = self.fd.take() else {
                return;
            };
            if !exited(&fd) {
                assert_eq!(
                    unsafe {
                        libc::syscall(
                            libc::SYS_pidfd_send_signal,
                            fd.as_raw_fd(),
                            libc::SIGKILL,
                            std::ptr::null::<libc::siginfo_t>(),
                            0,
                        )
                    },
                    0
                );
            }
            let mut status = 0;
            loop {
                let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if result == self.pid {
                    break;
                }
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::EINTR)
                );
            }
        }
    }
    impl Drop for Descendant {
        fn drop(&mut self) {
            self.finish();
        }
    }
    if let Ok(mode) = std::env::var(MODE) {
        assert_eq!(
            std::env::var(PARENT).unwrap().parse::<u32>().unwrap(),
            unsafe { libc::getppid() } as u32
        );
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("child.pid");
        let release = dir.path().join("release");
        let line = String::from_utf8(script_image(101, 0)).unwrap();
        let print = line.lines().nth(1).unwrap();
        let ending = match mode.as_str() {
            "line" => format!("{print}\nexit 0\n"),
            "no-line" => "exit 0\n".into(),
            "running" => format!("{print}\nwait\n"),
            _ => panic!("unknown owned verification fixture"),
        };
        let body = format!("#!/bin/bash\nset -m\ntrap '' HUP\n/bin/sleep 4 &\nprintf '%s\\n' \"$!\" > '{}'\nfor ((i=0;i<100;i++)); do [ -f '{}' ] && break; /bin/sleep .01; done\n{ending}", marker.display(), release.display());
        let path = executable(dir.path(), "probe", &body);
        let timeout = if mode == "line" {
            Duration::from_millis(500)
        } else {
            Duration::from_millis(200)
        };
        let started = Instant::now();
        let work = std::thread::spawn(move || run_self_check(&path, timeout));
        let deadline = Instant::now() + Duration::from_secs(2);
        let pid = loop {
            if let Ok(text) = std::fs::read_to_string(&marker) {
                if let Ok(pid) = text.trim().parse::<i32>() {
                    break pid;
                }
            }
            assert!(Instant::now() < deadline, "owned self-check did not start");
            std::thread::sleep(Duration::from_millis(1));
        };
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0, "pin the exact fixture descendant");
        let mut child = Descendant {
            pid,
            fd: Some(unsafe { OwnedFd::from_raw_fd(raw as i32) }),
        };
        while std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .and_then(|p| p.file_name().map(|s| s == "sleep"))
            != Some(true)
        {
            assert!(!exited(child.fd.as_ref().unwrap()));
            assert!(Instant::now() < deadline, "descendant did not enter sleep");
            std::thread::sleep(Duration::from_millis(1));
        }
        let sid = unsafe { libc::getsid(pid) };
        let pgid = unsafe { libc::getpgid(pid) };
        assert!(sid > 0 && pgid > 0 && !exited(child.fd.as_ref().unwrap()));
        std::fs::write(&release, b"ready").unwrap();
        let result = work.join().unwrap();
        let elapsed = started.elapsed();
        let product_exited = exited(child.fd.as_ref().unwrap());
        child.finish(); // RED cleanup/reap is exact-instance and precedes assertions.
        assert!(product_exited, "verification returned with its same-session job alive ({mode}, sid={sid}, pgid={pgid})");
        if mode == "line" {
            assert_eq!(result.unwrap().build, 101);
            assert!(
                elapsed > timeout,
                "cleanup grace must not change determined successful verification into timeout"
            );
        } else {
            assert!(result.is_err(), "unfinished verification must not succeed");
        }
        return;
    }
    let mut results = Vec::new();
    for mode in ["line", "no-line", "running"] {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", TEST, "--nocapture"])
            .env(MODE, mode)
            .env(PARENT, std::process::id().to_string())
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status.success();
            }
            if Instant::now() >= deadline {
                // An unexpected timeout is a test failure, never a cleanup
                // receipt. Only this exact unreaped helper is signalled here.
                child.kill().unwrap();
                child.wait().unwrap();
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        results.push((mode, status));
    }
    assert_eq!(
        results,
        vec![("line", true), ("no-line", true), ("running", true)]
    );
}
