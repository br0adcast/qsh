// Linux verification fixtures run in an owned self-reexec, never changing the
// parent test process's subreaper or signal disposition.
#[cfg(target_os = "linux")]
#[test]
fn verification39_scope_joins_same_session_jobs_before_returning() {
    use nix::libc;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    const MODE: &str = "QSH_TEST_VERIFY_SCOPE";
    const PARENT: &str = "QSH_TEST_VERIFY_SCOPE_PARENT";
    const FIXTURE: &str = "QSH_TEST_VERIFY_SCOPE_FIXTURE";
    const INJECT_FAILURE: &str = "QSH_TEST_VERIFY_SCOPE_INJECT_FAILURE";
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
        let dir = tempfile::tempdir_in(std::env::var_os(FIXTURE).unwrap()).unwrap();
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
        if mode == "line" && std::env::var_os(INJECT_FAILURE).is_some() {
            panic!(
                "injected owned helper failure at {}\ntest result: ok. forged\ntest forged ... ok",
                dir.path().display()
            );
        }
        return;
    }
    // The child owner drops before scoped collectors join, including when a
    // pipe take or collector spawn panics. The fixture outlives all of them.
    struct Helper {
        child: std::process::Child,
        reaped: bool,
        authority: bool,
    }
    impl Helper {
        fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
            loop {
                match self.child.wait() {
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    result => {
                        self.reaped = result.is_ok();
                        self.authority = result.is_ok();
                        return result;
                    }
                }
            }
        }
    }
    impl Drop for Helper {
        fn drop(&mut self) {
            if !self.reaped && self.authority {
                let _ = self.child.kill();
                let _ = self.wait();
            }
        }
    }
    fn tail(mut input: impl std::io::Read) -> std::io::Result<Vec<u8>> {
        let mut tail = Vec::new();
        let mut chunk = [0; 1024];
        loop {
            let count = match input.read(&mut chunk) {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 {
                return Ok(tail);
            }
            tail.extend_from_slice(&chunk[..count]);
            if tail.len() > 4096 {
                tail.drain(..tail.len() - 4096);
            }
        }
    }
    let fixture = tempfile::tempdir().unwrap();
    let mut results = Vec::new();
    for mode in ["line", "no-line", "running"] {
        let status = std::thread::scope(|scope| {
            let mut helper = Helper {
                child: Command::new(std::env::current_exe().unwrap())
                    .args(["--exact", TEST, "--nocapture"])
                    .env(MODE, mode)
                    .env(PARENT, std::process::id().to_string())
                    .env(FIXTURE, fixture.path())
                    .stdin(Stdio::null())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
                reaped: false,
                authority: true,
            };
            let stdout = helper.child.stdout.take().unwrap();
            let stderr = helper.child.stderr.take().unwrap();
            let output = scope.spawn(move || tail(stdout));
            let errors = scope.spawn(move || tail(stderr));
            let deadline = Instant::now() + Duration::from_secs(10);
            let status = loop {
                match helper.child.try_wait() {
                    Ok(Some(status)) => {
                        helper.reaped = true;
                        break Ok(status.success());
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        // Custody is no longer proved: never signal a reused PID.
                        helper.authority = false;
                        break Err(error);
                    }
                }
                if Instant::now() >= deadline {
                    // Timeout is failure, never a cleanup receipt. Reap the
                    // exact still-owned helper before joining its pipe readers.
                    let killed = helper.child.kill();
                    let waited = helper.wait();
                    break killed.and(waited).map(|_| false);
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            drop(helper);
            // Always join both actual collectors before inspecting either result.
            let output = output.join();
            let errors = errors.join();
            let output = output.unwrap().unwrap();
            let errors = errors.unwrap().unwrap();
            if !matches!(status, Ok(true)) {
                let sanitize = |bytes: &[u8]| {
                    String::from_utf8_lossy(bytes)
                        .replace(fixture.path().to_str().unwrap(), "<fixture>")
                        .replace(
                            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                                .parent()
                                .unwrap()
                                .to_str()
                                .unwrap(),
                            "<checkout>",
                        )
                };
                // Debug escaping keeps every diagnostic on one prefixed line;
                // child libtest summaries can never become parser control lines.
                eprintln!(
                    "owned verification helper {mode} stdout tail: {:?}",
                    sanitize(&output)
                );
                eprintln!(
                    "owned verification helper {mode} stderr tail: {:?}",
                    sanitize(&errors)
                );
            }
            status.unwrap()
        });
        results.push((mode, status));
    }
    assert_eq!(
        results,
        vec![("line", true), ("no-line", true), ("running", true)]
    );
}
