// A pidfd pins terminal identity; only a consuming wait establishes a local reap.
#[cfg(target_os = "linux")]
mod verification_wait {
    use nix::libc;
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    pub(super) fn pin(pid: i32) -> OwnedFd {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0, "pin the exact owned fixture process");
        unsafe { OwnedFd::from_raw_fd(raw as i32) }
    }
    pub(super) fn terminal(fd: &OwnedFd) -> bool {
        let mut poll = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut poll, 1, 0) } >= 0);
        poll.revents & libc::POLLIN != 0
    }
    fn wait(fd: &OwnedFd, observe: bool) -> io::Result<Option<i32>> {
        loop {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let flags = libc::WEXITED | libc::WNOHANG | if observe { libc::WNOWAIT } else { 0 };
            let result =
                unsafe { libc::waitid(libc::P_PIDFD, fd.as_raw_fd() as u32, &mut info, flags) };
            if result == 0 {
                return Ok((unsafe { info.si_pid() } != 0).then(|| {
                    let code = unsafe { info.si_status() };
                    if info.si_code == libc::CLD_EXITED {
                        code
                    } else {
                        128 + code
                    }
                }));
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
    // The isolated reexec has exactly one consumer of its direct parent's wait:
    // the product callback, or the explicitly waited parent in the order test.
    pub(super) struct SettledParent<'a>(&'a OwnedFd);
    pub(super) fn settled_parent(fd: &OwnedFd) -> io::Result<SettledParent<'_>> {
        if !terminal(fd) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        match wait(fd, true) {
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => Ok(SettledParent(fd)),
            Err(error) => Err(error),
            Ok(_) => Err(io::Error::other(
                "direct parent consuming wait is unsettled",
            )),
        }
    }
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Receipt {
        ReapedHere(i32),
        TerminalNotWaitable,
    }
    impl Receipt {
        pub(super) fn label(&self) -> &'static str {
            match self {
                Self::ReapedHere(_) => "reaped-here",
                Self::TerminalNotWaitable => "terminal-not-waitable",
            }
        }
    }
    pub(super) fn consume(fd: &OwnedFd, parent: Option<&SettledParent<'_>>) -> io::Result<Receipt> {
        if !terminal(fd) {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        match wait(fd, false) {
            Ok(Some(code)) => Ok(Receipt::ReapedHere(code)),
            Ok(None) => Err(io::ErrorKind::WouldBlock.into()),
            Err(error) if error.raw_os_error() == Some(libc::ECHILD) => {
                let parent = parent.ok_or(error)?;
                settled_parent(parent.0)?;
                if !terminal(fd) {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                Ok(Receipt::TerminalNotWaitable)
            }
            Err(error) => Err(error),
        }
    }
    #[derive(Default)]
    pub(super) struct CleanupCalls {
        pub(super) kills: std::sync::atomic::AtomicUsize,
        pub(super) waits: std::sync::atomic::AtomicUsize,
        pub(super) wait_succeeded: std::sync::atomic::AtomicBool,
    }
    // Only the forced-order fixture uses this guard. The observation seam
    // permits injected wait failures without creating or signalling a fake PID.
    pub(super) struct OwnedChild {
        pub(super) child: std::process::Child,
        pub(super) reaped: bool,
        pub(super) authority: bool,
        cleanup_calls: Option<std::sync::Arc<CleanupCalls>>,
    }
    impl OwnedChild {
        pub(super) fn new(child: std::process::Child) -> Self {
            Self {
                child,
                reaped: false,
                authority: true,
                cleanup_calls: None,
            }
        }
        pub(super) fn observed(mut self, calls: std::sync::Arc<CleanupCalls>) -> Self {
            self.cleanup_calls = Some(calls);
            self
        }
        pub(super) fn finish(&mut self) -> std::process::ExitStatus {
            self.finish_observed(
                std::time::Instant::now() + std::time::Duration::from_secs(5),
                std::process::Child::try_wait,
            )
            .expect("owned wait-order actor failed or exceeded deadline")
        }
        pub(super) fn finish_observed(
            &mut self,
            end: std::time::Instant,
            mut observe: impl FnMut(
                &mut std::process::Child,
            ) -> io::Result<Option<std::process::ExitStatus>>,
        ) -> io::Result<std::process::ExitStatus> {
            if !self.authority {
                return Err(io::Error::other(
                    "owned wait-order actor wait authority is lost",
                ));
            }
            loop {
                match observe(&mut self.child) {
                    Ok(Some(status)) => {
                        self.reaped = true;
                        return Ok(status);
                    }
                    Ok(None) => {}
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        // The error may mean another wait released the PID.
                        // Invalidate before the caller can unwind into Drop.
                        self.authority = false;
                        return Err(error);
                    }
                }
                if std::time::Instant::now() >= end {
                    return Err(io::ErrorKind::TimedOut.into());
                }
                std::thread::yield_now();
            }
        }
        fn wait_owned(&mut self) -> io::Result<std::process::ExitStatus> {
            loop {
                if let Some(calls) = &self.cleanup_calls {
                    calls
                        .waits
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                match self.child.wait() {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => {
                        self.reaped = result.is_ok();
                        self.authority = result.is_ok();
                        if let Some(calls) = &self.cleanup_calls {
                            calls
                                .wait_succeeded
                                .store(result.is_ok(), std::sync::atomic::Ordering::SeqCst);
                        }
                        return result;
                    }
                }
            }
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !self.reaped && self.authority {
                if let Some(calls) = &self.cleanup_calls {
                    calls
                        .kills
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                let _ = self.child.kill();
                if let Err(error) = self.wait_owned() {
                    eprintln!(
                        "verification39 guard_unsettled_cleanup errno={:?}",
                        error.raw_os_error()
                    );
                }
            }
        }
    }
}

// Linux verification fixtures run in an owned self-reexec, never changing the
// parent test process's subreaper or signal disposition.
#[cfg(target_os = "linux")]
#[test]
fn verification39_scope_joins_same_session_jobs_before_returning() {
    use nix::libc;
    use std::os::fd::{AsRawFd, OwnedFd};
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
        fd: Option<OwnedFd>,
        parent: OwnedFd,
    }
    impl Descendant {
        fn finish(&mut self) -> std::io::Result<Option<verification_wait::Receipt>> {
            let Some(fd) = self.fd.as_ref() else {
                return Ok(None);
            };
            if !exited(fd) {
                if unsafe {
                    libc::syscall(
                        libc::SYS_pidfd_send_signal,
                        fd.as_raw_fd(),
                        libc::SIGKILL,
                        std::ptr::null::<libc::siginfo_t>(),
                        0,
                    )
                } != 0
                {
                    return Err(std::io::Error::last_os_error());
                }
                let mut poll = libc::pollfd {
                    fd: fd.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                if unsafe { libc::poll(&mut poll, 1, 5000) } != 1 {
                    return Err(std::io::ErrorKind::TimedOut.into());
                }
            }
            let parent = verification_wait::settled_parent(&self.parent)?;
            let receipt = verification_wait::consume(fd, Some(&parent))?;
            // Only a proved receipt disarms the guard and closes its pidfd.
            self.fd.take();
            Ok(Some(receipt))
        }
    }
    impl Drop for Descendant {
        fn drop(&mut self) {
            if let Err(error) = self.finish() {
                eprintln!(
                    "verification39 unsettled_descendant_wait errno={:?}",
                    error.raw_os_error()
                );
                std::process::abort();
            }
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
        let body = format!("#!/bin/bash\nset -m\ntrap '' HUP\n/bin/sleep 4 &\nprintf '%s %s\\n' \"$BASHPID\" \"$!\" > '{}'\nfor ((i=0;i<100;i++)); do [ -f '{}' ] && break; /bin/sleep .01; done\n{ending}", marker.display(), release.display());
        let path = executable(dir.path(), "probe", &body);
        let timeout = if mode == "line" {
            Duration::from_millis(500)
        } else {
            Duration::from_millis(200)
        };
        let started = Instant::now();
        let work = std::thread::spawn(move || run_self_check(&path, timeout));
        let deadline = Instant::now() + Duration::from_secs(2);
        let (parent_pid, pid) = loop {
            if let Ok(text) = std::fs::read_to_string(&marker) {
                let fields: Vec<_> = text.split_whitespace().collect();
                if let [parent, child] = fields.as_slice() {
                    if let (Ok(parent), Ok(child)) = (parent.parse::<i32>(), child.parse::<i32>()) {
                        break (parent, child);
                    }
                }
            }
            assert!(Instant::now() < deadline, "owned self-check did not start");
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut child = Descendant {
            fd: Some(verification_wait::pin(pid)),
            parent: verification_wait::pin(parent_pid),
        };
        assert_eq!(unsafe { libc::getsid(parent_pid) }, parent_pid);
        assert_eq!(unsafe { libc::getsid(pid) }, parent_pid);
        assert!(!verification_wait::terminal(&child.parent));
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
        let receipt = child
            .finish()
            .expect("exact terminal instance and settled wait ownership")
            .unwrap();
        eprintln!("verification39 mode={mode} product_exited={product_exited} parent_wait=settled descendant_wait={} pidfd_closed={}", receipt.label(), child.fd.is_none());
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
            for line in String::from_utf8_lossy(&errors)
                .lines()
                .filter(|line| line.starts_with("verification39 mode="))
            {
                eprintln!("{line}");
            }
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

#[cfg(target_os = "linux")]
#[test]
fn verification39_wait_ownership_orders_are_distinct() {
    use nix::libc;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::os::unix::process::CommandExt;
    const MODE: &str = "QSH_TEST_WAIT_ORDER";
    const SOCKET: &str = "QSH_TEST_WAIT_ORDER_SOCKET";
    const TEST: &str = "update::tests::verification39_wait_ownership_orders_are_distinct";
    use verification_wait::OwnedChild;
    fn options(socket: &UnixStream) {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
    }
    fn record(socket: &mut UnixStream, fields: &[i32]) {
        for field in fields {
            socket.write_all(&field.to_le_bytes()).unwrap();
        }
    }
    fn fields<const N: usize>(socket: &mut UnixStream) -> [i32; N] {
        let mut values = [0; N];
        for value in &mut values {
            let mut bytes = [0; 4];
            socket.read_exact(&mut bytes).unwrap();
            *value = i32::from_le_bytes(bytes);
        }
        values
    }
    fn command(socket: &mut UnixStream) -> u8 {
        let mut byte = [0];
        socket.read_exact(&mut byte).unwrap();
        byte[0]
    }
    fn pin(pid: i32) -> OwnedFd {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(raw >= 0);
        unsafe { OwnedFd::from_raw_fd(raw as i32) }
    }
    fn terminal(fd: &OwnedFd) -> bool {
        let mut p = libc::pollfd {
            fd: fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut p, 1, 0) } >= 0);
        p.revents & libc::POLLIN != 0
    }
    fn accept(listener: &UnixListener) -> UnixStream {
        let mut p = libc::pollfd {
            fd: listener.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut p, 1, 5000) }, 1);
        let socket = listener.accept().unwrap().0;
        options(&socket);
        socket
    }
    if let Ok(mode) = std::env::var(MODE) {
        if mode == "job" {
            let mut socket = UnixStream::connect(std::env::var_os(SOCKET).unwrap()).unwrap();
            options(&socket);
            record(
                &mut socket,
                &[
                    std::process::id() as i32,
                    unsafe { libc::getppid() },
                    unsafe { libc::getsid(0) },
                    unsafe { libc::getpgrp() },
                ],
            );
            assert_eq!(command(&mut socket), b'X');
            std::process::exit(37);
        }
        if mode == "parent" {
            let mut socket = UnixStream::connect(std::env::var_os(SOCKET).unwrap()).unwrap();
            options(&socket);
            let mut job = Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(MODE, "job")
                .process_group(0)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            record(&mut socket, &[std::process::id() as i32, job.id() as i32]);
            match command(&mut socket) {
                b'W' => {
                    let status = job.wait().unwrap();
                    record(&mut socket, &[job.id() as i32, status.code().unwrap()]);
                    assert_eq!(command(&mut socket), b'X');
                }
                b'X' => drop(job),
                _ => panic!("unknown wait-order command"),
            }
            std::process::exit(0);
        }
        assert_eq!(mode, "controller");
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
        let mut outcomes = Vec::new();
        for parent_consumes in [true, false] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("wait.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", TEST, "--nocapture"])
                .env(MODE, "parent")
                .env(SOCKET, &path)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            unsafe {
                command.pre_exec(|| {
                    if libc::setsid() < 0 {
                        Err(std::io::Error::last_os_error())
                    } else {
                        Ok(())
                    }
                });
            }
            let mut parent = OwnedChild::new(command.spawn().unwrap());
            let mut parent_socket = accept(&listener);
            let [parent_pid, job_pid] = fields(&mut parent_socket);
            assert_eq!(parent_pid, parent.child.id() as i32);
            let parent_fd = pin(parent_pid);
            let mut job_socket = accept(&listener);
            let [pid, ppid, sid, pgid] = fields(&mut job_socket);
            assert_eq!(
                (pid, ppid, sid, pgid),
                (job_pid, parent_pid, parent_pid, job_pid)
            );
            let job_fd = pin(job_pid);
            assert!(!terminal(&job_fd));
            assert!(verification_wait::settled_parent(&parent_fd).is_err());
            assert_eq!(
                verification_wait::consume(&job_fd, None)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::WouldBlock
            );
            if parent_consumes {
                job_socket.write_all(b"X").unwrap();
                parent_socket.write_all(b"W").unwrap();
                assert_eq!(fields::<2>(&mut parent_socket), [job_pid, 37]);
                assert!(terminal(&job_fd));
                parent_socket.write_all(b"X").unwrap();
            } else {
                parent_socket.write_all(b"X").unwrap();
            }
            assert_eq!(parent.finish().code(), Some(0));
            assert!(terminal(&parent_fd));
            if !parent_consumes {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                assert_eq!(
                    unsafe {
                        libc::waitid(
                            libc::P_PIDFD,
                            job_fd.as_raw_fd() as u32,
                            &mut info,
                            libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                        )
                    },
                    0
                );
                assert_eq!(
                    unsafe { info.si_pid() },
                    0,
                    "adopted live child has not exited"
                );
                eprintln!(
                    "verification39 adopted_live waitid_result=0 si_pid=0 pidfd_terminal=false"
                );
                job_socket.write_all(b"X").unwrap();
            }
            let mut p = libc::pollfd {
                fd: job_fd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut p, 1, 5000) }, 1);
            assert!(terminal(&job_fd));
            if parent_consumes {
                assert_eq!(
                    verification_wait::consume(&job_fd, None)
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::ECHILD),
                    "unjustified ECHILD remains a failure"
                );
            }
            let parent_receipt = verification_wait::settled_parent(&parent_fd).unwrap();
            let receipt = verification_wait::consume(&job_fd, Some(&parent_receipt)).unwrap();
            let parent_job_status = parent_consumes.then_some(37);
            let fixture_status = match receipt {
                verification_wait::Receipt::ReapedHere(code) => Some(code),
                verification_wait::Receipt::TerminalNotWaitable => None,
            };
            eprintln!("verification39 wait_order parent_consumed={parent_consumes} parent_wait_status=0 parent_job_wait_status={parent_job_status:?} pidfd_terminal=true adopted={} descendant_wait={} fixture_wait_status={fixture_status:?}",!parent_consumes,receipt.label());
            outcomes.push(receipt);
        }
        assert_eq!(
            outcomes,
            vec![
                verification_wait::Receipt::TerminalNotWaitable,
                verification_wait::Receipt::ReapedHere(37)
            ]
        );
        return;
    }
    fn tail(mut input: impl Read) -> std::io::Result<Vec<u8>> {
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
    std::thread::scope(|scope| {
        let mut child = OwnedChild::new(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST, "--nocapture"])
                .env(MODE, "controller")
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let stdout = child.child.stdout.take().unwrap();
        let stderr = child.child.stderr.take().unwrap();
        let output = scope.spawn(move || tail(stdout));
        let errors = scope.spawn(move || tail(stderr));
        let status = child.finish();
        drop(child);
        let output = output.join();
        let errors = errors.join();
        let output = output.unwrap().unwrap();
        let errors = errors.unwrap().unwrap();
        for line in String::from_utf8_lossy(&errors)
            .lines()
            .filter(|line| line.starts_with("verification39 "))
        {
            eprintln!("{line}");
        }
        assert!(
            status.success(),
            "owned wait-order helper failed: stdout={output:?} stderr={errors:?}"
        );
    });
}

#[cfg(target_os = "linux")]
fn verification39_guard_lost_authority_case(errno: i32) {
    use std::sync::{atomic::Ordering, Arc};
    // Settle the actual child before injecting unknown wait ownership. Even
    // RED cleanup cannot signal a live child or a made-up numeric process.
    let mut child = Command::new("/bin/true").spawn().unwrap();
    assert!(child.wait().unwrap().success());
    let calls = Arc::new(verification_wait::CleanupCalls::default());
    let mut guard = verification_wait::OwnedChild::new(child).observed(Arc::clone(&calls));
    let result = guard.finish_observed(Instant::now() + Duration::from_secs(5), |_| {
        Err(std::io::Error::from_raw_os_error(errno))
    });
    assert_eq!(result.unwrap_err().raw_os_error(), Some(errno));
    assert!(!guard.authority && !guard.reaped);
    assert!(guard
        .finish_observed(Instant::now(), |_| panic!(
            "lost wait authority must not be renewed"
        ))
        .is_err());
    drop(guard);
    assert_eq!(
        calls.kills.load(Ordering::SeqCst),
        0,
        "lost authority must not attempt numeric kill"
    );
    assert_eq!(
        calls.waits.load(Ordering::SeqCst),
        0,
        "lost authority must not consume a wait"
    );
    eprintln!("verification39 guard_case errno={errno} cleanup_kills=0 cleanup_waits=0");
}

#[cfg(target_os = "linux")]
#[test]
fn verification39_guard_echild_loses_cleanup_authority() {
    verification39_guard_lost_authority_case(nix::libc::ECHILD);
}
#[cfg(target_os = "linux")]
#[test]
fn verification39_guard_unknown_error_loses_cleanup_authority() {
    verification39_guard_lost_authority_case(nix::libc::EIO);
}
#[cfg(target_os = "linux")]
#[test]
fn verification39_guard_interrupted_wait_retains_authority_and_retries() {
    use std::sync::{atomic::Ordering, Arc};
    let mut child = Command::new("/bin/true").spawn().unwrap();
    assert!(child.wait().unwrap().success());
    let calls = Arc::new(verification_wait::CleanupCalls::default());
    let mut guard = verification_wait::OwnedChild::new(child).observed(Arc::clone(&calls));
    let mut observations = 0;
    let status = guard
        .finish_observed(Instant::now() + Duration::from_secs(5), |child| {
            observations += 1;
            if observations == 1 {
                Err(std::io::Error::from_raw_os_error(nix::libc::EINTR))
            } else {
                child.try_wait()
            }
        })
        .unwrap();
    assert!(status.success());
    assert_eq!(observations, 2);
    assert!(guard.authority && guard.reaped);
    drop(guard);
    assert_eq!(calls.kills.load(Ordering::SeqCst), 0);
    assert_eq!(calls.waits.load(Ordering::SeqCst), 0);
}
#[cfg(target_os = "linux")]
#[test]
fn verification39_guard_success_disarms_cleanup() {
    use std::sync::{atomic::Ordering, Arc};
    let child = Command::new("/bin/true").spawn().unwrap();
    let calls = Arc::new(verification_wait::CleanupCalls::default());
    let mut guard = verification_wait::OwnedChild::new(child).observed(Arc::clone(&calls));
    assert!(guard.finish().success());
    assert!(guard.reaped);
    drop(guard);
    assert_eq!(calls.kills.load(Ordering::SeqCst), 0);
    assert_eq!(calls.waits.load(Ordering::SeqCst), 0);
}
#[cfg(target_os = "linux")]
#[test]
fn verification39_guard_owned_timeout_keeps_bounded_cleanup() {
    use std::sync::{atomic::Ordering, Arc};
    let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let calls = Arc::new(verification_wait::CleanupCalls::default());
    let mut guard = verification_wait::OwnedChild::new(child).observed(Arc::clone(&calls));
    let started = Instant::now();
    let error = guard.finish_observed(started, |_| Ok(None)).unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(guard.authority && !guard.reaped);
    drop(guard);
    assert_eq!(calls.kills.load(Ordering::SeqCst), 1);
    assert_eq!(calls.waits.load(Ordering::SeqCst), 1);
    assert!(calls.wait_succeeded.load(Ordering::SeqCst));
    assert!(started.elapsed() < Duration::from_secs(5));
}
#[cfg(target_os = "linux")]
#[test]
fn verification39_guard_interrupted_wait_respects_existing_deadline() {
    use std::sync::{atomic::Ordering, Arc};
    let mut child = Command::new("/bin/true").spawn().unwrap();
    assert!(child.wait().unwrap().success());
    let calls = Arc::new(verification_wait::CleanupCalls::default());
    let mut guard = verification_wait::OwnedChild::new(child).observed(Arc::clone(&calls));
    let error = guard
        .finish_observed(Instant::now(), |_| {
            Err(std::io::Error::from_raw_os_error(nix::libc::EINTR))
        })
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    assert!(guard.authority && !guard.reaped);
    drop(guard);
    assert_eq!(calls.kills.load(Ordering::SeqCst), 1);
    assert_eq!(calls.waits.load(Ordering::SeqCst), 1);
    assert!(calls.wait_succeeded.load(Ordering::SeqCst));
}
