//! A single-threaded entry point: libtest workers cannot safely continue Rust after fork.
#[path = "../src/detach.rs"]
mod detach;

use nix::libc;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.iter().any(|s| s == "--list") {
        if !args.iter().any(|s| s == "--ignored") {
            println!("detachment_contract: test");
        }
        return;
    }
    if args.first().map(String::as_str) == Some("--worker") {
        worker(&args[1..]);
        return;
    }
    assert!(
        args.is_empty()
            || args.iter().all(|a| matches!(
                a.as_str(),
                "detachment_contract" | "--exact" | "--nocapture"
            )),
        "unsupported arguments: {args:?}"
    );
    #[cfg(target_os = "linux")]
    // SAFETY: only this isolated controller adopts its own fixture descendants.
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
    eof_and_lock_release_are_independent();
    println!("validated independent EOF and lock-release observations");
    for code in [0, 1, 7] {
        let status = owned_status(Command::new(std::env::current_exe().unwrap()).args([
            "--worker",
            "status",
            &code.to_string(),
        ]));
        assert_eq!(status.code(), Some(code));
    }
    let status =
        owned_status(Command::new(std::env::current_exe().unwrap()).args(["--worker", "signal"]));
    assert_eq!(status.code(), Some(128 + libc::SIGTERM));
    let status = owned_status(
        Command::new(std::env::current_exe().unwrap()).args(["--worker", "interrupted"]),
    );
    assert_eq!(status.code(), Some(7));
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("control");
    let missing = directory.path().join("missing");
    let status = owned_status(Command::new(std::env::current_exe().unwrap()).args([
        "--worker",
        "setup-error",
        missing.to_str().unwrap(),
        socket.to_str().unwrap(),
    ]));
    assert_eq!(status.code(), Some(1));
    assert!(
        !socket.exists(),
        "the failed child's publication guard must clean up"
    );
    for closed in [-1, 0, 1, 2] {
        detached_case(closed);
    }
    println!("validated 10 isolated detachment cases");
    detached_case(-3);
    detached_case(-4);
    println!("validated bounded parent wait and partial-ready cleanup");
    for mask in 0..8 {
        runtime_precondition(mask);
    }
    println!("validated 8 closed-stdio runtime preconditions");
}

static RELEASE_FD: AtomicI32 = AtomicI32::new(-1);
static SIGNALS: AtomicUsize = AtomicUsize::new(0);
extern "C" fn interrupt_wait(_: i32) {
    if SIGNALS.fetch_add(1, Ordering::SeqCst) == 1 {
        // SAFETY: the isolated worker retains this pipe until after waiting;
        // write is async-signal-safe, and the child's read has room for one byte.
        unsafe {
            libc::write(RELEASE_FD.load(Ordering::SeqCst), b"x".as_ptr().cast(), 1);
        }
    }
}
fn worker(args: &[String]) {
    if args[0] == "runtime-precondition" {
        let report: i32 = args[1].parse().unwrap();
        let before = standard_identities();
        let first = std::fs::File::open("/dev/null").unwrap();
        assert!(first.as_raw_fd() > 2);
        assert_eq!(standard_identities(), before);
        let bytes = serde_json::to_vec(&(first.as_raw_fd(), before)).unwrap();
        // SAFETY: this dedicated inherited report descriptor has one owner.
        let mut report = unsafe { std::fs::File::from_raw_fd(report) };
        report.write_all(&bytes).unwrap();
        return;
    }
    if args[0] == "setup-error" {
        let result = (|| -> std::io::Result<()> {
            let (_listener, mut cleanup) =
                qshd::control::bind_private_owned(std::path::Path::new(&args[2]))?;
            let directory = std::ffi::CString::new(args[1].as_str()).unwrap();
            // SAFETY: fresh single-threaded worker, no competing waiter; directory
            // remains valid in each fork's copied address space through the call.
            match unsafe { detach::detach_at(&directory) } {
                detach::Outcome::Parent(result) => {
                    cleanup.leave_to_child();
                    std::process::exit(result?);
                }
                detach::Outcome::Child(result) => result?,
            }
            Ok(())
        })();
        assert!(result.is_err());
        std::process::exit(1);
    }
    if args[0] == "interrupted" {
        let (read, write) = pipe();
        // SAFETY: fresh single-threaded worker; direct child has exclusive custody.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            drop(write);
            let mut file = std::fs::File::from(read);
            file.read_exact(&mut [0]).unwrap();
            // SAFETY: this owned fixture child exits without inherited destructors.
            unsafe {
                libc::_exit(7);
            }
        }
        drop(read);
        let child = DirectChild {
            pid,
            release: Some(write),
        };
        RELEASE_FD.store(
            child.release.as_ref().unwrap().as_raw_fd(),
            Ordering::SeqCst,
        );
        // SAFETY: signal policy/timer apply only to this dedicated fixture process.
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = interrupt_wait as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGALRM, &action, std::ptr::null_mut()),
                0
            );
            let mut timer: libc::itimerval = std::mem::zeroed();
            timer.it_value.tv_usec = 20_000;
            timer.it_interval.tv_usec = 20_000;
            assert_eq!(
                libc::setitimer(libc::ITIMER_REAL, &timer, std::ptr::null_mut()),
                0
            );
        }
        let code = detach::wait_first_child(child.pid).unwrap();
        assert!(SIGNALS.load(Ordering::SeqCst) >= 2);
        std::process::exit(code);
    }
    if args[0] == "status" || args[0] == "signal" {
        // SAFETY: this executable has created no threads; only the owned child forks.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            if args[0] == "signal" {
                // SAFETY: raise targets this fixture child only.
                unsafe {
                    libc::raise(libc::SIGTERM);
                }
            }
            std::process::exit(args.get(1).map(|s| s.parse().unwrap()).unwrap_or(99));
        }
        let child = DirectChild { pid, release: None };
        std::process::exit(detach::wait_first_child(child.pid).unwrap());
    }
    assert_eq!(args[0], "detach");
    let report: i32 = args[1].parse().unwrap();
    let release: i32 = args[2].parse().unwrap();
    let closed: i32 = args[3].parse().unwrap();
    if closed >= 0 {
        // SAFETY: standard descriptor belongs only to this isolated worker.
        unsafe {
            libc::close(closed);
        }
    }
    // SAFETY: fresh single-threaded worker, no async runtime or competing waiter.
    match unsafe { detach::detach() } {
        detach::Outcome::Parent(result) => {
            let code = result.unwrap();
            if closed == -3 {
                loop {
                    // SAFETY: only this owned negative-control parent waits here;
                    // the controller's failure cleanup must terminate and reap it.
                    unsafe {
                        libc::pause();
                    }
                }
            }
            std::process::exit(code);
        }
        detach::Outcome::Child(result) => {
            result.unwrap();
            for (index, kind) in [(4, libc::SOCK_DGRAM), (5, libc::SOCK_STREAM)] {
                let fd: i32 = args[index].parse().unwrap();
                let mut actual = 0i32;
                let mut len = std::mem::size_of::<i32>() as libc::socklen_t;
                // SAFETY: inherited socket is live and output storage/length are valid.
                assert_eq!(
                    unsafe {
                        libc::getsockopt(
                            fd,
                            libc::SOL_SOCKET,
                            libc::SO_TYPE,
                            (&mut actual as *mut i32).cast(),
                            &mut len,
                        )
                    },
                    0
                );
                assert_eq!(actual, kind);
            }

            // SAFETY: inherited dedicated fixture descriptors have one owner here.
            let mut report = unsafe { std::fs::File::from_raw_fd(report) };
            let mut release = unsafe { std::fs::File::from_raw_fd(release) };
            assert_eq!(std::env::current_dir().unwrap(), std::path::Path::new("/"));
            // SAFETY: process-local queries, no concurrent threads changing state.
            unsafe {
                assert_ne!(libc::getsid(0), libc::getpid());
                assert_eq!(libc::umask(0o027), 0o027);
                for fd in 0..=2 {
                    let mut st: libc::stat = std::mem::zeroed();
                    assert_eq!(libc::fstat(fd, &mut st), 0);
                    assert_eq!(st.st_mode & libc::S_IFMT, libc::S_IFCHR);
                    assert_eq!(
                        st.st_rdev as u64,
                        std::fs::metadata("/dev/null").unwrap().rdev()
                    );
                }
            }
            report
                .write_all(if closed == -4 { b"r" } else { b"ready" })
                .unwrap();
            let mut byte = [0];
            assert_eq!(release.read(&mut byte).unwrap(), 0);
            // Keep the report pipe alive until process exit. EOF observes only
            // this descriptor closing; other inherited descriptors may close later.
            std::mem::forget(report);
            // SAFETY: final fixture child exits without duplicated parent destructors.
            unsafe { libc::_exit(0) }
        }
    }
}

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0; 2];
    // SAFETY: points to storage for the two returned owned descriptors.
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    // SAFETY: pipe returned two new descriptors, each transferred exactly once.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

fn eof_and_lock_release_are_independent() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("lock");
    let lock = std::fs::File::create(&path).unwrap();
    // SAFETY: this single-threaded controller owns the fixture descriptor.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    let mut holder = Some(lock.try_clone().unwrap());
    drop(lock);
    let (read, write) = pipe();
    drop(write);
    let mut report = std::fs::File::from(read);
    assert_eq!(report.read(&mut [0]).unwrap(), 0, "actual report EOF");
    let contender = std::fs::File::open(&path).unwrap();
    // A duplicate description can outlive the report writer, just as another
    // exit-time descriptor close can follow the pipe close on Darwin.
    assert_eq!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let mut failures = Vec::new();
    let expired = acquire_lock_before(contender.as_raw_fd(), Instant::now(), || {});
    if expired.unwrap_err().kind() != std::io::ErrorKind::TimedOut {
        failures.push("held lock did not exhaust the explicit deadline");
    }
    assert!(holder.is_some(), "expiry must retain the exact holder");
    assert_eq!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock
    );
    let mut contentions = 0;
    let released = acquire_lock_before(
        contender.as_raw_fd(),
        Instant::now() + Duration::from_secs(5),
        || {
            contentions += 1;
            drop(holder.take());
        },
    );
    assert_eq!(contentions, 1, "release follows actual kernel contention");
    assert!(holder.is_none());
    if released.is_err() {
        failures.push("report EOF did not wait for actual lock availability");
    }
    let error = acquire_lock_before(-1, Instant::now() + Duration::from_secs(5), || {
        panic!("an unexpected descriptor error must not be retried")
    })
    .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    assert!(failures.is_empty(), "{failures:?}");
    drop(contender);
    let expired = std::fs::File::open(&path).unwrap();
    let error = acquire_lock_before(expired.as_raw_fd(), Instant::now(), || {
        panic!("an expired free lock must not reach contention")
    })
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let independent = std::fs::File::open(&path).unwrap();
    // SAFETY: the independent owned description proves expiry acquired nothing.
    assert_eq!(
        unsafe { libc::flock(independent.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
}

fn acquire_lock_before(
    fd: i32,
    deadline: Instant,
    mut contended: impl FnMut(),
) -> std::io::Result<()> {
    loop {
        if Instant::now() >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "waiting for actual lock availability: deadline expired",
            ));
        }
        // SAFETY: ordinary callers retain their owned descriptor; the negative
        // control passes -1 to obtain EBADF without inventing a Rust fd owner.
        if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        match error.kind() {
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => {}
            _ => return Err(error),
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("waiting for actual lock availability: {error}"),
            ));
        }
        if error.kind() == std::io::ErrorKind::WouldBlock {
            contended();
        }
        // Backoff only paces retries; success requires an actual flock result.
        std::thread::sleep(left.min(Duration::from_millis(1)));
    }
}

fn detached_case(closed: i32) {
    let directory = tempfile::tempdir().unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let listener =
        std::os::unix::net::UnixListener::bind(directory.path().join("control")).unwrap();
    let lock_path = directory.path().join("transaction");
    let lock = std::fs::File::create(&lock_path).unwrap();
    // SAFETY: this controller exclusively owns the new fixture lock.
    assert_eq!(
        unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    for fd in [udp.as_raw_fd(), listener.as_raw_fd(), lock.as_raw_fd()] {
        // SAFETY: retain just these owned descriptors through the worker exec.
        assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    }
    let (report_read, report_write) = pipe();
    let (release_read, release_write) = pipe();
    // Parent-only ends must not survive exec and prevent release/completion EOF.
    for fd in [report_read.as_raw_fd(), release_write.as_raw_fd()] {
        // SAFETY: these live descriptors belong to this controller.
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--worker",
            "detach",
            &report_write.as_raw_fd().to_string(),
            &release_read.as_raw_fd().to_string(),
            &closed.to_string(),
            &udp.as_raw_fd().to_string(),
            &listener.as_raw_fd().to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    drop(lock);
    drop(udp);
    drop(listener);
    drop(report_write);
    drop(release_read);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut custody = Custody {
        child,
        report: std::fs::File::from(report_read),
        release: Some(release_write),
        deadline,
    };
    // One total deadline bounds ready bytes and the original parent's exit.
    // Failure cleanup separately releases the final child and reaps its parent.
    let mut ready = [0; 5];
    if closed == -4 {
        read_exact_before(&mut custody.report, &mut ready[..1], deadline).unwrap();
        assert_eq!(ready[0], b'r', "the partial record must actually arrive");
        let result = read_exact_before(&mut custody.report, &mut ready[1..], deadline);
        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        custody.cleanup().unwrap();
        return;
    }
    read_exact_before(&mut custody.report, &mut ready, deadline).unwrap();
    assert_eq!(&ready, b"ready");
    let status = wait_before(&mut custody.child, deadline);
    if closed == -3 {
        assert_eq!(status.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
        custody.cleanup().unwrap();
        return;
    }
    assert!(status.unwrap().success());
    let contender = std::fs::File::open(&lock_path).unwrap();
    // SAFETY: the controller owns a different open-file description; only the
    // final detached child's inherited description may now keep the lock held.
    assert_eq!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().kind(),
        std::io::ErrorKind::WouldBlock
    );
    drop(custody.release.take());
    assert!(readable(custody.report.as_raw_fd(), deadline));
    assert_eq!(custody.report.read(&mut [0]).unwrap(), 0);
    assert!(wait_before(&mut custody.child, deadline).unwrap().success());
    acquire_lock_before(contender.as_raw_fd(), deadline, || {}).unwrap();
    assert!(reap_adopted(deadline));
}
fn readable(fd: i32, deadline: Instant) -> bool {
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return false;
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: pfd is valid for one poll entry; bounded wait owns no signals.
        let rc = unsafe { libc::poll(&mut pfd, 1, left.as_millis().min(i32::MAX as u128) as i32) };
        if rc > 0 {
            return true;
        }
        if rc == 0 {
            return false;
        }
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted
        );
    }
}

struct Custody {
    child: Child,
    report: std::fs::File,
    release: Option<OwnedFd>,
    deadline: Instant,
}
impl Custody {
    fn cleanup(&mut self) -> std::io::Result<()> {
        // Release first, including on partial-ready or stuck-parent failures.
        drop(self.release.take());
        if wait_before(&mut self.child, self.deadline).is_err() {
            self.child.kill()?;
        }
        // Termination/reaping has its own explicit bound after observation ends;
        // it never starts another unbounded wait or silently discards a timeout.
        let cleanup_deadline = Instant::now() + Duration::from_secs(5);
        wait_before(&mut self.child, cleanup_deadline)?;
        let _ = read_to_eof_before(&mut self.report, cleanup_deadline)?;
        if !reap_adopted(cleanup_deadline) {
            return Err(deadline_error());
        }
        Ok(())
    }
}
impl Drop for Custody {
    fn drop(&mut self) {
        if let Err(error) = self.cleanup() {
            eprintln!("owned detachment fixture cleanup failed: {error}");
            // A failed cleanup must fail this isolated harness, including when
            // another assertion is already unwinding. Do not report a clean reap.
            std::process::abort();
        }
    }
}
fn deadline_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::TimedOut,
        "owned fixture deadline expired",
    )
}
fn wait_before(child: &mut Child, deadline: Instant) -> std::io::Result<std::process::ExitStatus> {
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            return Err(deadline_error());
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
fn read_exact_before(
    file: &mut std::fs::File,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> std::io::Result<()> {
    while !bytes.is_empty() {
        if !readable(file.as_raw_fd(), deadline) {
            return Err(deadline_error());
        }
        match file.read(bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "incomplete ready record",
                ))
            }
            Ok(count) => bytes = &mut bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}
fn read_to_eof_before(file: &mut std::fs::File, deadline: Instant) -> std::io::Result<Vec<u8>> {
    let mut all = Vec::new();
    loop {
        if !readable(file.as_raw_fd(), deadline) {
            return Err(deadline_error());
        }
        let mut bytes = [0; 256];
        match file.read(&mut bytes) {
            Ok(0) => return Ok(all),
            Ok(count) => all.extend_from_slice(&bytes[..count]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
fn reap_adopted(deadline: Instant) -> bool {
    loop {
        let mut status = 0;
        // SAFETY: this dedicated subreaper has no unrelated children or waiters.
        let rc = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
        if rc > 0 {
            continue;
        }
        if rc < 0 {
            return std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD);
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
#[cfg(not(target_os = "linux"))]
fn reap_adopted(_: Instant) -> bool {
    true
} // Completion EOF above is the portable receipt.

fn owned_status(command: &mut Command) -> std::process::ExitStatus {
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(1)),
            result => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = reap_adopted(Instant::now() + Duration::from_secs(5));
                panic!("owned worker did not complete: {result:?}");
            }
        }
    }
}

struct DirectChild {
    pid: libc::pid_t,
    release: Option<OwnedFd>,
}
impl Drop for DirectChild {
    fn drop(&mut self) {
        drop(self.release.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            // SAFETY: the worker owns this direct child exclusively. No other
            // waiter can release/reuse its PID while this guard retains it.
            let rc = unsafe { libc::waitpid(self.pid, &mut status, libc::WNOHANG) };
            if rc == self.pid {
                return;
            }
            if rc < 0 {
                if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return;
            }
            if Instant::now() >= deadline {
                // SAFETY: WNOHANG just established our unreaped child is live.
                unsafe {
                    libc::kill(self.pid, libc::SIGKILL);
                }
                loop {
                    let rc = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                    if rc >= 0
                        || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
                    {
                        return;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn standard_identities() -> Vec<(u64, u64, u64)> {
    (0..=2)
        .map(|fd| {
            // SAFETY: fstat only observes this process's standard descriptor.
            let mut stat: libc::stat = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::fstat(fd, &mut stat) }, 0);
            (stat.st_dev as u64, stat.st_ino as u64, stat.st_rdev as u64)
        })
        .collect()
}
fn runtime_precondition(mask: i32) {
    let before = standard_identities();
    let (read, write) = pipe();
    assert!(read.as_raw_fd() > 2 && write.as_raw_fd() > 2);
    assert_eq!(
        unsafe { libc::fcntl(read.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) },
        0
    );
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args([
        "--worker",
        "runtime-precondition",
        &write.as_raw_fd().to_string(),
    ]);
    // SAFETY: the exec child only closes selected raw standard descriptors here;
    // no allocation, locks or Rust-owned descriptor destructors run before exec.
    unsafe {
        command.pre_exec(move || {
            for fd in 0..=2 {
                if mask & (1 << fd) != 0 {
                    libc::close(fd);
                }
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    drop(write);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut custody = Custody {
        child,
        report: std::fs::File::from(read),
        release: None,
        deadline,
    };
    let bytes = read_to_eof_before(&mut custody.report, deadline).unwrap();
    let (first, after): (i32, Vec<(u64, u64, u64)>) = serde_json::from_slice(&bytes).unwrap();
    assert!(first > 2);
    for fd in 0..3 {
        if mask & (1 << fd) == 0 {
            assert_eq!(before[fd], after[fd]);
        }
    }
    assert!(wait_before(&mut custody.child, deadline).unwrap().success());
}
