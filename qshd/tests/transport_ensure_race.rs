//! Real personal-daemon transactions, isolated in this serialized test binary.
//! Linux subreaping keeps even an orphan from a failed race owned by this test.
#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

use qshd::control::{client_request_with_timeout, ControlReply, ControlRequest, StatusResponse};

struct Descendants;
impl Descendants {
    fn own() -> Self {
        // Tests in this binary are serialized and start no unrelated children.
        assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
        Self
    }

    fn children() -> Vec<i32> {
        let mut pids = Vec::new();
        for task in std::fs::read_dir("/proc/self/task").unwrap().flatten() {
            if let Ok(text) = std::fs::read_to_string(task.path().join("children")) {
                pids.extend(
                    text.split_whitespace()
                        .filter_map(|pid| pid.parse::<i32>().ok()),
                );
            }
        }
        pids.sort_unstable();
        pids.dedup();
        pids
    }

    fn reap(&self) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let pids = Self::children();
            if pids.is_empty() {
                return;
            }
            for pid in pids {
                // A direct child cannot reuse its PID before this parent reaps
                // it; this dedicated binary owns every process in this list.
                unsafe { libc::kill(pid, libc::SIGKILL) };
                let mut status = 0;
                unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            }
            if Instant::now() >= deadline {
                panic!("owned daemon descendants did not terminate");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
impl Drop for Descendants {
    fn drop(&mut self) {
        self.reap();
    }
}

struct Ensure {
    child: Option<Child>,
    out: File,
    err: File,
}
impl Ensure {
    fn start(home: &Path, port: u16) -> Self {
        Self::with_output(home, port, false)
    }
    fn with_output(home: &Path, port: u16, fail_output: bool) -> Self {
        Self::with_limit(home, port, fail_output, None)
    }

    fn with_limit(home: &Path, port: u16, fail_output: bool, limit: Option<u64>) -> Self {
        use std::os::unix::process::CommandExt;
        let out = tempfile::tempfile().unwrap();
        let err = tempfile::tempfile().unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_qshd"));
        if let Some(limit) = limit {
            // Only the freshly forked command child changes its limit. The
            // test process and concurrent test/build owners are untouched.
            unsafe {
                command.pre_exec(move || {
                    let value = libc::rlimit {
                        rlim_cur: limit,
                        rlim_max: limit,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &value) == 0 {
                        Ok(())
                    } else {
                        Err(std::io::Error::last_os_error())
                    }
                });
            }
        }
        let child = command
            .args([
                "transport-ensure",
                "--name",
                "race",
                "--port",
                &port.to_string(),
            ])
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_CACHE_HOME", home)
            .env("HISTFILE", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID")
            .stdin(Stdio::null())
            .stdout(if fail_output {
                OpenOptions::new().write(true).open("/dev/full").unwrap()
            } else {
                out.try_clone().unwrap()
            })
            .stderr(err.try_clone().unwrap())
            .spawn()
            .unwrap();
        Self {
            child: Some(child),
            out,
            err,
        }
    }

    fn finish(self) -> (bool, String, String) {
        self.finish_within(Duration::from_secs(15))
    }

    fn finish_within(mut self, patience: Duration) -> (bool, String, String) {
        use std::io::{Seek, SeekFrom};
        let deadline = Instant::now() + patience;
        let child = self.child.as_mut().unwrap();
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "ensure wrapper did not exit");
            std::thread::sleep(Duration::from_millis(10));
        };
        self.child.take();
        let mut out = String::new();
        let mut err = String::new();
        self.out.seek(SeekFrom::Start(0)).unwrap();
        self.err.seek(SeekFrom::Start(0)).unwrap();
        self.out.read_to_string(&mut out).unwrap();
        self.err.read_to_string(&mut err).unwrap();
        (status.success(), out, err)
    }
}

// This helper runs only in a dedicated subprocess. The marker acknowledges
// actual lock custody; stdin EOF releases it without involving a daemon.
#[test]
fn ensure_lock_holder_process() {
    let Some(home) = std::env::var_os("QSH_TEST_ENSURE_LOCK_HOLDER") else {
        return;
    };
    let home = PathBuf::from(home);
    let lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(home.join("qsh/control.sock.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    std::fs::write(home.join("holder-ready"), b"held").unwrap();
    let mut byte = [0];
    let _ = std::io::stdin().read(&mut byte).unwrap();
    drop(lock);
    std::fs::write(home.join("holder-released"), b"released").unwrap();
}

struct OwnedLockProcess(Option<Child>);

impl OwnedLockProcess {
    fn spawn(home: &Path, test: &str, budget: Option<u64>) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", test, "--nocapture"])
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join("config"))
            .env("XDG_CACHE_HOME", home)
            .env("HISTFILE", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(budget) = budget {
            command.env("QSH_TEST_ENSURE_LOCK_WAITER", home);
            command.env("QSH_TEST_ENSURE_LOCK_BUDGET_MS", budget.to_string());
        } else {
            command.env("QSH_TEST_ENSURE_LOCK_HOLDER", home);
        }
        Self(Some(command.spawn().unwrap()))
    }

    fn start_holder(home: &Path) -> Self {
        std::fs::create_dir(home.join("qsh")).unwrap();
        let mut holder = Self::spawn(home, "ensure_lock_holder_process", None);
        holder.await_marker(&home.join("holder-ready"));
        holder
    }

    fn alive(&mut self) -> bool {
        if self.0.as_mut().unwrap().try_wait().unwrap().is_some() {
            self.0.take(); // Reaped PID must never be signalled by Drop.
            false
        } else {
            true
        }
    }

    fn await_marker(&mut self, marker: &Path) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !marker.exists() {
            assert!(self.alive(), "lock fixture exited before its receipt");
            assert!(Instant::now() < deadline, "lock fixture gave no receipt");
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn wait(mut self, patience: Duration) -> std::process::ExitStatus {
        let deadline = Instant::now() + patience;
        loop {
            if let Some(status) = self.0.as_mut().unwrap().try_wait().unwrap() {
                self.0.take();
                return status;
            }
            assert!(Instant::now() < deadline, "lock fixture did not exit");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn finish(self, patience: Duration) {
        let status = self.wait(patience);
        assert!(status.success(), "lock fixture failed: {status}");
    }

    fn release(mut self, home: &Path) {
        drop(self.0.as_mut().unwrap().stdin.take());
        self.finish(Duration::from_secs(2));
        assert_eq!(
            std::fs::read(home.join("holder-released")).unwrap(),
            b"released"
        );
    }
}

impl Drop for OwnedLockProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn ensure_command_times_out_without_ready_or_mutating_the_live_holder() {
    use std::os::unix::fs::MetadataExt;
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    let mut holder = OwnedLockProcess::start_holder(home.path());
    let path = home.path().join("qsh/control.sock.lock");
    let before = std::fs::metadata(&path).unwrap();
    let result = Ensure::start(home.path(), 0).finish_within(Duration::from_secs(7));
    assert!(
        !result.0,
        "a contending ensure must fail within its lock budget"
    );
    assert!(
        result.1.is_empty(),
        "no READY before acquiring the transaction"
    );
    assert!(result
        .2
        .contains("locking the transport ensure transaction"));
    assert!(result.2.contains("timed out"), "{}", result.2);
    assert!(holder.alive(), "holder remains alive");
    let after = std::fs::metadata(&path).unwrap();
    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
    assert_eq!(std::fs::read(&path).unwrap(), b"");
    assert_eq!(
        std::fs::read_dir(home.path().join("qsh")).unwrap().count(),
        1
    );
    let contender = OpenOptions::new().write(true).open(&path).unwrap();
    assert_eq!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1,
        "the live holder still excludes independent contenders"
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EWOULDBLOCK)
    );
    drop(holder);
    assert_eq!(
        unsafe { libc::flock(contender.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    drop(contender);
    descendants.reap();
}
// The counter and signal disposition belong only to this self-reexec child.
static WAITER_SIGNALS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

extern "C" fn waiter_signal(_: libc::c_int) {
    WAITER_SIGNALS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn ensure_lock_waiter_process() {
    let Some(home) = std::env::var_os("QSH_TEST_ENSURE_LOCK_WAITER") else {
        return;
    };
    let home = PathBuf::from(home);
    let budget = std::env::var("QSH_TEST_ENSURE_LOCK_BUDGET_MS")
        .unwrap()
        .parse()
        .unwrap();
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = waiter_signal as *const () as usize;
        assert_eq!(libc::sigemptyset(&mut action.sa_mask), 0);
        assert_eq!(
            libc::sigaction(libc::SIGUSR1, &action, std::ptr::null_mut()),
            0
        );
        let mut set = std::mem::zeroed();
        assert_eq!(libc::sigemptyset(&mut set), 0);
        assert_eq!(libc::sigaddset(&mut set, libc::SIGUSR1), 0);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_UNBLOCK, &set, std::ptr::null_mut()),
            0
        );
    }
    std::fs::write(home.join("waiter-ready"), b"ready").unwrap();
    let result = qshd::control::EnsureLock::acquire(&socket(&home), Duration::from_millis(budget));
    let outcome = match result {
        Ok(lock) => {
            drop(lock);
            "acquired"
        }
        Err(error) => {
            assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
            "timed-out"
        }
    };
    let signals = WAITER_SIGNALS.load(std::sync::atomic::Ordering::Relaxed);
    std::fs::write(home.join("waiter-result"), format!("{outcome}:{signals}")).unwrap();
}

#[test]
fn zero_budget_attempts_once_without_waiting_for_a_held_lock() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    let holder = OwnedLockProcess::start_holder(home.path());
    let waiter = OwnedLockProcess::spawn(home.path(), "ensure_lock_waiter_process", Some(0));
    waiter.finish(Duration::from_secs(2));
    assert_eq!(
        std::fs::read_to_string(home.path().join("waiter-result")).unwrap(),
        "timed-out:0"
    );
    holder.release(home.path());
    let waiter = OwnedLockProcess::spawn(home.path(), "ensure_lock_waiter_process", Some(0));
    waiter.finish(Duration::from_secs(2));
    assert_eq!(
        std::fs::read_to_string(home.path().join("waiter-result")).unwrap(),
        "acquired:0"
    );
    assert!(Descendants::children().is_empty());
    descendants.reap();
}

#[test]
fn graceful_holder_release_allows_waiter_before_its_deadline() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    let holder = OwnedLockProcess::start_holder(home.path());
    let mut waiter = OwnedLockProcess::spawn(home.path(), "ensure_lock_waiter_process", Some(2000));
    waiter.await_marker(&home.path().join("waiter-ready"));
    assert!(!home.path().join("waiter-result").exists());
    holder.release(home.path());
    waiter.finish(Duration::from_secs(2));
    assert_eq!(
        std::fs::read_to_string(home.path().join("waiter-result")).unwrap(),
        "acquired:0"
    );
    assert!(Descendants::children().is_empty());
    descendants.reap();
}

#[test]
fn delivered_signals_do_not_renew_the_wait_budget() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    let holder = OwnedLockProcess::start_holder(home.path());
    let mut waiter = OwnedLockProcess::spawn(home.path(), "ensure_lock_waiter_process", Some(200));
    waiter.await_marker(&home.path().join("waiter-ready"));
    let deadline = Instant::now() + Duration::from_secs(2);
    while waiter.alive() {
        assert!(Instant::now() < deadline, "signals renewed the wait budget");
        // The unreaped direct child still owns this PID, including if it exits
        // between try_wait and kill. No unrelated process can reuse it here.
        assert_eq!(
            unsafe { libc::kill(waiter.0.as_ref().unwrap().id() as i32, libc::SIGUSR1) },
            0
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    let result = std::fs::read_to_string(home.path().join("waiter-result")).unwrap();
    let count = result
        .strip_prefix("timed-out:")
        .unwrap()
        .parse::<usize>()
        .unwrap();
    assert!(count > 0, "at least one actual signal must be delivered");
    holder.release(home.path());
    assert!(Descendants::children().is_empty());
    descendants.reap();
}

#[test]
fn terminating_a_waiter_does_not_unlock_or_remove_the_holder() {
    use std::os::unix::process::ExitStatusExt;
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    let mut holder = OwnedLockProcess::start_holder(home.path());
    let mut waiter = OwnedLockProcess::spawn(home.path(), "ensure_lock_waiter_process", Some(2000));
    waiter.await_marker(&home.path().join("waiter-ready"));
    assert_eq!(
        unsafe { libc::kill(waiter.0.as_ref().unwrap().id() as i32, libc::SIGTERM) },
        0
    );
    let status = waiter.wait(Duration::from_secs(2));
    assert_eq!(status.signal(), Some(libc::SIGTERM));
    assert!(holder.alive());
    let error = qshd::control::EnsureLock::acquire(&socket(home.path()), Duration::ZERO)
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    holder.release(home.path());
    drop(qshd::control::EnsureLock::acquire(&socket(home.path()), Duration::ZERO).unwrap());
    assert!(home.path().join("qsh/control.sock.lock").exists());
    assert!(Descendants::children().is_empty());
    descendants.reap();
}

impl Drop for Ensure {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn status(path: &Path) -> StatusResponse {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(ControlReply::Answered(line)) =
            client_request_with_timeout(path, &ControlRequest::Status, Duration::from_millis(200))
        {
            return StatusResponse::from_line(&line).unwrap();
        }
        assert!(
            Instant::now() < deadline,
            "owned control socket never answered"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

fn ready(run: (bool, String, String)) -> u16 {
    assert!(run.0, "ensure failed: {}", run.2);
    let lines: Vec<_> = run.1.lines().collect();
    assert_eq!(lines.len(), 2, "exact startup protocol");
    assert!(lines[0].starts_with("server-pubkey: "));
    let body: serde_json::Value =
        serde_json::from_str(lines[1].strip_prefix("TRANSPORT-READY ").unwrap()).unwrap();
    body["ports"][0].as_u64().unwrap() as u16
}

fn socket(home: &Path) -> PathBuf {
    home.join("qsh/control.sock")
}

#[test]
fn concurrent_ensure_transactions_leave_one_discoverable_daemon() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    let cache = home.path().join("qsh");
    std::fs::create_dir(&cache).unwrap();
    let lock = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(cache.join("control.sock.lock"))
        .unwrap();
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let first = Ensure::start(home.path(), 0);
    let second = Ensure::start(home.path(), 0);
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        !socket(home.path()).exists(),
        "a competing ensure published through the held transaction lock"
    );
    drop(lock);
    let first_port = ready(first.finish());
    let second_port = ready(second.finish());
    assert_ne!(first_port, 0, "READY reports the actual ephemeral port");
    assert_eq!(first_port, second_port);
    let live = status(&socket(home.path()));
    assert_eq!(live.ports[0].port, first_port);
    assert_eq!(
        Descendants::children(),
        vec![live.pid as i32],
        "no orphan daemon"
    );
    descendants.reap();

    for same in [true, false] {
        let home = tempfile::tempdir().unwrap();
        std::fs::create_dir(home.path().join("qsh")).unwrap();
        // Start from a real stale socket, exercising the existing retry path.
        drop(UnixListener::bind(socket(home.path())).unwrap());
        let a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let port_a = a.local_addr().unwrap().port();
        let port_b = if same {
            port_a
        } else {
            b.local_addr().unwrap().port()
        };
        drop((a, b));
        let first = Ensure::start(home.path(), port_a);
        let second = Ensure::start(home.path(), port_b);
        let first_port = ready(first.finish());
        let second_port = ready(second.finish());
        assert_eq!(first_port, second_port, "contenders must reuse one daemon");
        let live = status(&socket(home.path()));
        assert_eq!(live.ports[0].port, first_port);
        assert_eq!(
            Descendants::children(),
            vec![live.pid as i32],
            "no orphan daemon"
        );
        assert_eq!(ready(Ensure::start(home.path(), 0).finish()), first_port);
        descendants.reap();
    }

    let home = tempfile::tempdir().unwrap();
    let busy = UdpSocket::bind("0.0.0.0:0").unwrap();
    let failed = Ensure::start(home.path(), busy.local_addr().unwrap().port()).finish();
    assert!(!failed.0);
    assert!(failed.1.is_empty());
    assert!(!socket(home.path()).exists());
    assert!(Descendants::children().is_empty());
    let port = ready(Ensure::start(home.path(), 0).finish());
    assert_ne!(port, 0, "startup failure releases the transaction lock");
    status(&socket(home.path()));
    descendants.reap();
}

#[test]
fn stopped_daemon_does_not_unlink_a_replacement_control_socket() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    ready(Ensure::start(home.path(), 0).finish());
    let path = socket(home.path());
    let live = status(&path);
    let retired = home.path().join("qsh/retired.sock");
    std::fs::rename(&path, &retired).unwrap();
    let replacement = UnixListener::bind(&path).unwrap();
    let reply =
        client_request_with_timeout(&retired, &ControlRequest::Stop, Duration::from_secs(2))
            .unwrap();
    assert!(matches!(reply, ControlReply::Answered(line) if line.contains("stopped")));
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        let result = unsafe { libc::waitpid(live.pid as i32, &mut status, libc::WNOHANG) };
        if result == live.pid as i32 {
            break;
        }
        assert!(Instant::now() < deadline, "owned daemon did not stop");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        std::os::unix::net::UnixStream::connect(&path).is_ok(),
        "old daemon removed the replacement endpoint"
    );
    drop(replacement);
    descendants.reap();
}

#[test]
fn failed_ready_output_cleans_its_publication_and_releases_the_lock() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    let failed = Ensure::with_output(home.path(), 0, true).finish();
    assert!(!failed.0, "the output fixture must fail startup");
    assert!(
        !socket(home.path()).exists(),
        "failed startup left its published socket"
    );
    assert!(Descendants::children().is_empty());
    let port = ready(Ensure::start(home.path(), 0).finish());
    assert_ne!(port, 0);
    status(&socket(home.path()));
    descendants.reap();
}

#[test]
fn descriptor_exhaustion_before_fork_does_not_publish_a_control_socket() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let descendants = Descendants::own();
    let failed = Ensure::with_limit(home.path(), 0, false, Some(6)).finish();
    assert!(!failed.0);
    assert!(
        failed.1.is_empty(),
        "no READY on startup allocation failure"
    );
    assert!(
        failed.2.contains("Too many open files"),
        "actual EMFILE required: {}",
        failed.2
    );
    assert!(
        !socket(home.path()).exists(),
        "allocation failure left publication: {}",
        failed.2
    );
    assert!(
        std::fs::read_dir(home.path().join("qsh"))
            .unwrap()
            .flatten()
            .all(|entry| !entry.file_name().as_encoded_bytes().starts_with(b".c")),
        "failed staging is removed"
    );
    assert!(Descendants::children().is_empty());
    assert_ne!(ready(Ensure::start(home.path(), 0).finish()), 0);
    status(&socket(home.path()));
    descendants.reap();
}
