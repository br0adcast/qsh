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

    fn finish(mut self) -> (bool, String, String) {
        use std::io::{Seek, SeekFrom};
        let deadline = Instant::now() + Duration::from_secs(15);
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
