//! Real personal-daemon transactions, isolated in this serialized test binary.
//! Linux subreaping keeps even an orphan from a failed race owned by this test.
#![cfg(target_os = "linux")]

use std::fs::{File, OpenOptions};
use std::io::Read;
use std::net::UdpSocket;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

use base64::Engine as _;
use qshd::control::{client_request_with_timeout, ControlReply, ControlRequest, StatusResponse};
use transport::channel::{
    decode_server, encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord,
    CONTROL_STREAM, FIRST_CHANNEL_STREAM,
};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::{LinkState, Stats};

fn pidfd(pid: u32) -> OwnedFd {
    // The marker belongs to our live daemon's child; pin the exact process
    // before STOP, rather than polling or signalling a reusable numeric PID.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(
        fd >= 0,
        "pin owned process: {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(fd as i32) }
}

fn exited(fd: &OwnedFd) -> bool {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert!(unsafe { libc::poll(&mut poll, 1, 0) } >= 0);
    poll.revents & libc::POLLIN != 0
}

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

struct Events {
    records: Mutex<transport::shell_frame::RecordDeframer>,
    opened: AtomicBool,
}
impl Default for Events {
    fn default() -> Self {
        Self {
            records: Mutex::new(transport::shell_frame::RecordDeframer::new()),
            opened: AtomicBool::new(false),
        }
    }
}
impl ClientEvents for Events {
    fn on_bytes(&self, stream: u8, data: Vec<u8>) {
        if stream == CONTROL_STREAM {
            for raw in self.records.lock().unwrap().push(&data) {
                if matches!(
                    decode_server(&raw),
                    Ok(ServerRecord::Opened {
                        stream: FIRST_CHANNEL_STREAM
                    })
                ) {
                    self.opened.store(true, Ordering::Release);
                }
            }
        }
    }
    fn on_state(&self, _state: LinkState) {}
    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream: u8) {}
}

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
fn stop_joins_a_silent_authenticated_channel_before_daemon_exit() {
    stop_with_silent_channel(false);
}

#[test]
fn stop_joins_a_silent_channel_with_a_hup_ignoring_descendant() {
    stop_with_silent_channel(true);
}

fn stop_with_silent_channel(keep_descendant: bool) {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    // This dedicated, serialized binary owns every descendant it creates.
    // On RED/unwind the guard first kills/reaps the daemon, then adopts and
    // kills/reaps its remaining children. It never signals a reaped PID/group.
    let _descendants = Descendants::own();
    let run = Ensure::start(home.path(), 0).finish();
    let key_line = run.1.lines().next().unwrap().to_owned();
    let port = ready(run);
    let server_pub: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(key_line.strip_prefix("server-pubkey: ").unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let sock = socket(home.path());
    let daemon_pid = status(&sock).pid;
    let daemon_fd = pidfd(daemon_pid);
    assert_eq!(status(&sock).pid, daemon_pid, "pin the answering daemon");
    let key = generate_keypair();
    assert!(matches!(
        client_request_with_timeout(
            &sock,
            &ControlRequest::AddClient(key.public),
            Duration::from_secs(2)
        )
        .unwrap(),
        ControlReply::Answered(_)
    ));
    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        ([127, 0, 0, 1], port).into(),
        ConnectionConfig {
            required_features: transport::Features::NONE,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
        },
        [39; 16],
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        None,
    );
    client.send_bytes(
        CONTROL_STREAM,
        encode_client(&ClientRecord::Open(OpenRequest {
            stream: FIRST_CHANNEL_STREAM,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        })),
    );
    let open_deadline = Instant::now() + Duration::from_secs(15);
    while !events.opened.load(Ordering::Acquire) {
        assert!(
            Instant::now() < open_deadline,
            "authenticated channel did not open"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    let marker = home.path().join("silent-child.pid");
    // Shell execution, not terminal echo, publishes the owned identities.
    // The ordinary control execs one sleeper. The descendant case leaves a
    // responsive shell waiting on a sleeper; both deliberately ignore HUP,
    // so stopping only the direct child cannot close the PTY slave.
    let command = if keep_descendant {
        format!(
            "trap '' HUP; /bin/sleep 600 & printf '%s %s\\n' \"$$\" \"$!\" > '{}'; wait\n",
            marker.display()
        )
    } else {
        format!(
            "printf '%s\\n' \"$$\" > '{}'; exec /bin/sleep 600\n",
            marker.display()
        )
    };
    client.send_bytes(FIRST_CHANNEL_STREAM, command.into_bytes());
    let ready_deadline = Instant::now() + Duration::from_secs(15);
    let child_pids: Vec<u32> = loop {
        if let Ok(text) = std::fs::read_to_string(&marker) {
            if let Ok(pids) = text
                .split_whitespace()
                .map(str::parse)
                .collect::<Result<Vec<u32>, _>>()
            {
                if pids.len() == if keep_descendant { 2 } else { 1 } {
                    break pids;
                }
            }
        }
        assert!(
            Instant::now() < ready_deadline,
            "authenticated shell did not publish readiness"
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    let child_fds: Vec<_> = child_pids.iter().map(|&pid| pidfd(pid)).collect();
    let sleeper = *child_pids.last().unwrap();
    // The marker precedes exec. Wait for the pinned fixture to actually enter
    // sleep so a fast STOP cannot pass by racing a still-running shell command.
    while std::fs::read_link(format!("/proc/{sleeper}/exe"))
        .ok()
        .and_then(|p| p.file_name().map(|n| n == "sleep"))
        != Some(true)
    {
        assert!(
            !exited(child_fds.last().unwrap()),
            "sleeper exited before readiness"
        );
        assert!(
            Instant::now() < ready_deadline,
            "fixture did not exec sleep"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        child_fds.iter().all(|fd| !exited(fd)),
        "silent processes must be live before STOP"
    );
    // These exact instances are pinned and live across the observations. Record
    // ordinary shell job-control boundaries before deciding which scope to stop.
    let owned_scope: Vec<_> = child_pids
        .iter()
        .zip(&child_fds)
        .map(|(&pid, fd)| {
            assert!(
                !exited(fd),
                "owned scope observation needs the pinned live instance"
            );
            let pgid = unsafe { libc::getpgid(pid as libc::pid_t) };
            let sid = unsafe { libc::getsid(pid as libc::pid_t) };
            assert!(
                pgid > 0 && sid > 0 && !exited(fd),
                "owned scope changed during observation"
            );
            (pid, pgid, sid)
        })
        .collect();
    eprintln!("owned process scope (pid, pgid, sid): {owned_scope:?}");
    assert!(
        matches!(client_request_with_timeout(&sock, &ControlRequest::Stop,
        Duration::from_secs(2)).unwrap(),
        ControlReply::Answered(line) if line.contains("stopping"))
    );

    // Observe each obligation before cleanup or assertions can change it.
    // A successful STOP reply is not an exit/cleanup receipt.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !exited(&daemon_fd) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let daemon_exited = exited(&daemon_fd);
    let child_deadline = Instant::now() + Duration::from_secs(2);
    while child_fds.iter().any(|fd| !exited(fd)) && Instant::now() < child_deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    let child_exited: Vec<_> = child_fds.iter().map(exited).collect();
    let rebound = UdpSocket::bind(("127.0.0.1", port));
    let socket_removed = !sock.exists();
    assert!(daemon_exited && child_exited.iter().all(|&done| done) && rebound.is_ok() && socket_removed,
        "STOP obligations: daemon_exited={daemon_exited}, child_exited={child_exited:?}, udp_rebound={}, socket_removed={socket_removed}", rebound.is_ok());
    client.close();
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
    let port = ready(Ensure::start(home.path(), 0).finish());
    let path = socket(home.path());
    let live = status(&path);
    let retired = home.path().join("qsh/retired.sock");
    std::fs::rename(&path, &retired).unwrap();
    let replacement = UnixListener::bind(&path).unwrap();
    let reply =
        client_request_with_timeout(&retired, &ControlRequest::Stop, Duration::from_secs(2))
            .unwrap();
    assert!(matches!(reply, ControlReply::Answered(line) if line.contains("stopping")));
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
    assert!(
        UdpSocket::bind(("127.0.0.1", port)).is_ok(),
        "no-channel STOP retained the UDP port"
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
