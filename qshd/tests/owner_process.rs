//! Session owner processes (#529 M1) on real processes: a REAL `qshd serve`
//! driven by a real transport client (`StdClient`), with every claim about
//! the process tree read from `/proc` -- never from the daemon's own word.
//!
//! On Linux a personal daemon runs each session in an owner process of its
//! own, the direct parent of the session's shells. These tests check who is
//! whose parent, that ending a session or stopping the daemon leaves no
//! owner and no shell behind, that owners run the daemon's own image even
//! after the file on disk was replaced, and that an owner whose frontend
//! link dies parks its session instead of ending it.
//!
//! The helpers follow `serve_channels.rs` (signed connection, free port
//! under a file-local lock, a shell channel and marker output).
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use sshauth::sign_file::FileSigner;

use transport::channel::{
    decode_server, encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord,
    CONTROL_STREAM, FIRST_CHANNEL_STREAM,
};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::shell_frame::{RecordDeframer, ShellDeframer, ShellRecord};
use transport::{LinkState, Stats};

const OWNER_ROLE: &str = "__qshd-session-owner-v1";

static ONE_DAEMON_AT_A_TIME: Mutex<()> = Mutex::new(());

fn serialised() -> std::sync::MutexGuard<'static, ()> {
    ONE_DAEMON_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn private_temp_home() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("temp dir")
}

fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .and_then(|s| s.local_addr())
        .expect("an ephemeral port")
        .port()
}

fn wait_until(within: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    probe()
}

// ---- /proc -------------------------------------------------------------------

/// `PPid` of `pid`, or `None` once `/proc/<pid>` is gone (reaped).
fn ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// A process exists and has not exited: not gone, not a zombie.
fn running(pid: u32) -> bool {
    std::fs::read_to_string(format!("/proc/{pid}/stat"))
        .ok()
        .and_then(|stat| {
            let after = stat.rfind(')')?;
            stat[after + 1..]
                .split_whitespace()
                .next()
                .map(str::to_owned)
        })
        .is_some_and(|state| state != "Z" && state != "X")
}

/// `/proc/<pid>` is gone: the process exited and its parent reaped it.
fn reaped(pid: u32) -> bool {
    !Path::new(&format!("/proc/{pid}")).exists()
}

fn cmdline(pid: u32) -> Vec<String> {
    std::fs::read(format!("/proc/{pid}/cmdline"))
        .unwrap_or_default()
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

/// The (device, inode) of the image `pid` runs.
fn image_of(pid: u32) -> (u64, u64) {
    let meta = std::fs::metadata(format!("/proc/{pid}/exe")).expect("the process image");
    (meta.dev(), meta.ino())
}

fn file_identity(path: &Path) -> (u64, u64) {
    let meta = std::fs::metadata(path).expect("the file");
    (meta.dev(), meta.ino())
}

// ---- the daemon ----------------------------------------------------------------

struct Daemon {
    child: Child,
    mark: String,
    dir: tempfile::TempDir,
    port: u16,
    server_pub: [u8; 32],
    key_path: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        assert_no_owner_left(&self.mark);
    }
}

/// Marks the daemons this test binary starts: owners inherit the mark from
/// their daemon's environment, so a leaked owner -- reparented away from
/// its dead daemon -- is still found.
const MARK_ENV: &str = "QSHD_TEST_DAEMON_MARK";

fn new_daemon_mark() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    )
}

/// Running (not zombie) processes in the session owner role started under
/// `mark`.
fn owners_marked(mark: &str) -> Vec<u32> {
    let needle = format!("{MARK_ENV}={mark}");
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
        .filter(|pid| {
            let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).unwrap_or_default();
            let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
            let state = std::fs::read_to_string(format!("/proc/{pid}/stat"))
                .ok()
                .and_then(|stat| {
                    let rest = &stat[stat.rfind(')')? + 1..];
                    rest.split_whitespace().next().map(str::to_owned)
                });
            cmdline.split(|b| *b == 0).nth(1) == Some(b"__qshd-session-owner-v1".as_slice())
                && environ
                    .split(|b| *b == 0)
                    .any(|var| var == needle.as_bytes())
                && state.is_some_and(|state| state != "Z" && state != "X")
        })
        .collect()
}

/// No session owner of the daemon marked `mark` outlives it: waited for
/// (an owner whose host died drains for at most 10 s), else killed and
/// reported.
fn assert_no_owner_left(mark: &str) {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let left = owners_marked(mark);
        if left.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            for pid in &left {
                unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
            }
            if !std::thread::panicking() {
                panic!("session owner(s) {left:?} outlived their daemon");
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl Daemon {
    fn pid(&self) -> u32 {
        self.child.id()
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.dir.path().join("qsh").join("qshd.log")).unwrap_or_default()
    }

    /// SIGTERM, then wait for the daemon's own exit.
    fn stop(&mut self) -> std::process::ExitStatus {
        unsafe { libc::kill(self.pid() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(40);
        loop {
            if let Some(status) = self.child.try_wait().expect("waiting for the daemon") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "the daemon did not stop; log: {}",
                self.log()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }
}

fn write_key(dir: &Path) -> (PrivateKey, PathBuf) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let key = PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    )
    .expect("keygen");
    let path = dir.join("client_key");
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .and_then(|mut f| f.write_all(key.to_openssh(LineEnding::LF).expect("encode").as_bytes()))
        .expect("write key");
    (key, path)
}

/// `qshd serve` from `binary`, one key in `authorized_keys`, log under
/// `<dir>/qsh/qshd.log`.
fn start_daemon_from(binary: &Path, dir: tempfile::TempDir) -> Daemon {
    let (key, key_path) = write_key(dir.path());
    let authorized_keys = dir.path().join("authorized_keys");
    std::fs::write(
        &authorized_keys,
        format!("{}\n", key.public_key().to_openssh().expect("openssh")),
    )
    .expect("authorized_keys");
    let port = free_udp_port();
    let mark = new_daemon_mark();
    let mut child = Command::new(binary)
        .args([
            "serve",
            "--port",
            &port.to_string(),
            "--authorized-keys",
            authorized_keys.to_str().expect("utf-8 path"),
            "--host-key",
            dir.path().join("host_key").to_str().expect("utf-8 path"),
        ])
        .env("XDG_CACHE_HOME", dir.path())
        .env("HOME", dir.path())
        .env(MARK_ENV, &mark)
        .env("HISTFILE", "/dev/null")
        .env("SHELL", "/bin/sh")
        .env("TMUX_TMPDIR", dir.path())
        .env_remove("TMUX")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("`qshd serve` spawns");
    let mut reader = BufReader::new(child.stdout.take().expect("stdout"));
    let mut line = String::new();
    reader.read_line(&mut line).expect("server-pubkey line");
    let encoded = line
        .strip_prefix("server-pubkey: ")
        .unwrap_or_else(|| panic!("expected a server-pubkey line, got {line:?}"))
        .trim_end();
    let bytes = BASE64.decode(encoded).expect("base64 key");
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&bytes);
    // Drain the rest so the daemon never blocks on a full pipe.
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = reader.read_to_end(&mut sink);
    });
    Daemon {
        child,
        mark,
        dir,
        port,
        server_pub,
        key_path,
    }
}

fn start_daemon() -> Daemon {
    start_daemon_from(Path::new(env!("CARGO_BIN_EXE_qshd")), private_temp_home())
}

// ---- a client with one shell channel -------------------------------------------

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

#[derive(Default)]
struct Collected {
    control: Vec<ServerRecord>,
    shell: Vec<u8>,
    live: bool,
}

struct Events {
    control: Mutex<RecordDeframer>,
    shell: Mutex<ShellDeframer>,
    collected: Mutex<Collected>,
}

impl Default for Events {
    fn default() -> Self {
        Events {
            control: Mutex::new(RecordDeframer::new()),
            shell: Mutex::new(ShellDeframer::new()),
            collected: Mutex::new(Collected::default()),
        }
    }
}

impl ClientEvents for Events {
    fn on_input_failure(&self, _failure: transport::driver_std::InputFailure) {}
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        let mut collected = self.collected.lock().unwrap();
        if stream_id == CONTROL_STREAM {
            for raw in self.control.lock().unwrap().push(&data) {
                if let Ok(rec) = decode_server(&raw) {
                    collected.control.push(rec);
                }
            }
        } else if stream_id == FIRST_CHANNEL_STREAM {
            for rec in self.shell.lock().unwrap().push(&data) {
                if let ShellRecord::Data(bytes) = rec {
                    collected.shell.extend(bytes);
                }
            }
        }
    }
    fn on_state(&self, state: LinkState) {
        if state == LinkState::Live {
            self.collected.lock().unwrap().live = true;
        }
    }
    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream_id: u8) {}
}

struct Session {
    client: StdClient,
    events: Arc<Events>,
}

impl Session {
    fn connect(daemon: &Daemon, token: [u8; 16]) -> Session {
        let events = Arc::new(Events::default());
        let client = StdClient::connect(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), daemon.port),
            ConnectionConfig {
                required_features: transport::Features::NONE,
                features: transport::Features::SUPPORTED,
                role: Role::Client,
                local_static_priv: generate_keypair().private,
                remote_static_pub: Some(daemon.server_pub),
                auth: AuthPolicy::SshSignature,
            },
            token,
            StartKind::Cold,
            Arc::new(NoopBinder),
            events.clone(),
            Some(Arc::new(
                FileSigner::load(&daemon.key_path, None)
                    .expect("the client key")
                    .with_login("client".to_string()),
            )),
        );
        assert!(
            wait_until(Duration::from_secs(15), || events
                .collected
                .lock()
                .unwrap()
                .live),
            "the handshake with the real daemon must complete; log: {}",
            daemon.log()
        );
        Session { client, events }
    }

    /// Open a shell channel and return its shell's pid, as the shell itself
    /// computes it (`$$`); a typed literal would only echo back.
    fn open_shell(&self) -> u32 {
        self.client
            .send_bytes(
                CONTROL_STREAM,
                encode_client(&ClientRecord::Open(OpenRequest {
                    stream: FIRST_CHANNEL_STREAM,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: Vec::new(),
                })),
            )
            .expect("open admitted");
        assert!(
            wait_until(Duration::from_secs(15), || self
                .events
                .collected
                .lock()
                .unwrap()
                .control
                .contains(&ServerRecord::Opened {
                    stream: FIRST_CHANNEL_STREAM
                })),
            "the shell channel must open"
        );
        self.client
            .send_bytes(FIRST_CHANNEL_STREAM, b"echo P'I'D$$-\n".to_vec())
            .expect("input admitted");
        let mut pid = None;
        assert!(
            wait_until(Duration::from_secs(15), || {
                let text = String::from_utf8_lossy(&self.events.collected.lock().unwrap().shell)
                    .into_owned();
                pid = text.match_indices("PID").find_map(|(at, _)| {
                    let rest = &text[at + 3..];
                    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                    (!digits.is_empty() && rest[digits.len()..].starts_with('-'))
                        .then(|| digits.parse().ok())
                        .flatten()
                });
                pid.is_some()
            }),
            "the shell must say its pid"
        );
        pid.unwrap()
    }

    /// Open a command channel running `sh -c '<script>'`, which must print
    /// `PID<its pid>-` first, and return that pid.
    fn open_command(&self, script: &str) -> u32 {
        self.client
            .send_bytes(
                CONTROL_STREAM,
                encode_client(&ClientRecord::Open(OpenRequest {
                    stream: FIRST_CHANNEL_STREAM,
                    kind: ChannelKind::Command,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: format!("sh -c '{script}'").into_bytes(),
                })),
            )
            .expect("open admitted");
        self.said_pid()
    }

    /// The pid the channel's process printed as `PID<digits>-`.
    fn said_pid(&self) -> u32 {
        let mut pid = None;
        assert!(
            wait_until(Duration::from_secs(15), || {
                let text = String::from_utf8_lossy(&self.events.collected.lock().unwrap().shell)
                    .into_owned();
                pid = text.match_indices("PID").find_map(|(at, _)| {
                    let rest = &text[at + 3..];
                    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                    (!digits.is_empty() && rest[digits.len()..].starts_with('-'))
                        .then(|| digits.parse().ok())
                        .flatten()
                });
                pid.is_some()
            }),
            "the channel's process must say its pid"
        );
        pid.unwrap()
    }

    /// The shell answers a computed marker: it is alive and reachable.
    fn shell_answers(&self, n: u32) -> bool {
        let needle = format!("MARK-{}-", n * 7);
        self.client
            .send_bytes(
                FIRST_CHANNEL_STREAM,
                format!("echo MARK-$(({n}*7))-\n").into_bytes(),
            )
            .is_ok()
            && wait_until(Duration::from_secs(10), || {
                String::from_utf8_lossy(&self.events.collected.lock().unwrap().shell)
                    .contains(&needle)
            })
    }
}

/// The session owner of `shell`: its parent, checked to be an owner of
/// `daemon` running the daemon's own image in the owner role.
fn owner_of(shell: u32, daemon: &Daemon) -> u32 {
    let owner = ppid(shell).expect("the shell is alive");
    assert_ne!(
        owner,
        daemon.pid(),
        "the shell is not the daemon's own child"
    );
    assert_eq!(
        ppid(owner),
        Some(daemon.pid()),
        "the shell's parent is a child of the daemon"
    );
    assert_eq!(
        cmdline(owner),
        vec!["qshd".to_string(), OWNER_ROLE.to_string()],
        "the shell's parent runs in the owner role"
    );
    assert_eq!(
        image_of(owner),
        image_of(daemon.pid()),
        "the owner runs the daemon's own image"
    );
    owner
}

// ---- tests -----------------------------------------------------------------------

#[test]
fn shell_parent_is_the_session_owner() {
    let _serial = serialised();
    let daemon = start_daemon();
    let session = Session::connect(&daemon, [21; 16]);
    let shell = session.open_shell();
    let owner = owner_of(shell, &daemon);
    assert!(session.shell_answers(3));
    // One owner per session: a second session gets another one.
    let second = Session::connect(&daemon, [22; 16]);
    let other_shell = second.open_shell();
    let other = owner_of(other_shell, &daemon);
    assert_ne!(owner, other, "each session has its own owner");
    assert!(
        daemon
            .log()
            .contains(&format!("session owner {owner} started")),
        "log: {}",
        daemon.log()
    );
    session.client.close();
    second.client.close();
}

#[test]
fn closing_the_session_leaves_no_owner_or_child() {
    let _serial = serialised();
    let daemon = start_daemon();
    let session = Session::connect(&daemon, [23; 16]);
    let shell = session.open_shell();
    let owner = owner_of(shell, &daemon);

    // A deliberate close ends the session with its shell still running.
    session.client.close();
    assert!(
        wait_until(Duration::from_secs(20), || reaped(owner) && reaped(shell)),
        "a closed session leaves neither its owner nor its shell; owner running {}, shell \
         running {}; log: {}",
        running(owner),
        running(shell),
        daemon.log()
    );
    assert!(
        wait_until(Duration::from_secs(5), || daemon.log().contains(&format!(
            "session owner {owner} exited (exit 0); drained"
        ))),
        "the owner reports its receipt; log: {}",
        daemon.log()
    );
    assert!(running(daemon.pid()), "the daemon itself goes on");

    // A shell that exits on its own ends its channel, not the session; the
    // owner stays until the session ends.
    let again = Session::connect(&daemon, [24; 16]);
    let shell = again.open_shell();
    let owner = owner_of(shell, &daemon);
    again
        .client
        .send_bytes(FIRST_CHANNEL_STREAM, b"exit\n".to_vec())
        .expect("input admitted");
    assert!(
        wait_until(Duration::from_secs(15), || reaped(shell)),
        "the exited shell is reaped by its owner"
    );
    assert!(
        running(owner),
        "the session, and its owner, outlive the shell"
    );
    again.client.close();
    assert!(
        wait_until(Duration::from_secs(20), || reaped(owner)),
        "the closed session's owner is reaped; log: {}",
        daemon.log()
    );
}

#[test]
fn stop_reaps_every_owner_and_reports_drained() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let one = Session::connect(&daemon, [25; 16]);
    let two = Session::connect(&daemon, [26; 16]);
    let shells = [one.open_shell(), two.open_shell()];
    let owners = [owner_of(shells[0], &daemon), owner_of(shells[1], &daemon)];

    let status = daemon.stop();
    assert!(
        status.success(),
        "a stopped daemon exits cleanly: {status:?}"
    );
    for pid in owners.iter().chain(&shells) {
        assert!(
            reaped(*pid),
            "nothing of a session outlives the daemon's stop: {pid} is still there"
        );
    }
    let log = daemon.log();
    for owner in owners {
        assert!(
            log.contains(&format!("session owner {owner} exited (exit 0); drained")),
            "every owner's drain receipt is in the log; log: {log}"
        );
    }
    drop((one, two));
}

/// An owner that dies without its receipt -- its shells may live on under
/// whoever adopted them -- makes the daemon's later STOP a failure, as a
/// failed session worker did when sessions ran in the daemon.
#[test]
fn an_owner_killed_before_stop_fails_the_stop() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let session = Session::connect(&daemon, [29; 16]);
    let shell = session.open_shell();
    let owner = owner_of(shell, &daemon);
    assert_eq!(unsafe { libc::kill(owner as i32, libc::SIGKILL) }, 0);
    assert!(
        wait_until(Duration::from_secs(10), || reaped(owner)),
        "the daemon reaps its killed owner"
    );
    assert!(
        wait_until(Duration::from_secs(5), || daemon.log().contains(&format!(
            "session owner {owner} exited (signal 9); no receipt"
        ))),
        "log: {}",
        daemon.log()
    );
    let status = daemon.stop();
    assert!(
        !status.success(),
        "a stop after an owner died without its receipt is not clean: {status:?}; log: {}",
        daemon.log()
    );
    drop(session);
}

#[test]
fn owner_started_from_held_image_after_binary_replaced_on_disk() {
    use std::os::unix::fs::PermissionsExt;
    let _serial = serialised();
    let dir = private_temp_home();
    let bin_dir = dir.path().join("bin");
    std::fs::create_dir(&bin_dir).unwrap();
    let installed = bin_dir.join("qshd");
    std::fs::copy(env!("CARGO_BIN_EXE_qshd"), &installed).expect("copy the daemon");
    std::fs::set_permissions(&installed, std::fs::Permissions::from_mode(0o755)).unwrap();
    let daemon = start_daemon_from(&installed, dir);
    let running_image = image_of(daemon.pid());
    assert_eq!(running_image, file_identity(&installed));

    // A package upgrade: another file renamed over the installed path.
    let replacement = bin_dir.join("qshd.new");
    std::fs::write(&replacement, b"#!/bin/sh\nexit 97\n").unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::rename(&replacement, &installed).unwrap();
    assert_ne!(file_identity(&installed), running_image);

    let session = Session::connect(&daemon, [27; 16]);
    let shell = session.open_shell();
    let owner = owner_of(shell, &daemon);
    assert_eq!(
        image_of(owner),
        running_image,
        "the owner runs the image the daemon started with"
    );
    assert_ne!(image_of(owner), file_identity(&installed));
    assert!(
        std::fs::read_link(format!("/proc/{owner}/exe"))
            .unwrap()
            .to_string_lossy()
            .ends_with(" (deleted)"),
        "the owner's image is the replaced file, not the one now on disk"
    );
    assert!(session.shell_answers(5));
    session.client.close();
}

fn pidfd_open(pid: u32) -> OwnedFd {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    assert!(raw >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(raw as i32) }
}

/// A test-owned duplicate of descriptor `fd` of process `pid`.
fn steal_fd(pid: u32, fd: i32) -> OwnedFd {
    let pidfd = pidfd_open(pid);
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), fd, 0) };
    assert!(
        raw >= 0,
        "pidfd_getfd (needs ptrace access to this test's own descendant): {}",
        std::io::Error::last_os_error()
    );
    unsafe { OwnedFd::from_raw_fd(raw as i32) }
}

#[test]
fn owner_link_eof_parks_instead_of_ending() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let session = Session::connect(&daemon, [28; 16]);
    let shell = session.open_shell();
    let owner = owner_of(shell, &daemon);

    // Kill the link between the frontend and this owner, both ways, at the
    // socket itself (descriptor 3 is the owner's link end): neither side
    // ever sends an end of the session.
    let link = steal_fd(owner, 3);
    assert_eq!(
        unsafe { libc::shutdown(link.as_raw_fd(), libc::SHUT_RDWR) },
        0
    );
    drop(link);
    assert!(
        wait_until(Duration::from_secs(10), || daemon.log().contains("parking")),
        "the owner parks its session; log: {}",
        daemon.log()
    );
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        running(shell) && running(owner),
        "a lost link is not the end of the session: shell {} owner {}",
        running(shell),
        running(owner)
    );
    assert_eq!(ppid(shell), Some(owner), "the shell keeps its owner");

    // Only an explicit stop ends a parked session.
    let status = daemon.stop();
    assert!(status.success(), "{status:?}");
    assert!(
        reaped(owner) && reaped(shell),
        "the stop ends the parked session"
    );
    assert!(
        daemon
            .log()
            .contains(&format!("session owner {owner} exited (exit 0); drained")),
        "log: {}",
        daemon.log()
    );
    drop(session);
}

/// An owner whose host dies -- the daemon SIGKILLed -- ends its session
/// destructively and exits, even while a channel's input writer is blocked
/// for good in a write into the pseudo-terminal (a process that never reads
/// its input, under a large paste): neither the owner nor the channel's
/// process is left behind.
#[test]
fn an_owner_whose_host_dies_ends_even_with_a_blocked_channel() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let session = Session::connect(&daemon, [30; 16]);
    let process = session.open_command("stty raw -echo; echo PID$$-; exec sleep 300");
    let owner = owner_of(process, &daemon);
    // More input than the terminal takes: the owner's writer blocks.
    session
        .client
        .send_bytes(FIRST_CHANNEL_STREAM, vec![b'x'; 1 << 20])
        .expect("paste admitted");
    std::thread::sleep(Duration::from_secs(2));
    assert!(running(process) && running(owner));

    daemon.child.kill().expect("SIGKILL the daemon");
    daemon.child.wait().expect("reap the daemon");
    assert!(
        wait_until(Duration::from_secs(40), || !running(owner)
            && !running(process)),
        "the owner {owner} ({}) and its channel's process {process} ({}) outlived their host",
        running(owner),
        running(process)
    );
    drop(session);
}

/// `SIGTERM` to an owner is `Stop`: its session ends, its shell is reaped,
/// it reports a clean drain and exits 0 -- and the daemon serves on.
#[test]
fn sigterm_to_an_owner_is_a_stop() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let session = Session::connect(&daemon, [31; 16]);
    let shell = session.open_shell();
    let owner = owner_of(shell, &daemon);
    assert_eq!(unsafe { libc::kill(owner as i32, libc::SIGTERM) }, 0);
    assert!(
        wait_until(Duration::from_secs(20), || reaped(owner) && reaped(shell)),
        "owner {owner} and shell {shell} end; log: {}",
        daemon.log()
    );
    assert!(
        wait_until(Duration::from_secs(5), || daemon.log().contains(&format!(
            "session owner {owner} exited (exit 0); drained"
        ))),
        "log: {}",
        daemon.log()
    );
    let next = Session::connect(&daemon, [32; 16]);
    let other = next.open_shell();
    assert_ne!(owner_of(other, &daemon), owner);
    assert!(next.shell_answers(4));
    let status = daemon.stop();
    assert!(status.success(), "{status:?}; log: {}", daemon.log());
    drop((session, next));
}
