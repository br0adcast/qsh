//! The host and its replaceable frontend (#529 M1) on real processes: a
//! REAL personal daemon (`qshd serve`, and the detached `transport-ensure`
//! daemon) whose network frontend process is killed, with every claim
//! about the process tree read from `/proc`.
//!
//! On Linux a personal daemon is a host process that starts its session
//! router in a frontend process of its own and each session in an owner
//! process. These tests kill the frontend -- once, in a loop, around a
//! retention, around `ADD-CLIENT`, before a stop -- and check that the host
//! starts another after a growing wait, that the same shell answers the
//! client's warm return, that what the host keeps of a session does not
//! move, and that a stop still reaps everything.
//!
//! The helpers follow `owner_process.rs` (signed connection, free port
//! under a file-local lock, a shell channel and marker output).
#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader, Read};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use sshauth::sign_file::FileSigner;

use qshd::control::{client_request, ControlReply, ControlRequest};
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

mod daemon_guard;
use daemon_guard::DaemonGuard;

const OWNER_ROLE: &str = "__qshd-session-owner-v1";
const FRONTEND_ROLE: &str = "__qshd-frontend-v1";

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
        std::thread::sleep(Duration::from_millis(10));
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

fn role_of(pid: u32) -> Option<String> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let role = cmdline.split(|b| *b == 0).nth(1)?;
    Some(String::from_utf8_lossy(role).into_owned())
}

fn pids() -> Vec<u32> {
    std::fs::read_dir("/proc")
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| entry.file_name().to_str()?.parse().ok())
                .collect()
        })
        .unwrap_or_default()
}

/// The running frontend processes of the daemon `host`: its children in
/// the frontend role.
fn frontends_of(host: u32) -> Vec<u32> {
    pids()
        .into_iter()
        .filter(|pid| {
            ppid(*pid) == Some(host)
                && role_of(*pid).as_deref() == Some(FRONTEND_ROLE)
                && running(*pid)
        })
        .collect()
}

/// The one frontend of `host`, waited for.
fn frontend_of(host: u32) -> u32 {
    let mut found = Vec::new();
    assert!(
        wait_until(Duration::from_secs(15), || {
            found = frontends_of(host);
            found.len() == 1
        }),
        "the daemon runs exactly one frontend, found {found:?}"
    );
    found[0]
}

/// Kill exactly the frontend `pid` of `host` (checked to still be it).
fn kill_frontend(host: u32, pid: u32) {
    assert_eq!(
        (ppid(pid), role_of(pid).as_deref()),
        (Some(host), Some(FRONTEND_ROLE)),
        "pid {pid} is the daemon's frontend"
    );
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGKILL) }, 0);
}

/// The frontend that replaces `old`, waited for.
fn frontend_after(host: u32, old: u32) -> u32 {
    let mut found = Vec::new();
    assert!(
        wait_until(Duration::from_secs(20), || {
            found = frontends_of(host);
            found.len() == 1 && found[0] != old
        }),
        "the host starts another frontend after {old}, found {found:?}"
    );
    found[0]
}

/// Marks the daemons this test binary starts: frontends and owners inherit
/// the mark from their daemon's environment, so a leaked one -- reparented
/// away from its dead daemon -- is still found.
const MARK_ENV: &str = "QSHD_TEST_DAEMON_MARK";

fn new_daemon_mark() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "fr-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    )
}

/// Running processes in the owner or the frontend role started under `mark`.
fn children_marked(mark: &str) -> Vec<(u32, String)> {
    let needle = format!("{MARK_ENV}={mark}");
    pids()
        .into_iter()
        .filter_map(|pid| {
            let role = role_of(pid)?;
            let environ = std::fs::read(format!("/proc/{pid}/environ")).unwrap_or_default();
            ((role == OWNER_ROLE || role == FRONTEND_ROLE)
                && environ
                    .split(|b| *b == 0)
                    .any(|var| var == needle.as_bytes())
                && running(pid))
            .then_some((pid, role))
        })
        .collect()
}

/// No frontend and no session owner of the daemon marked `mark` outlives
/// it: waited for (an owner whose host died drains for at most 10 s), else
/// killed and reported.
fn assert_no_child_left(mark: &str) {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let left = children_marked(mark);
        if left.is_empty() {
            return;
        }
        if Instant::now() >= deadline {
            for (pid, _) in &left {
                unsafe { libc::kill(*pid as i32, libc::SIGKILL) };
            }
            if !std::thread::panicking() {
                panic!("processes {left:?} outlived their daemon");
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

// ---- a `serve` daemon ----------------------------------------------------------

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
        assert_no_child_left(&self.mark);
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

/// `qshd serve`, one key in `authorized_keys`, log under
/// `<dir>/qsh/qshd.log`.
fn start_daemon() -> Daemon {
    let dir = private_temp_home();
    let (key, key_path) = write_key(dir.path());
    let authorized_keys = dir.path().join("authorized_keys");
    std::fs::write(
        &authorized_keys,
        format!("{}\n", key.public_key().to_openssh().expect("openssh")),
    )
    .expect("authorized_keys");
    let port = free_udp_port();
    let mark = new_daemon_mark();
    let mut child = Command::new(env!("CARGO_BIN_EXE_qshd"))
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

/// How a client proves itself: with a signature, or with a static key the
/// daemon's allowlist holds.
enum Proof<'a> {
    Signature(&'a Path),
    Allowlisted([u8; 32]),
}

impl Session {
    fn connect(daemon: &Daemon, token: [u8; 16]) -> Session {
        Self::start(
            daemon.port,
            daemon.server_pub,
            Proof::Signature(&daemon.key_path),
            token,
            StartKind::Cold,
        )
        .unwrap_or_else(|| panic!("the handshake must complete; log: {}", daemon.log()))
    }

    /// A client's warm return to the session of `token`.
    fn come_back(daemon: &Daemon, token: [u8; 16]) -> Session {
        Self::start(
            daemon.port,
            daemon.server_pub,
            Proof::Signature(&daemon.key_path),
            token,
            StartKind::Warm,
        )
        .unwrap_or_else(|| panic!("the warm return must complete; log: {}", daemon.log()))
    }

    /// `None` if the handshake did not complete in time.
    fn start(
        port: u16,
        server_pub: [u8; 32],
        proof: Proof<'_>,
        token: [u8; 16],
        start: StartKind,
    ) -> Option<Session> {
        Self::start_within(
            port,
            server_pub,
            proof,
            token,
            start,
            Duration::from_secs(15),
        )
    }

    fn start_within(
        port: u16,
        server_pub: [u8; 32],
        proof: Proof<'_>,
        token: [u8; 16],
        start: StartKind,
        within: Duration,
    ) -> Option<Session> {
        let events = Arc::new(Events::default());
        let (auth, local_static_priv, signer) = match proof {
            Proof::Signature(key) => (
                AuthPolicy::SshSignature,
                generate_keypair().private,
                Some(Arc::new(
                    FileSigner::load(key, None)
                        .expect("the client key")
                        .with_login("client".to_string()),
                ) as Arc<_>),
            ),
            Proof::Allowlisted(private) => (AuthPolicy::Allowlist(Vec::new()), private, None),
        };
        let client = StdClient::connect(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
            ConnectionConfig {
                required_features: transport::Features::NONE,
                features: transport::Features::SUPPORTED,
                role: Role::Client,
                local_static_priv,
                remote_static_pub: Some(server_pub),
                auth,
            },
            token,
            start,
            Arc::new(NoopBinder),
            events.clone(),
            signer,
        );
        let live = wait_until(within, || events.collected.lock().unwrap().live);
        if !live {
            client.detach();
            return None;
        }
        Some(Session { client, events })
    }

    fn send(&self, line: &str) {
        self.client
            .send_bytes(FIRST_CHANNEL_STREAM, line.as_bytes().to_vec())
            .expect("input admitted");
    }

    fn shell_text(&self) -> String {
        String::from_utf8_lossy(&self.events.collected.lock().unwrap().shell).into_owned()
    }

    fn sees(&self, needle: &str) -> bool {
        wait_until(Duration::from_secs(15), || {
            self.shell_text().contains(needle)
        })
    }

    /// The pid the shell prints as `<tag><digits>-`, computed by the shell
    /// itself (`$$`): a typed literal would only echo back.
    fn said_pid(&self, tag: &str) -> u32 {
        let mut pid = None;
        assert!(
            wait_until(Duration::from_secs(15), || {
                let text = self.shell_text();
                pid = text.match_indices(tag).find_map(|(at, _)| {
                    let rest = &text[at + tag.len()..];
                    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
                    (!digits.is_empty() && rest[digits.len()..].starts_with('-'))
                        .then(|| digits.parse().ok())
                        .flatten()
                });
                pid.is_some()
            }),
            "the shell must say its pid after {tag}; saw {:?}",
            self.shell_text()
        );
        pid.unwrap()
    }

    /// Open a shell channel, plant `marker` in a variable of the shell, and
    /// return the shell's pid.
    fn open_shell(&self, marker: &str) -> u32 {
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
        self.send(&format!("QSH_KEPT={marker}; echo P'I'D$$-\n"));
        self.said_pid("PID")
    }

    /// The shell this (returned) client talks to: its pid, and the marker
    /// the first client planted in it.
    fn same_shell(&self, marker: &str) -> u32 {
        self.send("echo B'A'CK$$-$QSH_KEPT-\n");
        let pid = self.said_pid("BACK");
        assert!(
            self.sees(&format!("BACK{pid}-{marker}-")),
            "the shell still holds the marker; saw {:?}",
            self.shell_text()
        );
        pid
    }
}

/// The session owner of `shell`: its parent, a child of the daemon itself
/// (the host) -- not of any frontend -- in the owner role.
fn owner_of(shell: u32, host: u32) -> u32 {
    let owner = ppid(shell).expect("the shell is alive");
    assert_eq!(
        ppid(owner),
        Some(host),
        "the shell's parent is a child of the host"
    );
    assert_eq!(role_of(owner).as_deref(), Some(OWNER_ROLE));
    owner
}

fn pidfd_open(pid: u32) -> OwnedFd {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    assert!(raw >= 0, "pidfd_open: {}", std::io::Error::last_os_error());
    unsafe { OwnedFd::from_raw_fd(raw as i32) }
}

/// Kill the first link of `owner`'s session, both ways, at the socket
/// itself (descriptor 3 is the owner's end): neither side ever says the
/// session ended. Returns once the frontend has noticed.
fn sever_first_link(owner: u32, daemon: &Daemon) {
    let pidfd = pidfd_open(owner);
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), 3, 0) };
    assert!(
        raw >= 0,
        "pidfd_getfd (needs ptrace access to this test's own descendant): {}",
        std::io::Error::last_os_error()
    );
    let link = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    assert_eq!(
        unsafe { libc::shutdown(link.as_raw_fd(), libc::SHUT_RDWR) },
        0
    );
    assert!(
        wait_until(Duration::from_secs(10), || daemon
            .log()
            .contains("the link was lost")),
        "the frontend notices its lost link; log: {}",
        daemon.log()
    );
}

/// The number after `key` in the last log line that contains `line`.
fn logged_number(log: &str, line: &str, key: &str) -> Option<u64> {
    let found = log.lines().rev().find(|l| l.contains(line))?;
    let rest = &found[found.find(key)? + key.len()..];
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

// ---- tests -----------------------------------------------------------------------

/// The frontend process is killed under a session. The host starts another
/// one; the client's warm return -- a fresh, signed handshake with a
/// frontend that has never heard of it -- lands in the same shell: same
/// pid, same parent, and the variable the first client planted. The owner
/// is the host's child throughout, and nothing ended the session.
#[test]
fn killing_the_frontend_keeps_the_same_shell() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let token = [61; 16];
    let session = Session::connect(&daemon, token);
    let shell = session.open_shell("kept-61");
    let owner = owner_of(shell, daemon.pid());
    let frontend = frontend_of(daemon.pid());
    assert_ne!(frontend, owner);

    kill_frontend(daemon.pid(), frontend);
    let next = frontend_after(daemon.pid(), frontend);
    assert!(reaped(frontend), "the host reaped the dead frontend");
    // The client's old connection leads nowhere now; it lets go without a
    // word, as its death timer would have it do.
    session.client.detach();
    assert!(
        running(shell) && running(owner),
        "the session outlived its frontend"
    );

    let back = Session::come_back(&daemon, token);
    assert_eq!(back.same_shell("kept-61"), shell, "the same shell answers");
    assert_eq!(ppid(shell), Some(owner), "under the same owner");
    assert_eq!(owner_of(shell, daemon.pid()), owner);
    assert_eq!(frontends_of(daemon.pid()), [next]);
    let log = daemon.log();
    assert!(
        log.contains("network frontend 2 started") && log.contains("1 session(s) kept"),
        "log: {log}"
    );
    assert!(
        !log.contains(&format!("session owner {owner}: session ended")),
        "nothing ended the session; log: {log}"
    );

    // And a second time in a row, from the session the second frontend
    // recovered.
    kill_frontend(daemon.pid(), next);
    frontend_after(daemon.pid(), next);
    back.client.detach();
    let again = Session::come_back(&daemon, token);
    assert_eq!(again.same_shell("kept-61"), shell);

    // An explicit close still ends the shell and its owner.
    again.client.close();
    assert!(
        wait_until(Duration::from_secs(20), || reaped(shell) && reaped(owner)),
        "a deliberate close ends the session; log: {}",
        daemon.log()
    );
    assert!(daemon.stop().success());
}

/// A frontend that dies as soon as it is up does not make the host spin:
/// each next one comes after a wait that doubles from 0.1 s. Nothing of
/// this reaches the session: its owner and shell run on, and when a
/// frontend finally stays, the client is back in the same shell.
#[test]
fn frontend_crash_loop_backs_off_and_keeps_sessions() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let token = [62; 16];
    let session = Session::connect(&daemon, token);
    let shell = session.open_shell("kept-62");
    let owner = owner_of(shell, daemon.pid());
    session.client.detach();

    let mut frontend = frontend_of(daemon.pid());
    let mut waits = Vec::new();
    for _ in 0..5 {
        kill_frontend(daemon.pid(), frontend);
        let killed = Instant::now();
        frontend = frontend_after(daemon.pid(), frontend);
        waits.push(killed.elapsed());
        assert!(running(shell) && running(owner), "the session is kept");
    }
    // The host waited 0.1, 0.2, 0.4, 0.8 and 1.6 s; starting a process
    // comes on top.
    for (round, (wait, least)) in waits.iter().zip([100u64, 200, 400, 800, 1600]).enumerate() {
        assert!(
            *wait >= Duration::from_millis(least),
            "restart {round} came after {wait:?}, sooner than {least} ms: {waits:?}"
        );
        assert!(
            *wait < Duration::from_millis(least) + Duration::from_secs(4),
            "restart {round} took {wait:?}: {waits:?}"
        );
    }
    assert!(
        daemon.log().contains("the next one starts in 1600 ms"),
        "log: {}",
        daemon.log()
    );

    let back = Session::come_back(&daemon, token);
    assert_eq!(back.same_shell("kept-62"), shell);
    assert_eq!(ppid(shell), Some(owner));
    back.client.close();
    assert!(daemon.stop().success());
}

/// [RF 5] The daemon is stopped while no frontend runs (the host is waiting
/// out its backoff after a crash loop): the stop still ends every session,
/// reaps every owner and shell, starts no other frontend, and reports
/// success.
#[test]
fn stop_while_frontend_down_reaps_everything() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let first = Session::connect(&daemon, [63; 16]);
    let shell = first.open_shell("kept-63");
    let owner = owner_of(shell, daemon.pid());
    let second = Session::connect(&daemon, [64; 16]);
    let other_shell = second.open_shell("kept-64");
    let other_owner = owner_of(other_shell, daemon.pid());
    first.client.detach();
    second.client.detach();

    // Six deaths in a row: the seventh frontend is 3.2 s away.
    let mut frontend = frontend_of(daemon.pid());
    for _ in 0..5 {
        kill_frontend(daemon.pid(), frontend);
        frontend = frontend_after(daemon.pid(), frontend);
    }
    kill_frontend(daemon.pid(), frontend);
    assert!(
        wait_until(Duration::from_secs(5), || daemon
            .log()
            .contains("the next one starts in 3200 ms")),
        "log: {}",
        daemon.log()
    );
    assert!(frontends_of(daemon.pid()).is_empty(), "no frontend runs");
    assert!(running(shell) && running(other_shell));

    let stopping = Instant::now();
    let status = daemon.stop();
    assert!(status.success(), "{status:?}; log: {}", daemon.log());
    assert!(
        stopping.elapsed() < Duration::from_secs(15),
        "the stop did not wait for a frontend: {:?}",
        stopping.elapsed()
    );
    for pid in [shell, owner, other_shell, other_owner] {
        assert!(reaped(pid), "process {pid} outlived the stop");
    }
    let log = daemon.log();
    assert!(
        !log.contains("network frontend 7 started"),
        "no frontend was started for the stop; log: {log}"
    );
    for pid in [owner, other_owner] {
        assert!(
            log.contains(&format!("session owner {pid} exited (exit 0); drained")),
            "owner {pid} proved its cleanup; log: {log}"
        );
    }
}

/// This test process adopts the orphans of its children while this lives
/// (`PR_SET_CHILD_SUBREAPER`), and stops when it goes, however the test
/// ends: later tests' orphans must not stay its unreaped zombies.
struct Subreaper;

impl Subreaper {
    fn set() -> Subreaper {
        assert_eq!(
            unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
            0
        );
        Subreaper
    }
}

impl Drop for Subreaper {
    fn drop(&mut self) {
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0, 0, 0, 0) };
    }
}

/// Reap `pid`, a process this test adopted, waited for: how it ended.
fn reap_adopted(pid: u32) -> Option<i32> {
    let mut status = 0;
    wait_until(Duration::from_secs(10), || {
        let reaped = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
        reaped == pid as i32
    })
    .then_some(status)
}

/// The host itself dies (`SIGKILL`): its sessions are lost, as when a
/// single-process daemon dies. Its frontend dies with it -- the kernel
/// kills it (`PR_SET_PDEATHSIG`) instead of leaving it to notice and shut
/// down -- so it neither serves on as an orphan nor holds the daemon's UDP
/// port, which the daemon started next binds. This test adopts what the
/// host leaves (subreaper), so it sees how the frontend ended.
#[test]
fn a_dead_host_takes_its_frontend_and_frees_the_port() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let session = Session::connect(&daemon, [69; 16]);
    let shell = session.open_shell("kept-69");
    let owner = owner_of(shell, daemon.pid());
    let frontend = frontend_of(daemon.pid());
    let _adopting = Subreaper::set();

    daemon.child.kill().expect("SIGKILL to the host");
    daemon.child.wait().expect("the host is reaped");
    let status = reap_adopted(frontend).expect("the frontend ends with its host");
    assert!(
        libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL,
        "the kernel killed the frontend with its host (status {status:#x})"
    );
    assert!(
        wait_until(Duration::from_secs(5), || UdpSocket::bind((
            Ipv4Addr::UNSPECIFIED,
            daemon.port
        ))
        .is_ok()),
        "the port is free again"
    );
    session.client.detach();
    // The session died with its host; its owner ends it and exits.
    assert!(
        reap_adopted(owner).is_some() && wait_until(Duration::from_secs(30), || !running(shell)),
        "the owner of a dead host ends its session"
    );
}

/// A retained session's time is kept by the host, and a frontend's death
/// does not move it: the moment its retention began is the same before and
/// after the frontend is replaced, twice over. The client that finally
/// returns finds the same shell.
#[test]
fn retention_deadline_survives_frontend_death() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let token = [65; 16];
    let session = Session::connect(&daemon, token);
    let shell = session.open_shell("kept-65");
    let owner = owner_of(shell, daemon.pid());

    // The session loses its connection without a close: it is retained.
    sever_first_link(owner, &daemon);
    session.client.detach();
    let retained = format!("session owner={owner} retained since=");
    assert!(
        wait_until(Duration::from_secs(10), || daemon.log().contains(&retained)),
        "the host hears of the retention; log: {}",
        daemon.log()
    );
    let since = logged_number(&daemon.log(), &retained, "since=").expect("a time");

    let kept = format!("kept session owner={owner} state=retained since=");
    let mut frontend = frontend_of(daemon.pid());
    for generation in 2..=3 {
        // Long enough for a restarted clock to show.
        std::thread::sleep(Duration::from_millis(300));
        kill_frontend(daemon.pid(), frontend);
        frontend = frontend_after(daemon.pid(), frontend);
        let started = format!("network frontend {generation} started");
        assert!(
            wait_until(Duration::from_secs(10), || {
                let log = daemon.log();
                log.rfind(&started)
                    .is_some_and(|at| log[at..].contains(&kept))
            }),
            "frontend {generation} finds the retained session; log: {}",
            daemon.log()
        );
        assert_eq!(
            logged_number(&daemon.log(), &kept, "since="),
            Some(since),
            "the retention began when it began; log: {}",
            daemon.log()
        );
    }

    let back = Session::come_back(&daemon, token);
    assert_eq!(back.same_shell("kept-65"), shell);
    back.client.close();
    assert!(daemon.stop().success());
}

// ---- the detached `transport-ensure` daemon --------------------------------------

/// `qshd transport-ensure` for `client`'s key: starts the daemon, or adds
/// the key to the running one (`ADD-CLIENT`). Returns the server's key.
fn ensure(home: &Path, port: u16, mark: &str, client: &[u8; 32]) -> [u8; 32] {
    let output = Command::new(env!("CARGO_BIN_EXE_qshd"))
        .args([
            "transport-ensure",
            "--name",
            "frontend-replacement",
            "--port",
            &port.to_string(),
            "--client-pubkey",
            &BASE64.encode(client),
        ])
        .env("XDG_CACHE_HOME", home)
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home)
        .env(MARK_ENV, mark)
        .env("HISTFILE", "/dev/null")
        .env("SHELL", "/bin/sh")
        .stdin(Stdio::null())
        .output()
        .expect("`qshd transport-ensure` runs");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains("TRANSPORT-READY "),
        "transport-ensure: {stdout} {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let encoded = stdout
        .lines()
        .find_map(|line| line.strip_prefix("server-pubkey: "))
        .expect("a server-pubkey line");
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&BASE64.decode(encoded.trim()).expect("base64 key"));
    server_pub
}

fn status(sock: &Path) -> Option<qshd::control::StatusResponse> {
    match client_request(sock, &ControlRequest::Status) {
        Ok(ControlReply::Answered(line)) => qshd::control::StatusResponse::from_line(&line).ok(),
        _ => None,
    }
}

/// The allowlist is the host's. A key `ADD-CLIENT` added is still admitted
/// by the frontend that replaces the one that was running when it was
/// added; a key added after the replacement is admitted too; and the
/// control socket answers `STATUS` with the same daemon all along, also
/// while no frontend runs. On this daemon path as well, a session outlives
/// its frontend (same shell after a warm return) and a stop reaps it.
#[test]
fn allowlist_added_client_still_admitted_after_frontend_restart() {
    let _serial = serialised();
    let home = private_temp_home();
    let sock = home.path().join("qsh").join("control.sock");
    let port = free_udp_port();
    let mark = new_daemon_mark();
    let (first, added, later) = (generate_keypair(), generate_keypair(), generate_keypair());

    let server_pub = ensure(home.path(), port, &mark, &first.public);
    let guard = DaemonGuard::new(sock.clone());
    let host = status(&sock).expect("the daemon answers STATUS").pid;
    let frontend = frontend_of(host);

    // A second client's key, added to the running daemon.
    assert_eq!(ensure(home.path(), port, &mark, &added.public), server_pub);
    assert_eq!(status(&sock).map(|s| s.pid), Some(host), "the same daemon");

    kill_frontend(host, frontend);
    assert_eq!(
        status(&sock).map(|s| s.pid),
        Some(host),
        "the host answers STATUS with its frontend dead"
    );
    let next = frontend_after(host, frontend);

    let session = Session::start(
        port,
        server_pub,
        Proof::Allowlisted(added.private),
        [66; 16],
        StartKind::Cold,
    )
    .expect("the key added before the frontend died is admitted by the next one");
    let shell = session.open_shell("kept-66");
    let owner = owner_of(shell, host);

    // A third key, added now: the running frontend hears of it.
    assert_eq!(ensure(home.path(), port, &mark, &later.public), server_pub);
    let third = Session::start(
        port,
        server_pub,
        Proof::Allowlisted(later.private),
        [67; 16],
        StartKind::Cold,
    )
    .expect("a key added after the restart is admitted");
    third.client.close();

    // A stranger's key is still refused, by this frontend as by the first.
    assert!(
        Session::start_within(
            port,
            server_pub,
            Proof::Allowlisted(generate_keypair().private),
            [68; 16],
            StartKind::Cold,
            Duration::from_secs(3),
        )
        .is_none(),
        "a key nobody added is not admitted"
    );
    assert_eq!(frontends_of(host), [next]);
    assert!(status(&sock).is_some());

    // This daemon keeps its sessions across a frontend death too: the
    // allowlisted client's warm return lands in the same shell.
    kill_frontend(host, next);
    frontend_after(host, next);
    session.client.detach();
    let back = Session::start(
        port,
        server_pub,
        Proof::Allowlisted(added.private),
        [66; 16],
        StartKind::Warm,
    )
    .expect("the warm return through the next frontend");
    assert_eq!(back.same_shell("kept-66"), shell, "the same shell answers");
    assert_eq!(owner_of(shell, host), owner, "under the same owner");

    // `STOP` with the session still open ends it: shell and owner reaped.
    back.client.detach();
    drop(guard);
    assert!(
        wait_until(Duration::from_secs(20), || reaped(shell) && reaped(owner)),
        "the daemon's stop reaps the session it kept"
    );
    assert_no_child_left(&mark);
}

/// The host owns the allowlist: when it ends a session itself -- here its
/// owner dies while no frontend that knew the session runs -- it scrubs the
/// key that session's client proved, as a router does at a session's end,
/// and the running frontend refuses that key from then on. Also for a
/// session created fresh, whose key its router reports ahead of the
/// `Create`.
#[test]
fn a_session_the_host_ends_takes_its_key_with_it() {
    let _serial = serialised();
    let home = private_temp_home();
    let sock = home.path().join("qsh").join("control.sock");
    let port = free_udp_port();
    let mark = new_daemon_mark();
    let (first, kept, later) = (generate_keypair(), generate_keypair(), generate_keypair());

    let server_pub = ensure(home.path(), port, &mark, &first.public);
    let guard = DaemonGuard::new(sock.clone());
    let host = status(&sock).expect("the daemon answers STATUS").pid;
    assert_eq!(ensure(home.path(), port, &mark, &kept.public), server_pub);
    let session = Session::start(
        port,
        server_pub,
        Proof::Allowlisted(kept.private),
        [70; 16],
        StartKind::Cold,
    )
    .expect("a fresh session under the added key");
    let shell = session.open_shell("kept-70");
    let owner = owner_of(shell, host);

    // Its frontend dies: no router knows the session any more.
    let frontend = frontend_of(host);
    kill_frontend(host, frontend);
    let next = frontend_after(host, frontend);
    session.client.detach();

    // The session ends at the host: its owner dies.
    assert_eq!(role_of(owner).as_deref(), Some(OWNER_ROLE));
    assert_eq!(ppid(owner), Some(host));
    assert_eq!(unsafe { libc::kill(owner as i32, libc::SIGKILL) }, 0);
    assert!(
        wait_until(Duration::from_secs(10), || reaped(owner)),
        "the host reaps the owner"
    );

    assert!(
        Session::start_within(
            port,
            server_pub,
            Proof::Allowlisted(kept.private),
            [71; 16],
            StartKind::Cold,
            Duration::from_secs(3),
        )
        .is_none(),
        "the key of the session the host ended is scrubbed"
    );
    // The frontend serves all the same: a key added now is admitted.
    assert_eq!(ensure(home.path(), port, &mark, &later.public), server_pub);
    let other = Session::start(
        port,
        server_pub,
        Proof::Allowlisted(later.private),
        [72; 16],
        StartKind::Cold,
    )
    .expect("a key added now is admitted");
    other.client.close();
    assert_eq!(frontends_of(host), [next]);

    drop(guard);
    assert_no_child_left(&mark);
}
