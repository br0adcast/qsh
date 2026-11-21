//! What the end-to-end tests of a hosted personal daemon (#529) share:
//! `frontend_replacement.rs` (M1, the frontend dies) and
//! `frontend_upgrade.rs` (M2, the frontend is replaced by a newer image).
//! Free ports under a file-local lock, the process tree read from `/proc`,
//! the mark that finds a daemon's leaked children, and a signed client
//! with one shell channel.
//!
//! Compiled once per test binary that declares `mod hosted_daemon;`; each
//! uses only part of it.
#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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

pub const OWNER_ROLE: &str = "__qshd-session-owner-v1";
pub const FRONTEND_ROLE: &str = "__qshd-frontend-v1";

pub static ONE_DAEMON_AT_A_TIME: Mutex<()> = Mutex::new(());

pub fn serialised() -> std::sync::MutexGuard<'static, ()> {
    ONE_DAEMON_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn private_temp_home() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("temp dir")
}

pub fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .and_then(|s| s.local_addr())
        .expect("an ephemeral port")
        .port()
}

pub fn wait_until(within: Duration, mut probe: impl FnMut() -> bool) -> bool {
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
pub fn ppid(pid: u32) -> Option<u32> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    status
        .lines()
        .find_map(|line| line.strip_prefix("PPid:"))
        .and_then(|v| v.trim().parse().ok())
}

/// A process exists and has not exited: not gone, not a zombie.
pub fn running(pid: u32) -> bool {
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
pub fn reaped(pid: u32) -> bool {
    !Path::new(&format!("/proc/{pid}")).exists()
}

pub fn role_of(pid: u32) -> Option<String> {
    let cmdline = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let role = cmdline.split(|b| *b == 0).nth(1)?;
    Some(String::from_utf8_lossy(role).into_owned())
}

pub fn pids() -> Vec<u32> {
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
pub fn frontends_of(host: u32) -> Vec<u32> {
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
pub fn frontend_of(host: u32) -> u32 {
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
pub fn kill_frontend(host: u32, pid: u32) {
    assert_eq!(
        (ppid(pid), role_of(pid).as_deref()),
        (Some(host), Some(FRONTEND_ROLE)),
        "pid {pid} is the daemon's frontend"
    );
    assert_eq!(unsafe { libc::kill(pid as i32, libc::SIGKILL) }, 0);
}

/// The frontend that replaces `old`, waited for.
pub fn frontend_after(host: u32, old: u32) -> u32 {
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
pub const MARK_ENV: &str = "QSHD_TEST_DAEMON_MARK";

pub fn new_daemon_mark() -> String {
    static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
    format!(
        "fr-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    )
}

/// Running processes in the owner or the frontend role started under `mark`.
pub fn children_marked(mark: &str) -> Vec<(u32, String)> {
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
pub fn assert_no_child_left(mark: &str) {
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

pub fn write_key(dir: &Path) -> (PrivateKey, PathBuf) {
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

pub struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

#[derive(Default)]
pub struct Collected {
    pub control: Vec<ServerRecord>,
    pub shell: Vec<u8>,
    pub live: bool,
}

pub struct Events {
    pub control: Mutex<RecordDeframer>,
    pub shell: Mutex<ShellDeframer>,
    pub collected: Mutex<Collected>,
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

pub struct Session {
    pub client: StdClient,
    pub events: Arc<Events>,
}

/// How a client proves itself: with a signature, or with a static key the
/// daemon's allowlist holds.
pub enum Proof<'a> {
    Signature(&'a Path),
    Allowlisted([u8; 32]),
}

impl Session {
    /// `None` if the handshake did not complete in time.
    pub fn start(
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

    pub fn start_within(
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

    pub fn send(&self, line: &str) {
        self.client
            .send_bytes(FIRST_CHANNEL_STREAM, line.as_bytes().to_vec())
            .expect("input admitted");
    }

    pub fn shell_text(&self) -> String {
        String::from_utf8_lossy(&self.events.collected.lock().unwrap().shell).into_owned()
    }

    pub fn sees(&self, needle: &str) -> bool {
        wait_until(Duration::from_secs(15), || {
            self.shell_text().contains(needle)
        })
    }

    /// The pid the shell prints as `<tag><digits>-`, computed by the shell
    /// itself (`$$`): a typed literal would only echo back.
    pub fn said_pid(&self, tag: &str) -> u32 {
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
    pub fn open_shell(&self, marker: &str) -> u32 {
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
    pub fn same_shell(&self, marker: &str) -> u32 {
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
pub fn owner_of(shell: u32, host: u32) -> u32 {
    let owner = ppid(shell).expect("the shell is alive");
    assert_eq!(
        ppid(owner),
        Some(host),
        "the shell's parent is a child of the host"
    );
    assert_eq!(role_of(owner).as_deref(), Some(OWNER_ROLE));
    owner
}

/// The command name of `pid` (`/proc/<pid>/comm`), empty once it is gone.
pub fn comm(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .unwrap_or_default()
        .trim_end()
        .to_string()
}

/// One numbered line of a paste: eight digits and a newline.
pub fn paste_line(n: u32) -> Vec<u8> {
    format!("{n:08}\n").into_bytes()
}

pub fn status(sock: &Path) -> Option<qshd::control::StatusResponse> {
    match client_request(sock, &ControlRequest::Status) {
        Ok(ControlReply::Answered(line)) => qshd::control::StatusResponse::from_line(&line).ok(),
        _ => None,
    }
}

/// The host's children that have exited and are not reaped: zombies.
pub fn zombies_of(host: u32) -> Vec<u32> {
    pids()
        .into_iter()
        .filter(|pid| ppid(*pid) == Some(host) && !running(*pid) && !reaped(*pid))
        .collect()
}

/// The session owners the host `host` runs.
pub fn owners_of(host: u32) -> Vec<u32> {
    pids()
        .into_iter()
        .filter(|pid| {
            ppid(*pid) == Some(host)
                && role_of(*pid).as_deref() == Some(OWNER_ROLE)
                && running(*pid)
        })
        .collect()
}
