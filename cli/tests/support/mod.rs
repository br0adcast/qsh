//! What the console client's end-to-end tests share: a real `qshd serve`
//! on its own temp home, a real `qsh` on a pseudo-terminal that is its
//! controlling terminal, and the waiting helpers around them. Moved here
//! from `pty_session.rs` unchanged in meaning, so `ladder.rs` runs the
//! client exactly the way those tests do.

#![allow(dead_code)]

// Some suites also include the SSH sandbox. Both fixtures share this small
// test-only module without introducing a production dependency.
#[allow(clippy::duplicate_mod)]
#[path = "../../../crates/ssh/tests/support/shell_env.rs"]
pub mod shell_env;

use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::net::UdpSocket;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// These tests each bind a real port picked by "bind an ephemeral one and
/// close it", which is a hint rather than a reservation: run concurrently,
/// two of them can be handed the same number. See the same lock, and the same
/// reasoning, in `qshd/tests/transport_ensure.rs`.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

pub fn serialised() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner())
}

pub fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Waits for `probe` to hold, or gives up. Generous on purpose: a slow
/// machine must make this test slower, never red.
pub fn wait_until(mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// Where `qshd` should be, and builds it if it is not there yet.
///
/// Deviates from a plain `env!("CARGO_BIN_EXE_qshd")`: that macro only
/// exists for binaries of the package under test, and `qshd` is a binary of
/// the `qshd` package (the crate that happens to live in the `qshd/`
/// directory), not of `qsh` -- using it here would not compile. `qsh` and
/// `qshd` still land in the same target directory (this workspace does not
/// give each member its own), so the fix is to look for `qshd` beside the
/// `qsh` binary this test was built with, and build it on demand if it is
/// missing.
///
/// That happens under `cargo test -p qsh`: cargo only builds targets that
/// belong to the selected package, and `qshd` is not one of them. Under
/// `cargo test --workspace`, the `qshd` package is built as part of the
/// workspace and `qshd` is already there, so the on-demand build is a no-op
/// check.
pub fn qshd_path() -> PathBuf {
    let qsh_bin = PathBuf::from(env!("CARGO_BIN_EXE_qsh"));
    let bin_dir = qsh_bin
        .parent()
        .expect("the qsh binary path has a parent directory")
        .to_path_buf();
    let candidate = bin_dir.join("qshd");
    if candidate.is_file() {
        return candidate;
    }

    // Build it now, into the very directory `qsh` itself came from: the
    // parent of `bin_dir` is the shared target directory, and `bin_dir`'s own
    // name (`debug` or `release`) says which profile to match so the two
    // binaries end up side by side.
    let target_dir = bin_dir
        .parent()
        .expect("the target profile directory has a parent (the target directory itself)");
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("`cli` is a direct child of the workspace root");

    // The package living in the `qshd/` directory is named `qshd` in its own
    // `Cargo.toml` (`[package] name = "qshd"`), so `-p qshd` is the specifier
    // that selects it for this on-demand build.
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut build = Command::new(&cargo);
    build
        .args(["build", "-p", "qshd", "--bin", "qshd", "--target-dir"])
        .arg(target_dir)
        .current_dir(workspace_root);
    if bin_dir.file_name().and_then(|n| n.to_str()) == Some("release") {
        build.arg("--release");
    }

    let output = build.output().expect("run cargo to build qshd");
    if !output.status.success() {
        panic!(
            "building qshd on demand failed (status {:?}).\nstdout:\n{}\nstderr:\n{}\n\
             Run `cargo build -p qshd --bin qshd` yourself and re-run this test.",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    if !candidate.is_file() {
        panic!(
            "qshd is still missing at {} after building it. \
             Run `cargo build -p qshd --bin qshd` yourself and re-run this test.",
            candidate.display()
        );
    }
    candidate
}

pub struct Daemon {
    pub child: Child,
    pub port: u16,
    /// Everything the daemon has written to its own stdout and stderr so
    /// far, drained by two background threads started in [`start_daemon`].
    /// A failing assertion should be able to say what the daemon itself
    /// reported (its startup fingerprint, an authentication rejection, a
    /// panic), not just what did or didn't arrive at the client.
    pub output: std::sync::Arc<Mutex<Vec<u8>>>,
    // Never read directly: kept alive so its directory (holding the host key
    // and `authorized_keys` the daemon was started with) is not deleted
    // while the daemon is still running, and so it drops -- deleting that
    // directory -- only after `Drop for Daemon` has killed the daemon above.
    #[allow(dead_code)]
    home: tempfile::TempDir,
    shell: PathBuf,
}

impl Daemon {
    /// Rotate only this test daemon's key; the running process retains its
    /// old key until restart loads a newly generated one.
    pub fn restart_with_new_key(&mut self) {
        std::fs::remove_file(self.home.path().join("host_key")).expect("remove test host key");
        self.restart();
    }

    /// Record real shell starts without changing the daemon's transport behavior.
    pub fn track_shell_starts(&self) {
        use std::os::unix::fs::PermissionsExt;
        let script = self.home.path().join("tracked-shell");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf 'started\\n' >> {}\nexec /bin/sh \"$@\"\n",
                shell_env::quote(&self.home.path().join("shell-starts"))
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    pub fn shell_starts(&self) -> usize {
        std::fs::read_to_string(self.home.path().join("shell-starts"))
            .unwrap_or_default()
            .lines()
            .count()
    }

    /// Everything the daemon has printed (stdout and stderr, interleaved by
    /// arrival) up to this moment. For diagnostics only.
    pub fn output_text(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
    }

    /// Stops this daemon and starts a new one on the same port, with the same host key
    /// and `authorized_keys`: a restarted daemon with no sessions.
    ///
    /// The old process is killed and reaped first, so its UDP port is free
    /// again by the time the new one binds it. What the old one printed stays
    /// at the front of [`Daemon::output`], for diagnostics.
    pub fn restart(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let (child, output) = spawn_serve(self.home.path(), self.port, &self.shell);
        {
            let before = self
                .output
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone();
            let mut now = output.lock().unwrap_or_else(|p| p.into_inner());
            let mut all = before;
            all.extend_from_slice(b"\n--- qshd restarted ---\n");
            all.append(&mut now);
            *now = all;
        }
        self.child = child;
        self.output = output;
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The client process on its pseudo-terminal, and the master side. `Drop`
/// kills and reaps the child even if a test panics before an explicit
/// `wait_for_exit` -- the same shape as `Daemon`, and necessary for the same
/// reason: `std::process::Child`'s own `Drop` neither kills nor reaps, so a
/// panicking assertion between `spawn_client` and `wait_for_exit` would
/// otherwise leave `qsh` running.
pub struct Client {
    pub child: Child,
    pub master: std::fs::File,
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Client {
    /// The client process's OS pid, for sending it a signal directly (e.g.
    /// `SIGSTOP`/`SIGCONT` to simulate the lid closing on a real device).
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Types `line` into the client's pseudo-terminal followed by Enter, the
    /// way a person typing at the keyboard would.
    pub fn type_line(&mut self, line: &str) {
        self.master.write_all(line.as_bytes()).expect("type line");
        self.master.write_all(b"\r").expect("type enter");
    }
}

/// Reads `reader` to EOF on a background thread, appending everything into
/// `sink`. Used to keep a live, lock-guarded copy of a child process's
/// output for failure messages, without the test itself ever blocking on a
/// read.
pub fn drain_into(mut reader: impl Read + Send + 'static, sink: std::sync::Arc<Mutex<Vec<u8>>>) {
    std::thread::spawn(move || {
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => sink
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .extend_from_slice(&buf[..n]),
            }
        }
    });
}

/// A daemon with one authorized key, and the key's path.
pub fn start_daemon() -> (Daemon, std::path::PathBuf) {
    start_daemon_with_shell(Path::new("/bin/sh"))
}

/// Explicit compatibility coverage; generic fixtures always use /bin/sh.
pub fn start_daemon_with_shell(shell: &Path) -> (Daemon, std::path::PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::Builder::new()
        .prefix("qsh shell ' ")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("tempdir");
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .expect("generate");
    let key_path = home.path().join("id_ed25519");
    std::fs::write(
        &key_path,
        key.to_openssh(ssh_key::LineEnding::LF)
            .expect("encode")
            .as_bytes(),
    )
    .expect("write key");

    let authorized = home.path().join("authorized_keys");
    std::fs::write(
        &authorized,
        format!("{}\n", key.public_key().to_openssh().expect("openssh")),
    )
    .expect("write authorized_keys");

    let port = free_udp_port();
    let (child, output) = spawn_serve(home.path(), port, shell);

    let daemon = Daemon {
        child,
        port,
        output,
        home,
        shell: shell.to_path_buf(),
    };
    // Spawning is not readiness: an explicit refusal now ends discovery
    // immediately, so do not race the daemon's first socket bind.
    assert!(
        wait_until(|| sshauth::discover::discover(
            ([127, 0, 0, 1], port).into(),
            Duration::from_millis(100),
        )
        .is_ok()),
        "daemon did not become ready: {}",
        daemon.output_text()
    );
    (daemon, key_path)
}

/// `qshd serve` on `port`, with the host key and `authorized_keys` in
/// `home`, and everything it prints drained into the returned buffer.
fn spawn_serve(home: &Path, port: u16, shell: &Path) -> (Child, std::sync::Arc<Mutex<Vec<u8>>>) {
    let mut command = Command::new(qshd_path());
    let tracked_shell = home.join("tracked-shell");
    let shell = if tracked_shell.exists() {
        &tracked_shell
    } else {
        shell
    };
    command.envs(shell_env::prepare(home, shell));
    let mut child = command
        .args([
            "serve",
            "--port",
            &port.to_string(),
            "--authorized-keys",
            home.join("authorized_keys").to_str().expect("utf-8"),
            "--host-key",
            home.join("host_key").to_str().expect("utf-8"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qshd serve");

    let output = std::sync::Arc::new(Mutex::new(Vec::new()));
    drain_into(child.stdout.take().expect("piped stdout"), output.clone());
    drain_into(child.stderr.take().expect("piped stderr"), output.clone());
    (child, output)
}

/// Runs `qsh` on a pseudo-terminal and hands back the client, on its own
/// `Drop` guard (see [`Client`]).
pub fn spawn_client(
    daemon: &Daemon,
    key_path: &std::path::Path,
    config_home: &std::path::Path,
) -> Client {
    spawn_client_with(daemon, key_path, config_home, &[])
}

/// [`spawn_client`], with `extra` flags before the host.
pub fn spawn_client_with(
    daemon: &Daemon,
    key_path: &std::path::Path,
    config_home: &std::path::Path,
    extra: &[&str],
) -> Client {
    let port = daemon.port.to_string();
    let mut args = vec![
        "--port",
        port.as_str(),
        "-i",
        key_path.to_str().expect("utf-8"),
    ];
    args.extend_from_slice(extra);
    args.push("127.0.0.1");
    spawn_qsh(&args, config_home)
}

/// Runs `qsh args` on a fresh 80x24 pseudo-terminal that is its controlling
/// terminal, with `config_home` as its `HOME`, `XDG_CONFIG_HOME` and
/// `XDG_CACHE_HOME` and no `SSH_AUTH_SOCK`: nothing of the developer's own
/// `~/.ssh`, agent or `~/.cache/qsh` is within its reach.
pub fn spawn_qsh(args: &[&str], config_home: &std::path::Path) -> Client {
    spawn_qsh_on(args, config_home).0
}

/// [`spawn_qsh`], and the test's own descriptor of the pseudo-terminal's
/// slave side: its settings can be read after the client is gone.
pub fn spawn_qsh_on(
    args: &[&str],
    config_home: &std::path::Path,
) -> (Client, std::os::fd::OwnedFd) {
    let args: Vec<OsString> = args.iter().map(OsString::from).collect();
    spawn_qsh_os_on(&args, config_home, None)
}

/// Runs OS arguments without changing path bytes, using the same PTY lifecycle.
pub fn spawn_qsh_os(args: &[OsString], config_home: &Path) -> Client {
    spawn_qsh_os_on(args, config_home, None).0
}

/// OS-aware PTY spawn, with an optional executable name for argv[0] tests.
pub fn spawn_qsh_os_on(
    args: &[OsString],
    config_home: &Path,
    argv0: Option<&OsStr>,
) -> (Client, std::os::fd::OwnedFd) {
    spawn_qsh_os_at(args, config_home, argv0, 80, 24)
}

/// Start at the requested physical dimensions before the client opens its shell.
pub fn spawn_qsh_os_at(
    args: &[OsString],
    config_home: &Path,
    argv0: Option<&OsStr>,
    cols: u16,
    rows: u16,
) -> (Client, std::os::fd::OwnedFd) {
    let pty = nix::pty::openpty(
        Some(&nix::pty::Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )
    .expect("openpty");

    let slave = pty.slave;
    let mut command = Command::new(env!("CARGO_BIN_EXE_qsh"));
    if let Some(argv0) = argv0 {
        command.arg0(argv0);
    }
    command
        .args(args)
        .env_remove("SSH_AUTH_SOCK")
        .env("HOME", config_home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("XDG_CACHE_HOME", config_home)
        .env("TERM", "xterm-256color")
        .env("HISTFILE", "/dev/null")
        // Release checks must fail locally so seeded offline caches are used.
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("https_proxy", "http://127.0.0.1:1")
        .env("NO_PROXY", "")
        .env("no_proxy", "")
        .stdin(Stdio::from(slave.try_clone().expect("clone")))
        .stdout(Stdio::from(slave.try_clone().expect("clone")))
        .stderr(Stdio::from(slave.try_clone().expect("clone")));
    make_it_the_controlling_terminal(&mut command);
    let child = command.spawn().expect("spawn qsh");

    let master = std::fs::File::from(pty.master);
    (Client { child, master }, slave)
}

/// Makes the pseudo-terminal the client's controlling terminal: a new
/// session, then `TIOCSCTTY` on its stdin. Without this `/dev/tty` in the
/// client would be the terminal of whoever runs the tests, and every
/// question the client asks would land there instead of on this PTY.
pub fn make_it_the_controlling_terminal(command: &mut Command) {
    // SAFETY: only async-signal-safe calls between fork and exec.
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::ioctl(0, libc::TIOCSCTTY as _, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

pub fn wait_for_exit(child: &mut Child) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    // Reap it too, not just kill it -- a killed-but-unwaited child is a
    // zombie until something calls `wait` on it.
    let _ = child.kill();
    let _ = child.wait();
    None
}

/// A UDP relay between the client and a daemon: `cut` drops everything both ways
/// (a dead network), `restore` lets it through again.
///
/// Two sockets on `127.0.0.1`: the front one, where the client sends (its
/// port is [`UdpRelay::port`]), and the back one, connected to the daemon.
/// The client's address is whichever one sent last, so a reconnect from a
/// fresh socket is relayed too. The threads read with a short timeout, so
/// they notice `Drop` asking them to stop.
pub struct UdpRelay {
    pub port: u16,
    cut: Arc<AtomicBool>,
    upstream: UdpSocket,
    received: Arc<AtomicUsize>,
    handshakes: Arc<Mutex<std::collections::VecDeque<Instant>>>,
    handshake_only: Arc<AtomicBool>,
    transport_received: Arc<AtomicUsize>,
    next_initiator: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    threads: Vec<std::thread::JoinHandle<()>>,
}

impl UdpRelay {
    pub fn start(target_port: u16) -> UdpRelay {
        let front = UdpSocket::bind(("127.0.0.1", 0)).expect("bind the relay's front");
        let back = UdpSocket::bind(("127.0.0.1", 0)).expect("bind the relay's back");
        back.connect(("127.0.0.1", target_port))
            .expect("connect the relay's back to the daemon");
        for socket in [&front, &back] {
            socket
                .set_read_timeout(Some(Duration::from_millis(100)))
                .expect("read timeout");
        }
        let port = front.local_addr().expect("front addr").port();
        let cut = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let client: Arc<Mutex<Option<std::net::SocketAddr>>> = Arc::new(Mutex::new(None));

        let received = Arc::new(AtomicUsize::new(0));
        let handshakes = Arc::new(Mutex::new(std::collections::VecDeque::new()));
        let handshake_only = Arc::new(AtomicBool::new(false));
        let transport_received = Arc::new(AtomicUsize::new(0));
        let next_initiator = Arc::new(AtomicUsize::new(0));
        let upstream = back.try_clone().expect("clone upstream");
        let forward = {
            let front = front.try_clone().expect("clone front");
            let back = back.try_clone().expect("clone back");
            let (cut, stop, client) = (cut.clone(), stop.clone(), client.clone());
            let received = received.clone();
            let handshakes = handshakes.clone();
            let handshake_only = handshake_only.clone();
            let transport_received = transport_received.clone();
            let next_initiator = next_initiator.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 65536];
                let mut handshake_source = None;
                let mut first_initiator = None;
                while !stop.load(Ordering::SeqCst) {
                    let Ok((n, from)) = front.recv_from(&mut buf) else {
                        continue;
                    };
                    received.fetch_add(1, Ordering::SeqCst);
                    let msg1 = match transport::wire::parse(&buf[..n]) {
                        Ok(transport::wire::Frame::Handshake {
                            kind: transport::wire::Kind::HandshakeInit,
                            body,
                        }) => Some(body),
                        Ok(transport::wire::Frame::Handshake {
                            kind: transport::wire::Kind::HandshakeInitCookie,
                            body,
                        }) => transport::wire::split_cookie_init(body).map(|(_, body)| body),
                        _ => None,
                    };
                    if let Some(body) = msg1 {
                        match next_initiator.load(Ordering::SeqCst) {
                            1 => {
                                first_initiator = Some(body.to_vec());
                                next_initiator.store(2, Ordering::SeqCst);
                            }
                            2 if first_initiator.as_deref() != Some(body) => {
                                handshake_only.store(false, Ordering::SeqCst);
                                next_initiator.store(3, Ordering::SeqCst);
                            }
                            _ => {}
                        }
                    }
                    if matches!(
                        transport::wire::parse(&buf[..n]),
                        Ok(transport::wire::Frame::Handshake {
                            kind: transport::wire::Kind::HandshakeInit
                                | transport::wire::Kind::HandshakeInitCookie,
                            ..
                        })
                    ) {
                        if handshake_only.load(Ordering::SeqCst) {
                            handshake_source = Some(from);
                        }
                        let mut times = handshakes.lock().unwrap_or_else(|p| p.into_inner());
                        if times.len() == 64 {
                            times.pop_front();
                        }
                        times.push_back(Instant::now());
                    }
                    let is_transport = matches!(
                        transport::wire::parse(&buf[..n]),
                        Ok(transport::wire::Frame::Transport { .. })
                    );
                    if is_transport
                        && handshake_only.load(Ordering::SeqCst)
                        && handshake_source == Some(from)
                    {
                        transport_received.fetch_add(1, Ordering::SeqCst);
                    }
                    *client.lock().unwrap_or_else(|p| p.into_inner()) = Some(from);
                    if !cut.load(Ordering::SeqCst)
                        && !(handshake_only.load(Ordering::SeqCst) && is_transport)
                    {
                        let _ = back.send(&buf[..n]);
                    }
                }
            })
        };
        let backward = {
            let (cut, stop) = (cut.clone(), stop.clone());
            let handshake_only = handshake_only.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 65536];
                while !stop.load(Ordering::SeqCst) {
                    let Ok(n) = back.recv(&mut buf) else {
                        continue;
                    };
                    let to = *client.lock().unwrap_or_else(|p| p.into_inner());
                    if let (false, Some(to)) = (cut.load(Ordering::SeqCst), to) {
                        let is_transport = matches!(
                            transport::wire::parse(&buf[..n]),
                            Ok(transport::wire::Frame::Transport { .. })
                        );
                        if handshake_only.load(Ordering::SeqCst) && is_transport {
                            continue;
                        }
                        let _ = front.send_to(&buf[..n], to);
                    }
                }
            })
        };

        UdpRelay {
            port,
            cut,
            upstream,
            received,
            handshakes,
            handshake_only,
            transport_received,
            next_initiator,
            stop,
            threads: vec![forward, backward],
        }
    }

    /// Client datagrams observed, including those dropped by a cut. Encrypted
    /// path probes cannot be distinguished from other authenticated traffic.
    pub fn received(&self) -> usize {
        self.received.load(Ordering::SeqCst)
    }

    /// Bounded observations of actual msg1 sends, without retaining payloads.
    pub fn handshakes(&self) -> Vec<Instant> {
        self.handshakes
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .copied()
            .collect()
    }

    /// Keep real Noise replies but withhold transport proof/acceptance.
    pub fn handshake_only(&self, enabled: bool) {
        self.handshake_only.store(enabled, Ordering::SeqCst);
    }

    /// Keep the first initiator silent at the transport layer, then permit
    /// traffic only after a different actual Noise msg1 is observed. Retained
    /// fixture state is one bounded msg1 body, never a packet history.
    pub fn transport_after_next_initiator(&self) {
        self.handshake_only.store(true, Ordering::SeqCst);
        self.next_initiator.store(1, Ordering::SeqCst);
    }

    pub fn saw_next_initiator(&self) -> bool {
        self.next_initiator.load(Ordering::SeqCst) == 3
    }

    /// Transport from a source that sent msg1 during handshake-only mode.
    /// An old live connection closing cannot satisfy this recovery oracle.
    pub fn transport_received(&self) -> usize {
        self.transport_received.load(Ordering::SeqCst)
    }

    /// Move this test endpoint to another daemon without replacing the relay.
    pub fn redirect(&self, target_port: u16) {
        self.upstream
            .connect(("127.0.0.1", target_port))
            .expect("redirect relay");
    }

    pub fn cut(&self) {
        self.cut.store(true, Ordering::SeqCst);
    }

    pub fn restore(&self) {
        self.cut.store(false, Ordering::SeqCst);
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// The top row of the screen `bytes` draw on a `cols`x`rows` terminal, through the
/// same terminal model the client uses: what a person reads on the plate.
///
/// The renderer repaints only the cells that changed, so a plate's text is
/// not necessarily contiguous in the raw bytes; the model puts it back
/// together.
pub fn top_row(bytes: &[u8], cols: u16, rows: u16) -> String {
    let mut model = terminal::TerminalCore::new(cols, rows);
    model.feed(bytes);
    let frame = model.frame();
    (0..cols).map(|col| frame.cell(0, col).ch).collect()
}
