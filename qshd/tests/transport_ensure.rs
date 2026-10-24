//! Local integration test for `transport-ensure` daemonization: runs the
//! REAL `qshd transport-ensure` executable (built by
//! this same `cargo test`, path -- `env!("CARGO_BIN_EXE_qshd")`) in a
//! temporary cache directory and checks:
//!
//! - the parent prints EXACTLY two protocol lines (`server-pubkey:` +
//!   `TRANSPORT-READY`) and exits successfully before the detached daemon
//!   even opens its first channel (the lines are printed in the parent,
//!   before the fork);
//! - the control socket `control.sock` is created with exactly 0600
//!   permissions;
//! - a second invocation with a DIFFERENT `--client-pubkey` on the same
//!   port reuses the live daemon via `ADD-CLIENT` (same `server-pubkey`,
//!   no second process), rather than failing with "port in use".
//!
//! The client Noise key's allowlist is IN-MEMORY ONLY (an earlier version
//! retired the on-disk `transport_clients.json`), so it is
//! not independently checkable from outside the daemon process by these
//! black-box tests; `--client-pubkey` parsing/plumbing is covered by the
//! unit tests in `src/main.rs` and `src/transport_daemon.rs` instead.
//!
//! None of these checks need `tmux`: the daemon hands out channels and does
//! not drive tmux itself (what a client puts in a channel is its own
//! business), so the detached daemon comes all the way up -- and answers
//! `STATUS` on the control socket -- without it.

use std::io::{BufRead, BufReader, Read};
use std::net::UdpSocket;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use qshd::control::{client_request, ControlReply, ControlRequest};

mod daemon_guard;
use daemon_guard::{DaemonGuard, DAEMON_STATUS_TIMEOUT};

/// Serialises the tests in this file. Each of them spawns a REAL daemon that
/// binds a REAL port chosen by `free_udp_port`, which picks its number by
/// binding an ephemeral port and closing it again -- so the number is only a
/// hint, free at the moment it was read and claimable by anyone until the
/// daemon binds it. Run concurrently, two of these tests can be handed the
/// same number, and the loser's daemon exits with "port already in use"
/// while its parent prints nothing: the failure surfaces as an empty first
/// line of stdout, far from its cause. The window widens with anything that
/// slows the spawn, so this was always a latent flake rather than a new one.
/// A file-local lock costs a few seconds of wall clock and removes the whole
/// class.
///
/// Poisoning is tolerated on purpose: one failing test should report its own
/// failure, not turn every sibling into a panic about a poisoned lock.
static ONE_DAEMON_AT_A_TIME: Mutex<()> = Mutex::new(());

// Host-key parents must be private even when the test runner uses umask 0002.
fn private_temp_home() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

fn serialised() -> std::sync::MutexGuard<'static, ()> {
    ONE_DAEMON_AT_A_TIME
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Picks a free UDP port: binds to an ephemeral port and immediately closes
/// the socket, handing the number back to the caller. The number is a hint,
/// not a reservation -- see [`ONE_DAEMON_AT_A_TIME`] for why that matters.
fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("binding an ephemeral port to pick a free number")
        .local_addr()
        .expect("local address of the bound socket")
        .port()
}

/// One `transport-ensure` run and everything it printed.
struct EnsureRun {
    server_pubkey: String,
    /// The JSON after `TRANSPORT-READY `.
    ready: serde_json::Value,
    status: std::process::ExitStatus,
    stderr: String,
}

/// Launches `qshd transport-ensure ...` with an isolated `XDG_CACHE_HOME`
/// (so it doesn't pollute the shared cache), reads the `server-pubkey:` and
/// `TRANSPORT-READY` lines from stdout, and waits for the parent process to
/// exit. `extra_args` are appended after `--client-pubkey`.
fn spawn_transport_ensure_with(
    home: &std::path::Path,
    name: &str,
    port: u16,
    client_pubkey_b64: &str,
    extra_args: &[&str],
) -> EnsureRun {
    let bin = env!("CARGO_BIN_EXE_qshd");
    let mut child: Child = Command::new(bin)
        .args([
            "transport-ensure",
            "--name",
            name,
            "--port",
            &port.to_string(),
            "--client-pubkey",
            client_pubkey_b64,
        ])
        .args(extra_args)
        .env("XDG_CACHE_HOME", home)
        // The daemon opens a real login shell in a pseudo-terminal, and this test types
        // probe commands into it. Without this the shell appends every one of them to the
        // history of whoever ran the suite -- these tests do not set HOME, so that is the
        // developer's own `~/.bash_history`.
        .env("HISTFILE", "/dev/null")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("`qshd transport-ensure` process spawns");

    let stdout = child.stdout.take().expect("process stdout captured");
    let mut reader = BufReader::new(stdout);

    let mut line1 = String::new();
    reader
        .read_line(&mut line1)
        .expect("first line (server-pubkey) read from stdout");
    if !line1.starts_with("server-pubkey: ") {
        // An empty line means the child printed nothing and exited -- its
        // reason is on stderr, and without it this assertion sends the reader
        // hunting in the wrong place entirely.
        let mut why = String::new();
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut why);
        }
        panic!("expected a server-pubkey line, got: {line1:?}; process stderr: {why}");
    }
    let server_pubkey = line1
        .trim_start_matches("server-pubkey: ")
        .trim_end()
        .to_string();

    let mut line2 = String::new();
    reader
        .read_line(&mut line2)
        .expect("second line (TRANSPORT-READY) read from stdout");
    assert!(
        line2.starts_with("TRANSPORT-READY "),
        "expected a TRANSPORT-READY line, got: {line2:?}"
    );

    let ready: serde_json::Value =
        serde_json::from_str(line2.trim_start_matches("TRANSPORT-READY ").trim_end())
            .expect("the TRANSPORT-READY body is JSON");

    let status = child
        .wait()
        .expect("the `transport-ensure` wrapper process exited (parent after the fork)");

    // Capture stderr for diagnostics (e.g. the "port in use" message on a
    // reuse failure).
    let mut stderr_text = String::new();
    if let Some(mut se) = child.stderr.take() {
        let _ = se.read_to_string(&mut stderr_text);
    }

    EnsureRun {
        server_pubkey,
        ready,
        status,
        stderr: stderr_text,
    }
}

/// [`spawn_transport_ensure_with`] without extra arguments, as a tuple.
fn spawn_transport_ensure(
    home: &std::path::Path,
    name: &str,
    port: u16,
    client_pubkey_b64: &str,
) -> (String, std::process::ExitStatus, String) {
    let run = spawn_transport_ensure_with(home, name, port, client_pubkey_b64, &[]);
    (run.server_pubkey, run.status, run.stderr)
}

/// Waits until the daemon's control socket starts answering `STATUS` (the
/// daemon in the child doesn't come up instantly: after the fork it still
/// binds the transport socket and starts the control server). Returns `true`
/// if the daemon responded within the allotted time.
fn wait_for_status(sock_path: &std::path::Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(ControlReply::Answered(_)) = client_request(sock_path, &ControlRequest::Status) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// The parent part before the fork does NOT require tmux: both protocol
/// lines are printed, the parent process exits successfully, the control
/// socket is created with 0600 permissions. The client key itself is
/// IN-MEMORY ONLY and not independently checkable
/// from this black-box test -- see the module documentation.
#[test]
fn transport_ensure_prints_ready_and_creates_socket() {
    let _serial = serialised();
    let home = private_temp_home().expect("temp dir for XDG_CACHE_HOME is created");
    let cache_dir = home.path().join("qsh");
    let sock_path = cache_dir.join("control.sock");
    let _daemon = DaemonGuard::new(sock_path.clone());

    let port = free_udp_port();
    let client_pubkey = [7u8; 32];
    let b64 = BASE64.encode(client_pubkey);

    let (server_pubkey, status, stderr_text) =
        spawn_transport_ensure(home.path(), "s5-ready", port, &b64);
    assert!(
        status.success(),
        "the `transport-ensure` wrapper process must exit successfully, \
         got {status:?}; stderr: {stderr_text}"
    );
    assert!(!server_pubkey.is_empty(), "server-pubkey must not be empty");

    // The control socket is created by the parent BEFORE the fork -- the file already exists, 0600 permissions.
    assert!(
        sock_path.exists(),
        "control.sock must be created by the parent before the fork"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&sock_path)
            .expect("control.sock metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "expected exactly 0600 permissions");
    }
}

/// The full reuse scenario: the first invocation brings up the daemon; a
/// second invocation with a DIFFERENT `--client-pubkey` on the same port
/// reuses the live daemon -- prints the SAME `server-pubkey` and exits
/// successfully (rather than failing with "port in use", which would happen
/// if it tried to bring up a second daemon). The second key reaches the
/// daemon via the live `ADD-CLIENT` request; both keys' effect on the
/// (IN-MEMORY ONLY) allowlist is not independently
/// checkable from this black-box test -- see the module documentation.
#[test]
fn transport_ensure_second_invocation_reuses_live_daemon() {
    let _serial = serialised();
    let home = private_temp_home().expect("temp dir for XDG_CACHE_HOME is created");
    let cache_dir = home.path().join("qsh");
    let sock_path = cache_dir.join("control.sock");
    let _daemon = DaemonGuard::new(sock_path.clone());

    let port = free_udp_port();
    let key_a = [1u8; 32];
    let key_b = [2u8; 32];
    let b64_a = BASE64.encode(key_a);
    let b64_b = BASE64.encode(key_b);

    // First invocation -- brings up the daemon.
    let (server_pubkey_1, status_1, stderr_1) =
        spawn_transport_ensure(home.path(), "s5-reuse", port, &b64_a);
    assert!(
        status_1.success(),
        "the first transport-ensure must exit successfully; stderr: {stderr_1}"
    );

    // Wait for the detached daemon to come up and start answering STATUS.
    assert!(
        wait_for_status(&sock_path, DAEMON_STATUS_TIMEOUT),
        "the daemon must come up and answer STATUS over the control socket"
    );

    // Second invocation with a DIFFERENT key on the same port -- reuse of the live daemon.
    let (server_pubkey_2, status_2, stderr_2) =
        spawn_transport_ensure(home.path(), "s5-reuse", port, &b64_b);
    assert!(
        status_2.success(),
        "the second transport-ensure (reuse) must exit successfully, not fail \
         with \"port in use\"; stderr: {stderr_2}"
    );

    // Same server key -- the daemon was reused (not brought up again with a
    // new key; the important part is that reuse did not fork).
    assert_eq!(
        server_pubkey_1, server_pubkey_2,
        "server-pubkey must match between the first run and the reuse"
    );

    // Still a single live daemon (reuse did not fork a second one) -- STATUS responds.
    assert!(
        wait_for_status(&sock_path, DAEMON_STATUS_TIMEOUT),
        "the daemon must keep answering STATUS after reuse"
    );

    // Stopping it for real: the socket goes with the daemon.
    drop(_daemon);
    assert!(
        !sock_path.exists(),
        "the stopped daemon removes its control socket"
    );
}

/// Owns the fake busy daemon until its worker has been joined.
struct BusyControlSocket {
    release: Option<std::sync::mpsc::Sender<()>>,
    worker: Option<std::thread::JoinHandle<()>>,
    accepted: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl BusyControlSocket {
    fn bind(path: &std::path::Path) -> Self {
        let listener = std::os::unix::net::UnixListener::bind(path)
            .expect("binding the test busy control socket");
        listener
            .set_nonblocking(true)
            .expect("nonblocking test listener");
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_accepted = accepted.clone();
        let (release, cancelled) = std::sync::mpsc::channel::<()>();
        let worker = std::thread::spawn(move || {
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        // Disconnection cancels even if no client ever connects.
                        if cancelled.recv_timeout(Duration::from_millis(10))
                            != Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                        {
                            return;
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => panic!("accepting the control connection: {error}"),
                }
            };
            worker_accepted.store(true, std::sync::atomic::Ordering::SeqCst);
            // Hold the accepted stream until the command's outcome is observed.
            let _ = cancelled.recv();
            drop(stream);
        });
        Self {
            release: Some(release),
            worker: Some(worker),
            accepted,
        }
    }

    fn finish(&mut self) -> std::thread::Result<()> {
        self.release.take();
        self.worker.take().map_or(Ok(()), |worker| worker.join())
    }
}

impl Drop for BusyControlSocket {
    fn drop(&mut self) {
        let result = self.finish();
        // A worker failure must not replace the command's original panic.
        if !std::thread::panicking() {
            result.expect("the test busy daemon thread does not panic");
        }
    }
}

#[test]
fn busy_control_fixture_joins_after_command_exits_before_connecting() {
    use std::os::unix::net::UnixStream;
    let home = private_temp_home().unwrap();
    let cache_dir = home.path().join("qsh");
    std::fs::create_dir(&cache_dir).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cache_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    let sock_path = cache_dir.join("control.sock");
    let worker_path = sock_path.clone();
    let worker_home = home.path().to_owned();
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let supervisor = std::thread::spawn(move || {
        let busy = BusyControlSocket::bind(&worker_path);
        let accepted = busy.accepted.clone();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _busy = busy;
            let output = Command::new(env!("CARGO_BIN_EXE_qshd"))
                .args(["transport-ensure", "--client-pubkey", "invalid-key"])
                .env("HOME", &worker_home)
                .env("XDG_CONFIG_HOME", &worker_home)
                .env("XDG_CACHE_HOME", &worker_home)
                .env("HISTFILE", "/dev/null")
                .output()
                .expect("early-exit command spawns and is reaped");
            assert!(!output.status.success());
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("--client-pubkey: expected valid base64"),
                "{stderr}"
            );
            panic!("original command failure: {stderr}");
        }));
        assert!(
            !accepted.load(std::sync::atomic::Ordering::SeqCst),
            "invalid-key command must exit before connecting"
        );
        completed_tx.send(result).unwrap();
    });
    let completion = completed_rx.recv_timeout(Duration::from_secs(2));
    if completion.is_err() {
        // Reap even the broken blocking-accept implementation on a RED run.
        let rescue = UnixStream::connect(&sock_path);
        let joined = supervisor.join();
        panic!("busy listener did not cancel before accept; rescue: {rescue:?}; supervisor: {joined:?}");
    }
    supervisor.join().unwrap();
    let panic = completion
        .unwrap()
        .expect_err("original command failure must survive cleanup");
    let diagnostic = panic
        .downcast_ref::<String>()
        .expect("string panic diagnostic");
    assert!(
        diagnostic.contains("original command failure:"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("--client-pubkey: expected valid base64"),
        "{diagnostic}"
    );
}

/// A control socket that ACCEPTS a connection and then never answers looks
/// exactly like the diagnosed bug's scenario: a live daemon whose `STATUS`
/// handler is busy (e.g. hashing its own executable under load), not an
/// absent one. `transport-ensure` must not read that timeout as "no
/// daemon" and go bind a port.
///
/// This test proves BOTH halves at once by pre-occupying the port
/// `transport-ensure` would try to bind if (bug) it mistook the timeout
/// for "no daemon": if it attempted that bind despite the timeout, it
/// would collide with our pre-bound socket and fail with the OLD, WRONG
/// "port in use, probably an old-version daemon" message. The fix must
/// never reach that bind at all, so the process instead fails fast with a
/// NEW, honest message about the control socket being busy -- proving both
/// "does not attempt to bind on a timeout" and "says what actually
/// happened" in one process run, with no tmux dependency (the process
/// never gets far enough to need it).
#[test]
fn transport_ensure_timeout_does_not_start_a_second_daemon() {
    use std::os::unix::fs::DirBuilderExt;
    let _serial = serialised();
    let home = private_temp_home().expect("temp dir for XDG_CACHE_HOME is created");
    let cache_dir = home.path().join("qsh");
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&cache_dir)
        .expect("cache directory is created ahead of time to hold control.sock");
    let sock_path = cache_dir.join("control.sock");

    // A "daemon" that accepts the connection but is too busy to answer --
    // the diagnosed scenario, not "nothing is listening".
    let mut busy_daemon = BusyControlSocket::bind(&sock_path);

    // Pre-occupy the port `transport-ensure` would try to bind if it
    // mistook the timeout for "no daemon".
    let port = free_udp_port();
    let _port_guard = UdpSocket::bind(("0.0.0.0", port))
        .expect("holding the port ahead of time to check the behavior");

    let bin = env!("CARGO_BIN_EXE_qshd");
    let client_pubkey = [3u8; 32];
    let b64 = BASE64.encode(client_pubkey);
    let output = Command::new(bin)
        .args([
            "transport-ensure",
            "--name",
            "s5-timeout",
            "--port",
            &port.to_string(),
            "--client-pubkey",
            &b64,
        ])
        .env("XDG_CACHE_HOME", home.path())
        .env("TMUX_TMPDIR", home.path())
        .output()
        .expect("`qshd transport-ensure` process spawns");

    let cleanup = busy_daemon.finish();
    assert!(
        cleanup.is_ok(),
        "busy daemon cleanup failed; command status: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        busy_daemon
            .accepted
            .load(std::sync::atomic::Ordering::SeqCst),
        "busy-socket regression must accept the real control connection; status: {}; stderr: {}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        !output.status.success(),
        "transport-ensure must fail when the control socket is busy and does not \
         answer in time, not silently succeed or fail for a different reason"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("old-version daemon"),
        "must not blame a nonexistent old-version daemon -- the socket is held by a \
         live process, not silent; stderr: {stderr}"
    );
    assert!(
        stderr.contains("did not answer"),
        "must honestly report that the control socket is busy and did not answer in \
         time; stderr: {stderr}"
    );
}

/// A daemon already listens on one port; a second call asks for another.
/// The answer names the port the daemon is on, not the one asked for:
/// a client told the asked port would knock on a door nobody opens.
#[test]
fn transport_ensure_reports_the_port_the_live_daemon_listens_on() {
    let _guard = serialised();
    let home = private_temp_home().unwrap();
    let sock = home.path().join("qsh").join("control.sock");
    let _daemon = DaemonGuard::new(sock.clone());
    let key = BASE64.encode([7u8; 32]);
    let first = free_udp_port();
    let run = spawn_transport_ensure_with(home.path(), "t", first, &key, &[]);
    assert!(run.status.success(), "{}", run.stderr);
    assert!(wait_for_status(&sock, DAEMON_STATUS_TIMEOUT));
    let mut second = free_udp_port();
    while second == first {
        second = free_udp_port();
    }
    let again = spawn_transport_ensure_with(home.path(), "t", second, &key, &[]);
    assert_eq!(
        again.ready["ports"],
        serde_json::json!([first]),
        "{}",
        again.stderr
    );
}

/// A fresh daemon binds exactly `--port`; `--default-port` is parsed and
/// not bound, so it is not reported either.
#[test]
fn a_fresh_daemon_reports_only_the_port_it_bound() {
    let _guard = serialised();
    let home = private_temp_home().unwrap();
    let sock = home.path().join("qsh").join("control.sock");
    let _daemon = DaemonGuard::new(sock.clone());
    let port = free_udp_port();
    let other = if port == 65535 { port - 1 } else { port + 1 };
    let run = spawn_transport_ensure_with(
        home.path(),
        "t",
        port,
        &BASE64.encode([8u8; 32]),
        &["--default-port", &other.to_string()],
    );
    assert_eq!(
        run.ready["ports"],
        serde_json::json!([port]),
        "{}",
        run.stderr
    );
}
