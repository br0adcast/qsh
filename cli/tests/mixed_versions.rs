//! Published v0.5.0 (protocol 1) versus the current protocol 2, on real PTYs.
//! Opt-in fixtures are the unchanged binaries from the published release:
//! `QSH_OLD_QSH=<v0.5.0 qsh> QSH_OLD_QSHD=<v0.5.0 qshd> cargo test -p qsh --test mixed_versions -- --ignored --nocapture --test-threads=1`
//! Incompatible peers must never start a shell; compatible pairs prove the
//! shell-start counter and real I/O. Current-peer flood/paste coverage stays active.
mod support;

use std::io::{Read, Write};
use std::net::UdpSocket;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// These tests each bind a real port picked by "bind an ephemeral one and
/// close it", which is a hint rather than a reservation: run concurrently,
/// two of them can be handed the same number. See the same lock, and the same
/// reasoning, in `qshd/tests/transport_ensure.rs`.
static ONE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn serialised() -> std::sync::MutexGuard<'static, ()> {
    ONE_AT_A_TIME.lock().unwrap_or_else(|p| p.into_inner())
}

fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("bind an ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

/// Waits for `probe` to hold, or gives up. Generous on purpose: a slow
/// machine must make this test slower, never red.
fn wait_until(probe: impl FnMut() -> bool) -> bool {
    wait_within(Duration::from_secs(20), probe)
}

fn wait_within(timeout: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
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
fn qshd_path() -> PathBuf {
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

struct Daemon {
    child: Child,
    port: u16,
    /// Everything the daemon has written to its own stdout and stderr so
    /// far, drained by two background threads started in [`start_daemon_from`].
    /// A failing assertion should be able to say what the daemon itself
    /// reported (its startup fingerprint, an authentication rejection, a
    /// panic), not just what did or didn't arrive at the client.
    output: std::sync::Arc<Mutex<Vec<u8>>>,
    // Never read directly: kept alive so its directory (holding the host key
    // and `authorized_keys` the daemon was started with) is not deleted
    // while the daemon is still running, and so it drops -- deleting that
    // directory -- only after `Drop for Daemon` has killed the daemon above.
    #[allow(dead_code)]
    home: tempfile::TempDir,
}

impl Daemon {
    /// Everything the daemon has printed (stdout and stderr, interleaved by
    /// arrival) up to this moment. For diagnostics only.
    fn output_text(&self) -> String {
        String::from_utf8_lossy(&self.output.lock().unwrap_or_else(|p| p.into_inner())).into_owned()
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
/// panicking assertion between `spawn_qsh` and `wait_for_exit` would
/// otherwise leave `qsh` running.
struct Client {
    child: Child,
    master: std::fs::File,
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads `reader` to EOF on a background thread, appending everything into
/// `sink`. Used to keep a live, lock-guarded copy of a child process's
/// output for failure messages, without the test itself ever blocking on a
/// read.
fn drain_into(mut reader: impl Read + Send + 'static, sink: std::sync::Arc<Mutex<Vec<u8>>>) {
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

/// A daemon from `qshd` with one authorized key, and the key's path.
fn start_daemon_from(qshd: &Path) -> (Daemon, PathBuf) {
    start_daemon_with_ready_timeout(qshd, Duration::from_secs(20))
}

fn start_daemon_with_ready_timeout(qshd: &Path, timeout: Duration) -> (Daemon, PathBuf) {
    use std::os::unix::fs::PermissionsExt;
    let home = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .expect("tempdir");
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .expect("generate");
    let key_path = home.path().join("id_ed25519");
    support::write_private(
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

    let shell = home.path().join("tracked-shell");
    std::fs::write(
        &shell,
        format!(
            "#!/bin/sh\nprintf 'started\\n' >> '{}'\nexec /bin/sh \"$@\"\n",
            home.path().join("shell-starts").display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&shell, std::fs::Permissions::from_mode(0o700)).unwrap();
    qshd::load_or_create_transport_key(&home.path().join("host_key")).unwrap();
    let port = free_udp_port();
    let mut child = Command::new(qshd)
        .args([
            "serve",
            "--port",
            &port.to_string(),
            "--authorized-keys",
            authorized.to_str().expect("utf-8"),
            "--host-key",
            home.path().join("host_key").to_str().expect("utf-8"),
        ])
        // `qshd serve` spawns `$SHELL` through `portable_pty`, which copies
        // the whole parent environment: without an explicit `HOME` here the
        // spawned shell would be the developer's own real interactive
        // login shell, sourcing their rc files and appending this test's
        // typed commands to their real shell history.
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("HISTFILE", "/dev/null")
        .env("SHELL", &shell)
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn qshd serve");

    let output = std::sync::Arc::new(Mutex::new(Vec::new()));
    drain_into(child.stdout.take().expect("piped stdout"), output.clone());
    drain_into(child.stderr.take().expect("piped stderr"), output.clone());
    let daemon = Daemon {
        child,
        port,
        output,
        home,
    };
    assert!(
        wait_within(timeout, || daemon.output_text().contains("server-pubkey:")),
        "daemon did not bind its port: {}",
        daemon.output_text()
    );
    (daemon, key_path)
}

/// Runs `qsh` (the binary at `qsh`) on a pseudo-terminal, with `extra`
/// flags before the host, and hands back the client on its own `Drop`
/// guard (see [`Client`]).
fn spawn_qsh(
    qsh: &Path,
    daemon: &Daemon,
    key_path: &std::path::Path,
    config_home: &std::path::Path,
    extra: &[&str],
) -> Client {
    spawn_qsh_on_port(qsh, daemon.port, key_path, config_home, extra)
}

fn spawn_qsh_on_port(
    qsh: &Path,
    port: u16,
    key_path: &Path,
    config_home: &Path,
    extra: &[&str],
) -> Client {
    let pty = nix::pty::openpty(
        Some(&nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )
    .expect("openpty");

    let slave = pty.slave;
    let port = port.to_string();
    let mut args = vec![
        "--port",
        port.as_str(),
        "-i",
        key_path.to_str().expect("utf-8"),
    ];
    args.extend_from_slice(extra);
    args.push("127.0.0.1,nossh");
    let mut command = Command::new(qsh);
    command
        .args(&args)
        .env_remove("SSH_AUTH_SOCK")
        .env("HOME", config_home)
        .env("XDG_CONFIG_HOME", config_home)
        .env("XDG_CACHE_HOME", config_home)
        .env("TERM", "xterm-256color")
        .env("HISTFILE", "/dev/null")
        .env_remove("SSH_AGENT_PID")
        .stdin(Stdio::from(slave.try_clone().expect("clone")))
        .stdout(Stdio::from(slave.try_clone().expect("clone")))
        .stderr(Stdio::from(slave.try_clone().expect("clone")));
    make_it_the_controlling_terminal(&mut command);
    let child = command.spawn().expect("spawn qsh");

    drop(slave);
    let master = std::fs::File::from(pty.master);
    Client { child, master }
}

/// Makes the pseudo-terminal the client's controlling terminal: a new
/// session, then `TIOCSCTTY` on its stdin. Without this `/dev/tty` in the
/// client would be the terminal of whoever runs the tests, and every
/// question the client asks would land there instead of on this PTY.
fn make_it_the_controlling_terminal(command: &mut Command) {
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

fn wait_for_exit(child: &mut Child) -> Option<std::process::ExitStatus> {
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

fn old_binary(var: &str) -> PathBuf {
    PathBuf::from(
        std::env::var(var).unwrap_or_else(|_| {
            panic!("{var} names the published v0.5.0 binary (see the module doc)")
        }),
    )
}

fn this_qsh() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_qsh"))
}

fn text(seen: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&seen.lock().expect("seen")).into_owned()
}

/// Longer than `wait_until`: 8 MB of output through a screen channel and a
/// terminal renderer.
fn wait_long(mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// First contact, a signed session, a shell that answers.
fn sign_in(client: &mut Client, seen: &Arc<Mutex<Vec<u8>>>, daemon: &Daemon) {
    assert!(
        wait_until(|| text(seen).contains("Key fingerprint")),
        "client saw: {}\ndaemon: {}",
        text(seen),
        daemon.output_text()
    );
    client.master.write_all(b"yes\n").expect("answer");
    client
        .master
        .write_all(b"echo mixed-$((6*7))\n")
        .expect("type");
    assert!(
        wait_until(|| text(seen).contains("mixed-42")),
        "client saw: {}\ndaemon: {}",
        text(seen),
        daemon.output_text()
    );
}

/// `seq` writes ~8.3 MB, then Ctrl-C on a producer that never stops. The
/// console client's channel is a screen channel: the daemon collapses what
/// the gate holds back into repaints, so far less than 8 MB crosses the
/// wire. What this shows is a screen that keeps up with a flood and a
/// Ctrl-C that gets through it, not bulk transfer -- that is
/// `serve_sends_a_command_channel_in_full_with_the_header_under_aead` in
/// `qshd/tests/serve_channels.rs`.
fn follow_8_mb_of_output_as_repaints_and_interrupt(
    client: &mut Client,
    seen: &Arc<Mutex<Vec<u8>>>,
    daemon: &Daemon,
) {
    client
        .master
        .write_all(b"seq 1 1200000; echo seq-done-$((40+2))\n")
        .expect("type");
    assert!(
        wait_long(|| text(seen).contains("seq-done-42")),
        "daemon: {}",
        daemon.output_text()
    );
    client.master.write_all(b"yes\n").expect("type");
    std::thread::sleep(Duration::from_millis(500));
    client.master.write_all(b"\x03").expect("Ctrl-C");
    client
        .master
        .write_all(b"echo after-$((3*3))\n")
        .expect("type");
    assert!(
        wait_until(|| text(seen).contains("after-9")),
        "Ctrl-C stops the output; daemon: {}",
        daemon.output_text()
    );
}

/// A 1 MiB paste into a remote process that reads it raw and counts it:
/// what a terminal client does when someone pastes a file. The markers are
/// computed by the remote shell, so the echo of the typed line cannot match
/// them.
fn paste_a_megabyte(client: &mut Client, seen: &Arc<Mutex<Vec<u8>>>, daemon: &Daemon) {
    client
        .master
        .write_all(
            b"stty raw -echo; echo ready-$((6*7)); echo got-$(head -c 1048576 | wc -c); stty sane\n",
        )
        .expect("type");
    assert!(
        wait_until(|| text(seen).contains("ready-42")),
        "daemon: {}",
        daemon.output_text()
    );
    client
        .master
        .write_all(&vec![b'p'; 1 << 20])
        .expect("paste");
    assert!(
        wait_long(|| text(seen).contains("got-1048576")),
        "the whole paste arrived; daemon: {}",
        daemon.output_text()
    );
}

fn leave(mut client: Client) {
    client.master.write_all(b"exit\n").expect("type exit");
    assert_eq!(
        wait_for_exit(&mut client.child)
            .expect("client exits")
            .code(),
        Some(0)
    );
}

fn shell_starts(daemon: &Daemon) -> usize {
    std::fs::read_to_string(daemon.home.path().join("shell-starts"))
        .unwrap_or_default()
        .lines()
        .count()
}

fn incompatible(client_bin: &Path, daemon_bin: &Path, current_client: bool) {
    let (mut daemon, key) = start_daemon_from(daemon_bin);
    let config = tempfile::tempdir().unwrap();
    let server = qshd::load_or_create_transport_key(&daemon.home.path().join("host_key")).unwrap();
    sshauth::known_hosts::KnownHosts::open(config.path().join("qsh/known_hosts"))
        .pin("127.0.0.1", daemon.port, &server.public)
        .unwrap();
    let mut client = spawn_qsh(
        client_bin,
        &daemon,
        &key,
        config.path(),
        &["--status", "off"],
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), seen.clone());
    let status = wait_for_exit(&mut client.child)
        .unwrap_or_else(|| panic!("incompatible attempt must terminate: {}", text(&seen)));
    assert_eq!(
        status.code(),
        Some(12),
        "expected connection refusal, not a crash or unrelated failure"
    );
    let output = text(&seen);
    assert!(
        output.contains("qsh: could not connect:"),
        "missing connection diagnostic: {output}"
    );
    assert!(
        !output.contains("\x1b[?1049h"),
        "application terminal was entered: {output}"
    );
    assert_eq!(
        shell_starts(&daemon),
        0,
        "incompatible attempt started a shell"
    );
    if current_client {
        assert!(output.contains("protocol 2"), "{output}");
    }
    assert!(
        daemon.child.try_wait().unwrap().is_none(),
        "daemon died during rejection"
    );
}

#[test]
#[ignore = "needs unchanged published v0.5.0 QSH_OLD_QSH and QSH_OLD_QSHD"]
fn published_v050_pair_is_a_real_shell_start_positive_control() {
    let _serial = serialised();
    let (daemon, key) = start_daemon_from(&old_binary("QSH_OLD_QSHD"));
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_qsh(
        &old_binary("QSH_OLD_QSH"),
        &daemon,
        &key,
        config.path(),
        &[],
    );
    let seen = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), seen.clone());
    sign_in(&mut client, &seen, &daemon);
    assert_eq!(shell_starts(&daemon), 1);
    leave(client);
}

#[test]
#[ignore = "needs unchanged published v0.5.0 QSH_OLD_QSH"]
fn published_v050_client_cannot_mutate_protocol2_daemon() {
    let _serial = serialised();
    incompatible(&old_binary("QSH_OLD_QSH"), &qshd_path(), false);
}

#[test]
#[ignore = "needs unchanged published v0.5.0 QSH_OLD_QSHD"]
fn protocol2_client_cannot_mutate_published_v050_daemon() {
    let _serial = serialised();
    incompatible(&this_qsh(), &old_binary("QSH_OLD_QSHD"), true);
}

/// §8.1, row 6 with real binaries: this `qsh` and this daemon, the header
/// under the AEAD and stream credits, 8 MB of output collapsed into screen
/// repaints, and Ctrl-C.
#[test]
fn this_qsh_follows_a_flood_as_screen_repaints_with_the_header_under_aead() {
    let _serial = serialised();
    let (daemon, key) = start_daemon_from(&qshd_path());
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_qsh(&this_qsh(), &daemon, &key, config.path(), &["--verbose"]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    drain_into(
        client.master.try_clone().expect("clone master"),
        seen.clone(),
    );
    sign_in(&mut client, &seen, &daemon);
    assert_eq!(shell_starts(&daemon), 1);
    follow_8_mb_of_output_as_repaints_and_interrupt(&mut client, &seen, &daemon);
    let log = std::fs::read_to_string(config.path().join("qsh").join("log")).unwrap_or_default();
    assert!(
        log.contains("transport features: header-aad stream-credit offset-wrap auth-accepted channel-geometry"),
        "all three, credits among them: {log}"
    );
    leave(client);
}

/// Bulk input remains supported between geometry-capable peers.
#[test]
fn current_qsh_pastes_a_megabyte_into_current_daemon() {
    let _serial = serialised();
    let (daemon, key) = start_daemon_from(&qshd_path());
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_qsh(&this_qsh(), &daemon, &key, config.path(), &[]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), seen.clone());
    sign_in(&mut client, &seen, &daemon);
    assert_eq!(shell_starts(&daemon), 1);
    paste_a_megabyte(&mut client, &seen, &daemon);
    leave(client);
}

fn fixture_executable(dir: &Path, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn fixture_readiness_timeout_kills_and_reaps_its_owned_daemon() {
    let _serial = serialised();
    let dir = tempfile::tempdir().unwrap();
    let fake = fixture_executable(
        dir.path(),
        "silent-daemon",
        r#"printf '%s\n' "$$" > "$0.pid"
exec sleep 60"#,
    );
    let outcome =
        std::panic::catch_unwind(|| start_daemon_with_ready_timeout(&fake, Duration::from_secs(1)));
    assert!(outcome.is_err(), "silent fixture unexpectedly became ready");
    let pid: libc::pid_t = std::fs::read_to_string(dir.path().join("silent-daemon.pid"))
        .expect("the fixture actually executed")
        .trim()
        .parse()
        .unwrap();
    let mut status = 0;
    // SAFETY: this PID belongs to the direct child this fixture spawned. A
    // successful waitpid probe establishes ownership before the RED cleanup.
    let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
    let error = std::io::Error::last_os_error().raw_os_error();
    if waited == 0 {
        // The failed implementation must not leak a process even on RED.
        // Our still-unreaped child cannot have its PID reused before waitpid.
        unsafe {
            libc::kill(pid, libc::SIGKILL);
            libc::waitpid(pid, &mut status, 0);
        }
    }
    assert_eq!(
        (waited, error),
        (-1, Some(libc::ECHILD)),
        "readiness unwind must kill and reap its child before returning"
    );
}

#[test]
fn fixture_incompatible_oracle_rejects_an_unrelated_client_failure() {
    let _serial = serialised();
    let dir = tempfile::tempdir().unwrap();
    let fake = fixture_executable(
        dir.path(),
        "failed-client",
        r#"printf 'ran' > "$0.ran"
exit 1"#,
    );
    let outcome = std::panic::catch_unwind(|| incompatible(&fake, &qshd_path(), false));
    assert_eq!(
        std::fs::read(dir.path().join("failed-client.ran")).unwrap(),
        b"ran",
        "the client must have run; a setup failure cannot satisfy this oracle"
    );
    assert!(
        outcome.is_err(),
        "unrelated exit 1 was accepted as protocol rejection"
    );
}

#[cfg(target_os = "linux")]
#[path = "../../qshd/tests/daemon_guard/mod.rs"]
mod daemon_guard;

#[cfg(target_os = "macos")]
mod daemon_guard {
    use super::*;
    #[derive(Debug)]
    pub enum Finished {
        Stopped,
        Leaked,
    }
    pub struct DaemonGuard {
        socket: PathBuf,
    }
    impl DaemonGuard {
        pub fn new(socket: PathBuf) -> Self {
            Self { socket }
        }
        pub fn finish(&self) -> Finished {
            if !self.socket.exists() {
                return Finished::Stopped;
            }
            let _ =
                qshd::control::client_request(&self.socket, &qshd::control::ControlRequest::Stop);
            if wait_until(|| !self.socket.exists()) {
                Finished::Stopped
            } else {
                Finished::Leaked
            }
        }
    }
    impl Drop for DaemonGuard {
        fn drop(&mut self) {
            assert!(
                matches!(self.finish(), Finished::Stopped),
                "owned personal service cleanup failed"
            );
        }
    }
}

/// A released personal daemon, owned through the same control guard used by
/// the other real-daemon tests. Linux subreaps its double-forked children;
/// Darwin retains exit observations and leaves orphan reaping to launchd.
#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PersonalDaemon {
    guard: daemon_guard::DaemonGuard,
    pids: Vec<u32>,
    #[cfg(target_os = "macos")]
    processes: Vec<OwnedLegacyShell>,
    #[cfg(target_os = "linux")]
    previous_subreaper: libc::c_int,
}

#[cfg(target_os = "linux")]
impl Drop for PersonalDaemon {
    fn drop(&mut self) {
        let pids = self.pids.clone();
        let reaper = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(25);
            for pid in pids {
                loop {
                    let mut status = 0;
                    let result = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
                    if result == pid as i32 {
                        break;
                    }
                    if result < 0 || Instant::now() >= deadline {
                        return false;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            true
        });
        let stopped = self.guard.finish();
        let reaped = reaper.join().unwrap_or(false);
        unsafe {
            libc::prctl(libc::PR_SET_CHILD_SUBREAPER, self.previous_subreaper);
        }
        assert!(
            matches!(stopped, daemon_guard::Finished::Stopped),
            "{stopped:?}"
        );
        assert!(reaped, "owned personal daemon was not reaped");
    }
}

#[cfg(target_os = "macos")]
impl Drop for PersonalDaemon {
    fn drop(&mut self) {
        assert!(matches!(
            self.guard.finish(),
            daemon_guard::Finished::Stopped
        ));
        for process in &self.processes {
            assert!(
                wait_until(|| process.exited()),
                "owned daemon did not exit after its service released"
            );
        }
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn personal_status(socket: &Path) -> Option<qshd::control::StatusResponse> {
    match qshd::control::client_request(socket, &qshd::control::ControlRequest::Status).ok()? {
        qshd::control::ControlReply::Answered(line) => {
            qshd::control::StatusResponse::from_line(&line).ok()
        }
        _ => None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_legacy_fixture_metadata(check: &serde_json::Value, version: &str) {
    let mut fields = version
        .lines()
        .next()
        .unwrap_or("")
        .split_ascii_whitespace();
    assert_eq!(fields.next(), Some("qshd"));
    assert_eq!(fields.next(), Some("0.5.0"));
    // SelfCheck reports channel protocol here, not transport wire compatibility.
    assert_eq!(check["protocol"], 1);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn legacy_fixture_accepts_published_self_check_without_a_version_field() {
    // Public v0.5 root 5a5f561 SelfCheck schema; build is synthetic.
    let check = serde_json::json!({"build":0,"arch":"x86_64","protocol":1,"protocols":[1],"handover_versions":[1],"transport_features":[]});
    assert_legacy_fixture_metadata(&check, "qshd 0.5.0 (build 0)\n");
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn legacy_ensure_command(binary: &Path, port: u16, client_key: &str, report_busy: bool) -> Command {
    let mut command = Command::new(binary);
    command.arg("transport-ensure");
    if report_busy {
        command.args(["--report-busy", "--busy-attempt", &"12".repeat(16)]);
    }
    command.args([
        "--name",
        "legacy",
        "--port",
        &port.to_string(),
        "--client-pubkey",
        client_key,
    ]);
    command
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn busy_ensure_fixture_reaches_real_transport_dispatch_without_daemon_mutation() {
    let home = tempfile::tempdir().unwrap();
    let output = legacy_ensure_command(&qshd_path(), 60022, "invalid-key", true)
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("HISTFILE", "/dev/null")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error = String::from_utf8_lossy(&output.stderr);
    assert!(
        error.contains("--client-pubkey"),
        "the dispatcher must reach transport-ensure argument validation: {error}"
    );
    assert!(!error.contains("unknown command"), "{error}");
    assert_eq!(std::fs::read_dir(home.path()).unwrap().count(), 0);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "needs unchanged published v0.5.0 QSH_OLD_QSH and QSH_OLD_QSHD"]
fn current_ensure_reports_busy_published_v050_without_interrupting_shell() {
    legacy_service_fixture(false, false);
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "needs unchanged published v0.5.0 QSH_OLD_QSH and QSH_OLD_QSHD"]
fn published_v050_force_restarts_account_service_even_after_instance_change() {
    for changed in [false, true] {
        legacy_service_fixture(true, changed);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn legacy_service_fixture(force: bool, changed_during_dialog: bool) {
    use std::os::unix::fs::PermissionsExt;
    let _serial = serialised();
    let home = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let old_daemon = old_binary("QSH_OLD_QSHD");
    let old_client = old_binary("QSH_OLD_QSH");
    // The caller authenticates the archive digest using the release fixture
    // helper; this check also catches a wrongly supplied daemon executable.
    let check = Command::new(&old_daemon)
        .arg("self-check")
        .output()
        .unwrap();
    assert!(check.status.success());
    let check: serde_json::Value = serde_json::from_slice(&check.stdout).unwrap();
    let version = Command::new(&old_daemon).arg("--version").output().unwrap();
    assert!(version.status.success());
    assert_legacy_fixture_metadata(&check, std::str::from_utf8(&version.stdout).unwrap());
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let key_path = home.path().join("id_ed25519");
    support::write_private(
        &key_path,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    std::fs::create_dir(home.path().join(".ssh")).unwrap();
    std::fs::write(
        home.path().join(".ssh/authorized_keys"),
        key.public_key().to_openssh().unwrap(),
    )
    .unwrap();
    let personal_cache = if cfg!(target_os = "macos") {
        home.path().join("Library/Caches/qsh")
    } else {
        home.path().join("qsh")
    };
    let socket = personal_cache.join("control.sock");
    let port = free_udp_port();
    #[cfg(target_os = "linux")]
    let previous_subreaper = {
        #[cfg(target_os = "linux")]
        {
            let mut previous = 0;
            assert_eq!(
                unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut previous) },
                0
            );
            assert_eq!(unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) }, 0);
            previous
        }
    };
    let run_ensure = |binary: &Path, client_key: &str, report_busy: bool| {
        legacy_ensure_command(binary, port, client_key, report_busy)
            .env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env("HISTFILE", "/dev/null")
            .env("SHELL", "/bin/sh")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID")
            .output()
            .unwrap()
    };
    let started = run_ensure(
        &old_daemon,
        "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=",
        false,
    );
    assert!(
        started.status.success(),
        "{}",
        String::from_utf8_lossy(&started.stderr)
    );
    let guard = daemon_guard::DaemonGuard::new(socket.clone());
    assert!(wait_until(|| personal_status(&socket).is_some()));
    let before = personal_status(&socket).unwrap();
    let mut owned = PersonalDaemon {
        guard,
        pids: vec![before.pid],
        #[cfg(target_os = "macos")]
        processes: vec![OwnedLegacyShell::pin(before.pid)],
        #[cfg(target_os = "linux")]
        previous_subreaper,
    };
    let identity_path = personal_cache.join("transport_server_key.bin");
    let identity = std::fs::read(&identity_path).unwrap();
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_qsh_on_port(&old_client, port, &key_path, config.path(), &[]);
    let seen = Arc::new(Mutex::new(Vec::new()));
    drain_into(client.master.try_clone().unwrap(), seen.clone());
    assert!(
        wait_until(|| text(&seen).contains("Key fingerprint")),
        "{}",
        text(&seen)
    );
    client.master.write_all(b"yes\n").unwrap();
    client
        .master
        .write_all(b"echo before-upgrade-$((37*19))\n")
        .unwrap();
    assert!(
        wait_until(|| text(&seen).contains("before-upgrade-703")),
        "{}",
        text(&seen)
    );
    assert!(wait_until(
        || personal_status(&socket).is_some_and(|s| s.total_connections > 0)
    ));
    let original_current = std::env::var_os("QSH_TEST_CURRENT_ENSURE")
        .map(PathBuf::from)
        .unwrap_or_else(qshd_path);
    let current = if force {
        let selected = home.path().join("selected-qshd");
        std::fs::copy(&original_current, &selected).unwrap();
        assert!(Command::new("/usr/bin/strip")
            .arg(&selected)
            .status()
            .unwrap()
            .success());
        #[cfg(target_os = "macos")]
        assert!(Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--timestamp=none",
                "--identifier",
                "org.qsh.fixture.service527"
            ])
            .arg(&selected)
            .status()
            .unwrap()
            .success());
        std::fs::set_permissions(&selected, std::fs::Permissions::from_mode(0o500)).unwrap();
        selected
    } else {
        original_current.clone()
    };
    let baseline = home.path().join("selected-baseline-qshd");
    if force {
        std::fs::copy(&current, &baseline).unwrap();
    }
    let rejected = run_ensure(
        &current,
        "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
        true,
    );
    // Prove survival before asserting rejection, so even the baseline RED
    // demonstrates an active real shell rather than merely a synthetic count.
    let after = personal_status(&socket).unwrap();
    assert_eq!(
        (after.pid, &after.checksum, &after.version),
        (before.pid, &before.checksum, &before.version)
    );
    assert_eq!(std::fs::read(&identity_path).unwrap(), identity);
    client
        .master
        .write_all(b"echo after-upgrade-$((41*23))\n")
        .unwrap();
    assert!(
        wait_until(|| text(&seen).contains("after-upgrade-943")),
        "{}",
        text(&seen)
    );
    let stdout = String::from_utf8_lossy(&rejected.stdout);
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert!(
        rejected.status.success(),
        "busy report failed: {stdout}; {stderr}"
    );
    assert!(!stdout.contains("TRANSPORT-READY"), "{stdout}");
    let info: bringup::BusyDaemonInfo =
        serde_json::from_str(stdout.trim().strip_prefix("TRANSPORT-BUSY ").unwrap()).unwrap();
    assert_eq!(info.identity.version, "0.5.0");
    assert_eq!(info.serving_profiles, None);
    assert_eq!(info.preservation, bringup::PreservationCapability::Unknown);
    if !force {
        leave(client);
        return;
    }
    assert!(
        info.service_restart.is_some(),
        "legacy service must be explicitly offered"
    );
    let consent = info.confirm_service_restart().unwrap();
    let decision = bringup::PendingBusy::new(info.clone())
        .unwrap()
        .decide(bringup::BusyChoice::ForceUpdate);
    // Internal destination custody is meaningful only with an adopted stage.
    // Replaying it from an ordinary invocation, changing it, or duplicating
    // the option must never turn an installation path into STOP authority.
    for (destination, duplicate, forged_context) in [
        (current.clone(), false, false),
        (home.path().join("other-qshd"), false, true),
        (current.clone(), true, false),
    ] {
        let mut command = legacy_ensure_command(
            &current,
            port,
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
            true,
        );
        command.args([
            "--busy-decision",
            &serde_json::to_string(&decision).unwrap(),
            "--service-restart-consent",
            &serde_json::to_string(&consent).unwrap(),
            "--service-candidate-helper",
            current.to_str().unwrap(),
            "--service-installed-helper",
            destination.to_str().unwrap(),
        ]);
        if duplicate {
            command.args(["--service-installed-helper", destination.to_str().unwrap()]);
        }
        command
            .env("HOME", home.path())
            .env("XDG_CACHE_HOME", home.path())
            .env("XDG_CONFIG_HOME", home.path())
            .env("HISTFILE", "/dev/null")
            .env_remove("SSH_AUTH_SOCK")
            .env_remove("SSH_AGENT_PID");
        if forged_context {
            command.env(qshd::service_stage::LAUNCH_ENV, "forged-context");
        } else {
            command.env_remove(qshd::service_stage::LAUNCH_ENV);
        }
        let result = command.output().unwrap();
        let output = String::from_utf8_lossy(&result.stdout);
        assert!(!output.contains("TRANSPORT-READY"), "{output}");
        if !duplicate {
            assert!(
                result.status.success()
                    && output.starts_with("TRANSPORT-RESTART-FAILED ")
                    && output.contains("refused"),
                "{output}; {}",
                String::from_utf8_lossy(&result.stderr)
            );
        } else {
            assert!(!result.status.success());
        }
        assert_eq!(personal_status(&socket).unwrap().pid, before.pid);
    }
    // Replacing the ordinary selected artifact before confirmation must refuse
    // before STOP, even though the substituted ELF remains executable.
    let replacement = home.path().join("substituted-qshd");
    let mut changed_image = std::fs::read(&current).unwrap();
    changed_image.extend_from_slice(b"service-candidate-substitution");
    std::fs::write(&replacement, changed_image).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::rename(&replacement, &current).unwrap();
    // The intact driver selects the tampered on-disk artifact; on macOS the
    // altered file may itself be unlaunchable because of its code signature.
    let substituted = legacy_ensure_command(
        &original_current,
        port,
        "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
        true,
    )
    .args([
        "--busy-decision",
        &serde_json::to_string(&decision).unwrap(),
        "--service-restart-consent",
        &serde_json::to_string(&consent).unwrap(),
        "--service-candidate-helper",
        current.to_str().unwrap(),
    ])
    .env("HOME", home.path())
    .env("XDG_CACHE_HOME", home.path())
    .env("XDG_CONFIG_HOME", home.path())
    .env("HISTFILE", "/dev/null")
    .env_remove("SSH_AUTH_SOCK")
    .env_remove("SSH_AGENT_PID")
    .output()
    .unwrap();
    assert!(
        substituted.status.success(),
        "{}",
        String::from_utf8_lossy(&substituted.stderr)
    );
    let refused = String::from_utf8_lossy(&substituted.stdout);
    assert!(
        refused.starts_with("TRANSPORT-RESTART-FAILED ") && refused.contains("refused"),
        "{refused}"
    );
    assert_eq!(personal_status(&socket).unwrap().pid, before.pid);
    std::fs::copy(&baseline, &replacement).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::rename(&replacement, &current).unwrap();
    // Valid-looking substituted consent must not reach STOP. Both the decision
    // and consent are changed so this tests independently derived authority.
    for field in ["candidate", "uid", "port", "endpoint"] {
        let mut wrong_decision = decision.clone();
        let mut wrong_consent = consent.clone();
        match field {
            "candidate" => {
                wrong_consent.candidate.checksum = "00".repeat(32);
                wrong_decision.candidate = wrong_consent.candidate.clone();
            }
            "uid" => {
                wrong_consent.service.uid += 1;
                wrong_decision.service_restart = Some(wrong_consent.service.clone());
            }
            "port" => {
                wrong_consent.service.port = if port == u16::MAX { port - 1 } else { port + 1 };
                wrong_decision.service_restart = Some(wrong_consent.service.clone());
            }
            _ => {
                wrong_consent.service.endpoint = home
                    .path()
                    .join("another/control.sock")
                    .to_str()
                    .unwrap()
                    .into();
                wrong_decision.service_restart = Some(wrong_consent.service.clone());
            }
        }
        let refused = legacy_ensure_command(
            &current,
            port,
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
            true,
        )
        .args([
            "--busy-decision",
            &serde_json::to_string(&wrong_decision).unwrap(),
            "--service-restart-consent",
            &serde_json::to_string(&wrong_consent).unwrap(),
            "--service-candidate-helper",
            current.to_str().unwrap(),
        ])
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("HISTFILE", "/dev/null")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .output()
        .unwrap();
        let stdout = String::from_utf8_lossy(&refused.stdout);
        assert!(
            refused.status.success(),
            "{field}: {}",
            String::from_utf8_lossy(&refused.stderr)
        );
        assert!(
            stdout.starts_with("TRANSPORT-RESTART-FAILED ") && stdout.contains("refused"),
            "{field}: {stdout}"
        );
        assert!(!stdout.contains("TRANSPORT-READY"));
        assert_eq!(personal_status(&socket).unwrap().pid, before.pid);
    }
    client
        .master
        .write_all(b"echo refusal-survived-$((47*31))\n")
        .unwrap();
    assert!(
        wait_until(|| text(&seen).contains("refusal-survived-1457")),
        "{}",
        text(&seen)
    );
    // A real owned shell, rather than a synthetic connection counter, is lost.
    let marker = home.path().join("old-shell.pid");
    client
        .master
        .write_all(format!("printf '%s' \"$$\" > '{}'\n", marker.display()).as_bytes())
        .unwrap();
    assert!(wait_until(|| std::fs::read_to_string(&marker)
        .ok()
        .is_some_and(|pid| pid.parse::<u32>().is_ok())));
    let shell_pid: u32 = std::fs::read_to_string(&marker).unwrap().parse().unwrap();
    let shell = OwnedLegacyShell::pin(shell_pid);
    if changed_during_dialog {
        // This fixture deliberately changes the service during the dialog.
        // The old daemon is our unreaped subreaper child; resource release,
        // rather than kill(pid,0), is the correct controlled restart boundary.
        let stopped =
            qshd::control::client_request(&socket, &qshd::control::ControlRequest::Stop).unwrap();
        assert!(
            matches!(stopped, qshd::control::ControlReply::Answered(ref line) if serde_json::from_str::<serde_json::Value>(line).unwrap()["stopped"] == true)
        );
        assert!(wait_until(
            || !socket.exists() && UdpSocket::bind(("0.0.0.0", port)).is_ok()
        ));
        assert!(wait_until(|| shell.exited()));
        let restarted = run_ensure(
            &current,
            "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
            false,
        );
        assert!(
            restarted.status.success(),
            "{}",
            String::from_utf8_lossy(&restarted.stderr)
        );
        assert!(wait_until(|| personal_status(&socket).is_some()));
        let changed = personal_status(&socket).unwrap();
        assert_ne!(changed.pid, before.pid);
        owned.pids.push(changed.pid);
        #[cfg(target_os = "macos")]
        owned.processes.push(OwnedLegacyShell::pin(changed.pid));
    }
    let forced = legacy_ensure_command(
        &current,
        port,
        "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk=",
        true,
    )
    .args([
        "--busy-decision",
        &serde_json::to_string(&decision).unwrap(),
        "--service-restart-consent",
        &serde_json::to_string(&consent).unwrap(),
        "--service-candidate-helper",
        current.to_str().unwrap(),
    ])
    .env("HOME", home.path())
    .env("XDG_CACHE_HOME", home.path())
    .env("XDG_CONFIG_HOME", home.path())
    .env("HISTFILE", "/dev/null")
    .env("SHELL", "/bin/sh")
    .env_remove("SSH_AUTH_SOCK")
    .env_remove("SSH_AGENT_PID")
    .output()
    .unwrap();
    assert!(
        forced.status.success(),
        "{}",
        String::from_utf8_lossy(&forced.stderr)
    );
    let ready = String::from_utf8_lossy(&forced.stdout);
    assert!(ready.contains("TRANSPORT-READY "), "{ready}");
    assert!(!ready.contains("TRANSPORT-RESTART-FAILED"), "{ready}");
    assert!(
        wait_until(|| shell.exited()),
        "old shell survived destructive service restart"
    );
    assert!(wait_until(|| personal_status(&socket).is_some()));
    let after = personal_status(&socket).unwrap();
    assert_ne!(after.pid, *owned.pids.last().unwrap());
    assert_eq!(after.version, env!("CARGO_PKG_VERSION"));
    let executing = serving_stage_path(after.pid);
    assert!(
        executing.starts_with(personal_cache.join("service-staging")),
        "service must execute selected private stage: {}",
        executing.display()
    );
    assert!(
        executing.exists(),
        "daemonization parent must not remove child artifact"
    );
    use sha2::Digest as _;
    assert_eq!(
        format!(
            "{:x}",
            sha2::Sha256::digest(std::fs::read(&executing).unwrap())
        ),
        info.candidate.checksum
    );
    owned.pids.push(after.pid);
    #[cfg(target_os = "macos")]
    owned.processes.push(OwnedLegacyShell::pin(after.pid));
    assert_eq!(std::fs::read(&identity_path).unwrap(), identity);
    drop(client);
    let current_config = tempfile::tempdir().unwrap();
    let server_key = qshd::load_transport_key(&identity_path).unwrap();
    sshauth::known_hosts::KnownHosts::open(current_config.path().join("qsh/known_hosts"))
        .pin("127.0.0.1", port, &server_key.public)
        .unwrap();
    let mut current_client = spawn_qsh_on_port(
        Path::new(env!("CARGO_BIN_EXE_qsh")),
        port,
        &key_path,
        current_config.path(),
        &[],
    );
    let current_seen = Arc::new(Mutex::new(Vec::new()));
    drain_into(
        current_client.master.try_clone().unwrap(),
        current_seen.clone(),
    );
    assert!(wait_until(
        || personal_status(&socket).is_some_and(|status| status.total_connections > 0)
    ));
    current_client
        .master
        .write_all(b"echo service-ready-$((43*29))\n")
        .unwrap();
    assert!(
        wait_until(|| text(&current_seen).contains("service-ready-1247")),
        "{}",
        text(&current_seen)
    );
    leave(current_client);
    // Replacing the ordinary installed file does not change the serving image.
    // This is a fixture-owned valid executable; never alter Cargo artifacts.
    let mut replacement_bytes = std::fs::read(&baseline).unwrap();
    replacement_bytes.extend_from_slice(b"installed-after-service-start");
    std::fs::write(&replacement, replacement_bytes).unwrap();
    #[cfg(target_os = "macos")]
    assert!(Command::new("/usr/bin/codesign")
        .args([
            "--force",
            "--sign",
            "-",
            "--timestamp=none",
            "--identifier",
            "org.qsh.fixture.service527.replacement"
        ])
        .arg(&replacement)
        .status()
        .unwrap()
        .success());
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o500)).unwrap();
    std::fs::rename(&replacement, &current).unwrap();
    assert_ne!(
        format!(
            "{:x}",
            sha2::Sha256::digest(std::fs::read(&current).unwrap())
        ),
        info.candidate.checksum
    );
    assert_eq!(
        personal_status(&socket).unwrap().checksum,
        info.candidate.checksum
    );
    assert_service_update_stages_beside_installed_helper(
        &socket,
        port,
        server_key.public,
        &current,
        &executing,
        after.build,
    );
    drop(owned);
    assert!(
        !executing.exists(),
        "graceful service return must clean only its private stage"
    );
    assert!(
        current.exists(),
        "persistent helper is never a stage-cleanup target"
    );
}

#[cfg(target_os = "linux")]
struct OwnedLegacyShell {
    pid: u32,
    descriptor: std::os::fd::OwnedFd,
}
#[cfg(target_os = "linux")]
impl OwnedLegacyShell {
    fn pin(pid: u32) -> Self {
        use std::os::fd::FromRawFd;
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(fd >= 0, "pin the shell created by this fixture");
        Self {
            pid,
            descriptor: unsafe { std::os::fd::OwnedFd::from_raw_fd(fd as i32) },
        }
    }
    fn exited(&self) -> bool {
        use std::os::fd::AsRawFd;
        let mut poll = libc::pollfd {
            fd: self.descriptor.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert!(unsafe { libc::poll(&mut poll, 1, 0) } >= 0);
        poll.revents & libc::POLLIN != 0
    }
}
#[cfg(target_os = "linux")]
impl Drop for OwnedLegacyShell {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        if !self.exited() {
            // Only the process pinned from this fixture's shell-owned marker.
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.descriptor.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                );
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut status = 0;
            let result = unsafe { libc::waitpid(self.pid as i32, &mut status, libc::WNOHANG) };
            if result == self.pid as i32
                || (result < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                break;
            }
            if Instant::now() >= deadline {
                panic!("owned legacy shell was not reaped");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

#[cfg(target_os = "macos")]
struct OwnedLegacyShell {
    queue: std::os::fd::OwnedFd,
    observed: std::cell::Cell<bool>,
}
#[cfg(target_os = "macos")]
impl OwnedLegacyShell {
    fn pin(pid: u32) -> Self {
        use std::os::fd::{AsRawFd, FromRawFd};
        let queue = unsafe { libc::kqueue() };
        assert!(queue >= 0);
        let queue = unsafe { std::os::fd::OwnedFd::from_raw_fd(queue) };
        let change = libc::kevent {
            ident: pid as libc::uintptr_t,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: std::ptr::null_mut(),
        };
        assert_eq!(
            unsafe {
                libc::kevent(
                    queue.as_raw_fd(),
                    &change,
                    1,
                    std::ptr::null_mut(),
                    0,
                    std::ptr::null(),
                )
            },
            0
        );
        Self {
            queue,
            observed: std::cell::Cell::new(false),
        }
    }
    fn exited(&self) -> bool {
        use std::os::fd::AsRawFd;
        if self.observed.get() {
            return true;
        }
        let mut event = std::mem::MaybeUninit::<libc::kevent>::uninit();
        let timeout = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let count = unsafe {
            libc::kevent(
                self.queue.as_raw_fd(),
                std::ptr::null(),
                0,
                event.as_mut_ptr(),
                1,
                &timeout,
            )
        };
        assert!(count >= 0);
        if count == 1 {
            let event = unsafe { event.assume_init() };
            assert_eq!(event.filter, libc::EVFILT_PROC);
            assert_eq!(event.flags & libc::EV_ERROR, 0);
            self.observed.set(event.fflags & libc::NOTE_EXIT != 0);
        }
        self.observed.get()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn serving_stage_path(pid: u32) -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).unwrap()
    }
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut bytes = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let pid = libc::c_int::try_from(pid).expect("owned daemon PID must fit Darwin c_int");
        let count =
            unsafe { libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
        assert!(count > 0, "owned daemon path must be available");
        let end = bytes
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(count as usize);
        PathBuf::from(std::ffi::OsString::from_vec(bytes[..end].to_vec()))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn assert_service_update_stages_beside_installed_helper(
    socket: &Path,
    port: u16,
    server_key: [u8; 32],
    installed: &Path,
    executing: &Path,
    build: u64,
) {
    use transport::channel::{
        decode_server, encode_client, ClientRecord, ServerRecord, UpdateAnswer, UpdateOffer,
        CONTROL_STREAM, UPDATE_STREAM,
    };
    use transport::conn::{AuthPolicy, ConnectionConfig, Role};
    use transport::driver_std::{Binder, ClientEvents, StdClient};
    use transport::handshake_payload::StartKind;
    #[derive(Default)]
    struct Probe {
        deframer: Mutex<transport::shell_frame::RecordDeframer>,
        records: Mutex<Vec<ServerRecord>>,
        live: std::sync::atomic::AtomicBool,
    }
    impl ClientEvents for Probe {
        fn on_input_failure(&self, failure: transport::driver_std::InputFailure) {
            panic!("owned service probe input failed: {failure:?}");
        }
        fn on_bytes(&self, stream: u8, data: Vec<u8>) {
            if stream == CONTROL_STREAM {
                let raw = self.deframer.lock().unwrap().push(&data);
                for bytes in raw {
                    if let Ok(record) = decode_server(&bytes) {
                        self.records.lock().unwrap().push(record);
                    }
                }
            }
        }
        fn on_state(&self, state: transport::LinkState) {
            if state == transport::LinkState::Live {
                self.live.store(true, std::sync::atomic::Ordering::Release);
            }
        }
        fn on_stats(&self, _: transport::Stats) {}
        fn on_reset(&self, _: u8) {}
    }
    struct Bind;
    impl Binder for Bind {
        fn bind(&self, _: i32) -> bool {
            true
        }
    }
    assert!(wait_until(
        || personal_status(socket).is_some_and(|status| status.total_connections == 0)
    ));
    let key = transport::generate_keypair();
    assert!(matches!(
        qshd::control::client_request(
            socket,
            &qshd::control::ControlRequest::AddClient(key.public)
        )
        .unwrap(),
        qshd::control::ControlReply::Answered(_)
    ));
    let probe = Arc::new(Probe::default());
    let client = StdClient::connect(
        ([127, 0, 0, 1], port).into(),
        ConnectionConfig {
            required_features: transport::Features::CHANNEL_GEOMETRY,
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: key.private,
            remote_static_pub: Some(server_key),
            auth: AuthPolicy::Allowlist(Vec::new()),
        },
        [57; 16],
        StartKind::Cold,
        Arc::new(Bind),
        probe.clone(),
        None,
    );
    assert!(wait_until(|| probe
        .live
        .load(std::sync::atomic::Ordering::Acquire)));
    client
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::UpdateOffer(UpdateOffer {
                build: build.checked_add(1).unwrap(),
                checksum: [0; 32],
                arch: std::env::consts::ARCH.into(),
                size: 2,
            })),
        )
        .unwrap();
    assert!(
        wait_until(|| probe
            .records
            .lock()
            .unwrap()
            .contains(&ServerRecord::UpdateAnswer(UpdateAnswer::Accept))),
        "{:?}",
        probe.records.lock().unwrap()
    );
    client.send_bytes(UPDATE_STREAM, vec![0]).unwrap();
    let staged_in = |directory: &Path| {
        std::fs::read_dir(directory)
            .unwrap()
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|name| name.starts_with(".qshd-update-"))
            })
            .collect::<Vec<_>>()
    };
    assert!(
        wait_until(|| !staged_in(installed.parent().unwrap()).is_empty()),
        "update file was not created beside persistent helper"
    );
    assert!(
        staged_in(executing.parent().unwrap()).is_empty(),
        "executing service stage cannot be an installation destination"
    );
    client.close();
    assert!(
        wait_until(|| staged_in(installed.parent().unwrap()).is_empty()),
        "partial update must clean its owned temporary file"
    );
}
