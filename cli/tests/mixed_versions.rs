//! Published v0.5.0 (protocol 1) versus the current protocol 2, on real PTYs.
//! Opt-in fixtures are the unchanged binaries from the published release:
//! `QSH_OLD_QSH=<v0.5.0 qsh> QSH_OLD_QSHD=<v0.5.0 qshd> cargo test -p qsh --test mixed_versions -- --ignored --nocapture --test-threads=1`
//! Incompatible peers must never start a shell; compatible pairs prove the
//! shell-start counter and real I/O. Current-peer flood/paste coverage stays active.

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
    let home = tempfile::tempdir().expect("tempdir");
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

    use std::os::unix::fs::PermissionsExt;
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
    let port = daemon.port.to_string();
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
        log.contains("transport features: header-aad stream-credit offset-wrap channel-geometry"),
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
