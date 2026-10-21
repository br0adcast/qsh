//! Real job-control stops before raw mode. A live controller in the same
//! session keeps the client's foreground process group non-orphaned.

use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

mod support;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const CASE: &str = "QSH_TEST_FOREGROUND_SUSPEND";

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            // The only target is this still-owned child, never a cached PID
            // after wait. CONT also makes cleanup safe on an assertion failure.
            unsafe { libc::kill(self.0.id() as i32, libc::SIGCONT) };
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[derive(Default)]
struct ClientState {
    child: Option<Child>,
    status: Option<std::process::ExitStatus>,
}

/// Only this owner may wait or signal the client. Scenario operations are
/// nonblocking syscalls under a short lock; cleanup takes the Child out and
/// performs its actual join outside the mutex before releasing any held worker.
struct ClientCustody(Mutex<ClientState>);

impl ClientCustody {
    fn new(child: Child) -> Self {
        Self(Mutex::new(ClientState {
            child: Some(child),
            status: None,
        }))
    }

    fn status(&self) -> std::io::Result<Option<std::process::ExitStatus>> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(child) = state.child.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    state.status = Some(status);
                    state.child = None;
                }
                Ok(None) => {}
                Err(error) => {
                    if error.raw_os_error() == Some(libc::ECHILD) {
                        state.child = None;
                    }
                    return Err(error);
                }
            }
        }
        Ok(state.status)
    }

    fn live<T>(&self, operation: impl FnOnce(u32) -> std::io::Result<T>) -> std::io::Result<T> {
        let mut state = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let child = state
            .child
            .as_mut()
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ECHILD))?;
        match child.try_wait() {
            Ok(None) => {}
            Ok(Some(status)) => {
                state.status = Some(status);
                state.child = None;
                return Err(std::io::Error::from_raw_os_error(libc::ECHILD));
            }
            Err(error) => {
                if error.raw_os_error() == Some(libc::ECHILD) {
                    state.child = None;
                }
                return Err(error);
            }
        }
        let result = operation(child.id());
        if result.as_ref().err().and_then(|e| e.raw_os_error()) == Some(libc::ECHILD) {
            state.child = None;
        }
        result
    }

    fn signal(&self, signal: i32) -> std::io::Result<()> {
        self.live(|pid| {
            if unsafe { libc::kill(pid as i32, signal) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        })
    }

    fn stopped(&self) -> std::io::Result<bool> {
        self.live(|pid| {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid,
                    &mut info,
                    libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
                )
            } != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(info.si_code == libc::CLD_STOPPED && unsafe { info.si_status() } == libc::SIGTSTP)
        })
    }

    fn consume_stop(&self) -> std::io::Result<bool> {
        self.live(|pid| {
            let mut status = 0;
            let result =
                unsafe { libc::waitpid(pid as i32, &mut status, libc::WUNTRACED | libc::WNOHANG) };
            if result < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(result == pid as i32 && libc::WIFSTOPPED(status))
        })
    }

    fn close(&self) -> std::io::Result<std::process::ExitStatus> {
        let child = self
            .0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .child
            .take();
        let Some(mut child) = child else {
            return self
                .status()?
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ECHILD));
        };
        let status = match child.try_wait() {
            Ok(Some(status)) => status,
            Ok(None) => {
                // Still our unreaped child; no waiter can race after take().
                unsafe { libc::kill(child.id() as i32, libc::SIGCONT) };
                if let Err(error) = child.kill() {
                    // Preserve custody on a failure other than an already-exited child.
                    if error.raw_os_error() != Some(libc::ESRCH) {
                        self.0.lock().unwrap_or_else(|e| e.into_inner()).child = Some(child);
                        return Err(error);
                    }
                }
                child.wait()?
            }
            Err(error) => {
                // ECHILD has lost wait authority; never signal the numeric ID.
                if error.raw_os_error() != Some(libc::ECHILD) {
                    self.0.lock().unwrap_or_else(|e| e.into_inner()).child = Some(child);
                }
                return Err(error);
            }
        };
        self.0.lock().unwrap_or_else(|e| e.into_inner()).status = Some(status);
        Ok(status)
    }
}

impl Drop for ClientCustody {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// A real SSH TCP connection is accepted but no banner is sent. The CLI is
/// blocked inside SSH establishment, not in a foreground polling checkpoint.
struct StalledSsh {
    port: u16,
    accepted: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl StalledSsh {
    fn start() -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let accepted = Arc::new(AtomicUsize::new(0));
        let observed = accepted.clone();
        let thread = std::thread::spawn(move || {
            let mut held = [None, None];
            while !stopping.load(Ordering::SeqCst) {
                if let Ok((stream, _)) = listener.accept() {
                    observed.fetch_add(1, Ordering::SeqCst);
                    if let Some(slot) = held.iter_mut().find(|slot| slot.is_none()) {
                        *slot = Some(stream);
                    }
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        Self {
            port,
            accepted,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for StalledSsh {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

struct FreshFixture {
    daemon: support::Daemon,
    relay: support::UdpRelay,
    key_path: std::path::PathBuf,
    client_home: std::path::PathBuf,
}
impl FreshFixture {
    fn start(client_home: &std::path::Path) -> Self {
        let (daemon, key_path) = support::start_daemon();
        let relay = support::UdpRelay::start(daemon.port);
        Self {
            daemon,
            relay,
            key_path,
            client_home: client_home.to_owned(),
        }
    }
}

struct ScenarioPeers<'a> {
    key_only: &'a Peer,
    ssh: Option<&'a StalledSsh>,
    fresh: Option<&'a mut FreshFixture>,
}

struct Peer {
    port: u16,
    stop: Arc<AtomicBool>,
    handshakes: Arc<Mutex<HashSet<Vec<u8>>>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Peer {
    fn start() -> Self {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(20)))
            .unwrap();
        let port = socket.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let handshakes = Arc::new(Mutex::new(HashSet::new()));
        let seen = handshakes.clone();
        let thread = std::thread::spawn(move || {
            let mut buf = [0; 2048];
            while !stopping.load(Ordering::SeqCst) {
                let Ok((n, source)) = socket.recv_from(&mut buf) else {
                    continue;
                };
                if let Ok(transport::wire::Frame::Handshake { kind, .. }) =
                    transport::wire::parse(&buf[..n])
                {
                    if kind == transport::wire::Kind::KeyRequest {
                        let offer = transport::wire::encode_handshake(
                            transport::wire::Kind::KeyOffer,
                            &transport::wire::encode_key_offer_body(&[21; 32]),
                        );
                        socket.send_to(&offer, source).unwrap();
                    } else {
                        seen.lock().unwrap().insert(buf[..n].to_vec());
                    }
                }
            }
        });
        Self {
            port,
            stop,
            handshakes,
            thread: Some(thread),
        }
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn until(mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        if check() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn drain(master: &mut File, output: &mut Vec<u8>) {
    let mut buf = [0; 1024];
    loop {
        match master.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => {
                assert!(output.len() + n <= 64 * 1024, "bounded PTY output");
                output.extend_from_slice(&buf[..n]);
            }
        }
    }
}

fn run(case: &str) {
    let mut controller = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args(["controller", "--exact", "--nocapture", "--test-threads=1"])
            .env(CASE, case)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut stdout = controller.0.stdout.take().unwrap();
    let mut stderr = controller.0.stderr.take().unwrap();
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            assert!(flags >= 0);
            assert_eq!(libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK), 0);
        }
    }
    let mut output = Vec::new();
    let mut overflow = false;
    // The controller owns its watchdog and actual client custody. Do not kill
    // it from outside and bypass cleanup. Drain finite nonblocking turns so a
    // failed assertion cannot block its report on a full output pipe.
    let status = loop {
        collect_report(&mut stdout, &mut output, &mut overflow);
        collect_report(&mut stderr, &mut output, &mut overflow);
        if let Some(status) = controller.0.try_wait().unwrap() {
            break status;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    collect_report(&mut stdout, &mut output, &mut overflow);
    collect_report(&mut stderr, &mut output, &mut overflow);
    assert!(!overflow, "controller exceeded bounded report storage");
    assert!(
        status.success(),
        "controller failed ({status}): {}",
        String::from_utf8_lossy(&output)
    );
}

fn collect_report(reader: &mut impl Read, output: &mut Vec<u8>, overflow: &mut bool) {
    let mut buf = [0; 1024];
    for _ in 0..16 {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        let keep = n.min((64 * 1024_usize).saturating_sub(output.len()));
        output.extend_from_slice(&buf[..keep]);
        *overflow |= keep != n;
    }
}

#[test]
fn silent_handshake_suspends_before_raw_mode() {
    run("silent");
}

#[test]
fn visible_trust_prompt_suspends_before_raw_mode() {
    run("visible");
}

#[test]
fn hidden_passphrase_restores_echo_across_real_stop() {
    run("hidden");
}

#[test]
fn blocked_ssh_suspends_without_a_foreground_poll() {
    run("ssh");
}

#[test]
fn fresh_session_wait_suspends_and_resumes_the_same_attempt() {
    run("fresh");
}

#[test]
fn lost_wait_authority_never_enters_a_numeric_signal_operation() {
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["controller", "--exact", "--test-threads=1"])
        .env_remove(CASE)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = child.id();
    // Deliberately consume the actual child status outside std::Child to
    // reproduce ECHILD. No later numeric signal is authorized by that handle.
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(pid as i32, &mut status, 0) },
        pid as i32
    );
    let custody = ClientCustody::new(child);
    let entered = AtomicBool::new(false);
    let error = custody
        .live(|_| {
            entered.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
    assert!(!entered.load(Ordering::SeqCst));
    assert_eq!(
        custody.close().unwrap_err().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn held_scenario_is_failed_and_reaped_before_release() {
    run("held");
}

#[test]
fn controller() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    let home = tempfile::tempdir().unwrap();
    let peer = Peer::start();
    let stalled = (case == "ssh").then(StalledSsh::start);
    let mut fresh = (case == "fresh").then(|| FreshFixture::start(home.path()));
    let qsh_port = if let Some(fresh) = &fresh {
        fresh.relay.port
    } else if stalled.is_some() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.local_addr().unwrap().port()
    } else {
        peer.port
    };
    let mut key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    if case == "hidden" {
        key = key
            .encrypt(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                "suspend-test-secret",
            )
            .unwrap();
    }
    let key_path = home.path().join("identity");
    std::fs::write(
        &key_path,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let key_path = fresh
        .as_ref()
        .map(|f| f.key_path.clone())
        .unwrap_or(key_path);
    let server_key = if let Some(fresh) = &fresh {
        sshauth::discover::discover(
            ([127, 0, 0, 1], fresh.daemon.port).into(),
            Duration::from_millis(100),
        )
        .unwrap()
    } else {
        [21; 32]
    };
    if case != "visible" {
        std::fs::create_dir_all(home.path().join("qsh")).unwrap();
        sshauth::known_hosts::KnownHosts::open(home.path().join("qsh/known_hosts"))
            .pin("127.0.0.1", qsh_port, &server_key)
            .unwrap();
    }
    // Foreground-only controls did not need a drawable screen. Fresh enters
    // the real interactive shell, so use the established CLI fixture geometry.
    let pty = nix::pty::openpty(
        Some(&nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        }),
        None,
    )
    .unwrap();
    let saved = nix::sys::termios::tcgetattr(&pty.slave).unwrap();
    // This is a dedicated subprocess, not the multithreaded test parent.
    unsafe {
        assert!(libc::setsid() >= 0);
        // Closing the controller's last PTY descriptor hangs up its session.
        // This test controller must survive that teardown to report results;
        // the qsh child restores the normal disposition before exec.
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
        assert_eq!(
            libc::ioctl(pty.slave.as_raw_fd(), libc::TIOCSCTTY as _, 0),
            0
        );
    }
    // Optional fixture-only binary override qualifies preserved pre-fix code
    // under the same actual PTY/peer control; production reads no such setting.
    let binary = std::env::var_os("QSH_TEST_SUSPEND_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_qsh").into());
    let address = if let Some(ssh) = &stalled {
        format!("127.0.0.1:{qsh_port},ssh={}", ssh.port)
    } else {
        format!("127.0.0.1:{qsh_port}")
    };
    let mut command = Command::new(binary);
    command
        .args(["-i", key_path.to_str().unwrap(), &address])
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("HISTFILE", "/dev/null")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
        .stdout(Stdio::from(pty.slave.try_clone().unwrap()))
        .stderr(Stdio::from(pty.slave.try_clone().unwrap()));
    unsafe {
        command.pre_exec(|| {
            libc::signal(libc::SIGHUP, libc::SIG_DFL);
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            // The child is briefly background while establishing foreground
            // ownership. Ignore TTOU for this one operation, then restore it.
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            if libc::tcsetpgrp(0, libc::getpid()) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            libc::signal(libc::SIGTTOU, libc::SIG_DFL);
            Ok(())
        });
    }
    let child = Arc::new(ClientCustody::new(command.spawn().unwrap()));
    let mut master = File::from(pty.master);
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
            0
        );
    }
    let cancelled = AtomicBool::new(false);
    let (held_tx, held_rx) = std::sync::mpsc::sync_channel(1);
    let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
    let (held_ready, timed_out, cleanup, outcome) = std::thread::scope(|scope| {
        let worker_child = child.clone();
        let cancel = &cancelled;
        let case = case.as_str();
        let peer = &peer;
        let stalled = stalled.as_ref();
        let fresh = fresh.as_mut();
        let worker = scope.spawn(move || {
            if case == "held" {
                assert!(scenario_until(cancel, || !peer
                    .handshakes
                    .lock()
                    .unwrap()
                    .is_empty()));
                held_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(15)).unwrap();
                assert!(
                    worker_child.status().unwrap().is_some(),
                    "release must follow actual client reap"
                );
                return;
            }
            scenario(
                case,
                ScenarioPeers {
                    key_only: peer,
                    ssh: stalled,
                    fresh,
                },
                &worker_child,
                cancel,
                &mut master,
                &pty.slave,
                &saved,
            );
        });
        let forced = case == "held";
        let held_ready = !forced || held_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        // The held case reaches the same real watchdog-expiry branch after
        // a positive handshake fence, using a short fixture-only deadline.
        let budget = if forced {
            Duration::from_millis(50)
        } else if case == "fresh" {
            // Match the existing reconnect fixture's 20s observation budget;
            // this is a new multi-phase scenario, not a product timeout.
            Duration::from_secs(20)
        } else {
            Duration::from_secs(10)
        };
        let deadline = Instant::now() + budget;
        while !worker.is_finished() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        let timed_out = !worker.is_finished();
        if timed_out {
            cancelled.store(true, Ordering::SeqCst);
        }
        // This actual join precedes any held-worker release or Rust thread join.
        let cleanup = child.close();
        let _ = release_tx.send(());
        let outcome = worker.join();
        (held_ready, timed_out, cleanup, outcome)
    });
    assert!(
        held_ready,
        "held scenario never reached the actual handshake fence"
    );
    let status = cleanup.expect("supervisor must retain and reap exact client");
    assert!(child.status().unwrap().is_some());
    if case == "held" {
        use std::os::unix::process::ExitStatusExt;
        assert!(timed_out, "held scenario must report watchdog failure");
        assert_eq!(status.signal(), Some(libc::SIGKILL));
    } else {
        assert!(
            !timed_out,
            "scenario watchdog expired; cleanup was performed"
        );
    }
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}

fn scenario_until(cancel: &AtomicBool, mut check: impl FnMut() -> bool) -> bool {
    until(|| cancel.load(Ordering::SeqCst) || check()) && !cancel.load(Ordering::SeqCst)
}

fn scenario(
    case: &str,
    peers: ScenarioPeers<'_>,
    child: &ClientCustody,
    cancel: &AtomicBool,
    master: &mut File,
    slave: &std::os::fd::OwnedFd,
    saved: &nix::sys::termios::Termios,
) {
    if let Some(fresh) = peers.fresh {
        scenario_fresh(fresh, child, cancel, master, slave, saved);
        return;
    }
    let peer = peers.key_only;
    let stalled = peers.ssh;
    let mut output = Vec::new();
    assert!(
        scenario_until(cancel, || {
            drain(master, &mut output);
            match case {
                "silent" => !peer.handshakes.lock().unwrap().is_empty(),
                "ssh" => stalled.unwrap().accepted.load(Ordering::SeqCst) > 0,
                "visible" => String::from_utf8_lossy(&output).contains("[y/N]"),
                _ => {
                    String::from_utf8_lossy(&output).contains("Passphrase for key")
                        && !nix::sys::termios::tcgetattr(slave)
                            .unwrap()
                            .local_flags
                            .contains(nix::sys::termios::LocalFlags::ECHO)
                }
            }
        }),
        "initial phase missing: {}",
        String::from_utf8_lossy(&output)
    );
    if case == "visible" {
        master.write_all(b"n").unwrap();
    }
    if case == "hidden" {
        master.write_all(b"suspend-test-").unwrap();
    }
    stop_twice(case, child, cancel, master, slave, saved);
    if case == "visible" {
        master.write_all(b"no\n").unwrap();
    } else {
        if case == "hidden" {
            master.write_all(b"suspend-test-secret\n").unwrap();
            assert!(scenario_until(cancel, || !peer
                .handshakes
                .lock()
                .unwrap()
                .is_empty()));
        }
        child.signal(libc::SIGINT).unwrap();
    }
    assert!(
        scenario_until(cancel, || child.status().unwrap().is_some()),
        "client cancellation/answer did not exit"
    );
    let status = child.status().unwrap().unwrap();
    drain(master, &mut output);
    assert_eq!(nix::sys::termios::tcgetattr(slave).unwrap(), *saved);
    if case == "visible" {
        assert!(!status.success());
        assert!(
            peer.handshakes.lock().unwrap().is_empty(),
            "declined trust must not authenticate"
        );
    } else {
        assert_eq!(status.code(), Some(130));
        if let Some(ssh) = stalled {
            assert_eq!(
                ssh.accepted.load(Ordering::SeqCst),
                1,
                "continue must not start another SSH connection"
            );
        } else {
            assert_eq!(
                peer.handshakes.lock().unwrap().len(),
                1,
                "continue must not start a second handshake"
            );
        }
    }
    if case == "hidden" {
        assert!(
            !String::from_utf8_lossy(&output).contains("suspend-test-"),
            "secret input echoed"
        );
    }
}

fn stop_twice(
    case: &str,
    child: &ClientCustody,
    cancel: &AtomicBool,
    master: &mut File,
    slave: &std::os::fd::OwnedFd,
    saved: &nix::sys::termios::Termios,
) {
    for _ in 0..2 {
        // A literal terminal Ctrl-Z targets the actual foreground group.
        master.write_all(&[26]).unwrap();
        let stopped = scenario_until(cancel, || child.stopped().unwrap_or(false));
        assert!(stopped, "{case}: no actual SIGTSTP stop");
        assert_eq!(
            nix::sys::termios::tcgetattr(slave).unwrap(),
            *saved,
            "saved terminal settings while stopped"
        );
        assert!(child.consume_stop().unwrap());
        child.signal(libc::SIGCONT).unwrap();
        if case == "hidden" {
            assert!(scenario_until(cancel, || !nix::sys::termios::tcgetattr(
                slave
            )
            .unwrap()
            .local_flags
            .contains(nix::sys::termios::LocalFlags::ECHO)));
        }
    }
}

fn fresh_until(cancel: &AtomicBool, mut check: impl FnMut() -> bool) -> bool {
    // The existing actual reconnect suite uses the same 20s fixture budget.
    // The supervisor's cancellation interrupts every observation loop.
    let deadline = Instant::now() + Duration::from_secs(20);
    while !cancel.load(Ordering::SeqCst) && Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    false
}

fn tail(text: &str, max: usize) -> &str {
    let mut at = text.len().saturating_sub(max);
    while !text.is_char_boundary(at) {
        at += 1;
    }
    &text[at..]
}

fn log_from(home: &std::path::Path, offset: u64) -> String {
    let Ok(mut file) = File::open(home.join("qsh/log")) else {
        return String::new();
    };
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut bytes = Vec::new();
    file.take(8192).read_to_end(&mut bytes).unwrap();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn ready_since(home: &std::path::Path, offset: u64) -> bool {
    log_from(home, offset)
        .lines()
        .any(|line| line.contains("shell channel ") && line.ends_with(" ready"))
}

fn tokens(home: &std::path::Path) -> Vec<Vec<u8>> {
    let mut files: Vec<_> = std::fs::read_dir(home.join("qsh/sessions"))
        .unwrap()
        .take(9)
        .map(|file| file.unwrap().path())
        .collect();
    assert!(files.len() <= 8, "bounded owned session fixture");
    files.sort();
    files
        .into_iter()
        .map(|file| {
            assert!(file.metadata().unwrap().len() <= 4096);
            std::fs::read(file).unwrap()
        })
        .collect()
}

fn scenario_fresh(
    fresh: &mut FreshFixture,
    child: &ClientCustody,
    cancel: &AtomicBool,
    master: &mut File,
    slave: &std::os::fd::OwnedFd,
    saved: &nix::sys::termios::Termios,
) {
    let mut output = Vec::new();
    assert!(
        fresh_until(cancel, || {
            drain(master, &mut output);
            ready_since(&fresh.client_home, 0)
        }),
        "initial current Ready missing: {}",
        String::from_utf8_lossy(&output)
    );
    master.write_all(b"echo BEFORE'FRESH'\n").unwrap();
    assert!(
        fresh_until(cancel, || {
            drain(master, &mut output);
            String::from_utf8_lossy(&output).contains("BEFOREFRESH")
        }),
        "initial shell did not answer: {}\nlog: {}\ndaemon: {}",
        String::from_utf8_lossy(&output[output.len().saturating_sub(8192)..]),
        log_from(&fresh.client_home, 0),
        tail(&fresh.daemon.output_text(), 4096)
    );
    let old_tokens = tokens(&fresh.client_home);
    fresh.daemon.track_shell_starts();
    fresh.daemon.restart();
    assert!(fresh_until(cancel, || sshauth::discover::discover(
        ([127, 0, 0, 1], fresh.daemon.port).into(),
        Duration::from_millis(20)
    )
    .is_ok()));
    master.write_all(b"\x1dr").unwrap();
    assert!(
        fresh_until(cancel, || {
            drain(master, &mut output);
            String::from_utf8_lossy(&output).contains("Start a new session? [Y/n]")
        }),
        "Fresh consent missing: {}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(
        fresh.daemon.shell_starts(),
        0,
        "no new shell before consent"
    );
    let offset = std::fs::metadata(fresh.client_home.join("qsh/log"))
        .unwrap()
        .len();
    fresh.relay.cut();
    let before = fresh.relay.handshakes().len();
    master.write_all(b"yes\n").unwrap();
    assert!(
        fresh_until(cancel, || {
            drain(master, &mut output);
            fresh.relay.handshakes().len() > before
        }),
        "no actual replacement attempt after consent"
    );
    let replacement_tokens = tokens(&fresh.client_home);
    assert!(
        old_tokens != replacement_tokens,
        "consent must commit one new identity"
    );
    stop_twice("fresh", child, cancel, master, slave, saved);
    assert!(
        tokens(&fresh.client_home) == replacement_tokens,
        "resume must retain replacement identity"
    );
    assert_eq!(
        fresh.daemon.shell_starts(),
        0,
        "withheld replacement must not open a shell"
    );
    fresh.relay.restore();
    assert!(
        fresh_until(cancel, || {
            drain(master, &mut output);
            ready_since(&fresh.client_home, offset)
        }),
        "replacement current Ready missing: {}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(
        fresh.daemon.shell_starts(),
        1,
        "one consented shell, no duplicate open on continue"
    );
    master.write_all(b"echo AFTER'FRESH'\n").unwrap();
    assert!(
        fresh_until(cancel, || {
            drain(master, &mut output);
            String::from_utf8_lossy(&output).contains("AFTERFRESH")
        }),
        "replacement shell did not answer"
    );
    master.write_all(b"exit\n").unwrap();
    assert!(fresh_until(cancel, || child.status().unwrap().is_some()));
    assert_eq!(child.status().unwrap().unwrap().code(), Some(0));
    assert_eq!(nix::sys::termios::tcgetattr(slave).unwrap(), *saved);
    assert_eq!(
        String::from_utf8_lossy(&output)
            .matches("Start a new session? [Y/n]")
            .count(),
        1
    );
}
