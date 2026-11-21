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
use std::net::{Ipv4Addr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use transport::channel::FIRST_CHANNEL_STREAM;
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;

mod daemon_guard;
use daemon_guard::DaemonGuard;
mod hosted_daemon;
use hosted_daemon::*;

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

/// The frontend is SIGKILLed in the middle of a paste into the session's
/// shell, which has become a program that records every byte its terminal
/// gives it. Input that was inside the dead frontend may be lost, but only
/// as a tail, and none is delivered twice: what the program received is
/// exactly a leading part of the first client's paste -- each line once, in
/// order -- followed by exactly what the returning client sent.
///
/// How much of the tail is lost depends on timing (what the frontend had
/// taken but not yet passed on to the owner when it died), so only its
/// shape is asserted, never its length.
#[test]
fn killing_the_frontend_mid_paste_never_duplicates_input() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let token = [78; 16];
    let session = Session::connect(&daemon, token);
    let shell = session.open_shell("kept-78");
    let owner = owner_of(shell, daemon.pid());
    let record = daemon.dir.path().join("pasted");
    session.send(&format!(
        "stty raw -echo; exec cat > {}\n",
        record.display()
    ));
    assert!(
        wait_until(Duration::from_secs(15), || comm(shell) == "cat"),
        "the shell becomes the recording program; saw {:?}",
        session.shell_text()
    );
    let received = || std::fs::read(&record).unwrap_or_default();
    let frontend = frontend_of(daemon.pid());

    // The first client pastes numbered lines; its frontend is killed once
    // the program has taken a good part, and the client goes on a little.
    let mut sent = Vec::new();
    let mut killed_at = None;
    for n in 0..4000u32 {
        let line = paste_line(n);
        if session
            .client
            .send_bytes(FIRST_CHANNEL_STREAM, line.clone())
            .is_err()
        {
            break;
        }
        sent.extend(line);
        if killed_at.is_none() && received().len() >= 4096 {
            kill_frontend(daemon.pid(), frontend);
            killed_at = Some(n);
        }
        if killed_at.is_some_and(|at| n >= at + 200) {
            break;
        }
        if n % 64 == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    assert!(
        killed_at.is_some(),
        "the program takes the paste: {} bytes of {} sent; log: {}",
        received().len(),
        sent.len(),
        daemon.log()
    );
    frontend_after(daemon.pid(), frontend);
    session.client.detach();
    assert!(
        running(shell) && running(owner),
        "the session outlived its frontend"
    );

    // The returning client pastes lines of its own.
    let back = Session::come_back(&daemon, token);
    let mut later = Vec::new();
    for n in 0..300u32 {
        let line = paste_line(900_000 + n);
        back.client
            .send_bytes(FIRST_CHANNEL_STREAM, line.clone())
            .expect("input admitted on the new connection");
        later.extend(line);
    }
    assert!(
        wait_until(Duration::from_secs(20), || received().ends_with(&later)),
        "the returning client's paste arrives whole; the program has {} bytes; log: {}",
        received().len(),
        daemon.log()
    );
    // Nothing trails in later.
    std::thread::sleep(Duration::from_millis(500));
    let got = received();
    assert!(
        got.ends_with(&later),
        "nothing arrived after the second paste"
    );
    let first = &got[..got.len() - later.len()];
    assert!(
        sent.starts_with(first),
        "what arrived of the first paste is a leading part of it, each byte once: \
         {} bytes arrived, {} sent",
        first.len(),
        sent.len()
    );
    assert!(
        first.len() >= 4096,
        "what the program had taken before the kill stays taken ({} bytes)",
        first.len()
    );
    assert_eq!(ppid(shell), Some(owner), "the same program, the same owner");

    back.client.close();
    let status = daemon.stop();
    assert!(status.success(), "{status:?}; log: {}", daemon.log());
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

/// The daemon is stopped while no frontend runs (the host is waiting
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

// ---- hardening ---------------------------------------------------------------------

/// How often `needle` is in `log`.
fn count(log: &str, needle: &str) -> usize {
    log.matches(needle).count()
}

/// An owner killed under a live session: that session is lost, as every
/// session of a single-process daemon is when it dies. The host reaps the
/// owner -- no zombie of its own -- and takes the session off its catalog;
/// the shell goes with its terminal's hangup. The client is told of no
/// close: its session did not end, it was lost, and it finds that out when
/// it returns and lands in a fresh session (the existing session-loss
/// flow). The daemon and its frontend serve on.
#[test]
fn killed_owner_gives_session_loss_and_no_zombies() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let token = [73; 16];
    let session = Session::connect(&daemon, token);
    let shell = session.open_shell("kept-73");
    let owner = owner_of(shell, daemon.pid());
    let frontend = frontend_of(daemon.pid());

    assert_eq!(unsafe { libc::kill(owner as i32, libc::SIGKILL) }, 0);
    assert!(
        wait_until(Duration::from_secs(10), || reaped(owner)),
        "the host reaps the killed owner"
    );
    assert!(
        wait_until(Duration::from_secs(10), || reaped(shell)),
        "its shell ends with its terminal"
    );
    assert_eq!(zombies_of(daemon.pid()), Vec::<u32>::new());
    assert!(
        wait_until(Duration::from_secs(10), || session.client.is_gone()),
        "the client hears that its connection is gone; log: {}",
        daemon.log()
    );
    assert!(
        !session.client.closed_gracefully(),
        "a lost session is not closed; log: {}",
        daemon.log()
    );
    session.client.detach();

    let back = Session::come_back(&daemon, token);
    assert!(!back.client.resumed(), "the session is lost");
    let fresh = back.open_shell("fresh-73");
    assert_ne!(fresh, shell);
    assert_eq!(
        frontends_of(daemon.pid()),
        [frontend],
        "the frontend served on"
    );
    let log = daemon.log();
    assert!(
        log.contains(&format!("session owner {owner} exited (signal 9)")),
        "log: {log}"
    );
    back.client.close();
    assert!(wait_until(Duration::from_secs(20), || reaped(fresh)));
    // The killed owner sent no receipt, but nothing of its session is left:
    // the host proves that itself, so the stop is clean -- and leaves
    // nothing behind.
    assert!(daemon.stop().success(), "log: {}", daemon.log());
    assert_eq!(zombies_of(daemon.pid()), Vec::<u32>::new());
}

/// Sessions up to an account's cap across a frontend death: every
/// one comes back to its own shell; while the new frontend's router knows
/// none of them yet, the host still refuses a session over the cap (the
/// caps are the host's, once, not each frontend's or owner's); and once
/// they are all closed, every lease is back: the account starts as many
/// sessions again, and the stop proves every owner's cleanup.
#[test]
fn many_sessions_survive_frontend_death_with_budgets_intact() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let cap = transport::session_manager::MAX_SESSIONS_PER_OWNER as u8;
    let tokens: Vec<[u8; 16]> = (0..cap).map(|i| [100 + i; 16]).collect();
    let mut shells = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let session = Session::connect(&daemon, *token);
        shells.push(session.open_shell(&format!("many-{i}")));
        session.client.detach();
    }
    assert_eq!(owners_of(daemon.pid()).len(), cap as usize);

    let frontend = frontend_of(daemon.pid());
    kill_frontend(daemon.pid(), frontend);
    frontend_after(daemon.pid(), frontend);

    // The new router has heard of none of them: the host refuses.
    let refused = "no session owner for";
    if let Some(extra) = Session::start_within(
        daemon.port,
        daemon.server_pub,
        Proof::Signature(&daemon.key_path),
        [99; 16],
        StartKind::Cold,
        Duration::from_secs(5),
    ) {
        assert!(wait_until(Duration::from_secs(10), || extra
            .client
            .is_gone()));
    }
    assert!(
        wait_until(Duration::from_secs(5), || count(&daemon.log(), refused)
            == 1),
        "the host refused a session over the cap; log: {}",
        daemon.log()
    );
    assert_eq!(owners_of(daemon.pid()).len(), cap as usize);

    let mut back = Vec::new();
    for (i, token) in tokens.iter().enumerate() {
        let session = Session::come_back(&daemon, *token);
        assert_eq!(session.same_shell(&format!("many-{i}")), shells[i]);
        back.push(session);
    }
    for session in &back {
        session.client.close();
    }
    assert!(
        wait_until(Duration::from_secs(30), || shells
            .iter()
            .all(|pid| reaped(*pid))
            && owners_of(daemon.pid()).is_empty()),
        "every closed session is reaped; log: {}",
        daemon.log()
    );

    // Every lease is back: a full account's worth of sessions again.
    let mut again = Vec::new();
    for i in 0..cap {
        again.push(Session::connect(&daemon, [120 + i; 16]));
    }
    assert!(
        wait_until(Duration::from_secs(10), || owners_of(daemon.pid()).len()
            == cap as usize),
        "each has its owner; log: {}",
        daemon.log()
    );
    assert_eq!(count(&daemon.log(), refused), 1, "none refused");
    for session in &again {
        session.client.close();
    }
    assert!(daemon.stop().success(), "log: {}", daemon.log());
}

/// `cap` sessions of one account, the first two with a shell: their
/// sessions and those two shells.
fn full_account(daemon: &Daemon, first: u8) -> (Vec<Session>, [u32; 2]) {
    let cap = transport::session_manager::MAX_SESSIONS_PER_OWNER as u8;
    let mut sessions = Vec::new();
    let mut shells = [0; 2];
    for i in 0..cap {
        let session = Session::connect(daemon, [first + i; 16]);
        if (i as usize) < shells.len() {
            shells[i as usize] = session.open_shell(&format!("full-{i}"));
        }
        sessions.push(session);
    }
    (sessions, shells)
}

/// A host whose account is full after a frontend death evicts the oldest
/// retained session for a new one, as a router does: the session nobody
/// came back for goes, with its owner and shell; the new one starts; every
/// other session is kept.
#[test]
fn a_full_host_evicts_its_oldest_retained_session_for_a_new_one() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let (sessions, [victim, kept]) = full_account(&daemon, 140);
    let victim_owner = owner_of(victim, daemon.pid());
    let kept_owner = owner_of(kept, daemon.pid());
    // The first session loses its link: retained, at the host too.
    sever_first_link(victim_owner, &daemon);
    let retained = format!("session owner={victim_owner} retained since=");
    assert!(
        wait_until(Duration::from_secs(10), || daemon.log().contains(&retained)),
        "log: {}",
        daemon.log()
    );
    for session in &sessions {
        session.client.detach();
    }
    let frontend = frontend_of(daemon.pid());
    kill_frontend(daemon.pid(), frontend);
    frontend_after(daemon.pid(), frontend);

    let new = Session::connect(&daemon, [170; 16]);
    let shell = new.open_shell("evicting");
    assert!(
        wait_until(Duration::from_secs(20), || reaped(victim)
            && reaped(victim_owner)),
        "the retained session went; log: {}",
        daemon.log()
    );
    assert!(running(kept) && running(kept_owner), "the others are kept");
    assert!(!daemon.log().contains("every session envelope is taken"));
    let back = Session::come_back(&daemon, [141; 16]);
    assert_eq!(back.same_shell("full-1"), kept);
    new.client.close();
    back.client.close();
    assert!(wait_until(Duration::from_secs(20), || reaped(shell)));
    assert!(daemon.stop().success(), "log: {}", daemon.log());
}

/// A router at its account's cap evicts its own oldest retained session
/// for a new one; the host gives that session's lease back as soon as the
/// router has ended it -- not once its owner is reaped -- so the new
/// session starts at once. The evicted session's owner ends too, though
/// its link is lost and no `End` reaches it.
#[test]
fn a_session_the_router_evicts_frees_its_lease_at_once() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let (sessions, [victim, kept]) = full_account(&daemon, 180);
    let victim_owner = owner_of(victim, daemon.pid());
    sever_first_link(victim_owner, &daemon);
    sessions[0].client.detach();

    let new = Session::connect(&daemon, [210; 16]);
    let shell = new.open_shell("evicting");
    assert!(
        wait_until(Duration::from_secs(20), || reaped(victim)
            && reaped(victim_owner)),
        "the evicted session's owner ends; log: {}",
        daemon.log()
    );
    assert!(running(kept));
    assert!(!daemon.log().contains("every session envelope is taken"));
    new.client.close();
    for session in &sessions {
        session.client.close();
    }
    assert!(wait_until(Duration::from_secs(20), || reaped(shell) && reaped(kept)));
    assert!(daemon.stop().success(), "log: {}", daemon.log());
}

/// A frontend that is alive but answers nothing -- here stopped -- is found
/// out by the host within a bounded time and replaced like a dead one; the
/// session it served survives and its client comes back to the same shell.
/// An idle frontend that answers is kept, however long it is idle.
#[test]
fn a_wedged_frontend_is_replaced_and_its_sessions_survive() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let token = [74; 16];
    let session = Session::connect(&daemon, token);
    let shell = session.open_shell("kept-74");
    let owner = owner_of(shell, daemon.pid());
    let frontend = frontend_of(daemon.pid());
    session.client.detach();
    // Longer than the host waits for an answer: asked, and answering.
    std::thread::sleep(Duration::from_secs(25));
    assert_eq!(
        frontends_of(daemon.pid()),
        [frontend],
        "an idle frontend is kept"
    );

    let stopped = Instant::now();
    assert_eq!(unsafe { libc::kill(frontend as i32, libc::SIGSTOP) }, 0);
    let mut next = Vec::new();
    assert!(
        wait_until(Duration::from_secs(60), || {
            next = frontends_of(daemon.pid());
            next.len() == 1 && next[0] != frontend
        }),
        "the host replaces its wedged frontend; log: {}",
        daemon.log()
    );
    let found = stopped.elapsed();
    assert!(reaped(frontend), "and reaps it");
    assert!(
        found >= Duration::from_secs(10) && found < Duration::from_secs(40),
        "not on a moment's silence, and within its bound: {found:?}"
    );
    assert!(running(shell) && running(owner));
    let back = Session::come_back(&daemon, token);
    assert_eq!(back.same_shell("kept-74"), shell);
    back.client.close();
    assert!(daemon.stop().success(), "log: {}", daemon.log());
}

/// Signal exactly the frontend `pid` of `host` (checked to still be it).
fn signal_frontend(host: u32, pid: u32, signal: i32) {
    assert_eq!(
        (ppid(pid), role_of(pid).as_deref()),
        (Some(host), Some(FRONTEND_ROLE)),
        "pid {pid} is the daemon's frontend"
    );
    assert_eq!(unsafe { libc::kill(pid as i32, signal) }, 0);
}

/// A frontend told to go by `SIGTERM` or `SIGINT` -- a plain `kill`, or a
/// `^C` that reaches it -- shuts down in order, and still ends no session:
/// its router's last sweep is no end of a login. The client comes back to
/// the same shell, each time.
#[test]
fn a_frontend_stopped_by_sigterm_or_sigint_keeps_every_session() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let token = [75; 16];
    let session = Session::connect(&daemon, token);
    let shell = session.open_shell("kept-75");
    let owner = owner_of(shell, daemon.pid());
    session.client.detach();
    let mut frontend = frontend_of(daemon.pid());
    for signal in [libc::SIGTERM, libc::SIGINT] {
        signal_frontend(daemon.pid(), frontend, signal);
        frontend = frontend_after(daemon.pid(), frontend);
        assert!(
            running(shell) && running(owner),
            "signal {signal}: the session outlived its frontend; log: {}",
            daemon.log()
        );
        let back = Session::come_back(&daemon, token);
        assert_eq!(back.same_shell("kept-75"), shell);
        back.client.detach();
    }
    let back = Session::come_back(&daemon, token);
    back.client.close();
    assert!(wait_until(Duration::from_secs(20), || reaped(shell)));
    assert!(daemon.stop().success(), "log: {}", daemon.log());
}

/// An owner the host told to stop that does not -- here stopped itself --
/// is killed through its pidfd after the host's stop escalation, and
/// reaped: no owner outlives its session's end for long, counted or not.
#[test]
fn an_owner_that_does_not_stop_when_told_is_killed() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let session = Session::connect(&daemon, [76; 16]);
    let shell = session.open_shell("kept-76");
    let owner = owner_of(shell, daemon.pid());
    assert_eq!(unsafe { libc::kill(owner as i32, libc::SIGSTOP) }, 0);
    let closed = Instant::now();
    // The router ends the login; the host tells the owner to stop.
    session.client.close();
    assert!(
        wait_until(Duration::from_secs(40), || reaped(owner)),
        "the host kills and reaps the owner; log: {}",
        daemon.log()
    );
    let took = closed.elapsed();
    assert!(
        took >= Duration::from_secs(15),
        "not before the escalation: {took:?}"
    );
    assert!(wait_until(Duration::from_secs(10), || reaped(shell)));
    assert!(
        daemon
            .log()
            .contains(&format!("session owner {owner} did not stop")),
        "log: {}",
        daemon.log()
    );
    // It sent no receipt, but nothing of its session is left (its shell
    // ended with its terminal): the host proves that, and the stop is clean.
    assert!(daemon.stop().success(), "log: {}", daemon.log());
}

/// The processes whose whole command line is `args`.
fn processes_running(args: &[&str]) -> Vec<u32> {
    let want: Vec<u8> = args
        .iter()
        .flat_map(|a| [a.as_bytes(), b"\0"].concat())
        .collect();
    pids()
        .into_iter()
        .filter(|pid| std::fs::read(format!("/proc/{pid}/cmdline")).is_ok_and(|c| c == want))
        .collect()
}

/// A process the test left running, pinned by a pidfd when it was found:
/// SIGKILLed through it when dropped, so a failing test leaves nothing
/// behind -- never signalled by a bare number.
struct Leftover {
    pid: u32,
    pidfd: OwnedFd,
}

impl Leftover {
    /// The one process running `args`.
    fn find(args: &[&str]) -> Leftover {
        let mut found = Vec::new();
        assert!(
            wait_until(Duration::from_secs(15), || {
                found = processes_running(args);
                found.len() == 1
            }),
            "one process runs {args:?}: {found:?}"
        );
        let pid = found[0];
        let pidfd = pidfd_open(pid);
        // Still that process now that it is pinned.
        assert_eq!(processes_running(args), [pid]);
        Leftover { pid, pidfd }
    }
}

impl Drop for Leftover {
    fn drop(&mut self) {
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
    }
}

/// While a process that a dead owner left in its session still runs --
/// here a job that ignores the hangup, in the shell's own session -- the
/// host proves nothing: the stop is not clean, and the daemon's log names
/// the session and the process still in it.
#[test]
fn a_dead_owners_leftover_fails_the_stop() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let session = Session::connect(&daemon, [78; 16]);
    let shell = session.open_shell("kept-78");
    let owner = owner_of(shell, daemon.pid());
    let marker = format!("{}.528", daemon.port);
    session.send(&format!("(trap '' HUP TERM INT; exec sleep {marker}) &\n"));
    // Dropped before the daemon: declared after it.
    let job = Leftover::find(&["sleep", marker.as_str()]);
    assert_eq!(unsafe { libc::kill(owner as i32, libc::SIGKILL) }, 0);
    assert!(
        wait_until(Duration::from_secs(10), || reaped(owner)),
        "the host reaps the killed owner"
    );
    session.client.detach();
    assert!(running(job.pid), "the job outlives its owner");

    assert!(
        !daemon.stop().success(),
        "a stop while the job runs is not clean; log: {}",
        daemon.log()
    );
    let log = daemon.log();
    let named = format!("session {shell} of session owner {owner} ");
    assert!(
        log.lines()
            .any(|line| line.contains(&named) && line.contains(&job.pid.to_string())),
        "the log names the session and the job; log: {log}"
    );
    assert!(running(job.pid), "the host kills nothing there");
}

/// An owner whose host channel closes (here: severed, while the owner is
/// stopped) but whose process lives on is not waited for without end:
/// the host kills it through its pidfd after the stop escalation, and
/// reaps it.
#[test]
fn an_owner_that_closes_its_host_channel_but_lives_is_killed() {
    let _serial = serialised();
    let mut daemon = start_daemon();
    let session = Session::connect(&daemon, [77; 16]);
    let shell = session.open_shell("kept-77");
    let owner = owner_of(shell, daemon.pid());
    assert_eq!(unsafe { libc::kill(owner as i32, libc::SIGSTOP) }, 0);
    // Descriptor 4 is the owner's end of its host channel.
    let pidfd = pidfd_open(owner);
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), 4, 0) };
    assert!(raw >= 0, "pidfd_getfd: {}", std::io::Error::last_os_error());
    let channel = unsafe { OwnedFd::from_raw_fd(raw as i32) };
    let severed = Instant::now();
    assert_eq!(
        unsafe { libc::shutdown(channel.as_raw_fd(), libc::SHUT_RDWR) },
        0
    );
    drop(channel);
    assert!(
        wait_until(Duration::from_secs(40), || reaped(owner)),
        "the host kills and reaps the owner; log: {}",
        daemon.log()
    );
    let took = severed.elapsed();
    assert!(
        took >= Duration::from_secs(15),
        "not before the escalation: {took:?}"
    );
    assert!(
        daemon
            .log()
            .contains(&format!("session owner {owner} closed its host channel")),
        "log: {}",
        daemon.log()
    );
    session.client.detach();
    assert!(wait_until(Duration::from_secs(10), || reaped(shell)));
    // Nothing of its session is left: the host proves that, and the stop
    // is clean.
    assert!(daemon.stop().success(), "log: {}", daemon.log());
}
