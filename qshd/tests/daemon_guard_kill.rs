//! The test guard's kill path: a daemon that acks `STOP` and does not exit
//! is killed through its pidfd, and nothing is left. The fake daemon is
//! this very test binary run again (`fake_daemon_process`) inside a temp
//! dir (the guards here are `ManuallyDrop`: `finish` is called by hand, and
//! a second run on the dead fake's leftover socket would only wait); it ends on its own after `FAKE_LIFETIME` whatever happens.

mod daemon_guard;

use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use daemon_guard::{DaemonGuard, Finished};
use qshd::control::StatusResponse;

const ENV_SOCK: &str = "QSHD_FAKE_DAEMON_SOCK";
const ENV_MODE: &str = "QSHD_FAKE_DAEMON_MODE";
const FAKE_LIFETIME: Duration = Duration::from_secs(60);

/// Not a test unless re-run as the fake daemon: answers STATUS with its own
/// pid, acks STOP and (in `ignore-stop` mode) carries on.
#[test]
fn fake_daemon_process() {
    let Ok(sock) = std::env::var(ENV_SOCK) else {
        return;
    };
    let exits_on_stop = std::env::var(ENV_MODE).is_ok_and(|m| m == "obey-stop");
    let listener = UnixListener::bind(&sock).expect("bind the fake control socket");
    listener.set_nonblocking(true).unwrap();
    let end = Instant::now() + FAKE_LIFETIME;
    while Instant::now() < end {
        let Ok((mut s, _)) = listener.accept() else {
            std::thread::sleep(Duration::from_millis(20));
            continue;
        };
        s.set_nonblocking(false).unwrap();
        let mut line = String::new();
        let _ = std::io::BufRead::read_line(&mut std::io::BufReader::new(&s), &mut line);
        let reply = if line.trim() == "STOP" {
            "{\"stopped\":true}\n".to_string()
        } else {
            StatusResponse {
                version: "fake".into(),
                build: 0,
                checksum: String::new(),
                ports: vec![],
                total_connections: 0,
                pid: std::process::id(),
            }
            .to_line()
            .unwrap()
        };
        let _ = std::io::Write::write_all(&mut s, reply.as_bytes());
        if line.trim() == "STOP" && exits_on_stop {
            std::process::exit(0);
        }
    }
}

fn start_fake(dir: &std::path::Path, mode: &str) -> std::process::Child {
    let sock = dir.join("control.sock");
    let child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "fake_daemon_process", "--nocapture"])
        .env(ENV_SOCK, &sock)
        .env(ENV_MODE, mode)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start the fake daemon");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !sock.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(sock.exists(), "the fake daemon never bound its socket");
    child
}

/// The fake is this test's child, so unlike a real (daemonized) daemon it
/// stays a zombie until reaped, and `/proc/<pid>` would outlive it: a
/// thread reaps it the moment it ends and hands back how.
fn reap(mut child: std::process::Child) -> std::thread::JoinHandle<std::process::ExitStatus> {
    std::thread::spawn(move || child.wait().expect("reap the fake"))
}

/// The point: STOP is acked and ignored; the guard kills exactly that process.
#[test]
fn a_daemon_that_ignores_stop_is_killed_through_its_pidfd() {
    let dir = tempfile::tempdir().unwrap();
    let child = start_fake(dir.path(), "ignore-stop");
    let pid = child.id();
    let reaper = reap(child);
    let guard = std::mem::ManuallyDrop::new(DaemonGuard::with_patience(
        dir.path().join("control.sock"),
        Duration::from_secs(2),
    ));
    let result = guard.finish();
    let status = reaper.join().unwrap();
    assert_eq!(result, Finished::Killed { pid }, "{result:?}");
    use std::os::unix::process::ExitStatusExt;
    assert_eq!(status.signal(), Some(9), "killed by SIGKILL: {status:?}");
    assert!(
        !std::path::Path::new(&format!("/proc/{pid}")).exists(),
        "nothing is left of the fake"
    );
}

/// A daemon that obeys STOP is not signalled at all.
#[test]
fn a_daemon_that_obeys_stop_is_not_killed() {
    let dir = tempfile::tempdir().unwrap();
    let child = start_fake(dir.path(), "obey-stop");
    let reaper = reap(child);
    let guard = std::mem::ManuallyDrop::new(DaemonGuard::with_patience(
        dir.path().join("control.sock"),
        Duration::from_secs(5),
    ));
    let result = guard.finish();
    let status = reaper.join().unwrap();
    assert_eq!(result, Finished::Stopped, "{result:?}");
    assert_eq!(status.code(), Some(0), "exited by itself: {status:?}");
}

/// No daemon at all: nothing to do, nothing killed.
#[test]
fn no_daemon_is_no_work() {
    let dir = tempfile::tempdir().unwrap();
    let guard = DaemonGuard::new(dir.path().join("control.sock"));
    assert_eq!(guard.finish(), Finished::Stopped);
}
