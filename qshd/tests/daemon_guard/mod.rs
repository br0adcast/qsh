//! Stops a test's OWN daemon when the test ends, however it ends.
//!
//! The guard is given the daemon's control socket, always a path inside the
//! test's temp dir -- never the developer's own `~/.cache/qsh`. On drop it:
//!
//! 1. reads the daemon's pid from its own `STATUS` answer and opens a pidfd
//!    for that pid right then, while the daemon is alive and answering (a
//!    pidfd keeps referring to that process, so a reused pid can never be
//!    signalled by mistake); a second `STATUS` must name the same pid, or
//!    no pidfd is kept;
//! 2. calls `qshd::control::stop_daemon_and_wait` (signal-free, the library
//!    never kills);
//! 3. if that reports the process still there, sends `SIGKILL` once through
//!    the pidfd and waits a bounded time for it to go.
//!
//! With no pid or no pidfd nothing is ever killed, only reported. Nothing
//! is signalled by a bare pid number, and nothing but that pidfd's process.
//! Declare the guard AFTER the temp dir so it drops first: the daemon is
//! gone before the directory holding its socket.
//!
//! Used by the qshd tests and, through `#[path]`, by bringup's sandbox.

#![allow(dead_code)]

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use qshd::control::{
    client_request, stop_daemon_and_wait, ControlReply, ControlRequest, StatusResponse, StopOutcome,
};

/// How long the guard waits for the daemon to answer, and again for it to
/// go, before it reports (and, with a pidfd, kills).
pub const DAEMON_STATUS_TIMEOUT: Duration = Duration::from_secs(15);
/// How long it waits for a killed process to be gone.
const KILL_WAIT: Duration = Duration::from_secs(5);

pub struct DaemonGuard {
    sock: PathBuf,
    patience: Duration,
}

/// What became of the daemon, for the tests of the guard itself.
#[derive(Debug, PartialEq, Eq)]
pub enum Finished {
    /// It went (or there was none) without a signal.
    Stopped,
    /// `STOP` did not end it; it was killed through its pidfd and is gone.
    Killed { pid: u32 },
    /// Still there, and nothing could be done about it.
    Leaked(String),
}

impl DaemonGuard {
    pub fn new(sock: PathBuf) -> Self {
        Self::with_patience(sock, DAEMON_STATUS_TIMEOUT)
    }

    pub fn with_patience(sock: PathBuf, patience: Duration) -> Self {
        DaemonGuard { sock, patience }
    }

    /// Does the work of `drop` and says what happened.
    pub fn finish(&self) -> Finished {
        let armed = self.arm();
        let outcome = stop_daemon_and_wait(&self.sock, self.patience);
        match outcome {
            StopOutcome::NoDaemon | StopOutcome::Stopped { .. } => Finished::Stopped,
            StopOutcome::NeverAnswered => Finished::Leaked(format!(
                "the daemon never answered STATUS, so no STOP was sent: {outcome:?}"
            )),
            StopOutcome::StillThere { pid, .. } => match armed {
                Some((armed_pid, pidfd)) if armed_pid == pid => kill_through(&pidfd, pid),
                _ => Finished::Leaked(format!(
                    "still there and no pidfd for it, not killing: {outcome:?}"
                )),
            },
        }
    }

    /// The daemon's pid and a pidfd opened for it while it answers; `None`
    /// when there is no daemon, it names no pid, or it will not stay put.
    fn arm(&self) -> Option<(u32, OwnedFd)> {
        let deadline = Instant::now() + self.patience;
        let pid = loop {
            if let Some(pid) = self.status_pid() {
                break pid;
            }
            if !self.sock.exists() || Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        if pid == 0 {
            return None;
        }
        let pidfd = pidfd_open(pid).ok()?;
        // The pid was taken from the daemon's own answer and the pidfd
        // opened after it: ask once more that the same daemon is still
        // behind the socket, so the pidfd is certainly that process.
        (self.status_pid() == Some(pid)).then_some((pid, pidfd))
    }

    fn status_pid(&self) -> Option<u32> {
        match client_request(&self.sock, &ControlRequest::Status) {
            Ok(ControlReply::Answered(line)) => {
                StatusResponse::from_line(&line).ok().map(|s| s.pid)
            }
            _ => None,
        }
    }
}

impl Drop for DaemonGuard {
    fn drop(&mut self) {
        match self.finish() {
            Finished::Stopped => {}
            Finished::Killed { pid } => eprintln!(
                "the test daemon (pid {pid}) at {} ignored STOP; killed it through its pidfd",
                self.sock.display()
            ),
            Finished::Leaked(why) => {
                eprintln!("LEAK? the test daemon at {}: {why}", self.sock.display())
            }
        }
    }
}

fn kill_through(pidfd: &OwnedFd, pid: u32) -> Finished {
    // SAFETY: a plain syscall on our own pidfd; no siginfo pointer, flags 0.
    let sent = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if sent != 0 {
        return Finished::Leaked(format!(
            "pidfd_send_signal failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // A pidfd becomes readable when its process has terminated.
    let mut p = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one valid pollfd for the duration of the call.
    let ready = unsafe { libc::poll(&mut p, 1, KILL_WAIT.as_millis() as i32) };
    if ready == 1 {
        Finished::Killed { pid }
    } else {
        Finished::Leaked(format!("pid {pid} did not exit after SIGKILL"))
    }
}

fn pidfd_open(pid: u32) -> std::io::Result<OwnedFd> {
    // SAFETY: a plain syscall with no pointer arguments.
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: a non-negative return is a fresh descriptor only we hold.
    Ok(unsafe { OwnedFd::from_raw_fd(fd as i32) })
}
