//! Linux monitor startup reports and native custody advance as one owned step.

use super::super::server::CLOSE_GRACE_PERIOD;
use super::super::shell_owner::ShellOwner;
use super::super::startup::{Failure, Outcome, StartupReader};
use crate::process_scope::{
    scope::{LeaderStatus, Progress},
    QualifiedProc,
};
use nix::libc;
use std::io::{self, Read};
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::time::Instant;

pub(super) struct NativeShell {
    owner: ShellOwner,
    report: Option<OwnedFd>,
    startup: StartupReader,
    started: bool,
    outcome_reported: bool,
    session_established: bool,
    leader_reported: bool,
    stop_at: Option<Instant>,
}
pub(super) struct Advance {
    pub(super) startup: Option<Outcome>,
    pub(super) leader: Option<i32>,
    pub(super) progress: Progress,
    pub(super) signal_failure: Option<(i32, i32)>,
}
struct Report<'a>(&'a OwnedFd);
impl Read for Report<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let result =
            unsafe { libc::read(self.0.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(result as usize)
        }
    }
}
impl NativeShell {
    /// Infallible successful-fork parent construction, before descriptor drops
    /// or publication. Proc qualification and nonblocking report setup precede fork.
    pub(super) fn new(
        pid: NonZeroU32,
        view: QualifiedProc,
        report: OwnedFd,
        deadline: Instant,
    ) -> Self {
        let owner = ShellOwner::new(pid, view);
        Self {
            owner,
            report: Some(report),
            startup: StartupReader::new(pid.get(), deadline),
            started: false,
            outcome_reported: false,
            session_established: false,
            leader_reported: false,
            stop_at: None,
        }
    }
    pub(super) fn report_fd(&self) -> Option<RawFd> {
        self.report.as_ref().map(AsRawFd::as_raw_fd)
    }
    pub(super) fn request_stop(&mut self, now: Instant) {
        self.startup.cancel();
        self.owner.request_stop();
        self.stop_at.get_or_insert(now);
    }
    /// Every entry drains queued startup stages BEFORE observing/finally reaping
    /// the leader. Cancellation never retires that private authority stream.
    pub(super) fn advance(&mut self, now: Instant) -> Advance {
        let mut startup = None;
        if let Some(report) = self.report.as_ref() {
            let update = self.startup.poll(&mut Report(report), now);
            let established = update.established.map(|proof| self.owner.establish(proof));
            if established == Some(true) {
                self.session_established = true;
            }
            startup = if established == Some(false) {
                Some(Outcome::Failed(Failure::Read))
            } else {
                update.outcome
            };
            if self.startup.finished() {
                self.report = None;
            }
        }
        if startup.is_some() {
            if self.outcome_reported {
                startup = None;
            } else {
                self.outcome_reported = true;
            }
        }
        match startup {
            Some(Outcome::Started) => self.started = true,
            Some(Outcome::Failed(_)) => self.request_stop(now),
            None => {}
        }
        let leader = match self.owner.leader() {
            LeaderStatus::Exited(code) => {
                self.owner.request_stop();
                self.stop_at.get_or_insert(now);
                if self.started && !self.leader_reported {
                    self.leader_reported = true;
                    Some(code)
                } else {
                    None
                }
            }
            _ => None,
        };
        if self
            .stop_at
            .is_some_and(|started| now.saturating_duration_since(started) >= CLOSE_GRACE_PERIOD)
        {
            self.owner.escalate();
        }
        let progress = match self.owner.progress(self.startup.pre_session_terminal()) {
            // Final scope exit alone cannot retire an unread startup stream.
            // The owner latches its actual final reap and never reobserves PID.
            Progress::Complete(_) if !self.startup.finished() || self.report.is_some() => {
                Progress::Pending
            }
            Progress::Pending
                if self.startup.finished()
                    && !self.session_established
                    && !self.startup.pre_session_terminal() =>
            {
                Progress::Unknown
            }
            progress => progress,
        };
        Advance {
            startup,
            leader,
            progress,
            signal_failure: self.owner.take_signal_failure(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;
    struct Fixture {
        child: Child,
        reaped: bool,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if self.reaped {
                return;
            }
            loop {
                match self.child.try_wait() {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Ok(Some(_)) => return,
                    Err(error) if error.raw_os_error() == Some(libc::ECHILD) => return,
                    Err(error) => panic!("owned fixture wait: {error}"),
                    Ok(None) => break,
                }
            }
            let _ = self.child.kill();
            loop {
                match self.child.wait() {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    result => {
                        result.unwrap();
                        break;
                    }
                }
            }
        }
    }
    #[test]
    fn helper39_native_empty_controlled_eof_fails_then_waits_for_actual_receipt() {
        let view = crate::process_scope::prepare().unwrap();
        let (input, output) = UnixStream::pair().unwrap();
        input.set_nonblocking(true).unwrap();
        let isolated = tempfile::tempdir().unwrap();
        for directory in ["home", "cache", "config"] {
            std::fs::create_dir(isolated.path().join(directory)).unwrap();
        }
        let mut fixture = Fixture {
            child: Command::new("/bin/sh")
                .args(["-c", "read release"])
                .env_clear()
                .env("HOME", isolated.path().join("home"))
                .env("XDG_CACHE_HOME", isolated.path().join("cache"))
                .env("XDG_CONFIG_HOME", isolated.path().join("config"))
                .env("HISTFILE", "/dev/null")
                .env("PATH", "/usr/bin:/bin")
                .current_dir(isolated.path())
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
            reaped: false,
        };
        let now = Instant::now();
        let mut native = NativeShell::new(
            NonZeroU32::new(fixture.child.id()).unwrap(),
            view,
            input.into(),
            now + Duration::from_secs(1),
        );
        // Holding this parent-owned writer makes the first advance pending.
        // The later controlled EOF is associated with the owned child; it is
        // not a report actually emitted by fork_shell's child.
        assert!(native.report_fd().is_some());
        let first = native.advance(now);
        let first_report_retained = native.report_fd().is_some();
        let first_complete = matches!(&first.progress, Progress::Complete(_));
        let mut outcomes: Vec<_> = first.startup.into_iter().collect();
        let mut leaders: Vec<_> = first.leader.into_iter().collect();
        let mut progress = first.progress;
        drop(output);
        let deadline = now + Duration::from_secs(2);
        while !matches!(progress, Progress::Complete(_)) && Instant::now() < deadline {
            let update = native.advance(Instant::now());
            outcomes.extend(update.startup);
            leaders.extend(update.leader);
            progress = update.progress;
            std::thread::sleep(Duration::from_millis(1));
        }
        fixture.reaped = matches!(progress, Progress::Complete(_));
        drop(fixture); // owned failure cleanup is complete before assertions
        assert!(
            matches!(progress, Progress::Complete(_)),
            "timeout is failure, never receipt"
        );
        assert!(first_report_retained, "pending report remains owned");
        assert_eq!(first.startup, None, "held writer has not published EOF");
        assert_eq!(first.leader, None);
        assert!(!first_complete, "pending startup cannot complete custody");
        assert_eq!(outcomes, vec![Outcome::Failed(Failure::Protocol)]);
        assert!(
            leaders.is_empty(),
            "failed startup never publishes installed Exited"
        );
        assert!(native.report_fd().is_none());
        let last = native.advance(Instant::now());
        assert_eq!(last.startup, None);
        assert_eq!(last.leader, None);
        assert!(matches!(last.progress, Progress::Complete(_)));
    }
}
