//! Incremental private monitor startup framing; status and scope authority differ.

use std::io::{self, Read};
use std::time::Instant;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    Os(i32),
    Protocol,
    TimedOut,
    Cancelled,
    Read,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    Started,
    Failed(Failure),
}
/// Created only from this child's private, matching stage frame.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SessionEstablished(u32);
impl SessionEstablished {
    pub(crate) fn sid(&self) -> u32 {
        self.0
    }
}
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Update {
    pub(crate) established: Option<SessionEstablished>,
    pub(crate) outcome: Option<Outcome>,
}

pub(crate) struct StartupReader {
    sid: u32,
    deadline: Instant,
    frame: [u8; 5],
    filled: usize,
    total: usize,
    frames: usize,
    established: bool,
    failed_frame: bool,
    ambiguous: bool,
    eof: bool,
    outcome: Option<Outcome>,
    reported: bool,
}
impl StartupReader {
    pub(crate) fn new(sid: u32, deadline: Instant) -> Self {
        assert!(sid > 0 && sid <= i32::MAX as u32);
        Self {
            sid,
            deadline,
            frame: [0; 5],
            filled: 0,
            total: 0,
            frames: 0,
            established: false,
            failed_frame: false,
            ambiguous: false,
            eof: false,
            outcome: None,
            reported: false,
        }
    }
    pub(crate) fn cancel(&mut self) {
        self.fail(Failure::Cancelled);
    }
    fn fail(&mut self, error: Failure) {
        if self.outcome.is_none() {
            self.outcome = Some(Outcome::Failed(error));
        }
    }
    fn protocol_error(&mut self) {
        self.ambiguous = true;
        self.fail(Failure::Protocol);
    }
    pub(crate) fn finished(&self) -> bool {
        self.eof
    }
    /// Safe only with the matching child writer's fail-before-descendants
    /// contract. A deadline, read failure, or malformed stream is not proof.
    pub(crate) fn pre_session_terminal(&self) -> bool {
        self.eof && !self.established && !self.ambiguous && self.filled == 0
    }
    /// Input must be nonblocking. At most eleven bytes are consumed per pass:
    /// ten valid protocol bytes and one byte to detect an overlong stream.
    /// Even cancelled starts continue consuming their queued stage before reap.
    pub(crate) fn poll(&mut self, input: &mut impl Read, now: Instant) -> Update {
        if self.eof {
            return Update::default();
        }
        if now >= self.deadline {
            self.fail(Failure::TimedOut);
        }
        let mut update = Update::default();
        let mut consumed = 0;
        while consumed < 11 {
            let size = (self.frame.len() - self.filled).min(11 - consumed);
            let count = match input.read(&mut self.frame[self.filled..self.filled + size]) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => {
                    self.ambiguous = true;
                    self.fail(Failure::Read);
                    break;
                }
                Ok(0) => {
                    self.eof = true;
                    if self.filled != 0 {
                        self.protocol_error();
                    }
                    if self.outcome.is_none() {
                        if self.established && !self.ambiguous {
                            self.outcome = Some(Outcome::Started);
                        } else {
                            self.fail(Failure::Protocol);
                        }
                    }
                    break;
                }
                Ok(count) => count,
            };
            consumed += count;
            self.total = self.total.saturating_add(count).min(11);
            self.filled += count;
            if self.total > 10 {
                self.protocol_error();
            }
            if self.filled != 5 {
                continue;
            }
            if !self.ambiguous {
                let value = i32::from_ne_bytes(self.frame[1..].try_into().unwrap());
                match self.frame[0] {
                    1 if self.frames == 0 && value > 0 && value as u32 == self.sid => {
                        self.established = true;
                        update.established = Some(SessionEstablished(self.sid));
                    }
                    2 if !self.failed_frame && (1..=4095).contains(&value) => {
                        self.failed_frame = true;
                        self.fail(Failure::Os(value));
                    }
                    _ => self.protocol_error(),
                }
            }
            self.frames = self.frames.saturating_add(1);
            self.filled = 0;
        }
        if !self.reported && self.outcome.is_some() {
            self.reported = true;
            update.outcome = self.outcome;
        }
        update
    }
}

/// Incremental verification framing. A private stage precedes a bounded verdict.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct VerificationUpdate {
    pub(crate) established: Option<SessionEstablished>,
    pub(crate) result: Option<Result<Vec<u8>, Failure>>,
}

pub(crate) struct VerificationReader {
    sid: u32,
    deadline: Instant,
    max_verdict: usize,
    header: [u8; 5],
    filled: usize,
    established: bool,
    header_error: bool,
    ambiguous: bool,
    body: Vec<u8>,
    body_seen: usize,
    eof: bool,
    decided: bool,
    reported: bool,
    failure: Option<Failure>,
}
impl VerificationReader {
    pub(crate) fn new(sid: u32, deadline: Instant, max_verdict: usize) -> Self {
        assert!(sid > 0 && sid <= i32::MAX as u32);
        Self {
            sid,
            deadline,
            max_verdict,
            header: [0; 5],
            filled: 0,
            established: false,
            header_error: false,
            ambiguous: false,
            body: Vec::with_capacity(max_verdict),
            body_seen: 0,
            eof: false,
            decided: false,
            reported: false,
            failure: None,
        }
    }
    fn fail(&mut self, failure: Failure) {
        if !self.decided {
            self.decided = true;
            self.failure = Some(failure);
            self.body.clear();
        }
    }
    pub(crate) fn cancel(&mut self) {
        self.fail(Failure::Cancelled);
    }
    pub(crate) fn finished(&self) -> bool {
        self.eof
    }
    /// Only a terminal owned producer stream before any session stage proves
    /// the child performed no descendant-producing work. Cancellation is not proof.
    pub(crate) fn pre_session_terminal(&self) -> bool {
        self.eof
            && !self.established
            && !self.ambiguous
            && (self.filled == 0 || (self.header_error && self.body_seen == 0))
    }
    /// Consume at most 512 bytes per pass and yield on Interrupted. Deadline and
    /// refusal are sticky, but queued startup authority is still consumed.
    pub(crate) fn poll(&mut self, input: &mut impl Read, now: Instant) -> VerificationUpdate {
        if self.eof {
            return VerificationUpdate::default();
        }
        if now >= self.deadline {
            self.fail(Failure::TimedOut);
        }
        let mut update = VerificationUpdate::default();
        let mut chunk = [0u8; 512];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let header = self.filled < self.header.len();
            let size = if header {
                self.header.len() - self.filled
            } else {
                chunk.len() - consumed
            };
            let size = size.min(chunk.len() - consumed);
            let count = match input.read(&mut chunk[..size]) {
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::Interrupted | io::ErrorKind::WouldBlock
                    ) =>
                {
                    break
                }
                Err(_) => {
                    self.ambiguous = true;
                    self.fail(Failure::Read);
                    break;
                }
                Ok(0) => {
                    self.eof = true;
                    if self.filled != self.header.len() {
                        self.ambiguous |= self.filled != 0;
                        self.fail(Failure::Protocol);
                    } else if !self.decided {
                        self.decided = true;
                    }
                    break;
                }
                Ok(count) => count,
            };
            consumed += count;
            if header {
                self.header[self.filled..self.filled + count].copy_from_slice(&chunk[..count]);
                self.filled += count;
                if self.filled == self.header.len() {
                    let value = i32::from_ne_bytes(self.header[1..].try_into().unwrap());
                    match self.header[0] {
                        1 if !self.ambiguous && value > 0 && value as u32 == self.sid => {
                            self.established = true;
                            update.established = Some(SessionEstablished(self.sid));
                        }
                        2 if !self.ambiguous && (1..=4095).contains(&value) => {
                            self.header_error = true;
                            self.fail(Failure::Os(value));
                        }
                        _ => {
                            self.ambiguous = true;
                            self.fail(Failure::Protocol);
                        }
                    }
                }
            } else {
                self.body_seen = self
                    .body_seen
                    .saturating_add(count)
                    .min(self.max_verdict.saturating_add(1));
                if self.header_error || self.body_seen > self.max_verdict {
                    self.ambiguous = true;
                    self.fail(Failure::Protocol);
                } else if self.failure.is_none() {
                    self.body.extend_from_slice(&chunk[..count]);
                }
            }
        }
        if self.decided && !self.reported {
            self.reported = true;
            update.result = Some(match self.failure {
                Some(failure) => Err(failure),
                None => Ok(std::mem::take(&mut self.body)),
            });
        }
        update
    }
}

#[cfg(test)]
#[path = "verification_reader_tests.rs"]
mod verification_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::io::{self, Read};
    use std::time::{Duration, Instant};

    enum Input {
        Bytes(Vec<u8>),
        Block,
        Eof,
        Error,
        Interrupted,
    }
    struct Pipe(VecDeque<Input>);
    impl Read for Pipe {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            match self.0.pop_front().unwrap_or(Input::Block) {
                Input::Bytes(mut bytes) => {
                    let size = bytes.len().min(out.len());
                    out[..size].copy_from_slice(&bytes[..size]);
                    if size < bytes.len() {
                        self.0.push_front(Input::Bytes(bytes.split_off(size)));
                    }
                    Ok(size)
                }
                Input::Block => Err(io::ErrorKind::WouldBlock.into()),
                Input::Eof => Ok(0),
                Input::Error => Err(io::ErrorKind::PermissionDenied.into()),
                Input::Interrupted => Err(io::ErrorKind::Interrupted.into()),
            }
        }
    }
    fn pipe(input: impl IntoIterator<Item = Input>) -> Pipe {
        Pipe(input.into_iter().collect())
    }
    fn stage(sid: u32) -> Vec<u8> {
        let mut bytes = vec![1];
        bytes.extend(sid.to_ne_bytes());
        bytes
    }
    fn failed(errno: i32) -> Vec<u8> {
        let mut bytes = vec![2];
        bytes.extend(errno.to_ne_bytes());
        bytes
    }

    #[test]
    fn split_stage_is_independent_from_exec_and_never_blocks() {
        let now = Instant::now();
        let mut reader = StartupReader::new(39, now + Duration::from_secs(1));
        let bytes = stage(39);
        let first = reader.poll(
            &mut pipe([Input::Bytes(bytes[..2].to_vec()), Input::Block]),
            now,
        );
        assert_eq!(first, Update::default());
        let second = reader.poll(
            &mut pipe([Input::Bytes(bytes[2..].to_vec()), Input::Block]),
            now,
        );
        assert_eq!(second.established.unwrap().sid(), 39);
        assert_eq!(second.outcome, None);
        assert!(!reader.pre_session_terminal());
        let final_report = reader.poll(&mut pipe([Input::Eof]), now);
        assert_eq!(final_report.outcome, Some(Outcome::Started));
        assert_eq!(final_report.established, None);
    }

    #[test]
    fn cancellation_keeps_queued_stage_before_leader_final_reap() {
        let now = Instant::now();
        let mut reader = StartupReader::new(39, now + Duration::from_secs(1));
        reader.cancel();
        // The leader may already be a WNOWAIT zombie. The private pipe's
        // queued stage must still upgrade custody before final child handling.
        let update = reader.poll(&mut pipe([Input::Bytes(stage(39)), Input::Eof]), now);
        assert_eq!(update.established.unwrap().sid(), 39);
        assert_eq!(update.outcome, Some(Outcome::Failed(Failure::Cancelled)));
        assert!(!reader.pre_session_terminal());
        assert!(reader.finished());
        assert_eq!(reader.poll(&mut pipe([Input::Eof]), now), Update::default());
    }

    #[test]
    fn original_deadline_is_sticky_even_if_stage_and_exec_arrive_late() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut reader = StartupReader::new(39, deadline);
        assert_eq!(
            reader.poll(&mut pipe([Input::Block]), now),
            Update::default()
        );
        let update = reader.poll(&mut pipe([Input::Bytes(stage(39)), Input::Eof]), deadline);
        assert!(update.established.is_some());
        assert_eq!(update.outcome, Some(Outcome::Failed(Failure::TimedOut)));
        assert!(!reader.pre_session_terminal());
    }

    #[test]
    fn failed_exec_keeps_stage_but_pre_stage_failure_keeps_child_only() {
        let now = Instant::now();
        for session in [false, true] {
            let mut reader = StartupReader::new(39, now + Duration::from_secs(1));
            let mut bytes = if session { stage(39) } else { Vec::new() };
            bytes.extend(failed(13));
            let update = reader.poll(&mut pipe([Input::Bytes(bytes), Input::Eof]), now);
            assert_eq!(update.established.is_some(), session);
            assert_eq!(update.outcome, Some(Outcome::Failed(Failure::Os(13))));
            assert_eq!(reader.pre_session_terminal(), !session);
        }
    }

    #[test]
    fn empty_eof_refuses_start_without_session_authority() {
        let now = Instant::now();
        let mut reader = StartupReader::new(39, now + Duration::from_secs(1));
        let update = reader.poll(&mut pipe([Input::Eof]), now);
        assert_eq!(update.established, None);
        assert_eq!(update.outcome, Some(Outcome::Failed(Failure::Protocol)));
        assert!(reader.pre_session_terminal());
    }

    #[test]
    fn ambiguity_never_proves_pre_session_terminal() {
        let now = Instant::now();
        let mut wrong = stage(40);
        wrong.extend(stage(39));
        for input in [
            vec![Input::Bytes(vec![1, 0]), Input::Eof],
            vec![Input::Bytes(wrong), Input::Eof],
            vec![Input::Bytes(failed(0)), Input::Eof],
            vec![Input::Bytes(failed(-1)), Input::Eof],
            vec![Input::Error, Input::Eof],
        ] {
            let mut reader = StartupReader::new(39, now + Duration::from_secs(1));
            let mut input = pipe(input);
            let first = reader.poll(&mut input, now);
            let second = reader.poll(&mut input, now);
            assert!(first.established.is_none() && second.established.is_none());
            assert!(matches!(first.outcome, Some(Outcome::Failed(_))));
            assert!(!reader.pre_session_terminal());
        }
    }

    #[test]
    fn duplicate_and_overlong_frames_do_not_revoke_valid_stage() {
        let now = Instant::now();
        for bytes in [
            [stage(39), stage(39)].concat(),
            [stage(39), failed(13), vec![0; 128]].concat(),
        ] {
            let mut reader = StartupReader::new(39, now + Duration::from_secs(1));
            let update = reader.poll(&mut pipe([Input::Bytes(bytes), Input::Eof]), now);
            assert_eq!(update.established.unwrap().sid(), 39);
            assert!(matches!(update.outcome, Some(Outcome::Failed(_))));
            assert!(!reader.pre_session_terminal());
        }
    }

    #[test]
    fn success_before_deadline_is_not_changed_by_later_poll() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut reader = StartupReader::new(39, deadline);
        assert_eq!(
            reader
                .poll(&mut pipe([Input::Bytes(stage(39)), Input::Eof]), now)
                .outcome,
            Some(Outcome::Started)
        );
        assert_eq!(
            reader.poll(&mut pipe([Input::Error]), deadline),
            Update::default()
        );
    }

    #[test]
    fn repeated_interrupts_yield_without_losing_stage_or_original_deadline() {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut reader = StartupReader::new(39, deadline);
        let mut input = pipe(
            (0..100)
                .map(|_| Input::Interrupted)
                .chain([Input::Bytes(stage(39)), Input::Eof]),
        );
        for remaining in (3..=102).rev() {
            assert_eq!(input.0.len(), remaining);
            assert_eq!(reader.poll(&mut input, now), Update::default());
            assert_eq!(
                input.0.len(),
                remaining - 1,
                "one interrupted syscall yields this pass"
            );
        }
        let update = reader.poll(&mut input, deadline);
        assert_eq!(update.established.unwrap().sid(), 39);
        assert_eq!(update.outcome, Some(Outcome::Failed(Failure::TimedOut)));
        assert!(!reader.pre_session_terminal());
    }
}
