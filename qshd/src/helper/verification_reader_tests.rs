use super::*;
use std::collections::VecDeque;
use std::time::Duration;

struct Input(VecDeque<io::Result<Vec<u8>>>);
impl Read for Input {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        match self.0.pop_front().unwrap_or(Ok(Vec::new())) {
            Err(error) => Err(error),
            Ok(bytes) => {
                let count = bytes.len().min(out.len());
                out[..count].copy_from_slice(&bytes[..count]);
                if count < bytes.len() {
                    self.0.push_front(Ok(bytes[count..].to_vec()));
                }
                Ok(count)
            }
        }
    }
}
fn stage(sid: u32) -> Vec<u8> {
    let mut bytes = vec![1];
    bytes.extend_from_slice(&sid.to_ne_bytes());
    bytes
}
fn fail(kind: io::ErrorKind) -> io::Result<Vec<u8>> {
    Err(io::Error::from(kind))
}
fn drive(
    reader: &mut VerificationReader,
    input: &mut Input,
    now: Instant,
) -> Vec<VerificationUpdate> {
    let mut updates = Vec::new();
    for _ in 0..32 {
        updates.push(reader.poll(input, now));
        if reader.finished() {
            break;
        }
    }
    updates
}

#[test]
fn helper40_verification_reader_emits_stage_before_waiting_for_fragmented_verdict_eof() {
    let now = Instant::now();
    let mut reader = VerificationReader::new(40, now + Duration::from_secs(1), 8192);
    let mut input = Input(VecDeque::from([
        Ok(stage(40)),
        Ok(vec![0, 1]),
        fail(io::ErrorKind::WouldBlock),
    ]));
    let first = reader.poll(&mut input, now);
    assert_eq!(first.established.unwrap().sid(), 40);
    assert_eq!(
        first.result, None,
        "partial verdict cannot complete a request"
    );
    input.0.extend([Ok(vec![2, 3]), Ok(Vec::new())]);
    let last = reader.poll(&mut input, now);
    assert_eq!(last.result, Some(Ok(vec![0, 1, 2, 3])));
    assert!(reader.finished());
    assert!(!reader.pre_session_terminal());
    assert_eq!(reader.poll(&mut input, now), VerificationUpdate::default());
}

#[test]
fn helper40_verification_cancel_retains_queued_stage_and_refusal_is_sticky() {
    let now = Instant::now();
    let mut reader = VerificationReader::new(40, now + Duration::from_secs(1), 8192);
    reader.cancel();
    let mut input = Input(VecDeque::from([Ok(stage(40)), Ok(vec![0]), Ok(Vec::new())]));
    let update = reader.poll(&mut input, now);
    assert_eq!(update.established.unwrap().sid(), 40);
    assert_eq!(update.result, Some(Err(Failure::Cancelled)));
    assert!(reader.finished());
    assert!(!reader.pre_session_terminal());
}

#[test]
fn helper40_verification_interrupt_yields_and_keeps_original_absolute_deadline() {
    let now = Instant::now();
    let deadline = now + Duration::from_secs(1);
    let mut reader = VerificationReader::new(40, deadline, 8192);
    let mut input = Input(VecDeque::from([
        fail(io::ErrorKind::Interrupted),
        fail(io::ErrorKind::Interrupted),
        Ok(stage(40)),
        Ok(vec![0]),
        Ok(Vec::new()),
    ]));
    assert_eq!(reader.poll(&mut input, now), VerificationUpdate::default());
    assert_eq!(input.0.len(), 4, "one interrupted read yields the pass");
    assert_eq!(reader.poll(&mut input, now), VerificationUpdate::default());
    assert_eq!(input.0.len(), 3);
    let update = reader.poll(&mut input, deadline);
    assert_eq!(update.established.unwrap().sid(), 40);
    assert_eq!(update.result, Some(Err(Failure::TimedOut)));
}

#[test]
fn helper40_verification_reader_bounds_body_and_preserves_finished_result_after_deadline() {
    for (length, good) in [(8192, true), (8193, false)] {
        let now = Instant::now();
        let deadline = now + Duration::from_secs(1);
        let mut reader = VerificationReader::new(40, deadline, 8192);
        let mut input = Input(VecDeque::from([
            Ok(stage(40)),
            Ok(vec![7; length]),
            Ok(Vec::new()),
        ]));
        let updates = drive(&mut reader, &mut input, now);
        let result = updates
            .into_iter()
            .find_map(|update| update.result)
            .expect("bounded result");
        if good {
            assert_eq!(result, Ok(vec![7; 8192]));
        } else {
            assert_eq!(result, Err(Failure::Protocol));
        }
        assert!(reader.finished());
        assert_eq!(
            reader.poll(&mut input, deadline),
            VerificationUpdate::default()
        );
    }
}

#[test]
fn helper40_verification_ambiguous_header_cannot_authorize_session_or_pre_session_reap() {
    let now = Instant::now();
    for bytes in [stage(41), vec![1, 40], vec![9, 0, 0, 0, 0]] {
        let mut reader = VerificationReader::new(40, now + Duration::from_secs(1), 8192);
        let mut input = Input(VecDeque::from([Ok(bytes), Ok(Vec::new())]));
        let updates = drive(&mut reader, &mut input, now);
        assert!(updates.iter().all(|update| update.established.is_none()));
        assert!(updates
            .iter()
            .any(|update| update.result == Some(Err(Failure::Protocol))));
        assert!(!reader.pre_session_terminal());
    }
    let mut reader = VerificationReader::new(40, now + Duration::from_secs(1), 8192);
    let mut input = Input(VecDeque::from([fail(io::ErrorKind::PermissionDenied)]));
    assert_eq!(
        reader.poll(&mut input, now).result,
        Some(Err(Failure::Read))
    );
    assert!(!reader.pre_session_terminal());
}

#[test]
fn helper40_verification_only_terminal_pre_stage_stream_proves_no_session_acquired() {
    let now = Instant::now();
    let mut failed = vec![2];
    failed.extend_from_slice(&1i32.to_ne_bytes());
    for bytes in [vec![], failed] {
        let mut reader = VerificationReader::new(40, now + Duration::from_secs(1), 8192);
        let mut input = Input(VecDeque::from([Ok(bytes), Ok(Vec::new())]));
        let updates = drive(&mut reader, &mut input, now);
        assert!(updates.iter().all(|update| update.established.is_none()));
        assert!(updates
            .iter()
            .any(|update| update.result.as_ref().is_some_and(Result::is_err)));
        assert!(reader.pre_session_terminal());
    }
}
