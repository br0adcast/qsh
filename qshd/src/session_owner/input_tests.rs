//! Synthetic input/reply fixtures only; no real terminal or authentication state.
use super::*;
use std::collections::VecDeque;
use std::io::{self, Write};
use transport::SessionInputBudget;

fn epoch() -> InputEpoch {
    InputEpoch::new([1; 16]).unwrap()
}
fn ledger() -> InputLedger {
    InputLedger::new(epoch(), SessionInputBudget::new().channel())
}
#[derive(Default)]
struct Sink {
    bytes: Vec<u8>,
    steps: VecDeque<Result<usize, io::ErrorKind>>,
    calls: usize,
}
impl Sink {
    fn scripted(steps: impl IntoIterator<Item = Result<usize, io::ErrorKind>>) -> Self {
        Self {
            steps: steps.into_iter().collect(),
            ..Self::default()
        }
    }
}
impl Write for Sink {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.calls += 1;
        match self.steps.pop_front().unwrap_or(Ok(usize::MAX)) {
            Ok(n) => {
                let n = n.min(bytes.len());
                self.bytes.extend_from_slice(&bytes[..n]);
                Ok(n)
            }
            Err(kind) => Err(io::Error::new(kind, "synthetic private writer message")),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn drain(ledger: &mut InputLedger, sink: &mut Sink) {
    loop {
        if ledger.write_step(sink).unwrap() == WriteProgress::Idle {
            break;
        }
    }
}
#[test]
fn duplicates_partial_overlap_and_lost_ack_write_only_the_new_suffix() {
    let mut ledger = ledger();
    let mut sink = Sink::scripted([Ok(2)]);
    assert_eq!(ledger.accept(epoch(), 0, b"abcd").unwrap().accepted, 4);
    assert_eq!(ledger.accept(epoch(), 0, b"abcd").unwrap().accepted, 4);
    assert!(matches!(
        ledger.write_step(&mut sink).unwrap(),
        WriteProgress::Progress {
            written: 2,
            position: InputPosition { committed: 2, .. },
            ..
        }
    ));
    assert_eq!(sink.bytes, b"ab");
    assert_eq!(ledger.accept(epoch(), 0, b"XX").unwrap().committed, 2);
    assert_eq!(
        ledger.accept(epoch(), 0, b"abCDef"),
        Err(InputError::PendingMismatch)
    );
    assert_eq!(ledger.position().accepted, 4);
    assert_eq!(ledger.accept(epoch(), 1, b"bcdEF").unwrap().accepted, 6);
    assert_eq!(ledger.accept(epoch(), 1, b"bcdEF").unwrap().accepted, 6);
    drain(&mut ledger, &mut sink);
    assert_eq!(sink.bytes, b"abcdEF");
    assert_eq!(
        ledger.position(),
        InputPosition {
            epoch: epoch(),
            accepted: 6,
            committed: 6
        }
    );
    let calls = sink.calls;
    ledger.accept(epoch(), 0, b"abcdEF").unwrap();
    assert_eq!(ledger.write_step(&mut sink).unwrap(), WriteProgress::Idle);
    assert_eq!(sink.calls, calls);
}
#[test]
fn write_step_attempts_once_and_preserves_progress_on_temporary_or_fatal_errors() {
    let mut ledger = ledger();
    ledger.accept(epoch(), 0, b"abc").unwrap();
    let mut sink = Sink::scripted([
        Err(io::ErrorKind::Interrupted),
        Err(io::ErrorKind::WouldBlock),
        Ok(1),
        Err(io::ErrorKind::BrokenPipe),
    ]);
    assert_eq!(
        ledger.write_step(&mut sink).unwrap(),
        WriteProgress::Interrupted
    );
    assert_eq!(sink.calls, 1);
    assert_eq!(ledger.position().committed, 0);
    assert_eq!(
        ledger.write_step(&mut sink).unwrap(),
        WriteProgress::WouldBlock
    );
    assert_eq!(sink.calls, 2);
    assert_eq!(ledger.position().committed, 0);
    ledger.write_step(&mut sink).unwrap();
    assert_eq!(sink.bytes, b"a");
    assert_eq!(ledger.position().committed, 1);
    let error = ledger.write_step(&mut sink).unwrap_err();
    assert_eq!(error, InputError::WriterFailed(io::ErrorKind::BrokenPipe));
    assert!(!format!("{error:?}").contains("private"));
    let mut replacement = Sink::default();
    assert_eq!(ledger.write_step(&mut replacement), Err(error));
    assert_eq!(replacement.calls, 0);
    assert_eq!(ledger.accept(epoch(), 3, b"d"), Err(error));
    assert_eq!(ledger.queue_reply(b"reply"), Err(error));
    assert_eq!(
        ledger.position(),
        InputPosition {
            epoch: epoch(),
            accepted: 3,
            committed: 1
        }
    );
}
#[test]
fn zero_write_is_permanent_and_empty_work_does_not_call_a_writer() {
    let mut ledger = ledger();
    let mut sink = Sink::scripted([Ok(0)]);
    ledger.accept(epoch(), 0, b"").unwrap();
    ledger.queue_reply(b"").unwrap();
    assert_eq!(ledger.write_step(&mut sink).unwrap(), WriteProgress::Idle);
    assert_eq!(sink.calls, 0);
    ledger.accept(epoch(), 0, b"x").unwrap();
    assert_eq!(
        ledger.write_step(&mut sink),
        Err(InputError::WriterFailed(io::ErrorKind::WriteZero))
    );
    assert_eq!(ledger.position().committed, 0);
    assert!(ledger.write_step(&mut Sink::default()).is_err());
}
#[test]
fn replies_share_fifo_but_never_advance_user_offsets() {
    let mut ledger = ledger();
    ledger.accept(epoch(), 0, b"ab").unwrap();
    ledger.queue_reply(b"REPLY").unwrap();
    ledger.accept(epoch(), 2, b"cd").unwrap();
    ledger.accept(epoch(), 1, b"bcdE").unwrap();
    let mut sink = Sink::default();
    ledger.write_step(&mut sink).unwrap();
    assert_eq!(ledger.position().committed, 2);
    assert!(matches!(
        ledger.write_step(&mut sink).unwrap(),
        WriteProgress::Progress {
            origin: InputOrigin::LocalReply,
            written: 5,
            position: InputPosition {
                accepted: 5,
                committed: 2,
                ..
            }
        }
    ));
    drain(&mut ledger, &mut sink);
    assert_eq!(sink.bytes, b"abREPLYcdE");
    assert_eq!(ledger.position().committed, 5);
}
#[test]
fn wrong_epoch_gap_and_oversized_network_spans_leave_state_unchanged() {
    let mut ledger = ledger();
    ledger.accept(epoch(), 0, b"ab").unwrap();
    let before = ledger.position();
    assert_eq!(
        ledger.accept(InputEpoch::new([2; 16]).unwrap(), 0, b"ab"),
        Err(InputError::WrongEpoch)
    );
    assert_eq!(ledger.accept(epoch(), 3, b"c"), Err(InputError::Gap));
    assert_eq!(
        ledger.accept(epoch(), u64::MAX, b"xx"),
        Err(InputError::Overflow)
    );
    assert_eq!(
        ledger.accept(epoch(), 0, &vec![b'x'; MAX_RESUME_DATA + 1]),
        Err(InputError::TooLarge)
    );
    assert_eq!(ledger.position(), before);
    let mut sink = Sink::default();
    drain(&mut ledger, &mut sink);
    assert_eq!(sink.bytes, b"ab");
}
#[test]
fn full_network_quota_still_accepts_duplicates_and_keeps_partial_chunk_charged() {
    let session = SessionInputBudget::new();
    let budget = session.channel();
    let observer = budget.clone();
    let mut ledger = InputLedger::new(epoch(), budget);
    let chunk = vec![b'n'; MAX_RESUME_DATA];
    for _ in 0..512 {
        ledger
            .accept(epoch(), ledger.position().accepted, &chunk)
            .unwrap();
    }
    let ptr = ledger.queue.front().unwrap().chunk.bytes().as_ptr();
    assert_eq!(ledger.accept(epoch(), 0, &chunk).unwrap().accepted, 8 << 20);
    assert_eq!(ledger.queue.len(), 512);
    assert_eq!(ledger.queue.front().unwrap().chunk.bytes().as_ptr(), ptr);
    assert!(matches!(
        ledger.accept(epoch(), 8 << 20, b"x"),
        Err(InputError::Quota(_))
    ));
    assert_eq!(
        ledger.accept(epoch(), 0, b"WRONG"),
        Err(InputError::PendingMismatch)
    );
    let mut sink = Sink::scripted([Ok(1)]);
    ledger.write_step(&mut sink).unwrap();
    assert!(observer.try_network_slice(b"x").is_err());
    assert_eq!(ledger.position().committed, 1);
    ledger.write_step(&mut sink).unwrap();
    assert!(observer.try_network_slice(b"x").unwrap().is_some());
    drain(&mut ledger, &mut sink);
    assert_eq!(sink.bytes, vec![b'n'; 8 << 20]);
    assert_eq!(ledger.position().committed, 8 << 20);
}
#[test]
fn network_item_cap_does_not_charge_pending_duplicates_or_spend_reply_allowance() {
    let mut ledger = ledger();
    for offset in 0..16_384 {
        ledger.accept(epoch(), offset, b"x").unwrap();
    }
    assert_eq!(ledger.accept(epoch(), 0, b"x").unwrap().accepted, 16_384);
    assert!(matches!(
        ledger.accept(epoch(), 16_384, b"z"),
        Err(InputError::Quota(InputLimit::Items { .. }))
    ));
    ledger.queue_reply(b"R").unwrap();
    let mut sink = Sink::default();
    ledger.write_step(&mut sink).unwrap();
    ledger.accept(epoch(), 16_384, b"z").unwrap();
    drain(&mut ledger, &mut sink);
    let mut expected = vec![b'x'; 16_384];
    expected.extend_from_slice(b"Rz");
    assert_eq!(sink.bytes, expected);
    assert_eq!(ledger.position().committed, 16_385);
}
#[test]
fn exact_64k_local_reply_retains_its_whole_charge_across_partial_writes() {
    let session = SessionInputBudget::new();
    let budget = session.channel();
    let observer = budget.clone();
    let mut ledger = InputLedger::new(epoch(), budget);
    let reply = vec![b'r'; 64 << 10];
    ledger.queue_reply(&reply).unwrap();
    assert!(ledger.queue_reply(b"x").is_err());
    ledger.accept(epoch(), 0, b"user").unwrap();
    let mut sink = Sink::scripted([Ok(1)]);
    ledger.write_step(&mut sink).unwrap();
    assert!(observer.try_local_reply_slice(b"x").is_err());
    assert_eq!(
        ledger.position(),
        InputPosition {
            epoch: epoch(),
            accepted: 4,
            committed: 0
        }
    );
    ledger.write_step(&mut sink).unwrap();
    assert!(observer.try_local_reply_slice(b"x").unwrap().is_some());
    assert_eq!(ledger.position().committed, 0);
    drain(&mut ledger, &mut sink);
    let mut expected = reply;
    expected.extend_from_slice(b"user");
    assert_eq!(sink.bytes, expected);
    assert_eq!(ledger.position().committed, 4);
}
#[test]
fn local_item_and_aggregate_session_quotas_remain_independent_of_user_positions() {
    let session = SessionInputBudget::new();
    let mut ledgers: Vec<_> = (0..9)
        .map(|_| InputLedger::new(epoch(), session.channel()))
        .collect();
    for ledger in &mut ledgers[..8] {
        for _ in 0..64 {
            ledger.queue_reply(b"r").unwrap();
        }
        assert!(matches!(
            ledger.queue_reply(b"x"),
            Err(InputError::Quota(InputLimit::Items { .. }))
        ));
    }
    assert!(matches!(
        ledgers[8].queue_reply(b"x"),
        Err(InputError::Quota(InputLimit::Items {
            scope: transport::InputScope::Session,
            ..
        }))
    ));
    ledgers[8].accept(epoch(), 0, b"user").unwrap();
    for ledger in &ledgers[..8] {
        assert_eq!(ledger.position().accepted, 0);
    }
    let mut sink = Sink::default();
    drain(&mut ledgers[0], &mut sink);
    ledgers[8].queue_reply(b"x").unwrap();
}
#[test]
fn channel_ledgers_share_the_session_network_budget() {
    let session = SessionInputBudget::new();
    let mut first = InputLedger::new(epoch(), session.channel());
    let mut second = InputLedger::new(epoch(), session.channel());
    let chunk = vec![b'x'; MAX_RESUME_DATA];
    for _ in 0..256 {
        first
            .accept(epoch(), first.position().accepted, &chunk)
            .unwrap();
        second
            .accept(epoch(), second.position().accepted, &chunk)
            .unwrap();
    }
    let mut next = InputLedger::new(epoch(), session.channel());
    assert!(matches!(
        next.accept(epoch(), 0, b"x"),
        Err(InputError::Quota(InputLimit::Bytes {
            scope: transport::InputScope::Session,
            ..
        }))
    ));
    let mut sink = Sink::default();
    first.write_step(&mut sink).unwrap();
    next.accept(epoch(), 0, b"x").unwrap();
    assert_eq!(second.position().committed, 0);
    assert_eq!(second.position().accepted, 4 << 20);
}
#[test]
fn checked_offsets_reach_the_last_byte_but_never_wrap_or_replay() {
    let mut ledger = ledger();
    ledger.position.accepted = u64::MAX - 2;
    ledger.position.committed = u64::MAX - 2;
    ledger.accept(epoch(), u64::MAX - 2, b"XY").unwrap();
    let mut sink = Sink::scripted([Ok(1)]);
    ledger.write_step(&mut sink).unwrap();
    assert_eq!(ledger.position().committed, u64::MAX - 1);
    ledger.write_step(&mut sink).unwrap();
    assert_eq!(ledger.position().committed, u64::MAX);
    assert_eq!(
        ledger.accept(epoch(), u64::MAX, b"Z"),
        Err(InputError::Overflow)
    );
    ledger.accept(epoch(), u64::MAX - 1, b"Y").unwrap();
    assert_eq!(ledger.write_step(&mut sink).unwrap(), WriteProgress::Idle);
    assert_eq!(sink.bytes, b"XY");
}
#[test]
fn a_writer_violating_its_count_contract_fails_closed_without_refunding_debt() {
    struct Overcount;
    impl Write for Overcount {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            Ok(b.len() + 1)
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut ledger = ledger();
    ledger.accept(epoch(), 0, b"private input").unwrap();
    assert_eq!(
        ledger.write_step(&mut Overcount),
        Err(InputError::WriterFailed(io::ErrorKind::InvalidData))
    );
    assert_eq!(ledger.position().committed, 0);
    assert_eq!(ledger.queue.len(), 1);
    let debug = format!("{ledger:?}");
    assert!(!debug.contains("private input"));
    assert!(ledger.write_step(&mut Sink::default()).is_err());
}
#[test]
fn a_later_pending_mismatch_cannot_admit_a_new_suffix_across_reply_records() {
    let mut ledger = ledger();
    ledger.accept(epoch(), 0, b"ab").unwrap();
    ledger.queue_reply(b"R").unwrap();
    ledger.accept(epoch(), 2, b"cd").unwrap();
    let before = ledger.position();
    let queued = ledger.queue.len();
    assert_eq!(
        ledger.accept(epoch(), 1, b"bXdE"),
        Err(InputError::PendingMismatch)
    );
    assert_eq!(ledger.position(), before);
    assert_eq!(ledger.queue.len(), queued);
    let mut sink = Sink::default();
    drain(&mut ledger, &mut sink);
    assert_eq!(sink.bytes, b"abRcd");
}
#[test]
fn would_block_after_physical_partial_write_preserves_the_verified_resend_boundary() {
    let mut ledger = ledger();
    ledger.accept(epoch(), 0, b"abcd").unwrap();
    let mut sink = Sink::scripted([Ok(1), Err(io::ErrorKind::WouldBlock)]);
    ledger.write_step(&mut sink).unwrap();
    assert_eq!(sink.bytes, b"a");
    assert_eq!(
        ledger.write_step(&mut sink).unwrap(),
        WriteProgress::WouldBlock
    );
    assert_eq!(ledger.position().committed, 1);
    ledger.accept(epoch(), 0, b"abcdEF").unwrap();
    drain(&mut ledger, &mut sink);
    assert_eq!(sink.bytes, b"abcdEF");
    assert_eq!(ledger.position().committed, 6);
}
