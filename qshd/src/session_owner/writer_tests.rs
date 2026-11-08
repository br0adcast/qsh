use super::super::{
    authorization_contract::*, resource_contract::*, resources::OwnerResourceClient,
};
use super::*;
use std::sync::mpsc;
use std::time::{Duration, Instant};
use transport::{session_resume::*, SessionInputBudget};
fn attachment(epoch: u64) -> Attachment {
    Attachment {
        locator: SessionLocator {
            session: RetainedSessionId::new([1; 16]).unwrap(),
            owner: OwnerInstance::new([2; 16]).unwrap(),
        },
        frontend: FrontendGeneration::new([epoch as u8; 16]).unwrap(),
        epoch: AttachEpoch::new(epoch).unwrap(),
    }
}
struct Sink {
    bytes: Arc<Mutex<Vec<u8>>>,
    entered: mpsc::Sender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
    script: bool,
    calls: usize,
}
impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        let _ = self.entered.send(());
        let mut released = self.release.0.lock().unwrap();
        while !*released {
            released = self.release.1.wait(released).unwrap();
        }
        drop(released);
        self.calls += 1;
        if self.script {
            match self.calls {
                1 => return Err(std::io::ErrorKind::Interrupted.into()),
                2 => return Err(std::io::ErrorKind::WouldBlock.into()),
                3 => {}
                _ => return Err(std::io::ErrorKind::BrokenPipe.into()),
            }
        }
        let n = b.len().min(2);
        self.bytes.lock().unwrap().extend_from_slice(&b[..n]);
        Ok(n)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
struct Fixture {
    shared: Arc<WriterShared>,
    thread: Option<std::thread::JoinHandle<()>>,
    entered: mpsc::Receiver<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
    bytes: Arc<Mutex<Vec<u8>>>,
    ledger: Arc<Mutex<ResourceLedger>>,
}
impl Fixture {
    fn new() -> Self {
        Self::with_script(false)
    }
    fn with_script(script: bool) -> Self {
        let principal = AuthenticatedPrincipalRef::new([3; 16]).unwrap();
        let l = ByteLimits {
            channel_bytes: 1 << 20,
            session_bytes: 1 << 20,
            account_bytes: 1 << 20,
            global_bytes: 1 << 20,
        };
        let mut ledger = ResourceLedger::new(
            LedgerInstance::new([4; 16]).unwrap(),
            ResourceLimits {
                max_reservations: 8,
                screen: ScreenLimits {
                    global_cells: 0,
                    account_cells: 0,
                    global_rows: 0,
                    account_rows: 0,
                    global_models: 0,
                    account_models: 0,
                },
                snapshot_transfer: l,
                control_queue: l,
            },
        )
        .unwrap();
        let registration = ledger.register_fresh_principal(principal, 1000).unwrap();
        let ledger = Arc::new(Mutex::new(ledger));
        let client = OwnerResourceClient::new(ledger.clone(), registration);
        let reservation = Reservation {
            id: ReservationId::new(1).unwrap(),
            principal,
            locator: attachment(1).locator,
            channel: ChannelInstance::new(1).unwrap(),
            kind: ReservationKind::ControlQueue,
            bytes: PAYLOAD_BYTES as u64 + CONTROL_METADATA as u64,
            screen_charge: None,
        };
        let cleanup = RequestId::new(1).unwrap();
        let token = client.reserve(reservation, cleanup).unwrap();
        let charge = StorageCharge::new(client, token, cleanup);
        let (shared, worker) = WriterShared::new(
            reservation.channel,
            InputEpoch::new([5; 16]).unwrap(),
            SessionInputBudget::new().channel(),
            charge,
        )
        .unwrap();
        shared.resume(attachment(1)).unwrap();
        let (tx, entered) = mpsc::channel();
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let sink = Sink {
            bytes: bytes.clone(),
            entered: tx,
            release: release.clone(),
            script,
            calls: 0,
        };
        let thread = std::thread::spawn(move || worker.run(Box::new(sink)));
        Self {
            shared,
            thread: Some(thread),
            entered,
            release,
            bytes,
            ledger,
        }
    }
    fn unblock(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
    fn finish(&mut self) {
        self.shared.close();
        self.unblock();
        if let Some(t) = self.thread.take() {
            t.join().unwrap();
        }
        self.shared.allow_release();
    }
    fn submit(&self, offset: u64, b: &[u8]) -> Result<InputSubmission, WriterError> {
        self.shared.submit(
            attachment(1),
            ChannelInstance::new(1).unwrap(),
            InputEpoch::new([5; 16]).unwrap(),
            offset,
            b,
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.finish();
    }
}
#[tokio::test]
async fn writer_fence_resolves_actual_partial_then_retains_prebarrier_payload() {
    let mut fixture = Fixture::new();
    let accepted = fixture
        .submit(0, b"abcd")
        .unwrap()
        .accepted()
        .await
        .unwrap();
    assert_eq!((accepted.accepted, accepted.committed), (4, 0));
    fixture
        .entered
        .recv_timeout(Duration::from_secs(1))
        .unwrap();
    let queued = fixture.submit(4, b"efgh").unwrap();
    let ticket = fixture.shared.request_fence(attachment(1)).unwrap();
    assert!(
        fixture
            .shared
            .fence_result(ticket, attachment(1))
            .unwrap()
            .is_none(),
        "blocked actual write fabricated fencing"
    );
    fixture.unblock();
    let until = Instant::now() + Duration::from_millis(300);
    let result = loop {
        let p = fixture.shared.fence_result(ticket, attachment(1)).unwrap();
        if p.is_some() || Instant::now() >= until {
            break p;
        }
        tokio::task::yield_now().await;
    };
    let accepted_second = queued.accepted().await.unwrap();
    let bytes = fixture.bytes.lock().unwrap().clone();
    fixture.finish();
    assert_eq!(
        result.map(|p| (p.accepted, p.committed)),
        Some((8, 2)),
        "fence did not preserve actual partial-write boundary"
    );
    assert_eq!(
        (accepted_second.accepted, accepted_second.committed),
        (8, 2)
    );
    assert_eq!(bytes, b"ab");
}

#[tokio::test]
async fn writer_full_payload_still_revokes_and_closes_without_accepting_old_input() {
    let mut f = Fixture::new();
    f.submit(0, b"abcd").unwrap().accepted().await.unwrap();
    f.entered.recv_timeout(Duration::from_secs(1)).unwrap();
    let queued = f.submit(4, b"efgh").unwrap();
    assert!(matches!(f.submit(8, b"i"), Err(WriterError::Busy)));
    let ticket = f.shared.request_fence(attachment(1)).unwrap();
    assert!(matches!(f.submit(8, b"i"), Err(WriterError::Stale)));
    assert_eq!(f.shared.request_fence(attachment(1)).unwrap(), ticket);
    assert!(!f.shared.settled());
    f.shared.close();
    assert!(matches!(
        f.shared.fence_result(ticket, attachment(1)),
        Err(WriterError::Closed)
    ));
    f.unblock();
    assert!(matches!(queued.accepted().await, Err(WriterError::Closed)));
    f.finish();
    assert_eq!(f.shared.position().committed, 2);
    assert_eq!(*f.bytes.lock().unwrap(), b"ab");
    let ledger = f.ledger.clone();
    assert_eq!(
        ledger.lock().unwrap().reservations(),
        1,
        "live shared backing refunded before destruction"
    );
    drop(f);
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
}
#[tokio::test]
async fn writer_new_lease_keeps_suffix_and_owner_reply_before_new_input() {
    let mut f = Fixture::new();
    f.submit(0, b"abcd").unwrap().accepted().await.unwrap();
    f.entered.recv_timeout(Duration::from_secs(1)).unwrap();
    let reply = f.shared.reply(b"R").unwrap();
    let ticket = f.shared.request_fence(attachment(1)).unwrap();
    f.unblock();
    let p = f.shared.wait_fence(ticket, attachment(1)).await.unwrap();
    assert_eq!((p.accepted, p.committed), (4, 2));
    reply.accepted().await.unwrap();
    f.shared.assign(attachment(2)).unwrap();
    assert!(matches!(f.submit(4, b"EF"), Err(WriterError::Stale)));
    f.shared.resume(attachment(2)).unwrap();
    f.shared
        .submit(
            attachment(2),
            ChannelInstance::new(1).unwrap(),
            InputEpoch::new([5; 16]).unwrap(),
            4,
            b"EF",
        )
        .unwrap()
        .accepted()
        .await
        .unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    while f.shared.position().committed != 6 {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    f.finish();
    assert_eq!(*f.bytes.lock().unwrap(), b"abcdREF");
}
#[tokio::test]
async fn writer_lost_ack_resend_uses_same_ledger_without_second_physical_write() {
    let mut f = Fixture::new();
    let lost = f.submit(0, b"abcd").unwrap();
    drop(lost);
    f.entered.recv_timeout(Duration::from_secs(1)).unwrap();
    f.unblock();
    let until = Instant::now() + Duration::from_secs(1);
    while f.shared.position().committed != 4 {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    let acknowledged = f.submit(0, b"abcd").unwrap().accepted().await.unwrap();
    assert_eq!((acknowledged.accepted, acknowledged.committed), (4, 4));
    f.finish();
    assert_eq!(*f.bytes.lock().unwrap(), b"abcd");
}
#[tokio::test]
async fn writer_validates_lifetime_epoch_and_size_before_mailbox_copy() {
    let mut f = Fixture::new();
    let epoch = InputEpoch::new([5; 16]).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    assert!(matches!(
        f.shared.submit(attachment(2), channel, epoch, 0, b"a"),
        Err(WriterError::Stale)
    ));
    assert!(matches!(
        f.shared.submit(
            attachment(1),
            ChannelInstance::new(2).unwrap(),
            epoch,
            0,
            b"a"
        ),
        Err(WriterError::WrongChannel)
    ));
    assert!(matches!(
        f.shared.submit(
            attachment(1),
            channel,
            InputEpoch::new([6; 16]).unwrap(),
            0,
            b"a"
        ),
        Err(WriterError::WrongEpoch)
    ));
    assert!(matches!(
        f.submit(0, &vec![b'a'; 16385]),
        Err(WriterError::TooLarge)
    ));
    assert!(f
        .shared
        .state
        .lock()
        .unwrap()
        .buffer
        .iter()
        .all(|b| *b == 0));
    f.shared.state.lock().unwrap().next = u64::MAX;
    assert!(matches!(f.submit(0, b"a"), Err(WriterError::Exhausted)));
    assert_eq!(f.shared.position().accepted, 0);
    f.finish();
}

#[tokio::test]
async fn writer_interrupted_would_block_and_fatal_keep_real_progress_and_terminal_failure() {
    let mut f = Fixture::with_script(true);
    f.unblock();
    f.submit(0, b"abcd").unwrap().accepted().await.unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    while f.shared.state.lock().unwrap().failure.is_none() {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    assert_eq!(
        (f.shared.position().accepted, f.shared.position().committed),
        (4, 2)
    );
    assert!(matches!(
        f.submit(0, b"abcd"),
        Err(WriterError::Input(InputError::WriterFailed(
            std::io::ErrorKind::BrokenPipe
        )))
    ));
    let ticket = f.shared.request_fence(attachment(1)).unwrap();
    let p = f.shared.wait_fence(ticket, attachment(1)).await.unwrap();
    assert_eq!(p.committed, 2);
    assert_eq!(*f.bytes.lock().unwrap(), b"ab");
    f.finish();
}
#[test]
fn writer_fence_ticket_exhaustion_cannot_appear_settled_or_assign_a_new_lease() {
    let mut f = Fixture::new();
    f.shared.state.lock().unwrap().next = u64::MAX;
    assert!(matches!(
        f.shared.request_fence(attachment(1)),
        Err(WriterError::Exhausted)
    ));
    let incorrectly_settled = f.shared.settled();
    f.finish();
    assert!(
        !incorrectly_settled,
        "exhausted barrier ticket looked like successful fencing"
    );
}
