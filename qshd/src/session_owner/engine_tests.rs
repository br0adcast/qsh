use super::*;
fn locator() -> SessionLocator {
    SessionLocator {
        session: RetainedSessionId::new([1; 16]).unwrap(),
        owner: OwnerInstance::new([2; 16]).unwrap(),
    }
}
fn attachment(epoch: u64) -> Attachment {
    Attachment {
        locator: locator(),
        frontend: FrontendGeneration::new([epoch as u8; 16]).unwrap(),
        epoch: AttachEpoch::new(epoch).unwrap(),
    }
}
#[test]
fn dropped_frontend_revokes_only_the_lease() {
    let a = attachment(1);
    let mut state = AttachmentState::new();
    state.begin_attach(a).unwrap();
    state.attached(a).unwrap();
    let shared = Arc::new(Mutex::new(LeaseState {
        state,
        current: Some(a),
        writers: Vec::new(),
        generation: 0,
        ready_generation: None,
        closed: false,
        last_recovery_request: 0,
    }));
    let handle = FrontendAttachment {
        shared: shared.clone(),
        attachment: a,
    };
    drop(handle);
    let mut lease = shared.lock().unwrap();
    assert_eq!(lease.state.phase(), AttachmentPhase::Detached);
    assert!(lease.state.begin_attach(a).is_err());
    lease.state.begin_attach(attachment(2)).unwrap();
}

#[test]
fn no_screen_reader_reserves_exact_slice_and_stops_at_full_credit() {
    struct Probe {
        next: u8,
        calls: std::sync::mpsc::Sender<usize>,
    }
    impl Read for Probe {
        fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
            self.calls.send(into.len()).unwrap();
            for byte in into.iter_mut() {
                *byte = self.next;
                self.next += 1;
            }
            Ok(into.len())
        }
    }
    let shared = Arc::new(SharedOutput {
        state: Mutex::new(OutputState {
            bytes: Vec::with_capacity(8),
            start: 0,
            closed: false,
            eof: false,
            failed: false,
        }),
        changed: Condvar::new(),
        capacity: 8,
    });
    let (tx, rx) = std::sync::mpsc::channel();
    let reading = shared.clone();
    let worker = std::thread::spawn(move || {
        read_output(Box::new(Probe { next: 0, calls: tx }), reading, vec![0; 4])
    });
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(),
        4
    );
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(),
        4
    );
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(30))
            .is_err(),
        "full NoScreen storage allowed another read"
    );
    {
        let mut state = shared.state.lock().unwrap();
        assert_eq!(state.bytes, &[0, 1, 2, 3, 4, 5, 6, 7]);
        state.bytes.drain(..3);
        state.start = 3;
        shared.changed.notify_all();
    }
    assert_eq!(
        rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(),
        3,
        "actual read slice exceeded newly freed credit"
    );
    assert!(rx
        .recv_timeout(std::time::Duration::from_millis(30))
        .is_err());
    {
        let mut state = shared.state.lock().unwrap();
        assert_eq!(state.bytes, &[3, 4, 5, 6, 7, 8, 9, 10]);
        state.closed = true;
        shared.changed.notify_all();
    }
    worker.join().unwrap();
}

mod integrated {
    use super::*;
    use crate::session_owner::{
        authorization_contract::*, recovery_runtime::NoScreenConsumer, resource_contract::*,
    };
    use std::io::Write;
    use std::time::{Duration, Instant};
    use transport::{
        channel::{ChannelKind, OpenRequest},
        channel_open::{ChannelOpenRegistry, OpenLimits, SpawnFailure, UninstalledChannel},
        channel_server::{ChannelSpawner, ChannelWait, ChildStatus, LeaderStatus},
        shell_server::{NoScreen, ResizeHandle},
    };
    #[derive(Default)]
    struct Io {
        state: Mutex<(bool, Vec<u8>)>,
        changed: Condvar,
        held: std::sync::atomic::AtomicBool,
        entered: std::sync::atomic::AtomicUsize,
        fail_next: std::sync::atomic::AtomicBool,
        suffix_ready: std::sync::atomic::AtomicBool,
        spawn_hold: std::sync::atomic::AtomicBool,
        spawn_entered: std::sync::atomic::AtomicUsize,
    }
    struct Reader {
        io: Arc<Io>,
        offset: usize,
    }
    impl Read for Reader {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let data = b"record:partial";
            let suffix = b":live";
            let mut state = self.io.state.lock().unwrap();
            loop {
                if state.0 {
                    return Ok(0);
                }
                if self.offset < data.len() {
                    let n = b.len().min(data.len() - self.offset);
                    b[..n].copy_from_slice(&data[self.offset..self.offset + n]);
                    self.offset += n;
                    return Ok(n);
                }
                if self.offset < data.len() + suffix.len()
                    && self
                        .io
                        .suffix_ready
                        .load(std::sync::atomic::Ordering::SeqCst)
                {
                    let offset = self.offset - data.len();
                    let n = b.len().min(suffix.len() - offset);
                    b[..n].copy_from_slice(&suffix[offset..offset + n]);
                    self.offset += n;
                    return Ok(n);
                }
                state = self.io.changed.wait(state).unwrap();
            }
        }
    }

    struct Writer(Arc<Io>);
    impl Write for Writer {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            use std::sync::atomic::Ordering;
            self.0.entered.fetch_add(1, Ordering::SeqCst);
            self.0.changed.notify_all();
            let mut state = self.0.state.lock().unwrap();
            while self.0.held.load(Ordering::SeqCst) && !state.0 {
                state = self.0.changed.wait(state).unwrap();
            }
            if state.0 {
                return Err(std::io::ErrorKind::BrokenPipe.into());
            }
            let n = b.len().min(2);
            state.1.extend_from_slice(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct Wait(Arc<Io>);
    impl ChannelWait for Wait {
        fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
            Some(if self.0.state.lock().unwrap().0 {
                LeaderStatus::Exited { code: Some(0) }
            } else {
                LeaderStatus::Running
            })
        }
        fn poll_exit(&mut self) -> ChildStatus {
            if self.0.state.lock().unwrap().0 {
                ChildStatus::Reaped { code: Some(0) }
            } else {
                ChildStatus::Running
            }
        }
        fn kill(&mut self) {
            self.0.state.lock().unwrap().0 = true;
            self.0.changed.notify_all();
        }
        fn wait(self: Box<Self>) -> i32 {
            panic!("exact poll only")
        }
        fn cleanup_uninstalled(
            &mut self,
            a: &transport::channel_open::CleanupAuthority<'_>,
        ) -> CleanupStatus {
            self.kill();
            a.reaped()
        }
    }
    struct Resize;
    impl ResizeHandle for Resize {
        fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
            Ok(())
        }
    }
    struct Spawner {
        registry: Arc<ChannelOpenRegistry>,
        io: Arc<Io>,
    }
    impl ChannelSpawner for Spawner {
        fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            _: &Principal,
            _: LoginId,
            _: &OpenRequest,
            _: Option<&str>,
            custody: &OpenCustody,
        ) -> Result<UninstalledChannel, SpawnFailure> {
            self.io
                .spawn_entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            {
                let mut state = self.io.state.lock().unwrap();
                while self.io.spawn_hold.load(std::sync::atomic::Ordering::SeqCst) && !state.0 {
                    state = self.io.changed.wait(state).unwrap();
                }
            }
            if custody.is_cancelled() {
                return Err(custody.refuse_before_creation("synthetic cancellation".into()));
            }
            if self
                .io
                .fail_next
                .swap(false, std::sync::atomic::Ordering::SeqCst)
            {
                return Err(custody.refuse_before_creation("synthetic refusal".into()));
            }
            Ok(custody
                .protect(Box::new(Wait(self.io.clone())), Box::new(NoScreen))
                .finish(
                    Box::new(Reader {
                        io: self.io.clone(),
                        offset: 0,
                    }),
                    Box::new(Writer(self.io.clone())),
                    Box::new(Resize),
                ))
        }
    }
    struct Clock;
    impl MonotonicClock for Clock {
        fn now(&self) -> u64 {
            0
        }
    }
    struct Fixture {
        engine: SessionOwnerEngine,
        client: OwnerResourceClient,
        ledger: Arc<Mutex<ResourceLedger>>,
        next: u64,
        io: Arc<Io>,
        restart: tokio::sync::watch::Sender<RestartSignal>,
    }
    impl Fixture {
        fn new() -> (Self, FrontendAttachment) {
            Self::new_scope(72)
        }
        fn new_scope(scope: u8) -> (Self, FrontendAttachment) {
            let p = AuthenticatedPrincipalRef::new([71; 16]).unwrap();
            let l = ByteLimits {
                channel_bytes: 4 << 20,
                session_bytes: 8 << 20,
                account_bytes: 16 << 20,
                global_bytes: 32 << 20,
            };
            let mut ledger = ResourceLedger::new(
                LedgerInstance::new([scope; 16]).unwrap(),
                ResourceLimits {
                    max_reservations: 64,
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
            let reg = ledger.register_fresh_principal(p, 1000).unwrap();
            let ledger = Arc::new(Mutex::new(ledger));
            let client = OwnerResourceClient::new(ledger.clone(), reg);
            let io = Arc::new(Io::default());
            let spawner = Arc::new(Spawner {
                registry: ChannelOpenRegistry::new(OpenLimits::default()),
                io: io.clone(),
            });
            let (restart_tx, restart) = tokio::sync::watch::channel(RestartSignal::IDLE);
            let mut engine = SessionOwnerEngine::new(
                locator(),
                Principal {
                    uid: 1000,
                    name: "synthetic".into(),
                    identity: "synthetic".into(),
                    incarnation: 0,
                },
                [73; 16],
                spawner,
                client.clone(),
                Arc::new(Clock),
                restart,
            )
            .unwrap();
            let front = engine.attach_trusted(attachment(1)).unwrap();
            (
                Self {
                    engine,
                    client,
                    ledger,
                    next: 0,
                    io,
                    restart: restart_tx,
                },
                front,
            )
        }
        fn reserve(
            &mut self,
            channel: ChannelInstance,
            kind: ReservationKind,
            bytes: u64,
        ) -> Reservation {
            self.next += 1;
            Reservation {
                id: ReservationId::new(self.next).unwrap(),
                principal: self.client.principal(),
                locator: locator(),
                channel,
                kind,
                bytes,
                screen_charge: None,
            }
        }
        fn transfer(&mut self, channel: ChannelInstance, n: usize) -> TransferAllowance {
            let r = self.reserve(
                channel,
                ReservationKind::SnapshotTransfer,
                (n.max(1) + 16384 + 65536) as u64,
            );
            TransferAllowance::admit(
                self.client.clone(),
                r,
                RequestId::new(r.id.get()).unwrap(),
                n,
            )
            .unwrap()
        }
        async fn open(&mut self, front: &FrontendAttachment, id: u64) {
            let channel = ChannelInstance::new(id).unwrap();
            let history = self.reserve(channel, ReservationKind::OutputHistory, 4096);
            let control = self.reserve(channel, ReservationKind::ControlQueue, 131072);
            self.engine
                .open(
                    front,
                    OpenRequest {
                        stream: 15 + id as u8,
                        kind: ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: false,
                        command: Vec::new(),
                    },
                    None,
                    OwnerChannelResources {
                        history,
                        control,
                        cleanup: RequestId::new(history.id.get()).unwrap(),
                        read_buffer_bytes: 128,
                        input_epoch: InputEpoch::new([id as u8; 16]).unwrap(),
                    },
                )
                .await
                .unwrap();
            let until = Instant::now() + Duration::from_secs(2);
            while !self.engine.retained.catalog_active(channel)
                || self
                    .engine
                    .channels
                    .values()
                    .find(|c| c.instance == channel)
                    .unwrap()
                    .output
                    .state
                    .lock()
                    .unwrap()
                    .bytes
                    .is_empty()
            {
                assert!(Instant::now() < until);
                tokio::task::yield_now().await;
            }
        }
        fn catalog(&mut self, front: &FrontendAttachment) -> OwnerRecovery {
            let a = self.transfer(ChannelInstance::new(1).unwrap(), 0);
            self.engine.catalog(front, a).unwrap()
        }
        fn consumer(&mut self, id: u64) -> NoScreenConsumer {
            let channel = ChannelInstance::new(id).unwrap();
            NoScreenConsumer::new(channel, self.transfer(channel, 4096)).unwrap()
        }
        fn consume(
            &mut self,
            front: &FrontendAttachment,
            tx: &mut OwnerRecovery,
            consumer: &mut NoScreenConsumer,
        ) -> ConsumedRecovery {
            let cursor = consumer.cursor();
            let position = tx
                .catalog()
                .positions()
                .iter()
                .find(|p| p.channel == cursor.channel)
                .unwrap();
            let n = usize::try_from(position.output.offset - cursor.offset).unwrap();
            let allowance = self.transfer(cursor.channel, n);
            let request = RecoveryRequest {
                attachment: front.attachment(),
                channel: cursor.channel,
                parser: ParserContinuity::DataCursor { cursor },
            };
            let request_id = RequestId::new(self.next + 100).unwrap();
            let mut producer = self
                .engine
                .recover(
                    front,
                    tx,
                    request,
                    RecoveryId::new([self.next as u8; 16]).unwrap(),
                    request_id,
                    allowance,
                )
                .unwrap();
            consumer
                .begin(request_id, request, producer.start())
                .unwrap();
            while let Some(chunk) = producer.next_chunk().unwrap() {
                consumer.consume(&chunk).unwrap();
            }
            let (end, ready) = producer.end().unwrap();
            consumer.finish(end, ready).unwrap()
        }
    }
    #[tokio::test]
    async fn integrated_nonempty_catalog_open_invalidates_canonical_authority_until_both_real_consumers(
    ) {
        let (mut f, front) = Fixture::new();
        f.open(&front, 1).await;
        let mut a = f.consumer(1);
        let mut old = f.catalog(&front);
        let old_proof = f.consume(&front, &mut old, &mut a);
        let mut first = f.catalog(&front);
        let proof = f.consume(&front, &mut first, &mut a);
        first.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, first).unwrap();
        assert!(f
            .engine
            .leases
            .lock()
            .unwrap()
            .state
            .validate_input(front.attachment())
            .is_ok());
        f.open(&front, 2).await;
        old.accept_consumed(old_proof).unwrap();
        assert!(
            f.engine.finish_recovery(&front, old).is_err(),
            "old completion revived input after catalog change"
        );
        let canonical_blocked = f
            .engine
            .leases
            .lock()
            .unwrap()
            .state
            .validate_input(front.attachment())
            .is_err();
        assert!(f
            .engine
            .user_input(
                &front,
                ChannelInstance::new(1).unwrap(),
                InputEpoch::new([1; 16]).unwrap(),
                0,
                b""
            )
            .is_err());
        assert!(f
            .engine
            .user_input(
                &front,
                ChannelInstance::new(2).unwrap(),
                InputEpoch::new([2; 16]).unwrap(),
                0,
                b"B"
            )
            .is_err());
        if !canonical_blocked {
            f.engine.close_session().await.unwrap();
            drop(a);
            assert!(
                canonical_blocked,
                "additional OPEN preserved canonical recovered authority"
            );
            return;
        }
        let mut b = f.consumer(2);
        let mut second = f.catalog(&front);
        let proof_a = f.consume(&front, &mut second, &mut a);
        second.accept_consumed(proof_a).unwrap();
        let duplicate_allowance = f.transfer(ChannelInstance::new(1).unwrap(), 0);
        let duplicate_request = RecoveryRequest {
            attachment: front.attachment(),
            channel: ChannelInstance::new(1).unwrap(),
            parser: ParserContinuity::DataCursor { cursor: a.cursor() },
        };
        assert!(f
            .engine
            .recover(
                &front,
                &mut second,
                duplicate_request,
                RecoveryId::new([117; 16]).unwrap(),
                RequestId::new(f.next + 100).unwrap(),
                duplicate_allowance
            )
            .is_err());
        assert!(f
            .engine
            .user_input(
                &front,
                ChannelInstance::new(1).unwrap(),
                InputEpoch::new([1; 16]).unwrap(),
                0,
                b"A"
            )
            .is_err());
        let proof_b = f.consume(&front, &mut second, &mut b);
        second.accept_consumed(proof_b).unwrap();
        f.engine.finish_recovery(&front, second).unwrap();
        f.engine
            .user_input(
                &front,
                ChannelInstance::new(1).unwrap(),
                InputEpoch::new([1; 16]).unwrap(),
                0,
                b"A",
            )
            .unwrap()
            .accepted()
            .await
            .unwrap();
        f.engine
            .user_input(
                &front,
                ChannelInstance::new(2).unwrap(),
                InputEpoch::new([2; 16]).unwrap(),
                0,
                b"B",
            )
            .unwrap()
            .accepted()
            .await
            .unwrap();
        let until = Instant::now() + Duration::from_secs(1);
        while f
            .engine
            .input_position(ChannelInstance::new(1).unwrap())
            .unwrap()
            .committed
            != 1
            || f.engine
                .input_position(ChannelInstance::new(2).unwrap())
                .unwrap()
                .committed
                != 1
        {
            assert!(Instant::now() < until);
            tokio::task::yield_now().await;
        }
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 2);
        drop(a);
        drop(b);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
        assert_eq!(f.io.state.lock().unwrap().1.len(), 2);
    }
    #[tokio::test]
    async fn integrated_frontend_eof_during_partial_write_preserves_pending_fifo_and_stale_drop_cannot_revoke_new_lease(
    ) {
        use std::sync::atomic::Ordering;
        let (mut f, front) = Fixture::new();
        f.open(&front, 1).await;
        let mut consumer = f.consumer(1);
        let mut tx = f.catalog(&front);
        let proof = f.consume(&front, &mut tx, &mut consumer);
        tx.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        let channel = ChannelInstance::new(1).unwrap();
        let epoch = InputEpoch::new([1; 16]).unwrap();
        let writer_identity = Arc::as_ptr(&f.engine.channels[&16].writer);
        f.io.held.store(true, Ordering::SeqCst);
        f.engine
            .user_input(&front, channel, epoch, 0, b"abcd")
            .unwrap()
            .accepted()
            .await
            .unwrap();
        let until = Instant::now() + Duration::from_secs(2);
        while f.io.entered.load(Ordering::SeqCst) == 0 {
            assert!(Instant::now() < until);
            tokio::task::yield_now().await;
        }
        let queued = f
            .engine
            .user_input(&front, channel, epoch, 4, b"ef")
            .unwrap();
        let stale = FrontendAttachment {
            shared: front.shared.clone(),
            attachment: front.attachment(),
        };
        drop(front);
        assert!(!f.engine.barriers_settled());
        assert!(f.engine.attach_trusted(attachment(2)).is_err());
        assert!(f
            .engine
            .user_input(&stale, channel, epoch, 6, b"g")
            .is_err());
        {
            let _state = f.io.state.lock().unwrap();
            f.io.held.store(false, Ordering::SeqCst);
            f.io.changed.notify_all();
        }
        while !f.engine.barriers_settled() {
            assert!(Instant::now() < until);
            tokio::task::yield_now().await;
        }
        let p = queued.accepted().await.unwrap();
        assert_eq!((p.accepted, p.committed), (6, 2));
        assert_eq!(*f.io.state.lock().unwrap().1, b"ab"[..]);
        let front = f.engine.attach_trusted(attachment(2)).unwrap();
        drop(stale);
        assert_eq!(
            f.engine.leases.lock().unwrap().state.phase(),
            AttachmentPhase::Attached
        );
        assert!(f
            .engine
            .user_input(&front, channel, epoch, 6, b"gh")
            .is_err());
        let mut tx = f.catalog(&front);
        let proof = f.consume(&front, &mut tx, &mut consumer);
        tx.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        f.engine
            .user_input(&front, channel, epoch, 6, b"gh")
            .unwrap()
            .accepted()
            .await
            .unwrap();
        while f.engine.input_position(channel).unwrap().committed != 8 {
            assert!(Instant::now() < until);
            tokio::task::yield_now().await;
        }
        assert_eq!(Arc::as_ptr(&f.engine.channels[&16].writer), writer_identity);
        assert_eq!(*f.io.state.lock().unwrap().1, b"abcdefgh"[..]);
        let done = f.engine.close_session().await.unwrap();
        assert!(done[0].workers_joined());
        drop(consumer);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn integrated_empty_catalog_then_open_and_replaced_recovery_never_reuses_old_ready() {
        let (mut f, front) = Fixture::new();
        let empty = f.catalog(&front);
        assert!(empty.catalog().positions().is_empty());
        f.engine.finish_recovery(&front, empty).unwrap();
        f.open(&front, 1).await;
        let channel = ChannelInstance::new(1).unwrap();
        let epoch = InputEpoch::new([1; 16]).unwrap();
        assert!(f.engine.user_input(&front, channel, epoch, 0, b"").is_err());
        let mut consumer = f.consumer(1);
        let mut old = f.catalog(&front);
        let proof = f.consume(&front, &mut old, &mut consumer);
        let mut fresh = f.catalog(&front);
        assert!(
            fresh.accept_consumed(proof).is_err(),
            "old request/Ready completed replacement transaction"
        );
        let proof = f.consume(&front, &mut fresh, &mut consumer);
        fresh.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, fresh).unwrap();
        assert!(f.engine.finish_recovery(&front, old).is_err());
        f.engine
            .user_input(&front, channel, epoch, 0, b"")
            .unwrap()
            .accepted()
            .await
            .unwrap();
        f.engine.close_session().await.unwrap();
        drop(consumer);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn integrated_generation_exhaustion_and_failed_open_do_not_restore_or_half_publish_catalog(
    ) {
        let (mut f, front) = Fixture::new();
        f.open(&front, 1).await;
        let mut consumer = f.consumer(1);
        let mut tx = f.catalog(&front);
        let proof = f.consume(&front, &mut tx, &mut consumer);
        tx.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        {
            let mut s = f.engine.leases.lock().unwrap();
            s.generation = u64::MAX;
            s.ready_generation = Some(u64::MAX);
        }
        let before = f.ledger.lock().unwrap().reservations();
        let channel = ChannelInstance::new(2).unwrap();
        let history = f.reserve(channel, ReservationKind::OutputHistory, 4096);
        let control = f.reserve(channel, ReservationKind::ControlQueue, 131072);
        let request = OpenRequest {
            stream: 17,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        };
        assert!(f
            .engine
            .open(
                &front,
                request.clone(),
                None,
                OwnerChannelResources {
                    history,
                    control,
                    cleanup: RequestId::new(history.id.get()).unwrap(),
                    read_buffer_bytes: 128,
                    input_epoch: InputEpoch::new([2; 16]).unwrap()
                }
            )
            .await
            .is_err());
        assert_eq!(f.engine.channels.len(), 1);
        assert_eq!(f.engine.leases.lock().unwrap().generation, u64::MAX);
        assert!(f
            .engine
            .leases
            .lock()
            .unwrap()
            .state
            .validate_input(front.attachment())
            .is_ok());
        assert_eq!(f.ledger.lock().unwrap().reservations(), before);
        {
            let mut s = f.engine.leases.lock().unwrap();
            s.generation = 10;
            s.ready_generation = Some(10);
        }
        f.io.fail_next
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let history = f.reserve(channel, ReservationKind::OutputHistory, 4096);
        let control = f.reserve(channel, ReservationKind::ControlQueue, 131072);
        assert!(f
            .engine
            .open(
                &front,
                request,
                None,
                OwnerChannelResources {
                    history,
                    control,
                    cleanup: RequestId::new(history.id.get()).unwrap(),
                    read_buffer_bytes: 128,
                    input_epoch: InputEpoch::new([2; 16]).unwrap()
                }
            )
            .await
            .is_err());
        assert!(f
            .engine
            .leases
            .lock()
            .unwrap()
            .state
            .validate_input(front.attachment())
            .is_err());
        let allowance = f.transfer(ChannelInstance::new(1).unwrap(), 0);
        assert!(
            f.engine.catalog(&front, allowance).is_err(),
            "failed channel silently omitted from active catalog"
        );
        f.engine.close_session().await.unwrap();
        drop(consumer);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn integrated_recovery_refuses_unavailable_cursors_foreign_identity_and_unadmitted_storage(
    ) {
        let (mut f, front) = Fixture::new();
        f.open(&front, 1).await;
        let channel = ChannelInstance::new(1).unwrap();
        let mut consumer = f.consumer(1);
        let mut tx = f.catalog(&front);
        let proof = f.consume(&front, &mut tx, &mut consumer);
        tx.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        f.engine
            .acknowledge_output(&front, channel, consumer.cursor().offset)
            .unwrap();
        let mut tx = f.catalog(&front);
        let boundary = tx.catalog().positions()[0].output.offset;
        for cursor in [0, boundary + 1] {
            let allowance = f.transfer(channel, 32);
            let request = RecoveryRequest {
                attachment: front.attachment(),
                channel,
                parser: ParserContinuity::DataCursor {
                    cursor: OutputCursor {
                        channel,
                        offset: cursor,
                    },
                },
            };
            assert!(f
                .engine
                .recover(
                    &front,
                    &mut tx,
                    request,
                    RecoveryId::new([91; 16]).unwrap(),
                    RequestId::new(f.next + 100).unwrap(),
                    allowance
                )
                .is_err());
        }
        let allowance = f.transfer(channel, 32);
        let request = RecoveryRequest {
            attachment: attachment(2),
            channel,
            parser: ParserContinuity::DataCursor {
                cursor: consumer.cursor(),
            },
        };
        assert!(f
            .engine
            .recover(
                &front,
                &mut tx,
                request,
                RecoveryId::new([92; 16]).unwrap(),
                RequestId::new(f.next + 100).unwrap(),
                allowance
            )
            .is_err());
        let allowance = f.transfer(channel, 32);
        let foreign = ChannelInstance::new(2).unwrap();
        let request = RecoveryRequest {
            attachment: front.attachment(),
            channel: foreign,
            parser: ParserContinuity::DataCursor {
                cursor: OutputCursor {
                    channel: foreign,
                    offset: 0,
                },
            },
        };
        assert!(f
            .engine
            .recover(
                &front,
                &mut tx,
                request,
                RecoveryId::new([93; 16]).unwrap(),
                RequestId::new(f.next + 100).unwrap(),
                allowance
            )
            .is_err());
        let before = f.ledger.lock().unwrap().reservations();
        let r = f.reserve(channel, ReservationKind::SnapshotTransfer, 1);
        assert!(TransferAllowance::admit(
            f.client.clone(),
            r,
            RequestId::new(r.id.get()).unwrap(),
            32
        )
        .is_err());
        assert_eq!(f.ledger.lock().unwrap().reservations(), before);
        assert!(f.engine.catalog_available());
        let proof = f.consume(&front, &mut tx, &mut consumer);
        tx.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        f.engine.close_session().await.unwrap();
        drop(consumer);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn integrated_recovery_binds_actual_geometry_and_snapshot_live_boundary() {
        let (mut f, front) = Fixture::new();
        f.open(&front, 1).await;
        let channel = ChannelInstance::new(1).unwrap();
        let mut consumer = f.consumer(1);
        let mut tx = f.catalog(&front);
        let position = tx.catalog().positions()[0];
        let request = RecoveryRequest {
            attachment: front.attachment(),
            channel,
            parser: ParserContinuity::DataCursor {
                cursor: consumer.cursor(),
            },
        };
        let id = RequestId::new(100).unwrap();
        let allowance = f.transfer(channel, position.output.offset as usize);
        let mut producer = f
            .engine
            .recover(
                &front,
                &mut tx,
                request,
                RecoveryId::new([94; 16]).unwrap(),
                id,
                allowance,
            )
            .unwrap();
        let mut wrong_geometry = producer.start();
        wrong_geometry.geometry.cols = 81;
        consumer.begin(id, request, wrong_geometry).unwrap();
        while let Some(chunk) = producer.next_chunk().unwrap() {
            consumer.consume(&chunk).unwrap();
        }
        let (end, ready) = producer.end().unwrap();
        let proof = consumer.finish(end, ready).unwrap();
        assert!(tx.accept_consumed(proof).is_err());
        assert!(f.engine.finish_recovery(&front, tx).is_err());
        drop(producer);
        let mut tx = f.catalog(&front);
        let cursor = consumer.cursor();
        let request = RecoveryRequest {
            attachment: front.attachment(),
            channel,
            parser: ParserContinuity::DataCursor { cursor },
        };
        let allowance = f.transfer(channel, 0);
        let mut producer = f
            .engine
            .recover(
                &front,
                &mut tx,
                request,
                RecoveryId::new([95; 16]).unwrap(),
                RequestId::new(101).unwrap(),
                allowance,
            )
            .unwrap();
        {
            let _state = f.io.state.lock().unwrap();
            f.io.suffix_ready
                .store(true, std::sync::atomic::Ordering::SeqCst);
            f.io.changed.notify_all();
        }
        let until = Instant::now() + Duration::from_secs(2);
        while f.engine.channels[&16]
            .output
            .state
            .lock()
            .unwrap()
            .bytes
            .len()
            != 19
        {
            assert!(Instant::now() < until);
            tokio::task::yield_now().await;
        }
        consumer
            .begin(RequestId::new(101).unwrap(), request, producer.start())
            .unwrap();
        assert!(producer.next_chunk().unwrap().is_none());
        let (end, ready) = producer.end().unwrap();
        let proof = consumer.finish(end, ready).unwrap();
        tx.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        let mut live = [0; 16];
        let n = f
            .engine
            .copy_output(&front, channel, consumer.cursor().offset, &mut live)
            .unwrap();
        consumer
            .consume_live(consumer.cursor().offset, &live[..n])
            .unwrap();
        assert_eq!(consumer.bytes(), b"record:partial:live");
        f.engine
            .acknowledge_output(&front, channel, consumer.cursor().offset)
            .unwrap();
        drop(producer);
        f.engine.close_session().await.unwrap();
        drop(consumer);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn integrated_transfer_cannot_reset_host_accounting_with_a_foreign_real_ledger() {
        let (mut f, front) = Fixture::new();
        let (mut other, _) = Fixture::new_scope(73);
        f.open(&front, 1).await;
        let allowance = other.transfer(ChannelInstance::new(1).unwrap(), 0);
        let accepted_foreign_host = f.engine.catalog(&front, allowance).is_ok();
        if !accepted_foreign_host {
            let channel = ChannelInstance::new(1).unwrap();
            let mut tx = f.catalog(&front);
            let position = tx.catalog().positions()[0];
            let request = RecoveryRequest {
                attachment: front.attachment(),
                channel,
                parser: ParserContinuity::DataCursor {
                    cursor: OutputCursor { channel, offset: 0 },
                },
            };
            let foreign = other.transfer(channel, position.output.offset as usize);
            assert!(f
                .engine
                .recover(
                    &front,
                    &mut tx,
                    request,
                    RecoveryId::new([96; 16]).unwrap(),
                    RequestId::new(120).unwrap(),
                    foreign
                )
                .is_err());
            let own = f.transfer(channel, position.output.offset as usize);
            let mut producer = f
                .engine
                .recover(
                    &front,
                    &mut tx,
                    request,
                    RecoveryId::new([97; 16]).unwrap(),
                    RequestId::new(121).unwrap(),
                    own,
                )
                .unwrap();
            let mut consumer =
                NoScreenConsumer::new(channel, other.transfer(channel, 4096)).unwrap();
            consumer
                .begin(RequestId::new(121).unwrap(), request, producer.start())
                .unwrap();
            while let Some(chunk) = producer.next_chunk().unwrap() {
                consumer.consume(&chunk).unwrap();
            }
            let (end, ready) = producer.end().unwrap();
            assert!(
                tx.accept_consumed(consumer.finish(end, ready).unwrap())
                    .is_err(),
                "foreign consumer budget became host recovery authority"
            );
            assert!(f.engine.finish_recovery(&front, tx).is_err());
            drop(producer);
            drop(consumer);
        }
        f.engine.close_session().await.unwrap();
        other.engine.close_session().await.unwrap();
        assert!(
            !accepted_foreign_host,
            "matching public locator bypassed the actual shared host ledger"
        );
    }
    #[tokio::test]
    async fn integrated_reused_recovery_id_cannot_promote_an_old_completion_into_a_new_catalog() {
        let (mut f, front) = Fixture::new();
        f.open(&front, 1).await;
        let channel = ChannelInstance::new(1).unwrap();
        let mut consumer = f.consumer(1);
        let mut old = f.catalog(&front);
        let old_proof = f.consume(&front, &mut old, &mut consumer);
        let old_request = RequestId::new(f.next + 100).unwrap();
        drop(old);
        let mut fresh = f.catalog(&front);
        let allowance = f.transfer(channel, 0);
        let request = RecoveryRequest {
            attachment: front.attachment(),
            channel,
            parser: ParserContinuity::DataCursor {
                cursor: consumer.cursor(),
            },
        };
        let attempt = f.engine.recover(
            &front,
            &mut fresh,
            request,
            RecoveryId::new([118; 16]).unwrap(),
            old_request,
            allowance,
        );
        let stale_enabled = match attempt {
            Ok(producer) => {
                drop(producer);
                let accepted = fresh.accept_consumed(old_proof).is_ok();
                accepted && f.engine.finish_recovery(&front, fresh).is_ok()
            }
            Err(_) => {
                drop(fresh);
                false
            }
        };
        f.engine.close_session().await.unwrap();
        drop(consumer);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
        assert!(
            !stale_enabled,
            "old completion and reused request identity restored a replacement catalog"
        );
    }
    #[tokio::test]
    async fn integrated_cancelled_open_keeps_recovery_invalid_and_never_publishes_late_ready() {
        use std::sync::atomic::Ordering;
        let (mut f, front) = Fixture::new();
        f.open(&front, 1).await;
        let mut consumer = f.consumer(1);
        let mut tx = f.catalog(&front);
        let proof = f.consume(&front, &mut tx, &mut consumer);
        tx.accept_consumed(proof).unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        let before = f.engine.leases.lock().unwrap().generation;
        let channel = ChannelInstance::new(2).unwrap();
        let history = f.reserve(channel, ReservationKind::OutputHistory, 4096);
        let control = f.reserve(channel, ReservationKind::ControlQueue, 131072);
        let io = f.io.clone();
        io.spawn_hold.store(true, Ordering::SeqCst);
        {
            let open = f.engine.open(
                &front,
                OpenRequest {
                    stream: 17,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: Vec::new(),
                },
                None,
                OwnerChannelResources {
                    history,
                    control,
                    cleanup: RequestId::new(history.id.get()).unwrap(),
                    read_buffer_bytes: 128,
                    input_epoch: InputEpoch::new([2; 16]).unwrap(),
                },
            );
            tokio::pin!(open);
            tokio::select! {result=&mut open=>panic!("held backend unexpectedly completed: {result:?}"),_=async {let until=Instant::now()+Duration::from_secs(2);while io.spawn_entered.load(Ordering::SeqCst)<2 {assert!(Instant::now()<until);tokio::task::yield_now().await;}}=>{}}
        }
        assert!(f.engine.leases.lock().unwrap().generation > before);
        assert!(f
            .engine
            .leases
            .lock()
            .unwrap()
            .state
            .validate_input(front.attachment())
            .is_err());
        assert!(!f.engine.channels[&17].installed);
        assert!(!f.engine.catalog_available());
        {
            let _state = io.state.lock().unwrap();
            io.spawn_hold.store(false, Ordering::SeqCst);
            io.changed.notify_all();
        }
        f.engine.close_session().await.unwrap();
        drop(consumer);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn integrated_current_idle_watch_admission_and_changed_epoch_refuse_stale_installation() {
        use std::sync::atomic::Ordering;
        let (mut f, front) = Fixture::new();
        let channel = ChannelInstance::new(1).unwrap();
        f.restart.send_replace(RestartSignal {
            phase: transport::channel_server::RestartPhase::Announced,
            invalidation_epoch: 1,
            ..RestartSignal::IDLE
        });
        let history = f.reserve(channel, ReservationKind::OutputHistory, 4096);
        let control = f.reserve(channel, ReservationKind::ControlQueue, 131072);
        let request = OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        };
        assert!(f
            .engine
            .open(
                &front,
                request.clone(),
                None,
                OwnerChannelResources {
                    history,
                    control,
                    cleanup: RequestId::new(history.id.get()).unwrap(),
                    read_buffer_bytes: 128,
                    input_epoch: InputEpoch::new([1; 16]).unwrap()
                }
            )
            .await
            .is_err());
        assert_eq!(f.io.spawn_entered.load(Ordering::SeqCst), 0);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
        f.restart.send_replace(RestartSignal {
            invalidation_epoch: 1,
            ..RestartSignal::IDLE
        });
        // Successful commit at a nonzero current epoch proves admission did not
        // retain an initial/stale epoch before the adversarial change below.
        f.open(&front, 1).await;
        let channel = ChannelInstance::new(2).unwrap();
        let request = OpenRequest {
            stream: 17,
            ..request
        };
        let history = f.reserve(channel, ReservationKind::OutputHistory, 4096);
        let control = f.reserve(channel, ReservationKind::ControlQueue, 131072);
        let io = f.io.clone();
        let restart = f.restart.clone();
        io.spawn_hold.store(true, Ordering::SeqCst);
        {
            let open = f.engine.open(
                &front,
                request,
                None,
                OwnerChannelResources {
                    history,
                    control,
                    cleanup: RequestId::new(history.id.get()).unwrap(),
                    read_buffer_bytes: 128,
                    input_epoch: InputEpoch::new([1; 16]).unwrap(),
                },
            );
            tokio::pin!(open);
            tokio::select! {result=&mut open=>panic!("held open completed: {result:?}"),_=async{let until=Instant::now()+Duration::from_secs(2);while io.spawn_entered.load(Ordering::SeqCst)<2{assert!(Instant::now()<until);tokio::task::yield_now().await;}}=>{}}
            restart.send_replace(RestartSignal {
                invalidation_epoch: 2,
                ..RestartSignal::IDLE
            });
            {
                let _state = io.state.lock().unwrap();
                io.spawn_hold.store(false, Ordering::SeqCst);
                io.changed.notify_all();
            }
            assert!(
                open.await.is_err(),
                "stale prepared open ignored the authoritative new Idle epoch"
            );
        }
        assert_eq!(f.engine.retained.channels(), 1);
        assert!(!f.engine.channels[&17].installed);
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
}
