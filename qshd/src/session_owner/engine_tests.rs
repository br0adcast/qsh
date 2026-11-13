use super::*;
use std::io::Read;
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
        state: Mutex::new(OutputState::new(
            Vec::with_capacity(8),
            GeometryRecord {
                instance: ChannelInstance::new(1).unwrap(),
                request_id: 0,
                outcome: GeometryOutcome::Established,
                cols: 80,
                rows: 24,
            },
        )),
        changed: Condvar::new(),
        capacity: 8,
        writer: None,
        wake: Default::default(),
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
    async fn wait(mut condition: impl FnMut() -> bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !condition() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("actual fixture condition before deadline");
    }
    #[derive(Default)]
    struct Io {
        state: Mutex<(bool, Vec<u8>)>,
        script: Mutex<Option<Vec<u8>>>,
        changed: Condvar,
        held: std::sync::atomic::AtomicBool,
        entered: std::sync::atomic::AtomicUsize,
        fail_next: std::sync::atomic::AtomicBool,
        suffix_ready: std::sync::atomic::AtomicBool,
        spawn_hold: std::sync::atomic::AtomicBool,
        spawn_entered: std::sync::atomic::AtomicUsize,
        reader_held: std::sync::atomic::AtomicBool,
        reader_calls: std::sync::atomic::AtomicUsize,
        resize_calls: std::sync::atomic::AtomicUsize,
        resize_fail: std::sync::atomic::AtomicBool,
        resize_size: std::sync::atomic::AtomicUsize,
    }
    struct Reader {
        io: Arc<Io>,
        offset: usize,
    }
    impl Read for Reader {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let suffix = b":live";
            let mut state = self.io.state.lock().unwrap();
            self.io
                .reader_calls
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            loop {
                if self
                    .io
                    .reader_held
                    .load(std::sync::atomic::Ordering::SeqCst)
                    && !state.0
                {
                    state = self.io.changed.wait(state).unwrap();
                    continue;
                }
                let script = self.io.script.lock().unwrap();
                let data = script.as_deref().unwrap_or(b"record:partial");
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
                drop(script);
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
    struct Resize(Arc<Io>);
    impl ResizeHandle for Resize {
        fn try_resize(&self, cols: u16, rows: u16) -> Result<(), String> {
            use std::sync::atomic::Ordering;
            self.0.resize_calls.fetch_add(1, Ordering::SeqCst);
            if self.0.resize_fail.swap(false, Ordering::SeqCst) {
                return Err("synthetic ioctl refusal".into());
            }
            self.0.resize_size.store(
                (usize::from(cols) << 16) | usize::from(rows),
                Ordering::SeqCst,
            );
            Ok(())
        }
    }
    struct Spawner {
        registry: Arc<ChannelOpenRegistry>,
        io: Arc<Io>,
        screens: Option<Arc<crate::session_owner::screen_owner::RetainedScreenFactory>>,
    }
    impl ChannelSpawner for Spawner {
        fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            principal: &Principal,
            login: LoginId,
            request: &OpenRequest,
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
            let model: Box<dyn transport::shell_server::SessionScreen> = if request.screen {
                self.screens
                    .as_ref()
                    .unwrap()
                    .take(principal, login, request, custody)
                    .map_err(|e| custody.refuse_before_creation(e))?
            } else {
                Box::new(NoScreen)
            };
            Ok(custody
                .protect(Box::new(Wait(self.io.clone())), model)
                .finish(
                    Box::new(Reader {
                        io: self.io.clone(),
                        offset: 0,
                    }),
                    Box::new(Writer(self.io.clone())),
                    Box::new(Resize(self.io.clone())),
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
        control_scope: Option<crate::session_owner::screen_control::ControlTaskScope>,
    }
    impl Fixture {
        fn new() -> (Self, FrontendAttachment) {
            Self::new_scope(72)
        }
        fn new_scope(scope: u8) -> (Self, FrontendAttachment) {
            Self::new_config(scope, false)
        }
        fn new_screen() -> (Self, FrontendAttachment) {
            Self::new_config(82, true)
        }
        fn new_config(scope: u8, screen: bool) -> (Self, FrontendAttachment) {
            let p = AuthenticatedPrincipalRef::new([71; 16]).unwrap();
            let l = ByteLimits {
                channel_bytes: if screen { 32 << 20 } else { 4 << 20 },
                session_bytes: if screen { 64 << 20 } else { 8 << 20 },
                account_bytes: if screen { 128 << 20 } else { 16 << 20 },
                global_bytes: if screen { 256 << 20 } else { 32 << 20 },
            };
            let mut ledger = ResourceLedger::new(
                LedgerInstance::new([scope; 16]).unwrap(),
                ResourceLimits {
                    max_reservations: 64,
                    screen: if screen {
                        ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default())
                            .unwrap()
                    } else {
                        ScreenLimits {
                            global_cells: 0,
                            account_cells: 0,
                            global_rows: 0,
                            account_rows: 0,
                            global_models: 0,
                            account_models: 0,
                        }
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
            let screens = screen.then(|| {
                Arc::new(crate::session_owner::screen_owner::RetainedScreenFactory::new())
            });
            let spawner = Arc::new(Spawner {
                registry: ChannelOpenRegistry::new(OpenLimits::default()),
                io: io.clone(),
                screens: screens.clone(),
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
            let control_scope = screen.then(|| {
                crate::session_owner::screen_control::ControlTaskScope::new(
                    tokio::runtime::Handle::current(),
                )
            });
            if let Some(screens) = screens {
                use crate::session_owner::screen_control::*;
                let anchor = Reservation {
                    id: ReservationId::new(2).unwrap(),
                    principal: p,
                    locator: locator(),
                    channel: ChannelInstance::new(1).unwrap(),
                    kind: ReservationKind::ControlQueue,
                    bytes: 65536,
                    screen_charge: None,
                };
                engine = engine.with_screen_factory(screens).with_screen_control(
                    ScreenControlContext::new(
                        control_scope.as_ref().unwrap().clone(),
                        anchor,
                        RequestId::new(2).unwrap(),
                    ),
                );
            }
            let front = engine.attach_trusted(attachment(1)).unwrap();
            (
                Self {
                    engine,
                    client,
                    ledger,
                    next: 0,
                    io,
                    restart: restart_tx,
                    control_scope,
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
            self.next = self.next.max(
                self.ledger
                    .lock()
                    .unwrap()
                    .next_reservation_id()
                    .unwrap()
                    .get()
                    - 1,
            );
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
        fn screen_client(
            &mut self,
            channel: ChannelInstance,
        ) -> crate::session_owner::screen_recovery::ScreenConsumer {
            let quote = self.engine.screen_recovery_requirements(channel).unwrap();
            let allowance = self.transfer(channel, quote.max_bytes);
            let budget = Arc::new(crate::screen_budget::ScreenBudget::new(
                crate::screen_budget::BudgetLimits {
                    global_cells: 8_388_608,
                    owner_cells: 8_388_608,
                    global_rows: 2_097_152,
                    owner_rows: 2_097_152,
                    global_models: 1,
                    owner_models: 1,
                },
            ));
            crate::session_owner::screen_recovery::ScreenConsumer::new(
                channel,
                [91; 16],
                terminal_size::TerminalSize::new(80, 24).unwrap(),
                1000,
                budget,
                allowance,
            )
            .unwrap()
        }
        async fn recover_screen_client(
            &mut self,
            front: &FrontendAttachment,
            client: &mut crate::session_owner::screen_recovery::ScreenConsumer,
            serial: u8,
        ) -> RecoveryMode {
            let (mode, transaction) = self.recover_screen_transaction(front, client, serial).await;
            wait(|| self.engine.catalog_available()).await;
            self.engine.finish_recovery(front, transaction).unwrap();
            mode
        }
        async fn recover_screen_transaction(
            &mut self,
            front: &FrontendAttachment,
            client: &mut crate::session_owner::screen_recovery::ScreenConsumer,
            serial: u8,
        ) -> (RecoveryMode, OwnerRecovery) {
            use crate::session_owner::screen_recovery::*;
            let channel = client.cursor().channel;
            wait(|| {
                self.engine.catalog_available() && {
                    let s = self.engine.channels[&16].output.state.lock().unwrap();
                    !s.replies_pending() && !s.busy
                }
            })
            .await;
            let catalog = self.transfer(channel, 0);
            let mut tx = self.engine.catalog(front, catalog).unwrap();
            let quote = self.engine.screen_recovery_requirements(channel).unwrap();
            let bytes = self.reserve(
                channel,
                ReservationKind::SnapshotTransfer,
                quote.transfer_bytes as u64,
            );
            let mut scratch = self.reserve(channel, ReservationKind::ScreenModel, 0);
            scratch.screen_charge = Some(quote.scratch);
            let allowance = ScreenRecoveryAllowance::admit(
                self.client.clone(),
                bytes,
                scratch,
                RequestId::new(bytes.id.get()).unwrap(),
                quote,
            )
            .unwrap();
            let (request, evidence) = client.request(front.attachment());
            let id = RequestId::new(1000 + u64::from(serial)).unwrap();
            let mut producer = self
                .engine
                .recover_screen(
                    front,
                    &mut tx,
                    request,
                    &evidence,
                    RecoveryId::new([serial; 16]).unwrap(),
                    id,
                    allowance,
                )
                .unwrap();
            let mode = producer.start().mode;
            client.begin(id, request, producer.start()).unwrap();
            while let Some(chunk) = producer.next_chunk().unwrap() {
                client.consume(&chunk).unwrap();
            }
            let (end, ready) = producer.end().unwrap();
            tx.accept_consumed(client.finish(end, ready).unwrap())
                .unwrap();
            wait(|| {
                !self.engine.channels[&16]
                    .output
                    .state
                    .lock()
                    .unwrap()
                    .replies_pending()
            })
            .await;
            (mode, tx)
        }
        async fn open_screen(&mut self, front: &FrontendAttachment) -> ChannelInstance {
            let channel = ChannelInstance::new(1).unwrap();
            let size = terminal_size::TerminalSize::new(80, 24).unwrap();
            let slots = crate::screen_budget::ScreenEnvelope::new(size)
                .charge()
                .unwrap();
            let mut model = self.reserve(channel, ReservationKind::ScreenModel, 0);
            model.screen_charge = Some(ScreenCharge {
                cells: slots.cells as u64,
                rows: slots.rows as u64,
                models: 1,
            });
            let lease = crate::session_owner::screen_owner::HostScreenLease::admit(
                self.client.clone(),
                model,
                RequestId::new(model.id.get()).unwrap(),
                size,
            )
            .unwrap();
            self.next += 1; // separately supplied scheduler anchor id2 is admitted by open_screen first
            let history = self.reserve(channel, ReservationKind::OutputHistory, 4096);
            let control = self.reserve(channel, ReservationKind::ControlQueue, 512 * 1024);
            self.engine
                .open_screen(
                    front,
                    OpenRequest {
                        stream: 16,
                        kind: ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: true,
                        command: vec![],
                    },
                    None,
                    OwnerChannelResources {
                        history,
                        control,
                        cleanup: RequestId::new(history.id.get()).unwrap(),
                        read_buffer_bytes: 128,
                        input_epoch: InputEpoch::new([1; 16]).unwrap(),
                    },
                    lease,
                )
                .await
                .expect("charged canonical Screen OPEN")
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
    #[tokio::test]
    async fn screen_owner_open_retains_the_actual_charged_model_across_frontend_drop() {
        let (mut f, front) = Fixture::new_screen();
        let channel = f.open_screen(&front).await;
        assert_eq!(
            f.io.spawn_entered.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        let before = f.ledger.lock().unwrap().reservations();
        drop(front);
        assert_eq!(f.ledger.lock().unwrap().reservations(), before);
        assert!(f.engine.retained.ready_to_publish(channel));
        let receipts = f.engine.close_session().await.unwrap();
        assert_eq!(receipts.len(), 1);
        assert!(receipts[0].workers_joined());
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }

    #[tokio::test]
    async fn screen_owner_recreated_consumer_resets_inside_available_history_then_matches_live_continuation(
    ) {
        use crate::session_owner::screen_recovery::*;
        let (mut f, front) = Fixture::new_screen();
        let script = b"\x1b[31mhello\x1b[0m\r\nworld\x1b[2;3H\x1b[";
        *f.io.script.lock().unwrap() = Some(script.to_vec());
        let channel = f.open_screen(&front).await;
        wait(|| {
            f.engine.channels[&16]
                .output
                .state
                .lock()
                .unwrap()
                .bytes
                .len()
                == script.len()
        })
        .await;
        let quote = f.engine.screen_recovery_requirements(channel).unwrap();
        let client_allowance = f.transfer(channel, quote.max_bytes);
        let client_budget = Arc::new(crate::screen_budget::ScreenBudget::new(
            crate::screen_budget::BudgetLimits {
                global_cells: 8_388_608,
                owner_cells: 8_388_608,
                global_rows: 2_097_152,
                owner_rows: 2_097_152,
                global_models: 1,
                owner_models: 1,
            },
        ));
        let mut client = ScreenConsumer::new(
            channel,
            [9; 16],
            terminal_size::TerminalSize::new(80, 24).unwrap(),
            1000,
            client_budget,
            client_allowance,
        )
        .unwrap();
        let catalog_allowance = f.transfer(channel, 0);
        let mut recovery = f.engine.catalog(&front, catalog_allowance).unwrap();
        let (request, evidence) = client.request(front.attachment());
        let bytes = f.reserve(
            channel,
            ReservationKind::SnapshotTransfer,
            quote.transfer_bytes as u64,
        );
        let mut scratch = f.reserve(channel, ReservationKind::ScreenModel, 0);
        scratch.screen_charge = Some(quote.scratch);
        let allowance = ScreenRecoveryAllowance::admit(
            f.client.clone(),
            bytes,
            scratch,
            RequestId::new(bytes.id.get()).unwrap(),
            quote,
        )
        .unwrap();
        let mut producer = f
            .engine
            .recover_screen(
                &front,
                &mut recovery,
                request,
                &evidence,
                RecoveryId::new([8; 16]).unwrap(),
                RequestId::new(100).unwrap(),
                allowance,
            )
            .unwrap();
        assert_eq!(
            producer.start().mode,
            RecoveryMode::ScreenReset,
            "a fresh parser was mistaken for retained evidence"
        );
        client
            .begin(RequestId::new(100).unwrap(), request, producer.start())
            .unwrap();
        while let Some(chunk) = producer.next_chunk().unwrap() {
            client.consume(&chunk).unwrap();
        }
        let (end, ready) = producer.end().unwrap();
        recovery
            .accept_consumed(client.finish(end, ready).unwrap())
            .unwrap();
        f.engine.finish_recovery(&front, recovery).unwrap();
        {
            let mut output = f.engine.channels[&16].output.state.lock().unwrap();
            let actual = (&mut *output.model.as_mut().unwrap().screen as &mut dyn std::any::Any)
                .downcast_mut::<crate::screen::PtyScreen>()
                .unwrap()
                .snapshot();
            assert_eq!(client.snapshot(), actual);
        }
        let suffix = b"4m!\x1b[0m";
        f.io.script
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .extend_from_slice(suffix);
        f.io.changed.notify_all();
        wait(|| {
            f.engine.channels[&16]
                .output
                .state
                .lock()
                .unwrap()
                .bytes
                .len()
                == script.len() + suffix.len()
        })
        .await;
        let mut live = [0; 128];
        let n = f
            .engine
            .copy_output(&front, channel, end.boundary.offset, &mut live)
            .unwrap();
        client
            .consume_live(end.boundary.offset, &live[..n])
            .unwrap();
        {
            let mut output = f.engine.channels[&16].output.state.lock().unwrap();
            let actual = (&mut *output.model.as_mut().unwrap().screen as &mut dyn std::any::Any)
                .downcast_mut::<crate::screen::PtyScreen>()
                .unwrap()
                .snapshot();
            assert_eq!(client.snapshot(), actual);
        }
        drop(producer);
        drop(client);
        f.engine.close_session().await.unwrap();
        assert!(f.engine.control_joined());
        assert_eq!(
            f.ledger.lock().unwrap().reservations(),
            1,
            "private evidence still retains actual parser metadata backing"
        );
        drop(evidence);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }

    #[tokio::test]
    async fn screen_owner_resize_rolls_back_ioctl_failure_and_resets_real_geometry_epoch() {
        use std::sync::atomic::Ordering;
        use transport::channel_geometry::{ResizeRefusal, ResizeRequestId};
        let (mut f, front) = Fixture::new_screen();
        let channel = f.open_screen(&front).await;
        wait(|| {
            f.engine.channels[&16]
                .output
                .state
                .lock()
                .unwrap()
                .bytes
                .len()
                == 14
        })
        .await;
        let mut client = f.screen_client(channel);
        assert_eq!(
            f.recover_screen_client(&front, &mut client, 1).await,
            RecoveryMode::ScreenReset
        );
        let baseline = f.ledger.lock().unwrap().reservations();
        f.io.resize_fail.store(true, Ordering::SeqCst);
        let failed = f
            .engine
            .resize(&front, channel, ResizeRequestId::new(1).unwrap(), 70, 20)
            .unwrap();
        assert_eq!(
            failed.outcome,
            GeometryOutcome::Refused(ResizeRefusal::PtyResizeFailed)
        );
        assert_eq!((failed.cols, failed.rows), (80, 24));
        assert_eq!(
            f.ledger.lock().unwrap().reservations(),
            baseline,
            "cancelled provisional lease leaked"
        );
        assert!(f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"")
            .is_err());
        assert_eq!(
            f.recover_screen_client(&front, &mut client, 2).await,
            RecoveryMode::Replay
        );
        let same = f
            .engine
            .resize(&front, channel, ResizeRequestId::new(2).unwrap(), 80, 24)
            .unwrap();
        assert_eq!(same.outcome, GeometryOutcome::Applied);
        assert_eq!(
            f.io.resize_calls.load(Ordering::SeqCst),
            1,
            "same size invoked ioctl or scratch"
        );
        let applied = f
            .engine
            .resize(&front, channel, ResizeRequestId::new(3).unwrap(), 100, 30)
            .unwrap();
        assert_eq!((applied.cols, applied.rows), (100, 30));
        assert_eq!(applied.outcome, GeometryOutcome::Applied);
        assert_eq!(f.ledger.lock().unwrap().reservations(), baseline);
        assert!(f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"")
            .is_err());
        assert_eq!(
            f.recover_screen_client(&front, &mut client, 3).await,
            RecoveryMode::ScreenReset,
            "old geometry evidence authorized raw replay across resize"
        );
        assert_eq!(f.io.resize_size.load(Ordering::SeqCst), (100 << 16) | 30);
        let actual = {
            let mut output = f.engine.channels[&16].output.state.lock().unwrap();
            (&mut *output.model.as_mut().unwrap().screen as &mut dyn std::any::Any)
                .downcast_mut::<crate::screen::PtyScreen>()
                .unwrap()
                .snapshot()
        };
        assert_eq!(client.snapshot(), actual);
        drop(client);
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }

    #[tokio::test]
    async fn screen_control_stopped_runtime_refuses_child_and_close_cannot_claim_unknown_cleanup() {
        use crate::session_owner::{screen_control::*, screen_owner::HostScreenLease};
        let (mut f, front) = Fixture::new_screen();
        let handle = std::thread::spawn(|| {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let handle = rt.handle().clone();
            drop(rt);
            handle
        })
        .join()
        .unwrap();
        let scope = ControlTaskScope::new(handle);
        let channel = ChannelInstance::new(1).unwrap();
        let anchor = Reservation {
            id: ReservationId::new(2).unwrap(),
            principal: f.client.principal(),
            locator: locator(),
            channel,
            kind: ReservationKind::ControlQueue,
            bytes: 65536,
            screen_charge: None,
        };
        f.engine.screen_control = Some(ScreenControlContext::new(
            scope.clone(),
            anchor,
            RequestId::new(2).unwrap(),
        ));
        let size = terminal_size::TerminalSize::new(80, 24).unwrap();
        let slots = crate::screen_budget::ScreenEnvelope::new(size)
            .charge()
            .unwrap();
        let mut model = f.reserve(channel, ReservationKind::ScreenModel, 0);
        model.screen_charge = Some(ScreenCharge {
            cells: slots.cells as u64,
            rows: slots.rows as u64,
            models: 1,
        });
        let lease =
            HostScreenLease::admit(f.client.clone(), model, RequestId::new(1).unwrap(), size)
                .unwrap();
        f.next += 1;
        let history = f.reserve(channel, ReservationKind::OutputHistory, 4096);
        let control = f.reserve(channel, ReservationKind::ControlQueue, 4 * 65536 + 4096);
        let opened = f
            .engine
            .open_screen(
                &front,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: true,
                    command: vec![],
                },
                None,
                OwnerChannelResources {
                    history,
                    control,
                    cleanup: RequestId::new(3).unwrap(),
                    read_buffer_bytes: 128,
                    input_epoch: InputEpoch::new([1; 16]).unwrap(),
                },
                lease,
            )
            .await;
        assert!(opened.is_err());
        assert_eq!(
            f.io.spawn_entered.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        assert_eq!(scope.registered(), 0);
        assert_eq!(
            f.ledger.lock().unwrap().reservations(),
            1,
            "unknown task charge was refunded"
        );
        assert!(
            f.engine.close_session().await.is_err(),
            "Close reported successful cleanup with unresolved scheduler debt"
        );
    }

    #[tokio::test]
    async fn screen_owner_replay_checkpoint_flushes_fresh_sync_query_once_before_ready() {
        let (mut f, front) = Fixture::new_screen();
        *f.io.script.lock().unwrap() = Some(b"start".to_vec());
        let channel = f.open_screen(&front).await;
        wait(|| {
            f.engine.channels[&16]
                .output
                .state
                .lock()
                .unwrap()
                .bytes
                .len()
                == 5
        })
        .await;
        let mut client = f.screen_client(channel);
        f.recover_screen_client(&front, &mut client, 1).await;
        let query = b"\x1b[?2026h\x1b[18t";
        f.io.script
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .extend_from_slice(query);
        f.io.changed.notify_all();
        wait(|| {
            f.engine.channels[&16]
                .output
                .state
                .lock()
                .unwrap()
                .bytes
                .len()
                == 5 + query.len()
        })
        .await;
        let (mode, transaction) = f.recover_screen_transaction(&front, &mut client, 2).await;
        assert_eq!(mode, RecoveryMode::Replay);
        // Admission of the captured answer is distinct from the writer's
        // physical partial writes. Ready requires the actual writer barrier.
        wait(|| f.io.state.lock().unwrap().1.len() == b"\x1b[8;24;80t".len()).await;
        wait(|| f.engine.barriers_settled()).await;
        f.engine.finish_recovery(&front, transaction).unwrap();
        assert!(
            f.engine.channels[&16]
                .output
                .state
                .lock()
                .unwrap()
                .model
                .as_ref()
                .unwrap()
                .screen
                .sync_deadline()
                .is_none(),
            "raw replay checkpoint left fresh authoritative output unexecuted"
        );
        wait(|| f.io.state.lock().unwrap().1.len() == b"\x1b[8;24;80t".len()).await;
        assert_eq!(f.io.state.lock().unwrap().1, b"\x1b[8;24;80t");
        let actual = {
            let mut output = f.engine.channels[&16].output.state.lock().unwrap();
            (&mut *output.model.as_mut().unwrap().screen as &mut dyn std::any::Any)
                .downcast_mut::<crate::screen::PtyScreen>()
                .unwrap()
                .snapshot()
        };
        assert_eq!(client.snapshot(), actual);
        drop(client);
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn screen_owner_due_query_flushes_while_actual_reader_waits_and_recovery_never_reanswers()
    {
        use std::sync::atomic::Ordering;
        let (mut f, front) = Fixture::new_screen();
        let query = b"\x1b[?2026h\x1b[18t";
        *f.io.script.lock().unwrap() = Some(query.to_vec());
        let channel = f.open_screen(&front).await;
        wait(|| f.io.reader_calls.load(Ordering::SeqCst) >= 2).await;
        wait(|| {
            let output = f.engine.channels[&16].output.state.lock().unwrap();
            !output.replies_pending()
                && output
                    .model
                    .as_ref()
                    .unwrap()
                    .screen
                    .sync_deadline()
                    .is_none()
        })
        .await;
        assert!(
            f.io.state.lock().unwrap().1.is_empty(),
            "reply bypassed initial recovery fence"
        );
        let mut client = f.screen_client(channel);
        f.recover_screen_client(&front, &mut client, 1).await;
        wait(|| f.io.state.lock().unwrap().1.len() >= b"\x1b[8;24;80t".len()).await;
        assert_eq!(f.io.state.lock().unwrap().1, b"\x1b[8;24;80t");
        f.recover_screen_client(&front, &mut client, 2).await;
        assert_eq!(
            f.io.state.lock().unwrap().1,
            b"\x1b[8;24;80t",
            "a repeated checkpoint answered an already-executed query"
        );
        drop(client);
        f.engine.close_session().await.unwrap();
        assert!(f.engine.control_joined());
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn screen_owner_detached_megabyte_progress_evicts_only_raw_history_and_resets_fresh_client(
    ) {
        use std::sync::atomic::Ordering;
        let (mut f, front) = Fixture::new_screen();
        let mut script = b"x\r\n".repeat(400_000);
        script.extend_from_slice(b"FINAL529");
        *f.io.script.lock().unwrap() = Some(script.clone());
        f.io.reader_held.store(true, Ordering::SeqCst);
        let channel = f.open_screen(&front).await;
        drop(front);
        f.io.reader_held.store(false, Ordering::SeqCst);
        f.io.changed.notify_all();
        wait(|| {
            let output = f.engine.channels[&16].output.state.lock().unwrap();
            output.start + output.bytes.len() as u64 == script.len() as u64
        })
        .await;
        {
            let mut output = f.engine.channels[&16].output.state.lock().unwrap();
            assert!(output.start > 0);
            assert!(output.bytes.len() <= 3968);
            let actual = (&mut *output.model.as_mut().unwrap().screen as &mut dyn std::any::Any)
                .downcast_mut::<crate::screen::PtyScreen>()
                .unwrap()
                .snapshot();
            let mut expected = terminal::TerminalCore::with_options(
                terminal_size::TerminalSize::new(80, 24).unwrap(),
                terminal::TerminalOptions {
                    history_lines: 0,
                    replay: true,
                },
            );
            expected.feed(&script);
            assert_eq!(actual, expected.snapshot().unwrap());
        }
        wait(|| f.engine.barriers_settled()).await;
        let front = f.engine.attach_trusted(attachment(2)).unwrap();
        let mut client = f.screen_client(channel);
        assert_eq!(
            f.recover_screen_client(&front, &mut client, 1).await,
            RecoveryMode::ScreenReset
        );
        drop(client);
        let receipts = f.engine.close_session().await.unwrap();
        assert!(receipts[0].workers_joined());
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }

    #[tokio::test]
    async fn screen_owner_copy_inventory_refuses_before_factory_and_child_when_third_command_copy_is_uncharged(
    ) {
        use crate::session_owner::screen_owner::HostScreenLease;
        let (mut f, front) = Fixture::new_screen();
        let channel = ChannelInstance::new(1).unwrap();
        let size = terminal_size::TerminalSize::new(80, 24).unwrap();
        let slots = crate::screen_budget::ScreenEnvelope::new(size)
            .charge()
            .unwrap();
        let mut model = f.reserve(channel, ReservationKind::ScreenModel, 0);
        model.screen_charge = Some(ScreenCharge {
            cells: slots.cells as u64,
            rows: slots.rows as u64,
            models: 1,
        });
        let lease =
            HostScreenLease::admit(f.client.clone(), model, RequestId::new(1).unwrap(), size)
                .unwrap();
        f.next += 1;
        let history = f.reserve(channel, ReservationKind::OutputHistory, 4096);
        let control = f.reserve(
            channel,
            ReservationKind::ControlQueue,
            4 * 65536 + 4096 + 2 * 4096,
        );
        let result = f
            .engine
            .open_screen(
                &front,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Command,
                    cols: 80,
                    rows: 24,
                    screen: true,
                    command: vec![b'a'; 4096],
                },
                None,
                OwnerChannelResources {
                    history,
                    control,
                    cleanup: RequestId::new(history.id.get()).unwrap(),
                    read_buffer_bytes: 128,
                    input_epoch: InputEpoch::new([1; 16]).unwrap(),
                },
                lease,
            )
            .await;
        assert!(
            result.is_err(),
            "factory allocated its third full command copy outside the supplied inventory"
        );
        assert_eq!(
            f.io.spawn_entered.load(std::sync::atomic::Ordering::SeqCst),
            0
        );
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn screen_owner_actual_parser_reset_and_retained_replay_cut_matrix_preserves_common_suffix(
    ) {
        let cases: &[(&[u8], &[u8])] = &[
            (b"\x1b[31mA\x1b[", b"4mB\x1b[0m"),
            (b"\x1b]0;fixture-title", b"\x07X"),
            (b"\x1b(", b"0qx\x1b(BY"),
            (b"A\xe7\x95", b"\x8cB"),
            (b"\x1b[?2026hA\x1b[", b"31mB\x1b[?2026l"),
            (b"\x1b[3;8r\x1b[?6h\x1b[2;3HX\x1b[", b"4;5HY\x1b[?6l"),
            (
                b"shell\x1b[2;4H\x1b7\x1b[?1049hALT\x1b[",
                b"3;4HX\x1b[?1049l\x1b8Z",
            ),
            (
                b"\x1b[3g\x1b[1;5H\x1bH\x1b[?1h\x1b=\x1b[38;2;1;2;3mX",
                b"\tY\x1b[0m",
            ),
            (b"\x1b[31\x08;4", b"mX"),
        ];
        for (case, (prefix, suffix)) in cases.iter().enumerate() {
            for retained in [false, true] {
                let (mut f, front) = Fixture::new_screen();
                *f.io.script.lock().unwrap() = Some(if retained {
                    b"seed".to_vec()
                } else {
                    prefix.to_vec()
                });
                let channel = f.open_screen(&front).await;
                let initial = if retained { 4 } else { prefix.len() };
                wait(|| {
                    f.engine.channels[&16]
                        .output
                        .state
                        .lock()
                        .unwrap()
                        .bytes
                        .len()
                        == initial
                })
                .await;
                let mut client = f.screen_client(channel);
                assert_eq!(
                    f.recover_screen_client(&front, &mut client, 1).await,
                    RecoveryMode::ScreenReset
                );
                if retained {
                    f.io.script
                        .lock()
                        .unwrap()
                        .as_mut()
                        .unwrap()
                        .extend_from_slice(prefix);
                    f.io.changed.notify_all();
                    wait(|| {
                        f.engine.channels[&16]
                            .output
                            .state
                            .lock()
                            .unwrap()
                            .bytes
                            .len()
                            == 4 + prefix.len()
                    })
                    .await;
                    assert_eq!(
                        f.recover_screen_client(&front, &mut client, 2).await,
                        RecoveryMode::Replay,
                        "case{case}"
                    );
                }
                {
                    let mut output = f.engine.channels[&16].output.state.lock().unwrap();
                    let actual = (&mut *output.model.as_mut().unwrap().screen
                        as &mut dyn std::any::Any)
                        .downcast_mut::<crate::screen::PtyScreen>()
                        .unwrap()
                        .snapshot();
                    assert_eq!(
                        client.snapshot(),
                        actual,
                        "checkpoint case{case} retained={retained}"
                    );
                }
                let offset = client.cursor().offset;
                f.io.script
                    .lock()
                    .unwrap()
                    .as_mut()
                    .unwrap()
                    .extend_from_slice(suffix);
                f.io.changed.notify_all();
                wait(|| {
                    f.engine.channels[&16]
                        .output
                        .state
                        .lock()
                        .unwrap()
                        .bytes
                        .len() as u64
                        == offset + suffix.len() as u64
                })
                .await;
                let mut buffer = [0; 256];
                let n = f
                    .engine
                    .copy_output(&front, channel, offset, &mut buffer)
                    .unwrap();
                client.consume_live(offset, &buffer[..n]).unwrap();
                {
                    let mut output = f.engine.channels[&16].output.state.lock().unwrap();
                    let actual = (&mut *output.model.as_mut().unwrap().screen
                        as &mut dyn std::any::Any)
                        .downcast_mut::<crate::screen::PtyScreen>()
                        .unwrap()
                        .snapshot();
                    assert_eq!(
                        client.snapshot(),
                        actual,
                        "continuation case{case} retained={retained}"
                    );
                }
                drop(client);
                f.engine.close_session().await.unwrap();
                assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
            }
        }
    }

    #[tokio::test]
    async fn screen_control_cancelled_close_preserves_registered_join_then_drains_two_workers() {
        use std::{future::Future, sync::atomic::Ordering};
        let (mut f, front) = Fixture::new_screen();
        let channel = f.open_screen(&front).await;
        wait(|| {
            f.engine.channels[&16]
                .output
                .state
                .lock()
                .unwrap()
                .bytes
                .len()
                == 14
        })
        .await;
        let mut client = f.screen_client(channel);
        f.recover_screen_client(&front, &mut client, 1).await;
        f.io.held.store(true, Ordering::SeqCst);
        let input = f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"X")
            .unwrap();
        input.accepted().await.unwrap();
        wait(|| f.io.entered.load(Ordering::SeqCst) > 0).await;
        let before = f.ledger.lock().unwrap().reservations();
        {
            let close = f.engine.close_session();
            tokio::pin!(close);
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(close.as_mut().poll(&mut cx).is_pending());
        }
        assert_eq!(
            f.control_scope.as_ref().unwrap().registered(),
            1,
            "cancellation detached the actual control join"
        );
        assert_eq!(
            f.ledger.lock().unwrap().reservations(),
            before,
            "cancelled close refunded live backing"
        );
        let done = f.engine.close_session().await.unwrap();
        assert_eq!(done.len(), 1);
        assert!(done[0].workers_joined());
        assert!(f.engine.control_joined());
        assert_eq!(f.control_scope.as_ref().unwrap().registered(), 0);
        drop(client);
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn screen_control_unexpected_engine_drop_keeps_task_owned_until_caller_drain_and_native_debt_unresolved(
    ) {
        let (mut f, front) = Fixture::new_screen();
        f.open_screen(&front).await;
        let scope = f.control_scope.clone().unwrap();
        let ledger = f.ledger.clone();
        let io = f.io.clone();
        drop(front);
        drop(f.engine);
        assert_eq!(
            scope.registered(),
            1,
            "unexpected Drop detached the registered control task"
        );
        scope.drain().await.unwrap();
        assert_eq!(scope.registered(), 0);
        wait(|| io.state.lock().unwrap().0).await;
        wait(|| ledger.lock().unwrap().reservations() == 2).await;
        assert_eq!(
            ledger.lock().unwrap().reservations(),
            2,
            "unknown native history/writer debt was fabricated into cleanup"
        );
    }
    #[tokio::test]
    async fn screen_control_task_panic_refuses_input_and_drains_native_obligations_without_success_claim(
    ) {
        use crate::session_owner::screen_control::{ControlChannel, ControlPoll};
        struct Panic;
        impl ControlChannel for Panic {
            fn service(&self, _: Instant) -> ControlPoll {
                panic!("owned control fixture panic")
            }
        }
        let (mut f, front) = Fixture::new_screen();
        let channel = f.open_screen(&front).await;
        let panic: Arc<dyn ControlChannel> = Arc::new(Panic);
        f.engine
            .control_ticket
            .as_ref()
            .unwrap()
            .register(panic.clone())
            .unwrap();
        wait(|| !f.engine.control_ticket.as_ref().unwrap().healthy()).await;
        assert!(f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"")
            .is_err());
        assert!(f.engine.close_session().await.is_err());
        assert!(!f.engine.control_joined());
        assert_eq!(f.engine.retained.channels(), 0);
        f.engine.retained.join_workers().await.unwrap();
        assert!(f.engine.channels.is_empty());
        assert_eq!(f.control_scope.as_ref().unwrap().registered(), 0);
        assert_eq!(
            f.ledger.lock().unwrap().reservations(),
            1,
            "failed task join refunded unknown scheduler debt"
        );
    }
    #[tokio::test]
    async fn screen_owner_busy_reply_mailbox_keeps_batch_and_fence_progress_without_duplicate_answers(
    ) {
        use std::sync::atomic::Ordering;
        let (mut f, front) = Fixture::new_screen();
        *f.io.script.lock().unwrap() = Some(b"start".to_vec());
        let channel = f.open_screen(&front).await;
        wait(|| {
            f.engine.channels[&16]
                .output
                .state
                .lock()
                .unwrap()
                .bytes
                .len()
                == 5
        })
        .await;
        let mut client = f.screen_client(channel);
        f.recover_screen_client(&front, &mut client, 1).await;
        f.io.held.store(true, Ordering::SeqCst);
        let user = f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"N")
            .unwrap();
        user.accepted().await.unwrap();
        wait(|| f.io.entered.load(Ordering::SeqCst) > 0).await;
        let earlier = f.engine.queue_owner_reply(channel, b"prior").unwrap();
        let query = b"\x1b[?2026h\x1b[5n";
        f.io.script
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .extend_from_slice(query);
        f.io.changed.notify_all();
        wait(|| {
            let s = f.engine.channels[&16].output.state.lock().unwrap();
            s.replies_pending() && s.model.as_ref().unwrap().screen.sync_deadline().is_none()
        })
        .await;
        assert!(matches!(
            f.engine.user_input(
                &front,
                channel,
                InputEpoch::new([1; 16]).unwrap(),
                1,
                b"later"
            ),
            Err(EngineError::Writer(WriterError::Busy))
        ));
        let fence = f.engine.fence(&front).unwrap();
        assert!(!f.engine.barriers_settled());
        f.io.held.store(false, Ordering::SeqCst);
        f.io.changed.notify_all();
        let positions = fence.completed().await.unwrap();
        assert_eq!(positions[0].1.committed, 1);
        drop(earlier);
        drop(front);
        let front = f.engine.attach_trusted(attachment(2)).unwrap();
        f.recover_screen_client(&front, &mut client, 2).await;
        wait(|| f.io.state.lock().unwrap().1.len() >= 10).await;
        assert_eq!(f.io.state.lock().unwrap().1, b"Nprior\x1b[0n");
        assert_eq!(f.engine.input_position(channel).unwrap().accepted, 1);
        drop(client);
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }

    fn replay_consumed(source: &ConsumedRecovery) -> ConsumedRecovery {
        ConsumedRecovery {
            host: source.host.clone(),
            completion: source.completion,
            request_id: source.request_id,
            recovery_id: source.recovery_id,
            attachment: source.attachment,
            channel: source.channel,
        }
    }
    #[tokio::test]
    async fn screen_owner_denied_snapshot_preserves_actual_model_and_later_recovers_after_real_capacity_release(
    ) {
        use crate::session_owner::screen_recovery::*;
        let (mut f, front) = Fixture::new_screen();
        let channel = f.open_screen(&front).await;
        wait(|| f.engine.output_bounds_for_test(channel).1 == 14).await;
        let before = f.engine.screen_snapshot_for_test(channel).1;
        let mut client = f.screen_client(channel);
        let quote = f.engine.screen_recovery_requirements(channel).unwrap();
        let mut block = f.reserve(channel, ReservationKind::ScreenModel, 0);
        block.screen_charge = Some(ScreenCharge {
            cells: 8_388_608 - quote.scratch.cells,
            rows: 2_097_152 - quote.scratch.rows,
            models: 0,
        });
        let blocker = f
            .client
            .reserve(block, RequestId::new(block.id.get()).unwrap())
            .unwrap();
        let catalog = f.transfer(channel, 0);
        let transaction = f.engine.catalog(&front, catalog).unwrap();
        let bytes = f.reserve(
            channel,
            ReservationKind::SnapshotTransfer,
            quote.transfer_bytes as u64,
        );
        let mut scratch = f.reserve(channel, ReservationKind::ScreenModel, 0);
        scratch.screen_charge = Some(quote.scratch);
        let count = f.ledger.lock().unwrap().reservations();
        assert!(ScreenRecoveryAllowance::admit(
            f.client.clone(),
            bytes,
            scratch,
            RequestId::new(bytes.id.get()).unwrap(),
            quote
        )
        .is_err());
        assert_eq!(
            f.ledger.lock().unwrap().reservations(),
            count,
            "denied scratch leaked its empty transfer allocation"
        );
        assert_eq!(f.engine.screen_snapshot_for_test(channel).1, before);
        assert_eq!(
            f.io.spawn_entered.load(std::sync::atomic::Ordering::SeqCst),
            1
        );
        assert!(f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"")
            .is_err());
        drop(transaction);
        f.client
            .release(
                &blocker,
                ReservationReceipt {
                    id: RequestId::new(block.id.get()).unwrap(),
                    reservation: block.id,
                    locator: block.locator,
                    channel,
                },
            )
            .unwrap();
        assert_eq!(
            f.recover_screen_client(&front, &mut client, 1).await,
            RecoveryMode::ScreenReset
        );
        assert_eq!(
            f.engine.screen_snapshot_for_test(channel).1,
            client.snapshot()
        );
        drop(client);
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn screen_owner_wrong_parser_proof_resets_and_old_geometry_completion_ready_cannot_unlock_resize(
    ) {
        use crate::session_owner::screen_recovery::*;
        use transport::channel_geometry::ResizeRequestId;
        let (mut f, front) = Fixture::new_screen();
        let channel = f.open_screen(&front).await;
        wait(|| f.engine.output_bounds_for_test(channel).1 == 14).await;
        let mut client = f.screen_client(channel);
        f.recover_screen_client(&front, &mut client, 1).await;
        let catalog = f.transfer(channel, 0);
        let mut tx = f.engine.catalog(&front, catalog).unwrap();
        let quote = f.engine.screen_recovery_requirements(channel).unwrap();
        let bytes = f.reserve(
            channel,
            ReservationKind::SnapshotTransfer,
            quote.transfer_bytes as u64,
        );
        let mut scratch = f.reserve(channel, ReservationKind::ScreenModel, 0);
        scratch.screen_charge = Some(quote.scratch);
        let allowance = ScreenRecoveryAllowance::admit(
            f.client.clone(),
            bytes,
            scratch,
            RequestId::new(bytes.id.get()).unwrap(),
            quote,
        )
        .unwrap();
        let (mut request, evidence) = client.request(front.attachment());
        request.parser = ParserContinuity::Retained {
            parser_instance: [99; 16],
            cursor: client.cursor(),
        };
        let id = RequestId::new(1002).unwrap();
        let mut producer = f
            .engine
            .recover_screen(
                &front,
                &mut tx,
                request,
                &evidence,
                RecoveryId::new([32; 16]).unwrap(),
                id,
                allowance,
            )
            .unwrap();
        assert_eq!(
            producer.start().mode,
            RecoveryMode::ScreenReset,
            "a request asserted another parser identity"
        );
        client.begin(id, request, producer.start()).unwrap();
        while let Some(chunk) = producer.next_chunk().unwrap() {
            client.consume(&chunk).unwrap();
        }
        let (end, ready) = producer.end().unwrap();
        let old_ready = ready.clone();
        let consumed = client.finish(end, ready).unwrap();
        let stale = replay_consumed(&consumed);
        tx.accept_consumed(consumed).unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        drop(producer);
        drop(evidence);
        f.engine
            .resize(&front, channel, ResizeRequestId::new(1).unwrap(), 100, 30)
            .unwrap();
        let catalog = f.transfer(channel, 0);
        let mut tx = f.engine.catalog(&front, catalog).unwrap();
        assert!(tx.accept_consumed(stale).is_err());
        assert!(f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"")
            .is_err());
        let quote = f.engine.screen_recovery_requirements(channel).unwrap();
        let bytes = f.reserve(
            channel,
            ReservationKind::SnapshotTransfer,
            quote.transfer_bytes as u64,
        );
        let mut scratch = f.reserve(channel, ReservationKind::ScreenModel, 0);
        scratch.screen_charge = Some(quote.scratch);
        let allowance = ScreenRecoveryAllowance::admit(
            f.client.clone(),
            bytes,
            scratch,
            RequestId::new(bytes.id.get()).unwrap(),
            quote,
        )
        .unwrap();
        let (request, evidence) = client.request(front.attachment());
        let id = RequestId::new(1003).unwrap();
        let mut producer = f
            .engine
            .recover_screen(
                &front,
                &mut tx,
                request,
                &evidence,
                RecoveryId::new([33; 16]).unwrap(),
                id,
                allowance,
            )
            .unwrap();
        assert_eq!(producer.start().mode, RecoveryMode::ScreenReset);
        client.begin(id, request, producer.start()).unwrap();
        while let Some(chunk) = producer.next_chunk().unwrap() {
            client.consume(&chunk).unwrap();
        }
        let (end, ready) = producer.end().unwrap();
        assert!(client.finish(end, old_ready).is_err());
        assert!(f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"")
            .is_err());
        tx.accept_consumed(client.finish(end, ready).unwrap())
            .unwrap();
        f.engine.finish_recovery(&front, tx).unwrap();
        assert_eq!(
            client.snapshot(),
            f.engine.screen_snapshot_for_test(channel).1
        );
        drop(producer);
        drop(evidence);
        drop(client);
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn screen_owner_catalog_boundary_race_refuses_newer_model_under_old_start_and_recovers_explicitly(
    ) {
        use crate::session_owner::screen_recovery::*;
        let (mut f, front) = Fixture::new_screen();
        *f.io.script.lock().unwrap() = Some(b"start".to_vec());
        let channel = f.open_screen(&front).await;
        wait(|| f.engine.output_bounds_for_test(channel).1 == 5).await;
        let mut client = f.screen_client(channel);
        f.recover_screen_client(&front, &mut client, 1).await;
        let catalog = f.transfer(channel, 0);
        let mut tx = f.engine.catalog(&front, catalog).unwrap();
        let quote = f.engine.screen_recovery_requirements(channel).unwrap();
        let bytes = f.reserve(
            channel,
            ReservationKind::SnapshotTransfer,
            quote.transfer_bytes as u64,
        );
        let mut scratch = f.reserve(channel, ReservationKind::ScreenModel, 0);
        scratch.screen_charge = Some(quote.scratch);
        let allowance = ScreenRecoveryAllowance::admit(
            f.client.clone(),
            bytes,
            scratch,
            RequestId::new(bytes.id.get()).unwrap(),
            quote,
        )
        .unwrap();
        f.io.script
            .lock()
            .unwrap()
            .as_mut()
            .unwrap()
            .extend_from_slice(b"later");
        f.io.changed.notify_all();
        wait(|| f.engine.output_bounds_for_test(channel).1 == 10).await;
        let (request, evidence) = client.request(front.attachment());
        assert!(matches!(
            f.engine.recover_screen(
                &front,
                &mut tx,
                request,
                &evidence,
                RecoveryId::new([2; 16]).unwrap(),
                RequestId::new(1002).unwrap(),
                allowance
            ),
            Err(EngineError::Unavailable)
        ));
        assert!(f.engine.finish_recovery(&front, tx).is_err());
        drop(evidence);
        assert!(f
            .engine
            .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"")
            .is_err());
        assert_eq!(
            f.recover_screen_client(&front, &mut client, 2).await,
            RecoveryMode::Replay
        );
        assert_eq!(
            client.snapshot(),
            f.engine.screen_snapshot_for_test(channel).1
        );
        drop(client);
        f.engine.close_session().await.unwrap();
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
    #[tokio::test]
    async fn screen_owner_mixed_catalog_requires_both_real_consumers_and_rejects_old_completion() {
        use crate::session_owner::screen_recovery::*;
        let (mut f, front) = Fixture::new_screen();
        let screen = f.open_screen(&front).await;
        f.open(&front, 2).await;
        let raw = ChannelInstance::new(2).unwrap();
        wait(|| {
            f.engine.output_bounds_for_test(screen).1 == 14
                && f.engine.output_bounds_for_test(raw).1 == 14
        })
        .await;
        let mut client = f.screen_client(screen);
        let mut raw_client = NoScreenConsumer::new(raw, f.transfer(raw, 64)).unwrap();
        let mut saved = None;
        for pass in 1..=2 {
            let catalog = f.transfer(screen, 0);
            let mut tx = f.engine.catalog(&front, catalog).unwrap();
            if pass == 2 {
                assert!(tx.accept_consumed(saved.take().unwrap()).is_err());
            }
            let quote = f.engine.screen_recovery_requirements(screen).unwrap();
            let bytes = f.reserve(
                screen,
                ReservationKind::SnapshotTransfer,
                quote.transfer_bytes as u64,
            );
            let mut scratch = f.reserve(screen, ReservationKind::ScreenModel, 0);
            scratch.screen_charge = Some(quote.scratch);
            let allowance = ScreenRecoveryAllowance::admit(
                f.client.clone(),
                bytes,
                scratch,
                RequestId::new(bytes.id.get()).unwrap(),
                quote,
            )
            .unwrap();
            let (request, evidence) = client.request(front.attachment());
            let id = RequestId::new(1000 + pass * 2).unwrap();
            let mut producer = f
                .engine
                .recover_screen(
                    &front,
                    &mut tx,
                    request,
                    &evidence,
                    RecoveryId::new([pass as u8; 16]).unwrap(),
                    id,
                    allowance,
                )
                .unwrap();
            client.begin(id, request, producer.start()).unwrap();
            while let Some(chunk) = producer.next_chunk().unwrap() {
                client.consume(&chunk).unwrap();
            }
            let (end, ready) = producer.end().unwrap();
            let consumed = client.finish(end, ready).unwrap();
            if pass == 1 {
                saved = Some(replay_consumed(&consumed));
            }
            tx.accept_consumed(consumed).unwrap();
            drop(producer);
            drop(evidence);
            for channel in [screen, raw] {
                assert!(f
                    .engine
                    .user_input(&front, channel, InputEpoch::new([1; 16]).unwrap(), 0, b"")
                    .is_err());
            }
            if pass == 1 {
                assert!(f.engine.finish_recovery(&front, tx).is_err());
                continue;
            }
            let request = RecoveryRequest {
                attachment: front.attachment(),
                channel: raw,
                parser: ParserContinuity::DataCursor {
                    cursor: raw_client.cursor(),
                },
            };
            let allowance = f.transfer(raw, 14);
            let id = RequestId::new(1005).unwrap();
            let mut producer = f
                .engine
                .recover(
                    &front,
                    &mut tx,
                    request,
                    RecoveryId::new([5; 16]).unwrap(),
                    id,
                    allowance,
                )
                .unwrap();
            raw_client.begin(id, request, producer.start()).unwrap();
            while let Some(chunk) = producer.next_chunk().unwrap() {
                raw_client.consume(&chunk).unwrap();
            }
            let (end, ready) = producer.end().unwrap();
            tx.accept_consumed(raw_client.finish(end, ready).unwrap())
                .unwrap();
            drop(producer);
            f.engine.finish_recovery(&front, tx).unwrap();
        }
        assert_eq!(raw_client.bytes(), b"record:partial");
        drop(client);
        drop(raw_client);
        let done = f.engine.close_session().await.unwrap();
        assert_eq!(done.len(), 2);
        assert!(done.iter().all(|r| r.workers_joined()));
        assert_eq!(f.ledger.lock().unwrap().reservations(), 0);
    }
}
