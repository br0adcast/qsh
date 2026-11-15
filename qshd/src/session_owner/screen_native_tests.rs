//! Bounded real personal Screen owner; every PID/PTY/file is fixture-owned.
use super::*;
use crate::session_owner::{
    screen_control::*,
    screen_owner::{HostScreenLease, RetainedScreenFactory},
    screen_recovery::*,
};
use crate::test_support::borrowed_scope::{
    self, DiagnosticAssertion as Check, DiagnosticPhase as Phase,
};
use std::io::Write as _;
use transport::channel_geometry::{GeometryOutcome, ResizeRequestId};
fn checkpoint(code: Check) {
    borrowed_scope::diagnostic_assertion(code, Duration::ZERO);
}
fn phase(code: Phase) {
    borrowed_scope::diagnostic_phase(code);
}
static TAIL_RETRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
const SCREEN_NAME:&str="session_owner::engine_native_tests::screen::owner_engine_screen_child_survives_history_gap_query_and_resize";
fn quoted(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn child_identity(stage: u64, tty: &std::path::Path) {
    println!(
        "\r\nOWNER529 {} {} {} progress {stage}\r",
        std::process::id(),
        unsafe { libc::getppid() },
        tty.display()
    );
}
fn native_screen_child() {
    assert_eq!(unsafe { libc::isatty(0) }, 1);
    let tty = std::fs::read_link("/proc/self/fd/0").unwrap();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    assert_eq!(unsafe { libc::tcgetattr(0, original.as_mut_ptr()) }, 0);
    let original = unsafe { original.assume_init() };
    let mut raw = original;
    unsafe { libc::cfmakeraw(&mut raw) };
    assert_eq!(unsafe { libc::tcsetattr(0, libc::TCSANOW, &raw) }, 0);
    struct Restore(libc::termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            unsafe { libc::tcsetattr(0, libc::TCSANOW, &self.0) };
        }
    }
    let _restore = Restore(original);
    child_identity(0, &tty);
    let mut input = std::io::stdin().lock();
    let mut command = Vec::new();
    let mut reply = Vec::new();
    let mut replies = 0;
    loop {
        let mut byte = [0];
        match input.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) if e.raw_os_error() == Some(libc::EIO) => break,
            Err(e) => panic!("owned raw PTY read failed: {e}"),
        }
        // portable-pty's owned master writer drops with newline + VEOF.
        // In raw mode these are bytes, not the kernel's canonical EOF.
        if original.c_cc[libc::VEOF] != 0 && byte[0] == original.c_cc[libc::VEOF] {
            assert!(
                command.is_empty() && reply.is_empty(),
                "fixture EOF interrupted a command or answer"
            );
            break;
        }
        if !reply.is_empty() || byte[0] == 0x1b {
            assert!(reply.len() < 64);
            reply.push(byte[0]);
            if byte[0] == b't' {
                assert_eq!(
                    reply, b"\x1b[8;24;80t",
                    "child received a malformed/duplicate geometry answer"
                );
                replies += 1;
                reply.clear();
                println!("\r\nREPLY529 seen={replies}\r");
                child_identity(2, &tty);
            }
            continue;
        }
        assert!(command.len() < 64);
        if byte[0] != b'\n' {
            command.push(byte[0]);
            continue;
        }
        match command.as_slice() {
            b"" => {}
            b"BURST529" => {
                let gate = std::env::var_os("QSH529_SCREEN_GO").unwrap();
                let until = Instant::now() + Duration::from_secs(10);
                while !std::path::Path::new(&gate).exists() {
                    assert!(Instant::now() < until, "fixture gate was never released");
                    std::thread::sleep(Duration::from_millis(1));
                }
                let mut output = std::io::stdout().lock();
                for _ in 0..400 {
                    output.write_all(&[b'x'; 4096]).unwrap();
                    output.write_all(b"\r\n").unwrap();
                }
                output
                    .write_all(b"\x1b[2J\x1b[HAFTER-BURST529\r\n")
                    .unwrap();
                drop(output);
                child_identity(1, &tty);
                print!("\x1b[18t");
                std::io::stdout().flush().unwrap();
            }
            b"CHECK529" => println!("\r\nCHECK529 replies={replies}\r"),
            b"SIZE529" => {
                let mut size = std::mem::MaybeUninit::<libc::winsize>::uninit();
                assert_eq!(
                    unsafe { libc::ioctl(0, libc::TIOCGWINSZ, size.as_mut_ptr()) },
                    0
                );
                let size = unsafe { size.assume_init() };
                println!(
                    "\r\nSIZE529 cols={} rows={} replies={replies}\r",
                    size.ws_col, size.ws_row
                );
                child_identity(3, &tty);
            }
            _ => panic!("unexpected bounded fixture command"),
        }
        command.clear();
    }
}
struct ScreenHost {
    client: OwnerResourceClient,
    ledger: Arc<Mutex<ResourceLedger>>,
    locator: SessionLocator,
    next: u64,
}
impl ScreenHost {
    fn spec(
        &mut self,
        channel: ChannelInstance,
        kind: ReservationKind,
        bytes: u64,
        screen_charge: Option<ScreenCharge>,
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
            locator: self.locator,
            channel,
            kind,
            bytes,
            screen_charge,
        }
    }
    fn transfer(&mut self, channel: ChannelInstance, retained: usize) -> TransferAllowance {
        let r = self.spec(
            channel,
            ReservationKind::SnapshotTransfer,
            (retained.max(1) + 16384 + 65536) as u64,
            None,
        );
        TransferAllowance::admit(
            self.client.clone(),
            r,
            RequestId::new(r.id.get()).unwrap(),
            retained,
        )
        .unwrap()
    }
    async fn recover(
        &mut self,
        engine: &SessionOwnerEngine,
        front: &FrontendAttachment,
        client: &mut ScreenConsumer,
        serial: u8,
    ) -> RecoveryMode {
        let until = Instant::now() + Duration::from_secs(5);
        checkpoint(Check::ScreenCatalogWait);
        while !engine.catalog_available() {
            assert!(Instant::now() < until);
            tokio::task::yield_now().await;
        }
        let channel = client.cursor().channel;
        checkpoint(Check::ScreenRequirements);
        let quote = engine.screen_recovery_requirements(channel).unwrap();
        checkpoint(Check::ScreenCatalog);
        let mut catalog = engine.catalog(front, self.transfer(channel, 0)).unwrap();
        checkpoint(Check::ScreenAllowance);
        let bytes = self.spec(
            channel,
            ReservationKind::SnapshotTransfer,
            quote.transfer_bytes as u64,
            None,
        );
        let scratch = self.spec(
            channel,
            ReservationKind::ScreenModel,
            0,
            Some(quote.scratch),
        );
        let allowance = ScreenRecoveryAllowance::admit(
            self.client.clone(),
            bytes,
            scratch,
            RequestId::new(bytes.id.get()).unwrap(),
            quote,
        )
        .unwrap();
        checkpoint(Check::ScreenRecoveryStart);
        let (request, evidence) = client.request(front.attachment());
        let request_id = RequestId::new(1000 + u64::from(serial)).unwrap();
        let mut producer = engine
            .recover_screen(
                front,
                &mut catalog,
                request,
                &evidence,
                RecoveryId::new([serial; 16]).unwrap(),
                request_id,
                allowance,
            )
            .unwrap();
        let mode = producer.start().mode;
        if serial == 2 {
            checkpoint(Check::ScreenRecoveryGap);
            assert!(
                producer.start().gap,
                "detached raw history did not expose its real gap"
            );
        }
        checkpoint(Check::ScreenRecoveryBegin);
        client.begin(request_id, request, producer.start()).unwrap();
        checkpoint(Check::ScreenRecoveryChunk);
        while let Some(chunk) = producer.next_chunk().unwrap() {
            client.consume(&chunk).unwrap();
        }
        checkpoint(Check::ScreenRecoveryEnd);
        let (end, ready) = producer.end().unwrap();
        checkpoint(Check::ScreenRecoveryAccept);
        catalog
            .accept_consumed(client.finish(end, ready).unwrap())
            .unwrap();
        checkpoint(Check::ScreenCatalogWait);
        while !engine.catalog_available() {
            assert!(Instant::now() < until);
            tokio::task::yield_now().await;
        }
        checkpoint(Check::ScreenRecoveryFinish);
        engine.finish_recovery(front, catalog).unwrap();
        mode
    }
    fn client(
        &mut self,
        engine: &SessionOwnerEngine,
        channel: ChannelInstance,
        id: u8,
    ) -> ScreenConsumer {
        let quote = engine.screen_recovery_requirements(channel).unwrap();
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
        ScreenConsumer::new(
            channel,
            [id; 16],
            terminal_size::TerminalSize::new(80, 24).unwrap(),
            unsafe { libc::geteuid() },
            budget,
            self.transfer(channel, quote.max_bytes),
        )
        .unwrap()
    }
}
fn tail(
    engine: &SessionOwnerEngine,
    front: &FrontendAttachment,
    channel: ChannelInstance,
) -> String {
    let (start, _) = engine.output_bounds_for_test(channel);
    let mut bytes = [0; 32768];
    let copied = engine.copy_output(front, channel, start, &mut bytes);
    let n = match copied {
        Ok(n) => n,
        Err(EngineError::InvalidRequest) => {
            TAIL_RETRIES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return String::new();
        }
        Err(e) => panic!("owned tail unavailable: {e:?}"),
    };
    String::from_utf8_lossy(&bytes[..n]).into_owned()
}
async fn wait_tail(
    engine: &SessionOwnerEngine,
    front: &FrontendAttachment,
    channel: ChannelInstance,
    needle: &str,
) -> String {
    let until = Instant::now() + Duration::from_secs(10);
    checkpoint(Check::ScreenProgress);
    loop {
        let bytes = tail(engine, front, channel);
        if bytes.contains(needle) {
            return bytes;
        }
        assert!(
            Instant::now() < until,
            "native Screen progress did not arrive"
        );
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
}
fn identity_from_tail(bytes: &str, stage: u64) -> Identity {
    checkpoint(Check::ScreenIdentity);
    observed_identity(
        bytes
            .lines()
            .map(str::trim)
            .find(|l| {
                l.starts_with("OWNER529 ")
                    && l.split_whitespace().last() == Some(stage.to_string().as_str())
            })
            .unwrap(),
    )
    .0
}
fn compare_client(
    engine: &SessionOwnerEngine,
    front: &FrontendAttachment,
    channel: ChannelInstance,
    client: &mut ScreenConsumer,
) {
    checkpoint(Check::ScreenCursor);
    let (boundary, snapshot) = engine.screen_snapshot_for_test(channel);
    let mut buffer = [0; 4096];
    while client.cursor().offset < boundary {
        let offset = client.cursor().offset;
        let want = usize::try_from(boundary - offset)
            .unwrap()
            .min(buffer.len());
        checkpoint(Check::ScreenCanonicalCopy);
        let n = engine
            .copy_output(front, channel, offset, &mut buffer[..want])
            .unwrap();
        assert!(n > 0);
        checkpoint(Check::ScreenCanonicalConsume);
        client.consume_live(offset, &buffer[..n]).unwrap();
    }
    checkpoint(Check::ScreenCanonicalEqual);
    assert_eq!(
        client.snapshot(),
        snapshot,
        "actual canonical Screen state/continuation differs"
    );
}
#[test]
fn owner_engine_screen_child_survives_history_gap_query_and_resize() {
    if std::env::var("QSH529_SCREEN_CHILD").as_deref() == Ok("1") {
        // Keep fixed fixture-only panic location evidence available after PTY teardown.
        let diagnostic = std::path::PathBuf::from(std::env::var_os("QSH529_SCREEN_PANIC").unwrap());
        std::panic::set_hook(Box::new(move |info| {
            if let Some(location) = info.location() {
                borrowed_scope::diagnostic_write_child_panic(
                    &diagnostic,
                    location.file(),
                    location.line(),
                    location.column(),
                );
            }
        }));
        native_screen_child();
        return;
    }
    let outcome = crate::test_support::borrowed_scope::run_exact(SCREEN_NAME, 0, || {
        borrowed_scope::diagnostic_capture_locations();
        phase(Phase::ScreenSetup);
        checkpoint(Check::ScreenRuntime);
        note("screen529 stage=runtime");
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(screen_body());
    });
    outcome.assert_clean(0);
}
async fn screen_body() {
    note("screen529 stage=setup");
    phase(Phase::ScreenSetup);
    checkpoint(Check::ScreenSetup);
    let locator = SessionLocator {
        session: RetainedSessionId::new([91; 16]).unwrap(),
        owner: OwnerInstance::new([92; 16]).unwrap(),
    };
    let principal_ref = AuthenticatedPrincipalRef::new([93; 16]).unwrap();
    let bytes = ByteLimits {
        channel_bytes: 32 << 20,
        session_bytes: 64 << 20,
        account_bytes: 128 << 20,
        global_bytes: 256 << 20,
    };
    let limits = ResourceLimits {
        max_reservations: 32,
        screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default()).unwrap(),
        snapshot_transfer: bytes,
        control_queue: bytes,
    };
    let mut ledger = ResourceLedger::new(LedgerInstance::new([94; 16]).unwrap(), limits).unwrap();
    let uid = unsafe { libc::geteuid() };
    let registration = ledger.register_fresh_principal(principal_ref, uid).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));
    let client = OwnerResourceClient::new(ledger.clone(), registration);
    let mut host = ScreenHost {
        client: client.clone(),
        ledger: ledger.clone(),
        locator,
        next: 0,
    };
    let factory = Arc::new(RetainedScreenFactory::new());
    let ordinary = Arc::new(crate::screen_budget::ScreenBudget::new(
        crate::screen_budget::BudgetLimits {
            global_cells: 0,
            owner_cells: 0,
            global_rows: 0,
            owner_rows: 0,
            global_models: 0,
            owner_models: 0,
        },
    ));
    let spawner = Arc::new(
        crate::channel_backend::PtyChannelSpawner::new(ordinary)
            .with_retained_screens(factory.clone()),
    );
    let (_, restart) = tokio::sync::watch::channel(RestartSignal::IDLE);
    let scope = ControlTaskScope::new(tokio::runtime::Handle::current());
    let mut engine = SessionOwnerEngine::new(
        locator,
        transport::Principal {
            uid,
            name: "owned-screen-fixture".into(),
            identity: "local self-account fixture".into(),
            incarnation: 0,
        },
        [95; 16],
        spawner,
        client.clone(),
        Arc::new(Clock(Instant::now())),
        restart,
    )
    .unwrap()
    .with_screen_factory(factory);
    let first = engine.attach_trusted(attachment(locator, 1)).unwrap();
    let channel = ChannelInstance::new(1).unwrap();
    let size = terminal_size::TerminalSize::new(80, 24).unwrap();
    let slots = crate::screen_budget::ScreenEnvelope::new(size)
        .charge()
        .unwrap();
    let model = host.spec(
        channel,
        ReservationKind::ScreenModel,
        0,
        Some(ScreenCharge {
            cells: slots.cells as u64,
            rows: slots.rows as u64,
            models: 1,
        }),
    );
    let lease = HostScreenLease::admit(
        client.clone(),
        model,
        RequestId::new(model.id.get()).unwrap(),
        size,
    )
    .unwrap();
    let anchor = host.spec(channel, ReservationKind::ControlQueue, 65536, None);
    engine = engine.with_screen_control(ScreenControlContext::new(
        scope.clone(),
        anchor,
        RequestId::new(anchor.id.get()).unwrap(),
    ));
    let history = host.spec(channel, ReservationKind::OutputHistory, 16384 + 1024, None);
    let control = host.spec(channel, ReservationKind::ControlQueue, 512 * 1024, None);
    let temp = tempfile::tempdir().unwrap();
    let go = temp.path().join("go");
    let panic_path = borrowed_scope::diagnostic_child_panic_path();
    let executable = std::env::current_exe().unwrap();
    let command=format!("/usr/bin/env QSH529_SCREEN_CHILD=1 QSH529_SCREEN_GO={} QSH529_SCREEN_PANIC={} {} --exact {SCREEN_NAME} --nocapture",quoted(go.to_str().unwrap()),quoted(panic_path.to_str().unwrap()),quoted(executable.to_str().unwrap())).into_bytes();
    note("screen529 stage=before-open");
    phase(Phase::ScreenOpen);
    checkpoint(Check::ScreenOpen);
    engine
        .open_screen(
            &first,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: true,
                command,
            },
            None,
            OwnerChannelResources {
                history,
                control,
                cleanup: RequestId::new(history.id.get()).unwrap(),
                read_buffer_bytes: 1024,
                input_epoch: InputEpoch::new([96; 16]).unwrap(),
            },
            lease,
        )
        .await
        .unwrap();
    note("screen529 stage=opened");
    phase(Phase::ScreenInitialIdentity);
    let initial = wait_tail(&engine, &first, channel, "progress 0").await;
    let identity = identity_from_tail(&initial, 0);
    note("screen529 stage=initial-identity");
    phase(Phase::ScreenInitialRecovery);
    checkpoint(Check::ScreenClient);
    let mut receiver = host.client(&engine, channel, 97);
    let initial_mode = host.recover(&engine, &first, &mut receiver, 1).await;
    checkpoint(Check::ScreenRecoveryMode);
    assert_eq!(initial_mode, RecoveryMode::ScreenReset);
    compare_client(&engine, &first, channel, &mut receiver);
    note("screen529 stage=initial-recovery");
    phase(Phase::ScreenInput);
    checkpoint(Check::ScreenInput);
    let frontend = Frontend::new();
    let epoch = InputEpoch::new([96; 16]).unwrap();
    let burst = b"BURST529\n";
    engine
        .user_input(&first, channel, epoch, 0, burst)
        .unwrap()
        .accepted()
        .await
        .unwrap();
    checkpoint(Check::ScreenCommitted);
    wait_committed(&engine, channel, burst.len() as u64).await;
    note("screen529 stage=before-detach");
    phase(Phase::ScreenFrontendLoss);
    checkpoint(Check::ScreenBarrier);
    frontend.disappear(true);
    drop(first);
    wait_barrier(&engine).await;
    checkpoint(Check::ScreenGate);
    std::fs::write(&go, b"go").unwrap();
    note("screen529 stage=detached-go");
    // The gate is released only after owned frontend death and actual fence.
    phase(Phase::ScreenDetachedBurst);
    checkpoint(Check::ScreenDetachedBytes);
    let until = Instant::now() + Duration::from_secs(10);
    while engine.output_bounds_for_test(channel).1 < 1_048_576 {
        assert!(Instant::now() < until);
        tokio::task::yield_now().await;
    }
    note("screen529 stage=megabyte-observed");
    phase(Phase::ScreenReattach);
    checkpoint(Check::ScreenAttach);
    let second = engine.attach_trusted(attachment(locator, 2)).unwrap();
    let after = wait_tail(&engine, &second, channel, "progress 1").await;
    assert_eq!(identity_from_tail(&after, 1), identity);
    note("screen529 stage=detached-identity");
    phase(Phase::ScreenGapRecovery);
    checkpoint(Check::ScreenClient);
    drop(receiver);
    let mut receiver = host.client(&engine, channel, 98);
    let gap_mode = host.recover(&engine, &second, &mut receiver, 2).await;
    checkpoint(Check::ScreenRecoveryMode);
    assert_eq!(gap_mode, RecoveryMode::ScreenReset);
    phase(Phase::ScreenQuery);
    wait_tail(&engine, &second, channel, "REPLY529 seen=1").await;
    compare_client(&engine, &second, channel, &mut receiver);
    let check = b"CHECK529\n";
    checkpoint(Check::ScreenInput);
    engine
        .user_input(&second, channel, epoch, burst.len() as u64, check)
        .unwrap()
        .accepted()
        .await
        .unwrap();
    checkpoint(Check::ScreenQueryReply);
    wait_tail(&engine, &second, channel, "CHECK529 replies=1").await;
    phase(Phase::ScreenResize);
    checkpoint(Check::ScreenGeometry);
    let geometry = engine
        .resize(&second, channel, ResizeRequestId::new(1).unwrap(), 100, 30)
        .unwrap();
    assert_eq!(geometry.outcome, GeometryOutcome::Applied);
    assert_eq!((geometry.cols, geometry.rows), (100, 30));
    checkpoint(Check::ScreenInputStatus);
    assert!(engine
        .user_input(
            &second,
            channel,
            epoch,
            (burst.len() + check.len()) as u64,
            b""
        )
        .is_err());
    phase(Phase::ScreenPostResizeRecovery);
    let resize_mode = host.recover(&engine, &second, &mut receiver, 3).await;
    checkpoint(Check::ScreenRecoveryMode);
    assert_eq!(resize_mode, RecoveryMode::ScreenReset);
    compare_client(&engine, &second, channel, &mut receiver);
    phase(Phase::ScreenFinalChecks);
    checkpoint(Check::ScreenInput);
    let request = b"SIZE529\n";
    engine
        .user_input(
            &second,
            channel,
            epoch,
            (burst.len() + check.len()) as u64,
            request,
        )
        .unwrap()
        .accepted()
        .await
        .unwrap();
    let final_tail = wait_tail(
        &engine,
        &second,
        channel,
        "SIZE529 cols=100 rows=30 replies=1",
    )
    .await;
    wait_tail(&engine, &second, channel, "progress 3").await;
    assert_eq!(
        identity_from_tail(&tail(&engine, &second, channel), 3),
        identity
    );
    checkpoint(Check::ScreenQueryReply);
    assert!(!final_tail.contains("REPLY529 seen=2"));
    compare_client(&engine, &second, channel, &mut receiver);
    checkpoint(Check::ScreenHistory);
    let (start, end) = engine.output_bounds_for_test(channel);
    assert!(start > 0 && end > 1_048_576);
    checkpoint(Check::ScreenInputStatus);
    let position = engine.input_position(channel).unwrap();
    assert_eq!(position.epoch, epoch);
    assert_eq!(
        position.accepted,
        (burst.len() + check.len() + request.len()) as u64
    );
    note(&format!("screen529 owner={} child={} parent={} tty={} kernel_tty={} group={} session={} start={} output_start={start} output_end={end} epochs=1,2 raw_history_gap=1 query_responses=1 native_resize=100x30 canonical_equal=1 continuation_equal=1 tail_range_retries={}",std::process::id(),identity.child,identity.parent,identity.tty,identity.kernel_tty,identity.group,identity.session,identity.start,TAIL_RETRIES.load(std::sync::atomic::Ordering::Relaxed)));
    phase(Phase::ScreenCleanup);
    checkpoint(Check::ScreenReceipts);
    drop(receiver);
    let receipts = engine.close_session().await.unwrap();
    assert_eq!(receipts.len(), 1);
    borrowed_scope::diagnostic_screen_receipt(receipts[0].code());
    checkpoint(Check::ScreenWorkerJoin);
    assert!(receipts[0].workers_joined());
    checkpoint(Check::ScreenControlJoin);
    assert!(engine.control_joined());
    checkpoint(Check::ScreenScopeDrain);
    scope.drain().await.unwrap();
    assert_eq!(scope.registered(), 0);
    checkpoint(Check::ScreenReservations);
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
    checkpoint(Check::ScreenNoChildren);
    assert_eq!(
        unsafe { libc::waitpid(identity.child as i32, std::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    note(&format!("screen529 exact_child_reaped=1 reader_joined=1 writer_joined=1 control_joined=1 resource_reservations=0 frontend_waits=1 code={:?}",receipts[0].code()));
    checkpoint(Check::ScreenReceiptStatus);
    assert_eq!(
        receipts[0].code(),
        Some(0),
        "owned Screen child must exit successfully"
    );
}
