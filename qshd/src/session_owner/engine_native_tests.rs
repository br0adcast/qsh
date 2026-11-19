//! All PIDs, IPC and terminals in this fixture belong to its isolated owner.
use super::authorization_contract::*;
use super::engine::*;
use super::recovery_runtime::{NoScreenConsumer, TransferAllowance};
use super::resource_contract::*;
use super::resources::OwnerResourceClient;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use transport::channel::{ChannelKind, OpenRequest};
use transport::channel_geometry::ChannelInstance;
use transport::channel_server::RestartSignal;
use transport::session_resume::*;
fn note(message: &str) {
    eprintln!("{message}");
    if let Some(path) = std::env::var_os("QSH529_NATIVE_PROOF") {
        use std::io::Write;
        writeln!(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap(),
            "{message}"
        )
        .unwrap();
    }
}
struct Clock(Instant);
impl MonotonicClock for Clock {
    fn now(&self) -> u64 {
        self.0.elapsed().as_millis() as u64
    }
}
fn attachment(locator: SessionLocator, epoch: u64) -> Attachment {
    Attachment {
        locator,
        frontend: FrontendGeneration::new([epoch as u8; 16]).unwrap(),
        epoch: AttachEpoch::new(epoch).unwrap(),
    }
}
struct Frontend {
    child: std::process::Child,
    ipc: UnixStream,
    reaped: bool,
}
impl Frontend {
    fn new() -> Self {
        let (ipc, peer) = UnixStream::pair().unwrap();
        let child = Command::new("/bin/cat")
            .stdin(Stdio::from(OwnedFd::from(peer)))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            ipc,
            reaped: false,
        }
    }
    fn disappear(mut self, abrupt: bool) {
        if abrupt {
            self.child.kill().unwrap();
        } else {
            self.ipc.shutdown(std::net::Shutdown::Write).unwrap();
        }
        self.child.wait().unwrap();
        self.reaped = true;
        self.ipc
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        assert_eq!(
            self.ipc.read(&mut [0; 1]).unwrap(),
            0,
            "owned frontend IPC did not reach EOF"
        );
    }
}
impl Drop for Frontend {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
#[derive(Debug, PartialEq, Eq)]
struct Identity {
    child: u32,
    parent: u32,
    group: u32,
    session: u32,
    tty: String,
    kernel_tty: i64,
    start: u64,
}
fn observed_identity(record: &str) -> (Identity, u64) {
    let fields: Vec<_> = record.split_whitespace().collect();
    assert_eq!(
        fields.len(),
        6,
        "malformed deterministic child record: {record}"
    );
    assert_eq!(fields[0], "OWNER529");
    let pid: u32 = fields[1].parse().unwrap();
    let parent: u32 = fields[2].parse().unwrap();
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap();
    let tail: Vec<_> = stat[stat.rfind(')').unwrap() + 2..]
        .split_whitespace()
        .collect();
    assert_eq!(tail[1].parse::<u32>().unwrap(), parent);
    assert_eq!(
        parent,
        std::process::id(),
        "owner fixture must be actual spawning/waiting parent"
    );
    (
        Identity {
            child: pid,
            parent,
            group: tail[2].parse().unwrap(),
            session: tail[3].parse().unwrap(),
            tty: fields[3].into(),
            kernel_tty: tail[4].parse().unwrap(),
            start: tail[19].parse().unwrap(),
        },
        fields[5].parse().unwrap(),
    )
}
fn consume_live(
    engine: &SessionOwnerEngine,
    frontend: &FrontendAttachment,
    instance: ChannelInstance,
    consumer: &mut NoScreenConsumer,
) {
    let mut scratch = [0; 16384];
    let offset = consumer.cursor().offset;
    let n = engine
        .copy_output(frontend, instance, offset, &mut scratch)
        .unwrap();
    consumer.consume_live(offset, &scratch[..n]).unwrap();
    engine
        .acknowledge_output(frontend, instance, consumer.cursor().offset)
        .unwrap();
}
async fn progress(
    engine: &SessionOwnerEngine,
    frontend: &FrontendAttachment,
    instance: ChannelInstance,
    consumer: &mut NoScreenConsumer,
    after: u64,
) -> (Identity, u64) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        consume_live(engine, frontend, instance, consumer);
        let text = std::str::from_utf8(consumer.bytes()).unwrap();
        if let Some(record) = text.split_inclusive('\n').rev().find(|l| {
            l.ends_with('\n')
                && l.starts_with("OWNER529 ")
                && l.split_whitespace().count() == 6
                && l.split_whitespace()
                    .last()
                    .and_then(|s| s.parse::<u64>().ok())
                    .is_some_and(|v| v > after)
        }) {
            return observed_identity(record);
        }
        assert!(
            Instant::now() < until,
            "same child did not advance progress"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}
async fn wait_committed(engine: &SessionOwnerEngine, instance: ChannelInstance, offset: u64) {
    let until = Instant::now() + Duration::from_secs(5);
    while engine.input_position(instance).unwrap().committed < offset {
        assert!(
            Instant::now() < until,
            "physical input write never committed"
        );
        tokio::task::yield_now().await;
    }
}
async fn wait_barrier(engine: &SessionOwnerEngine) {
    let until = Instant::now() + Duration::from_secs(5);
    while !engine.barriers_settled() {
        assert!(
            Instant::now() < until,
            "actual writer barrier remained pending"
        );
        tokio::task::yield_now().await;
    }
}
async fn wait_checks(
    engine: &SessionOwnerEngine,
    front: &FrontendAttachment,
    instance: ChannelInstance,
    consumer: &mut NoScreenConsumer,
    count: usize,
) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        consume_live(engine, front, instance, consumer);
        let text = std::str::from_utf8(consumer.bytes()).unwrap();
        let checks: Vec<_> = text
            .lines()
            .filter(|l| l.starts_with("INPUT529 CHECK seen="))
            .collect();
        if checks.len() >= count {
            assert!(
                checks
                    .iter()
                    .all(|l| l.trim_end() == "INPUT529 CHECK seen=1"),
                "child received a duplicate uncertain input marker"
            );
            return;
        }
        assert!(
            Instant::now() < until,
            "deterministic child input check did not arrive"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}
struct Host {
    client: OwnerResourceClient,
    locator: SessionLocator,
    next: u64,
}
impl Host {
    fn transfer(&mut self, instance: ChannelInstance, retained: usize) -> TransferAllowance {
        self.next += 1;
        let r = Reservation {
            id: ReservationId::new(self.next).unwrap(),
            principal: self.client.principal(),
            locator: self.locator,
            channel: instance,
            kind: ReservationKind::SnapshotTransfer,
            bytes: (retained.max(1) + 16384 + 65536) as u64,
            screen_charge: None,
        };
        TransferAllowance::admit(
            self.client.clone(),
            r,
            RequestId::new(self.next).unwrap(),
            retained,
        )
        .unwrap()
    }
    async fn recover(
        &mut self,
        engine: &SessionOwnerEngine,
        front: &FrontendAttachment,
        instance: ChannelInstance,
        consumer: &mut NoScreenConsumer,
    ) {
        let until = Instant::now() + Duration::from_secs(5);
        while !engine.catalog_available() {
            assert!(
                Instant::now() < until,
                "actual owner catalog facts unavailable"
            );
            tokio::task::yield_now().await;
        }
        let mut catalog = engine.catalog(front, self.transfer(instance, 0)).unwrap();
        let cursor = consumer.cursor();
        let boundary = catalog
            .catalog()
            .positions()
            .iter()
            .find(|p| p.channel == instance)
            .unwrap()
            .output;
        let allowance = self.transfer(
            instance,
            usize::try_from(boundary.offset - cursor.offset).unwrap(),
        );
        let request = RecoveryRequest {
            attachment: front.attachment(),
            channel: instance,
            parser: ParserContinuity::DataCursor { cursor },
        };
        let request_id = RequestId::new(self.next + 100).unwrap();
        let recovery_id = RecoveryId::new([self.next as u8; 16]).unwrap();
        let mut producer = engine
            .recover(
                front,
                &mut catalog,
                request,
                recovery_id,
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
        let consumed = consumer.finish(end, ready).unwrap();
        catalog.accept_consumed(consumed).unwrap();
        engine.finish_recovery(front, catalog).unwrap();
        engine
            .acknowledge_output(front, instance, consumer.cursor().offset)
            .unwrap();
    }
}

#[test]
fn owner_engine_personal_child_survives_frontend_loss() {
    if std::env::var("QSH529_NATIVE_CHILD").as_deref() == Ok("progress") {
        let tty = std::fs::read_link("/proc/self/fd/0").unwrap();
        assert!(unsafe { libc::isatty(0) } == 1);
        std::thread::spawn(move || {
            for n in 0..400 {
                println!(
                    "\nOWNER529 {} {} {} progress {n}",
                    std::process::id(),
                    unsafe { libc::getppid() },
                    tty.display()
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        });
        use std::io::BufRead;
        let stdin = std::io::stdin();
        let mut input = stdin.lock();
        let mut line = String::new();
        let mut seen = 0;
        loop {
            line.clear();
            if input.read_line(&mut line).unwrap() == 0 {
                break;
            }
            match line.trim_end() {
                "MARK529-ONCE" => {
                    seen += 1;
                    println!("\nINPUT529 seen={seen}");
                }
                "CHECK529" => println!("\nINPUT529 CHECK seen={seen}"),
                _ => {}
            }
        }
        return;
    }
    let outcome = crate::test_support::borrowed_scope::run_exact(NAME, 0, || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(survival_body());
    });
    outcome.assert_clean(0);
}

const NAME: &str =
    "session_owner::engine_native_tests::owner_engine_personal_child_survives_frontend_loss";
async fn survival_body() {
    let locator = SessionLocator {
        session: RetainedSessionId::new([51; 16]).unwrap(),
        owner: OwnerInstance::new([52; 16]).unwrap(),
    };
    let principal_ref = AuthenticatedPrincipalRef::new([53; 16]).unwrap();
    let bytes = ByteLimits {
        channel_bytes: 1048576,
        session_bytes: 1048576,
        account_bytes: 1048576,
        global_bytes: 2097152,
    };
    let limits = ResourceLimits {
        max_reservations: 16,
        screen: ScreenLimits {
            global_cells: 0,
            account_cells: 0,
            global_rows: 0,
            account_rows: 0,
            global_models: 0,
            account_models: 0,
        },
        snapshot_transfer: bytes,
        control_queue: bytes,
    };
    let mut ledger = ResourceLedger::new(LedgerInstance::new([54; 16]).unwrap(), limits).unwrap();
    let uid = unsafe { libc::geteuid() };
    let registration = ledger.register_fresh_principal(principal_ref, uid).unwrap();
    let ledger = Arc::new(Mutex::new(ledger));
    let client = OwnerResourceClient::new(ledger.clone(), registration);
    let screen_budget = crate::screen_budget::BudgetLimits {
        global_cells: 0,
        owner_cells: 0,
        global_rows: 0,
        owner_rows: 0,
        global_models: 0,
        owner_models: 0,
    };
    let spawner = Arc::new(crate::channel_backend::PtyChannelSpawner::new(Arc::new(
        crate::screen_budget::ScreenBudget::new(screen_budget),
    )));
    let (_restart_tx, restart) = tokio::sync::watch::channel(RestartSignal::IDLE);
    let principal = transport::Principal {
        uid,
        name: "owned-native-fixture".into(),
        identity: "local self-account fixture".into(),
        incarnation: 0,
    };
    let mut engine = SessionOwnerEngine::new(
        locator,
        principal,
        [55; 16],
        spawner,
        client.clone(),
        Arc::new(Clock(Instant::now())),
        restart,
    )
    .unwrap();
    let first = engine.attach_trusted(attachment(locator, 1)).unwrap();
    let instance = ChannelInstance::new(1).unwrap();
    let reservation = |id, kind, bytes| Reservation {
        id: ReservationId::new(id).unwrap(),
        principal: principal_ref,
        locator,
        channel: instance,
        kind,
        bytes,
        screen_charge: None,
    };
    let executable = std::env::current_exe().unwrap();
    let command = format!(
        "/usr/bin/env QSH529_NATIVE_CHILD=progress '{}' --exact {NAME} --nocapture",
        executable.display()
    )
    .into_bytes();
    engine
        .open(
            &first,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command,
            },
            None,
            OwnerChannelResources {
                history: reservation(1, ReservationKind::OutputHistory, 32768 + 1024),
                control: reservation(2, ReservationKind::ControlQueue, 131072),
                cleanup: RequestId::new(1).unwrap(),
                read_buffer_bytes: 1024,
                input_epoch: InputEpoch::new([61; 16]).unwrap(),
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        engine.user_input(
            &first,
            instance,
            InputEpoch::new([1; 16]).unwrap(),
            0,
            b"not admitted"
        ),
        Err(EngineError::Unavailable)
    ));
    let mut host = Host {
        client,
        locator,
        next: 2,
    };
    let mut consumer = NoScreenConsumer::new(instance, host.transfer(instance, 65536)).unwrap();
    // No input is available merely because the frontend attached or OPEN completed.
    host.recover(&engine, &first, instance, &mut consumer).await;
    let frontend = Frontend::new();
    let (identity, n) = progress(&engine, &first, instance, &mut consumer, 0).await;
    assert!(identity.kernel_tty != 0 && identity.tty.starts_with("/dev/pts/"));
    const MARKER: &[u8] = b"MARK529-ONCE\n";
    const PROBE: &[u8] = b"CHECK529\n";
    let epoch = InputEpoch::new([61; 16]).unwrap();
    let lost_ack = engine
        .user_input(&first, instance, epoch, 0, MARKER)
        .unwrap();
    drop(lost_ack);
    wait_committed(&engine, instance, MARKER.len() as u64).await;
    note(&format!(
        "owner529 physical_marker_committed={} lost_ack=1 epoch_stable=1",
        MARKER.len()
    ));
    frontend.disappear(false);
    drop(first);
    wait_barrier(&engine).await;
    let second = engine.attach_trusted(attachment(locator, 2)).unwrap();
    assert!(
        engine
            .user_input(&second, instance, epoch, 0, MARKER)
            .is_err(),
        "new lease input bypassed real recovery"
    );
    host.recover(&engine, &second, instance, &mut consumer)
        .await;
    let ack = engine
        .user_input(&second, instance, epoch, 0, MARKER)
        .unwrap()
        .accepted()
        .await
        .unwrap();
    assert_eq!(ack.epoch, epoch);
    assert_eq!(ack.committed, MARKER.len() as u64);
    engine
        .user_input(&second, instance, epoch, MARKER.len() as u64, PROBE)
        .unwrap()
        .accepted()
        .await
        .unwrap();
    wait_committed(&engine, instance, (MARKER.len() + PROBE.len()) as u64).await;
    wait_checks(&engine, &second, instance, &mut consumer, 1).await;
    let (same, n2) = progress(&engine, &second, instance, &mut consumer, n + 2).await;
    assert_eq!(same, identity);
    let frontend = Frontend::new();
    frontend.disappear(true);
    drop(second);
    wait_barrier(&engine).await;
    let third = engine.attach_trusted(attachment(locator, 3)).unwrap();
    host.recover(&engine, &third, instance, &mut consumer).await;
    engine
        .user_input(&third, instance, epoch, 0, MARKER)
        .unwrap()
        .accepted()
        .await
        .unwrap();
    engine
        .user_input(
            &third,
            instance,
            epoch,
            (MARKER.len() + PROBE.len()) as u64,
            PROBE,
        )
        .unwrap()
        .accepted()
        .await
        .unwrap();
    wait_committed(&engine, instance, (MARKER.len() + 2 * PROBE.len()) as u64).await;
    wait_checks(&engine, &third, instance, &mut consumer, 2).await;
    let (same, n3) = progress(&engine, &third, instance, &mut consumer, n2 + 2).await;
    assert_eq!(same, identity);
    assert_eq!(engine.locator(), locator);
    let records: Vec<_> = std::str::from_utf8(consumer.bytes())
        .unwrap()
        .split_inclusive('\n')
        .filter(|l| l.ends_with('\n') && l.starts_with("OWNER529 "))
        .map(observed_identity)
        .collect();
    assert!(records.len() > n3 as usize);
    for (expected, (same, n)) in records.iter().enumerate() {
        assert_eq!(same, &identity);
        assert_eq!(
            *n, expected as u64,
            "NoScreen output lost or duplicated a record"
        );
    }
    assert_eq!(
        std::str::from_utf8(consumer.bytes())
            .unwrap()
            .lines()
            .filter(|l| l.trim_end() == "INPUT529 seen=1")
            .count(),
        1
    );
    note(&format!("owner529 owner={} child={} parent={} tty={} kernel_tty={} group={} session={} start={} channel={} epochs=1,2,3 progress={n},{n2},{n3} marker_count=1 checked_after_resend=2",std::process::id(),identity.child,identity.parent,identity.tty,identity.kernel_tty,identity.group,identity.session,identity.start,instance.get()));
    let completed = tokio::time::timeout(Duration::from_secs(5), engine.close_session())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].instance(), instance);
    assert!(completed[0].code().is_some());
    assert!(completed[0].workers_joined());
    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(identity.child as i32, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert_eq!(
        ledger.lock().unwrap().reservations(),
        1,
        "consumer backing must remain charged after child cleanup"
    );
    drop(consumer);
    assert_eq!(ledger.lock().unwrap().reservations(), 0);
    note(&format!("owner529 exact_child_reaped=1 reader_joined=1 writer_joined=1 resource_reservations=0 frontend_waits=2 code={:?}",completed[0].code()));
}

#[path = "screen_native_tests.rs"]
mod screen;
