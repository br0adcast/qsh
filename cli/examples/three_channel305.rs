//! Opt-in native functional qualification. Tests never launch this entry point.
#[path = "three_channel305/accounting.rs"]
mod accounting;
#[path = "three_channel305/pacing.rs"]
mod pacing;
use accounting::{Budget, Hold, Ledger, Raw};
use client::channel::{ChannelSendError, ChannelSession, SessionEvent};
use client::qsh::QshSubstrate;
use qshd::channel_backend::ChannelSessionBackend;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Notify};
use transport::driver_std::{Binder, ClientEvents, DriverSetup, StdClient};
use transport::session_manager::{
    BackendFactory, LoginEndedReports, QualificationOwner, ServerAuth, SessionBackend, SessionIo,
    SessionManager,
};
use transport::{AuthPolicy, ConnectionConfig, Consumption, Features, LinkState, Role, Shutdown};

const BULK_BYTES: u64 = 4 * 1024 * 1024;
const BULK_RECORDS: u32 = 65536;
const ECHOES: u32 = 32;
const INBOX_ENTRIES: usize = 1024;
const RAW_LIMIT: usize = 2 * 1024 * 1024;
const HELD_LIMIT: usize = 512 * 1024;
const FINAL: &str = "QSH305-FINAL";
// No newlines in fixed bulk bytes: PTY ONLCR cannot alter the checksum.
const BULK_COMMAND: &[u8] = b"/usr/bin/python3 -I -c 'import os,sys; sys.stdin.buffer.readline(); [(os.write(1,(format(i,\"08x\")+\":\"+\"x\"*55).encode())) for i in range(65536)]; sys.stdin.buffer.readline()'";
const ECHO_COMMAND: &[u8] = b"/usr/bin/python3 -I -c 'import os,sys; [(os.write(1,sys.stdin.buffer.readline().rstrip(b\"\\n\")+b\";\")) for _ in range(32)]'";
const READY: &str = "QSH305-READY";
const SCREEN_COMMAND: &[u8] = b"/usr/bin/python3 -I -c 'import os,sys,termios; old=termios.tcgetattr(0); new=old.copy(); new[3]&=~(termios.ECHO|termios.ECHONL); termios.tcsetattr(0,termios.TCSANOW,new)\ntry:\n os.write(1,b\"\\x1b[2J\\x1b[HQSH305-\"+b\"READY\\n\")\n for i in range(97):\n  line=sys.stdin.buffer.readline()\n  if line==b\"FINISH\\n\": break\n  if i==96 or line!=b\"G\\n\": raise RuntimeError(\"grant\")\n  sys.stdout.buffer.write(b\"x\"*8192); sys.stdout.buffer.flush()\n os.write(1,b\"\\x1b[2J\\x1b[HQSH305-\"+b\"FINAL\\n\")\nfinally: termios.tcsetattr(0,termios.TCSANOW,old)'\n";

type Sink = Box<dyn FnMut(u8, Vec<u8>) -> Result<(), ChannelSendError> + Send>;
type Session = ChannelSession<QshSubstrate<Sink>>;
enum Incoming {
    Bytes(Raw),
    State(LinkState),
    Auth(transport::AuthAcceptance),
    Fault,
}
struct Mailbox {
    tx: mpsc::Sender<Incoming>,
    budget: Budget,
    sequence: [AtomicU64; 256],
    failed: AtomicBool,
    fault: Notify,
}
impl Mailbox {
    fn fail(&self) {
        self.failed.store(true, Ordering::Release);
        self.fault.notify_one();
    }
    fn publish(&self, event: Incoming) {
        if self.tx.try_send(event).is_err() {
            self.fail();
        }
    }
}
impl ClientEvents for Mailbox {
    fn on_bytes(&self, stream: u8, bytes: Vec<u8>) {
        let sequence = self.sequence[usize::from(stream)].fetch_add(1, Ordering::Relaxed);
        match self.budget.chunk(stream, sequence, bytes) {
            Ok(raw) => self.publish(Incoming::Bytes(raw)),
            Err(_) => self.fail(),
        }
    }
    fn on_state(&self, state: LinkState) {
        self.publish(Incoming::State(state));
    }
    fn on_stats(&self, _: transport::Stats) {}
    fn on_reset(&self, _: u8) {
        self.publish(Incoming::Fault);
    }
    fn on_input_failure(&self, _: transport::driver_std::InputFailure) {
        self.publish(Incoming::Fault);
    }
    fn on_auth_accepted(&self, value: transport::AuthAcceptance) {
        self.publish(Incoming::Auth(value));
    }
    fn on_protocol_failure(&self, _: transport::ProtocolFailure) {
        self.publish(Incoming::Fault);
    }
    fn on_session_aborted(&self, _: transport::SessionAbortReason) {
        self.publish(Incoming::Fault);
    }
}
struct AnyNetwork;
impl Binder for AnyNetwork {
    fn bind(&self, _: i32) -> bool {
        true
    }
}
struct ObservedBackend {
    inner: ChannelSessionBackend,
    owner: Mutex<Option<oneshot::Sender<QualificationOwner>>>,
}
impl SessionBackend for ObservedBackend {
    fn required_features(&self) -> Features {
        self.inner.required_features()
    }
    fn consumption(&self) -> Consumption {
        self.inner.consumption()
    }
    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        if let Some(sender) = self.owner.lock().expect("fixture owner slot").take() {
            let _ = sender.send(io.qualification_owner());
        }
        self.inner.run(io) // No Live interception/forwarding or replacement backend.
    }
}
#[derive(Default, Clone, Serialize)]
struct Summary {
    bulk_bytes: u64,
    echo_responses: u32,
    decoded_gaps: u64,
    raw_processed: u64,
    blocked_sequence: u64,
    release_sequence: u64,
    credit_recovered_sequence: u64,
    released: bool,
    final_state_marker: bool,
    source_pending_high_water: u64,
    reliable_tail_high_water: u64,
    observer_skipped: u64,
    held_bytes: usize,
    held_high_water: usize,
    producer_ready: bool,
    producer_grants: u16,
    last_credit: Option<u64>,
    last_gate_open: bool,
    last_source_pending: u64,
    last_reliable_tail: u64,
    bulk_exited: bool,
    echo_exited: bool,
    screen_exited: bool,
}
struct Progress {
    bulk: u8,
    echo: u8,
    screen: u8,
    summary: Summary,
    bulk_hash: Sha256,
    echo_buffer: Vec<u8>,
    terminal: terminal::TerminalCore,
}
impl Progress {
    fn refresh_markers(&mut self) {
        let frame = self.terminal.frame();
        let text: String = frame.cells.iter().map(|cell| cell.ch).collect();
        self.summary.final_state_marker = text.contains(FINAL);
        self.summary.producer_ready =
            text.contains(READY) && frame.cursor_row == 1 && frame.cursor_col == 0;
    }
    fn events(&mut self, events: Vec<SessionEvent>) -> Result<(), String> {
        for event in events {
            match event {
                SessionEvent::Data { ch, bytes } if ch == self.bulk => {
                    self.summary.bulk_bytes += bytes.len() as u64;
                    if self.summary.bulk_bytes > BULK_BYTES {
                        return Err("bulk overflow".into());
                    }
                    self.bulk_hash.update(&bytes);
                }
                SessionEvent::Data { ch, bytes } if ch == self.echo => {
                    self.echo_buffer.extend_from_slice(&bytes);
                    if self.echo_buffer.len() > 10 {
                        return Err("echo size/order".into());
                    }
                    if self.echo_buffer.len() == 10 {
                        let expected = format!("E{:08};", self.summary.echo_responses);
                        if self.echo_buffer != expected.as_bytes() {
                            return Err("echo mismatch".into());
                        }
                        self.echo_buffer.clear();
                        self.summary.echo_responses += 1;
                    }
                }
                SessionEvent::Data { ch, bytes } if ch == self.screen => {
                    self.terminal.feed(&bytes);
                    self.refresh_markers();
                }
                SessionEvent::Geometry { ch, record } if ch == self.screen => {
                    self.terminal.resize(record.cols, record.rows);
                    self.refresh_markers();
                }
                SessionEvent::OutputContinuityLost { .. } => self.summary.decoded_gaps += 1, // Diagnostic only; no applied-gap claim.
                SessionEvent::Exit { ch, code } => {
                    if code != 0 {
                        return Err("nonzero remote exit".into());
                    }
                    if ch == self.bulk {
                        if self.summary.bulk_bytes != BULK_BYTES {
                            return Err("bulk Exit before prefix".into());
                        }
                        self.summary.bulk_exited = true;
                    } else if ch == self.echo {
                        if self.summary.echo_responses != ECHOES {
                            return Err("echo Exit before prefix".into());
                        }
                        self.summary.echo_exited = true;
                    } else if ch == self.screen {
                        self.refresh_markers();
                        if !self.summary.released
                            || !self.summary.final_state_marker
                            || self.summary.credit_recovered_sequence == 0
                        {
                            return Err("Screen Exit before required state".into());
                        }
                        self.summary.screen_exited = true;
                    }
                }
                SessionEvent::ExtendedData { .. } => {
                    return Err("unexpected PTY extended output".into())
                }
                SessionEvent::ProtocolFailure(_)
                | SessionEvent::SendFailure { .. }
                | SessionEvent::Refused { .. }
                | SessionEvent::Vanished { .. }
                | SessionEvent::ExitStatusUnavailable { .. } => {
                    return Err("channel failure".into())
                }
                _ => {}
            }
        }
        Ok(())
    }
}
struct Finished {
    session: Session,
    progress: Progress,
    receiver: mpsc::Receiver<Incoming>,
    ledger: Ledger,
    mailbox: Arc<Mailbox>,
}
fn process(
    raw: Raw,
    session: &mut Session,
    progress: &mut Progress,
    ledger: &mut Ledger,
    client: &StdClient,
) -> Result<(), String> {
    ledger.process(
        raw,
        |stream, bytes| progress.events(session.on_bytes(stream, bytes)),
        |stream, n| {
            // CONTROL is configured OnDelivery; explicitly consuming it here would double credit.
            if stream >= transport::channel::FIRST_CHANNEL_STREAM {
                client.consumed(stream, n);
            }
        },
    )
}
fn record_observation(summary: &mut Summary, sample: transport::qualification305::Snapshot) {
    if sample.values_available {
        summary.source_pending_high_water = sample.pending_high_water;
        summary.reliable_tail_high_water = sample.tail_high_water;
        summary.observer_skipped = sample.publications_skipped;
        summary.last_credit = sample.credit_remaining;
        summary.last_gate_open =
            sample.gate_byte_open && !sample.gate_closed && !sample.gate_metadata_blocked;
        summary.last_source_pending = sample.source_pending;
        summary.last_reliable_tail = sample.reliable_tail;
    }
    if sample.valid && sample.credit_blocked && summary.blocked_sequence == 0 {
        summary.blocked_sequence = sample.sequence;
    }
    if summary.released
        && sample.values_available
        && sample.valid
        && !sample.retired
        && sample.sequence > summary.release_sequence
        && sample
            .credit_remaining
            .is_some_and(|remaining| remaining > 0)
        && summary.credit_recovered_sequence == 0
    {
        summary.credit_recovered_sequence = sample.sequence;
    }
}

async fn next_report(
    reports: &mut Option<transport::qualification305::Reports>,
) -> Option<transport::qualification305::Snapshot> {
    match reports.as_mut() {
        Some(reports) => reports.changed().await,
        None => std::future::pending().await,
    }
}
fn end_observation(
    scope: &mut Option<transport::qualification305::Scope>,
    reports: &mut Option<transport::qualification305::Reports>,
) {
    drop(reports.take());
    drop(scope.take());
}

struct Bootstrap {
    addr: std::net::SocketAddr,
    server_pub: [u8; 32],
    client_priv: [u8; 32],
    login: [u8; 16],
}
async fn work(
    bootstrap: Bootstrap,
    mut owner_rx: oneshot::Receiver<QualificationOwner>,
    client_tx: oneshot::Sender<Arc<StdClient>>,
    shared: Arc<Mutex<Summary>>,
    budget: Budget,
) -> Result<Finished, String> {
    let Bootstrap {
        addr,
        server_pub,
        client_priv,
        login,
    } = bootstrap;
    let (tx, mut receiver) = mpsc::channel(INBOX_ENTRIES);
    let mailbox = Arc::new(Mailbox {
        tx,
        budget,
        sequence: std::array::from_fn(|_| AtomicU64::new(0)),
        failed: AtomicBool::new(false),
        fault: Notify::new(),
    });
    let client = Arc::new(StdClient::connect_with(
        addr,
        ConnectionConfig {
            role: Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(server_pub),
            auth: AuthPolicy::Allowlist(Vec::new()),
            features: Features::SUPPORTED,
            required_features: Features::AUTH_ACCEPTED
                | Features::CHANNEL_GEOMETRY
                | Features::STREAM_CREDIT,
        },
        login,
        transport::handshake_payload::StartKind::Cold,
        Arc::new(AnyNetwork),
        mailbox.clone(),
        None,
        DriverSetup {
            default_consumption: Consumption::Explicit,
            stream_consumption: vec![(transport::channel::CONTROL_STREAM, Consumption::OnDelivery)],
            ..Default::default()
        },
    ));
    client_tx
        .send(client.clone())
        .map_err(|_| "client custody receiver closed")?;
    let sink_client = client.clone();
    let sink: Sink = Box::new(move |stream, bytes| {
        sink_client
            .send_bytes_bounded(stream, bytes, Duration::ZERO)
            .map_err(|failure| match failure.reason {
                transport::driver_std::SendBlocked::Full => ChannelSendError::Full,
                transport::driver_std::SendBlocked::OnDriverThread => {
                    ChannelSendError::OnDriverThread
                }
                _ => ChannelSendError::Gone,
            })
    });
    let mut session = Session::new(QshSubstrate::new(sink));
    let mut authenticated = None;
    // Nothing is opened before actual authenticated acceptance.
    while authenticated.is_none() {
        match receiver.recv().await.ok_or("callback closed")? {
            Incoming::Auth(a) => authenticated = Some(a.session_id),
            Incoming::State(LinkState::Closed) | Incoming::Fault => {
                return Err("connect failed".into())
            }
            Incoming::Bytes(_) => return Err("bytes before authenticated acceptance".into()),
            _ => {}
        }
    }
    session
        .announce_term("xterm-256color")
        .map_err(|_| "term admission")?;
    let bulk = session
        .open_command(BULK_COMMAND, 80, 24)
        .map_err(|_| "bulk open")?;
    let echo = session
        .open_command(ECHO_COMMAND, 80, 24)
        .map_err(|_| "echo open")?;
    let screen = session.open_shell(80, 24).map_err(|_| "Screen open")?;
    let mut progress = Progress {
        bulk,
        echo,
        screen,
        summary: Summary::default(),
        bulk_hash: Sha256::new(),
        echo_buffer: Vec::new(),
        terminal: terminal::TerminalCore::new(80, 24),
    };
    let mut ledger = Ledger::default();
    let mut hold: Option<Hold> = None;
    let mut reports: Option<transport::qualification305::Reports> = None;
    let mut scope = None;
    let mut hold_started = None;
    let mut sent_echoes = 0;
    let mut bulk_started = false;
    let mut bulk_finish = false;
    let mut screen_exit = false;
    let mut producer_started = false;
    let mut pace = pacing::Pace::default();
    let mut last_sample = None;
    loop {
        if mailbox.failed.load(Ordering::Acquire) {
            return Err("bounded callback inbox overflow".into());
        }
        if hold_started.is_some_and(|start: Instant| {
            !progress.summary.released && start.elapsed() >= Duration::from_secs(5)
        }) {
            return Err("missing blocked/progress evidence within hold watchdog".into());
        }
        if !producer_started
            && session.is_ready(bulk)
            && session.is_ready(echo)
            && session.is_ready(screen)
        {
            session
                .send(screen, SCREEN_COMMAND)
                .map_err(|_| "Screen producer admission")?;
            producer_started = true;
        }
        if reports.is_none()
            && hold_started.is_none()
            && progress.summary.producer_ready
            && session.is_ready(bulk)
            && session.is_ready(echo)
            && session.is_ready(screen)
        {
            let owner = (&mut owner_rx).await.map_err(|_| "backend owner missing")?;
            let instance = session
                .committed_geometry(screen)
                .ok_or("missing Screen geometry")?
                .instance;
            let (registered, receiver) =
                owner
                    .register(authenticated.unwrap(), screen, instance)
                    .map_err(|error| format!("processed Live scope refused: {error:?}"))?;
            scope = Some(registered);
            reports = Some(receiver);
            hold = Some(Hold::new(screen, HELD_LIMIT, INBOX_ENTRIES));
            hold_started = Some(Instant::now());
        }
        if hold.is_some() && progress.summary.blocked_sequence == 0 {
            if let Some(sample) = last_sample.take() {
                if pace.grant(sample).map_err(str::to_owned)? {
                    session
                        .send(screen, b"G\n")
                        .map_err(|_| "Screen grant admission")?;
                }
                progress.summary.producer_grants = pace.grants;
            }
        }
        if progress.summary.blocked_sequence != 0 && !bulk_started {
            session.send(bulk, b"RUN\n").map_err(|_| "bulk start")?;
            bulk_started = true;
            session
                .send(echo, b"E00000000\n")
                .map_err(|_| "echo start")?;
            sent_echoes = 1;
        }
        if bulk_started && progress.summary.echo_responses == sent_echoes && sent_echoes < ECHOES {
            session
                .send(echo, format!("E{sent_echoes:08}\n").as_bytes())
                .map_err(|_| "echo next")?;
            sent_echoes += 1;
        }
        if !progress.summary.released
            && progress.summary.blocked_sequence != 0
            && progress.summary.bulk_bytes >= 65536
            && progress.summary.echo_responses >= 1
        {
            let witness = reports
                .as_ref()
                .and_then(|r| r.latest())
                .ok_or("blocked report unavailable at release")?;
            if !witness.valid || !witness.credit_blocked {
                return Err("Screen no longer credit blocked at release".into());
            }
            let mut held = hold.take().ok_or("held owner missing")?;
            progress.summary.release_sequence = witness.sequence;
            progress.summary.released = true;
            while let Some(raw) = held.pop() {
                process(raw, &mut session, &mut progress, &mut ledger, &client)?;
            }
            progress.summary.held_bytes = held.bytes();
            session
                .send(screen, b"FINISH\n")
                .map_err(|_| "Screen finish admission")?;
        }
        if progress.summary.bulk_bytes == BULK_BYTES && !bulk_finish {
            session.send(bulk, b"FINISH\n").map_err(|_| "bulk finish")?;
            bulk_finish = true;
        }
        if progress.summary.released
            && progress.summary.final_state_marker
            && progress.summary.credit_recovered_sequence != 0
            && progress.summary.bulk_exited
            && progress.summary.echo_exited
            && !screen_exit
        {
            end_observation(&mut scope, &mut reports);
            session.send(screen, b"exit\n").map_err(|_| "Screen exit")?;
            screen_exit = true;
        }
        progress.summary.raw_processed = ledger.processed_bytes;
        progress.summary.held_bytes = hold.as_ref().map_or(0, Hold::bytes);
        progress.summary.held_high_water = progress
            .summary
            .held_high_water
            .max(progress.summary.held_bytes);
        *shared.lock().unwrap() = progress.summary.clone();
        if progress.summary.bulk_exited
            && progress.summary.echo_exited
            && progress.summary.screen_exited
        {
            let mut expected = Sha256::new();
            for i in 0..BULK_RECORDS {
                expected.update(format!("{i:08x}:{}", "x".repeat(55)).as_bytes());
            }
            if progress.bulk_hash.clone().finalize() != expected.finalize() {
                return Err("bulk checksum mismatch".into());
            }
            drop(scope);
            return Ok(Finished {
                session,
                progress,
                receiver,
                ledger,
                mailbox,
            });
        }
        enum Turn {
            Incoming(Option<Incoming>),
            Report(Option<transport::qualification305::Snapshot>),
            Fault,
            Watchdog,
        }
        let deadline = hold_started
            .map(|start| tokio::time::Instant::from_std(start + Duration::from_secs(5)));
        let turn = tokio::select! {
            event=receiver.recv()=>Turn::Incoming(event),
            report=next_report(&mut reports)=>Turn::Report(report),
            _=mailbox.fault.notified()=>Turn::Fault,
            _=async {match deadline {Some(d) if !progress.summary.released=>tokio::time::sleep_until(d).await,_=>std::future::pending().await}}=>Turn::Watchdog,
        };
        match turn {
            Turn::Incoming(Some(Incoming::Bytes(raw))) => {
                match (raw.stream() == screen, hold.as_mut()) {
                    (true, Some(held)) => held.push(raw).map_err(|_| "held Screen FIFO cap")?,
                    _ => process(raw, &mut session, &mut progress, &mut ledger, &client)?,
                }
            }
            Turn::Incoming(Some(Incoming::State(LinkState::Closed)))
            | Turn::Incoming(Some(Incoming::Fault))
            | Turn::Incoming(None)
            | Turn::Fault => return Err("transport/callback failure".into()),
            Turn::Report(Some(sample)) => {
                if sample.retired {
                    return Err("registered Screen scope retired".into());
                }
                record_observation(&mut progress.summary, sample);
                last_sample = Some(sample);
            }
            Turn::Incoming(Some(Incoming::Auth(_))) => {
                return Err("unexpected additional admission".into())
            }
            Turn::Report(None) | Turn::Watchdog => {
                return Err("missing owned Screen blockage".into())
            }
            _ => {}
        }
    }
}

/// Called only after the actual StdClient thread has joined; no callback
/// producer remains. CONTROL receipts are already OnDelivery, not explicit.
fn finish_receipts(output: &mut Finished) -> Result<(), String> {
    if output.mailbox.failed.load(Ordering::Acquire) {
        return Err("sticky late callback failure".into());
    }
    while let Ok(event) = output.receiver.try_recv() {
        match event {
            Incoming::Bytes(raw) => {
                if raw.stream() != transport::channel::CONTROL_STREAM {
                    return Err("late channel/reserved bytes after ordered Exit".into());
                }
                output.ledger.process(
                    raw,
                    |stream, bytes| {
                        output
                            .progress
                            .events(output.session.on_bytes(stream, bytes))
                    },
                    |_, _| {},
                )?;
            }
            Incoming::State(LinkState::Closed) => {}
            Incoming::Fault | Incoming::Auth(_) | Incoming::State(_) => {
                return Err("unexpected late terminal/auth/state callback".into())
            }
        }
    }
    if output.mailbox.failed.load(Ordering::Acquire) {
        return Err("sticky late callback failure".into());
    }
    Ok(())
}

async fn owned_run() -> Result<(), String> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).map_err(|_| "TERM setup")?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(|_| "INT setup")?;
    let socket = Arc::new(
        tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .map_err(|_| "owned UDP bind")?,
    );
    let addr = socket.local_addr().map_err(|_| "owned UDP address")?;
    let server_key = transport::handshake::generate_keypair();
    let client_key = transport::handshake::generate_keypair();
    let auth = ServerAuth {
        allowlist: Arc::new(Mutex::new(vec![client_key.public])),
        verifier: None,
        server_pub: server_key.public,
        self_principal: transport::Principal {
            uid: nix::unistd::getuid().as_raw(),
            name: "qualification".into(),
            identity: "owned-functional".into(),
            incarnation: 0,
        },
        nonces: Arc::new(qshd::RandomNonces),
        logins: Arc::new(qshd::ForgetNothing),
    };
    let budget = Arc::new(qshd::screen_budget::ScreenBudget::new(Default::default()));
    let inner = ChannelSessionBackend::new(budget);
    let registry = inner.open_registry();
    let (owner_tx, owner_rx) = oneshot::channel();
    let backend = Arc::new(ObservedBackend {
        inner,
        owner: Mutex::new(Some(owner_tx)),
    });
    let shutdown = Shutdown::default();
    let manager = tokio::spawn(SessionManager::serve_until_shutdown(
        socket,
        server_key.private,
        auth,
        BackendFactory(backend),
        Arc::new(AtomicUsize::new(0)),
        LoginEndedReports::none(),
        shutdown.clone(),
    ));
    let (client_tx, mut client_rx) = oneshot::channel();
    let summary = Arc::new(Mutex::new(Summary::default()));
    let raw_budget = Budget::new(RAW_LIMIT);
    let login = rand::random();
    let mut worker = tokio::spawn(work(
        Bootstrap {
            addr,
            server_pub: server_key.public,
            client_priv: client_key.private,
            login,
        },
        owner_rx,
        client_tx,
        summary.clone(),
        raw_budget.clone(),
    ));
    let result = tokio::select! {
        result=&mut worker=>Some(result),
        _=term.recv()=>None,
        _=interrupt.recv()=>None,
        _=tokio::time::sleep(Duration::from_secs(30))=>None,
    };
    let mut failure = None;
    let mut finished = None;
    match result {
        Some(Ok(Ok(output))) => finished = Some(output),
        Some(Ok(Err(error))) => failure = Some(error),
        Some(Err(_)) => failure = Some("functional task panic/cancellation".into()),
        None => {
            worker.abort();
            let _ = worker.await;
            failure = Some("functional deadline or signal".into());
        }
    }
    // Keep the actual client and server owners until their joins settle. There
    // is no timed task/JoinHandle drop or process-group signalling here.
    let client = client_rx.try_recv().ok();
    let mut cleanup_overrun = false;
    let mut driver_ok = false;
    if let Some(client) = client.as_ref() {
        let close = client.clone();
        let mut close_task = tokio::task::spawn_blocking(move || close.close());
        let joined = tokio::select! {
            result=&mut close_task=>result,
            _=tokio::time::sleep(Duration::from_secs(120))=>{
                cleanup_overrun = true;
                println!("{}",serde_json::json!({"phase":"driver-cleanup-overrun","ok":false,"custody_retained":true}));
                close_task.await
            }
        };
        driver_ok = joined.is_ok();
        if !driver_ok {
            failure = Some("driver close task panic".into());
        }
    }
    if let Some(output) = finished.as_mut() {
        if finish_receipts(output).is_err() {
            failure = Some("sealed callback receipt failure".into());
        }
        output.progress.summary.raw_processed = output.ledger.processed_bytes;
        *summary.lock().unwrap() = output.progress.summary.clone();
    }
    drop(finished);
    shutdown.request();
    let mut manager = manager;
    let manager_result = tokio::select! {
        result=&mut manager=>result,
        _=tokio::time::sleep(Duration::from_secs(120))=>{
            cleanup_overrun = true;
            println!("{}",serde_json::json!({"phase":"cleanup-overrun","ok":false,"custody_retained":true}));
            manager.await
        }
    };
    if cleanup_overrun {
        failure = Some("cleanup exceeded grace; custody retained until settlement".into());
    }
    let manager_ok = matches!(manager_result, Ok(Ok(())));
    if !manager_ok {
        failure = Some("manager cleanup task failure".into());
    }
    let mut snapshot = registry.cleanup_snapshot();
    let settled = |value: Option<transport::channel_open::CleanupSnapshot>| {
        value.is_some_and(|s| {
            s.healthy_pending_opens == 0
                && s.canceled_opens == 0
                && s.retiring_channels == 0
                && s.unique_cleanup_debt == 0
                && !s.leader_unconfirmed
                && !s.cleanup_unconfirmed
                && !s.observation_panicked
        })
    };
    if !driver_ok || !manager_ok || !settled(snapshot) {
        println!(
            "{}",
            serde_json::json!({"phase":"cleanup-hold","ok":false,"custody_retained":true})
        );
        // Unknown physical cleanup is not converted into success or abandoned
        // when a watchdog expires. The owned external supervisor stays owner.
        while !driver_ok || !manager_ok || !settled(snapshot) {
            tokio::time::sleep(Duration::from_secs(1)).await;
            snapshot = registry.cleanup_snapshot();
        }
    }
    if raw_budget.used() != 0 {
        failure = Some("raw chunk ownership remains after cleanup".into());
    }
    let summary = summary.lock().unwrap().clone();
    println!(
        "{}",
        serde_json::json!({"phase":"complete","ok":failure.is_none(),"summary":summary,"raw_bytes_retained":raw_budget.used(),"driver_joined":driver_ok,"manager_joined":manager_ok,"registered_cleanup_settled":settled(snapshot),"producer_completion_before_release":"unobserved","applied_gap_model_qualified":false,"error":failure})
    );
    if failure.is_some() {
        Err("functional qualification failed; retain complete output".into())
    } else {
        Ok(())
    }
}
fn entry() -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 || args[1] != "--run-owned-functional" {
        return Err("requires --run-owned-functional OWNED_ROOT; no runtime by default".into());
    }
    let root = std::fs::canonicalize(&args[2]).map_err(|_| "owned root missing")?;
    for path in [
        root.clone(),
        root.join("home"),
        root.join("config"),
        root.join("cache"),
        root.join("tmp"),
    ] {
        let meta = std::fs::symlink_metadata(&path).map_err(|_| "owned state directory missing")?;
        if !meta.is_dir()
            || meta.file_type().is_symlink()
            || meta.uid() != nix::unistd::getuid().as_raw()
            || meta.permissions().mode() & 0o777 != 0o700
        {
            return Err("owned directories require real current-user0700".into());
        }
    }
    for (name, child) in [
        ("HOME", "home"),
        ("XDG_CONFIG_HOME", "config"),
        ("XDG_CACHE_HOME", "cache"),
        ("TMPDIR", "tmp"),
    ] {
        if std::env::var_os(name).map(std::path::PathBuf::from) != Some(root.join(child)) {
            return Err("isolated state environment mismatch".into());
        }
    }
    if std::env::var("HISTFILE").as_deref() != Ok("/dev/null")
        || std::env::var("SHELL").as_deref() != Ok("/bin/sh")
        || [
            "ENV",
            "BASH_ENV",
            "PYTHONPATH",
            "PYTHONHOME",
            "SSH_AUTH_SOCK",
        ]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
    {
        return Err("owned shell/Python environment not isolated".into());
    }
    if !std::env::current_dir()
        .map_err(|_| "cwd unavailable")?
        .starts_with(&root)
    {
        return Err("fixture cwd must be owned".into());
    }
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .map_err(|_| "fixture runtime setup")?
        .block_on(owned_run())
}
fn main() {
    if let Err(error) = entry() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod framed_tests {
    use super::*;
    use transport::channel::{encode_server, ServerRecord, CONTROL_STREAM};
    use transport::channel_geometry::{ChannelInstance, GeometryOutcome, GeometryRecord};
    use transport::shell_frame::{encode_shell, ShellRecord};

    #[test]
    fn qualification305_fragmented_geometry_data_and_early_exit_keep_raw_accounting() {
        let sink: Sink = Box::new(|_, _| Ok(()));
        let mut session = Session::new(QshSubstrate::new(sink));
        let ch = session.open_shell(80, 24).unwrap();
        let budget = Budget::new(1024);
        let mut ledger = Ledger::default();
        let mut consumed = Vec::new();
        let mut events = Vec::new();
        let (geometry_len, data_len);
        {
            let mut deliver = |raw: Raw| {
                ledger
                    .process(
                        raw,
                        |stream, bytes| {
                            events.extend(session.on_bytes(stream, bytes));
                            Ok(())
                        },
                        |stream, n| {
                            if stream >= transport::channel::FIRST_CHANNEL_STREAM {
                                consumed.push(n);
                            }
                        },
                    )
                    .unwrap()
            };
            let opened = encode_server(&ServerRecord::Opened { stream: ch });
            deliver(budget.chunk(CONTROL_STREAM, 0, opened).ok().unwrap());
            let geometry = encode_shell(&ShellRecord::Geometry(GeometryRecord {
                instance: ChannelInstance::new(1).unwrap(),
                request_id: 0,
                outcome: GeometryOutcome::Established,
                cols: 80,
                rows: 24,
            }))
            .unwrap();
            for (i, fragment) in geometry.chunks(3).enumerate() {
                deliver(budget.chunk(ch, i as u64, fragment.to_vec()).ok().unwrap());
            }
            let next = geometry.len().div_ceil(3) as u64;
            let data = encode_shell(&ShellRecord::Data(b"tail".to_vec())).unwrap();
            deliver(budget.chunk(ch, next, data[..6].to_vec()).ok().unwrap());
            deliver(
                budget
                    .chunk(
                        CONTROL_STREAM,
                        1,
                        encode_server(&ServerRecord::Exit {
                            stream: ch,
                            code: 0,
                        }),
                    )
                    .ok()
                    .unwrap(),
            );
            // The real ordered decoder must retain its partial channel deframer.
            deliver(budget.chunk(ch, next + 1, data[6..].to_vec()).ok().unwrap());
            geometry_len = geometry.len();
            data_len = data.len();
        }
        let tail = events
            .iter()
            .position(|e| matches!(e,SessionEvent::Data{bytes,..} if bytes==b"tail"))
            .unwrap();
        let exit = events
            .iter()
            .position(|e| matches!(e, SessionEvent::Exit { code: 0, .. }))
            .unwrap();
        assert!(tail < exit);
        assert_eq!(
            consumed.iter().sum::<usize>(),
            geometry_len + data_len,
            "raw framed channel bytes, no double CONTROL consumption"
        );
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(test)]
mod observation_phase_tests {
    use super::*;
    #[test]
    fn qualification305_intentional_exit_retires_observer_without_false_failure() {
        let registration = transport::qualification305::Registration {
            login: [12; 16],
            attachment: transport::session_manager::AttachmentContext {
                session_id: 91,
                generation: 4,
                features: Features::SUPPORTED,
            },
            stream: 19,
            instance: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
        };
        let (scope, report) = transport::qualification305::Scope::register(registration).unwrap();
        let mut scope = Some(scope);
        let mut reports = Some(report);
        end_observation(&mut scope, &mut reports);
        drop(scope.take()); // Simulate normal source retirement racing client Exit.
        let mut pending = Box::pin(next_report(&mut reports));
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        let disabled = pending.as_mut().poll(&mut cx).is_pending();
        drop(pending);
        drop(reports);
        assert!(
            disabled,
            "normal terminal retirement must not remain a failing report arm"
        );
        let (early_scope, mut early_reports) =
            transport::qualification305::Scope::register(registration).unwrap();
        drop(early_scope);
        let mut pending = Box::pin(early_reports.changed());
        assert!(
            matches!(pending.as_mut().poll(&mut cx),std::task::Poll::Ready(Some(sample)) if sample.retired),
            "unplanned early retirement must remain visible"
        );
    }
}

#[cfg(test)]
mod marker_tests {
    use super::*;
    fn progress() -> Progress {
        Progress {
            bulk: 16,
            echo: 17,
            screen: 18,
            summary: Summary {
                released: true,
                release_sequence: 1,
                credit_recovered_sequence: 2,
                ..Default::default()
            },
            bulk_hash: Sha256::new(),
            echo_buffer: Vec::new(),
            terminal: terminal::TerminalCore::new(80, 24),
        }
    }
    #[test]
    fn qualification305_screen_exit_requires_current_marker_not_erased_history() {
        let mut positive = progress();
        positive
            .events(vec![
                SessionEvent::Data {
                    ch: 18,
                    bytes: b"\x1b[2J\x1b[HQSH305-FINAL".to_vec(),
                },
                SessionEvent::Exit { ch: 18, code: 0 },
            ])
            .unwrap();
        assert!(positive.summary.screen_exited);
        let mut erased = progress();
        erased
            .events(vec![SessionEvent::Data {
                ch: 18,
                bytes: b"\x1b[2J\x1b[HQSH305-FINAL".to_vec(),
            }])
            .unwrap();
        assert!(erased.summary.final_state_marker);
        erased
            .events(vec![SessionEvent::Data {
                ch: 18,
                bytes: b"\x1b[2J\x1b[HERASED".to_vec(),
            }])
            .unwrap();
        assert!(
            erased
                .events(vec![SessionEvent::Exit { ch: 18, code: 0 }])
                .is_err(),
            "a past marker cannot certify the final terminal state"
        );
    }
}

#[cfg(test)]
mod failure_controls {
    use super::*;
    #[test]
    fn qualification305_callback_overflow_is_sticky_bounded_and_wakes() {
        let (tx, mut rx) = mpsc::channel(1);
        let budget = Budget::new(32);
        let mailbox = Mailbox {
            tx,
            budget: budget.clone(),
            sequence: std::array::from_fn(|_| AtomicU64::new(0)),
            failed: AtomicBool::new(false),
            fault: Notify::new(),
        };
        mailbox.on_bytes(18, vec![1; 3]);
        mailbox.on_bytes(18, vec![2; 4]);
        assert!(mailbox.failed.load(Ordering::Acquire));
        assert_eq!(
            budget.used(),
            3,
            "rejected original owner is refunded, queued owner remains charged"
        );
        let mut wake = Box::pin(mailbox.fault.notified());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(wake.as_mut().poll(&mut cx).is_ready());
        drop(rx.try_recv().unwrap());
        assert_eq!(budget.used(), 0);
    }
    #[tokio::test]
    async fn qualification305_cancellation_reaps_task_and_refunds_held_chunks() {
        let budget = Budget::new(32);
        let mut held = Hold::new(18, 32, 4);
        assert!(held
            .push(budget.chunk(18, 0, vec![1; 3]).ok().unwrap())
            .is_ok());
        let (ready_tx, ready_rx) = oneshot::channel();
        let worker = tokio::spawn(async move {
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
            drop(held);
        });
        tokio::time::timeout(Duration::from_secs(1), ready_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(budget.used(), 3);
        worker.abort();
        let joined = tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .unwrap();
        assert!(joined.unwrap_err().is_cancelled());
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(test)]
mod finish_tests {
    use super::*;
    fn output() -> Finished {
        let (tx, receiver) = mpsc::channel(1);
        let mailbox = Arc::new(Mailbox {
            tx,
            budget: Budget::new(100),
            sequence: std::array::from_fn(|_| AtomicU64::new(0)),
            failed: AtomicBool::new(false),
            fault: Notify::new(),
        });
        let sink: Sink = Box::new(|_, _| Ok(()));
        Finished {
            session: Session::new(QshSubstrate::new(sink)),
            progress: Progress {
                bulk: 16,
                echo: 17,
                screen: 18,
                summary: Default::default(),
                bulk_hash: Sha256::new(),
                echo_buffer: Vec::new(),
                terminal: terminal::TerminalCore::new(80, 24),
            },
            receiver,
            ledger: Ledger::default(),
            mailbox,
        }
    }
    #[test]
    fn qualification305_finish_rejects_sticky_postwork_callback_overflow() {
        let mut output = output();
        output.mailbox.publish(Incoming::State(LinkState::Closed));
        output
            .mailbox
            .on_bytes(transport::channel::CONTROL_STREAM, vec![9]);
        assert!(output.mailbox.failed.load(Ordering::Acquire));
        assert!(
            finish_receipts(&mut output).is_err(),
            "expectedClosed alone cannot mask late callback overflow"
        );
    }
    #[test]
    fn qualification305_finish_accepts_expected_close_but_rejects_late_fault() {
        let mut output = output();
        output.mailbox.publish(Incoming::State(LinkState::Closed));
        finish_receipts(&mut output).unwrap();
        output.mailbox.publish(Incoming::Fault);
        assert!(
            finish_receipts(&mut output).is_err(),
            "terminal callbacks cannot be ignored after work returns"
        );
    }
}

#[cfg(test)]
mod recovery_observation_tests {
    use super::*;
    #[test]
    fn qualification305_driver_credit_recovery_requires_new_postrelease_sample() {
        let mut summary = Summary {
            blocked_sequence: 5,
            release_sequence: 7,
            ..Default::default()
        };
        let positive = transport::qualification305::Snapshot {
            values_available: true,
            valid: true,
            sequence: 8,
            credit_remaining: Some(1),
            ..Default::default()
        };
        record_observation(&mut summary, positive);
        assert_eq!(
            summary.credit_recovered_sequence, 0,
            "prerelease positive credit is not recovery"
        );
        summary.released = true;
        for sample in [
            transport::qualification305::Snapshot {
                sequence: 7,
                ..positive
            },
            transport::qualification305::Snapshot {
                credit_remaining: None,
                ..positive
            },
            transport::qualification305::Snapshot {
                credit_remaining: Some(0),
                ..positive
            },
            transport::qualification305::Snapshot {
                valid: false,
                ..positive
            },
            transport::qualification305::Snapshot {
                retired: true,
                ..positive
            },
            transport::qualification305::Snapshot {
                values_available: false,
                ..positive
            },
        ] {
            record_observation(&mut summary, sample);
            assert_eq!(summary.credit_recovered_sequence, 0);
        }
        record_observation(&mut summary, positive);
        assert_eq!(
            summary.credit_recovered_sequence, 8,
            "must observe actual returned remote credit"
        );
    }
}

#[cfg(test)]
mod producer_ready_tests {
    use super::*;
    #[test]
    fn qualification305_ready_uses_current_model_not_echoed_command_or_past_marker() {
        let mut p = Progress {
            bulk: 16,
            echo: 17,
            screen: 18,
            summary: Default::default(),
            bulk_hash: Sha256::new(),
            echo_buffer: Vec::new(),
            terminal: terminal::TerminalCore::new(80, 24),
        };
        p.events(vec![SessionEvent::Data {
            ch: 18,
            bytes: SCREEN_COMMAND.to_vec(),
        }])
        .unwrap();
        assert!(!p.summary.producer_ready);
        p.events(vec![SessionEvent::Data {
            ch: 18,
            bytes: b"\x1b[2J\x1b[HQSH305-READY\r\n".to_vec(),
        }])
        .unwrap();
        assert!(p.summary.producer_ready);
        p.events(vec![SessionEvent::Data {
            ch: 18,
            bytes: b"\x1b[2J\x1b[HERASED".to_vec(),
        }])
        .unwrap();
        assert!(!p.summary.producer_ready);
    }
}
