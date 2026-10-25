//! Daemonization of the `transport-ensure` subcommand -- a self-installing,
//! SELF-DAEMONIZING server for the NEW transport (Noise over UDP,
//! `transport::Connection`), that survives the SSH `exec` closing.
//!
//! Division of responsibilities with `main.rs`:
//! - `main.rs::run_transport_ensure` (parent, BEFORE the fork) -- argument
//!   parsing, polling the control socket, the reuse/replace/become
//!   decision (which live-adds the client key via `ADD-CLIENT` on reuse, or
//!   seeds the initial in-memory allowlist via [`build_server_allowlist`] on
//!   become), synchronous socket binding, and printing `TRANSPORT-READY`,
//!   then `daemonize::start()`;
//! - this module (daemon, AFTER the fork) -- the daemon body
//!   [`run_transport_daemon`]: hands the already-bound sockets over to
//!   tokio, brings up the control server ([`serve_transport_control`]) and
//!   the multi-session router (`transport::SessionManager::serve`, driving a
//!   per-session [`crate::channel_backend::ChannelSessionBackend`]) in a
//!   single runtime, and lives until the router exits or a `STOP` arrives.
//!
//! The transport daemon's control protocol is the same line-based codec as
//! `control.rs`, but with its OWN set of verbs: `STATUS` (version
//! reconciliation via `version::reconcile`), `ADD-CLIENT` (live-add a
//! client Noise key to the IN-MEMORY allowlist ONLY -- the on-disk
//! allowlist was retired, so a daemon
//! restart forgets every key added after startup and the caller must
//! `ADD-CLIENT` again), and `STOP`. `ADD-PORT` does not apply here: the
//! new transport roams natively by changing the source address on a
//! SINGLE port (unlike qsh's port range) -- there is no live port
//! addition.
//!
//! **The live allowlist is honored WITHOUT a restart.** The daemon now serves
//! through `transport::SessionManager::serve`, which snapshots the SHARED
//! in-memory [`SharedAllowlist`] FRESH at every `HandshakeInit` (see
//! `crates/transport/src/session_manager.rs`). So an `ADD-CLIENT` on a live
//! daemon takes effect on the very next handshake, and a session's key is
//! scrubbed off the shared set when it ends (a self-cleaning allowlist)
//! -- no snapshot-at-startup limitation remains.
//!
//! [`run_serve_loop`] is the OTHER entry point into this module, used by the
//! `serve` command (`serve.rs`) instead of [`run_transport_daemon`]: just the
//! router on one socket, no control socket, no `daemonize`, no version
//! negotiation -- `serve` is not self-installing, so none of that applies.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
use tokio::sync::mpsc;

use transport::{BackendFactory, LoginEndedReports, ServerAuth, SessionBackend, SessionManager};

use crate::control::{self, ControlRequest, PortStatus, StatusResponse};
use crate::version::ReconcileAction;
use crate::{log, state};
use transport::channel_open::ChannelOpenRegistry;

/// The original deadline for an accepted control connection: request read,
/// control gate, command delivery, and response write all share this budget.
pub const CONTROL_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Shared in-memory set of trusted client Noise keys for the transport
/// daemon. The control server updates it on `ADD-CLIENT`; see the note
/// about the snapshot in the module documentation.
pub type SharedAllowlist = Arc<Mutex<Vec<[u8; 32]>>>;

/// `transport-ensure`'s decision when a daemon is already alive: reuse it
/// without forking, or become a daemon itself after all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnsureDecision {
    /// The daemon is up to date -- add the client via `ADD-CLIENT`, print
    /// `TRANSPORT-READY`, and exit without forking.
    Reuse,
    /// The daemon is stale (`Replace`) -- stop it and become the daemon ourselves.
    BecomeDaemon,
}

/// Maps the version reconciliation decision [`ReconcileAction`] to a
/// `transport-ensure` action. Mirrors the branching of `run_ensure` (old
/// qsh): an up-to-date or ambiguously-ordered daemon is reused, a strictly
/// stale one is replaced. The `KeepOldWarn` warning is printed separately
/// by the caller (`run_transport_ensure`); only reuse-vs-become matters
/// here.
pub fn decide_reuse(action: &ReconcileAction) -> EnsureDecision {
    match action {
        ReconcileAction::UpToDate | ReconcileAction::KeepOldWarn(_) => EnsureDecision::Reuse,
        ReconcileAction::Replace => EnsureDecision::BecomeDaemon,
    }
}

/// Builds the INITIAL server allowlist for starting the daemon: just this
/// call's supplied `--client-pubkey`, if any (the on-disk allowlist was
/// retired, so there is no disk set to
/// union with anymore). Wrapped as a function rather than inlined at the
/// call site so it stays independently unit-testable, matching the shape it
/// had before.
pub fn build_server_allowlist(client_pubkey: Option<[u8; 32]>) -> Vec<[u8; 32]> {
    client_pubkey.into_iter().collect()
}

/// Live-adds a client Noise key to a running daemon's allowlist: updates the
/// shared IN-MEMORY set [`SharedAllowlist`] only, if it isn't there already
/// (idempotent by key bytes). An earlier version retired
/// the on-disk half (`transport_state::add_client_pubkey`) -- a live
/// self-cleaning allowlist has no durable copy to keep in sync, so there is
/// nothing left to write to disk.
pub fn apply_add_client(shared: &SharedAllowlist, pubkey: [u8; 32]) {
    let mut guard = shared.lock().unwrap();
    if !guard.contains(&pubkey) {
        guard.push(pubkey);
    }
}

/// Builds the transport daemon's `STATUS` response: the same
/// [`StatusResponse`] shape as qsh (read by `version::reconcile` and the
/// `transport-ensure` client). `total_connections` is the LIVE active-session
/// count from the session manager's shared `Arc<AtomicUsize>` (see
/// `transport::session_manager`'s `ACTIVE_WINDOW` / `is_active`) -- a session
/// counts while its last authenticated receive is recent, so this reflects
/// devices actually attached right now, not merely ever-connected. A non-zero
/// count does not make replacing this daemon unsafe: replacing it does not
/// kill the tmux session itself -- it lives inside the tmux server, not the
/// daemon -- the channels simply reconnect to it, so a `Replace` is safe even
/// while sessions are merely parked (silent, not gone).
pub fn transport_status_response(
    ports: &[u16],
    total_connections: u64,
    cleanup_registry: Option<&ChannelOpenRegistry>,
) -> Result<StatusResponse> {
    Ok(StatusResponse {
        cleanup: cleanup_registry.map(|registry| {
            control::CleanupStatusResponse::from_snapshot(registry.try_cleanup_snapshot())
        }),
        version: state::QSHD_VERSION.to_string(),
        build: state::build_label(),
        checksum: state::self_checksum()?,
        ports: ports
            .iter()
            .map(|&port| PortStatus {
                port,
                default: true,
                connections: 0,
            })
            .collect(),
        total_connections,
        pid: std::process::id(),
    })
}

/// Transport daemon body AFTER the fork. Sockets already bound
/// synchronously (before the fork) are handed over to tokio, and the control
/// server and the multi-session router are brought up in a single runtime.
/// The function returns once the router exits or a `STOP` arrives; before
/// returning its ownership guard removes only its own published control socket,
/// so the next `transport-ensure` won't see a dead daemon
/// behind an existing file.
///
/// `server_priv` is the daemon's static Noise private key (the manager needs
/// it to run `Connection::accept` per handshake); `auth` carries the SHARED
/// in-memory allowlist the control server mutates on `ADD-CLIENT` and the
/// manager snapshots fresh at every handshake, plus the signature verifier
/// (none today: `transport-ensure` authenticates by allowlist); `backend` is
/// the per-session application driver
/// ([`crate::channel_backend::ChannelSessionBackend`]), which the manager
/// invokes ONCE per accepted session to run that session's channel protocol.
///
/// This module knows nothing about PTYs -- the backend owns all of that --
/// and `transport` knows nothing about what a channel is spent on (the
/// backend decides that, the router only demultiplexes).
///
/// `active_count` is shared with whoever else must see the live count --
/// the update service (`crate::update::DaemonSelf`) counts the sessions a
/// replacement would cut off from it; `control_gate` is how it keeps the
/// control socket still while it hands itself over.
///
/// IMPORTANT: `tokio::net::UdpSocket::from_std` requires a non-blocking
/// socket and is called already INSIDE the runtime (here, after the fork)
/// -- the tokio runtime does not survive `fork`, so both the socket and the
/// listener are bound with the std API before the fork, and "adopted" into
/// tokio here.
#[allow(clippy::too_many_arguments)]
pub async fn run_transport_daemon(
    socket: std::net::UdpSocket,
    server_priv: [u8; 32],
    auth: ServerAuth,
    backend: Arc<dyn SessionBackend>,
    listener: std::os::unix::net::UnixListener,
    _cleanup: control::SocketCleanup,
    ports: Vec<u16>,
    active_count: Arc<AtomicUsize>,
    control_gate: Arc<tokio::sync::RwLock<()>>,
    cleanup_registry: Option<Arc<ChannelOpenRegistry>>,
) -> Result<()> {
    run_transport_daemon_until_stop(
        socket,
        server_priv,
        auth,
        backend,
        listener,
        _cleanup,
        ports,
        active_count,
        control_gate,
        cleanup_registry,
        std::future::pending(),
    )
    .await
}

/// The executable owns its signal streams until this joined boundary returns.
#[allow(clippy::too_many_arguments)]
pub async fn run_transport_daemon_until_stop(
    socket: std::net::UdpSocket,
    server_priv: [u8; 32],
    auth: ServerAuth,
    backend: Arc<dyn SessionBackend>,
    listener: std::os::unix::net::UnixListener,
    _cleanup: control::SocketCleanup,
    ports: Vec<u16>,
    active_count: Arc<AtomicUsize>,
    control_gate: Arc<tokio::sync::RwLock<()>>,
    cleanup_registry: Option<Arc<ChannelOpenRegistry>>,
    stop: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    listener
        .set_nonblocking(true)
        .context("switching the control socket to non-blocking mode")?;
    let listener = tokio::net::UnixListener::from_std(listener)
        .context("adopting the control socket into tokio")?;

    run_transport_daemon_with_acceptor(
        socket,
        server_priv,
        auth,
        backend,
        listener,
        ports,
        active_count,
        control_gate,
        cleanup_registry,
        stop,
    )
    .await
}

/// Only errors that can clear while this listening socket remains valid are
/// retried. Unknown errors remain fatal rather than hiding a broken listener.
fn recoverable_control_accept(error: &std::io::Error) -> bool {
    use nix::libc;
    matches!(
        error.raw_os_error(),
        Some(libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM)
    ) || matches!(
        error.kind(),
        std::io::ErrorKind::Interrupted
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::ConnectionReset
    )
}

const CONTROL_ACCEPT_RETRY_INITIAL: Duration = Duration::from_millis(50);
const CONTROL_ACCEPT_RETRY_MAX: Duration = Duration::from_secs(1);
const CONTROL_ACCEPT_WARNING_INTERVAL: Duration = Duration::from_secs(5);

trait ControlAcceptor {
    fn accept(
        &mut self,
    ) -> impl std::future::Future<Output = std::io::Result<tokio::net::UnixStream>> + Send;
}

impl ControlAcceptor for tokio::net::UnixListener {
    async fn accept(&mut self) -> std::io::Result<tokio::net::UnixStream> {
        tokio::net::UnixListener::accept(self)
            .await
            .map(|(stream, _)| stream)
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_transport_daemon_with_acceptor(
    socket: std::net::UdpSocket,
    server_priv: [u8; 32],
    auth: ServerAuth,
    backend: Arc<dyn SessionBackend>,
    mut listener: impl ControlAcceptor,
    ports: Vec<u16>,
    active_count: Arc<AtomicUsize>,
    control_gate: Arc<tokio::sync::RwLock<()>>,
    cleanup_registry: Option<Arc<ChannelOpenRegistry>>,
    stop: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    // Sized here, where every socket the daemon serves passes -- one it
    // bound, and one an older binary handed over on an update (spec §4.12).
    transport::log_socket_buffers(&transport::tune_udp_buffers(&socket));
    socket
        .set_nonblocking(true)
        .context("switching the transport UDP socket to non-blocking mode")?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .context("adopting the transport UDP socket into tokio")?;

    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);

    log::info(
        "qshd",
        &format!(
            "transport daemon started pid={} ports={}",
            std::process::id(),
            ports.len()
        ),
    );

    // `active_count` is the shared active-session counter: ONE atomic,
    // updated incrementally by each session bridge in the manager, read by
    // the control server's STATUS/ADD-CLIENT/ADD-PORT replies
    // (`total_connections`) and by the update service.
    let shared_allowlist = auth.allowlist.clone();
    let mut handlers = tokio::task::JoinSet::new();
    // The multi-session router: one UDP socket, per-token sessions, the
    // per-session channel backend. It snapshots the allowlist fresh at every
    // handshake and scrubs an ended session's key off it.
    let shutdown = transport::Shutdown::default();
    let manager_loop = SessionManager::serve_until_shutdown(
        Arc::new(socket),
        server_priv,
        auth,
        BackendFactory(backend),
        active_count.clone(),
        LoginEndedReports::none(),
        shutdown.clone(),
    );
    tokio::pin!(manager_loop);

    tokio::pin!(stop);
    let mut trigger_error = None;
    let mut retry_at = None;
    let mut retry_delay = CONTROL_ACCEPT_RETRY_INITIAL;
    let mut last_accept_warning: Option<tokio::time::Instant> = None;
    let completed = loop {
        tokio::select! {
            biased;
            result = &mut stop => {
                trigger_error = result.err();
                break None;
            }
            _ = stop_rx.recv() => break None,
            result = &mut manager_loop => break Some(result),
            result = handlers.join_next(), if !handlers.is_empty() => {
                if let Some(Err(error)) = result {
                    // No accepted handler is deliberately aborted here. Panic
                    // can mean poisoned shared allowlist state; cancellation
                    // also loses an owned request. Fail closed and join all
                    // remaining handlers and sessions instead of isolating it.
                    trigger_error = Some(anyhow::Error::new(error).context("joining transport control task"));
                    break None;
                }
            }
            _ = async {
                if let Some(deadline) = retry_at {
                    tokio::time::sleep_until(deadline).await;
                }
            }, if retry_at.is_some() => retry_at = None,
            accepted = listener.accept(), if retry_at.is_none() => match accepted {
                Ok(stream) => {
                    retry_delay = CONTROL_ACCEPT_RETRY_INITIAL;
                    spawn_control_handler(&mut handlers, stream,
                        shared_allowlist.clone(), ports.clone(), stop_tx.clone(),
                        active_count.clone(), control_gate.clone(), cleanup_registry.clone());
                }
                Err(error) if recoverable_control_accept(&error) => {
                    let now = tokio::time::Instant::now();
                    if last_accept_warning.is_none_or(|last| now.duration_since(last) >= CONTROL_ACCEPT_WARNING_INTERVAL) {
                        log::warn("qshd", &format!("error accepting transport control connection; retrying: {error}"));
                        last_accept_warning = Some(now);
                    }
                    retry_at = Some(now + retry_delay);
                    retry_delay = (retry_delay * 2).min(CONTROL_ACCEPT_RETRY_MAX);
                }
                Err(error) => {
                    trigger_error = Some(anyhow::Error::new(error).context("accepting transport control connection"));
                    break None;
                }
            }
        }
    };
    // Close admission before requesting drain. Accepted STOP acknowledgments
    // retain their tasks and original deadlines while the manager joins.
    drop(listener);
    shutdown.request();
    let (manager_result, control_result) = match completed {
        Some(result) => (
            result,
            join_control_handlers(&mut handlers, &mut stop_rx).await,
        ),
        None => tokio::join!(
            &mut manager_loop,
            join_control_handlers(&mut handlers, &mut stop_rx)
        ),
    };
    manager_result.context("joining transport session shutdown")?;
    control_result?;
    if let Some(error) = trigger_error {
        return Err(error);
    }

    log::info("qshd", "transport daemon stopped");
    Ok(())
}

/// The `serve` loop: one UDP socket, the multi-session router, no control
/// socket and no version negotiation -- nothing installs this daemon, so
/// there is nothing to reconcile.
///
/// `login_ends` is the system mode's: its privileged helper reports a login
/// it has forgotten, and the router ends that login's session (see
/// `transport::LoginEndedReporter`). The personal mode has no helper to hear
/// it from and passes [`LoginEndedReports::none()`].
pub async fn run_serve_loop(
    socket: std::net::UdpSocket,
    server_priv: [u8; 32],
    auth: ServerAuth,
    backend: Arc<dyn SessionBackend>,
    login_ends: LoginEndedReports,
) -> Result<()> {
    run_serve_loop_until_stop(
        socket,
        server_priv,
        auth,
        backend,
        login_ends,
        std::future::pending(),
    )
    .await
}

pub(crate) async fn run_serve_loop_until_stop(
    socket: std::net::UdpSocket,
    server_priv: [u8; 32],
    auth: ServerAuth,
    backend: Arc<dyn SessionBackend>,
    login_ends: LoginEndedReports,
    stop: impl std::future::Future<Output = Result<()>>,
) -> Result<()> {
    let shutdown = transport::Shutdown::default();
    let manager = run_serve_loop_until_shutdown(
        socket,
        server_priv,
        auth,
        backend,
        login_ends,
        shutdown.clone(),
    );
    tokio::pin!(manager);
    tokio::pin!(stop);
    let (result, stop_error) = tokio::select! {
        biased;
        stopped = &mut stop => {
            shutdown.request();
            (manager.await, stopped.err())
        }
        result = &mut manager => (result, None),
    };
    result.map_err(|error| match error {
        ServeLoopError::Initialize(error) => error,
        ServeLoopError::Shutdown(error) => anyhow::Error::new(error),
    })?;
    if let Some(error) = stop_error {
        return Err(error);
    }
    Ok(())
}

/// Unix handlers are installed only at executable entry, after daemonization.
/// Keep this owner alive through the complete manager and control-task drain.
pub struct PersonalSignals {
    term: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

impl PersonalSignals {
    pub fn register() -> Result<Self> {
        use tokio::signal::unix::{signal, SignalKind};
        Ok(Self {
            term: signal(SignalKind::terminate()).context("registering personal daemon SIGTERM")?,
            interrupt: signal(SignalKind::interrupt())
                .context("registering personal daemon SIGINT")?,
        })
    }

    pub async fn requested(&mut self) -> Result<()> {
        let received = tokio::select! {
            received = self.term.recv() => received,
            received = self.interrupt.recv() => received,
        };
        received.context("personal daemon signal stream closed")
    }
}

/// Initialization failure is not a joined manager receipt.
#[derive(Debug)]
pub(crate) enum ServeLoopError {
    Initialize(anyhow::Error),
    Shutdown(transport::ShutdownError),
}

/// The system worker's owned manager boundary; cancellation is not completion.
pub(crate) async fn run_serve_loop_until_shutdown(
    socket: std::net::UdpSocket,
    server_priv: [u8; 32],
    auth: ServerAuth,
    backend: Arc<dyn SessionBackend>,
    login_ends: LoginEndedReports,
    shutdown: transport::Shutdown,
) -> std::result::Result<(), ServeLoopError> {
    transport::log_socket_buffers(&transport::tune_udp_buffers(&socket));
    socket.set_nonblocking(true).map_err(|error| {
        ServeLoopError::Initialize(
            anyhow::Error::new(error)
                .context("switching the worker UDP socket to non-blocking mode"),
        )
    })?;
    let socket = tokio::net::UdpSocket::from_std(socket).map_err(|error| {
        ServeLoopError::Initialize(
            anyhow::Error::new(error).context("adopting the worker UDP socket into tokio"),
        )
    })?;
    // Retained by the caller until this real lifecycle drain returns. An error
    // is not a producer-fence receipt, even though sibling tasks were joined.
    SessionManager::serve_until_shutdown(
        Arc::new(socket),
        server_priv,
        auth,
        BackendFactory(backend),
        Arc::new(AtomicUsize::new(0)),
        login_ends,
        shutdown,
    )
    .await
    .map_err(ServeLoopError::Shutdown)
}

/// The transport daemon's control server: an `accept()` loop, a separate
/// task per connection (one request line, one response, close). Shaped
/// like the qsh path's `control::serve_control`, but with transport verbs
/// (`STATUS`/`ADD-CLIENT`/`STOP`). A given connection's error is not
/// propagated outward -- it is logged and the loop continues, so one bad
/// connection doesn't take down the whole control socket.
pub async fn serve_transport_control(
    listener: tokio::net::UnixListener,
    shared_allowlist: SharedAllowlist,
    ports: Vec<u16>,
    stop_tx: mpsc::Sender<()>,
    active_count: Arc<AtomicUsize>,
    control_gate: Arc<tokio::sync::RwLock<()>>,
    cleanup_registry: Option<Arc<ChannelOpenRegistry>>,
) {
    let mut handlers = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => spawn_control_handler(&mut handlers, stream,
                    shared_allowlist.clone(), ports.clone(), stop_tx.clone(),
                    active_count.clone(), control_gate.clone(), cleanup_registry.clone()),
                Err(error) => log::warn("qshd", &format!("error accepting transport control connection: {error}")),
            },
            result = handlers.join_next(), if !handlers.is_empty() => {
                if let Some(Err(error)) = result {
                    log::warn("qshd", &format!("error joining transport control task: {error}"));
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_control_handler(
    handlers: &mut tokio::task::JoinSet<()>,
    stream: tokio::net::UnixStream,
    shared_allowlist: SharedAllowlist,
    ports: Vec<u16>,
    stop_tx: mpsc::Sender<()>,
    active_count: Arc<AtomicUsize>,
    control_gate: Arc<tokio::sync::RwLock<()>>,
    cleanup_registry: Option<Arc<ChannelOpenRegistry>>,
) {
    let deadline = tokio::time::Instant::now() + CONTROL_REQUEST_TIMEOUT;
    handlers.spawn(async move {
        if let Err(error) = handle_transport_control_connection(
            stream,
            shared_allowlist,
            ports,
            stop_tx,
            active_count,
            control_gate,
            cleanup_registry,
            deadline,
        )
        .await
        {
            log::warn(
                "qshd",
                &format!("error handling transport control connection: {error}"),
            );
        }
    });
}

async fn join_control_handlers(
    handlers: &mut tokio::task::JoinSet<()>,
    stop_rx: &mut mpsc::Receiver<()>,
) -> Result<()> {
    let mut failure = None;
    while !handlers.is_empty() {
        // A STOP admitted before listener closure still has a live delivery
        // endpoint. Drain its request while its task retains the ACK write.
        let result = tokio::select! {
            result = handlers.join_next() => result.expect("retained control task"),
            _ = stop_rx.recv() => continue,
        };
        if let Err(error) = result {
            log::warn(
                "qshd",
                &format!("error joining transport control task: {error}"),
            );
            if failure.is_none() {
                failure = Some(error);
            }
        }
    }
    match failure {
        Some(error) => Err(anyhow::Error::new(error).context("joining transport control tasks")),
        None => Ok(()),
    }
}

/// Serves a single connection to the transport daemon's control socket:
/// reads exactly one request line, executes it, and writes exactly one
/// response. `ADD-CLIENT` live-adds the key ([`apply_add_client`]) and
/// replies with the current status; `ADD-PORT` does not apply to the
/// transport (native roaming on a single port) -- we silently reply with
/// status, without binding anything.
///
/// The line is read before taking `control_gate` for reading, held until
/// the answer is
/// written: a client that connects and says nothing never holds the gate a
/// replacement waits for. Read, gate, delivery and reply share the original
/// accepted deadline.
#[allow(clippy::too_many_arguments)]
async fn handle_transport_control_connection(
    stream: tokio::net::UnixStream,
    shared_allowlist: SharedAllowlist,
    ports: Vec<u16>,
    stop_tx: mpsc::Sender<()>,
    active_count: Arc<AtomicUsize>,
    control_gate: Arc<tokio::sync::RwLock<()>>,
    cleanup_registry: Option<Arc<ChannelOpenRegistry>>,
    deadline: tokio::time::Instant,
) -> Result<()> {
    handle_transport_control_connection_with_peer_check(
        stream,
        shared_allowlist,
        ports,
        stop_tx,
        active_count,
        control_gate,
        cleanup_registry,
        deadline,
        |stream| {
            control::require_same_account(
                control::peer_uid(stream),
                nix::unistd::geteuid().as_raw(),
            )
        },
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_transport_control_connection_with_peer_check(
    stream: tokio::net::UnixStream,
    shared_allowlist: SharedAllowlist,
    ports: Vec<u16>,
    stop_tx: mpsc::Sender<()>,
    active_count: Arc<AtomicUsize>,
    control_gate: Arc<tokio::sync::RwLock<()>>,
    cleanup_registry: Option<Arc<ChannelOpenRegistry>>,
    deadline: tokio::time::Instant,
    check: impl FnOnce(&tokio::net::UnixStream) -> Result<()>,
) -> Result<()> {
    check(&stream)?;

    tokio::time::timeout_at(deadline, async {
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = tokio::io::BufReader::new(read_half);
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .await
            .context("reading the request from the transport control socket")?;
        let line = line.trim_end_matches('\n');

        // Held for the rest of the request: a replacement takes this for writing
        // before it snapshots the allowlist, so an `ADD-CLIENT` either lands
        // before the snapshot or waits -- and then meets the new process.
        let _gate = control_gate.read().await;

        let Some(request) = control::parse_request(line) else {
            // Unparseable request -- silently close the connection: the only
            // client is `transport-ensure` itself, not external input.
            return Ok(());
        };

        match request {
            ControlRequest::Status => {
                let response = transport_status_response(
                    &ports,
                    active_count.load(Ordering::SeqCst) as u64,
                    cleanup_registry.as_deref(),
                )?;
                write_half.write_all(response.to_line()?.as_bytes()).await?;
            }
            ControlRequest::AddClient(pubkey) => {
                apply_add_client(&shared_allowlist, pubkey);
                let response = transport_status_response(
                    &ports,
                    active_count.load(Ordering::SeqCst) as u64,
                    cleanup_registry.as_deref(),
                )?;
                write_half.write_all(response.to_line()?.as_bytes()).await?;
            }
            ControlRequest::AddPort(_) => {
                // The transport has no live port addition -- reply with status.
                let response = transport_status_response(
                    &ports,
                    active_count.load(Ordering::SeqCst) as u64,
                    cleanup_registry.as_deref(),
                )?;
                write_half.write_all(response.to_line()?.as_bytes()).await?;
            }
            ControlRequest::Stop => {
                stop_tx
                    .send(())
                    .await
                    .context("requesting transport shutdown")?;
                // This acknowledges accepted work. Joined daemon completion is
                // observed independently; owned cleanup may still be pending.
                write_half.write_all(b"{\"stopping\":true}\n").await?;
            }
        }

        Ok(())
    })
    .await
    .context("transport control request exceeded its accepted deadline")?
}

#[cfg(test)]
#[path = "transport_shutdown_tests.rs"]
mod shutdown_tests;

#[cfg(test)]
mod tests {
    use super::{
        apply_add_client, build_server_allowlist, decide_reuse, transport_status_response,
        EnsureDecision, SharedAllowlist,
    };
    use crate::version::ReconcileAction;
    use std::sync::{Arc, Mutex};

    #[test]
    fn decide_reuse_maps_reconcile_actions() {
        assert_eq!(
            decide_reuse(&ReconcileAction::UpToDate),
            EnsureDecision::Reuse
        );
        assert_eq!(
            decide_reuse(&ReconcileAction::KeepOldWarn("something".into())),
            EnsureDecision::Reuse
        );
        assert_eq!(
            decide_reuse(&ReconcileAction::Replace),
            EnsureDecision::BecomeDaemon
        );
    }

    #[test]
    fn build_server_allowlist_with_flag_is_just_that_key() {
        let key = [1u8; 32];
        assert_eq!(build_server_allowlist(Some(key)), vec![key]);
    }

    #[test]
    fn build_server_allowlist_without_flag_is_empty() {
        assert_eq!(build_server_allowlist(None), Vec::<[u8; 32]>::new());
    }

    /// `apply_add_client` updates the shared
    /// IN-MEMORY allowlist only -- no disk file is written (the function no
    /// longer even takes a directory to write one into).
    #[test]
    fn add_client_is_in_memory_only() {
        let shared: SharedAllowlist = Arc::new(Mutex::new(Vec::new()));
        apply_add_client(&shared, [5u8; 32]);
        assert_eq!(shared.lock().unwrap().clone(), vec![[5u8; 32]]);
    }

    #[test]
    fn apply_add_client_is_idempotent_in_memory() {
        let shared: SharedAllowlist = Arc::new(Mutex::new(Vec::new()));
        let key = [6u8; 32];

        apply_add_client(&shared, key);
        apply_add_client(&shared, key);

        // A repeat does not duplicate.
        assert_eq!(shared.lock().unwrap().clone(), vec![key]);
    }

    #[test]
    fn status_reports_given_active_count() {
        let status = transport_status_response(&[60000, 60999], 3, None).unwrap();
        assert_eq!(status.total_connections, 3);
        let reported: Vec<u16> = status.ports.iter().map(|p| p.port).collect();
        assert_eq!(reported, vec![60000, 60999]);
        assert_eq!(status.version, crate::state::QSHD_VERSION);
        assert_eq!(
            status.pid,
            std::process::id(),
            "STATUS names the process answering it"
        );
        let zero = transport_status_response(&[60000], 0, None).unwrap();
        assert_eq!(zero.total_connections, 0);
    }

    /// A control server on a socket of its own, with `gate` as its control
    /// gate. The server runs until the test's runtime ends.
    fn control_server(
        dir: &std::path::Path,
        gate: Arc<tokio::sync::RwLock<()>>,
    ) -> std::path::PathBuf {
        let path = dir.join("control.sock");
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        let (stop_tx, stop_rx) = tokio::sync::mpsc::channel(1);
        tokio::spawn(async move {
            // This fixture accepts one STOP without ending its control loop.
            let _receiver = stop_rx;
            super::serve_transport_control(
                listener,
                Arc::new(Mutex::new(Vec::new())),
                vec![1],
                stop_tx,
                Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                gate,
                None,
            )
            .await;
        });
        path
    }

    /// A client that connects and never finishes its request must not hold
    /// the gate a replacement takes for writing: the gate is taken only once
    /// the request has been read.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_silent_control_client_never_holds_the_gate() {
        let dir = tempfile::tempdir().unwrap();
        let gate = Arc::new(tokio::sync::RwLock::new(()));
        let path = control_server(dir.path(), Arc::clone(&gate));
        let _silent = tokio::net::UnixStream::connect(&path).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            gate.try_write().is_ok(),
            "a client that sent nothing holds nothing"
        );
    }

    /// A request that arrives while a replacement holds the gate for writing
    /// waits, and is answered once the gate is free again.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_request_waits_while_the_gate_is_held_for_writing() {
        let dir = tempfile::tempdir().unwrap();
        let gate = Arc::new(tokio::sync::RwLock::new(()));
        let path = control_server(dir.path(), Arc::clone(&gate));
        let held = gate.clone().write_owned().await;
        let ask = {
            let path = path.clone();
            tokio::task::spawn_blocking(move || {
                crate::control::client_request_with_timeout(
                    &path,
                    &crate::control::ControlRequest::Stop,
                    std::time::Duration::from_secs(10),
                )
                .unwrap()
            })
        };
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(!ask.is_finished(), "answered while the gate was held");
        drop(held);
        let reply = ask.await.unwrap();
        assert!(
            matches!(reply, crate::control::ControlReply::Answered(ref line) if line.contains("stopping")),
            "{reply:?}"
        );
    }

    /// A client that never sends its request line is dropped after
    /// [`super::CONTROL_REQUEST_TIMEOUT`] rather than kept forever.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_client_that_never_sends_a_request_is_dropped_in_time() {
        let dir = tempfile::tempdir().unwrap();
        let gate = Arc::new(tokio::sync::RwLock::new(()));
        let path = control_server(dir.path(), gate);
        let started = std::time::Instant::now();
        let read = tokio::task::spawn_blocking(move || {
            use std::io::Read;
            let mut stream = std::os::unix::net::UnixStream::connect(&path).unwrap();
            stream
                .set_read_timeout(Some(super::CONTROL_REQUEST_TIMEOUT * 3))
                .unwrap();
            let mut buf = [0u8; 16];
            stream.read(&mut buf).map_err(|e| e.kind())
        })
        .await
        .unwrap();
        assert_eq!(read, Ok(0), "the daemon closes a silent connection");
        assert!(started.elapsed() < super::CONTROL_REQUEST_TIMEOUT * 2);
    }
}

#[cfg(test)]
mod cleanup143_tests {
    use super::*;
    use crate::control::{CleanupPhase, ControlRequest};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use transport::channel_open::{OpenIdentity, OpenRequestSnapshot, SpawnCleanup};

    async fn ask(
        registry: &Arc<ChannelOpenRegistry>,
        allowlist: &SharedAllowlist,
        request: ControlRequest,
    ) -> StatusResponse {
        let (server, mut client) = tokio::net::UnixStream::pair().unwrap();
        let (stop, _receiver) = mpsc::channel(1);
        client
            .write_all(control::format_request(&request).as_bytes())
            .await
            .unwrap();
        handle_transport_control_connection(
            server,
            allowlist.clone(),
            vec![60000],
            stop,
            Arc::new(AtomicUsize::new(2)),
            Arc::new(tokio::sync::RwLock::new(())),
            Some(registry.clone()),
            tokio::time::Instant::now() + CONTROL_REQUEST_TIMEOUT,
        )
        .await
        .unwrap();
        let mut bytes = Vec::new();
        client.read_to_end(&mut bytes).await.unwrap();
        StatusResponse::from_line(std::str::from_utf8(&bytes).unwrap().trim_end()).unwrap()
    }

    struct ObservedLossWait {
        complete: Arc<std::sync::atomic::AtomicBool>,
        notifier: Arc<std::sync::Mutex<Option<transport::channel_server::ReapNotifier>>>,
    }
    impl transport::channel_server::ChannelWait for ObservedLossWait {
        fn poll_leader_status(&mut self) -> Option<transport::channel_server::LeaderStatus> {
            Some(if self.complete.load(Ordering::SeqCst) {
                transport::channel_server::LeaderStatus::Exited { code: None }
            } else {
                transport::channel_server::LeaderStatus::Unknown("owned fixture observation".into())
            })
        }
        fn poll_exit(&mut self) -> transport::channel_server::ChildStatus {
            if self.complete.load(Ordering::SeqCst) {
                transport::channel_server::ChildStatus::Reaped { code: None }
            } else {
                transport::channel_server::ChildStatus::Unknown("owned fixture cleanup".into())
            }
        }
        fn kill(&mut self) {
            assert!(
                self.complete.load(Ordering::SeqCst),
                "unconfirmed ownership must not signal"
            );
        }
        fn wait(self: Box<Self>) -> i32 {
            panic!("exclusive polling required")
        }
        fn cleanup_uninstalled(
            &mut self,
            authority: &transport::channel_open::CleanupAuthority<'_>,
        ) -> transport::channel_open::CleanupStatus {
            if self.complete.load(Ordering::SeqCst) {
                authority.reaped()
            } else {
                transport::channel_open::CleanupStatus::Unknown
            }
        }
        fn set_reap_notifier(&mut self, notifier: transport::channel_server::ReapNotifier) {
            *self.notifier.lock().unwrap() = Some(notifier);
        }
    }
    struct FixtureResize;
    impl transport::shell_server::ResizeHandle for FixtureResize {
        fn try_resize(&self, _: u16, _: u16) -> Result<(), String> {
            Ok(())
        }
    }
    struct ObservedLossSpawner {
        registry: Arc<ChannelOpenRegistry>,
        reader: std::sync::Mutex<Option<std::os::unix::net::UnixStream>>,
        complete: Arc<std::sync::atomic::AtomicBool>,
        notifier: Arc<std::sync::Mutex<Option<transport::channel_server::ReapNotifier>>>,
    }
    impl transport::channel_server::ChannelSpawner for ObservedLossSpawner {
        fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            _: &transport::auth::Principal,
            _: transport::session_manager::LoginId,
            _: &transport::channel::OpenRequest,
            _: Option<&str>,
            custody: &transport::channel_open::OpenCustody,
        ) -> Result<
            transport::channel_open::UninstalledChannel,
            transport::channel_open::SpawnFailure,
        > {
            Ok(custody
                .protect(
                    Box::new(ObservedLossWait {
                        complete: self.complete.clone(),
                        notifier: self.notifier.clone(),
                    }),
                    Box::new(transport::shell_server::NoScreen),
                )
                .finish(
                    Box::new(self.reader.lock().unwrap().take().unwrap()),
                    Box::new(std::io::sink()),
                    Box::new(FixtureResize),
                ))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cleanup143_real_control_projects_observed_active_loss_until_exact_completion() {
        use transport::session_manager::{
            AttachmentContext, SessionBackend, SessionInbound, SessionIo, StreamData,
        };
        let registry = ChannelOpenRegistry::new(Default::default());
        let (reader, peer) = std::os::unix::net::UnixStream::pair().unwrap();
        let complete = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let notifier = Arc::new(std::sync::Mutex::new(None));
        let spawner = Arc::new(ObservedLossSpawner {
            registry: registry.clone(),
            reader: std::sync::Mutex::new(Some(reader)),
            complete: complete.clone(),
            notifier: notifier.clone(),
        });
        let backend = crate::channel_backend::ChannelSessionBackend::with_spawner(spawner);
        let principal = transport::auth::Principal {
            uid: 1000,
            name: "fixture".into(),
            identity: "fixture".into(),
            incarnation: 0,
        };
        let (io, input, _output) = SessionIo::test_pair_for(principal, [5; 16]);
        let runner = tokio::spawn(backend.run(io));
        input
            .send(SessionInbound::Live(AttachmentContext {
                generation: 1,
                session_id: 21,
                features: transport::Features::CHANNEL_GEOMETRY,
            }))
            .await
            .unwrap();
        input
            .send(SessionInbound::Data(StreamData {
                stream_id: transport::channel::CONTROL_STREAM,
                data: transport::channel::encode_client(&transport::channel::ClientRecord::Open(
                    transport::channel::OpenRequest {
                        stream: 16,
                        kind: transport::channel::ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: false,
                        command: Vec::new(),
                    },
                )),
            }))
            .await
            .unwrap();
        let allowlist = Arc::new(std::sync::Mutex::new(Vec::new()));
        let unresolved = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let response = ask(&registry, &allowlist, ControlRequest::Status).await;
                if response.cleanup.as_ref().unwrap().phase == CleanupPhase::Unresolved {
                    break response;
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        // Release the exact owned fake receipt and I/O worker, including RED.
        complete.store(true, Ordering::SeqCst);
        let notification = notifier.lock().unwrap().clone();
        if let Some(notifier) = notification {
            notifier.notify();
        }
        peer.shutdown(std::net::Shutdown::Both).unwrap();
        drop(peer);
        drop(input);
        tokio::time::timeout(Duration::from_secs(5), runner)
            .await
            .unwrap()
            .unwrap();
        let response = unresolved.expect("an actual active loss must appear on STATUS");
        let counts = response.cleanup.unwrap().counts.unwrap();
        assert_eq!(counts.observed_unconfirmed_owners, 1);
        assert_eq!(
            counts.retiring_channels, 0,
            "must observe active loss before EOF/retirement"
        );
        assert_eq!(counts.unique_cleanup_debt, 1);
        assert!(counts.leader_unconfirmed);
        let settled = ask(&registry, &allowlist, ControlRequest::Status)
            .await
            .cleanup
            .unwrap();
        assert_eq!(settled.phase, CleanupPhase::Completed);
        assert_eq!(settled.counts.unwrap().unique_cleanup_debt, 0);
    }

    #[tokio::test]
    async fn cleanup143_real_control_uses_shared_registry_without_mutating_custody() {
        let backend = crate::channel_backend::ChannelSessionBackend::new(Arc::new(
            crate::screen_budget::ScreenBudget::new(Default::default()),
        ));
        let registry = backend.open_registry();
        assert!(Arc::ptr_eq(&registry, &backend.open_registry()));
        let session = registry.session().unwrap();
        let job = registry
            .try_reserve(
                &session,
                OpenRequestSnapshot {
                    owner: transport::auth::Principal {
                        uid: 1000,
                        name: "fixture".into(),
                        identity: "fixture".into(),
                        incarnation: 0,
                    },
                    login: [0; 16],
                    term: None,
                    request: transport::channel::OpenRequest {
                        stream: 16,
                        kind: transport::channel::ChannelKind::Shell,
                        cols: 80,
                        rows: 24,
                        screen: false,
                        command: Vec::new(),
                    },
                    identity: OpenIdentity {
                        session: session.id(),
                        instance: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
                        stream: 16,
                        generation: 0,
                        invalidation_epoch: 0,
                    },
                },
            )
            .unwrap();
        let allowlist = Arc::new(std::sync::Mutex::new(Vec::new()));
        for request in [
            ControlRequest::Status,
            ControlRequest::AddClient([42; 32]),
            ControlRequest::AddPort(60999),
            ControlRequest::Status,
        ] {
            let response = ask(&registry, &allowlist, request).await;
            assert_eq!(response.total_connections, 2);
            assert_eq!(response.ports.len(), 1);
            assert_eq!(response.ports[0].port, 60000);
            let cleanup = response.cleanup.unwrap();
            assert_eq!(cleanup.phase, CleanupPhase::Pending);
            let counts = cleanup.counts.unwrap();
            assert_eq!(counts.healthy_pending_opens, 1);
            assert_eq!(counts.unique_cleanup_debt, 0);
            assert!(!job.custody().is_cancelled());
            assert_eq!(session.occupied(), 1);
        }
        assert_eq!(*allowlist.lock().unwrap(), vec![[42; 32]]);
        job.cancel();
        let cleanup = ask(&registry, &allowlist, ControlRequest::Status)
            .await
            .cleanup
            .unwrap();
        assert_eq!(cleanup.phase, CleanupPhase::Pending);
        assert_eq!(cleanup.counts.unwrap().unique_cleanup_debt, 1);
        assert_eq!(session.occupied(), 1);
        let failure = job.custody().refuse_before_creation("owned fixture".into());
        let SpawnCleanup::NoChild(proof) = failure.cleanup else {
            unreachable!()
        };
        assert!(registry.finish_cleanup(job.id(), &proof));
        let cleanup = ask(&registry, &allowlist, ControlRequest::Status)
            .await
            .cleanup
            .unwrap();
        assert_eq!(cleanup.phase, CleanupPhase::Completed);
        assert_eq!(cleanup.counts.unwrap().unique_cleanup_debt, 0);
        assert_eq!(session.occupied(), 0);
    }
}

#[cfg(test)]
#[path = "transport_control_peer_tests.rs"]
mod peer_tests;
