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

/// How long a control-socket client has to send its one request line
/// before the connection is dropped.
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
pub fn transport_status_response(ports: &[u16], total_connections: u64) -> Result<StatusResponse> {
    Ok(StatusResponse {
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
) -> Result<()> {
    // Sized here, where every socket the daemon serves passes -- one it
    // bound, and one an older binary handed over on an update (spec §4.12).
    transport::log_socket_buffers(&transport::tune_udp_buffers(&socket));
    socket
        .set_nonblocking(true)
        .context("switching the transport UDP socket to non-blocking mode")?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .context("adopting the transport UDP socket into tokio")?;

    listener
        .set_nonblocking(true)
        .context("switching the control socket to non-blocking mode")?;
    let listener = tokio::net::UnixListener::from_std(listener)
        .context("adopting the control socket into tokio")?;

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
    let control_loop = serve_transport_control(
        listener,
        auth.allowlist.clone(),
        ports,
        stop_tx.clone(),
        active_count.clone(),
        control_gate,
    );
    // The multi-session router: one UDP socket, per-token sessions, the
    // per-session channel backend. It snapshots the allowlist fresh at every
    // handshake and scrubs an ended session's key off it.
    let shutdown = transport::Shutdown::default();
    let manager_loop = SessionManager::serve_until_shutdown(
        Arc::new(socket),
        server_priv,
        auth,
        BackendFactory(backend),
        active_count,
        LoginEndedReports::none(),
        shutdown.clone(),
    );
    tokio::pin!(manager_loop);

    let completed = tokio::select! {
        _ = control_loop => None,
        result = &mut manager_loop => Some(result),
        _ = stop_rx.recv() => None,
    };
    let result = match completed {
        Some(result) => result,
        None => {
            shutdown.request();
            manager_loop.await
        }
    };
    result.context("joining transport session shutdown")?;

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
    // Sized here, where every socket the daemon serves passes -- one it
    // bound, and one an older binary handed over on an update (spec §4.12).
    transport::log_socket_buffers(&transport::tune_udp_buffers(&socket));
    socket
        .set_nonblocking(true)
        .context("switching the UDP socket to non-blocking mode")?;
    let socket = Arc::new(
        tokio::net::UdpSocket::from_std(socket).context("adopting the UDP socket into tokio")?,
    );
    let active_count = Arc::new(AtomicUsize::new(0));
    SessionManager::serve(
        socket,
        server_priv,
        auth,
        BackendFactory(backend),
        active_count,
        login_ends,
    )
    .await;
    Ok(())
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
) {
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _addr)) => stream,
            Err(e) => {
                log::warn(
                    "qshd",
                    &format!("error accepting a connection to the transport control socket: {e}"),
                );
                continue;
            }
        };

        let shared_allowlist = shared_allowlist.clone();
        let ports = ports.clone();
        let stop_tx = stop_tx.clone();
        let active_count = active_count.clone();
        let control_gate = control_gate.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_transport_control_connection(
                stream,
                shared_allowlist,
                ports,
                stop_tx,
                active_count,
                control_gate,
            )
            .await
            {
                log::warn(
                    "qshd",
                    &format!("error handling a connection to the transport control socket: {e}"),
                );
            }
        });
    }
}

/// Serves a single connection to the transport daemon's control socket:
/// reads exactly one request line, executes it, and writes exactly one
/// response. `ADD-CLIENT` live-adds the key ([`apply_add_client`]) and
/// replies with the current status; `ADD-PORT` does not apply to the
/// transport (native roaming on a single port) -- we silently reply with
/// status, without binding anything.
///
/// The request is read first, within [`CONTROL_REQUEST_TIMEOUT`], and only
/// then is `control_gate` taken for reading, held until the answer is
/// written: a client that connects and says nothing never holds the gate a
/// replacement waits for.
async fn handle_transport_control_connection(
    stream: tokio::net::UnixStream,
    shared_allowlist: SharedAllowlist,
    ports: Vec<u16>,
    stop_tx: mpsc::Sender<()>,
    active_count: Arc<AtomicUsize>,
    control_gate: Arc<tokio::sync::RwLock<()>>,
) -> Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = tokio::io::BufReader::new(read_half);
    let mut line = String::new();
    tokio::time::timeout(CONTROL_REQUEST_TIMEOUT, reader.read_line(&mut line))
        .await
        .context("the transport control socket's client sent no request in time")?
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
            let response =
                transport_status_response(&ports, active_count.load(Ordering::SeqCst) as u64)?;
            write_half.write_all(response.to_line()?.as_bytes()).await?;
        }
        ControlRequest::AddClient(pubkey) => {
            apply_add_client(&shared_allowlist, pubkey);
            let response =
                transport_status_response(&ports, active_count.load(Ordering::SeqCst) as u64)?;
            write_half.write_all(response.to_line()?.as_bytes()).await?;
        }
        ControlRequest::AddPort(_) => {
            // The transport has no live port addition -- reply with status.
            let response =
                transport_status_response(&ports, active_count.load(Ordering::SeqCst) as u64)?;
            write_half.write_all(response.to_line()?.as_bytes()).await?;
        }
        ControlRequest::Stop => {
            write_half.write_all(b"{\"stopped\":true}\n").await?;
            // Ignore the send error: the receiver may have already closed
            // (the daemon is shutting down via another signal) -- that's
            // not a connection failure.
            let _ = stop_tx.send(()).await;
        }
    }

    Ok(())
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
        let status = transport_status_response(&[60000, 60999], 3).unwrap();
        assert_eq!(status.total_connections, 3);
        let reported: Vec<u16> = status.ports.iter().map(|p| p.port).collect();
        assert_eq!(reported, vec![60000, 60999]);
        assert_eq!(status.version, crate::state::QSHD_VERSION);
        assert_eq!(
            status.pid,
            std::process::id(),
            "STATUS names the process answering it"
        );
        let zero = transport_status_response(&[60000], 0).unwrap();
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
        // No receiver: a `STOP` is answered, and its send ignored.
        let (stop_tx, _) = tokio::sync::mpsc::channel(1);
        tokio::spawn(super::serve_transport_control(
            listener,
            Arc::new(Mutex::new(Vec::new())),
            vec![1],
            stop_tx,
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            gate,
        ));
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
            matches!(reply, crate::control::ControlReply::Answered(ref line) if line.contains("stopped")),
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
