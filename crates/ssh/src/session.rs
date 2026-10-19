//! The connection's own thread: a single-threaded tokio runtime running the
//! russh session, the channels, and a queue of commands from the session
//! above. Everything the session asks for is queued -- `ChannelSubstrate`
//! calls happen under the session's lock and must never wait.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc as std_mpsc, Arc, Mutex};

use client::channel::{ChannelId, ChannelSubstrate, ResizeSemantics, SubstrateEvent};
use russh::ChannelMsg;
use tokio::sync::{mpsc, Notify, OwnedSemaphorePermit, Semaphore};
use transport::channel::{ChannelKind, OpenRequest};

use crate::write_budget::WriteCredits;
use crate::{establish, runtime, SshAuthPlan, SshError, SshEvents, SshParams};

/// How often the connection thread checks whether russh's session ended
/// (keepalive failure, reset TCP, server disconnect).
const WATCHDOG: std::time::Duration = std::time::Duration::from_millis(500);

enum Command {
    Upload(crate::sftp::Upload),
    Open(OpenRequest, OwnedSemaphorePermit, knock::Cancel),
    Term(Arc<QueuedTerm>),
    Send(ChannelId, QueuedData),
    Resize(ChannelId, u16, u16),
    Close(ChannelId),
}

const MAX_QUEUED_BYTES: usize = 1024 * 1024;
const MAX_QUEUED_COMMANDS: usize = 256;

/// A reservation follows the bytes through both queues and the SSH write.
struct QueuedData {
    bytes: Vec<u8>,
    _permit: OwnedSemaphorePermit,
}

struct QueuedTerm {
    value: String,
    _permit: Option<OwnedSemaphorePermit>,
}

#[derive(Default)]
pub(crate) struct Stop {
    reason: Mutex<Option<String>>,
    changed: Notify,
}

impl Stop {
    pub(crate) fn request(&self, reason: String) {
        let mut requested = self.reason.lock().unwrap();
        if requested.is_none() {
            *requested = Some(reason);
            self.changed.notify_one();
        }
    }

    fn resource_limit(&self, reason: &str) {
        self.request(SshError::ResourceLimit(format!("resource limit: {reason}")).to_string());
    }
}

#[derive(Clone)]
struct Commands {
    upload: Arc<Semaphore>,
    tx: mpsc::Sender<Command>,
    bytes: Arc<Semaphore>,
    stop: Arc<Stop>,
}

fn commands() -> (Commands, mpsc::Receiver<Command>) {
    let (tx, rx) = mpsc::channel(MAX_QUEUED_COMMANDS);
    (
        Commands {
            upload: Arc::new(Semaphore::new(1)),
            tx,
            bytes: Arc::new(Semaphore::new(MAX_QUEUED_BYTES)),
            stop: Arc::new(Stop::default()),
        },
        rx,
    )
}

impl Commands {
    fn reserve(&self, count: usize) -> Option<OwnedSemaphorePermit> {
        if self.stop.reason.lock().unwrap().is_some() {
            return None;
        }
        if count <= MAX_QUEUED_BYTES {
            if let Ok(permit) = Arc::clone(&self.bytes).try_acquire_many_owned(count as u32) {
                return Some(permit);
            }
        }
        self.stop.resource_limit("queued SSH data exceeds 1 MiB");
        None
    }

    fn send(&self, command: Command) {
        if self.stop.reason.lock().unwrap().is_some() {
            return;
        }
        if let Err(mpsc::error::TrySendError::Full(_)) = self.tx.try_send(command) {
            self.stop.resource_limit("the SSH command queue is full");
        }
    }
}

/// The channels' side of the connection, for `ChannelSession`.
pub struct SshSubstrate {
    commands: Commands,
    cancel: knock::Cancel,
}

impl SshSubstrate {
    /// Use an explicit cancellation scope for commands on this connection.
    /// The default scope is the token supplied to `connect`. A separate scope
    /// permits owner-authorized cleanup after that original scope is cancelled.
    pub fn with_cancel(&self, cancel: &knock::Cancel) -> Self {
        Self {
            commands: self.commands.clone(),
            cancel: cancel.clone(),
        }
    }
}

impl ChannelSubstrate for SshSubstrate {
    fn protocol_failed(&mut self, error: client::channel::ChannelProtocolError) {
        self.commands
            .stop
            .request(format!("the SSH channel admission failed: {error:?}"));
    }
    fn resize_semantics(&self) -> ResizeSemantics {
        ResizeSemantics::Unconfirmed
    }
    fn open(&mut self, req: &OpenRequest) {
        if let Some(permit) = self.commands.reserve(req.command.len()) {
            self.commands
                .send(Command::Open(req.clone(), permit, self.cancel.clone()));
        }
    }
    fn announce_term(&mut self, term: &str) {
        if let Some(permit) = self.commands.reserve(term.len()) {
            self.commands.send(Command::Term(Arc::new(QueuedTerm {
                value: term.to_string(),
                _permit: Some(permit),
            })));
        }
    }
    fn send(&mut self, ch: ChannelId, data: &[u8]) {
        let Some(permit) = self.commands.reserve(data.len()) else {
            return;
        };
        self.commands.send(Command::Send(
            ch,
            QueuedData {
                bytes: data.to_vec(),
                _permit: permit,
            },
        ));
    }
    fn resize(&mut self, ch: ChannelId, cols: u16, rows: u16) {
        self.commands.send(Command::Resize(ch, cols, rows));
    }
    fn close(&mut self, ch: ChannelId) {
        self.commands.send(Command::Close(ch));
    }
    /// SSH delivers channel events through `SshEvents`, never as raw
    /// stream bytes -- there is no framing to decode.
    fn on_bytes(&mut self, _stream: u8, _bytes: &[u8]) -> Vec<SubstrateEvent> {
        Vec::new()
    }
}

/// The live connection: closing it and asking whether it still is.
pub struct SshConnection {
    commands: Commands,
    closed: Arc<AtomicBool>,
    host_key: crate::HostKeyInfo,
}

impl SshConnection {
    /// The server key from this connection's completed, verified key exchange.
    pub fn server_host_key(&self) -> crate::HostKeyInfo {
        self.host_key.clone()
    }

    /// Upload a new file on this validated connection. Existing files are refused.
    /// Blocks until the transfer completes, fails, times out, or is cancelled.
    pub fn upload_file(
        &self,
        absolute_path: &str,
        bytes: Arc<[u8]>,
        limits: crate::TransferLimits,
        progress: Arc<dyn crate::UploadProgress>,
        cancel: &knock::Cancel,
    ) -> Result<(), SshError> {
        if self.is_closed() || self.commands.stop.reason.lock().unwrap().is_some() {
            return Err(SshError::Protocol("the SSH connection is closed".into()));
        }
        let (upload, result) = crate::sftp::Upload::prepare(
            absolute_path,
            bytes,
            limits,
            progress,
            cancel,
            &self.commands.bytes,
            &self.commands.upload,
        )?;
        self.commands
            .tx
            .try_send(Command::Upload(upload))
            .map_err(|_| SshError::ResourceLimit("the SSH command queue is unavailable".into()))?;
        result.recv().unwrap_or_else(|_| {
            Err(SshError::Protocol(
                "the SSH connection ended during upload".into(),
            ))
        })
    }
    /// Disconnect. Idempotent; `on_closed` follows once.
    pub fn close(&self) {
        self.commands.stop.request("closed by the client".into());
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// Reports `on_closed` once, whoever notices first.
struct CloseOnce {
    events: Arc<dyn SshEvents>,
    closed: Arc<AtomicBool>,
}

impl CloseOnce {
    fn close(&self, reason: String) {
        if !self.closed.swap(true, Ordering::SeqCst) {
            self.events.on_closed(reason);
        }
    }
}

/// Blocking: returns once logged in, or with the reason it could not.
pub fn connect(
    params: SshParams,
    auth: SshAuthPlan,
    bind: Arc<dyn knock::SocketBind>,
    events: Arc<dyn SshEvents>,
    cancel: &knock::Cancel,
) -> Result<(SshConnection, SshSubstrate), SshError> {
    let (commands, rx) = commands();
    let (ready_tx, ready_rx) = std_mpsc::channel::<Result<crate::HostKeyInfo, SshError>>();
    let closed = Arc::new(AtomicBool::new(false));
    let cancel_for_thread = cancel.clone();
    let close_once = Arc::new(CloseOnce {
        events: Arc::clone(&events),
        closed: Arc::clone(&closed),
    });
    let stop = Arc::clone(&commands.stop);
    let budget = Arc::clone(&commands.bytes);
    let credits = Arc::new(WriteCredits::default());
    std::thread::Builder::new()
        .name("ssh-connection".into())
        .spawn(move || {
            runtime().block_on(async move {
                let handle = match establish(
                    &params,
                    auth,
                    bind,
                    events.as_ref(),
                    Arc::clone(&credits),
                    &cancel_for_thread,
                )
                .await
                {
                    Ok((h, host_key)) => {
                        if cancel_for_thread.is_cancelled() {
                            let _ = ready_tx.send(Err(SshError::Cancelled));
                            return;
                        }
                        if ready_tx.send(Ok(host_key)).is_err() {
                            return;
                        }
                        h
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                run(
                    Arc::new(handle),
                    rx,
                    events,
                    close_once,
                    RunLimits {
                        stop,
                        budget,
                        credits,
                        request_timeout: params.connect_timeout,
                    },
                )
                .await;
            })
        })
        .map_err(|e| {
            SshError::ResourceLimit(format!("could not start the connection thread: {e}"))
        })?;
    match ready_rx.recv() {
        Ok(Ok(host_key)) => {
            let connection = SshConnection {
                commands: commands.clone(),
                closed,
                host_key,
            };
            if cancel.is_cancelled() {
                connection.close();
                return Err(SshError::Cancelled);
            }
            Ok((
                connection,
                SshSubstrate {
                    commands,
                    cancel: cancel.clone(),
                },
            ))
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(SshError::Protocol(
            "the connection thread ended unexpectedly".into(),
        )),
    }
}

/// What a channel's writer task does, in the order it was asked.
enum Write {
    Data(QueuedData),
    Resize(u16, u16),
    Close,
}

/// Each open channel's writer queue. A write can wait on the channel's SSH
/// window for as long as the far side does not read, so writes never run in
/// the command loop: each channel has its own writer task, and the loop only
/// routes into its queue.
type Writers = Arc<Mutex<HashMap<ChannelId, mpsc::Sender<Write>>>>;

/// Queues `write` for `ch`, if it is open. Never waits.
fn route(writers: &Writers, ch: ChannelId, write: Write, stop: &Stop) {
    if let Some(queue) = writers.lock().unwrap().get(&ch) {
        if let Err(mpsc::error::TrySendError::Full(_)) = queue.try_send(write) {
            stop.resource_limit("the SSH channel write queue is full");
        }
    }
}

/// Drains one channel's queue in order. Ends after `Close`, or when the
/// queue's sender is gone (the channel closed). A write stuck on a full
/// window stays stuck until the runtime is dropped with the connection.
async fn write_channel(
    write: russh::ChannelWriteHalf<russh::client::Msg>,
    mut queue: mpsc::Receiver<Write>,
    credits: Arc<WriteCredits>,
    stop: Arc<Stop>,
    cancel: knock::Cancel,
) {
    while let Some(w) = queue.recv().await {
        if action_cancelled(&stop, &cancel) {
            return;
        }
        match w {
            Write::Data(data) => {
                let QueuedData { bytes, _permit } = data;
                if let Err(error) = write.data_bytes(credits.data(bytes, _permit)).await {
                    stop.request(format!("the SSH write failed: {error}"));
                    return;
                }
            }
            Write::Resize(cols, rows) => {
                if let Err(error) = write.window_change(cols.into(), rows.into(), 0, 0).await {
                    stop.request(format!("the SSH resize write failed: {error}"));
                    return;
                }
            }
            Write::Close => {
                let _ = write.close().await;
                return;
            }
        }
    }
}

/// How long `close()` lets the goodbye take before the connection is simply
/// dropped.
const DISCONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

struct RunLimits {
    stop: Arc<Stop>,
    budget: Arc<Semaphore>,
    credits: Arc<WriteCredits>,
    request_timeout: std::time::Duration,
}

/// The generation token stays authoritative after authentication, including
/// workers waiting for a remote channel-open response.
fn action_cancelled(stop: &Stop, cancel: &knock::Cancel) -> bool {
    cancel.is_cancelled() || stop.reason.lock().unwrap().is_some()
}

async fn run(
    handle: Arc<russh::client::Handle<crate::Handler>>,
    mut rx: mpsc::Receiver<Command>,
    events: Arc<dyn SshEvents>,
    close_once: Arc<CloseOnce>,
    limits: RunLimits,
) {
    let RunLimits {
        stop,
        budget,
        credits,
        request_timeout,
    } = limits;
    tokio::spawn(flush_credits(
        Arc::clone(&handle),
        Arc::clone(&credits),
        Arc::clone(&stop),
        request_timeout,
    ));
    let writers: Writers = Arc::new(Mutex::new(HashMap::new()));
    let mut term = Arc::new(QueuedTerm {
        value: "xterm-256color".into(),
        _permit: None,
    });
    let mut watchdog = tokio::time::interval(WATCHDOG);
    loop {
        tokio::select! {
            biased;
            _ = stop.changed.notified() => {
                let bye = handle.disconnect(russh::Disconnect::ByApplication, "", "en");
                let _ = tokio::time::timeout(DISCONNECT_TIMEOUT, bye).await;
                let reason = stop.reason.lock().unwrap().clone().unwrap_or_else(|| "closed by the client".into());
                close_once.close(reason);
                return;
            }
            cmd = rx.recv() => {
                match cmd {
                    None => {
                        let bye = handle.disconnect(russh::Disconnect::ByApplication, "", "en");
                        let _ = tokio::time::timeout(DISCONNECT_TIMEOUT, bye).await;
                        close_once.close("closed by the client".into());
                        return;
                    }
                    Some(Command::Term(t)) => term = t,
                    Some(Command::Upload(upload)) => {
                        tokio::spawn(upload.run(Arc::clone(&handle), Arc::clone(&credits), Arc::clone(&stop)));
                    }
                    Some(Command::Open(req, permit, cancel)) => {
                        tokio::spawn(open_channel(
                            Arc::clone(&handle),
                            Opening { req, term: term.clone(), permit, cancel },
                            Arc::clone(&events),
                            Arc::clone(&writers),
                            RunLimits { stop: Arc::clone(&stop), budget: Arc::clone(&budget), credits: Arc::clone(&credits), request_timeout },
                        ));
                    }
                    Some(Command::Send(ch, data)) => route(&writers, ch, Write::Data(data), &stop),
                    Some(Command::Resize(ch, cols, rows)) => route(&writers, ch, Write::Resize(cols, rows), &stop),
                    Some(Command::Close(ch)) => {
                        let queue = writers.lock().unwrap().remove(&ch);
                        if let Some(queue) = queue {
                            if let Err(mpsc::error::TrySendError::Full(_)) = queue.try_send(Write::Close) {
                                stop.resource_limit("the SSH channel write queue is full");
                            }
                        }
                    }
                }
            },
            _ = watchdog.tick() => {
                // Keepalive failures, a reset TCP connection and a server
                // that disconnected all end the russh session; its handle
                // then reports closed.
                if handle.is_closed() {
                    close_once.close("the connection was lost".into());
                    return;
                }
            }
        }
    }
}

async fn flush_credits(
    handle: Arc<russh::client::Handle<crate::Handler>>,
    credits: Arc<WriteCredits>,
    stop: Arc<Stop>,
    timeout: std::time::Duration,
) {
    loop {
        credits.changed.notified().await;
        if !credits.needs_flush() {
            continue;
        }
        // Pinned russh enqueues an expected reply even for
        // send_keepalive(false), desynchronizing subsequent replies. Use
        // one bounded ping instead; payload credits return at write flush,
        // independently of its reply, and only one worker request can wait.
        if !matches!(
            tokio::time::timeout(timeout, handle.send_ping()).await,
            Ok(Ok(()))
        ) {
            stop.request("the SSH write confirmation timed out or failed".into());
            return;
        }
    }
}

pub(crate) async fn confirm_requests(
    handle: &russh::client::Handle<crate::Handler>,
    credits: &WriteCredits,
    permits: Vec<OwnedSemaphorePermit>,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let result = match tokio::time::timeout(timeout, handle.send_ping()).await {
        Ok(Ok(())) if !handle.is_closed() => Ok(()),
        Ok(Ok(())) => Err("the SSH connection closed before its request was written".to_string()),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err("the SSH request write confirmation timed out".into()),
    };
    if result.is_err() {
        credits.hold_until_close(permits);
    }
    result
}

/// A pending channel request and its outgoing byte reservations.
struct Opening {
    req: OpenRequest,
    term: Arc<QueuedTerm>,
    permit: OwnedSemaphorePermit,
    cancel: knock::Cancel,
}

/// Opens one channel, then reads it until it closes: one `Opened` or
/// `Refused`, and after `Opened` exactly one `Exit`.
async fn open_channel(
    handle: Arc<russh::client::Handle<crate::Handler>>,
    opening: Opening,
    events: Arc<dyn SshEvents>,
    writers: Writers,
    limits: RunLimits,
) {
    let Opening {
        mut req,
        term,
        permit,
        cancel,
    } = opening;
    let RunLimits {
        stop,
        budget,
        credits,
        request_timeout,
    } = limits;
    let ch = req.stream;
    if action_cancelled(&stop, &cancel) {
        events.on_channel(SubstrateEvent::Refused {
            ch,
            reason: SshError::Cancelled.to_string(),
        });
        return;
    }
    let channel = match handle.channel_open_session().await {
        Ok(c) => c,
        Err(e) => {
            events.on_channel(SubstrateEvent::Refused {
                ch,
                reason: e.to_string(),
            });
            return;
        }
    };
    if action_cancelled(&stop, &cancel) {
        let _ = tokio::time::timeout(request_timeout, channel.close()).await;
        events.on_channel(SubstrateEvent::Refused {
            ch,
            reason: SshError::Cancelled.to_string(),
        });
        return;
    }
    let pty = req.cols > 0 && req.rows > 0;
    let mut control_permits = vec![permit];
    if pty {
        let copy = Arc::clone(&budget).try_acquire_many_owned(term.value.len() as u32);
        let Ok(copy) = copy else {
            stop.resource_limit("queued SSH PTY data exceeds 1 MiB");
            return;
        };
        control_permits.push(copy);
    }
    let requested = crate::with_cancel(
        async {
            if action_cancelled(&stop, &cancel) {
                return Err(russh::Error::Disconnect);
            }
            if pty {
                // Command PTYs carry machine-readable replies (notably tmux
                // control mode). Kernel echo can interleave input with those
                // replies, even in the middle of a protocol marker. Match qshd's
                // command PTYs while preserving interactive shell defaults.
                let modes: &[(russh::Pty, u32)] = match req.kind {
                    ChannelKind::Command => &[(russh::Pty::ECHO, 0), (russh::Pty::ECHONL, 0)],
                    ChannelKind::Shell => &[],
                };
                channel
                    .request_pty(
                        false,
                        &term.value,
                        req.cols.into(),
                        req.rows.into(),
                        0,
                        0,
                        modes,
                    )
                    .await?;
            }
            // PTY enqueueing can yield; recheck before the next remote action.
            if action_cancelled(&stop, &cancel) {
                return Err(russh::Error::Disconnect);
            }
            match req.kind {
                ChannelKind::Shell => channel.request_shell(false).await,
                ChannelKind::Command => channel.exec(false, std::mem::take(&mut req.command)).await,
            }
        },
        &cancel,
    )
    .await
    .map_err(|error| error.to_string())
    .and_then(|result| result.map_err(|error| error.to_string()));
    // Exec and PTY requests retain owned Vec/String values in russh's FIFO. A
    // keepalive reply (success OR failure) proves those requests were
    // written. This barrier is bounded; it adds no RTT to channel data.
    if let Err(error) = requested {
        credits.hold_until_close(control_permits);
        let reason = error.to_string();
        if cancel.is_cancelled() {
            let _ = tokio::time::timeout(request_timeout, channel.close()).await;
        } else {
            stop.request(reason.clone());
        }
        events.on_channel(SubstrateEvent::Refused { ch, reason });
        return;
    }
    let confirmation_handle = Arc::clone(&handle);
    let confirmation_credits = Arc::clone(&credits);
    let confirmation_stop = Arc::clone(&stop);
    tokio::spawn(async move {
        let result = confirm_requests(
            &confirmation_handle,
            &confirmation_credits,
            control_permits,
            request_timeout,
        )
        .await;
        drop(term);
        if let Err(reason) = result {
            confirmation_stop.request(reason);
        }
    });
    // Read immediately: awaiting the ping here could fill russh's incoming
    // channel queue and prevent it from processing that very ping reply.
    let (mut read, write) = channel.split();
    let (queue, queued) = mpsc::channel(MAX_QUEUED_COMMANDS);
    tokio::spawn(write_channel(
        write,
        queued,
        credits,
        Arc::clone(&stop),
        cancel,
    ));
    writers.lock().unwrap().insert(ch, queue.clone());
    events.on_channel(SubstrateEvent::Opened(ch));
    let mut code = -1;
    while let Some(msg) = read.wait().await {
        match msg {
            ChannelMsg::Data { data } => events.on_channel(SubstrateEvent::Data {
                ch,
                bytes: data.to_vec(),
            }),
            ChannelMsg::ExtendedData { data, ext } => {
                events.on_channel(SubstrateEvent::ExtendedData {
                    ch,
                    data_type: ext,
                    bytes: data.to_vec(),
                })
            }
            ChannelMsg::ExitStatus { exit_status } => code = exit_status as i32,
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    {
        // Only this channel's own queue: the stream id may already belong
        // to a newer channel opened after a close.
        let mut map = writers.lock().unwrap();
        if map.get(&ch).is_some_and(|q| q.same_channel(&queue)) {
            map.remove(&ch);
        }
    }
    events.on_channel(SubstrateEvent::Exit { ch, code });
}

#[cfg(test)]
mod tests {
    use super::*;

    struct WriteGate {
        blocked: AtomicBool,
        allowed_writes: std::sync::atomic::AtomicUsize,
        attempted: Notify,
        waker: Mutex<Option<std::task::Waker>>,
    }

    impl WriteGate {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                blocked: AtomicBool::new(false),
                allowed_writes: std::sync::atomic::AtomicUsize::new(0),
                attempted: Notify::new(),
                waker: Mutex::new(None),
            })
        }
        fn release(&self) {
            self.blocked.store(false, Ordering::SeqCst);
            if let Some(waker) = self.waker.lock().unwrap().take() {
                waker.wake();
            }
        }
    }

    struct GatedIo {
        stream: tokio::net::TcpStream,
        gate: Arc<WriteGate>,
    }
    impl tokio::io::AsyncRead for GatedIo {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
    impl tokio::io::AsyncWrite for GatedIo {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            if self.gate.blocked.load(Ordering::SeqCst)
                && self
                    .gate
                    .allowed_writes
                    .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                    .is_err()
            {
                *self.gate.waker.lock().unwrap() = Some(cx.waker().clone());
                self.gate.attempted.notify_one();
                return std::task::Poll::Pending;
            }
            std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.stream).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
        }
    }

    async fn gated_handle() -> (
        crate::test_support::TestSshd,
        Arc<russh::client::Handle<crate::Handler>>,
        Arc<WriteGate>,
        Arc<WriteCredits>,
    ) {
        use crate::test_support::{params, wire_of, SoftSigner, TestSshd};
        let signer = SoftSigner::random();
        let sshd = TestSshd::start(&[signer.authorized_line()]);
        let params = params(&sshd, vec![wire_of(&sshd.host_public_key_line())]);
        let gate = WriteGate::new();
        let credits = Arc::new(WriteCredits::default());
        let stream = tokio::net::TcpStream::connect(("127.0.0.1", sshd.port))
            .await
            .unwrap();
        let ended = Arc::new(crate::EndSlot::default());
        let handler = crate::Handler {
            known: params.known_host_keys.clone(),
            slot: Arc::new(crate::HostKeySlot::default()),
            ended: Arc::clone(&ended),
        };
        let mut handle = russh::client::connect_stream(
            Arc::new(russh::client::Config::default()),
            crate::write_budget::TrackedIo::new(
                GatedIo {
                    stream,
                    gate: Arc::clone(&gate),
                },
                Arc::clone(&credits),
            ),
            handler,
        )
        .await
        .unwrap();
        let mut login = crate::auth::Login {
            handle: &mut handle,
            username: &params.username,
            host: &params.host,
            step_timeout: params.connect_timeout,
            clock: crate::auth::PromptClock::default(),
            cancel: knock::Cancel::new(),
            ended,
        };
        crate::auth::authenticate(
            &mut login,
            SshAuthPlan::single(crate::AuthMethod::Signer(Arc::new(signer))),
        )
        .await
        .unwrap();
        let handle = Arc::new(handle);
        (sshd, handle, gate, credits)
    }

    #[test]
    fn client_early_output_failure_requests_bounded_connection_stop() {
        let (commands, _incoming) = commands();
        let stop = commands.stop.clone();
        let sub = SshSubstrate {
            commands,
            cancel: knock::Cancel::new(),
        };
        let mut session = client::channel::ChannelSession::new(sub);
        let ch = session.open_shell(80, 24).unwrap();
        let events = session.on_event(SubstrateEvent::Data {
            ch,
            bytes: vec![0; 65537],
        });
        assert!(matches!(
            events.as_slice(),
            [client::channel::SessionEvent::ProtocolFailure(_)]
        ));
        assert!(stop
            .reason
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|reason| reason.contains("EarlyOutputOverflow")));
    }

    #[test]
    fn resize_writer_failure_requests_one_real_connection_close() {
        runtime().block_on(async {
            let (_sshd, handle, _gate, credits) = gated_handle().await;
            let channel = handle.channel_open_session().await.unwrap();
            let (_read, write) = channel.split();
            handle
                .disconnect(russh::Disconnect::ByApplication, "test done", "")
                .await
                .unwrap();
            let mut handle = Arc::try_unwrap(handle).ok().expect("sole handle");
            let _ = tokio::time::timeout(std::time::Duration::from_secs(5), &mut handle)
                .await
                .unwrap();
            let stop = Arc::new(Stop::default());
            let (tx, rx) = mpsc::channel(2);
            tx.send(Write::Resize(100, 30)).await.unwrap();
            tx.send(Write::Resize(101, 31)).await.unwrap();
            drop(tx);
            write_channel(
                write,
                rx,
                credits.clone(),
                Arc::clone(&stop),
                knock::Cancel::new(),
            )
            .await;
            let reason = stop
                .reason
                .lock()
                .unwrap()
                .clone()
                .expect("window_change failure must stop the connection");
            assert!(reason.contains("SSH resize write failed"), "{reason}");
            let events = Arc::new(ChannelEvents::default());
            let close = Arc::new(CloseOnce {
                events: events.clone(),
                closed: Arc::new(AtomicBool::new(false)),
            });
            let (_commands, incoming) = commands();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                run(
                    Arc::new(handle),
                    incoming,
                    events.clone(),
                    close.clone(),
                    RunLimits {
                        stop,
                        budget: Arc::new(Semaphore::new(MAX_QUEUED_BYTES)),
                        credits,
                        request_timeout: std::time::Duration::from_secs(2),
                    },
                ),
            )
            .await
            .unwrap();
            close.close(reason);
            assert_eq!(events.closed_count.load(Ordering::SeqCst), 1);
            assert!(
                events.events.lock().unwrap().is_empty(),
                "no remote Geometry is invented"
            );
        });
    }

    #[test]
    fn blocked_transport_keeps_reservations_across_russh_queues_and_channels() {
        runtime().block_on(async {
            let (_sshd, handle, gate, credits) = gated_handle().await;
            let first = handle.channel_open_session().await.unwrap();
            let second = handle.channel_open_session().await.unwrap();
            first.exec(false, b"cat >/dev/null".to_vec()).await.unwrap();
            second
                .exec(false, b"cat >/dev/null".to_vec())
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(2), handle.send_ping())
                .await
                .unwrap()
                .unwrap();
            let first_id = first.id();
            let (_read_first, write_first) = first.split();
            let (_read_second, write_second) = second.split();
            let (first_tx, first_rx) = mpsc::channel(256);
            let (second_tx, second_rx) = mpsc::channel(256);
            let (commands, mut incoming) = commands();
            tokio::spawn(write_channel(
                write_first,
                first_rx,
                Arc::clone(&credits),
                Arc::clone(&commands.stop),
                knock::Cancel::new(),
            ));
            tokio::spawn(write_channel(
                write_second,
                second_rx,
                Arc::clone(&credits),
                Arc::clone(&commands.stop),
                knock::Cancel::new(),
            ));
            tokio::spawn(flush_credits(
                Arc::clone(&handle),
                Arc::clone(&credits),
                Arc::clone(&commands.stop),
                std::time::Duration::from_secs(2),
            ));
            let budget = Arc::clone(&commands.bytes);
            let stop = Arc::clone(&commands.stop);
            let mut sub = SshSubstrate {
                commands,
                cancel: knock::Cancel::new(),
            };
            gate.blocked.store(true, Ordering::SeqCst);
            for (index, channel) in [16, 17, 16, 17].into_iter().enumerate() {
                sub.send(channel, &vec![b'x'; 256 * 1024]);
                let Command::Send(ch, data) = incoming.try_recv().unwrap() else {
                    panic!("expected data")
                };
                let queue = if ch == 16 { &first_tx } else { &second_tx };
                queue
                    .send(Write::Data(data))
                    .await
                    .unwrap_or_else(|_| panic!("writer stopped"));
                if index == 0 {
                    tokio::time::timeout(
                        std::time::Duration::from_secs(2),
                        gate.attempted.notified(),
                    )
                    .await
                    .unwrap();
                }
            }
            for _ in 0..32 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                budget.available_permits(),
                0,
                "moving data into russh returned byte credits before transport write"
            );
            assert!(stop.reason.lock().unwrap().is_none());
            gate.release();
            let all = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                budget.acquire_many(1024 * 1024),
            )
            .await
            .unwrap()
            .unwrap();
            drop(all);
            // Keep the last Bytes owner beyond its already confirmed flush.
            // Dropping it must provoke another flush without new user input.
            let permit = Arc::clone(&budget)
                .try_acquire_many_owned(64 * 1024)
                .unwrap();
            let bytes = credits.data(vec![b'y'; 64 * 1024], permit);
            let late_owner = bytes.clone();
            handle.data(first_id, bytes).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(2), handle.send_ping())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(budget.available_permits(), 1024 * 1024 - 64 * 1024);
            drop(late_owner);
            let all = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                budget.acquire_many(1024 * 1024),
            )
            .await
            .expect("late owner credits waited forever for new input")
            .unwrap();
            drop(all);
        });
    }

    #[derive(Default)]
    struct ChannelEvents {
        events: Mutex<Vec<SubstrateEvent>>,
        closed_count: std::sync::atomic::AtomicUsize,
        changed: Notify,
    }
    impl SshEvents for ChannelEvents {
        fn on_channel(&self, event: SubstrateEvent) {
            self.events.lock().unwrap().push(event);
            self.changed.notify_one();
        }
        fn on_closed(&self, _: String) {
            self.closed_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn exec_and_pty_credits_wait_for_a_written_fifo_barrier() {
        runtime().block_on(async {
            let (_sshd, handle, gate, credits) = gated_handle().await;
            let (commands, _incoming) = commands();
            let events = Arc::new(ChannelEvents::default());
            let term_permit = commands.reserve(16 * 1024).unwrap();
            let command_permit = commands.reserve(128 * 1024).unwrap();
            let opening = Opening {
                req: OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Command,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: vec![b' '; 128 * 1024],
                },
                term: Arc::new(QueuedTerm {
                    value: "x".repeat(16 * 1024),
                    _permit: Some(term_permit),
                }),
                permit: command_permit,
                cancel: knock::Cancel::new(),
            };
            gate.allowed_writes.store(1, Ordering::SeqCst);
            gate.blocked.store(true, Ordering::SeqCst);
            tokio::spawn(open_channel(
                Arc::clone(&handle),
                opening,
                events.clone(),
                Arc::new(Mutex::new(HashMap::new())),
                RunLimits {
                    stop: Arc::clone(&commands.stop),
                    budget: Arc::clone(&commands.bytes),
                    credits,
                    request_timeout: std::time::Duration::from_secs(2),
                },
            ));
            tokio::time::timeout(std::time::Duration::from_secs(1), gate.attempted.notified())
                .await
                .unwrap();
            assert!(events
                .events
                .lock()
                .unwrap()
                .contains(&SubstrateEvent::Opened(16)));
            assert_eq!(commands.bytes.available_permits(), 1024 * 1024 - 160 * 1024);
            // Channel-open was allowed; the gate now blocks the next batch,
            // containing owned copies of PTY and exec requests in russh.
            gate.release();
            let all = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                commands.bytes.acquire_many(1024 * 1024),
            )
            .await
            .unwrap()
            .unwrap();
            drop(all);
            assert_eq!(commands.bytes.available_permits(), 1024 * 1024);
        });
    }

    #[test]
    fn a_silent_write_barrier_times_out_and_keeps_credits_until_close() {
        let budget = runtime().block_on(async {
            let (_sshd, handle, gate, credits) = gated_handle().await;
            // Open the channel before blocking transport, so the timer
            // specifically covers the request confirmation, not channel-open.
            let channel = handle.channel_open_session().await.unwrap();
            let (commands, _incoming) = commands();
            let permit = commands.reserve(4096).unwrap();
            gate.blocked.store(true, Ordering::SeqCst);
            channel.exec(false, vec![b' '; 4096]).await.unwrap();
            let result = confirm_requests(
                &handle,
                &credits,
                vec![permit],
                std::time::Duration::from_millis(50),
            )
            .await;
            assert!(result.unwrap_err().contains("timed out"));
            assert_eq!(commands.bytes.available_permits(), 1024 * 1024 - 4096);
            Arc::clone(&commands.bytes)
        });
        assert_eq!(
            budget.available_permits(),
            1024 * 1024,
            "teardown kept failed-request credits alive"
        );
    }

    #[test]
    fn explicit_close_bypasses_blocked_transport_without_prior_overflow() {
        let budget = runtime().block_on(async {
            let (_sshd, handle, gate, credits) = gated_handle().await;
            let channel = handle.channel_open_session().await.unwrap();
            channel
                .exec(false, b"cat >/dev/null".to_vec())
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(2), handle.send_ping())
                .await
                .unwrap()
                .unwrap();
            let (commands, incoming) = commands();
            let permit = commands.reserve(128 * 1024).unwrap();
            gate.blocked.store(true, Ordering::SeqCst);
            channel
                .data_bytes(credits.data(vec![b'x'; 128 * 1024], permit))
                .await
                .unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(2), gate.attempted.notified())
                .await
                .unwrap();
            assert!(commands.stop.reason.lock().unwrap().is_none());
            let closed = Arc::new(AtomicBool::new(false));
            let events = Arc::new(ChannelEvents::default());
            let connection = SshConnection {
                commands: commands.clone(),
                closed: Arc::clone(&closed),
                host_key: crate::host_key_info(
                    &crate::test_support::SoftSigner::random().public_wire(),
                )
                .unwrap(),
            };
            let started = std::time::Instant::now();
            connection.close();
            tokio::time::timeout(
                std::time::Duration::from_secs(2),
                run(
                    handle,
                    incoming,
                    events.clone(),
                    Arc::new(CloseOnce {
                        events: events.clone(),
                        closed,
                    }),
                    RunLimits {
                        stop: Arc::clone(&commands.stop),
                        budget: Arc::clone(&commands.bytes),
                        credits,
                        request_timeout: std::time::Duration::from_secs(2),
                    },
                ),
            )
            .await
            .unwrap();
            assert!(started.elapsed() < std::time::Duration::from_secs(2));
            assert!(connection.is_closed());
            assert_eq!(events.closed_count.load(Ordering::SeqCst), 1);
            Arc::clone(&commands.bytes)
        });
        assert_eq!(
            budget.available_permits(),
            1024 * 1024,
            "close kept a writer or flush worker alive"
        );
    }

    #[test]
    fn routing_data_keeps_its_byte_reservation_until_the_write_is_dropped() {
        let (commands, mut pending) = commands();
        let budget = Arc::clone(&commands.bytes);
        let stop = Arc::clone(&commands.stop);
        let mut sub = SshSubstrate {
            commands,
            cancel: knock::Cancel::new(),
        };
        sub.send(16, &vec![b'x'; 1024 * 1024]);
        let Command::Send(ch, data) = pending.try_recv().unwrap() else {
            panic!("expected data")
        };
        let (queue, mut writes) = mpsc::channel(MAX_QUEUED_COMMANDS);
        let writers = Arc::new(Mutex::new(HashMap::from([(ch, queue)])));
        route(&writers, ch, Write::Data(data), &stop);
        assert_eq!(budget.available_permits(), 0);
        let in_flight = writes.try_recv().unwrap();
        assert_eq!(budget.available_permits(), 0);
        sub.send(16, b"overflow");
        assert!(stop
            .reason
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .contains("resource limit"));
        drop(in_flight);
        assert_eq!(budget.available_permits(), 1024 * 1024);
    }

    #[test]
    fn control_commands_are_bounded_and_report_overflow() {
        let (commands, pending) = commands();
        let stop = Arc::clone(&commands.stop);
        let mut sub = SshSubstrate {
            commands,
            cancel: knock::Cancel::new(),
        };
        for _ in 0..257 {
            sub.resize(16, 80, 24);
        }
        assert_eq!(pending.len(), 256);
        assert!(stop
            .reason
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .contains("resource limit"));
    }

    #[test]
    fn close_notification_bypasses_a_full_command_queue() {
        let (commands, pending) = commands();
        let connection = SshConnection {
            commands: commands.clone(),
            closed: Arc::new(AtomicBool::new(false)),
            host_key: crate::host_key_info(
                &crate::test_support::SoftSigner::random().public_wire(),
            )
            .unwrap(),
        };
        let mut sub = SshSubstrate {
            commands,
            cancel: knock::Cancel::new(),
        };
        for _ in 0..256 {
            sub.resize(16, 80, 24);
        }
        connection.close();
        runtime().block_on(async {
            tokio::time::timeout(
                std::time::Duration::from_millis(100),
                connection.commands.stop.changed.notified(),
            )
            .await
            .unwrap();
        });
        assert_eq!(pending.len(), 256);
        assert_eq!(
            connection.commands.stop.reason.lock().unwrap().as_deref(),
            Some("closed by the client")
        );
    }

    #[test]
    fn command_payloads_share_the_outgoing_byte_limit() {
        let (commands, pending) = commands();
        let stop = Arc::clone(&commands.stop);
        let mut sub = SshSubstrate {
            commands,
            cancel: knock::Cancel::new(),
        };
        sub.open(&OpenRequest {
            stream: 16,
            kind: ChannelKind::Command,
            cols: 0,
            rows: 0,
            screen: false,
            command: vec![b'x'; 1024 * 1024 + 1],
        });
        assert_eq!(pending.len(), 0, "an oversized exec payload was queued");
        assert!(stop
            .reason
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .contains("resource limit"));
    }

    #[test]
    fn queued_ssh_bytes_are_bounded() {
        let (commands, mut rx) = commands();
        let mut sub = SshSubstrate {
            commands,
            cancel: knock::Cancel::new(),
        };
        let chunk = vec![b'x'; 64 * 1024];
        for _ in 0..80 {
            sub.send(16, &chunk);
        }
        let mut max_queued_bytes = 0;
        while let Ok(command) = rx.try_recv() {
            if let Command::Send(_, bytes) = command {
                max_queued_bytes += bytes.bytes.len();
            }
        }
        assert!(
            max_queued_bytes <= 1024 * 1024,
            "held {max_queued_bytes} bytes"
        );
    }
}
