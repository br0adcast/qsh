//! The owner role: one session's channel backend, run in a process of its
//! own (see the parent module).

use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::libc;
use tokio::sync::{mpsc, watch};
use transport::channel::{About, RejectCode, UpdateAnswer, UpdateOffer, UpdateResult};
use transport::channel_server::{DaemonUpdates, RestartPhase, RestartSignal, UpdateTransfer};
use transport::session_manager::{OwnerExit, OwnerInit, OwnerLink, SessionBackend, Shutdown};
use transport::Principal;

use super::wire::{self, HostInit, ToHost, ToOwner, WRITE_CHUNK};
use super::{HOST_FD, LINK_FD, OWNER_ROLE};

/// How long a fresh owner waits for its `Init`.
const INIT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long it waits for its last frames to leave before it exits.
const FAREWELL_TIMEOUT: Duration = Duration::from_secs(5);
/// Log records waiting for the host channel; more are dropped.
const LOG_QUEUE: usize = 256;

/// The owner role, if `args` asks for it: dispatched before every other
/// command. Refused unless this process was started the way a daemon starts
/// an owner -- exactly the role argument, and descriptors 3 and 4 Unix
/// stream sockets whose peer is the parent process of the same account.
pub fn owner_entry(args: &[OsString]) -> Option<Result<()>> {
    if args.first().map(OsString::as_os_str) != Some(OsStr::new(OWNER_ROLE)) {
        return None;
    }
    Some(if args.len() != 1 {
        Err(anyhow::anyhow!("the session owner role takes no arguments"))
    } else {
        run_entry()
    })
}

fn run_entry() -> Result<()> {
    if std::env::var_os(crate::handover::HANDOVER_FD_ENV).is_some()
        || std::env::var_os(crate::service_stage::LAUNCH_ENV).is_some()
    {
        bail!("a session owner never takes a handover or a service stage");
    }
    let parent = std::os::unix::process::parent_id();
    let uid = unsafe { libc::geteuid() };
    let link = claim(LINK_FD, parent, uid).context("claiming the owner link")?;
    let host = claim(HOST_FD, parent, uid).context("claiming the host channel")?;
    let (mut a, mut b): (libc::stat, libc::stat) = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(link.as_raw_fd(), &mut a) } != 0
        || unsafe { libc::fstat(host.as_raw_fd(), &mut b) } != 0
        || (a.st_dev == b.st_dev && a.st_ino == b.st_ino)
    {
        bail!("the owner link and the host channel must be two sockets");
    }
    // Nothing else this process inherited reaches its shells.
    crate::handover::close_on_exec_except(&[])
        .context("marking inherited descriptors close-on-exec")?;
    // The same disposition the daemon's own process ownership needs: the
    // owner waits for its shells itself (`process_scope`).
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || action.sa_sigaction == libc::SIG_IGN
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        bail!("a session owner needs a non-auto-reaping SIGCHLD disposition");
    }
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .context("creating the session owner's runtime")?;
    let result = runtime.block_on(run_owner(link, host));
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

fn int_option(fd: i32, level: i32, name: i32) -> io::Result<i32> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            name,
            (&mut value as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(value)
}

/// Take descriptor `fd` as one end of a socket pair the parent made.
fn claim(fd: i32, parent: u32, uid: u32) -> Result<OwnedFd> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        bail!("descriptor {fd} is not open");
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        bail!("descriptor {fd}: {}", io::Error::last_os_error());
    }
    if int_option(fd, libc::SOL_SOCKET, libc::SO_DOMAIN)? != libc::AF_UNIX
        || int_option(fd, libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_STREAM
    {
        bail!("descriptor {fd} is not a Unix stream socket");
    }
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
    {
        bail!("descriptor {fd}: {}", io::Error::last_os_error());
    }
    if cred.pid as u32 != parent || cred.uid != uid {
        bail!("descriptor {fd} does not lead to the parent daemon");
    }
    Ok(owned)
}

fn stream(fd: OwnedFd) -> io::Result<tokio::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(stream)
}

async fn run_owner(link: OwnedFd, host: OwnedFd) -> Result<()> {
    let (mut read, write) = stream(host)?.into_split();
    let init = match tokio::time::timeout(INIT_TIMEOUT, wire::read_frame(&mut read)).await {
        Ok(Ok(Some(body))) => match ToOwner::decode(&body) {
            Ok(ToOwner::Init(init)) => init,
            _ => bail!("the host channel did not start with Init"),
        },
        _ => bail!("no Init on the host channel"),
    };
    // Records go to the host, the only writer (and rotator) of the
    // daemon's log, which writes them under this process's pid. Bounded:
    // past `LOG_QUEUE` waiting records, new ones are counted and dropped,
    // and the count is reported (see `LogRelay`).
    let (relay, logs_rx) = LogRelay::new(LOG_QUEUE);
    {
        let relay = relay.clone();
        crate::log::init_relay(Box::new(move |level, component, message| {
            relay.record(level, component, message)
        }));
    }
    let HostInit {
        principal,
        login,
        last_generation,
        updates,
        log_dir: _,
    } = init;

    let shutdown = Shutdown::default();
    let (out, out_rx) = mpsc::unbounded_channel::<ToHost>();
    let writer = tokio::spawn(write_to_host(write, out_rx, logs_rx, relay.clone()));
    let client = Arc::new(HostClient {
        out: out.clone(),
        pending: Mutex::new(Pending::default()),
        signal: watch::channel(RestartSignal::IDLE).0,
    });
    let reader = tokio::spawn(serve_host(read, client.clone(), shutdown.clone()));
    let signals = {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).context("registering SIGTERM")?;
        let mut interrupt = signal(SignalKind::interrupt()).context("registering SIGINT")?;
        let (shutdown, client) = (shutdown.clone(), client.clone());
        tokio::spawn(async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = interrupt.recv() => {}
            }
            shutdown.request();
            client.close();
        })
    };

    let budget = Arc::new(crate::screen_budget::ScreenBudget::new(
        crate::screen_budget::BudgetLimits::default(),
    ));
    let mut backend = crate::channel_backend::ChannelSessionBackend::new(budget);
    if updates {
        backend = backend.with_daemon(Arc::new(RemoteDaemonUpdates(client.clone())));
    }
    let backend: Arc<dyn SessionBackend> = Arc::new(backend);
    let mut owner_init = OwnerInit::new(principal.clone(), login);
    owner_init.last_generation = last_generation;
    let run = OwnerLink::run_and_drain(stream(link)?, backend, owner_init, shutdown).await;
    if run.exit != OwnerExit::Shutdown {
        let _ = out.send(ToHost::End);
    }
    client.close();
    let drained = run.drained.map_err(|error| error.to_string());
    match &drained {
        Ok(()) => crate::log::info(
            "owner",
            &format!("session of {} ended ({:?})", principal.name, run.exit),
        ),
        Err(error) => crate::log::error("owner", &format!("session drain failed: {error}")),
    }
    let _ = out.send(ToHost::Drained(drained.clone()));
    drop(out);
    let _ = tokio::time::timeout(FAREWELL_TIMEOUT, writer).await;
    reader.abort();
    signals.abort();
    // Nothing reaches the host any more: whatever was dropped since the
    // last report, and every later record, goes to standard error.
    relay.close();
    // A failed drain is a failed owner: the host sees it in the receipt and
    // in the exit status.
    drained.map_err(|error| anyhow::anyhow!("session drain failed: {error}"))
}

/// The owner's log records on their way to the host: a bounded queue, and
/// a count of the records it had no room for. The count is never silent:
/// it is reported as a record of its own the next time the queue has room,
/// and before `Drained`; once the host channel is gone, it and every later
/// record go to standard error.
pub(super) struct LogRelay {
    tx: mpsc::Sender<ToHost>,
    dropped: std::sync::atomic::AtomicU64,
    closed: std::sync::atomic::AtomicBool,
}

impl LogRelay {
    pub(super) fn new(capacity: usize) -> (Arc<LogRelay>, mpsc::Receiver<ToHost>) {
        let (tx, rx) = mpsc::channel(capacity);
        (
            Arc::new(LogRelay {
                tx,
                dropped: Default::default(),
                closed: Default::default(),
            }),
            rx,
        )
    }

    fn summary(n: u64) -> ToHost {
        ToHost::Log {
            level: log::Level::Warn,
            component: "owner".into(),
            message: format!("{n} owner log record(s) dropped: the queue to the daemon was full"),
        }
    }

    /// Queue one record, after the report of what was dropped before it.
    pub(super) fn record(&self, level: log::Level, component: &str, message: &str) {
        use std::sync::atomic::Ordering;
        if self.closed.load(Ordering::SeqCst) {
            return stderr_record(level, component, message);
        }
        let dropped = self.dropped.load(Ordering::SeqCst);
        if dropped > 0 {
            if self.tx.try_send(Self::summary(dropped)).is_err() {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                return;
            }
            self.dropped.fetch_sub(dropped, Ordering::SeqCst);
        }
        let record = ToHost::Log {
            level,
            component: component.to_owned(),
            message: message.to_owned(),
        };
        match self.tx.try_send(record) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::SeqCst);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => stderr_record(level, component, message),
        }
    }

    /// The report owed for dropped records, if any; taken.
    fn take_summary(&self) -> Option<ToHost> {
        match self.dropped.swap(0, std::sync::atomic::Ordering::SeqCst) {
            0 => None,
            n => Some(Self::summary(n)),
        }
    }

    /// The host channel is gone: report what is still owed on standard
    /// error, and send every later record there.
    fn close(&self) {
        self.closed.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(ToHost::Log {
            level,
            component,
            message,
        }) = self.take_summary()
        {
            stderr_record(level, &component, &message);
        }
    }
}

/// One record on standard error (inherited from the daemon), for when the
/// daemon can no longer be told.
fn stderr_record(level: log::Level, component: &str, message: &str) {
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr(),
        "qshd owner [{}] {level} {component}: {}",
        std::process::id(),
        crate::log::one_line(message)
    );
}

/// Write the owner's frames: everything `out` carries, and records from
/// `logs` in between, neither able to starve the other. `Drained` is the
/// last frame; records still waiting, and the report of any dropped ones,
/// go out just before it.
pub(super) async fn write_to_host<W: tokio::io::AsyncWrite + Unpin>(
    mut write: W,
    mut out: mpsc::UnboundedReceiver<ToHost>,
    mut logs: mpsc::Receiver<ToHost>,
    relay: Arc<LogRelay>,
) {
    use tokio::io::AsyncWriteExt;
    async fn put<W: tokio::io::AsyncWrite + Unpin>(write: &mut W, msg: &ToHost) -> bool {
        match msg.encode() {
            Ok(bytes) => write.write_all(&bytes).await.is_ok(),
            // Nothing the owner sends can exceed a frame; drop it if it did.
            Err(_) => true,
        }
    }
    loop {
        // Unbiased: steady protocol traffic cannot hold the records back.
        let msg = tokio::select! {
            msg = out.recv() => match msg {
                Some(msg) => msg,
                None => break,
            },
            Some(msg) = logs.recv() => msg,
        };
        if matches!(msg, ToHost::Drained(_)) {
            let mut ok = true;
            while let Ok(record) = logs.try_recv() {
                if !put(&mut write, &record).await {
                    ok = false;
                    break;
                }
            }
            if ok {
                if let Some(summary) = relay.take_summary() {
                    ok = put(&mut write, &summary).await;
                }
            }
            if ok {
                let _ = put(&mut write, &msg).await;
            }
            break;
        }
        if !put(&mut write, &msg).await {
            break;
        }
    }
    let _ = write.shutdown().await;
}

/// Read the host channel: `Stop` and the end of input (the host is gone)
/// both end the session; restart signals and replies go to `client`.
async fn serve_host(
    mut read: tokio::net::unix::OwnedReadHalf,
    client: Arc<HostClient>,
    shutdown: Shutdown,
) {
    loop {
        let frame = match wire::read_frame(&mut read).await {
            Ok(Some(body)) => ToOwner::decode(&body),
            Ok(None) => {
                crate::log::warn("owner", "the host channel closed; ending the session");
                break;
            }
            Err(error) => {
                crate::log::error("owner", &format!("host channel read failed: {error}"));
                break;
            }
        };
        match frame {
            Ok(ToOwner::Stop) => break,
            Ok(ToOwner::Signal(signal)) => {
                client.signal.send_replace(signal);
            }
            Ok(ToOwner::Init(_)) | Err(_) => {
                crate::log::error("owner", "the host channel sent a bad frame");
                break;
            }
            Ok(reply) => client.reply(reply),
        }
    }
    // The order matters: the session sees the stop before a request it
    // has outstanding fails, so nothing of that failure reaches its client.
    shutdown.request();
    client.close();
}

#[derive(Default)]
struct Pending {
    closed: bool,
    next: u64,
    waiters: HashMap<u64, std::sync::mpsc::SyncSender<ToOwner>>,
}

/// Requests to the host, from the session's blocking workers.
struct HostClient {
    out: mpsc::UnboundedSender<ToHost>,
    pending: Mutex<Pending>,
    signal: watch::Sender<RestartSignal>,
}

impl HostClient {
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Send one request and wait for its reply; `None` once the session is
    /// stopping or the host is gone. Blocking.
    fn call(&self, request: impl FnOnce(u64) -> ToHost) -> Option<ToOwner> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        {
            let mut pending = self.lock();
            if pending.closed {
                return None;
            }
            pending.next += 1;
            let id = pending.next;
            pending.waiters.insert(id, tx);
            if self.out.send(request(id)).is_err() {
                pending.waiters.remove(&id);
                return None;
            }
        }
        rx.recv().ok()
    }

    fn reply(&self, reply: ToOwner) {
        let id = match &reply {
            ToOwner::About { id, .. }
            | ToOwner::Offered { id, .. }
            | ToOwner::Written { id, .. }
            | ToOwner::Verified { id, .. }
            | ToOwner::Restarted { id, .. } => *id,
            _ => return,
        };
        if let Some(waiter) = self.lock().waiters.remove(&id) {
            let _ = waiter.try_send(reply);
        }
    }

    fn notify(&self, msg: ToHost) {
        let _ = self.out.send(msg);
    }

    /// Every outstanding and later request fails.
    fn close(&self) {
        let mut pending = self.lock();
        pending.closed = true;
        pending.waiters.clear();
    }
}

/// The daemon's update service, seen from an owner: every call goes to the
/// host, which holds the only `DaemonSelf`.
struct RemoteDaemonUpdates(Arc<HostClient>);

impl DaemonUpdates for RemoteDaemonUpdates {
    fn about(&self) -> Option<About> {
        match self.0.call(|id| ToHost::About { id })? {
            ToOwner::About { about, .. } => about,
            _ => None,
        }
    }

    fn offer(
        &self,
        _from: &Principal,
        offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        // The host answers for this owner's own principal.
        let offer = offer.clone();
        match self.0.call(|id| ToHost::Offer { id, offer }) {
            Some(ToOwner::Offered {
                result: Ok(transfer),
                ..
            }) => Ok(Box::new(RemoteTransfer {
                client: self.0.clone(),
                transfer,
                done: false,
            })),
            Some(ToOwner::Offered {
                result: Err(answer),
                ..
            }) => Err(answer),
            _ => Err(UpdateAnswer::ProviderFailed),
        }
    }

    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.0.signal.subscribe()
    }

    /// Decided here against the signal as the host last pushed it, and
    /// reported. The host counts the join only if the attempt is still
    /// announced when the report arrives, and confirms a release only for a
    /// join it counted; whatever this owner believes, the host stops and
    /// reaps every owner before it execs.
    fn restart_joined(&self, restart: u64) -> bool {
        let signal = *self.0.signal.borrow();
        if signal.restart != restart || signal.phase != RestartPhase::Announced {
            return false;
        }
        self.0.notify(ToHost::Joined { restart });
        true
    }

    fn channels_released(&self, restart: u64) {
        self.0.notify(ToHost::Released { restart });
    }
}

fn stopping() -> UpdateResult {
    UpdateResult::Rejected {
        code: RejectCode::ExecFailed,
        detail: "the session is stopping".into(),
    }
}

/// An accepted image, staged by the host.
struct RemoteTransfer {
    client: Arc<HostClient>,
    transfer: u64,
    done: bool,
}

impl UpdateTransfer for RemoteTransfer {
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        for piece in bytes.chunks(WRITE_CHUNK) {
            let bytes = piece.to_vec();
            let transfer = self.transfer;
            match self.client.call(|id| ToHost::Write {
                id,
                transfer,
                bytes,
            }) {
                Some(ToOwner::Written { result, .. }) => result?,
                _ => return Err("the session is stopping".into()),
            }
        }
        Ok(())
    }

    fn verify(&mut self) -> Result<(), UpdateResult> {
        let transfer = self.transfer;
        match self.client.call(|id| ToHost::Verify { id, transfer }) {
            Some(ToOwner::Verified { result, .. }) => result,
            _ => Err(stopping()),
        }
    }

    fn restart(mut self: Box<Self>) -> UpdateResult {
        // The host consumes its transfer whatever happens.
        self.done = true;
        let transfer = self.transfer;
        match self.client.call(|id| ToHost::Restart { id, transfer }) {
            Some(ToOwner::Restarted { result, .. }) => result,
            _ => stopping(),
        }
    }
}

impl Drop for RemoteTransfer {
    fn drop(&mut self) {
        if !self.done {
            self.client.notify(ToHost::Abandon {
                transfer: self.transfer,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record_text(msg: &ToHost) -> Option<&str> {
        match msg {
            ToHost::Log { message, .. } => Some(message),
            _ => None,
        }
    }

    async fn frames_until_drained(read: &mut tokio::net::UnixStream) -> Vec<ToHost> {
        let mut seen = Vec::new();
        while let Some(body) = wire::read_frame(read).await.expect("a frame") {
            let msg = ToHost::decode(&body).expect("a host frame");
            let last = matches!(msg, ToHost::Drained(_));
            seen.push(msg);
            if last {
                break;
            }
        }
        seen
    }

    /// Records the full queue had no room for are counted, and the count
    /// reaches the host as a record of its own as soon as the queue takes
    /// one again -- ahead of that record.
    #[tokio::test]
    async fn an_overflowing_log_relay_reports_its_dropped_records_when_it_has_room() {
        let (relay, logs) = LogRelay::new(4);
        for n in 0..10 {
            relay.record(log::Level::Info, "test", &format!("early {n}"));
        }
        let (write, mut read) = tokio::net::UnixStream::pair().unwrap();
        let (out, out_rx) = mpsc::unbounded_channel();
        let writer = tokio::spawn(write_to_host(write, out_rx, logs, relay.clone()));
        let mut seen = Vec::new();
        while seen.len() < 4 {
            let body = wire::read_frame(&mut read).await.unwrap().unwrap();
            seen.push(ToHost::decode(&body).unwrap());
        }
        relay.record(log::Level::Info, "test", "late");
        out.send(ToHost::Drained(Ok(()))).unwrap();
        seen.extend(frames_until_drained(&mut read).await);
        writer.await.unwrap();
        let texts: Vec<&str> = seen.iter().filter_map(record_text).collect();
        assert_eq!(&texts[..4], ["early 0", "early 1", "early 2", "early 3"]);
        let report = texts
            .iter()
            .position(|t| t.starts_with("6 owner log record(s) dropped"))
            .unwrap_or_else(|| panic!("no dropped-count record in {texts:?}"));
        let late = texts
            .iter()
            .position(|t| *t == "late")
            .expect("late record");
        assert!(
            report < late,
            "the count goes ahead of the next record: {texts:?}"
        );
        assert!(matches!(seen.last(), Some(ToHost::Drained(Ok(())))));
    }

    /// A count still owed when the session ends goes out before `Drained`,
    /// whatever protocol traffic there is.
    #[tokio::test]
    async fn dropped_records_are_reported_before_the_receipt() {
        let (relay, logs) = LogRelay::new(2);
        for n in 0..5 {
            relay.record(log::Level::Info, "test", &format!("record {n}"));
        }
        let (write, mut read) = tokio::net::UnixStream::pair().unwrap();
        let (out, out_rx) = mpsc::unbounded_channel();
        for _ in 0..100 {
            out.send(ToHost::Joined { restart: 1 }).unwrap();
        }
        out.send(ToHost::Drained(Ok(()))).unwrap();
        let writer = tokio::spawn(write_to_host(write, out_rx, logs, relay.clone()));
        let seen = frames_until_drained(&mut read).await;
        writer.await.unwrap();
        let texts: Vec<&str> = seen.iter().filter_map(record_text).collect();
        assert_eq!(
            texts,
            [
                "record 0",
                "record 1",
                "3 owner log record(s) dropped: the queue to the daemon was full"
            ]
        );
        assert!(matches!(seen.last(), Some(ToHost::Drained(Ok(())))));
        // After the channel is gone nothing is queued or lost silently: the
        // record goes to standard error instead.
        relay.close();
        relay.record(log::Level::Info, "test", "after the end");
        assert_eq!(relay.dropped.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}
