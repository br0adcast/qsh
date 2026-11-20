//! The frontend role (#529 M1): the network part of a personal daemon on
//! Linux, in a process of its own that the host ([`crate::host`]) starts
//! and replaces.
//!
//! It runs the session router on the UDP socket it inherited: handshakes,
//! authentication, connections and one bridge per session, each speaking to
//! its session's owner process over a link the host hands it. It keeps
//! nothing that must outlive it:
//!
//! - a session's backend, shells and custody are its owner's;
//! - who has a session, when its client was last heard and since when it
//!   is retained are the host's catalog, which this process reports to
//!   ([`transport::session_manager::SessionDirectory`]) and asks about
//!   logins it has never heard of;
//! - the allowlist and the admission gate are the host's: this process
//!   holds mirrors the host fills, and reports the keys its router scrubs.
//!
//! Started with exactly the role argument and two descriptors: **3**, the
//! channel to the host (a sequenced-packet socket whose peer is the parent
//! daemon), and **4**, the daemon's UDP socket. It ends when the host says
//! `Stop` or on `SIGTERM`/`SIGINT` -- without ending a session: its links
//! then close, and every owner parks. It dies with the host: the kernel
//! kills it when the host process dies (`PR_SET_PDEATHSIG`), and it exits
//! at once should it see its channel to the host end (its sessions are
//! lost with the host, and the UDP port must be free for the next daemon).
//!
//! **Queue bounds.** To the host: requests and notices share one queue of
//! [`HOST_QUEUE`] entries. Each request waits for its answer (at most
//! [`HOST_SERVICE_TIMEOUT`]), and there is at most one per bridge and one
//! for the router; a session reports its liveness at most every ten
//! seconds and at each change, and a scrubbed key once. A request that
//! finds the queue full is refused at once (fail-closed, as an unanswered
//! one); a notice is dropped and logged. Log records have a queue of their
//! own of [`LOG_QUEUE`] records, past which new ones are counted, dropped
//! and reported.

use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use nix::libc;
use tokio::sync::{mpsc, oneshot};
use transport::session_manager::{
    FrontendRelink, LinkIo, Liveness, LoginId, Lookup, OwnerInit, OwnerStarter, RemoteBackend,
    SessionDirectory, Shutdown, StartedOwner,
};
use transport::{BackendFactory, LoginEndedReports, Principal, ServerAuth, SessionManager};

use crate::host::wire::{self, Channel, FrontendInit, Reply, ToFrontend, ToHost};
use crate::host_services::HOST_SERVICE_TIMEOUT;
use crate::owner_process::owner::{claim, int_option, stream};

/// The only argument of a frontend process.
pub const FRONTEND_ROLE: &str = "__qshd-frontend-v1";
/// The frontend's end of the channel to the host.
pub(crate) const CHANNEL_FD: i32 = 3;
/// The daemon's UDP socket.
pub(crate) const UDP_FD: i32 = 4;

/// How long a fresh frontend waits for its `Init`.
const INIT_TIMEOUT: Duration = Duration::from_secs(10);
/// Log records waiting for the host; more are dropped and counted.
const LOG_QUEUE: usize = 256;
/// Requests and notices waiting for the host. A host that takes its packets
/// never lets this fill: far above one request per session and a few
/// notices each.
const HOST_QUEUE: usize = 1024;
/// How long the last packets may take to leave before the process exits.
const FAREWELL_TIMEOUT: Duration = Duration::from_secs(2);
/// The exit status of a frontend whose host is gone.
const HOST_GONE_EXIT: i32 = 3;

/// The frontend role, if `args` asks for it: dispatched before every other
/// command. Refused unless this process was started the way a host starts a
/// frontend.
pub fn frontend_entry(args: &[OsString]) -> Option<Result<()>> {
    if args.first().map(OsString::as_os_str) != Some(OsStr::new(FRONTEND_ROLE)) {
        return None;
    }
    Some(if args.len() != 1 {
        Err(anyhow::anyhow!("the frontend role takes no arguments"))
    } else {
        run_entry()
    })
}

fn run_entry() -> Result<()> {
    if std::env::var_os(crate::handover::HANDOVER_FD_ENV).is_some()
        || std::env::var_os(crate::service_stage::LAUNCH_ENV).is_some()
    {
        bail!("a frontend never takes a handover or a service stage");
    }
    // Die with the host: the kernel kills this process when the host's
    // spawner thread ends, which is when the host process does
    // (`host::on_spawner_thread`). Set before the parent is read: a host
    // already gone leaves this process another parent, which is not the
    // peer of its channel, and it is refused below.
    if unsafe {
        libc::prctl(
            libc::PR_SET_PDEATHSIG,
            libc::SIGKILL as libc::c_ulong,
            0,
            0,
            0,
        )
    } != 0
    {
        bail!(
            "cannot ask to die with the host: {}",
            std::io::Error::last_os_error()
        );
    }
    let parent = std::os::unix::process::parent_id();
    let uid = unsafe { libc::geteuid() };
    let channel = claim(CHANNEL_FD, libc::SOCK_SEQPACKET, parent, uid)
        .context("claiming the channel to the host")?;
    let flags = unsafe { libc::fcntl(UDP_FD, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(UDP_FD, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        bail!("descriptor {UDP_FD} is not open");
    }
    // SAFETY: open, checked just above, and owned by nothing else in this
    // fresh process.
    let socket = unsafe { OwnedFd::from_raw_fd(UDP_FD) };
    let domain = int_option(UDP_FD, libc::SOL_SOCKET, libc::SO_DOMAIN)?;
    if int_option(UDP_FD, libc::SOL_SOCKET, libc::SO_TYPE)? != libc::SOCK_DGRAM
        || (domain != libc::AF_INET && domain != libc::AF_INET6)
    {
        bail!("descriptor {UDP_FD} is not a UDP socket");
    }
    // Nothing else this process inherited goes anywhere.
    crate::handover::close_on_exec_except(&[])
        .context("marking inherited descriptors close-on-exec")?;

    let (init, keys) = first_init(&channel)?;
    let mut builder = tokio::runtime::Builder::new_multi_thread();
    if init.runtime_threads > 0 {
        builder.worker_threads(init.runtime_threads as usize);
    }
    let runtime = builder
        .enable_all()
        .build()
        .context("creating the frontend's runtime")?;
    let result = runtime.block_on(run_frontend(init, keys, channel, socket, uid));
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

/// Wait (until `deadline`) for the next packet on the channel to the host.
fn next_start_packet(channel: &OwnedFd, deadline: std::time::Instant) -> Result<Vec<u8>> {
    let mut poll = libc::pollfd {
        fd: channel.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        // SAFETY: one valid `pollfd`.
        let ready = unsafe { libc::poll(&mut poll, 1, left.as_millis() as libc::c_int) };
        if ready > 0 {
            break;
        }
        if ready == 0 || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
            bail!("the host did not finish this frontend's start in time");
        }
    }
    match wire::receive_packet(channel.as_fd(), false)? {
        Some((packet, descriptors)) if descriptors.is_empty() => Ok(packet),
        _ => bail!("the channel to the host broke during the start"),
    }
}

/// What this process starts from: the `Init` the host put in the channel
/// before it started it, and the allowlist the host sends behind it, up to
/// `Serve`. Nothing is served before: a key the host has is admitted from
/// the first handshake on.
fn first_init(channel: &OwnedFd) -> Result<(FrontendInit, Vec<Addition>)> {
    let deadline = std::time::Instant::now() + INIT_TIMEOUT;
    let mut packet = next_start_packet(channel, deadline)?;
    let decoded = ToFrontend::decode(&packet);
    // The packet held the static key.
    packet.fill(0);
    std::hint::black_box(&packet);
    let init = match decoded {
        Ok(ToFrontend::Init(init)) => *init,
        _ => bail!("the channel to the host did not start with Init"),
    };
    let mut keys = Vec::new();
    loop {
        match ToFrontend::decode(&next_start_packet(channel, deadline)?) {
            Ok(ToFrontend::AllowKeys(more)) => keys.extend(more),
            Ok(ToFrontend::Serve) => return Ok((init, keys)),
            _ => bail!("the host sent a packet a starting frontend does not take"),
        }
    }
}

/// A key of the allowlist, with its addition's sequence number.
type Addition = ([u8; 32], u64);

/// A request's answer, with the descriptors its packet carried.
type Answer = (Reply, Vec<OwnedFd>);

/// The frontend's end of the channel to the host: the session directory of
/// its router, and the starter of its sessions' owners.
pub(crate) struct HostLink {
    this: Weak<HostLink>,
    /// Requests and notices on their way to the host.
    out: mpsc::Sender<ToHost>,
    /// Log records on their way to the host.
    logs: mpsc::Sender<ToHost>,
    logs_dropped: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<Answer>>>,
    next: AtomicU64,
    /// The logins that had a session when this frontend started.
    known: HashSet<LoginId>,
    /// The router's allowlist, as the host fills it.
    allowlist: transport::SharedAllowlist,
    /// Each key's addition, as the host numbered it; held while the list
    /// changes, so a scrub and an addition of one key are ordered.
    additions: Mutex<HashMap<[u8; 32], u64>>,
}

impl HostLink {
    fn new(
        known: Vec<LoginId>,
    ) -> (
        Arc<HostLink>,
        mpsc::Receiver<ToHost>,
        mpsc::Receiver<ToHost>,
    ) {
        let (out, out_rx) = mpsc::channel(HOST_QUEUE);
        let (logs, logs_rx) = mpsc::channel(LOG_QUEUE);
        let link = Arc::new_cyclic(|this| HostLink {
            this: this.clone(),
            out,
            logs,
            logs_dropped: AtomicU64::new(0),
            pending: Mutex::default(),
            next: AtomicU64::new(1),
            known: known.into_iter().collect(),
            allowlist: Arc::new(Mutex::new(Vec::new())),
            additions: Mutex::default(),
        });
        (link, out_rx, logs_rx)
    }

    fn pending(&self) -> std::sync::MutexGuard<'_, HashMap<u64, oneshot::Sender<Answer>>> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Ask the host and wait for its answer, at most
    /// [`HOST_SERVICE_TIMEOUT`]: `None` when none came (fail-closed -- the
    /// caller refuses what it asked for). An answer that comes later is
    /// dropped, descriptors and all.
    async fn ask(&self, request: impl FnOnce(u64) -> ToHost) -> Option<Answer> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        let (tx, rx) = oneshot::channel();
        self.pending().insert(id, tx);
        let answer = if self.out.try_send(request(id)).is_ok() {
            tokio::time::timeout(HOST_SERVICE_TIMEOUT, rx)
                .await
                .ok()
                .and_then(Result::ok)
        } else {
            None
        };
        if answer.is_none() {
            self.pending().remove(&id);
            crate::log::error("qshd", "the host did not answer a session request in time");
        }
        answer
    }

    /// [`HostLink::ask`] from a place that cannot await: the calling worker
    /// waits, for at most the same time.
    fn ask_blocking(&self, request: impl FnOnce(u64) -> ToHost) -> Option<Answer> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.ask(request))
        })
    }

    /// A notice for the host, which never waits: dropped (and logged) when
    /// the queue to a host that does not read is full.
    fn notify(&self, notice: ToHost) {
        if let Err(mpsc::error::TrySendError::Full(notice)) = self.out.try_send(notice) {
            let what = match notice {
                ToHost::Traffic { .. } => "a liveness report",
                ToHost::Retained { .. } => "a retention report",
                ToHost::ForgetKey { .. } => "a scrubbed key",
                ToHost::ClientKey { .. } => "a session's key",
                ToHost::KeysTaken { .. } => "an allowlist receipt",
                _ => "a notice",
            };
            crate::log::error(
                "qshd",
                &format!("{what} for the host was dropped: the queue to the host is full"),
            );
        }
    }

    fn additions(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], u64>> {
        self.additions.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The host added `keys`: admitted from now on. Tells the host up to
    /// which addition this frontend admits.
    fn allow(&self, keys: Vec<([u8; 32], u64)>) {
        let mut additions = self.additions();
        let mut list = self.allowlist.lock().unwrap_or_else(|e| e.into_inner());
        let mut top = 0;
        for (key, seq) in keys {
            if !list.contains(&key) {
                list.push(key);
            }
            additions.insert(key, seq);
            top = top.max(seq);
        }
        drop((list, additions));
        self.notify(ToHost::KeysTaken { seq: top });
    }

    /// The host scrubbed `keys` itself: dropped unless added again since.
    fn revoke(&self, keys: Vec<([u8; 32], u64)>) {
        let mut additions = self.additions();
        let mut list = self.allowlist.lock().unwrap_or_else(|e| e.into_inner());
        for (key, seq) in keys {
            if additions.get(&key) == Some(&seq) {
                additions.remove(&key);
                list.retain(|k| *k != key);
            }
        }
    }

    /// The host answered request `id`.
    fn answer(&self, id: u64, reply: Reply, descriptors: Vec<OwnedFd>) {
        // No waiter left: it timed out, and what the answer carried closes.
        if let Some(waiter) = self.pending().remove(&id) {
            let _ = waiter.send((reply, descriptors));
        }
    }

    /// One log record for the daemon's log.
    fn record(&self, level: log::Level, component: &str, message: &str) {
        let dropped = self.logs_dropped.load(Ordering::SeqCst);
        if dropped > 0 {
            let summary = ToHost::Log {
                level: log::Level::Warn,
                component: "frontend".into(),
                message: format!(
                    "{dropped} frontend log record(s) dropped: the queue to the host was full"
                ),
            };
            if self.logs.try_send(summary).is_err() {
                self.logs_dropped.fetch_add(1, Ordering::SeqCst);
                return;
            }
            self.logs_dropped.fetch_sub(dropped, Ordering::SeqCst);
        }
        let record = ToHost::Log {
            level,
            component: component.to_owned(),
            message: message.to_owned(),
        };
        if self.logs.try_send(record).is_err() {
            self.logs_dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// The owner behind an `Owner` answer, as the router holds it.
    fn started(
        &self,
        token: LoginId,
        mut descriptors: Vec<OwnedFd>,
    ) -> std::io::Result<StartedOwner> {
        let (Some(pidfd), Some(link), Some(host)) =
            (descriptors.pop(), descriptors.pop(), self.this.upgrade())
        else {
            return Err(std::io::Error::other("an owner without its descriptors"));
        };
        Ok(StartedOwner {
            link: Box::new(stream(link)?),
            relink: Arc::new(HostRelink { host, token, pidfd }),
        })
    }
}

impl OwnerStarter for HostLink {
    /// Called on a bridge's task: the worker waits for the host's answer.
    fn start(&self, init: OwnerInit) -> std::io::Result<StartedOwner> {
        let token = init.login;
        let principal = init.principal.clone();
        match self.ask_blocking(|id| ToHost::Create {
            id,
            token,
            principal,
        }) {
            Some((Reply::Owner, descriptors)) => self.started(token, descriptors),
            Some((Reply::Full(why), _)) => Err(std::io::Error::other(why)),
            Some(_) => Err(std::io::Error::other("the host refused the session")),
            None => Err(std::io::Error::other("the host did not answer")),
        }
    }
}

impl SessionDirectory for HostLink {
    fn lookup(
        &self,
        login: LoginId,
        uid: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Lookup> + Send + '_>> {
        Box::pin(async move {
            match self
                .ask(|id| ToHost::Lookup {
                    id,
                    token: login,
                    uid,
                })
                .await
            {
                Some((Reply::Owner, descriptors)) => match self.started(login, descriptors) {
                    Ok(owner) => Lookup::Running(owner),
                    // Not "no session": one may run, and must not be
                    // replaced by a fresh one.
                    Err(error) => {
                        crate::log::error(
                            "qshd",
                            &format!("cannot take a session's owner over: {error}"),
                        );
                        Lookup::Unavailable
                    }
                },
                Some((Reply::Foreign, _)) => Lookup::Foreign,
                Some((Reply::Unknown, _)) => Lookup::Unknown,
                // No answer, a full queue, or one that does not belong to a
                // lookup: whether the session runs is not known.
                _ => Lookup::Unavailable,
            }
        })
    }

    fn known(&self, login: LoginId) -> bool {
        self.known.contains(&login)
    }

    fn liveness(&self, login: LoginId, liveness: Liveness) {
        self.notify(match liveness {
            Liveness::Traffic { idle, active } => ToHost::Traffic {
                token: login,
                idle_ms: idle.as_millis().min(u64::MAX as u128) as u64,
                active,
            },
            Liveness::Retained => ToHost::Retained { token: login },
        });
    }

    /// Reported with the addition it scrubbed -- unless the host added the
    /// key again meanwhile: that addition wins, here and at the host.
    fn key_scrubbed(&self, key: [u8; 32]) {
        let mut additions = self.additions();
        if self
            .allowlist
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&key)
        {
            return;
        }
        let Some(seq) = additions.remove(&key) else {
            return;
        };
        drop(additions);
        self.notify(ToHost::ForgetKey { key, seq });
    }

    fn client_key(&self, login: LoginId, key: [u8; 32]) {
        self.notify(ToHost::ClientKey { token: login, key });
    }
}

/// The router's handle on one session's owner: the host replaces its link.
struct HostRelink {
    host: Arc<HostLink>,
    token: LoginId,
    /// Refers to exactly this owner, which is the host's child.
    pidfd: OwnedFd,
}

impl FrontendRelink for HostRelink {
    fn exited(&self) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + '_>> {
        Box::pin(crate::owner_process::owner_exited(&self.pidfd))
    }

    /// Called on a bridge's task: the worker waits for the host's answer,
    /// at most [`HOST_SERVICE_TIMEOUT`]. Only the host's `Gone` says the
    /// owner is gone (the session then ends); no answer, or any other, is
    /// "not now" (`relink_unavailable`): the session is kept, parked, for
    /// the client's next return.
    fn relink(&self) -> std::io::Result<Box<dyn LinkIo>> {
        let token = self.token;
        // Only `Gone` says the owner is gone; anything else is "not now"
        // (`transport::session_manager::relink_unavailable`), and the
        // session is kept.
        let unavailable =
            |why: &str| std::io::Error::new(std::io::ErrorKind::TimedOut, why.to_string());
        match self.host.ask_blocking(|id| ToHost::Relink { id, token }) {
            Some((Reply::Link, mut descriptors)) => match descriptors.pop() {
                Some(link) => stream(link)
                    .map(|link| Box::new(link) as Box<dyn LinkIo>)
                    .map_err(|error| unavailable(&error.to_string())),
                None => Err(unavailable("a link without its descriptor")),
            },
            Some((Reply::Gone, _)) => Err(std::io::Error::other("the session's owner is gone")),
            Some(_) => Err(unavailable(
                "the host cannot reach the session's owner just now",
            )),
            None => Err(unavailable("the host did not answer")),
        }
    }
}

/// Write requests, notices and log records to the host until a send fails
/// or `stop` fires; then what is still queued, and no more.
async fn write_to_host(
    channel: Arc<Channel>,
    mut out: mpsc::Receiver<ToHost>,
    mut logs: mpsc::Receiver<ToHost>,
    mut stop: oneshot::Receiver<()>,
) {
    let mut stopping = false;
    loop {
        let msg = if stopping {
            match out.try_recv().or_else(|_| logs.try_recv()) {
                Ok(msg) => msg,
                Err(_) => return,
            }
        } else {
            tokio::select! {
                biased;
                Some(msg) = out.recv() => msg,
                Some(msg) = logs.recv() => msg,
                _ = &mut stop => {
                    stopping = true;
                    continue;
                }
            }
        };
        let Ok(packet) = msg.encode() else {
            // A record too long for a packet: only a log line can be.
            continue;
        };
        if channel.send(&packet, &[]).await.is_err() {
            return;
        }
    }
}

async fn run_frontend(
    init: FrontendInit,
    keys: Vec<([u8; 32], u64)>,
    channel: OwnedFd,
    socket: OwnedFd,
    uid: u32,
) -> Result<()> {
    let FrontendInit {
        server_priv,
        server_pub,
        generation,
        authorized_keys,
        account,
        admission_closed,
        runtime_threads: _,
        known,
    } = init;
    let channel = Arc::new(Channel::new(channel).context("watching the channel to the host")?);
    let (host, out_rx, logs_rx) = HostLink::new(known);
    // Only the host writes (and rotates) the daemon's log.
    {
        let host = host.clone();
        crate::log::init_relay(Box::new(move |level, component, message| {
            host.record(level, component, message)
        }));
    }
    let (last_words, stop_writer) = oneshot::channel();
    let writer = tokio::spawn(write_to_host(channel.clone(), out_rx, logs_rx, stop_writer));

    let shutdown = Shutdown::default();
    // Applied before anything is served; the host hears up to where.
    host.allow(keys);
    let allowlist = host.allowlist.clone();
    let admission = Arc::new(crate::update::AdmissionGate::default());
    if admission_closed {
        admission.close();
    }
    let reader = {
        let (channel, host, shutdown) = (channel.clone(), host.clone(), shutdown.clone());
        let admission = admission.clone();
        tokio::spawn(async move {
            loop {
                let (packet, descriptors) = match channel.receive().await {
                    Ok(Some(received)) => received,
                    // The host is gone (or the channel broke, which ends
                    // the host's use of this process just the same): its
                    // sessions die with it, as with a single-process
                    // daemon, and nobody is left to stop in order for. Go
                    // at once -- above all, let go of the daemon's UDP
                    // port, which the next daemon binds.
                    Ok(None) | Err(_) => std::process::exit(HOST_GONE_EXIT),
                };
                match ToFrontend::decode(&packet) {
                    Ok(ToFrontend::Reply { id, reply })
                        if descriptors.len() == reply.descriptors() =>
                    {
                        host.answer(id, reply, descriptors)
                    }
                    Ok(ToFrontend::AllowKeys(keys)) => host.allow(keys),
                    Ok(ToFrontend::RevokeKeys(keys)) => host.revoke(keys),
                    Ok(ToFrontend::Admission { closed }) => {
                        if closed {
                            admission.close()
                        } else {
                            admission.open()
                        }
                    }
                    Ok(ToFrontend::Stop) => shutdown.request(),
                    _ => {
                        crate::log::error(
                            "qshd",
                            "the host sent a packet a frontend does not take",
                        );
                        break;
                    }
                }
            }
            shutdown.request();
        })
    };
    let signals = {
        use tokio::signal::unix::{signal, SignalKind};
        let mut term = signal(SignalKind::terminate()).context("registering SIGTERM")?;
        let mut interrupt = signal(SignalKind::interrupt()).context("registering SIGINT")?;
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = term.recv() => {}
                _ = interrupt.recv() => {}
            }
            shutdown.request();
        })
    };

    let auth = ServerAuth {
        allowlist,
        verifier: authorized_keys.map(|path| {
            Arc::new(sshauth::verify::AuthorizedKeysVerifier::new(
                path,
                uid,
                account.clone(),
            )) as Arc<dyn transport::AuthVerifier>
        }),
        server_pub,
        self_principal: Principal {
            uid,
            name: account,
            identity: "allowlist".to_string(),
            incarnation: 0,
        },
        // Minted here, behind the host's admission gate.
        nonces: Arc::new(crate::update::GatedNonces::new(
            Arc::new(crate::RandomNonces),
            admission,
        )),
        logins: Arc::new(crate::ForgetNothing),
    };
    // The channel backend only answers for the features and the consumption
    // model of the sessions the owners run.
    let inner = crate::channel_backend::ChannelSessionBackend::new(Arc::new(
        crate::screen_budget::ScreenBudget::new(crate::screen_budget::BudgetLimits::default()),
    ));
    let backend = RemoteBackend::with_owners(Arc::new(inner), host.clone()).with_directory(host);
    let socket = std::net::UdpSocket::from(socket);
    socket
        .set_nonblocking(true)
        .context("switching the UDP socket to non-blocking mode")?;
    let socket = tokio::net::UdpSocket::from_std(socket).context("adopting the UDP socket")?;
    let info = transport::bootstrap::ServerInfo {
        generation,
        ..crate::server_info::current()
    };
    crate::log::info("qshd", "network frontend serving");
    let served = SessionManager::serve_with_server_info(
        Arc::new(socket),
        server_priv,
        auth,
        BackendFactory(Arc::new(backend)),
        Arc::new(AtomicUsize::new(0)),
        LoginEndedReports::none(),
        shutdown,
        Some(info),
    )
    .await;
    crate::log::info("qshd", "network frontend stopped");
    reader.abort();
    signals.abort();
    // The last records leave, then the process.
    let _ = last_words.send(());
    let _ = tokio::time::timeout(FAREWELL_TIMEOUT, writer).await;
    served.map_err(|error| anyhow::anyhow!("frontend shutdown: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A host that does not read never makes the frontend wait or grow:
    /// once the queue to it is full, a request is refused at once (as an
    /// unanswered one) and a notice is dropped, and nothing more is queued.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_full_queue_to_the_host_refuses_requests_at_once_and_drops_notices() {
        let (host, out_rx, _logs_rx) = HostLink::new(Vec::new());
        for _ in 0..HOST_QUEUE {
            host.liveness([1; 16], Liveness::Retained);
        }
        assert_eq!(out_rx.len(), HOST_QUEUE);
        host.key_scrubbed([2; 32]);
        assert_eq!(
            out_rx.len(),
            HOST_QUEUE,
            "a notice past the bound is dropped"
        );

        let asked = std::time::Instant::now();
        let refused = tokio::time::timeout(
            HOST_SERVICE_TIMEOUT * 2,
            host.ask(|id| ToHost::Relink { id, token: [1; 16] }),
        )
        .await;
        assert!(
            matches!(refused, Ok(None)),
            "no room for the request: refused"
        );
        assert!(
            asked.elapsed() < HOST_SERVICE_TIMEOUT,
            "refused at once, not after the service timeout: {:?}",
            asked.elapsed()
        );
        assert!(host.pending().is_empty(), "nothing waits for an answer");
        assert_eq!(out_rx.len(), HOST_QUEUE);
    }

    /// A host that does not answer is never taken for "no such session":
    /// a lookup without an answer is `Unavailable` (the router then drops
    /// the handshake instead of starting a fresh session, which would have
    /// the host stop the owner that keeps the old one), and a relink without
    /// one is "not now" (the session is kept), not "the owner is gone".
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_that_does_not_answer_is_never_taken_for_no_session() {
        let (host, _requests, _logs) = HostLink::new(vec![[1; 16]]);
        let asked = std::time::Instant::now();
        let found = host.lookup([1; 16], 1000).await;
        assert!(matches!(found, Lookup::Unavailable), "not Unknown");
        assert!(
            asked.elapsed() >= HOST_SERVICE_TIMEOUT,
            "it waited its bound"
        );

        let pidfd = OwnedFd::from(std::fs::File::open("/dev/null").unwrap());
        let relink = HostRelink {
            host: host.clone(),
            token: [1; 16],
            pidfd,
        };
        // On a runtime worker, as a bridge asks.
        let error = match relink.relink() {
            Ok(_) => panic!("no link without a host"),
            Err(error) => error,
        };
        assert!(
            transport::session_manager::relink_unavailable(&error),
            "not now, the session is kept: {error}"
        );

        // A reply that is no lookup's answer is no answer either.
        let looking = {
            let host = host.clone();
            tokio::spawn(async move { host.lookup([1; 16], 1000).await })
        };
        let id = loop {
            if let Some(id) = host.pending().keys().next().copied() {
                break id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        };
        host.answer(id, Reply::Link, Vec::new());
        assert!(matches!(looking.await.unwrap(), Lookup::Unavailable));
    }
}
