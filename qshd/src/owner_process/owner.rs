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
use transport::channel_open::{ChannelOpenRegistry, OpenAdmission, RestartOpenFence};
use transport::channel_server::{DaemonUpdates, RestartPhase, RestartSignal, UpdateTransfer};
use transport::session_manager::{
    OwnerExit, OwnerInit, OwnerLink, OwnerRelink, SessionBackend, Shutdown,
};
use transport::Principal;

use super::wire::{self, HostInit, ToHost, ToOwner, WRITE_CHUNK};
use super::{HOST_FD, LINK_FD, OWNER_ROLE, RELINK_FD};
use crate::host_services::HOST_SERVICE_TIMEOUT;
use crate::screen_budget::{BackingSlots, ScreenPool};

/// How long a fresh owner waits for its `Init`.
const INIT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long it waits for its last frames to leave before it exits.
const FAREWELL_TIMEOUT: Duration = Duration::from_secs(5);
/// How long an ending session may take to join its tasks and workers; a
/// drain still running then is given up on (a failed receipt). With the
/// last-resort kill (no waits), the farewell (`FAREWELL_TIMEOUT`) and the
/// runtime's 2 s shutdown, at most 17 s: below the host's 20 s stop
/// escalation, so a stopping daemon hears the receipt first. A session its
/// frontend ended (`End`) gets the same bound before that for its backend
/// to finish; past it, it is stopped as at a `Stop`
/// (`OwnerLink::run_and_drain`). So a session whose processes keep its
/// terminal open after a close is killed whole (`end_children`) with a
/// failed receipt: about 10 s after the close, since the host's `Stop`
/// follows the router's end of the login at once and the drain bound runs
/// from there; at most about 20 s, when only the link's `End` ends it.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);
/// Log records waiting for the host channel; more are dropped.
const LOG_QUEUE: usize = 256;
/// Limit requests given up on whose late answers are still awaited; one
/// more and the host is taken for unreachable.
pub(crate) const ABANDONED_MAX: usize = 16;

/// The owner role, if `args` asks for it: dispatched before every other
/// command. Refused unless this process was started the way a daemon starts
/// an owner -- exactly the role argument, descriptors 3 and 4 Unix stream
/// sockets and descriptor 5 a Unix sequenced-packet socket, each with the
/// parent process of the same account as its peer.
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
    let link = claim(LINK_FD, libc::SOCK_STREAM, parent, uid).context("claiming the owner link")?;
    let host =
        claim(HOST_FD, libc::SOCK_STREAM, parent, uid).context("claiming the host channel")?;
    let relink = claim(RELINK_FD, libc::SOCK_SEQPACKET, parent, uid)
        .context("claiming the relink channel")?;
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
        .worker_threads(OWNER_WORKERS)
        .enable_all()
        .build()
        .context("creating the session owner's runtime")?;
    let result = runtime.block_on(run_owner(link, host, relink, parent, uid));
    runtime.shutdown_timeout(Duration::from_secs(2));
    result
}

/// One runtime worker per session owner (#650). An owner serves one session:
/// its PTY reader, the channel runner and the link writer hand work to one
/// another for every record, and a second worker only took turns with the
/// first, woken through the kernel each time. A blocking wait still frees the
/// worker (`block_in_place` hands it to another thread), and blocking work
/// runs on the runtime's blocking pool as before. A multi-thread runtime is
/// kept because `block_in_place` needs one.
const OWNER_WORKERS: usize = 1;

pub(crate) fn int_option(fd: i32, level: i32, name: i32) -> io::Result<i32> {
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

/// Take descriptor `fd` as one end of a socket pair of type `kind` the
/// parent made.
pub(crate) fn claim(fd: i32, kind: i32, parent: u32, uid: u32) -> Result<OwnedFd> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        bail!("descriptor {fd} is not open");
    }
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        bail!("descriptor {fd}: {}", io::Error::last_os_error());
    }
    from_parent(&owned, kind, parent, uid)?;
    Ok(owned)
}

/// Check that `socket` is one end of a Unix socket pair of type `kind`
/// whose other end the parent daemon made.
pub(crate) fn from_parent(socket: &OwnedFd, kind: i32, parent: u32, uid: u32) -> Result<()> {
    let fd = socket.as_raw_fd();
    if int_option(fd, libc::SOL_SOCKET, libc::SO_DOMAIN)? != libc::AF_UNIX
        || int_option(fd, libc::SOL_SOCKET, libc::SO_TYPE)? != kind
    {
        bail!("descriptor {fd} is not a Unix socket of the expected type");
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
    Ok(())
}

/// One packet off the relink channel: the descriptor it carries, `None`
/// for a packet without exactly one (whatever it carried is closed), and an
/// error at the end of input or when nothing is waiting.
fn receive_descriptor(channel: &OwnedFd) -> io::Result<Option<OwnedFd>> {
    let mut byte = [0u8; 1];
    let mut vector = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: byte.len(),
    };
    // Aligned for a control header; room for a few descriptors, so that a
    // packet carrying more than one is seen whole and refused.
    let mut control = [0u64; 8];
    // SAFETY: an all-zero `msghdr` has no address and no control data.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = size_of_val(&control) as _;
    // SAFETY: every pointer in `message` refers to a live local of the
    // length given with it.
    let got = unsafe {
        libc::recvmsg(
            channel.as_raw_fd(),
            &mut message,
            libc::MSG_DONTWAIT | libc::MSG_CMSG_CLOEXEC,
        )
    };
    if got < 0 {
        return Err(io::Error::last_os_error());
    }
    if got == 0 {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let mut descriptors = Vec::new();
    // SAFETY: the kernel filled `msg_controllen` bytes of `control`; the
    // header macros walk only inside them, and every integer of an
    // `SCM_RIGHTS` record is a descriptor this process now owns, adopted
    // here exactly once.
    unsafe {
        let mut header = libc::CMSG_FIRSTHDR(&message);
        while !header.is_null() {
            if (*header).cmsg_level == libc::SOL_SOCKET && (*header).cmsg_type == libc::SCM_RIGHTS {
                let bytes = (*header).cmsg_len as usize - libc::CMSG_LEN(0) as usize;
                let data = libc::CMSG_DATA(header).cast::<libc::c_int>();
                for i in 0..bytes / size_of::<libc::c_int>() {
                    descriptors.push(OwnedFd::from_raw_fd(std::ptr::read_unaligned(data.add(i))));
                }
            }
            header = libc::CMSG_NXTHDR(&message, header);
        }
    }
    if message.msg_flags & (libc::MSG_CTRUNC | libc::MSG_TRUNC) != 0 || descriptors.len() != 1 {
        return Ok(None);
    }
    Ok(descriptors.pop())
}

/// Take the links the daemon passes over the relink channel, and hand each
/// to the session's owner link in place of its current one. Only a stream
/// socket pair end the parent daemon made is accepted. Ends when the
/// channel closes (the daemon is gone).
async fn receive_links(channel: OwnedFd, relinks: OwnerRelink, parent: u32, uid: u32) {
    // SAFETY: the channel is owned by the `AsyncFd` and stays open for as
    // long as it is registered.
    let registered = unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(channel, tokio::io::Interest::READABLE)
    };
    let channel = match registered {
        Ok(channel) => channel,
        Err(error) => {
            crate::log::error(
                "owner",
                &format!("cannot watch the relink channel: {error}"),
            );
            return;
        }
    };
    loop {
        let Ok(mut ready) = channel.readable().await else {
            return;
        };
        let link = match receive_descriptor(channel.get_ref()) {
            Ok(link) => link,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                ready.clear_ready();
                continue;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            // The daemon closed its end, or the channel broke.
            Err(_) => return,
        };
        let link = link
            .ok_or_else(|| anyhow::anyhow!("a packet without exactly one descriptor"))
            .and_then(|link| {
                from_parent(&link, libc::SOCK_STREAM, parent, uid)?;
                Ok(stream(link)?)
            });
        match link {
            Ok(link) => {
                crate::log::info("owner", "the frontend replaced the session's link");
                relinks.relink(link);
            }
            Err(error) => {
                crate::log::error("owner", &format!("refused a replacement link: {error:#}"))
            }
        }
    }
}

pub(crate) fn stream(fd: OwnedFd) -> io::Result<tokio::net::UnixStream> {
    let stream = std::os::unix::net::UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    tokio::net::UnixStream::from_std(stream)
}

async fn run_owner(
    link: OwnedFd,
    host: OwnedFd,
    relink: OwnedFd,
    parent: u32,
    uid: u32,
) -> Result<()> {
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
    let client = HostClient::new(out.clone());
    client.end_session_on_unreachable(shutdown.clone());

    let OwnerBackend {
        backend,
        screens: _,
    } = owner_backend(&client, updates);
    let opens = OpensFence::new(backend.open_registry());
    let backend: Arc<dyn SessionBackend> = Arc::new(backend);

    let mut owner_init = OwnerInit::new(principal.clone(), login);
    owner_init.last_generation = last_generation;
    let reader = tokio::spawn(serve_host(
        read,
        client.clone(),
        opens,
        shutdown.clone(),
        owner_init.abandon(),
    ));
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

    let links = tokio::spawn(receive_links(relink, owner_init.relinks(), parent, uid));
    let run =
        OwnerLink::run_and_drain(stream(link)?, backend, owner_init, shutdown, DRAIN_TIMEOUT).await;
    if run.exit != OwnerExit::Shutdown {
        let _ = out.send(ToHost::End);
    }
    client.close();
    let mut drained = run.drained.map_err(|error| error.to_string());
    if drained.is_err() {
        // Something of the session did not join: nothing of it may outlive
        // this process, which is about to exit whatever is still blocked.
        let killed = end_children();
        if killed > 0 {
            drained = drained
                .map_err(|error| format!("{error}; {killed} process(es) of the session killed"));
        }
    }
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
    links.abort();
    // Nothing reaches the host any more: whatever was dropped since the
    // last report, and every later record, goes to standard error.
    relay.close();
    // A failed drain is a failed owner: the host sees it in the receipt and
    // in the exit status.
    drained.map_err(|error| anyhow::anyhow!("session drain failed: {error}"))
}

/// Kill every process of the sessions this process's children lead, and
/// how many were alive when signalled: exactly, through descriptors that pin each one
/// (`process_scope::kill_child_sessions`), never by a numeric PID or group.
/// It never waits and never reaps -- the channel scopes, or init once this
/// process has exited, do -- so it cannot hold up the receipt or the exit.
fn end_children() -> usize {
    let view = match crate::process_scope::qualify_native_proc() {
        Ok(view) => view,
        Err(error) => {
            crate::log::error(
                "owner",
                &format!(
                    "the session did not drain, and its processes cannot be pinned \
                     ({error:?}); none signalled"
                ),
            );
            return 0;
        }
    };
    match crate::process_scope::kill_child_sessions(
        &view,
        |_| true,
        &mut crate::process_scope::Native,
    ) {
        Ok(kill) => {
            if kill.killed > 0 {
                crate::log::warn(
                    "owner",
                    &format!(
                        "the session did not drain; killed {} of its process(es)",
                        kill.killed
                    ),
                );
            }
            if !kill.settled {
                crate::log::error(
                    "owner",
                    &format!(
                        "the session still had new processes after {} passes; \
                         some may outlive this owner",
                        crate::process_scope::KILL_PASSES
                    ),
                );
            }
            kill.killed
        }
        Err(error) => {
            crate::log::error(
                "owner",
                &format!(
                    "the session did not drain, and its processes could not be listed: {error:?}"
                ),
            );
            0
        }
    }
}

/// What an owner runs its session with.
pub(crate) struct OwnerBackend {
    pub(crate) backend: crate::channel_backend::ChannelSessionBackend,
    /// The screen budget its channels are charged to (given to the
    /// backend's spawner; read here only by tests).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) screens: Arc<crate::screen_budget::ScreenBudget>,
}

/// The owner's channel backend: every daemon-wide limit is the host's,
/// shared by all of the daemon's owners (`crate::host_services`) -- the
/// screen pool and the open count by request through `client`; the control
/// budget is one envelope (`OwnerLink::run_and_drain`). Every session
/// leader it starts is told to the host ([`HostLeaders`]). With `updates`,
/// it speaks for the host's update service.
pub(crate) fn owner_backend(client: &Arc<HostClient>, updates: bool) -> OwnerBackend {
    let limits = Arc::new(RemoteLimits(client.clone()));
    let screens = Arc::new(crate::screen_budget::ScreenBudget::remote(limits.clone()));
    let spawner = crate::channel_backend::PtyChannelSpawner::new(screens.clone())
        .with_open_admission(limits)
        .with_leader_reports(Arc::new(HostLeaders(client.clone())));
    let mut backend =
        crate::channel_backend::ChannelSessionBackend::with_spawner(Arc::new(spawner));
    if updates {
        backend = backend.with_daemon(Arc::new(RemoteDaemonUpdates(client.clone())));
    }
    OwnerBackend { backend, screens }
}

/// The owner's log records on their way to the host: a bounded queue, and
/// a count of the records it had no room for. The count is never silent:
/// it is reported as a record of its own the next time the queue has room,
/// and before `Drained`; once the host channel is gone, it and every later
/// record go to standard error.
pub(super) struct LogRelay {
    tx: mpsc::Sender<ToHost>,
    dropped: crate::log::dropped::DroppedRecords,
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
        if !self
            .dropped
            .report(|n| self.tx.try_send(Self::summary(n)).is_ok())
        {
            self.dropped.add(1);
            return;
        }
        let record = ToHost::Log {
            level,
            component: component.to_owned(),
            message: message.to_owned(),
        };
        match self.tx.try_send(record) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => self.dropped.add(1),
            Err(mpsc::error::TrySendError::Closed(_)) => stderr_record(level, component, message),
        }
    }

    /// The report owed for dropped records, if any; taken.
    fn take_summary(&self) -> Option<ToHost> {
        match self.dropped.take() {
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
/// both end the session; restart signals and replies go to `client`, the
/// restart fence to `opens`.
async fn serve_host(
    mut read: tokio::net::unix::OwnedReadHalf,
    client: Arc<HostClient>,
    opens: OpensFence,
    shutdown: Shutdown,
    abandon: Shutdown,
) {
    // Restart signals are published off this loop: a runner may hold the
    // signal's read side for a moment, and nothing may hold up the replies
    // and stops this loop delivers.
    let relay = tokio::spawn(client.clone().relay_signals());
    loop {
        let frame = match wire::read_frame(&mut read).await {
            Ok(Some(body)) => ToOwner::decode(&body),
            // The host is gone: its sessions are lost, as when a
            // single-process daemon dies. Nothing tells the frontend the
            // session ended (`OwnerInit::abandon`).
            Ok(None) => {
                crate::log::warn("owner", "the host channel closed; ending the session");
                abandon.request();
                break;
            }
            Err(error) => {
                crate::log::error("owner", &format!("host channel read failed: {error}"));
                abandon.request();
                break;
            }
        };
        match frame {
            Ok(ToOwner::Stop) => break,
            Ok(ToOwner::Signal(signal)) => client.push_signal(signal),
            Ok(ToOwner::FenceOpens { fence }) => {
                let result = opens.fence();
                client.notify(ToHost::OpensFenced { fence, result });
            }
            Ok(ToOwner::ReopenOpens) => opens.reopen(),
            Ok(ToOwner::Init(_)) | Err(_) => {
                crate::log::error("owner", "the host channel sent a bad frame");
                break;
            }
            Ok(reply) => client.reply(reply),
        }
    }
    relay.abort();
    // The order matters: the session sees the stop before a request it
    // has outstanding fails, so nothing of that failure reaches its client.
    shutdown.request();
    client.close();
}

/// This owner's channel opening, fenced for the daemon's replacement while
/// the host asks (`FenceOpens` .. `ReopenOpens`), as a single-process
/// daemon fences its own registry.
pub(crate) struct OpensFence {
    registry: Arc<ChannelOpenRegistry>,
    held: Mutex<Option<RestartOpenFence>>,
}

impl OpensFence {
    pub(crate) fn new(registry: Arc<ChannelOpenRegistry>) -> OpensFence {
        OpensFence {
            registry,
            held: Mutex::new(None),
        }
    }

    /// Fence: from here on every open is refused as `Restarting` and every
    /// pending one cancelled. `Ok` only if no channel cleanup was pending
    /// or unconfirmed before (the update preflight's condition, which the
    /// host cannot see in an owner's registry); fenced either way, until
    /// [`OpensFence::reopen`].
    pub(crate) fn fence(&self) -> Result<(), String> {
        let mut held = self.held.lock().unwrap_or_else(|e| e.into_inner());
        // Still fenced for an earlier attempt (its `ReopenOpens` folded into
        // this request): fence afresh, as that attempt's undo and this
        // attempt would have.
        if let Some(earlier) = held.take() {
            earlier.reopen();
        }
        let debt = match self.registry.cleanup_snapshot() {
            Some(snapshot) if !snapshot.has_cleanup_debt() => None,
            Some(_) => Some("registered channel cleanup is still pending or unconfirmed"),
            None => Some("registered channel cleanup observation is unavailable"),
        };
        match self.registry.begin_restart_fence() {
            Ok(fence) => *held = Some(fence),
            Err(_) => return Err("channel opening could not be fenced".into()),
        }
        match debt {
            Some(debt) => Err(debt.into()),
            None => Ok(()),
        }
    }

    /// The replacement did not happen: admit opens again.
    pub(crate) fn reopen(&self) {
        let fence = self.held.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(fence) = fence {
            fence.reopen();
        }
    }
}

#[derive(Default)]
struct Pending {
    closed: bool,
    next: u64,
    waiters: HashMap<u64, std::sync::mpsc::SyncSender<ToOwner>>,
    /// What gives back a grant whose request was given up on (timed out):
    /// sent if the grant still arrives. At most one per such request,
    /// dropped with its answer.
    abandoned: HashMap<u64, ToHost>,
}

/// Wait for `wait` on this thread. On a runtime worker the worker's other
/// tasks -- among them the writer and the reader of the host channel this
/// wait is for -- move to another thread meanwhile, so a blocking call from
/// async code cannot hold up its own answer.
fn block_for<T>(wait: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(wait)
        }
        _ => wait(),
    }
}

/// Requests to the host, from the session's blocking workers and, for the
/// daemon-wide limits, from wherever the session charges them.
pub(crate) struct HostClient {
    out: mpsc::UnboundedSender<ToHost>,
    pending: Mutex<Pending>,
    signal: watch::Sender<RestartSignal>,
    /// The latest restart signal from the host not yet published, and
    /// the wake of its relay ([`HostClient::relay_signals`]).
    incoming: Mutex<Option<RestartSignal>>,
    relay: tokio::sync::Notify,
    /// The session, ended when the host is taken for unreachable.
    on_unreachable: std::sync::OnceLock<Shutdown>,
}

impl HostClient {
    /// A client whose requests go to `out`; replies come through
    /// [`HostClient::reply`].
    pub(crate) fn new(out: mpsc::UnboundedSender<ToHost>) -> Arc<HostClient> {
        Arc::new(HostClient {
            out,
            pending: Mutex::new(Pending::default()),
            signal: watch::channel(RestartSignal::IDLE).0,
            incoming: Mutex::new(None),
            relay: tokio::sync::Notify::new(),
            on_unreachable: std::sync::OnceLock::new(),
        })
    }

    /// End `shutdown`'s session if the host is ever taken for unreachable.
    pub(crate) fn end_session_on_unreachable(&self, shutdown: Shutdown) {
        let _ = self.on_unreachable.set(shutdown);
    }

    /// A restart signal from the host, for the relay to publish; never
    /// waits for the signal's readers. A newer one replaces one not yet
    /// published, as the watch itself would.
    pub(crate) fn push_signal(&self, signal: RestartSignal) {
        *self.incoming.lock().unwrap_or_else(|e| e.into_inner()) = Some(signal);
        self.relay.notify_one();
    }

    /// Publish the host's restart signals to the session, one at a time;
    /// a publication that waits for a reader waits here, not in the loop
    /// that delivers replies.
    pub(crate) async fn relay_signals(self: Arc<Self>) {
        loop {
            self.relay.notified().await;
            let next = self
                .incoming
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take();
            if let Some(signal) = next {
                block_for(|| {
                    self.signal.send_replace(signal);
                });
            }
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// [`HostClient::call`] for a daemon-wide limit: `None` (a refusal) also
    /// when no reply came within [`HOST_SERVICE_TIMEOUT`]. A grant that
    /// arrives after that is given back with `undo`.
    fn call_within(&self, request: impl FnOnce(u64) -> ToHost, undo: ToHost) -> Option<ToOwner> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let id = {
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
            id
        };
        match block_for(|| rx.recv_timeout(HOST_SERVICE_TIMEOUT)) {
            Ok(reply) => Some(reply),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let mut pending = self.lock();
                if pending.waiters.remove(&id).is_some() {
                    // Given up: a grant that still comes is given back --
                    // unless so many went unanswered that the host is taken
                    // for unreachable: then the session ends (its late
                    // grants could no longer be given back, and would count
                    // against the account's other sessions), every later
                    // request fails at once, and the host frees whatever it
                    // granted when it reaps this owner.
                    if !pending.closed {
                        if pending.abandoned.len() >= ABANDONED_MAX {
                            drop(pending);
                            crate::log::error(
                                "owner",
                                &format!(
                                    "{} requests to the daemon went unanswered; \
                                     taking it for unreachable",
                                    ABANDONED_MAX + 1
                                ),
                            );
                            // As on `Stop`: the session sees the end before
                            // its requests fail.
                            if let Some(shutdown) = self.on_unreachable.get() {
                                shutdown.request();
                            }
                            self.close();
                        } else {
                            pending.abandoned.insert(id, undo);
                        }
                    }
                    None
                } else {
                    // The reply was handed over just now.
                    rx.try_recv().ok()
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => None,
        }
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

    /// One reply from the host, for the request it answers.
    pub(crate) fn reply(&self, reply: ToOwner) {
        let id = match &reply {
            ToOwner::About { id, .. }
            | ToOwner::Offered { id, .. }
            | ToOwner::Written { id, .. }
            | ToOwner::Verified { id, .. }
            | ToOwner::Restarted { id, .. }
            | ToOwner::ScreenAcquired { id, .. }
            | ToOwner::OpenAcquired { id, .. }
            | ToOwner::SpawnNoted { id, .. } => *id,
            _ => return,
        };
        let mut pending = self.lock();
        if let Some(waiter) = pending.waiters.remove(&id) {
            let _ = waiter.try_send(reply);
            return;
        }
        let Some(undo) = pending.abandoned.remove(&id) else {
            return;
        };
        drop(pending);
        let granted = matches!(
            reply,
            ToOwner::ScreenAcquired { result: Ok(()), .. }
                | ToOwner::OpenAcquired { granted: true, .. }
                | ToOwner::SpawnNoted { admitted: true, .. }
        );
        if granted {
            self.notify(undo);
        }
    }

    pub(crate) fn notify(&self, msg: ToHost) {
        let _ = self.out.send(msg);
    }

    /// Every outstanding and later request fails.
    pub(crate) fn close(&self) {
        let mut pending = self.lock();
        pending.closed = true;
        pending.waiters.clear();
        pending.abandoned.clear();
    }
}

/// The daemon-wide limits, seen from an owner: the host's screen pool and
/// open count (`crate::host_services`), charged by request with a bounded
/// wait (no answer in time is a refusal) and refunded by notice.
pub(crate) struct RemoteLimits(pub(crate) Arc<HostClient>);

impl ScreenPool for RemoteLimits {
    fn acquire(&self, uid: u32, slots: BackingSlots, models: usize) -> Result<(), String> {
        let reply = self.0.call_within(
            |id| ToHost::ScreenAcquire {
                id,
                uid,
                slots,
                models,
            },
            ToHost::ScreenRelease { uid, slots, models },
        );
        match reply {
            Some(ToOwner::ScreenAcquired { result, .. }) => result,
            _ => Err("terminal screen budget unavailable: the daemon did not answer".into()),
        }
    }

    fn release(&self, uid: u32, slots: BackingSlots, models: usize) {
        self.0.notify(ToHost::ScreenRelease { uid, slots, models });
    }
}

impl OpenAdmission for RemoteLimits {
    fn acquire(&self, uid: u32) -> bool {
        let reply = self.0.call_within(
            |id| ToHost::OpenAcquire { id, uid },
            ToHost::OpenRelease { uid },
        );
        matches!(reply, Some(ToOwner::OpenAcquired { granted: true, .. }))
    }

    fn charge(&self, uid: u32) {
        self.0.notify(ToHost::OpenCharge { uid });
    }

    fn release(&self, uid: u32) {
        self.0.notify(ToHost::OpenRelease { uid });
    }
}

/// The session's leaders, told to the host: a start is announced and
/// answered before anything starts (no answer within
/// [`HOST_SERVICE_TIMEOUT`]: the open is refused, and a late answer is
/// given back with `NotStarted`), then its outcome -- who leads the new
/// session -- and, once the session was proved empty, its end. All on the
/// owner's one queue to the host, in order. If this owner dies without
/// proving its cleanup, the host checks each session it was told of and
/// not told the end of (see the parent module, "Receipts").
pub(crate) struct HostLeaders(pub(crate) Arc<HostClient>);

impl crate::process_scope::LeaderReports for HostLeaders {
    fn starting(&self) -> Result<(), String> {
        let reply = self.0.call_within(
            |id| ToHost::Spawning { id },
            ToHost::Leader(crate::process_scope::LeaderStart::NotStarted),
        );
        match reply {
            Some(ToOwner::SpawnNoted { admitted: true, .. }) => Ok(()),
            Some(_) => Err(
                "the daemon refused the new session: this session already has as many \
                 shells and commands, starting or running, as the daemon keeps track of"
                    .into(),
            ),
            // `call_within` answers nothing once the session is ending, the
            // host is gone, or no answer came in time.
            None => Err(
                "the daemon did not note the new session's start: the session is ending, \
                 or the daemon did not answer in time"
                    .into(),
            ),
        }
    }

    fn started(&self, leader: crate::process_scope::LeaderStart) {
        self.0.notify(ToHost::Leader(leader));
    }

    fn ended(&self, pid: u32) {
        self.0.notify(ToHost::LeaderGone { pid });
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

    fn open_request(
        session: &transport::channel_open::SessionOpenLedger,
        instance: u64,
    ) -> transport::channel_open::OpenRequestSnapshot {
        transport::channel_open::OpenRequestSnapshot {
            owner: Principal {
                uid: 1000,
                name: "me".into(),
                identity: "fixture".into(),
                incarnation: 0,
            },
            login: [0; 16],
            request: transport::channel::OpenRequest {
                stream: 16,
                kind: transport::channel::ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: Vec::new(),
            },
            term: None,
            identity: transport::channel_open::OpenIdentity {
                session: session.id(),
                stream: 16,
                instance: transport::channel_geometry::ChannelInstance::new(instance).unwrap(),
                generation: 0,
                invalidation_epoch: 0,
            },
        }
    }

    /// A restart announcement the host sends ahead of a reply never holds
    /// that reply up, even while the session holds the signal's read side
    /// (as an open's admission guard does): the reply arrives, and the
    /// signal is published once the reader lets go.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restart_signal_never_holds_up_the_replies_behind_it() {
        use tokio::io::AsyncWriteExt;
        let (mut host_end, owner_end) = tokio::net::UnixStream::pair().unwrap();
        let (out, mut requests) = mpsc::unbounded_channel();
        let client = HostClient::new(out);
        let (read, _write) = owner_end.into_split();
        let reader = tokio::spawn(serve_host(
            read,
            client.clone(),
            OpensFence::new(ChannelOpenRegistry::new(Default::default())),
            Shutdown::default(),
            Shutdown::default(),
        ));
        let mut published = client.signal.subscribe();
        // The session holds the signal's read side...
        let (held_tx, held_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let watching = client.signal.subscribe();
        let holder = std::thread::spawn(move || {
            let guard = watching.borrow();
            held_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            drop(guard);
        });
        held_rx.recv().unwrap();
        // ...while one of its opens waits for the host.
        let asking = client.clone();
        let caller = std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let granted = OpenAdmission::acquire(&RemoteLimits(asking), 1000);
            (granted, started.elapsed())
        });
        let Some(ToHost::OpenAcquire { id, .. }) = requests.recv().await else {
            panic!("an open request")
        };
        let signal = RestartSignal::announced(1, 1);
        for frame in [
            ToOwner::Signal(signal),
            ToOwner::OpenAcquired { id, granted: true },
        ] {
            host_end.write_all(&frame.encode().unwrap()).await.unwrap();
        }
        let (granted, waited) = tokio::task::spawn_blocking(move || caller.join().unwrap())
            .await
            .unwrap();
        assert!(granted, "the reply behind the signal arrived");
        assert!(waited < HOST_SERVICE_TIMEOUT, "{waited:?}");
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        tokio::time::timeout(Duration::from_secs(2), published.wait_for(|s| *s == signal))
            .await
            .expect("published")
            .unwrap();
        drop(host_end);
        reader.await.unwrap();
    }

    /// A host that answers nothing is not waited for without bound: past
    /// `ABANDONED_MAX` requests given up on, it is taken for unreachable and
    /// every later request fails at once, unasked.
    #[test]
    fn a_host_that_never_answers_is_taken_for_unreachable() {
        let (out, mut requests) = mpsc::unbounded_channel();
        let client = HostClient::new(out);
        let shutdown = Shutdown::default();
        client.end_session_on_unreachable(shutdown.clone());
        let callers: Vec<_> = (0..=ABANDONED_MAX)
            .map(|_| {
                let client = client.clone();
                std::thread::spawn(move || OpenAdmission::acquire(&RemoteLimits(client), 1000))
            })
            .collect();
        for caller in callers {
            assert!(!caller.join().unwrap(), "unanswered: refused");
        }
        let mut asked = 0;
        while requests.try_recv().is_ok() {
            asked += 1;
        }
        assert_eq!(asked, ABANDONED_MAX + 1);
        {
            let pending = client.lock();
            assert!(pending.closed, "taken for unreachable");
            assert!(shutdown.is_requested(), "and the session ends");
            assert!(pending.abandoned.is_empty() && pending.waiters.is_empty());
        }
        let started = std::time::Instant::now();
        assert!(!OpenAdmission::acquire(&RemoteLimits(client.clone()), 1000));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(requests.try_recv().is_err(), "nothing more is asked");
    }

    /// The host's `FenceOpens` fences this owner's registry as a
    /// single-process daemon fences its own: opens are refused until
    /// `ReopenOpens`, and pending cleanup is reported, not hidden.
    #[test]
    fn a_fence_from_the_host_refuses_opens_until_it_is_lifted() {
        use transport::channel_open::OpenRefusal;
        let registry = ChannelOpenRegistry::new(Default::default());
        let session = registry.session().unwrap();
        let opens = OpensFence::new(registry.clone());
        assert_eq!(opens.fence(), Ok(()));
        assert_eq!(opens.fence(), Ok(()), "asked again: fenced afresh");
        assert!(matches!(
            registry.try_reserve(&session, open_request(&session, 1)),
            Err(OpenRefusal::Restarting)
        ));
        opens.reopen();
        let job = registry
            .try_reserve(&session, open_request(&session, 2))
            .expect("open again");
        // A cancelled open whose cleanup is not proved is cleanup debt.
        job.cancel();
        let refused = opens.fence().unwrap_err();
        assert!(refused.contains("cleanup"), "{refused}");
        assert!(
            matches!(
                registry.try_reserve(&session, open_request(&session, 3)),
                Err(OpenRefusal::Restarting)
            ),
            "fenced all the same, until the host lifts it"
        );
        opens.reopen();
        assert!(registry.begin_restart_fence().is_ok());
    }

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
        assert_eq!(relay.dropped.owed(), 0);
    }

    /// Records from several threads race each other, a reader that empties
    /// the queue, and the writer's own taking of the count: every record is
    /// accounted for exactly once -- it reached the queue, or it is in
    /// exactly one dropped-count report, or it is still owed -- and no
    /// report counts more records than there ever were (a wrapped count).
    #[test]
    fn racing_log_records_are_each_counted_once_and_the_count_never_wraps() {
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
        const WRITERS: u64 = 4;
        const EACH: u64 = 20_000;
        const ALL: u64 = WRITERS * EACH;
        let (relay, mut logs) = LogRelay::new(2);
        let writing = Arc::new(AtomicBool::new(true));
        let reported = Arc::new(AtomicU64::new(0));
        let count = |n: u64, reported: &AtomicU64| {
            assert!(n <= ALL, "a report of {n} dropped records, of {ALL} in all");
            reported.fetch_add(n, Ordering::SeqCst);
        };
        let reader = {
            let (writing, reported) = (writing.clone(), reported.clone());
            std::thread::spawn(move || {
                let mut queued = 0u64;
                loop {
                    match logs.try_recv() {
                        Ok(ToHost::Log { message, .. }) => {
                            match message.strip_suffix(
                                " owner log record(s) dropped: the queue to the daemon was full",
                            ) {
                                Some(n) => count(n.parse().unwrap(), &reported),
                                None => queued += 1,
                            }
                        }
                        Ok(other) => panic!("not a log record: {other:?}"),
                        Err(_) if writing.load(Ordering::SeqCst) => std::thread::yield_now(),
                        Err(_) => return queued,
                    }
                }
            })
        };
        let taker = {
            let (relay, writing, reported) = (relay.clone(), writing.clone(), reported.clone());
            std::thread::spawn(move || {
                while writing.load(Ordering::SeqCst) {
                    if let Some(ToHost::Log { message, .. }) = relay.take_summary() {
                        let n = message.split(' ').next().unwrap().parse().unwrap();
                        count(n, &reported);
                    }
                    std::thread::yield_now();
                }
            })
        };
        let writers: Vec<_> = (0..WRITERS)
            .map(|w| {
                let relay = relay.clone();
                std::thread::spawn(move || {
                    for n in 0..EACH {
                        relay.record(log::Level::Info, "test", &format!("{w}/{n}"));
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        writing.store(false, Ordering::SeqCst);
        taker.join().unwrap();
        let queued = reader.join().unwrap();
        if let Some(ToHost::Log { message, .. }) = relay.take_summary() {
            count(
                message.split(' ').next().unwrap().parse().unwrap(),
                &reported,
            );
        }
        assert_eq!(
            queued + reported.load(Ordering::SeqCst),
            ALL,
            "{queued} queued and {} reported dropped, of {ALL}",
            reported.load(Ordering::SeqCst)
        );
    }

    /// Everything `link` carries until it has been quiet for `quiet`, or
    /// until its end: the bytes, and whether it ended.
    async fn read_link(link: &mut tokio::net::UnixStream, quiet: Duration) -> (usize, bool) {
        use tokio::io::AsyncReadExt;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total = 0;
        loop {
            match tokio::time::timeout(quiet, link.read(&mut buf)).await {
                Err(_) => return (total, false),
                Ok(Ok(0)) | Ok(Err(_)) => return (total, true),
                Ok(Ok(n)) => total += n,
            }
        }
    }

    /// An owner whose host is gone loses its session (as a single-process
    /// daemon's death loses it): its link closes without a word more, never
    /// with `Finished`, which a frontend still reading it for a moment
    /// would take for the end of the session and tell the client so. An
    /// owner told to stop says `Finished` on its way out.
    ///
    /// The owner installs the process's log relay and its `SIGTERM` and
    /// `SIGINT` handlers for good, so the body runs in a process of its own.
    ///
    /// The test runs itself again, as its own process, with [`HOST_GONE_CHILD`]
    /// set; that run drives the owner.
    #[test]
    fn an_owner_whose_host_is_gone_closes_its_link_without_a_word() {
        if std::env::var_os(HOST_GONE_CHILD).is_some() {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(an_owner_whose_host_is_gone_closes_its_link_without_a_word_body());
            return;
        }
        let name = "owner_process::owner::tests::an_owner_whose_host_is_gone_closes_its_link_without_a_word";
        let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
            .env(HOST_GONE_CHILD, "1")
            .args([name, "--exact", "--test-threads=1", "--nocapture"])
            .output()
            .expect("run the isolated check");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stdout.contains("running 1 test\n"),
            "the filter must match exactly one test:\n{stdout}\n{stderr}"
        );
        assert!(
            out.status.success(),
            "the isolated check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Set in the process of its own that
    /// [`an_owner_whose_host_is_gone_closes_its_link_without_a_word`] starts.
    const HOST_GONE_CHILD: &str = "QSHD_TEST_OWNER_HOST_GONE_CHILD";

    /// The owner's part of
    /// [`an_owner_whose_host_is_gone_closes_its_link_without_a_word`], in its
    /// process of its own.
    async fn an_owner_whose_host_is_gone_closes_its_link_without_a_word_body() {
        use std::io::Write;
        let uid = unsafe { libc::geteuid() };
        for host_dies in [true, false] {
            let (front, owner_link) = std::os::unix::net::UnixStream::pair().unwrap();
            let (host, owner_host) = std::os::unix::net::UnixStream::pair().unwrap();
            let (_relink, owner_relink) = nix::sys::socket::socketpair(
                nix::sys::socket::AddressFamily::Unix,
                nix::sys::socket::SockType::SeqPacket,
                None,
                nix::sys::socket::SockFlag::SOCK_CLOEXEC,
            )
            .unwrap();
            let init = ToOwner::Init(HostInit {
                principal: Principal {
                    uid,
                    name: "test".into(),
                    identity: "fixture".into(),
                    incarnation: 0,
                },
                login: [9; 16],
                last_generation: 0,
                updates: false,
                log_dir: None,
            });
            let mut host = host;
            host.write_all(&init.encode().unwrap()).unwrap();
            let run = tokio::spawn(run_owner(
                OwnedFd::from(owner_link),
                OwnedFd::from(owner_host),
                owner_relink,
                std::process::id(),
                uid,
            ));
            front.set_nonblocking(true).unwrap();
            let mut front = tokio::net::UnixStream::from_std(front).unwrap();
            // The owner is up: its first credits arrive, then it is quiet.
            let (first, ended) = read_link(&mut front, Duration::from_millis(500)).await;
            assert!(first > 0 && !ended, "the owner runs its session");

            let kept = if host_dies {
                drop(host);
                None
            } else {
                host.write_all(&ToOwner::Stop.encode().unwrap()).unwrap();
                Some(host)
            };
            let (last, ended) = read_link(&mut front, Duration::from_secs(15)).await;
            assert!(ended, "the owner closes its link");
            if host_dies {
                assert_eq!(last, 0, "not a word after its host is gone");
            } else {
                assert!(last > 0, "a stop says `Finished`");
            }
            drop(kept);
            let _ = tokio::time::timeout(Duration::from_secs(15), run).await;
        }
    }
}
