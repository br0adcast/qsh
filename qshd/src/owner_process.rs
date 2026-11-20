//! Session owner processes (#529 M1): on Linux a personal daemon runs each
//! session's channel backend in an owner process of its own, the direct
//! parent of that session's shells and their PTYs.
//!
//! The daemon (the host and, for now, also the network frontend) starts one
//! owner per cold-created session, from the image it holds since its own
//! start ([`SelfImage`]), never from the path on disk: a package or update
//! that replaces the file cannot give a session another build. It starts it
//! by `posix_spawn` only -- no Rust code runs between the fork and the exec
//! -- with exactly two descriptors besides the standard ones:
//!
//! - **3**, the owner's end of the frontend/owner link
//!   (`transport::session_manager::OwnerLink`);
//! - **4**, the host channel ([`wire`]): `Init` first, then `Stop` and the
//!   restart signal from the host, update requests, `End` and the final
//!   `Drained` receipt from the owner.
//!
//! An owner that loses its link without an explicit end parks: its backend
//! and shells keep running. It ends when its session ends (the backend
//! finished), on `Stop`, on `SIGTERM`/`SIGINT`, or when the host channel
//! closes (the host died: its sessions are lost, as when a single-process
//! daemon dies). Then it drains every task and worker of its session and
//! reports `Drained` before it exits. The host reaps each owner through a
//! pidfd held from the spawn, so a reused PID is never waited for or
//! signalled.
//!
//! Daemon-wide limits (screen budget, the global control budget, open
//! limits) are, until Task 4, each owner's own: they bound one session, not
//! the daemon.
//!
//! **Queue bounds** (every IPC queue is bounded, by entry counts its
//! producers impose). Host to owner: replies, one per outstanding request;
//! `Stop`, once; restart signals, one per change of the daemon's restart
//! attempt (its phases are few and attempts serialized). Owner to host:
//! requests, at most one per blocking worker of the session waiting for its
//! reply (`About`, the one update transfer); `Joined`/`Released`, once per
//! attempt; `Abandon`, once per transfer; `End` and `Drained`, once; log
//! records in a queue of their own of 256 records, past which new ones are
//! counted and dropped -- never silently: the count goes to the daemon's
//! log as soon as the queue has room and before `Drained`, and to standard
//! error once the host channel is gone. The writer serves both queues
//! without preference, so neither starves the other. Frames read off either end wait in a 16-frame queue, behind
//! which the reader stops reading. Each frame is at most
//! [`wire::MAX_FRAME`] bytes, an image piece at most [`wire::WRITE_CHUNK`].
//!
//! **Log.** Only the daemon writes and rotates `qshd.log`: an owner sends
//! its records over the host channel, and the daemon writes them under the
//! owner's pid.
//!
//! **Receipts.** An owner proves its cleanup by `Drained(Ok)` and exit
//! status 0. One that ends otherwise (crash, kill, failed drain) leaves the
//! fleet unproved for good: STOP then fails, and an in-place update is
//! refused (`OwnerStop::proved`).

#[path = "owner_process/owner.rs"]
mod owner;
#[path = "owner_process/wire.rs"]
pub(crate) mod wire;

pub use owner::owner_entry;

use std::collections::{BTreeSet, HashMap};
use std::ffi::CString;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use nix::libc;
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use transport::channel_server::{DaemonUpdates, RestartSignal, UpdateTransfer};
use transport::session_manager::{LinkIo, OwnerInit, OwnerStarter};
use transport::Principal;

use wire::{HostInit, ToHost, ToOwner};

/// The only argument of an owner process.
pub const OWNER_ROLE: &str = "__qshd-session-owner-v1";
/// The owner's end of the frontend/owner link.
pub(crate) const LINK_FD: i32 = 3;
/// The owner's end of the host channel.
pub(crate) const HOST_FD: i32 = 4;

/// How long the host waits, after asking every owner to stop, before it
/// kills the ones still running.
const STOP_ESCALATION: Duration = Duration::from_secs(20);
/// How long, after killing them, it still waits for them to be reaped.
const KILL_GRACE: Duration = Duration::from_secs(5);

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// A duplicate of `fd` numbered 10 or above, close-on-exec: never one of
/// the numbers a spawn's file actions write to.
fn dup_high(fd: &OwnedFd) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
    if raw < 0 {
        return Err(last_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The executable image this process runs, held open since the daemon
/// started: owners exec it through `/proc/self/fd`, whatever has happened
/// to the file on disk since.
pub struct SelfImage {
    fd: OwnedFd,
}

impl SelfImage {
    /// Open `/proc/self/exe`: the running image, not the path it came from.
    pub fn hold() -> io::Result<SelfImage> {
        let path = c"/proc/self/exe";
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(last_error());
        }
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(SelfImage { fd: dup_high(&fd)? })
    }

    /// Another descriptor of the same image.
    pub fn try_clone(&self) -> io::Result<SelfImage> {
        Ok(SelfImage {
            fd: dup_high(&self.fd)?,
        })
    }
}

/// A started owner process: unreaped, with the host's ends of its link and
/// of its host channel.
pub struct OwnerChild {
    pub pid: u32,
    /// Refers to exactly this child for as long as it is held, reaped or not.
    pub pidfd: OwnedFd,
    /// The frontend's end of the frontend/owner link.
    pub link: UnixStream,
    /// The host's end of the host channel; `Init` is already in it.
    pub host: UnixStream,
}

struct SpawnActions(libc::posix_spawn_file_actions_t);
impl Drop for SpawnActions {
    fn drop(&mut self) {
        unsafe { libc::posix_spawn_file_actions_destroy(&mut self.0) };
    }
}
struct SpawnAttr(libc::posix_spawnattr_t);
impl Drop for SpawnAttr {
    fn drop(&mut self) {
        unsafe { libc::posix_spawnattr_destroy(&mut self.0) };
    }
}

fn check(rc: libc::c_int) -> io::Result<()> {
    if rc == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(rc))
    }
}

fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if raw < 0 {
        return Err(last_error());
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw as i32) })
}

fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag, SockType};
    socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::SOCK_CLOEXEC,
    )
    .map_err(io::Error::from)
}

/// Start one session owner from `image`.
///
/// Everything the child needs is prepared here, in the parent: the
/// arguments, the environment (without the reserved launch and handover
/// variables), the file actions that put the two channel ends on 3 and 4
/// and `/dev/null` on standard input and output, default dispositions for
/// every signal (so `SIGCHLD` does not auto-reap) and an empty signal mask,
/// and a process group of its own (a terminal's `^C` meant for a foreground
/// `serve` goes to the daemon, which stops the owners itself). Then one
/// `posix_spawn`, under the daemon's spawn permit (which the caller holds,
/// proven by `_permit`) so no exec window is open meanwhile.
pub(crate) fn spawn_owner(
    image: &SelfImage,
    init: &HostInit,
    _permit: &std::sync::RwLockReadGuard<'static, ()>,
) -> io::Result<OwnerChild> {
    use std::os::unix::ffi::OsStrExt;
    let (link_front, link_owner) = socket_pair()?;
    let (host_host, host_owner) = socket_pair()?;
    let link_owner = dup_high(&link_owner)?;
    let host_owner = dup_high(&host_owner)?;
    let mut host = UnixStream::from(host_host);
    // Small, into an empty socket buffer: it waits for the owner there.
    host.write_all(
        &ToOwner::Init(init.clone())
            .encode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
    )?;

    let to_c = |bytes: &[u8]| {
        CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    };
    let program = to_c(format!("/proc/self/fd/{}", image.fd.as_raw_fd()).as_bytes())?;
    let args = [to_c(b"qshd")?, to_c(OWNER_ROLE.as_bytes())?];
    let mut env = Vec::new();
    for (name, value) in std::env::vars_os() {
        if name == crate::service_stage::LAUNCH_ENV || name == crate::handover::HANDOVER_FD_ENV {
            continue;
        }
        let mut entry = name.as_bytes().to_vec();
        entry.push(b'=');
        entry.extend_from_slice(value.as_bytes());
        if let Ok(entry) = CString::new(entry) {
            env.push(entry);
        }
    }
    let mut argv: Vec<*mut libc::c_char> = args
        .iter()
        .map(|a| a.as_ptr() as *mut libc::c_char)
        .collect();
    argv.push(std::ptr::null_mut());
    let mut envp: Vec<*mut libc::c_char> = env
        .iter()
        .map(|e| e.as_ptr() as *mut libc::c_char)
        .collect();
    envp.push(std::ptr::null_mut());
    let null = c"/dev/null";

    let mut actions = SpawnActions(unsafe { std::mem::zeroed() });
    check(unsafe { libc::posix_spawn_file_actions_init(&mut actions.0) })?;
    check(unsafe {
        libc::posix_spawn_file_actions_adddup2(&mut actions.0, link_owner.as_raw_fd(), LINK_FD)
    })?;
    check(unsafe {
        libc::posix_spawn_file_actions_adddup2(&mut actions.0, host_owner.as_raw_fd(), HOST_FD)
    })?;
    check(unsafe {
        libc::posix_spawn_file_actions_addopen(&mut actions.0, 0, null.as_ptr(), libc::O_RDONLY, 0)
    })?;
    check(unsafe {
        libc::posix_spawn_file_actions_addopen(&mut actions.0, 1, null.as_ptr(), libc::O_WRONLY, 0)
    })?;
    let mut attr = SpawnAttr(unsafe { std::mem::zeroed() });
    check(unsafe { libc::posix_spawnattr_init(&mut attr.0) })?;
    let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
    let mut defaults: libc::sigset_t = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut mask);
        libc::sigfillset(&mut defaults);
    }
    check(unsafe { libc::posix_spawnattr_setsigmask(&mut attr.0, &mask) })?;
    check(unsafe { libc::posix_spawnattr_setsigdefault(&mut attr.0, &defaults) })?;
    check(unsafe { libc::posix_spawnattr_setpgroup(&mut attr.0, 0) })?;
    check(unsafe {
        libc::posix_spawnattr_setflags(
            &mut attr.0,
            (libc::POSIX_SPAWN_SETSIGMASK
                | libc::POSIX_SPAWN_SETSIGDEF
                | libc::POSIX_SPAWN_SETPGROUP) as libc::c_short,
        )
    })?;

    let mut pid: libc::pid_t = 0;
    let rc = {
        unsafe {
            libc::posix_spawn(
                &mut pid,
                program.as_ptr(),
                &actions.0,
                &attr.0,
                argv.as_ptr(),
                envp.as_ptr(),
            )
        }
    };
    check(rc)?;
    // Our unreaped child: the number cannot name anything else yet.
    let pidfd = match pidfd_open(pid) {
        Ok(fd) => fd,
        Err(error) => {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, std::ptr::null_mut(), 0);
            }
            return Err(error);
        }
    };
    drop((link_owner, host_owner));
    Ok(OwnerChild {
        pid: pid as u32,
        pidfd,
        link: UnixStream::from(link_front),
        host,
    })
}

// ---- the owners of one daemon ------------------------------------------------

struct OwnerSlot {
    stop: tokio::sync::Notify,
    stopping: AtomicBool,
    /// Already counted as unproved (given up on by a stop): its later reap
    /// is not counted again.
    counted: AtomicBool,
    /// A duplicate of the supervisor's pidfd, for the kill on escalation.
    pidfd: OwnedFd,
}

impl OwnerSlot {
    fn request_stop(&self) {
        if !self.stopping.swap(true, Ordering::SeqCst) {
            self.stop.notify_one();
        }
    }
    fn kill(&self) {
        // A pidfd never signals a reused PID: once reaped, this is ESRCH.
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                self.pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
    }
}

#[derive(Default)]
struct FleetState {
    /// No new owner is started: the daemon is stopping or replacing itself.
    closed: bool,
    owners: HashMap<u32, Arc<OwnerSlot>>,
    /// Owners that ended without proving their cleanup (no `Drained(Ok)`,
    /// a non-zero exit, a kill), and why the last one did not. Sticky: their
    /// shells may live on under whoever adopted them.
    unproved: u64,
    last_unproved: Option<String>,
}

/// Every owner process a daemon has started and not yet reaped, and
/// whether every one that ended proved its cleanup.
#[derive(Default)]
pub struct OwnerFleet {
    state: Mutex<FleetState>,
    /// An owner was reaped (async waiters).
    gone: tokio::sync::Notify,
    /// The same, for blocking waiters on `state`.
    gone_cv: std::sync::Condvar,
}

impl OwnerFleet {
    pub fn new() -> Arc<OwnerFleet> {
        Arc::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FleetState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Owners not yet reaped.
    pub fn len(&self) -> usize {
        self.lock().owners.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Count `slot`'s owner as unproved, once whatever happens later.
    fn count_unproved(state: &mut FleetState, slot: &OwnerSlot, why: String) {
        if !slot.counted.swap(true, Ordering::SeqCst) {
            state.unproved += 1;
            state.last_unproved = Some(why);
        }
    }

    /// `pid` was reaped; `cleanup` is whether it proved its cleanup.
    fn remove(&self, pid: u32, slot: &OwnerSlot, cleanup: Result<(), String>) {
        {
            let mut state = self.lock();
            state.owners.remove(&pid);
            if let Err(why) = cleanup {
                Self::count_unproved(&mut state, slot, why);
            }
        }
        self.gone.notify_waiters();
        self.gone_cv.notify_all();
    }

    fn cleanup_result(state: &FleetState) -> Result<(), String> {
        match state.unproved {
            0 => Ok(()),
            n => Err(format!(
                "{n} session owner(s) ended without proving their cleanup (last: {})",
                state.last_unproved.as_deref().unwrap_or("unknown")
            )),
        }
    }

    /// Refuse new owners and ask each running one to stop.
    fn close_and_stop(&self) {
        let mut state = self.lock();
        state.closed = true;
        for slot in state.owners.values() {
            slot.request_stop();
        }
    }

    /// STOP: refuse new owners, stop every one and wait until each has been
    /// reaped -- after its `Drained` receipt, or, for one that does not
    /// stop within [`STOP_ESCALATION`], after it was killed. `Err` unless
    /// every owner this daemon ever started proved its cleanup: one that
    /// crashed earlier, was killed now, or drained with a failure fails the
    /// stop, as a failed worker join failed a single-process daemon's.
    pub async fn stop_all(&self) -> Result<(), String> {
        self.close_and_stop();
        let started = tokio::time::Instant::now();
        let escalate_at = started + STOP_ESCALATION;
        let give_up = escalate_at + KILL_GRACE;
        let mut killed = false;
        loop {
            let gone = self.gone.notified();
            tokio::pin!(gone);
            gone.as_mut().enable();
            let left: Vec<Arc<OwnerSlot>> = self.lock().owners.values().cloned().collect();
            if left.is_empty() {
                break;
            }
            let now = tokio::time::Instant::now();
            if !killed && now >= escalate_at {
                crate::log::warn(
                    "qshd",
                    &format!(
                        "{} session owner(s) did not stop within {} s; killing them",
                        left.len(),
                        STOP_ESCALATION.as_secs()
                    ),
                );
                for slot in &left {
                    slot.kill();
                }
                killed = true;
            }
            if now >= give_up {
                let why = format!(
                    "{} session owner(s) were not reaped after a kill",
                    left.len()
                );
                crate::log::error("qshd", &why);
                let mut state = self.lock();
                for slot in &left {
                    Self::count_unproved(&mut state, slot, why.clone());
                }
                break;
            }
            // Woken by a reap, or at the next deadline: no polling.
            let deadline = if killed { give_up } else { escalate_at };
            let _ = tokio::time::timeout_at(deadline, gone).await;
        }
        Self::cleanup_result(&self.lock())
    }
}

impl crate::update::OwnerStop for OwnerFleet {
    fn proved(&self) -> bool {
        self.lock().unproved == 0
    }

    fn stop_all_until(&self, deadline: Instant) -> bool {
        self.close_and_stop();
        let mut state = self.lock();
        while !state.owners.is_empty() {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            state = self
                .gone_cv
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        state.unproved == 0
    }

    fn reopen(&self) {
        self.lock().closed = false;
    }
}

/// The host side of a personal daemon's owners: it starts one per session
/// (as the frontend's [`OwnerStarter`]) and serves each one's host channel.
pub struct OwnerHost {
    image: SelfImage,
    log_dir: Option<PathBuf>,
    daemon: Option<Arc<dyn DaemonUpdates>>,
    fleet: Arc<OwnerFleet>,
}

impl OwnerHost {
    pub fn new(
        image: SelfImage,
        log_dir: Option<PathBuf>,
        daemon: Option<Arc<dyn DaemonUpdates>>,
        fleet: Arc<OwnerFleet>,
    ) -> OwnerHost {
        OwnerHost {
            image,
            log_dir,
            daemon,
            fleet,
        }
    }
}

impl OwnerStarter for OwnerHost {
    fn start(&self, init: OwnerInit) -> io::Result<Box<dyn LinkIo>> {
        let host_init = HostInit {
            principal: init.principal.clone(),
            login: init.login,
            last_generation: init.last_generation,
            updates: self.daemon.is_some(),
            log_dir: self.log_dir.clone(),
        };
        let (child, slot) = {
            // The permit first, then the fleet: a replacement holds the
            // spawn gate for writing while it stops the fleet, so the other
            // order could deadlock.
            let permit = crate::update::spawn_permit();
            // Checked and registered under one lock: a stop that closes the
            // fleet either sees this owner or this start sees it closed.
            let mut state = self.fleet.lock();
            if state.closed {
                return Err(io::Error::other("the daemon is stopping"));
            }
            let child = spawn_owner(&self.image, &host_init, &permit)?;
            drop(permit);
            let pidfd = match child.pidfd.try_clone() {
                Ok(pidfd) => pidfd,
                Err(error) => {
                    // Not registered, so nobody else would ever reap it.
                    unsafe {
                        libc::kill(child.pid as libc::pid_t, libc::SIGKILL);
                        libc::waitpid(child.pid as libc::pid_t, std::ptr::null_mut(), 0);
                    }
                    return Err(error);
                }
            };
            let slot = Arc::new(OwnerSlot {
                stop: tokio::sync::Notify::new(),
                stopping: AtomicBool::new(false),
                counted: AtomicBool::new(false),
                pidfd,
            });
            state.owners.insert(child.pid, slot.clone());
            (child, slot)
        };
        crate::log::info(
            "qshd",
            &format!(
                "session owner {} started for {} (uid {})",
                child.pid, init.principal.name, init.principal.uid
            ),
        );
        let OwnerChild {
            pid,
            pidfd,
            link,
            host,
        } = child;
        tokio::spawn(supervise(Supervised {
            fleet: self.fleet.clone(),
            slot: slot.clone(),
            pid,
            pidfd,
            host,
            daemon: self.daemon.clone(),
            principal: init.principal,
        }));
        let link = link
            .set_nonblocking(true)
            .and_then(|()| tokio::net::UnixStream::from_std(link));
        match link {
            Ok(link) => Ok(Box::new(link)),
            Err(error) => {
                slot.request_stop();
                Err(error)
            }
        }
    }
}

// ---- one owner's host channel ------------------------------------------------

struct Supervised {
    fleet: Arc<OwnerFleet>,
    slot: Arc<OwnerSlot>,
    pid: u32,
    pidfd: OwnedFd,
    host: UnixStream,
    daemon: Option<Arc<dyn DaemonUpdates>>,
    principal: Principal,
}

type Transfers = Arc<Mutex<HashMap<u64, Box<dyn UpdateTransfer>>>>;

/// Write `frames` until the sender is gone or a write fails.
pub(crate) async fn write_frames<W, M>(
    mut write: W,
    mut frames: mpsc::UnboundedReceiver<M>,
    encode: fn(&M) -> Result<Vec<u8>, wire::WireError>,
) where
    W: AsyncWrite + Unpin,
{
    while let Some(msg) = frames.recv().await {
        let Ok(bytes) = encode(&msg) else {
            crate::log::error("qshd", "a host channel message exceeds its frame bound");
            break;
        };
        if write.write_all(&bytes).await.is_err() {
            break;
        }
    }
    let _ = write.shutdown().await;
}

/// Read frames into `tx` until end of input or an error.
pub(crate) async fn read_frames<R, M>(
    mut read: R,
    tx: mpsc::Sender<M>,
    decode: fn(&[u8]) -> Result<M, wire::WireError>,
) where
    R: tokio::io::AsyncRead + Unpin,
{
    loop {
        match wire::read_frame(&mut read).await {
            Ok(Some(body)) => match decode(&body) {
                Ok(msg) => {
                    if tx.send(msg).await.is_err() {
                        return;
                    }
                }
                Err(error) => {
                    crate::log::error("qshd", &format!("host channel: {error}"));
                    return;
                }
            },
            Ok(None) => return,
            Err(error) => {
                crate::log::warn("qshd", &format!("host channel read failed: {error}"));
                return;
            }
        }
    }
}

async fn signal_changed(
    rx: &mut Option<tokio::sync::watch::Receiver<RestartSignal>>,
) -> RestartSignal {
    if let Some(rx) = rx {
        if rx.changed().await.is_ok() {
            return *rx.borrow_and_update();
        }
    }
    std::future::pending().await
}

/// Serve one owner's host channel until the owner closes it, then reap the
/// owner and take it off the fleet.
async fn supervise(s: Supervised) {
    let Supervised {
        fleet,
        slot,
        pid,
        pidfd,
        host,
        daemon,
        principal,
    } = s;
    let host = host
        .set_nonblocking(true)
        .and_then(|()| tokio::net::UnixStream::from_std(host));
    let (mut frames, out) = match host {
        Ok(host) => {
            let (read, write) = host.into_split();
            let (in_tx, in_rx) = mpsc::channel(16);
            tokio::spawn(read_frames(read, in_tx, ToHost::decode));
            let (out, out_rx) = mpsc::unbounded_channel::<ToOwner>();
            tokio::spawn(write_frames(write, out_rx, ToOwner::encode));
            (Some(in_rx), Some(out))
        }
        Err(error) => {
            crate::log::error(
                "qshd",
                &format!("session owner {pid}: no host channel ({error})"),
            );
            slot.kill();
            (None, None)
        }
    };
    let mut signal = daemon.as_ref().map(|d| d.restart_signal());
    if let (Some(rx), Some(out)) = (signal.as_mut(), out.as_ref()) {
        let _ = out.send(ToOwner::Signal(*rx.borrow_and_update()));
    }
    let transfers: Transfers = Arc::default();
    let mut next_transfer = 0u64;
    let mut joined = BTreeSet::new();
    let mut receipt: Option<Result<(), String>> = None;
    let mut stop_sent = false;
    while let (Some(rx), Some(out)) = (frames.as_mut(), out.as_ref()) {
        let msg = tokio::select! {
            _ = slot.stop.notified(), if !stop_sent => {
                stop_sent = true;
                let _ = out.send(ToOwner::Stop);
                continue;
            }
            changed = signal_changed(&mut signal) => {
                let _ = out.send(ToOwner::Signal(changed));
                continue;
            }
            msg = rx.recv() => msg,
        };
        let Some(msg) = msg else { break };
        match msg {
            ToHost::About { id } => {
                let daemon = daemon.clone();
                let out = out.clone();
                tokio::task::spawn_blocking(move || {
                    let about = daemon.and_then(|d| d.about());
                    let _ = out.send(ToOwner::About { id, about });
                });
            }
            ToHost::Offer { id, offer } => {
                let daemon = daemon.clone();
                let out = out.clone();
                let transfers = transfers.clone();
                let principal = principal.clone();
                next_transfer += 1;
                let transfer = next_transfer;
                tokio::task::spawn_blocking(move || {
                    let result = match daemon {
                        None => Err(transport::channel::UpdateAnswer::NotAllowed),
                        Some(d) => d.offer(&principal, &offer).map(|staged| {
                            transfers
                                .lock()
                                .unwrap_or_else(|e| e.into_inner())
                                .insert(transfer, staged);
                            transfer
                        }),
                    };
                    let _ = out.send(ToOwner::Offered { id, result });
                });
            }
            ToHost::Write {
                id,
                transfer,
                bytes,
            } => {
                let (out, transfers) = (out.clone(), transfers.clone());
                tokio::task::spawn_blocking(move || {
                    let result = with_transfer(&transfers, transfer, |t| t.write(&bytes))
                        .unwrap_or_else(|| Err("no such transfer".into()));
                    let _ = out.send(ToOwner::Written { id, result });
                });
            }
            ToHost::Verify { id, transfer } => {
                let (out, transfers) = (out.clone(), transfers.clone());
                tokio::task::spawn_blocking(move || {
                    let result = with_transfer(&transfers, transfer, |t| t.verify())
                        .unwrap_or_else(|| {
                            Err(transport::channel::UpdateResult::Rejected {
                                code: transport::channel::RejectCode::Other,
                                detail: "no such transfer".into(),
                            })
                        });
                    let _ = out.send(ToOwner::Verified { id, result });
                });
            }
            ToHost::Restart { id, transfer } => {
                let (out, transfers) = (out.clone(), transfers.clone());
                tokio::task::spawn_blocking(move || {
                    let staged = transfers
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .remove(&transfer);
                    // Returns only if the daemon was not replaced.
                    let result = match staged {
                        Some(staged) => staged.restart(),
                        None => transport::channel::UpdateResult::Rejected {
                            code: transport::channel::RejectCode::Other,
                            detail: "no such transfer".into(),
                        },
                    };
                    let _ = out.send(ToOwner::Restarted { id, result });
                });
            }
            ToHost::Abandon { transfer } => {
                let staged = transfers
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .remove(&transfer);
                // Removing a staged file is blocking work.
                tokio::task::spawn_blocking(move || drop(staged));
            }
            ToHost::Joined { restart } => {
                if daemon.as_ref().is_some_and(|d| d.restart_joined(restart)) {
                    joined.insert(restart);
                    // Attempts are numbered upwards; older ones are over.
                    while joined.len() > 8 {
                        joined.pop_first();
                    }
                }
            }
            ToHost::Released { restart } => {
                // Only a counted join is confirmed, or the drain could end
                // while a counted session still reaps.
                if joined.remove(&restart) {
                    if let Some(d) = &daemon {
                        d.channels_released(restart);
                    }
                }
            }
            ToHost::End => {
                crate::log::info("qshd", &format!("session owner {pid}: session ended"));
                // No longer a session that a restart waits for.
                signal = None;
            }
            ToHost::Drained(result) => receipt = Some(result),
            ToHost::Log {
                level,
                component,
                message,
            } => crate::log::record_from(pid, level, &component, &message),
        }
    }
    drop(signal);
    drop(out);
    // The owner closed its channel: it has exited or is about to.
    let (status, exited_cleanly) = reap(pid, pidfd).await;
    let proved = exited_cleanly && matches!(receipt, Some(Ok(())));
    let receipt = match receipt {
        Some(Ok(())) => "drained".to_string(),
        Some(Err(detail)) => format!("drained with an error: {detail}"),
        None => "no receipt".to_string(),
    };
    let text = format!("session owner {pid} exited ({status}); {receipt}");
    if proved {
        crate::log::info("qshd", &text);
    } else {
        crate::log::warn("qshd", &text);
    }
    let left = std::mem::take(&mut *transfers.lock().unwrap_or_else(|e| e.into_inner()));
    if !left.is_empty() {
        let _ = tokio::task::spawn_blocking(move || drop(left)).await;
    }
    fleet.remove(pid, &slot, if proved { Ok(()) } else { Err(text) });
}

fn with_transfer<T>(
    transfers: &Transfers,
    id: u64,
    op: impl FnOnce(&mut Box<dyn UpdateTransfer>) -> T,
) -> Option<T> {
    let mut staged = transfers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id)?;
    let result = op(&mut staged);
    transfers
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, staged);
    Some(result)
}

/// Wait for exactly this child to exit, then reap it: how it ended, and
/// whether that was exit status 0.
async fn reap(pid: u32, pidfd: OwnedFd) -> (String, bool) {
    // SAFETY: the pidfd is owned by the `AsyncFd` and stays open for as
    // long as it is registered.
    match unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(pidfd, tokio::io::Interest::READABLE)
    } {
        Ok(fd) => {
            let _ = fd.readable().await;
        }
        Err(_) => {
            // Not pollable: wait on a blocking thread instead.
        }
    }
    let pid = pid as libc::pid_t;
    let status = tokio::task::spawn_blocking(move || {
        let mut status = 0;
        loop {
            if unsafe { libc::waitpid(pid, &mut status, 0) } == pid {
                return Ok(status);
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
    })
    .await;
    match status {
        Ok(Ok(status)) => {
            if libc::WIFEXITED(status) {
                (
                    format!("exit {}", libc::WEXITSTATUS(status)),
                    libc::WEXITSTATUS(status) == 0,
                )
            } else if libc::WIFSIGNALED(status) {
                (format!("signal {}", libc::WTERMSIG(status)), false)
            } else {
                (format!("status {status}"), false)
            }
        }
        Ok(Err(error)) => (format!("wait failed: {error}"), false),
        Err(error) => (format!("wait failed: {error}"), false),
    }
}
