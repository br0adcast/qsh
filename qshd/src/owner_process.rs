//! Session owner processes (#529 M1): on Linux a personal daemon runs each
//! session's channel backend in an owner process of its own, the direct
//! parent of that session's shells and their PTYs.
//!
//! The daemon -- the host ([`crate::host`]), whose network frontend is a
//! process of its own -- starts one owner per cold-created session, from
//! the image it holds since its own start ([`SelfImage`]), never from the
//! path on disk: a package or update that replaces the file cannot give a
//! session another build. It starts it by `posix_spawn` only -- no Rust code
//! runs between the fork and the exec -- with exactly three descriptors
//! besides the standard ones:
//!
//! - **3**, the owner's end of the frontend/owner link
//!   (`transport::session_manager::OwnerLink`); the host passes the other
//!   end to its frontend process;
//! - **4**, the host channel ([`wire`]): `Init` first, then `Stop` and the
//!   restart signal from the host, update requests, `End` and the final
//!   `Drained` receipt from the owner;
//! - **5**, the relink channel: a sequenced-packet socket over which the
//!   host passes the owner, one descriptor per packet, the owner's end of
//!   each link that replaces its current one.
//!
//! **Replaced links.** A link carries one attachment of the frontend's
//! bridge. At every warm reattach the frontend retires the session's link
//! in order and asks the host for a new one: the host makes the socket
//! pair, passes the owner its end over the relink channel and the frontend
//! the other. The owner replays its custody on it, and the frontend builds
//! the new connection's bridge from that replay. A link that is lost -- the
//! socket died, or its frontend process did -- is replaced the same way at
//! the client's next warm return, also through a frontend process that did
//! not exist when the session began: until then the owner keeps the
//! session's backend and shells running, and everything they send. An owner ends when its session ends
//! (the backend finished), on `Stop`, on `SIGTERM`/`SIGINT`, or when the
//! host channel closes (the host died: its sessions are lost, as when a
//! single-process daemon dies). Then it drains every task and worker of its session and
//! reports `Drained` before it exits. The host reaps each owner through a
//! pidfd held from the spawn, so a reused PID is never waited for or
//! signalled.
//!
//! **Daemon-wide limits** are the host's, once for all owners
//! ([`crate::host_services`]): the host takes a control budget envelope
//! before it starts an owner (none free: no owner, and the session ends at
//! once); it stops counting against the session caps when the session
//! ends, and is given back for good when the host has reaped the owner. The
//! owner runs its session within that one envelope. The screen pool and the open count
//! are charged over the host channel (`ScreenAcquire`/`OpenAcquire`, each
//! answered, a refusal also when no answer comes within
//! [`crate::host_services::HOST_SERVICE_TIMEOUT`]) and refunded by notice
//! (`ScreenRelease`, `OpenCharge`/`OpenRelease`). Whatever an owner still
//! holds when it is reaped -- crashed, killed or not -- the host frees then.
//!
//! **Restart fence.** Before an in-place replacement announces itself it
//! fences channel opening in every owner, as in its own registry:
//! `FenceOpens` to each (and to each one started while the fence stands),
//! answered by `OpensFenced` once the owner's own registry is fenced, with
//! no channel cleanup pending there; a replacement that does not happen
//! lifts it again (`ReopenOpens`).
//!
//! **Queue bounds** (every IPC queue is bounded, by entry counts its
//! producers impose). Host to owner: replies, one per outstanding request;
//! `Stop`, once; restart signals, one per change of the daemon's restart
//! attempt (its phases are few and attempts serialized); `FenceOpens` and
//! `ReopenOpens`, one per change of the fence (attempts are serialized).
//! Owner to host:
//! requests, at most one per blocking worker of the session waiting for its
//! reply (`About`, the one update transfer, limit requests); limit refunds,
//! one per charge the host granted (a grant that comes after its request
//! timed out is refunded once it comes); `OpensFenced`, one per
//! `FenceOpens`; `Joined`/`Released`, once per
//! attempt; `Abandon`, once per transfer; `Spawning`, a request, one per
//! session leader about to start, and `Leader`, one per `Spawning` the host
//! noted (a late note is given back the same way); `LeaderGone`, one per
//! leader started; `End` and `Drained`, once; log
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
//! status 0. One that ends otherwise (crash, kill, failed drain) may have
//! left processes of its sessions running under whoever adopted them, so
//! the host checks each such session itself. It knows them: before an
//! owner starts a session leader (a channel's shell or command, which
//! leads a session of its own) it announces the start (`Spawning`) and
//! waits for the host to note it, then reports who leads the new session
//! (`Leader`: its pid -- the session's ID -- and its start time from
//! procfs), and the end once its own cleanup proved that session empty and
//! reaped the leader (`LeaderGone`). Every session the host was told of and
//! not told the end of stays *unproved* until a census of `/proc` finds no
//! process in it ([`crate::process_scope::census_sessions`]: bounded in
//! time and walks, never a polling loop, and any process with that session
//! ID keeps it unproved, also one that reused the number). The host checks
//! once when it reaps the owner -- an owner killed with nothing left
//! behind is proved at once -- and again at every `STATUS`, every update's
//! check (`OwnerStop::proved`, `OwnerStop::stop_all_until`) and the end of
//! a stop ([`OwnerFleet::stop_all`]). A check that fails or runs out of
//! time leaves the session unproved. The host never kills anything here:
//! the user ends what is left, and the next check proves it.
//!
//! While anything is unproved, STOP fails and an in-place update is
//! refused, each naming the sessions and what still runs in them; so does
//! `STATUS` (`cleanup`). An owner that died after announcing a leader and
//! before reporting it -- the window between the host's note and the
//! report, around the fork -- or that reported one with no exact identity,
//! leaves a session whose ID the host never learned: that one stays
//! unproved for the daemon's life.

#[path = "owner_process/owner.rs"]
pub(crate) mod owner;
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
use transport::session_manager::OwnerInit;
use transport::Principal;

use crate::host_services::{HostServices, OwnerAccount};
use wire::{HostInit, ToHost, ToOwner};

/// The only argument of an owner process.
pub const OWNER_ROLE: &str = "__qshd-session-owner-v1";
/// The owner's end of the frontend/owner link.
pub(crate) const LINK_FD: i32 = 3;
/// The owner's end of the host channel.
pub(crate) const HOST_FD: i32 = 4;
/// The owner's end of the relink channel.
pub(crate) const RELINK_FD: i32 = 5;

/// How long the host waits, after asking every owner to stop, before it
/// kills the ones still running.
const STOP_ESCALATION: Duration = Duration::from_secs(20);
/// How long, after killing them, it still waits for them to be reaped.
const KILL_GRACE: Duration = Duration::from_secs(5);
/// Most owner processes a host keeps unreaped at once, ending ones
/// included: past it, no new session gets an owner (`Full`). A session
/// stops counting against the session caps when it ends, while its owner
/// still drains; this bounds those owners by count, as the stop escalation
/// bounds each one in time. Twice the daemon's session cap: room for every
/// session it may hold and as many again ending, so no ordinary churn of
/// sessions ever meets it.
pub(crate) const MAX_OWNERS: usize = 2 * transport::session_manager::MAX_SESSIONS_TOTAL;

fn last_error() -> io::Error {
    io::Error::last_os_error()
}

/// A duplicate of `fd` numbered 10 or above, close-on-exec: never one of
/// the numbers a spawn's file actions write to.
pub(crate) fn dup_high(fd: &impl AsRawFd) -> io::Result<OwnedFd> {
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
    /// The daemon's end of the relink channel.
    pub relink: OwnedFd,
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

pub(crate) fn socket_pair_of(kind: nix::sys::socket::SockType) -> io::Result<(OwnedFd, OwnedFd)> {
    use nix::sys::socket::{socketpair, AddressFamily, SockFlag};
    socketpair(AddressFamily::Unix, kind, None, SockFlag::SOCK_CLOEXEC).map_err(io::Error::from)
}

pub(crate) fn socket_pair() -> io::Result<(OwnedFd, OwnedFd)> {
    socket_pair_of(nix::sys::socket::SockType::Stream)
}

/// How long a frontend that lost a link waits to see its owner's exit
/// before it takes the owner for alive: a dying process closes its sockets
/// a moment before its exit shows.
const OWNER_EXIT_GRACE: Duration = Duration::from_millis(500);

/// Whether the owner `pidfd` refers to has exited, waiting at most
/// [`OWNER_EXIT_GRACE`] for an exit that is under way to show.
pub(crate) async fn owner_exited(pidfd: &OwnedFd) -> bool {
    let Ok(pidfd) = pidfd.try_clone() else {
        return false;
    };
    // SAFETY: the duplicate is owned by the `AsyncFd` and stays open for as
    // long as it is registered.
    let registered = unsafe {
        tokio::io::unix::AsyncFd::register_with_interest(pidfd, tokio::io::Interest::READABLE)
    };
    let Ok(pidfd) = registered else {
        return false;
    };
    // A pidfd reads as ready once its process has exited.
    tokio::time::timeout(OWNER_EXIT_GRACE, pidfd.readable())
        .await
        .is_ok()
}

/// Pass `descriptor` over `channel` in one packet, without waiting.
pub(crate) fn send_descriptor(channel: &OwnedFd, descriptor: &OwnedFd) -> io::Result<()> {
    let byte = [0u8; 1];
    let mut vector = libc::iovec {
        iov_base: byte.as_ptr() as *mut libc::c_void,
        iov_len: byte.len(),
    };
    // Aligned for a control header, and large enough for one descriptor.
    let mut control = [0u64; 4];
    // SAFETY: a fixed, small argument.
    let space = unsafe { libc::CMSG_SPACE(size_of::<libc::c_int>() as libc::c_uint) } as usize;
    assert!(space <= size_of_val(&control));
    // SAFETY: an all-zero `msghdr` has no address and no control data.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = space as _;
    // SAFETY: `control` is zeroed, aligned and `space` bytes long, so the
    // first header and its one integer of data lie inside it.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<libc::c_int>() as libc::c_uint) as _;
        std::ptr::write_unaligned(
            libc::CMSG_DATA(header).cast::<libc::c_int>(),
            descriptor.as_raw_fd(),
        );
    }
    // SAFETY: every pointer in `message` refers to a live local.
    let sent = unsafe {
        libc::sendmsg(
            channel.as_raw_fd(),
            &message,
            libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
        )
    };
    if sent < 0 {
        return Err(last_error());
    }
    Ok(())
}

/// Start this daemon's image in `role` (its only argument), with each of
/// `descriptors` on the number given with it -- every source numbered 10 or
/// above (`dup_high`), so no action overwrites one -- `/dev/null` on
/// standard input and output, the daemon's environment without the
/// reserved launch and handover variables, default dispositions for every
/// signal (so `SIGCHLD` does not auto-reap), an empty signal mask, and a
/// process group of its own. One `posix_spawn`, under the daemon's spawn
/// permit (`_permit`), so no exec window is open meanwhile. Returns the
/// unreaped child's pid and a descriptor that refers to exactly it.
pub(crate) fn spawn_role(
    image: &SelfImage,
    role: &str,
    descriptors: &[(&OwnedFd, i32)],
    _permit: &std::sync::RwLockReadGuard<'static, ()>,
) -> io::Result<(u32, OwnedFd)> {
    use std::os::unix::ffi::OsStrExt;
    debug_assert!(descriptors.iter().all(|(fd, _)| fd.as_raw_fd() >= 10));
    let to_c = |bytes: &[u8]| {
        CString::new(bytes).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
    };
    let program = to_c(format!("/proc/self/fd/{}", image.fd.as_raw_fd()).as_bytes())?;
    let args = [to_c(b"qshd")?, to_c(role.as_bytes())?];
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
    for (descriptor, number) in descriptors {
        check(unsafe {
            libc::posix_spawn_file_actions_adddup2(&mut actions.0, descriptor.as_raw_fd(), *number)
        })?;
    }
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
    Ok((pid as u32, pidfd))
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
    let (link_front, link_owner) = socket_pair()?;
    let (host_host, host_owner) = socket_pair()?;
    let (relink_host, relink_owner) = socket_pair_of(nix::sys::socket::SockType::SeqPacket)?;
    let link_owner = dup_high(&link_owner)?;
    let host_owner = dup_high(&host_owner)?;
    let relink_owner = dup_high(&relink_owner)?;
    let mut host = UnixStream::from(host_host);
    // Small, into an empty socket buffer: it waits for the owner there.
    host.write_all(
        &ToOwner::Init(init.clone())
            .encode()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
    )?;

    let (pid, pidfd) = spawn_role(
        image,
        OWNER_ROLE,
        &[
            (&link_owner, LINK_FD),
            (&host_owner, HOST_FD),
            (&relink_owner, RELINK_FD),
        ],
        _permit,
    )?;
    drop((link_owner, host_owner, relink_owner));
    Ok(OwnerChild {
        pid,
        pidfd,
        link: UnixStream::from(link_front),
        host,
        relink: relink_host,
    })
}

// ---- the owners of one daemon ------------------------------------------------

struct OwnerSlot {
    stop: tokio::sync::Notify,
    stopping: AtomicBool,
    /// A duplicate of the supervisor's pidfd, for the kill on escalation.
    pidfd: OwnedFd,
    /// What the owner holds of the daemon-wide limits; the supervisor
    /// holds it, until it has reaped the owner.
    account: std::sync::Weak<OwnerAccount>,
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

/// Whether channel opening is fenced in every owner, for which attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpensFence {
    Open,
    Fenced(u64),
}

#[derive(Default)]
struct FleetState {
    /// No new owner is started: the daemon is stopping or replacing itself.
    closed: bool,
    owners: HashMap<u32, Arc<OwnerSlot>>,
    /// The last fence asked for, and each owner's answer to the fence it
    /// was last asked for.
    last_fence: u64,
    fenced: HashMap<u32, (u64, Result<(), String>)>,
    /// What is left unproved of owners that ended without proving their
    /// cleanup (no `Drained(Ok)`, a non-zero exit, a kill): at most
    /// [`MAX_UNPROVED`].
    unproved: Vec<Unproved>,
    /// Records past [`MAX_UNPROVED`]: unproved for the daemon's life.
    untracked: u64,
    /// The last record's number.
    last_record: u64,
}

/// Most unproved records a fleet keeps; past them, only a count, which
/// stays unproved.
const MAX_UNPROVED: usize = 4 * MAX_OWNERS;
/// Most session leaders a host keeps of one owner, started and announced
/// together: the session's channels and their retirements are far fewer.
/// An announcement past it is refused (that open fails), and a report past
/// it leaves a session the host cannot check.
const MAX_LEADERS: usize = 8 * transport::channel::MAX_CHANNELS;
/// How long one check of the unproved sessions may walk `/proc`.
const CENSUS_TIMEOUT: Duration = Duration::from_secs(1);
/// The most of an owner's own account of how it ended (its drain error) a
/// record keeps: a refusal naming the sessions must stay within a control
/// record.
const ENDED_TEXT: usize = 160;
/// How many unproved sessions `STATUS` names, and a refusal.
const STATUS_NAMED: usize = 8;
const REFUSAL_NAMED: usize = 3;

/// One session a dead owner may have left processes in.
#[derive(Debug, Clone)]
struct Unproved {
    /// This record, among every one the fleet ever made.
    number: u64,
    /// The owner's pid.
    owner: u32,
    /// How the owner ended: its exit and its receipt.
    ended: String,
    kind: UnprovedKind,
    /// What the last check of it found; `None` before the first.
    found: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum UnprovedKind {
    /// The session `sid` (its leader's pid) whose leader started at
    /// `start` (clock ticks after boot, from procfs): proved once a census
    /// finds none of its processes.
    Session { sid: u32, start: Option<u64> },
    /// A session the owner may have started whose ID the host never
    /// learned, and why: unproved for the daemon's life.
    Unidentified(String),
    /// The owner itself, killed but not reaped (a stop gave up on it):
    /// replaced by its sessions once it is reaped.
    Unreaped,
}

impl Unproved {
    fn describe(&self) -> String {
        let owner = format!("session owner {} ({})", self.owner, self.ended);
        match &self.kind {
            UnprovedKind::Session { sid, .. } => format!(
                "session {sid} of {owner}: {}",
                self.found.as_deref().unwrap_or("not checked yet")
            ),
            UnprovedKind::Unidentified(why) => format!(
                "a session of {owner} whose ID the daemon never learned ({why}); \
                 unproved until the daemon restarts"
            ),
            UnprovedKind::Unreaped => format!("{owner}: killed, but not reaped"),
        }
    }
}

/// What a host knows of one owner's session leaders: the ones started and
/// not yet ended, and the starts announced and not yet reported.
#[derive(Default, Debug)]
pub(crate) struct Leaders {
    /// Noted `Spawning`s without their `Leader` yet.
    starting: usize,
    /// The leaders started (pid: start time), their sessions not yet
    /// proved empty by the owner.
    started: HashMap<u32, Option<u64>>,
    /// Why some leader's session cannot be checked, if one cannot.
    unidentified: Option<String>,
}

impl Leaders {
    /// A leader is about to start: noted, unless too many are kept.
    fn starting(&mut self) -> bool {
        if self.starting + self.started.len() >= MAX_LEADERS {
            return false;
        }
        self.starting += 1;
        true
    }

    /// The outcome of the last noted start.
    fn started(&mut self, leader: crate::process_scope::LeaderStart) {
        use crate::process_scope::LeaderStart;
        if self.starting == 0 {
            // Never announced: fail closed, as for a start never reported.
            self.unidentified
                .get_or_insert("it reported a session it had not announced".into());
        }
        self.starting = self.starting.saturating_sub(1);
        match leader {
            LeaderStart::Started { pid, start } => {
                if self.started.len() >= MAX_LEADERS && !self.started.contains_key(&pid) {
                    self.unidentified
                        .get_or_insert("it reported more sessions than the daemon keeps".into());
                } else {
                    self.started.insert(pid, start);
                }
            }
            LeaderStart::Unidentified => {
                self.unidentified
                    .get_or_insert("a session leader with no exact process identity".into());
            }
            LeaderStart::NotStarted => {}
        }
    }

    /// The session `pid` led was proved empty, and the leader reaped.
    fn ended(&mut self, pid: u32) {
        self.started.remove(&pid);
    }

    /// What stays unproved of these sessions, the owner having died
    /// without proving its cleanup.
    fn unproved(self) -> Vec<UnprovedKind> {
        let mut kinds: Vec<UnprovedKind> = self
            .started
            .into_iter()
            .map(|(sid, start)| UnprovedKind::Session { sid, start })
            .collect();
        kinds.sort_by_key(|kind| match kind {
            UnprovedKind::Session { sid, .. } => *sid,
            _ => 0,
        });
        let unidentified = match (self.starting, self.unidentified) {
            (_, Some(why)) => Some(why),
            (0, None) => None,
            (n, None) => Some(format!(
                "it died starting {n} session leader(s) it did not report"
            )),
        };
        kinds.extend(unidentified.map(UnprovedKind::Unidentified));
        kinds
    }
}

/// Every owner process a daemon has started and not yet reaped, and what
/// is left unproved of the ones that ended without proving their cleanup.
pub struct OwnerFleet {
    state: Mutex<FleetState>,
    /// An owner was reaped (async waiters).
    gone: tokio::sync::Notify,
    /// The same, or an owner answered a fence, for blocking waiters on
    /// `state`.
    gone_cv: std::sync::Condvar,
    /// The restart fence every owner's supervisor relays to its owner.
    fence: tokio::sync::watch::Sender<OpensFence>,
}

impl Default for OwnerFleet {
    fn default() -> Self {
        OwnerFleet {
            state: Mutex::default(),
            gone: tokio::sync::Notify::new(),
            gone_cv: std::sync::Condvar::new(),
            fence: tokio::sync::watch::channel(OpensFence::Open).0,
        }
    }
}

impl OwnerFleet {
    pub fn new() -> Arc<OwnerFleet> {
        Arc::default()
    }

    /// A replacement's open fence stands.
    fn opens_fenced(&self) -> bool {
        matches!(*self.fence.borrow(), OpensFence::Fenced(_))
    }

    /// Owner `pid` answered fence `fence`.
    fn fence_answered(&self, pid: u32, fence: u64, result: Result<(), String>) {
        self.lock().fenced.insert(pid, (fence, result));
        self.gone_cv.notify_all();
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

    /// End owner `pid`'s session, if it still runs: it no longer counts
    /// against the session caps from now on, and the owner is asked to
    /// stop -- it drains and is reaped as at a stop of the daemon.
    pub(crate) fn end_session(&self, pid: u32) {
        let slot = self.lock().owners.get(&pid).cloned();
        if let Some(slot) = slot {
            if let Some(account) = slot.account.upgrade() {
                account.end_session();
            }
            slot.request_stop();
        }
    }

    fn record(state: &mut FleetState, owner: u32, ended: &str, kind: UnprovedKind) {
        if state.unproved.len() >= MAX_UNPROVED {
            state.untracked += 1;
            return;
        }
        state.last_record += 1;
        let number = state.last_record;
        state.unproved.push(Unproved {
            number,
            owner,
            ended: ended.to_owned(),
            kind,
            found: None,
        });
    }

    /// Owner `pid`, killed by a stop that gave up waiting for its reap:
    /// unproved until it is reaped, once.
    fn unreaped(state: &mut FleetState, pid: u32) {
        let already = state
            .unproved
            .iter()
            .any(|u| u.owner == pid && u.kind == UnprovedKind::Unreaped);
        if !already {
            Self::record(state, pid, "killed", UnprovedKind::Unreaped);
        }
    }

    /// `pid` was reaped. `cleanup`: `Ok` if it proved its cleanup, else how
    /// it ended -- and then each session of `leaders` stays unproved until
    /// checked ([`OwnerFleet::recheck`]).
    fn remove(&self, pid: u32, cleanup: Result<(), String>, leaders: Leaders) {
        {
            let mut state = self.lock();
            state.owners.remove(&pid);
            state.fenced.remove(&pid);
            state
                .unproved
                .retain(|u| !(u.owner == pid && u.kind == UnprovedKind::Unreaped));
            if let Err(ended) = cleanup {
                let ended = bounded(&ended, ENDED_TEXT);
                for kind in leaders.unproved() {
                    Self::record(&mut state, pid, &ended, kind);
                }
            }
        }
        self.gone.notify_waiters();
        self.gone_cv.notify_all();
    }

    /// What is unproved of owner `pid`'s sessions, described, and whether
    /// each can still be proved (its session's ID is known).
    fn unproved_of(&self, pid: u32) -> Vec<(String, bool)> {
        self.lock()
            .unproved
            .iter()
            .filter(|u| u.owner == pid)
            .map(|u| {
                let checkable = matches!(u.kind, UnprovedKind::Session { .. });
                (u.describe(), checkable)
            })
            .collect()
    }

    fn cleanup_result(state: &FleetState, named: usize) -> Result<(), String> {
        let total = state.unproved.len() as u64 + state.untracked;
        if total == 0 {
            return Ok(());
        }
        let mut text = format!(
            "{total} session(s) of session owners that ended without proving their cleanup \
             are not proved empty: "
        );
        let shown: Vec<String> = state
            .unproved
            .iter()
            .take(named)
            .map(Unproved::describe)
            .collect();
        text.push_str(&shown.join("; "));
        let more = total - shown.len() as u64;
        if more > 0 {
            text.push_str(&format!("; and {more} more"));
        }
        Err(text)
    }

    /// Check every unproved session with a known ID once more, by a bounded
    /// census of `/proc` ([`crate::process_scope::census_sessions`]): those
    /// with no process left are proved, and forgotten. `Ok` once nothing is
    /// unproved; else why, naming what is. Blocking, for at most about
    /// [`CENSUS_TIMEOUT`], and never under the fleet's lock.
    pub(crate) fn recheck(&self) -> Result<(), String> {
        self.recheck_with(REFUSAL_NAMED, census_now)
    }

    /// [`OwnerFleet::recheck`] with `census` for the census, naming at most
    /// `named` records.
    fn recheck_with(
        &self,
        named: usize,
        census: impl FnOnce(&[u32]) -> Vec<crate::process_scope::SessionCensus>,
    ) -> Result<(), String> {
        use crate::process_scope::SessionCensus;
        let asked: Vec<(u64, u32)> = self
            .lock()
            .unproved
            .iter()
            .filter_map(|u| match u.kind {
                UnprovedKind::Session { sid, .. } => Some((u.number, sid)),
                _ => None,
            })
            .collect();
        if !asked.is_empty() {
            let mut sids: Vec<u32> = asked.iter().map(|(_, sid)| *sid).collect();
            sids.sort_unstable();
            sids.dedup();
            let results = census(&sids);
            let mut proved = Vec::new();
            {
                let mut state = self.lock();
                for (number, sid) in asked {
                    // Missing: a census that gave fewer answers proves nothing.
                    let result = sids
                        .binary_search(&sid)
                        .ok()
                        .and_then(|at| results.get(at))
                        .cloned()
                        .unwrap_or_else(|| SessionCensus::Unknown("no census answer".into()));
                    // Gone meanwhile: proved by another check.
                    let Some(at) = state.unproved.iter().position(|u| u.number == number) else {
                        continue;
                    };
                    match result {
                        SessionCensus::Empty => proved.push(state.unproved.remove(at)),
                        SessionCensus::Occupied(pids) => {
                            let pids: Vec<String> = pids.iter().map(u32::to_string).collect();
                            state.unproved[at].found = Some(match pids.len() {
                                1 => format!("pid {} still runs in it", pids[0]),
                                _ => format!("pids {} still run in it", pids.join(", ")),
                            });
                        }
                        SessionCensus::Unknown(why) => {
                            state.unproved[at].found =
                                Some(format!("it could not be checked ({why})"));
                        }
                    }
                }
            }
            for record in proved {
                if let UnprovedKind::Session { sid, .. } = record.kind {
                    crate::log::info(
                        "qshd",
                        &format!(
                            "session {sid} of session owner {} has no process left: \
                             its cleanup is proved",
                            record.owner
                        ),
                    );
                }
            }
        }
        Self::cleanup_result(&self.lock(), named)
    }

    /// The fleet's cleanup for `STATUS`, checked afresh ([`OwnerFleet::recheck`]):
    /// `completed` when nothing is unproved, else `unresolved` with the
    /// sessions that keep it so. Blocking, as the check.
    pub(crate) fn cleanup_status(&self) -> crate::control::CleanupStatusResponse {
        self.cleanup_status_with(census_now)
    }

    fn cleanup_status_with(
        &self,
        census: impl FnOnce(&[u32]) -> Vec<crate::process_scope::SessionCensus>,
    ) -> crate::control::CleanupStatusResponse {
        use crate::control::{CleanupDomain, CleanupPhase, CleanupStatusResponse, UnprovedSession};
        let _ = self.recheck_with(0, census);
        // The phase and the list from one look at the records.
        let state = self.lock();
        let unproved: Vec<UnprovedSession> = state
            .unproved
            .iter()
            .take(STATUS_NAMED)
            .map(|u| {
                let (session, leader_start) = match u.kind {
                    UnprovedKind::Session { sid, start } => (Some(sid), start),
                    _ => (None, None),
                };
                UnprovedSession {
                    session,
                    leader_start,
                    owner: u.owner,
                    reason: u.describe(),
                }
            })
            .collect();
        let total = state.unproved.len() as u64 + state.untracked;
        CleanupStatusResponse {
            domain: CleanupDomain::PersonalChannels,
            phase: if total == 0 {
                CleanupPhase::Completed
            } else {
                CleanupPhase::Unresolved
            },
            counts: None,
            unproved_more: total - unproved.len() as u64,
            unproved,
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
    /// stop within [`STOP_ESCALATION`], after it was killed. `Err` while
    /// anything of an owner that ended without proving its cleanup is
    /// unproved, checked once more at the end ([`OwnerFleet::recheck`]): a
    /// session that something of it outlived fails the stop, as a failed
    /// worker join failed a single-process daemon's.
    pub async fn stop_all(self: &Arc<Self>) -> Result<(), String> {
        self.close_and_stop();
        let started = tokio::time::Instant::now();
        let escalate_at = started + STOP_ESCALATION;
        let give_up = escalate_at + KILL_GRACE;
        let mut killed = false;
        loop {
            let gone = self.gone.notified();
            tokio::pin!(gone);
            gone.as_mut().enable();
            let left: Vec<(u32, Arc<OwnerSlot>)> = self
                .lock()
                .owners
                .iter()
                .map(|(pid, slot)| (*pid, slot.clone()))
                .collect();
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
                for (_, slot) in &left {
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
                for (pid, _) in &left {
                    // One reaped since the list was taken has its records.
                    if state.owners.contains_key(pid) {
                        Self::unreaped(&mut state, *pid);
                    }
                }
                break;
            }
            // Woken by a reap, or at the next deadline: no polling.
            let deadline = if killed { give_up } else { escalate_at };
            let _ = tokio::time::timeout_at(deadline, gone).await;
        }
        let fleet = self.clone();
        tokio::task::spawn_blocking(move || fleet.recheck())
            .await
            .unwrap_or_else(|error| Err(format!("checking the owners' sessions failed: {error}")))
    }
}

/// `text`, cut to at most `limit` bytes (at a character boundary), marked
/// as cut.
fn bounded(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

/// One census of the sessions `sids`, bounded by [`CENSUS_TIMEOUT`].
fn census_now(sids: &[u32]) -> Vec<crate::process_scope::SessionCensus> {
    use crate::process_scope::SessionCensus;
    match crate::process_scope::qualify_native_proc() {
        // Hidden processes would be missed, and their sessions taken for
        // empty: nothing is proved.
        Ok(view) => match crate::process_scope::proc_hides_processes(&view) {
            Some(why) => vec![SessionCensus::Unknown(why); sids.len()],
            None => crate::process_scope::census_sessions(
                &view,
                sids,
                Instant::now() + CENSUS_TIMEOUT,
                &mut crate::process_scope::Native,
            ),
        },
        Err(error) => {
            let why = format!("/proc cannot be used ({error:?})");
            vec![SessionCensus::Unknown(why); sids.len()]
        }
    }
}

impl crate::update::OwnerStop for OwnerFleet {
    fn proved(&self) -> Result<(), String> {
        self.recheck()
    }

    fn stop_all_until(&self, deadline: Instant) -> Result<(), String> {
        self.close_and_stop();
        {
            let mut state = self.lock();
            while !state.owners.is_empty() {
                let now = Instant::now();
                if now >= deadline {
                    return Err(format!(
                        "{} session owner(s) did not stop in time",
                        state.owners.len()
                    ));
                }
                state = self
                    .gone_cv
                    .wait_timeout(state, deadline - now)
                    .unwrap_or_else(|e| e.into_inner())
                    .0;
            }
        }
        self.recheck()
    }

    fn reopen(&self) {
        self.lock().closed = false;
        self.reopen_opens();
    }

    fn fence_opens_until(&self, deadline: Instant) -> Result<(), String> {
        let mut state = self.lock();
        state.last_fence += 1;
        let fence = state.last_fence;
        // Every supervisor relays it to its owner, and so does each one
        // that starts while it stands.
        self.fence.send_replace(OpensFence::Fenced(fence));
        loop {
            let mut waiting = 0;
            for pid in state.owners.keys() {
                match state.fenced.get(pid) {
                    Some((answered, Ok(()))) if *answered == fence => {}
                    Some((answered, Err(why))) if *answered == fence => {
                        return Err(format!("session owner {pid}: {why}"));
                    }
                    _ => waiting += 1,
                }
            }
            if waiting == 0 {
                return Ok(());
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(format!(
                    "{waiting} session owner(s) did not fence channel opening in time"
                ));
            }
            // Woken by an answer or a reap: no polling.
            state = self
                .gone_cv
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    fn reopen_opens(&self) {
        self.fence.send_if_modified(|fence| {
            let fenced = *fence != OpensFence::Open;
            *fence = OpensFence::Open;
            fenced
        });
    }
}

/// The host side of a personal daemon's owners: it starts one per session
/// ([`OwnerHost::start_raw`], when the frontend asks the host for one) and
/// serves each one's host channel.
pub struct OwnerHost {
    image: SelfImage,
    log_dir: Option<PathBuf>,
    daemon: Option<Arc<dyn DaemonUpdates>>,
    fleet: Arc<OwnerFleet>,
    services: Arc<HostServices>,
    /// Told the pid of an owner whose session ended, and again when the
    /// owner has been reaped (the host's catalog).
    ended: Option<OwnerEnded>,
}

/// See [`OwnerHost::on_ended`].
pub(crate) type OwnerEnded = Arc<dyn Fn(u32) + Send + Sync>;

/// A started owner as the host holds it, before any frontend has its link.
pub(crate) struct RawOwner {
    pub(crate) pid: u32,
    /// Refers to exactly this owner, reaped or not.
    pub(crate) pidfd: OwnedFd,
    /// The frontend's end of the owner's first link.
    pub(crate) link: OwnedFd,
    /// The host's end of the relink channel.
    pub(crate) relink: OwnedFd,
}

impl OwnerHost {
    pub(crate) fn new(
        image: SelfImage,
        log_dir: Option<PathBuf>,
        daemon: Option<Arc<dyn DaemonUpdates>>,
        fleet: Arc<OwnerFleet>,
        services: Arc<HostServices>,
    ) -> OwnerHost {
        OwnerHost {
            image,
            log_dir,
            daemon,
            fleet,
            services,
            ended: None,
        }
    }

    /// `ended` hears the pid of every owner whose session ended, and again
    /// once that owner has been reaped.
    pub(crate) fn on_ended(mut self, ended: OwnerEnded) -> OwnerHost {
        self.ended = Some(ended);
        self
    }

    pub(crate) fn fleet(&self) -> &Arc<OwnerFleet> {
        &self.fleet
    }

    /// Whether a new session of `uid` would get its envelope now.
    pub(crate) fn room(&self, uid: u32) -> Result<(), crate::host_services::Cap> {
        self.services.room(uid)
    }

    /// Why no owner may start now, if one may not, short of an envelope:
    /// the daemon is stopping, or [`MAX_OWNERS`] are unreaped.
    pub(crate) fn start_check(&self) -> Result<(), String> {
        Self::may_start(&self.fleet.lock())
    }

    fn may_start(state: &FleetState) -> Result<(), String> {
        if state.closed {
            return Err("the daemon is stopping".into());
        }
        if state.owners.len() >= MAX_OWNERS {
            return Err(format!(
                "{} session owners are unreaped; no more start until some are",
                state.owners.len()
            ));
        }
        Ok(())
    }
}

impl OwnerHost {
    /// Start one owner for `init`'s session and supervise it: its envelope
    /// lease, its host channel, its reaping. The caller gets the ends a
    /// frontend needs, and hands them on to its frontend process.
    pub(crate) fn start_raw(&self, init: OwnerInit) -> io::Result<RawOwner> {
        let host_init = HostInit {
            principal: init.principal.clone(),
            login: init.login,
            last_generation: init.last_generation,
            updates: self.daemon.is_some(),
            log_dir: self.log_dir.clone(),
        };
        // The owner's control budget envelope, held until it is reaped.
        let account = self.services.admit(init.principal.uid).map_err(|why| {
            crate::log::warn(
                "qshd",
                &format!(
                    "no session owner for {} (uid {}): {why}",
                    init.principal.name, init.principal.uid
                ),
            );
            io::Error::other(why)
        })?;
        let account = Arc::new(account);
        let (child, slot) = {
            // The permit first, then the fleet: a replacement holds the
            // spawn gate for writing while it stops the fleet, so the other
            // order could deadlock.
            let permit = crate::update::spawn_permit();
            // Checked and registered under one lock: a stop that closes the
            // fleet either sees this owner or this start sees it closed.
            let mut state = self.fleet.lock();
            Self::may_start(&state).map_err(io::Error::other)?;
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
                pidfd,
                account: Arc::downgrade(&account),
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
            relink,
        } = child;
        // The frontend's own reference to exactly this owner.
        let front_pidfd = pidfd.try_clone();
        tokio::spawn(supervise(Supervised {
            fleet: self.fleet.clone(),
            slot: slot.clone(),
            pid,
            pidfd,
            host,
            daemon: self.daemon.clone(),
            principal: init.principal,
            account,
            ended: self.ended.clone(),
        }));
        match front_pidfd {
            Ok(pidfd) => Ok(RawOwner {
                pid,
                pidfd,
                link: OwnedFd::from(link),
                relink,
            }),
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
    /// What the owner holds of the daemon-wide limits; freed when it has
    /// been reaped.
    account: Arc<OwnerAccount>,
    ended: Option<OwnerEnded>,
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
        account,
        ended,
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
    let mut fence = fleet.fence.subscribe();
    if let (OpensFence::Fenced(fence), Some(out)) = (*fence.borrow_and_update(), out.as_ref()) {
        let _ = out.send(ToOwner::FenceOpens { fence });
    }
    let transfers: Transfers = Arc::default();
    let mut next_transfer = 0u64;
    let mut joined = BTreeSet::new();
    let mut leaders = Leaders::default();
    let mut receipt: Option<Result<(), String>> = None;
    let mut stop_sent = false;
    // An owner told to stop, or whose session ended, that is still there
    // after the stop escalation is killed (its pidfd: never a reused pid).
    // Its own bounds end it well before (`owner::DRAIN_TIMEOUT`).
    let mut kill_at: Option<tokio::time::Instant> = None;
    let mut killed = false;
    while let (Some(rx), Some(out)) = (frames.as_mut(), out.as_ref()) {
        let msg = tokio::select! {
            _ = slot.stop.notified(), if !stop_sent => {
                stop_sent = true;
                let _ = out.send(ToOwner::Stop);
                kill_at.get_or_insert(tokio::time::Instant::now() + STOP_ESCALATION);
                continue;
            }
            _ = async {
                match kill_at {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending().await,
                }
            }, if !killed => {
                crate::log::warn(
                    "qshd",
                    &format!(
                        "session owner {pid} did not stop within {} s of its end; killing it",
                        STOP_ESCALATION.as_secs()
                    ),
                );
                slot.kill();
                killed = true;
                continue;
            }
            changed = signal_changed(&mut signal) => {
                let _ = out.send(ToOwner::Signal(changed));
                continue;
            }
            Ok(()) = fence.changed() => {
                let _ = out.send(match *fence.borrow_and_update() {
                    OpensFence::Fenced(fence) => ToOwner::FenceOpens { fence },
                    OpensFence::Open => ToOwner::ReopenOpens,
                });
                continue;
            }
            msg = rx.recv() => msg,
        };
        let Some(msg) = msg else { break };
        // While the replacement's fence stands no owner opens a channel,
        // whatever its own registry says (one that started after the fence
        // was answered, say).
        let msg = match serve_limits(&account, msg, fleet.opens_fenced()) {
            Ok(Some(reply)) => {
                let _ = out.send(reply);
                continue;
            }
            Ok(None) => continue,
            Err(msg) => msg,
        };
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
                // No longer a session that a restart waits for, nor one
                // the session caps count.
                signal = None;
                account.end_session();
                kill_at.get_or_insert(tokio::time::Instant::now() + STOP_ESCALATION);
                if let Some(ended) = &ended {
                    ended(pid);
                }
            }
            ToHost::Drained(result) => receipt = Some(result),
            ToHost::Log {
                level,
                component,
                message,
            } => crate::log::record_from(pid, level, &component, &message),
            ToHost::OpensFenced { fence, result } => fleet.fence_answered(pid, fence, result),
            ToHost::Spawning { id } => {
                let admitted = leaders.starting();
                let _ = out.send(ToOwner::SpawnNoted { id, admitted });
            }
            ToHost::Leader(leader) => leaders.started(leader),
            ToHost::LeaderGone { pid: leader } => leaders.ended(leader),
            ToHost::ScreenAcquire { .. }
            | ToHost::ScreenRelease { .. }
            | ToHost::OpenAcquire { .. }
            | ToHost::OpenCharge { .. }
            | ToHost::OpenRelease { .. } => unreachable!("served by serve_limits"),
        }
    }
    drop(signal);
    drop(out);
    // The owner closed its channel: it has exited or is about to. One that
    // lives on regardless is killed after the stop escalation (or at the
    // kill already due), never waited for without end.
    let killer = (!killed).then(|| {
        let slot = slot.clone();
        let due = tokio::time::Instant::now() + STOP_ESCALATION;
        let at = kill_at.map_or(due, |at| at.min(due));
        tokio::spawn(async move {
            tokio::time::sleep_until(at).await;
            crate::log::warn(
                "qshd",
                &format!(
                    "session owner {pid} closed its host channel but did not exit within {} s; \
                     killing it",
                    STOP_ESCALATION.as_secs()
                ),
            );
            slot.kill();
        })
    });
    let (status, exited_cleanly) = reap(pid, pidfd).await;
    if let Some(killer) = killer {
        killer.abort();
    }
    let proved = exited_cleanly && matches!(receipt, Some(Ok(())));
    let receipt = match receipt {
        Some(Ok(())) => "drained".to_string(),
        Some(Err(detail)) => format!("drained with an error: {detail}"),
        None => "no receipt".to_string(),
    };
    let text = format!("session owner {pid} exited ({status}); {receipt}");
    let how = format!("{status}, {receipt}");
    if proved {
        crate::log::info("qshd", &text);
    } else {
        crate::log::warn("qshd", &text);
    }
    let left = std::mem::take(&mut *transfers.lock().unwrap_or_else(|e| e.into_inner()));
    if !left.is_empty() {
        let _ = tokio::task::spawn_blocking(move || drop(left)).await;
    }
    // Reaped: whatever it still held of the daemon-wide limits is free.
    drop(account);
    if let Some(ended) = &ended {
        ended(pid);
    }
    fleet.remove(pid, if proved { Ok(()) } else { Err(how) }, leaders);
    if !proved {
        // Checked at once: an owner killed with nothing of its sessions
        // left is proved now. Whatever is left is named in the log.
        let checked = fleet.clone();
        let _ = tokio::task::spawn_blocking(move || checked.recheck()).await;
        let left = fleet.unproved_of(pid);
        if left.is_empty() {
            crate::log::info(
                "qshd",
                &format!("session owner {pid} left nothing of its sessions running"),
            );
        }
        for (record, checkable) in left {
            let hint = if checkable {
                "; the daemon proves its cleanup once nothing runs in it (STATUS shows what does)"
            } else {
                ""
            };
            crate::log::warn("qshd", &format!("{record}{hint}"));
        }
    }
}

/// Serve `msg` against `account` if it is a daemon-wide limit request: its
/// reply, if it has one; `Err(msg)` if it is something else. While
/// `opens_fenced` (a replacement's fence stands) no open is granted.
pub(crate) fn serve_limits(
    account: &OwnerAccount,
    msg: ToHost,
    opens_fenced: bool,
) -> Result<Option<ToOwner>, ToHost> {
    Ok(match msg {
        ToHost::ScreenAcquire {
            id,
            uid,
            slots,
            models,
        } => Some(ToOwner::ScreenAcquired {
            id,
            result: account.screen_acquire(uid, slots, models),
        }),
        ToHost::ScreenRelease { uid, slots, models } => {
            account.screen_release(uid, slots, models);
            None
        }
        ToHost::OpenAcquire { id, uid } => Some(ToOwner::OpenAcquired {
            id,
            granted: !opens_fenced && account.open_acquire(uid),
        }),
        ToHost::OpenCharge { uid } => {
            account.open_charge(uid);
            None
        }
        ToHost::OpenRelease { uid } => {
            account.open_release(uid);
            None
        }
        other => return Err(other),
    })
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
pub(crate) async fn reap(pid: u32, pidfd: OwnedFd) -> (String, bool) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::update::OwnerStop;

    fn slot() -> Arc<OwnerSlot> {
        Arc::new(OwnerSlot {
            stop: tokio::sync::Notify::new(),
            stopping: AtomicBool::new(false),
            pidfd: OwnedFd::from(std::fs::File::open("/dev/null").unwrap()),
            account: std::sync::Weak::new(),
        })
    }

    /// A fleet of owners 1 and 2, with no processes behind them.
    fn fleet() -> Arc<OwnerFleet> {
        let fleet = OwnerFleet::new();
        for pid in [1, 2] {
            fleet.lock().owners.insert(pid, slot());
        }
        fleet
    }

    /// What each owner's supervisor does: relay the next fence to its owner
    /// and hand back the owner's answer -- here `answers`, straight away.
    fn answer(
        fleet: &Arc<OwnerFleet>,
        answers: Vec<(u32, Result<(), String>)>,
    ) -> std::thread::JoinHandle<()> {
        let fleet = fleet.clone();
        let mut fence = fleet.fence.subscribe();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .build()
                .unwrap();
            runtime.block_on(fence.changed()).unwrap();
            let OpensFence::Fenced(id) = *fence.borrow() else {
                panic!("a fence")
            };
            for (pid, result) in answers {
                fleet.fence_answered(pid, id, result);
            }
        })
    }

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(10)
    }

    /// The replacement's fence spans every owner: it stands once each one
    /// has answered that its own registry is fenced, and not before.
    #[test]
    fn the_restart_fence_waits_for_every_owner_to_answer() {
        let fleet = fleet();
        let answers = answer(&fleet, vec![(1, Ok(())), (2, Ok(()))]);
        assert_eq!(fleet.fence_opens_until(soon()), Ok(()));
        answers.join().unwrap();

        // An owner that cannot fence (cleanup pending there) refuses it.
        let answers = answer(
            &fleet,
            vec![(1, Ok(())), (2, Err("cleanup pending".into()))],
        );
        let refused = fleet.fence_opens_until(soon()).unwrap_err();
        assert!(
            refused.contains("session owner 2: cleanup pending"),
            "{refused}"
        );
        answers.join().unwrap();

        // Answers to an earlier fence do not count: nobody answers this one.
        let refused = fleet
            .fence_opens_until(Instant::now() + Duration::from_millis(50))
            .unwrap_err();
        assert!(
            refused.contains("2 session owner(s) did not fence"),
            "{refused}"
        );

        // An owner reaped meanwhile is not waited for.
        let answers = answer(&fleet, vec![(1, Ok(()))]);
        fleet.remove(2, Ok(()), Leaders::default());
        assert_eq!(fleet.fence_opens_until(soon()), Ok(()));
        answers.join().unwrap();

        // Lifted, every supervisor tells its owner so.
        let mut fence = fleet.fence.subscribe();
        fleet.reopen_opens();
        assert!(fence.has_changed().unwrap());
        assert_eq!(*fence.borrow_and_update(), OpensFence::Open);
        fleet.reopen_opens();
        assert!(!fence.has_changed().unwrap(), "once");
    }

    use crate::process_scope::{LeaderStart, SessionCensus};

    /// What an owner told its host of its sessions: leaders `started`,
    /// and `starting` more announced but never reported.
    fn leaders(started: &[u32], starting: usize) -> Leaders {
        let mut leaders = Leaders::default();
        for &pid in started {
            assert!(leaders.starting());
            leaders.started(LeaderStart::Started {
                pid,
                start: Some(1000 + pid as u64),
            });
        }
        for _ in 0..starting {
            assert!(leaders.starting());
        }
        leaders
    }

    /// A census that must not be made.
    fn no_census(_: &[u32]) -> Vec<SessionCensus> {
        panic!("nothing to check")
    }

    /// Every census answers `answer` for each session asked about, and the
    /// sessions asked about are kept in `asked`.
    fn census(
        asked: &Mutex<Vec<Vec<u32>>>,
        answer: SessionCensus,
    ) -> impl FnOnce(&[u32]) -> Vec<SessionCensus> + '_ {
        move |sids| {
            asked.lock().unwrap().push(sids.to_vec());
            vec![answer; sids.len()]
        }
    }

    /// An owner that died having told its host of no session (none started,
    /// or each one's end already told) leaves nothing unproved: proved at
    /// once, without a census. One that proved its cleanup leaves nothing
    /// whatever it was told.
    #[test]
    fn an_owner_that_left_no_session_is_proved_at_once() {
        let fleet = fleet();
        let mut ended = leaders(&[4242], 0);
        ended.ended(4242);
        fleet.remove(1, Err("signal 9, no receipt".into()), ended);
        assert_eq!(fleet.recheck_with(3, no_census), Ok(()));
        fleet.remove(2, Ok(()), leaders(&[4343], 1));
        assert_eq!(fleet.recheck_with(3, no_census), Ok(()));
        let status = fleet.cleanup_status_with(no_census);
        assert_eq!(status.phase, crate::control::CleanupPhase::Completed);
        assert!(status.unproved.is_empty());
        assert_eq!(status.counts, None);
    }

    /// A session a dead owner told its host of stays unproved while a
    /// process is in it -- whoever it is: the census goes by the session
    /// ID alone, so a process of a new session that reused the number keeps
    /// it unproved too -- and every check names it and what runs in it. Once
    /// a census finds it empty it is proved, and forgotten.
    #[test]
    fn a_process_in_the_session_keeps_it_unproved_until_it_is_gone() {
        let fleet = fleet();
        fleet.remove(1, Err("signal 9, no receipt".into()), leaders(&[4242], 0));
        let asked = Mutex::new(Vec::new());
        let why = fleet
            .recheck_with(3, census(&asked, SessionCensus::Occupied(vec![4250])))
            .unwrap_err();
        assert!(why.contains("session 4242 of session owner 1"), "{why}");
        assert!(why.contains("signal 9, no receipt"), "{why}");
        assert!(why.contains("pid 4250 still runs in it"), "{why}");
        let status =
            fleet.cleanup_status_with(census(&asked, SessionCensus::Occupied(vec![4250, 4251])));
        assert_eq!(status.phase, crate::control::CleanupPhase::Unresolved);
        assert_eq!(status.unproved.len(), 1);
        assert_eq!(status.unproved[0].session, Some(4242));
        assert_eq!(status.unproved[0].leader_start, Some(5242));
        assert_eq!(status.unproved[0].owner, 1);
        assert!(
            status.unproved[0]
                .reason
                .contains("pids 4250, 4251 still run in it"),
            "{:?}",
            status.unproved
        );
        assert_eq!(
            fleet.recheck_with(3, census(&asked, SessionCensus::Empty)),
            Ok(())
        );
        assert_eq!(*asked.lock().unwrap(), vec![vec![4242]; 3]);
        assert_eq!(fleet.recheck_with(3, no_census), Ok(()), "forgotten");
    }

    /// A census that fails or runs out of time proves nothing: the session
    /// stays unproved, says why, and the next check that works proves it.
    #[test]
    fn a_census_that_fails_or_times_out_leaves_the_session_unproved() {
        let fleet = fleet();
        fleet.remove(
            1,
            Err("exit 1, no receipt".into()),
            leaders(&[4242, 4343], 0),
        );
        let asked = Mutex::new(Vec::new());
        for failure in [
            "the census did not finish in time",
            "/proc could not be listed (Errno(13))",
        ] {
            let why = fleet
                .recheck_with(3, census(&asked, SessionCensus::Unknown(failure.into())))
                .unwrap_err();
            assert!(why.starts_with("2 session(s)"), "{why}");
            for sid in [4242, 4343] {
                assert!(why.contains(&format!("session {sid} ")), "{why}");
            }
            assert!(
                why.contains(&format!("could not be checked ({failure})")),
                "{why}"
            );
        }
        // A census that answers for fewer sessions than asked proves none.
        assert!(fleet.recheck_with(3, |_| Vec::new()).is_err());
        assert!(fleet
            .recheck_with(3, |_| vec![SessionCensus::Empty])
            .unwrap_err()
            .contains("session 4343"));
        assert_eq!(
            fleet.recheck_with(3, census(&asked, SessionCensus::Empty)),
            Ok(())
        );
    }

    /// A session whose ID the host never learned -- the owner died between
    /// announcing a leader and reporting it, or reported one with no exact
    /// identity -- cannot be checked: it stays unproved for the daemon's
    /// life, alone. The sessions it does know are proved as usual.
    #[test]
    fn a_session_of_unknown_id_stays_unproved_alone() {
        let fleet = fleet();
        fleet.remove(1, Err("signal 9, no receipt".into()), leaders(&[4242], 1));
        let mut unidentified = leaders(&[], 1);
        unidentified.started(LeaderStart::Unidentified);
        fleet.remove(2, Err("signal 9, no receipt".into()), unidentified);
        let asked = Mutex::new(Vec::new());
        for _ in 0..2 {
            let why = fleet
                .recheck_with(3, census(&asked, SessionCensus::Empty))
                .unwrap_err();
            assert!(why.starts_with("2 session(s)"), "{why}");
            assert!(!why.contains("session 4242"), "proved: {why}");
            assert!(why.contains("session owner 1"), "{why}");
            assert!(why.contains("did not report"), "{why}");
            assert!(why.contains("session owner 2"), "{why}");
            assert!(why.contains("no exact process identity"), "{why}");
            assert!(why.contains("until the daemon restarts"), "{why}");
        }
        assert_eq!(
            *asked.lock().unwrap(),
            vec![vec![4242]],
            "never asked again"
        );
        let status = fleet.cleanup_status_with(no_census);
        assert_eq!(status.phase, crate::control::CleanupPhase::Unresolved);
        assert_eq!(status.unproved.len(), 2);
        assert!(status.unproved.iter().all(|u| u.session.is_none()));
    }

    /// What a host keeps of an owner's leaders is bounded: an announcement
    /// past [`MAX_LEADERS`] is refused (the open fails), a start never
    /// announced or past the bound leaves a session it cannot check, and a
    /// leader whose end was told is no longer kept.
    #[test]
    fn an_owners_leaders_are_bounded_and_fail_closed() {
        let mut full = Leaders::default();
        for _ in 0..MAX_LEADERS {
            assert!(full.starting());
        }
        assert!(!full.starting(), "past the bound");
        full.started(LeaderStart::NotStarted);
        assert!(
            full.starting(),
            "a start that did not happen frees its place"
        );

        let mut unannounced = Leaders::default();
        unannounced.started(LeaderStart::Started {
            pid: 7,
            start: None,
        });
        assert_eq!(
            unannounced.unproved(),
            vec![
                UnprovedKind::Session {
                    sid: 7,
                    start: None
                },
                UnprovedKind::Unidentified("it reported a session it had not announced".into()),
            ]
        );

        let mut told = leaders(&[7, 8], 0);
        told.ended(7);
        assert_eq!(
            told.unproved(),
            vec![UnprovedKind::Session {
                sid: 8,
                start: Some(1008)
            }]
        );
    }

    /// An owner a stop gave up on (killed, not reaped) is unproved once,
    /// however often a stop gives up on it, until it is reaped: then what it
    /// left takes its place.
    #[test]
    fn an_unreaped_owner_is_replaced_by_its_sessions_at_its_reap() {
        let fleet = fleet();
        for _ in 0..2 {
            OwnerFleet::unreaped(&mut fleet.lock(), 1);
        }
        let why = fleet.recheck_with(3, no_census).unwrap_err();
        assert!(why.starts_with("1 session(s)"), "{why}");
        assert!(why.contains("killed, but not reaped"), "{why}");
        fleet.remove(1, Err("signal 9, no receipt".into()), Leaders::default());
        assert_eq!(fleet.recheck_with(3, no_census), Ok(()));
    }

    /// An owner's own account of how it ended (its drain error) is cut in
    /// every record: a refusal naming several sessions stays short enough
    /// to keep its naming, whatever the owner sent.
    #[test]
    fn a_long_owner_account_is_cut_in_every_record() {
        let fleet = fleet();
        let long = format!("exit 1, drained with an error: {}", "é".repeat(20_000));
        fleet.remove(1, Err(long), leaders(&[4242, 4343], 0));
        let why = fleet
            .recheck_with(3, |sids| {
                vec![SessionCensus::Occupied(vec![4250]); sids.len()]
            })
            .unwrap_err();
        assert!(why.len() < 1024, "{} bytes", why.len());
        for sid in [4242, 4343] {
            assert!(why.contains(&format!("session {sid} of session owner 1 (exit 1")));
        }
        assert!(why.contains("...): pid 4250 still runs in it"), "{why}");
    }

    /// The update's checks see the same, with a real census: `proved` and
    /// `stop_all_until` name what keeps the cleanup unproved -- here a
    /// session that is not empty, this test's own -- and pass once nothing
    /// is unproved.
    #[test]
    fn the_update_checks_name_what_keeps_the_cleanup_unproved() {
        let fleet = OwnerFleet::new();
        let sid = unsafe { libc::getsid(0) } as u32;
        fleet.remove(1, Err("signal 9, no receipt".into()), leaders(&[sid], 0));
        let why = fleet.proved().unwrap_err();
        assert!(why.contains(&format!("session {sid} ")), "{why}");
        assert!(why.contains("still run"), "{why}");
        let why = fleet.stop_all_until(soon()).unwrap_err();
        assert!(why.contains(&format!("session {sid} ")), "{why}");
        fleet.lock().unproved.clear();
        assert_eq!(fleet.proved(), Ok(()));
        assert_eq!(fleet.stop_all_until(soon()), Ok(()));
    }

    /// No owner process starts without a control budget envelope: the
    /// session's start fails before anything is spawned.
    #[tokio::test]
    async fn no_owner_starts_without_a_free_envelope() {
        let services = HostServices::new(crate::host_services::HostLimits {
            envelopes: 0,
            ..Default::default()
        });
        let fleet = OwnerFleet::new();
        let host = OwnerHost::new(
            SelfImage::hold().unwrap(),
            None,
            None,
            fleet.clone(),
            services.clone(),
        );
        let principal = Principal {
            uid: 1000,
            name: "me".into(),
            identity: "fixture".into(),
            incarnation: 0,
        };
        let refused = host.start_raw(OwnerInit::new(principal, [0; 16])).err();
        let refused = refused.expect("no envelope: no owner");
        assert!(refused.to_string().contains("envelope"), "{refused}");
        assert!(fleet.is_empty(), "nothing was spawned");
        assert_eq!(services.in_use().envelopes, 0);
    }

    /// However many sessions have ended, no more than [`MAX_OWNERS`] owner
    /// processes are ever unreaped at once: past that, a new session's
    /// owner is refused before anything is spawned or charged.
    #[tokio::test]
    async fn no_owner_starts_while_too_many_are_unreaped() {
        let services = HostServices::new(Default::default());
        let fleet = OwnerFleet::new();
        for pid in 0..MAX_OWNERS as u32 {
            fleet.lock().owners.insert(1_000_000 + pid, slot());
        }
        let host = OwnerHost::new(
            SelfImage::hold().unwrap(),
            None,
            None,
            fleet.clone(),
            services.clone(),
        );
        let principal = Principal {
            uid: 1000,
            name: "me".into(),
            identity: "fixture".into(),
            incarnation: 0,
        };
        assert!(host.start_check().is_err());
        let refused = host.start_raw(OwnerInit::new(principal, [0; 16])).err();
        let refused = refused.expect("too many unreaped owners: no owner");
        assert!(refused.to_string().contains("unreaped"), "{refused}");
        assert_eq!(fleet.len(), MAX_OWNERS, "nothing was spawned");
        assert_eq!(services.in_use().envelopes, 0, "nothing stays charged");
    }

    /// The fence holds at the host too: while it stands no owner is granted
    /// an open -- also one whose own registry was never fenced, such as an
    /// owner started after every running one had answered.
    #[test]
    fn no_open_is_granted_while_the_fence_stands() {
        let services = HostServices::new(Default::default());
        let account = services.admit(1000).unwrap();
        let fleet = OwnerFleet::new();
        let open = |id| ToHost::OpenAcquire { id, uid: 1000 };
        assert_eq!(
            fleet.fence_opens_until(soon()),
            Ok(()),
            "no owner to wait for"
        );
        assert!(fleet.opens_fenced());
        assert_eq!(
            serve_limits(&account, open(1), fleet.opens_fenced()),
            Ok(Some(ToOwner::OpenAcquired {
                id: 1,
                granted: false
            }))
        );
        // A retirement is still charged: it cannot fail.
        assert_eq!(
            serve_limits(&account, ToHost::OpenCharge { uid: 1000 }, true),
            Ok(None)
        );
        assert_eq!(services.in_use().opens, 1);
        fleet.reopen_opens();
        assert!(!fleet.opens_fenced());
        assert_eq!(
            serve_limits(&account, open(2), fleet.opens_fenced()),
            Ok(Some(ToOwner::OpenAcquired {
                id: 2,
                granted: true
            }))
        );
        assert_eq!(services.in_use().opens, 2);
    }
}
