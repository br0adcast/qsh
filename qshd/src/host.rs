//! The host of a personal daemon on Linux (#529 M1): the stable process
//! that keeps every session alive while the daemon's network part comes and
//! goes.
//!
//! A personal daemon is three roles of one executable:
//!
//! - the **host** -- this module, in the process that is the daemon (the
//!   detached `transport-ensure` daemon, or `serve` under a service
//!   manager). It holds the UDP socket, the control socket, the static key,
//!   the allowlist, the daemon-wide limits ([`crate::host_services`]), the
//!   update service, every session's owner process
//!   ([`crate::owner_process`]) and the session catalog. It never reads a
//!   datagram.
//! - the **frontend** ([`crate::frontend`]) -- a child process that runs the
//!   session router on the inherited UDP socket: handshakes, connections,
//!   bridges. It holds nothing that must outlive it. The host starts it
//!   from the image it holds since its own start, and starts another when
//!   it dies.
//! - one **owner** per session, the parent of that session's shells.
//!
//! **Frontend death.** Every owner sees its link close and parks its
//! session, as at a client's death. The host reaps the frontend and starts
//! the next one after a backoff ([`BACKOFF_MIN`], doubling to
//! [`BACKOFF_MAX`], back to the minimum once a frontend has lived
//! [`HEALTHY_AFTER`]). A client that returns -- by its own death timer --
//! shakes hands with the new frontend, which has never heard of its login,
//! asks the host (`Lookup`) and gets the session's owner on a new link; the
//! owner replays its custody there and the client goes on in the same
//! shell. A frontend that keeps dying costs no session anything.
//!
//! **The catalog** is what a frontend may not keep: per login the owner's
//! account and process, when its client was last heard, and whether the
//! session is live or retained since when. A frontend reports these
//! (`Traffic`, `Retained`); a frontend's death changes none of them. A
//! session no frontend holds is ended by the host exactly when a router
//! would have ended it: [`RETAIN_AFTER_DEATH`] after it was retained, or
//! that long after its client's connection would have died of silence
//! ([`SERVER_DEATH_AFTER`] past its last packet). A session the running
//! frontend holds is that frontend's router's to end.
//!
//! **The channel** to a frontend ([`wire`]) is one sequenced-packet socket
//! pair. The frontend asks (`Lookup`, `Create`, `Relink`; each answered,
//! with descriptors attached to the answer) and reports; the host sends
//! what a frontend starts from (the key, the catalog's logins, the
//! allowlist, then `Serve`) and afterwards only what changes in state it
//! owns: keys that `ADD-CLIENT` adds and keys the host scrubbed itself
//! ([`HostAllowlist`]), the admission gate of a replacement, and `Stop`.
//! Requests are bounded by the frontend's own waits
//! ([`crate::host_services::HOST_SERVICE_TIMEOUT`]); no answer is never
//! taken for "no such session" (`Unavailable`: the handshake is dropped,
//! and a session that may still run is never replaced or ended on a
//! guess). A frontend that does not take a packet within that time is
//! killed and replaced.

#[path = "host/allow.rs"]
mod allow;
#[path = "host/wire.rs"]
pub(crate) mod wire;

pub use allow::HostAllowlist;
pub(crate) use allow::ADD_CLIENT_WAIT;

use std::collections::{HashMap, VecDeque};
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use nix::libc;
use transport::session_manager::{
    LoginId, OwnerInit, Shutdown, RETAIN_AFTER_DEATH, SERVER_DEATH_AFTER,
};

use crate::frontend::{CHANNEL_FD, FRONTEND_ROLE, UDP_FD};
use crate::host_services::HOST_SERVICE_TIMEOUT;
use crate::owner_process::{
    dup_high, send_descriptor, socket_pair, socket_pair_of, spawn_role, OwnerHost, SelfImage,
};
use crate::update::AdmissionGate;
use wire::{Channel, FrontendInit, Reply, ToFrontend, ToHost, KEYS_PER_PACKET};

/// The wait before the first restart of a frontend that died.
pub(crate) const BACKOFF_MIN: Duration = Duration::from_millis(100);
/// The longest wait between two frontends.
pub(crate) const BACKOFF_MAX: Duration = Duration::from_secs(5);
/// A frontend that lived this long was healthy: the backoff starts over.
pub(crate) const HEALTHY_AFTER: Duration = Duration::from_secs(60);
/// How long a frontend that was told to stop may take before it is killed.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// How long a session the host handed a frontend (`Lookup`) counts as that
/// frontend's without a word from it: past this, its router never took the
/// link (a late answer, a refused handshake), and the host keeps the
/// session's deadline again. Far above the frontend's wait for the owner's
/// replay (`REBUILD_TIMEOUT`, 10 s), after which a bridge reports at once.
pub(crate) const TAKEOVER_CONFIRM: Duration = Duration::from_secs(30);

/// How one start of a frontend went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Attempt {
    /// A frontend ran, and lived this long.
    Ran(Duration),
    /// None was started: an exec window was open. Not a crash.
    Skipped,
}

/// The wait after `attempt`, the backoff having been `backoff`, and the
/// backoff that follows.
pub(crate) fn next_backoff(backoff: Duration, attempt: Attempt) -> (Duration, Duration) {
    let lived = match attempt {
        Attempt::Ran(lived) => lived,
        Attempt::Skipped => return (BACKOFF_MIN, backoff),
    };
    let wait = if lived >= HEALTHY_AFTER {
        BACKOFF_MIN
    } else {
        backoff
    };
    (wait, (wait * 2).min(BACKOFF_MAX))
}

// ---- the catalog -------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SessionState {
    Live,
    Retained { since: Instant },
}

struct Entry {
    /// The account the session belongs to; it never changes hands.
    uid: u32,
    owner_pid: u32,
    /// Refers to exactly this owner, reaped or not.
    pidfd: OwnedFd,
    /// The host's end of the owner's relink channel: every link after the
    /// first reaches the owner through it.
    relink: OwnedFd,
    /// When the session's client was last heard, as its frontend said.
    last_client_recv: Instant,
    state: SessionState,
    /// The running frontend holds a link to the owner: the session is its
    /// router's. Cleared when that frontend is gone.
    attached: bool,
    /// Handed to the running frontend (`Lookup`) and not yet reported by
    /// it: until when it counts as attached without a word.
    confirm_by: Option<Instant>,
    /// Counted in the daemon's active sessions.
    active: bool,
    /// The key the session's client last proved, and that key's addition
    /// to the allowlist then: scrubbed when the host ends the session,
    /// unless added again since.
    client_key: Option<([u8; 32], u64)>,
}

impl Entry {
    /// When the host next acts on this session: for one the running
    /// frontend holds, when a takeover it never confirmed lapses; for one
    /// nobody holds, when a router would have ended it.
    fn deadline(&self) -> Option<Instant> {
        if self.attached {
            return self.confirm_by;
        }
        Some(match self.state {
            SessionState::Retained { since } => since + RETAIN_AFTER_DEATH,
            SessionState::Live => self.last_client_recv + SERVER_DEATH_AFTER + RETAIN_AFTER_DEATH,
        })
    }
}

/// What the host found for a `Lookup`.
enum Found {
    Unknown,
    Foreign,
    /// The session runs, but its owner cannot be handed over just now.
    Unavailable,
    /// The frontend's end of a new link, and a descriptor of the owner.
    Owner(OwnedFd, OwnedFd),
}

/// What became of a `Relink`.
enum Relinked {
    /// The frontend's end of the new link.
    Link(OwnedFd),
    /// No such session any more, or its owner is gone.
    Gone,
    /// The owner's relink channel does not take the link just now.
    Unavailable,
}

/// Every session of the daemon, by login: what must outlive a frontend.
pub(crate) struct Catalog {
    entries: Mutex<HashMap<LoginId, Entry>>,
    /// A deadline may have moved.
    changed: tokio::sync::Notify,
    /// The daemon's count of active sessions (`STATUS`, the update
    /// service): sessions whose frontend says their client is there.
    active: Arc<AtomicUsize>,
    /// What retention times are logged against.
    born: Instant,
    /// Keys reported for sessions whose `Create` has not come yet.
    early_keys: Mutex<VecDeque<EarlyKey>>,
}

/// A key reported for a session whose `Create` has not come yet, with its
/// addition to the allowlist.
type EarlyKey = (LoginId, ([u8; 32], u64));

/// Most keys kept for a `Create` still to come: one per session the
/// daemon may have.
const EARLY_KEYS: usize = transport::session_manager::MAX_SESSIONS_TOTAL;

impl Catalog {
    pub(crate) fn new(active: Arc<AtomicUsize>) -> Arc<Catalog> {
        Arc::new(Catalog {
            entries: Mutex::default(),
            changed: tokio::sync::Notify::new(),
            active,
            born: Instant::now(),
            early_keys: Mutex::default(),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<LoginId, Entry>> {
        self.entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn recount(&self, entries: &HashMap<LoginId, Entry>) {
        let active = entries.values().filter(|e| e.active).count();
        self.active.store(active, Ordering::SeqCst);
    }

    /// Milliseconds from the catalog's start to `at`, for the log.
    fn stamp(&self, at: Instant) -> u128 {
        at.saturating_duration_since(self.born).as_millis()
    }

    /// The owner `pid` ended its session, or was reaped: its login has no
    /// session any more (unless another owner took the login since). The
    /// keys of the sessions taken off: see [`Catalog::scrubbable`].
    pub(crate) fn owner_ended(&self, pid: u32) -> Vec<([u8; 32], u64)> {
        let mut entries = self.lock();
        let mut gone = Vec::new();
        entries.retain(|_, entry| {
            let ended = entry.owner_pid == pid;
            if ended {
                gone.extend(entry.client_key);
            }
            !ended
        });
        self.recount(&entries);
        let keys = Self::scrubbable(&entries, gone);
        drop(entries);
        self.changed.notify_one();
        keys
    }

    /// Of the keys of sessions that just ended, those no other session
    /// still has.
    fn scrubbable(
        entries: &HashMap<LoginId, Entry>,
        ended: Vec<([u8; 32], u64)>,
    ) -> Vec<([u8; 32], u64)> {
        ended
            .into_iter()
            .filter(|(key, _)| {
                !entries
                    .values()
                    .any(|entry| entry.client_key.is_some_and(|(k, _)| k == *key))
            })
            .collect()
    }

    /// `token`'s session is its client's under `key` (added as `seq`). A
    /// frontend's router reports a fresh session's key when it creates the
    /// session, ahead of the `Create` its bridge sends: kept for that
    /// `Create` ([`Catalog::created`]), at most [`EARLY_KEYS`] of them.
    fn client_key(&self, token: LoginId, key: [u8; 32], seq: Option<u64>) {
        let key = seq.map(|seq| (key, seq));
        if let Some(entry) = self.lock().get_mut(&token).filter(|e| e.attached) {
            entry.client_key = key;
            return;
        }
        let mut early = self.early_keys();
        early.retain(|(t, _)| *t != token);
        if let Some(key) = key {
            if early.len() >= EARLY_KEYS {
                early.pop_front();
            }
            early.push_back((token, key));
        }
    }

    fn early_keys(&self) -> std::sync::MutexGuard<'_, VecDeque<EarlyKey>> {
        self.early_keys.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A session the running frontend created: with the key its router
    /// reported for it, if that came first.
    fn created(&self, token: LoginId, mut entry: Entry) {
        let mut early = self.early_keys();
        if let Some(at) = early.iter().position(|(t, _)| *t == token) {
            entry.client_key = early.remove(at).map(|(_, key)| key);
        }
        drop(early);
        self.insert(token, entry);
    }

    /// A report from the running frontend about `entry`: it holds it.
    fn confirmed(entry: &mut Entry) {
        entry.confirm_by = None;
    }

    /// The frontend is gone: no session is anybody's router's, and none is
    /// active. Nothing else changes -- above all no retention time.
    fn detach_all(&self) {
        // What a dead frontend's router reported ahead of a `Create` is
        // moot: that `Create` never comes.
        self.early_keys().clear();
        let mut entries = self.lock();
        for entry in entries.values_mut() {
            entry.attached = false;
            entry.confirm_by = None;
            entry.active = false;
        }
        self.recount(&entries);
        drop(entries);
        self.changed.notify_one();
    }

    fn known(&self) -> Vec<LoginId> {
        self.lock().keys().copied().collect()
    }

    /// One log line per session a new frontend finds.
    fn describe(&self) -> Vec<String> {
        self.lock()
            .values()
            .map(|entry| match entry.state {
                SessionState::Live => format!(
                    "kept session owner={} state=live last_client_recv={}ms",
                    entry.owner_pid,
                    self.stamp(entry.last_client_recv)
                ),
                SessionState::Retained { since } => format!(
                    "kept session owner={} state=retained since={}ms",
                    entry.owner_pid,
                    self.stamp(since)
                ),
            })
            .collect()
    }

    fn traffic(&self, token: LoginId, idle: Duration, active: bool) {
        let mut entries = self.lock();
        let Some(entry) = entries.get_mut(&token).filter(|e| e.attached) else {
            return;
        };
        Self::confirmed(entry);
        let now = Instant::now();
        entry.last_client_recv = now.checked_sub(idle).unwrap_or(now);
        entry.active = active;
        if active {
            // Heard again: whatever retention there was is over.
            entry.state = SessionState::Live;
        }
        self.recount(&entries);
    }

    fn retained(&self, token: LoginId) {
        let mut entries = self.lock();
        let Some(entry) = entries.get_mut(&token).filter(|e| e.attached) else {
            return;
        };
        Self::confirmed(entry);
        // The first report counts: a retention never starts over.
        if entry.state == SessionState::Live {
            let since = Instant::now();
            entry.state = SessionState::Retained { since };
            crate::log::info(
                "qshd",
                &format!(
                    "session owner={} retained since={}ms",
                    entry.owner_pid,
                    self.stamp(since)
                ),
            );
        }
        entry.active = false;
        self.recount(&entries);
    }

    /// Hand `token`'s owner the owner's end of a new link, and the
    /// frontend the other.
    fn relink(&self, token: LoginId) -> Relinked {
        let mut entries = self.lock();
        let Some(entry) = entries.get_mut(&token) else {
            return Relinked::Gone;
        };
        let Ok((front, owner)) = socket_pair() else {
            return Relinked::Unavailable;
        };
        match send_descriptor(&entry.relink, &owner) {
            Ok(()) => {
                entry.attached = true;
                Relinked::Link(front)
            }
            // Its relink channel is full: the owner is busy, not gone.
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Relinked::Unavailable,
            // Fails at once when the owner has closed its end (it is gone).
            Err(_) => Relinked::Gone,
        }
    }

    /// A warm start by `uid` for `token`: the session's owner on a new
    /// link, which the asking frontend's router then holds -- once it says
    /// so ([`TAKEOVER_CONFIRM`]).
    fn lookup(&self, token: LoginId, uid: u32) -> Found {
        let mut entries = self.lock();
        let Some(entry) = entries.get_mut(&token) else {
            return Found::Unknown;
        };
        if entry.uid != uid {
            return Found::Foreign;
        }
        let Ok(pidfd) = entry.pidfd.try_clone() else {
            return Found::Unavailable;
        };
        drop(entries);
        let front = match self.relink(token) {
            Relinked::Link(front) => front,
            Relinked::Gone => return Found::Unknown,
            Relinked::Unavailable => return Found::Unavailable,
        };
        let mut entries = self.lock();
        let Some(entry) = entries.get_mut(&token) else {
            return Found::Unknown;
        };
        // Its client is back, proven by the handshake that asks.
        entry.state = SessionState::Live;
        entry.last_client_recv = Instant::now();
        entry.confirm_by = Some(Instant::now() + TAKEOVER_CONFIRM);
        Found::Owner(front, pidfd)
    }

    /// The owner of `token`'s session and its account, if there is one.
    fn owner_of(&self, token: LoginId) -> Option<(u32, u32)> {
        self.lock().get(&token).map(|e| (e.uid, e.owner_pid))
    }

    fn insert(&self, token: LoginId, entry: Entry) {
        self.lock().insert(token, entry);
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.lock().values().filter_map(Entry::deadline).min()
    }

    /// Act on every session whose time is up: a takeover its frontend
    /// never confirmed is nobody's again, and a session nobody holds whose
    /// deadline passed is taken off. The owners to stop, and the keys to
    /// scrub (see [`Catalog::scrubbable`]).
    fn take_expired(&self, now: Instant) -> (Vec<u32>, Vec<([u8; 32], u64)>) {
        let mut entries = self.lock();
        for entry in entries.values_mut() {
            if entry.attached && entry.confirm_by.is_some_and(|at| at <= now) {
                crate::log::warn(
                    "qshd",
                    &format!(
                        "session owner {}: the frontend never took the session it was handed; \
                         the host keeps its deadline",
                        entry.owner_pid
                    ),
                );
                entry.attached = false;
                entry.confirm_by = None;
            }
        }
        let mut owners = Vec::new();
        let mut keys = Vec::new();
        entries.retain(|_, entry| {
            let expired = !entry.attached && entry.deadline().is_some_and(|at| at <= now);
            if expired {
                owners.push(entry.owner_pid);
                keys.extend(entry.client_key);
            }
            !expired
        });
        let keys = Self::scrubbable(&entries, keys);
        (owners, keys)
    }
}

// ---- stopping the frontend around a replacement of the daemon ----------------

#[derive(Default)]
struct ControlState {
    /// No frontend runs: the daemon is replacing itself.
    closed: bool,
    /// A frontend process was started and is not reaped yet.
    running: bool,
}

/// Whether the daemon runs a frontend at all. A daemon about to replace
/// itself by exec stops its frontend first, as it stops its owners -- the
/// new image would inherit a child it never heard of, holding the UDP
/// socket -- and starts one again if the exec does not happen.
#[derive(Default)]
pub(crate) struct FrontendControl {
    state: Mutex<ControlState>,
    reaped: Condvar,
    changed: tokio::sync::Notify,
}

impl FrontendControl {
    fn lock(&self) -> std::sync::MutexGuard<'_, ControlState> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Stop the frontend and start no other; `true` once none runs, by
    /// `deadline`.
    pub(crate) fn close_until(&self, deadline: Instant) -> bool {
        let mut state = self.lock();
        state.closed = true;
        self.changed.notify_one();
        while state.running {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            state = self
                .reaped
                .wait_timeout(state, deadline - now)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        true
    }

    /// Run a frontend again.
    pub(crate) fn reopen(&self) {
        self.lock().closed = false;
        self.changed.notify_one();
    }

    fn is_closed(&self) -> bool {
        self.lock().closed
    }

    /// Leave to start a frontend: `false` while closed.
    fn begin(&self) -> bool {
        let mut state = self.lock();
        if state.closed {
            return false;
        }
        state.running = true;
        true
    }

    fn reaped(&self) {
        self.lock().running = false;
        self.reaped.notify_all();
    }
}

// ---- the host ----------------------------------------------------------------

/// What a host's frontends are started with, besides the catalog.
pub struct HostStart {
    pub server_priv: [u8; 32],
    pub server_pub: [u8; 32],
    /// The session-reset secret, kept beside the static key
    /// (`load_or_create_session_reset_secret`): every frontend is handed it,
    /// so each derives the same reset tokens, and so does the daemon after a
    /// restart. `None` (it could not be read or made): no frontend offers
    /// the session reset.
    pub reset_secret: Option<transport::session_reset::SessionResetSecret>,
    /// The signature gate's `authorized_keys`, if the daemon has one.
    pub authorized_keys: Option<PathBuf>,
    /// The account's name: a log label, and the allowlist path's principal.
    pub account: String,
    /// The daemon's allowlist: the control server adds to it, a frontend's
    /// router scrubs it through its reports, the host scrubs the keys of
    /// the sessions it ends.
    pub allowlist: Arc<HostAllowlist>,
    /// The gate a replacement of the daemon closes.
    pub admission: Arc<AdmissionGate>,
    pub runtime_threads: Option<NonZeroUsize>,
}

/// The session-reset secret kept beside the static key at `key_path`, made
/// on first use. A daemon whose secret cannot be read or made still serves,
/// only without the session reset: its clients learn of a lost connection
/// by their death timer, as before (said in the log).
pub fn reset_secret_beside(
    key_path: &std::path::Path,
) -> Option<transport::session_reset::SessionResetSecret> {
    let path = crate::session_reset_secret_path(key_path);
    match crate::load_or_create_session_reset_secret(&path) {
        Ok(secret) => Some(secret),
        Err(error) => {
            crate::log::warn(
                "qshd",
                &format!("no session reset: {error:#}; clients notice a lost connection late"),
            );
            None
        }
    }
}

/// The host side of a personal daemon: see the module documentation.
pub struct Host {
    image: SelfImage,
    owners: OwnerHost,
    catalog: Arc<Catalog>,
    control: Arc<FrontendControl>,
    start: HostStart,
}

struct FrontendChild {
    pid: u32,
    pidfd: OwnedFd,
    channel: OwnedFd,
}

type SpawnJob = Box<dyn FnOnce() + Send>;

/// Run `job` on the host's frontend spawner: one thread that lives as long
/// as the host process. A frontend asks the kernel to kill it when the
/// thread that started it ends (`PR_SET_PDEATHSIG`); started from this
/// thread, that is exactly when the host process dies -- killed, crashed,
/// or replaced by exec -- so a frontend never outlives its host holding the
/// daemon's UDP port, which the next daemon binds. (A runtime worker would
/// not do: a blocking thread ends when it has been idle for a while.)
fn on_spawner_thread<T: Send + 'static>(
    job: impl FnOnce() -> T + Send + 'static,
) -> std::io::Result<T> {
    static SPAWNER: std::sync::OnceLock<Option<Mutex<std::sync::mpsc::Sender<SpawnJob>>>> =
        std::sync::OnceLock::new();
    let spawner = SPAWNER.get_or_init(|| {
        let (jobs, queue) = std::sync::mpsc::channel::<SpawnJob>();
        // The sender lives in the static: the thread waits for jobs for the
        // life of the process.
        std::thread::Builder::new()
            .name("qshd-frontends".into())
            .spawn(move || {
                // A job that panics must not end the thread: every running
                // frontend would die with it, and none could start again.
                for job in queue {
                    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(job));
                }
            })
            .ok()
            .map(|_| Mutex::new(jobs))
    });
    let gone = || std::io::Error::other("the frontend spawner thread is gone");
    let spawner = spawner.as_ref().ok_or_else(gone)?;
    let (done, result) = std::sync::mpsc::sync_channel(1);
    spawner
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .send(Box::new(move || {
            let _ = done.send(job());
        }))
        .map_err(|_| gone())?;
    result.recv().map_err(|_| gone())
}

/// End every session nobody holds whose time is up, when it is up, through
/// `stop` (the owner to stop, the keys to scrub); and hand back the sessions
/// a frontend never took. Until `shutdown`.
pub(crate) async fn expire(
    catalog: Arc<Catalog>,
    shutdown: Shutdown,
    stop: impl Fn(&[u32], &[([u8; 32], u64)]),
) {
    loop {
        let changed = catalog.changed.notified();
        tokio::pin!(changed);
        changed.as_mut().enable();
        let next = catalog.next_deadline();
        let timer = async {
            match next {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            _ = shutdown.requested() => return,
            _ = changed => {}
            _ = timer => {
                // Measured as the timer was: never a turn too early.
                let now = next.map_or_else(Instant::now, |at| Instant::now().max(at));
                let (owners, keys) = catalog.take_expired(now);
                for pid in &owners {
                    crate::log::info(
                        "qshd",
                        &format!("session owner {pid}: nobody came back for its session in time; ending it"),
                    );
                }
                if !owners.is_empty() || !keys.is_empty() {
                    stop(&owners, &keys);
                }
            }
        }
    }
}

fn kill(pidfd: &OwnedFd) {
    // A pidfd never signals a reused PID: once reaped, this is ESRCH.
    unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
}

impl Host {
    pub(crate) fn new(
        image: SelfImage,
        owners: OwnerHost,
        catalog: Arc<Catalog>,
        control: Arc<FrontendControl>,
        start: HostStart,
    ) -> Arc<Host> {
        Arc::new(Host {
            image,
            owners,
            catalog,
            control,
            start,
        })
    }

    /// Run frontends on `socket` until `shutdown`: start one, serve its
    /// requests, reap it when it ends, start the next after the backoff.
    /// Returns once no frontend is left. The owners are not stopped here:
    /// the daemon stops them next (`PersonalSessions::stop_all`), frontend
    /// or no frontend.
    ///
    /// `generation` is the daemon's: every frontend answers with it.
    pub async fn serve(
        self: Arc<Self>,
        socket: std::net::UdpSocket,
        shutdown: Shutdown,
        generation: [u8; 16],
    ) -> anyhow::Result<()> {
        use anyhow::Context;
        // Sized once, where every socket the daemon serves passes.
        transport::log_socket_buffers(&transport::tune_udp_buffers(&socket));
        // The copy each frontend inherits; `socket` itself stays as it is
        // for the daemon's life (a replacement hands its number over).
        let inherited = dup_high(&socket).context("duplicating the UDP socket")?;
        let expiry = {
            let host = self.clone();
            tokio::spawn(expire(
                self.catalog.clone(),
                shutdown.clone(),
                move |owners: &[u32], keys: &[([u8; 32], u64)]| {
                    for pid in owners {
                        host.owners.fleet().stop_owner(*pid);
                    }
                    for (key, seq) in keys {
                        host.start.allowlist.scrub(key, *seq);
                    }
                },
            ))
        };
        let mut backoff = BACKOFF_MIN;
        let mut number = 0u64;
        while !shutdown.is_requested() && self.may_start(&shutdown).await {
            number += 1;
            let started = Instant::now();
            let attempt = match tokio::task::block_in_place(|| self.spawn_frontend(&inherited)) {
                Ok(Some(child)) => {
                    self.run_frontend(child, number, generation, &shutdown)
                        .await;
                    Attempt::Ran(started.elapsed())
                }
                // An exec window is open: no child is spawned into it, and
                // nothing crashed.
                Ok(None) => {
                    number -= 1;
                    Attempt::Skipped
                }
                Err(error) => {
                    crate::log::error(
                        "qshd",
                        &format!("cannot start the network frontend: {error}"),
                    );
                    Attempt::Ran(started.elapsed())
                }
            };
            self.catalog.detach_all();
            self.control.reaped();
            if shutdown.is_requested() {
                break;
            }
            let (wait, next) = next_backoff(backoff, attempt);
            backoff = next;
            if !self.control.is_closed() && attempt != Attempt::Skipped {
                crate::log::warn(
                    "qshd",
                    &format!(
                        "the network frontend is down; sessions are kept, the next one starts in {} ms",
                        wait.as_millis()
                    ),
                );
            }
            tokio::select! {
                _ = shutdown.requested() => break,
                _ = tokio::time::sleep(wait) => {}
            }
        }
        expiry.abort();
        let _ = expiry.await;
        Ok(())
    }

    /// Leave to start a frontend, waited for while the daemon is replacing
    /// itself (until the exec turns out not to happen); `false` at shutdown.
    async fn may_start(&self, shutdown: &Shutdown) -> bool {
        loop {
            let changed = self.control.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.control.begin() {
                return true;
            }
            tokio::select! {
                _ = shutdown.requested() => return false,
                _ = changed => {}
            }
        }
    }

    /// `None` while a replacement's exec window is open.
    fn spawn_frontend(&self, socket: &OwnedFd) -> std::io::Result<Option<FrontendChild>> {
        let (host_end, front_end) = socket_pair_of(nix::sys::socket::SockType::SeqPacket)?;
        let front_end = dup_high(&front_end)?;
        let image = self.image.try_clone()?;
        let socket = dup_high(socket)?;
        let spawned = on_spawner_thread(move || {
            let Some(permit) = crate::update::try_spawn_permit() else {
                return Ok(None);
            };
            spawn_role(
                &image,
                FRONTEND_ROLE,
                &[(&front_end, CHANNEL_FD), (&socket, UDP_FD)],
                &permit,
            )
            .map(Some)
        })??;
        Ok(spawned.map(|(pid, pidfd)| FrontendChild {
            pid,
            pidfd,
            channel: host_end,
        }))
    }

    async fn send(
        &self,
        channel: &Channel,
        msg: &ToFrontend,
        descriptors: &[std::os::fd::BorrowedFd<'_>],
    ) -> bool {
        let Ok(packet) = msg.encode() else {
            crate::log::error(
                "qshd",
                "a frontend channel message exceeds its packet bound",
            );
            return false;
        };
        matches!(
            tokio::time::timeout(HOST_SERVICE_TIMEOUT, channel.send(&packet, descriptors)).await,
            Ok(Ok(()))
        )
    }

    /// Send `init`, and wipe the copies of the static key and the reset
    /// secret made for it.
    async fn send_init(&self, channel: &Channel, mut init: ToFrontend) -> bool {
        let encoded = init.encode();
        if let ToFrontend::Init(init) = &mut init {
            init.server_priv.fill(0);
            std::hint::black_box(&init.server_priv);
            if let Some(secret) = &mut init.reset_secret {
                secret.fill(0);
                std::hint::black_box(secret);
            }
        }
        let Ok(mut packet) = encoded else {
            return false;
        };
        let sent = matches!(
            tokio::time::timeout(HOST_SERVICE_TIMEOUT, channel.send(&packet, &[])).await,
            Ok(Ok(()))
        );
        packet.fill(0);
        std::hint::black_box(&packet);
        sent
    }

    /// Send the frontend every key of the allowlist it does not have yet.
    /// Send the frontend every addition to the allowlist it does not have
    /// yet, and the host's own scrubs since it last heard.
    async fn push_keys(&self, channel: &Channel, sent: &mut HashMap<[u8; 32], u64>) -> bool {
        let fresh = self.start.allowlist.fresh(sent);
        for keys in fresh.chunks(KEYS_PER_PACKET) {
            if !self
                .send(channel, &ToFrontend::AllowKeys(keys.to_vec()), &[])
                .await
            {
                return false;
            }
            sent.extend(keys.iter().copied());
        }
        let revoked = self.start.allowlist.take_revoked();
        for keys in revoked.chunks(KEYS_PER_PACKET) {
            if !self
                .send(channel, &ToFrontend::RevokeKeys(keys.to_vec()), &[])
                .await
            {
                return false;
            }
            for (key, _) in keys {
                sent.remove(key);
            }
        }
        true
    }

    /// Serve one frontend process until it has exited, and reap it.
    async fn run_frontend(
        &self,
        child: FrontendChild,
        number: u64,
        generation: [u8; 16],
        shutdown: &Shutdown,
    ) {
        let FrontendChild {
            pid,
            pidfd,
            channel,
        } = child;
        let kept = self.catalog.describe();
        crate::log::info(
            "qshd",
            &format!(
                "network frontend {number} started pid={pid}; {} session(s) kept",
                kept.len()
            ),
        );
        for line in kept {
            crate::log::info("qshd", &line);
        }
        // SAFETY: the duplicate is owned by the `AsyncFd` and stays open
        // for as long as it is registered.
        let exited = pidfd.try_clone().and_then(|pidfd| unsafe {
            tokio::io::unix::AsyncFd::register_with_interest(pidfd, tokio::io::Interest::READABLE)
                .map_err(std::io::Error::from)
        });
        let channel = Channel::new(channel);
        let mut sent = HashMap::new();
        // What an earlier frontend was to drop is moot: this one starts
        // from the whole list.
        self.start.allowlist.take_revoked();
        self.start.allowlist.set_taken(allow::Taken {
            running: true,
            seq: 0,
        });
        let mut usable = match (&channel, &exited) {
            (Ok(channel), Ok(_)) => {
                let init = ToFrontend::Init(Box::new(FrontendInit {
                    server_priv: self.start.server_priv,
                    server_pub: self.start.server_pub,
                    generation,
                    reset_secret: self.start.reset_secret.as_ref().map(|s| *s.expose()),
                    authorized_keys: self.start.authorized_keys.clone(),
                    account: self.start.account.clone(),
                    admission_closed: self.start.admission.is_closed(),
                    runtime_threads: self
                        .start
                        .runtime_threads
                        .map_or(0, |n| n.get().min(u32::MAX as usize) as u32),
                    known: self.catalog.known(),
                }));
                // The keys before `Serve`: the frontend admits no
                // handshake before it has them.
                let started = self.send_init(channel, init).await;
                started
                    && self.push_keys(channel, &mut sent).await
                    && self.send(channel, &ToFrontend::Serve, &[]).await
            }
            _ => false,
        };
        if !usable {
            crate::log::error("qshd", &format!("network frontend {pid}: no channel to it"));
            kill(&pidfd);
        }
        // When a frontend that was told to stop is killed.
        let mut stop_at: Option<tokio::time::Instant> = None;
        let mut told_to_stop = false;
        if let (Ok(channel), Ok(exited)) = (&channel, &exited) {
            loop {
                let stopping = stop_at.is_some();
                let deadline = async {
                    match stop_at {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    biased;
                    // A pidfd reads as ready once its process has exited.
                    _ = exited.readable() => break,
                    _ = deadline => {
                        kill(&pidfd);
                        stop_at = None;
                        usable = false;
                    }
                    _ = shutdown.requested(), if usable && !stopping => {
                        let _ = self.send(channel, &ToFrontend::Stop, &[]).await;
                        stop_at = Some(tokio::time::Instant::now() + STOP_GRACE);
                        told_to_stop = true;
                    }
                    _ = self.control.changed.notified(), if usable && !stopping => {
                        if self.control.is_closed() {
                            let _ = self.send(channel, &ToFrontend::Stop, &[]).await;
                            stop_at = Some(tokio::time::Instant::now() + STOP_GRACE);
                            told_to_stop = true;
                        }
                    }
                    packet = channel.receive(), if usable => {
                        let served = match packet {
                            Ok(Some((packet, descriptors))) => {
                                drop(descriptors);
                                self.serve_request(channel, pid, &packet, &mut sent).await
                            }
                            // It closed its channel: it is exiting, and its
                            // exit shows in a moment -- or it is killed.
                            Ok(None) => {
                                usable = false;
                                stop_at.get_or_insert(tokio::time::Instant::now() + STOP_GRACE);
                                true
                            }
                            Err(_) => false,
                        };
                        if !served {
                            kill(&pidfd);
                            usable = false;
                        }
                    }
                    _ = self.start.allowlist.added(), if usable => {
                        if !self.push_keys(channel, &mut sent).await {
                            kill(&pidfd);
                            usable = false;
                        }
                    }
                    _ = self.start.admission.changed(), if usable => {
                        let closed = self.start.admission.is_closed();
                        if !self.send(channel, &ToFrontend::Admission { closed }, &[]).await {
                            kill(&pidfd);
                            usable = false;
                        }
                    }
                }
            }
        }
        drop((channel, exited));
        let (status, _) = crate::owner_process::reap(pid, pidfd).await;
        self.start.allowlist.set_taken(allow::Taken::default());
        let text = format!("network frontend {number} pid={pid} exited ({status})");
        if told_to_stop {
            crate::log::info("qshd", &text);
        } else {
            crate::log::warn("qshd", &text);
        }
    }

    /// Serve one packet of the frontend `pid`; `false` if the frontend is
    /// to be given up on.
    async fn serve_request(
        &self,
        channel: &Channel,
        pid: u32,
        packet: &[u8],
        sent: &mut HashMap<[u8; 32], u64>,
    ) -> bool {
        let msg = match ToHost::decode(packet) {
            Ok(msg) => msg,
            Err(error) => {
                crate::log::error("qshd", &format!("network frontend {pid}: {error}"));
                return false;
            }
        };
        match msg {
            ToHost::Lookup { id, token, uid } => match self.catalog.lookup(token, uid) {
                Found::Owner(link, owner) => {
                    let reply = ToFrontend::Reply {
                        id,
                        reply: Reply::Owner,
                    };
                    self.send(channel, &reply, &[link.as_fd(), owner.as_fd()])
                        .await
                }
                found => {
                    let reply = match found {
                        Found::Foreign => Reply::Foreign,
                        Found::Unavailable => Reply::Unavailable,
                        _ => Reply::Unknown,
                    };
                    self.send(channel, &ToFrontend::Reply { id, reply }, &[])
                        .await
                }
            },
            ToHost::Create {
                id,
                token,
                principal,
            } => {
                let created = tokio::task::block_in_place(|| self.create(token, principal));
                match created {
                    Ok((link, owner)) => {
                        let reply = ToFrontend::Reply {
                            id,
                            reply: Reply::Owner,
                        };
                        self.send(channel, &reply, &[link.as_fd(), owner.as_fd()])
                            .await
                    }
                    Err(why) => {
                        let reply = ToFrontend::Reply {
                            id,
                            reply: Reply::Full(why),
                        };
                        self.send(channel, &reply, &[]).await
                    }
                }
            }
            ToHost::Relink { id, token } => match self.catalog.relink(token) {
                Relinked::Link(link) => {
                    let reply = ToFrontend::Reply {
                        id,
                        reply: Reply::Link,
                    };
                    self.send(channel, &reply, &[link.as_fd()]).await
                }
                other => {
                    let reply = ToFrontend::Reply {
                        id,
                        reply: match other {
                            Relinked::Unavailable => Reply::Unavailable,
                            _ => Reply::Gone,
                        },
                    };
                    self.send(channel, &reply, &[]).await
                }
            },
            ToHost::Traffic {
                token,
                idle_ms,
                active,
            } => {
                self.catalog
                    .traffic(token, Duration::from_millis(idle_ms), active);
                true
            }
            ToHost::Retained { token } => {
                self.catalog.retained(token);
                true
            }
            // Removed unless added again since: then the frontend is sent
            // that addition (it is newer than what `sent` holds).
            ToHost::ForgetKey { key, seq } => {
                if self.start.allowlist.forget(&key, seq) {
                    sent.remove(&key);
                }
                true
            }
            ToHost::ClientKey { token, key } => {
                let seq = self.start.allowlist.seq_of(&key);
                self.catalog.client_key(token, key, seq);
                true
            }
            ToHost::KeysTaken { seq } => {
                self.start
                    .allowlist
                    .set_taken(allow::Taken { running: true, seq });
                true
            }
            ToHost::Log {
                level,
                component,
                message,
            } => {
                crate::log::record_from(pid, level, &component, &message);
                true
            }
        }
    }

    /// Start the owner of `token`'s new session: the frontend's end of its
    /// link and a descriptor of its process. A session the login already
    /// has is replaced (a cold start), unless it is another account's.
    fn create(
        &self,
        token: LoginId,
        principal: transport::Principal,
    ) -> Result<(OwnedFd, OwnedFd), String> {
        if let Some((uid, old)) = self.catalog.owner_of(token) {
            if uid != principal.uid {
                return Err("the login belongs to another account".into());
            }
            // Its `End` takes it off the catalog, unless the new owner's
            // entry is there by then.
            self.owners.fleet().stop_owner(old);
        }
        let uid = principal.uid;
        let owner = self
            .owners
            .start_raw(OwnerInit::new(principal, token))
            .map_err(|error| error.to_string())?;
        let pidfd = match owner.pidfd.try_clone() {
            Ok(pidfd) => pidfd,
            Err(error) => {
                self.owners.fleet().stop_owner(owner.pid);
                return Err(error.to_string());
            }
        };
        self.catalog.created(
            token,
            Entry {
                uid,
                owner_pid: owner.pid,
                pidfd,
                relink: owner.relink,
                last_client_recv: Instant::now(),
                state: SessionState::Live,
                attached: true,
                confirm_by: None,
                active: false,
                client_key: None,
            },
        );
        Ok((owner.link, owner.pidfd))
    }
}

/// What a replacement of the daemon stops before its exec: every session's
/// owner, then the frontend.
pub(crate) struct HostStop {
    pub(crate) owners: Arc<crate::owner_process::OwnerFleet>,
    pub(crate) frontend: Arc<FrontendControl>,
}

impl crate::update::OwnerStop for HostStop {
    fn proved(&self) -> bool {
        self.owners.proved()
    }

    fn stop_all_until(&self, deadline: Instant) -> bool {
        // Owners first: their sessions' ends still reach the clients.
        let owners = self.owners.stop_all_until(deadline);
        let frontend = self.frontend.close_until(deadline);
        if !frontend {
            crate::log::error("qshd", "the network frontend did not stop in time");
        }
        owners && frontend
    }

    fn reopen(&self) {
        self.owners.reopen();
        self.frontend.reopen();
    }

    fn fence_opens_until(&self, deadline: Instant) -> Result<(), String> {
        self.owners.fence_opens_until(deadline)
    }

    fn reopen_opens(&self) {
        self.owners.reopen_opens();
    }
}

#[cfg(test)]
#[path = "host_tests.rs"]
mod tests;
