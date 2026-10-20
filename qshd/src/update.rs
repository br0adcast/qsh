//! The personal daemon's side of an update over qsh (spec §3.2, §4, §7).
//!
//! [`DaemonSelf`] speaks for the daemon to every session
//! (`transport::channel_server::DaemonUpdates`): it describes the daemon,
//! decides an offer by the same table `transport-ensure` uses
//! ([`crate::version::replacement`]), stages an accepted image next to the
//! binary, checks it -- size, sha256, `self-check` (build, architecture, the
//! protocol its clients speak, the handover it is about to get), and once
//! more that nobody else arrived -- and replaces the process with it through
//! [`crate::handover`]. Before the exec it closes admission and counts the
//! sessions once more, then announces the restart, waits the grace, and has
//! every session that heard the announcement end and reap its channels. A daemon a service manager
//! started ([`DaemonSelf::managed`]) describes itself and takes nothing.
//!
//! The daemon's own checksum is worked out on the first question, never at
//! start-up: hashing a binary costs a second in a debug build, and start-up
//! is watched by a two-second `STATUS` budget.
//!
//! **The exec window.** From the moment close-on-exec is cleared on the
//! handed-over descriptors until `execve` returns, anything this process
//! spawns would inherit them. So every child the personal daemon spawns
//! goes through [`spawn_permit`] (the pseudo-terminal channels of
//! `crate::channel_backend` and the `self-check` here), and the window holds
//! the other side of that lock; and no new session is admitted: the
//! router's nonce source is wrapped in [`GatedNonces`], whose
//! [`AdmissionGate`] the replacement closes before its last count of the
//! sessions -- the end of `verify`, before anything is announced -- and
//! keeps closed through the exec -- a handshake that meets it
//! is refused, and its client sends msg1 again, to the new binary.
//!
//! **The order of a replacement.** Admission closed and the sessions counted
//! once more (others there: `Busy`, admission open again, nothing
//! announced); announce; the grace, only for the announcement to reach the
//! clients; every subscribed session joins (within
//! [`JOIN_TIMEOUT`]); drain, and every joined session confirms (within
//! [`DRAIN_TIMEOUT`], a bound of its own); only then the
//! control socket is held still -- for at most [`CONTROL_GATE_TIMEOUT`] of
//! waiting -- the allowlist snapshotted, and the exec. `STATUS` and
//! `ADD-CLIENT` are answered through the whole drain: what must not move is
//! only the allowlist between its snapshot and the exec. Any way out short
//! of a successful exec, a panic included, admits handshakes again and ends
//! the attempt.

use std::fs::File;
use std::io::Write;
#[cfg(not(target_os = "linux"))]
use std::io::{BufRead, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock, RwLockReadGuard};
use std::time::{Duration, Instant};
use transport::channel_open::{ChannelOpenRegistry, OpenExecPermit, RestartOpenFence};

use anyhow::Result;
use nix::errno::Errno;
use sha2::{Digest, Sha256};
use tokio::sync::watch;

use transport::channel::{
    About, DaemonMode, RejectCode, UpdateAnswer, UpdateOffer, UpdateResult, PROTOCOL_VERSION,
};
use transport::channel_server::{DaemonUpdates, RestartPhase, RestartSignal, UpdateTransfer};
use transport::{NonceSource, Principal, SharedAllowlist, AUTH_NONCE_LEN};

use crate::handover::{self, Handover};
use crate::state::{self, SelfCheck, HANDOVER_VERSION};
use crate::version::{replacement, Replacement};

/// The largest image a daemon takes (spec §7).
pub const MAX_UPDATE_SIZE: u64 = 64 * 1024 * 1024;

/// How long a staged binary's `self-check` may take (spec §4.2).
pub const SELF_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Between telling every session `Restarting` and the drain: long enough for
/// the session bridges to put the record on the wire and retransmit it once.
/// The decision is made by then -- admission is closed and the sessions
/// counted before the announcement -- so the grace only delivers it.
/// Delivery is still best effort -- a client checks `About` after it logs in
/// again either way.
pub const RESTART_GRACE: Duration = Duration::from_millis(500);

/// How long the replacement waits for every session to end and reap its
/// channels before it execs anyway.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(3);

/// How long the replacement waits, before draining, for every subscribed
/// session to join. Its own bound, apart from [`DRAIN_TIMEOUT`]: a session
/// that is stuck and never joins must not use up the time the others need
/// to reap their channels.
pub const JOIN_TIMEOUT: Duration = Duration::from_secs(1);

/// How long the replacement waits for the control socket's handlers to
/// finish before it gives up: a client that never finishes its request must
/// not hold the daemon closed to every session.
pub const CONTROL_GATE_TIMEOUT: Duration = Duration::from_secs(2);

/// The staged files' name prefix, next to the binary.
pub(crate) const STAGED_PREFIX: &str = ".qshd-update-";

/// Held for reading around every child the personal daemon spawns, and for
/// writing through the exec window (see the module docs).
static SPAWN_GATE: RwLock<()> = RwLock::new(());

/// Leave to spawn a child: hold it until the spawn call has returned (the
/// child has exec'd by then, and whatever it inherited is its own). Waits
/// while an exec window is open.
pub fn spawn_permit() -> RwLockReadGuard<'static, ()> {
    SPAWN_GATE
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Holds an exec window open, for tests of what waits for one.
#[cfg(test)]
pub(crate) fn exec_window_for_test() -> std::sync::RwLockWriteGuard<'static, ()> {
    SPAWN_GATE
        .write()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Whether new sessions may be admitted: closed through a replacement's
/// exec window (see the module docs).
#[derive(Debug, Default)]
pub struct AdmissionGate {
    closed: AtomicBool,
}

impl AdmissionGate {
    pub fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    pub fn open(&self) {
        self.closed.store(false, Ordering::SeqCst);
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// A nonce source that refuses while its [`AdmissionGate`] is closed.
///
/// The router asks its nonce source once for every handshake it is about to
/// admit, on either path (allowlist or signature), a warm reattach included,
/// and refuses the handshake when the source does -- the one point every
/// admission passes. Refusing there is instant, which the router requires.
pub struct GatedNonces {
    inner: Arc<dyn NonceSource>,
    gate: Arc<AdmissionGate>,
}

impl GatedNonces {
    pub fn new(inner: Arc<dyn NonceSource>, gate: Arc<AdmissionGate>) -> GatedNonces {
        GatedNonces { inner, gate }
    }
}

impl NonceSource for GatedNonces {
    fn issue(&self) -> Result<[u8; AUTH_NONCE_LEN], String> {
        if self.gate.is_closed() {
            return Err("the daemon is replacing itself".to_string());
        }
        self.inner.issue()
    }

    fn release(&self, nonce: [u8; AUTH_NONCE_LEN]) {
        self.inner.release(nonce);
    }
}

/// The active sessions other than the offering one. That session has just
/// sent its offer, so the session bridge already counts it active -- and it
/// is in nobody's way. The one place this is decided: the offer and the
/// last count (the end of the verification) both ask here.
pub fn others_than_offering(active_sessions: u64) -> u64 {
    active_sessions.saturating_sub(1)
}

fn busy_count(others: u64) -> u32 {
    others.min(u64::from(u32::MAX)) as u32
}

/// This daemon's own build, checksum and architecture.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnImage {
    pub build: u64,
    /// sha256, lower-case hex -- the form `STATUS` and `reconcile` use.
    pub checksum: String,
    pub arch: String,
}

impl OwnImage {
    /// Hashes this process's binary: call it off the hot path.
    pub fn current() -> Result<OwnImage> {
        Ok(OwnImage {
            build: state::build_label(),
            checksum: state::self_checksum()?,
            arch: std::env::consts::ARCH.to_string(),
        })
    }
}

/// What the replacing binary will need, apart from the paths of the image
/// itself (see [`Handover`]), and what the replacement holds still while it
/// hands itself over.
pub struct HandoverBase {
    pub udp_fd: RawFd,
    pub control_fd: RawFd,
    pub control_path: PathBuf,
    pub cache_dir: PathBuf,
    pub port: u16,
    pub ports: Vec<u16>,
    pub name: String,
    pub allowlist: SharedAllowlist,
    /// Held for reading by every control-socket handler; taken for writing
    /// before the allowlist is snapshotted, so no `ADD-CLIENT` can land
    /// between the snapshot and the exec.
    pub control_gate: Arc<tokio::sync::RwLock<()>>,
    /// The gate of the [`GatedNonces`] the session router was given: closed
    /// from the last count of the sessions through the exec.
    pub admission: Arc<AdmissionGate>,
}

/// Everything an offer is decided by.
#[derive(Debug, Clone, Copy)]
pub struct OfferContext<'a> {
    pub managed: bool,
    pub from_uid: u32,
    pub own_uid: u32,
    pub own: &'a OwnImage,
    pub in_progress: bool,
    /// Every active session, the offering one included.
    pub active_sessions: u64,
}

/// The table of spec §3.2, row by row. `Ok` is `Accept`.
pub fn decide_offer(offer: &UpdateOffer, ctx: &OfferContext<'_>) -> Result<(), UpdateAnswer> {
    if ctx.managed {
        return Err(UpdateAnswer::Managed);
    }
    // A session reaches this code only once it is proven (probation ends
    // before a session exists at all); what is left to refuse is a session
    // of another account.
    if ctx.from_uid != ctx.own_uid {
        return Err(UpdateAnswer::NotAllowed);
    }
    if offer.arch != ctx.own.arch {
        return Err(UpdateAnswer::ArchMismatch);
    }
    if offer.size > MAX_UPDATE_SIZE {
        return Err(UpdateAnswer::TooLarge);
    }
    match replacement(
        offer.build,
        &hex::encode(offer.checksum),
        ctx.own.build,
        &ctx.own.checksum,
        others_than_offering(ctx.active_sessions),
    ) {
        Replacement::UpToDate => Err(UpdateAnswer::UpToDate),
        Replacement::DaemonNewer => Err(UpdateAnswer::DaemonNewer),
        _ if ctx.in_progress => Err(UpdateAnswer::InProgress),
        Replacement::Busy { others } => Err(UpdateAnswer::Busy {
            others: busy_count(others),
        }),
        Replacement::Replace => Ok(()),
    }
}

/// Remove staged files a daemon that died mid-update left next to the
/// binary. `keep` is the one this very process may be running from (a
/// replacement whose rename failed).
pub fn remove_stale_staged(binary_path: &Path, keep: Option<&Path>) {
    let Some(dir) = binary_path.parent() else {
        return;
    };
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        let Some(rest) = name.strip_prefix(STAGED_PREFIX) else {
            continue;
        };
        // Daemons of other names share this directory: a live one's file is
        // its update in progress.
        let owner = rest.split('-').next().and_then(|p| p.parse::<u32>().ok());
        if owner.is_some_and(|pid| pid != std::process::id() && process_alive(pid)) {
            continue;
        }
        if Some(path.as_path()) != keep {
            match std::fs::remove_file(&path) {
                Ok(()) => crate::log::info(
                    "update",
                    &format!(
                        "removed {}, left by an update that never finished",
                        path.display()
                    ),
                ),
                Err(e) => crate::log::warn(
                    "update",
                    &format!("could not remove {}: {e}", path.display()),
                ),
            }
        }
    }
}

/// Whether process `pid` exists: `kill(pid, 0)`, where a process of another
/// account (EPERM) exists too.
fn process_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    if raw <= 0 {
        return false;
    }
    match nix::sys::signal::kill(nix::unistd::Pid::from_raw(raw), None) {
        Ok(()) => true,
        Err(e) => e == Errno::EPERM,
    }
}

/// How one restart attempt's drain stands.
#[derive(Debug, Default)]
struct DrainCount {
    restart: u64,
    joined: u64,
    released: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RestartCounterExhausted;

/// The restart signal every session watches, with the count of who joined
/// each attempt and who has confirmed its drain -- exact per attempt (see
/// `transport::channel_server::RestartSignal`).
pub(crate) struct Restarts {
    publication: Mutex<()>,
    tx: watch::Sender<RestartSignal>,
    last: AtomicU64,
    count: Mutex<DrainCount>,
}

impl Restarts {
    pub(crate) fn new() -> Restarts {
        Restarts {
            publication: Mutex::new(()),
            tx: watch::channel(RestartSignal::IDLE).0,
            last: AtomicU64::new(0),
            count: Mutex::new(DrainCount::default()),
        }
    }

    fn count(&self) -> std::sync::MutexGuard<'_, DrainCount> {
        self.count
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// How many receivers of the signal are alive. The daemon keeps none of
    /// its own (the one `watch::channel` makes is dropped in [`Restarts::new`]),
    /// so these are the sessions' alone.
    pub(crate) fn subscribers(&self) -> u64 {
        self.tx.receiver_count() as u64
    }

    pub(crate) fn subscribe(&self) -> watch::Receiver<RestartSignal> {
        self.tx.subscribe()
    }

    /// Begin a new attempt: a larger number than any before, announced.
    pub(crate) fn announce(&self) -> Result<u64, RestartCounterExhausted> {
        let _publication = self
            .publication
            .lock()
            .map_err(|_| RestartCounterExhausted)?;
        let restart = self
            .last
            .load(Ordering::SeqCst)
            .checked_add(1)
            .ok_or(RestartCounterExhausted)?;
        self.last.store(restart, Ordering::SeqCst);
        *self.count() = DrainCount {
            restart,
            joined: 0,
            released: 0,
        };
        // The count lock is released before publishing: readers join under a
        // watch guard followed by the count lock, never in reverse order.
        self.tx
            .send_replace(RestartSignal::announced(restart, restart));
        Ok(restart)
    }

    /// A session asks to be counted in attempt `restart`. Decided while the
    /// signal is borrowed, so it cannot move to `Draining` between the look
    /// and the count: every join counted happened before the drain began.
    pub(crate) fn join(&self, restart: u64) -> bool {
        let signal = self.tx.borrow();
        if signal.restart != restart || signal.phase != RestartPhase::Announced {
            return false;
        }
        let mut count = self.count();
        if count.restart != restart {
            return false;
        }
        count.joined += 1;
        true
    }

    /// A counted session has reaped its channels for `restart`; one for any
    /// other attempt is ignored.
    pub(crate) fn release(&self, restart: u64) {
        let mut count = self.count();
        if count.restart == restart {
            count.released += 1;
        }
    }

    /// Wait, at most `timeout`, until as many sessions have joined attempt
    /// `restart` as there are sessions subscribed to the signal -- see
    /// [`Restarts::subscribers`]. A session that ends meanwhile drops its
    /// receiver and is no longer waited for. `false` if some had not joined
    /// by then.
    pub(crate) fn wait_joined(&self, restart: u64, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let count = self.count();
                if count.restart == restart && count.joined >= self.subscribers() {
                    return true;
                }
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Tell every session to end its channels. No join is counted after this.
    pub(crate) fn drain(&self, restart: u64) {
        let Ok(_publication) = self.publication.lock() else {
            return;
        };
        let current = *self.tx.borrow();
        if current.restart == restart && current.phase == RestartPhase::Announced {
            self.tx
                .send_replace(RestartSignal::draining(restart, current.invalidation_epoch));
        }
    }

    /// Wait, at most `timeout`, until every session counted in `restart` has
    /// confirmed. `false` if some had not by then.
    #[cfg(test)]
    pub(crate) fn wait_drained(&self, restart: u64, timeout: Duration) -> bool {
        self.wait_drained_until(restart, Instant::now() + timeout)
    }

    fn wait_drained_until(&self, restart: u64, deadline: Instant) -> bool {
        loop {
            {
                let count = self.count();
                if count.restart == restart && count.released >= count.joined {
                    return true;
                }
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The attempt is over, one way or the other.
    pub(crate) fn end(&self) {
        let Ok(_publication) = self.publication.lock() else {
            return;
        };
        self.tx
            .send_replace(RestartSignal::idle(self.last.load(Ordering::SeqCst)));
    }

    fn phase(&self) -> RestartPhase {
        self.tx.borrow().phase
    }
}

/// How the replacement execs the staged binary: [`handover::exec_staged`],
/// or a stand-in in tests. Returns only on failure.
pub(crate) type ExecFn = Arc<dyn Fn(&Path, RawFd) -> Errno + Send + Sync>;

/// Speaks for this daemon to every session.
pub struct DaemonSelf {
    /// Worked out on the first question, once -- a binary that cannot be
    /// read is remembered as `None` too, not hashed again per request.
    own: OnceLock<Option<OwnImage>>,
    managed: bool,
    binary_path: PathBuf,
    own_uid: u32,
    active: Arc<AtomicUsize>,
    in_progress: Arc<AtomicBool>,
    restarts: Arc<Restarts>,
    opens: Arc<ChannelOpenRegistry>,
    handover: Option<Arc<HandoverBase>>,
    exec: ExecFn,
}

impl DaemonSelf {
    /// A daemon a client installed: it takes updates. `own` is `None` in
    /// production (worked out on the first question); `active` is the session
    /// manager's own active-session count; `handover` is `None` only in tests
    /// that never get as far as an exec.
    ///
    /// Sweeps away staged files an update that never finished left next to
    /// the binary -- all but the one this process may be running from.
    pub fn personal(
        opens: Arc<ChannelOpenRegistry>,
        own: Option<OwnImage>,
        binary_path: PathBuf,
        own_uid: u32,
        active: Arc<AtomicUsize>,
        handover: Option<HandoverBase>,
    ) -> DaemonSelf {
        let running_from = std::env::current_exe().ok();
        remove_stale_staged(&binary_path, running_from.as_deref());
        DaemonSelf {
            own: own_cell(own),
            managed: false,
            binary_path,
            own_uid,
            active,
            in_progress: Arc::new(AtomicBool::new(false)),
            restarts: Arc::new(Restarts::new()),
            opens,
            handover: handover.map(Arc::new),
            exec: Arc::new(handover::exec_staged),
        }
    }

    /// A daemon a service manager or a package owns: it describes itself and
    /// answers every offer `Managed`.
    pub fn managed(opens: Arc<ChannelOpenRegistry>, own: Option<OwnImage>) -> DaemonSelf {
        DaemonSelf {
            own: own_cell(own),
            managed: true,
            binary_path: PathBuf::new(),
            own_uid: u32::MAX,
            active: Arc::new(AtomicUsize::new(0)),
            in_progress: Arc::new(AtomicBool::new(false)),
            restarts: Arc::new(Restarts::new()),
            opens,
            handover: None,
            exec: Arc::new(handover::exec_staged),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_exec(mut self, exec: ExecFn) -> DaemonSelf {
        self.exec = exec;
        self
    }

    /// This daemon's image, worked out once. `None` if the binary cannot be
    /// read: the daemon then stays silent on `About`, as an old one does.
    fn own(&self) -> Option<&OwnImage> {
        self.own
            .get_or_init(|| match OwnImage::current() {
                Ok(own) => Some(own),
                Err(e) => {
                    crate::log::warn(
                        "qshd",
                        &format!("cannot describe its own binary ({e:#}); About goes unanswered"),
                    );
                    None
                }
            })
            .as_ref()
    }

    /// `.qshd-update-<pid>-<random>`. The pid is what the sweep of stale
    /// files goes by; the rest is random rather than counted, because a
    /// resumed daemon keeps its pid and would count from zero again -- into
    /// the name of a file an earlier attempt left behind.
    fn staging_path(&self) -> PathBuf {
        self.binary_path.with_file_name(format!(
            "{STAGED_PREFIX}{}-{:016x}",
            std::process::id(),
            random_suffix()
        ))
    }
}

/// 64 random bits for a staged name: std's per-process random hash keys
/// (seeded from the operating system), over the time of day. Not a secret --
/// only a name no earlier attempt of this pid can have taken.
fn random_suffix() -> u64 {
    use std::hash::{BuildHasher, Hasher};
    let mut hasher = std::collections::hash_map::RandomState::new().build_hasher();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    hasher.write_u128(now.as_nanos());
    hasher.finish()
}

fn own_cell(own: Option<OwnImage>) -> OnceLock<Option<OwnImage>> {
    let cell = OnceLock::new();
    if let Some(own) = own {
        let _ = cell.set(Some(own));
    }
    cell
}

impl DaemonUpdates for DaemonSelf {
    fn about(&self) -> Option<About> {
        let own = self.own()?;
        let mut checksum = [0u8; 32];
        let bytes = hex::decode(&own.checksum).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        checksum.copy_from_slice(&bytes);
        Some(About {
            build: own.build,
            checksum,
            arch: own.arch.clone(),
            protocol: PROTOCOL_VERSION,
            mode: if self.managed {
                DaemonMode::Managed
            } else {
                DaemonMode::Personal
            },
        })
    }

    fn offer(
        &self,
        from: &Principal,
        offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
        if self.managed {
            return Err(UpdateAnswer::Managed);
        }
        // A daemon that cannot describe itself never answered `About`, so no
        // client has a reason to offer; one that does anyway is not taken.
        let Some(own) = self.own() else {
            return Err(UpdateAnswer::NotAllowed);
        };
        decide_offer(
            offer,
            &OfferContext {
                managed: self.managed,
                from_uid: from.uid,
                own_uid: self.own_uid,
                own,
                in_progress: self.in_progress.load(Ordering::SeqCst),
                active_sessions: self.active.load(Ordering::SeqCst) as u64,
            },
        )?;
        // Claim the one slot. A second offer that raced past the check above
        // loses here.
        if self.in_progress.swap(true, Ordering::SeqCst) {
            return Err(UpdateAnswer::InProgress);
        }
        crate::log::info(
            "update",
            &format!(
                "accepted build {} ({} bytes) from {}",
                offer.build, offer.size, from.name
            ),
        );
        Ok(Box::new(StagedImage {
            offer: offer.clone(),
            path: self.staging_path(),
            file: None,
            created: false,
            hasher: Sha256::new(),
            written: 0,
            closed_admission: false,
            binary_path: self.binary_path.clone(),
            active: Arc::clone(&self.active),
            in_progress: Arc::clone(&self.in_progress),
            restarts: Arc::clone(&self.restarts),
            opens: self.opens.clone(),
            handover: self.handover.clone(),
            exec: Arc::clone(&self.exec),
        }))
    }

    fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
        self.restarts.subscribe()
    }

    fn restart_joined(&self, restart: u64) -> bool {
        self.restarts.join(restart)
    }

    fn channels_released(&self, restart: u64) {
        self.restarts.release(restart);
    }
}

/// An accepted image on its way to replacing the daemon. Dropped before the
/// exec succeeds, it removes its staged file and frees the slot.
struct StagedImage {
    offer: UpdateOffer,
    path: PathBuf,
    /// Opened on the first write, so a directory that cannot take the file
    /// is a `Rejected` with the reason rather than a refused offer.
    file: Option<File>,
    created: bool,
    hasher: Sha256,
    written: u64,
    /// This image closed admission for its last count (see `verify`), and
    /// opens it again if it never gets as far as the exec.
    closed_admission: bool,
    binary_path: PathBuf,
    active: Arc<AtomicUsize>,
    in_progress: Arc<AtomicBool>,
    restarts: Arc<Restarts>,
    opens: Arc<ChannelOpenRegistry>,
    handover: Option<Arc<HandoverBase>>,
    exec: ExecFn,
}

impl StagedImage {
    /// Active sessions other than the offering one.
    fn others(&self) -> u64 {
        others_than_offering(self.active.load(Ordering::SeqCst) as u64)
    }

    /// Admit handshakes again, if this image closed admission.
    fn reopen_admission(&mut self) {
        if std::mem::take(&mut self.closed_admission) {
            if let Some(base) = &self.handover {
                base.admission.open();
            }
        }
    }
}

impl UpdateTransfer for StagedImage {
    fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.file.is_none() {
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&self.path)
                .map_err(|e| format!("could not create {}: {e}", self.path.display()))?;
            self.created = true;
            self.file = Some(file);
        }
        let file = self.file.as_mut().expect("opened just above");
        file.write_all(bytes)
            .map_err(|e| format!("could not write {}: {e}", self.path.display()))?;
        self.hasher.update(bytes);
        self.written += bytes.len() as u64;
        Ok(())
    }

    fn verify(&mut self) -> Result<(), UpdateResult> {
        let rejected = |code: RejectCode, detail: String| UpdateResult::Rejected { code, detail };
        if self.written != self.offer.size {
            return Err(rejected(
                RejectCode::SizeMismatch,
                format!(
                    "expected {} bytes, received {}",
                    self.offer.size, self.written
                ),
            ));
        }
        let Some(file) = self.file.take() else {
            return Err(rejected(
                RejectCode::SizeMismatch,
                "no image was received".to_string(),
            ));
        };
        file.sync_all().map_err(|e| {
            rejected(
                RejectCode::DiskError,
                format!("could not flush {}: {e}", self.path.display()),
            )
        })?;
        // Closed before it is run: a file open for writing cannot be executed.
        drop(file);
        let mut digest = [0u8; 32];
        digest.copy_from_slice(&std::mem::take(&mut self.hasher).finalize());
        if digest != self.offer.checksum {
            return Err(rejected(
                RejectCode::ChecksumMismatch,
                "the image does not match its checksum".to_string(),
            ));
        }
        let check = run_self_check(&self.path, SELF_CHECK_TIMEOUT)
            .map_err(|detail| rejected(RejectCode::SelfCheckFailed, detail))?;
        if check.build != self.offer.build || check.arch != self.offer.arch {
            return Err(rejected(
                RejectCode::SelfCheckFailed,
                format!(
                    "self-check reported build {} {}, the offer said build {} {}",
                    check.build, check.arch, self.offer.build, self.offer.arch
                ),
            ));
        }
        if !check.protocols.contains(&PROTOCOL_VERSION) {
            return Err(rejected(
                RejectCode::VersionNotAccepted,
                format!(
                    "the new binary does not speak protocol {PROTOCOL_VERSION} (it speaks {:?})",
                    check.protocols
                ),
            ));
        }
        if !check.handover_versions.contains(&HANDOVER_VERSION) {
            return Err(rejected(
                RejectCode::VersionNotAccepted,
                format!(
                    "the new binary cannot take handover version {HANDOVER_VERSION} (it takes {:?})",
                    check.handover_versions
                ),
            ));
        }
        // The last count, right before the replacement: others may have
        // arrived while the image was on its way (spec §4.3). Admission is
        // closed first and stays closed through the exec, so the count holds
        // -- and it comes before anything is announced: a `Busy` here has
        // told no session `Restarting`, and cut none.
        if let Some(base) = &self.handover {
            base.admission.close();
            self.closed_admission = true;
        }
        let others = self.others();
        if others > 0 {
            self.reopen_admission();
            return Err(UpdateResult::Busy {
                others: busy_count(others),
            });
        }
        Ok(())
    }

    /// Called by the session runner from a blocking task, like everything
    /// else here: it sleeps, waits for locks and execs.
    fn restart(self: Box<Self>) -> UpdateResult {
        let Some(base) = self.handover.clone() else {
            return UpdateResult::Rejected {
                code: RejectCode::ExecFailed,
                detail: "this daemon cannot hand itself over".to_string(),
            };
        };
        // Closed already by the last count in `verify`, and kept closed to
        // the exec: no new session from here on (see the module docs).
        base.admission.close();
        let fence = match self.opens.begin_restart_fence() {
            Ok(fence) => fence,
            Err(_) => {
                return UpdateResult::Rejected {
                    code: RejectCode::ExecFailed,
                    detail: "channel opening could not be fenced".into(),
                };
            }
        };
        // Fence first: cancellation survives a dropped runner and precedes
        // watch publication. Every failure unwinds Idle -> registry -> admission.
        let undo = UndoRestart {
            admission: Arc::clone(&base.admission),
            restarts: Arc::clone(&self.restarts),
            opens: Some(fence),
        };
        let restart = match self.restarts.announce() {
            Ok(restart) => restart,
            Err(_) => {
                return UpdateResult::Rejected {
                    code: RejectCode::ExecFailed,
                    detail: "restart identity exhausted".into(),
                };
            }
        };
        // Only for the sessions to put `Restarting` on the wire: the
        // decision is made, and nobody is admitted meanwhile.
        std::thread::sleep(RESTART_GRACE);
        // First every subscribed session joins -- a session whose loop was
        // busy through the grace joins late, and is waited for -- within a
        // bound of its own; then every one that joined confirms, with the
        // whole drain budget: one stuck session must not use up the others'
        // time to reap.
        if !self.restarts.wait_joined(restart, JOIN_TIMEOUT) {
            crate::log::warn(
                "update",
                "not every session heard the restart in time; draining anyway",
            );
        }
        let drain_deadline = Instant::now() + DRAIN_TIMEOUT;
        self.restarts.drain(restart);
        if !self.restarts.wait_drained_until(restart, drain_deadline) {
            crate::log::warn(
                "update",
                &format!(
                    "not every session reaped its installed channels within {} s",
                    DRAIN_TIMEOUT.as_secs()
                ),
            );
        }
        let Some(open_exec_permit) = undo
            .opens
            .as_ref()
            .and_then(|fence| fence.wait_until(drain_deadline))
        else {
            return UpdateResult::Rejected {
                code: RejectCode::ExecFailed,
                detail: "pending channel creation has not proved cleanup".into(),
            };
        };
        // No `ADD-CLIENT` between the allowlist snapshot and the exec: the
        // gate is taken here, after the drain -- a key added during the
        // drain is in the snapshot, and `STATUS` is answered throughout it
        // -- and held until the process is replaced or the exec failed.
        // Bounded: a control client that never finishes must not keep the
        // daemon closed to every session.
        let Some(_control) = write_within(&base.control_gate, CONTROL_GATE_TIMEOUT) else {
            let reason = format!(
                "the control socket stayed busy for {} s",
                CONTROL_GATE_TIMEOUT.as_secs()
            );
            crate::log::warn("update", &reason);
            return UpdateResult::Rejected {
                code: RejectCode::ControlBusy,
                detail: reason,
            };
        };
        let reason = self.exec_with_handover(&base, &open_exec_permit);
        // Still here: the exec failed, and this daemon goes on as it was --
        // minus the channels it drained.
        crate::log::warn("update", &reason);
        UpdateResult::Rejected {
            code: RejectCode::ExecFailed,
            detail: reason,
        }
    }
}

/// Undoes an attempt on every way out of [`StagedImage::restart`] short of a
/// successful exec, a panic included.
struct UndoRestart {
    admission: Arc<AdmissionGate>,
    restarts: Arc<Restarts>,
    opens: Option<RestartOpenFence>,
}

impl Drop for UndoRestart {
    fn drop(&mut self) {
        self.restarts.end();
        if let Some(fence) = self.opens.take() {
            fence.reopen();
        }
        self.admission.open();
    }
}

/// Makes the handed-over sockets close-on-exec again, on every way out of
/// the exec window -- a panic included.
struct PutBackCloexec<'a>(&'a HandoverBase);

impl Drop for PutBackCloexec<'_> {
    fn drop(&mut self) {
        for fd in [self.0.udp_fd, self.0.control_fd] {
            if let Err(e) = handover::set_cloexec(fd, true) {
                crate::log::warn(
                    "update",
                    &format!("could not make descriptor {fd} close-on-exec again: {e}"),
                );
            }
        }
    }
}

/// The control gate for writing, trying for at most `timeout`. Never queued
/// behind: a waiting `write()` on tokio's fair lock would hold every new
/// reader -- every `STATUS` -- back for as long as it waits.
fn write_within(
    gate: &tokio::sync::RwLock<()>,
    timeout: Duration,
) -> Option<tokio::sync::RwLockWriteGuard<'_, ()>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(guard) = gate.try_write() {
            return Some(guard);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

impl StagedImage {
    /// Hand everything over and exec the staged binary. Returns only if that
    /// failed, with the descriptors put back the way this process needs them.
    fn exec_with_handover(&self, base: &HandoverBase, _opens: &OpenExecPermit<'_>) -> String {
        debug_assert_eq!(self.restarts.phase(), RestartPhase::Draining);
        let allowlist = match base.allowlist.lock() {
            Ok(keys) => keys.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let description = Handover {
            handover_version: HANDOVER_VERSION,
            binary_path: self.binary_path.clone(),
            staged_path: self.path.clone(),
            udp_fd: base.udp_fd,
            control_fd: base.control_fd,
            control_path: base.control_path.clone(),
            cache_dir: base.cache_dir.clone(),
            port: base.port,
            ports: base.ports.clone(),
            name: base.name.clone(),
            allowlist: handover::encode_allowlist(&allowlist),
        };
        let memfd = match handover::write_memfd(&description) {
            Ok(fd) => fd,
            Err(e) => return format!("could not write the handover: {e:#}"),
        };
        let keep = [base.udp_fd, base.control_fd, memfd.as_raw_fd()];
        // The exec window: no child may be spawned until `execve` returns,
        // or it would inherit what is about to become inheritable.
        let _no_spawns = SPAWN_GATE
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Err(e) = handover::close_on_exec_except(&keep) {
            return format!("could not mark descriptors close-on-exec: {e}");
        }
        let _put_back = PutBackCloexec(base);
        for fd in keep {
            if let Err(e) = handover::set_cloexec(fd, false) {
                return format!("could not keep descriptor {fd} across exec: {e}");
            }
        }
        crate::log::info(
            "update",
            &format!("replacing this process with build {}", self.offer.build),
        );
        let err = (self.exec)(&self.path, memfd.as_raw_fd());
        // Closed while the spawn gate is still held: it is inheritable now.
        // (The sockets are put back by `_put_back`, dropped before the gate.)
        drop(memfd);
        format!("exec of the new binary failed: {err}")
    }
}

impl Drop for StagedImage {
    fn drop(&mut self) {
        self.reopen_admission();
        self.file = None;
        if self.created {
            let _ = std::fs::remove_file(&self.path);
        }
        self.in_progress.store(false, Ordering::SeqCst);
    }
}

#[cfg(target_os = "linux")]
#[path = "update_scope.rs"]
mod native_self_check;

#[cfg(target_os = "linux")]
pub(crate) fn run_self_check(path: &Path, timeout: Duration) -> Result<SelfCheck, String> {
    native_self_check::run(path, timeout)
}

/// Run `<path> self-check`, bounded by `timeout`, and read its line.
/// Non-Linux cleanup remains a separate platform acceptance requirement.
#[cfg(not(target_os = "linux"))]
pub(crate) fn run_self_check(path: &Path, timeout: Duration) -> Result<SelfCheck, String> {
    let mut child = spawn_self_check(path)?;
    let deadline = Instant::now() + timeout;
    // Read on a thread of its own, up to the first line: a process the
    // staged binary left behind can hold its stdout open for as long as it
    // likes, and that must not hold `verify` -- and the one update slot --
    // with it. A reader still blocked past the deadline is left to finish
    // on its own.
    let (line_tx, line_rx) = std::sync::mpsc::channel();
    if let Some(stdout) = child.stdout.take() {
        std::thread::spawn(move || {
            let mut line = String::new();
            let _ = std::io::BufReader::new(stdout.take(4096)).read_line(&mut line);
            let _ = line_tx.send(line);
        });
    }
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "self-check did not finish within {}s",
                    timeout.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
            Err(e) => return Err(format!("self-check could not be waited for: {e}")),
        }
    };
    if !status.success() {
        return Err(format!("self-check failed: {status}"));
    }
    let out = line_rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| {
            format!(
                "self-check's output did not end within {}s",
                timeout.as_secs()
            )
        })?;
    SelfCheck::from_line(out.lines().next().unwrap_or(""))
        .map_err(|e| format!("self-check printed something else: {e:#}"))
}

/// Start the self-check, waiting out ETXTBSY with the same budget the exec
/// has (`handover::EXEC_ATTEMPTS` x `handover::EXEC_RETRY`, about 1.5 s).
fn spawn_self_check(path: &Path) -> Result<Child, String> {
    let mut attempt = 0;
    loop {
        let spawned = {
            let _permit = spawn_permit();
            let mut command = Command::new(path);
            command
                .arg("self-check")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null());
            #[cfg(target_os = "linux")]
            {
                use std::os::unix::process::CommandExt;
                // Child-only setup, acknowledged by Command's exec-error pipe.
                unsafe {
                    command.pre_exec(|| {
                        if nix::libc::setsid() < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            }
            command.spawn()
        };
        match spawned {
            Ok(child) => return Ok(child),
            Err(e)
                if e.raw_os_error() == Some(Errno::ETXTBSY as i32)
                    && attempt + 1 < handover::EXEC_ATTEMPTS =>
            {
                attempt += 1;
                std::thread::sleep(handover::EXEC_RETRY);
            }
            Err(e) => return Err(format!("self-check did not start: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    include!("update_open_tests.rs");
    include!("update_scope_tests.rs");
    use super::*;
    use crate::test_support::{fd_flags_lock, suppress_shell_history};
    use std::os::fd::AsRawFd;
    use std::sync::Mutex;
    use std::time::Duration;
    use transport::channel_server::RestartPhase;
    use transport::NonceSource;

    const ARCH: &str = std::env::consts::ARCH;

    fn uid() -> u32 {
        nix::unistd::Uid::current().as_raw()
    }

    fn me() -> Principal {
        Principal {
            uid: uid(),
            name: "me".to_string(),
            identity: "test".to_string(),
            incarnation: 0,
        }
    }

    fn own_image() -> OwnImage {
        OwnImage {
            build: 100,
            checksum: hex::encode([1u8; 32]),
            arch: ARCH.to_string(),
        }
    }

    /// A stand-in binary: a shell script that answers `self-check` the way
    /// qshd does -- with the protocols and handover versions it is told to
    /// claim -- then exits with `exit`.
    fn script_with(build: u64, protocols: &[u8], handovers: &[u32], exit: i32) -> Vec<u8> {
        let protocols: Vec<String> = protocols.iter().map(|p| p.to_string()).collect();
        let handovers: Vec<String> = handovers.iter().map(|h| h.to_string()).collect();
        format!(
            "#!/bin/sh\nprintf '%s\\n' '{{\"build\":{build},\"arch\":\"{ARCH}\",\"protocol\":{PROTOCOL_VERSION},\"protocols\":[{}],\"handover_versions\":[{}]}}'\nexit {exit}\n",
            protocols.join(","),
            handovers.join(",")
        )
        .into_bytes()
    }

    /// The same, claiming exactly what this build speaks and takes.
    fn script_image(build: u64, exit: i32) -> Vec<u8> {
        script_with(build, &[PROTOCOL_VERSION], &[HANDOVER_VERSION], exit)
    }

    fn offer_for(image: &[u8], build: u64) -> UpdateOffer {
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&Sha256::digest(image));
        UpdateOffer {
            build,
            checksum,
            arch: ARCH.to_string(),
            size: image.len() as u64,
        }
    }

    fn service(dir: &Path, active: usize) -> (DaemonSelf, Arc<AtomicUsize>) {
        let active = Arc::new(AtomicUsize::new(active));
        let daemon = DaemonSelf::personal(
            ChannelOpenRegistry::new(Default::default()),
            Some(own_image()),
            dir.join("qshd"),
            uid(),
            Arc::clone(&active),
            None,
        );
        (daemon, active)
    }

    /// Nobody holds an exec window open. A window a panic unwound through
    /// leaves the lock poisoned, not held: that is free too.
    fn spawn_gate_free() -> bool {
        !matches!(
            SPAWN_GATE.try_read(),
            Err(std::sync::TryLockError::WouldBlock)
        )
    }

    /// The pid of a process that has come and gone.
    fn dead_pid() -> u32 {
        let mut child = Command::new("true").spawn().unwrap();
        let pid = child.id();
        child.wait().unwrap();
        pid
    }

    /// A restartable daemon over this test's own sockets whose exec is
    /// `exec`, with an image already accepted, written and verified.
    fn verified_transfer(dir: &Path, exec: ExecFn) -> Restartable {
        verified_transfer_with_registry(dir, exec, ChannelOpenRegistry::new(Default::default()))
    }

    fn verified_transfer_with_registry(
        dir: &Path,
        exec: ExecFn,
        opens: Arc<ChannelOpenRegistry>,
    ) -> Restartable {
        let (base, udp, control) = handover_base(dir);
        let admission = Arc::clone(&base.admission);
        let control_gate = Arc::clone(&base.control_gate);
        let daemon = Arc::new(
            DaemonSelf::personal(
                opens,
                Some(own_image()),
                dir.join("qshd"),
                uid(),
                Arc::new(AtomicUsize::new(1)),
                Some(base),
            )
            .with_exec(exec),
        );
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        transfer.verify().expect("a good image");
        Restartable {
            daemon,
            transfer,
            admission,
            control_gate,
            udp,
            control,
        }
    }

    /// What [`verified_transfer`] sets up.
    struct Restartable {
        daemon: Arc<DaemonSelf>,
        transfer: Box<dyn UpdateTransfer>,
        admission: Arc<AdmissionGate>,
        control_gate: Arc<tokio::sync::RwLock<()>>,
        udp: std::net::UdpSocket,
        control: std::os::unix::net::UnixListener,
    }

    type Log = Arc<Mutex<Vec<String>>>;

    /// A session stand-in on its own thread: subscribed from the start (so
    /// the daemon counts it), it joins `join_after` into the announcement,
    /// and once told to drain writes down whether the control socket is
    /// free, then confirms.
    fn fake_session(
        daemon: &Arc<DaemonSelf>,
        join_after: Duration,
        control_gate: &Arc<tokio::sync::RwLock<()>>,
    ) -> (std::thread::JoinHandle<()>, Log) {
        fake_session_reaping(daemon, join_after, Duration::from_millis(100), control_gate)
    }

    /// The same, taking `reap_for` to reap its channels once told to drain.
    fn fake_session_reaping(
        daemon: &Arc<DaemonSelf>,
        join_after: Duration,
        reap_for: Duration,
        control_gate: &Arc<tokio::sync::RwLock<()>>,
    ) -> (std::thread::JoinHandle<()>, Log) {
        let rx = daemon.restart_signal();
        let daemon = Arc::clone(daemon);
        let control_gate = Arc::clone(control_gate);
        let log = Arc::new(Mutex::new(Vec::new()));
        let handle = {
            let log = Arc::clone(&log);
            std::thread::spawn(move || {
                let wait = |phase: RestartPhase| {
                    let deadline = Instant::now() + Duration::from_secs(10);
                    while rx.borrow().phase != phase && Instant::now() < deadline {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    rx.borrow().restart
                };
                let n = wait(RestartPhase::Announced);
                std::thread::sleep(join_after);
                let joined = daemon.restart_joined(n);
                log.lock().unwrap().push(format!("joined {joined}"));
                wait(RestartPhase::Draining);
                log.lock().unwrap().push(format!(
                    "control free during the drain {}",
                    control_gate.try_read().is_ok()
                ));
                std::thread::sleep(reap_for);
                daemon.channels_released(n);
                log.lock().unwrap().push("released".to_string());
                drop(rx);
            })
        };
        (handle, log)
    }

    fn staged_files(dir: &Path) -> Vec<PathBuf> {
        std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(STAGED_PREFIX))
            })
            .collect()
    }

    fn rejected(result: Result<(), UpdateResult>) -> (RejectCode, String) {
        match result {
            Err(UpdateResult::Rejected { code, detail }) => (code, detail),
            other => panic!("expected a rejection, got {other:?}"),
        }
    }

    /// A handover base over real sockets of this test, so a restart can get
    /// as far as the exec.
    fn handover_base(
        dir: &Path,
    ) -> (
        HandoverBase,
        std::net::UdpSocket,
        std::os::unix::net::UnixListener,
    ) {
        let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let control_path = dir.join("control.sock");
        let control = std::os::unix::net::UnixListener::bind(&control_path).unwrap();
        let base = HandoverBase {
            udp_fd: udp.as_raw_fd(),
            control_fd: control.as_raw_fd(),
            control_path,
            cache_dir: dir.to_path_buf(),
            port: 1,
            ports: vec![1],
            name: "main".to_string(),
            allowlist: Arc::new(Mutex::new(vec![[3u8; 32]])),
            control_gate: Arc::new(tokio::sync::RwLock::new(())),
            admission: Arc::new(AdmissionGate::default()),
        };
        (base, udp, control)
    }

    #[test]
    fn the_offer_is_decided_row_by_row() {
        let own = own_image();
        let base = OfferContext {
            managed: false,
            from_uid: 1000,
            own_uid: 1000,
            own: &own,
            in_progress: false,
            active_sessions: 1,
        };
        let newer = UpdateOffer {
            build: 101,
            checksum: [2; 32],
            arch: ARCH.to_string(),
            size: 1024,
        };
        assert_eq!(
            decide_offer(&newer, &base),
            Ok(()),
            "only the offering session is active, and it does not count"
        );
        assert_eq!(
            decide_offer(
                &UpdateOffer {
                    arch: "sparc".into(),
                    ..newer.clone()
                },
                &OfferContext {
                    managed: true,
                    ..base
                }
            ),
            Err(UpdateAnswer::Managed),
            "a managed daemon says so before anything else"
        );
        assert_eq!(
            decide_offer(
                &newer,
                &OfferContext {
                    from_uid: 0,
                    ..base
                }
            ),
            Err(UpdateAnswer::NotAllowed)
        );
        assert_eq!(
            decide_offer(
                &UpdateOffer {
                    arch: "sparc".into(),
                    ..newer.clone()
                },
                &base
            ),
            Err(UpdateAnswer::ArchMismatch)
        );
        assert_eq!(
            decide_offer(
                &UpdateOffer {
                    size: MAX_UPDATE_SIZE + 1,
                    ..newer.clone()
                },
                &base
            ),
            Err(UpdateAnswer::TooLarge)
        );
        assert_eq!(
            decide_offer(
                &UpdateOffer {
                    size: MAX_UPDATE_SIZE,
                    ..newer.clone()
                },
                &base
            ),
            Ok(()),
            "the limit itself is allowed"
        );
        assert_eq!(
            decide_offer(
                &UpdateOffer {
                    checksum: [1; 32],
                    build: 1,
                    ..newer.clone()
                },
                &base
            ),
            Err(UpdateAnswer::UpToDate),
            "equal checksums win over any build"
        );
        assert_eq!(
            decide_offer(
                &UpdateOffer {
                    build: 99,
                    ..newer.clone()
                },
                &base
            ),
            Err(UpdateAnswer::DaemonNewer)
        );
        assert_eq!(
            decide_offer(
                &UpdateOffer {
                    build: 100,
                    ..newer.clone()
                },
                &base
            ),
            Ok(()),
            "a tied build with other bytes replaces"
        );
        assert_eq!(
            decide_offer(
                &newer,
                &OfferContext {
                    in_progress: true,
                    ..base
                }
            ),
            Err(UpdateAnswer::InProgress)
        );
        assert_eq!(
            decide_offer(
                &newer,
                &OfferContext {
                    active_sessions: 3,
                    ..base
                }
            ),
            Err(UpdateAnswer::Busy { others: 2 })
        );
        assert_eq!(
            decide_offer(
                &newer,
                &OfferContext {
                    active_sessions: 0,
                    ..base
                }
            ),
            Ok(()),
            "a count that missed the offering session is still nobody else"
        );
    }

    #[test]
    fn about_describes_this_daemon() {
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        assert_eq!(
            daemon.about(),
            Some(About {
                build: 100,
                checksum: [1; 32],
                arch: ARCH.to_string(),
                protocol: PROTOCOL_VERSION,
                mode: DaemonMode::Personal,
            })
        );
        assert_eq!(
            DaemonSelf::managed(
                ChannelOpenRegistry::new(Default::default()),
                Some(own_image())
            )
            .about()
            .map(|a| a.mode),
            Some(DaemonMode::Managed)
        );
    }

    /// Nothing is hashed until somebody asks: a daemon made with no image
    /// works it out on the first `About`, from its own binary.
    #[test]
    fn the_own_image_is_worked_out_on_the_first_question() {
        let daemon = DaemonSelf::managed(ChannelOpenRegistry::new(Default::default()), None);
        let about = daemon.about().expect("this test binary can be hashed");
        assert_eq!(about.build, state::build_label());
        assert_eq!(about.arch, ARCH);
        assert_eq!(hex::encode(about.checksum), state::self_checksum().unwrap());
    }

    #[test]
    fn a_managed_daemon_takes_no_offer() {
        let image = script_image(101, 0);
        assert!(matches!(
            DaemonSelf::managed(
                ChannelOpenRegistry::new(Default::default()),
                Some(own_image())
            )
            .offer(&me(), &offer_for(&image, 101)),
            Err(UpdateAnswer::Managed)
        ));
    }

    #[test]
    fn a_short_image_is_rejected_and_its_staged_file_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image[..10]).unwrap();
        assert_eq!(
            staged_files(dir.path()).len(),
            1,
            "staged next to the binary"
        );
        assert_eq!(rejected(transfer.verify()).0, RejectCode::SizeMismatch);
        drop(transfer);
        assert!(staged_files(dir.path()).is_empty());
    }

    #[test]
    fn an_image_that_does_not_match_its_checksum_is_rejected_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let image = script_image(101, 0);
        let mut offer = offer_for(&image, 101);
        offer.checksum[0] ^= 0xff;
        let mut transfer = daemon.offer(&me(), &offer).expect("accepted");
        transfer.write(&image).unwrap();
        assert_eq!(rejected(transfer.verify()).0, RejectCode::ChecksumMismatch);
        drop(transfer);
        assert!(staged_files(dir.path()).is_empty());
    }

    #[test]
    fn a_failed_self_check_leaves_the_running_binary_alone() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("qshd"), b"the running binary").unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let image = script_image(101, 3);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        assert_eq!(rejected(transfer.verify()).0, RejectCode::SelfCheckFailed);
        drop(transfer);
        assert!(staged_files(dir.path()).is_empty());
        assert_eq!(
            std::fs::read(dir.path().join("qshd")).unwrap(),
            b"the running binary"
        );
    }

    #[test]
    fn a_self_check_that_reports_another_build_is_refused() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let image = script_image(555, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        let (code, detail) = rejected(transfer.verify());
        assert_eq!(code, RejectCode::SelfCheckFailed);
        assert!(detail.contains("build 555"), "{detail}");
    }

    /// Its clients speak this protocol: a binary that no longer does would
    /// cut every one of them off.
    #[test]
    fn an_image_that_no_longer_speaks_the_protocol_is_refused() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let image = script_with(101, &[PROTOCOL_VERSION + 1], &[HANDOVER_VERSION], 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        assert_eq!(
            rejected(transfer.verify()).0,
            RejectCode::VersionNotAccepted
        );
    }

    /// Refused BEFORE the exec: a binary that cannot read the handover would
    /// start with no sockets and no keys, and nothing could bring the old
    /// daemon back.
    #[test]
    fn an_image_that_cannot_take_this_handover_is_refused() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let image = script_with(101, &[PROTOCOL_VERSION], &[HANDOVER_VERSION + 98], 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        let (code, detail) = rejected(transfer.verify());
        assert_eq!(code, RejectCode::VersionNotAccepted);
        assert!(detail.contains("handover"), "{detail}");
    }

    #[test]
    fn sessions_that_arrived_during_the_transfer_make_it_busy() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (daemon, active) = service(dir.path(), 1);
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        active.store(2, Ordering::SeqCst);
        assert_eq!(transfer.verify(), Err(UpdateResult::Busy { others: 1 }));
    }

    /// The last count comes before anything is announced, with admission
    /// already closed: a verified image leaves handshakes refused and no
    /// session told `Restarting`; an image dropped instead of restarted
    /// admits them again.
    #[test]
    fn the_last_count_closes_admission_before_anything_is_announced() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (base, _udp, _control) = handover_base(dir.path());
        let admission = Arc::clone(&base.admission);
        let nonces = GatedNonces::new(Arc::new(transport::RandomNonces), Arc::clone(&admission));
        let daemon = DaemonSelf::personal(
            ChannelOpenRegistry::new(Default::default()),
            Some(own_image()),
            dir.path().join("qshd"),
            uid(),
            Arc::new(AtomicUsize::new(1)),
            Some(base),
        );
        let rx = daemon.restart_signal();
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        transfer.verify().expect("a good image");
        assert!(admission.is_closed(), "no session admitted past the count");
        assert!(nonces.issue().is_err(), "a handshake is refused");
        assert!(!rx.has_changed().unwrap(), "nothing announced yet");
        drop(transfer);
        assert!(!admission.is_closed(), "handshakes are admitted again");
        assert!(nonces.issue().is_ok());
    }

    /// A session there at the last count stops the replacement before any
    /// session hears `Restarting`: `Busy`, nothing announced, admission open
    /// again, the staged file gone. (It used to be counted after the grace,
    /// when every session had already been told to restart.)
    #[test]
    fn a_session_counted_at_the_last_moment_is_busy_and_nobody_hears_restarting() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (base, _udp, _control) = handover_base(dir.path());
        let admission = Arc::clone(&base.admission);
        let active = Arc::new(AtomicUsize::new(1));
        let daemon = DaemonSelf::personal(
            ChannelOpenRegistry::new(Default::default()),
            Some(own_image()),
            dir.path().join("qshd"),
            uid(),
            Arc::clone(&active),
            Some(base),
        );
        let rx = daemon.restart_signal();
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        active.store(2, Ordering::SeqCst);
        assert_eq!(transfer.verify(), Err(UpdateResult::Busy { others: 1 }));
        assert!(!rx.has_changed().unwrap(), "no session told Restarting");
        assert!(!admission.is_closed(), "handshakes are admitted again");
        drop(transfer);
        assert!(staged_files(dir.path()).is_empty());
        assert_eq!(daemon.restart_signal().borrow().phase, RestartPhase::Idle);
    }

    /// A resumed daemon keeps its pid and starts its counters afresh, so a
    /// file an earlier attempt of the same pid left behind (its rename
    /// failed) must not collide with the next staged name.
    #[test]
    fn staged_names_do_not_collide_with_files_left_by_the_same_pid() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        for n in 0..4096u32 {
            let left = dir
                .path()
                .join(format!("{STAGED_PREFIX}{}-{n}", std::process::id()));
            std::fs::write(left, b"left behind").unwrap();
        }
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).expect("a fresh staged name");
        assert_eq!(transfer.verify(), Ok(()));
    }

    #[test]
    fn a_good_image_passes_and_is_removed_if_never_restarted() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        assert_eq!(transfer.verify(), Ok(()));
        use std::os::unix::fs::PermissionsExt;
        let staged = staged_files(dir.path());
        assert_eq!(
            std::fs::metadata(&staged[0]).unwrap().permissions().mode() & 0o777,
            0o700
        );
        drop(transfer);
        assert!(staged_files(dir.path()).is_empty());
    }

    #[test]
    fn only_one_update_at_a_time_across_sessions() {
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let image = script_image(101, 0);
        let first = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        assert!(matches!(
            daemon.offer(&me(), &offer_for(&image, 101)),
            Err(UpdateAnswer::InProgress)
        ));
        drop(first);
        assert!(daemon.offer(&me(), &offer_for(&image, 101)).is_ok());
    }

    /// Another thread forking while the staged file is still open for
    /// writing makes executing it fail with ETXTBSY for a moment; the
    /// self-check waits that out (up to about 1.5 s) instead of refusing a
    /// good image. The hold here is well inside that budget.
    #[test]
    fn a_self_check_waits_out_a_file_briefly_held_open_for_writing() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("image");
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o700)
                .open(&path)
                .unwrap();
            f.write_all(&script_image(101, 0)).unwrap();
        }
        let holder = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(300));
            drop(holder);
        });
        let check =
            run_self_check(&path, SELF_CHECK_TIMEOUT).expect("the retry outlasts the holder");
        release.join().unwrap();
        assert_eq!(check.build, 101);
    }

    /// Staged files left by a daemon that died mid-update are removed at the
    /// next start; the running binary and anything else stay.
    #[test]
    fn stale_staged_files_are_removed_at_start() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("qshd");
        std::fs::write(&binary, b"binary").unwrap();
        let dead = dead_pid();
        let stale = format!(".qshd-update-{dead}-0");
        let ours = format!(".qshd-update-{}-7", std::process::id());
        std::fs::write(dir.path().join(&stale), b"stale").unwrap();
        std::fs::write(dir.path().join(&ours), b"ours").unwrap();
        std::fs::write(dir.path().join("notes"), b"keep").unwrap();
        remove_stale_staged(&binary, Some(&dir.path().join(&ours)));
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, vec![ours.as_str(), "notes", "qshd"]);
    }

    /// The sweep runs when the personal daemon's update service is made,
    /// i.e. at start; it hashes nothing.
    #[test]
    fn a_personal_daemon_sweeps_stale_staged_files_when_made() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("qshd"), b"binary").unwrap();
        std::fs::write(
            dir.path().join(format!(".qshd-update-{}-9", dead_pid())),
            b"stale",
        )
        .unwrap();
        let (daemon, _) = service(dir.path(), 1);
        assert!(staged_files(dir.path()).is_empty());
        assert!(dir.path().join("qshd").exists());
        assert_eq!(
            daemon.own.get(),
            Some(&Some(own_image())),
            "given, not computed"
        );
    }

    /// An exec that fails leaves the daemon exactly as it was: its sockets
    /// close-on-exec again, the restart signal back down, the slot free.
    #[test]
    fn a_failed_exec_puts_the_descriptors_back_and_frees_the_slot() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (base, udp, control) = handover_base(dir.path());
        let daemon = DaemonSelf::personal(
            ChannelOpenRegistry::new(Default::default()),
            Some(own_image()),
            dir.path().join("qshd"),
            uid(),
            Arc::new(AtomicUsize::new(1)),
            Some(base),
        );
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        transfer.verify().expect("a good image");
        // Taken away, the exec fails with ENOENT -- and so can never succeed
        // and replace this test process.
        for staged in staged_files(dir.path()) {
            std::fs::remove_file(staged).unwrap();
        }
        match transfer.restart() {
            UpdateResult::Rejected { code, detail } => {
                assert_eq!(code, RejectCode::ExecFailed, "{detail}")
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
        assert!(crate::handover::is_cloexec(udp.as_raw_fd()).unwrap());
        assert!(crate::handover::is_cloexec(control.as_raw_fd()).unwrap());
        assert_eq!(daemon.restart_signal().borrow().phase, RestartPhase::Idle);
        assert!(
            daemon.offer(&me(), &offer_for(&image, 101)).is_ok(),
            "the slot is free"
        );
    }

    /// Everything the exec window promises, seen from inside it: the three
    /// descriptors inheritable, no child can be spawned, no handshake
    /// admitted, the control socket held still, the sessions told to drain.
    /// Afterwards -- the stand-in exec fails -- all of it is undone.
    #[test]
    fn inside_the_exec_window_nothing_can_spawn_or_be_admitted() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let (base, udp, control) = handover_base(dir.path());
        let admission = Arc::clone(&base.admission);
        let control_gate = Arc::clone(&base.control_gate);
        let nonces = GatedNonces::new(Arc::new(transport::RandomNonces), Arc::clone(&admission));
        let (udp_fd, control_fd) = (udp.as_raw_fd(), control.as_raw_fd());
        let seen: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        // Read through the daemon's own `Restarts`, not a receiver: a
        // receiver would be a subscriber the replacement waits to join.
        let restarts = Arc::new(Mutex::new(None::<Arc<Restarts>>));
        let exec: ExecFn = {
            let seen = Arc::clone(&seen);
            let restarts = Arc::clone(&restarts);
            let control_gate = Arc::clone(&control_gate);
            Arc::new(move |staged: &Path, memfd: RawFd| {
                let mut seen = seen.lock().unwrap();
                seen.push(format!("staged exists {}", staged.exists()));
                for (name, fd) in [("udp", udp_fd), ("control", control_fd), ("memfd", memfd)] {
                    seen.push(format!(
                        "{name} cloexec {}",
                        handover::is_cloexec(fd).unwrap()
                    ));
                }
                seen.push(format!("spawn blocked {}", !spawn_gate_free()));
                seen.push(format!("admission refused {}", nonces.issue().is_err()));
                seen.push(format!("control held {}", control_gate.try_read().is_err()));
                let phase = restarts.lock().unwrap().as_ref().unwrap().phase();
                seen.push(format!("phase {phase:?}"));
                nix::errno::Errno::ENOENT
            })
        };
        let daemon = DaemonSelf::personal(
            ChannelOpenRegistry::new(Default::default()),
            Some(own_image()),
            dir.path().join("qshd"),
            uid(),
            Arc::new(AtomicUsize::new(1)),
            Some(base),
        )
        .with_exec(exec);
        *restarts.lock().unwrap() = Some(Arc::clone(&daemon.restarts));
        let image = script_image(101, 0);
        let mut transfer = daemon
            .offer(&me(), &offer_for(&image, 101))
            .expect("accepted");
        transfer.write(&image).unwrap();
        transfer.verify().expect("a good image");
        assert!(matches!(
            transfer.restart(),
            UpdateResult::Rejected {
                code: RejectCode::ExecFailed,
                ..
            }
        ));
        assert_eq!(
            *seen.lock().unwrap(),
            vec![
                "staged exists true",
                "udp cloexec false",
                "control cloexec false",
                "memfd cloexec false",
                "spawn blocked true",
                "admission refused true",
                "control held true",
                "phase Draining",
            ]
        );
        assert!(handover::is_cloexec(udp_fd).unwrap());
        assert!(handover::is_cloexec(control_fd).unwrap());
        assert!(spawn_gate_free(), "children can be spawned again");
        assert!(!admission.is_closed(), "handshakes are admitted again");
        assert!(
            control_gate.try_read().is_ok(),
            "the control socket is free again"
        );
    }

    /// A handshake that reaches the nonce source while admission is closed
    /// is refused (the client sends its msg1 again and meets the new
    /// binary); once reopened, it is served by the source underneath.
    #[test]
    fn closed_admission_refuses_every_handshake_until_reopened() {
        let gate = Arc::new(AdmissionGate::default());
        let nonces = GatedNonces::new(Arc::new(transport::RandomNonces), Arc::clone(&gate));
        assert!(nonces.issue().is_ok());
        gate.close();
        assert!(nonces.issue().is_err());
        gate.open();
        assert!(nonces.issue().is_ok());
    }

    /// A child spawned through the permit waits for an exec window to end:
    /// it would otherwise inherit the descriptors the window makes
    /// inheritable.
    #[test]
    fn a_spawn_waits_for_the_exec_window() {
        // Serialised with the tests that look at the gate from outside.
        let _fds = fd_flags_lock();
        let window = exec_window_for_test();
        let spawned = Arc::new(AtomicBool::new(false));
        let spawner = {
            let spawned = Arc::clone(&spawned);
            std::thread::spawn(move || {
                let _permit = spawn_permit();
                spawned.store(true, Ordering::SeqCst);
            })
        };
        std::thread::sleep(Duration::from_millis(150));
        assert!(!spawned.load(Ordering::SeqCst), "held off by the window");
        drop(window);
        spawner.join().unwrap();
        assert!(spawned.load(Ordering::SeqCst));
    }

    /// Every attempt gets a larger number than the last, the aborted ones
    /// included.
    #[test]
    fn restarts_are_numbered_upwards() {
        let restarts = Restarts::new();
        let first = restarts.announce().unwrap();
        restarts.end();
        let second = restarts.announce().unwrap();
        assert!(second > first && first > 0);
        assert_eq!(
            *restarts.subscribe().borrow(),
            RestartSignal::announced(second, second)
        );
    }

    /// A session that joins just before `Draining` is waited for, however
    /// late its confirmation comes within the bound.
    #[test]
    fn a_session_that_joined_just_before_the_drain_is_waited_for() {
        let restarts = Arc::new(Restarts::new());
        let n = restarts.announce().unwrap();
        assert!(restarts.join(n), "announced: counted");
        restarts.drain(n);
        let late = {
            let restarts = Arc::clone(&restarts);
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                restarts.release(n);
            })
        };
        let started = Instant::now();
        assert!(restarts.wait_drained(n, DRAIN_TIMEOUT));
        assert!(
            started.elapsed() >= Duration::from_millis(150),
            "{:?}",
            started.elapsed()
        );
        late.join().unwrap();
    }

    /// A session that first hears of the attempt when it is already
    /// draining is neither counted nor waited for.
    #[test]
    fn a_late_subscriber_is_neither_counted_nor_waited_for() {
        let restarts = Restarts::new();
        let n = restarts.announce().unwrap();
        assert!(restarts.join(n));
        restarts.drain(n);
        assert!(!restarts.join(n), "draining: not counted");
        restarts.release(n);
        let started = Instant::now();
        assert!(restarts.wait_drained(n, DRAIN_TIMEOUT));
        assert!(started.elapsed() < Duration::from_millis(100));
        restarts.end();
        assert!(!restarts.join(n), "over: not counted");
    }

    /// Confirmations of an earlier attempt do not count towards this one.
    #[test]
    fn a_confirmation_of_an_older_restart_is_ignored() {
        let restarts = Restarts::new();
        let old = restarts.announce().unwrap();
        assert!(restarts.join(old));
        restarts.end();
        let n = restarts.announce().unwrap();
        assert!(restarts.join(n));
        restarts.drain(n);
        restarts.release(old);
        assert!(!restarts.wait_drained(n, Duration::from_millis(200)));
        restarts.release(n);
        assert!(restarts.wait_drained(n, Duration::from_millis(200)));
    }

    /// The daemon's side of the trait is the same count.
    #[test]
    fn the_daemon_counts_joins_and_releases_per_restart() {
        let dir = tempfile::tempdir().unwrap();
        let (daemon, _) = service(dir.path(), 1);
        let n = daemon.restarts.announce().unwrap();
        assert!(daemon.restart_joined(n));
        assert!(!daemon.restart_joined(n + 1), "not the attempt under way");
        daemon.restarts.drain(n);
        daemon.channels_released(n - 1);
        assert!(!daemon.restarts.wait_drained(n, Duration::from_millis(100)));
        daemon.channels_released(n);
        assert!(daemon.restarts.wait_drained(n, Duration::from_millis(100)));
    }

    /// A control-socket client that never finishes must not wedge the
    /// replacement: past the limit it gives up, rejected, and everything is
    /// open again.
    #[test]
    fn a_silent_control_client_cannot_wedge_the_replacement() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let execs = Arc::new(AtomicUsize::new(0));
        let exec: ExecFn = {
            let execs = Arc::clone(&execs);
            Arc::new(move |_: &Path, _: RawFd| {
                execs.fetch_add(1, Ordering::SeqCst);
                Errno::ENOENT
            })
        };
        let Restartable {
            daemon,
            transfer,
            admission,
            control_gate,
            udp: _udp,
            control: _control,
        } = verified_transfer(dir.path(), exec);
        let silent = control_gate.try_read().expect("a reader holds the gate");
        let started = Instant::now();
        match transfer.restart() {
            UpdateResult::Rejected { code, detail } => {
                assert_eq!(code, RejectCode::ControlBusy, "{detail}")
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
        let took = started.elapsed();
        assert!(
            took < RESTART_GRACE + CONTROL_GATE_TIMEOUT + Duration::from_millis(700),
            "{took:?}"
        );
        drop(silent);
        assert_eq!(
            execs.load(Ordering::SeqCst),
            0,
            "never got as far as the exec"
        );
        assert!(!admission.is_closed(), "handshakes are admitted again");
        assert_eq!(daemon.restart_signal().borrow().phase, RestartPhase::Idle);
        let image = script_image(101, 0);
        assert!(
            daemon.offer(&me(), &offer_for(&image, 101)).is_ok(),
            "the slot is free"
        );
    }

    /// The control socket is held still only from the allowlist snapshot to
    /// the exec: during the drain `STATUS` is still answered.
    #[test]
    fn the_control_socket_is_free_during_the_drain() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let exec: ExecFn = Arc::new(|_: &Path, _: RawFd| Errno::ENOENT);
        let Restartable {
            daemon,
            transfer,
            admission: _,
            control_gate,
            udp: _udp,
            control: _control,
        } = verified_transfer(dir.path(), exec);
        let (session, log) = fake_session(&daemon, Duration::ZERO, &control_gate);
        assert!(matches!(transfer.restart(), UpdateResult::Rejected { .. }));
        session.join().unwrap();
        assert_eq!(
            *log.lock().unwrap(),
            vec![
                "joined true",
                "control free during the drain true",
                "released"
            ]
        );
    }

    /// A session whose loop was busy through the whole grace joins late --
    /// and is still waited for: the drain begins only once every subscribed
    /// session has joined (within the drain budget), so its channels are
    /// reaped before the exec.
    #[test]
    fn a_session_that_joins_after_the_grace_is_still_drained() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let late: Arc<Mutex<Option<Log>>> = Arc::new(Mutex::new(None));
        let exec: ExecFn = {
            let seen = Arc::clone(&seen);
            let late = Arc::clone(&late);
            Arc::new(move |_: &Path, _: RawFd| {
                let log = late.lock().unwrap().clone().unwrap();
                seen.lock()
                    .unwrap()
                    .push(format!("at exec: {:?}", log.lock().unwrap()));
                Errno::ENOENT
            })
        };
        let Restartable {
            daemon,
            transfer,
            admission: _,
            control_gate,
            udp: _udp,
            control: _control,
        } = verified_transfer(dir.path(), exec);
        let (session, log) = fake_session(
            &daemon,
            RESTART_GRACE + Duration::from_millis(400),
            &control_gate,
        );
        *late.lock().unwrap() = Some(Arc::clone(&log));
        assert!(matches!(transfer.restart(), UpdateResult::Rejected { .. }));
        session.join().unwrap();
        assert_eq!(
            *seen.lock().unwrap(),
            vec![r#"at exec: ["joined true", "control free during the drain true", "released"]"#]
        );
    }

    /// A subscribed session that never joins holds the drain back only for
    /// the join limit: then `Draining` goes out, and a session that did join
    /// still gets the whole drain budget to reap -- the stuck one does not
    /// eat it.
    #[test]
    fn a_session_that_never_joins_does_not_eat_the_drain_budget() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let reaper: Arc<Mutex<Option<Log>>> = Arc::new(Mutex::new(None));
        let exec: ExecFn = {
            let seen = Arc::clone(&seen);
            let reaper = Arc::clone(&reaper);
            Arc::new(move |_: &Path, _: RawFd| {
                let log = reaper.lock().unwrap().clone().unwrap();
                seen.lock()
                    .unwrap()
                    .push(format!("at exec: {:?}", log.lock().unwrap()));
                Errno::ENOENT
            })
        };
        let Restartable {
            daemon,
            transfer,
            admission: _,
            control_gate,
            udp: _udp,
            control: _control,
        } = verified_transfer(dir.path(), exec);
        // Subscribed, and never heard from again.
        let stuck = daemon.restart_signal();
        // Reaping takes most of the drain budget -- more than would be left
        // of one budget shared with the join wait.
        let (session, log) = fake_session_reaping(
            &daemon,
            Duration::ZERO,
            DRAIN_TIMEOUT - Duration::from_millis(800),
            &control_gate,
        );
        *reaper.lock().unwrap() = Some(Arc::clone(&log));
        let restarts = Arc::clone(&daemon.restarts);
        let started = Instant::now();
        let drained_at = std::thread::spawn(move || {
            while restarts.phase() != RestartPhase::Draining {
                std::thread::sleep(Duration::from_millis(5));
            }
            Instant::now()
        });
        assert!(matches!(transfer.restart(), UpdateResult::Rejected { .. }));
        session.join().unwrap();
        let to_drain = drained_at.join().unwrap() - started;
        drop(stuck);
        assert!(
            to_drain >= RESTART_GRACE + JOIN_TIMEOUT
                && to_drain < RESTART_GRACE + JOIN_TIMEOUT + Duration::from_millis(500),
            "Draining went out {to_drain:?} in"
        );
        assert_eq!(
            *seen.lock().unwrap(),
            vec![r#"at exec: ["joined true", "control free during the drain true", "released"]"#]
        );
    }

    /// Daemons with different names share the binary's directory: a staged
    /// file of another daemon that is still alive is its own business, and
    /// stays; one of a dead process, or of this very process, goes.
    #[test]
    fn a_live_daemons_staged_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("qshd");
        std::fs::write(&binary, b"binary").unwrap();
        let mut other = Command::new("sleep").arg("5").spawn().unwrap();
        let live = format!(".qshd-update-{}-0", other.id());
        let dead = format!(".qshd-update-{}-0", dead_pid());
        let mine = format!(".qshd-update-{}-3", std::process::id());
        for name in [&live, &dead, &mine, &".qshd-update-junk".to_string()] {
            std::fs::write(dir.path().join(name), b"image").unwrap();
        }
        remove_stale_staged(&binary, None);
        let mut left: Vec<String> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        let _ = other.kill();
        let _ = other.wait();
        assert_eq!(left, vec![live.as_str(), "qshd"]);
    }

    fn executable(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    /// A self-check that leaves a process behind holding its stdout, and
    /// prints nothing, is given up on within the limit -- reading its output
    /// is bounded too.
    #[test]
    fn a_self_check_whose_output_never_ends_is_given_up_on() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let path = executable(
            dir.path(),
            "held",
            "#!/bin/sh
sleep 3 &
exit 0
",
        );
        let started = Instant::now();
        let err = run_self_check(&path, Duration::from_secs(1)).unwrap_err();
        assert!(
            started.elapsed() < Duration::from_millis(1800),
            "{:?}: {err}",
            started.elapsed()
        );
    }

    /// One that prints its line first and then leaves a process behind is
    /// read at once: the line is all there is to read.
    #[test]
    fn a_self_check_that_prints_then_leaves_a_process_behind_is_read_at_once() {
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let script = String::from_utf8(script_image(101, 0)).unwrap();
        let script = script.strip_suffix("exit 0\n").unwrap().to_string() + "sleep 3 &\nexit 0\n";
        let path = executable(dir.path(), "prints", &script);
        let started = Instant::now();
        let check = run_self_check(&path, Duration::from_secs(2)).expect("a self-check line");
        assert_eq!(check.build, 101);
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    /// A panic anywhere in the replacement undoes it like any failure:
    /// handshakes admitted, the attempt over, the slot free, the descriptors
    /// close-on-exec again.
    #[test]
    fn a_panic_in_the_replacement_puts_everything_back() {
        let _fds = fd_flags_lock();
        suppress_shell_history();
        let dir = tempfile::tempdir().unwrap();
        let exec: ExecFn = Arc::new(|_: &Path, _: RawFd| panic!("an injected panic"));
        let Restartable {
            daemon,
            transfer,
            admission,
            control_gate: _,
            udp,
            control,
        } = verified_transfer(dir.path(), exec);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| transfer.restart()));
        assert!(result.is_err(), "the panic went through");
        assert!(!admission.is_closed(), "handshakes are admitted again");
        assert_eq!(daemon.restart_signal().borrow().phase, RestartPhase::Idle);
        assert!(handover::is_cloexec(udp.as_raw_fd()).unwrap());
        assert!(handover::is_cloexec(control.as_raw_fd()).unwrap());
        assert!(spawn_gate_free(), "children can be spawned again");
        let image = script_image(101, 0);
        assert!(
            daemon.offer(&me(), &offer_for(&image, 101)).is_ok(),
            "the slot is free"
        );
    }

    /// The daemon's receivers are the sessions' alone: it keeps none of its
    /// own, so the subscriber count it waits on counts sessions only.
    #[test]
    fn the_daemon_holds_no_receiver_of_its_own() {
        let restarts = Restarts::new();
        assert_eq!(restarts.subscribers(), 0);
        let rx = restarts.subscribe();
        assert_eq!(restarts.subscribers(), 1);
        drop(rx);
        assert_eq!(restarts.subscribers(), 0);
    }

    /// The offering session is in nobody's way: one helper says so at every
    /// place the sessions are counted.
    #[test]
    fn the_offering_session_is_not_counted_against_itself() {
        assert_eq!(others_than_offering(0), 0);
        assert_eq!(others_than_offering(1), 0);
        assert_eq!(others_than_offering(4), 3);
    }

    /// A daemon built for tests or production hashes nothing until asked;
    /// asked twice, it works its image out once.
    #[test]
    fn the_own_image_is_worked_out_once() {
        let daemon = DaemonSelf::managed(ChannelOpenRegistry::new(Default::default()), None);
        assert!(daemon.own.get().is_none(), "nothing hashed at construction");
        let first = daemon.about();
        assert!(daemon.own.get().is_some());
        assert_eq!(daemon.about(), first);
    }
}
