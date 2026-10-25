//! Protocol of the `qshd` daemon's control Unix socket: request/response
//! types, their line-based codec (parse/serialize), and a synchronous
//! client ([`client_request`]). The async server for this protocol is
//! separate per daemon path (there used to be a `serve_control` for the
//! qsh path, removed along with `quic.rs`/`ports.rs` when the daemon moved
//! to the new transport; the new transport has
//! [`crate::transport_daemon::serve_transport_control`]), so only the
//! shared types/codec/client remain here.
//!
//! **Incident notes ([`ControlReply`]):** the `STATUS` handler used to
//! re-hash the daemon's own (debug-build) executable on every single
//! request (`state::self_checksum`, tens of MB, unoptimized `sha2`) --
//! measured at ~1.7s idle and ~7s under CPU load on a four-core box. That
//! alone was fixed by caching the checksum once per process (see
//! `state::self_checksum`'s doc comment), but it exposed a second, harmful
//! bug in this module: [`client_request`] used to map BOTH "nothing is
//! listening" and "a read timed out on an established connection" to the
//! same `Ok(None)`. A `transport-ensure` client reading a slow-but-alive
//! daemon's silence as "no daemon" would go bind the port that daemon
//! still held, fail with `AddrInUse`, and blame a fictitious "old-version
//! daemon". [`ControlReply`] exists so those two outcomes can never be
//! conflated again, regardless of how fast or slow `STATUS` itself gets in
//! the future.

mod path;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Control socket client request (a text line without `\n`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlRequest {
    /// Return the daemon's current state ([`StatusResponse`]).
    Status,
    /// Start listening on one more QUIC port (without restarting the daemon).
    AddPort(u16),
    /// Add a client Noise key (32-byte X25519) to a live transport daemon's
    /// allowlist (`transport-ensure`): the daemon adds the key to its
    /// IN-MEMORY set of trusted clients only (`transport_daemon::apply_add_client`
    /// -- an earlier on-disk copy of the allowlist was retired in favor of
    /// this live, self-cleaning one). The
    /// qsh path (mTLS certificates) does not use this request.
    AddClient([u8; 32]),
    /// Shut the daemon down.
    Stop,
}

/// State of a single port on which the daemon accepts QUIC connections --
/// part of [`StatusResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortStatus {
    pub port: u16,
    /// The port the daemon was originally started with (from `server.json`),
    /// as opposed to ports added later via `ADD-PORT`.
    pub default: bool,
    pub connections: u64,
}

/// A snapshot of registered personal-channel custody only. Empty custody does
/// not prove that every OS descendant or a privileged helper has completed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupStatusResponse {
    pub domain: CleanupDomain,
    pub phase: CleanupPhase,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counts: Option<CleanupCounts>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupDomain {
    PersonalChannels,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupPhase {
    Completed,
    Pending,
    Unresolved,
    Unknown,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CleanupCounts {
    pub healthy_pending_opens: usize,
    pub canceled_opens: usize,
    pub retiring_channels: usize,
    pub observed_unconfirmed_owners: usize,
    pub unique_cleanup_debt: usize,
    pub leader_unconfirmed: bool,
    pub cleanup_unconfirmed: bool,
    pub observation_panicked: bool,
}
impl CleanupStatusResponse {
    pub fn from_snapshot(snapshot: Option<transport::channel_open::CleanupSnapshot>) -> Self {
        let counts = snapshot.map(|s| CleanupCounts {
            healthy_pending_opens: s.healthy_pending_opens,
            canceled_opens: s.canceled_opens,
            retiring_channels: s.retiring_channels,
            observed_unconfirmed_owners: s.observed_unconfirmed_owners,
            unique_cleanup_debt: s.unique_cleanup_debt,
            leader_unconfirmed: s.leader_unconfirmed,
            cleanup_unconfirmed: s.cleanup_unconfirmed,
            observation_panicked: s.observation_panicked,
        });
        let phase = match counts {
            None => CleanupPhase::Unknown,
            Some(c) if c.observed_unconfirmed_owners != 0 => CleanupPhase::Unresolved,
            Some(c) if c.unique_cleanup_debt != 0 || c.healthy_pending_opens != 0 => {
                CleanupPhase::Pending
            }
            Some(_) => CleanupPhase::Completed,
        };
        Self {
            domain: CleanupDomain::PersonalChannels,
            phase,
            counts,
        }
    }
}

/// Response to `STATUS` -- executable version/build/checksum and the list of
/// ports with the active connection count on each. The fields and their
/// names are part of a contract with other code that reads them directly
/// (`reconcile` and the `ensure` client both do), so they cannot change
/// without a coordinated update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Bounded same-account startup diagnostic, never credential contents.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logging_warning: Option<String>,
    /// Absent on older daemons or a backend without this registered domain.
    /// Absence means unknown, never completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<CleanupStatusResponse>,
    pub version: String,
    pub build: u64,
    pub checksum: String,
    pub ports: Vec<PortStatus>,
    pub total_connections: u64,
    /// The daemon's process id. Absent (zero) from a daemon that predates the
    /// field. The same across an update over qsh, which replaces the binary
    /// in place.
    #[serde(default)]
    pub pid: u32,
}

impl StatusResponse {
    /// Compact JSON without whitespace plus a trailing `\n` -- this is
    /// exactly how it goes out as a single line on the control socket.
    pub fn to_line(&self) -> Result<String> {
        let mut line = serde_json::to_string(self).context("serializing StatusResponse to JSON")?;
        line.push('\n');
        Ok(line)
    }

    /// Parse a line without a trailing `\n` (the caller strips it, the way
    /// the socket's line reader does).
    pub fn from_line(line: &str) -> Result<Self> {
        serde_json::from_str(line).context("parsing StatusResponse from JSON")
    }
}

/// Parse a control socket request line. The line arrives already stripped
/// of its trailing `\n` (the socket's line reader removes it).
pub fn parse_request(line: &str) -> Option<ControlRequest> {
    let mut parts = line.split(' ');
    match parts.next()? {
        "STATUS" => {
            if parts.next().is_some() {
                return None;
            }
            Some(ControlRequest::Status)
        }
        "ADD-PORT" => {
            let port_str = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            port_str.parse::<u16>().ok().map(ControlRequest::AddPort)
        }
        "ADD-CLIENT" => {
            let b64 = parts.next()?;
            if parts.next().is_some() {
                return None;
            }
            let raw = BASE64.decode(b64).ok()?;
            let key: [u8; 32] = raw.as_slice().try_into().ok()?;
            Some(ControlRequest::AddClient(key))
        }
        "STOP" => {
            if parts.next().is_some() {
                return None;
            }
            Some(ControlRequest::Stop)
        }
        _ => None,
    }
}

/// Build a request line to send on the socket -- the inverse of
/// [`parse_request`], with a trailing `\n`.
pub fn format_request(req: &ControlRequest) -> String {
    match req {
        ControlRequest::Status => "STATUS\n".to_string(),
        ControlRequest::AddPort(port) => format!("ADD-PORT {port}\n"),
        ControlRequest::AddClient(key) => format!("ADD-CLIENT {}\n", BASE64.encode(key)),
        ControlRequest::Stop => "STOP\n".to_string(),
    }
}

/// Short read timeout for the control socket response: a stale socket
/// (the file is still there but nothing is listening on the other end)
/// must not hang `ensure` for long -- it is only asking "is the daemon
/// alive?". Public so a caller that DOES get [`ControlReply::TimedOut`] can
/// name the budget it waited out in its own error message, instead of
/// duplicating the number.
pub const CLIENT_READ_TIMEOUT: Duration = Duration::from_secs(2);

/// The three, and only three, outcomes of asking the control socket a
/// question. Collapsing the last two into one value is exactly the bug this
/// type exists to prevent: if [`UnixStream::connect`] succeeds, SOMETHING is
/// listening, so a subsequent read timeout means "present but slow", never
/// "absent" -- see [`client_request`]'s doc comment for the incident this
/// distinction fixes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlReply {
    /// The daemon answered within the budget; the line, with its trailing
    /// `\n` stripped.
    Answered(String),
    /// Nothing is listening: no socket file, a refused connection (a stale
    /// socket file with no live listener behind it), or a peer that closes
    /// the connection without writing a single byte -- exactly what a first
    /// launch legitimately looks like.
    NoDaemon,
    /// A connection WAS accepted -- a daemon holds the control socket -- but
    /// it did not answer within the budget. The daemon is alive and busy,
    /// not gone; a caller must not treat this as permission to start a
    /// second daemon.
    TimedOut,
}

/// Synchronous control socket client -- used in `ensure` BEFORE forking and
/// BEFORE the tokio runtime is created (forking a multi-threaded tokio
/// process is undefined behavior), so it deliberately uses a blocking
/// `std::os::unix::net::UnixStream` instead of tokio.
///
/// A connection error (no socket file, nothing listening) is an expected
/// case on first launch, not a failure: it returns `Ok(ControlReply::NoDaemon)`,
/// not `Err`. A read TIMEOUT on an already-established connection is
/// DIFFERENT and must stay different: the connection succeeded, so a daemon
/// is there, merely slow to answer (e.g. a `STATUS` handler doing real work
/// under load) -- that is [`ControlReply::TimedOut`], not `NoDaemon`.
/// Conflating the two used to make `transport-ensure` start a second daemon
/// on top of a live, merely-busy one, which then failed to bind the port the
/// live daemon still held and blamed a fictitious "old version" (see the
/// module-level incident notes for the measurements).
///
/// Uses the production budget [`CLIENT_READ_TIMEOUT`]; see
/// [`client_request_with_timeout`] for an injectable budget (tests only).
pub fn client_request(sock_path: &Path, req: &ControlRequest) -> Result<ControlReply> {
    client_request_with_timeout(sock_path, req, CLIENT_READ_TIMEOUT)
}

/// [`client_request`] with an explicit read-timeout budget. Exists so tests
/// exercising the "accepts but never answers" case don't have to eat the
/// full 2s production budget; production code should call [`client_request`]
/// and get [`CLIENT_READ_TIMEOUT`] instead of picking a number.
pub fn client_request_with_timeout(
    sock_path: &Path,
    req: &ControlRequest,
    timeout: Duration,
) -> Result<ControlReply> {
    client_request_with_peer_check(sock_path, req, timeout, check_control_peer)
}

fn client_request_with_peer_check(
    sock_path: &Path,
    req: &ControlRequest,
    timeout: Duration,
    check: impl FnOnce(&UnixStream) -> Result<()>,
) -> Result<ControlReply> {
    let authority = match path::EndpointAuthority::open(sock_path, false) {
        Ok(authority) => authority,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ControlReply::NoDaemon)
        }
        Err(error) => return Err(error).context("validating the control endpoint parent"),
    };
    client_request_at(&authority, req, timeout, check)
}

fn client_request_at(
    authority: &path::EndpointAuthority,
    req: &ControlRequest,
    timeout: Duration,
    check: impl FnOnce(&UnixStream) -> Result<()>,
) -> Result<ControlReply> {
    authority.validate_route()?;
    if authority.entry()?.is_none() {
        authority.validate_route()?;
        return Ok(ControlReply::NoDaemon);
    }
    let mut stream = match UnixStream::connect(&authority.syscall_path) {
        Ok(stream) => stream,
        Err(error) => {
            authority.validate_route()?;
            return match error.kind() {
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => {
                    Ok(ControlReply::NoDaemon)
                }
                _ => Err(error).context("connecting to the trusted control endpoint"),
            };
        }
    };

    authority.validate_route()?;
    check(&stream)?;
    // A relative-path peer check may observe a process-wide cwd/route change.
    // Refuse it before any request bytes, not only after the response.
    authority.validate_route()?;

    stream
        .set_read_timeout(Some(timeout))
        .context("setting the control socket's read timeout")?;

    if stream.write_all(format_request(req).as_bytes()).is_err() {
        authority.validate_route()?;
        return Ok(ControlReply::NoDaemon);
    }
    // Half-close the write side -- signals the server that the request is
    // fully written (it reads the line up to `\n`, but the half-close is
    // harmless and adds a safety net).
    let _ = stream.shutdown(std::net::Shutdown::Write);

    let mut reader = BufReader::new(stream);
    let mut line = String::new();
    let reply = match reader.read_line(&mut line) {
        Ok(0) => Ok(ControlReply::NoDaemon), // closed with no response -- no one home
        Ok(_) => Ok(ControlReply::Answered(
            line.trim_end_matches('\n').to_string(),
        )),
        Err(e) if is_timeout(&e) => Ok(ControlReply::TimedOut),
        Err(_) => Ok(ControlReply::NoDaemon), // other read errors (e.g. reset) -- as before
    };
    authority.validate_route()?;
    reply
}

/// Was this read error a timeout expiring (as set by `set_read_timeout`),
/// as opposed to some other I/O failure? A blocking Unix socket read that
/// times out surfaces as `WouldBlock` on Linux (verified: `SO_RCVTIMEO`
/// expiring returns `EAGAIN`); `TimedOut` is accepted too since that is
/// what the platform-independent parts of `std` document for a timing out
/// read and nothing guarantees `WouldBlock` everywhere `qshd` might build.
fn is_timeout(e: &std::io::Error) -> bool {
    matches!(
        e.kind(),
        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
    )
}

/// What [`stop_daemon_and_wait`] saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopOutcome {
    /// No socket file at the path: there is no daemon to stop.
    NoDaemon,
    /// The socket file is there but nothing answered `STATUS` within the
    /// patience, so no `STOP` was sent: whatever holds the socket (if
    /// anything does) is still there.
    NeverAnswered,
    /// The daemon's process is gone -- or, when it did not name its pid
    /// (`pid` 0, or no `/proc` to look in), its control socket is.
    Stopped { pid: u32 },
    /// `STOP` was sent (and acknowledged, if `stop_answered`), yet after the
    /// patience the process -- or, with `pid` 0, the socket -- is still
    /// there.
    StillThere { pid: u32, stop_answered: bool },
}

impl StopOutcome {
    /// Whether a daemon may have been left running.
    pub fn may_have_leaked(&self) -> bool {
        matches!(
            self,
            StopOutcome::NeverAnswered | StopOutcome::StillThere { .. }
        )
    }
}

/// How many times [`stop_daemon_and_wait`] sends `STOP` before it only waits.
const STOP_ATTEMPTS: usize = 5;

/// Stops the daemon at `sock` and waits until its process is gone. For
/// callers that must know a daemon they started is really over (test
/// harnesses, before they drop its temp dir); it talks only to `sock`, and
/// signals nothing: a daemon that will not go is reported, never killed.
///
/// A plain `STOP` is not enough. The daemon writes its answer before it
/// acts on it, so a client that gave up waiting (a daemon not yet in its
/// accept loop answers late) makes that write fail and the `STOP` is lost.
/// So this: waits (up to `patience`) until `STATUS` answers and takes the
/// daemon's pid from it; sends `STOP`, again while it was not acknowledged
/// and the daemon is still there ([`STOP_ATTEMPTS`] in all); then waits (up
/// to `patience` again) until `/proc/<pid>` is gone -- or, when the pid is
/// unknown, until the socket file is.
pub fn stop_daemon_and_wait(sock: &Path, patience: Duration) -> StopOutcome {
    stop_daemon_and_wait_with(sock, patience, CLIENT_READ_TIMEOUT)
}

/// [`stop_daemon_and_wait`] with an explicit per-request read timeout, so
/// tests of a silent peer need not wait out [`CLIENT_READ_TIMEOUT`].
fn stop_daemon_and_wait_with(sock: &Path, patience: Duration, read: Duration) -> StopOutcome {
    use std::time::Instant;
    let pause = Duration::from_millis(50);

    let deadline = Instant::now() + patience;
    let pid = loop {
        if let Ok(ControlReply::Answered(line)) =
            client_request_with_timeout(sock, &ControlRequest::Status, read)
        {
            break StatusResponse::from_line(&line).map_or(0, |s| s.pid);
        }
        if !sock.exists() {
            return StopOutcome::NoDaemon;
        }
        if Instant::now() >= deadline {
            return StopOutcome::NeverAnswered;
        }
        std::thread::sleep(pause);
    };

    let mut stop_answered = false;
    for _ in 0..STOP_ATTEMPTS {
        if let Ok(ControlReply::Answered(line)) =
            client_request_with_timeout(sock, &ControlRequest::Stop, read)
        {
            let ack = serde_json::from_str::<serde_json::Value>(&line).is_ok_and(|v| {
                // Older peers used "stopped" for the same acknowledgement.
                // Neither reply replaces the actual exit observation below.
                v["stopping"] == serde_json::Value::Bool(true)
                    || v["stopped"] == serde_json::Value::Bool(true)
            });
            if ack {
                stop_answered = true;
                break;
            }
        }
        // A STOP that did arrive takes a moment to act on: look before
        // sending another.
        std::thread::sleep(pause * 4);
        if daemon_gone(pid, sock) {
            break;
        }
    }

    let deadline = Instant::now() + patience;
    while !daemon_gone(pid, sock) {
        if Instant::now() >= deadline {
            return StopOutcome::StillThere { pid, stop_answered };
        }
        std::thread::sleep(pause);
    }
    StopOutcome::Stopped { pid }
}

/// Whether the daemon of [`stop_daemon_and_wait`] is gone: its `/proc`
/// entry, or with no pid (or no `/proc`) its control socket file. Only
/// looks.
fn daemon_gone(pid: u32, sock: &Path) -> bool {
    if pid != 0 && Path::new("/proc/self").exists() {
        !Path::new(&format!("/proc/{pid}")).exists()
    } else {
        !sock.exists()
    }
}

/// Serializes check/start/publication for one personal control path. The file
/// is permanent: unlinking it would let later callers lock a different inode.
/// Drop only closes this descriptor, never LOCK_UN: a fork inherits the same
/// open-file description, so the lock ends only after its last copy closes.
pub struct EnsureLock {
    authority: path::EndpointAuthority,
    _file: std::fs::File,
}

impl EnsureLock {
    /// Attempt immediately, even for a zero budget, then bound contention by
    /// `patience`. This does not bound filesystem operations or the transaction
    /// performed after acquisition. A timeout never removes or unlocks the file.
    pub fn acquire(socket: &Path, patience: Duration) -> std::io::Result<Self> {
        Self::acquire_prepared(socket, patience, || {})
    }

    fn acquire_prepared(
        socket: &Path,
        patience: Duration,
        opened: impl FnOnce(),
    ) -> std::io::Result<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::MetadataExt;
        let authority = path::EndpointAuthority::open(socket, true)?;
        authority.entry()?;
        let file = authority.open_lock()?;
        let metadata = file.metadata()?;
        let identity = nix::sys::stat::fstat(file.as_raw_fd())?;
        if !metadata.is_file()
            || metadata.uid() != nix::unistd::geteuid().as_raw()
            || metadata.nlink() != 1
            || metadata.mode() & 0o7777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "the ensure lock must be a private, singly linked regular file owned by this user",
            ));
        }
        opened();
        let deadline = std::time::Instant::now()
            .checked_add(patience)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "ensure lock wait budget is too large",
                )
            })?;
        let mut attempted = false;
        loop {
            // There is one immediate attempt, including with zero patience.
            // Neither contention nor EINTR grants another attempt after expiry.
            if attempted && std::time::Instant::now() >= deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("timed out after {patience:?} waiting for another transport ensure transaction"),
                ));
            }
            attempted = true;
            // SAFETY: the descriptor remains owned by file throughout the call.
            if unsafe {
                nix::libc::flock(file.as_raw_fd(), nix::libc::LOCK_EX | nix::libc::LOCK_NB)
            } == 0
            {
                break;
            }
            let error = std::io::Error::last_os_error();
            match error.kind() {
                std::io::ErrorKind::Interrupted => continue,
                std::io::ErrorKind::WouldBlock => std::thread::sleep(
                    Duration::from_millis(25)
                        .min(deadline.saturating_duration_since(std::time::Instant::now())),
                ),
                _ => return Err(error),
            }
        }
        authority.validate_route()?;
        let current = nix::sys::stat::fstatat(
            Some(authority.parent.as_raw_fd()),
            authority.lock.as_os_str(),
            nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
        )?;
        if !path::same(&current, &identity) {
            return Err(path::refused("the ensure lock changed while waiting"));
        }
        Ok(Self {
            authority,
            _file: file,
        })
    }

    /// Reject an observed route change; never move an active transaction.
    pub fn validate_route(&self) -> std::io::Result<()> {
        self.authority.validate_route()
    }

    pub fn request(&self, request: &ControlRequest) -> Result<ControlReply> {
        client_request_at(
            &self.authority,
            request,
            CLIENT_READ_TIMEOUT,
            check_control_peer,
        )
    }

    pub fn bind_private_owned(&self) -> std::io::Result<(UnixListener, SocketCleanup)> {
        bind_with_authority(&self.authority)
    }

    pub fn endpoint_exists(&self) -> std::io::Result<bool> {
        self.validate_route()?;
        Ok(self.authority.entry()?.is_some())
    }
}

/// Owns removal of one published socket, including startup errors. Keeping a
/// listener reference until removal prevents another ensure from observing a
/// refused endpoint between the serving future's drop and this cleanup.
/// The duplicate is close-on-exec; only the original listener crosses update
/// handover, whose resumed owner creates its own guard before serving.
pub struct SocketCleanup {
    parent: std::fs::File,
    leaf: std::ffi::OsString,
    device: nix::libc::dev_t,
    inode: nix::libc::ino_t,
    remove_on_drop: bool,
    _listener: UnixListener,
}

impl SocketCleanup {
    /// A daemonization parent cannot infer child death from a wait error.
    /// Leave publication to the child's inherited guard (or stale recovery).
    pub fn leave_to_child(&mut self) {
        self.remove_on_drop = false;
    }

    /// The caller must know that this path names this listener: an owned
    /// private staging path, or a cooperatively inherited update listener.
    /// A live inherited listener prevents another ensure from replacing it;
    /// arbitrary external same-UID pathname mutation is outside this contract.
    pub fn capture(listener: &UnixListener, path: &Path) -> std::io::Result<Self> {
        let authority = path::EndpointAuthority::open(path, false)?;
        authority.validate_route()?;
        let metadata = authority.entry()?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "the control publication is missing",
            )
        })?;
        if metadata.st_mode & 0o7777 != 0o600 {
            return Err(path::refused(
                "the inherited control publication must be private",
            ));
        }
        Self::from_authority(listener, &authority, &metadata)
    }

    fn from_authority(
        listener: &UnixListener,
        authority: &path::EndpointAuthority,
        metadata: &nix::libc::stat,
    ) -> std::io::Result<Self> {
        let parent = authority.parent.try_clone()?;
        Ok(Self {
            parent,
            leaf: authority.leaf.clone(),
            device: metadata.st_dev,
            inode: metadata.st_ino,
            remove_on_drop: true,
            _listener: listener.try_clone()?,
        })
    }
}

impl Drop for SocketCleanup {
    fn drop(&mut self) {
        if !self.remove_on_drop {
            return;
        }
        use nix::fcntl::AtFlags;
        use nix::sys::stat::{fstatat, SFlag};
        use std::os::fd::AsRawFd;
        if let Ok(current) = fstatat(
            Some(self.parent.as_raw_fd()),
            self.leaf.as_os_str(),
            AtFlags::AT_SYMLINK_NOFOLLOW,
        ) {
            if current.st_mode & SFlag::S_IFMT.bits() == SFlag::S_IFSOCK.bits()
                && current.st_dev == self.device
                && current.st_ino == self.inode
            {
                let _ = nix::unistd::unlinkat(
                    Some(self.parent.as_raw_fd()),
                    self.leaf.as_os_str(),
                    nix::unistd::UnlinkatFlags::NoRemoveDir,
                );
            }
        }
    }
}

/// Name of the staged socket inside the staging directory. One byte, kept
/// short for the same reason the directory name is (see [`bind_private`]'s
/// doc, Minor 1 of the task 6 review): a long staging path could refuse to
/// bind at a length a plain bind at the final name would have accepted.
const STAGED_NAME: &str = "s";

/// Low-level pathname-bind fixture for the original permission/length tests.
/// Production binds through the verified exclusive stage in `path::Stage`.
#[cfg(test)]
fn bind_in(dir: &Path, name: &str) -> std::io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;
    let staged = dir.join(name);
    let listener = UnixListener::bind(&staged).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!("binding the staging socket {}: {e}", staged.display()),
        )
    })?;
    std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

/// Bind the control socket at `path` so that nobody but its owner can reach
/// it, not even for an instant (spec §4.16, QSH-14): bound inside a verified
/// fresh `0700` directory next to `path`, where the
/// umask's permissions on the file let nobody in -- tightened to `0600`,
/// then renamed into place, which also replaces a stale file of a daemon
/// that died. Not a process-wide umask: that would race every other thread
/// creating a file.
///
/// The staging name (`.c<pid>/s`) is kept short on purpose (task 6 review,
/// Minor 1): the earlier scheme (`.control-<pid>.bind/control.sock`) added
/// about 22 bytes over the final name, long enough that a `path` a plain
/// `bind` would still accept could refuse here with `ENAMETOOLONG`.
/// The binding error names the staging path it actually failed on, since
/// that is the one that may be too long even though `path` itself is not.
pub fn bind_private(path: &Path) -> std::io::Result<UnixListener> {
    let (listener, mut cleanup) = bind_private_owned(path)?;
    // This convenience API deliberately leaves the endpoint to its caller.
    cleanup.leave_to_child();
    Ok(listener)
}

/// Standalone binding convenience; production ensure uses its retained lock.
pub fn bind_private_owned(path: &Path) -> std::io::Result<(UnixListener, SocketCleanup)> {
    bind_with_authority(&path::EndpointAuthority::open(path, false)?)
}

fn bind_with_authority(
    authority: &path::EndpointAuthority,
) -> std::io::Result<(UnixListener, SocketCleanup)> {
    bind_prepared(authority, |_| {})
}

fn bind_prepared(
    authority: &path::EndpointAuthority,
    configure: impl FnOnce(&mut path::Stage),
) -> std::io::Result<(UnixListener, SocketCleanup)> {
    authority.validate_route()?;
    authority.entry()?;
    sweep_stale_staging_at(&authority.parent, std::time::SystemTime::now());
    let mut stage = path::Stage::create(authority)?;
    configure(&mut stage);
    let listener = stage.bind(authority)?;
    // Allocate every cleanup descriptor before publication. On a later error,
    // this guard owns only this socket in this pinned parent, never a new route.
    let cleanup = SocketCleanup::from_authority(&listener, authority, stage.socket())?;
    stage.publish(authority)?;
    Ok((listener, cleanup))
}

/// Minimum staging age for conservative crash recovery. Age is a heuristic;
/// the separate PID check also preserves every process visible to this caller.
/// Neither check proves that an inaccessible PID namespace has no live owner.
const STALE_STAGING_AFTER: Duration = Duration::from_secs(60);

/// The pid in a staging directory's name, if the name is exactly what
/// [`bind_private`] writes: `.c` and a positive pid in decimal, no leading
/// zero, nothing after it.
fn staging_pid(name: &str) -> Option<i32> {
    let digits = name.strip_prefix(".c")?;
    if digits.is_empty() || digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse::<i32>().ok().filter(|&pid| pid > 0)
}

/// Whether a process with this pid exists (a zombie counts), as far as
/// this process can tell: only `ESRCH` says it does not.
fn process_exists(pid: i32) -> bool {
    !matches!(
        nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid), None),
        Err(nix::errno::Errno::ESRCH)
    )
}

/// Remove the staging directories that daemons of this user left in
/// `parent` when they died between [`bind_private`]'s `mkdir` and its
/// cleanup (final review of slice 5, M4): only the next run with the same
/// pid would otherwise remove one. Best effort, and conservative: a
/// directory is removed only if every one of these holds --
///
/// - its name is `.c<pid>` exactly (see [`staging_pid`]);
/// - it is a directory, not a symlink to one: it is opened with
///   `O_NOFOLLOW`, and what that descriptor shows is what gets emptied;
/// - it belongs to this process's effective uid and its mode is `0700`, as
///   `bind_private` makes it;
/// - it has gone unchanged for [`STALE_STAGING_AFTER`] as of `now`;
/// - no process with its pid exists (a pid in use by anyone is left alone,
///   whatever that process is);
/// - it is empty, or holds only the staged socket (`s`, a socket, this
///   uid's) -- which is dead then: its pid is gone.
///
/// The socket is unlinked through the directory's descriptor, the
/// directory by name with `AT_REMOVEDIR`, which removes only an empty
/// directory and never follows a symlink. Anything else in `parent` is
/// never touched. Returns how many directories were removed.
#[cfg(test)]
fn sweep_stale_staging(parent: &Path, now: std::time::SystemTime) -> usize {
    let Ok(authority) = path::EndpointAuthority::open(&parent.join("control.sock"), false) else {
        return 0;
    };
    sweep_stale_staging_at(&authority.parent, now)
}

fn sweep_stale_staging_at(parent: &std::fs::File, now: std::time::SystemTime) -> usize {
    use nix::dir::Dir;
    use nix::fcntl::OFlag;
    use nix::sys::stat::Mode;
    use std::os::fd::AsRawFd;
    let Ok(mut entries) = Dir::openat(
        Some(parent.as_raw_fd()),
        ".",
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) else {
        return 0;
    };
    let mut removed = 0;
    for entry in entries.iter().flatten() {
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        let Some(pid) = staging_pid(name) else {
            continue;
        };
        if remove_if_stale(parent.as_raw_fd(), name, pid, now) {
            removed += 1;
        }
    }
    removed
}

/// One directory of [`sweep_stale_staging`]: whether it was removed.
fn remove_if_stale(
    parent: std::os::fd::RawFd,
    name: &str,
    pid: i32,
    now: std::time::SystemTime,
) -> bool {
    remove_if_stale_prepared(parent, name, pid, now, || {})
}

fn remove_if_stale_prepared(
    parent: std::os::fd::RawFd,
    name: &str,
    pid: i32,
    now: std::time::SystemTime,
    before_remove: impl FnOnce(),
) -> bool {
    use nix::dir::Dir;
    use nix::fcntl::{AtFlags, OFlag};
    use nix::sys::stat::{fstat, fstatat, Mode, SFlag};
    use nix::unistd::{geteuid, unlinkat, UnlinkatFlags};
    use std::os::fd::AsRawFd;

    let Ok(mut dir) = Dir::openat(
        Some(parent),
        name,
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) else {
        return false;
    };
    let fd = dir.as_raw_fd();
    let uid = geteuid().as_raw();
    let Ok(st) = fstat(fd) else {
        return false;
    };
    if st.st_uid != uid || st.st_mode & 0o7777 != 0o700 {
        return false;
    }
    let (Ok(secs), Ok(nanos)) = (u64::try_from(st.st_mtime), u32::try_from(st.st_mtime_nsec))
    else {
        return false;
    };
    let changed = std::time::UNIX_EPOCH + Duration::new(secs, nanos);
    if now
        .duration_since(changed)
        .map_or(true, |age| age < STALE_STAGING_AFTER)
    {
        return false;
    }
    if process_exists(pid) {
        return false;
    }
    let mut socket = false;
    for entry in dir.iter() {
        let Ok(entry) = entry else {
            return false;
        };
        let entry_name = entry.file_name().to_bytes();
        if entry_name == b"." || entry_name == b".." {
            continue;
        }
        if entry_name != STAGED_NAME.as_bytes() {
            return false;
        }
        let Ok(staged) = fstatat(Some(fd), STAGED_NAME, AtFlags::AT_SYMLINK_NOFOLLOW) else {
            return false;
        };
        let kind = SFlag::from_bits_truncate(staged.st_mode) & SFlag::S_IFMT;
        if kind != SFlag::S_IFSOCK || staged.st_uid != uid {
            return false;
        }
        socket = true;
    }
    if socket && unlinkat(Some(fd), STAGED_NAME, UnlinkatFlags::NoRemoveDir).is_err() {
        return false;
    }
    before_remove();
    let Ok(current) = fstatat(Some(parent), name, AtFlags::AT_SYMLINK_NOFOLLOW) else {
        return false;
    };
    if !path::same(&current, &st) {
        return false;
    }
    unlinkat(Some(parent), name, UnlinkatFlags::RemoveDir).is_ok()
}

#[cfg(test)]
pub(crate) fn private_test_dir() -> std::io::Result<tempfile::TempDir> {
    use std::os::unix::fs::PermissionsExt;
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::*;

    #[test]
    fn ensure_lock_rejects_unsafe_files_without_modifying_them() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = super::private_test_dir().unwrap();
        let socket = dir.path().join("control.sock");
        let lock = dir.path().join("control.sock.lock");
        let target = dir.path().join("untouched");
        std::fs::write(&target, b"fixture sentinel").unwrap();
        symlink(&target, &lock).unwrap();
        assert!(EnsureLock::acquire(&socket, Duration::from_secs(1)).is_err());
        assert_eq!(std::fs::read(&target).unwrap(), b"fixture sentinel");
        std::fs::remove_file(&lock).unwrap();
        std::fs::hard_link(&target, &lock).unwrap();
        assert!(EnsureLock::acquire(&socket, Duration::from_secs(1)).is_err());
        std::fs::remove_file(&lock).unwrap();
        nix::unistd::mkfifo(
            &lock,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        assert!(EnsureLock::acquire(&socket, Duration::from_secs(1)).is_err());
        std::fs::remove_file(&lock).unwrap();
        std::fs::write(&lock, b"retained lock contents").unwrap();
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(EnsureLock::acquire(&socket, Duration::from_secs(1)).is_err());
        std::fs::set_permissions(&lock, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(EnsureLock::acquire(&socket, Duration::from_secs(1)).unwrap());
        assert_eq!(std::fs::read(&lock).unwrap(), b"retained lock contents");
    }

    #[test]
    fn ensure_lock_lasts_until_the_last_inherited_descriptor_closes() {
        use std::os::fd::AsRawFd;
        let dir = super::private_test_dir().unwrap();
        let socket = dir.path().join("control.sock");
        let held = EnsureLock::acquire(&socket, Duration::from_secs(1)).unwrap();
        let inherited = held._file.try_clone().unwrap();
        let contender = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.path().join("control.sock.lock"))
            .unwrap();
        drop(held);
        // dup and fork refer to the same open-file description. Closing the
        // original guard must not unlock while its inherited copy remains.
        assert_eq!(
            unsafe {
                nix::libc::flock(
                    contender.as_raw_fd(),
                    nix::libc::LOCK_EX | nix::libc::LOCK_NB,
                )
            },
            -1
        );
        drop(inherited);
        assert_eq!(
            unsafe {
                nix::libc::flock(
                    contender.as_raw_fd(),
                    nix::libc::LOCK_EX | nix::libc::LOCK_NB,
                )
            },
            0
        );
        assert!(dir.path().join("control.sock.lock").exists());
    }

    #[test]
    fn daemonization_parent_leaves_publication_to_the_child_owner() {
        let dir = super::private_test_dir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = bind_private(&path).unwrap();
        let mut parent = SocketCleanup::capture(&listener, &path).unwrap();
        let child = SocketCleanup::capture(&listener, &path).unwrap();
        // Exercise the same owned-resource seam as an uncertain parent outcome:
        // closing the parent's guard must not remove the child's live endpoint.
        parent.leave_to_child();
        drop(parent);
        assert!(UnixStream::connect(&path).is_ok());
        drop(child);
        assert!(!path.exists(), "known child termination still owns cleanup");
    }

    #[test]
    fn socket_cleanup_keeps_listener_alive_until_its_own_path_is_removed() {
        use std::os::fd::AsRawFd;
        let dir = super::private_test_dir().unwrap();
        let path = dir.path().join("control.sock");
        let listener = bind_private(&path).unwrap();
        let cleanup = SocketCleanup::capture(&listener, &path).unwrap();
        let flags = unsafe { nix::libc::fcntl(cleanup._listener.as_raw_fd(), nix::libc::F_GETFD) };
        assert!(
            flags >= 0 && flags & nix::libc::FD_CLOEXEC != 0,
            "the cleanup duplicate must not leak through update exec"
        );
        drop(listener);
        assert!(UnixStream::connect(&path).is_ok());
        drop(cleanup);
        assert!(!path.exists());
    }

    #[test]
    fn parses_status() {
        assert_eq!(parse_request("STATUS"), Some(ControlRequest::Status));
    }

    #[test]
    fn parses_add_port() {
        assert_eq!(
            parse_request("ADD-PORT 60001"),
            Some(ControlRequest::AddPort(60001))
        );
    }

    #[test]
    fn parses_stop() {
        assert_eq!(parse_request("STOP"), Some(ControlRequest::Stop));
    }

    #[test]
    fn parses_add_client() {
        let key = [7u8; 32];
        let b64 = BASE64.encode(key);
        assert_eq!(
            parse_request(&format!("ADD-CLIENT {b64}")),
            Some(ControlRequest::AddClient(key))
        );
    }

    #[test]
    fn rejects_bad_add_client() {
        // No argument.
        assert_eq!(parse_request("ADD-CLIENT"), None);
        // Extra argument.
        let b64 = BASE64.encode([1u8; 32]);
        assert_eq!(parse_request(&format!("ADD-CLIENT {b64} extra")), None);
        // Not base64.
        assert_eq!(parse_request("ADD-CLIENT not-valid-base64!!"), None);
        // Valid base64, but not 32 bytes.
        let short = BASE64.encode([9u8; 3]);
        assert_eq!(parse_request(&format!("ADD-CLIENT {short}")), None);
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse_request("NONSENSE"), None);
        assert_eq!(parse_request("ADD-PORT x"), None);
        assert_eq!(parse_request("ADD-PORT"), None);
    }

    #[test]
    fn request_round_trips() {
        for req in [
            ControlRequest::Status,
            ControlRequest::AddPort(60001),
            ControlRequest::AddClient([42u8; 32]),
            ControlRequest::Stop,
        ] {
            let line = format_request(&req);
            assert_eq!(parse_request(line.trim_end()), Some(req));
        }
    }

    #[test]
    fn status_response_round_trips() {
        let resp = StatusResponse {
            logging_warning: Some("file logging disabled: /owned/qshd.log".into()),
            cleanup: None,
            version: "0.1.0".into(),
            build: 42,
            checksum: "ab".repeat(32),
            ports: vec![PortStatus {
                port: 60000,
                default: true,
                connections: 1,
            }],
            total_connections: 1,
            pid: 4242,
        };
        let line = resp.to_line().unwrap();
        assert_eq!(StatusResponse::from_line(line.trim_end()).unwrap(), resp);
    }

    /// A daemon that predates the field does not send it: its `STATUS`
    /// still parses, with the pid unknown (zero).
    #[test]
    fn a_status_line_without_a_pid_still_parses() {
        let line =
            r#"{"version":"0.1.0","build":1,"checksum":"ab","ports":[],"total_connections":0}"#;
        assert_eq!(StatusResponse::from_line(line).unwrap().pid, 0);
    }

    /// Test-only read budget: short enough that the "accepts but never
    /// replies" case below doesn't make the suite unpleasantly slow. The
    /// production default ([`CLIENT_READ_TIMEOUT`]) stays 2s -- this constant
    /// exists only because [`client_request_with_timeout`] makes the budget
    /// injectable for tests.
    const TEST_TIMEOUT: Duration = Duration::from_millis(200);

    /// The budget for the one test below whose server is expected to ANSWER
    /// rather than stay silent. Two seconds, not [`TEST_TIMEOUT`]'s 200 ms:
    /// there the wait is measuring nothing, it only has to outlast the
    /// first scheduling of a thread spawned microseconds earlier -- and on
    /// a loaded machine (a whole `cargo test` run on every core, a CI box)
    /// that first scheduling can take longer than 200 ms, failing the test
    /// for a reason that has nothing to do with what it checks. The silent
    /// and stale cases keep the short budget, because there the wait IS the
    /// thing being measured and every millisecond of it is spent.
    const ANSWER_TIMEOUT: Duration = Duration::from_secs(2);

    /// `client_request_with_timeout` against a path that doesn't exist at
    /// all -- the plain "first launch" case: no socket file means no
    /// daemon, full stop.
    #[test]
    fn no_socket_file_is_no_daemon() {
        let dir = super::private_test_dir().expect("temp dir for a nonexistent socket path");
        let sock_path = dir.path().join("nope.sock");
        assert_eq!(
            client_request_with_timeout(&sock_path, &ControlRequest::Status, TEST_TIMEOUT)
                .expect("connecting to a missing path is not an error"),
            ControlReply::NoDaemon
        );
    }

    /// A stale socket FILE with nothing bound behind it any more: connect()
    /// itself fails (ECONNREFUSED) before a single byte is exchanged. Still
    /// "no daemon" -- indistinguishable from a first launch as far as the
    /// caller is concerned.
    #[test]
    fn refused_connection_is_no_daemon() {
        let dir = super::private_test_dir().expect("temp dir for a stale socket file");
        let sock_path = dir.path().join("stale.sock");
        {
            // Bind and immediately drop the listener WITHOUT removing the
            // file: the filesystem entry survives, nothing is listening
            // behind it any more.
            let _listener = UnixListener::bind(&sock_path).expect("bind a throwaway listener");
        }
        assert_eq!(
            client_request_with_timeout(&sock_path, &ControlRequest::Status, TEST_TIMEOUT)
                .expect("connecting to a stale socket file is not an error"),
            ControlReply::NoDaemon
        );
    }

    /// A peer that accepts and closes right away, without writing a single
    /// byte -- also "no daemon" (see [`ControlReply::NoDaemon`]'s own doc:
    /// a peer closing without a word counts the same as nothing listening).
    #[test]
    fn peer_closes_without_a_word_is_no_daemon() {
        let dir = super::private_test_dir().expect("temp dir for the accept-then-close listener");
        let sock_path = dir.path().join("closes.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind the accept-then-close listener");
        let server = std::thread::spawn(move || {
            let (stream, _addr) = listener.accept().expect("accept one connection");
            drop(stream); // close immediately, no bytes written
        });

        let reply = client_request_with_timeout(&sock_path, &ControlRequest::Status, TEST_TIMEOUT)
            .expect("a clean close is not an error");
        assert_eq!(reply, ControlReply::NoDaemon);
        server
            .join()
            .expect("accept-then-close thread does not panic");
    }

    /// A peer that accepts the connection and answers properly within the
    /// budget -- the ordinary case.
    #[test]
    fn peer_answers_is_answered() {
        fn answer(listener: UnixListener, deadline: std::time::Instant) {
            let mut stream = super::peer_fixture::accept(&listener, deadline);
            stream
                .set_nonblocking(false)
                .expect("restore blocking mode on the accepted fixture stream");
            stream
                .set_read_timeout(Some(ANSWER_TIMEOUT))
                .expect("bound the fixture request read");
            let mut request = String::new();
            BufReader::new(&mut stream)
                .read_line(&mut request)
                .expect("read the actual request before answering");
            assert_eq!(request, "STATUS\n");
            stream
                .write_all(b"STATUS-OK\n")
                .expect("write the canned response");
        }

        let dir = super::private_test_dir().expect("temp dir for the answering listener");
        let sock_path = dir.path().join("answers.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind the answering listener");
        let server = std::thread::spawn(move || {
            answer(listener, std::time::Instant::now() + ANSWER_TIMEOUT);
        });

        let reply =
            client_request_with_timeout(&sock_path, &ControlRequest::Status, ANSWER_TIMEOUT);
        server.join().expect("answering thread does not panic");
        assert_eq!(
            reply.expect("an answered request is not an error"),
            ControlReply::Answered("STATUS-OK".to_string())
        );

        let listener = UnixListener::bind(dir.path().join("no-connect.sock")).unwrap();
        let observer = std::thread::spawn(move || {
            answer(listener, std::time::Instant::now());
        });
        let failure = observer
            .join()
            .expect_err("expired accept must terminate the observer");
        let message = failure
            .downcast_ref::<String>()
            .expect("the bounded accept reports its owned fixture error");
        assert!(message.contains("owned peer accept failed"), "{message}");
        assert!(message.contains("WouldBlock"), "{message}");
    }

    /// A peer that accepts the connection but NEVER answers (and never
    /// closes) within the budget -- this is the case the bug conflated
    /// with "no daemon". A connection was accepted, so something is
    /// listening: the correct reply is `TimedOut`, distinct from
    /// `NoDaemon`.
    #[test]
    fn peer_accepts_and_stays_silent_is_timed_out() {
        let dir = super::private_test_dir().expect("temp dir for the silent listener");
        let sock_path = dir.path().join("silent.sock");
        let listener = UnixListener::bind(&sock_path).expect("bind the silent listener");
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (stream, _addr) = listener.accept().expect("accept one connection");
            // Hold the connection open past the client's budget, then close
            // once the client has already given up (`done_rx` signals it).
            let _ = done_rx.recv_timeout(Duration::from_secs(5));
            drop(stream);
        });

        let reply = client_request_with_timeout(&sock_path, &ControlRequest::Status, TEST_TIMEOUT)
            .expect("a timeout is not an error");
        assert_eq!(reply, ControlReply::TimedOut);
        let _ = done_tx.send(());
        server
            .join()
            .expect("silent-listener thread does not panic");
    }

    /// Spec §4.16 (QSH-14): the control socket is owner-only from the moment
    /// it has its name, answers there, and leaves no staging directory.
    #[test]
    fn the_control_socket_is_owner_only_from_the_start() {
        use std::os::unix::fs::PermissionsExt;
        let dir = super::private_test_dir().unwrap();
        let path = dir.path().join("control.sock");
        let _listener = bind_private(&path).expect("bound");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let names: Vec<std::ffi::OsString> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("control.sock")]);
        std::os::unix::net::UnixStream::connect(&path).expect("it answers where it was named");
    }

    /// A stale socket file of a daemon that died is replaced.
    #[test]
    fn a_stale_socket_file_is_replaced() {
        let dir = super::private_test_dir().unwrap();
        let path = dir.path().join("control.sock");
        drop(UnixListener::bind(&path).unwrap());
        assert!(path.exists(), "the dead daemon's file stays");
        let _listener = bind_private(&path).expect("bound over it");
        std::os::unix::net::UnixStream::connect(&path).expect("connects to the new one");
    }

    /// Task 6 review, Minor 1: a path a plain `UnixListener::bind` accepts
    /// must still bind through `bind_private` -- the staging name
    /// (`.c<pid>/s`) must not add enough bytes to push a path that fit
    /// under the kernel's `sun_path` budget over it. The old staging name
    /// (`.control-<pid>.bind/control.sock`, ~22 bytes longer than the final
    /// name) could: pick a length where +22 overflows a typical 108-byte
    /// budget but the few bytes `.c<pid>/s` adds over `control.sock` do
    /// not.
    #[test]
    fn a_path_near_the_kernel_limit_that_bound_before_still_binds() {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::DirBuilderExt;
        // The staging path never includes the FINAL name (it is always
        // `<parent>/.c<pid>/s`), so what matters here is the PARENT
        // directory's own length -- a real long path comes from a deep or
        // long-named cache directory, with the final component always the
        // fixed name `control.sock`.
        let dir = super::private_test_dir().unwrap();
        let base_len = dir.path().as_os_str().as_bytes().len();
        // Aim for a parent path of about 80 bytes: the final path
        // (parent + "/control.sock") sits at about 93, comfortably under a
        // 107-byte kernel budget by itself, but +22 (the old scheme's
        // staging overhead over "control.sock") pushes the STAGED path
        // past it, while +~9 (`.c<pid>/s`, the new scheme) does not.
        let target_parent_len = 80usize;
        let pad = target_parent_len.saturating_sub(base_len + 1).max(1);
        let parent = dir.path().join("x".repeat(pad));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&parent)
            .unwrap();
        let path = parent.join("control.sock");
        let total_len = path.as_os_str().as_bytes().len();
        assert!(
            (85..107).contains(&total_len),
            "test path is {total_len} bytes, not close enough to the kernel limit to be meaningful"
        );

        UnixListener::bind(&path)
            .expect("a plain bind at this length must succeed, or this test proves nothing");
        std::fs::remove_file(&path).unwrap();

        let _listener = bind_private(&path).expect(
            "bind_private must succeed where a plain bind does -- the old, ~22-byte-longer \
             staging name did not (Minor 1)",
        );
    }

    /// Task 6 review, Minor 2: `bind_in` never creates its own directory --
    /// it only ever binds inside one the caller already made. Since it
    /// cannot create a directory, it can never be the code path that binds
    /// a socket before that directory's mode is tightened (QSH-14): the
    /// absence of that window is by construction, pinned structurally
    /// rather than by racing a clock.
    #[test]
    fn bind_in_never_creates_its_own_directory() {
        let dir = super::private_test_dir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let err = bind_in(&missing, "s").expect_err("no directory, no bind");
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// `bind_private`'s own directory (`DirBuilder::mode(0o700).create`, one
    /// `mkdir(2)` with the mode already 0700 -- no separate `chmod`) is the
    /// only directory `bind_in` is ever called with in production; this
    /// pins that `bind_in` works, and needs no permission of its own,
    /// inside such a directory.
    #[test]
    fn bind_in_binds_inside_an_owner_only_directory() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let dir = super::private_test_dir().unwrap();
        let staging = dir.path().join("staging");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&staging)
            .unwrap();
        let mode = std::fs::metadata(&staging).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o700,
            "bind_in must be given a directory already 0700"
        );
        let _listener = bind_in(&staging, "s").expect("bound inside the 0700 directory");
    }

    /// Pids of processes that ran and were reaped: nobody has them now
    /// (barring reuse within the test, which the kernel's pid counter makes
    /// all but impossible).
    fn dead_pids(n: usize) -> Vec<u32> {
        (0..n)
            .map(|_| {
                let mut child = std::process::Command::new("true").spawn().unwrap();
                let pid = child.id();
                child.wait().unwrap();
                pid
            })
            .collect()
    }

    fn private_dir(path: &Path) {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }

    /// Final review of slice 5, M4: at start the daemon removes what a crash
    /// between `bind_private`'s `mkdir` and its cleanup left -- an empty
    /// `.c<pid>` of a gone process, or one holding only its dead staged
    /// socket -- and nothing else: not a directory whose pid is alive, not a
    /// fresh one, not one holding anything but the staged socket, not a
    /// symlink (nor what it points to), not one of another mode, not a name
    /// `bind_private` does not write. Another uid's directory needs root to
    /// make; the check is the same `fstat` as the mode's.
    #[test]
    fn a_start_sweeps_only_its_own_stale_staging_directories() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = super::private_test_dir().unwrap();
        let at = |name: &str| dir.path().join(name);
        let dead = dead_pids(9);
        let empty = format!(".c{}", dead[0]);
        let with_socket = format!(".c{}", dead[1]);
        let with_file = format!(".c{}", dead[2]);
        let file_named_s = format!(".c{}", dead[3]);
        let link = format!(".c{}", dead[4]);
        let open_mode = format!(".c{}", dead[5]);
        let leading_zero = format!(".c0{}", dead[6]);
        let suffixed = format!(".c{}x", dead[7]);
        let signed = format!(".c+{}", dead[8]);
        let alive = format!(".c{}", std::process::id());
        for name in [
            &empty,
            &with_socket,
            &with_file,
            &file_named_s,
            &open_mode,
            &leading_zero,
            &suffixed,
            &signed,
            &alive,
        ] {
            private_dir(&at(name));
        }
        drop(UnixListener::bind(at(&with_socket).join(STAGED_NAME)).unwrap());
        std::fs::write(at(&with_file).join("x"), b"").unwrap();
        std::fs::write(at(&file_named_s).join(STAGED_NAME), b"").unwrap();
        std::fs::set_permissions(at(&open_mode), std::fs::Permissions::from_mode(0o755)).unwrap();
        let target = super::private_test_dir().unwrap();
        let pointed = target.path().join("pointed");
        private_dir(&pointed);
        drop(UnixListener::bind(pointed.join(STAGED_NAME)).unwrap());
        symlink(&pointed, at(&link)).unwrap();
        std::fs::write(at("control.sock"), b"").unwrap();

        let now = std::time::SystemTime::now();
        assert_eq!(sweep_stale_staging(dir.path(), now), 0, "all fresh");
        let later = now + STALE_STAGING_AFTER + Duration::from_secs(1);
        assert_eq!(sweep_stale_staging(dir.path(), later), 2);
        assert!(!at(&empty).exists(), "empty, pid gone");
        assert!(!at(&with_socket).exists(), "only its dead socket");
        for kept in [
            &with_file,
            &file_named_s,
            &open_mode,
            &leading_zero,
            &suffixed,
            &signed,
            &alive,
        ] {
            assert!(at(kept).is_dir(), "{kept} kept");
        }
        assert!(at(&with_file).join("x").exists());
        assert!(at(&file_named_s).join(STAGED_NAME).exists());
        assert!(
            std::fs::symlink_metadata(at(&link))
                .unwrap()
                .file_type()
                .is_symlink(),
            "the symlink kept"
        );
        assert!(
            pointed.join(STAGED_NAME).exists(),
            "and what it points to, contents and all"
        );
        assert!(at("control.sock").exists(), "nothing else touched");
    }

    /// The sweep runs where it should: `bind_private` itself, so every
    /// start of the daemon does it, next to the socket it binds.
    #[test]
    fn bind_private_sweeps_stale_staging_next_to_its_socket() {
        use std::os::unix::fs::DirBuilderExt;
        let dir = super::private_test_dir().unwrap();
        let stale = dir.path().join(format!(".c{}", dead_pids(1)[0]));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&stale)
            .unwrap();
        let old = std::time::SystemTime::now() - STALE_STAGING_AFTER - Duration::from_secs(1);
        std::fs::File::open(&stale)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let _listener = bind_private(&dir.path().join("control.sock")).expect("bound");
        assert!(!stale.exists(), "the leftover is gone");
    }

    /// A stand-in daemon for [`stop_daemon_and_wait`]: answers each request
    /// line with what `answer` returns, or closes without a word on `None`.
    /// Stops accepting when dropped.
    struct FakeDaemon {
        done: std::sync::Arc<std::sync::atomic::AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }

    impl FakeDaemon {
        fn start(
            sock: &Path,
            mut answer: impl FnMut(&str) -> Option<String> + Send + 'static,
        ) -> FakeDaemon {
            use std::sync::atomic::Ordering;
            let listener = UnixListener::bind(sock).expect("bind the fake daemon");
            listener.set_nonblocking(true).unwrap();
            let done = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let flag = done.clone();
            let thread = std::thread::spawn(move || {
                while !flag.load(Ordering::SeqCst) {
                    let Ok((stream, _)) = listener.accept() else {
                        std::thread::sleep(Duration::from_millis(5));
                        continue;
                    };
                    stream.set_nonblocking(false).unwrap();
                    let mut line = String::new();
                    let _ = BufReader::new(&stream).read_line(&mut line);
                    if let Some(reply) = answer(line.trim_end()) {
                        let _ = (&stream).write_all(format!("{reply}\n").as_bytes());
                    }
                }
            });
            FakeDaemon {
                done,
                thread: Some(thread),
            }
        }
    }

    impl Drop for FakeDaemon {
        fn drop(&mut self) {
            self.done.store(true, std::sync::atomic::Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    fn status_line(pid: u32) -> String {
        let status = StatusResponse {
            logging_warning: None,
            cleanup: None,
            version: "0.0.0".into(),
            build: 0,
            checksum: String::new(),
            ports: vec![],
            total_connections: 0,
            pid,
        };
        status.to_line().unwrap().trim_end().to_string()
    }

    const STOPPED: &str = "{\"stopped\":true}";

    #[test]
    fn stopping39_ack_waits_for_real_exit_and_reports_still_live() {
        let dir = super::private_test_dir().unwrap();
        let sock = dir.path().join("control.sock");
        let pid = std::process::id();
        let stops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = stops.clone();
        let daemon = FakeDaemon::start(&sock, move |line| match line {
            "STATUS" => Some(status_line(pid)),
            "STOP" => {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some("{\"stopping\":true}".into())
            }
            _ => None,
        });
        let outcome = stop_daemon_and_wait_with(&sock, Duration::from_millis(100), TEST_TIMEOUT);
        drop(daemon); // Join the fake peer before asserting on the RED path.
        assert_eq!(
            outcome,
            StopOutcome::StillThere {
                pid,
                stop_answered: true
            }
        );
        assert_eq!(stops.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn stopping_where_there_is_no_socket_is_no_daemon_at_once() {
        let dir = super::private_test_dir().unwrap();
        let started = std::time::Instant::now();
        let outcome =
            stop_daemon_and_wait(&dir.path().join("control.sock"), Duration::from_secs(10));
        assert_eq!(outcome, StopOutcome::NoDaemon);
        assert!(!outcome.may_have_leaked());
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "{:?}",
            started.elapsed()
        );
    }

    /// The case that leaked daemons: the first STOP is lost (read, but never
    /// acted on). It is sent again, and the wait lasts until the daemon's
    /// process -- here a `cat` that ends when the second STOP closes its
    /// input -- is gone.
    #[test]
    fn a_lost_stop_is_sent_again_and_the_wait_lasts_until_the_process_is_gone() {
        let dir = super::private_test_dir().unwrap();
        let sock = dir.path().join("control.sock");
        let mut child = std::process::Command::new("cat")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .spawn()
            .expect("spawn cat");
        let pid = child.id();
        let input = std::sync::Mutex::new(child.stdin.take());
        // Reaps it, so its /proc entry goes when it exits.
        let reaper = std::thread::spawn(move || child.wait());
        let stops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = stops.clone();
        let _daemon = FakeDaemon::start(&sock, move |line| match line {
            "STATUS" => Some(status_line(pid)),
            "STOP" => {
                if seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    return None; // lost
                }
                drop(input.lock().unwrap().take());
                Some(STOPPED.into())
            }
            _ => None,
        });
        let outcome = stop_daemon_and_wait_with(&sock, Duration::from_secs(10), TEST_TIMEOUT);
        assert_eq!(outcome, StopOutcome::Stopped { pid });
        assert_eq!(stops.load(std::sync::atomic::Ordering::SeqCst), 2);
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
        reaper.join().unwrap().unwrap();
    }

    /// An acknowledged STOP is not the end: a process that stays is reported
    /// with its pid. (Its pid is this test's own, which does stay.)
    #[test]
    fn a_process_that_stays_after_stop_is_reported() {
        let dir = super::private_test_dir().unwrap();
        let sock = dir.path().join("control.sock");
        let pid = std::process::id();
        let _daemon = FakeDaemon::start(&sock, move |line| match line {
            "STATUS" => Some(status_line(pid)),
            "STOP" => Some(STOPPED.into()),
            _ => None,
        });
        let outcome = stop_daemon_and_wait_with(&sock, Duration::from_millis(300), TEST_TIMEOUT);
        assert_eq!(
            outcome,
            StopOutcome::StillThere {
                pid,
                stop_answered: true
            }
        );
        assert!(outcome.may_have_leaked());
    }

    /// A daemon that does not name its pid: its socket going is the stop.
    #[test]
    fn without_a_pid_the_socket_going_is_the_stop() {
        let dir = super::private_test_dir().unwrap();
        let sock = dir.path().join("control.sock");
        let path = sock.clone();
        let _daemon = FakeDaemon::start(&sock, move |line| match line {
            "STATUS" => Some(status_line(0)),
            "STOP" => {
                let _ = std::fs::remove_file(&path);
                Some(STOPPED.into())
            }
            _ => None,
        });
        let outcome = stop_daemon_and_wait_with(&sock, Duration::from_secs(10), TEST_TIMEOUT);
        assert_eq!(outcome, StopOutcome::Stopped { pid: 0 });
    }

    /// Nothing answers STATUS: no STOP goes out, and it says so.
    #[test]
    fn a_socket_that_never_answers_gets_no_stop() {
        let dir = super::private_test_dir().unwrap();
        let sock = dir.path().join("control.sock");
        let stops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = stops.clone();
        let _daemon = FakeDaemon::start(&sock, move |line| {
            if line == "STOP" {
                seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            None
        });
        let outcome = stop_daemon_and_wait_with(&sock, Duration::from_millis(300), TEST_TIMEOUT);
        assert_eq!(outcome, StopOutcome::NeverAnswered);
        assert!(outcome.may_have_leaked());
        assert_eq!(stops.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod cleanup143_tests {
    use super::*;

    #[test]
    fn cleanup143_old_status_is_unknown_and_new_status_is_additive() {
        let old = r#"{"version":"0.5.0","build":1,"checksum":"ab","ports":[],"total_connections":2,"pid":42,"future":true}"#;
        let mut status = StatusResponse::from_line(old).unwrap();
        assert!(status.cleanup.is_none());
        assert!(!status.to_line().unwrap().contains("cleanup"));
        let registry = transport::channel_open::ChannelOpenRegistry::new(Default::default());
        status.cleanup = Some(CleanupStatusResponse::from_snapshot(
            registry.try_cleanup_snapshot(),
        ));
        assert_eq!(
            status.cleanup.as_ref().unwrap().phase,
            CleanupPhase::Completed
        );
        let wire = status.to_line().unwrap();
        assert_eq!(StatusResponse::from_line(wire.trim_end()).unwrap(), status);
        let legacy: serde_json::Value = serde_json::from_str(old).unwrap();
        let current: serde_json::Value = serde_json::from_str(&wire).unwrap();
        for field in [
            "version",
            "build",
            "checksum",
            "ports",
            "total_connections",
            "pid",
        ] {
            assert_eq!(legacy[field], current[field]);
        }
        let unknown = CleanupStatusResponse::from_snapshot(None);
        assert_eq!(unknown.phase, CleanupPhase::Unknown);
        assert!(
            unknown.counts.is_none(),
            "unavailable status must not fabricate zero counts"
        );
    }
}

/// Authenticate the account at the connected endpoint, never its PID: a
/// legitimate listener may have been inherited across fork or exec.
pub(crate) fn peer_uid(stream: &impl std::os::fd::AsFd) -> std::io::Result<u32> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
            .map(|credentials| credentials.uid())
            .map_err(std::io::Error::from)
    }
    #[cfg(target_os = "macos")]
    {
        nix::unistd::getpeereid(stream)
            .map(|(uid, _)| uid.as_raw())
            .map_err(std::io::Error::from)
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = stream;
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "control peer credentials are unsupported on this platform",
        ))
    }
}

pub(crate) fn require_same_account(peer: std::io::Result<u32>, expected: u32) -> Result<()> {
    let peer = peer.context("reading control peer credentials")?;
    anyhow::ensure!(
        peer == expected,
        "control peer belongs to a different effective account"
    );
    Ok(())
}

fn check_control_peer(stream: &UnixStream) -> Result<()> {
    require_same_account(peer_uid(stream), nix::unistd::geteuid().as_raw())
}

#[cfg(test)]
#[path = "control_peer_tests.rs"]
mod peer_tests;

#[cfg(test)]
#[path = "control_peer_fixture.rs"]
pub(crate) mod peer_fixture;

#[cfg(test)]
#[path = "control_path_tests.rs"]
mod path_tests;
