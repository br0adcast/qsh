//! Linux exact-instance process ownership; unavailable evidence never proves cleanup.

use nix::libc;
use std::os::fd::OwnedFd;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Evidence {
    Pending,
    Exited,
    Unknown,
}
#[derive(Debug, Clone, Copy)]
pub enum Failure {
    Errno(i32),
    Malformed,
}
pub trait Operations {
    fn stat(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure>;
    fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure>;
    fn signal(&mut self, fd: &OwnedFd, signal: i32) -> Result<(), Failure>;
    /// `signal` to the process group that the process `fd` pins leads,
    /// through that descriptor. Refused (`EINVAL`) unless implemented: no
    /// kernel signal is ever sent to a group by its number.
    fn signal_group(&mut self, _fd: &OwnedFd, _signal: i32) -> Result<(), Failure> {
        Err(Failure::Errno(libc::EINVAL))
    }
}
pub struct RetainedProcess {
    fd: OwnedFd,
    exited: bool,
}
impl RetainedProcess {
    pub fn observe(&mut self, ops: &mut impl Operations) -> Evidence {
        if self.exited {
            return Evidence::Exited;
        }
        let result = match ops.stat(&self.fd).and_then(|bytes| parse_stat(&bytes)) {
            Ok(record) if record.state == b'Z' && record.threads == 1 => Evidence::Exited,
            Ok(_) => Evidence::Pending,
            Err(Failure::Errno(libc::ENOENT | libc::ESRCH)) => match ops.signal(&self.fd, 0) {
                Err(Failure::Errno(libc::ESRCH)) => Evidence::Exited,
                _ => Evidence::Unknown,
            },
            Err(_) => Evidence::Unknown,
        };
        self.exited = result == Evidence::Exited;
        result
    }
    // Call only after exact-fd membership or exclusive reserved-child identity
    // was established. Neither path grants authority over numeric PID reuse.
    pub fn stop(&mut self, ops: &mut impl Operations, signal: i32) -> Evidence {
        if self.exited {
            return Evidence::Exited;
        }
        match ops.signal(&self.fd, signal) {
            Ok(()) => Evidence::Pending,
            // An unsuccessful signal is not a completed exit receipt.
            Err(_) => match self.observe(ops) {
                Evidence::Exited => Evidence::Exited,
                _ => Evidence::Unknown,
            },
        }
    }
    fn acquire_reserved_child(
        fd: OwnedFd,
        expected_pid: u32,
        ops: &mut impl Operations,
    ) -> Result<Self, Acquisition> {
        if ops
            .status(&fd)
            .and_then(|bytes| validate_tgid(&bytes, expected_pid))
            .unwrap_or(false)
        {
            Ok(Self { fd, exited: false })
        } else {
            Err(Acquisition::Unknown(fd))
        }
    }
    pub fn acquire_member(
        fd: OwnedFd,
        expected_pid: u32,
        sid: u32,
        ops: &mut impl Operations,
    ) -> Result<Self, Acquisition> {
        if !ops
            .status(&fd)
            .and_then(|bytes| validate_tgid(&bytes, expected_pid))
            .unwrap_or(false)
        {
            return Err(Acquisition::Unknown(fd));
        }
        match ops.stat(&fd).and_then(|bytes| parse_stat(&bytes)) {
            Ok(record) if record.sid == sid => Ok(Self { fd, exited: false }),
            Ok(_) => Err(Acquisition::OutsideSession),
            Err(_) => Err(Acquisition::Unknown(fd)),
        }
    }
}

#[derive(Debug)]
pub enum Acquisition {
    OutsideSession,
    Unknown(OwnedFd),
}
fn unsigned_number(bytes: &[u8]) -> Result<u64, Failure> {
    if bytes.is_empty() {
        return Err(Failure::Malformed);
    }
    let mut value = 0u64;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(Failure::Malformed);
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((byte - b'0') as u64))
            .ok_or(Failure::Malformed)?;
    }
    Ok(value)
}
fn positive_number(bytes: &[u8]) -> Result<u64, Failure> {
    let value = unsigned_number(bytes)?;
    if value == 0 {
        return Err(Failure::Malformed);
    }
    Ok(value)
}

fn validate_tgid(bytes: &[u8], expected_pid: u32) -> Result<bool, Failure> {
    let read = |key: &[u8]| -> Result<u32, Failure> {
        // Ignore incomplete trailing lines. Identity needs explicit line endings;
        // unrelated trailing Groups data may exceed this bounded prefix.
        let mut values = bytes
            .split_inclusive(|b| *b == b'\n')
            .filter(|line| line.ends_with(b"\n"))
            .filter_map(|line| line.strip_prefix(key));
        let field = values.next().ok_or(Failure::Malformed)?.trim_ascii();
        let value = u32::try_from(positive_number(field)?).map_err(|_| Failure::Malformed)?;
        if values.next().is_some() {
            return Err(Failure::Malformed);
        }
        Ok(value)
    };
    Ok(read(b"Pid:")? == expected_pid && read(b"Tgid:")? == expected_pid)
}
struct Stat {
    state: u8,
    threads: usize,
    ppid: u32,
    pgrp: u32,
    sid: u32,
    /// Field 22, the start time; `None` if the record ends before it.
    start: Option<u64>,
}
fn parse_stat(bytes: &[u8]) -> Result<Stat, Failure> {
    let end = bytes
        .iter()
        .rposition(|b| *b == b')')
        .ok_or(Failure::Malformed)?;
    let fields: Vec<_> = bytes[end + 1..]
        .split(u8::is_ascii_whitespace)
        .filter(|s| !s.is_empty())
        .collect();
    let state = fields
        .first()
        .filter(|s| s.len() == 1)
        .ok_or(Failure::Malformed)?[0];
    if !b"RSDZTWtXxKPI".contains(&state) {
        return Err(Failure::Malformed);
    }
    let ppid = u32::try_from(unsigned_number(fields.get(1).ok_or(Failure::Malformed)?)?)
        .map_err(|_| Failure::Malformed)?;
    let pgrp = u32::try_from(unsigned_number(fields.get(2).ok_or(Failure::Malformed)?)?)
        .map_err(|_| Failure::Malformed)?;
    let sid = u32::try_from(unsigned_number(fields.get(3).ok_or(Failure::Malformed)?)?)
        .map_err(|_| Failure::Malformed)?;
    let threads = usize::try_from(positive_number(fields.get(17).ok_or(Failure::Malformed)?)?)
        .map_err(|_| Failure::Malformed)?;
    let start = fields.get(19).and_then(|field| unsigned_number(field).ok());
    Ok(Stat {
        state,
        threads,
        ppid,
        pgrp,
        sid,
        start,
    })
}

/// Native operations assume documented syscall semantics. Custom filters that
/// fabricate ESRCH are outside this prototype's qualified environment.
pub struct Native;
impl Operations for Native {
    fn stat(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        read_relative(fd, c"stat", false)
    }
    fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        read_relative(fd, c"status", true)
    }
    fn signal(&mut self, fd: &OwnedFd, signal: i32) -> Result<(), Failure> {
        use std::os::fd::AsRawFd;
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                0u32,
            )
        };
        if result < 0 {
            Err(last_error())
        } else {
            Ok(())
        }
    }
    /// `pidfd_send_signal(fd, signal, NULL, PIDFD_SIGNAL_PROCESS_GROUP)`:
    /// the group whose ID the pinned process's own `struct pid` is, never
    /// a number. Linux 6.9 and later; older kernels refuse the flag with
    /// `EINVAL`.
    fn signal_group(&mut self, fd: &OwnedFd, signal: i32) -> Result<(), Failure> {
        use std::os::fd::AsRawFd;
        let result = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                signal,
                std::ptr::null::<libc::siginfo_t>(),
                PIDFD_SIGNAL_PROCESS_GROUP,
            )
        };
        if result < 0 {
            Err(last_error())
        } else {
            Ok(())
        }
    }
}

/// `pidfd_send_signal`'s flag for the process group of the target (Linux
/// 6.9, `include/uapi/linux/pidfd.h`).
const PIDFD_SIGNAL_PROCESS_GROUP: u32 = 1 << 2;
fn read_relative(fd: &OwnedFd, name: &std::ffi::CStr, prefix: bool) -> Result<Vec<u8>, Failure> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let raw = unsafe {
        libc::openat(
            fd.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(last_error());
    }
    let file = unsafe { std::fs::File::from_raw_fd(raw) };
    read_bounded(file, prefix)
}
fn read_bounded(reader: impl std::io::Read, prefix: bool) -> Result<Vec<u8>, Failure> {
    use std::io::Read;
    let mut bytes = Vec::new();
    reader
        .take(if prefix { 8192 } else { 8193 })
        .read_to_end(&mut bytes)
        .map_err(|e| Failure::Errno(e.raw_os_error().unwrap_or(libc::EIO)))?;
    if bytes.len() > 8192 {
        return Err(Failure::Malformed);
    }
    Ok(bytes)
}

fn last_error() -> Failure {
    Failure::Errno(
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}
pub fn retain_proc_root() -> std::io::Result<OwnedFd> {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open("/proc")
        .map(Into::into)
}
/// Availability only: does not establish target membership or cleanup.
#[cfg(test)]
pub fn preflight(fd: &OwnedFd, ops: &mut impl Operations) -> Result<(), Failure> {
    ops.signal(fd, 0)
}

pub trait ProcOperations: Operations {
    fn open_self(&mut self, root: &OwnedFd) -> Result<OwnedFd, Failure>;
    fn self_identity(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure>;
    fn open_numeric(&mut self, root: &OwnedFd, pid: u32) -> Result<OwnedFd, Failure>;
}
pub struct QualifiedProc {
    root: OwnedFd,
}
#[derive(Debug)]
pub enum Unavailable {
    SelfOpen(Failure),
    Identity(Failure),
    Mismatch,
    Capability(Failure),
}
pub fn qualify_proc(
    root: OwnedFd,
    expected_pid: u32,
    ops: &mut impl ProcOperations,
) -> Result<QualifiedProc, Unavailable> {
    let self_fd = ops.open_self(&root).map_err(Unavailable::SelfOpen)?;
    let identity = ops.self_identity(&self_fd).map_err(Unavailable::Identity)?;
    if !validate_tgid(&identity, expected_pid).map_err(Unavailable::Identity)? {
        return Err(Unavailable::Mismatch);
    }
    let mut matches = identity
        .split_inclusive(|b| *b == b'\n')
        .filter(|line| line.ends_with(b"\n"))
        .filter_map(|line| line.strip_prefix(b"NSpid:"));
    let line = matches
        .next()
        .ok_or(Unavailable::Identity(Failure::Malformed))?;
    if matches.next().is_some() {
        return Err(Unavailable::Identity(Failure::Malformed));
    }
    let ids: Vec<_> = line
        .split(u8::is_ascii_whitespace)
        .filter(|v| !v.is_empty())
        .collect();
    if ids.len() != 1
        || positive_number(ids[0]).map_err(Unavailable::Identity)? != expected_pid as u64
    {
        return Err(Unavailable::Mismatch);
    }
    ops.signal(&self_fd, 0).map_err(Unavailable::Capability)?;
    Ok(QualifiedProc { root })
}
#[derive(Debug)]
pub enum CaptureFailure {
    Open(Failure),
    Unproved(Acquisition),
}
impl QualifiedProc {
    /// Caller exclusively owns this exact unreaped direct child. This proves
    /// its identity, never membership in a session or authority over siblings.
    fn capture_reserved_child(
        &self,
        pid: u32,
        ops: &mut impl ProcOperations,
    ) -> Result<RetainedProcess, CaptureFailure> {
        let fd = ops
            .open_numeric(&self.root, pid)
            .map_err(CaptureFailure::Open)?;
        RetainedProcess::acquire_reserved_child(fd, pid, ops).map_err(CaptureFailure::Unproved)
    }
    pub fn capture(
        &self,
        pid: u32,
        sid: u32,
        ops: &mut impl ProcOperations,
    ) -> Result<RetainedProcess, CaptureFailure> {
        let fd = ops
            .open_numeric(&self.root, pid)
            .map_err(CaptureFailure::Open)?;
        RetainedProcess::acquire_member(fd, pid, sid, ops).map_err(CaptureFailure::Unproved)
    }
}
const IDENTITY_READ_LIMIT: usize = 1024 * 1024;
fn project_identity(mut reader: impl std::io::Read) -> Result<Vec<u8>, Failure> {
    let mut buffer = [0u8; 4096];
    let mut line = Vec::with_capacity(512);
    let mut overlong = false;
    let mut total = 0usize;
    let keys: [&[u8]; 3] = [b"Pid:", b"Tgid:", b"NSpid:"];
    let mut seen = [false; 3];
    let mut projected = Vec::new();
    loop {
        if total == IDENTITY_READ_LIMIT {
            return Err(Failure::Malformed);
        }
        let allowed = buffer.len().min(IDENTITY_READ_LIMIT - total);
        let count = match reader.read(&mut buffer[..allowed]) {
            Ok(count) => count,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(Failure::Errno(e.raw_os_error().unwrap_or(libc::EIO))),
        };
        if count == 0 {
            break;
        }
        total += count;
        for byte in &buffer[..count] {
            if line.len() < 512 {
                line.push(*byte);
            } else {
                overlong = true;
            }
            if *byte == b'\n' {
                for (index, key) in keys.iter().enumerate() {
                    if line.starts_with(key) {
                        if overlong || seen[index] {
                            return Err(Failure::Malformed);
                        }
                        seen[index] = true;
                        projected.extend_from_slice(&line);
                    }
                }
                line.clear();
                overlong = false;
            }
        }
    }
    // A truncated unrelated trailing line is harmless; target lines must end.
    if keys.iter().any(|key| line.starts_with(key)) || seen.iter().any(|seen| !*seen) {
        return Err(Failure::Malformed);
    }
    Ok(projected)
}
fn open_relative_directory(root: &OwnedFd, path: &std::ffi::CStr) -> Result<OwnedFd, Failure> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let fd = unsafe {
        libc::openat(
            root.as_raw_fd(),
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(last_error())
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }
}
impl ProcOperations for Native {
    fn open_self(&mut self, root: &OwnedFd) -> Result<OwnedFd, Failure> {
        open_relative_directory(root, c"self")
    }
    fn self_identity(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
        use std::os::fd::{AsRawFd, FromRawFd};
        let raw = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                c"status".as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(last_error());
        }
        project_identity(unsafe { std::fs::File::from_raw_fd(raw) })
    }
    fn open_numeric(&mut self, root: &OwnedFd, pid: u32) -> Result<OwnedFd, Failure> {
        let name = std::ffi::CString::new(pid.to_string()).map_err(|_| Failure::Malformed)?;
        open_relative_directory(root, &name)
    }
}
/// A process pinned by its own procfs descriptor, as its descriptor reads.
struct Pinned {
    pid: u32,
    fd: OwnedFd,
    ppid: u32,
    /// Its process group: it leads one when this is its own pid.
    pgrp: u32,
    sid: u32,
    /// Its start time: with `pid`, which process this is among those that
    /// ever carry that number.
    start: u64,
    /// Exited and not yet reaped: a zombie with no thread left.
    exited: bool,
}

/// `pid`, pinned and read through its pin: `None` unless the descriptor's
/// own status names `pid` as both `Pid` and `Tgid` and its stat parses.
///
/// The status check proves only that the descriptor is a thread-group
/// leader's with that number, not a thread's (procfs opens a thread ID by
/// number too). It does not prove which process had the number when it was
/// looked up. That is not needed: everything believed about the process
/// afterwards is read through this descriptor, and every signal goes
/// through it, so all of it is about one and the same process.
fn pin(view: &QualifiedProc, pid: u32, ops: &mut impl ProcOperations) -> Option<Pinned> {
    let fd = ops.open_numeric(&view.root, pid).ok()?;
    if !ops
        .status(&fd)
        .and_then(|bytes| validate_tgid(&bytes, pid))
        .unwrap_or(false)
    {
        return None;
    }
    let stat = ops.stat(&fd).and_then(|bytes| parse_stat(&bytes)).ok()?;
    Some(Pinned {
        pid,
        fd,
        ppid: stat.ppid,
        pgrp: stat.pgrp,
        sid: stat.sid,
        start: stat.start?,
        exited: stat.state == b'Z' && stat.threads == 1,
    })
}

/// How many censuses of a session's members `kill_child_sessions` makes at
/// most. A pass that signals nobody new ends it; this bound only stops a
/// session that keeps producing new processes faster than they are found.
pub(crate) const KILL_PASSES: usize = 32;

/// What `kill_child_sessions` did.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct SessionKill {
    /// Processes that were alive (not exited, as read through their pins)
    /// when they were signalled.
    pub(crate) killed: usize,
    /// The last pass found no member left to signal. `false`: every one of
    /// the `KILL_PASSES` passes still found a new one, so members may remain.
    pub(crate) settled: bool,
}

/// A session owner's last resort (#529), when its session did not drain:
/// SIGKILL every process of the sessions this process's direct children
/// (`ours` of them) lead -- every process group of each, job-control jobs
/// included -- and those children themselves.
///
/// Exact, as the channel scopes are: nothing is believed about a process
/// before it is pinned by its own procfs descriptor (within `view`, this
/// process's own PID namespace), and every signal goes through that
/// descriptor (`pidfd_send_signal`), never a numeric PID or group. A
/// session's member is signalled only if the child leading it still reads
/// through its own pin after the member was found in that session: the
/// session ID cannot have been reused in between. A child already reaped by
/// its scope is not found, and its session left alone; so is the rest of a
/// session from the moment its leading child is reaped.
///
/// A member is signalled as soon as it is found, and the members are
/// listed again until a pass signals nobody new. Signalling one process at
/// a time does not stop a fork in progress the way a group signal does: a
/// member can fork after the list passed its place and before its own
/// SIGKILL, and that child is in no list yet. A killed process cannot
/// complete another fork, so only processes not yet signalled add members,
/// and each pass leaves fewer of them. A process already signalled is known
/// by its PID and start time (never signalled by them), so one that is slow
/// to die is neither signalled nor counted twice, and no descriptor is kept
/// per member. A process that has exited is not signalled: it cannot fork.
///
/// Where the kernel can (Linux 6.9 and later), a member that leads its
/// process group also has that whole group signalled, through its own pin
/// (`PIDFD_SIGNAL_PROCESS_GROUP`): at once, so no process of the group can
/// complete a fork past it -- not even one that forks a relay and exits
/// before its own turn. A kernel that refuses the flag (`EINVAL`) is asked
/// once; the passes then do all of it, as before. Never a group by number.
///
/// It never waits and never reaps: the scopes, or init once this process
/// has exited, do. So it cannot block on a process that cannot finish.
pub(crate) fn kill_child_sessions(
    view: &QualifiedProc,
    ours: impl Fn(u32) -> bool,
    ops: &mut impl scope::ScopeOperations,
) -> Result<SessionKill, Failure> {
    let me = std::process::id();
    let mut children = Vec::new();
    ops.census(&view.root, &mut |ops, pid| {
        if ours(pid) {
            if let Some(child) = pin(view, pid, ops).filter(|child| child.ppid == me) {
                children.push(child);
            }
        }
    })?;
    let mut sessions: Vec<u32> = children
        .iter()
        .filter(|child| child.sid == child.pid)
        .map(|child| child.sid)
        .collect();
    let mut signalled = std::collections::HashSet::new();
    let mut killed = 0;
    let mut settled = false;
    // Until the kernel refuses the group flag.
    let mut groups = true;
    for _ in 0..KILL_PASSES {
        if sessions.is_empty() {
            settled = true;
            break;
        }
        let mut new = false;
        ops.census(&view.root, &mut |ops, pid| {
            let Some(member) = pin(view, pid, ops) else {
                return;
            };
            if member.exited
                || !sessions.contains(&member.sid)
                || signalled.contains(&(member.pid, member.start))
            {
                return;
            }
            let leader = children
                .iter()
                .find(|child| child.pid == member.sid)
                .expect("a session of a pinned child");
            if ops
                .stat(&leader.fd)
                .and_then(|bytes| parse_stat(&bytes))
                .is_err()
            {
                // Reaped: its session ID proves nothing any more.
                sessions.retain(|sid| *sid != member.sid);
                return;
            }
            if groups && member.pgrp == member.pid {
                if let Err(Failure::Errno(libc::EINVAL)) =
                    ops.signal_group(&member.fd, libc::SIGKILL)
                {
                    groups = false;
                }
            }
            if ops.signal(&member.fd, libc::SIGKILL).is_ok() {
                signalled.insert((member.pid, member.start));
                killed += 1;
                new = true;
            }
        })?;
        if !new {
            settled = true;
            break;
        }
    }
    // Children that lead no session of their own: each alone.
    for child in children.iter().filter(|child| child.sid != child.pid) {
        let alive = ops
            .stat(&child.fd)
            .and_then(|bytes| parse_stat(&bytes))
            .is_ok_and(|stat| !(stat.state == b'Z' && stat.threads == 1));
        if alive && ops.signal(&child.fd, libc::SIGKILL).is_ok() {
            killed += 1;
        }
    }
    Ok(SessionKill { killed, settled })
}

/// `pid` as a census lists it, pinned and read through its pin: `Ok(None)`
/// if it is gone (reaped since it was listed), an error if it is there but
/// cannot be read -- its session is then unknown.
fn pin_listed(
    view: &QualifiedProc,
    pid: u32,
    ops: &mut impl ProcOperations,
) -> Result<Option<Pinned>, Failure> {
    let gone = |failure: &Failure| matches!(failure, Failure::Errno(libc::ENOENT | libc::ESRCH));
    let fd = match ops.open_numeric(&view.root, pid) {
        Ok(fd) => fd,
        Err(failure) if gone(&failure) => return Ok(None),
        Err(failure) => return Err(failure),
    };
    let status = match ops.status(&fd) {
        Ok(status) => status,
        Err(failure) if gone(&failure) => return Ok(None),
        Err(failure) => return Err(failure),
    };
    if !validate_tgid(&status, pid)? {
        return Err(Failure::Malformed);
    }
    let stat = match ops.stat(&fd) {
        Ok(stat) => parse_stat(&stat)?,
        Err(failure) if gone(&failure) => return Ok(None),
        Err(failure) => return Err(failure),
    };
    Ok(Some(Pinned {
        pid,
        fd,
        ppid: stat.ppid,
        pgrp: stat.pgrp,
        sid: stat.sid,
        start: stat.start.ok_or(Failure::Malformed)?,
        exited: stat.state == b'Z' && stat.threads == 1,
    }))
}

/// How many walks of `/proc` a session census makes: each must find no
/// process of a session for it to count as empty.
pub(crate) const CENSUS_PASSES: usize = 2;
/// How many of a session's processes a census names.
pub(crate) const CENSUS_NAMED: usize = 4;

/// What a census found of one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SessionCensus {
    /// No process of this session: every walk of `/proc` read every
    /// process listed and found none whose session ID is this one.
    Empty,
    /// Processes still in it (at most [`CENSUS_NAMED`] of them).
    Occupied(Vec<u32>),
    /// Not known: why.
    Unknown(String),
}

/// Which of the sessions `sids` still have a process, by their session ID
/// alone (#529: a session owner died, and its host checks whether anything
/// of its sessions is left). One result per entry of `sids`, in order.
///
/// Each walk of `/proc` pins every process it lists and reads its session
/// ID through the pin. A session counts as empty only when each of
/// [`CENSUS_PASSES`] walks, one after the other, found none of its
/// processes: one walk alone can miss a process whose parent forks it onto
/// a PID behind the walk -- the PIDs have wrapped -- and exits before the
/// walk reaches the parent; the next walk finds it. A process that has
/// exited (a zombie, nothing left of it running) is not counted.
///
/// Fail-closed: any process found with the session ID keeps the session
/// occupied, whoever it is -- also one in a new session that reused the
/// number. A walk that fails, a listed process that cannot be read (its
/// session cannot be told), or `deadline` passing leaves every session not
/// yet found occupied unknown. Never a signal, never a wait.
///
/// Every walk must also list (and read) pid 1, which belongs to another
/// account unless this one is root: a `/proc` that hides processes
/// (`hidepid=invisible` or `ptraceable`) hides it, and then no session is
/// proved empty -- the walk proves nothing. (The caller checks the mount's
/// options too: [`proc_hides_processes`].)
///
/// Not a proof against a process that wants to escape: one that leaves the
/// session (`setsid`) is not in it, as for the owner's own cleanup, and an
/// endless chain of processes that each fork the next and exit before the
/// walk reaches them could be missed by every walk.
pub(crate) fn census_sessions(
    view: &QualifiedProc,
    sids: &[u32],
    deadline: std::time::Instant,
    ops: &mut impl scope::ScopeOperations,
) -> Vec<SessionCensus> {
    let mut found: Vec<Vec<u32>> = vec![Vec::new(); sids.len()];
    let mut unknown: Option<String> = None;
    for _ in 0..CENSUS_PASSES {
        if found.iter().all(|members| !members.is_empty()) {
            break;
        }
        let mut failure: Option<String> = None;
        let mut saw_init = false;
        let walk = ops.census(&view.root, &mut |ops, pid| {
            if failure.is_some() {
                return;
            }
            if std::time::Instant::now() >= deadline {
                failure = Some("the census did not finish in time".into());
                return;
            }
            let pinned = pin_listed(view, pid, ops);
            if pid == 1 && matches!(pinned, Ok(Some(_))) {
                saw_init = true;
            }
            match pinned {
                Ok(None) => {}
                Ok(Some(process)) if process.exited => {}
                Ok(Some(process)) => {
                    for (sid, members) in sids.iter().zip(found.iter_mut()) {
                        if process.sid == *sid
                            && members.len() < CENSUS_NAMED
                            && !members.contains(&process.pid)
                        {
                            members.push(process.pid);
                        }
                    }
                }
                Err(error) => {
                    failure = Some(format!("process {pid} could not be read ({error:?})"))
                }
            }
        });
        if let Err(error) = walk {
            failure.get_or_insert(format!("/proc could not be listed ({error:?})"));
        }
        if !saw_init {
            failure
                .get_or_insert("/proc does not show pid 1, so it hides processes (hidepid)".into());
        }
        if failure.is_some() {
            unknown = failure;
            break;
        }
    }
    found
        .into_iter()
        .map(|members| {
            if !members.is_empty() {
                SessionCensus::Occupied(members)
            } else if let Some(why) = &unknown {
                SessionCensus::Unknown(why.clone())
            } else {
                SessionCensus::Empty
            }
        })
        .collect()
}

/// Why the procfs `view` is a mount that hides processes from this one, if
/// it is, or why that cannot be told: its super options (from
/// `/proc/self/mountinfo`, the entry of the view's own device) set
/// `hidepid` to anything but `0`/`off`. `None`: it shows every process.
pub(crate) fn proc_hides_processes(view: &QualifiedProc) -> Option<String> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(view.root.as_raw_fd(), &mut stat) } != 0 {
        return Some(format!("/proc cannot be identified ({:?})", last_error()));
    }
    let raw = unsafe {
        libc::openat(
            view.root.as_raw_fd(),
            c"self/mountinfo".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Some(format!("its mounts cannot be read ({:?})", last_error()));
    }
    // Bytes: a mount point need not be UTF-8 (a user's FUSE mount, say),
    // and one that is not must not keep every check unproved.
    let mut text = Vec::new();
    let file = unsafe { std::fs::File::from_raw_fd(raw) };
    if file
        .take(MOUNTINFO_LIMIT as u64 + 1)
        .read_to_end(&mut text)
        .is_err()
        || text.len() > MOUNTINFO_LIMIT
    {
        return Some("its mounts cannot be read".into());
    }
    let device = (libc::major(stat.st_dev), libc::minor(stat.st_dev));
    mount_hides_processes(&text, device)
}

/// The most of `/proc/self/mountinfo` read.
const MOUNTINFO_LIMIT: usize = 4 * 1024 * 1024;

/// [`proc_hides_processes`] on `mountinfo`'s bytes, for the procfs mount of
/// `device` (major, minor). Lines of other devices are skipped whatever
/// bytes they hold; a line of this device must be UTF-8 and parse whole,
/// or nothing is proved.
pub(crate) fn mount_hides_processes(mountinfo: &[u8], device: (u32, u32)) -> Option<String> {
    let want = format!("{}:{}", device.0, device.1);
    let mut found = false;
    for line in mountinfo.split(|b| *b == b'\n') {
        if line.split(|b| *b == b' ').nth(2) != Some(want.as_bytes()) {
            continue;
        }
        let Ok(line) = std::str::from_utf8(line) else {
            return Some("its mount entry cannot be parsed".into());
        };
        let fields: Vec<&str> = line.split(' ').collect();
        // After the optional fields: "-", the type, the source, the
        // superblock's options.
        let Some(dash) = fields.iter().position(|f| *f == "-") else {
            return Some("its mount entry cannot be parsed".into());
        };
        if fields.get(dash + 1) != Some(&"proc") {
            return Some("it is not a procfs mount".into());
        }
        let Some(options) = fields.get(dash + 3) else {
            return Some("its mount entry cannot be parsed".into());
        };
        for option in options.split(',') {
            if let Some(value) = option.strip_prefix("hidepid=") {
                if !matches!(value, "0" | "off") {
                    return Some(format!("/proc is mounted with hidepid={value}"));
                }
            }
        }
        found = true;
    }
    (!found).then(|| "its mount entry is not found".into())
}

pub fn qualify_native_proc() -> Result<QualifiedProc, Unavailable> {
    let root = retain_proc_root().map_err(|e| {
        Unavailable::SelfOpen(Failure::Errno(e.raw_os_error().unwrap_or(libc::EIO)))
    })?;
    // std::process::id queries the calling process; do not use a numeric proc path
    // to locate the self descriptor or probe capability before this validation.
    qualify_proc(root, std::process::id(), &mut Native)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        fs::File,
        os::fd::{AsRawFd, FromRawFd, IntoRawFd},
    };
    struct Fake {
        stats: VecDeque<Result<Vec<u8>, Failure>>,
        signals: VecDeque<Result<(), Failure>>,
        calls: Vec<(i32, i32)>,
    }
    impl Operations for Fake {
        fn stat(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            self.calls.push((fd.as_raw_fd(), -1));
            self.stats.pop_front().unwrap()
        }
        fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            self.calls.push((fd.as_raw_fd(), -2));
            self.stats.pop_front().unwrap()
        }
        fn signal(&mut self, fd: &OwnedFd, signal: i32) -> Result<(), Failure> {
            self.calls.push((fd.as_raw_fd(), signal));
            self.signals.pop_front().unwrap()
        }
    }
    fn stat(state: char, threads: usize) -> Vec<u8> {
        // Fields 4..19, with session at field 6; field 20 is num_threads.
        format!(
            "42 (name with ) parens) {state} 1 42 42 0 0 0 0 0 0 0 0 0 0 0 0 0 {threads} 0 123\n"
        )
        .into_bytes()
    }
    fn process() -> RetainedProcess {
        let fd = File::open("/dev/null").unwrap().into_raw_fd();
        RetainedProcess {
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            exited: false,
        }
    }
    fn fake(value: Result<Vec<u8>, Failure>, signal: Result<(), Failure>) -> Fake {
        Fake {
            stats: [value].into(),
            signals: [signal].into(),
            calls: vec![],
        }
    }
    #[test]
    fn zombie_leader_with_live_threads_is_pending() {
        let mut p = process();
        let mut ops = fake(Ok(stat('Z', 2)), Ok(()));
        assert_eq!(p.observe(&mut ops), Evidence::Pending);
        assert_eq!(ops.calls, vec![(p.fd.as_raw_fd(), -1)]);
    }
    #[test]
    fn full_thread_exit_is_latched_without_signalling() {
        let mut p = process();
        let mut ops = fake(Ok(stat('Z', 1)), Ok(()));
        assert_eq!(p.observe(&mut ops), Evidence::Exited);
        assert_eq!(p.observe(&mut ops), Evidence::Exited);
        assert_eq!(ops.calls.len(), 1);
    }
    #[test]
    fn denied_or_malformed_stat_never_implies_exit() {
        for error in [Failure::Errno(libc::EACCES), Failure::Malformed] {
            for errno in [libc::ENOSYS, libc::EPERM, libc::ESRCH] {
                let mut p = process();
                let mut ops = fake(Err(error), Err(Failure::Errno(errno)));
                assert_eq!(p.observe(&mut ops), Evidence::Unknown);
            }
        }
    }
    #[test]
    fn anchored_disappearance_requires_exact_fd_esrch() {
        let mut p = process();
        let mut ops = fake(
            Err(Failure::Errno(libc::ENOENT)),
            Err(Failure::Errno(libc::ESRCH)),
        );
        assert_eq!(p.observe(&mut ops), Evidence::Exited);
        assert_eq!(
            ops.calls,
            vec![(p.fd.as_raw_fd(), -1), (p.fd.as_raw_fd(), 0)]
        );
    }
    #[test]
    fn failed_disappearance_confirmation_retains_unknown() {
        for errno in [libc::ENOENT, libc::ESRCH] {
            for result in [
                Ok(()),
                Err(Failure::Errno(libc::ENOSYS)),
                Err(Failure::Errno(libc::EPERM)),
            ] {
                let mut p = process();
                let mut ops = fake(Err(Failure::Errno(errno)), result);
                assert_eq!(p.observe(&mut ops), Evidence::Unknown);
                assert_eq!(
                    ops.calls,
                    vec![(p.fd.as_raw_fd(), -1), (p.fd.as_raw_fd(), 0)]
                );
            }
        }
    }
    #[test]
    fn actual_malformed_stat_and_zero_threads_are_unknown() {
        for bytes in [
            b"garbage".to_vec(),
            stat('Z', 0),
            stat('?', 1),
            b"42 (x) Z".to_vec(),
        ] {
            let mut p = process();
            let mut ops = fake(Ok(bytes), Ok(()));
            assert_eq!(p.observe(&mut ops), Evidence::Unknown);
            assert_eq!(ops.calls.len(), 1);
        }
    }
    #[test]
    fn stop_errors_do_not_replace_exit_observation() {
        for errno in [libc::ENOSYS, libc::EPERM, libc::ESRCH] {
            let mut p = process();
            let mut ops = fake(
                Err(Failure::Errno(libc::EACCES)),
                Err(Failure::Errno(errno)),
            );
            assert_eq!(p.stop(&mut ops, libc::SIGKILL), Evidence::Unknown);
            assert_eq!(
                ops.calls,
                vec![(p.fd.as_raw_fd(), libc::SIGKILL), (p.fd.as_raw_fd(), -1)]
            );
        }
    }
    #[test]
    fn acquisition_requires_exact_tgid_and_membership() {
        for status in [
            b"Pid: 42\nTgid: 41\n".to_vec(),
            b"Pid: 42\n".to_vec(),
            b"Pid: 43\nTgid: 43\n".to_vec(),
        ] {
            let p = process();
            let raw = p.fd.as_raw_fd();
            let mut ops = fake(Ok(status), Ok(()));
            match RetainedProcess::acquire_member(p.fd, 42, 42, &mut ops) {
                Err(Acquisition::Unknown(fd)) => assert_eq!(fd.as_raw_fd(), raw),
                _ => panic!("unproved TGID must retain exact descriptor"),
            }
            assert_eq!(ops.calls, vec![(raw, -2)]);
        }
        for sid in [42, 99] {
            let p = process();
            let raw = p.fd.as_raw_fd();
            let mut ops = fake(Ok(b"Pid: 42\nTgid: 42\n".to_vec()), Ok(()));
            ops.stats.push_back(Ok(stat('S', 1)));
            let acquired = RetainedProcess::acquire_member(p.fd, 42, sid, &mut ops);
            if sid == 42 {
                assert!(acquired.is_ok());
            } else {
                assert!(matches!(acquired, Err(Acquisition::OutsideSession)));
            }
            assert_eq!(ops.calls, vec![(raw, -2), (raw, -1)]);
        }
    }
    #[test]
    fn preflight_reports_capability_errors_without_fallback() {
        for errno in [libc::ENOSYS, libc::EPERM, libc::ESRCH] {
            let p = process();
            let mut ops = fake(Err(Failure::Malformed), Err(Failure::Errno(errno)));
            assert!(preflight(&p.fd, &mut ops).is_err());
            assert_eq!(ops.calls, vec![(p.fd.as_raw_fd(), 0)]);
        }
    }
    #[test]
    fn non_utf8_comm_and_name_do_not_block_valid_identity() {
        let mut bytes = stat('S', 1);
        let offset = bytes.iter().position(|b| *b == b'n').unwrap();
        bytes[offset] = 0xff;
        assert!(parse_stat(&bytes).is_ok());
        assert!(validate_tgid(b"Name:\tbad\xffname\nPid:\t42\nTgid:\t42\n", 42).unwrap());
    }
    #[test]
    fn bounded_status_prefix_requires_complete_identity_lines_only() {
        let mut bytes = b"Name:\tname\nPid:\t42\nTgid:\t42\nGroups:".to_vec();
        bytes.resize(16384, b'1');
        let bytes = read_bounded(std::io::Cursor::new(bytes), true).unwrap();
        assert_eq!(bytes.len(), 8192);
        assert!(validate_tgid(&bytes, 42).unwrap());
        assert!(validate_tgid(b"Pid: 42\nTgid: 42", 42).is_err());
        assert!(validate_tgid(b"Pid: 4\xff2\nTgid: 42\n", 42).is_err());
    }
    struct ViewFake {
        inner: Fake,
        identity: Result<Vec<u8>, Failure>,
        opened: Vec<String>,
    }
    impl Operations for ViewFake {
        fn stat(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            self.inner.stat(fd)
        }
        fn status(&mut self, fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            self.inner.status(fd)
        }
        fn signal(&mut self, fd: &OwnedFd, sig: i32) -> Result<(), Failure> {
            self.inner.signal(fd, sig)
        }
    }
    impl ProcOperations for ViewFake {
        fn open_self(&mut self, _root: &OwnedFd) -> Result<OwnedFd, Failure> {
            self.opened.push("self".into());
            Ok(process().fd)
        }
        fn self_identity(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
            self.identity.clone()
        }
        fn open_numeric(&mut self, _root: &OwnedFd, pid: u32) -> Result<OwnedFd, Failure> {
            self.opened.push(pid.to_string());
            Ok(process().fd)
        }
    }
    fn view(identity: Result<Vec<u8>, Failure>) -> ViewFake {
        ViewFake {
            inner: fake(Err(Failure::Malformed), Ok(())),
            identity,
            opened: vec![],
        }
    }
    #[test]
    fn qualified_self_identity_precedes_any_numeric_access() {
        let mut ops = view(Ok(b"Pid: 42\nTgid: 42\nNSpid: 42\n".to_vec()));
        assert!(qualify_proc(process().fd, 42, &mut ops).is_ok());
        assert_eq!(ops.opened, vec!["self"]);
        assert_eq!(ops.inner.calls.len(), 1);
        assert_eq!(ops.inner.calls[0].1, 0);
    }
    #[test]
    fn invalid_or_unavailable_self_identity_never_signals_or_opens_numeric() {
        for identity in [
            Ok(b"Pid: 43\nTgid: 43\nNSpid: 43\n".to_vec()),
            Ok(b"Pid: 42\nTgid: 42\nNSpid: 42 42\n".to_vec()),
            Ok(b"Pid: 42\nTgid: 42\n".to_vec()),
            Ok(b"Pid: 42\nTgid: 42\nNSpid: nope\n".to_vec()),
            Err(Failure::Errno(libc::EACCES)),
            Err(Failure::Malformed),
        ] {
            let mut ops = view(identity);
            assert!(qualify_proc(process().fd, 42, &mut ops).is_err());
            assert!(ops.inner.calls.is_empty());
            assert!(!ops.opened.iter().any(|p| p != "self"));
        }
    }
    #[test]
    fn projection_skips_maximum_group_line_across_chunk_boundaries() {
        let mut input = b"Name: bad\xffname\nTgid: 42\nPid: 42\nGroups:\t".to_vec();
        for _ in 0..65536 {
            input.extend_from_slice(b"4294967295 ");
        }
        input.extend_from_slice(b"\nNStgid:\t42\nNSpid:\t42\nignored trailing data");
        let projected = project_identity(std::io::Cursor::new(input)).unwrap();
        assert_eq!(projected, b"Tgid: 42\nPid: 42\nNSpid:\t42\n");
        assert!(projected.len() < 512);
    }
    #[test]
    fn projection_rejects_incomplete_duplicate_oversized_or_denied_input() {
        for input in [
            b"Pid: 42\nTgid: 42\nNSpid: 42".to_vec(),
            b"Pid: 42\nPid: 42\nTgid: 42\nNSpid: 42\n".to_vec(),
            vec![b'x'; 1048577],
        ] {
            assert!(project_identity(std::io::Cursor::new(input)).is_err());
        }
        struct Denied;
        impl std::io::Read for Denied {
            fn read(&mut self, _b: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from_raw_os_error(libc::EACCES))
            }
        }
        assert!(matches!(
            project_identity(Denied),
            Err(Failure::Errno(libc::EACCES))
        ));
    }
    #[test]
    fn capability_denial_never_exposes_qualified_numeric_access() {
        for errno in [libc::ENOSYS, libc::EPERM, libc::ESRCH] {
            let mut ops = view(Ok(b"Pid: 42\nTgid: 42\nNSpid: 42\n".to_vec()));
            ops.inner.signals = [Err(Failure::Errno(errno))].into();
            assert!(matches!(
                qualify_proc(process().fd, 42, &mut ops),
                Err(Unavailable::Capability(_))
            ));
            assert_eq!(ops.opened, vec!["self"]);
            assert_eq!(ops.inner.calls.len(), 1);
        }
    }
    #[test]
    fn each_duplicate_identity_field_and_late_read_failure_is_unavailable() {
        for key in [b"Pid:".as_slice(), b"Tgid:", b"NSpid:"] {
            let mut bytes = b"Pid: 42\nTgid: 42\nNSpid: 42\n".to_vec();
            bytes.extend_from_slice(key);
            bytes.extend_from_slice(b" 42\n");
            assert!(project_identity(std::io::Cursor::new(bytes)).is_err());
        }
        struct LateDenied {
            first: bool,
        }
        impl std::io::Read for LateDenied {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
                if self.first {
                    self.first = false;
                    let line = b"Pid: 42\nTgid: 42\nNSpid: 42\n";
                    b[..line.len()].copy_from_slice(line);
                    Ok(line.len())
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::EIO))
                }
            }
        }
        assert!(matches!(
            project_identity(LateDenied { first: true }),
            Err(Failure::Errno(libc::EIO))
        ));
    }
}

#[cfg(test)]
mod census_parser_tests {
    use super::*;
    #[test]
    fn kernel_thread_zero_sid_is_valid_outside_session_data() {
        let bytes = b"2 (kthreadd) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9\n";
        assert_eq!(parse_stat(bytes).unwrap().sid, 0);
    }
    #[test]
    fn zero_sid_is_excluded_without_signal_and_bad_sid_stays_malformed() {
        struct KernelThread;
        impl Operations for KernelThread {
            fn status(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
                Ok(b"Pid: 2\nTgid: 2\n".to_vec())
            }
            fn stat(&mut self, _fd: &OwnedFd) -> Result<Vec<u8>, Failure> {
                Ok(b"2 (kthreadd) S 0 0 0 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9\n".to_vec())
            }
            fn signal(&mut self, _fd: &OwnedFd, _sig: i32) -> Result<(), Failure> {
                panic!("outside-session process must not be signalled")
            }
        }
        let fd = std::fs::File::open("/dev/null").unwrap().into();
        assert!(matches!(
            RetainedProcess::acquire_member(fd, 2, 42, &mut KernelThread),
            Err(Acquisition::OutsideSession)
        ));
        for sid in ["-1", "4294967296", "bad"] {
            let text = format!("2 (test) S 0 0 {sid} 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 9\n");
            assert!(parse_stat(text.as_bytes()).is_err());
        }
    }
}

pub mod scope;

mod leader_watch;
mod pty;
pub(crate) use pty::{
    own_child, own_reported_child, prepare, LeaderReports, LeaderStart, LeaderWindow,
};

pub(crate) mod fork;

pub(crate) mod fork_child;

#[cfg(feature = "system")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod adoption;

mod observation;
pub(crate) use observation::ObservedProcess;

#[cfg(test)]
#[path = "kill_child_sessions_tests.rs"]
mod kill_child_sessions_tests;
