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
    sid: u32,
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
    let sid = u32::try_from(unsigned_number(fields.get(3).ok_or(Failure::Malformed)?)?)
        .map_err(|_| Failure::Malformed)?;
    let threads = usize::try_from(positive_number(fields.get(17).ok_or(Failure::Malformed)?)?)
        .map_err(|_| Failure::Malformed)?;
    Ok(Stat {
        state,
        threads,
        sid,
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
}
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

mod pty;
pub(crate) use pty::{own_child, prepare};

pub(crate) mod fork;

pub(crate) mod fork_child;

#[cfg(feature = "system")]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod adoption;
