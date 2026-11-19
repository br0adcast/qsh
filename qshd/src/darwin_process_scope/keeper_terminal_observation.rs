//! Actor-only, non-atomic fixture observations. Raw records remain private.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
const CAP: usize = 65536;
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Checkpoint {
    BeforeStdioClose,
    AfterStdioClose,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ObserverError {
    Binding,
    Deadline,
    Enumeration,
    EntryLimit,
    MalformedEntry,
    DescriptorRace,
    Stat,
    EnumClose,
    ReportIo,
    ReportLimit,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Binding {
    pub schema: u8,
    pub nonce: String,
    pub end: u128,
    pub actor: [u64; 3],
    pub source: String,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Descriptor {
    pub fd: i32,
    pub dev: u64,
    pub rdev: u64,
    pub ino: u64,
    pub mode: u32,
    pub flags: i32,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    checkpoint: Checkpoint,
    binding: Binding,
    pid: i32,
    sid: i32,
    group: i32,
    foreground: Option<i32>,
    descriptors: Vec<Descriptor>,
    enumeration: Descriptor,
    enum_closed: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CloseReceipt {
    fd: i32,
    before: Option<Descriptor>,
    success: bool,
    errno: Option<i32>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Report {
    binding: Binding,
    before: Result<Snapshot, ObserverError>,
    closes: Vec<CloseReceipt>,
    after: Result<Snapshot, ObserverError>,
}
pub(super) trait Ops {
    fn now(&mut self) -> u128;
    fn process(&mut self) -> Result<(i32, i32, i32), ObserverError>;
    fn foreground(&mut self) -> Result<i32, ObserverError>;
    fn begin(&mut self) -> Result<Descriptor, ObserverError>;
    fn next(&mut self) -> Result<Option<String>, ObserverError>;
    fn descriptor(&mut self, fd: i32) -> Result<Descriptor, ObserverError>;
    fn finish(&mut self) -> Result<(), ObserverError>;
    fn close_original(&mut self, fd: i32) -> Result<(), i32>;
}
pub(super) fn source_digest() -> String {
    let mut h = Sha256::new();
    h.update(b"qsh223-original-owner-observation-v1\0");
    for bytes in [
        include_bytes!("keeper_integration_tests.rs").as_slice(),
        include_bytes!("keeper_terminal_observation.rs").as_slice(),
        include_bytes!("keeper_owner_observation.rs").as_slice(),
        include_bytes!("keeper.rs").as_slice(),
        include_bytes!("native.c").as_slice(),
        include_bytes!("native.h").as_slice(),
        include_bytes!("native.rs").as_slice(),
    ] {
        h.update((bytes.len() as u64).to_be_bytes());
        h.update(bytes);
    }
    hex::encode(h.finalize())
}
fn clock(ops: &mut impl Ops, end: u128) -> Result<(), ObserverError> {
    if ops.now() >= end {
        Err(ObserverError::Deadline)
    } else {
        Ok(())
    }
}
pub(super) fn collect_snapshot(
    checkpoint: Checkpoint,
    binding: &Binding,
    end: u128,
    ops: &mut impl Ops,
) -> Result<Snapshot, ObserverError> {
    clock(ops, end)?;
    let enumeration = ops.begin()?;
    let gathered = (|| {
        if enumeration.fd < 0 || enumeration.mode & 0o170000 != 0o040000 {
            return Err(ObserverError::Enumeration);
        }
        let (pid, sid, group) = ops.process()?;
        let foreground = if checkpoint == Checkpoint::BeforeStdioClose {
            Some(ops.foreground()?)
        } else {
            None
        };
        let mut descriptors = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        let mut entries = 0;
        while let Some(name) = ops.next()? {
            clock(ops, end)?;
            entries += 1;
            if entries > 256 {
                return Err(ObserverError::EntryLimit);
            }
            if name == "." || name == ".." {
                continue;
            }
            if name.is_empty() || !name.bytes().all(|x| x.is_ascii_digit()) {
                return Err(ObserverError::MalformedEntry);
            }
            let fd = name
                .parse::<i32>()
                .map_err(|_| ObserverError::MalformedEntry)?;
            if !seen.insert(fd) {
                return Err(ObserverError::MalformedEntry);
            }
            let d = ops.descriptor(fd)?;
            if d.fd != fd || d.flags < 0 {
                return Err(ObserverError::DescriptorRace);
            }
            if fd == enumeration.fd {
                if d != enumeration {
                    return Err(ObserverError::DescriptorRace);
                }
            } else {
                if descriptors.len() == 128 {
                    return Err(ObserverError::EntryLimit);
                };
                descriptors.push(d)
            }
        }
        if !seen.contains(&enumeration.fd) || ops.descriptor(enumeration.fd)? != enumeration {
            return Err(ObserverError::DescriptorRace);
        }
        clock(ops, end)?;
        descriptors.sort_by_key(|x| x.fd);
        Ok(Snapshot {
            checkpoint,
            binding: binding.clone(),
            pid,
            sid,
            group,
            foreground,
            descriptors,
            enumeration,
            enum_closed: true,
        })
    })();
    // Exactly one closure attempt even after collection refusal; no blind retry.
    let closed = ops.finish();
    closed?;
    clock(ops, end)?;
    gathered
}
pub(super) fn observe_closes(binding: &Binding, ops: &mut impl Ops) -> Report {
    let before = collect_snapshot(Checkpoint::BeforeStdioClose, binding, binding.end, ops);
    let mut closes = Vec::new();
    for fd in 0..3 {
        let identity = ops.descriptor(fd).ok();
        let result = ops.close_original(fd);
        closes.push(CloseReceipt {
            fd,
            before: identity,
            success: result.is_ok(),
            errno: result.err(),
        });
        if closes.last().is_some_and(|x| !x.success) {
            break;
        }
    }
    let after = if closes.len() == 3 && closes.iter().all(|x| x.success) {
        collect_snapshot(Checkpoint::AfterStdioClose, binding, binding.end, ops)
    } else {
        Err(ObserverError::Stat)
    };
    Report {
        binding: binding.clone(),
        before,
        closes,
        after,
    }
}
#[derive(Serialize)]
pub(super) struct Projection {
    pub actor_only: bool,
    pub state: &'static str,
    pub refusal: Option<ObserverError>,
    pub closes: [bool; 3],
    pub enum_closed: bool,
    pub process_match: bool,
    pub session_match: bool,
    pub group_match: bool,
    pub foreground_match: bool,
    pub before_count: usize,
    pub after_count: usize,
    pub same_slave: usize,
    pub other_character: usize,
    pub after_table: &'static str,
    pub source: String,
}
pub(super) fn unavailable(error: ObserverError) -> Projection {
    Projection {
        actor_only: true,
        state: if error == ObserverError::Binding {
            "unbound"
        } else {
            "unavailable"
        },
        refusal: Some(error),
        closes: [false; 3],
        enum_closed: false,
        process_match: false,
        session_match: false,
        group_match: false,
        foreground_match: false,
        before_count: 0,
        after_count: 0,
        same_slave: 0,
        other_character: 0,
        after_table: "unavailable",
        source: source_digest(),
    }
}
pub(super) fn validate_report(
    bytes: &[u8],
    expected: &Binding,
    admitted: Option<([u64; 3], i32)>,
) -> Result<Projection, ObserverError> {
    if bytes.len() > CAP {
        return Err(ObserverError::ReportLimit);
    }
    let r: Report = serde_json::from_slice(bytes).map_err(|_| ObserverError::Binding)?;
    if r.binding != *expected {
        return Err(ObserverError::Binding);
    }
    let (before, after) = match (&r.before, &r.after) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => return Err(*e),
    };
    let Some((actor, sid)) = admitted else {
        return Err(ObserverError::Binding);
    };
    if expected.schema != 1
        || expected.nonce.len() != 32
        || !expected.nonce.bytes().all(|c| c.is_ascii_hexdigit())
        || expected.source != source_digest()
        || actor != expected.actor
        || actor[0] == 0
        || actor[1] == 0
        || actor[0] > i32::MAX as u64
    {
        return Err(ObserverError::Binding);
    }
    for (s, phase) in [
        (before, Checkpoint::BeforeStdioClose),
        (after, Checkpoint::AfterStdioClose),
    ] {
        if s.checkpoint != phase
            || s.binding != *expected
            || s.pid != actor[0] as i32
            || s.sid != sid
            || s.group != s.pid
            || !s.enum_closed
            || s.enumeration.fd < 0
            || s.enumeration.mode & 0o170000 != 0o040000
            || s.descriptors.len() > 128
        {
            return Err(ObserverError::Binding);
        }
        let mut seen = std::collections::BTreeSet::new();
        for d in &s.descriptors {
            if d.fd < 0 || d.flags < 0 || d.fd == s.enumeration.fd || !seen.insert(d.fd) {
                return Err(ObserverError::Binding);
            }
        }
    }
    if before.foreground != Some(before.group) || after.foreground.is_some() || r.closes.len() != 3
    {
        return Err(ObserverError::Binding);
    }
    for (fd, c) in r.closes.iter().enumerate() {
        if c.fd != fd as i32
            || !c.success
            || c.errno.is_some()
            || c.before.as_ref().is_some_and(|d| d.fd != fd as i32)
            || c.before.as_ref() != before.descriptors.iter().find(|d| d.fd == fd as i32)
        {
            return Err(ObserverError::Binding);
        }
    }
    let slave = before
        .descriptors
        .iter()
        .find(|d| d.fd == 0)
        .ok_or(ObserverError::Binding)?;
    if slave.mode & 0o170000 != 0o020000 {
        return Err(ObserverError::Binding);
    }
    let same = after
        .descriptors
        .iter()
        .filter(|d| {
            d.mode & 0o170000 == 0o020000
                && d.dev == slave.dev
                && d.rdev == slave.rdev
                && d.ino == slave.ino
        })
        .count();
    let characters = after
        .descriptors
        .iter()
        .filter(|d| d.mode & 0o170000 == 0o020000)
        .count();
    Ok(Projection {
        actor_only: true,
        state: "complete",
        refusal: None,
        closes: [true; 3],
        enum_closed: true,
        process_match: true,
        session_match: true,
        group_match: true,
        foreground_match: true,
        before_count: before.descriptors.len(),
        after_count: after.descriptors.len(),
        same_slave: same,
        other_character: characters - same,
        after_table: if after.descriptors.is_empty() {
            "empty"
        } else {
            "nonempty"
        },
        source: expected.source.clone(),
    })
}
pub(super) fn closes_succeeded(r: &Report) -> bool {
    r.closes.len() == 3
        && r.closes
            .iter()
            .enumerate()
            .all(|(i, c)| c.fd == i as i32 && c.success && c.errno.is_none())
}
pub(super) fn complete(r: &Report) -> bool {
    match (&r.before, &r.after) {
        (Ok(a), Ok(_)) => encoded(r)
            .ok()
            .and_then(|bytes| {
                validate_report(&bytes, &r.binding, Some((r.binding.actor, a.sid))).ok()
            })
            .is_some(),
        _ => false,
    }
}
pub(super) fn gate(nonce: &str, complete: bool) -> Vec<u8> {
    format!(
        "{} {}\n",
        nonce,
        if complete { "complete" } else { "refused" }
    )
    .into_bytes()
}
pub(super) fn parse_gate(bytes: &[u8], nonce: &str) -> Option<bool> {
    if bytes == gate(nonce, true) {
        Some(true)
    } else if bytes == gate(nonce, false) {
        Some(false)
    } else {
        None
    }
}
fn encoded(report: &Report) -> Result<Vec<u8>, ObserverError> {
    if report.closes.len() > 3
        || [&report.before, &report.after]
            .into_iter()
            .any(|s| s.as_ref().is_ok_and(|s| s.descriptors.len() > 128))
    {
        return Err(ObserverError::ReportLimit);
    }
    let bytes = serde_json::to_vec(report).map_err(|_| ObserverError::ReportIo)?;
    if bytes.len() > CAP {
        Err(ObserverError::ReportLimit)
    } else {
        Ok(bytes)
    }
}
// Files are private fixture evidence, never PTY bytes or public diagnostics.
fn directory(path: &std::path::Path) -> Result<std::fs::File, ObserverError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ObserverError::ReportIo)?;
    let m = f.metadata().map_err(|_| ObserverError::ReportIo)?;
    if !m.is_dir() || m.uid() != unsafe { nix::libc::geteuid() } || m.mode() & 0o077 != 0 {
        return Err(ObserverError::ReportIo);
    }
    Ok(f)
}
fn close_file(f: std::fs::File) -> Result<(), ObserverError> {
    use std::os::fd::IntoRawFd;
    let fd = f.into_raw_fd();
    if unsafe { nix::libc::close(fd) } == 0 {
        Ok(())
    } else {
        Err(ObserverError::ReportIo)
    }
}
fn checked_file(f: &std::fs::File) -> Result<(), ObserverError> {
    use std::os::unix::fs::MetadataExt;
    let m = f.metadata().map_err(|_| ObserverError::ReportIo)?;
    if !m.is_file()
        || m.uid() != unsafe { nix::libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
        || m.len() > CAP as u64
    {
        return Err(ObserverError::ReportIo);
    }
    Ok(())
}
pub(super) fn publish(path: &std::path::Path, report: &Report) -> Result<(), ObserverError> {
    publish_with_close(path, report, close_file)
}
fn publish_with_close(
    path: &std::path::Path,
    report: &Report,
    mut close: impl FnMut(std::fs::File) -> Result<(), ObserverError>,
) -> Result<(), ObserverError> {
    let bytes = encoded(report)?;
    publish_named(path, &bytes, c"terminal-observation.json", &mut close)
}
pub(super) fn publish_owner(path: &std::path::Path, bytes: &[u8]) -> Result<(), ObserverError> {
    if bytes.len() > CAP {
        return Err(ObserverError::ReportLimit);
    }
    publish_named(path, bytes, c"owner-observation.json", &mut close_file)
}
fn publish_named(
    path: &std::path::Path,
    bytes: &[u8],
    leaf: &std::ffi::CStr,
    close: &mut impl FnMut(std::fs::File) -> Result<(), ObserverError>,
) -> Result<(), ObserverError> {
    use std::io::Write;
    use std::os::fd::{AsRawFd, FromRawFd};
    let dir = directory(path)?;
    let fd = unsafe {
        nix::libc::openat(
            dir.as_raw_fd(),
            leaf.as_ptr(),
            nix::libc::O_WRONLY
                | nix::libc::O_CREAT
                | nix::libc::O_EXCL
                | nix::libc::O_NOFOLLOW
                | nix::libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        let _ = close(dir);
        return Err(ObserverError::ReportIo);
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let result = (|| {
        checked_file(&f)?;
        f.write_all(bytes).map_err(|_| ObserverError::ReportIo)?;
        checked_file(&f)
    })();
    let file_closed = close(f);
    let dir_closed = close(dir);
    result?;
    file_closed?;
    dir_closed
}
pub(super) fn read_report(path: &std::path::Path) -> Result<Vec<u8>, ObserverError> {
    use std::io::Read;
    use std::os::fd::{AsRawFd, FromRawFd};
    let dir = directory(path)?;
    let fd = unsafe {
        nix::libc::openat(
            dir.as_raw_fd(),
            c"terminal-observation.json".as_ptr(),
            nix::libc::O_RDONLY
                | nix::libc::O_NOFOLLOW
                | nix::libc::O_CLOEXEC
                | nix::libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        let _ = close_file(dir);
        return Err(ObserverError::ReportIo);
    }
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut bytes = Vec::new();
    let result = (|| {
        checked_file(&f)?;
        (&mut f)
            .take((CAP + 1) as u64)
            .read_to_end(&mut bytes)
            .map_err(|_| ObserverError::ReportIo)?;
        if bytes.len() > CAP {
            return Err(ObserverError::ReportLimit);
        }
        checked_file(&f)
    })();
    let file_closed = close_file(f);
    let dir_closed = close_file(dir);
    result?;
    file_closed?;
    dir_closed?;
    Ok(bytes)
}
pub(super) fn project_report(
    bytes: &[u8],
    binding: &Binding,
    admitted: Option<([u64; 3], i32)>,
    complete_gate: bool,
) -> Projection {
    if complete_gate {
        if let Ok(p) = validate_report(bytes, binding, admitted) {
            return p;
        }
    }
    let error = validate_report(bytes, binding, admitted)
        .err()
        .unwrap_or(ObserverError::Binding);
    let mut p = unavailable(error);
    if admitted.is_some() && bytes.len() <= CAP {
        if let Ok(r) = serde_json::from_slice::<Report>(bytes) {
            if r.binding == *binding {
                p.state = "refused";
                for (i, c) in r.closes.iter().take(3).enumerate() {
                    p.closes[i] = c.fd == i as i32 && c.success && c.errno.is_none()
                }
            }
        }
    }
    p
}
#[derive(Clone, Copy)]
pub(super) struct SlaveKey {
    pub dev: u64,
    pub rdev: u64,
    pub ino: u64,
    pub kind: u32,
}
pub(super) fn validated_slave_key(
    bytes: &[u8],
    binding: &Binding,
    admitted: Option<([u64; 3], i32)>,
    complete_gate: bool,
) -> Result<SlaveKey, ObserverError> {
    if !complete_gate {
        return Err(ObserverError::Binding);
    }
    validate_report(bytes, binding, admitted)?;
    let mut time: nix::libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { nix::libc::clock_gettime(nix::libc::CLOCK_MONOTONIC, &mut time) } != 0
        || time.tv_sec < 0
        || time.tv_nsec < 0
        || time.tv_sec as u128 * 1_000_000_000 + time.tv_nsec as u128 >= binding.end
    {
        return Err(ObserverError::Deadline);
    }
    let report: Report = serde_json::from_slice(bytes).map_err(|_| ObserverError::Binding)?;
    let before = report.before.map_err(|_| ObserverError::Binding)?;
    let d = before
        .descriptors
        .iter()
        .find(|d| d.fd == 0)
        .ok_or(ObserverError::Binding)?;
    Ok(SlaveKey {
        dev: d.dev,
        rdev: d.rdev,
        ino: d.ino,
        kind: d.mode & 0o170000,
    })
}
#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
pub(super) mod real {
    use super::*;
    use nix::libc;
    pub(super) struct Native {
        directory: Option<*mut libc::DIR>,
    }
    impl Native {
        pub(super) fn new() -> Self {
            Self { directory: None }
        }
    }
    impl Drop for Native {
        fn drop(&mut self) {
            if let Some(d) = self.directory.take() {
                unsafe {
                    libc::closedir(d);
                }
            }
        }
    }
    impl Ops for Native {
        fn now(&mut self) -> u128 {
            let mut t: libc::timespec = unsafe { std::mem::zeroed() };
            if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut t) } < 0 {
                u128::MAX
            } else {
                t.tv_sec as u128 * 1_000_000_000 + t.tv_nsec as u128
            }
        }
        fn process(&mut self) -> Result<(i32, i32, i32), ObserverError> {
            let p = unsafe { libc::getpid() };
            let sid = unsafe { libc::getsid(0) };
            let group = unsafe { libc::getpgrp() };
            if p <= 0 || sid <= 0 || group <= 0 {
                Err(ObserverError::Binding)
            } else {
                Ok((p, sid, group))
            }
        }
        fn foreground(&mut self) -> Result<i32, ObserverError> {
            let p = unsafe { libc::tcgetpgrp(0) };
            if p <= 0 {
                Err(ObserverError::Stat)
            } else {
                Ok(p)
            }
        }
        fn begin(&mut self) -> Result<Descriptor, ObserverError> {
            let fd = unsafe {
                libc::open(
                    c"/dev/fd".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(ObserverError::Enumeration);
            }
            let dir = unsafe { libc::fdopendir(fd) };
            if dir.is_null() {
                unsafe {
                    libc::close(fd);
                };
                return Err(ObserverError::Enumeration);
            }
            self.directory = Some(dir);
            let owned = unsafe { libc::dirfd(dir) };
            match self.descriptor(owned) {
                Ok(d) => Ok(d),
                Err(e) => {
                    let _ = self.finish();
                    Err(e)
                }
            }
        }
        fn next(&mut self) -> Result<Option<String>, ObserverError> {
            let dir = self.directory.ok_or(ObserverError::Enumeration)?;
            unsafe { *libc::__error() = 0 };
            let entry = unsafe { libc::readdir(dir) };
            if entry.is_null() {
                if unsafe { *libc::__error() } != 0 {
                    return Err(ObserverError::Enumeration);
                }
                return Ok(None);
            }
            let name = unsafe { std::ffi::CStr::from_ptr((*entry).d_name.as_ptr()) };
            Ok(Some(
                name.to_str()
                    .map_err(|_| ObserverError::MalformedEntry)?
                    .to_owned(),
            ))
        }
        fn descriptor(&mut self, fd: i32) -> Result<Descriptor, ObserverError> {
            let mut a: libc::stat = unsafe { std::mem::zeroed() };
            let mut b: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(fd, &mut a) } < 0 {
                return Err(ObserverError::Stat);
            }
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            if flags < 0 || unsafe { libc::fstat(fd, &mut b) } < 0 {
                return Err(ObserverError::DescriptorRace);
            }
            let record = |s: libc::stat| Descriptor {
                fd,
                dev: s.st_dev as u64,
                rdev: s.st_rdev as u64,
                ino: s.st_ino,
                mode: s.st_mode as u32,
                flags,
            };
            let first = record(a);
            if first != record(b) {
                return Err(ObserverError::DescriptorRace);
            }
            Ok(first)
        }
        fn finish(&mut self) -> Result<(), ObserverError> {
            let d = self.directory.take().ok_or(ObserverError::EnumClose)?;
            if unsafe { libc::closedir(d) } == 0 {
                Ok(())
            } else {
                Err(ObserverError::EnumClose)
            }
        }
        fn close_original(&mut self, fd: i32) -> Result<(), i32> {
            if unsafe { libc::close(fd) } == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(0))
            }
        }
    }
}

#[cfg(all(target_os = "macos", feature = "test-darwin-keeper"))]
pub(super) fn capture(binding: &Binding) -> Report {
    observe_closes(binding, &mut real::Native::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    struct Fake {
        entries: Vec<String>,
        cursor: usize,
        descriptors: Vec<Descriptor>,
        finish_ok: bool,
        finished: usize,
        closes: Vec<i32>,
        fail_close: Option<i32>,
        failure: Option<ObserverError>,
    }
    fn d(fd: i32, mode: u32) -> Descriptor {
        Descriptor {
            fd,
            dev: 1,
            rdev: 2,
            ino: 3,
            mode,
            flags: 1,
        }
    }
    fn binding() -> Binding {
        Binding {
            schema: 1,
            nonce: "a".repeat(32),
            end: 100,
            actor: [20, 30, 40],
            source: source_digest(),
        }
    }
    fn fake() -> Fake {
        Fake {
            entries: vec![".".into(), "..".into(), "0".into(), "9".into()],
            cursor: 0,
            descriptors: vec![d(0, 0o020600), d(9, 0o040700)],
            finish_ok: true,
            finished: 0,
            closes: vec![],
            fail_close: None,
            failure: None,
        }
    }
    impl Ops for Fake {
        fn now(&mut self) -> u128 {
            1
        }
        fn process(&mut self) -> Result<(i32, i32, i32), ObserverError> {
            Ok((20, 10, 20))
        }
        fn foreground(&mut self) -> Result<i32, ObserverError> {
            Ok(20)
        }
        fn begin(&mut self) -> Result<Descriptor, ObserverError> {
            Ok(d(9, 0o040700))
        }
        fn next(&mut self) -> Result<Option<String>, ObserverError> {
            if let Some(e) = self.failure {
                return Err(e);
            };
            let x = self.entries.get(self.cursor).cloned();
            self.cursor += 1;
            Ok(x)
        }
        fn descriptor(&mut self, fd: i32) -> Result<Descriptor, ObserverError> {
            self.descriptors
                .iter()
                .find(|d| d.fd == fd)
                .cloned()
                .ok_or(ObserverError::DescriptorRace)
        }
        fn finish(&mut self) -> Result<(), ObserverError> {
            self.finished += 1;
            if self.finish_ok {
                Ok(())
            } else {
                Err(ObserverError::EnumClose)
            }
        }
        fn close_original(&mut self, fd: i32) -> Result<(), i32> {
            self.closes.push(fd);
            if self.fail_close == Some(fd) {
                Err(9)
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn keeper_terminal_observation_actual_collection_requires_positive_close() {
        let mut f = fake();
        assert!(collect_snapshot(Checkpoint::BeforeStdioClose, &binding(), 100, &mut f).is_ok());
        assert_eq!(f.finished, 1);
        let mut f = fake();
        f.finish_ok = false;
        assert!(matches!(
            collect_snapshot(Checkpoint::BeforeStdioClose, &binding(), 100, &mut f),
            Err(ObserverError::EnumClose)
        ));
    }
    fn successful() -> Report {
        let mut f = fake();
        f.entries = vec!["0".into(), "1".into(), "2".into(), "9".into()];
        f.descriptors = vec![
            d(0, 0o020600),
            d(1, 0o020600),
            d(2, 0o020600),
            d(9, 0o040700),
        ];
        let before = collect_snapshot(Checkpoint::BeforeStdioClose, &binding(), 100, &mut f)
            .unwrap_or_else(|_| panic!("synthetic collection"));
        let mut f = fake();
        f.entries = vec!["9".into()];
        let after = collect_snapshot(Checkpoint::AfterStdioClose, &binding(), 100, &mut f)
            .unwrap_or_else(|_| panic!("synthetic collection"));
        Report {
            binding: binding(),
            before: Ok(before.clone()),
            closes: (0..3)
                .map(|fd| CloseReceipt {
                    fd,
                    before: before.descriptors.iter().find(|d| d.fd == fd).cloned(),
                    success: true,
                    errno: None,
                })
                .collect(),
            after: Ok(after),
        }
    }
    #[test]
    fn keeper_terminal_observation_failures_never_mean_empty() {
        for error in [
            ObserverError::Enumeration,
            ObserverError::Stat,
            ObserverError::DescriptorRace,
        ] {
            let mut f = fake();
            f.failure = Some(error);
            assert!(
                matches!(collect_snapshot(Checkpoint::AfterStdioClose,&binding(),100,&mut f),Err(e) if e==error)
            );
            assert_eq!(f.finished, 1)
        }
        for entry in ["bad", "-1", "999999999999999999999"] {
            let mut f = fake();
            f.entries.push(entry.into());
            assert!(matches!(
                collect_snapshot(Checkpoint::AfterStdioClose, &binding(), 100, &mut f),
                Err(ObserverError::MalformedEntry)
            ));
            assert_eq!(f.finished, 1)
        }
        let mut f = fake();
        f.entries.push("0".into());
        assert!(matches!(
            collect_snapshot(Checkpoint::AfterStdioClose, &binding(), 100, &mut f),
            Err(ObserverError::MalformedEntry)
        ));
    }
    #[test]
    fn keeper_terminal_observation_bounds_deadline_and_owned_enum() {
        let mut f = fake();
        f.entries = (0..129).map(|x| x.to_string()).collect();
        f.descriptors = (0..129).map(|x| d(x, 0o020600)).collect();
        f.descriptors.iter_mut().find(|x| x.fd == 9).unwrap().mode = 0o040700;
        f.entries.push("130".into());
        f.descriptors.push(d(130, 0o020600));
        assert!(matches!(
            collect_snapshot(Checkpoint::AfterStdioClose, &binding(), 100, &mut f),
            Err(ObserverError::EntryLimit)
        ));
        let mut many = fake();
        many.entries = vec![".".into(); 257];
        assert!(matches!(
            collect_snapshot(Checkpoint::AfterStdioClose, &binding(), 100, &mut many),
            Err(ObserverError::EntryLimit)
        ));
        assert_eq!(many.finished, 1);
        let mut f = fake();
        assert!(matches!(
            collect_snapshot(Checkpoint::AfterStdioClose, &binding(), 1, &mut f),
            Err(ObserverError::Deadline)
        ));
        assert_eq!(f.finished, 0);
        let mut f = fake();
        f.descriptors.iter_mut().find(|d| d.fd == 9).unwrap().ino = 99;
        assert!(matches!(
            collect_snapshot(Checkpoint::AfterStdioClose, &binding(), 100, &mut f),
            Err(ObserverError::DescriptorRace)
        ));
    }
    #[test]
    fn keeper_terminal_observation_close_order_and_refusal() {
        for failed in [None, Some(0), Some(1), Some(2)] {
            let mut f = fake();
            f.failure = Some(ObserverError::Enumeration);
            f.fail_close = failed;
            let r = observe_closes(&binding(), &mut f);
            let last = failed.unwrap_or(2);
            assert_eq!(f.closes, (0..=last).collect::<Vec<_>>());
            assert_eq!(closes_succeeded(&r), failed.is_none());
            if failed.is_some() {
                let c = r.closes.last().unwrap();
                assert!(!c.success);
                assert_eq!(c.errno, Some(9))
            }
            assert!(!complete(&r));
        }
    }
    #[test]
    fn keeper_terminal_observation_projection_retains_character_alias() {
        let mut r = successful();
        let after = r.after.as_mut().unwrap_or_else(|_| panic!("after"));
        after.descriptors.push(d(0, 0o020600));
        let mut other = d(7, 0o020600);
        other.rdev = 9;
        after.descriptors.push(other);
        let p = validate_report(
            &encoded(&r).unwrap_or_default(),
            &binding(),
            Some((binding().actor, 10)),
        )
        .unwrap_or_else(|_| panic!("admission"));
        assert_eq!(p.same_slave, 1);
        assert_eq!(p.other_character, 1);
        assert_eq!(p.after_table, "nonempty");
        assert!(p.foreground_match);
        assert!(r
            .after
            .as_ref()
            .unwrap_or_else(|_| panic!("after"))
            .foreground
            .is_none());
    }
    #[test]
    fn keeper_terminal_observation_binding_replays_and_fake_closure() {
        let r = successful();
        let bytes = encoded(&r).unwrap_or_default();
        assert!(validate_report(&bytes, &binding(), None).is_err());
        for n in 0..7 {
            let mut r = r.clone();
            match n {
                0 => r.binding.nonce = "b".repeat(32),
                1 => r.binding.end += 1,
                2 => r.binding.source = "PRIVATE_PATH_CANARY".into(),
                3 => r.binding.actor[0] += 1,
                4 => {
                    r.after.as_mut().unwrap_or_else(|_| panic!()).checkpoint =
                        Checkpoint::BeforeStdioClose
                }
                5 => r.after.as_mut().unwrap_or_else(|_| panic!()).enum_closed = false,
                _ => {
                    r.after.as_mut().unwrap_or_else(|_| panic!()).descriptors =
                        vec![d(3, 0o020600), d(3, 0o020600)]
                }
            }
            assert!(validate_report(
                &encoded(&r).unwrap_or_default(),
                &binding(),
                Some((binding().actor, 10))
            )
            .is_err())
        }
    }
    #[test]
    fn keeper_terminal_observation_gate_privacy_and_limits() {
        let r = successful();
        let bytes = encoded(&r).unwrap_or_default();
        assert_eq!(
            parse_gate(&gate(&binding().nonce, true), &binding().nonce),
            Some(true)
        );
        assert_eq!(
            parse_gate(&gate(&binding().nonce, false), &binding().nonce),
            Some(false)
        );
        for raw in [binding().nonce.as_bytes(), b"bad", b" "] {
            assert!(parse_gate(raw, &binding().nonce).is_none())
        }
        assert_eq!(
            project_report(&bytes, &binding(), None, true).state,
            "unbound"
        );
        let p = project_report(&bytes, &binding(), Some((binding().actor, 10)), true);
        let text = serde_json::to_string(&p).unwrap_or_default();
        for private in [
            &binding().nonce,
            "PRIVATE_PATH_CANARY",
            "descriptors",
            "errno",
            "\"fd\"",
            "\"pid\"",
        ] {
            assert!(!text.contains(private))
        }
        assert_eq!(
            project_report(&bytes, &binding(), Some((binding().actor, 10)), false).state,
            "refused"
        );
        assert!(matches!(
            validate_report(&vec![0; CAP + 1], &binding(), Some((binding().actor, 10))),
            Err(ObserverError::ReportLimit)
        ));
    }
    #[test]
    fn keeper_terminal_observation_enum_reused_stdio_only_exactly_excluded() {
        let mut r = successful();
        let after = r.after.as_mut().unwrap_or_else(|_| panic!());
        after.enumeration = d(0, 0o040700);
        assert!(validate_report(
            &encoded(&r).unwrap_or_default(),
            &binding(),
            Some((binding().actor, 10))
        )
        .is_ok());
        r.after
            .as_mut()
            .unwrap_or_else(|_| panic!())
            .descriptors
            .push(d(0, 0o020600));
        assert!(validate_report(
            &encoded(&r).unwrap_or_default(),
            &binding(),
            Some((binding().actor, 10))
        )
        .is_err());
    }
    #[test]
    fn keeper_terminal_observation_private_file_validation() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let r = successful();
        assert!(publish(t.path(), &r).is_ok());
        assert!(publish(t.path(), &r).is_err());
        let raw = read_report(t.path()).unwrap_or_default();
        assert!(validate_report(&raw, &binding(), Some((binding().actor, 10))).is_ok());
        let file = t.path().join("terminal-observation.json");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_report(t.path()).is_err());
        std::fs::remove_file(&file).unwrap();
        symlink("unadmitted", &file).unwrap();
        assert!(read_report(t.path()).is_err());
        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(read_report(t.path()).is_err());
    }
    #[test]
    fn keeper_terminal_observation_report_close_failure_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        std::fs::set_permissions(t.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let mut count = 0;
        assert!(publish_with_close(t.path(), &successful(), |f| {
            count += 1;
            close_file(f)?;
            Err(ObserverError::ReportIo)
        })
        .is_err());
        assert_eq!(count, 2);
        assert_eq!(
            parse_gate(&gate(&binding().nonce, false), &binding().nonce),
            Some(false)
        );
    }
    #[test]
    fn keeper_terminal_observation_original_gate_and_finalizer_order() {
        let source = include_str!("keeper_integration_tests.rs");
        assert!(source.contains("read_eof && reader_drop && retiring_poll_running"));
        let terminal = source
            .split("pub(super) fn terminal()")
            .nth(1)
            .unwrap()
            .split("pub(super) fn cancel_setup()")
            .next()
            .unwrap();
        assert!(
            terminal.find("terminal_observation(&path").unwrap()
                < terminal.find("super::terminal_eof_until").unwrap()
        );
        assert!(
            terminal.find("super::terminal_eof_until").unwrap()
                < terminal.find("exclusive(&path.join(\"release\")").unwrap()
        );
        let failed = terminal
            .split("let body_ok=result.is_ok();")
            .nth(1)
            .unwrap();
        assert!(
            failed.find("terminal_observation").unwrap()
                < failed.find("release.release()").unwrap()
        );
        assert!(failed.find("d.keep()").unwrap() < failed.find("c.finish(body_ok)").unwrap());
        let actor = source
            .split("let report = observation::capture")
            .nth(1)
            .unwrap();
        assert!(
            actor.find("observation::publish").unwrap() < actor.find("observation::gate").unwrap()
        );
        // #548: stdio is blocking again before the marker and the closes.
        let terminal_actor = source
            .split("if mode == \"terminal\" {")
            .nth(1)
            .unwrap()
            .split("let report = observation::capture")
            .next()
            .unwrap();
        let restored = terminal_actor
            .find("nix::libc::fcntl(0, nix::libc::F_SETFL, flags)")
            .unwrap();
        assert!(terminal_actor.find("keeper-input-proof\\n\");").unwrap() < restored);
        assert!(restored < terminal_actor.find("println!(\"KEEPER_RESIZED\")").unwrap());
        assert!(!terminal_actor[restored..].contains("O_NONBLOCK"));
    }
    #[test]
    fn owner_slave_key_requires_complete_bound_report_and_live_deadline() {
        let mut report = successful();
        let mut binding = binding();
        binding.end = u128::MAX;
        report.binding = binding.clone();
        report
            .before
            .as_mut()
            .unwrap_or_else(|_| panic!("fixture"))
            .binding = binding.clone();
        report
            .after
            .as_mut()
            .unwrap_or_else(|_| panic!("fixture"))
            .binding = binding.clone();
        let bytes = serde_json::to_vec(&report).unwrap();
        let admitted = Some((binding.actor, 10));
        let key = validated_slave_key(&bytes, &binding, admitted, true)
            .unwrap_or_else(|_| panic!("fixture"));
        let descriptor = &report
            .before
            .as_ref()
            .unwrap_or_else(|_| panic!("fixture"))
            .descriptors[0];
        assert_eq!(
            (key.dev, key.rdev, key.ino, key.kind),
            (
                descriptor.dev,
                descriptor.rdev,
                descriptor.ino,
                descriptor.mode & 0o170000
            )
        );
        assert!(validated_slave_key(&bytes, &binding, admitted, false).is_err());
        for variant in 0..4 {
            let mut changed = binding.clone();
            match variant {
                0 => changed.nonce = "b".repeat(32),
                1 => changed.source = "f".repeat(64),
                2 => changed.actor[2] += 1,
                _ => changed.end = 0,
            };
            assert!(validated_slave_key(&bytes, &changed, admitted, true).is_err());
        }
        assert!(validated_slave_key(&bytes, &binding, Some((binding.actor, 11)), true).is_err());
        report.binding.end = 0;
        report
            .before
            .as_mut()
            .unwrap_or_else(|_| panic!("fixture"))
            .binding
            .end = 0;
        report
            .after
            .as_mut()
            .unwrap_or_else(|_| panic!("fixture"))
            .binding
            .end = 0;
        binding.end = 0;
        assert!(matches!(
            validated_slave_key(
                &serde_json::to_vec(&report).unwrap(),
                &binding,
                admitted,
                true
            ),
            Err(ObserverError::Deadline)
        ));
    }
    #[test]
    fn owner_private_leaf_is_exclusive_bounded_and_separate() {
        use std::os::unix::fs::PermissionsExt;
        let d = tempfile::tempdir().unwrap();
        std::fs::set_permissions(d.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(publish_owner(d.path(), b"PRIVATE_SENTINEL").is_ok());
        assert!(publish_owner(d.path(), b"replacement").is_err());
        assert_eq!(
            std::fs::read(d.path().join("owner-observation.json")).unwrap(),
            b"PRIVATE_SENTINEL"
        );
        assert!(!d.path().join("terminal-observation.json").exists());
        assert!(publish_owner(d.path(), &vec![0; CAP + 1]).is_err());
    }
}
