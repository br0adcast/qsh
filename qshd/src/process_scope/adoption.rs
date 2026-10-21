//! Staged global-stop adoption fence; not connected to the helper pump.
use super::{validate_tgid, Failure, Operations, RetainedProcess};
use std::{io::Read, os::fd::OwnedFd};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    Pending,
    Unknown,
    Complete,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reservation {
    Reserved,
    Other,
    Unknown,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RootState {
    Active,
    Settled,
    Unknown,
}
pub(crate) trait Roots {
    /// Reserved means actual unreaped custody, never an old diagnostic PID.
    fn classify(&mut self, pid: u32) -> Reservation;
    fn state(&self) -> RootState;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Observation {
    Running,
    Exited(i32),
    Yielded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reaped {
    Exited(i32),
    Yielded,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Empty {
    Yes,
    No,
    Yielded,
}
pub(crate) trait AdoptionOps: Operations {
    fn census(&mut self) -> Result<Box<dyn Read>, Failure>;
    fn open_child(&mut self, pid: u32) -> Result<OwnedFd, Failure>;
    fn observe_child(&mut self, pid: u32) -> Result<Observation, Failure>;
    fn reap_child(&mut self, pid: u32) -> Result<Reaped, Failure>;
    fn no_children(&mut self) -> Result<Empty, Failure>;
}

struct Census {
    reader: Box<dyn Read>,
    bytes: [u8; 4096],
    pos: usize,
    end: usize,
    token: u32,
    digits: usize,
    roots_settled: bool,
}
enum Token {
    Pid(u32),
    End,
    Yielded,
}
impl Census {
    fn next(&mut self) -> Result<Token, Failure> {
        // At most one buffer's bytes and one candidate per bounded owner pass.
        for _ in 0..4096 {
            if self.pos == self.end {
                match self.reader.read(&mut self.bytes) {
                    Ok(0) => {
                        if self.digits == 0 {
                            return Ok(Token::End);
                        }
                        let pid = self.token;
                        self.token = 0;
                        self.digits = 0;
                        return if pid > 0 && pid <= i32::MAX as u32 {
                            Ok(Token::Pid(pid))
                        } else {
                            Err(Failure::Malformed)
                        };
                    }
                    Ok(n) => {
                        self.pos = 0;
                        self.end = n;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {
                        return Ok(Token::Yielded)
                    }
                    Err(e) => {
                        return Err(Failure::Errno(e.raw_os_error().unwrap_or(nix::libc::EIO)))
                    }
                }
            }
            let byte = self.bytes[self.pos];
            self.pos += 1;
            if byte.is_ascii_whitespace() {
                if self.digits != 0 {
                    let pid = self.token;
                    self.token = 0;
                    self.digits = 0;
                    return if pid > 0 && pid <= i32::MAX as u32 {
                        Ok(Token::Pid(pid))
                    } else {
                        Err(Failure::Malformed)
                    };
                }
            } else if byte.is_ascii_digit() {
                self.digits += 1;
                if self.digits > 10 {
                    return Err(Failure::Malformed);
                }
                self.token = self
                    .token
                    .checked_mul(10)
                    .and_then(|n| n.checked_add(u32::from(byte - b'0')))
                    .ok_or(Failure::Malformed)?;
            } else {
                return Err(Failure::Malformed);
            }
        }
        Ok(Token::Yielded)
    }
}
struct Pending {
    pid: u32,
    fd: OwnedFd,
    process: Option<RetainedProcess>,
    proved: bool,
}
#[must_use = "retain adopted direct-child ownership until actual physical completion"]
pub(crate) struct Adoption {
    helper: u32,
    census: Option<Census>,
    pending: Option<Pending>,
    lost: bool,
    complete: bool,
    failed: bool,
}
impl Adoption {
    pub(crate) fn new(proof: QualifiedHelper) -> Self {
        let helper = proof.pid;
        Self {
            helper,
            census: None,
            pending: None,
            lost: false,
            complete: false,
            failed: false,
        }
    }
    pub(crate) fn failed(&self) -> bool {
        self.failed
    }
    fn unknown(&mut self) -> Progress {
        self.failed = true;
        Progress::Unknown
    }
    pub(crate) fn step(&mut self, ops: &mut impl AdoptionOps, roots: &mut impl Roots) -> Progress {
        if self.complete {
            return Progress::Complete;
        }
        if self.lost {
            return Progress::Unknown;
        }
        if roots.state() == RootState::Unknown {
            self.lost = true;
            return self.unknown();
        }
        if self.pending.is_some() {
            return self.progress_child(ops);
        }
        if self.census.is_none() {
            let reader = match ops.census() {
                Ok(reader) => reader,
                Err(_) => return self.unknown(),
            };
            self.census = Some(Census {
                reader,
                bytes: [0; 4096],
                pos: 0,
                end: 0,
                token: 0,
                digits: 0,
                roots_settled: roots.state() == RootState::Settled,
            });
        }
        match self.census.as_mut().unwrap().next() {
            Ok(Token::Yielded) => Progress::Pending,
            Err(_) => {
                self.census = None;
                self.unknown()
            }
            Ok(Token::Pid(pid)) => match roots.classify(pid) {
                Reservation::Reserved => Progress::Pending,
                Reservation::Unknown => {
                    self.lost = true;
                    self.unknown()
                }
                Reservation::Other => {
                    // Caller cannot advance/reap registered roots during this
                    // synchronous acquisition. No signal authority exists yet.
                    let fd = match ops.open_child(pid) {
                        Ok(fd) => fd,
                        Err(Failure::Errno(nix::libc::ENOENT | nix::libc::ESRCH)) => {
                            // No exact child was acquired. A previously buffered
                            // root number can disappear after its owner reaps it.
                            // Retry discovery; only fresh census + ECHILD settle.
                            self.census = None;
                            return Progress::Pending;
                        }
                        Err(_) => {
                            self.census = None;
                            return self.unknown();
                        }
                    };
                    self.pending = Some(Pending {
                        pid,
                        fd,
                        process: None,
                        proved: false,
                    });
                    self.census = None;
                    self.acquire(ops)
                }
            },
            Ok(Token::End) => {
                let fresh = self.census.take().unwrap().roots_settled
                    && roots.state() == RootState::Settled;
                if !fresh {
                    return Progress::Pending;
                }
                match ops.no_children() {
                    Ok(Empty::Yes) => {
                        self.complete = true;
                        Progress::Complete
                    }
                    Ok(Empty::No | Empty::Yielded) => Progress::Pending,
                    Err(_) => self.unknown(),
                }
            }
        }
    }
    fn acquire(&mut self, ops: &mut impl AdoptionOps) -> Progress {
        let pending = self.pending.as_mut().unwrap();
        let status = match ops.status(&pending.fd) {
            Ok(bytes) => bytes,
            Err(Failure::Errno(nix::libc::ENOENT | nix::libc::ESRCH)) => {
                // This is still an unproved candidate, not reserved wait
                // custody. Its anchored entry may disappear before validation.
                // Refresh only; a fresh census + ECHILD must prove completion.
                self.pending = None;
                self.census = None;
                return Progress::Pending;
            }
            Err(_) => return self.unknown(),
        };
        match direct_child(&status, pending.pid, self.helper) {
            Ok(true) => {}
            Ok(false) => {
                // A buffered old root number can now name an unrelated process.
                // Positive incompatible identity grants no child custody. Drop
                // only that unowned fd and require a fresh census + ECHILD.
                // Ordinary unowned PID reuse is not a cleanup failure.
                self.pending = None;
                self.census = None;
                return Progress::Pending;
            }
            Err(_) => return self.unknown(),
        }
        match ops.observe_child(pending.pid) {
            Ok(Observation::Yielded) => return Progress::Pending,
            Err(_) => {
                self.lost = true;
                return self.unknown();
            }
            Ok(_) => {}
        }
        // Unique PID/TGID/PPid plus actual WNOWAIT eligibility establishes
        // exclusively reserved child custody, not any session membership.
        pending.proved = true;
        Progress::Pending
    }
    fn progress_child(&mut self, ops: &mut impl AdoptionOps) -> Progress {
        if !self.pending.as_ref().unwrap().proved {
            return self.acquire(ops);
        }
        let pid = self.pending.as_ref().unwrap().pid;
        match ops.observe_child(pid) {
            Ok(Observation::Yielded) => Progress::Pending,
            Err(_) => {
                self.lost = true;
                self.unknown()
            }
            Ok(Observation::Exited(_)) => match ops.reap_child(pid) {
                Ok(Reaped::Exited(_)) => {
                    // No old census survives a consuming wait. A fresh one must
                    // begin on the NEXT pass after all prior captured children.
                    self.pending = None;
                    self.census = None;
                    Progress::Pending
                }
                Ok(Reaped::Yielded) => Progress::Pending,
                Err(_) => {
                    self.lost = true;
                    self.unknown()
                }
            },
            Ok(Observation::Running) => {
                let pending = self.pending.as_mut().unwrap();
                // Retain the same exact fd. Cloning is fallible; an error
                // leaves the original child+descriptor owned and Unknown.
                if pending.process.is_none() {
                    let fd = match pending.fd.try_clone() {
                        Ok(fd) => fd,
                        Err(_) => return self.unknown(),
                    };
                    pending.process = Some(RetainedProcess { fd, exited: false });
                }
                match pending
                    .process
                    .as_mut()
                    .unwrap()
                    .stop(ops, nix::libc::SIGKILL)
                {
                    super::Evidence::Unknown => self.unknown(),
                    _ => Progress::Pending,
                }
            }
        }
    }
}
fn direct_child(bytes: &[u8], pid: u32, helper: u32) -> Result<bool, Failure> {
    if !validate_tgid(bytes, pid)? {
        return Ok(false);
    }
    let mut parents = bytes
        .split_inclusive(|b| *b == b'\n')
        .filter(|line| line.ends_with(b"\n"))
        .filter_map(|line| line.strip_prefix(b"PPid:"));
    let parent = parents.next().ok_or(Failure::Malformed)?.trim_ascii();
    let parent = u32::try_from(super::positive_number(parent)?).map_err(|_| Failure::Malformed)?;
    if parents.next().is_some() {
        return Err(Failure::Malformed);
    }
    Ok(parent == helper)
}

#[cfg(test)]
mod tests;

pub(crate) trait QualificationOps {
    fn ids(&mut self) -> Result<(u32, u32), Failure>;
    fn single_thread(&mut self) -> Result<bool, Failure>;
    fn children_empty(&mut self) -> Result<bool, Failure>;
    fn no_children(&mut self) -> Result<Empty, Failure>;
    fn set_subreaper(&mut self) -> Result<(), Failure>;
    fn get_subreaper(&mut self) -> Result<bool, Failure>;
}
pub(crate) struct QualifiedHelper {
    pid: u32,
}
pub(crate) fn qualify(ops: &mut impl QualificationOps) -> Result<QualifiedHelper, Failure> {
    let (pid, tid) = ops.ids()?;
    if pid == 0
        || pid > i32::MAX as u32
        || tid != pid
        || !ops.single_thread()?
        || !ops.children_empty()?
        || ops.no_children()? != Empty::Yes
    {
        return Err(Failure::Malformed);
    }
    ops.set_subreaper()?;
    if !ops.get_subreaper()? {
        return Err(Failure::Malformed);
    }
    Ok(QualifiedHelper { pid })
}

pub(crate) mod native;
