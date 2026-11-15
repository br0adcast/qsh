//! Fixed private child. It never creates host evidence, descendants or FD exports.
use super::{
    record::{self, LaunchDeadline, SetupRecord},
    MARKER,
};
use crate::session_owner::local_channel::{self, launch, AdmissionError};
use nix::libc;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::sync::atomic::{AtomicBool, Ordering};

/// Only the checked fixed-descriptor entry can construct this capability.
pub(in crate::session_owner) struct ClaimedFrontend {
    fd: OwnedFd,
    record: SetupRecord,
}
impl ClaimedFrontend {
    pub(in crate::session_owner) fn into_parts(self) -> (OwnedFd, SetupRecord) {
        (self.fd, self.record)
    }
}
struct FixedFd(Option<OwnedFd>);
impl FixedFd {
    fn fd(&self) -> &OwnedFd {
        self.0.as_ref().unwrap()
    }
    fn close(&mut self) -> io::Result<()> {
        let Some(fd) = self.0.take() else {
            return Ok(());
        };
        // Invalidate before one close. EINTR never permits numeric retry.
        if unsafe { libc::close(fd.into_raw_fd()) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}
impl Drop for FixedFd {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn error(_: AdmissionError) -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "private frontend admission refused",
    )
}

pub(super) fn recognizes(args: &[OsString]) -> Option<io::Result<()>> {
    if args.first().map(OsString::as_os_str) != Some(OsStr::new(MARKER)) {
        return None;
    }
    Some(if args.len() == 1 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "private frontend entry takes no arguments",
        ))
    })
}
pub(crate) fn entry(args: &[OsString]) -> Option<io::Result<()>> {
    let recognized = recognizes(args)?;
    Some(recognized.and_then(|()| run()))
}
fn claim(raw: i32) -> io::Result<OwnedFd> {
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    if unsafe { libc::fcntl(raw, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        let mut owned = FixedFd(Some(fd));
        let _ = owned.close();
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}
fn run() -> io::Result<()> {
    run_inner(
        #[cfg(test)]
        None,
    )
}
#[cfg(test)]
pub(super) fn fixture_entry(mode: &str) -> io::Result<()> {
    run_inner(Some(mode))
}
fn run_inner(#[cfg(test)] fixture: Option<&str>) -> io::Result<()> {
    let uid = unsafe { libc::geteuid() };
    // This branch precedes even inspection of fixed descriptor numbers.
    if uid == 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "personal frontend requires non-root",
        ));
    }
    if std::env::var_os(crate::service_stage::LAUNCH_ENV).is_some()
        || std::env::var_os(crate::handover::HANDOVER_FD_ENV).is_some()
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "reserved launch environment",
        ));
    }
    static CLAIMED: AtomicBool = AtomicBool::new(false);
    if CLAIMED.swap(true, Ordering::AcqRel) {
        return Err(error(AdmissionError::Refused));
    }
    let mut setup = FixedFd(Some(claim(3)?));
    let mut admission = FixedFd(Some(claim(4)?));
    launch::validate_personal_fd(setup.fd(), uid).map_err(error)?;
    launch::validate_personal_fd(admission.fd(), uid).map_err(error)?;
    let mut a: libc::stat = unsafe { std::mem::zeroed() };
    let mut b: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(3, &mut a) } != 0
        || unsafe { libc::fstat(4, &mut b) } != 0
        || (a.st_ino != 0 && a.st_dev == b.st_dev && a.st_ino == b.st_ino)
    {
        return Err(error(AdmissionError::Refused));
    }
    let mut bytes = [0; record::RECORD_LEN];
    // Before byte96 only the retained parent's original deadline/EOF can bound
    // setup. No new child duration or per-byte refresh is invented here.
    let mut used = 0;
    while used < 96 {
        match launch::read(setup.fd(), &mut bytes[used..96]) {
            Ok(0) => return Err(error(AdmissionError::Refused)),
            Ok(n) => used += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => wait_prefix(setup.fd())?,
            Err(e) => return Err(e),
        }
    }
    let absolute =
        SetupRecord::prefix_deadline(&bytes[..96], uid, record::monotonic_now().map_err(error)?)
            .map_err(error)?;
    let deadline = LaunchDeadline::child_local(absolute).map_err(error)?;
    launch::read_setup(setup.fd(), &mut bytes[96..], deadline).map_err(error)?;
    let record =
        SetupRecord::decode(&bytes, uid, record::monotonic_now().map_err(error)?).map_err(error)?;
    let claimed = ClaimedFrontend {
        fd: admission.0.take().unwrap(),
        record,
    };
    let expected = launch::restore_frontend(claimed).map_err(error)?;
    #[cfg(test)]
    let mut coordination = if let Some(mode) = fixture {
        use std::io::{Read, Write};
        let mut socket = std::os::unix::net::UnixStream::connect(
            std::env::var_os("QSH_LAUNCH_FIXTURE_COORD")
                .ok_or_else(|| error(AdmissionError::Refused))?,
        )?;
        socket.set_read_timeout(Some(std::time::Duration::from_secs(10)))?;
        socket.set_write_timeout(Some(std::time::Duration::from_secs(10)))?;
        if mode == "late" {
            socket.write_all(b"R")?;
            let mut go = [0; 1];
            socket.read_exact(&mut go)?;
            if go != *b"G" {
                return Err(error(AdmissionError::Refused));
            }
        }
        Some(socket)
    } else {
        None
    };

    let admitted = local_channel::admit_channel(expected, deadline).map_err(error)?;
    if record::monotonic_now().map_err(error)? >= absolute {
        return Err(error(AdmissionError::Deadline));
    }
    #[cfg(test)]
    if let Some(socket) = coordination.as_mut() {
        use std::io::{Read, Write};
        socket.write_all(b"A")?;
        if fixture == Some("eof-live") {
            if unsafe { libc::shutdown(setup.fd().as_raw_fd(), libc::SHUT_WR) } != 0 {
                return Err(io::Error::last_os_error());
            }
            socket.write_all(b"E")?;
            let mut go = [0; 1];
            socket.read_exact(&mut go)?;
            if go != *b"G" {
                return Err(error(AdmissionError::Refused));
            }
            drop(admitted);
            return setup.close();
        }
        if fixture == Some("exit") {
            drop(admitted);
            return setup.close();
        }
    }
    // The fixed entry does not half-close, fork or pass a descriptor. Extra
    // setup bytes refuse; only physical EOF ends this otherwise dormant child.
    let result = loop {
        let mut extra = [0; 1];
        match launch::read(setup.fd(), &mut extra) {
            Ok(0) => break Ok(()),
            Ok(_) => break Err(error(AdmissionError::Refused)),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => wait_prefix(setup.fd())?,
            Err(e) => break Err(e),
        }
    };
    drop(admitted);
    let closed = setup.close();
    result.and(closed)
}
fn wait_prefix(fd: &OwnedFd) -> io::Result<()> {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut poll, 1, -1) } >= 0 {
        Ok(())
    } else {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            Ok(())
        } else {
            Err(error)
        }
    }
}
