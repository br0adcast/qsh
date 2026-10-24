//! The personal daemon's fixed Unix detachment sequence, before any threads exist.
use nix::libc;
use std::io;

pub(crate) enum Outcome {
    Parent(io::Result<i32>),
    Child(io::Result<()>),
}

/// Detach the personal daemon, retaining its already-bound descriptors.
///
/// # Safety
/// The caller must be single-threaded, before logger/runtime/background worker
/// initialization. No other waiter or signal handler may reap the first child.
/// No Rust-owned handle may refer to descriptors 0, 1 or 2: redirection replaces
/// those descriptors, so an inherited owner could later close the replacement.
/// The binary relies on Rust Unix startup initializing missing standard fds and
/// its synchronous startup leaving them open while acquiring resource owners.
/// The final child continues Rust execution; this is not safe in a libtest worker.
pub(crate) unsafe fn detach() -> Outcome {
    // SAFETY: the caller establishes the same contract for the fixed directory.
    unsafe { detach_at(c"/") }
}

/// The directory seam lets an owned subprocess exercise an early setup failure.
/// Production always uses `detach` with `/`.
///
/// # Safety
/// The same single-threaded and exclusive-child-wait contract as `detach` applies.
pub(crate) unsafe fn detach_at(directory: &std::ffi::CStr) -> Outcome {
    // SAFETY: the caller establishes the single-threaded fork contract above.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Outcome::Parent(Err(io::Error::last_os_error()));
    }
    if pid > 0 {
        return Outcome::Parent(wait_first_child(pid));
    }
    Outcome::Child(detach_child(directory))
}

fn detach_child(directory: &std::ffi::CStr) -> io::Result<()> {
    // SAFETY: the constant is a terminated path; only this single-threaded child
    // changes its own cwd/session/umask. The second fork has the same contract.
    unsafe {
        cvt(libc::chdir(directory.as_ptr()))?;
        cvt(libc::setsid())?;
        libc::umask(0o027);
        let pid = libc::fork();
        if pid < 0 {
            return Err(io::Error::last_os_error());
        }
        if pid > 0 {
            // The intermediate must not run inherited publication/lock destructors.
            libc::_exit(0);
        }
    }
    redirect_standard_streams()
}

fn cvt(value: i32) -> io::Result<i32> {
    if value < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(value)
    }
}

pub(crate) fn wait_first_child(pid: libc::pid_t) -> io::Result<i32> {
    if pid <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an owned positive child pid",
        ));
    }
    wait_with(pid, |wanted| {
        let mut status = 0;
        // SAFETY: detach owns this direct child exclusively; status is valid storage.
        let returned = unsafe { libc::waitpid(wanted, &mut status, 0) };
        cvt(returned).map(|returned| (returned, status))
    })
}

fn wait_with(
    pid: libc::pid_t,
    mut wait: impl FnMut(libc::pid_t) -> io::Result<(libc::pid_t, i32)>,
) -> io::Result<i32> {
    loop {
        let (returned, status) = match wait(pid) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => other?,
        };
        if returned != pid {
            return Err(io::Error::other("wait returned a different child"));
        }
        if libc::WIFEXITED(status) {
            return Ok(libc::WEXITSTATUS(status));
        }
        if libc::WIFSIGNALED(status) {
            return Ok(128 + libc::WTERMSIG(status));
        }
        return Err(io::Error::other(
            "child did not exit or terminate by signal",
        ));
    }
}

fn redirect_standard_streams() -> io::Result<()> {
    let fd = loop {
        // SAFETY: terminated constant path, open returns a new process-owned fd.
        let opened = unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDWR) };
        match cvt(opened) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            other => break other?,
        }
    };
    let result: io::Result<()> = (|| {
        for target in 0..=2 {
            loop {
                // SAFETY: fd is live; target is this child's standard descriptor.
                let duplicated = unsafe { libc::dup2(fd, target) };
                match cvt(duplicated) {
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    other => {
                        other?;
                        break;
                    }
                }
            }
        }
        Ok(())
    })();
    if fd > 2 {
        // SAFETY: the spare is ours. Never retry close(EINTR), whose ownership
        // semantics differ across Unix systems; never close a standard-fd alias.
        let closed = unsafe { libc::close(fd) };
        result?;
        cvt(closed)?;
    } else {
        result?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn interrupted_wait_retries_the_same_child_and_decodes_its_exit() {
        let mut calls = 0;
        assert_eq!(
            super::wait_with(42, |pid| {
                assert_eq!(pid, 42);
                calls += 1;
                if calls == 1 {
                    Err(std::io::Error::from_raw_os_error(nix::libc::EINTR))
                } else {
                    Ok((pid, 7 << 8))
                }
            })
            .unwrap(),
            7
        );
        assert_eq!(calls, 2);
    }
    #[test]
    fn wait_errors_and_unexpected_status_do_not_prove_success() {
        assert_eq!(
            super::wait_with(42, |_| Err(std::io::Error::from_raw_os_error(
                nix::libc::ECHILD
            )))
            .unwrap_err()
            .raw_os_error(),
            Some(nix::libc::ECHILD)
        );
        assert!(super::wait_with(42, |_| Ok((43, 0))).is_err());
        assert!(super::wait_with(42, |_| Ok((42, 0x7f))).is_err());
    }
}
