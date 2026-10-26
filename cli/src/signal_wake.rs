//! Process-lifetime signal notifications; handlers never own or close an fd.
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::OnceLock;

struct Pair {
    read: OwnedFd,
    write: OwnedFd,
}
impl Pair {
    fn new() -> io::Result<Self> {
        let mut fds = [-1; 2];
        #[cfg(any(target_os = "linux", target_os = "android"))]
        let kind = libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC;
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        let kind = libc::SOCK_STREAM;
        if unsafe { libc::socketpair(libc::AF_UNIX, kind, 0, fds.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let pair = Self {
            read: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        };
        #[cfg(not(any(target_os = "linux", target_os = "android")))]
        for fd in [&pair.read, &pair.write] {
            for (get, set, flag) in [
                (libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK),
                (libc::F_GETFD, libc::F_SETFD, libc::FD_CLOEXEC),
            ] {
                let old = unsafe { libc::fcntl(fd.as_raw_fd(), get) };
                if old < 0 || unsafe { libc::fcntl(fd.as_raw_fd(), set, old | flag) } < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        #[cfg(target_vendor = "apple")]
        {
            let yes: libc::c_int = 1;
            if unsafe {
                libc::setsockopt(
                    pair.write.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_NOSIGPIPE,
                    (&yes as *const libc::c_int).cast(),
                    std::mem::size_of_val(&yes) as libc::socklen_t,
                )
            } < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(pair)
    }
}
static PAIR: OnceLock<Result<Pair, i32>> = OnceLock::new();
static WRITER: AtomicI32 = AtomicI32::new(-1);
static FAILURE: AtomicI32 = AtomicI32::new(0);
static SHUTDOWN_ERROR: AtomicI32 = AtomicI32::new(0);
pub(crate) fn initialize() -> Result<(), nix::Error> {
    match PAIR.get_or_init(|| Pair::new().map_err(|e| e.raw_os_error().unwrap_or(libc::EIO))) {
        Ok(pair) => {
            WRITER.store(pair.write.as_raw_fd(), Ordering::Release);
            Ok(())
        }
        Err(error) => Err(nix::Error::from_raw(*error)),
    }
}
pub(crate) fn read_fd() -> io::Result<RawFd> {
    match PAIR.get() {
        Some(Ok(pair)) => Ok(pair.read.as_raw_fd()),
        _ => Err(io::Error::other("signal notifications not initialized")),
    }
}
pub(crate) fn notify() {
    let fd = WRITER.load(Ordering::Acquire);
    // RawMode is also a library API used without the CLI's common install.
    // The actual CLI initializes before any notifying handler is installed.
    if fd >= 0 {
        notify_raw(fd, &FAILURE, &SHUTDOWN_ERROR, 0);
    }
}
fn notify_raw(fd: RawFd, failure: &AtomicI32, shutdown_error: &AtomicI32, mut injected: i32) {
    let saved = nix::errno::Errno::last_raw();
    if failure.load(Ordering::Acquire) == 0 {
        loop {
            #[cfg(target_vendor = "apple")]
            let flags = 0;
            #[cfg(not(target_vendor = "apple"))]
            let flags = libc::MSG_NOSIGNAL;
            let n = if injected != 0 {
                nix::errno::Errno::set_raw(std::mem::take(&mut injected));
                -1
            } else {
                unsafe { libc::send(fd, b"x".as_ptr().cast(), 1, flags) }
            };
            if n == 1 {
                nix::errno::Errno::set_raw(saved);
                return;
            }
            let error = if n == 0 {
                libc::EIO
            } else {
                nix::errno::Errno::last_raw()
            };
            if error == libc::EINTR {
                continue;
            }
            if error == libc::EAGAIN || error == libc::EWOULDBLOCK {
                nix::errno::Errno::set_raw(saved);
                return;
            }
            // First failure is authoritative. Any failed handler may half-close;
            // delivery never depends on one paused exclusive shutdown owner.
            let _ = failure.compare_exchange(0, error, Ordering::AcqRel, Ordering::Acquire);
            break;
        }
    }
    if unsafe { libc::shutdown(fd, libc::SHUT_WR) } < 0 {
        shutdown_error.store(nix::errno::Errno::last_raw(), Ordering::Release);
    }
    nix::errno::Errno::set_raw(saved);
}

pub(crate) fn failure() -> Option<(i32, i32)> {
    let error = FAILURE.load(Ordering::Acquire);
    (error != 0).then(|| (error, SHUTDOWN_ERROR.load(Ordering::Acquire)))
}
pub(crate) fn drain() -> io::Result<()> {
    drain_fd(read_fd()?)?;
    if failure().is_some() {
        return Err(io::Error::other("signal notification failed"));
    }
    Ok(())
}
fn drain_fd(fd: RawFd) -> io::Result<()> {
    drain_fd_with(fd, || {})
}
fn drain_fd_with(fd: RawFd, mut before_read: impl FnMut()) -> io::Result<()> {
    let mut bytes = [0u8; 256];
    for _ in 0..8 {
        before_read();
        let n = unsafe { libc::recv(fd, bytes.as_mut_ptr().cast(), bytes.len(), 0) };
        if n > 0 {
            continue;
        }
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "signal notification EOF",
            ));
        }
        let error = io::Error::last_os_error();
        match error.kind() {
            io::ErrorKind::Interrupted => return Ok(()),
            io::ErrorKind::WouldBlock => return Ok(()),
            _ => return Err(error),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn ready(fd: RawFd) -> bool {
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        (unsafe { libc::poll(&mut poll, 1, 0) }) == 1
    }
    #[test]
    fn ui_wait_signal_common_handler_publishes_flag_and_readability() {
        let _serial = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::signals::install().unwrap();
        let _ = crate::signals::take_pending();
        drain().unwrap();
        assert!(
            !ready(read_fd().unwrap()),
            "old wake bytes cannot satisfy this control"
        );
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGWINCH).unwrap();
        assert!(crate::signals::take_pending().resized);
        assert!(
            ready(read_fd().unwrap()),
            "flag-only signal cannot wake an indefinite UI wait"
        );
        drain().unwrap();
    }
    #[test]
    fn ui_wait_signal_hard_send_failure_half_closes_without_fd_reuse() {
        let pair = Pair::new().unwrap();
        let failed = AtomicI32::new(0);
        notify_raw(
            pair.write.as_raw_fd(),
            &failed,
            &AtomicI32::new(0),
            libc::ENOMEM,
        );
        assert!(
            ready(pair.read.as_raw_fd()),
            "hard send failure must expose readable EOF"
        );
        assert_eq!(failed.load(Ordering::Acquire), libc::ENOMEM);
        let mut byte = 0u8;
        assert_eq!(
            unsafe { libc::recv(pair.read.as_raw_fd(), (&mut byte as *mut u8).cast(), 1, 0) },
            0
        );
        assert!(unsafe { libc::fcntl(pair.write.as_raw_fd(), libc::F_GETFD) } >= 0);
    }
    #[test]
    fn ui_wait_signal_eintr_and_full_buffer_preserve_errno_and_coalesce() {
        let pair = Pair::new().unwrap();
        let failed = AtomicI32::new(0);
        let shutdown = AtomicI32::new(0);
        nix::errno::Errno::set_raw(libc::EDOM);
        notify_raw(pair.write.as_raw_fd(), &failed, &shutdown, libc::EINTR);
        assert_eq!(nix::errno::Errno::last_raw(), libc::EDOM);
        assert!(ready(pair.read.as_raw_fd()));
        let mut full = false;
        for _ in 0..65536 {
            #[cfg(target_vendor = "apple")]
            let flags = 0;
            #[cfg(not(target_vendor = "apple"))]
            let flags = libc::MSG_NOSIGNAL;
            let n = unsafe { libc::send(pair.write.as_raw_fd(), b"x".as_ptr().cast(), 1, flags) };
            if n < 0 {
                assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
                full = true;
                break;
            }
        }
        assert!(full, "the fixture must actually reach socket capacity");
        nix::errno::Errno::set_raw(libc::EDOM);
        notify_raw(pair.write.as_raw_fd(), &failed, &shutdown, libc::EINTR);
        assert_eq!(nix::errno::Errno::last_raw(), libc::EDOM);
        assert_eq!(failed.load(Ordering::Acquire), 0);
        drain_fd(pair.read.as_raw_fd()).unwrap();
        assert!(!ready(pair.read.as_raw_fd()));
    }
    #[test]
    fn ui_wait_signal_buffered_bytes_precede_persistent_eof() {
        let pair = Pair::new().unwrap();
        let failed = AtomicI32::new(0);
        let shutdown = AtomicI32::new(0);
        notify_raw(pair.write.as_raw_fd(), &failed, &shutdown, 0);
        nix::errno::Errno::set_raw(libc::EDOM);
        notify_raw(pair.write.as_raw_fd(), &failed, &shutdown, libc::ENOMEM);
        assert_eq!(nix::errno::Errno::last_raw(), libc::EDOM);
        let mut b = [0u8; 1];
        assert_eq!(
            unsafe { libc::recv(pair.read.as_raw_fd(), b.as_mut_ptr().cast(), 1, 0) },
            1
        );
        assert_eq!(b, [b'x']);
        assert_eq!(
            unsafe { libc::recv(pair.read.as_raw_fd(), b.as_mut_ptr().cast(), 1, 0) },
            0
        );
        notify_raw(pair.write.as_raw_fd(), &failed, &shutdown, 0);
        assert!(ready(pair.read.as_raw_fd()));
        assert_eq!(shutdown.load(Ordering::Acquire), 0);
        assert!(drain_fd(pair.read.as_raw_fd()).is_err());
        assert!(unsafe { libc::fcntl(pair.write.as_raw_fd(), libc::F_GETFD) } >= 0);
    }
    #[test]
    fn ui_wait_signal_other_thread_wakes_owner_and_preserves_errno() {
        let _serial = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::signals::install().unwrap();
        drain().unwrap();
        let _ = crate::signals::take_pending();
        assert!(!ready(read_fd().unwrap()));
        let errno = std::thread::spawn(|| {
            nix::errno::Errno::set_raw(libc::EDOM);
            nix::sys::signal::raise(nix::sys::signal::Signal::SIGWINCH).unwrap();
            nix::errno::Errno::last_raw()
        })
        .join()
        .unwrap();
        assert_eq!(errno, libc::EDOM);
        assert!(ready(read_fd().unwrap()));
        assert!(crate::signals::take_pending().resized);
        drain().unwrap();
    }
    #[test]
    fn ui_wait_signal_reinstall_reuses_fixed_endpoints() {
        let _serial = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        crate::signals::install().unwrap();
        let fd = read_fd().unwrap();
        drain().unwrap();
        assert!(!ready(fd));
        crate::signals::install().unwrap();
        assert_eq!(read_fd().unwrap(), fd);
        nix::sys::signal::raise(nix::sys::signal::Signal::SIGCONT).unwrap();
        assert!(ready(fd));
        assert!(crate::signals::take_pending().resumed);
        drain().unwrap();
    }
    #[test]
    fn ui_wait_signal_continuously_replenished_notifications_have_bounded_drain() {
        let pair = Pair::new().unwrap();
        let mut reads = 0;
        drain_fd_with(pair.read.as_raw_fd(), || {
            reads += 1;
            assert!(
                reads <= 8,
                "signal bytes starved authoritative flag service"
            );
            #[cfg(target_vendor = "apple")]
            let flags = 0;
            #[cfg(not(target_vendor = "apple"))]
            let flags = libc::MSG_NOSIGNAL;
            assert_eq!(
                unsafe {
                    libc::send(
                        pair.write.as_raw_fd(),
                        [b'x'; 512].as_ptr().cast(),
                        512,
                        flags,
                    )
                },
                512
            );
        })
        .unwrap();
        assert_eq!(reads, 8);
        assert!(ready(pair.read.as_raw_fd()));
    }
    fn owned_child(name: &str, body: impl FnOnce()) {
        const FLAG: &str = "QSH_UI_WAIT_SIGNAL_CHILD";
        if std::env::var(FLAG).as_deref() == Ok(name) {
            body();
            return;
        }
        struct OwnedChild {
            child: std::process::Child,
            reaped: bool,
        }
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                if !self.reaped {
                    let _ = self.child.kill();
                }
                let _ = self.child.wait();
            }
        }
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--nocapture"])
            .env(FLAG, name)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut owned = OwnedChild {
            child,
            reaped: false,
        };
        let until = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let status = loop {
            if let Some(status) = owned.child.try_wait().unwrap() {
                owned.reaped = true;
                break status;
            }
            assert!(
                std::time::Instant::now() < until,
                "owned signal child exceeded watchdog"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        };
        let mut stderr = String::new();
        use std::io::Read;
        owned
            .child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut stderr)
            .unwrap();
        assert!(status.success(), "owned signal child failed: {stderr}");
    }

    #[test]
    fn ui_wait_signal_global_failure_survives_reinstall_in_subprocess() {
        owned_child(
            "signal_wake::tests::ui_wait_signal_global_failure_survives_reinstall_in_subprocess",
            || {
                crate::signals::install().unwrap();
                let fd = read_fd().unwrap();
                drain().unwrap();
                notify_raw(
                    WRITER.load(Ordering::Acquire),
                    &FAILURE,
                    &SHUTDOWN_ERROR,
                    libc::ENOMEM,
                );
                assert!(ready(fd));
                assert!(drain().is_err());
                crate::signals::install().unwrap();
                assert_eq!(read_fd().unwrap(), fd);
                assert_eq!(failure(), Some((libc::ENOMEM, 0)));
                assert!(drain().is_err());
            },
        );
    }
    #[test]
    fn ui_wait_signal_partial_install_retains_published_endpoints_in_subprocess() {
        owned_child("signal_wake::tests::ui_wait_signal_partial_install_retains_published_endpoints_in_subprocess", || {
            crate::signals::INSTALL_FAILURE.store(libc::SIGCONT, Ordering::Release);
            assert!(crate::signals::install().is_err());
            let fd = read_fd().unwrap(); assert!(!ready(fd));
            nix::sys::signal::raise(nix::sys::signal::Signal::SIGWINCH).unwrap();
            assert!(ready(fd)); assert!(crate::signals::take_pending().resized);
            drain().unwrap(); crate::signals::install().unwrap(); assert_eq!(read_fd().unwrap(), fd);
        });
    }
}
