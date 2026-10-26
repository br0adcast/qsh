//! Owned ordinary-thread notifications for keyboard input waits.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
struct Pair {
    read: OwnedFd,
    writer: Mutex<Option<OwnedFd>>,
    #[cfg(test)]
    fail_notify: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    before_poll: Mutex<Option<PollHook>>,
}
#[cfg(test)]
#[derive(Debug)]
struct PollHook {
    entered: std::sync::mpsc::Sender<()>,
    resume: std::sync::mpsc::Receiver<()>,
}

/// Clones retain the read end too, so late producers cannot encounter SIGPIPE
/// or a descriptor reused by another session. Only ordinary threads may notify.
#[derive(Clone, Debug)]
pub struct WakeSender {
    inner: Arc<Pair>,
}

/// One owner polls and drains the read side.
pub struct WakeReader {
    inner: Arc<Pair>,
}

pub fn pair() -> io::Result<(WakeReader, WakeSender)> {
    let mut fds = [-1; 2];
    #[cfg(any(target_os = "linux", target_os = "android"))]
    let result = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) };
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    let result = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if result < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful pipe call returned two fresh descriptors.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };
    // macOS has no pipe2. These checked flags are non-atomic with respect to
    // a concurrent local exec, as with existing CLI pipe setup. Current CLI
    // production recovery uses in-process SSH, not a local child process.
    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    for fd in [&read, &write] {
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
    let inner = Arc::new(Pair {
        read,
        writer: Mutex::new(Some(write)),
        #[cfg(test)]
        fail_notify: std::sync::atomic::AtomicBool::new(false),
        #[cfg(test)]
        before_poll: Mutex::new(None),
    });
    Ok((
        WakeReader {
            inner: inner.clone(),
        },
        WakeSender { inner },
    ))
}

fn closed() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "keyboard wake channel closed")
}

impl WakeSender {
    pub fn notify(&self) -> io::Result<()> {
        let mut writer = self.inner.writer.lock().unwrap_or_else(|e| e.into_inner());
        let Some(fd) = writer.as_ref() else {
            return Err(closed());
        };
        loop {
            #[cfg(test)]
            let injected = self
                .inner
                .fail_notify
                .swap(false, std::sync::atomic::Ordering::SeqCst);
            #[cfg(not(test))]
            let injected = false;
            let result = if injected {
                -1
            } else {
                // SAFETY: writer remains owned under the lock, and read is retained.
                unsafe { libc::write(fd.as_raw_fd(), b"x".as_ptr().cast(), 1) }
            };
            if result == 1 {
                return Ok(());
            }
            let error = if injected {
                io::Error::from_raw_os_error(libc::ENOMEM)
            } else {
                io::Error::last_os_error()
            };
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => {
                    // No other producer owns a duplicated writer. Closing it
                    // under custody wakes the reader with HUP, even on failure.
                    drop(writer.take());
                    return Err(error);
                }
            }
        }
    }

    #[cfg(test)]
    pub fn fail_next_notify(&self) {
        self.inner
            .fail_notify
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(test)]
    pub(crate) fn arm_poll(&self) -> (std::sync::mpsc::Receiver<()>, std::sync::mpsc::Sender<()>) {
        let (entered, observed) = std::sync::mpsc::channel();
        let (resume, resumed) = std::sync::mpsc::channel();
        *self.inner.before_poll.lock().unwrap() = Some(PollHook {
            entered,
            resume: resumed,
        });
        (observed, resume)
    }

    /// Only used while the fixture has paused the sole reader before poll.
    #[cfg(test)]
    pub(crate) fn drain_paused_reader(&self) {
        WakeReader {
            inner: self.inner.clone(),
        }
        .drain()
        .unwrap();
    }

    #[cfg(test)]
    pub(crate) fn close_for_test(&self) {
        drop(self.inner.writer.lock().unwrap().take());
    }

    #[cfg(test)]
    fn writer_fd(&self) -> RawFd {
        self.inner
            .writer
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .as_raw_fd()
    }
}

impl AsRawFd for WakeReader {
    fn as_raw_fd(&self) -> RawFd {
        self.inner.read.as_raw_fd()
    }
}

impl WakeReader {
    pub fn drain(&mut self) -> io::Result<()> {
        let mut bytes = [0u8; 256];
        loop {
            let n = unsafe { libc::read(self.as_raw_fd(), bytes.as_mut_ptr().cast(), bytes.len()) };
            if n > 0 {
                continue;
            }
            if n == 0 {
                return Err(closed());
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => return Ok(()),
                _ => return Err(error),
            }
        }
    }

    /// Returns stdin readiness only; a notification never authorizes a read.
    pub fn poll_stdin(&self, stdin: Option<RawFd>) -> io::Result<bool> {
        #[cfg(test)]
        if let Some(hook) = self.inner.before_poll.lock().unwrap().take() {
            let _ = hook.entered.send(());
            hook.resume
                .recv_timeout(std::time::Duration::from_secs(3))
                .map_err(|_| io::Error::other("fixture poll barrier was not released"))?;
        }
        let mut fds = [
            libc::pollfd {
                fd: self.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: stdin.unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, -1) };
        if n < 0 {
            let error = io::Error::last_os_error();
            return if error.kind() == io::ErrorKind::Interrupted {
                Ok(false)
            } else {
                Err(error)
            };
        }
        if fds[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(closed());
        }
        if fds[1].revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err(io::Error::other("keyboard descriptor poll failed"));
        }
        Ok(fds[1].revents & (libc::POLLIN | libc::POLLHUP) != 0)
    }

    #[cfg(test)]
    pub(crate) fn ready_now(&self) -> bool {
        let mut fd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe { libc::poll(&mut fd, 1, 0) > 0 }
    }

    #[cfg(test)]
    fn wait(&self) -> io::Result<()> {
        self.poll_stdin(None).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn input_wake_coalesces_and_retains_owned_endpoints() {
        let (mut reader, sender) = pair().unwrap();
        sender.notify().unwrap();
        reader.wait().unwrap();
        reader.drain().unwrap();
        for _ in 0..100_000 {
            sender.notify().unwrap();
        }
        reader.wait().unwrap();
        reader.drain().unwrap();
        for fd in [reader.as_raw_fd(), sender.writer_fd()] {
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
            assert_ne!(
                unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_NONBLOCK,
                0
            );
        }
        drop(reader);
        sender.notify().unwrap();
    }

    #[test]
    fn input_wake_hard_failure_closes_writer_and_releases_wait() {
        let (mut reader, sender) = pair().unwrap();
        sender.fail_next_notify();
        assert!(sender.notify().is_err());
        assert!(reader.wait().is_err());
        assert!(reader.drain().is_err());
        assert!(sender.notify().is_err());
        assert!(sender.inner.writer.lock().unwrap().is_none());
    }
    #[test]
    fn input_wake_writer_custody_and_late_failure_never_touch_foreign_file() {
        let (reader, sender) = pair().unwrap();
        let writer = sender.inner.writer.lock().unwrap();
        let original = writer.as_ref().unwrap().as_raw_fd();
        let late = sender.clone();
        let (started, observed) = std::sync::mpsc::channel();
        let owner = std::thread::spawn(move || {
            started.send(()).unwrap();
            late.notify()
        });
        observed
            .recv_timeout(std::time::Duration::from_secs(3))
            .unwrap();
        drop(reader);
        assert!(unsafe { libc::fcntl(original, libc::F_GETFD) } >= 0);
        drop(writer);
        owner.join().unwrap().unwrap();
        sender.fail_next_notify();
        assert!(sender.notify().is_err());
        // A new unrelated file may reuse the closed writer number. Late
        // notification must fail without borrowing any raw closed descriptor.
        let foreign = tempfile::tempfile().unwrap();
        assert!(sender.notify().is_err());
        assert_eq!(foreign.metadata().unwrap().len(), 0);
        assert!(unsafe { libc::fcntl(foreign.as_raw_fd(), libc::F_GETFD) } >= 0);
    }
}
