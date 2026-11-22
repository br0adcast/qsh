//! Wake a channel's exclusive wait owner when its leader exits, instead of
//! polling it every 20 ms for as long as it lives (#649).
//!
//! The leader is this process's own unreaped child, so a pidfd opened for it
//! right after the spawn names exactly that process until the scope reaps
//! it. A pidfd becomes readable when its process exits and stays readable,
//! so an exit before the watch starts is not missed. Readability is only a
//! wake-up: the owner then observes the leader through the scope as before,
//! and nothing here reaps, signals or decides anything.

use nix::libc;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

pub(super) struct LeaderWatch {
    pidfd: Option<OwnedFd>,
    started: bool,
    task: Option<tokio::task::AbortHandle>,
}

impl LeaderWatch {
    /// A watch on `pid`, the caller's unreaped child. Without a pidfd (a
    /// kernel before 5.3, or a refused open) the owner keeps polling.
    pub(super) fn open(pid: NonZeroU32) -> Self {
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid.get() as libc::pid_t, 0) };
        let pidfd = (raw >= 0).then(|| unsafe { OwnedFd::from_raw_fd(raw as libc::c_int) });
        Self {
            pidfd,
            started: false,
            task: None,
        }
    }

    /// Whether the leader's exit will be notified: a pidfd and a runtime to
    /// watch it on, or a watch that already runs.
    pub(super) fn notifies(&self) -> bool {
        self.started || (self.pidfd.is_some() && tokio::runtime::Handle::try_current().is_ok())
    }

    /// Call `notify` once the leader has exited (or at once if it already
    /// has). Without a runtime, or if the runtime cannot register the pidfd,
    /// a thread blocks on it instead, so a promised notification is never lost.
    pub(super) fn start(&mut self, notify: impl FnOnce() + Send + 'static) {
        let Some(pidfd) = self.pidfd.take() else {
            return;
        };
        self.started = true;
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let task = runtime.spawn(async move {
                    // A copy for the fallback: registration panics on a
                    // runtime without an I/O driver and then drops `pidfd`.
                    let spare = pidfd.try_clone();
                    let registered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        // SAFETY: an `OwnedFd` stays open and names the
                        // same descriptor until the `AsyncFd` drops it.
                        unsafe {
                            tokio::io::unix::AsyncFd::register_with_interest(
                                pidfd,
                                tokio::io::Interest::READABLE,
                            )
                        }
                    }));
                    match registered {
                        Ok(Ok(watched)) => {
                            // Any readiness or error ends the watch: the
                            // owner's observation is what decides.
                            let _ = watched.readable().await;
                            notify();
                        }
                        Ok(Err(error)) => block_then(error.into_parts().0, notify),
                        Err(_) => match spare {
                            Ok(spare) => block_then(spare, notify),
                            Err(_) => notify(),
                        },
                    }
                });
                self.task = Some(task.abort_handle());
            }
            Err(_) => block_then(pidfd, notify),
        }
    }
}

impl Drop for LeaderWatch {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// The fallback: one thread blocks until the pidfd is readable.
fn block_then(pidfd: OwnedFd, notify: impl FnOnce() + Send + 'static) {
    let slot = std::sync::Arc::new(std::sync::Mutex::new(Some(notify)));
    let theirs = slot.clone();
    let spawned = std::thread::Builder::new()
        .name("qshd-leader-watch".into())
        .spawn(move || {
            let mut entry = libc::pollfd {
                fd: pidfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            loop {
                let ready = unsafe { libc::poll(&mut entry, 1, -1) };
                if ready >= 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    break;
                }
            }
            let notify = theirs.lock().unwrap_or_else(|e| e.into_inner()).take();
            if let Some(notify) = notify {
                notify();
            }
        });
    if let Err(error) = spawned {
        // No way left to wait. Wake the owner now: its observation still
        // decides and keeps the leader in custody, but no later wake-up comes.
        log::warn!("leader exit watch unavailable: {error}");
        let notify = slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(notify) = notify {
            notify();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;

    const LIVENESS: Duration = Duration::from_secs(20);

    fn sleeper() -> std::process::Child {
        Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .spawn()
            .expect("sleep")
    }

    fn pid_of(child: &std::process::Child) -> NonZeroU32 {
        NonZeroU32::new(child.id()).unwrap()
    }

    /// Wait for `child` to exit without reaping it, as a scope would leave it.
    fn wait_unreaped(child: &std::process::Child) {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let rc = unsafe {
            libc::waitid(
                libc::P_PID,
                child.id(),
                &mut info,
                libc::WEXITED | libc::WNOWAIT,
            )
        };
        assert_eq!(rc, 0, "waitid: {}", std::io::Error::last_os_error());
    }

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn a_live_leader_wakes_nobody_until_it_exits() {
        let rt = runtime();
        let mut child = sleeper();
        let (tx, rx) = mpsc::channel();
        let _guard = rt.enter();
        let mut watch = LeaderWatch::open(pid_of(&child));
        assert!(
            watch.notifies(),
            "a pidfd and a runtime promise a notification"
        );
        watch.start(move || tx.send(()).unwrap());
        rt.block_on(async {
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
        });
        assert!(
            rx.try_recv().is_err(),
            "a running leader's pidfd cannot be readable"
        );
        child.kill().unwrap();
        wait_unreaped(&child);
        rt.block_on(async {
            tokio::time::timeout(LIVENESS, async {
                while rx.try_recv().is_err() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the exit is notified");
        });
        child.wait().unwrap();
    }

    #[test]
    fn an_exit_before_the_watch_starts_is_still_notified() {
        let rt = runtime();
        let mut child = Command::new("true").spawn().unwrap();
        let _guard = rt.enter();
        let mut watch = LeaderWatch::open(pid_of(&child));
        wait_unreaped(&child);
        let (tx, rx) = mpsc::channel();
        watch.start(move || tx.send(()).unwrap());
        rt.block_on(async {
            tokio::time::timeout(LIVENESS, async {
                while rx.try_recv().is_err() {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("an earlier exit is sticky");
        });
        child.wait().unwrap();
    }

    #[test]
    fn without_a_runtime_a_thread_waits_instead() {
        let mut child = sleeper();
        let mut watch = LeaderWatch::open(pid_of(&child));
        assert!(
            !watch.notifies(),
            "outside a runtime the owner is told to keep polling"
        );
        let (tx, rx) = mpsc::channel();
        watch.start(move || tx.send(()).unwrap());
        assert!(watch.notifies(), "a started watch notifies");
        child.kill().unwrap();
        rx.recv_timeout(LIVENESS).expect("the thread notifies");
        child.wait().unwrap();
    }

    #[test]
    fn dropping_the_watch_stops_its_task() {
        let rt = runtime();
        let mut child = sleeper();
        let (tx, rx) = mpsc::channel::<()>();
        {
            let _guard = rt.enter();
            let mut watch = LeaderWatch::open(pid_of(&child));
            watch.start(move || tx.send(()).unwrap());
        }
        child.kill().unwrap();
        wait_unreaped(&child);
        rt.block_on(async {
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }
        });
        // The aborted task dropped its sender without sending.
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::TryRecvError::Disconnected)
        ));
        child.wait().unwrap();
    }
}
