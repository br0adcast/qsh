// Generated slots use temporary storage and a synthetic reserved endpoint.
mod inheritance {
    use super::*;
    use std::io;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Command, ExitStatus};
    use std::thread::JoinHandle;
    use std::time::Duration;

    // Only async-signal-safe system calls and stack data after fork. The poll
    // bound is fixture cleanup protection, not synchronization by elapsed time.
    fn child_barrier(fd: libc::c_int) -> bool {
        let byte = 1u8;
        let mut release = 0u8;
        let mut poll = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the inherited socket remains open, both buffers are valid for
        // one byte, and poll points to one initialized descriptor.
        unsafe {
            libc::write(fd, (&byte as *const u8).cast(), 1) == 1
                && libc::poll(&mut poll, 1, 10_000) == 1
                && libc::read(fd, (&mut release as *mut u8).cast(), 1) == 1
        }
    }

    struct PreExecChild {
        socket: UnixStream,
        worker: Option<JoinHandle<io::Result<ExitStatus>>>,
    }
    impl PreExecChild {
        fn start() -> Self {
            let (socket, peer) = UnixStream::pair().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let worker = std::thread::spawn(move || {
                let mut command = Command::new("/bin/sh");
                command.args(["-c", "exit 0"]);
                let fd = peer.as_raw_fd();
                // SAFETY: the callback uses only the inherited socket, stack
                // values and async-signal-safe calls; no locks or allocation.
                unsafe {
                    command.pre_exec(move || {
                        if child_barrier(fd) {
                            Ok(())
                        } else {
                            Err(io::Error::from_raw_os_error(libc::EIO))
                        }
                    });
                }
                let result = command.spawn().and_then(|mut child| child.wait());
                drop(peer);
                result
            });
            let mut child = Self {
                socket,
                worker: Some(worker),
            };
            let mut ready = [0];
            child.socket.read_exact(&mut ready).unwrap();
            child
        }
        fn finish(mut self) -> ExitStatus {
            let release = self.socket.write_all(&[1]);
            let joined = self.worker.take().unwrap().join();
            release.unwrap();
            joined.unwrap().unwrap()
        }
    }
    impl Drop for PreExecChild {
        fn drop(&mut self) {
            let _ = self.socket.write_all(&[1]);
            if let Some(worker) = self.worker.take() {
                let _ = worker.join();
            }
        }
    }

    struct ForkChild {
        pid: libc::pid_t,
        socket: UnixStream,
        reaped: bool,
    }
    impl ForkChild {
        fn finish(mut self) -> libc::c_int {
            let release = self.socket.write_all(&[1]);
            let status = self.reap();
            release.unwrap();
            status
        }
        fn reap(&mut self) -> libc::c_int {
            let mut status = 0;
            loop {
                // SAFETY: pid names our unreaped child and status is writable.
                let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if result == self.pid {
                    self.reaped = true;
                    return status;
                }
                if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    self.reaped = true;
                    return -1;
                }
            }
        }
    }
    impl Drop for ForkChild {
        fn drop(&mut self) {
            if !self.reaped {
                let _ = self.socket.write_all(&[1]);
                self.reap();
            }
        }
    }

    #[test]
    fn slot125_owner_drop_releases_the_replacement_while_a_child_is_pre_exec() {
        let dir = tempfile::tempdir().unwrap();
        let mut owner = claim(dir.path(), "alice", "example.invalid", 60000);
        let child = PreExecChild::start();
        let replacement = owner.replace_token().unwrap();
        let live = claim(dir.path(), "alice", "example.invalid", 60000);
        let excluded_while_live = live.token != replacement;
        drop(live);
        drop(owner);
        let reclaimed = claim(dir.path(), "alice", "example.invalid", 60000);
        let same_while_child_is_held = reclaimed.token == replacement;
        drop(reclaimed);
        let status = child.finish();
        assert!(status.success());
        assert!(excluded_while_live, "a live claim must remain exclusive");
        assert!(
            same_while_child_is_held,
            "owner drop must release its slot before an unrelated child's exec"
        );
    }

    #[test]
    fn slot125_a_forked_copy_cannot_unlock_the_live_parent() {
        let dir = tempfile::tempdir().unwrap();
        let owner = claim(dir.path(), "alice", "example.invalid", 60000);
        let original = owner.token;
        let path = dir
            .path()
            .join(slot_name("alice", "example.invalid", 60000, 0));
        let (socket, peer) = UnixStream::pair().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        // SAFETY: child only drops the syscall-only claim, exchanges raw socket
        // bytes and calls _exit; it never allocates, formats or unwinds.
        let pid = unsafe { libc::fork() };
        if pid == 0 {
            drop(owner);
            let ok = child_barrier(peer.as_raw_fd());
            // SAFETY: terminate this fixture child without Rust destructors.
            unsafe { libc::_exit(if ok { 0 } else { 1 }) }
        }
        assert!(pid > 0, "fork failed");
        drop(peer);
        let mut child = ForkChild {
            pid,
            socket,
            reaped: false,
        };
        let mut ready = [0];
        child.socket.read_exact(&mut ready).unwrap();
        assert_lock_from_subprocess(&path, false);
        let concurrent = claim(dir.path(), "alice", "example.invalid", 60000);
        let excluded = concurrent.token != original;
        drop(concurrent);
        drop(owner);
        assert_lock_from_subprocess(&path, true);
        let status = child.finish();
        assert_eq!(status, 0, "fork child failed");
        assert!(
            excluded,
            "fork-copy drop must not release the parent's slot"
        );
    }
    #[test]
    fn slot125_failed_token_replacement_retains_ownership_until_drop() {
        let dir = tempfile::tempdir().unwrap();
        let initial = claim(dir.path(), "alice", "example.invalid", 60000);
        let original = initial.token;
        drop(initial);
        let path = dir
            .path()
            .join(slot_name("alice", "example.invalid", 60000, 0));
        let file = OpenOptions::new().read(true).open(&path).unwrap();
        assert!(lock_exclusive(&file));
        let mut owner = Claim {
            token: original,
            _lock: Some(SlotLock::new(file)),
        };
        let child = PreExecChild::start();
        let failed = owner.replace_token().is_err();
        let token_retained = owner.token == original;
        assert_lock_from_subprocess(&path, false);
        drop(owner);
        let reclaimed = claim(dir.path(), "alice", "example.invalid", 60000);
        let persisted_token_retained = reclaimed.token == original;
        drop(reclaimed);
        let status = child.finish();
        assert!(status.success());
        assert!(failed, "read-only token storage must reject replacement");
        assert!(token_retained && persisted_token_retained);
    }
}
