// Generated slots use temporary storage and a synthetic reserved endpoint.
mod inheritance {
    use super::*;
    use std::io;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, ExitStatus};
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

    // A wait error is not completion. Keep the exact child and the enclosing
    // fixture alive; after an unexpected error request termination once, then
    // keep waiting. Only a terminal wait result permits destruction.
    fn wait_owned(
        child: &mut Child,
        mut wait: impl FnMut(&mut Child) -> io::Result<ExitStatus>,
    ) -> ExitStatus {
        let mut reported = false;
        loop {
            match wait(child) {
                Ok(status) => return status,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    if !reported {
                        eprintln!("owned session fixture wait failed; retaining child and retrying: {error}");
                        // ECHILD removes our evidence that the numeric PID
                        // still names this child. Retain custody without signal.
                        if error.raw_os_error() != Some(libc::ECHILD) {
                            let _ = child.kill();
                        }
                        reported = true;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
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
                let result = command
                    .spawn()
                    .map(|mut child| wait_owned(&mut child, Child::wait));
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
            let mut reported = false;
            loop {
                // SAFETY: pid names our unreaped child and status is writable.
                let result = unsafe { libc::waitpid(self.pid, &mut status, 0) };
                if result == self.pid {
                    self.reaped = true;
                    return status;
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    if !reported {
                        eprintln!(
                            "owned fork fixture wait failed; retaining child and retrying: {error}"
                        );
                        if error.raw_os_error() != Some(libc::ECHILD) {
                            // SAFETY: this owned child has no other reaper and
                            // wait has not reported loss of child identity.
                            unsafe { libc::kill(self.pid, libc::SIGKILL) };
                        }
                        reported = true;
                    }
                    std::thread::sleep(Duration::from_millis(10));
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
        let dir = slot139_fixture();
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
        let dir = slot139_fixture();
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
        let dir = slot139_fixture();
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
            _lock: Some({
                let store = Store::open(dir.path(), DirectoryIntent::Generic).unwrap();
                let (parent, binding) = store
                    .binding(path.file_name().unwrap().to_str().unwrap())
                    .unwrap();
                binding.validate_private_current(&parent, &file).unwrap();
                SlotLock::new(file, parent, binding)
            }),
        };
        let child = PreExecChild::start();
        let error = owner.replace_token().unwrap_err();
        let failed = error.raw_os_error().is_some();
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
        // A transient wait failure must retain an actual owned child until a
        // real terminal wait result, rather than release its fixture early.
        let mut probe = Command::new("/bin/sh")
            .args(["-c", "exit 0"])
            .spawn()
            .unwrap();
        let mut calls = 0;
        let _terminal = wait_owned(&mut probe, |child| {
            calls += 1;
            if calls == 1 {
                Err(io::Error::from_raw_os_error(libc::EIO))
            } else {
                child.wait()
            }
        });
        assert_eq!(
            calls, 2,
            "injected error is followed by exact terminal wait"
        );
        // ECHILD must not authorize signaling a possibly reused numeric PID.
        // This owned child cannot finish successfully until the second call
        // supplies input; an erroneous kill would make its status fail.
        let mut probe = Command::new("/bin/sh")
            .args(["-c", "read value"])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut calls = 0;
        let terminal = wait_owned(&mut probe, |child| {
            calls += 1;
            if calls == 1 {
                Err(io::Error::from_raw_os_error(libc::ECHILD))
            } else {
                if let Some(mut input) = child.stdin.take() {
                    let _ = input.write_all(b"owned\n");
                }
                child.wait()
            }
        });
        assert_eq!(calls, 2);
        assert!(
            terminal.success(),
            "ECHILD observation must not trigger kill"
        );
    }
}
