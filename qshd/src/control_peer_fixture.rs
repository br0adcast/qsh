//! Owned self-exec custody for the four disposable-root credential controls.
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub(crate) const FOREIGN: u32 = 61001;
const ROLE: &str = "QSH_TEST_CONTROL_PEER_ROLE";
const PATH: &str = "QSH_TEST_CONTROL_PEER_PATH";

pub(crate) fn child_role() -> Option<(String, PathBuf)> {
    let role = std::env::var(ROLE).ok()?;
    let path = std::env::var_os(PATH).expect("owned child socket path");
    assert_eq!(nix::unistd::geteuid().as_raw(), FOREIGN);
    assert_eq!(nix::unistd::getegid().as_raw(), FOREIGN);
    println!("owned control-peer child effective UID/GID: 61001/61001");
    Some((role, path.into()))
}

pub(crate) fn enabled(name: &str) -> bool {
    if nix::unistd::geteuid().is_root()
        && std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref() == Ok("1")
    {
        true
    } else {
        eprintln!("SKIPPED {name}: requires root and QSHD_TEST_DISPOSABLE_HOST=1 in the existing disposable container tier");
        false
    }
}

pub(crate) struct Fixture {
    _dir: tempfile::TempDir,
    pub(crate) path: PathBuf,
    pub(crate) deadline: Instant,
    child: Option<Child>,
    // Private, per-fixture fault injection for the cleanup regression.
    cleanup_wait_errors: usize,
}

impl Fixture {
    pub(crate) fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let child_dir = dir.path().join("child");
        std::fs::create_dir(&child_dir).unwrap();
        std::os::unix::fs::chown(&child_dir, Some(FOREIGN), Some(FOREIGN)).unwrap();
        Self {
            path: child_dir.join("control"),
            _dir: dir,
            deadline: Instant::now() + Duration::from_secs(5),
            child: None,
            cleanup_wait_errors: 0,
        }
    }

    pub(crate) fn spawn(&mut self, name: &str, role: &str) {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", name, "--test-threads=1", "--nocapture"])
            .env(ROLE, role)
            .env(PATH, &self.path)
            .env("HOME", self._dir.path())
            .env("XDG_CONFIG_HOME", self._dir.path())
            .env("XDG_CACHE_HOME", self._dir.path())
            .env("HISTFILE", "/dev/null")
            .uid(FOREIGN)
            .gid(FOREIGN)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.child = Some(command.spawn().expect("spawn owned foreign-UID test child"));
    }

    pub(crate) fn remaining(&self) -> Duration {
        self.deadline
            .checked_duration_since(Instant::now())
            .expect("owned peer fixture deadline")
    }

    pub(crate) fn wait_for_socket(&mut self) {
        while !self.path.exists() {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "foreign server exited before binding"
            );
            let _ = self.remaining();
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    pub(crate) fn wait_for_server_ready(&mut self) {
        use std::os::unix::fs::MetadataExt;
        self.wait_for_socket();
        let ready = self.path.with_extension("ready");
        while !ready.exists() {
            assert!(
                self.child.as_mut().unwrap().try_wait().unwrap().is_none(),
                "foreign server exited before its setup receipt"
            );
            let _ = self.remaining();
            std::thread::sleep(Duration::from_millis(1));
        }
        let metadata = std::fs::symlink_metadata(&ready).unwrap();
        assert!(metadata.is_file());
        assert_eq!(metadata.uid(), FOREIGN);
        assert_eq!(
            std::fs::read(&ready).unwrap(),
            b"owned server setup complete"
        );
    }

    /// Path authority follows the client, independently of the listener process.
    pub(crate) fn own_path_for_client(&self, client_uid: u32, server_uid: u32) {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        assert!(nix::unistd::geteuid().is_root());
        let parent = self.path.parent().unwrap();
        assert_eq!(parent, self._dir.path().join("child"));
        let directory = std::fs::symlink_metadata(parent).unwrap();
        assert!(directory.is_dir());
        assert_eq!(directory.uid(), FOREIGN);
        let socket = std::fs::symlink_metadata(&self.path).unwrap();
        assert!(socket.file_type().is_socket());
        assert_eq!(socket.uid(), server_uid);
        assert_eq!(socket.mode() & 0o777, 0o666);
        std::os::unix::fs::chown(parent, Some(client_uid), Some(client_uid)).unwrap();
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::chown(&self.path, Some(client_uid), Some(client_uid)).unwrap();
        assert_eq!(std::fs::symlink_metadata(parent).unwrap().uid(), client_uid);
        assert_eq!(
            std::fs::symlink_metadata(&self.path).unwrap().uid(),
            client_uid
        );
    }

    pub(crate) fn finish(&mut self) {
        loop {
            if let Some(status) = self.child.as_mut().unwrap().try_wait().unwrap() {
                let mut child = self.child.take().unwrap();
                // try_wait(Some) has already reaped this exact child; wait
                // returns its cached status and cannot start a blocking wait.
                assert_eq!(child.wait().unwrap(), status);
                let mut stdout = String::new();
                let mut stderr = String::new();
                child
                    .stdout
                    .take()
                    .unwrap()
                    .read_to_string(&mut stdout)
                    .unwrap();
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut stderr)
                    .unwrap();
                assert!(
                    status.success(),
                    "owned child failed: {status}\n{stdout}\n{stderr}"
                );
                assert!(stdout.contains("owned control-peer child effective UID/GID: 61001/61001"));
                assert!(
                    stdout.contains("1 passed; 0 failed; 0 ignored;"),
                    "child must execute its exact named test: {stdout}"
                );
                return;
            }
            let _ = self.remaining();
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            if let Err(error) = child.kill() {
                eprintln!("owned control-peer child termination failed; retaining custody until wait succeeds: {error}");
            }
            // The result deadline may fail the test, but cannot prove cleanup.
            // Keep both Child and TempDir until this exact Child returns a
            // terminal status. A wait error (including ECHILD) is not proof.
            let mut reported_wait_error = false;
            loop {
                let result = if self.cleanup_wait_errors > 0 {
                    self.cleanup_wait_errors -= 1;
                    Err(std::io::Error::from_raw_os_error(libc::EIO))
                } else {
                    child.wait()
                };
                match result {
                    Ok(_) => break,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) => {
                        if !reported_wait_error {
                            eprintln!("owned control-peer child wait failed; retaining child and fixture and retrying: {error}");
                            reported_wait_error = true;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            }
        }
    }
}

pub(crate) fn allow_fixture_connection(path: &Path) {
    // Permit the socket connect so EACCES cannot masquerade as peer rejection.
    // These modes apply only to this deliberately cross-account test fixture.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666)).unwrap();
}

pub(crate) fn mark_server_ready(path: &Path) {
    assert_eq!(nix::unistd::geteuid().as_raw(), FOREIGN);
    let temporary = path.with_extension("ready-new");
    std::fs::write(&temporary, b"owned server setup complete").unwrap();
    std::fs::rename(temporary, path.with_extension("ready")).unwrap();
}

pub(crate) fn accept(
    listener: &std::os::unix::net::UnixListener,
    deadline: Instant,
) -> std::os::unix::net::UnixStream {
    listener.set_nonblocking(true).unwrap();
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            other => panic!("owned peer accept failed: {other:?}"),
        }
    }
}

#[test]
fn control_peer_cleanup_retains_child_and_fixture_after_wait_error_during_unwind() {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().to_path_buf();
    let child = Command::new("/bin/sleep")
        .arg("60")
        .env("HOME", &path)
        .env("XDG_CONFIG_HOME", &path)
        .env("XDG_CACHE_HOME", &path)
        .env("HISTFILE", "/dev/null")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = Pid::from_raw(child.id().try_into().unwrap());
    let fixture = Fixture {
        _dir: dir,
        path: path.join("unused-control"),
        deadline: Instant::now(),
        child: Some(child),
        cleanup_wait_errors: 1,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = fixture;
        panic!("injected owner failure");
    }));
    assert!(result.is_err());
    // No other waiter exists. ECHILD here means the fixture's Child already
    // reaped it. It is NOT accepted as terminal-wait proof inside cleanup.
    let already_reaped = match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
        Err(nix::errno::Errno::ECHILD) => true,
        Ok(WaitStatus::StillAlive) => {
            // RED cleanup: the old Drop can abandon its killed child before
            // reaping. It is still our exact unreaped child, never a reused PID.
            loop {
                match waitpid(pid, None) {
                    Ok(_) => break,
                    Err(nix::errno::Errno::EINTR) => continue,
                    other => panic!("reaping the RED control's owned child: {other:?}"),
                }
            }
            false
        }
        Ok(_) => false,
        other => panic!("observing the owned child: {other:?}"),
    };
    assert!(
        !path.exists(),
        "fixture removal follows confirmed child cleanup"
    );
    assert!(already_reaped, "fixture Drop must retain and reap the child after a wait error before removing its directory");
}
