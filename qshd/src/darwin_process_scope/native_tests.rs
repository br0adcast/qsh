//! Actual Darwin qualification; never selected on a non-Darwin host.
use super::native::{own_child, prepare, NativeOps};
use super::*;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use transport::channel_server::ChildStatus;

// Retain the actual fixture Child independently of the production wrapper so
// assertion failure cannot discard it. Rescue is failure-only, never evidence.
struct FixtureChild {
    inner: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    waits: Arc<AtomicUsize>,
}
impl portable_pty::ChildKiller for FixtureChild {
    fn kill(&mut self) -> std::io::Result<()> {
        panic!("production numeric-PID kill fallback");
    }
    fn clone_killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
        panic!("unexpected fixture killer clone");
    }
}
impl portable_pty::Child for FixtureChild {
    fn try_wait(&mut self) -> std::io::Result<Option<portable_pty::ExitStatus>> {
        panic!("production consuming try_wait");
    }
    fn wait(&mut self) -> std::io::Result<portable_pty::ExitStatus> {
        let value = self.inner.lock().unwrap().wait()?;
        self.waits.fetch_add(1, Ordering::SeqCst);
        Ok(value)
    }
    fn process_id(&self) -> Option<u32> {
        self.inner.lock().unwrap().process_id()
    }
}
struct FixtureGuard {
    inner: Arc<Mutex<Box<dyn portable_pty::Child + Send + Sync>>>,
    waits: Arc<AtomicUsize>,
    rescued: Arc<AtomicBool>,
    abort_directory: Option<std::path::PathBuf>,
}
impl FixtureGuard {
    fn new(
        child: Box<dyn portable_pty::Child + Send + Sync>,
    ) -> (Self, Box<dyn portable_pty::Child + Send + Sync>) {
        let inner = Arc::new(Mutex::new(child));
        let waits = Arc::new(AtomicUsize::new(0));
        (
            Self {
                inner: inner.clone(),
                waits: waits.clone(),
                rescued: Arc::new(AtomicBool::new(false)),
                abort_directory: None,
            },
            Box::new(FixtureChild { inner, waits }),
        )
    }
    fn with_abort(mut self, path: &Path) -> Self {
        self.abort_directory = Some(path.to_path_buf());
        self
    }
    fn assert_normal(&self) {
        assert_eq!(self.waits.load(Ordering::SeqCst), 1);
        assert!(!self.rescued.load(Ordering::SeqCst));
    }
}
impl Drop for FixtureGuard {
    fn drop(&mut self) {
        if self.waits.load(Ordering::SeqCst) > 0 {
            return;
        }
        self.rescued.store(true, Ordering::SeqCst);
        let mut child = self.inner.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(directory) = &self.abort_directory {
            let _ = std::fs::write(directory.join("abort"), b"abort");
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return,
                    Err(_) => return,
                    Ok(None) => {}
                }
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        // Only the exclusive still-unreaped fixture Child may use this path.
        // An error cannot authorize a signal to a potentially reused PID.
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
fn assert_census_receipt() {
    let receipt = super::native::take_receipt().expect("production owner receipt");
    assert_eq!(receipt.progress, "reaped");
    assert_eq!(receipt.retained, (0, 0));
    let (generation, n, p) = receipt.evidence.expect("same-call C/N/P");
    assert!(generation > 0 && n < CAPACITY && p.checked_add(20).is_some_and(|minimum| n < minimum));
    eprintln!(
        "darwin223 C={} N={} P={} generation={} physical_reap=normal retained=0",
        CAPACITY, n, p, generation
    );
}
static ACKNOWLEDGED: AtomicBool = AtomicBool::new(false);
extern "C" fn acknowledge(_: i32) {
    ACKNOWLEDGED.store(true, Ordering::Relaxed);
}
fn publish_bytes(path: &Path, bytes: &[u8]) {
    let pending = path.with_extension("pending");
    std::fs::write(&pending, bytes).unwrap();
    std::fs::rename(pending, path).unwrap();
}
fn publish(path: &Path) {
    publish_bytes(path, b"ready");
}
fn until(mut check: impl FnMut() -> bool) {
    let end = Instant::now() + Duration::from_secs(10);
    while !check() {
        assert!(Instant::now() < end, "owned native fixture deadline");
        std::thread::sleep(Duration::from_millis(10));
    }
}
fn actor(directory: &Path) -> std::process::Child {
    Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "darwin_process_scope::native_tests::darwin223_owned_actor",
            "--nocapture",
        ])
        .env("QSH_DARWIN223_ACTOR", directory)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}
#[test]
fn darwin223_owned_actor() {
    let Some(directory) = std::env::var_os("QSH_DARWIN223_ACTOR") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    if std::env::var_os("QSH_DARWIN223_CONNECTED_ACTOR").is_some() {
        use std::io::{Read, Write};
        let identity = NativeOps
            .identity(std::process::id() as i32)
            .expect("actor self identity");
        let finish = || {
            publish_bytes(
                &directory.join("finished"),
                format!("{} {} {}", identity.pid, identity.unique, identity.version).as_bytes(),
            )
        };
        if directory.join("delay-publication").exists() {
            publish(&directory.join("delay-entered"));
            std::thread::sleep(Duration::from_millis(200));
        }
        // The controller creates the abort authority before Open is enqueued.
        // Even an actor starting after failed observation sees that authority.
        if directory.join("abort").exists() {
            finish();
            return;
        }
        publish_bytes(
            &directory.join("actor-pid"),
            std::process::id().to_string().as_bytes(),
        );
        let flags = unsafe { nix::libc::fcntl(0, nix::libc::F_GETFL) };
        assert!(
            flags >= 0
                && unsafe {
                    nix::libc::fcntl(0, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK)
                } == 0
        );
        let end = Instant::now() + Duration::from_secs(45);
        while !directory.join("controller-bound").exists() {
            if directory.join("abort").exists() || Instant::now() >= end {
                finish();
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        while !directory.join("abort").exists() && Instant::now() < end {
            let mut buffer = [0; 256];
            match std::io::stdin().read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    std::io::stdout().write_all(&buffer[..n]).unwrap();
                    std::io::stdout().flush().unwrap();
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => break,
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        finish();
        return;
    }
    let stage = std::env::var_os("QSH_DARWIN223_STAGE2").is_some();
    let descendant = std::env::var_os("QSH_DARWIN223_DESCENDANT").is_some();
    let pty_leader = std::env::var_os("QSH_DARWIN223_PTY_LEADER").is_some();
    let fork_root = std::env::var_os("QSH_DARWIN223_FORK_ROOT").is_some();
    let foreign_parent = std::env::var_os("QSH_DARWIN223_FOREIGN_PARENT").is_some();
    if descendant {
        assert_eq!(unsafe { nix::libc::setpgid(0, 0) }, 0);
    } else if !stage && !pty_leader && !foreign_parent {
        assert!(unsafe { nix::libc::setsid() } > 0);
    }
    if pty_leader {
        assert_eq!(unsafe { nix::libc::getsid(0) }, std::process::id() as i32);
    }
    unsafe {
        nix::libc::signal(nix::libc::SIGHUP, acknowledge as *const () as usize);
    }
    if fork_root {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_actor",
                "--nocapture",
            ])
            .env_remove("QSH_DARWIN223_FORK_ROOT")
            .env("QSH_DARWIN223_FOREIGN_PARENT", "1")
            .spawn()
            .unwrap();
        until(|| directory.join("foreign-parent-ready").exists());
        publish(&directory.join("ready1"));
        let end = Instant::now() + Duration::from_secs(25);
        while !directory.join("exit").exists() {
            if directory.join("abort").exists() || Instant::now() >= end {
                let _ = std::fs::write(directory.join("abort"), b"abort");
                let _ = child.wait();
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(child);
        return;
    }
    if foreign_parent {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_actor",
                "--nocapture",
            ])
            .env_remove("QSH_DARWIN223_FOREIGN_PARENT")
            .env("QSH_DARWIN223_DESCENDANT", "1")
            .spawn()
            .unwrap();
        until(|| directory.join("descendant-ready").exists());
        assert!(unsafe { nix::libc::setsid() } > 0);
        publish_bytes(
            &directory.join("foreign-parent-pid"),
            std::process::id().to_string().as_bytes(),
        );
        publish(&directory.join("foreign-parent-ready"));
        let end = Instant::now() + Duration::from_secs(25);
        let mut terminal = false;
        let mut reaped = false;
        loop {
            if !terminal && directory.join("candidate-exit").exists() {
                publish(&directory.join("descendant-exit"));
                if std::env::var_os("QSH_DARWIN223_CASE").as_deref()
                    == Some(std::ffi::OsStr::new("zombie"))
                {
                    let mut ops = NativeOps;
                    until(|| {
                        ops.classify(child.id() as i32)
                            .is_ok_and(|value| value.class == Class::Zombie)
                    });
                } else {
                    assert!(child.wait().unwrap().success());
                    reaped = true;
                }
                terminal = true;
                publish(&directory.join("candidate-terminal"));
            }
            if directory.join("finish").exists()
                || directory.join("abort").exists()
                || Instant::now() >= end
            {
                if !reaped {
                    publish(&directory.join("descendant-exit"));
                    assert!(child.wait().unwrap().success());
                }
                publish(&directory.join("candidate-reaped"));
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    if pty_leader {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_actor",
                "--nocapture",
            ])
            .env_remove("QSH_DARWIN223_PTY_LEADER")
            .env("QSH_DARWIN223_DESCENDANT", "1");
        let mut child = OwnedCommand::spawn(&mut command).unwrap();
        until(|| directory.join("descendant-ready").exists());
        // Do not orphan the fixture until the independent controller owns its
        // exact token/watch. Setup refusal retains a direct-child cleanup path.
        let deadline = Instant::now() + Duration::from_secs(10);
        while !directory.join("controller-bound").exists() {
            if directory.join("abort").exists() || Instant::now() >= deadline {
                if matches!(child.poll(), Ok(None)) {
                    let _ = child.child.kill();
                    let _ = child.finish(Instant::now() + Duration::from_secs(5));
                }
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        if std::env::var_os("QSH_DARWIN223_HOLD_LEADER").is_some() {
            let deadline = Instant::now() + Duration::from_secs(180);
            while Instant::now() < deadline && !directory.join("abort").exists() {
                std::thread::sleep(Duration::from_millis(10));
            }
            if matches!(child.poll(), Ok(None)) {
                let _ = child.child.kill();
                let _ = child.finish(Instant::now() + Duration::from_secs(5));
            }
            return;
        }
        child.transfer_to_bound_controller();
        std::process::exit(0);
    }
    let grandchild = std::env::var_os("QSH_DARWIN223_GRANDCHILD").is_some();
    if descendant && grandchild {
        publish_bytes(
            &directory.join("grandchild-pid"),
            std::process::id().to_string().as_bytes(),
        );
        publish(&directory.join("grandchild-ready"));
    }
    if descendant && !grandchild {
        publish_bytes(
            &directory.join("descendant-pid"),
            std::process::id().to_string().as_bytes(),
        );
        publish(&directory.join("descendant-ready"));
    }
    publish(&directory.join(if stage { "ready2" } else { "ready1" }));
    let actor_deadline = Instant::now()
        + Duration::from_secs(if std::env::var_os("QSH_DARWIN223_HOLD_LEADER").is_some() {
            180
        } else {
            30
        });
    loop {
        if Instant::now() >= actor_deadline {
            return;
        }
        if ACKNOWLEDGED.swap(false, Ordering::Relaxed) {
            publish(&directory.join(if stage { "ack2" } else { "ack1" }));
        }
        if !stage && directory.join("exec").exists() {
            use std::os::unix::process::CommandExt;
            let error = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "darwin_process_scope::native_tests::darwin223_owned_actor",
                    "--nocapture",
                ])
                .env("QSH_DARWIN223_STAGE2", "1")
                .exec();
            panic!("owned exec failed: {error}");
        }
        if (descendant && !grandchild && directory.join("descendant-exit").exists())
            || (!descendant && directory.join("exit").exists())
        {
            if descendant
                && !directory.join("abort").exists()
                && std::env::var_os("QSH_DARWIN223_CASE").as_deref()
                    == Some(std::ffi::OsStr::new("last-fork"))
            {
                let mut command = Command::new(std::env::current_exe().unwrap());
                command
                    .args([
                        "--exact",
                        "darwin_process_scope::native_tests::darwin223_owned_actor",
                        "--nocapture",
                    ])
                    .env_remove("QSH_DARWIN223_CASE")
                    .env("QSH_DARWIN223_GRANDCHILD", "1");
                let child = command.spawn().unwrap();
                drop(child);
                until(|| directory.join("grandchild-ready").exists());
            }
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
#[test]
fn darwin223_native_noncooperative_token_exec_and_bound_exit() {
    let qualification = prepare().expect("actual production admission");
    eprintln!(
        "darwin223 contract={} arch={}",
        qualification.contract,
        std::env::consts::ARCH
    );
    let directory = tempfile::tempdir().unwrap();
    let mut child = actor(directory.path());
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        until(|| directory.path().join("ready1").exists());
        let mut ops = NativeOps;
        let pid = child.id() as i32;
        let before = ops.classify(pid).unwrap();
        assert_eq!(before.class, Class::Session(pid));
        let mut bound = ops.bind_exit(before, 1).unwrap();
        let queue = bound.handle.raw_fd();
        assert_ne!(
            unsafe { nix::libc::fcntl(queue, nix::libc::F_GETFD) } & nix::libc::FD_CLOEXEC,
            0
        );
        let old = ops.acquire_signal_token(before.identity, pid).unwrap();
        ops.signal_exact(&old.handle, Signal::Hup).unwrap();
        until(|| directory.path().join("ack1").exists());
        publish(&directory.path().join("exec"));
        until(|| directory.path().join("ready2").exists());
        let after = ops.classify(pid).unwrap();
        assert_eq!(before.identity.unique, after.identity.unique);
        assert_ne!(before.identity.version, after.identity.version);
        assert_eq!(
            ops.signal_exact(&old.handle, Signal::Hup),
            Err(Failure::Errno(nix::libc::ESRCH))
        );
        let fresh = ops.acquire_signal_token(after.identity, pid).unwrap();
        ops.signal_exact(&fresh.handle, Signal::Hup).unwrap();
        until(|| directory.path().join("ack2").exists());
        publish(&directory.path().join("exit"));
        assert!(child.wait().unwrap().success());
        until(|| ops.observe_exit(&mut bound.handle).unwrap().is_some());
        drop(bound);
        assert_eq!(unsafe { nix::libc::fcntl(queue, nix::libc::F_GETFD) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::EBADF)
        );
        eprintln!("darwin223 token=noncooperative exec=fresh stale=refused NOTE_EXIT=bound direct_wait=normal");
    }));
    if result.is_err() {
        if matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    result.unwrap();
}
#[test]
fn darwin223_native_signaled_leader_scope_uses_portable_code_one() {
    let qualification = prepare().expect("actual production admission");
    let directory = tempfile::tempdir().unwrap();
    let child = actor(directory.path());
    until(|| directory.path().join("ready1").exists());
    let (guard, child) = FixtureGuard::new(Box::new(child));
    let mut wait = own_child(child, qualification);
    wait.kill();
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        match wait.poll_exit() {
            ChildStatus::Reaped { code } => {
                assert_eq!(code, Some(1));
                break;
            }
            _ => {
                assert!(
                    Instant::now() < end,
                    "production Darwin owner did not close"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    guard.assert_normal();
    assert_census_receipt();
    assert!(
        directory.path().join("ack1").exists(),
        "actual HUP delivery before KILL"
    );
}

#[test]
fn darwin223_native_already_zombie_handshake_child_keeps_reserved_leader() {
    let qualification = prepare().expect("production admission");
    let directory = tempfile::tempdir().unwrap();
    let child = actor(directory.path());
    let pid = child.id() as i32;
    let (guard, child) = FixtureGuard::new(Box::new(child));
    until(|| directory.path().join("ready1").exists());
    publish(&directory.path().join("exit"));
    let mut ops = NativeOps;
    until(|| {
        ops.classify(pid)
            .is_ok_and(|value| value.class == Class::Zombie)
    });
    let mut wait = own_child(child, qualification);
    let end = Instant::now() + Duration::from_secs(15);
    loop {
        match wait.poll_exit() {
            ChildStatus::Reaped { code } => {
                assert_eq!(code, Some(0));
                break;
            }
            _ => {
                assert!(Instant::now() < end, "already-zombie child was stranded");
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
    guard.assert_normal();
    assert_census_receipt();
}
#[test]
fn darwin223_native_classification_bracket_refuses_exec_and_one_sided_zombie() {
    use super::native::classification_matches_for_test as stable;
    let first = Classified {
        identity: Identity {
            pid: 10,
            unique: 99,
            version: 2,
        },
        class: Class::Zombie,
    };
    assert!(stable(first, first));
    let mut changed = first;
    changed.identity.version = 3;
    assert!(!stable(first, changed));
    changed = first;
    changed.identity.unique = 100;
    assert!(!stable(first, changed));
    changed = first;
    changed.class = Class::Session(10);
    assert!(!stable(first, changed));
    let running = Classified {
        class: Class::Session(10),
        ..first
    };
    assert!(stable(running, running));
}

struct DescendantGuard {
    token: super::native::Token,
    watch: super::native::Watch,
    normal_exit: bool,
}
impl DescendantGuard {
    fn finish(&mut self) {
        let mut ops = NativeOps;
        until(|| ops.observe_exit(&mut self.watch).unwrap().is_some());
        self.normal_exit = true;
    }
}
impl Drop for DescendantGuard {
    fn drop(&mut self) {
        if !self.normal_exit {
            let mut ops = NativeOps;
            let _ = ops.signal_exact(&self.token, Signal::Kill);
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if matches!(ops.observe_exit(&mut self.watch), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
    }
}
#[test]
fn darwin223_native_silent_pty_leader_first_other_group_and_real_io_joins() {
    use std::io::Read;
    let qualification = prepare().expect("production admission");
    let directory = tempfile::tempdir().unwrap();
    let executable = std::env::current_exe().unwrap();
    let quote = |text: &str| format!("'{}'", text.replace('\'', "'\"'\"'"));
    let mut command = portable_pty::CommandBuilder::new("/bin/sh");
    command.args(["-c".to_string(),format!("exec {} --exact darwin_process_scope::native_tests::darwin223_owned_actor --nocapture >/dev/null 2>&1",quote(executable.to_str().unwrap()))]);
    command.env("QSH_DARWIN223_ACTOR", directory.path());
    command.env("QSH_DARWIN223_PTY_LEADER", "1");
    let (master, child) =
        crate::pty::spawn_command_no_echo(crate::pty::DEFAULT_PTY_SIZE, command, None).unwrap();
    let (guard, child) = FixtureGuard::new(child);
    let guard = guard.with_abort(directory.path());
    let leader_pid = child.process_id().unwrap() as i32;
    until(|| directory.path().join("descendant-ready").exists());
    let pid = std::fs::read_to_string(directory.path().join("descendant-pid"))
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let mut ops = NativeOps;
    let value = ops.classify(pid).unwrap();
    assert_eq!(value.class, Class::Session(leader_pid));
    assert_ne!(unsafe { nix::libc::getpgid(pid) }, leader_pid);
    let token = ops
        .acquire_signal_token(value.identity, leader_pid)
        .unwrap();
    let watch = ops.bind_exit(value, 1).unwrap();
    let mut descendant = DescendantGuard {
        token: token.handle,
        watch: watch.handle,
        normal_exit: false,
    };
    let mut reader = master.try_clone_reader().unwrap();
    let writer = master.take_writer().unwrap();
    let reading = std::thread::spawn(move || {
        let mut bytes = [0; 256];
        loop {
            match reader.read(&mut bytes) {
                Ok(0) => return,
                Ok(_) => {}
                Err(error) if error.raw_os_error() == Some(nix::libc::EIO) => return,
                Err(error) => panic!("actual PTY reader failed: {error}"),
            }
        }
    });
    let writing = std::thread::spawn(move || {
        use std::io::Write;
        let mut writer = writer;
        writer.write_all(b"fixture-input\n")
    });
    publish(&directory.path().join("controller-bound"));
    let mut wait = own_child(child, qualification);
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            match wait.poll_exit() {
                ChildStatus::Reaped { code } => {
                    assert_eq!(code, Some(0));
                    break;
                }
                _ => {
                    assert!(
                        Instant::now() < deadline,
                        "silent descendant scope not complete"
                    );
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
        descendant.finish();
        guard.assert_normal();
        assert_census_receipt();
    }));
    drop(wait);
    drop(descendant);
    drop(guard);
    drop(master);
    let read_join = reading.join();
    let write_join = writing.join();
    result.unwrap();
    read_join.expect("actual PTY EOF join");
    write_join
        .expect("actual writer join")
        .expect("actual PTY write");

    eprintln!("darwin223 silent_leader=first descendant_other_pgrp=true process_reap=normal reader_join=actual writer_join=actual rescue=false");
}

#[derive(Default)]
struct ConnectedEvents {
    live: AtomicBool,
    input_failed: AtomicBool,
    deframer: Mutex<transport::shell_frame::RecordDeframer>,
    records: Mutex<Vec<transport::channel::ServerRecord>>,
    shell: Mutex<transport::shell_frame::ShellDeframer>,
    output: Mutex<Vec<u8>>,
}
impl transport::driver_std::ClientEvents for ConnectedEvents {
    fn on_bytes(&self, stream: u8, data: Vec<u8>) {
        if stream == transport::channel::CONTROL_STREAM {
            for raw in self.deframer.lock().unwrap().push(&data) {
                if let Ok(record) = transport::channel::decode_server(&raw) {
                    self.records.lock().unwrap().push(record);
                }
            }
        } else if stream == transport::channel::FIRST_CHANNEL_STREAM {
            for record in self.shell.lock().unwrap().push(&data) {
                if let transport::shell_frame::ShellRecord::Data(bytes) = record {
                    let mut output = self.output.lock().unwrap();
                    if output.len() + bytes.len() > 4096 {
                        self.input_failed.store(true, Ordering::SeqCst);
                    } else {
                        output.extend_from_slice(&bytes);
                    }
                }
            }
        }
    }
    fn on_state(&self, state: transport::LinkState) {
        if state == transport::LinkState::Live {
            self.live.store(true, Ordering::SeqCst);
        }
    }
    fn on_stats(&self, _: transport::Stats) {}
    fn on_reset(&self, _: u8) {}
    fn on_input_failure(&self, _: transport::driver_std::InputFailure) {
        self.input_failed.store(true, Ordering::SeqCst);
    }
}
struct ConnectedBinder;
impl transport::driver_std::Binder for ConnectedBinder {
    fn bind(&self, _: i32) -> bool {
        true
    }
}
async fn connected_until(mut predicate: impl FnMut() -> bool) -> Result<(), &'static str> {
    let end = Instant::now() + Duration::from_secs(15);
    while !predicate() {
        if Instant::now() >= end {
            return Err("connected observation deadline");
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Ok(())
}
struct ConnectedActorAuthority {
    directory: Option<tempfile::TempDir>,
    bound: Option<DescendantGuard>,
}
impl ConnectedActorAuthority {
    fn new() -> Self {
        Self {
            directory: Some(tempfile::tempdir().unwrap()),
            bound: None,
        }
    }
    fn path(&self) -> &Path {
        self.directory.as_ref().unwrap().path()
    }
    fn observe(&mut self) {
        if self.bound.is_some() {
            return;
        }
        let Ok(value) = std::fs::read_to_string(self.path().join("actor-pid")) else {
            return;
        };
        let pid = value.parse::<i32>().expect("actor published PID");
        let mut ops = NativeOps;
        let current = ops
            .classify(pid)
            .expect("waiting cooperative actor identity");
        let Class::Session(sid) = current.class else {
            panic!("actor exited before controller authority");
        };
        let token = ops
            .acquire_signal_token(current.identity, sid)
            .expect("actor full token");
        // An injected refusal exercises the actual pre-binding cleanup route.
        assert!(
            !self.path().join("refuse-binding").exists(),
            "injected actor binding refusal"
        );
        let watch = ops.bind_exit(current, 1).expect("actor exit watch");
        self.bound = Some(DescendantGuard {
            token: token.handle,
            watch: watch.handle,
            normal_exit: false,
        });
        publish(&self.path().join("controller-bound"));
    }
    fn command(directory: &Path) -> Vec<u8> {
        let quote = |value: &str| format!("'{}'", value.replace('\'', "'\"'\"'"));
        format!("QSH_DARWIN223_ACTOR={} QSH_DARWIN223_CONNECTED_ACTOR=1 exec {} --exact darwin_process_scope::native_tests::darwin223_owned_actor --nocapture",
            quote(directory.to_str().unwrap()), quote(std::env::current_exe().unwrap().to_str().unwrap())).into_bytes()
    }
    fn abort(&self) {
        publish(&self.path().join("abort"));
    }
    fn terminal(&mut self) -> bool {
        if let Some(bound) = self.bound.as_mut() {
            if bound.normal_exit {
                return true;
            }
            if matches!(NativeOps.observe_exit(&mut bound.watch), Ok(Some(_))) {
                bound.normal_exit = true;
                return true;
            }
        }
        // Written only after actual manager return and both registry counts0.
        // This is also explicit proof of no remaining actor for no-channel.
        if self.path().join("manager-joined").exists() {
            return true;
        }
        // A trusted cooperative actor publishes its exact self identity before
        // return. A completion file alone is insufficient: confirm terminal
        // state/absence or a different lifetime, never signal by this PID.
        let Ok(value) = std::fs::read_to_string(self.path().join("finished")) else {
            return false;
        };
        if value.len() > 128 {
            return false;
        }
        let fields: Vec<_> = value.split_whitespace().collect();
        if fields.len() != 3 {
            return false;
        }
        let (Ok(pid), Ok(unique), Ok(version)) =
            (fields[0].parse(), fields[1].parse(), fields[2].parse())
        else {
            return false;
        };
        let identity = Identity {
            pid,
            unique,
            version,
        };
        if !identity.valid() {
            return false;
        }
        match NativeOps.classify(pid) {
            Ok(current) => {
                !current.identity.same_process(identity) || current.class == Class::Zombie
            }
            Err(Failure::Errno(code)) if code == nix::libc::ESRCH => true,
            _ => false,
        }
    }
    fn settle(&mut self) -> bool {
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            if self.terminal() {
                if let Some(bound) = self.bound.as_mut() {
                    bound.normal_exit = true;
                }
                return true;
            }
            if Instant::now() >= end {
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
    fn finish(&mut self, expect_actor: bool) {
        let observed = self.bound.is_some();
        assert!(self.settle(), "actor exit remains unconfirmed");
        assert!(
            !expect_actor || observed,
            "expected actor never acquired exact controller authority"
        );
    }
}
impl Drop for ConnectedActorAuthority {
    fn drop(&mut self) {
        self.abort();
        if !self.settle() {
            let retained = self.directory.take().unwrap().keep();
            eprintln!(
                "darwin223 actor cleanup UNCONFIRMED; abort authority retained at {}",
                retained.display()
            );
        }
    }
}
fn connected_authority_controls() {
    for delayed in [true, false] {
        let mut authority = ConnectedActorAuthority::new();
        let path = authority.path().to_path_buf();
        publish(&path.join(if delayed {
            "delay-publication"
        } else {
            "refuse-binding"
        }));
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_actor",
                "--nocapture",
            ])
            .env("QSH_DARWIN223_ACTOR", &path)
            .env("QSH_DARWIN223_CONNECTED_ACTOR", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut owner = OwnedCommand::spawn(&mut command).unwrap();
        if delayed {
            until(|| path.join("delay-entered").exists());
            assert!(!path.join("actor-pid").exists());
        } else {
            until(|| path.join("actor-pid").exists());
            let refusal =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| authority.observe()));
            assert!(refusal.is_err());
            assert!(authority.bound.is_none());
        }
        // Drop must retain abort authority until the unbound actor really exits.
        // The delayed actor deterministically cannot observe an ephemeral marker.
        drop(authority);
        assert!(owner
            .finish(Instant::now() + Duration::from_secs(3))
            .unwrap()
            .success());
        assert!(
            !path.exists(),
            "only confirmed completion permits directory removal"
        );
    }
    // No actor/no manager receipt is not a successful expected-actor finish.
    let mut authority = ConnectedActorAuthority::new();
    publish(&authority.path().join("manager-joined"));
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| authority.finish(true))).is_err()
    );
}
async fn connected_case(mode: &str, signal_directory: Option<&Path>) {
    use transport::channel::{
        encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord, CONTROL_STREAM,
        FIRST_CHANNEL_STREAM,
    };
    use transport::driver_std::StdClient;
    use transport::handshake::generate_keypair;
    use transport::handshake_payload::StartKind;
    use transport::session_manager::{LoginEndedReports, ServerAuth};
    use transport::{AuthPolicy, ConnectionConfig, Role};
    prepare().expect("native production admission");

    let server_keys = generate_keypair();
    let client_keys = generate_keypair();
    let allowlist = Arc::new(Mutex::new(vec![client_keys.public]));
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    let backend = Arc::new(crate::channel_backend::ChannelSessionBackend::new(
        Arc::new(crate::screen_budget::ScreenBudget::new(
            crate::screen_budget::BudgetLimits::default(),
        )),
    ));
    let registry = backend.open_registry();
    let shutdown = transport::Shutdown::default();
    let auth = ServerAuth {
        allowlist: allowlist.clone(),
        verifier: None,
        server_pub: server_keys.public,
        self_principal: transport::auth::Principal {
            uid: unsafe { nix::libc::getuid() },
            name: "darwin-owned-fixture".into(),
            identity: "fixture-allowlist".into(),
            incarnation: 0,
        },
        nonces: Arc::new(crate::RandomNonces),
        logins: Arc::new(crate::ForgetNothing),
    };
    let actor_directory = std::path::PathBuf::from(
        std::env::var_os("QSH_DARWIN223_CONNECTED_ACTORS")
            .expect("external actor authority required"),
    );
    let actor_command = ConnectedActorAuthority::command(&actor_directory);
    let body_actor_directory = actor_directory.clone();
    let mut manager = if let Some(directory) = signal_directory {
        let directory = directory.to_path_buf();
        let mut signals = crate::transport_daemon::PersonalSignals::register()
            .expect("owned signal registration");
        tokio::spawn(async move {
            crate::transport_daemon::run_serve_loop_until_stop(
                socket,
                server_keys.private,
                auth,
                backend,
                LoginEndedReports::none(),
                async {
                    signals.requested().await?;
                    publish(&directory.join("signal-observed"));
                    Ok(())
                },
            )
            .await
            .map_err(|error| error.to_string())
        })
    } else {
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            crate::transport_daemon::run_serve_loop_until_shutdown(
                socket,
                server_keys.private,
                auth,
                backend,
                LoginEndedReports::none(),
                shutdown,
            )
            .await
            .map_err(|error| format!("{error:?}"))
        })
    };
    let connect = move |token, events, private_key| {
        StdClient::connect(
            address,
            ConnectionConfig {
                required_features: transport::Features::CHANNEL_GEOMETRY
                    | transport::Features::AUTH_ACCEPTED,
                features: transport::Features::SUPPORTED,
                role: Role::Client,
                local_static_priv: private_key,
                remote_static_pub: Some(server_keys.public),
                auth: AuthPolicy::Allowlist(Vec::new()),
            },
            token,
            StartKind::Cold,
            Arc::new(ConnectedBinder),
            events,
            None,
        )
    };
    let events = Arc::new(ConnectedEvents::default());
    let client = Arc::new(connect([1; 16], events.clone(), client_keys.private));
    let result = {
        let client = client.clone();
        let events = events.clone();
        let registry = registry.clone();
        let allowlist = allowlist.clone();
        let mode = mode.to_owned();
        match tokio::spawn(async move {
            connected_until(|| events.live.load(Ordering::SeqCst)).await?;
            if mode == "no-channel" { return Ok::<(), &'static str>(()); }
            let open = OpenRequest {
                stream: FIRST_CHANNEL_STREAM, kind: ChannelKind::Command,
                cols: 80, rows: 24, screen: false, command: actor_command,
            };
            client.send_bytes(CONTROL_STREAM, encode_client(&ClientRecord::Open(open)))
                .map_err(|_| "open enqueue failed")?;
            connected_until(|| events.records.lock().unwrap().iter().any(|record| {
                matches!(record, ServerRecord::Opened { stream } if *stream == FIRST_CHANNEL_STREAM)
            })).await?;
            connected_until(|| body_actor_directory.join("controller-bound").exists()).await?;
            if mode == "body-failure" { return Err("injected live-channel body failure"); }
            if mode == "rebind" {
                client.rebind();
                client.send_bytes(FIRST_CHANNEL_STREAM, b"darwin-rebind-proof\n".to_vec())
                    .map_err(|_| "post-rebind request failed")?;
                connected_until(|| events.output.lock().unwrap().windows(b"darwin-rebind-proof".len())
                    .any(|window| window == b"darwin-rebind-proof")).await?;
            }
            if mode != "manager-stop" && mode != "signal" {
                client.send_bytes(CONTROL_STREAM, encode_client(&ClientRecord::Close { stream: FIRST_CHANNEL_STREAM }))
                    .map_err(|_| "close enqueue failed")?;
                connected_until(|| events.records.lock().unwrap().iter().any(|record| {
                    matches!(record, ServerRecord::Exit { stream, .. } if *stream == FIRST_CHANNEL_STREAM)
                })).await?;
                connected_until(|| registry.outstanding() == 0).await?;
            }
            if mode == "fresh-session" {
                client.close();
                connected_until(|| registry.outstanding() == 0).await?;
                let fresh_keys = generate_keypair();
                allowlist.lock().unwrap().push(fresh_keys.public);
                let fresh_events = Arc::new(ConnectedEvents::default());
                let fresh = connect([2; 16], fresh_events.clone(), fresh_keys.private);
                let fresh_result = async {
                    connected_until(|| fresh_events.live.load(Ordering::SeqCst)).await?;
                    let open = OpenRequest {
                        stream: FIRST_CHANNEL_STREAM, kind: ChannelKind::Command,
                        cols: 80, rows: 24, screen: false, command: b"/bin/true".to_vec(),
                    };
                    fresh.send_bytes(CONTROL_STREAM, encode_client(&ClientRecord::Open(open)))
                        .map_err(|_| "fresh enqueue failed")?;
                    connected_until(|| fresh_events.records.lock().unwrap().iter().any(|record| {
                        matches!(record, ServerRecord::Exit { stream, code: 0 } if *stream == FIRST_CHANNEL_STREAM)
                    })).await
                }.await;
                fresh.close();
                fresh_result?;
            }
            if events.input_failed.load(Ordering::SeqCst) { return Err("client input failed"); }
            Ok(())
        }).await {
            Ok(result)=>result,
            Err(_)=>Err("connected body panicked or was cancelled"),
        }
    };
    // This is the manager-stop seam, not a claim about the wire STOP
    // endpoint. Always retain and await the real lifecycle drain.
    if let Some(directory) = signal_directory {
        publish(&directory.join("signal-ready"));
    } else {
        shutdown.request();
        client.close();
    }
    let joined = if mode == "observation-timeout" {
        // Exercise the failure route deterministically without a 30-second sleep.
        Err(
            tokio::time::timeout(Duration::ZERO, std::future::pending::<()>())
                .await
                .unwrap_err(),
        )
    } else {
        tokio::time::timeout(Duration::from_secs(30), &mut manager).await
    };
    let observation_timed_out = joined.is_err();
    let settled = match joined {
        Ok(value) => value,
        Err(_) => {
            // Never drop/abort the manager handle or its runtime on observation
            // timeout. Cooperative actor authority predates the Open request.
            publish(&actor_directory.join("abort"));
            client.close();
            shutdown.request();
            manager.await
        }
    };
    settled.unwrap().expect("actual manager/worker drain");
    client.close();
    assert_eq!(registry.outstanding(), 0);
    assert_eq!(registry.retiring_count(), 0);
    publish(&actor_directory.join("manager-joined"));
    assert!(
        !observation_timed_out,
        "manager observation deadline exceeded; joined after failure cleanup"
    );
    result.unwrap_or_else(|failure| panic!("connected mode={mode}: {failure}"));
    if let Some(directory) = signal_directory {
        publish(&directory.join("signal-joined"));
    }
    eprintln!(
        "darwin223 connected_mode={mode} lifecycle_join=normal open_obligations=0 retiring=0"
    );
}
#[test]
fn darwin223_native_connected_close_stop_rebind_and_fresh_session() {
    connected_authority_controls();
    let control_directory = tempfile::tempdir().unwrap();
    let mut control = Command::new(std::env::current_exe().unwrap());
    control
        .args([
            "--exact",
            "darwin_process_scope::native_tests::darwin223_owned_signal_server",
            "--nocapture",
        ])
        .env("QSH_DARWIN223_SIGNAL_SERVER", control_directory.path())
        .env("QSH_DARWIN223_COMMAND_CONTROLS", "1");
    assert!(bounded_command(
        &mut control,
        64 * 1024,
        Instant::now() + Duration::from_secs(10)
    )
    .unwrap()
    .status
    .success());
    for mode in [
        "channel-close",
        "manager-stop",
        "no-channel",
        "rebind",
        "fresh-session",
        "body-failure",
        "observation-timeout",
    ] {
        let directory = tempfile::tempdir().unwrap();
        let mut actors = ConnectedActorAuthority::new();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env("QSH_DARWIN223_CONNECTED_ACTORS", actors.path())
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_signal_server",
                "--nocapture",
            ])
            .env("QSH_DARWIN223_CONNECTED_SERVER", mode)
            .env("QSH_DARWIN223_SIGNAL_SERVER", directory.path());
        let output = bounded_command_observe(
            &mut command,
            64 * 1024,
            Instant::now() + Duration::from_secs(90),
            || actors.observe(),
        )
        .unwrap();
        let expected_failure = matches!(mode, "body-failure" | "observation-timeout");
        if !output.status.success() {
            actors.abort();
        }
        actors.finish(mode != "no-channel");
        assert_eq!(
            output.status.success(),
            !expected_failure,
            "connected fixture mode={mode}"
        );
        assert!(actors.path().join("manager-joined").exists());
        if !expected_failure {
            assert!(directory.path().join("connected-joined").exists());
        }
    }
}

struct ExitBeforeBind {
    native: NativeOps,
    directory: std::path::PathBuf,
    candidate: i32,
    attempted: bool,
    refused: bool,
}
impl Ops<super::native::PtyChild> for ExitBeforeBind {
    type Watch = super::native::Watch;
    type Token = super::native::Token;
    fn baseline(&mut self) -> Result<Vec<Classified>, Failure> {
        self.native.baseline()
    }
    fn raw_all(&mut self, pids: &mut [i32; CAPACITY]) -> Result<usize, Failure> {
        self.native.raw_all(pids)
    }
    fn confirm(&mut self, identity: Identity) -> Result<Identity, Failure> {
        self.native.confirm(identity)
    }
    fn classify(&mut self, pid: i32) -> Result<Classified, Failure> {
        self.native.classify(pid)
    }
    fn bind_exit(
        &mut self,
        process: Classified,
        cookie: u64,
    ) -> Result<Registration<Self::Watch>, Failure> {
        if process.identity.pid == self.candidate && !self.attempted {
            self.attempted = true;
            publish(&self.directory.join("candidate-exit"));
            until(|| self.directory.join("candidate-terminal").exists());
            let result = self.native.bind_exit(process, cookie);
            self.refused = matches!(&result,Err(Failure::Errno(code)) if *code==nix::libc::ESRCH);
            result
        } else {
            self.native.bind_exit(process, cookie)
        }
    }
    fn observe_exit(&mut self, watch: &mut Self::Watch) -> Result<Option<ExitEvent>, Failure> {
        self.native.observe_exit(watch)
    }
    fn acquire_signal_token(
        &mut self,
        identity: Identity,
        sid: i32,
    ) -> Result<SignalToken<Self::Token>, Failure> {
        self.native.acquire_signal_token(identity, sid)
    }
    fn signal_exact(&mut self, token: &Self::Token, signal: Signal) -> Result<(), Failure> {
        self.native.signal_exact(token, signal)
    }
    fn observe_leader(
        &mut self,
        child: &mut super::native::PtyChild,
    ) -> Result<Option<i32>, Failure> {
        self.native.observe_leader(child)
    }
    fn reap_leader(&mut self, child: &mut super::native::PtyChild) -> Result<i32, Failure> {
        self.native.reap_leader(child)
    }
}
#[test]
fn darwin223_native_exit_before_binding_exclusion_zombie_and_last_fork() {
    for mode in ["reaped", "zombie", "last-fork"] {
        let qualification = prepare().expect("production admission");
        let directory = tempfile::tempdir().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_actor",
                "--nocapture",
            ])
            .env("QSH_DARWIN223_ACTOR", directory.path())
            .env("QSH_DARWIN223_FORK_ROOT", "1")
            .env("QSH_DARWIN223_CASE", mode)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let sid = child.id() as i32;
        let (guard, child) = FixtureGuard::new(Box::new(child));
        let guard = guard.with_abort(directory.path());
        until(|| directory.path().join("foreign-parent-ready").exists());
        let read_pid = |name| {
            std::fs::read_to_string(directory.path().join(name))
                .unwrap()
                .parse::<i32>()
                .unwrap()
        };
        let candidate = read_pid("descendant-pid");
        let parent = read_pid("foreign-parent-pid");
        let mut native = NativeOps;
        assert_eq!(
            native.classify(candidate).unwrap().class,
            Class::Session(sid)
        );
        let foreign = native.classify(parent).unwrap();
        assert_eq!(foreign.class, Class::Session(parent));
        let token = native
            .acquire_signal_token(foreign.identity, parent)
            .unwrap();
        let watch = native.bind_exit(foreign, 1).unwrap();
        let mut parent_guard = DescendantGuard {
            token: token.handle,
            watch: watch.handle,
            normal_exit: false,
        };
        let candidate_value = native.classify(candidate).unwrap();
        let candidate_token = native
            .acquire_signal_token(candidate_value.identity, sid)
            .unwrap();
        let candidate_watch = native.bind_exit(candidate_value, 2).unwrap();
        // Independent fixture custody only; this receipt never enters Scope.
        let mut candidate_guard = DescendantGuard {
            token: candidate_token.handle,
            watch: candidate_watch.handle,
            normal_exit: false,
        };
        let mut scope = super::native::owned_scope(child, qualification);
        scope.request_stop();
        let mut ops = ExitBeforeBind {
            native,
            directory: directory.path().to_path_buf(),
            candidate,
            attempted: false,
            refused: false,
        };
        let first_deadline = Instant::now() + Duration::from_secs(10);
        while !ops.attempted {
            assert_ne!(scope.step(&mut ops), super::scope::Progress::Complete(0));
            assert!(
                Instant::now() < first_deadline,
                "owned discovery did not reach registration barrier"
            );
        }
        assert!(
            ops.refused,
            "actual registration unexpectedly admitted an already-terminal candidate"
        );
        assert_eq!(guard.waits.load(Ordering::SeqCst), 0);
        assert_eq!(scope.retained(), (1, 0));
        let mut grandchild = None;
        if mode == "last-fork" {
            until(|| directory.path().join("grandchild-ready").exists());
            let pid = read_pid("grandchild-pid");
            let current = ops.native.classify(pid).unwrap();
            let token = ops
                .native
                .acquire_signal_token(current.identity, sid)
                .unwrap();
            let watch = ops.native.bind_exit(current, 2).unwrap();
            grandchild = Some(DescendantGuard {
                token: token.handle,
                watch: watch.handle,
                normal_exit: false,
            });
        }
        publish(&directory.path().join("exit"));
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut captured_last_fork = mode != "last-fork";
        loop {
            let progress = scope.step(&mut ops);
            if mode == "last-fork" && scope.retained().1 > 0 {
                assert_eq!(guard.waits.load(Ordering::SeqCst), 0);
                captured_last_fork = true;
                scope.escalate();
            }
            if progress == super::scope::Progress::Complete(0) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "native candidate closure failed; mode={mode}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(captured_last_fork);
        guard.assert_normal();
        let (_, n, p) = scope.census().unwrap();
        assert!(n < CAPACITY && p.checked_add(20).is_some_and(|minimum| n < minimum));
        assert_eq!(
            scope.discharged_for_test(),
            if mode == "zombie" { (0, 1) } else { (1, 0) }
        );
        if mode == "zombie" {
            assert_eq!(ops.native.classify(candidate).unwrap().class, Class::Zombie);
        }
        if let Some(guard) = grandchild.as_mut() {
            guard.finish();
        }
        candidate_guard.finish();
        publish(&directory.path().join("finish"));
        until(|| directory.path().join("candidate-reaped").exists());
        parent_guard.finish();
        eprintln!("darwin223 candidate_mode={mode} binding=actual_refusal C={} N={} P={} later_pass=normal direct_wait=normal rescue=false",CAPACITY,n,p);
    }
}

fn bootstrap_command(
    udp: &std::net::UdpSocket,
    listener: &std::os::unix::net::UnixListener,
    child_gate: &std::os::unix::net::UnixStream,
    home: &Path,
    destination: &Path,
    client: [u8; 32],
    labels: &str,
) -> Command {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;
    let inherited = [
        udp.as_raw_fd(),
        listener.as_raw_fd(),
        child_gate.as_raw_fd(),
    ];
    assert!(inherited.iter().all(|fd| *fd > 2));
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "darwin_process_scope::native_tests::darwin223_owned_signal_server",
            "--nocapture",
        ])
        .env("QSH_DARWIN223_BOOTSTRAP", "1")
        .env("QSH_DARWIN223_SIGNAL_SERVER", home)
        .env("QSH_DARWIN223_PARENT", std::process::id().to_string())
        .env("QSH_DARWIN223_UDP", inherited[0].to_string())
        .env("QSH_DARWIN223_CONTROL", inherited[1].to_string())
        .env("QSH_DARWIN223_GATE", inherited[2].to_string())
        .env("QSH_DARWIN223_DESTINATION", destination)
        .env("QSH_DARWIN223_CACHE", home)
        .env(
            "QSH_DARWIN223_CONTROL_PATH",
            listener.local_addr().unwrap().as_pathname().unwrap(),
        )
        .env(
            "QSH_DARWIN223_CLIENT",
            crate::handover::encode_allowlist(&[client]).pop().unwrap(),
        )
        .env("HOME", home)
        .env("XDG_CONFIG_HOME", home.join("config"))
        .env("XDG_CACHE_HOME", home)
        .env("HISTFILE", "/dev/null")
        .env_remove("TMUX")
        .env(crate::state::TEST_BUILD_LABELS_ENV, labels)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            for fd in inherited {
                let flags = nix::libc::fcntl(fd, nix::libc::F_GETFD);
                if flags < 0
                    || nix::libc::fcntl(fd, nix::libc::F_SETFD, flags & !nix::libc::FD_CLOEXEC) < 0
                {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    command
}
fn bootstrap_gate(gate: &mut std::os::unix::net::UnixStream) -> std::io::Result<()> {
    use std::io::Read;
    let end = Instant::now() + Duration::from_secs(10);
    let mut frame = [0; 4];
    let mut used = 0;
    loop {
        let remaining = end
            .checked_duration_since(Instant::now())
            .filter(|value| !value.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "bootstrap gate deadline")
            })?;
        gate.set_read_timeout(Some(remaining))?;
        match gate.read(&mut frame[used..]) {
            Ok(0) if used == 3 && &frame[..3] == b"GO\n" => return Ok(()),
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "bootstrap GO frame",
                ))
            }
            Ok(n) => {
                used += n;
                if used > 3 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bootstrap trailing frame",
                    ));
                }
                if used == 3 && &frame[..3] != b"GO\n" {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bootstrap GO frame",
                    ));
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}
fn fixture_gate_controls() {
    use std::io::Write;
    for (frame, expected) in [
        (b"GO\n".as_slice(), true),
        (b"NO\n".as_slice(), false),
        (b"GO\nX".as_slice(), false),
        (b"".as_slice(), false),
    ] {
        let (mut parent, mut child) = std::os::unix::net::UnixStream::pair().unwrap();
        parent.write_all(frame).unwrap();
        parent.shutdown(std::net::Shutdown::Write).unwrap();
        assert_eq!(bootstrap_gate(&mut child).is_ok(), expected);
    }
}
fn bootstrap_actor() {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    let parent: u32 = std::env::var("QSH_DARWIN223_PARENT")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(unsafe { nix::libc::getppid() } as u32, parent);
    let fd = |name: &str| -> i32 { std::env::var(name).unwrap().parse().unwrap() };
    let fds = [
        fd("QSH_DARWIN223_UDP"),
        fd("QSH_DARWIN223_CONTROL"),
        fd("QSH_DARWIN223_GATE"),
    ];
    assert!(fds.iter().all(|fd| *fd > 2));
    assert!(fds[0] != fds[1] && fds[0] != fds[2] && fds[1] != fds[2]);
    // These descriptors are the three exclusively inherited actor inputs.
    let udp = unsafe { std::net::UdpSocket::from_raw_fd(fds[0]) };
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fds[1]) };
    let mut gate = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fds[2]) };
    for fd in fds {
        crate::handover::set_cloexec(fd, true).unwrap();
    }
    let path = |name: &str| {
        let value = std::path::PathBuf::from(std::env::var_os(name).unwrap());
        assert!(value.is_absolute() && value.as_os_str().as_bytes().len() <= 1024);
        assert!(!value.components().any(|part| matches!(
            part,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )));
        value
    };
    let destination = path("QSH_DARWIN223_DESTINATION");
    let cache = path("QSH_DARWIN223_CACHE");
    let control = path("QSH_DARWIN223_CONTROL_PATH");
    let client = std::env::var("QSH_DARWIN223_CLIENT").unwrap();
    assert_eq!(client.len(), 44);
    crate::handover::decode_allowlist(std::slice::from_ref(&client)).unwrap();
    let port = udp.local_addr().unwrap().port();
    assert_eq!(
        listener.local_addr().unwrap().as_pathname(),
        Some(control.as_path())
    );
    bootstrap_gate(&mut gate).unwrap();
    drop(gate);
    let staged = destination.with_file_name(format!(".qshd-update-{}-a223", std::process::id()));
    let handover = crate::handover::Handover {
        handover_version: crate::state::HANDOVER_VERSION,
        binary_path: destination,
        staged_path: staged.clone(),
        udp_fd: udp.as_raw_fd(),
        control_fd: listener.as_raw_fd(),
        control_path: control,
        cache_dir: cache,
        port,
        ports: vec![port],
        name: "main".into(),
        allowlist: vec![client],
    };
    let state = crate::handover::write_memfd(&handover).unwrap();
    let retained = [udp.as_raw_fd(), listener.as_raw_fd(), state.as_raw_fd()];
    crate::handover::close_on_exec_except(&retained).unwrap();
    for fd in retained {
        crate::handover::set_cloexec(fd, false).unwrap();
    }
    let failure = crate::handover::exec_staged(&staged, state.as_raw_fd());
    for fd in retained {
        crate::handover::set_cloexec(fd, true).unwrap();
    }
    panic!("owned bootstrap exec refused: {failure}");
}
#[test]
fn darwin223_owned_signal_server() {
    let Some(directory) = std::env::var_os("QSH_DARWIN223_SIGNAL_SERVER") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    if std::env::var_os("QSH_DARWIN223_BOOTSTRAP").is_some() {
        bootstrap_actor();
        return;
    }
    if std::env::var_os("QSH_DARWIN223_COMMAND_CONTROLS").is_some() {
        fixture_command_controls();
        fixture_gate_controls();
        return;
    }
    let mode = std::env::var("QSH_DARWIN223_CONNECTED_SERVER").ok();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(connected_case(
            mode.as_deref().unwrap_or("signal"),
            if mode.is_some() {
                None
            } else {
                Some(&directory)
            },
        ));
    publish(&directory.join("connected-joined"));
}
#[test]
fn darwin223_native_term_and_interrupt_join_real_manager_and_workers() {
    for signal in [nix::libc::SIGTERM, nix::libc::SIGINT] {
        let directory = tempfile::tempdir().unwrap();
        let mut actors = ConnectedActorAuthority::new();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_signal_server",
                "--nocapture",
            ])
            .env("QSH_DARWIN223_SIGNAL_SERVER", directory.path())
            .env("QSH_DARWIN223_CONNECTED_ACTORS", actors.path())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            until(|| {
                actors.observe();
                directory.path().join("signal-ready").exists()
            });
            assert!(
                child.try_wait().unwrap().is_none(),
                "signal fixture exited before the owned signal"
            );
            // The exact direct Child is still unreaped and reserves this PID.
            // This fixture operation is not a metadata-derived production fallback.
            assert_eq!(unsafe { nix::libc::kill(child.id() as i32, signal) }, 0);
            let end = Instant::now() + Duration::from_secs(35);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    break status;
                }
                assert!(Instant::now() < end, "owned signal helper deadline");
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(status.success());
            assert!(directory.path().join("signal-observed").exists());
            assert!(directory.path().join("signal-joined").exists());
        }));
        if result.is_err() {
            actors.abort();
        }
        if result.is_err() && matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
            let _ = child.wait();
        }
        actors.finish(true);
        result.unwrap();
    }
}

#[test]
fn darwin223_native_partial_descriptor_failure_retains_real_process_owner() {
    use transport::channel_open::{
        ChannelOpenRegistry, OpenCustody, SpawnFailure, UninstalledChannel,
    };
    use transport::channel_server::ChannelSpawner;
    struct FailingSpawner {
        registry: Arc<ChannelOpenRegistry>,
        reader_failure: bool,
        guards: Mutex<Vec<FixtureGuard>>,
    }
    impl ChannelSpawner for FailingSpawner {
        fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
            self.registry.clone()
        }
        fn spawn(
            &self,
            _: &transport::auth::Principal,
            _: transport::session_manager::LoginId,
            _: &transport::channel::OpenRequest,
            _: Option<&str>,
            custody: &OpenCustody,
        ) -> Result<UninstalledChannel, SpawnFailure> {
            let qualification =
                prepare().map_err(|error| custody.refuse_before_creation(error.to_string()))?;
            let (master, child) = crate::pty::spawn_command_no_echo(
                crate::pty::DEFAULT_PTY_SIZE,
                portable_pty::CommandBuilder::new("/bin/cat"),
                None,
            )
            .map_err(|error| custody.refuse_before_creation(error.to_string()))?;
            let (guard, child) = FixtureGuard::new(child);
            self.guards.lock().unwrap().push(guard);
            let wait = own_child(child, qualification);
            crate::channel_backend::darwin_setup_failure_for_test(
                master,
                wait,
                custody,
                self.reader_failure,
            )
        }
    }
    for reader_failure in [true, false] {
        let spawner = FailingSpawner {
            registry: ChannelOpenRegistry::new(Default::default()),
            reader_failure,
            guards: Mutex::new(Vec::new()),
        };
        let owner = transport::auth::Principal {
            uid: unsafe { nix::libc::getuid() },
            name: "darwin-custody-fixture".into(),
            identity: "fixture".into(),
            incarnation: 0,
        };
        let request = transport::channel::OpenRequest {
            stream: transport::channel::FIRST_CHANNEL_STREAM,
            kind: transport::channel::ChannelKind::Command,
            cols: 80,
            rows: 24,
            screen: false,
            command: b"/bin/cat".to_vec(),
        };
        assert!(
            crate::channel_backend::fixture_spawn(&spawner, &owner, [1; 16], &request, None)
                .is_err()
        );
        let guards = spawner.guards.lock().unwrap();
        assert_eq!(guards.len(), 1);
        guards[0].assert_normal();
        assert_eq!(spawner.registry.outstanding(), 0);
        assert_eq!(spawner.registry.retiring_count(), 0);
        eprintln!(
            "darwin223 injected_descriptor_failure={} actual_native_cleanup=normal rescue=false",
            if reader_failure { "reader" } else { "writer" }
        );
    }
}

fn hash_path(path: &Path) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path).unwrap();
    assert!(file.metadata().unwrap().len() <= 512 * 1024 * 1024);
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buffer).unwrap();
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    hash.finalize().into()
}
fn daemon_status(path: &Path) -> Option<crate::control::StatusResponse> {
    match crate::control::client_request(path, &crate::control::ControlRequest::Status) {
        Ok(crate::control::ControlReply::Answered(line)) => {
            crate::control::StatusResponse::from_line(&line).ok()
        }
        _ => None,
    }
}
struct DirectDaemonGuard {
    owner: OwnedCommand,
    socket: std::path::PathBuf,
    identity: Option<Classified>,
    watch: Option<super::native::Watch>,
    normal: bool,
    rescues: usize,
}
impl DirectDaemonGuard {
    fn arm(&mut self) {
        until(|| daemon_status(&self.socket).is_some());
        let status = daemon_status(&self.socket).unwrap();
        assert_eq!(status.pid, self.owner.child.id());
        assert!(self.owner.poll().unwrap().is_none());
        let mut ops = NativeOps;
        let identity = ops.classify(status.pid as i32).unwrap();
        self.watch = Some(ops.bind_exit(identity, 1).unwrap().handle);
        assert_eq!(daemon_status(&self.socket).unwrap().pid, status.pid);
        self.identity = Some(identity);
    }
    fn stop_normally(&mut self) {
        crate::control::client_request(&self.socket, &crate::control::ControlRequest::Stop)
            .expect("normal wire STOP request");
        let watch = self.watch.as_mut().expect("bound daemon exit authority");
        let mut ops = NativeOps;
        until(|| ops.observe_exit(watch).unwrap().is_some());
        assert!(self
            .owner
            .finish(Instant::now() + Duration::from_secs(10))
            .unwrap()
            .success());
        self.normal = true;
        assert_eq!(self.rescues, 0);
    }
}
impl Drop for DirectDaemonGuard {
    fn drop(&mut self) {
        if self.normal {
            return;
        }
        let _ = crate::control::client_request(&self.socket, &crate::control::ControlRequest::Stop);
        let mut ops = NativeOps;
        if let Some(watch) = self.watch.as_mut() {
            let end = Instant::now() + Duration::from_secs(15);
            while Instant::now() < end {
                if matches!(ops.observe_exit(watch), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
        if let Some(original) = self.identity {
            if let Ok(current) = ops.classify(original.identity.pid) {
                if current.identity.same_process(original.identity)
                    && current.class == original.class
                {
                    if let Class::Session(sid) = current.class {
                        if let Ok(token) = ops.acquire_signal_token(current.identity, sid) {
                            self.rescues += 1;
                            let _ = ops.signal_exact(&token.handle, Signal::Kill);
                        }
                    }
                }
            }
        }
        if let Some(watch) = self.watch.as_mut() {
            let end = Instant::now() + Duration::from_secs(5);
            while Instant::now() < end {
                if matches!(ops.observe_exit(watch), Ok(Some(_))) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}
// Exclusive unreaped Child custody starts immediately after spawn.
struct OwnedCommand {
    child: std::process::Child,
    status: Option<std::process::ExitStatus>,
    transferred: bool,
}
impl OwnedCommand {
    fn spawn(command: &mut Command) -> std::io::Result<Self> {
        Ok(Self {
            child: command.spawn()?,
            status: None,
            transferred: false,
        })
    }
    fn transfer_to_bound_controller(mut self) {
        // Only the actor's controller-bound gate may discharge this fixture
        // direct-child reservation to already retained exact native authority.
        self.transferred = true;
    }
    fn poll(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }
    fn finish(&mut self, end: Instant) -> std::io::Result<std::process::ExitStatus> {
        loop {
            if let Some(status) = self.poll()? {
                return Ok(status);
            }
            if Instant::now() >= end {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "fixture child deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl Drop for OwnedCommand {
    fn drop(&mut self) {
        if self.transferred {
            return;
        }
        self.child.stdout.take();
        self.child.stderr.take();
        if self.status.is_none() {
            match self.child.try_wait() {
                Ok(Some(status)) => self.status = Some(status),
                Ok(None) => {
                    let _ = self.child.kill();
                    self.status = Some(self.child.wait().expect("fixture rescue consuming wait"));
                }
                Err(error) => panic!("fixture custody could not settle: {error}"),
            }
        }
    }
}
fn bounded_command(
    command: &mut Command,
    cap: usize,
    end: Instant,
) -> std::io::Result<std::process::Output> {
    bounded_command_observe(command, cap, end, || {})
}
fn bounded_command_observe(
    command: &mut Command,
    cap: usize,
    end: Instant,
    mut observe: impl FnMut(),
) -> std::io::Result<std::process::Output> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut owner = OwnedCommand::spawn(command)?;
    let mut stdout = owner.child.stdout.take();
    let mut stderr = owner.child.stderr.take();
    for fd in [
        stdout.as_ref().unwrap().as_raw_fd(),
        stderr.as_ref().unwrap().as_raw_fd(),
    ] {
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        if flags < 0
            || unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) }
                < 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    let mut out = Vec::new();
    let mut err = Vec::new();
    loop {
        observe();
        // Finite work per turn, even for a continuously noisy child.
        fn drain<R: Read>(pipe: &mut Option<R>, bytes: &mut Vec<u8>) -> std::io::Result<()> {
            if let Some(stream) = pipe.as_mut() {
                let mut buffer = [0; 4096];
                match stream.read(&mut buffer) {
                    Ok(0) => {
                        *pipe = None;
                    }
                    Ok(n) => bytes.extend_from_slice(&buffer[..n]),
                    Err(error)
                        if matches!(
                            error.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(error) => return Err(error),
                }
            }
            Ok(())
        }
        drain(&mut stdout, &mut out)?;
        drain(&mut stderr, &mut err)?;
        if out.len() + err.len() > cap {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "fixture output cap",
            ));
        }
        if let Some(status) = owner.poll()? {
            if stdout.is_none() && stderr.is_none() {
                return Ok(std::process::Output {
                    status,
                    stdout: out,
                    stderr: err,
                });
            }
        }
        if Instant::now() >= end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "fixture output deadline",
            ));
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}
fn fixture_command_controls() {
    let end = Instant::now() + Duration::from_secs(2);
    let output = bounded_command(
        Command::new("/bin/sh").args(["-c", "printf ready; printf diagnostic >&2"]),
        128,
        end,
    )
    .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"ready");
    assert_eq!(output.stderr, b"diagnostic");
    let error = bounded_command(
        Command::new("/bin/sh").args(["-c", "exec /bin/sleep 5"]),
        128,
        Instant::now() + Duration::from_millis(30),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let error = bounded_command(
        Command::new("/bin/sh").args(["-c", "while :; do printf 01234567890123456789; done"]),
        32,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
    let output = bounded_command(
        Command::new("/bin/sh").args(["-c", "exit 7"]),
        32,
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(output.status.code(), Some(7));
    // No child can remain waitable after either refusal or normal completion.
    let mut status = 0;
    assert_eq!(
        unsafe { nix::libc::waitpid(-1, &mut status, nix::libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(nix::libc::ECHILD)
    );
}
fn actual_self_check(binary: &Path, labels: Option<&str>) -> crate::state::SelfCheck {
    let mut command = Command::new(binary);
    command
        .arg("self-check")
        .env_remove(crate::state::TEST_BUILD_LABELS_ENV)
        .env_remove(crate::handover::HANDOVER_FD_ENV)
        .env("HISTFILE", "/dev/null");
    if let Some(labels) = labels {
        command.env(crate::state::TEST_BUILD_LABELS_ENV, labels);
    }
    let output =
        bounded_command(&mut command, 4096, Instant::now() + Duration::from_secs(10)).unwrap();
    assert!(output.status.success());
    assert!(output.stdout.len() <= 4096);
    crate::state::SelfCheck::from_line(std::str::from_utf8(&output.stdout).unwrap().trim()).unwrap()
}
fn fixture_tool(program: &str, args: &[&std::ffi::OsStr]) {
    let output = bounded_command(
        Command::new(program).args(args),
        64 * 1024,
        Instant::now() + Duration::from_secs(15),
    )
    .expect("bounded fixture transform");
    assert!(output.status.success(), "required fixture transform failed");
}
fn actual_connect(
    port: u16,
    server_pub: [u8; 32],
    client_priv: [u8; 32],
    token: [u8; 16],
) -> (transport::driver_std::StdClient, Arc<ConnectedEvents>) {
    let events = Arc::new(ConnectedEvents::default());
    let client = transport::driver_std::StdClient::connect(
        ([127, 0, 0, 1], port).into(),
        transport::ConnectionConfig {
            required_features: transport::Features::CHANNEL_GEOMETRY
                | transport::Features::AUTH_ACCEPTED,
            features: transport::Features::SUPPORTED,
            role: transport::Role::Client,
            local_static_priv: client_priv,
            remote_static_pub: Some(server_pub),
            auth: transport::AuthPolicy::Allowlist(Vec::new()),
        },
        token,
        transport::StartKind::Cold,
        Arc::new(ConnectedBinder),
        events.clone(),
        None,
    );
    until(|| events.live.load(Ordering::SeqCst));
    (client, events)
}
#[test]
fn darwin223_native_actual_daemon_replacement_reaps_parked_scope_and_fresh_session() {
    use std::ffi::OsStr;
    use std::os::fd::AsRawFd;
    use transport::channel::{
        encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord, UpdateAnswer,
        UpdateOffer, UpdateResult, CONTROL_STREAM, FIRST_CHANNEL_STREAM, UPDATE_STREAM,
    };
    prepare().expect("production runtime admission");
    let original = std::path::PathBuf::from(
        std::env::var_os("QSH_DARWIN223_DAEMON").expect("required source-bound Cargo daemon path"),
    );
    assert!(original.is_absolute() && original.is_file());
    let original_hash = hash_path(&original);
    assert_eq!(
        hex::encode(original_hash),
        std::env::var("QSH_DARWIN223_DAEMON_SHA256").expect("required Cargo artifact digest")
    );
    let original_check = actual_self_check(&original, None);
    let copies = tempfile::tempdir().unwrap();
    let old = copies.path().join("qshd");
    let new = copies.path().join("new-qshd");
    for (path, identifier) in [
        (&old, "org.qsh.fixture.darwin223.old"),
        (&new, "org.qsh.fixture.darwin223.new"),
    ] {
        fixture_tool("/bin/cp", &[original.as_os_str(), path.as_os_str()]);
        fixture_tool("/usr/bin/strip", &[path.as_os_str()]);
        fixture_tool(
            "/usr/bin/codesign",
            &[
                OsStr::new("--force"),
                OsStr::new("--sign"),
                OsStr::new("-"),
                OsStr::new("--timestamp=none"),
                OsStr::new("--identifier"),
                OsStr::new(identifier),
                path.as_os_str(),
            ],
        );
        fixture_tool(
            "/usr/bin/codesign",
            &[
                OsStr::new("--verify"),
                OsStr::new("--strict"),
                path.as_os_str(),
            ],
        );
    }
    let old_hash = hash_path(&old);
    let new_hash = hash_path(&new);
    assert_ne!(old_hash, new_hash);
    assert_eq!(
        hash_path(&original),
        original_hash,
        "never mutate the required Cargo artifact"
    );
    let old_check = actual_self_check(&old, None);
    assert_eq!(old_check.build, original_check.build);
    assert_eq!(old_check.arch, std::env::consts::ARCH);
    let new_build = old_check.build.checked_add(1).unwrap();
    let labels = format!("{}={new_build}", hex::encode(new_hash));
    assert_eq!(actual_self_check(&new, Some(&labels)).build, new_build);
    assert!(std::fs::metadata(&new).unwrap().len() <= crate::update::MAX_UPDATE_SIZE);
    let image = std::fs::read(&new).unwrap();
    assert!(image.len() as u64 <= crate::update::MAX_UPDATE_SIZE);
    eprintln!("darwin223 Cargo_binary_sha256={} original_build={} old_fixture_sha256={} new_fixture_sha256={} new_test_label={} profile=fixture-only-ad-hoc-signatures",hex::encode(original_hash),original_check.build,hex::encode(old_hash),hex::encode(new_hash),new_build);
    let home = tempfile::tempdir().unwrap();
    let actor_directory = tempfile::tempdir().unwrap();
    let socket = home.path().join("qsh/control.sock");
    let first = transport::handshake::generate_keypair();
    let parked_key = transport::handshake::generate_keypair();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let listener = crate::control::bind_private(&socket).unwrap();
    let server_pub =
        crate::load_or_create_transport_key(&home.path().join("transport_server_key.bin"))
            .unwrap()
            .public;
    for frame in [b"NO\n".as_slice(), b"".as_slice(), b"GO\n".as_slice()] {
        use std::io::Write;
        let (mut gate, child_gate) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut command = bootstrap_command(
            &udp,
            &listener,
            &child_gate,
            home.path(),
            &old,
            first.public,
            &labels,
        );
        let mut owner = OwnedCommand::spawn(&mut command).unwrap();
        drop(child_gate);
        gate.set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        gate.write_all(frame).unwrap();
        gate.shutdown(std::net::Shutdown::Write).unwrap();
        drop(gate);
        // Valid GO deliberately has no PID stage here: actual exec must fail,
        // and its exclusively owned actor must be consumed, never detached.
        assert!(!owner
            .finish(Instant::now() + Duration::from_secs(10))
            .unwrap()
            .success());
        assert!(owner.status.is_some());
    }
    {
        let (_gate, child_gate) = std::os::unix::net::UnixStream::pair().unwrap();
        let mut command = bootstrap_command(
            &udp,
            &listener,
            &child_gate,
            home.path(),
            &old,
            first.public,
            &labels,
        );
        let owner = OwnedCommand::spawn(&mut command).unwrap();
        let pid = owner.child.id() as i32;
        drop(owner);
        drop(child_gate);
        let mut status = 0;
        assert_eq!(
            unsafe { nix::libc::waitpid(pid, &mut status, nix::libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::ECHILD)
        );
    }
    let (mut gate, child_gate) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut command = bootstrap_command(
        &udp,
        &listener,
        &child_gate,
        home.path(),
        &old,
        first.public,
        &labels,
    );
    let owner = OwnedCommand::spawn(&mut command).unwrap();
    let mut daemon = DirectDaemonGuard {
        owner,
        socket: socket.clone(),
        identity: None,
        watch: None,
        normal: false,
        rescues: 0,
    };
    drop((udp, listener, child_gate));
    let staged = old.with_file_name(format!(".qshd-update-{}-a223", daemon.owner.child.id()));
    // Fresh distinct inode, preserving the already reviewed signed image.
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    let mut source = std::fs::File::open(&old).unwrap();
    let mut target = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&staged)
        .unwrap();
    let copied = std::io::copy(
        &mut Read::by_ref(&mut source).take(crate::update::MAX_UPDATE_SIZE + 1),
        &mut target,
    )
    .unwrap();
    assert!(copied <= crate::update::MAX_UPDATE_SIZE);
    target
        .set_permissions(std::fs::Permissions::from_mode(0o700))
        .unwrap();
    target.sync_all().unwrap();
    drop(target);
    drop(source);
    assert_eq!(hash_path(&staged), old_hash);
    gate.set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    gate.write_all(b"GO\n").unwrap();
    gate.shutdown(std::net::Shutdown::Write).unwrap();
    drop(gate);
    eprintln!("darwin223 bootstrap=validated_direct_owned_handover initial_detachment=unqualified");
    daemon.arm();
    let before = daemon_status(&socket).unwrap();
    assert_eq!(before.build, old_check.build);
    assert_eq!(before.version, env!("CARGO_PKG_VERSION"));
    assert_eq!(
        original_check.protocol,
        transport::channel::PROTOCOL_VERSION
    );
    eprintln!(
        "darwin223 actual_daemon_version={} arch={} protocol={} build={}",
        before.version, original_check.arch, original_check.protocol, original_check.build
    );
    assert_eq!(before.ports.len(), 1);
    assert_eq!(before.ports[0].port, port);
    crate::control::client_request(
        &socket,
        &crate::control::ControlRequest::AddClient(parked_key.public),
    )
    .unwrap();
    struct AbortActor<'a>(&'a Path);
    impl Drop for AbortActor<'_> {
        fn drop(&mut self) {
            publish(&self.0.join("abort"));
        }
    }
    // Installed before Open enqueue; leader retains its real child until the
    // controller binds both watches, and observes abort even before Opened.
    let _actor_abort = AbortActor(actor_directory.path());
    let (parked, parked_events) = actual_connect(port, server_pub, parked_key.private, [9; 16]);
    let executable = std::env::current_exe().unwrap();
    assert!(!executable.to_str().unwrap().contains('\''));
    assert!(!actor_directory.path().to_str().unwrap().contains('\''));
    let command=format!("/usr/bin/env QSH_DARWIN223_ACTOR='{}' QSH_DARWIN223_PTY_LEADER=1 QSH_DARWIN223_HOLD_LEADER=1 '{}' --exact darwin_process_scope::native_tests::darwin223_owned_actor --nocapture",actor_directory.path().display(),executable.display());
    parked
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: command.into_bytes(),
            })),
        )
        .unwrap();
    until(|| {
        parked_events
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|record| matches!(record, ServerRecord::Opened { .. }))
    });
    until(|| actor_directory.path().join("descendant-ready").exists());
    let descendant_pid = std::fs::read_to_string(actor_directory.path().join("descendant-pid"))
        .unwrap()
        .parse::<i32>()
        .unwrap();
    let mut ops = NativeOps;
    let desc = ops.classify(descendant_pid).unwrap();
    let Class::Session(sid) = desc.class else {
        panic!("live owned descendant required");
    };
    let leader = ops.classify(sid).unwrap();
    assert_eq!(leader.class, Class::Session(sid));
    let desc_token = ops.acquire_signal_token(desc.identity, sid).unwrap();
    let desc_watch = ops.bind_exit(desc, 1).unwrap();
    let mut desc_guard = DescendantGuard {
        token: desc_token.handle,
        watch: desc_watch.handle,
        normal_exit: false,
    };
    let leader_token = ops.acquire_signal_token(leader.identity, sid).unwrap();
    let leader_watch = ops.bind_exit(leader, 2).unwrap();
    let mut leader_guard = DescendantGuard {
        token: leader_token.handle,
        watch: leader_watch.handle,
        normal_exit: false,
    };
    publish(&actor_directory.path().join("controller-bound"));
    parked.detach();
    until(|| daemon_status(&socket).is_some_and(|status| status.total_connections == 0));
    let (client, events) = actual_connect(port, server_pub, first.private, [1; 16]);
    assert_eq!(
        ops.classify(sid).unwrap().identity.unique,
        leader.identity.unique
    );
    assert_eq!(
        ops.classify(descendant_pid).unwrap().identity.unique,
        desc.identity.unique
    );
    client
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::UpdateOffer(UpdateOffer {
                build: new_build,
                checksum: new_hash,
                arch: std::env::consts::ARCH.into(),
                size: image.len() as u64,
            })),
        )
        .unwrap();
    until(|| {
        events
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|record| *record == ServerRecord::UpdateAnswer(UpdateAnswer::Accept))
    });
    let upload_end = Instant::now() + Duration::from_secs(60);
    for chunk in image.chunks(64 * 1024) {
        let remaining = upload_end
            .checked_duration_since(Instant::now())
            .expect("bounded whole upload");
        client
            .send_bytes_bounded(UPDATE_STREAM, chunk.to_vec(), remaining)
            .unwrap();
    }
    let restart_end = Instant::now() + Duration::from_secs(60);
    while !events
        .records
        .lock()
        .unwrap()
        .iter()
        .any(|record| *record == ServerRecord::UpdateResult(UpdateResult::Restarting))
    {
        assert!(
            Instant::now() < restart_end,
            "actual replacement receipt deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    client.detach();
    until(|| daemon_status(&socket).is_some_and(|status| status.build == new_build));
    let after = daemon_status(&socket).unwrap();
    assert_eq!(after.pid, before.pid);
    assert_eq!(after.ports, before.ports);
    assert_eq!(after.checksum, hex::encode(new_hash));
    assert_eq!(hash_path(&old), new_hash);
    let resumed = ops.classify(after.pid as i32).unwrap();
    let original_identity = daemon.identity.unwrap();
    assert!(resumed.identity.same_process(original_identity.identity));
    assert_ne!(resumed.identity.version, original_identity.identity.version);
    leader_guard.finish();
    desc_guard.finish();
    assert!(
        !ops.identity(sid)
            .is_ok_and(|value| value.same_process(leader.identity)),
        "old direct leader must be physically reaped before exec"
    );
    let (fresh, fresh_events) = actual_connect(port, server_pub, first.private, [2; 16]);
    fresh
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: b"/bin/true".to_vec(),
            })),
        )
        .unwrap();
    until(|| {
        fresh_events
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|record| matches!(record, ServerRecord::Exit { code: 0, .. }))
    });
    fresh.close();
    daemon.stop_normally();
    assert_eq!(daemon.rescues, 0);
    assert_eq!(hash_path(&original), original_hash);
    eprintln!("darwin223 actual_update=exec same_pid=true execution_version=fresh parked_leader=reaped descendant=exited fresh_channel=completed wire_STOP=normal rescue=false");
}
