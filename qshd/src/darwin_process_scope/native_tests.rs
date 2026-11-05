//! Actual Darwin qualification; never selected on a non-Darwin host.
use super::native::{own_child, prepare, NativeOps};
use super::*;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use transport::channel_server::ChildStatus;

use super::keeper_integration_tests::{
    parse_replacement_actor_report, parse_replacement_descendant_report, parse_replacement_stage,
    replacement_terminal, valid_replacement_nonce, validate_replacement_binding,
    validate_replacement_topology, ReplacementActorProjection, ReplacementActorReport,
    ReplacementActorRole, ReplacementActorStage, ReplacementTopology,
};

fn replacement_exclusive(directory: &Path, name: &str, bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    assert!(bytes.len() <= 1024);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(directory.join(name))
        .expect("exclusive replacement fixture record");
    file.write_all(bytes)
        .expect("bounded replacement fixture record");
    drop(file);
    let ready = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(directory.join(format!("{name}-ready")))
        .expect("exclusive replacement ready marker");
    drop(ready);
}
fn replacement_private_file(path: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { nix::libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() > 1024
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(1025).read_to_end(&mut bytes).ok()?;
    (bytes.len() <= 1024).then_some(bytes)
}
fn replacement_private_read(directory: &Path, name: &str) -> Option<Vec<u8>> {
    if !replacement_private_file(&directory.join(format!("{name}-ready")))?.is_empty() {
        return None;
    }
    replacement_private_file(&directory.join(name))
}
fn replacement_stage_publish(
    directory: &Path,
    nonce: &str,
    role: ReplacementActorRole,
    stage: ReplacementActorStage,
) {
    assert!(valid_replacement_nonce(nonce));
    replacement_exclusive(
        directory,
        &format!("replacement-stage-{}", stage.token()),
        format!(
            "qsh223-stage-v1 nonce={nonce} role={} stage={}\n",
            role.token(),
            stage.token()
        )
        .as_bytes(),
    );
}
fn replacement_stage_observe(
    directory: &Path,
    nonce: Option<&str>,
) -> Option<ReplacementActorProjection> {
    let nonce = nonce?;
    for stage in [
        ReplacementActorStage::DescendantPublished,
        ReplacementActorStage::Refused,
        ReplacementActorStage::Accepted,
        ReplacementActorStage::Sampled,
        ReplacementActorStage::Entry,
    ] {
        if let Some(raw) =
            replacement_private_read(directory, &format!("replacement-stage-{}", stage.token()))
        {
            let record = parse_replacement_stage(&raw, nonce).ok()?;
            if record.stage != stage {
                return None;
            }
            return Some(record);
        }
    }
    None
}
fn replacement_actor_sample(role: ReplacementActorRole) -> Result<ReplacementActorReport, Failure> {
    let mut ops = NativeOps;
    let pid = std::process::id() as i32;
    let before = ops.identity(pid)?;
    let sid = unsafe { nix::libc::getsid(0) };
    if sid <= 0 {
        return Err(Failure::Invalid);
    }
    let session = ops.identity(sid)?;
    let group = unsafe { nix::libc::getpgrp() };
    let foreground = unsafe { nix::libc::tcgetpgrp(0) };
    let tty = unsafe { nix::libc::isatty(0) } == 1;
    if ops.identity(pid)? != before
        || ops.identity(sid)? != session
        || unsafe { nix::libc::getsid(0) } != sid
        || unsafe { nix::libc::getpgrp() } != group
        || unsafe { nix::libc::tcgetpgrp(0) } != foreground
        || (unsafe { nix::libc::isatty(0) } == 1) != tty
    {
        return Err(Failure::LostBinding);
    }
    Ok(ReplacementActorReport {
        role,
        topology: ReplacementTopology {
            application: before,
            session,
            sid,
            group,
            foreground,
            tty,
        },
    })
}
fn replacement_report_publish(directory: &Path, nonce: &str, report: ReplacementActorReport) {
    let t = report.topology;
    let a = t.application;
    let s = t.session;
    replacement_exclusive(directory,"replacement-actor",format!("qsh223-actor-v1 nonce={nonce} role={} a={}:{}:{} s={}:{}:{} sid={} pgrp={} fg={} tty={}\n",report.role.token(),a.pid,a.unique,a.version,s.pid,s.unique,s.version,t.sid,t.group,t.foreground,u8::from(t.tty)).as_bytes());
}
fn replacement_descendant_publish(directory: &Path, nonce: &str) {
    assert!(valid_replacement_nonce(nonce));
    let mut ops = NativeOps;
    let pid = std::process::id() as i32;
    let before = ops.identity(pid).unwrap();
    let sid = unsafe { nix::libc::getsid(0) };
    let group = unsafe { nix::libc::getpgrp() };
    assert_eq!(before, ops.identity(pid).unwrap());
    assert_eq!(unsafe { nix::libc::getsid(0) }, sid);
    assert_eq!(unsafe { nix::libc::getpgrp() }, group);
    assert_eq!(group, pid);
    assert_eq!(ops.keeper_group(before, sid).unwrap(), group);
    replacement_exclusive(
        directory,
        "replacement-descendant",
        format!(
            "qsh223-desc-v1 nonce={nonce} d={}:{}:{} sid={sid} pgrp={group}\n",
            before.pid, before.unique, before.version
        )
        .as_bytes(),
    );
}
fn replacement_kernel_binding(
    identity: Identity,
    sid: i32,
    group: i32,
) -> Result<Classified, Failure> {
    let mut ops = NativeOps;
    let actual = ops.classify(identity.pid)?;
    let observed_group = ops.keeper_group(identity, sid)?;
    validate_replacement_binding(identity, actual, sid, observed_group, group)
        .map_err(|_| Failure::LostBinding)?;
    Ok(actual)
}
fn replacement_guard(identity: Classified, sid: i32, cookie: u64) -> DescendantGuard {
    let mut ops = NativeOps;
    let token = ops.acquire_signal_token(identity.identity, sid).unwrap();
    let watch = ops.bind_exit(identity, cookie).unwrap();
    DescendantGuard {
        token: token.handle,
        watch: watch.handle,
        normal_exit: false,
    }
}
fn replacement_absent(identity: Identity) -> bool {
    super::keeper_integration_tests::replacement_identity_absent(
        identity,
        NativeOps.identity(identity.pid),
    )
}

// Retain the actual fixture Child independently of the production wrapper so
// assertion failure cannot discard it. Rescue is failure-only, never evidence.
#[derive(Debug)]
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
// Closed fixture metadata only. A checkpoint is the last complete recorded
// stage; its registry sample and the later marker observations are not atomic.
const SIGNAL_RECORD_LIMIT: usize = 1024;
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SignalCheckpointStage {
    Ready,
    SignalObserved,
    ObservationTimeout,
    ManagerJoined,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignalSnapshot {
    pending: usize,
    retiring: usize,
    debt: usize,
    unconfirmed: usize,
    leader_unknown: bool,
    cleanup_unknown: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct SignalCheckpoint {
    schema: u8,
    stage: SignalCheckpointStage,
    snapshot: Option<SignalSnapshot>,
}
fn signal_checkpoint(
    stage: SignalCheckpointStage,
    sample: impl FnOnce() -> Option<transport::channel_open::CleanupSnapshot>,
) -> SignalCheckpoint {
    let snapshot = sample().and_then(|value| {
        // Pending includes both healthy and canceled registered opens.
        Some(SignalSnapshot {
            pending: value
                .healthy_pending_opens
                .checked_add(value.canceled_opens)?,
            retiring: value.retiring_channels,
            debt: value.unique_cleanup_debt,
            unconfirmed: value.observed_unconfirmed_owners,
            leader_unknown: value.leader_unconfirmed,
            cleanup_unknown: value.cleanup_unconfirmed,
        })
    });
    SignalCheckpoint {
        schema: 1,
        stage,
        snapshot,
    }
}
fn signal_record_bytes(value: &impl serde::Serialize) -> Option<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value).ok()?;
    bytes.push(b'\n');
    (bytes.len() <= SIGNAL_RECORD_LIMIT).then_some(bytes)
}
fn signal_checkpoint_parse(raw: &[u8]) -> Option<SignalCheckpoint> {
    if raw.len() > SIGNAL_RECORD_LIMIT {
        return None;
    }
    let record: SignalCheckpoint = serde_json::from_slice(raw).ok()?;
    if record.schema != 1 || signal_record_bytes(&record)?.as_slice() != raw {
        return None;
    }
    Some(record)
}
fn signal_checkpoint_write(directory: &Path, record: SignalCheckpoint) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let Some(bytes) = signal_record_bytes(&record) else {
        return;
    };
    let pending = directory.join("signal-checkpoint.pending");
    let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(&pending)
    else {
        return;
    };
    let complete = file.write_all(&bytes).is_ok();
    drop(file);
    if complete && std::fs::rename(&pending, directory.join("signal-checkpoint.json")).is_ok() {
        return;
    }
    // A successful rename relinquishes this name; never remove a later writer's file.
    let _ = std::fs::remove_file(pending);
}
fn signal_checkpoint_read(directory: &Path) -> Option<SignalCheckpoint> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(directory.join("signal-checkpoint.json"))
        .ok()?;
    let before = file.metadata().ok()?;
    if !before.is_file() || before.len() > SIGNAL_RECORD_LIMIT as u64 {
        return None;
    }
    let mut raw = Vec::new();
    (&file)
        .take((SIGNAL_RECORD_LIMIT + 1) as u64)
        .read_to_end(&mut raw)
        .ok()?;
    let after = file.metadata().ok()?;
    if before.len() != after.len() || raw.len() as u64 != after.len() {
        return None;
    }
    signal_checkpoint_parse(&raw)
}
fn signal_marker(path: &Path) -> Option<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Some(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
        _ => None,
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum SignalParentStage {
    WaitReady,
    Ready,
    SignalSent,
    WaitExit,
    Exited,
    AssertJoin,
}
#[derive(serde::Serialize)]
struct SignalMarkers {
    signal_ready: Option<bool>,
    signal_observed: Option<bool>,
    signal_joined: Option<bool>,
    manager_joined: Option<bool>,
}
#[derive(serde::Serialize)]
struct SignalFailure {
    schema: u8,
    kind: &'static str,
    signal: &'static str,
    parent_stage: SignalParentStage,
    exit_code: Option<i32>,
    markers: SignalMarkers,
    checkpoint: Option<SignalCheckpoint>,
}
fn signal_fixture_failure(
    signal: i32,
    stage: SignalParentStage,
    exit_code: Option<i32>,
    directory: &Path,
    actor_directory: &Path,
) -> Option<Vec<u8>> {
    let signal = match signal {
        nix::libc::SIGTERM => "TERM",
        nix::libc::SIGINT => "INT",
        _ => return None,
    };
    let mut record = SignalFailure {
        schema: 1,
        kind: "darwin-signal-fixture-failure",
        signal,
        parent_stage: stage,
        exit_code,
        markers: SignalMarkers {
            signal_ready: signal_marker(&directory.join("signal-ready")),
            signal_observed: signal_marker(&directory.join("signal-observed")),
            signal_joined: signal_marker(&directory.join("signal-joined")),
            manager_joined: signal_marker(&actor_directory.join("manager-joined")),
        },
        checkpoint: signal_checkpoint_read(directory),
    };
    if let Some(bytes) = signal_record_bytes(&record) {
        return Some(bytes);
    }
    record.checkpoint = None;
    signal_record_bytes(&record)
}

fn publish_bytes(path: &Path, bytes: &[u8]) {
    let pending = path.with_extension("pending");
    std::fs::write(&pending, bytes).unwrap();
    std::fs::rename(pending, path).unwrap();
}
fn publish(path: &Path) {
    publish_bytes(path, b"ready");
}
fn until(check: impl FnMut() -> bool) {
    until_tagged(check, None);
}
fn until_tagged(mut check: impl FnMut() -> bool, diagnostic: Option<ReplacementDiagnostic<'_>>) {
    let end = Instant::now() + Duration::from_secs(10);
    while !check() {
        let within = Instant::now() < end;
        if !within {
            if let Some(context) = diagnostic {
                replacement_failure(context);
            }
        }
        assert!(within, "owned native fixture deadline");
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
    let replacement_role = std::env::var("QSH_DARWIN223_REPLACEMENT_ROLE")
        .ok()
        .map(|value| ReplacementActorRole::parse(&value).expect("closed replacement actor role"));
    let replacement_nonce = std::env::var("QSH_DARWIN223_REPLACEMENT_NONCE").ok();
    if let Some(role) = replacement_role {
        let nonce = replacement_nonce
            .as_deref()
            .filter(|nonce| valid_replacement_nonce(nonce))
            .expect("private replacement nonce");
        replacement_stage_publish(&directory, nonce, role, ReplacementActorStage::Entry);
        let sampled = replacement_actor_sample(role);
        replacement_stage_publish(&directory, nonce, role, ReplacementActorStage::Sampled);
        let accepted = match sampled {
            Ok(report) => {
                replacement_report_publish(&directory, nonce, report);
                validate_replacement_topology(role, &report).is_ok()
            }
            Err(_) => false,
        };
        if !accepted {
            replacement_stage_publish(&directory, nonce, role, ReplacementActorStage::Refused);
            panic!("replacement actor topology refused");
        }
        replacement_stage_publish(&directory, nonce, role, ReplacementActorStage::Accepted);
    }
    let stage = std::env::var_os("QSH_DARWIN223_STAGE2").is_some();
    let descendant = std::env::var_os("QSH_DARWIN223_DESCENDANT").is_some();
    let legacy_pty_leader = std::env::var_os("QSH_DARWIN223_PTY_LEADER").is_some();
    let pty_leader = legacy_pty_leader || replacement_role.is_some();
    let fork_root = std::env::var_os("QSH_DARWIN223_FORK_ROOT").is_some();
    let foreign_parent = std::env::var_os("QSH_DARWIN223_FOREIGN_PARENT").is_some();
    if descendant {
        assert_eq!(unsafe { nix::libc::setpgid(0, 0) }, 0);
    } else if !stage && !pty_leader && !foreign_parent {
        assert!(unsafe { nix::libc::setsid() } > 0);
    }
    if legacy_pty_leader {
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
            .env_remove("QSH_DARWIN223_REPLACEMENT_ROLE")
            .env("QSH_DARWIN223_DESCENDANT", "1");
        if replacement_role.is_some() {
            command.env("QSH_DARWIN223_REPLACEMENT_DESCENDANT", "1");
        }
        let mut child = OwnedCommand::spawn(&mut command).unwrap();
        until(|| directory.join("descendant-ready").exists());
        if let Some(role) = replacement_role {
            replacement_stage_publish(
                &directory,
                replacement_nonce.as_deref().unwrap(),
                role,
                ReplacementActorStage::DescendantPublished,
            );
        }
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
        if std::env::var_os("QSH_DARWIN223_REPLACEMENT_DESCENDANT").is_some() {
            replacement_descendant_publish(
                &directory,
                replacement_nonce
                    .as_deref()
                    .expect("bound descendant nonce"),
            );
        }
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
        self.finish_tagged(None);
    }
    fn finish_tagged(&mut self, diagnostic: Option<ReplacementDiagnostic<'_>>) {
        let mut ops = NativeOps;
        until_tagged(
            || ops.observe_exit(&mut self.watch).unwrap().is_some(),
            diagnostic,
        );
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
pub(super) struct ConnectedEvents {
    pub(super) live: AtomicBool,
    pub(super) input_failed: AtomicBool,
    deframer: Mutex<transport::shell_frame::RecordDeframer>,
    pub(super) records: Mutex<Vec<transport::channel::ServerRecord>>,
    shell: Mutex<transport::shell_frame::ShellDeframer>,
    #[cfg(feature = "test-darwin-keeper")]
    pub(super) geometries: Mutex<Vec<transport::channel_geometry::GeometryRecord>>,
    pub(super) output: Mutex<Vec<u8>>,
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
                #[cfg(feature = "test-darwin-keeper")]
                if let transport::shell_frame::ShellRecord::Geometry(geometry) = &record {
                    self.geometries.lock().unwrap().push(*geometry);
                }
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
pub(super) struct ConnectedBinder;
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
fn connected_actor_command(directory: &Path, executable: &Path) -> Vec<u8> {
    let quote = |value: &Path| {
        let value = value.to_str().expect("fixture path UTF-8");
        assert!(
            !value.contains('\''),
            "fixture paths use the maintained single-quote grammar"
        );
        format!("'{value}'")
    };
    // Command channels parse argv; they do not evaluate shell assignments or exec.
    format!("/usr/bin/env QSH_DARWIN223_ACTOR={} QSH_DARWIN223_CONNECTED_ACTOR=1 {} --exact darwin_process_scope::native_tests::darwin223_owned_actor --nocapture",
        quote(directory), quote(executable)).into_bytes()
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
            // Only the parent owns this real watch. Do not publish this proof
            // until the helper has actually enqueued CLOSE, and never infer it
            // from a zero registry snapshot or subsequent manager shutdown.
            if self.path().join("close-enqueued").exists()
                && !self.path().join("close-observed").exists()
            {
                let expected_pid: i32 = std::fs::read_to_string(self.path().join("actor-pid"))
                    .unwrap()
                    .parse()
                    .unwrap();
                let bound = self.bound.as_mut().unwrap();
                if let Some(event) = NativeOps
                    .observe_exit(&mut bound.watch)
                    .expect("bound CLOSE actor watch")
                {
                    assert_eq!(event.pid, expected_pid);
                    assert!(
                        event.process_filter
                            && event.note_exit
                            && !event.error
                            && event.cookie == 1
                    );
                    bound.normal_exit = true;
                    publish(&self.path().join("close-observed"));
                }
            }
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
        connected_actor_command(directory, &std::env::current_exe().unwrap())
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
fn refusal_origin(reason: &str) -> &'static str {
    match reason {
        "the daemon is restarting" => "RESTARTING",
        "channel already opening" | "channel already open" => "STREAM_OCCUPIED",
        "too many channels" => "CHANNEL_LIMIT",
        "too many pending channels" => "OPEN_ADMISSION",
        "channel opening identity exhausted" => "IDENTITY",
        "channel opening unavailable" => "EXECUTOR",
        "channel preparation unavailable" => "INSTALLATION",
        "this Darwin runtime has no qualified process ownership contract" => "DARWIN_CONTRACT",
        _ if reason.starts_with("Darwin process ownership unavailable:") => "DARWIN_ADMISSION",
        _ if reason.starts_with("could not open channel: opening the pseudo-terminal: ") => "PTY_OPEN",
        "could not open channel: disabling echo on the PTY master side: the PTY master side does not hand over a file descriptor" => "PTY_ECHO_FD",
        _ if reason.starts_with("could not open channel: disabling echo on the PTY master side: reading the PTY master side's termios: ") => "PTY_ECHO_READ",
        _ if reason.starts_with("could not open channel: disabling echo on the PTY master side: writing the PTY master side's termios: ") => "PTY_ECHO_WRITE",
        _ if reason.starts_with("could not open channel: starting the command in the PTY: ") => "PTY_SPAWN",
        _ => "OTHER",
    }
}
const FIXTURE_TRUE: &str = "/usr/bin/true";
fn admit_fixture_true(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    if !info.is_file() || info.len() == 0 || info.permissions().mode() & 0o111 == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "FIXTURE_TRUE_ADMISSION",
        ));
    }
    use std::os::fd::IntoRawFd;
    let fd = file.into_raw_fd();
    if unsafe { nix::libc::close(fd) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}
#[derive(Clone, Copy)]
#[repr(usize)]
enum BootstrapStage {
    Input,
    Parent,
    FdValidate,
    FdFlags,
    Path,
    Client,
    Udp,
    Control,
    Gate,
    StateFile,
    FdSelection,
    FdInherit,
    Exec,
    FdRestore,
}
const BOOTSTRAP_STAGES: [&str; 14] = [
    "INPUT",
    "PARENT",
    "FD_VALIDATE",
    "FD_FLAGS",
    "PATH",
    "CLIENT",
    "UDP",
    "CONTROL",
    "GATE",
    "STATE_FILE",
    "FD_SELECTION",
    "FD_INHERIT",
    "EXEC",
    "FD_RESTORE",
];
#[derive(Clone, Copy)]
#[repr(usize)]
enum BootstrapErrno {
    Unknown,
    Enoent,
    Eacces,
    Eperm,
    Emfile,
    Enfile,
    Enomem,
    Eio,
    Enotty,
    Einval,
    Enoexec,
}
const BOOTSTRAP_ERRORS: [&str; 11] = [
    "UNKNOWN", "ENOENT", "EACCES", "EPERM", "EMFILE", "ENFILE", "ENOMEM", "EIO", "ENOTTY",
    "EINVAL", "ENOEXEC",
];
static BOOTSTRAP_STAGE: AtomicUsize = AtomicUsize::new(0);
static BOOTSTRAP_ERROR: AtomicUsize = AtomicUsize::new(0);
fn bootstrap_stage(stage: BootstrapStage) {
    BOOTSTRAP_ERROR.store(0, Ordering::SeqCst);
    BOOTSTRAP_STAGE.store(stage as usize, Ordering::SeqCst);
}
fn bootstrap_errno(value: i32) -> BootstrapErrno {
    match value {
        nix::libc::ENOENT => BootstrapErrno::Enoent,
        nix::libc::EACCES => BootstrapErrno::Eacces,
        nix::libc::EPERM => BootstrapErrno::Eperm,
        nix::libc::EMFILE => BootstrapErrno::Emfile,
        nix::libc::ENFILE => BootstrapErrno::Enfile,
        nix::libc::ENOMEM => BootstrapErrno::Enomem,
        nix::libc::EIO => BootstrapErrno::Eio,
        nix::libc::ENOTTY => BootstrapErrno::Enotty,
        nix::libc::EINVAL => BootstrapErrno::Einval,
        nix::libc::ENOEXEC => BootstrapErrno::Enoexec,
        _ => BootstrapErrno::Unknown,
    }
}
fn bootstrap_result<T, E: Into<anyhow::Error>>(result: Result<T, E>) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            let error = error.into();
            let number = error.chain().take(8).find_map(|item| {
                item.downcast_ref::<std::io::Error>()
                    .and_then(|e| e.raw_os_error())
                    .or_else(|| item.downcast_ref::<nix::errno::Errno>().map(|e| *e as i32))
            });
            let code = number
                .map(bootstrap_errno)
                .unwrap_or(BootstrapErrno::Unknown);
            BOOTSTRAP_ERROR.store(code as usize, Ordering::SeqCst);
            panic!("bootstrap operation refused");
        }
    }
}
fn bootstrap_hook() -> Box<dyn Fn(&std::panic::PanicHookInfo<'_>) + Sync + Send + 'static> {
    let previous = std::panic::take_hook();
    // Only the dedicated bootstrap reexec installs this hook. Never print the
    // panic payload, original error or source location into public CI output.
    std::panic::set_hook(Box::new(|_| {
        use std::io::Write;
        let stage = BOOTSTRAP_STAGES[BOOTSTRAP_STAGE.load(Ordering::SeqCst)];
        let error = BOOTSTRAP_ERRORS[BOOTSTRAP_ERROR.load(Ordering::SeqCst)];
        let _ = writeln!(
            std::io::stderr().lock(),
            "QSH223_BOOTSTRAP stage={stage} errno={error}"
        );
    }));
    previous
}
fn bootstrap_record(bytes: &[u8]) -> Option<(&'static str, &'static str)> {
    if bytes.len() > 64 * 1024 {
        return None;
    }
    let text = std::str::from_utf8(bytes).ok()?;
    let mut found = None;
    for raw in text.split_inclusive('\n') {
        let line = raw.strip_suffix('\n').unwrap_or(raw);
        if !line.starts_with("QSH223_BOOTSTRAP") {
            continue;
        }
        if found.is_some() || !raw.ends_with('\n') {
            return None;
        }
        let (stage, error) = line
            .strip_prefix("QSH223_BOOTSTRAP stage=")?
            .split_once(" errno=")?;
        let stage = *BOOTSTRAP_STAGES.iter().find(|value| **value == stage)?;
        let error = *BOOTSTRAP_ERRORS.iter().find(|value| **value == error)?;
        found = Some((stage, error));
    }
    found
}
fn settled_bootstrap_record(bytes: &[u8], settled: bool) -> Option<(&'static str, &'static str)> {
    if settled {
        bootstrap_record(bytes)
    } else {
        None
    }
}
fn bootstrap_error_origin(bytes: &[u8]) -> &'static str {
    bootstrap_record(bytes)
        .map(|value| value.0)
        .unwrap_or("OTHER")
}
fn retain_bootstrap_stderr(bytes: &[u8]) {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "qsh223-private-bootstrap-{}-{}.txt",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    // Raw controlled-fixture data stays in a private local evidence file;
    // neither its bytes nor its path is emitted to public CI output.
    if let Ok(mut file) = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        let _ = file.write_all(bytes);
    }
}
// Fixed private observations only; a failure record never certifies cleanup.
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ConnectedMode {
    ChannelClose,
    ManagerStop,
    NoChannel,
    Rebind,
    FreshSession,
    BodyFailure,
    ObservationTimeout,
}
impl ConnectedMode {
    fn from_mode(mode: &str) -> Self {
        match mode {
            "channel-close" => Self::ChannelClose,
            "manager-stop" => Self::ManagerStop,
            "no-channel" => Self::NoChannel,
            "rebind" => Self::Rebind,
            "fresh-session" => Self::FreshSession,
            "body-failure" => Self::BodyFailure,
            "observation-timeout" => Self::ObservationTimeout,
            _ => unreachable!("closed connected fixture mode"),
        }
    }
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FixtureStage {
    Spawn,
    PipeSetup,
    Observe,
    StdoutRead,
    StderrRead,
    Cap,
    Poll,
    Deadline,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ReplacementSite {
    ParkedLink,
    ParkedOpened,
    DescendantReady,
    ParkedDetached,
    UpdateLink,
    UpdateAccept,
    NewBuildStatus,
    RestartingReceipt,
    OldLeaderExit,
    OldDescendantExit,
    FreshLink,
    FreshExit,
    FinalStop,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FailureCode {
    FixtureTrueAdmission,
    FreshLink,
    FreshEnqueue,
    FreshExit,
    BodyError,
    BodyOk,
    CloseObservation,
    CloseRegistry,
    OldClientRegistry,
    ExitAfterClose,
    OldInputFailed,
    BodyPanic,
    BodyCancelled,
}
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum FailureError {
    Timeout,
    Io,
    OutputLimit,
    Unknown,
}
#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Terminal {
    Unknown,
    Exited,
    Signaled,
}
#[derive(Clone, Copy, serde::Serialize)]
struct CachedStatus {
    terminal: Terminal,
    exit: Option<i32>,
    signal: Option<i32>,
}
impl CachedStatus {
    fn from_status(status: Option<std::process::ExitStatus>) -> Self {
        use std::os::unix::process::ExitStatusExt;
        let terminal = match status {
            None => Terminal::Unknown,
            Some(s) if s.signal().is_some() => Terminal::Signaled,
            Some(_) => Terminal::Exited,
        };
        Self {
            terminal,
            exit: status.and_then(|s| s.code()),
            signal: status.and_then(|s| s.signal()),
        }
    }
}
struct ConnectedDiagnostic {
    mode: ConnectedMode,
    actor: std::path::PathBuf,
    connected: std::path::PathBuf,
}
#[derive(Clone, Copy, Default, serde::Serialize)]
struct ReplacementProgress {
    open_enqueued: bool,
    offer_enqueued: bool,
    accepted: bool,
    // All local whole-record admissions returned; not remote verification.
    upload_enqueued: bool,
    restarting: bool,
}
#[derive(Clone, Copy)]
struct ReplacementDiagnostic<'a> {
    site: ReplacementSite,
    progress: &'a std::cell::Cell<ReplacementProgress>,
    events: Option<&'a ConnectedEvents>,
    actor: &'a Path,
    replacement: Option<(&'a str, ReplacementActorRole)>,
    status_wait: Option<&'a std::cell::Cell<StatusWaitObservation>>,
    update_wait: Option<UpdateWaitSnapshot>,
}
#[derive(serde::Serialize)]
struct MarkerFacts {
    actor_published: Option<bool>,
    controller_bound: Option<bool>,
    close_enqueued: Option<bool>,
    close_observed: Option<bool>,
    manager_joined: Option<bool>,
    connected_joined: Option<bool>,
    failure_code: Option<FailureCode>,
}
#[derive(Default, serde::Serialize)]
struct EventFacts {
    opened: bool,
    refused: bool,
    update_accept: bool,
    update_reject: bool,
    restarting: bool,
    exit0: bool,
    exitother: bool,
    parked_terminal: Option<super::keeper_integration_tests::ReplacementTerminal>,
}
#[derive(serde::Serialize)]
#[serde(tag = "case", rename_all = "SCREAMING_SNAKE_CASE")]
enum FailurePayload {
    Connected {
        mode: ConnectedMode,
        stage: FixtureStage,
        error: FailureError,
        #[serde(flatten)]
        status: CachedStatus,
        stdout_eof: Option<bool>,
        stderr_eof: Option<bool>,
        stdout_bytes: usize,
        stderr_bytes: usize,
        markers: MarkerFacts,
    },
    Replacement {
        stage: ReplacementSite,
        progress: ReplacementProgress,
        events: Option<EventFacts>,
        markers: MarkerFacts,
        status_wait: Option<StatusWaitObservation>,
        update_wait: Option<UpdateWaitSnapshot>,
        actor_stage: Option<ReplacementActorProjection>,
    },
}
#[derive(Clone, Copy, Default, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum StatusResult {
    #[default]
    Unobserved,
    ValidStatus,
    ParseRefused,
    NoDaemon,
    TimedOut,
    RequestError,
    Unknown,
}
#[derive(Clone, Copy, Default, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum StatusBuild {
    #[default]
    Unknown,
    Expected,
    Old,
    Other,
}
#[derive(Clone, Copy, Default, serde::Serialize)]
struct SeenStatusResults {
    valid_status: bool,
    parse_refused: bool,
    no_daemon: bool,
    timed_out: bool,
    request_error: bool,
    unknown: bool,
    expected_build: bool,
    old_build: bool,
    other_build: bool,
}
#[derive(Clone, Copy, serde::Serialize)]
struct CachedAtWaitEntry {
    status: CachedStatus,
    stderr_eof: bool,
    stderr_bytes: usize,
}
#[derive(Clone, Copy, serde::Serialize)]
struct StatusWaitObservation {
    last_result: StatusResult,
    last_build: StatusBuild,
    seen: SeenStatusResults,
    completed_calls: u32,
    cached_at_wait_entry: CachedAtWaitEntry,
}
impl StatusWaitObservation {
    fn new(cached_at_wait_entry: CachedAtWaitEntry) -> Self {
        Self {
            last_result: StatusResult::Unobserved,
            last_build: StatusBuild::Unknown,
            seen: SeenStatusResults::default(),
            completed_calls: 0,
            cached_at_wait_entry,
        }
    }
}
fn status_wait_predicate(
    observation: &std::cell::Cell<StatusWaitObservation>,
    old: u64,
    expected: u64,
    request: impl FnOnce() -> (Option<u64>, &'static str),
) -> bool {
    // Exactly one existing request, recorded only after it returns. Its original
    // build-equality predicate remains the sole success decision.
    let (build, family) = request();
    let mut value = observation.get();
    value.last_result = match family {
        "VALID_STATUS" => StatusResult::ValidStatus,
        "PARSE_REFUSED" => StatusResult::ParseRefused,
        "NO_DAEMON" => StatusResult::NoDaemon,
        "TIMED_OUT" => StatusResult::TimedOut,
        "REQUEST_ERROR" => StatusResult::RequestError,
        _ => StatusResult::Unknown,
    };
    value.last_build = match (value.last_result, build) {
        (StatusResult::ValidStatus, Some(n)) if n == expected => StatusBuild::Expected,
        (StatusResult::ValidStatus, Some(n)) if n == old => StatusBuild::Old,
        (StatusResult::ValidStatus, Some(_)) => StatusBuild::Other,
        _ => StatusBuild::Unknown,
    };
    match value.last_build {
        StatusBuild::Expected => value.seen.expected_build = true,
        StatusBuild::Old => value.seen.old_build = true,
        StatusBuild::Other => value.seen.other_build = true,
        StatusBuild::Unknown => {}
    }
    match value.last_result {
        StatusResult::ValidStatus => value.seen.valid_status = true,
        StatusResult::ParseRefused => value.seen.parse_refused = true,
        StatusResult::NoDaemon => value.seen.no_daemon = true,
        StatusResult::TimedOut => value.seen.timed_out = true,
        StatusResult::RequestError => value.seen.request_error = true,
        StatusResult::Unknown => value.seen.unknown = true,
        StatusResult::Unobserved => {}
    }
    value.completed_calls = value.completed_calls.saturating_add(1);
    observation.set(value);
    build.is_some_and(|build| build == expected)
}
fn fixture_status_projection_controls() {
    let cache = CachedAtWaitEntry {
        status: CachedStatus::from_status(None),
        stderr_eof: false,
        stderr_bytes: usize::MAX,
    };
    let state = std::cell::Cell::new(StatusWaitObservation::new(cache));
    let initial = serde_json::to_value(state.get()).unwrap();
    assert_eq!(initial["last_result"], "UNOBSERVED");
    for (build, family, result, category) in [
        (Some(20), "VALID_STATUS", "VALID_STATUS", "EXPECTED"),
        (Some(10), "VALID_STATUS", "VALID_STATUS", "OLD"),
        (Some(30), "VALID_STATUS", "VALID_STATUS", "OTHER"),
        (None, "PARSE_REFUSED", "PARSE_REFUSED", "UNKNOWN"),
        (None, "NO_DAEMON", "NO_DAEMON", "UNKNOWN"),
        (None, "TIMED_OUT", "TIMED_OUT", "UNKNOWN"),
        (None, "REQUEST_ERROR", "REQUEST_ERROR", "UNKNOWN"),
        (None, "PRIVATE_CANARY", "UNKNOWN", "UNKNOWN"),
    ] {
        status_wait_predicate(&state, 10, 20, || (build, family));
        let value = serde_json::to_value(state.get()).unwrap();
        assert_eq!(value["last_result"], result);
        assert_eq!(value["last_build"], category);
    }
    assert!(serde_json::to_value(state.get()).unwrap()["seen"]
        .as_object()
        .unwrap()
        .values()
        .all(|v| *v == true));
    let directory = tempfile::tempdir().unwrap();
    let record = FailurePayload::Replacement {
        stage: ReplacementSite::NewBuildStatus,
        progress: ReplacementProgress {
            open_enqueued: true,
            offer_enqueued: true,
            accepted: true,
            upload_enqueued: true,
            restarting: true,
        },
        events: Some(EventFacts {
            opened: true,
            refused: true,
            update_accept: true,
            update_reject: true,
            restarting: true,
            exit0: true,
            exitother: true,
            parked_terminal: Some(super::keeper_integration_tests::ReplacementTerminal {
                stream: transport::channel::FIRST_CHANNEL_STREAM,
                code: 101,
            }),
        }),
        markers: marker_facts(directory.path(), directory.path()),
        status_wait: Some(state.get()),
        update_wait: None,
        actor_stage: None,
    };
    let bytes = failure_bytes(&record).unwrap();
    assert!(bytes.len() <= 2048);
    assert!(!bytes
        .windows(b"PRIVATE_CANARY".len())
        .any(|b| b == b"PRIVATE_CANARY"));
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        value["status_wait"]["cached_at_wait_entry"]["status"]["terminal"],
        "UNKNOWN"
    );
    assert_eq!(
        value["status_wait"]["cached_at_wait_entry"]["stderr_eof"],
        false
    );
    assert!(value["status_wait"].get("build").is_none());
    assert!(value["status_wait"].get("pid").is_none());
}
fn fixture_status_single_request_controls() {
    let cache = CachedAtWaitEntry {
        status: CachedStatus::from_status(None),
        stderr_eof: false,
        stderr_bytes: 0,
    };
    let state = std::cell::Cell::new(StatusWaitObservation::new(cache));
    let requests = std::cell::Cell::new(0);
    for (build, family) in [
        (Some(10), "VALID_STATUS"),
        (None, "NO_DAEMON"),
        (Some(20), "VALID_STATUS"),
    ] {
        let before = requests.get();
        let accepted = status_wait_predicate(&state, 10, 20, || {
            requests.set(requests.get() + 1);
            (build, family)
        });
        assert_eq!(requests.get(), before + 1);
        assert_eq!(state.get().completed_calls, requests.get());
        assert_eq!(accepted, build.is_some_and(|build| build == 20));
        if family == "NO_DAEMON" {
            let facts = serde_json::to_value(state.get()).unwrap();
            assert_eq!(facts["last_build"], "UNKNOWN");
            assert_eq!(facts["seen"]["old_build"], true);
        }
    }
    let observed = serde_json::to_value(state.get()).unwrap();
    assert_eq!(observed["seen"]["valid_status"], true);
    assert_eq!(observed["seen"]["no_daemon"], true);
    assert_eq!(
        observed["cached_at_wait_entry"]["status"]["terminal"],
        "UNKNOWN"
    );
    let mut maximum = state.get();
    maximum.completed_calls = u32::MAX;
    state.set(maximum);
    status_wait_predicate(&state, 10, 20, || (None, "REQUEST_ERROR"));
    assert_eq!(state.get().completed_calls, u32::MAX);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ObservedUpdateOutcome {
    Waiting,
    Restarting,
    Rejected,
    Busy,
    UnknownResult,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum ObservedRejectCode {
    Other,
    SizeMismatch,
    ChecksumMismatch,
    SelfCheckFailed,
    VersionNotAccepted,
    DiskError,
    ExecFailed,
    TransferStalled,
    ControlBusy,
    Unknown,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
struct UpdateObservation {
    outcome: ObservedUpdateOutcome,
    reject_code: Option<ObservedRejectCode>,
}
fn observed_reject_code(code: transport::channel::RejectCode) -> ObservedRejectCode {
    use transport::channel::RejectCode;
    match code {
        RejectCode::Other => ObservedRejectCode::Other,
        RejectCode::SizeMismatch => ObservedRejectCode::SizeMismatch,
        RejectCode::ChecksumMismatch => ObservedRejectCode::ChecksumMismatch,
        RejectCode::SelfCheckFailed => ObservedRejectCode::SelfCheckFailed,
        RejectCode::VersionNotAccepted => ObservedRejectCode::VersionNotAccepted,
        RejectCode::DiskError => ObservedRejectCode::DiskError,
        RejectCode::ExecFailed => ObservedRejectCode::ExecFailed,
        RejectCode::TransferStalled => ObservedRejectCode::TransferStalled,
        RejectCode::ControlBusy => ObservedRejectCode::ControlBusy,
        RejectCode::Unknown(_) => ObservedRejectCode::Unknown,
    }
}
fn observed_update_result(records: &[transport::channel::ServerRecord]) -> UpdateObservation {
    use transport::channel::{ServerRecord, UpdateResult};
    let mut restarting = false;
    for record in records {
        match record {
            ServerRecord::UpdateResult(UpdateResult::Restarting) => restarting = true,
            ServerRecord::UpdateResult(UpdateResult::Rejected { code, .. }) => {
                return UpdateObservation {
                    outcome: ObservedUpdateOutcome::Rejected,
                    reject_code: Some(observed_reject_code(*code)),
                }
            }
            ServerRecord::UpdateResult(UpdateResult::Busy { .. }) => {
                return UpdateObservation {
                    outcome: ObservedUpdateOutcome::Busy,
                    reject_code: None,
                }
            }
            ServerRecord::UpdateResult(UpdateResult::Unknown(_)) => {
                return UpdateObservation {
                    outcome: ObservedUpdateOutcome::UnknownResult,
                    reject_code: None,
                }
            }
            _ => {}
        }
    }
    UpdateObservation {
        outcome: if restarting {
            ObservedUpdateOutcome::Restarting
        } else {
            ObservedUpdateOutcome::Waiting
        },
        reject_code: None,
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum UpdateWaitFailure {
    TerminalResult,
    InputFailure,
    Deadline,
}
#[derive(Clone, Copy, Debug, serde::Serialize)]
struct UpdateWaitSnapshot {
    #[serde(flatten)]
    observed: UpdateObservation,
    input_failed: bool,
    failure: UpdateWaitFailure,
}
enum UpdateWaitDecision {
    Waiting,
    Restarting,
    Refused(UpdateWaitSnapshot),
}
fn update_wait_decision(
    observed: UpdateObservation,
    input_failed: bool,
    within_deadline: impl FnOnce() -> bool,
) -> UpdateWaitDecision {
    let failure = if matches!(
        observed.outcome,
        ObservedUpdateOutcome::Rejected
            | ObservedUpdateOutcome::Busy
            | ObservedUpdateOutcome::UnknownResult
    ) {
        UpdateWaitFailure::TerminalResult
    } else if input_failed {
        UpdateWaitFailure::InputFailure
    } else if observed.outcome == ObservedUpdateOutcome::Restarting {
        return UpdateWaitDecision::Restarting;
    } else if within_deadline() {
        return UpdateWaitDecision::Waiting;
    } else {
        UpdateWaitFailure::Deadline
    };
    UpdateWaitDecision::Refused(UpdateWaitSnapshot {
        observed,
        input_failed,
        failure,
    })
}
// Controls use the real encoder, deframer, enum and callback implementation.
fn fixture_update_records(records: &[transport::channel::ServerRecord]) -> ConnectedEvents {
    use transport::driver_std::ClientEvents;
    let events = ConnectedEvents::default();
    for record in records {
        let encoded = transport::channel::encode_server(record);
        for part in encoded.chunks(7) {
            events.on_bytes(transport::channel::CONTROL_STREAM, part.to_vec());
        }
    }
    events
}
fn fixture_update_terminal_controls() {
    use transport::channel::{RejectCode, ServerRecord, UpdateAnswer, UpdateResult};
    let rejected = |code| {
        ServerRecord::UpdateResult(UpdateResult::Rejected {
            code,
            detail: "PRIVATE_CANARY".into(),
        })
    };
    let events = fixture_update_records(&[rejected(RejectCode::SelfCheckFailed)]);
    let records = events.records.lock().unwrap();
    assert!(!records
        .iter()
        .any(|record| *record == ServerRecord::UpdateResult(UpdateResult::Restarting)));
    assert_eq!(
        observed_update_result(&records).outcome,
        ObservedUpdateOutcome::Rejected
    );
    assert_eq!(
        observed_update_result(&records).reject_code,
        Some(ObservedRejectCode::SelfCheckFailed)
    );
    drop(records);
    for initial in [
        vec![],
        vec![ServerRecord::UpdateAnswer(UpdateAnswer::Accept)],
    ] {
        let events = fixture_update_records(&initial);
        assert_eq!(
            observed_update_result(&events.records.lock().unwrap()).outcome,
            ObservedUpdateOutcome::Waiting
        );
    }
    for (code, expected) in [
        (RejectCode::Other, ObservedRejectCode::Other),
        (RejectCode::SizeMismatch, ObservedRejectCode::SizeMismatch),
        (
            RejectCode::ChecksumMismatch,
            ObservedRejectCode::ChecksumMismatch,
        ),
        (
            RejectCode::SelfCheckFailed,
            ObservedRejectCode::SelfCheckFailed,
        ),
        (
            RejectCode::VersionNotAccepted,
            ObservedRejectCode::VersionNotAccepted,
        ),
        (RejectCode::DiskError, ObservedRejectCode::DiskError),
        (RejectCode::ExecFailed, ObservedRejectCode::ExecFailed),
        (
            RejectCode::TransferStalled,
            ObservedRejectCode::TransferStalled,
        ),
        (RejectCode::ControlBusy, ObservedRejectCode::ControlBusy),
        (RejectCode::Unknown(233), ObservedRejectCode::Unknown),
    ] {
        let events = fixture_update_records(&[rejected(code)]);
        let observed = observed_update_result(&events.records.lock().unwrap());
        assert_eq!(observed.reject_code, Some(expected));
        assert!(matches!(
            update_wait_decision(observed, false, || panic!("terminal must not query clock")),
            UpdateWaitDecision::Refused(UpdateWaitSnapshot {
                failure: UpdateWaitFailure::TerminalResult,
                ..
            })
        ));
    }
    for (result, expected) in [
        (UpdateResult::Restarting, ObservedUpdateOutcome::Restarting),
        (
            UpdateResult::Busy { others: 444444 },
            ObservedUpdateOutcome::Busy,
        ),
        (
            UpdateResult::Unknown(234),
            ObservedUpdateOutcome::UnknownResult,
        ),
    ] {
        let events = fixture_update_records(&[ServerRecord::UpdateResult(result)]);
        assert_eq!(
            observed_update_result(&events.records.lock().unwrap()).outcome,
            expected
        );
    }
    for initial in [
        vec![
            ServerRecord::UpdateResult(UpdateResult::Restarting),
            rejected(RejectCode::SelfCheckFailed),
            rejected(RejectCode::DiskError),
        ],
        vec![
            rejected(RejectCode::SelfCheckFailed),
            ServerRecord::UpdateResult(UpdateResult::Restarting),
        ],
    ] {
        let events = fixture_update_records(&initial);
        assert_eq!(
            observed_update_result(&events.records.lock().unwrap()).reject_code,
            Some(ObservedRejectCode::SelfCheckFailed)
        );
    }
    let reversed = fixture_update_records(&[
        rejected(RejectCode::DiskError),
        rejected(RejectCode::SelfCheckFailed),
    ]);
    assert_eq!(
        observed_update_result(&reversed.records.lock().unwrap()).reject_code,
        Some(ObservedRejectCode::DiskError)
    );
}
fn fixture_update_decision_controls() {
    use transport::driver_std::ClientEvents;
    let events = ConnectedEvents::default();
    let waiting = observed_update_result(&[]);
    let end = 10;
    assert!(matches!(
        update_wait_decision(waiting, false, || 9 < end),
        UpdateWaitDecision::Waiting
    ));
    assert!(matches!(
        update_wait_decision(waiting, false, || 10 < end),
        UpdateWaitDecision::Refused(UpdateWaitSnapshot {
            failure: UpdateWaitFailure::Deadline,
            ..
        })
    ));
    let negative = UpdateObservation {
        outcome: ObservedUpdateOutcome::Rejected,
        reject_code: Some(ObservedRejectCode::DiskError),
    };
    assert!(matches!(
        update_wait_decision(negative, true, || panic!("negative precedence")),
        UpdateWaitDecision::Refused(UpdateWaitSnapshot {
            failure: UpdateWaitFailure::TerminalResult,
            ..
        })
    ));
    assert!(matches!(
        update_wait_decision(waiting, false, || true),
        UpdateWaitDecision::Waiting
    ));
    assert!(matches!(
        update_wait_decision(waiting, false, || false),
        UpdateWaitDecision::Refused(UpdateWaitSnapshot {
            failure: UpdateWaitFailure::Deadline,
            ..
        })
    ));
    events.on_input_failure(transport::driver_std::InputFailure::DriverUnavailable);
    assert!(matches!(
        update_wait_decision(
            waiting,
            events.input_failed.load(Ordering::SeqCst),
            || panic!("input failure must not query clock")
        ),
        UpdateWaitDecision::Refused(UpdateWaitSnapshot {
            failure: UpdateWaitFailure::InputFailure,
            ..
        })
    ));
    let restarting = UpdateObservation {
        outcome: ObservedUpdateOutcome::Restarting,
        reject_code: None,
    };
    assert!(matches!(
        update_wait_decision(restarting, false, || panic!("success must not query clock")),
        UpdateWaitDecision::Restarting
    ));
    assert!(matches!(
        update_wait_decision(restarting, true, || panic!(
            "input failure must not query clock"
        )),
        UpdateWaitDecision::Refused(UpdateWaitSnapshot {
            failure: UpdateWaitFailure::InputFailure,
            ..
        })
    ));
}
fn fixture_update_record_controls() {
    let directory = tempfile::tempdir().unwrap();
    let mut status = StatusWaitObservation::new(CachedAtWaitEntry {
        status: CachedStatus::from_status(None),
        stderr_eof: false,
        stderr_bytes: usize::MAX,
    });
    status.completed_calls = u32::MAX;
    for (observed, failure) in [
        (
            UpdateObservation {
                outcome: ObservedUpdateOutcome::Waiting,
                reject_code: None,
            },
            UpdateWaitFailure::Deadline,
        ),
        (
            UpdateObservation {
                outcome: ObservedUpdateOutcome::Rejected,
                reject_code: Some(ObservedRejectCode::Unknown),
            },
            UpdateWaitFailure::TerminalResult,
        ),
        (
            UpdateObservation {
                outcome: ObservedUpdateOutcome::UnknownResult,
                reject_code: None,
            },
            UpdateWaitFailure::TerminalResult,
        ),
        (
            UpdateObservation {
                outcome: ObservedUpdateOutcome::Busy,
                reject_code: None,
            },
            UpdateWaitFailure::TerminalResult,
        ),
    ] {
        let record = FailurePayload::Replacement {
            stage: ReplacementSite::RestartingReceipt,
            progress: ReplacementProgress::default(),
            events: Some(EventFacts::default()),
            markers: marker_facts(directory.path(), directory.path()),
            status_wait: Some(status),
            update_wait: Some(UpdateWaitSnapshot {
                observed,
                input_failed: true,
                failure,
            }),
            actor_stage: None,
        };
        let bytes = failure_bytes(&record).unwrap();
        assert!(bytes.len() <= 2048);
        assert!(!bytes
            .windows(b"PRIVATE_CANARY".len())
            .any(|b| b == b"PRIVATE_CANARY"));
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["stage"], "RESTARTING_RECEIPT");
        assert_eq!(value["update_wait"].as_object().unwrap().len(), 4);
        assert_eq!(
            value["update_wait"]["failure"],
            serde_json::to_value(failure).unwrap()
        );
        assert_eq!(
            value["update_wait"]["reject_code"],
            serde_json::to_value(observed.reject_code).unwrap()
        );
        assert_eq!(
            value["update_wait"]["outcome"],
            serde_json::to_value(observed.outcome).unwrap()
        );
        assert!(value["update_wait"].get("detail").is_none());
        assert!(value["update_wait"].get("others").is_none());
    }
    let record = FailurePayload::Replacement {
        stage: ReplacementSite::ParkedLink,
        progress: ReplacementProgress::default(),
        events: None,
        markers: marker_facts(directory.path(), directory.path()),
        status_wait: None,
        update_wait: None,
        actor_stage: None,
    };
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&failure_bytes(&record).unwrap()).unwrap()
            ["update_wait"],
        serde_json::Value::Null
    );
}

impl FailureCode {
    fn token(self) -> &'static str {
        match self {
            Self::FixtureTrueAdmission => "FIXTURE_TRUE_ADMISSION",
            Self::FreshLink => "FRESH_LINK",
            Self::FreshEnqueue => "FRESH_ENQUEUE",
            Self::FreshExit => "FRESH_EXIT",
            Self::BodyError => "BODY_ERROR",
            Self::BodyOk => "BODY_OK",
            Self::CloseObservation => "CLOSE_OBSERVATION",
            Self::CloseRegistry => "CLOSE_REGISTRY",
            Self::OldClientRegistry => "OLD_CLIENT_REGISTRY",
            Self::ExitAfterClose => "EXIT_AFTER_CLOSE",
            Self::OldInputFailed => "OLD_INPUT_FAILED",
            Self::BodyPanic => "BODY_PANIC",
            Self::BodyCancelled => "BODY_CANCELLED",
        }
    }
}
fn connected_body_failure_code(result: Result<(), &'static str>) -> FailureCode {
    match result {
        Err("FIXTURE_TRUE_ADMISSION") => FailureCode::FixtureTrueAdmission,
        Err("fresh link observation failed") => FailureCode::FreshLink,
        Err("fresh enqueue failed") => FailureCode::FreshEnqueue,
        Err("fresh exit observation failed") => FailureCode::FreshExit,
        Err("CLOSE_OBSERVATION") => FailureCode::CloseObservation,
        Err("CLOSE_REGISTRY") => FailureCode::CloseRegistry,
        Err("OLD_CLIENT_REGISTRY") => FailureCode::OldClientRegistry,
        Err("unexpected Exit after client CLOSE") => FailureCode::ExitAfterClose,
        Err("client input failed") => FailureCode::OldInputFailed,
        Err("BODY_PANIC") => FailureCode::BodyPanic,
        Err("BODY_CANCELLED") => FailureCode::BodyCancelled,
        Err(_) => FailureCode::BodyError,
        Ok(()) => FailureCode::BodyOk,
    }
}
fn connected_body_join_error(error: &tokio::task::JoinError) -> &'static str {
    if error.is_panic() {
        "BODY_PANIC"
    } else if error.is_cancelled() {
        "BODY_CANCELLED"
    } else {
        "connected body panicked or was cancelled"
    }
}
fn fixture_body_mapping_controls() {
    let directory = tempfile::tempdir().unwrap();
    for (result, expected) in [
        (
            Err("FIXTURE_TRUE_ADMISSION"),
            FailureCode::FixtureTrueAdmission,
        ),
        (Err("fresh link observation failed"), FailureCode::FreshLink),
        (Err("fresh enqueue failed"), FailureCode::FreshEnqueue),
        (Err("fresh exit observation failed"), FailureCode::FreshExit),
        (Ok(()), FailureCode::BodyOk),
        (Err("CLOSE_OBSERVATION"), FailureCode::CloseObservation),
        (Err("CLOSE_REGISTRY"), FailureCode::CloseRegistry),
        (Err("OLD_CLIENT_REGISTRY"), FailureCode::OldClientRegistry),
        (
            Err("unexpected Exit after client CLOSE"),
            FailureCode::ExitAfterClose,
        ),
        (Err("client input failed"), FailureCode::OldInputFailed),
        (Err("BODY_PANIC"), FailureCode::BodyPanic),
        (Err("BODY_CANCELLED"), FailureCode::BodyCancelled),
        (Err("PRIVATE_CANARY"), FailureCode::BodyError),
        (
            Err("CLOSE_OBSERVATION PRIVATE_CANARY"),
            FailureCode::BodyError,
        ),
    ] {
        let code = connected_body_failure_code(result);
        assert_eq!(code, expected);
        assert!(code.token().len() < 65);
        std::fs::write(directory.path().join("failure-code"), code.token()).unwrap();
        assert_eq!(failure_marker(directory.path()), Some(expected));
        assert_eq!(serde_json::to_value(code).unwrap(), code.token());
    }
    std::fs::write(directory.path().join("failure-code"), b"PRIVATE_CANARY").unwrap();
    assert!(failure_marker(directory.path()).is_none());
}
fn fixture_body_callback_controls() {
    use transport::channel::{ServerRecord, FIRST_CHANNEL_STREAM};
    use transport::driver_std::ClientEvents;
    for (stream, expected) in [
        (FIRST_CHANNEL_STREAM, FailureCode::ExitAfterClose),
        (FIRST_CHANNEL_STREAM + 1, FailureCode::BodyOk),
    ] {
        let events = fixture_update_records(&[ServerRecord::Exit { stream, code: 0 }]);
        let forbidden=events.records.lock().unwrap().iter().any(|record|matches!(record,ServerRecord::Exit{stream,..} if *stream==FIRST_CHANNEL_STREAM));
        let result = if forbidden {
            Err("unexpected Exit after client CLOSE")
        } else {
            Ok(())
        };
        assert_eq!(connected_body_failure_code(result), expected);
    }
    let events = ConnectedEvents::default();
    events.on_input_failure(transport::driver_std::InputFailure::DriverUnavailable);
    let result = if events.input_failed.load(Ordering::SeqCst) {
        Err("client input failed")
    } else {
        Ok(())
    };
    assert_eq!(
        connected_body_failure_code(result),
        FailureCode::OldInputFailed
    );
}
fn fixture_body_join_controls() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    runtime.block_on(async {
        let panic = tokio::spawn(async { panic!("expected body task panic") })
            .await
            .unwrap_err();
        assert_eq!(
            connected_body_failure_code(Err(connected_body_join_error(&panic))),
            FailureCode::BodyPanic
        );
        let cancelled = tokio::spawn(std::future::pending::<()>());
        cancelled.abort();
        let cancelled = cancelled.await.unwrap_err();
        assert_eq!(
            connected_body_failure_code(Err(connected_body_join_error(&cancelled))),
            FailureCode::BodyCancelled
        );
    });
}

fn marker_fact(directory: &Path, name: &str) -> Option<bool> {
    match std::fs::symlink_metadata(directory.join(name)) {
        Ok(info) if info.is_file() => Some(true),
        Ok(_) => None,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(false),
        Err(_) => None,
    }
}
fn failure_marker(directory: &Path) -> Option<FailureCode> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(directory.join("failure-code"))
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut raw = Vec::new();
    file.take(65).read_to_end(&mut raw).ok()?;
    match raw.as_slice() {
        b"FIXTURE_TRUE_ADMISSION" => Some(FailureCode::FixtureTrueAdmission),
        b"FRESH_LINK" => Some(FailureCode::FreshLink),
        b"FRESH_ENQUEUE" => Some(FailureCode::FreshEnqueue),
        b"FRESH_EXIT" => Some(FailureCode::FreshExit),
        b"BODY_ERROR" => Some(FailureCode::BodyError),
        b"BODY_OK" => Some(FailureCode::BodyOk),
        b"CLOSE_OBSERVATION" => Some(FailureCode::CloseObservation),
        b"CLOSE_REGISTRY" => Some(FailureCode::CloseRegistry),
        b"OLD_CLIENT_REGISTRY" => Some(FailureCode::OldClientRegistry),
        b"EXIT_AFTER_CLOSE" => Some(FailureCode::ExitAfterClose),
        b"OLD_INPUT_FAILED" => Some(FailureCode::OldInputFailed),
        b"BODY_PANIC" => Some(FailureCode::BodyPanic),
        b"BODY_CANCELLED" => Some(FailureCode::BodyCancelled),
        _ => None,
    }
}
fn marker_facts(actor: &Path, connected: &Path) -> MarkerFacts {
    MarkerFacts {
        actor_published: marker_fact(actor, "actor-pid"),
        controller_bound: marker_fact(actor, "controller-bound"),
        close_enqueued: marker_fact(actor, "close-enqueued"),
        close_observed: marker_fact(actor, "close-observed"),
        manager_joined: marker_fact(actor, "manager-joined"),
        connected_joined: marker_fact(connected, "connected-joined"),
        failure_code: failure_marker(actor),
    }
}
fn event_facts(events: Option<&ConnectedEvents>) -> Option<EventFacts> {
    use transport::channel::{ServerRecord, UpdateAnswer, UpdateResult};
    let records = events?.records.try_lock().ok()?;
    if records.len() > 256 {
        return None;
    }
    let mut facts = EventFacts {
        parked_terminal: replacement_terminal(&records),
        ..EventFacts::default()
    };
    for record in records.iter() {
        match record {
            ServerRecord::Opened { .. } => facts.opened = true,
            ServerRecord::Refused { .. } => facts.refused = true,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept) => facts.update_accept = true,
            ServerRecord::UpdateAnswer(_) => facts.update_reject = true,
            ServerRecord::UpdateResult(UpdateResult::Restarting) => facts.restarting = true,
            ServerRecord::Exit { code: 0, .. } => facts.exit0 = true,
            ServerRecord::Exit { .. } => facts.exitother = true,
            _ => {}
        }
    }
    Some(facts)
}
fn failure_bytes(payload: &FailurePayload) -> Option<Vec<u8>> {
    #[derive(serde::Serialize)]
    struct Record<'a> {
        schema: u8,
        kind: &'static str,
        phase: &'static str,
        cleanup: &'static str,
        #[serde(flatten)]
        payload: &'a FailurePayload,
    }
    let record = Record {
        schema: 1,
        kind: "darwin223-fixture-failure",
        phase: "PRE_RESCUE",
        cleanup: "UNKNOWN",
        payload,
    };
    // Converting the typed record to a sorted map preserves deterministic keys.
    let value = serde_json::to_value(record).ok()?;
    let mut bytes = serde_json::to_vec(&value).ok()?;
    bytes.push(b'\n');
    if bytes.len() > 2048 {
        return None;
    }
    Some(bytes)
}
fn emit_failure(payload: FailurePayload) {
    use std::io::Write;
    if let Some(bytes) = failure_bytes(&payload) {
        let mut stderr = std::io::stderr().lock();
        let _ = stderr.write_all(b"QSH223_FIXTURE_FAILURE ");
        let _ = stderr.write_all(&bytes);
    }
}
fn replacement_failure(context: ReplacementDiagnostic<'_>) {
    emit_failure(FailurePayload::Replacement {
        stage: context.site,
        progress: context.progress.get(),
        events: event_facts(context.events),
        markers: marker_facts(context.actor, context.actor),
        status_wait: context.status_wait.map(|value| value.get()),
        update_wait: context.update_wait,
        actor_stage: context.replacement.and_then(|(nonce, role)| {
            replacement_stage_observe(context.actor, Some(nonce)).filter(|stage| stage.role == role)
        }),
    });
}
fn connected_failure(
    context: &ConnectedDiagnostic,
    stage: FixtureStage,
    error: &std::io::Error,
    status: Option<std::process::ExitStatus>,
    stdout_eof: Option<bool>,
    stderr_eof: Option<bool>,
    out: usize,
    err: usize,
) {
    let category = match error.kind() {
        std::io::ErrorKind::TimedOut => FailureError::Timeout,
        std::io::ErrorKind::InvalidData if matches!(stage, FixtureStage::Cap) => {
            FailureError::OutputLimit
        }
        _ => FailureError::Io,
    };
    emit_failure(FailurePayload::Connected {
        mode: context.mode,
        stage,
        error: category,
        status: CachedStatus::from_status(status),
        stdout_eof,
        stderr_eof,
        stdout_bytes: out,
        stderr_bytes: err,
        markers: marker_facts(&context.actor, &context.connected),
    });
}
fn fixture_timeout_formatter_controls() {
    use std::os::unix::process::ExitStatusExt;
    let contains_canary = |bytes: &[u8]| {
        bytes
            .windows(b"PRIVATE_CANARY".len())
            .any(|w| w == b"PRIVATE_CANARY")
    };
    assert!(contains_canary(b"prefix_PRIVATE_CANARY_suffix"));
    assert!(!contains_canary(b"PRIVATE_CANAR"));
    let directory = tempfile::tempdir().unwrap();
    let private = directory.path().join("PRIVATE_CANARY");
    for mode in [
        "channel-close",
        "manager-stop",
        "no-channel",
        "rebind",
        "fresh-session",
        "body-failure",
        "observation-timeout",
    ] {
        for status in [
            None,
            Some(std::process::ExitStatus::from_raw(0)),
            Some(std::process::ExitStatus::from_raw(15)),
        ] {
            for error in [
                FailureError::Timeout,
                FailureError::Io,
                FailureError::OutputLimit,
                FailureError::Unknown,
            ] {
                let value = FailurePayload::Connected {
                    mode: ConnectedMode::from_mode(mode),
                    stage: FixtureStage::Spawn,
                    error,
                    status: CachedStatus::from_status(status),
                    stdout_eof: None,
                    stderr_eof: Some(false),
                    stdout_bytes: usize::MAX,
                    stderr_bytes: usize::MAX,
                    markers: marker_facts(&private, directory.path()),
                };
                let bytes = failure_bytes(&value).unwrap();
                assert!(bytes.len() <= 2048);
                assert_eq!(bytes, failure_bytes(&value).unwrap());
                assert!(!contains_canary(&bytes));
            }
        }
    }
    let events = ConnectedEvents::default();
    let locked = events.records.lock().unwrap();
    assert!(event_facts(Some(&events)).is_none());
    drop(locked);
    for site in [
        ReplacementSite::ParkedLink,
        ReplacementSite::ParkedOpened,
        ReplacementSite::DescendantReady,
        ReplacementSite::ParkedDetached,
        ReplacementSite::UpdateLink,
        ReplacementSite::UpdateAccept,
        ReplacementSite::NewBuildStatus,
        ReplacementSite::OldLeaderExit,
        ReplacementSite::OldDescendantExit,
        ReplacementSite::FreshLink,
        ReplacementSite::FreshExit,
        ReplacementSite::FinalStop,
    ] {
        let record = FailurePayload::Replacement {
            stage: site,
            progress: ReplacementProgress::default(),
            events: None,
            markers: marker_facts(&private, directory.path()),
            status_wait: None,
            update_wait: None,
            actor_stage: None,
        };
        assert!(failure_bytes(&record).unwrap().len() <= 2048);
    }
}
fn fixture_timeout_tag_control() {
    assert_eq!(
        serde_json::to_value(ReplacementSite::ParkedLink).unwrap(),
        "PARKED_LINK"
    );
    assert_eq!(
        serde_json::to_value(ReplacementSite::UpdateAccept).unwrap(),
        "UPDATE_ACCEPT"
    );
    let calls = std::cell::Cell::new(0);
    until_tagged(
        || {
            calls.set(calls.get() + 1);
            true
        },
        None,
    );
    assert_eq!(calls.get(), 1);
    let directory = tempfile::tempdir().unwrap();
    let progress = std::cell::Cell::new(ReplacementProgress::default());
    for site in [ReplacementSite::ParkedLink, ReplacementSite::UpdateAccept] {
        replacement_failure(ReplacementDiagnostic {
            site,
            progress: &progress,
            events: None,
            actor: directory.path(),
            replacement: None,
            status_wait: None,
            update_wait: None,
        });
    }
    assert!(!progress.get().offer_enqueued);
}
fn fixture_timeout_owner_control() {
    let directory = tempfile::tempdir().unwrap();
    let pidfile = directory.path().join("pid");
    let context = ConnectedDiagnostic {
        mode: ConnectedMode::ChannelClose,
        actor: directory.path().to_path_buf(),
        connected: directory.path().to_path_buf(),
    };
    let error = bounded_command_observe_diagnostic(
        Command::new("/bin/sh").args([
            "-c",
            "printf '%s' $$ > \"$1\"; printf ready; exec /bin/sleep 1",
            "fixture",
            pidfile.to_str().unwrap(),
        ]),
        128,
        Instant::now() + Duration::from_millis(100),
        || {},
        Some(&context),
    )
    .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
    let pid: i32 = std::fs::read_to_string(pidfile).unwrap().parse().unwrap();
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

fn bounded_fixture_receipt(path: &Path) -> String {
    use std::io::Read;
    let Ok(file) = std::fs::File::open(path) else {
        return "UNAVAILABLE".into();
    };
    let mut bytes = Vec::new();
    if file.take(257).read_to_end(&mut bytes).is_err()
        || bytes.len() > 256
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_ =-".contains(byte))
    {
        return "INVALID".into();
    }
    String::from_utf8(bytes).unwrap_or_else(|_| "INVALID".into())
}
fn connected_authority_controls() {
    let command = connected_actor_command(
        Path::new("/fixture with spaces"),
        Path::new("/fixture executable"),
    );
    let argv = crate::channel_backend::split_command(&command).unwrap();
    assert_eq!(argv[0], "/usr/bin/env");
    assert_eq!(argv[1], "QSH_DARWIN223_ACTOR=/fixture with spaces");
    assert_eq!(argv[2], "QSH_DARWIN223_CONNECTED_ACTOR=1");
    assert_eq!(argv[3], "/fixture executable");
    assert_eq!(argv.len(), 7);
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
    {
        let mut authority = ConnectedActorAuthority::new();
        let path = authority.path().to_path_buf();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_actor",
                "--nocapture",
            ])
            .env("QSH_DARWIN223_ACTOR", &path)
            .env("QSH_DARWIN223_CONNECTED_ACTOR", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut owner = OwnedCommand::spawn(&mut command).unwrap();
        until(|| path.join("actor-pid").exists());
        authority.observe();
        assert!(authority.bound.is_some());
        publish(&path.join("close-enqueued"));
        authority.observe();
        assert!(
            !path.join("close-observed").exists(),
            "an active actor cannot satisfy CLOSE proof"
        );
        authority.abort();
        until(|| {
            authority.observe();
            path.join("close-observed").exists()
        });
        assert!(owner
            .finish(Instant::now() + Duration::from_secs(3))
            .unwrap()
            .success());
        authority.finish(true);
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
    #[cfg(feature = "test-darwin-keeper")]
    let (backend, keeper_fixture) = super::keeper_integration_tests::native::backend();
    #[cfg(not(feature = "test-darwin-keeper"))]
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
    let signal_registry = registry.clone();
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
                    signal_checkpoint_write(
                        &directory,
                        signal_checkpoint(SignalCheckpointStage::SignalObserved, || {
                            signal_registry.try_cleanup_snapshot()
                        }),
                    );
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
            if mode == "no-channel" || mode == "no-channel-signal" { return Ok::<(), &'static str>(()); }
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
                // An adopted active channel may already have registry counts0.
                // Require the independent parent's actual bound actor NOTE_EXIT
                // after enqueue, then registry0, before any manager shutdown.
                publish(&body_actor_directory.join("close-enqueued"));
                connected_until(|| body_actor_directory.join("close-observed").exists()).await.map_err(|_| "CLOSE_OBSERVATION")?;
                connected_until(|| registry.outstanding() == 0 && registry.retiring_count() == 0).await.map_err(|_| "CLOSE_REGISTRY")?;
                if events.records.lock().unwrap().iter().any(|record| {
                    matches!(record, ServerRecord::Exit { stream, .. } if *stream == FIRST_CHANNEL_STREAM)
                }) { return Err("unexpected Exit after client CLOSE"); }
            }
            if mode == "fresh-session" {
                admit_fixture_true(Path::new(FIXTURE_TRUE)).map_err(|_| "FIXTURE_TRUE_ADMISSION")?;
                client.close();
                connected_until(|| registry.outstanding() == 0).await.map_err(|_| "OLD_CLIENT_REGISTRY")?;
                let fresh_keys = generate_keypair();
                allowlist.lock().unwrap().push(fresh_keys.public);
                let fresh_events = Arc::new(ConnectedEvents::default());
                let fresh = connect([2; 16], fresh_events.clone(), fresh_keys.private);
                let fresh_result = async {
                    connected_until(|| fresh_events.live.load(Ordering::SeqCst)).await.map_err(|_| "fresh link observation failed")?;
                    let open = OpenRequest {
                        stream: FIRST_CHANNEL_STREAM, kind: ChannelKind::Command,
                        cols: 80, rows: 24, screen: false, command: FIXTURE_TRUE.as_bytes().to_vec(),
                    };
                    fresh.send_bytes(CONTROL_STREAM, encode_client(&ClientRecord::Open(open)))
                        .map_err(|_| "fresh enqueue failed")?;
                    connected_until(|| fresh_events.records.lock().unwrap().iter().any(|record| {
                        matches!(record, ServerRecord::Exit { stream, code: 0 } if *stream == FIRST_CHANNEL_STREAM)
                    })).await.map_err(|_| "fresh exit observation failed")
                }.await;
                let records = fresh_events.records.lock().unwrap();
                let count = |predicate: fn(&ServerRecord) -> bool| records.iter().filter(|record| predicate(record)).count();
                let metadata = registry.try_cleanup_snapshot();
                let origin = records.iter().find_map(|r| match r { ServerRecord::Refused { reason, .. } => Some(refusal_origin(reason)), _ => None }).unwrap_or("NONE");
                let exit_code = records.iter().find_map(|r| match r { ServerRecord::Exit { code, .. } => Some(code.to_string()), _ => None }).unwrap_or_else(|| "none".into());
                let receipt = format!("live={} opened={} exit0={} exitother={} code={} unavailable={} refused={} origin={} errno=UNKNOWN input_failed={} pending={} retiring={} debt={} leader_unknown={} cleanup_unknown={} unconfirmed={}",
                    fresh_events.live.load(Ordering::SeqCst) as u8,
                    count(|r| matches!(r, ServerRecord::Opened { .. })),
                    count(|r| matches!(r, ServerRecord::Exit { code: 0, .. })),
                    count(|r| matches!(r, ServerRecord::Exit { code, .. } if *code != 0)),
                    exit_code,
                    count(|r| matches!(r, ServerRecord::ExitStatusUnavailable { .. })),
                    count(|r| matches!(r, ServerRecord::Refused { .. })),
                    origin,
                    fresh_events.input_failed.load(Ordering::SeqCst) as u8,
                    metadata.as_ref().map(|m| m.healthy_pending_opens.to_string()).unwrap_or_else(|| "none".into()),
                    metadata.as_ref().map(|m| m.retiring_channels.to_string()).unwrap_or_else(|| "none".into()),
                    metadata.as_ref().map(|m| m.unique_cleanup_debt.to_string()).unwrap_or_else(|| "none".into()),
                    metadata.as_ref().is_some_and(|m| m.leader_unconfirmed) as u8,
                    metadata.as_ref().is_some_and(|m| m.cleanup_unconfirmed) as u8,
                    metadata.as_ref().map(|m| m.observed_unconfirmed_owners.to_string()).unwrap_or_else(|| "none".into()));
                publish_bytes(&body_actor_directory.join("fresh-receipt"), receipt.as_bytes());
                drop(records);
                fresh.close();
                fresh_result?;
            }
            if events.input_failed.load(Ordering::SeqCst) { return Err("client input failed"); }
            Ok(())
        }).await {
            Ok(result)=>result,
            Err(error)=>Err(connected_body_join_error(&error)),
        }
    };
    let failure_code = connected_body_failure_code(result);
    publish_bytes(
        &actor_directory.join("failure-code"),
        failure_code.token().as_bytes(),
    );
    // This is the manager-stop seam, not a claim about the wire STOP
    // endpoint. Always retain and await the real lifecycle drain.
    if let Some(directory) = signal_directory {
        signal_checkpoint_write(
            directory,
            signal_checkpoint(SignalCheckpointStage::Ready, || {
                registry.try_cleanup_snapshot()
            }),
        );
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
            if let Some(directory) = signal_directory {
                signal_checkpoint_write(
                    directory,
                    signal_checkpoint(SignalCheckpointStage::ObservationTimeout, || {
                        registry.try_cleanup_snapshot()
                    }),
                );
            }
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
    #[cfg(feature = "test-darwin-keeper")]
    keeper_fixture.assert_settled(if mode == "fresh-session" {
        2
    } else if mode == "no-channel" || mode == "no-channel-signal" {
        0
    } else {
        1
    });
    if let Some(directory) = signal_directory {
        signal_checkpoint_write(
            directory,
            signal_checkpoint(SignalCheckpointStage::ManagerJoined, || {
                registry.try_cleanup_snapshot()
            }),
        );
    }
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
        let diagnostic = ConnectedDiagnostic {
            mode: ConnectedMode::from_mode(mode),
            actor: actors.path().to_path_buf(),
            connected: directory.path().to_path_buf(),
        };
        let output = bounded_command_observe_diagnostic(
            &mut command,
            64 * 1024,
            Instant::now() + Duration::from_secs(90),
            || actors.observe(),
            Some(&diagnostic),
        )
        .unwrap();
        let expected_failure = matches!(mode, "body-failure" | "observation-timeout");
        #[cfg(feature = "test-darwin-keeper")]
        super::keeper_integration_tests::native::assert_routes(
            &output.stderr,
            if mode == "fresh-session" {
                2
            } else if mode == "no-channel" {
                0
            } else {
                1
            },
        );
        if !output.status.success() {
            actors.abort();
        }
        actors.finish(mode != "no-channel");
        assert_eq!(
            output.status.success(),
            !expected_failure,
            "connected fixture mode={mode} stage={} facts={}",
            bounded_fixture_receipt(&actors.path().join("failure-code")),
            bounded_fixture_receipt(&actors.path().join("fresh-receipt"))
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
        if mode == "last-fork" {
            // Preserve the intended normal leader status before escalating the
            // remaining grandchild. poll_leader is WNOWAIT: SID custody stays
            // reserved, and no consuming wait can occur at this barrier.
            until(|| scope.poll_leader(&mut ops) == Ok(Some(0)));
            assert_eq!(guard.waits.load(Ordering::SeqCst), 0);
        }
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut captured_last_fork = mode != "last-fork";
        loop {
            let progress = scope.step(&mut ops);
            if mode == "last-fork" && scope.retained().1 > 0 {
                assert_eq!(guard.waits.load(Ordering::SeqCst), 0);
                captured_last_fork = true;
                scope.escalate();
            }
            if let super::scope::Progress::Complete(code) = progress {
                assert_eq!(code, 0, "fixture normal leader completion; mode={mode}");
                break;
            }
            assert!(
                Instant::now() < deadline,
                "native candidate closure failed; mode={mode} progress={progress:?} retained={:?} census={:?}",
                scope.retained(), scope.census()
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
    let cache = home.join("qsh");
    let expected_control = cache.join("control.sock");
    // bind_private publishes by rename; local_addr retains the .cPID/s bind
    // name. Handover carries the published endpoint, not that kernel address.
    use std::os::unix::fs::FileTypeExt;
    assert!(std::fs::symlink_metadata(&expected_control)
        .unwrap()
        .file_type()
        .is_socket());
    assert!(listener.local_addr().unwrap().as_pathname().is_some());
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
        .env("QSH_DARWIN223_CACHE", &cache)
        .env("QSH_DARWIN223_CONTROL_PATH", &expected_control)
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
        .stderr(Stdio::piped());
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
fn gate_remaining(end: Instant) -> std::io::Result<Duration> {
    end.checked_duration_since(Instant::now())
        .filter(|remaining| !remaining.is_zero())
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::TimedOut, "bootstrap gate deadline"))
}
fn bootstrap_gate(gate: &mut std::os::unix::net::UnixStream) -> std::io::Result<()> {
    bootstrap_gate_until(gate, Instant::now() + Duration::from_secs(10))
}
fn bootstrap_gate_until(
    gate: &mut std::os::unix::net::UnixStream,
    end: Instant,
) -> std::io::Result<()> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    gate_remaining(end)?;
    let fd = gate.as_raw_fd();
    let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
    if flags < 0
        || unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) } < 0
    {
        return Err(std::io::Error::last_os_error());
    }
    gate_remaining(end)?;
    let mut frame = [0; 4];
    let mut used = 0;
    loop {
        gate_remaining(end)?;
        let result = gate.read(&mut frame[used..]);
        gate_remaining(end)?;
        match result {
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
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(gate_remaining(end)?.min(Duration::from_millis(1)));
            }
            Err(error) => return Err(error),
        }
    }
}
fn fixture_gate_controls() {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    for full_close in [false, true] {
        for (frame, expected) in [
            (b"GO\n".as_slice(), true),
            (b"NO\n".as_slice(), false),
            (b"GO\nX".as_slice(), false),
            (b"".as_slice(), false),
            (b"G".as_slice(), false),
            (b"GO".as_slice(), false),
        ] {
            let (mut parent, mut child) = std::os::unix::net::UnixStream::pair().unwrap();
            let before = unsafe { nix::libc::fcntl(child.as_raw_fd(), nix::libc::F_GETFL) };
            assert!(before >= 0);
            parent.write_all(frame).unwrap();
            parent.shutdown(std::net::Shutdown::Write).unwrap();
            let _parent = if full_close {
                drop(parent);
                None
            } else {
                Some(parent)
            };
            assert_eq!(bootstrap_gate(&mut child).is_ok(), expected);
            let after = unsafe { nix::libc::fcntl(child.as_raw_fd(), nix::libc::F_GETFL) };
            assert_eq!(after, before | nix::libc::O_NONBLOCK);
        }
    }
    for frame in [b"GO\n".as_slice(), b"G".as_slice()] {
        let (mut parent, mut child) = std::os::unix::net::UnixStream::pair().unwrap();
        parent.write_all(frame).unwrap();
        let end = Instant::now() + Duration::from_millis(15);
        let error = bootstrap_gate_until(&mut child, end).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(Instant::now() >= end);
        drop(parent);
    }
    fixture_expired_gate_control();
}
fn fixture_expired_gate_control() {
    use std::io::Write;
    let (mut parent, mut child) = std::os::unix::net::UnixStream::pair().unwrap();
    parent.write_all(b"GO\n").unwrap();
    parent.shutdown(std::net::Shutdown::Write).unwrap();
    drop(parent);
    let end = Instant::now() - Duration::from_millis(1);
    assert_eq!(
        bootstrap_gate_until(&mut child, end).unwrap_err().kind(),
        std::io::ErrorKind::TimedOut
    );
}
fn fixture_socket_publication_controls() {
    use std::os::unix::fs::{DirBuilderExt, FileTypeExt};
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = std::env::temp_dir().join(format!(
        "qsh223-socket-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&root)
        .unwrap();
    let staging = root.join(format!(".c{}", std::process::id()));
    let published = root.join("control.sock");
    struct RemoveOwnedSocket {
        root: std::path::PathBuf,
        staging: std::path::PathBuf,
        published: std::path::PathBuf,
    }
    impl Drop for RemoveOwnedSocket {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.published);
            let _ = std::fs::remove_file(self.staging.join("s"));
            let _ = std::fs::remove_dir(&self.staging);
            let _ = std::fs::remove_dir(&self.root);
        }
    }
    let _cleanup = RemoveOwnedSocket {
        root,
        staging: staging.clone(),
        published: published.clone(),
    };
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&staging)
        .unwrap();
    let bound = staging.join("s");
    let listener = std::os::unix::net::UnixListener::bind(&bound).unwrap();
    std::fs::rename(&bound, &published).unwrap();
    assert_eq!(
        listener.local_addr().unwrap().as_pathname(),
        Some(bound.as_path())
    );
    assert_ne!(bound, published);
    assert!(std::fs::symlink_metadata(&published)
        .unwrap()
        .file_type()
        .is_socket());
}
const PROOF_LIMIT: u64 = 512 * 1024 * 1024;
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RenameProof {
    case: String,
    checksum_errno: String,
    checksum_matches: Option<bool>,
    checksum_result: String,
    copied_bytes: u64,
    current_exe_errno: String,
    current_exe_location: String,
    fixture: String,
    kind: String,
    new_hash_matches: bool,
    old_absent: bool,
    request: String,
    same_inode: bool,
    schema: u32,
    source_sha256: String,
    status_checksum_matches: Option<bool>,
    status_errno: String,
    status_result: String,
}
const PROOF_ERRNOS: [&str; 13] = [
    "ENOENT",
    "EACCES",
    "EPERM",
    "EIO",
    "EINVAL",
    "EBADF",
    "EMFILE",
    "ENFILE",
    "ENOMEM",
    "ENOSPC",
    "EFBIG",
    "ETIMEDOUT",
    "UNKNOWN",
];
fn proof_errno(error: &anyhow::Error) -> &'static str {
    let value = error.chain().take(8).find_map(|item| {
        item.downcast_ref::<std::io::Error>()
            .and_then(|e| e.raw_os_error())
    });
    match value {
        Some(nix::libc::ENOENT) => "ENOENT",
        Some(nix::libc::EACCES) => "EACCES",
        Some(nix::libc::EPERM) => "EPERM",
        Some(nix::libc::EIO) => "EIO",
        Some(nix::libc::EINVAL) => "EINVAL",
        Some(nix::libc::EBADF) => "EBADF",
        Some(nix::libc::EMFILE) => "EMFILE",
        Some(nix::libc::ENFILE) => "ENFILE",
        Some(nix::libc::ENOMEM) => "ENOMEM",
        Some(nix::libc::ENOSPC) => "ENOSPC",
        Some(nix::libc::EFBIG) => "EFBIG",
        Some(nix::libc::ETIMEDOUT) => "ETIMEDOUT",
        _ => "UNKNOWN",
    }
}
fn proof_json(record: &RenameProof) -> Vec<u8> {
    // Field declarations are lexical: all admitted strings are ASCII tokens.
    let mut bytes = serde_json::to_vec(record).unwrap();
    bytes.push(b'\n');
    bytes
}
fn proof_result_valid(result: &str, matched: Option<bool>, errno: &str) -> bool {
    match result {
        "ok" => matched.is_some() && errno == "NONE",
        "error" => matched.is_none() && PROOF_ERRNOS.contains(&errno),
        "not_called" => matched.is_none() && errno == "NONE",
        _ => false,
    }
}
fn parse_proof_record(
    raw: &[u8],
    case: &str,
    request: &str,
    sha: &str,
    size: u64,
) -> Result<RenameProof, &'static str> {
    if raw.is_empty() || raw.len() > 1024 {
        return Err("PROOF_RECORD");
    }
    let record: RenameProof = serde_json::from_slice(raw).map_err(|_| "PROOF_RECORD")?;
    let lower_hex = |value: &str, len| {
        value.len() == len
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    };
    if proof_json(&record) != raw
        || record.schema != 1
        || record.kind != "darwin-rename-checksum-proof"
        || !matches!(record.case.as_str(), "baseline" | "renamed")
        || record.case != case
        || !lower_hex(&record.request, 32)
        || record.request != request
        || !lower_hex(&record.source_sha256, 64)
        || record.source_sha256 != sha
        || !(1..=PROOF_LIMIT).contains(&record.copied_bytes)
        || record.copied_bytes != size
        || !matches!(record.fixture.as_str(), "ready" | "refused")
        || !matches!(
            record.current_exe_location.as_str(),
            "old" | "new" | "other" | "unavailable"
        )
        || (if record.current_exe_location == "unavailable" {
            !PROOF_ERRNOS.contains(&record.current_exe_errno.as_str())
        } else {
            record.current_exe_errno != "NONE"
        })
        || !proof_result_valid(
            &record.checksum_result,
            record.checksum_matches,
            &record.checksum_errno,
        )
        || !proof_result_valid(
            &record.status_result,
            record.status_checksum_matches,
            &record.status_errno,
        )
    {
        return Err("PROOF_RECORD");
    }
    if record.fixture == "ready"
        && (!record.same_inode
            || !record.new_hash_matches
            || record.old_absent != (case == "renamed")
            || record.checksum_result == "not_called"
            || record.status_result == "not_called")
    {
        return Err("PROOF_PRECONDITION");
    }
    Ok(record)
}
fn proof_refused(case: &str, request: &str, sha: &str, size: u64) -> RenameProof {
    RenameProof {
        case: case.into(),
        checksum_errno: "NONE".into(),
        checksum_matches: None,
        checksum_result: "not_called".into(),
        copied_bytes: size,
        current_exe_errno: "UNKNOWN".into(),
        current_exe_location: "unavailable".into(),
        fixture: "refused".into(),
        kind: "darwin-rename-checksum-proof".into(),
        new_hash_matches: false,
        old_absent: false,
        request: request.into(),
        same_inode: false,
        schema: 1,
        source_sha256: sha.into(),
        status_checksum_matches: None,
        status_errno: "NONE".into(),
        status_result: "not_called".into(),
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
struct ProofFileIdentity {
    dev: u64,
    ino: u64,
    mode: u32,
    links: u64,
    uid: u32,
    gid: u32,
    size: u64,
    modified: i64,
    modified_ns: i64,
    changed: i64,
    changed_ns: i64,
}
fn proof_identity(info: &std::fs::Metadata) -> ProofFileIdentity {
    use std::os::unix::fs::MetadataExt;
    ProofFileIdentity {
        dev: info.dev(),
        ino: info.ino(),
        mode: info.mode(),
        links: info.nlink(),
        uid: info.uid(),
        gid: info.gid(),
        size: info.len(),
        modified: info.mtime(),
        modified_ns: info.mtime_nsec(),
        changed: info.ctime(),
        changed_ns: info.ctime_nsec(),
    }
}
fn proof_require_absent(path: &Path) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => anyhow::bail!("PROOF_PREEXISTING"),
        Err(error) => Err(error.into()),
    }
}
fn proof_open(path: &Path) -> anyhow::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK)
        .open(path)?;
    let info = file.metadata()?;
    anyhow::ensure!(
        info.is_file() && (1..=PROOF_LIMIT).contains(&info.len()),
        "PROOF_INPUT"
    );
    anyhow::ensure!(
        proof_identity(&std::fs::symlink_metadata(path)?) == proof_identity(&info),
        "PROOF_ROUTE"
    );
    Ok(file)
}
fn proof_hash(file: &mut std::fs::File, size: u64, end: Instant) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    gate_remaining(end)?;
    file.seek(SeekFrom::Start(0))?;
    let mut value = Sha256::new();
    let mut total = 0;
    let mut buffer = [0; 64 * 1024];
    loop {
        gate_remaining(end)?;
        let limit = ((size - total + 1).min(buffer.len() as u64)) as usize;
        let count = file.read(&mut buffer[..limit])?;
        gate_remaining(end)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        anyhow::ensure!(total <= size, "PROOF_SIZE");
        value.update(&buffer[..count]);
    }
    anyhow::ensure!(total == size, "PROOF_SIZE");
    Ok(hex::encode(value.finalize()))
}
fn proof_source_bound(
    file: &std::fs::File,
    path: &Path,
    expected: ProofFileIdentity,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        proof_identity(&file.metadata()?) == expected
            && proof_identity(&std::fs::symlink_metadata(path)?) == expected,
        "PROOF_SOURCE_DRIFT"
    );
    Ok(())
}
fn proof_copy(
    source: &mut std::fs::File,
    source_path: &Path,
    source_identity: ProofFileIdentity,
    destination: &Path,
    end: Instant,
) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::fs::OpenOptionsExt;
    gate_remaining(end)?;
    proof_source_bound(source, source_path, source_identity)?;
    source.seek(SeekFrom::Start(0))?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination)?;
    let mut total = 0;
    let mut value = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        gate_remaining(end)?;
        let limit = ((source_identity.size - total + 1).min(buffer.len() as u64)) as usize;
        let count = source.read(&mut buffer[..limit])?;
        gate_remaining(end)?;
        if count == 0 {
            break;
        }
        total += count as u64;
        anyhow::ensure!(total <= source_identity.size, "PROOF_SIZE");
        output.write_all(&buffer[..count])?;
        value.update(&buffer[..count]);
    }
    anyhow::ensure!(total == source_identity.size, "PROOF_SIZE");
    output.sync_all()?;
    use std::os::unix::fs::PermissionsExt;
    output.set_permissions(std::fs::Permissions::from_mode(0o700))?;
    drop(output);
    proof_source_bound(source, source_path, source_identity)?;
    let expected = hex::encode(value.finalize());
    let mut copied = proof_open(destination)?;
    let before = proof_identity(&copied.metadata()?);
    anyhow::ensure!(
        proof_hash(&mut copied, source_identity.size, end)? == expected,
        "PROOF_COPY_HASH"
    );
    proof_source_bound(&copied, destination, before)?;
    Ok(expected)
}

fn proof_control_record() -> RenameProof {
    let mut record = proof_refused("baseline", &"1".repeat(32), &"a".repeat(64), 7);
    record.fixture = "ready".into();
    record.same_inode = true;
    record.new_hash_matches = true;
    record.current_exe_location = "old".into();
    record.current_exe_errno = "NONE".into();
    record.checksum_result = "ok".into();
    record.checksum_matches = Some(true);
    record.status_result = "ok".into();
    record.status_checksum_matches = Some(true);
    record
}
fn proof_control_actor(mode: &str) {
    let mut bytes = proof_json(&proof_control_record());
    if mode == "oversize" {
        bytes.resize(1025, b' ');
    }
    use std::io::Write;
    std::io::stderr().write_all(&bytes).unwrap();
    if mode == "nonzero" {
        std::process::exit(7);
    }
}
fn fixture_proof_schema_controls() {
    let record = proof_control_record();
    assert!(proof_checksums_usable(&record));
    let mut invalid_baseline = record.clone();
    invalid_baseline.checksum_matches = Some(false);
    assert!(!proof_checksums_usable(&invalid_baseline));
    let raw = proof_json(&record);
    let parse =
        |raw: &[u8]| parse_proof_record(raw, "baseline", &"1".repeat(32), &"a".repeat(64), 7);
    assert!(parse(&raw).is_ok());
    let mut spaced = raw.clone();
    spaced.insert(1, b' ');
    assert!(parse(&spaced).is_err());
    assert!(parse(&vec![b' '; 1025]).is_err());
    assert!(parse(&raw[..raw.len() - 1]).is_err());
    let mut value: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    for key in value
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect::<Vec<_>>()
    {
        let mut missing = value.clone();
        missing.as_object_mut().unwrap().remove(&key);
        assert!(parse(&serde_json::to_vec(&missing).unwrap()).is_err());
    }
    value["unknown"] = serde_json::json!(true);
    assert!(parse(&serde_json::to_vec(&value).unwrap()).is_err());
    let duplicate = String::from_utf8(raw.clone())
        .unwrap()
        .replace("\"schema\":1", "\"schema\":1,\"schema\":1");
    assert!(parse(duplicate.as_bytes()).is_err());
    for field in ["same_inode", "new_hash_matches"] {
        let mut bad = record.clone();
        if field == "same_inode" {
            bad.same_inode = false;
        } else {
            bad.new_hash_matches = false;
        }
        assert!(parse(&proof_json(&bad)).is_err());
    }
    let mut bad = record.clone();
    bad.old_absent = true;
    assert!(parse(&proof_json(&bad)).is_err());
    let mut bad = record.clone();
    bad.current_exe_location = "unavailable".into();
    assert!(parse(&proof_json(&bad)).is_err());
    let mut bad = record.clone();
    bad.checksum_errno = "ENOENT".into();
    assert!(parse(&proof_json(&bad)).is_err());
    let mut bad = record.clone();
    bad.status_checksum_matches = None;
    assert!(parse(&proof_json(&bad)).is_err());
    let mut bad = record.clone();
    bad.request = "2".repeat(32);
    assert!(parse(&proof_json(&bad)).is_err());
    let mut bad = record.clone();
    bad.source_sha256 = "b".repeat(64);
    assert!(parse(&proof_json(&bad)).is_err());
    let mut bad = record.clone();
    bad.copied_bytes = 8;
    assert!(parse(&proof_json(&bad)).is_err());
    let mut bad = record.clone();
    bad.case = "renamed".into();
    assert!(parse(&proof_json(&bad)).is_err());
    let mut bad = record.clone();
    bad.checksum_result = "not_called".into();
    bad.checksum_matches = None;
    assert!(parse(&proof_json(&bad)).is_err());
    let refused = proof_refused("baseline", &"1".repeat(32), &"a".repeat(64), 7);
    assert_eq!(parse(&proof_json(&refused)).unwrap().fixture, "refused");
    let bool_schema = String::from_utf8(raw.clone())
        .unwrap()
        .replace("\"schema\":1", "\"schema\":true");
    assert!(parse(bool_schema.as_bytes()).is_err());
    let mut renamed = record.clone();
    renamed.case = "renamed".into();
    renamed.old_absent = true;
    renamed.current_exe_location = "old".into();
    renamed.checksum_result = "error".into();
    renamed.checksum_matches = None;
    renamed.checksum_errno = "ENOENT".into();
    renamed.status_result = "error".into();
    renamed.status_checksum_matches = None;
    renamed.status_errno = "ENOENT".into();
    assert!(parse_proof_record(
        &proof_json(&renamed),
        "renamed",
        &"1".repeat(32),
        &"a".repeat(64),
        7
    )
    .is_ok());
}
fn fixture_proof_copy_controls() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing-sibling");
    proof_require_absent(&missing).unwrap();
    std::os::unix::fs::symlink("absent-target", &missing).unwrap();
    assert!(proof_require_absent(&missing).is_err());
    assert!(std::fs::symlink_metadata(&missing)
        .unwrap()
        .file_type()
        .is_symlink());
    let source = dir.path().join("source");
    std::fs::write(&source, b"inert source bytes").unwrap();
    let mut file = proof_open(&source).unwrap();
    let identity = proof_identity(&file.metadata().unwrap());
    let end = Instant::now() + Duration::from_secs(2);
    let expected = proof_hash(&mut file, identity.size, end).unwrap();
    let copy = dir.path().join("copy");
    assert_eq!(
        proof_copy(&mut file, &source, identity, &copy, end).unwrap(),
        expected
    );
    let mut output = proof_open(&copy).unwrap();
    assert_eq!(
        proof_hash(&mut output, identity.size, end).unwrap(),
        expected
    );
    assert!(proof_copy(&mut file, &source, identity, &copy, end).is_err());
    let mut wrong = identity;
    wrong.size -= 1;
    assert!(proof_copy(&mut file, &source, wrong, &dir.path().join("wrong"), end).is_err());
    assert!(proof_hash(&mut file, 1, end).is_err());
    assert!(proof_hash(
        &mut file,
        identity.size,
        Instant::now() - Duration::from_millis(1)
    )
    .is_err());
    std::os::unix::fs::symlink(&source, dir.path().join("link")).unwrap();
    assert!(proof_open(&dir.path().join("link")).is_err());
    std::fs::write(&source, b"changed contents!").unwrap();
    assert!(proof_source_bound(&file, &source, identity).is_err());
}
fn fixture_proof_owner_controls() {
    for mode in ["good", "oversize", "nonzero"] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_signal_server",
                "--nocapture",
            ])
            .env("QSH_DARWIN223_SIGNAL_SERVER", "/private-fixture-canary")
            .env("QSH_DARWIN223_PROOF_CONTROL", mode)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut owner = OwnedCommand::spawn(&mut command).unwrap();
        owner.capture_stderr().unwrap();
        let status = owner
            .finish(Instant::now() + Duration::from_secs(3))
            .unwrap();
        assert!(owner.captured_stderr.is_none());
        let parsed = if status.success() {
            parse_proof_record(
                &owner.stderr_bytes,
                "baseline",
                &"1".repeat(32),
                &"a".repeat(64),
                7,
            )
            .ok()
        } else {
            None
        };
        assert_eq!(parsed.is_some(), mode == "good");
        assert!(owner.status.is_some());
    }
}

fn rename_proof_actor() {
    // This entry is selected in a fresh dedicated libtest process, before any
    // code that can warm the production checksum cache.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| eprintln!("QSH223_PROOF FIXTURE_REFUSED")));
    let case = std::env::var("QSH_DARWIN223_RENAME_PROOF").unwrap();
    let request = std::env::var("QSH_DARWIN223_PROOF_REQUEST").unwrap();
    let sha = std::env::var("QSH_DARWIN223_PROOF_SHA256").unwrap();
    let size: u64 = std::env::var("QSH_DARWIN223_PROOF_BYTES")
        .unwrap()
        .parse()
        .unwrap();
    let mut record = proof_refused(&case, &request, &sha, size);
    // Validate all output-bound strings before they can enter a record.
    parse_proof_record(&proof_json(&record), &case, &request, &sha, size).unwrap();
    let result =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> anyhow::Result<()> {
            let old = std::path::PathBuf::from(
                std::env::var_os("QSH_DARWIN223_PROOF_OLD")
                    .ok_or_else(|| anyhow::anyhow!("PROOF_INPUT"))?,
            );
            let new = old.with_file_name("renamed-image");
            anyhow::ensure!(old.is_absolute(), "PROOF_INPUT");
            proof_require_absent(&new)?;
            let millis: u64 = std::env::var("QSH_DARWIN223_PROOF_MILLIS")?.parse()?;
            anyhow::ensure!((1..=10_000).contains(&millis), "PROOF_DEADLINE");
            let end = Instant::now() + Duration::from_millis(millis);
            let mut image = proof_open(&old)?;
            let before = proof_identity(&image.metadata()?);
            anyhow::ensure!(
                before.size == size && proof_hash(&mut image, size, end)? == sha,
                "PROOF_SOURCE"
            );
            proof_source_bound(&image, &old, before)?;
            let launched = std::env::current_exe()?;
            let launched_identity = proof_identity(&std::fs::metadata(&launched)?);
            anyhow::ensure!(
                (launched_identity.dev, launched_identity.ino) == (before.dev, before.ino),
                "PROOF_LAUNCH"
            );
            if case == "renamed" {
                gate_remaining(end)?;
                std::fs::rename(&old, &new)?;
            }
            // Both production calls below are deliberately AFTER the rename.
            let selected = if case == "renamed" { &new } else { &old };
            let after = proof_identity(&std::fs::symlink_metadata(selected)?);
            record.same_inode = (after.dev, after.ino) == (before.dev, before.ino);
            record.old_absent = match std::fs::symlink_metadata(&old) {
                Ok(_) => false,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
                Err(error) => return Err(error.into()),
            };
            record.new_hash_matches = proof_hash(&mut image, size, end)? == sha;
            proof_source_bound(&image, selected, after)?;
            anyhow::ensure!(
                record.same_inode
                    && record.new_hash_matches
                    && record.old_absent == (case == "renamed"),
                "PROOF_PRECONDITION"
            );
            match std::env::current_exe() {
                Ok(path) => {
                    record.current_exe_location = if path == old {
                        "old"
                    } else if path == new {
                        "new"
                    } else {
                        "other"
                    }
                    .into();
                    record.current_exe_errno = "NONE".into();
                }
                Err(error) => {
                    record.current_exe_location = "unavailable".into();
                    record.current_exe_errno = proof_errno(&error.into()).into();
                }
            }
            gate_remaining(end)?;
            match crate::state::self_checksum() {
                Ok(value) => {
                    record.checksum_result = "ok".into();
                    record.checksum_matches = Some(value == sha);
                    record.checksum_errno = "NONE".into();
                }
                Err(error) => {
                    record.checksum_result = "error".into();
                    record.checksum_matches = None;
                    record.checksum_errno = proof_errno(&error).into();
                }
            }
            gate_remaining(end)?;
            match crate::transport_daemon::transport_status_response(&[], 0, None) {
                Ok(value) => {
                    record.status_result = "ok".into();
                    record.status_checksum_matches = Some(value.checksum == sha);
                    record.status_errno = "NONE".into();
                }
                Err(error) => {
                    record.status_result = "error".into();
                    record.status_checksum_matches = None;
                    record.status_errno = proof_errno(&error).into();
                }
            }
            gate_remaining(end)?;
            anyhow::ensure!(
                proof_hash(&mut image, size, end)? == sha,
                "PROOF_FINAL_HASH"
            );
            proof_source_bound(&image, selected, after)?;
            record.fixture = "ready".into();
            Ok(())
        }));
    if !matches!(result, Ok(Ok(()))) {
        record.fixture = "refused".into();
    }
    std::panic::set_hook(previous);
    let raw = proof_json(&record);
    assert!(raw.len() <= 1024);
    use std::io::Write;
    std::io::stderr().write_all(&raw).unwrap();
}
fn proof_checksums_usable(record: &RenameProof) -> bool {
    record.checksum_result == "ok"
        && record.checksum_matches == Some(true)
        && record.status_result == "ok"
        && record.status_checksum_matches == Some(true)
}
fn run_rename_proof() {
    eprintln!("darwin223 original_update_reached=false");
    let end = Instant::now() + Duration::from_secs(30);
    let source_path = std::env::current_exe().unwrap();
    let mut source = proof_open(&source_path).expect("FIXTURE_REFUSED");
    let source_identity = proof_identity(&source.metadata().unwrap());
    let source_sha = proof_hash(&mut source, source_identity.size, end).expect("FIXTURE_REFUSED");
    let baseline_directory = tempfile::tempdir().unwrap();
    let rename_directory = tempfile::tempdir().unwrap();
    let baseline_path = baseline_directory.path().join("proof-image");
    let rename_path = rename_directory.path().join("proof-image");
    // Both copies and the original descriptor stay owned until both children settle.
    for path in [&baseline_path, &rename_path] {
        assert_eq!(
            proof_copy(&mut source, &source_path, source_identity, path, end)
                .expect("FIXTURE_REFUSED"),
            source_sha
        );
    }
    let mut records = Vec::new();
    let mut requests = Vec::new();
    for (case, path) in [("baseline", &baseline_path), ("renamed", &rename_path)] {
        gate_remaining(end).expect("FIXTURE_REFUSED");
        let request = hex::encode(&transport::handshake::generate_keypair().public[..16]);
        assert!(!requests.contains(&request));
        requests.push(request.clone());
        let actor_end = end.min(Instant::now() + Duration::from_secs(10));
        let millis = gate_remaining(actor_end)
            .expect("FIXTURE_REFUSED")
            .as_millis()
            .min(10_000);
        assert!(millis > 0);
        let mut command = Command::new(path);
        command
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_signal_server",
                "--nocapture",
            ])
            .env("QSH_DARWIN223_SIGNAL_SERVER", path.parent().unwrap())
            .env("QSH_DARWIN223_RENAME_PROOF", case)
            .env("QSH_DARWIN223_PROOF_REQUEST", &request)
            .env("QSH_DARWIN223_PROOF_SHA256", &source_sha)
            .env(
                "QSH_DARWIN223_PROOF_BYTES",
                source_identity.size.to_string(),
            )
            .env("QSH_DARWIN223_PROOF_OLD", path)
            .env("QSH_DARWIN223_PROOF_MILLIS", millis.to_string())
            .env("HISTFILE", "/dev/null")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        gate_remaining(actor_end).expect("FIXTURE_REFUSED");
        let mut owner = OwnedCommand::spawn(&mut command).expect("FIXTURE_REFUSED");
        owner.capture_stderr().expect("FIXTURE_REFUSED");
        let status = owner.finish(actor_end).expect("FIXTURE_REFUSED");
        gate_remaining(actor_end).expect("FIXTURE_REFUSED");
        assert!(
            status.success() && owner.status.is_some() && owner.captured_stderr.is_none(),
            "FIXTURE_REFUSED"
        );
        let record = parse_proof_record(
            &owner.stderr_bytes,
            case,
            &request,
            &source_sha,
            source_identity.size,
        )
        .expect("FIXTURE_REFUSED");
        records.push(record);
        // No success is inferred from failure-only Drop rescue.
        drop(owner);
    }
    proof_source_bound(&source, &source_path, source_identity).expect("FIXTURE_REFUSED");
    gate_remaining(end).expect("FIXTURE_REFUSED");
    for record in &records {
        eprint!(
            "darwin223 rename_proof={}",
            std::str::from_utf8(&proof_json(record)).unwrap()
        );
    }
    assert!(
        records.iter().all(|record| record.fixture == "ready"),
        "FIXTURE_REFUSED"
    );
    assert!(
        proof_checksums_usable(&records[0]),
        "FIXTURE_REFUSED_BASELINE"
    );
    assert!(
        proof_checksums_usable(&records[1]),
        "Darwin rename checksum/STATUS regression"
    );
    eprintln!("darwin223 original_update_reached=true");
}

fn bootstrap_failure_control(mode: &str) {
    let previous = bootstrap_hook();
    let result = std::panic::catch_unwind(|| {
        bootstrap_stage(BootstrapStage::StateFile);
        match mode {
            "missing" => {
                bootstrap_result(std::fs::File::open("/qsh223-no-such-private-canary/state"));
            }
            "typed" => {
                bootstrap_stage(BootstrapStage::FdFlags);
                bootstrap_result(Err::<(), _>(nix::errno::Errno::EINVAL));
            }
            "assert" => {
                BOOTSTRAP_ERROR.store(BootstrapErrno::Enoent as usize, Ordering::SeqCst);
                bootstrap_stage(BootstrapStage::Parent);
                panic!("private assertion canary must never be emitted");
            }
            _ => panic!("invalid private control"),
        }
    });
    std::panic::set_hook(previous);
    std::panic::resume_unwind(result.unwrap_err());
}
fn bootstrap_actor() {
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::ffi::OsStrExt;
    bootstrap_stage(BootstrapStage::Input);
    let _previous_hook = bootstrap_hook();
    let parent: u32 = std::env::var("QSH_DARWIN223_PARENT")
        .unwrap()
        .parse()
        .unwrap();
    bootstrap_stage(BootstrapStage::Parent);
    assert_eq!(unsafe { nix::libc::getppid() } as u32, parent);
    bootstrap_stage(BootstrapStage::Input);
    let fd = |name: &str| -> i32 { std::env::var(name).unwrap().parse().unwrap() };
    let fds = [
        fd("QSH_DARWIN223_UDP"),
        fd("QSH_DARWIN223_CONTROL"),
        fd("QSH_DARWIN223_GATE"),
    ];
    bootstrap_stage(BootstrapStage::FdValidate);
    assert!(fds.iter().all(|fd| *fd > 2));
    assert!(fds[0] != fds[1] && fds[0] != fds[2] && fds[1] != fds[2]);
    // These descriptors are the three exclusively inherited actor inputs.
    let udp = unsafe { std::net::UdpSocket::from_raw_fd(fds[0]) };
    let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fds[1]) };
    let mut gate = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fds[2]) };
    for fd in fds {
        bootstrap_stage(BootstrapStage::FdFlags);
        bootstrap_result(crate::handover::set_cloexec(fd, true));
    }
    bootstrap_stage(BootstrapStage::Path);
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
    bootstrap_stage(BootstrapStage::Client);
    let client = std::env::var("QSH_DARWIN223_CLIENT").unwrap();
    assert_eq!(client.len(), 44);
    bootstrap_result(crate::handover::decode_allowlist(std::slice::from_ref(
        &client,
    )));
    bootstrap_stage(BootstrapStage::Udp);
    let port = bootstrap_result(udp.local_addr()).port();
    bootstrap_stage(BootstrapStage::Control);
    assert_eq!(control, cache.join("control.sock"));
    // The actual startup validator separately checks the kernel's original
    // private bind address. It deliberately differs from this published path.
    assert!(bootstrap_result(listener.local_addr())
        .as_pathname()
        .is_some());
    bootstrap_stage(BootstrapStage::Gate);
    bootstrap_result(bootstrap_gate(&mut gate));
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
    bootstrap_stage(BootstrapStage::StateFile);
    let state = bootstrap_result(crate::handover::write_memfd(&handover));
    let retained = [udp.as_raw_fd(), listener.as_raw_fd(), state.as_raw_fd()];
    bootstrap_stage(BootstrapStage::FdSelection);
    bootstrap_result(crate::handover::close_on_exec_except(&retained));
    for fd in retained {
        bootstrap_stage(BootstrapStage::FdInherit);
        bootstrap_result(crate::handover::set_cloexec(fd, false));
    }
    bootstrap_stage(BootstrapStage::Exec);
    let failure = crate::handover::exec_staged(&staged, state.as_raw_fd());
    let exec_error = bootstrap_errno(failure as i32);
    BOOTSTRAP_ERROR.store(exec_error as usize, Ordering::SeqCst);
    for fd in retained {
        bootstrap_stage(BootstrapStage::FdRestore);
        bootstrap_result(crate::handover::set_cloexec(fd, true));
    }
    bootstrap_stage(BootstrapStage::Exec);
    BOOTSTRAP_ERROR.store(exec_error as usize, Ordering::SeqCst);
    panic!("owned bootstrap exec refused");
}
#[test]
fn darwin223_owned_signal_server() {
    let Some(directory) = std::env::var_os("QSH_DARWIN223_SIGNAL_SERVER") else {
        return;
    };
    let directory = std::path::PathBuf::from(directory);
    if std::env::var_os("QSH_DARWIN223_RENAME_PROOF").is_some() {
        rename_proof_actor();
        return;
    }
    if let Ok(mode) = std::env::var("QSH_DARWIN223_PROOF_CONTROL") {
        proof_control_actor(&mode);
        return;
    }
    if let Ok(mode) = std::env::var("QSH_DARWIN223_BOOTSTRAP_CONTROL") {
        bootstrap_failure_control(&mode);
    }
    if std::env::var_os("QSH_DARWIN223_BOOTSTRAP").is_some() {
        bootstrap_actor();
        return;
    }
    if std::env::var_os("QSH_DARWIN223_COMMAND_CONTROLS").is_some() {
        fixture_command_controls();
        fixture_stderr_controls();
        fixture_diagnostic_controls();
        fixture_proof_schema_controls();
        fixture_proof_copy_controls();
        fixture_proof_owner_controls();
        fixture_gate_controls();
        fixture_socket_publication_controls();
        return;
    }
    let mode = std::env::var("QSH_DARWIN223_CONNECTED_SERVER").ok();
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
        .block_on(connected_case(
            mode.as_deref().unwrap_or(
                if cfg!(feature = "test-darwin-keeper")
                    && std::env::var_os("QSH_KEEPER_TEST_NO_CHANNEL_SIGNAL").is_some()
                {
                    "no-channel-signal"
                } else {
                    "signal"
                },
            ),
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
    signal_cases(false);
}
fn signal_cases(no_channel: bool) {
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
            .env_remove("QSH_KEEPER_TEST_NO_CHANNEL_SIGNAL")
            .envs(if no_channel {
                vec![("QSH_KEEPER_TEST_NO_CHANNEL_SIGNAL", "1")]
            } else {
                Vec::new()
            })
            .stderr(if cfg!(feature = "test-darwin-keeper") {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .spawn()
            .unwrap();
        let parent_stage = std::cell::Cell::new(SignalParentStage::WaitReady);
        let mut observed_exit = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            until(|| {
                actors.observe();
                directory.path().join("signal-ready").exists()
            });
            parent_stage.set(SignalParentStage::Ready);
            assert!(
                child.try_wait().unwrap().is_none(),
                "signal fixture exited before the owned signal"
            );
            // The exact direct Child is still unreaped and reserves this PID.
            // This fixture operation is not a metadata-derived production fallback.
            assert_eq!(unsafe { nix::libc::kill(child.id() as i32, signal) }, 0);
            parent_stage.set(SignalParentStage::SignalSent);
            parent_stage.set(SignalParentStage::WaitExit);
            let end = Instant::now() + Duration::from_secs(35);
            let status = loop {
                if let Some(status) = child.try_wait().unwrap() {
                    observed_exit = status.code();
                    parent_stage.set(SignalParentStage::Exited);
                    break status;
                }
                assert!(Instant::now() < end, "owned signal helper deadline");
                std::thread::sleep(Duration::from_millis(10));
            };
            assert!(status.success());
            #[cfg(feature = "test-darwin-keeper")]
            {
                use std::io::Read;
                use std::os::fd::AsRawFd;
                let mut pipe = child.stderr.take().expect("fixture stderr pipe");
                let fd = pipe.as_raw_fd();
                let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
                assert!(
                    flags >= 0
                        && unsafe {
                            nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK)
                        } == 0
                );
                let mut bytes = Vec::new();
                loop {
                    let mut buffer = [0; 4096];
                    match pipe.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => {
                            bytes.extend_from_slice(&buffer[..n]);
                            assert!(bytes.len() <= 64 * 1024);
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) =>
                        {
                            assert!(Instant::now() < end, "original owned signal deadline");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("signal receipt read {e}"),
                    }
                }
                super::keeper_integration_tests::native::assert_routes(
                    &bytes,
                    usize::from(!no_channel),
                );
            }
            parent_stage.set(SignalParentStage::AssertJoin);
            assert!(directory.path().join("signal-observed").exists());
            assert!(directory.path().join("signal-joined").exists());
        }));
        if result.is_err() {
            if let Some(bytes) = signal_fixture_failure(
                signal,
                parent_stage.get(),
                observed_exit,
                directory.path(),
                actors.path(),
            ) {
                use std::io::Write;
                let _ = std::io::stderr().write_all(&bytes);
            }
            actors.abort();
        }
        if result.is_err() && matches!(child.try_wait(), Ok(None)) {
            let _ = child.kill();
            let _ = child.wait();
        }
        actors.finish(!no_channel);
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
        custodies: Mutex<Vec<OpenCustody>>,
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
            self.custodies.lock().unwrap().push(custody.clone());
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
            custodies: Mutex::new(Vec::new()),
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
        // fixture_spawn performs one cleanup observation. Unknown retains the
        // exact capsule; this fixture owns the blocking retry duty that the real
        // lifecycle normally drives, rather than assuming the first census stable.
        let custody = spawner.custodies.lock().unwrap()[0].clone();
        until(|| {
            matches!(
                custody.retry_cleanup(),
                transport::channel_open::CleanupStatus::Confirmed(_)
            )
        });
        assert_census_receipt();
        let guards = spawner.guards.lock().unwrap();
        assert_eq!(guards.len(), 1);
        guards[0].assert_normal();
        let pid = guards[0].inner.lock().unwrap().process_id().unwrap() as i32;
        let mut status = 0;
        assert_eq!(
            unsafe { nix::libc::waitpid(pid, &mut status, nix::libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::ECHILD)
        );
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
fn daemon_status_observation(
    path: &Path,
) -> (Option<crate::control::StatusResponse>, &'static str) {
    match crate::control::client_request(path, &crate::control::ControlRequest::Status) {
        Ok(crate::control::ControlReply::Answered(line)) => {
            match crate::control::StatusResponse::from_line(&line) {
                Ok(value) => (Some(value), "VALID_STATUS"),
                Err(_) => (None, "PARSE_REFUSED"),
            }
        }
        Ok(crate::control::ControlReply::NoDaemon) => (None, "NO_DAEMON"),
        Ok(crate::control::ControlReply::TimedOut) => (None, "TIMED_OUT"),
        Err(_) => (None, "REQUEST_ERROR"),
    }
}
fn daemon_status(path: &Path) -> Option<crate::control::StatusResponse> {
    daemon_status_observation(path).0
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
        let end = Instant::now() + Duration::from_secs(10);
        loop {
            let observed = match self.owner.poll() {
                Ok(value) => value,
                Err(_) => {
                    retain_bootstrap_stderr(&self.owner.stderr_bytes);
                    panic!("owned handover bootstrap refused exit=-1 category=STDERR_CAPTURE");
                }
            };
            if let Some(status) = observed {
                let settled = self.owner.finish(end).is_ok();
                retain_bootstrap_stderr(&self.owner.stderr_bytes);
                let record = settled_bootstrap_record(&self.owner.stderr_bytes, settled);
                let category = if settled {
                    record.map(|v| v.0).unwrap_or("OTHER")
                } else {
                    "STDERR_UNSETTLED"
                };
                panic!(
                    "owned handover bootstrap exited before STATUS exit={} category={} errno={} provenance={}",
                    status.code().unwrap_or(-1),
                    category,
                    record.map(|v| v.1).unwrap_or("UNKNOWN"),
                    if record.is_some_and(|v| v.1 != "UNKNOWN") { "TYPED" } else { "UNKNOWN" }
                );
            }
            let (status, control_family) = daemon_status_observation(&self.socket);
            if status.is_some() {
                break;
            }
            assert!(
                Instant::now() < end,
                "owned bootstrap STATUS observation deadline control={control_family}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let status = daemon_status(&self.socket).unwrap();
        assert_eq!(status.pid, self.owner.child.id());
        assert!(self.owner.poll().unwrap().is_none());
        let mut ops = NativeOps;
        let identity = ops.classify(status.pid as i32).unwrap();
        self.watch = Some(ops.bind_exit(identity, 1).unwrap().handle);
        assert_eq!(daemon_status(&self.socket).unwrap().pid, status.pid);
        self.identity = Some(identity);
    }
    #[cfg(feature = "test-darwin-keeper")]
    fn stop_normally(&mut self) {
        self.stop_normally_tagged(None);
    }
    fn stop_normally_tagged(&mut self, diagnostic: Option<ReplacementDiagnostic<'_>>) {
        crate::control::client_request(&self.socket, &crate::control::ControlRequest::Stop)
            .expect("normal wire STOP request");
        let watch = self.watch.as_mut().expect("bound daemon exit authority");
        let mut ops = NativeOps;
        until_tagged(|| ops.observe_exit(watch).unwrap().is_some(), diagnostic);
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
    captured_stderr: Option<std::process::ChildStderr>,
    stderr_bytes: Vec<u8>,
}
impl OwnedCommand {
    fn spawn(command: &mut Command) -> std::io::Result<Self> {
        Ok(Self {
            child: command.spawn()?,
            status: None,
            transferred: false,
            captured_stderr: None,
            stderr_bytes: Vec::new(),
        })
    }
    fn capture_stderr(&mut self) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;
        let pipe = self.child.stderr.take().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "missing fixture stderr pipe",
            )
        })?;
        let fd = pipe.as_raw_fd();
        let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
        if flags < 0
            || unsafe { nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK) }
                < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        self.captured_stderr = Some(pipe);
        Ok(())
    }
    fn drain_stderr(&mut self) -> std::io::Result<()> {
        use std::io::Read;
        if let Some(pipe) = self.captured_stderr.as_mut() {
            let mut bytes = [0; 4096];
            match pipe.read(&mut bytes) {
                Ok(0) => self.captured_stderr = None,
                Ok(n) if self.stderr_bytes.len() + n <= 64 * 1024 => {
                    self.stderr_bytes.extend_from_slice(&bytes[..n])
                }
                Ok(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "fixture stderr cap",
                    ))
                }
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
    fn transfer_to_bound_controller(mut self) {
        // Only the actor's controller-bound gate may discharge this fixture
        // direct-child reservation to already retained exact native authority.
        self.transferred = true;
    }
    fn poll(&mut self) -> std::io::Result<Option<std::process::ExitStatus>> {
        self.drain_stderr()?;
        if self.status.is_none() {
            self.status = self.child.try_wait()?;
        }
        Ok(self.status)
    }
    fn finish(&mut self, end: Instant) -> std::io::Result<std::process::ExitStatus> {
        loop {
            if let Some(status) = self.poll()? {
                if self.captured_stderr.is_none() {
                    return Ok(status);
                }
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
        self.captured_stderr.take();
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
    observe: impl FnMut(),
) -> std::io::Result<std::process::Output> {
    bounded_command_observe_diagnostic(command, cap, end, observe, None)
}
fn bounded_command_observe_diagnostic(
    command: &mut Command,
    cap: usize,
    end: Instant,
    mut observe: impl FnMut(),
    diagnostic: Option<&ConnectedDiagnostic>,
) -> std::io::Result<std::process::Output> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut stage = FixtureStage::Spawn;
    let mut owner = match OwnedCommand::spawn(command) {
        Ok(owner) => owner,
        Err(error) => {
            if let Some(context) = diagnostic {
                connected_failure(context, stage, &error, None, None, None, 0, 0);
            }
            return Err(error);
        }
    };
    let mut stdout = owner.child.stdout.take();
    let mut stderr = owner.child.stderr.take();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut pipes_ready = false;
    let result = (|| {
        stage = FixtureStage::PipeSetup;
        for fd in [
            stdout.as_ref().unwrap().as_raw_fd(),
            stderr.as_ref().unwrap().as_raw_fd(),
        ] {
            let flags = unsafe { nix::libc::fcntl(fd, nix::libc::F_GETFL) };
            if flags < 0
                || unsafe {
                    nix::libc::fcntl(fd, nix::libc::F_SETFL, flags | nix::libc::O_NONBLOCK)
                } < 0
            {
                return Err(std::io::Error::last_os_error());
            }
        }
        pipes_ready = true;
        loop {
            stage = FixtureStage::Observe;
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
            stage = FixtureStage::StdoutRead;
            drain(&mut stdout, &mut out)?;
            stage = FixtureStage::StderrRead;
            drain(&mut stderr, &mut err)?;
            stage = FixtureStage::Cap;
            if out.len() + err.len() > cap {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "fixture output cap",
                ));
            }
            stage = FixtureStage::Poll;
            if let Some(status) = owner.poll()? {
                if stdout.is_none() && stderr.is_none() {
                    return Ok(std::process::Output {
                        status,
                        stdout: std::mem::take(&mut out),
                        stderr: std::mem::take(&mut err),
                    });
                }
            }
            stage = FixtureStage::Deadline;
            if Instant::now() >= end {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "fixture output deadline",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    if let (Err(error), Some(context)) = (&result, diagnostic) {
        connected_failure(
            context,
            stage,
            error,
            owner.status,
            pipes_ready.then(|| stdout.is_none()),
            pipes_ready.then(|| stderr.is_none()),
            out.len(),
            err.len(),
        );
    }
    result
}
fn fixture_replacement_role_controls() {
    use std::os::unix::fs::PermissionsExt;
    use transport::channel::{ServerRecord, FIRST_CHANNEL_STREAM};
    let directory = tempfile::tempdir().unwrap();
    let nonce = "a".repeat(32);
    for stage in [
        ReplacementActorStage::Entry,
        ReplacementActorStage::Sampled,
        ReplacementActorStage::Accepted,
        ReplacementActorStage::Refused,
        ReplacementActorStage::DescendantPublished,
    ] {
        replacement_stage_publish(
            directory.path(),
            &nonce,
            ReplacementActorRole::KeeperForegroundApplication,
            stage,
        );
        let bytes = replacement_private_read(
            directory.path(),
            &format!("replacement-stage-{}", stage.token()),
        )
        .unwrap();
        assert_eq!(
            parse_replacement_stage(&bytes, &nonce).unwrap().stage,
            stage
        );
        let record = FailurePayload::Replacement {
            stage: ReplacementSite::DescendantReady,
            progress: ReplacementProgress::default(),
            events: Some(EventFacts {
                parked_terminal: Some(super::keeper_integration_tests::ReplacementTerminal {
                    stream: FIRST_CHANNEL_STREAM,
                    code: 101,
                }),
                ..EventFacts::default()
            }),
            markers: marker_facts(directory.path(), directory.path()),
            status_wait: None,
            update_wait: None,
            actor_stage: Some(parse_replacement_stage(&bytes, &nonce).unwrap()),
        };
        let bytes = failure_bytes(&record).unwrap();
        assert!(bytes.len() <= 2048);
        assert!(!String::from_utf8(bytes).unwrap().contains(&nonce));
    }
    assert!(replacement_stage_observe(directory.path(), Some(&"b".repeat(32))).is_none());
    assert!(replacement_stage_observe(directory.path(), None).is_none());
    let private = tempfile::tempdir().unwrap();
    replacement_exclusive(private.path(), "replacement-stage-entry", b"PRIVATE_CANARY");
    assert!(replacement_stage_observe(private.path(), Some(&nonce)).is_none());
    assert!(replacement_private_read(private.path(), "unpublished").is_none());
    let file = private.path().join("replacement-stage-entry");
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(replacement_private_read(private.path(), "replacement-stage-entry").is_none());
    let events = fixture_update_records(&[ServerRecord::Exit {
        stream: FIRST_CHANNEL_STREAM,
        code: 101,
    }]);
    assert_eq!(
        event_facts(Some(&events))
            .unwrap()
            .parked_terminal
            .unwrap()
            .code,
        101
    );
    let held = events.records.lock().unwrap();
    assert!(event_facts(Some(&events)).is_none());
    drop(held);
}
fn fixture_command_controls() {
    fixture_replacement_role_controls();
    fixture_body_mapping_controls();
    fixture_body_callback_controls();
    fixture_body_join_controls();
    fixture_update_terminal_controls();
    fixture_update_decision_controls();
    fixture_update_record_controls();
    fixture_status_projection_controls();
    fixture_status_single_request_controls();
    fixture_timeout_formatter_controls();
    fixture_timeout_owner_control();
    fixture_timeout_tag_control();
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
fn fixture_stderr_controls() {
    assert_eq!(
        refusal_origin(
            "could not open channel: opening the pseudo-terminal: synthetic private canary"
        ),
        "PTY_OPEN"
    );
    let end = Instant::now() + Duration::from_secs(2);
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "printf 'QSH223_BOOTSTRAP stage=CONTROL errno=EIO\\n' >&2; exit 7",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut owner = OwnedCommand::spawn(&mut command).unwrap();
    owner.capture_stderr().unwrap();
    assert_eq!(owner.finish(end).unwrap().code(), Some(7));
    assert!(owner.captured_stderr.is_none());
    assert_eq!(bootstrap_error_origin(&owner.stderr_bytes), "CONTROL");
    assert_eq!(
        bootstrap_error_origin(b"opaque fixture-only text /fixture/private"),
        "OTHER"
    );
    assert_eq!(
        refusal_origin("too many pending channels"),
        "OPEN_ADMISSION"
    );
    assert_eq!(
        refusal_origin("could not open channel: fixture-only"),
        "OTHER"
    );
    assert_eq!(
        refusal_origin("opaque fixture-only text /fixture/private"),
        "OTHER"
    );
    drop(owner);
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "while :; do printf 01234567890123456789 >&2; done"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut owner = OwnedCommand::spawn(&mut command).unwrap();
    owner.capture_stderr().unwrap();
    loop {
        match owner.poll() {
            Err(error) => {
                assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
                break;
            }
            Ok(_) => assert!(Instant::now() < end, "stderr cap observation deadline"),
        }
    }
    assert!(owner.stderr_bytes.len() <= 64 * 1024);
    drop(owner); // actual kill + consuming wait before leaving the refusal
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
fn fixture_diagnostic_controls() {
    let record = b"QSH223_BOOTSTRAP stage=EXEC errno=EIO\n";
    assert_eq!(settled_bootstrap_record(record, false), None);
    assert_eq!(
        settled_bootstrap_record(record, true),
        Some(("EXEC", "EIO"))
    );
    for (reason, expected) in [
        ("could not open channel: opening the pseudo-terminal: arbitrary (os error 2)", "PTY_OPEN"),
        ("could not open channel: disabling echo on the PTY master side: the PTY master side does not hand over a file descriptor", "PTY_ECHO_FD"),
        ("could not open channel: disabling echo on the PTY master side: reading the PTY master side's termios: opaque", "PTY_ECHO_READ"),
        ("could not open channel: disabling echo on the PTY master side: writing the PTY master side's termios: opaque", "PTY_ECHO_WRITE"),
        ("could not open channel: starting the command in the PTY: opaque", "PTY_SPAWN"),
        ("/private/could not open channel: opening the pseudo-terminal: opaque", "OTHER"),
        ("could not open channel: /private/starting the command in the PTY: opaque", "OTHER"),
        ("could not open channel: disabling echo on the PTY master side: the PTY master side does not hand over a file descriptor suffix", "OTHER"),
    ] { assert_eq!(refusal_origin(reason), expected); }
    for raw in [
        b"QSH223_BOOTSTRAP stage=EXEC errno=EIO extra\n".as_slice(),
        b"QSH223_BOOTSTRAP stage=EXEC errno=EIO",
        b"QSH223_BOOTSTRAP stage=EXEC errno=EIO\r\n",
        b"QSH223_BOOTSTRAP stage=OTHER errno=EIO\n",
        b"QSH223_BOOTSTRAP stage=EXEC errno=EBADF\n",
        b"QSH223_BOOTSTRAP stage=EXEC errno=EIO\nQSH223_BOOTSTRAP stage=EXEC errno=EIO\n",
    ] {
        assert_eq!(bootstrap_record(raw), None);
    }
    for (mode, stage, errno) in [
        ("missing", "STATE_FILE", "ENOENT"),
        ("typed", "FD_FLAGS", "EINVAL"),
        ("assert", "PARENT", "UNKNOWN"),
    ] {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "darwin_process_scope::native_tests::darwin223_owned_signal_server",
                "--nocapture",
            ])
            .env("QSH_DARWIN223_SIGNAL_SERVER", "/private-fixture-canary")
            .env("QSH_DARWIN223_BOOTSTRAP_CONTROL", mode)
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let mut owner = OwnedCommand::spawn(&mut command).unwrap();
        owner.capture_stderr().unwrap();
        let status = owner
            .finish(Instant::now() + Duration::from_secs(3))
            .unwrap();
        assert!(!status.success());
        assert!(owner.captured_stderr.is_none());
        let expected = format!("QSH223_BOOTSTRAP stage={stage} errno={errno}\n");
        assert_eq!(owner.stderr_bytes, expected.as_bytes());
    }
    use std::os::unix::fs::PermissionsExt;
    let directory = std::env::temp_dir().join(format!("qsh223-admission-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let file = directory.join("inert");
    std::fs::write(&file, b"inert-not-executed").unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o700)).unwrap();
    admit_fixture_true(&file).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert!(admit_fixture_true(&file).is_err());
    assert!(admit_fixture_true(&directory).is_err());
    assert!(admit_fixture_true(&directory.join("missing")).is_err());
    std::fs::remove_file(file).unwrap();
    std::fs::remove_dir(directory).unwrap();
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
#[cfg(feature = "test-darwin-keeper")]
fn actual_connect(
    port: u16,
    server_pub: [u8; 32],
    client_priv: [u8; 32],
    token: [u8; 16],
) -> (transport::driver_std::StdClient, Arc<ConnectedEvents>) {
    actual_connect_tagged(port, server_pub, client_priv, token, None)
}
fn actual_connect_tagged(
    port: u16,
    server_pub: [u8; 32],
    client_priv: [u8; 32],
    token: [u8; 16],
    diagnostic: Option<ReplacementDiagnostic<'_>>,
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
    until_tagged(|| events.live.load(Ordering::SeqCst), diagnostic);
    (client, events)
}
#[test]
fn darwin223_native_actual_daemon_replacement_reaps_parked_scope_and_fresh_session() {
    run_actual_daemon_replacement(ReplacementActorRole::ModernSessionLeader);
}
fn run_actual_daemon_replacement(role: ReplacementActorRole) {
    use std::ffi::OsStr;
    use transport::channel::{
        encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord, UpdateAnswer,
        UpdateOffer, CONTROL_STREAM, FIRST_CHANNEL_STREAM, UPDATE_STREAM,
    };
    prepare().expect("production runtime admission");
    run_rename_proof();
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
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(home.path().join("qsh"))
        .unwrap();
    let socket = home.path().join("qsh/control.sock");
    let first = transport::handshake::generate_keypair();
    let parked_key = transport::handshake::generate_keypair();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let listener = crate::control::bind_private(&socket).unwrap();
    let server_pub =
        crate::load_or_create_transport_key(&home.path().join("qsh/transport_server_key.bin"))
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
        owner.capture_stderr().unwrap();
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
        let mut owner = OwnedCommand::spawn(&mut command).unwrap();
        owner.capture_stderr().unwrap();
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
    let mut owner = OwnedCommand::spawn(&mut command).unwrap();
    owner.capture_stderr().unwrap();
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
    use rand_core::RngCore;
    let mut nonce_bytes = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut nonce_bytes);
    let actor_nonce = hex::encode(nonce_bytes);
    let progress = std::cell::Cell::new(ReplacementProgress::default());
    let diagnostic = |site, events| ReplacementDiagnostic {
        site,
        progress: &progress,
        events,
        actor: actor_directory.path(),
        replacement: Some((&actor_nonce, role)),
        status_wait: None,
        update_wait: None,
    };
    let (parked, parked_events) = actual_connect_tagged(
        port,
        server_pub,
        parked_key.private,
        [9; 16],
        Some(diagnostic(ReplacementSite::ParkedLink, None)),
    );
    let executable = std::env::current_exe().unwrap();
    assert!(!executable.to_str().unwrap().contains('\''));
    assert!(!actor_directory.path().to_str().unwrap().contains('\''));
    let command=format!("/usr/bin/env QSH_DARWIN223_ACTOR='{}' QSH_DARWIN223_REPLACEMENT_ROLE={} QSH_DARWIN223_REPLACEMENT_NONCE={} QSH_DARWIN223_HOLD_LEADER=1 '{}' --exact darwin_process_scope::native_tests::darwin223_owned_actor --nocapture",actor_directory.path().display(),role.token(),actor_nonce,executable.display());
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
    progress.set(ReplacementProgress {
        open_enqueued: true,
        ..progress.get()
    });
    until_tagged(
        || {
            parked_events
                .records
                .lock()
                .unwrap()
                .iter()
                .any(|record| matches!(record, ServerRecord::Opened { .. }))
        },
        Some(diagnostic(
            ReplacementSite::ParkedOpened,
            Some(&parked_events),
        )),
    );
    let reports = std::cell::Cell::new(None);
    until_tagged(
        || {
            if !actor_directory.path().join("descendant-ready").exists() {
                return false;
            }
            let Some(raw) = replacement_private_read(actor_directory.path(), "replacement-actor")
            else {
                return false;
            };
            let Ok(application) = parse_replacement_actor_report(&raw, &actor_nonce) else {
                return false;
            };
            if validate_replacement_topology(role, &application).is_err() {
                return false;
            }
            let Some(raw) =
                replacement_private_read(actor_directory.path(), "replacement-descendant")
            else {
                return false;
            };
            let Ok(descendant) = parse_replacement_descendant_report(&raw, &actor_nonce) else {
                return false;
            };
            let t = application.topology;
            if descendant.sid != t.sid
                || descendant.group != descendant.identity.pid
                || descendant.identity.pid == t.application.pid
                || descendant.identity.pid == t.session.pid
            {
                return false;
            }
            if replacement_kernel_binding(t.application, t.sid, t.application.pid).is_err()
                || replacement_kernel_binding(t.session, t.sid, t.session.pid).is_err()
                || replacement_kernel_binding(descendant.identity, t.sid, descendant.group).is_err()
            {
                return false;
            }
            reports.set(Some((application, descendant)));
            true
        },
        Some(diagnostic(
            ReplacementSite::DescendantReady,
            Some(&parked_events),
        )),
    );
    let (application, descendant) = reports.get().expect("actual bound replacement reports");
    let t = application.topology;
    let sid = t.sid;
    let leader = replacement_kernel_binding(t.application, sid, t.application.pid).unwrap();
    let desc = replacement_kernel_binding(descendant.identity, sid, descendant.group).unwrap();
    let session = replacement_kernel_binding(t.session, sid, t.session.pid).unwrap();
    let mut leader_guard = replacement_guard(leader, sid, 2);
    let mut desc_guard = replacement_guard(desc, sid, 1);
    let mut session_guard = if t.session != t.application {
        Some(replacement_guard(session, sid, 3))
    } else {
        None
    };
    let mut ops = NativeOps;
    publish(&actor_directory.path().join("controller-bound"));
    parked.detach();
    until_tagged(
        || daemon_status(&socket).is_some_and(|status| status.total_connections == 0),
        Some(diagnostic(
            ReplacementSite::ParkedDetached,
            Some(&parked_events),
        )),
    );
    let (client, events) = actual_connect_tagged(
        port,
        server_pub,
        first.private,
        [1; 16],
        Some(diagnostic(ReplacementSite::UpdateLink, None)),
    );
    replacement_kernel_binding(t.application, sid, t.application.pid).unwrap();
    replacement_kernel_binding(t.session, sid, t.session.pid).unwrap();
    replacement_kernel_binding(descendant.identity, sid, descendant.group).unwrap();
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
    progress.set(ReplacementProgress {
        offer_enqueued: true,
        ..progress.get()
    });
    until_tagged(
        || {
            events
                .records
                .lock()
                .unwrap()
                .iter()
                .any(|record| *record == ServerRecord::UpdateAnswer(UpdateAnswer::Accept))
        },
        Some(diagnostic(ReplacementSite::UpdateAccept, Some(&events))),
    );
    progress.set(ReplacementProgress {
        accepted: true,
        ..progress.get()
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
    progress.set(ReplacementProgress {
        upload_enqueued: true,
        ..progress.get()
    });
    let restart_end = Instant::now() + Duration::from_secs(60);
    loop {
        let observed = observed_update_result(&events.records.lock().unwrap());
        let input_failed = events.input_failed.load(Ordering::SeqCst);
        match update_wait_decision(observed, input_failed, || Instant::now() < restart_end) {
            UpdateWaitDecision::Restarting => break,
            UpdateWaitDecision::Waiting => std::thread::sleep(Duration::from_millis(20)),
            UpdateWaitDecision::Refused(snapshot) => {
                replacement_failure(ReplacementDiagnostic {
                    update_wait: Some(snapshot),
                    ..diagnostic(ReplacementSite::RestartingReceipt, Some(&events))
                });
                match snapshot.failure {
                    UpdateWaitFailure::Deadline => panic!("actual replacement receipt deadline"),
                    UpdateWaitFailure::TerminalResult => {
                        panic!("actual replacement terminal result")
                    }
                    UpdateWaitFailure::InputFailure => panic!("fixture input failure observed"),
                }
            }
        }
    }
    progress.set(ReplacementProgress {
        restarting: true,
        ..progress.get()
    });
    client.detach();
    let status_wait = std::cell::Cell::new(StatusWaitObservation::new(CachedAtWaitEntry {
        status: CachedStatus::from_status(daemon.owner.status),
        stderr_eof: daemon.owner.captured_stderr.is_none(),
        stderr_bytes: daemon.owner.stderr_bytes.len(),
    }));
    until_tagged(
        || {
            status_wait_predicate(&status_wait, before.build, new_build, || {
                let (status, family) = daemon_status_observation(&socket);
                (status.map(|status| status.build), family)
            })
        },
        Some(ReplacementDiagnostic {
            status_wait: Some(&status_wait),
            ..diagnostic(ReplacementSite::NewBuildStatus, Some(&events))
        }),
    );
    let after = daemon_status(&socket).unwrap();
    assert_eq!(after.pid, before.pid);
    assert_eq!(after.ports, before.ports);
    assert_eq!(after.checksum, hex::encode(new_hash));
    assert_eq!(hash_path(&old), new_hash);
    let resumed = ops.classify(after.pid as i32).unwrap();
    let original_identity = daemon.identity.unwrap();
    assert!(resumed.identity.same_process(original_identity.identity));
    assert_ne!(resumed.identity.version, original_identity.identity.version);
    let mut application_exited = false;
    let mut session_exited = session_guard.is_none();
    until_tagged(
        || {
            if !application_exited {
                application_exited = ops.observe_exit(&mut leader_guard.watch).unwrap().is_some();
            }
            if !session_exited {
                session_exited = ops
                    .observe_exit(&mut session_guard.as_mut().unwrap().watch)
                    .unwrap()
                    .is_some();
            }
            application_exited
                && session_exited
                && replacement_absent(t.application)
                && replacement_absent(t.session)
        },
        Some(diagnostic(ReplacementSite::OldLeaderExit, Some(&events))),
    );
    leader_guard.normal_exit = true;
    if let Some(guard) = session_guard.as_mut() {
        guard.normal_exit = true;
    }
    desc_guard.finish_tagged(Some(diagnostic(
        ReplacementSite::OldDescendantExit,
        Some(&events),
    )));
    admit_fixture_true(Path::new(FIXTURE_TRUE)).expect("FIXTURE_TRUE_ADMISSION");
    let (fresh, fresh_events) = actual_connect_tagged(
        port,
        server_pub,
        first.private,
        [2; 16],
        Some(diagnostic(ReplacementSite::FreshLink, None)),
    );
    fresh
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: FIXTURE_TRUE.as_bytes().to_vec(),
            })),
        )
        .unwrap();
    until_tagged(
        || {
            fresh_events
                .records
                .lock()
                .unwrap()
                .iter()
                .any(|record| matches!(record, ServerRecord::Exit { code: 0, .. }))
        },
        Some(diagnostic(ReplacementSite::FreshExit, Some(&fresh_events))),
    );
    fresh.close();
    daemon.stop_normally_tagged(Some(diagnostic(
        ReplacementSite::FinalStop,
        Some(&fresh_events),
    )));
    assert_eq!(daemon.rescues, 0);
    #[cfg(feature = "test-darwin-keeper")]
    {
        let routes = super::keeper_integration_tests::route_images(&daemon.owner.stderr_bytes)
            .expect("actual daemon compiled route receipts");
        assert!(
            routes.iter().any(|hash| *hash == hex::encode(old_hash)),
            "parked channel did not select keeper in old image"
        );
        assert!(
            routes.iter().any(|hash| *hash == hex::encode(new_hash)),
            "fresh channel did not select keeper after real exec"
        );
        eprintln!(
            "keeper223 replacement_routes old_image={} new_image={} source=compiled-missing",
            hex::encode(old_hash),
            hex::encode(new_hash)
        );
    }
    assert_eq!(hash_path(&original), original_hash);
    eprintln!("darwin223 actual_update=exec same_pid=true execution_version=fresh parked_leader=reaped descendant=exited application_reaped=true session_reaped=true fresh_channel=completed wire_STOP=normal rescue=false");
}

#[cfg(feature = "test-darwin-keeper")]
pub(super) fn keeper_connected_suite() {
    super::keeper_integration_tests::native::fixture();
    darwin223_native_connected_close_stop_rebind_and_fresh_session();
    keeper_stop_control_case();
}
#[cfg(feature = "test-darwin-keeper")]
pub(super) fn keeper_signal_suite() {
    super::keeper_integration_tests::native::fixture();
    signal_cases(false);
    signal_cases(true);
}
#[cfg(feature = "test-darwin-keeper")]
pub(super) fn keeper_replacement_suite() {
    super::keeper_integration_tests::native::fixture();
    run_actual_daemon_replacement(ReplacementActorRole::KeeperForegroundApplication);
}
#[cfg(feature = "test-darwin-keeper")]
fn keeper_stop_control_case() {
    use std::io::Write;
    use std::os::unix::fs::DirBuilderExt;
    use transport::channel::{
        encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord, CONTROL_STREAM,
        FIRST_CHANNEL_STREAM,
    };
    let fixture = super::keeper_integration_tests::native::fixture();
    let home = tempfile::tempdir().unwrap();
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(home.path().join("qsh"))
        .unwrap();
    let socket = home.path().join("qsh/control.sock");
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    let listener = crate::control::bind_private(&socket).unwrap();
    let server =
        crate::load_or_create_transport_key(&home.path().join("qsh/transport_server_key.bin"))
            .unwrap()
            .public;
    let client_key = transport::handshake::generate_keypair();
    let (mut gate, child_gate) = std::os::unix::net::UnixStream::pair().unwrap();
    let mut command = bootstrap_command(
        &udp,
        &listener,
        &child_gate,
        home.path(),
        &fixture.path,
        client_key.public,
        "",
    );
    let mut owner = OwnedCommand::spawn(&mut command).unwrap();
    owner.capture_stderr().unwrap();
    let mut daemon = DirectDaemonGuard {
        owner,
        socket: socket.clone(),
        identity: None,
        watch: None,
        normal: false,
        rescues: 0,
    };
    drop((udp, listener, child_gate));
    gate.set_write_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    gate.write_all(b"GO\n").unwrap();
    gate.shutdown(std::net::Shutdown::Write).unwrap();
    drop(gate);
    daemon.arm();
    let mut actors = ConnectedActorAuthority::new();
    let (client, events) = actual_connect(port, server, client_key.private, [3; 16]);
    client
        .send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: ConnectedActorAuthority::command(actors.path()),
            })),
        )
        .unwrap();
    until(|| {
        actors.observe();
        events
            .records
            .lock()
            .unwrap()
            .iter()
            .any(|r| matches!(r, ServerRecord::Opened { .. }))
            && actors.path().join("controller-bound").exists()
    });
    daemon.stop_normally();
    client.close();
    actors.finish(true);
    super::keeper_integration_tests::native::assert_routes(&daemon.owner.stderr_bytes, 1);
    assert_eq!(daemon.rescues, 0);
    eprintln!("keeper223 wire_STOP=ack_then_actual_exit_watch_and_consumed_wait actors=joined rescue=false");
}
