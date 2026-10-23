use super::*;
use std::{
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
    time::Duration,
};

struct Fixture {
    child: Child,
    reaped: bool,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        match self.child.try_wait() {
            Ok(Some(_)) => return,
            Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => return,
            Err(error) => panic!("worker fixture wait failed: {error}"),
            Ok(None) => {}
        }
        let _ = self.child.kill();
        loop {
            match self.child.wait() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    result.unwrap();
                    break;
                }
            }
        }
    }
}

fn fixture(mode: &str) -> (WorkerOwner, Fixture) {
    let view = crate::process_scope::prepare().unwrap();
    let (parent, child) = worker_control::pair().unwrap();
    let fd = child.as_raw_fd();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "helper::worker_owner::tests::worker40_owned_packet_producer_body",
            "--ignored",
            "--test-threads=1",
        ])
        .env("QSH_TEST_WORKER_FD", fd.to_string())
        .env("QSH_TEST_WORKER_MODE", mode)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: this owned fork child performs only async-signal-safe descriptor
    // operations and setsid before exec. No parent handler or descriptor changes.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) < 0 || nix::libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child_process = command.spawn().unwrap();
    let pid = NonZeroU32::new(child_process.id()).unwrap();
    let owner = WorkerOwner::new(pid, view, parent, deadline);
    let fixture = Fixture {
        child: child_process,
        reaped: false,
    };
    drop(child);
    (owner, fixture)
}

#[test]
#[ignore = "runs only in the owned worker coordination subprocess"]
fn worker40_owned_packet_producer_body() {
    let fd: i32 = std::env::var("QSH_TEST_WORKER_FD")
        .unwrap()
        .parse()
        .unwrap();
    assert!(fd >= 3);
    // SAFETY: the fixture's pre_exec installed this one owned inherited fd.
    let socket = unsafe { UnixStream::from_raw_fd(fd) };
    if std::env::var("QSH_TEST_WORKER_MODE").unwrap() == "malformed" {
        super::super::channel::send(&socket, &[], None).unwrap();
    }
    let mut stage = vec![2];
    stage.extend_from_slice(&std::process::id().to_be_bytes());
    super::super::channel::send(&socket, &stage, None).unwrap();
    super::super::channel::send(&socket, &[4, 0, 0, 0, 15, 15, 0, 0], None).unwrap();
}

#[test]
fn worker40_queued_child_stage_and_drained_survive_exit_and_interrupted_pass() {
    let (mut owner, mut fixture) = fixture("good");
    let reserved = crate::process_scope::scope::ReservedRoot::Owned(owner.pid);
    let initial_root = owner.reserved_root();
    let deadline = Instant::now() + Duration::from_secs(3);
    let exited = loop {
        if owner.leader() == LeaderStatus::Exited(0) {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let exited_root = owner.reserved_root();
    let stage = owner.poll(Instant::now());
    let interrupted = owner.poll_with(Instant::now(), |_| Ok(Received::Yielded));
    let interrupted_root = owner.reserved_root();
    let independent = crate::process_scope::fork_child::ForkChild::new(owner.pid).observe();
    let receipt = owner.poll(Instant::now());
    let receipt_root = owner.reserved_root();
    let receipt_received = receipt.receipt.is_some();
    let receipt_failure = receipt.failure;
    let mut final_progress = owner.poll(Instant::now()).native;
    while !matches!(final_progress, Progress::Complete(_)) && Instant::now() < deadline {
        final_progress = owner.poll(Instant::now()).native;
        std::thread::sleep(Duration::from_millis(1));
    }
    let final_root = owner.reserved_root();
    fixture.reaped = matches!(final_progress, Progress::Complete(_));
    drop(owner);
    drop(fixture); // actual owned child settled before every assertion, including RED
    assert_eq!(initial_root, reserved);
    assert_eq!(
        exited_root, reserved,
        "observed exit still reserves the unreaped leader"
    );
    assert_eq!(interrupted_root, reserved);
    assert_eq!(
        receipt_root, reserved,
        "queued final receipt does not consume child custody"
    );
    assert_eq!(
        final_root,
        crate::process_scope::scope::ReservedRoot::Released
    );
    assert!(exited);
    assert_eq!(stage.native, Progress::Pending);
    assert_eq!(
        interrupted.native,
        Progress::Pending,
        "yield cannot release the queued receipt's leader"
    );
    assert!(matches!(independent, Ok(Some(0))), "{independent:?}");
    assert!(receipt_received);
    assert_eq!(
        receipt.native,
        Progress::Pending,
        "a consumed frame is not queue-empty proof"
    );
    assert_eq!(receipt_failure, None);
    assert_eq!(final_progress, Progress::Complete(0));
}

fn wait_for_exit(owner: &mut WorkerOwner) -> bool {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if owner.leader() == LeaderStatus::Exited(0) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn outsider() -> Fixture {
    use std::io::Read;
    let mut result = Fixture {
        child: Command::new("/bin/sh")
            .args(["-c", "printf ready; read release"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
        reaped: false,
    };
    result
        .child
        .stdout
        .as_mut()
        .unwrap()
        .read_exact(&mut [0; 5])
        .unwrap();
    result
}

#[test]
fn worker40_malformed_startup_cannot_recover_authority_from_later_stage_or_receipt() {
    let (mut owner, fixture) = fixture("malformed");
    let exited = wait_for_exit(&mut owner);
    let mut progress = Vec::new();
    for _ in 0..8 {
        progress.push(owner.poll(Instant::now()));
    }
    drop(owner);
    drop(fixture); // explicit fixture wait, not a synthesized product receipt
    assert!(exited);
    assert!(progress.iter().all(|p| p.native == Progress::Unknown));
    assert!(progress.iter().all(|p| p.receipt.is_none()));
    assert!(progress
        .iter()
        .all(|p| p.failure == Some(WorkerFailure::Protocol(Fault::Protocol))));
}

#[test]
fn worker40_lost_child_wait_cannot_renew_from_queued_matching_private_records() {
    let mut unrelated = outsider();
    let (mut owner, mut fixture) = fixture("good");
    let exited = wait_for_exit(&mut owner);
    let stolen = fixture.child.wait().unwrap(); // controlled ownership-loss fault
    fixture.reaped = true;
    owner.cancel();
    let mut progress = Vec::new();
    let mut roots = Vec::new();
    for _ in 0..8 {
        progress.push(owner.poll(Instant::now()));
        roots.push(owner.reserved_root());
    }
    let unrelated_running = unrelated.child.try_wait().unwrap().is_none();
    drop(owner);
    drop(fixture);
    drop(unrelated);
    assert!(exited && stolen.success());
    assert!(unrelated_running);
    assert!(roots
        .iter()
        .all(|root| *root == crate::process_scope::scope::ReservedRoot::Lost));
    assert!(progress.iter().all(|p| p.native == Progress::Unknown));
    assert!(progress.iter().all(|p| p.receipt.is_none()));
    assert!(progress
        .iter()
        .all(|p| p.failure == Some(WorkerFailure::LostAuthority)));
}

#[test]
fn worker40_pre_stage_cancel_signals_only_owned_child_in_shared_parent_session() {
    let mut unrelated = outsider();
    let view = crate::process_scope::prepare().unwrap();
    let (parent, child) = worker_control::pair().unwrap();
    let fd = child.as_raw_fd();
    let parent_sid = unsafe { nix::libc::getsid(0) };
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut command = Command::new("/bin/sh");
    command
        .args(["-c", "read release"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only preserve this fixture's owned private endpoint across exec;
    // intentionally no setsid/ack, so authority must remain exact-child-only.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let process = command.spawn().unwrap();
    let pid = NonZeroU32::new(process.id()).unwrap();
    let mut owner = WorkerOwner::new(pid, view, parent, deadline);
    let mut fixture = Fixture {
        child: process,
        reaped: false,
    };
    drop(child);
    let shared_sid = unsafe { nix::libc::getsid(pid.get() as i32) } == parent_sid;
    owner.cancel();
    let mut progress = owner.poll(Instant::now());
    while !matches!(progress.native, Progress::Complete(_)) && Instant::now() < deadline {
        progress = owner.poll(Instant::now());
        std::thread::sleep(Duration::from_millis(1));
    }
    fixture.reaped = matches!(progress.native, Progress::Complete(_));
    let unrelated_running = unrelated.child.try_wait().unwrap().is_none();
    let unchanged_sid = unsafe { nix::libc::getsid(0) } == parent_sid;
    drop(owner);
    drop(fixture);
    drop(unrelated);
    assert!(shared_sid && unchanged_sid && unrelated_running);
    assert!(matches!(progress.native, Progress::Complete(_)));
    assert!(progress.receipt.is_none());
    assert_eq!(progress.failure, Some(WorkerFailure::MissingReceipt));
}

#[test]
fn worker40_native_signal_diagnostic_survives_first_protocol_fault_and_later_errors() {
    let (mut owner, fixture) = fixture("malformed");
    let exited = wait_for_exit(&mut owner);
    let first = owner.poll(Instant::now());
    owner
        .child
        .inject_signal_failure((nix::libc::SIGHUP, nix::libc::EPERM));
    let signal = owner.poll(Instant::now());
    owner
        .child
        .inject_signal_failure((nix::libc::SIGKILL, nix::libc::EACCES));
    let later = owner.poll(Instant::now());
    drop(owner);
    drop(fixture);
    assert!(exited);
    assert_eq!(
        first.failure,
        Some(WorkerFailure::Protocol(Fault::Protocol))
    );
    assert_eq!(
        signal.signal_failure,
        Some((nix::libc::SIGHUP, nix::libc::EPERM))
    );
    assert_eq!(later.signal_failure, signal.signal_failure);
    assert_eq!(
        later.failure, first.failure,
        "native diagnostics cannot erase the earlier fault"
    );
}
