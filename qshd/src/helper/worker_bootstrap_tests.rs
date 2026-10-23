use super::super::worker_control::Received;
use super::super::worker_protocol::Frame;
use super::super::worker_stop::WorkerStop;
use super::super::worker_threads::{Role, WorkerThreads};
use super::*;
use std::{
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Command, Stdio},
};

struct ChildFixture {
    child: std::process::Child,
    reaped: bool,
}
impl Drop for ChildFixture {
    fn drop(&mut self) {
        if self.reaped {
            return;
        }
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => return,
                Err(error) => panic!("owned bootstrap fixture wait failed: {error}"),
            }
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

#[test]
fn worker40_dropped_publisher_never_synthesizes_a_final_receipt() {
    let (parent, child) = worker_control::pair().unwrap();
    drop(Publisher::new(child));
    assert_eq!(worker_control::receive(&parent), Ok(Received::Eof));
}

#[test]
fn worker40_checked_publisher_delivers_one_final_frame_and_rejects_replacement() {
    let (parent, child) = worker_control::pair().unwrap();
    let mut publisher = Publisher::new(child);
    let mut roles = WorkerThreads::default();
    for role in [
        Role::NoncePool,
        Role::ChannelReader,
        Role::AuthReader,
        Role::TellReleaser,
    ] {
        roles.register(role, std::thread::spawn(|| Ok(())), || Ok(()));
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let outcome =
        super::super::worker_drain::run(runtime, async { Ok(()) }, roles, WorkerStop::default());
    let result = publisher.finish(outcome);
    let received = worker_control::receive(&parent);
    let replace = publisher.init_failed(nix::libc::EIO);
    drop(publisher);
    assert!(result.is_ok());
    assert!(
        matches!(received, Ok(Received::Frame { frame: Frame::Drained(receipt), .. }) if receipt.successful())
    );
    assert!(replace.is_err());
    assert_eq!(worker_control::receive(&parent), Ok(Received::Eof));
}

#[test]
fn worker40_failed_final_publication_cannot_be_replaced_with_a_clean_status() {
    let (parent, child) = worker_control::pair().unwrap();
    let mut publisher = Publisher::new(child);
    drop(parent);
    let failed = publisher.init_failed(nix::libc::EIO);
    let replaced = publisher.init_failed(nix::libc::ECANCELED);
    assert!(failed.is_err(), "closed peer was reported as delivered");
    assert!(replaced.is_err());
}

#[test]
#[ignore = "runs only inside the owned bootstrap subprocess"]
fn worker40_bootstrap_packet_child_body() {
    let fd: i32 = std::env::var("QSH_TEST_BOOTSTRAP_FD")
        .unwrap()
        .parse()
        .unwrap();
    assert!(fd >= 3);
    // SAFETY: the owned pre_exec cleared CLOEXEC for this one fixture fd.
    let socket = unsafe { UnixStream::from_raw_fd(fd) };
    let mut publisher = Publisher::new(socket);
    publisher.establish().unwrap();
    assert_eq!(
        nix::unistd::getsid(None).unwrap(),
        nix::unistd::getpid(),
        "startup advanced before setsid"
    );
    // This is a controlled framing producer, not real auxiliary/PAM cleanup.
    publisher.publish(&[4, 0, 0, 0, 15, 15, 0, 0]).unwrap();
}

#[test]
fn worker40_prepared_custody_consumes_actual_child_stage_and_final_before_reap() {
    use crate::process_scope::scope::{LeaderStatus, Progress};
    let prepared = Prepared::new(Duration::from_secs(3)).unwrap();
    let fd = prepared.child.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "helper::worker_bootstrap::tests::worker40_bootstrap_packet_child_body",
            "--ignored",
            "--test-threads=1",
        ])
        .env("QSH_TEST_BOOTSTRAP_FD", fd.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe descriptor setup, no parent mutation.
    unsafe {
        command.pre_exec(move || {
            if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().unwrap();
    let mut owner = prepared.parent(NonZeroU32::new(child.id()).unwrap());
    let mut fixture = ChildFixture {
        child,
        reaped: false,
    };
    let deadline = Instant::now() + Duration::from_secs(3);
    let exited = loop {
        let status = owner.leader();
        if matches!(status, LeaderStatus::Exited(_)) {
            break status;
        }
        if Instant::now() >= deadline {
            break status;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    let first = owner.poll(Instant::now());
    let second = owner.poll(Instant::now());
    let mut last = owner.poll(Instant::now());
    while matches!(last.native, Progress::Pending) && Instant::now() < deadline {
        last = owner.poll(Instant::now());
    }
    fixture.reaped = matches!(last.native, Progress::Complete(_));
    // Cleanup of this fixture child is complete before any RED assertion.
    drop(fixture);
    assert_eq!(exited, LeaderStatus::Exited(0));
    assert_eq!(first.native, Progress::Pending);
    assert!(first.receipt.is_none());
    assert_eq!(second.native, Progress::Pending);
    assert!(second.receipt.is_some());
    assert!(matches!(last.native, Progress::Complete(0)));
}
