use super::super::{
    channel,
    pam_completion::PamCompletion,
    protocol::{encode, MonitorEvent},
};
use super::*;
use std::{
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::process::CommandExt,
    },
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Fixture(Child);
impl Drop for Fixture {
    fn drop(&mut self) {
        loop {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => return,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => panic!("owned monitor fixture wait: {error}"),
                Ok(None) => break,
            }
        }
        self.0.kill().unwrap();
        loop {
            match self.0.wait() {
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
#[ignore = "runs only inside an owned monitor-component child"]
fn monitor40_private_producer_body() {
    let fd: i32 = std::env::var("QSH_TEST_MONITOR_OWNER_FD")
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        std::env::var("QSH_TEST_MONITOR_OWNER_PARENT")
            .unwrap()
            .parse::<i32>()
            .unwrap(),
        unsafe { nix::libc::getppid() }
    );
    let seam = unsafe { UnixStream::from_raw_fd(fd) };
    let mode = std::env::var("QSH_TEST_MONITOR_OWNER_MODE").unwrap();
    if mode == "prestage" {
        loop {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert_eq!(unsafe { nix::libc::setsid() }, std::process::id() as i32);
    if mode == "zero" {
        channel::send(&seam, &[], None).unwrap();
    }
    let mut stage = encode(&MonitorEvent::SessionEstablished {
        sid: std::process::id() + u32::from(mode == "wrong"),
    })
    .unwrap();
    if mode == "oversized" {
        stage.resize(8193, b' ');
    }
    let rights = (mode == "rights").then(|| std::fs::File::open("/dev/null").unwrap());
    channel::send(&seam, &stage, rights.as_ref().map(AsFd::as_fd)).unwrap();
    if matches!(mode.as_str(), "refused" | "started") {
        let outcome = if mode == "refused" {
            MonitorEvent::Refused {
                id: 209,
                why: "fixture account denied".into(),
            }
        } else {
            MonitorEvent::Started { id: 209 }
        };
        channel::send(&seam, &encode(&outcome).unwrap(), None).unwrap();
        channel::send(
            &seam,
            &encode(&MonitorEvent::CleanupComplete {
                id: 209,
                kind: if mode == "refused" {
                    super::super::protocol::CleanupKind::NoChild
                } else {
                    super::super::protocol::CleanupKind::Reaped
                },
            })
            .unwrap(),
            None,
        )
        .unwrap();
    }
    if mode == "malformed-outcome" {
        channel::send(&seam, b"not a monitor record", None).unwrap();
    }
    channel::send(
        &seam,
        &encode(&MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened,
        })
        .unwrap(),
        None,
    )
    .unwrap();
}
fn fixture() -> (NativeMonitor, Fixture) {
    fixture_mode("good")
}
fn fixture_mode(mode: &str) -> (NativeMonitor, Fixture) {
    let view = crate::process_scope::prepare().unwrap();
    let (parent, child) = worker_control::pair().unwrap();
    let fd = child.as_raw_fd();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "helper::monitor_owner::tests::monitor40_private_producer_body",
            "--ignored",
            "--test-threads=1",
        ])
        .env("QSH_TEST_MONITOR_OWNER_MODE", mode)
        .env("QSH_TEST_MONITOR_OWNER_FD", fd.to_string())
        .env(
            "QSH_TEST_MONITOR_OWNER_PARENT",
            std::process::id().to_string(),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let process = command.spawn().unwrap();
    let owner = NativeMonitor::new(NonZeroU32::new(process.id()).unwrap(), view, parent);
    drop(child);
    (owner, Fixture(process))
}
#[test]
fn monitor40_queued_stage_and_pam_receipt_precede_final_wait_after_yield() {
    let (mut owner, mut fixture) = fixture();
    let deadline = Instant::now() + Duration::from_secs(2);
    while owner.leader() == LeaderStatus::Running && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let before = owner.leader();
    let interrupted = owner.advance_with(Instant::now(), |_| {
        Err(io::Error::from(io::ErrorKind::Interrupted))
    });
    let stage = owner.advance(Instant::now());
    let receipt = owner.advance(Instant::now());
    let mut last = owner.advance(Instant::now());
    while !matches!(last.native, Progress::Complete(_)) && Instant::now() < deadline {
        last = owner.advance(Instant::now());
        std::thread::sleep(Duration::from_millis(1));
    }
    let product_reaped = matches!(fixture.0.try_wait(), Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD));
    drop(fixture); // exact actual cleanup before any assertion, including RED
    assert_eq!(before, LeaderStatus::Exited(0));
    assert!(matches!(interrupted.native, Progress::Pending));
    assert!(stage.event.is_none() && matches!(stage.native, Progress::Pending));
    assert_eq!(
        receipt.event,
        Some(MonitorEvent::SessionClosed {
            result: PamCompletion::NotOpened
        })
    );
    assert!(matches!(receipt.native, Progress::Pending));
    assert!(product_reaped && matches!(last.native, Progress::Complete(0)));
    assert_eq!(last.failure, None);
    assert!(last.signal_failure.is_none());
    assert_eq!(last.leader, LeaderStatus::Exited(0));
    assert!(owner.closed());
    let latched = owner.advance_with(Instant::now(), |_| {
        panic!("completed owner must not read again")
    });
    assert!(matches!(latched.native, Progress::Complete(0)));
}

#[test]
fn monitor40_pre_stage_force_owns_only_exact_child_not_parent_session() {
    let (mut owner, mut child) = fixture_mode("prestage");
    let mut unrelated = Fixture(Command::new("/bin/sleep").arg("60").spawn().unwrap());
    assert_eq!(unsafe { nix::libc::getsid(child.0.id() as i32) }, unsafe {
        nix::libc::getsid(0)
    });
    // Cooperative write-half closure is not a native cancel or permission to
    // signal the shared parent SID; explicit force remains exact-child-only.
    owner.seam().shutdown(std::net::Shutdown::Write).unwrap();
    let before = owner.advance(Instant::now());
    owner.force(Instant::now());
    let deadline = Instant::now() + Duration::from_secs(2);
    let last = loop {
        let update = owner.advance(Instant::now());
        if matches!(update.native, Progress::Complete(_)) || Instant::now() >= deadline {
            break update;
        }
        std::thread::sleep(Duration::from_millis(1));
    };
    let unrelated_running = unrelated.0.try_wait().unwrap().is_none();
    let reaped =
        matches!(child.0.try_wait(), Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD));
    drop(child);
    drop(unrelated);
    assert_eq!(before.leader, LeaderStatus::Running);
    assert!(matches!(before.native, Progress::Pending));
    assert!(reaped && unrelated_running && matches!(last.native, Progress::Complete(_)));
}
#[test]
fn monitor40_wrong_stage_never_renews_session_authority() {
    for mode in ["wrong", "zero", "oversized", "rights"] {
        let (mut owner, mut child) = fixture_mode(mode);
        let deadline = Instant::now() + Duration::from_secs(2);
        while owner.leader() == LeaderStatus::Running && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        let mut results = Vec::new();
        for _ in 0..5 {
            results.push(owner.advance(Instant::now()));
        }
        let external_wait = child.0.wait().unwrap();
        drop(child);
        assert!(external_wait.success());
        assert!(results
            .iter()
            .all(|update| update.event.is_none() && update.native == Progress::Unknown));
        assert!(
            results
                .iter()
                .all(|update| update.failure == Some(Failure::Protocol)),
            "mode={mode}"
        );
    }
}
#[test]
fn monitor40_stolen_wait_remains_unknown_despite_matching_queued_records() {
    let (mut owner, mut child) = fixture();
    let mut unrelated = Fixture(Command::new("/bin/sleep").arg("60").spawn().unwrap());
    let stolen = child.0.wait().unwrap();
    owner.force(Instant::now());
    let mut results = Vec::new();
    for _ in 0..5 {
        results.push(owner.advance(Instant::now()));
    }
    let unrelated_running = unrelated.0.try_wait().unwrap().is_none();
    drop(child);
    drop(unrelated);
    assert!(stolen.success() && unrelated_running);
    assert!(results
        .iter()
        .all(|update| update.native == Progress::Unknown && update.event.is_none()));
    assert!(results
        .iter()
        .all(|update| update.failure == Some(Failure::LostAuthority)));
}

#[test]
fn monitor40_denied_private_read_cannot_be_erased_by_later_matching_stage() {
    let (mut owner, mut child) = fixture();
    let denied = owner.advance_with(Instant::now(), |_| {
        Err(io::Error::from_raw_os_error(nix::libc::EACCES))
    });
    let deadline = Instant::now() + Duration::from_secs(2);
    while owner.leader() == LeaderStatus::Running && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut results = vec![denied];
    for _ in 0..5 {
        results.push(owner.advance(Instant::now()));
    }
    let external_wait = child.0.wait().unwrap();
    drop(child);
    assert!(external_wait.success());
    assert!(results
        .iter()
        .all(|update| update.native == Progress::Unknown && update.event.is_none()));
    assert!(results
        .iter()
        .all(|update| update.failure == Some(Failure::Stream(nix::libc::EACCES))));
}
#[test]
fn monitor40_kernel_sender_cannot_be_replaced_by_a_matching_payload_pid() {
    let view = crate::process_scope::prepare().unwrap();
    let (parent, peer) = worker_control::pair().unwrap();
    let child = Command::new("/bin/sh")
        .args(["-c", "read release"])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let pid = NonZeroU32::new(child.id()).unwrap();
    let mut child = Fixture(child);
    let mut owner = NativeMonitor::new(pid, view, parent);
    channel::send(
        &peer,
        &encode(&MonitorEvent::SessionEstablished { sid: pid.get() }).unwrap(),
        None,
    )
    .unwrap();
    let result = owner.advance(Instant::now());
    drop(child.0.stdin.take());
    drop(child);
    assert_eq!(result.failure, Some(Failure::Protocol));
    assert_eq!(result.native, Progress::Unknown);
    assert!(result.event.is_none());
}
