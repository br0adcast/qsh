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
    let mut after_gate = None;
    if mode.starts_with("refused-gated") || mode.starts_with("failed-gated") {
        use std::io::{Read as _, Write as _};
        let raw = std::env::var("QSH_TEST_MONITOR_GATE_FD")
            .unwrap()
            .parse()
            .unwrap();
        let mut gate = unsafe { UnixStream::from_raw_fd(raw) };
        gate.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        if mode.ends_with("-running") {
            seam.shutdown(std::net::Shutdown::Read).unwrap();
        }
        gate.write_all(b"S").unwrap();
        gate.read_exact(&mut [0u8; 1]).unwrap();
        after_gate = Some(gate);
    }
    if mode.starts_with("refused-gated-drain") {
        let (bytes, fd) = channel::recv(&seam).unwrap().unwrap();
        assert!(fd.is_some());
        let id =
            match super::super::protocol::decode::<super::super::protocol::MonitorRequest>(&bytes)
                .unwrap()
            {
                super::super::protocol::MonitorRequest::Open { id, .. } => id,
                _ => panic!("first fixture request must be an Open"),
            };
        drop(fd);
        let helper_pid = nix::unistd::Pid::from_raw(
            std::env::var("QSH_TEST_MONITOR_OWNER_PARENT")
                .unwrap()
                .parse()
                .unwrap(),
        );
        assert!(super::super::monitor::refused_requests_fixture(
            &seam, helper_pid, id
        ));
        if mode.ends_with("-late") {
            unsafe {
                nix::libc::_exit(75);
            }
        }
        return;
    }
    if matches!(mode.as_str(), "refused" | "started")
        || mode.starts_with("refused-gated")
        || mode.starts_with("failed-gated")
    {
        let outcome = if mode == "refused" || mode.starts_with("refused-gated") {
            MonitorEvent::Refused {
                id: 209,
                why: "fixture account denied".into(),
            }
        } else if mode.starts_with("failed-gated") {
            MonitorEvent::Failed {
                id: 209,
                errno: nix::libc::EIO,
            }
        } else {
            MonitorEvent::Started { id: 209 }
        };
        channel::send(&seam, &encode(&outcome).unwrap(), None).unwrap();
        channel::send(
            &seam,
            &encode(&MonitorEvent::CleanupComplete {
                id: 209,
                kind: if mode == "refused"
                    || mode.starts_with("refused-gated")
                    || mode.starts_with("failed-gated")
                {
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
    if mode.starts_with("refused-gated-after-") {
        use std::io::{Read as _, Write as _};
        let gate = after_gate.as_mut().unwrap();
        if mode.ends_with("failed") {
            seam.shutdown(std::net::Shutdown::Read).unwrap();
        }
        gate.write_all(b"R").unwrap();
        gate.read_exact(&mut [0u8; 1]).unwrap();
        if !mode.ends_with("failed") {
            seam.set_nonblocking(true).unwrap();
            let queued = matches!(channel::recv_once(&seam), Ok(Some((bytes, _)))
                if matches!(super::super::protocol::decode::<super::super::protocol::MonitorRequest>(&bytes),
                    Ok(super::super::protocol::MonitorRequest::Open { id: 210, .. })));
            gate.write_all(if queued { b"O" } else { b"N" }).unwrap();
        }
    }
    if mode == "malformed-outcome" {
        channel::send(&seam, b"not a monitor record", None).unwrap();
    }
    if mode.ends_with("-missing") {
        return;
    }
    if mode.ends_with("-malformed") {
        channel::send(&seam, b"not a final receipt", None).unwrap();
        return;
    }
    channel::send(
        &seam,
        &encode(&MonitorEvent::SessionClosed {
            request_failure: (mode == "request-failed")
                .then_some(super::super::protocol::RequestDrainFailure::Protocol),
            cleanup_failure: None,
            result: PamCompletion::NotOpened,
        })
        .unwrap(),
        None,
    )
    .unwrap();
    if mode == "failed-gated-exit75" {
        unsafe {
            nix::libc::_exit(75);
        }
    }
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
            request_failure: None,
            cleanup_failure: None,
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

#[test]
fn refusal406_native_failed_completion_keeps_authenticated_event() {
    let (mut owner, _fixture) = fixture_mode("request-failed");
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut event_seen = false;
    while Instant::now() < deadline {
        let update = owner.advance(Instant::now());
        if let Some(MonitorEvent::SessionClosed {
            request_failure: Some(failure),
            result,
            ..
        }) = update.event
        {
            assert_eq!(
                failure,
                super::super::protocol::RequestDrainFailure::Protocol
            );
            assert_eq!(result, PamCompletion::NotOpened);
            assert_eq!(update.failure, Some(Failure::Request(failure)));
            event_seen = true;
        }
        if matches!(update.native, Progress::Complete(_)) {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(
        event_seen,
        "typed failure must not discard valid authenticated PAM evidence"
    );
}
