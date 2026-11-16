//! CI-only real execution. None of these cases is local qualification.
use super::*;
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::time::Duration;

const BODY: &str = "session_owner::inherited_launch::native_tests::launch529_isolated_child_body";
fn config() -> TrustedChannelConfig {
    let uid = unsafe { libc::geteuid() };
    assert_ne!(
        uid, 0,
        "positive inherited launch requires an ordinary account"
    );
    TrustedChannelConfig {
        host: transport::session_resume::HostInstance::new([29; 16]).unwrap(),
        owner: None,
        requester: super::super::protocol::OwnerRole::Frontend,
        mode: super::super::authorization::HostMode::Personal { canonical_uid: uid },
        system_uid: uid,
        min_version: 1,
        max_version: 1,
    }
}
/// The maintained real case exercises the actual supervisor, not a modeled child.
fn supervisor_handoff_and_stop() {
    use crate::session_owner::host::{HostLimits, HostState};
    use crate::session_owner::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
    use crate::session_owner::supervisor::{HostSupervisor, SupervisionError, SupervisionProgress};
    let mut config = config();
    let bytes = ByteLimits {
        channel_bytes: 1 << 20,
        session_bytes: 8 << 20,
        account_bytes: 32 << 20,
        global_bytes: 128 << 20,
    };
    let resources = ResourceLimits {
        max_reservations: 128,
        screen: ScreenLimits::from_existing(crate::screen_budget::BudgetLimits::default()).unwrap(),
        snapshot_transfer: bytes,
        control_queue: bytes,
    };
    let mut host = HostState::new(
        config.mode,
        HostLimits::new(resources, 1, 4, 4, 4, 100).unwrap(),
    )
    .unwrap();
    config.host = host.instance();
    let mut supervisor = HostSupervisor::new(&mut host).unwrap();
    supervisor
        .set_program_for_test(TestProgram {
            executable: daemon(),
            args: vec![MARKER.into()],
            environment: vec![],
            body: false,
        })
        .unwrap();
    let setup_deadline = Instant::now() + Duration::from_secs(10);
    let handle = supervisor
        .prepare(&mut host, config, setup_deadline)
        .unwrap();
    supervisor.start(&mut host, &handle).unwrap();
    let SupervisionProgress::AttachedChannel(frontend) =
        supervisor.poll_frontend(&handle, &mut host).unwrap()
    else {
        panic!("actual inherited handoff did not admit its exact frontend")
    };
    assert!(host.frontend_is_current(frontend));
    assert_eq!(supervisor.in_use(), 1);
    assert_eq!(host.frontend_obligations_for_test(), 1);
    assert!(supervisor
        .prepare(&mut host, config, setup_deadline)
        .is_err());
    // Reuse the same host only after its exact real Child/EOF/paired-close
    // settlement, not merely after retiring logical frontend permission.
    let deadline = Instant::now() + Duration::from_secs(12);
    drop(handle);
    while supervisor.in_use() != 0 || host.frontend_obligations_for_test() != 0 {
        supervisor.poll_frontends(&mut host).unwrap();
        assert!(
            Instant::now() < deadline,
            "exact first frontend settlement deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert!(!host.frontend_is_current(frontend));
    assert_eq!(supervisor.in_use(), 0);
    assert_eq!(host.frontend_obligations_for_test(), 0);
    let successor = supervisor
        .prepare(&mut host, config, setup_deadline)
        .unwrap();
    supervisor.start(&mut host, &successor).unwrap();
    let SupervisionProgress::AttachedChannel(next) =
        supervisor.poll_frontend(&successor, &mut host).unwrap()
    else {
        panic!("same-host successor did not receive exact real admission")
    };
    assert_ne!(next, frontend);
    assert!(host.frontend_is_current(next));
    assert_eq!(supervisor.in_use(), 1);
    supervisor.begin_stop(&mut host).unwrap();
    assert!(!host.frontend_is_current(next));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    loop {
        match runtime.block_on(supervisor.finish_stop(&mut host, 0)) {
            Ok(()) => break,
            Err(SupervisionError::CleanupPending) => {}
            Err(error) => panic!("exact supervisor stop refused: {error:?}"),
        }
        assert!(
            Instant::now() < deadline,
            "supervisor exact Child/EOF cleanup deadline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(supervisor.in_use(), 0);
    // A successor claim is possible only after actual debt/registration cleanup.
    let _successor = HostSupervisor::new(&mut host).unwrap();
}
fn daemon() -> PathBuf {
    let path = PathBuf::from(
        std::env::var_os("QSH_TEST_QSHD").expect("CI supplies exact current Cargo daemon artifact"),
    );
    assert!(path.is_absolute() && path.is_file());
    path
}
fn real() -> FrontendLaunches {
    let mut launches = FrontendLaunches::new(1).unwrap();
    launches.program = Some(TestProgram {
        executable: daemon(),
        args: vec![MARKER.into()],
        environment: vec![],
        body: false,
    });
    launches
}
fn prepare(launches: &mut FrontendLaunches) -> LaunchHandle {
    launches
        .prepare(config(), Instant::now() + Duration::from_secs(10))
        .unwrap()
}
fn body_program(mode: &str, path: &std::path::Path) -> TestProgram {
    TestProgram {
        executable: std::env::current_exe().unwrap(),
        args: [
            "--exact",
            BODY,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
            "--color=never",
        ]
        .map(OsString::from)
        .to_vec(),
        environment: vec![
            ("QSH_LAUNCH_FIXTURE_MODE".into(), mode.into()),
            (
                "QSH_LAUNCH_FIXTURE_COORD".into(),
                path.as_os_str().to_owned(),
            ),
        ],
        body: true,
    }
}
fn accept(listener: &UnixListener) -> UnixStream {
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(10)))
                    .unwrap();
                return stream;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                let left = deadline
                    .checked_duration_since(Instant::now())
                    .expect("owned fixture connect deadline");
                let mut fd = libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                let millis = i32::try_from(left.as_millis().max(1)).unwrap_or(i32::MAX);
                let result = unsafe { libc::poll(&mut fd, 1, millis) };
                assert!(
                    result > 0
                        || (result < 0
                            && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted)
                );
            }
            Err(e) => panic!("fixture accept: {e}"),
        }
    }
}
fn byte(stream: &mut UnixStream, expected: u8) {
    let mut got = [0; 1];
    stream.read_exact(&mut got).unwrap();
    assert_eq!(got, [expected]);
}
fn body_output(launches: &mut FrontendLaunches, handle: &LaunchHandle) {
    let capsule = launches.find(handle).unwrap();
    let mut c = capsule.lock().unwrap();
    assert_eq!(c.wait, WaitState::Terminal);
    assert!(
        c.status.unwrap().success(),
        "actual fixture child status {:?}",
        c.status
    );
    if let Some(mut output) = c.output.take() {
        let raw = output.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        assert!(
            flags >= 0 && unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0
        );
        let mut text = String::new();
        output
            .by_ref()
            .take(16384)
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(
            text.lines().filter(|l| *l == "running 1 test").count(),
            1,
            "{text}"
        );
        assert_eq!(
            text.matches("test result: ok. 1 passed; 0 failed; 0 ignored;")
                .count(),
            1,
            "{text}"
        );
        assert!(text.contains(&format!("test {BODY} ... ")), "{text}");
        assert!(!text.contains("SKIPPED"), "{text}");
        println!("launch529 actual exact fixture body successful: {BODY}");
    }
    if let Some(mut errors) = c.errors.take() {
        let raw = errors.as_raw_fd();
        let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
        assert!(
            flags >= 0 && unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0
        );
        let mut text = String::new();
        errors
            .by_ref()
            .take(16384)
            .read_to_string(&mut text)
            .unwrap();
        assert!(!text.contains("SKIPPED"), "{text}");
    }
}
fn settled(launches: &mut FrontendLaunches, handle: &LaunchHandle, success: bool) {
    settled_case(launches, handle, success, observation::Subcase::Other);
}
fn subcase(case: observation::Subcase) {
    eprintln!("launch529_subcase_v1 label={}", case.label());
}
fn settled_case(
    launches: &mut FrontendLaunches,
    handle: &LaunchHandle,
    success: bool,
    case: observation::Subcase,
) {
    let deadline = Instant::now() + Duration::from_secs(12);
    loop {
        let progress = launches.poll(handle);
        if progress == LaunchProgress::Settled {
            break;
        }
        if progress == LaunchProgress::Unknown {
            eprintln!(
                "{}",
                observation::render(case, &launches.observation(handle))
            );
        }
        assert_ne!(
            progress,
            LaunchProgress::Unknown,
            "unknown is not cleanup proof"
        );
        if Instant::now() >= deadline {
            eprintln!(
                "{}",
                observation::render(case, &launches.observation(handle))
            );
        }
        assert!(
            Instant::now() < deadline,
            "exact Child/EOF cleanup deadline"
        );
        // Production poll itself never sleeps or loops. This is the CI fixture scheduler.
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(launches.in_use(), 0);
    assert_eq!(launches.budget.in_use(), 0);
    let observed = launches.observe(handle).unwrap();
    assert_eq!(observed.progress(), LaunchProgress::Settled);
    assert!(observed.eof(), "setup EOF is an actual launch observation");
    let capsule = launches.find(handle).unwrap();
    let c = capsule.lock().unwrap();
    assert!(
        c.setup_allocated && c.eof && matches!(c.wait, WaitState::Terminal | WaitState::NotCreated)
    );
    if success {
        assert!(c.status.unwrap().success());
    }
    use observation::Subcase as S;
    if matches!(
        case,
        S::RecordMagic
            | S::RecordHostZero
            | S::RecordChannelZero
            | S::RecordChallengeZero
            | S::RecordUid
            | S::RecordFrontendRole
            | S::RecordHostRole
            | S::RecordMinVersion
            | S::RecordMaxVersion
            | S::RecordReservedPrefix
            | S::RecordDeadlineZero
            | S::RecordTailVersion
            | S::RecordReservedTail
    ) {
        assert_eq!(
            c.wait,
            WaitState::Terminal,
            "malformed record created an exact owned child"
        );
        assert!(
            c.status.is_some(),
            "native wait must retain actual ExitStatus"
        );
    }
    let local_closes = c.host.is_none()
        && c.admitted.is_none()
        && c.frontend.is_none()
        && c.setup.is_none()
        && c.setup_child.is_none()
        && c.duplicates.iter().all(Option::is_none)
        && c.remote.is_none()
        && c.child.is_none();
    assert!(local_closes);
    let receipt = format!("launch529_settlement_v1 subcase={} rejection={:?} eof={} wait={:?} status={:?} local_closes={} remote_charge=0", case.label(), c.first_rejection, c.eof, c.wait, observation::Status::capture(c.status.as_ref()), local_closes);
    assert!(receipt.len() <= 512, "bounded settlement receipt");
    println!("{receipt}");
    println!(
        "launch529 cleanup eof={} owned_wait={} local_closes=true remote_charge=0",
        c.eof,
        c.wait == WaitState::Terminal
    );
}

#[test]
#[ignore = "controlled ordinary-account real-exec CI only"]
fn launch529_exec_admits_only_the_designated_frontend() {
    let mut launches = real();
    let handle = prepare(&mut launches);
    assert_eq!(launches.poll(&handle), LaunchProgress::Preparing);
    launches.start(&handle).unwrap();
    assert_eq!(launches.poll(&handle), LaunchProgress::Admitted);
    {
        let capsule = launches.find(&handle).unwrap();
        let mut c = capsule.lock().unwrap();
        println!(
            "launch529 actual qshd child pid={} observation_only=true",
            c.child.as_ref().unwrap().id()
        );
        assert!(launch::test_evidence(c.admitted.as_mut().unwrap()));
        assert!(
            !launch::test_evidence(c.admitted.as_mut().unwrap()),
            "one-shot host-side evidence"
        );
    }
    launches.cancel(&handle);
    settled(&mut launches, &handle, true);
    supervisor_handoff_and_stop();
    // Copied setup on another real pair cannot satisfy the retained original Host.
    let mut launches = real();
    let handle = prepare(&mut launches);
    let (fake, peer) = UnixStream::pair().unwrap();
    let mut peer = {
        let capsule = launches.find(&handle).unwrap();
        let mut c = capsule.lock().unwrap();
        let remote = c.remote.as_ref().unwrap();
        let fake = remote.track(fake.into());
        let source = fake.duplicate().unwrap();
        let peer = remote.track(peer.into());
        c.duplicates[1] = Some(source);
        drop(fake);
        peer
    };
    assert!(launches.start(&handle).is_err());
    assert_ne!(launches.poll(&handle), LaunchProgress::Admitted);
    peer.close();
    settled(&mut launches, &handle, false);
}

#[test]
#[ignore = "controlled ordinary-account real-exec CI only"]
fn launch529_exec_failure_and_cancel_keep_exact_custody() {
    let dir = tempfile::tempdir().unwrap();
    let noexec = dir.path().join("noexec");
    std::fs::write(&noexec, b"not executable").unwrap();
    std::fs::set_permissions(&noexec, std::fs::Permissions::from_mode(0o600)).unwrap();
    for executable in [dir.path().join("absent"), noexec] {
        let mut launches = real();
        launches.program.as_mut().unwrap().executable = executable;
        let handle = prepare(&mut launches);
        assert!(launches.start(&handle).is_err());
        assert_ne!(launches.poll(&handle), LaunchProgress::Admitted);
        settled(&mut launches, &handle, false);
    }
    let mut launches = real();
    launches.fail_after_spawn = true;
    let handle = prepare(&mut launches);
    assert!(launches.start(&handle).is_err());
    assert_ne!(launches.poll(&handle), LaunchProgress::Admitted);
    settled(&mut launches, &handle, false);
    // Parent expiry does not require any child prefix/admission reply.
    for prefix in [0, 16, 95] {
        let mut launches = real();
        launches.prefix_bytes = Some(prefix);
        let handle = launches
            .prepare(config(), Instant::now() + Duration::from_secs(2))
            .unwrap();
        assert!(launches.start(&handle).is_err());
        assert_ne!(launches.poll(&handle), LaunchProgress::Admitted);
        settled(&mut launches, &handle, false);
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coord");
    let listener = UnixListener::bind(&path).unwrap();
    let mut launches = real();
    launches.program = Some(body_program("late", &path));
    let handle = prepare(&mut launches);
    std::thread::scope(|scope| {
        let control = Arc::clone(&handle.control);
        let thread = scope.spawn(move || {
            let mut socket = accept(&listener);
            byte(&mut socket, b'R');
            control.cancel();
            socket.write_all(b"G").unwrap();
            byte(&mut socket, b'A');
        });
        assert!(launches.start(&handle).is_err());
        thread.join().unwrap();
    });
    assert_ne!(launches.poll(&handle), LaunchProgress::Admitted);
    settled(&mut launches, &handle, true);
    body_output(&mut launches, &handle);
}

#[test]
#[ignore = "controlled ordinary-account real-exec CI only"]
fn launch529_eof_wait_and_extra_reference_order() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coord");
    let listener = UnixListener::bind(&path).unwrap();
    let mut launches = real();
    launches.program = Some(body_program("eof-live", &path));
    let handle = prepare(&mut launches);
    launches.start(&handle).unwrap();
    let mut socket = accept(&listener);
    byte(&mut socket, b'A');
    byte(&mut socket, b'E');
    assert_eq!(launches.poll(&handle), LaunchProgress::Closing);
    {
        let capsule = launches.find(&handle).unwrap();
        let c = capsule.lock().unwrap();
        assert!(c.eof && c.wait == WaitState::Pending);
    }
    assert_eq!(launches.in_use(), 1);
    socket.write_all(b"G").unwrap();
    settled(&mut launches, &handle, true);
    body_output(&mut launches, &handle);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("coord");
    let listener = UnixListener::bind(&path).unwrap();
    let mut launches = real();
    launches.program = Some(body_program("exit", &path));
    let handle = prepare(&mut launches);
    let mut extra = {
        let c = launches.find(&handle).unwrap();
        let c = c.lock().unwrap();
        c.setup_child.as_ref().unwrap().duplicate().unwrap()
    };
    launches.start(&handle).unwrap();
    let mut socket = accept(&listener);
    byte(&mut socket, b'A');
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let _ = launches.poll(&handle);
        let c = launches.find(&handle).unwrap();
        let c = c.lock().unwrap();
        if c.wait == WaitState::Terminal {
            assert!(!c.eof);
            break;
        }
        assert!(Instant::now() < deadline);
        drop(c);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(launches.in_use(), 1);
    assert_eq!(launches.budget.in_use(), 1);
    extra.close();
    settled(&mut launches, &handle, true);
    body_output(&mut launches, &handle);
}

#[test]
#[ignore = "controlled ordinary-account real-exec CI only"]
fn launch529_foreign_or_invalid_inheritance_refuses() {
    // Real foreign-UID refusal is separately required in the disposable root tier.
    config();
    use observation::Subcase as S;
    for (offset, case) in [
        (0, S::RecordMagic),
        (12, S::RecordHostZero),
        (28, S::RecordChannelZero),
        (44, S::RecordChallengeZero),
        (76, S::RecordUid),
        (80, S::RecordFrontendRole),
        (81, S::RecordHostRole),
        (82, S::RecordMinVersion),
        (84, S::RecordMaxVersion),
        (86, S::RecordReservedPrefix),
        (88, S::RecordDeadlineZero),
        (96, S::RecordTailVersion),
        (104, S::RecordReservedTail),
    ] {
        subcase(case);
        let mut launches = real();
        let handle = prepare(&mut launches);
        {
            let c = launches.find(&handle).unwrap();
            let mut c = c.lock().unwrap();
            if [12, 28, 44].contains(&offset) {
                let end = match offset {
                    12 => 28,
                    28 => 44,
                    _ => 76,
                };
                c.record[offset..end].fill(0);
            } else if offset == 88 {
                c.record[88..96].fill(0);
            } else {
                c.record[offset] ^= 0x80;
            }
        }
        assert!(launches.start(&handle).is_err());
        settled_case(&mut launches, &handle, false, case);
    }
    for (kind, case) in [
        ("regular", S::SetupRegular),
        ("listener", S::SetupListener),
        ("alias", S::SetupAlias),
    ] {
        subcase(case);
        let mut launches = real();
        let handle = prepare(&mut launches);
        let dir = tempfile::tempdir().unwrap();
        {
            let c = launches.find(&handle).unwrap();
            let mut c = c.lock().unwrap();
            if kind == "alias" {
                c.duplicates[0] = Some(c.duplicates[1].as_ref().unwrap().duplicate().unwrap());
            } else {
                let fd: OwnedFd = match kind {
                    "regular" => std::fs::File::open("/dev/null").unwrap().into(),
                    "listener" => UnixListener::bind(dir.path().join("invalid"))
                        .unwrap()
                        .into(),
                    _ => unreachable!(),
                };
                let tracked = c.remote.as_ref().unwrap().track(fd);
                c.duplicates[0] = Some(tracked.duplicate().unwrap());
                drop(tracked);
            }
        }
        assert!(launches.start(&handle).is_err());
        settled_case(&mut launches, &handle, false, case);
    }
    subcase(S::ExtraSetupBytes);
    let mut launches = real();
    let handle = prepare(&mut launches);
    launches.start(&handle).unwrap();
    {
        let c = launches.find(&handle).unwrap();
        let c = c.lock().unwrap();
        assert_eq!(
            launch::test_write(c.setup.as_ref().unwrap().fd().unwrap(), b"extra").unwrap(),
            5
        );
    }
    settled_case(&mut launches, &handle, false, S::ExtraSetupBytes);
    for (args, case) in [
        (vec![MARKER.into()], S::DirectMissingFds),
        (vec![MARKER.into(), "extra".into()], S::DirectExtraArgs),
    ] {
        subcase(case);
        let output = direct(daemon(), args, true);
        assert!(!output.0.success());
    }
}

#[test]
#[ignore = "isolated fixture body; exact owning outer selects it"]
fn launch529_isolated_child_body() {
    let mode = std::env::var("QSH_LAUNCH_FIXTURE_MODE")
        .expect("only exact owning native outer supplies fixture mode");
    assert!(matches!(mode.as_str(), "late" | "eof-live" | "exit"));
    child::fixture_entry(&mode).unwrap();
}

// Direct malformed-entry fixtures own one Child, never reconstruct or signal a PID.
fn direct(program: PathBuf, args: Vec<OsString>, close_fixed: bool) -> (ExitStatus, String) {
    let mut command = Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .env_remove(crate::service_stage::LAUNCH_ENV)
        .env_remove(crate::handover::HANDOVER_FD_ENV);
    if close_fixed {
        unsafe {
            command.pre_exec(|| {
                libc::close(3);
                libc::close(4);
                Ok(())
            });
        }
    }
    let child = command.spawn().unwrap();
    drop(command);
    struct Retained {
        child: Option<Child>,
        quarantine: Option<Arc<Mutex<Retained>>>,
    }
    let retained = Arc::new(Mutex::new(Retained {
        child: Some(child),
        quarantine: None,
    }));
    let mut deadline = Instant::now() + Duration::from_secs(5);
    let mut killed = false;
    let status = loop {
        let mut owner = retained.lock().unwrap();
        match owner.child.as_mut().unwrap().try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if Instant::now() >= deadline {
                    if killed {
                        owner.quarantine = Some(Arc::clone(&retained));
                        panic!("direct fixture unresolved; exact Child quarantined");
                    }
                    owner.child.as_mut().unwrap().kill().unwrap();
                    killed = true;
                    deadline = Instant::now() + Duration::from_secs(2);
                }
            }
            Err(error) => {
                owner.quarantine = Some(Arc::clone(&retained));
                panic!("direct fixture lost wait; no numeric signal: {error}");
            }
        }
        drop(owner);
        std::thread::sleep(Duration::from_millis(1));
    };
    let mut child = retained.lock().unwrap().child.take().unwrap();
    assert_eq!(child.wait().unwrap(), status);
    let mut stderr = child.stderr.take().unwrap();
    let raw = stderr.as_raw_fd();
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    assert!(
        flags >= 0 && unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0
    );
    let mut text = String::new();
    stderr
        .by_ref()
        .take(4096)
        .read_to_string(&mut text)
        .unwrap();
    (status, text)
}

#[cfg(target_os = "linux")]
#[test]
fn launch529_root_and_foreign_entry_refuse_before_setup() {
    use crate::control::peer_fixture::{self, Fixture};
    use std::os::fd::FromRawFd;
    const NAME:&str="session_owner::inherited_launch::native_tests::launch529_root_and_foreign_entry_refuse_before_setup";
    if let Some((role, path)) = peer_fixture::child_role() {
        assert_eq!(role, "launch-foreign");
        let setup = UnixStream::connect(&path).unwrap();
        let admission = UnixStream::connect(&path).unwrap();
        assert_eq!(crate::control::peer_uid(&setup).unwrap(), 0);
        let duplicate = |fd: i32| {
            let raw = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 5) };
            assert!(raw > 4);
            unsafe { OwnedFd::from_raw_fd(raw) }
        };
        let a = duplicate(setup.as_raw_fd());
        let b = duplicate(admission.as_raw_fd());
        drop(setup);
        drop(admission);
        unsafe {
            assert_eq!(libc::dup2(a.as_raw_fd(), 3), 3);
            assert_eq!(libc::dup2(b.as_raw_fd(), 4), 4);
        }
        // The isolated body now owns the fixed descriptors; no setup byte is sent.
        assert!(child::entry(&[MARKER.into()]).unwrap().is_err());
        return;
    }
    assert_eq!(
        unsafe { libc::geteuid() },
        0,
        "root refusal has a separate maintained owner"
    );
    assert_eq!(
        std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref(),
        Ok("1")
    );
    let (status, error) = direct(daemon(), vec![MARKER.into()], true);
    assert!(!status.success());
    assert!(
        error.contains("personal frontend requires non-root"),
        "{error}"
    );
    let mut fixture = Fixture::new();
    let listener = UnixListener::bind(&fixture.path).unwrap();
    peer_fixture::allow_fixture_connection(&fixture.path);
    fixture.spawn(NAME, "launch-foreign");
    let setup = peer_fixture::accept(&listener, fixture.deadline);
    let admission = peer_fixture::accept(&listener, fixture.deadline);
    assert_eq!(
        crate::control::peer_uid(&setup).unwrap(),
        peer_fixture::FOREIGN
    );
    assert_eq!(
        crate::control::peer_uid(&admission).unwrap(),
        peer_fixture::FOREIGN
    );
    fixture.finish();
    println!("launch529 root entry refused before fixed-fd read; real foreign UID61001 refused root-created connected peers without setup bytes");
}
