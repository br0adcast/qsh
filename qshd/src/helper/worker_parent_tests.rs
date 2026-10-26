#[cfg(target_os = "linux")]
mod worker_parent {
    use super::*;
    use crate::helper::{
        worker_bootstrap::Publisher,
        worker_control,
        worker_owner::WorkerOwner,
        worker_stop::WorkerStop,
        worker_threads::{Role, WorkerThreads},
    };
    use std::os::fd::FromRawFd;
    use std::{
        num::NonZeroU32,
        os::unix::process::CommandExt,
        process::{Command, Stdio},
    };

    #[test]
    #[ignore = "runs only inside the owned parent-pump subprocess"]
    fn worker40_parent_held_child_body() {
        let fd: i32 = std::env::var("QSH_TEST_PARENT_CONTROL")
            .unwrap()
            .parse()
            .unwrap();
        // SAFETY: inherited exact fixture descriptor has one owner in this child.
        let socket = unsafe { UnixStream::from_raw_fd(fd) };
        let dir = PathBuf::from(std::env::var_os("QSH_TEST_PARENT_DIR").unwrap());
        let mut publisher = Publisher::new(socket);
        publisher.establish().unwrap();
        let reader = publisher.reader().unwrap();
        let stop = WorkerStop::default();
        let shutdown = stop.shutdown();
        let manager = async {
            std::fs::write(dir.join("ready"), b"ready").unwrap();
            if std::env::var_os("QSH_TEST_PARENT_NATURAL").is_none() {
                shutdown.requested().await;
                std::fs::write(dir.join("stopped"), b"stopped").unwrap();
                while !dir.join("release").exists() {
                    tokio::time::sleep(Duration::from_millis(2)).await;
                }
            }
            Ok(())
        };
        let manager = crate::helper::worker_child::drive(
            reader,
            nix::unistd::getppid().as_raw() as u32,
            stop.clone(),
            manager,
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut auxiliary = WorkerThreads::default();
        for role in [
            Role::ChannelReader,
            Role::AuthReader,
            Role::TellReleaser,
            Role::NoncePool,
        ] {
            auxiliary.register(role, std::thread::spawn(|| Ok(())), || Ok(()));
        }
        let outcome = crate::helper::worker_drain::run(runtime, manager, auxiliary, stop);
        // ChannelLost is a retained fault even though actual joins completed.
        let _ = publisher.finish(outcome);
        std::fs::write(dir.join("finished"), b"finished").unwrap();
        if let Ok(code) = std::env::var("QSH_TEST_PARENT_EXIT") {
            let code: i32 = code.parse().unwrap();
            if code < 0 {
                // This exact disposable child terminates only itself after Drained.
                unsafe { nix::libc::raise(-code) };
                panic!("fixture terminating signal unexpectedly returned");
            }
            std::process::exit(code);
        }
    }

    struct ChildOwner(std::process::Child);
    impl Drop for ChildOwner {
        fn drop(&mut self) {
            match self.0.try_wait() {
                Ok(Some(_)) => return,
                Err(e) if e.raw_os_error() == Some(nix::libc::ECHILD) => return,
                Ok(None) => {}
                Err(e) => panic!("owned parent fixture wait: {e}"),
            }
            self.0.kill().unwrap();
            self.0.wait().unwrap();
        }
    }

    fn child_fixture(natural: bool) -> (tempfile::TempDir, WorkerOwner, ChildOwner) {
        child_fixture_exit(natural, None)
    }

    fn child_fixture_exit(
        natural: bool,
        exit: Option<i32>,
    ) -> (tempfile::TempDir, WorkerOwner, ChildOwner) {
        use std::os::fd::AsRawFd;
        let dir = tempfile::tempdir().unwrap();
        let view = crate::process_scope::prepare().unwrap();
        let (private, child_private) = worker_control::pair().unwrap();
        let fd = child_private.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "helper::server::tests::worker_parent::worker40_parent_held_child_body",
                "--ignored",
                "--test-threads=1",
            ])
            .env("QSH_TEST_PARENT_CONTROL", fd.to_string())
            .env("QSH_TEST_PARENT_DIR", dir.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        command
            .env_remove("QSH_TEST_PARENT_EXIT")
            .env_remove("QSH_TEST_PARENT_NATURAL");
        if let Some(code) = exit {
            command.env("QSH_TEST_PARENT_EXIT", code.to_string());
        }
        if natural {
            command.env("QSH_TEST_PARENT_NATURAL", "1");
        }
        // SAFETY: async-signal-safe setup of this exact fixture descriptor only.
        unsafe {
            command.pre_exec(move || {
                if nix::libc::fcntl(fd, nix::libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        let worker = WorkerOwner::new(
            NonZeroU32::new(child.id()).unwrap(),
            view,
            private,
            Instant::now() + Duration::from_secs(3),
        );
        let child = ChildOwner(child);
        drop(child_private);
        let ready_deadline = Instant::now() + Duration::from_secs(2);
        while !dir.path().join("ready").exists() && Instant::now() < ready_deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(
            dir.path().join("ready").exists(),
            "child manager must enter before EOF"
        );
        (dir, worker, child)
    }

    #[test]
    fn worker40_parent_channel_eof_retains_actual_held_manager_and_auth_route() {
        let (dir, worker, mut child) = child_fixture(false);
        let (channels, worker_channels) = channel::pair().unwrap();
        let (auth, worker_auth) = channel::pair().unwrap();
        drop(worker_channels);
        let (done, finished) = std::sync::mpsc::channel();
        let parent = std::thread::spawn(move || {
            serve_owned(
                channels,
                auth,
                test_config(),
                HashMap::new(),
                AccountSwitches::REAL,
                None,
                worker,
            );
            done.send(()).unwrap();
        });
        let early = finished.recv_timeout(Duration::from_millis(100)).is_ok();
        let deadline = Instant::now() + Duration::from_secs(2);
        while !dir.path().join("stopped").exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        let saw_stop = dir.path().join("stopped").exists();
        worker_auth
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        let auth_answer = channel::send(
            &worker_auth,
            &encode(&AuthRequest {
                id: 401,
                body: Request::Nonce,
            })
            .unwrap(),
            None,
        )
        .and_then(|()| channel::recv(&worker_auth));
        let refused = matches!(auth_answer, Ok(Some((bytes, None))) if matches!(decode::<AuthResponse>(&bytes), Ok(AuthResponse { id:401, body:Response::NonceUnavailable })));

        // All failure paths release and actually join both fixture owners before assertions.
        std::fs::write(dir.path().join("release"), b"release").unwrap();
        drop(worker_auth);
        parent.join().unwrap();
        let product_reaped = matches!(child.0.try_wait(), Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD));
        drop(child);
        assert!(
            product_reaped,
            "the parent pump must perform the actual final wait"
        );
        assert!(
            !early,
            "parent returned while the exact child manager remained held"
        );
        assert!(saw_stop, "parent did not deliver cooperative Stop");
        assert!(
            refused,
            "auth route must remain serviced while stopping, without new admission"
        );
        assert!(dir.path().join("finished").exists());
    }
    #[test]
    fn worker40_parent_final_receipt_does_not_create_an_irrelevant_stop_send() {
        let (_dir, owner, mut child) = child_fixture(true);
        let mut worker = WorkerDomain::new(owner);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !worker.native_complete && Instant::now() < deadline {
            worker.advance();
            std::thread::sleep(Duration::from_millis(2));
        }
        let settled = worker.settled();
        let clean = worker.first_failure.is_none();
        worker.request_stop(crate::helper::worker_protocol::StopReason::Requested);
        let no_late_send = worker.pending.is_none();
        let product_reaped =
            matches!(child.0.try_wait(), Err(e) if e.raw_os_error() == Some(nix::libc::ECHILD));
        drop(child);
        assert!(settled && clean && product_reaped);
        assert!(
            no_late_send,
            "already final receipt must not acquire a new Stop send failure"
        );
    }

    #[test]
    fn worker40_drained_nonzero_native_exit_remains_failed() {
        drained_native_exit(23, 23, None);
    }

    #[test]
    fn worker40_drained_signal_native_exit_remains_failed() {
        drained_native_exit(-nix::libc::SIGTERM, 128 + nix::libc::SIGTERM, None);
    }

    #[test]
    fn worker40_drained_zero_native_exit_remains_successful() {
        drained_native_exit(0, 0, None);
    }

    #[test]
    fn required40_actual_zero_exit_and_drained_cannot_erase_publication_failure() {
        drained_native_exit(0, 0, Some(super::required_reply::exited_failure()));
    }

    fn drained_native_exit(
        code: i32,
        expected: i32,
        publication: Option<RequiredPublicationFailure>,
    ) {
        let (_dir, owner, mut child) = child_fixture_exit(true, Some(code));
        let mut worker = WorkerDomain::new(owner);
        let deadline = Instant::now() + Duration::from_secs(2);
        while !worker.settled() && Instant::now() < deadline {
            worker.advance();
            std::thread::sleep(Duration::from_millis(2));
        }
        let reaped =
            matches!(child.0.try_wait(), Err(e) if e.raw_os_error() == Some(nix::libc::ECHILD));
        drop(child);
        assert!(reaped && worker.settled());
        let outcome = HelperPhysicalOutcome {
            worker: worker.physical_outcome(),
            pam_received: PamCompletion::NotOpened,
            missing_pam: 0,
            channel_receipts: ChannelReceiptDebt::default(),
            pending_requests: false,
            monitor_failure: None,
            adoption_failed: false,
            forced_worker: false,
            required_publication: publication,
        };
        assert!(outcome.worker.terminal_received);
        assert!(outcome.worker.first_failure.is_none());
        assert!(outcome.worker.signal_failure.is_none());
        assert_eq!(outcome.worker.native_exit, expected);
        assert_eq!(
            outcome.failed(),
            expected != 0 || publication.is_some(),
            "successful Drained cannot erase actual nonzero native exit"
        );
    }

    #[test]
    fn worker40_only_requested_stop_accepts_clean_eof_and_never_receive_failure() {
        use crate::helper::worker_protocol::StopReason;
        for reason in [
            None,
            Some(StopReason::Requested),
            Some(StopReason::Protocol),
        ] {
            for failed in [false, true] {
                let (dir, owner, child) = child_fixture(false);
                let mut worker = WorkerDomain::new(owner);
                // stopping alone can come from a receipt or unrelated failure.
                worker.stopping = true;
                if let Some(reason) = reason {
                    worker.request_stop(reason);
                    // A fallback or later request cannot change the first cause.
                    worker.request_stop(StopReason::Protocol);
                    worker.request_stop(StopReason::Requested);
                }
                worker.record_seam_end(
                    if failed { Next::Failed } else { Next::Eof },
                    ParentFailure::Channel,
                );
                let recorded = worker.first_failure.is_some();
                std::fs::write(dir.path().join("release"), b"release").unwrap();
                worker.request_stop(StopReason::Requested);
                worker.send_stop();
                let deadline = Instant::now() + Duration::from_secs(2);
                while !worker.settled() && Instant::now() < deadline {
                    worker.advance();
                    std::thread::sleep(Duration::from_millis(2));
                }
                let settled = worker.settled();
                drop(worker);
                drop(child);
                assert!(settled, "fixture must actually settle before assertions");
                assert_eq!(recorded, failed || reason != Some(StopReason::Requested));
            }
        }
    }

    #[test]
    fn worker40_parent_native_wait_without_receipt_settles_failed_physical_owner() {
        let view = crate::process_scope::prepare().unwrap();
        let (private, peer) = worker_control::pair().unwrap();
        let process = Command::new("/bin/true").spawn().unwrap();
        let owner = WorkerOwner::new(
            NonZeroU32::new(process.id()).unwrap(),
            view,
            private,
            Instant::now() + Duration::from_secs(2),
        );
        let mut child = ChildOwner(process);
        drop(peer);
        let mut worker = WorkerDomain::new(owner);
        worker.request_stop(crate::helper::worker_protocol::StopReason::Requested);
        assert!(worker.pending.is_some());
        let deadline = Instant::now() + Duration::from_secs(2);
        while !worker.native_complete && Instant::now() < deadline {
            worker.advance();
            std::thread::sleep(Duration::from_millis(2));
        }
        let reaped =
            matches!(child.0.try_wait(), Err(e) if e.raw_os_error() == Some(nix::libc::ECHILD));
        drop(child);
        assert!(reaped && worker.native_complete);
        assert!(
            worker.settled(),
            "proved physical exit must not wait forever for a missing logical receipt"
        );
        assert!(matches!(
            worker.first_failure,
            Some(ParentFailure::Worker(
                crate::helper::worker_owner::WorkerFailure::MissingReceipt
            ))
        ));
        worker.record(ParentFailure::Poll(nix::libc::EIO));
        worker.advance();
        assert!(matches!(
            worker.first_failure,
            Some(ParentFailure::Worker(
                crate::helper::worker_owner::WorkerFailure::MissingReceipt
            ))
        ));
        assert!(worker.settled());
        assert!(
            worker.pending.is_none(),
            "native completion must discard queued Stop"
        );
        worker.request_stop(crate::helper::worker_protocol::StopReason::Requested);
        assert!(worker.pending.is_none());
    }

    #[test]
    fn worker40_parent_lost_wait_cannot_settle_from_queued_matching_records() {
        let (_dir, owner, mut child) = child_fixture(true);
        let mut unrelated = ChildOwner(Command::new("/bin/sleep").arg("60").spawn().unwrap());
        let stolen = child.0.wait().unwrap();
        let mut worker = WorkerDomain::new(owner);
        for _ in 0..8 {
            worker.advance();
        }
        let unrelated_running = unrelated.0.try_wait().unwrap().is_none();
        drop(child);
        drop(unrelated);
        assert!(stolen.success() && unrelated_running);
        assert!(!worker.native_complete && !worker.settled());
        assert!(matches!(
            worker.first_failure,
            Some(ParentFailure::Worker(
                crate::helper::worker_owner::WorkerFailure::LostAuthority
            ))
        ));
    }

    const PHYSICAL_PHASE: &str = "QSH_TEST_PARENT_PHYSICAL_PHASE";
    const PHYSICAL_REPORT_LIMIT: usize = 512;
    const PHYSICAL_CHECKPOINT_LIMIT: usize = 128;
    const PHYSICAL_PHASES: &[&str] = &[
        "unavailable",
        "body-exec",
        "identity",
        "prepare",
        "control-pair",
        "spawn",
        "worker-owner",
        "held-body",
        "pump",
        "outcome",
        "assertions",
        "complete",
    ];
    const PHYSICAL_ASSERTIONS: &[&str] = &[
        "none",
        "parent",
        "physical-wait",
        "required-failure",
        "no-receipt",
        "no-signal-failure",
        "deliberate",
    ];

    // Only closed codes and bounded numeric facts cross the body boundary.
    // Never copy panic payloads, stdout/stderr, process identities or environment.
    #[derive(Clone, Copy, Default)]
    struct PhysicalDiagnostic {
        phase: usize,
        assertion: usize,
        elapsed_ms: u64,
        observations: u8,
        native_exit: i32,
    }
    impl PhysicalDiagnostic {
        fn checkpoint(&mut self, phase: &str, assertion: &str, started: Instant) {
            self.phase = PHYSICAL_PHASES
                .iter()
                .position(|code| *code == phase)
                .unwrap();
            self.assertion = PHYSICAL_ASSERTIONS
                .iter()
                .position(|code| *code == assertion)
                .unwrap();
            self.elapsed_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
            let record = format!(
                "{} {} {} {} {}",
                self.phase, self.assertion, self.elapsed_ms, self.observations, self.native_exit
            );
            assert!(record.len() <= PHYSICAL_CHECKPOINT_LIMIT);
            let path = PathBuf::from(std::env::var_os(PHYSICAL_PHASE).unwrap());
            let next = path.with_extension("next");
            // A killed write must leave the preceding complete checkpoint intact.
            // Both files are overwritten, never appended or allowed to grow.
            std::fs::write(&next, record).unwrap();
            std::fs::rename(next, path).unwrap();
        }
        fn decode(record: &str) -> Option<Self> {
            let mut fields = record.split_whitespace();
            let diagnostic = Self {
                phase: fields.next()?.parse().ok()?,
                assertion: fields.next()?.parse().ok()?,
                elapsed_ms: fields.next()?.parse().ok()?,
                observations: fields.next()?.parse().ok()?,
                native_exit: fields.next()?.parse().ok()?,
            };
            (fields.next().is_none()
                && diagnostic.phase < PHYSICAL_PHASES.len()
                && diagnostic.assertion < PHYSICAL_ASSERTIONS.len()
                && diagnostic.observations <= 31)
                .then_some(diagnostic)
        }
        fn read() -> Self {
            use std::io::Read;
            let read = || {
                let mut record = String::new();
                std::fs::File::open(std::env::var_os(PHYSICAL_PHASE)?)
                    .ok()?
                    .take(PHYSICAL_CHECKPOINT_LIMIT as u64 + 1)
                    .read_to_string(&mut record)
                    .ok()?;
                (record.len() <= PHYSICAL_CHECKPOINT_LIMIT).then_some(record)
            };
            read()
                .and_then(|record| Self::decode(&record))
                .unwrap_or_default()
        }
        fn report(self) -> String {
            format!("phase={}, assertion={}, checkpoint_elapsed_ms={}, outcome_observed={}, physical_wait={}, first_failure={}, terminal_received={}, signal_failure={}, native_exit={:?}",
                PHYSICAL_PHASES[self.phase], PHYSICAL_ASSERTIONS[self.assertion], self.elapsed_ms,
                self.observations & 1 != 0, self.observations & 2 != 0,
                self.observations & 4 != 0, self.observations & 8 != 0,
                self.observations & 16 != 0,
                (self.observations & 1 != 0).then_some(self.native_exit))
        }
    }

    #[test]
    fn worker40_parent_diagnostic_codes_and_storage_are_bounded() {
        assert!(PhysicalDiagnostic::decode("99 0 0 0 0").is_none());
        assert!(PhysicalDiagnostic::decode("0 99 0 0 0").is_none());
        assert!(PhysicalDiagnostic::decode("0 0 0 32 0").is_none());
        assert!(PhysicalDiagnostic::decode("0 0 0 0 0 private-payload").is_none());
        let diagnostic = PhysicalDiagnostic {
            phase: PHYSICAL_PHASES.len() - 1,
            assertion: PHYSICAL_ASSERTIONS.len() - 1,
            elapsed_ms: u64::MAX,
            observations: 31,
            native_exit: i32::MIN,
        };
        assert!(diagnostic.report().len() + 100 <= PHYSICAL_REPORT_LIMIT);
    }

    fn failed_physical_fixture(control: &str) -> String {
        use std::io::Read;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report");
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "helper::server::tests::worker_parent::worker40_parent_missing_receipt_returns_failed_physical_outcome_after_actual_wait",
                "--test-threads=1",
            ])
            .env_remove("QSH_TEST_PARENT_PHYSICAL_STAGE")
            .env_remove("QSH_TEST_PARENT_PHYSICAL_HOLD")
            .env_remove("QSH_TEST_PARENT_PHYSICAL_ASSERT")
            .env("QSH_TEST_PARENT_PHYSICAL_CAPTURE", &path)
            .env(control, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut fixture = ChildOwner(command.spawn().unwrap());
        let status = fixture.0.wait().unwrap();
        drop(fixture);
        let mut report = String::new();
        std::fs::File::open(path)
            .unwrap()
            .take(PHYSICAL_REPORT_LIMIT as u64 + 1)
            .read_to_string(&mut report)
            .unwrap();
        assert!(
            report.len() <= PHYSICAL_REPORT_LIMIT,
            "bounded owned fixture report"
        );
        assert!(!status.success(), "controlled fixture must fail");
        report
    }

    #[test]
    fn worker40_parent_held_body_reports_phase_after_owned_cleanup() {
        let report = failed_physical_fixture("QSH_TEST_PARENT_PHYSICAL_HOLD");
        assert!(report.contains("timed_out=true"), "{report}");
        assert!(report.contains("adopted_reaped=1"), "{report}");
        assert!(report.contains("no_children=true"), "{report}");
        assert!(report.contains("phase=held-body"), "{report}");
    }

    #[test]
    fn worker40_parent_child_assertion_reports_observed_physical_outcome() {
        let report = failed_physical_fixture("QSH_TEST_PARENT_PHYSICAL_ASSERT");
        assert!(report.contains("timed_out=false"), "{report}");
        assert!(report.contains("adopted_reaped=0"), "{report}");
        assert!(report.contains("no_children=true"), "{report}");
        assert!(report.contains("assertion=deliberate"), "{report}");
        assert!(report.contains("physical_wait=true"), "{report}");
        assert!(report.contains("outcome_observed=true"), "{report}");
    }

    #[test]
    fn worker40_parent_missing_receipt_returns_failed_physical_outcome_after_actual_wait() {
        const STAGE: &str = "QSH_TEST_PARENT_PHYSICAL_STAGE";
        const PARENT: &str = "QSH_TEST_PARENT_PHYSICAL_PARENT";
        const REPORT: &str = "QSH_TEST_PARENT_PHYSICAL_REPORT";
        const TEST: &str = "helper::server::tests::worker_parent::worker40_parent_missing_receipt_returns_failed_physical_outcome_after_actual_wait";
        let reexec = |stage: &str| {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args(["--exact", TEST, "--test-threads=1"])
                .env(STAGE, stage)
                .env(PARENT, std::process::id().to_string())
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null());
            command
        };
        let started = Instant::now();
        let mut diagnostic = PhysicalDiagnostic::default();
        match std::env::var(STAGE).ok().as_deref() {
            Some("supervisor") => {
                assert_eq!(
                    std::env::var(PARENT).unwrap().parse::<i32>().unwrap(),
                    unsafe { nix::libc::getppid() }
                );
                // Only this owned self-reexec becomes subreaper. The normal
                // libtest process and its global signal/subreaper state are unchanged.
                assert_eq!(
                    unsafe { nix::libc::prctl(nix::libc::PR_SET_CHILD_SUBREAPER, 1) },
                    0
                );
                diagnostic.checkpoint("body-exec", "none", started);
                let mut body = ChildOwner(reexec("body").spawn().unwrap());
                let deadline = Instant::now() + Duration::from_secs(2);
                let status = loop {
                    match body.0.try_wait() {
                        Ok(Some(status)) => break Some(status),
                        Ok(None) if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(2))
                        }
                        Ok(None) => break None,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(error) => panic!("owned pump body observation: {error}"),
                    }
                };
                // This direct child is exclusively owned; killing it cannot target
                // a reused PID. Drop performs the actual wait before orphan drain.
                drop(body);
                let mut adopted_reaped = 0;
                loop {
                    let mut child_status = 0;
                    let pid = unsafe { nix::libc::waitpid(-1, &mut child_status, 0) };
                    if pid > 0 {
                        adopted_reaped += 1;
                        continue;
                    }
                    match std::io::Error::last_os_error().raw_os_error() {
                        Some(nix::libc::EINTR) => continue,
                        Some(nix::libc::ECHILD) => break,
                        error => panic!("owned pump descendant wait failed: {error:?}"),
                    }
                }
                // The body can create only /bin/true. Actual wait of that finite
                // child is cleanup; elapsed time never supplies exit evidence.
                let report = format!("timed_out={}, body_success={}, adopted_reaped={adopted_reaped}, no_children=true, {}",
                    status.is_none(), status.is_some_and(|s| s.success()), PhysicalDiagnostic::read().report());
                assert!(report.len() <= PHYSICAL_REPORT_LIMIT, "bounded owned fixture report");
                std::fs::write(std::env::var_os(REPORT).unwrap(), &report).unwrap();
                assert!(status.is_some_and(|s| s.success()), "{report}");
                return;
            }
            Some("body") => {
                diagnostic.checkpoint("identity", "parent", started);
                assert_eq!(
                    std::env::var(PARENT).unwrap().parse::<i32>().unwrap(),
                    unsafe { nix::libc::getppid() }
                );
            }
            None => {
                let fixture = tempfile::tempdir().unwrap();
                let report_path = fixture.path().join("cleanup");
                let mut supervisor = ChildOwner(
                    reexec("supervisor")
                        .env(REPORT, &report_path)
                        .env(PHYSICAL_PHASE, fixture.path().join("phase"))
                        .spawn()
                        .unwrap(),
                );
                let status = supervisor.0.wait().unwrap();
                use std::io::Read;
                let mut report = String::new();
                std::fs::File::open(&report_path)
                    .unwrap()
                    .take(PHYSICAL_REPORT_LIMIT as u64 + 1)
                    .read_to_string(&mut report)
                    .unwrap();
                assert!(report.len() <= PHYSICAL_REPORT_LIMIT, "bounded owned fixture report");
                if let Some(path) = std::env::var_os("QSH_TEST_PARENT_PHYSICAL_CAPTURE") {
                    std::fs::write(path, &report).unwrap();
                }
                assert!(status.success(), "owned pump supervisor failed: {report:?}");
                return;
            }
            other => panic!("unknown owned pump fixture stage: {other:?}"),
        }
        diagnostic.checkpoint("prepare", "none", started);
        let view = crate::process_scope::prepare().unwrap();
        diagnostic.checkpoint("control-pair", "none", started);
        let (private, peer) = worker_control::pair().unwrap();
        diagnostic.checkpoint("spawn", "none", started);
        let process = Command::new("/bin/true").spawn().unwrap();
        let owner = WorkerOwner::new(
            NonZeroU32::new(process.id()).unwrap(),
            view,
            private,
            Instant::now() + Duration::from_secs(2),
        );
        let mut child = ChildOwner(process);
        diagnostic.checkpoint("worker-owner", "none", started);
        if std::env::var_os("QSH_TEST_PARENT_PHYSICAL_HOLD").is_some() {
            // Controlled supervisor failure mutation: child and /bin/true remain
            // owned until the supervisor performs actual cleanup, never success.
            diagnostic.checkpoint("held-body", "none", started);
            loop {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        drop(peer);
        let (channels, worker_channels) = channel::pair().unwrap();
        let (auth, worker_auth) = channel::pair().unwrap();
        drop(worker_channels);
        drop(worker_auth);
        diagnostic.checkpoint("pump", "none", started);
        let outcome = serve_owned(
            channels,
            auth,
            test_config(),
            HashMap::new(),
            AccountSwitches::REAL,
            None,
            owner,
        );
        diagnostic.observations = 1 | (u8::from(outcome.first_failure.is_some()) << 2)
            | (u8::from(outcome.terminal_received) << 3)
            | (u8::from(outcome.signal_failure.is_some()) << 4);
        diagnostic.native_exit = outcome.native_exit;
        diagnostic.checkpoint("outcome", "none", started);
        let reaped = matches!(child.0.try_wait(), Err(error)
            if error.raw_os_error() == Some(nix::libc::ECHILD));
        drop(child);
        diagnostic.observations |= u8::from(reaped) << 1;
        diagnostic.checkpoint("assertions", "physical-wait", started);
        assert!(reaped, "return must follow the product's actual final wait");
        diagnostic.checkpoint("assertions", "required-failure", started);
        assert!(outcome.first_failure.is_some());
        diagnostic.checkpoint("assertions", "no-receipt", started);
        assert!(!outcome.terminal_received);
        diagnostic.checkpoint("assertions", "no-signal-failure", started);
        assert!(outcome.signal_failure.is_none());
        if std::env::var_os("QSH_TEST_PARENT_PHYSICAL_ASSERT").is_some() {
            diagnostic.checkpoint("assertions", "deliberate", started);
            panic!("controlled physical fixture assertion");
        }
        diagnostic.checkpoint("complete", "none", started);
    }
}
