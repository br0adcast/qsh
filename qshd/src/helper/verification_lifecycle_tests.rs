#[cfg(target_os = "linux")]
struct Helper40VerificationFixture {
    child: std::process::Child,
    report: Option<OwnedFd>,
    view: Option<crate::process_scope::QualifiedProc>,
}

#[cfg(target_os = "linux")]
impl Helper40VerificationFixture {
    fn new(record: Vec<u8>, keep_writer: bool) -> Self {
        use nix::fcntl::OFlag;
        use std::io;
        use std::os::unix::process::CommandExt;
        use std::process::{Command, Stdio};
        let view = crate::process_scope::prepare().unwrap();
        let (report, output) = nix::unistd::pipe2(OFlag::O_CLOEXEC).unwrap();
        nix::fcntl::fcntl(
            report.as_raw_fd(),
            nix::fcntl::FcntlArg::F_SETFL(OFlag::O_NONBLOCK),
        )
        .unwrap();
        let mut command = Command::new("/bin/sleep");
        command
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                // Child-only HUP handling keeps cleanup held until explicit
                // escalation/fixture takeover; no test-parent disposition changes.
                let mut action: nix::libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = nix::libc::SIG_IGN;
                nix::libc::sigemptyset(&mut action.sa_mask);
                if nix::libc::sigaction(nix::libc::SIGHUP, &action, std::ptr::null_mut()) < 0 {
                    return Err(io::Error::last_os_error());
                }
                // This fixture produces private startup after setsid, not the
                // product fork path. All subsequent report bytes are controlled.
                let sid = nix::libc::setsid();
                if sid < 0 {
                    return Err(io::Error::last_os_error());
                }
                let mut stage = [0u8; 5];
                stage[0] = 1;
                stage[1..].copy_from_slice(&(sid as u32).to_ne_bytes());
                for bytes in [&stage[..], &record[..]] {
                    let mut written = 0;
                    while written < bytes.len() {
                        let count = nix::libc::write(
                            output.as_raw_fd(),
                            bytes[written..].as_ptr().cast(),
                            bytes.len() - written,
                        );
                        if count < 0 {
                            let error = io::Error::last_os_error();
                            if error.kind() == io::ErrorKind::Interrupted {
                                continue;
                            }
                            return Err(error);
                        }
                        if count == 0 {
                            return Err(io::Error::from_raw_os_error(nix::libc::EIO));
                        }
                        written += count as usize;
                    }
                }
                if keep_writer && nix::libc::fcntl(output.as_raw_fd(), nix::libc::F_SETFD, 0) < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        drop(command); // parent's writer clone; child owns any retained writer
        Self {
            child,
            report: Some(report),
            view: Some(view),
        }
    }

    fn pending(&mut self, deadline: Instant, id: u64) -> Pending {
        Pending {
            deadline,
            what: PendingWhat::Verify {
                report: self.report.take().unwrap(),
                child: Pid::from_raw(self.child.id() as i32),
                answered: false,
                custody: Some(Box::new(
                    super::super::verification::VerificationChild::new(
                        std::num::NonZeroU32::new(self.child.id()).unwrap(),
                        self.view.take().unwrap(),
                        deadline,
                    ),
                )),
                id,
                login: "controlled".into(),
                login_id: [42; 16],
                rhost: "203.0.113.7:1234".into(),
            },
        }
    }
}

#[cfg(target_os = "linux")]
impl Drop for Helper40VerificationFixture {
    fn drop(&mut self) {
        use std::io;
        // Callers retain the product tables through synchronous work, then drop
        // them before this fallback takes custody back; no competing waiter.
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => return,
                Ok(None) => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => return,
                Err(error) => panic!("owned verification fixture wait failed: {error}"),
            }
        }
        let _ = self.child.kill();
        loop {
            match self.child.wait() {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => {
                    result.unwrap();
                    return;
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn helper40_verdict_does_not_refund_verification_admission_before_child_cleanup() {
    let record = encode_verdict(&Verdict::Refused {
        reason: "controlled refusal".into(),
        unknown_account: false,
    });
    let mut fixture = Helper40VerificationFixture::new(record, false);
    let running = fixture.child.try_wait().unwrap().is_none(); // before publication
    let pending = fixture.pending(Instant::now() + Duration::from_secs(2), 40);
    let fd = match &pending.what {
        PendingWhat::Verify { report, .. } => report.as_raw_fd(),
        _ => unreachable!(),
    };
    let mut state = empty_state();
    let seams = DirectSeam::new();
    state.pending.insert(pending);
    let pending = state.pending.take_ready(fd).unwrap();
    finish_pending(
        seams.seams(),
        &mut state,
        &test_config(),
        pending,
        WhyFinished::Spoke,
    );
    let charged = state.pending.verifying();
    let orphaned = state.orphans.len();
    drop(state);
    drop(fixture); // actual fixture termination/wait before assertions
    assert!(
        running,
        "controlled child is alive after report EOF before product cleanup"
    );
    assert_eq!(
        charged, 1,
        "answered-but-unjoined verification still consumes admission"
    );
    assert_eq!(
        orphaned, 0,
        "no raw-PID orphan transfer may replace exact owner custody"
    );
}

#[cfg(target_os = "linux")]
fn helper40_pin_verification(state: &mut LoopState) -> crate::process_scope::RetainedProcess {
    let fd = *state.pending.verification_fds().first().unwrap();
    let pending = state.pending.take_ready(fd).unwrap();
    let pid = match &pending.what {
        PendingWhat::Verify {
            child,
            custody: Some(_),
            ..
        } => child.as_raw() as u32,
        _ => panic!("a real owned verification is required"),
    };
    // The still-unreaped product owner reserves this child identity while the
    // independent observer captures its anchored fd; no numeric signalling.
    let view = crate::process_scope::prepare().unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    let pin = loop {
        // This observer is captured while the exclusive child owner reserves
        // the PID. It grants no session-upgrade authority to the product;
        // only that child's private header can establish the product scope.
        if let Ok(pin) = view.capture(pid, pid, &mut crate::process_scope::Native) {
            break pin;
        }
        assert!(
            Instant::now() < deadline,
            "retain exact verification fixture identity after its setsid"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    state.pending.insert(pending);
    pin
}

#[cfg(target_os = "linux")]
#[test]
fn helper40_late_verification_result_cannot_admit_after_sticky_stop() {
    let mut state = empty_state();
    state.stopping = true;
    let seam = DirectSeam::new();
    publish_verification(
        seam.seams(),
        &mut state,
        VerificationReply {
            id: 40,
            login: "controlled",
            login_id: [44; 16],
            rhost: "203.0.113.7:1234",
        },
        Some(Verdict::Admitted {
            account: distinctive_account(),
            identity: "SHA256:controlled".into(),
            algorithm: "ED25519".into(),
        }),
        WhyFinished::Spoke,
    );
    let response = next_answer(&seam.worker_auth);
    assert_eq!(response.id, 40);
    assert!(matches!(response.body, Response::Refused { reason } if reason == REFUSED_REASON));
    assert!(state.logins.is_empty());
    assert!(state.verified.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn helper40_missing_verification_custody_retains_admission_without_deadline_spin() {
    let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
        "helper::server::tests::helper40_missing_verification_custody_retains_admission_without_deadline_spin_body",
    );
    assert!(
        status.success(),
        "owned missing-custody control failed ({status}):\n{stdout}\n{stderr}"
    );
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "runs only in the owned missing-verification-custody subprocess"]
fn helper40_missing_verification_custody_retains_admission_without_deadline_spin_body() {
    let (report, writer) = nix::unistd::pipe().unwrap();
    drop(writer);
    let fd = report.as_raw_fd();
    let deadline = Instant::now();
    let mut state = empty_state();
    let seam = DirectSeam::new();
    state.pending.insert(Pending {
        deadline,
        what: PendingWhat::Verify {
            report,
            // Only this owned subprocess can be targeted by a broken numeric
            // fallback. Missing custody must perform no process operations at all.
            child: Pid::this(),
            answered: false,
            custody: None,
            id: 40,
            login: "controlled".into(),
            login_id: [45; 16],
            rhost: String::new(),
        },
    });
    let pending = state.pending.take_ready(fd).unwrap();
    finish_pending(
        seam.seams(),
        &mut state,
        &test_config(),
        pending,
        WhyFinished::Spoke,
    );
    assert!(matches!(
        next_answer(&seam.worker_auth).body,
        Response::Refused { .. }
    ));
    assert_eq!(state.pending.verifying(), 1);
    assert!(state.orphans.is_empty());
    assert!(
        state.pending.poll_fds().is_empty(),
        "answered EOF cannot spin poll"
    );
    assert_eq!(
        state
            .pending
            .nearest_deadline(deadline + Duration::from_secs(1)),
        None
    );
    expire_pending(
        seam.seams(),
        &mut state,
        &test_config(),
        deadline + Duration::from_secs(1),
    );
    progress_verifications(seam.seams(), &mut state, &test_config());
    assert_eq!(
        state.pending.verifying(),
        1,
        "age cannot refund unknown custody"
    );
    assert!(state.orphans.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn helper40_shutdown_tail_joins_queued_verification_before_refunding_admission() {
    let record = encode_verdict(&Verdict::Admitted {
        account: distinctive_account(),
        identity: "SHA256:controlled".into(),
        algorithm: "ED25519".into(),
    });
    // The private stage and verdict are queued by the owned fixture child;
    // keeping its writer open prevents EOF from masquerading as child cleanup.
    let mut fixture = Helper40VerificationFixture::new(record, true);
    let pending = fixture.pending(Instant::now() + Duration::from_secs(10), 40);
    let mut state = empty_state();
    state.pending.insert(pending);
    let mut pin = helper40_pin_verification(&mut state);
    let seams = DirectSeam::new();
    let mut shutdown = HelperShutdown::new(state);
    shutdown.end_the_monitors(seams.seams(), &test_config());
    let charged = shutdown.state.pending.verifying();
    let orphaned = shutdown.state.orphans.len();
    let admitted = !shutdown.state.logins.is_empty() || !shutdown.state.verified.is_empty();
    let exited = matches!(
        pin.observe(&mut crate::process_scope::Native),
        crate::process_scope::Evidence::Exited
    );
    let response = next_answer(&seams.worker_auth);
    drop(shutdown);
    drop(fixture); // actual cleanup even if a later assertion fails
    assert_eq!(charged, 0, "tail waits for native cleanup and final wait");
    assert_eq!(orphaned, 0, "no numeric orphan transfer");
    assert!(
        exited,
        "exact queued-stage child has exited before tail returns"
    );
    assert!(!admitted, "queued success cannot admit after sticky stop");
    assert!(matches!(response.body, Response::Refused { reason } if reason == REFUSED_REASON));
}
