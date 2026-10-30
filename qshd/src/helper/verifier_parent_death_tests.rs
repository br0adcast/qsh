#[cfg(target_os = "linux")]
mod verifier_parent {
    use super::adoption_native::Pin;
    use super::*;
    use authorized::{IdentityTransition as Step, VerifierBoundary as Boundary};

    fn publish_release(path: &Path, before_publish: impl FnOnce()) {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let pending = path.with_extension("release.pending");
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)
            .unwrap();
        file.write_all(b"release\n").unwrap();
        // This public control record is also read after switching to nobody.
        file.set_permissions(std::fs::Permissions::from_mode(0o644))
            .unwrap();
        drop(file);
        before_publish();
        // A polling verifier must see absence or the whole release record.
        std::fs::rename(pending, path).unwrap();
    }

    #[test]
    fn verifier_release_is_hidden_until_complete_publication() {
        if std::env::var_os("QSH_TEST_RELEASE_PRIVATE_UMASK").is_some() {
            // Only the explicit self-reexec child changes its process umask.
            unsafe { nix::libc::umask(0o077) };
        }
        let dir = tempfile::tempdir().unwrap();
        let release = dir.path().join("boundary.release");
        publish_release(&release, || {
            assert_eq!(
                std::fs::read(&release).unwrap_err().kind(),
                std::io::ErrorKind::NotFound
            );
        });
        assert_eq!(std::fs::read(&release).unwrap(), b"release\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&release).unwrap().permissions().mode() & 0o777, 0o644);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn verifier_release_publication_ignores_restrictive_umask() {
        use std::io::{Read, Seek, SeekFrom};
        use std::process::{Child, Stdio};
        struct OwnedChild(Child);
        impl Drop for OwnedChild {
            fn drop(&mut self) {
                loop {
                    match self.0.try_wait() {
                        Ok(Some(_)) => return,
                        Ok(None) => break,
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(error) => panic!("owned release child wait failed: {error}"),
                    }
                }
                self.0.kill().unwrap();
                loop {
                    match self.0.wait() {
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        result => { result.unwrap(); break; }
                    }
                }
            }
        }
        // File capture cannot block the child on a full pipe and keeps nested
        // libtest control lines out of this test's --nocapture CI stream.
        let mut stdout = tempfile::tempfile().unwrap();
        let mut stderr = tempfile::tempfile().unwrap();
        let mut child = OwnedChild(std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "helper::server::tests::verifier_parent::verifier_release_is_hidden_until_complete_publication",
                "--test-threads=1",
            ])
            .env("QSH_TEST_RELEASE_PRIVATE_UMASK", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout.try_clone().unwrap()))
            .stderr(Stdio::from(stderr.try_clone().unwrap()))
            .spawn()
            .unwrap());
        let deadline = Instant::now() + Duration::from_secs(3);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() { break status; }
            assert!(Instant::now() < deadline, "owned release child deadline");
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut output = Vec::new();
        stdout.seek(SeekFrom::Start(0)).unwrap();
        stdout.take(65537).read_to_end(&mut output).unwrap();
        let mut errors = Vec::new();
        stderr.seek(SeekFrom::Start(0)).unwrap();
        stderr.take(65537).read_to_end(&mut errors).unwrap();
        assert!(output.len() <= 65536 && errors.len() <= 65536, "release child output bound");
        assert!(status.success(), "release child status={status:?}, stdout={output:?}, stderr={errors:?}");
        assert!(errors.is_empty(), "release child stderr={errors:?}");
        let output = std::str::from_utf8(&output).unwrap();
        assert!(output.contains("test result: ok. 1 passed; 0 failed; 0 ignored;"), "release child result={output:?}");
    }

    #[test]
    fn verifier39_helper_death_kills_actual_blocked_lookup() {
        super::adoption_native::run_case(Some("verifier_lookup_death"));
    }

    fn credential_case(name: &str, mode: &str) {
        if !running_as_root() || std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref() != Ok("1") {
            eprintln!("SKIPPED {name}: requires disposable root credential fixture");
            return;
        }
        super::adoption_native::run_case(Some(mode));
    }

    #[test]
    fn verifier39_helper_death_kills_actual_switched_key_reader() {
        credential_case(
            "verifier39_helper_death_kills_actual_switched_key_reader",
            "verifier_credential_death",
        );
    }

    #[test]
    fn verifier39_helper_death_kills_verifier_after_identity_restoration() {
        credential_case(
            "verifier39_helper_death_kills_verifier_after_identity_restoration",
            "verifier_credential_restored_death",
        );
    }

    #[test]
    fn verifier39_parent_lost_before_initial_arm_cannot_enter_lookup() {
        credential_case(
            "verifier39_parent_lost_before_initial_arm_cannot_enter_lookup",
            "verifier_initial_race_death",
        );
    }

    #[test]
    fn verifier39_parent_lost_after_effective_gid_change_fails_closed() {
        credential_case(
            "verifier39_parent_lost_after_effective_gid_change_fails_closed",
            "verifier_credential_entry_gid_race_death",
        );
    }

    #[test]
    fn verifier39_parent_lost_after_effective_uid_change_fails_closed() {
        credential_case(
            "verifier39_parent_lost_after_effective_uid_change_fails_closed",
            "verifier_credential_entry_uid_race_death",
        );
    }

    #[test]
    fn verifier39_parent_lost_after_uid_restoration_fails_closed() {
        credential_case(
            "verifier39_parent_lost_after_uid_restoration_fails_closed",
            "verifier_credential_restore_uid_race_death",
        );
    }

    #[test]
    fn verifier39_parent_lost_after_gid_restoration_fails_closed() {
        credential_case(
            "verifier39_parent_lost_after_gid_restoration_fails_closed",
            "verifier_credential_restore_gid_race_death",
        );
    }

    #[test]
    fn verifier39_live_parent_allows_actual_signed_key_read_and_restoration() {
        credential_case(
            "verifier39_live_parent_allows_actual_signed_key_read_and_restoration",
            "verifier_credential_positive",
        );
    }

    #[test]
    fn verifier39_partial_identity_entry_restores_checked_parent_protection() {
        credential_case(
            "verifier39_partial_identity_entry_restores_checked_parent_protection",
            "verifier_credential_rollback",
        );
    }

    #[test]
    fn verifier39_identity_restoration_failure_is_terminal() {
        credential_case(
            "verifier39_identity_restoration_failure_is_terminal",
            "verifier_credential_restore_failure",
        );
    }

    #[test]
    fn verifier39_parent_signal_registration_failure_is_terminal() {
        credential_case(
            "verifier39_parent_signal_registration_failure_is_terminal",
            "verifier_registration_failure",
        );
    }

    #[test]
    fn verifier39_parent_signal_readback_failure_is_terminal() {
        credential_case(
            "verifier39_parent_signal_readback_failure_is_terminal",
            "verifier_readback_failure",
        );
    }

    fn mode() -> String {
        std::env::var("QSH_TEST_VERIFIER_MODE").unwrap()
    }
    fn death_signal() -> i32 {
        nix::sys::prctl::get_pdeathsig()
            .unwrap()
            .map_or(0, |signal| signal as i32)
    }
    fn record(path: &Path) {
        let pending = path.with_extension("pending");
        std::fs::write(
            &pending,
            format!(
                "{} {} {} {} {}\n",
                std::process::id(),
                Uid::effective(),
                Gid::effective(),
                death_signal(),
                nix::unistd::getppid()
            ),
        )
        .unwrap();
        std::fs::rename(pending, path).unwrap();
    }
    fn boundary_path() -> PathBuf {
        PathBuf::from(std::env::var_os("QSH_TEST_VERIFIER_MARKER").unwrap())
    }
    fn blocked_lookup(marker: &str) -> Result<Account, AccountError> {
        record(Path::new(marker));
        loop {
            unsafe { nix::libc::pause() };
        }
    }
    fn failing_identity_lookup(login: &str) -> Result<Account, AccountError> {
        let mut account = account::lookup(login)?;
        // setegid succeeds first; this invalid uid makes the actual seteuid
        // fail, exercising the partially-built guard's real Drop rollback.
        account.uid = Uid::from_raw(u32::MAX);
        Ok(account)
    }
    fn race_step(mode: &str) -> Option<Step> {
        if mode.contains("entry_gid_race") {
            Some(Step::EntryGroup)
        } else if mode.contains("entry_uid_race") {
            Some(Step::EntryUser)
        } else if mode.contains("restore_uid_race") {
            Some(Step::RestoreUser)
        } else if mode.contains("restore_gid_race") {
            Some(Step::RestoreGroup)
        } else {
            None
        }
    }
    fn trace(boundary: Boundary) {
        use std::io::Write;
        let path = boundary_path().with_extension("trace");
        writeln!(
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .unwrap(),
            "{boundary:?} uid={} gid={} pdeath={}",
            Uid::effective(),
            Gid::effective(),
            death_signal()
        )
        .unwrap();
    }
    fn deny_parent_prctl(option: i32) {
        // Child-local fault control: deny exactly one prctl operation using
        // kernel seccomp, retaining every other syscall and the real arm path.
        let mut filters = [
            nix::libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            nix::libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 3,
                k: nix::libc::SYS_prctl as u32,
            },
            nix::libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 16,
            },
            nix::libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: option as u32,
            },
            nix::libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x0005_0000 | nix::libc::EPERM as u32,
            },
            nix::libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: 0x7fff_0000,
            },
        ];
        let program = nix::libc::sock_fprog {
            len: filters.len() as u16,
            filter: filters.as_mut_ptr(),
        };
        assert_eq!(
            unsafe { nix::libc::prctl(nix::libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
            0
        );
        assert_eq!(
            unsafe { nix::libc::prctl(nix::libc::PR_SET_SECCOMP, 2, &program) },
            0
        );
    }
    fn observer(boundary: Boundary) {
        let mode = mode();
        if boundary == Boundary::BeforeInitialArm {
            if mode == "verifier_registration_failure" {
                deny_parent_prctl(nix::libc::PR_SET_PDEATHSIG);
                return;
            }
            if mode == "verifier_readback_failure" {
                deny_parent_prctl(nix::libc::PR_GET_PDEATHSIG);
                return;
            }
        }
        if mode.contains("positive") || mode.contains("rollback") {
            trace(boundary);
            match boundary {
                Boundary::BeforeInitialArm => assert_eq!(death_signal(), 0),
                Boundary::BeforeRearm(step) => assert_eq!(
                    death_signal(),
                    if mode.contains("rollback") && step == Step::RestoreUser {
                        nix::libc::SIGKILL
                    } else {
                        0
                    }
                ),
                _ => assert_eq!(death_signal(), nix::libc::SIGKILL),
            }
        }
        if mode == "verifier_credential_restore_failure" && boundary == Boundary::BeforeRestore {
            record(&boundary_path());
            let uid = Uid::effective();
            assert!(!uid.is_root());
            // Discard the saved root identity only in this deliberate failure
            // child. The guard's next real seteuid(root) must abort, not return.
            nix::unistd::setresuid(uid, uid, uid).unwrap();
            nix::sys::prctl::set_dumpable(false).unwrap();
            assert!(!nix::sys::prctl::get_dumpable().unwrap());
            return;
        }
        let gated = (mode == "verifier_initial_race_death"
            && boundary == Boundary::BeforeInitialArm)
            || race_step(&mode).is_some_and(|step| boundary == Boundary::BeforeRearm(step));
        let held = (mode == "verifier_credential_death" && boundary == Boundary::BeforeRead)
            || (mode == "verifier_credential_restored_death" && boundary == Boundary::Restored);
        if !gated && !held {
            return;
        }
        let marker = boundary_path();
        record(&marker);
        if held {
            loop {
                unsafe { nix::libc::pause() };
            }
        }
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match std::fs::read(marker.with_extension("release")) {
                Ok(bytes) => {
                    assert_eq!(bytes, b"release\n");
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("race gate read: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "owned parent-race gate not released"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    fn wait_completion(mut start: VerificationStart, mode: &str, dir: &Path) {
        let deadline = Instant::now() + Duration::from_secs(3);
        // Observe the exact native outcome without consuming it. Scope's final
        // code is normalized (exit or 128+signal), not a raw waitpid status.
        // The existing VerificationChild remains the sole consuming waiter.
        let mut native: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        loop {
            let rc = unsafe {
                nix::libc::waitid(
                    nix::libc::P_PID,
                    start.child.as_raw() as u32,
                    &mut native,
                    nix::libc::WEXITED
                        | nix::libc::WNOWAIT
                        | nix::libc::WNOHANG
                        | nix::libc::__WALL,
                )
            };
            if rc < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(nix::libc::EINTR)
                );
                continue;
            }
            if unsafe { native.si_pid() } != 0 {
                assert_eq!(unsafe { native.si_pid() }, start.child.as_raw());
                break;
            }
            assert!(
                Instant::now() < deadline,
                "native verifier failed to exit before custody drainage"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        let native_status = unsafe { native.si_status() };
        let mut result = None;
        let status = loop {
            let progress = start.custody.poll(&start.report, false, Instant::now());
            assert!(progress.signal_failure.is_none());
            if progress.result.is_some() {
                result = progress.result;
            }
            if let crate::process_scope::scope::Progress::Complete(status) = progress.cleanup {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "real verifier custody failed to settle"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        let verdict = result
            .as_ref()
            .and_then(|result| result.as_ref().ok())
            .and_then(|bytes| decode_verdict(bytes));
        if mode == "verifier_credential_positive" {
            assert_eq!(status, 0);
            assert_eq!((native.si_code, native_status), (nix::libc::CLD_EXITED, 0));
            assert!(
                matches!(verdict, Some(Verdict::Admitted { account, .. }) if account.name == "nobody" && !account.uid.is_root())
            );
            let trace = std::fs::read_to_string(dir.join("account/boundary.trace")).unwrap();
            for step in [
                "GroupsInstalled",
                "BeforeRead",
                "Restored",
                "EntryGroup",
                "EntryUser",
                "RestoreUser",
                "RestoreGroup",
            ] {
                assert!(
                    trace.contains(step),
                    "missing actual transition {step}: {trace}"
                );
            }
            let account = account::lookup("nobody").unwrap();
            assert!(trace.contains(&format!(
                "BeforeRead uid={} gid={} pdeath=9",
                account.uid, account.gid
            )));
            assert!(trace.contains("Restored uid=0 gid=0 pdeath=9"));
        } else if mode == "verifier_credential_rollback" {
            assert_eq!(status, 0);
            assert_eq!((native.si_code, native_status), (nix::libc::CLD_EXITED, 0));
            assert!(matches!(verdict, Some(Verdict::Refused { .. })));
            let trace = std::fs::read_to_string(dir.join("account/boundary.trace")).unwrap();
            assert!(trace.contains("Restored uid=0 gid=0 pdeath=9"));
            assert!(
                !trace.contains("BeforeRead"),
                "failed entry must never read keys"
            );
        } else if mode == "verifier_credential_restore_failure" {
            assert_eq!(status, 128 + nix::libc::SIGABRT);
            assert!(matches!(
                native.si_code,
                nix::libc::CLD_KILLED | nix::libc::CLD_DUMPED
            ));
            assert_eq!(native_status, nix::libc::SIGABRT);
            assert!(
                verdict.is_none(),
                "failed restoration must never return a verdict"
            );
        } else {
            assert!(matches!(
                mode,
                "verifier_registration_failure" | "verifier_readback_failure"
            ));
            assert_eq!(status, 127);
            assert_eq!(
                (native.si_code, native_status),
                (nix::libc::CLD_EXITED, 127)
            );
            assert!(
                verdict.is_none(),
                "failed registration must never return a verdict"
            );
            assert!(!dir.join("actual-verifier-lookup").exists());
        }
        std::fs::write(dir.join("helper-result"), format!("mode={mode}, native_code={}, native_status={native_status}, custody_status={status}, actual_verdict_checked=true, exact_custody_complete=true", native.si_code)).unwrap();
    }
    pub(super) fn helper_body(dir: &Path, control: UnixStream, mode: &str) {
        // This private child alone deliberately exercises abort. Also mark the
        // failing verifier nondumpable immediately before its failed restore.
        let core_limit = nix::libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        assert_eq!(
            unsafe { nix::libc::setrlimit(nix::libc::RLIMIT_CORE, &core_limit) },
            0
        );
        std::env::set_var("QSH_TEST_VERIFIER_MODE", mode);
        let credential = mode.starts_with("verifier_credential");
        let marker = if credential {
            dir.join("account/boundary")
        } else {
            dir.join("boundary")
        };
        std::env::set_var("QSH_TEST_VERIFIER_MARKER", &marker);
        let start = if credential {
            use std::os::unix::fs::PermissionsExt;
            let account = account::lookup("nobody").unwrap();
            assert!(!account.uid.is_root());
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).unwrap();
            let home = dir.join("account");
            std::fs::create_dir(&home).unwrap();
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            nix::unistd::chown(&home, Some(account.uid), Some(account.gid)).unwrap();
            let trace = home.join("boundary.trace");
            std::fs::write(&trace, b"").unwrap();
            std::fs::set_permissions(&trace, std::fs::Permissions::from_mode(0o600)).unwrap();
            nix::unistd::chown(&trace, Some(account.uid), Some(account.gid)).unwrap();
            let key = PrivateKey::random(
                &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
                Algorithm::Ed25519,
            )
            .unwrap();
            let config = HelperConfig {
                verify_timeout: Duration::from_secs(30),
                ..trusting_config(&home, &key)
            };
            nix::unistd::chown(
                &home.join("authorized_keys"),
                Some(account.uid),
                Some(account.gid),
            )
            .unwrap();
            let Request::Verify {
                login,
                public_key,
                signature,
                handshake_hash,
                nonce,
                ..
            } = proof(&key, "nobody", [7; 32], [5; AUTH_NONCE_LEN])
            else {
                unreachable!()
            };
            fork_verification(
                &login,
                &public_key,
                &signature,
                &handshake_hash,
                &nonce,
                &config,
                AccountSwitches {
                    lookup: if mode.contains("rollback") {
                        failing_identity_lookup
                    } else {
                        account::lookup
                    },
                    verifier_observer: observer,
                    ..AccountSwitches::REAL
                },
                None,
            )
            .unwrap()
        } else {
            let config = HelperConfig {
                verify_timeout: Duration::from_secs(30),
                ..test_config()
            };
            fork_verification(
                dir.join("actual-verifier-lookup").to_str().unwrap(),
                &[],
                &[],
                &[0; 32],
                &[0; AUTH_NONCE_LEN],
                &config,
                AccountSwitches {
                    lookup: blocked_lookup,
                    verifier_observer: observer,
                    ..UNPRIVILEGED
                },
                None,
            )
            .unwrap()
        };
        channel::send(&control, start.child.to_string().as_bytes(), None).unwrap();
        if mode.ends_with("_death") {
            // Retain real parent-side custody intact until deliberate helper kill.
            loop {
                unsafe { nix::libc::pause() };
            }
        }
        // Do not consume the exact child identity before the supervisor pins it.
        control
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        assert_eq!(channel::recv(&control).unwrap().unwrap().0, b"pinned");
        wait_completion(start, mode, dir);
        channel::send(&control, b"done", None).unwrap();
    }
    fn wait_exited(pin: &Pin, what: &str) {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !pin.exited() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(pin.exited(), "{what}");
    }
    pub(super) fn drive(
        control: &UnixStream,
        dir: &Path,
        helper: &Pin,
        helper_pid: i32,
        mode: &str,
    ) -> Vec<Pin> {
        control
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let report = channel::recv(control).unwrap().unwrap();
        let pid: i32 = std::str::from_utf8(&report.0).unwrap().parse().unwrap();
        let verifier = Pin::new(pid);
        if !mode.ends_with("_death") {
            channel::send(control, b"pinned", None).unwrap();
            assert_eq!(channel::recv(control).unwrap().unwrap().0, b"done");
            assert!(verifier.exited());
            return vec![verifier];
        }
        let marker = if mode.starts_with("verifier_credential") {
            dir.join("account/boundary")
        } else if mode == "verifier_initial_race_death" {
            dir.join("boundary")
        } else {
            dir.join("actual-verifier-lookup")
        };
        let deadline = Instant::now() + Duration::from_secs(3);
        let observation = loop {
            match std::fs::read_to_string(&marker) {
                Ok(text) if text.ends_with('\n') && text.split_whitespace().count() == 5 => {
                    break text
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("read actual verifier boundary: {error}"),
            }
            assert!(
                Instant::now() < deadline,
                "actual verifier boundary never entered: {mode}"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        let fields: Vec<_> = observation
            .split_whitespace()
            .map(|n| n.parse::<i32>().unwrap())
            .collect();
        assert_eq!(fields[0], pid);
        assert_eq!(fields[4], helper_pid);
        if mode == "verifier_credential_death" {
            let account = account::lookup("nobody").unwrap();
            assert_eq!(fields[1], account.uid.as_raw() as i32);
            assert_eq!(fields[2], account.gid.as_raw() as i32);
        }
        if mode == "verifier_credential_restored_death" {
            assert_eq!(&fields[1..3], &[0, 0]);
        }
        let race = mode.contains("race");
        assert_eq!(fields[3], if race { 0 } else { nix::libc::SIGKILL });
        assert!(!verifier.exited());
        helper.signal_kill();
        wait_exited(helper, "owned helper did not finish its actual SIGKILL");
        if race {
            publish_release(&marker.with_extension("release"), || {});
        }
        wait_exited(&verifier, &format!("actual verifier survived helper death before fixture rescue: mode={mode}, observed={observation:?}"));
        let fd = verifier.as_fd();
        let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        for flags in [
            nix::libc::WEXITED | nix::libc::WNOWAIT | nix::libc::__WALL,
            nix::libc::WEXITED | nix::libc::__WALL,
        ] {
            loop {
                let rc = unsafe {
                    nix::libc::waitid(nix::libc::P_PIDFD, fd.as_raw_fd() as u32, &mut info, flags)
                };
                if rc == 0 {
                    break;
                }
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(nix::libc::EINTR)
                );
            }
            assert_eq!(unsafe { info.si_pid() }, pid);
            assert_eq!(
                info.si_code,
                if race {
                    nix::libc::CLD_EXITED
                } else {
                    nix::libc::CLD_KILLED
                }
            );
            assert_eq!(
                unsafe { info.si_status() },
                if race { 127 } else { nix::libc::SIGKILL }
            );
        }
        if mode == "verifier_initial_race_death" {
            assert!(!dir.join("actual-verifier-lookup").exists());
        }
        std::fs::write(dir.join("helper-result"), format!("mode={mode}, exact_native_wait=true, observed={observation:?}, native_code={}, native_status={}", info.si_code, unsafe { info.si_status() })).unwrap();
        vec![verifier]
    }
}
