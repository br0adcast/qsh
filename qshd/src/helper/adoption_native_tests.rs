// Isolated native adoption qualification; never enables subreaping in libtest.
#[cfg(target_os = "linux")]
mod adoption_native {
    use super::*;
    use crate::process_scope::adoption::{
        native::NativeOps, Progress, Reservation, RootState, Roots,
    };
    use std::{
        os::fd::{AsRawFd, FromRawFd},
        process::{Command, Stdio},
    };

    const BODY: &str = "helper::server::tests::adoption_native::adoption40_owned_runtime_body";
    const MODE: &str = "QSH_TEST_ADOPTION_MODE";
    const REPORT: &str = "QSH_TEST_ADOPTION_REPORT";

    pub(super) struct Pin(OwnedFd);
    impl Pin {
        pub(super) fn new(pid: i32) -> Self {
            let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid, 0) };
            assert!(fd >= 0, "owned runtime fixture requires pidfd_open");
            Self(unsafe { OwnedFd::from_raw_fd(fd as i32) })
        }
        pub(super) fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
            self.0.as_fd()
        }
        pub(super) fn exited(&self) -> bool {
            let mut poll = nix::libc::pollfd {
                fd: self.0.as_raw_fd(),
                events: nix::libc::POLLIN,
                revents: 0,
            };
            let result = unsafe { nix::libc::poll(&mut poll, 1, 0) };
            if result < 0 {
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(nix::libc::EINTR)
                );
                return false;
            }
            poll.revents & nix::libc::POLLIN != 0
        }
        pub(super) fn signal(&self, signal: i32) {
            let result = unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_pidfd_send_signal,
                    self.0.as_raw_fd(),
                    signal,
                    std::ptr::null::<nix::libc::siginfo_t>(),
                    0,
                )
            };
            assert!(
                result == 0
                    || std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::ESRCH)
            );
        }
        pub(super) fn signal_kill(&self) {
            self.signal(nix::libc::SIGKILL);
        }
        fn settle(&self) {
            if !self.exited() {
                self.signal_kill();
            }
            loop {
                let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
                let rc = unsafe {
                    nix::libc::waitid(
                        nix::libc::P_PIDFD,
                        self.0.as_raw_fd() as u32,
                        &mut info,
                        nix::libc::WEXITED | nix::libc::__WALL,
                    )
                };
                if rc == 0 {
                    break;
                }
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(nix::libc::EINTR) => continue,
                    Some(nix::libc::ECHILD) if self.exited() => break,
                    e => panic!("exact owned fixture wait failed: {e:?}"),
                }
            }
        }
    }
    fn preflight_fixture_apis() {
        // These test-only APIs are stricter than production proc-dirfd custody.
        // Qualify all of them before any fixture process is created.
        let pin = Pin::new(std::process::id() as i32);
        assert_eq!(
            unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_pidfd_send_signal,
                    pin.0.as_raw_fd(),
                    0,
                    std::ptr::null::<nix::libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
        let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                nix::libc::waitid(
                    nix::libc::P_PIDFD,
                    pin.0.as_raw_fd() as u32,
                    &mut info,
                    nix::libc::WEXITED
                        | nix::libc::WNOWAIT
                        | nix::libc::WNOHANG
                        | nix::libc::__WALL,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::ECHILD)
        );
    }
    fn cleanup_owned_children() -> usize {
        let mut adopted = 0;
        loop {
            // Every child in this dedicated subreaper belongs to this fixture.
            // The ordinary libtest process never enables or runs this sweep.
            let mut children = std::collections::BTreeSet::new();
            for entry in std::fs::read_dir("/proc/self/task").unwrap() {
                let text = std::fs::read_to_string(entry.unwrap().path().join("children")).unwrap();
                children.extend(text.split_whitespace().map(|p| p.parse::<i32>().unwrap()));
            }
            if children.is_empty() {
                return adopted;
            }
            for pid in children {
                Pin::new(pid).settle();
                adopted += 1;
            }
        }
    }
    struct OwnedCleanup;
    impl Drop for OwnedCleanup {
        fn drop(&mut self) {
            cleanup_owned_children();
        }
    }
    fn command(mode: &str) -> Command {
        let mut cmd = Command::new(std::env::current_exe().unwrap());
        cmd.args(["--exact", BODY, "--ignored", "--test-threads=1"])
            .env(MODE, mode)
            .env("QSH_TEST_ADOPTION_PARENT", std::process::id().to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        cmd
    }
    #[test]
    fn adoption40_real_escaped_pam_exec_and_nested_session_are_joined() {
        run_case(None);
    }
    pub(super) fn run_case(scenario: Option<&str>) {
        preflight_fixture_apis();
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report");
        let mut supervisor = command("supervisor");
        supervisor.env(REPORT, &report);
        if let Some(mode) = scenario {
            supervisor.env("QSH_TEST_ADOPTION_SCENARIO", mode);
        } else {
            supervisor.env_remove("QSH_TEST_ADOPTION_SCENARIO");
        }
        let status = supervisor.status().unwrap();
        let evidence = std::fs::read_to_string(report).unwrap();
        assert!(evidence.len() <= 4096, "bounded owned fixture evidence");
        eprintln!("adoption40 owned evidence: {evidence:?}");
        assert!(
            status.success(),
            "owned adoption fixture failed: {evidence:?}"
        );
        assert!(
            evidence.contains("case_success=true") && evidence.contains("no_children=true"),
            "{evidence:?}"
        );
        if scenario == Some("legacy_helper_death")
            || scenario
                .is_some_and(|mode| mode.starts_with("verifier_") && mode.ends_with("_death"))
        {
            assert!(
                evidence.contains("helper_success=false")
                    && evidence.contains("helper_killed=true"),
                "{evidence:?}"
            );
        } else {
            assert!(evidence.contains("helper_success=true"), "{evidence:?}");
        }
    }
    #[test]
    #[ignore = "owned subprocess body; outer fixture supervises and reaps"]
    fn adoption40_owned_runtime_body() {
        assert_eq!(std::env::var(MODE).unwrap(), "supervisor");
        assert_eq!(
            std::env::var("QSH_TEST_ADOPTION_PARENT")
                .unwrap()
                .parse::<i32>()
                .unwrap(),
            unsafe { nix::libc::getppid() }
        );
        assert_eq!(
            unsafe { nix::libc::prctl(nix::libc::PR_SET_CHILD_SUBREAPER, 1) },
            0
        );
        let dir = if std::env::var("QSH_TEST_ADOPTION_SCENARIO")
            .is_ok_and(|mode| mode.starts_with("verifier_credential"))
        {
            assert!(running_as_root());
            assert_eq!(
                std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref(),
                Ok("1")
            );
            // Protected authorized_keys traversal must not pass through /tmp.
            tempfile::Builder::new()
                .prefix("qshd-test-verifier-")
                .tempdir_in("/run")
                .unwrap()
        } else {
            tempfile::tempdir().unwrap()
        };
        // This guard precedes all child creation and outlives their resources.
        let _cleanup = OwnedCleanup;
        // Sibling is owned by this supervisor, outside the helper's child domain.
        let outsider = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let outsider_pin = Pin::new(outsider.id() as i32);
        let (control, child_control) = channel::pair().unwrap();
        let child = unsafe { nix::unistd::fork() }.unwrap();
        let pid = match child {
            nix::unistd::ForkResult::Child => {
                drop(control);
                let result = std::panic::catch_unwind(|| {
                    if let Ok(mode) = std::env::var("QSH_TEST_ADOPTION_SCENARIO") {
                        if mode.starts_with("verifier_") {
                            super::verifier_parent::helper_body(dir.path(), child_control, &mode);
                        } else if mode.starts_with("signal_") {
                            super::owned_signal::helper_body(dir.path(), child_control, &mode);
                        } else if mode == "required_reply_cleanup" {
                            super::required_reply::helper_body(dir.path(), child_control);
                        } else if mode.starts_with("legacy_") {
                            super::adoption_legacy::helper_body(dir.path(), child_control, &mode);
                        } else {
                            super::adoption_pump::helper_body(dir.path(), child_control, &mode);
                        }
                    } else {
                        drop(child_control);
                        helper_body(dir.path());
                    }
                });
                let code = if let Err(cause) = result {
                    let message = cause
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| cause.downcast_ref::<&str>().copied())
                        .unwrap_or("non-string helper panic");
                    let bounded: String = message.chars().take(512).collect();
                    let _ = std::fs::write(
                        dir.path().join("helper-result"),
                        format!("helper_failure={bounded:?}"),
                    );
                    101
                } else {
                    0
                };
                unsafe { nix::libc::_exit(code) };
            }
            nix::unistd::ForkResult::Parent { child } => child.as_raw(),
        };
        drop(child_control);
        let helper = Pin::new(pid);
        let setup_started = Instant::now();
        let pam_only = std::env::var("QSH_TEST_ADOPTION_SCENARIO").as_deref() == Ok("pam_only");
        // PAM-only close legitimately permits 4s x two deadline firings. Its
        // setup and final physical drainage cannot share the old 10s budget.
        // Keep a finite owned outer fence, independent of all success evidence.
        let hard_deadline = setup_started + Duration::from_secs(if pam_only { 20 } else { 10 });
        let driven = if let Ok(mode) = std::env::var("QSH_TEST_ADOPTION_SCENARIO") {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if mode.starts_with("verifier_") {
                    super::verifier_parent::drive(&control, dir.path(), &helper, pid, &mode)
                } else if mode.starts_with("signal_") {
                    super::owned_signal::drive(&control, &helper, &mode)
                } else if mode == "required_reply_cleanup" {
                    super::required_reply::drive(&control)
                } else if mode.starts_with("legacy_") {
                    super::adoption_legacy::drive(&control, dir.path(), &helper, pid, &mode)
                } else {
                    super::adoption_pump::drive(&control, dir.path(), &helper, pid, &mode)
                }
            }))
        } else {
            Ok(Vec::new())
        };
        let (observed, driver_failure) = match driven {
            Ok(observed) => (observed, None),
            Err(cause) => {
                let message = cause
                    .downcast_ref::<String>()
                    .map(String::as_str)
                    .or_else(|| cause.downcast_ref::<&str>().copied())
                    .unwrap_or("non-string driver panic");
                (
                    Vec::new(),
                    Some(message.chars().take(512).collect::<String>()),
                )
            }
        };
        let setup_elapsed = setup_started.elapsed();
        let drain_started = Instant::now();
        // Keep the absolute fence established before setup; PAM-only already
        // reserves time there for PAM escalation and final physical drainage.
        let deadline = hard_deadline;
        drop(control);
        while driver_failure.is_none() && !helper.exited() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        let timed_out = driver_failure.is_none() && !helper.exited();
        let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = if !timed_out && helper.exited() {
            unsafe {
                nix::libc::waitid(
                    nix::libc::P_PIDFD,
                    helper.0.as_raw_fd() as u32,
                    &mut info,
                    nix::libc::WEXITED | nix::libc::WNOWAIT | nix::libc::__WALL,
                )
            }
        } else {
            -1
        };
        let helper_success = driver_failure.is_none()
            && !timed_out
            && result == 0
            && info.si_code == nix::libc::CLD_EXITED
            && unsafe { info.si_status() } == 0;
        let helper_killed = result == 0
            && info.si_code == nix::libc::CLD_KILLED
            && unsafe { info.si_status() } == nix::libc::SIGKILL;
        let expected_helper_death = std::env::var("QSH_TEST_ADOPTION_SCENARIO").is_ok_and(|mode| {
            mode == "legacy_helper_death"
                || (mode.starts_with("verifier_") && mode.ends_with("_death"))
        });
        let outsider_untouched = !outsider_pin.exited();
        let observed_exited = observed.iter().all(Pin::exited);
        let case_success = driver_failure.is_none()
            && !timed_out
            && outsider_untouched
            && observed_exited
            && if expected_helper_death {
                helper_killed
            } else {
                helper_success
            };
        helper.settle();
        outsider_pin.settle();
        drop(outsider);
        let adopted = cleanup_owned_children();
        let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                nix::libc::waitid(
                    nix::libc::P_ALL,
                    0,
                    &mut info,
                    nix::libc::WEXITED
                        | nix::libc::WNOWAIT
                        | nix::libc::WNOHANG
                        | nix::libc::__WALL,
                )
            },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(nix::libc::ECHILD)
        );
        let details = std::fs::read_to_string(dir.path().join("helper-result"))
            .unwrap_or_else(|_| "helper produced no success receipt".into());
        let evidence = format!("case_success={case_success}, timed_out={timed_out}, helper_success={helper_success}, helper_killed={helper_killed}, outsider_untouched={outsider_untouched}, observed_exited={observed_exited}, adopted_reaped={adopted}, no_children=true, driver_failure={driver_failure:?}, setup_elapsed={setup_elapsed:?}, drain_elapsed={:?}, phase=post_driver_drain, details={details:?}", drain_started.elapsed());
        std::fs::write(std::env::var_os(REPORT).unwrap(), &evidence).unwrap();
        assert!(case_success, "{evidence}");
    }
    struct MonitorRoots {
        pid: u32,
        state: RootState,
    }
    impl Roots for MonitorRoots {
        fn classify(&mut self, pid: u32) -> Reservation {
            if self.state == RootState::Unknown {
                Reservation::Unknown
            } else if self.state == RootState::Active && self.pid == pid {
                Reservation::Reserved
            } else {
                Reservation::Other
            }
        }
        fn state(&self) -> RootState {
            self.state
        }
    }
    fn helper_body(dir: &Path) {
        let mut flag = -1;
        assert_eq!(
            unsafe { nix::libc::prctl(nix::libc::PR_GET_CHILD_SUBREAPER, &mut flag) },
            0
        );
        assert_eq!(flag, 0, "subreaper attribute is not inherited across fork");
        let (mut adoption, mut ops) =
            NativeOps::prepare().expect("single-thread owned helper qualification");
        let marker = dir.join("escaped-jobs");
        let fifo = dir.join("barrier");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let script = dir.join("pam.sh");
        write_script(&script, &format!("exec /bin/bash -c 'trap \"\" HUP; /usr/bin/setsid /bin/sleep 60 & member=$!; printf \"%s %s %s adoption-native-40\\n\" \"$$\" \"$member\" \"$PPID\" > \"{}\"; IFS= read -r unused < \"{}\"'", marker.display(), fifo.display()));
        write_stack(dir, "qshd-adoption", &format!("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_exec.so {}\nsession required pam_permit.so\n", script.display()));
        let plan = MonitorPlan {
            #[cfg(target_os = "linux")]
            child_mask: None,
            account: my_account(),
            login: [40; 16],
            tty: "/dev/pts/0".into(),
            rhost: PROOF_RHOST.into(),
            pam_service: "qshd-adoption".into(),
            pam_confdir: Some(dir.to_path_buf()),
            become_account: UNPRIVILEGED.become_account,
            session_group_ops: UNPRIVILEGED.session_group_ops,
            fd_limit: max_open_descriptors(),
            session_budget: Duration::from_secs(30),
            session_close_budget: Duration::from_secs(2),
        };
        let login = plan.login;
        let mut state = state_with_login(&plan.account, login);
        let owner = owner_for(&state, login);
        let monitor = fork_monitor(plan).unwrap();
        let pid = monitor.pid.as_raw();
        let monitor_pin = Pin::new(pid);
        state.monitors.insert(owner, monitor);
        let seams = DirectSeam::new();
        let pty = nix::pty::openpty(None, None).unwrap();
        channel::send(
            state.monitors[&owner].seam(),
            &encode(&MonitorRequest::Open {
                id: 4040,
                term: None,
                shell: false,
                command: "/bin/true".into(),
            })
            .unwrap(),
            Some(pty.slave.as_fd()),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        let ids = loop {
            serve_ready_monitors(seams.seams(), &mut state, &[]);
            if let Ok(text) = std::fs::read_to_string(&marker) {
                let fields: Vec<_> = text.split_whitespace().collect();
                if text.ends_with('\n') && fields.len() == 4 && fields[3] == "adoption-native-40" {
                    break fields[..3]
                        .iter()
                        .map(|p| p.parse::<i32>().unwrap())
                        .collect::<Vec<_>>();
                }
            }
            assert!(
                Instant::now() < deadline,
                "real private PAM did not reach barrier"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        let script_pin = Pin::new(ids[0]);
        let member_pin = Pin::new(ids[1]);
        while std::fs::read_link(format!("/proc/{}/exe", ids[1]))
            .ok()
            .and_then(|p| p.file_name().map(|n| n == "sleep"))
            != Some(true)
        {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(1));
        }
        let parent_of = |pid| {
            let bytes = std::fs::read(format!("/proc/{pid}/status")).unwrap();
            let text = std::str::from_utf8(&bytes).unwrap();
            text.lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .unwrap()
                .trim()
                .parse::<i32>()
                .unwrap()
        };
        assert_eq!(parent_of(ids[0]), ids[2]);
        assert_eq!(parent_of(ids[1]), ids[0]);
        let mut ancestors = Vec::new();
        let mut ancestor = ids[2];
        while ancestor != pid {
            assert!(ancestors.len() < 8, "unexpected owned private PAM ancestry");
            let pin = Pin::new(ancestor);
            let parent = parent_of(ancestor);
            assert!(!pin.exited());
            ancestors.push(pin);
            ancestor = parent;
        }
        assert_ne!(
            unsafe { nix::libc::getsid(ids[0]) },
            pid,
            "real pam_exec starts a separate session"
        );
        assert_ne!(
            unsafe { nix::libc::getsid(ids[1]) },
            unsafe { nix::libc::getsid(ids[0]) },
            "nested setsid member is separate again"
        );
        let mut roots = MonitorRoots {
            pid: pid as u32,
            state: RootState::Active,
        };
        assert_eq!(adoption.step(&mut ops, &mut roots), Progress::Pending);
        assert!(
            !monitor_pin.exited(),
            "live registered root must not be stolen by adoption"
        );
        if std::env::var_os("QSH_TEST_ADOPTION_HOLD").is_some() {
            loop {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        lose_monitor(
            &seams.helper,
            &mut state,
            owner,
            "owned escaped-PAM adoption qualification",
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while !state.monitors[&owner].reaped {
            serve_ready_monitors(seams.seams(), &mut state, &[]);
            reap_owned_monitors(&seams.helper, &mut state);
            assert!(
                Instant::now() < deadline,
                "monitor native scope did not finish"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!state.monitors[&owner].wait_lost);
        assert!(
            !script_pin.exited() && !member_pin.exited(),
            "separate sessions survive the monitor's same-SID drain"
        );
        roots.state = RootState::Settled; // Actual native completion above, not a fabricated receipt.
        loop {
            match adoption.step(&mut ops, &mut roots) {
                Progress::Complete => break,
                Progress::Unknown => panic!("native adoption lost qualified evidence"),
                Progress::Pending => {}
            }
            assert!(
                Instant::now() < deadline,
                "finite escaped PAM jobs did not settle"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!adoption.failed());
        assert!(monitor_pin.exited() && script_pin.exited() && member_pin.exited());
        assert!(
            state.monitors[&owner].completion.is_none(),
            "physical proof does not synthesize PAM completion"
        );
        assert!(
            state.retired.contains(&owner),
            "component proof does not refund logical admission"
        );
        std::fs::write(dir.join("helper-result"), "qualified=true, native_root=true, escaped_pam=true, nested_setsid=true, joined=true, no_synthetic_pam=true, retired_debt=true").unwrap();
    }
}
