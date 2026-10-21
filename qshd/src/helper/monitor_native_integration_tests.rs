// Real monitor fixtures use only private PAM stacks and exact native identities.
#[cfg(target_os = "linux")]
mod monitor_native_integration {
    use super::*;
    use std::os::fd::{AsRawFd, FromRawFd};

    fn qualify_fixture_pidfds() {
        // Test-only pidfd_open is stricter than the production proc-dirfd API.
        // Reject unavailable fixture APIs before creating any owned process.
        let raw = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, std::process::id(), 0) };
        assert!(
            raw >= 0,
            "fixture pidfd_open unavailable before child creation"
        );
        let fd = unsafe { OwnedFd::from_raw_fd(raw as i32) };
        assert_eq!(
            unsafe {
                nix::libc::syscall(
                    nix::libc::SYS_pidfd_send_signal,
                    fd.as_raw_fd(),
                    0,
                    std::ptr::null::<nix::libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
    }

    struct Pin {
        fd: OwnedFd,
        settled: bool,
    }
    impl Pin {
        fn new(pid: Pid) -> Self {
            let fd = unsafe { nix::libc::syscall(nix::libc::SYS_pidfd_open, pid.as_raw(), 0) };
            assert!(fd >= 0, "pin the exclusively owned fixture process");
            Self {
                fd: unsafe { OwnedFd::from_raw_fd(fd as i32) },
                settled: false,
            }
        }
        fn exited(&self) -> bool {
            let mut poll = nix::libc::pollfd {
                fd: self.fd.as_raw_fd(),
                events: nix::libc::POLLIN,
                revents: 0,
            };
            loop {
                let result = unsafe { nix::libc::poll(&mut poll, 1, 0) };
                if result >= 0 {
                    return poll.revents & nix::libc::POLLIN != 0;
                }
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(nix::libc::EINTR)
                );
            }
        }
        fn settle(&mut self) {
            if self.settled {
                return;
            }
            if !self.exited() {
                let result = unsafe {
                    nix::libc::syscall(
                        nix::libc::SYS_pidfd_send_signal,
                        self.fd.as_raw_fd(),
                        nix::libc::SIGKILL,
                        std::ptr::null::<nix::libc::siginfo_t>(),
                        0,
                    )
                };
                assert!(
                    result == 0
                        || std::io::Error::last_os_error().raw_os_error() == Some(nix::libc::ESRCH)
                );
            }
            while !self.exited() {
                std::thread::sleep(Duration::from_millis(1));
            }
            loop {
                let mut info: nix::libc::siginfo_t = unsafe { std::mem::zeroed() };
                let result = unsafe {
                    nix::libc::waitid(
                        nix::libc::P_PIDFD,
                        self.fd.as_raw_fd() as u32,
                        &mut info,
                        nix::libc::WEXITED,
                    )
                };
                if result == 0 {
                    break;
                }
                match std::io::Error::last_os_error().raw_os_error() {
                    Some(nix::libc::EINTR) => continue,
                    Some(nix::libc::ECHILD) if self.exited() => break,
                    error => panic!("exact owned fixture wait failed: {error:?}"),
                }
            }
            self.settled = true;
        }
    }
    impl Drop for Pin {
        fn drop(&mut self) {
            self.settle();
        }
    }

    fn empty_monitor_plan() -> MonitorPlan {
        let config = test_config();
        MonitorPlan {
            account: my_account(),
            login: [40; 16],
            tty: "/dev/pts/0".into(),
            rhost: PROOF_RHOST.into(),
            pam_service: config.pam_service,
            pam_confdir: config.pam_confdir,
            become_account: UNPRIVILEGED.become_account,
            session_group_ops: UNPRIVILEGED.session_group_ops,
            fd_limit: max_open_descriptors(),
            session_budget: Duration::from_secs(2),
            session_close_budget: Duration::from_secs(2),
        }
    }
    #[test]
    fn monitor40_real_monitor_emits_private_session_stage_before_any_open() {
        qualify_fixture_pidfds();
        let monitor = fork_monitor(empty_monitor_plan()).unwrap();
        let pid = monitor.pid;
        let mut pin = Pin::new(pid);
        monitor
            .seam()
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let first = channel::recv_once(monitor.seam());
        // This producer-only control deliberately consumes the private record
        // outside the native reader. Fixture cleanup retains exact custody and
        // does not claim a product native-completion receipt.
        monitor.seam().shutdown(std::net::Shutdown::Write).unwrap();
        pin.settle();
        drop(monitor);
        let first = first.unwrap();
        assert!(
            matches!(first, Some((bytes, None)) if matches!(decode::<MonitorEvent>(&bytes),
            Ok(MonitorEvent::SessionEstablished { sid }) if sid == pid.as_raw() as u32))
        );
    }
    #[test]
    fn monitor40_credentialed_open_preserves_its_owned_terminal_fd() {
        use std::os::fd::AsFd;
        let (helper, monitor) = super::super::super::worker_control::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        channel::send(&helper, b"open", Some(file.as_fd())).unwrap();
        let received = channel::recv_once(&monitor).unwrap().unwrap();
        assert_eq!(received.0, b"open");
        assert!(
            received.1.is_some(),
            "SO_PASSCRED must not truncate the terminal fd"
        );
    }

    const FORCE_MODE: &str = "QSH_TEST_MONITOR_FORCE_MODE";
    const FORCE_PARENT: &str = "QSH_TEST_MONITOR_FORCE_PARENT";
    const FORCE_REPORT: &str = "QSH_TEST_MONITOR_FORCE_REPORT";
    const FORCE_TEST: &str =
        "helper::server::tests::monitor_native_integration::monitor40_force_owned_body";

    fn force_command(mode: &str) -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", FORCE_TEST, "--ignored", "--test-threads=1"])
            .env(FORCE_MODE, mode)
            .env(FORCE_PARENT, std::process::id().to_string())
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        command
    }

    #[test]
    fn monitor40_force_joins_real_pam_same_sid_jobs_without_touching_outsider() {
        qualify_fixture_pidfds();
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report");
        let status = force_command("supervisor")
            .env(FORCE_REPORT, &report)
            .status()
            .unwrap();
        let report = std::fs::read_to_string(report).unwrap();
        assert!(status.success(), "owned native-monitor control: {report}");
        assert!(
            report.contains("body_success=true") && report.contains("no_children=true"),
            "{report}"
        );
    }

    #[test]
    #[ignore = "runs only in the exact owned monitor-force subprocess"]
    fn monitor40_force_owned_body() {
        use std::process::{Command, Stdio};
        assert_eq!(
            std::env::var(FORCE_PARENT).unwrap().parse::<i32>().unwrap(),
            unsafe { nix::libc::getppid() }
        );
        assert_eq!(
            unsafe { nix::libc::prctl(nix::libc::PR_SET_CHILD_SUBREAPER, 1) },
            0
        );
        if std::env::var(FORCE_MODE).unwrap() == "supervisor" {
            let mut body = force_command("body").spawn().unwrap();
            let mut pin = Pin::new(Pid::from_raw(body.id() as i32));
            let deadline = Instant::now() + Duration::from_secs(10);
            while !pin.exited() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(2));
            }
            let timed_out = !pin.exited();
            // The body is held by its exact pidfd; only its exclusively owned
            // finite fixture descendants can be adopted by this fresh process.
            if timed_out {
                pin.settle();
            }
            // Timeout cleanup consumed the exact pidfd wait; Child::wait may
            // then return ECHILD. It cannot turn that failed control into success.
            let body_status = body.wait();
            let body_success = !timed_out && body_status.is_ok_and(|status| status.success());
            pin.settle();
            let mut adopted = 0;
            loop {
                // Direct children remain unreaped, so their IDs cannot recycle
                // before pidfd capture. No numeric PID is ever used to signal.
                let children = std::fs::read_to_string(format!(
                    "/proc/self/task/{}/children",
                    std::process::id()
                ))
                .unwrap();
                if children.trim().is_empty() {
                    break;
                }
                for pid in children
                    .split_whitespace()
                    .map(|p| p.parse::<i32>().unwrap())
                {
                    Pin::new(Pid::from_raw(pid)).settle();
                    adopted += 1;
                }
            }
            let mut status = 0;
            assert_eq!(
                unsafe { nix::libc::waitpid(-1, &mut status, nix::libc::WNOHANG) },
                -1
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(nix::libc::ECHILD)
            );
            let report = format!("timed_out={timed_out}, body_success={body_success}, adopted_reaped={adopted}, no_children=true");
            std::fs::write(std::env::var_os(FORCE_REPORT).unwrap(), &report).unwrap();
            assert!(body_success && !timed_out, "{report}");
            return;
        }
        assert_eq!(std::env::var(FORCE_MODE).unwrap(), "body");
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("owned-jobs");
        let fifo = dir.path().join("barrier");
        nix::unistd::mkfifo(
            &fifo,
            nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
        )
        .unwrap();
        let script = dir.path().join("pam.sh");
        // Only this private stack creates the controlled PAM-like sibling job.
        // Bash builtins provide readiness without transient polling children.
        write_script(&script, &format!("exec /bin/bash -c 'set -m; trap \"\" HUP; /bin/sleep 60 & member=$!; printf \"%s %s %s native-monitor-40\\n\" \"$$\" \"$member\" \"$PPID\" > \"{}\"; IFS= read -r unused < \"{}\"'", marker.display(), fifo.display()));
        // pam_exec deliberately calls setsid. This owned module instead keeps
        // its finite helper in the monitor session; it is a same-SID contract
        // control, not evidence for descendants that start separate sessions.
        let module_source = dir.path().join("pam_owned.c");
        let module = dir.path().join("pam_owned.so");
        std::fs::write(
            &module_source,
            r#"
#include <security/pam_modules.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
PAM_EXTERN int pam_sm_open_session(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags;
    if (argc != 1) return PAM_SESSION_ERR;
    pid_t child = fork();
    if (child < 0) return PAM_SESSION_ERR;
    if (child == 0) { execl(argv[0], argv[0], (char *)0); _exit(127); }
    int status;
    while (waitpid(child, &status, 0) < 0) {
        if (errno != EINTR) return PAM_SESSION_ERR;
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? PAM_SUCCESS : PAM_SESSION_ERR;
}
PAM_EXTERN int pam_sm_close_session(pam_handle_t *p, int flags, int argc, const char **argv) {
    (void)p; (void)flags; (void)argc; (void)argv;
    return PAM_SUCCESS;
}
"#,
        )
        .unwrap();
        let built = Command::new("cc")
            .args(["-shared", "-fPIC", "-Werror", "-Wall", "-Wextra"])
            .arg(&module_source)
            .arg("-o")
            .arg(&module)
            .output()
            .unwrap();
        assert!(
            built.status.success(),
            "owned PAM module build failed: {:?}",
            String::from_utf8_lossy(&built.stderr)
        );
        write_stack(dir.path(), "qshd-monitor-force", &format!("auth required pam_permit.so\naccount required pam_permit.so\nsession required {} {}\nsession required pam_permit.so\n", module.display(), script.display()));
        let mut plan = empty_monitor_plan();
        plan.pam_service = "qshd-monitor-force".into();
        plan.pam_confdir = Some(dir.path().to_path_buf());
        plan.session_budget = Duration::from_secs(30);
        let login = plan.login;
        let mut state = state_with_login(&plan.account, login);
        let owner = owner_for(&state, login);
        let monitor = fork_monitor(plan).unwrap();
        let monitor_pid = monitor.pid;
        let mut monitor_pin = Pin::new(monitor_pid);
        state.monitors.insert(owner, monitor);
        let seams = DirectSeam::new();
        let outsider = Command::new("/bin/sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut outsider_pin = Pin::new(Pid::from_raw(outsider.id() as i32));
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
                if text.ends_with('\n') && fields.len() == 4 && fields[3] == "native-monitor-40" {
                    break fields[..3]
                        .iter()
                        .map(|p| p.parse::<i32>().unwrap())
                        .collect::<Vec<_>>();
                }
            }
            assert!(
                Instant::now() < deadline,
                "private PAM child did not reach its owned barrier"
            );
            std::thread::sleep(Duration::from_millis(1));
        };
        let mut script_pin = Pin::new(Pid::from_raw(ids[0]));
        let mut member_pin = Pin::new(Pid::from_raw(ids[1]));
        let parent_of = |pid| {
            use std::io::Read;
            let mut status = String::new();
            std::fs::File::open(format!("/proc/{pid}/status"))
                .unwrap()
                .take(4096)
                .read_to_string(&mut status)
                .unwrap();
            status
                .lines()
                .find_map(|line| line.strip_prefix("PPid:"))
                .unwrap()
                .trim()
                .parse::<i32>()
                .unwrap()
        };
        assert_eq!(
            parent_of(ids[0]),
            ids[2],
            "the still-held marker actor reports its actual kernel parent"
        );
        // pam_exec may retain an intermediate helper. Authenticate the finite
        // live ancestry, retaining every exact identity before any stop.
        let mut intermediate = Vec::new();
        let mut ancestor = ids[2];
        while ancestor != monitor_pid.as_raw() {
            assert!(
                intermediate.len() < 8,
                "unexpected private PAM fixture ancestry"
            );
            let pin = Pin::new(Pid::from_raw(ancestor));
            assert_eq!(unsafe { nix::libc::getsid(ancestor) }, monitor_pid.as_raw());
            let next = parent_of(ancestor);
            assert!(!pin.exited());
            intermediate.push(pin);
            ancestor = next;
        }
        assert_eq!(unsafe { nix::libc::getsid(ids[0]) }, monitor_pid.as_raw());
        assert_eq!(unsafe { nix::libc::getsid(ids[1]) }, monitor_pid.as_raw());
        assert_ne!(unsafe { nix::libc::getpgid(ids[0]) }, unsafe {
            nix::libc::getpgid(ids[1])
        });
        while std::fs::read_link(format!("/proc/{}/exe", ids[1]))
            .ok()
            .and_then(|p| p.file_name().map(|name| name == "sleep"))
            != Some(true)
        {
            assert!(Instant::now() < deadline, "owned job has not exec'd sleep");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!monitor_pin.exited() && !script_pin.exited() && !member_pin.exited());
        assert!(!state.monitors[&owner].reaped);
        if std::env::var_os("QSH_TEST_MONITOR_FORCE_HOLD").is_some() {
            loop {
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        lose_monitor(
            &seams.helper,
            &mut state,
            owner,
            "owned forced monitor control",
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        while !state.monitors[&owner].reaped && Instant::now() < deadline {
            serve_ready_monitors(seams.seams(), &mut state, &[]);
            reap_owned_monitors(&seams.helper, &mut state);
            std::thread::sleep(Duration::from_millis(1));
        }
        let native_complete = state.monitors[&owner].reaped;
        let jobs_exited = monitor_pin.exited() && script_pin.exited() && member_pin.exited();
        let outsider_untouched = !outsider_pin.exited();
        let no_fabricated_pam = state.monitors[&owner].completion.is_none();
        let debt_retained = state.retired.contains(&owner);
        // Product completion is recorded above; fixture cleanup cannot turn a
        // timeout into proof. Parent-first actual waits make adoption explicit.
        monitor_pin.settle();
        for pin in &mut intermediate {
            pin.settle();
        }
        script_pin.settle();
        member_pin.settle();
        outsider_pin.settle();
        drop(outsider);
        assert!(native_complete && jobs_exited && outsider_untouched, "native_complete={native_complete}, jobs_exited={jobs_exited}, outsider_untouched={outsider_untouched}");
        assert!(
            no_fabricated_pam && debt_retained,
            "native monitor exit cannot invent PAM/shell receipts"
        );
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
}
