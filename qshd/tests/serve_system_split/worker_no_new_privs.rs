//! Worker-only exec hardening; all account/PAM/setuid state stays disposable.
use super::*;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};

fn no_new_privs(pid: u32) -> u8 {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
    status
        .lines()
        .find_map(|line| line.strip_prefix("NoNewPrivs:"))
        .expect("the disposable kernel exposes NoNewPrivs")
        .trim()
        .parse()
        .unwrap()
}

// Keep the helper owner until the real terminal wait, including assertion paths.
fn stop_owned(mut daemon: common::Daemon) -> io::Result<ExitStatus> {
    let pid = nix::unistd::Pid::from_raw(daemon.child.id() as i32);
    let deadline = Instant::now() + WORKER_WAIT;
    let mut problem = None;
    let mut term_sent = false;
    let mut kill_sent = false;
    loop {
        // Check for a terminal receipt before signaling the retained child.
        match daemon.child.try_wait() {
            Ok(Some(status)) => return problem.map_or(Ok(status), Err),
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.raw_os_error() == Some(nix::libc::ECHILD) => {
                eprintln!("worker67 lost helper wait ownership; refusing further signals: {error}");
                // The common guard unconditionally kills on Drop. After ECHILD
                // its PID is no longer ours to signal. Retain no success claim;
                // forget only this failed fixture's heap owner to prevent that
                // old guard from signaling a possibly reused, unowned PID.
                std::mem::forget(daemon);
                return Err(error);
            }
            Err(error) => {
                if problem.is_none() {
                    eprintln!("worker67 retaining helper custody after wait error: {error}");
                    problem = Some(error);
                }
            }
        }
        if !term_sent {
            if let Err(error) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM) {
                problem.get_or_insert_with(|| io::Error::from(error));
            }
            term_sent = true;
        }
        if Instant::now() >= deadline && !kill_sent {
            let _ = daemon.child.kill();
            kill_sent = true;
            problem.get_or_insert_with(|| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "helper stop exceeded fixture deadline",
                )
            });
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn worker67_no_new_privs_does_not_restrict_helper_or_user_exec() {
    const NAME: &str =
        "worker_no_new_privs::worker67_no_new_privs_does_not_restrict_helper_or_user_exec";
    common::on_a_disposable_host(
        NAME,
        "creates an owned account, PAM stack and guest-only setuid identity probe",
        || {
            assert!(
                !nix::sys::prctl::get_no_new_privs().unwrap(),
                "fixture launcher must start without a service-wide restriction"
            );
            // /tmp is the guest filesystem, never a source/target bind mount.
            let dir = tempfile::Builder::new()
                .prefix("qsh-worker67-")
                .tempdir_in("/tmp")
                .unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            let parent_metadata = std::fs::metadata(dir.path()).unwrap();
            assert!(parent_metadata.uid() == 0 && parent_metadata.mode() & 0o7777 == 0o755);
            let account = common::TestAccount::create("qshd-test-worker67", "/bin/sh");
            let passwd = nix::unistd::User::from_name(&account.name)
                .unwrap()
                .unwrap();
            let gid = passwd.gid;
            let original = std::fs::metadata("/usr/bin/id").unwrap();
            assert!(original.is_file() && original.uid() == 0 && original.mode() & 0o111 != 0);
            let probe = dir.path().join("effective-id");
            std::fs::copy("/usr/bin/id", &probe).unwrap();
            nix::unistd::chown(
                &probe,
                Some(nix::unistd::ROOT),
                Some(nix::unistd::Gid::from_raw(0)),
            )
            .unwrap();
            std::fs::set_permissions(&probe, std::fs::Permissions::from_mode(0o4755)).unwrap();
            let metadata = std::fs::metadata(&probe).unwrap();
            assert!(
                metadata.is_file() && metadata.uid() == 0 && metadata.mode() & 0o7777 == 0o4755
            );
            // Prove this guest filesystem honors setuid, not merely its mode bit.
            for (argument, expected) in [("-ru", account.uid.as_raw()), ("-u", 0)] {
                let output = Command::new(&probe)
                    .arg(argument)
                    .uid(account.uid.as_raw())
                    .gid(gid.as_raw())
                    .output()
                    .unwrap();
                assert!(output.status.success());
                assert_eq!(
                    String::from_utf8(output.stdout)
                        .unwrap()
                        .trim()
                        .parse::<u32>()
                        .unwrap(),
                    expected
                );
            }
            let phases = dir.path().join("pam-phases");
            let script = dir.path().join("pam-phase");
            std::fs::write(&script, format!("#!/bin/sh\nprintf '%s ' \"$PAM_TYPE\" >> '{}'\nawk '/^NoNewPrivs:/ {{print $2}}' /proc/self/status >> '{}'\n", phases.display(), phases.display())).unwrap();
            std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o700)).unwrap();
            common::install_service_file(&format!("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_exec.so {}\n", script.display()));
            let (daemon, pubkey, port) = common::start_daemon_for_accounts(dir.path());
            let helper = daemon.child.id();
            let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let (worker, _role) = wait_for_worker_pid(helper).expect("qualified owned worker");
                let nobody = nix::unistd::User::from_name("nobody").unwrap().unwrap();
                wait_until_worker_is_armed_the_second_time(worker, nobody.uid);
                assert_eq!(
                    no_new_privs(helper),
                    0,
                    "helper must retain the launcher's policy"
                );
                let tasks: Vec<_> = std::fs::read_dir(format!("/proc/{worker}/task"))
                    .unwrap()
                    .map(|entry| {
                        entry
                            .unwrap()
                            .file_name()
                            .to_string_lossy()
                            .parse::<u32>()
                            .unwrap()
                    })
                    .collect();
                assert!(tasks.len() >= 3, "observe actual auxiliary worker threads");
                for tid in tasks {
                    assert_eq!(no_new_privs(tid), 1, "worker thread {tid}");
                }
                let session = common::Session::connect(port, pubkey, &account.key, &account.name);
                session.open_shell();
                let deadline = Instant::now() + WORKER_WAIT;
                let monitor = loop {
                    let children = children_of(helper);
                    let others: Vec<_> = children
                        .iter()
                        .copied()
                        .filter(|pid| *pid != worker)
                        .collect();
                    if children.contains(&worker) {
                        if let [monitor] = others[..] {
                            break monitor;
                        }
                    }
                    assert!(
                        Instant::now() < deadline,
                        "login monitor did not settle: {children:?}"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                };
                assert_eq!(no_new_privs(monitor), 0, "PAM monitor is a helper child");
                let report = |tag: &str| {
                    format!("printf '{tag}-NNP='; awk '/^NoNewPrivs:/ {{print $2}}' /proc/self/status; printf '{tag}-UID='; /usr/bin/id -u; printf '{tag}-ELEVATED='; '{}' -u", probe.display())
                };
                let output = session.run_in_shell(&report("SHELL67"));
                assert!(output.contains("SHELL67-NNP=0"), "{output}");
                assert!(
                    output.contains(&format!("SHELL67-UID={}", account.uid)),
                    "{output}"
                );
                assert!(output.contains("SHELL67-ELEVATED=0"), "{output}");
                // The common collector intentionally retains only the first
                // channel's bytes. A fresh owned file carries Command output.
                let command_record = passwd.dir.join("worker67-command");
                assert!(!command_record.exists());
                session.run_command_on_stream(
                    24,
                    &format!(
                        "{{ {}; }} > '{}'",
                        report("COMMAND67"),
                        command_record.display()
                    ),
                );
                let output = std::fs::read_to_string(&command_record).unwrap();
                assert!(output.contains("COMMAND67-NNP=0"), "{output}");
                assert!(
                    output.contains(&format!("COMMAND67-UID={}", account.uid)),
                    "{output}"
                );
                assert!(output.contains("COMMAND67-ELEVATED=0"), "{output}");
                session.exit_shell();
                assert_eq!(session.wait_for_exit(), 0);
                session.disconnect_gracefully();
                drop(session);
                let deadline = Instant::now() + WORKER_WAIT;
                while !std::fs::read_to_string(&phases)
                    .unwrap_or_default()
                    .contains("close_session 0")
                    || children_of(helper).contains(&monitor)
                {
                    assert!(
                        Instant::now() < deadline,
                        "PAM close/monitor wait did not settle"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                assert_eq!(
                    std::fs::read_to_string(&phases)
                        .unwrap()
                        .lines()
                        .collect::<Vec<_>>(),
                    ["open_session 0", "close_session 0"]
                );
            }));
            let stopped = stop_owned(daemon);
            // Remove the only setuid copy after user exit and helper physical wait.
            std::fs::remove_file(&probe).unwrap();
            assert!(
                stopped.unwrap().success(),
                "helper must settle on an ordinary stop"
            );
            if let Err(panic) = outcome {
                std::panic::resume_unwind(panic);
            }
        },
    );
}
