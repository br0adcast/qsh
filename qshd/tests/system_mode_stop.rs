//! Real Linux system-worker TERM/INT and PAM-close acceptance, disposable only.
#![cfg(all(feature = "system", target_os = "linux"))]
mod common;
#[path = "../src/test_borrowed_scope.rs"]
mod test_borrowed_scope;

use nix::libc;
use std::io::Write;
use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

// This fixture uses proc children lists plus exact pidfds, not the library's
// proc-dirfd ownership implementation. Reject a mismatched proc namespace and
// unavailable non-consuming waitid before any fixture actor is created.
fn qualify_borrowed_fixture() {
    let pid = std::process::id();
    assert_eq!(
        std::fs::read_link("/proc/self").unwrap().to_str().unwrap(),
        pid.to_string()
    );
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    for field in ["Pid", "Tgid"] {
        let value = status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{field}:")))
            .unwrap();
        assert_eq!(value.trim().parse::<u32>().unwrap(), pid);
    }
    let pin = Pin::new(pid);
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pin.0.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    assert!(std::fs::read_dir("/proc/self/task").is_ok());
}
struct Pin(OwnedFd);
impl Pin {
    fn new(pid: u32) -> Self {
        let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        assert!(
            fd >= 0,
            "exact fixture pidfd: {}",
            std::io::Error::last_os_error()
        );
        Self(unsafe { OwnedFd::from_raw_fd(fd as i32) })
    }
    fn signal(&self, signal: i32) {
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.0.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
    }
    fn exited(&self) -> bool {
        let mut fd = libc::pollfd {
            fd: self.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut fd, 1, 0) };
        if result < 0 {
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EINTR)
            );
            return false;
        }
        fd.revents & libc::POLLIN != 0
    }
}
fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while !predicate() {
        assert!(
            Instant::now() < deadline,
            "bounded real service phase did not settle"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn worker_pid(helper: u32, helper_pin: &Pin) -> (u32, Pin) {
    assert!(!helper_pin.exited());
    let uid = nix::unistd::User::from_name("nobody")
        .unwrap()
        .unwrap()
        .uid
        .as_raw();
    // Signed shell readiness has already proved the owned split completed.
    // Startup locale children and root PAM monitors are not worker identities.
    let children =
        std::fs::read_to_string(format!("/proc/{helper}/task/{helper}/children")).unwrap();
    let mut workers: Vec<_> = children
        .split_whitespace()
        .filter_map(|pid| {
            let pid = pid.parse::<u32>().unwrap();
            common::qualified_system_worker(pid, helper, uid).map(|pin| (pid, Pin(pin)))
        })
        .collect();
    assert_eq!(
        workers.len(),
        1,
        "exactly one privately established unprivileged worker"
    );
    assert!(!helper_pin.exited());
    workers.pop().unwrap()
}
#[test]
fn a_warmup_like_child_is_not_the_privately_established_worker() {
    test_borrowed_scope::run_exact(
        "a_warmup_like_child_is_not_the_privately_established_worker",
        0,
        || {
            let mut child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
            let uid = nix::unistd::User::from_name("nobody")
                .unwrap()
                .unwrap()
                .uid
                .as_raw();
            let accepted =
                common::qualified_system_worker(child.id(), std::process::id(), uid).is_some();
            child.kill().unwrap();
            child.wait().unwrap();
            assert!(
                !accepted,
                "a direct warmup-like child grants no worker role"
            );
        },
    )
    .assert_clean(0);
}
fn worker_task_status(worker: u32, tid: u32) -> Option<String> {
    match std::fs::read_to_string(format!("/proc/{worker}/task/{tid}/status")) {
        Ok(status) => Some(status),
        // An observed secondary thread can end between enumeration and read.
        // The caller separately requires the exact live main task before/after.
        Err(error) if tid != worker && error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => panic!("worker task {tid} status is unavailable: {error}"),
    }
}
fn assert_unblocked_stop_mask(status: &str) {
    let stop_bits = (1u64 << (libc::SIGTERM - 1)) | (1u64 << (libc::SIGINT - 1));
    let blocked = status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .unwrap();
    assert_eq!(
        u64::from_str_radix(blocked.trim(), 16).unwrap() & stop_bits,
        0,
        "worker threads must not inherit helper stop mask"
    );
}
fn assert_worker_masks_and_fds(worker: u32, pin: &Pin) {
    assert!(
        !pin.exited(),
        "exact worker must be live before mask inventory"
    );
    assert_unblocked_stop_mask(&worker_task_status(worker, worker).expect("mandatory main task"));
    for entry in std::fs::read_dir(format!("/proc/{worker}/task")).unwrap() {
        let tid = entry
            .unwrap()
            .file_name()
            .to_str()
            .unwrap()
            .parse::<u32>()
            .unwrap();
        if tid != worker {
            if let Some(status) = worker_task_status(worker, tid) {
                assert_unblocked_stop_mask(&status);
            }
        }
    }
    for entry in std::fs::read_dir(format!("/proc/{worker}/fd")).unwrap() {
        if let Ok(target) = std::fs::read_link(entry.unwrap().path()) {
            assert_ne!(
                target.as_os_str(),
                std::ffi::OsStr::new("anon_inode:[signalfd]")
            );
        }
    }
    assert_unblocked_stop_mask(&worker_task_status(worker, worker).expect("mandatory main task"));
    assert!(
        !pin.exited(),
        "exact worker must stay live through mask inventory"
    );
}
#[test]
fn a_vanished_secondary_task_preserves_the_required_live_main_task() {
    let worker = std::process::id();
    let pin = Pin::new(worker);
    let (started, receiver) = std::sync::mpsc::channel();
    let (release, released) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let tid = unsafe { libc::syscall(libc::SYS_gettid) } as u32;
        started.send(tid).unwrap();
        released.recv().unwrap();
    });
    let tid = receiver.recv().unwrap();
    assert_ne!(tid, worker);
    assert!(worker_task_status(worker, tid).is_some());
    release.send(()).unwrap();
    thread.join().unwrap();
    // Join can wake before the kernel removes its proc task entry. Establish
    // the control's absent-task premise; the production inventory never retries.
    let status_path = format!("/proc/{worker}/task/{tid}/status");
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        match std::fs::metadata(&status_path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Ok(_) => {
                assert!(
                    Instant::now() < deadline,
                    "joined fixture task did not leave proc"
                );
                std::thread::yield_now();
            }
            Err(error) => panic!("cannot establish vanished fixture task: {error}"),
        }
    }
    assert!(
        worker_task_status(worker, tid).is_none(),
        "actual joined thread must disappear"
    );
    assert_worker_masks_and_fds(worker, &pin);
}
fn release_fifo(path: &Path) {
    let mut writer = None;
    until(|| {
        match std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
        {
            Ok(file) => {
                writer = Some(file);
                true
            }
            Err(error) if error.raw_os_error() == Some(libc::ENXIO) => false,
            Err(error) => panic!("owned PAM release: {error}"),
        }
    });
    writer.unwrap().write_all(b"release\n").unwrap();
}
fn service_case(name: &str, signal: i32, failed_close: bool) {
    common::on_a_disposable_host(
        name,
        "creates a real account and overwrites /etc/pam.d/qshd",
        || {
            // The shared supervisor deliberately does not inherit output pipes.
            // Retain one bounded private phase/panic file across its reexecs.
            let diagnostic_owner = std::env::var_os("QSH_TEST_BORROWED_SCOPE_MODE")
                .is_none()
                .then(|| tempfile::tempdir().unwrap());
            if let Some(dir) = diagnostic_owner.as_ref() {
                std::env::set_var("QSH_TEST_STOP_DIAGNOSTIC", dir.path().join("phase"));
            }
            let result = test_borrowed_scope::run_exact(name, 1, || {
                let previous = std::panic::take_hook();
                std::panic::set_hook(Box::new(move |info| {
                    let path = std::env::var_os("QSH_TEST_STOP_DIAGNOSTIC").unwrap();
                    let prior = std::fs::read_to_string(&path).unwrap_or_default();
                    let detail = format!("{info}");
                    let _ = std::fs::write(
                        path,
                        format!(
                            "{prior} panic_location={}",
                            detail.chars().take(2048).collect::<String>()
                        ),
                    );
                    previous(info);
                }));
                let result = std::panic::catch_unwind(|| real_service_body(signal, failed_close));
                if let Err(cause) = result {
                    let message = cause
                        .downcast_ref::<String>()
                        .map(String::as_str)
                        .or_else(|| cause.downcast_ref::<&str>().copied())
                        .unwrap_or("non-string panic");
                    let path = std::env::var_os("QSH_TEST_STOP_DIAGNOSTIC").unwrap();
                    let prior = std::fs::read_to_string(&path).unwrap_or_default();
                    std::fs::write(
                        path,
                        format!(
                            "{prior} failure={}",
                            message.chars().take(2048).collect::<String>()
                        ),
                    )
                    .unwrap();
                    std::panic::resume_unwind(cause);
                }
            });
            if diagnostic_owner.is_some() {
                let diagnostic =
                    std::fs::read_to_string(std::env::var_os("QSH_TEST_STOP_DIAGNOSTIC").unwrap())
                        .unwrap_or_default();
                std::env::remove_var("QSH_TEST_STOP_DIAGNOSTIC");
                eprintln!(
                    "owned real service evidence: {}",
                    diagnostic.chars().take(4096).collect::<String>()
                );
            }
            result.assert_clean(1);
        },
    );
}
fn phase(name: &str) {
    std::fs::write(
        std::env::var_os("QSH_TEST_STOP_DIAGNOSTIC").unwrap(),
        format!("phase={name}"),
    )
    .unwrap();
}
fn real_service_body(signal: i32, failed_close: bool) {
    phase("private_setup");
    let dir = tempfile::tempdir().unwrap();
    let account = common::TestAccount::create("qshd-test-stop", "/bin/sh");
    let close = dir.path().join("close-entered");
    let complete = dir.path().join("close-returned");
    let fifo = dir.path().join("close-release");
    nix::unistd::mkfifo(
        &fifo,
        nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
    )
    .unwrap();
    let script = dir.path().join("pam-close.sh");
    // Read our own mask using builtins before any external-command fork.
    // Sampling this shell from a spawned cat observes shell critical sections.
    let marker = close.display();
    let release = fifo.display();
    let returned = complete.display();
    let code = if failed_close { 7 } else { 0 };
    std::fs::write(
        &script,
        format!(
            r#"#!/bin/sh
[ "$PAM_TYPE" = close_session ] || exit 0
while IFS= read -r line; do
    case "$line" in SigBlk:*) printf '%s\n' "$line";; esac
done < /proc/$$/status > '{marker}.status.tmp'
mv '{marker}.status.tmp' '{marker}.status'
printf '%s %s\n' "$$" "$PPID" > '{marker}.tmp'
mv '{marker}.tmp' '{marker}'
IFS= read -r release < '{release}'
printf returned > '{returned}'
exit {code}
"#
        ),
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    common::install_service_file(&format!("auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_exec.so {}\nsession required pam_permit.so\n",script.display()));
    // This exact unrelated child is outside the daemon's owned domain.
    let sentinel = Command::new("/bin/sleep")
        .arg("60")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let sentinel_pin = Pin::new(sentinel.id());
    let (mut daemon, server_pub, port) = common::start_daemon_for_accounts(dir.path());
    let helper = Pin::new(daemon.child.id());
    phase("real_daemon_started");
    phase("real_signed_session_connect");
    let session = common::Session::connect(port, server_pub, &account.key, &account.name);
    phase("real_signed_session_open_shell");
    session.open_shell();
    phase("real_shell_command");
    let output = session.run_in_shell("printf 'stop-%s\\n' actual-worker");
    assert!(
        output.contains("stop-actual-worker"),
        "signed session must run in the real worker shell"
    );
    phase("qualified_actual_worker_role");
    let (worker, worker_pin) = worker_pid(daemon.child.id(), &helper);
    phase("live_worker_task_and_fd_inventory");
    assert_worker_masks_and_fds(worker, &worker_pin);
    phase("signed_shell_opened");
    helper.signal(signal);
    until(|| close.exists());
    phase("actual_pam_close_held");
    let ids = std::fs::read_to_string(&close).unwrap();
    let ids: Vec<u32> = ids
        .split_whitespace()
        .map(|id| id.parse().unwrap())
        .collect();
    assert_eq!(ids.len(), 2);
    let pam = Pin::new(ids[0]);
    let monitor = Pin::new(ids[1]);
    assert!(
        !helper.exited() && !monitor.exited() && !pam.exited(),
        "held PAM close retains actual helper, monitor and hook"
    );
    let status = std::fs::read_to_string(close.with_extension("status")).unwrap();
    let blocked = status
        .lines()
        .find_map(|line| line.strip_prefix("SigBlk:"))
        .unwrap();
    let blocked = u64::from_str_radix(blocked.trim(), 16).unwrap();
    assert_eq!(
        blocked & ((1u64 << (libc::SIGTERM - 1)) | (1u64 << (libc::SIGINT - 1))),
        0,
        "actual PAM hook must inherit restored stop mask"
    );
    helper.signal(libc::SIGTERM);
    helper.signal(libc::SIGINT);
    assert!(!sentinel_pin.exited() && !complete.exists());
    release_fifo(&fifo);
    phase("actual_pam_close_released");
    let mut exit = None;
    until(|| {
        exit = daemon.child.try_wait().unwrap();
        exit.is_some()
    });
    let exit = exit.unwrap();
    phase("actual_helper_native_wait");
    assert_eq!(
        exit.code(),
        Some(i32::from(failed_close)),
        "truthful actual service status: {}",
        daemon.stderr_text()
    );
    assert!(complete.exists() && worker_pin.exited() && monitor.exited() && pam.exited());
    assert!(
        !sentinel_pin.exited(),
        "owned stop must leave unrelated child untouched"
    );
    drop(session);
    sentinel_pin.signal(libc::SIGTERM);
    test_borrowed_scope::wait_expected(sentinel_pin.0.as_fd());
    drop(sentinel);
    // Daemon Child cached its exact wait above, so its Drop cannot target reuse.
    drop(daemon);
    phase("actual_native_cleanup_and_untouched_sentinel_proved");
}
#[test]
fn term_retains_helper_until_successful_pam_close() {
    service_case(
        "term_retains_helper_until_successful_pam_close",
        libc::SIGTERM,
        false,
    )
}
#[test]
fn int_retains_helper_until_successful_pam_close() {
    service_case(
        "int_retains_helper_until_successful_pam_close",
        libc::SIGINT,
        false,
    )
}
#[test]
fn failed_pam_close_keeps_service_exit_nonzero() {
    service_case(
        "failed_pam_close_keeps_service_exit_nonzero",
        libc::SIGTERM,
        true,
    )
}
#[test]
// This negative deliberately leaves one child for the supervisor's exact wait.
#[allow(clippy::zombie_processes)]
fn a_fixture_rescue_never_becomes_a_clean_service_stop() {
    let result = test_borrowed_scope::run_exact(
        "a_fixture_rescue_never_becomes_a_clean_service_stop",
        0,
        || {
            let _child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
        },
    );
    assert!(
        !result.body_success
            && !result.supervisor_success
            && result.body_adopted == 1
            && result.body_rescues == 1
            && result.no_children
    );
}
