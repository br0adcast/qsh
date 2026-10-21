//! Owned subprocesses keep deliberate poison/failure states out of the test
//! runner. No callback blocks, allocates, or waits on a test barrier.

use super::*;
use crate::tty::{EchoOff, RawMode};
use std::fs::File;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicI32, AtomicU8};
use std::time::{Duration, Instant};

const CASE: &str = "QSH_TEST_SUSPEND_TRANSITION";
static FAIL_ACTION: AtomicU8 = AtomicU8::new(0);
static FAIL_RAW: AtomicBool = AtomicBool::new(false);
static CLOSE_RAW: AtomicI32 = AtomicI32::new(-1);

pub(crate) fn before_action(handler: SigHandler) -> Result<(), nix::Error> {
    let code = if handler == SigHandler::SigDfl { 1 } else { 2 };
    if FAIL_ACTION
        .compare_exchange(code, 0, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        Err(nix::Error::EIO)
    } else {
        Ok(())
    }
}

pub(crate) fn before_raw(fd: i32) -> Result<(), nix::Error> {
    if CLOSE_RAW
        .compare_exchange(fd, -1, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        // Only this isolated fixture's explicitly duplicated raw fd is closed.
        assert_eq!(unsafe { libc::close(fd) }, 0);
    }
    if FAIL_RAW.swap(false, Ordering::SeqCst) {
        Err(nix::Error::EIO)
    } else {
        Ok(())
    }
}

struct Owner(Option<Child>);
impl Drop for Owner {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            if matches!(child.try_wait(), Ok(None)) {
                unsafe { libc::kill(child.id() as i32, libc::SIGCONT) };
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

fn run(case: &str, expected_stops: usize) {
    let home = tempfile::tempdir().unwrap();
    let pty = nix::pty::openpty(None, None).unwrap();
    let saved = nix::sys::termios::tcgetattr(&pty.slave).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "signals::suspend_tests::child_process",
            "--exact",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CASE, case)
        .env("HOME", home.path())
        .env("XDG_CACHE_HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("HISTFILE", "/dev/null")
        .env_remove("SSH_AUTH_SOCK")
        .env_remove("SSH_AGENT_PID")
        .stdin(Stdio::from(pty.slave.try_clone().unwrap()))
        .stdout(Stdio::from(pty.slave.try_clone().unwrap()))
        .stderr(Stdio::from(pty.slave.try_clone().unwrap()));
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let mut child = Owner(Some(command.spawn().unwrap()));
    let mut master = File::from(pty.master);
    unsafe {
        let flags = libc::fcntl(master.as_raw_fd(), libc::F_GETFL);
        assert!(flags >= 0);
        assert_eq!(
            libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK),
            0
        );
    }
    let mut output = Vec::new();
    let mut stops = 0;
    let deadline = Instant::now() + Duration::from_secs(5);
    let status = loop {
        let mut buf = [0; 1024];
        for _ in 0..16 {
            let n = match master.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            assert!(output.len() + n <= 64 * 1024, "bounded unit-child report");
            output.extend_from_slice(&buf[..n]);
        }
        let owned = child.0.as_mut().unwrap();
        match owned.try_wait() {
            Ok(Some(status)) => {
                child.0.take();
                break status;
            }
            Ok(None) => {}
            Err(error) => {
                if error.raw_os_error() == Some(libc::ECHILD) {
                    child.0.take();
                }
                panic!("lost child wait authority: {error}");
            }
        }
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PID,
                owned.id(),
                &mut info,
                libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
            )
        };
        if result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ECHILD) {
                child.0.take();
            }
            panic!("stop observation failed: {error}");
        }
        if info.si_code == libc::CLD_STOPPED {
            assert_eq!(unsafe { info.si_status() }, libc::SIGTSTP);
            assert_eq!(
                nix::sys::termios::tcgetattr(&pty.slave).unwrap(),
                saved,
                "{case}: must be cooked while actually stopped"
            );
            let mut status = 0;
            assert_eq!(
                unsafe {
                    libc::waitpid(
                        owned.id() as i32,
                        &mut status,
                        libc::WUNTRACED | libc::WNOHANG,
                    )
                },
                owned.id() as i32
            );
            stops += 1;
            assert!(stops <= expected_stops, "unexpected extra stop in {case}");
            assert_eq!(unsafe { libc::kill(owned.id() as i32, libc::SIGCONT) }, 0);
        }
        assert!(
            Instant::now() < deadline,
            "{case} timed out: {}",
            String::from_utf8_lossy(&output)
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    // Fault cases intentionally make restoration impossible on their duplicate
    // fd. Only the test parent repairs its own PTY after actual child reap.
    nix::sys::termios::tcsetattr(&pty.slave, nix::sys::termios::SetArg::TCSANOW, &saved).unwrap();
    assert!(
        status.success(),
        "{case}: {}",
        String::from_utf8_lossy(&output)
    );
    assert_eq!(
        stops, expected_stops,
        "{case}: no missing or repeated replay"
    );
}

macro_rules! control {
    ($name:ident, $case:literal, $stops:literal) => {
        #[test]
        fn $name() {
            run($case, $stops);
        }
    };
}
control!(pending_exit_replays_after_cooked_restore, "pending", 1);
control!(late_callback_uses_current_default, "late", 1);
control!(late_callback_uses_current_echo_owner, "echo", 1);
control!(
    late_callback_cannot_release_new_raw_generation,
    "replacement",
    1
);
control!(
    blocked_owner_replays_another_threads_delivered_request,
    "masked-pending",
    1
);
control!(owned_stop_preserves_blocked_mask, "masked-stop", 1);
control!(replay_preserves_exact_mask_and_errno, "masked-direct", 1);
control!(
    failed_default_stop_is_fatal_to_raw_owner,
    "stop-default-error",
    0
);
control!(
    failed_reinstall_cannot_reenter_raw,
    "stop-reinstall-error",
    1
);
control!(
    failed_restore_disposition_keeps_poison,
    "restore-handler-error",
    0
);
control!(
    failed_restore_drops_fd_custody_and_poisons,
    "restore-error",
    0
);
control!(failed_suspend_cannot_stop_or_reenter, "suspend-error", 0);
control!(failed_reenter_cannot_reuse_fd, "reenter-error", 0);
control!(
    failed_entry_handler_releases_cooked_claim,
    "entry-handler-error",
    0
);
control!(
    failed_raw_entry_rolls_back_before_default,
    "entry-set-error",
    0
);
control!(
    failed_entry_rollback_keeps_fixed_poison,
    "entry-rollback-error",
    0
);
control!(
    owner_panic_restores_policy_before_late_callback,
    "owner-panic",
    1
);
control!(worker_panic_retains_raw_owner, "worker-panic", 0);

fn disposition() -> libc::sighandler_t {
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(
            libc::sigaction(libc::SIGTSTP, std::ptr::null(), &mut action),
            0
        );
        action.sa_sigaction
    }
}

fn mask() -> [i32; 128] {
    unsafe {
        let mut mask: libc::sigset_t = std::mem::zeroed();
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut mask),
            0
        );
        std::array::from_fn(|i| libc::sigismember(&mask, i as i32 + 1))
    }
}

fn block_owner() -> [i32; 128] {
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGTSTP);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        assert_eq!(
            libc::pthread_sigmask(libc::SIG_BLOCK, &set, std::ptr::null_mut()),
            0
        );
    }
    mask()
}

#[test]
fn child_process() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    install().unwrap();
    let fd = libc::STDIN_FILENO;
    let callback = on_tstp;
    if case == "masked-direct" {
        let before = block_owner();
        nix::errno::Errno::set_raw(libc::E2BIG);
        replay_tstp().unwrap();
        assert_eq!(nix::errno::Errno::last_raw(), libc::E2BIG);
        assert_eq!(mask(), before);
        return;
    }
    if case.starts_with("entry-") {
        let owned = unsafe { libc::dup(fd) };
        assert!(owned >= 0);
        match case.as_str() {
            "entry-handler-error" => FAIL_ACTION.store(2, Ordering::SeqCst),
            "entry-set-error" => FAIL_RAW.store(true, Ordering::SeqCst),
            _ => CLOSE_RAW.store(owned, Ordering::SeqCst),
        }
        assert!(RawMode::enter(owned).is_err());
        if case == "entry-rollback-error" {
            assert_eq!(SUSPEND.load(Ordering::SeqCst) & FLAGS, DEFERRED | POISONED);
            assert!(RawMode::enter(fd).is_err());
        } else {
            assert_eq!(disposition(), libc::SIG_DFL);
            RawMode::enter(fd).unwrap().restore().unwrap();
            assert_eq!(unsafe { libc::close(owned) }, 0);
        }
        return;
    }
    if matches!(
        case.as_str(),
        "restore-error" | "suspend-error" | "reenter-error"
    ) {
        let owned = unsafe { libc::dup(fd) };
        assert!(owned >= 0);
        let raw = RawMode::enter(owned).unwrap();
        // Allocate the sentinel while the old duplicate is still occupied,
        // so fd-number reuse below cannot close a fresh OwnedFd accidentally.
        let fresh = nix::pty::openpty(None, None).unwrap();
        if case == "reenter-error" {
            raw.suspend().unwrap();
        }
        assert_eq!(unsafe { libc::close(owned) }, 0);
        let failed = match case.as_str() {
            "restore-error" => raw.restore(),
            "suspend-error" => raw.suspend(),
            _ => raw.reenter(),
        };
        assert_eq!(failed.unwrap_err(), nix::Error::EBADF);
        assert_eq!(SUSPEND.load(Ordering::SeqCst) & FLAGS, DEFERRED | POISONED);
        assert!(raw.stop().is_err());
        assert!(raw.reenter().is_err());
        assert!(RawMode::enter(fd).is_err());
        let mut sentinel = nix::sys::termios::tcgetattr(&fresh.slave).unwrap();
        nix::sys::termios::cfmakeraw(&mut sentinel);
        nix::sys::termios::tcsetattr(&fresh.slave, nix::sys::termios::SetArg::TCSANOW, &sentinel)
            .unwrap();
        // Reuse the old number without transferring ownership of fresh.slave.
        // Old guard Drop must not reset this unrelated terminal's modes.
        let reused = unsafe { libc::fcntl(fresh.slave.as_raw_fd(), libc::F_DUPFD, owned) };
        assert!(reused >= 0);
        if reused == owned {
            drop(raw);
            assert_eq!(
                nix::sys::termios::tcgetattr(&fresh.slave).unwrap(),
                sentinel
            );
        } else {
            drop(raw);
            panic!("fixture did not obtain exact fd reuse");
        }
        assert_eq!(unsafe { libc::close(reused) }, 0);
        return;
    }
    let raw = RawMode::enter(fd).unwrap();
    match case.as_str() {
        "pending" => {
            callback(libc::SIGTSTP);
            raw.restore().unwrap();
        }
        "late" => {
            raw.restore().unwrap();
            callback(libc::SIGTSTP);
        }
        "echo" => {
            raw.restore().unwrap();
            let quiet = EchoOff::enter(fd).unwrap();
            callback(libc::SIGTSTP);
            let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
            assert!(!nix::sys::termios::tcgetattr(borrowed)
                .unwrap()
                .local_flags
                .contains(nix::sys::termios::LocalFlags::ECHO));
            drop(quiet);
        }
        "replacement" => {
            raw.restore().unwrap();
            let next = RawMode::enter(fd).unwrap();
            callback(libc::SIGTSTP);
            raw.restore().unwrap();
            assert!(SUSPEND.load(Ordering::SeqCst) & PENDING != 0);
            assert!(raw.reenter().is_err());
            next.restore().unwrap();
        }
        "masked-pending" => {
            let before = block_owner();
            std::thread::spawn(|| {
                unsafe {
                    let mut one: libc::sigset_t = std::mem::zeroed();
                    libc::sigemptyset(&mut one);
                    libc::sigaddset(&mut one, libc::SIGTSTP);
                    assert_eq!(
                        libc::pthread_sigmask(libc::SIG_UNBLOCK, &one, std::ptr::null_mut()),
                        0
                    );
                }
                signal::raise(Signal::SIGTSTP).unwrap();
            })
            .join()
            .unwrap();
            assert!(SUSPEND.load(Ordering::SeqCst) & PENDING != 0);
            raw.restore().unwrap();
            assert_eq!(mask(), before);
        }
        "masked-stop" => {
            let before = block_owner();
            raw.suspend().unwrap();
            raw.stop().unwrap();
            assert_eq!(mask(), before);
            raw.reenter().unwrap();
            raw.restore().unwrap();
        }
        "stop-default-error" | "stop-reinstall-error" => {
            raw.suspend().unwrap();
            FAIL_ACTION.store(
                if case == "stop-default-error" { 1 } else { 2 },
                Ordering::SeqCst,
            );
            assert_eq!(raw.stop().unwrap_err(), nix::Error::EIO);
            assert_eq!(SUSPEND.load(Ordering::SeqCst) & FLAGS, DEFERRED | POISONED);
            assert!(raw.reenter().is_err());
            assert!(RawMode::enter(fd).is_err());
        }
        "restore-handler-error" => {
            FAIL_ACTION.store(1, Ordering::SeqCst);
            assert_eq!(raw.restore().unwrap_err(), nix::Error::EIO);
            assert_eq!(SUSPEND.load(Ordering::SeqCst) & FLAGS, DEFERRED | POISONED);
            assert!(raw.reenter().is_err());
            assert!(RawMode::enter(fd).is_err());
        }
        "owner-panic" => {
            RawMode::install_panic_hook();
            assert!(std::panic::catch_unwind(|| panic!("owned terminal panic")).is_err());
            assert_eq!(disposition(), libc::SIG_DFL);
            raw.restore().unwrap();
            callback(libc::SIGTSTP);
        }
        "worker-panic" => {
            RawMode::install_panic_hook();
            assert!(std::thread::spawn(|| panic!("background panic"))
                .join()
                .is_err());
            assert_eq!(SUSPEND.load(Ordering::SeqCst) & FLAGS, DEFERRED);
            assert_ne!(disposition(), libc::SIG_DFL);
            raw.restore().unwrap();
        }
        _ => panic!("unknown transition fixture"),
    }
}
