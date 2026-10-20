use super::*;
use nix::pty::openpty;
use std::sync::atomic::{AtomicBool, AtomicI32};

static CLOSE_BEFORE_QUIET: AtomicI32 = AtomicI32::new(-1);
static CHECK_RESUME: AtomicBool = AtomicBool::new(false);
static RESUME_CHECKED: AtomicU32 = AtomicU32::new(0);

pub(super) fn before_enter_quiet(fd: RawFd) {
    if CLOSE_BEFORE_QUIET
        .compare_exchange(fd, -1, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // Only a test-owned duplicated raw descriptor is closed by this seam.
        unsafe {
            libc::close(fd);
        }
    }
}

pub(super) fn before_resume_quiet(sig: libc::c_int) {
    if CHECK_RESUME.load(Ordering::Relaxed) {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            if libc::sigaction(sig, std::ptr::null(), &mut action) != 0
                || action.sa_sigaction
                    != restore_and_reraise as extern "C" fn(libc::c_int) as libc::sighandler_t
            {
                libc::_exit(120);
            }
        }
        RESUME_CHECKED.fetch_add(1, Ordering::Relaxed);
    }
}

#[test]
fn failed_quiet_after_handler_install_restores_dispositions_and_releases_claim() {
    let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let disposition = |sig| unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(sig, std::ptr::null(), &mut action), 0);
        action.sa_sigaction
    };
    let before = ECHO_SIGNALS.map(disposition);
    let pty = openpty(None, None).unwrap();
    let saved = termios::tcgetattr(&pty.slave).unwrap();
    let owned_raw = unsafe { libc::dup(pty.slave.as_raw_fd()) };
    assert!(owned_raw >= 0);
    CLOSE_BEFORE_QUIET.store(owned_raw, Ordering::Release);
    let result = EchoOff::enter(owned_raw);
    // The hook consumes this raw duplicate; no OwnedFd is double-closed.
    assert_eq!(CLOSE_BEFORE_QUIET.load(Ordering::Acquire), -1);
    assert_eq!(result.err(), Some(nix::Error::EBADF));
    assert_eq!(ECHO_SIGNALS.map(disposition), before);
    assert_eq!(termios::tcgetattr(&pty.slave).unwrap(), saved);
    drop(EchoOff::enter(pty.slave.as_raw_fd()).unwrap());
}

#[test]
fn nested_echo_off_refuses_without_changing_the_first_guard() {
    let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let pty = openpty(None, None).unwrap();
    let saved = termios::tcgetattr(&pty.slave).unwrap();
    let first = EchoOff::enter(pty.slave.as_raw_fd()).unwrap();
    assert_eq!(
        EchoOff::enter(pty.slave.as_raw_fd()).err(),
        Some(nix::Error::EBUSY)
    );
    assert!(!termios::tcgetattr(&pty.slave)
        .unwrap()
        .local_flags
        .contains(termios::LocalFlags::ECHO));
    drop(first);
    assert_eq!(termios::tcgetattr(&pty.slave).unwrap(), saved);
    drop(EchoOff::enter(pty.slave.as_raw_fd()).unwrap());
}

#[test]
fn concurrent_contenders_leave_both_terminals_untouched() {
    let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    let first = openpty(None, None).unwrap();
    let other = openpty(None, None).unwrap();
    let before_first = termios::tcgetattr(&first.slave).unwrap();
    let before_other = termios::tcgetattr(&other.slave).unwrap();
    let holder = EchoOff::enter(first.slave.as_raw_fd()).unwrap();
    let quiet_first = termios::tcgetattr(&first.slave).unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(9));
    std::thread::scope(|scope| {
        let contenders: Vec<_> = (0..8)
            .map(|index| {
                let barrier = barrier.clone();
                let fd = if index % 2 == 0 {
                    first.slave.as_raw_fd()
                } else {
                    other.slave.as_raw_fd()
                };
                scope.spawn(move || {
                    barrier.wait();
                    assert_eq!(EchoOff::enter(fd).err(), Some(nix::Error::EBUSY));
                })
            })
            .collect();
        barrier.wait();
        for contender in contenders {
            contender.join().unwrap();
        }
    });
    assert_eq!(termios::tcgetattr(&first.slave).unwrap(), quiet_first);
    assert_eq!(termios::tcgetattr(&other.slave).unwrap(), before_other);
    drop(holder);
    assert_eq!(termios::tcgetattr(&first.slave).unwrap(), before_first);
    drop(EchoOff::enter(other.slave.as_raw_fd()).unwrap());
}

#[test]
fn invalid_descriptor_releases_echo_claim_before_any_handler_is_installed() {
    let _serial = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(EchoOff::enter(-1).err(), Some(nix::Error::EBADF));
    let pty = openpty(None, None).unwrap();
    drop(EchoOff::enter(pty.slave.as_raw_fd()).unwrap());
}

#[test]
fn queued_signal_before_release_is_captured_by_the_owner() {
    let state = AtomicU32::new(ECHO_ACTIVE | ECHO_BUSY);
    let bit = echo_signal_bit(libc::SIGTERM);
    assert_eq!(
        echo_signal_claim(&state, bit, ECHO_ACTIVE | ECHO_BUSY),
        None
    );
    assert_eq!(
        state.swap(ECHO_ACTIVE, Ordering::AcqRel),
        ECHO_ACTIVE | ECHO_BUSY | bit
    );
    assert_eq!(state.load(Ordering::Acquire), ECHO_ACTIVE);
}

#[test]
fn signal_after_release_observation_retries_and_acquires_the_gate() {
    let state = AtomicU32::new(ECHO_ACTIVE | ECHO_BUSY);
    let observed = state.load(Ordering::Acquire);
    state.swap(ECHO_ACTIVE, Ordering::AcqRel);
    assert_eq!(
        echo_signal_claim(&state, echo_signal_bit(libc::SIGTERM), observed),
        Some(ECHO_ACTIVE)
    );
    assert_eq!(
        state.swap(ECHO_ACTIVE, Ordering::AcqRel),
        ECHO_ACTIVE | ECHO_BUSY
    );
}

#[test]
fn signal_after_teardown_observation_cannot_read_old_active_payload() {
    let state = AtomicU32::new(ECHO_ACTIVE | ECHO_BUSY);
    let observed = state.load(Ordering::Acquire);
    state.swap(0, Ordering::AcqRel);
    assert_eq!(
        echo_signal_claim(&state, echo_signal_bit(libc::SIGTERM), observed),
        Some(0)
    );
    assert_eq!(state.load(Ordering::Acquire), ECHO_BUSY);
}

#[cfg(target_os = "linux")]
mod owned {
    use super::*;
    use std::fs::File;
    use std::io::{ErrorKind, Read};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const CASE: &str = "QSH_ECHO_OWNERSHIP_CASE";
    static CUSTOM: AtomicU32 = AtomicU32::new(0);
    static REPLAY_COUNT: AtomicU32 = AtomicU32::new(0);
    static REPLAY_DEPTH: AtomicU32 = AtomicU32::new(0);
    static REPLAY_MAX_DEPTH: AtomicU32 = AtomicU32::new(0);

    extern "C" fn replay_again(sig: libc::c_int) {
        let depth = REPLAY_DEPTH.fetch_add(1, Ordering::Relaxed) + 1;
        REPLAY_MAX_DEPTH.fetch_max(depth, Ordering::Relaxed);
        if REPLAY_COUNT.fetch_add(1, Ordering::Relaxed) < 127 {
            echo_replay(echo_signal_bit(sig));
        }
        REPLAY_DEPTH.fetch_sub(1, Ordering::Relaxed);
    }

    extern "C" fn custom(_sig: libc::c_int) {
        CUSTOM.fetch_add(1, Ordering::Relaxed);
    }

    struct Owned(Child);
    impl Drop for Owned {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn drain(master: &mut File, output: &mut Vec<u8>) {
        loop {
            let mut buffer = [0; 1024];
            match master.read(&mut buffer) {
                Ok(0) => return,
                Ok(n) => {
                    output.extend_from_slice(&buffer[..n]);
                    assert!(output.len() < 32 * 1024, "owned fixture output bound");
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == ErrorKind::WouldBlock => return,
                Err(e) if e.raw_os_error() == Some(libc::EIO) => return,
                Err(e) => panic!("owned PTY read: {e}"),
            }
        }
    }

    fn run(case: &str) {
        let home = tempfile::tempdir().unwrap();
        let pty = openpty(None, None).unwrap();
        let saved = termios::tcgetattr(&pty.slave).unwrap();
        let mut master = File::from(pty.master);
        let fd = master.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "tty::echo_ownership_tests::owned::child_process",
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
        // A separate process group in the parent's session is non-orphaned,
        // so default SIGTSTP really stops this owned child (not a setsid skip).
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = Owned(command.spawn().unwrap());
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut output = Vec::new();
        let mut stopped = false;
        let status = loop {
            drain(&mut master, &mut output);
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            if !stopped {
                let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
                // WNOWAIT observes the stop without reaping/stealing Child's
                // exit ownership. No signal is sent after Child reaps it.
                let observed = unsafe {
                    libc::waitid(
                        libc::P_PID,
                        child.0.id(),
                        &mut info,
                        libc::WSTOPPED | libc::WNOHANG | libc::WNOWAIT,
                    )
                };
                if observed == 0 && info.si_code == libc::CLD_STOPPED {
                    assert_eq!(unsafe { info.si_status() }, libc::SIGTSTP);
                    assert!(
                        termios::tcgetattr(&pty.slave)
                            .unwrap()
                            .local_flags
                            .contains(termios::LocalFlags::ECHO),
                        "echo must be restored while actually stopped"
                    );
                    assert_eq!(unsafe { libc::kill(child.0.id() as i32, libc::SIGCONT) }, 0);
                    stopped = true;
                }
            }
            assert!(
                Instant::now() < deadline,
                "owned {case} did not complete: {}",
                String::from_utf8_lossy(&output)
            );
            std::thread::sleep(Duration::from_millis(5));
        };
        drain(&mut master, &mut output);
        assert!(
            status.success(),
            "owned {case}: {}",
            String::from_utf8_lossy(&output)
        );
        assert_eq!(stopped, case != "replay", "unexpected real-stop evidence");
        assert!(String::from_utf8_lossy(&output).contains("ECHO-OWNERSHIP-DONE"));
        assert_eq!(termios::tcgetattr(&pty.slave).unwrap(), saved);
    }

    #[test]
    fn blocked_owner_replays_delivered_signal_and_restores_exact_mask() {
        run("blocked");
    }

    #[test]
    fn stop_continue_with_competing_drop_allows_clean_reentry() {
        run("drop");
    }

    #[test]
    fn synchronous_replay_waves_are_iterative_and_restore_the_mask() {
        run("replay");
    }

    #[test]
    fn child_process() {
        let Ok(case) = std::env::var(CASE) else {
            return;
        };
        assert_eq!(unsafe { libc::isatty(0) }, 1);
        let mut old_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&mut blocked);
            libc::sigaddset(&mut blocked, libc::SIGTSTP);
            libc::sigaddset(&mut blocked, libc::SIGUSR2);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, &mut old_mask),
                0
            );
        }
        if case == "replay" {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = replay_again as extern "C" fn(libc::c_int) as libc::sighandler_t;
            action.sa_flags = libc::SA_NODEFER;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(
                    libc::sigaction(libc::SIGTSTP, &action, std::ptr::null_mut()),
                    0
                );
            }
            echo_replay(echo_signal_bit(libc::SIGTSTP));
            assert_eq!(REPLAY_COUNT.load(Ordering::Relaxed), 128);
            assert_eq!(REPLAY_MAX_DEPTH.load(Ordering::Relaxed), 1);
            assert_eq!(ECHO_REPLAY.load(Ordering::Relaxed), 0);
            let mut now: libc::sigset_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut now) },
                0
            );
            assert_eq!(unsafe { libc::sigismember(&now, libc::SIGTSTP) }, 1);
            assert_eq!(unsafe { libc::sigismember(&now, libc::SIGUSR2) }, 1);
            println!("ECHO-OWNERSHIP-DONE");
            return;
        }
        CHECK_RESUME.store(true, Ordering::Release);
        let mut prior: libc::sigaction = unsafe { std::mem::zeroed() };
        if case == "blocked" {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = custom as extern "C" fn(libc::c_int) as libc::sighandler_t;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
                assert_eq!(libc::sigaction(libc::SIGTSTP, &action, &mut prior), 0);
            }
        }
        let guard = EchoOff::enter(0).unwrap();
        assert_eq!(
            ECHO_SLOT.state.compare_exchange(
                ECHO_ACTIVE,
                ECHO_ACTIVE | ECHO_BUSY,
                Ordering::Acquire,
                Ordering::Relaxed
            ),
            Ok(ECHO_ACTIVE)
        );
        let (queued_tx, queued_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let delivered = std::thread::spawn(move || {
            let mut one: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                libc::sigemptyset(&mut one);
                libc::sigaddset(&mut one, libc::SIGTSTP);
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_UNBLOCK, &one, std::ptr::null_mut()),
                    0
                );
                assert_eq!(libc::raise(libc::SIGTSTP), 0);
            }
            queued_tx.send(()).unwrap();
            done_rx.recv().unwrap();
        });
        queued_rx.recv().unwrap();
        assert!(ECHO_SLOT.state.load(Ordering::Acquire) & echo_signal_bit(libc::SIGTSTP) != 0);
        if case == "drop" {
            let (started_tx, started_rx) = mpsc::channel();
            let dropping = std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                drop(guard);
            });
            started_rx.recv().unwrap();
            echo_release(ECHO_ACTIVE);
            dropping.join().unwrap();
            drop(EchoOff::enter(0).unwrap());
        } else {
            echo_release(ECHO_ACTIVE);
            let mut now: libc::sigset_t = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &mut now) },
                0
            );
            assert_eq!(unsafe { libc::sigismember(&now, libc::SIGTSTP) }, 1);
            assert_eq!(unsafe { libc::sigismember(&now, libc::SIGUSR2) }, 1);
            let borrowed = unsafe { BorrowedFd::borrow_raw(0) };
            assert!(!termios::tcgetattr(borrowed)
                .unwrap()
                .local_flags
                .contains(termios::LocalFlags::ECHO));
            assert_eq!(
                RESUME_CHECKED.load(Ordering::Relaxed),
                1,
                "actual stop/CONT must check handler before quiet"
            );
            drop(guard);
            let saved_errno = libc::ERANGE;
            nix::errno::Errno::set_raw(saved_errno);
            restore_and_reraise(libc::SIGTSTP); // old selected callback, now inactive
            assert_eq!(nix::errno::Errno::last_raw(), saved_errno);
            assert_eq!(
                CUSTOM.load(Ordering::Acquire),
                1,
                "current custom disposition must be used"
            );
            unsafe {
                libc::sigaction(libc::SIGTSTP, &prior, std::ptr::null_mut());
            }
        }
        done_tx.send(()).unwrap();
        delivered.join().unwrap();
        assert_eq!(
            unsafe { libc::pthread_sigmask(libc::SIG_SETMASK, &old_mask, std::ptr::null_mut()) },
            0
        );
        println!("ECHO-OWNERSHIP-DONE");
    }
}
