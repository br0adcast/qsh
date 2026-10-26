//! Foreground job control and deferred signals while RawMode owns the terminal.
//!
//! A signal handler runs at an arbitrary point in the program, so almost
//! nothing is safe to call from one: allocating, locking a mutex or printing
//! are all ways to deadlock rarely and unreproducibly. Storing into an
//! lock-free atomic is safe. A late suspend callback may also forward through
//! the current disposition using signal-safe libc::raise.
//!
//! `SA_RESTART` is deliberately NOT set: a blocked read of stdin returning
//! `EINTR` is how the loop learns to look at these flags at all.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};

static RESIZED: AtomicBool = AtomicBool::new(false);
static RESUMED: AtomicBool = AtomicBool::new(false);
static TERMINATE: AtomicBool = AtomicBool::new(false);
// The low bits are fixed policy flags; high bits are a non-wrapping owner
// generation. An old Saved guard cannot restore a replacement's disposition.
const DEFERRED: u64 = 1;
const PENDING: u64 = 2;
const POISONED: u64 = 4;
const FLAGS: u64 = 7;
static SUSPEND: AtomicU64 = AtomicU64::new(0);

/// What arrived since the last look. `terminate` is a GROUP: SIGTERM,
/// SIGHUP, SIGINT and SIGQUIT all mean the same thing to this program --
/// close the session and put the terminal back -- and the loop has nothing
/// to do differently for any of them.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Pending {
    pub resized: bool,
    pub resumed: bool,
    pub terminate: bool,
    /// SIGTSTP: the terminal is to be handed back before the process stops
    /// ([`stop`]).
    pub suspend: bool,
}

extern "C" fn on_winch(_: libc::c_int) {
    RESIZED.store(true, Ordering::SeqCst);
    crate::signal_wake::notify();
}

extern "C" fn on_cont(_: libc::c_int) {
    RESUMED.store(true, Ordering::SeqCst);
    crate::signal_wake::notify();
}

extern "C" fn on_terminate(_: libc::c_int) {
    TERMINATE.store(true, Ordering::SeqCst);
    crate::signal_wake::notify();
}

extern "C" fn on_tstp(_: libc::c_int) {
    let errno = nix::errno::Errno::last_raw();
    let mut observed = SUSPEND.load(Ordering::SeqCst);
    loop {
        if observed & DEFERRED == 0 {
            // Selected before policy teardown, delivered after it: do not
            // restore an old handler. The current default/EchoOff/raw owner
            // handles replay after this callback returns and unblocks TSTP.
            if unsafe { libc::raise(libc::SIGTSTP) } != 0 {
                unsafe { libc::_exit(128 + libc::SIGTSTP) };
            }
            break;
        }
        match SUSPEND.compare_exchange(
            observed,
            observed | PENDING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(_) => {
                crate::signal_wake::notify();
                break;
            }
            Err(current) => observed = current,
        }
    }
    nix::errno::Errno::set_raw(errno);
}

#[cfg(test)]
#[path = "signals/suspend_tests.rs"]
pub(crate) mod suspend_tests;

fn set_tstp(handler: SigHandler) -> Result<SigAction, nix::Error> {
    #[cfg(test)]
    suspend_tests::before_action(handler)?;
    unsafe { signal::sigaction(Signal::SIGTSTP, &action(handler)) }
}

/// The disposition every handler here is installed with. Empty flags on
/// purpose: with `SA_RESTART` a blocked read would resume instead of
/// returning EINTR, and the loop would not notice the signal until the user
/// pressed a key.
fn action(handler: SigHandler) -> SigAction {
    SigAction::new(handler, SaFlags::empty(), SigSet::empty())
}

#[cfg(test)]
pub(crate) static INSTALL_FAILURE: std::sync::atomic::AtomicI32 =
    std::sync::atomic::AtomicI32::new(0);
fn install_common(signal: Signal, handler: SigHandler) -> Result<SigAction, nix::Error> {
    #[cfg(test)]
    if INSTALL_FAILURE
        .compare_exchange(signal as i32, 0, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        return Err(nix::Error::EIO);
    }
    unsafe { signal::sigaction(signal, &action(handler)) }
}

/// Installs the handlers. Idempotent -- installing twice is the same as once.
pub fn install() -> Result<(), nix::Error> {
    if SUSPEND.load(Ordering::SeqCst) & FLAGS != 0 {
        return Err(nix::Error::EBUSY);
    }
    crate::signal_wake::initialize()?;
    // SAFETY: handlers use lock-free atomics; late TSTP callbacks forward
    // only with signal-safe libc calls and preserve errno.
    install_common(Signal::SIGWINCH, SigHandler::Handler(on_winch))?;
    install_common(Signal::SIGCONT, SigHandler::Handler(on_cont))?;
    install_common(Signal::SIGTERM, SigHandler::Handler(on_terminate))?;
    install_common(Signal::SIGHUP, SigHandler::Handler(on_terminate))?;
    // SIGINT and SIGQUIT belong here for one reason: their DEFAULT
    // disposition ends the process on the spot, running neither `Drop`,
    // nor the panic hook, nor `restore()` -- leaving exactly the broken
    // shell `tty.rs` exists to prevent. Raw mode has `ISIG` off, so
    // neither can arrive from the keyboard while the client is running;
    // routing them here therefore shadows no keystroke and costs
    // nothing, while covering `kill -INT` and a Ctrl-C that lands in the
    // window before raw mode is on.
    install_common(Signal::SIGINT, SigHandler::Handler(on_terminate))?;
    install_common(Signal::SIGQUIT, SigHandler::Handler(on_terminate))?;
    // Cooked foreground phases may block in DNS/SSH without a polling
    // loop. RawMode installs the narrower deferred policy before raw mode.
    set_tstp(SigHandler::SigDfl)?;

    Ok(())
}

/// Borrow the fixed process-lifetime notification descriptor; callers never close it.
pub fn notification_fd() -> std::io::Result<std::os::fd::RawFd> {
    crate::signal_wake::read_fd()
}
/// Drain bytes without consuming authoritative signal flags. EOF is a fault.
pub fn drain_notifications() -> std::io::Result<()> {
    crate::signal_wake::drain()
}
/// Raw fixed failure codes, formatted only by the ordinary terminal owner.
pub fn notification_failure() -> Option<(i32, i32)> {
    crate::signal_wake::failure()
}

/// Read-only park recheck; only the UI owner consumes these flags.
pub fn has_pending() -> bool {
    RESIZED.load(Ordering::SeqCst)
        || RESUMED.load(Ordering::SeqCst)
        || TERMINATE.load(Ordering::SeqCst)
        || SUSPEND.load(Ordering::SeqCst) & PENDING != 0
}

/// Replay only TSTP, even if the terminal owner originally blocked it.
/// The request may have been handled on another unblocked thread. Preserve
/// all other mask bits and errno, including across a real stop/continue.
fn replay_tstp() -> Result<(), nix::Error> {
    let errno = nix::errno::Errno::last_raw();
    let result = unsafe {
        let mut one: libc::sigset_t = std::mem::zeroed();
        let mut saved: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut one);
        libc::sigaddset(&mut one, libc::SIGTSTP);
        let unblocked = libc::pthread_sigmask(libc::SIG_UNBLOCK, &one, &mut saved);
        if unblocked != 0 {
            Err(nix::Error::from_raw(unblocked))
        } else {
            let raised = signal::raise(Signal::SIGTSTP);
            let restored = libc::pthread_sigmask(libc::SIG_SETMASK, &saved, std::ptr::null_mut());
            if restored != 0 {
                Err(nix::Error::from_raw(restored))
            } else {
                raised
            }
        }
    };
    nix::errno::Errno::set_raw(errno);
    result
}

/// Stops the process as SIGTSTP's own default would, and returns once it is
/// continued (SIGCONT, which also sets `resumed`). The loop calls it after
/// handing the terminal back; the handler is put back afterwards.
///
/// A process group the kernel counts as orphaned -- one no shell of the same
/// session could ever continue -- is not stopped by SIGTSTP at all: this then
/// returns at once, and the loop comes straight back.
pub(crate) fn stop(generation: u64) -> Result<(), nix::Error> {
    validate_deferred(generation)?;
    set_tstp(SigHandler::SigDfl)?;
    replay_tstp()?;
    // A continued old caller may not overwrite a replacement or EchoOff owner.
    validate_deferred(generation)?;
    set_tstp(SigHandler::Handler(on_tstp))?;
    Ok(())
}

fn validate_deferred(generation: u64) -> Result<(), nix::Error> {
    let observed = SUSPEND.load(Ordering::SeqCst);
    if observed & !FLAGS == generation && observed & (DEFERRED | POISONED) == DEFERRED {
        Ok(())
    } else {
        Err(nix::Error::EINVAL)
    }
}

/// The single non-clone suspend-policy owner, held by tty::Saved. Dropping
/// without confirmed cooked restoration poisons fixed state rather than enabling
/// an unsafe default stop. No descriptor is stored in this policy state.
pub(crate) struct DeferredSuspend {
    generation: u64,
    finished: bool,
}

impl DeferredSuspend {
    pub(crate) fn enter() -> Result<Self, nix::Error> {
        let observed = SUSPEND.load(Ordering::SeqCst);
        if observed & FLAGS != 0 {
            return Err(nix::Error::EBUSY);
        }
        let generation = observed
            .checked_add(FLAGS + 1)
            .ok_or(nix::Error::EOVERFLOW)?;
        SUSPEND
            .compare_exchange(
                observed,
                generation | DEFERRED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .map_err(|_| nix::Error::EBUSY)?;
        let owner = Self {
            generation,
            finished: false,
        };
        // This conventional handler-before-raw ordering cannot recall a kernel
        // default action already selected on another thread before installation.
        if let Err(error) = set_tstp(SigHandler::Handler(on_tstp)) {
            let _ = owner.finish_cooked();
            return Err(error);
        }
        Ok(owner)
    }

    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    pub(crate) fn finish_cooked(mut self) -> Result<(), nix::Error> {
        let mut observed = SUSPEND.load(Ordering::SeqCst);
        if observed & !FLAGS != self.generation || observed & (DEFERRED | POISONED) != DEFERRED {
            return Err(nix::Error::EINVAL);
        }
        // Called only after a successful termios restore, outside Saved's lock.
        set_tstp(SigHandler::SigDfl)?;
        loop {
            if observed & !FLAGS != self.generation || observed & (DEFERRED | POISONED) != DEFERRED
            {
                return Err(nix::Error::EINVAL);
            }
            match SUSPEND.compare_exchange(
                observed,
                self.generation,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        self.finished = true;
        if observed & PENDING != 0 {
            if let Err(error) = replay_tstp() {
                // Cooked is confirmed, but this failed owner cannot reenter.
                let _ = SUSPEND.compare_exchange(
                    self.generation,
                    self.generation | DEFERRED | POISONED,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                );
                return Err(error);
            }
        }
        Ok(())
    }

    pub(crate) fn is_poisoned(generation: u64) -> bool {
        let observed = SUSPEND.load(Ordering::SeqCst);
        observed & !FLAGS == generation && observed & POISONED != 0
    }
}

impl Drop for DeferredSuspend {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        let mut observed = SUSPEND.load(Ordering::SeqCst);
        while observed & !FLAGS == self.generation && observed & DEFERRED != 0 {
            match SUSPEND.compare_exchange(
                observed,
                observed | POISONED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
    }
}

/// Whether termination was requested, without consuming the interactive loop's flag.
pub fn termination_requested() -> bool {
    TERMINATE.load(Ordering::SeqCst)
}

/// Keeps a cancellation token synchronized with termination for one foreground operation.
/// The scoped watcher stops on every return or panic and is joined before this returns.
pub fn with_termination_cancel<T>(cancel: &knock::Cancel, operation: impl FnOnce() -> T) -> T {
    let done = AtomicBool::new(false);
    std::thread::scope(|scope| {
        struct StopWatcher<'a>(&'a AtomicBool);
        impl Drop for StopWatcher<'_> {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }
        let _stop = StopWatcher(&done);
        scope.spawn(|| {
            while !done.load(Ordering::SeqCst) {
                if termination_requested() {
                    cancel.cancel();
                    break;
                }
                std::thread::sleep(knock::SLICE);
            }
        });
        operation()
    })
}

/// Reads and clears the flags.
pub fn take_pending() -> Pending {
    Pending {
        resized: RESIZED.swap(false, Ordering::SeqCst),
        resumed: RESUMED.swap(false, Ordering::SeqCst),
        terminate: TERMINATE.swap(false, Ordering::SeqCst),
        suspend: SUSPEND.fetch_and(!PENDING, Ordering::SeqCst) & PENDING != 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::sys::signal::{raise, Signal};

    #[test]
    fn termination_cancels_the_wait_for_a_silent_dns_lookup() {
        let _serial = ONE_AT_A_TIME
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        install().unwrap();
        let _ = take_pending();
        let cancel = knock::Cancel::new();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            scope.spawn(move || {
                started_rx
                    .recv_timeout(std::time::Duration::from_secs(2))
                    .unwrap();
                raise(Signal::SIGINT).unwrap();
            });
            let start = std::time::Instant::now();
            let result = with_termination_cancel(&cancel, || {
                knock::resolve_with("test.invalid", &cancel, knock::RESOLVE_BUDGET, move |_| {
                    started_tx.send(()).unwrap();
                    release_rx
                        .recv_timeout(std::time::Duration::from_secs(2))
                        .unwrap();
                    done_tx.send(()).unwrap();
                    Ok(vec!["127.0.0.1:0".parse().unwrap()])
                })
            });
            let elapsed = start.elapsed();
            let terminated = take_pending().terminate;
            release_tx.send(()).unwrap();
            done_rx
                .recv_timeout(std::time::Duration::from_secs(1))
                .unwrap();
            assert!(matches!(result, Err(knock::KnockError::Cancelled)));
            assert!(elapsed < std::time::Duration::from_secs(1));
            assert!(
                terminated,
                "the foreground watcher must preserve the interactive signal flag"
            );
        });
    }

    /// These tests install process-wide handlers and raise real signals, so
    /// they cannot run beside each other -- nor beside the echo tests, which
    /// swap the same handlers: one lock for all of them,
    /// `crate::tty::SIGNAL_TESTS`.
    use crate::tty::SIGNAL_TESTS as ONE_AT_A_TIME;

    /// These tests use `raise()`, not `kill(getpid(), _)`: `cargo test` runs
    /// every test on its own OS thread, and `kill()` targets the whole
    /// process, so the kernel is free to deliver to any thread that has not
    /// blocked the signal -- not necessarily the one that called `kill()`.
    /// That left the flag still `false` right after `kill()` returned in this
    /// harness. `raise()` is `pthread_kill(pthread_self(), _)`: it names the
    /// calling thread, so delivery happens before the call returns.
    ///
    /// Sending ourselves the signal must be visible to the loop. This is the
    /// whole contract: the handler sets a flag, the loop reads it.
    #[test]
    fn a_window_change_is_recorded() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        raise(Signal::SIGWINCH).expect("raise");
        let pending = take_pending();
        assert!(pending.resized, "SIGWINCH must be seen");
    }

    /// Taking clears: a flag that stays set makes the loop repaint forever.
    #[test]
    fn taking_the_flags_clears_them() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        raise(Signal::SIGWINCH).expect("raise");
        assert!(take_pending().resized);
        assert!(!take_pending().resized, "the second read must be clean");
    }

    /// Terminate has to come through as its own flag: the loop closes the
    /// session and restores the terminal rather than dying where it stands.
    #[test]
    fn a_termination_request_is_recorded() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        raise(Signal::SIGTERM).expect("raise");
        assert!(take_pending().terminate, "SIGTERM must be seen, not fatal");
    }

    /// SIGINT must not be fatal either. Its default disposition kills the
    /// process without running `Drop`, the panic hook or `restore()`, and
    /// the user is left with a terminal in raw mode -- the failure this
    /// whole module and `tty.rs` exist to avoid.
    #[test]
    fn an_interrupt_is_recorded_rather_than_fatal() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        raise(Signal::SIGINT).expect("raise");
        assert!(take_pending().terminate, "SIGINT must be seen, not fatal");
    }

    /// And SIGQUIT, for the same reason -- with a core dump on top of the
    /// raw terminal if it is left at its default.
    #[test]
    fn a_quit_is_recorded_rather_than_fatal() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        raise(Signal::SIGQUIT).expect("raise");
        assert!(take_pending().terminate, "SIGQUIT must be seen, not fatal");
    }

    #[test]
    fn foreground_install_uses_default_stop_even_without_a_polling_loop() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().unwrap();
        let current = unsafe {
            let mut current: libc::sigaction = std::mem::zeroed();
            assert_eq!(
                libc::sigaction(libc::SIGTSTP, std::ptr::null(), &mut current),
                0
            );
            current.sa_sigaction
        };
        assert_eq!(
            current,
            libc::SIG_DFL,
            "foreground blocking work must stop without polling"
        );
    }

    #[test]
    fn foreground_policy_preserves_other_signal_owners() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        raise(Signal::SIGWINCH).unwrap();
        raise(Signal::SIGCONT).unwrap();
        raise(Signal::SIGINT).unwrap();
        assert!(termination_requested(), "cancellation must remain visible");
        let pending = take_pending();
        assert!(pending.resized && pending.resumed && pending.terminate);
        assert!(!pending.suspend);
    }

    /// A stop request is caught, not obeyed on the spot: the loop hands the
    /// terminal back first.
    #[test]
    fn a_stop_request_is_recorded_rather_than_obeyed() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        let owner = DeferredSuspend::enter().unwrap();
        raise(Signal::SIGTSTP).expect("raise");
        let pending = take_pending();
        assert!(pending.suspend, "SIGTSTP must be seen");
        assert!(!take_pending().suspend, "and taken once");
        owner.finish_cooked().unwrap();
    }

    /// Coming back from the background is its own event: the terminal was
    /// someone else's while we were stopped.
    #[test]
    fn a_resume_is_recorded() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        raise(Signal::SIGCONT).expect("raise");
        assert!(take_pending().resumed, "SIGCONT must be seen");
    }
}
