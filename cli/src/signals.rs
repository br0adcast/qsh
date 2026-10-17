//! Signals, reduced to four flags the main loop reads at its own pace.
//!
//! A signal handler runs at an arbitrary point in the program, so almost
//! nothing is safe to call from one: allocating, locking a mutex or printing
//! are all ways to deadlock rarely and unreproducibly. Storing into an
//! `AtomicBool` is safe, so that is all the handlers do.
//!
//! `SA_RESTART` is deliberately NOT set: a blocked read of stdin returning
//! `EINTR` is how the loop learns to look at these flags at all.

use std::sync::atomic::{AtomicBool, Ordering};

use nix::sys::signal::{self, SaFlags, SigAction, SigHandler, SigSet, Signal};

static RESIZED: AtomicBool = AtomicBool::new(false);
static RESUMED: AtomicBool = AtomicBool::new(false);
static TERMINATE: AtomicBool = AtomicBool::new(false);
static SUSPEND: AtomicBool = AtomicBool::new(false);

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
}

extern "C" fn on_cont(_: libc::c_int) {
    RESUMED.store(true, Ordering::SeqCst);
}

extern "C" fn on_terminate(_: libc::c_int) {
    TERMINATE.store(true, Ordering::SeqCst);
}

extern "C" fn on_tstp(_: libc::c_int) {
    SUSPEND.store(true, Ordering::SeqCst);
}

/// The disposition every handler here is installed with. Empty flags on
/// purpose: with `SA_RESTART` a blocked read would resume instead of
/// returning EINTR, and the loop would not notice the signal until the user
/// pressed a key.
fn action(handler: SigHandler) -> SigAction {
    SigAction::new(handler, SaFlags::empty(), SigSet::empty())
}

/// Installs the handlers. Idempotent -- installing twice is the same as once.
pub fn install() -> Result<(), nix::Error> {
    // SAFETY: every handler only stores into a static AtomicBool, which is
    // async-signal-safe.
    unsafe {
        signal::sigaction(Signal::SIGWINCH, &action(SigHandler::Handler(on_winch)))?;
        signal::sigaction(Signal::SIGCONT, &action(SigHandler::Handler(on_cont)))?;
        signal::sigaction(Signal::SIGTERM, &action(SigHandler::Handler(on_terminate)))?;
        signal::sigaction(Signal::SIGHUP, &action(SigHandler::Handler(on_terminate)))?;
        // SIGINT and SIGQUIT belong here for one reason: their DEFAULT
        // disposition ends the process on the spot, running neither `Drop`,
        // nor the panic hook, nor `restore()` -- leaving exactly the broken
        // shell `tty.rs` exists to prevent. Raw mode has `ISIG` off, so
        // neither can arrive from the keyboard while the client is running;
        // routing them here therefore shadows no keystroke and costs
        // nothing, while covering `kill -INT` and a Ctrl-C that lands in the
        // window before raw mode is on.
        signal::sigaction(Signal::SIGINT, &action(SigHandler::Handler(on_terminate)))?;
        signal::sigaction(Signal::SIGQUIT, &action(SigHandler::Handler(on_terminate)))?;
        // SIGTSTP's default stops the process on the spot, with the
        // terminal still raw and on the alternate screen, under the shell
        // that takes it over. Caught, it is the loop that stops the process
        // ([`stop`]), once the terminal is handed back. Raw mode has `ISIG`
        // off, so a `Ctrl-Z` is a byte for the remote side, as before: this
        // is `kill -TSTP`.
        signal::sigaction(Signal::SIGTSTP, &action(SigHandler::Handler(on_tstp)))?;
    }
    Ok(())
}

/// Stops the process as SIGTSTP's own default would, and returns once it is
/// continued (SIGCONT, which also sets `resumed`). The loop calls it after
/// handing the terminal back; the handler is put back afterwards.
///
/// A process group the kernel counts as orphaned -- one no shell of the same
/// session could ever continue -- is not stopped by SIGTSTP at all: this then
/// returns at once, and the loop comes straight back.
pub fn stop() {
    // SAFETY: the default disposition and back to our handler, which only
    // stores into a static AtomicBool; `raise` names the calling thread, so
    // the stop happens before it returns.
    unsafe {
        let _ = signal::sigaction(Signal::SIGTSTP, &action(SigHandler::SigDfl));
        let _ = signal::raise(Signal::SIGTSTP);
        let _ = signal::sigaction(Signal::SIGTSTP, &action(SigHandler::Handler(on_tstp)));
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
        suspend: SUSPEND.swap(false, Ordering::SeqCst),
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

    /// A stop request is caught, not obeyed on the spot: the loop hands the
    /// terminal back first.
    #[test]
    fn a_stop_request_is_recorded_rather_than_obeyed() {
        let _serial = ONE_AT_A_TIME.lock().unwrap_or_else(|e| e.into_inner());
        install().expect("install");
        let _ = take_pending();
        raise(Signal::SIGTSTP).expect("raise");
        let pending = take_pending();
        assert!(pending.suspend, "SIGTSTP must be seen");
        assert!(!take_pending().suspend, "and taken once");
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
