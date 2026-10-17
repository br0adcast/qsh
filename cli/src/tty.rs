//! The local terminal: raw mode, and getting out of it no matter how the
//! program ends.
//!
//! A terminal left in raw mode is a broken shell -- no echo, no line
//! editing, `Ctrl-C` delivered as a byte instead of a signal. The user
//! usually does not know that `reset` fixes it; they close the window. So
//! restoration is wired three ways: the ordinary path calls `restore`,
//! `Drop` catches an early return, and a panic hook catches the rest.
//! `Drop` alone is not enough: it does not run on `std::process::exit`, and
//! it does not run at all under `panic = "abort"`.
//!
//! While raw mode is on, the terminal belongs to the renderer, and a line
//! anything else writes to stderr would land over the frame with no line
//! breaks. So a guard can also set stderr aside for as long as raw mode
//! lasts ([`RawMode::set_stderr_aside`]): fd 2 points somewhere else, and
//! every way out of raw mode puts the original back first. The client points
//! it into the log ([`RawMode::set_stderr_to_log`]): each line becomes a
//! record of its own.
//!
//! The session is drawn on the terminal's alternate screen
//! ([`RawMode::enter_alternate_screen`]), so that once it is over the
//! terminal shows what it showed before -- and the lines the client printed
//! on its way in -- rather than the last picture of the remote screen. Every
//! way out of raw mode switches back first, before anything meant to stay on
//! the terminal's own screen is printed; a stop ([`RawMode::suspend`])
//! switches back too, and [`RawMode::reenter`] comes back to it.

use std::cell::UnsafeCell;
use std::fs::File;
use std::io::Read;
use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::Mutex;
use std::thread::ThreadId;
use std::time::Duration;

use nix::sys::termios::{self, SetArg, Termios};

/// What a panic hook needs to put the terminal back. A hook runs on
/// whichever thread panicked, so this cannot live in the guard.
struct Saved {
    fd: RawFd,
    termios: Termios,
    /// The thread that entered raw mode: the only one whose panic ends the
    /// session, and so the only one whose panic may touch the terminal.
    thread: ThreadId,
    /// The original stderr while it is set aside; taken by whichever way
    /// out of raw mode runs first.
    stderr: Option<OwnedFd>,
    /// The alternate screen, once it has been entered.
    alt: Option<AltScreen>,
}

/// Where the alternate screen was entered, and whether the terminal is on it
/// now: a stop switches back to the terminal's own screen and remembers to
/// come back.
#[derive(Clone, Copy)]
struct AltScreen {
    out: RawFd,
    on: bool,
}

/// Switches the terminal to its alternate screen, saving the cursor.
const ALT_SCREEN_ON: &[u8] = b"\x1b[?1049h";
/// Switches back to the terminal's own screen, and puts the cursor back.
const ALT_SCREEN_OFF: &[u8] = b"\x1b[?1049l";

/// Writes all of `bytes` to `fd`, straight to the descriptor: a panic hook
/// must not wait on a lock of `std::io::stdout` its own thread may hold. A
/// failure gives up quietly -- there is nowhere to report it.
fn write_fd(fd: RawFd, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        // SAFETY: `bytes` is valid for `len` bytes; `fd` is the caller's.
        let n = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if n > 0 {
            bytes = &bytes[n as usize..];
        } else if n < 0 && nix::Error::last() == nix::Error::EINTR {
            continue;
        } else {
            return;
        }
    }
}

/// Switches back to the terminal's own screen, when it is on the alternate
/// one; `alt` remembers where it was entered.
fn leave_alt_screen(alt: &mut Option<AltScreen>) {
    if let Some(a) = alt.as_mut().filter(|a| a.on) {
        write_fd(a.out, ALT_SCREEN_OFF);
        a.on = false;
    }
}

/// The settings to put back, kept where a panic hook can reach them.
static SAVED: Mutex<Option<Saved>> = Mutex::new(None);

/// What the panic hook does, by where the panic happened.
#[derive(Debug, PartialEq, Eq)]
enum OnPanic {
    /// Raw mode is off: the message goes out as usual.
    Print,
    /// The thread that entered raw mode panicked, so the session is over:
    /// the terminal and stderr go back first, then the message.
    RestoreThenPrint,
    /// Another thread panicked while raw mode is on (a reconnect round,
    /// say). The session goes on without it, so the terminal must stay as
    /// it is and nothing may be printed over the frame: the message goes to
    /// the log, as an `error` record.
    LogOnly,
}

/// `raw_thread` is the thread that entered raw mode, if it is on.
fn on_panic(raw_thread: Option<ThreadId>, current: ThreadId) -> OnPanic {
    match raw_thread {
        None => OnPanic::Print,
        Some(t) if t == current => OnPanic::RestoreThenPrint,
        Some(_) => OnPanic::LogOnly,
    }
}

/// Puts the original stderr back on fd 2 and closes the copy it was kept in.
fn put_stderr_back(original: OwnedFd) {
    // SAFETY: both descriptors are open; `dup2` only replaces fd 2.
    unsafe { libc::dup2(original.as_raw_fd(), libc::STDERR_FILENO) };
}

/// The longest line of stderr one record holds; the rest goes on in the next.
const STDERR_LINE_MAX: usize = 4096;

/// How long `restore` waits for the last of stderr to reach the log.
const STDERR_DRAIN: Duration = Duration::from_millis(250);

/// Stderr's bytes, cut into the lines that become records.
#[derive(Default)]
struct StderrLines {
    partial: Vec<u8>,
}

impl StderrLines {
    /// The lines `bytes` completes; an unfinished one is kept for later.
    fn push(&mut self, bytes: &[u8]) -> Vec<String> {
        let mut out = Vec::new();
        for &b in bytes {
            if b == b'\n' {
                out.extend(self.take());
            } else {
                self.partial.push(b);
                if self.partial.len() >= STDERR_LINE_MAX {
                    out.extend(self.take());
                }
            }
        }
        out
    }

    /// What is left once the writers are gone.
    fn finish(&mut self) -> Option<String> {
        self.take()
    }

    fn take(&mut self) -> Option<String> {
        let bytes = std::mem::take(&mut self.partial);
        let bytes = bytes.strip_suffix(b"\r").unwrap_or(&bytes);
        (!bytes.is_empty()).then(|| String::from_utf8_lossy(bytes).into_owned())
    }
}

/// How long the reader of stderr's pipe waits after a read error before it
/// reads again.
const STDERR_RETRY: Duration = Duration::from_millis(50);

/// Reads stderr's pipe until every writer is gone, one `warn` record with
/// component `stderr` per line.
fn log_stderr(pipe: File) {
    pump_stderr(pipe, |line| ::log::warn!(target: "stderr", "{line}"));
}

/// Hands `emit` each line read from `pipe`, until end of file and only
/// then. A read error does not end it: the read end has to stay open for
/// as long as anything may write to fd 2, since a pipe with no reader
/// answers a write with EPIPE -- and `eprintln!` panics on that, on
/// whichever thread wrote, the raw-mode thread included.
fn pump_stderr(mut pipe: impl Read, mut emit: impl FnMut(String)) {
    let mut lines = StderrLines::default();
    let mut buf = [0u8; 4096];
    loop {
        match pipe.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => lines.push(&buf[..n]).into_iter().for_each(&mut emit),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => std::thread::sleep(STDERR_RETRY),
        }
    }
    if let Some(line) = lines.finish() {
        emit(line);
    }
}

/// A pipe whose two ends are close-on-exec from the start, so no program
/// started on another thread in between can inherit either.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn cloexec_pipe() -> Result<(OwnedFd, OwnedFd), nix::Error> {
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` has room for the two descriptors `pipe2` writes.
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(nix::Error::last());
    }
    // SAFETY: both are fresh descriptors nobody else owns.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

/// A pipe with both ends close-on-exec. macOS has no `pipe2`: the flag is
/// set right after, which leaves a moment a fork on another thread could
/// fall into.
#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn cloexec_pipe() -> Result<(OwnedFd, OwnedFd), nix::Error> {
    let (read, write) = nix::unistd::pipe()?;
    for fd in [&read, &write] {
        // SAFETY: `fd` is open; `F_SETFD` changes only its own flags.
        unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
    }
    Ok((read, write))
}

/// Raw mode for the lifetime of the value.
pub struct RawMode {
    fd: RawFd,
    saved: Termios,
    /// Told when the thread writing stderr into the log is done
    /// ([`RawMode::set_stderr_to_log`]).
    stderr_logged: Mutex<Option<Receiver<()>>>,
}

impl RawMode {
    /// Switches `fd` into raw mode, remembering what to put back.
    ///
    /// `SAVED` is a single, process-wide slot, so a process is expected to
    /// hold at most one `RawMode` at a time. Entering a second descriptor
    /// while an earlier guard is still alive overwrites the slot, so a panic
    /// afterwards would restore only the second descriptor and leave the
    /// first stuck in raw mode. Entering the *same* descriptor twice is
    /// worse: the second call would capture the already-raw settings as the
    /// "original", so dropping both guards in order would put the terminal
    /// back into raw mode instead of out of it.
    ///
    /// The calling thread is remembered as the one raw mode belongs to (see
    /// [`RawMode::install_panic_hook`]).
    pub fn enter(fd: RawFd) -> Result<RawMode, nix::Error> {
        // SAFETY: the descriptor is owned by the caller for the whole life of
        // the returned guard; we only borrow it for termios calls.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let saved = termios::tcgetattr(borrowed)?;
        let mut raw = saved.clone();
        termios::cfmakeraw(&mut raw);
        termios::tcsetattr(borrowed, SetArg::TCSANOW, &raw)?;

        if let Ok(mut slot) = SAVED.lock() {
            *slot = Some(Saved {
                fd,
                termios: saved.clone(),
                thread: std::thread::current().id(),
                stderr: None,
                alt: None,
            });
        }
        Ok(RawMode {
            fd,
            saved,
            stderr_logged: Mutex::new(None),
        })
    }

    /// Points fd 2 at `to` until raw mode ends: whatever writes to stderr
    /// meanwhile -- a library's `eprintln!` on some thread of its own --
    /// lands there instead of over the frame. `restore`, and the panic hook
    /// on this guard's thread, put the original back before anything else
    /// is printed.
    ///
    /// Does nothing a second time: the original is already kept aside.
    pub fn set_stderr_aside(&self, to: &File) -> Result<(), nix::Error> {
        let Ok(mut slot) = SAVED.lock() else {
            return Err(nix::Error::EDEADLK);
        };
        let Some(saved) = slot.as_mut().filter(|s| s.fd == self.fd) else {
            return Err(nix::Error::EBADF);
        };
        if saved.stderr.is_some() {
            return Ok(());
        }
        // Closed on exec: a program started meanwhile (`ssh`) must not
        // inherit the copy, or it would hold the person's terminal open.
        // SAFETY: `F_DUPFD_CLOEXEC` of fd 2 hands back a fresh descriptor,
        // owned from here on by the `OwnedFd`.
        let original = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 0) };
        if original < 0 {
            return Err(nix::Error::last());
        }
        // SAFETY: `original` is open and nobody else owns it.
        let original = unsafe { OwnedFd::from_raw_fd(original) };
        // SAFETY: both descriptors are open; `dup2` only replaces fd 2.
        if unsafe { libc::dup2(to.as_raw_fd(), libc::STDERR_FILENO) } < 0 {
            return Err(nix::Error::last());
        }
        saved.stderr = Some(original);
        Ok(())
    }

    /// [`RawMode::set_stderr_aside`] into the log: fd 2 becomes a pipe, and
    /// a thread writes each line that arrives there as a `warn` record with
    /// component `stderr`. Once raw mode ends, fd 2 is the terminal again,
    /// the pipe has no writer left, and the thread ends at its end of file;
    /// `restore` waits a moment for it, so the last lines are not lost.
    ///
    /// Does nothing a second time.
    pub fn set_stderr_to_log(&self) -> Result<(), nix::Error> {
        let Ok(mut logged) = self.stderr_logged.lock() else {
            return Err(nix::Error::EDEADLK);
        };
        if logged.is_some() {
            return Ok(());
        }
        // Neither end goes to a program started meanwhile: the copy on fd 2
        // is the one a child inherits as its stderr.
        let (read, write) = cloexec_pipe()?;
        // The reader first: should fd 2 then fail to move, `write` is
        // dropped here and the reader ends at once.
        let (done, finished) = mpsc::channel();
        let pipe = File::from(read);
        std::thread::Builder::new()
            .name("stderr-to-log".into())
            .spawn(move || {
                log_stderr(pipe);
                let _ = done.send(());
            })
            .map_err(|_| nix::Error::EAGAIN)?;
        self.set_stderr_aside(&File::from(write))?;
        *logged = Some(finished);
        Ok(())
    }

    /// Switches the terminal written through `out` to its alternate screen,
    /// for as long as raw mode lasts: `restore`, and the panic hook on this
    /// guard's thread, switch back before anything else is printed, so what
    /// stays on the terminal's own screen is what was there before and what
    /// is printed after. Whatever is buffered for `out` elsewhere (in
    /// `std::io::stdout`) must be flushed first: this writes to the
    /// descriptor itself.
    ///
    /// Does nothing a second time.
    pub fn enter_alternate_screen(&self, out: RawFd) -> Result<(), nix::Error> {
        let Ok(mut slot) = SAVED.lock() else {
            return Err(nix::Error::EDEADLK);
        };
        let Some(saved) = slot.as_mut().filter(|s| s.fd == self.fd) else {
            return Err(nix::Error::EBADF);
        };
        if saved.alt.is_none() {
            write_fd(out, ALT_SCREEN_ON);
            saved.alt = Some(AltScreen { out, on: true });
        }
        Ok(())
    }

    /// Whether the terminal is on the alternate screen now.
    pub fn alternate_screen(&self) -> bool {
        SAVED.lock().ok().is_some_and(|slot| {
            slot.as_ref()
                .filter(|s| s.fd == self.fd)
                .and_then(|s| s.alt)
                .is_some_and(|a| a.on)
        })
    }

    /// Hands the terminal back ahead of a stop (SIGTSTP): its own screen
    /// and its own settings, as `vim` does -- the shell that takes over
    /// meanwhile must not draw its prompt on the alternate screen, nor in
    /// raw mode. `reenter` comes back to both. Unlike `restore` this keeps
    /// everything else as it is: the slot, stderr set aside, what to put
    /// back at the end.
    pub fn suspend(&self) {
        if let Ok(mut slot) = SAVED.lock() {
            if let Some(saved) = slot.as_mut().filter(|s| s.fd == self.fd) {
                leave_alt_screen(&mut saved.alt);
            }
        }
        // SAFETY: as in `enter` -- the descriptor outlives this guard.
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ = termios::tcsetattr(borrowed, SetArg::TCSANOW, &self.saved);
    }

    /// Re-applies raw mode to a terminal that has been put back into cooked
    /// mode behind our back -- which is what a stop/continue cycle does, so
    /// this is what the `SIGCONT` handler calls, to put raw mode, the
    /// mirrored modes, and the repaint back the way they were.
    ///
    /// Deliberately does NOT re-read the terminal's current settings the way
    /// `enter` does: `saved` must go on describing the terminal as the user
    /// handed it over, and re-capturing here would save whatever state the
    /// job-control stop left behind -- destroying the restore this whole
    /// module exists for. For the same reason it leaves `SAVED` alone: the
    /// slot still holds this guard's original settings, since only `restore`
    /// ever clears it and a resumed process has not restored anything.
    ///
    /// bash saves and restores per-job terminal attributes across `fg`, which
    /// hides the need for this most of the time. A `kill -CONT` from
    /// elsewhere, or a shell that does not, does not.
    ///
    /// The alternate screen comes back too, if `suspend` left it. A stop
    /// the client did not take itself (`SIGSTOP`) never left it, and it is
    /// not entered again: a second switch would save the cursor a second
    /// time, over the position the switch back at the end must put back.
    pub fn reenter(&self) -> Result<(), nix::Error> {
        // SAFETY: as in `enter` -- the descriptor outlives this guard.
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let mut raw = self.saved.clone();
        termios::cfmakeraw(&mut raw);
        let result = termios::tcsetattr(borrowed, SetArg::TCSANOW, &raw);
        if let Ok(mut slot) = SAVED.lock() {
            if let Some(alt) = slot
                .as_mut()
                .filter(|s| s.fd == self.fd)
                .and_then(|s| s.alt.as_mut())
                .filter(|a| !a.on)
            {
                write_fd(alt.out, ALT_SCREEN_ON);
                alt.on = true;
            }
        }
        result
    }

    /// Puts the terminal back -- its own screen first, then its settings --
    /// and stderr if it was set aside. Safe to call more than once: the
    /// ordinary exit path calls it and `Drop` calls it again, and only the
    /// first switches back to the terminal's own screen.
    pub fn restore(&self) {
        // Clear the slot once it is put back, so a later, unrelated panic
        // finds nothing to act on. Left in place, a stale entry would make
        // the panic hook re-apply these settings to `self.fd` after the OS
        // may have already reused that number for something else. Only
        // clear it if it is still ours -- a later `enter()` on another
        // descriptor may have overwritten it, and that entry is not ours to
        // touch.
        let mut original_stderr = None;
        if let Ok(mut slot) = SAVED.lock() {
            if slot.as_ref().map(|s| s.fd) == Some(self.fd) {
                if let Some(mut saved) = slot.take() {
                    leave_alt_screen(&mut saved.alt);
                    original_stderr = saved.stderr;
                }
            }
        }
        // SAFETY: as in `enter` -- the descriptor outlives this guard.
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ = termios::tcsetattr(borrowed, SetArg::TCSANOW, &self.saved);
        if let Some(original) = original_stderr {
            put_stderr_back(original);
        }
        // fd 2 no longer writes into the pipe: its thread ends as soon as it
        // has logged what was left -- unless a program started meanwhile
        // still holds the pipe as its stderr, which is not waited for.
        let finished = self.stderr_logged.lock().ok().and_then(|mut l| l.take());
        if let Some(finished) = finished {
            let _ = finished.recv_timeout(STDERR_DRAIN);
        }
    }

    /// Makes a panic on the thread that entered raw mode restore the
    /// terminal -- its own screen, its settings -- and stderr, before the
    /// message is printed -- otherwise the backtrace itself arrives with no
    /// line breaks, on a terminal the user can no longer type into, on a
    /// screen that vanishes as soon as anything switches back (or, with
    /// stderr set aside, nowhere the user looks).
    ///
    /// A panic on any other thread while raw mode is on leaves the terminal
    /// alone: the session goes on (the main loop counts a reconnect round
    /// that died as a failed one), and a terminal put back to cooked under a
    /// running session would echo every key and buffer by line. Its message
    /// goes to the log instead of over the frame.
    pub fn install_panic_hook() {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let current = std::thread::current();
            if let Ok(mut slot) = SAVED.lock() {
                match on_panic(slot.as_ref().map(|s| s.thread), current.id()) {
                    OnPanic::Print => {}
                    OnPanic::LogOnly => {
                        crate::log::error(&format!(
                            "thread '{}' panicked: {info}",
                            current.name().unwrap_or("<unnamed>")
                        ));
                        return;
                    }
                    OnPanic::RestoreThenPrint => {
                        crate::log::error(&format!(
                            "thread '{}' panicked: {info}",
                            current.name().unwrap_or("<unnamed>")
                        ));
                        if let Some(saved) = slot.as_mut() {
                            leave_alt_screen(&mut saved.alt);
                            // SAFETY: the descriptor is the process's own
                            // terminal, open for the life of the process.
                            let borrowed = unsafe { BorrowedFd::borrow_raw(saved.fd) };
                            let _ = termios::tcsetattr(borrowed, SetArg::TCSANOW, &saved.termios);
                            if let Some(original) = saved.stderr.take() {
                                put_stderr_back(original);
                            }
                        }
                    }
                }
            }
            previous(info);
        }));
    }
}
impl Drop for RawMode {
    fn drop(&mut self) {
        self.restore();
    }
}

/// Echo off for the lifetime of the value: used while a passphrase is typed.
/// A passphrase on screen is a passphrase in the scrollback.
///
/// A signal while echo is off would otherwise leave the shell without echo
/// -- the session's own signal handlers only come after login. So, as
/// OpenSSH's `readpassphrase` does, the guard catches SIGINT, SIGTERM,
/// SIGQUIT, SIGHUP and SIGTSTP for its lifetime: the handler puts the saved
/// settings back and raises the signal again with its default action. A
/// stop comes back from that: the handler then turns echo off again and
/// catches the signal again, and the read goes on. The previous handlers
/// are put back when the guard drops.
///
/// One guard at a time per process: the settings a handler restores live in
/// one static slot, because a signal handler can take no lock.
pub struct EchoOff {
    fd: RawFd,
    saved: Termios,
    previous: Vec<(libc::c_int, libc::sigaction)>,
}

/// The signals that would end or stop the process with echo still off.
const ECHO_SIGNALS: [libc::c_int; 5] = [
    libc::SIGINT,
    libc::SIGTERM,
    libc::SIGQUIT,
    libc::SIGHUP,
    libc::SIGTSTP,
];

/// What a signal handler needs while an `EchoOff` lives: written before the
/// handlers go in, and `fd` set last; a handler reads nothing unless `fd`
/// is set.
struct EchoSlot {
    fd: AtomicI32,
    saved: UnsafeCell<MaybeUninit<libc::termios>>,
    quiet: UnsafeCell<MaybeUninit<libc::termios>>,
}

// SAFETY: `saved` and `quiet` are written only while `fd` is -1 and no
// handler of ours is installed, and only read by the handler after it has
// seen `fd` set (release/acquire).
unsafe impl Sync for EchoSlot {}

/// Every test in the crate that turns echo off, installs a signal handler,
/// raises a signal or looks at a disposition takes this one lock: the slot
/// and the dispositions are process-wide, and two locks would let an echo
/// test put back a handler a signal test is about to rely on -- or leave
/// the default one in place for its `raise`, which ends the test process.
#[cfg(test)]
pub(crate) static SIGNAL_TESTS: Mutex<()> = Mutex::new(());

static ECHO_SLOT: EchoSlot = EchoSlot {
    fd: AtomicI32::new(-1),
    saved: UnsafeCell::new(MaybeUninit::uninit()),
    quiet: UnsafeCell::new(MaybeUninit::uninit()),
};

/// Only async-signal-safe calls: `tcsetattr`, `sigaction`, `raise`.
extern "C" fn restore_and_reraise(sig: libc::c_int) {
    let fd = ECHO_SLOT.fd.load(Ordering::Acquire);
    // SAFETY: the slot is filled before `fd` is set (see `EchoSlot`); the
    // rest are plain libc calls on values this handler owns.
    unsafe {
        if fd >= 0 {
            libc::tcsetattr(fd, libc::TCSANOW, (*ECHO_SLOT.saved.get()).as_ptr());
        }
        let mut default: libc::sigaction = std::mem::zeroed();
        default.sa_sigaction = libc::SIG_DFL;
        libc::sigemptyset(&mut default.sa_mask);
        libc::sigaction(sig, &default, std::ptr::null_mut());
        // Not blocked inside this handler (`SA_NODEFER`), so the default
        // action happens right here: the process ends -- or stops, and
        // comes back on SIGCONT.
        libc::raise(sig);
        if fd >= 0 && ECHO_SLOT.fd.load(Ordering::Acquire) == fd {
            libc::tcsetattr(fd, libc::TCSANOW, (*ECHO_SLOT.quiet.get()).as_ptr());
            catch(sig);
        }
    }
}

/// Installs `restore_and_reraise` for `sig`; the handler it replaces.
///
/// # Safety
/// Changes the process's disposition for `sig`.
unsafe fn catch(sig: libc::c_int) -> libc::sigaction {
    let mut ours: libc::sigaction = std::mem::zeroed();
    ours.sa_sigaction = restore_and_reraise as extern "C" fn(libc::c_int) as libc::sighandler_t;
    ours.sa_flags = libc::SA_RESTART | libc::SA_NODEFER;
    libc::sigemptyset(&mut ours.sa_mask);
    let mut previous: libc::sigaction = std::mem::zeroed();
    libc::sigaction(sig, &ours, &mut previous);
    previous
}

impl EchoOff {
    pub fn enter(fd: RawFd) -> Result<EchoOff, nix::Error> {
        // SAFETY: the descriptor outlives this guard.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let saved = termios::tcgetattr(borrowed)?;
        let mut quiet = saved.clone();
        quiet.local_flags.remove(termios::LocalFlags::ECHO);
        debug_assert_eq!(
            ECHO_SLOT.fd.load(Ordering::Acquire),
            -1,
            "one EchoOff at a time: another guard holds the signal slot"
        );

        // SAFETY: no handler of ours is installed and `fd` is unset, so
        // nothing reads the slot while it is written.
        unsafe {
            (*ECHO_SLOT.saved.get()).write(saved.clone().into());
            (*ECHO_SLOT.quiet.get()).write(quiet.clone().into());
        }
        ECHO_SLOT.fd.store(fd, Ordering::Release);
        // SAFETY: the handler only touches the slot filled just above.
        let previous = ECHO_SIGNALS
            .iter()
            .map(|&sig| (sig, unsafe { catch(sig) }))
            .collect();
        let guard = EchoOff {
            fd,
            saved,
            previous,
        };
        // On failure the guard drops: the handlers go back, echo stays on.
        termios::tcsetattr(borrowed, SetArg::TCSANOW, &quiet)?;
        Ok(guard)
    }
}

impl Drop for EchoOff {
    fn drop(&mut self) {
        // SAFETY: as in `enter`.
        let borrowed = unsafe { BorrowedFd::borrow_raw(self.fd) };
        let _ = termios::tcsetattr(borrowed, SetArg::TCSANOW, &self.saved);
        for (sig, previous) in &self.previous {
            // SAFETY: puts back exactly what `enter` found.
            unsafe { libc::sigaction(*sig, previous, std::ptr::null_mut()) };
        }
        ECHO_SLOT.fd.store(-1, Ordering::Release);
    }
}

/// The terminal's size as `(cols, rows)`, or `None` when there is no usable
/// size to report: either `fd` is not a terminal at all (`qsh` redirected
/// into a pipe reaches this), or it is one that answers `0x0` -- which a
/// pty whose size has never been set does, and which is no more usable as a
/// screen size than no answer at all. The caller falls back to a default
/// either way, so the two need not be told apart.
pub fn window_size(fd: RawFd) -> Option<(u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    // SAFETY: `ws` is a valid, correctly sized winsize for the whole call.
    let rc = unsafe { libc::ioctl(fd, libc::TIOCGWINSZ, &mut ws) };
    if rc != 0 || ws.ws_col == 0 || ws.ws_row == 0 {
        return None;
    }
    Some((ws.ws_col, ws.ws_row))
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::pty::openpty;
    use std::os::fd::{AsFd, AsRawFd};

    /// `SAVED` is one process-wide slot. Serialize the tests that touch it
    /// (via `enter`/`restore`) so parallel test threads cannot interleave
    /// their writes to it and make `restoring_clears_the_saved_slot` flaky.
    static SAVED_SLOT_TESTS: Mutex<()> = Mutex::new(());

    /// Raw mode is the whole point: no echo, no line discipline, and signal
    /// characters delivered as bytes rather than turned into signals.
    #[test]
    fn entering_raw_mode_turns_off_echo_and_line_editing() {
        let _serialize = SAVED_SLOT_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let pty = openpty(None, None).expect("openpty");
        let fd = pty.slave.as_raw_fd();
        let before = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        assert!(
            before.local_flags.contains(termios::LocalFlags::ECHO),
            "a fresh pty starts cooked, or this test proves nothing"
        );

        let raw = RawMode::enter(fd).expect("enter raw mode");
        let now = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        assert!(!now.local_flags.contains(termios::LocalFlags::ECHO));
        assert!(!now.local_flags.contains(termios::LocalFlags::ICANON));
        assert!(!now.local_flags.contains(termios::LocalFlags::ISIG));
        drop(raw);
    }

    /// And it must come back. A terminal left raw is a broken shell, and the
    /// user usually does not know `reset`.
    #[test]
    fn leaving_restores_exactly_what_was_there() {
        let _serialize = SAVED_SLOT_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let pty = openpty(None, None).expect("openpty");
        let fd = pty.slave.as_raw_fd();
        let before = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        {
            let _raw = RawMode::enter(fd).expect("enter raw mode");
        }
        let after = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        assert_eq!(before.local_flags, after.local_flags);
        assert_eq!(before.input_flags, after.input_flags);
        assert_eq!(before.output_flags, after.output_flags);
        assert_eq!(before.control_flags, after.control_flags);
    }

    /// Restoring twice must be safe: the ordinary exit path restores, and so
    /// does `Drop` right after it.
    #[test]
    fn restoring_twice_is_harmless() {
        let _serialize = SAVED_SLOT_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let pty = openpty(None, None).expect("openpty");
        let fd = pty.slave.as_raw_fd();
        let before = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        let raw = RawMode::enter(fd).expect("enter raw mode");
        raw.restore();
        raw.restore();
        let after = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        assert_eq!(before.local_flags, after.local_flags);
    }

    /// Once a guard has restored, the panic hook must have nothing left to
    /// act on -- otherwise an unrelated panic later in the process would
    /// re-apply these settings to a descriptor number the OS may have
    /// already handed to something else.
    #[test]
    fn restoring_clears_the_saved_slot() {
        let _serialize = SAVED_SLOT_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let pty = openpty(None, None).expect("openpty");
        let fd = pty.slave.as_raw_fd();
        let raw = RawMode::enter(fd).expect("enter raw mode");
        raw.restore();

        let slot = SAVED.lock().expect("saved lock");
        assert!(
            slot.is_none(),
            "a stale entry would make the panic hook act on a since-reused fd"
        );
    }

    /// A terminal put back into cooked mode behind our back -- what a
    /// stop/continue cycle does -- goes back to raw, and the settings to
    /// restore at the end are STILL the ones the user handed over. Getting
    /// that second half wrong is silent: re-capturing in `reenter` would
    /// save the cooked state and leave the terminal raw at exit, and every
    /// other test here would still pass.
    #[test]
    fn reentering_restores_raw_without_forgetting_the_original() {
        let _serialize = SAVED_SLOT_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let pty = openpty(None, None).expect("openpty");
        let fd = pty.slave.as_raw_fd();
        let before = termios::tcgetattr(&pty.slave).expect("tcgetattr");

        let raw = RawMode::enter(fd).expect("enter raw mode");
        // Someone else -- job control, another program -- puts the terminal
        // back to cooked while we are stopped.
        termios::tcsetattr(&pty.slave, SetArg::TCSANOW, &before).expect("tcsetattr");
        assert!(
            termios::tcgetattr(&pty.slave)
                .expect("tcgetattr")
                .local_flags
                .contains(termios::LocalFlags::ECHO),
            "the terminal must be cooked again, or this test proves nothing"
        );

        raw.reenter().expect("reenter raw mode");
        let now = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        assert!(!now.local_flags.contains(termios::LocalFlags::ECHO));
        assert!(!now.local_flags.contains(termios::LocalFlags::ICANON));
        assert!(!now.local_flags.contains(termios::LocalFlags::ISIG));

        drop(raw);
        let after = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        assert_eq!(
            before.local_flags, after.local_flags,
            "`saved` must still describe the ORIGINAL cooked terminal"
        );
        assert_eq!(before.input_flags, after.input_flags);
        assert_eq!(before.output_flags, after.output_flags);
        assert_eq!(before.control_flags, after.control_flags);
    }

    /// A panic touches the terminal only on the thread that entered raw
    /// mode: a reconnect round's thread dying must not leave a running
    /// session cooked, nor print over its frame.
    #[test]
    fn only_the_raw_mode_thread_s_panic_restores_the_terminal() {
        let here = std::thread::current().id();
        let other = std::thread::spawn(|| std::thread::current().id())
            .join()
            .expect("join");
        assert_eq!(on_panic(None, here), OnPanic::Print);
        assert_eq!(on_panic(Some(here), here), OnPanic::RestoreThenPrint);
        assert_eq!(on_panic(Some(other), here), OnPanic::LogOnly);
    }

    /// Set by the parent test for the child process it runs; names the case.
    const CHILD_CASE: &str = "QSH_TTY_TEST_CHILD";
    /// Where the child sets stderr aside to.
    const CHILD_ASIDE: &str = "QSH_TTY_TEST_ASIDE";

    /// Runs `child_process` of this test binary as its own process, with
    /// `case`, its stderr on a pipe: fd 2 is process-wide, so moving it in
    /// this process would take the test runner's own stderr with it.
    /// Returns the child's exit status, its stderr and what it set aside.
    fn run_child(case: &str) -> (std::process::ExitStatus, String, String) {
        let dir = tempfile::tempdir().expect("tempdir");
        let aside = dir.path().join("aside");
        let out = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args([
                "tty::tests::child_process",
                "--exact",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD_CASE, case)
            .env(CHILD_ASIDE, &aside)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .output()
            .expect("run the child");
        (
            out.status,
            String::from_utf8_lossy(&out.stderr).into_owned(),
            std::fs::read_to_string(&aside).unwrap_or_default(),
        )
    }

    /// Writes `line` straight to fd 2, the way a library's `eprintln!` on
    /// its own thread reaches it -- not through the test harness's capture.
    fn to_fd2(line: &str) {
        use std::io::Write;
        let _ = std::io::stderr().write_all(line.as_bytes());
    }

    /// The child side of the tests below: does nothing unless run by
    /// `run_child`.
    #[test]
    fn child_process() {
        let Ok(case) = std::env::var(CHILD_CASE) else {
            return;
        };
        let aside_path = std::env::var(CHILD_ASIDE).expect("aside path");
        let aside = File::create(&aside_path).expect("aside");
        let pty = openpty(None, None).expect("openpty");
        let raw = RawMode::enter(pty.slave.as_raw_fd()).expect("enter raw mode");
        if case.starts_with("alt-") {
            alternate_screen_child(&case, &raw, &pty.slave, &aside);
            return;
        }
        if case == "to-log" {
            let sink =
                logging::FileSink::open(std::path::Path::new(&aside_path), 1 << 20).expect("sink");
            let filter = logging::Filter {
                default: ::log::LevelFilter::Trace,
                per_component: vec![],
            };
            assert!(logging::install(sink, filter));
            raw.set_stderr_to_log().expect("stderr to the log");
            to_fd2("LIB-LINE-ONE\nLIB-");
            to_fd2("PART\r\n\nNO-NEWLINE-AT-END");
            raw.restore();
            to_fd2("AFTER-RESTORE\n");
            return;
        }
        raw.set_stderr_aside(&aside).expect("set stderr aside");
        to_fd2("WHILE-RAW\n");
        match case.as_str() {
            "restore" => {
                raw.restore();
                to_fd2("AFTER-RESTORE\n");
            }
            "panics" => {
                RawMode::install_panic_hook();
                let _ = std::thread::spawn(|| panic!("ROUND-THREAD-PANIC")).join();
                let still_raw = !termios::tcgetattr(&pty.slave)
                    .expect("tcgetattr")
                    .local_flags
                    .contains(termios::LocalFlags::ECHO);
                to_fd2(&format!("STILL-RAW={still_raw}\n"));
                panic!("MAIN-THREAD-PANIC");
            }
            "cloexec" => {
                let kept = SAVED
                    .lock()
                    .expect("saved slot")
                    .as_ref()
                    .and_then(|s| s.stderr.as_ref().map(|fd| fd.as_raw_fd()))
                    .expect("the original stderr is kept");
                // SAFETY: `kept` is open for as long as raw mode lasts.
                let flags = unsafe { libc::fcntl(kept, libc::F_GETFD) };
                to_fd2(&format!("CLOEXEC={}\n", flags & libc::FD_CLOEXEC != 0));
                raw.restore();
            }
            other => panic!("unknown case {other}"),
        }
    }

    /// The child side of the alternate-screen tests. The screen is switched
    /// on a copy of the original stderr -- the pipe the parent reads -- so
    /// the parent sees the switches and the messages in the order they were
    /// written.
    fn alternate_screen_child(case: &str, raw: &RawMode, slave: &OwnedFd, aside: &File) {
        let out = std::io::stderr().as_fd().try_clone_to_owned().expect("dup");
        let cooked = || {
            termios::tcgetattr(slave)
                .expect("tcgetattr")
                .local_flags
                .contains(termios::LocalFlags::ECHO)
        };
        raw.enter_alternate_screen(out.as_raw_fd())
            .expect("enter the alternate screen");
        to_fd2(&format!("ON={}\n", raw.alternate_screen()));
        raw.set_stderr_aside(aside).expect("set stderr aside");
        match case {
            "alt-restore" => {
                raw.restore();
                raw.restore();
                to_fd2(&format!("AFTER-RESTORE ON={}\n", raw.alternate_screen()));
            }
            "alt-panics" => {
                RawMode::install_panic_hook();
                let _ = std::thread::spawn(|| panic!("ROUND-THREAD-PANIC")).join();
                panic!("MAIN-THREAD-PANIC");
            }
            "alt-suspend" => {
                raw.suspend();
                to_fd2(&format!(
                    "SUSPENDED COOKED={} ON={}\n",
                    cooked(),
                    raw.alternate_screen()
                ));
                raw.reenter().expect("reenter");
                raw.reenter().expect("reenter again");
                to_fd2(&format!(
                    "REENTERED COOKED={} ON={}\n",
                    cooked(),
                    raw.alternate_screen()
                ));
                raw.restore();
            }
            "alt-sigcont-only" => {
                // A stop the client did not see coming (SIGSTOP), then
                // SIGCONT: the alternate screen was never left, so it is not
                // entered again -- that would save the cursor a second time,
                // over the one the switch back puts back.
                raw.reenter().expect("reenter");
                raw.restore();
            }
            other => panic!("unknown case {other}"),
        }
        drop(out);
    }

    /// The switches in `text`, in order: `h` onto the alternate screen, `l`
    /// back.
    fn switches(text: &str) -> String {
        let mut out = String::new();
        let mut rest = text;
        while let Some(at) = rest.find("\x1b[?1049") {
            let after = &rest[at + "\x1b[?1049".len()..];
            out.extend(after.chars().next());
            rest = after;
        }
        out
    }

    /// Leaving raw mode leaves the alternate screen, once however often it is
    /// left, and before anything printed after it.
    #[test]
    fn restoring_leaves_the_alternate_screen_once_and_first() {
        let (status, stderr, aside) = run_child("alt-restore");
        assert!(status.success(), "child failed: {stderr}");
        assert_eq!(switches(&stderr), "hl", "stderr: {stderr:?}");
        let off = stderr.find("\x1b[?1049l").expect("checked above");
        let on = stderr.find("\x1b[?1049h").expect("checked above");
        assert!(stderr[on..off].contains("ON=true"), "stderr: {stderr:?}");
        let after = stderr.find("AFTER-RESTORE ON=false").expect("printed");
        assert!(off < after, "stderr: {stderr:?}");
        assert!(!aside.contains("1049"), "aside: {aside:?}");
    }

    /// The raw-mode thread's panic leaves the alternate screen before its
    /// message; another thread's panic leaves it alone.
    #[test]
    fn a_panic_leaves_the_alternate_screen_before_its_message() {
        let (status, stderr, aside) = run_child("alt-panics");
        assert!(!status.success(), "the child ends in a panic");
        assert_eq!(switches(&stderr), "hl", "stderr: {stderr:?}");
        let off = stderr.find("\x1b[?1049l").expect("checked above");
        let message = stderr.find("MAIN-THREAD-PANIC").expect("the message");
        assert!(off < message, "stderr: {stderr:?}");
        assert!(!stderr.contains("ROUND-THREAD-PANIC"), "stderr: {stderr:?}");
        assert!(!aside.contains("1049"), "aside: {aside:?}");
    }

    /// Ahead of a stop the terminal gets its own screen and settings back;
    /// after it, raw mode and the alternate screen come back -- once, however
    /// often `reenter` is called -- and leaving still leaves it.
    #[test]
    fn a_suspend_leaves_the_alternate_screen_and_reenter_comes_back_to_it() {
        let (status, stderr, aside) = run_child("alt-suspend");
        assert!(status.success(), "child failed: {stderr}");
        assert_eq!(switches(&aside), "", "aside: {aside:?}");
        assert!(
            aside.contains("SUSPENDED COOKED=true ON=false"),
            "aside: {aside:?}"
        );
        assert!(
            aside.contains("REENTERED COOKED=false ON=true"),
            "aside: {aside:?}"
        );
        assert_eq!(switches(&stderr), "hlhl", "stderr: {stderr:?}");
    }

    /// `reenter` after a stop the client did not take itself does not switch
    /// to the alternate screen a second time.
    #[test]
    fn reentering_without_a_suspend_does_not_switch_again() {
        let (status, stderr, _) = run_child("alt-sigcont-only");
        assert!(status.success(), "child failed: {stderr}");
        assert_eq!(switches(&stderr), "hl", "stderr: {stderr:?}");
    }

    /// While raw mode is on, stderr lands in the file set aside for it, not
    /// on the terminal; once it is restored, stderr is the terminal again.
    #[test]
    fn stderr_is_set_aside_while_raw_and_comes_back_on_restore() {
        let (status, stderr, aside) = run_child("restore");
        assert!(status.success(), "child failed: {stderr}");
        assert!(aside.contains("WHILE-RAW"), "aside: {aside:?}");
        assert!(!stderr.contains("WHILE-RAW"), "stderr: {stderr:?}");
        assert!(stderr.contains("AFTER-RESTORE"), "stderr: {stderr:?}");
        assert!(!aside.contains("AFTER-RESTORE"), "aside: {aside:?}");
    }

    /// While raw mode is on, whatever reaches fd 2 becomes records of the
    /// log, component `stderr`, one per line; `restore` waits for the last
    /// of them and gives the terminal its stderr back.
    #[test]
    fn stderr_becomes_log_records_while_raw() {
        let (status, stderr, log) = run_child("to-log");
        assert!(status.success(), "child failed: {stderr}");
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 3, "the log: {log:?}");
        assert!(
            lines[0].ends_with("] WARN  stderr: LIB-LINE-ONE"),
            "{log:?}"
        );
        assert!(lines[1].ends_with("] WARN  stderr: LIB-PART"), "{log:?}");
        assert!(
            lines[2].ends_with("] WARN  stderr: NO-NEWLINE-AT-END"),
            "{log:?}"
        );
        assert!(!stderr.contains("LIB-"), "stderr: {stderr:?}");
        assert!(stderr.contains("AFTER-RESTORE"), "stderr: {stderr:?}");
        assert!(!log.contains("AFTER-RESTORE"), "the log: {log:?}");
    }

    /// Bytes become lines: split on `\n`, a trailing `\r` dropped, blank
    /// lines skipped, a line with no end cut at `STDERR_LINE_MAX`.
    #[test]
    fn stderr_bytes_split_into_lines() {
        let mut l = StderrLines::default();
        assert_eq!(l.push(b"a\r\nb"), vec!["a".to_string()]);
        assert_eq!(l.push(b"c\n\n\nd"), vec!["bc".to_string()]);
        assert_eq!(l.finish(), Some("d".to_string()));
        assert_eq!(l.finish(), None);
        let long = vec![b'x'; STDERR_LINE_MAX + 10];
        let got = l.push(&long);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].len(), STDERR_LINE_MAX);
        assert_eq!(l.finish(), Some("x".repeat(10)));
        assert_eq!(l.push(b"\xff\n"), vec!["\u{fffd}".to_string()]);
    }

    /// A read error does not end the reader: the pipe's read end must stay
    /// open until end of file, or the next write to fd 2 fails with EPIPE --
    /// and `eprintln!` panics on that, on whatever thread wrote it.
    #[test]
    fn a_read_error_does_not_end_the_stderr_reader() {
        struct Flaky(Vec<std::io::Result<Vec<u8>>>);
        impl Read for Flaky {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.0.is_empty() {
                    return Ok(0);
                }
                match self.0.remove(0) {
                    Ok(bytes) => {
                        buf[..bytes.len()].copy_from_slice(&bytes);
                        Ok(bytes.len())
                    }
                    Err(e) => Err(e),
                }
            }
        }
        let reader = Flaky(vec![
            Ok(b"one\n".to_vec()),
            Err(std::io::Error::other("a hiccup")),
            Err(std::io::ErrorKind::Interrupted.into()),
            Ok(b"two\nthr".to_vec()),
            Ok(b"ee".to_vec()),
        ]);
        let mut got = Vec::new();
        pump_stderr(reader, |line| got.push(line));
        assert_eq!(got, vec!["one", "two", "three"]);
    }

    /// Both ends of stderr's pipe are close-on-exec from the moment they
    /// exist.
    #[test]
    fn stderr_s_pipe_is_close_on_exec() {
        let (r, w) = cloexec_pipe().expect("pipe");
        for fd in [&r, &w] {
            // SAFETY: `fd` is open; F_GETFD only reads its flags.
            let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
            assert!(flags & libc::FD_CLOEXEC != 0);
        }
    }

    /// The copy of the original stderr is not handed to a program the client
    /// starts (`ssh`): it would hold the person's terminal open after the
    /// client itself let go of it.
    #[test]
    fn the_kept_stderr_is_closed_on_exec() {
        let (status, stderr, aside) = run_child("cloexec");
        assert!(status.success(), "child failed: {stderr}");
        assert!(aside.contains("CLOEXEC=true"), "aside: {aside:?}");
    }

    /// Another thread's panic leaves raw mode on and prints nothing where
    /// stderr was; the raw-mode thread's panic puts stderr back BEFORE its
    /// message, so the message reaches the person.
    #[test]
    fn a_panic_restores_only_on_the_raw_mode_thread_and_before_its_message() {
        let (status, stderr, aside) = run_child("panics");
        assert!(!status.success(), "the child ends in a panic");
        assert!(
            aside.contains("STILL-RAW=true"),
            "another thread's panic must leave the terminal raw and stderr aside; aside: {aside:?}, stderr: {stderr:?}"
        );
        assert!(
            !stderr.contains("ROUND-THREAD-PANIC") && !aside.contains("ROUND-THREAD-PANIC"),
            "another thread's panic goes to the log only; stderr: {stderr:?}, aside: {aside:?}"
        );
        assert!(
            stderr.contains("MAIN-THREAD-PANIC"),
            "the raw-mode thread's panic message reaches the original stderr; stderr: {stderr:?}"
        );
        assert!(!aside.contains("MAIN-THREAD-PANIC"), "aside: {aside:?}");
    }

    /// The size is read from the descriptor, not guessed from environment
    /// variables that go stale the moment the window is dragged.
    #[test]
    fn the_window_size_comes_from_the_descriptor() {
        let size = nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = openpty(Some(&size), None).expect("openpty");
        assert_eq!(window_size(pty.slave.as_raw_fd()), Some((80, 24)));
    }

    /// Something that is not a terminal has no size, and that is not a crash
    /// -- `qsh` redirected into a pipe reaches this path.
    #[test]
    fn a_pipe_has_no_window_size() {
        let (r, _w) = nix::unistd::pipe().expect("pipe");
        assert_eq!(window_size(r.as_raw_fd()), None);
    }

    /// While echo is off a signal is caught (so it can put echo back), and
    /// afterwards the process's own handling is exactly what it was.
    #[test]
    fn signals_are_caught_only_while_echo_is_off() {
        let _serialize = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let disposition = |sig| unsafe {
            let mut now: libc::sigaction = std::mem::zeroed();
            libc::sigaction(sig, std::ptr::null(), &mut now);
            now.sa_sigaction
        };
        let pty = openpty(None, None).expect("openpty");
        let before: Vec<_> = ECHO_SIGNALS.iter().map(|&s| disposition(s)).collect();
        {
            let _quiet = EchoOff::enter(pty.slave.as_raw_fd()).expect("echo off");
            for &sig in &ECHO_SIGNALS {
                assert_eq!(
                    disposition(sig),
                    restore_and_reraise as extern "C" fn(libc::c_int) as libc::sighandler_t
                );
            }
        }
        let after: Vec<_> = ECHO_SIGNALS.iter().map(|&s| disposition(s)).collect();
        assert_eq!(before, after);
    }

    /// Echo off on something that is not a terminal fails, and leaves no
    /// handler of ours behind.
    #[test]
    fn a_failed_echo_off_leaves_the_handlers_alone() {
        let _serialize = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let disposition = |sig| unsafe {
            let mut now: libc::sigaction = std::mem::zeroed();
            libc::sigaction(sig, std::ptr::null(), &mut now);
            now.sa_sigaction
        };
        let before: Vec<_> = ECHO_SIGNALS.iter().map(|&s| disposition(s)).collect();
        let (r, _w) = nix::unistd::pipe().expect("pipe");
        assert!(EchoOff::enter(r.as_raw_fd()).is_err());
        let after: Vec<_> = ECHO_SIGNALS.iter().map(|&s| disposition(s)).collect();
        assert_eq!(before, after);
    }

    /// A passphrase must not appear on screen, and echo must come back
    /// afterwards -- the user still has a question to answer after this one.
    #[test]
    fn echo_goes_off_and_comes_back() {
        let _serialize = SIGNAL_TESTS.lock().unwrap_or_else(|e| e.into_inner());
        let pty = openpty(None, None).expect("openpty");
        let fd = pty.slave.as_raw_fd();
        {
            let _quiet = EchoOff::enter(fd).expect("echo off");
            let now = termios::tcgetattr(&pty.slave).expect("tcgetattr");
            assert!(!now.local_flags.contains(termios::LocalFlags::ECHO));
        }
        let after = termios::tcgetattr(&pty.slave).expect("tcgetattr");
        assert!(after.local_flags.contains(termios::LocalFlags::ECHO));
    }
}
