//! Exercise the real panic hook before unwinding can restore the terminal.
use super::{write_fd, RawMode};
use nix::pty::openpty;
use nix::sys::termios::{tcgetattr, Termios};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::os::fd::AsRawFd;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const CASE: &str = "QSH_TTY_MODE_TEST_CASE";
const READY: &str = "MODES-READY";
const OBSERVED: &str = "PANIC-HOOK-OBSERVED";
const WORKER_DONE: &str = "WORKER-JOINED";
const RESETS: &[&str] = &[
    "\x1b[0m",
    "\x1b[?1l",
    "\x1b>",
    "\x1b[?1000l",
    "\x1b[?1002l",
    "\x1b[?1003l",
    "\x1b[?1006l",
    "\x1b[?2004l",
    "\x1b[?25h",
];

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Outcome {
    status: ExitStatus,
    output: String,
    original: Termios,
    restored: Termios,
}

fn drain(master: &mut File, output: &mut Vec<u8>) {
    let mut buffer = [0; 4096];
    loop {
        match master.read(&mut buffer) {
            Ok(0) => return,
            Ok(n) => {
                output.extend_from_slice(&buffer[..n]);
                assert!(
                    output.len() <= 64 * 1024,
                    "panic fixture output exceeded bound"
                );
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) if error.kind() == ErrorKind::WouldBlock => return,
            Err(error) if error.raw_os_error() == Some(libc::EIO) => return,
            Err(error) => panic!("read test PTY: {error}"),
        }
    }
}

fn run(case: &str) -> Outcome {
    let home = tempfile::tempdir().unwrap();
    let pty = openpty(None, None).unwrap();
    let original = tcgetattr(&pty.slave).unwrap();
    let mut master = File::from(pty.master);
    // SAFETY: this owned descriptor remains open throughout the capture.
    let flags = unsafe { libc::fcntl(master.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    // SAFETY: same descriptor, preserving its other status flags.
    assert_eq!(
        unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let mut child = OwnedChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "tty::panic_tests::child_process",
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
            .stderr(Stdio::from(pty.slave.try_clone().unwrap()))
            .spawn()
            .unwrap(),
    );
    let mut output = Vec::new();
    let until = Instant::now() + Duration::from_secs(10);
    let status = loop {
        drain(&mut master, &mut output);
        if let Some(status) = child.0.try_wait().unwrap() {
            drain(&mut master, &mut output);
            break status;
        }
        assert!(Instant::now() < until, "panic fixture {case} did not exit");
        std::thread::sleep(Duration::from_millis(10));
    };
    Outcome {
        status,
        output: String::from_utf8_lossy(&output).into_owned(),
        original,
        restored: tcgetattr(&pty.slave).unwrap(),
    }
}

fn interval<'a>(output: &'a str, end: &str) -> &'a str {
    let start = output.find(READY).expect("child enabled the fixture") + READY.len();
    let end = output[start..].find(end).expect("child reached observer") + start;
    &output[start..end]
}

#[test]
fn ui_thread_panic_restores_modes_before_the_previous_hook() {
    for case in ["click", "drag", "motion"] {
        let outcome = run(case);
        assert_eq!(outcome.status.code(), Some(101), "case {case}");
        assert_eq!(outcome.restored, outcome.original, "case {case}");
        let cleanup = interval(&outcome.output, OBSERVED);
        for reset in RESETS.iter().copied().chain(["\x1b[?1049l"]) {
            assert!(cleanup.contains(reset), "case {case}: missing {reset:?}");
        }
        assert_eq!(cleanup.matches("\x1b[?1049l").count(), 1);
    }
}

#[test]
fn worker_panic_keeps_the_active_terminal_modes() {
    let outcome = run("worker");
    assert!(outcome.status.success());
    assert_eq!(outcome.restored, outcome.original);
    let untouched = interval(&outcome.output, WORKER_DONE);
    for reset in RESETS.iter().copied().chain(["\x1b[?1049l"]) {
        assert!(!untouched.contains(reset), "worker emitted {reset:?}");
    }
    assert!(!outcome.output.contains("MODE-WORKER"));
    let mut terminal = terminal::TerminalCore::new(20, 4);
    terminal.feed(&outcome.output.as_bytes()[..outcome.output.find(WORKER_DONE).unwrap()]);
    let frame = terminal.frame();
    assert!(frame.app_cursor && frame.app_keypad && frame.mouse_sgr && frame.bracketed_paste);
    assert_eq!(frame.mouse_tracking, terminal::MouseTracking::Motion);
    assert!(!frame.cursor_visible);
    assert!(frame.alt_screen);
}

#[test]
fn panic_without_an_active_screen_does_not_write_mode_resets() {
    for case in ["unregistered", "suspended"] {
        let outcome = run(case);
        assert_eq!(outcome.status.code(), Some(101));
        assert_eq!(outcome.restored, outcome.original);
        let cleanup = interval(&outcome.output, OBSERVED);
        for reset in RESETS.iter().copied().chain(["\x1b[?1049l"]) {
            assert!(!cleanup.contains(reset), "case {case} emitted {reset:?}");
        }
    }
}

#[test]
fn child_process() {
    let Ok(case) = std::env::var(CASE) else {
        return;
    };
    // The real hook must run first. Terminating here forbids unwind/Drop from
    // making a broken hook look correct, and also works with stdout locked.
    std::panic::set_hook(Box::new(|info| {
        let expected = info.payload().downcast_ref::<&str>() == Some(&"MODE-FATAL");
        if expected {
            write_fd(libc::STDERR_FILENO, OBSERVED.as_bytes());
        }
        // SAFETY: test subprocess only; deliberately skip every destructor.
        unsafe { libc::_exit(if expected { 101 } else { 102 }) };
    }));
    RawMode::install_panic_hook();
    let raw = RawMode::enter(libc::STDIN_FILENO).unwrap();
    let aside =
        File::create(std::path::PathBuf::from(std::env::var_os("HOME").unwrap()).join("aside"))
            .unwrap();
    raw.set_stderr_aside(&aside).unwrap();
    let mut renderer = render::Renderer::new(render::TermCaps::truecolor());
    if case != "unregistered" {
        raw.enter_alternate_screen(libc::STDOUT_FILENO).unwrap();
        let mut source = terminal::TerminalCore::new(20, 4);
        source.feed(b"\x1b[?1h\x1b=\x1b[?1006h\x1b[?2004h\x1b[?25l\x1b[31mred");
        source.feed(match case.as_str() {
            "click" => b"\x1b[?1000h",
            "drag" => b"\x1b[?1002h",
            _ => b"\x1b[?1003h",
        });
        write_fd(libc::STDOUT_FILENO, &renderer.render(&source.frame()));
        if case == "suspended" {
            write_fd(libc::STDOUT_FILENO, &renderer.finish());
            raw.suspend().unwrap();
        }
    }
    write_fd(libc::STDOUT_FILENO, READY.as_bytes());
    if case == "worker" {
        // SAFETY: stdin is the PTY the parent keeps alive for this process.
        let slave = unsafe { std::os::fd::BorrowedFd::borrow_raw(libc::STDIN_FILENO) };
        let raw_before = tcgetattr(slave).unwrap();
        assert!(std::thread::spawn(|| panic!("MODE-WORKER")).join().is_err());
        assert_eq!(tcgetattr(slave).unwrap(), raw_before);
        assert!(raw.alternate_screen());
        write_fd(libc::STDOUT_FILENO, WORKER_DONE.as_bytes());
        write_fd(libc::STDOUT_FILENO, &renderer.finish());
        raw.restore().unwrap();
        std::process::exit(0);
    }
    let _stdout_lock = std::io::stdout().lock();
    panic!("MODE-FATAL");
}
