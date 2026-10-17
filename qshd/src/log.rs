//! Diagnostic log for the `qshd` daemon, written to a file with size-based
//! rotation.
//!
//! A daemonized `qshd` redirects stdout/stderr to `/dev/null`, so ordinary
//! `eprintln!` calls are lost once the daemon is running. This module
//! writes events to `<cache_dir>/qshd.log` (append, `0600` permissions):
//! once [`MAX_BYTES`] is reached, the current file is renamed to
//! `qshd.log.1` (overwriting the previous rotation) and a new one is
//! started -- at most ~2x[`MAX_BYTES`] on disk.
//!
//! Every line has the format the `qsh` client's log uses too
//! ([`logging::format_lines`]):
//! `2026-09-30 20:15:03.123 UTC [4242] INFO  helper: text` -- a UTC
//! timestamp (absolute and timezone-independent, so server events line up
//! easily with the app's log), the writing process's pid (the system mode's
//! helper and worker share one file), a level and a component: the role of
//! the process or the subsystem that wrote it (`qshd`, `helper`, `worker`,
//! `update`, `transport`).
//!
//! Two ways in, one sink: this module's own [`info`]/[`warn`]/[`error`], and
//! the `log` crate's macros -- [`init`] installs a `log::Log` adapter over
//! this same sink, so what `transport` (or any other library) logs lands
//! here with its component taken from the record's target. The sink itself
//! is this module's, not the shared crate's: rotation after a privilege
//! drop, [`mute`] and the system mode's forks are the daemon's business.
//!
//! The log is a best-effort helper: I/O errors are silently swallowed, and
//! writing to the log must never crash the daemon.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

pub use ::log::Level;

/// Size threshold after which the log rotates (`qshd.log` -> `qshd.log.1`).
const MAX_BYTES: u64 = 2 * 1024 * 1024;

const LOG_FILE_NAME: &str = "qshd.log";
const ROTATED_FILE_NAME: &str = "qshd.log.1";

static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

/// Initializes the file log at `<cache_dir>/qshd.log` (once, in the daemon
/// after daemonization). Repeated calls are ignored. If the file cannot be
/// opened, the log stays uninitialized -- [`record`] then writes nothing to
/// a file (a [`mirror_to_stderr`] still gets its copy).
///
/// Also installs the `log` crate's global logger (see [`Adapter`]), once per
/// process, so records from `transport` and the daemon's own `log::` macros
/// reach this same sink.
///
/// `cache_dir` is created here (best-effort) if it does not exist yet:
/// `Logger::open`'s `OpenOptions::create(true)` only creates the FILE, not
/// its parent directory, and every caller used to get away with that only
/// because something else (a key file living inside the same directory)
/// happened to create it first. `serve`'s host key lives elsewhere, so
/// nothing else creates this directory before `init` runs -- without this,
/// the open below fails, the logger stays uninitialized, and every later
/// `log` call is a silent, permanent no-op.
pub fn init(cache_dir: &Path) {
    install_adapter();
    if LOGGER.get().is_some() {
        return;
    }
    let _ = fs::create_dir_all(cache_dir);
    let logger = Logger::open(
        cache_dir.join(LOG_FILE_NAME),
        cache_dir.join(ROTATED_FILE_NAME),
        MAX_BYTES,
    );
    if let Ok(logger) = logger {
        let _ = LOGGER.set(Mutex::new(logger));
    }
}

/// Set by a process that must never write to this file again -- see
/// [`mute`]. Only the `system` build has such a process.
static MUTED: AtomicBool = AtomicBool::new(false);

/// Stop this process writing to the log, for good.
///
/// For a process that has closed every descriptor it inherited while the
/// `File` below stayed open: `helper::monitor`'s per-login monitor, which
/// sweeps its inherited descriptors and then calls into Linux-PAM, whose
/// conversation function logs what a module says. That `File` still holds
/// the descriptor NUMBER it was opened on, and a pipe, a socket or a
/// terminal opened after the sweep can be given that very number -- so a
/// log line written afterwards would not fail, it would land in some
/// channel's startup-report pipe or in a PAM module's own socket. Muting
/// makes that unreachable rather than unlikely.
///
/// One way only, and process-wide: a muted process has nowhere safe to
/// write, and nothing it learns later changes that. A process muted before
/// a `fork` mutes the child too, which is right -- the child inherits the
/// same closed descriptor.
#[cfg(feature = "system")]
pub fn mute() {
    MUTED.store(true, Ordering::Relaxed);
}

/// Whether [`record`] may write at all. Never set in the featureless
/// build, which forks no monitor and so has nothing to mute.
fn muted() -> bool {
    MUTED.load(Ordering::Relaxed)
}

/// Set by `serve`: every record also goes to standard error, for the
/// journal (see [`mirror_to_stderr`]).
static MIRRORED: AtomicBool = AtomicBool::new(false);

/// From now on, every record this process (and any process it forks) logs
/// is also written to standard error -- the same lines as the file, header
/// included (the journal stamps its own time as well; harmless). For
/// `qshd serve`, whose standard error a service manager keeps: the
/// authentication audit trail `docs/qshd-service.md` points operators to in
/// `journalctl` is these lines.
///
/// Written with a plain `write(2)` on descriptor 2, its result discarded:
/// no `eprintln!` (which panics on a closed pipe or a hung-up terminal) and
/// no `Stderr` lock (which a process forked while another thread held it
/// would wait on forever).
pub fn mirror_to_stderr() {
    MIRRORED.store(true, Ordering::Relaxed);
}

/// Logs `msg` at level Info on behalf of `component` (`qshd`, `helper`,
/// `worker`, `update`, ...) -- see [`record`].
pub fn info(component: &str, msg: &str) {
    record(Level::Info, component, msg);
}

/// Logs `msg` at level Warn: a refusal, or something that did not work but
/// that the daemon carries on past. See [`record`].
pub fn warn(component: &str, msg: &str) {
    record(Level::Warn, component, msg);
}

/// Logs `msg` at level Error: a failure that ends or cripples a process or
/// a login. See [`record`].
pub fn error(component: &str, msg: &str) {
    record(Level::Error, component, msg);
}

/// Writes one record, in the shared line format, to the log (and to
/// standard error after [`mirror_to_stderr`]). No-op if the log is not
/// initialized (e.g. during the `ensure` stage before daemonization, or in
/// tests without [`init`]), and no-op for good once [`mute`] has been
/// called.
pub fn record(level: Level, component: &str, msg: &str) {
    write_record(level, component, msg, false);
}

/// As [`record`], and ALWAYS on standard error too, exactly once (whether
/// or not [`mirror_to_stderr`] was called): for the few lines a service
/// manager must see even from a process whose file log is not the one an
/// operator reads first -- the worker saying why it ends, `serve`'s startup
/// warnings.
pub fn loud(level: Level, component: &str, msg: &str) {
    write_record(level, component, msg, true);
}

fn write_record(level: Level, component: &str, msg: &str, to_stderr: bool) {
    if muted() {
        return;
    }
    let lines = logging::format_lines(SystemTime::now(), std::process::id(), level, component, msg);
    let text = joined(&lines);
    if let Some(cell) = LOGGER.get() {
        if let Ok(mut logger) = cell.lock() {
            logger.write_text(&text);
        }
    }
    if to_stderr || MIRRORED.load(Ordering::Relaxed) {
        write_stderr(text.as_bytes());
    }
}

/// A record's lines as one buffer, each ended by a newline: written with a
/// single `write`, so a multi-line record is not interleaved with another
/// process's line.
fn joined(lines: &[String]) -> String {
    let mut text = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
    for line in lines {
        text.push_str(line);
        text.push('\n');
    }
    text
}

/// `write(2)` to descriptor 2 until done or refused; errors are dropped. See
/// [`mirror_to_stderr`] for why not `eprintln!` or the `Stderr` lock.
fn write_stderr(mut bytes: &[u8]) {
    while !bytes.is_empty() {
        match nix::unistd::write(std::io::stderr(), bytes) {
            Ok(0) => return,
            Ok(n) => bytes = &bytes[n..],
            Err(nix::errno::Errno::EINTR) => {}
            Err(_) => return,
        }
    }
}

/// `text` on one line: every control character -- a newline above all --
/// and the Unicode line and paragraph separators (U+2028, U+2029)
/// written out as their Rust escapes (`\n`, `\u{1b}`, `\u{2028}`), so no part of it can
/// start a line of its own. For any text the daemon did not write itself:
/// a decode error quoting what a peer sent, a reason a child reported.
/// The log gives every line of a multi-line record the record's genuine
/// header ([`logging::format_lines`]), so a newline that reached a record
/// raw would let whoever chose that text write a whole line -- with this
/// process's pid and level -- that reads as the daemon's own word.
pub fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        // Every control character, the tab included, and U+2028/U+2029.
        if c == '\t' || logging::breaks_the_line(c) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

/// The components this daemon's own code logs under: their Info records are
/// kept, while every other library's (`alacritty_terminal`, `portable_pty`,
/// ...) must reach Warn to be worth a line.
const OWN_COMPONENTS: &[&str] = &["qshd", "helper", "worker", "monitor", "update", "transport"];

/// The `log::Log` behind the `log` crate's macros in this process: the
/// record's component is the first segment of its target
/// ([`logging::component_of`]), and it goes through [`record`] -- so the
/// same file, [`mute`] and [`mirror_to_stderr`] apply.
///
/// Its text is made [`one_line`] first: in this daemon these records come
/// from libraries -- `transport` above all, whose notices quote errors
/// about what a client on the network sent -- and none of them may start
/// a line of the daemon's log. (The daemon's own multi-line records, a
/// panic's, still repeat the header on each line.)
struct Adapter;

static ADAPTER: Adapter = Adapter;

impl ::log::Log for Adapter {
    fn enabled(&self, metadata: &::log::Metadata) -> bool {
        let component = logging::component_of(metadata.target());
        let limit = if OWN_COMPONENTS.contains(&component) {
            Level::Info
        } else {
            Level::Warn
        };
        metadata.level() <= limit
    }

    fn log(&self, rec: &::log::Record) {
        if !self.enabled(rec.metadata()) {
            return;
        }
        record(
            rec.level(),
            logging::component_of(rec.target()),
            &one_line(&rec.args().to_string()),
        );
    }

    fn flush(&self) {}
}

/// Installs [`Adapter`] as the process's `log` logger, once; a second call
/// (or a logger someone else installed first) changes nothing.
fn install_adapter() {
    if ::log::set_logger(&ADAPTER).is_ok() {
        ::log::set_max_level(::log::LevelFilter::Info);
    }
}

/// Internal logger state: the file open for appending, the rotation path,
/// and a counter of bytes written (so rotation decisions don't need a
/// `stat` on every line).
struct Logger {
    path: PathBuf,
    rotated_path: PathBuf,
    file: File,
    written: u64,
    max_bytes: u64,
    /// Whether the most recent rotation attempt failed and has already been
    /// reported. Writing itself goes through the already-open `file` above
    /// and keeps working regardless (a `write` on an open descriptor is not
    /// re-checked against the file's current permissions or owner), but
    /// `rotate` below opens and renames BY PATH, which is re-checked -- and
    /// fails for exactly this reason once the process that owns this logger
    /// is no longer privileged enough to touch its own log's directory (the
    /// system mode's worker, after `helper::drop_worker_privileges`, whose
    /// log stays in the account that started the daemon's cache directory).
    /// A silently swallowed rename failure would leave the log growing
    /// without bound and nothing on record to say why; this flag makes sure
    /// that is said once, loudly, instead of on every single line past the
    /// threshold forever.
    rotation_failed: bool,
}

impl Logger {
    fn open(path: PathBuf, rotated_path: PathBuf, max_bytes: u64) -> std::io::Result<Logger> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        restrict_to_owner(&path);
        Ok(Logger {
            path,
            rotated_path,
            file,
            written,
            max_bytes,
            rotation_failed: false,
        })
    }

    /// Appends `text` (whole lines, newlines included) with one `write`,
    /// rotating first if it would take the file past `max_bytes`.
    fn write_text(&mut self, text: &str) {
        let bytes = text.len() as u64;
        if self.written + bytes > self.max_bytes {
            self.rotate();
        }
        if self.file.write_all(text.as_bytes()).is_ok() {
            let _ = self.file.flush();
            self.written += bytes;
        }
    }

    /// Renames the current log to `qshd.log.1` (overwriting the previous
    /// rotation) and opens a fresh, empty `qshd.log`. On error, keeps the
    /// current file -- better to skip rotation than lose the writer.
    ///
    /// A rename failure here is reported to stderr, once, rather than
    /// swallowed: on any other day it means a genuinely unwritable
    /// directory, but for the system mode's worker it is the expected
    /// shape of "I dropped root and this log lives in root's directory" --
    /// see `rotation_failed`'s docs. Reported only the first time a given
    /// failure streak starts (`rotation_failed` already true means an
    /// earlier line already said so), so a daemon stuck past the threshold
    /// does not print the same line on every subsequent write.
    ///
    /// In the shared line format, through [`write_stderr`] -- never
    /// `eprintln!`, which panics on a write error (a closed pipe, a hung-up
    /// terminal -- entirely reachable for the personal mode's `serve`,
    /// which shares this same code path), and a panic here runs inside the
    /// `LOGGER` mutex, which poisons it and takes the entire log silently
    /// out of service for the rest of the process's life -- exactly the
    /// crash this module's own "must never crash the daemon" rule forbids.
    fn rotate(&mut self) {
        if let Err(err) = fs::rename(&self.path, &self.rotated_path) {
            if !self.rotation_failed {
                self.rotation_failed = true;
                let notice = format!(
                    "could not rotate the log file {} ({err}) -- writes through the \
                     already-open file descriptor will keep working, but the log will grow past \
                     its {} byte limit instead of rotating until the process is restarted with \
                     permission to do so",
                    self.path.display(),
                    self.max_bytes
                );
                let lines = logging::format_lines(
                    SystemTime::now(),
                    std::process::id(),
                    Level::Error,
                    "qshd",
                    &notice,
                );
                write_stderr(joined(&lines).as_bytes());
            }
            return;
        }
        self.rotation_failed = false;
        if let Ok(file) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            restrict_to_owner(&self.path);
            self.file = file;
            self.written = 0;
        }
    }
}

/// `0600` permissions on the log file (it holds diagnostics for a specific
/// user). Errors are ignored: the log must never crash the daemon.
fn restrict_to_owner(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
}

#[cfg(test)]
mod tests {
    use super::{joined, Level, Logger};
    use std::time::{Duration, UNIX_EPOCH};

    /// One record's text as [`super::write_record`] hands it to the file.
    fn text(at_ms: u64, msg: &str) -> String {
        let at = UNIX_EPOCH + Duration::from_millis(at_ms);
        joined(&logging::format_lines(at, 7, Level::Info, "qshd", msg))
    }

    /// Runs the `#[ignore]`d test `name` alone in a process of its own:
    /// [`super::init`] and the `log` crate's logger are once per process,
    /// so a test that points them at a file of its own must not share one.
    fn run_alone(name: &str) -> (String, String) {
        let out = std::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args([
                name,
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .expect("run the isolated check");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            stdout.contains("running 1 test\n"),
            "the filter must match exactly one test -- `{name}` renamed?\n{stdout}\n{stderr}"
        );
        assert!(
            out.status.success(),
            "the isolated check `{name}` failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
        (stdout, stderr)
    }

    fn read(p: &std::path::Path) -> String {
        std::fs::read_to_string(p).unwrap_or_default()
    }

    /// `YYYY-MM-DD HH:MM:SS.mmm UTC [pid] LEVEL component: text`, checked
    /// field by field rather than against a copy of the formatter.
    fn assert_shape(line: &str, pid: u32, level: &str, component: &str, msg: &str) {
        let b = line.as_bytes();
        assert!(line.len() > 28, "too short: {line:?}");
        for (i, c) in b[..23].iter().enumerate() {
            let want_digit = !matches!(i, 4 | 7 | 10 | 13 | 16 | 19);
            assert_eq!(c.is_ascii_digit(), want_digit, "timestamp shape: {line:?}");
        }
        assert_eq!(&line[23..28], " UTC ", "timestamp shape: {line:?}");
        let rest = format!("[{pid}] {level:<5} {component}: {msg}");
        assert_eq!(&line[28..], rest, "header after the timestamp: {line:?}");
    }

    #[test]
    fn a_record_has_the_shared_format_with_pid_level_and_component() {
        run_alone("log::tests::a_record_has_the_shared_format_with_pid_level_and_component_body");
    }

    #[test]
    #[ignore = "runs only via a_record_has_the_shared_format_with_pid_level_and_component"]
    fn a_record_has_the_shared_format_with_pid_level_and_component_body() {
        let dir = tempfile::tempdir().unwrap();
        super::init(dir.path());
        super::info("helper", "hello from the helper");
        super::warn("worker", "a refusal");
        super::error("update", "two\nlines");
        let log = read(&dir.path().join("qshd.log"));
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 4, "{log}");
        let pid = std::process::id();
        assert_shape(lines[0], pid, "INFO", "helper", "hello from the helper");
        assert_shape(lines[1], pid, "WARN", "worker", "a refusal");
        assert_shape(lines[2], pid, "ERROR", "update", "two");
        assert_shape(lines[3], pid, "ERROR", "update", "lines");
    }

    #[test]
    fn a_log_crate_record_from_transport_reaches_the_file() {
        run_alone("log::tests::a_log_crate_record_from_transport_reaches_the_file_body");
    }

    #[test]
    #[ignore = "runs only via a_log_crate_record_from_transport_reaches_the_file"]
    fn a_log_crate_record_from_transport_reaches_the_file_body() {
        let dir = tempfile::tempdir().unwrap();
        super::init(dir.path());
        ::log::warn!(target: "transport", "probe warn");
        ::log::info!(target: "transport::session_manager", "probe info");
        ::log::debug!(target: "transport", "probe debug");
        ::log::info!(target: "alacritty_terminal::term", "library info");
        ::log::warn!(target: "alacritty_terminal", "library warn");
        // A library's text may quote what a peer sent: it stays one line.
        ::log::warn!(target: "transport", "session refused: `x\nFailed signature for bob`");
        let log = read(&dir.path().join("qshd.log"));
        let pid = std::process::id();
        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 4, "{log}");
        assert_shape(lines[0], pid, "WARN", "transport", "probe warn");
        assert_shape(lines[1], pid, "INFO", "transport", "probe info");
        assert_shape(lines[2], pid, "WARN", "alacritty_terminal", "library warn");
        assert_shape(
            lines[3],
            pid,
            "WARN",
            "transport",
            "session refused: `x\\nFailed signature for bob`",
        );
    }

    #[test]
    fn one_line_escapes_every_control_character() {
        assert_eq!(super::one_line("plain text"), "plain text");
        assert_eq!(
            super::one_line("a\nb\r\tc\x1b[2J\u{85}"),
            "a\\nb\\r\\tc\\u{1b}[2J\\u{85}"
        );
        assert_eq!(
            super::one_line("a\u{2028}b\u{2029}c"),
            "a\\u{2028}b\\u{2029}c"
        );
        assert!(!super::one_line("x\ny").contains('\n'));
    }

    #[test]
    fn a_mirrored_process_writes_the_same_lines_to_stderr() {
        let (stdout, stderr) =
            run_alone("log::tests::a_mirrored_process_writes_the_same_lines_to_stderr_body");
        let file_line = stdout
            .lines()
            .find_map(|l| l.split_once("FILE LINE: ").map(|(_, line)| line))
            .unwrap_or_else(|| panic!("the child names its file line:\n{stdout}"));
        assert_eq!(
            stderr.lines().filter(|l| *l == file_line).count(),
            1,
            "stderr must carry the file's line, once:\nfile: {file_line}\nstderr:\n{stderr}"
        );
        assert_eq!(
            stderr.matches("loud and mirrored").count(),
            1,
            "a loud line in a mirrored process is still written once:\n{stderr}"
        );
    }

    #[test]
    #[ignore = "runs only via a_mirrored_process_writes_the_same_lines_to_stderr"]
    fn a_mirrored_process_writes_the_same_lines_to_stderr_body() {
        let dir = tempfile::tempdir().unwrap();
        super::mirror_to_stderr();
        super::init(dir.path());
        super::info("qshd", "mirrored");
        ::log::warn!(target: "transport", "from the transport");
        super::loud(Level::Warn, "qshd", "loud and mirrored");
        let log = read(&dir.path().join("qshd.log"));
        assert_eq!(log.lines().count(), 3, "{log}");
        println!("FILE LINE: {}", log.lines().next().unwrap());
    }

    #[test]
    fn an_unmirrored_process_writes_only_loud_lines_to_stderr() {
        let (_, stderr) =
            run_alone("log::tests::an_unmirrored_process_writes_only_loud_lines_to_stderr_body");
        assert!(!stderr.contains("quiet line"), "{stderr}");
        assert_eq!(
            stderr.matches("WARN  worker: loud line").count(),
            1,
            "{stderr}"
        );
    }

    #[test]
    #[ignore = "runs only via an_unmirrored_process_writes_only_loud_lines_to_stderr"]
    fn an_unmirrored_process_writes_only_loud_lines_to_stderr_body() {
        let dir = tempfile::tempdir().unwrap();
        super::init(dir.path());
        super::info("qshd", "quiet line");
        super::loud(Level::Warn, "worker", "loud line");
        let log = read(&dir.path().join("qshd.log"));
        assert!(log.contains("INFO  qshd: quiet line"), "{log}");
        assert!(log.contains("WARN  worker: loud line"), "{log}");
    }

    /// [`super::mute`] silences the mirror as well as the file: a muted
    /// process has nowhere it may write, standard error included.
    #[cfg(feature = "system")]
    #[test]
    fn a_muted_process_writes_nowhere() {
        let (_, stderr) = run_alone("log::tests::a_muted_process_writes_nowhere_body");
        assert!(stderr.contains("before the mute"), "{stderr}");
        assert!(!stderr.contains("after the mute"), "{stderr}");
    }

    #[cfg(feature = "system")]
    #[test]
    #[ignore = "runs only via a_muted_process_writes_nowhere"]
    fn a_muted_process_writes_nowhere_body() {
        let dir = tempfile::tempdir().unwrap();
        super::mirror_to_stderr();
        super::init(dir.path());
        super::info("qshd", "before the mute");
        super::mute();
        super::info("qshd", "after the mute");
        super::loud(Level::Error, "qshd", "after the mute, loud");
        ::log::warn!(target: "transport", "after the mute, transport");
        let log = read(&dir.path().join("qshd.log"));
        assert!(log.contains("before the mute"), "{log}");
        assert!(!log.contains("after the mute"), "{log}");
    }

    #[test]
    fn rotates_when_exceeding_max_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qshd.log");
        let rotated = dir.path().join("qshd.log.1");
        // Small threshold so rotation happens after just a few lines.
        let mut logger = Logger::open(path.clone(), rotated.clone(), 64).unwrap();

        for i in 0..20 {
            logger.write_text(&text(1_000 + i, &format!("event number {i}")));
        }

        assert!(
            rotated.exists(),
            "qshd.log.1 appears once the threshold is exceeded"
        );
        let current = std::fs::metadata(&path).unwrap().len();
        assert!(
            current <= 64 + 64,
            "the current log stays small after rotation: {current}"
        );
        // Every line is whole: rotation happens between records.
        let rotated_text = std::fs::read_to_string(&rotated).unwrap();
        assert!(rotated_text
            .lines()
            .all(|l| l.starts_with("1970-01-01 00:00:01.") && l.contains(" INFO  qshd: event")));
    }

    /// The seam a privilege drop opens: once the process that owns an
    /// already-open log file descriptor is no longer privileged enough to
    /// touch the log's DIRECTORY (the system mode's worker, after
    /// `helper::drop_worker_privileges`, whose log stays in the account
    /// that started the daemon's cache directory), `rename` -- which
    /// resolves a path and is re-checked -- fails, while `write` through
    /// the descriptor already open before the drop keeps succeeding
    /// regardless, because the kernel does not re-check a write against the
    /// file's current permissions or owner.
    ///
    /// Reproduced here without needing an actual `setuid` or a second
    /// account: stripping the directory's write bit produces exactly the
    /// same `rename` failure a lost privilege would, for the same reason
    /// (the kernel's directory permission check, not an identity check).
    /// Skipped under root, which bypasses that check entirely and would
    /// turn this into a false failure rather than a faithful reproduction.
    #[cfg(unix)]
    #[test]
    fn a_rotation_that_cannot_rename_is_reported_once_but_writes_keep_working() {
        use std::os::unix::fs::PermissionsExt;

        if nix::unistd::Uid::effective().is_root() {
            eprintln!(
                "SKIPPED a_rotation_that_cannot_rename_is_reported_once_but_writes_keep_working: \
                 root bypasses the directory permission check this test relies on."
            );
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qshd.log");
        let rotated = dir.path().join("qshd.log.1");
        // Small threshold so a couple of lines are enough to cross it.
        let mut logger = Logger::open(path.clone(), rotated.clone(), 64).unwrap();

        // Remove the directory's write bit: `rename` needs it, `write` on
        // the already-open descriptor above does not.
        let original_mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o500)).unwrap();
        let restore = |mode: u32| {
            let _ = std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode));
        };

        for i in 0..20 {
            logger.write_text(&text(1_000 + i, &format!("event number {i}")));
        }

        restore(original_mode & 0o777);

        assert!(
            !rotated.exists(),
            "rotation cannot happen without write permission on the directory"
        );
        assert!(
            logger.rotation_failed,
            "a rotation that could not rename must be noticed, not swallowed silently"
        );
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            text.contains("event number 19"),
            "writes through the already-open descriptor must keep succeeding even though \
             rotation cannot: {text:?}"
        );
    }

    #[test]
    fn appends_to_existing_and_tracks_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qshd.log");
        let rotated = dir.path().join("qshd.log.1");
        {
            let mut logger = Logger::open(path.clone(), rotated.clone(), 1_000_000).unwrap();
            logger.write_text(&text(1, "first"));
        }
        // Reopening continues appending without wiping out the past.
        let mut logger = Logger::open(path.clone(), rotated.clone(), 1_000_000).unwrap();
        logger.write_text(&text(2, "second"));
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("first") && text.contains("second"));
        assert!(
            !rotated.exists(),
            "no rotation without exceeding the threshold"
        );
    }
}
