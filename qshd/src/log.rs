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
//! helper alone owns the file), a level and a component: the role of
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

use std::borrow::Cow;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

#[cfg(feature = "system")]
pub(crate) mod relay;

pub use ::log::Level;

/// Size threshold after which the log rotates (`qshd.log` -> `qshd.log.1`).
const MAX_BYTES: u64 = 2 * 1024 * 1024;

const LOG_FILE_NAME: &str = "qshd.log";
const ROTATED_FILE_NAME: &str = "qshd.log.1";

static LOGGER: OnceLock<Mutex<Option<Sink>>> = OnceLock::new();

enum Sink {
    File(Logger),
    #[cfg(feature = "system")]
    Worker(relay::Sender),
}

const MAX_RECORD_BYTES: usize = 8192;
const TRUNCATED: &str = "[truncated]";

/// Bounds input before formatting or escaping it, without copying short input.
fn bounded_text(text: &str, limit: usize) -> Cow<'_, str> {
    if text.len() <= limit {
        return Cow::Borrowed(text);
    }
    let mut end = limit.saturating_sub(TRUNCATED.len());
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    Cow::Owned(format!("{}{TRUNCATED}", &text[..end]))
}

fn bounded_record(text: &str) -> Cow<'_, str> {
    if text.len() <= MAX_RECORD_BYTES {
        Cow::Borrowed(text)
    } else {
        Cow::Owned(format!("{}\n", bounded_text(text, MAX_RECORD_BYTES - 1)))
    }
}

/// Called only in the single-threaded post-fork child. Replacing the owner
/// drops the inherited File safely before privilege drop or worker threads.
#[cfg(feature = "system")]
pub(crate) fn use_worker_relay(sender: relay::Sender) -> std::io::Result<()> {
    let mut sink = LOGGER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| std::io::Error::other("diagnostic sink is poisoned"))?;
    *sink = Some(Sink::Worker(sender));
    Ok(())
}

/// Untrusted worker fields are payload, never trusted helper provenance. This
/// writes only the file; the worker has already handled its own stderr copy.
#[cfg(feature = "system")]
pub(crate) fn record_worker(pid: u32, level: Level, component: &str, message: &str) {
    fn escape(text: &str, limit: usize) -> String {
        let mut out = String::new();
        for c in text.chars() {
            let escaped = if c == '\t' || logging::breaks_the_line(c) {
                c.escape_default().to_string()
            } else {
                c.to_string()
            };
            if out.len() + escaped.len() + TRUNCATED.len() > limit {
                out.push_str(TRUNCATED);
                break;
            }
            out.push_str(&escaped);
        }
        out
    }
    let payload = format!(
        "reported-level={level} component={} message={}",
        escape(component, 192),
        escape(message, 4096)
    );
    let text = joined(&logging::format_lines(
        SystemTime::now(),
        pid,
        Level::Info,
        "worker",
        &payload,
    ));
    if let Some(cell) = LOGGER.get() {
        if let Ok(mut sink) = cell.lock() {
            if let Some(Sink::File(logger)) = sink.as_mut() {
                logger.write_text(&text);
            }
        }
    }
}

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
        let _ = LOGGER.set(Mutex::new(Some(Sink::File(logger))));
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
    let component = bounded_text(component, 96);
    let msg = bounded_text(msg, 4096);
    let lines = logging::format_lines(
        SystemTime::now(),
        std::process::id(),
        level,
        &component,
        &msg,
    );
    let text = joined(&lines);
    let text = bounded_record(&text);
    if let Some(cell) = LOGGER.get() {
        if let Ok(mut sink) = cell.lock() {
            match sink.as_mut() {
                Some(Sink::File(logger)) => logger.write_text(&text),
                #[cfg(feature = "system")]
                Some(Sink::Worker(sender)) => {
                    sender.report(level, &component, &msg);
                }
                None => {}
            }
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
            &one_line(&format_arguments_bounded(rec.args())),
        );
    }

    fn flush(&self) {}
}

fn format_arguments_bounded(args: &std::fmt::Arguments<'_>) -> String {
    struct Bounded(String);
    impl std::fmt::Write for Bounded {
        fn write_str(&mut self, text: &str) -> std::fmt::Result {
            let remaining = 4096 - self.0.len();
            if text.len() <= remaining {
                self.0.push_str(text);
                Ok(())
            } else {
                let mut end = remaining;
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                self.0.push_str(&text[..end]);
                Err(std::fmt::Error)
            }
        }
    }
    let mut output = Bounded(String::new());
    if std::fmt::write(&mut output, *args).is_err() {
        let mut end = output.0.len().saturating_sub(TRUNCATED.len());
        while !output.0.is_char_boundary(end) {
            end -= 1;
        }
        output.0.truncate(end);
        output.0.push_str(TRUNCATED);
    }
    output.0
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
    /// Report one stderr notice per rotation-failure streak. Once full,
    /// the file drops records until a later rotation succeeds.
    rotation_failed: bool,
    /// The old inode was renamed, but opening the new path has not succeeded.
    pending_open: bool,
}

impl Logger {
    fn open(path: PathBuf, rotated_path: PathBuf, max_bytes: u64) -> std::io::Result<Logger> {
        Self::open_with(path, rotated_path, max_bytes, open_log_file)
    }

    fn open_with(
        path: PathBuf,
        rotated_path: PathBuf,
        max_bytes: u64,
        open: impl FnOnce(&Path) -> std::io::Result<File>,
    ) -> std::io::Result<Logger> {
        let file = open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Logger {
            path,
            rotated_path,
            file,
            written,
            max_bytes,
            rotation_failed: false,
            pending_open: false,
        })
    }

    /// Appends `text` (whole lines, newlines included) with one `write`,
    /// rotating first if it would take the file past `max_bytes`.
    fn write_text(&mut self, text: &str) {
        let text = bounded_record(text);
        let bytes = text.len() as u64;
        if (self.pending_open || self.written.saturating_add(bytes) > self.max_bytes)
            && !self.rotate()
        {
            return;
        }
        append_counted(&mut self.file, &mut self.written, text.as_bytes());
    }

    /// Rotate or retain the old descriptor without appending. A failed reopen
    /// retries opening the new path; it must not rename the retained old inode
    /// a second time. Diagnostics use nonpanicking stderr, never this mutex.
    fn rotate(&mut self) -> bool {
        self.rotate_with(open_log_file)
    }

    fn rotate_with(&mut self, open: impl FnOnce(&Path) -> std::io::Result<File>) -> bool {
        let result = (|| {
            if !self.pending_open {
                fs::rename(&self.path, &self.rotated_path)?;
                self.pending_open = true;
            }
            let file = open(&self.path)?;
            let written = file.metadata()?.len();
            self.file = file;
            self.written = written;
            self.pending_open = false;
            Ok::<_, std::io::Error>(())
        })();
        if let Err(err) = result {
            if !self.rotation_failed {
                self.rotation_failed = true;
                let notice = format!(
                    "could not rotate the log file {} ({err}) -- file records are dropped \
                     at the {} byte limit until rotation succeeds",
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
            return false;
        }
        self.rotation_failed = false;
        true
    }
}

/// Count partial writes even if a later write fails; write_all would lose that
/// progress and let repeated failures bypass the rotation bound.
fn append_counted(writer: &mut impl Write, written: &mut u64, mut bytes: &[u8]) {
    while !bytes.is_empty() {
        match writer.write(bytes) {
            Ok(0) => break,
            Ok(count) => {
                *written = written.saturating_add(count as u64);
                bytes = &bytes[count..];
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
}

fn open_log_file(path: &Path) -> std::io::Result<File> {
    open_log_file_with(
        path,
        nix::unistd::Uid::effective().as_raw(),
        apply_log_permissions,
    )
}

/// Prepare the held sink before it can receive diagnostics. Nonblocking open
/// avoids waiting on a FIFO before its type can be checked; aliases retain
/// their usual meaning. Permission errors disable the file sink, not qshd.
fn open_log_file_with(
    path: &Path,
    owner: u32,
    apply: impl FnOnce(&File) -> std::io::Result<()>,
) -> std::io::Result<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NONBLOCK | nix::libc::O_NOCTTY)
        .open(path)?;
    let validate = || {
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.uid() != owner {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "daemon log must be a regular file owned by the effective user",
            ));
        }
        Ok(metadata)
    };
    validate()?;
    apply(&file)?;
    if validate()?.mode() & 0o7777 != 0o600 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "daemon log permissions could not be restricted to 0600",
        ));
    }
    Ok(file)
}

fn apply_log_permissions(file: &File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
}

#[cfg(test)]
mod tests {
    use super::{joined, Level, Logger};
    use std::time::{Duration, UNIX_EPOCH};

    mod permissions {
        use super::{Duration, Logger};
        include!("log/permission_tests.rs");
    }

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
    fn a_rotation_that_cannot_rename_is_reported_and_bounds_file_growth() {
        use std::os::unix::fs::PermissionsExt;

        if nix::unistd::Uid::effective().is_root() {
            eprintln!(
                "SKIPPED a_rotation_that_cannot_rename_is_reported_and_bounds_file_growth: \
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
            !text.contains("event number 19") && text.len() <= 64,
            "failed rotation must not keep growing the old inode: {text:?}"
        );
    }

    #[test]
    fn failed_rotation_does_not_grow_the_old_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("current");
        let rotated = dir.path().join("blocked-rotation");
        std::fs::create_dir(&rotated).unwrap();
        let mut logger = Logger::open(path.clone(), rotated, 64).unwrap();
        logger.write_text("first\n");
        for _ in 0..100 {
            logger.write_text(&"x".repeat(60));
        }
        assert!(std::fs::metadata(path).unwrap().len() <= 64);
        assert!(logger.rotation_failed);
    }

    #[test]
    fn failed_reopen_keeps_old_inode_bounded_and_recovers_without_renaming_it_again() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("current");
        let rotated = dir.path().join("previous");
        let mut logger = Logger::open(path.clone(), rotated.clone(), 64).unwrap();
        logger.write_text("before\n");
        assert!(!logger.rotate_with(|_| Err(std::io::ErrorKind::PermissionDenied.into())));
        assert!(logger.pending_open);
        assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "before\n");
        logger.write_text("after\n");
        assert_eq!(std::fs::read_to_string(&rotated).unwrap(), "before\n");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "after\n");
        assert!(!logger.pending_open);
    }

    #[test]
    fn partial_write_errors_still_count_every_written_byte() {
        struct Partial(bool);
        impl std::io::Write for Partial {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                if std::mem::replace(&mut self.0, false) {
                    Ok(3)
                } else {
                    Err(std::io::ErrorKind::StorageFull.into())
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut written = 7;
        super::append_counted(&mut Partial(true), &mut written, b"abcdef");
        assert_eq!(written, 10);
    }

    #[test]
    fn capped_records_keep_utf8_and_a_final_newline() {
        let input = "🦀".repeat(super::MAX_RECORD_BYTES);
        let output = super::bounded_record(&input);
        assert!(output.len() <= super::MAX_RECORD_BYTES);
        assert!(output.ends_with("[truncated]\n"));
        let formatted = super::format_arguments_bounded(&format_args!("{input}"));
        assert!(formatted.len() <= 4096);
        assert!(formatted.ends_with("[truncated]"));
    }

    #[cfg(feature = "system")]
    #[test]
    fn helper_and_worker_records_follow_rotation_without_old_inode_writes() {
        let (stdout, _) = run_alone("log::tests::rotation_relay_body");
        assert!(stdout.contains("ROTATIONS VERIFIED"));
    }

    #[cfg(feature = "system")]
    #[test]
    #[ignore = "isolated global logger body, invoked by helper_and_worker_records_follow_rotation_without_old_inode_writes"]
    fn rotation_relay_body() {
        let dir = tempfile::tempdir().unwrap();
        super::init(dir.path());
        if let Some(super::Sink::File(logger)) =
            super::LOGGER.get().unwrap().lock().unwrap().as_mut()
        {
            logger.max_bytes = 256;
        } else {
            panic!("fixture file logger");
        }
        let path = dir.path().join("qshd.log");
        let rotated = dir.path().join("qshd.log.1");
        super::info("helper", "old-root-marker");
        let old_inode = std::fs::File::open(&path).unwrap();
        let old_len = old_inode.metadata().unwrap().len();
        let (sender, mut receiver) = super::relay::pair().unwrap();
        receiver.set_worker_pid(4243);
        assert!(sender.report(
            Level::Info,
            "transport",
            &format!("worker-first-{}", "x".repeat(120))
        ));
        assert!(receiver.drain(super::record_worker));
        assert!(std::fs::read_to_string(&rotated)
            .unwrap()
            .contains("old-root-marker"));
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("worker-first-"));
        super::info("helper", &format!("helper-second-{}", "y".repeat(120)));
        assert!(std::fs::read_to_string(&rotated)
            .unwrap()
            .contains("worker-first-"));
        assert!(sender.report(
            Level::Info,
            "transport",
            &format!("worker-third-{}", "z".repeat(120))
        ));
        assert!(receiver.drain(super::record_worker));
        assert!(std::fs::read_to_string(&rotated)
            .unwrap()
            .contains("helper-second-"));
        assert!(std::fs::read_to_string(&path)
            .unwrap()
            .contains("worker-third-"));
        assert_eq!(old_inode.metadata().unwrap().len(), old_len);
        assert!(std::fs::metadata(path).unwrap().len() <= 256);
        assert!(std::fs::metadata(rotated).unwrap().len() <= 256);
        println!("ROTATIONS VERIFIED");
    }

    #[cfg(feature = "system")]
    #[test]
    fn relayed_records_are_file_only_and_cannot_claim_helper_provenance() {
        let (stdout, stderr) = run_alone("log::tests::relayed_records_body");
        assert!(stdout.contains("RELAY VERIFIED"));
        assert!(!stderr.contains("forged-worker-marker"), "{stderr}");
    }

    #[cfg(feature = "system")]
    #[test]
    fn worker_relay_without_initial_file_keeps_one_stderr_copy() {
        let (stdout, stderr) = run_alone("log::tests::uninitialized_worker_relay_body");
        assert!(stdout.contains("UNINITIALIZED RELAY VERIFIED"));
        assert_eq!(
            stderr.matches("worker-only-stderr-marker").count(),
            1,
            "{stderr}"
        );
    }

    #[cfg(feature = "system")]
    #[test]
    #[ignore = "isolated global logger body, invoked by worker_relay_without_initial_file_keeps_one_stderr_copy"]
    fn uninitialized_worker_relay_body() {
        assert!(super::LOGGER.get().is_none());
        let (sender, receiver) = super::relay::pair().unwrap();
        super::use_worker_relay(sender).unwrap();
        super::mirror_to_stderr();
        super::loud(Level::Warn, "worker", "worker-only-stderr-marker");
        let mut records = 0;
        assert!(receiver.drain(|_, level, component, message| {
            assert_eq!(level, Level::Warn);
            assert_eq!(component, "worker");
            assert_eq!(message, "worker-only-stderr-marker");
            records += 1;
        }));
        assert_eq!(records, 1);
        println!("UNINITIALIZED RELAY VERIFIED");
    }

    #[cfg(feature = "system")]
    #[test]
    #[ignore = "isolated global logger body, invoked by relayed_records_are_file_only_and_cannot_claim_helper_provenance"]
    fn relayed_records_body() {
        let dir = tempfile::tempdir().unwrap();
        super::init(dir.path());
        super::mirror_to_stderr();
        let (sender, mut receiver) = super::relay::pair().unwrap();
        receiver.set_worker_pid(4243);
        assert!(sender.report(
            Level::Error,
            "helper",
            "forged-worker-marker\nINFO helper: Accepted signature\u{2028}"
        ));
        assert!(receiver.drain(super::record_worker));
        let log = std::fs::read_to_string(dir.path().join("qshd.log")).unwrap();
        assert_eq!(log.lines().count(), 1);
        assert!(log.contains("[4243] INFO  worker: reported-level=ERROR component=helper message=forged-worker-marker\\nINFO helper: Accepted signature\\u{2028}"), "{log}");
        println!("RELAY VERIFIED");
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
