//! Private exact-test self-reexec for fixtures that deliberately orphan jobs.
//! Neither subreaping nor descendant collection runs in ordinary shared libtest.
use nix::libc;
use std::{
    os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

const MODE: &str = "QSH_TEST_BORROWED_SCOPE_MODE";
const TEST: &str = "QSH_TEST_BORROWED_SCOPE_TEST";
const PARENT: &str = "QSH_TEST_BORROWED_SCOPE_PARENT";
const REPORT: &str = "QSH_TEST_BORROWED_SCOPE_REPORT";
// Observation deadline only. These fixed fixtures create finite killable jobs;
// consuming waits retain custody even if an OS wait cannot finish promptly.
// This helper does not promise a universal wall bound for uninterruptible exit.
const BODY_LIMIT: Duration = Duration::from_secs(30);
static EXPECTED_WAITS: AtomicUsize = AtomicUsize::new(0);

// Reports contain only closed diagnostic codes and bounded numeric facts.
// In particular, panic payloads, stderr, identities and environment are never copied.
const REPORT_LIMIT: usize = 1024;
macro_rules! diagnostic_codes {
    ($name:ident { $($variant:ident => $label:literal),+ $(,)? }) => {
        #[derive(Clone, Copy)]
        pub(crate) enum $name { $($variant),+ }
        impl $name {
            fn label(code: usize) -> &'static str {
                match code {
                    $(value if value == Self::$variant as usize => $label,)+
                    _ => "unknown",
                }
            }
        }
    };
}
diagnostic_codes!(DiagnosticMode {
    Unspecified => "unspecified", Close => "close", LeaderFirst => "leader-first",
    LoginEnded => "login-ended", NegativeControl => "negative-control",
});
diagnostic_codes!(DiagnosticPhase {
    Unspecified => "unspecified", Setup => "setup", Identity => "identity",
    MemberExec => "member-exec", Membership => "membership", PtyAck => "pty-ack",
    Receipt => "receipt", Cleanup => "cleanup", Assertions => "assertions", Complete => "complete",
});
diagnostic_codes!(DiagnosticAssertion {
    Unspecified => "unspecified", Opened => "opened", Barrier => "identity-barrier",
    Pin => "pin", Alive => "jobs-alive", MemberExec => "member-exec",
    Session => "session-membership", ProcessGroup => "sibling-process-group",
    Parent => "monitor-parent", Write => "pty-write", Ack => "pty-ack",
    Receive => "scope-response", Join => "helper-join", Receipt => "scope-receipt",
    MemberExit => "member-exit", EarlyPam => "no-early-pam-close", PamClosed => "pam-closed",
    Elapsed => "receipt-deadline", LeaderStatus => "leader-status", Deliberate => "deliberate-assertion",
});

#[derive(Clone, Copy, Default)]
struct Diagnostic {
    mode: usize,
    phase: usize,
    assertion: usize,
    elapsed_ms: usize,
    observations: usize,
    cleanup_stops: usize,
    exit_code: usize,
}
impl std::fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Diagnostic")
            .field("mode", &DiagnosticMode::label(self.mode))
            .field("phase", &DiagnosticPhase::label(self.phase))
            .field("assertion", &DiagnosticAssertion::label(self.assertion))
            .field("elapsed_ms", &self.elapsed_ms)
            .field("receipt", &(self.observations & 1 != 0))
            .field("exit_seen", &(self.observations & 2 != 0))
            .field(
                "exit_code",
                &(if self.observations & 2 != 0 {
                    Some(self.exit_code as u32 as i32)
                } else {
                    None
                }),
            )
            .field("member_exited", &(self.observations & 4 != 0))
            .field("live_member_at_receipt", &(self.observations & 8 != 0))
            .field("early_pam_close", &(self.observations & 16 != 0))
            .field("pam_closed", &(self.observations & 32 != 0))
            .field("helper_joined", &(self.observations & 64 != 0))
            .field("leader_cleanup_stop", &(self.cleanup_stops & 1 != 0))
            .field("member_cleanup_stop", &(self.cleanup_stops & 2 != 0))
            .field("monitor_cleanup_stop", &(self.cleanup_stops & 4 != 0))
            .finish()
    }
}
impl Diagnostic {
    fn report_fields(self) -> String {
        format!("mode={} phase={} assertion={} elapsed_ms={} observations={} cleanup_stops={} exit_code={}",
            self.mode, self.phase, self.assertion, self.elapsed_ms, self.observations, self.cleanup_stops, self.exit_code)
    }
    fn from_fields(fields: &std::collections::BTreeMap<String, usize>) -> Self {
        let field = |name| fields.get(name).copied().unwrap_or(0);
        Self {
            mode: field("mode"),
            phase: field("phase"),
            assertion: field("assertion"),
            elapsed_ms: field("elapsed_ms"),
            observations: field("observations"),
            cleanup_stops: field("cleanup_stops"),
            exit_code: field("exit_code"),
        }
    }
}
thread_local! {
    static DIAGNOSTIC: std::cell::Cell<Diagnostic> = const { std::cell::Cell::new(Diagnostic {
        mode: 0, phase: 0, assertion: 0, elapsed_ms: 0, observations: 0, cleanup_stops: 0, exit_code: 0,
    }) };
}
pub(crate) fn diagnostic_mode(mode: DiagnosticMode) {
    DIAGNOSTIC.set(Diagnostic {
        mode: mode as usize,
        ..Diagnostic::default()
    });
}
pub(crate) fn diagnostic_phase(phase: DiagnosticPhase) {
    DIAGNOSTIC.with(|cell| {
        cell.set(Diagnostic {
            phase: phase as usize,
            assertion: 0,
            elapsed_ms: 0,
            ..cell.get()
        })
    });
}
// Elapsed is relative to the caller's existing observation budget, not cleanup time.
pub(crate) fn diagnostic_assertion(assertion: DiagnosticAssertion, elapsed: Duration) {
    DIAGNOSTIC.with(|cell| {
        cell.set(Diagnostic {
            assertion: assertion as usize,
            elapsed_ms: elapsed.as_millis().min(usize::MAX as u128) as usize,
            ..cell.get()
        })
    });
}
// Fixed bit meanings: receipt, exit response, member exited, live member at receipt,
// early PAM close, final PAM close, helper joined. No process identities are retained.
pub(crate) fn diagnostic_observations(bits: usize) {
    DIAGNOSTIC.with(|cell| {
        cell.set(Diagnostic {
            observations: bits,
            ..cell.get()
        })
    });
}
pub(crate) fn diagnostic_exit_code(code: Option<i32>) {
    DIAGNOSTIC.with(|cell| {
        cell.set(Diagnostic {
            exit_code: code.unwrap_or(0) as u32 as usize,
            ..cell.get()
        })
    });
}
// Cleanup updates cannot overwrite the phase/assertion that caused unwinding.
// Bits identify fixture roles only: leader=1, member=2, monitor=4.
pub(crate) fn diagnostic_cleanup_stops(bits: usize) {
    DIAGNOSTIC.with(|cell| {
        cell.set(Diagnostic {
            cleanup_stops: cell.get().cleanup_stops | bits,
            ..cell.get()
        })
    });
}
fn write_report(path: impl AsRef<std::path::Path>, report: String) {
    assert!(report.len() <= REPORT_LIMIT, "bounded fixture report");
    std::fs::write(path, report).unwrap();
}

#[derive(Debug)]
pub(crate) struct Outcome {
    pub(crate) body_success: bool,
    pub(crate) timed_out: bool,
    pub(crate) expected_waits: usize,
    pub(crate) body_adopted: usize,
    pub(crate) body_rescues: usize,
    pub(crate) supervisor_adopted: usize,
    pub(crate) supervisor_rescues: usize,
    pub(crate) no_children: bool,
    pub(crate) supervisor_success: bool,
    diagnostic: Diagnostic,
}
impl Outcome {
    pub(crate) fn assert_clean(&self, expected_waits: usize) {
        assert!(
            self.supervisor_success
                && self.body_success
                && !self.timed_out
                && self.expected_waits == expected_waits
                && self.body_adopted == 0
                && self.body_rescues == 0
                && self.supervisor_adopted == 0
                && self.supervisor_rescues == 0
                && self.no_children,
            "borrowed fixture did not finish unaided: {self:?}"
        );
    }
}

fn pin(pid: u32) -> OwnedFd {
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    assert!(raw >= 0, "private fixture pidfd_open unavailable");
    unsafe { OwnedFd::from_raw_fd(raw as i32) }
}
fn exited(fd: BorrowedFd<'_>) -> bool {
    let mut descriptor = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result >= 0 {
            return descriptor.revents & libc::POLLIN != 0;
        }
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINTR)
        );
    }
}
fn signal_kill(fd: BorrowedFd<'_>) {
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            libc::SIGKILL,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    assert!(result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
}
fn wait_exact(fd: BorrowedFd<'_>) {
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                fd.as_raw_fd() as u32,
                &mut info,
                libc::WEXITED | libc::__WALL,
            )
        };
        if result == 0 {
            assert!(
                unsafe { info.si_pid() } > 0,
                "actual consuming wait required"
            );
            return;
        }
        // ECHILD is a lost/not-owned wait, never a successful fixture receipt.
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::EINTR)
        );
    }
}
/// Called only for a positively identified fixture member, after its parent
/// has ended and this dedicated body has adopted it. No ECHILD shortcut.
pub(crate) fn wait_expected(fd: BorrowedFd<'_>) {
    assert_eq!(std::env::var(MODE).as_deref(), Ok("body"));
    wait_exact(fd);
    EXPECTED_WAITS.fetch_add(1, Ordering::SeqCst);
}

fn qualify_private_child() {
    super::qualify_borrowed_fixture();
    assert_eq!(
        std::env::var(PARENT).unwrap().parse::<u32>().unwrap(),
        unsafe { libc::getppid() } as u32
    );
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) },
        0
    );
    assert_eq!(
        action.sa_sigaction,
        libc::SIG_DFL,
        "private fixture needs exclusive waits"
    );
    assert_eq!(action.sa_flags & libc::SA_NOCLDWAIT, 0);
    let own = pin(std::process::id());
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            own.as_raw_fd(),
            0,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    assert_eq!(result, 0);
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) },
        0
    );
    let mut enabled = 0i32;
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &mut enabled, 0, 0, 0) },
        0
    );
    assert_eq!(enabled, 1);
}

#[derive(Default)]
struct Drain {
    adopted: usize,
    rescues: usize,
}
fn drain_owned_children() -> Drain {
    // As in the qualified adoption fixtures: include the libtest body's task,
    // not just /proc/self/task/<main>/children. Every child belongs to this case.
    use std::os::fd::AsFd;
    let mut drain = Drain::default();
    loop {
        let mut children = std::collections::BTreeSet::new();
        for task in std::fs::read_dir("/proc/self/task").unwrap() {
            let path = task.unwrap().path().join("children");
            match std::fs::read_to_string(path) {
                Ok(text) => {
                    children.extend(text.split_whitespace().map(|p| p.parse::<u32>().unwrap()))
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("owned fixture child census: {error}"),
            }
        }
        if children.is_empty() {
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::waitid(
                    libc::P_ALL,
                    0,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
                )
            };
            if result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            assert_eq!(result, -1, "empty census alone is not no-child proof");
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
            return drain;
        }
        for child in children {
            // These are our exclusively waitable direct children. Their PIDs
            // stay reserved until this exact wait; only the pidfd is signaled.
            let fd = pin(child);
            if !exited(fd.as_fd()) {
                signal_kill(fd.as_fd());
                drain.rescues += 1;
            }
            wait_exact(fd.as_fd());
            drain.adopted += 1;
        }
    }
}
struct DrainOnDrop(bool);
impl DrainOnDrop {
    fn finish(&mut self) -> Drain {
        let result = drain_owned_children();
        self.0 = true;
        result
    }
}
impl Drop for DrainOnDrop {
    fn drop(&mut self) {
        if !self.0 {
            // Declared before the root owner: unwind kills/waits that root
            // first, then retains all of its adopted descendants here.
            let _ = self.finish();
        }
    }
}
struct ChildOwner {
    child: Child,
    reaped: bool,
    authority: bool,
}
impl ChildOwner {
    fn wait(&mut self) -> std::io::Result<std::process::ExitStatus> {
        loop {
            match self.child.wait() {
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                result => {
                    self.reaped = result.is_ok();
                    if result.is_err() {
                        self.authority = false;
                    }
                    return result;
                }
            }
        }
    }
}
impl Drop for ChildOwner {
    fn drop(&mut self) {
        if !self.reaped && self.authority {
            // This root is still an exclusively owned, unreaped direct child.
            let _ = self.child.kill();
            let _ = self.wait();
        }
    }
}
fn command(test: &str, mode: &str, report: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", test, "--test-threads=1"])
        .env(MODE, mode)
        .env(TEST, test)
        .env(PARENT, std::process::id().to_string())
        .env(REPORT, report)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // No inherited output pipe can be held by a borrowed job. The bounded
    // private report supplies status; there are no detached pipe collectors.
    command
}
fn read_fields(path: &std::path::Path) -> std::collections::BTreeMap<String, usize> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .unwrap()
        .take((REPORT_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .unwrap();
    assert!(bytes.len() <= REPORT_LIMIT, "bounded fixture report");
    String::from_utf8(bytes)
        .unwrap()
        .split_whitespace()
        .map(|field| {
            let (key, value) = field.split_once('=').unwrap();
            (key.to_string(), value.parse::<usize>().unwrap())
        })
        .collect()
}

/// One fixed exact test, two private stages. A body panic/crash/timeout remains
/// failed after the supervisor has actually waited its root and all adoptees.
pub(crate) fn run_exact(test: &str, expected_waits: usize, body: impl FnOnce()) -> Outcome {
    match std::env::var(MODE).ok().as_deref() {
        Some("body") => {
            qualify_private_child();
            assert_eq!(std::env::var(TEST).unwrap(), test);
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
            let drain = drain_owned_children();
            let waits = EXPECTED_WAITS.load(Ordering::SeqCst);
            let success = result.is_ok() && waits == expected_waits && drain.adopted == 0;
            write_report(std::env::var_os(REPORT).unwrap(), format!(
                "body_success={} expected_waits={waits} body_adopted={} body_rescues={} no_children=1 {}",
                usize::from(success), drain.adopted, drain.rescues, DIAGNOSTIC.get().report_fields()));
            std::process::exit(if success { 0 } else { 101 });
        }
        Some("supervisor") => {
            qualify_private_child();
            assert_eq!(std::env::var(TEST).unwrap(), test);
            let report = std::path::PathBuf::from(std::env::var_os(REPORT).unwrap());
            let body_report = report.with_extension("body");
            let mut cleanup = DrainOnDrop(false);
            let mut root = ChildOwner {
                child: command(test, "body", &body_report).spawn().unwrap(),
                reaped: false,
                authority: true,
            };
            let until = Instant::now() + BODY_LIMIT;
            let status = loop {
                match root.child.try_wait() {
                    Ok(Some(status)) => {
                        root.reaped = true;
                        break Some(status);
                    }
                    Ok(None) if Instant::now() < until => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Ok(None) => break None,
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
                    Err(error) => {
                        root.authority = false;
                        panic!("private fixture root observation: {error}");
                    }
                }
            };
            // Root kill/wait precedes adopted-child draining, never substitutes
            // for it. A failed body cannot leave a grandchild outside this fence.
            drop(root);
            let drain = cleanup.finish();
            let fields = if body_report.exists() {
                read_fields(&body_report)
            } else {
                Default::default()
            };
            let body_ok =
                status.is_some_and(|s| s.success()) && fields.get("body_success") == Some(&1);
            let success = body_ok && drain.adopted == 0;
            write_report(report, format!(
                "body_success={} timed_out={} expected_waits={} body_adopted={} body_rescues={} supervisor_adopted={} supervisor_rescues={} no_children=1 {}",
                usize::from(body_ok), usize::from(status.is_none()), fields.get("expected_waits").copied().unwrap_or(0),
                fields.get("body_adopted").copied().unwrap_or(0), fields.get("body_rescues").copied().unwrap_or(0), drain.adopted, drain.rescues, Diagnostic::from_fields(&fields).report_fields()));
            std::process::exit(if success { 0 } else { 101 });
        }
        Some(_) => panic!("unknown private borrowed fixture stage"),
        None => {
            let dir = tempfile::tempdir().unwrap();
            let report = dir.path().join("result");
            let mut root = ChildOwner {
                child: command(test, "supervisor", &report).spawn().unwrap(),
                reaped: false,
                authority: true,
            };
            let status = root.wait().unwrap();
            let fields = read_fields(&report);
            Outcome {
                body_success: fields["body_success"] == 1,
                timed_out: fields["timed_out"] == 1,
                expected_waits: fields["expected_waits"],
                body_adopted: fields["body_adopted"],
                body_rescues: fields["body_rescues"],
                supervisor_adopted: fields["supervisor_adopted"],
                supervisor_rescues: fields["supervisor_rescues"],
                no_children: fields["no_children"] == 1,
                supervisor_success: status.success(),
                diagnostic: Diagnostic::from_fields(&fields),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assertion_failure_stays_failed_after_borrowed_child_cleanup() {
        const NAME: &str = "test_borrowed_scope::tests::assertion_failure_stays_failed_after_borrowed_child_cleanup";
        let result = run_exact(NAME, 0, || {
            let status = Command::new("/bin/sh")
                .args(["-c", "sleep 60 & exit 0"])
                .status()
                .unwrap();
            assert!(status.success());
            struct CleanupMarker;
            impl Drop for CleanupMarker {
                fn drop(&mut self) {
                    diagnostic_cleanup_stops(2);
                }
            }
            let _cleanup_marker = CleanupMarker;
            diagnostic_mode(DiagnosticMode::NegativeControl);
            diagnostic_phase(DiagnosticPhase::Assertions);
            diagnostic_assertion(DiagnosticAssertion::Deliberate, Duration::from_millis(7));
            panic!("deliberate original assertion failure");
        });
        assert!(!result.supervisor_success && !result.body_success && !result.timed_out);
        let report = format!("{result:?}");
        assert!(report.contains("negative-control"), "{report}");
        assert!(report.contains("assertions"), "{report}");
        assert!(report.contains("deliberate-assertion"), "{report}");
        assert!(
            !report.contains("deliberate original assertion failure"),
            "raw panic payload must not be propagated"
        );
        assert_eq!(result.diagnostic.elapsed_ms, 7);
        assert_eq!(result.diagnostic.cleanup_stops, 2);
        assert_eq!(result.body_adopted, 1);
        assert_eq!(result.body_rescues, 1);
        assert_eq!(result.supervisor_adopted, 0);
        assert!(result.no_children);
    }

    #[test]
    fn maximum_report_fields_remain_bounded() {
        diagnostic_observations(2);
        diagnostic_exit_code(Some(-1));
        let rendered = format!("{:?}", DIAGNOSTIC.get());
        assert!(rendered.contains("exit_code: Some(-1)"), "{rendered}");
        let fields = std::collections::BTreeMap::from([
            ("mode".into(), usize::MAX),
            ("phase".into(), usize::MAX),
            ("assertion".into(), usize::MAX),
            ("elapsed_ms".into(), usize::MAX),
            ("observations".into(), usize::MAX),
            ("cleanup_stops".into(), usize::MAX),
            ("exit_code".into(), usize::MAX),
        ]);
        let diagnostic = Diagnostic::from_fields(&fields);
        let report = format!("{} {}", "9".repeat(512), diagnostic.report_fields());
        assert!(report.len() <= REPORT_LIMIT);
        assert!(format!("{diagnostic:?}").contains("unknown"));
        let dir = tempfile::tempdir().unwrap();
        let report_path = dir.path().join("bounded-report");
        write_report(&report_path, report);
        assert!(std::fs::metadata(&report_path).unwrap().len() <= REPORT_LIMIT as u64);
        let oversized =
            std::panic::catch_unwind(|| write_report(&report_path, "x".repeat(REPORT_LIMIT + 1)));
        assert!(oversized.is_err());
        assert!(std::fs::metadata(&report_path).unwrap().len() <= REPORT_LIMIT as u64);
    }

    #[test]
    // Deliberate crash leaves this child to the supervisor's consuming wait.
    #[allow(clippy::zombie_processes)]
    fn body_crash_stays_failed_after_supervisor_adopted_wait() {
        const NAME: &str =
            "test_borrowed_scope::tests::body_crash_stays_failed_after_supervisor_adopted_wait";
        let result = run_exact(NAME, 0, || {
            let _child = Command::new("/bin/sleep").arg("60").spawn().unwrap();
            unsafe { libc::_exit(73) }
        });
        assert!(!result.supervisor_success && !result.body_success && !result.timed_out);
        assert_eq!(result.supervisor_adopted, 1);
        assert_eq!(result.supervisor_rescues, 1);
        assert!(result.no_children);
    }
}
