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
    ScreenSetup => "screen-setup", ScreenOpen => "screen-open",
    ScreenInitialIdentity => "screen-initial-identity", ScreenInitialRecovery => "screen-initial-recovery",
    ScreenInput => "screen-input", ScreenFrontendLoss => "screen-frontend-loss",
    ScreenDetachedBurst => "screen-detached-burst", ScreenReattach => "screen-reattach",
    ScreenGapRecovery => "screen-gap-recovery", ScreenQuery => "screen-query",
    ScreenResize => "screen-resize", ScreenPostResizeRecovery => "screen-post-resize-recovery",
    ScreenFinalChecks => "screen-final-checks", ScreenCleanup => "screen-cleanup",
});
diagnostic_codes!(DiagnosticAssertion {
    Unspecified => "unspecified", Opened => "opened", Barrier => "identity-barrier",
    Pin => "pin", Alive => "jobs-alive", MemberExec => "member-exec",
    Session => "session-membership", ProcessGroup => "sibling-process-group",
    Parent => "monitor-parent", Write => "pty-write", Ack => "pty-ack",
    Receive => "scope-response", Join => "helper-join", Receipt => "scope-receipt",
    MemberExit => "member-exit", EarlyPam => "no-early-pam-close", PamClosed => "pam-closed",
    Elapsed => "receipt-deadline", LeaderStatus => "leader-status", Deliberate => "deliberate-assertion",
    FixtureIntervention => "fixture-intervention", ResidualChildren => "residual-children",
    ScreenRuntime => "screen-runtime", ScreenSetup => "screen-setup", ScreenOpen => "screen-open",
    ScreenCatalogWait => "screen-catalog-wait", ScreenCatalog => "screen-catalog",
    ScreenRequirements => "screen-requirements", ScreenAllowance => "screen-allowance",
    ScreenRecoveryStart => "screen-recovery-start", ScreenRecoveryMode => "screen-recovery-mode",
    ScreenRecoveryGap => "screen-recovery-gap", ScreenRecoveryBegin => "screen-recovery-begin",
    ScreenRecoveryChunk => "screen-recovery-chunk", ScreenRecoveryEnd => "screen-recovery-end",
    ScreenRecoveryAccept => "screen-recovery-accept", ScreenRecoveryFinish => "screen-recovery-finish",
    ScreenClient => "screen-client", ScreenCanonicalCopy => "screen-canonical-copy",
    ScreenCanonicalConsume => "screen-canonical-consume", ScreenCanonicalEqual => "screen-canonical-equal",
    ScreenProgress => "screen-progress", ScreenIdentity => "screen-identity", ScreenInput => "screen-input",
    ScreenCommitted => "screen-committed", ScreenBarrier => "screen-barrier", ScreenGate => "screen-gate",
    ScreenDetachedBytes => "screen-detached-bytes", ScreenAttach => "screen-attach",
    ScreenQueryReply => "screen-query-reply", ScreenGeometry => "screen-geometry",
    ScreenCursor => "screen-cursor", ScreenHistory => "screen-history", ScreenInputStatus => "screen-input-status",
    ScreenReceipts => "screen-receipts", ScreenWorkerJoin => "screen-worker-join",
    ScreenControlJoin => "screen-control-join", ScreenScopeDrain => "screen-scope-drain",
    ScreenReservations => "screen-reservations", ScreenNoChildren => "screen-no-children",
    ScreenReceiptStatus => "screen-receipt-status",
});
diagnostic_codes!(DiagnosticSource {
    Unknown => "unknown", Screen => "screen_native_tests.rs",
    Engine => "engine_native_tests.rs", BorrowedScope => "test_borrowed_scope.rs",
});
diagnostic_codes!(DiagnosticRecordStatus {
    Unavailable => "unavailable", Available => "available", Invalid => "invalid",
});

#[derive(Clone, Copy, Default)]
struct DiagnosticLocation {
    source: usize,
    line: usize,
    column: usize,
}
impl DiagnosticLocation {
    fn from_source(file: &str, line: u32, column: u32) -> Self {
        let source = match file.rsplit(['/', '\\']).next() {
            Some("screen_native_tests.rs") => DiagnosticSource::Screen,
            Some("engine_native_tests.rs") => DiagnosticSource::Engine,
            Some("test_borrowed_scope.rs") => DiagnosticSource::BorrowedScope,
            _ => DiagnosticSource::Unknown,
        };
        Self {
            source: source as usize,
            line: line as usize,
            column: column as usize,
        }
    }
}
impl std::fmt::Debug for DiagnosticLocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Location")
            .field("source", &DiagnosticSource::label(self.source))
            .field("line", &self.line)
            .field("column", &self.column)
            .finish()
    }
}

#[derive(Clone, Copy, Default)]
struct Diagnostic {
    mode: usize,
    phase: usize,
    assertion: usize,
    elapsed_ms: usize,
    observations: usize,
    cleanup_stops: usize,
    exit_code: usize,
    screen_receipt_state: usize,
    screen_receipt_code: usize,
    failure: bool,
    body_status: usize,
    body: DiagnosticLocation,
    child_status: usize,
    child: DiagnosticLocation,
}
impl std::fmt::Debug for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Diagnostic")
            .field("mode", &DiagnosticMode::label(self.mode))
            .field("phase", &DiagnosticPhase::label(self.phase))
            .field("assertion", &DiagnosticAssertion::label(self.assertion))
            .field(
                "body_record",
                &DiagnosticRecordStatus::label(self.body_status),
            )
            .field("body_location", &self.body)
            .field(
                "child_record",
                &DiagnosticRecordStatus::label(self.child_status),
            )
            .field("child_location", &self.child)
            .field("elapsed_ms", &self.elapsed_ms)
            .field(
                "screen_receipt_state",
                &match self.screen_receipt_state {
                    0 => "unavailable",
                    1 => "none",
                    2 => "code",
                    _ => "invalid",
                },
            )
            .field(
                "screen_receipt_code",
                &(if self.screen_receipt_state == 2 {
                    u32::try_from(self.screen_receipt_code)
                        .ok()
                        .map(|code| code as i32)
                } else {
                    None
                }),
            )
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
            .field("monitor_fixture_wait", &(self.cleanup_stops & 8 != 0))
            .field("leader_fixture_wait", &(self.cleanup_stops & 16 != 0))
            .finish()
    }
}
impl Diagnostic {
    fn report_fields(self) -> String {
        format!("mode={} phase={} assertion={} elapsed_ms={} observations={} cleanup_stops={} exit_code={} failure={} body_status={} body_source={} body_line={} body_column={} child_status={} child_source={} child_line={} child_column={} screen_receipt_state={} screen_receipt_code={}",
            self.mode, self.phase, self.assertion, self.elapsed_ms, self.observations, self.cleanup_stops, self.exit_code,
            usize::from(self.failure), self.body_status, self.body.source, self.body.line, self.body.column,
            self.child_status, self.child.source, self.child.line, self.child.column,
            self.screen_receipt_state, self.screen_receipt_code)
    }
    fn from_fields(fields: &std::collections::BTreeMap<String, usize>) -> Self {
        let field = |name| fields.get(name).copied().unwrap_or(0);
        let (screen_receipt_state, screen_receipt_code) = match (
            fields.get("screen_receipt_state"),
            fields.get("screen_receipt_code"),
        ) {
            (None, None) => (0, 0),
            (Some(&state), Some(&0)) if matches!(state, 0 | 1 | 3) => (state, 0),
            (Some(&2), Some(&code)) if u32::try_from(code).is_ok() => (2, code),
            _ => (3, 0),
        };
        Self {
            mode: field("mode"),
            phase: field("phase"),
            assertion: field("assertion"),
            elapsed_ms: field("elapsed_ms"),
            observations: field("observations"),
            cleanup_stops: field("cleanup_stops"),
            exit_code: field("exit_code"),
            screen_receipt_state,
            screen_receipt_code,
            failure: field("failure") != 0,
            body_status: field("body_status"),
            body: DiagnosticLocation {
                source: field("body_source"),
                line: field("body_line"),
                column: field("body_column"),
            },
            child_status: field("child_status"),
            child: DiagnosticLocation {
                source: field("child_source"),
                line: field("child_line"),
                column: field("child_column"),
            },
        }
    }
    fn record_failure(&mut self, location: Option<DiagnosticLocation>) {
        if !self.failure {
            self.failure = true;
            self.body_status = usize::from(location.is_some());
            self.body = location.unwrap_or_default();
        }
    }
}
thread_local! {
    static DIAGNOSTIC: std::cell::Cell<Diagnostic> = const { std::cell::Cell::new(Diagnostic {
        mode: 0, phase: 0, assertion: 0, elapsed_ms: 0, observations: 0, cleanup_stops: 0, exit_code: 0,
        screen_receipt_state: 0, screen_receipt_code: 0,
        failure: false, body_status: 0, body: DiagnosticLocation { source: 0, line: 0, column: 0 },
        child_status: 0, child: DiagnosticLocation { source: 0, line: 0, column: 0 },
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
        if cell.get().failure {
            return;
        }
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
        if cell.get().failure {
            return;
        }
        cell.set(Diagnostic {
            assertion: assertion as usize,
            elapsed_ms: elapsed.as_millis().min(usize::MAX as u128) as usize,
            ..cell.get()
        })
    });
}

/// Installed only in a dedicated private body, never shared outer libtest.
/// Other-thread panics are not attributed to this body's observation site.
pub(crate) fn diagnostic_capture_locations() {
    assert_eq!(std::env::var(MODE).as_deref(), Ok("body"));
    let body_thread = std::thread::current().id();
    std::panic::set_hook(Box::new(move |info| {
        if std::thread::current().id() == body_thread {
            DIAGNOSTIC.with(|cell| {
                let mut diagnostic = cell.get();
                diagnostic.record_failure(info.location().map(|location| {
                    DiagnosticLocation::from_source(
                        location.file(),
                        location.line(),
                        location.column(),
                    )
                }));
                cell.set(diagnostic);
            });
        }
    }));
}

fn child_panic_path(report: &std::path::Path) -> std::path::PathBuf {
    report.with_extension("screen-panic")
}
pub(crate) fn diagnostic_child_panic_path() -> std::path::PathBuf {
    child_panic_path(&std::path::PathBuf::from(std::env::var_os(REPORT).unwrap()))
}
const CHILD_RECORD_LIMIT: usize = 128;
/// First child location wins. No panic payload or arbitrary path is retained.
pub(crate) fn diagnostic_write_child_panic(
    path: &std::path::Path,
    file: &str,
    line: u32,
    column: u32,
) {
    use std::io::Write;
    let location = DiagnosticLocation::from_source(file, line, column);
    let record = format!(
        "version=1 source={} line={} column={}\n",
        location.source, location.line, location.column
    );
    if record.len() <= CHILD_RECORD_LIMIT {
        if let Ok(mut output) = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
        {
            let _ = output.write_all(record.as_bytes());
        }
    }
}
fn parse_child_location(bytes: &[u8]) -> Option<DiagnosticLocation> {
    if bytes.len() > CHILD_RECORD_LIMIT {
        return None;
    }
    let mut parts = std::str::from_utf8(bytes).ok()?.split_ascii_whitespace();
    let mut values = [0usize; 4];
    for (key, value) in ["version", "source", "line", "column"]
        .into_iter()
        .zip(&mut values)
    {
        let (name, number) = parts.next()?.split_once('=')?;
        if name != key || number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *value = number.parse().ok()?;
    }
    let [version, source, line, column] = values;
    if parts.next().is_some()
        || version != 1
        || source > DiagnosticSource::BorrowedScope as usize
        || line == 0
        || column == 0
        || line > u32::MAX as usize
        || column > u32::MAX as usize
    {
        return None;
    }
    Some(DiagnosticLocation {
        source,
        line,
        column,
    })
}
fn read_child_location(path: &std::path::Path) -> (usize, DiagnosticLocation) {
    use std::io::Read;
    let file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (0, DiagnosticLocation::default())
        }
        Err(_) => return (2, DiagnosticLocation::default()),
    };
    let mut bytes = Vec::new();
    if file
        .take((CHILD_RECORD_LIMIT + 1) as u64)
        .read_to_end(&mut bytes)
        .is_err()
    {
        return (2, DiagnosticLocation::default());
    }
    match parse_child_location(&bytes) {
        Some(location) => (1, location),
        None => (2, DiagnosticLocation::default()),
    }
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
// A completed Screen cleanup receipt is separate from the helper exit-response bits.
pub(crate) fn diagnostic_screen_receipt(code: Option<i32>) {
    DIAGNOSTIC.with(|cell| {
        let mut diagnostic = cell.get();
        if diagnostic.failure {
            return;
        }
        (
            diagnostic.screen_receipt_state,
            diagnostic.screen_receipt_code,
        ) = match code {
            None => (1, 0),
            Some(code) => (2, code as u32 as usize),
        };
        cell.set(diagnostic);
    });
}
// Cleanup updates cannot overwrite the phase/assertion that caused unwinding.
// Bits identify fixture roles only: leader=1, member=2, monitor=4 are stops;
// monitor=8 and leader=16 are consuming waits the fixture itself performed.
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
fn format_body_report(
    body_success: bool,
    expected_waits: usize,
    body_counts: (usize, usize),
    diagnostic: Diagnostic,
) -> String {
    format!(
        "body_success={} expected_waits={expected_waits} body_adopted={} body_rescues={} no_children=1 {}",
        usize::from(body_success), body_counts.0, body_counts.1, diagnostic.report_fields()
    )
}
fn format_supervisor_report(
    body_success: bool,
    timed_out: bool,
    expected_waits: usize,
    body_counts: (usize, usize),
    supervisor_counts: (usize, usize),
    diagnostic: Diagnostic,
) -> String {
    format!(
        "body_success={} timed_out={} expected_waits={expected_waits} body_adopted={} body_rescues={} supervisor_adopted={} supervisor_rescues={} no_children=1 {}",
        usize::from(body_success), usize::from(timed_out), body_counts.0, body_counts.1,
        supervisor_counts.0, supervisor_counts.1, diagnostic.report_fields()
    )
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
/// Non-consuming proof that this private body owns no child at all: every
/// task's children list is empty and the kernel has no waitable child, exited
/// or not. Nothing is waited or signaled, so a failed proof leaves every child
/// to the final owned drain.
pub(crate) fn owned_children_absent() -> bool {
    assert_eq!(std::env::var(MODE).as_deref(), Ok("body"));
    if !owned_child_census().is_empty() {
        return false;
    }
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result = unsafe {
            libc::waitid(
                libc::P_ALL,
                0,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        };
        // Success, with or without an exited child, means a child exists.
        if result == 0 {
            return false;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => {}
            Some(libc::ECHILD) => return true,
            other => panic!("owned fixture child probe: {other:?}"),
        }
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
// As in the qualified adoption fixtures: include the libtest body's task,
// not just /proc/self/task/<main>/children. Every child belongs to this case.
fn owned_child_census() -> std::collections::BTreeSet<u32> {
    let mut children = std::collections::BTreeSet::new();
    for task in std::fs::read_dir("/proc/self/task").unwrap() {
        let path = task.unwrap().path().join("children");
        match std::fs::read_to_string(path) {
            Ok(text) => children.extend(text.split_whitespace().map(|p| p.parse::<u32>().unwrap())),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("owned fixture child census: {error}"),
        }
    }
    children
}
fn drain_owned_children() -> Drain {
    use std::os::fd::AsFd;
    let mut drain = Drain::default();
    loop {
        let children = owned_child_census();
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
            let mut diagnostic = DIAGNOSTIC.get();
            if result.is_err() {
                diagnostic.record_failure(None);
                DIAGNOSTIC.set(diagnostic);
            }
            let drain = drain_owned_children();
            diagnostic.cleanup_stops |= DIAGNOSTIC.get().cleanup_stops;
            let waits = EXPECTED_WAITS.load(Ordering::SeqCst);
            let success = result.is_ok() && waits == expected_waits && drain.adopted == 0;
            write_report(
                std::env::var_os(REPORT).unwrap(),
                format_body_report(success, waits, (drain.adopted, drain.rescues), diagnostic),
            );
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
            let mut diagnostic = Diagnostic::from_fields(&fields);
            (diagnostic.child_status, diagnostic.child) =
                read_child_location(&child_panic_path(&report));
            write_report(
                report,
                format_supervisor_report(
                    body_ok,
                    status.is_none(),
                    fields.get("expected_waits").copied().unwrap_or(0),
                    (
                        fields.get("body_adopted").copied().unwrap_or(0),
                        fields.get("body_rescues").copied().unwrap_or(0),
                    ),
                    (drain.adopted, drain.rescues),
                    diagnostic,
                ),
            );
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

    fn receipt_fields(diagnostic: Diagnostic) -> std::collections::BTreeMap<String, usize> {
        parse_receipt_report(&diagnostic.report_fields())
    }
    fn parse_receipt_report(report: &str) -> std::collections::BTreeMap<String, usize> {
        report
            .split_whitespace()
            .map(|field| {
                let (key, value) = field.split_once('=').unwrap();
                (key.to_string(), value.parse().unwrap())
            })
            .collect()
    }
    fn receipt_input(
        state: Option<usize>,
        code: Option<usize>,
    ) -> std::collections::BTreeMap<String, usize> {
        let mut fields = std::collections::BTreeMap::new();
        if let Some(state) = state {
            fields.insert("screen_receipt_state".into(), state);
        }
        if let Some(code) = code {
            fields.insert("screen_receipt_code".into(), code);
        }
        fields
    }

    #[test]
    fn screen_receipt_diagnostic_preserves_option_through_reports() {
        diagnostic_mode(DiagnosticMode::Unspecified);
        for (input, state, wire_code, label, observed) in [
            (Some((2, 7)), 2, 7, "code", Some(7)),
            (None, 0, 0, "unavailable", None),
            (Some((1, 0)), 1, 0, "none", None),
            (Some((2, 0)), 2, 0, "code", Some(0)),
            (
                Some((2, (-1i32) as u32 as usize)),
                2,
                (-1i32) as u32 as usize,
                "code",
                Some(-1),
            ),
            (
                Some((2, i32::MIN as u32 as usize)),
                2,
                i32::MIN as u32 as usize,
                "code",
                Some(i32::MIN),
            ),
            (
                Some((2, i32::MAX as u32 as usize)),
                2,
                i32::MAX as u32 as usize,
                "code",
                Some(i32::MAX),
            ),
        ] {
            diagnostic_mode(DiagnosticMode::Unspecified);
            if input.is_some() {
                diagnostic_screen_receipt(observed);
            }
            let set = DIAGNOSTIC.get();
            assert_eq!(
                (set.screen_receipt_state, set.screen_receipt_code),
                (state, wire_code)
            );
            let fields =
                input.map_or_else(Default::default, |(s, c)| receipt_input(Some(s), Some(c)));
            let mut diagnostic = Diagnostic::from_fields(&fields);
            for hop in 0..2 {
                assert_eq!(
                    (
                        diagnostic.screen_receipt_state,
                        diagnostic.screen_receipt_code
                    ),
                    (state, wire_code)
                );
                let rendered = format!("{diagnostic:?}");
                assert!(
                    rendered.contains(&format!("screen_receipt_state: {label:?}")),
                    "{rendered}"
                );
                assert!(
                    rendered.contains(&format!("screen_receipt_code: {observed:?}")),
                    "{rendered}"
                );
                let report = if hop == 0 {
                    format_body_report(false, 0, (0, 0), diagnostic)
                } else {
                    format_supervisor_report(false, false, 0, (0, 0), (0, 0), diagnostic)
                };
                let forwarded = parse_receipt_report(&report);
                assert_eq!(forwarded.get("screen_receipt_state"), Some(&state));
                assert_eq!(forwarded.get("screen_receipt_code"), Some(&wire_code));
                diagnostic = Diagnostic::from_fields(&forwarded);
            }
        }
    }

    #[test]
    fn screen_receipt_diagnostic_rejects_partial_or_invalid_fields() {
        diagnostic_mode(DiagnosticMode::Unspecified);
        let missing = Diagnostic::from_fields(&Default::default());
        assert_eq!(
            (missing.screen_receipt_state, missing.screen_receipt_code),
            (0, 0)
        );
        let mut invalid = vec![
            receipt_input(Some(0), None),
            receipt_input(Some(1), None),
            receipt_input(Some(2), None),
            receipt_input(Some(3), None),
            receipt_input(None, Some(0)),
            receipt_input(Some(4), Some(0)),
            receipt_input(Some(usize::MAX), Some(0)),
            receipt_input(Some(0), Some(1)),
            receipt_input(Some(1), Some(1)),
            receipt_input(Some(3), Some(1)),
            receipt_input(Some(3), Some(0)),
        ];
        if let Ok(overflow) = usize::try_from(u64::from(u32::MAX) + 1) {
            invalid.push(receipt_input(Some(2), Some(overflow)));
        }
        for mut fields in invalid {
            fields.insert("failure".into(), 1);
            let mut diagnostic = Diagnostic::from_fields(&fields);
            for _ in 0..2 {
                assert_eq!(
                    (
                        diagnostic.screen_receipt_state,
                        diagnostic.screen_receipt_code
                    ),
                    (3, 0)
                );
                let forwarded = receipt_fields(diagnostic);
                assert_eq!(forwarded.get("screen_receipt_state"), Some(&3));
                assert_eq!(forwarded.get("screen_receipt_code"), Some(&0));
                assert!(diagnostic.failure);
                let rendered = format!("{diagnostic:?}");
                assert!(
                    rendered.contains("screen_receipt_state: \"invalid\""),
                    "{rendered}"
                );
                assert!(rendered.contains("screen_receipt_code: None"), "{rendered}");
                diagnostic = Diagnostic::from_fields(&forwarded);
            }
        }
    }

    #[test]
    fn screen_receipt_diagnostic_freezes_with_first_failure() {
        diagnostic_mode(DiagnosticMode::Unspecified);
        let mut fields = receipt_input(Some(2), Some((-1i32) as u32 as usize));
        fields.insert("observations".into(), 127);
        fields.insert("exit_code".into(), 42);
        DIAGNOSTIC.set(Diagnostic::from_fields(&fields));
        diagnostic_phase(DiagnosticPhase::ScreenCleanup);
        diagnostic_assertion(
            DiagnosticAssertion::ScreenReceiptStatus,
            Duration::from_millis(7),
        );
        let before = DIAGNOSTIC.get();
        let legacy = (before.observations, before.exit_code, before.elapsed_ms);
        for code in [None, Some(0), Some(-1)] {
            diagnostic_screen_receipt(code);
            let after = DIAGNOSTIC.get();
            assert_eq!(
                (after.observations, after.exit_code, after.elapsed_ms),
                legacy
            );
        }
        let mut diagnostic = DIAGNOSTIC.get();
        diagnostic.record_failure(Some(DiagnosticLocation::from_source(
            "screen_native_tests.rs",
            689,
            9,
        )));
        DIAGNOSTIC.set(diagnostic);
        diagnostic_screen_receipt(Some(7));
        diagnostic_screen_receipt(None);
        diagnostic_phase(DiagnosticPhase::ScreenResize);
        diagnostic_assertion(
            DiagnosticAssertion::ScreenGeometry,
            Duration::from_millis(90),
        );
        let retained = DIAGNOSTIC.get();
        assert_eq!(
            receipt_fields(retained).get("screen_receipt_state"),
            Some(&2)
        );
        assert_eq!(
            receipt_fields(retained).get("screen_receipt_code"),
            Some(&((-1i32) as u32 as usize))
        );
        assert_eq!(retained.phase, DiagnosticPhase::ScreenCleanup as usize);
        assert_eq!(
            retained.assertion,
            DiagnosticAssertion::ScreenReceiptStatus as usize
        );
        assert_eq!((retained.body.line, retained.body.column), (689, 9));
        assert_eq!(
            (
                retained.observations,
                retained.exit_code,
                retained.elapsed_ms
            ),
            (127, 42, 7)
        );
    }

    #[test]
    fn screen_diagnostic_checkpoint_preserves_phase_and_failure_location() {
        diagnostic_mode(DiagnosticMode::Unspecified);
        diagnostic_phase(DiagnosticPhase::ScreenGapRecovery);
        diagnostic_assertion(
            DiagnosticAssertion::ScreenRecoveryGap,
            Duration::from_millis(4),
        );
        assert!(format!("{:?}", DIAGNOSTIC.get()).contains("screen-gap-recovery"));
        diagnostic_phase(DiagnosticPhase::ScreenResize);
        assert_eq!(DIAGNOSTIC.get().assertion, 0);
        assert_eq!(DIAGNOSTIC.get().elapsed_ms, 0);
        diagnostic_assertion(
            DiagnosticAssertion::ScreenGeometry,
            Duration::from_millis(7),
        );
        let mut failure = DIAGNOSTIC.get();
        failure.record_failure(Some(DiagnosticLocation::from_source(
            "screen_native_tests.rs",
            71,
            9,
        )));
        DIAGNOSTIC.set(failure);
        diagnostic_phase(DiagnosticPhase::ScreenCleanup);
        diagnostic_assertion(
            DiagnosticAssertion::ScreenReservations,
            Duration::from_millis(90),
        );
        diagnostic_cleanup_stops(4);
        let retained = DIAGNOSTIC.get();
        assert_eq!(retained.phase, DiagnosticPhase::ScreenResize as usize);
        assert_eq!(
            retained.assertion,
            DiagnosticAssertion::ScreenGeometry as usize
        );
        assert_eq!(retained.elapsed_ms, 7);
        assert_eq!((retained.body.line, retained.body.column), (71, 9));
        assert_eq!(retained.cleanup_stops, 4);
        let fields = retained
            .report_fields()
            .split_whitespace()
            .map(|field| {
                let (key, value) = field.split_once('=').unwrap();
                (key.to_string(), value.parse().unwrap())
            })
            .collect();
        let forwarded = Diagnostic::from_fields(&fields);
        assert_eq!(forwarded.body.line, 71);
        assert!(format!("{forwarded:?}").contains("screen-resize"));
    }

    #[test]
    fn diagnostic_location_is_closed_and_payload_free() {
        for (file, label) in [
            (
                "qshd/src/session_owner/screen_native_tests.rs",
                "screen_native_tests.rs",
            ),
            (
                "qshd/src/session_owner/engine_native_tests.rs",
                "engine_native_tests.rs",
            ),
            ("qshd/src/test_borrowed_scope.rs", "test_borrowed_scope.rs"),
            ("/private/CANARY-IDENTITY/PAYLOAD.rs", "unknown"),
        ] {
            let location = DiagnosticLocation::from_source(file, 41, 7);
            let mut diagnostic = Diagnostic::default();
            diagnostic.record_failure(Some(location));
            let rendered = format!("{diagnostic:?}");
            assert!(rendered.contains(label), "{rendered}");
            assert!(rendered.contains("line: 41") && rendered.contains("column: 7"));
            assert!(!rendered.contains("private") && !rendered.contains("CANARY"));
            assert!(!rendered.contains("PAYLOAD"));
            assert_eq!(diagnostic.child_status, 0);
        }
        let mut absent = Diagnostic::default();
        absent.record_failure(None);
        assert!(absent.failure);
        assert_eq!(absent.body_status, 0);
        assert_eq!(absent.body.line, 0);
        assert!(format!("{absent:?}").contains("unavailable"));
    }

    #[test]
    fn diagnostic_location_first_failure_is_sticky() {
        let mut diagnostic = Diagnostic::default();
        diagnostic.record_failure(Some(DiagnosticLocation::from_source(
            "screen_native_tests.rs",
            12,
            3,
        )));
        diagnostic.record_failure(Some(DiagnosticLocation::from_source(
            "engine_native_tests.rs",
            99,
            8,
        )));
        assert_eq!(diagnostic.body.line, 12);
        assert_eq!(diagnostic.body.column, 3);
        assert_eq!(diagnostic.body.source, 1);
        let mut absent = Diagnostic::default();
        absent.record_failure(None);
        absent.record_failure(Some(DiagnosticLocation::from_source(
            "screen_native_tests.rs",
            99,
            8,
        )));
        assert_eq!(
            absent.body_status, 0,
            "a later panic cannot invent the first location"
        );
    }

    #[test]
    fn diagnostic_child_record_is_bounded_and_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("result");
        let path = child_panic_path(&report);
        assert_eq!(path, child_panic_path(&report.with_extension("body")));
        assert_eq!(read_child_location(&path).0, 0);
        diagnostic_write_child_panic(&path, "screen_native_tests.rs", 19, 4);
        diagnostic_write_child_panic(&path, "engine_native_tests.rs", 90, 7);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "version=1 source=1 line=19 column=4\n"
        );
        let (status, location) = read_child_location(&path);
        assert_eq!(status, 1);
        assert_eq!(
            (location.source, location.line, location.column),
            (1, 19, 4)
        );
        let mut diagnostic = Diagnostic::default();
        diagnostic.record_failure(Some(DiagnosticLocation::from_source(
            "test_borrowed_scope.rs",
            7,
            2,
        )));
        diagnostic.child_status = status;
        diagnostic.child = location;
        assert_eq!(diagnostic.body.line, 7);
        assert_eq!(diagnostic.child.line, 19);
        let mut boundary = b"version=1 source=3 line=4294967295 column=4294967295".to_vec();
        boundary.resize(128, b' ');
        std::fs::write(&path, &boundary).unwrap();
        assert_eq!(read_child_location(&path).0, 1);
        boundary.push(b' ');
        std::fs::write(&path, &boundary).unwrap();
        assert_eq!(read_child_location(&path).0, 2);
        for bytes in [
            b"version=1 source=0 line=20 column=2\n".as_slice(),
            b"version=1 source=1 line=0 column=2\n",
            b"version=1 source=1 line=1 column=0\n",
            b"version=2 source=1 line=1 column=2\n",
            b"version=1 source=99 line=1 column=2\n",
            b"version=1 source=1 line=1 column=2 payload=CANARY\n",
            b"version=1 source=1 line=1 line=2\n",
            b"CANARY-IDENTITY private/path PAYLOAD",
            &[b'x'; 129],
        ] {
            std::fs::write(&path, bytes).unwrap();
            let (status, location) = read_child_location(&path);
            assert_eq!(
                status,
                if bytes.starts_with(b"version=1 source=0 ") {
                    1
                } else {
                    2
                }
            );
            let text = format!("{location:?}");
            assert!(
                !text.contains("CANARY") && !text.contains("PAYLOAD") && !text.contains("private")
            );
        }
        assert!(format!("{:?}", read_child_location(&path).1).contains("unknown"));
    }

    #[test]
    fn assertion_failure_stays_failed_after_borrowed_child_cleanup() {
        const NAME: &str = "test_borrowed_scope::tests::assertion_failure_stays_failed_after_borrowed_child_cleanup";
        let result = run_exact(NAME, 0, || {
            diagnostic_capture_locations();
            assert_eq!(
                diagnostic_child_panic_path().file_name(),
                Some(std::ffi::OsStr::new("result.screen-panic")),
                "body report must retain the sidecar in the outer report directory"
            );
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
        assert_eq!(result.diagnostic.body_status, 1);
        assert_eq!(
            result.diagnostic.body.source,
            DiagnosticSource::BorrowedScope as usize
        );
        assert!(result.diagnostic.body.line > 0 && result.diagnostic.body.column > 0);
        assert_eq!(result.body_adopted, 1);
        assert_eq!(result.body_rescues, 1);
        assert_eq!(result.supervisor_adopted, 0);
        assert!(result.no_children);
    }

    #[test]
    fn maximum_report_fields_remain_bounded() {
        diagnostic_mode(DiagnosticMode::Unspecified);
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
            ("failure".into(), usize::MAX),
            ("body_status".into(), usize::MAX),
            ("body_source".into(), usize::MAX),
            ("body_line".into(), usize::MAX),
            ("body_column".into(), usize::MAX),
            ("child_status".into(), usize::MAX),
            ("child_source".into(), usize::MAX),
            ("child_line".into(), usize::MAX),
            ("child_column".into(), usize::MAX),
            ("screen_receipt_state".into(), 2),
            ("screen_receipt_code".into(), u32::MAX as usize),
        ]);
        let diagnostic = Diagnostic::from_fields(&fields);
        assert!(format!("{diagnostic:?}").contains("unknown"));
        assert_eq!(
            receipt_fields(diagnostic).keys().collect::<Vec<_>>(),
            fields.keys().collect::<Vec<_>>()
        );
        let dir = tempfile::tempdir().unwrap();
        let report_path = dir.path().join("bounded-report");
        // Use the actual formatters so added fields cannot evade the bound.
        // Counts are maximal; serialized booleans have the real maximum, 1.
        for (report, envelope_keys) in [
            (
                format_body_report(true, usize::MAX, (usize::MAX, usize::MAX), diagnostic),
                &[
                    "body_success",
                    "expected_waits",
                    "body_adopted",
                    "body_rescues",
                    "no_children",
                ][..],
            ),
            (
                format_supervisor_report(
                    true,
                    true,
                    usize::MAX,
                    (usize::MAX, usize::MAX),
                    (usize::MAX, usize::MAX),
                    diagnostic,
                ),
                &[
                    "body_success",
                    "timed_out",
                    "expected_waits",
                    "body_adopted",
                    "body_rescues",
                    "supervisor_adopted",
                    "supervisor_rescues",
                    "no_children",
                ][..],
            ),
        ] {
            assert!(report.len() <= REPORT_LIMIT);
            write_report(&report_path, report.clone());
            assert!(std::fs::metadata(&report_path).unwrap().len() <= REPORT_LIMIT as u64);
            let parsed = read_fields(&report_path);
            let mut expected_keys: std::collections::BTreeSet<_> = fields.keys().cloned().collect();
            expected_keys.extend(envelope_keys.iter().map(|key| key.to_string()));
            assert_eq!(
                parsed
                    .keys()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>(),
                expected_keys
            );
            assert_eq!(report.split_whitespace().count(), parsed.len());
        }
        let oversized =
            std::panic::catch_unwind(|| write_report(&report_path, "x".repeat(REPORT_LIMIT + 1)));
        assert!(oversized.is_err());
        assert!(std::fs::metadata(&report_path).unwrap().len() <= REPORT_LIMIT as u64);
    }

    #[test]
    // The std handle is dropped unwaited: the exact pidfd wait below consumes it.
    #[allow(clippy::zombie_processes)]
    fn owned_child_probe_is_complete_and_non_consuming() {
        use std::os::fd::AsFd;
        const NAME: &str =
            "test_borrowed_scope::tests::owned_child_probe_is_complete_and_non_consuming";
        run_exact(NAME, 0, || {
            assert!(owned_children_absent());
            // Spawned from the libtest body thread, not the main task.
            let running = Command::new("/bin/sleep").arg("60").spawn().unwrap();
            let running = pin(running.id());
            assert!(!owned_children_absent(), "a running child is owned");
            signal_kill(running.as_fd());
            while !exited(running.as_fd()) {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(
                !owned_children_absent(),
                "an exited, unwaited child is owned"
            );
            assert!(!owned_children_absent(), "the probe did not consume it");
            // Still waitable: the probe neither waited nor released it.
            wait_exact(running.as_fd());
            assert!(owned_children_absent());
        })
        .assert_clean(0);
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
        assert_eq!(result.diagnostic.body_status, 0);
        assert_eq!(result.diagnostic.body.line, 0);
    }
}
