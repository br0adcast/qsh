//! The per-login monitor: the process that stands between the helper and a
//! login's shells.
//!
//! One monitor per LOGIN, never per channel. `pam_open_session` and
//! `pam_close_session` must be called by one and the same process, once per
//! login (spec §3.3), so the process that makes those calls has to outlive
//! its first shell and serve every later channel of the same login. Its
//! life is the life of the login's ENTRY in the helper
//! (`server::LoopState::logins`), not of that login's channel set: a set
//! that empties every time somebody types `exit` says nothing about whether
//! the login is over.
//!
//! What it does: forks a shell per `MonitorRequest::Open`, reports each
//! one's startup and exit back to the helper, and ends a shell on
//! `MonitorRequest::Close` -- `SIGHUP` first, `SIGKILL` once
//! [`server::CLOSE_GRACE_PERIOD`] has passed with no exit. All three moved
//! here with the fork itself: a helper that no longer forks a login's
//! shells cannot signal them either (they are this process's children, not
//! its own), so keeping any part of the closing there would leave a channel
//! nobody could end.
//!
//! # The login's PAM session
//!
//! And it holds the login's PAM transaction, opened at the FIRST channel
//! and closed when the login ends, in the order spec §6.4 fixes (see
//! [`Session`]). One transaction per monitor, and one monitor per login, so
//! "one session per login" needs no bookkeeping of its own: a second
//! session would take a second monitor, which `server::LoopState::monitors`
//! makes unbuildable. Every later channel of the same login forks its shell
//! inside the session the first one opened.
//!
//! # What it holds open
//!
//! The monitor never execs, so close-on-exec closes nothing for it: what it
//! inherited from the helper is its own to close, and
//! [`server::close_other_descriptors`] is the first thing it does. Closing
//! "the helper's two seams" would not be enough -- the helper also holds one
//! socket per live monitor, and the master side of every channel that is
//! still starting. A monitor of Alice's that kept a socket of Bob's monitor
//! would keep Bob's monitor from ever seeing end-of-file when the helper
//! closes its end, and from the next task on that is a PAM session nobody
//! is left to close.
//!
//! After the sweep it holds exactly two kinds of descriptor: its own end of
//! its own seam to the helper (the one `keep`), and whatever the helper
//! hands it afterwards over that seam -- the slave side of a channel's
//! terminal, which it holds only from the `Open` that carries it until the
//! shell it forks for that channel has it on 0, 1 and 2. Descriptors 0, 1
//! and 2 are the helper's own, left alone by the sweep as they are for a
//! channel's child.
//!
//! # Why it writes nothing to the log
//!
//! `crate::log` holds its file open on a descriptor this process has just
//! closed, and a pipe opened here can be given that very number. A log line
//! would then be written into some channel's startup-report pipe. The
//! monitor therefore says everything it has to say on its seam, as a
//! [`MonitorEvent`], the same way the verifying child says everything in
//! its verdict (`server::fork_verification`).
//!
//! That is not left to this module's own discipline any more. Linux-PAM's
//! conversation function logs what a module says (`pam::converse`), and the
//! modules are the administrator's, not ours -- so [`run_monitor`] calls
//! `crate::log::mute` right after the sweep, and every logging path in this
//! process, present or future, becomes a no-op. What a PAM stack said
//! reaches the log the same way everything else here does: over the seam,
//! as [`MonitorEvent::Refused`] or [`MonitorEvent::Noted`], for the helper
//! to write down.
//!
//! That call site is pinned, and deterministically:
//! `server::close_other_descriptors` starts at descriptor 3, so a log file
//! sitting on descriptor 0 survives the sweep -- and an unmuted monitor
//! whose PAM stack has a module that talks then appends that module's words
//! to the real log file. No descriptor-number reuse is involved. See
//! `server::tests::a_monitor_writes_nothing_to_the_log_when_a_module_speaks`.
//! (An earlier round of this task recorded that the call could not be
//! witnessed; it was wrong, and the reasoning is left here so the next
//! reader does not repeat it.)

use std::collections::{HashMap, VecDeque};
use std::ffi::CString;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::raw::c_char;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::sys::signal::Signal;
use nix::unistd::{Gid, Pid, Uid};
use transport::LoginId;

use super::account::Account;
use super::channel;
use super::pam::{Cred, Pam, PamError, PamStartFailure};
use super::pam_completion::{PamCompletion, PamStep};
use super::protocol::{
    decode, encode, merge_cleanup_failure, ChannelId, CleanupFailure, CleanupKind, MonitorEvent,
    MonitorRequest,
};
#[cfg(target_os = "linux")]
use super::selinux_tty::{self, Adapter, Guard, Native, Prepared, Snapshot};
use super::server::{
    become_account_checks, child_env, close_other_descriptors, login_shell, shell_basename,
    REAP_INTERVAL, STARTUP_REPORT_TIMEOUT,
};

#[cfg(not(target_os = "linux"))]
use super::server::CLOSE_GRACE_PERIOD;
#[cfg(any(test, not(target_os = "linux")))]
use super::server::{read_startup_report, StartupReport};

/// Supplementary-group operations confined to each login's monitor.
/// Production always uses REAL; function pointers let tests exercise syscall failures.
#[derive(Clone, Copy)]
pub(super) struct SessionGroupOps {
    pub(super) install: fn(&[Gid]) -> nix::Result<()>,
    pub(super) capture: fn() -> nix::Result<Vec<Gid>>,
}

impl SessionGroupOps {
    pub(super) const REAL: Self = Self {
        install: nix::unistd::setgroups,
        capture: capture_supplementary_groups,
    };
}

fn allocate_groups(count: usize) -> nix::Result<Vec<Gid>> {
    let mut groups = Vec::new();
    groups
        .try_reserve_exact(count)
        .map_err(|_| nix::errno::Errno::ENOMEM)?;
    groups.resize(count, Gid::from_raw(0));
    Ok(groups)
}

/// Take one bounded kernel snapshot. A changed count is an error, never a retry
/// or an empty-list fallback. No NSS reconstruction is valid after PAM.
fn capture_supplementary_groups() -> nix::Result<Vec<Gid>> {
    // SAFETY: sysconf takes a constant and returns a value, touching no pointers.
    let limit = unsafe { nix::libc::sysconf(nix::libc::_SC_NGROUPS_MAX) };
    capture_groups_with(
        limit,
        |buffer| {
            // SAFETY: buffer has the validated, representable length passed to getgroups.
            // A zero length is its count query and writes nothing.
            let count = unsafe {
                nix::libc::getgroups(
                    buffer.len() as nix::libc::c_int,
                    buffer.as_mut_ptr().cast::<nix::libc::gid_t>(),
                )
            };
            if count < 0 {
                Err(nix::errno::Errno::last())
            } else {
                Ok(count as i64)
            }
        },
        allocate_groups,
    )
}

fn capture_groups_with(
    limit: nix::libc::c_long,
    mut read: impl FnMut(&mut [Gid]) -> nix::Result<i64>,
    allocate: fn(usize) -> nix::Result<Vec<Gid>>,
) -> nix::Result<Vec<Gid>> {
    use nix::errno::Errno::EINVAL;
    if limit <= 0 || limit > nix::libc::c_int::MAX as nix::libc::c_long {
        return Err(EINVAL);
    }
    let count = usize::try_from(read(&mut [])?).map_err(|_| EINVAL)?;
    if count > limit as usize {
        return Err(EINVAL);
    }
    let mut groups = allocate(count)?;
    if groups.len() != count || read(&mut groups)? != count as i64 {
        return Err(EINVAL);
    }
    Ok(groups)
}

/// The errno a channel is refused with when its shell could not even be
/// prepared -- a command or a home path with a NUL in it, a pipe the kernel
/// would not open. Nothing about those is an errno of its own, and the
/// helper's answer to the worker names the errno it is given, so the one
/// thing that must not happen is inventing a plausible-looking failure of
/// the launch itself.
const PREPARATION_REFUSED: nix::Error = nix::Error::EINVAL;

/// Everything a monitor needs to know about the login it serves, decided by
/// the helper before the fork and carried into the monitor by the fork
/// itself -- never over the seam, which carries only what changes from
/// channel to channel.
pub(super) struct MonitorPlan {
    #[cfg(target_os = "linux")]
    pub(super) child_mask: Option<super::stop_signal::ChildMask>,
    /// The account every shell of this login runs as, exactly as the
    /// verification that admitted the login resolved it.
    pub(super) account: Account,
    /// Which login this monitor belongs to. Nothing here reads it: the
    /// helper keys the monitor by it, and this process's PAM session is its
    /// whole life rather than something it looks a login up by. Carried all
    /// the same, because a monitor that cannot say whose it is could not be
    /// told apart in a core file or a `/proc` listing.
    #[allow(dead_code)]
    pub(super) login: LoginId,
    /// The name of the first channel's terminal (`/dev/pts/7`), for the
    /// session's `PAM_TTY`. Taken by the helper, which is where the
    /// terminal is opened; a later channel of the same login gets a
    /// terminal of its own that the session never hears about (spec §9
    /// `tty-first-channel`).
    pub(super) tty: String,
    /// Full source endpoint, converted to its numeric IP for `PAM_RHOST`. Chosen by
    /// the WORKER, so it is worth nothing as a fact: see
    /// `protocol::Request::Verify`'s own field, and spec §9
    /// `rhost-from-worker`.
    pub(super) rhost: String,
    /// The PAM service the session is opened for -- `qshd` in the daemon,
    /// so the stack is `/etc/pam.d/qshd` (`config::HelperConfig::pam_service`).
    pub(super) pam_service: String,
    /// Where that stack is read from, for tests only: `Some(dir)` makes
    /// [`start_transaction`] call `pam_start_confdir` instead of
    /// `pam_start`. See `config::HelperConfig::pam_confdir` for why this
    /// field, and not merely the call, is `#[cfg(test)]`.
    #[cfg(test)]
    pub(super) pam_confdir: Option<std::path::PathBuf>,
    /// How a shell becomes the account -- `server::become_account` in the
    /// daemon. A plain function pointer, carried across the fork like the
    /// rest of this plan, because the tests of this crate run a helper
    /// unprivileged and need a drop that changes nothing.
    pub(super) become_account: fn(Uid, Gid, &[Gid]) -> nix::Result<()>,
    pub(super) session_group_ops: SessionGroupOps,
    /// How far a descriptor sweep may have to walk
    /// (`server::max_open_descriptors`), read by the helper before the fork:
    /// `getrlimit` is a libc call, and the sweep runs before this process
    /// makes any.
    pub(super) fd_limit: RawFd,
    /// How long the PAM calls in [`Session::begin`] get before this monitor
    /// stops waiting for them -- see [`SessionDeadline`].
    ///
    /// The helper sets it to the budget it gives the CHANNEL that is
    /// opening this session (`config::HelperConfig::startup_timeout`),
    /// because the session opens inside that channel's start: past it the
    /// helper has already given up on the channel, so a session that opened
    /// afterwards would be a session with nothing to serve. A field rather
    /// than a constant read here, for the reason `startup_timeout` is a
    /// setting rather than the bare constant: a test has to be able to
    /// watch the giving-up happen without sitting out the production
    /// budget.
    pub(super) session_budget: Duration,
    /// How long `pam_close_session` and what follows it get, when the login
    /// ends, before this monitor stops waiting for them -- see
    /// [`SessionDeadline`], which is the same guard on the same signal.
    ///
    /// **Its own number, and deliberately the more generous of the two.**
    /// Giving up on an OPEN abandons work that had not finished starting;
    /// giving up on a CLOSE abandons work that might still have succeeded,
    /// and leaves the administrator's stack half-torn -- a logind session
    /// that was being released, a home that was being unmounted. So this
    /// is twice [`MonitorPlan::session_budget`], and the two are not
    /// interchangeable however alike the guard around them looks.
    ///
    /// Twice rather than ten times, because what it bounds is a root
    /// process outliving the login it belongs to, which is the whole
    /// disease this guard was written for; and because past
    /// `server::MONITOR_GRACE_PERIOD` of it the helper's own shutdown stops
    /// waiting anyway (`server::end_the_monitors`), so a larger number
    /// would only lengthen the one case where the helper stays alive -- a
    /// single login ending under a daemon that carries on serving others.
    pub(super) session_close_budget: Duration,
}

/// One shell this monitor has forked, for as long as it is this monitor's
/// business.
struct Shell {
    /// The channel id the helper knows this shell by. The helper refuses a
    /// repeated id, so no two live shells of one monitor share one.
    id: ChannelId,
    #[cfg(any(test, not(target_os = "linux")))]
    pid: Pid,
    #[cfg(target_os = "linux")]
    native: Option<native::NativeShell>,
    #[cfg(target_os = "linux")]
    tty: Option<Guard<'static, Native>>,
    /// The read end of this shell's startup-report pipe, while it is still
    /// starting: end-of-file with nothing in it means the `execve` took,
    /// four bytes mean it did not (`server::read_startup_report`). `None`
    /// once the report has been read.
    #[cfg(any(test, not(target_os = "linux")))]
    report: Option<OwnedFd>,
    /// Whether the helper has been told this shell STARTED.
    ///
    /// What it decides is whether this shell's exit is reported at all: a
    /// shell whose start failed was already answered with
    /// [`MonitorEvent::Failed`], and an `Exited` for the same channel id
    /// afterwards would be a second answer to one request.
    #[cfg(any(test, not(target_os = "linux")))]
    started: bool,
}

#[derive(Debug)]
struct CleanupSummary {
    pam: PamCompletion,
    failure: Option<CleanupFailure>,
    terminal: Option<Result<(), super::protocol::RequestDrainFailure>>,
    request_failure: Option<super::protocol::RequestDrainFailure>,
}
impl Default for CleanupSummary {
    fn default() -> Self {
        Self {
            pam: PamCompletion::NotOpened,
            failure: None,
            terminal: None,
            request_failure: None,
        }
    }
}
fn report_channel_cleanup(
    seam: &UnixStream,
    id: ChannelId,
    kind: CleanupKind,
    failure: Option<CleanupFailure>,
    summary: &mut CleanupSummary,
) {
    merge_cleanup_failure(&mut summary.failure, failure);
    let event = match failure {
        Some(failure) => MonitorEvent::CleanupFailed { id, kind, failure },
        None => MonitorEvent::CleanupComplete { id, kind },
    };
    tell(seam, &event);
}

/// One login's PAM transaction: opened at its first channel, closed when
/// the login ends, both by this one process -- which is the whole reason
/// the monitor exists (spec §3.3).
///
/// The order is spec §6.4's, and every step of it is load-bearing:
///
/// ```text
/// pam_start                      (the stack, the account)
///   -> pam_set_item(PAM_TTY)     both inside `Pam::start`
///   -> pam_set_item(PAM_RHOST)
///   -> pam_acct_mgmt             the account stack's verdict: locked,
///                                expired, not allowed here. A refusal
///                                here opens nothing at all.
///   -> pam_setcred(ESTABLISH)    BEFORE the session opens: `pam_setcred(3)`
///                                says the credentials are established
///                                "before a session is opened for the user".
///   -> pam_open_session
///   -> pam_getenvlist            before any fork, because nothing between
///                                `fork` and `execve` may allocate.
/// ```
///
/// and, when the login ends, its mirror: `pam_close_session` ->
/// `pam_setcred(DELETE_CRED)` -> `pam_end`.
///
/// **Only what was opened is closed.** A `pam_acct_mgmt` that refused left
/// no session and no credentials, so its exit runs `pam_end` alone. That is
/// what the two flags below are for. `pam_end` runs once on consuming close,
/// with `Pam`'s `Drop` retained as fallback for an unfinished transaction.
struct Session {
    /// The transaction, explicitly ended by consuming close; Drop is fallback.
    pam: Pam,
    /// Whether `pam_setcred(PAM_ESTABLISH_CRED)` returned success, and so
    /// whether there is anything for `PAM_DELETE_CRED` to take down.
    ///
    /// The real fixture records establish/delete and failed establishment,
    /// including the absence of cleanup for credentials never established.
    cred_established: bool,
    /// Whether `pam_open_session` returned success, and so whether there is
    /// a session for `pam_close_session` to close. A close of a session
    /// that never opened is what the modules must never be handed.
    session_open: bool,
    /// What `pam_getenvlist` said once the session was open, as
    /// `KEY=VALUE` strings -- merged into every shell's environment (see
    /// [`merge_env`]). Read once, here, because a shell's environment has
    /// to be complete before the fork that runs it.
    env: Vec<CString>,
    /// Exact kernel snapshot after the complete PAM opening sequence.
    groups: Vec<Gid>,
    #[cfg(target_os = "linux")]
    selinux: Snapshot,
}

#[derive(Debug)]
struct SessionFailure {
    why: String,
    cleanup: PamCompletion,
}
impl From<String> for SessionFailure {
    fn from(why: String) -> Self {
        Self {
            why,
            cleanup: PamCompletion::NotOpened,
        }
    }
}
impl From<&str> for SessionFailure {
    fn from(why: &str) -> Self {
        Self::from(why.to_owned())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CleanupStep {
    CloseSession,
    DeleteCred,
    End,
}

fn native_cleanup_step(pam: &mut Pam, step: CleanupStep) -> PamStep {
    match step {
        CleanupStep::CloseSession => {
            PamStep::Attempted(pam.close_session().map_or_else(|e| e.code, |_| 0))
        }
        CleanupStep::DeleteCred => {
            PamStep::Attempted(pam.setcred(Cred::Delete).map_or_else(|e| e.code, |_| 0))
        }
        CleanupStep::End => PamStep::Attempted(
            pam.finish()
                .expect("owned session retains live PAM transaction"),
        ),
    }
}

impl Session {
    /// Open this login's session: the whole opening half of §6.4, in order.
    ///
    /// On failure every acquired cleanup step is attempted before returning.
    /// The error keeps the original refusal separately from cleanup evidence;
    /// messages must be read before the owned transaction is ended.
    fn begin(plan: &MonitorPlan) -> Result<Session, SessionFailure> {
        Self::begin_using(plan, Self::close)
    }

    fn begin_using(
        plan: &MonitorPlan,
        close: impl FnOnce(Session) -> PamCompletion,
    ) -> Result<Session, SessionFailure> {
        // The one place this process blocks outside its poll loop, and
        // until now the one place nothing bounded -- see
        // [`SessionDeadline`] for what that cost. Armed for the whole of
        // this function, including the `close` on the refusal path, and
        // disarmed by its own `Drop` however this returns.
        let _deadline = SessionDeadline::armed(plan.session_budget);
        (plan.session_group_ops.install)(&plan.account.groups)
            .map_err(|e| sanitized_detail(&format!("install account supplementary groups: {e}")))?;
        let mut baseline = (plan.session_group_ops.capture)()
            .map_err(|e| sanitized_detail(&format!("read account supplementary groups: {e}")))?;
        let mut expected = plan.account.groups.clone();
        baseline.sort_unstable_by_key(|g| g.as_raw());
        expected.sort_unstable_by_key(|g| g.as_raw());
        if baseline != expected {
            return Err("verify account supplementary groups: group list mismatch".into());
        }
        let pam = match start_transaction(plan) {
            Ok(pam) => pam,
            // Owned construction may already have rolled back an acquired
            // transaction. Preserve that result independently of the refusal.
            Err(failure) => {
                return Err(SessionFailure {
                    why: sanitized_detail(&failure.error.to_string()),
                    cleanup: failure.cleanup,
                })
            }
        };
        let mut session = Session {
            pam,
            cred_established: false,
            session_open: false,
            env: Vec::new(),
            groups: Vec::new(),
            #[cfg(target_os = "linux")]
            selinux: Snapshot::Disabled,
        };
        match session.open() {
            Ok(()) => match (plan.session_group_ops.capture)() {
                Ok(groups) => {
                    session.groups = groups;
                    session.env = session.pam.env_list();
                    #[cfg(target_os = "linux")]
                    {
                        session.selinux = match selinux_tty::capture(&selinux_tty::NATIVE) {
                            Ok(snapshot) => snapshot,
                            Err(failure) => {
                                let why = sanitized_detail(&format!(
                                    "capture SELinux {:?}: {}",
                                    failure.operation, failure.error
                                ));
                                let cleanup = close(session);
                                return Err(SessionFailure { why, cleanup });
                            }
                        };
                    }
                    Ok(session)
                }
                Err(e) => {
                    let why =
                        sanitized_detail(&format!("capture PAM session supplementary groups: {e}"));
                    let cleanup = close(session);
                    Err(SessionFailure { why, cleanup })
                }
            },
            Err(e) => {
                let why = session.refusal_detail(&e);
                let cleanup = close(session);
                Err(SessionFailure { why, cleanup })
            }
        }
    }

    /// The steps after `pam_start`, each recorded as it succeeds so that
    /// [`Session::close`] can undo exactly those and no others.
    ///
    /// **The stack must have an `auth` section**, although nothing here ever
    /// calls `pam_authenticate`: `pam_setcred` runs the AUTH stack's setcred
    /// half, and Linux-PAM answers `PAM_PERM_DENIED` when there is no such
    /// half to run -- so a `/etc/pam.d/qshd` of `account` and `session`
    /// lines alone refuses EVERY login, with "authentication failed" on the
    /// wire and the real reason only in the helper's log. Measured on
    /// Linux-PAM 1.5.3: `pam_setcred(PAM_ESTABLISH_CRED)` returns 6 without
    /// an `auth` section and 0 with one, everything else unchanged.
    /// `a_stack_with_no_auth_section_refuses_the_login` pins it, and the
    /// packaged `/etc/pam.d/qshd` has to carry such a section.
    ///
    /// `sshd` gets away without one because it only logs a `pam_setcred`
    /// failure when PAM did not authenticate the user; here the refusal is
    /// the point, so the requirement is real.
    fn open(&mut self) -> Result<(), PamError> {
        self.pam.acct_mgmt()?;
        self.pam.setcred(Cred::Establish)?;
        self.cred_established = true;
        self.pam.open_session()?;
        self.session_open = true;
        Ok(())
    }

    /// Close what was opened, in the reverse order, and end the
    /// transaction.
    ///
    /// Every attempted cleanup status is independent from the authentication verdict.
    fn close(self) -> PamCompletion {
        self.close_using(native_cleanup_step)
    }

    fn close_using(
        mut self,
        mut step: impl FnMut(&mut Pam, CleanupStep) -> PamStep,
    ) -> PamCompletion {
        let close_session = if self.session_open {
            step(&mut self.pam, CleanupStep::CloseSession)
        } else {
            PamStep::Skipped
        };
        let delete_cred = if self.cred_established {
            step(&mut self.pam, CleanupStep::DeleteCred)
        } else {
            PamStep::Skipped
        };
        let end = step(&mut self.pam, CleanupStep::End);
        PamCompletion::Finished {
            close_session,
            delete_cred,
            end,
        }
    }

    /// What the modules said as ERRORS while this session was opened
    /// successfully, for the helper's log -- at most [`MAX_NOTES`] of them,
    /// each bounded by [`sanitized_detail`].
    ///
    /// An error message on a session that OPENED is "something is wrong but
    /// we let you in": an `optional` module that failed, a warning from
    /// `pam_faillock`, a password about to expire. Nothing here refuses,
    /// and without this the line reaches nobody -- the person logging in
    /// has no interactive side yet, and this process may not write to the
    /// log. The `PAM_TEXT_INFO` chatter is deliberately left behind; see
    /// `protocol::MonitorEvent::Noted`.
    fn notes(&self) -> Vec<String> {
        self.pam
            .error_messages()
            .iter()
            .take(MAX_NOTES)
            .map(|said| sanitized_detail(said))
            .collect()
    }

    /// What a PAM refusal has to say for the helper's log: the call that
    /// refused and the library's own words for its code, plus anything the
    /// modules said along the way (an expiry notice, a "your account is
    /// locked"), which is often the only part that names the real cause.
    fn refusal_detail(&self, e: &PamError) -> String {
        let mut detail = e.to_string();
        for said in self.pam.messages() {
            detail.push_str("; the stack said: ");
            detail.push_str(said);
        }
        sanitized_detail(&detail)
    }
}

/// A deadline on a monitor's PAM calls, armed for as long as this guard
/// lives. Both places a monitor makes them: [`Session::begin`], and the
/// [`Session::close`] that ends the login -- each on its own budget, for
/// the reason [`MonitorPlan::session_close_budget`] gives.
///
/// # Why this process needs one at all
///
/// Everything else the monitor does is inside its own `poll` loop, and the
/// loop is what notices that this login is over: the helper ends a login by
/// dropping its end of the seam (`server::forget_login`), and the monitor
/// reads that as end-of-file on its next pass. Those two calls are the only
/// places the monitor leaves that loop, and none of the five PAM calls they
/// make -- `pam_acct_mgmt`, `pam_setcred`, `pam_open_session`,
/// `pam_close_session`, the second `pam_setcred` -- has a deadline of its
/// own or any bound on what an administrator's module may do
/// inside it: `pam_ldap` against a directory server that has stopped
/// answering, `pam_systemd` against a wedged dbus, `pam_mount` against a
/// share that is gone.
///
/// A monitor stuck there does not merely take its time. It is a ROOT
/// process that has outlived the login it belongs to, with a PAM
/// transaction open, a terminal held, and -- when the call finally returns
/// -- one more shell forked for a channel the helper has already refused
/// and a login the helper has already told the worker was gone. The helper
/// cannot fix this from outside: killing the monitor is what
/// `server::lose_monitor` does, and a bare kill is exactly what skips
/// `pam_close_session`. The monitor has to end its own login, and to do
/// that it has to come back.
///
/// # How
///
/// `SIGALRM` on an interval timer, with a handler installed WITHOUT
/// `SA_RESTART` -- interrupting the call is the whole point, and a
/// restarted system call would leave the module exactly where it was.
///
/// The better outcome is the first one: the blocking call fails with
/// `EINTR`, the module answers with an error, `Session::open` returns
/// `Err`, and [`Session::begin`]'s own refusal path closes whatever it had
/// opened (`pam_setcred(DELETE_CRED)`, `pam_end`) and tells the helper
/// why. That is a login ended by closing its session rather than by dying.
///
/// **It is not the one to count on, and that is measured, not assumed.**
/// Careful C loops on `EINTR`, and Linux-PAM's own `pam_exec` -- the module
/// this crate's tests stand a hanging stack up with -- does: a monitor
/// stuck in it comes back at TWICE the budget, by the give-up below, with
/// no refusal in the helper's log. So the timer REPEATS rather than firing
/// once, and the give-up is load-bearing rather than a belt over braces.
/// Removing it leaves the stuck monitor running for ever, which is the
/// whole bug back again.
///
/// So it gives up. On the [`SESSION_DEADLINE_FIRINGS`]th firing the handler
/// ends the process, because by then there is nothing left to close
/// politely: the call that would have to be undone has not returned, so no
/// `pam_close_session` was ever possible. What that loses against the
/// first outcome is `pam_end` and a `pam_setcred(DELETE_CRED)` for
/// credentials a half-finished `pam_open_session` may have left -- which a
/// `SIGKILL` from the helper would have lost anyway, one grace period
/// later, while leaving the root process standing in the meantime.
///
/// # Why a signal at all
///
/// Because there is no other way in. The monitor is single-threaded on
/// purpose (it is a child of the single-threaded helper), the PAM handle
/// belongs to the call that is stuck, and a thread abandoned inside PAM
/// would hold that handle for good. A signal is what reaches a process that
/// is inside a system call.
///
/// # What this cannot defend against
///
/// `SIGALRM` and `ITIMER_REAL` are PROCESS-wide, and the modules running
/// inside this window are the administrator's. A module that calls
/// `alarm()` or `setitimer(ITIMER_REAL, ...)` of its own replaces this
/// timer outright -- silently, since the kernel simply returns the old
/// setting to the module and nothing comes back here. The deadline is then
/// gone, this guard cannot know it, and the monitor is back to waiting
/// however long the stack takes. `sshd` shares the same exposure for its
/// own `LoginGraceTime` alarm, so a module that does this is already
/// broken for everyone; it is written down because the failure is silent,
/// which is the kind this slice keeps finding.
///
/// The remedy, if it ever matters: `timer_create` with a private real-time
/// signal (`SIGRTMIN+n`) instead of `ITIMER_REAL` and `SIGALRM`. A
/// per-process timer nobody else names cannot be overwritten by a module
/// that knows nothing about it. Not done now because it costs a signal
/// number, a `sigevent`, and a second disarming path, for a case nobody
/// has seen.
struct SessionDeadline {
    /// What `SIGALRM` was set to before this guard armed it, restored by
    /// [`Drop`]. The monitor installs no other `SIGALRM` handler, so this
    /// is the default disposition in practice; restored rather than
    /// assumed, because a guard that leaves a handler behind would change
    /// what a later `SIGALRM` means to a process that outlives it.
    previous: nix::sys::signal::SigAction,
}

/// How many times the deadline may fire before the monitor stops asking
/// nicely and ends the process.
///
/// Two: one firing to interrupt the call and give the stack its chance to
/// fail, and one more to say that it did not take it. The same shape as
/// every other escalation in this design -- `SIGHUP` then `SIGKILL` for a
/// shell (`escalate`), a grace then a kill for a monitor
/// (`server::MONITOR_GRACE_PERIOD`) -- and the same reason: the polite step
/// is tried first and is not allowed to be the last one.
///
/// What it costs is the bound itself: a monitor is outside its poll loop
/// for at most twice whichever budget is armed -- [`MonitorPlan::session_budget`]
/// on the way in, [`MonitorPlan::session_close_budget`] on the way out --
/// and never longer.
const SESSION_DEADLINE_FIRINGS: usize = 2;

/// What the monitor exits with when its PAM stack would not be interrupted.
///
/// Not `0`: this is not a monitor whose login ended tidily. The helper
/// turns any monitor exit into the end of that monitor's login
/// (`server::forget_login`, the one door), so the code changes no
/// behaviour -- it is what tells whoever reads a `waitpid` status, a
/// `strace` or a core file which of the two exits this was, since a muted
/// monitor cannot say so in the log.
const SESSION_DEADLINE_EXIT: i32 = 70;
const TERMINAL_REFUSAL_FAILED_EXIT: i32 = 75;

/// A private session stage was not established; PAM has not been entered.
#[cfg(target_os = "linux")]
const SESSION_ESTABLISH_FAILED_EXIT: i32 = 74;

/// What the monitor exits with when it cannot arm its parent-death signal.
///
/// Beside [`SESSION_DEADLINE_EXIT`] and for the same reason: a muted
/// process's only way of saying which of its exits this was. The helper
/// treats it like any other monitor exit -- the login ends, with a line in
/// the helper's own log.
const PDEATHSIG_REFUSED_EXIT: i32 = 71;

/// Firings left before [`session_deadline_fired`] ends the process; `0`
/// means disarmed.
///
/// A `static` because a signal handler takes no context, and ONE of them
/// because at most one deadline is ever armed. That used to be true for a
/// simpler reason than it is now: a monitor armed the guard once, opening
/// its session. Since the closing half got a deadline of its own there are
/// TWO armings in a monitor's life -- [`Session::begin`] and the
/// [`Session::close`] at the end of [`run_monitor_until_its_login_ends`] --
/// and what makes one `static` right is that they are SEQUENTIAL and never
/// nested: the opening guard is dropped when `begin` returns, long before
/// the login ends, and both run on this process's only thread.
///
/// Sequential is exactly what [`A_SESSION_DEADLINE_IS_ARMED`] checks, and
/// why it checks it.
static SESSION_DEADLINE_FIRINGS_LEFT: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Whether a [`SessionDeadline`] is armed right now.
///
/// The invariant every piece of this guard rests on is that at most one is
/// armed at a time, and that holds by the shape of the code rather than by
/// anything the code checks: the two armings are sequential (see
/// [`SESSION_DEADLINE_FIRINGS_LEFT`]), and a test for the nesting would
/// have to construct a call order that does not exist.
///
/// It is checked anyway, because breaking it would fail SILENTLY and
/// destructively rather than loudly. A guard armed inside another would
/// record the OUTER guard's handler as its own `previous`, reset the timer
/// to its own budget, and then, on its `Drop`, put all of that back and
/// disarm -- leaving the outer deadline gone, its counter zeroed and its
/// timer stopped, with nothing anywhere to say so. The monitor would go on
/// believing it was bounded, which is the one belief this whole guard
/// exists to make true.
///
/// One `swap` in [`SessionDeadline::armed`] turns that into a panic, which
/// `run_monitor`'s own guard turns into an `_exit`. And it costs no test of
/// its own: every test in this crate that opens a session arms this guard
/// twice in succession, so a check that refused a SEQUENTIAL arming -- a
/// flag left set by a `Drop` that forgot it, say -- would fail those tests
/// at once.
static A_SESSION_DEADLINE_IS_ARMED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// The deadline's handler: interrupt now, end the process on the last
/// firing.
///
/// Async-signal-safe by construction, which is what a handler installed in
/// a process running an administrator's PAM modules has to be: one relaxed
/// atomic on a lock-free `usize` and, at most, `_exit`.
extern "C" fn session_deadline_fired(_sig: std::os::raw::c_int) {
    use std::sync::atomic::Ordering;

    // Disarmed. This is what makes a firing that lands in the window
    // between the PAM call returning and `Drop` stopping the timer harmless
    // -- rather than a monitor killed for a session it had just opened.
    if SESSION_DEADLINE_FIRINGS_LEFT.load(Ordering::Relaxed) == 0 {
        return;
    }
    if SESSION_DEADLINE_FIRINGS_LEFT.fetch_sub(1, Ordering::Relaxed) == 1 {
        // SAFETY: `_exit` ends the process immediately, running no atexit
        // handlers and no Rust `Drop` impls, and is on POSIX's
        // async-signal-safe list -- sound to call from a handler, and the
        // only thing that is sound to do here.
        unsafe { nix::libc::_exit(SESSION_DEADLINE_EXIT) }
    }
}

impl SessionDeadline {
    /// Arm the deadline: `budget` from now, and again every `budget` after
    /// that.
    fn armed(budget: Duration) -> SessionDeadline {
        use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet};
        use std::sync::atomic::Ordering;

        // At most one armed at a time -- see [`A_SESSION_DEADLINE_IS_ARMED`]
        // for why a violation would be silent, and why that is worse here
        // than being loud. A panic rather than a quiet correction: this is
        // an order of calls that does not exist, and if it ever does, the
        // monitor's own guard turns this into an `_exit` with a message on
        // the helper's standard error.
        assert!(
            !A_SESSION_DEADLINE_IS_ARMED.swap(true, Ordering::SeqCst),
            "a session deadline was armed inside another one: the outer deadline would be \
             silently thrown away by the inner guard's Drop"
        );
        SESSION_DEADLINE_FIRINGS_LEFT.store(SESSION_DEADLINE_FIRINGS, Ordering::Relaxed);
        let action = SigAction::new(
            SigHandler::Handler(session_deadline_fired),
            // No `SA_RESTART`: a restarted system call would put the module
            // straight back where it was, which is the one outcome this
            // must not have. No signals blocked during the handler either;
            // it does nothing a second firing could disturb.
            SaFlags::empty(),
            SigSet::empty(),
        );
        // SAFETY: the handler is async-signal-safe (see its own docs), and
        // `sigaction` on `SIGALRM` with a valid action cannot fail -- the
        // call's only errors are an invalid signal number and the two
        // signals that may not be caught, none of which this is.
        let previous =
            unsafe { sigaction(Signal::SIGALRM, &action) }.expect("SIGALRM may always be caught");
        set_interval_timer(budget);
        SessionDeadline { previous }
    }
}

impl Drop for SessionDeadline {
    fn drop(&mut self) {
        use nix::sys::signal::sigaction;
        use std::sync::atomic::Ordering;

        // In this order, and the order is the point: disarming the COUNTER
        // first makes any firing still in flight a no-op, so neither the
        // stop nor the restore below can race a signal into ending a
        // monitor that has just come back.
        SESSION_DEADLINE_FIRINGS_LEFT.store(0, Ordering::Relaxed);
        set_interval_timer(Duration::ZERO);
        // SAFETY: as in `armed`; this restores what was there before.
        let _ = unsafe { sigaction(Signal::SIGALRM, &self.previous) };
        // Last, so the flag is true for exactly as long as this guard's own
        // state is installed -- and so the NEXT arming, which in a
        // monitor's life is the closing half, finds it clear.
        A_SESSION_DEADLINE_IS_ARMED.store(false, Ordering::SeqCst);
    }
}

/// Set `ITIMER_REAL` to fire after `every` and again every `every` after
/// that. `Duration::ZERO` stops it.
fn set_interval_timer(every: Duration) {
    let interval = nix::libc::timeval {
        tv_sec: every.as_secs() as nix::libc::time_t,
        tv_usec: i64::from(every.subsec_micros()) as nix::libc::suseconds_t,
    };
    let timer = nix::libc::itimerval {
        it_interval: interval,
        it_value: interval,
    };
    // SAFETY: one system call, with a pointer to a local this frame owns
    // and a NULL for the previous value, which this caller does not want.
    unsafe {
        nix::libc::setitimer(nix::libc::ITIMER_REAL, &timer, std::ptr::null_mut());
    }
}

/// Translate the worker-reported endpoint only at the remote PAM boundary.
/// The full endpoint stays with the helper for diagnostics. This validates
/// its representation, not its truth: a compromised worker still chooses it.
/// Never give PAM an empty/unknown origin, which some stacks treat as local.
fn pam_origin(rhost: &str) -> Result<String, PamError> {
    rhost
        .parse::<SocketAddr>()
        .map(|endpoint| endpoint.ip())
        .or_else(|_| rhost.parse::<IpAddr>())
        .map(|ip| match ip {
            IpAddr::V6(v6) => v6
                .to_ipv4_mapped()
                .map_or_else(|| v6.to_string(), |v4| v4.to_string()),
            IpAddr::V4(v4) => v4.to_string(),
        })
        .map_err(|_| PamError {
            code: super::pam::PAM_SYSTEM_ERR,
            what: "the client address is not a numeric IP or endpoint",
        })
}

/// `pam_start` for this login, from the stack the plan names.
///
/// Two functions, not one with a branch, and the test one is
/// `#[cfg(test)]`: `pam_start_confdir` is versioned `@LIBPAM_1.4`, and a
/// reference to it anywhere in the daemon -- in a branch never taken
/// included -- makes the dynamic loader refuse the whole binary on
/// Linux-PAM 1.3.1 (Ubuntu 20.04, RHEL 8) before `main` runs. See
/// `config::HelperConfig::pam_confdir`, and `scripts/check-pam-linkage.sh`,
/// which is what actually checks it.
#[cfg(not(test))]
fn start_transaction(plan: &MonitorPlan) -> Result<Pam, PamStartFailure> {
    let origin = pam_origin(&plan.rhost)?;
    Pam::start_owned(&plan.pam_service, &plan.account.name, &plan.tty, &origin)
}

/// [`start_transaction`], for the tests: a stack in a directory of the
/// test's own, so the PAM tests need no root and touch no `/etc/pam.d`.
#[cfg(test)]
fn start_transaction(plan: &MonitorPlan) -> Result<Pam, PamStartFailure> {
    let origin = pam_origin(&plan.rhost)?;
    match &plan.pam_confdir {
        Some(dir) => Pam::start_confdir_owned(
            dir,
            &plan.pam_service,
            &plan.account.name,
            &plan.tty,
            &origin,
        ),
        None => Pam::start_owned(&plan.pam_service, &plan.account.name, &plan.tty, &origin),
    }
}

/// The most of a PAM refusal that travels to the helper's log.
///
/// Generous next to anything a module actually says, and small enough that
/// the whole event stays far inside `protocol::MAX_MESSAGE_LEN` -- an event
/// over that cap would not be sent at all, and a refusal with no reason
/// anywhere is the one outcome this text exists to prevent.
///
/// `pub(super)` so `super::pam` can pin its own keeping bound against it:
/// what a transaction HOLDS is bounded by the same number this cuts the
/// output to, which is what makes that bound invisible to every reader
/// (`pam::MAX_KEPT_CHARS`).
pub(super) const MAX_REFUSAL_DETAIL: usize = 512;

/// The most lines of "we let you in, but" a login may put in the helper's
/// log ([`Session::notes`]).
///
/// A cap rather than none, because how many a stack produces is the
/// administrator's modules' business and the log is a root process's: a
/// module that complained once per login would already be noisy, and one
/// that complained a hundred times per login would be an amplifier. The
/// cap is silent -- a login whose stack says more than this has bigger
/// problems than a truncated log line.
///
/// `pub(super)` only so `server`'s tests can pin it from outside:
/// `server::tests::a_login_leaves_at_most_max_notes_lines_in_the_log` is
/// what actually proves the cap applies, not just that it is declared.
pub(super) const MAX_NOTES: usize = 8;

/// What a PAM module's words are allowed to be in the helper's log: at most
/// [`MAX_REFUSAL_DETAIL`] bytes of printable ASCII.
///
/// The text comes from modules the administrator configured and is written
/// into a ROOT process's log. A newline in it would forge a second log
/// line; an escape sequence would aim at whoever reads that log on a
/// terminal. Unlike `server::sanitized_rhost`, which replaces a value it
/// does not like WHOLE (an address is an identity, and a mangled one must
/// not read as a real one), this keeps what it can: it is diagnostic prose,
/// and half of it still says more about a refusal than nothing does.
fn sanitized_detail(detail: &str) -> String {
    detail
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '.'
            }
        })
        .take(MAX_REFUSAL_DETAIL)
        .collect()
}

/// A shell's environment: the one built from passwd
/// (`server::child_env`), with what the session stack set on top.
///
/// The session stack wins where the two name the same variable, which is
/// what `sshd` does with its own `pam_getenvlist` -- a `pam_env` that sets
/// `PATH` or a module that points `XDG_RUNTIME_DIR` at the session it has
/// just made is answering a question passwd knows nothing about. Neither
/// side may contribute the same name twice: `getenv` answers with the FIRST
/// match, so an array with both would hand every program that reads its
/// environment directly the passwd value, while a shell -- which rebuilds
/// its own table and keeps the LAST -- showed the stack's. A `pam_env` that
/// set `PATH` would then be silently ignored by exactly the programs that
/// do not go through a shell.
///
/// That this function is actually WIRED IN is pinned by
/// `server::tests::the_shell_is_handed_each_environment_name_once`, which
/// reads `/proc/$$/environ` -- the array `execve` was given -- rather than a
/// variable's value, because the value alone cannot tell one entry from two.
///
/// An entry with no `=` at all cannot come from `pam_getenvlist` (it lists
/// `KEY=VALUE`), and is treated as a name with an empty value rather than
/// guessed at.
fn merge_env(passwd: Vec<CString>, session: &[CString]) -> Vec<CString> {
    let name_of = |entry: &CString| {
        let bytes = entry.as_bytes();
        let end = bytes.iter().position(|b| *b == b'=').unwrap_or(bytes.len());
        bytes[..end].to_vec()
    };
    let mut merged = passwd;
    for entry in session {
        let name = name_of(entry);
        match merged.iter().position(|had| name_of(had) == name) {
            Some(at) => merged[at] = entry.clone(),
            None => merged.push(entry.clone()),
        }
    }
    merged
}

/// Serve one login's shells until the helper closes the seam, then take
/// them down, close the login's PAM session and end this process. Never
/// returns: this is a child of the helper, and returning into the helper's
/// loop would make a second helper.
pub(super) fn run_monitor(plan: MonitorPlan, seam: UnixStream, helper_pid: Pid) -> ! {
    // The whole body under a `catch_unwind`: every `_exit` below closes a
    // `return`, and nothing closed a `panic`. See
    // `server::PANICKED_CHILD_EXIT` for what a panic would do instead and
    // why the guard is here rather than `panic = "abort"` in a manifest.
    //
    // It does NOT cover a shell's own child, and that was measured rather
    // than assumed: a panic between `fork_shell`'s `fork` and its `execve`
    // never reaches this frame, because the unwinding hits the `OwnedFd`s
    // of `fork_shell`'s own frame first -- descriptors
    // `close_other_descriptors` has just closed in that child -- and Rust
    // ends the process there with `fatal runtime error: IO Safety
    // violation: owned file descriptor already closed`. That child dies
    // either way, which is the outcome that matters, but it dies by
    // `SIGABRT` partway through the unwinding rather than by an `_exit` of
    // its own. Left as it is: the shell child is the one fork the privilege
    // review did not name, and turning an abort into a tidy exit there is a
    // change of its own to argue.
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        run_monitor_until_its_login_ends(plan, seam, helper_pid)
    }));
    if let Err(payload) = panicked {
        // Dropping the payload could itself panic, and this is outside the
        // catch: leak it rather than unwind past the `_exit` after all --
        // the same treatment `pam::converse` gives a panic on its own C
        // boundary.
        std::mem::forget(payload);
    }
    // SAFETY: `_exit` ends the process immediately, running no atexit
    // handlers and no Rust `Drop` impls -- which is what has to happen in a
    // process that shares its parent's image, and doubly so in one whose
    // stack has just been unwound past descriptor numbers it no longer
    // owns.
    unsafe { nix::libc::_exit(super::server::PANICKED_CHILD_EXIT) }
}

/// Makes the next monitor forked in this process panic as soon as it
/// starts.
///
/// The only way a test can reach [`run_monitor`]'s panic guard, and so the
/// only way removing that guard can be made to show. Nothing in this
/// process's own body can be made to panic from outside: every failure it
/// has is a `Result`, and the three `expect`s it does make are on a
/// constant, a literal and a signal that may always be caught. Without
/// this the guard would be reasoning rather than coverage, and taking it
/// away would leave every test green.
///
/// A `static` rather than a field of [`MonitorPlan`] because it never
/// travels as data: a monitor is a `fork` of the process that sets this,
/// and inherits it. `#[cfg(test)]`, so nothing a daemon is started with can
/// reach it -- the rule [`MonitorPlan::pam_confdir`] follows. The one test
/// that sets it runs in a process of its own, because a process-wide flag
/// read by every monitor is not something to leave lying about in a suite
/// whose default is several threads.
#[cfg(test)]
pub(super) static PANIC_WHEN_A_MONITOR_STARTS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// [`run_monitor`]'s whole body, inside its guard. Never returns, for the
/// reason [`run_monitor`] never does: each of its endings is an `_exit`, so
/// the ordinary paths still run no destructor at all.
fn run_monitor_until_its_login_ends(plan: MonitorPlan, seam: UnixStream, helper_pid: Pid) -> ! {
    // FIRST, before anything that allocates or opens a descriptor of its
    // own: this process never execs, so nothing else is ever going to close
    // what it inherited -- see this module's docs for what that inheritance
    // costs if it is left in place. `seam` is the one descriptor kept.
    close_other_descriptors(seam.as_raw_fd(), plan.fd_limit);
    // And the log goes with them: the file is closed now but `crate::log`
    // still holds its NUMBER, which the pipes, sockets and terminals opened
    // below -- by this code and by every PAM module the administrator
    // configured -- can be handed. See this module's docs.
    crate::log::mute();
    // The monitor was the one link in the chain of deaths without a
    // parent-death signal: the worker arms one against the helper
    // (`helper::split_and_run`), every shell arms one against its monitor
    // (`fork_shell`), and nothing armed one HERE. A helper killed while a
    // monitor sat inside its PAM stack therefore left that monitor -- a
    // root process, with a session open and shells under it -- reparented
    // to init and running across a restart of the service, with nobody left
    // who could close its session or even find it.
    //
    // `helper::arm_and_verify_pdeathsig` rather than a bare `prctl`: it
    // proves the registration actually took, and its `getppid` check closes
    // the window between the fork and this line -- a helper that died
    // anywhere in there has already reparented this process, whenever in
    // that window it happened. This is a child of a `fork`, so nothing here
    // inherited the helper's own registration; and unlike a shell, a
    // monitor changes supplementary groups only, which does not clear
    // the parent-death signal. Its uid and primary gid remain unchanged,
    // so it needs no second arming. `a_monitor_dies_with_its_helper` pins the
    // effect.
    //
    // A failure is fatal, and silently: this process may not write to the
    // log (`mute`, just above), and a monitor that cannot be killed when
    // its helper dies is the very thing this call exists to prevent, so
    // carrying on without it would be worse than not starting. The helper
    // reads the exit as the loss of a monitor and ends the login
    // (`server::forget_login`), which is the right outcome and is logged
    // there.
    //
    // **The trade-off, and what is left of it.** When this signal fires,
    // the session this process holds is never closed: no
    // `pam_close_session`, no `pam_setcred(DELETE_CRED)`, no `pam_end`.
    // That is the right price for a helper that DIED -- there the whole
    // daemon is going, and the alternative is this root process, with its
    // session and its shells, reparented to init and surviving a restart of
    // the service with nobody left who could close anything.
    //
    // It was the wrong price for a helper that LEAVES, and arming this
    // signal took a close away that used to happen: measured on the wave
    // that added it, a login ended by `Request::LoginEnded` still closed
    // its session while the same login with the helper stopping did not.
    // That case is no longer this signal's: `server::end_the_monitors`
    // drops the seams and waits before the helper's process exits, so the
    // ordinary end of a daemon closes its sessions and this signal only
    // ever catches the death it was written for. What remains uncovered is
    // a close slower than `server::MONITOR_GRACE_PERIOD`, and a helper that
    // dies outright -- in that order of likelihood, and both named rather
    // than left to be found.
    if super::arm_and_verify_pdeathsig(helper_pid).is_err() {
        // SAFETY: `_exit` ends the process immediately, running no atexit
        // handlers and no Rust `Drop` impls -- which is what has to happen
        // in a child that shares its parent's image.
        unsafe { nix::libc::_exit(PDEATHSIG_REFUSED_EXIT) }
    }
    #[cfg(target_os = "linux")]
    {
        // This private stage precedes every NSS/PAM/descendant-producing action.
        // Failed setup/publication keeps parent authority exact-child-only.
        let established = nix::unistd::setsid().and_then(|sid| {
            let bytes = encode(&MonitorEvent::SessionEstablished {
                sid: sid.as_raw() as u32,
            })
            .map_err(|_| nix::Error::EINVAL)?;
            channel::send(&seam, &bytes, None).map_err(|error| {
                nix::Error::from_raw(error.raw_os_error().unwrap_or(nix::libc::EIO))
            })
        });
        if established.is_err() {
            unsafe { nix::libc::_exit(SESSION_ESTABLISH_FAILED_EXIT) }
        }
    }
    // The one way a test can reach [`run_monitor`]'s panic guard; see the
    // flag's own docs for why nothing else can.
    #[cfg(target_os = "linux")]
    if plan.child_mask.is_some_and(|mask| mask.restore().is_err()) {
        unsafe { nix::libc::_exit(SESSION_ESTABLISH_FAILED_EXIT) }
    }
    #[cfg(test)]
    if PANIC_WHEN_A_MONITOR_STARTS.load(std::sync::atomic::Ordering::SeqCst) {
        panic!("a deliberate panic in a monitor's own body");
    }
    let mut shells = Vec::new();
    let mut session = None;
    let mut cleanup = CleanupSummary::default();
    serve(
        &plan,
        &seam,
        &mut shells,
        &mut session,
        &mut cleanup,
        helper_pid,
    );
    if let Some(result) = cleanup.terminal {
        unsafe {
            nix::libc::_exit(if result.is_ok() {
                0
            } else {
                TERMINAL_REFUSAL_FAILED_EXIT
            })
        }
    }
    // The shells first, then the session: a session closed under a live
    // shell would be closed while the thing it was opened for is still
    // running, and the modules that count logins (`pam_systemd`,
    // `pam_limits`) would tear down what that shell is still using.
    end_the_shells(&seam, &mut shells, &mut cleanup);
    if let Some(session) = session {
        // The closing half gets a deadline too, and the asymmetry it
        // corrects was an accident rather than a decision: the guard had
        // exactly one call site, on the opening half, and `pam_close_session`
        // blocks in the same modules for the same reasons -- `pam_systemd`
        // closes a session with a synchronous round trip to logind. The
        // danger is smaller here (the login is already over, and nobody is
        // waiting for an answer), but so is the rescue: a monitor hung in a
        // close is killed by nobody at all, since the helper's own
        // escalation needs a monitor that has a channel to fail to report,
        // and this one has none left.
        let _deadline = SessionDeadline::armed(plan.session_close_budget);
        cleanup.pam.merge(session.close());
    }
    tell(
        &seam,
        &MonitorEvent::SessionClosed {
            result: cleanup.pam,
            request_failure: cleanup.request_failure,
            cleanup_failure: cleanup.failure,
        },
    );
    // SAFETY: `_exit` ends the process immediately, running no atexit
    // handlers and no Rust `Drop` impls -- which is what has to happen
    // here, in a process that shares its parent's image.
    unsafe {
        nix::libc::_exit(if cleanup.request_failure.is_none() {
            0
        } else {
            TERMINAL_REFUSAL_FAILED_EXIT
        })
    }
}

/// The monitor's own loop: serve the helper's requests, report what becomes
/// of each shell, and end the shells the helper has asked to close.
/// Returns when the seam is gone -- the login has ended, or the helper has.
fn serve(
    plan: &MonitorPlan,
    seam: &UnixStream,
    shells: &mut Vec<Shell>,
    session: &mut Option<Session>,
    cleanup: &mut CleanupSummary,
    helper_pid: Pid,
) {
    // Channels a `MonitorRequest::Close` has sent `SIGHUP`, keyed to the
    // deadline by which the escalation to `SIGKILL` follows -- the helper's
    // own `closing` map, moved here with the fork it belongs to.
    let mut closing: HashMap<ChannelId, Instant> = HashMap::new();
    loop {
        let report_fds: Vec<RawFd> = shells
            .iter()
            .filter_map(|shell| {
                #[cfg(target_os = "linux")]
                {
                    shell
                        .native
                        .as_ref()
                        .and_then(native::NativeShell::report_fd)
                }
                #[cfg(not(target_os = "linux"))]
                {
                    shell.report.as_ref().map(AsRawFd::as_raw_fd)
                }
            })
            .collect();
        let mut fds: Vec<PollFd> = Vec::with_capacity(1 + report_fds.len());
        fds.push(PollFd::new(seam.as_fd(), PollFlags::POLLIN));
        for fd in &report_fds {
            // SAFETY: every number here came out of `shells` a line ago, and
            // each is owned there (`Shell::report` is an `OwnedFd`) for the
            // whole of this pass -- nothing between here and the `poll`
            // below takes one out.
            fds.push(PollFd::new(
                unsafe { BorrowedFd::borrow_raw(*fd) },
                PollFlags::POLLIN,
            ));
        }
        // Never longer than the helper's own reap interval: a shell that
        // exits while the helper is silent has to be noticed all the same,
        // and so does a `SIGHUP` that has gone unanswered past its grace.
        match poll(
            &mut fds,
            PollTimeout::try_from(REAP_INTERVAL).expect("the reap interval fits a poll timeout"),
        ) {
            Ok(_) => {}
            Err(nix::Error::EINTR) => continue,
            // A poll that fails for any other reason is a monitor that can
            // no longer watch anything: end, and let the shells go with it.
            Err(_) => return,
        }
        let seam_ready = fds[0].any().unwrap_or(true);
        let ready: Vec<RawFd> = report_fds
            .iter()
            .zip(&fds[1..])
            .filter(|(_, polled)| polled.any().unwrap_or(true))
            .map(|(fd, _)| *fd)
            .collect();

        #[cfg(target_os = "linux")]
        {
            let _ = ready;
            report_owned_shells(seam, shells, cleanup);
        }
        #[cfg(not(target_os = "linux"))]
        report_startups(seam, shells, &ready);
        if seam_ready
            && !serve_request(
                plan,
                seam,
                shells,
                session,
                cleanup,
                &mut closing,
                helper_pid,
            )
        {
            return;
        }
        #[cfg(not(target_os = "linux"))]
        {
            reap_shells(seam, shells, &mut closing);
            escalate(seam, shells, &mut closing);
        }
    }
}

/// Consume the sealed refused request queue without ever starting PAM/shells.
/// One absolute phase covers original outcomes, queue drain and final send.
#[cfg(test)]
pub(super) fn refused_requests_fixture(
    seam: &UnixStream,
    helper_pid: Pid,
    original: ChannelId,
) -> bool {
    refused_requests(
        seam,
        helper_pid,
        original,
        "fixture account denied".into(),
        &CleanupSummary::default(),
        Instant::now() + Duration::from_secs(1),
    )
    .is_ok()
}

fn refused_requests(
    seam: &UnixStream,
    helper_pid: Pid,
    original: ChannelId,
    why: String,
    cleanup: &CleanupSummary,
    until: Instant,
) -> Result<(), super::protocol::RequestDrainFailure> {
    let mut acknowledged = false;
    let result = refused_requests_inner(
        seam,
        helper_pid,
        original,
        why,
        cleanup,
        until,
        &mut acknowledged,
    );
    if let Err(failure) = result {
        if !acknowledged {
            if let Ok(packet) = encode(&MonitorEvent::SessionClosed {
                result: cleanup.pam,
                cleanup_failure: cleanup.failure,
                request_failure: Some(failure),
            }) {
                while Instant::now() < until {
                    match channel::try_send_before(seam, &packet, until) {
                        Ok(()) => break,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                            ) => {}
                        Err(_) => break,
                    }
                    let remaining = until.saturating_duration_since(Instant::now());
                    let mut fds = [PollFd::new(seam.as_fd(), PollFlags::POLLOUT)];
                    match poll(
                        &mut fds,
                        PollTimeout::try_from(remaining.min(REAP_INTERVAL)).unwrap(),
                    ) {
                        Ok(_) | Err(nix::Error::EINTR) => {}
                        Err(_) => break,
                    }
                }
            }
        }
    }
    result
}

fn refused_requests_inner(
    seam: &UnixStream,
    helper_pid: Pid,
    original: ChannelId,
    why: String,
    cleanup: &CleanupSummary,
    until: Instant,
    acknowledged: &mut bool,
) -> Result<(), super::protocol::RequestDrainFailure> {
    use super::protocol::RequestDrainFailure as Fault;
    let mut queue = VecDeque::new();
    let mut ids = vec![original];
    let mut sealed = false;
    let mut final_queued = false;
    let mut phase_failure = None;
    let append = |queue: &mut VecDeque<Vec<u8>>, event: MonitorEvent| -> Result<(), Fault> {
        if queue.len() >= 33 {
            return Err(Fault::Protocol);
        }
        queue.push_back(encode(&event).map_err(|_| Fault::Protocol)?);
        Ok(())
    };
    append(&mut queue, MonitorEvent::Refused { id: original, why })?;
    append(
        &mut queue,
        MonitorEvent::CleanupComplete {
            id: original,
            kind: CleanupKind::NoChild,
        },
    )?;
    loop {
        if Instant::now() >= until {
            return Err(Fault::Deadline);
        }
        if (sealed || phase_failure.is_some()) && queue.is_empty() && !final_queued {
            append(
                &mut queue,
                MonitorEvent::SessionClosed {
                    result: cleanup.pam,
                    cleanup_failure: cleanup.failure,
                    request_failure: phase_failure,
                },
            )?;
            final_queued = true;
        }
        if let Some(packet) = queue.front() {
            match channel::try_send_before(seam, packet, until) {
                Ok(()) => {
                    queue.pop_front();
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                    return Err(Fault::Deadline)
                }
                Err(_) => return Err(Fault::Send),
            }
        }
        if final_queued && queue.is_empty() {
            *acknowledged = true;
            return phase_failure.map_or(Ok(()), Err);
        }
        if !sealed && phase_failure.is_none() {
            let received = channel::receive_owned_once(seam);
            match received {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
                    ) => {}
                Err(_) => phase_failure = Some(Fault::Receive),
                Ok(packet) => {
                    #[cfg(target_os = "linux")]
                    let sender_ok = packet.sender == Some(helper_pid.as_raw());
                    #[cfg(not(target_os = "linux"))]
                    let sender_ok = {
                        let _ = helper_pid;
                        true
                    };
                    if packet.invalid || !sender_ok || packet.bytes.is_empty() {
                        phase_failure = Some(Fault::Protocol);
                    } else {
                        match decode::<MonitorRequest>(&packet.bytes) {
                            Ok(MonitorRequest::SealRefused) if packet.descriptors.is_empty() => {
                                sealed = true
                            }
                            Ok(MonitorRequest::Close { id })
                                if packet.descriptors.is_empty() && ids.contains(&id) => {}
                            Ok(MonitorRequest::Open { id, .. })
                                if packet.descriptors.len() == 1
                                    && ids.len() < 16
                                    && id > *ids.last().unwrap() =>
                            {
                                // All received PTYs close before certifying this exact no-fork request.
                                drop(packet.descriptors);
                                ids.push(id);
                                append(
                                    &mut queue,
                                    MonitorEvent::Refused {
                                        id,
                                        why: "authentication failed".into(),
                                    },
                                )?;
                                append(
                                    &mut queue,
                                    MonitorEvent::CleanupComplete {
                                        id,
                                        kind: CleanupKind::NoChild,
                                    },
                                )?;
                            }
                            _ => phase_failure = Some(Fault::Protocol),
                        }
                    }
                }
            }
        }
        let remaining = until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Fault::Deadline);
        }
        let mut interests = PollFlags::empty();
        if !queue.is_empty() {
            interests |= PollFlags::POLLOUT;
        }
        if !sealed && phase_failure.is_none() {
            interests |= PollFlags::POLLIN;
        }
        let mut fds = [PollFd::new(seam.as_fd(), interests)];
        match poll(
            &mut fds,
            PollTimeout::try_from(remaining.min(REAP_INTERVAL)).unwrap(),
        ) {
            Ok(_) | Err(nix::Error::EINTR) => {}
            Err(_) => return Err(Fault::Receive),
        }
    }
}

/// Read one request off the seam and act on it. `false` means the seam is
/// gone (the login has ended, or the helper has) and this monitor is over.
fn serve_request(
    plan: &MonitorPlan,
    seam: &UnixStream,
    shells: &mut Vec<Shell>,
    session: &mut Option<Session>,
    cleanup: &mut CleanupSummary,
    closing: &mut HashMap<ChannelId, Instant>,
    helper_pid: Pid,
) -> bool {
    let (bytes, slave) = match channel::recv(seam) {
        Ok(Some(message)) => message,
        // The helper closed its end: this login is over.
        Ok(None) => return false,
        Err(_) => return false,
    };
    // A message that does not decode means the helper is not the process
    // this one thinks it is. There is nothing to answer it with and no
    // reason to go on serving.
    let Ok(request) = decode::<MonitorRequest>(&bytes) else {
        return false;
    };
    match request {
        MonitorRequest::SealRefused => {
            cleanup.request_failure = Some(super::protocol::RequestDrainFailure::Protocol);
            return false;
        }
        MonitorRequest::Open {
            id,
            term,
            shell,
            command,
        } => {
            // Every `Open` carries its channel's terminal. One without it is
            // a helper that is not what this process thinks it is.
            let Some(slave) = slave else {
                return false;
            };
            // The login's session, opened by the FIRST channel that asks
            // for one and by no other: every later channel of this login
            // forks its shell inside the session already open. See
            // [`Session`] for the order, and this module's docs for why one
            // session per login needs no bookkeeping beyond this `Option`.
            if session.is_none() {
                match Session::begin(plan) {
                    Ok(opened) => {
                        // What the stack complained about while letting this
                        // login in. Said BEFORE the session is stored, so
                        // that an event about opening the session cannot
                        // arrive after one about the shell it was opened
                        // for.
                        for what in opened.notes() {
                            tell(seam, &MonitorEvent::Noted { id, what });
                        }
                        *session = Some(opened);
                    }
                    Err(SessionFailure {
                        why,
                        cleanup: failed_cleanup,
                    }) => {
                        cleanup.pam.merge(failed_cleanup);
                        // Session::begin attempted every acquired cleanup step;
                        // its result remains independent from the refusal.
                        // This login gets no shell, now or later.
                        // The monitor ENDS: a login whose account
                        // stack refused it must not be left with a process
                        // that could still fork a shell outside any
                        // session, and the helper turns the loss of a
                        // monitor into the end of its login (`forget_login`,
                        // the one door). The refusal reaches the worker as
                        // the shared `server::REFUSED_REASON`; the real
                        // reason travels in `why`, for the helper's log,
                        // because this process may not write to it.
                        let until = Instant::now() + plan.session_budget;
                        drop(slave); // no startup descriptor may outlive the proof
                        cleanup.terminal =
                            Some(refused_requests(seam, helper_pid, id, why, cleanup, until));
                        return false;
                    }
                }
            }
            let Some(open) = session.as_ref() else {
                // Unreachable: the block above either put a session here or
                // returned. An empty environment as a fallback would be a
                // shell forked with no session behind it, which is the one
                // thing this whole process exists to prevent -- so this
                // ends the monitor instead of carrying on with a
                // plausible-looking default.
                return false;
            };
            #[cfg(target_os = "linux")]
            let (slave, tty) = match prepare_terminal(&open.selinux, slave) {
                Ok(prepared) => prepared,
                Err(failure) => {
                    tell(
                        seam,
                        &MonitorEvent::Noted {
                            id,
                            what: sanitized_detail(&failure.why),
                        },
                    );
                    tell(
                        seam,
                        &MonitorEvent::Failed {
                            id,
                            errno: terminal_errno(&failure.error),
                        },
                    );
                    report_channel_cleanup(
                        seam,
                        id,
                        CleanupKind::NoChild,
                        failure.cleanup,
                        cleanup,
                    );
                    return true;
                }
            };
            match fork_shell(
                plan,
                &open.env,
                &open.groups,
                slave,
                term.as_deref(),
                shell,
                &command,
            ) {
                Ok(forked) => shells.push(Shell {
                    id,
                    #[cfg(any(test, not(target_os = "linux")))]
                    pid: forked.pid,
                    #[cfg(target_os = "linux")]
                    native: Some(forked.native),
                    #[cfg(target_os = "linux")]
                    tty,
                    #[cfg(any(test, not(target_os = "linux")))]
                    report: forked.report,
                    #[cfg(any(test, not(target_os = "linux")))]
                    started: false,
                }),
                Err(errno) => {
                    // All fork_shell Err branches precede successful fork.
                    tell(
                        seam,
                        &MonitorEvent::Failed {
                            id,
                            errno: errno as i32,
                        },
                    );
                    #[cfg(target_os = "linux")]
                    report_terminal_cleanup(seam, id, CleanupKind::NoChild, tty, cleanup);
                    #[cfg(not(target_os = "linux"))]
                    report_channel_cleanup(seam, id, CleanupKind::NoChild, None, cleanup);
                }
            }
        }
        MonitorRequest::Close { id } => {
            #[cfg(target_os = "linux")]
            {
                let _ = closing;
                if let Some(native) = shells
                    .iter_mut()
                    .find(|shell| shell.id == id)
                    .and_then(|shell| shell.native.as_mut())
                {
                    native.request_stop(Instant::now());
                }
            }
            #[cfg(not(target_os = "linux"))]
            if let Some(shell) = shells.iter().find(|shell| shell.id == id) {
                signal_shell(seam, shell, Signal::SIGHUP);
                closing.insert(id, Instant::now() + CLOSE_GRACE_PERIOD);
            }
            // A `Close` for a channel this monitor has no shell for is a
            // no-op: the helper sends one for a start it has given up on
            // (`server::refuse_starting_channel`), whose shell may already
            // have failed and gone.
        }
    }
    true
}

/// Tell the helper what became of every shell whose report pipe has just
/// spoken.
#[cfg(any(test, not(target_os = "linux")))]
fn report_startups(seam: &UnixStream, shells: &mut [Shell], ready: &[RawFd]) {
    for shell in shells.iter_mut() {
        let Some(report) = shell.report.as_ref() else {
            continue;
        };
        if !ready.contains(&report.as_raw_fd()) {
            continue;
        }
        // The read is bounded the way the helper's own was: the only way it
        // can wait at all is a report arriving in pieces, which the child's
        // single 4-byte write cannot produce (see `read_startup_report`),
        // and the helper bounds the whole channel with its own deadline
        // regardless.
        let verdict = read_startup_report(report, Instant::now() + STARTUP_REPORT_TIMEOUT);
        shell.report = None;
        match verdict {
            StartupReport::Started => {
                shell.started = true;
                tell(seam, &MonitorEvent::Started { id: shell.id });
            }
            StartupReport::Failed(errno) => tell(
                seam,
                &MonitorEvent::Failed {
                    id: shell.id,
                    errno: errno as i32,
                },
            ),
            // Nothing on the pipe and no end-of-file either: the read gave
            // up. The shell is left to `reap_shells` (its exit is not
            // reported: `started` is false), and the helper gives up on the
            // channel at its own deadline.
            StartupReport::TimedOut => tell(
                seam,
                &MonitorEvent::Failed {
                    id: shell.id,
                    errno: nix::Error::ETIMEDOUT as i32,
                },
            ),
        }
    }
}

/// Collect every shell that has exited and tell the helper about each.
///
/// `WNOHANG`, and only on pids this process forked itself -- never
/// `waitpid(None, ...)`, which would reap whatever else happened to be a
/// child of this process (the tests run a helper on a thread of a process
/// with children of its own).
#[cfg(any(test, not(target_os = "linux")))]
fn reap_shells(
    seam: &UnixStream,
    shells: &mut Vec<Shell>,
    closing: &mut HashMap<ChannelId, Instant>,
) {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    let mut index = 0;
    while index < shells.len() {
        let shell = &shells[index];
        // A shell whose startup has not been read yet is left alone, even
        // if it has already exited: reaping it here would take its exit
        // before its START has been reported, and the helper would be told
        // a channel ended that it was never told had opened -- which it
        // drops, leaving the `Open` to be refused at its own deadline.
        //
        // Nothing is lost by waiting: the report pipe reaches end-of-file
        // at the `execve` (it is close-on-exec) or at the `_exit` that
        // follows a failure, so it is always ready STRICTLY BEFORE the exit
        // this would have reaped. The next pass therefore reads the report
        // in `report_startups` and reaps here, in that order, with no wait
        // in between.
        if shell.report.is_some() {
            index += 1;
            continue;
        }
        let code = loop {
            match waitpid(shell.pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(_, code)) => break Some(code),
                // A signalled exit is an exit too; reported the way a shell
                // reports one, as 128 plus the signal number.
                Ok(WaitStatus::Signaled(_, signal, _)) => break Some(128 + signal as i32),
                // Still running, or already reaped by something else.
                Ok(_) | Err(nix::Error::ECHILD) => break None,
                Err(nix::Error::EINTR) => continue,
                Err(_) => break None,
            }
        };
        let Some(code) = code else {
            index += 1;
            continue;
        };
        // Retire local callbacks/ownership before publishing the exact proof.
        let shell = shells.remove(index);
        closing.remove(&shell.id);
        // Only for a shell the helper was told had started: one whose start
        // failed has already been answered, and a second answer for one
        // channel id is one more than the protocol allows.
        if shell.started {
            tell(seam, &MonitorEvent::Exited { id: shell.id, code });
        }
        tell(
            seam,
            &MonitorEvent::CleanupComplete {
                id: shell.id,
                kind: super::protocol::CleanupKind::Reaped,
            },
        );
    }
}

/// `SIGKILL` every shell that has not exited within
/// [`CLOSE_GRACE_PERIOD`] of the `SIGHUP` its `Close` sent -- the helper's
/// own escalation, moved here with the fork. Without it a shell that traps
/// the hang-up away (`trap "" HUP`) would never exit, never be reported,
/// and pin whatever is waiting for that channel to end.
#[cfg(not(target_os = "linux"))]
fn escalate(seam: &UnixStream, shells: &[Shell], closing: &mut HashMap<ChannelId, Instant>) {
    let now = Instant::now();
    let mut overdue: Vec<ChannelId> = Vec::new();
    closing.retain(|id, deadline| {
        if !shells.iter().any(|shell| shell.id == *id) {
            // Already gone -- reaped on this pass or an earlier one.
            return false;
        }
        if now < *deadline {
            return true;
        }
        overdue.push(*id);
        false
    });
    for id in overdue {
        if let Some(shell) = shells.iter().find(|shell| shell.id == id) {
            signal_shell(seam, shell, Signal::SIGKILL);
        }
    }
}

/// Send `signal` to one shell, and tell the helper when it could not be
/// delivered.
///
/// `kill(2)` from this root process to a shell running as the account needs
/// `CAP_KILL`, which the packaged unit (spec §8.3) must grant. Without it
/// every signal here fails with `EPERM`, a `SIGHUP`-ignoring shell never
/// dies, and the channel it holds can only be ended by the helper killing
/// this whole monitor -- so the reason has to reach a log, and the only log
/// a monitor can reach is the helper's, through its seam (see this module's
/// docs for why it may not write to the file itself). `ESRCH` -- the shell
/// exited between the lookup and the signal -- is ordinary and says
/// nothing.
#[cfg(any(test, not(target_os = "linux")))]
fn signal_shell(seam: &UnixStream, shell: &Shell, signal: Signal) {
    match nix::sys::signal::kill(shell.pid, signal) {
        Ok(()) | Err(nix::Error::ESRCH) => {}
        Err(errno) => tell(
            seam,
            &MonitorEvent::SignalFailed {
                id: shell.id,
                signal: signal as i32,
                errno: errno as i32,
            },
        ),
    }
}

/// Take every shell down, as the last thing this monitor does: `SIGHUP`,
/// then `SIGKILL` for whatever is still there once the grace has passed.
///
/// Not merely a courtesy to the shells: this process is about to exit, and
/// a shell that outlived it would hold a pseudo-terminal that nothing can
/// close and (from the next task on) a PAM session nothing can end. The
/// parent-death signal every shell arms before its `execve` is the second
/// half of the same promise, for the case where this process is killed
/// outright and never reaches here.
#[cfg(not(target_os = "linux"))]
fn end_the_shells(_seam: &UnixStream, shells: &mut Vec<Shell>, _cleanup: &mut CleanupSummary) {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    // Nothing is reported from here: the seam is what this function runs
    // for the loss of, so there is nobody left to tell. A signal that fails
    // here costs nothing either -- the shells' own parent-death signal ends
    // them when this process exits a moment later.
    for shell in shells.iter() {
        let _ = nix::sys::signal::kill(shell.pid, Signal::SIGHUP);
    }
    let give_up_at = Instant::now() + CLOSE_GRACE_PERIOD;
    while !shells.is_empty() && Instant::now() < give_up_at {
        shells.retain(|shell| {
            !matches!(
                waitpid(shell.pid, Some(WaitPidFlag::WNOHANG)),
                Ok(WaitStatus::Exited(..)) | Ok(WaitStatus::Signaled(..)) | Err(nix::Error::ECHILD)
            )
        });
        if shells.is_empty() {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    for shell in shells.iter() {
        let _ = nix::sys::signal::kill(shell.pid, Signal::SIGKILL);
    }
}

/// Advance Linux startup, leader status and complete cleanup in that order.
#[cfg(target_os = "linux")]
fn report_owned_shells(seam: &UnixStream, shells: &mut Vec<Shell>, cleanup: &mut CleanupSummary) {
    use super::startup::{Failure, Outcome};
    use crate::process_scope::scope::Progress;
    let mut index = 0;
    while index < shells.len() {
        let shell = &mut shells[index];
        let Some(native) = shell.native.as_mut() else {
            // Only legacy unit fixtures omit the native owner. Missing custody
            // can never authorize numeric signalling or a cleanup receipt.
            index += 1;
            continue;
        };
        let update = native.advance(Instant::now());
        match update.startup {
            Some(Outcome::Started) => {
                #[cfg(test)]
                {
                    shell.started = true;
                }
                tell(seam, &MonitorEvent::Started { id: shell.id });
            }
            Some(Outcome::Failed(failure)) => {
                let errno = match failure {
                    Failure::Os(errno) => errno,
                    Failure::Protocol => nix::libc::EPROTO,
                    Failure::TimedOut => nix::libc::ETIMEDOUT,
                    Failure::Cancelled => nix::libc::ECANCELED,
                    Failure::Read => nix::libc::EIO,
                };
                tell(
                    seam,
                    &MonitorEvent::Failed {
                        id: shell.id,
                        errno,
                    },
                );
            }
            None => {}
        }
        if let Some(code) = update.leader {
            tell(seam, &MonitorEvent::Exited { id: shell.id, code });
        }
        if let Some((signal, errno)) = update.signal_failure {
            tell(
                seam,
                &MonitorEvent::SignalFailed {
                    id: shell.id,
                    signal,
                    errno,
                },
            );
        }
        if matches!(update.progress, Progress::Complete(_)) {
            let mut shell = shells.remove(index);
            // Taking the guard is explicit: lexical Shell Drop would run only
            // after publication and could retain the slave beyond its receipt.
            report_terminal_cleanup(
                seam,
                shell.id,
                CleanupKind::Reaped,
                shell.tty.take(),
                cleanup,
            );
        } else {
            index += 1;
        }
    }
}

#[cfg(target_os = "linux")]
fn end_the_shells(seam: &UnixStream, shells: &mut Vec<Shell>, cleanup: &mut CleanupSummary) {
    let now = Instant::now();
    for shell in shells.iter_mut() {
        if let Some(native) = shell.native.as_mut() {
            native.request_stop(now);
        }
    }
    // Grace controls escalation only. Unknown remains owned; PAM close must
    // never run while a shell scope or its private startup stream is retained.
    while !shells.is_empty() {
        report_owned_shells(seam, shells, cleanup);
        if !shells.is_empty() {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Send one event to the helper. Best-effort, like every other line this
/// process says: a monitor whose helper has stopped reading has nowhere to
/// report to, and blocking here would only stop it from serving the shells
/// it already has.
fn tell(seam: &UnixStream, event: &MonitorEvent) {
    if let Ok(bytes) = encode(event) {
        let _ = channel::send(seam, &bytes, None);
    }
}

/// Fork one shell for a channel, on the terminal the helper opened for it,
/// and hand back its pid and the read end of its startup-report pipe.
///
/// Everything the child reads is built HERE, before the fork -- the shell's
/// path and `argv`, the environment, the home directory, the expected group
/// list and the buffer to read the real one into, and the pointer arrays
/// `execve` needs -- because between `fork` and `execve` nothing may
/// allocate (see `server`'s module docs for the full accounting, which this
/// child keeps to unchanged: it is the same code, one process further from
/// the helper). This function itself is the monitor's, not the child's, so
/// it may allocate freely.
///
/// `session_env` is what this login's session stack set
/// (`Session::env`, read by `pam_getenvlist` when the session opened and
/// not once per channel): it is merged into the environment built from
/// passwd, here, before the fork, for exactly the reason above.
struct ForkedShell {
    #[cfg(any(test, not(target_os = "linux")))]
    pid: Pid,
    #[cfg(any(test, not(target_os = "linux")))]
    report: Option<OwnedFd>,
    #[cfg(target_os = "linux")]
    native: native::NativeShell,
}

fn fork_shell(
    plan: &MonitorPlan,
    session_env: &[CString],
    session_groups: &[Gid],
    slave: OwnedFd,
    term: Option<&str>,
    login: bool,
    command: &str,
) -> Result<ForkedShell, nix::Error> {
    use nix::fcntl::OFlag;
    use nix::sys::signal::{self, SigHandler, SigSet, SigmaskHow};
    use nix::unistd::{close, dup2, fork, pipe2, setsid, ForkResult};

    let account = &plan.account;
    let shell = login_shell(account);
    let base = shell_basename(shell);
    let c_shell = CString::new(shell).map_err(|_| PREPARATION_REFUSED)?;
    let c_argv: Vec<CString> = if login {
        let mut argv0 = Vec::with_capacity(1 + base.len());
        argv0.push(b'-');
        argv0.extend_from_slice(base);
        vec![CString::new(argv0).map_err(|_| PREPARATION_REFUSED)?]
    } else {
        vec![
            CString::new(base).map_err(|_| PREPARATION_REFUSED)?,
            CString::new(&b"-c"[..]).expect("a literal with no NUL"),
            CString::new(command).map_err(|_| PREPARATION_REFUSED)?,
        ]
    };
    let c_env = merge_env(
        child_env(account, shell, term).map_err(|_| PREPARATION_REFUSED)?,
        session_env,
    );
    let c_home =
        CString::new(account.home.as_os_str().as_bytes()).map_err(|_| PREPARATION_REFUSED)?;
    let chdir_warning = super::server::chdir_warning_bytes(account.home.as_os_str().as_bytes());
    let mut expected_groups: Vec<Gid> = session_groups.to_vec();
    expected_groups.sort_unstable_by_key(|g| g.as_raw());
    let mut groups_buffer: Vec<Gid> = vec![Gid::from_raw(0); session_groups.len()];
    let argv_ptrs: Vec<*const c_char> = c_argv
        .iter()
        .map(|a| a.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();
    let envp_ptrs: Vec<*const c_char> = c_env
        .iter()
        .map(|e| e.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    #[cfg(target_os = "linux")]
    let view = crate::process_scope::prepare().map_err(|_| nix::Error::EOPNOTSUPP)?;
    let (report_read, report_write) = pipe2(OFlag::O_CLOEXEC)?;
    #[cfg(target_os = "linux")]
    nix::fcntl::fcntl(
        report_read.as_raw_fd(),
        nix::fcntl::FcntlArg::F_SETFL(OFlag::O_NONBLOCK),
    )?;
    #[cfg(target_os = "linux")]
    let startup_deadline = Instant::now() + STARTUP_REPORT_TIMEOUT;
    // Taken BEFORE the fork, so the child can tell a monitor that died in
    // the window between the fork and its own `PR_SET_PDEATHSIG` apart from
    // one still alive -- exactly as `helper::split_and_run` takes the
    // helper's pid before forking the worker.
    let monitor_pid = nix::unistd::getpid();
    let fd_limit = plan.fd_limit;
    let become_account = plan.become_account;
    let uid = account.uid;
    let gid = account.gid;
    let groups = session_groups;

    // SAFETY: this monitor is single-threaded -- it is a child of the
    // single-threaded helper and starts no thread of its own -- so no other
    // thread can have been frozen mid-allocation at the moment of this fork
    // holding a lock the child would deadlock on; and between `fork` and
    // `execve` below NOTHING allocates and every call is async-signal-safe
    // or a bare system-call wrapper, which is the same accounting
    // `server`'s module docs make for the code this is.
    match unsafe { fork() }? {
        ForkResult::Parent { child } => {
            #[cfg(target_os = "linux")]
            let native = native::NativeShell::new(
                std::num::NonZeroU32::new(child.as_raw() as u32)
                    .expect("fork returns a positive child PID"),
                view,
                report_read,
                startup_deadline,
            );
            drop(slave);
            // Our own copy of the write end has to close BEFORE anything
            // reads the pipe, or it never reaches end-of-file even once the
            // child's copy is gone.
            drop(report_write);
            Ok(ForkedShell {
                #[cfg(any(test, not(target_os = "linux")))]
                pid: child,
                #[cfg(not(target_os = "linux"))]
                report: Some(report_read),
                #[cfg(all(test, target_os = "linux"))]
                report: None,
                #[cfg(target_os = "linux")]
                native,
            })
        }
        ForkResult::Child => {
            #[cfg(target_os = "linux")]
            fn record(report: BorrowedFd<'_>, tag: u8, payload: i32) {
                let mut frame = [0u8; 5];
                frame[0] = tag;
                frame[1..].copy_from_slice(&payload.to_ne_bytes());
                loop {
                    match nix::unistd::write(report, &frame) {
                        Ok(5) => return,
                        Err(nix::Error::EINTR) => continue,
                        // A partial/failed stage never proceeds to exec or any
                        // descendant-producing code. No allocation after fork.
                        _ => unsafe { nix::libc::_exit(127) },
                    }
                }
            }
            fn fail<T>(report_write: BorrowedFd<'_>, e: nix::Error) -> T {
                #[cfg(target_os = "linux")]
                record(report_write, 2, e as i32);
                #[cfg(not(target_os = "linux"))]
                let _ = nix::unistd::write(report_write, &(e as i32).to_ne_bytes());
                // SAFETY: `_exit` ends the process immediately, running no
                // atexit handlers and no Rust `Drop` impls -- sound to call
                // from anywhere, including here where returning to the
                // caller is exactly what must not happen.
                unsafe { nix::libc::_exit(127) }
            }

            let report_write = report_write.as_fd();
            let slave = slave.as_raw_fd();
            let sid = setsid().unwrap_or_else(|e| fail(report_write, e));
            #[cfg(target_os = "linux")]
            record(report_write, 1, sid.as_raw());
            #[cfg(not(target_os = "linux"))]
            let _ = sid;
            // Without this every program started here would inherit the
            // ignored `SIGPIPE` Rust's runtime sets, and whatever mask the
            // helper happened to have -- see `server::open_channel`'s docs.
            for sig in [
                Signal::SIGCHLD,
                Signal::SIGHUP,
                Signal::SIGINT,
                Signal::SIGQUIT,
                Signal::SIGTERM,
                Signal::SIGALRM,
                Signal::SIGPIPE,
            ] {
                // SAFETY: `signal` is on POSIX's async-signal-safe list.
                // `SigHandler::SigDfl` installs the kernel's own default
                // disposition, not a function pointer supplied by this
                // process, so there is nothing here for a signal arriving
                // mid-call to unsafely reenter.
                unsafe { signal::signal(sig, SigHandler::SigDfl) }
                    .unwrap_or_else(|e| fail(report_write, e));
            }
            signal::sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)
                .unwrap_or_else(|e| fail(report_write, e));
            // SAFETY: a plain ioctl on `slave`, a descriptor this process
            // owns, with a constant `0` as the third argument rather than a
            // pointer the kernel could misuse.
            if unsafe { nix::libc::ioctl(slave, nix::libc::TIOCSCTTY as _, 0) } < 0 {
                fail::<()>(report_write, nix::Error::last());
            }
            for target in [0, 1, 2] {
                dup2(slave, target).unwrap_or_else(|e| fail(report_write, e));
            }
            if slave > 2 {
                let _ = close(slave);
            }
            // And everything else this child inherited, close-on-exec or
            // not -- the monitor's seam above all, which is a socket to the
            // ROOT helper. After the `dup2`s, so the three standard
            // descriptors are already this terminal's; before the drop, so
            // nothing of root's is still open by the time this process is
            // anything but root.
            close_other_descriptors(report_write.as_raw_fd(), fd_limit);

            become_account(uid, gid, groups).unwrap_or_else(|e| fail(report_write, e));
            become_account_checks(uid, gid, &expected_groups, &mut groups_buffer)
                .unwrap_or_else(|e| fail(report_write, e));

            // `become_account` just changed the effective uid and gid, and
            // `prctl(2)` clears the parent-death signal on exactly that.
            // Re-armed here, after the drop, so a monitor that dies takes
            // its shells with it instead of leaving them running with a PAM
            // session nobody is left to close -- nothing else would, since
            // the `setsid` above already left the monitor's session.
            // Preserved across the `execve` below, which is an ordinary
            // non-setuid shell (`prctl(2)` again); an account whose login
            // shell is itself set-user-ID loses it there, and has larger
            // problems than this.
            //
            // The raw `prctl`, not `helper::arm_and_verify_pdeathsig`: this
            // is between fork and exec, where nothing may allocate, and a
            // failure is reported through the startup pipe rather than
            // returned.
            // SAFETY: two integers by value; `prctl` touches nothing in this
            // address space.
            if unsafe { nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) } != 0 {
                fail::<()>(report_write, nix::Error::last());
            }
            // And the monitor must still BE the parent: one that died in
            // the window between the fork above and the arming just now
            // would have left this child reparented, with a parent-death
            // signal that can never fire. NOT pinned by a test -- that
            // window is a few instructions wide and not reachable on demand
            // -- so this is reasoning, not coverage: treat it as
            // load-bearing when you edit it.
            if nix::unistd::getppid() != monitor_pid {
                fail::<()>(report_write, nix::Error::ESRCH);
            }

            // AFTER the drop, so the account's own permissions decide
            // whether it may enter its home -- as `sshd` does.
            // SAFETY: `chdir` with two live, NUL-terminated strings:
            // `c_home`, built before the fork, and a literal.
            if unsafe { nix::libc::chdir(c_home.as_ptr()) } != 0 {
                // Best-effort, to fd 2 (the terminal, dup2'd above).
                // SAFETY: fd 2 is open (dup2'd from the slave).
                let _ = nix::unistd::write(unsafe { BorrowedFd::borrow_raw(2) }, &chdir_warning);
                if unsafe { nix::libc::chdir(c"/".as_ptr()) } != 0 {
                    fail::<()>(report_write, nix::Error::last());
                }
            }

            // One `execve`, of the account's shell. It returns only on
            // failure.
            // SAFETY: `c_shell`, `argv_ptrs` and `envp_ptrs` point into
            // `CString`s built before the fork and still alive in this stack
            // frame; both arrays are NUL-terminated.
            unsafe {
                nix::libc::execve(c_shell.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
            }
            fail(report_write, nix::Error::last())
        }
    }
}

#[cfg(test)]
mod tests {
    include!("session_cleanup_tests.rs");
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn refusal406_consumed_requests_get_exact_nochild_before_completion() {
        crate::test_borrowed_scope::run_exact(
            "helper::monitor::tests::refusal406_consumed_requests_get_exact_nochild_before_completion", 0, || {
                use std::os::fd::AsFd;
                let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
                {
                    let (helper, monitor) = super::super::worker_control::pair().unwrap();
                    let file = tempfile::tempfile().unwrap();
                    for id in 2..=16 {
                        channel::send(&helper, &encode(&MonitorRequest::Open { id, term: None,
                            shell: false, command: "never executed".into() }).unwrap(), Some(file.as_fd())).unwrap();
                        channel::send(&helper, &encode(&MonitorRequest::Close { id }).unwrap(), None).unwrap();
                    }
                    channel::send(&helper, &encode(&MonitorRequest::SealRefused).unwrap(), None).unwrap();
                    let summary = CleanupSummary::default();
                    assert_eq!(refused_requests(&monitor, Pid::this(), 1, "denied".into(), &summary,
                        Instant::now() + Duration::from_secs(1)), Ok(()));
                    helper.set_nonblocking(true).unwrap();
                    let mut nochild = Vec::new();
                    let mut refused = Vec::new();
                    let mut closed = false;
                    while let Ok(Some((bytes, fd))) = channel::recv_once(&helper) {
                        assert!(fd.is_none() && !closed);
                        match decode::<MonitorEvent>(&bytes).unwrap() {
                            MonitorEvent::Refused { id, .. } => refused.push(id),
                            MonitorEvent::CleanupComplete { id, kind: CleanupKind::NoChild } => nochild.push(id),
                            MonitorEvent::SessionClosed { request_failure: None, result: PamCompletion::NotOpened, cleanup_failure: None } => closed = true,
                            other => panic!("unexpected terminal outcome {other:?}"),
                        }
                    }
                    assert!(closed);
                    assert_eq!(nochild, (1..=16).collect::<Vec<_>>());
                    assert_eq!(refused, nochild);
                }
                assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
            },
        ).assert_clean(0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refusal406_invalid_barriers_preserve_pam_without_blanket_receipts() {
        crate::test_borrowed_scope::run_exact(
            "helper::monitor::tests::refusal406_invalid_barriers_preserve_pam_without_blanket_receipts", 0, || {
                use std::os::fd::AsFd;
                use super::super::protocol::RequestDrainFailure as Fault;
                use super::super::pam_completion::PamStep;
                let before = std::fs::read_dir("/proc/self/fd").unwrap().count();
                for mode in ["marker-fd", "zero", "duplicate", "missing-fd", "wrong-sender", "extra-fd", "truncated", "wrong-close", "eof", "excess"] {
                    let (helper, monitor) = super::super::worker_control::pair().unwrap();
                    let file = tempfile::tempfile().unwrap();
                    let open = |id| encode(&MonitorRequest::Open { id, term: None, shell: false, command: "never".into() }).unwrap();
                    match mode {
                        "marker-fd" => channel::send(&helper, &encode(&MonitorRequest::SealRefused).unwrap(), Some(file.as_fd())).unwrap(),
                        "zero" => channel::send(&helper, b"", None).unwrap(),
                        "duplicate" => channel::send(&helper, &open(1), Some(file.as_fd())).unwrap(),
                        "missing-fd" => channel::send(&helper, &open(2), None).unwrap(),
                        "wrong-sender" => channel::send(&helper, &open(2), Some(file.as_fd())).unwrap(),
                        "extra-fd" => {
                            let raw = file.as_raw_fd();
                            nix::sys::socket::sendmsg::<()>(helper.as_raw_fd(), &[std::io::IoSlice::new(&open(2))],
                                &[nix::sys::socket::ControlMessage::ScmRights(&[raw, raw])],
                                nix::sys::socket::MsgFlags::empty(), None).unwrap();
                        },
                        "truncated" => channel::send(&helper, &vec![b'x'; super::super::protocol::MAX_MESSAGE_LEN+1], None).unwrap(),
                        "wrong-close" => channel::send(&helper, &encode(&MonitorRequest::Close { id:999 }).unwrap(), None).unwrap(),
                        "eof" => helper.shutdown(std::net::Shutdown::Write).unwrap(),
                        "excess" => for id in 2..=17 { channel::send(&helper, &open(id), Some(file.as_fd())).unwrap(); },
                        _ => unreachable!(),
                    }
                    let pam = PamCompletion::Finished { close_session: PamStep::Skipped,
                        delete_cred: PamStep::Skipped, end: PamStep::Attempted(7) };
                    let summary = CleanupSummary { pam, failure: Some(CleanupFailure::PtyLabelRestore { errno: 13 }), terminal: None, request_failure: None };
                    let expected_pid = if mode == "wrong-sender" { Pid::from_raw(1) } else { Pid::this() };
                    assert_eq!(refused_requests(&monitor, expected_pid, 1, "denied".into(), &summary,
                        Instant::now() + Duration::from_secs(1)), Err(Fault::Protocol));
                    helper.set_nonblocking(true).unwrap();
                    let mut ids = Vec::new();
                    let mut final_seen = false;
                    while let Ok(Some((bytes, fd))) = channel::recv_once(&helper) {
                        assert!(fd.is_none());
                        match decode::<MonitorEvent>(&bytes).unwrap() {
                            MonitorEvent::CleanupComplete { id, .. } => ids.push(id),
                            MonitorEvent::SessionClosed { request_failure: Some(Fault::Protocol), result, cleanup_failure } => {
                                assert_eq!(result, pam); assert_eq!(cleanup_failure, summary.failure); final_seen = true;
                            },
                            _ => {},
                        }
                    }
                    assert!(final_seen);
                    assert!(!ids.contains(&17));
                    if mode != "excess" { assert_eq!(ids, vec![1]); }
                }
                assert_eq!(std::fs::read_dir("/proc/self/fd").unwrap().count(), before);
            },
        ).assert_clean(0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn refusal406_absolute_deadline_and_send_failure_never_complete_cleanly() {
        crate::test_borrowed_scope::run_exact(
            "helper::monitor::tests::refusal406_absolute_deadline_and_send_failure_never_complete_cleanly", 0, || {
                use super::super::protocol::RequestDrainFailure as Fault;
                let (helper, monitor) = super::super::worker_control::pair().unwrap();
                let summary = CleanupSummary::default();
                assert_eq!(refused_requests(&monitor, Pid::this(), 1, "denied".into(), &summary,
                    Instant::now()), Err(Fault::Deadline));
                helper.set_nonblocking(true).unwrap();
                assert!(matches!(channel::recv_once(&helper), Err(error) if error.kind()==std::io::ErrorKind::WouldBlock));
                assert_eq!(refused_requests(&monitor, Pid::this(), 1, "denied".into(), &summary,
                    Instant::now()+Duration::from_millis(20)), Err(Fault::Deadline));
                while let Ok(Some((bytes, _))) = channel::recv_once(&helper) {
                    assert!(!matches!(decode::<MonitorEvent>(&bytes).unwrap(), MonitorEvent::SessionClosed { request_failure: None, .. }));
                }
                helper.shutdown(std::net::Shutdown::Read).unwrap();
                assert_eq!(refused_requests(&monitor, Pid::this(), 1, "denied".into(), &summary,
                    Instant::now()+Duration::from_secs(1)), Err(Fault::Send));
            },
        ).assert_clean(0);
    }

    #[test]
    fn refusal406_unexpected_marker_is_typed_failure_without_pam_or_fork() {
        let (helper, monitor) = channel::pair().unwrap();
        channel::send(
            &helper,
            &encode(&MonitorRequest::SealRefused).unwrap(),
            None,
        )
        .unwrap();
        let directory = tempfile::tempdir().unwrap();
        let account = super::super::account::lookup(&current_account_name()).unwrap();
        let plan = MonitorPlan {
            #[cfg(target_os = "linux")]
            child_mask: None,
            account,
            login: [6; 16],
            tty: String::new(),
            rhost: String::new(),
            pam_service: "must-not-open".into(),
            pam_confdir: Some(directory.path().to_path_buf()),
            become_account: |_, _, _| panic!("unexpected marker must not fork"),
            session_group_ops: SessionGroupOps {
                install: |_| panic!("unexpected marker must not enter PAM"),
                capture: || panic!("unexpected marker must not enter PAM"),
            },
            fd_limit: 0,
            session_budget: Duration::from_secs(1),
            session_close_budget: Duration::from_secs(1),
        };
        let mut summary = CleanupSummary::default();
        let mut shells = Vec::new();
        let mut session = None;
        let mut closing = HashMap::new();
        assert!(!serve_request(
            &plan,
            &monitor,
            &mut shells,
            &mut session,
            &mut summary,
            &mut closing,
            Pid::this()
        ));
        assert_eq!(
            summary.request_failure,
            Some(super::super::protocol::RequestDrainFailure::Protocol)
        );
        assert!(shells.is_empty() && session.is_none());
        assert_eq!(summary.pam, PamCompletion::NotOpened);
    }

    fn current_account_name() -> String {
        nix::unistd::User::from_uid(Uid::current())
            .expect("passwd")
            .expect("account")
            .name
    }

    #[test]
    fn bounded_group_capture_rejects_invalid_limit_and_count() {
        use nix::errno::Errno::EINVAL;
        let mut limits = vec![-1, 0];
        if let Some(excessive) = (nix::libc::c_int::MAX as nix::libc::c_long).checked_add(1) {
            limits.push(excessive);
        }
        for limit in limits {
            assert_eq!(
                capture_groups_with(
                    limit,
                    |_| panic!("invalid limit must not query"),
                    allocate_groups
                ),
                Err(EINVAL)
            );
        }
        for count in [-1, 5, i64::MAX] {
            assert_eq!(
                capture_groups_with(4, |_| Ok(count), allocate_groups),
                Err(EINVAL)
            );
        }
        assert_eq!(
            capture_groups_with(4, |_| Err(nix::errno::Errno::EIO), allocate_groups),
            Err(nix::errno::Errno::EIO)
        );
    }

    #[test]
    fn bounded_group_capture_rejects_second_read_failure_or_count_change() {
        use nix::errno::Errno::{EINVAL, EIO};
        for result in [Err(EIO), Ok(0), Ok(2)] {
            let mut reads = 0;
            assert_eq!(
                capture_groups_with(
                    4,
                    |_| {
                        reads += 1;
                        if reads == 1 {
                            Ok(1)
                        } else {
                            result
                        }
                    },
                    allocate_groups
                ),
                Err(if result.is_err() { EIO } else { EINVAL })
            );
            assert_eq!(reads, 2, "no unbounded retry");
        }
    }

    #[test]
    fn bounded_group_capture_maps_allocation_failure_and_preserves_empty() {
        use nix::errno::Errno::ENOMEM;
        assert_eq!(
            capture_groups_with(4, |_| Ok(1), |_| Err(ENOMEM)),
            Err(ENOMEM)
        );
        assert_eq!(allocate_groups(usize::MAX), Err(ENOMEM));
        assert_eq!(
            capture_groups_with(4, |_| Ok(0), allocate_groups),
            Ok(vec![])
        );
        let mut reads = 0;
        assert_eq!(
            capture_groups_with(
                4,
                |out| {
                    reads += 1;
                    if reads == 2 {
                        out.copy_from_slice(&[Gid::from_raw(0), Gid::from_raw(42)]);
                    }
                    Ok(2)
                },
                allocate_groups
            ),
            Ok(vec![Gid::from_raw(0), Gid::from_raw(42)])
        );
        assert_eq!(capture_supplementary_groups(), nix::unistd::getgroups());
    }

    fn remote_transaction(
        dir: &std::path::Path,
        service: &str,
        user: &str,
        tty: &str,
        rhost: &str,
    ) -> Result<Pam, PamError> {
        let account = super::super::account::lookup(user).expect("existing test account");
        start_transaction(&MonitorPlan {
            #[cfg(target_os = "linux")]
            child_mask: None,
            account,
            login: [7; 16],
            tty: tty.into(),
            rhost: rhost.into(),
            pam_service: service.into(),
            pam_confdir: Some(dir.to_path_buf()),
            become_account: |_, _, _| Ok(()),
            session_group_ops: SessionGroupOps::REAL,
            fd_limit: 0,
            session_budget: Duration::from_secs(1),
            session_close_budget: Duration::from_secs(1),
        })
        .map_err(|failure| failure.error)
    }

    /// Capture the actual module environment, including IPv6 scope removal.
    #[test]
    fn pam_rhost_is_the_numeric_ip_without_the_endpoint_port() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::monitor::tests::pam_rhost_is_the_numeric_ip_without_the_endpoint_port_body",
        );
        assert!(status.success(), "{status}:\n{stdout}\n{stderr}");
    }

    #[test]
    #[ignore = "runs only via pam_rhost_is_the_numeric_ip_without_the_endpoint_port"]
    fn pam_rhost_is_the_numeric_ip_without_the_endpoint_port_body() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = tempfile::tempdir().expect("tempdir");
        let seen = dir.path().join("seen");
        let script = dir.path().join("record.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s\\n' \"$PAM_RHOST\" >> {}\n",
                seen.display()
            ),
        )
        .expect("write capture script");
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
        std::fs::write(
            dir.path().join("qshd-test-rhost"),
            format!("account required pam_exec.so {}\n", script.display()),
        )
        .expect("write stack");
        // Synthetic PAM-boundary inputs, not a dual-stack listener reproduction.
        let cases = [
            ("203.0.113.7:2222", "203.0.113.7"),
            ("[2001:db8::7]:2222", "2001:db8::7"),
            ("[fe80::7%3]:2222", "fe80::7"),
            ("203.0.113.7", "203.0.113.7"),
            ("2001:db8::7", "2001:db8::7"),
            ("::ffff:203.0.113.7", "203.0.113.7"),
            ("[::ffff:203.0.113.7]:2222", "203.0.113.7"),
            ("0:0:0:0:0:ffff:cb00:7107", "203.0.113.7"),
            ("[::ffff:cb00:7107]:65535", "203.0.113.7"),
            ("::203.0.113.7", "::cb00:7107"),
            ("[::cb00:7107]:2222", "::cb00:7107"),
            ("::", "::"),
            ("[::1]:2222", "::1"),
            ("64:ff9b::cb00:7107", "64:ff9b::cb00:7107"),
        ];
        for (endpoint, _) in cases {
            let mut pam = remote_transaction(
                dir.path(),
                "qshd-test-rhost",
                &current_account_name(),
                "/dev/pts/7",
                endpoint,
            )
            .expect("start");
            pam.acct_mgmt().expect("capture module");
        }
        assert_eq!(
            std::fs::read_to_string(seen).expect("capture"),
            cases
                .iter()
                .map(|(_, expected)| format!("{expected}\n"))
                .collect::<String>()
        );
    }

    /// Linux-PAM 1.5.3 resolves CIDR network tokens with NULL getaddrinfo
    /// hints. glibc implicitly applies AI_ADDRCONFIG there, so even numeric
    /// IPv6 needs a configured address other than ::1. Probe that real call.
    fn pam_access_can_resolve_ipv6() -> bool {
        let network = CString::new("2001:db8:1::").expect("numeric network");
        let mut addresses = std::ptr::null_mut();
        // SAFETY: the input is terminated, output points to a live local,
        // and any returned list is released with the matching libc function.
        let result = unsafe {
            nix::libc::getaddrinfo(
                network.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                &mut addresses,
            )
        };
        if !addresses.is_null() {
            unsafe { nix::libc::freeaddrinfo(addresses) };
        }
        result == 0
    }

    /// Only constructed after this fixture successfully added its address.
    /// A preexisting address is never owned or removed by the fixture.
    struct DisposableIpv6Address {
        socket: OwnedFd,
        request: Ipv6AddressRequest,
    }

    // Linux's `struct in6_ifreq`, used by SIOCSIFADDR/SIOCDIFADDR.
    #[repr(C)]
    struct Ipv6AddressRequest {
        address: nix::libc::in6_addr,
        prefix_len: u32,
        interface_index: nix::libc::c_int,
    }

    impl DisposableIpv6Address {
        fn add() -> Self {
            use std::os::fd::FromRawFd as _;
            assert!(
                Uid::effective().is_root()
                    && std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref() == Ok("1"),
                "IPv6 setup is restricted to an explicitly disposable root container"
            );
            // SAFETY: socket returns an owned descriptor or -1; it is
            // adopted exactly once, only after checking the result.
            let fd = unsafe {
                nix::libc::socket(
                    nix::libc::AF_INET6,
                    nix::libc::SOCK_DGRAM | nix::libc::SOCK_CLOEXEC,
                    0,
                )
            };
            assert!(fd >= 0, "IPv6 socket: {}", std::io::Error::last_os_error());
            let socket = unsafe { OwnedFd::from_raw_fd(fd) };
            let interface = CString::new("lo").expect("interface name");
            let index = unsafe { nix::libc::if_nametoindex(interface.as_ptr()) };
            assert_ne!(index, 0, "the disposable namespace must have loopback");
            let request = Ipv6AddressRequest {
                address: nix::libc::in6_addr {
                    s6_addr: "2001:db8::42"
                        .parse::<std::net::Ipv6Addr>()
                        .expect("fixture IP")
                        .octets(),
                },
                prefix_len: 128,
                interface_index: index as nix::libc::c_int,
            };
            // SAFETY: request has Linux in6_ifreq's layout and remains live
            // throughout the ioctl. This socket belongs to this namespace.
            let result =
                unsafe { nix::libc::ioctl(socket.as_raw_fd(), nix::libc::SIOCSIFADDR, &request) };
            assert_eq!(
                result,
                0,
                "add disposable IPv6 address (requires container NET_ADMIN): {}",
                std::io::Error::last_os_error()
            );
            Self { socket, request }
        }
    }

    impl Drop for DisposableIpv6Address {
        fn drop(&mut self) {
            // SAFETY: this is the exact request that succeeded in add(),
            // and the descriptor and request are still owned by this guard.
            let result = unsafe {
                nix::libc::ioctl(
                    self.socket.as_raw_fd(),
                    nix::libc::SIOCDIFADDR,
                    &self.request,
                )
            };
            assert_eq!(
                result,
                0,
                "remove fixture-owned IPv6 address: {}",
                std::io::Error::last_os_error()
            );
        }
    }

    fn assert_pam_access_cidr_family(family: &str) {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated_with_env(
            "helper::monitor::tests::pam_access_matches_source_cidrs_with_explicit_fallbacks_body",
            &[("QSHD_TEST_PAM_ACCESS_FAMILY", std::ffi::OsStr::new(family))],
        );
        assert!(status.success(), "{status}:\n{stdout}\n{stderr}");
    }

    /// Both CIDR matches and their opposite fallbacks matter: a broken
    /// origin can deny an allowed peer OR admit a denied peer.
    #[test]
    fn pam_access_matches_ipv4_source_cidrs_with_explicit_fallbacks() {
        assert_pam_access_cidr_family("ipv4");
    }

    #[test]
    fn pam_access_matches_ipv6_source_cidrs_with_explicit_fallbacks() {
        let _address = if pam_access_can_resolve_ipv6() {
            None
        } else if Uid::effective().is_root()
            && std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref() == Ok("1")
        {
            Some(DisposableIpv6Address::add())
        } else {
            eprintln!(
                "SKIPPED pam_access_matches_ipv6_source_cidrs_with_explicit_fallbacks: \
                Linux-PAM's AI_ADDRCONFIG requires a configured IPv6 address other than ::1; \
                CI runs this test in an explicitly disposable root container with NET_ADMIN"
            );
            return;
        };
        assert_pam_access_cidr_family("ipv6");
    }

    #[test]
    #[ignore = "runs only via the pam_access IPv4 and IPv6 CIDR wrappers"]
    fn pam_access_matches_source_cidrs_with_explicit_fallbacks_body() {
        let family =
            std::env::var("QSHD_TEST_PAM_ACCESS_FAMILY").expect("family selected by wrapper");
        let (cidr, matching, outside) = match family.as_str() {
            "ipv4" => ("203.0.113.0/24", "203.0.113.7:2222", "198.51.100.7:2222"),
            "ipv6" => (
                "2001:db8:1::/48",
                "[2001:db8:1::7]:2222",
                "[2001:db8:2::7]:2222",
            ),
            other => panic!("unexpected CIDR fixture family: {other}"),
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let access = dir.path().join("access.conf");
        std::fs::write(
            dir.path().join("qshd-test-access"),
            format!(
                "account required pam_access.so nodefgroup noaudit accessfile={}\n",
                access.display()
            ),
        )
        .expect("write stack");
        let me = current_account_name();
        let mut results = Vec::new();
        for (rule, fallback, expected) in [("+", "-", true), ("-", "+", false)] {
            std::fs::write(&access, format!("{rule}:ALL:{cidr}\n{fallback}:ALL:ALL\n"))
                .expect("write access policy");
            // Exercise synthetic PAM-boundary representations of the same IPv4
            // peers; current production listeners do not establish dual-stack reachability.
            let mut endpoints = vec![(matching, expected), (outside, !expected)];
            if family == "ipv4" {
                endpoints.extend([
                    ("::ffff:203.0.113.7", expected),
                    ("[::ffff:203.0.113.7]:2222", expected),
                    ("[::ffff:cb00:7107]:65535", expected),
                    ("::ffff:198.51.100.7", !expected),
                    ("[::ffff:198.51.100.7]:2222", !expected),
                    ("[::ffff:c633:6407]:65535", !expected),
                ]);
            }
            for (endpoint, allowed) in endpoints {
                let mut pam =
                    remote_transaction(dir.path(), "qshd-test-access", &me, "/dev/pts/7", endpoint)
                        .expect("start");
                results.push((cidr, rule, endpoint, pam.acct_mgmt().is_ok(), allowed));
            }
        }
        assert!(
            results
                .iter()
                .all(|(_, _, _, actual, expected)| actual == expected),
            "CIDR verdicts (cidr, rule, endpoint, actual, expected): {results:?}"
        );
    }

    #[test]
    fn invalid_pam_origins_are_refused_before_starting_the_stack() {
        // No stack exists: the argument error must precede pam_start_confdir.
        let dir = tempfile::tempdir().expect("tempdir");
        for origin in [
            "",
            "localhost",
            "host.example:22",
            "not-an-ip",
            "203.0.113.7:bad",
            "[2001:db8::7]",
            "203.0.113.7\n",
            "[fe80::7%eth0]:22",
        ] {
            let error = remote_transaction(
                dir.path(),
                "qshd-test-absent",
                &current_account_name(),
                "/dev/pts/7",
                origin,
            )
            .expect_err("invalid remote must never become local");
            assert_eq!(
                (error.code, error.what),
                (
                    super::super::pam::PAM_SYSTEM_ERR,
                    "the client address is not a numeric IP or endpoint"
                ),
                "origin {origin:?}"
            );
        }
    }

    /// How long a test here waits on a seam for a message a monitor may or
    /// may not have sent. Both waits below are bounded by it, the opposite
    /// ways round: one wants a message and must fail rather than hang if
    /// the code stops sending it, the other wants silence and pays this in
    /// full. Short is safe for both -- `signal_shell` returns before either
    /// wait starts, so anything it sent is already in the socket's buffer.
    const SEAM_READ_TIMEOUT: Duration = Duration::from_millis(200);

    /// The two caps this module argues for are the numbers it uses --
    /// pinned here, beside the constants, and in one line each.
    ///
    /// Both are pinned elsewhere too, and deliberately again here. The
    /// value of [`MAX_NOTES`] is checked inside
    /// `server::tests::a_login_leaves_at_most_max_notes_lines_in_the_log_body`,
    /// which is the test that shows the cap is APPLIED -- but that one
    /// lives in an `#[ignore]` body behind a fork, a `pam_exec` stack and a
    /// log read, and a pin that depends on its scaffolding is a pin that
    /// leaves when the scaffolding does. `super::super::pam`'s
    /// `what_a_transaction_keeps_covers_what_its_readers_take` reaches both
    /// numbers too, but only while that module's own caps stay coupled to
    /// these. Neither dependency is a reason not to spend a line where the
    /// constant is.
    ///
    /// The VALUE is the property in both cases: `MAX_NOTES`'s docs rest the
    /// whole case for letting a login write to a root process's log on "a
    /// handful of lines", and `MAX_REFUSAL_DETAIL`'s on a refusal's reason
    /// staying far inside `protocol::MAX_MESSAGE_LEN`. Every other test of
    /// either scales with the constant and would pass at any value.
    #[test]
    fn the_caps_this_module_argues_for_are_the_numbers_it_uses() {
        assert_eq!(
            MAX_NOTES, 8,
            "see the constant's own docs: a handful of lines is the whole \
             justification for letting a login's stack write to a root process's log"
        );
        assert_eq!(
            MAX_REFUSAL_DETAIL, 512,
            "see the constant's own docs: generous next to anything a module says, and far \
             inside protocol::MAX_MESSAGE_LEN"
        );
    }

    /// A signal a monitor cannot deliver is reported to the helper, with
    /// the `errno` that says why -- never swallowed.
    ///
    /// The `EPERM` is a real one, and needs no root to come by: an
    /// unprivileged process signalling process 1 gets exactly it, which is
    /// also what a service unit that stopped granting `CAP_KILL` (spec
    /// §8.3) looks like from inside a monitor. The test is therefore
    /// skipped when it runs AS root -- there the signal would be delivered,
    /// to init.
    ///
    /// Nothing is signalled that this process owns: the point is the
    /// failure, and the only pid guaranteed to refuse an ordinary user is
    /// the one process no user may signal.
    ///
    /// The other half of this path -- the helper turning the event into the
    /// line it used to write itself -- is
    /// `server::tests::an_undeliverable_signal_reaches_the_helpers_log`.
    #[test]
    fn an_undeliverable_signal_is_reported_to_the_helper() {
        if Uid::effective().is_root() {
            eprintln!(
                "SKIPPED an_undeliverable_signal_is_reported_to_the_helper: as root the signal \
                 below would be DELIVERED, to process 1"
            );
            return;
        }
        let (helper_end, monitor_end) = channel::pair().expect("socketpair");
        // Bounded, because the failure this test is watching for is SILENCE:
        // an unbounded read would hang the whole suite where it should fail
        // this one test.
        helper_end
            .set_read_timeout(Some(SEAM_READ_TIMEOUT))
            .expect("bounded read");
        let init = Shell {
            #[cfg(target_os = "linux")]
            native: None,
            #[cfg(target_os = "linux")]
            tty: None,
            id: 4,
            pid: Pid::from_raw(1),
            report: None,
            started: true,
        };

        signal_shell(&monitor_end, &init, Signal::SIGKILL);

        let heard = channel::recv(&helper_end);
        let Ok(Some((bytes, _fd))) = heard else {
            panic!(
                "a monitor that could not deliver a signal must say so, not swallow it -- a \
                 shell that then never dies is a channel that never ends, with nothing anywhere \
                 to say why; got {heard:?}"
            );
        };
        let event: MonitorEvent = decode(&bytes).expect("decoding the monitor's event");
        assert_eq!(
            event,
            MonitorEvent::SignalFailed {
                id: 4,
                signal: Signal::SIGKILL as i32,
                errno: nix::Error::EPERM as i32,
            },
            "the channel, the signal and the reason must all reach the helper: without the \
             reason a shell that never dies is a channel that never ends, with nothing anywhere \
             to say why"
        );
    }

    /// The other side of the same rule: `ESRCH` -- the shell exited between
    /// the lookup and the signal -- is ordinary, and says nothing.
    ///
    /// Without this, a monitor would report a failure per shell on every
    /// ordinary close it lost the race with, and the helper's log would
    /// fill with lines about a `CAP_KILL` that is not missing at all.
    #[test]
    fn a_signal_to_a_shell_that_already_exited_is_not_reported() {
        let (helper_end, monitor_end) = channel::pair().expect("socketpair");
        helper_end
            .set_read_timeout(Some(SEAM_READ_TIMEOUT))
            .expect("bounded read");
        // A pid above any this kernel hands out, so `kill` refuses it with
        // `ESRCH` and not with the `EPERM` that would stand in for it --
        // asserted below, because a pid that turned out to be somebody's
        // would make this test signal a stranger.
        let gone = Pid::from_raw(i32::MAX);
        let shell = Shell {
            #[cfg(target_os = "linux")]
            native: None,
            #[cfg(target_os = "linux")]
            tty: None,
            id: 5,
            pid: gone,
            report: None,
            started: true,
        };
        assert_eq!(
            nix::sys::signal::kill(gone, None),
            Err(nix::Error::ESRCH),
            "setup: this pid must be nobody's, or the signal below would be delivered"
        );

        signal_shell(&monitor_end, &shell, Signal::SIGHUP);

        let heard = channel::recv(&helper_end);
        // Decoded for the message: a seam carries bytes, and forty of them
        // spelled out as numbers is not a diagnosis.
        let said = match &heard {
            Ok(Some((bytes, _fd))) => format!("{:?}", decode::<MonitorEvent>(bytes)),
            other => format!("{other:?}"),
        };
        assert!(
            matches!(&heard, Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "a shell that exited before its signal is ordinary and must say nothing, got {said}"
        );
    }

    /// What the session stack sets goes ON TOP of what passwd gave: a name
    /// both sides carry is the session's, a name only the session carries
    /// is added, and neither can appear twice.
    ///
    /// The duplicate is the point. `execve` takes the array as it is, and
    /// `getenv` answers with the FIRST match -- so an environment carrying
    /// two `PATH`s would keep whichever came first, which is passwd's, and
    /// a `pam_env` that set `PATH` would be silently ignored while looking
    /// perfectly present in `env`.
    #[test]
    fn the_session_stacks_environment_goes_on_top_of_the_one_from_passwd() {
        let passwd = ["HOME=/home/a", "PATH=/from-passwd", "TERM=xterm"]
            .iter()
            .map(|e| CString::new(*e).expect("no NUL"))
            .collect();
        let session = ["PATH=/from-the-stack", "XDG_SESSION_ID=7"]
            .iter()
            .map(|e| CString::new(*e).expect("no NUL"))
            .collect::<Vec<_>>();

        let merged: Vec<String> = merge_env(passwd, &session)
            .iter()
            .map(|e| e.to_string_lossy().into_owned())
            .collect();

        assert_eq!(
            merged,
            [
                "HOME=/home/a",
                "PATH=/from-the-stack",
                "TERM=xterm",
                "XDG_SESSION_ID=7"
            ],
            "the session's value must replace passwd's in place, and its own names be added"
        );
    }

    /// A name with no `=` at all -- which `pam_getenvlist` does not
    /// produce, and which must therefore not be guessed at -- is a name
    /// with an empty value, and still replaces rather than duplicates.
    #[test]
    fn an_environment_entry_with_no_value_still_replaces_by_name() {
        let passwd = vec![CString::new("TERM=xterm").expect("no NUL")];
        let session = vec![CString::new("TERM").expect("no NUL")];

        let merged = merge_env(passwd, &session);

        assert_eq!(
            merged
                .iter()
                .map(|e| e.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            ["TERM"],
            "an entry with no value is one name, not a second TERM beside the first"
        );
    }

    /// What a PAM module said reaches the helper's log as one line of
    /// printable ASCII, and no more of it than [`MAX_REFUSAL_DETAIL`].
    ///
    /// The text is written by modules the administrator configured and ends
    /// up in a ROOT process's log: a newline in it would forge a second log
    /// line, and an escape sequence would aim at whoever reads that log on
    /// a terminal.
    #[test]
    fn a_modules_words_reach_the_log_as_one_printable_line() {
        let forged = "denied\nqshd helper: and now a line of my own\x1b[2J";

        let sanitized = sanitized_detail(forged);

        assert_eq!(
            sanitized, "denied.qshd helper: and now a line of my own.[2J",
            "a newline or an escape must not survive into the log"
        );
        assert_eq!(
            sanitized_detail(&"x".repeat(MAX_REFUSAL_DETAIL + 100)).len(),
            MAX_REFUSAL_DETAIL,
            "and no module may spend more of the log, or of the seam's message cap, than this"
        );
    }

    /// A monitor writes nothing to the daemon's log file, ever.
    ///
    /// It closed that file's descriptor in its very first act, while
    /// `crate::log` still holds the NUMBER it was open on -- and the pipes,
    /// terminals and sockets opened afterwards, by this code and by every
    /// PAM module the administrator configured, can be handed that number.
    /// A log line would then be written into a channel's startup-report
    /// pipe, where four bytes of a timestamp read as an `errno`. So
    /// `run_monitor` mutes the process instead, and this is that muting.
    ///
    /// In a process of its own, because muting is one-way and the whole
    /// test binary would go quiet with it.
    #[test]
    fn a_muted_process_writes_nothing_to_the_log() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::monitor::tests::a_muted_process_writes_nothing_to_the_log_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`a_muted_process_writes_nothing_to_the_log`], in a
    /// process of its own: it silences that process's log for good.
    #[test]
    #[ignore = "runs only via a_muted_process_writes_nothing_to_the_log, in a process of its own"]
    fn a_muted_process_writes_nothing_to_the_log_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::log::init(dir.path());
        let log_path = dir.path().join("qshd.log");
        let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();
        crate::log::info("qshd", "before the sweep");
        assert!(
            read_log().contains("before the sweep"),
            "setup: the log must be writable, or the silence below proves nothing"
        );

        crate::log::mute();
        crate::log::info("qshd", "after the sweep");

        assert!(
            !read_log().contains("after the sweep"),
            "a muted process must write nothing at all; the log is:\n{}",
            read_log()
        );
    }

    // This guard owns only this fixture's direct child. ECHILD means it must
    // never signal that numeric PID again; it is not a product cleanup proof.
    struct Open24OwnedChild(Pid);
    impl Drop for Open24OwnedChild {
        fn drop(&mut self) {
            use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
            match waitpid(self.0, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::StillAlive) => {
                    let _ = nix::sys::signal::kill(self.0, Signal::SIGKILL);
                    loop {
                        match waitpid(self.0, None) {
                            Err(nix::Error::EINTR) => continue,
                            Ok(_) | Err(nix::Error::ECHILD) => break,
                            Err(error) => panic!("fixture wait failed: {error}"),
                        }
                    }
                }
                Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) | Err(nix::Error::ECHILD) => {
                }
                other => panic!("unexpected fixture wait result: {other:?}"),
            }
        }
    }

    #[test]
    fn open24_failed_start_reports_cleanup_only_after_exact_reap() {
        let (helper, monitor) = channel::pair().unwrap();
        helper.set_nonblocking(true).unwrap();
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "read marker; exit 7"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let owned = Open24OwnedChild(pid);
        let (report_read, report_write) = nix::unistd::pipe().unwrap();
        let raw_report = report_read.as_raw_fd();
        nix::unistd::write(&report_write, &(nix::Error::EACCES as i32).to_ne_bytes()).unwrap();
        drop(report_write);
        let mut shells = vec![Shell {
            #[cfg(target_os = "linux")]
            native: None,
            #[cfg(target_os = "linux")]
            tty: None,
            id: 101,
            pid,
            report: Some(report_read),
            started: false,
        }];
        report_startups(&monitor, &mut shells, &[raw_report]);
        let (bytes, fd) = channel::recv(&helper).unwrap().unwrap();
        assert!(fd.is_none());
        assert_eq!(
            decode::<MonitorEvent>(&bytes).unwrap(),
            MonitorEvent::Failed {
                id: 101,
                errno: nix::Error::EACCES as i32
            }
        );
        assert!(shells[0].report.is_none());
        let mut closing = HashMap::new();
        reap_shells(&monitor, &mut shells, &mut closing);
        assert_eq!(shells.len(), 1, "the pipe barrier keeps the child alive");
        assert!(matches!(channel::recv(&helper), Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock));
        drop(child.stdin.take());
        let deadline = Instant::now() + Duration::from_secs(5);
        while !shells.is_empty() {
            reap_shells(&monitor, &mut shells, &mut closing);
            assert!(Instant::now() < deadline, "owned child was not reaped");
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            child.wait().unwrap_err().raw_os_error(),
            Some(nix::libc::ECHILD),
            "the product monitor already reaped this exact child"
        );
        drop(owned);
        // Raw JSON keeps this behavioral RED independent of the new enum's
        // compile-time presence. A failed startup never gets installed Exited.
        let message = channel::recv(&helper)
            .expect("exact reap must send a cleanup receipt")
            .expect("the fixture peer remains open");
        assert!(message.1.is_none());
        let value: serde_json::Value = serde_json::from_slice(&message.0).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "CleanupComplete": { "id": 101, "kind": "Reaped" }
            })
        );
        reap_shells(&monitor, &mut shells, &mut closing);
        assert!(matches!(channel::recv(&helper), Err(error)
            if error.kind() == std::io::ErrorKind::WouldBlock));
    }
    #[test]
    fn open24_echild_is_not_a_cleanup_receipt() {
        let (helper, monitor) = channel::pair().unwrap();
        helper.set_nonblocking(true).unwrap();
        let mut child = std::process::Command::new("/bin/true").spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        child.wait().unwrap(); // the monitor did not reap this child
        let mut shells = vec![Shell {
            #[cfg(target_os = "linux")]
            native: None,
            #[cfg(target_os = "linux")]
            tty: None,
            id: 102,
            pid,
            report: None,
            started: true,
        }];
        reap_shells(&monitor, &mut shells, &mut HashMap::new());
        assert_eq!(shells.len(), 1, "missing ownership remains unknown");
        assert!(
            matches!(channel::recv(&helper), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
        );
    }

    #[test]
    fn helper39_empty_pre_session_report_never_publishes_started() {
        use std::io::Read;
        let view = crate::process_scope::prepare().unwrap();
        let (helper, monitor) = channel::pair().unwrap();
        helper.set_nonblocking(true).unwrap();
        // This exact owned child has not called setsid: EOF cannot grant
        // authority over the parent's session or claim exec success.
        let mut child = std::process::Command::new("/bin/sh")
            .args(["-c", "printf ready; read release"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let owned = Open24OwnedChild(pid);
        let mut ready = [0; 5];
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_exact(&mut ready)
            .unwrap();
        assert_eq!(&ready, b"ready");
        assert_eq!(unsafe { nix::libc::getsid(pid.as_raw()) }, unsafe {
            nix::libc::getsid(0)
        });
        let (read, write) = nix::unistd::pipe().unwrap();
        let raw = read.as_raw_fd();
        drop(write);
        let mut shells = vec![Shell {
            #[cfg(target_os = "linux")]
            native: Some(native::NativeShell::new(
                std::num::NonZeroU32::new(pid.as_raw() as u32).unwrap(),
                view,
                read,
                Instant::now() + STARTUP_REPORT_TIMEOUT,
            )),
            #[cfg(target_os = "linux")]
            tty: None,
            id: 3901,
            pid,
            report: None,
            started: false,
        }];
        let _ = raw;
        report_owned_shells(&monitor, &mut shells, &mut CleanupSummary::default());
        let event = channel::recv(&helper).unwrap().unwrap();
        assert!(event.1.is_none());
        let event: MonitorEvent = decode(&event.0).unwrap();
        let started = shells[0].started;
        // Fixture cleanup is exact direct-child kill + actual wait, before
        // the RED assertion. No session/group signalling occurs here.
        drop(owned);
        assert_eq!(
            child.wait().unwrap_err().raw_os_error(),
            Some(nix::libc::ECHILD)
        );
        assert!(
            !started,
            "missing setsid acknowledgement must not establish a session"
        );
        assert!(
            matches!(event, MonitorEvent::Failed { id: 3901, .. }),
            "empty pre-session EOF must fail startup, got {event:?}"
        );
    }
}

#[cfg(target_os = "linux")]
#[path = "monitor_native.rs"]
mod native;

#[cfg(test)]
mod cleanup_receipt_tests {
    use super::*;
    #[test]
    fn selinux57_monitor_failure_receipt_and_final_summary_remain_independent_of_pam() {
        let (monitor, helper) = channel::pair().unwrap();
        helper
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut summary = CleanupSummary::default();
        let failure = CleanupFailure::PtyLabelRestore { errno: 13 };
        report_channel_cleanup(
            &monitor,
            57,
            CleanupKind::Reaped,
            Some(failure),
            &mut summary,
        );
        let (bytes, fd) = channel::recv(&helper).unwrap().unwrap();
        assert!(fd.is_none());
        assert_eq!(
            decode::<MonitorEvent>(&bytes).unwrap(),
            MonitorEvent::CleanupFailed {
                id: 57,
                kind: CleanupKind::Reaped,
                failure
            }
        );
        report_channel_cleanup(&monitor, 58, CleanupKind::NoChild, None, &mut summary);
        assert_eq!(summary.failure, Some(failure));
        assert_eq!(summary.pam, PamCompletion::NotOpened);
        let event = MonitorEvent::SessionClosed {
            result: summary.pam,
            request_failure: None,
            cleanup_failure: summary.failure,
        };
        assert_eq!(
            decode::<MonitorEvent>(&encode(&event).unwrap()).unwrap(),
            event
        );
    }
}

#[cfg(all(test, target_os = "linux"))]
#[path = "monitor_selinux_tests.rs"]
mod selinux_tests;

#[cfg(target_os = "linux")]
fn report_terminal_cleanup<A: super::selinux_tty::Adapter>(
    seam: &UnixStream,
    id: ChannelId,
    kind: CleanupKind,
    guard: Option<super::selinux_tty::Guard<'_, A>>,
    summary: &mut CleanupSummary,
) {
    let failure = finish_terminal(guard);
    report_channel_cleanup(seam, id, kind, failure, summary);
}

#[cfg(target_os = "linux")]
fn terminal_errno(error: &std::io::Error) -> i32 {
    error
        .raw_os_error()
        .filter(|errno| *errno > 0)
        .unwrap_or(nix::libc::EIO)
}
#[cfg(target_os = "linux")]
fn finish_terminal<A: Adapter>(guard: Option<Guard<'_, A>>) -> Option<CleanupFailure> {
    match guard.map(Guard::finish) {
        Some(selinux_tty::Finish::RestoreFailed(error)) => Some(CleanupFailure::PtyLabelRestore {
            errno: terminal_errno(&error),
        }),
        _ => None,
    }
}
#[cfg(target_os = "linux")]
struct TerminalPreparationFailure {
    why: String,
    error: std::io::Error,
    cleanup: Option<CleanupFailure>,
}
#[cfg(target_os = "linux")]
fn prepare_terminal(
    snapshot: &Snapshot,
    slave: OwnedFd,
) -> Result<(OwnedFd, Option<Guard<'static, Native>>), TerminalPreparationFailure> {
    use nix::fcntl::{fcntl, FcntlArg, FdFlag};
    // SCM_RIGHTS receipt must have set CLOEXEC atomically. OwnedFd and the
    // sender's flags alone establish neither property.
    let flags = fcntl(slave.as_raw_fd(), FcntlArg::F_GETFD).map_err(|error| {
        TerminalPreparationFailure {
            why: format!("read channel terminal descriptor flags: {error}"),
            error: error.into(),
            cleanup: None,
        }
    })?;
    if !FdFlag::from_bits_truncate(flags).contains(FdFlag::FD_CLOEXEC) {
        return Err(TerminalPreparationFailure {
            why: "received channel terminal is not close-on-exec".into(),
            error: std::io::Error::from_raw_os_error(nix::libc::EPROTO),
            cleanup: None,
        });
    }
    match Prepared::prepare(&selinux_tty::NATIVE, snapshot, slave) {
        Ok(Prepared::Unchanged(slave)) => Ok((slave, None)),
        Ok(Prepared::Relabeled(guard)) => match guard.as_fd().try_clone_to_owned() {
            Ok(fork_input) => Ok((fork_input, Some(guard))),
            Err(error) => {
                let why = format!("duplicate channel terminal descriptor: {error}");
                let cleanup = finish_terminal(Some(guard));
                Err(TerminalPreparationFailure {
                    why,
                    error,
                    cleanup,
                })
            }
        },
        Err(failure) => {
            let cleanup = match failure.rollback {
                selinux_tty::Rollback::Failed(ref error) => Some(CleanupFailure::PtyLabelRestore {
                    errno: terminal_errno(error),
                }),
                _ => None,
            };
            Err(TerminalPreparationFailure {
                why: format!(
                    "prepare channel terminal {:?}: {}",
                    failure.operation, failure.error
                ),
                error: failure.error,
                cleanup,
            })
        }
    }
}
