//! The helper's loop: read one message at a time from the worker, over two
//! seams. On the channel seam, open or close pseudo-terminal channels --
//! only ever for an account this helper verified itself -- and report their
//! exits, unprompted, as soon as `waitpid` sees them, not merely as an
//! answer to a request. On the authentication seam, mint the one-shot
//! nonces a handshake's msg2 carries, so a compromised worker cannot mint
//! its own, and verify a client's authentication proof against them itself
//! ([`verify_proof_after_nonce`], in a child of its own), so a compromised
//! worker cannot merely claim who logged in.
//!
//! # Who forks a channel's shell
//!
//! Not this module, since task 7 of slice 2c: [`open_channel`] opens the
//! terminal and hands the work to that login's MONITOR (`super::monitor`),
//! forking one for the login if it has none. A shell is therefore the
//! monitor's child, not the helper's -- so the helper neither reaps one nor
//! signals one, and learns what became of each from the monitor's own seam
//! (`protocol::MonitorEvent`). What the helper still owns is the terminal,
//! the channel id, and every decision about WHO a channel is for.
//!
//! # Why a hand-rolled `openpty` + `fork` + `exec`, not `portable_pty`
//!
//! A channel's process becomes its account BETWEEN the fork and the `exec`
//! -- groups, group id, user id, working directory -- and the next task
//! adds the opening of a PAM session beside it: a place `portable_pty` does
//! not expose. Writing the process descent by hand here is what made each
//! of those an insertion of a few calls into an already-existing place, not
//! a rewrite of this whole module.
//!
//! # Between `fork` and `exec`
//!
//! The child (see `monitor::fork_shell`, which is where the code below
//! moved with the fork) calls, in order: `setsid`, a `signal`
//! per reset signal, `sigprocmask` once to clear the mask, a raw
//! `ioctl(TIOCSCTTY)`, `dup2` three times, `close` (at most twice); then,
//! to become the account ([`become_account`]), `setgroups`, `setgid` and
//! `setuid`; `getresuid`, `getresgid` and `getgroups` to prove that took
//! ([`check_identity`], [`check_supplementary_groups`]), and, for a non-root
//! account, `capget` to prove no capability survived ([`check_no_capabilities`]);
//! a raw `prctl(PR_SET_PDEATHSIG)` and `getppid`, because the drop just
//! cleared the parent-death signal and nothing else would ever end this
//! shell with its monitor; `chdir` (at most twice, with one `write` of a
//! fixed warning to the terminal between them when the home is
//! unreachable); and one `execve` of
//! the account's shell -- and, ONLY on a failure that must stop the launch,
//! one `write` of a 4-byte `errno` to the startup-report pipe before `_exit`.
//!
//! `setsid`, `signal`, `sigprocmask`, `dup2`, `close`, `setgid`, `setuid`,
//! `getgroups`, `getppid`, `chdir`, `execve`, `write` and `_exit` are all on
//! POSIX's
//! async-signal-safe function list. `setgroups`, `getresuid`, `getresgid`,
//! the raw `ioctl`, the raw `prctl` and the raw `capget` syscall are not
//! POSIX functions, but
//! each is a wrapper over one system call that touches no libc or Rust
//! global state and allocates nothing. One libc detail: glibc routes
//! `setgroups`/`setgid`/`setuid` through its `setxid` machinery, which takes
//! a lock and walks the thread list -- but `fork` resets both in the child,
//! which has only the one thread that called it, so nothing there blocks and
//! nothing allocates.
//!
//! Nothing between `fork` and `exec` allocates: everything the child reads
//! -- the argument and environment arrays, the account's expected group
//! list and a buffer to read its real one into, the home path and the
//! chdir-warning bytes -- is built before the fork, and the child only reads
//! through (or sorts, in place) what is already there. The one in-place sort
//! ([`check_supplementary_groups`]) is pure computation, no allocation and
//! no libc call. The program is the account's shell at its absolute passwd
//! path, so there is no `PATH` search here at all -- the shell does that
//! itself, as the account, with the child's own `PATH`; see
//! `monitor::fork_shell`'s docs. None of the calls is `std::env::set_var`, which this module
//! deliberately avoids there -- see [`child_env`]'s docs.

use std::collections::{HashMap, HashSet};
use std::ffi::{CString, OsStr};
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use anyhow::Context;
use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use nix::unistd::{Gid, Pid, Uid};
use transport::auth::{AuthRecord, AuthV2};
use transport::LoginId;

use super::account::{self, Account, AccountError};
use super::authorized::{self, AuthorizedError};
use super::channel;
use super::config::HelperConfig;
#[cfg(test)]
use super::config::PAM_SERVICE;
use super::monitor::{run_monitor, MonitorPlan};
use super::pending::{Pending, PendingTable, PendingWhat};
use super::protocol::{
    decode, encode, AuthRequest, AuthResponse, ChannelId, MonitorEvent, MonitorRequest, Nonce,
    Request, Response,
};

/// How long the loop waits on the socket before looking for dead children.
/// Children are also reaped right after every message, so this only bounds
/// how stale an `Exited` can be when nothing else is happening, AND how
/// stale a `SIGHUP`-to-`SIGKILL` escalation (see [`CLOSE_GRACE_PERIOD`]) can
/// be once its deadline has passed.
pub(super) const REAP_INTERVAL: Duration = Duration::from_millis(200);

/// How long a channel gets, after `Request::Close` sends it `SIGHUP`, to
/// exit on its own before the escalation to `SIGKILL`.
///
/// `ChannelWait::kill`'s contract (`crates/transport/src/channel_server.rs`)
/// is to force the process down, not merely ask nicely, and the personal
/// mode's own implementation sends `SIGKILL` outright. `SIGHUP` alone
/// cannot deliver that contract: a channel that traps or ignores it
/// (`trap "" HUP`, deliberately or as a side effect of whatever program it
/// runs) would otherwise never die, never produce an `Exited`, and pin
/// whatever awaits its reap (see `run_channel_session`'s teardown) forever.
/// A couple of seconds is enough for `SIGHUP`'s well-behaved case (a shell
/// flushing its history) to finish, while still bounding how long a
/// misbehaving one can wedge a channel.
///
/// Both signals are the MONITOR's since task 7 -- the shell is its child,
/// not the helper's -- so this is the budget it keeps
/// (`monitor::escalate`). The helper keeps an escalation of its own one
/// level up, at [`MONITOR_GRACE_PERIOD`]: a monitor that reports no exit
/// makes its channel unclosable however well its shell behaves.
pub(super) const CLOSE_GRACE_PERIOD: Duration = Duration::from_secs(2);

/// How long the helper gives a MONITOR, after forwarding it a
/// `Request::Close`, to report that channel's exit before killing the
/// monitor itself.
///
/// Twice [`CLOSE_GRACE_PERIOD`], because the monitor's own escalation
/// happens inside that budget: a monitor doing its job sends `SIGHUP`,
/// waits a grace period, sends `SIGKILL` and reports the exit that follows,
/// all before this deadline. Reaching it therefore means the monitor itself
/// is not serving -- wedged, or stopped -- and not that its shell is slow.
///
/// Killing a monitor takes every shell of that login with it (each arms
/// `PR_SET_PDEATHSIG` before its `execve`), which is drastic and is meant
/// to be: the alternative is a channel the worker asked to close that never
/// closes, never reports an exit, and pins whatever awaits its reap --
/// exactly what `CLOSE_GRACE_PERIOD` exists to prevent one level down.
///
/// **What it costs, named rather than left to be discovered:** a monitor
/// killed here never runs `monitor::Session::close`, so its login's
/// `pam_close_session`, its `pam_setcred(DELETE_CRED)` and its `pam_end`
/// do not happen -- whatever the administrator's stack counts (a logind
/// session for `pam_systemd`, a mounted home for `pam_mount`, a keyring
/// for `pam_keyinit`) is left standing. Nothing can be done about it from
/// here: a monitor that has not answered within this budget is one that
/// is not serving, and a process that is not serving cannot be asked to
/// close anything politely. What CAN be done is to make sure the ordinary
/// path never comes here, and that is what `forget_login`'s seam drop plus
/// `monitor::SessionDeadline` are for: a monitor that is merely stuck
/// inside its PAM stack now comes back and ends its own login, instead of
/// waiting here to be killed.
const MONITOR_GRACE_PERIOD: Duration = CLOSE_GRACE_PERIOD.saturating_mul(2);

/// How long an issued nonce stays spendable. Generous next to the client's
/// own five-second authentication budget, short enough that the table cannot
/// grow without bound on a daemon nobody logs into successfully.
pub(crate) const NONCE_LIFETIME: Duration = Duration::from_secs(30);

/// How long a login entry has to become REAL -- to have a channel actually
/// open under it -- before the helper drops it on its own.
///
/// Deliberately the same timescale as [`NONCE_LIFETIME`], and beside it, for
/// the same reason: both bound a handshake that STARTED and never finished.
/// A nonce is that at its first half (issued, never spent); a
/// `Request::Verify`-created login entry is that at its second (the proof
/// checked out, but no session ever reached the point of opening a channel
/// for it).
///
/// Why the helper must bound this itself: an entry now exists from the
/// moment a proof verifies (fix F2), while the only thing that ever REMOVES
/// one is `Request::LoginEnded` -- which the worker can only send for a
/// login its router actually had a backend for. Every way a client can fail
/// in between leaves an entry behind: the worker's own session caps refusing
/// the admission, a client that vanishes after its proof, a handshake that
/// fails afterwards, a dropped datagram at the wrong moment. That is the
/// ordinary failure tail of authentication, not an exotic case, so the
/// privileged process cannot keep its table finite by trusting the
/// unprivileged worker to be correct and prompt -- exactly why the nonce
/// table has both a cap and a lifetime rather than a cap alone.
///
/// An ESTABLISHED login is never expired by age, however old, however idle,
/// and even once every one of its channels has closed again: that is the
/// availability property fix F2 exists to protect, and ending it early would
/// reintroduce F2's bug in a worse form. Such an entry ends only on a
/// genuine `Request::LoginEnded`. See [`sweep_expired_logins`].
const LOGIN_GRACE: Duration = Duration::from_secs(30);

/// The most nonces the helper will hold at once. Reaching it means somebody
/// is asking for them and never spending them, which is a flood, not a
/// backlog: refuse rather than evict, because evicting would let a flood
/// invalidate honest clients' nonces.
pub(super) const MAX_OUTSTANDING_NONCES: usize = 256;

/// The most logins the helper will hold at once. Only a successful
/// `Request::Verify` creates one (see [`LoopState::logins`]), so every entry
/// here stands for a genuine proof -- but a login's token is chosen by the
/// device presenting it, and one key holder can present as many proofs, each
/// under a fresh token, as it has nonces for. Capped the same way
/// [`MAX_OUTSTANDING_NONCES`] is: refuse a NEW login past the cap rather
/// than evict one that might still be live. [`LOGIN_GRACE`] is the other
/// half of the same bound -- the cap alone would be exhaustible for good by
/// entries that never became real and that nothing ever reports as ended.
///
/// Since task 7 a login also costs a PROCESS once it opens its first
/// channel -- its monitor (`super::monitor`) -- so this cap is now also the
/// cap on how many of those a worker can make the helper fork. They are
/// root processes, and they are the reason the cap is kept at a few hundred
/// rather than raised for comfort.
pub(super) const MAX_LOGINS: usize = 256;

/// The most proofs the helper will be checking at once.
///
/// Since task 4 every `Request::Verify` forks a child of its own, and this
/// is what bounds how many of those there may be. Its two siblings above
/// bound TABLES; this one bounds PROCESSES of a daemon running as root, on
/// a path that runs before anybody has authenticated -- so it matters more
/// than they do, not less. [`MAX_OUTSTANDING_NONCES`] is no help here:
/// `spend_nonce` frees a nonce's slot the moment its proof arrives, so a
/// single nonce at a time is enough to drive an unbounded number of forks.
///
/// Refuse rather than evict, exactly as the other two do: evicting would
/// kill a child half-way through its check and free a slot that whoever
/// filled the table would simply take again.
///
/// An honest worker never comes near this cap. It verifies at most
/// `transport`'s `MAX_CONCURRENT_VERIFIES` (four) proofs at once, and waits
/// for each verdict longer than this helper may take to give it
/// (`spawner::HelperAuth`), so a proof it has stopped waiting for is, as a
/// rule, one this helper has already stopped checking -- the exception is a
/// loop held up past the worker's margin. Sixty-four is far above that,
/// while keeping what a taken-over worker can reach to a handful of
/// processes rather than a fork bomb.
pub(super) const MAX_VERIFYING: usize = 64;

/// The most channels one login may hold at once.
///
/// The fourth of this process's caps, and the one that was missing. The
/// three above bound what a worker can make this process KEEP -- nonces,
/// logins, verifications in flight -- and each says in its own docs that it
/// is there because the worker is not trusted. Channels had no such bound
/// here at all: the only one lived in the worker
/// (`transport::channel::MAX_CHANNELS`, eight per session), in the process
/// this split exists to distrust. A worker that skipped its own check made
/// this process open a pseudo-terminal pair and its login's monitor fork a
/// root process for every `Request::Open` it cared to send, with nothing to
/// refuse it -- and a pseudo-terminal is not even this daemon's to spend:
/// `kernel.pty.max` is one pool for the whole machine, shared with `sshd`,
/// `screen` and `tmux`.
///
/// **Per login, not per daemon.** The three caps above are daemon-wide
/// because they bound tables this process keeps on everybody's behalf; a
/// channel belongs to exactly one login. A daemon-wide cap on channels
/// would let one login's flood lock every other login out -- the very
/// outcome [`MAX_OUTSTANDING_NONCES`] refuses in its own words. A login is
/// a session, so this is the worker's own shape, one privilege level down.
///
/// **Twice the worker's eight, and derived from it rather than written
/// out.** Twice, because the two halves free a channel at different
/// moments: the worker drops one from its table the instant the client
/// says `CLOSE` (`transport::channel_server`), while this process keeps it
/// in [`LoopState::live`] until that channel's monitor reports its shell's
/// exit -- up to [`CLOSE_GRACE_PERIOD`] later, and [`MONITOR_GRACE_PERIOD`]
/// at the outside. A session that closes all eight of its channels and
/// opens eight more at once is therefore worth sixteen here for a moment,
/// and refusing that would be this process refusing what its own rules
/// allow. Nothing smaller has that property. Derived rather than written
/// out so the two cannot drift: raising the worker's cap raises this one
/// with it.
///
/// A worker that churns channels FASTER than they can be buried is still
/// refused, and that is the cap doing its work rather than a defect: what
/// it bounds is the terminals this process holds at once, dying ones
/// included.
///
/// At the ceiling, [`MAX_LOGINS`] times this is 4096 pseudo-terminals --
/// a stock `kernel.pty.max` exactly -- but only half of that can be
/// steady, the other half being channels whose shells are already on their
/// way out. That upper half is what would have to be argued again if the
/// worker's cap were raised.
pub(super) const MAX_CHANNELS_PER_LOGIN: usize = 2 * transport::channel::MAX_CHANNELS;

/// What a forked child of the helper exits with when it panicked.
///
/// Both children this process forks and does not `exec` -- the one that
/// checks a proof ([`fork_verification`]) and a login's monitor
/// (`monitor::run_monitor`) -- are documented as never returning, because
/// returning into the helper's loop would make a second helper, and both
/// rest on control flow reaching an `_exit`. A panic does not reach it:
/// nothing in this workspace sets `panic = "abort"`, so the default
/// `unwind` strategy applies and a panic travels back through the frames
/// between the panic and the `fork`, running each one's `Drop` glue in a
/// process that has just swept its own descriptor table, and then ends the
/// THREAD rather than the process.
///
/// Closed with `catch_unwind` at each child's own boundary rather than with
/// `panic = "abort"` in the manifests: a profile switch would change how
/// every other process in this workspace behaves, the worker's async
/// runtime included, where a panicking task is contained on purpose -- and
/// cargo ignores `panic` for the test profile, so the property would hold
/// in production and not under test, which is the one place it could be
/// shown to hold at all. The narrow guard is also what the branch already
/// reaches for at the other boundary it cared about (`pam::converse`).
///
/// A code of its own so a `waitpid` status says which of a child's exits
/// this was; neither child may write to the log to say so itself.
pub(super) const PANICKED_CHILD_EXIT: i32 = 72;

/// The one reason every refused `Request::Verify` carries back to the
/// worker, whichever check actually refused it: the `MAX_VERIFYING` cap,
/// the nonce, one of [`verify_proof_after_nonce`]'s checks in the verifying
/// child, the login table, a verifying child that could not be started at
/// all, or one that never delivered a verdict.
///
/// And, since the login's PAM session moved into the monitor, every
/// `Request::Open` its stack refuses as well -- a locked account, an
/// expired one, a session stack that failed
/// ([`refuse_channel_outright`]). Same string for the same reason: the
/// account stack's verdict is exactly as much of an enumerator as the
/// signature check's.
/// Naming the real reason on the wire would hand the worker -- which this
/// whole slice exists to distrust -- an account and key enumerator (an
/// "unknown login" refusal distinguishable from a "key not listed" one
/// already tells an attacker which accounts exist on the machine). The real
/// reason is logged, here, in the privileged process, and nowhere else.
const REFUSED_REASON: &str = "authentication failed";

/// How long a send on either of the helper's own seam ends may block before
/// it gives up on that one message.
///
/// The helper is single-threaded: a `reply` that blocks blocks EVERYTHING
/// -- every other session's channel, every login, the reaper. And it can
/// block: a worker that stops reading (wedged, or taken over and doing it
/// deliberately) leaves the socket's buffer full, and a send with no
/// timeout then waits for a reader that may never come back.
///
/// The budget is the worker's budget for a nonce's answer, and past it
/// nobody is waiting for a nonce any more. A verdict's call and an open's
/// may still be waiting then -- both wait longer (`spawner::HelperAuth`,
/// `spawner::OPEN_REPLY_TIMEOUT`) -- but a send blocks only while the worker
/// has stopped emptying its end, and each seam has a reader thread on the
/// worker's side whose work is exactly that: a buffer still full after this
/// long means that reader is stuck, and waiting on it longer would only
/// stop the helper for longer.
///
/// A dropped answer is never mistaken for another -- the worker matches
/// answers to questions by number on the authentication seam and by channel
/// id on the other. Its cost falls on its own call: a channel whose `Opened`
/// could not be handed over is closed by the worker's own
/// `OPEN_REPLY_TIMEOUT` path a few seconds later, and a verdict that could
/// not be handed over leaves its call to run out its time and refuse, while
/// the login entry an admission opened here can stay for up to
/// `LOGIN_GRACE`.
const SEAM_SEND_TIMEOUT: Duration = super::spawner::HELPER_ANSWER_TIMEOUT;

/// The loop, as the daemon runs it. The worker closing either of its two
/// ends means the worker is gone, and a helper without a worker has nothing
/// to serve.
///
/// Exits non-zero: `docs/qshd-service.md`'s unit uses `Restart=on-failure`,
/// which only restarts a service that exits non-zero or dies by signal.
/// The worker being gone is not a request to stop -- it is half the
/// service disappearing out from under the other half -- so `exit(0)`,
/// which systemd reads as an intentional, successful stop, would leave the
/// whole service down instead of restarted.
pub fn run(channels: UnixStream, auth: UnixStream, config: HelperConfig) -> ! {
    run_until_peer_closes(channels, auth, config);
    crate::log::error("helper", "the worker is gone, stopping");
    std::process::exit(1);
}

/// The loop, as the tests drive it: returns when the peer closes either end
/// instead of ending the process, so a test can join it.
///
/// `channels` is the helper's end of the channel seam and `auth` its end of
/// the authentication seam -- see `helper::split_and_run` for why there are
/// two, and [`serve`] for how one loop serves both.
///
/// `config` is resolved once by the caller, before the split
/// ([`HelperConfig::resolve`]). `authorized_keys_template`/`permit_root` are
/// read in the verification path ([`verify_proof_after_nonce`]); `tty_gid` names the
/// group a channel's terminal is given to ([`open_channel`]).
///
/// A thin wrapper over [`serve`], always with [`AccountSwitches::REAL`] --
/// the switches that really change identity, and so always need root -- and
/// with NO login admitted up front: a login, and the account behind it, get
/// in only through `Request::Verify`. Tests call `serve` directly instead --
/// see `serve`'s own docs.
pub fn run_until_peer_closes(channels: UnixStream, auth: UnixStream, config: HelperConfig) {
    serve(
        channels,
        auth,
        config,
        HashMap::new(),
        AccountSwitches::REAL,
    );
}

/// The two places the helper acts as another account, as plain function
/// pointers -- not closures or trait objects: nothing here has state to
/// carry, and [`AccountSwitches::become_account`] is called in the child
/// between `fork` and `exec`, where a plain call is all there is room for.
///
/// The daemon always runs with [`AccountSwitches::REAL`]. The one reason
/// this is a parameter at all is that both real switches need root --
/// `setgroups` needs `CAP_SETGID` even to set the list a process already
/// has -- while most of this module's tests run unprivileged: they pass
/// switches that read the same file and run the same program WITHOUT
/// changing identity (see the tests' `UNPRIVILEGED`), and the switching
/// itself is proven under root with `REAL`. Kept module-private: nothing
/// outside `helper` has any business choosing different switches.
#[derive(Clone, Copy)]
struct AccountSwitches {
    /// How [`verify_proof_after_nonce`]'s step 2 resolves a login name to
    /// the account behind it. Called in the VERIFYING CHILD, never in the
    /// loop -- it is the name-service lookup with no deadline of its own
    /// that the whole fork exists to get out of the helper's way.
    ///
    /// A switch at all only so a test can hand the child an account that
    /// differs from what `getpwnam` would answer in the parent, and then
    /// insist that what lands in `LoopState::verified` is the CHILD's
    /// version -- the property that makes this task worth anything. A
    /// parent that re-ran the lookup on the loop would undo the whole
    /// thing, and no test could tell.
    lookup: fn(&str) -> Result<Account, AccountError>,
    /// How [`verify_proof_after_nonce`]'s step 4 reads an account's
    /// `authorized_keys`. Called in the verifying child too, for the same
    /// reason: the file may live on a home directory that never answers.
    read_keys: fn(&Account, &str) -> Result<String, AuthorizedError>,
    /// How a channel's child becomes the account it runs as: called between
    /// `fork` and `exec`, so it must not allocate -- see the module's docs.
    become_account: fn(Uid, Gid, &[Gid]) -> nix::Result<()>,
}

impl AccountSwitches {
    /// The daemon's switches: `account::lookup`, which asks the name
    /// service; `authorized::read_for`, which reads the file as the account
    /// itself; and [`become_account`], which drops a channel's process to
    /// it.
    const REAL: AccountSwitches = AccountSwitches {
        lookup: account::lookup,
        read_keys: authorized::read_for,
        become_account,
    };
}

/// The `PATH` every account except root is given, and the one a bare
/// program name is searched for on -- never the helper's own; see
/// `monitor::fork_shell`'s docs for why that distinction is the point.
const USER_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The `PATH` uid 0 is given, and searched on: [`USER_PATH`] with the
/// `sbin` directories, where the administration tools live.
const ROOT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// Everything the loop keeps between messages: one of each, shared by both
/// seams. The sharing is the point -- the nonce a `Request::Nonce` issues on
/// the authentication seam is the one a `Request::Verify` spends there, and
/// the account that `Verify` admits is the one a `Request::Open` on the
/// CHANNEL seam may then open a channel for -- and it is also why each seam
/// refuses the other's requests (see [`serve_channel_seam`] and
/// [`serve_auth_seam`]): a request honoured on the wrong seam would reach
/// this state by a door that seam's own rules were never written for.
struct LoopState {
    /// Every channel id that is TAKEN, by id -- one whose process is still
    /// starting as much as one already running; see [`ChannelSlot`] for why
    /// those are one table and not two.
    live: HashMap<ChannelId, ChannelSlot>,
    /// The requests this loop cannot finish on the spot, each waiting on a
    /// child of its own: see [`PendingTable`]. Their report pipes join both
    /// seams in the loop's one `poll`, which is what keeps a slow channel
    /// from stopping every other session on the machine.
    pending: PendingTable,
    /// Pids the helper has already given up on -- a verifying child whose
    /// verdict it will not use, and every monitor it has stopped talking to
    /// -- see `reap`'s docs for why they still need a place to be reaped
    /// from.
    orphans: Vec<Pid>,
    /// Channels `Request::Close` has been forwarded to a monitor for, keyed
    /// to the deadline by which that monitor must have reported the exit --
    /// see [`MONITOR_GRACE_PERIOD`], and `reap`, which kills the monitor
    /// itself past it.
    closing: HashMap<ChannelId, Instant>,
    /// Nonces issued via `Request::Nonce`, keyed by the nonce itself, valued
    /// by when each was minted. Removed four ways: explicitly, via
    /// `Request::ReleaseNonce`, by whoever asked for one and then found it
    /// will never be spent; by `reap`'s sweep, once one ages past
    /// `NONCE_LIFETIME` unclaimed; by being spent, via `Request::Verify`
    /// ([`spend_nonce`], which `serve_auth_seam` calls itself before any
    /// child is forked, and which removes it whether or not the rest of the
    /// proof goes on to verify -- a request the `MAX_VERIFYING` cap turns
    /// away never gets that far); or found already gone, because one of
    /// those three already claimed it.
    nonces: HashMap<Nonce, Instant>,
    /// Accounts a `Request::Verify` has admitted, keyed by uid -- the
    /// account exactly as the verifying child resolved and approved it
    /// ([`verify_proof_after_nonce`]), carried back whole on its report
    /// pipe. Filled
    /// there and nowhere else in the daemon (it starts empty -- see
    /// [`run_until_peer_closes`]), and emptied of a uid by
    /// [`forget_login`] once that uid's last login ends -- see
    /// `Request::LoginEnded`'s docs for why: the threat model promises only
    /// whoever is connected right now, not whoever ever connected.
    /// `Request::Open` refuses any uid missing from here, and takes
    /// everything else about the channel's account -- gid, groups, home,
    /// shell -- from here too, so a channel never needs a second `getpwuid`
    /// (under NSS/LDAP, a lookup this single-threaded helper cannot afford
    /// to repeat per channel).
    verified: HashMap<Uid, Account>,
    /// Every LIVE login, by its [`LoginId`] -- about LOGINS, not accounts,
    /// which is why this is a second table rather than folded into
    /// `verified`: one account can hold several logins at once (two
    /// terminals, two sessions), and a login is what a PAM session (from the
    /// next task on) belongs to.
    ///
    /// # The one place an entry is CREATED
    ///
    /// **Only the `Request::Verify` that proved its account creates an
    /// entry** ([`ensure_login`], from `finish_pending`), before the login
    /// has opened anything at all, and refused outright past
    /// [`MAX_LOGINS`]. `Request::Open` never creates one: it REQUIRES the
    /// login it names to be on file already, bound to the uid it names, in
    /// ADDITION to that uid being in `verified` -- see that arm's own
    /// comment. Every system-mode login proves itself through `Verify`
    /// before its first `Open`, so an `Open` finding no entry is a login
    /// that has ended, or expired, or never proved anything. Allowing it to
    /// create one is what once let an `Open` still queued on the channel
    /// seam put back a login whose `LoginEnded` the authentication seam had
    /// just served -- and that entry, once its channel opened, would never
    /// have been removed again.
    ///
    /// # Every place an entry is REMOVED, and the one rule they share
    ///
    /// **A login entry is removed only when nothing of its is in flight,
    /// and `Request::LoginEnded` gets there by cancelling rather than by
    /// waiting.**
    ///
    /// The rule has no exception, and that is deliberate: tasks 7 and 8
    /// decide a monitor's and a PAM session's lifetime from this state, and
    /// a rule with a documented carve-out is one somebody satisfies on the
    /// wrong side. What makes it necessary: a channel between its fork and
    /// its verdict is not in `LoginState::channels` yet, so "no channels"
    /// is not "nothing here", and a remover that ignores the difference
    /// drops an entry out from under a channel that is about to open. That
    /// happened once for each remover there has been, which is why the list
    /// is written out here rather than left to be rediscovered:
    ///
    /// 1. [`sweep_expired_logins`] -> [`forget_login`], on age, and only for
    ///    an entry that never became established. Asks
    ///    [`PendingTable::holds_login`] in its filter, and declines to
    ///    remove while a start is in flight.
    /// 2. `Request::LoginEnded` -> [`forget_login`]. Cannot decline: no
    ///    second `LoginEnded` is coming, and an entry that goes on to
    ///    become established is never swept either, so a removal deferred
    ///    here is a removal lost -- the entry and its account's place in
    ///    `verified` would outlive the session for the daemon's whole life.
    ///    So it makes the condition true instead, with
    ///    [`PendingTable::cancel_login`]: every start of that login is
    ///    cancelled, and each is then refused and killed by its own verdict
    ///    (`finish_pending`), exactly as a `Close` during startup is.
    ///    `login_ended_cancels_a_start_still_in_flight` pins it.
    ///
    /// Nothing on the `Open` path removes an entry, whatever becomes of the
    /// request: an `Open` never inserted the entry it names, so it has
    /// nothing of its own to take back.
    logins: HashMap<LoginId, LoginState>,
    /// The monitor of every login that has one: the process that forks and
    /// watches that login's shells (`super::monitor`).
    ///
    /// # Its life is the LOGIN ENTRY's life, in BOTH directions
    ///
    /// One is forked by the first `Request::Open` of a login that has none,
    /// and taken down in exactly one place: inside [`forget_login`], just
    /// after it has removed the login's entry -- inlined there rather
    /// than kept as a function of its own precisely so that no other place
    /// can take a monitor down without ending its login (see the comment at
    /// that spot). And the other way round: every path
    /// that loses a monitor -- one killed for not answering, one nobody can
    /// reach, one that died on its own -- goes through [`forget_login`]
    /// too, so the login goes in the same step. The two tables therefore
    /// cannot disagree about whether a login is live.
    ///
    /// The second direction is what makes one login's monitor UNIQUE for
    /// that login's whole life. A login whose monitor was lost but whose
    /// entry stayed would be given a second monitor by its next
    /// `Request::Open` -- and from the next task on that is a second
    /// `pam_open_session` for one login, while the first session is left
    /// open with the process that could have closed it already killed. Spec
    /// §3.3 is exactly about that, and it is why a lost monitor ends its
    /// login rather than being replaced: a fresh proof is what admits the
    /// device again, and a fresh proof is a fresh login ENTRY.
    /// `a_login_never_gets_a_second_monitor` pins it.
    ///
    /// The entry, and not the token: the token is the CLIENT's to choose
    /// (`msg1.token`, carried into `Request::Verify`), so a client may well
    /// prove itself again under the very same one, and `ensure_login` then
    /// makes a new entry for it -- which `logins` allows outright. The
    /// invariant is therefore "one login ENTRY, one monitor, for that
    /// entry's life", never "one token, one monitor, for ever". From the
    /// next task on that is the distinction that matters, because a PAM
    /// session hangs off the monitor and so off the entry.
    ///
    /// `LoginState::channels` has nothing to say about it. That set means
    /// "open right now" and empties every time somebody types `exit`
    /// (`LoginState::channels`'s own docs), while the login is still very
    /// much alive and may open another channel a moment later -- and from
    /// the next task on, ending a monitor ends that login's PAM session.
    /// Deciding a monitor's life from that set would close the session
    /// under a session that has not ended.
    monitors: HashMap<LoginId, Monitor>,
    /// The number [`ensure_login`] gives the next login entry it creates,
    /// and then advances -- see [`LoginState::incarnation`] for what the
    /// number is for.
    ///
    /// One counter for the whole helper rather than one per token, so that
    /// no two entries ever share a number and nothing has to be reclaimed
    /// when an entry goes. A `u64` from 1: at one login a nanosecond it
    /// would take five hundred years to wrap, and the helper caps live
    /// logins at [`MAX_LOGINS`] in any case. Starts at 1 so that 0 can mean
    /// "no incarnation" everywhere it travels (`transport::Principal`'s own
    /// field, for a verifier that keeps nothing per login).
    next_incarnation: u64,
}

/// One login's monitor, as the helper holds it.
struct Monitor {
    /// The helper's end of the seam to it. Dropping this is what tells a
    /// monitor its login is over: its own end then reaches end-of-file, it
    /// takes its shells down and exits.
    seam: UnixStream,
    /// The monitor's process, so the helper can reap it -- and, past
    /// [`MONITOR_GRACE_PERIOD`], kill it.
    pid: Pid,
}

/// One login's own bookkeeping: which account it belongs to (fixed for the
/// login's whole life -- see [`LoopState::logins`]), when its entry was
/// created, whether it ever became real, and which channels are currently
/// open under it, right now -- an id enters `channels` only once its channel
/// has actually opened (never for one refused as a repeated id, and never
/// for a fork/exec that failed, so this set never remembers a channel that
/// never existed), and leaves it the moment `reap` reports that channel's
/// exit, the same instant it leaves `LoopState::live` (fix round F5: tasks 7
/// and 8 decide a monitor's and a PAM session's lifetime from this set, so
/// it must mean "open right now", never "ever opened").
struct LoginState {
    account: Account,
    /// Where the client was when it proved itself, as the worker named it
    /// -- kept for this login's monitor (`PAM_RHOST`, from the next task
    /// on) and for the log, and believed by nothing. See
    /// `Request::Verify`'s own `rhost` for why it decides nothing, and
    /// [`sanitized_rhost`] for what it is allowed to be.
    rhost: String,
    /// When this entry was inserted -- what [`LOGIN_GRACE`] is measured
    /// from, and only for as long as `established` is still false.
    created_at: Instant,
    /// Whether a channel has ever actually OPENED under this login.
    ///
    /// Set where a channel really opens, NOT merely on entering the `Open`
    /// arm: an `Open` refused for a repeated id or lost to a failed fork
    /// costs whoever sent it nothing, and a taken-over worker must not be
    /// able to buy a provisional entry immortality with one.
    ///
    /// Once true it stays true, including after every one of this login's
    /// channels has closed again -- `channels` going empty says the session
    /// has nothing open RIGHT NOW, never that the login is over; only
    /// `Request::LoginEnded` says that. [`sweep_expired_logins`] keys on
    /// this field, and on nothing else, for exactly that reason.
    established: bool,
    /// Which life of this token's login this entry is -- [`LoopState`]'s
    /// counter at the moment [`ensure_login`] created it, never reused.
    ///
    /// The token is the CLIENT's, stable across a roam and across a
    /// reconnect, so it cannot tell one life of a login from the next. This
    /// can, and the worker needs it to: it rides out on
    /// [`Response::Verified`] when the entry is created and on
    /// [`Response::LoginEnded`] when it ends, and the worker's router
    /// compares the two. Without it a notice about a login that HAS ended
    /// can be acted on after the same device has proved itself again --
    /// the two messages cross on separate seams, are read by separate
    /// threads, and meet in one unbiased `select!` -- and it would tear
    /// down the session that device just got, leaving this helper holding
    /// a login with no session behind it. Which, once established, nothing
    /// expires.
    ///
    /// Not `created_at`: two entries can share an instant, and an instant
    /// does not survive being compared across processes.
    incarnation: u64,
    channels: HashSet<ChannelId>,
}

impl LoginState {
    /// A login as a successful `Request::Verify` first puts it on file:
    /// created now, PROVISIONAL until a channel really opens under it -- see
    /// [`LoginState::established`] and [`LOGIN_GRACE`] -- and with nothing
    /// open.
    fn provisional(account: Account, rhost: String, incarnation: u64) -> LoginState {
        LoginState {
            account,
            rhost,
            created_at: Instant::now(),
            established: false,
            incarnation,
            channels: HashSet::new(),
        }
    }
}

/// What a login may keep as the address it came from: at most
/// [`MAX_RHOST_LEN`] bytes of ASCII graphic characters (no control
/// characters, and -- see [`sanitized_identity`] -- no space either), and
/// the empty string for anything else.
///
/// The value comes from the worker, which chooses it and which this split
/// exists to distrust, and it ends up in a root process's tables, in its
/// log, and (from the next task on) in `PAM_RHOST`. Neither an unbounded
/// string nor one carrying control characters -- a newline that forges a
/// second log line, an escape sequence aimed at whoever reads the log on a
/// terminal -- may get that far. Nothing is escaped or truncated into
/// something plausible-looking: a value that is not allowed is replaced
/// whole by the empty string, which is what a login whose address is
/// unknown carries anyway, so no reader has to tell a mangled address from
/// a real one.
fn sanitized_rhost(rhost: &str) -> String {
    sanitized_identity(rhost, MAX_RHOST_LEN)
}

/// The most bytes a login's source address may be. Generous next to the
/// longest address there is (an IPv6 address with a scope and a port fits
/// in about sixty characters) and small enough that `MAX_LOGINS` of them
/// are nothing.
const MAX_RHOST_LEN: usize = 255;

/// What a login may keep as the ACCOUNT NAME its proof claimed: at most
/// [`MAX_LOGIN_NAME_LEN`] bytes of ASCII graphic characters (no control
/// characters, and -- see [`sanitized_identity`] -- no space either), and
/// the empty string for anything else.
///
/// The same rule as [`sanitized_rhost`], for the same reason and against a
/// worse case. This value is the OTHER half of the same worker-chosen
/// record (`protocol::Request::Verify`), it reaches the same root process's
/// log -- `finish_pending` names it in every line it writes about this
/// login, accepted or refused -- and it gets there on a path that runs
/// BEFORE anything has authenticated: the name is what the account lookup
/// is still being attempted FOR, so a proof that never checks out has
/// already had its name logged. A newline in it forges a second line in
/// that log, which is the log an administrator's `fail2ban` filter reads;
/// an escape sequence in it aims at whoever reads the log on a terminal; a
/// space in it can relocate the ` from ` boundary such a filter anchors on
/// (task 9a review, MEDIUM).
///
/// Replaced WHOLE, never escaped or cut down, exactly as an address is: a
/// name is an identity, and a mangled one must not read as a real account.
/// An empty name in one of those two lines says "the name this proof
/// claimed was not something this helper will repeat", which is a truer
/// thing for an administrator to read than a plausible-looking fragment of
/// an attacker's string.
fn sanitized_login_name(login: &str) -> String {
    sanitized_identity(login, MAX_LOGIN_NAME_LEN)
}

/// The most bytes the account name a proof claimed may be.
///
/// The same number as [`MAX_RHOST_LEN`], reached independently: Linux's
/// `_SC_LOGIN_NAME_MAX` is 256 counting the terminator, so 255 is exactly
/// the most a name any name service could resolve may be, while `useradd`
/// itself stops at 32. Generous next to anything real, then, and small
/// enough that the [`MAX_VERIFYING`] of these that may exist at once are
/// nothing -- the bound that matters here, since a name is kept only for as
/// long as its verification is in flight, unlike an address, which a login
/// entry keeps for its whole life.
const MAX_LOGIN_NAME_LEN: usize = 255;

/// The one rule [`sanitized_rhost`] and [`sanitized_login_name`] share: at
/// most `max_len` bytes of ASCII graphic characters, and the empty string
/// for anything else.
///
/// One function rather than two copies of the predicate, because the two
/// callers must not be able to drift apart: they bound the two fields of
/// one record, chosen by one worker, on one path, for one log.
///
/// No space, unlike an earlier version of this rule: both call sites'
/// lines put the value immediately before the literal token ` from ` that
/// separates a name from an address -- the same token a `sshd`-style
/// filter anchors on -- so a value allowed to carry a space could relocate
/// that boundary (task 9a review, MEDIUM: a login of exactly `root from
/// 198.51.100.7` read as though that address were the connection's own).
/// Dropped the same way a newline already was: the whole value becomes
/// empty rather than losing just the offending character, so a mangled
/// name still cannot read as a real, merely-differently-shaped one. A real
/// account name cannot contain a space (`useradd` refuses one), so nothing
/// legitimate is lost; an address never contains one either.
fn sanitized_identity(value: &str, max_len: usize) -> String {
    if value.len() <= max_len && value.chars().all(|c| c.is_ascii_graphic()) {
        value.to_string()
    } else {
        String::new()
    }
}

/// A channel id is taken from the instant its shell is ASKED for, not from
/// the instant the monitor reports it started: between those two the worker
/// can send a second `Open` with the same id, and a `Vacant` entry there
/// would ask for a second shell whose exit would then be reported against
/// an id the first shell also holds -- one channel, two processes, and
/// whichever `Close` arrived would end only one of them.
///
/// So both states live in `LoopState::live` and both refuse a repeated id.
/// Each names the LOGIN the channel belongs to, which is how the helper
/// finds the monitor to forward a `Close` to and the monitor to kill when
/// one stops answering; the shell's own pid is no business of the helper's
/// since task 7 -- it is the monitor's child, and only the monitor may
/// signal or reap it.
///
/// What the difference between the two states decides is whether an exit
/// may be reported for this id at all: a `Starting` one's `Exited` would be
/// an answer to a request the worker has not been given its first answer to
/// yet.
enum ChannelSlot {
    /// Asked for, and the monitor has not yet said whether the `exec` took.
    /// The matching entry in `LoopState::pending` is what is waiting for
    /// that.
    Starting(LoginId),
    /// The monitor reported a successful start; the worker has been handed
    /// its terminal.
    Running(LoginId),
}

impl ChannelSlot {
    /// The login this channel belongs to, whichever state it is in -- what
    /// names the monitor that owns its shell.
    fn login(&self) -> LoginId {
        match self {
            ChannelSlot::Starting(login) | ChannelSlot::Running(login) => *login,
        }
    }
}

/// The helper's own ends of its two seams, together.
///
/// A pending request now belongs to one seam or the other -- a channel's
/// verdict is answered on the channel seam, a verification's on the
/// authentication seam -- while the loop settles both kinds in the same
/// pass, so the settling has to be able to reach either. Passing the pair
/// keeps "which seam answers this" a property of the ENTRY, decided in
/// [`finish_pending`] beside everything else that entry decides, rather
/// than a second `&UnixStream` threaded through three functions that would
/// each have to remember not to use the wrong one.
#[derive(Clone, Copy)]
struct Seams<'a> {
    channels: &'a UnixStream,
    auth: &'a UnixStream,
}

/// Why the loop has come back to a pending entry.
#[derive(Clone, Copy, PartialEq, Eq)]
enum WhyFinished {
    /// `poll` said the child's report pipe has something to say, so there
    /// is something to READ and what it says decides the answer.
    Spoke,
    /// The entry's own deadline passed with nothing said. Nothing is read:
    /// the child is killed and whoever is waiting for it is refused.
    Expired,
}

/// What a seam's handler tells the loop to do next.
enum Next {
    Continue,
    /// The worker is gone, or sent something that says it is not the
    /// process this helper thinks it is: end the loop.
    Stop,
}

/// Why an `Open` for an account nobody verified is refused. Shown to the
/// user, like every `Response::Failed` reason -- though an honest worker
/// never asks for such a channel, so an honest user never sees it.
const UNVERIFIED_ACCOUNT_REASON: &str = "the account this channel is for has not authenticated";

/// The loop's real body -- see [`run_until_peer_closes`] for the production
/// entry point, which always passes an empty `admitted` and
/// [`AccountSwitches::REAL`] here.
///
/// `admitted` is the logins the loop starts with, each with the account it
/// belongs to, and each put on file exactly as a successful
/// `Request::Verify` leaves one: a provisional entry in
/// [`LoopState::logins`], and its account in [`LoopState::verified`]. The
/// daemon passes it empty, so the only way into either table there is
/// `Request::Verify`; this module's tests pass the logins they need a
/// channel under, directly, so a test about what a channel runs AS does not
/// also depend on the verification path (which has tests of its own). No
/// message on either seam can put anything there, and nothing outside
/// `helper` can call this.
///
/// `switches` says how the helper acts as another account -- see
/// [`AccountSwitches`] for why that is a parameter at all.
///
/// One loop, two seams: `poll` waits on both descriptors at once, and each
/// pass serves at most ONE message from each seam that has one -- never one
/// seam's whole backlog before the other's first -- so a worker flooding
/// one seam cannot starve the other. One thread also means nothing here
/// needs a lock: [`LoopState`] is only ever touched by this loop, one
/// message at a time.
fn serve(
    channels: UnixStream,
    auth: UnixStream,
    config: HelperConfig,
    admitted: HashMap<LoginId, Account>,
    switches: AccountSwitches,
) {
    // Neither seam may be able to park this loop for good -- see
    // `SEAM_SEND_TIMEOUT`. Reported rather than fatal: a helper that could
    // not set the option is still a working helper, and saying so beats
    // refusing to serve anyone.
    for (seam, which) in [(&channels, "channel"), (&auth, "authentication")] {
        if let Err(e) = seam.set_write_timeout(Some(SEAM_SEND_TIMEOUT)) {
            crate::log::warn(
                "helper",
                &format!(
                    "could not bound sends on the {which} seam ({e}); a worker that \
                 stops reading it could block this helper for good"
                ),
            );
        }
    }

    // Read before `admitted` is consumed below, so the counter can start
    // past every login seeded out of it.
    let seeded = admitted.len();
    let mut state = LoopState {
        live: HashMap::new(),
        pending: PendingTable::default(),
        orphans: Vec::new(),
        closing: HashMap::new(),
        nonces: HashMap::new(),
        verified: admitted
            .values()
            .map(|account| (account.uid, account.clone()))
            .collect(),
        logins: admitted
            .into_iter()
            .enumerate()
            .map(|(n, (login, account))| {
                // No address: a login seeded here never came off a wire
                // (see this function's `admitted`), so there is nothing to
                // record as where it came from.
                //
                // An incarnation apiece all the same, from the same
                // sequence `ensure_login` will go on with below: two
                // entries sharing a number is the one thing the number
                // exists to rule out, seeded or not.
                (
                    login,
                    LoginState::provisional(account, String::new(), 1 + n as u64),
                )
            })
            .collect(),
        monitors: HashMap::new(),
        next_incarnation: 1 + seeded as u64,
    };
    // Borrowed once, for the whole loop: both are owned locals that outlive
    // it, and everything below takes them immutably.
    let seams = Seams {
        channels: &channels,
        auth: &auth,
    };
    loop {
        // Everything the helper is waiting on goes into ONE `poll`: both
        // seams, and the report pipe of every child a request is still
        // pending on. The numbers come out of the table first and the array
        // is built from them, rather than borrowing the table -- see
        // `pending`'s own docs for why that is the point and not a
        // shortcut.
        let report_fds = state.pending.poll_fds();
        // And every live monitor's seam: a channel's startup, its exit, and
        // a monitor's own death all arrive there. Collected as a list of
        // logins, in one order, so the `revents` below can be read back
        // against it -- the same shape the report pipes use, and for the
        // same reason (the array must not borrow the table it was built
        // from).
        let monitor_logins: Vec<LoginId> = state.monitors.keys().copied().collect();
        let mut fds: Vec<PollFd> = Vec::with_capacity(2 + report_fds.len() + monitor_logins.len());
        fds.push(PollFd::new(channels.as_fd(), PollFlags::POLLIN));
        fds.push(PollFd::new(auth.as_fd(), PollFlags::POLLIN));
        for fd in &report_fds {
            // SAFETY: every number here came out of `poll_fds` a line ago,
            // and the pending table owns each of those descriptors
            // (`Pending::report` is an `OwnedFd`) until its entry leaves --
            // which nothing between there and the `poll` below does. The
            // borrow is used for this one call and never outlives the pass.
            fds.push(PollFd::new(
                unsafe { BorrowedFd::borrow_raw(*fd) },
                PollFlags::POLLIN,
            ));
        }
        for login in &monitor_logins {
            // SAFETY: every login here came out of `state.monitors` a line
            // ago, and the `Monitor` it names owns its seam socket
            // (`Monitor::seam` is a `UnixStream`) until the entry leaves the
            // table -- which nothing between there and the `poll` below
            // does. The borrow is used for this one call and never outlives
            // the pass.
            let raw = state.monitors[login].seam.as_raw_fd();
            fds.push(PollFd::new(
                unsafe { BorrowedFd::borrow_raw(raw) },
                PollFlags::POLLIN,
            ));
        }
        // Never longer than REAP_INTERVAL, so a child that exits while the
        // worker is silent is still noticed -- and never past the nearest
        // startup deadline either, so a child that says nothing at all is
        // given up on when its own budget runs out rather than up to a reap
        // pass later.
        match poll(&mut fds, poll_timeout(&state.pending, Instant::now())) {
            // `Ok(0)` -- nothing spoke -- needs no arm of its own: every
            // `revents` is then empty, nothing below is served, and the
            // pass falls straight through to the deadline and reap sweeps,
            // which is the whole point of the timeout.
            Ok(_) => {}
            Err(nix::Error::EINTR) => continue,
            Err(e) => {
                crate::log::error("helper", &format!("poll failed: {e}"));
                break;
            }
        }
        // Anything at all in `revents` -- data, a hang-up, an error -- is
        // for `recv` (or the report read) to interpret, which is why this
        // does not look at WHICH flags came back; flags `nix` does not know
        // count as ready for the same reason.
        let channel_ready = fds[0].any().unwrap_or(true);
        let auth_ready = fds[1].any().unwrap_or(true);
        let ready_reports: Vec<RawFd> = report_fds
            .iter()
            .zip(&fds[2..])
            .filter(|(_, polled)| polled.any().unwrap_or(true))
            .map(|(fd, _)| *fd)
            .collect();
        let ready_monitors: Vec<LoginId> = monitor_logins
            .iter()
            .zip(&fds[2 + report_fds.len()..])
            .filter(|(_, polled)| polled.any().unwrap_or(true))
            .map(|(login, _)| *login)
            .collect();

        // Settled BEFORE either seam is served, and that order is
        // load-bearing: `ready_reports` names raw descriptor NUMBERS, and
        // an `Open` served first would fork a child whose fresh report pipe
        // can be handed the very number an entry finished in this pass has
        // just freed. NOT pinned by any test -- moving this call below both
        // seams leaves the suite green, and a descriptor-number race is not
        // reachable on demand -- so this is reasoning, not coverage: treat
        // it as load-bearing when you edit it.
        settle_ready_pending(seams, &mut state, &config, &ready_reports);
        // And the monitors, before the seams too, for the same reason: a
        // channel whose start this pass finishes frees its id, and an
        // `Open` served first could otherwise be refused for an id that is
        // about to be free.
        serve_ready_monitors(seams, &mut state, &ready_monitors);
        if channel_ready {
            if let Next::Stop =
                serve_channel_seam(&channels, &mut state, &config, switches.become_account)
            {
                break;
            }
        }
        if auth_ready {
            if let Next::Stop = serve_auth_seam(seams, &mut state, &config, switches) {
                break;
            }
        }
        expire_pending(seams, &mut state, &config, Instant::now());
        reap(&channels, &mut state);
    }

    // `break`, not `return`, at each of the three ways out above: this
    // helper is LEAVING, and every live login's PAM session still has to be
    // closed by the process that opened it.
    end_the_monitors(&mut state);
}

/// The helper is stopping: let every live monitor close its login's PAM
/// session before this process goes.
///
/// # Why this exists at all
///
/// Dropping a monitor's seam is how a login is ended everywhere else
/// ([`forget_login`]), and it works because the monitor is still there to
/// read the end-of-file and run `monitor::Session::close`. Letting `serve`
/// simply return would drop the same seams -- `LoopState` owns them -- and
/// then immediately race them: `run` exits the process, the monitors'
/// parent-death signal fires, and each gets a `SIGKILL` somewhere in the
/// middle of the close it had just started. Measured, on the branch that
/// added that signal: a login ended by `Request::LoginEnded` closed its
/// session (`Exited(0)`, `closed=true`), the same login with the helper
/// stopping did not (`Signaled(SIGKILL)`, `closed=false`) -- where the
/// revision before the signal closed it.
///
/// So the seams go FIRST, on their own, and the monitors get their moment
/// before this process leaves.
///
/// # What it does not cover
///
/// A helper that DIES -- killed, crashed -- never reaches this line, and
/// then the parent-death signal is exactly right: a root process with an
/// open session, reparented to init and surviving a restart of the service,
/// is worse than an unclosed session. This function is about the other
/// case, the one the signal made worse: a helper that leaves on purpose,
/// which is the ordinary end of a daemon whose worker has gone.
///
/// [`MONITOR_GRACE_PERIOD`] is the budget, the same number the helper
/// already gives a monitor to finish something it was asked to do. A close
/// that needs longer than this loses the rest of it to the parent-death
/// signal when the process exits -- the same trade-off as everywhere else
/// here, one level up, and the reason a monitor bounds its own close
/// (`monitor::MonitorPlan::session_close_budget`) rather than trusting this
/// budget to be generous.
fn end_the_monitors(state: &mut LoopState) {
    // The seam of each goes with the entry, which is what each monitor is
    // waiting to see close.
    let mut leaving: Vec<Pid> = state
        .monitors
        .drain()
        .map(|(_, monitor)| monitor.pid)
        .collect();
    if leaving.is_empty() {
        return;
    }
    let give_up_at = Instant::now() + MONITOR_GRACE_PERIOD;
    loop {
        // `reap_orphan` answers "gone", by the same `WNOHANG` pass the loop
        // uses: a monitor that has finished is reaped here rather than left
        // for an init this process is about to hand it to.
        leaving.retain(|pid| !reap_orphan(*pid));
        if leaving.is_empty() {
            return;
        }
        if Instant::now() >= give_up_at {
            break;
        }
        std::thread::sleep(REAP_INTERVAL);
    }
    crate::log::warn(
        "helper",
        &format!(
            "{} monitor(s) had not finished closing their logins' sessions within \
         {MONITOR_GRACE_PERIOD:?} of this helper stopping; what is left of those sessions goes \
         unclosed",
            leaving.len()
        ),
    );
}

/// Read one message from the channel seam and act on it.
///
/// This seam opens and closes channels and nothing else. An authentication
/// request arriving here -- `Nonce`, `ReleaseNonce`, `Verify` -- is logged
/// and dropped without an answer: an honest worker never sends one on this
/// seam, and a taken-over one must get nothing for it, above all no effect.
/// The nonce table and the verified set are shared with the authentication
/// seam (see [`LoopState`]), so honouring these here would open a second
/// door into both: a flood of `Nonce` could fill the table that seam issues
/// from, and a `Verify` could admit an account outside the one path meant to
/// do that.
fn serve_channel_seam(
    sock: &UnixStream,
    state: &mut LoopState,
    config: &HelperConfig,
    become_account: fn(Uid, Gid, &[Gid]) -> nix::Result<()>,
) -> Next {
    let message = match channel::recv(sock) {
        Ok(Some((bytes, _fd))) => bytes,
        // The worker closed its end: it is gone.
        Ok(None) => return Next::Stop,
        Err(e) => {
            crate::log::warn(
                "helper",
                &format!("receive on the channel seam failed: {e}"),
            );
            return Next::Stop;
        }
    };
    match decode::<Request>(&message) {
        Ok(Request::Open {
            id,
            uid,
            login,
            cols,
            rows,
            term,
            echo,
            shell,
            command,
        }) => {
            // Only for an account this helper verified itself
            // (`Request::Verify`, on the other seam): the uid comes from the
            // worker, and a taken-over worker would name whichever account
            // it liked. Refused before anything else -- no fork, no program
            // lookup, not even the repeated-id check below -- so a uid
            // nobody proved costs nothing and reveals nothing. The channel's
            // process then runs AS this account (in its login's monitor),
            // which is
            // what this check makes safe to do.
            //
            // Cloned out of `state.verified` (rather than borrowed) so the
            // borrow releases at once: the arms below take `state` whole.
            //
            // `verified` forgets an account once its last login has ended
            // (`Request::LoginEnded`, see `forget_login`): a worker that
            // once admitted alice cannot go on opening channels as her once
            // every login of hers is over, only for as long as at least one
            // still is. Either way it still cannot name an account whose
            // proof this helper never checked.
            let Some(account) = state.verified.get(&Uid::from_raw(uid)).cloned() else {
                crate::log::warn(
                    "helper",
                    &format!("refusing a channel for uid {uid}, which has not authenticated"),
                );
                reply(
                    sock,
                    &Response::Failed {
                        id,
                        reason: UNVERIFIED_ACCOUNT_REASON.to_string(),
                    },
                );
                return Next::Continue;
            };
            // And only under a login that is already on file, bound to this
            // very account. `Open` never creates a login entry: only the
            // `Request::Verify` that proved it does (see
            // `LoopState::logins`), and every system-mode login proves
            // itself before its first channel. So a login that is not on
            // file is one that has ended, expired, or never proved anything
            // -- and none of the three may open a channel. The first of them
            // is not exotic: nothing orders the two seams against each
            // other, so an `Open` the worker sent before `LoginEnded` can be
            // served after it. Were this arm to create the entry instead,
            // such an `Open` would put the ended login back on file while
            // another login keeps its account verified, its channel would
            // make the entry established, and nothing would ever remove it
            // again. A fresh proof for the same login is what admits it
            // again. Refused, like everything here, before anything forks.
            //
            // A login also belongs to exactly one account for its whole life
            // -- the account the proof that created it verified -- so an
            // `Open` naming another uid under it is refused too. This is
            // also where the next task's PAM session gets its key: it
            // belongs to the login, and this is what makes "this login" a
            // well-defined, single-owner thing to open one for.
            //
            // Both refusals carry the `REFUSED_REASON` every refusal of this
            // kind does; the real one goes to the helper's own log only.
            let refusal = match state.logins.get(&login) {
                Some(entry) if entry.account.uid == account.uid => None,
                Some(_) => Some("its login is already bound to a different account"),
                None => Some("its login is not on file -- it has ended, or nothing proved it"),
            };
            if let Some(why) = refusal {
                crate::log::warn("helper", &format!("refusing an Open for uid {uid}: {why}"));
                reply(
                    sock,
                    &Response::Failed {
                        id,
                        reason: REFUSED_REASON.to_string(),
                    },
                );
                return Next::Continue;
            }
            // The account's shell runs the show either way -- it is the
            // exec target for both a `shell: true` request (a login shell)
            // and a command (`<shell> -c <command>`), taken from passwd as
            // the helper verified it, never from the worker. `open_channel`
            // does the rest.
            let launch = Launch {
                id,
                cols,
                rows,
                term: term.as_deref(),
                echo,
                shell,
                command: &command,
            };
            // A repeated id is a protocol violation by the worker, not a
            // reason to silently overwrite the live entry: the shell
            // already running under it would then never be closed by
            // anyone (the worker has lost its own handle to it) and its
            // exit would be reported against a channel that is somebody
            // else's -- and, once it really exited, the id would be freed
            // out from under the second one. Refuse instead, before
            // anything is started for the new request.
            if state.live.contains_key(&id) {
                reply(
                    sock,
                    &Response::Failed {
                        id,
                        reason: "a channel with this id is already open".to_string(),
                    },
                );
                return Next::Continue;
            }
            // And how many this login may hold at once -- the last gate
            // before anything is opened or forked. Counted over `live`,
            // which holds a channel from the moment its shell is ASKED for
            // until the moment it is answered for the last time, so what is
            // bounded is what this process holds RIGHT NOW: a login that
            // closes channels as it opens them is never refused, and one
            // that only opens is. After the repeated-id check above, so a
            // worker that reuses a number still gets the precise reason
            // rather than this one -- the same order the worker's own cap
            // keeps.
            //
            // By scanning rather than by a counter kept beside the table:
            // `live` holds at most `MAX_LOGINS * MAX_CHANNELS_PER_LOGIN`
            // entries, so the scan is trivial, and a parallel counter would
            // be one more thing to keep exactly in step with every removal
            // -- a leak there would lock a login out of channels for the
            // rest of its life.
            //
            // Refuse rather than evict, exactly as the three sibling caps
            // do: evicting would let a flood take a channel away from the
            // session that is using it.
            //
            // And with the shared `REFUSED_REASON`, although the argument
            // that constant makes for itself does NOT apply here. Its
            // reason is that a precise refusal would be an account and key
            // enumerator; this one enumerates nothing, since whoever is
            // asking has already proved who they are and already holds the
            // channels being counted. The reason to share the string
            // anyway is the other half: every refusal on this path looks
            // alike, so a taken-over worker cannot map out WHICH of this
            // process's bounds it has reached by walking into them one at a
            // time and reading the answers -- and an honest worker needs no
            // detail, because it never comes near this cap (its own is
            // half of it). The real reason goes to the log above, where
            // every real reason goes.
            let held = state
                .live
                .values()
                .filter(|slot| slot.login() == login)
                .count();
            if held >= MAX_CHANNELS_PER_LOGIN {
                crate::log::warn(
                    "helper",
                    &format!(
                        "refusing an Open for uid {uid}: login {:02x}{:02x}.. already \
                     holds {held} channels, and {MAX_CHANNELS_PER_LOGIN} is the cap",
                        login[0], login[1]
                    ),
                );
                reply(
                    sock,
                    &Response::Failed {
                        id,
                        reason: REFUSED_REASON.to_string(),
                    },
                );
                return Next::Continue;
            }
            match open_channel(
                sock,
                state,
                &account,
                login,
                config,
                &launch,
                become_account,
            ) {
                Ok(master) => {
                    // The id is taken from the instant the shell is ASKED
                    // for, not from the instant the monitor reports it --
                    // see `ChannelSlot` for what a second `Open` naming it
                    // would otherwise cost.
                    state.live.insert(id, ChannelSlot::Starting(login));
                    // And this request now leaves the handler unanswered:
                    // `Opened` (with the terminal) or `Failed` goes out
                    // from the loop once the monitor has spoken, or once
                    // this entry's deadline has passed -- see
                    // `finish_channel`. Waiting for it here is exactly what
                    // used to stop every other session on the machine.
                    state.pending.insert(Pending {
                        deadline: Instant::now() + config.startup_timeout,
                        what: PendingWhat::Channel {
                            id,
                            master,
                            login,
                            uid: account.uid,
                            cancelled: false,
                        },
                    });
                }
                Err(e) => {
                    // Nothing was started: everything that can fail in
                    // there fails before the monitor is asked for a shell,
                    // so there is no channel to track and no reserved id to
                    // give back.
                    reply(
                        sock,
                        &Response::Failed {
                            id,
                            reason: format!("{e:#}"),
                        },
                    );
                }
            }
        }
        Ok(Request::Close { id }) => {
            // Whichever state the slot is in: an honest worker only ever
            // closes a channel it was told had opened, and a `Close` for
            // one still starting is its own protocol violation -- answered
            // by ending that shell, not by pretending the id is free.
            let slot = state
                .live
                .get(&id)
                .map(|slot| (slot.login(), matches!(slot, ChannelSlot::Starting(_))));
            if let Some((login, still_starting)) = slot {
                if still_starting {
                    // The monitor's `SIGHUP` ends a shell that has not
                    // exec'd yet, and its report pipe then reaches
                    // end-of-file with no data -- which is exactly what a
                    // SUCCESSFUL exec looks like, to the monitor as much as
                    // to the helper before it. Mark the entry, or the
                    // monitor's `Started` will be read as an open and the
                    // worker handed a terminal whose process is a corpse.
                    state.pending.cancel_channel(id);
                }
                // The signalling is the MONITOR's: the shell is its child,
                // and this process may not signal another process's
                // children out from under it. It sends `SIGHUP` first (a
                // shell that wants to save its history gets the chance) and
                // escalates to `SIGKILL` at `CLOSE_GRACE_PERIOD`. The
                // helper's own escalation is one level up -- see
                // `MONITOR_GRACE_PERIOD`, which is the deadline recorded
                // here.
                tell_monitor(sock, state, login, &MonitorRequest::Close { id });
                state
                    .closing
                    .insert(id, Instant::now() + MONITOR_GRACE_PERIOD);
            }
        }
        Ok(
            request @ (Request::Nonce
            | Request::ReleaseNonce { .. }
            | Request::Verify { .. }
            | Request::LoginEnded { .. }),
        ) => {
            crate::log::warn(
                "helper",
                &format!(
                    "a {} request arrived on the channel seam; dropped unanswered",
                    request_kind(&request)
                ),
            );
        }
        Err(_) => {
            // A malformed request means the worker is not the process we
            // think it is. Say so and stop rather than guess -- in words
            // of this helper's own: see `malformed_request_line`.
            crate::log::error("helper", &malformed_request_line("channel", &message));
            return Next::Stop;
        }
    }
    Next::Continue
}

/// The log line for a request from the worker that did not decode: what
/// happened, where and how long it was -- and nothing of the request or
/// of the decoder's error. `serde_json` quotes what it could not match (an
/// unknown variant or field name) verbatim, so its error text is the
/// sender's text: a newline in it would give a line of the sender's own
/// choosing this helper's genuine header in a root process's log -- a
/// forged `Failed signature for ...` a `fail2ban` filter would count.
fn malformed_request_line(seam: &str, message: &[u8]) -> String {
    format!(
        "a malformed request from the worker ({} bytes) on the {seam} seam; stopping",
        message.len()
    )
}

/// Read one message from the authentication seam and act on it.
///
/// Every request here arrives in an [`AuthRequest`], and every answer
/// leaves in an [`AuthResponse`] carrying that request's id, so the worker
/// can hand each answer to the call that asked for it, and drop one whose
/// call has already given up (see `helper::spawner::HelperAuth`). `ReleaseNonce` and `LoginEnded` are never
/// answered at all: they are tells, not asks.
///
/// This seam issues, releases and spends nonces and verifies proofs, and
/// nothing else. A channel request arriving here -- `Open`, `Close` -- is
/// logged and dropped without an answer, the mirror of what
/// [`serve_channel_seam`] does with this seam's requests: channels have a
/// seam of their own, and the worker's end of this one routes answers by
/// request number, with no room for a terminal descriptor or an `Exited`
/// notice.
fn serve_auth_seam(
    seams: Seams<'_>,
    state: &mut LoopState,
    config: &HelperConfig,
    switches: AccountSwitches,
) -> Next {
    // This seam's own end, for every answer below. The other one is needed
    // in exactly one place -- `Request::LoginEnded`, which ends that
    // login's monitor and so its channels, and a channel's end is the
    // CHANNEL seam's news.
    let sock = seams.auth;
    let message = match channel::recv(sock) {
        Ok(Some((bytes, _fd))) => bytes,
        // The worker closed its end: it is gone.
        Ok(None) => return Next::Stop,
        Err(e) => {
            crate::log::warn(
                "helper",
                &format!("receive on the authentication seam failed: {e}"),
            );
            return Next::Stop;
        }
    };
    let AuthRequest { id, body } = match decode::<AuthRequest>(&message) {
        Ok(request) => request,
        Err(_) => {
            // As on the channel seam: a malformed request means the worker
            // is not the process we think it is.
            crate::log::error(
                "helper",
                &malformed_request_line("authentication", &message),
            );
            return Next::Stop;
        }
    };
    match body {
        Request::Nonce => {
            let answer = match issue_nonce(&mut state.nonces) {
                Some(nonce) => Response::Nonce { nonce },
                None => Response::NonceUnavailable,
            };
            reply(sock, &AuthResponse { id, body: answer });
        }
        Request::ReleaseNonce { nonce } => {
            // A tell, not an ask: no reply, ever -- see the request's own
            // docs. An unknown nonce (already spent, already expired, or
            // never issued by this helper) is a harmless no-op.
            state.nonces.remove(&nonce);
        }
        Request::Verify {
            login,
            public_key,
            signature,
            handshake_hash,
            nonce,
            login_id,
            rhost,
        } => {
            // Capped before anything else happens. Every verification now
            // forks a process of its own, and nothing else bounds how many
            // may be in flight at once: `MAX_OUTSTANDING_NONCES` does not,
            // because `spend_nonce` frees a nonce's slot the moment its
            // proof arrives. A worker that has been taken over could
            // otherwise take one nonce, present a proof, take another, and
            // fork a child of the ROOT helper on every pass of the loop --
            // on a path that runs BEFORE anybody has authenticated. See
            // [`MAX_VERIFYING`].
            //
            // Checked before `spend_nonce`, so that a refusal here changes
            // nothing at all, the nonce table included -- the way the two
            // sibling caps refuse before touching their own tables. Nothing
            // depends on that order: a request refused here verifies
            // nothing, so either order keeps "at most one verification per
            // nonce". Nor is it what lets an honest client retry: an honest
            // worker never reaches this cap (see `MAX_VERIFYING`), and a
            // retry is a new handshake with a new nonce. The nonce left here
            // stays outstanding until it is released (an honest worker does
            // so as soon as its probation is refused), presented again, or
            // expires at `NONCE_LIFETIME`. The wire answer is the shared
            // `REFUSED_REASON`, so nothing out there can tell which limit
            // was reached -- or that one was.
            if state.pending.verifying() >= MAX_VERIFYING {
                crate::log::warn(
                    "helper",
                    &format!(
                        "refusing a Verify request: already checking {MAX_VERIFYING} \
                     proofs at once"
                    ),
                );
                reply(
                    sock,
                    &AuthResponse {
                        id,
                        body: Response::Refused {
                            reason: REFUSED_REASON.to_string(),
                        },
                    },
                );
                return Next::Continue;
            }
            // Step 1 happens HERE, in the parent, before the fork. Two
            // children started for one nonce would each find it unspent,
            // and both would admit -- so the one check that is cheap,
            // in-memory and order-critical stays on the loop, and
            // everything that can block goes to the child.
            if let Err(reason) = spend_nonce(&mut state.nonces, &nonce, Instant::now()) {
                crate::log::warn("helper", &format!("a Verify request was refused: {reason}"));
                reply(
                    sock,
                    &AuthResponse {
                        id,
                        body: Response::Refused {
                            reason: REFUSED_REASON.to_string(),
                        },
                    },
                );
                return Next::Continue;
            }
            match fork_verification(
                &login,
                &public_key,
                &signature,
                &handshake_hash,
                &nonce,
                config,
                switches,
            ) {
                Ok((report, child)) => {
                    // And this request now leaves the handler unanswered:
                    // `Verified` or `Refused` goes out from the loop once
                    // this child has spoken, or once its deadline has
                    // passed -- see `finish_pending`. Waiting for it here
                    // is what used to stop every other session on the
                    // machine, for as long as one account's home directory
                    // felt like taking.
                    state.pending.insert(Pending {
                        deadline: Instant::now() + config.verify_timeout,
                        what: PendingWhat::Verify {
                            report,
                            child,
                            id,
                            // Bounded HERE too, and for the same reason the
                            // address below is. The name the CHILD was
                            // forked with is the one the client sent, whole
                            // -- `getpwnam` has to be asked about the real
                            // string -- but the copy this process keeps
                            // exists for one purpose, the log line
                            // `finish_pending` writes when that child says
                            // nothing, so it is kept in the form that line
                            // may safely carry.
                            login: sanitized_login_name(&login),
                            login_id,
                            // Bounded HERE, on the way in, rather than
                            // wherever it is eventually read: what the
                            // privileged process keeps must be within its
                            // own bounds from the moment it keeps it.
                            rhost: sanitized_rhost(&rhost),
                        },
                    });
                }
                Err(e) => {
                    // Nothing was forked, and the nonce stays spent: a proof
                    // that has got as far as `spend_nonce` is spent whatever
                    // happens after, success or not. (The one refusal that
                    // leaves a nonce unspent is the `MAX_VERIFYING` cap
                    // above, which turns a request away before looking at
                    // it.)
                    crate::log::warn(
                        "helper",
                        &format!("could not fork a child to verify a proof: {e:#}"),
                    );
                    reply(
                        sock,
                        &AuthResponse {
                            id,
                            body: Response::Refused {
                                reason: REFUSED_REASON.to_string(),
                            },
                        },
                    );
                }
            }
        }
        Request::LoginEnded { login } => {
            // A tell, not an ask: no reply, ever -- mirrors `ReleaseNonce`.
            // A login never opened here, or already forgotten, is a
            // harmless no-op.
            //
            // Cancelled BEFORE the entry goes, which is what keeps every
            // remover under one rule (see `LoopState::logins`). This one
            // cannot decline to remove -- no second `LoginEnded` is coming,
            // so a removal deferred is a removal lost -- so instead of
            // asking whether a start of this login is in flight it makes
            // sure none is: each one is refused and killed by its own
            // verdict, the same path a `Close` during startup takes. Left
            // running, such a child would be a forked process holding a
            // pseudo-terminal for a login the helper has just forgotten --
            // reachable by no `Close`, owned by no entry.
            let cancelled = state.pending.cancel_login(&login);
            if cancelled > 0 {
                crate::log::info(
                    "helper",
                    &format!(
                        "login {:02x}{:02x}.. ended with {cancelled} channel(s) still \
                     starting; cancelling them",
                        login[0], login[1]
                    ),
                );
            }
            forget_login(seams.channels, state, login);
        }
        request @ (Request::Open { .. } | Request::Close { .. }) => {
            crate::log::warn(
                "helper",
                &format!(
                    "a {} request arrived on the authentication seam; dropped unanswered",
                    request_kind(&request)
                ),
            );
        }
    }
    Next::Continue
}

/// A request's name, for a log line -- never its content, which for an
/// `Open` can be a long command line and for a `Verify` a whole proof.
fn request_kind(request: &Request) -> &'static str {
    match request {
        Request::Open { .. } => "Open",
        Request::Close { .. } => "Close",
        Request::Nonce => "Nonce",
        Request::ReleaseNonce { .. } => "ReleaseNonce",
        Request::Verify { .. } => "Verify",
        Request::LoginEnded { .. } => "LoginEnded",
    }
}

/// Ensure a login entry exists for `login`, tied to `account` -- called by
/// `Request::Verify`'s success arm, and by nothing else: a login exists from
/// the moment its account proves itself, before it has opened any channel
/// at all (fix F2 -- see that request's own docs for why leaving it out
/// until a first `Open` reopened a window `Request::LoginEnded` was meant to
/// close), and `Request::Open` never creates one (see `LoopState::logins`).
///
/// Enforces both halves of the invariant a login keeps for its whole life:
/// capped by [`MAX_LOGINS`] the way a nonce is capped by
/// `MAX_OUTSTANDING_NONCES` (a login's token is chosen by the device
/// presenting its proof, so a fresh one must cost nothing to refuse); and
/// bound to exactly one account for its whole life (the FIRST account a
/// proof verified for a login wins -- a later proof for the same token
/// naming another account is refused, and `Request::Open` refuses an `Open`
/// naming another uid under it). Both refusals share `REFUSED_REASON` on the
/// wire (the error string returned here is for the caller's OWN log line
/// only, never sent to the worker), so neither leaks which one fired.
///
/// A new entry starts PROVISIONAL ([`LoginState::provisional`]): the helper
/// drops it on its own if no channel ever opens under it within
/// [`LOGIN_GRACE`], so a proof that verifies and then goes nowhere -- the
/// worker's session caps refusing the admission, a client that vanishes, a
/// lost datagram -- cannot leave anything behind in the privileged process.
/// See [`sweep_expired_logins`]. An entry already on file is left exactly as
/// it is -- a repeat proof renews neither its grace nor anything else.
fn ensure_login(
    state: &mut LoopState,
    login: LoginId,
    account: &Account,
    rhost: String,
) -> Result<u64, &'static str> {
    if !state.logins.contains_key(&login) && state.logins.len() >= MAX_LOGINS {
        return Err("already holding MAX_LOGINS logins");
    }
    // Taken before the entry is touched, and spent only if one is really
    // created: `or_insert_with` runs its closure at most once, so a repeat
    // proof for a token already on file keeps the incarnation it has. That
    // is what makes a warm reattach -- which re-proves under the same token
    // -- leave the number alone, so a notice still in flight for THIS life
    // of the login is acted on rather than mistaken for a stale one.
    let fresh = state.next_incarnation;
    let entry = state
        .logins
        .entry(login)
        .or_insert_with(|| LoginState::provisional(account.clone(), rhost, fresh));
    if entry.account.uid != account.uid {
        return Err("its login is already bound to a different account");
    }
    let incarnation = entry.incarnation;
    if incarnation == fresh {
        state.next_incarnation += 1;
    }
    Ok(incarnation)
}

/// A login is over for good: take its monitor down, drop its entry, and
/// drop the account it belonged to from `verified` once no OTHER login of
/// that same account is still on file -- the threat model promises only
/// whoever is connected right now, not whoever ever connected (see the
/// slice's own review finding, referenced from `LoopState::verified`'s
/// docs).
///
/// **The one door.** Every way a login can end comes through here: the
/// worker reporting it (`Request::LoginEnded`), the age sweep
/// ([`sweep_expired_logins`]), and every way its MONITOR can be lost --
/// killed for not answering, unreachable, or dead on its own
/// ([`lose_monitor`], `reap`, [`serve_ready_monitors`]). That is what keeps
/// the two tables from ever disagreeing, and what makes a login's monitor
/// unique for that login's whole life: see [`LoopState::monitors`] for what
/// a second one would mean from the next task on.
///
/// **And the worker is told** ([`Response::LoginEnded`]), whenever there
/// was an entry to remove and for no other reason. That telling lives here
/// for the same
/// reason the monitor's teardown does: every way a login can end already
/// converges on this one door, and a telling lifted out to the callers is
/// one that a path added later forgets. A login whose end the worker never
/// hears leaves it holding a session that is STERILE -- it pings fine and
/// every channel it asks for is refused, for good -- and the person sees
/// not a disconnect but a channel that will not open. The worker cannot
/// work that out for itself: a refusal carries one shared reason whatever
/// caused it ([`REFUSED_REASON`]), deliberately, so that a taken-over
/// worker cannot enumerate accounts.
///
/// **"There was an entry", not "the entry was established."** The narrower
/// gate looks safer and is worse, because the two predicates are exact
/// complements: [`sweep_expired_logins`] selects on `!established`, so a
/// notice gated on `established` can never fire for the one class of login
/// the helper's own garbage collector ends. A client that proves itself,
/// gets a live session bound, and then opens no channel within
/// [`LOGIN_GRACE`] -- an app frozen by Doze right after connecting is
/// enough, against a retention of an hour -- loses its login from under a
/// session that is kept, and that is exactly the symptom this notice
/// exists to end. The same shape covers a monitor that dies DURING the
/// first `Open` and a PAM stack that refuses the first channel: both end a
/// login while it is still provisional.
///
/// Nor does the narrow gate buy anything against enumeration. Every entry
/// in [`LoopState::logins`] was created by [`ensure_login`] out of the
/// worker's OWN `Request::Verify`, provisional ones included, so naming any
/// of them tells a taken-over worker nothing it did not already have. What
/// must never be named is a token the helper never held -- and that is what
/// the `let Some(ended)` guard below is for, not `established`.
///
/// The first two halves are unconditional, and deliberately so: the entry
/// is removed
/// whether or not it was there, and the monitor is taken down whether or
/// not the entry was. A login with no entry but a live monitor is exactly
/// the state this function exists to make unreachable, so it must not be a
/// state this function can return from. NOT pinned by a test -- making the
/// monitor's half conditional on the entry having been there leaves the
/// whole suite green, precisely because every caller reaches here with the
/// two in step, so no test can tell the difference -- so this is reasoning,
/// not coverage: treat it as load-bearing when you edit it. It is a belt
/// over braces, and the braces are what the rest of these docs describe.
///
/// **What a user sees that they did not before.** A login that ends while a
/// channel is still open now takes that channel's shell -- and everything
/// under it -- down within `CLOSE_GRACE_PERIOD`, and the worker is told the
/// channel exited (code 137). The worker's router ends a login not only on
/// a graceful close but on eviction and on garbage collection past
/// retention (`transport::session_manager`), so a session collected while
/// its channel was open used to leave that shell running and now does not.
/// That is the right way round: a shell left behind would be a root-forked
/// process under an account whose verification this same call has just
/// dropped, holding a pseudo-terminal that no `Close` can name any more --
/// the worker cannot close a channel of a login it has already reported as
/// ended. For this product the cost is small, since the work that must
/// survive lives in tmux on the server rather than in the channel's own
/// shell; but "the session was collected" went from harmless to
/// destructive, and that is worth knowing before reading a bug report about
/// it. `a_login_that_ends_takes_its_open_channels_with_it` pins it.
fn forget_login(sock: &UnixStream, state: &mut LoopState, login: LoginId) {
    let ended = state.logins.remove(&login);

    // Taking the monitor down is INLINED here, and deliberately not a
    // function of its own. While it was one (`shut_down_monitor`), six of
    // the seven places that lose a monitor could be made to call IT instead
    // of this function -- which compiles, passes every test, and is exactly
    // the bug the fix round before this one removed. There is now nothing
    // to call wrongly: a monitor can only be taken down by the code that
    // has just removed its login entry, in the line above. Do not lift this
    // back out; if it grows, it grows here.
    //
    // Dropping the helper's end of the seam is what ends a live monitor:
    // its own end reaches end-of-file, it takes its shells down (`SIGHUP`,
    // then `SIGKILL`) and exits, and every shell that somehow outran that
    // dies with it through the parent-death signal each one armed before
    // its `execve`. Its pid goes to `orphans`, because nothing here waits
    // for it: a monitor gets the same treatment as every other child this
    // helper has given up on (see `reap`).
    //
    // The channels go with it, and the worker is told so -- it is the only
    // half that can close a channel, and one it never hears the end of is a
    // session it waits on for ever. A channel still STARTING is refused
    // instead, since the worker has had no answer to its `Open` yet.
    if let Some(monitor) = state.monitors.remove(&login) {
        drop(monitor.seam);
        state.orphans.push(monitor.pid);

        let hers: Vec<(ChannelId, bool)> = state
            .live
            .iter()
            .filter(|(_, slot)| slot.login() == login)
            .map(|(id, slot)| (*id, matches!(slot, ChannelSlot::Running(_))))
            .collect();
        for (id, running) in hers {
            if running {
                // 128 plus the signal number, the way every other signalled
                // exit is reported: a shell of a monitor that is gone was
                // killed, by that monitor or by the kernel on its behalf.
                report_exit(
                    sock,
                    state,
                    id,
                    128 + nix::sys::signal::Signal::SIGKILL as i32,
                );
            } else {
                let Some(pending) = state.pending.take_channel(id) else {
                    // Not waiting on it any more -- some earlier step of
                    // this same pass already settled it.
                    continue;
                };
                let PendingWhat::Channel { master, .. } = pending.what else {
                    continue;
                };
                drop(master);
                refuse_starting_channel(
                    sock,
                    state,
                    id,
                    "the monitor of the login this channel belongs to is gone".to_string(),
                );
            }
        }
    }

    let Some(ended) = ended else {
        return;
    };
    let uid = ended.account.uid;
    let still_has_a_live_login = state.logins.values().any(|l| l.account.uid == uid);
    if !still_has_a_live_login {
        state.verified.remove(&uid);
    }

    // And the worker is told, because nothing else will tell it: see
    // `Response::LoginEnded`, and this function's own docs for why the
    // telling lives HERE rather than in any of the callers, and why the
    // condition is "there was an entry" rather than "the entry was
    // established" -- the narrower one is silent for exactly the logins the
    // age sweep ends.
    //
    // Inside the `Some(ended)` arm, which is the whole gate: a token the
    // helper never held is named to nobody.
    //
    // LAST, after the block above has reported every channel of this login
    // as exited: the worker settles each channel's waiter first and only
    // then hears that the session behind them is over. Nothing depends on
    // the order today -- the worker ends the session either way -- but the
    // other order would have it tear the session down with channel waiters
    // still parked on answers that are already on the seam behind it.
    reply(
        sock,
        &Response::LoginEnded {
            login,
            incarnation: ended.incarnation,
        },
    );
}

/// A monitor that cannot serve its login any more: say why, kill it, and
/// end the login with it ([`forget_login`]).
///
/// Killing it without ending the login would leave an entry whose next
/// `Request::Open` forks a SECOND monitor for one login -- see
/// [`LoopState::monitors`] for why that is the one thing this table may
/// never allow. The client is not stranded by this: a fresh proof admits
/// the device again, under a login of its own.
fn lose_monitor(sock: &UnixStream, state: &mut LoopState, login: LoginId, why: &str) {
    let Some(pid) = state.monitors.get(&login).map(|monitor| monitor.pid) else {
        return;
    };
    crate::log::warn(
        "helper",
        &format!(
            "the monitor of login {:02x}{:02x}.. {why}; killing it and ending the login",
            login[0], login[1]
        ),
    );
    log_failed_kill(
        nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL),
        pid,
        "SIGKILL to a monitor that cannot serve",
    );
    forget_login(sock, state, login);
}

/// Send one request to a login's monitor. Nothing answers here: what the
/// monitor has to say comes back on its seam, which the loop polls.
///
/// A send that fails is a monitor that is gone or wedged -- the send is
/// bounded (`SEAM_SEND_TIMEOUT`, set when the monitor was forked), because
/// a monitor that stopped reading must not be able to stop the helper that
/// serves every session on the machine. Either way that monitor's LOGIN
/// ends with it ([`lose_monitor`]): what it was asked to do cannot reach
/// it, and a monitor nobody can reach can only hold its channels open for
/// good.
fn tell_monitor(
    sock: &UnixStream,
    state: &mut LoopState,
    login: LoginId,
    request: &MonitorRequest,
) {
    let Some(monitor) = state.monitors.get(&login) else {
        return;
    };
    let failed = match encode(request) {
        Ok(bytes) => channel::send(&monitor.seam, &bytes, None)
            .err()
            .map(|e| e.to_string()),
        Err(e) => Some(e.to_string()),
    };
    if let Some(why) = failed {
        lose_monitor(sock, state, login, &format!("could not be reached ({why})"));
    }
}

/// Read one event from each monitor whose seam `poll` has just reported
/// ready, and act on it.
///
/// One event per monitor per pass, the way each seam serves one message per
/// pass: a monitor with a backlog cannot starve the others, and the loop
/// comes straight back for the rest (`poll` returns at once while anything
/// is still readable).
fn serve_ready_monitors(seams: Seams<'_>, state: &mut LoopState, ready: &[LoginId]) {
    for login in ready {
        let Some(monitor) = state.monitors.get(login) else {
            // Gone already -- an earlier step of this same pass took it
            // down (its login ended, or another of its events did).
            continue;
        };
        let message = match channel::recv(&monitor.seam) {
            Ok(Some((bytes, _fd))) => bytes,
            // The monitor closed its end, or died: either way it is gone,
            // and so are its login and every channel of it. The LOGIN goes
            // too, and not only the monitor -- an entry left behind would
            // be given a monitor of its own by its next `Open`, and one
            // login may never have two (see `LoopState::monitors`).
            Ok(None) => {
                crate::log::warn(
                    "helper",
                    &format!(
                        "the monitor of login {:02x}{:02x}.. is gone; ending the login \
                     and its channels",
                        login[0], login[1]
                    ),
                );
                forget_login(seams.channels, state, *login);
                continue;
            }
            Err(e) => {
                crate::log::warn(
                    "helper",
                    &format!(
                        "receiving from the monitor of login {:02x}{:02x}.. failed: {e}; \
                     ending the login",
                        login[0], login[1]
                    ),
                );
                forget_login(seams.channels, state, *login);
                continue;
            }
        };
        match decode::<MonitorEvent>(&message) {
            Ok(MonitorEvent::Started { id }) => {
                finish_channel(seams.channels, state, id, StartupReport::Started)
            }
            Ok(MonitorEvent::Failed { id, errno }) => finish_channel(
                seams.channels,
                state,
                id,
                StartupReport::Failed(nix::Error::from_raw(errno)),
            ),
            Ok(MonitorEvent::Exited { id, code }) => report_exit(seams.channels, state, id, code),
            // The login's PAM stack refused it, so no session was opened and
            // no shell forked. The real reason is written down HERE, in the
            // one process that has a log (a monitor may not write to it --
            // see `monitor`'s module docs), and the worker is told only the
            // shared `REFUSED_REASON`: which check refused a login is
            // exactly what a worker that has been taken over must not be
            // able to enumerate.
            //
            // The monitor ends itself after saying this, so its login ends
            // too, through the same one door every other lost monitor takes
            // (`forget_login`, reached from the end-of-file this seam is
            // about to reach). Nothing here has to do that: doing it twice
            // is what leaves the two tables disagreeing.
            Ok(MonitorEvent::Refused { id, why }) => {
                crate::log::warn(
                    "helper",
                    &format!(
                        "the PAM stack refused login {:02x}{:02x}.. at channel {id}: \
                     {why}; refusing the channel and ending the login",
                        login[0], login[1]
                    ),
                );
                refuse_channel_outright(seams.channels, state, id);
            }
            // The stack let this login IN and complained while doing it: an
            // `optional` module that failed, a password about to expire.
            // Nothing is refused -- the channel is answered exactly as it
            // would have been -- but the line has nowhere else to go: the
            // person logging in has no interactive side while their session
            // is being opened, and a monitor may not write to this file
            // itself (see `monitor`'s module docs).
            Ok(MonitorEvent::Noted { id, what }) => crate::log::info(
                "helper",
                &format!(
                    "the PAM stack of login {:02x}{:02x}.. admitted channel {id} and \
                 said: {what}",
                    login[0], login[1]
                ),
            ),
            // A monitor could not signal its own child. `EPERM` above all,
            // which is what a service unit that stopped granting `CAP_KILL`
            // (spec §8.3) looks like from in there -- and what would
            // otherwise be silent, since a monitor may not write to the log
            // (see `monitor`'s module docs). Same wording as
            // `log_failed_kill`, which used to say this when the helper
            // still signalled channels itself.
            Ok(MonitorEvent::SignalFailed { id, signal, errno }) => crate::log::warn(
                "helper",
                &format!(
                    "signal {signal} to channel {id}'s process failed in the monitor of \
                 login {:02x}{:02x}..: {} -- the process may outlive its channel (does the \
                 service unit grant CAP_KILL?)",
                    login[0],
                    login[1],
                    nix::Error::from_raw(errno)
                ),
            ),
            Err(e) => {
                // A monitor is this helper's own code, one fork away. A
                // message that does not decode is not a monitor.
                crate::log::warn(
                    "helper",
                    &format!(
                        "the monitor of login {:02x}{:02x}.. said something that is not \
                     an event ({e}); ending the login",
                        login[0], login[1]
                    ),
                );
                forget_login(seams.channels, state, *login);
            }
        }
    }
}

/// Collect every monitor that has exited, finish reaping whatever is left
/// in `orphans`, and escalate a `Close` no monitor has answered.
///
/// Waits only on pids this helper itself forked -- NOT `waitpid(None, ...)`,
/// which reaps *any* child of this process. That matters even here, in the
/// test binary: `helper::channel`'s leak-check test
/// (`a_second_descriptor_in_one_message_is_not_leaked_body`) spawns this
/// very test binary as a subprocess and calls its own blocking `wait()` on
/// it, and every `helper::server` test runs a loop of this function on its
/// own thread, in the same process, concurrently. A `waitpid(None, ...)`
/// here could reap that unrelated subprocess first, leaving the other
/// test's `wait()` to see `ECHILD` for a child it never actually lost.
///
/// A channel's own shell is NOT among these: it is the monitor's child, and
/// only the monitor may wait on it. What reaches the worker as `Exited` is
/// what that monitor reports (see [`serve_ready_monitors`]).
///
/// Every wait here is `WNOHANG`: a corpse that is not ready yet (`SIGKILL`
/// does not take effect immediately for a process stuck in uninterruptible
/// sleep) is left in `orphans` for the next pass rather than blocked on.
///
/// Also escalates: any id still in `closing` whose
/// [`MONITOR_GRACE_PERIOD`] has passed with no exit reported has its
/// LOGIN'S MONITOR killed -- see that constant's docs for why the helper's
/// escalation is one level up from the monitor's own.
fn reap(sock: &UnixStream, state: &mut LoopState) {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

    // Snapshot first: `forget_login` mutates `monitors`, so mutating it
    // while iterating it directly would be a borrow conflict.
    let monitors: Vec<(LoginId, Pid)> = state
        .monitors
        .iter()
        .map(|(login, monitor)| (*login, monitor.pid))
        .collect();
    for (login, pid) in monitors {
        let gone = loop {
            match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => break true,
                // Still running, or (should not happen -- `monitors` only
                // ever holds pids this process itself forked) not our
                // child.
                Ok(_) | Err(nix::Error::ECHILD) => break false,
                Err(nix::Error::EINTR) => continue,
                Err(e) => {
                    crate::log::warn("helper", &format!("waitpid({pid}) failed: {e}"));
                    break false;
                }
            }
        };
        if gone {
            crate::log::warn(
                "helper",
                &format!(
                    "the monitor of login {:02x}{:02x}.. exited; ending the login and \
                 its channels",
                    login[0], login[1]
                ),
            );
            // The LOGIN goes with it, not only the monitor: an entry left
            // behind would be given a second monitor by its next `Open`,
            // which is the one thing `LoopState::monitors` may never allow.
            forget_login(sock, state, login);
            // `forget_login` pushed this pid to `orphans`, where the sweep
            // below finds it already reaped and drops it.
        }
    }
    // No channel id was ever handed out for a verifying child, and a
    // monitor's exit has already been acted on above -- so there is nothing
    // left to report for either, only reaping to finish once each is truly
    // gone.
    state.orphans.retain(|&pid| !reap_orphan(pid));

    let now = Instant::now();

    // Nonces past NONCE_LIFETIME are swept here too, on the same pass:
    // releasing one (see `Request::ReleaseNonce`) would remove it before
    // this ever needs to -- this is what bounds the table for a nonce
    // nobody follows up on.
    sweep_expired_nonces(&mut state.nonces, now);

    // And, on the same pass and the same timescale, logins that verified
    // and never became real: a `Request::LoginEnded` (see
    // `forget_login`) would remove one before this ever needs to -- this
    // is what bounds the table for a login nobody follows up on. See
    // `LOGIN_GRACE`.
    sweep_expired_logins(sock, state, now);

    // Escalate any channel `Close` asked to end whose monitor has still not
    // reported an exit -- see `MONITOR_GRACE_PERIOD`'s docs. Collected into
    // a separate `Vec` first, rather than acted on from inside `retain`'s
    // closure, only to keep the borrow of `live` (immutable, `get`) out of
    // the same expression as `closing`'s own mutable borrow.
    let mut escalate: Vec<ChannelId> = Vec::new();
    let live = &state.live;
    state.closing.retain(|id, deadline| match live.get(id) {
        // Already gone -- reported by its monitor just now, or on an
        // earlier pass before `closing` got a chance to run. Either way,
        // nothing left to escalate.
        None => false,
        Some(_) if now < *deadline => true,
        Some(_) => {
            escalate.push(*id);
            false
        }
    });
    for id in escalate {
        let Some(login) = state.live.get(&id).map(ChannelSlot::login) else {
            continue;
        };
        // And the login goes with its monitor -- see `lose_monitor`, and
        // `LoopState::monitors` for what a second monitor for one login
        // would mean from the next task on.
        lose_monitor(
            sock,
            state,
            login,
            &format!(
                "did not report channel {id} as exited within {MONITOR_GRACE_PERIOD:?} of its \
                 Close"
            ),
        );
    }
}

/// Log a `kill` that failed, instead of discarding it. Now that a channel's
/// process runs as another uid, `kill(2)` from the root helper to it needs
/// `CAP_KILL` -- which the packaged unit (spec §8.3) must grant. If it does
/// not, every signal here fails with `EPERM`, and a `SIGHUP`-ignoring
/// channel would then never die and never be reaped: a silent `let _ =`
/// would leave nothing in the log to say why. `ESRCH` (the process already
/// exited, between the caller's `live` lookup and this signal) is ordinary
/// and not logged.
fn log_failed_kill(result: nix::Result<()>, pid: Pid, what: &str) {
    match result {
        Ok(()) | Err(nix::Error::ESRCH) => {}
        Err(e) => crate::log::warn(
            "helper",
            &format!(
                "{what} to channel process {pid} failed: {e} -- the process may \
             outlive its channel (does the service unit grant CAP_KILL?)"
            ),
        ),
    }
}

/// Mint a fresh, single-use nonce and remember when it was issued, or
/// refuse if the table already holds [`MAX_OUTSTANDING_NONCES`] -- see that
/// constant's docs for why refusing beats evicting here. Spending one --
/// checking a client's echoed-back proof against this table -- is
/// [`spend_nonce`]'s job, called from `serve_auth_seam` as step 1 of a
/// proof's check; this
/// function only issues, and, via `reap`'s sweep, expires what nobody
/// spends or releases.
///
/// The bytes come from [`transport::random_nonce`] -- the operating system's
/// own randomness, never a thread-local generator whose state this process
/// inherited across the split; see that function's docs for why the whole
/// replay defence would otherwise rest on two facts about other people's
/// code.
fn issue_nonce(nonces: &mut HashMap<Nonce, Instant>) -> Option<Nonce> {
    if nonces.len() >= MAX_OUTSTANDING_NONCES {
        return None;
    }
    // A collision is vanishingly unlikely at 16 random bytes, but the table
    // can rule it out for itself with one extra check rather than assume it.
    loop {
        let nonce: Nonce = transport::random_nonce();
        if let std::collections::hash_map::Entry::Vacant(entry) = nonces.entry(nonce) {
            entry.insert(Instant::now());
            return Some(nonce);
        }
    }
}

/// Remove every nonce whose age has reached [`NONCE_LIFETIME`], given `now`.
/// A pure function of its two inputs (no `Instant::now()` of its own) so the
/// boundary is testable with synthetic instants, rather than an actual 30s
/// wait.
fn sweep_expired_nonces(nonces: &mut HashMap<Nonce, Instant>, now: Instant) {
    nonces.retain(|_, issued_at| now.saturating_duration_since(*issued_at) < NONCE_LIFETIME);
}

/// Drop every login that never became REAL and has now aged past
/// [`LOGIN_GRACE`] -- see that constant's docs for why the privileged
/// process has to bound its own table rather than wait for the unprivileged
/// worker to report each one.
///
/// Keyed on `LoginState::established` and on NOTHING else. In particular an
/// established login with an EMPTY `channels` set is not expirable: since
/// fix F5 a set goes empty the moment `reap` reports the last channel's
/// exit, and a session whose shell has ended but whose connection is still
/// up is exactly the case fix F2 had to protect. Expiring by age alone, or
/// by emptiness, would reintroduce F2's own bug in a worse form.
///
/// Ends each expired login through [`forget_login`], the same path a
/// genuine `Request::LoginEnded` takes: the entry goes AND -- if it was the
/// last login of its account -- so does that account's place in `verified`,
/// which is the half that actually matters here (a leaked entry's real cost
/// is that the helper goes on trusting its uid).
///
/// A pure function of its inputs (`now` is passed in, no `Instant::now()` of
/// its own), the way [`sweep_expired_nonces`] is, so the boundary is
/// testable with synthetic instants instead of a 30-second wait.
///
/// Asks whether a start of the login is still in flight, and declines to
/// remove while one is: a remover that does not ask drops an entry out from
/// under a channel that is about to open -- see the enumeration in
/// `LoopState::logins`'s docs, where `Request::LoginEnded`, the one other
/// remover, is the one that cannot decline.
fn sweep_expired_logins(sock: &UnixStream, state: &mut LoopState, now: Instant) {
    // Collected first: `forget_login` needs `logins` mutably, and it also
    // has to see the OTHER entries to decide whether the account keeps its
    // verification -- neither is possible from inside a `retain` closure.
    // The table holds at most `MAX_LOGINS` entries, so this scan is
    // trivial, and it runs on `reap`'s pass, never on a per-byte path.
    // Each entry's uid is taken HERE, while it still exists: `forget_login`
    // below removes it, and the log line is the only record that would
    // explain the symptom an operator actually sees (a session whose
    // channels are refused from now on), so it has to name the account. Two
    // bytes of the token go with it -- enough to line this up with the
    // worker's own lifecycle lines for the same login, and too little to
    // matter to anyone reading this log, which is privileged-side only in
    // any case: two bytes of sixteen do not name a login, and a token is no
    // credential on its own -- every use of one needs a verified proof from
    // the account it belongs to. (It is not on the wire in the clear either:
    // msg1 carries it encrypted.)
    let pending = &state.pending;
    let expired: Vec<(LoginId, u32)> = state
        .logins
        .iter()
        .filter(|(id, login)| {
            // A login is in use while ANYTHING of its still exists, and a
            // channel between its fork and its verdict is one of those
            // things -- `LoginState::channels` does not know about it yet.
            // `established` is only set when that verdict
            // lands, so a login whose FIRST `Open` is in flight is
            // otherwise provisional -- and sweepable -- for the whole start
            // window, and `forget_login` would take its account's
            // verification with it while that channel is live.
            !pending.holds_login(id)
                && !login.established
                && now.saturating_duration_since(login.created_at) >= LOGIN_GRACE
        })
        .map(|(id, login)| (*id, login.account.uid.as_raw()))
        .collect();
    for (login, uid) in expired {
        crate::log::warn(
            "helper",
            &format!(
                "dropping login {:02x}{:02x}.. for uid {uid} -- it verified \
             {LOGIN_GRACE:?} ago and never opened a channel",
                login[0], login[1]
            ),
        );
        forget_login(sock, state, login);
    }
}

/// Step 1 of checking a proof, taken by the loop itself before any child is
/// forked: is `nonce` ours, unspent, and unexpired?
/// Removed unconditionally when found -- whether the answer that follows is
/// "admitted" or "expired" -- so an expired entry does not survive this
/// call either, the same promise `sweep_expired_nonces` keeps on its own
/// pass. A pure function of its inputs (`now` is passed in, not read
/// internally), the same way `sweep_expired_nonces` is, so the boundary is
/// testable with synthetic instants rather than an actual `NONCE_LIFETIME`
/// wait. The `Err` string is the exact reason `serve_auth_seam` logs.
fn spend_nonce(
    nonces: &mut HashMap<Nonce, Instant>,
    nonce: &Nonce,
    now: Instant,
) -> Result<(), &'static str> {
    let issued_at = nonces
        .remove(nonce)
        .ok_or("nonce unknown or already spent")?;
    if now.saturating_duration_since(issued_at) >= NONCE_LIFETIME {
        return Err("nonce expired");
    }
    Ok(())
}

/// [`verify_proof_after_nonce`]'s step 2 policy: `permit_root` is about uid
/// 0, whatever
/// the account's name happens to be (aliases such as `toor` included) --
/// see `HelperConfig::permit_root`'s docs. Pulled out to one place so
/// nothing can duplicate this check with a name comparison instead of a uid
/// one; a synthetic `Account` exercises every case without needing a
/// second uid-0 passwd entry on the test machine.
fn root_refused(config: &HelperConfig, account: &Account) -> bool {
    !config.permit_root && account.uid.is_root()
}

/// Check one `Request::Verify` against everything the helper itself must
/// verify, MINUS the nonce -- see that request's own docs for why this runs
/// in the privileged process at all, rather than being taken on the
/// worker's word: a taken-over worker's claim "this is alice" must never be
/// believed.
///
/// Runs in the VERIFYING CHILD (`fork_verification`), never on the loop.
/// Every step below can block for as long as somebody else's file system or
/// directory server feels like, and the helper serves every session on the
/// machine from one thread.
///
/// Step 1 -- was this nonce ours, unspent and unexpired? -- is deliberately
/// NOT here. It belongs to the parent, before the fork: two children
/// started for one nonce would each find it unspent, and both would admit.
/// This function has no access to the nonce table to spend it with, so the
/// order cannot be got wrong by accident. See `serve_auth_seam`'s `Verify`
/// arm.
///
/// The order of what remains is required, not incidental:
///
/// 2. Does the login name resolve, and is it allowed? A refused root login
///    stops here, before the key file is touched.
/// 3. Does the signature verify over "qsh-auth-v2" || hash || nonce || login?
///    Checked BEFORE the key file is read, so a request whose signature does
///    not verify costs no read of the key file. This is NOT a guard against an
///    unauthenticated client making the helper read an account's file:
///    anyone can make a verifying signature with a key of their own. What
///    the order does buy is that the file is read for EVERY verifying
///    signature, listed key or not, so the answer's timing does not reveal
///    whether a key is listed. (Whether an ACCOUNT exists still shows in the
///    timing: step 2 refuses a missing one before any of this. `sshd` has
///    the same leak.)
/// 4. Is the key listed in that account's authorized_keys, read as the
///    account itself?
///
/// On success, returns the account this proof admitted, its key's
/// fingerprint (for `Response::Verified`'s `identity`) and its key's family
/// name (for the accept line's `key <ALGORITHM>` field). On refusal, returns
/// a [`VerifyRefusal`] -- see that type's docs for why it carries more than
/// prose.
#[allow(clippy::too_many_arguments)]
fn verify_proof_after_nonce(
    login: &str,
    public_key: &[u8],
    signature: &[u8],
    handshake_hash: &[u8; 32],
    nonce: &Nonce,
    config: &HelperConfig,
    switches: AccountSwitches,
) -> Result<(Account, String, String), VerifyRefusal> {
    // 2.
    let account = (switches.lookup)(login).map_err(|e| VerifyRefusal {
        reason: format!("account lookup: {e}"),
        // A positive claim, made only when step 2 itself is sure there is
        // no such account -- see the field's own docs.
        unknown_account: matches!(e, AccountError::NoSuchAccount | AccountError::BadName),
    })?;
    if root_refused(config, &account) {
        return Err(VerifyRefusal::other(
            "root login refused: permit_root is off",
        ));
    }

    // 3. `sshauth::verify::verify_record_signature` is the SAME function the
    // personal mode's `AuthorizedKeysVerifier` uses, over the SAME
    // `record_challenge`, so the two modes cannot drift on what counts as a
    // verifying signature.
    let record = AuthRecord {
        public_key: public_key.to_vec(),
        signature: signature.to_vec(),
        v2: Some(AuthV2 {
            login: login.to_string(),
            nonce: *nonce,
        }),
    };
    let key = sshauth::verify::verify_record_signature(handshake_hash, &record)
        .map_err(|e| VerifyRefusal::other(format!("signature: {e}")))?;

    // 4. `read_keys` reads the file (production: as the account itself, via
    // `authorized::read_for`); `key_is_listed` is the SAME parsing and
    // matching the personal mode's verifier uses -- never a second parser,
    // see that function's docs.
    let text = (switches.read_keys)(&account, &config.authorized_keys_template)
        .map_err(|e| VerifyRefusal::other(format!("reading authorized_keys: {e}")))?;
    if !sshauth::verify::key_is_listed(&text, &key)
        .map_err(|e| VerifyRefusal::other(format!("matching authorized_keys: {e}")))?
    {
        return Err(VerifyRefusal::other("key not listed"));
    }

    let identity = sshauth::verify::fingerprint(&key);
    let algorithm = sshauth::verify::algorithm_label(&key).to_string();
    Ok((account, identity, algorithm))
}

/// Why [`verify_proof_after_nonce`] refused a proof: the DETAILED reason --
/// for the helper's own log only, never for the wire; every refusal crosses
/// the seam as the same [`REFUSED_REASON`], see that constant's docs for why
/// -- plus the one fact `finish_pending` needs to pick which of §10's two
/// refuse-line shapes to write.
///
/// `unknown_account` is not derived by matching `reason`'s text back at that
/// call site: `reason` is documented, here and at every one of its call
/// sites, as free-form log prose for a human, and parsing it back into
/// control flow is exactly the kind of coupling that lets the two quietly
/// drift apart the next time someone rewords a message. The check that
/// already knows the fact -- step 2's account lookup, and only step 2's --
/// states it directly instead.
struct VerifyRefusal {
    reason: String,
    /// True only when step 2's lookup itself says there is no such account
    /// (`AccountError::NoSuchAccount`/`BadName`). A lookup that failed for
    /// some OTHER reason (`Groups`, `Backend` -- the name service errored,
    /// or the account resolved but its group list could not be read) does
    /// not claim to know the account is missing, so it is not folded in
    /// here: §10's `invalid user` wording is a positive claim, made only
    /// when this function is sure of it.
    unknown_account: bool,
}

impl VerifyRefusal {
    /// A refusal from anywhere past step 2: the account exists (this
    /// function got that far), so `unknown_account` is always `false`.
    fn other(reason: impl Into<String>) -> VerifyRefusal {
        VerifyRefusal {
            reason: reason.into(),
            unknown_account: false,
        }
    }
}

/// The most supplementary groups a verdict record may carry -- Linux's own
/// `NGROUPS_MAX`.
///
/// In practice [`MAX_VERDICT_LEN`] binds long before this does (a list this
/// long would be a quarter of a megabyte), but both are checked, on both
/// sides of the pipe. The count is a number read off a descriptor, and a
/// parser that trusts a length field to be sane is how a privileged process
/// is talked into allocating on demand.
const NGROUPS_MAX: usize = 65_536;

/// The most a verifying child may write about one account.
///
/// The same cap the seam itself uses, for the same reason: the reader is
/// the privileged loop, and an unbounded record is an unbounded allocation
/// there. 512 bytes would not do -- one account's supplementary group list
/// alone can be longer than that -- while 8 KiB leaves room for a name, a
/// home, a shell, a fingerprint and some two thousand groups.
const MAX_VERDICT_LEN: usize = super::protocol::MAX_MESSAGE_LEN;

/// The outcome byte at the head of every verdict record.
const VERDICT_ADMITTED: u8 = 1;
/// The other outcome -- see [`VERDICT_ADMITTED`].
const VERDICT_REFUSED: u8 = 0;

/// What the verifying child tells the loop, and the only thing the loop
/// learns from it.
///
/// `Admitted` carries the WHOLE account, not merely its uid and name,
/// because `LoopState::verified` stores an `Account` and a channel takes
/// its gid, its supplementary groups, its home and its shell from there --
/// and must never repeat the lookup. A record carrying less would leave the
/// parent two choices, both wrong: re-run `account::lookup` on the loop,
/// undoing this entire split, or store a defaulted account, and then a
/// channel's child drops to the wrong gid with no supplementary groups at
/// all.
enum Verdict {
    /// The proof checked out: the account it admitted, that key's
    /// fingerprint for `Response::Verified`'s `identity`, and that key's
    /// family name (`ED25519`, `RSA`, `ECDSA`, ...) for the accept line
    /// `finish_pending` writes -- see [`sshauth::verify::algorithm_label`]
    /// and the design spec's §10.
    Admitted {
        account: Account,
        identity: String,
        algorithm: String,
    },
    /// One of the child's own checks refused it. The reason is for the
    /// helper's log and nowhere else -- every refusal crosses the seam as
    /// the same [`REFUSED_REASON`]. `unknown_account` is log-only too: it
    /// is what picks §10's `invalid user` wording apart from its plain
    /// one, in `finish_pending`. Not derived by matching `reason`'s text
    /// back at that call site -- a message documented as free-form log
    /// prose is not a value to pattern-match control flow on -- so the
    /// child that already knows which check refused carries the fact
    /// alongside the words.
    Refused {
        reason: String,
        unknown_account: bool,
    },
}

/// Write `verdict` to `w` as one fixed-shape record: the child's last act
/// before `_exit`.
///
/// Native byte order throughout. Both ends of this pipe are the same
/// program image one `fork` apart, exactly as a channel's own startup
/// report already assumes for its `errno`.
///
/// Best-effort, like that report: a record that cannot be written leaves
/// the parent at end-of-file with nothing, which it reads as a refusal (see
/// [`verdict_from_pipe`]). A record past [`MAX_VERDICT_LEN`], or an account
/// with more than [`NGROUPS_MAX`] groups, becomes a refusal HERE rather
/// than being truncated: a truncated group list is a channel running with
/// the wrong privileges, which is a great deal worse than a login the
/// client has to retry.
fn verdict_to_pipe(w: BorrowedFd<'_>, verdict: &Verdict) {
    let too_many_groups = match verdict {
        Verdict::Admitted { account, .. } => account.groups.len() > NGROUPS_MAX,
        Verdict::Refused { .. } => false,
    };
    let mut record = if too_many_groups {
        encode_verdict(&Verdict::Refused {
            reason: "the account carries more supplementary groups than NGROUPS_MAX".to_string(),
            // The account WAS found and admitted -- this refusal is the
            // record format's own limit, not a claim about whether an
            // account exists.
            unknown_account: false,
        })
    } else {
        encode_verdict(verdict)
    };
    if record.len() > MAX_VERDICT_LEN {
        record = encode_verdict(&Verdict::Refused {
            reason: format!(
                "the verdict record is {} bytes, past the {MAX_VERDICT_LEN}-byte cap",
                record.len()
            ),
            // Same reasoning as above: this fires on an admission too big
            // to carry, so the account plainly exists.
            unknown_account: false,
        });
    }
    let mut written = 0;
    while written < record.len() {
        match nix::unistd::write(w, &record[written..]) {
            // Nothing is going to make progress; the parent will see a
            // short record and refuse, which is the safe reading.
            Ok(0) => return,
            Ok(n) => written += n,
            Err(nix::Error::EINTR) => {}
            Err(_) => return,
        }
    }
}

/// One verdict as bytes -- see [`verdict_to_pipe`] for the shape.
fn encode_verdict(verdict: &Verdict) -> Vec<u8> {
    let mut out = Vec::new();
    match verdict {
        Verdict::Admitted {
            account,
            identity,
            algorithm,
        } => {
            out.push(VERDICT_ADMITTED);
            out.extend_from_slice(&account.uid.as_raw().to_ne_bytes());
            out.extend_from_slice(&account.gid.as_raw().to_ne_bytes());
            put_field(&mut out, account.name.as_bytes());
            put_field(&mut out, account.home.as_os_str().as_bytes());
            put_field(&mut out, account.shell.as_os_str().as_bytes());
            out.extend_from_slice(&(account.groups.len() as u32).to_ne_bytes());
            for gid in &account.groups {
                out.extend_from_slice(&gid.as_raw().to_ne_bytes());
            }
            put_field(&mut out, identity.as_bytes());
            put_field(&mut out, algorithm.as_bytes());
        }
        Verdict::Refused {
            reason,
            unknown_account,
        } => {
            out.push(VERDICT_REFUSED);
            put_field(&mut out, reason.as_bytes());
            out.push(u8::from(*unknown_account));
        }
    }
    out
}

/// One length-prefixed field: a `u32` count, then that many bytes.
fn put_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_ne_bytes());
    out.extend_from_slice(bytes);
}

/// Read one verdict record off `report`, bounded by that entry's own
/// `deadline`, and return it ONLY if it arrived whole.
///
/// `None` is the answer to everything else -- a clean end-of-file with
/// nothing read, a record that stops short, a length field that does not
/// match what followed, trailing bytes, a read error, a deadline reached --
/// and `None` means refusal at every call site.
///
/// This deliberately does NOT copy the shape of [`read_startup_report`],
/// where `Ok(0)` with nothing read means SUCCESS. That is right there
/// because the kernel closes the child's close-on-exec write end as part of
/// a successful `execve`, so end-of-file IS the success signal. This child
/// never execs: it writes its verdict and `_exit`s, so end-of-file with
/// nothing in it means it died, was killed, or gave up before it had
/// checked anything at all. Copying that idiom would turn "never checked"
/// into "admitted".
///
/// Bounded by the deadline rather than read straight through, unlike that
/// function's single four-byte report: a record can exceed `PIPE_BUF` (an
/// account with a few hundred groups does), so the child's one `write` is
/// not necessarily atomic and the rest can arrive in pieces. The loop must
/// not be parked waiting for them.
fn verdict_from_pipe(report: &OwnedFd, deadline: Instant) -> Option<Verdict> {
    let mut record = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(report.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, timeout) {
            Ok(0) => return None,
            Ok(_) => {}
            Err(nix::Error::EINTR) => continue,
            Err(_) => return None,
        }
        match nix::unistd::read(report.as_raw_fd(), &mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                record.extend_from_slice(&chunk[..n]);
                if record.len() > MAX_VERDICT_LEN {
                    return None;
                }
            }
            Err(nix::Error::EINTR) => continue,
            Err(_) => return None,
        }
    }
    decode_verdict(&record)
}

/// Parse a verdict record. Every shortfall answers `None` -- see
/// [`verdict_from_pipe`] for why that is the only safe reading.
fn decode_verdict(record: &[u8]) -> Option<Verdict> {
    let mut cursor = VerdictCursor { rest: record };
    let verdict = match cursor.byte()? {
        VERDICT_ADMITTED => {
            let uid = Uid::from_raw(cursor.u32()?);
            let gid = Gid::from_raw(cursor.u32()?);
            let name = String::from_utf8(cursor.field()?.to_vec()).ok()?;
            let home = PathBuf::from(OsStr::from_bytes(cursor.field()?));
            let shell = PathBuf::from(OsStr::from_bytes(cursor.field()?));
            let count = cursor.u32()? as usize;
            if count > NGROUPS_MAX {
                return None;
            }
            // Not `with_capacity(count)`: the count is a number off a
            // pipe, and reserving on it would let a bogus one allocate
            // before a single group had actually been read.
            let mut groups = Vec::new();
            for _ in 0..count {
                groups.push(Gid::from_raw(cursor.u32()?));
            }
            let identity = String::from_utf8(cursor.field()?.to_vec()).ok()?;
            let algorithm = String::from_utf8(cursor.field()?.to_vec()).ok()?;
            Verdict::Admitted {
                account: Account {
                    uid,
                    gid,
                    name,
                    home,
                    shell,
                    groups,
                },
                identity,
                algorithm,
            }
        }
        VERDICT_REFUSED => {
            let reason = String::from_utf8(cursor.field()?.to_vec()).ok()?;
            let unknown_account = cursor.byte()? != 0;
            Verdict::Refused {
                reason,
                unknown_account,
            }
        }
        _ => return None,
    };
    // Anything left over is not the record this helper writes.
    if !cursor.rest.is_empty() {
        return None;
    }
    Some(verdict)
}

/// A reader over a verdict record: every read that would run past the end
/// answers `None`, so a short record can only ever become a refusal, never
/// a half-parsed account.
struct VerdictCursor<'a> {
    rest: &'a [u8],
}

impl<'a> VerdictCursor<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.rest.len() < n {
            return None;
        }
        let (head, tail) = self.rest.split_at(n);
        self.rest = tail;
        Some(head)
    }

    fn byte(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_ne_bytes(self.take(4)?.try_into().ok()?))
    }

    fn field(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        self.take(len)
    }
}

/// Fork the child that checks one proof; hand back its report pipe and its
/// pid, having waited for nothing at all.
///
/// The nonce is ALREADY spent by the time this is called -- see
/// `serve_auth_seam`'s `Verify` arm, and [`verify_proof_after_nonce`]'s own
/// docs for why that order is required rather than tidy.
///
/// The child closes every descriptor it inherited except the report pipe's
/// write end. `O_CLOEXEC` does nothing for it, because it never execs, so
/// the sweep has to be explicit -- and closing "both seams" would not be
/// enough: since task 3 the loop also holds the master side of every
/// channel that is still starting, and the report pipe of every other
/// pending child besides (task 7 adds a monitor socket per login on top).
/// A terminal or a seam left open in a process that goes on to read an
/// account's own files is exactly what [`close_other_descriptors`] exists
/// to rule out.
#[allow(clippy::too_many_arguments)]
fn fork_verification(
    login: &str,
    public_key: &[u8],
    signature: &[u8],
    handshake_hash: &[u8; 32],
    nonce: &Nonce,
    config: &HelperConfig,
    switches: AccountSwitches,
) -> anyhow::Result<(OwnedFd, Pid)> {
    use nix::fcntl::OFlag;
    use nix::unistd::{fork, pipe2, ForkResult};

    let (report_read, report_write) =
        pipe2(OFlag::O_CLOEXEC).context("opening the verification report pipe")?;
    // Read here, by the parent, for the same reason a monitor reads it
    // here: `getrlimit` is a libc call, and the child has closing to do
    // before it may make any.
    let fd_limit = max_open_descriptors();

    // SAFETY: the helper is single-threaded by construction (it forked
    // before the tokio runtime existed and never starts a thread), so no
    // other thread can have been frozen mid-allocation at the moment of
    // this fork holding a lock the child would then deadlock on. Unlike
    // a channel's shell this one never execs, so it is an ordinary
    // process that may allocate freely -- but only AFTER the descriptor
    // sweep below, which must come first precisely because nothing else
    // will ever close what it inherited.
    match unsafe { fork() }.context("forking the verifying process")? {
        ForkResult::Parent { child } => {
            // Our own copy of the write end has to close before anything
            // reads the pipe, or it never reaches end-of-file even once
            // the child's copy is gone.
            drop(report_write);
            Ok((report_read, child))
        }
        ForkResult::Child => {
            // The whole body under a `catch_unwind`, because the `_exit`
            // below closes `return` and nothing closed `panic`. This crate
            // is built with the default `unwind` strategy (`panic =
            // "abort"` is set in no manifest), so a panic here would
            // travel back through every frame between this line and the
            // `fork` -- running the `Drop` glue of each, in a process
            // whose descriptor numbers have just been swept out from under
            // that glue -- and then end the thread rather than the
            // process, which is the "second helper" this child's `_exit`
            // exists to make impossible. See `PANICKED_CHILD_EXIT`.
            let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let report_write = report_write.as_fd();
                // FIRST, and before anything that allocates: this child never
                // execs, so `close_other_descriptors` is the only thing that
                // is ever going to close what it inherited. `report_read` --
                // this child's own copy -- goes with the rest; nothing here
                // reads the pipe.
                close_other_descriptors(report_write.as_raw_fd(), fd_limit);
                let verdict = match verify_proof_after_nonce(
                    login,
                    public_key,
                    signature,
                    handshake_hash,
                    nonce,
                    config,
                    switches,
                ) {
                    Ok((account, identity, algorithm)) => Verdict::Admitted {
                        account,
                        identity,
                        algorithm,
                    },
                    Err(VerifyRefusal {
                        reason,
                        unknown_account,
                    }) => Verdict::Refused {
                        reason,
                        unknown_account,
                    },
                };
                verdict_to_pipe(report_write, &verdict);
                // SAFETY: `_exit` ends the process immediately, running no
                // atexit handlers and no Rust `Drop` impls -- which is exactly
                // what has to happen here: returning into the helper's loop
                // would make a second helper. Inside the closure, so that
                // the ordinary path still runs no destructors at all.
                unsafe { nix::libc::_exit(0) }
            }));
            // Only a panic reaches this line.
            if let Err(payload) = panicked {
                // Dropping the payload could itself panic, and this is
                // outside the catch: leak it rather than unwind past the
                // `_exit` after all. The same treatment `pam::converse`
                // gives a panic on its own C boundary.
                std::mem::forget(payload);
            }
            // The pipe is closed by this exit with nothing written, and an
            // incomplete verdict is a refusal, always
            // (`verdict_from_pipe`) -- so a child that panicked refuses its
            // proof rather than admitting it.
            // SAFETY: as above.
            unsafe { nix::libc::_exit(PANICKED_CHILD_EXIT) }
        }
    }
}

/// Try, without blocking, to finish reaping `pid`. Returns whether it is
/// gone -- reaped just now, or already gone by some other means -- which is
/// the caller's signal to stop tracking it.
fn reap_orphan(pid: Pid) -> bool {
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    loop {
        match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) => return true,
            // Not a zombie yet -- SIGKILL was sent, but has not taken
            // effect; try again on a later pass rather than block here.
            Ok(_) => return false,
            // Already reaped by some other means, or never our child.
            Err(nix::Error::ECHILD) => return true,
            Err(nix::Error::EINTR) => continue,
            Err(e) => {
                crate::log::warn("helper", &format!("waitpid({pid}) (orphan) failed: {e}"));
                // Give up tracking rather than retry a persistent error
                // forever.
                return true;
            }
        }
    }
}

/// Tell the worker that channel `id` exited with `code`, if it is one we
/// are still tracking.
///
/// A monitor names the channel, so nothing is looked up by pid any more --
/// but the channel may be one this helper has already given up on (a start
/// it refused at its deadline, a channel whose login ended), and an
/// `Exited` for a channel the worker was told had FAILED would be a second
/// answer to one request. So an id that is no longer `live` is dropped
/// silently, and a channel that never reported its start is too: its
/// `Open` has not been answered at all yet, and its refusal is on its way
/// through the pending table.
fn report_exit(sock: &UnixStream, state: &mut LoopState, id: ChannelId, code: i32) {
    if !matches!(state.live.get(&id), Some(ChannelSlot::Running(_))) {
        return;
    }
    state.live.remove(&id);
    state.closing.remove(&id);
    // A channel belongs to exactly one login; drop it from whichever one
    // has it, mirroring the removal from `live` above. See
    // `LoginState::channels`'s own docs for why this matters: that set is
    // meant to answer "what does this login have open RIGHT NOW", and
    // without this it would only ever grow, answering "what has it ever
    // opened" instead (fix round F5).
    for login in state.logins.values_mut() {
        login.channels.remove(&id);
    }
    reply(sock, &Response::Exited { id, code });
}

fn reply<T: serde::Serialize>(sock: &UnixStream, msg: &T) {
    match encode(msg) {
        Ok(bytes) => {
            if let Err(e) = channel::send(sock, &bytes, None) {
                crate::log::warn("helper", &format!("reply failed: {e}"));
            }
        }
        Err(e) => crate::log::warn("helper", &format!("could not encode a reply: {e}")),
    }
}

fn reply_with_fd(sock: &UnixStream, msg: &Response, fd: BorrowedFd<'_>) {
    match encode(msg) {
        Ok(bytes) => {
            if let Err(e) = channel::send(sock, &bytes, Some(fd)) {
                crate::log::warn("helper", &format!("reply failed: {e}"));
            }
        }
        Err(e) => crate::log::warn("helper", &format!("could not encode a reply: {e}")),
    }
}

/// How long a channel's child gets to report its own startup before the
/// helper gives up on it, kills it, and answers the worker with a refusal
/// -- the value the daemon resolves `HelperConfig::startup_timeout` to, and
/// the deadline every `PendingWhat::Channel` entry carries.
///
/// The helper no longer waits for this inside a request handler (that is
/// what the pending table exists for), so a slow child costs nobody else
/// anything while it starts. A budget is still needed all the same: a child
/// stuck before `exec` -- a binary on a hung mount, or one `SIGSTOP`ped by
/// whatever started this channel's command -- would otherwise hold its
/// channel id, its terminal and its login entry for ever, and answer the
/// worker never. Five seconds is generous next to the microseconds a
/// healthy `exec` actually takes, while still bounding that to a few
/// seconds rather than forever.
///
/// `pub(crate)`: `helper::spawner`'s own wait for the reply to an `Open`
/// request is bound just above this value -- see that module's
/// `OPEN_REPLY_TIMEOUT` -- so a slow-but-healthy open on the helper's side
/// (bounded by this very constant) can never itself be mistaken, on the
/// worker's side, for a reply that is lost.
pub(crate) const STARTUP_REPORT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long the child checking one client's proof gets before the helper
/// gives up on it, kills it and refuses that proof -- the value the daemon
/// resolves `HelperConfig::verify_timeout` to.
///
/// Five seconds, to match the client's own `transport::AUTH_DEADLINE`: past
/// that the client has already given up on its handshake, so a verdict
/// arriving later has nobody left to admit. The budget is not what keeps the
/// helper responsive -- the child and the pending table are (nothing waits in
/// the handler any more) -- it is what stops one wedged verification from
/// holding a forked process, a report pipe and a poll slot for ever: the
/// account's home may sit on a mount that never answers, and `getpwnam`
/// through a directory server has no timeout of its own at all.
pub(super) const VERIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// What the child reported about its own startup within
/// [`STARTUP_REPORT_TIMEOUT`], read by [`read_startup_report`].
pub(super) enum StartupReport {
    /// The write end closed with no data: an `execve` succeeded.
    Started,
    /// The child reported this `errno` before ending itself.
    Failed(nix::Error),
    /// Nothing arrived, success or failure, before the deadline.
    TimedOut,
}

/// Open a pseudo-terminal of `launch.cols` x `launch.rows` and have this
/// login's MONITOR run the account's shell in it AS the account: a LOGIN
/// shell when `launch.shell` is set, `<shell> -c launch.command` otherwise.
/// Returns the master side, which travels to the worker with the `Opened`
/// answer once the monitor says the shell started.
///
/// What happens here, in order:
///
/// 1. `openpty` -- both sides, at the size asked for, so nothing has to
///    resize a moment later (a resize right after open is what makes tmux
///    reflow a pane and leave a blank line behind) -- and give the slave to
///    the account: owner `account.uid`, group `tty_gid` (the account's own
///    group on a machine with no `tty` group), mode `0620`;
/// 2. if this login has no monitor yet, fork one ([`fork_monitor`]), with
///    everything it will need to know about the login decided here, before
///    the fork ([`MonitorPlan`]);
/// 3. send it `MonitorRequest::Open`, with the SLAVE side of the terminal
///    riding along out of band.
///
/// And nothing else. This function waits for nothing, forks no shell, and
/// learns nothing about whether the shell started: the monitor says that,
/// later, on its own seam, and the pending entry the caller makes is what
/// is waiting for it.
///
/// **Why the terminal is opened here and not in the monitor.** Its master
/// side belongs to the worker, and the shortest way there is the seam the
/// answer already travels on; routing it back out of the monitor would add
/// a second descriptor hand-over and a second thing that can fail. Its
/// NAME, which the monitor needs for `PAM_TTY` (next task), is known only
/// once it is open -- so opening it here is also what lets the plan carry
/// that name across the fork.
///
/// **What the monitor is not told.** Not the account, the login or the uid:
/// those were settled when the login proved itself and travel in the plan,
/// across the fork, where nothing that arrives later can change them. The
/// message carries only what differs from channel to channel.
fn open_channel(
    sock: &UnixStream,
    state: &mut LoopState,
    account: &Account,
    login: LoginId,
    config: &HelperConfig,
    launch: &Launch<'_>,
    become_account: fn(Uid, Gid, &[Gid]) -> nix::Result<()>,
) -> anyhow::Result<OwnedFd> {
    use nix::pty::{openpty, Winsize};

    let winsize = Winsize {
        ws_row: launch.rows,
        ws_col: launch.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let pty = openpty(&winsize, None).context("opening the pseudo-terminal")?;
    // The account must own its own terminal (`give_terminal`): `openpty`
    // gives it to whoever opened it, and that is root here.
    give_terminal(
        pty.slave.as_raw_fd(),
        account.uid,
        config.tty_gid.unwrap_or(account.gid),
    )
    .context("giving the terminal to the account")?;
    if !launch.echo {
        disable_echo(pty.master.as_fd()).context("disabling echo on the master side")?;
    }

    if !state.monitors.contains_key(&login) {
        // The terminal's name, for the `PAM_TTY` of the session the monitor
        // opens. Taken from the FIRST channel of the login, which is the one
        // whose monitor -- and whose session -- this is; a later channel
        // gets a terminal of its own that the session never hears about
        // (spec §9 `tty-first-channel`).
        let tty = nix::unistd::ttyname(pty.slave.as_fd())
            .context("reading the name of the channel's terminal")?;
        // No test of this crate may fork a monitor that reads the MACHINE's
        // `/etc/pam.d`. Nothing structural stopped one: a fixture built
        // with `pam_confdir: None` would open its channels against the
        // host's policy and pass or fail by it. Proven not to fire today --
        // replacing the non-test branch of `monitor::start_transaction` with
        // a process that dies leaves all 360 tests green and its marker
        // unwritten -- so this is a latch on a door nobody is at, put there
        // because the cost of noticing later is a green suite that tests
        // the wrong machine.
        #[cfg(test)]
        assert!(
            config.pam_confdir.is_some(),
            "a test that forks a monitor must point it at a PAM stack of its own; with None it \
             would read the machine's /etc/pam.d and pass or fail by the host's policy"
        );
        let plan = MonitorPlan {
            account: account.clone(),
            login,
            tty: tty
                .into_os_string()
                .into_string()
                .map_err(|_| anyhow::anyhow!("the terminal's name is not UTF-8"))?,
            rhost: state
                .logins
                .get(&login)
                .map(|entry| entry.rhost.clone())
                .unwrap_or_default(),
            pam_service: config.pam_service.clone(),
            #[cfg(test)]
            pam_confdir: config.pam_confdir.clone(),
            become_account,
            fd_limit: max_open_descriptors(),
            // The monitor's share of this channel's own budget. The session
            // it is about to open opens INSIDE this `Open`, so a stack that
            // takes longer than the helper is prepared to wait for the
            // channel has already lost that channel -- and the monitor that
            // is still waiting for it is a root process outliving whatever
            // the helper decides in the meantime, its login included. See
            // `MonitorPlan::session_budget` and `monitor::SessionDeadline`.
            session_budget: config.startup_timeout,
            // Twice that, and the reason the two are separate fields is in
            // the field's own docs: a close abandoned half-way loses work
            // that might still have succeeded, while an open abandoned
            // half-way loses work that had not started.
            session_close_budget: config.startup_timeout.saturating_mul(2),
        };
        let monitor = fork_monitor(plan).context("forking the login's monitor")?;
        state.monitors.insert(login, monitor);
    }

    let request = MonitorRequest::Open {
        id: launch.id,
        term: launch.term.map(str::to_string),
        shell: launch.shell,
        command: launch.command.to_string(),
    };
    let bytes = encode(&request).context("encoding the monitor's request")?;
    let monitor = state
        .monitors
        .get(&login)
        .expect("the monitor was just put on file");
    if let Err(e) = channel::send(&monitor.seam, &bytes, Some(pty.slave.as_fd())) {
        // The monitor cannot be reached, so this channel can never start --
        // and a monitor nobody can reach can only hold whatever it already
        // has open for good. It is killed and its LOGIN ends with it: the
        // next `Open` under that token is refused rather than given a
        // second monitor, which is the one thing `LoopState::monitors` may
        // never allow. A fresh proof admits the device again.
        lose_monitor(
            sock,
            state,
            login,
            &format!("could not be asked for a channel ({e})"),
        );
        anyhow::bail!("the login's monitor could not be reached: {e}");
    }
    // Ours is closed now that the monitor has a copy of its own: a slave
    // side still open here would keep the terminal from ever hanging up
    // when the shell ends.
    drop(pty.slave);
    Ok(pty.master)
}

/// One monitor seam, with BOTH ends bounded -- a function of its own so
/// that the bound can be witnessed without forking
/// (`a_monitor_seam_is_bounded_at_both_ends`): what a later edit is likely
/// to take away is the LINE, not the behaviour under a full buffer.
///
/// The helper's end, because the helper is single-threaded and serves every
/// session on the machine: a send to a monitor that has stopped reading
/// must give up rather than stop everything.
///
/// The monitor's end, set HERE so the setting travels into the child (see
/// [`fork_monitor`]), for the mirror of the same reason: a monitor asleep
/// in a send to a helper that has stopped reading is a monitor that has
/// stopped serving its own shells -- no `SIGHUP`, no escalation, no exit
/// reported. The helper's own [`MONITOR_GRACE_PERIOD`] would reach such a
/// monitor only once some channel of that login had been asked to close,
/// and its bounded sends only once it had something to send; this makes the
/// bound unconditional instead.
///
/// A bound that cannot be set is reported rather than fatal, as the two
/// worker seams' own timeouts are.
fn bounded_monitor_pair() -> anyhow::Result<(UnixStream, UnixStream)> {
    let (helper_end, monitor_end) =
        channel::pair().context("creating the monitor seam's socket pair")?;
    for (end, whose) in [
        (&helper_end, "sends to a monitor"),
        (&monitor_end, "a monitor's own sends"),
    ] {
        if let Err(e) = end.set_write_timeout(Some(SEAM_SEND_TIMEOUT)) {
            crate::log::warn(
                "helper",
                &format!(
                    "could not bound {whose} ({e}); a send that blocks for good could \
                 stop the process making it from serving anything"
                ),
            );
        }
    }
    Ok((helper_end, monitor_end))
}

/// Fork one login's monitor and return the helper's end of the seam to it,
/// with the monitor's pid.
///
/// The child never returns: `monitor::run_monitor` serves that login until
/// its seam closes and then ends the process. It never execs either, which
/// is why its very first act is to close everything it inherited -- see
/// that module's docs for what the helper holds that a monitor must not.
///
/// The seam is made by [`bounded_monitor_pair`], which is where both ends'
/// send bounds are set and why they have to be: the monitor's before this
/// fork, so that it travels into the child.
fn fork_monitor(plan: MonitorPlan) -> anyhow::Result<Monitor> {
    use nix::unistd::{fork, ForkResult};

    let (helper_end, monitor_end) = bounded_monitor_pair()?;

    // Taken BEFORE the fork, so the child can tell a helper that died in
    // the window between the fork and its own `PR_SET_PDEATHSIG` apart from
    // one still alive -- exactly as `monitor::fork_shell` takes the
    // monitor's pid before forking a shell, and as `helper::split_and_run`
    // takes the helper's before forking the worker.
    let helper_pid = nix::unistd::getpid();

    // SAFETY: the helper is single-threaded by construction (it forked
    // before the tokio runtime existed and never starts a thread), so no
    // other thread can have been frozen mid-allocation at the moment of
    // this fork holding a lock the child would then deadlock on. Unlike a
    // channel's shell this child never execs, so it is an ordinary process
    // that may allocate freely -- but only after the descriptor sweep
    // `run_monitor` makes first, which must come first precisely because
    // nothing else will ever close what it inherited.
    match unsafe { fork() }.context("forking the login's monitor")? {
        ForkResult::Parent { child } => {
            drop(monitor_end);
            Ok(Monitor {
                seam: helper_end,
                pid: child,
            })
        }
        ForkResult::Child => {
            // `helper_end` is deliberately NOT dropped here: `run_monitor`
            // never returns, so nothing in this frame is ever dropped, and
            // its descriptor sweep is what closes that end -- along with
            // every other descriptor of the helper's this child inherited,
            // which no `drop` here could have reached.
            run_monitor(plan, monitor_end, helper_pid)
        }
    }
}

/// Read the child's startup report off `report_read`, bounded by that
/// entry's own `deadline` -- see [`StartupReport`] for the three outcomes.
///
/// Called by the loop once `poll` has already said this pipe has something
/// to say, so in every real case it returns at once, having waited for
/// nothing. It can still wait, in one case: a report arriving in PIECES,
/// which would leave it polling for the rest until the deadline. Nothing
/// outside this process can provoke that -- the child's one `write` (see
/// `monitor::fork_shell`'s inner `fail`) is at most 4 bytes, well under a pipe's
/// atomic-write guarantee (`PIPE_BUF`, at least 512 bytes on any POSIX
/// system), and the code making it is this module's own, running before the
/// `exec` that gives the account's program any say at all. So that wait is
/// bounded by the same deadline the loop was already waiting for, and the
/// case this whole split exists to close -- a child that says NOTHING,
/// stuck before its exec -- is the deadline's business rather than this
/// function's.
///
/// Anything short of a complete 4-byte report (or a clean end-of-file with
/// none at all) is treated as a timeout rather than guessed at.
pub(super) fn read_startup_report(report_read: &OwnedFd, deadline: Instant) -> StartupReport {
    let mut buf = [0u8; 4];
    let mut filled = 0usize;
    loop {
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return StartupReport::TimedOut;
        };
        let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(report_read.as_fd(), PollFlags::POLLIN)];
        match poll(&mut fds, timeout) {
            Ok(0) => return StartupReport::TimedOut,
            Ok(_) => {}
            Err(nix::Error::EINTR) => continue,
            Err(_) => return StartupReport::TimedOut,
        }
        match nix::unistd::read(report_read.as_raw_fd(), &mut buf[filled..]) {
            Ok(0) => return StartupReport::Started,
            Ok(n) => {
                filled += n;
                if filled == buf.len() {
                    return StartupReport::Failed(nix::Error::from_raw(i32::from_ne_bytes(buf)));
                }
            }
            Err(nix::Error::EINTR) => continue,
            Err(_) => return StartupReport::TimedOut,
        }
    }
}

/// How long the loop may sleep in `poll`: never past the next reap pass
/// ([`REAP_INTERVAL`]), and never past the nearest deadline in the pending
/// table either -- a child given three hundred milliseconds has to be given
/// up on then, not whenever the reaper next happens to come round.
///
/// A function of its two inputs, with no `Instant::now()` of its own, so
/// the bound is testable against synthetic instants rather than by watching
/// a real loop sleep.
fn poll_timeout(pending: &PendingTable, now: Instant) -> PollTimeout {
    let budget = match pending.nearest_deadline(now) {
        Some(until_deadline) => until_deadline.min(REAP_INTERVAL),
        None => REAP_INTERVAL,
    };
    // At most REAP_INTERVAL (200ms), which always fits; `PollTimeout` only
    // offers `TryFrom<Duration>`, not an infallible `From`, because a
    // `Duration` in general might not.
    PollTimeout::try_from(budget).expect("a budget of at most REAP_INTERVAL fits in a poll timeout")
}

/// Finish every VERIFICATION whose report pipe `poll` has just reported
/// ready, in the order the loop found them.
///
/// `ready` names raw descriptor NUMBERS rather than entries, which is what
/// keeps the loop's `PollFd` array from borrowing the table it was built
/// from -- see `pending`'s own docs. A channel start is never among these:
/// it has no pipe of its own, and what finishes one is its monitor's word
/// (see [`serve_ready_monitors`]).
fn settle_ready_pending(
    seams: Seams<'_>,
    state: &mut LoopState,
    config: &HelperConfig,
    ready: &[RawFd],
) {
    for fd in ready {
        // `None` for a number the table no longer holds -- a list naming
        // the same one twice, or an entry some earlier step of this same
        // pass already finished. Harmless, and the reason `take_ready`
        // answers with an `Option` instead of trusting its caller's list.
        let Some(pending) = state.pending.take_ready(*fd) else {
            continue;
        };
        finish_pending(seams, state, config, pending, WhyFinished::Spoke);
    }
}

/// Give up on every pending request whose deadline `now` has reached: end
/// whatever never spoke, and answer whoever is waiting.
///
/// Runs on every pass of the loop, the way `reap` does, and for the same
/// reason: the thing it is looking for announces itself by SILENCE, so
/// nothing else is ever going to bring the loop back for it.
fn expire_pending(seams: Seams<'_>, state: &mut LoopState, config: &HelperConfig, now: Instant) {
    for pending in state.pending.take_expired(now) {
        finish_pending(seams, state, config, pending, WhyFinished::Expired);
    }
}

/// Apply one pending entry's verdict, whichever kind it is and whichever of
/// the two ways the loop came back to it.
///
/// A CHANNEL start can only arrive here expired: the other route to one is
/// its monitor speaking, and that goes straight to [`finish_channel`] with
/// what the monitor actually said. So the report this hands on is always
/// `TimedOut`, which is the one thing silence can mean.
fn finish_pending(
    seams: Seams<'_>,
    state: &mut LoopState,
    config: &HelperConfig,
    pending: Pending,
    why: WhyFinished,
) {
    let Pending { deadline, what } = pending;
    match what {
        what @ PendingWhat::Channel { .. } => {
            apply_channel_verdict(seams.channels, state, what, StartupReport::TimedOut)
        }
        PendingWhat::Verify {
            report: report_pipe,
            child,
            id,
            login,
            login_id,
            rhost,
        } => {
            // Whatever the verdict, this child is finished: it wrote its
            // record and `_exit`ed, or it is about to be killed. Either
            // way NOTHING waits for it here -- `reap`'s `WNOHANG` pass
            // buries it.
            state.orphans.push(child);
            let verdict = match why {
                WhyFinished::Spoke => verdict_from_pipe(&report_pipe, deadline),
                WhyFinished::Expired => {
                    // The child is stuck in something with no deadline of
                    // its own: a name service that never answers, a home
                    // directory on a mount that has stopped. SIGKILL
                    // rather than SIGHUP -- it is this helper's own code,
                    // it installs no handler, and a process stuck in an
                    // uninterruptible read would ignore anything catchable
                    // in any case. Not followed by a blocking wait, for
                    // the same reason the channel arm above does not wait:
                    // that would freeze the whole single-threaded helper
                    // one step past the budget meant to bound it.
                    log_failed_kill(
                        nix::sys::signal::kill(child, nix::sys::signal::Signal::SIGKILL),
                        child,
                        "SIGKILL on verification timeout",
                    );
                    crate::log::warn(
                        "helper",
                        &format!(
                            "the child verifying a proof for {login} said nothing \
                         within {:?}; killed, and the proof refused",
                            config.verify_timeout
                        ),
                    );
                    None
                }
            };
            let answer = match verdict {
                Some(Verdict::Admitted {
                    account,
                    identity,
                    algorithm,
                }) => {
                    // Fix F2, unchanged by the fork: the login exists from
                    // THIS moment, not only once it opens a first channel --
                    // and this is the one place it can come to exist at all
                    // (see `LoopState::logins`). A refusal here (the cap,
                    // or this token already bound to a different account)
                    // refuses the WHOLE verification, exactly as a bad
                    // signature would, and carries the same
                    // `REFUSED_REASON` so the two cannot be told apart.
                    //
                    // `rhost` is cloned into `ensure_login`, which keeps its
                    // own copy on the login entry, so that the accept line
                    // below can still use the one this process already
                    // sanitized rather than reading it back out of state.
                    match ensure_login(state, login_id, &account, rhost.clone()) {
                        Ok(incarnation) => {
                            // §10's accept line: a public contract, close
                            // to `sshd`'s own wording so an existing
                            // `fail2ban` filter needs only a small edit.
                            // `login` and `rhost` are ALREADY
                            // `sanitized_login_name`/`sanitized_rhost` --
                            // set once, on `PendingWhat::Verify`, the one
                            // door anything external takes into this root
                            // process's log -- and `identity` is already
                            // `SHA256:<fingerprint>`, so this line needs no
                            // sanitizing of its own, only assembly.
                            crate::log::info(
                                "helper",
                                &format!(
                                    "Accepted signature for {login} from {rhost} key \
                                 {algorithm} {identity}"
                                ),
                            );
                            let response = Response::Verified {
                                uid: account.uid.as_raw(),
                                name: account.name.clone(),
                                identity,
                                incarnation,
                            };
                            // Exactly what came off the pipe, and never a
                            // second `account::lookup`: repeating that
                            // lookup on the loop is the unbounded
                            // name-service call this entire fork exists to
                            // be rid of, and a channel takes this
                            // account's gid, groups, home and shell from
                            // here.
                            state.verified.insert(account.uid, account);
                            response
                        }
                        Err(reason) => {
                            crate::log::warn(
                                "helper",
                                &format!(
                                    "a Verify request that otherwise checked out was \
                                 refused: {}",
                                    crate::log::one_line(reason)
                                ),
                            );
                            Response::Refused {
                                reason: REFUSED_REASON.to_string(),
                            }
                        }
                    }
                }
                Some(Verdict::Refused {
                    reason,
                    unknown_account,
                }) => {
                    // The DETAILED reason to the log; the worker gets only
                    // the fixed `REFUSED_REASON` -- see that constant's
                    // docs for why. The reason travels back from the child
                    // rather than being logged there, so that every line
                    // about a refusal still comes from the one privileged
                    // process that has a log at all.
                    // `one_line`: the child's words about a proof the worker
                    // chose -- an error text may quote it.
                    crate::log::warn(
                        "helper",
                        &format!(
                            "a Verify request was refused: {}",
                            crate::log::one_line(&reason)
                        ),
                    );
                    // §10's refuse line, the mirror of the accept line
                    // above -- `sshd`'s own two shapes, picked by
                    // `unknown_account`, which the child decided rather
                    // than this site guessing it back out of `reason`'s
                    // free-form words. `login`/`rhost` are the same
                    // sanitized copies the accept line uses; the WIRE
                    // answer stays the single `REFUSED_REASON` below
                    // either way, so this line changes nothing the worker
                    // can observe.
                    if unknown_account {
                        crate::log::warn(
                            "helper",
                            &format!("Failed signature for invalid user {login} from {rhost}"),
                        );
                    } else {
                        crate::log::warn(
                            "helper",
                            &format!("Failed signature for {login} from {rhost}"),
                        );
                    }
                    Response::Refused {
                        reason: REFUSED_REASON.to_string(),
                    }
                }
                None => {
                    // An incomplete verdict is a refusal, ALWAYS -- see
                    // `verdict_from_pipe` for why end-of-file here cannot
                    // mean what it means for a channel's startup report.
                    // The expired case has already logged a line of its
                    // own above; this covers a child that died, was killed
                    // from outside, or wrote something that is not a
                    // verdict.
                    if matches!(why, WhyFinished::Spoke) {
                        crate::log::warn(
                            "helper",
                            &format!(
                                "the child verifying a proof for {login} ended without \
                             a usable verdict; refusing"
                            ),
                        );
                    }
                    Response::Refused {
                        reason: REFUSED_REASON.to_string(),
                    }
                }
            };
            reply(seams.auth, &AuthResponse { id, body: answer });
        }
    }
}

/// Apply what a monitor said about one channel it was asked to start.
///
/// Takes the pending entry off the table itself, so an event naming a
/// channel the helper has already given up on -- one whose deadline passed
/// a moment before its monitor got round to answering, one whose login has
/// ended -- costs nothing and answers nobody twice.
fn finish_channel(
    channels: &UnixStream,
    state: &mut LoopState,
    id: ChannelId,
    report: StartupReport,
) {
    let Some(pending) = state.pending.take_channel(id) else {
        return;
    };
    apply_channel_verdict(channels, state, pending.what, report);
}

/// Refuse one channel whose shell was never started at all, with the shared
/// [`REFUSED_REASON`] -- what a `MonitorEvent::Refused` comes to.
///
/// Not [`apply_channel_verdict`]'s `StartupReport::Failed` arm: that one
/// names the `errno` on the wire, which is right for a shell that could not
/// be exec'd and wrong for a login the account stack turned away. The real
/// reason has already reached the log by the time this runs.
///
/// Takes the pending entry itself, like [`finish_channel`], so a refusal
/// naming a channel the helper has already given up on costs nothing and
/// answers nobody twice.
fn refuse_channel_outright(channels: &UnixStream, state: &mut LoopState, id: ChannelId) {
    let Some(pending) = state.pending.take_channel(id) else {
        return;
    };
    let PendingWhat::Channel { id, master, .. } = pending.what else {
        return;
    };
    // The terminal goes with the refusal: nothing is running on it, and a
    // master left open here would be a pseudo-terminal no channel names.
    drop(master);
    refuse_starting_channel(channels, state, id, REFUSED_REASON.to_string());
}

/// Answer one `Request::Open`, now that what became of its shell is known.
///
/// Everything it needs travelled here inside the entry itself
/// (`PendingWhat::Channel`) rather than being looked up again, because
/// between the request and this moment the loop has served others: the
/// channel may have been closed, or the login it belongs to may have ended
/// -- which is what the entry's own `cancelled` mark records.
fn apply_channel_verdict(
    channels: &UnixStream,
    state: &mut LoopState,
    what: PendingWhat,
    report: StartupReport,
) {
    let PendingWhat::Channel {
        id,
        master,
        login,
        uid,
        cancelled,
    } = what
    else {
        return;
    };
    match report {
        StartupReport::Started if cancelled => {
            // `Request::Close` reached this channel while it was still
            // starting. Its shell is already dead of that `SIGHUP`, and a
            // report pipe at end-of-file says only "the descriptor closed"
            // -- never "the exec took". Answering `Opened` here would hand
            // the worker a terminal whose process is a corpse; the
            // cancellation is answered as what it is.
            //
            // And the shell must not survive the cancellation. In the
            // ordinary case it is already gone -- the monitor's `SIGHUP`
            // ended it before its `exec`. The case this is here for is the
            // narrow one where the `exec` landed between that signal and
            // this verdict: the program is the account's own, it may ignore
            // a hang-up, and the terminal master about to be dropped below
            // is only another one of those. Left alive it would hold a
            // pseudo-terminal with no channel id, closed by nobody. The
            // monitor is asked again, since only it can signal its own
            // child, and it escalates to `SIGKILL` on its own grace.
            tell_monitor(channels, state, login, &MonitorRequest::Close { id });
            drop(master);
            refuse_starting_channel(
                channels,
                state,
                id,
                "the channel was closed while it was still starting".to_string(),
            );
        }
        StartupReport::Started => {
            // The slot the `Open` reserved becomes a running channel: only
            // from here may an `Exited` be reported for this id at all --
            // see `ChannelSlot`.
            state.live.insert(id, ChannelSlot::Running(login));
            match state.logins.get_mut(&login) {
                Some(entry) => {
                    // Only now, once the channel is really open -- never
                    // for a repeated id refused before anything started,
                    // and never for a start that failed -- so this set
                    // never remembers a channel that never was (see
                    // `LoginState::channels`'s own docs).
                    entry.channels.insert(id);
                    // And the login is ESTABLISHED from here on: it has
                    // really had a channel, so it is no longer the
                    // half-finished handshake `LOGIN_GRACE` bounds, and
                    // age stops applying to it for good -- including
                    // later, once this channel and every other one of
                    // its channels has closed.
                    entry.established = true;
                }
                // No entry left to record this channel against -- a
                // fail-safe rather than a path anything takes today. Every
                // remover now leaves nothing of a login in flight behind it
                // (see `LoopState::logins`): the age sweep declines while a
                // start is in flight, and `Request::LoginEnded` cancels
                // these starts before removing, so a cancelled one is
                // refused by the arm above rather than arriving here. It is
                // kept, and pinned, because a remover added later could
                // reintroduce the case -- and if it does, the channel is
                // open and the worker must still be told: the worker is the
                // only half that can close one, and a channel it never
                // hears about is a pseudo-terminal held for good.
                None => crate::log::warn(
                    "helper",
                    &format!(
                        "channel {id} for uid {uid} started after its login had \
                     already ended; nothing left to record it against"
                    ),
                ),
            }
            reply_with_fd(channels, &Response::Opened { id }, master.as_fd());
        }
        StartupReport::Failed(errno) => {
            drop(master);
            refuse_starting_channel(
                channels,
                state,
                id,
                format!("starting the channel's process failed: {errno}"),
            );
        }
        StartupReport::TimedOut => {
            // The monitor said nothing about this channel within its whole
            // budget. Its shell may be a perfectly healthy program that has
            // just exec'd, and leaving it behind -- refused, its id already
            // taken back, still holding the terminal -- is the very outage
            // the budget exists to bound. So the monitor is asked to close
            // it, which is the only way this process can reach another
            // process's child; if the monitor is what is wedged, the
            // escalation in `reap` reaches the monitor itself.
            tell_monitor(channels, state, login, &MonitorRequest::Close { id });
            crate::log::warn(
                "helper",
                &format!(
                    "channel {id} for uid {uid} was never reported as started; closing \
                 it and refusing the request"
                ),
            );
            drop(master);
            refuse_starting_channel(
                channels,
                state,
                id,
                "starting the channel's process timed out".to_string(),
            );
        }
    }
}

/// What a failed start and a start that never reported have in common: the
/// id goes back and the worker is told why. The login entry is left alone
/// -- this request never created it (see `LoopState::logins`), and it stays
/// provisional unless some other channel really opened under it, so the
/// grace still bounds it.
///
/// Nothing is reaped here and nothing is signalled: the shell, if there
/// ever was one, is the monitor's child. What ends it is the
/// `MonitorRequest::Close` each caller that needs one sends before calling
/// this.
fn refuse_starting_channel(
    channels: &UnixStream,
    state: &mut LoopState,
    id: ChannelId,
    reason: String,
) {
    // The id is free again only now: from the request to this line a second
    // `Open` naming it was refused, which is the whole point of reserving
    // it early (see `ChannelSlot`).
    state.live.remove(&id);
    // And no escalation is owed for a channel that never opened: a `Close`
    // that arrived while it was starting has been answered by this refusal.
    // `reap`'s own `retain` would drop this entry on its next pass anyway;
    // what this line adds is that the id cannot carry an old deadline into
    // a NEW channel the worker opens under the same number before that pass
    // runs. NOT pinned by a test -- the window is a few milliseconds wide
    // and not reachable on demand -- so this is reasoning, not coverage:
    // treat it as load-bearing when you edit it.
    state.closing.remove(&id);
    reply(channels, &Response::Failed { id, reason });
}

/// What a `Request::Open` asks [`open_channel`] to start, besides whose
/// channel it is.
struct Launch<'a> {
    /// The channel id the worker asked for -- what the monitor's own
    /// request and every event it sends back name this channel by.
    id: ChannelId,
    cols: u16,
    rows: u16,
    /// The client's terminal type, or `None` when it announced nothing.
    term: Option<&'a str>,
    /// Kernel echo on the pseudo-terminal.
    echo: bool,
    /// Run the account's login shell rather than a command.
    shell: bool,
    /// The command line, whole and unparsed; the account's shell runs it as
    /// `<shell> -c <command>`. Ignored when `shell` is set.
    command: &'a str,
}

/// The account's login shell, from passwd as the helper verified it --
/// `/bin/sh` when passwd leaves it empty, as `sshd` and `login` both do.
/// Never the helper's own `$SHELL`, which is root's, and never anything the
/// worker sent: the worker does not even know which account a channel's
/// process runs as.
pub(super) fn login_shell(account: &Account) -> &[u8] {
    let shell = account.shell.as_os_str().as_bytes();
    if shell.is_empty() {
        b"/bin/sh"
    } else {
        shell
    }
}

/// The last path component of a shell, for its `argv[0]` -- `bash` out of
/// `/bin/bash`, the whole thing when there is no `/`. The same
/// `strrchr(shell, '/')` `sshd` and `login` use.
pub(super) fn shell_basename(shell: &[u8]) -> &[u8] {
    match shell.iter().rposition(|&b| b == b'/') {
        Some(slash) => &shell[slash + 1..],
        None => shell,
    }
}

/// The terminal for a channel whose home the account cannot enter, as fixed
/// bytes built before the fork so the child can `write` them with no
/// allocation -- the way `sshd` prints "Could not chdir to home directory".
///
/// `\r\n` rather than a bare `\n`: nothing has driven this terminal yet, so
/// it is still in its default cooked mode, where `ONLCR` expands a `\n` of
/// its own accord -- what actually reaches the screen here is `\r\r\n`, one
/// redundant carriage return that costs nothing. Written out all the same,
/// rather than left to `ONLCR`, so the line lands whole on a terminal
/// something has already put into raw mode, where a bare `\n` really would
/// step down a line without returning the carriage.
pub(super) fn chdir_warning_bytes(home: &[u8]) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(b"qshd: could not enter home directory ");
    message.extend_from_slice(home);
    message.extend_from_slice(b"; using /\r\n");
    message
}

/// Give the terminal `slave` to the account: mode `0620` FIRST, while root
/// still owns it, then owner `uid` and group `gid`.
///
/// The order is load-bearing. `chmod(2)` by a process that is not the
/// file's owner needs `CAP_FOWNER`, which the packaged system unit
/// (spec §8.3) does NOT grant -- so the `fchmod` has to happen while root is
/// still the owner, before the `fchown` hands the file to the account.
/// `fchown` itself needs only `CAP_CHOWN`, which the unit does grant, and it
/// leaves the mode bits alone (it clears set-user-ID/set-group-ID, neither
/// of which is set here). Reversed, every channel for a non-root account
/// would be refused with `EPERM` under that unit.
///
/// `0620` with group `tty` is what `sshd` and `login` leave behind, and what
/// `write`/`wall` expect: the account reads and writes its terminal, its
/// group may only write to it, nobody else may touch it. `gid` is the `tty`
/// group, resolved once at startup (`HelperConfig::tty_gid`), or the
/// account's own group on a machine without one.
fn give_terminal(slave: std::os::fd::RawFd, uid: Uid, gid: Gid) -> nix::Result<()> {
    use nix::sys::stat::{fchmod, Mode};
    fchmod(slave, Mode::from_bits_truncate(0o620))?;
    nix::unistd::fchown(slave, Some(uid), Some(gid))
}

/// The child's environment, as `KEY=VALUE` `CString`s ready for `execve` --
/// built and fully allocated HERE, before the fork, from the account and
/// from nothing the helper itself inherited.
///
/// Between `fork` and `exec` nothing may allocate (see the module's docs).
/// `std::env::set_var` would: it allocates and takes a lock shared by every
/// reader and writer of the process environment, and in a process that
/// ever had more than one thread, a call made between fork and exec can
/// deadlock on a lock another (now-vanished-to-the-child) thread held at
/// the instant of the fork -- rarely, not reliably, which is worse.
/// Building the environment here, before the fork, and handing it to
/// `execve` (which takes it explicitly, doing no `setenv`/`getenv` of its
/// own) avoids the call entirely rather than arguing it is safe today.
///
/// Nothing is inherited: the helper's environment is root's and the service
/// manager's, and none of it is the account's business. `HOME`, `USER`,
/// `LOGNAME` and `SHELL` come from passwd, as the helper verified the
/// account (`shell` is [`login_shell`]'s answer, the same one a shell
/// channel runs); `PATH` is [`search_path`]'s -- the account's own list,
/// which the SHELL searches a bare command name on, this child searching
/// nothing at all; `TERM` is what the client announced about its own
/// emulator, [`crate::pty::TERM_VALUE`] when it announced nothing -- a
/// client whose Home key is `\e[1~` talking to a shell configured for
/// `\eOH` gets no Home at all; and a UTF-8 locale variable, because the line
/// editor has to agree with the emulator about what a character is -- see
/// [`crate::pty::utf8_locale_for_fresh_env`] for which one, and why it is
/// not simply `utf8_locale_env`'s answer.
pub(super) fn child_env(
    account: &Account,
    shell: &[u8],
    term: Option<&str>,
) -> anyhow::Result<Vec<CString>> {
    let variable = |name: &str, value: &[u8]| {
        let mut entry = Vec::with_capacity(name.len() + 1 + value.len());
        entry.extend_from_slice(name.as_bytes());
        entry.push(b'=');
        entry.extend_from_slice(value);
        CString::new(entry)
            .with_context(|| format!("the environment variable {name} holds a NUL byte"))
    };
    let mut env = vec![
        variable("HOME", account.home.as_os_str().as_bytes())?,
        variable("USER", account.name.as_bytes())?,
        variable("LOGNAME", account.name.as_bytes())?,
        variable("SHELL", shell)?,
        variable("PATH", search_path(account.uid).as_bytes())?,
        variable("TERM", term.unwrap_or(crate::pty::TERM_VALUE).as_bytes())?,
    ];
    if let Some((name, locale)) = crate::pty::utf8_locale_for_fresh_env() {
        env.push(variable(name, locale.as_bytes())?);
    }
    Ok(env)
}

/// The `PATH` a channel's program is searched for on, and the one its
/// environment carries: [`ROOT_PATH`] for uid 0, [`USER_PATH`] for every
/// other account.
fn search_path(uid: Uid) -> &'static str {
    if uid.is_root() {
        ROOT_PATH
    } else {
        USER_PATH
    }
}

/// The drop, as the daemon does it ([`AccountSwitches::REAL`]): the
/// supplementary groups, then the group id, then the user id -- and never
/// the other way round: after `setuid` this process can no longer change
/// either, so a reversed order would leave it carrying root's groups. From
/// root, `setgid`/`setuid` move the real, effective and saved ids alike;
/// [`check_identity`] proves they did.
///
/// Called in the child between `fork` and `exec`: `groups` is the list
/// built before the fork, and nothing here allocates.
fn become_account(uid: Uid, gid: Gid, groups: &[Gid]) -> nix::Result<()> {
    nix::unistd::setgroups(groups)?;
    nix::unistd::setgid(gid)?;
    nix::unistd::setuid(uid)
}

/// Prove the drop took: the three checks a channel's shell makes right
/// after [`AccountSwitches::become_account`], as one call.
///
/// A drop that returned success and did not take is the worst outcome of
/// all: the program would run as root and look as if it did not. So the ids
/// ([`check_identity`]), the supplementary groups
/// ([`check_supplementary_groups`]) and -- for a non-root account -- that no
/// capability survived the `setuid` ([`check_no_capabilities`], which they
/// would under `SECBIT_NO_SETUID_FIXUP`, letting `chdir` and the exec run
/// with root's `CAP_DAC_*` and slipping the ambient set into the user's
/// program) are all proven rather than assumed. Root keeps its capabilities
/// on purpose, so that check is for a non-root target only.
///
/// One function rather than three calls at the one call site
/// (`monitor::fork_shell`) so that the three cannot drift apart from each
/// other, or from the account the drop was for, once the fork that makes
/// them moves again. Called between `fork` and `exec`: `expected` is sorted
/// and `buffer` allocated before the fork, and nothing here allocates.
pub(super) fn become_account_checks(
    uid: Uid,
    gid: Gid,
    expected: &[Gid],
    buffer: &mut [Gid],
) -> nix::Result<()> {
    check_identity(uid, gid)?;
    check_supplementary_groups(expected, buffer)?;
    if !uid.is_root() {
        check_no_capabilities()?;
    }
    Ok(())
}

/// `Ok` when this process now IS `uid`/`gid` -- real, effective and saved,
/// user and group alike -- and `EPERM` otherwise: a drop that returned
/// success and did not take would run the account's program as root while
/// looking as if it did not, and that is not something to assume away.
/// Called in the child between `fork` and `exec`, after
/// [`AccountSwitches::become_account`] whichever switches are in use, so
/// allocation-free.
fn check_identity(uid: Uid, gid: Gid) -> nix::Result<()> {
    let users = nix::unistd::getresuid()?;
    let groups = nix::unistd::getresgid()?;
    let is_account = [users.real, users.effective, users.saved]
        .iter()
        .all(|&u| u == uid)
        && [groups.real, groups.effective, groups.saved]
            .iter()
            .all(|&g| g == gid);
    if is_account {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

/// `Ok` when this process's supplementary groups are exactly `expected`
/// (which the caller sorted before the fork), and `EPERM` otherwise -- the
/// group half of the same proof [`check_identity`] makes for the ids: a
/// `setgroups` that returned success and did not take would leave the
/// account's program carrying root's groups.
///
/// Called in the child between `fork` and `exec`, so allocation-free:
/// `buffer` was allocated before the fork, `getgroups` reads the real list
/// into it, and the in-place `sort_unstable_by_key` is pure computation --
/// no allocation, no libc call. `getgroups` is on POSIX's async-signal-safe
/// list.
fn check_supplementary_groups(expected: &[Gid], buffer: &mut [Gid]) -> nix::Result<()> {
    // SAFETY: `getgroups(size, list)` reads at most `size` entries into
    // `list`; `buffer` has exactly `size` `Gid`s (each a transparent
    // `gid_t`), and its raw parts are passed. A real list longer than the
    // buffer returns -1/EINVAL, which becomes `Err` right below.
    let count = unsafe {
        nix::libc::getgroups(
            buffer.len() as nix::libc::c_int,
            buffer.as_mut_ptr().cast::<nix::libc::gid_t>(),
        )
    };
    if count < 0 {
        return Err(Errno::last());
    }
    // `getgroups` called with a size of ZERO -- which an empty `expected`
    // list would pass -- is the "how many are there?" form: it returns the
    // real COUNT and writes nothing. Slicing the buffer to that count would
    // then panic, HERE, between `fork` and `exec`, where a panic unwinds a
    // forked copy of the test harness and ends the child with 101 -- the
    // worker would see `Opened` followed by `Exited(101)` and never learn
    // why. Unreachable today (`getgrouplist` always returns at least the
    // primary group, so `expected` is never empty), and refused rather than
    // trusted to stay that way.
    if count as usize > buffer.len() {
        return Err(Errno::EPERM);
    }
    let got = &mut buffer[..count as usize];
    got.sort_unstable_by_key(|g| g.as_raw());
    if got.len() == expected.len() && got.iter().zip(expected).all(|(a, b)| a == b) {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

/// Linux capability header version 3 (64-bit sets), the value a
/// `_LINUX_CAPABILITY_VERSION_3` header carries. `libc` 0.2 has neither this
/// constant nor the two structs `capget` fills, so they are spelled out
/// here.
const LINUX_CAPABILITY_VERSION_3: u32 = 0x2008_0522;

/// The `capget` header: which version, and whose capabilities (`pid` 0 means
/// this thread). `#[repr(C)]` to match `struct __user_cap_header_struct`.
#[repr(C)]
struct CapHeader {
    version: u32,
    pid: nix::libc::c_int,
}

/// One 32-bit slice of a capability set. Version 3 uses `[CapData; 2]` for
/// the low and high halves of each 64-bit set. `#[repr(C)]` to match
/// `struct __user_cap_data_struct`.
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

/// `Ok` when this process holds no capability in its permitted or effective
/// set, and `EPERM` otherwise. Run in the child, for a NON-root target,
/// right after the identity check: a `setuid` away from root clears the
/// capability sets under ordinary rules, but NOT under
/// `SECBIT_NO_SETUID_FIXUP`, and there the account's program would run with
/// root's `CAP_DAC_*` (so ruling 7's "the account's own permissions decide"
/// would be a lie) and, with an ambient set, keep capabilities into its own
/// code. Proven here rather than assumed away, whatever the securebit's
/// cause. The inheritable set is left alone: `pam_cap` in slice 2c may set
/// it, and the ambient set -- which does reach the program -- is always a
/// subset of permitted, already required to be empty.
///
/// Allocation-free: a stack header, a two-element stack array, one `capget`
/// syscall (a bare system-call wrapper, no libc global state).
fn check_no_capabilities() -> nix::Result<()> {
    let mut header = CapHeader {
        version: LINUX_CAPABILITY_VERSION_3,
        pid: 0,
    };
    let mut data = [CapData::default(); 2];
    // SAFETY: `capget(header, data)` reads the header and writes two
    // `CapData` entries; both live on this stack frame and outlive the call.
    let rc = unsafe {
        nix::libc::syscall(
            nix::libc::SYS_capget,
            &mut header as *mut CapHeader,
            data.as_mut_ptr(),
        )
    };
    if rc != 0 {
        return Err(Errno::last());
    }
    let held = data
        .iter()
        .fold(0u32, |acc, d| acc | d.permitted | d.effective);
    if held == 0 {
        Ok(())
    } else {
        Err(Errno::EPERM)
    }
}

/// The ceiling on the fallback sweep in [`close_other_descriptors`], and
/// the answer when there is no usable limit to read. High enough to cover
/// anything a daemon realistically holds, low enough that walking it costs
/// microseconds -- a soft limit of 1048576 (what systemd hands out) would
/// otherwise mean a million `close` calls per channel on a kernel too old
/// for `close_range`.
const FD_SWEEP_CEILING: RawFd = 65_536;

/// The highest descriptor number a child could be holding: `getrlimit`'s
/// soft limit on open files, capped at [`FD_SWEEP_CEILING`].
///
/// Read BEFORE the fork, by the parent. Only the fallback path of
/// [`close_other_descriptors`] needs it -- `close_range` needs no limit at
/// all -- but it has to be read here either way: `getrlimit` is a libc call,
/// and the space between `fork` and `execve` is for bare syscalls on values
/// that already exist.
fn max_open_descriptors() -> RawFd {
    let mut limit = nix::libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `getrlimit` fills the `rlimit` on this stack frame and
    // touches nothing else of this process.
    if unsafe { nix::libc::getrlimit(nix::libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return FD_SWEEP_CEILING;
    }
    match RawFd::try_from(limit.rlim_cur) {
        Ok(soft) if soft > 0 => soft.min(FD_SWEEP_CEILING),
        // `RLIM_INFINITY`, or a limit past what a descriptor number can be.
        _ => FD_SWEEP_CEILING,
    }
}

/// `close_range(first, last, 0)`: whether the kernel closed that whole
/// range for us. `nix` 0.28 has no wrapper for it, so the syscall is made
/// directly.
///
/// Called in the child between `fork` and `execve`: one syscall, three
/// integers by value, no memory of this process involved. A kernel older
/// than 5.9 answers `ENOSYS`, which comes back as `false` and sends the
/// caller to its loop.
fn close_range(first: RawFd, last: RawFd) -> bool {
    // SAFETY: a bare system call taking three integers by value; it reads
    // and writes nothing in this address space.
    unsafe {
        nix::libc::syscall(
            nix::libc::SYS_close_range,
            first as nix::libc::c_uint,
            last as nix::libc::c_uint,
            0 as nix::libc::c_uint,
        ) == 0
    }
}

/// Close every descriptor from 3 upward except `keep` -- the "close all
/// other descriptors" step the spec asks for (§6.4), and what `sshd` does
/// with `closefrom(STDERR_FILENO + 1)`.
///
/// Everything this crate opens is already close-on-exec (both seams, the
/// startup-report pipe, every Rust `File`), and so, as far as is known, is
/// everything glibc's own NSS machinery opens on the helper's behalf. But
/// "as far as is known" is a property of other people's code, re-decided by
/// every libc and every NSS module a machine happens to install --
/// `libnss_sss`'s socket, an LDAP module's connection to a directory
/// server -- and what it would cost to be wrong is a descriptor of the ROOT
/// helper's reaching an unprivileged program run by whoever logged in.
/// Closing them outright needs no such argument to be true.
///
/// `keep` is the one descriptor the caller cannot do without: a channel's
/// shell keeps the startup-report pipe's write end, its only way to say why
/// it could not start (and closed by the kernel on a successful `execve`
/// anyway), while a monitor keeps its own end of its seam to the helper,
/// which is the only thing it has.
///
/// Called in a channel's shell between `fork` and `execve`, so: no
/// allocation, and every call is a bare syscall. A monitor, which never
/// execs, calls it for a different reason -- nothing else will EVER close
/// what it inherited (see `super::monitor`) -- and keeps to the same rule
/// because it makes the call before it has anything of its own open. `close_range` covers the whole range in
/// two calls whatever the limit is; the fallback walks `3..limit` (see
/// [`max_open_descriptors`]) and is reached only on a kernel older than
/// Linux 5.9.
pub(super) fn close_other_descriptors(keep: RawFd, limit: RawFd) {
    // Two calls, because `keep` is a hole in the middle of the range.
    let below = keep <= 3 || close_range(3, keep - 1);
    let above = close_range(keep + 1, RawFd::MAX);
    if below && above {
        return;
    }
    for fd in 3..limit {
        if fd != keep {
            // Best effort: a number that was never open answers `EBADF`,
            // which is the state this wants it in regardless.
            let _ = nix::unistd::close(fd);
        }
    }
}

/// Clear `ECHO` on the master side, for a tmux control-mode client that
/// must not be shown its own writes.
fn disable_echo(master: BorrowedFd<'_>) -> nix::Result<()> {
    use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
    let mut attrs = tcgetattr(master)?;
    attrs.local_flags.remove(LocalFlags::ECHO);
    tcsetattr(master, SetArg::TCSANOW, &attrs)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::thread::JoinHandle;

    use ssh_key::{Algorithm, PrivateKey};
    use sshauth::record::{encode_public_key, encode_signature};
    use tempfile::TempDir;
    use transport::auth::auth_challenge_v2;
    use transport::AUTH_NONCE_LEN;

    use super::super::protocol::AuthRequestId;

    /// How long a test's `recv` waits for a message before giving up.
    ///
    /// `channel::recv` itself has no timeout, and `cargo test` has no
    /// per-test one either -- so without this, a regression in the
    /// reaping machinery these tests exercise (a missing `Exited`, most
    /// concretely) would present as a run that never returns rather than
    /// a failing test. That already happened once on this branch, with an
    /// early draft of two of the tests below (see the fix-round report).
    const TEST_RECV_TIMEOUT: Duration = Duration::from_secs(10);

    /// A throwaway helper running on a thread of this test process, and the
    /// worker's ends of its two seams.
    ///
    /// Both ends read with [`TEST_RECV_TIMEOUT`] -- see that constant's docs
    /// for why. A test that hands `channels` to a `HelperChannelSpawner` has
    /// to clear it first: that spawner's reader thread would read the
    /// timeout as the helper being gone.
    pub(crate) struct TestHelper {
        /// The worker's end of the channel seam.
        pub(crate) channels: UnixStream,
        /// The worker's end of the authentication seam.
        pub(crate) auth: UnixStream,
        /// The helper's loop. It ends once the peer closes either seam.
        pub(crate) thread: JoinHandle<()>,
        /// Holds the `authorized_keys` file a [`helper_trusting`] helper
        /// reads, and is somewhere for a test's own files to go.
        pub(crate) dir: TempDir,
        /// The login name of the account this test process runs as.
        pub(crate) me: String,
        /// The device token whose login this fixture put on file -- what a
        /// test of it opens its channels under.
        ///
        /// [`PROOF_LOGIN`] for every fixture that admits exactly one login,
        /// whether through a real proof ([`helper_trusting`] plus
        /// [`assert_admits`]) or through `serve`'s own `admitted`
        /// ([`helper_for`]); the FIRST of the tokens seeded by
        /// [`helper_with_verified`], whose tests name each of theirs
        /// anyway. A fixture that admits nobody ([`production_helper`])
        /// still carries it, and an `Open` under it is refused there like
        /// any other.
        pub(crate) login: LoginId,
    }

    impl TestHelper {
        /// Close both seams and wait for the loop to notice.
        pub(crate) fn stop(self) {
            let TestHelper {
                channels,
                auth,
                thread,
                ..
            } = self;
            drop(channels);
            drop(auth);
            join_within(
                thread,
                "the helper loop must end once its peer closes both seams",
            );
        }
    }

    /// Waits for a helper's loop to end, bounded by [`TEST_RECV_TIMEOUT`],
    /// and fails with `what` if it has not: a loop that never ends must fail
    /// the test that expected it to end, not hang the whole run. Polls
    /// `is_finished` rather than joining outright, because a plain `join`
    /// has no timeout; a thread still running at the deadline is left
    /// behind, not waited for.
    pub(crate) fn join_within(thread: JoinHandle<()>, what: &str) {
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while !thread.is_finished() {
            assert!(
                Instant::now() < deadline,
                "{what} -- still running after {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        thread.join().expect("the helper loop must not panic");
    }

    /// The uid of the account this test process runs as -- the one account
    /// every machine the suite runs on is sure to have.
    pub(crate) fn me_uid() -> u32 {
        nix::unistd::Uid::current().as_raw()
    }

    fn my_login() -> String {
        nix::unistd::User::from_uid(nix::unistd::Uid::current())
            .expect("passwd")
            .expect("this account exists")
            .name
    }

    /// Both seams: the worker's two ends, each read bounded by
    /// [`TEST_RECV_TIMEOUT`], and the helper's two ends.
    fn seams_for_test() -> ((UnixStream, UnixStream), (UnixStream, UnixStream)) {
        let (worker_channels, helper_channels) = super::channel::pair().expect("socketpair");
        let (worker_auth, helper_auth) = super::channel::pair().expect("socketpair");
        for end in [&worker_channels, &worker_auth] {
            end.set_read_timeout(Some(TEST_RECV_TIMEOUT))
                .expect("the read must be bounded: a regression here must fail, not hang");
        }
        (
            (worker_channels, worker_auth),
            (helper_channels, helper_auth),
        )
    }

    /// A helper exactly as the daemon runs it -- [`run_until_peer_closes`],
    /// reading keys with the real, identity-switching reader -- for tests
    /// that never ask it to verify anyone.
    pub(crate) fn production_helper() -> TestHelper {
        let ((channels, auth), (helper_channels, helper_auth)) = seams_for_test();
        let thread = std::thread::spawn(move || {
            run_until_peer_closes(helper_channels, helper_auth, test_config())
        });
        TestHelper {
            channels,
            auth,
            thread,
            dir: tempfile::tempdir().expect("tempdir"),
            me: my_login(),
            login: PROOF_LOGIN,
        }
    }

    /// A helper that has already verified the account this test process
    /// runs as, through a genuine `Request::Verify` -- the only way into its
    /// verified set there is -- for the tests about channels, which the
    /// helper opens only for such an account.
    pub(crate) fn helper_with_me_verified() -> TestHelper {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        assert_admits(&h.auth, &key, &h.me);
        h
    }

    /// A number for each request a test sends on the authentication seam.
    /// Unique across the whole test binary, which is all the helper needs:
    /// it only echoes them back.
    fn next_request_id() -> AuthRequestId {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        NEXT.fetch_add(1, AtomicOrdering::Relaxed)
    }

    /// Send `body` on the authentication seam, numbered, without waiting
    /// for an answer; returns the number it went out with.
    pub(crate) fn tell(auth: &UnixStream, body: Request) -> AuthRequestId {
        let id = next_request_id();
        super::channel::send(
            auth,
            &encode(&AuthRequest { id, body }).expect("encode"),
            None,
        )
        .expect("send");
        id
    }

    /// The next answer on the authentication seam.
    pub(crate) fn next_answer(auth: &UnixStream) -> AuthResponse {
        let (bytes, fd) = super::channel::recv(auth).expect("recv").expect("open");
        assert!(
            fd.is_none(),
            "an answer on the authentication seam must not carry a descriptor"
        );
        decode::<AuthResponse>(&bytes).expect("decode")
    }

    /// Ask on the authentication seam and return the answer, which must
    /// carry the question's own number.
    pub(crate) fn ask(auth: &UnixStream, body: Request) -> Response {
        let id = tell(auth, body);
        let answer = next_answer(auth);
        assert_eq!(
            answer.id, id,
            "the helper must answer with the number of the request it answers"
        );
        answer.body
    }

    /// The next message on the channel seam, and the descriptor riding
    /// with it if there is one.
    pub(crate) fn next_response(channels: &UnixStream) -> (Response, Option<OwnedFd>) {
        let (bytes, fd) = super::channel::recv(channels).expect("recv").expect("open");
        (decode::<Response>(&bytes).expect("decode"), fd)
    }

    /// [`answer_to`], but a wait that runs out fails with `what` rather
    /// than with the bare `WouldBlock` the socket's own read timeout
    /// produces: a test whose expected message never arrives should say
    /// WHICH message was missing and what its absence means, not merely
    /// that some read gave up.
    pub(crate) fn answer_to_or_fail(
        channels: &UnixStream,
        id: ChannelId,
        what: &str,
    ) -> (Response, Option<OwnedFd>) {
        loop {
            let (bytes, fd) = match super::channel::recv(channels) {
                Ok(Some(message)) => message,
                Ok(None) => panic!("{what} (the helper closed the channel seam)"),
                Err(e) => panic!("{what} (nothing arrived on the channel seam: {e})"),
            };
            let response = decode::<Response>(&bytes).expect("decode");
            let about = match &response {
                Response::Opened { id }
                | Response::Failed { id, .. }
                | Response::Exited { id, .. } => Some(*id),
                _ => None,
            };
            if about == Some(id) {
                return (response, fd);
            }
        }
    }

    /// Reads the channel seam until a message about channel `id` arrives,
    /// and returns it with its descriptor -- plus every other message that
    /// came first, so a test can insist there were none.
    pub(crate) fn answer_to(
        channels: &UnixStream,
        id: ChannelId,
    ) -> (Response, Option<OwnedFd>, Vec<Response>) {
        let mut before = Vec::new();
        loop {
            let (response, fd) = next_response(channels);
            let about = match &response {
                Response::Opened { id }
                | Response::Failed { id, .. }
                | Response::Exited { id, .. } => Some(*id),
                _ => None,
            };
            if about == Some(id) {
                return (response, fd, before);
            }
            before.push(response);
        }
    }

    /// A program only this test runs: `sleep`, under a name of its own -- a
    /// symbolic link in `dir` whose name nothing else on the machine has.
    /// The kernel names a process after the file it was started from, so
    /// [`processes_named`] can then tell whether it was ever started at all:
    /// running, or dead and not yet reaped, alike. A marker file the program
    /// wrote could not -- a program killed before its first instruction (by
    /// a terminal hung up under it, say) leaves none. Returns the link's path
    /// and the name.
    fn unique_program(dir: &Path, tag: &str) -> (PathBuf, String) {
        uniquely_named(dir, tag, "/bin/sleep")
    }

    /// [`unique_program`], for any `target` rather than only `sleep`.
    fn uniquely_named(dir: &Path, tag: &str, target: &str) -> (PathBuf, String) {
        // A process name holds 15 bytes; this stays under that.
        let name = format!(
            "qsh{tag}{:08x}",
            rand_core::RngCore::next_u32(&mut rand_core::OsRng)
        );
        let path = dir.join(&name);
        std::os::unix::fs::symlink(target, &path).expect("link a uniquely named program");
        (path, name)
    }

    /// Every process named `name`, running or a zombie -- see
    /// [`unique_program`].
    fn processes_named(name: &str) -> Vec<u32> {
        std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .filter(|pid| {
                std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .map(|comm| comm.trim_end() == name)
                    .unwrap_or(false)
            })
            .collect()
    }

    /// An `Open` for this test's own account that runs `program` for five
    /// minutes -- long enough to still be there whenever the test looks.
    /// `exec` so the account's shell replaces itself with `program`, whose
    /// name `processes_named` then finds in the process table (a bare
    /// command a shell might or might not exec-optimize; `exec` makes it
    /// certain).
    fn open_running(id: ChannelId, program: &Path) -> Request {
        Request::Open {
            id,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            command: format!("exec {} 300", program.display()),
        }
    }

    /// A `HelperConfig` for tests that never ask the helper to verify
    /// anyone, and so never read its contents.
    ///
    /// `startup_timeout` is the DAEMON's, not a shorter one: a test whose
    /// child is merely slow (`slow_become_account`, a whole second of it)
    /// has to be inside the budget, or what it measures is the giving-up
    /// rather than the waiting. The one test that is about the giving-up
    /// asks for a short budget of its own
    /// (`a_child_that_never_reports_is_killed_and_refused`).
    fn test_config() -> HelperConfig {
        HelperConfig {
            authorized_keys_template: "%h/.ssh/authorized_keys".into(),
            permit_root: false,
            tty_gid: None,
            worker_user: "qshd".into(),
            startup_timeout: STARTUP_REPORT_TIMEOUT,
            verify_timeout: VERIFY_TIMEOUT,
            pam_service: PAM_SERVICE.to_string(),
            pam_confdir: Some(permissive_pam_confdir()),
        }
    }

    /// The PAM stack every fixture here runs on unless it names one of its
    /// own: a permissive one, checked in at
    /// `qshd/tests/fixtures/pam/qshd`.
    ///
    /// It is what keeps the suite testing THIS code rather than the machine
    /// it runs on. A monitor with no configuration directory calls
    /// `pam_start("qshd", ...)`, finds no `/etc/pam.d/qshd`, and gets
    /// `/etc/pam.d/other` -- on a stock Ubuntu `@include common-account`
    /// and `@include common-session`, so every channel test would be asking
    /// logind for a session and reading `/etc/shadow`, unprivileged, and
    /// would pass or fail by the host's policy rather than by anything here.
    ///
    /// A file in the repository rather than a temporary directory made at
    /// run time, because every fixture in this module needs it and a
    /// process-wide temporary one would outlive the run that made it.
    fn permissive_pam_confdir() -> PathBuf {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join("pam");
        assert!(
            dir.join(PAM_SERVICE).is_file(),
            "the fixture PAM stack must exist, or every channel test would silently run the \
             machine's own /etc/pam.d/other: {}",
            dir.display()
        );
        dir
    }

    /// Reads from a channel's pty master until `needle` appears in the
    /// accumulated output, or [`TEST_RECV_TIMEOUT`] elapses without it --
    /// the same bound every other blocking wait in this module's tests
    /// already has (see that constant's docs), applied to the one blocking
    /// call here that used to have none: a plain `File::read` on a pty
    /// master has no read-timeout knob of its own the way `UnixStream`
    /// does (`set_read_timeout`), so this polls first, bounded by the
    /// remaining budget, and only reads once `poll` says there is
    /// something there -- a regression that stops output from ever
    /// containing `needle` then fails the assertion below instead of
    /// hanging the test run.
    fn read_until_or_timeout(master: &mut std::fs::File, needle: &str) -> String {
        use std::io::Read;

        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        let mut seen = String::new();
        let mut chunk = [0u8; 256];
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return seen;
            };
            let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
            let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, timeout) {
                Ok(0) => return seen,
                Ok(_) => {}
                Err(nix::Error::EINTR) => continue,
                Err(_) => return seen,
            }
            match master.read(&mut chunk) {
                Ok(0) => return seen,
                Ok(n) => {
                    seen.push_str(&String::from_utf8_lossy(&chunk[..n]));
                    if seen.contains(needle) {
                        return seen;
                    }
                }
                Err(_) => return seen,
            }
        }
    }

    /// The helper opens a channel, runs the command in it, and the master
    /// side it hands back really is connected to that process.
    #[test]
    fn the_helper_opens_a_channel_that_echoes_its_command() {
        let h = helper_with_me_verified();

        let req = Request::Open {
            id: 1,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: Some("xterm-256color".to_string()),
            echo: false,
            shell: false,
            command: "/bin/echo helper-works".to_string(),
        };
        super::channel::send(&h.channels, &encode(&req).expect("encode"), None).expect("send");

        let (bytes, fd) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("open");
        assert_eq!(
            decode::<Response>(&bytes).expect("decode"),
            Response::Opened { id: 1 }
        );
        let mut master = std::fs::File::from(fd.expect("a master descriptor must arrive"));

        let seen = read_until_or_timeout(&mut master, "helper-works");
        assert!(
            seen.contains("helper-works"),
            "the channel must carry the command's output, got {seen:?}"
        );

        h.stop();
    }

    /// The account's shell mediates every command, the `sshd` way: the
    /// helper never parses the command, it runs it as `<shell> -c <command>`,
    /// so a confining shell (`git-shell`, `rbash`, `nologin`) keeps its say.
    /// A command channel must show the shell was handed `-c` and the command
    /// as its ARGUMENTS -- and must NOT show the command's own output, which
    /// exec'ing it directly (the old behaviour) would.
    ///
    /// The account's shell is a small `#!/bin/sh` script that prints its
    /// arguments and exits, so what the child was handed is visible. It is
    /// not `$0`: the kernel rewrites a shebang script's `$0` to the script's
    /// path, so only the positional arguments carry what argv the helper
    /// built -- which is exactly the thing under test here. The command is
    /// an ABSOLUTE path (`/usr/bin/id`) so that a direct-exec control really
    /// runs it and its output really appears.
    #[test]
    fn the_shell_mediates_commands_the_sshd_way() {
        let dir = tempfile::tempdir().expect("tempdir");
        let script = dir.path().join("say-argv");
        std::fs::write(
            &script,
            "#!/bin/sh\nprintf 'ARGS'\nfor a in \"$@\"; do printf '|%s' \"$a\"; done\n\
             printf '|END\\n'\n",
        )
        .expect("write the script shell");
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
            .expect("make the script executable");

        let me = super::account::lookup(&my_login()).expect("this account resolves");
        let account = Account {
            shell: script.clone(),
            ..me
        };

        let h = helper_for(account.clone(), test_config(), UNPRIVILEGED);
        let out = output_of(&h, &open_for(1, &account, "/usr/bin/id"));
        assert!(
            out.contains("ARGS|-c|/usr/bin/id|END"),
            "a command must reach the shell as `-c <command>`, got {out:?}"
        );
        assert!(
            !out.contains("uid="),
            "the command must reach the account's shell, not be exec'd directly (no `id` output \
             may appear), got {out:?}"
        );
        h.stop();
    }

    /// Spec §6.4: a channel's program inherits its terminal, on 0, 1 and 2,
    /// and not one descriptor more -- whether or not what the helper holds
    /// happens to be close-on-exec.
    ///
    /// The bait is an ordinary file opened in the helper's own process
    /// (these tests run the helper on a thread of this one) WITHOUT
    /// `O_CLOEXEC`: the shape a descriptor left behind by an NSS module has,
    /// and the one the exec would not close by itself. Its name is one
    /// nothing else on the machine has, and `/proc/self/fd` reports the
    /// path each descriptor resolves to, so finding it in the child's own
    /// table is unambiguous. Control: drop the `close_other_descriptors`
    /// call -- the name appears.
    #[test]
    fn a_channels_program_inherits_no_descriptor_but_its_terminal() {
        let me = super::account::lookup(&my_login()).expect("this account resolves");
        let account = Account {
            shell: PathBuf::from("/bin/sh"),
            ..me
        };
        let h = helper_for(account.clone(), test_config(), UNPRIVILEGED);

        let bait_name = format!(
            "qshd-bait-{:08x}",
            rand_core::RngCore::next_u32(&mut rand_core::OsRng)
        );
        let bait_path = h.dir.path().join(&bait_name);
        std::fs::write(&bait_path, b"bait").expect("write the bait file");
        let bait = nix::fcntl::open(
            &bait_path,
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        )
        .expect("open the bait");
        // Precondition: the bait really is inheritable. Were it
        // close-on-exec, the exec would close it whatever this child did,
        // and the check below would pass with the sweep having done
        // nothing at all.
        let flags = nix::fcntl::FdFlag::from_bits_truncate(
            nix::fcntl::fcntl(bait, nix::fcntl::FcntlArg::F_GETFD).expect("fcntl(F_GETFD)"),
        );
        assert!(
            !flags.contains(nix::fcntl::FdFlag::FD_CLOEXEC),
            "precondition: the bait must NOT be close-on-exec, or this test proves nothing"
        );

        let out = output_of(&h, &open_for(1, &account, "ls -l /proc/self/fd"));
        let _ = nix::unistd::close(bait);

        // The listing really happened, so the absence below is an absence
        // in a real answer rather than in no answer at all.
        assert!(
            out.contains("->"),
            "the program must have listed its own descriptors, got {out:?}"
        );
        assert!(
            !out.contains(&bait_name),
            "a channel's program must inherit no descriptor of the helper's, but its own \
             /proc/self/fd names {bait_name}: {out:?}"
        );
        h.stop();
    }

    /// A `shell: true` channel is a LOGIN shell, `argv[0]` starting with
    /// `-`, as `sshd` and `login` start one (M7). The account's shell is a
    /// real binary (`/bin/sh`), which -- unlike a shebang script -- keeps the
    /// `argv[0]` it was exec'd with as its own `$0`. Echo is off, so the only
    /// `ARGZERO=` in the output is the shell's own `printf`, never the echo
    /// of the typed line.
    #[test]
    fn a_shell_channel_is_a_login_shell() {
        use std::io::Write;

        let me = super::account::lookup(&my_login()).expect("this account resolves");
        let account = Account {
            shell: PathBuf::from("/bin/sh"),
            ..me
        };
        let h = helper_for(account.clone(), test_config(), UNPRIVILEGED);

        // Echo off so the typed line is not reflected -- only the shell's
        // own output carries `ARGZERO=`.
        let req = Request::Open {
            id: 1,
            uid: account.uid.as_raw(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: false,
            shell: true,
            command: String::new(),
        };
        super::channel::send(&h.channels, &encode(&req).expect("encode"), None).expect("send");
        let (opened, fd, _) = answer_to(&h.channels, 1);
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        let mut master = std::fs::File::from(fd.expect("a master descriptor"));
        // `unset HISTFILE` first: this is a real interactive login shell
        // with the account's real `HOME` from passwd (the helper hands a
        // channel nothing of this test process's environment, so the
        // `HISTFILE=/dev/null` other tests rely on never reaches it), and
        // where `/bin/sh` is bash it appends what it was typed to that
        // home's history on exit -- the runner's own, or root's under
        // `sudo`.
        master
            .write_all(b"unset HISTFILE; printf 'ARGZERO=%s\\n' \"$0\"; exit\n")
            .expect("write into the login shell");
        let out = read_to_end_within(&mut master)
            .unwrap_or_else(|partial| panic!("the shell must exit, got so far {partial:?}"));
        // The whole `argv[0]`, not merely its first character: `-` alone
        // would also match `-` followed by anything at all, and what is
        // under test is that the helper built `-` + the shell's BASENAME
        // (`/bin/sh` -> `-sh`), which is what `sshd` and `login` start.
        assert!(
            out.contains("ARGZERO=-sh"),
            "a shell channel must be a login shell whose argv[0] is exactly \"-sh\", got {out:?}"
        );
        h.stop();
    }

    /// A COMMAND's shell is not a login shell: its `$0` is the shell's bare
    /// basename, with no leading `-`. The distinction is not cosmetic -- a
    /// login shell reads the profile files (`/etc/profile`,
    /// `~/.bash_profile`, ...) before it runs anything, so making every
    /// command a login shell would run the account's whole login
    /// environment on every single command: the app's `tmux -C` control
    /// channel included, and worse for any account whose profile is slow or
    /// expects a human.
    ///
    /// `/bin/sh` is a real binary, unlike the script shell of the test
    /// above, so it keeps the `argv[0]` it was exec'd with as its own `$0`.
    #[test]
    fn a_command_runs_under_a_shell_that_is_not_a_login_shell() {
        let me = super::account::lookup(&my_login()).expect("this account resolves");
        let account = Account {
            shell: PathBuf::from("/bin/sh"),
            ..me
        };
        let h = helper_for(account.clone(), test_config(), UNPRIVILEGED);
        let out = output_of(&h, &open_for(1, &account, "printf 'ZERO=%s\\n' \"$0\""));
        assert!(
            out.contains("ZERO=sh"),
            "a command's shell must be a plain `sh`, argv[0] exactly \"sh\", got {out:?}"
        );
        assert!(
            !out.contains("ZERO=-sh"),
            "a command must NOT get a login shell (it would read the profiles before every \
             command), got {out:?}"
        );
        h.stop();
    }

    /// An account whose shell cannot be exec'd fails its channel rather
    /// than opening one: the `execve` returns, the child reports the errno
    /// over the startup-report pipe, and the worker is told `Failed` with
    /// that errno in it and no terminal -- never `Opened` followed a moment
    /// later by an unexplained exit.
    #[test]
    fn a_shell_that_cannot_be_exec_d_fails_the_channel_with_no_terminal() {
        let me = super::account::lookup(&my_login()).expect("this account resolves");
        let account = Account {
            shell: PathBuf::from("/nonexistent/shell"),
            ..me
        };
        let h = helper_for(account.clone(), test_config(), UNPRIVILEGED);
        super::channel::send(
            &h.channels,
            &encode(&open_shell(1, &account)).expect("encode"),
            None,
        )
        .expect("send");
        let (answer, fd) = next_response(&h.channels);
        match &answer {
            Response::Failed { id: 1, reason } => assert!(
                reason.contains("ENOENT"),
                "the refusal must carry the exec's own errno, got {reason:?}"
            ),
            other => panic!("a shell that cannot be exec'd must fail the channel, got {other:?}"),
        }
        assert!(fd.is_none(), "a failed channel hands back no terminal");
        h.stop();
    }

    /// The exec target is the account's shell FROM PASSWD -- a uniquely
    /// named link so only IT can be what ran -- and `/bin/sh` when passwd
    /// leaves it empty, never the helper's own `$SHELL`.
    #[test]
    fn the_exec_target_is_the_accounts_shell_from_passwd() {
        let me = super::account::lookup(&my_login()).expect("this account resolves");

        // A uniquely named link to `/usr/bin/env` as the shell: a login
        // shell execs it directly, and `env` -- ignoring its argv0 -- prints
        // the environment, in which SHELL is what the helper set from passwd:
        // the link itself, nothing else on the machine has that name.
        let dir = tempfile::tempdir().expect("tempdir");
        let (renamed_env, _) = uniquely_named(dir.path(), "e", "/usr/bin/env");
        let account = Account {
            shell: renamed_env.clone(),
            ..me.clone()
        };
        let h = helper_for(account.clone(), test_config(), UNPRIVILEGED);
        let out = output_of(&h, &open_shell(1, &account));
        assert!(
            out.contains(&format!("SHELL={}", renamed_env.display())),
            "the shell channel must exec the account's shell ({}) and set SHELL to it, got \
             {out:?}",
            renamed_env.display()
        );
        h.stop();

        // An empty passwd shell falls back to `/bin/sh`: ask the resulting
        // shell for `$SHELL` through a command channel.
        let account = Account {
            shell: PathBuf::new(),
            ..me
        };
        let h = helper_for(account.clone(), test_config(), UNPRIVILEGED);
        let out = output_of(
            &h,
            &open_for(2, &account, "printf 'SHELL=%s\\n' \"$SHELL\""),
        );
        assert!(
            out.contains("SHELL=/bin/sh"),
            "an empty passwd shell must fall back to /bin/sh, got {out:?}"
        );
        h.stop();
    }

    /// A channel whose program exits on its own is reported exactly once,
    /// with its own id and exit code -- the reaper, exercised rather than
    /// only read. This is the machinery the next task's `ChannelWait` is
    /// built on.
    #[test]
    fn a_channel_that_exits_on_its_own_reports_its_exit_exactly_once() {
        let h = helper_with_me_verified();

        let req = Request::Open {
            id: 5,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            command: "exit 42".to_string(),
        };
        super::channel::send(&h.channels, &encode(&req).expect("encode"), None).expect("send");

        // `_fd` (the master side), held until the end of the function:
        // dropping it early would close the pty, and the kernel would then
        // send the shell (its session leader, via `setsid`/`TIOCSCTTY`) a
        // real `SIGHUP` -- racing the shell's own `exit 42` and risking a
        // signalled exit instead of the one this test means to observe.
        let (bytes, _fd) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("open");
        assert_eq!(
            decode::<Response>(&bytes).expect("decode"),
            Response::Opened { id: 5 }
        );

        let (bytes, _) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("an exit report");
        assert_eq!(
            decode::<Response>(&bytes).expect("decode"),
            Response::Exited { id: 5, code: 42 }
        );

        h.stop();
    }

    /// `Close` brings down a program that would otherwise keep running: the
    /// helper sends it `SIGHUP`, and the reaper reports the exit that
    /// follows.
    #[test]
    fn close_ends_a_channel_that_would_otherwise_keep_running() {
        let h = helper_with_me_verified();

        let req = Request::Open {
            id: 6,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            // `exec` so the shell becomes `sleep`: then the helper's SIGHUP
            // reaches `sleep` itself, whose default disposition terminates
            // it, rather than the shell that spawned it.
            command: "exec sleep 300".to_string(),
        };
        super::channel::send(&h.channels, &encode(&req).expect("encode"), None).expect("send");

        // `_fd` (the master side), held until the end of the function: this
        // test means to prove that `Close` is what ends `sleep`, and
        // dropping the master side early would hang up the pty and send it
        // a `SIGHUP` of its own, making the assertion below pass for the
        // wrong reason.
        let (bytes, _fd) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("open");
        assert_eq!(
            decode::<Response>(&bytes).expect("decode"),
            Response::Opened { id: 6 }
        );

        let close = Request::Close { id: 6 };
        super::channel::send(&h.channels, &encode(&close).expect("encode"), None)
            .expect("send close");

        let (bytes, _) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("an exit report following the close");
        match decode::<Response>(&bytes).expect("decode") {
            // `sleep` does not catch SIGHUP, so the default disposition
            // (terminate) applies -- reported as a shell would, 128 plus
            // the signal number.
            Response::Exited { id, code } => {
                assert_eq!(id, 6);
                assert_eq!(code, 128 + nix::sys::signal::Signal::SIGHUP as i32);
            }
            other => panic!("expected the closed channel to exit, got {other:?}"),
        }

        h.stop();
    }

    /// The critical case `close_ends_a_channel_that_would_otherwise_keep_running`
    /// does not cover: a channel that TRAPS `SIGHUP` away entirely. Before
    /// this fix, `Close` only ever sent `SIGHUP` and nothing escalated --
    /// this channel would never exit, never produce an `Exited`, and (in
    /// `run_channel_session`'s teardown) wedge whatever awaited its reap
    /// forever, for as long as any authenticated user cared to open one.
    /// `ChannelWait::kill`'s contract
    /// (`crates/transport/src/channel_server.rs`) is to force the process
    /// down, and this proves the helper now actually does: within
    /// `CLOSE_GRACE_PERIOD` of the `SIGHUP` going unanswered, `reap`
    /// escalates to `SIGKILL`, which cannot be trapped, and the exit
    /// arrives regardless.
    #[test]
    fn close_kills_a_channel_that_ignores_sighup() {
        let h = helper_with_me_verified();

        let req = Request::Open {
            id: 8,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            // `trap '' HUP` ignores the signal outright; `echo ready` gives
            // the test a marker to wait for so `Close` is never sent before
            // the trap is actually installed (a real race: the child is a
            // freshly exec'd process, and nothing here otherwise says the
            // shell has run past its first statement before the test's
            // `Close` arrives). `read` then blocks with no forked child and
            // no input ever coming, so the only way out is a signal it
            // cannot trap.
            command: "trap '' HUP; echo ready; read x".to_string(),
        };
        super::channel::send(&h.channels, &encode(&req).expect("encode"), None).expect("send");

        // `master`, held until the end: dropping it early would hang the
        // pty up on its own, defeating the point of this test -- see the
        // sibling test above for the same reasoning. It also doubles here
        // as the synchronisation channel described above.
        let (bytes, fd) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("open");
        assert_eq!(
            decode::<Response>(&bytes).expect("decode"),
            Response::Opened { id: 8 }
        );
        let mut master = std::fs::File::from(fd.expect("a master descriptor must arrive"));
        let seen = read_until_or_timeout(&mut master, "ready");
        assert!(
            seen.contains("ready"),
            "the trap must be installed before this test sends Close, got {seen:?}"
        );

        let close = Request::Close { id: 8 };
        super::channel::send(&h.channels, &encode(&close).expect("encode"), None)
            .expect("send close");

        let (bytes, _) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("an exit report, even though the channel ignored SIGHUP");
        match decode::<Response>(&bytes).expect("decode") {
            // SIGKILL cannot be trapped or ignored, so the default
            // disposition applies -- 128 plus the signal number, exactly as
            // `reap` already reports every signalled exit.
            Response::Exited { id, code } => {
                assert_eq!(id, 8);
                assert_eq!(code, 128 + nix::sys::signal::Signal::SIGKILL as i32);
            }
            other => panic!("expected the escalated channel to exit, got {other:?}"),
        }

        h.stop();
    }

    /// A repeated `id` is a protocol violation, refused rather than
    /// silently overwriting the pid already `live` under it -- an
    /// overwritten pid would never be closed (the worker has lost its own
    /// handle to it) and never reaped (`reap` only waits on pids reachable
    /// from `live`), a permanent zombie.
    #[test]
    fn a_repeated_id_is_refused_rather_than_overwriting_the_live_pid() {
        let h = helper_with_me_verified();

        let first = Request::Open {
            id: 7,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            command: "exec sleep 300".to_string(),
        };
        super::channel::send(&h.channels, &encode(&first).expect("encode"), None).expect("send");
        let (bytes, _fd) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("open");
        assert_eq!(
            decode::<Response>(&bytes).expect("decode"),
            Response::Opened { id: 7 }
        );

        let second = Request::Open {
            id: 7,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            command: "echo should-not-run".to_string(),
        };
        super::channel::send(&h.channels, &encode(&second).expect("encode"), None).expect("send");
        let (bytes, _) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("a refusal");
        match decode::<Response>(&bytes).expect("decode") {
            // Refused for the repeated id, not by an earlier check -- the
            // account is verified and the login is on file, so neither the
            // uid check nor the login check has anything to say.
            Response::Failed { id: 7, reason } => assert!(
                reason.contains("already open"),
                "the refusal must be the repeated id's, got {reason:?}"
            ),
            other => panic!(
                "a repeated id must be refused, not silently opened over the live one, got \
                 {other:?}"
            ),
        }

        // The original channel must still be the one tracked: closing id 7
        // now has to end the first `sleep`, proving the second `Open`
        // never touched `live`'s entry for it.
        let close = Request::Close { id: 7 };
        super::channel::send(&h.channels, &encode(&close).expect("encode"), None)
            .expect("send close");
        let (bytes, _) = super::channel::recv(&h.channels)
            .expect("recv")
            .expect("an exit report");
        match decode::<Response>(&bytes).expect("decode") {
            Response::Exited { id, .. } => assert_eq!(id, 7),
            other => panic!("expected the original channel to exit, got {other:?}"),
        }

        h.stop();
    }

    /// Every nonce the helper hands out is different, and it remembers each
    /// one so a proof can only be spent against the handshake it was issued
    /// for. This only checks issuance; spending is `spend_nonce`'s own
    /// tests, below, and the `Request::Verify` end-to-end ones.
    #[test]
    fn the_helper_issues_a_fresh_nonce_every_time() {
        let h = production_helper();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..8 {
            match ask(&h.auth, Request::Nonce) {
                Response::Nonce { nonce } => assert!(seen.insert(nonce), "a nonce repeated"),
                other => panic!("expected a nonce, got {other:?}"),
            }
        }
        h.stop();
    }

    /// At [`MAX_OUTSTANDING_NONCES`], the helper refuses rather than evicts:
    /// evicting would let a flood of unspent requests invalidate an honest
    /// client's still-outstanding nonce (see that constant's docs). Every one
    /// of the first `MAX_OUTSTANDING_NONCES` requests here lands well inside
    /// `NONCE_LIFETIME` (30s), so none has expired by the time the next one
    /// arrives -- the table is genuinely full, not merely stale.
    #[test]
    fn the_helper_refuses_a_nonce_once_the_outstanding_table_is_full() {
        let h = production_helper();
        for _ in 0..MAX_OUTSTANDING_NONCES {
            assert!(
                matches!(ask(&h.auth, Request::Nonce), Response::Nonce { .. }),
                "every request up to the cap must be granted"
            );
        }
        assert!(
            matches!(ask(&h.auth, Request::Nonce), Response::NonceUnavailable),
            "the request past the cap must be refused, not silently granted"
        );
        h.stop();
    }

    /// The sweep uses an inclusive boundary: an entry issued exactly
    /// `NONCE_LIFETIME` ago is gone, one issued a millisecond later (so it
    /// is a millisecond younger at the same `now`) survives.
    #[test]
    fn sweep_expired_nonces_uses_an_inclusive_boundary() {
        let now = Instant::now();
        let mut nonces: HashMap<Nonce, Instant> = HashMap::new();
        let exactly_expired = now
            .checked_sub(NONCE_LIFETIME)
            .expect("NONCE_LIFETIME fits before now in this test run");
        let one_ms_younger = now
            .checked_sub(NONCE_LIFETIME - Duration::from_millis(1))
            .expect("fits before now in this test run");
        nonces.insert([1u8; 16], exactly_expired);
        nonces.insert([2u8; 16], one_ms_younger);

        sweep_expired_nonces(&mut nonces, now);

        assert!(
            !nonces.contains_key(&[1u8; 16]),
            "an entry exactly NONCE_LIFETIME old must be swept"
        );
        assert!(
            nonces.contains_key(&[2u8; 16]),
            "an entry one millisecond younger must survive"
        );
    }

    /// `spend_nonce`'s own boundary, one call each way rather than through
    /// the full seam: an entry issued exactly `NONCE_LIFETIME` ago is
    /// refused -- and gone either way, per `spend_nonce`'s own doc comment
    /// -- while one issued a nanosecond later (so a nanosecond younger at
    /// the same `now`) is admitted, and spent (also gone) by the very call
    /// that admitted it.
    #[test]
    fn spend_nonce_is_inclusive_at_the_boundary_and_removes_either_way() {
        let now = Instant::now();
        let nonce = [3u8; 16];

        let exactly_expired = now
            .checked_sub(NONCE_LIFETIME)
            .expect("NONCE_LIFETIME fits before now in this test run");
        let mut expired_table: HashMap<Nonce, Instant> = HashMap::new();
        expired_table.insert(nonce, exactly_expired);
        assert_eq!(
            spend_nonce(&mut expired_table, &nonce, now),
            Err("nonce expired"),
            "an entry exactly NONCE_LIFETIME old must be refused"
        );
        assert!(
            !expired_table.contains_key(&nonce),
            "an expired entry must not survive spend_nonce either"
        );

        let one_ns_younger = now
            .checked_sub(NONCE_LIFETIME - Duration::from_nanos(1))
            .expect("fits before now in this test run");
        let mut live_table: HashMap<Nonce, Instant> = HashMap::new();
        live_table.insert(nonce, one_ns_younger);
        assert_eq!(
            spend_nonce(&mut live_table, &nonce, now),
            Ok(()),
            "an entry one nanosecond younger must be admitted"
        );
        assert!(
            !live_table.contains_key(&nonce),
            "an admitted entry is spent -- removed -- too, by the same call"
        );
    }

    /// A synthetic `Account` for `root_refused`'s tests. `uid` and `name`
    /// are the point; everything else is filler -- no real passwd lookup is
    /// involved on purpose, since the property under test ("uid 0, not the
    /// name") is exactly the one an end-to-end test cannot exercise without
    /// a second uid-0 passwd entry on the machine the suite runs on.
    fn synthetic_account(uid: u32, name: &str) -> Account {
        Account {
            uid: nix::unistd::Uid::from_raw(uid),
            gid: nix::unistd::Gid::from_raw(1000),
            name: name.to_string(),
            home: "/home/nobody-in-particular".into(),
            shell: "/bin/sh".into(),
            groups: Vec::new(),
        }
    }

    /// `root_refused` looks at the uid, never the name: an account named
    /// "toor" (a common root alias) but carrying uid 0 is refused exactly
    /// like an account actually named "root" would be, and an ordinary
    /// account that merely happens to be NAMED "root" is not refused by
    /// this check at all. `permit_root: true` admits uid 0 regardless of
    /// its name.
    #[test]
    fn root_refused_looks_at_uid_not_name() {
        let refusing = HelperConfig {
            authorized_keys_template: "%h/.ssh/authorized_keys".into(),
            permit_root: false,
            tty_gid: None,
            worker_user: "qshd".into(),
            startup_timeout: STARTUP_REPORT_TIMEOUT,
            verify_timeout: VERIFY_TIMEOUT,
            pam_service: PAM_SERVICE.to_string(),
            pam_confdir: None,
        };
        assert!(
            root_refused(&refusing, &synthetic_account(0, "toor")),
            "uid 0 must be refused under permit_root: false, whatever the name is"
        );
        assert!(
            !root_refused(&refusing, &synthetic_account(1000, "root")),
            "an ordinary uid merely NAMED \"root\" must not be refused by this check"
        );

        let permitting = HelperConfig {
            authorized_keys_template: "%h/.ssh/authorized_keys".into(),
            permit_root: true,
            tty_gid: None,
            worker_user: "qshd".into(),
            startup_timeout: STARTUP_REPORT_TIMEOUT,
            verify_timeout: VERIFY_TIMEOUT,
            pam_service: PAM_SERVICE.to_string(),
            pam_confdir: None,
        };
        assert!(
            !root_refused(&permitting, &synthetic_account(0, "toor")),
            "uid 0 must be admitted once permit_root is on, whatever the name is"
        );
    }

    /// Releasing a nonce frees its slot BY IDENTITY, not merely by count:
    /// fill the table to `MAX_OUTSTANDING_NONCES`, then release an UNKNOWN
    /// nonce first -- the table is still full of the real ones, so the next
    /// request must still be refused. Only releasing one of the real,
    /// outstanding nonces frees a slot and lets the next request through.
    /// `ReleaseNonce` gets no reply either way, so the very next thing read
    /// off the authentication seam after each release is the answer to the
    /// `Nonce` request that follows it -- `ask` insists the number matches --
    /// proving the no-reply contract at the same time, not just asserting
    /// it.
    #[test]
    fn releasing_a_nonce_frees_a_slot_only_by_identity() {
        let h = production_helper();
        let mut first_nonce = None;
        for i in 0..MAX_OUTSTANDING_NONCES {
            match ask(&h.auth, Request::Nonce) {
                Response::Nonce { nonce } => {
                    if i == 0 {
                        first_nonce = Some(nonce);
                    }
                }
                other => panic!("expected a nonce, got {other:?}"),
            }
        }
        let first_nonce = first_nonce.expect("at least one nonce was issued");

        // Releasing an UNKNOWN nonce must NOT free a slot: the table still
        // holds MAX_OUTSTANDING_NONCES real entries, so the next request is
        // still refused.
        tell(
            &h.auth,
            Request::ReleaseNonce {
                nonce: [0xFFu8; 16],
            },
        );
        assert!(
            matches!(ask(&h.auth, Request::Nonce), Response::NonceUnavailable),
            "releasing an unknown nonce must not free a slot"
        );

        // Releasing the KNOWN, real nonce DOES free its slot.
        tell(&h.auth, Request::ReleaseNonce { nonce: first_nonce });
        assert!(
            matches!(ask(&h.auth, Request::Nonce), Response::Nonce { .. }),
            "releasing the known, outstanding nonce must free its slot"
        );
        h.stop();
    }

    // -- Request::Verify: the helper checks a client's proof itself -------

    /// Test-only key reader: the same file, the same bounds, no identity
    /// switch. The real reader, `authorized::read_for`, always calls
    /// `setgroups`, which needs `CAP_SETGID` even to "become yourself" --
    /// so it cannot run unprivileged. The switch itself is proven under
    /// root in `qshd/tests/authorized_keys_privilege.rs` and end to end in
    /// a later task.
    fn read_keys_plainly(account: &Account, template: &str) -> Result<String, AuthorizedError> {
        let path = super::account::expand_template(template, account);
        super::authorized::to_key_text(super::authorized::read_regular_file_bounded(&path), &path)
    }

    /// Test-only stand-in for [`become_account`]: changes nothing, because
    /// an unprivileged process cannot change anything here -- `setgroups`
    /// needs `CAP_SETGID` even to set the list the process already has. The
    /// child still runs [`check_identity`] after it, so a helper with these
    /// switches runs channels for this test process's own account and
    /// refuses every other one. The drop itself is proven under root, with
    /// [`AccountSwitches::REAL`].
    ///
    /// PRECONDITION for every unprivileged channel test that uses these
    /// switches: the runner's LIVE supplementary groups must equal what
    /// `getgrouplist` returns for its account, because the child still
    /// checks the real list against the expected one
    /// ([`check_supplementary_groups`]) and nothing here changes either. A
    /// session that has not picked up a recent `usermod -aG` yet, or a CI
    /// job started with a narrower list, therefore fails these tests with
    /// `EPERM` -- loudly, and for a reason that has nothing to do with what
    /// they check. Seeding the account handed to `helper_for` with this
    /// process's own `getgroups()` would side-step it where the test is not
    /// about verification; it is left undone because no machine this suite
    /// runs on has needed it.
    fn keep_identity(_uid: Uid, _gid: Gid, _groups: &[Gid]) -> nix::Result<()> {
        Ok(())
    }

    /// Test-only stand-in for [`become_account`] that takes a whole second
    /// about it, in the CHILD, before the `exec` that would close the
    /// startup-report pipe: the shape of a `chdir` hung on a dead NFS home,
    /// with no NFS anywhere in sight.
    ///
    /// `nanosleep` is on POSIX's async-signal-safe list and allocates
    /// nothing, so it is legal between `fork` and `exec` -- see this
    /// module's own docs for what that rules out.
    fn slow_become_account(_uid: Uid, _gid: Gid, _groups: &[Gid]) -> nix::Result<()> {
        let how_long = nix::libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        // SAFETY: `nanosleep` reads one `timespec` on this thread's own
        // stack and writes nothing back (the second argument is null).
        let _ = unsafe { nix::libc::nanosleep(&how_long, std::ptr::null_mut()) };
        Ok(())
    }

    /// The same, but for ever: a child that never reports its startup at
    /// all, which is the case `HelperConfig::startup_timeout` exists to
    /// bound. `pause` returns only for a signal with a handler, and this
    /// child has none -- `SIGKILL`, which is what the helper sends, could
    /// not be caught even if it had.
    fn hang_forever(_uid: Uid, _gid: Gid, _groups: &[Gid]) -> nix::Result<()> {
        loop {
            // SAFETY: `pause` takes no arguments, touches nothing this
            // process owns, and is on POSIX's async-signal-safe list.
            unsafe { nix::libc::pause() };
        }
    }

    /// The path [`read_keys_from_the_fifo`] opens, filled by whichever test
    /// is using it before that test starts its helper.
    ///
    /// A `OnceLock` rather than a parameter because `AccountSwitches`'s
    /// fields are plain function pointers (see that struct's docs for why
    /// they have to be): there is nowhere on one to hang a closure's
    /// captured path. One slot is enough -- exactly one test in this binary
    /// uses these switches.
    static HUNG_KEYS_FIFO: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    /// Test-only `read_keys` that never returns: it opens a FIFO nobody ever
    /// writes to, and `open(O_RDONLY)` on a FIFO blocks until a writer
    /// appears. An unbounded read inside the verifying child -- the shape of
    /// an account whose home sits on a mount that has stopped answering --
    /// with no NFS server to borrow.
    ///
    /// Note what this deliberately does NOT do: the production reader
    /// (`authorized::read_regular_file_bounded`) opens `O_NONBLOCK` and
    /// refuses anything that is not a regular file, precisely so an account
    /// cannot wedge the helper with a FIFO at its own key path. This
    /// stand-in is the hang that reader already rules out, used here to
    /// stand for the hangs it cannot -- a home directory on a dead mount, a
    /// name service that never answers -- which is what the fork exists for.
    fn read_keys_from_the_fifo(
        _account: &Account,
        _template: &str,
    ) -> Result<String, AuthorizedError> {
        let path = HUNG_KEYS_FIFO
            .get()
            .expect("the fifo path must be set before the helper starts");
        std::fs::read_to_string(path).map_err(|e| AuthorizedError::Read {
            path: path.display().to_string(),
            why: e.to_string(),
        })
    }

    /// A FIFO in `dir` that nothing will ever open for writing.
    fn make_fifo_nobody_writes_to(dir: &Path) -> PathBuf {
        let path = dir.join("authorized_keys.fifo");
        nix::unistd::mkfifo(&path, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .expect("mkfifo");
        path
    }

    /// Test-only `lookup`: a panic exactly where the verifying child does
    /// its work -- after its descriptor sweep, with the report pipe still
    /// unwritten. Stands for any bug in that child, since what matters is
    /// not which line panics but where the unwinding would go.
    fn lookup_that_panics(_login: &str) -> Result<Account, AccountError> {
        panic!("a deliberate panic inside the verifying child");
    }

    /// Waits, bounded, for `child` to be reaped, and returns how it ended.
    fn exit_status_of(child: Pid, what: &str) -> nix::sys::wait::WaitStatus {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(status @ (WaitStatus::Exited(..) | WaitStatus::Signaled(..))) => return status,
                Ok(_) => {}
                Err(nix::Error::EINTR) => continue,
                Err(e) => panic!("{what} -- waitpid({child}) failed: {e}"),
            }
            assert!(
                Instant::now() < give_up_at,
                "{what} -- {child} was still running after {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Test-only `read_keys` that never finishes and never reads anything:
    /// the child is simply still working when its deadline passes.
    ///
    /// `pause` returns only for a signal with a handler, and this child has
    /// none -- `SIGKILL`, which is what the helper sends, could not be
    /// caught even if it had. A second hang alongside
    /// [`read_keys_from_the_fifo`] because that one's path travels through
    /// a `OnceLock`, which exactly one test in the binary may fill.
    fn read_keys_that_never_finishes(
        _account: &Account,
        _template: &str,
    ) -> Result<String, AuthorizedError> {
        loop {
            // SAFETY: `pause` takes no arguments and touches nothing this
            // process owns.
            unsafe { nix::libc::pause() };
        }
    }

    /// Test-only `read_keys` that kills its own process outright, leaving
    /// the report pipe at end-of-file with nothing written to it.
    ///
    /// The shape a child killed by the out-of-memory killer, or crashing
    /// inside an NSS module, leaves behind -- and byte-identical to what a
    /// SUCCESSFUL `execve` leaves on a CHANNEL's startup-report pipe.
    /// Reading it the way `read_startup_report` reads that one would turn
    /// "never checked the signature" into "admitted".
    fn read_keys_killing_this_process(
        _account: &Account,
        _template: &str,
    ) -> Result<String, AuthorizedError> {
        let _ = nix::sys::signal::kill(nix::unistd::Pid::this(), nix::sys::signal::Signal::SIGKILL);
        // Not reached: `SIGKILL` cannot be caught, blocked or ignored.
        loop {
            unsafe { nix::libc::pause() };
        }
    }

    /// Where [`read_keys_recording_descriptors`] writes what it found.
    static FD_LISTING_PATH: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();

    /// Test-only `read_keys` that records every descriptor the verifying
    /// child still holds, then refuses.
    ///
    /// Runs inside that child, after `fork_verification`'s own
    /// `close_other_descriptors` sweep, so what it writes down is exactly
    /// what survived it. `/proc/self/fd` is the only way to ask a process
    /// what it is actually holding from inside it.
    fn read_keys_recording_descriptors(
        _account: &Account,
        _template: &str,
    ) -> Result<String, AuthorizedError> {
        // Built BEFORE anything below opens a file of its own, so the
        // listing describes what was inherited rather than what this
        // function then went on to open.
        let mut lines = String::new();
        for entry in std::fs::read_dir("/proc/self/fd").expect("read /proc/self/fd") {
            let entry = entry.expect("a /proc/self/fd entry");
            let number = entry.file_name().to_string_lossy().to_string();
            let target = std::fs::read_link(entry.path())
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "<unreadable>".to_string());
            lines.push_str(&format!("{number} {target}\n"));
        }
        std::fs::write(FD_LISTING_PATH.get().expect("the listing path"), lines)
            .expect("write the listing");
        Err(AuthorizedError::Read {
            path: "none -- this stand-in records descriptors".to_string(),
            why: "and never returns keys".to_string(),
        })
    }

    /// The account [`lookup_a_distinctive_account`] answers with:
    /// deliberately unlike anything `getpwnam` would return for this test
    /// process's own login, in every field a channel later reads out of
    /// `LoopState::verified`.
    ///
    /// The uid is this process's own on purpose, so that a parent which
    /// re-ran `account::lookup` would store its answer under the SAME key
    /// -- and the test then fails on the VALUE (gid, home, shell, groups)
    /// rather than on a missing entry.
    fn distinctive_account() -> Account {
        Account {
            uid: my_uid(),
            gid: Gid::from_raw(4242),
            name: "verdict-account".to_string(),
            home: PathBuf::from("/verdict/home"),
            shell: PathBuf::from("/verdict/shell"),
            groups: vec![Gid::from_raw(4242), Gid::from_raw(4243)],
        }
    }

    /// Test-only `lookup`: the name service, standing still. Answers with
    /// [`distinctive_account`] whatever name it is handed.
    fn lookup_a_distinctive_account(_login: &str) -> Result<Account, AccountError> {
        Ok(distinctive_account())
    }

    /// The switches most tests here run with: the same file read and the
    /// same program run, without changing identity -- see
    /// [`read_keys_plainly`] and [`keep_identity`].
    const UNPRIVILEGED: AccountSwitches = AccountSwitches {
        lookup: super::account::lookup,
        read_keys: read_keys_plainly,
        become_account: keep_identity,
    };

    /// A helper that starts out with `account` admitted under
    /// [`PROOF_LOGIN`] -- its login on file and the account verified, as a
    /// successful `Request::Verify` would leave them -- running with
    /// `config` and `switches`, plus the worker's ends of its seams. The
    /// login goes in through `serve`'s own `admitted` parameter, which the
    /// daemon always passes empty -- so there the only way in stays
    /// `Request::Verify` -- and a test about what a channel runs AS does not
    /// have to route through the verification path to get one. Its channels
    /// are opened under `PROOF_LOGIN` ([`open_for`], [`open_shell`]).
    fn helper_for(account: Account, config: HelperConfig, switches: AccountSwitches) -> TestHelper {
        let admitted = HashMap::from([(PROOF_LOGIN, account)]);
        helper_running(
            config,
            admitted,
            switches,
            tempfile::tempdir().expect("tempdir"),
            PROOF_LOGIN,
        )
    }

    /// Start a helper on a thread of this process and hand back both
    /// worker ends -- the shape every fixture here shares, so that what a
    /// [`TestHelper`] carries is decided in ONE place.
    ///
    /// `dir` is the fixture's own directory, whatever it holds: a
    /// throwaway for a test's files, or the `authorized_keys` a
    /// [`helper_trusting`]-shaped one reads. It is handed in rather than
    /// made here because the config was built against it.
    fn helper_running(
        config: HelperConfig,
        admitted: HashMap<LoginId, Account>,
        switches: AccountSwitches,
        dir: TempDir,
        login: LoginId,
    ) -> TestHelper {
        let ((channels, auth), (helper_channels, helper_auth)) = seams_for_test();
        let thread = std::thread::spawn(move || {
            serve(helper_channels, helper_auth, config, admitted, switches)
        });
        TestHelper {
            channels,
            auth,
            thread,
            dir,
            me: my_login(),
            login,
        }
    }

    /// The account this test process runs as, resolved through
    /// `account::lookup` exactly as a real `Request::Verify` would -- for a
    /// test that seeds its logins directly (see
    /// [`helper_with_verified`]) and needs a genuine, working account rather
    /// than [`synthetic_account`]'s filler one.
    fn my_account() -> Account {
        super::account::lookup(&my_login()).expect("this account resolves")
    }

    /// [`helper_for`], for any number of logins, each admitted with its own
    /// account: unprivileged (see [`UNPRIVILEGED`]) and against the default
    /// test config, for a test about what the helper does with a login
    /// already on file rather than about how it got there.
    ///
    /// The one fixture for those tests, and a whole [`TestHelper`]: a test
    /// about a monitor's life needs the AUTHENTICATION seam too, since
    /// `Request::LoginEnded` -- the thing that ends a login, and with it
    /// its monitor -- travels there, while `Open` and `Close` travel on the
    /// channel seam. A fixture that handed back only the channel seam would
    /// have such a test reach for a second one, and then two tests would
    /// speak to one helper through two different shapes.
    ///
    /// Each login's token is the TEST's to choose (a plain constant in its
    /// body), because what a test of monitors needs is several logins it
    /// can tell apart -- and because the helper opens a channel only under
    /// a login already on file, which is exactly what this seeds.
    fn helper_with_verified(logins: impl IntoIterator<Item = (LoginId, Account)>) -> TestHelper {
        let admitted: HashMap<LoginId, Account> = logins.into_iter().collect();
        // The first token seeded, in the order the caller gave them: its
        // tests name each of their logins themselves, and this is only what
        // `TestHelper::login` has to be for a fixture that has several.
        let first = admitted.keys().copied().next().unwrap_or(PROOF_LOGIN);
        helper_running(
            test_config(),
            admitted,
            UNPRIVILEGED,
            tempfile::tempdir().expect("tempdir"),
            first,
        )
    }

    /// Sends an `Open` running `command` and returns the helper's answer
    /// about that id, with whatever terminal rode with it.
    ///
    /// Echo off, so what comes back over the terminal is the program's own
    /// output and never the command typed into it -- a test that reads a
    /// pid out of that output must not be able to read it out of an echo.
    fn open_command_with_fd(
        channels: &UnixStream,
        id: ChannelId,
        uid: Uid,
        login: LoginId,
        command: &str,
    ) -> (Response, Option<OwnedFd>) {
        let request = Request::Open {
            id,
            uid: uid.as_raw(),
            login,
            cols: 80,
            rows: 24,
            term: None,
            echo: false,
            shell: false,
            command: command.to_string(),
        };
        super::channel::send(channels, &encode(&request).expect("encode"), None).expect("send");
        answer_to_or_fail(channels, id, "the helper must answer this Open")
    }

    /// Waits for channel `id`'s exit to reach the worker, and returns the
    /// code it carried.
    fn wait_for_exited(channels: &UnixStream, id: ChannelId) -> i32 {
        let (exit, _fd) = answer_to_or_fail(channels, id, "the helper must report this exit");
        match exit {
            Response::Exited { code, .. } => code,
            other => panic!("expected an exit for channel {id}, got {other:?}"),
        }
    }

    /// The number `marker` is followed by in `output`, as a pid -- what a
    /// shell asked to print one writes on its terminal.
    fn pid_after(output: &str, marker: &str) -> Pid {
        let tail = output
            .split_once(marker)
            .unwrap_or_else(|| panic!("no {marker} in the channel's output: {output:?}"))
            .1;
        let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
        Pid::from_raw(
            digits
                .parse()
                .unwrap_or_else(|e| panic!("{marker}{digits:?} is not a pid ({e}): {output:?}")),
        )
    }

    /// Opens a channel whose shell prints ITS OWN PARENT and exits, and
    /// returns that parent: the monitor behind this channel, named by the
    /// one process that can see it from inside.
    fn monitor_pid_behind_channel(
        channels: &UnixStream,
        id: ChannelId,
        uid: Uid,
        login: LoginId,
    ) -> Pid {
        // The trailing marker is what the read waits for, so that the pid
        // is whole by the time it is parsed: waiting for `MONITOR=` itself
        // could return with its digits still on their way.
        let (opened, fd) = open_command_with_fd(
            channels,
            id,
            uid,
            login,
            "printf 'MONITOR=%s END\\n' \"$PPID\"",
        );
        assert!(
            matches!(opened, Response::Opened { .. }),
            "setup: this channel must open, got {opened:?}"
        );
        // Read to the marker, never to the terminal's end: WHO ELSE holds
        // this terminal open is exactly what some of these tests are
        // about, and a read that waited for its end would give up before
        // saying anything about the monitor.
        let mut master =
            std::fs::File::from(fd.expect("an opened channel comes with its terminal"));
        let seen = read_until_or_timeout(&mut master, " END");
        let monitor = pid_after(&seen, "MONITOR=");
        assert_eq!(
            wait_for_exited(channels, id),
            0,
            "setup: the shell that printed its parent must exit cleanly"
        );
        monitor
    }

    /// Opens a channel whose shell prints its OWN pid and then becomes a
    /// program that keeps running, and returns that pid with the channel's
    /// terminal.
    ///
    /// The terminal comes back with it and must be held: dropping it hangs
    /// the pseudo-terminal up, and the `SIGHUP` that follows would end the
    /// program by itself -- so a test about what ends it would pass whether
    /// or not the thing under test did anything.
    fn shell_pid_behind_channel(
        channels: &UnixStream,
        id: ChannelId,
        uid: Uid,
        login: LoginId,
    ) -> (Pid, OwnedFd) {
        let (opened, fd) = open_command_with_fd(
            channels,
            id,
            uid,
            login,
            // `exec`, so the shell BECOMES the program: the pid it printed
            // stays the pid of what is running. The marker after it is
            // what the read below waits for.
            "printf 'SHELL=%s END\\n' \"$$\"; exec sleep 300",
        );
        assert!(
            matches!(opened, Response::Opened { .. }),
            "setup: this channel must open, got {opened:?}"
        );
        let mut master =
            std::fs::File::from(fd.expect("an opened channel comes with its terminal"));
        // The trailing marker, so the pid is whole when it is parsed.
        let seen = read_until_or_timeout(&mut master, " END");
        let shell = pid_after(&seen, "SHELL=");
        (shell, OwnedFd::from(master))
    }

    /// The descriptor number one line of `ls -l /proc/<pid>/fd` is about,
    /// or `None` for a line that is not an entry at all (`total 0`, or
    /// `ls`'s own complaint when it could not read the directory). The
    /// number is the last field before the ` -> `, which is where however
    /// the target happens to be quoted begins.
    fn listed_fd(line: &str) -> Option<RawFd> {
        line.split(" -> ")
            .next()?
            .split_whitespace()
            .last()?
            .parse()
            .ok()
    }

    /// The `socket:[12345]` or `pipe:[12345]` a `/proc/<pid>/fd` line's
    /// target names, or `None` for a line that names anything else (a path,
    /// an anonymous inode of another kind, or no entry at all).
    ///
    /// Two processes whose listings carry the same one hold the SAME open
    /// file; two different sockets, or two different pipes, never share it.
    fn listed_inode(line: &str) -> Option<String> {
        let target = line.split(" -> ").nth(1)?.trim().trim_matches('\'');
        (target.starts_with("socket:[") || target.starts_with("pipe:[")).then(|| target.to_string())
    }

    /// Every socket and pipe this process has open, as the same
    /// `socket:[12345]`/`pipe:[12345]` strings a `/proc/<pid>/fd` listing
    /// carries -- so a monitor's listing can be checked against the
    /// helper's own without either side naming a descriptor NUMBER, which
    /// says nothing about which file it is.
    fn open_file_inodes_here() -> HashSet<String> {
        std::fs::read_dir("/proc/self/fd")
            .expect("read /proc/self/fd")
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| std::fs::read_link(entry.path()).ok())
            .map(|target| target.to_string_lossy().into_owned())
            .filter(|target| target.starts_with("socket:[") || target.starts_with("pipe:["))
            .collect()
    }

    /// The parent `/proc` gives for `pid`.
    fn parent_of(pid: Pid) -> Pid {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap_or_else(|e| panic!("read /proc/{pid}/status: {e}"));
        let line = status
            .lines()
            .find(|line| line.starts_with("PPid:"))
            .unwrap_or_else(|| panic!("no PPid line for {pid}"));
        Pid::from_raw(
            line.trim_start_matches("PPid:")
                .trim()
                .parse()
                .unwrap_or_else(|e| panic!("PPid of {pid} is not a number: {e}")),
        )
    }

    /// Sends a plain `Open` on `channels` for `uid`/`login`, and returns the
    /// helper's answer -- specifically the answer ABOUT THIS `id` --
    /// together with whatever terminal descriptor rode with it.
    ///
    /// Filtered by id through `answer_to_or_fail`, not read blind through
    /// `next_response`: the command exits at once (`true`), so a test using
    /// this never has to reap a lingering process of its own -- but that
    /// also means the helper's unprompted `Exited { id }` for an EARLIER
    /// `Open` can land on the seam before this call's own `Opened`/`Failed`
    /// does. A blind read would then hand back that `Exited` as if it were
    /// the answer to THIS request, which is exactly the flake this file's
    /// own id-filtering helpers exist to rule out.
    ///
    /// Takes the bare seam rather than a `Worker`/`TestHelper`, so it works
    /// for either -- more than one of this module's test fixtures has a
    /// `channels: UnixStream` field, and this needs nothing else from them.
    fn open_result_with_fd(
        channels: &UnixStream,
        id: ChannelId,
        uid: Uid,
        login: LoginId,
    ) -> (Response, Option<OwnedFd>) {
        let req = open_request(id, uid.as_raw(), login);
        super::channel::send(channels, &encode(&req).expect("encode"), None).expect("send");
        answer_to_or_fail(channels, id, "the helper must answer this Open")
    }

    /// A plain `Open` request for `uid`/`login` on channel `id`, running
    /// `true` (exits at once) -- shared by every test that just needs a
    /// well-formed `Open`, whether it goes out over a real seam
    /// ([`open_result_with_fd`]) or straight into [`serve_channel_seam`]
    /// ([`call_channel_seam_once`]).
    fn open_request(id: ChannelId, uid: u32, login: LoginId) -> Request {
        Request::Open {
            id,
            uid,
            login,
            cols: 80,
            rows: 24,
            term: None,
            echo: false,
            shell: false,
            command: "true".to_string(),
        }
    }

    /// One socketpair, kept across as many requests as a test needs, and
    /// the two production steps an `Open` now takes: the handler, and the
    /// loop's own settling once the child has spoken.
    ///
    /// Two steps because they really are two moments. An `Open` that
    /// reaches the fork leaves the handler UNANSWERED and is answered from
    /// the loop, so a test that wants to see the state between them -- a
    /// second `Open` arriving while the first is still starting -- must be
    /// able to stop in the middle, which [`call_channel_seam_once`] (one
    /// request, settled before it returns) cannot express.
    struct DirectSeam {
        /// The worker's end: what a test sends requests on and reads
        /// answers off.
        worker: UnixStream,
        /// The helper's end, handed to `serve_channel_seam` and to the
        /// settling below -- the same seam a real answer leaves by.
        helper: UnixStream,
        /// The worker's end of the AUTHENTICATION seam.
        worker_auth: UnixStream,
        /// The helper's end of it. A second pair, because a verdict for a
        /// `Request::Verify` is answered THERE while a channel's is
        /// answered on the seam above -- and `settle` below now drives
        /// both kinds through the one production path.
        helper_auth: UnixStream,
    }

    impl DirectSeam {
        fn new() -> DirectSeam {
            let (worker, helper) = super::channel::pair().expect("socketpair");
            let (worker_auth, helper_auth) = super::channel::pair().expect("socketpair");
            for end in [&worker, &helper, &worker_auth, &helper_auth] {
                // The HELPER end too: `serve_channel_seam` reads from it,
                // and this suite has no per-test timeout -- an unbounded
                // read there would hang the whole run instead of failing
                // one test. A request is always queued before the call, so
                // it cannot block today; this is what keeps that from being
                // load-bearing.
                end.set_read_timeout(Some(TEST_RECV_TIMEOUT))
                    .expect("bounded read");
            }
            DirectSeam {
                worker,
                helper,
                worker_auth,
                helper_auth,
            }
        }

        /// Both helper-side ends, as the loop itself hands them to the
        /// settling.
        fn seams(&self) -> Seams<'_> {
            Seams {
                channels: &self.helper,
                auth: &self.helper_auth,
            }
        }

        /// Queue `req` on the AUTHENTICATION seam and serve exactly that
        /// one message -- the mirror of [`DirectSeam::serve`], for the
        /// requests that arrive there. Returns the number it went out
        /// with, so a test can insist the answer carries it back.
        fn serve_auth(
            &self,
            state: &mut LoopState,
            req: Request,
            config: &HelperConfig,
            switches: AccountSwitches,
        ) -> AuthRequestId {
            let id = tell(&self.worker_auth, req);
            serve_auth_seam(self.seams(), state, config, switches);
            id
        }

        /// Queue `req` and serve exactly that one message -- no thread, no
        /// `serve` loop, and (for a request the cap or the pairing check
        /// refuses) no fork either, since both sit before `open_channel`.
        fn serve(
            &self,
            state: &mut LoopState,
            req: &Request,
            config: &HelperConfig,
            become_account: fn(Uid, Gid, &[Gid]) -> nix::Result<()>,
        ) {
            super::channel::send(&self.worker, &encode(req).expect("encode"), None).expect("send");
            serve_channel_seam(&self.helper, state, config, become_account);
        }

        /// The loop's own pending pass, run until nothing is pending: the
        /// report pipes polled, the ready ones settled and the expired ones
        /// given up on -- through the SAME two production functions
        /// (`settle_ready_pending`, `expire_pending`), in the same order,
        /// so that a test about a child that never reports sees the kill
        /// the loop would do and not some test-only shortcut past it.
        ///
        /// Bounded twice over: each entry by its own deadline
        /// (`config.startup_timeout`), and the whole thing by
        /// [`TEST_RECV_TIMEOUT`], so a regression fails a test instead of
        /// hanging the run.
        fn settle(&self, state: &mut LoopState, config: &HelperConfig) {
            let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
            while !state.pending.is_empty() {
                assert!(
                    Instant::now() < give_up_at,
                    "a pending request outlived the whole test budget of {TEST_RECV_TIMEOUT:?}"
                );
                self.one_pass(state, config);
            }
        }

        /// One pass of the loop's waiting, for a test that must not settle
        /// everything: the same `poll` over the same three kinds of
        /// descriptor the real loop watches (report pipes, monitor seams),
        /// and the same production functions applied to whatever spoke.
        fn one_pass(&self, state: &mut LoopState, config: &HelperConfig) {
            let report_fds = state.pending.poll_fds();
            let monitor_logins: Vec<LoginId> = state.monitors.keys().copied().collect();
            let mut fds: Vec<PollFd> = Vec::with_capacity(report_fds.len() + monitor_logins.len());
            for fd in &report_fds {
                // SAFETY: as in `serve`'s own loop -- every number came
                // from `poll_fds`, and the table owns each of those
                // descriptors until its entry leaves it.
                fds.push(PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(*fd) },
                    PollFlags::POLLIN,
                ));
            }
            for login in &monitor_logins {
                // SAFETY: as in `serve`'s own loop -- the `Monitor` owns
                // its seam for as long as it is on the table.
                let raw = state.monitors[login].seam.as_raw_fd();
                fds.push(PollFd::new(
                    unsafe { BorrowedFd::borrow_raw(raw) },
                    PollFlags::POLLIN,
                ));
            }
            match poll(&mut fds, poll_timeout(&state.pending, Instant::now())) {
                Ok(_) => {}
                Err(nix::Error::EINTR) => return,
                Err(e) => panic!("polling what the helper is waiting on failed: {e}"),
            }
            let ready: Vec<RawFd> = report_fds
                .iter()
                .zip(&fds)
                .filter(|(_, polled)| polled.any().unwrap_or(true))
                .map(|(fd, _)| *fd)
                .collect();
            let ready_monitors: Vec<LoginId> = monitor_logins
                .iter()
                .zip(&fds[report_fds.len()..])
                .filter(|(_, polled)| polled.any().unwrap_or(true))
                .map(|(login, _)| *login)
                .collect();
            settle_ready_pending(self.seams(), state, config, &ready);
            serve_ready_monitors(self.seams(), state, &ready_monitors);
            expire_pending(self.seams(), state, config, Instant::now());
        }
    }

    /// End every monitor `state` has and bury it, the way `forget_login`
    /// and `reap` do between them in the loop -- for a test that drives the
    /// handlers directly and has no loop of its own, so that it leaves
    /// neither a running monitor nor a zombie behind in the test binary.
    ///
    /// The wait is bounded: a monitor takes its shells down before it
    /// exits, which is `CLOSE_GRACE_PERIOD` in the worst case (a shell that
    /// ignores `SIGHUP`), and a monitor still there long after that is a
    /// failure worth reporting rather than hanging on.
    fn stop_monitors(state: &mut LoopState) {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

        let monitors: Vec<Pid> = state
            .monitors
            .drain()
            .map(|(_, monitor)| {
                // Its end-of-file is what tells a monitor to end.
                drop(monitor.seam);
                monitor.pid
            })
            .collect();
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        for pid in monitors {
            loop {
                match waitpid(pid, Some(WaitPidFlag::WNOHANG)) {
                    Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..))
                    | Err(nix::Error::ECHILD) => break,
                    Ok(_) => {}
                    Err(nix::Error::EINTR) => continue,
                    Err(e) => panic!("waitpid({pid}) on a monitor failed: {e}"),
                }
                assert!(
                    Instant::now() < give_up_at,
                    "a monitor must end once its seam closes -- {pid} is still there after \
                     {TEST_RECV_TIMEOUT:?}"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }

    /// Serves one request against `state` and settles whatever it left
    /// pending, so the answer is on the seam by the time this returns --
    /// see [`DirectSeam`] for the two steps, and for what a test that needs
    /// them apart uses instead.
    ///
    /// Lets a test that needs `MAX_LOGINS`-scale state pay only for the
    /// HashMap it built, not for hundreds of real processes -- see
    /// [`logins_are_capped_like_nonces`]'s own docs for why that matters.
    fn call_channel_seam_once(state: &mut LoopState, req: &Request) -> (Response, Option<OwnedFd>) {
        let seam = DirectSeam::new();
        seam.serve(state, req, &test_config(), UNPRIVILEGED.become_account);
        seam.settle(state, &test_config());
        next_response(&seam.worker)
    }

    /// A `LoopState` with `account` already verified and `logins`
    /// pre-filled with `count` synthetic entries, each holding one channel
    /// and established (so [`sweep_expired_logins`] never touches them) --
    /// the cheap way to reach `MAX_LOGINS`-scale without forking anything.
    fn filled_state(account: &Account, count: usize) -> LoopState {
        let logins = (0..count)
            .map(|n| {
                (
                    login_token(n),
                    login_entry(account, Instant::now(), true, &[n as ChannelId]),
                )
            })
            .collect();
        LoopState {
            live: HashMap::new(),
            pending: PendingTable::default(),
            orphans: Vec::new(),
            closing: HashMap::new(),
            nonces: HashMap::new(),
            verified: HashMap::from([(account.uid, account.clone())]),
            logins,
            monitors: HashMap::new(),
            next_incarnation: 1,
        }
    }

    /// A `LoopState` with `login` admitted for `account` and nothing else on
    /// file: its entry provisional and the account verified, exactly as a
    /// successful `Request::Verify` leaves them -- the state every `Open` a
    /// test drives directly needs, since an `Open` never creates the login
    /// it names.
    fn state_with_login(account: &Account, login: LoginId) -> LoopState {
        let mut state = filled_state(account, 0);
        state.logins.insert(
            login,
            LoginState::provisional(account.clone(), String::new(), 1),
        );
        state
    }

    /// How long [`drain_responses`] waits for one more message before it
    /// concludes there is none. Short on purpose, and nothing rests on the
    /// value: everything it reads was put on the seam by a call that has
    /// already returned, so nothing is in flight. A test about a message
    /// that must NOT be there pays this once instead of
    /// [`TEST_RECV_TIMEOUT`].
    const DRAIN_TIMEOUT: Duration = Duration::from_millis(250);

    /// Every response waiting on the worker's end of a channel seam right
    /// now, in the order they were sent.
    ///
    /// Bounded (see [`DRAIN_TIMEOUT`]), which is the whole point: a test
    /// about a message that never comes must fail on its own assertion
    /// rather than hang the run. The seam's own timeout is put back, so a
    /// test may go on using it for a message it really does wait for.
    fn drain_responses(channels: &UnixStream) -> Vec<Response> {
        let was = channels.read_timeout().expect("the seam's own bound");
        channels
            .set_read_timeout(Some(DRAIN_TIMEOUT))
            .expect("bounded read");
        let mut seen = Vec::new();
        while let Ok(Some((bytes, _fd))) = super::channel::recv(channels) {
            seen.push(decode::<Response>(&bytes).expect("decode"));
        }
        channels
            .set_read_timeout(was)
            .expect("put the seam's own bound back");
        seen
    }

    /// A `LoopState` with nothing in it at all -- for a test that wants to
    /// watch something get PUT there, which [`filled_state`] (whose account
    /// is already verified) cannot express.
    fn empty_state() -> LoopState {
        LoopState {
            live: HashMap::new(),
            pending: PendingTable::default(),
            orphans: Vec::new(),
            closing: HashMap::new(),
            nonces: HashMap::new(),
            verified: HashMap::new(),
            logins: HashMap::new(),
            monitors: HashMap::new(),
            next_incarnation: 1,
        }
    }

    /// A config whose `authorized_keys` is a file in `dir` listing `key` --
    /// what [`helper_trusting`] runs on, for a test that drives the
    /// handlers directly instead of starting a whole helper.
    fn trusting_config(dir: &Path, key: &PrivateKey) -> HelperConfig {
        let keys = dir.join("authorized_keys");
        std::fs::write(
            &keys,
            format!("{}\n", key.public_key().to_openssh().expect("openssh")),
        )
        .expect("write");
        HelperConfig {
            // An absolute path with no placeholder: every account gets the
            // same file, so a test can make the key "listed" for any name
            // it likes.
            authorized_keys_template: keys.display().to_string(),
            permit_root: running_as_root(),
            ..test_config()
        }
    }

    /// [`open_result_with_fd`], for a test that only cares about the answer.
    fn open_result(channels: &UnixStream, id: ChannelId, uid: Uid, login: LoginId) -> Response {
        open_result_with_fd(channels, id, uid, login).0
    }

    /// Opens a channel and asserts it succeeded -- for a test that needs a
    /// real, live channel under `login` and is not testing the open itself.
    fn open_channel_for(channels: &UnixStream, id: ChannelId, uid: Uid, login: LoginId) {
        let (response, fd) = open_result_with_fd(channels, id, uid, login);
        assert!(
            matches!(response, Response::Opened { .. }),
            "setup: this open must succeed, got {response:?}"
        );
        assert!(
            fd.is_some(),
            "setup: an opened channel must come with its terminal"
        );
    }

    /// Closes channel `id` and waits for its `Exited` notice -- so a
    /// following `Open` that reuses the same id is never refused merely
    /// because the previous process has not been reaped yet.
    fn close_channel(channels: &UnixStream, id: ChannelId) {
        super::channel::send(
            channels,
            &encode(&Request::Close { id }).expect("encode"),
            None,
        )
        .expect("send close");
        let (exit, _fd) = answer_to_or_fail(channels, id, "the helper must report this exit");
        assert!(
            matches!(exit, Response::Exited { .. }),
            "expected Exited for the closed channel, got {exit:?}"
        );
    }

    /// Tells the helper a login ended, on the authentication seam, and
    /// blocks until the helper has actually applied it: `LoginEnded` is a
    /// tell (see the request's own docs), so this follows it with a `Nonce`
    /// request on the SAME seam and waits for that answer. The seam is
    /// served strictly in order, one message at a time, so that answer
    /// cannot come back before the `LoginEnded` sent just before it was
    /// already handled -- without this, a caller that immediately checks
    /// the effect on the CHANNEL seam would race the helper's own loop,
    /// which polls both seams and may serve a channel request first. The
    /// nonce itself is released at once, so this helper does not quietly
    /// spend one of `MAX_OUTSTANDING_NONCES`'s slots.
    fn tell_login_ended(auth: &UnixStream, login: LoginId) {
        tell(auth, Request::LoginEnded { login });
        match ask(auth, Request::Nonce) {
            Response::Nonce { nonce } => {
                tell(auth, Request::ReleaseNonce { nonce });
            }
            other => panic!("sync barrier after LoginEnded: expected a nonce, got {other:?}"),
        }
    }

    /// The uid of the account this test process runs as, as the `Uid`
    /// `Request::Open`'s test helpers want (`me_uid` returns the raw
    /// `u32`).
    fn my_uid() -> Uid {
        Uid::from_raw(me_uid())
    }

    /// A distinct login token for iteration `n` of a test that needs many.
    fn login_token(n: usize) -> LoginId {
        let mut token = [0u8; 16];
        token[..8].copy_from_slice(&(n as u64).to_be_bytes());
        token
    }

    /// The program still runs as its account and still reports its exit
    /// code, now through a monitor that sits between it and the helper. And
    /// the monitor holds no seam of the helper's: a process that never
    /// execs would otherwise keep those sockets alive for as long as the
    /// shell lives.
    #[test]
    fn the_monitor_runs_the_shell_and_holds_no_seam() {
        let login = [6u8; 16];
        let h = helper_with_verified([(login, my_account())]);

        // The shell lists ITS PARENT's descriptors: the monitor never
        // execs, so close-on-exec does nothing for it -- it must close what
        // it inherited itself, or it keeps the helper's sockets alive for
        // as long as the shell lives.
        let (opened, fd) = open_command_with_fd(
            &h.channels,
            1,
            my_uid(),
            login,
            // The marker, and the read that waits for it rather than for
            // the terminal's end, are what keep this test failing on its
            // OWN assertion when the sweep is taken out: a monitor that
            // kept the master side of this very terminal would keep it
            // from ever reaching end-of-file, and a read that waited for
            // that would time out before counting anything.
            "ls -l /proc/$PPID/fd; printf 'LISTED\\n'; exit 7",
        );
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        let mut master =
            std::fs::File::from(fd.expect("an opened channel comes with its terminal"));
        let seen = read_until_or_timeout(&mut master, "LISTED");

        // Only the descriptors the sweep answers for. 0, 1 and 2 are the
        // helper's own and are left alone by design (see
        // `close_other_descriptors`), and in a test binary they are
        // whatever the runner's shell handed down -- a socket among them
        // would make this test's answer depend on how the suite was
        // started rather than on what the monitor closed.
        let held: Vec<&str> = seen
            .lines()
            .filter(|line| listed_fd(line).is_some_and(|fd| fd >= 3))
            .collect();
        // The listing really happened, so the count below is a count in a
        // real answer rather than in no answer at all -- an `ls` that could
        // not read the directory leaves nothing here, and says so in the
        // message.
        assert!(
            seen.contains("LISTED") && !held.is_empty(),
            "the shell must have listed its parent's descriptors, got {seen:?}"
        );
        // The monitor holds its own seam, and it must: a monitor with no
        // socket at all closed the one descriptor it was told to keep.
        assert!(
            held.iter().any(|line| line.contains("socket:")),
            "the monitor must still hold its own seam to the helper:\n{seen}"
        );
        // And not one descriptor that is also OPEN HERE. A count of sockets
        // used to say this, and cannot any more: since the login's PAM
        // session moved into the monitor, the monitor legitimately opens
        // sockets of its own (Linux-PAM's own logging, and whatever a
        // module opens), and a count cannot tell one of those from a socket
        // of the helper's left behind. An inode can: two processes holding
        // the same `socket:[n]` or `pipe:[n]` hold the SAME open file,
        // which is exactly what the sweep exists to make impossible, and
        // two different sockets never share one. This test process IS the
        // helper (it runs the loop on a thread), so its own descriptors are
        // the ones that must not appear.
        let ours = open_file_inodes_here();
        let shared: Vec<&&str> = held
            .iter()
            .filter(|line| listed_inode(line).is_some_and(|inode| ours.contains(&inode)))
            .collect();
        assert!(
            shared.is_empty(),
            "the monitor holds {} descriptor(s) that are open in the helper too -- it never \
             execs, so close-on-exec will never close them for it: {shared:?}\n{seen}",
            shared.len()
        );
        // And no terminal of the helper's either. The master side of this
        // channel's own terminal is open in the helper at the moment the
        // monitor is forked, and a monitor that kept it would keep that
        // terminal from ever hanging up -- while satisfying the count
        // above, which only knows about sockets. Checked separately for
        // exactly that reason.
        assert!(
            !held.iter().any(|line| line.contains("/dev/ptmx")),
            "the monitor must hold no terminal of the helper's:\n{seen}"
        );
        assert_eq!(
            wait_for_exited(&h.channels, 1),
            7,
            "the shell's own exit code must reach the worker through the monitor"
        );
        h.stop();
    }

    /// Two channels of one login share one monitor: the PAM session (from
    /// the next task on) belongs to the login, so a second channel must not
    /// start a second session-keeper. Each shell prints its own parent, and
    /// the two must match -- while a different login's does not.
    #[test]
    fn two_channels_of_one_login_share_a_monitor() {
        let login = [7u8; 16];
        let other_login = [8u8; 16];
        let h = helper_with_verified([(login, my_account()), (other_login, my_account())]);

        let first = monitor_pid_behind_channel(&h.channels, 1, my_uid(), login);
        let second = monitor_pid_behind_channel(&h.channels, 2, my_uid(), login);
        assert_eq!(
            first, second,
            "both channels of one login must hang off the same monitor: the session belongs to \
             the login"
        );

        let other = monitor_pid_behind_channel(&h.channels, 3, my_uid(), other_login);
        assert_ne!(
            other, first,
            "a different login must get its own monitor, and its own session"
        );
        h.stop();
    }

    /// Killing a monitor must not leave shells running with nobody to end
    /// their session: they are the monitor's own children, and each arms
    /// the parent-death signal after its drop to the account.
    ///
    /// Both terminals are held to the end of the test on purpose: dropping
    /// one hangs its pseudo-terminal up, and the `SIGHUP` that follows
    /// would end the program by itself -- this test would then pass with
    /// the arming deleted.
    #[test]
    fn a_killed_monitor_takes_its_shells_with_it() {
        let login = [9u8; 16];
        let h = helper_with_verified([(login, my_account())]);
        let (first, first_terminal) = shell_pid_behind_channel(&h.channels, 1, my_uid(), login);
        let (second, second_terminal) = shell_pid_behind_channel(&h.channels, 2, my_uid(), login);
        let monitor = parent_of(first);
        assert_eq!(
            parent_of(second),
            monitor,
            "setup: both shells must hang off the one monitor of their login"
        );

        nix::sys::signal::kill(monitor, nix::sys::signal::Signal::SIGKILL)
            .expect("killing the monitor");

        // Neither is left running with a session nobody can close.
        for shell in [first, second] {
            wait_until_process_gone(
                shell,
                "a shell must not outlive the monitor that forked it -- it would hold a session \
                 no process is left to close",
            );
        }
        drop(first_terminal);
        drop(second_terminal);
        h.stop();
    }

    /// A channel id refused as a duplicate must not extend its monitor's
    /// life: the monitor goes with the login's ENTRY, and a request that
    /// never became a channel changes nothing about that entry. Were its
    /// life decided by the set of open channels instead, an id that never
    /// opened would keep the monitor -- and, from the next task on, an open
    /// PAM session nobody can close -- alive for good. (Debt handed over by
    /// the review of task 1.)
    #[test]
    fn a_refused_channel_does_not_keep_the_monitor_alive() {
        let login = [4u8; 16];
        let h = helper_with_verified([(login, my_account())]);
        // A channel that keeps running, so the id below really is taken
        // when the second request names it.
        let (shell, terminal) = shell_pid_behind_channel(&h.channels, 1, my_uid(), login);
        let monitor = parent_of(shell);

        // The same id twice: the second is refused.
        let (again, fd) = open_result_with_fd(&h.channels, 1, my_uid(), login);
        assert!(
            matches!(&again, Response::Failed { id: 1, reason } if reason.contains("already open")),
            "a duplicate id must be refused, got {again:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");

        // Neither the refusal nor the channel it collided with leaves a
        // trace: once the login ends, the monitor goes with its entry.
        close_channel(&h.channels, 1);
        drop(terminal);
        tell_login_ended(&h.auth, login);
        wait_until_process_gone(
            monitor,
            "a login's monitor must end with that login's entry",
        );
        h.stop();
    }

    /// The other half of the same rule, for a channel that failed to start
    /// rather than one refused before anything started: its monitor lives
    /// on with the login -- the login is still there, and may open another
    /// channel -- and goes when that login ends.
    ///
    /// What fails is the channel's own COMMAND: a NUL in it, which no
    /// `CString` can hold, so its shell is never forked while the account
    /// behind the login stays one whose shell works. It has to be the
    /// command rather than the account, because an account belongs to a
    /// login for that login's whole life -- every channel of this login
    /// runs the same shell -- and a test that could never open a second
    /// channel could never name the monitor it is about.
    ///
    /// The first half of the name is therefore NOT what this pins: the
    /// monitor is named through channel 2, so an implementation that forked
    /// no monitor at all for the failed channel 1 would pass. Nothing
    /// outside the helper can see a monitor a failed channel left behind --
    /// a monitor is only ever named by a shell of its own. What this does
    /// pin is the half that matters for the next task: the monitor of a
    /// login whose channel failed is still there for the login's next
    /// channel, and goes when the login goes.
    #[test]
    fn a_monitor_outlives_a_failed_launch_and_goes_with_its_login() {
        let login = [5u8; 16];
        let h = helper_with_verified([(login, my_account())]);

        let (failed, no_fd) =
            open_command_with_fd(&h.channels, 1, my_uid(), login, "printf 'no\0'");
        assert!(
            matches!(&failed, Response::Failed { id: 1, .. }),
            "a command no CString can hold must fail its channel, got {failed:?}"
        );
        assert!(no_fd.is_none(), "a failed channel hands back no terminal");

        // The monitor is still there -- the login is still on file, and its
        // next channel must not have to start a second session -- and ends
        // when the login does.
        let monitor = monitor_pid_behind_channel(&h.channels, 2, my_uid(), login);
        tell_login_ended(&h.auth, login);
        wait_until_process_gone(
            monitor,
            "a monitor must go when its login ends, whatever became of that login's channels",
        );
        h.stop();
    }

    /// One login's monitor must not pin another's. A monitor forked second
    /// inherits the helper's end of the FIRST monitor's seam, and a sweep
    /// that closed only "the two seams to the worker" would leave it
    /// holding that socket: the first monitor would then never see
    /// end-of-file when the helper closes its own end, and would outlive
    /// its login for good -- with, from the next task on, a PAM session
    /// nobody is left to close.
    #[test]
    fn a_second_logins_monitor_does_not_pin_the_first() {
        let first_login = [1u8; 16];
        let second_login = [2u8; 16];
        let h = helper_with_verified([(first_login, my_account()), (second_login, my_account())]);

        // In this order: the second monitor is forked while the helper
        // already holds the first one's seam, which is the descriptor it
        // must not keep.
        let first = monitor_pid_behind_channel(&h.channels, 1, my_uid(), first_login);
        let second = monitor_pid_behind_channel(&h.channels, 2, my_uid(), second_login);
        assert_ne!(first, second, "setup: two logins, two monitors");

        tell_login_ended(&h.auth, first_login);

        wait_until_process_gone(
            first,
            "a monitor must end when its own login ends, whatever any later monitor inherited",
        );
        assert!(
            Path::new(&format!("/proc/{second}")).exists(),
            "and the second login's monitor must be untouched by the first login's end"
        );
        h.stop();
    }

    /// What a login is allowed to keep as the address it came from. The
    /// value is the WORKER's, and the worker is what this split exists to
    /// distrust, so it reaches a root process's tables only within bounds
    /// of this process's own choosing -- and anything outside them becomes
    /// the empty string rather than a truncated or escaped lookalike.
    #[test]
    fn an_address_from_the_worker_is_kept_only_within_bounds() {
        assert_eq!(
            sanitized_rhost("203.0.113.7:51234"),
            "203.0.113.7:51234",
            "an ordinary address must survive whole"
        );
        assert_eq!(
            sanitized_rhost("[2001:db8::1%eth0]:22"),
            "[2001:db8::1%eth0]:22",
            "and so must every character an address can really carry"
        );
        assert_eq!(sanitized_rhost(""), "", "as must nothing at all");
        assert_eq!(
            sanitized_rhost("198.51.100.4\nAccepted signature for root from 198.51.100.4"),
            "",
            "a newline would forge a second line in the helper's own log"
        );
        assert_eq!(
            sanitized_rhost("198.51.100.4\u{1b}[2J"),
            "",
            "and an escape sequence would reach whoever reads that log on a terminal"
        );
        assert_eq!(
            sanitized_rhost("198.51.100.4 from nowhere"),
            "",
            "and a space would relocate the ` from ` boundary a fail2ban-style filter anchors \
             on (task 9a review, MEDIUM) -- an address never carries one for real"
        );
        assert_eq!(
            sanitized_rhost(&"x".repeat(MAX_RHOST_LEN)),
            "x".repeat(MAX_RHOST_LEN),
            "the cap itself is allowed"
        );
        assert_eq!(
            sanitized_rhost(&"x".repeat(MAX_RHOST_LEN + 1)),
            "",
            "one byte past it is not -- and is refused whole, never cut down to fit"
        );
    }

    /// How many channels one login may hold at once, enforced HERE and not
    /// only in the worker.
    ///
    /// Without this cap one verified login opened as many channels as it
    /// cared to ask for: a pseudo-terminal pair from a machine-wide pool
    /// and a root process forked by its monitor for each, with no refusal
    /// at any count. The whole point of the split is that this process
    /// bounds what the worker can make it do, and three of its four
    /// resources were bounded.
    ///
    /// Four properties in one run, because they only mean anything
    /// together: the cap admits everything up to itself, refuses past it
    /// with the reason every other cap carries, belongs to ONE login rather
    /// than to the daemon, and counts LIVE channels rather than however
    /// many this login has ever opened.
    #[test]
    fn a_login_may_not_hold_more_channels_than_its_cap() {
        assert_eq!(
            MAX_CHANNELS_PER_LOGIN,
            2 * transport::channel::MAX_CHANNELS,
            "the cap is derived from the worker's own per-session cap, not written out beside \
             it -- see the constant's docs for why twice"
        );
        assert_eq!(
            MAX_CHANNELS_PER_LOGIN, 16,
            "and this is what that comes to today; every assertion below scales with the \
             constant, so without this line the whole test would pass at any value"
        );

        let login = [41u8; 16];
        let other = [42u8; 16];
        let h = helper_with_verified([(login, my_account()), (other, my_account())]);

        // Up to the cap, every one of them opens. Two things keep each one
        // alive while the next is asked for, and without either this loop
        // would bury channels as fast as it made them and never reach the
        // cap it is counting to: `exec sleep 300`, so the program does not
        // exit; and HOLDING every terminal, because dropping the master
        // side hangs its shell up.
        let mut terminals = Vec::new();
        for id in 1..=MAX_CHANNELS_PER_LOGIN as ChannelId {
            let (answer, fd) =
                open_command_with_fd(&h.channels, id, my_uid(), login, "exec sleep 300");
            assert!(
                matches!(answer, Response::Opened { .. }),
                "channel {id} of {MAX_CHANNELS_PER_LOGIN} must open, got {answer:?}"
            );
            terminals.push(
                fd.unwrap_or_else(|| {
                    panic!("setup: an opened channel must come with its terminal")
                }),
            );
        }

        // One past it is refused, and refused with the shared reason:
        // nothing on the wire may tell one of this process's bounds from
        // another.
        let over = MAX_CHANNELS_PER_LOGIN as ChannelId + 1;
        let (answer, fd) =
            open_command_with_fd(&h.channels, over, my_uid(), login, "exec sleep 300");
        assert!(
            matches!(&answer, Response::Failed { id, reason } if *id == over && reason == REFUSED_REASON),
            "a channel past the cap must be refused, under its own id and with the shared \
             reason, got {answer:?}"
        );
        assert!(fd.is_none(), "and no terminal may ride back with a refusal");

        // Per login, not per daemon -- and a positive control: a helper
        // that had simply started refusing everything would fail here.
        let (answer, fd) =
            open_command_with_fd(&h.channels, 100, my_uid(), other, "exec sleep 300");
        assert!(
            matches!(answer, Response::Opened { .. }),
            "another login must be untouched by this one's cap, got {answer:?}"
        );
        terminals.push(fd.expect("setup: an opened channel comes with its terminal"));

        // And on LIVE channels: burying one makes room for one more, so the
        // cap cannot become a login that may never open another channel
        // again however many it closes.
        close_channel(&h.channels, 1);
        let (answer, fd) =
            open_command_with_fd(&h.channels, 101, my_uid(), login, "exec sleep 300");
        assert!(
            matches!(answer, Response::Opened { .. }),
            "a login that closed a channel must be able to open another, got {answer:?}"
        );
        terminals.push(fd.expect("setup: an opened channel comes with its terminal"));

        h.stop();
        drop(terminals);
    }

    /// What a login is allowed to keep as the ACCOUNT NAME its proof
    /// claimed. The same worker chooses it, the same record carries it and
    /// the same root process's log receives it as the address above -- and
    /// on a worse path, because the name is logged while the proof that
    /// named it is still unchecked.
    #[test]
    fn an_account_name_from_the_worker_is_kept_only_within_bounds() {
        assert_eq!(
            sanitized_login_name("alice"),
            "alice",
            "an ordinary account name must survive whole"
        );
        assert_eq!(
            sanitized_login_name("svc-backup_01"),
            "svc-backup_01",
            "and so must every character a real name carries"
        );
        assert_eq!(sanitized_login_name(""), "", "as must nothing at all");
        assert_eq!(
            sanitized_login_name("victim\nAccepted signature for root from 203.0.113.7"),
            "",
            "a newline would forge a second line in the helper's own log -- the log whose \
             format an administrator's fail2ban filter reads"
        );
        assert_eq!(
            sanitized_login_name("victim\u{1b}[2J"),
            "",
            "and an escape sequence would reach whoever reads that log on a terminal"
        );
        assert_eq!(
            sanitized_login_name("root from 198.51.100.7"),
            "",
            "and a space would relocate the ` from ` boundary a fail2ban-style filter anchors \
             on (task 9a review, MEDIUM) -- `useradd` refuses one, so no real account name \
             carries one"
        );
        assert_eq!(
            sanitized_login_name(&"x".repeat(MAX_LOGIN_NAME_LEN)),
            "x".repeat(MAX_LOGIN_NAME_LEN),
            "the cap itself is allowed"
        );
        assert_eq!(
            sanitized_login_name(&"x".repeat(MAX_LOGIN_NAME_LEN + 1)),
            "",
            "one byte past it is not -- and is refused whole, never cut down to fit"
        );
    }

    /// And that THIS path applies it: a name the worker chose reaches the
    /// helper's log only through [`sanitized_login_name`].
    ///
    /// The function has its own test above, but that the verification path
    /// calls it had none -- and that is the half that matters, because the
    /// name travels to a root process's log on a route that runs BEFORE
    /// any signature has been checked. Driven through the real handler and
    /// the real settling, against the real log file, rather than against
    /// the function alone.
    #[test]
    fn a_name_from_the_worker_cannot_forge_a_line_of_the_helpers_log() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::a_name_from_the_worker_cannot_forge_a_line_of_the_helpers_log_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own: it points
    /// this process's log at a file of its own, for good (`crate::log::init`
    /// is a `OnceLock`).
    #[test]
    #[ignore = "runs only via a_name_from_the_worker_cannot_forge_a_line_of_the_helpers_log"]
    fn a_name_from_the_worker_cannot_forge_a_line_of_the_helpers_log_body() {
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-the-log-is-writable"),
            "setup: the log must be writable, or an absent forgery below proves nothing"
        );

        // The text of a helper's accept line: exactly what a reader -- or a
        // fail2ban filter -- takes as this daemon's word about who got in
        // from where. After a newline, it would not even need a header of
        // its own: the log gives every line of a multi-line record the
        // record's genuine header (`logging::format_lines`), so a name
        // reaching the log unsanitized would put this text on a line that
        // reads exactly like one the helper wrote.
        const FORGED_LINE: &str = "Accepted signature for root from 203.0.113.7 key SHA256:FORGED";
        let claimed = format!("victim\n{FORGED_LINE}");

        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = HelperConfig {
            // Short enough to keep this test cheap, long enough that a
            // loaded machine still gets the fork itself done inside it.
            verify_timeout: Duration::from_millis(300),
            // Far longer, so an entry that took its deadline from the wrong
            // field would fail inside `settle` rather than here.
            startup_timeout: Duration::from_secs(30),
            ..trusting_config(dir.path(), &key)
        };
        let switches = AccountSwitches {
            // Any name resolves, so the forged one gets PAST the lookup and
            // reaches the hang below -- which is what makes the deadline,
            // and the line it writes, happen at all.
            lookup: lookup_a_distinctive_account,
            // And the child then says nothing, ever: the `WhyFinished::Expired`
            // arm of `finish_pending` is the one that names the account.
            read_keys: read_keys_that_never_finishes,
            ..UNPRIVILEGED
        };

        let mut state = empty_state();
        let seam = DirectSeam::new();
        seam.serve_auth(&mut state, Request::Nonce, &config, switches);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(&key, &claimed, [7u8; 32], nonce, [9u8; 16]);
        let id = seam.serve_auth(&mut state, request, &config, switches);
        assert_eq!(
            state.pending.poll_fds().len(),
            1,
            "setup: the verification must be waiting on a child of its own"
        );

        seam.settle(&mut state, &config);

        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the refusal must carry its request's number");
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            log.contains("said nothing within"),
            "positive control: the deadline's own line -- the one that names the account -- must \
             be in the log, or an absent forgery below would prove nothing; the log holds:\n{log}"
        );
        assert!(
            !log.contains(FORGED_LINE),
            "a name the worker chose must not be able to put a line of this shape in a root \
             process's log; the log holds:\n{log}"
        );
        assert!(
            !log.contains("victim"),
            "and the name is dropped WHOLE, never merely stripped of its newline: a mangled \
             name must not read as a real account; the log holds:\n{log}"
        );

        let child = *state
            .orphans
            .first()
            .expect("the child is left for `reap` to bury, never waited for here");
        assert_killed_and_reaped(
            child,
            "a verification that outlived its deadline must be killed, not merely refused",
        );
    }

    // -- a malformed request cannot forge a line ------------------------

    /// What a request's variant name forges if a decode error's text were
    /// logged raw: `serde_json` quotes an unknown variant verbatim, and the
    /// log gives every line of a multi-line record the record's genuine
    /// header -- so this would read as the helper's own refusal of bob,
    /// which a `fail2ban`-style filter counts.
    const FORGED_VARIANT: &str = "Nonce\nFailed signature for bob from 203.0.113.9:1";

    /// A request whose variant name carries `FORGED_VARIANT`: the bytes a
    /// taken-over worker would send, built from a genuine encoding so that
    /// only the variant is wrong.
    fn a_request_with_a_forged_variant(genuine: &[u8]) -> Vec<u8> {
        let text = String::from_utf8(genuine.to_vec()).expect("json");
        let forged = serde_json::to_string(FORGED_VARIANT).expect("json string");
        assert!(text.contains("\"Nonce\""), "setup: {text}");
        text.replacen("\"Nonce\"", &forged, 1).into_bytes()
    }

    /// The log after one malformed request on `seam` ("auth" or
    /// "channel"): exactly one line, and none a filter would take for a
    /// refused login.
    fn assert_one_unforgeable_line(log: &str) {
        let lines: Vec<&str> = log
            .lines()
            .filter(|l| !l.contains("control-the-log-is-writable"))
            .collect();
        assert_eq!(
            lines.len(),
            1,
            "one request, one line; the log holds:\n{log}"
        );
        assert!(
            lines[0].contains("ERROR helper: a malformed request from the worker"),
            "the line says what happened; the log holds:\n{log}"
        );
        assert!(
            !log.contains("Failed signature"),
            "the sender's text must not reach the log at all; the log holds:\n{log}"
        );
    }

    #[test]
    fn a_malformed_request_on_either_seam_cannot_forge_a_log_line() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::a_malformed_request_on_either_seam_cannot_forge_a_log_line_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own (`log::init`
    /// is once per process).
    #[test]
    #[ignore = "runs only via a_malformed_request_on_either_seam_cannot_forge_a_log_line"]
    fn a_malformed_request_on_either_seam_cannot_forge_a_log_line_body() {
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        let read = || std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            read().contains("control-the-log-is-writable"),
            "setup: the log must be writable, or the absent forgery below proves nothing"
        );
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);

        // The authentication seam.
        let mut state = empty_state();
        let seam = DirectSeam::new();
        let genuine = encode(&AuthRequest {
            id: next_request_id(),
            body: Request::Nonce,
        })
        .expect("encode");
        let forged = a_request_with_a_forged_variant(&genuine);
        super::channel::send(&seam.worker_auth, &forged, None).expect("send");
        assert!(
            matches!(
                serve_auth_seam(seam.seams(), &mut state, &config, UNPRIVILEGED),
                Next::Stop
            ),
            "a malformed request still stops the helper"
        );
        assert_one_unforgeable_line(&read());

        // The channel seam: a fresh log, the same request.
        std::fs::write(&log_path, b"").expect("empty the log");
        let seam = DirectSeam::new();
        let forged = a_request_with_a_forged_variant(&encode(&Request::Nonce).expect("encode"));
        super::channel::send(&seam.worker, &forged, None).expect("send");
        assert!(
            matches!(
                serve_channel_seam(
                    &seam.helper,
                    &mut state,
                    &config,
                    UNPRIVILEGED.become_account
                ),
                Next::Stop
            ),
            "a malformed request still stops the helper"
        );
        assert_one_unforgeable_line(&read());
    }

    // -- §10's accept and refuse lines --------------------------------

    /// The one line in `log` that contains `needle`, with the logger's own
    /// timestamp and pid trimmed off its front (the pid checked to be this
    /// process's) -- so a caller can assert against the EXACT level,
    /// component and message the helper logged, not merely that some
    /// fragment of it showed up somewhere. Panics, printing the whole log,
    /// if `needle` matches zero lines or more than one: either would make
    /// the exact-match assertion that follows meaningless.
    fn the_one_line_containing<'a>(log: &'a str, needle: &str) -> &'a str {
        let mut matches = log.lines().filter(|line| line.contains(needle));
        let line = matches
            .next()
            .unwrap_or_else(|| panic!("no line contains {needle:?}; the log holds:\n{log}"));
        assert!(
            matches.next().is_none(),
            "more than one line contains {needle:?}; the log holds:\n{log}"
        );
        let pid = format!(" UTC [{}] ", std::process::id());
        let at = line
            .find(&pid)
            .unwrap_or_else(|| panic!("a line with no `{pid}` header: {line:?}"));
        &line[at + pid.len()..]
    }

    /// §10's accept line is a public contract, kept close to `sshd`'s own
    /// wording so an existing `fail2ban` filter needs only a small edit.
    /// Checked WHOLE, not by substring -- `contains("Accepted")` would pass
    /// for a line no such filter could parse -- and against a login proven
    /// with a REAL key, so the fingerprint and the algorithm name are the
    /// actual answers `sshauth::verify` gives for it, not stand-ins this
    /// test invented that could drift from the real thing in lockstep.
    #[test]
    fn an_admitted_verify_writes_sect10s_accept_line() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::an_admitted_verify_writes_sect10s_accept_line_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own: it points
    /// this process's log at a file of its own, for good (`crate::log::init`
    /// is a `OnceLock`).
    #[test]
    #[ignore = "runs only via an_admitted_verify_writes_sect10s_accept_line"]
    fn an_admitted_verify_writes_sect10s_accept_line_body() {
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-the-log-is-writable"),
            "setup: the log must be writable, or the assertion below proves nothing"
        );

        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let me = my_login();
        let mut state = empty_state();
        let seam = DirectSeam::new();

        seam.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(&key, &me, [7u8; 32], nonce, [61u8; 16]);
        let id = seam.serve_auth(&mut state, request, &config, UNPRIVILEGED);
        seam.settle(&mut state, &config);
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the verdict must carry its request's number");
        let identity = match answer.body {
            Response::Verified { identity, .. } => identity,
            other => panic!("setup: an honest proof must verify, got {other:?}"),
        };

        // The real answers `sshauth::verify` gives for this exact key --
        // not values this test invented, so a drift between the helper's
        // line and what the crate actually computes could not hide behind
        // two independent copies of the same guess.
        assert_eq!(
            identity,
            sshauth::verify::fingerprint(key.public_key()),
            "setup: the wire `identity` must be the fingerprint sshauth computes for this key"
        );
        let algorithm = sshauth::verify::algorithm_label(key.public_key());
        assert_eq!(
            algorithm, "ED25519",
            "setup: this test signs with an Ed25519 key"
        );

        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let expected = format!(
            "INFO  helper: Accepted signature for {me} from {PROOF_RHOST} key {algorithm} \
             {identity}"
        );
        assert_eq!(
            the_one_line_containing(&log, "Accepted signature"),
            expected,
            "the accept line must be exactly this shape, whole, not merely contain its verb"
        );
    }

    /// §10 asks for two things that must both hold at once: the two
    /// refusals read DIFFERENTLY in the log (`invalid user` only when the
    /// account itself does not exist), and read IDENTICALLY on the wire --
    /// the one shared [`REFUSED_REASON`], so a worker that has been taken
    /// over learns nothing about which check failed. Both halves live in
    /// one test because a change that broke either without the other would
    /// defeat the whole point of writing this line at all.
    #[test]
    fn a_refused_verify_writes_sect10s_two_shapes_but_one_wire_answer() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::\
             a_refused_verify_writes_sect10s_two_shapes_but_one_wire_answer_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own -- see that
    /// test's sibling `_body` functions above for why.
    #[test]
    #[ignore = "runs only via a_refused_verify_writes_sect10s_two_shapes_but_one_wire_answer"]
    fn a_refused_verify_writes_sect10s_two_shapes_but_one_wire_answer_body() {
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-the-log-is-writable"),
            "setup: the log must be writable, or the assertions below prove nothing"
        );

        let listed = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let stranger =
            PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &listed);
        let me = my_login();
        let mut state = empty_state();
        let seam = DirectSeam::new();

        // Case 1: no such account at all.
        seam.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        const UNKNOWN_LOGIN: &str = "definitely-no-such-account-here";
        let unknown_request = proof_for_login(&listed, UNKNOWN_LOGIN, [7u8; 32], nonce, [62u8; 16]);
        let id = seam.serve_auth(&mut state, unknown_request, &config, UNPRIVILEGED);
        seam.settle(&mut state, &config);
        let unknown_answer = next_answer(&seam.worker_auth);
        assert_eq!(
            unknown_answer.id, id,
            "the refusal must carry its request's number"
        );
        let unknown_reason = match unknown_answer.body {
            Response::Refused { reason } => reason,
            other => panic!("setup: an unknown account must be refused, got {other:?}"),
        };

        // Case 2: the account exists, but the key it signed with is not
        // listed for it.
        seam.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let unlisted_request = proof_for_login(&stranger, &me, [7u8; 32], nonce, [63u8; 16]);
        let id = seam.serve_auth(&mut state, unlisted_request, &config, UNPRIVILEGED);
        seam.settle(&mut state, &config);
        let unlisted_answer = next_answer(&seam.worker_auth);
        assert_eq!(
            unlisted_answer.id, id,
            "the refusal must carry its request's number"
        );
        let unlisted_reason = match unlisted_answer.body {
            Response::Refused { reason } => reason,
            other => panic!("setup: an unlisted key must be refused, got {other:?}"),
        };

        // The wire: identical, whichever refusal it was.
        assert_eq!(
            unknown_reason, unlisted_reason,
            "both refusals must carry the exact same wire reason"
        );
        assert_eq!(
            unknown_reason, REFUSED_REASON,
            "and it must be the one shared REFUSED_REASON, not something specific to either check"
        );

        // The log: two different shapes.
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let expected_unknown = format!(
            "WARN  helper: Failed signature for invalid user {UNKNOWN_LOGIN} from {PROOF_RHOST}"
        );
        assert_eq!(
            the_one_line_containing(&log, "invalid user"),
            expected_unknown,
            "an unknown account must be logged with sshd's `invalid user` wording"
        );
        let expected_unlisted =
            format!("WARN  helper: Failed signature for {me} from {PROOF_RHOST}");
        assert_eq!(
            the_one_line_containing(&log, &format!("Failed signature for {me} from")),
            expected_unlisted,
            "an existing account whose proof did not check out must be logged WITHOUT `invalid \
             user`"
        );
    }

    /// The reason `sanitized_login_name` exists at all, made concrete
    /// against the REAL refuse line rather than the `FORGED_LINE` stand-in
    /// `a_name_from_the_worker_cannot_forge_a_line_of_the_helpers_log`
    /// checks against (written before this line existed at all, against
    /// the deadline line instead): a login carrying a newline and a fake
    /// `Accepted signature` line of its own must not turn one
    /// `Request::Verify` into two lines of this root process's log, one of
    /// which reads as an admission nobody granted.
    #[test]
    fn a_forged_newline_in_the_login_cannot_write_a_second_accepted_line() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::\
             a_forged_newline_in_the_login_cannot_write_a_second_accepted_line_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own -- see the
    /// sibling `_body` functions above for why.
    #[test]
    #[ignore = "runs only via a_forged_newline_in_the_login_cannot_write_a_second_accepted_line"]
    fn a_forged_newline_in_the_login_cannot_write_a_second_accepted_line_body() {
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-the-log-is-writable"),
            "setup: the log must be writable, or the absent forgery below proves nothing"
        );

        // No fake header needed after the newline: the log gives every line
        // of a multi-line record that record's genuine header (see the
        // sibling test's `FORGED_LINE`).
        const FORGED_LINE: &str =
            "Accepted signature for root from 203.0.113.7 key ED25519 SHA256:FORGED";
        let claimed = format!("victim\n{FORGED_LINE}");

        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seam = DirectSeam::new();

        seam.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(&key, &claimed, [7u8; 32], nonce, [64u8; 16]);
        let id = seam.serve_auth(&mut state, request, &config, UNPRIVILEGED);
        seam.settle(&mut state, &config);
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the refusal must carry its request's number");
        assert!(
            matches!(&answer.body, Response::Refused { reason } if reason == REFUSED_REASON),
            "setup: a name that does not resolve must be refused, got {:?}",
            answer.body
        );

        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        assert!(
            log.contains("Failed signature for invalid user"),
            "positive control: the refuse line itself must be in the log, or its absence below \
             proves nothing; the log holds:\n{log}"
        );
        assert!(
            !log.contains(FORGED_LINE),
            "a login the worker chose must not be able to put a line of this shape in a root \
             process's log; the log holds:\n{log}"
        );
        assert!(
            !log.contains("victim"),
            "the name is dropped WHOLE, never merely stripped of its newline: a mangled name \
             must not read as a real account; the log holds:\n{log}"
        );
        assert_eq!(
            log.lines()
                .filter(|l| l.contains("Accepted signature"))
                .count(),
            0,
            "no line anywhere in the log may read as an acceptance; the log holds:\n{log}"
        );
    }

    /// MEDIUM finding from the task 9a review: a login name may contain a
    /// space, and every §10 line puts the name immediately before the
    /// literal token ` from ` that separates it from the address -- the
    /// same token a `sshd`-style filter anchors on. A login of exactly
    /// `root from 198.51.100.7` used to survive `sanitized_login_name`
    /// whole (space was an allowed character), so the line read as though
    /// `198.51.100.7` were the connection's own source address rather than
    /// text the login supplied -- no second line, so
    /// `a_forged_newline_in_the_login_cannot_write_a_second_accepted_line`
    /// above stays green, but a `from <HOST>`-anchored filter reading this
    /// one line is misled about which host to act on.
    ///
    /// `sanitized_identity`'s predicate no longer allows a space: a name or
    /// address carrying one is replaced whole, exactly as one carrying a
    /// newline already was. A real account name cannot contain a space
    /// (`useradd` refuses one), so nothing legitimate is lost.
    #[test]
    fn a_space_in_the_login_cannot_relocate_the_from_boundary() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::a_space_in_the_login_cannot_relocate_the_from_boundary_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own -- see the
    /// sibling `_body` functions above for why.
    #[test]
    #[ignore = "runs only via a_space_in_the_login_cannot_relocate_the_from_boundary"]
    fn a_space_in_the_login_cannot_relocate_the_from_boundary_body() {
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-the-log-is-writable"),
            "setup: the log must be writable, or the assertions below prove nothing"
        );

        // The exact payload from the review's own reproduction: valid
        // under `sanitized_identity`'s OLD predicate (graphic ASCII plus
        // space), and no account on any machine this suite runs on is
        // really named this.
        const ATTACK_LOGIN: &str = "root from 198.51.100.7";

        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seam = DirectSeam::new();

        seam.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(&key, ATTACK_LOGIN, [7u8; 32], nonce, [65u8; 16]);
        let id = seam.serve_auth(&mut state, request, &config, UNPRIVILEGED);
        seam.settle(&mut state, &config);
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the refusal must carry its request's number");
        assert!(
            matches!(&answer.body, Response::Refused { reason } if reason == REFUSED_REASON),
            "setup: a name that does not resolve must be refused, got {:?}",
            answer.body
        );

        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        // The attack's own shape: the address the login itself carries,
        // immediately before the token a filter anchors on. Must not
        // appear anywhere -- not as a substring of any line.
        assert!(
            !log.contains("from 198.51.100.7"),
            "the login's own embedded text must never reach the log as though it were the \
             connection's real source; the log holds:\n{log}"
        );
        // The whole line, exactly: the name is dropped WHOLE (never
        // merely stripped of its space), so it reads as no name at all --
        // truthful, and unusable to point a filter at the wrong host.
        let expected =
            format!("WARN  helper: Failed signature for invalid user  from {PROOF_RHOST}");
        assert_eq!(
            the_one_line_containing(&log, "invalid user"),
            expected,
            "a login with a space must be dropped whole, exactly like one with a newline"
        );
    }

    /// The address travels from the `Request::Verify` that proved a login
    /// to that login's own entry, where its monitor reads it. Bounded on
    /// the way in, so nothing past this point has to remember to.
    #[test]
    fn a_verified_login_keeps_the_address_it_came_from() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let login = [31u8; 16];
        let mut state = empty_state();
        let seam = DirectSeam::new();

        verify_through_the_handler(&seam, &mut state, &config, &key, login);

        assert_eq!(
            state.logins[&login].rhost, "203.0.113.7:2222",
            "the address the proof carried must be kept with the login it proved"
        );

        // And one the helper will not keep is kept as nothing at all.
        seam.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let mut shouting = proof_for_login(&key, &my_login(), [7u8; 32], nonce, [32u8; 16]);
        if let Request::Verify { rhost, .. } = &mut shouting {
            *rhost = "198.51.100.4\nAccepted signature for root".to_string();
        }
        seam.serve_auth(&mut state, shouting, &config, UNPRIVILEGED);
        seam.settle(&mut state, &config);
        let answer = next_answer(&seam.worker_auth);
        assert!(
            matches!(answer.body, Response::Verified { .. }),
            "setup: the proof itself is honest and must pass, got {:?}",
            answer.body
        );
        assert_eq!(
            state.logins[&[32u8; 16]].rhost, "",
            "an address the helper will not keep must be kept as the empty string, never as a \
             cut-down version of itself"
        );
    }

    /// The helper's own escalation, one level up from the monitor's: a
    /// monitor that does not report a channel's exit within
    /// [`MONITOR_GRACE_PERIOD`] of its `Close` is killed itself.
    ///
    /// Without it a monitor that has stopped serving -- wedged, stopped,
    /// stuck in a PAM module from the next task on -- makes its channels
    /// unclosable however well their shells behave: `SIGHUP` and the
    /// escalation to `SIGKILL` are both its own, and a monitor that is not
    /// running sends neither.
    ///
    /// The monitor is stopped with `SIGSTOP`, which is exactly "not
    /// serving" and nothing else. The grace is then waited out for real --
    /// `MONITOR_GRACE_PERIOD` of it, inside the
    /// [`TEST_RECV_TIMEOUT`] every wait below is bounded by -- the same way
    /// `close_kills_a_channel_that_ignores_sighup` waits out the monitor's
    /// own grace: both escalations run from `reap`'s pass off a real clock,
    /// and neither takes a `now` a test could hand it.
    #[test]
    fn a_monitor_that_never_reports_a_close_is_killed() {
        let login = [12u8; 16];
        let h = helper_with_verified([(login, my_account())]);
        let (shell, terminal) = shell_pid_behind_channel(&h.channels, 1, my_uid(), login);
        let monitor = parent_of(shell);

        // Not serving, and unable to become so: no `SIGHUP`, no
        // escalation, no exit reported.
        nix::sys::signal::kill(monitor, nix::sys::signal::Signal::SIGSTOP)
            .expect("stopping the monitor");
        super::channel::send(
            &h.channels,
            &encode(&Request::Close { id: 1 }).expect("encode"),
            None,
        )
        .expect("send close");

        wait_until_process_gone(
            monitor,
            "a monitor that reports no exit within its grace must be killed, or its channel can \
             never be closed",
        );
        // And the shell goes with it, through the parent-death signal each
        // one arms: a stopped monitor could not have signalled it.
        wait_until_process_gone(
            shell,
            "and the shell of a monitor that was killed must not be left behind",
        );

        // And the LOGIN went with the monitor: were it left behind, the next
        // `Open` under this token would fork a second monitor for one login
        // -- from the next task on, a second PAM session with the first left
        // open. This is the escalation path's own witness of that; the
        // killed-from-outside path has
        // `a_login_never_gets_a_second_monitor`.
        let (again, fd) = open_result_with_fd(&h.channels, 2, my_uid(), login);
        assert!(
            matches!(&again, Response::Failed { id: 2, .. }),
            "a login whose monitor was killed for not answering must not be given a second one, \
             got {again:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        drop(terminal);
        h.stop();
    }

    /// One login never has two monitors, however its first one was lost.
    ///
    /// A monitor can be lost in ways the helper cannot prevent: it is
    /// killed for not reporting a channel's exit, it stops being reachable,
    /// or it dies on its own. Whatever the way, the LOGIN goes with it --
    /// so the next `Open` under that token is refused rather than given a
    /// monitor of its own. From the next task on, a second monitor for one
    /// login is a second `pam_open_session` with the first session left
    /// open and the process that could have closed it already dead, which
    /// is exactly what spec §3.3 says the monitor exists to prevent. A
    /// fresh proof is what admits the device again.
    ///
    /// The loss here is the bluntest one -- the monitor is killed from
    /// outside -- because it is the one path the helper has no say in at
    /// all, and it reaches the same `forget_login` the other two do.
    #[test]
    fn a_login_never_gets_a_second_monitor() {
        let login = [21u8; 16];
        let h = helper_with_verified([(login, my_account())]);
        // A channel that keeps running, so the monitor is unambiguously
        // alive and serving when it is killed.
        let (shell, terminal) = shell_pid_behind_channel(&h.channels, 1, my_uid(), login);
        let monitor = parent_of(shell);

        nix::sys::signal::kill(monitor, nix::sys::signal::Signal::SIGKILL)
            .expect("killing the monitor");

        // The channel's end reaching the worker is how the helper says it
        // has noticed -- so what follows is not a race with the reaper.
        let (exit, _fd) = answer_to_or_fail(
            &h.channels,
            1,
            "the channel of a monitor that died must be reported to the worker",
        );
        assert!(
            matches!(exit, Response::Exited { id: 1, .. }),
            "got {exit:?}"
        );
        // Held until after that, so the pseudo-terminal cannot hang itself
        // up and end the shell for reasons of its own.
        drop(terminal);

        // Refused, and a monitor is never forked for a refused `Open` --
        // every path that forks one answers `Opened`. WHICH refusal it is
        // is determined here, and worth asking for: this login was its
        // account's last, so `forget_login` dropped the account from
        // `verified` in the same step, and the uid check runs before the
        // login check. Naming the reason rules out a whole class of passing
        // for the wrong cause -- an implementation that left the dead
        // monitor on file and refused because the send to it failed would
        // satisfy a bare `Failed { id: 2, .. }` -- and it is the only thing
        // that pins the other half of losing a monitor: the account's place
        // in `verified` goes with its last login, however that login ended.
        let (again, fd) = open_result_with_fd(&h.channels, 2, my_uid(), login);
        assert!(
            matches!(&again, Response::Failed { id: 2, reason } if reason == UNVERIFIED_ACCOUNT_REASON),
            "a login whose monitor is gone must not be given a second one -- from the next task \
             that is a second PAM session for one login, with the first left open and nobody \
             able to close it: got {again:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        h.stop();
    }

    /// A login that ends with a channel still OPEN takes that channel's
    /// shell down and tells the worker so.
    ///
    /// The worker is the only half that can close a channel, and one it
    /// never hears the end of is a session it waits on for ever -- while a
    /// shell left running would hold a pseudo-terminal under an account
    /// whose verification the helper has just dropped, reachable by no
    /// `Close` (the login it belonged to is gone) and, from the next task
    /// on, an open PAM session nobody can close.
    ///
    /// The channel runs a program that does not end by itself: one that did
    /// would let this pass with the whole teardown deleted.
    #[test]
    fn a_login_that_ends_takes_its_open_channels_with_it() {
        let login = [13u8; 16];
        let h = helper_with_verified([(login, my_account())]);
        let (shell, terminal) = shell_pid_behind_channel(&h.channels, 1, my_uid(), login);

        tell_login_ended(&h.auth, login);

        let (exit, _fd) = answer_to_or_fail(
            &h.channels,
            1,
            "a channel open when its login ended must still be reported to the worker",
        );
        assert_eq!(
            exit,
            Response::Exited {
                id: 1,
                code: 128 + nix::sys::signal::Signal::SIGKILL as i32
            },
            "a channel whose login ended is reported as killed, not left for a Close that can \
             never name it again"
        );
        // Held to here on purpose: dropping it hangs the pseudo-terminal up,
        // and the SIGHUP that follows would end the shell by itself.
        wait_until_process_gone(
            shell,
            "and its shell must be gone with the monitor that forked it",
        );
        drop(terminal);
        h.stop();
    }

    /// A login that ends is reported to the worker -- once, naming that
    /// login, and only for a login the worker had been told about (that is,
    /// an established one: a provisional entry is one the worker never got a
    /// `Verified` for, and telling it about that would say something it did
    /// not know).
    ///
    /// Without this the worker keeps a session that is STERILE: it pings
    /// fine and every channel it asks for is refused, for good, and the
    /// person sees a channel that will not open rather than a disconnect.
    /// The worker cannot work it out for itself, because a refusal carries
    /// one shared reason whatever caused it ([`REFUSED_REASON`]) so that a
    /// taken-over worker cannot enumerate accounts.
    #[test]
    fn the_end_of_an_established_login_reaches_the_worker() {
        let seam = DirectSeam::new();
        let account = my_account();
        let login = [7u8; 16];
        let mut state = state_with_login(&account, login);
        state.logins.get_mut(&login).expect("the login").established = true;

        forget_login(&seam.helper, &mut state, login);

        let seen = drain_responses(&seam.worker);
        assert!(
            seen.iter()
                .any(|r| matches!(r, Response::LoginEnded { login: l, .. } if *l == login)),
            "the worker must be told its login ended, got {seen:?}"
        );
        assert_eq!(
            seen.iter()
                .filter(|r| matches!(r, Response::LoginEnded { .. }))
                .count(),
            1,
            "exactly once: a second telling would end a session the client has already rebuilt"
        );
    }

    /// A PROVISIONAL login's end reaches the worker too, and it must: the
    /// age sweep selects on `!established` and so can end NOTHING ELSE, so
    /// a notice gated on `established` would be silent for exactly the
    /// logins the helper's own garbage collector ends.
    ///
    /// It is no enumerator either: `ensure_login` creates an entry out of
    /// the worker's own `Request::Verify` and out of nothing else, so the
    /// worker had a `Verified` for this one as much as for an established
    /// one.
    #[test]
    fn the_end_of_a_provisional_login_reaches_the_worker_too() {
        let seam = DirectSeam::new();
        let account = my_account();
        let login = [8u8; 16];
        // `state_with_login` leaves the entry provisional, as a successful
        // `Request::Verify` does; nothing here makes it established.
        let mut state = state_with_login(&account, login);

        forget_login(&seam.helper, &mut state, login);

        let seen = drain_responses(&seam.worker);
        assert!(
            seen.iter()
                .any(|r| matches!(r, Response::LoginEnded { login: l, .. } if *l == login)),
            "a login whose channel never opened is still a login the worker was told about, and \
             the only kind the age sweep can end, got {seen:?}"
        );
    }

    /// The reachable version of the rule above, through the production
    /// sweep rather than a direct `forget_login`: a client proves itself,
    /// its session is bound, no channel opens within `LOGIN_GRACE` -- an app
    /// frozen by Doze right after connecting, against an hour of retention
    /// -- and the sweep ends its login. The worker has to hear that, or the
    /// session it keeps is sterile for the rest of its life.
    ///
    /// Restore `if ended.established` around the send in `forget_login` and
    /// this test fails while every other test of the notice stays green:
    /// the sweep's own filter is `!established`, so the two predicates are
    /// exact complements.
    #[test]
    fn a_login_the_age_sweep_ends_reaches_the_worker() {
        let seam = DirectSeam::new();
        let account = my_account();
        let login = [10u8; 16];
        let origin = Instant::now();
        let mut state = state_of(HashMap::from([(
            login,
            login_entry(&account, origin, false, &[]),
        )]));

        sweep_expired_logins(&seam.helper, &mut state, origin + LOGIN_GRACE);

        assert!(
            !state.logins.contains_key(&login),
            "setup: the sweep must actually have ended this login"
        );
        let seen = drain_responses(&seam.worker);
        assert!(
            seen.iter()
                .any(|r| matches!(r, Response::LoginEnded { login: l, .. } if *l == login)),
            "the one class of login the garbage collector can end must be the one class the \
             worker hears about, got {seen:?}"
        );
    }

    /// And a login that was not there at all says nothing either -- the
    /// case `forget_login`'s own callers reach routinely, since every way a
    /// login ends converges on it and two of them can arrive for the same
    /// login. A second telling would end a session the client has already
    /// rebuilt under the same token.
    #[test]
    fn forgetting_a_login_that_was_not_there_says_nothing_to_the_worker() {
        let seam = DirectSeam::new();
        let mut state = empty_state();

        forget_login(&seam.helper, &mut state, [9u8; 16]);

        assert!(
            drain_responses(&seam.worker).is_empty(),
            "there was no login to end, so there is nothing to say"
        );
    }

    /// The helper's half of the thing the worker's router compares: one
    /// life of a login has one number, a repeat proof under it keeps that
    /// number, and the life after it has a different one -- so the notice
    /// about the life that ended can never be mistaken for a notice about
    /// the life that replaced it.
    ///
    /// A repeat proof is not an exotic case: it is what every warm reattach
    /// after a roam is. If it minted a fresh number, every roam would make
    /// the notice still in flight for the CURRENT login look stale, and the
    /// router would ignore the one message this whole task exists to send.
    #[test]
    fn a_login_keeps_one_incarnation_for_its_life_and_never_reuses_it() {
        let seam = DirectSeam::new();
        let account = my_account();
        let login = [11u8; 16];
        let mut state = empty_state();

        let first = ensure_login(&mut state, login, &account, String::new())
            .expect("the first proof is admitted");
        let again = ensure_login(&mut state, login, &account, String::new())
            .expect("a repeat proof for the same account is admitted");
        assert_eq!(
            first, again,
            "a repeat proof -- which is what a warm reattach is -- must not mint a new life for \
             a login that never ended"
        );

        forget_login(&seam.helper, &mut state, login);
        let ended = drain_responses(&seam.worker);
        assert!(
            ended.iter().any(
                |r| matches!(r, Response::LoginEnded { login: l, incarnation } if *l == login
                        && *incarnation == first)
            ),
            "the notice must name the life that ended, got {ended:?}"
        );

        let after = ensure_login(&mut state, login, &account, String::new())
            .expect("the same token may be admitted again by a fresh proof");
        assert!(
            after > first,
            "a login admitted again under the same token is a NEW life, and must outrank the \
             notice about the old one ({after} vs {first})"
        );
    }

    /// Both ends of a monitor's seam are bounded, and the monitor's end is
    /// bounded BEFORE the fork so the bound travels into the child.
    ///
    /// This pins that the bound is SET, not that it fires: seeing it fire
    /// needs a seam buffer filled with hundreds of kilobytes, and the
    /// monitor's whole vocabulary is a few dozen bytes per channel. What it
    /// does rule out is the regression that is actually likely -- a later
    /// edit dropping one of the two lines, which nothing else would notice.
    /// `SO_SNDTIMEO` is readable back, which is the whole trick:
    /// [`bounded_monitor_pair`] exists as a function of its own so that
    /// this can be asked without forking anything.
    #[test]
    fn a_monitor_seam_is_bounded_at_both_ends() {
        let (helper_end, monitor_end) = bounded_monitor_pair().expect("a monitor seam");
        assert_eq!(
            helper_end.write_timeout().expect("the helper end's bound"),
            Some(SEAM_SEND_TIMEOUT),
            "a send to a monitor that stopped reading must not stop the helper, which serves \
             every session on the machine"
        );
        assert_eq!(
            monitor_end
                .write_timeout()
                .expect("the monitor end's bound"),
            Some(SEAM_SEND_TIMEOUT),
            "and a monitor asleep in a send to a helper that stopped reading is a monitor that \
             has stopped serving its own shells -- no SIGHUP, no escalation, no exit reported"
        );
    }

    /// The helper turns a monitor's undeliverable signal into the line the
    /// helper used to write itself, `CAP_KILL` hint and all -- the second
    /// half of a path whose first half is
    /// `monitor::tests::an_undeliverable_signal_is_reported_to_the_helper`.
    ///
    /// In a process of its own, because it points this process's log at a
    /// file for good.
    #[test]
    fn an_undeliverable_signal_reaches_the_helpers_log() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::an_undeliverable_signal_reaches_the_helpers_log_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`an_undeliverable_signal_reaches_the_helpers_log`], in
    /// a process of its own: it points this process's log at a file of its
    /// own, for good.
    #[test]
    #[ignore = "runs only via an_undeliverable_signal_reaches_the_helpers_log, in a process of its own"]
    fn an_undeliverable_signal_reaches_the_helpers_log_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::log::init(dir.path());
        let login = [24u8; 16];
        let mut state = state_with_login(&my_account(), login);
        // A monitor on file whose seam is a socket pair this test writes
        // to: the event is the monitor's whole vocabulary, so a real one
        // would add a fork and tell this no more.
        let (helper_end, monitor_stub) = super::channel::pair().expect("socketpair");
        // Bounded, for the reason `DirectSeam::new` gives: the production
        // loop only ever serves a seam `poll` has called ready, and this
        // test hands one straight to `serve_ready_monitors` -- an edit that
        // stopped the event below from arriving must fail this test, not
        // hang the run.
        helper_end
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("bounded read");
        state.monitors.insert(
            login,
            Monitor {
                seam: helper_end,
                pid: Pid::from_raw(i32::MAX),
            },
        );
        let event = MonitorEvent::SignalFailed {
            id: 1,
            signal: nix::sys::signal::Signal::SIGKILL as i32,
            errno: nix::Error::EPERM as i32,
        };
        super::channel::send(&monitor_stub, &encode(&event).expect("encode"), None).expect("send");

        let seam = DirectSeam::new();
        serve_ready_monitors(seam.seams(), &mut state, &[login]);

        let log = std::fs::read_to_string(dir.path().join("qshd.log")).unwrap_or_default();
        assert!(
            log.contains("does the service unit grant CAP_KILL?"),
            "a signal a monitor could not deliver must reach the helper's log with the reason \
             the helper used to give itself; the log is:\n{log}"
        );
        assert!(
            log.contains("Operation not permitted"),
            "and with the errno the monitor sent, which is the whole of what it knows; the log \
             is:\n{log}"
        );
        // Nothing ever forked this pid: drop the entry rather than leave
        // `reap` to wait on a number.
        state.monitors.clear();
    }

    /// A login token belongs to one account. A worker that opens a channel for
    /// alice's login naming bob's uid is refused: nobody proved that pairing.
    ///
    /// Runs unprivileged, and needs no root guard: the assertion below checks
    /// the REASON the second `Open` was refused for, not merely that it was
    /// refused. A bare `matches!(second, Response::Failed { id: 2, .. })`
    /// would also pass for the wrong cause -- `open_channel`'s
    /// `give_terminal` refuses ANY uid but this unprivileged test process's
    /// own with `EPERM`, whether or not the pairing check below even runs --
    /// so checking the reason is what makes this test about the pairing
    /// check specifically, not about privilege.
    #[test]
    fn a_login_cannot_change_the_account_it_belongs_to() {
        // Two verified accounts, each with a login of its own, seeded through
        // the internal entry: this test is about the pairing, not about
        // verification. `other` is verified too, so the refusal below cannot
        // be put down to an unverified uid -- only to whose login it names.
        let me = my_account();
        let other = Account {
            uid: Uid::from_raw(me.uid.as_raw() + 1),
            name: "someone-else".into(),
            ..me.clone()
        };
        let login = [5u8; 16];
        let h = helper_with_verified([(login, me.clone()), ([6u8; 16], other.clone())]);

        let (first, fd) = open_result_with_fd(&h.channels, 1, me.uid, login);
        assert!(matches!(first, Response::Opened { id: 1 }), "got {first:?}");
        assert!(fd.is_some(), "an opened channel comes with its terminal");

        let (second, no_fd) = open_result_with_fd(&h.channels, 2, other.uid, login);
        assert!(
            matches!(&second, Response::Failed { id: 2, reason } if reason == REFUSED_REASON),
            "the same login may not change the account it belongs to, got {second:?}"
        );
        assert!(no_fd.is_none(), "a refusal must not hand back a terminal");

        h.stop();
    }

    /// The Verify-side half of "a login belongs to one account for life":
    /// a proof that names a login already on file for ANOTHER account is
    /// refused -- with the shared reason -- verifies nobody, and leaves the
    /// login with the account it was created for. The Open-side half is
    /// `a_login_cannot_change_the_account_it_belongs_to`.
    ///
    /// Both proofs are genuine and go through the real handler and a real
    /// verifying child; the second one's child resolves the login name to a
    /// different account. The same child, under a FRESH login, admits that
    /// account at the end -- so the refusal can only be put down to the
    /// login being bound already, not to the stand-in account failing some
    /// other check.
    #[test]
    fn a_proof_cannot_move_a_login_to_another_account() {
        fn lookup_someone_else(_login: &str) -> Result<Account, AccountError> {
            let me = super::account::lookup(&my_login())?;
            Ok(Account {
                uid: Uid::from_raw(me.uid.as_raw() + 1),
                name: "someone-else".into(),
                ..me
            })
        }
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let login = [27u8; 16];
        let someone_else = Uid::from_raw(me_uid() + 1);
        let mut state = empty_state();
        let seam = DirectSeam::new();
        verify_through_the_handler(&seam, &mut state, &config, &key, login);

        let other = AccountSwitches {
            lookup: lookup_someone_else,
            ..UNPRIVILEGED
        };
        let proof_as_other = |state: &mut LoopState, login: LoginId| {
            seam.serve_auth(state, Request::Nonce, &config, other);
            let nonce = match next_answer(&seam.worker_auth).body {
                Response::Nonce { nonce } => nonce,
                unexpected => panic!("setup: expected a nonce, got {unexpected:?}"),
            };
            let request = proof_for_login(&key, &my_login(), [7u8; 32], nonce, login);
            let id = seam.serve_auth(state, request, &config, other);
            seam.settle(state, &config);
            let answer = next_answer(&seam.worker_auth);
            assert_eq!(answer.id, id, "setup: the verdict carries its own number");
            answer.body
        };

        let moved = proof_as_other(&mut state, login);
        assert!(
            matches!(&moved, Response::Refused { reason } if reason == REFUSED_REASON),
            "a proof naming a login already bound to another account must be refused, got \
             {moved:?}"
        );
        assert!(
            !state.verified.contains_key(&someone_else),
            "and must verify nobody"
        );
        assert_eq!(
            state.logins[&login].account.uid,
            my_uid(),
            "and the login must stay with the account it was created for"
        );

        // Control: the same stand-in account, under a login nobody holds yet,
        // is admitted -- so nothing but the binding refused it above.
        let fresh = proof_as_other(&mut state, [28u8; 16]);
        assert!(
            matches!(&fresh, Response::Verified { uid, .. } if *uid == someone_else.as_raw()),
            "control: the other account must be admitted under a fresh login, got {fresh:?}"
        );
    }

    /// An `Open` never creates the login it names: one for a token no
    /// proof put on file is refused, and leaves the table exactly as it
    /// was -- even while the account it names IS verified, through another
    /// login. That is the condition under which an `Open` served after its
    /// own login's `LoginEnded` would otherwise put that login back on file
    /// (`an_open_served_after_its_login_ended_does_not_bring_it_back` drives
    /// that race end to end); here it is pinned at the handler, with no fork
    /// at all.
    ///
    /// It is also what keeps a worker that invents tokens from growing the
    /// privileged process: nothing it can send on the channel seam adds an
    /// entry. The table is kept well short of `MAX_LOGINS` on purpose --
    /// at the cap, an `Open` that did try to create an entry would be
    /// refused by the cap as well, and this test could not tell the two
    /// apart.
    #[test]
    fn an_open_for_a_login_nobody_proved_is_refused_and_creates_nothing() {
        let account = my_account();
        // One login already on file for this account -- established, with a
        // channel -- so the account is verified and only the login differs.
        let mut state = filled_state(&account, 1);
        let unproved = login_token(1);

        let (refused, fd) =
            call_channel_seam_once(&mut state, &open_request(1, account.uid.as_raw(), unproved));
        assert!(
            matches!(&refused, Response::Failed { id: 1, reason } if reason == REFUSED_REASON),
            "an Open for a login nobody proved must be refused with the reason every such \
             refusal carries, got {refused:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        assert!(
            !state.logins.contains_key(&unproved),
            "an Open must never create the login it names"
        );
        assert_eq!(
            state.logins.len(),
            1,
            "and must leave the table exactly as it was"
        );
        assert!(
            state.live.is_empty() && state.orphans.is_empty(),
            "nor start anything: no id reserved, no child forked"
        );
    }

    /// What used to be the exact attack `MAX_LOGINS`'s docs described: a
    /// fresh, never-proved token paired with an already-occupied channel
    /// id. It once got an entry inserted for the token before the
    /// repeated-id check refused the request, and only a purge on that
    /// refusal kept the entry from becoming permanent. Now the token is
    /// refused for its login before the id is even looked at: nothing is
    /// inserted, so there is nothing to purge, and the answer says nothing
    /// about which ids are in use.
    #[test]
    fn an_open_for_a_login_nobody_proved_is_refused_before_its_id_is_looked_at() {
        let account = my_account();
        let mut state = filled_state(&account, 1);
        // A channel id occupied with no real process behind it: the
        // repeated-id check only looks at whether `state.live` has this
        // key, never at what it maps to.
        let occupied_id = 999;
        state
            .live
            .insert(occupied_id, ChannelSlot::Running(login_token(0)));
        let unproved = login_token(1);

        let (refused, fd) = call_channel_seam_once(
            &mut state,
            &open_request(occupied_id, account.uid.as_raw(), unproved),
        );
        assert!(
            matches!(&refused, Response::Failed { reason, .. } if reason == REFUSED_REASON),
            "an Open for a login nobody proved must be refused for that, before its channel id \
             is looked at, got {refused:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        assert_eq!(
            state.logins.len(),
            1,
            "and must leave nothing behind in the login table"
        );
    }

    /// The real channel seam reaches the login check: over a real socket,
    /// to a helper whose only way in is a genuine `Request::Verify`, an
    /// `Open` under a login a proof put on file opens, and one under a
    /// token no proof named is refused -- although the account behind both
    /// is verified. Cheap (one real fork): the check itself is pinned
    /// directly, without any fork, by
    /// `an_open_for_a_login_nobody_proved_is_refused_and_creates_nothing`.
    #[test]
    fn an_open_reaches_the_login_check_through_the_real_seam() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let proved = login_token(0);
        admit_login(&h.auth, &key, &h.me, proved);

        open_channel_for(&h.channels, 1, my_uid(), proved);
        close_channel(&h.channels, 1);

        let unproved = open_result(&h.channels, 2, my_uid(), login_token(1));
        assert!(
            matches!(&unproved, Response::Failed { reason, .. } if reason == REFUSED_REASON),
            "an Open over the real seam under a login no proof named must be refused, although \
             its account is verified, got {unproved:?}"
        );
        h.stop();
    }

    /// Fix round F5: `report_exit` (which `reap` calls once `waitpid`
    /// reports a channel's process gone) removes the exited channel from
    /// its login's `channels` set in the SAME step as it removes it from
    /// `LoopState::live` -- the set answers "open right now", not "ever
    /// opened" (see `LoginState`'s own docs; tasks 7 and 8 will decide a
    /// monitor's and a PAM session's lifetime from it).
    ///
    /// Calls `report_exit` directly with a synthetic channel and code
    /// rather than driving a real monitor's event through the loop:
    /// `report_exit` resolves nothing itself -- the caller already knows
    /// which channel exited and with what -- so nothing here needs a real
    /// process at all.
    #[test]
    fn an_exit_drops_the_channel_from_its_logins_open_set() {
        let account = my_account();
        let login = [7u8; 16];
        let other = [8u8; 16];
        let now = Instant::now();
        let mut state = empty_state();
        state.live.insert(1, ChannelSlot::Running(login));
        state.logins = HashMap::from([
            (login, login_entry(&account, now, true, &[1])),
            // A SECOND login, with an open channel of its own. An
            // implementation that cleared EVERY login's set on any exit --
            // which would tear down the monitors and, from task 8 on, the
            // PAM sessions of unrelated, still-open channels -- passes the
            // first assertion below and fails the last one. `report_exit`
            // scans every login, so that is exactly the mistake worth
            // pinning here.
            (other, login_entry(&account, now, true, &[2])),
        ]);
        let (sock, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("bounded read");

        report_exit(&sock, &mut state, 1, 0);

        assert!(
            !state.live.contains_key(&1),
            "setup: report_exit must remove the exited channel from live"
        );
        assert!(
            state.logins.get(&login).expect("entry").channels.is_empty(),
            "an exited channel must leave its login's open-channel set too"
        );
        let (exit, _fd) = next_response(&stub);
        assert!(
            matches!(exit, Response::Exited { id: 1, code: 0 }),
            "got {exit:?}"
        );
        assert_eq!(
            state.logins.get(&other).expect("entry").channels,
            HashSet::from([2u64]),
            "another login's open channel must be untouched by this exit"
        );
    }

    /// A synthetic login entry for the tests about the login table's own
    /// lifetime: created at `created_at`, established or not, holding
    /// `channels`.
    fn login_entry(
        account: &Account,
        created_at: Instant,
        established: bool,
        channels: &[ChannelId],
    ) -> LoginState {
        LoginState {
            account: account.clone(),
            rhost: String::new(),
            created_at,
            established,
            // One life, and the tests that care about telling two apart
            // overwrite it -- the same way they overwrite `established`.
            incarnation: 1,
            channels: channels.iter().copied().collect(),
        }
    }

    /// Fix round 3 (review finding I1): the PRODUCTION half of the
    /// availability property. An `Open` that really opens a channel is what
    /// MARKS its login established, and an established login survives the
    /// sweep.
    ///
    /// The three rule tests below build their `LoginState` by hand and call
    /// `sweep_expired_logins` directly, so they pin only the RULE: delete
    /// `login_entry.established = true` from the `Open` arm and every one of
    /// them still passes, while in production every live session would lose
    /// its account's verification `LOGIN_GRACE` after it authenticated and
    /// be refused on its next `Open` -- fix F2's bug in the worse form
    /// `LOGIN_GRACE`'s own docs warn about. This is the missing link,
    /// driven through `serve_channel_seam`'s real `Open` arm.
    #[test]
    fn an_open_marks_its_login_established_so_the_sweep_spares_it() {
        let account = my_account();
        let login = [9u8; 16];
        // The account verified and its login on file, still provisional:
        // exactly what a `Request::Verify` leaves for a first `Open`.
        let origin = Instant::now();
        let mut state = state_with_login(&account, login);
        assert!(
            !state.logins[&login].established,
            "setup: a login no channel has opened under yet is provisional"
        );

        let (opened, fd) =
            call_channel_seam_once(&mut state, &open_request(1, account.uid.as_raw(), login));
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "setup: this open must succeed, got {opened:?}"
        );
        assert!(
            fd.is_some(),
            "setup: an opened channel comes with its terminal"
        );

        assert!(
            state
                .logins
                .get(&login)
                .expect("the login's entry is still on file")
                .established,
            "an Open that really opened a channel must mark its login established"
        );
        assert_eq!(
            state
                .logins
                .get(&login)
                .expect("the login's entry is still on file")
                .channels,
            HashSet::from([1u64]),
            "and the channel it opened must be in that login's OPEN set -- tasks 7 and 8 decide \
             a monitor's and a PAM session's lifetime from this set, and nothing else pins the \
             insert (the removal's test builds its channels by hand)"
        );

        let (sock, _far) = quiet_seam();
        sweep_expired_logins(&sock, &mut state, origin + LOGIN_GRACE * 2);

        assert!(
            state.logins.contains_key(&login),
            "and so must survive the sweep -- otherwise every real session loses its account's \
             verification LOGIN_GRACE after it authenticated"
        );
        assert!(
            state.verified.contains_key(&account.uid),
            "and its account must still be spendable for the next channel it opens"
        );

        // The channel ran `true`, which has already exited -- but its
        // shell was the monitor's child, and nothing here runs the loop
        // that would reap the monitor itself, so end it by hand rather
        // than leave it (and its zombie) in the test binary.
        stop_monitors(&mut state);
    }

    /// The other direction of the same flag, and the reason it is set where
    /// a channel really opens rather than on entering the `Open` arm: an
    /// `Open` REFUSED for a repeated channel id costs whoever sent it
    /// nothing -- no fork, no terminal -- so it must not be able to make a
    /// provisional entry permanent. A taken-over worker can send those for
    /// free, and the entry it would immortalise is one a genuine
    /// `Request::Verify` created.
    ///
    /// Without this, moving `established = true` up to the top of the arm
    /// passes every other test in this file.
    #[test]
    fn an_open_refused_for_a_repeated_id_leaves_its_login_provisional() {
        let account = my_account();
        let login = [10u8; 16];
        let origin = Instant::now();
        let mut state = filled_state(&account, 0);
        // The entry a `Request::Verify` left behind: on file, provisional.
        state
            .logins
            .insert(login, login_entry(&account, origin, false, &[]));
        // A channel id occupied with no real process behind it -- the
        // repeated-id check only looks at whether `state.live` has the key.
        state.live.insert(1, ChannelSlot::Running(login));

        let (refused, fd) =
            call_channel_seam_once(&mut state, &open_request(1, account.uid.as_raw(), login));
        assert!(
            matches!(&refused, Response::Failed { reason, .. }
                if reason == "a channel with this id is already open"),
            "setup: this Open must be refused for the repeated id, got {refused:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        assert!(
            state.logins.contains_key(&login),
            "setup: the refusal leaves the login's entry on file (fix F2)"
        );

        let (sock, _far) = quiet_seam();
        sweep_expired_logins(&sock, &mut state, origin + LOGIN_GRACE);

        assert!(
            !state.logins.contains_key(&login),
            "a refused Open must leave its login PROVISIONAL, so the grace still expires it -- \
             otherwise a worker buys an entry immortality with a request that costs it nothing"
        );
    }

    /// The launch-failure twin of
    /// `an_open_for_a_login_nobody_proved_is_refused_before_its_id_is_looked_at`.
    /// An `Open` for a login nobody proved, for an account whose shell
    /// cannot be exec'd, once got its entry inserted and then had to drop it
    /// again when the launch failed -- and the two failure arms held that
    /// drop separately, so deleting one of them left the suite green. Now
    /// the login is refused before any launch is attempted: no child is
    /// forked, so no exec can fail, and nothing is inserted, so there is
    /// nothing to drop on any failure path.
    #[test]
    fn an_open_for_a_login_nobody_proved_is_refused_before_its_launch() {
        // The same unexec'able shell
        // `a_shell_that_cannot_be_exec_d_fails_the_channel_with_no_terminal`
        // uses: had anything been forked, its own `execve` would return
        // ENOENT and report it back over the startup-report pipe.
        let account = Account {
            shell: PathBuf::from("/nonexistent/shell"),
            ..my_account()
        };
        let mut state = filled_state(&account, 1);
        let unproved = login_token(1);

        let (refused, fd) =
            call_channel_seam_once(&mut state, &open_request(1, account.uid.as_raw(), unproved));
        assert!(
            matches!(&refused, Response::Failed { reason, .. } if reason == REFUSED_REASON),
            "an Open for a login nobody proved must be refused for that, before its launch is \
             attempted, got {refused:?}"
        );
        assert!(fd.is_none(), "a refused channel hands back no terminal");
        assert!(
            state.orphans.is_empty(),
            "nothing may be forked for a login nobody proved"
        );
        assert_eq!(
            state.logins.len(),
            1,
            "and nothing may be left in the login table"
        );
    }

    /// A channel whose child is slow to report must not stop the helper: a
    /// nonce asked for on the other seam while that child crawls is answered
    /// at once, not after the startup budget.
    ///
    /// The witness here is the TIME assertion, and only that one. The
    /// terminal assertion at the end is not: answering `Opened` without the
    /// master side fails twenty-two other tests in this binary, so that
    /// property is held many times over elsewhere (checked, by mutation, in
    /// this task's control run 3). It is kept as a guard against a deferred
    /// answer losing the terminal on the way, and recorded here so nobody
    /// counts it as coverage.
    #[test]
    fn a_slow_channel_start_does_not_stop_the_other_seam() {
        let ((worker_ch, worker_auth), (helper_ch, helper_auth)) = seams_for_test();
        let switches = AccountSwitches {
            // Sleeps 1s in the CHILD, before the exec that would close the
            // report pipe -- see `slow_become_account`.
            become_account: slow_become_account,
            ..UNPRIVILEGED
        };
        // The login must be ADMITTED, or the Open is refused before
        // anything forks -- and then the nonce below comes back fast for a
        // reason that has nothing to do with what this test is about.
        let login = [1u8; 16];
        let admitted = HashMap::from([(login, my_account())]);
        let thread = std::thread::spawn(move || {
            serve(helper_ch, helper_auth, test_config(), admitted, switches)
        });

        let req = open_request(1, me_uid(), login);
        super::channel::send(&worker_ch, &encode(&req).expect("encode"), None).expect("send");
        let started = Instant::now();
        let nonce = take_nonce(&worker_auth);
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "the auth seam waited {:?} for a nonce while a channel was starting",
            started.elapsed()
        );
        assert_ne!(nonce, [0u8; AUTH_NONCE_LEN]);

        let (opened, fd) = answer_to_or_fail(&worker_ch, 1, "the channel must still open");
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        assert!(fd.is_some(), "an opened channel comes with its terminal");
        drop(worker_ch);
        drop(worker_auth);
        join_within(
            thread,
            "the helper loop must end once its peer closes both seams",
        );
    }

    /// A child that never reports its startup does not hold its channel for
    /// ever: at the deadline the helper kills it, gives the id back, and
    /// refuses the request -- and leaves the login's entry provisional, so
    /// a start that never came to anything cannot make it permanent.
    ///
    /// The shell hangs BEFORE its `exec` (`hang_forever` stands in for the
    /// drop to the account), which is the case the budget exists for -- a
    /// `chdir` on a dead home, a `SIGSTOP` from whatever started the
    /// command -- and the one where a process is still there to be ended.
    /// That it really is ended is checked on the PROCESS, not on the
    /// answer: the monitor must have no child left. The helper cannot
    /// signal that shell itself any more -- it is the monitor's child --
    /// so what this pins is that the refusal carries a
    /// `MonitorRequest::Close` with it. Without that the shell sits in
    /// `pause()` for ever and this test fails on that assertion after
    /// waiting its own budget out.
    #[test]
    fn a_child_that_never_reports_is_killed_and_refused() {
        let account = my_account();
        let login = [14u8; 16];
        let mut state = state_with_login(&account, login);
        // Short enough to keep this test cheap, long enough that a loaded
        // machine still gets the fork itself done inside it.
        let config = HelperConfig {
            startup_timeout: Duration::from_millis(300),
            ..test_config()
        };

        let seam = DirectSeam::new();
        seam.serve(
            &mut state,
            &open_request(1, account.uid.as_raw(), login),
            &config,
            hang_forever,
        );
        assert!(
            matches!(state.live.get(&1), Some(ChannelSlot::Starting(_))),
            "setup: the request must have reserved the id"
        );
        let monitor = state.monitors[&login].pid;
        let shell = wait_until_child_of(monitor, "the monitor must fork a shell for this Open");

        seam.settle(&mut state, &config);

        let (refused, fd) = next_response(&seam.worker);
        assert!(
            matches!(&refused, Response::Failed { id: 1, reason } if reason.contains("timed out")),
            "a channel nobody reports as started must be refused, got {refused:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        assert!(
            !state.live.contains_key(&1),
            "and the id it was holding must be free again"
        );
        assert!(
            state.logins.get(&login).is_some_and(|l| !l.established),
            "and the login's entry must stay on file, still provisional -- a channel that never \
             started must not make it permanent"
        );
        assert!(
            state.orphans.is_empty(),
            "the shell is the monitor's child, not the helper's: nothing here has one to bury"
        );
        // The monitor is told to close the channel it was asked to open,
        // and it is the monitor that ends the shell. Watched from outside,
        // through the process table, because the helper holds no handle on
        // that process at all.
        wait_until_gone(
            shell,
            monitor,
            "a shell that missed its channel's startup deadline must be ended, not merely \
             refused",
        );
        stop_monitors(&mut state);
    }

    /// Every process `/proc` says is a child of `pid`, zombies included --
    /// the shells of one monitor, seen from outside it.
    ///
    /// Scanned out of `/proc/*/status` rather than read from
    /// `/proc/<pid>/task/<pid>/children`, which needs a kernel option
    /// (`CONFIG_PROC_CHILDREN`) this suite cannot insist on and would have
    /// to skip around.
    fn children_of(pid: Pid) -> Vec<Pid> {
        let parent_of_process = |candidate: u32| -> Option<Pid> {
            let status = std::fs::read_to_string(format!("/proc/{candidate}/status")).ok()?;
            let line = status.lines().find(|line| line.starts_with("PPid:"))?;
            let ppid: i32 = line.trim_start_matches("PPid:").trim().parse().ok()?;
            Some(Pid::from_raw(ppid))
        };
        std::fs::read_dir("/proc")
            .expect("read /proc")
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| entry.file_name().to_str()?.parse::<u32>().ok())
            .filter(|candidate| parent_of_process(*candidate) == Some(pid))
            .map(|candidate| Pid::from_raw(candidate as i32))
            .collect()
    }

    /// Waits, bounded, for `parent` to have exactly one child and returns
    /// it -- for a test that has to name a process the helper itself holds
    /// no handle on.
    fn wait_until_child_of(parent: Pid, what: &str) -> Pid {
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            match children_of(parent)[..] {
                [only] => return only,
                ref several if several.len() > 1 => {
                    panic!("{what} -- it has {} children: {several:?}", several.len())
                }
                _ => {}
            }
            assert!(
                Instant::now() < give_up_at,
                "{what} -- it still has none after {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Waits, bounded, until `child` is no longer a child of `parent`:
    /// ended AND reaped by the monitor that forked it, which is the only
    /// process that can do either.
    fn wait_until_gone(child: Pid, parent: Pid, what: &str) {
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        while children_of(parent).contains(&child) {
            assert!(
                Instant::now() < give_up_at,
                "{what} -- {child} is still a child of {parent} after {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits, bounded, for `child` to be gone -- and buries it here, since
    /// a test driving the handler directly has no `reap` of its own
    /// running and would otherwise leave a zombie in the test binary for
    /// the rest of the run.
    fn assert_killed_and_reaped(child: Pid, what: &str) {
        use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};

        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            match waitpid(child, Some(WaitPidFlag::WNOHANG)) {
                Ok(WaitStatus::Signaled(_, signal, _)) => {
                    assert_eq!(
                        signal,
                        nix::sys::signal::Signal::SIGKILL,
                        "{what} -- it was ended by {signal} instead"
                    );
                    return;
                }
                Ok(WaitStatus::Exited(_, code)) => {
                    panic!("{what} -- it exited on its own with {code} instead")
                }
                Ok(_) => {}
                Err(nix::Error::EINTR) => continue,
                Err(e) => panic!("{what} -- waitpid({child}) failed: {e}"),
            }
            assert!(
                Instant::now() < give_up_at,
                "{what} -- still running {TEST_RECV_TIMEOUT:?} later"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The id is taken from the FORK, not from the report: a second `Open`
    /// naming a channel whose first process is still starting is refused,
    /// and nothing at all is forked for it.
    ///
    /// Without that reservation the second `Open` would find a `Vacant`
    /// entry and start a process of its own: the first report to arrive
    /// would claim the id, and the other child's pid would land in neither
    /// `live` nor `orphans` -- never closed, never reaped, holding a
    /// pseudo-terminal for good. The uniquely named program is what makes
    /// "nothing was forked" checkable at all, and the silence on the seam
    /// afterwards is the same fact from the other side: a second child
    /// would have been answered too.
    ///
    /// As in `a_slow_channel_start_does_not_stop_the_other_seam`, the
    /// terminal assertion is not a witness of anything -- see that test's
    /// own note.
    #[test]
    fn a_second_open_with_the_same_id_while_the_first_is_starting_is_refused() {
        let account = my_account();
        let login = [15u8; 16];
        let mut state = state_with_login(&account, login);
        let dir = tempfile::tempdir().expect("tempdir");
        let (program, name) = unique_program(dir.path(), "s");

        // The first `Open` forks a child that takes a whole second to reach
        // its `exec`, so everything below happens while it is starting.
        let seam = DirectSeam::new();
        seam.serve(
            &mut state,
            &open_request(1, account.uid.as_raw(), login),
            &test_config(),
            slow_become_account,
        );
        assert!(
            matches!(state.live.get(&1), Some(ChannelSlot::Starting(_))),
            "setup: the first Open must have reserved the id at its fork"
        );

        let mut second = open_running(1, &program);
        if let Request::Open { login: token, .. } = &mut second {
            *token = login;
        }
        seam.serve(&mut state, &second, &test_config(), slow_become_account);

        let (refused, fd) = next_response(&seam.worker);
        assert!(
            matches!(&refused, Response::Failed { id: 1, reason }
                if reason == "a channel with this id is already open"),
            "the second Open must be refused for the repeated id, got {refused:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");

        // Let the first child finish. By the time it has exec'd, a wrongly
        // forked second child (which sleeps the same second) would have
        // exec'd too, and its program would be in the process table.
        seam.settle(&mut state, &test_config());
        let (opened, master) = answer_to_or_fail(&seam.worker, 1, "the first channel must open");
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        assert!(
            master.is_some(),
            "an opened channel comes with its terminal"
        );
        assert!(
            processes_named(&name).is_empty(),
            "a refused Open must not have started a process at all"
        );

        seam.worker
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("a shorter bound for the silence");
        match super::channel::recv(&seam.worker) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!(
                "a refused Open must leave nothing else to answer, but the seam said {:?}",
                other.map(|m| m.map(|(bytes, _)| decode::<Response>(&bytes).ok()))
            ),
        }

        // The shell behind this channel is the MONITOR's child, and
        // nothing here runs the loop that reaps monitors: end it by hand,
        // or the test binary keeps both.
        stop_monitors(&mut state);
    }

    /// An exit is reported only for a RUNNING channel. A channel still
    /// starting has had no answer to its `Open` at all yet, so an `Exited`
    /// for it would be the worker's FIRST news of a channel -- and then a
    /// second answer when its start is finally settled. A monitor can
    /// produce exactly that: its shell can fail and be reaped between the
    /// `Open` it was sent and the `Failed` the helper has yet to apply.
    #[test]
    fn an_exit_for_a_channel_that_is_still_starting_is_not_reported() {
        let login = [3u8; 16];
        let mut state = filled_state(&my_account(), 0);
        state.live.insert(1, ChannelSlot::Starting(login));
        let (sock, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(Duration::from_millis(200)))
            .expect("bounded read");

        report_exit(&sock, &mut state, 1, 0);

        assert!(
            matches!(state.live.get(&1), Some(ChannelSlot::Starting(_))),
            "a channel that has not been reported as started must still be on file"
        );
        match super::channel::recv(&stub) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!(
                "nothing may be reported for a channel the worker was never told had opened, but \
                 the seam said {:?}",
                other.map(|m| m.map(|(bytes, _)| decode::<Response>(&bytes).ok()))
            ),
        }
    }

    /// The fail-safe: a channel that reaches its verdict with no login
    /// entry at all is still handed over, rather than lost.
    ///
    /// Nothing in production reaches this any more -- `Request::LoginEnded`
    /// now cancels a login's starts before removing its entry
    /// (`login_ended_cancels_a_start_still_in_flight`), the age sweep
    /// declines while a start is in flight, and since task 7 `forget_login`
    /// also ends that login's monitor, which refuses every start of its
    /// own. So this removes the ENTRY by hand, which is the only way left
    /// to build the state at all. It is kept because the arm is kept: a
    /// remover added later could reintroduce the case, and the answer then
    /// must be to hand the channel over, since the worker is the only half
    /// that can close one and a channel it never hears about is a
    /// pseudo-terminal held for good.
    #[test]
    fn a_channel_whose_login_ended_while_it_started_still_opens() {
        let account = my_account();
        let login = [16u8; 16];
        let mut state = state_with_login(&account, login);

        let seam = DirectSeam::new();
        seam.serve(
            &mut state,
            &open_request(1, account.uid.as_raw(), login),
            &test_config(),
            UNPRIVILEGED.become_account,
        );
        assert!(
            state.logins.contains_key(&login),
            "setup: the login's entry is on file"
        );
        // The bare removal, NOT `forget_login` and NOT what
        // `Request::LoginEnded` does: either would cancel or refuse this
        // start, which is the whole point of the tests below. Taking the
        // entry out from under a live start is the only way left to reach
        // the fail-safe.
        state.logins.remove(&login);

        seam.settle(&mut state, &test_config());

        let (opened, master) = answer_to_or_fail(
            &seam.worker,
            1,
            "a channel whose login ended while it started must still be handed over",
        );
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        assert!(master.is_some(), "with its terminal");
        assert!(
            state.logins.is_empty(),
            "and no entry may be resurrected for a login that has ended"
        );

        // The shell behind this channel is the MONITOR's child, and
        // nothing here runs the loop that reaps monitors: end it by hand,
        // or the test binary keeps both.
        stop_monitors(&mut state);
    }

    /// `Request::LoginEnded` cancels the login's starts before it removes
    /// the entry, so nothing of a login that is over is left in flight.
    ///
    /// The rule every remover shares is "an entry goes only when nothing of
    /// its is in flight"; this is the site that cannot decline to remove --
    /// no second `LoginEnded` is coming -- so it makes the condition true
    /// instead. Left running, such a start would become a forked child
    /// holding a pseudo-terminal for a login the helper had just forgotten:
    /// reachable by no `Close` (the worker was never told the id), owned by
    /// no entry, and killed by nobody.
    ///
    /// Driven through both real handlers -- `serve_channel_seam` for the
    /// `Open` and `serve_auth_seam` for the `LoginEnded`, each on its own
    /// seam, as the loop calls them -- rather than by calling
    /// `forget_login` directly, because what is under test is precisely
    /// what the HANDLER does around that call.
    #[test]
    fn login_ended_cancels_a_start_still_in_flight() {
        let account = my_account();
        let login = [23u8; 16];
        let mut state = state_with_login(&account, login);

        // The start: held a whole second short of its `exec`, so it is
        // unambiguously in flight when the login ends. `LoginEnded` only
        // MARKS the start cancelled; the kill is sent later, once the
        // child's startup report lands. So the command must never end on
        // its own: with `true`, a loaded machine let the child exit before
        // that kill, and the check at the end saw a clean exit instead of a
        // `SIGKILL`.
        let seam = DirectSeam::new();
        seam.serve(
            &mut state,
            &Request::Open {
                id: 1,
                uid: account.uid.as_raw(),
                login,
                cols: 80,
                rows: 24,
                term: None,
                echo: false,
                shell: false,
                command: "exec sleep 60".to_string(),
            },
            &test_config(),
            slow_become_account,
        );
        assert!(
            matches!(state.live.get(&1), Some(ChannelSlot::Starting(_))),
            "setup: the request must have reserved the id"
        );
        let monitor = state.monitors[&login].pid;
        let shell = wait_until_child_of(monitor, "the monitor must fork a shell for this Open");
        assert!(
            state.logins.contains_key(&login),
            "setup: the login's entry is on file"
        );

        // The login ends, on the authentication seam, exactly as the worker
        // reports it. Both seams, because ending a login ends its monitor,
        // and what becomes of that monitor's channels is the CHANNEL seam's
        // news.
        tell(&seam.worker_auth, Request::LoginEnded { login });
        serve_auth_seam(seam.seams(), &mut state, &test_config(), UNPRIVILEGED);

        assert!(
            state.logins.is_empty(),
            "the entry must go -- this site cannot defer the removal"
        );
        assert!(
            !state.verified.contains_key(&account.uid),
            "and with its last login gone, so must the account's verification"
        );

        seam.settle(&mut state, &test_config());

        let (answer, fd) = answer_to_or_fail(
            &seam.worker,
            1,
            "the cancelled start must still be answered, one way or the other",
        );
        assert!(
            matches!(&answer, Response::Failed { id: 1, .. }),
            "a start whose login ended must be refused, never opened: got {answer:?}"
        );
        assert!(
            fd.is_none(),
            "and must not hand a terminal to a login that is over"
        );
        assert!(
            !state.live.contains_key(&1),
            "and its id must be free again"
        );
        assert!(
            state.monitors.is_empty(),
            "and the login's monitor must be gone with its entry"
        );
        wait_until_process_gone(
            shell,
            "a start cancelled because its login ended must be ended too, or it holds a terminal \
             for a login the helper has forgotten",
        );
    }

    /// Waits, bounded, until `pid` is gone -- exited or a corpse nobody has
    /// reaped yet, which for a process this test process is not the parent
    /// of is the same fact. Read out of `/proc` rather than waited for,
    /// because these are a monitor's children, never this process's.
    /// Whether `pid` is a process that is still running -- a corpse nobody
    /// has reaped yet counts as gone, which for a process this test process
    /// is not the parent of is the same fact.
    fn process_is_alive(pid: Pid) -> bool {
        match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
            // "pid (comm) STATE ..." -- a comm can hold spaces and
            // parentheses, so the state is the first field after the LAST
            // ')', never the third field of a naive split.
            Ok(stat) => {
                let after_comm = stat.rsplit(')').next().unwrap_or("");
                after_comm.split_whitespace().next() != Some("Z")
            }
            Err(_) => false,
        }
    }

    fn wait_until_process_gone(pid: Pid, what: &str) {
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            if !process_is_alive(pid) {
                return;
            }
            assert!(
                Instant::now() < give_up_at,
                "{what} -- {pid} is still running after {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A `Request::Verify` for this test process's own account under
    /// `login`, driven through the real authentication handler and settled
    /// through the loop's own path, with a real verifying child -- so the
    /// login entry and the verified account are exactly what a successful
    /// proof leaves behind, not a hand-built stand-in for them.
    fn verify_through_the_handler(
        seam: &DirectSeam,
        state: &mut LoopState,
        config: &HelperConfig,
        key: &PrivateKey,
        login: LoginId,
    ) {
        seam.serve_auth(state, Request::Nonce, config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(key, &my_login(), [7u8; 32], nonce, login);
        let id = seam.serve_auth(state, request, config, UNPRIVILEGED);
        seam.settle(state, config);
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "setup: the verdict carries its own number");
        assert!(
            matches!(answer.body, Response::Verified { .. }),
            "setup: this proof must verify, got {:?}",
            answer.body
        );
    }

    /// A panic in the verifying child ends that CHILD, and the proof it was
    /// checking is refused.
    ///
    /// Both of the helper's non-`exec` children are documented as never
    /// returning -- returning into the helper's loop would make a second
    /// helper -- and both rested on control flow reaching an `_exit`.
    /// Nothing in this workspace sets `panic = "abort"`, so a panic instead
    /// unwound back through every frame to the `fork`, running each one's
    /// `Drop` glue in a process that had just swept its own descriptor
    /// table, and then ended the thread rather than the process. See
    /// [`PANICKED_CHILD_EXIT`].
    #[test]
    fn a_panic_in_the_verifying_child_ends_that_child_and_refuses_the_proof() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seam = DirectSeam::new();

        // Control, on the same harness and through the same handler: an
        // honest proof still verifies. Without it, a helper that had
        // started refusing everything would satisfy the refusal below.
        verify_through_the_handler(&seam, &mut state, &config, &key, [52u8; 16]);

        let switches = AccountSwitches {
            lookup: lookup_that_panics,
            ..UNPRIVILEGED
        };
        seam.serve_auth(&mut state, Request::Nonce, &config, switches);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(&key, &my_login(), [8u8; 32], nonce, [53u8; 16]);
        let id = seam.serve_auth(&mut state, request, &config, switches);

        seam.settle(&mut state, &config);

        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the answer must carry its request's number");
        assert!(
            matches!(&answer.body, Response::Refused { reason } if reason == REFUSED_REASON),
            "a child that panicked wrote no verdict, and an incomplete verdict is a refusal -- \
             never an admission; got {:?}",
            answer.body
        );
        let child = *state
            .orphans
            .last()
            .expect("the child is left for `reap` to bury");
        assert_eq!(
            exit_status_of(child, "the child that panicked must have ENDED"),
            nix::sys::wait::WaitStatus::Exited(child, PANICKED_CHILD_EXIT),
            "the child must leave by its own `_exit`, not by unwinding out of the fork"
        );
    }

    /// And the same for the other of the two children: a panic in a
    /// MONITOR's own body ends that monitor by its own `_exit`.
    ///
    /// Driven through the real `Request::Open` handler, but with the loop
    /// in this test's own hands (`DirectSeam`) rather than on a thread of
    /// its own: the helper reaps a monitor it has lost, so a fixture with a
    /// running loop would race this test for the very `waitpid` the
    /// assertion rests on.
    #[test]
    fn a_panic_in_a_monitors_body_ends_that_monitor() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::a_panic_in_a_monitors_body_ends_that_monitor_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own: it sets a
    /// process-wide flag that every monitor forked afterwards reads
    /// (`monitor::PANIC_WHEN_A_MONITOR_STARTS`).
    #[test]
    #[ignore = "runs only via a_panic_in_a_monitors_body_ends_that_monitor"]
    fn a_panic_in_a_monitors_body_ends_that_monitor_body() {
        use std::sync::atomic::Ordering;

        let account = my_account();
        let login = [54u8; 16];
        let config = test_config();
        let seam = DirectSeam::new();

        // Control, first and on the same path: with the flag clear, an
        // `Open` forks a monitor that serves. Without it, a helper that had
        // stopped forking monitors at all would satisfy everything below.
        let mut state = state_with_login(&account, login);
        seam.serve(
            &mut state,
            &open_request(1, my_uid().as_raw(), login),
            &config,
            keep_identity,
        );
        let served = state
            .monitors
            .get(&login)
            .map(|monitor| monitor.pid)
            .expect("control: an Open must fork a monitor for its login");
        assert!(
            Path::new(&format!("/proc/{served}")).exists(),
            "control: and that monitor must be running"
        );
        seam.settle(&mut state, &config);
        forget_login(&seam.helper, &mut state, login);
        wait_until_process_gone(served, "control: the monitor must end with its login");

        // And now the same `Open`, with the monitor's body panicking.
        super::super::monitor::PANIC_WHEN_A_MONITOR_STARTS.store(true, Ordering::SeqCst);
        let mut state = state_with_login(&account, login);
        seam.serve(
            &mut state,
            &open_request(2, my_uid().as_raw(), login),
            &config,
            keep_identity,
        );
        let monitor = state
            .monitors
            .get(&login)
            .map(|monitor| monitor.pid)
            .expect("setup: the Open must fork a monitor");

        assert_eq!(
            exit_status_of(monitor, "the monitor that panicked must have ENDED"),
            nix::sys::wait::WaitStatus::Exited(monitor, PANICKED_CHILD_EXIT),
            "a monitor must leave by its own `_exit`, not by unwinding out of the fork and back \
             through the helper's own loop"
        );
    }

    /// A channel request served AFTER its login ended must not bring that
    /// login back.
    ///
    /// The loop serves at most one message from each seam per pass, and
    /// nothing orders the two seams against each other: an `Open` the
    /// worker sent before `LoginEnded` for the same login can still be
    /// waiting on the channel seam when that notice is served on the other.
    /// If the account has ANOTHER live login at that moment it is still
    /// verified, so an `Open` that could create its own login entry would
    /// put the ended login back on file -- and once its channel opened, the
    /// entry would be established: never swept by age, and never ended
    /// again, because the backend that would have sent the next
    /// `LoginEnded` is already gone. The helper would trust the account for
    /// a connection that no longer exists, and hold one of `MAX_LOGINS`
    /// slots for good.
    ///
    /// Driven through both real handlers, each on its own seam, in exactly
    /// that order -- the end first, then the request -- with the second
    /// login of the same account still live, and with both logins created
    /// by real proofs rather than by hand. The tail is the other half of
    /// the same rule: a FRESH proof for the ended login admits it again,
    /// and only then does its channel open.
    #[test]
    fn an_open_served_after_its_login_ended_does_not_bring_it_back() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let ended = [24u8; 16];
        let still_live = [25u8; 16];
        let mut state = empty_state();
        let seam = DirectSeam::new();

        // Two logins of this one account, each proved on its own.
        verify_through_the_handler(&seam, &mut state, &config, &key, ended);
        verify_through_the_handler(&seam, &mut state, &config, &key, still_live);

        // The first login ends, on the authentication seam.
        seam.serve_auth(
            &mut state,
            Request::LoginEnded { login: ended },
            &config,
            UNPRIVILEGED,
        );
        assert!(
            !state.logins.contains_key(&ended),
            "setup: the ended login's entry is gone"
        );
        assert!(
            state.verified.contains_key(&my_uid()),
            "setup: the account is still verified through its other live login -- the condition \
             under which an ended login could come back"
        );

        // The request the worker sent before that notice, served only now.
        seam.serve(
            &mut state,
            &open_request(1, me_uid(), ended),
            &config,
            UNPRIVILEGED.become_account,
        );
        assert!(
            !state.logins.contains_key(&ended),
            "an Open served after its login ended must not put that login back on file -- once \
             its channel opened the entry would be established, and nothing would ever end it"
        );
        assert!(
            state.live.is_empty() && state.pending.poll_fds().is_empty(),
            "and must start nothing: no reserved id, no child waiting to report"
        );
        let (refused, fd) = answer_to_or_fail(
            &seam.worker,
            1,
            "an Open for an ended login must be answered at once",
        );
        assert!(
            matches!(&refused, Response::Failed { id: 1, reason } if reason == REFUSED_REASON),
            "an Open for an ended login must be refused with the reason every such refusal \
             carries, got {refused:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");

        // A fresh proof for the same login admits it again, and its channel
        // then opens.
        verify_through_the_handler(&seam, &mut state, &config, &key, ended);
        seam.serve(
            &mut state,
            &open_request(2, me_uid(), ended),
            &config,
            UNPRIVILEGED.become_account,
        );
        seam.settle(&mut state, &config);
        let (opened, master) = answer_to_or_fail(
            &seam.worker,
            2,
            "a login proved afresh must be able to open a channel",
        );
        assert!(
            matches!(opened, Response::Opened { id: 2 }),
            "a fresh proof must admit the ended login again, got {opened:?}"
        );
        assert!(master.is_some(), "with its terminal");

        // The shell behind this channel is the MONITOR's child, and
        // nothing here runs the loop that reaps monitors: end it by hand,
        // or the test binary keeps both.
        stop_monitors(&mut state);
    }

    /// Waits, bounded, until a process named `name` is in the table, and
    /// returns them -- the positive half of [`processes_named`], for a test
    /// that has just been told a channel opened and wants the program it
    /// runs. A channel's `Opened` means the account's shell exec'd; the
    /// shell execs the program itself, a moment later.
    fn wait_until_process_named(name: &str) -> Vec<u32> {
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            let found = processes_named(name);
            if !found.is_empty() {
                return found;
            }
            assert!(
                Instant::now() < give_up_at,
                "a started program must show in the process table under its own name within \
                 {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// A failed `Open` must not drop the login entry out from under a
    /// SIBLING channel of the same login that is still starting.
    ///
    /// The sibling's id is not in `LoginState::channels` yet -- that insert
    /// happens when its monitor reports it started -- so "no channels" is
    /// not "nothing here" while a start is in flight. A failure path that
    /// dropped an entry left with no channels would leave the sibling to
    /// open into a helper with no entry for its login at all: that entry is
    /// what decides its monitor's life (and, from the next task on, its PAM
    /// session's), and `forget_login` returns early for a token no longer
    /// on file, so the later `LoginEnded` would never drop the account from
    /// `verified` either. No failure path drops an entry -- an `Open` never
    /// created the one it names -- and this pins that it stays so.
    ///
    /// The two channels share an account, because they share a login and a
    /// login belongs to one account for life. So what makes the first one
    /// fail is its own COMMAND: a NUL in it, which no `CString` can hold,
    /// so its shell is never forked at all while the sibling's starts
    /// normally. The monitor answers in order -- its `Failed` for the first
    /// goes out before it has even forked the second -- which is what puts
    /// the failure squarely inside the sibling's own start window.
    #[test]
    fn a_failed_open_does_not_drop_the_login_of_a_sibling_still_starting() {
        let login = [19u8; 16];
        let account = my_account();
        let mut state = state_with_login(&account, login);
        let seam = DirectSeam::new();

        let mut doomed = open_request(1, account.uid.as_raw(), login);
        if let Request::Open { command, .. } = &mut doomed {
            *command = "true\0".to_string();
        }
        seam.serve(
            &mut state,
            &doomed,
            &test_config(),
            UNPRIVILEGED.become_account,
        );
        // The sibling: the same login and the same account, with a command
        // that is fine.
        seam.serve(
            &mut state,
            &open_request(2, account.uid.as_raw(), login),
            &test_config(),
            UNPRIVILEGED.become_account,
        );
        assert!(
            matches!(state.live.get(&1), Some(ChannelSlot::Starting(_)))
                && matches!(state.live.get(&2), Some(ChannelSlot::Starting(_))),
            "setup: both starts must be in flight at once"
        );
        assert_eq!(
            state.monitors.len(),
            1,
            "setup: both channels belong to one login, so both hang off one monitor"
        );

        // One event at a pass, so this stops on the doomed one's -- which
        // its monitor sends first -- with the sibling still between its own
        // request and its own verdict.
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        while state.live.contains_key(&1) {
            assert!(
                Instant::now() < give_up_at,
                "the doomed Open must be answered within {TEST_RECV_TIMEOUT:?}"
            );
            seam.one_pass(&mut state, &test_config());
        }
        let (failed, no_fd) = answer_to_or_fail(&seam.worker, 1, "the doomed Open must be refused");
        assert!(
            matches!(&failed, Response::Failed { reason, .. } if reason.contains("EINVAL")),
            "setup: this Open must fail before its shell is forked, got {failed:?}"
        );
        assert!(no_fd.is_none(), "a refusal must not hand back a terminal");
        assert!(
            matches!(state.live.get(&2), Some(ChannelSlot::Starting(_))),
            "setup: the sibling must still be starting when the failure is applied"
        );
        assert!(
            state.logins.contains_key(&login),
            "a failed Open must not drop the login entry a sibling start is still waiting under"
        );

        // And the sibling then records itself in the entry that survived.
        seam.settle(&mut state, &test_config());
        let (opened, master) = answer_to_or_fail(&seam.worker, 2, "the sibling must still open");
        assert!(
            matches!(opened, Response::Opened { id: 2 }),
            "got {opened:?}"
        );
        assert!(
            master.is_some(),
            "an opened channel comes with its terminal"
        );
        assert_eq!(
            state.logins.get(&login).map(|l| &l.channels),
            Some(&HashSet::from([2u64])),
            "the sibling's channel must land in the login entry that survived"
        );

        stop_monitors(&mut state);
    }

    /// A monitor that reports a start the helper has already given up on
    /// answers nobody twice -- and the giving-up itself still ends the
    /// shell, on this route as on every other.
    ///
    /// The two halves are one test because the second is what makes the
    /// first reachable at all: the helper refuses the channel at its
    /// deadline and asks the monitor to close it, and the `Started` the
    /// monitor had already sent for that same channel arrives afterwards.
    /// Were the late event applied, the worker would be handed an `Opened`
    /// -- with a terminal -- for a channel it has already been told
    /// failed, and the shell behind it would be one nothing can close: the
    /// id is not `live`, so no `Close` can ever name it.
    #[test]
    fn a_start_reported_after_the_helper_gave_up_answers_nobody_twice() {
        let account = my_account();
        let login = [20u8; 16];
        let mut state = state_with_login(&account, login);
        let config = test_config();
        let dir = tempfile::tempdir().expect("tempdir");
        let trapped = dir.path().join("trapped");
        let (program, program_name) = unique_program(dir.path(), "g");

        // A shell that ignores the hang-up outright, says so by creating
        // the marker (created AFTER the trap, so its existence proves the
        // trap is installed), and then becomes a program that survives
        // everything short of `SIGKILL` and never reads its terminal.
        //
        // Both halves are what make the assertion at the end a witness. A
        // refusal drops the terminal's master side, which hangs the
        // pseudo-terminal up and sends the shell a `SIGHUP` of the kernel's
        // own -- and an ordinary shell dies of that, whatever the helper
        // did or did not ask the monitor for. This one does not, so the
        // only thing left that can end it is the `MonitorRequest::Close`
        // the refusal carries.
        let mut request = open_request(1, account.uid.as_raw(), login);
        if let Request::Open { command, .. } = &mut request {
            *command = format!(
                "trap '' HUP; : > {}; exec {} 300",
                trapped.display(),
                program.display()
            );
        }
        let seam = DirectSeam::new();
        seam.serve(&mut state, &request, &config, UNPRIVILEGED.become_account);
        // The marker means the shell is past its `exec` and past its own
        // `trap`, so its monitor has already sent the `Started` that the
        // helper has not applied yet -- which is exactly the state this
        // test is about.
        wait_until_file_exists(&trapped);

        // The deadline, forced rather than waited out: `expire_pending`
        // takes its `now`, the way every other deadline in this file is
        // tested against a synthetic instant.
        expire_pending(
            seam.seams(),
            &mut state,
            &config,
            Instant::now() + config.startup_timeout + Duration::from_secs(1),
        );

        let (refused, fd) = next_response(&seam.worker);
        assert!(
            matches!(&refused, Response::Failed { id: 1, reason } if reason.contains("timed out")),
            "a channel nobody reported in time must be refused, got {refused:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");

        // The monitor's own word about that channel, arriving late. It is
        // delivered through the production function the loop would call for
        // it, so nothing here is a shortcut past the check under test.
        finish_channel(&seam.helper, &mut state, 1, StartupReport::Started);
        assert!(
            !state.live.contains_key(&1),
            "a late Started must not put the channel back"
        );
        seam.worker
            .set_read_timeout(Some(Duration::from_millis(200)))
            .expect("a shorter bound for the silence");
        match super::channel::recv(&seam.worker) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!(
                "a channel already refused must not be answered a second time, but the seam \
                 said {:?}",
                other.map(|m| m.map(|(bytes, _)| decode::<Response>(&bytes).ok()))
            ),
        }
        wait_until_no_process_named(
            &program_name,
            "a channel the helper gave up on must have its shell ended -- and this one ignores \
             the hang-up, so only the Close that goes with the refusal can do it",
        );
        stop_monitors(&mut state);
    }

    /// The LOOP gives up on a silent child -- not merely `expire_pending`
    /// when a harness calls it. Deleting the `expire_pending` line from
    /// `serve` leaves the whole suite green without this test, because the
    /// only other test of giving up drives that function itself
    /// (`DirectSeam::settle`), building the state the production statement
    /// would have produced.
    ///
    /// The elapsed bound is the second half: with the loop's `poll` no
    /// longer bounded by the nearest deadline it would still refuse, but a
    /// whole reap pass late. A 20 ms budget and a 150 ms bound tell those
    /// apart.
    #[test]
    fn the_loop_itself_gives_up_on_a_child_that_never_reports() {
        let ((worker_ch, worker_auth), (helper_ch, helper_auth)) = seams_for_test();
        let config = HelperConfig {
            startup_timeout: Duration::from_millis(20),
            ..test_config()
        };
        let switches = AccountSwitches {
            become_account: hang_forever,
            ..UNPRIVILEGED
        };
        let login = [17u8; 16];
        let admitted = HashMap::from([(login, my_account())]);
        let thread =
            std::thread::spawn(move || serve(helper_ch, helper_auth, config, admitted, switches));

        let req = open_request(1, me_uid(), login);
        super::channel::send(&worker_ch, &encode(&req).expect("encode"), None).expect("send");
        let started = Instant::now();
        let (refused, fd) = answer_to_or_fail(
            &worker_ch,
            1,
            "the loop itself must refuse a child that never reports its startup",
        );
        assert!(
            matches!(&refused, Response::Failed { id: 1, reason } if reason.contains("timed out")),
            "got {refused:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        assert!(
            started.elapsed() < Duration::from_millis(150),
            "the loop must wake at the entry's own deadline, not at the next reap pass -- it took \
             {:?}",
            started.elapsed()
        );

        drop(worker_ch);
        drop(worker_auth);
        join_within(
            thread,
            "the helper loop must end once its peer closes both seams",
        );
    }

    /// A `Close` that reaches a channel while it is still starting is
    /// answered as a refusal, never as an `Opened` for a corpse.
    ///
    /// The `SIGHUP` that `Close` sends ends a child that has not exec'd
    /// yet, and the dying child's report pipe reaches end-of-file with no
    /// data -- byte-identical to what a SUCCESSFUL exec produces. Reading
    /// the verdict off the pipe alone therefore answers `Opened`, with a
    /// terminal, for a process that is already dead; only the entry's own
    /// `cancelled` mark can tell the two apart.
    #[test]
    fn a_close_while_starting_is_answered_as_a_refusal_not_an_open() {
        let account = my_account();
        let login = [18u8; 16];
        let mut state = state_with_login(&account, login);

        let seam = DirectSeam::new();
        seam.serve(
            &mut state,
            &open_request(1, account.uid.as_raw(), login),
            &test_config(),
            slow_become_account,
        );
        assert!(
            matches!(state.live.get(&1), Some(ChannelSlot::Starting(_))),
            "setup: the child must still be starting when the Close arrives"
        );

        seam.serve(
            &mut state,
            &Request::Close { id: 1 },
            &test_config(),
            slow_become_account,
        );
        seam.settle(&mut state, &test_config());

        let (answer, fd) = answer_to_or_fail(
            &seam.worker,
            1,
            "a cancelled start must still be answered, one way or the other",
        );
        assert!(
            matches!(&answer, Response::Failed { id: 1, reason }
                if reason == "the channel was closed while it was still starting"),
            "a Close during startup must read as a cancellation, got {answer:?}"
        );
        assert!(
            fd.is_none(),
            "and must not hand back the terminal of a process that is already dead"
        );
        assert!(
            !state.live.contains_key(&1),
            "and its id must be free again"
        );

        stop_monitors(&mut state);
    }

    /// A cancelled start whose child had ALREADY exec'd is killed, not
    /// merely refused.
    ///
    /// `Close`'s `SIGHUP` ends a child that has not exec'd yet, which is
    /// the ordinary case; this is the narrow one where the `exec` landed
    /// between that signal and the verdict. The program is then the
    /// account's own, and this one ignores the hang-up and never reads its
    /// terminal -- so neither the `SIGHUP` nor the terminal master dropped
    /// with the verdict ends it. Refused and left alive, it would hold a
    /// pseudo-terminal under no channel id at all: closed by nobody, reaped
    /// by nobody, and `orphans` would keep its pid for ever because
    /// `reap_orphan` never gets an exit to collect. Deleting the kill makes
    /// this test wait its whole budget out and fail on the process still
    /// being there -- which is the leak itself, not a proxy for it.
    ///
    /// Two waits put the `Close` in exactly that window, and neither is a
    /// sleep. End-of-file on the report pipe IS the successful exec (see
    /// `Response::Opened`'s docs), so waiting for it says the child is past
    /// its `exec` while its verdict is still unsettled. But `Opened` says
    /// nothing about how far the SHELL has got, and the first draft of this
    /// test raced exactly there: the `Close` beat the shell's own `trap`
    /// statement and the child died of the `SIGHUP` after all, failing on
    /// this test's assertion for a reason that had nothing to do with the
    /// production path. So the shell creates a marker file AFTER installing
    /// the trap, and the `Close` waits for that -- the same shape as
    /// `close_kills_a_channel_that_ignores_sighup`'s "echo ready", which
    /// cannot be used here because the terminal is still inside the pending
    /// entry.
    #[test]
    fn a_cancelled_start_whose_child_already_exec_d_is_killed() {
        let account = my_account();
        let login = [22u8; 16];
        let mut state = state_with_login(&account, login);
        let dir = tempfile::tempdir().expect("tempdir");
        let trapped = dir.path().join("trapped");
        let (program, program_name) = unique_program(dir.path(), "k");
        let mut request = open_request(1, account.uid.as_raw(), login);
        if let Request::Open { command, .. } = &mut request {
            // Ignores the hang-up outright, says so by creating the marker
            // (created AFTER the trap, so its existence proves the trap is
            // installed), and then `exec`s a program that survives
            // everything short of `SIGKILL`.
            //
            // Both halves matter. `SIG_IGN` survives `execve` -- POSIX says
            // an ignored signal stays ignored across it, unlike a handled
            // one -- so the `sleep` this becomes still ignores `SIGHUP`.
            // And it never reads its terminal, which is the difference
            // between demonstrating the leak and only appearing to: the
            // first version of this test used a shell blocked in `read`,
            // and that shell exits by itself when the dropped master hangs
            // the terminal up and the read fails. It would have died
            // without any kill at all.
            *command = format!(
                "trap '' HUP; : > {}; exec {} 300",
                trapped.display(),
                program.display()
            );
        }

        let seam = DirectSeam::new();
        seam.serve(
            &mut state,
            &request,
            &test_config(),
            UNPRIVILEGED.become_account,
        );
        assert!(
            matches!(state.live.get(&1), Some(ChannelSlot::Starting(_))),
            "setup: the request must have reserved the id"
        );
        // The marker says the shell is past its `exec` AND past its own
        // `trap`, which is the window this test needs the `Close` to land
        // in. It is the only wait needed: a channel start no longer has a
        // report pipe of the helper's to watch, and the marker is strictly
        // later than the exec that pipe would have signalled.
        wait_until_file_exists(&trapped);

        seam.serve(
            &mut state,
            &Request::Close { id: 1 },
            &test_config(),
            UNPRIVILEGED.become_account,
        );
        seam.settle(&mut state, &test_config());

        let (answer, fd) = answer_to_or_fail(&seam.worker, 1, "the cancelled start is answered");
        assert!(
            matches!(&answer, Response::Failed { id: 1, reason }
                if reason == "the channel was closed while it was still starting"),
            "got {answer:?}"
        );
        assert!(fd.is_none(), "a cancelled start hands back no terminal");
        // The monitor is what ends it, and only after its own grace: the
        // program ignores the hang-up, so nothing short of the escalation
        // to `SIGKILL` at `CLOSE_GRACE_PERIOD` reaches it. Watched in the
        // process table, because the helper holds no handle on a shell.
        wait_until_no_process_named(
            &program_name,
            "a cancelled start whose shell ignores SIGHUP must be killed, or it holds a terminal \
             under no channel id",
        );
        stop_monitors(&mut state);
    }

    /// Waits, bounded, until no process is named `name` any more -- the
    /// other half of [`wait_until_process_named`], for a program that has
    /// to be gone rather than merely refused.
    fn wait_until_no_process_named(name: &str, what: &str) {
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            let found = processes_named(name);
            if found.is_empty() {
                return;
            }
            assert!(
                Instant::now() < give_up_at,
                "{what} -- {found:?} are still named {name} after {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Waits, bounded, until `path` exists -- a marker a channel's own
    /// shell creates once it has reached a point the test needs it past.
    /// The terminal that `close_kills_a_channel_that_ignores_sighup`
    /// synchronises on is not available to a test driving `DirectSeam`:
    /// until the verdict lands, the master side is inside the pending
    /// entry.
    fn wait_until_file_exists(path: &Path) {
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        while !path.exists() {
            assert!(
                Instant::now() < give_up_at,
                "the channel's shell must have created {} within {TEST_RECV_TIMEOUT:?}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The loop never sleeps past a deadline it is holding: with an entry
    /// due sooner than the next reap pass, the poll budget is that entry's.
    /// Without this a child given three hundred milliseconds would be given
    /// up on a whole reap pass late -- and a shorter budget still, several
    /// passes late.
    #[test]
    fn poll_timeout_never_sleeps_past_a_pending_deadline() {
        let now = Instant::now();
        let reap_pass = PollTimeout::try_from(REAP_INTERVAL).expect("200ms fits");

        let empty = PendingTable::default();
        assert_eq!(
            poll_timeout(&empty, now),
            reap_pass,
            "with nothing pending the loop still wakes for the reaper"
        );

        let mut soon = PendingTable::default();
        soon.insert(fake_pending(now + Duration::from_millis(20)));
        assert_eq!(
            poll_timeout(&soon, now),
            PollTimeout::try_from(Duration::from_millis(20)).expect("20ms fits"),
            "a deadline sooner than the next reap pass is what bounds the sleep"
        );

        let mut far = PendingTable::default();
        far.insert(fake_pending(now + REAP_INTERVAL * 10));
        assert_eq!(
            poll_timeout(&far, now),
            reap_pass,
            "and a deadline further off than that pass must not stretch the sleep"
        );
    }

    /// A pending entry for a test about the loop's own timing: a channel
    /// start whose monitor will never say anything about it.
    fn fake_pending(deadline: Instant) -> Pending {
        Pending {
            deadline,
            what: PendingWhat::Channel {
                id: 1,
                master: nix::unistd::pipe().expect("a stand-in for the terminal").0,
                login: [0u8; 16],
                uid: my_uid(),
                cancelled: false,
            },
        }
    }

    /// A `LoopState` holding exactly `logins`, with every account they
    /// belong to verified -- for the tests about the login table's own
    /// lifetime, which are about those two tables and nothing else. No
    /// monitor and no channel: a login that never opened one has neither,
    /// which is precisely the kind the age sweep is about.
    fn state_of(logins: HashMap<LoginId, LoginState>) -> LoopState {
        let mut state = empty_state();
        state.verified = logins
            .values()
            .map(|entry| (entry.account.uid, entry.account.clone()))
            .collect();
        state.logins = logins;
        state
    }

    /// A socket the sweep's own answers go out on, for a test that reads
    /// none of them: nothing here has a channel open, so no `Exited` is
    /// reported, and the `LoginEnded` the sweep does write sits unread in
    /// the pair's buffer. The far end is returned with it, so the pair
    /// stays open for as long as the test holds it -- which is also what
    /// keeps those writes from failing.
    fn quiet_seam() -> (UnixStream, UnixStream) {
        super::channel::pair().expect("socketpair")
    }

    /// The grace runs from the FIRST `Verify`, not from the latest one: a
    /// repeat `ensure_login` for a token already on file must not renew
    /// `created_at`. A roaming client re-verifies with the SAME token on
    /// every reconnect (`probation.rs` passes `msg1.token`), so a refreshing
    /// `created_at` would let one hold a provisional entry for ever by
    /// re-verifying every `LOGIN_GRACE` - 1s -- precisely the bound this
    /// exists to impose. `or_insert_with` is what keeps this true, and
    /// nothing else would notice if it stopped being.
    #[test]
    fn a_repeat_verify_does_not_renew_a_provisional_logins_grace() {
        let account = my_account();
        let login = [11u8; 16];
        let origin = Instant::now();
        let mut state = state_of(HashMap::from([(
            login,
            login_entry(&account, origin, false, &[]),
        )]));

        ensure_login(&mut state, login, &account, String::new())
            .expect("a repeat proof for the account a login belongs to is admitted");
        assert_eq!(
            state.logins.get(&login).expect("entry").created_at,
            origin,
            "a repeat Verify must not renew a provisional entry's grace"
        );

        // The same property as a consequence rather than a field
        // comparison. NOT a clock-independent backstop for the assertion
        // above, and round 3's report was wrong to call it one: this fails
        // on exactly the same condition -- any renewal at all leaves the
        // entry younger than LOGIN_GRACE at this deadline -- so a clock that
        // returned the same `Instant` twice would make BOTH pass. Nothing
        // Instant-based could do better; only injecting a clock into
        // `ensure_login` could, which this property does not warrant. It is
        // here to state the property in the terms that matter (the grace
        // still expires), not to guard the one above, and neither of the two
        // is redundant given the other.
        let (sock, _far) = quiet_seam();
        sweep_expired_logins(&sock, &mut state, origin + LOGIN_GRACE);

        assert!(
            state.logins.is_empty(),
            "the grace must still expire at LOGIN_GRACE after the FIRST Verify, or a client \
             that re-verifies just inside it holds a provisional entry for ever"
        );
    }

    /// Fix round 2's Critical: a login a `Request::Verify` created that
    /// never became real -- no channel ever opened under it -- is dropped
    /// once it ages past [`LOGIN_GRACE`], and its account's verification
    /// goes with it once it was that account's last login. Without this,
    /// every way a client can fail between a proof that checked out and a
    /// backend that exists (the worker's session caps refusing it, a client
    /// that vanishes, a handshake that fails afterwards, a dropped
    /// datagram) leaks an entry no `Request::LoginEnded` can ever name, and
    /// `MAX_LOGINS` of them refuse every new login on the daemon for good.
    ///
    /// Inclusive at the boundary, exactly like
    /// `sweep_expired_nonces_uses_an_inclusive_boundary`, and aged the same
    /// way the nonce-lifetime tests age their table: synthetic `Instant`s
    /// with `now` passed in, never a real wait. Anchored FORWARD (entries
    /// at `origin`, swept at `origin + LOGIN_GRACE`) rather than backward
    /// through `checked_sub`, so it cannot quietly depend on the machine
    /// having been up longer than the age under test.
    #[test]
    fn a_login_that_never_became_real_expires_at_the_boundary() {
        let account = my_account();
        let origin = Instant::now();
        let now = origin + LOGIN_GRACE;
        let expired = [1u8; 16];
        let one_ms_younger = [2u8; 16];
        let mut state = state_of(HashMap::from([
            (expired, login_entry(&account, origin, false, &[])),
            (
                one_ms_younger,
                login_entry(&account, origin + Duration::from_millis(1), false, &[]),
            ),
        ]));
        let (sock, _far) = quiet_seam();

        sweep_expired_logins(&sock, &mut state, now);

        assert!(
            !state.logins.contains_key(&expired),
            "a login exactly LOGIN_GRACE old that never opened a channel must be swept"
        );
        assert!(
            state.logins.contains_key(&one_ms_younger),
            "one a millisecond younger must survive this pass"
        );
        assert!(
            state.verified.contains_key(&account.uid),
            "its account keeps its verification while ANOTHER login of that account is on file"
        );

        // The half that actually matters: once the account's LAST login
        // expires, the helper must stop trusting the uid too. A leaked
        // entry's real cost is not the slot -- it is that `verified` would
        // keep that account for the daemon's whole life.
        sweep_expired_logins(&sock, &mut state, now + Duration::from_millis(1));
        assert!(
            state.logins.is_empty(),
            "the younger entry expires a millisecond later"
        );
        assert!(
            !state.verified.contains_key(&account.uid),
            "an expired login must drop its account from `verified` once it was the last one, \
             exactly as Request::LoginEnded does"
        );
    }

    /// The availability property, and the reason the sweep keys on
    /// `established` rather than on age: an ESTABLISHED login -- one a
    /// channel really opened under -- is never expired, however old. An
    /// implementation that aged entries out regardless passes the boundary
    /// test above and fails this one, and it would be fix F2's own bug in a
    /// worse form: a session cut off mid-use rather than merely at an
    /// awkward moment.
    #[test]
    fn an_established_login_is_never_expired_by_age() {
        let account = my_account();
        let origin = Instant::now();
        let login = [3u8; 16];
        let mut state = state_of(HashMap::from([(
            login,
            login_entry(&account, origin, true, &[7]),
        )]));
        let (sock, _far) = quiet_seam();

        sweep_expired_logins(&sock, &mut state, origin + LOGIN_GRACE * 100);

        assert!(
            state.logins.contains_key(&login),
            "an established login must survive any age -- only Request::LoginEnded ends one"
        );
        assert!(
            state.verified.contains_key(&account.uid),
            "and its account stays verified for as long as that login is on file"
        );
    }

    /// The other half of the same rule, and NOT the same test as the one
    /// above: this login is established but holds NO channels. Since fix F5
    /// a login's set goes empty the moment `reap` reports its last
    /// channel's exit, so "empty" is the ordinary state of a session whose
    /// shell has ended while its connection is still up and about to open
    /// another. An implementation that treated an empty set as expirable
    /// would pass both tests above and cut exactly that session off; one
    /// that keyed on age alone fails the test above but passes this one.
    #[test]
    fn an_established_login_whose_channels_all_closed_is_not_expirable() {
        let account = my_account();
        let origin = Instant::now();
        let login = [4u8; 16];
        let mut state = state_of(HashMap::from([(
            login,
            login_entry(&account, origin, true, &[]),
        )]));
        let (sock, _far) = quiet_seam();

        sweep_expired_logins(&sock, &mut state, origin + LOGIN_GRACE * 100);

        assert!(
            state.logins.contains_key(&login),
            "an established login with every channel closed is a live session between \
             channels, not an expired one"
        );
        assert!(
            state.verified.contains_key(&account.uid),
            "and its account must still be spendable for the next channel it opens"
        );
    }

    /// The sweep is WIRED IN: `reap` -- the same pass that already ages
    /// nonces out -- is what calls it, so a login that never became real
    /// goes even if nothing else ever happens on either seam. The three
    /// tests above pin the rule; this pins that the rule runs, which no
    /// direct call to `sweep_expired_logins` can.
    ///
    /// The one place here that must age its entry BACKWARD, since `reap`
    /// reads the clock itself -- the same `checked_sub` the nonce-lifetime
    /// tests use, over the same 30 seconds.
    #[test]
    fn reap_sweeps_a_login_that_never_became_real() {
        let account = my_account();
        let provisional = [5u8; 16];
        let established = [6u8; 16];
        let created_at = Instant::now()
            .checked_sub(LOGIN_GRACE)
            .expect("LOGIN_GRACE fits before now in this test run");
        let mut state = filled_state(&account, 0);
        state.logins = HashMap::from([
            (provisional, login_entry(&account, created_at, false, &[])),
            (established, login_entry(&account, created_at, true, &[])),
        ]);
        let (sock, _stub) = super::channel::pair().expect("socketpair");

        reap(&sock, &mut state);
        let (logins, verified) = (state.logins, state.verified);

        assert!(
            !logins.contains_key(&provisional),
            "reap's own pass must expire a login that never became real -- the sweep has to be \
             reachable from the loop, not only from its own unit test"
        );
        assert!(
            logins.contains_key(&established),
            "and must leave an established one of the same age alone"
        );
        assert!(
            verified.contains_key(&account.uid),
            "the established login keeps the account verified"
        );
    }

    /// Fix round 2's Critical: the age sweep removes login entries, and it
    /// has to ask whether a start of the login is still in flight. A login
    /// whose FIRST `Open` is still between its fork and its verdict is
    /// provisional -- `established` is only set when that verdict lands --
    /// so without the predicate the
    /// sweep drops it, and `forget_login` takes the account's verification
    /// with it: the channel then opens live, with no login entry at all,
    /// for an account the helper no longer trusts.
    ///
    /// Aged FORWARD (the entry is created at `origin`, the sweep runs at
    /// `origin + LOGIN_GRACE`) like the other boundary tests, so it cannot
    /// depend on the machine having been up longer than the age under test.
    #[test]
    fn a_login_whose_first_open_is_still_starting_is_not_swept() {
        let account = my_account();
        let login = [21u8; 16];
        let origin = Instant::now();
        let mut state = filled_state(&account, 0);
        // The entry a `Request::Verify` left behind, already old enough to
        // be swept, with no channel of its own yet.
        state
            .logins
            .insert(login, login_entry(&account, origin, false, &[]));

        // Its first `Open`, forked and still starting: `slow_become_account`
        // keeps the child a whole second short of its `exec`, so the sweep
        // below runs squarely inside the start window.
        let seam = DirectSeam::new();
        seam.serve(
            &mut state,
            &open_request(1, account.uid.as_raw(), login),
            &test_config(),
            slow_become_account,
        );
        assert!(
            matches!(state.live.get(&1), Some(ChannelSlot::Starting(_))),
            "setup: the start must be in flight when the sweep runs"
        );
        assert!(
            !state
                .logins
                .get(&login)
                .expect("setup: the entry is on file")
                .established,
            "setup: a login whose first Open has not reported yet is still provisional"
        );

        let (sock, _far) = quiet_seam();
        sweep_expired_logins(&sock, &mut state, origin + LOGIN_GRACE);

        assert!(
            state.logins.contains_key(&login),
            "a login whose first Open is still starting must not be swept -- its channel is \
             about to open and would have no entry at all"
        );
        assert!(
            state.verified.contains_key(&account.uid),
            "and its account must keep its verification, or the next Open of a live session is \
             refused as unauthenticated"
        );

        // And the channel really does open into the entry that survived.
        seam.settle(&mut state, &test_config());
        let (opened, master) = answer_to_or_fail(&seam.worker, 1, "the channel must still open");
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        assert!(
            master.is_some(),
            "an opened channel comes with its terminal"
        );
        assert_eq!(
            state.logins.get(&login).map(|l| &l.channels),
            Some(&HashSet::from([1u64])),
            "the channel must land in the login entry the sweep spared"
        );

        // The shell behind this channel is the MONITOR's child, and
        // nothing here runs the loop that reaps monitors: end it by hand,
        // or the test binary keeps both.
        stop_monitors(&mut state);
    }

    /// The NONCE sweep is wired into `reap` too -- this is the twin of
    /// `reap_sweeps_a_login_that_never_became_real`, and the older of the
    /// two sweeps never had one.
    ///
    /// `sweep_expired_nonces_uses_an_inclusive_boundary` pins the RULE by
    /// calling the sweep directly, so deleting the call from `reap` left the
    /// whole suite green. What that costs is a permanent, daemon-wide denial
    /// of authentication: a nonce issued and then neither spent nor released
    /// -- a client that vanishes mid-handshake, a dropped datagram, a worker
    /// that stops calling back -- would stay for ever, and `issue_nonce`
    /// refuses rather than evicts at [`MAX_OUTSTANDING_NONCES`]
    /// (deliberately: evicting would let a flood invalidate honest clients'
    /// nonces), so 256 of them answer every later `Request::Nonce` with
    /// `NonceUnavailable` and no client completes a handshake on that daemon
    /// again until it restarts. That is exactly the failure round 2's
    /// Critical closed for the login table, on the table beside it, and
    /// `NONCE_LIFETIME`'s own docs claim this sweep as the reason the table
    /// "cannot grow without bound on a daemon nobody logs into
    /// successfully".
    ///
    /// Also pins that the sweep REMOVES what has aged out rather than
    /// CLEARING the table: a nonce issued now survives the same pass, or the
    /// bound would itself invalidate the nonce an honest client is still
    /// holding -- the same `remove`-versus-`clear` mistake
    /// `an_exit_drops_the_channel_from_its_logins_open_set` pins next door.
    #[test]
    fn reap_sweeps_a_nonce_nobody_spends() {
        let stale = [20u8; 16];
        let outstanding = [21u8; 16];
        let issued_at = Instant::now()
            .checked_sub(NONCE_LIFETIME)
            .expect("NONCE_LIFETIME fits before now in this test run");
        let mut state = filled_state(&my_account(), 0);
        state.nonces = HashMap::from([(stale, issued_at), (outstanding, Instant::now())]);
        let (sock, _stub) = super::channel::pair().expect("socketpair");

        reap(&sock, &mut state);
        let nonces = state.nonces;

        assert!(
            !nonces.contains_key(&stale),
            "reap's own pass must expire a nonce nobody spent -- the sweep has to be reachable \
             from the loop, not only from its own unit test"
        );
        assert!(
            nonces.contains_key(&outstanding),
            "and must leave an outstanding one alone: the sweep removes what has aged out, it \
             never clears the table an honest client is still waiting on"
        );
    }

    /// A helper running against a throwaway `authorized_keys` holding
    /// `key`, plus the worker's ends of its two seams. The account is the
    /// one this test process runs as, so `getpwnam` finds it on any
    /// machine; `permit_root` follows that account, so the suite also works
    /// when CI runs it as root. It runs with [`UNPRIVILEGED`] switches, so a
    /// channel it opens runs as this test process's own account, unchanged
    /// -- the drop itself is proven under root, with the daemon's switches,
    /// by the tests that say so.
    pub(crate) fn helper_trusting(key: &PrivateKey, permit_root: bool) -> TestHelper {
        helper_trusting_with(key, permit_root, UNPRIVILEGED)
    }

    /// [`helper_trusting`], with the switches spelled out -- for the tests
    /// about what the VERIFYING CHILD does, which need to stand something
    /// of their own in for the account lookup or the key read that child
    /// makes.
    fn helper_trusting_with(
        key: &PrivateKey,
        permit_root: bool,
        switches: AccountSwitches,
    ) -> TestHelper {
        let dir = tempfile::tempdir().expect("tempdir");
        let config = HelperConfig {
            permit_root,
            ..trusting_config(dir.path(), key)
        };
        let ((channels, auth), (helper_channels, helper_auth)) = seams_for_test();
        let thread = std::thread::spawn(move || {
            serve(
                helper_channels,
                helper_auth,
                config,
                HashMap::new(),
                switches,
            )
        });
        TestHelper {
            channels,
            auth,
            thread,
            dir,
            me: my_login(),
            // Nothing is on file yet: the proof a test sends next
            // ([`assert_admits`]) is what puts this token there.
            login: PROOF_LOGIN,
        }
    }

    /// How long [`lookup_slowly`] keeps a verifying child waiting on every
    /// lookup.
    pub(crate) const SLOW_LOOKUP: Duration = Duration::from_secs(1);

    /// Test-only `lookup`: the real answer, but only after [`SLOW_LOOKUP`]
    /// -- a directory server that answers, slowly. It runs in the verifying
    /// child, never in the loop, so the delay is that child's alone.
    fn lookup_slowly(login: &str) -> Result<Account, AccountError> {
        std::thread::sleep(SLOW_LOOKUP);
        super::account::lookup(login)
    }

    /// [`helper_trusting`], in front of an account database that takes
    /// [`SLOW_LOOKUP`] over every lookup -- for a test of what the WORKER
    /// does while several verifications are slow at once.
    pub(crate) fn helper_trusting_a_slow_database(
        key: &PrivateKey,
        permit_root: bool,
    ) -> TestHelper {
        helper_trusting_with(
            key,
            permit_root,
            AccountSwitches {
                lookup: lookup_slowly,
                ..UNPRIVILEGED
            },
        )
    }

    /// Whether this test process is root (then `me` is root, and a helper
    /// that must admit `me` has to permit root).
    pub(crate) fn running_as_root() -> bool {
        nix::unistd::Uid::current().is_root()
    }

    /// Ask the helper for a nonce, on the authentication seam.
    pub(crate) fn take_nonce(auth: &UnixStream) -> [u8; AUTH_NONCE_LEN] {
        match ask(auth, Request::Nonce) {
            Response::Nonce { nonce } => nonce,
            other => panic!("expected a nonce, got {other:?}"),
        }
    }

    /// The login token every [`proof`]-built request carries, and so the
    /// one every channel test opens its channels under: the helper opens a
    /// channel only under a login a proof put on file, so a test that
    /// admits its account through [`assert_admits`] (or has `serve` admit
    /// it, through [`helper_for`]) names this same token in its `Open`s. A
    /// fixed placeholder otherwise: none of those tests are about which
    /// device a login belongs to (that has its own tests, added for fix
    /// F2), and no two of them successfully verify two DIFFERENT accounts
    /// against the same helper, so a shared token never collides against
    /// `ensure_login`'s pairing check.
    ///
    /// `0xAA` in every byte, not zeros, so it cannot collide with
    /// [`login_token`]: that helper writes its `n` as a big-endian `u64`
    /// into the first eight bytes and leaves the rest zero, so
    /// `login_token(0)` WAS byte-identical to this constant and every
    /// `login_token(n)` has eight zero bytes at the end. A test that called
    /// `assert_admits` and then named `login_token(0)` would have had one
    /// entry where it believed it had two, and a cap count silently off by
    /// one -- latent today, but tasks 7 and 8 add login-table-aware tests,
    /// and this is far cheaper to rule out now than to diagnose then.
    pub(crate) const PROOF_LOGIN: LoginId = [0xAA; 16];

    /// The address every [`proof`]-built request says it came from -- what
    /// a login admitted through one carries, and so what its session's
    /// `PAM_RHOST` must be
    /// (`the_stack_sees_the_account_service_terminal_and_address`). A
    /// constant rather than a literal in two places, so the test cannot
    /// drift from what the proof actually sends.
    pub(crate) const PROOF_RHOST: &str = "203.0.113.7:2222";

    /// Build a proof for `login` over `hash` and `nonce`, signed with `key`,
    /// carrying [`PROOF_LOGIN`] as its device token -- see that constant's
    /// docs. A test that needs a genuine, DISTINCT device token (fix F2's
    /// own tests do) uses [`proof_for_login`] instead.
    pub(crate) fn proof(
        key: &PrivateKey,
        login: &str,
        hash: [u8; 32],
        nonce: [u8; AUTH_NONCE_LEN],
    ) -> Request {
        proof_for_login(key, login, hash, nonce, PROOF_LOGIN)
    }

    /// [`proof`], naming the device token explicitly rather than defaulting
    /// to [`PROOF_LOGIN`].
    pub(crate) fn proof_for_login(
        key: &PrivateKey,
        login: &str,
        hash: [u8; 32],
        nonce: [u8; AUTH_NONCE_LEN],
        login_id: LoginId,
    ) -> Request {
        let v2 = AuthV2 {
            login: login.to_string(),
            nonce,
        };
        let signature =
            signature::Signer::try_sign(key, &auth_challenge_v2(&hash, &v2)).expect("sign");
        Request::Verify {
            login: login.to_string(),
            public_key: encode_public_key(key.public_key()).expect("encode key"),
            signature: encode_signature(&signature).expect("encode signature"),
            handshake_hash: hash,
            nonce,
            login_id,
            // A plain, printable address: this is a test's stand-in for
            // what the worker saw, and every test that cares what becomes
            // of it names its own (`sanitized_rhost`'s tests).
            rhost: PROOF_RHOST.to_string(),
        }
    }

    /// Send a `Verify` on the authentication seam and read the verdict.
    pub(crate) fn verdict(auth: &UnixStream, request: &Request) -> Response {
        ask(auth, request.clone())
    }

    /// Send a `Verify` that must be refused and return the reason the
    /// worker was given. Every refusal must carry the same
    /// `REFUSED_REASON`: a reason that said WHICH check failed would hand
    /// the worker an account and key enumerator.
    pub(crate) fn refusal(auth: &UnixStream, request: &Request) -> String {
        match verdict(auth, request) {
            Response::Refused { reason } => reason,
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    /// An honest proof for `me` under the device token `login`, which must
    /// pass -- what puts `login` on file with the helper, and so what a test
    /// does first for every login it opens a channel under.
    fn admit_login(auth: &UnixStream, key: &PrivateKey, me: &str, login: LoginId) {
        let request = proof_for_login(key, me, [7u8; 32], take_nonce(auth), login);
        let answer = verdict(auth, &request);
        assert!(
            matches!(answer, Response::Verified { .. }),
            "setup: an honest proof for {me} must pass, got {answer:?}"
        );
    }

    /// Positive control: an honest proof for `login`, on this same helper,
    /// must pass. Every refusal test calls it first, so a refusal can never
    /// be put down to a helper that refuses everything -- a broken key
    /// reader, a broken signature check, an account that does not resolve.
    pub(crate) fn assert_admits(auth: &UnixStream, key: &PrivateKey, login: &str) {
        let honest = proof(key, login, [7u8; 32], take_nonce(auth));
        assert!(
            matches!(verdict(auth, &honest), Response::Verified { .. }),
            "control: an honest proof for {login} must pass, or the refusal that follows \
             proves nothing"
        );
    }

    /// A verification that hangs -- a home directory that never answers --
    /// must not stop the helper: channels and nonces keep working, and the
    /// hung proof is refused at its own deadline.
    #[test]
    fn a_hung_verification_does_not_stop_the_helper() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = make_fifo_nobody_writes_to(dir.path());
        HUNG_KEYS_FIFO
            .set(fifo)
            .expect("only one test in this binary uses the hanging reader");
        let switches = AccountSwitches {
            read_keys: read_keys_from_the_fifo,
            ..UNPRIVILEGED
        };
        let config = HelperConfig {
            verify_timeout: Duration::from_millis(200),
            ..test_config()
        };
        // Admitted up front, under `PROOF_LOGIN`, so the `Open` below is
        // about the loop being free -- not about a login nobody proved,
        // which is refused before any fork.
        let h = helper_for(my_account(), config, switches);
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");

        let hung = proof_for_login(&key, &h.me, [7u8; 32], take_nonce(&h.auth), [5u8; 16]);
        let hung_id = tell(&h.auth, hung); // will hang in the child

        let started = Instant::now();
        let (opened, fd) = open_result_with_fd(&h.channels, 1, my_uid(), PROOF_LOGIN);
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        assert!(fd.is_some());
        assert!(
            started.elapsed() < Duration::from_millis(300),
            "the channel seam waited {:?} for a hung verification",
            started.elapsed()
        );

        // The hung proof is answered, answered as a refusal, and answered
        // under ITS OWN request number -- not some later answer picked up
        // blind.
        let answer = next_answer(&h.auth);
        assert_eq!(
            answer.id, hung_id,
            "the refusal must carry the hung request's own number"
        );
        assert!(
            matches!(&answer.body, Response::Refused { reason } if reason == REFUSED_REASON),
            "got {:?}",
            answer.body
        );
        h.stop();
    }

    /// One nonce, two proofs racing: whichever child answers first, the
    /// other must be refused -- the nonce was spent before either fork.
    ///
    /// Both requests go out before either answer is read: if the nonce were
    /// spent in the CHILD, each child would find it unspent in its own
    /// inherited copy of the table and both would admit.
    ///
    /// The answers are matched to their questions BY NUMBER, never read
    /// blind. The second proof is refused on the loop (its `spend_nonce`
    /// fails before anything forks) while the first is still waiting for
    /// its child, so the refusal usually arrives FIRST -- a blind read
    /// would hand one request's answer to the other and this test would
    /// pass or fail by timing.
    #[test]
    fn two_proofs_over_one_nonce_cannot_both_be_verified() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let nonce = take_nonce(&h.auth);
        // Two different handshakes, the same nonce -- exactly what a
        // taken-over worker would try.
        let first = proof_for_login(&key, &h.me, [7u8; 32], nonce, [1u8; 16]);
        let second = proof_for_login(&key, &h.me, [8u8; 32], nonce, [2u8; 16]);

        let first_id = tell(&h.auth, first);
        let second_id = tell(&h.auth, second);

        let mut answers = HashMap::new();
        for _ in 0..2 {
            let answer = next_answer(&h.auth);
            answers.insert(answer.id, answer.body);
        }
        let first_answer = answers
            .remove(&first_id)
            .expect("the first proof must be answered under its own number");
        let second_answer = answers
            .remove(&second_id)
            .expect("the second proof must be answered under its own number");

        let admitted = [&first_answer, &second_answer]
            .into_iter()
            .filter(|body| matches!(body, Response::Verified { .. }))
            .count();
        assert_eq!(
            admitted, 1,
            "exactly one proof may spend one nonce, got {first_answer:?} and {second_answer:?}"
        );
        h.stop();
    }

    /// The verifying child holds NOTHING it inherited: not either seam, not
    /// the master side of a channel that is still starting, not another
    /// pending child's report pipe -- only its own report pipe and the
    /// three standard descriptors.
    ///
    /// It never execs, so `O_CLOEXEC` does nothing for it: an explicit
    /// sweep is the only thing that closes any of this. Closing "both
    /// seams" is not enough, and this test process -- which holds plenty
    /// besides -- is what makes the difference visible.
    #[test]
    fn the_verifying_child_holds_no_seam() {
        let dir = tempfile::tempdir().expect("tempdir");
        let listing = dir.path().join("descriptors");
        FD_LISTING_PATH
            .set(listing.clone())
            .expect("only one test in this binary records descriptors");
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let switches = AccountSwitches {
            read_keys: read_keys_recording_descriptors,
            ..UNPRIVILEGED
        };
        let h = helper_trusting_with(&key, running_as_root(), switches);

        // The proof has to get PAST the signature check to reach
        // `read_keys` at all, so it is a genuine one for this account.
        let request = proof_for_login(&key, &h.me, [7u8; 32], take_nonce(&h.auth), [3u8; 16]);
        assert_eq!(
            refusal(&h.auth, &request),
            REFUSED_REASON,
            "setup: this stand-in reader records and then refuses"
        );

        let text = std::fs::read_to_string(&listing)
            .expect("the child must have recorded its descriptors");
        let held: Vec<(i32, String)> = text
            .lines()
            .filter_map(|line| {
                let (number, target) = line.split_once(' ')?;
                Some((number.parse::<i32>().ok()?, target.to_string()))
            })
            .collect();
        // The directory handle `read_dir` opened to produce this listing
        // appears in it. It survived nothing: it was created afterwards.
        let inherited: Vec<&(i32, String)> = held
            .iter()
            .filter(|(number, _)| *number > 2)
            .filter(|(_, target)| !target.contains("/fd"))
            .collect();
        assert_eq!(
            inherited.len(),
            1,
            "the verifying child must hold exactly one descriptor besides the standard three -- \
             its own report pipe. It held: {held:?}"
        );
        assert!(
            inherited[0].1.starts_with("pipe:"),
            "and that one must be the report pipe, not a seam or a terminal: {:?}",
            inherited[0]
        );
        h.stop();
    }

    /// The verdict carries the WHOLE account, and `verified` gets exactly
    /// what the child resolved -- never a second `account::lookup` run in
    /// the parent.
    ///
    /// The child's name service answers with an account whose gid, home,
    /// shell and supplementary groups all differ from what `getpwnam`
    /// would say for this login. A parent that looked the name up again on
    /// the loop would store that other answer instead -- undoing the whole
    /// point of the fork, and leaving a later channel to drop to the wrong
    /// gid with the wrong groups.
    #[test]
    fn the_verdict_carries_the_whole_account() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let switches = AccountSwitches {
            lookup: lookup_a_distinctive_account,
            ..UNPRIVILEGED
        };
        let fake = distinctive_account();
        assert_ne!(
            fake,
            my_account(),
            "precondition: the child's account must differ from what getpwnam answers, or this \
             test cannot tell the two apart"
        );

        let mut state = empty_state();
        let seam = DirectSeam::new();
        // Through the real issuing path, so the nonce is one this state
        // really holds.
        seam.serve_auth(&mut state, Request::Nonce, &config, switches);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        // Signed for this process's own login, so that a parent re-running
        // the lookup would get a real -- and different -- account back,
        // rather than failing to resolve at all.
        let request = proof_for_login(&key, &my_login(), [7u8; 32], nonce, [9u8; 16]);
        let id = seam.serve_auth(&mut state, request, &config, switches);
        seam.settle(&mut state, &config);

        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the verdict must carry its request's number");
        assert!(
            matches!(answer.body, Response::Verified { .. }),
            "setup: this proof must verify, got {:?}",
            answer.body
        );

        let stored = state
            .verified
            .get(&fake.uid)
            .expect("the verified account must be on file");
        assert_eq!(
            *stored, fake,
            "`verified` must hold exactly the account the CHILD resolved -- gid, home, shell and \
             supplementary groups included -- never one the parent looked up again"
        );
    }

    /// A verifying child that dies without writing a verdict is a REFUSAL,
    /// never an admission.
    ///
    /// End-of-file with nothing in it is byte-identical to what a
    /// successful `execve` leaves on a channel's startup-report pipe, where
    /// it means success. Here it can only mean the child died before it had
    /// checked anything -- so the account must not end up verified either,
    /// which the `Open` below is what actually proves.
    #[test]
    fn a_verifying_child_that_dies_without_a_verdict_is_refused() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let switches = AccountSwitches {
            read_keys: read_keys_killing_this_process,
            ..UNPRIVILEGED
        };
        let h = helper_trusting_with(&key, running_as_root(), switches);

        let login = [6u8; 16];
        let request = proof_for_login(&key, &h.me, [7u8; 32], take_nonce(&h.auth), login);
        assert_eq!(
            refusal(&h.auth, &request),
            REFUSED_REASON,
            "a child that ended without a verdict must be refused, never admitted"
        );

        // And nothing was admitted: an `Open` for that uid is refused for
        // the one reason that says the account never authenticated at all.
        let over = open_result(&h.channels, 1, my_uid(), login);
        assert!(
            matches!(&over, Response::Failed { reason, .. } if reason == UNVERIFIED_ACCOUNT_REASON),
            "a child that died before checking anything must leave its account unverified, \
             got {over:?}"
        );
        h.stop();
    }

    /// A verification that outlives its deadline is KILLED, not merely
    /// refused -- and the child is handed to `reap` to bury.
    ///
    /// Left alive it would be a forked copy of the privileged helper,
    /// sitting in somebody else's file system for ever, answering nobody.
    /// Checked on the PROCESS, not on the answer: `waitpid` must report it
    /// signalled.
    #[test]
    fn a_verification_that_outlives_its_deadline_is_killed_and_refused() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = HelperConfig {
            // Short enough to keep this test cheap, long enough that a
            // loaded machine still gets the fork itself done inside it.
            verify_timeout: Duration::from_millis(300),
            // Deliberately far longer than the verification budget AND longer
            // than the whole test budget (`TEST_RECV_TIMEOUT`, 10s): an entry
            // that took its deadline from the wrong field (`startup_timeout`
            // rather than `verify_timeout`) would not expire within that
            // budget, so this test would fail inside `DirectSeam::settle`, on
            // its "outlived the whole test budget" assertion -- before any of
            // the assertions below run, and with the child still asleep for
            // whoever ran that control to reap.
            startup_timeout: Duration::from_secs(30),
            ..trusting_config(dir.path(), &key)
        };
        let switches = AccountSwitches {
            read_keys: read_keys_that_never_finishes,
            ..UNPRIVILEGED
        };

        let mut state = empty_state();
        let seam = DirectSeam::new();
        seam.serve_auth(&mut state, Request::Nonce, &config, switches);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(&key, &my_login(), [7u8; 32], nonce, [8u8; 16]);
        let id = seam.serve_auth(&mut state, request, &config, switches);
        assert_eq!(
            state.pending.poll_fds().len(),
            1,
            "setup: the verification must be waiting on a child of its own"
        );

        seam.settle(&mut state, &config);

        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the refusal must carry its request's number");
        assert!(
            matches!(&answer.body, Response::Refused { reason } if reason == REFUSED_REASON),
            "got {:?}",
            answer.body
        );
        assert!(
            !state.verified.contains_key(&my_uid()),
            "a proof nobody ever finished checking must admit nobody"
        );
        let child = *state
            .orphans
            .first()
            .expect("the child is left for `reap` to bury, never waited for here");
        assert_killed_and_reaped(
            child,
            "a verification that outlived its deadline must be killed, not merely refused",
        );
    }

    /// A proof whose nonce is already spent must not merely be REFUSED on the
    /// wire -- it must never reach a verification at all. Nothing in the child
    /// re-checks the nonce (`verify_proof_after_nonce` has no nonce table, by
    /// design), so a fall-through on this path would verify a replay and admit
    /// its account while the worker is being told "refused".
    #[test]
    fn a_replayed_nonce_never_reaches_a_verification() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seam = DirectSeam::new();

        seam.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        let request = proof_for_login(&key, &my_login(), [7u8; 32], nonce, [11u8; 16]);

        // First presentation: honest, and it spends the nonce.
        let first = seam.serve_auth(&mut state, request.clone(), &config, UNPRIVILEGED);
        seam.settle(&mut state, &config);
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, first);
        assert!(
            matches!(answer.body, Response::Verified { .. }),
            "setup: the first presentation must be admitted, got {:?}",
            answer.body
        );
        state.verified.clear();
        state.logins.clear();

        // The replay: the same proof over the same, now-spent nonce.
        let replay = seam.serve_auth(&mut state, request, &config, UNPRIVILEGED);
        assert_eq!(
            state.pending.poll_fds().len(),
            0,
            "a spent nonce is refused on the loop -- nothing may be forked to verify it"
        );
        seam.settle(&mut state, &config);
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(
            answer.id, replay,
            "the refusal must carry its request's number"
        );
        assert!(
            matches!(&answer.body, Response::Refused { reason } if reason == REFUSED_REASON),
            "got {:?}",
            answer.body
        );
        assert!(
            state.verified.is_empty(),
            "a replayed proof must admit nobody, however well it is signed"
        );
        assert!(state.logins.is_empty(), "and must create no login entry");
    }

    /// The number of proofs in flight is capped: past [`MAX_VERIFYING`] a
    /// further `Verify` is refused and nothing is forked for it. Because the
    /// cap is checked before `spend_nonce`, its nonce is also left as it
    /// was -- that pins the order the handler has, not a property anything
    /// else relies on; the handler's own comment says why either order would
    /// be safe.
    #[test]
    fn verify_is_capped_by_max_verifying() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let dir = tempfile::tempdir().expect("tempdir");
        let config = trusting_config(dir.path(), &key);
        let mut state = empty_state();
        let seam = DirectSeam::new();

        // Fill the pending table with MAX_VERIFYING verifications in flight --
        // synthetic entries, so this costs a handful of pipes rather than 64
        // real forks. Each holds a real report pipe, exactly as a forked one
        // would, and `verifying()` counts them the same.
        for _ in 0..MAX_VERIFYING {
            state.pending.insert(fake_verify_pending(
                Instant::now() + Duration::from_secs(60),
            ));
        }
        assert_eq!(
            state.pending.verifying(),
            MAX_VERIFYING,
            "setup: the table is full of verifications in flight"
        );

        // A real nonce, so we can watch whether the refused proof spends it.
        seam.serve_auth(&mut state, Request::Nonce, &config, UNPRIVILEGED);
        let nonce = match next_answer(&seam.worker_auth).body {
            Response::Nonce { nonce } => nonce,
            other => panic!("setup: expected a nonce, got {other:?}"),
        };
        assert!(
            state.nonces.contains_key(&nonce),
            "setup: the issued nonce is on file"
        );

        // One more proof, over that nonce, while the table is full.
        let request = proof_for_login(&key, &my_login(), [7u8; 32], nonce, [12u8; 16]);
        let id = seam.serve_auth(&mut state, request, &config, UNPRIVILEGED);

        // The state effects are checked FIRST, before any answer is read:
        // the cap refuses synchronously, so a helper that let this proof
        // through would fork a child and leave this request UNANSWERED
        // until a settle that never comes -- reading the wire first would
        // then hang the test rather than fail it on the effect that matters.
        assert_eq!(
            state.pending.verifying(),
            MAX_VERIFYING,
            "nothing may be forked past the cap: the table is no fuller than before"
        );
        assert!(
            state.nonces.contains_key(&nonce),
            "the cap is checked before the nonce is spent, so a proof refused at the cap leaves \
             the nonce table as it was"
        );

        // And only then the wire answer, which the cap sends at once.
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, id, "the refusal must carry its request's number");
        assert!(
            matches!(&answer.body, Response::Refused { reason } if reason == REFUSED_REASON),
            "a proof past MAX_VERIFYING must be refused, sharing the reason every refusal \
             carries, got {:?}",
            answer.body
        );
    }

    /// A pending `Verify` entry for the cap test above: a real report pipe
    /// nobody writes to, a pid nothing signals, and a far deadline so it does
    /// not expire mid-test.
    fn fake_verify_pending(deadline: Instant) -> Pending {
        let (report, write) = nix::unistd::pipe().expect("a pipe for the report");
        drop(write);
        Pending {
            deadline,
            what: PendingWhat::Verify {
                report,
                child: Pid::from_raw(999_999),
                id: 1,
                login: "filler".to_string(),
                login_id: [0u8; 16],
                rhost: String::new(),
            },
        }
    }

    /// The verdict codec is the privileged loop's parser for bytes another
    /// process wrote, so every shortfall must be a refusal rather than a
    /// half-parsed account -- and a whole record must survive the round trip
    /// with every field a channel later reads out of `verified`.
    #[test]
    fn a_verdict_record_round_trips_and_every_shortfall_is_refused() {
        let account = distinctive_account();
        let record = encode_verdict(&Verdict::Admitted {
            account: account.clone(),
            identity: "SHA256:whatever".to_string(),
            algorithm: "ED25519".to_string(),
        });
        match decode_verdict(&record).expect("a whole record must decode") {
            Verdict::Admitted {
                account: got,
                identity,
                algorithm,
            } => {
                assert_eq!(got, account, "every field must survive the pipe");
                assert_eq!(identity, "SHA256:whatever");
                assert_eq!(algorithm, "ED25519");
            }
            Verdict::Refused { reason, .. } => {
                panic!("expected an admission, got a refusal: {reason}")
            }
        }

        assert!(
            decode_verdict(&[]).is_none(),
            "an empty record -- a child that died before checking anything -- is never an \
             admission"
        );
        for cut in 0..record.len() {
            assert!(
                decode_verdict(&record[..cut]).is_none(),
                "a record that stops short at {cut} must refuse, not half-parse"
            );
        }
        let mut trailing = record.clone();
        trailing.push(0);
        assert!(
            decode_verdict(&trailing).is_none(),
            "trailing bytes are not the record this helper writes"
        );
        let mut wrong_outcome = record.clone();
        wrong_outcome[0] = 0xEE;
        assert!(
            decode_verdict(&wrong_outcome).is_none(),
            "an outcome byte that is neither admitted nor refused is refused"
        );
    }

    /// The codec over a REAL pipe: a whole record survives `verdict_to_pipe`
    /// then `verdict_from_pipe`, and an account too large to carry is written
    /// as a refusal rather than a truncated group list. The read cap has a
    /// test of its own, `a_well_formed_record_past_the_cap_is_refused_on_the_read`:
    /// only a WELL-FORMED over-long record lets the cap, and nothing else,
    /// decide the outcome.
    #[test]
    fn a_verdict_survives_a_real_pipe_and_its_write_bounds_hold() {
        // Round trip.
        let (read, write) = nix::unistd::pipe().expect("a pipe");
        let account = distinctive_account();
        verdict_to_pipe(
            write.as_fd(),
            &Verdict::Admitted {
                account: account.clone(),
                identity: "SHA256:pipe".to_string(),
                algorithm: "ED25519".to_string(),
            },
        );
        drop(write);
        match verdict_from_pipe(&read, Instant::now() + Duration::from_secs(5)) {
            Some(Verdict::Admitted {
                account: got,
                identity,
                algorithm,
            }) => {
                assert_eq!(got, account, "the account must survive the real pipe");
                assert_eq!(identity, "SHA256:pipe");
                assert_eq!(algorithm, "ED25519");
            }
            other => panic!(
                "a whole record must survive the pipe, got Some={}",
                other.is_some()
            ),
        }

        // An account with more groups than a record may carry is written as
        // a refusal -- never an admission with a truncated group list.
        let (read, write) = nix::unistd::pipe().expect("a pipe");
        let mut swollen = distinctive_account();
        swollen.groups = vec![Gid::from_raw(1); NGROUPS_MAX + 1];
        verdict_to_pipe(
            write.as_fd(),
            &Verdict::Admitted {
                account: swollen,
                identity: "SHA256:swollen".to_string(),
                algorithm: "ED25519".to_string(),
            },
        );
        drop(write);
        assert!(
            matches!(
                verdict_from_pipe(&read, Instant::now() + Duration::from_secs(5)),
                Some(Verdict::Refused { .. })
            ),
            "an account too large for one record must be written as a refusal, never truncated"
        );
    }

    /// The read cap refuses a record past `MAX_VERDICT_LEN` even when that
    /// record is otherwise WELL-FORMED -- the only input on which the cap,
    /// and nothing else, decides the outcome. The reader is the privileged
    /// loop, and an uncapped read there is an allocation of whatever size the
    /// writer chose.
    #[test]
    fn a_well_formed_record_past_the_cap_is_refused_on_the_read() {
        let mut huge = distinctive_account();
        huge.home = PathBuf::from("/".repeat(MAX_VERDICT_LEN));
        let oversize = encode_verdict(&Verdict::Admitted {
            account: huge,
            identity: String::new(),
            algorithm: String::new(),
        });
        assert!(
            oversize.len() > MAX_VERDICT_LEN,
            "setup: the record is past the cap"
        );
        assert!(
            decode_verdict(&oversize).is_some(),
            "control: the record is well-formed, so only the read cap can refuse it"
        );
        let (read, write) = nix::unistd::pipe().expect("a pipe");
        nix::unistd::write(write.as_fd(), &oversize).expect("write the record");
        drop(write);
        assert!(
            verdict_from_pipe(&read, Instant::now() + Duration::from_secs(5)).is_none(),
            "a record past MAX_VERDICT_LEN must be refused on the read, however well-formed"
        );
    }

    /// Writer and reader agree on the cap's edge: a record of EXACTLY
    /// `MAX_VERDICT_LEN` bytes is one the child may write, so it is one the
    /// loop must read. A `>=` on either side would refuse an honest account
    /// whose record happens to land on that length.
    #[test]
    fn a_record_exactly_at_the_cap_crosses_the_pipe() {
        let mut account = distinctive_account();
        account.home = PathBuf::new();
        let bare = encode_verdict(&Verdict::Admitted {
            account: account.clone(),
            identity: String::new(),
            algorithm: String::new(),
        })
        .len();
        account.home = PathBuf::from("/".repeat(MAX_VERDICT_LEN - bare));
        let verdict = Verdict::Admitted {
            account: account.clone(),
            identity: String::new(),
            algorithm: String::new(),
        };
        assert_eq!(
            encode_verdict(&verdict).len(),
            MAX_VERDICT_LEN,
            "setup: the record is exactly at the cap"
        );
        let (read, write) = nix::unistd::pipe().expect("a pipe");
        verdict_to_pipe(write.as_fd(), &verdict);
        drop(write);
        match verdict_from_pipe(&read, Instant::now() + Duration::from_secs(5)) {
            Some(Verdict::Admitted { account: got, .. }) => assert_eq!(got, account),
            other => panic!(
                "a record exactly at the cap must cross the pipe, got Some={}",
                other.is_some()
            ),
        }
    }

    /// A verdict that starts arriving and then stops is refused at the
    /// ENTRY'S OWN deadline, through the loop's own settling path: the loop
    /// is never parked waiting for the rest. No child at all -- the test
    /// holds the pipe's write end open with half a record in it, which is
    /// what a child whose one `write` was split past `PIPE_BUF` and which
    /// then stalled leaves behind.
    ///
    /// Pins both halves: `verdict_from_pipe` honouring the deadline it is
    /// given, and `finish_pending` handing it the entry's own. A rescue
    /// thread closes the write end after `RESCUE_AFTER`, so a regression
    /// fails the elapsed-time assertion below instead of hanging the run.
    #[test]
    fn a_verdict_that_stops_arriving_is_refused_at_its_own_deadline() {
        const BUDGET: Duration = Duration::from_millis(200);
        const RESCUE_AFTER: Duration = Duration::from_secs(4);

        let (report, write) = nix::unistd::pipe().expect("a pipe for the report");
        let whole = encode_verdict(&Verdict::Admitted {
            account: distinctive_account(),
            identity: "SHA256:partial".to_string(),
            algorithm: "ED25519".to_string(),
        });
        nix::unistd::write(write.as_fd(), &whole[..whole.len() / 2]).expect("write half a record");
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let rescue = std::thread::spawn(move || {
            let _ = done_rx.recv_timeout(RESCUE_AFTER);
            drop(write);
        });

        let mut state = empty_state();
        let seam = DirectSeam::new();
        let fd = report.as_raw_fd();
        state.pending.insert(Pending {
            deadline: Instant::now() + BUDGET,
            what: PendingWhat::Verify {
                report,
                child: Pid::from_raw(999_999),
                id: 77,
                login: "partial".to_string(),
                login_id: [13u8; 16],
                rhost: String::new(),
            },
        });

        let started = Instant::now();
        settle_ready_pending(seam.seams(), &mut state, &test_config(), &[fd]);
        let elapsed = started.elapsed();
        let _ = done_tx.send(());
        rescue.join().expect("the rescue thread");

        assert!(
            elapsed < Duration::from_secs(2),
            "a half-written verdict must be given up on at the entry's own deadline \
             ({BUDGET:?}), not waited on until its writer went away -- the loop was parked \
             for {elapsed:?}"
        );
        let answer = next_answer(&seam.worker_auth);
        assert_eq!(answer.id, 77, "the refusal must carry its request's number");
        assert!(
            matches!(&answer.body, Response::Refused { reason } if reason == REFUSED_REASON),
            "half a record is a refusal, got {:?}",
            answer.body
        );
        assert!(state.verified.is_empty(), "and admits nobody");
    }

    /// A uid stops being spendable once its last login is over: the promise
    /// of the threat model is "whoever is connected right now", not
    /// "whoever ever connected" (2b's final review, finding I3).
    #[test]
    fn the_helper_forgets_an_account_when_its_last_login_ends() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let login = [3u8; 16];

        // Positive control, and the channel this test then tears down:
        // proves the account really is spendable before the login ends, so
        // the refusal below cannot be put down to a helper that refuses
        // every `Open`. `login` is the account's ONLY login -- a second one
        // still on file would keep the account verified, and the assertion
        // below would then fail for a reason
        // `the_helper_keeps_an_account_verified_while_another_login_is_still_live`
        // pins on its own.
        admit_login(&h.auth, &key, &h.me, login);
        open_channel_for(&h.channels, 1, my_uid(), login);
        close_channel(&h.channels, 1);
        tell_login_ended(&h.auth, login);

        // The proof is gone: an `Open` for the same uid is refused now, for
        // the same reason a uid nobody ever verified is -- not merely
        // refused for some unrelated cause (a repeated id, say, or the
        // login no longer being on file, which the uid check comes before).
        let over = open_result(&h.channels, 2, my_uid(), login);
        assert!(
            matches!(&over, Response::Failed { reason, .. } if reason == UNVERIFIED_ACCOUNT_REASON),
            "after the last login ended the helper must not open a channel for that uid, \
             got {over:?}"
        );
        h.stop();
    }

    /// Ending one of TWO logins for the same account must not forget the
    /// account: the threat model's promise is whoever is connected right
    /// now, and with the second login still live, that is still true. A
    /// helper that forgot the uid on every `LoginEnded`, regardless of what
    /// else it still holds on file for that account, would pass
    /// [`the_helper_forgets_an_account_when_its_last_login_ends`] above for
    /// the wrong reason -- this is the discriminating case that test alone
    /// cannot rule out.
    #[test]
    fn the_helper_keeps_an_account_verified_while_another_login_is_still_live() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let first_login = [3u8; 16];
        let second_login = [4u8; 16];

        admit_login(&h.auth, &key, &h.me, first_login);
        open_channel_for(&h.channels, 1, my_uid(), first_login);
        close_channel(&h.channels, 1);
        admit_login(&h.auth, &key, &h.me, second_login);
        open_channel_for(&h.channels, 2, my_uid(), second_login);
        close_channel(&h.channels, 2);

        // End only the first login: the account must still be spendable
        // through the second, still-live one. Opened under `second_login`
        // itself: a channel opens only under a login a proof put on file,
        // and closing a CHANNEL never ends its login (only
        // `Request::LoginEnded` does -- see `LoopState::logins`'s own docs).
        tell_login_ended(&h.auth, first_login);
        let (still_good, fd) = open_result_with_fd(&h.channels, 3, my_uid(), second_login);
        assert!(
            matches!(still_good, Response::Opened { .. }),
            "ending one of two logins must not forget the account while the other is still \
             live, got {still_good:?}"
        );
        assert!(fd.is_some());
        close_channel(&h.channels, 3);

        // Now end the second login too: nothing keeps the account verified
        // any more.
        tell_login_ended(&h.auth, second_login);
        let over = open_result(&h.channels, 4, my_uid(), second_login);
        assert!(
            matches!(&over, Response::Failed { reason, .. } if reason == UNVERIFIED_ACCOUNT_REASON),
            "once every login has ended the account must no longer be spendable, got {over:?}"
        );
        h.stop();
    }

    /// Fix F2 (review finding on this task): a login exists for the helper
    /// from the moment its account proves itself, not only once it opens a
    /// first channel. Before this fix, a session that had verified but not
    /// yet opened anything could lose its account's verification if some
    /// OTHER login of the same account ended in that window -- an
    /// availability regression the original fix introduced, reported by
    /// this task's own review.
    #[test]
    fn a_verified_login_survives_another_logins_end_even_before_its_first_open() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let session_a = [3u8; 16];
        let session_b = [4u8; 16];

        // Session A: verifies and opens a channel -- the account's first
        // live login, the one this task's original fix already handled.
        admit_login(&h.auth, &key, &h.me, session_a);
        open_channel_for(&h.channels, 1, my_uid(), session_a);
        close_channel(&h.channels, 1);

        // Session B: a genuine Verify for the SAME account, naming its own
        // token -- but no `Open` yet. Exactly the window the review's
        // scenario describes.
        let nonce = take_nonce(&h.auth);
        let honest_b = proof_for_login(&key, &h.me, [7u8; 32], nonce, session_b);
        assert!(
            matches!(verdict(&h.auth, &honest_b), Response::Verified { .. }),
            "setup: session B's own proof must pass"
        );

        // Session A ends. Before fix F2, session B's token would not exist
        // in `logins` at all yet, so this would be the account's ONLY
        // login on file from the helper's point of view -- ending it would
        // drop the account from `verified`.
        tell_login_ended(&h.auth, session_a);

        // Session B can still open its first channel.
        let (opened, fd) = open_result_with_fd(&h.channels, 2, my_uid(), session_b);
        assert!(
            matches!(opened, Response::Opened { .. }),
            "a verified session that has not opened a channel yet must not lose its account's \
             verification when a DIFFERENT login of the same account ends, got {opened:?}"
        );
        assert!(fd.is_some());
        h.stop();
    }

    /// Fix F2's own first consequence: `MAX_LOGINS` guards the entries a
    /// `Request::Verify` creates -- since the fix for a resurrected login,
    /// the only entries there are -- so that anyone who can produce a
    /// genuine proof cannot exhaust the table through `Verify`. The proofs
    /// are checked in children, but filling the table this way still costs
    /// nothing like the 256 channel fork+exec+reap cycles an earlier
    /// version of the cap's test paid.
    ///
    /// Fix round 2 hangs a second probe off this one full table, rather
    /// than filling another: this fill is measured at 1.5s, against a
    /// whole-file suite of 6.2s. The two probes, in order:
    ///
    /// 1. A `Verify` for a NEVER-SEEN token is refused (the cap; the
    ///    pairing check cannot fire for a token with no entry to disagree
    ///    with).
    /// 2. A `Verify` for a token ALREADY ON FILE still succeeds. Without
    ///    this, making `ensure_login`'s cap refuse every token, not only a
    ///    new one, leaves probe 1 passing -- `REFUSED_REASON` is the one
    ///    reason EVERY refusal on this seam carries, deliberately -- while
    ///    every warm reattach on a daemon at the cap starts failing. That
    ///    is the roaming path.
    #[test]
    fn verify_is_capped_by_max_logins_too() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        // These entries are PROVISIONAL -- a `Verify` creates them and no
        // channel is ever opened under any of them here -- so the helper's
        // own `reap` sweeps them `LOGIN_GRACE` after each one is made. The
        // fill measures ~1.5s against a 30s grace, but this test now
        // depends on that ratio, and a machine slow enough to break it
        // would otherwise fail inside the shared `refusal()` helper with
        // "expected a refusal, got Verified" -- which points nowhere near
        // the real cause. Say so instead.
        let started = Instant::now();
        for n in 0..MAX_LOGINS {
            let nonce = take_nonce(&h.auth);
            let request = proof_for_login(&key, &h.me, [7u8; 32], nonce, login_token(n));
            assert!(
                matches!(verdict(&h.auth, &request), Response::Verified { .. }),
                "setup: filling the table with genuine verifies must succeed"
            );
        }
        let filled_in = started.elapsed();
        assert!(
            filled_in < LOGIN_GRACE / 2,
            "the fill took {filled_in:?}: these entries are provisional and the helper's own \
             reap sweeps them at {LOGIN_GRACE:?}, so the probes below would be testing a table \
             that is emptying, not a full one"
        );
        // MAX_LOGINS logins are now on file, all for this SAME account. One
        // more, for a token NEVER seen before, must be refused -- and it
        // can only be the cap that refuses it: the pairing check cannot
        // fire for a token with no entry to disagree with.
        let nonce = take_nonce(&h.auth);
        let over_the_cap = proof_for_login(&key, &h.me, [7u8; 32], nonce, login_token(MAX_LOGINS));
        assert_eq!(
            refusal(&h.auth, &over_the_cap),
            REFUSED_REASON,
            "a Verify past MAX_LOGINS must be refused, sharing the same reason as any other \
             refusal"
        );

        // Probe 2: the cap refuses a NEW login, never one already on file.
        // A warm reattach -- roaming -- re-verifies with the SAME token it
        // was admitted under (`probation.rs` passes `msg1.token`, which for
        // a reattach is the existing one), and must still pass with the
        // table full.
        let nonce = take_nonce(&h.auth);
        let already_on_file = proof_for_login(&key, &h.me, [7u8; 32], nonce, login_token(0));
        assert!(
            matches!(
                verdict(&h.auth, &already_on_file),
                Response::Verified { .. }
            ),
            "a login already on file must still verify with the table full, or roaming stops \
             working at the cap"
        );

        h.stop();
    }

    /// Fix F2's own second consequence: an entry `Request::Verify` creates,
    /// still empty because its account has not opened a channel yet, must
    /// survive an UNRELATED `Open` failure for that same login (a repeated
    /// channel id, here) -- purging it would reopen exactly the window F2
    /// exists to close, the moment some OTHER login of the same account
    /// happens to end afterward.
    #[test]
    fn a_verify_created_login_survives_an_unrelated_open_failure() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let login = [3u8; 16]; // Verify-created, must survive
        let other_login = [4u8; 16]; // a second login, ended later

        // `login` verifies but opens nothing yet -- the proof creates its
        // entry here, empty.
        let nonce = take_nonce(&h.auth);
        let honest = proof_for_login(&key, &h.me, [7u8; 32], nonce, login);
        assert!(
            matches!(verdict(&h.auth, &honest), Response::Verified { .. }),
            "setup: the honest proof for `login` must pass"
        );

        // A second, unrelated login of the same account, with an OPEN
        // channel occupying id 1 -- the collision target below.
        //
        // A channel that cannot evaporate mid-test, rather than
        // `open_channel_for`'s `true`, which exits at once: once `reap` has
        // reported that exit the id is vacant again, the collision below is
        // not refused at all, and `answer_to_or_fail` -- which filters by
        // channel ID, not by kind -- hands back that dead channel's
        // `Exited { id: 1 }` as if it were the answer to the colliding
        // `Open`. Under saturating load that is exactly what happened, four
        // times in ten runs (task 3 review, Critical 2). The premise "id 1
        // is taken" must not be decided by timing.
        admit_login(&h.auth, &key, &h.me, other_login);
        let dir = tempfile::tempdir().expect("tempdir");
        let (program, _name) = unique_program(dir.path(), "v");
        let mut occupying = open_running(1, &program);
        if let Request::Open { login: token, .. } = &mut occupying {
            *token = other_login;
        }
        super::channel::send(&h.channels, &encode(&occupying).expect("encode"), None)
            .expect("send");
        let (occupied, occupied_master) =
            answer_to_or_fail(&h.channels, 1, "setup: the occupying channel must open");
        assert!(
            matches!(occupied, Response::Opened { id: 1 }),
            "setup: got {occupied:?}"
        );
        // Held to the end of the test: dropping the master side would hang
        // the terminal up and end that process early, which is the very
        // thing this setup exists to prevent.
        let _occupied_master = occupied_master.expect("an opened channel comes with its terminal");

        // `login`'s FIRST Open collides on the occupied channel id --
        // refused for the repeated id, nothing to do with `login` itself.
        // A refusal that took the login's entry with it would leave
        // `login` unable to open anything once the other login ends.
        let (conflict, fd) = open_result_with_fd(&h.channels, 1, my_uid(), login);
        assert!(
            matches!(&conflict, Response::Failed { reason, .. }
                if reason == "a channel with this id is already open"),
            "setup: the conflict must be refused for the repeated id, got {conflict:?}"
        );
        assert!(fd.is_none());

        // End every OTHER login of this account. If `login`'s own entry
        // survived the conflict above, it is what keeps the account
        // verified now.
        close_channel(&h.channels, 1);
        tell_login_ended(&h.auth, other_login);

        let (after, fd2) = open_result_with_fd(&h.channels, 2, my_uid(), login);
        assert!(
            matches!(after, Response::Opened { .. }),
            "a login Request::Verify created must survive an unrelated Open failure elsewhere, \
             got {after:?}"
        );
        assert!(fd2.is_some());
        h.stop();
    }

    /// THE security test of this slice. The login travels under the
    /// signature precisely so that nothing standing between the client and
    /// `getpwnam` can change it -- including a worker that has been taken
    /// over. A genuine proof, signed for one name and presented under
    /// another, must be refused.
    ///
    /// The presented name has to pass every OTHER check, or the test
    /// proves nothing: it is this test's own account (it resolves, root is
    /// permitted exactly when that is who we are, and the key is listed
    /// for it), so the signature is the only thing left that can refuse.
    #[test]
    fn a_proof_signed_for_another_login_is_refused() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let me = h.me.clone();
        assert_admits(&h.auth, &key, &me);

        // Signed for somebody else, presented as `me`.
        let mut swapped = proof(&key, "someone-else", [7u8; 32], take_nonce(&h.auth));
        if let Request::Verify { login, .. } = &mut swapped {
            *login = me.clone();
        }
        assert_eq!(
            refusal(&h.auth, &swapped),
            REFUSED_REASON,
            "a signature made for one account must not admit another"
        );
        h.stop();
    }

    /// Root is refused while `permit_root` is off -- even with a genuine
    /// proof signed for "root" by a key that is listed for it. The control
    /// is the same kind of proof on a helper that permits root, so nothing
    /// but `permit_root` separates the two answers. Works under any uid: it
    /// never presents the test's own account.
    #[test]
    fn root_is_refused_while_permit_root_is_off() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let permitting = helper_trusting(&key, true);
        assert_admits(&permitting.auth, &key, "root");

        let refusing = helper_trusting(&key, false);
        let as_root = proof(&key, "root", [7u8; 32], take_nonce(&refusing.auth));
        assert_eq!(refusal(&refusing.auth, &as_root), REFUSED_REASON);

        permitting.stop();
        refusing.stop();
    }

    /// A proof is spendable once. Replaying it -- which is exactly what a
    /// compromised worker would try, having watched an honest login go past
    /// -- finds the nonce already gone. The first attempt is its own
    /// control.
    #[test]
    fn the_same_proof_cannot_be_spent_twice() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let me = h.me.clone();
        let request = proof(&key, &me, [7u8; 32], take_nonce(&h.auth));

        assert!(
            matches!(verdict(&h.auth, &request), Response::Verified { .. }),
            "the first, honest attempt must be admitted"
        );
        assert_eq!(
            refusal(&h.auth, &request),
            REFUSED_REASON,
            "the same proof must not be spendable a second time"
        );
        h.stop();
    }

    /// A proof is spent the moment the helper starts checking it, not at its
    /// first success: a refused attempt leaves nothing behind to try again
    /// with.
    /// Without this, a compromised worker holding one issued nonce could
    /// make unlimited verification attempts against it for the whole
    /// `NONCE_LIFETIME` window -- exactly what "single-use" is meant to
    /// rule out.
    #[test]
    fn a_refused_proof_still_spends_its_nonce() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let me = h.me.clone();
        assert_admits(&h.auth, &key, &me);

        let nonce = take_nonce(&h.auth);
        // Signed over another handshake, presented with this one: step 3
        // (the signature check) refuses it.
        let mut bad = proof(&key, &me, [8u8; 32], nonce);
        if let Request::Verify { handshake_hash, .. } = &mut bad {
            *handshake_hash = [7u8; 32];
        }
        assert_eq!(refusal(&h.auth, &bad), REFUSED_REASON);

        // An honest proof over the SAME nonce would pass if it were still
        // live -- it is not, because the refused attempt above already
        // spent it at step 1.
        let honest = proof(&key, &me, [7u8; 32], nonce);
        assert_eq!(
            refusal(&h.auth, &honest),
            REFUSED_REASON,
            "a refused proof must still spend its nonce"
        );
        h.stop();
    }

    /// The same property one step earlier: a proof refused because its
    /// `public_key` bytes do not even decode -- refused inside step 3,
    /// before any cryptography runs -- still spends the nonce. Pins "spent
    /// before the key is decoded," not merely "spent before the signature
    /// is checked."
    #[test]
    fn a_proof_refused_at_key_decode_still_spends_its_nonce() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let me = h.me.clone();
        assert_admits(&h.auth, &key, &me);

        let nonce = take_nonce(&h.auth);
        let mut garbled = proof(&key, &me, [7u8; 32], nonce);
        if let Request::Verify { public_key, .. } = &mut garbled {
            // Not a valid SSH wire-encoded key at all -- refused at decode,
            // before `verify_record_signature` ever reaches the crypto.
            *public_key = vec![0xFFu8; 4];
        }
        assert_eq!(refusal(&h.auth, &garbled), REFUSED_REASON);

        let honest = proof(&key, &me, [7u8; 32], nonce);
        assert_eq!(
            refusal(&h.auth, &honest),
            REFUSED_REASON,
            "a proof refused at key decode must still spend its nonce"
        );
        h.stop();
    }

    /// The nonce is spent at step 1, BEFORE the login is looked up at step
    /// 2. A proof naming an account that does not exist is refused by that
    /// lookup -- and must have consumed its nonce all the same. Otherwise a
    /// worker holding one issued nonce could spend as long as
    /// `NONCE_LIFETIME` firing proofs at it, each refused by the cheapest
    /// check there is (a name nothing resolves) and none of them costing it
    /// the nonce -- which is exactly what "single-use" is meant to rule
    /// out.
    ///
    /// The second proof is HONEST: this test's own account, a listed key, a
    /// genuine signature over the same handshake -- identical in every
    /// respect to the control at the top except for the nonce it carries.
    /// It must be refused regardless.
    #[test]
    fn a_proof_refused_for_an_unknown_login_still_spends_its_nonce() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let me = h.me.clone();
        assert_admits(&h.auth, &key, &me);

        let nonce = take_nonce(&h.auth);
        // Signed for a name no machine has: step 2 refuses it, after step 1
        // has already spent the nonce.
        let unknown = proof(&key, "definitely-no-such-account-here", [7u8; 32], nonce);
        assert_eq!(refusal(&h.auth, &unknown), REFUSED_REASON);

        let honest = proof(&key, &me, [7u8; 32], nonce);
        assert_eq!(
            refusal(&h.auth, &honest),
            REFUSED_REASON,
            "a proof refused at the login lookup must still have spent its nonce"
        );
        h.stop();
    }

    /// A nonce this helper never issued is not a nonce, however well the
    /// signature over it verifies.
    #[test]
    fn a_nonce_the_helper_never_issued_is_refused() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let me = h.me.clone();
        assert_admits(&h.auth, &key, &me);

        let forged = proof(&key, &me, [7u8; 32], [0xABu8; AUTH_NONCE_LEN]);
        assert_eq!(refusal(&h.auth, &forged), REFUSED_REASON);
        h.stop();
    }

    /// An unlisted key is refused even with a perfectly good signature and
    /// a perfectly good nonce -- the file is what decides, not the
    /// mathematics.
    #[test]
    fn a_key_that_is_not_listed_is_refused() {
        let listed = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let stranger =
            PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&listed, running_as_root());
        let me = h.me.clone();
        assert_admits(&h.auth, &listed, &me);

        let unlisted = proof(&stranger, &me, [7u8; 32], take_nonce(&h.auth));
        assert_eq!(refusal(&h.auth, &unlisted), REFUSED_REASON);
        h.stop();
    }

    // -- Two seams, and the uid gate on Open ------------------------------

    /// The loop ends when the worker closes only its end of the
    /// AUTHENTICATION seam, the channel seam still open. A worker that has
    /// lost either seam is half a service, and the helper stops rather than
    /// serve it -- in production the process then exits non-zero and the
    /// service manager restarts both halves. The wait is bounded: a helper
    /// that went on serving would spin on the hang-up forever, and this test
    /// must fail on that, not hang.
    #[test]
    fn the_helper_loop_ends_when_only_the_authentication_seam_closes() {
        let TestHelper {
            channels,
            auth,
            thread,
            ..
        } = production_helper();
        drop(auth);
        join_within(
            thread,
            "the helper loop must end once the authentication seam closes, even with the channel \
             seam still open",
        );
        drop(channels);
    }

    /// The mirror: the loop ends when only the CHANNEL seam closes, the
    /// authentication seam still open.
    #[test]
    fn the_helper_loop_ends_when_only_the_channel_seam_closes() {
        let TestHelper {
            channels,
            auth,
            thread,
            ..
        } = production_helper();
        drop(channels);
        join_within(
            thread,
            "the helper loop must end once the channel seam closes, even with the authentication \
             seam still open",
        );
        drop(auth);
    }

    /// The helper opens a channel only for an account it verified itself.
    /// Two helpers get the very same `Open`, for this test's own account:
    /// one has verified that account through a genuine `Request::Verify`
    /// first and opens the channel -- the positive control, proving the
    /// request is good in every other respect -- while the other, which
    /// never verified anyone, must refuse it, hand back no terminal, and
    /// start no process at all: the program runs under a name nothing else
    /// has, and the process table must not know that name.
    #[test]
    fn a_channel_is_opened_only_for_an_account_the_helper_verified() {
        let dir = tempfile::tempdir().expect("tempdir");
        let (program, name) = unique_program(dir.path(), "g");
        let open = open_running(1, &program);

        // Positive control first -- which also shows that a started
        // program is found in the process table under its name, and gone
        // from it once reaped.
        let verified = helper_with_me_verified();
        super::channel::send(&verified.channels, &encode(&open).expect("encode"), None)
            .expect("send");
        let (answer, master, _) = answer_to(&verified.channels, 1);
        assert!(
            matches!(answer, Response::Opened { id: 1 }) && master.is_some(),
            "control: the helper that verified this account must open its channel, got {answer:?}"
        );
        // Waited for, not assumed: `Opened` says the account's SHELL
        // exec'd, and the name below only appears once that shell in turn
        // execs the program. Asserting immediately made this test fail
        // twice in ten runs under saturating load (task 3 review, Critical
        // 2). The negative assertions further down stay immediate -- there
        // is nothing to wait for when the claim is that nothing started.
        wait_until_process_named(&name);
        super::channel::send(
            &verified.channels,
            &encode(&Request::Close { id: 1 }).expect("encode"),
            None,
        )
        .expect("send");
        let (exit, _, _) = answer_to(&verified.channels, 1);
        assert!(
            matches!(exit, Response::Exited { id: 1, .. }),
            "control: the channel must close, got {exit:?}"
        );
        verified.stop();
        // `Exited` is only sent once the process is reaped.
        assert!(
            processes_named(&name).is_empty(),
            "control: a reaped program must be gone from the process table"
        );

        // The same Open, to a helper that verified nobody.
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let unverified = helper_trusting(&key, running_as_root());
        super::channel::send(&unverified.channels, &encode(&open).expect("encode"), None)
            .expect("send");
        let (answer, fd) = next_response(&unverified.channels);
        // The REASON, not merely a refusal: the login check refuses this
        // `Open` too (no proof put its login on file here), so a bare
        // `Failed` would pass with the uid check gone.
        assert!(
            matches!(&answer, Response::Failed { id: 1, reason }
                if reason == UNVERIFIED_ACCOUNT_REASON),
            "a helper that verified nobody must refuse a channel for this account, got {answer:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        assert!(
            processes_named(&name).is_empty(),
            "a refused channel must not have started a process at all"
        );
        unverified.stop();
    }

    /// A flood of `Nonce` requests on the CHANNEL seam fills nothing. The
    /// channel seam drops authentication requests unanswered, so the table
    /// the authentication seam issues from stays as empty as it was; were
    /// the channel seam to honour them, a worker could exhaust that table --
    /// and with it every honest login -- through a door the authentication
    /// seam never sees.
    ///
    /// The flood is one request past the table's capacity, so honouring it
    /// would leave the table full. An `Open` for an account nobody verified
    /// follows it on the same seam, and its `Failed` comes back only once the
    /// helper has taken every message ahead of it -- so the check below runs
    /// strictly after the whole flood was processed. The flood goes out from
    /// a thread of its own while this one reads, so a helper that DID answer
    /// it could not wedge the test on a full socket buffer.
    #[test]
    fn a_nonce_flood_on_the_channel_seam_leaves_the_authentication_table_alone() {
        let h = production_helper();
        let flooding = h.channels.try_clone().expect("clone the channel seam");
        let flood = std::thread::spawn(move || {
            for _ in 0..=MAX_OUTSTANDING_NONCES {
                super::channel::send(&flooding, &encode(&Request::Nonce).expect("encode"), None)
                    .expect("send");
            }
            let barrier = Request::Open {
                id: 1,
                uid: me_uid(),
                login: [0u8; 16],
                cols: 80,
                rows: 24,
                term: None,
                echo: false,
                shell: false,
                command: "true".to_string(),
            };
            super::channel::send(&flooding, &encode(&barrier).expect("encode"), None)
                .expect("send");
        });
        let (barrier, _, stray) = answer_to(&h.channels, 1);
        flood.join().expect("the flooding thread");
        assert!(
            matches!(barrier, Response::Failed { id: 1, .. }),
            "the barrier is an Open for an account nobody verified, got {barrier:?}"
        );

        assert!(
            matches!(ask(&h.auth, Request::Nonce), Response::Nonce { .. }),
            "a Nonce flood on the channel seam must not fill the table the authentication seam \
             issues from"
        );
        assert!(
            stray.is_empty(),
            "the channel seam must not answer an authentication request, got {} answers, the \
             first {:?}",
            stray.len(),
            stray.first()
        );
        h.stop();
    }

    /// A `Verify` on the CHANNEL seam verifies nobody. The proof is genuine
    /// -- for this test's own account, over a nonce this very helper issued
    /// -- so the only thing wrong with it is the seam it arrives on. Were
    /// the channel seam to honour it, the `Open` that follows would be
    /// opened; it must be refused instead. The positive control then sends
    /// the same kind of proof on the authentication seam, after which the
    /// same kind of `Open` succeeds -- so the refusal can only be put down to
    /// the seam.
    #[test]
    fn a_verify_on_the_channel_seam_verifies_nobody() {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let h = helper_trusting(&key, running_as_root());
        let open = |id| Request::Open {
            id,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: false,
            shell: false,
            command: "true".to_string(),
        };

        let wrong_seam = proof(&key, &h.me, [7u8; 32], take_nonce(&h.auth));
        super::channel::send(&h.channels, &encode(&wrong_seam).expect("encode"), None)
            .expect("send");
        super::channel::send(&h.channels, &encode(&open(1)).expect("encode"), None).expect("send");
        let (answer, fd, stray) = answer_to(&h.channels, 1);
        // The REASON, not merely a refusal: the account must still be
        // unverified. The login check would refuse this `Open` on its own
        // whenever the wrong-seam `Verify` put the account in `verified`
        // without also putting the login on file, and a bare `Failed` would
        // hide exactly that.
        assert!(
            matches!(&answer, Response::Failed { id: 1, reason }
                if reason == UNVERIFIED_ACCOUNT_REASON)
                && fd.is_none(),
            "a Verify on the channel seam must not verify the account it names, got {answer:?}"
        );
        assert!(
            stray.is_empty(),
            "the channel seam must not answer a Verify, got {stray:?}"
        );

        // Positive control: the right seam.
        let right_seam = proof(&key, &h.me, [7u8; 32], take_nonce(&h.auth));
        assert!(
            matches!(verdict(&h.auth, &right_seam), Response::Verified { .. }),
            "control: the same kind of proof on the authentication seam must pass"
        );
        super::channel::send(&h.channels, &encode(&open(2)).expect("encode"), None).expect("send");
        let (answer, _master, _) = answer_to(&h.channels, 2);
        assert!(
            matches!(answer, Response::Opened { id: 2 }),
            "control: once verified on the authentication seam, the account's channel must \
             open, got {answer:?}"
        );
        h.stop();
    }

    /// An `Open` on the AUTHENTICATION seam starts nothing and gets no
    /// answer -- the mirror of the two tests above. The account is
    /// verified, so on the channel seam the same kind of request starts its
    /// program: the positive control below shows exactly that, program and
    /// all, in the process table under a name nothing else has. The request
    /// on the wrong seam must get no answer on either seam, and its own
    /// uniquely named program must never appear there.
    #[test]
    fn an_open_on_the_authentication_seam_runs_nothing() {
        let h = helper_with_me_verified();
        let (wrong, wrong_name) = unique_program(h.dir.path(), "a");
        let (right, right_name) = unique_program(h.dir.path(), "c");

        tell(&h.auth, open_running(1, &wrong));
        // Answered strictly after the `Open` above was taken off the seam:
        // an answer to that `Open`, had there been one, would come first --
        // since a channel's `Open` is answered only once the account's
        // shell has exec'd. NOT once its program has started: `Opened` says
        // nothing about that (see `Response::Opened`'s own docs), which is
        // why the positive control below waits for the program rather than
        // asserting on it.
        let nonce_id = tell(&h.auth, Request::Nonce);
        let answer = next_answer(&h.auth);
        assert_eq!(
            answer.id, nonce_id,
            "an Open on the authentication seam must get no answer there, got {answer:?}"
        );

        // Positive control: the same kind of request on the channel seam.
        super::channel::send(
            &h.channels,
            &encode(&open_running(2, &right)).expect("encode"),
            None,
        )
        .expect("send");
        let (opened, _master, stray) = answer_to(&h.channels, 2);
        assert!(
            stray.is_empty(),
            "an Open on the authentication seam must not open a channel on the other seam \
             either, got {stray:?}"
        );
        assert!(
            matches!(opened, Response::Opened { id: 2 }),
            "control: the same kind of Open on the channel seam must be opened, got {opened:?}"
        );
        // Waited for, not assumed -- the same race as in
        // `a_channel_is_opened_only_for_an_account_the_helper_verified`:
        // `Opened` says the account's SHELL exec'd, and this name appears
        // only once that shell in turn execs the program. Asserting
        // immediately failed once in ten runs under saturating load.
        wait_until_process_named(&right_name);
        assert!(
            processes_named(&wrong_name).is_empty(),
            "an Open on the authentication seam must not start a process"
        );

        super::channel::send(
            &h.channels,
            &encode(&Request::Close { id: 2 }).expect("encode"),
            None,
        )
        .expect("send");
        let (exit, _, _) = answer_to(&h.channels, 2);
        assert!(
            matches!(exit, Response::Exited { id: 2, .. }),
            "control: the channel seam's channel must close, got {exit:?}"
        );
        h.stop();
    }

    /// The helper's OWN ends of the two seams are bounded as well. It is
    /// single-threaded, so a `reply` that blocks blocks everything it does:
    /// every other session's channel, every login, the reaper. A worker
    /// that stops reading -- wedged, or taken over and doing it on
    /// purpose -- must therefore cost it one send's budget, not its whole
    /// life.
    ///
    /// The worker's receive queue is filled BEFORE the helper starts, from
    /// a second handle on the helper's own end of the channel seam, so that
    /// the first reply the helper tries has nowhere to go and nothing is
    /// ever going to make room (this test never reads that seam). The proof
    /// that the helper came back out of it is taken on the OTHER seam: a
    /// `Nonce` asked afterwards must still be answered. Control: set the
    /// helper's write timeout to `None` in `serve` -- the send then never
    /// returns and no answer ever comes.
    #[test]
    fn a_worker_that_stops_reading_costs_the_helper_a_send_not_its_loop() {
        let ((channels, auth), (helper_channels, helper_auth)) = seams_for_test();

        let filling = helper_channels
            .try_clone()
            .expect("a second handle on the helper's end");
        let filler = [0u8; 100];
        let mut queued = 0usize;
        loop {
            match nix::sys::socket::send(
                filling.as_raw_fd(),
                &filler,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(_) => queued += 1,
                Err(nix::Error::EAGAIN) => break,
                Err(e) => panic!("filling the channel seam failed after {queued} records: {e}"),
            }
            assert!(queued < 100_000, "the seam never filled");
        }
        drop(filling);

        let thread = std::thread::spawn(move || {
            serve(
                helper_channels,
                helper_auth,
                test_config(),
                HashMap::new(),
                UNPRIVILEGED,
            )
        });

        // An `Open` for an account nobody verified: answered with `Failed`,
        // into a queue with no room for it, so that send blocks until its
        // budget runs out.
        let blocked = Request::Open {
            id: 1,
            uid: me_uid(),
            login: [0u8; 16],
            cols: 80,
            rows: 24,
            term: None,
            echo: false,
            shell: false,
            command: "true".to_string(),
        };
        super::channel::send(&channels, &encode(&blocked).expect("encode"), None).expect("send");

        // Read by hand rather than through `ask`, so that a regression says
        // what it was: `ask`'s own `expect` would report a bare
        // `WouldBlock` ten seconds later and name nothing.
        let id = tell(&auth, Request::Nonce);
        let answer = match super::channel::recv(&auth) {
            Ok(Some((bytes, _fd))) => decode::<AuthResponse>(&bytes).expect("decode"),
            other => panic!(
                "the helper must go on serving the authentication seam once a send to a worker \
                 that stopped reading has given up, but that seam said {other:?} -- is the \
                 helper's own send timeout gone?"
            ),
        };
        assert_eq!(answer.id, id, "the answer must carry this request's number");
        assert!(
            matches!(answer.body, Response::Nonce { .. }),
            "the helper must answer the other seam, got {:?}",
            answer.body
        );

        drop(channels);
        drop(auth);
        join_within(
            thread,
            "the helper loop must end once its peer closes both seams",
        );
    }

    /// A `Close` on the AUTHENTICATION seam closes nothing. A channel that
    /// would otherwise run for minutes is opened on the channel seam; a
    /// `Close` for it on the wrong seam must leave it running, and the
    /// positive control -- the same `Close` on the channel seam -- then ends
    /// it at once.
    #[test]
    fn a_close_on_the_authentication_seam_closes_nothing() {
        let h = helper_with_me_verified();
        let sleeper = Request::Open {
            id: 1,
            uid: me_uid(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            command: "exec sleep 300".to_string(),
        };
        super::channel::send(&h.channels, &encode(&sleeper).expect("encode"), None).expect("send");
        // The master side, held to the end: dropping it would hang the
        // terminal up and end `sleep` by a signal of its own.
        let (opened, _master, _) = answer_to(&h.channels, 1);
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );

        tell(&h.auth, Request::Close { id: 1 });
        let nonce_id = tell(&h.auth, Request::Nonce);
        let answer = next_answer(&h.auth);
        assert_eq!(
            answer.id, nonce_id,
            "a Close on the authentication seam must get no answer there, got {answer:?}"
        );

        // Honoured, that Close would have sent `SIGHUP`, which ends `sleep`,
        // and its `Exited` would arrive within one reap pass. Five passes'
        // worth of silence says it was not.
        h.channels
            .set_read_timeout(Some(REAP_INTERVAL * 5))
            .expect("a shorter bound for the silence");
        match super::channel::recv(&h.channels) {
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!(
                "a Close on the authentication seam must not end the channel, but the channel \
                 seam said {:?}",
                other.map(|m| m.map(|(bytes, _)| decode::<Response>(&bytes).ok()))
            ),
        }
        h.channels
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("the usual bound again");

        // Positive control: the same Close, on the channel seam.
        super::channel::send(
            &h.channels,
            &encode(&Request::Close { id: 1 }).expect("encode"),
            None,
        )
        .expect("send");
        let (exit, _, _) = answer_to(&h.channels, 1);
        assert_eq!(
            exit,
            Response::Exited {
                id: 1,
                code: 128 + nix::sys::signal::Signal::SIGHUP as i32
            },
            "control: the same Close on the channel seam must end the channel"
        );
        h.stop();
    }

    // -- A channel's process runs as its account ---------------------------

    /// Whether to skip a test that needs the real drop -- see
    /// [`keep_identity`] for why nothing short of root can run it -- saying
    /// so, loudly, when it does.
    fn skip_unless_root(test: &str) -> bool {
        if running_as_root() {
            return false;
        }
        eprintln!(
            "SKIPPED {test}: the drop to another account needs root (setgroups needs \
             CAP_SETGID). Build the test binary as yourself, then run it with \
             `sudo -n <binary> helper::server:: --test-threads=1 --nocapture`."
        );
        true
    }

    /// `nobody`, as passwd has it: an unprivileged account every Linux
    /// machine has, and one the tests using it -- which run as root -- are
    /// not. Refused outright if it carries any trace of root, because then
    /// nothing these tests check could tell a drop from no drop.
    fn nobody() -> Account {
        let nobody = super::account::lookup("nobody").expect("the account `nobody` exists");
        assert!(
            !nobody.uid.is_root()
                && nobody.gid.as_raw() != 0
                && !nobody.groups.iter().any(|g| g.as_raw() == 0),
            "`nobody` must carry no trace of root, or these tests prove nothing: {nobody:?}"
        );
        nobody
    }

    /// A command channel for `account` running `command` (through the
    /// account's shell, `<shell> -c <command>`): no echo, not a login shell.
    fn open_for(id: ChannelId, account: &Account, command: &str) -> Request {
        Request::Open {
            id,
            uid: account.uid.as_raw(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: false,
            shell: false,
            command: command.to_string(),
        }
    }

    /// A shell (login-shell) channel for `account`.
    fn open_shell(id: ChannelId, account: &Account) -> Request {
        Request::Open {
            id,
            uid: account.uid.as_raw(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: true,
            command: String::new(),
        }
    }

    /// Reads a channel's terminal until the program is gone AND nothing
    /// else holds its slave side -- end-of-file, or `EIO`, which is how
    /// Linux reports a master whose slave has no descriptor left open
    /// anywhere -- bounded by [`TEST_RECV_TIMEOUT`]. `Err` carries what
    /// arrived before the deadline: a terminal that never reaches its end
    /// must fail the test reading it, not hang it.
    fn read_to_end_within(master: &mut std::fs::File) -> Result<String, String> {
        use std::io::Read;

        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        let mut seen = Vec::new();
        let mut chunk = [0u8; 1024];
        let text = |seen: &[u8]| String::from_utf8_lossy(seen).into_owned();
        loop {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return Err(text(&seen));
            };
            let timeout = PollTimeout::try_from(remaining).unwrap_or(PollTimeout::MAX);
            let mut fds = [PollFd::new(master.as_fd(), PollFlags::POLLIN)];
            match poll(&mut fds, timeout) {
                Ok(0) => return Err(text(&seen)),
                Ok(_) => {}
                Err(nix::Error::EINTR) => continue,
                Err(e) => return Err(format!("poll failed: {e}; read so far: {}", text(&seen))),
            }
            match master.read(&mut chunk) {
                Ok(0) => return Ok(text(&seen)),
                Ok(n) => seen.extend_from_slice(&chunk[..n]),
                Err(e) if e.raw_os_error() == Some(nix::libc::EIO) => return Ok(text(&seen)),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(format!("read failed: {e}; read so far: {}", text(&seen))),
            }
        }
    }

    /// Sends `request`, an `Open`, insists the channel opens, and returns
    /// everything its program printed before the terminal reached its end
    /// (see [`read_to_end_within`]).
    fn output_of(h: &TestHelper, request: &Request) -> String {
        let Request::Open { id, .. } = request else {
            panic!("output_of takes an Open, got {request:?}");
        };
        super::channel::send(&h.channels, &encode(request).expect("encode"), None).expect("send");
        let (answer, fd, _) = answer_to(&h.channels, *id);
        assert!(
            matches!(answer, Response::Opened { .. }),
            "the channel must open, got {answer:?}"
        );
        let mut master =
            std::fs::File::from(fd.expect("an opened channel hands back its terminal"));
        read_to_end_within(&mut master).unwrap_or_else(|partial| {
            panic!(
                "the terminal must reach its end once the program exits -- still open after \
                 {TEST_RECV_TIMEOUT:?}; read so far: {partial:?}"
            )
        })
    }

    /// The uid, the gid and the supplementary groups `id` printed, as
    /// numbers -- from `uid=65534(nobody) gid=65534(nogroup)
    /// groups=65534(nogroup)`.
    fn parse_id(output: &str) -> Option<(u32, u32, Vec<u32>)> {
        let line = output.lines().map(str::trim).find(|l| l.contains("uid="))?;
        let field = |key: &str| line.split_whitespace().find_map(|w| w.strip_prefix(key));
        let number = |s: &str| s.split('(').next()?.parse::<u32>().ok();
        let uid = number(field("uid=")?)?;
        let gid = number(field("gid=")?)?;
        let groups = field("groups=")?
            .split(',')
            .map(number)
            .collect::<Option<Vec<u32>>>()?;
        Some((uid, gid, groups))
    }

    /// `nobody`, but with a working shell, since a channel now runs the
    /// account's shell and `nobody`'s real one is `/usr/sbin/nologin` -- for
    /// tests that inspect the child (its ids, its terminal, where it starts)
    /// rather than the confinement the real shell provides.
    fn nobody_with_shell(shell: &str) -> Account {
        Account {
            shell: PathBuf::from(shell),
            ..nobody()
        }
    }

    /// The point of this task: a channel opened for an account runs AS that
    /// account -- its uid, its gid, and its supplementary groups and nothing
    /// else, root's least of all. Opened for `nobody`, from a helper running
    /// as root with the daemon's own switches, so a drop that never happened
    /// cannot hide behind a test that already runs as the account it asks
    /// for. The command is `id`; its output is read to the very end under a
    /// deadline, so it is whole when it is parsed.
    #[test]
    fn the_child_runs_as_the_account_the_channel_was_opened_for() {
        if skip_unless_root("the_child_runs_as_the_account_the_channel_was_opened_for") {
            return;
        }
        let nobody = nobody();
        // Precondition (M5): the runner must carry a supplementary group
        // OUTSIDE `nobody`'s list, or a `setgroups` that quietly did nothing
        // would leave the child with exactly `nobody`'s groups anyway and
        // the groups check below could not tell. Under `sudo` root carries
        // group 0, which `nobody` does not.
        let runner_groups = nix::unistd::getgroups().expect("getgroups");
        let nobody_gids: Vec<u32> = nobody.groups.iter().map(|g| g.as_raw()).collect();
        assert!(
            runner_groups
                .iter()
                .any(|g| !nobody_gids.contains(&g.as_raw())),
            "precondition: the test runner must carry a supplementary group outside `nobody`'s \
             list, or a skipped setgroups would be invisible; getgroups={runner_groups:?}, \
             nobody's groups={nobody_gids:?}"
        );

        let h = helper_for(
            nobody_with_shell("/bin/sh"),
            test_config(),
            AccountSwitches::REAL,
        );
        let output = output_of(&h, &open_for(1, &nobody, "id"));
        let (uid, gid, groups) =
            parse_id(&output).unwrap_or_else(|| panic!("`id` must print its ids, got {output:?}"));
        assert_eq!(
            uid,
            nobody.uid.as_raw(),
            "the program must run as the channel's account, not as root; `id` said {output:?}"
        );
        assert_eq!(
            gid,
            nobody.gid.as_raw(),
            "the program must run with the account's group; `id` said {output:?}"
        );
        assert!(
            !groups.contains(&0),
            "the program must not keep root's group among its groups; `id` said {output:?}"
        );
        let allowed: Vec<u32> = nobody.groups.iter().map(|g| g.as_raw()).collect();
        assert!(
            groups.iter().all(|g| allowed.contains(g)),
            "the program's groups must be the account's ({allowed:?}) and nothing else; `id` \
             said {output:?}"
        );
        h.stop();
    }

    /// A uid the helper never verified is refused, however real the
    /// account. Two helpers get the very same `Open`, for `nobody`: one has
    /// `nobody` in its verified set and opens the channel -- the control,
    /// proving the request is good in every other respect, drop included --
    /// and the other is the daemon's own entry, whose set starts empty, and
    /// must refuse it with no terminal. The refusal can then be put down
    /// neither to root nor to an account that does not exist.
    #[test]
    fn a_channel_for_an_unverified_account_is_refused() {
        if skip_unless_root("a_channel_for_an_unverified_account_is_refused") {
            return;
        }
        let nobody = nobody();
        let open = open_for(1, &nobody, "id");

        let verified = helper_for(
            nobody_with_shell("/bin/sh"),
            test_config(),
            AccountSwitches::REAL,
        );
        super::channel::send(&verified.channels, &encode(&open).expect("encode"), None)
            .expect("send");
        let (answer, master, _) = answer_to(&verified.channels, 1);
        assert!(
            matches!(answer, Response::Opened { id: 1 }) && master.is_some(),
            "control: a helper that verified `nobody` must open its channel, got {answer:?}"
        );
        verified.stop();

        let unverified = production_helper();
        super::channel::send(&unverified.channels, &encode(&open).expect("encode"), None)
            .expect("send");
        let (answer, fd) = next_response(&unverified.channels);
        assert!(
            matches!(&answer, Response::Failed { id: 1, reason } if reason == UNVERIFIED_ACCOUNT_REASON),
            "a helper that verified nobody must refuse a channel for `nobody`, got {answer:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        unverified.stop();
    }

    /// The account owns its terminal: owner its uid, group `tty` -- or the
    /// account's own group when the machine has none (`tty_gid: None`) --
    /// mode 0620. Asked of the terminal by the program itself, running as
    /// `nobody`, through its own standard input.
    #[test]
    fn the_terminal_belongs_to_the_account() {
        if skip_unless_root("the_terminal_belongs_to_the_account") {
            return;
        }
        let nobody = nobody();
        let tty = super::super::config::tty_group_named("tty").unwrap_or(Gid::from_raw(5));
        assert_ne!(tty, nobody.gid, "the two cases below must be told apart");

        // Home `/`, which `nobody` can enter, so no chdir warning lands on
        // the terminal ahead of `stat`'s one line.
        let account = Account {
            home: PathBuf::from("/"),
            ..nobody_with_shell("/bin/sh")
        };
        for (tty_gid, group) in [(Some(tty), tty), (None, nobody.gid)] {
            let config = HelperConfig {
                tty_gid,
                ..test_config()
            };
            let h = helper_for(account.clone(), config, AccountSwitches::REAL);
            let output = output_of(
                &h,
                &open_for(1, &account, "stat -L -c %u:%g:%a /proc/self/fd/0"),
            );
            assert_eq!(
                output.trim(),
                format!("{}:{group}:620", nobody.uid),
                "the terminal must belong to the account, group {group} (tty_gid {tty_gid:?}), \
                 mode 0620"
            );
            h.stop();
        }
    }

    /// The program's environment is built from the account and nothing
    /// else: `HOME`, `USER`, `LOGNAME`, `SHELL` from passwd, `PATH` the
    /// account's, `TERM` the client's, and one UTF-8 locale variable -- and
    /// not a variable more, and no key twice (M2). Nothing of the helper's
    /// own environment (this test process's: under `sudo`, root's `HOME` and
    /// `PATH`, `SUDO_USER` and the rest) may reach it.
    ///
    /// The exec target is a uniquely named link to `/usr/bin/env` set as the
    /// account's shell, run as a login shell: `env` ignores its argv0 and
    /// prints the environment execve was given, WITHOUT the extra variables
    /// (`SHLVL`, `PWD`, `_`, ...) a real shell would add on top -- so this
    /// sees exactly what the helper built.
    #[test]
    fn the_childs_environment_comes_from_passwd_and_nothing_else() {
        use std::os::unix::fs::PermissionsExt;
        if skip_unless_root("the_childs_environment_comes_from_passwd_and_nothing_else") {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("let `nobody` reach the shell");
        let (env_shell, _) = uniquely_named(dir.path(), "v", "/usr/bin/env");
        let account = Account {
            shell: env_shell.clone(),
            ..nobody()
        };
        let h = helper_for(account.clone(), test_config(), AccountSwitches::REAL);
        let mut request = open_shell(1, &account);
        if let Request::Open { term, .. } = &mut request {
            *term = Some("qsh-test-term".to_string());
        }
        let output = output_of(&h, &request);
        // A Vec, not a map (M2): a duplicated key must be visible, and
        // `getenv` would take the FIRST, a map the LAST.
        let env: Vec<(&str, &str)> = output
            .lines()
            .map(str::trim_end)
            .filter_map(|line| line.split_once('='))
            .collect();
        let value_of = |key: &str| env.iter().find(|(k, _)| *k == key).map(|(_, v)| *v);
        let count_of = |key: &str| env.iter().filter(|(k, _)| *k == key).count();

        let home = account.home.display().to_string();
        let shell = env_shell.display().to_string();
        for (key, value) in [
            ("HOME", home.as_str()),
            ("USER", account.name.as_str()),
            ("LOGNAME", account.name.as_str()),
            ("SHELL", shell.as_str()),
            ("PATH", USER_PATH),
            ("TERM", "qsh-test-term"),
        ] {
            assert_eq!(
                value_of(key),
                Some(value),
                "{key} must be the account's; the whole environment: {env:?}"
            );
            assert_eq!(
                count_of(key),
                1,
                "{key} must appear exactly once; the whole environment: {env:?}"
            );
        }

        // Whether a UTF-8 locale is there to hand on at all, decided
        // without asking the code under test: this process's own
        // environment already means UTF-8, or the host offers a UTF-8
        // locale.
        let utf8 = |name: &str| name.to_ascii_lowercase().replace('-', "").contains("utf8");
        let env_means_utf8 = ["LC_ALL", "LC_CTYPE", "LANG"]
            .iter()
            .find_map(|var| std::env::var(var).ok().filter(|v| !v.is_empty()))
            .is_some_and(|v| utf8(&v));
        let host_has_utf8 = std::process::Command::new("locale")
            .arg("-a")
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).lines().any(utf8));
        let locale: Vec<(&str, &str)> = env
            .iter()
            .copied()
            .filter(|(key, _)| matches!(*key, "LC_ALL" | "LC_CTYPE" | "LANG"))
            .collect();
        if env_means_utf8 || host_has_utf8 {
            assert!(
                locale.len() == 1 && utf8(locale[0].1) && locale[0].0 != "LC_ALL",
                "the program must be handed exactly one locale variable, a UTF-8 one and never \
                 LC_ALL (M6), got {locale:?}"
            );
        } else {
            assert!(
                locale.is_empty(),
                "no UTF-8 locale to hand on, got {locale:?}"
            );
        }

        let extra: Vec<&str> = env
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| {
                ![
                    "HOME", "USER", "LOGNAME", "SHELL", "PATH", "TERM", "LC_ALL", "LC_CTYPE",
                    "LANG",
                ]
                .contains(key)
            })
            .collect();
        assert!(
            extra.is_empty(),
            "nothing else may reach the program, but it was handed {extra:?}; the whole \
             environment: {env:?}"
        );
        h.stop();
    }

    /// The program starts in the account's home -- entered AFTER the drop,
    /// as the account, so a home the account itself may not enter is not
    /// entered for it by root: the program starts in `/` instead, and a
    /// fixed warning goes to the terminal first (M8b), as `sshd` does. The
    /// account is `nobody` with its home swapped for two directories this
    /// test makes, one it may enter and one only root may; `/bin/pwd` as its
    /// shell says where each program started.
    #[test]
    fn the_child_starts_in_its_home_only_if_the_account_may_enter_it() {
        use std::os::unix::fs::PermissionsExt;

        if skip_unless_root("the_child_starts_in_its_home_only_if_the_account_may_enter_it") {
            return;
        }
        let dir = tempfile::tempdir().expect("tempdir");
        // `nobody` must be able to reach both, so only the last step differs.
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("open the parent to everyone");
        let open = dir.path().join("open");
        let closed = dir.path().join("closed");
        for (path, mode) in [(&open, 0o755), (&closed, 0o700)] {
            std::fs::create_dir(path).expect("mkdir");
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).expect("chmod");
        }

        for (home, may_enter) in [(open.clone(), true), (closed.clone(), false)] {
            let account = Account {
                home: home.clone(),
                shell: PathBuf::from("/bin/pwd"),
                ..nobody()
            };
            let h = helper_for(account.clone(), test_config(), AccountSwitches::REAL);
            // A login shell execs `/bin/pwd`, which prints the cwd and exits.
            let output = output_of(&h, &open_shell(1, &account));
            let started_in = output
                .lines()
                .map(str::trim)
                .rfind(|l| !l.is_empty())
                .unwrap_or("");
            if may_enter {
                assert_eq!(
                    started_in,
                    home.display().to_string(),
                    "an enterable home must be where the program starts, got {output:?}"
                );
                assert!(
                    !output.contains("could not enter home directory"),
                    "an enterable home must not warn, got {output:?}"
                );
            } else {
                assert_eq!(
                    started_in, "/",
                    "an unenterable home must fall the program back to /, got {output:?}"
                );
                assert!(
                    output.contains(&format!(
                        "could not enter home directory {}",
                        home.display()
                    )),
                    "the fall back to / must be announced on the terminal (M8b), got {output:?}"
                );
            }
            h.stop();
        }
    }

    // I2/M7 (the account's shell parses every command) is pinned by
    // `the_shell_mediates_commands_the_sshd_way`, above.

    /// The drop and the exec of the account's shell need no more privilege
    /// than these five capabilities: `CAP_SETUID CAP_SETGID CAP_CHOWN
    /// CAP_AUDIT_WRITE CAP_KILL`.
    ///
    /// What this pins is the helper's own REQUIREMENT -- measured by
    /// running it with nothing else and watching it still work -- and NOT a
    /// recommendation that the packaged unit confine the helper to those
    /// five with a `CapabilityBoundingSet`. It must not be read as one. A
    /// bounding set is inherited across `fork` and preserved across
    /// `execve`, and for a setuid-root binary the file's permitted set is
    /// notionally all-ones, so every setuid-root program inside every
    /// session -- `sudo`, `su`, `passwd` -- would come out holding exactly
    /// these five and nothing else, failing at `apt`, `systemctl`, `ip` and
    /// `mount` in ways nobody would trace back to the unit. `sshd` runs
    /// without a bounding set for precisely that reason.
    ///
    /// The mechanism is `setpriv`, which for a process still running as
    /// root makes the exec below recompute the permitted and effective sets
    /// down to the set named. The `_body` then (a) opens a channel for
    /// `nobody` and sees it run as `nobody` (pins the `fchmod`-before-
    /// `fchown` order: a swap needs `CAP_FOWNER`, absent here), and (b)
    /// closes a `SIGHUP`-ignoring channel and sees it die (pins that the
    /// `SIGKILL` escalation needs, and has, `CAP_KILL`).
    #[test]
    fn the_helper_runs_under_the_units_capabilities() {
        const INNER: &str =
            "helper::server::tests::the_helper_runs_under_the_units_capabilities_body";
        if skip_unless_root("the_helper_runs_under_the_units_capabilities") {
            return;
        }
        if std::process::Command::new("setpriv")
            .arg("--help")
            .output()
            .is_err()
        {
            eprintln!(
                "SKIPPED the_helper_runs_under_the_units_capabilities: `setpriv` (util-linux) \
                 is needed to lower the process to the unit's capabilities."
            );
            return;
        }
        // The test binary itself, at its own path. `setpriv` lowers only
        // the BOUNDING set before it execs, so it is still full root when
        // it opens and executes this file -- a dev tree under a 0750 home
        // is no obstacle, and the recomputation to the five capabilities
        // happens as part of that exec, to the process that comes out of
        // it. An earlier version copied the binary to `/tmp` for a reach
        // problem that does not exist, and a panic between the copy and its
        // removal left a root-owned file behind.
        let exe = std::env::current_exe().expect("current_exe");

        let output = std::process::Command::new("setpriv")
            .arg(UNIT_BOUNDING_SET)
            .arg(&exe)
            .args([
                INNER,
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .output()
            .expect("run the body under setpriv");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stdout.contains("running 1 test\n"),
            "expected the filter to match exactly one test -- `{INNER}` renamed?\nstdout:\n\
             {stdout}\nstderr:\n{stderr}"
        );
        assert!(
            output.status.success(),
            "the helper must work with only the unit's capabilities:\nstdout:\n{stdout}\n\
             stderr:\n{stderr}"
        );
    }

    /// `setpriv`'s bounding-set argument for the packaged unit's
    /// capabilities. A control removes `+kill` from it to prove (b) needs
    /// `CAP_KILL`.
    const UNIT_BOUNDING_SET: &str = "--bounding-set=-all,+setuid,+setgid,+chown,+audit_write,+kill";

    /// Runs only via [`the_helper_runs_under_the_units_capabilities`], in a
    /// process `setpriv` has lowered to the unit's capabilities.
    #[test]
    #[ignore = "runs only via the_helper_runs_under_the_units_capabilities, under setpriv"]
    fn the_helper_runs_under_the_units_capabilities_body() {
        let nobody = nobody();

        // (a) A channel for `nobody` runs as `nobody` -- so the terminal was
        // given away (fchmod, then fchown by CAP_CHOWN) and the drop took,
        // all within the unit's set.
        let h = helper_for(
            nobody_with_shell("/bin/sh"),
            test_config(),
            AccountSwitches::REAL,
        );
        let output = output_of(&h, &open_for(1, &nobody, "id"));
        let (uid, ..) = parse_id(&output)
            .unwrap_or_else(|| panic!("(a) `id` must print its ids, got {output:?}"));
        assert_eq!(
            uid,
            nobody.uid.as_raw(),
            "(a) the channel must run as `nobody` under the unit's capabilities, got {output:?}"
        );
        h.stop();

        // (b) A SIGHUP-ignoring channel of `nobody` must still be killed:
        // the escalation is a SIGKILL from root to another uid, which needs
        // CAP_KILL.
        let h = helper_for(
            nobody_with_shell("/bin/sh"),
            test_config(),
            AccountSwitches::REAL,
        );
        let req = Request::Open {
            id: 2,
            uid: nobody.uid.as_raw(),
            login: PROOF_LOGIN,
            cols: 80,
            rows: 24,
            term: None,
            echo: true,
            shell: false,
            command: "trap '' HUP; echo ready; read x".to_string(),
        };
        super::channel::send(&h.channels, &encode(&req).expect("encode"), None).expect("send");
        let (opened, fd, _) = answer_to(&h.channels, 2);
        assert!(
            matches!(opened, Response::Opened { id: 2 }),
            "(b) got {opened:?}"
        );
        let mut master = std::fs::File::from(fd.expect("a master descriptor"));
        let seen = read_until_or_timeout(&mut master, "ready");
        assert!(
            seen.contains("ready"),
            "(b) the trap must be installed, got {seen:?}"
        );

        super::channel::send(
            &h.channels,
            &encode(&Request::Close { id: 2 }).expect("encode"),
            None,
        )
        .expect("send close");
        // Bounded, and with the reason spelled out: without `CAP_KILL` the
        // escalation's `kill` fails with `EPERM`, the channel never dies,
        // no `Exited` ever arrives, and `answer_to`'s own `recv` would
        // otherwise end this test on a bare `WouldBlock` ten seconds later
        // -- a failure that names neither the message that never came nor
        // the capability that would have produced it.
        let (exit, _) = answer_to_or_fail(
            &h.channels,
            2,
            "(b) a SIGHUP-ignoring channel of `nobody` must be SIGKILL'd, and no exit was \
             reported for it -- the escalation is a signal from root to another account's \
             process, so it needs CAP_KILL: does the set under test still grant it?",
        );
        assert_eq!(
            exit,
            Response::Exited {
                id: 2,
                code: 128 + nix::sys::signal::Signal::SIGKILL as i32
            },
            "(b) a SIGHUP-ignoring channel must be SIGKILL'd -- needs CAP_KILL"
        );
        h.stop();
    }

    /// A drop that sets the wrong group id (root's, not the account's) is
    /// caught by [`check_identity`], with no channel opened and no
    /// descriptor handed back. The other two child checks cannot catch it:
    /// the groups are the account's, and the `setuid` clears the
    /// capabilities. Control: delete the `check_identity` call in the child
    /// -- the channel then opens with the account's uid but root's group.
    #[test]
    fn a_wrong_gid_drop_is_caught_by_the_identity_check() {
        if skip_unless_root("a_wrong_gid_drop_is_caught_by_the_identity_check") {
            return;
        }
        let nobody = nobody();
        let h = helper_for(nobody_with_shell("/bin/sh"), test_config(), WRONG_GID_DROP);
        super::channel::send(
            &h.channels,
            &encode(&open_for(1, &nobody, "id")).expect("encode"),
            None,
        )
        .expect("send");
        let (answer, fd) = next_response(&h.channels);
        assert!(
            matches!(&answer, Response::Failed { id: 1, reason }
                if reason.contains("starting the channel's process failed") && reason.contains("EPERM")),
            "a wrong-gid drop must be caught (EPERM), got {answer:?}"
        );
        assert!(fd.is_none(), "a caught drop must hand back no terminal");
        h.stop();
    }

    /// A drop that keeps the capabilities across the `setuid` (as
    /// `SECBIT_NO_SETUID_FIXUP` would) is caught by [`check_no_capabilities`]
    /// -- the ids and groups are the account's, so nothing else catches it.
    /// The test switch sets `PR_SET_KEEPCAPS` before the `setuid`, which
    /// needs no privilege and `execve` clears, so it cannot leak. Control:
    /// delete the `check_no_capabilities` call -- the child then reaches its
    /// `chdir` and exec holding root's permitted set.
    #[test]
    fn a_drop_that_keeps_capabilities_is_caught() {
        if skip_unless_root("a_drop_that_keeps_capabilities_is_caught") {
            return;
        }
        let nobody = nobody();
        let h = helper_for(nobody_with_shell("/bin/sh"), test_config(), KEEP_CAPS_DROP);
        super::channel::send(
            &h.channels,
            &encode(&open_for(1, &nobody, "id")).expect("encode"),
            None,
        )
        .expect("send");
        let (answer, fd) = next_response(&h.channels);
        assert!(
            matches!(&answer, Response::Failed { id: 1, reason }
                if reason.contains("starting the channel's process failed") && reason.contains("EPERM")),
            "a capability-keeping drop must be caught (EPERM), got {answer:?}"
        );
        assert!(fd.is_none(), "a caught drop must hand back no terminal");
        h.stop();
    }

    /// A drop that sets the wrong supplementary groups (an empty list, not
    /// the account's) is caught by [`check_supplementary_groups`]. The ids
    /// are the account's and the caps are cleared, so only the groups check
    /// catches it. Control: delete the `check_supplementary_groups` call.
    #[test]
    fn a_wrong_supplementary_group_set_is_caught() {
        if skip_unless_root("a_wrong_supplementary_group_set_is_caught") {
            return;
        }
        let nobody = nobody();
        // `nobody` carries one supplementary group (its own primary), so an
        // empty list really is wrong for it -- the check has something to see.
        assert!(
            !nobody.groups.is_empty(),
            "`nobody`'s expected group list must be non-empty for this test"
        );
        let h = helper_for(
            nobody_with_shell("/bin/sh"),
            test_config(),
            EMPTY_GROUPS_DROP,
        );
        super::channel::send(
            &h.channels,
            &encode(&open_for(1, &nobody, "id")).expect("encode"),
            None,
        )
        .expect("send");
        let (answer, fd) = next_response(&h.channels);
        assert!(
            matches!(&answer, Response::Failed { id: 1, reason }
                if reason.contains("starting the channel's process failed") && reason.contains("EPERM")),
            "a wrong-groups drop must be caught (EPERM), got {answer:?}"
        );
        assert!(fd.is_none(), "a caught drop must hand back no terminal");
        h.stop();
    }

    /// A test `become_account` that sets the account's groups and root's own
    /// gid, then the account's uid -- so `check_identity` sees the gid
    /// mismatch.
    fn become_account_wrong_gid(uid: Uid, _gid: Gid, groups: &[Gid]) -> nix::Result<()> {
        nix::unistd::setgroups(groups)?;
        nix::unistd::setgid(Gid::from_raw(0))?;
        nix::unistd::setuid(uid)
    }
    const WRONG_GID_DROP: AccountSwitches = AccountSwitches {
        lookup: super::account::lookup,
        read_keys: read_keys_plainly,
        become_account: become_account_wrong_gid,
    };

    /// A test `become_account` that keeps the permitted capability set across
    /// the `setuid`, the way `SECBIT_NO_SETUID_FIXUP` would -- so
    /// `check_no_capabilities` has something to catch.
    fn become_account_keeping_caps(uid: Uid, gid: Gid, groups: &[Gid]) -> nix::Result<()> {
        nix::unistd::setgroups(groups)?;
        nix::unistd::setgid(gid)?;
        // SAFETY: `PR_SET_KEEPCAPS` sets a per-process flag, needs no
        // privilege, and is cleared by `execve`, so it cannot outlive the
        // child. This is test code, not the child of the daemon's own drop.
        if unsafe { nix::libc::prctl(nix::libc::PR_SET_KEEPCAPS, 1) } != 0 {
            return Err(Errno::last());
        }
        nix::unistd::setuid(uid)
    }
    const KEEP_CAPS_DROP: AccountSwitches = AccountSwitches {
        lookup: super::account::lookup,
        read_keys: read_keys_plainly,
        become_account: become_account_keeping_caps,
    };

    /// A test `become_account` that sets an EMPTY supplementary list instead
    /// of the account's -- so `check_supplementary_groups` catches it.
    fn become_account_empty_groups(uid: Uid, gid: Gid, _groups: &[Gid]) -> nix::Result<()> {
        nix::unistd::setgroups(&[])?;
        nix::unistd::setgid(gid)?;
        nix::unistd::setuid(uid)
    }
    const EMPTY_GROUPS_DROP: AccountSwitches = AccountSwitches {
        lookup: super::account::lookup,
        read_keys: read_keys_plainly,
        become_account: become_account_empty_groups,
    };

    /// `give_terminal` leaves the slave at mode exactly 0620, owned by the
    /// uid and group asked for. Unprivileged: the test owns the slave it
    /// just opened, so it may `fchmod` it and `fchown` it to its own uid and
    /// group with no capability. Starts from 0600 so the function's own
    /// `fchmod` is what makes it 0620 (M4). Control: drop the `fchmod`.
    #[test]
    fn give_terminal_sets_mode_0620_and_the_asked_owner() {
        use nix::sys::stat::{fchmod, fstat, Mode};
        let ws = nix::pty::Winsize {
            ws_row: 24,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        let pty = nix::pty::openpty(&ws, None).expect("openpty");
        let slave = pty.slave.as_raw_fd();
        fchmod(slave, Mode::from_bits_truncate(0o600)).expect("start from a non-0620 mode");

        give_terminal(slave, Uid::current(), Gid::current())
            .expect("an owner may chmod-then-chown to itself with no capability");

        let st = fstat(slave).expect("fstat");
        assert_eq!(st.st_mode & 0o777, 0o620, "the mode must be exactly 0620");
        assert_eq!(st.st_uid, Uid::current().as_raw(), "owner must be as asked");
        assert_eq!(st.st_gid, Gid::current().as_raw(), "group must be as asked");
    }

    /// `shell_basename` is the last path component, the whole string when
    /// there is no `/` -- what `argv[0]` is built from.
    #[test]
    fn shell_basename_is_the_last_path_component() {
        assert_eq!(shell_basename(b"/bin/bash"), b"bash");
        assert_eq!(shell_basename(b"/usr/sbin/nologin"), b"nologin");
        assert_eq!(shell_basename(b"sh"), b"sh");
        assert_eq!(shell_basename(b"/bin/"), b"");
    }

    /// Root is handed the `sbin` directories on its `PATH`; every other
    /// account is not.
    #[test]
    fn the_search_path_has_the_sbin_directories_for_root_only() {
        assert_eq!(search_path(Uid::from_raw(0)), ROOT_PATH);
        assert_eq!(search_path(Uid::from_raw(1000)), USER_PATH);
        assert_eq!(search_path(Uid::from_raw(65534)), USER_PATH);
        assert!(ROOT_PATH.contains("/usr/sbin") && !USER_PATH.contains("sbin"));
    }

    /// The check the child runs after the drop: this process IS its own
    /// ids, and nobody else's -- another uid, or another gid alone, is
    /// `EPERM`.
    #[test]
    fn the_identity_check_refuses_any_ids_but_this_processs_own() {
        let uid = Uid::current();
        let gid = Gid::current();
        assert_eq!(
            check_identity(uid, gid),
            Ok(()),
            "control: this process's own ids must pass"
        );
        let other_uid = Uid::from_raw(uid.as_raw().wrapping_add(1));
        let other_gid = Gid::from_raw(gid.as_raw().wrapping_add(1));
        assert_eq!(check_identity(other_uid, gid), Err(Errno::EPERM));
        assert_eq!(check_identity(uid, other_gid), Err(Errno::EPERM));
    }

    /// `check_supplementary_groups` compares as multisets, sorting the real
    /// list the kernel returns: this process's own groups (sorted or not)
    /// pass, an added or a missing one is `EPERM`.
    #[test]
    fn the_supplementary_group_check_compares_as_a_multiset() {
        let mut own: Vec<Gid> = nix::unistd::getgroups().expect("getgroups");
        // A buffer the size of the real list, as `open_channel` allocates.
        let mut buffer = vec![Gid::from_raw(0); own.len()];
        own.sort_unstable_by_key(|g| g.as_raw());
        assert_eq!(
            check_supplementary_groups(&own, &mut buffer),
            Ok(()),
            "control: this process's own groups, sorted, must pass"
        );

        // One more expected than the process has: the buffer is now too
        // small for the real list to differ into, and the counts cannot
        // match -- either way EPERM.
        let mut too_many = own.clone();
        too_many.push(Gid::from_raw(4_000_000));
        too_many.sort_unstable_by_key(|g| g.as_raw());
        let mut bigger = vec![Gid::from_raw(0); too_many.len()];
        assert_eq!(
            check_supplementary_groups(&too_many, &mut bigger),
            Err(Errno::EPERM),
            "a group the process does not have must be caught"
        );
    }

    // ---- the login's PAM session -------------------------------------
    //
    // Every test here runs unprivileged, against a stack it writes into a
    // temporary directory of its own and reaches through
    // `pam_start_confdir` (`HelperConfig::pam_confdir`). The real
    // `/etc/pam.d` path is exercised under root, in a container, by
    // `qshd/tests/serve_system_split.rs`.

    /// A helper whose monitors read their PAM stack from `dir` instead of
    /// `/etc/pam.d`, with this test process's own account admitted under
    /// [`PROOF_LOGIN`] -- through a REAL proof, so the login on file
    /// carries the address the worker reported, which is what becomes
    /// `PAM_RHOST`.
    ///
    /// Both seams come back: `Open`/`Close` go over the channel seam,
    /// `LoginEnded` -- the thing that ends a login, and with it its
    /// session -- over the authentication one.
    fn helper_with_pam_confdir(dir: &Path, service: &str) -> TestHelper {
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let keys = tempfile::tempdir().expect("tempdir");
        let config = HelperConfig {
            pam_service: service.to_string(),
            pam_confdir: Some(dir.to_path_buf()),
            ..trusting_config(keys.path(), &key)
        };
        let h = helper_running(config, HashMap::new(), UNPRIVILEGED, keys, PROOF_LOGIN);
        assert_admits(&h.auth, &key, &h.me);
        h
    }

    /// A stack that admits everything, for a control on the same harness.
    const PERMISSIVE_STACK: &str = "auth required pam_permit.so\n\
                                    account required pam_permit.so\n\
                                    session required pam_permit.so\n";

    /// Writes `stack` into `dir` under the name `service`.
    fn write_stack(dir: &Path, service: &str, stack: &str) {
        std::fs::write(dir.join(service), stack).expect("write the PAM stack");
    }

    /// Writes an executable `#!/bin/sh` script at `path`.
    ///
    /// A file of its own, never an inline `/bin/sh -c '...'`: Linux-PAM
    /// splits a module's arguments on whitespace and knows nothing of shell
    /// quoting, so an inline command would reach `pam_exec` as a dozen
    /// broken words. For the same reason the path must hold no whitespace;
    /// a tempdir's does not.
    fn write_script(path: &Path, body: &str) {
        std::fs::write(path, format!("#!/bin/sh\n{body}\n")).expect("write the script");
        std::fs::set_permissions(
            path,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o755),
        )
        .expect("make the script executable");
        assert!(
            !path.to_string_lossy().contains(char::is_whitespace),
            "a pam_exec script's path must hold no whitespace: {}",
            path.display()
        );
    }

    /// Waits for `path` to exist, bounded -- a marker that never appears
    /// must fail the test that wanted it, not hang the run.
    fn wait_until_exists(path: &Path, within: Duration) {
        let deadline = Instant::now() + within;
        while !path.exists() {
            assert!(
                Instant::now() < deadline,
                "{} never appeared within {within:?}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    /// The lines of `path`, trimmed -- what an appending `pam_exec` script
    /// leaves behind, one line per call.
    fn recorded_lines(path: &Path) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
            .lines()
            .map(|line| line.trim().to_string())
            .filter(|line| !line.is_empty())
            .collect()
    }

    /// A locked account is refused even with a perfect proof: the account
    /// stack decides, and `pam_deny` stands in for `usermod -L` here so the
    /// test needs no privileges.
    #[test]
    fn a_denied_account_stack_refuses_the_channel() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `pam_deny` stands in for a locked or expired account: the account
        // stack is what decides, and this test needs no privileges to say
        // so.
        write_stack(
            dir.path(),
            "qshd-test-deny",
            "auth required pam_permit.so\n\
             account required pam_deny.so\n\
             session required pam_permit.so\n",
        );
        // Positive control, from the same confdir and the same harness:
        // without it this test passes for a monitor that never reached PAM
        // at all -- a confdir that never arrived, an unreadable service
        // file, a fork that failed. Every one of those produces the same
        // refusal.
        write_stack(dir.path(), "qshd-test-permit", PERMISSIVE_STACK);
        let ok = helper_with_pam_confdir(dir.path(), "qshd-test-permit");
        let (admitted, fd) = open_result_with_fd(&ok.channels, 1, my_uid(), ok.login);
        assert!(
            matches!(admitted, Response::Opened { id: 1 }),
            "control: a pam_permit account stack must admit, or the refusal below proves \
             nothing -- got {admitted:?}"
        );
        assert!(fd.is_some());
        ok.stop();

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-deny");

        let (answer, fd) = open_result_with_fd(&h.channels, 1, my_uid(), h.login);

        assert!(
            matches!(&answer, Response::Failed { id: 1, reason } if reason == REFUSED_REASON),
            "a refused account stack must close the channel with the shared reason, got \
             {answer:?}"
        );
        assert!(fd.is_none(), "a refusal must not hand back a terminal");
        h.stop();
    }

    /// And the refusal is the END of that login, not merely of that
    /// channel: the second `Open` under the same token gets no terminal,
    /// and never reaches a monitor at all -- the account stack is asked
    /// ONCE, because by then there is no monitor and no login left to ask
    /// it for.
    ///
    /// Both halves are needed. A monitor that answered the refusal and
    /// stayed would refuse the second channel too, so "no terminal" alone
    /// passes for it -- and it would be a process still able to fork a
    /// shell outside any session, which is the whole thing `pam_acct_mgmt`
    /// was asked about. Counting the calls to the account stack is what
    /// tells the two apart: a monitor that stayed asks it a second time.
    #[test]
    fn a_refused_account_stack_ends_the_login() {
        let dir = tempfile::tempdir().expect("tempdir");
        let asked = dir.path().join("account-asked");
        let script = dir.path().join("record-account.sh");
        write_script(
            &script,
            &format!("echo $PAM_TYPE >> {a}", a = asked.display()),
        );
        write_stack(
            dir.path(),
            "qshd-test-deny",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_exec.so {s}\n\
                 account required pam_deny.so\n\
                 session required pam_permit.so\n",
                s = script.display()
            ),
        );
        // Control on the same harness, with the same recording script in
        // the same half of the stack: when the stack admits, a SECOND
        // channel of one login opens perfectly well and the account stack
        // is still asked exactly once -- so the count below measures how
        // many times the stack was consulted and not whether `pam_exec`
        // works here at all, and the refusal is not put down to a helper
        // that refuses every second channel for reasons of its own.
        let control_asked = dir.path().join("control-account-asked");
        let control_script = dir.path().join("record-control-account.sh");
        write_script(
            &control_script,
            &format!("echo $PAM_TYPE >> {a}", a = control_asked.display()),
        );
        write_stack(
            dir.path(),
            "qshd-test-permit",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_exec.so {s}\n\
                 account required pam_permit.so\n\
                 session required pam_permit.so\n",
                s = control_script.display()
            ),
        );
        let ok = helper_with_pam_confdir(dir.path(), "qshd-test-permit");
        open_channel_for(&ok.channels, 1, my_uid(), ok.login);
        open_channel_for(&ok.channels, 2, my_uid(), ok.login);
        assert_eq!(
            recorded_lines(&control_asked),
            ["account"],
            "control: two channels of one login must ask the account stack once, and it must \
             have been asked at all"
        );
        ok.stop();

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-deny");
        let (first, _fd) = open_result_with_fd(&h.channels, 1, my_uid(), h.login);
        assert!(
            matches!(&first, Response::Failed { id: 1, reason } if reason == REFUSED_REASON),
            "setup: the first channel must be refused, got {first:?}"
        );

        let (second, fd) = open_result_with_fd(&h.channels, 2, my_uid(), h.login);

        assert!(
            matches!(second, Response::Failed { id: 2, .. }),
            "a login whose account stack refused it must get no second channel either, got \
             {second:?}"
        );
        assert!(
            fd.is_none(),
            "and above all no terminal: a shell forked for it would be running outside any PAM \
             session"
        );
        assert_eq!(
            recorded_lines(&asked),
            ["account"],
            "the refusal must end the LOGIN: the second Open must find no monitor and no login \
             left, so the account stack is asked once and not once per channel"
        );
        h.stop();
    }

    /// What the session stack puts in the environment reaches the account's
    /// program: `pam_getenvlist` is merged into the environment built from
    /// passwd, and a variable `pam_env` set is visible to the shell.
    #[test]
    fn the_session_stacks_environment_reaches_the_shell() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(
            dir.path().join("env"),
            "QSHD_PAM_TEST DEFAULT=from-the-stack\n",
        )
        .expect("write");
        write_stack(
            dir.path(),
            "qshd-test-env",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_env.so conffile={} envfile=/dev/null readenv=0\n\
                 session required pam_permit.so\n",
                dir.path().join("env").display()
            ),
        );

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-env");
        let (opened, fd) =
            open_command_with_fd(&h.channels, 1, my_uid(), h.login, "echo [$QSHD_PAM_TEST]");
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        let seen = read_until_or_timeout(&mut std::fs::File::from(fd.expect("terminal")), "]");
        assert!(
            seen.contains("[from-the-stack]"),
            "pam_getenvlist must reach the child's environment, got {seen:?}"
        );
        h.stop();
    }

    /// And a variable BOTH sides set is the session stack's by the time the
    /// shell reads it: `TERM` comes from passwd (`server::child_env`) and
    /// `pam_env` redefines it, and what the shell sees is the stack's value.
    ///
    /// `sshd` merges its own `pam_getenvlist` the same way, and the
    /// alternative is not "the passwd value wins" but "it depends": the
    /// environment would carry two `TERM`s, `getenv` answers with the
    /// first, and a shell keeps the last.
    ///
    /// **What this cannot witness** is that the array handed to `execve`
    /// carries the name ONCE: a shell rebuilds its environment from
    /// `environ` into its own table, where a repeated name collapses and
    /// the LAST value wins, so `$TERM` reads the same whether the array had
    /// one entry or two. That half is
    /// `the_shell_is_handed_each_environment_name_once`'s, which reads the
    /// array itself through `/proc/$$/environ`.
    ///
    /// An earlier round of this task recorded that NO shell-mediated test
    /// could see it. That was wrong -- a shell can read its own
    /// `/proc/$$/environ` -- and it left `fork_shell`'s call to `merge_env`
    /// pinned by nothing at all.
    #[test]
    fn the_session_stacks_value_replaces_the_one_from_passwd() {
        let dir = tempfile::tempdir().expect("tempdir");
        // `TERM`, not `PATH`. Both come from passwd, but a stack that
        // redefines `PATH` leaves the shell below unable to find any
        // program at all -- and the "command not found" line it prints
        // instead happens to contain the digit an earlier draft of this
        // test looked for, so the check passed on an error message.
        std::fs::write(dir.path().join("env"), "TERM DEFAULT=from-the-stack\n").expect("write");
        write_stack(
            dir.path(),
            "qshd-test-term",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_env.so conffile={} envfile=/dev/null readenv=0\n\
                 session required pam_permit.so\n",
                dir.path().join("env").display()
            ),
        );

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-term");
        let (opened, fd) = open_command_with_fd(
            &h.channels,
            1,
            my_uid(),
            h.login,
            "printf 'TERM=[%s] END\\n' \"$TERM\"",
        );
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        let seen = read_until_or_timeout(&mut std::fs::File::from(fd.expect("terminal")), "END");
        assert!(
            seen.contains("TERM=[from-the-stack] END"),
            "a variable the session stack redefines must reach the shell as the STACK's value, \
             not as the one passwd gave, got {seen:?}"
        );
        h.stop();
    }

    /// Every direct child of this process, across all of its threads.
    ///
    /// A monitor is forked by whichever thread runs the helper's loop, so
    /// `/proc/self/task/*/children` -- and not one thread's -- is what
    /// names it. Read out of `/proc` because a monitor whose stack hangs
    /// never answers anything a test could learn its pid from.
    fn direct_children() -> Vec<Pid> {
        let mut children = Vec::new();
        let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
            return children;
        };
        for task in tasks.flatten() {
            let Ok(listed) = std::fs::read_to_string(task.path().join("children")) else {
                continue;
            };
            children.extend(
                listed
                    .split_whitespace()
                    .filter_map(|pid| pid.parse::<i32>().ok())
                    .map(Pid::from_raw),
            );
        }
        children
    }

    /// Waits, bounded, for a direct child this process did not have before,
    /// and returns it.
    fn wait_for_new_child(before: &[Pid], what: &str) -> Pid {
        let give_up_at = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            if let Some(fresh) = direct_children()
                .into_iter()
                .find(|pid| !before.contains(pid))
            {
                return fresh;
            }
            assert!(
                Instant::now() < give_up_at,
                "{what} -- no new child appeared within {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// A monitor whose PAM stack will not come back does not outlive the
    /// login it belongs to.
    ///
    /// `Session::begin` is the one place the monitor leaves its poll loop,
    /// and the loop is the only thing that notices a login ending -- the
    /// helper ends one by dropping its end of the seam
    /// ([`forget_login`]). With nothing bounding those PAM calls, a stack
    /// that hangs left a ROOT process running past the end of its own
    /// login: measured on the branch before this deadline existed, a
    /// monitor was still in state `S` two seconds after its `LoginEnded`
    /// and outlived its login by as long as the stack felt like taking.
    /// The helper cannot fix that from outside, because the only thing it
    /// can do to a monitor is kill it, and a bare kill is exactly what
    /// skips `pam_close_session`.
    ///
    /// The stack here blocks on a FIFO nobody ever writes to -- a module
    /// that is not slow but stopped, which is the case
    /// `monitor::SessionDeadline` exists for and the one no amount of
    /// waiting fixes.
    #[test]
    fn a_monitor_stuck_in_its_pam_stack_does_not_outlive_its_login() {
        // What the monitor's `session_budget` is in this test; the daemon
        // runs on `STARTUP_REPORT_TIMEOUT`, which is why it is a setting
        // rather than a constant read in the monitor.
        const BUDGET: Duration = Duration::from_millis(300);

        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("never-written-to");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .expect("mkfifo");
        // The writer is held HERE, and that is this test's whole cleanup:
        // when this frame goes -- by returning or by an assertion unwinding
        // it -- the last writer closes, the script's `read` reaches
        // end-of-file, and the script exits. A stack that hung on a sleep
        // instead would leave a process behind on every failing run.
        //
        // `O_RDWR`, not `O_WRONLY`: opening a FIFO for writing alone blocks
        // until a reader appears, and the reader is the very script this
        // has to be open before.
        let _writer = nix::fcntl::open(
            &fifo,
            nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NOCTTY,
            nix::sys::stat::Mode::empty(),
        )
        .expect("open the fifo's write end");

        let script = dir.path().join("hang.sh");
        write_script(&script, &format!("read line < {f}", f = fifo.display()));
        write_stack(
            dir.path(),
            "qshd-test-hanging-session",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_exec.so {s}\n\
                 session required pam_permit.so\n",
                s = script.display()
            ),
        );

        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let keys = tempfile::tempdir().expect("tempdir");
        let config = HelperConfig {
            pam_service: "qshd-test-hanging-session".to_string(),
            pam_confdir: Some(dir.path().to_path_buf()),
            startup_timeout: BUDGET,
            ..trusting_config(keys.path(), &key)
        };
        let h = helper_running(config, HashMap::new(), UNPRIVILEGED, keys, PROOF_LOGIN);
        assert_admits(&h.auth, &key, &h.me);

        // Sent, not waited for: this `Open` is never answered while its
        // monitor is inside the stack, so a test that waited here would
        // hang instead of measuring anything.
        let before = direct_children();
        super::channel::send(
            &h.channels,
            &encode(&open_request(1, my_uid().as_raw(), h.login)).expect("encode"),
            None,
        )
        .expect("send the Open");
        let monitor = wait_for_new_child(
            &before,
            "setup: the Open must fork a monitor, or there is nothing here to be stuck",
        );

        // And now the login ends, the only way the helper can end one.
        tell_login_ended(&h.auth, h.login);
        let ended_at = Instant::now();

        // The monitor must go, and go on its own: nothing kills it here.
        // Without the deadline it stays for as long as the stack does,
        // which for this stack is for ever.
        wait_until_process_gone(
            monitor,
            "a monitor whose PAM stack will not come back must end itself rather than outlive \
             its login as a root process with a terminal and a transaction open",
        );
        let outlived = ended_at.elapsed();
        assert!(
            outlived < TEST_RECV_TIMEOUT,
            "setup: the wait above is what bounds this, and it returned late ({outlived:?})"
        );

        h.stop();
    }

    /// A monitor stuck in the CLOSING half of its stack does not outlive
    /// its login either.
    ///
    /// The asymmetry this closes was an accident, not a decision: the guard
    /// had one call site, on the opening half, while `pam_close_session`
    /// blocks in the same modules for the same reasons -- `pam_systemd`
    /// closes a session with a synchronous round trip to logind. The danger
    /// is smaller here, since the login is over and nobody waits for an
    /// answer, but so is the rescue: the helper's own escalation
    /// (`MONITOR_GRACE_PERIOD`) needs a monitor with a channel it fails to
    /// report on, and a monitor in its close has none left. Nobody at all
    /// would end this one.
    #[test]
    fn a_monitor_stuck_closing_its_session_does_not_outlive_its_login() {
        // The opening budget; the closing one is twice it, so the monitor's
        // whole ordeal is bounded by four of these -- under two seconds.
        const BUDGET: Duration = Duration::from_millis(300);

        let dir = tempfile::tempdir().expect("tempdir");
        let fifo = dir.path().join("never-written-to");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .expect("mkfifo");
        // Held here, so that leaving this frame -- by returning or by an
        // assertion unwinding it -- releases the script. See
        // `a_monitor_stuck_in_its_pam_stack_does_not_outlive_its_login`.
        let _writer = nix::fcntl::open(
            &fifo,
            nix::fcntl::OFlag::O_RDWR | nix::fcntl::OFlag::O_NOCTTY,
            nix::sys::stat::Mode::empty(),
        )
        .expect("open the fifo's write end");

        // Only the CLOSING half hangs. The opening half must go through, or
        // there would be no session to be stuck closing -- and the channel
        // that opens below is the control that says it did.
        let script = dir.path().join("hang-on-close.sh");
        write_script(
            &script,
            &format!(
                "if [ \"$PAM_TYPE\" = close_session ]; then read line < {f}; fi",
                f = fifo.display()
            ),
        );
        write_stack(
            dir.path(),
            "qshd-test-hanging-close",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_exec.so {s}\n\
                 session required pam_permit.so\n",
                s = script.display()
            ),
        );

        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let keys = tempfile::tempdir().expect("tempdir");
        let config = HelperConfig {
            pam_service: "qshd-test-hanging-close".to_string(),
            pam_confdir: Some(dir.path().to_path_buf()),
            startup_timeout: BUDGET,
            ..trusting_config(keys.path(), &key)
        };
        let h = helper_running(config, HashMap::new(), UNPRIVILEGED, keys, PROOF_LOGIN);
        assert_admits(&h.auth, &key, &h.me);

        let before = direct_children();
        let (opened, fd) =
            open_command_with_fd(&h.channels, 1, my_uid(), h.login, "exec sleep 300");
        assert!(
            matches!(opened, Response::Opened { .. }),
            "control: the opening half of this stack must go through, or there is no session \
             to be stuck closing; got {opened:?}"
        );
        let terminal = fd.expect("control: an opened channel comes with its terminal");
        let monitor = wait_for_new_child(&before, "setup: the Open must fork a monitor");

        tell_login_ended(&h.auth, h.login);

        wait_until_process_gone(
            monitor,
            "a monitor whose stack will not come back OUT of pam_close_session must end itself: \
             nothing else ends it, since the helper's own escalation needs a channel this \
             monitor no longer has",
        );

        h.stop();
        drop(terminal);
    }

    /// And the deadline STOPS once the stack has come back: a monitor whose
    /// session opened must not be killed by the budget that was bounding
    /// the opening.
    ///
    /// The disarming half of `monitor::SessionDeadline`'s `Drop` -- two
    /// lines -- and it was the branch's own disease when it went in: remove
    /// them and this suite stayed 376 of 376, because the production budget
    /// is five seconds and no test here keeps a monitor alive that long. In
    /// the daemon the same two lines decide whether every HEALTHY monitor
    /// ends itself with `_exit(70)` about ten seconds after opening its
    /// session, taking its login and all of its shells with it.
    ///
    /// So this test runs the monitor on a budget short enough to see it,
    /// and then asks the one question that cannot be answered by a corpse:
    /// whether the login still opens channels.
    #[test]
    fn a_monitors_deadline_stops_once_its_session_is_open() {
        // Short enough that twice it, plus a margin, is under a second;
        // long enough for a real fork, `execve` and PAM stack inside it.
        const BUDGET: Duration = Duration::from_millis(300);

        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");
        let keys = tempfile::tempdir().expect("tempdir");
        let config = HelperConfig {
            startup_timeout: BUDGET,
            ..trusting_config(keys.path(), &key)
        };
        let h = helper_running(config, HashMap::new(), UNPRIVILEGED, keys, PROOF_LOGIN);
        assert_admits(&h.auth, &key, &h.me);

        let before = direct_children();
        let (opened, fd) =
            open_command_with_fd(&h.channels, 1, my_uid(), h.login, "exec sleep 300");
        assert!(
            matches!(opened, Response::Opened { .. }),
            "setup: the first channel must open -- it is what opens the session this test is \
             about; got {opened:?}"
        );
        let first_terminal = fd.expect("setup: an opened channel comes with its terminal");
        let monitor = wait_for_new_child(&before, "setup: the Open must fork a monitor");

        // Past the point at which a deadline still armed would have given
        // up and ended this process.
        std::thread::sleep(BUDGET * 2 + Duration::from_millis(250));

        assert!(
            process_is_alive(monitor),
            "a monitor whose session opened must outlive the budget that bounded the opening: \
             {monitor} is gone {:?} after its session opened, which is what an armed deadline \
             does to it",
            BUDGET * 2
        );
        let (second, fd) =
            open_command_with_fd(&h.channels, 2, my_uid(), h.login, "exec sleep 300");
        assert!(
            matches!(second, Response::Opened { .. }),
            "and it must still be SERVING its login, not merely alive; got {second:?}"
        );
        let second_terminal = fd.expect("an opened channel comes with its terminal");

        h.stop();
        drop((first_terminal, second_terminal));
    }

    /// And a monitor dies with its HELPER, which is the other half of the
    /// same hole: the worker arms a parent-death signal against the helper
    /// and every shell arms one against its monitor, and until now the
    /// monitor armed none against the helper. A helper killed while a
    /// monitor was not watching its seam therefore left a root process
    /// with an open PAM session reparented to init, across a restart of
    /// the service.
    ///
    /// Stopped with `SIGSTOP` first, which is exactly "not watching its
    /// seam" and nothing else: a running monitor would notice end-of-file
    /// when the helper's end closed and exit tidily, and the test would
    /// pass without any signal being armed at all. A stopped process can
    /// still be killed, which is why `SIGKILL` -- and not something
    /// catchable -- is what the arming asks for.
    #[test]
    fn a_monitor_dies_with_its_helper() {
        let login = [43u8; 16];
        let h = helper_with_verified([(login, my_account())]);
        let monitor = monitor_pid_behind_channel(&h.channels, 1, my_uid(), login);

        nix::sys::signal::kill(monitor, nix::sys::signal::Signal::SIGSTOP)
            .expect("setup: stopping the monitor");

        // The helper's loop runs on a thread of this process, and a
        // parent-death signal fires on the death of the parent THREAD --
        // so ending the loop is this suite's "the helper died".
        h.stop();

        assert_killed_and_reaped(
            monitor,
            "a monitor must die with the helper that forked it, even when it is in no state to \
             notice its seam close",
        );
    }

    /// The session is closed when the login ends, by the process that
    /// opened it: `pam_exec.so` in the session stack records which process
    /// ran each half, so the test can see both halves happen -- and see
    /// that the same process did both.
    #[test]
    fn the_session_is_opened_and_closed_by_the_monitor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("session-open");
        let closed_marker = dir.path().join("session-open.closed");
        // `pam_exec.so` runs once for each half of the session stack.
        // Nothing here needs privileges: the stack is `pam_permit` plus
        // `pam_exec`, and the config directory is the test's own.
        // The script records WHICH process called pam_open_session, and the
        // close half must be the same one: `pam_close_session` from any
        // other process is what the monitor exists to prevent (spec 3.3).
        // pam_exec forks and execs the script from the process that called
        // into PAM, so the script's $PPID is that process.
        let script = dir.path().join("record-session.sh");
        write_script(
            &script,
            &format!(
                "if [ \"$PAM_TYPE\" = open_session ]; then echo $PPID > {m}; \
                 else echo $PPID > {m}.closed; fi",
                m = marker.display()
            ),
        );
        write_stack(
            dir.path(),
            "qshd-test-session",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_exec.so {s}\n\
                 session required pam_permit.so\n",
                s = script.display()
            ),
        );

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-session");
        let monitor = monitor_pid_behind_channel(&h.channels, 1, my_uid(), h.login);
        assert!(
            marker.exists(),
            "pam_open_session must run before the first channel is answered"
        );

        let opened_by = std::fs::read_to_string(&marker)
            .expect("open marker")
            .trim()
            .to_string();
        assert_eq!(
            opened_by,
            monitor.to_string(),
            "pam_open_session must be called by the monitor itself, not by the helper"
        );

        tell_login_ended(&h.auth, h.login);
        wait_until_exists(&closed_marker, TEST_RECV_TIMEOUT);
        assert_eq!(
            std::fs::read_to_string(&closed_marker)
                .expect("close marker")
                .trim(),
            opened_by,
            "pam_close_session must be called by the SAME process that opened the session"
        );
        h.stop();
    }

    /// And the session is closed when the HELPER stops, not only when the
    /// login ends.
    ///
    /// This is the ordinary end of the daemon -- the worker has gone, so
    /// the helper's loop ends -- and it used to close every live login's
    /// session, because `LoopState` owns the monitors' seams and dropping
    /// them is what a monitor reads as "your login is over". Arming the
    /// parent-death signal took that away: the process exited on the heels
    /// of the drop and each monitor was `SIGKILL`ed part-way through the
    /// close it had just begun. Measured on one variable, with the same
    /// stack as `the_session_is_opened_and_closed_by_the_monitor` above:
    /// `LoginEnded` gave `Exited(0)` and `closed=true`, the helper stopping
    /// gave `Signaled(SIGKILL)` and `closed=false`.
    ///
    /// `end_the_monitors` is what puts it back, and this is what holds it.
    #[test]
    fn a_helper_that_stops_lets_its_monitors_close_their_sessions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("session-open");
        let closed_marker = dir.path().join("session-open.closed");
        let script = dir.path().join("record-session.sh");
        write_script(
            &script,
            &format!(
                "if [ \"$PAM_TYPE\" = open_session ]; then echo $PPID > {m}; \
                 else echo $PPID > {m}.closed; fi",
                m = marker.display()
            ),
        );
        write_stack(
            dir.path(),
            "qshd-test-shutdown",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_exec.so {s}\n\
                 session required pam_permit.so\n",
                s = script.display()
            ),
        );

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-shutdown");
        let monitor = monitor_pid_behind_channel(&h.channels, 1, my_uid(), h.login);
        let opened_by = std::fs::read_to_string(&marker)
            .expect("setup: pam_open_session must have run before the channel was answered")
            .trim()
            .to_string();
        assert_eq!(
            opened_by,
            monitor.to_string(),
            "setup: the monitor itself must have opened the session"
        );
        assert!(
            !closed_marker.exists(),
            "setup: and it must not be closed yet, or what follows proves nothing"
        );

        // The worker is gone: both seams drop, and the helper's loop ends.
        // Nothing here tells the login to end -- that is the other path,
        // and the one that already worked.
        h.stop();

        // Asserted straight away rather than waited for: `end_the_monitors`
        // runs INSIDE the loop's own thread, before `stop` can join it, so
        // by this line the close has either happened or run out of time.
        assert!(
            closed_marker.exists(),
            "a helper that stops must let its monitors close their logins' PAM sessions: \
             {} was never written",
            closed_marker.display()
        );
        assert_eq!(
            std::fs::read_to_string(&closed_marker)
                .expect("close marker")
                .trim(),
            opened_by,
            "and by the same process that opened it, as spec 3.3 requires"
        );
    }

    /// One login, one session, however many channels it opens -- and the
    /// same process runs both halves of it.
    ///
    /// `pam_exec` runs for each half of the session stack, and the script
    /// APPENDS, so the file is the whole sequence rather than its last
    /// step: a second session for the login's second channel would show as
    /// a second `open_session` line, and a close that never ran would show
    /// as a missing one.
    #[test]
    fn one_login_gets_one_session_however_many_channels_it_opens() {
        let dir = tempfile::tempdir().expect("tempdir");
        let calls = dir.path().join("calls");
        let script = dir.path().join("record-calls.sh");
        write_script(
            &script,
            &format!("echo \"$PAM_TYPE $PPID\" >> {c}", c = calls.display()),
        );
        write_stack(
            dir.path(),
            "qshd-test-order",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_exec.so {s}\n\
                 session required pam_permit.so\n",
                s = script.display()
            ),
        );

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-order");
        let monitor = monitor_pid_behind_channel(&h.channels, 1, my_uid(), h.login);
        // A second channel of the SAME login, opened and closed: it must
        // add nothing to the sequence at all.
        open_channel_for(&h.channels, 2, my_uid(), h.login);
        close_channel(&h.channels, 2);
        tell_login_ended(&h.auth, h.login);

        // Bounded, because what this waits for is the LAST line: the close
        // half lands after the login ends, and a wait with no bound would
        // hang the run instead of failing this test.
        wait_until_exists(&calls, TEST_RECV_TIMEOUT);
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while recorded_lines(&calls).len() < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        // And then a moment longer, with nothing expected. Stopping at the
        // second line would let `open, close, open` pass whenever the third
        // line lands after the read -- the window is narrow, but it is the
        // window a session-per-channel implementation lives in, and this
        // test is the one that has to close it. Two reap intervals is more
        // than a monitor needs to serve anything it has already been sent.
        std::thread::sleep(REAP_INTERVAL * 2);
        let recorded = recorded_lines(&calls);

        let sequence: Vec<&str> = recorded
            .iter()
            .map(|line| line.split(' ').next().unwrap_or(""))
            .collect();
        assert_eq!(
            sequence,
            ["open_session", "close_session"],
            "one login gets ONE session, opened once and closed once: {recorded:?}"
        );
        for line in &recorded {
            assert_eq!(
                line.split(' ').nth(1),
                Some(monitor.to_string().as_str()),
                "every half must be run by the login's own monitor: {recorded:?}"
            );
        }
        h.stop();
    }

    /// The credentials are established BEFORE the session opens, which is
    /// what `pam_setcred(3)` says ("before a session is opened for the
    /// user") and the order spec 6.4 fixes.
    ///
    /// Witnessed by a stack whose auth half refuses `pam_setcred`
    /// (`pam_deny`'s own `pam_sm_setcred` returns `PAM_CRED_ERR`) while its
    /// account half admits: the login is refused, and the `pam_exec` in the
    /// session stack never runs at all. That is two things at once -- that
    /// `pam_setcred` is called, since otherwise this stack would admit; and
    /// that it is called first, since otherwise the marker would be there.
    ///
    /// `pam_exec` cannot witness the call directly: its own
    /// `pam_sm_setcred` returns `PAM_IGNORE` without running anything.
    #[test]
    fn credentials_are_established_before_the_session_opens() {
        let dir = tempfile::tempdir().expect("tempdir");
        // A marker, and a script, PER ARM. Sharing one and clearing it
        // between the two does not work and looked as if it did: the
        // control's session is closed by its monitor, a process of its own,
        // some time after `stop()` returns -- so its `close_session` line
        // can land in the file after this test has emptied it, and the
        // refusal below then reads a marker the refusal had nothing to do
        // with.
        let control_marker = dir.path().join("control-session");
        let refused_marker = dir.path().join("refused-session");
        let stack = |name: &str, auth: &str, marker: &Path| {
            let script = dir.path().join(format!("record-{name}.sh"));
            write_script(
                &script,
                &format!("echo $PAM_TYPE >> {m}", m = marker.display()),
            );
            write_stack(
                dir.path(),
                name,
                &format!(
                    "auth required {auth}\n\
                     account required pam_permit.so\n\
                     session required pam_exec.so {s}\n\
                     session required pam_permit.so\n",
                    s = script.display()
                ),
            );
        };
        // Positive control, same harness and the same kind of script: with
        // an auth half that grants credentials the channel opens and the
        // session stack really does run -- so the absence below is the
        // refusal's doing and not a pam_exec that never works here.
        stack("qshd-test-cred-ok", "pam_permit.so", &control_marker);
        stack("qshd-test-cred", "pam_deny.so", &refused_marker);

        let ok = helper_with_pam_confdir(dir.path(), "qshd-test-cred-ok");
        let (admitted, fd) = open_result_with_fd(&ok.channels, 1, my_uid(), ok.login);
        assert!(
            matches!(admitted, Response::Opened { id: 1 }),
            "control: credentials that are granted must open the channel, got {admitted:?}"
        );
        assert!(fd.is_some());
        wait_until_exists(&control_marker, TEST_RECV_TIMEOUT);
        assert_eq!(
            recorded_lines(&control_marker),
            ["open_session"],
            "control: the session stack must run when nothing refuses"
        );
        ok.stop();

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-cred");

        let (answer, fd) = open_result_with_fd(&h.channels, 1, my_uid(), h.login);

        assert!(
            matches!(&answer, Response::Failed { id: 1, reason } if reason == REFUSED_REASON),
            "credentials that cannot be established must refuse the channel, got {answer:?}"
        );
        assert!(fd.is_none());
        // The two ways this can be wrong say different things, so the
        // message distinguishes them rather than naming one: an
        // `open_session` here means `pam_setcred` ran AFTER
        // `pam_open_session`, and a `close_session` alone means a session
        // that never opened was closed -- which is the OTHER half of
        // `Session::close`'s rule and a different repair.
        assert!(
            !refused_marker.exists(),
            "the session stack must not run at all when the credentials were refused: an \
             `open_session` here means pam_setcred ran AFTER pam_open_session, a `close_session` \
             means a session that never opened was closed -- {:?}",
            recorded_lines(&refused_marker)
        );
        h.stop();
    }

    /// The modules see who is logging in, on what, and from where: the
    /// account's name, the service the daemon was configured for, the
    /// terminal the helper opened for the login's first channel, and the
    /// address the worker reported when the login proved itself.
    ///
    /// `PAM_RHOST` decides nothing here and is believed by nobody (spec §9
    /// `rhost-from-worker`) -- it is the worker's word -- but a stack that
    /// consults it (`pam_access`, `pam_rhosts`) must at least be given what
    /// arrived on `Request::Verify` rather than an empty string, which is
    /// what looks LOCAL to `pam_access` and as a rule loosens its rules.
    ///
    /// `pam_exec` puts all four in the script's environment, which is how a
    /// test with no privileges can read back what the modules were handed.
    #[test]
    fn the_stack_sees_the_account_service_terminal_and_address() {
        let dir = tempfile::tempdir().expect("tempdir");
        let items = dir.path().join("items");
        let script = dir.path().join("record-items.sh");
        write_script(
            &script,
            &format!(
                "echo \"$PAM_USER|$PAM_SERVICE|$PAM_TTY|$PAM_RHOST\" >> {i}",
                i = items.display()
            ),
        );
        write_stack(
            dir.path(),
            "qshd-test-items",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_exec.so {s}\n\
                 session required pam_permit.so\n",
                s = script.display()
            ),
        );

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-items");
        // The terminal of the FIRST channel is the session's, so this one
        // has to be read back from the channel itself -- the helper names
        // it, and nothing else here knows it.
        let (opened, fd) = open_command_with_fd(&h.channels, 1, my_uid(), h.login, "tty; echo END");
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        let seen = read_until_or_timeout(&mut std::fs::File::from(fd.expect("terminal")), "END");
        let tty = seen
            .lines()
            .map(str::trim)
            .find(|line| line.starts_with("/dev/"))
            .unwrap_or_else(|| panic!("the shell must name its own terminal, got {seen:?}"))
            .to_string();

        wait_until_exists(&items, TEST_RECV_TIMEOUT);
        let recorded = recorded_lines(&items);

        assert_eq!(
            recorded.first().map(String::as_str),
            Some(
                format!(
                    "{me}|qshd-test-items|{tty}|{rhost}",
                    me = h.me,
                    rhost = PROOF_RHOST
                )
                .as_str()
            ),
            "the account, the service, the login's terminal and the address it logged in from \
             must all reach the modules: {recorded:?}"
        );
        h.stop();
    }

    /// The array handed to `execve` carries each environment name ONCE.
    ///
    /// A shell CAN witness this, through its own `/proc/$$/environ`: that is
    /// the array `execve` was given, byte for byte, and not the table the
    /// shell rebuilds from it, which collapses a repeated name and keeps the
    /// LAST. `$TERM` alone cannot tell the two apart, which is why a
    /// value-only test passes for an environment that carries `TERM` twice
    /// -- and why `fork_shell` could stop calling `merge_env` altogether
    /// with every other test still green.
    ///
    /// What the gap costs, if it is ever reopened: `getenv(3)` answers with
    /// the FIRST match, so every program that reads its environment without
    /// a shell in between gets the passwd value, and a `pam_env` that set
    /// `PATH` is ignored while looking perfectly present in `env`.
    #[test]
    fn the_shell_is_handed_each_environment_name_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("env"), "TERM DEFAULT=from-the-stack\n").expect("write");
        write_stack(
            dir.path(),
            "qshd-test-once",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session required pam_env.so conffile={} envfile=/dev/null readenv=0\n\
                 session required pam_permit.so\n",
                dir.path().join("env").display()
            ),
        );

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-once");
        let (opened, fd) = open_command_with_fd(
            &h.channels,
            1,
            my_uid(),
            h.login,
            "printf 'TERMS=[%s] END\\n' \"$(tr '\\0' '\\n' < /proc/$$/environ | grep -c '^TERM=')\"",
        );
        assert!(
            matches!(opened, Response::Opened { id: 1 }),
            "got {opened:?}"
        );
        let seen = read_until_or_timeout(&mut std::fs::File::from(fd.expect("terminal")), "END");
        assert!(
            seen.contains("TERMS=[1] END"),
            "a name both passwd and the session stack set must reach execve ONCE, got {seen:?}"
        );
        h.stop();
    }

    /// A stack with no `auth` section refuses every login: `pam_setcred`
    /// runs the AUTH stack's setcred half, and Linux-PAM answers
    /// `PAM_PERM_DENIED` when there is no such half to run.
    ///
    /// The trap this pins is for whoever writes `/etc/pam.d/qshd`: an
    /// `account` plus `session` file is the natural thing to write, since
    /// `pam_authenticate` is never called here -- and it locks every user
    /// out with "authentication failed" and nothing but the helper's log to
    /// go on. See `monitor::Session::open`.
    #[test]
    fn a_stack_with_no_auth_section_refuses_the_login() {
        let dir = tempfile::tempdir().expect("tempdir");
        write_stack(
            dir.path(),
            "qshd-test-noauth",
            "account required pam_permit.so\nsession required pam_permit.so\n",
        );
        write_stack(dir.path(), "qshd-test-auth", PERMISSIVE_STACK);

        // Positive control, same harness, the same two lines plus an `auth`
        // one: without it this test passes for any helper that refuses
        // everything, and what it would be pinning is not the missing
        // section at all.
        let ok = helper_with_pam_confdir(dir.path(), "qshd-test-auth");
        let (admitted, fd) = open_result_with_fd(&ok.channels, 1, my_uid(), ok.login);
        assert!(
            matches!(admitted, Response::Opened { id: 1 }),
            "control: the same stack WITH an auth line must admit, got {admitted:?}"
        );
        assert!(fd.is_some());
        ok.stop();

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-noauth");

        let (answer, fd) = open_result_with_fd(&h.channels, 1, my_uid(), h.login);

        assert!(
            matches!(&answer, Response::Failed { id: 1, reason } if reason == REFUSED_REASON),
            "a stack with no auth section leaves pam_setcred nothing to run, and Linux-PAM \
             answers PAM_PERM_DENIED, so the login is refused, got {answer:?}"
        );
        assert!(fd.is_none());
        h.stop();
    }

    /// The CALL SITE of `crate::log::mute()` in `monitor::run_monitor`.
    ///
    /// `close_other_descriptors` starts at 3, so a log file that sits on
    /// descriptor 0 survives the monitor's sweep -- and an UNMUTED monitor
    /// whose PAM conversation hears a module (`pam_echo`) would then append
    /// that module's words to the real log file. No descriptor-number reuse
    /// is involved, and nothing here is timing-dependent.
    ///
    /// Its sibling `monitor::tests::a_muted_process_writes_nothing_to_the_log`
    /// pins `mute()` itself; this one pins that the monitor calls it.
    #[test]
    fn a_monitor_writes_nothing_to_the_log_when_a_module_speaks() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::a_monitor_writes_nothing_to_the_log_when_a_module_speaks_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own: it closes this
    /// process's stdin for good and points its log at a file of its own.
    #[test]
    #[ignore = "runs only via a_monitor_writes_nothing_to_the_log_when_a_module_speaks"]
    fn a_monitor_writes_nothing_to_the_log_when_a_module_speaks_body() {
        nix::unistd::close(0).expect("close stdin, so the log lands on descriptor 0");
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        assert_eq!(
            std::fs::read_link("/proc/self/fd/0").expect("fd 0"),
            log_path,
            "setup: the log must sit on descriptor 0, below the monitor's sweep, or an unmuted \
             monitor could not write to it at all and this would prove nothing"
        );
        crate::log::info("qshd", "control-before-the-monitor");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-before-the-monitor"),
            "setup: the log must be writable, or the silence below proves nothing"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        write_stack(
            dir.path(),
            "qshd-test-echo",
            "auth required pam_permit.so\n\
             account required pam_permit.so\n\
             session required pam_echo.so QSHD-MODULE-SPOKE\n\
             session required pam_permit.so\n",
        );
        let h = helper_with_pam_confdir(dir.path(), "qshd-test-echo");
        open_channel_for(&h.channels, 1, my_uid(), h.login);
        // The monitor has already spoken to PAM by the time the channel is
        // answered -- the session opens before the shell is forked -- so
        // this waits only for a write that would already have happened.
        std::thread::sleep(Duration::from_millis(300));
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        h.stop();
        // Split in two, not one `&&`: since `MonitorEvent::Noted` exists, a
        // module's words CAN legitimately reach this log -- written by the
        // HELPER, not the monitor. A run where `notes()` forwards
        // `PAM_TEXT_INFO` too would make `QSHD-MODULE-SPOKE` appear here
        // for a reason that has nothing to do with muting, and a combined
        // assertion would blame the monitor for it.
        assert!(
            !log.contains("a PAM module says"),
            "a monitor must write nothing to the daemon's log -- that prefix is its own \
             conversation logger's; the log holds:\n{log}"
        );
        assert!(
            !log.contains("QSHD-MODULE-SPOKE"),
            "and nothing else may carry a module's words here either: PAM_TEXT_INFO is not \
             forwarded (see MonitorEvent::Noted), so this text has no legitimate writer; the \
             log holds:\n{log}"
        );
    }

    /// What the stack says as an ERROR while letting a login IN reaches the
    /// helper's log -- and nothing else does.
    ///
    /// The case is "something is wrong but we let you in": an `optional`
    /// module whose script fails makes `pam_exec` call `pam_error`
    /// (`PAM_ERROR_MSG` through the conversation) while `pam_open_session`
    /// still returns success, because `optional` does not decide the stack.
    /// Measured on Linux-PAM 1.5.3, which is why this test can exist at all.
    ///
    /// The other half of the assertion is as load-bearing as the first: the
    /// `PAM_TEXT_INFO` line from `pam_echo` in the same stack must NOT be
    /// there. Forwarding everything a module says would put "motd"-like
    /// text in a root process's log on every single login, at a rate the
    /// administrator's modules choose.
    #[test]
    fn what_the_stack_complains_about_while_admitting_reaches_the_log() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::\
             what_the_stack_complains_about_while_admitting_reaches_the_log_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own: it points this
    /// process's log at a file of its own, for good (`crate::log::init` is a
    /// `OnceLock`).
    #[test]
    #[ignore = "runs only via what_the_stack_complains_about_while_admitting_reaches_the_log"]
    fn what_the_stack_complains_about_while_admitting_reaches_the_log_body() {
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-the-log-is-writable"),
            "setup: the log must be writable, or an absent line below proves nothing"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let failing = dir.path().join("complain.sh");
        write_script(&failing, "exit 3");
        write_stack(
            dir.path(),
            "qshd-test-note",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session optional pam_exec.so {s}\n\
                 session required pam_echo.so QSHD-CHATTER\n\
                 session required pam_permit.so\n",
                s = failing.display()
            ),
        );

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-note");
        // The channel OPENS: `optional` does not decide the stack, so the
        // complaint below is a complaint and not a refusal. Without this the
        // test would pass for an implementation that refused the login and
        // logged the same words.
        open_channel_for(&h.channels, 1, my_uid(), h.login);
        let log = wait_for_log_line(&log_path, "complain.sh failed");
        h.stop();

        assert!(
            log.contains("admitted channel 1 and said:") && log.contains("complain.sh failed"),
            "an error a module reported while the session still opened must reach the log, so \
             an administrator learns an optional module of theirs is broken; the log holds:\n{log}"
        );
        assert!(
            !log.contains("QSHD-CHATTER"),
            "and only the errors: forwarding every PAM_TEXT_INFO would put motd-like text in a \
             root process's log on every login; the log holds:\n{log}"
        );
    }

    /// `Session::notes` caps what it returns at [`MAX_NOTES`]
    /// (`super::super::monitor::MAX_NOTES`) -- the whole justification for
    /// letting a login write to a root process's log at all is that a
    /// stack cannot make it write more than a handful of lines. A stack
    /// with `MAX_NOTES + 1` complaining `optional` modules pins that the
    /// cap is applied, not just declared: without `.take(MAX_NOTES)` in
    /// `Session::notes`, this stack would put `MAX_NOTES + 1` lines in the
    /// log instead.
    #[test]
    fn a_login_leaves_at_most_max_notes_lines_in_the_log() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::a_login_leaves_at_most_max_notes_lines_in_the_log_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own: it points
    /// this process's log at a file of its own, for good (`crate::log::init`
    /// is a `OnceLock`).
    #[test]
    #[ignore = "runs only via a_login_leaves_at_most_max_notes_lines_in_the_log"]
    fn a_login_leaves_at_most_max_notes_lines_in_the_log_body() {
        // The VALUE, not only that it is applied. Everything below counts
        // to `MAX_NOTES` and builds a stack of `MAX_NOTES + 1` modules, so
        // without this line the whole test scales with the constant and
        // passes at any value -- measured: 8 to 3 and 8 to 64 both left all
        // 367 tests of this suite green. And the value IS the property: the
        // constant's own docs rest the whole case for letting a login write
        // to a root process's log on "a stack cannot make it write more
        // than a handful of lines", and sixty-four of them per login is the
        // amplifier that argument rules out. Its neighbour in the same
        // commit, `MAX_REFUSAL_DETAIL`, is pinned by value the same way
        // (`a_notes_words_reach_the_log_through_sanitized_detail`), and
        // `probation::the_probation_caps_are_the_numbers_the_spec_argues_for`
        // exists for exactly this disease.
        assert_eq!(
            super::super::monitor::MAX_NOTES,
            8,
            "see the constant's own docs: a handful of lines is the whole justification for \
             letting a login's stack write to a root process's log at all"
        );

        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-the-log-is-writable"),
            "setup: the log must be writable, or a short count below proves nothing"
        );

        let dir = tempfile::tempdir().expect("tempdir");
        let failing = dir.path().join("complain.sh");
        write_script(&failing, "exit 3");
        let mut stack = "auth required pam_permit.so\naccount required pam_permit.so\n".to_string();
        for _ in 0..(super::super::monitor::MAX_NOTES + 1) {
            stack.push_str(&format!(
                "session optional pam_exec.so {}\n",
                failing.display()
            ));
        }
        stack.push_str("session required pam_permit.so\n");
        write_stack(dir.path(), "qshd-test-many-notes", &stack);

        let h = helper_with_pam_confdir(dir.path(), "qshd-test-many-notes");
        open_channel_for(&h.channels, 1, my_uid(), h.login);
        // By the time `open_channel_for` returns, every note the stack
        // produced has already reached this log: `Session::notes` is sent
        // over the monitor seam BEFORE the session is stored and the shell
        // forked (see `monitor::serve_request`), and the helper answers a
        // channel's `Open` only once that shell is running, so it has
        // already drained and logged every `Noted` event first. The short
        // sleep below is only a margin against scheduler jitter -- what is
        // asserted comes from a FRESH read taken after it, not from
        // whatever arrived first.
        std::thread::sleep(Duration::from_millis(50));
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        h.stop();
        let lines = log
            .lines()
            .filter(|l| l.contains("admitted channel 1 and said:"))
            .count();
        assert_eq!(
            lines,
            super::super::monitor::MAX_NOTES,
            "a login may put at most MAX_NOTES lines in the helper's log however many times its \
             stack complains; the log holds:\n{log}"
        );
    }

    /// The words `Session::notes` collects go through `sanitized_detail` on
    /// their way to the helper's log -- a root process's. That function has
    /// its own unit test (`monitor::tests::a_modules_words_reach_the_log_as_one_printable_line`),
    /// but that THIS path calls it had none: this pins both of its bounds
    /// with modules a stock Linux-PAM ships.
    #[test]
    fn a_notes_words_reach_the_log_through_sanitized_detail() {
        let (status, stdout, stderr) = super::super::spawner::tests::run_isolated(
            "helper::server::tests::a_notes_words_reach_the_log_through_sanitized_detail_body",
        );
        assert!(
            status.success(),
            "the isolated check failed ({status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via the test above, in a process of its own: it points
    /// this process's log at a file of its own, for good (`crate::log::init`
    /// is a `OnceLock`).
    #[test]
    #[ignore = "runs only via a_notes_words_reach_the_log_through_sanitized_detail"]
    fn a_notes_words_reach_the_log_through_sanitized_detail_body() {
        let logdir = tempfile::tempdir().expect("tempdir");
        crate::log::init(logdir.path());
        let log_path = logdir.path().join("qshd.log");
        crate::log::info("qshd", "control-the-log-is-writable");
        assert!(
            std::fs::read_to_string(&log_path)
                .unwrap_or_default()
                .contains("control-the-log-is-writable"),
            "setup: the log must be writable, or an absent line below proves nothing"
        );

        // Bound one: printable ASCII only. A non-ASCII byte survives
        // Linux-PAM's argument splitting on whitespace (a space in the
        // path would not, and `write_script` already checks for that), so
        // the failing script's own name carries the witness.
        let ascii_dir = tempfile::tempdir().expect("tempdir");
        let odd = ascii_dir.path().join("complain-é-here.sh");
        write_script(&odd, "exit 3");
        write_stack(
            ascii_dir.path(),
            "qshd-test-note-ascii",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session optional pam_exec.so {s}\n\
                 session required pam_permit.so\n",
                s = odd.display(),
            ),
        );
        let h1 = helper_with_pam_confdir(ascii_dir.path(), "qshd-test-note-ascii");
        open_channel_for(&h1.channels, 1, my_uid(), h1.login);
        std::thread::sleep(Duration::from_millis(50));
        let log1 = std::fs::read_to_string(&log_path).unwrap_or_default();
        h1.stop();
        assert!(
            log1.contains("complain-.-here.sh"),
            "a module's words must reach a root process's log as printable ASCII only; the log \
             holds:\n{log1}"
        );
        assert!(
            !log1.contains("complain-é-here.sh"),
            "and the unsanitized form must not be there at all; the log holds:\n{log1}"
        );

        // Bound two: a length cap, not just a cleanup. A script reached
        // through a deep enough directory makes `pam_exec`'s own message
        // (the script's path plus " failed: exit code N") longer than the
        // cap -- measured at ~700 bytes on Linux-PAM 1.5.3 for a path of
        // this shape. `sanitized_detail`'s `.take(MAX_REFUSAL_DETAIL)` is
        // what must cut it down; without it the note would be longer.
        let long_dir = tempfile::tempdir().expect("tempdir");
        let mut deep = long_dir.path().to_path_buf();
        for i in 0..15 {
            deep = deep.join(format!(
                "directory-component-number-{i:02}-making-the-path-long"
            ));
        }
        std::fs::create_dir_all(&deep).expect("mkdir -p a path long enough to blow past the cap");
        let long = deep.join("complain.sh");
        write_script(&long, "exit 3");
        assert!(
            long.as_os_str().len() > 512,
            "setup: the script's own path must already be longer than the 512-byte cap this \
             test means to pin (monitor::MAX_REFUSAL_DETAIL), or a short note below would prove \
             nothing; got {} bytes",
            long.as_os_str().len()
        );
        write_stack(
            long_dir.path(),
            "qshd-test-note-long",
            &format!(
                "auth required pam_permit.so\n\
                 account required pam_permit.so\n\
                 session optional pam_exec.so {s}\n\
                 session required pam_permit.so\n",
                s = long.display(),
            ),
        );
        let h2 = helper_with_pam_confdir(long_dir.path(), "qshd-test-note-long");
        open_channel_for(&h2.channels, 1, my_uid(), h2.login);
        std::thread::sleep(Duration::from_millis(50));
        let log2 = std::fs::read_to_string(&log_path).unwrap_or_default();
        h2.stop();
        let said = log2
            .lines()
            .find(|l| {
                l.contains("admitted channel 1 and said:")
                    && l.contains("directory-component-number-00")
            })
            .and_then(|l| l.split_once("and said: ").map(|(_, said)| said))
            .unwrap_or_else(|| {
                panic!("setup: no note line for the long path was found; the log holds:\n{log2}")
            });
        assert_eq!(
            said.chars().count(),
            512,
            "a module's words must be CAPPED at MAX_REFUSAL_DETAIL bytes, not merely cleaned, \
             before they reach a root process's log; the note read:\n{said}"
        );
    }

    /// Reads the daemon log until `needle` appears in it, bounded by
    /// [`TEST_RECV_TIMEOUT`] -- a line that never arrives must fail the test
    /// that wanted it, not hang the run.
    fn wait_for_log_line(log_path: &Path, needle: &str) -> String {
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            let log = std::fs::read_to_string(log_path).unwrap_or_default();
            if log.contains(needle) || Instant::now() >= deadline {
                return log;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}
