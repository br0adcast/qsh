//! The worker's ends of its two seams to the helper.
//!
//! [`HelperChannelSpawner`] is a [`ChannelSpawner`] that asks the helper for
//! a channel instead of opening a pseudo-terminal itself, over the channel
//! seam. One reader thread owns that seam's receiving side, because it
//! carries request outcomes, installed `Exited` notices, and independent
//! terminal cleanup receipts. "The next message answers my
//! request" is therefore false there, and something has to demultiplex by
//! channel id.
//!
//! [`HelperAuth`] asks the helper for handshake nonces and for its verdict on
//! a client's proof, over the authentication seam: a second socket pair,
//! with a reader thread of its own. Its answers are matched to their
//! questions differently -- by the number every request carries (see
//! [`AuthRequest`]) rather than by channel id -- and that seam carries no
//! descriptors and no unprompted notices, so the two readers never have to
//! share a stream.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use transport::auth::{AuthError, AuthRecord, AuthVerifier, Principal};
use transport::channel::{ChannelKind, OpenRequest};
#[cfg(test)]
use transport::channel_server::SpawnedChannel;
use transport::channel_server::{ChannelSpawner, ChannelWait};
use transport::probation::MAX_PROBATION;
use transport::session_manager::{
    login_end_channel, LoginEndNotReported, LoginEndedReports, LoginId, LoginSink,
    MAX_SESSIONS_TOTAL,
};
use transport::shell_server::ResizeHandle;

use anyhow::Context;

use crate::channel_backend::make_screen;
use crate::screen_budget::{BudgetLimits, ScreenBudget};

use super::channel;
use super::config::HelperConfig;
use super::protocol::{
    decode, encode, AuthRequest, AuthRequestId, AuthResponse, ChannelId, CleanupFailure,
    CleanupKind, Nonce, Request, Response,
};
use super::worker_threads::{Role as ThreadRole, WorkerThreads};

/// The most bytes of a thread's name Linux keeps: `TASK_COMM_LEN` is 16,
/// with the terminating NUL. A longer name is cut to this silently, so
/// `/proc/<pid>/task/<tid>/comm`, `ps -L` and `top -H` show only its first
/// 15 bytes -- and anything looking for the full name never finds it.
pub const MAX_THREAD_NAME_LEN: usize = 15;

/// The name of the worker's thread that reads the channel seam
/// ([`HelperChannelSpawner`]).
pub const CHANNEL_READER_THREAD: &str = "qshd-chan-read";

/// The name of the worker's thread that reads the authentication seam
/// ([`HelperAuth`]).
pub const AUTH_READER_THREAD: &str = "qshd-auth-read";

/// The name of the worker's thread that sends the helper what needs no
/// answer -- released nonces, late ones among them, and the ends of logins
/// ([`HelperAuth`]; see `AuthSeam::queue_tell`).
pub const AUTH_RELEASE_THREAD: &str = "qshd-auth-free";

/// The name of the worker's thread that keeps its pool of nonces filled
/// (`crate::nonce_pool::PooledNonces`), asking the helper over this seam.
pub const AUTH_POOL_THREAD: &str = "qshd-auth-pool";

/// Every name the worker gives a thread it starts itself -- this module's
/// three and the nonce pool's; the helper starts none. Kept together here,
/// beside the seam those threads serve. Each must fit in
/// [`MAX_THREAD_NAME_LEN`]. The worker's tokio runtime names its own
/// threads, with tokio's default.
pub const THREAD_NAMES: [&str; 4] = [
    CHANNEL_READER_THREAD,
    AUTH_READER_THREAD,
    AUTH_RELEASE_THREAD,
    AUTH_POOL_THREAD,
];

/// How the worker is ended, and why -- `super::end_the_worker` in the
/// daemon, which logs the reason and exits. The worker's clients call it when
/// the worker can no longer keep up its side of the seams: the helper is
/// gone, or a login's end could not be kept until it reaches the helper.
pub(crate) type EndWorker = Arc<dyn Fn(&str) + Send + Sync>;

/// Why the worker ends once a seam to its helper is lost.
pub(crate) const HELPER_GONE_REASON: &str = "the helper it depends on is gone";

/// Why the worker ends when a login's end cannot be kept for the helper --
/// see [`MAX_QUEUED_LOGIN_ENDS`].
pub(crate) const LOGIN_ENDS_OVERFLOW_REASON: &str =
    "the helper has not taken the ends of logins for too long; a login it is not told has ended \
     would stay trusted";

/// Why the worker ends when the ends of logins the HELPER reports cannot be
/// kept for the router -- the mirror of [`LOGIN_ENDS_OVERFLOW_REASON`], for
/// the other direction, and bounded by the same
/// [`MAX_QUEUED_LOGIN_ENDS`].
///
/// Nothing is dropped instead, for the reason that direction's own docs
/// give in reverse: a session whose login has ended and whose router was
/// never told goes on answering pings while every channel it asks for is
/// refused, and the person sees a channel that will not open rather than a
/// disconnect. Ending the worker ends every session at once, which is
/// recoverable -- each client reconnects and proves itself again -- where
/// one sterile session is not.
///
/// The end itself is then lost, unlike a `Request::LoginEnded` the other
/// direction puts back at the front of its queue. That is the right
/// difference: there the helper survives and still has to hear it, here
/// the process that would have acted on it is the one going away.
pub(crate) const HELPER_LOGIN_ENDS_OVERFLOW_REASON: &str =
    "the router has not taken the ends of logins the helper reported; a session whose login has \
     ended would go on answering while every channel it asks for is refused";

/// What the worker logs when the helper reports a login ended and there is
/// no router left to tell -- the daemon is on its way down, and the session
/// that login belonged to is going with it.
const ROUTER_GONE_FOR_A_LOGIN_END_LOG: &str =
    "the helper reported a login ended, but the router is gone -- its session is \
     ending anyway";

/// Why the worker ends when its release thread (`AUTH_RELEASE_THREAD`) stops
/// by a panic: that thread carries the ends of logins to the helper.
pub(crate) const RELEASE_THREAD_GONE_REASON: &str =
    "the thread that sends the ends of logins to the helper has stopped";

/// How many `ReleaseNonce` tells may wait to be sent at once; one more is
/// dropped, with a line in the log.
///
/// Each names a nonce the helper issued and nobody spent, and the helper
/// never holds more than `MAX_OUTSTANDING_NONCES` of those -- and issues no
/// more once the worker stops reaching it, since every request first sends
/// what is queued. A dropped release costs nothing but a slot in the
/// helper's table until the helper expires that nonce on its own
/// (`helper::server::NONCE_LIFETIME`).
const MAX_QUEUED_RELEASES: usize = super::server::MAX_OUTSTANDING_NONCES;

/// How many `LoginEnded` tells may wait to be sent at once. One more is never
/// dropped: the worker ends instead ([`LOGIN_ENDS_OVERFLOW_REASON`]). A login
/// the helper never hears the end of stays on file -- and its account
/// trusted -- for good once it has been established.
///
/// Sized from the router's own bounds, so that it cannot fill while the
/// router works as it should. Every request sends what is queued before it
/// goes out, a `Verify` included, and a login is established only by a
/// `Verify` the helper answered. So between the last time a request found
/// the queue empty and the next, the router can end only the logins it knew
/// then: a backend of its table ([`MAX_SESSIONS_TOTAL`]) or a proof in
/// probation ([`MAX_PROBATION`]) -- each once. Twice that, for room.
///
/// This rests on the system mode refusing the allowlist path
/// (`serve::refuse_the_allowlist_path`): a login admitted -- or refused -- by
/// allowlist needs no `Verify`, and its ends would be bounded only by how fast
/// handshakes arrive. A mode that served that path would need a bound of its
/// own here.
pub(crate) const MAX_QUEUED_LOGIN_ENDS: usize = 2 * (MAX_SESSIONS_TOTAL + MAX_PROBATION);

/// How long the release thread waits before it sends a login's end again,
/// once a send of it has failed.
const TELL_RETRY_DELAY: Duration = Duration::from_millis(500);

/// What wakes the release thread (`AUTH_RELEASE_THREAD`): a late nonce to
/// give back, or tells waiting in the queue.
pub(crate) enum Wake {
    Late(Nonce),
    Flush,
    Finish(Instant),
}

/// Where the worker hands on the end of a login the HELPER reported
/// (`Response::LoginEnded`): [`worker_clients`] builds the one there is in
/// production, around `transport::LoginEndedReporter`, so that a report
/// which cannot be kept ends the worker rather than vanishing
/// ([`HELPER_LOGIN_ENDS_OVERFLOW_REASON`]).
///
/// Called from the channel seam's reader thread, so it must not block and
/// must not wait on anything outside this process -- the same rule the
/// router's own `LoginSink` runs under, for the same reason: everything
/// else on this seam (every `Opened`, every `Exited`) queues behind it.
///
/// Takes WHICH LIFE of that login ended alongside the login itself (see
/// `Principal::incarnation`): the router drops a notice older than the
/// incarnation its current session was admitted under, and the worker
/// passes the number on without looking at it.
///
/// A plain closure rather than a trait: the whole of it is one call, and a
/// test that has to watch that call wants to watch nothing else.
pub(crate) type LoginEndedSink = Box<dyn Fn(LoginId, u64) + Send>;

/// What the worker logs when the authentication seam's reader finds the
/// helper gone -- the channel seam's reader logs a line of its own. A test
/// that has to know WHICH reader noticed a lost seam looks for this.
pub const AUTH_SEAM_CLOSED_LOG: &str = "the helper is gone (its authentication seam closed)";

/// What the worker logs when its release thread (`AUTH_RELEASE_THREAD`)
/// stops by a panic rather than because nothing can hand it anything any
/// more. The worker then ends ([`RELEASE_THREAD_GONE_REASON`]).
const RELEASE_THREAD_GONE_LOG: &str =
    "the thread that sends releases and the ends of logins to the helper has \
     stopped";

/// What the worker logs for each late nonce it could not hand to the
/// release thread, because that thread is gone.
const LATE_NONCE_NOT_RELEASED_LOG: &str =
    "a late nonce could not be handed back -- the release thread is gone; the \
     helper expires it on its own";

/// How long `spawn` waits for the helper's `Opened`/`Failed` reply before
/// concluding the reply itself is lost rather than merely slow.
///
/// The helper is single-threaded and serialises every channel open across
/// every session it serves, and bounds its own wait for a child's startup
/// report at `helper::server::STARTUP_REPORT_TIMEOUT` -- see that
/// constant's docs for why a healthy-but-slow open can legitimately take
/// close to that long. Set here just above it: this thread (one of the
/// async runtime's blocking-pool threads, since `ChannelSpawner::spawn`
/// runs synchronously from the session loop) must never be parked longer
/// than the helper's own worst case for an ordinary open, or a handful of
/// slow opens in flight at once could tie up several such threads --
/// including, transitively, whatever else is waiting for the pool. The
/// next slice's PAM stack can reach the network from inside that same
/// wait, which turns a slow-but-healthy open from exotic into ordinary.
const OPEN_REPLY_TIMEOUT: Duration =
    Duration::from_secs(super::server::STARTUP_REPORT_TIMEOUT.as_secs() + 1);

/// How long `HelperWait::wait` waits for the helper's `Exited` notice
/// before giving up on it as unreachable.
///
/// This is a backstop, not the ordinary path. A channel that exits on its
/// own is reported the moment the helper's reaper next runs (at most
/// `helper::server::REAP_INTERVAL` later); one this spawner asked to close
/// is reported within `helper::server::CLOSE_GRACE_PERIOD` of that, plus
/// the same reap latency, once the helper's own `SIGHUP`-to-`SIGKILL`
/// escalation forces it down. A dead helper is already handled without
/// this timeout at all: the reader thread's `read_loop` notices the socket
/// close and drops every sender, which turns this `recv` into an
/// immediate error rather than a wait. What this bounds is everything
/// else -- a helper that stays connected but simply never answers for this
/// id, for any reason, including one this module has not thought of --
/// so `wait()` cannot park a caller forever no matter which of those it
/// turns out to be. Generous next to both numbers above, so a correctly
/// behaving helper never comes close to tripping it.
const HELPER_EXIT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a send on the worker's end of the CHANNEL seam may block before
/// it gives up on that message.
///
/// The authentication seam got one of these in an earlier task
/// ([`HELPER_ANSWER_TIMEOUT`]); this seam did not, and every `spawn` and
/// every `kill` sends under the `tx` mutex. A helper that has stopped
/// reading -- wedged on an NSS lookup, on a home directory that hangs, on a
/// channel that will not start -- plus a full socket buffer therefore
/// parked the sending thread forever with that mutex held, taking every
/// other session's `spawn` and `kill` down with it.
///
/// `OPEN_REPLY_TIMEOUT` is the budget: a caller is already prepared to wait
/// that long for the open it is asking for, and a send that cannot get out
/// within it has nothing left to be in time for.
const CHANNEL_SEND_TIMEOUT: Duration = OPEN_REPLY_TIMEOUT;

/// The worker's two clients of the helper, as `split_and_run`'s worker
/// builds them. If either reader thread ever finds its seam gone for a
/// reason other than the worker letting go of it, there is no reason left
/// for the worker to keep running -- see `split_and_run`'s docs -- so both
/// are wired to `end_the_worker`; so is the authentication client's
/// promise to deliver every login's end ([`MAX_QUEUED_LOGIN_ENDS`]). The wait for a verdict is derived from
/// `config`, the settings the helper runs with, so the two can never
/// disagree.
///
/// The only way the daemon can build these clients: their constructors are
/// private ([`HelperChannelSpawner::new_with_hook`],
/// [`HelperAuth::new_with_hook`]) or exist only in tests
/// ([`HelperChannelSpawner::new`], [`HelperAuth::new`]), so wiring either
/// client any other way does not compile. A function of its own so that a
/// test can watch this wiring end a real process without root
/// (`helper::tests::the_worker_ends_once_*_seam_is_lost`): `split_and_run`
/// reaches it only after dropping privileges.
///
/// What nothing checks is WHICH settings the caller passes: a
/// `split_and_run` that handed this a `HelperConfig` other than the one the
/// helper runs with would still compile, and would still pass every test --
/// the tests pass their own settings, and the root-only test does not look
/// at the verdict wait. `split_and_run` has exactly one `HelperConfig` in
/// scope.
///
/// The third thing it hands back is the ROUTER's half of the ends of
/// logins the helper reports ([`Response::LoginEnded`]): the reporting half
/// is already wired into the spawner's reader thread here, so the caller
/// has only to give this to `SessionManager::serve`. Built here rather than
/// by the caller because the spawner's reader must hold the other half from
/// the moment it starts -- there is no point in the worker's life where the
/// helper may report a login ended and nothing is listening.
pub(super) fn worker_clients(
    worker_channels: UnixStream,
    worker_auth: UnixStream,
    config: &HelperConfig,
) -> anyhow::Result<(HelperChannelSpawner, HelperAuth, LoginEndedReports)> {
    let end_worker: EndWorker = Arc::new(super::end_the_worker);
    worker_clients_with_hooks(
        worker_channels,
        worker_auth,
        config,
        end_worker.clone(),
        end_worker.clone(),
        end_worker,
    )
}

pub(super) fn worker_clients_with_stop(
    worker_channels: UnixStream,
    worker_auth: UnixStream,
    config: &HelperConfig,
    stop: super::worker_stop::WorkerStop,
) -> anyhow::Result<(HelperChannelSpawner, HelperAuth, LoginEndedReports)> {
    use super::worker_protocol::StopReason;
    worker_clients_with_hooks(
        worker_channels,
        worker_auth,
        config,
        stop.fatal_hook(StopReason::ChannelLost),
        stop.fatal_hook(StopReason::AuthLost),
        stop.fatal_hook(StopReason::RequiredTellLost),
    )
}

fn worker_clients_with_hooks(
    worker_channels: UnixStream,
    worker_auth: UnixStream,
    config: &HelperConfig,
    channel_gone: EndWorker,
    auth_failure: EndWorker,
    login_end_lost: EndWorker,
) -> anyhow::Result<(HelperChannelSpawner, HelperAuth, LoginEndedReports)> {
    // Bounded by the SAME constant as the opposite direction, and for the
    // same reason: the two carry the same news about the same logins. See
    // `MAX_QUEUED_LOGIN_ENDS` for how that number is derived from the
    // router's own caps, and `HELPER_LOGIN_ENDS_OVERFLOW_REASON` for why
    // the worker ends rather than drop one.
    let (reporter, reports) = login_end_channel(MAX_QUEUED_LOGIN_ENDS);
    // One pool for this serving worker; every session/backend shares its spawner.
    let budget = Arc::new(ScreenBudget::new(BudgetLimits::default()));
    let spawner = HelperChannelSpawner::with_budget_hook(
        worker_channels,
        budget,
        move || channel_gone(HELPER_GONE_REASON),
        Box::new(
            move |login, incarnation| match reporter.report(login, incarnation) {
                Ok(()) => {}
                Err(LoginEndNotReported::Queued(bound)) => login_end_lost(&format!(
                    "{HELPER_LOGIN_ENDS_OVERFLOW_REASON} ({bound} already waiting)"
                )),
                Err(LoginEndNotReported::RouterGone) => {
                    crate::log::warn("worker", ROUTER_GONE_FOR_A_LOGIN_END_LOG)
                }
            },
        ),
    )
    .context("starting the helper client")?;
    let auth = HelperAuth::new_with_hook(worker_auth, config, auth_failure)
        .context("starting the helper's authentication client")?;
    Ok((spawner, auth, reports))
}

/// Asks a privileged helper to open channels, over one `socketpair` shared
/// with it.
pub struct HelperChannelSpawner {
    opens: Arc<transport::channel_open::ChannelOpenRegistry>,
    budget: Arc<ScreenBudget>,
    /// The sending side. A mutex, not a channel: `spawn` is synchronous (the
    /// trait is), the message is tiny, and the helper answers in
    /// microseconds.
    tx: Mutex<UnixStream>,
    next_id: AtomicU64,
    /// Where the reader thread delivers each id's reply and exit code.
    waiting: Arc<Mutex<HashMap<ChannelId, Pending>>>,
    /// Set by `Drop`, just before it shuts the connection down, so the
    /// reader thread and every `HelperWait` can tell "we disconnected
    /// ourselves" apart from "the helper died." Both look identical on the
    /// wire -- the socket closes either way -- but they are not the same
    /// fact: a channel whose process is genuinely still running when the
    /// LAST spawner handle drops must not be reported as having exited just
    /// because nothing can find out any more.
    disconnected_locally: Arc<AtomicBool>,
    /// How long `spawn` waits for the helper's reply before abandoning the
    /// open -- [`OPEN_REPLY_TIMEOUT`] outside tests, held as a field for the
    /// same reason [`HelperAuth::timeout`] is: a test that has to watch an
    /// open be given up on must not wait out the production budget to see
    /// it.
    open_timeout: Duration,
    auxiliary: Mutex<Option<WorkerThreads>>,
}

/// What a caller is waiting for on one channel id.
struct Pending {
    opened: Option<Sender<Result<OwnedFd, String>>>,
    exited: Option<Sender<i32>>,
    outcome: OpenOutcome,
    receipt: Arc<Mutex<CleanupReceipt>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenOutcome {
    Waiting,
    Opened,
    Failed,
    Abandoned,
}

struct CleanupReceipt {
    kind: Option<CleanupKind>,
    failure: Option<CleanupFailure>,
    cleanup_requested: bool,
    notify: transport::channel_open::CleanupNotifier,
    reap_notify: Option<transport::channel_server::ReapNotifier>,
    leader_notified: bool,
    connection_closed: bool,
}

impl Pending {
    fn finished(&self) -> bool {
        self.receipt
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .kind
            .is_some()
            && match self.outcome {
                OpenOutcome::Waiting => false,
                OpenOutcome::Opened => self.exited.is_none(),
                OpenOutcome::Failed | OpenOutcome::Abandoned => true,
            }
    }
}

impl HelperChannelSpawner {
    /// Production takes custody before publishing this client in an Arc.
    pub(crate) fn take_auxiliary(&mut self) -> WorkerThreads {
        self.auxiliary
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("channel reader custody is transferred once")
    }

    /// Take the worker's end of the pair and start the reader thread.
    ///
    /// Does not end the process if the reader thread later notices the
    /// helper is gone -- see [`HelperChannelSpawner::new_with_hook`], which
    /// does, and is what `split_and_run`'s worker actually uses. Kept
    /// separate so the existing unit tests, which construct a
    /// `HelperChannelSpawner` directly inside the test process, are not put
    /// at risk of a stray `process::exit` taking the whole test binary down
    /// with them. Test-only: the daemon builds its spawner through
    /// [`worker_clients`], and nowhere else.
    #[cfg(test)]
    pub(crate) fn new(sock: UnixStream) -> io::Result<HelperChannelSpawner> {
        Self::new_with_hook(sock, || {}, Box::new(|_, _| {}))
    }

    /// As [`HelperChannelSpawner::new`], with a sink of the test's choosing
    /// for the ends of logins the helper reports -- the one thing about
    /// this reader a test cannot otherwise see, since every other message
    /// it handles is demultiplexed to a caller that asked for it.
    #[cfg(test)]
    pub(crate) fn with_login_ended_sink(
        sock: UnixStream,
        login_ended: LoginEndedSink,
    ) -> io::Result<HelperChannelSpawner> {
        Self::new_with_hook(sock, || {}, login_ended)
    }

    /// As [`HelperChannelSpawner::new`], but calls `on_helper_gone` from the
    /// reader thread the instant it notices the helper died -- specifically
    /// NOT when this spawner is merely dropped locally (see
    /// `disconnected_locally`, which is what tells the two apart).
    ///
    /// This is the other half of the mutual watch `helper/mod.rs` promises.
    /// A dead worker already takes the helper down on its own (the helper's
    /// loop returns, and exits, the moment the socket closes). Without this
    /// hook, the reverse was not true: a dead helper left the worker
    /// running indefinitely, holding the listening port and every other
    /// session's pty open with no way left to open a new one -- exactly the
    /// half-alive state this module's docs call worse than a clean exit.
    ///
    /// Private: [`worker_clients`] is the one caller outside tests.
    #[cfg(test)]
    fn new_with_hook(
        sock: UnixStream,
        on_helper_gone: impl FnOnce() + Send + 'static,
        login_ended: LoginEndedSink,
    ) -> io::Result<HelperChannelSpawner> {
        Self::with_budget_hook(
            sock,
            Arc::new(ScreenBudget::new(BudgetLimits::default())),
            on_helper_gone,
            login_ended,
        )
    }

    fn with_budget_hook(
        sock: UnixStream,
        budget: Arc<ScreenBudget>,
        on_helper_gone: impl FnOnce() + Send + 'static,
        login_ended: LoginEndedSink,
    ) -> io::Result<HelperChannelSpawner> {
        Self::build(
            sock,
            budget,
            on_helper_gone,
            login_ended,
            CHANNEL_SEND_TIMEOUT,
            OPEN_REPLY_TIMEOUT,
        )
    }

    /// As [`HelperChannelSpawner::new`], with a send budget of the test's
    /// choosing: a test that has to watch a send give up should not wait
    /// out the production budget to see it.
    #[cfg(test)]
    pub(crate) fn with_send_timeout(
        sock: UnixStream,
        send_timeout: Duration,
    ) -> io::Result<HelperChannelSpawner> {
        Self::build(
            sock,
            Arc::new(ScreenBudget::new(BudgetLimits::default())),
            || {},
            Box::new(|_, _| {}),
            send_timeout,
            OPEN_REPLY_TIMEOUT,
        )
    }

    /// As [`HelperChannelSpawner::new`], with a budget for the helper's
    /// reply of the test's choosing -- the sibling of
    /// [`HelperChannelSpawner::with_send_timeout`] for the other of the two
    /// waits `spawn` makes. A test that has to watch an unanswered open be
    /// abandoned would otherwise spend [`OPEN_REPLY_TIMEOUT`] (six seconds,
    /// tied to the helper's own startup budget) doing it.
    #[cfg(test)]
    pub(crate) fn with_open_timeout(
        sock: UnixStream,
        open_timeout: Duration,
    ) -> io::Result<HelperChannelSpawner> {
        Self::build(
            sock,
            Arc::new(ScreenBudget::new(BudgetLimits::default())),
            || {},
            Box::new(|_, _| {}),
            CHANNEL_SEND_TIMEOUT,
            open_timeout,
        )
    }

    fn build(
        sock: UnixStream,
        budget: Arc<ScreenBudget>,
        on_helper_gone: impl FnOnce() + Send + 'static,
        login_ended: LoginEndedSink,
        send_timeout: Duration,
        open_timeout: Duration,
    ) -> io::Result<HelperChannelSpawner> {
        // Every send on this seam is bounded -- see `CHANNEL_SEND_TIMEOUT`.
        // The reader thread's clone below, and every `HelperWait`'s, share
        // this socket's open file description, so they inherit it too.
        sock.set_write_timeout(Some(send_timeout))?;
        let reading = sock.try_clone()?;
        let waiting: Arc<Mutex<HashMap<ChannelId, Pending>>> = Arc::new(Mutex::new(HashMap::new()));
        let waiting_thread = Arc::clone(&waiting);
        let disconnected_locally = Arc::new(AtomicBool::new(false));
        let disconnected_locally_thread = Arc::clone(&disconnected_locally);
        let stop_socket = sock.try_clone()?;
        let stop_flag = disconnected_locally.clone();
        let mut auxiliary = WorkerThreads::default();
        let reader = std::thread::Builder::new()
            .name(CHANNEL_READER_THREAD.to_string())
            .spawn(move || {
                read_loop(
                    reading,
                    waiting_thread,
                    disconnected_locally_thread,
                    on_helper_gone,
                    login_ended,
                );
                Ok(())
            })?;
        auxiliary.register(ThreadRole::ChannelReader, reader, move || {
            stop_flag.store(true, Ordering::SeqCst);
            stop_socket.shutdown(std::net::Shutdown::Both)
        });
        Ok(HelperChannelSpawner {
            opens: transport::channel_open::ChannelOpenRegistry::new(Default::default()),
            budget,
            tx: Mutex::new(sock),
            next_id: AtomicU64::new(1),
            waiting,
            disconnected_locally,
            open_timeout,
            auxiliary: Mutex::new(Some(auxiliary)),
        })
    }
}

impl Drop for HelperChannelSpawner {
    /// Standalone fixtures retain local custody. Production transfers it to
    /// the serving worker before Arc publication, so dropping a client cannot
    /// shut a seam while its global owner still owes an ordered thread drain.
    fn drop(&mut self) {
        if let Some(mut owner) = self
            .auxiliary
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            owner.stop_and_join();
        }
    }
}

/// Deliver every message the helper sends to whoever is waiting for that
/// channel id. Ends when the helper closes its end -- which is how the
/// worker learns the helper is gone (or, exactly as far as this thread can
/// tell from the wire, that the worker just disconnected itself; see
/// `disconnected_locally`, which is what tells the two apart in the log).
///
/// `on_helper_gone` runs exactly once, only on the "the helper is gone"
/// branch below -- never on a local disconnect, and never more than once,
/// since this loop returns right after either way.
fn read_loop(
    sock: UnixStream,
    waiting: Arc<Mutex<HashMap<ChannelId, Pending>>>,
    disconnected_locally: Arc<AtomicBool>,
    on_helper_gone: impl FnOnce(),
    login_ended: LoginEndedSink,
) {
    loop {
        let (bytes, fd) = match channel::recv(&sock) {
            Ok(Some(msg)) => msg,
            // The helper is gone -- or we just disconnected from it
            // ourselves; `disconnected_locally` says which. Either way,
            // drop every sender so nobody waits forever: a `spawn` in
            // flight gets an error, and a `wait` gets its channel closed
            // and returns rather than hanging. A `spawn` that inserts its
            // entry AFTER this point (the helper died before it was even
            // called) never gets that benefit from here -- but it does not
            // hang either, because its own `channel::send` on the
            // now-peerless socket fails first and it never reaches the
            // point of waiting; see `spawn`'s cleanup on that path.
            Ok(None) | Err(_) => {
                let pending = std::mem::take(
                    &mut *waiting.lock().expect("the waiting map is never poisoned"),
                );
                let mut wake = Vec::with_capacity(pending.len());
                for entry in pending.values() {
                    let mut receipt = entry.receipt.lock().unwrap_or_else(|e| e.into_inner());
                    receipt.connection_closed = true;
                    if let Some(notifier) = &receipt.reap_notify {
                        wake.push(notifier.clone());
                    }
                }
                drop(pending); // Drop one-shot senders before waking exact owners.
                for notifier in wake {
                    notifier.notify();
                }
                if disconnected_locally.load(Ordering::SeqCst) {
                    crate::log::warn(
                        "worker",
                        "helper connection closed locally (the spawner was \
                         dropped); any channel still open at that moment cannot report its \
                         real exit any more",
                    );
                } else {
                    crate::log::error("worker", "the helper is gone");
                    on_helper_gone();
                }
                return;
            }
        };
        let response = match decode::<Response>(&bytes) {
            Ok(r) => r,
            Err(e) => {
                crate::log::warn("worker", &e.to_string());
                continue;
            }
        };
        let mut map = waiting.lock().expect("the waiting map is never poisoned");
        match response {
            Response::Opened { id } => {
                let Some(pending) = map.get_mut(&id) else {
                    continue;
                };
                if pending.outcome == OpenOutcome::Waiting {
                    let tx = pending.opened.take().expect("one pending outcome");
                    let result = fd.ok_or_else(|| {
                        "the helper opened a channel but sent no terminal".to_string()
                    });
                    pending.outcome = if result.is_ok() {
                        OpenOutcome::Opened
                    } else {
                        OpenOutcome::Failed
                    };
                    if tx.send(result).is_err() {
                        pending.outcome = OpenOutcome::Abandoned;
                        pending.exited = None;
                    }
                }
                let close = matches!(
                    pending.outcome,
                    OpenOutcome::Failed | OpenOutcome::Abandoned
                );
                if pending.finished() {
                    map.remove(&id);
                }
                drop(map);
                if close {
                    if let Ok(bytes) = encode(&Request::Close { id }) {
                        let _ = channel::send(&sock, &bytes, None);
                    }
                }
            }
            Response::Failed { id, reason } => {
                let Some(pending) = map.get_mut(&id) else {
                    continue;
                };
                if pending.outcome == OpenOutcome::Waiting {
                    pending.outcome = OpenOutcome::Failed;
                    pending.exited = None;
                    if let Some(tx) = pending.opened.take() {
                        let _ = tx.send(Err(reason));
                    }
                }
                if pending.finished() {
                    map.remove(&id);
                }
            }
            Response::Exited { id, code } => {
                let Some(pending) = map.get_mut(&id) else {
                    continue;
                };
                if let Some(tx) = pending.exited.take() {
                    let _ = tx.send(code);
                }
                let notifier = {
                    let mut receipt = pending.receipt.lock().unwrap_or_else(|e| e.into_inner());
                    receipt.leader_notified = true;
                    receipt.reap_notify.clone()
                };
                if pending.finished() {
                    map.remove(&id);
                }
                drop(map);
                if let Some(notifier) = notifier {
                    notifier.notify();
                }
            }
            Response::CleanupComplete { id, kind } | Response::CleanupFailed { id, kind, .. } => {
                let failure = match response {
                    Response::CleanupFailed { failure, .. } => Some(failure),
                    _ => None,
                };
                // This connection owns this map. A new helper connection can
                // never satisfy an old ticket, even if its numeric IDs match.
                if fd.is_some() {
                    continue;
                }
                let Some(pending) = map.get_mut(&id) else {
                    continue;
                };
                let (notify, reap_notify) = {
                    let mut receipt = pending.receipt.lock().unwrap_or_else(|e| e.into_inner());
                    if receipt.kind.is_some() {
                        continue;
                    }
                    receipt.kind = Some(kind);
                    receipt.failure = failure;
                    if let Some(failure) = failure {
                        crate::log::warn(
                            "worker",
                            &format!("channel {id} physical cleanup completed with {failure:?}"),
                        );
                    }
                    (
                        receipt.cleanup_requested.then(|| receipt.notify.clone()),
                        receipt.reap_notify.clone(),
                    )
                };
                if pending.finished() {
                    map.remove(&id);
                }
                drop(map);
                // Never call the registry or backend while holding helper
                // map/ticket locks. A sticky receipt makes this path I/O-free.
                // A healthy Ready result may already have exited naturally;
                // recording that fact alone must never cancel its adoption.
                if let Some(notify) = notify {
                    let _ = notify.retry_cleanup();
                }
                if let Some(notify) = reap_notify {
                    notify.notify();
                }
            }
            // `HelperChannelSpawner` never sends `Request::Nonce` or
            // `Request::Verify` on this socket -- authentication has its own
            // seam (`HelperAuth`), and the helper drops either request
            // unanswered here -- so an answer to either arriving here would
            // be a protocol violation by the helper, or a message from a
            // test driving this loop directly. None of the four name a
            // channel id, so there is nothing to demultiplex any of them to;
            // log and drop.
            // Unsolicited, like `Exited`, but about a LOGIN rather than a
            // channel, so there is nothing in `waiting` to demultiplex it
            // to: it goes straight on to the router, which ends that
            // login's session. Dropping it here would leave the worker
            // holding a session that is sterile -- see
            // `Response::LoginEnded` and `LoginEndedSink`.
            //
            // The `waiting` lock is held across this call, as it is across
            // every other arm of this match. That is safe because the sink
            // never waits on anything outside this process (its own docs
            // require it, and the one in production is a `try_send`), and
            // it is deliberate: taking the lock per arm instead would be a
            // second place to get the ordering wrong for no gain.
            Response::LoginEnded { login, incarnation } => login_ended(login, incarnation),
            Response::Nonce { .. }
            | Response::NonceUnavailable
            | Response::Verified { .. }
            | Response::Refused { .. } => {
                crate::log::warn(
                    "worker",
                    "unexpected authentication response on the channel socket, \
                     ignoring",
                );
            }
        }
    }
}

impl HelperChannelSpawner {
    /// Suppress this open's outcome and request Close after possible creation.
    /// Keep the bounded ticket and custody until an exact cleanup receipt.
    /// A failed send or a disconnected helper leaves cleanup Unknown, not
    /// successful; neither proves that the process or its resources are gone.
    /// Takes the `tx` lock, so no caller may already hold it.
    fn abandon(&self, id: ChannelId) {
        let needs_close = {
            let mut map = self
                .waiting
                .lock()
                .expect("the waiting map is never poisoned");
            if let Some(pending) = map.get_mut(&id) {
                pending.outcome = OpenOutcome::Abandoned;
                pending.opened = None;
                pending.exited = None;
                if pending.finished() {
                    map.remove(&id);
                    false
                } else {
                    true
                }
            } else {
                true
            }
        };
        if needs_close {
            if let Ok(close) = encode(&Request::Close { id }) {
                let tx = self.tx.lock().expect("the helper socket is never poisoned");
                let _ = channel::send(&tx, &close, None);
            }
        }
    }
}

impl ChannelSpawner for HelperChannelSpawner {
    fn open_registry(&self) -> Arc<transport::channel_open::ChannelOpenRegistry> {
        self.opens.clone()
    }
    /// Asks for the channel on `owner`'s behalf: its uid goes into the
    /// request, and the helper opens the channel only if it verified that
    /// account itself -- through `HelperAuth`, when the session logged in.
    /// `login` goes into the request too, unchanged: the helper is the one
    /// that decides whether it may pair with `owner` (see
    /// `helper::server`'s `LoopState::logins`), never this worker.
    fn spawn(
        &self,
        owner: &Principal,
        login: LoginId,
        req: &OpenRequest,
        term: Option<&str>,
        custody: &transport::channel_open::OpenCustody,
    ) -> Result<transport::channel_open::UninstalledChannel, transport::channel_open::SpawnFailure>
    {
        self.spawn_with_clone(owner, login, req, term, custody, std::fs::File::try_clone)
    }
}

impl HelperChannelSpawner {
    // Descriptor preparation is fallible even after the helper reports Opened.
    // Keep it inside the same custody scope as the creating request.
    fn spawn_with_clone(
        &self,
        owner: &Principal,
        login: LoginId,
        req: &OpenRequest,
        term: Option<&str>,
        custody: &transport::channel_open::OpenCustody,
        mut clone_descriptor: impl FnMut(&std::fs::File) -> io::Result<std::fs::File>,
    ) -> Result<transport::channel_open::UninstalledChannel, transport::channel_open::SpawnFailure>
    {
        // The same refusal the personal mode's spawner gives, in the same
        // words: the two must not disagree about what a channel is.
        if req.cols == 0 || req.rows == 0 {
            return Err(custody.refuse_before_creation(
                "a channel without a terminal is not supported yet".to_string(),
            ));
        }
        terminal_size::TerminalSize::new(req.cols, req.rows)
            .map_err(|e| custody.refuse_before_creation(e.to_string()))?;
        let screen = make_screen(req, owner, Arc::clone(&self.budget))
            .map_err(|e| custody.refuse_before_creation(e))?;
        let (shell, command) = match req.kind {
            // The helper runs the account's login shell, from passwd as it
            // verified the account (`helper::server::login_shell`) -- never
            // anything the worker sends. The worker runs as an unprivileged
            // account of its own, whose shell is typically `nologin`:
            // resolving the shell HERE would exec that for every shell
            // channel rather than the account's real one.
            ChannelKind::Shell => (true, String::new()),
            // The command travels WHOLE and unparsed: the helper runs it as
            // `<account shell> -c <command>`, the `sshd` way, so the
            // account's own shell (`git-shell`, `rbash`, `nologin`, ...)
            // decides what it may do. The worker does not split it -- doing
            // so here would let `qsh git@host bash` walk out of a
            // `git-shell`. It must be valid UTF-8, which is all the worker
            // checks; the personal mode still splits argv itself
            // (`channel_backend::split_command`), because there one account
            // runs everything and there is no shell to confine anyone.
            ChannelKind::Command => (
                false,
                String::from_utf8(req.command.clone()).map_err(|e| {
                    custody.refuse_before_creation(format!("the command is not valid UTF-8: {e}"))
                })?,
            ),
        };
        // Echo ON for a shell (a full-screen program sets raw mode itself),
        // OFF for a command channel: today every one of those is the app's
        // `tmux -C` client, which must not be shown its own writes.
        let echo = matches!(req.kind, ChannelKind::Shell);

        // Never recycled: the helper refuses an `Open` naming an id that is
        // already live, so every request on this connection needs an id
        // that has never been used before, for as long as the connection
        // lasts.
        let tx = self.tx.lock().expect("the helper socket is never poisoned");
        let mut id = self.next_id.load(Ordering::Relaxed);
        loop {
            let next = id.checked_add(1).ok_or_else(|| {
                custody.refuse_before_creation("helper channel identity exhausted".into())
            })?;
            match self
                .next_id
                .compare_exchange_weak(id, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => break,
                Err(current) => id = current,
            }
        }

        let request = Request::Open {
            id,
            uid: owner.uid,
            name: owner.name.clone(),
            login,
            cols: req.cols,
            rows: req.rows,
            term: term.map(str::to_string),
            echo,
            shell,
            command,
        };
        // Encoded BEFORE the waiting-map entry is created, not after: a
        // request that fails `helper::protocol::MAX_MESSAGE_LEN`'s cap
        // (reachable -- `transport::channel::MAX_COMMAND_LEN` allows a
        // 4096-byte command, and JSON's mandatory escape for a control
        // character with no short named form, `\u00XX`, is six ASCII bytes
        // for one source byte, so a command built of those alone clears the
        // 8192-byte message cap several times over; see the test that pins
        // this relation) never reaches the helper and so never gets a
        // reply. An entry inserted before this point would then sit in
        // `waiting`, with both its senders, for the rest of the process's
        // life -- nobody left to remove it. Failing here, before either
        // sender exists, needs no such cleanup at all.
        let bytes = encode(&request).map_err(|e| {
            custody.refuse_before_creation(format!("could not ask for a channel: {e}"))
        })?;

        let (opened_tx, opened_rx) = mpsc::channel::<Result<OwnedFd, String>>();
        let (exited_tx, exited_rx) = mpsc::channel::<i32>();
        // Clone the close handle before sending any possibly creating request.
        let wait_tx = tx.try_clone().map_err(|e| {
            custody.refuse_before_creation(format!("closing the channel later: {e}"))
        })?;
        let receipt = Arc::new(Mutex::new(CleanupReceipt {
            kind: None,
            failure: None,
            cleanup_requested: false,
            notify: custody.cleanup_notifier(),
            reap_notify: None,
            leader_notified: false,
            connection_closed: false,
        }));
        let construction = custody.protect(
            Box::new(HelperWait {
                id,
                exits: exited_rx,
                leader_code: None,
                exits_closed: false,
                receipt: receipt.clone(),
                tx: wait_tx,
                disconnected_locally: self.disconnected_locally.clone(),
            }),
            screen,
        );

        self.waiting
            .lock()
            .expect("the waiting map is never poisoned")
            .insert(
                id,
                Pending {
                    opened: Some(opened_tx),
                    exited: Some(exited_tx),
                    outcome: OpenOutcome::Waiting,
                    receipt,
                },
            );

        let sent = channel::send(&tx, &bytes, None);
        drop(tx);
        if let Err(e) = sent {
            // A generic send error is not a receipt. Keep the bounded ticket
            // registered in case a delivered request later proves cleanup.
            self.abandon(id);
            return Err(custody.failure(format!("could not reach the helper: {e}")));
        }

        // Blocking on purpose: `ChannelSpawner::spawn` is synchronous, and
        // the personal mode's spawner blocks here too (it forks a process).
        // Bounded by `OPEN_REPLY_TIMEOUT` (see that constant's docs) rather
        // than an unbounded `recv`: a dead helper already closes the
        // socket, which the reader thread turns into an immediate error on
        // this same call without needing a timeout at all -- what the
        // bound catches is a helper that stays connected but simply never
        // answers.
        let fd = match opened_rx.recv_timeout(self.open_timeout) {
            Ok(result) => result.map_err(|reason| custody.failure(reason))?,
            Err(_) => {
                // A reply that was merely slow rather than lost would leave
                // a channel running with nothing holding a `ChannelWait`
                // able to close it -- see `abandon`.
                self.abandon(id);
                return Err(custody
                    .failure("the helper did not answer an open request in time".to_string()));
            }
        };

        // The helper has returned a live descriptor. Preparation can still
        // fail, so the construction guard already owns the wait handle and
        // screen. Abandon requests Close and suppresses late outcomes; only
        // the exact receipt releases the registered cleanup custody.
        let master = std::fs::File::from(fd);
        let mut clone = |what: &str| {
            clone_descriptor(&master).map_err(|e| {
                self.abandon(id);
                custody.failure(format!("{what}: {e}"))
            })
        };
        let reader = Box::new(clone("reading the channel")?);
        let writer = Box::new(clone("writing the channel")?);
        Ok(construction.finish(
            reader,
            writer,
            Box::new(MasterResize(clone("resizing the channel")?)),
        ))
    }
}

#[cfg(test)]
impl HelperChannelSpawner {
    fn spawn(
        &self,
        owner: &Principal,
        login: LoginId,
        req: &OpenRequest,
        term: Option<&str>,
    ) -> Result<SpawnedChannel, String> {
        crate::channel_backend::fixture_spawn(self, owner, login, req, term)
    }
}

/// Waits for a channel's process by listening for the helper's `Exited`.
struct HelperWait {
    id: ChannelId,
    exits: Receiver<i32>,
    leader_code: Option<i32>,
    exits_closed: bool,
    receipt: Arc<Mutex<CleanupReceipt>>,
    tx: UnixStream,
    /// Shared with the [`HelperChannelSpawner`] this channel came from --
    /// see that field's docs. Read only on the failure path of `wait`,
    /// where it decides which of two different facts the log records.
    disconnected_locally: Arc<AtomicBool>,
}

impl ChannelWait for HelperWait {
    fn active_observation(&self) -> transport::channel_server::ActiveObservation {
        transport::channel_server::ActiveObservation::Notification
    }
    fn set_reap_notifier(&mut self, notifier: transport::channel_server::ReapNotifier) {
        let evidence_ready = {
            let mut receipt = self.receipt.lock().unwrap_or_else(|e| e.into_inner());
            receipt.reap_notify = Some(notifier.clone());
            receipt.kind == Some(CleanupKind::Reaped)
                || receipt.leader_notified
                || receipt.connection_closed
        };
        // A receipt or leader/seam event may precede notifier installation.
        // Never notify under its lock: the observer reads the same receipt.
        if evidence_ready {
            notifier.notify();
        }
    }
    fn poll_leader_status(&mut self) -> Option<transport::channel_server::LeaderStatus> {
        use transport::channel_server::LeaderStatus;
        if self.leader_code.is_none() && !self.exits_closed {
            match self.exits.try_recv() {
                Ok(code) => self.leader_code = Some(code),
                Err(mpsc::TryRecvError::Disconnected) => self.exits_closed = true,
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(code) = self.leader_code {
            return Some(LeaderStatus::Exited { code: Some(code) });
        }
        let receipt = self.receipt.lock().unwrap_or_else(|e| e.into_inner());
        Some(if receipt.kind == Some(CleanupKind::Reaped) {
            LeaderStatus::Exited { code: None }
        } else if self.exits_closed || receipt.connection_closed {
            LeaderStatus::Unknown("helper exit receiver closed without cleanup proof".into())
        } else {
            LeaderStatus::Running
        })
    }
    fn poll_exit(&mut self) -> transport::channel_server::ChildStatus {
        use transport::channel_server::ChildStatus;
        let _ = self.poll_leader_status();
        let receipt = self.receipt.lock().unwrap_or_else(|e| e.into_inner());
        if receipt.kind == Some(CleanupKind::Reaped) {
            ChildStatus::Reaped {
                code: self.leader_code,
            }
        } else if self.exits_closed || receipt.connection_closed {
            ChildStatus::Unknown("helper exit receiver closed without cleanup proof".into())
        } else {
            ChildStatus::Running
        }
    }
    fn cleanup_uninstalled(
        &mut self,
        authority: &transport::channel_open::CleanupAuthority<'_>,
    ) -> transport::channel_open::CleanupStatus {
        // Check the sticky fact first: receipt-triggered retries must never
        // perform socket I/O on the reader thread or lose a pre-cancel receipt.
        let kind = {
            let mut receipt = self.receipt.lock().unwrap_or_else(|e| e.into_inner());
            receipt.cleanup_requested = true;
            receipt.kind
        };
        match kind {
            Some(CleanupKind::NoChild) => authority.no_child(),
            Some(CleanupKind::Reaped) => authority.reaped(),
            None => {
                self.kill();
                transport::channel_open::CleanupStatus::Unknown
            }
        }
    }
    fn kill(&mut self) {
        match encode(&Request::Close { id: self.id }) {
            Ok(bytes) => {
                if let Err(e) = channel::send(&self.tx, &bytes, None) {
                    crate::log::warn("worker", &format!("could not close a channel: {e}"));
                }
            }
            Err(e) => crate::log::warn("worker", &e.to_string()),
        }
    }

    fn wait(self: Box<Self>) -> i32 {
        if let Some(code) = self.leader_code {
            return code;
        }
        match self.exits.recv_timeout(HELPER_EXIT_TIMEOUT) {
            Ok(code) => code,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                // The helper never actually disconnected (that is the
                // `Disconnected` arm below) -- it simply never answered for
                // this id within HELPER_EXIT_TIMEOUT. See that constant's
                // docs for why this is a backstop, not the ordinary path.
                // `ChannelWait::wait`'s signature has no room for "unknown",
                // so this reports -1, the same failure code every arm here
                // uses; the log is where the distinction survives.
                crate::log::warn(
                    "worker",
                    &format!(
                        "channel {} has no exit code -- the helper did not answer \
                     within {HELPER_EXIT_TIMEOUT:?}",
                        self.id
                    ),
                );
                -1
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                // `ChannelWait::wait`'s signature has no room for "unknown"
                // -- every arm here reports -1, the same failure code
                // `spawn`'s own dead-helper case uses -- but they are not
                // the same fact, and a caller must never be told a process
                // exited when it may well still be running (the local-
                // disconnect case: the worker gave up on the helper while
                // this channel was still open, so nothing here actually
                // knows what became of it). The log is where the
                // distinction survives, since the return type cannot carry
                // it.
                if self.disconnected_locally.load(Ordering::SeqCst) {
                    crate::log::warn(
                        "worker",
                        &format!(
                            "channel {} has no exit code -- the worker disconnected \
                         from the helper while this channel was still open, its process's fate \
                         is unknown",
                            self.id
                        ),
                    );
                } else {
                    crate::log::warn(
                        "worker",
                        &format!("channel {} has no exit code -- the helper is gone", self.id),
                    );
                }
                -1
            }
        }
    }
}

/// Resizes a channel by its master side. `portable_pty` does this for the
/// personal mode; here the descriptor is all we have, so the ioctl is
/// direct.
struct MasterResize(std::fs::File);

impl ResizeHandle for MasterResize {
    fn try_resize(&self, cols: u16, rows: u16) -> Result<(), String> {
        terminal_size::TerminalSize::new(cols, rows).map_err(|e| e.to_string())?;
        let winsize = nix::pty::Winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: a winsize pointer and descriptor owned by this process.
        let result =
            unsafe { nix::libc::ioctl(self.0.as_raw_fd(), nix::libc::TIOCSWINSZ as _, &winsize) };
        if result == -1 {
            Err(format!(
                "resizing the terminal: {}",
                io::Error::last_os_error()
            ))
        } else {
            Ok(())
        }
    }
}

/// How long [`HelperAuth`] waits for the helper's answer to any request but
/// a verification -- a nonce, today -- before giving up on it; also the send
/// timeout on the worker's end of the authentication seam.
///
/// A nonce is a table insert in the helper and comes back at once, and the
/// helper's loop no longer keeps one request waiting behind another's work:
/// since task 3 a channel start, and since task 4 a proof's check, each runs
/// in a child of its own while the loop goes on answering. The one
/// exception is a verifying child's report that arrives in pieces -- a
/// verdict record can be longer than `PIPE_BUF` -- whose rest the loop
/// waits for, up to that verification's own deadline, and a nonce asked for
/// meanwhile can run out of this budget. Otherwise this budget only has to
/// outlast a loop that is running.
///
/// A verification is different, and waits longer, for a budget derived
/// from the helper's own deadline for checking a proof -- see
/// [`VERIFY_ANSWER_MARGIN`]. Its verdict comes back when the verifying child
/// reports, which a slow account database can stretch to that whole
/// deadline.
///
/// Nothing on this side makes one call wait for another's answer. One reader
/// thread takes every answer off the seam and hands it to the call that
/// asked, by the number its request carried (see [`AuthRequest`]), and a
/// call holds the seam's send lock only while it takes that number and
/// sends -- never while it waits. A nonce asked for while four slow
/// verifications are in flight is therefore sent at once, and given up on at
/// this budget whatever they do.
///
/// `ask` fixes its deadline before it takes the send lock, and a call whose
/// deadline passed while it waited for that lock sends nothing at all. The
/// wait is ordinarily one send long, but a send to a helper that has
/// stopped reading blocks for up to this budget (the socket's send timeout),
/// and `std::sync::Mutex` is not fair, so it is not a hard bound: a call can
/// sit out several such sends in turn before it finds its deadline gone.
/// Nor is a call's own send cut short by its deadline: one that gets the
/// lock with a sliver of its budget left can still block for a whole send
/// timeout on a full socket.
///
/// `release` and `login_ended` wait for nothing: they queue their tell and
/// return, and the release thread sends it -- one tell per hold of the send
/// lock, each send bounded by the socket's send timeout, this budget. A
/// request sends everything queued before it, within its own deadline,
/// before it goes out itself -- and while a login's end waits to be sent
/// again after a failed send, a request fails at once instead (see
/// `AuthSeam::login_end_stuck`). The reader thread never waits for the send
/// lock either: a nonce that came back too late for its call goes to the
/// release thread (see [`AuthSeam::drop_late_answer`]), so a send stuck on a
/// full socket holds up tells, never the delivery of an answer.
///
/// Every one of these calls is synchronous, which is why bounding them at
/// all matters. The session router calls `release` and `login_ended` right
/// on its own task -- through the nonce pool and as the `LoginSink` -- and
/// that is why those two only queue. `issue` is called only by the nonce
/// pool (`crate::nonce_pool`), from its own thread, and up to `POOL_TARGET`
/// times while the pool starts; never by the router -- see
/// [`HelperAuth::issue`]. A probation calls `verify` on the runtime's
/// blocking pool (`AuthVerifier` is blocking by design).
pub const HELPER_ANSWER_TIMEOUT: Duration = Duration::from_secs(2);

/// How much longer than the helper's own deadline for checking a proof
/// (`HelperConfig::verify_timeout`) the worker waits for that proof's
/// verdict.
///
/// The two budgets come from one value, the helper's config, which both
/// halves hold from before the fork -- see [`verify_answer_timeout`]. The
/// worker must not give up first: a verdict that lands after the worker
/// stopped waiting is dropped here, and if it was an admission the helper
/// has already trusted the account and opened a login entry for a handshake
/// the transport refused, which it can keep for up to its own
/// `LOGIN_GRACE`.
///
/// Equal budgets would not be enough. The helper starts its clock when its
/// loop picks the request up, later than the worker started its own, and
/// refuses a proof that ran out of time only once its loop notices. The
/// margin covers a loop that is running; it is not a hard bound, since a
/// loop held up for longer -- by a send to a worker that is not reading,
/// which may take up to its own send timeout -- can still answer past it. One
/// second, the same margin [`OPEN_REPLY_TIMEOUT`] leaves over the helper's
/// startup deadline.
const VERIFY_ANSWER_MARGIN: Duration = Duration::from_secs(1);

/// How long the worker waits for a verdict, given the settings the helper
/// runs with: the helper's deadline for producing one, plus
/// [`VERIFY_ANSWER_MARGIN`].
fn verify_answer_timeout(helper: &HelperConfig) -> Duration {
    helper.verify_timeout + VERIFY_ANSWER_MARGIN
}

/// What a waiting call is handed: the helper's answer, or why none will
/// come.
type Delivery = Result<Response, AuthError>;

/// How the reader thread takes the next message off the seam --
/// `channel::recv` outside tests. A parameter only so a test can stop the
/// reader on command without closing the helper's end (see
/// `HelperAuth::with_reader`).
type RecvMessage = fn(&UnixStream) -> io::Result<Option<(Vec<u8>, Option<OwnedFd>)>>;

/// How a request goes out on the seam -- [`send_request`] outside tests. A
/// parameter only so a test can hold a call between its send and whatever
/// comes after it, and so show that nothing a call needs for its answer is
/// left until then (see `HelperAuth::with_io`).
type SendMessage = fn(&UnixStream, &[u8]) -> io::Result<()>;

type SpawnAuxiliary = fn(
    &str,
    Box<dyn FnOnce() -> io::Result<()> + Send>,
) -> io::Result<std::thread::JoinHandle<io::Result<()>>>;

fn spawn_auxiliary(
    name: &str,
    body: Box<dyn FnOnce() -> io::Result<()> + Send>,
) -> io::Result<std::thread::JoinHandle<io::Result<()>>> {
    std::thread::Builder::new()
        .name(name.to_string())
        .spawn(body)
}

/// What a failed send on the seam is called in the log and in errors. A send
/// that timed out on a full socket -- the helper has stopped reading -- says
/// so, rather than "Resource temporarily unavailable".
fn describe_send_error(e: &io::Error) -> String {
    match e.kind() {
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
            "the helper is not reading (a send timed out)".to_string()
        }
        _ => e.to_string(),
    }
}

/// One request out on the seam: no request on this seam carries a
/// descriptor.
fn send_request(sock: &UnixStream, bytes: &[u8]) -> io::Result<()> {
    channel::send(sock, bytes, None)
}

/// The worker's end of the authentication seam: asks the helper for the
/// nonces handshakes' msg2 carry, and for the verdict on the proof that
/// comes back. ONE value is the [`AuthVerifier`] and the [`LoginSink`] of the
/// system mode's `ServerAuth`, and the one client its nonce pool draws from
/// -- one seam, one send lock, one numbering.
///
/// It is deliberately NOT a
/// [`NonceSource`](transport::session_manager::NonceSource): the session
/// router asks its source for a nonce on the task that routes every live
/// session, and [`HelperAuth::issue`] waits for the helper. The router's
/// source is the pool ([`PooledNonces`](crate::nonce_pool::PooledNonces)),
/// which hands out nonces this client fetched earlier, from a thread of its
/// own. Without the trait, this client cannot be put in the pool's place by
/// mistake: that does not compile.
///
/// The worker deliberately decides nothing here. It cannot read another
/// account's `authorized_keys` -- it has no privilege to -- and it must not
/// be believed if it claims somebody authenticated: that claim is exactly
/// what a taken-over worker would make. So this forwards the proof and
/// reports the helper's verdict, whichever way it goes.
///
/// Every request carries a number (see [`AuthRequest`]'s docs for what an
/// unnumbered answer would allow), and a reader thread of this value's own
/// hands each answer to the call waiting on that number, so any number of
/// calls can wait at once. An answer whose call has stopped waiting is late,
/// and is dropped: never handed to another call. A nonce in one is released
/// by a second thread, so that the reader never waits to send anything. One numbered above
/// anything asked so far cannot come from an honest helper, and fails every
/// call then waiting.
///
/// If the reader thread ends -- the helper is gone, or the reader itself
/// stopped -- every waiting call is woken at once, every later call fails
/// before it sends anything, and the worker ends (see `worker_clients`).
pub struct HelperAuth {
    seam: Arc<AuthSeam>,
    /// The budget of every request but a verification --
    /// [`HELPER_ANSWER_TIMEOUT`] outside tests.
    timeout: Duration,
    /// The budget of a verification -- [`verify_answer_timeout`] of the
    /// helper's config outside tests.
    verify_timeout: Duration,
    /// Wakes the release thread: tells are queued, or -- from a test that
    /// drives [`AuthSeam::route`] itself -- a late nonce. The reader holds a
    /// sender of its own.
    late: Sender<Wake>,
    auxiliary: Mutex<Option<WorkerThreads>>,
}

/// What [`HelperAuth`] and its reader thread share.
///
/// Two locks, always taken in this order when both are needed -- `sender`,
/// then `waiters` -- and neither is ever held while a call waits for its
/// answer. `waiters` is never held across any input or output at all.
struct AuthSeam {
    /// The sending side. Held for one send at a time, together with taking
    /// that send's number, so the helper sees the numbers in order.
    sender: Mutex<UnixStream>,
    /// How each request is sent -- see [`SendMessage`].
    send: SendMessage,
    waiters: Mutex<Waiters>,
    /// Set by `HelperAuth`'s `Drop`, before it shuts the connection down,
    /// so the reader can tell "the worker let go of this seam" from "the
    /// helper died" -- the same distinction, for the same reason,
    /// [`HelperChannelSpawner`]'s own flag of this name draws.
    disconnected_locally: AtomicBool,
    /// Tells waiting to be sent, oldest first -- see
    /// [`AuthSeam::queue_tell`]. Taken off only by whoever holds `sender`,
    /// so they leave in the order they were queued. Never held across any
    /// input or output.
    tells: Mutex<Tells>,
    late_after_seal: Arc<AtomicBool>,
    /// Tell sends that failed since the last one that did not -- counted for
    /// the log, which says so at 1, 2, 4, 8... in a row.
    failed_tell_sends: AtomicU64,
    /// Releases dropped because too many were queued -- counted for the log
    /// the same way.
    dropped_releases: AtomicU64,
    /// Set while a login's end, first in the queue, waits to be sent again
    /// after a send of it failed; cleared once one is sent. While it is set,
    /// a request fails at once without touching the socket (see
    /// [`HelperAuth::ask_by`]): nothing may go out ahead of that end, and a
    /// request that tried it again itself would only hold the send lock for
    /// a send timeout, with every other request queued behind it.
    login_end_stuck: AtomicBool,
    /// Ends the worker -- see [`EndWorker`].
    end_worker: EndWorker,
}

/// The queue of tells, with how many of each kind it holds -- each kind has
/// its own bound ([`MAX_QUEUED_RELEASES`], [`MAX_QUEUED_LOGIN_ENDS`]).
#[derive(Default)]
struct Tells {
    sealed: bool,
    queue: VecDeque<Request>,
    releases: usize,
    login_ends: usize,
}

impl Tells {
    fn count(&mut self, body: &Request, added: bool) {
        let kind = match body {
            Request::LoginEnded { .. } => &mut self.login_ends,
            _ => &mut self.releases,
        };
        if added {
            *kind += 1;
        } else {
            *kind -= 1;
        }
    }

    fn push_back(&mut self, body: Request) {
        self.count(&body, true);
        self.queue.push_back(body);
    }

    fn push_front(&mut self, body: Request) {
        self.count(&body, true);
        self.queue.push_front(body);
    }

    fn pop_front(&mut self) -> Option<Request> {
        let body = self.queue.pop_front()?;
        self.count(&body, false);
        Some(body)
    }
}

/// Who is waiting for which answer.
struct Waiters {
    /// The number the next request carries. Every number below it has been
    /// handed out; none at or above it has.
    next_id: AuthRequestId,
    /// The calls waiting for an answer, by the number of their request.
    waiting: HashMap<AuthRequestId, Waiter>,
    /// Set once the reader thread has ended: from then on nothing will ever
    /// deliver an answer, so a call must not even send.
    reader_gone: bool,
}

/// One call waiting for its answer.
struct Waiter {
    answer: Sender<Delivery>,
    /// When the call stops waiting. An answer that reaches the reader at or
    /// after this is late, even if the call has not taken itself off the
    /// table yet.
    deadline: Instant,
}

impl AuthSeam {
    /// The send lock. A lock poisoned by a panic is taken anyway: it guards
    /// a socket and nothing else, and the numbering is what keeps whatever
    /// the interrupted call left on the wire from being taken for anybody
    /// else's answer.
    fn lock_sender(&self) -> MutexGuard<'_, UnixStream> {
        self.sender
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The waiters' table, taken the same way: nothing that holds it can
    /// leave it half-changed -- every change is one map operation or one
    /// flag.
    fn lock_waiters(&self) -> MutexGuard<'_, Waiters> {
        self.waiters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The number for the next request that nobody waits an answer for.
    /// Called with the send lock held, so requests go out in the order of
    /// their numbers.
    fn take_id(&self) -> AuthRequestId {
        let mut waiters = self.lock_waiters();
        let id = waiters.next_id;
        waiters.next_id += 1;
        id
    }

    /// The number for the next request, with `waiter` already on the table
    /// under it -- in one step, so no request can be numbered, and so none
    /// sent, before the entry its answer goes to exists: an answer that came
    /// back before its entry would be taken for a late one and dropped, and
    /// its call would wait out its whole budget for nothing. Called with the
    /// send lock held, like [`AuthSeam::take_id`].
    ///
    /// Refused once the reader has ended: the request would get an answer
    /// that nothing can ever deliver.
    fn register(&self, waiter: Waiter) -> Result<AuthRequestId, AuthError> {
        let mut waiters = self.lock_waiters();
        if waiters.reader_gone {
            return Err(helper_gone());
        }
        let id = waiters.next_id;
        waiters.next_id += 1;
        waiters.waiting.insert(id, waiter);
        Ok(id)
    }

    /// Stop waiting for the answer to request `id`. `false` when the reader
    /// had already taken the entry -- to hand an answer over, or to drop it.
    fn forget(&self, id: AuthRequestId) -> bool {
        self.lock_waiters().waiting.remove(&id).is_some()
    }

    /// Send a request nobody waits an answer for. `sender` is the send
    /// lock's guard: the caller holds it.
    fn tell(&self, sender: &UnixStream, body: Request) -> Result<(), String> {
        let id = self.take_id();
        let bytes = encode(&AuthRequest { id, body }).map_err(|e| e.to_string())?;
        (self.send)(sender, &bytes).map_err(|e| describe_send_error(&e))
    }

    /// The queue of tells, taken the same way as the other two locks:
    /// every change under it is one push or pop and its count.
    fn lock_tells(&self) -> MutexGuard<'_, Tells> {
        self.tells
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Queue a tell -- `ReleaseNonce` or `LoginEnded` -- touching neither the
    /// socket nor the send lock: the session router calls this on the task
    /// that routes every session.
    ///
    /// Past its kind's bound, a release is dropped, with a line in the log
    /// (see [`MAX_QUEUED_RELEASES`]). A login's end is not: the worker is
    /// ended instead (see [`MAX_QUEUED_LOGIN_ENDS`]), and the end is queued
    /// all the same if the queue remains open when a returning hook completes.
    fn queue_tell(&self, body: Request) {
        let mut tells = self.lock_tells();
        if tells.sealed {
            self.late_after_seal.store(true, Ordering::SeqCst);
            return;
        }
        let over_bound = match body {
            Request::LoginEnded { .. } => tells.login_ends >= MAX_QUEUED_LOGIN_ENDS,
            _ => tells.releases >= MAX_QUEUED_RELEASES,
        };
        if over_bound {
            drop(tells);
            if !matches!(body, Request::LoginEnded { .. }) {
                let dropped = self.dropped_releases.fetch_add(1, Ordering::SeqCst) + 1;
                if dropped.is_power_of_two() {
                    crate::log::warn(
                        "worker",
                        &format!(
                            "{dropped} nonce releases dropped so far -- too many were \
                         waiting for the helper; it expires each such nonce on its own"
                        ),
                    );
                }
                return;
            }
            (self.end_worker)(LOGIN_ENDS_OVERFLOW_REASON);
            tells = self.lock_tells();
            if tells.sealed {
                self.late_after_seal.store(true, Ordering::SeqCst);
                return;
            }
        }
        tells.push_back(body);
    }

    /// Send the oldest queued tell, if there is one: `Ok(false)` when there
    /// was none. `sender` is the send lock's guard: the caller holds it.
    ///
    /// A release that cannot be sent is given up -- the helper expires its
    /// nonce on its own. A login's end that cannot be sent goes back to the
    /// front of the queue, and the failure is returned: nothing queued after
    /// it may be sent before it.
    fn send_next_tell(&self, sender: &UnixStream) -> Result<bool, String> {
        let Some(body) = self.lock_tells().pop_front() else {
            return Ok(false);
        };
        let Err(e) = self.tell(sender, body.clone()) else {
            self.failed_tell_sends.store(0, Ordering::SeqCst);
            if matches!(body, Request::LoginEnded { .. }) {
                self.login_end_stuck.store(false, Ordering::SeqCst);
            }
            return Ok(true);
        };
        let failed = self.failed_tell_sends.fetch_add(1, Ordering::SeqCst) + 1;
        if failed.is_power_of_two() {
            crate::log::warn(
                "worker",
                &format!(
                    "could not send the helper a tell ({e}); {failed} such sends have \
                 failed in a row -- a release is given up, the helper expires its nonce on its \
                 own; the end of a login is kept and sent again"
                ),
            );
        }
        if matches!(body, Request::LoginEnded { .. }) {
            self.lock_tells().push_front(body);
            self.login_end_stuck.store(true, Ordering::SeqCst);
            return Err(e);
        }
        Ok(true)
    }

    /// Send every queued tell, oldest first -- what a request does before it
    /// goes out, so that nothing queued before it reaches the helper after
    /// it. `Err` if any is left: a login's end that could not be sent, or
    /// `deadline` reached first. `sender` is the send lock's guard.
    fn flush_tells(&self, sender: &UnixStream, deadline: Instant) -> Result<(), String> {
        loop {
            if Instant::now() >= deadline && !self.lock_tells().queue.is_empty() {
                return Err("out of time sending the tells queued before this request".to_string());
            }
            if !self.send_next_tell(sender)? {
                return Ok(());
            }
        }
    }

    /// Send whatever is queued, one tell per hold of the send lock, so that
    /// a send stuck on a full socket holds a request up for one send timeout
    /// at most, not for the whole queue -- the release thread's work. `Err`
    /// when a login's end could not be sent: it is first in the queue again.
    fn send_queued(&self) -> Result<(), String> {
        loop {
            let sender = self.lock_sender();
            if !self.send_next_tell(&sender)? {
                return Ok(());
            }
        }
    }

    /// Hand one answer to the call waiting for it, or deal with it as late
    /// or as a protocol violation. A nonce that nobody will take goes to
    /// `late_nonces`, to be released by a thread of its own.
    fn route(&self, answer: AuthResponse, late_nonces: &Sender<Wake>) {
        let AuthResponse { id, body } = answer;
        let late = {
            let mut waiters = self.lock_waiters();
            match waiters.waiting.remove(&id) {
                Some(waiter) if Instant::now() < waiter.deadline => {
                    // A call that has stopped waiting since is still the one
                    // this answer belongs to, and takes it from its channel.
                    let _ = waiter.answer.send(Ok(body));
                    return;
                }
                // Its call's deadline has passed: late, even though the call
                // has not taken itself off the table yet. Dropping the entry
                // wakes that call, which reports its own timeout.
                Some(_) => body,
                // Its call has already stopped waiting.
                None if id < waiters.next_id => body,
                None => {
                    let violation = format!(
                        "the helper answered request {id}, which was never asked -- a protocol \
                         violation"
                    );
                    // Nothing that helper says can be matched to a question
                    // on trust any more; every call now waiting is failed
                    // rather than handed whatever comes next. The seam stays
                    // open for later calls: their answers are matched by
                    // number like any other. Logged once the table is let
                    // go -- it is never held across output.
                    let failed: Vec<Waiter> = waiters.waiting.drain().map(|(_, w)| w).collect();
                    drop(waiters);
                    crate::log::warn("worker", &violation.to_string());
                    for waiter in failed {
                        let _ = waiter
                            .answer
                            .send(Err(AuthError::Backend(violation.clone())));
                    }
                    // A nonce in it is released all the same: whatever the
                    // helper meant by it, nobody here will spend it.
                    if let Response::Nonce { nonce } = body {
                        hand_to_releaser(late_nonces, nonce);
                    }
                    return;
                }
            }
        };
        self.drop_late_answer(id, late, late_nonces);
    }

    /// A late answer is dropped, with a line in the log. One that carries a
    /// nonce is released on the spot as well: the handshake it was issued
    /// for stopped waiting for it when its call gave up, so nothing will
    /// ever spend it, and left alone it would hold one of the helper's
    /// limited slots until it expired.
    ///
    /// Never released from here, by the reader: the send lock may be held
    /// by a send stuck on a full socket, and every other answer -- a verdict
    /// in time among them -- would wait behind it. The releaser thread
    /// sends it; if that thread is gone, the helper expires the nonce on its
    /// own.
    fn drop_late_answer(&self, id: AuthRequestId, body: Response, late_nonces: &Sender<Wake>) {
        crate::log::warn(
            "worker",
            &format!("dropping the helper's late answer to request {id}"),
        );
        if let Response::Nonce { nonce } = body {
            hand_to_releaser(late_nonces, nonce);
        }
    }
}

/// Hand a nonce nobody will spend to the release thread -- or, if that
/// thread is gone, say so: the nonce then stays in the helper until it
/// expires there.
fn hand_to_releaser(late_nonces: &Sender<Wake>, nonce: Nonce) {
    if late_nonces.send(Wake::Late(nonce)).is_err() {
        crate::log::warn("worker", LATE_NONCE_NOT_RELEASED_LOG);
    }
}

/// The release thread's whole body: whenever it is woken -- a late nonce to
/// give back, tells queued -- it sends everything queued, until nothing can
/// wake it any more. A login's end whose send failed is sent again after
/// [`TELL_RETRY_DELAY`], woken or not. If the thread stops any other way --
/// a panic -- its [`ReleaserExit`] says so, and ends the worker.
fn send_tells(seam: Arc<AuthSeam>, wakes: Receiver<Wake>) -> io::Result<()> {
    let _exit = ReleaserExit {
        seam: Arc::clone(&seam),
    };
    let mut retry = false;
    loop {
        let wake = if retry {
            wakes.recv_timeout(TELL_RETRY_DELAY)
        } else {
            wakes
                .recv()
                .map_err(|_| mpsc::RecvTimeoutError::Disconnected)
        };
        match wake {
            Ok(Wake::Late(nonce)) => seam.queue_tell(Request::ReleaseNonce { nonce }),
            Ok(Wake::Flush) | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Ok(Wake::Finish(deadline)) => {
                // Reader/pool/manager producers must have settled before a
                // qualified finish. Seal atomically; any later required tell
                // remains a retained owner fault, not a successful silent drop.
                seam.lock_tells().sealed = true;
                let sender = seam.lock_sender();
                let flushed = seam
                    .flush_tells(&sender, deadline)
                    .map_err(io::Error::other);
                let closed = sender.shutdown(std::net::Shutdown::Write);
                return flushed.and(closed);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
        retry = seam.send_queued().is_err();
    }
}

/// Runs when the release thread ends. The ordinary end -- every sender
/// gone, the reader first among them -- is nothing to report. A panic is
/// logged and ends the worker: the thread carries the ends of logins, and a
/// login the helper is never told has ended stays trusted.
struct ReleaserExit {
    seam: Arc<AuthSeam>,
}

impl Drop for ReleaserExit {
    fn drop(&mut self) {
        if std::thread::panicking() {
            crate::log::error("worker", RELEASE_THREAD_GONE_LOG);
            (self.seam.end_worker)(RELEASE_THREAD_GONE_REASON);
        }
    }
}

/// The reader thread's whole body: every answer on the seam goes to
/// [`AuthSeam::route`] until the seam closes. However the thread ends -- the
/// helper closed its end, a receive failed, or the thread panicked -- its
/// [`ReaderExit`] wakes every waiting call and, unless the worker let go of
/// the seam itself, runs `on_helper_gone`.
fn read_answers(
    seam: Arc<AuthSeam>,
    sock: UnixStream,
    recv: RecvMessage,
    on_helper_gone: Box<dyn FnOnce() + Send>,
    late_nonces: Sender<Wake>,
) {
    let _exit = ReaderExit {
        seam: Arc::clone(&seam),
        on_helper_gone: Some(on_helper_gone),
    };
    loop {
        let bytes = match recv(&sock) {
            Ok(Some((bytes, fd))) => {
                // No answer on this seam carries a descriptor. One that did
                // is closed here, unused, rather than leaked.
                drop(fd);
                bytes
            }
            Ok(None) => return,
            Err(e) => {
                crate::log::warn(
                    "worker",
                    &format!("receiving on the authentication seam failed: {e}"),
                );
                return;
            }
        };
        match decode::<AuthResponse>(&bytes) {
            Ok(answer) => seam.route(answer, &late_nonces),
            // Carries no number anybody could be matched to: logged and
            // dropped, and whoever it was meant for runs out its own
            // deadline -- the channel seam's reader treats an unreadable
            // message the same way. Not a reason to stop reading: every
            // other answer still carries its number.
            Err(e) => crate::log::warn("worker", &format!("the helper's answer: {e}")),
        }
    }
}

/// Runs when the reader thread ends, by whatever way it ends -- a `Drop`
/// rather than code after the loop, so a panic in the reader is covered too.
struct ReaderExit {
    seam: Arc<AuthSeam>,
    on_helper_gone: Option<Box<dyn FnOnce() + Send>>,
}

impl Drop for ReaderExit {
    fn drop(&mut self) {
        // Nothing will deliver an answer again. Dropping every entry wakes
        // its call at once, and the flag makes every later call fail before
        // it sends.
        {
            let mut waiters = self.seam.lock_waiters();
            waiters.reader_gone = true;
            waiters.waiting.clear();
        }
        if self.seam.disconnected_locally.load(Ordering::SeqCst) {
            crate::log::info(
                "worker",
                "authentication seam closed locally (its client was dropped)",
            );
            return;
        }
        if std::thread::panicking() {
            crate::log::warn(
                "worker",
                "the authentication seam's reader stopped; no answer from the helper \
                 can be read any more",
            );
        } else {
            crate::log::error("worker", AUTH_SEAM_CLOSED_LOG);
        }
        if let Some(on_helper_gone) = self.on_helper_gone.take() {
            on_helper_gone();
        }
    }
}

fn helper_gone() -> AuthError {
    AuthError::Backend("the helper is gone: no answer from it can be read any more".to_string())
}

fn timed_out(budget: Duration) -> AuthError {
    AuthError::Backend(format!("the helper did not answer within {budget:?}"))
}

impl HelperAuth {
    /// Production takes custody before publishing this client in an Arc.
    pub(crate) fn take_auxiliary(&mut self) -> WorkerThreads {
        self.auxiliary
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .expect("authentication thread custody is transferred once")
    }

    /// Take the worker's end of the authentication seam, and start its
    /// reader thread.
    ///
    /// `helper` is the configuration the helper runs with -- the daemon
    /// passes the very value it hands the helper on the other side of the
    /// fork -- and the wait for a verdict is derived from it (see
    /// [`VERIFY_ANSWER_MARGIN`]).
    ///
    /// Does not end the process if the reader thread later finds the helper
    /// gone; [`HelperAuth::new_with_hook`] does, and is what
    /// `split_and_run`'s worker uses. Kept separate for the same reason
    /// [`HelperChannelSpawner::new`] is, and test-only for the same reason
    /// too.
    #[cfg(test)]
    pub(crate) fn new(sock: UnixStream, helper: &HelperConfig) -> io::Result<HelperAuth> {
        HelperAuth::new_with_hook(sock, helper, ignore_the_end())
    }

    /// As [`HelperAuth::new`], but calls `end_worker` when the worker can no
    /// longer keep up its side of the seam: from the reader thread once it
    /// ends for any reason other than this value being dropped -- the helper
    /// closed its end, or the reader itself stopped; from the release thread
    /// if it stops by a panic; and wherever a login's end would otherwise be
    /// lost ([`MAX_QUEUED_LOGIN_ENDS`]). No verdict can reach the worker any
    /// more, or the helper would go on trusting a login that ended, and a
    /// worker in either state is the half-alive one `helper`'s docs call
    /// worse than a clean exit.
    ///
    /// Fails only if the socket refuses its timeouts or a thread cannot
    /// start. Private: [`worker_clients`] is the one caller outside tests.
    fn new_with_hook(
        sock: UnixStream,
        helper: &HelperConfig,
        end_worker: EndWorker,
    ) -> io::Result<HelperAuth> {
        let on_helper_gone = {
            let end_worker = Arc::clone(&end_worker);
            Box::new(move || end_worker(HELPER_GONE_REASON))
        };
        HelperAuth::build(
            sock,
            HELPER_ANSWER_TIMEOUT,
            verify_answer_timeout(helper),
            on_helper_gone,
            end_worker,
            channel::recv,
            send_request,
        )
    }

    /// As [`HelperAuth::with_timeout`], with requests going out through
    /// `send` and `end_worker` called wherever the daemon's client would end
    /// the worker -- for a test that has to watch that happen.
    #[cfg(test)]
    pub(crate) fn with_end_worker(
        sock: UnixStream,
        timeout: Duration,
        send: SendMessage,
        end_worker: EndWorker,
    ) -> io::Result<HelperAuth> {
        HelperAuth::build(
            sock,
            timeout,
            timeout,
            Box::new(|| {}),
            end_worker,
            channel::recv,
            send,
        )
    }

    /// As [`HelperAuth::new`], with one budget of the test's choosing for
    /// every request, verifications included: a test that has to watch a
    /// call give up should not wait out a production budget to see it.
    #[cfg(test)]
    pub(crate) fn with_timeout(sock: UnixStream, timeout: Duration) -> io::Result<HelperAuth> {
        HelperAuth::with_timeouts(sock, timeout, timeout)
    }

    /// As [`HelperAuth::with_timeout`], with the verification budget chosen
    /// separately.
    #[cfg(test)]
    pub(crate) fn with_timeouts(
        sock: UnixStream,
        timeout: Duration,
        verify_timeout: Duration,
    ) -> io::Result<HelperAuth> {
        HelperAuth::build(
            sock,
            timeout,
            verify_timeout,
            Box::new(|| {}),
            ignore_the_end(),
            channel::recv,
            send_request,
        )
    }

    /// As [`HelperAuth::with_timeouts`], with a hook, and with the reader
    /// taking its messages through `recv`: a test that has to stop the
    /// reader without closing the helper's end hands in one that stops.
    #[cfg(test)]
    fn with_reader(
        sock: UnixStream,
        timeout: Duration,
        verify_timeout: Duration,
        on_helper_gone: impl FnOnce() + Send + 'static,
        recv: RecvMessage,
    ) -> io::Result<HelperAuth> {
        HelperAuth::with_io(
            sock,
            timeout,
            verify_timeout,
            on_helper_gone,
            recv,
            send_request,
        )
    }

    /// As [`HelperAuth::with_reader`], with requests going out through
    /// `send` as well.
    #[cfg(test)]
    fn with_io(
        sock: UnixStream,
        timeout: Duration,
        verify_timeout: Duration,
        on_helper_gone: impl FnOnce() + Send + 'static,
        recv: RecvMessage,
        send: SendMessage,
    ) -> io::Result<HelperAuth> {
        HelperAuth::build(
            sock,
            timeout,
            verify_timeout,
            Box::new(on_helper_gone),
            ignore_the_end(),
            recv,
            send,
        )
    }

    fn build(
        sock: UnixStream,
        timeout: Duration,
        verify_timeout: Duration,
        on_helper_gone: Box<dyn FnOnce() + Send>,
        end_worker: EndWorker,
        recv: RecvMessage,
        send: SendMessage,
    ) -> io::Result<HelperAuth> {
        Self::build_with_spawn(
            sock,
            timeout,
            verify_timeout,
            on_helper_gone,
            end_worker,
            recv,
            send,
            spawn_auxiliary,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn build_with_spawn(
        sock: UnixStream,
        timeout: Duration,
        verify_timeout: Duration,
        on_helper_gone: Box<dyn FnOnce() + Send>,
        end_worker: EndWorker,
        recv: RecvMessage,
        send: SendMessage,
        spawn: SpawnAuxiliary,
    ) -> io::Result<HelperAuth> {
        // A send to a helper that has stopped reading fails within the
        // budget a nonce's answer gets, instead of blocking forever -- and
        // holding the send lock all that while -- once the socket's buffer
        // is full.
        sock.set_write_timeout(Some(timeout))?;
        // The reader waits for the next answer however long it takes: a
        // helper with nothing to say is not a helper that is gone. A read
        // timeout left on the socket by whoever made it -- the tests'
        // harness sets one -- would be taken for exactly that, and would end
        // the reader, and the worker with it.
        sock.set_read_timeout(None)?;
        let reading = sock.try_clone()?;
        let seam = Arc::new(AuthSeam {
            sender: Mutex::new(sock),
            send,
            waiters: Mutex::new(Waiters {
                next_id: 1,
                waiting: HashMap::new(),
                reader_gone: false,
            }),
            disconnected_locally: AtomicBool::new(false),
            tells: Mutex::new(Tells::default()),
            late_after_seal: Arc::new(AtomicBool::new(false)),
            failed_tell_sends: AtomicU64::new(0),
            dropped_releases: AtomicU64::new(0),
            login_end_stuck: AtomicBool::new(false),
            end_worker,
        });
        // Tells -- late nonces among them, see `AuthSeam::drop_late_answer`
        // -- are sent by a thread of their own. It ends once every sender is
        // gone: the reader's, when the reader ends, and this value's, when
        // it is dropped.
        let (late, late_rx) = mpsc::channel::<Wake>();
        let stop_read = reading.try_clone()?;
        let mut auxiliary = WorkerThreads::default();
        auxiliary.watch(ThreadRole::TellReleaser, seam.late_after_seal.clone());
        let releaser_seam = Arc::clone(&seam);
        let release_thread = spawn(
            AUTH_RELEASE_THREAD,
            Box::new(move || send_tells(releaser_seam, late_rx)),
        )?;
        let finish = late.clone();
        auxiliary.register(ThreadRole::TellReleaser, release_thread, move || {
            finish
                .send(Wake::Finish(Instant::now() + timeout))
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "tell releaser already stopped")
                })
        });
        let reader_seam = Arc::clone(&seam);
        let reader_late = late.clone();
        let reader_thread = spawn(
            AUTH_READER_THREAD,
            Box::new(move || {
                read_answers(reader_seam, reading, recv, on_helper_gone, reader_late);
                Ok(())
            }),
        )?;
        let stopping_seam = seam.clone();
        auxiliary.register(ThreadRole::AuthReader, reader_thread, move || {
            stopping_seam
                .disconnected_locally
                .store(true, Ordering::SeqCst);
            stop_read.shutdown(std::net::Shutdown::Read)
        });
        Ok(HelperAuth {
            seam,
            timeout,
            verify_timeout,
            late,
            auxiliary: Mutex::new(Some(auxiliary)),
        })
    }

    /// One request, and its answer, within its budget -- and no request at
    /// all if the budget ran out before it could be sent.
    fn ask(&self, body: Request) -> Result<Response, AuthError> {
        self.ask_by(body, None)
    }

    /// As [`HelperAuth::ask`], but done by `cap` when there is one: the
    /// call's deadline is whichever comes first, the end of its own budget
    /// or `cap`. For a caller with a deadline of its own that spans several
    /// calls -- the nonce pool's warm-up.
    fn ask_by(&self, body: Request, cap: Option<Instant>) -> Result<Response, AuthError> {
        let mut budget = match body {
            Request::Verify { .. } => self.verify_timeout,
            _ => self.timeout,
        };
        // One deadline for the whole call, fixed BEFORE the send lock is
        // taken -- not after it, and not after the send. Whatever this call
        // waited for the lock is part of what it costs its caller, so
        // whatever is left of the budget after the lock is all the answer
        // gets.
        let started = Instant::now();
        let mut deadline = started + budget;
        if let Some(cap) = cap {
            if cap < deadline {
                deadline = cap;
                budget = cap.saturating_duration_since(started);
            }
        }
        // A login's end is waiting to be sent again: this request could not
        // go out ahead of it, and trying the end again here would only hold
        // the send lock for a send timeout. The release thread retries it;
        // this call fails at once, touching nothing -- before the send lock,
        // which a retry may be holding, and again once it is held.
        self.refuse_while_a_login_end_is_stuck(started)?;
        let (answer_tx, answer_rx) = mpsc::channel::<Delivery>();
        let id = {
            let sender = self.seam.lock_sender();
            self.refuse_while_a_login_end_is_stuck(started)?;
            // Out of time already, so nothing is sent. The caller has given
            // up by now and an answer would have nobody to go to -- and the
            // request would not be harmless on its way: a `Verify` sent now
            // is still checked by the helper, and if it verifies, the helper
            // trusts the account and opens a login entry for a handshake the
            // transport has already refused. Failed exactly the way a wait
            // that ran out fails.
            if deadline.saturating_duration_since(Instant::now()).is_zero() {
                return Err(timed_out(budget));
            }
            // Every tell queued before this request leaves before it: a
            // `LoginEnded` the router queued must reach the helper ahead of a
            // `Verify` for the same login that came after it. If one cannot
            // be sent, neither is this request.
            if let Err(e) = self.seam.flush_tells(&sender, deadline) {
                // Whatever is left is the release thread's to send -- wake
                // it, in case nothing else will.
                let _ = self.late.send(Wake::Flush);
                if deadline.saturating_duration_since(Instant::now()).is_zero() {
                    return Err(timed_out(budget));
                }
                return Err(AuthError::Backend(format!("reaching the helper: {e}")));
            }
            // On the table before anything is sent -- see `register`.
            let id = self.seam.register(Waiter {
                answer: answer_tx,
                deadline,
            })?;
            let bytes = match encode(&AuthRequest { id, body }) {
                Ok(bytes) => bytes,
                Err(e) => {
                    self.seam.forget(id);
                    return Err(AuthError::Backend(format!("could not ask the helper: {e}")));
                }
            };
            if let Err(e) = (self.seam.send)(&sender, &bytes) {
                // Never reached the helper, so no answer is coming.
                self.seam.forget(id);
                return Err(AuthError::Backend(format!(
                    "reaching the helper: {}",
                    describe_send_error(&e)
                )));
            }
            id
        };
        // The send lock is released: the wait below holds nothing.
        self.wait_for(id, &answer_rx, deadline, budget)
    }

    /// Fails a request that began at `started` while a login's end waits to
    /// be sent again -- see [`AuthSeam::login_end_stuck`].
    fn refuse_while_a_login_end_is_stuck(&self, started: Instant) -> Result<(), AuthError> {
        if self.seam.login_end_stuck.load(Ordering::SeqCst) {
            return Err(AuthError::Backend(format!(
                "reaching the helper: the end of a login is still waiting to be sent (after {:?})",
                started.elapsed()
            )));
        }
        Ok(())
    }

    /// The answer to request `id`, or an error once `deadline` passes, or
    /// at once if the reader ends.
    fn wait_for(
        &self,
        id: AuthRequestId,
        answers: &Receiver<Delivery>,
        deadline: Instant,
        budget: Duration,
    ) -> Result<Response, AuthError> {
        match answers.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(delivery) => delivery,
            Err(mpsc::RecvTimeoutError::Timeout) => self.give_up(id, answers, budget),
            // The entry was dropped with no answer: the reader ended, or it
            // found this call's answer late a moment before this call woke.
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if Instant::now() >= deadline {
                    Err(timed_out(budget))
                } else {
                    Err(helper_gone())
                }
            }
        }
    }

    /// What a call whose wait for request `id` has just run out ends with.
    ///
    /// The call takes itself off the table first, so that from then on the
    /// reader treats this number's answer as late. If the reader had
    /// already taken the entry, it did so either to hand the answer over --
    /// which it does only before the deadline, and which is then waiting in
    /// the channel, this call's still -- or to drop it as late.
    fn give_up(
        &self,
        id: AuthRequestId,
        answers: &Receiver<Delivery>,
        budget: Duration,
    ) -> Result<Response, AuthError> {
        if self.seam.forget(id) {
            return Err(timed_out(budget));
        }
        answers
            .try_recv()
            .unwrap_or_else(|_| Err(timed_out(budget)))
    }

    /// The send lock, for a test that has to hold it the way a send stuck
    /// on a full socket would.
    #[cfg(test)]
    fn lock_sender(&self) -> MutexGuard<'_, UnixStream> {
        self.seam.lock_sender()
    }

    /// How long this client waits for a verdict -- for a test outside this
    /// module that has to see where that wait came from.
    #[cfg(test)]
    pub(crate) fn verify_timeout(&self) -> Duration {
        self.verify_timeout
    }
}

impl Drop for HelperAuth {
    /// Local fixture cleanup joins the reader before the final ordered tell
    /// flush and releaser join. A transferred production owner preserves the
    /// writable seam independently of this client's Arc lifetime. This is
    /// auxiliary custody, not a proof of manager/required-producer settlement.
    fn drop(&mut self) {
        if let Some(mut auxiliary) = self
            .auxiliary
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            auxiliary.stop_and_join();
        }
    }
}

impl AuthVerifier for HelperAuth {
    fn verify(
        &self,
        handshake_hash: &[u8; 32],
        record: &AuthRecord,
        login: LoginId,
        rhost: &str,
    ) -> Result<Principal, AuthError> {
        // A version 1 record carries no login, and this mode has several
        // accounts to choose between. Refuse rather than guess one -- and
        // without asking the helper: there is nothing to ask it about.
        let v2 = record.v2.as_ref().ok_or(AuthError::KeyNotAuthorized)?;
        let request = Request::Verify {
            login: v2.login.clone(),
            public_key: record.public_key.clone(),
            signature: record.signature.clone(),
            handshake_hash: *handshake_hash,
            nonce: v2.nonce,
            login_id: login,
            // Passed on exactly as this process saw it, and believed by
            // nobody: the helper keeps it for the login's monitor and
            // decides nothing by it -- see `Request::Verify`'s own field.
            rhost: rhost.to_string(),
        };
        match self.ask(request)? {
            Response::Verified {
                uid,
                name,
                identity,
                incarnation,
            } => Ok(Principal {
                uid,
                name,
                identity,
                // Carried through untouched, to be compared against the
                // incarnation of a later `Response::LoginEnded` for the
                // same device -- see `Principal::incarnation`. The worker
                // decides nothing by it; it only passes it on.
                incarnation,
            }),
            // The helper's reason went to its own log; the client gets one
            // indistinguishable refusal, so this is not an account
            // enumerator.
            Response::Refused { .. } => Err(AuthError::KeyNotAuthorized),
            other => Err(AuthError::Backend(format!(
                "the helper answered a verification with {other:?}"
            ))),
        }
    }
}

/// The nonce calls. Not a `NonceSource` -- see [`HelperAuth`]'s docs.
impl HelperAuth {
    /// A fresh nonce from the helper, waiting for its answer up to
    /// [`HELPER_ANSWER_TIMEOUT`]. Never to be called on the session router's
    /// task: the nonce pool calls it, from its own thread.
    pub(crate) fn issue(&self) -> Result<Nonce, String> {
        self.issue_by_cap(None)
    }

    /// As [`HelperAuth::issue`], but done by `deadline` if that comes before
    /// the call's own budget runs out -- and sending nothing if it has
    /// already passed.
    pub(crate) fn issue_by(&self, deadline: Instant) -> Result<Nonce, String> {
        self.issue_by_cap(Some(deadline))
    }

    fn issue_by_cap(&self, cap: Option<Instant>) -> Result<Nonce, String> {
        match self
            .ask_by(Request::Nonce, cap)
            .map_err(|e| e.to_string())?
        {
            Response::Nonce { nonce } => Ok(nonce),
            Response::NonceUnavailable => {
                Err("the helper already holds as many unspent nonces as it will issue".to_string())
            }
            other => Err(format!(
                "the helper answered a nonce request with {other:?}"
            )),
        }
    }

    /// Give up a nonce nobody will spend. A tell, not an ask: the helper
    /// never answers a `ReleaseNonce`. Queued, never sent here -- see
    /// [`HelperAuth::tell_later`].
    pub(crate) fn release(&self, nonce: Nonce) {
        self.tell_later(Request::ReleaseNonce { nonce });
    }

    /// Queue a tell and wake the release thread to send it. Waits for
    /// neither the send lock nor the socket: the session router calls this on
    /// its own task. The tell leaves ahead of any request made after it (see
    /// [`AuthSeam::flush_tells`]). If the release thread is gone -- which
    /// ends the worker, see [`ReleaserExit`] -- the next request sends it.
    fn tell_later(&self, body: Request) {
        self.seam.queue_tell(body);
        let _ = self.late.send(Wake::Flush);
    }

    /// Queue a tell without waking anybody -- for a test that has to control
    /// when it is sent.
    #[cfg(test)]
    pub(crate) fn queue_only_for_test(&self, body: Request) {
        self.seam.queue_tell(body);
    }

    /// The seam's descriptor, for a test that fills the socket itself.
    #[cfg(test)]
    pub(crate) fn raw_fd_for_test(&self) -> std::os::fd::RawFd {
        self.seam.lock_sender().as_raw_fd()
    }
}

/// An [`EndWorker`] that ends nothing -- for the constructors of tests that
/// do not watch it.
#[cfg(test)]
fn ignore_the_end() -> EndWorker {
    Arc::new(|_why: &str| {})
}

impl LoginSink for HelperAuth {
    /// A tell, not an ask: the helper never answers a `LoginEnded`. Queued
    /// like [`HelperAuth::release`], never sent on the caller's task -- the
    /// router calls this on its own -- and never dropped: see
    /// [`MAX_QUEUED_LOGIN_ENDS`].
    fn login_ended(&self, login: LoginId) {
        self.tell_later(Request::LoginEnded { login });
    }
}

#[cfg(test)]
pub(crate) mod tests {
    include!("spawner_auxiliary_tests.rs");
    include!("spawner_cleanup_failure_tests.rs");
    include!("spawner_login_retry_tests.rs");
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsFd;
    use std::sync::atomic::AtomicUsize;
    use std::thread::JoinHandle;

    use ssh_key::{Algorithm, PrivateKey};
    use sshauth::record::{encode_public_key, encode_signature};
    use transport::auth::{auth_challenge, auth_challenge_v2, AuthV2};
    use transport::AUTH_NONCE_LEN;

    use super::super::server::tests::{
        helper_trusting, helper_trusting_a_slow_database, join_within, running_as_root, TestHelper,
        PROOF_RHOST, SLOW_LOOKUP,
    };
    use super::super::server::MAX_OUTSTANDING_NONCES;

    /// How long a test here waits for a call that is meant not to hang
    /// before concluding it really is stuck rather than merely slow.
    /// Mirrors `helper::server`'s own `TEST_RECV_TIMEOUT` (see that
    /// module's tests for the fuller account): this branch has already
    /// shipped a test that hung instead of failing when the behaviour it
    /// covered regressed three times before this one (the ssh-agent test in
    /// slice 1, the leak check in task 3, the reaping tests in task 4) --
    /// every blocking call a test here makes that could, on a regression,
    /// block forever is bounded by this constant, one way or another.
    const TEST_RECV_TIMEOUT: Duration = Duration::from_secs(10);

    /// The budget a [`HelperAuth`] gets in the tests below that have to
    /// watch a call give up: long enough that an answer the stub sends at
    /// once always makes it, short enough that waiting it out is cheap.
    const SHORT_ANSWER_TIMEOUT: Duration = Duration::from_millis(100);

    /// The helper's settings exactly as the daemon resolves them at startup
    /// -- the value `split_and_run` hands both the helper and the worker's
    /// `HelperAuth`.
    fn daemon_config() -> HelperConfig {
        HelperConfig::resolve(&crate::serve::ServeArgs {
            status_socket: None,
            port: 60022,
            authorized_keys: None, // unread in the system mode -- see its own doc comment
            host_key: "/etc/qshd/host_key".into(),
            system: true,
            worker_user: "qshd".to_string(),
            permit_root: false,
            authorized_keys_template: "%h/.ssh/authorized_keys".to_string(),
            runtime_threads: None,
        })
    }

    /// A `HelperConfig` for tests that do not care about its contents --
    /// the tests here that run a real helper without `helper_trusting`
    /// never ask it to verify anyone, so `permit_root` and
    /// `authorized_keys_template` go unread.
    fn test_config() -> super::super::config::HelperConfig {
        super::super::config::HelperConfig {
            authorized_keys_template: "%h/.ssh/authorized_keys".into(),
            permit_root: false,
            tty_gid: None,
            worker_user: "qshd".into(),
            startup_timeout: super::super::server::STARTUP_REPORT_TIMEOUT,
            verify_timeout: super::super::server::VERIFY_TIMEOUT,
            pam_service: super::super::config::PAM_SERVICE.to_string(),
            pam_confdir: None,
        }
    }

    /// Runs a blocking call that is meant not to hang on a thread of its
    /// own, and bounds how long the CALLING thread waits for an answer by
    /// [`TEST_RECV_TIMEOUT`], panicking rather than hanging if none comes.
    ///
    /// This exists because the calls under test here --
    /// `ChannelSpawner::spawn` and `ChannelWait::wait` -- are synchronous
    /// trait methods: the actual blocking `mpsc::Receiver::recv` each one
    /// makes is a private implementation detail no test can reach directly
    /// to put a timeout on, unlike the raw socket-level `recv` calls
    /// `helper::server`'s tests bound with `set_read_timeout`. Running the
    /// call on its own thread and bounding the WAIT for its result is the
    /// equivalent for a call hidden behind an ordinary blocking function
    /// signature -- the same trade `channel_backend.rs`'s own `read_until`
    /// test helper makes, for the same reason.
    ///
    /// Only reached once the spawned thread has already sent its result, so
    /// the trailing `join` here cannot itself hang -- there is nothing left
    /// for that thread to do but unwind and drop whatever it captured (an
    /// `Arc` clone, typically), which the tests below that check state
    /// immediately after calling `bounded` rely on having already happened.
    fn bounded<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        let result = rx
            .recv_timeout(TEST_RECV_TIMEOUT)
            .expect("must return within the timeout rather than hang");
        let _ = handle.join();
        result
    }

    /// Whose session asks, for a test whose helper never looks: a stub, or
    /// a request refused before it is ever sent.
    fn anyone() -> Principal {
        Principal {
            uid: 4242,
            name: "anyone".to_string(),
            identity: "SHA256:anyone".to_string(),
            incarnation: 0,
        }
    }

    /// Which login asks, for a test that does not care -- none here checks
    /// what `Request::Open.login` carries (that is `helper::server`'s and
    /// `crates/transport/src/channel_server.rs`'s own tests' job); a fixed
    /// value threads through `spawn`'s now-mandatory parameter. It is also
    /// the login [`verified_worker`] proves: the helper opens a channel only
    /// under a login a proof put on file.
    fn any_login() -> LoginId {
        [1u8; 16]
    }

    /// A shell channel's request, 80x24.
    fn shell_request() -> OpenRequest {
        OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: false,
            command: Vec::new(),
        }
    }

    /// A client's proof for `login`, over `hash` and `nonce`, signed with
    /// `key` -- the record `HelperAuth::verify` is handed.
    fn record_for(key: &PrivateKey, login: &str, hash: &[u8; 32], nonce: Nonce) -> AuthRecord {
        let v2 = AuthV2 {
            login: login.to_string(),
            nonce,
        };
        let signature =
            signature::Signer::try_sign(key, &auth_challenge_v2(hash, &v2)).expect("sign");
        AuthRecord {
            public_key: encode_public_key(key.public_key()).expect("encode"),
            signature: encode_signature(&signature).expect("encode"),
            v2: Some(v2),
        }
    }

    /// A real helper, and in front of it the worker side exactly as the
    /// daemon builds it: a [`HelperChannelSpawner`] on the channel seam, a
    /// [`HelperAuth`] on the authentication seam -- with this test's own
    /// account already verified through that `HelperAuth`, the way a
    /// session logs in for real, under [`any_login`]. `owner` is the
    /// principal that verification returned: what a session hands the
    /// spawner with every channel.
    struct Worker {
        spawner: Arc<HelperChannelSpawner>,
        /// Held, never used after the login: the helper's loop ends when
        /// EITHER seam closes, so dropping this would end it too.
        _auth: HelperAuth,
        owner: Principal,
        thread: JoinHandle<()>,
        _dir: tempfile::TempDir,
    }

    fn verified_worker() -> Worker {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let TestHelper {
            channels,
            auth,
            thread,
            dir,
            me,
            login: _login,
        } = helper_trusting(&key, running_as_root());
        // The harness bounds every raw read with a timeout; the spawner's
        // reader thread would take that for the helper being gone.
        channels
            .set_read_timeout(None)
            .expect("clear the receive timeout");
        let auth = HelperAuth::new(auth, &test_config()).expect("the authentication client");
        let hash = [7u8; 32];
        let nonce = auth.issue().expect("the helper issues a nonce");
        let owner = auth
            .verify(
                &hash,
                &record_for(&key, &me, &hash, nonce),
                any_login(),
                PROOF_RHOST,
            )
            .expect("the helper admits this test's own account");
        Worker {
            spawner: Arc::new(HelperChannelSpawner::new(channels).expect("spawner")),
            _auth: auth,
            owner,
            thread,
            _dir: dir,
        }
    }

    /// The next request a stub helper receives on the authentication seam.
    fn next_request(stub: &UnixStream) -> AuthRequest {
        let (bytes, _fd) = channel::recv(stub).expect("recv").expect("open");
        decode::<AuthRequest>(&bytes).expect("decode")
    }

    /// A stub helper's answer on the authentication seam.
    fn answer(stub: &UnixStream, id: AuthRequestId, body: Response) {
        channel::send(
            stub,
            &encode(&AuthResponse { id, body }).expect("encode"),
            None,
        )
        .expect("reply");
    }

    #[test]
    fn screen_budget_helper_refusal_and_failure_do_not_leak_or_send_extra_open() {
        let budget = Arc::new(ScreenBudget::new(BudgetLimits {
            owner_models: 1,
            ..BudgetLimits::default()
        }));
        let (worker, helper) = channel::pair().unwrap();
        helper.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
        let spawner = HelperChannelSpawner::with_budget_hook(
            worker,
            budget.clone(),
            || {},
            Box::new(|_, _| {}),
        )
        .unwrap();
        let mut req = shell_request();
        req.cols = 2;
        req.rows = 1;
        req.screen = true;
        let lease = budget
            .reserve(
                anyone().uid,
                terminal_size::TerminalSize::new(2, 1).unwrap(),
            )
            .unwrap();
        assert!(spawner
            .spawn(&anyone(), any_login(), &req, None)
            .err()
            .unwrap()
            .contains("screen budget"));
        helper.set_nonblocking(true).unwrap();
        assert!(
            matches!(channel::recv(&helper),Err(e) if e.kind()==io::ErrorKind::WouldBlock),
            "refusal starts no helper OPEN"
        );
        helper.set_nonblocking(false).unwrap();
        drop(lease);
        let stub = std::thread::spawn(move || {
            let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
            let Request::Open { id, .. } = decode::<Request>(&bytes).unwrap() else {
                panic!("OPEN")
            };
            channel::send(
                &helper,
                &encode(&Response::Failed {
                    id,
                    reason: "test helper failed".into(),
                })
                .unwrap(),
                None,
            )
            .unwrap();
            (helper, id)
        });
        assert!(spawner.spawn(&anyone(), any_login(), &req, None).is_err());
        let (helper, id) = stub.join().unwrap();
        assert_eq!(budget.used().models, 1, "Failed alone is not cleanup");
        channel::send(
            &helper,
            &encode(&Response::CleanupComplete {
                id,
                kind: CleanupKind::NoChild,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        wait_for("the exact receipt refunds the screen", &|| {
            budget.used().models == 0
        });
        assert_eq!(budget.used(), crate::screen_budget::Usage::default());
    }

    #[test]
    fn master_resize_returns_the_actual_ioctl_error() {
        let handle = MasterResize(tempfile::tempfile().unwrap());
        assert!(
            handle.try_resize(2, 1).is_err(),
            "a regular file is not a PTY"
        );
        assert!(handle.try_resize(1, 1).unwrap_err().contains("columns"));
    }

    /// A channel opened through the helper reads and writes like any other.
    #[test]
    fn a_channel_opened_through_the_helper_carries_a_shell() {
        let w = verified_worker();

        let mut channel = bounded({
            let spawner = Arc::clone(&w.spawner);
            let owner = w.owner.clone();
            move || {
                spawner.spawn(
                    &owner,
                    any_login(),
                    &shell_request(),
                    Some("xterm-256color"),
                )
            }
        })
        .expect("spawn");

        // `unset HISTFILE` first: this is the account's real login shell,
        // from passwd, with its real `HOME` -- the helper hands a channel
        // nothing of this test process's environment, so the
        // `HISTFILE=/dev/null` other tests rely on never reaches it -- and an
        // interactive shell saves what it was given to that home's history
        // when the channel ends. And `printf 'seam-%s' works`, not
        // `echo seam-works`: the terminal echoes the typed line back before
        // the shell runs any of it, so a literal `seam-works` in the command
        // would be found in that echo alone. `seam-works` can only come from
        // `printf` running.
        channel
            .writer
            .write_all(b"unset HISTFILE; printf 'seam-%s' works\n")
            .expect("write");
        channel.writer.flush().expect("flush");

        // `channel.reader` wraps a pty master, whose `Read::read` has no
        // timeout knob of its own the way `UnixStream::set_read_timeout`
        // does -- so, like `channel_backend.rs`'s own `read_until` test
        // helper, this runs the blocking read loop on its own thread and
        // reuses `bounded` to bound the WAIT for its result: a regression
        // that stops "seam-works" from ever coming back must fail the
        // assertion below within `TEST_RECV_TIMEOUT`, not hang the run.
        let mut reader = channel.reader;
        let seen = bounded(move || {
            let mut seen = String::new();
            let mut chunk = [0u8; 256];
            while let Ok(n) = reader.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                seen.push_str(&String::from_utf8_lossy(&chunk[..n]));
                if seen.contains("seam-works") {
                    break;
                }
            }
            seen
        });
        assert!(
            seen.contains("seam-works"),
            "the shell's output must come back, got {seen:?}"
        );

        channel.wait.kill();
        // `bounded` returning at all is the whole check here: it is what
        // proves `wait` did not hang. The code itself is whatever the
        // shell's death produced, which depends on the shell.
        let _code = bounded(move || channel.wait.wait());

        drop(w.spawner);
        join_within(
            w.thread,
            "the helper loop must end once the spawner closes the channel seam",
        );
    }

    /// A request with no terminal is refused here, exactly as the personal
    /// mode's spawner refuses it -- the two must not disagree about what a
    /// channel is.
    #[test]
    fn a_request_without_a_terminal_is_refused() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        let (_worker_auth, helper_auth) = super::channel::pair().expect("socketpair");
        let loop_thread = std::thread::spawn(move || {
            super::super::server::run_until_peer_closes(helper, helper_auth, test_config())
        });
        let spawner = Arc::new(HelperChannelSpawner::new(worker).expect("spawner"));

        let req = OpenRequest {
            cols: 0,
            ..shell_request()
        };
        assert!(bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &req, None)
        })
        .is_err());

        drop(spawner);
        join_within(
            loop_thread,
            "the helper loop must end once the spawner closes the channel seam",
        );
    }

    /// `transport::channel::MAX_COMMAND_LEN` (4096 bytes, the longest
    /// command line a client may send) and `helper::protocol::MAX_MESSAGE_LEN`
    /// (8192 bytes, the cap on a message to the helper) are not
    /// independent, and nothing pinned that relation before this test. JSON
    /// requires escaping a control character with no short named form
    /// (`\n`, `\t`, and the like) as `\u00XX` -- six ASCII bytes for one
    /// source byte -- so a command AT the length limit, built entirely of
    /// such a byte, encodes to something close to 24576 bytes: several
    /// times past the message cap. A change to either constant that closed
    /// this gap would silently make this refusal path unreachable.
    ///
    /// Also exercises the fix for the bookkeeping leak this refusal used to
    /// cause: `spawn` used to insert into `waiting` BEFORE encoding the
    /// request, so a request that failed the size cap left its entry --
    /// and both its senders -- behind for the life of the process. Here,
    /// after the refusal, the map must be empty.
    #[test]
    fn an_over_long_command_is_refused_without_leaking_its_bookkeeping() {
        assert_eq!(
            transport::channel::MAX_COMMAND_LEN,
            4096,
            "this test's math assumes the current limit; update the repeat count below if it \
             ever changes"
        );
        // 0x01 (SOH): valid single-byte UTF-8, not whitespace and not a
        // quote (so `split_command` keeps the whole run as one word), and
        // one of the control characters JSON has no short escape for.
        let command = "\u{0001}".repeat(transport::channel::MAX_COMMAND_LEN);
        assert_eq!(command.len(), transport::channel::MAX_COMMAND_LEN);

        let (worker, helper) = super::channel::pair().expect("socketpair");
        let spawner = Arc::new(HelperChannelSpawner::new(worker).expect("spawner"));

        let req = OpenRequest {
            kind: ChannelKind::Command,
            command: command.into_bytes(),
            ..shell_request()
        };
        let result = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &req, None)
        });
        // `expect_err`/`unwrap_err` both require `SpawnedChannel: Debug`,
        // which it is not (it carries trait objects) -- matched by hand
        // instead.
        let err = match result {
            Ok(_) => panic!("a command this large must be refused, not sent"),
            Err(e) => e,
        };
        assert!(
            err.contains("exceeds"),
            "expected the message-size refusal, got: {err}"
        );
        assert!(
            spawner.waiting.lock().expect("not poisoned").is_empty(),
            "a request refused before it was ever sent must not leave an entry behind"
        );

        drop(spawner);
        drop(helper);
    }

    /// The helper refuses a repeated channel id, so ids must never be
    /// reused for the life of a connection -- proven here by opening a
    /// channel, letting it run, and confirming a second `spawn` still gets
    /// a fresh id rather than colliding with the first (which is still
    /// live: nothing closed it).
    #[test]
    fn ids_are_not_reused_across_spawns() {
        let w = verified_worker();

        let mut first = bounded({
            let spawner = Arc::clone(&w.spawner);
            let owner = w.owner.clone();
            move || spawner.spawn(&owner, any_login(), &shell_request(), None)
        })
        .expect("first spawn");
        let mut second = bounded({
            let spawner = Arc::clone(&w.spawner);
            let owner = w.owner.clone();
            move || spawner.spawn(&owner, any_login(), &shell_request(), None)
        })
        .expect("second spawn must not collide with the first");

        first.wait.kill();
        second.wait.kill();
        bounded(move || first.wait.wait());
        bounded(move || second.wait.wait());

        drop(w.spawner);
        join_within(
            w.thread,
            "the helper loop must end once the spawner closes the channel seam",
        );
    }

    /// If the helper is already gone by the time `spawn` is called -- its
    /// end of the pair was dropped without ever running a server loop --
    /// `spawn` must return an error rather than block forever waiting for a
    /// reply that is never coming.
    ///
    /// Checked by hand: silencing the early `channel::send` failure in
    /// `spawn` (so it falls through to `opened_rx.recv()` instead of
    /// returning right away) was, by itself, NOT enough to make this test
    /// hang -- the reader thread's own `waiting.clear()` on the very same
    /// "peer is gone" event usually still won the race and rescued it,
    /// just by a different path than the one this test names. Only with
    /// `waiting.clear()` ALSO disabled did the two protections both give
    /// out and the test genuinely hang -- at which point `bounded`'s
    /// `TEST_RECV_TIMEOUT` turned that hang into a loud failure after 10s
    /// instead of an indefinite one, exactly what it exists for. Both
    /// changes were reverted afterwards; this test passes again in well
    /// under a second.
    #[test]
    fn spawn_fails_rather_than_hangs_when_the_helper_is_already_gone() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        drop(helper);
        let spawner = Arc::new(HelperChannelSpawner::new(worker).expect("spawner"));

        let result = bounded(move || spawner.spawn(&anyone(), any_login(), &shell_request(), None));
        assert!(
            result.is_err(),
            "a dead helper must be reported as an error, not hung on"
        );
    }

    /// If the helper dies while a channel is already open -- crashes, is
    /// killed, whatever -- `wait()` must return rather than block forever
    /// for an `Exited` that will never arrive, and it must not be confused
    /// with the worker having disconnected on its own (see
    /// `dropping_the_spawner_marks_the_disconnect_as_local`, the mirror of
    /// this test): `disconnected_locally` must stay false here, because
    /// `HelperChannelSpawner::drop` never runs in this test at all.
    ///
    /// A stub stands in for the helper here rather than the real one from
    /// `super::server`: what is under test is the SPAWNER's reaction to its
    /// peer disappearing, a property of this module alone, and the real
    /// helper has no lever to make it stop answering on command without
    /// tearing down the very socket this test needs to keep open a moment
    /// longer. The real helper's `Open` handling is already exercised end
    /// to end by the tests above.
    #[test]
    fn wait_returns_rather_than_hangs_when_the_helper_dies_mid_flight() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        // A read timeout on the STUB's own end: if `spawn`'s request never
        // arrives (the very regression this test exists to catch), this
        // `recv` must fail loudly within `TEST_RECV_TIMEOUT` rather than
        // block forever -- the same `set_read_timeout` pattern
        // `helper::server`'s own tests use on the raw socket.
        helper
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        // Answers exactly one `Open` with a fake master descriptor, then
        // drops its end of the pair -- standing in for the helper process
        // dying before it ever gets to report an exit.
        let stub = std::thread::spawn(move || {
            let (bytes, _fd) = channel::recv(&helper).expect("recv").expect("open");
            let Request::Open { id, .. } = decode::<Request>(&bytes).expect("decode") else {
                panic!("expected an Open request");
            };
            let fake_master = tempfile::tempfile().expect("a fake master descriptor");
            let response = encode(&Response::Opened { id }).expect("encode");
            channel::send(&helper, &response, Some(fake_master.as_fd())).expect("reply");
        });

        let spawner = Arc::new(HelperChannelSpawner::new(worker).expect("spawner"));
        let channel = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &shell_request(), None)
        })
        .expect("spawn");
        // The stub has already sent its one reply and returned, dropping
        // `helper` on the way out -- the worker's reader thread now has a
        // closed peer with no `Exited` ever having arrived.
        stub.join().expect("join");

        let code = bounded(move || channel.wait.wait());
        assert_eq!(
            code, -1,
            "a channel orphaned by a dead helper reports -1, not a hang"
        );
        assert!(
            !spawner.disconnected_locally.load(Ordering::SeqCst),
            "the helper dying is not the same fact as the worker disconnecting -- \
             this spawner's own Drop never ran in this test, so the flag must stay false"
        );
    }

    /// The mirror of the test above: when the LAST spawner handle is
    /// dropped while a channel opened through it is still running, that is
    /// a different fact from the helper dying, and `disconnected_locally`
    /// is what makes the difference checkable rather than merely asserted
    /// in a doc comment. `Drop` must set it before it shuts the connection
    /// down; a channel's `wait()` reads the SAME flag through its own
    /// clone, so once this test proves the top-level flag flips, the
    /// `HelperWait` behind `channel.wait` (opaque here behind
    /// `Box<dyn ChannelWait>`, so it cannot be inspected directly) is
    /// reading that identical `AtomicBool` when it decides what to log.
    #[test]
    fn dropping_the_spawner_marks_the_disconnect_as_local() {
        let w = verified_worker();

        // A shell with nothing asked of it keeps running rather than
        // exiting on its own -- exactly the "still alive when the seam
        // goes away" situation this test is about.
        let channel = bounded({
            let spawner = Arc::clone(&w.spawner);
            let owner = w.owner.clone();
            move || spawner.spawn(&owner, any_login(), &shell_request(), None)
        })
        .expect("spawn");

        assert!(
            !w.spawner.disconnected_locally.load(Ordering::SeqCst),
            "must be false before anything has dropped the spawner"
        );

        // Take the only remaining reference alongside `w.spawner`, so that
        // dropping `w.spawner` below drops the LAST `Arc` and really runs
        // `HelperChannelSpawner::drop` -- and clone the flag out first,
        // since the field is gone once that happens.
        let disconnected_locally = Arc::clone(&w.spawner.disconnected_locally);
        drop(w.spawner);
        join_within(
            w.thread,
            "the helper loop must end once the spawner closes the channel seam",
        );

        assert!(
            disconnected_locally.load(Ordering::SeqCst),
            "Drop must mark the disconnect as its own doing, not the helper's"
        );

        // `wait()` still returns -1 -- the trait's return type cannot say
        // "unknown" -- but must return rather than hang even though the
        // process behind this channel was never told to stop and the
        // helper never got the chance to report it (see the `Drop` doc
        // comment on `HelperChannelSpawner` for why this is expected, not
        // a leak this test needs to chase down).
        let code = bounded(move || channel.wait.wait());
        assert_eq!(
            code, -1,
            "no exit ever arrives once the connection is gone, but wait() must still return"
        );
    }

    /// The UID and canonical name in `Open` are the OWNER's -- the session's,
    /// as `spawn` was handed it. Both identify the immutable account binding;
    /// neither may be the worker's account or a placeholder. A
    /// stub records what arrives; the owner's uid is one no test process
    /// runs as, so it cannot match by coincidence.
    #[test]
    fn the_open_request_names_the_sessions_owner() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        helper
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let stub = std::thread::spawn(move || {
            let (bytes, _fd) = channel::recv(&helper).expect("recv").expect("open");
            let Request::Open { id, uid, .. } = decode::<Request>(&bytes).expect("decode") else {
                panic!("expected an Open request");
            };
            let refusal = Response::Failed {
                id,
                reason: "this stub opens nothing".to_string(),
            };
            channel::send(&helper, &encode(&refusal).expect("encode"), None).expect("reply");
            let name = serde_json::from_slice::<serde_json::Value>(&bytes).unwrap()["Open"]["name"]
                .as_str()
                .map(str::to_owned);
            (uid, name)
        });

        let spawner = Arc::new(HelperChannelSpawner::new(worker).expect("spawner"));
        let alice = Principal {
            uid: 4242,
            name: "alice".to_string(),
            identity: "SHA256:alice".to_string(),
            incarnation: 0,
        };
        let result = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&alice, any_login(), &shell_request(), None)
        });
        assert!(result.is_err(), "the stub refuses every channel");
        assert_eq!(
            stub.join().expect("join"),
            (4242, Some("alice".to_string())),
            "the Open must carry both UID and canonical name of the session owner"
        );
    }

    /// The worker does not decide who got in: it forwards the proof and
    /// takes the helper's answer, both ways.
    #[test]
    fn the_verifier_forwards_to_the_helper_and_returns_its_verdict() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        // The same throwaway-helper harness the verification tests use, so
        // the two sides are exercised against each other rather than
        // against a stub.
        let h = helper_trusting(&key, running_as_root());
        let me = h.me.clone();
        let verifier = HelperAuth::new(h.auth.try_clone().expect("clone"), &test_config())
            .expect("the authentication client");

        let hash = [7u8; 32];
        let nonce = verifier.issue().expect("the helper issues a nonce");
        let record = record_for(&key, &me, &hash, nonce);

        let principal = verifier
            .verify(&hash, &record, [0u8; 16], "")
            .expect("the helper admits this proof");
        assert_eq!(principal.name, me);
        assert_eq!(principal.uid, nix::unistd::Uid::current().as_raw());

        // The same proof again: the helper refuses, and the worker reports
        // the refusal rather than inventing a verdict of its own.
        assert_eq!(
            verifier.verify(&hash, &record, [0u8; 16], ""),
            Err(AuthError::KeyNotAuthorized),
            "a refusal from the helper must come back as a refusal"
        );

        drop(verifier);
        h.stop();
    }

    /// A version 1 record names no account, and the system mode has several
    /// to choose between: refuse rather than guess -- and without asking
    /// the helper, because there is nothing to ask it about. Checked against
    /// a silent stub rather than the real helper, which would refuse such a
    /// request too and so could not tell "refused here" from "forwarded and
    /// refused there": the stub's end must hold nothing afterwards.
    #[test]
    fn a_version_1_record_is_refused_without_asking_the_helper() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        let verifier = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");

        let hash = [7u8; 32];
        let signature = signature::Signer::try_sign(&key, &auth_challenge(&hash)).expect("sign");
        let record = AuthRecord {
            public_key: encode_public_key(key.public_key()).expect("encode"),
            signature: encode_signature(&signature).expect("encode"),
            v2: None,
        };
        let verdict = verifier.verify(&hash, &record, [0u8; 16], "");

        stub.set_nonblocking(true).expect("a non-blocking look");
        match channel::recv(&stub) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!(
                "a version 1 record must not reach the helper at all, but the helper was sent \
                 {:?}",
                other.map(|m| m.map(|(bytes, _)| String::from_utf8_lossy(&bytes).into_owned()))
            ),
        }
        assert_eq!(verdict, Err(AuthError::KeyNotAuthorized));
    }

    /// The reason every request on the authentication seam carries a
    /// number. The stub helper answers request 1 -- `Verified`, for
    /// somebody else entirely -- only AFTER this side has given up waiting
    /// for it, then answers request 2 with a refusal. The first call must
    /// fail; the second must come back refused. Handing the late answer to
    /// the second call would let one client in under another's name.
    ///
    /// Both orderings are made certain rather than likely: the stub holds
    /// the late answer until this thread has seen the first call return, AND
    /// until request 2 is out -- so the late answer reaches this side's
    /// reader while the second call is waiting, the one moment there is a
    /// call it could wrongly go to. The stub's end is handed back rather
    /// than dropped, so the seam stays open until the assertions are done.
    #[test]
    fn a_late_answer_is_never_taken_for_the_next_one() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub_end) = super::channel::pair().expect("socketpair");
        stub_end
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let verifier = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let (gave_up_tx, gave_up_rx) = mpsc::channel::<()>();
        let stub = std::thread::spawn(move || {
            let first = next_request(&stub_end);
            gave_up_rx
                .recv_timeout(TEST_RECV_TIMEOUT)
                .expect("the first call must give up");
            let second = next_request(&stub_end);
            answer(
                &stub_end,
                first.id,
                Response::Verified {
                    uid: 4242,
                    name: "alice".to_string(),
                    identity: "SHA256:alice".to_string(),
                    incarnation: 0,
                },
            );
            answer(
                &stub_end,
                second.id,
                Response::Refused {
                    reason: "authentication failed".to_string(),
                },
            );
            stub_end
        });

        let hash = [7u8; 32];
        let record = record_for(&key, "mallory", &hash, [1u8; AUTH_NONCE_LEN]);
        let first = verifier.verify(&hash, &record, [0u8; 16], "");
        gave_up_tx.send(()).expect("the stub is waiting");
        assert!(
            matches!(first, Err(AuthError::Backend(_))),
            "a call the helper did not answer in time must fail, got {first:?}"
        );

        let second = verifier.verify(&hash, &record, [0u8; 16], "");
        let _stub_end = stub.join().expect("join");
        assert_eq!(
            second,
            Err(AuthError::KeyNotAuthorized),
            "the late Verified for request 1 must not be taken for request 2's answer"
        );
    }

    /// A number LARGER than the request's own cannot come from an honest
    /// helper -- nothing has asked that question yet -- and fails the call,
    /// rather than being skipped the way a late one is: skipping would take
    /// whatever came next on trust. The stub answers request 1 first as if
    /// it were a later request, then properly, with `Verified`; the call
    /// must fail, not admit.
    #[test]
    fn an_answer_ahead_of_its_request_fails_the_call() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub_end) = super::channel::pair().expect("socketpair");
        stub_end
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let verifier = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let stub = std::thread::spawn(move || {
            let request = next_request(&stub_end);
            let verified = Response::Verified {
                uid: 4242,
                name: "alice".to_string(),
                identity: "SHA256:alice".to_string(),
                incarnation: 0,
            };
            answer(&stub_end, request.id + 6, verified.clone());
            answer(&stub_end, request.id, verified);
            stub_end
        });

        let hash = [7u8; 32];
        let result = verifier.verify(
            &hash,
            &record_for(&key, "alice", &hash, [1u8; AUTH_NONCE_LEN]),
            [0u8; 16],
            "",
        );
        // Held until the assertion is done, and the failure checked for its
        // reason: a call that ran out of time, or whose helper went away,
        // fails with `Backend` too.
        let _stub_end = stub.join().expect("join");
        assert!(
            matches!(&result, Err(AuthError::Backend(why)) if why.contains("protocol violation")),
            "an answer numbered ahead of its request must fail the call as a protocol violation, \
             got {result:?}"
        );
    }

    /// One deadline per call, not one per read: a helper that keeps sending
    /// stale answers -- numbered below anything this side has asked -- must
    /// not keep the call waiting past its budget. Each is dropped, and the
    /// wait resumes with only what is left of that budget.
    #[test]
    fn stale_answers_do_not_stretch_the_deadline() {
        let (worker, stub_end) = super::channel::pair().expect("socketpair");
        stub_end
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let stub = std::thread::spawn(move || {
            let _request = next_request(&stub_end);
            // Numbers start at 1 on this side, so 0 is below anything it
            // ever asked: every one of these is stale. A second's worth,
            // one every 20 ms -- far more often than the budget.
            for _ in 0..50 {
                answer(&stub_end, 0, Response::NonceUnavailable);
                std::thread::sleep(Duration::from_millis(20));
            }
        });

        let started = Instant::now();
        let result = auth.issue();
        let took = started.elapsed();
        assert!(result.is_err(), "no answer to this call ever came");
        assert!(
            took < Duration::from_millis(600),
            "a stream of stale answers must not stretch a call past its budget \
             ({SHORT_ANSWER_TIMEOUT:?}); it took {took:?}"
        );
        stub.join().expect("join");
    }

    /// A nonce that arrives too late for the call that asked for it is
    /// released as soon as it is seen: that call's handshake stopped
    /// waiting, so nothing will ever spend it, and left alone it would hold
    /// one of the helper's limited slots for its whole lifetime -- a slow
    /// helper would then fill its own table with nonces nobody wants. The
    /// second call, meanwhile, must get its own nonce, not the late one.
    ///
    /// The release comes from this side's reader, and the second request
    /// from the second call, so the two may reach the stub in either order;
    /// the stub takes them as they come. Its end is handed back, so the seam
    /// stays open until the assertions are done.
    #[test]
    fn a_late_nonce_is_released_rather_than_left_to_expire() {
        let (worker, stub_end) = super::channel::pair().expect("socketpair");
        stub_end
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let late: Nonce = [0x5Au8; AUTH_NONCE_LEN];
        let fresh: Nonce = [0xA5u8; AUTH_NONCE_LEN];
        let (gave_up_tx, gave_up_rx) = mpsc::channel::<()>();
        let stub = std::thread::spawn(move || {
            let first = next_request(&stub_end);
            gave_up_rx
                .recv_timeout(TEST_RECV_TIMEOUT)
                .expect("the first call must give up");
            answer(&stub_end, first.id, Response::Nonce { nonce: late });
            // The second call's request, answered as soon as it comes, and
            // whatever else this side sends: the late nonce's release, if
            // it sends one.
            stub_end
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("a shorter bound for the reads that follow");
            let other = answer_a_nonce_and_take_one_more(&stub_end, fresh);
            (other, stub_end)
        });

        assert!(
            auth.issue().is_err(),
            "a nonce the helper did not send in time must fail the call"
        );
        gave_up_tx.send(()).expect("the stub is waiting");
        assert_eq!(
            auth.issue(),
            Ok(fresh),
            "the second call must get its own nonce, not the late one"
        );
        let (released, _stub_end) = stub.join().expect("join");
        assert_eq!(
            released,
            Some(Request::ReleaseNonce { nonce: late }),
            "the late nonce must be released as soon as it is seen"
        );
    }

    /// `release` goes to the helper on the authentication seam and frees
    /// exactly the slot it names: fill the helper's table to its cap through
    /// `HelperAuth` itself, see the next request refused -- the table really
    /// is full, or the release would prove nothing -- then release one
    /// nonce, and the next request is granted.
    #[test]
    fn a_released_nonce_frees_its_slot_in_the_helper() {
        let (_worker_channels, helper_channels) = super::channel::pair().expect("socketpair");
        let (worker_auth, helper_auth) = super::channel::pair().expect("socketpair");
        let loop_thread = std::thread::spawn(move || {
            super::super::server::run_until_peer_closes(helper_channels, helper_auth, test_config())
        });
        let auth = HelperAuth::new(worker_auth, &test_config()).expect("the authentication client");

        let issued: Vec<Nonce> = (0..MAX_OUTSTANDING_NONCES)
            .map(|_| {
                auth.issue()
                    .expect("every request up to the cap is granted")
            })
            .collect();
        assert!(
            auth.issue().is_err(),
            "control: the helper's table must really be full, or the release below proves \
             nothing"
        );

        auth.release(issued[0]);
        assert!(
            auth.issue().is_ok(),
            "a nonce released through HelperAuth must free its slot in the helper"
        );

        // The channel seam stays open (`_worker_channels`): only the
        // authentication seam closing can end the loop here, and a loop that
        // does not end must fail this test, not hang it.
        drop(auth);
        join_within(
            loop_thread,
            "the helper loop must end once the authentication seam closes, even with the channel \
             seam still open",
        );
    }

    /// A command that is not valid UTF-8 is refused by the WORKER, and
    /// nothing about it ever reaches the helper: the seam carries a JSON
    /// `String`, and the privileged end must never be handed bytes that are
    /// not one. The stub's end must hold nothing at all afterwards.
    #[test]
    fn a_command_that_is_not_utf_8_is_refused_without_reaching_the_helper() {
        let (worker, stub) = super::channel::pair().expect("socketpair");
        let spawner = Arc::new(HelperChannelSpawner::new(worker).expect("spawner"));

        let req = OpenRequest {
            kind: ChannelKind::Command,
            // 0xFF begins no UTF-8 sequence there is.
            command: vec![0xff],
            ..shell_request()
        };
        let result = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &req, None)
        });
        let err = match result {
            Ok(_) => panic!("a command that is not valid UTF-8 must be refused, not forwarded"),
            Err(e) => e,
        };
        assert!(
            err.contains("not valid UTF-8"),
            "the refusal must say what was wrong with it, got: {err}"
        );

        stub.set_nonblocking(true).expect("a non-blocking look");
        match channel::recv(&stub) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!(
                "nothing may reach the helper for a command the worker refuses, but it was sent \
                 {other:?}"
            ),
        }
        drop(spawner);
    }

    /// Takes `auth`'s send lock on a thread of its own, holds it for `hold`
    /// -- the way a send stuck on a full socket holds it -- and lets go.
    /// Returns once the lock is really held.
    fn hold_send_lock_for(auth: &Arc<HelperAuth>, hold: Duration) -> JoinHandle<()> {
        let auth = Arc::clone(auth);
        let (held_tx, held_rx) = mpsc::channel::<()>();
        let holder = std::thread::spawn(move || {
            let guard = auth.lock_sender();
            held_tx.send(()).expect("the test is waiting");
            std::thread::sleep(hold);
            drop(guard);
        });
        held_rx
            .recv_timeout(TEST_RECV_TIMEOUT)
            .expect("the holder must take the lock");
        holder
    }

    /// A call's budget is its OWN, and counts from before the call waits for
    /// the send lock: one queued behind another sender gives up at its own
    /// deadline, not at its deadline plus the wait. The deadline is fixed
    /// before the lock for exactly this reason (see `HelperAuth::ask`) --
    /// the router that asked for a nonce is held for as long as the call
    /// takes.
    ///
    /// The lock is held only for a send now, but a send to a helper that
    /// has stopped reading holds it for up to the socket's send timeout. A
    /// stand-in holds it here for most of the call's budget; nothing ever
    /// answers. With the deadline fixed after the lock, the call would wait
    /// the holder out and then a whole budget of its own.
    #[test]
    fn a_call_queued_behind_another_gives_up_at_its_own_budget() {
        /// Long enough that scheduling noise cannot be mistaken for the
        /// holder's wait added on top, short enough to wait out in a test.
        const BUDGET: Duration = Duration::from_millis(800);
        const HOLD: Duration = Duration::from_millis(600);

        // Held, never read: the call's request goes out and is never
        // answered, and the seam stays open throughout.
        let (worker, _stub_end) = super::channel::pair().expect("socketpair");
        let auth =
            Arc::new(HelperAuth::with_timeout(worker, BUDGET).expect("the authentication client"));

        let holder = hold_send_lock_for(&auth, HOLD);
        let started = Instant::now();
        let result = auth.issue();
        let took = started.elapsed();
        holder.join().expect("join the holder");

        assert!(result.is_err(), "nothing answered the call");
        assert!(
            took < BUDGET + (BUDGET - HOLD) * 3 / 2,
            "a call that waited {HOLD:?} for the send lock must still give up at its own budget \
             ({BUDGET:?}), not at the wait plus a budget; it took {took:?}"
        );
    }

    /// A call whose deadline passes while it waits for the seam's send lock
    /// sends NOTHING once it gets the lock. Its caller has given up by then,
    /// and a `Verify` sent anyway would still be checked by the helper --
    /// and, if it verified, trust an account for a handshake the transport
    /// refused.
    ///
    /// The lock is ordinarily held for one send, but a send stuck on a full
    /// socket holds it for up to the send timeout, which can outlast what is
    /// left of a call's budget. A stand-in holds it here instead, for as long
    /// as the test needs.
    ///
    /// Checked on the stub's end of the seam, not on the call's result: an
    /// error comes back either way, from a call that sent nothing and from
    /// one that sent its request and then timed out at once. The positive
    /// control goes first, on the same seam: a call that gets the lock with
    /// time to spare DOES reach the stub, so the silence after the second
    /// call means something.
    #[test]
    fn a_call_that_runs_out_of_time_waiting_for_the_lock_sends_nothing() {
        const BUDGET: Duration = Duration::from_millis(200);
        const HASH: [u8; 32] = [7u8; 32];

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        // Both looks at the stub's end are non-blocking: `bounded` returns
        // only once each call has finished, so whatever that call sent is
        // already in the socket by then, and a read that waited could only
        // turn a failure into a stall.
        stub.set_nonblocking(true).expect("a non-blocking stub");
        let auth =
            Arc::new(HelperAuth::with_timeout(worker, BUDGET).expect("the authentication client"));
        let record = record_for(&key, "someone", &HASH, [9u8; AUTH_NONCE_LEN]);
        let sent = || -> io::Result<Option<String>> {
            channel::recv(&stub)
                .map(|m| m.map(|(bytes, _)| String::from_utf8_lossy(&bytes).into_owned()))
        };
        let verify_now = || {
            let auth = Arc::clone(&auth);
            let record = record.clone();
            bounded(move || auth.verify(&HASH, &record, [0u8; 16], ""))
        };

        // Positive control: the lock comes free with most of the budget
        // left, so the request goes out -- unanswered, the call then gives
        // up on its own.
        let holder = hold_send_lock_for(&auth, BUDGET / 4);
        let in_time = verify_now();
        holder.join().expect("join the holder");
        assert!(in_time.is_err(), "control: nothing answered that call");
        match sent() {
            Ok(Some(request)) if request.contains("Verify") => {}
            other => panic!(
                "control: a call that got the lock in time must reach the helper, or the silence \
                 checked below proves nothing -- the helper's end held {other:?}"
            ),
        }

        // The call under test: its whole budget passes while the lock is
        // held elsewhere.
        let holder = hold_send_lock_for(&auth, BUDGET * 3);
        let too_late = verify_now();
        holder.join().expect("join the holder");
        assert!(too_late.is_err(), "a call that ran out of time must fail");
        match sent() {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!(
                "a call whose deadline passed while it waited for the lock must send nothing, \
                 but the helper's end held {other:?}"
            ),
        }
    }

    /// The channel seam's mirror of the authentication seam's test below: a
    /// helper that has stopped reading must cost `spawn` one send's budget,
    /// not the `tx` mutex -- and with it every other channel's `spawn` and
    /// `kill` -- forever.
    ///
    /// Filled with `MSG_DONTWAIT` sends rather than by making the socket
    /// non-blocking, for the reason spelled out in that sibling test: the
    /// non-blocking flag belongs to the open file description every
    /// duplicate shares, so the spawner's own send would fail at once and
    /// the timeout would never be what this observes.
    #[test]
    fn a_helper_that_stops_reading_costs_the_channel_seam_a_send_not_forever() {
        let (worker, _never_read) = super::channel::pair().expect("socketpair");
        let filler = [0u8; 100];
        let mut queued = 0usize;
        loop {
            match nix::sys::socket::send(
                worker.as_raw_fd(),
                &filler,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(_) => queued += 1,
                Err(nix::Error::EAGAIN) => break,
                Err(e) => panic!("filling the seam failed after {queued} records: {e}"),
            }
            assert!(queued < 100_000, "the seam never filled");
        }
        let spawner = Arc::new(
            HelperChannelSpawner::with_send_timeout(worker, SHORT_ANSWER_TIMEOUT).expect("spawner"),
        );

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            let result = spawner.spawn(&anyone(), any_login(), &shell_request(), None);
            let _ = done_tx.send((started.elapsed(), result.err()));
        });
        let (took, error) = done_rx.recv_timeout(Duration::from_secs(3)).expect(
            "a helper that stops reading must not block spawn for good: its send must give up \
             at its budget",
        );
        let error = error.expect("nothing could have answered this spawn, yet it succeeded");
        assert!(
            error.contains("could not reach the helper"),
            "spawn must fail at its own send, got: {error}"
        );
        assert!(
            took >= SHORT_ANSWER_TIMEOUT / 2,
            "the send must have waited on the full queue (it returned after {took:?}), or this \
             test proved nothing about the send timeout"
        );
    }

    /// A helper that has stopped reading costs a send its budget, not a
    /// thread forever: the worker's end of the authentication seam carries a
    /// send timeout. The stub's end is held and never read, and the
    /// worker-to-helper direction is filled until the kernel refuses more.
    /// After that, `release` must come back at once -- it only queues its
    /// tell, the release thread sends it -- and `issue`, which sends what is
    /// queued and then itself, must fail once those sends give up: within a
    /// bound that a send blocked for good would blow straight through.
    ///
    /// The queue is filled with `MSG_DONTWAIT` sends, not by switching the
    /// socket to non-blocking: that switch belongs to the open file
    /// description every duplicate shares, so `HelperAuth`'s own sends would
    /// then fail at once, timeout or no timeout, and the test would prove
    /// nothing. The lower bound on `issue`'s wait below checks exactly that:
    /// its sends really did wait on a full queue.
    #[test]
    fn a_helper_that_stops_reading_costs_a_send_its_budget_not_forever() {
        let (worker, _never_read) = super::channel::pair().expect("socketpair");
        let filler = [0u8; 100];
        let mut queued = 0usize;
        loop {
            match nix::sys::socket::send(
                worker.as_raw_fd(),
                &filler,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(_) => queued += 1,
                Err(nix::Error::EAGAIN) => break,
                Err(e) => panic!("filling the seam failed after {queued} records: {e}"),
            }
            assert!(queued < 100_000, "the seam never filled");
        }
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");

        let (done_tx, done_rx) = mpsc::channel();
        std::thread::spawn(move || {
            let started = Instant::now();
            auth.release([1u8; AUTH_NONCE_LEN]);
            let released_after = started.elapsed();
            let issued = auth.issue();
            let issued_after = started.elapsed() - released_after;
            let _ = done_tx.send((released_after, issued, issued_after));
        });
        let (released_after, issued, issued_after) =
            done_rx.recv_timeout(Duration::from_secs(3)).expect(
                "a helper that stops reading must not block release and issue for good: each \
                 send must give up at its budget",
            );
        assert!(
            released_after < SHORT_ANSWER_TIMEOUT / 2,
            "release must only queue its tell, never wait on the full queue (it returned after \
             {released_after:?})"
        );
        assert!(
            issued_after >= SHORT_ANSWER_TIMEOUT / 2,
            "issue must have waited on the full queue (it returned after {issued_after:?}), or \
             this test proved nothing about the send timeout"
        );
        match issued {
            Err(why) => assert!(
                why.contains("reaching the helper") || why.contains("did not answer within"),
                "issue must fail at a send or at its deadline, got: {why}"
            ),
            Ok(nonce) => panic!("nothing could have answered this issue, yet it got {nonce:?}"),
        }
    }

    /// The worker's `LoginSink` really does tell the helper a login is over.
    ///
    /// `helper::server`'s own tests cover what the helper DOES with a
    /// `Request::LoginEnded` -- but they put that message on the wire
    /// themselves, which is precisely the state this side's one statement
    /// would have produced. So the helper's handling was pinned while the
    /// worker ever SENDING it was not, and deleting the body of
    /// `LoginSink::login_ended` left the whole suite green. Unsent, the
    /// helper keeps an ended session's account verified for ever, and its
    /// bounded login table fills with logins nothing retires -- past
    /// `MAX_LOGINS` every new login on the daemon is refused, for every
    /// account.
    ///
    /// Proven through the helper's own BEHAVIOUR rather than by watching the
    /// wire: while the login is live the helper opens a channel for it, and
    /// once the login has ended it must not.
    #[test]
    fn a_login_that_ends_is_reported_to_the_helper() {
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let TestHelper {
            channels,
            auth,
            thread,
            dir: _dir,
            me,
            login: _login,
        } = helper_trusting(&key, running_as_root());
        // The harness bounds every raw read with a timeout; the spawner's
        // reader thread would take that for the helper being gone.
        channels
            .set_read_timeout(None)
            .expect("clear the receive timeout");
        let auth = HelperAuth::new(auth, &test_config()).expect("the authentication client");
        let hash = [7u8; 32];
        let nonce = auth.issue().expect("the helper issues a nonce");
        let login: LoginId = [9u8; 16];
        let owner = auth
            .verify(
                &hash,
                &record_for(&key, &me, &hash, nonce),
                login,
                PROOF_RHOST,
            )
            .expect("the helper admits this test's own account");
        let spawner = Arc::new(HelperChannelSpawner::new(channels).expect("spawner"));

        // Setup, and the control for the assertion below: while the login is
        // live the helper opens a channel for it.
        let mut first = bounded({
            let spawner = Arc::clone(&spawner);
            let owner = owner.clone();
            move || spawner.spawn(&owner, login, &shell_request(), None)
        })
        .expect("the helper must open a channel while the login is live");
        first.wait.kill();
        let _ = bounded(move || first.wait.wait());

        // The statement under test.
        LoginSink::login_ended(&auth, login);
        // `LoginEnded` is a tell, not an ask. The seam is served strictly in
        // order, so a round trip on the SAME seam proves it has been applied
        // -- without this the check below races the helper's own loop.
        let barrier = auth.issue().expect("the helper still answers");
        auth.release(barrier);

        let after = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&owner, login, &shell_request(), None)
        });
        // The REASON, not merely the failure. `is_err()` alone would pass for
        // any refusal at all -- a helper that died, a seam that closed, a
        // `spawn` that tripped over something unrelated -- and this test is
        // the pin on a daemon-wide denial of service, so an assertion that
        // survives the thing it watches being removed is worth little. The
        // helper's own words for "I no longer know this account" are what
        // prove the login was retired, and nothing else produces them.
        let why = match after {
            Ok(_) => panic!(
                "once the worker reports the login ended, the helper must stop opening channels \
                 for that account"
            ),
            Err(e) => e,
        };
        assert!(
            why.contains("has not authenticated"),
            "the refusal must be the helper forgetting this account (its \
             UNVERIFIED_ACCOUNT_REASON), not some other failure standing in for it, got: {why}"
        );

        drop(spawner);
        join_within(
            thread,
            "the helper loop must end once the spawner closes the channel seam",
        );
    }

    /// The other half of the mutual watch `helper/mod.rs` promises: when the
    /// HELPER dies, the worker acts on it. In production the hook ends the
    /// process (`helper::split_and_run`); here it records that it fired,
    /// which is the same fact without taking the test binary down with it.
    ///
    /// The mirror of `dropping_the_spawner_marks_the_disconnect_as_local`,
    /// which covers only the NEGATIVE direction -- that a local `Drop` must
    /// NOT fire the hook. Nothing asserted it fires when the helper really
    /// dies, and every other test here builds its spawner with
    /// `HelperChannelSpawner::new`, whose hook is `|| {}`. Without the call,
    /// a dead helper leaves the worker running half-alive: holding the
    /// listening port and every pty, unable to open another channel for
    /// anyone, and blocking a restart from taking the port.
    #[test]
    fn a_helper_that_dies_ends_the_worker() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        let (fired_tx, fired_rx) = mpsc::channel::<()>();
        let spawner = HelperChannelSpawner::new_with_hook(
            worker,
            move || {
                let _ = fired_tx.send(());
            },
            Box::new(|_, _| {}),
        )
        .expect("spawner");

        // The helper dies. Not a local `Drop` of the spawner -- that is the
        // other fact, and the mirror test above is what covers it.
        drop(helper);

        fired_rx
            .recv_timeout(TEST_RECV_TIMEOUT)
            .expect("the worker must act on the helper's death, not run on without it");
        drop(spawner);
    }

    /// How long a stub waits for the `Close` an abandoned open must produce.
    /// Comfortably past [`SHORT_ANSWER_TIMEOUT`], which is what the
    /// abandoning `spawn` waits out first, and short enough that a
    /// regression that stops sending it fails the test promptly instead of
    /// idling for [`TEST_RECV_TIMEOUT`].
    const ABANDON_CLOSE_WAIT: Duration = Duration::from_secs(2);

    /// An open the helper never answers is given up on -- and giving up is
    /// not nothing. By then the helper may already have started the child,
    /// and a channel whose process is running with no `ChannelWait` anywhere
    /// is a process nothing can ever end, as `abandon`'s own docs say. So
    /// the worker asks for that id to be closed (or one process per timed-out
    /// open, running as the TARGET account, survives for the daemon's life),
    /// and drops its own bookkeeping for it (or every such id accumulates,
    /// with both its senders, for the process's life). Both halves were
    /// deletable with the suite staying green.
    ///
    /// A stub that reads the `Open` and answers nothing stands in for a
    /// helper wedged mid-open; the reply budget is this test's own, so it
    /// does not wait out `OPEN_REPLY_TIMEOUT`'s production six seconds.
    #[test]
    fn an_abandoned_open_is_closed_and_leaves_no_bookkeeping() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        helper
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let stub = std::thread::spawn(move || {
            let (bytes, _fd) = channel::recv(&helper).expect("recv").expect("open");
            let Request::Open { id, .. } = decode::<Request>(&bytes).expect("decode") else {
                panic!("expected an Open request");
            };
            // Answered with nothing at all: `spawn` has to give up on its
            // own. Whatever it sends next is what this test is about.
            helper
                .set_read_timeout(Some(ABANDON_CLOSE_WAIT))
                .expect("a shorter bound for the last read");
            let next = match channel::recv(&helper) {
                Ok(Some((bytes, _))) => Some(decode::<Request>(&bytes).expect("decode")),
                _ => None,
            };
            (id, next, helper)
        });

        let spawner = Arc::new(
            HelperChannelSpawner::with_open_timeout(worker, SHORT_ANSWER_TIMEOUT).expect("spawner"),
        );
        let result = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &shell_request(), None)
        });
        let err = match result {
            Ok(_) => panic!("nothing answered this open, yet it succeeded"),
            Err(e) => e,
        };
        assert!(
            err.contains("did not answer an open request in time"),
            "spawn must give up on the unanswered reply, got: {err}"
        );

        // The stub's end of the pair comes back alive rather than being
        // dropped when its thread ends: the reader thread clears the WHOLE
        // `waiting` map the moment its peer goes away, which would stand in
        // for the removal the second assertion below is about and prove
        // nothing about it. (Checked: with it dropped, deleting that removal
        // left this test green.)
        let (id, next, helper) = stub.join().expect("join");
        assert_eq!(
            next,
            Some(Request::Close { id }),
            "an open the worker gave up on must be closed, or its process outlives every handle \
             to it"
        );
        assert_eq!(
            spawner.waiting.lock().unwrap().len(),
            1,
            "abandonment retains the proof route"
        );
        channel::send(
            &helper,
            &encode(&Response::CleanupComplete {
                id,
                kind: CleanupKind::Reaped,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        wait_for("abandoned receipt retires its ticket", &|| {
            spawner.waiting.lock().unwrap().is_empty()
        });
    }

    /// A refused outcome retains its receipt route. NoChild retires that exact
    /// ticket while the socket remains open, so EOF cannot fake the removal.
    #[test]
    fn a_failed_open_leaves_no_bookkeeping_behind() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        helper
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let stub = std::thread::spawn(move || {
            let (bytes, _fd) = channel::recv(&helper).expect("recv").expect("open");
            let Request::Open { id, .. } = decode::<Request>(&bytes).expect("decode") else {
                panic!("expected an Open request");
            };
            let refusal = Response::Failed {
                id,
                reason: "this stub opens nothing".to_string(),
            };
            channel::send(&helper, &encode(&refusal).expect("encode"), None).expect("reply");
            (helper, id)
        });

        let spawner = Arc::new(HelperChannelSpawner::new(worker).expect("spawner"));
        let result = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &shell_request(), None)
        });
        assert!(result.is_err(), "the stub refuses every channel");

        // Held open for the assertion below -- see this test's doc comment.
        let (helper, id) = stub.join().expect("join");
        assert_eq!(
            spawner.waiting.lock().unwrap().len(),
            1,
            "outcome alone cannot retire cleanup custody"
        );
        channel::send(
            &helper,
            &encode(&Response::CleanupComplete {
                id,
                kind: CleanupKind::NoChild,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        wait_for("receipt retires bookkeeping", &|| {
            spawner.waiting.lock().unwrap().is_empty()
        });
        assert!(
            spawner.waiting.lock().expect("not poisoned").is_empty(),
            "a channel the helper refused must leave no entry behind"
        );
    }

    /// Installed Exited delivery and terminal cleanup are separate: preserve
    /// the real exit code, then retire bookkeeping only after exact Reaped.
    #[test]
    fn an_exited_channel_leaves_no_bookkeeping_behind() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        helper
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let (report_exit, allow_exit) = std::sync::mpsc::sync_channel(1);
        let stub = std::thread::spawn(move || {
            let (bytes, _fd) = channel::recv(&helper).expect("recv").expect("open");
            let Request::Open { id, .. } = decode::<Request>(&bytes).expect("decode") else {
                panic!("expected an Open request");
            };
            let fake_master = tempfile::tempfile().expect("a fake master descriptor");
            let opened = encode(&Response::Opened { id }).expect("encode");
            channel::send(&helper, &opened, Some(fake_master.as_fd())).expect("reply");
            allow_exit
                .recv_timeout(TEST_RECV_TIMEOUT)
                .expect("exit permission");
            let exited = encode(&Response::Exited { id, code: 7 }).expect("encode");
            channel::send(&helper, &exited, None).expect("report the exit");
            (helper, id)
        });

        let spawner = Arc::new(HelperChannelSpawner::new(worker).expect("spawner"));
        let mut channel = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &shell_request(), None)
        })
        .expect("spawn");
        use transport::channel_server::ChildStatus;
        assert!(matches!(channel.wait.poll_exit(), ChildStatus::Running));
        report_exit.send(()).unwrap();
        let (status, mut channel) = bounded(move || {
            let deadline = std::time::Instant::now() + TEST_RECV_TIMEOUT;
            loop {
                match channel.wait.poll_leader_status() {
                    Some(transport::channel_server::LeaderStatus::Exited { code }) => {
                        break (code, channel)
                    }
                    Some(transport::channel_server::LeaderStatus::Unknown(detail)) => {
                        panic!("exact helper status lost: {detail}")
                    }
                    _ => {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "leader status missing"
                        );
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            }
        });
        assert_eq!(
            status,
            Some(7),
            "poll retains the helper's actual exit status"
        );

        assert!(
            matches!(channel.wait.poll_exit(), ChildStatus::Running),
            "leader status alone must not release custody"
        );
        // Held open for the assertion below, for the reason the twin test
        // above spells out.
        let (helper, id) = stub.join().expect("join");
        assert_eq!(
            spawner.waiting.lock().unwrap().len(),
            1,
            "outcome alone cannot retire cleanup custody"
        );
        channel::send(
            &helper,
            &encode(&Response::CleanupComplete {
                id,
                kind: CleanupKind::Reaped,
            })
            .unwrap(),
            None,
        )
        .unwrap();
        wait_for("receipt retires bookkeeping", &|| {
            spawner.waiting.lock().unwrap().is_empty()
        });
        assert!(
            matches!(
                channel.wait.poll_exit(),
                ChildStatus::Reaped { code: Some(7) }
            ),
            "the explicit final receipt preserves the cached code"
        );
        assert!(
            spawner.waiting.lock().expect("not poisoned").is_empty(),
            "a channel that has reported its exit must leave no entry behind"
        );
    }

    /// The worker ACTS on the news rather than dropping it: an unsolicited
    /// `LoginEnded` -- the third kind of message this seam carries, and the
    /// only one that names no channel id -- reaches the sink the router
    /// gave the spawner, naming the login the helper named.
    ///
    /// The wait is bounded, so a reader that drops the message fails this
    /// test on its own `expect` rather than hanging the run.
    #[test]
    fn a_login_ended_from_the_helper_reaches_the_router() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        let login: LoginId = [42u8; 16];
        let incarnation = 9u64;
        let (tx, rx) = mpsc::channel::<(LoginId, u64)>();
        // Held to the end of the test: dropping the spawner shuts the seam
        // down, and the reader thread with it.
        let _spawner = HelperChannelSpawner::with_login_ended_sink(
            worker,
            Box::new(move |ended, which| {
                let _ = tx.send((ended, which));
            }),
        )
        .expect("spawner");

        let news = encode(&Response::LoginEnded { login, incarnation }).expect("encode");
        channel::send(&helper, &news, None).expect("report the end of a login");

        let got = rx
            .recv_timeout(TEST_RECV_TIMEOUT)
            .expect("the worker must hand the end of a login to the router, bounded");
        assert_eq!(
            got,
            (login, incarnation),
            "it must name the login the helper named, and WHICH LIFE of it -- the router drops \
             a report older than the session it has"
        );
    }

    /// And it is handed on ONCE per notice, in the order the helper sent
    /// them: the worker ends one session per login that ended, not one per
    /// login it has ever heard of.
    #[test]
    fn each_login_the_helper_ends_is_handed_on_once_and_in_order() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        let first: LoginId = [1u8; 16];
        let second: LoginId = [2u8; 16];
        let (tx, rx) = mpsc::channel::<(LoginId, u64)>();
        let _spawner = HelperChannelSpawner::with_login_ended_sink(
            worker,
            Box::new(move |ended, which| {
                let _ = tx.send((ended, which));
            }),
        )
        .expect("spawner");

        for (login, incarnation) in [(first, 1u64), (second, 2u64)] {
            let news = encode(&Response::LoginEnded { login, incarnation }).expect("encode");
            channel::send(&helper, &news, None).expect("report the end of a login");
        }

        assert_eq!(
            rx.recv_timeout(TEST_RECV_TIMEOUT),
            Ok((first, 1)),
            "the first login the helper ended"
        );
        assert_eq!(
            rx.recv_timeout(TEST_RECV_TIMEOUT),
            Ok((second, 2)),
            "then the second, in the order they were sent"
        );
        assert!(
            rx.recv_timeout(SHORT_ANSWER_TIMEOUT).is_err(),
            "and nothing else: two notices are two ended sessions, not more"
        );
    }

    /// A request that could not be sent gets no response, ever -- so `spawn`
    /// retains the entry it inserted moments earlier rather than refunding it
    /// for a reader thread that has no way to know about an id which arrived
    /// after it gave up.
    ///
    /// The helper here is wedged rather than gone, which is the situation
    /// that actually reaches this path -- and the only one that can witness
    /// it: with the peer CLOSED, the reader thread's own `waiting.clear()`
    /// fires on that same event and clears the map whether or not `spawn`
    /// cleaned up after itself. So the seam is filled until the kernel
    /// refuses more (with `MSG_DONTWAIT`, for the reason its sibling tests
    /// spell out) and the peer is kept alive.
    #[test]
    fn a_request_send_failure_keeps_unknown_cleanup_charged() {
        let (worker, _never_read) = super::channel::pair().expect("socketpair");
        let filler = [0u8; 100];
        let mut queued = 0usize;
        loop {
            match nix::sys::socket::send(
                worker.as_raw_fd(),
                &filler,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(_) => queued += 1,
                Err(nix::Error::EAGAIN) => break,
                Err(e) => panic!("filling the seam failed after {queued} records: {e}"),
            }
            assert!(queued < 100_000, "the seam never filled");
        }
        let spawner = Arc::new(
            HelperChannelSpawner::with_send_timeout(worker, SHORT_ANSWER_TIMEOUT).expect("spawner"),
        );

        let result = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &shell_request(), None)
        });
        let err = match result {
            Ok(_) => panic!("nothing could have answered this spawn, yet it succeeded"),
            Err(e) => e,
        };
        assert!(
            err.contains("could not reach the helper"),
            "spawn must fail at its own send, got: {err}"
        );
        assert_eq!(
            spawner.waiting.lock().unwrap().len(),
            1,
            "a generic send failure is not a cleanup receipt"
        );
        assert_eq!(
            spawner.open_registry().outstanding(),
            1,
            "unknown cleanup retains its charge"
        );
    }

    /// The production constructors really do install the production budgets.
    ///
    /// Both waits `spawn` makes are now held as state rather than read from a
    /// constant where they are used, and each has a test-only constructor
    /// beside it. That is what makes this test necessary rather than
    /// pedantic: with the budget in a field, lengthening the production
    /// default -- `OPEN_REPLY_TIMEOUT` to ten minutes, say -- changes nothing
    /// any other test here observes, because every one of them either hands
    /// in a budget of its own or never waits the default out. The harm is the
    /// one `OPEN_REPLY_TIMEOUT`'s own docs describe: `spawn` runs on a
    /// blocking-pool thread, so a budget that long parks one of those per
    /// wedged open. A test-only knob beside an unpinned production default is
    /// how a default quietly stops being the default.
    ///
    /// `HelperAuth` is checked in the same breath, for the same reason and
    /// against the same blind spot: it has had this shape -- a budget in a
    /// field, a test-only constructor next to it -- since before this file
    /// grew a second one. Its other budget, the wait for a verdict, is not a
    /// constant at all but derived from the helper's settings, and has a pin
    /// of its own:
    /// `the_wait_for_a_verdict_follows_the_helpers_own_deadline`.
    ///
    /// The two authentication constants are pinned by VALUE here as well.
    /// Every other check compares a field with the same constant the code
    /// uses, so a changed constant would pass them all.
    #[test]
    fn the_production_constructors_install_the_production_budgets() {
        // The values themselves, not only where they are used: every
        // request but a verification gets two seconds, and the margin on a
        // verdict only has to cover a loop that is running -- a longer one
        // keeps a probation's verification permit for as long.
        assert_eq!(
            HELPER_ANSWER_TIMEOUT,
            Duration::from_secs(2),
            "every request but a verification is given up on after two seconds"
        );
        assert_eq!(
            VERIFY_ANSWER_MARGIN,
            Duration::from_secs(1),
            "the worker waits one second past the helper's own deadline for a verdict"
        );

        let (worker, _helper) = super::channel::pair().expect("socketpair");
        let spawner = HelperChannelSpawner::new(worker).expect("spawner");
        assert_eq!(
            spawner.open_timeout, OPEN_REPLY_TIMEOUT,
            "production must wait exactly OPEN_REPLY_TIMEOUT for the helper's reply"
        );
        assert_eq!(
            spawner
                .tx
                .lock()
                .expect("the helper socket is never poisoned")
                .write_timeout()
                .expect("the socket reports its own send budget"),
            Some(CHANNEL_SEND_TIMEOUT),
            "production must bound every send on the channel seam by CHANNEL_SEND_TIMEOUT"
        );

        let (auth_worker, _auth_helper) = super::channel::pair().expect("socketpair");
        let auth =
            HelperAuth::new(auth_worker, &daemon_config()).expect("the authentication client");
        assert_eq!(
            auth.timeout, HELPER_ANSWER_TIMEOUT,
            "production must wait exactly HELPER_ANSWER_TIMEOUT for the answer to any request \
             but a verification on the authentication seam"
        );
        assert_eq!(
            auth.seam
                .lock_sender()
                .write_timeout()
                .expect("the socket reports its own send budget"),
            Some(HELPER_ANSWER_TIMEOUT),
            "production must bound every send on the authentication seam -- and with it every \
             hold of the send lock -- by HELPER_ANSWER_TIMEOUT"
        );
    }

    /// `Opened` with no descriptor alongside it is the helper breaking its
    /// own contract, and the worker says exactly that instead of letting the
    /// wait run out.
    ///
    /// The difference is entirely in what the next person to read the log is
    /// told. Refused here, the caller gets "sent no terminal", which names
    /// what happened; left to the budget, it gets "did not answer an open
    /// request in time", which sends whoever reads it hunting a wedged helper
    /// that is in fact answering promptly and wrongly. The budget is this
    /// test's own, so a regression that stops refusing is noticed at once
    /// rather than six seconds later.
    #[test]
    fn an_opened_without_a_terminal_is_refused_in_its_own_words() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        helper
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let stub = std::thread::spawn(move || {
            let (bytes, _fd) = channel::recv(&helper).expect("recv").expect("open");
            let Request::Open { id, .. } = decode::<Request>(&bytes).expect("decode") else {
                panic!("expected an Open request");
            };
            // The contract broken on purpose: `Opened`, and nothing carried
            // alongside it.
            let opened = encode(&Response::Opened { id }).expect("encode");
            channel::send(&helper, &opened, None).expect("reply");
            helper
        });

        let spawner = Arc::new(
            HelperChannelSpawner::with_open_timeout(worker, SHORT_ANSWER_TIMEOUT).expect("spawner"),
        );
        let result = bounded({
            let spawner = Arc::clone(&spawner);
            move || spawner.spawn(&anyone(), any_login(), &shell_request(), None)
        });
        let err = match result {
            Ok(_) => panic!("a channel with no terminal must be refused, not handed to the caller"),
            Err(e) => e,
        };
        assert!(
            err.contains("sent no terminal"),
            "the refusal must name the broken contract rather than blame a slow helper, got: {err}"
        );

        // Held to the end, like its sibling stubs: a peer that goes away is a
        // second way for the caller's wait to end, and this test is about
        // which of the two it was.
        let _helper = stub.join().expect("join");
    }

    /// Whether `auth`'s send lock could be taken, within a second, while
    /// `call` was still running: `None` if it never could, `Some(false)` if
    /// the call had already ended by then. Polled rather than tried once:
    /// a call lets go of the lock only after its send returns, a moment
    /// after the stub may already have read what it sent.
    fn send_lock_free_while<T>(auth: &HelperAuth, call: &JoinHandle<T>) -> Option<bool> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if auth.seam.sender.try_lock().is_ok() {
                return Some(!call.is_finished());
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// No call holds the seam's send lock while it waits for its answer --
    /// neither a verification nor a nonce request. Every other call needs
    /// that lock to send anything at all, so a call that kept it across its
    /// wait would line every call up behind the slowest answer in flight:
    /// the router's nonces behind a verification, and verifications behind
    /// each other.
    ///
    /// The stub reads each request and says nothing until the lock has been
    /// checked, so the call is certainly waiting while it is; its end stays
    /// open throughout.
    #[test]
    fn no_call_holds_the_send_lock_while_it_waits_for_its_answer() {
        const BUDGET: Duration = Duration::from_secs(5);
        const HASH: [u8; 32] = [7u8; 32];

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth =
            Arc::new(HelperAuth::with_timeout(worker, BUDGET).expect("the authentication client"));

        let verifying = {
            let auth = Arc::clone(&auth);
            let record = record_for(&key, "someone", &HASH, [9u8; AUTH_NONCE_LEN]);
            std::thread::spawn(move || auth.verify(&HASH, &record, [0u8; 16], ""))
        };
        let request = next_request(&stub);
        match send_lock_free_while(&auth, &verifying) {
            Some(true) => {}
            Some(false) => panic!("setup: the verification ended before anything answered it"),
            None => {
                panic!("a verification held the seam's send lock while it waited for its answer")
            }
        }
        answer(
            &stub,
            request.id,
            Response::Refused {
                reason: "authentication failed".to_string(),
            },
        );
        assert_eq!(
            verifying.join().expect("join"),
            Err(AuthError::KeyNotAuthorized),
            "control: the verification was waiting for exactly that answer"
        );

        let issuing = {
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || auth.issue())
        };
        let request = next_request(&stub);
        match send_lock_free_while(&auth, &issuing) {
            Some(true) => {}
            Some(false) => panic!("setup: the nonce request ended before anything answered it"),
            None => {
                panic!("a nonce request held the seam's send lock while it waited for its answer")
            }
        }
        let nonce: Nonce = [3u8; AUTH_NONCE_LEN];
        answer(&stub, request.id, Response::Nonce { nonce });
        assert_eq!(
            issuing.join().expect("join"),
            Ok(nonce),
            "control: the nonce request was waiting for exactly that answer"
        );
    }

    /// Verifications do not queue on the worker's side. Against an account
    /// database that takes [`SLOW_LOOKUP`] over every lookup, four proofs
    /// checked at once -- as many as the transport lets run at a time --
    /// finish in about ONE delay, not four: the helper checks each in a
    /// child of its own, and the worker sends all four at once and waits
    /// for each without holding the seam.
    ///
    /// A real helper, so the whole path is what is timed -- the worker's
    /// sends and waits and the helper's children -- with only the database
    /// standing in. The bound leaves one and a half delays for scheduling
    /// under load; four delays in a row cannot fit in it.
    #[test]
    fn four_slow_verifications_take_about_one_delay_not_four() {
        const PROOFS: u8 = 4;
        const HASH: [u8; 32] = [7u8; 32];

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let h = helper_trusting_a_slow_database(&key, running_as_root());
        let me = h.me.clone();
        let auth = Arc::new(
            HelperAuth::new(h.auth.try_clone().expect("clone"), &daemon_config())
                .expect("the authentication client"),
        );

        // The nonces first, one at a time: taking them is not what is timed.
        let proofs: Vec<(AuthRecord, LoginId)> = (1..=PROOFS)
            .map(|i| {
                let nonce = auth.issue().expect("the helper issues a nonce");
                (record_for(&key, &me, &HASH, nonce), [i; 16])
            })
            .collect();

        let started = Instant::now();
        let calls: Vec<JoinHandle<Result<Principal, AuthError>>> = proofs
            .into_iter()
            .map(|(record, login)| {
                let auth = Arc::clone(&auth);
                std::thread::spawn(move || auth.verify(&HASH, &record, login, ""))
            })
            .collect();
        // Every call is bounded by its own budget, so none of these joins
        // can hang.
        let verdicts: Vec<Result<Principal, AuthError>> = calls
            .into_iter()
            .map(|call| call.join().expect("join"))
            .collect();
        let took = started.elapsed();

        assert!(
            took < SLOW_LOOKUP * 5 / 2,
            "{PROOFS} verifications at once, against a database that takes {SLOW_LOOKUP:?} per \
             lookup, took {took:?} -- {:.1} delays; checked side by side they take about one",
            took.as_secs_f64() / SLOW_LOOKUP.as_secs_f64()
        );
        for verdict in &verdicts {
            assert!(
                matches!(verdict, Ok(principal) if principal.name == me),
                "every proof here is genuine and must be admitted, got {verdict:?}"
            );
        }
        assert!(
            took >= SLOW_LOOKUP,
            "control: the slow database must really have been in the way (the whole run took \
             {took:?}), or the bound above proves nothing"
        );

        drop(auth);
        h.stop();
    }

    /// Answers go to the calls that asked for them, whatever order they come
    /// back in. Two verifications wait at once; the stub answers the later
    /// request first, each with a verdict naming the login its own request
    /// carried. Handing either to the other call would let one client in
    /// under another's name.
    #[test]
    fn each_answer_reaches_the_call_that_asked_for_it() {
        const BUDGET: Duration = Duration::from_secs(5);
        const HASH: [u8; 32] = [7u8; 32];

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth =
            Arc::new(HelperAuth::with_timeout(worker, BUDGET).expect("the authentication client"));

        let calls: Vec<(&str, JoinHandle<Result<Principal, AuthError>>)> = ["alice", "bob"]
            .into_iter()
            .map(|login| {
                let auth = Arc::clone(&auth);
                let record = record_for(&key, login, &HASH, [1u8; AUTH_NONCE_LEN]);
                let call = std::thread::spawn(move || auth.verify(&HASH, &record, [0u8; 16], ""));
                (login, call)
            })
            .collect();
        let first = next_request(&stub);
        let second = next_request(&stub);
        for request in [second, first] {
            let Request::Verify { login, .. } = request.body else {
                panic!("expected a Verify, got {:?}", request.body);
            };
            answer(
                &stub,
                request.id,
                Response::Verified {
                    uid: 4242,
                    identity: format!("SHA256:{login}"),
                    name: login,
                    incarnation: 0,
                },
            );
        }

        for (login, call) in calls {
            let verdict = call.join().expect("join");
            assert_eq!(
                verdict.map(|principal| principal.name),
                Ok(login.to_string()),
                "the call that asked about {login} must get the verdict about {login}"
            );
        }
    }

    /// An answer that reaches the reader at or after its call's deadline is
    /// late -- never handed over, and a nonce in it released -- even though
    /// the call has not yet taken itself off the table; and the call, woken
    /// by that, reports running out of time, not a helper that is gone.
    /// Driven through `route` and `wait_for` directly, with an entry whose
    /// deadline is already now: in a real call the gap between its deadline
    /// and its leaving the table is far too short to aim at.
    #[test]
    fn an_answer_at_its_calls_deadline_is_late_even_before_the_call_leaves() {
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let late: Nonce = [0x5Au8; AUTH_NONCE_LEN];

        let (answer_tx, answer_rx) = mpsc::channel::<Delivery>();
        let deadline = Instant::now();
        let id = auth
            .seam
            .register(Waiter {
                answer: answer_tx,
                deadline,
            })
            .expect("the reader is running");
        auth.seam.route(
            AuthResponse {
                id,
                body: Response::Nonce { nonce: late },
            },
            &auth.late,
        );

        match auth.wait_for(id, &answer_rx, deadline, SHORT_ANSWER_TIMEOUT) {
            Err(AuthError::Backend(why)) => assert!(
                why.contains("did not answer within"),
                "a call whose answer came late must report running out of time, got: {why}"
            ),
            other => panic!(
                "an answer at or past its call's deadline must not be handed to that call, got \
                 {other:?}"
            ),
        }
        stub.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("a shorter bound: the releaser sends the nonce at once");
        match channel::recv(&stub) {
            Ok(Some((bytes, _))) => assert_eq!(
                decode::<AuthRequest>(&bytes).expect("decode").body,
                Request::ReleaseNonce { nonce: late },
                "a late nonce must go back to the helper"
            ),
            other => panic!(
                "a late nonce must go back to the helper, but nothing came: {:?}",
                other.map(|m| m.map(|(bytes, _)| String::from_utf8_lossy(&bytes).into_owned()))
            ),
        }
    }

    /// The other side of the same edge: an answer the reader handed over
    /// BEFORE the deadline is the call's, even if the call's own timer fires
    /// before it has looked -- it is in the call's channel, and nobody else
    /// can have it. Driven through `give_up` directly, after `route` has
    /// already handed the answer over: in a real call that ordering is a
    /// race far too narrow to aim at.
    #[test]
    fn an_answer_handed_over_in_time_is_taken_even_if_its_call_wakes_late() {
        let (worker, _stub_end) = super::channel::pair().expect("socketpair");
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let nonce: Nonce = [3u8; AUTH_NONCE_LEN];

        let (answer_tx, answer_rx) = mpsc::channel::<Delivery>();
        let id = auth
            .seam
            .register(Waiter {
                answer: answer_tx,
                deadline: Instant::now() + TEST_RECV_TIMEOUT,
            })
            .expect("the reader is running");
        auth.seam.route(
            AuthResponse {
                id,
                body: Response::Nonce { nonce },
            },
            &auth.late,
        );

        assert_eq!(
            auth.give_up(id, &answer_rx, SHORT_ANSWER_TIMEOUT),
            Ok(Response::Nonce { nonce }),
            "an answer handed over in time must be taken, not dropped with no release"
        );
    }

    /// An answer numbered above anything asked fails EVERY call then
    /// waiting, not just one: it comes from a helper whose answers can no
    /// longer be matched to questions on trust, and every waiting call is
    /// exposed to that alike. The stub then answers both calls properly,
    /// with admissions; neither may take one.
    #[test]
    fn an_answer_ahead_of_every_request_fails_every_waiting_call() {
        const BUDGET: Duration = Duration::from_secs(5);
        const HASH: [u8; 32] = [7u8; 32];

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth =
            Arc::new(HelperAuth::with_timeout(worker, BUDGET).expect("the authentication client"));

        let calls: Vec<JoinHandle<Result<Principal, AuthError>>> = ["alice", "bob"]
            .into_iter()
            .map(|login| {
                let auth = Arc::clone(&auth);
                let record = record_for(&key, login, &HASH, [1u8; AUTH_NONCE_LEN]);
                std::thread::spawn(move || auth.verify(&HASH, &record, [0u8; 16], ""))
            })
            .collect();
        let first = next_request(&stub);
        let second = next_request(&stub);
        let verified = Response::Verified {
            uid: 4242,
            name: "alice".to_string(),
            identity: "SHA256:alice".to_string(),
            incarnation: 0,
        };
        answer(&stub, first.id.max(second.id) + 6, verified.clone());
        answer(&stub, first.id, verified.clone());
        answer(&stub, second.id, verified);

        for call in calls {
            let result = call.join().expect("join");
            assert!(
                matches!(&result, Err(AuthError::Backend(why)) if why.contains("protocol violation")),
                "an answer numbered ahead of every request must fail every call waiting, as a \
                 protocol violation, got {result:?}"
            );
        }
    }

    /// A call that gives up takes its entry off the table: nothing will ever
    /// read its channel again, so an entry left behind is bookkeeping nobody
    /// reclaims -- one per unanswered request, for the life of the worker.
    /// The stub's end stays open, so the reader never clears the table
    /// itself.
    #[test]
    fn a_call_that_gives_up_leaves_no_entry_behind() {
        let (worker, _stub_end) = super::channel::pair().expect("socketpair");
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");

        assert!(auth.issue().is_err(), "nothing answered the call");
        assert!(
            auth.seam.lock_waiters().waiting.is_empty(),
            "a call that gave up must leave no entry behind"
        );
    }

    /// A request that could not be sent takes its entry off the table too:
    /// no answer is coming for it, ever. The helper here is wedged rather
    /// than gone -- the seam filled until the kernel refuses more, with
    /// `MSG_DONTWAIT` for the reason its sibling tests spell out -- because
    /// a closed peer would end the reader, which clears the whole table and
    /// would stand in for the removal under test.
    #[test]
    fn a_request_that_could_not_be_sent_leaves_no_entry_behind() {
        let (worker, _never_read) = super::channel::pair().expect("socketpair");
        let filler = [0u8; 100];
        let mut queued = 0usize;
        loop {
            match nix::sys::socket::send(
                worker.as_raw_fd(),
                &filler,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(_) => queued += 1,
                Err(nix::Error::EAGAIN) => break,
                Err(e) => panic!("filling the seam failed after {queued} records: {e}"),
            }
            assert!(queued < 100_000, "the seam never filled");
        }
        let auth = Arc::new(
            HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
                .expect("the authentication client"),
        );

        // Bounded: with no send timeout this call would block for ever.
        let issued = bounded({
            let auth = Arc::clone(&auth);
            move || auth.issue()
        });
        match issued {
            Err(why) => assert!(
                why.contains("reaching the helper"),
                "setup: the call must fail at its send, got: {why}"
            ),
            Ok(nonce) => panic!("nothing could have answered this call, yet it got {nonce:?}"),
        }
        assert!(
            auth.seam.lock_waiters().waiting.is_empty(),
            "a request that never reached the helper must leave no entry behind"
        );
    }

    /// The worker waits for a verdict at least as long as the helper may take
    /// to give one -- both budgets as the daemon resolves them -- and in fact
    /// a little longer. Waiting less, the worker gives up on a proof the
    /// helper may still admit, and an admission after that trusts the
    /// account, and opens a login entry, for a handshake the transport has
    /// already refused.
    #[test]
    fn the_worker_waits_for_a_verdict_as_long_as_the_helper_may_take() {
        let config = daemon_config();
        let (worker, _helper) = super::channel::pair().expect("socketpair");
        let auth = HelperAuth::new(worker, &config).expect("the authentication client");
        assert!(
            auth.verify_timeout >= config.verify_timeout,
            "the worker gives up on a verdict after {:?}, while the helper may take {:?} to give it",
            auth.verify_timeout,
            config.verify_timeout
        );
        // Equal is not enough: the helper's clock starts only when its loop
        // picks the request up, after the worker's has.
        assert!(
            auth.verify_timeout > config.verify_timeout,
            "the worker must wait for a verdict strictly longer than the helper's own deadline \
             ({:?}), which starts later than the worker's wait does; it waits {:?}",
            config.verify_timeout,
            auth.verify_timeout
        );
    }

    /// The same relation, as behaviour, with the budgets the daemon runs
    /// with: a verdict that comes later than a nonce's budget but inside
    /// the helper's own deadline still reaches the worker. That gap is
    /// where an admission used to land after the worker had given up.
    #[test]
    fn a_verdict_slower_than_a_nonces_budget_still_reaches_the_worker() {
        const HASH: [u8; 32] = [7u8; 32];
        let config = daemon_config();
        let delay = HELPER_ANSWER_TIMEOUT + Duration::from_millis(500);
        assert!(
            delay < config.verify_timeout,
            "setup: the verdict must come inside the helper's own deadline"
        );

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub_end) = super::channel::pair().expect("socketpair");
        stub_end
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = HelperAuth::new(worker, &config).expect("the authentication client");
        // The stub's end comes back rather than being dropped, so the seam
        // stays open until the assertion is done.
        let stub = std::thread::spawn(move || {
            let request = next_request(&stub_end);
            std::thread::sleep(delay);
            answer(
                &stub_end,
                request.id,
                Response::Verified {
                    uid: 4242,
                    name: "alice".to_string(),
                    identity: "SHA256:alice".to_string(),
                    incarnation: 0,
                },
            );
            stub_end
        });

        let verdict = auth.verify(
            &HASH,
            &record_for(&key, "alice", &HASH, [1u8; AUTH_NONCE_LEN]),
            [0u8; 16],
            "",
        );
        let _stub_end = stub.join().expect("join");
        assert_eq!(
            verdict.map(|principal| principal.name),
            Ok("alice".to_string()),
            "a verdict the helper gave {delay:?} after being asked -- inside its own deadline of \
             {:?} -- must reach the worker",
            config.verify_timeout
        );
    }

    /// The wait for a verdict is DERIVED from the helper's deadline, not
    /// merely equal to a value that fits it today: move the helper's
    /// deadline, and the worker's wait moves with it -- while every other
    /// request keeps [`HELPER_ANSWER_TIMEOUT`]. Two deadlines no production
    /// constant has, so no fixed value in place of the derivation passes
    /// both.
    #[test]
    fn the_wait_for_a_verdict_follows_the_helpers_own_deadline() {
        for deadline in [Duration::from_secs(3), Duration::from_secs(17)] {
            let config = HelperConfig {
                verify_timeout: deadline,
                ..daemon_config()
            };
            let (worker, _helper) = super::channel::pair().expect("socketpair");
            let auth = HelperAuth::new(worker, &config).expect("the authentication client");
            assert_eq!(
                auth.verify_timeout,
                deadline + VERIFY_ANSWER_MARGIN,
                "a helper deadline of {deadline:?} must give the worker a verdict wait of exactly \
                 that plus VERIFY_ANSWER_MARGIN"
            );
            assert_eq!(
                auth.timeout, HELPER_ANSWER_TIMEOUT,
                "every other request keeps its own budget, whatever the helper's deadline for a \
                 verification"
            );
        }
    }

    /// A nonce is given up on at its own budget -- the production two
    /// seconds -- even while a verification waits far longer for a slow
    /// verdict. The nonce pool's thread asks for every nonce the pool hands
    /// out, and holds the pool below its target for as long as that call
    /// takes; a slow account database must not stretch that to a
    /// verification's budget.
    ///
    /// Nothing answers either request until the end, and the stub's end
    /// stays open throughout: the helper vanishing would wake both calls at
    /// once and pass for a prompt refusal (the lower bound below would catch
    /// that too).
    #[test]
    fn a_nonce_gives_up_at_its_own_budget_while_a_slow_verification_waits() {
        /// Scheduling slack on top of the nonce's budget: far short of the
        /// verification's budget, which a nonce held behind it would take.
        const SLACK: Duration = Duration::from_secs(1);
        const HASH: [u8; 32] = [7u8; 32];

        let config = daemon_config();
        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = Arc::new(HelperAuth::new(worker, &config).expect("the authentication client"));

        let verifying = {
            let auth = Arc::clone(&auth);
            let record = record_for(&key, "someone", &HASH, [9u8; AUTH_NONCE_LEN]);
            std::thread::spawn(move || auth.verify(&HASH, &record, [0u8; 16], ""))
        };
        let verify_request = next_request(&stub);
        assert!(
            matches!(verify_request.body, Request::Verify { .. }),
            "setup: the verification is in flight"
        );

        let started = Instant::now();
        let refused = auth.issue();
        let took = started.elapsed();
        let verification_still_waiting = !verifying.is_finished();

        assert!(
            took < HELPER_ANSWER_TIMEOUT + SLACK,
            "a nonce asked for while a verification waited took {took:?}; its own budget is \
             {HELPER_ANSWER_TIMEOUT:?}"
        );
        assert!(
            took >= HELPER_ANSWER_TIMEOUT,
            "the nonce was refused after {took:?}, before its budget ran out -- not the refusal \
             this test is about"
        );
        match refused {
            Err(why) => assert!(
                why.contains("did not answer within"),
                "the nonce must be refused for running out of time, got: {why}"
            ),
            Ok(nonce) => panic!("nothing answered the nonce request, yet it got {nonce:?}"),
        }
        assert!(
            verification_still_waiting,
            "control: the verification must still have been waiting when the nonce was given up \
             on, or the two were never in flight together"
        );
        stub.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("a short bound for a request that is already there");
        assert_eq!(
            next_request(&stub).body,
            Request::Nonce,
            "control: the nonce request went out while the verification waited"
        );

        answer(
            &stub,
            verify_request.id,
            Response::Refused {
                reason: "authentication failed".to_string(),
            },
        );
        assert_eq!(
            verifying.join().expect("join"),
            Err(AuthError::KeyNotAuthorized),
            "control: the verification was waiting for its own answer all along"
        );
    }

    /// A nonce asked for by a deadline earlier than its own budget's end is
    /// given up on at that deadline, and says how long it waited -- the
    /// nonce pool's warm-up counts on it, to stay within one budget however
    /// many nonces it asks for. A deadline already past sends nothing.
    #[test]
    fn a_nonce_asked_for_by_a_deadline_is_given_up_on_at_that_deadline() {
        const CAP: Duration = Duration::from_millis(300);
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = HelperAuth::new(worker, &daemon_config()).expect("the authentication client");

        let started = Instant::now();
        let refused = auth.issue_by(started + CAP);
        let took = started.elapsed();

        assert_eq!(
            next_request(&stub).body,
            Request::Nonce,
            "setup: the request must have gone out"
        );
        assert!(
            took >= CAP && took < HELPER_ANSWER_TIMEOUT,
            "a nonce asked for by a deadline {CAP:?} away was given up on after {took:?}; its \
             own budget is {HELPER_ANSWER_TIMEOUT:?}"
        );
        match refused {
            Err(why) => assert!(
                why.contains("did not answer within")
                    && !why.contains(&format!("within {HELPER_ANSWER_TIMEOUT:?}")),
                "the refusal must name the wait the call actually had, not its whole budget, \
                 got: {why}"
            ),
            Ok(nonce) => panic!("nothing answered the nonce request, yet it got {nonce:?}"),
        }

        let refused = auth.issue_by(Instant::now());
        assert!(
            refused.is_err(),
            "a deadline already past must fail the call"
        );
        stub.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("a short bound for a request that must not be there");
        match channel::recv(&stub) {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            other => panic!("a call already out of time must send nothing, but sent {other:?}"),
        }
    }

    /// A login token for the tests of the tell queue, different for every
    /// `n`.
    fn login_number(n: usize) -> LoginId {
        let mut login = [0x4Cu8; 16];
        login[..8].copy_from_slice(&(n as u64).to_be_bytes());
        login
    }

    /// Whether `bytes` are a `LoginEnded` request.
    fn is_login_end(bytes: &[u8]) -> bool {
        matches!(
            decode::<AuthRequest>(bytes).map(|request| request.body),
            Ok(Request::LoginEnded { .. })
        )
    }

    /// Fails the send of `bytes` if they are a login's end and `refusals`
    /// still has one to spend -- the way a send to a full socket fails.
    fn refuse_a_login_end(refusals: &AtomicUsize, bytes: &[u8]) -> io::Result<()> {
        if is_login_end(bytes)
            && refusals
                .try_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "this test's send refuses a login's end",
            ));
        }
        Ok(())
    }

    /// Login ends the send of
    /// [`a_request_is_not_sent_ahead_of_a_login_end_that_could_not_be_sent`]
    /// refuses before it lets one through. That test's alone.
    static REFUSALS_BEFORE_A_REQUEST: AtomicUsize = AtomicUsize::new(0);

    fn send_refusing_before_a_request(sock: &UnixStream, bytes: &[u8]) -> io::Result<()> {
        refuse_a_login_end(&REFUSALS_BEFORE_A_REQUEST, bytes)?;
        send_request(sock, bytes)
    }

    /// Login ends the send of [`a_login_end_whose_send_fails_is_sent_again`]
    /// refuses before it lets one through. That test's alone.
    static REFUSALS_ON_THE_RELEASE_THREAD: AtomicUsize = AtomicUsize::new(0);

    fn send_refusing_on_the_release_thread(sock: &UnixStream, bytes: &[u8]) -> io::Result<()> {
        refuse_a_login_end(&REFUSALS_ON_THE_RELEASE_THREAD, bytes)?;
        send_request(sock, bytes)
    }

    /// The next message a stub has, within `bound`, or why there is none.
    fn next_within(stub: &UnixStream, bound: Duration) -> Result<Request, String> {
        stub.set_read_timeout(Some(bound))
            .expect("set a receive timeout on the stub's socket");
        match channel::recv(stub) {
            Ok(Some((bytes, _))) => decode::<AuthRequest>(&bytes)
                .map(|request| request.body)
                .map_err(|e| e.to_string()),
            Ok(None) => Err("the seam closed".to_string()),
            Err(e) => Err(e.to_string()),
        }
    }

    /// A tell queued before a request reaches the helper before it, even
    /// when nothing has woken the release thread: the request sends it
    /// first. Otherwise a `LoginEnded` the router queued could land after a
    /// `Verify` for the same login that followed it, and the helper would
    /// forget the login the proof had just put on file.
    #[test]
    fn a_queued_tell_leaves_before_a_later_request() {
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let login: LoginId = [7u8; 16];
        auth.queue_only_for_test(Request::LoginEnded { login });
        let _ = auth.issue();
        assert_eq!(
            next_request(&stub).body,
            Request::LoginEnded { login },
            "the tell queued first must reach the helper first"
        );
        assert_eq!(next_request(&stub).body, Request::Nonce, "then the request");
    }

    /// A request is not sent at all while a login's end queued before it
    /// cannot be: it would reach the helper first. The request wakes the
    /// release thread, which sends the end again; after that, requests go
    /// out.
    #[test]
    fn a_request_is_not_sent_ahead_of_a_login_end_that_could_not_be_sent() {
        let (worker, stub) = super::channel::pair().expect("socketpair");
        let auth = HelperAuth::with_end_worker(
            worker,
            SHORT_ANSWER_TIMEOUT,
            send_refusing_before_a_request,
            ignore_the_end(),
        )
        .expect("the authentication client");
        let login = login_number(1);
        REFUSALS_BEFORE_A_REQUEST.store(1, Ordering::SeqCst);
        auth.queue_only_for_test(Request::LoginEnded { login });

        let refused = auth.issue();
        assert!(
            refused.is_err(),
            "a request must fail while a login's end queued before it cannot be sent, got \
             {refused:?}"
        );
        assert_eq!(
            REFUSALS_BEFORE_A_REQUEST.load(Ordering::SeqCst),
            0,
            "setup: the login's end must have been refused"
        );

        assert_eq!(
            next_within(&stub, TEST_RECV_TIMEOUT),
            Ok(Request::LoginEnded { login }),
            "the login's end must reach the helper before any request made after it was queued"
        );
        assert!(
            wait_for_stuck(&auth, false),
            "setup: once the end is sent, it no longer counts as waiting"
        );
        let asking = std::thread::spawn(move || auth.issue());
        let request = next_request(&stub);
        assert_eq!(request.body, Request::Nonce, "then the second request");
        let nonce: Nonce = [4u8; AUTH_NONCE_LEN];
        answer(&stub, request.id, Response::Nonce { nonce });
        assert_eq!(
            join_within_value(asking),
            Ok(nonce),
            "the second request must get its answer"
        );
    }

    /// Joins a thread that returns a value, failing rather than hanging if it
    /// is still running after [`TEST_RECV_TIMEOUT`].
    fn join_within_value<T>(thread: JoinHandle<T>) -> T {
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while !thread.is_finished() {
            assert!(
                Instant::now() < deadline,
                "still running after {TEST_RECV_TIMEOUT:?}"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        thread.join().expect("the thread must not panic")
    }

    /// Whether `auth` comes to count a login's end as waiting to be sent
    /// again (`stuck`) -- or as no longer waiting -- within
    /// [`TEST_RECV_TIMEOUT`].
    fn wait_for_stuck(auth: &HelperAuth, stuck: bool) -> bool {
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while auth.seam.login_end_stuck.load(Ordering::SeqCst) != stuck {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        true
    }

    /// How long a send of a login's end takes to fail in
    /// [`a_request_fails_at_once_while_a_login_end_waits_to_be_sent_again`] --
    /// the way a send to a full socket takes its timeout.
    const STUCK_SEND: Duration = Duration::from_millis(300);

    /// Whether that test's send refuses the ends of logins just now, and how
    /// many such refusals have begun. That test's alone.
    static LOGIN_ENDS_STUCK: AtomicBool = AtomicBool::new(false);
    static STUCK_SENDS_BEGUN: AtomicUsize = AtomicUsize::new(0);

    fn send_with_login_ends_stuck(sock: &UnixStream, bytes: &[u8]) -> io::Result<()> {
        if is_login_end(bytes) && LOGIN_ENDS_STUCK.load(Ordering::SeqCst) {
            STUCK_SENDS_BEGUN.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(STUCK_SEND);
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "this test's send of a login's end is stuck",
            ));
        }
        send_request(sock, bytes)
    }

    /// While a login's end waits to be sent again, a request fails at once:
    /// it neither waits for the send lock -- which the release thread holds
    /// for a whole send each time it tries the end again -- nor tries the end
    /// itself. With the helper stuck no request could succeed anyway, and
    /// those that waited would hold their callers -- a probation's
    /// verification permits -- for as long as the send lock stayed busy.
    ///
    /// A request made while the end's FIRST send is still under way waits for
    /// the send lock, and must then fail the same way rather than try the end
    /// once more. Requests made during a retry must not wait at all. Nothing
    /// reaches the helper ahead of the end, and once the end gets through,
    /// requests go out again.
    #[test]
    fn a_request_fails_at_once_while_a_login_end_waits_to_be_sent_again() {
        const CALLS: usize = 4;
        let is_waiting = |result: &Result<Nonce, String>| matches!(result, Err(why) if why.contains("still waiting to be sent"));
        let (worker, stub) = super::channel::pair().expect("socketpair");
        LOGIN_ENDS_STUCK.store(true, Ordering::SeqCst);
        let auth = Arc::new(
            HelperAuth::with_end_worker(
                worker,
                SHORT_ANSWER_TIMEOUT,
                send_with_login_ends_stuck,
                ignore_the_end(),
            )
            .expect("the authentication client"),
        );
        let login = login_number(4);
        LoginSink::login_ended(&*auth, login);

        // The end's first send is under way: a request waits for the lock.
        assert!(
            wait_until_count(&STUCK_SENDS_BEGUN, 1),
            "setup: the end's first send must begin"
        );
        let during_the_first_send = auth.issue();
        assert!(
            is_waiting(&during_the_first_send),
            "a request that waited for the send lock while a login's end failed to go out must \
             fail because the end is waiting, not try the end itself or run out its time; got \
             {during_the_first_send:?}"
        );

        // A retry is under way: requests must not wait for it.
        assert!(
            wait_until_count(&STUCK_SENDS_BEGUN, 2),
            "setup: the release thread must try the end again"
        );
        let calls: Vec<JoinHandle<(Duration, Result<Nonce, String>)>> = (0..CALLS)
            .map(|_| {
                let auth = Arc::clone(&auth);
                std::thread::spawn(move || {
                    let started = Instant::now();
                    let result = auth.issue();
                    (started.elapsed(), result)
                })
            })
            .collect();
        let results: Vec<(Duration, Result<Nonce, String>)> =
            calls.into_iter().map(join_within_value).collect();
        let slowest = results
            .iter()
            .map(|(took, _)| *took)
            .max()
            .unwrap_or_default();
        assert!(
            slowest < STUCK_SEND / 6,
            "while a login's end waits to be sent again a request must fail at once, not wait \
             for the send lock: the slowest of {CALLS} took {slowest:?}"
        );
        assert!(
            results.iter().all(|(_, result)| is_waiting(result)),
            "each must say the end is waiting: {results:?}"
        );
        assert!(
            next_within(&stub, Duration::from_millis(50)).is_err(),
            "nothing may reach the helper ahead of the end"
        );

        // The helper reads again: the end goes through, and so do requests.
        LOGIN_ENDS_STUCK.store(false, Ordering::SeqCst);
        assert_eq!(
            next_within(&stub, TEST_RECV_TIMEOUT),
            Ok(Request::LoginEnded { login }),
            "setup: the end must go through once the helper reads again"
        );
        let asking = {
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || {
                let deadline = Instant::now() + TEST_RECV_TIMEOUT;
                loop {
                    let result = auth.issue();
                    if !is_waiting(&result) || Instant::now() >= deadline {
                        return result;
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
            })
        };
        let request = next_within(&stub, TEST_RECV_TIMEOUT);
        assert_eq!(
            request,
            Ok(Request::Nonce),
            "once the end has reached the helper, requests must go out again"
        );
        drop(stub);
        let _ = join_within_value(asking);
    }

    /// Whether `count` reaches `at_least` within [`TEST_RECV_TIMEOUT`].
    fn wait_until_count(count: &AtomicUsize, at_least: usize) -> bool {
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while count.load(Ordering::SeqCst) < at_least {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        true
    }

    /// A send that times out because the helper has stopped reading says so
    /// in words an operator can act on, not as "Resource temporarily
    /// unavailable".
    #[test]
    fn a_send_to_a_helper_that_is_not_reading_says_so() {
        let (worker, _never_read) = super::channel::pair().expect("socketpair");
        let filler = [0u8; 100];
        let mut filled = 0usize;
        loop {
            match nix::sys::socket::send(
                worker.as_raw_fd(),
                &filler,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(_) => filled += 1,
                Err(nix::Error::EAGAIN) => break,
                Err(e) => panic!("filling the seam failed after {filled} records: {e}"),
            }
            assert!(filled < 100_000, "the seam never filled");
        }
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");

        match auth.issue() {
            Err(why) => assert!(
                why.contains("reaching the helper: the helper is not reading (a send timed out)"),
                "a send that timed out must say the helper is not reading, got: {why}"
            ),
            Ok(nonce) => panic!("nothing could have answered this issue, yet it got {nonce:?}"),
        }
    }

    /// A login's end whose send fails is not given up: the release thread
    /// sends it again until it gets through -- with nothing else waking it --
    /// still ahead of everything queued after it, and a failed send does not
    /// end the worker.
    #[test]
    fn a_login_end_whose_send_fails_is_sent_again() {
        let (worker, stub) = super::channel::pair().expect("socketpair");
        let (ended_tx, ended_rx) = mpsc::channel::<String>();
        let auth = HelperAuth::with_end_worker(
            worker,
            SHORT_ANSWER_TIMEOUT,
            send_refusing_on_the_release_thread,
            Arc::new(move |why: &str| {
                let _ = ended_tx.send(why.to_string());
            }),
        )
        .expect("the authentication client");
        let first = login_number(2);
        let second = login_number(3);
        REFUSALS_ON_THE_RELEASE_THREAD.store(1, Ordering::SeqCst);

        auth.queue_only_for_test(Request::LoginEnded { login: first });
        LoginSink::login_ended(&auth, second);

        assert_eq!(
            next_within(&stub, TEST_RECV_TIMEOUT),
            Ok(Request::LoginEnded { login: first }),
            "a login's end whose send failed must be sent again until it reaches the helper, \
             still first"
        );
        assert_eq!(
            next_within(&stub, TEST_RECV_TIMEOUT),
            Ok(Request::LoginEnded { login: second }),
            "then the end queued after it"
        );
        assert_eq!(
            REFUSALS_ON_THE_RELEASE_THREAD.load(Ordering::SeqCst),
            0,
            "setup: the refused send must have happened first"
        );
        assert_eq!(
            ended_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty),
            "a send that failed must not end the worker"
        );
        drop(auth);
    }

    /// A request sending what is queued before it stops at its own deadline:
    /// with the helper not reading, every queued release costs a send
    /// timeout, and a request that sent them all would take that many times
    /// its budget. It fails as out of time, having sent nothing of its own.
    #[test]
    fn a_request_gives_up_on_what_is_queued_at_its_own_deadline() {
        const QUEUED: u8 = 5;
        let (worker, _never_read) = super::channel::pair().expect("socketpair");
        let filler = [0u8; 100];
        let mut filled = 0usize;
        loop {
            match nix::sys::socket::send(
                worker.as_raw_fd(),
                &filler,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ) {
                Ok(_) => filled += 1,
                Err(nix::Error::EAGAIN) => break,
                Err(e) => panic!("filling the seam failed after {filled} records: {e}"),
            }
            assert!(filled < 100_000, "the seam never filled");
        }
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        for n in 0..QUEUED {
            auth.queue_only_for_test(Request::ReleaseNonce {
                nonce: [n; AUTH_NONCE_LEN],
            });
        }

        let started = Instant::now();
        let refused = auth.issue();
        let took = started.elapsed();

        assert!(
            took < SHORT_ANSWER_TIMEOUT * 3,
            "a request took {took:?} over {QUEUED} queued tells; its budget is \
             {SHORT_ANSWER_TIMEOUT:?}"
        );
        match refused {
            Err(why) => assert!(
                why.contains("did not answer within"),
                "a request out of time before it could be sent must fail as out of time, got: \
                 {why}"
            ),
            Ok(nonce) => panic!("nothing could have answered this issue, yet it got {nonce:?}"),
        }
    }

    /// Dropping the client sends what is still queued before the seam
    /// closes, even if nothing woke the release thread.
    #[test]
    fn dropping_the_client_sends_what_is_still_queued() {
        let (worker, stub) = super::channel::pair().expect("socketpair");
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let login = login_number(3);
        auth.queue_only_for_test(Request::LoginEnded { login });

        drop(auth);

        assert_eq!(
            next_within(&stub, TEST_RECV_TIMEOUT),
            Ok(Request::LoginEnded { login }),
            "a tell still queued when the client is dropped must reach the helper before the seam \
             closes"
        );
    }

    /// A release that does not fit in the queue is dropped, and its nonce
    /// stays with the helper -- which expires it on its own
    /// (`helper::server`'s sweep tests pin that). Seen with a real helper:
    /// its table is filled, all but one of the nonces are queued for
    /// release -- with one more the helper never issued, to fill the queue's
    /// share -- and the release of the last one, past the bound, is dropped.
    /// Once the queue is sent, every slot but that one is free again.
    #[test]
    fn a_release_past_the_bound_is_dropped_and_its_nonce_stays_with_the_helper() {
        let (_worker_channels, helper_channels) = super::channel::pair().expect("socketpair");
        let (worker_auth, helper_auth) = super::channel::pair().expect("socketpair");
        let loop_thread = std::thread::spawn(move || {
            super::super::server::run_until_peer_closes(helper_channels, helper_auth, test_config())
        });
        let auth = HelperAuth::new(worker_auth, &test_config()).expect("the authentication client");
        let issued: Vec<Nonce> = (0..MAX_OUTSTANDING_NONCES)
            .map(|_| {
                auth.issue()
                    .expect("every request up to the cap is granted")
            })
            .collect();
        assert_eq!(
            MAX_QUEUED_RELEASES, MAX_OUTSTANDING_NONCES,
            "setup: the queue's share of releases is what this test fills"
        );

        for nonce in &issued[1..] {
            auth.queue_only_for_test(Request::ReleaseNonce { nonce: *nonce });
        }
        auth.queue_only_for_test(Request::ReleaseNonce {
            nonce: [0xEEu8; AUTH_NONCE_LEN],
        });
        auth.release(issued[0]);

        for _ in 1..MAX_OUTSTANDING_NONCES {
            auth.issue()
                .expect("every slot a queued release freed must be granted again");
        }
        match auth.issue() {
            Err(why) => assert!(
                why.contains("as many unspent nonces"),
                "the nonce whose release was dropped must still hold its slot in the helper, got: \
                 {why}"
            ),
            Ok(nonce) => panic!(
                "a release past the queue's bound must be dropped, yet its nonce's slot was freed \
                 (the helper issued {nonce:?})"
            ),
        }

        drop(auth);
        join_within(
            loop_thread,
            "the helper loop must end once the authentication seam closes",
        );
    }

    /// A login's end that does not fit in the queue is never dropped: the
    /// worker is ended, with the reason -- and the end is kept all the same,
    /// so a hook that returns (a test's) still sees it reach the helper, after
    /// every end queued before it.
    #[test]
    fn a_login_end_past_the_bound_ends_the_worker_and_is_still_sent() {
        let (worker, stub) = super::channel::pair().expect("socketpair");
        let (ended_tx, ended_rx) = mpsc::channel::<String>();
        let auth = HelperAuth::with_end_worker(
            worker,
            SHORT_ANSWER_TIMEOUT,
            send_request,
            Arc::new(move |why: &str| {
                let _ = ended_tx.send(why.to_string());
            }),
        )
        .expect("the authentication client");
        for n in 0..MAX_QUEUED_LOGIN_ENDS {
            auth.queue_only_for_test(Request::LoginEnded {
                login: login_number(n),
            });
        }
        assert_eq!(
            ended_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty),
            "setup: a queue within its bound must not end the worker"
        );

        LoginSink::login_ended(&auth, login_number(MAX_QUEUED_LOGIN_ENDS));

        assert_eq!(
            ended_rx.recv_timeout(TEST_RECV_TIMEOUT),
            Ok(LOGIN_ENDS_OVERFLOW_REASON.to_string()),
            "a login's end that does not fit in the queue must end the worker, never be dropped"
        );
        for n in 0..=MAX_QUEUED_LOGIN_ENDS {
            assert_eq!(
                next_within(&stub, TEST_RECV_TIMEOUT),
                Ok(Request::LoginEnded {
                    login: login_number(n)
                }),
                "every login's end must reach the helper, in order, the one past the bound too"
            );
        }
    }

    /// The queue's shares hold everything the worker can owe the helper
    /// while the helper does not read -- see the two constants' docs.
    #[test]
    fn the_queue_has_room_for_everything_the_worker_can_owe() {
        // Read at run time, so that a regression fails this test rather than
        // the build.
        let queued_login_ends = std::hint::black_box(MAX_QUEUED_LOGIN_ENDS);
        let queued_releases = std::hint::black_box(MAX_QUEUED_RELEASES);
        assert!(
            queued_login_ends >= MAX_SESSIONS_TOTAL + MAX_PROBATION,
            "the router may owe the end of every backend ({MAX_SESSIONS_TOTAL}) and of every proof \
             in probation ({MAX_PROBATION}); the queue holds {MAX_QUEUED_LOGIN_ENDS}"
        );
        assert!(
            queued_releases >= MAX_OUTSTANDING_NONCES,
            "the worker may owe a release for every nonce the helper holds \
             ({MAX_OUTSTANDING_NONCES}); the queue holds {MAX_QUEUED_RELEASES}"
        );
    }

    /// Whether [`the_client_logs_failed_and_dropped_tells_sparingly_body`]'s
    /// send refuses tells just now. That test's alone, in a process of its
    /// own.
    static REFUSE_TELLS: AtomicBool = AtomicBool::new(false);

    fn send_refusing_tells_on_command(sock: &UnixStream, bytes: &[u8]) -> io::Result<()> {
        let is_tell = matches!(
            decode::<AuthRequest>(bytes).map(|request| request.body),
            Ok(Request::LoginEnded { .. } | Request::ReleaseNonce { .. })
        );
        if is_tell && REFUSE_TELLS.load(Ordering::SeqCst) {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "this test's send refuses tells",
            ));
        }
        send_request(sock, bytes)
    }

    /// Failed tell sends and dropped releases are logged at the first, the
    /// second, the fourth... -- a helper stuck for hours must not fill the
    /// log -- and a spell of failures that follows a send that went through
    /// is logged from its first again.
    #[test]
    fn the_client_logs_failed_and_dropped_tells_sparingly() {
        let (status, stdout, stderr) = run_isolated(
            "helper::spawner::tests::the_client_logs_failed_and_dropped_tells_sparingly_body",
        );
        assert!(
            status.success(),
            "the isolated check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_client_logs_failed_and_dropped_tells_sparingly`],
    /// in a process of its own: it points this process's log at a file of its
    /// own, for good.
    #[test]
    #[ignore = "runs only via the_client_logs_failed_and_dropped_tells_sparingly, in a process of \
                its own"]
    fn the_client_logs_failed_and_dropped_tells_sparingly_body() {
        const FAILED: &str = "could not send the helper a tell";
        const DROPPED: &str = "nonce releases dropped so far";
        let dir = tempfile::tempdir().expect("tempdir");
        crate::log::init(dir.path());
        let log_path = dir.path().join("qshd.log");
        let log = || std::fs::read_to_string(&log_path).unwrap_or_default();
        let lines = |what: &str| log().matches(what).count();
        let wait_for = |what: &str, done: &dyn Fn() -> bool| {
            let deadline = Instant::now() + TEST_RECV_TIMEOUT;
            while !done() {
                assert!(Instant::now() < deadline, "{what}; the log is:\n{}", log());
                std::thread::sleep(Duration::from_millis(2));
            }
        };

        let (worker, stub) = super::channel::pair().expect("socketpair");
        let auth = HelperAuth::with_end_worker(
            worker,
            SHORT_ANSWER_TIMEOUT,
            send_refusing_tells_on_command,
            ignore_the_end(),
        )
        .expect("the authentication client");
        let failed = || auth.seam.failed_tell_sends.load(Ordering::SeqCst);

        REFUSE_TELLS.store(true, Ordering::SeqCst);
        for n in 0..5u8 {
            auth.release([n; AUTH_NONCE_LEN]);
        }
        wait_for("setup: five sends must fail", &|| failed() == 5);
        assert_eq!(
            lines(FAILED),
            3,
            "five failed sends in a row must be logged at the first, second and fourth; the log \
             is:\n{}",
            log()
        );

        REFUSE_TELLS.store(false, Ordering::SeqCst);
        auth.release([0x10u8; AUTH_NONCE_LEN]);
        assert_eq!(
            next_within(&stub, TEST_RECV_TIMEOUT),
            Ok(Request::ReleaseNonce {
                nonce: [0x10u8; AUTH_NONCE_LEN]
            }),
            "setup: a send that is not refused goes through"
        );
        REFUSE_TELLS.store(true, Ordering::SeqCst);
        auth.release([0x11u8; AUTH_NONCE_LEN]);
        // Not asserted: without a restart the line never comes, and the
        // assertion below says so.
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while lines(FAILED) < 4 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(
            lines(FAILED),
            4,
            "a new spell of failures must be logged from its first again; the log is:\n{}",
            log()
        );

        // Dropped releases, on a client of their own: nothing ever wakes its
        // release thread, so nothing can take a release off its queue while
        // the queue is being filled.
        let (idle_worker, _idle_stub) = super::channel::pair().expect("socketpair");
        let idle = HelperAuth::with_timeout(idle_worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        for n in 0..MAX_QUEUED_RELEASES + 5 {
            let mut nonce = [0x20u8; AUTH_NONCE_LEN];
            nonce[..8].copy_from_slice(&(n as u64).to_be_bytes());
            idle.queue_only_for_test(Request::ReleaseNonce { nonce });
        }
        assert_eq!(
            lines(DROPPED),
            3,
            "five dropped releases must be logged at the first, second and fourth; the log \
             is:\n{}",
            log()
        );
    }

    /// A helper that dies wakes every call waiting on it at once -- long
    /// before any of their deadlines -- with the helper's death as the
    /// reason. Otherwise a dead helper would hold every handshake in flight
    /// for its whole budget, the router's nonce request among them.
    ///
    /// The stub reads every request first, so all three calls are certainly
    /// waiting, and only then closes its end. The budgets are long, so that
    /// a call woken by its deadline cannot pass for one woken by the death.
    #[test]
    fn a_helper_that_dies_wakes_every_waiting_call_at_once() {
        const NONCE_BUDGET: Duration = Duration::from_secs(4);
        const VERIFY_BUDGET: Duration = Duration::from_secs(8);
        const WOKEN_WITHIN: Duration = Duration::from_secs(1);
        const HASH: [u8; 32] = [7u8; 32];

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = Arc::new(
            HelperAuth::with_timeouts(worker, NONCE_BUDGET, VERIFY_BUDGET)
                .expect("the authentication client"),
        );

        let mut calls: Vec<JoinHandle<(Result<(), String>, Instant)>> = ["alice", "bob"]
            .into_iter()
            .map(|login| {
                let auth = Arc::clone(&auth);
                let record = record_for(&key, login, &HASH, [1u8; AUTH_NONCE_LEN]);
                std::thread::spawn(move || {
                    let result = auth.verify(&HASH, &record, [0u8; 16], "");
                    (
                        result.map(|_| ()).map_err(|e| e.to_string()),
                        Instant::now(),
                    )
                })
            })
            .collect();
        calls.push({
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || {
                let result = auth.issue();
                (result.map(|_| ()), Instant::now())
            })
        });
        for _ in 0..calls.len() {
            next_request(&stub);
        }

        let died = Instant::now();
        drop(stub);

        for call in calls {
            let (result, ended) = call.join().expect("join");
            let after = ended.saturating_duration_since(died);
            assert!(
                after < WOKEN_WITHIN,
                "a call waiting on a helper that died returned only {after:?} later -- its own \
                 deadline ended it, not the death"
            );
            match result {
                Err(why) => assert!(
                    why.contains("the helper is gone"),
                    "the call must be told the helper is gone, got: {why}"
                ),
                Ok(()) => panic!("nothing answered, yet a call succeeded"),
            }
        }
    }

    /// The authentication seam's half of the mutual watch: a helper that
    /// dies ends the worker from this seam's reader too, not only from the
    /// channel seam's (`a_helper_that_dies_ends_the_worker`) -- no verdict
    /// can reach a worker whose helper is gone.
    #[test]
    fn a_helper_that_dies_ends_the_worker_from_the_authentication_seam() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        let (fired_tx, fired_rx) = mpsc::channel::<String>();
        let auth = HelperAuth::new_with_hook(
            worker,
            &daemon_config(),
            Arc::new(move |why: &str| {
                let _ = fired_tx.send(why.to_string());
            }),
        )
        .expect("the authentication client");

        drop(helper);

        assert_eq!(
            fired_rx.recv_timeout(TEST_RECV_TIMEOUT),
            Ok(HELPER_GONE_REASON.to_string()),
            "the worker must act on the helper's death, not run on without it, and say why"
        );
        drop(auth);
    }

    /// The mirror: the worker dropping its own client is not the helper
    /// dying, and must not end the worker. The reader does end -- the hook
    /// it held is then dropped unrun, which closes the hook's channel -- so
    /// the silence here is an answer, not a reader that never noticed.
    #[test]
    fn dropping_the_authentication_client_does_not_end_the_worker() {
        let (worker, helper) = super::channel::pair().expect("socketpair");
        helper
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let (fired_tx, fired_rx) = mpsc::channel::<()>();
        let auth = HelperAuth::new_with_hook(
            worker,
            &daemon_config(),
            Arc::new(move |_: &str| {
                let _ = fired_tx.send(());
            }),
        )
        .expect("the authentication client");

        drop(auth);

        assert!(
            matches!(channel::recv(&helper), Ok(None)),
            "dropping the client must close the seam, for the helper to see"
        );
        assert_eq!(
            fired_rx.recv_timeout(TEST_RECV_TIMEOUT),
            Err(mpsc::RecvTimeoutError::Disconnected),
            "the reader must end without running the hook: the worker let go of the seam itself"
        );
    }

    /// The reader's receive for a test that has to stop the reader while
    /// the helper stays: the real one, except that the message `panic`
    /// panics the reader thread, and the message `fail` comes back as a
    /// failed receive.
    fn recv_or_stop(sock: &UnixStream) -> io::Result<Option<(Vec<u8>, Option<OwnedFd>)>> {
        let message = channel::recv(sock)?;
        match &message {
            Some((bytes, _)) if bytes.as_slice() == b"panic" => {
                panic!("this test's reader stops here, on purpose")
            }
            Some((bytes, _)) if bytes.as_slice() == b"fail" => Err(io::Error::other(
                "this test's receive fails here, on purpose",
            )),
            _ => Ok(message),
        }
    }

    /// A reader that stops for any reason but the helper leaving -- a panic,
    /// or a receive that fails -- is as final as the helper dying: no answer
    /// can reach the worker any more. So it wakes every waiting call at
    /// once, fails every later call before that call sends anything, and
    /// ends the worker.
    ///
    /// The helper's end stays open throughout: its closing would be a second
    /// way for every one of these effects to happen, and the one call made
    /// after the reader stopped could still send.
    #[test]
    fn a_reader_that_stops_wakes_every_call_and_ends_the_worker() {
        for how in [b"panic".as_slice(), b"fail".as_slice()] {
            a_reader_that_stops_on(how);
        }
    }

    fn a_reader_that_stops_on(how: &'static [u8]) {
        const BUDGET: Duration = Duration::from_secs(5);
        const WOKEN_WITHIN: Duration = Duration::from_secs(1);
        let how_text = String::from_utf8_lossy(how);

        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let (fired_tx, fired_rx) = mpsc::channel::<()>();
        let auth = Arc::new(
            HelperAuth::with_reader(
                worker,
                BUDGET,
                BUDGET,
                move || {
                    let _ = fired_tx.send(());
                },
                recv_or_stop,
            )
            .expect("the authentication client"),
        );
        let waiting = {
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || (auth.issue(), Instant::now()))
        };
        let _request = next_request(&stub);

        let stopped = Instant::now();
        channel::send(&stub, how, None).expect("stop the reader");

        assert_eq!(
            fired_rx.recv_timeout(TEST_RECV_TIMEOUT),
            Ok(()),
            "a reader stopped by `{how_text}` must end the worker, as a helper that dies does"
        );
        let (result, ended) = waiting.join().expect("join");
        let after = ended.saturating_duration_since(stopped);
        assert!(
            after < WOKEN_WITHIN,
            "the waiting call returned only {after:?} after the reader was stopped by \
             `{how_text}` -- its own deadline ended it"
        );
        match result {
            Err(why) => assert!(
                why.contains("the helper is gone"),
                "the waiting call must be told no answer can come, got: {why}"
            ),
            Ok(nonce) => panic!("nothing answered, yet the call got {nonce:?}"),
        }

        let started = Instant::now();
        let later = auth.issue();
        let took = started.elapsed();
        assert!(
            took < WOKEN_WITHIN,
            "a call made after the reader was stopped by `{how_text}` took {took:?}: it waited \
             for an answer nothing can read"
        );
        match later {
            Err(why) => assert!(
                why.contains("the helper is gone"),
                "a call made after the reader stopped must be told no answer can come, got: {why}"
            ),
            Ok(nonce) => panic!("nothing can read an answer, yet the call got {nonce:?}"),
        }
        stub.set_nonblocking(true).expect("a non-blocking look");
        match channel::recv(&stub) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!(
                "a call made after the reader stopped must send nothing, but the helper's end held \
                 {:?}",
                other.map(|m| m.map(|(bytes, _)| String::from_utf8_lossy(&bytes).into_owned()))
            ),
        }
    }

    /// A read timeout left on the socket -- the tests' own harness leaves
    /// one on every end it makes -- does not stop the reader: a helper with
    /// nothing to say for a while is not a helper that is gone. Taken for
    /// one, it would end the worker at the first quiet moment.
    #[test]
    fn a_quiet_helper_is_not_a_helper_that_is_gone() {
        const QUIET: Duration = Duration::from_millis(20);

        let (worker, stub_end) = super::channel::pair().expect("socketpair");
        stub_end
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        worker
            .set_read_timeout(Some(QUIET))
            .expect("a read timeout, as the harness leaves one");
        let (fired_tx, fired_rx) = mpsc::channel::<()>();
        let auth = HelperAuth::new_with_hook(
            worker,
            &daemon_config(),
            Arc::new(move |_: &str| {
                let _ = fired_tx.send(());
            }),
        )
        .expect("the authentication client");

        assert_eq!(
            fired_rx.recv_timeout(QUIET * 10),
            Err(mpsc::RecvTimeoutError::Timeout),
            "a seam that is merely quiet must not end the worker"
        );

        // And the reader is still there to deliver.
        let nonce: Nonce = [3u8; AUTH_NONCE_LEN];
        let stub = std::thread::spawn(move || {
            let request = next_request(&stub_end);
            answer(&stub_end, request.id, Response::Nonce { nonce });
            stub_end
        });
        let issued = auth.issue();
        let _stub_end = stub.join().expect("join");
        assert_eq!(
            issued,
            Ok(nonce),
            "an answer after a quiet spell must still reach its call"
        );
    }

    /// The reader never waits for the send lock to release a late nonce: the
    /// release goes to a thread of its own. While that lock is held -- the
    /// way a send stuck on a full socket holds it -- a verdict the helper
    /// sends in good time must still reach its call at once. Were the reader
    /// to release the late nonce itself, it would sit behind the lock, and
    /// hand over nothing else until the verdict's call had given up: the
    /// helper would have trusted an account for a refused handshake.
    ///
    /// The reviewer's probe of task 5 step 0, kept as the witness.
    #[test]
    fn a_late_nonce_does_not_hold_up_another_calls_verdict() {
        const NONCE_BUDGET: Duration = Duration::from_millis(100);
        const VERIFY_BUDGET: Duration = Duration::from_secs(2);
        const HOLD: Duration = Duration::from_secs(3);
        const HASH: [u8; 32] = [7u8; 32];

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth = Arc::new(
            HelperAuth::with_timeouts(worker, NONCE_BUDGET, VERIFY_BUDGET)
                .expect("the authentication client"),
        );

        assert!(
            auth.issue().is_err(),
            "setup: nothing answered the nonce in time"
        );
        let late = next_request(&stub);
        let verifying = {
            let auth = Arc::clone(&auth);
            let record = record_for(&key, "alice", &HASH, [1u8; AUTH_NONCE_LEN]);
            std::thread::spawn(move || auth.verify(&HASH, &record, [0u8; 16], ""))
        };
        let verify = next_request(&stub);
        let holder = hold_send_lock_for(&auth, HOLD);

        answer(
            &stub,
            late.id,
            Response::Nonce {
                nonce: [0x5A; AUTH_NONCE_LEN],
            },
        );
        answer(
            &stub,
            verify.id,
            Response::Verified {
                uid: 4242,
                name: "alice".to_string(),
                identity: "SHA256:alice".to_string(),
                incarnation: 0,
            },
        );
        let answered = Instant::now();
        let verdict = verifying.join().expect("join");
        let took = answered.elapsed();
        holder.join().expect("join the holder");

        assert_eq!(
            verdict.as_ref().map(|p| p.name.clone()),
            Ok("alice".to_string()),
            "a verdict the helper sent in good time must reach its call; it took {took:?}"
        );
        assert!(
            took < Duration::from_millis(500),
            "a verdict the helper sent at once reached its call only after {took:?}"
        );
    }

    /// Reads requests off a stub's end until both a `Nonce` request -- which
    /// it answers with `nonce` -- and one other request have come, in
    /// whichever order, or until a read times out. Returns that other
    /// request, if any.
    fn answer_a_nonce_and_take_one_more(stub: &UnixStream, nonce: Nonce) -> Option<Request> {
        let mut answered = false;
        let mut other = None;
        while !answered || other.is_none() {
            let Ok(Some((bytes, _))) = channel::recv(stub) else {
                break;
            };
            let request = decode::<AuthRequest>(&bytes).expect("decode");
            match request.body {
                Request::Nonce if !answered => {
                    answer(stub, request.id, Response::Nonce { nonce });
                    answered = true;
                }
                body => {
                    other.get_or_insert(body);
                }
            }
        }
        other
    }

    /// An answer numbered above every request fails the calls then waiting,
    /// and that is all it does: the seam stays open, and a later call is
    /// answered as usual. A nonce such an answer carries is released, like a
    /// late one -- nobody here will spend it.
    ///
    /// The stub's end stays open throughout: a seam that closed would fail
    /// the later call for a reason of its own.
    #[test]
    fn a_protocol_violation_fails_the_calls_waiting_and_nothing_after() {
        const BUDGET: Duration = Duration::from_secs(5);

        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let auth =
            Arc::new(HelperAuth::with_timeout(worker, BUDGET).expect("the authentication client"));
        let stray: Nonce = [0x77u8; AUTH_NONCE_LEN];
        let fresh: Nonce = [0x33u8; AUTH_NONCE_LEN];

        let waiting = {
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || auth.issue())
        };
        let request = next_request(&stub);
        answer(&stub, request.id + 6, Response::Nonce { nonce: stray });
        match waiting.join().expect("join") {
            Err(why) => assert!(
                why.contains("protocol violation"),
                "setup: the waiting call must fail as a protocol violation, got: {why}"
            ),
            Ok(nonce) => panic!("setup: the waiting call must fail, got {nonce:?}"),
        }

        let later = {
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || auth.issue())
        };
        stub.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("a shorter bound for the reads that follow");
        let released = answer_a_nonce_and_take_one_more(&stub, fresh);
        assert_eq!(
            later.join().expect("join"),
            Ok(fresh),
            "a call made after a protocol violation must still be answered"
        );
        assert_eq!(
            released,
            Some(Request::ReleaseNonce { nonce: stray }),
            "a nonce in an answer that violated the protocol must go back to the helper"
        );
    }

    /// An answer that cannot be read at all carries no number to match, so
    /// it is dropped and the reader reads on: the call it may have been
    /// meant for runs out its own budget -- it is neither handed anything
    /// nor told the helper is gone -- the worker is not ended, and the next
    /// call is answered as usual.
    #[test]
    fn an_unreadable_answer_is_dropped_and_reading_goes_on() {
        const BUDGET: Duration = Duration::from_millis(300);

        let (worker, stub) = super::channel::pair().expect("socketpair");
        stub.set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        let (fired_tx, fired_rx) = mpsc::channel::<()>();
        let auth = Arc::new(
            HelperAuth::with_reader(
                worker,
                BUDGET,
                BUDGET,
                move || {
                    let _ = fired_tx.send(());
                },
                channel::recv,
            )
            .expect("the authentication client"),
        );
        let fresh: Nonce = [0x33u8; AUTH_NONCE_LEN];

        let waiting = {
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || {
                let started = Instant::now();
                (auth.issue(), started.elapsed())
            })
        };
        let _request = next_request(&stub);
        channel::send(&stub, b"not an answer", None).expect("send something unreadable");
        let (result, took) = waiting.join().expect("join");
        match result {
            Err(why) => assert!(
                why.contains("did not answer within"),
                "the call must run out its own budget, got: {why}"
            ),
            Ok(nonce) => panic!("nothing readable answered the call, yet it got {nonce:?}"),
        }
        assert!(
            took >= BUDGET,
            "the call ended after {took:?}, before its budget of {BUDGET:?}"
        );
        assert_eq!(
            fired_rx.try_recv(),
            Err(mpsc::TryRecvError::Empty),
            "an unreadable answer must not end the worker"
        );

        let later = {
            let auth = Arc::clone(&auth);
            std::thread::spawn(move || auth.issue())
        };
        let request = next_request(&stub);
        answer(&stub, request.id, Response::Nonce { nonce: fresh });
        assert_eq!(
            later.join().expect("join"),
            Ok(fresh),
            "the reader must go on reading after an unreadable answer"
        );
    }

    /// A request that cannot be encoded -- a verification whose record is
    /// larger than a seam message may be -- never reaches the helper, and
    /// takes its entry off the table again: its number was handed out
    /// together with the entry, and no answer is coming for it. The stub's
    /// end stays open, so the reader never clears the table itself.
    #[test]
    fn a_request_too_large_to_send_leaves_no_entry_behind() {
        const HASH: [u8; 32] = [7u8; 32];

        let key = PrivateKey::random(
            &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
            Algorithm::Ed25519,
        )
        .expect("keygen");
        let (worker, stub) = super::channel::pair().expect("socketpair");
        let auth = HelperAuth::with_timeout(worker, SHORT_ANSWER_TIMEOUT)
            .expect("the authentication client");
        let mut record = record_for(&key, "someone", &HASH, [9u8; AUTH_NONCE_LEN]);
        record.public_key = vec![0u8; super::super::protocol::MAX_MESSAGE_LEN];

        match auth.verify(&HASH, &record, [0u8; 16], "") {
            Err(AuthError::Backend(why)) => assert!(
                why.contains("could not ask the helper"),
                "setup: the request must fail to encode, got: {why}"
            ),
            other => panic!("setup: the request must fail to encode, got {other:?}"),
        }
        assert!(
            auth.seam.lock_waiters().waiting.is_empty(),
            "a request that could not be encoded must leave no entry behind"
        );
        stub.set_nonblocking(true).expect("a non-blocking look");
        match channel::recv(&stub) {
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            other => panic!(
                "a request that could not be encoded must not reach the helper, got {:?}",
                other.map(|m| m.map(|(bytes, _)| bytes.len()))
            ),
        }
    }

    /// How many times the reader of
    /// [`an_answer_that_comes_back_at_once_finds_its_call_waiting`] has gone
    /// to the seam for a message. The only test that reads or writes it.
    static ENTRIES_INTO_RECV: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// What [`ENTRIES_INTO_RECV`] was at the moment that test's send
    /// returned: the hold's own record, so the test can tell a send that
    /// really waited for the reader from one that did not.
    static ENTRIES_WHEN_SEND_RETURNED: std::sync::atomic::AtomicUsize =
        std::sync::atomic::AtomicUsize::new(0);

    /// The reader's receive for that test: the real one, counted.
    fn recv_counted(sock: &UnixStream) -> io::Result<Option<(Vec<u8>, Option<OwnedFd>)>> {
        ENTRIES_INTO_RECV.fetch_add(1, Ordering::SeqCst);
        channel::recv(sock)
    }

    /// The send for that test: the real one, and then no return until the
    /// reader has dealt with the answer and gone back for the next message
    /// -- its second entry into `recv` -- or a second has passed.
    fn send_and_let_the_reader_route_first(sock: &UnixStream, bytes: &[u8]) -> io::Result<()> {
        send_request(sock, bytes)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while ENTRIES_INTO_RECV.load(Ordering::SeqCst) < 2 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        ENTRIES_WHEN_SEND_RETURNED
            .store(ENTRIES_INTO_RECV.load(Ordering::SeqCst), Ordering::SeqCst);
        Ok(())
    }

    /// A call is on the table before its request goes out -- in the same
    /// step that numbers it -- so an answer that comes back at once always
    /// finds it. The stub answers the moment the request arrives, and the
    /// call's send does not return until the reader has already dealt with
    /// that answer: anything the call did only after sending would come too
    /// late, and the answer would be dropped as late while its call waited
    /// out its budget.
    #[test]
    fn an_answer_that_comes_back_at_once_finds_its_call_waiting() {
        const BUDGET: Duration = Duration::from_secs(1);

        let (worker, stub_end) = super::channel::pair().expect("socketpair");
        stub_end
            .set_read_timeout(Some(TEST_RECV_TIMEOUT))
            .expect("set a receive timeout on the stub's socket");
        ENTRIES_INTO_RECV.store(0, Ordering::SeqCst);
        ENTRIES_WHEN_SEND_RETURNED.store(0, Ordering::SeqCst);
        let auth = HelperAuth::with_io(
            worker,
            BUDGET,
            BUDGET,
            || {},
            recv_counted,
            send_and_let_the_reader_route_first,
        )
        .expect("the authentication client");
        let nonce: Nonce = [0x42u8; AUTH_NONCE_LEN];
        // The stub's end comes back, so the seam stays open until the
        // assertions are done.
        let stub = std::thread::spawn(move || {
            let request = next_request(&stub_end);
            answer(&stub_end, request.id, Response::Nonce { nonce });
            stub_end
        });

        let issued = auth.issue();
        let _stub_end = stub.join().expect("join");
        assert!(
            ENTRIES_WHEN_SEND_RETURNED.load(Ordering::SeqCst) >= 2,
            "control: the reader must have dealt with the answer before the call's send \
             returned, or this test did not hold the call where it means to"
        );
        assert_eq!(
            issued,
            Ok(nonce),
            "an answer that came back before its call's send returned must still reach the call"
        );
    }

    /// Every thread the worker starts for its seams has a name Linux keeps
    /// whole. Linux cuts a thread's name to [`MAX_THREAD_NAME_LEN`] bytes
    /// without a word, and a longer name then matches nothing that looks for
    /// it -- the root-only test that waits for the authentication seam's
    /// reader by name waited for one that could never appear.
    #[test]
    fn every_thread_name_fits_what_linux_keeps() {
        assert_eq!(
            MAX_THREAD_NAME_LEN, 15,
            "Linux keeps 15 bytes of a thread's name (TASK_COMM_LEN is 16, with the NUL)"
        );
        for name in THREAD_NAMES {
            assert!(
                name.len() <= MAX_THREAD_NAME_LEN,
                "the thread name {name:?} is {} bytes; Linux keeps only {MAX_THREAD_NAME_LEN} and \
                 shows it cut off",
                name.len()
            );
        }
        let distinct: std::collections::HashSet<&str> = THREAD_NAMES.into_iter().collect();
        assert_eq!(
            distinct.len(),
            THREAD_NAMES.len(),
            "every thread name must tell its thread apart: {THREAD_NAMES:?}"
        );
    }

    /// The same, as the kernel reports it: with a channel spawner, an
    /// authentication client and a nonce pool drawing from it alive -- their
    /// far ends open, so all four threads keep running -- this process has a
    /// thread whose `comm` is each name in full. Checked on the kernel's side
    /// as well as by length, so a name the kernel keeps differently than
    /// assumed shows up too.
    ///
    /// Looked for until every name is there or [`TEST_RECV_TIMEOUT`] has
    /// passed, not once: a new thread carries its parent's name until it has
    /// run far enough to set its own, and on a loaded machine that can take a
    /// while after `spawn` returns.
    #[test]
    fn every_seam_thread_carries_its_name_in_full() {
        let (channels, _channels_far) = super::channel::pair().expect("socketpair");
        let (auth, _auth_far) = super::channel::pair().expect("socketpair");
        let _spawner = HelperChannelSpawner::new(channels).expect("spawner");
        let auth = Arc::new(
            HelperAuth::with_timeout(auth, SHORT_ANSWER_TIMEOUT)
                .expect("the authentication client"),
        );
        // Nothing answers, so the pool's warm-up gives up after one short
        // budget and its thread keeps asking.
        let _pool = crate::nonce_pool::PooledNonces::start(auth).expect("the nonce pool");

        let thread_names = || -> Vec<String> {
            std::fs::read_dir("/proc/self/task")
                .expect("list this process's threads")
                .filter_map(|task| task.ok())
                .filter_map(|task| std::fs::read_to_string(task.path().join("comm")).ok())
                .map(|comm| comm.trim_end().to_string())
                .collect()
        };
        let all_there = |comms: &[String]| {
            THREAD_NAMES
                .iter()
                .all(|name| comms.iter().any(|comm| comm == name))
        };
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        let mut comms = thread_names();
        while !all_there(&comms) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
            comms = thread_names();
        }
        for name in THREAD_NAMES {
            assert!(
                comms.iter().any(|comm| comm == name),
                "no thread of this process is named {name:?} in full; the kernel reports these \
                 names: {comms:?}"
            );
        }
    }

    /// How long [`run_isolated`] waits for the process it starts.
    const ISOLATED_PROCESS_WAIT: Duration = Duration::from_secs(30);

    /// Runs the one `#[ignore]`d test `inner` in a process of its own --
    /// for a check that must change process-wide state, such as where the
    /// log goes -- and returns its exit status and output. The wait is
    /// bounded: a process still running after [`ISOLATED_PROCESS_WAIT`] is
    /// killed, and the calling test fails rather than hangs.
    pub(crate) fn run_isolated(inner: &str) -> (std::process::ExitStatus, String, String) {
        run_isolated_with_env(inner, &[])
    }

    /// As [`run_isolated`], with `env` set in the process's environment.
    pub(crate) fn run_isolated_with_env(
        inner: &str,
        env: &[(&str, &std::ffi::OsStr)],
    ) -> (std::process::ExitStatus, String, String) {
        let exe = std::env::current_exe().expect("current_exe");
        let mut child = std::process::Command::new(exe)
            .args([
                inner,
                "--exact",
                "--ignored",
                "--test-threads=1",
                "--nocapture",
            ])
            .envs(env.iter().copied())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn the isolated check");
        let mut stdout_pipe = child.stdout.take().expect("the child's stdout");
        let mut stderr_pipe = child.stderr.take().expect("the child's stderr");
        let stdout_reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stdout_pipe.read_to_end(&mut out);
            out
        });
        let stderr_reader = std::thread::spawn(move || {
            let mut out = Vec::new();
            let _ = stderr_pipe.read_to_end(&mut out);
            out
        });
        let deadline = Instant::now() + ISOLATED_PROCESS_WAIT;
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait for the isolated check") {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the isolated check `{inner}` was still running after \
                     {ISOLATED_PROCESS_WAIT:?}; killed"
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        let stdout = String::from_utf8_lossy(&stdout_reader.join().expect("join")).into_owned();
        let stderr = String::from_utf8_lossy(&stderr_reader.join().expect("join")).into_owned();
        assert!(
            stdout.contains("running 1 test\n"),
            "expected the filter to match exactly one test -- `{inner}` renamed?\nstdout:\n\
             {stdout}\nstderr:\n{stderr}"
        );
        (status, stdout, stderr)
    }

    /// Only the authentication seam's reader writes
    /// [`AUTH_SEAM_CLOSED_LOG`] when its seam is lost, and it does write it.
    /// The root-only test in `qshd/tests/serve_system_split.rs` relies on
    /// exactly that to tell which seam it shut down and which reader noticed;
    /// this keeps that ground under it in every ordinary run.
    #[test]
    fn only_the_authentication_seams_reader_logs_its_lost_seam_line() {
        let (status, stdout, stderr) = run_isolated(
            "helper::spawner::tests::only_the_authentication_seams_reader_logs_its_lost_seam_line_body",
        );
        assert!(
            status.success(),
            "the isolated check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via
    /// [`only_the_authentication_seams_reader_logs_its_lost_seam_line`], in a
    /// process of its own: it points this process's log at a file of its
    /// own, for good.
    #[test]
    #[ignore = "runs only via only_the_authentication_seams_reader_logs_its_lost_seam_line, in a \
                process of its own"]
    fn only_the_authentication_seams_reader_logs_its_lost_seam_line_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::log::init(dir.path());
        let log_path = dir.path().join("qshd.log");
        let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();

        // The channel seam goes first: its reader writes a line of its own.
        let (channels, channels_far) = super::channel::pair().expect("socketpair");
        let (fired_tx, fired_rx) = mpsc::channel::<()>();
        let _spawner = HelperChannelSpawner::new_with_hook(
            channels,
            move || {
                let _ = fired_tx.send(());
            },
            Box::new(|_, _| {}),
        )
        .expect("spawner");
        drop(channels_far);
        fired_rx
            .recv_timeout(TEST_RECV_TIMEOUT)
            .expect("setup: the channel seam's reader must notice its seam is gone");
        let log = read_log();
        assert!(
            log.contains("the helper is gone"),
            "setup: the channel seam's reader must have logged the lost seam, the log is:\n{log}"
        );
        assert!(
            !log.contains(AUTH_SEAM_CLOSED_LOG),
            "the channel seam's reader must not write the authentication seam's line, the log \
             is:\n{log}"
        );

        // Then the authentication seam: its reader writes the line, before
        // it calls the hook. The hook reads the log itself: what it finds
        // there is what the log held when the hook ran -- in the daemon, the
        // moment before the process ends.
        let (auth, auth_far) = super::channel::pair().expect("socketpair");
        let (fired_tx, fired_rx) = mpsc::channel::<String>();
        let hook_log_path = log_path.clone();
        let _auth = HelperAuth::with_reader(
            auth,
            SHORT_ANSWER_TIMEOUT,
            SHORT_ANSWER_TIMEOUT,
            move || {
                let _ = fired_tx.send(std::fs::read_to_string(&hook_log_path).unwrap_or_default());
            },
            channel::recv,
        )
        .expect("the authentication client");
        drop(auth_far);
        let log = fired_rx
            .recv_timeout(TEST_RECV_TIMEOUT)
            .expect("setup: the authentication seam's reader must notice its seam is gone");
        assert!(
            log.contains(AUTH_SEAM_CLOSED_LOG),
            "the authentication seam's reader must log {AUTH_SEAM_CLOSED_LOG:?} before it ends \
             the worker, the log when it did was:\n{log}"
        );
    }

    /// The send for [`the_release_thread_does_not_die_in_silence_body`]:
    /// fails the way no real send does, by panicking -- on the release
    /// thread, the only thread that sends in that test.
    fn send_that_panics(_sock: &UnixStream, _bytes: &[u8]) -> io::Result<()> {
        panic!("this test's send panics here, on purpose")
    }

    /// The release thread cannot stop without a word: if it ends by a panic
    /// it logs that and ends the worker -- it carries the ends of logins --
    /// and every late nonce that can no longer be handed to it is logged as
    /// well, from either place the reader hands one over, a late answer and
    /// an answer that violated the protocol.
    #[test]
    fn the_release_thread_does_not_die_in_silence() {
        let (status, stdout, stderr) =
            run_isolated("helper::spawner::tests::the_release_thread_does_not_die_in_silence_body");
        assert!(
            status.success(),
            "the isolated check failed:\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }

    /// Runs only via [`the_release_thread_does_not_die_in_silence`], in a
    /// process of its own: it points this process's log at a file of its
    /// own, for good.
    #[test]
    #[ignore = "runs only via the_release_thread_does_not_die_in_silence, in a process of its own"]
    fn the_release_thread_does_not_die_in_silence_body() {
        let dir = tempfile::tempdir().expect("tempdir");
        crate::log::init(dir.path());
        let log_path = dir.path().join("qshd.log");
        let read_log = || std::fs::read_to_string(&log_path).unwrap_or_default();
        let wait_for = |what: &str, done: &dyn Fn() -> bool| {
            let deadline = Instant::now() + TEST_RECV_TIMEOUT;
            while !done() {
                assert!(
                    Instant::now() < deadline,
                    "{what}, the log is:\n{}",
                    read_log()
                );
                std::thread::sleep(Duration::from_millis(5));
            }
        };

        let (worker, _stub_end) = super::channel::pair().expect("socketpair");
        let (ended_tx, ended_rx) = mpsc::channel::<String>();
        let auth = HelperAuth::with_end_worker(
            worker,
            SHORT_ANSWER_TIMEOUT,
            send_that_panics,
            Arc::new(move |why: &str| {
                let _ = ended_tx.send(why.to_string());
            }),
        )
        .expect("the authentication client");

        // The release thread takes this nonce, and dies sending it.
        auth.late
            .send(Wake::Late([1u8; AUTH_NONCE_LEN]))
            .expect("setup: the release thread is there to take a nonce");
        wait_for(
            "the release thread's end must be logged when it dies",
            &|| read_log().contains(RELEASE_THREAD_GONE_LOG),
        );
        assert_eq!(
            ended_rx.recv_timeout(TEST_RECV_TIMEOUT),
            Ok(RELEASE_THREAD_GONE_REASON.to_string()),
            "a release thread that dies must end the worker: it carries the ends of logins"
        );
        wait_for("setup: the release thread must be gone for good", &|| {
            auth.late.send(Wake::Late([2u8; AUTH_NONCE_LEN])).is_err()
        });

        // Both places the reader hands a nonce over now find nobody there.
        let late_id = auth.seam.take_id();
        auth.seam.route(
            AuthResponse {
                id: late_id,
                body: Response::Nonce {
                    nonce: [3u8; AUTH_NONCE_LEN],
                },
            },
            &auth.late,
        );
        auth.seam.route(
            AuthResponse {
                id: late_id + 6,
                body: Response::Nonce {
                    nonce: [4u8; AUTH_NONCE_LEN],
                },
            },
            &auth.late,
        );
        let log = read_log();
        assert_eq!(
            log.matches(LATE_NONCE_NOT_RELEASED_LOG).count(),
            2,
            "a late nonce and a protocol-violating answer's nonce, both with nobody to take \
             them, must each be logged; the log is:\n{log}"
        );
    }

    #[test]
    fn open24_failed_outcome_keeps_custody_until_no_child_receipt() {
        use transport::channel_geometry::ChannelInstance;
        use transport::channel_open::{CleanupStatus, OpenIdentity, OpenRequestSnapshot};
        let budget = Arc::new(ScreenBudget::new(BudgetLimits::default()));
        let (worker, helper) = channel::pair().unwrap();
        helper.set_read_timeout(Some(TEST_RECV_TIMEOUT)).unwrap();
        let spawner = HelperChannelSpawner::with_budget_hook(
            worker,
            budget.clone(),
            || {},
            Box::new(|_, _| {}),
        )
        .unwrap();
        let registry = spawner.open_registry();
        let session = registry.session().unwrap();
        let mut request = shell_request();
        request.cols = 2;
        request.rows = 1;
        request.screen = true;
        let job = registry
            .try_reserve(
                &session,
                OpenRequestSnapshot {
                    owner: anyone(),
                    login: any_login(),
                    request: request.clone(),
                    term: None,
                    identity: OpenIdentity {
                        session: session.id(),
                        instance: ChannelInstance::new(1).unwrap(),
                        stream: request.stream,
                        generation: 1,
                        invalidation_epoch: 0,
                    },
                },
            )
            .unwrap();
        let helper = std::thread::scope(|scope| {
            let stub = scope.spawn(move || {
                let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
                let Request::Open { id, .. } = decode::<Request>(&bytes).unwrap() else {
                    panic!("expected the actual Open request")
                };
                channel::send(
                    &helper,
                    &encode(&Response::Failed {
                        id,
                        reason: "fixture refused".into(),
                    })
                    .unwrap(),
                    None,
                )
                .unwrap();
                (helper, id)
            });
            let outcome = ChannelSpawner::spawn(
                &spawner,
                &anyone(),
                any_login(),
                &request,
                None,
                job.custody(),
            );
            let helper = stub.join().unwrap();
            assert!(outcome.is_err(), "the real Failed outcome must arrive");
            drop(outcome);
            helper
        });
        assert!(matches!(job.cleanup(), CleanupStatus::Unknown));
        assert_eq!(registry.outstanding(), 1);
        assert_eq!(session.occupied(), 1);
        assert_eq!(budget.used().models, 1);
        let (helper, id) = helper;
        let (bytes, _) = channel::recv(&helper).unwrap().unwrap();
        assert_eq!(decode::<Request>(&bytes).unwrap(), Request::Close { id });
        channel::send(
            &helper,
            &serde_json::to_vec(&serde_json::json!({
                "CleanupComplete": { "id": id, "kind": "NoChild" }
            }))
            .unwrap(),
            None,
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        while registry.outstanding() != 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            registry.outstanding(),
            0,
            "the exact receipt must release its job"
        );
        assert_eq!(session.occupied(), 0);
        assert_eq!(budget.used(), crate::screen_budget::Usage::default());
    }
    fn wait_for(what: &str, ready: &impl Fn() -> bool) {
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        while !ready() {
            assert!(Instant::now() < deadline, "{what}");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    include!("spawner_open_tests.rs");
    include!("executor_open_tests.rs");

    #[test]
    fn deadlines302_known_leader_then_disconnect_parks_until_exact_receipt() {
        use transport::channel_server::{ChildStatus, LeaderStatus};
        let (tx, peer) = channel::pair().unwrap();
        let (send, exits) = mpsc::channel();
        let custody = transport::channel_open::OpenCustody::new();
        let receipt = Arc::new(Mutex::new(CleanupReceipt {
            kind: None,
            failure: None,
            cleanup_requested: false,
            notify: custody.cleanup_notifier(),
            reap_notify: None,
            leader_notified: false,
            connection_closed: false,
        }));
        let waiting = Arc::new(Mutex::new(HashMap::from([(
            302,
            Pending {
                opened: None,
                exited: Some(send.clone()),
                outcome: OpenOutcome::Opened,
                receipt: receipt.clone(),
            },
        )])));
        let read_socket = tx.try_clone().unwrap();
        let local = Arc::new(AtomicBool::new(false));
        let read_local = local.clone();
        let reader = std::thread::spawn(move || {
            read_loop(read_socket, waiting, read_local, || {}, Box::new(|_, _| {}))
        });
        let mut wait = HelperWait {
            id: 302,
            exits,
            leader_code: None,
            exits_closed: false,
            receipt: receipt.clone(),
            tx,
            disconnected_locally: local,
        };
        drop(send);
        channel::send(
            &peer,
            &encode(&Response::Exited { id: 302, code: 7 }).unwrap(),
            None,
        )
        .unwrap();
        let deadline = Instant::now() + TEST_RECV_TIMEOUT;
        loop {
            if matches!(
                wait.poll_leader_status(),
                Some(LeaderStatus::Exited { code: Some(7) })
            ) {
                break;
            }
            assert!(Instant::now() < deadline, "leader notification delivered");
            std::thread::yield_now();
        }
        assert!(
            matches!(wait.poll_exit(), ChildStatus::Running),
            "normal one-shot exit sender drop is not helper disconnect"
        );
        assert!(
            !receipt.lock().unwrap().connection_closed,
            "normal Exited delivery is not seam loss"
        );
        drop(peer);
        reader.join().unwrap();
        assert!(receipt.lock().unwrap().leader_notified);
        assert!(receipt.lock().unwrap().connection_closed);
        let disconnected = wait.poll_exit();
        receipt.lock().unwrap().kind = Some(CleanupKind::Reaped);
        let recovered = wait.poll_exit();
        drop(wait);
        assert!(
            matches!(disconnected, ChildStatus::Unknown(_)),
            "disconnect after leader exit is not cleanup proof or a running scope"
        );
        assert!(matches!(recovered, ChildStatus::Reaped { code: Some(7) }));
    }

    #[test]
    fn helper39_leader_exited_without_scope_receipt_remains_owned() {
        use transport::channel_server::ChildStatus;
        let (tx, peer) = channel::pair().unwrap();
        let (send, exits) = mpsc::channel();
        let custody = transport::channel_open::OpenCustody::new();
        let receipt = Arc::new(Mutex::new(CleanupReceipt {
            kind: None,
            failure: None,
            cleanup_requested: false,
            notify: custody.cleanup_notifier(),
            reap_notify: None,
            leader_notified: false,
            connection_closed: false,
        }));
        let mut wait = HelperWait {
            id: 3902,
            exits,
            leader_code: None,
            exits_closed: false,
            receipt: receipt.clone(),
            tx,
            disconnected_locally: Arc::new(AtomicBool::new(false)),
        };
        send.send(7).unwrap();
        let before_scope = wait.poll_exit();
        let leader = wait.poll_leader_status();
        let still_owned = wait.poll_exit();
        // This controlled receipt is distinct from the preceding leader event.
        receipt.lock().unwrap().kind = Some(CleanupKind::Reaped);
        drop(send);
        let after_scope = wait.poll_exit();
        drop(wait);
        drop(peer);
        assert!(
            !matches!(before_scope, ChildStatus::Reaped { .. }),
            "leader Exited is not a final scope receipt"
        );
        assert!(matches!(
            leader,
            Some(transport::channel_server::LeaderStatus::Exited { code: Some(7) })
        ));
        assert!(!matches!(still_owned, ChildStatus::Reaped { .. }));
        assert!(matches!(after_scope, ChildStatus::Reaped { code: Some(7) }));
    }
}
