//! The server side of a channel session: open, exchange data, close.
//!
//! Where [`crate::shell_server::serve_shell`] drives ONE pseudo-terminal
//! wired in at start-up, this runner drives however many the CLIENT asks
//! for, opened one at a time by a record on [`crate::channel::CONTROL_STREAM`]
//! and identified by the transport stream their data travels on (see
//! `crate::channel`'s module docs). The transport crate still does not know
//! what a pseudo-terminal is: [`ChannelSpawner`] hands over an already-running
//! one's reader/writer/resize/screen, exactly the boundary `serve_shell`
//! already draws with its own arguments -- the only difference is that here
//! there can be several, and the client decides when.
//!
//! **The bridge, generalised.** `serve_shell` pairs one PTY with two
//! `spawn_blocking` tasks and two dedicated channels (one per direction).
//! Doing the same per channel here would mean a growing number of `select!`
//! arms as channels come and go, so instead every channel's reader task
//! shares ONE output channel, tagging each chunk with the stream it came
//! from (`(u8, u64, Option<Vec<u8>>)`; a `None` chunk marks that instance's
//! output EOF, which does not prove its process has ended). Each input FIFO
//! uses nonblocking sends with owned admission permits: queued and writer-held
//! network payloads share an 8 MiB / 16,384-item cap per channel and per session.
//! Generated terminal replies use separate 64 KiB / 64-item channel quotas and
//! 512 KiB / 512-item session quotas in that same FIFO, without input credit.
//! Warm attachment, channel closure and stream reuse never refund live chunks.
//! An input that exceeds either cap stops its receiving channel; other output
//! and control processing continues. Aggregate exhaustion can refuse another
//! channel's new input until retained debt is released. This also bounds peers
//! without stream credit; it does not change the raw diagnostic shell runner.
//!
//! **Opening stays off the loop.** The factory registry admits finite work
//! before the blocking executor calls a spawner. Pending jobs count against the
//! session slot cap and keep their child/model custody through cancellation.
//! Only exact cleanup proof refunds unresolved work; a late Ready result cannot
//! cross reset, stream reuse or restart. Adoption installs inert ownership under
//! the epoch/registry guards before backend callbacks and bridge scheduling.
//!
//! **A refusal is an answer, not a session failure.** Past the channel cap,
//! on a re-used stream number, or when [`ChannelSpawner::spawn`] itself
//! fails, the client gets `ServerRecord::Refused` and the session keeps
//! running with whatever else is already open.
//!
//! **Channel termination and final output are separate.** Reader EOF starts
//! an asynchronous exact-instance retirement owner; the loop keeps servicing
//! other channels. That owner serializes child status observation and stop
//! requests. The runner sends the terminal record only after both exact reap
//! proof and delivery of all accepted output. A delivery marker names the
//! instance and attachment generation, so an old acknowledgement cannot end a
//! replacement. Warm reattachment retains draining metadata and renews only
//! delivery evidence. An explicit Close owes no final record and may reuse the
//! stream, but cannot refund an unresolved child slot.
//!
//! **Reaping is not optional.** Dropping a portable-pty child does not reap it.
//! Installed children move into factory-owned custody before a retirement task
//! is scheduled. A dropped runner, cancelled queued task, wait error or missing
//! helper connection does not prove cleanup. Unknown observation parks custody
//! without retaining a blocking worker; a later exact helper receipt can wake
//! it. Stop and poll share one exclusive child owner, and no signal is allowed
//! after reap or after PID identity becomes unknown. Session shutdown and
//! restart request stop for active and already-draining children, then wait
//! for exact cleanup. Broader runtime/task shutdown is a separate obligation.
//!
//! **Repaint and the live-channel list.** `Repaint` asks every channel's
//! screen model to repaint and puts any non-empty answer on that channel's
//! own stream; a channel with no screen model (`NoScreen`) always answers
//! empty, so no separate "has a screen" bookkeeping is needed. `ResumeReset`
//! (a warm reattach) resets every channel's echo_ack accounting and publishes
//! one atomic lifecycle snapshot before replay. The geometry profile separates
//! active channels from draining EOF owners and retains exact OPEN classification;
//! only ordered GEOMETRY confirms a size. The snapshot
//! is not sent on `Live` (a cold start), where no retained channels are expected.
//!
//! **Send gates (spec §4.7.2).** Every channel takes a gate on its stream
//! when it opens, and gives it up when it goes. A channel with a screen
//! model never waits on its gate: behind a closed one its output only feeds
//! the model and is dropped, whole records at a time, before the transport,
//! and one repaint (with an unconditional echo ack) goes out once the gate
//! opens -- on the next chunk or on `SessionInbound::Writable`, whichever
//! comes first. A channel without one (`tmux -C`) has nothing to repaint
//! from: its reader waits for the gate before every read, so its process
//! blocks on its PTY. The loop itself never waits on a gate, which is what
//! keeps the one shared output channel from ever holding a screen channel's
//! output behind a line channel's.
//!
//! **Speaking for the daemon.** With a [`DaemonUpdates`] behind it
//! (`run_channel_session_with`), the runner answers `AboutRequest` and
//! decides at most one update offer at a time -- both off the loop, since
//! the daemon may hash its own binary to answer -- receives the accepted
//! image off `UPDATE_STREAM` into a blocking task, tells its client
//! `Restarting` when the daemon announces a restart, refuses new channels
//! while one is under way, and ends and reaps its channels when the daemon
//! drains before replacing itself -- or when its own client goes away
//! mid-restart, confirming that too. Every restart is numbered
//! ([`RestartSignal`]), so each is acted on once even when a watch coalesces
//! its phases. Without a daemon behind it the runner stays silent, as a
//! daemon that predates those records does.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use terminal_size::TerminalSize;

use tokio::sync::mpsc;

use crate::auth::Principal;
use std::time::Duration;

use tokio::sync::watch;

use crate::channel::{
    decode_client, encode_server, About, ChannelCodecError, ClientRecord, OpenRequest, RejectCode,
    ServerRecord, UpdateAnswer, UpdateOffer, UpdateResult, CONTROL_STREAM, MAX_CHANNELS,
    UPDATE_STREAM,
};
// Only the tests need this constant (via `use super::*` in `mod tests`);
// keep it out of a non-test build so it doesn't sit there unused.
#[cfg(test)]
use crate::channel::FIRST_CHANNEL_STREAM;
use crate::channel_geometry::{
    ChannelInstance, GeometryOutcome, GeometryRecord, ProtocolErrorCode, ResizeRefusal,
    ResizeRequestId,
};
use crate::channel_timeline::{
    EntryClass, TimelineBudget, TimelinePermit, WaitRegistration, DELIVERY_MARKER_BYTES,
    GEOMETRY_BYTES,
};
use crate::conn::StreamClass;
use crate::send_gate::{GateKind, SendGate};
use crate::session_manager::{AttachmentContext, ChannelOutput, DeliveryMarker};
#[path = "control_input.rs"]
mod control_input;

use crate::session_manager::{ConsumptionReporter, LoginId, SessionInbound, SessionIo, StreamData};
use crate::shell_frame::RawRecord;
use crate::shell_server::{ResizeHandle, SessionScreen};

/// Buffer size for a single channel read. Matches `shell_server::CHUNK_SIZE`.
const CHUNK_SIZE: usize = 8 * 1024;

/// Capacity of the SHARED output channel every open channel's reader feeds.
/// As in `shell_server`: a decoupling point between execution threads with
/// backpressure, not a data buffer -- shared by every open channel (rather
/// than one per channel) is what lets a dynamic channel count cost a single
/// extra `select!` arm instead of one per channel.
const CHANNEL_CAPACITY: usize = 16;

/// A child observation. Only Reaped proves cleanup; its exit code can be
/// unavailable even when an exact backend receipt proves the child is gone.
pub enum ChildStatus {
    Running,
    /// Process cleanup is proved; actual owned I/O worker joins are pending.
    /// Retain custody and retry from the worker notifier without parking a thread.
    WaitingForWorkers,
    Reaped {
        code: Option<i32>,
    },
    Unknown(String),
}

#[path = "channel_reap.rs"]
pub(crate) mod reaping;
pub use reaping::ReapNotifier;
use reaping::ReapSet;

/// Non-reaping leader status, independent of process-scope and I/O cleanup.
pub enum LeaderStatus {
    Running,
    Exited { code: Option<i32> },
    Unknown(String),
}

/// Exclusive child lifecycle operations. The runner calls observation/stop on
/// blocking workers; a pending or failed observation never releases custody.
pub trait ChannelWait: Send {
    /// Nonblocking observation by the exclusive wait owner. After Unknown the
    /// owner must retain custody and must not signal a possibly reused PID.
    fn poll_exit(&mut self) -> ChildStatus;

    /// Observed by the same exclusive blocking owner as cleanup. Legacy backends
    /// may omit this signal; it never implies a full cleanup receipt.
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        None
    }

    /// Wake a parked retirement owner after an exact backend receipt arrives.
    fn set_reap_notifier(&mut self, _notifier: ReapNotifier) {}

    /// Force the process down. Called only where the process is not already
    /// known to have exited (a `CLOSE` or a session tearing down while a
    /// channel is still open). Natural termination is observed with `poll_exit`.
    fn kill(&mut self);

    /// Legacy blocking fixture/adapter operation. Installed retirement uses
    /// `poll_exit` so that a stop request never competes with an owned waiter.
    fn wait(self: Box<Self>) -> i32;

    /// Cleanup of a never-installed result. A status code, timeout or kill
    /// request is not proof; return Unknown unless the exact child was reaped.
    fn cleanup_uninstalled(
        &mut self,
        authority: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus;
}

/// Everything one opened channel gives the runner. Assembled by the caller
/// (`qshd`), because the transport crate does not know what a
/// pseudo-terminal is -- the same boundary `serve_shell` already draws with
/// its reader/writer/resize arguments.
pub struct SpawnedChannel {
    pub reader: Box<dyn Read + Send>,
    pub writer: Box<dyn Write + Send>,
    pub resize: Box<dyn ResizeHandle>,
    /// The screen model, or `NoScreen` when the request did not ask for one.
    pub screen: Box<dyn SessionScreen>,
    pub wait: Box<dyn ChannelWait>,
}

/// Constructs a channel on its already-admitted blocking worker. The typed
/// failure preserves any unresolved child/model custody. Its reason string is
/// shown to the user, so it is written in the language the daemon's other
/// messages use.
pub trait ChannelSpawner: Send + Sync + 'static {
    /// Factory-owned registry; every runner and replacement uses this same owner.
    fn open_registry(&self) -> Arc<crate::channel_open::ChannelOpenRegistry>;
    /// `owner` is whose session asks for the channel -- the session's own
    /// [`SessionIo::principal`], exactly as authentication established it.
    /// A spawner that serves several accounts opens the channel for this
    /// one; a spawner that only ever runs as one account ignores it.
    ///
    /// `login` is which LOGIN asks -- the session's own [`SessionIo::login`],
    /// stable across a warm reattach even though the session id is not (see
    /// that method's docs). Two logins of the same account are different
    /// sessions; a spawner that opens a PAM session per login (the system
    /// mode's, from the next task on) needs to tell them apart, so this is
    /// handed alongside `owner` rather than derived from it. A spawner with
    /// no such notion -- one account, one login, for its whole life --
    /// ignores it.
    ///
    /// `term` is the client's terminal type, as announced by
    /// [`ClientRecord::Term`] earlier on the control stream, or `None` when
    /// this client never said. A spawner that puts a process behind a
    /// pseudo-terminal passes it on as `TERM`; one that has no environment
    /// to speak of ignores it.
    fn spawn(
        &self,
        owner: &Principal,
        login: LoginId,
        req: &OpenRequest,
        term: Option<&str>,
        custody: &crate::channel_open::OpenCustody,
    ) -> Result<crate::channel_open::UninstalledChannel, crate::channel_open::SpawnFailure>;
}

/// How long an accepted transfer may go without a byte before it is given
/// up. Without a bound, a client that stopped sending would hold the
/// daemon's one update slot until its session ended.
pub const TRANSFER_STALL: Duration = Duration::from_secs(30);

/// Where one restart of the daemon stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPhase {
    Idle,
    /// About to replace itself: tell the client `Restarting`. No channel may
    /// be opened from here on.
    Announced,
    /// End every channel and wait for its process, then say so
    /// ([`DaemonUpdates::channels_released`]). A process left running would
    /// become a child of the new binary, which never waits for it.
    Draining,
}

/// Where a daemon's replacement of itself stands, as every session hears it.
///
/// `restart` numbers the attempts: the daemon gives each new one a larger
/// number than the last. A watch channel keeps only the latest value, so a
/// session busy elsewhere can miss phases -- the end of one attempt and the
/// start of the next can reach it as a single change. The number is what
/// still tells it a new attempt began, and what it acts on once per attempt.
/// It means nothing while the phase is `Idle`.
///
/// **Who confirms a drain.** A session that sees an attempt `Announced`
/// joins it ([`DaemonUpdates::restart_joined`]), once; the daemon counts a
/// join only while that attempt is still announced, and says whether it
/// did. Exactly the sessions it counted confirm
/// ([`DaemonUpdates::channels_released`], tagged with the attempt's number),
/// once each -- after draining, or on ending mid-restart -- and the daemon
/// waits until as many have confirmed as joined. A session that first hears
/// of an attempt when it is already `Draining` (it subscribed late, or the
/// watch folded the announcement away) was not counted: it tells its client
/// `Restarting`, refuses channels and ends whatever it has, but never
/// confirms that attempt, or the count would overshoot and the daemon could
/// replace itself while a counted session is still reaping. It takes part
/// in later attempts as usual.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartSignal {
    pub restart: u64,
    /// Persistent invalidation survives returning to Idle.
    pub invalidation_epoch: u64,
    pub phase: RestartPhase,
}

impl RestartSignal {
    /// No restart under way.
    pub const IDLE: RestartSignal = RestartSignal {
        restart: 0,
        invalidation_epoch: 0,
        phase: RestartPhase::Idle,
    };

    pub const fn idle(invalidation_epoch: u64) -> RestartSignal {
        RestartSignal {
            restart: 0,
            invalidation_epoch,
            phase: RestartPhase::Idle,
        }
    }

    /// Attempt `restart` is announced with its persistent invalidation epoch.
    pub const fn announced(restart: u64, invalidation_epoch: u64) -> RestartSignal {
        RestartSignal {
            restart,
            invalidation_epoch,
            phase: RestartPhase::Announced,
        }
    }

    /// Attempt `restart` is draining.
    pub const fn draining(restart: u64, invalidation_epoch: u64) -> RestartSignal {
        RestartSignal {
            restart,
            invalidation_epoch,
            phase: RestartPhase::Draining,
        }
    }
}

/// The daemon's side of describing and replacing itself (spec §3, §4).
/// Implemented by `qshd`; the transport knows nothing about binaries.
/// `about` and `offer` may block -- hashing a binary, creating a file -- and
/// the runner calls them only from a blocking task.
pub trait DaemonUpdates: Send + Sync + 'static {
    /// What the daemon says about itself, or `None` if it cannot say (the
    /// session then stays silent, as a daemon that predates `About` does).
    fn about(&self) -> Option<About>;

    /// An offer from a session run by `from`. `Ok` is the go-ahead: the
    /// returned transfer receives the image and, once it is whole and good,
    /// replaces the daemon. `Err` is the answer to send instead. At most one
    /// transfer exists at a time across all sessions; the rest get
    /// `InProgress`.
    fn offer(
        &self,
        from: &Principal,
        offer: &UpdateOffer,
    ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer>;

    /// The restart signal every session watches.
    fn restart_signal(&self) -> watch::Receiver<RestartSignal>;

    /// A session saw restart `restart` announced and asks to be counted in
    /// its drain. Called at most once per session per restart. `true` means
    /// the daemon counted it and will wait for its
    /// [`DaemonUpdates::channels_released`]; `false` -- the attempt is no
    /// longer announced (already draining, or over) -- means the session
    /// owes that attempt nothing. The daemon must decide this atomically
    /// with respect to its own move to `Draining` (see [`RestartSignal`]).
    fn restart_joined(&self, restart: u64) -> bool;

    /// One session that joined restart `restart` has ended and reaped all
    /// its channels for it: after `Draining`, or when it ended itself (its
    /// client went away) while that restart was announced or draining.
    /// Called at most once per session per restart, and only after a
    /// `restart_joined(restart)` that returned `true`.
    fn channels_released(&self, restart: u64);

    /// How long a transfer may go without a byte. Overridden by tests.
    fn stall_timeout(&self) -> Duration {
        TRANSFER_STALL
    }
}

/// One accepted image on its way in. Everything here is blocking (a file, a
/// child process, `exec`), so the runner calls it only from a blocking task.
/// Dropping it before `restart` succeeds abandons the update: the
/// implementation removes whatever it staged and frees the slot.
pub trait UpdateTransfer: Send {
    /// The next bytes of the image, in order. `Err` is a detail for the log;
    /// it is reported as `RejectCode::DiskError`.
    fn write(&mut self, bytes: &[u8]) -> Result<(), String>;

    /// Every byte is in: check the image. `Err` is the result to report.
    fn verify(&mut self) -> Result<(), UpdateResult>;

    /// Replace the daemon. Returns only if that did not happen, with the
    /// result to report (`Busy` or `Rejected`).
    fn restart(self: Box<Self>) -> UpdateResult;
}

/// Where this session's update stands.
enum UpdateSlot {
    Idle,
    /// The daemon is deciding an offer (off the loop).
    Deciding,
    /// The original attachment must commit Accept before receiving can start.
    Accepting {
        size: u64,
        transfer: Box<dyn UpdateTransfer>,
        committed: tokio::sync::oneshot::Receiver<()>,
    },
    /// Accepted: `remaining` more bytes are expected on `UPDATE_STREAM`, each
    /// handed to the blocking receiver through `tx`.
    Receiving {
        tx: std::sync::mpsc::Sender<Vec<u8>>,
        remaining: u64,
    },
    /// Every byte is in; the blocking task verifies, then restarts.
    Finishing,
}

/// What a blocking call into the daemon came back with.
enum DaemonReply {
    Offer {
        origin: AttachmentContext,
        size: u64,
        decision: Result<Box<dyn UpdateTransfer>, UpdateAnswer>,
    },
}

/// How a blocking update task ended.
enum UpdateTaskEnd {
    Verified(Box<dyn UpdateTransfer>),
    Failed(UpdateResult),
}

type AboutResult = Result<Option<About>, crate::channel::AboutUnavailable>;
const ABOUT_RECORD_MAX: usize = 5 + 8 + 32 + 1 + crate::channel::MAX_ARCH_LEN + 2;

struct AboutWaiter {
    origin: AttachmentContext,
    response: crate::control_budget::ResponsePermit,
}
// Separate from response leases: at most two bounded logical metadata DTOs
// (provider result + one per-waiter clone) coexist under this job owner. The
// unshrunk response reservation covers encoder payload/record overlap.
struct AboutFlight {
    _job: crate::control_job::JobOwner,
    waiters: Vec<AboutWaiter>,
    result: tokio::sync::oneshot::Receiver<
        Result<AboutResult, crate::session_manager::CallbackFailure>,
    >,
}

async fn next_about(flight: &mut Option<AboutFlight>) -> AboutResult {
    match flight.as_mut() {
        Some(flight) => match (&mut flight.result).await {
            Ok(Ok(result)) => result,
            _ => Err(crate::channel::AboutUnavailable::ProviderFailed),
        },
        None => std::future::pending().await,
    }
}

fn send_about_result(io: &SessionIo, waiter: AboutWaiter, result: &AboutResult) {
    let record = match result {
        Ok(Some(about)) => ServerRecord::About(about.clone()),
        Ok(None) => return,
        Err(reason) => {
            if !waiter
                .origin
                .features
                .contains(crate::Features::RESOURCE_LIMITS)
            {
                io.close_session(waiter.origin);
                return;
            }
            ServerRecord::AboutUnavailable(*reason)
        }
    };
    // The provider metadata was validated on its bounded callback before this
    // encoding. Each waiter owns its own complete byte allocation and entry.
    let bytes = encode_server(&record);
    // The unshrunk response preflight covers payload/encoded overlap. The
    // separate About-job allowance covers provider DTO + this one clone.
    // Destroy the clone before narrowing to source/reliable-copy bytes.
    drop(record);
    let mut response = waiter.response;
    response
        .shrink_ordinary(bytes.len())
        .expect("About preflight covers encoding");
    let mut owner = response.into_owner();
    let part = owner
        .take_record(bytes.len())
        .expect("one reserved About response");
    io.send_reserved_control(waiter.origin, bytes, part);
}

struct UpdateChain {
    origin: AttachmentContext,
    response: crate::control_budget::ResponseOwner,
    job: crate::control_job::JobOwner,
}

/// Everything one session keeps about updating the daemon.
struct SessionUpdate {
    about: Option<AboutFlight>,
    daemon: Option<Arc<dyn DaemonUpdates>>,
    restart_rx: Option<watch::Receiver<RestartSignal>>,
    chain: Option<UpdateChain>,
    replies_rx: Option<
        tokio::sync::oneshot::Receiver<
            Result<DaemonReply, crate::session_manager::CallbackFailure>,
        >,
    >,
    slot: UpdateSlot,
    task: Option<
        tokio::sync::oneshot::Receiver<
            Result<UpdateTaskEnd, crate::session_manager::CallbackFailure>,
        >,
    >,
    /// The restart this session last told its client `Restarting` about.
    /// A watch channel keeps only the latest value, so a runner busy
    /// elsewhere can see `Draining` without ever having seen `Announced`, or
    /// the next attempt's `Announced` without the `Idle` between them; the
    /// number is what lets it say it exactly once per attempt.
    announced: Option<u64>,
    /// Uncommitted attempt retried only on watch or processed attachment changes.
    pending_announcement: Option<u64>,
    /// The restart this session last joined -- the only one it may confirm.
    joined: Option<u64>,
    /// The restart this session last ended its channels for.
    reaped: Option<u64>,
    /// The restart this session last confirmed.
    released: Option<u64>,
    /// Bytes of the transfer in progress handed to its receiving task, and
    /// what that task has taken (spec §4.10.3): when it ends, the difference
    /// -- queued to a task that stopped early -- is taken then.
    handed: u64,
    taken: Arc<AtomicU64>,
}

impl SessionUpdate {
    fn new(daemon: Option<Arc<dyn DaemonUpdates>>) -> SessionUpdate {
        let mut restart_rx = daemon.as_ref().map(|d| d.restart_signal());
        if let Some(rx) = restart_rx.as_mut() {
            // A restart already under way when this session starts is not a
            // change it will ever be told about -- yet it must act on it:
            // tell its client and, on a drain, confirm.
            if rx.borrow().phase != RestartPhase::Idle {
                rx.mark_changed();
            }
        }
        SessionUpdate {
            about: None,
            daemon,
            restart_rx,
            chain: None,
            replies_rx: None,
            slot: UpdateSlot::Idle,
            task: None,
            announced: None,
            pending_announcement: None,
            joined: None,
            reaped: None,
            released: None,
            handed: 0,
            taken: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Waiters share one actual provider call; every accepted request owns a
    /// separate response reservation. Missing optional service stays silent.
    fn about(
        &mut self,
        io: &SessionIo,
        origin: AttachmentContext,
        response: Option<crate::control_budget::ResponsePermit>,
    ) {
        let Some(daemon) = self.daemon.clone() else {
            return;
        };
        let waiter = AboutWaiter {
            origin,
            response: response.expect("About effect requires response preflight"),
        };
        if let Some(flight) = self.about.as_mut() {
            flight.waiters.push(waiter);
            return;
        }
        let mut job = match crate::control_job::JobOwner::reserve(
            io.control_budget(),
            crate::control_budget::Job::About,
        ) {
            Ok(job) => job,
            Err(_) => {
                send_about_result(
                    io,
                    waiter,
                    &Err(crate::channel::AboutUnavailable::ResourceExhausted),
                );
                return;
            }
        };
        let lease = job.take_worker().expect("one About provider phase");
        let result = io.spawn_callback(lease, move || {
            let mut about = daemon.about();
            if about
                .as_ref()
                .is_some_and(|about| !crate::channel::is_arch_name(&about.arch))
            {
                Err(crate::channel::AboutUnavailable::ProviderFailed)
            } else {
                if let Some(about) = about.as_mut() {
                    // Valid length alone does not bound retained provider
                    // capacity. Discard excess storage before publication.
                    about.arch = std::mem::take(&mut about.arch)
                        .into_boxed_str()
                        .into_string();
                }
                Ok(about)
            }
        });
        self.about = Some(AboutFlight {
            _job: job,
            waiters: vec![waiter],
            result,
        });
    }

    fn on_about(&mut self, io: &SessionIo, result: AboutResult) {
        let flight = self.about.take().expect("one joined provider result");
        for waiter in flight.waiters {
            send_about_result(io, waiter, &result);
        }
        // Metadata custody ends before the final About job owner is refunded.
        // Function parameters would otherwise outlive the local flight owner.
        drop(result);
    }

    fn offer(
        &mut self,
        io: &SessionIo,
        origin: AttachmentContext,
        offer: UpdateOffer,
        response: Option<crate::control_budget::ResponsePermit>,
    ) {
        let Some(daemon) = self.daemon.clone() else {
            return;
        };
        let mut response = response
            .expect("offer effects require response preflight")
            .into_owner();
        if !matches!(self.slot, UpdateSlot::Idle) {
            send_reserved_answer(io, origin, &mut response, UpdateAnswer::InProgress);
            return;
        }
        let mut job = match crate::control_job::JobOwner::reserve(
            io.control_budget(),
            crate::control_budget::Job::Update,
        ) {
            Ok(job) => job,
            Err(_) => {
                send_reserved_answer(io, origin, &mut response, UpdateAnswer::ResourceExhausted);
                return;
            }
        };
        let lease = job.take_worker().expect("reserved offer phase");
        self.chain = Some(UpdateChain {
            origin,
            response,
            job,
        });
        self.slot = UpdateSlot::Deciding;
        let from = io.principal().clone();
        self.replies_rx = Some(io.spawn_callback(lease, move || {
            let decision = daemon.offer(&from, &offer);
            DaemonReply::Offer {
                origin,
                size: offer.size,
                decision,
            }
        }));
    }

    fn on_reply(&mut self, io: &SessionIo, reply: DaemonReply) {
        let DaemonReply::Offer { origin, .. } = &reply;
        if *origin != io.processed_attachment() {
            self.slot = UpdateSlot::Idle;
            self.chain = None;
            return;
        }
        match reply {
            DaemonReply::Offer {
                decision: Err(refusal),
                ..
            } => {
                self.slot = UpdateSlot::Idle;
                let mut chain = self.chain.take().expect("reserved offer chain");
                send_reserved_answer(io, chain.origin, &mut chain.response, refusal);
            }
            DaemonReply::Offer {
                size,
                decision: Ok(transfer),
                ..
            } => {
                let chain = self.chain.as_mut().expect("reserved offer chain");
                let part = chain.response.take_record(6).expect("reserved Accept");
                let committed = io.commit_update(chain.origin, part);
                self.slot = UpdateSlot::Accepting {
                    size,
                    transfer,
                    committed,
                };
            }
        }
    }

    fn on_acceptance(&mut self, io: &SessionIo, committed: bool) {
        let slot = std::mem::replace(&mut self.slot, UpdateSlot::Idle);
        let UpdateSlot::Accepting { size, transfer, .. } = slot else {
            unreachable!("one pending acceptance receipt");
        };
        if !committed {
            self.chain = None;
            return;
        }
        let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let stall = self
            .daemon
            .as_ref()
            .map_or(TRANSFER_STALL, |d| d.stall_timeout());
        self.handed = 0;
        self.taken.store(0, Ordering::SeqCst);
        let taken = Arc::clone(&self.taken);
        let reporter = io.consumption_reporter();
        let lease = self
            .chain
            .as_mut()
            .expect("accepted update chain")
            .job
            .take_worker()
            .expect("reserved receive/verify phase");
        self.task = Some(io.spawn_callback(lease, move || {
            receive_and_verify(rx, transfer, size, stall, &reporter, &taken)
        }));
        self.slot = if size == 0 {
            UpdateSlot::Finishing
        } else {
            UpdateSlot::Receiving {
                tx,
                remaining: size,
            }
        };
    }

    fn send_result(&mut self, io: &SessionIo, result: UpdateResult) {
        let result = match result {
            UpdateResult::Rejected { code, detail } => UpdateResult::Rejected {
                code,
                detail: crate::channel::bounded_control_diagnostic(detail, 2),
            },
            result => result,
        };
        let bytes = crate::channel::encode_server_owned(ServerRecord::UpdateResult(result));
        let part = self
            .chain
            .as_mut()
            .expect("accepted outcome reservation")
            .response
            .take_record(bytes.len())
            .expect("finite reserved update outcome");
        io.send_session_control(bytes, part);
    }

    /// Bytes on `UPDATE_STREAM`. Without an accepted transfer in this
    /// session they are dropped, as bytes for a channel that is not open
    /// are; past the promised size they are dropped too. A dropped byte is
    /// taken at once; a byte handed to the transfer, once it is on disk
    /// (spec §4.10.3).
    fn receive(&mut self, io: &SessionIo, data: Vec<u8>) {
        let n = data.len();
        let (whole, handed) = match &mut self.slot {
            UpdateSlot::Receiving { tx, remaining } => {
                let take = (*remaining).min(n as u64) as usize;
                let handed = if tx.send(data[..take].to_vec()).is_ok() {
                    take
                } else {
                    // Its task is gone already: nobody takes these.
                    io.consumed(UPDATE_STREAM, take);
                    0
                };
                io.consumed(UPDATE_STREAM, n - take);
                *remaining -= take as u64;
                (*remaining == 0, handed)
            }
            _ => {
                io.consumed(UPDATE_STREAM, n);
                return;
            }
        };
        self.handed += handed as u64;
        if whole {
            // Dropping `tx` with the slot tells the receiver the image is whole.
            self.slot = UpdateSlot::Finishing;
        }
    }

    /// The restart signal as it stands now, seen or not.
    fn current_signal(&self) -> RestartSignal {
        self.restart_rx
            .as_ref()
            .map_or(RestartSignal::IDLE, |rx| *rx.borrow())
    }

    fn idle_epoch_guard(
        &self,
    ) -> Result<crate::channel_open::IdleEpochGuard<'_>, crate::channel_open::OpenRefusal> {
        match &self.restart_rx {
            Some(rx) => crate::channel_open::IdleEpochGuard::from_signal(rx.borrow()),
            None => Ok(crate::channel_open::IdleEpochGuard::initial()),
        }
    }

    /// A restart is under way: no channel may be opened.
    fn restarting(&self) -> bool {
        self.current_signal().phase != RestartPhase::Idle
    }

    /// Admit the complete mandatory announcement before committing its state.
    /// The watch guard establishes the source commit point; publication and
    /// permit destruction happen outside it, since receiver wakes may publish.
    fn announce(&mut self, io: &SessionIo, restart: u64) {
        let origin = io.processed_attachment();
        let Some(rx) = &self.restart_rx else { return };
        let signal = rx.borrow();
        if signal.restart != restart || signal.phase == RestartPhase::Idle {
            self.pending_announcement = None;
            return;
        }
        if self.announced == Some(restart) {
            self.pending_announcement = None;
            return;
        }
        self.pending_announcement = Some(restart);
        let reserved = io
            .control_budget()
            .reserve(crate::control_budget::Response::Restart);
        match reserved {
            Ok(response) => {
                self.announced = Some(restart);
                self.pending_announcement = None;
                drop(signal);
                let mut owner = response.into_owner();
                let bytes = encode_server(&ServerRecord::Restarting);
                let part = owner
                    .take_record(bytes.len())
                    .expect("fixed Restarting envelope");
                io.send_session_control(bytes, part);
            }
            Err(_) => {
                drop(signal);
                // This is independent of joining the daemon's cleanup count.
                // A captured old origin can never terminate its replacement.
                io.resource_exhausted(origin);
            }
        }
    }

    fn retry_announcement(&mut self, io: &SessionIo) {
        if let Some(restart) = self.pending_announcement {
            self.announce(io, restart);
        }
    }

    /// Ask to be counted in restart `restart`'s drain, once: only a session
    /// the daemon counted confirms it (see [`RestartSignal`]).
    fn join(&mut self, restart: u64) {
        let Some(daemon) = &self.daemon else {
            return;
        };
        if self.joined != Some(restart) && daemon.restart_joined(restart) {
            self.joined = Some(restart);
        }
    }

    /// Whether this session has yet to end its channels for `restart`.
    fn owes_reap(&self, restart: u64) -> bool {
        self.daemon.is_some() && self.reaped != Some(restart)
    }

    /// Every channel of this session is ended and reaped for `restart`:
    /// tell the daemon, once -- if it counted this session in.
    fn confirm_released(&mut self, restart: u64) {
        self.reaped = Some(restart);
        if self.joined != Some(restart) || self.released == Some(restart) {
            return;
        }
        self.released = Some(restart);
        if let Some(daemon) = &self.daemon {
            daemon.channels_released(restart);
        }
    }

    fn on_task_end(&mut self, io: &SessionIo, end: UpdateTaskEnd) {
        // What the transfer was handed and its task never took -- it ended
        // early -- is taken now.
        let taken = self.taken.swap(0, Ordering::SeqCst);
        io.consumed(UPDATE_STREAM, self.handed.saturating_sub(taken) as usize);
        self.handed = 0;
        match end {
            UpdateTaskEnd::Verified(transfer) => {
                // Said before the attempt: once it succeeds, nothing of this
                // process is left to say anything.
                self.send_result(io, UpdateResult::Restarting);
                let lease = self
                    .chain
                    .as_mut()
                    .expect("accepted update chain")
                    .job
                    .take_worker()
                    .expect("reserved restart phase");
                self.task = Some(
                    io.spawn_callback(lease, move || UpdateTaskEnd::Failed(transfer.restart())),
                );
            }
            UpdateTaskEnd::Failed(result) => {
                self.send_result(io, result);
                self.slot = UpdateSlot::Idle;
                self.chain = None;
            }
        }
    }
}

fn send_reserved_answer(
    io: &SessionIo,
    origin: AttachmentContext,
    response: &mut crate::control_budget::ResponseOwner,
    answer: UpdateAnswer,
) {
    if matches!(
        answer,
        UpdateAnswer::ResourceExhausted | UpdateAnswer::ProviderFailed
    ) && !origin.features.contains(crate::Features::RESOURCE_LIMITS)
    {
        io.close_session(origin);
        return;
    }
    let bytes = encode_server(&ServerRecord::UpdateAnswer(answer));
    let part = response
        .take_record(bytes.len())
        .expect("reserved update answer");
    io.send_reserved_control(origin, bytes, part);
}

/// The blocking half of a transfer: take the image as it arrives, then
/// verify it. A sender that goes quiet for `stall` is given up on; one that
/// goes away early leaves fewer bytes than promised.
fn receive_and_verify(
    rx: std::sync::mpsc::Receiver<Vec<u8>>,
    mut transfer: Box<dyn UpdateTransfer>,
    size: u64,
    stall: Duration,
    reporter: &ConsumptionReporter,
    taken: &AtomicU64,
) -> UpdateTaskEnd {
    let rejected = |code: RejectCode, detail: String| {
        UpdateTaskEnd::Failed(UpdateResult::Rejected { code, detail })
    };
    let mut got = 0u64;
    loop {
        match rx.recv_timeout(stall) {
            Ok(chunk) => {
                got += chunk.len() as u64;
                let written = transfer.write(&chunk);
                // On disk, or refused by it: taken either way.
                reporter.consumed(UPDATE_STREAM, chunk.len());
                taken.fetch_add(chunk.len() as u64, Ordering::SeqCst);
                if let Err(detail) = written {
                    return rejected(RejectCode::DiskError, detail);
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                return rejected(
                    RejectCode::TransferStalled,
                    format!("the transfer stalled: no data for {} ms", stall.as_millis()),
                );
            }
        }
    }
    if got != size {
        return rejected(
            RejectCode::SizeMismatch,
            format!("expected {size} bytes, received {got}"),
        );
    }
    match transfer.verify() {
        Ok(()) => UpdateTaskEnd::Verified(transfer),
        Err(result) => UpdateTaskEnd::Failed(result),
    }
}

/// The next change of the restart signal; never, for a session with nobody
/// behind it or once the signal's sender is gone.
async fn restart_signal_changed(rx: &mut Option<watch::Receiver<RestartSignal>>) -> RestartSignal {
    let Some(rx) = rx else {
        return std::future::pending().await;
    };
    if rx.changed().await.is_err() {
        return std::future::pending().await;
    }
    *rx.borrow_and_update()
}

/// One bounded result from an actual-joined offer callback.
async fn next_reply(
    rx: &mut Option<
        tokio::sync::oneshot::Receiver<
            Result<DaemonReply, crate::session_manager::CallbackFailure>,
        >,
    >,
) -> Option<DaemonReply> {
    let result = match rx.as_mut() {
        Some(rx) => rx.await,
        None => return std::future::pending().await,
    };
    *rx = None;
    result.ok().and_then(Result::ok)
}

async fn acceptance_committed(slot: &mut UpdateSlot) -> bool {
    match slot {
        UpdateSlot::Accepting { committed, .. } => committed.await.is_ok(),
        _ => std::future::pending().await,
    }
}

/// One phase result is published only after actual blocking join.
async fn join_update(
    task: &mut Option<
        tokio::sync::oneshot::Receiver<
            Result<UpdateTaskEnd, crate::session_manager::CallbackFailure>,
        >,
    >,
) -> UpdateTaskEnd {
    let end = match task.as_mut() {
        Some(receiver) => match receiver.await {
            Ok(Ok(end)) => end,
            _ => UpdateTaskEnd::Failed(UpdateResult::Rejected {
                code: RejectCode::Other,
                detail: "the update provider failed".to_string(),
            }),
        },
        None => std::future::pending().await,
    };
    *task = None;
    end
}

/// End every channel still open and wait for its process -- the same reap
/// the session's own end does (see the module docs), shared with a drain
/// before the daemon replaces itself.
fn begin_reap_all(io: &SessionIo, channels: &mut HashMap<u8, Channel>, reaps: &mut ReapSet) {
    reaps.stop_all();
    for (stream, ch) in channels.drain() {
        io.channel_closed(
            stream,
            ChannelInstance::new(ch.instance).unwrap(),
            ch.producer.origin,
        );
        forget_channel_stream(io, stream);
        let Channel {
            input_tx,
            wait,
            _open_slot,
            instance,
            ..
        } = ch;
        drop(input_tx);
        if let Some(wait) = wait {
            reaps.start(stream, instance, wait, _open_slot, true);
        } else {
            reaps.stop(instance);
        }
    }
}

/// A channel is gone -- its process ended, the client closed it, or the
/// runner reaped it -- and its stream number is free for another. What the
/// channel still owns in the typed bridge survives until handoff or explicit
/// teardown. Its registered send gate is closed for good,
/// which wakes a line channel's reader waiting on it (it then ends instead
/// of reading on), and its class goes back to interactive, every stream's
/// default. The bridge declares every class it kept again after a warm
/// reattach, so a class left behind would reach whatever channel reuses the
/// number.
fn forget_channel_stream(io: &SessionIo, stream: u8) {
    io.drop_send_gate(stream);
    io.set_stream_class(stream, StreamClass::Interactive);
}

/// A channel that ended, waiting for its output to be delivered before its
/// `Exit` goes (see the module docs).
struct PendingExit {
    /// Which channel on this stream number it was: the delivery answer
    /// names it, and an answer to an earlier channel's request -- one the
    /// client closed and opened again -- must not release this one.
    instance: u64,
    code: Option<Option<i32>>,
    delivered: bool,
    geometry: GeometryRecord,
    open: crate::channel::OpenClassification,
    gate: Arc<SendGate>,
    final_marker: DeliveryMarker,
    producer: ProducerState,
}
impl PendingExit {
    fn reset(&mut self, origin: AttachmentContext) {
        self.producer
            .timeline
            .reset_attachment(self.geometry.instance, origin.generation);
        self.producer.origin = origin;
        self.delivered = false;
        self.geometry.request_id = 0;
        self.geometry.outcome = GeometryOutcome::Established;
    }
}
impl Drop for PendingExit {
    fn drop(&mut self) {
        self.gate.close();
    }
}

/// Input retains its payload quota until actual write or discard. A local
/// receipt additionally prevents EOF from overtaking its write outcome.
enum WriterInput {
    Network(crate::channel_input::InputChunk),
    LocalReply {
        // Settle failure before releasing quota if a queued item is dropped.
        receipt: crate::channel_reply_delivery::ReplyReceipt,
        chunk: crate::channel_input::InputChunk,
    },
}
impl std::fmt::Debug for WriterInput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Network(_) => "WriterInput::Network",
            Self::LocalReply { .. } => "WriterInput::LocalReply",
        })
    }
}
impl WriterInput {
    fn into_parts(
        self,
    ) -> (
        crate::channel_input::InputChunk,
        Option<crate::channel_reply_delivery::ReplyReceipt>,
    ) {
        match self {
            Self::Network(chunk) => (chunk, None),
            Self::LocalReply { receipt, chunk } => (chunk, Some(receipt)),
        }
    }
    #[cfg(test)]
    fn bytes(&self) -> &[u8] {
        match self {
            Self::Network(chunk) | Self::LocalReply { chunk, .. } => chunk.bytes(),
        }
    }
    #[cfg(test)]
    fn network_bytes(&self) -> usize {
        match self {
            Self::Network(chunk) | Self::LocalReply { chunk, .. } => chunk.network_bytes(),
        }
    }
}

/// One open channel, as the runner keeps track of it.
struct Channel {
    _open_slot: Option<crate::channel_open::InstalledSlot>,
    producer: ProducerState,
    /// Every queued or writer-held chunk owns channel and session quota.
    /// Admission bounds this nonblocking FIFO independently of transport credit.
    input_tx: Option<mpsc::UnboundedSender<WriterInput>>,
    input_budget: crate::channel_input::ChannelInputBudget,
    resize: Box<dyn ResizeHandle>,
    screen: Box<dyn SessionScreen>,
    /// Echo-ack accounting, exactly as in `serve_shell`, but tracked per
    /// channel rather than per session.
    input_consumed: u64,
    last_acked: u64,
    /// The channel's send gate (spec §4.7.2). A screen channel's is looked
    /// at here, per chunk; a line channel's by its reader, before each read.
    gate: Arc<SendGate>,
    /// Whether the channel has a screen model -- the same answer it gave at
    /// open, kept so the per-chunk rule need not ask again.
    screened: bool,
    /// A screen channel dropped output behind its closed gate: the next
    /// chunk or `Writable` after the gate opens sends one repaint instead.
    stale: bool,
    /// This channel among every one the session opened, whatever its
    /// stream number (see `PendingExit`).
    instance: u64,
    /// The request that opened this channel, kept up to date by `Resize` so
    /// it always reflects the geometry actually applied. Used to build
    /// active lifecycle metadata on a warm reattach; EOF retains only classification.
    request: OpenRequest,
    /// Reaps the channel's process: fetches its exit code when the reader
    /// hits EOF, or is forced down if the session ends first (see the
    /// module docs).
    wait: Option<Box<dyn ChannelWait>>,
    /// Confirmed process termination, including an unavailable exit status.
    terminal_code: Option<Option<i32>>,
    /// Leader exit rejects client input while real EOF may still flush replies.
    ending: bool,
}

/// The runner's ordered attachment, admitted-open ledger and capacity signal.
#[derive(Default)]
struct ProducerContext {
    attachment: AttachmentContext,
    ready: Arc<tokio::sync::Notify>,
    opens: OpenScope,
    input_budget: crate::channel_input::SessionInputBudget,
}
struct OpenScope {
    registry: Arc<crate::channel_open::ChannelOpenRegistry>,
    session: Option<Arc<crate::channel_open::SessionOpenLedger>>,
}
impl OpenScope {
    fn new(registry: Arc<crate::channel_open::ChannelOpenRegistry>) -> Self {
        let allocation = registry.session();
        Self::from_allocation(registry, allocation)
    }
    fn from_allocation(
        registry: Arc<crate::channel_open::ChannelOpenRegistry>,
        allocation: Result<
            Arc<crate::channel_open::SessionOpenLedger>,
            crate::channel_open::OpenRefusal,
        >,
    ) -> Self {
        let session = allocation.ok();
        Self { registry, session }
    }
    fn occupied(&self) -> usize {
        self.session
            .as_ref()
            .map_or(0, |session| session.occupied())
    }
    async fn notified(&self) {
        match &self.session {
            Some(session) => session.notified().await,
            None => std::future::pending().await,
        }
    }
}
impl Default for OpenScope {
    fn default() -> Self {
        Self::new(crate::channel_open::ChannelOpenRegistry::new(
            Default::default(),
        ))
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResizeIntent {
    instance: ChannelInstance,
    request_id: ResizeRequestId,
    cols: u16,
    rows: u16,
    origin: AttachmentContext,
}
struct ProducerState {
    terminal_response: Option<crate::control_budget::ResponseOwner>,
    reply_delivery: crate::channel_reply_delivery::ReplyDelivery,
    origin: AttachmentContext,
    timeline: TimelineBudget,
    deferred: Option<ResizeIntent>,
    last_request: Option<ResizeIntent>,
    last_outcome: Option<GeometryRecord>,
    failed: bool,
    checkpoint_due: bool,
    data_since_checkpoint: bool,
    queued_data: std::collections::VecDeque<Vec<u8>>,
    eof: bool,
    final_marker: Option<TimelinePermit>,
    exit_permit: Option<TimelinePermit>,
    // One fixed allowance for bridge gap/bootstrap, independent of requests.
    gap_reserve: Option<TimelinePermit>,
    // Reply failure is permanent for this instance, including after reattachment.
    reply_failed: bool,
    reply_failure_permit: Option<TimelinePermit>,
}
impl ProducerState {
    fn new(instance: ChannelInstance, context: &ProducerContext) -> Self {
        let ready = context.ready.clone();
        let timeline = TimelineBudget::new(instance, context.attachment.generation, move |_| {
            ready.notify_one()
        });
        let final_marker = timeline.try_reserve(EntryClass::Lifecycle, DELIVERY_MARKER_BYTES);
        let exit_permit = timeline.try_reserve(EntryClass::Lifecycle, 10);
        let gap_permit = timeline
            .try_reserve(
                EntryClass::Lifecycle,
                crate::channel_timeline::BRIDGE_LIFECYCLE_BYTES,
            )
            .expect("fixed lifecycle reserve");
        let reply_failure_permit = timeline
            .try_reserve(EntryClass::Lifecycle, 14)
            .expect("fixed terminal failure reserve");
        Self {
            terminal_response: None,
            reply_delivery: crate::channel_reply_delivery::ReplyDelivery::new(
                context.ready.clone(),
            ),
            origin: context.attachment,
            timeline,
            deferred: None,
            last_request: None,
            last_outcome: None,
            failed: false,
            checkpoint_due: false,
            data_since_checkpoint: false,
            queued_data: Default::default(),
            eof: false,
            final_marker,
            exit_permit,
            gap_reserve: Some(gap_permit),
            reply_failed: false,
            reply_failure_permit: Some(reply_failure_permit),
        }
    }
}

/// Disclose an unrecoverable model/reply failure without poisoning the session.
/// The runner transfers the exact process to its reaper after this event.
fn fail_terminal_reply(io: &SessionIo, ch: &mut Channel) {
    if ch.producer.reply_failed {
        return;
    }
    ch.producer.reply_failed = true;
    ch.producer.deferred = None;
    ch.stale = false;
    ch.input_budget.close();
    ch.gate.set_metadata_blocked(ch.producer.checkpoint_due);
    let permit = ch
        .producer
        .reply_failure_permit
        .take()
        .expect("one terminal failure");
    io.send_channel_output(
        ch.request.stream,
        ChannelInstance::new(ch.instance).unwrap(),
        ch.producer.origin,
        ch.gate.clone(),
        ChannelOutput::OutputGap(
            crate::channel_geometry::OutputGapCause::TerminalReplyFailure,
            permit,
        ),
        ch.producer.gap_reserve.take(),
    );
    log::warn!(
        "terminal reply failed; stopping channel {}/{}",
        ch.request.stream,
        ch.instance
    );
}

fn admit_terminal_reply(
    io: &SessionIo,
    ch: &mut Channel,
    reply: Result<Vec<u8>, crate::shell_server::ScreenReplyError>,
) -> bool {
    if ch.producer.reply_failed {
        return false;
    }
    if let Ok(bytes) = reply {
        if bytes.is_empty() {
            return true;
        }
        match ch.input_budget.try_local_reply(bytes) {
            Ok(None) => return true,
            Ok(Some(chunk)) => {
                if let Some(receipt) = ch.producer.reply_delivery.try_reserve() {
                    if ch.input_tx.as_ref().is_some_and(|tx| {
                        tx.send(WriterInput::LocalReply { receipt, chunk }).is_ok()
                    }) {
                        return true;
                    }
                }
            }
            _ => {}
        }
    }
    fail_terminal_reply(io, ch);
    false
}

fn flush_due_terminal_output(io: &SessionIo, ch: &mut Channel, now: std::time::Instant) {
    if ch.producer.reply_failed || ch.producer.eof {
        return;
    }
    if ch.producer.reply_delivery.snapshot().failed {
        fail_terminal_reply(io, ch);
        return;
    }
    let replies = ch.screen.flush_due_output(now);
    admit_terminal_reply(io, ch, replies);
}

fn emit_screen_repaint(io: &SessionIo, ch: &mut Channel) -> bool {
    if ch.producer.reply_failed {
        return false;
    }
    match ch.screen.repaint() {
        Ok(repaint) => {
            if !admit_terminal_reply(io, ch, Ok(repaint.replies)) {
                return false;
            }
            emit_data(io, ch, &repaint.bytes);
            true
        }
        Err(error) => admit_terminal_reply(io, ch, Err(error)),
    }
}

fn absorb_output(io: &SessionIo, ch: &mut Channel, chunk: &[u8]) {
    if ch.producer.reply_failed {
        return;
    }
    let replies = ch.screen.absorb(chunk);
    if admit_terminal_reply(io, ch, replies) {
        forward_output(io, ch.request.stream, ch, chunk);
    }
}
fn fail_resize(io: &SessionIo, ch: &mut Channel, code: Option<ProtocolErrorCode>) -> bool {
    if !ch.producer.failed {
        ch.producer.failed = true;
        ch.producer.deferred = None;
        io.protocol_failure(ch.producer.origin, code);
    }
    false
}
fn current_geometry(ch: &Channel) -> GeometryRecord {
    ch.producer.last_outcome.unwrap_or(GeometryRecord {
        instance: ChannelInstance::new(ch.instance).expect("nonzero channel instance"),
        request_id: 0,
        outcome: GeometryOutcome::Established,
        cols: ch.request.cols,
        rows: ch.request.rows,
    })
}
fn emit_geometry(io: &SessionIo, ch: &mut Channel, record: GeometryRecord, permit: TimelinePermit) {
    let gap_reserve = ch.producer.gap_reserve.take();
    io.send_channel_output(
        ch.request.stream,
        record.instance,
        ch.producer.origin,
        ch.gate.clone(),
        ChannelOutput::Geometry(record, permit),
        gap_reserve,
    );
    ch.producer.data_since_checkpoint = false;
}
fn emit_data(io: &SessionIo, ch: &mut Channel, bytes: &[u8]) {
    if bytes.is_empty() {
        return;
    }
    ch.producer.data_since_checkpoint = true;
    io.send_channel_output(
        ch.request.stream,
        ChannelInstance::new(ch.instance).unwrap(),
        ch.producer.origin,
        ch.gate.clone(),
        ChannelOutput::Data(bytes.to_vec()),
        None,
    );
}
fn emit_ack(io: &SessionIo, ch: &mut Channel) {
    let Some(permit) = ch.producer.timeline.try_reserve(EntryClass::Ordinary, 13) else {
        return;
    };
    io.send_channel_output(
        ch.request.stream,
        ChannelInstance::new(ch.instance).unwrap(),
        ch.producer.origin,
        ch.gate.clone(),
        ChannelOutput::EchoAck(ch.input_consumed, permit),
        None,
    );
    ch.last_acked = ch.input_consumed;
}
fn process_resize(io: &SessionIo, ch: &mut Channel, request: ResizeIntent) -> bool {
    if ch.producer.reply_failed {
        return true;
    }
    if ch.producer.failed {
        return false;
    }
    if ch.producer.eof {
        return fail_resize(io, ch, None);
    }
    if request.instance.get() != ch.instance || request.origin != ch.producer.origin {
        return fail_resize(io, ch, None);
    }
    if let Some(deferred) = ch.producer.deferred {
        if deferred == request {
            return true;
        }
        return fail_resize(io, ch, Some(ProtocolErrorCode::ResizePipelineOverflow));
    }
    if ch.producer.last_request == Some(request) {
        return true;
    }
    let expected = ch
        .producer
        .last_request
        .map_or(Some(1), |r| r.request_id.get().checked_add(1));
    if expected != Some(request.request_id.get()) {
        return fail_resize(io, ch, None);
    }
    let permit = if ch.producer.checkpoint_due {
        None
    } else {
        ch.producer
            .timeline
            .try_reserve(EntryClass::Ordinary, GEOMETRY_BYTES)
    };
    let Some(permit) = permit else {
        ch.producer.deferred = Some(request);
        ch.gate.set_metadata_blocked(true);
        if !ch.producer.checkpoint_due
            && ch
                .producer
                .timeline
                .register_waiter_and_recheck(request.instance, request.origin.generation)
                == WaitRegistration::Ready
        {
            ch.producer.deferred = None;
            return process_resize(io, ch, request);
        }
        return true;
    };
    // The complete outcome is owned before validation, preparation or ioctl.
    // Synchronized output queries belong to the geometry before this resize.
    let replies = ch.screen.flush_pending_output();
    if !admit_terminal_reply(io, ch, replies) {
        return true;
    }
    let previous = (ch.request.cols, ch.request.rows);
    let result = if previous.0 == 0 || previous.1 == 0 {
        Err(ResizeRefusal::NoPty)
    } else {
        TerminalSize::new(request.cols, request.rows)
            .map_err(|_| ResizeRefusal::InvalidSize)
            .and_then(|size| resize_channel(ch, size))
    };
    let record = GeometryRecord {
        instance: request.instance,
        request_id: request.request_id.get(),
        outcome: match result {
            Ok(()) => GeometryOutcome::Applied,
            Err(reason) => GeometryOutcome::Refused(reason),
        },
        cols: ch.request.cols,
        rows: ch.request.rows,
    };
    ch.producer.last_request = Some(request);
    ch.producer.last_outcome = Some(record);
    ch.gate.set_metadata_blocked(false);
    if ch.screened && !ch.gate.is_open() {
        ch.stale = true; // the fixed last_outcome is the Screen replacement
        drop(permit);
    } else {
        emit_geometry(io, ch, record, permit);
        if ch.screened && result.is_ok() && previous != (record.cols, record.rows) {
            if !emit_screen_repaint(io, ch) {
                return true;
            }
            emit_ack(io, ch);
            ch.stale = false;
        }
    }
    true
}
fn reset_producer(ch: &mut Channel, origin: AttachmentContext) {
    ch.producer.timeline.reset_attachment(
        ChannelInstance::new(ch.instance).unwrap(),
        origin.generation,
    );
    ch.producer.origin = origin;
    ch.producer.deferred = None;
    ch.producer.last_request = None;
    ch.producer.last_outcome = None;
    ch.producer.failed = false;
    ch.gate.set_metadata_blocked(ch.producer.checkpoint_due);
}
/// A missing lifecycle slot holds only one current checkpoint and bounded
/// reader overshoot. Ordinary resize results cannot consume this allowance.
fn checkpoint(io: &SessionIo, ch: &mut Channel) -> bool {
    let instance = ChannelInstance::new(ch.instance).unwrap();
    let class = if ch.producer.data_since_checkpoint {
        EntryClass::Ordinary
    } else {
        EntryClass::Lifecycle
    };
    loop {
        if let Some(permit) = ch.producer.timeline.try_reserve(class, GEOMETRY_BYTES) {
            emit_geometry(io, ch, current_geometry(ch), permit);
            // Every checkpoint caller must finish the hold before admitting
            // newer output or a resize. Repaint can win the runner select
            // before the capacity notification that resumes this producer.
            while let Some(bytes) = ch.producer.queued_data.pop_front() {
                emit_data(io, ch, &bytes);
            }
            ch.producer.checkpoint_due = false;
            ch.gate.set_metadata_blocked(ch.producer.deferred.is_some());
            return true;
        }
        ch.producer.checkpoint_due = true;
        ch.gate.set_metadata_blocked(true);
        match ch.producer.timeline.register_waiter_for(
            instance,
            ch.producer.origin.generation,
            class,
            GEOMETRY_BYTES,
        ) {
            WaitRegistration::Ready => continue,
            _ => return false,
        }
    }
}
fn resume_producer(io: &SessionIo, ch: &mut Channel) {
    if ch.producer.reply_failed {
        // A failure may race a capacity-blocked attachment bootstrap. Its
        // committed geometry is still valid, but its model must never replay.
        if ch.producer.checkpoint_due {
            checkpoint(io, ch);
        }
        return;
    }
    if ch.producer.failed {
        return;
    }
    let checkpoint_was_due = ch.producer.checkpoint_due;
    if checkpoint_was_due && !checkpoint(io, ch) {
        return;
    }
    if checkpoint_was_due && ch.screened && ch.stale {
        if !emit_screen_repaint(io, ch) {
            return;
        }
        emit_ack(io, ch);
        ch.stale = false;
    }
    if let Some(request) = ch.producer.deferred.take() {
        process_resize(io, ch, request);
    }
    if ch.screened && ch.stale && ch.gate.is_open() {
        repaint_stale(io, ch.request.stream, ch);
    }
}

#[cfg(test)]
thread_local! {
    static CONTROL_REFUND_BEFORE_SELECT: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
    static CONTROL_CAPACITY_WAKES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static CONTROL_FIRST_ACK_TICK: std::cell::RefCell<Option<Arc<tokio::sync::Notify>>> = const { std::cell::RefCell::new(None) };
}

/// What woke the runner loop.
enum Wakeup {
    /// An inbound session event (`None` = the manager dropped the io,
    /// session torn down).
    Inbound(Option<SessionInbound>),
    /// Output tagged with which channel produced it (`None` chunk = that
    /// channel's reader hit EOF, i.e. its process ended).
    ChannelOut(Option<(u8, u64, Option<Vec<u8>>)>),
    /// The short echo_ack flush timer, as in `serve_shell`.
    AckTick,
    ControlReady,
    CapacityReady,
    About(AboutResult),
    OutputReady,
    OpenReady,
    Reaped(reaping::ReapEvent),
    /// The restart signal moved.
    Restart(RestartSignal),
    /// A blocking call into the daemon came back.
    Reply(Option<DaemonReply>),
    Acceptance(bool),
    /// This session's update task ended.
    Update(UpdateTaskEnd),
}

fn reset_attachment_outputs(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    exits: &mut HashMap<u8, PendingExit>,
    context: AttachmentContext,
) {
    // Reserve all three independent snapshot representations before resetting
    // producer/model state. Rejection leaves the old view untouched.
    let published = io.publish_resume_snapshot(context, || {
        for ch in channels.values_mut() {
            // These bounded reader chunks use geometry already established in the
            // old timeline. A capacity-blocked repaint checkpoint did not resize
            // that model. Transfer the bytes under their old origin before closing
            // that producer scope; Stage 4 supplies the new attachment bootstrap.
            while let Some(bytes) = ch.producer.queued_data.pop_front() {
                emit_data(io, ch, &bytes);
            }
            reset_producer(ch, context);
            ch.input_consumed = 0;
            ch.last_acked = 0;
            // The same rule `open_channel` uses: ask the channel's
            // OWN screen model, not `ch.request.screen` (what the
            // client originally asked for) -- see
            // `SessionScreen::has_screen`'s own doc for why the two
            // can disagree.
            io.set_stream_resyncable(ch.request.stream, ch.screened && !ch.producer.reply_failed);
        }
        for pending in exits.values_mut() {
            pending.reset(context);
        }
        use crate::channel::{ActiveChannel, ChannelSnapshot, DrainingChannel, OpenClassification};
        let mut active = Vec::with_capacity(channels.len());
        let mut draining = Vec::with_capacity(exits.len() + channels.len());
        for (&stream, ch) in channels.iter() {
            let instance = ChannelInstance::new(ch.instance).expect("channel instance");
            if ch.ending {
                draining.push(DrainingChannel {
                    stream,
                    instance,
                    open: OpenClassification::from_open(&ch.request),
                });
            } else {
                active.push(ActiveChannel {
                    instance,
                    request: ch.request.clone(),
                });
            }
        }
        draining.extend(exits.iter().map(|(&stream, pending)| DrainingChannel {
            stream,
            instance: pending.geometry.instance,
            open: pending.open,
        }));
        ChannelSnapshot::new(active, draining)
    });
    // Publication emits the snapshot wake before new-generation repaint output.
    if published {
        repaint_all(io, channels);
    }
}

fn send_pending_exit(io: &SessionIo, stream: u8, pending: &mut PendingExit) {
    let code = pending
        .code
        .expect("child termination confirmed before Exit");
    forget_channel_stream(io, stream);
    let permit = pending.producer.exit_permit.take().expect("one final Exit");
    let bytes = if code.is_some() { 10 } else { 6 };
    let response = pending
        .producer
        .terminal_response
        .as_mut()
        .expect("terminal outcome retains admitted open envelope")
        .take_record(bytes)
        .expect("one reserved terminal outcome");
    io.send_channel_exit(
        crate::channel::DrainingChannel {
            stream,
            instance: pending.geometry.instance,
            open: pending.open,
        },
        pending.producer.origin,
        code,
        permit,
        response,
    );
}

/// Transfer process custody exactly once, independently of output backpressure.
/// Natural EOF observes without signalling; an explicit stop also reaches a
/// process already being observed by the registered reaper.
fn begin_channel_ending(ch: &mut Channel, reaps: &mut ReapSet, stop: bool) {
    ch.ending = true;
    ch.input_budget.close();
    drop(ch.input_tx.take());
    ch.producer.deferred = None;
    if let Some(wait) = ch.wait.take() {
        reaps.start(
            ch.request.stream,
            ch.instance,
            wait,
            ch._open_slot.take(),
            stop,
        );
    } else if stop {
        reaps.stop(ch.instance);
    } else {
        reaps.retire(ch.instance);
    }
}

fn finish_channel(io: &SessionIo, mut ch: Channel, reaps: &mut ReapSet) -> PendingExit {
    begin_channel_ending(&mut ch, reaps, false);
    let geometry = current_geometry(&ch);
    let open = crate::channel::OpenClassification::from_open(&ch.request);
    let final_marker = DeliveryMarker { token: ch.instance };
    drop(ch.input_tx);
    io.send_channel_output(
        ch.request.stream,
        geometry.instance,
        ch.producer.origin,
        ch.gate.clone(),
        ChannelOutput::DeliveryMarker(
            final_marker,
            ch.producer.final_marker.take().expect("one final marker"),
        ),
        None,
    );
    PendingExit {
        instance: ch.instance,
        code: ch.terminal_code,
        delivered: false,
        geometry,
        open,
        gate: ch.gate,
        final_marker,
        producer: ch.producer,
    }
}

/// [`run_channel_session_with`] with nobody behind it speaking for the
/// daemon: `About` goes unanswered and offers are ignored, exactly as by a
/// daemon that predates those records.
pub async fn run_channel_session(io: SessionIo, spawner: Arc<dyn ChannelSpawner>) {
    run_channel_session_with(io, spawner, None).await
}

/// Drive a session that hands out channels on demand, over a [`SessionIo`]
/// -- see the module docs -- and, with `daemon`, answer for the daemon
/// itself: `About`, one update at a time, `Restarting` to this session's
/// client, and a drain of its channels before the daemon replaces itself.
/// See the module docs for how this generalises `serve_shell`'s single fixed
/// pseudo-terminal into a client-controlled, dynamically sized set.
///
/// Returns once the manager drops the io (`io.recv()` yields `None` --
/// session torn down). A channel's process ending does NOT end the session
/// (its exit code is reported and the loop moves on); only the session
/// ending drops every channel's input sender, which is what lets their
/// writer bridge tasks exit, and reaps whatever channel is still open (see
/// the module docs).
pub async fn run_channel_session_with(
    mut io: SessionIo,
    spawner: Arc<dyn ChannelSpawner>,
    daemon: Option<Arc<dyn DaemonUpdates>>,
) {
    let mut channels: HashMap<u8, Channel> = HashMap::new();
    let mut opening = HashMap::new();
    let mut reaps = ReapSet::new(spawner.open_registry());
    let mut draining = None;
    let executor =
        crate::channel_open::ChannelOpenExecutor::new(spawner.clone(), spawner.open_registry());
    // EOF owners by stream: final output delivery and exact child reap are
    // independent prerequisites of each terminal record.
    let mut exits: HashMap<u8, PendingExit> = HashMap::new();
    // Numbers every channel opened, so a delivery answer names the channel
    // it was asked for (see `PendingExit`).
    let mut next_instance: u64 = 1;
    let mut producer = ProducerContext {
        opens: OpenScope::new(spawner.open_registry()),
        input_budget: crate::channel_input::SessionInputBudget::new(),
        attachment: AttachmentContext::default(),
        ready: Arc::new(tokio::sync::Notify::new()),
    };
    let mut control_buf = control_input::ControlInput::default();
    let global_budget = io.global_control_budget();
    let mut control_overflow_logged = false;
    // A protocol failure stops further application input for this attachment.
    let mut unsupported_control = false;
    let mut retiring = false;
    // Sticky only within this exact attachment. Removing a job is not proof
    // that its decision was published; epoch/registry cancellation may drop it.
    let mut decisions_complete = true;
    // The client's terminal type, once it says: every channel opened after
    // that is spawned with it. `None` until then, and for a client that
    // never says at all -- the spawner decides what to do with that.
    let mut term: Option<String> = None;
    let mut update = SessionUpdate::new(daemon);

    // Every open channel's reader bridge task sends into this ONE shared
    // channel, tagged with its stream -- see the module docs for why.
    let (chan_out_tx, mut chan_out_rx) =
        mpsc::channel::<(u8, u64, Option<Vec<u8>>)>(CHANNEL_CAPACITY);

    // Short echo_ack flush timer -- as in `serve_shell`, but swept over every
    // open channel each tick rather than a single counter.
    let mut ack_tick = tokio::time::interval(std::time::Duration::from_millis(20));
    ack_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Register before admission checks, including the refund/select race.
        let capacity_changed = global_budget.changed();
        tokio::pin!(capacity_changed);
        capacity_changed.as_mut().enable();
        let mut control_blocked = false;
        let mut applied = 0;
        let mut consumed = 0;
        if io.retiring() {
            retiring = true;
            let discarded = control_buf.reset();
            if discarded != 0 {
                io.consumed(CONTROL_STREAM, discarded);
            }
        }
        if !unsupported_control && !retiring {
            for _ in 0..crate::channel_timeline::ORDINARY_ENTRIES {
                let raw = match control_buf.peek() {
                    Ok(Some(raw)) => raw,
                    Ok(None) => break,
                    Err(overflow) => {
                        consumed += overflow.dropped;
                        if !control_overflow_logged {
                            control_overflow_logged = true;
                            log::warn!("session control stream: a record declared a length past CONTROL_RECORD_MAX; nothing more on it is read (spec §4.16)");
                        }
                        break;
                    }
                };
                let open_refusal = match decode_client(raw) {
                    Ok(ClientRecord::Open(req)) => {
                        known_open_refusal(&channels, &opening, &req, &update, &producer)
                    }
                    _ => None,
                };
                let response_class = if matches!(decode_client(raw), Ok(ClientRecord::Open(_))) {
                    Some(match &open_refusal {
                        Some(reason) => crate::control_budget::Response::Ordinary(reason.len() + 6),
                        None => crate::control_budget::Response::Open,
                    })
                } else if update.daemon.is_some() {
                    match decode_client(raw) {
                        Ok(ClientRecord::AboutRequest) => {
                            Some(crate::control_budget::Response::Ordinary(ABOUT_RECORD_MAX))
                        }
                        Ok(ClientRecord::UpdateOffer(_))
                            if matches!(update.slot, UpdateSlot::Idle) =>
                        {
                            Some(crate::control_budget::Response::Update)
                        }
                        Ok(ClientRecord::UpdateOffer(_)) => {
                            Some(crate::control_budget::Response::Ordinary(6))
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                let (response, terminal) = if let Some(class) = response_class {
                    let reserved = if matches!(class, crate::control_budget::Response::Open) {
                        io.control_budget()
                            .reserve_open()
                            .map(|[decision, terminal]| (decision, Some(terminal)))
                    } else {
                        io.control_budget()
                            .reserve(class)
                            .map(|decision| (decision, None))
                    };
                    match reserved {
                        Ok((response, terminal)) => (Some(response), terminal),
                        Err(_) => {
                            control_blocked = true;
                            break;
                        }
                    }
                } else {
                    (None, None)
                };
                let (raw, n) = control_buf
                    .complete()
                    .expect("peek materialized one record");
                consumed += n;
                applied += 1;
                if !apply_control_record(
                    &io,
                    &mut channels,
                    &mut exits,
                    &mut next_instance,
                    &executor,
                    &mut opening,
                    raw,
                    response,
                    terminal,
                    open_refusal,
                    &mut term,
                    &mut update,
                    &producer,
                    &mut reaps,
                ) {
                    unsupported_control = true;
                    consumed += control_buf.reset();
                    for ch in channels.values_mut() {
                        ch.producer.failed = true;
                        ch.producer.deferred = None;
                    }
                    break;
                }
            }
        }
        if consumed != 0 {
            io.consumed(CONTROL_STREAM, consumed);
        }
        let more_control =
            applied == crate::channel_timeline::ORDINARY_ENTRIES && control_buf.held() != 0;
        #[cfg(test)]
        if control_blocked {
            let refund = CONTROL_REFUND_BEFORE_SELECT.with(|hook| hook.borrow_mut().take());
            if let Some(refund) = refund {
                refund();
            }
        }
        // Accept is committed before the peer can send valid image bytes.
        // Observe its ready receipt before polling inbound data, preserving
        // fairness among all the ordinary runner arms in the inner select.
        let wakeup = tokio::select! {
            biased;
            committed = acceptance_committed(&mut update.slot) => Wakeup::Acceptance(committed),
            wakeup = async {
                tokio::select! {
                    _ = std::future::ready(()), if more_control => Wakeup::ControlReady,
                    _ = &mut capacity_changed, if control_blocked => Wakeup::CapacityReady,
                    about = next_about(&mut update.about) => Wakeup::About(about),
                    ev = io.recv(), if !retiring => Wakeup::Inbound(ev),
                    c = chan_out_rx.recv() => Wakeup::ChannelOut(c),
                    _ = ack_tick.tick() => Wakeup::AckTick,
                    _ = producer.ready.notified() => Wakeup::OutputReady,
                    _ = producer.opens.notified() => Wakeup::OpenReady,
                    done = reaps.next_event(), if !reaps.is_empty() => Wakeup::Reaped(done),
                    signal = restart_signal_changed(&mut update.restart_rx) => Wakeup::Restart(signal),
                    reply = next_reply(&mut update.replies_rx) => Wakeup::Reply(reply),
                    end = join_update(&mut update.task), if update.task.is_some() => Wakeup::Update(end),
                }
            } => wakeup,
        };

        match wakeup {
            Wakeup::Inbound(Some(SessionInbound::Data(StreamData { stream_id, data }))) => {
                let n = data.len();
                if !producer.attachment.has_geometry() {
                    io.consumed(stream_id, n);
                    io.protocol_failure(producer.attachment, None);
                    break;
                }
                if unsupported_control {
                    io.consumed(stream_id, n);
                    continue;
                }
                if stream_id == CONTROL_STREAM {
                    match control_buf.push(data) {
                        Ok(dropped) => {
                            if dropped != 0 {
                                io.consumed(CONTROL_STREAM, dropped);
                            }
                        }
                        Err(data) => {
                            let dropped = data.len() + control_buf.reset();
                            io.consumed(CONTROL_STREAM, dropped);
                            unsupported_control = true;
                            io.resource_exhausted(producer.attachment);
                        }
                    }
                } else if stream_id == UPDATE_STREAM {
                    update.receive(&io, data);
                } else if let Some(ch) = channels.get_mut(&stream_id) {
                    if ch.ending {
                        // Ending channels retain output, but accept no new input.
                        io.consumed(stream_id, n);
                        continue;
                    }
                    match ch.input_budget.try_network(data) {
                        Ok(Some(chunk)) => {
                            // Echo offsets cover admitted network input only.
                            ch.input_consumed += n as u64;
                            if ch
                                .input_tx
                                .as_ref()
                                .is_none_or(|tx| tx.send(WriterInput::Network(chunk)).is_err())
                            {
                                io.consumed(stream_id, n);
                            }
                        }
                        Ok(None) => {}
                        Err(_) => {
                            // Refuse the offending chunk, stop only its exact
                            // process owner, and keep draining real output/exit.
                            io.consumed(stream_id, n);
                            begin_channel_ending(ch, &mut reaps, true);
                        }
                    }
                } else {
                    // Bytes for a stream that names no open channel -- the
                    // client's own mistake (writing before OPENED, or after
                    // the channel closed) -- are dropped, and a dropped byte
                    // is taken: its window must not shrink for good.
                    io.consumed(stream_id, n);
                }
            }
            Wakeup::Inbound(Some(SessionInbound::Live(context))) => {
                if !context.has_geometry() {
                    io.protocol_failure(context, None);
                    break;
                }
                producer.attachment = context;
                decisions_complete = true;
                // A cold attachment has no retained lifecycle inventory.
                update.retry_announcement(&io);
            }
            Wakeup::Inbound(Some(SessionInbound::ResumeReset(context))) => {
                if !context.has_geometry() {
                    io.protocol_failure(context, None);
                    break;
                }
                opening.clear(); // Drop cancels; registry custody survives until proof.
                producer.attachment = context;
                decisions_complete = true;
                // A new connection's control stream starts from its first
                // byte: nothing half-read on the old one carries over.
                let old_input = control_buf.reset();
                if old_input != 0 {
                    io.consumed(CONTROL_STREAM, old_input);
                }
                control_overflow_logged = false;
                unsupported_control = false;
                // A warm reattach is a new client connection: its echo_ack
                // accounting starts over, exactly as `serve_shell` resets its
                // own on a fresh `HandshakeInit` -- the same cue there: a new
                // client attaching. It is also a brand-new `Connection`
                // object (`BridgeControl::Attach` swaps the whole thing in),
                // and a connection's recoverability declarations are ITS OWN
                // state -- they do not travel with the swap. Every live
                // channel must say again what it said when it was opened, or
                // the new connection falls back to its default (never drop
                // the backlog) for every one of them: a channel WITH a
                // screen model would then stop getting the desync/resync
                // treatment after this reattach, and the next long absence
                // would replay its full backlog instead of a single repaint.
                reset_attachment_outputs(&io, &mut channels, &mut exits, context);
                update.retry_announcement(&io);
            }
            Wakeup::Inbound(Some(SessionInbound::RepaintCutover {
                generation,
                sequence,
            })) => {
                if generation == producer.attachment.generation {
                    io.repaint_barrier(generation, sequence);
                    repaint_all(&io, &mut channels);
                }
            }
            Wakeup::Inbound(Some(SessionInbound::Repaint)) => {
                // A hot-roam resync: the client's picture is stale, and the
                // model is what is left to fix it (see this module's own
                // docs above, "Repaint and the live-channel list").
                repaint_all(&io, &mut channels);
            }
            // A screen channel's gate opened: if it dropped output behind
            // it, the repaint goes now rather than with its next chunk, which
            // may be a long time coming (spec §4.7.2). The gate may have shut
            // again since the bridge said so; the next `Writable` then.
            Wakeup::Inbound(Some(SessionInbound::Writable { stream })) => {
                if let Some(ch) = channels.get_mut(&stream) {
                    if ch.stale && ch.gate.is_open() {
                        repaint_stale(&io, stream, ch);
                    }
                }
            }
            // An ended channel's output is delivered: its `Exit` now, unless
            // the client closed the channel (or opened the number again)
            // meanwhile.
            Wakeup::Inbound(Some(SessionInbound::Delivered {
                stream,
                token,
                generation,
            })) => {
                // An answer to an earlier channel's request on this number
                // -- one the client closed, then opened again -- is not this
                // channel's.
                if exits.get(&stream).is_some_and(|e| {
                    e.instance == token
                        && e.final_marker.token == token
                        && e.producer.origin.generation == generation
                }) {
                    exits.get_mut(&stream).expect("just found").delivered = true;
                }
            }
            Wakeup::Inbound(Some(SessionInbound::OutputReady {
                stream,
                instance,
                generation,
            })) => {
                if let Some(ch) = channels.get_mut(&stream) {
                    if ch.instance == instance.get()
                        && ch.producer.origin.generation == generation
                        && ch.producer.timeline.take_notification(instance, generation)
                    {
                        resume_producer(&io, ch);
                    }
                }
            }
            Wakeup::ControlReady => {}
            Wakeup::CapacityReady => {
                #[cfg(test)]
                CONTROL_CAPACITY_WAKES.with(|count| count.set(count.get() + 1));
            }
            Wakeup::About(result) => update.on_about(&io, result),
            Wakeup::OpenReady => {}
            Wakeup::Reaped(reaping::ReapEvent::LeaderExited(done)) => {
                if let Some(ch) = channels
                    .get_mut(&done.stream)
                    .filter(|ch| ch.instance == done.instance)
                {
                    ch.ending = true;
                    // Scope cleanup advances before workers join. Keep the
                    // writer alive for parser replies until real reader EOF.
                    reaps.retire(ch.instance);
                }
            }
            Wakeup::Reaped(reaping::ReapEvent::Complete(done)) => {
                if done.code.is_none() {
                    log::warn!(
                        "channel {}/{} reaped without an exit status",
                        done.stream,
                        done.instance
                    );
                }
                if let Some(pending) = exits
                    .get_mut(&done.stream)
                    .filter(|p| p.instance == done.instance)
                {
                    pending.code = Some(done.code);
                } else if let Some(ch) = channels
                    .get_mut(&done.stream)
                    .filter(|ch| ch.instance == done.instance)
                {
                    ch.terminal_code = Some(done.code);
                }
            }
            Wakeup::OutputReady => {
                for ch in channels.values_mut() {
                    let instance = ChannelInstance::new(ch.instance).unwrap();
                    if ch
                        .producer
                        .timeline
                        .take_notification(instance, ch.producer.origin.generation)
                    {
                        resume_producer(&io, ch);
                    }
                }
            }
            Wakeup::Inbound(None) if io.retiring() => retiring = true,
            Wakeup::Inbound(None) => break,
            Wakeup::ChannelOut(Some((stream, instance, Some(chunk)))) => {
                if let Some(ch) = channels
                    .get_mut(&stream)
                    .filter(|ch| ch.instance == instance)
                {
                    // The model sees every byte the process wrote, sent or not.
                    absorb_output(&io, ch, &chunk);
                }
                // Else: output for a channel that already closed -- nobody
                // is listening for it any more.
            }
            Wakeup::ChannelOut(Some((stream, instance, None))) => {
                if let Some(ch) = channels
                    .get_mut(&stream)
                    .filter(|ch| ch.instance == instance)
                {
                    ch.producer.eof = true;
                    if !ch.producer.reply_failed {
                        let replies = ch.screen.flush_pending_output();
                        admit_terminal_reply(&io, ch, replies);
                    }
                    if !ch.producer.reply_failed && (ch.stale || ch.screened) {
                        // The model cannot repaint once EOF moves to PendingExit.
                        repaint_stale(&io, stream, ch);
                    }
                    ch.producer.reply_delivery.seal();
                    let stop = ch.producer.reply_failed;
                    begin_channel_ending(ch, &mut reaps, stop);
                }
            }
            Wakeup::ChannelOut(None) => {
                // The loop keeps its own clone of `chan_out_tx` for its whole
                // life, so the shared channel never runs dry while the loop
                // is still running.
            }
            Wakeup::AckTick => {
                reaps.observe_active();
                #[cfg(test)]
                {
                    let fence = CONTROL_FIRST_ACK_TICK.with(|slot| slot.borrow_mut().take());
                    if let Some(fence) = fence {
                        fence.notify_one();
                    }
                }
                let now = std::time::Instant::now();
                // Flush a pending echo_ack per channel: input advanced but no
                // output happened (the program silently ate a keystroke).
                for (stream, ch) in channels.iter_mut() {
                    // Parser deadlines belong to models, independent of output
                    // gates and prediction. Admission never waits for a writer.
                    flush_due_terminal_output(&io, ch, now);
                    // Behind a closed gate, and until the repaint, the ack
                    // waits for the repaint (see repaint_stale).
                    if ch.stale || !ch.gate.is_open() {
                        continue;
                    }
                    send_echo_ack_if_moved(&io, *stream, ch);
                }
            }
            Wakeup::Restart(_observed) => {
                let signal = update.current_signal();
                if signal.phase == RestartPhase::Idle {
                    update.pending_announcement = None;
                }
                opening.retain(|_, job| {
                    let keep = signal.phase == RestartPhase::Idle
                        && job.request().identity.invalidation_epoch == signal.invalidation_epoch;
                    if !keep && job.request().identity.generation == producer.attachment.generation
                    {
                        decisions_complete = false;
                    }
                    keep
                });
                match signal.phase {
                    RestartPhase::Idle => {}
                    RestartPhase::Announced => {
                        update.announce(&io, signal.restart);
                        update.join(signal.restart);
                    }
                    RestartPhase::Draining => {
                        // A client about to lose its channels hears why first,
                        // even if the announcement itself was coalesced away.
                        update.announce(&io, signal.restart);
                        // Reaped whether or not the daemon counted this session:
                        // a process left running would become a child of the new
                        // binary. Only a counted session confirms.
                        if update.owes_reap(signal.restart) {
                            begin_reap_all(&io, &mut channels, &mut reaps);
                            draining = Some(signal.restart);
                        }
                    }
                }
            }
            Wakeup::Reply(Some(reply)) => update.on_reply(&io, reply),
            Wakeup::Reply(None) => {
                update.slot = UpdateSlot::Idle;
                if let Some(mut chain) = update.chain.take() {
                    send_reserved_answer(
                        &io,
                        chain.origin,
                        &mut chain.response,
                        UpdateAnswer::ProviderFailed,
                    );
                }
            }
            Wakeup::Acceptance(committed) => update.on_acceptance(&io, committed),
            Wakeup::Update(end) => update.on_task_end(&io, end),
        }
        if reaps.is_empty() && producer.opens.occupied() == 0 {
            if let Some(restart) = draining.take() {
                update.confirm_released(restart);
            }
        }
        decisions_complete &= complete_opens(
            &io,
            &mut channels,
            &mut opening,
            &chan_out_tx,
            &update,
            &producer,
            &mut reaps,
        );
        if retiring && opening.is_empty() {
            // This marker follows settled Open jobs, with explicit decision
            // completeness. Actual cleanup below remains independently owned.
            io.retirement_ready(producer.attachment, decisions_complete);
            break;
        }
        let mut finished = Vec::new();
        for (&stream, ch) in channels.iter_mut() {
            // Failure and pending ownership must come from ONE snapshot: a
            // late writer failure cannot slip behind the final marker. Once
            // sealed with no receipts, this instance cannot acquire new ones.
            let replies = ch.producer.reply_delivery.snapshot();
            if replies.failed {
                fail_terminal_reply(&io, ch);
            }
            if ch.producer.reply_failed {
                begin_channel_ending(ch, &mut reaps, true);
            }
            if ch.producer.eof
                && replies.sealed
                && replies.pending == 0
                && !ch.producer.checkpoint_due
                && ch.producer.queued_data.is_empty()
            {
                finished.push(stream);
            }
        }
        for stream in finished {
            let ch = channels.remove(&stream).expect("finished channel");
            let pending = finish_channel(&io, ch, &mut reaps);
            exits.insert(stream, pending);
        }
        let delivered: Vec<_> = exits
            .iter()
            .filter_map(|(&stream, p)| (p.delivered && p.code.is_some()).then_some(stream))
            .collect();
        for stream in delivered {
            let mut pending = exits.remove(&stream).expect("completed exit");
            send_pending_exit(&io, stream, &mut pending);
        }
    }

    // The manager tore the session down (`io.recv()` returned `None`), but
    // any channels still open are not: their processes must still be
    // reaped, or they leak as zombies once a real `ChannelSpawner` is wired
    // in (see the module docs). Drop each one's writer first
    // -- not because the process is guaranteed to see that ahead of the
    // `kill()` that follows (there is no synchronisation between the two),
    // but because otherwise the writer's own blocking bridge task would sit
    // in `blocking_recv()` forever with nothing left to tell it to stop --
    // then force the process down and wait for it, both blocking so both
    // run on a blocking task; every reap is awaited before this function
    // returns, so no process is left running past the runner's own
    // lifetime. Every gate is closed first, for good: a line channel's
    // reader waiting on its shut gate wakes and ends instead of waiting for
    // a bridge that is gone.
    opening.clear();
    update.slot = UpdateSlot::Idle;
    producer.input_budget.close();
    io.close_send_gates();
    chan_out_rx.close();
    begin_reap_all(&io, &mut channels, &mut reaps);
    // The transport is gone, but exact cleanup receipts and blocking reaps
    // still own this runner's drain obligation. Unknown never gets a timeout refund.
    while !reaps.is_empty() || producer.opens.occupied() != 0 {
        tokio::select! {
            _ = reaps.next(), if !reaps.is_empty() => {}
            _ = producer.opens.notified() => {}
            signal = restart_signal_changed(&mut update.restart_rx) => {
                if signal.phase == RestartPhase::Announced { update.join(signal.restart); }
            }
            _ = next_reply(&mut update.replies_rx), if update.replies_rx.is_some() => {
                update.slot = UpdateSlot::Idle;
                update.chain = None;
            }
            _ = join_update(&mut update.task), if update.task.is_some() => {
                update.chain = None;
            }
        }
    }
    // A session that ends while a restart is under way has, by now, ended
    // and reaped everything it had: that is its drain, and the daemon --
    // which may be counting on this session -- is told so rather than left
    // to wait out its whole drain timeout.
    let signal = update.current_signal();
    if signal.phase != RestartPhase::Idle {
        update.confirm_released(signal.restart);
    }
}

/// Asks every open channel's screen model to repaint, and puts any non-empty
/// answer on that channel's own stream as `REC_DATA`. A channel with no
/// screen model (`NoScreen`) always answers empty, so this doubles as the
/// "channels that asked for a screen" filter: no separate bookkeeping is
/// needed to avoid asking a line protocol like `tmux -C` to repaint, which
/// would corrupt the conversation.
fn repaint_all(io: &SessionIo, channels: &mut HashMap<u8, Channel>) {
    for ch in channels.values_mut() {
        if ch.producer.reply_failed {
            resume_producer(io, ch);
            continue;
        }
        if !checkpoint(io, ch) {
            ch.stale = ch.screened;
            continue;
        }
        if !emit_screen_repaint(io, ch) {
            continue;
        }
        ch.stale = false;
    }
}

/// Put one chunk of a channel's output on its stream (spec §4.7.2, §13).
/// A line channel's reader already waited for its gate: the chunk goes out.
/// A screen channel's reader never waits: behind a closed gate the chunk is
/// dropped whole -- a whole `REC_DATA` record, before the transport, so the
/// client's record parser never loses its place and no `Reset` is needed --
/// and the channel is stale; the first chunk after the gate reopens goes out
/// as one repaint (the model already holds it).
fn forward_output(io: &SessionIo, stream: u8, ch: &mut Channel, chunk: &[u8]) {
    if ch.producer.checkpoint_due && !ch.screened {
        // The reader already observed its gate. At most the bounded shared
        // reader queue plus one current read per channel can overshoot a hold.
        ch.producer.queued_data.push_back(chunk.to_vec());
        return;
    }
    if ch.screened {
        if !ch.gate.is_open() {
            ch.stale = true;
            return;
        }
        if ch.stale {
            repaint_stale(io, stream, ch);
            return;
        }
    }
    emit_data(io, ch, chunk);
    send_echo_ack_if_moved(io, stream, ch);
}

/// The echo ack, when input was consumed since the last one.
fn send_echo_ack_if_moved(io: &SessionIo, _stream: u8, ch: &mut Channel) {
    if ch.input_consumed != ch.last_acked {
        emit_ack(io, ch);
    }
}

/// One repaint for a stale screen channel, then the echo ack of everything
/// consumed -- unconditionally: the dropped output may have carried a
/// keystroke's echo, and the next ack would otherwise wait for the next
/// keystroke, the client's prediction hanging unconfirmed until then.
fn repaint_stale(io: &SessionIo, _stream: u8, ch: &mut Channel) {
    if ch.producer.reply_failed {
        return;
    }
    if !checkpoint(io, ch) {
        ch.stale = true;
        return;
    }
    if !emit_screen_repaint(io, ch) {
        return;
    }
    emit_ack(io, ch);
    ch.stale = false;
}

/// Apply one decoded record from [`CONTROL_STREAM`]: open, resize or close a
/// channel -- closing one also reaps its process (see the module docs). An
/// `UnknownKind` record (a newer client's own evolution) is ignored in
/// silence -- the envelope already kept the stream in sync (see
/// [`crate::shell_frame::RecordDeframer`]), so there is nothing left to resynchronise. A
/// `Malformed` one is different: it is a broken promise from a peer that
/// claims to speak this exact protocol, and every record on this stream is
/// one-shot, so losing it silently would leave whatever channel it named
/// stuck forever with no evidence why -- logged, not just dropped.
#[allow(clippy::too_many_arguments)]
fn apply_control_record(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    exits: &mut HashMap<u8, PendingExit>,
    next_instance: &mut u64,
    executor: &crate::channel_open::ChannelOpenExecutor,
    opening: &mut HashMap<u8, PendingOpen>,
    raw: RawRecord,
    response: Option<crate::control_budget::ResponsePermit>,
    terminal: Option<crate::control_budget::ResponsePermit>,
    open_refusal: Option<String>,
    term: &mut Option<String>,
    update: &mut SessionUpdate,
    context: &ProducerContext,
    reaps: &mut ReapSet,
) -> bool {
    match decode_client(&raw) {
        Ok(ClientRecord::ResizeRequest {
            stream,
            instance,
            request_id,
            cols,
            rows,
        }) => {
            if !context.attachment.has_geometry() {
                log::warn!("correlated resize received without channel-geometry support; application input stopped");
                return false;
            }
            let Some(ch) = channels.get_mut(&stream) else {
                io.protocol_failure(context.attachment, None);
                return false;
            };
            return process_resize(
                io,
                ch,
                ResizeIntent {
                    instance,
                    request_id,
                    cols,
                    rows,
                    origin: context.attachment,
                },
            );
        }
        Ok(ClientRecord::Open(req)) => {
            let terminal = terminal.map(crate::control_budget::ResponsePermit::into_owner);
            let response = response
                .expect("open effect requires response preflight")
                .into_owner();
            // A client opens a number it considers free: whatever ended on
            // it before, it is not waiting for that `Exit` any more, and it
            // must not end the new channel.
            if let Some(pending) = exits.remove(&req.stream) {
                reaps.stop(pending.instance);
                io.channel_closed(
                    req.stream,
                    pending.geometry.instance,
                    pending.producer.origin,
                );
                forget_channel_stream(io, req.stream);
            }
            if let Some(reason) = open_refusal {
                reserved_refusal(io, req.stream, reason, context.attachment, response);
            } else {
                // Numbered whether or not it opens: only uniqueness matters.
                let instance = *next_instance;
                let Some(next) = next_instance.checked_add(1) else {
                    io.protocol_failure(context.attachment, None);
                    return false;
                };
                *next_instance = next;
                open_channel_async(
                    io,
                    channels,
                    executor,
                    opening,
                    req,
                    term.as_deref(),
                    instance,
                    update,
                    context,
                    response,
                    terminal.expect("admitted open reserves future terminal"),
                )
            }
        }
        Ok(ClientRecord::Term(name)) => {
            // Kept for the channels opened after it, not applied to the ones
            // already running: a process's environment is fixed when it is
            // spawned, so telling a live channel would change nothing while
            // suggesting it had.
            *term = Some(name);
        }

        Ok(ClientRecord::Close { stream }) => {
            opening.remove(&stream);
            // An `Exit` still waiting for its channel's output is not owed
            // either: the client closed the channel first.
            if let Some(pending) = exits.remove(&stream) {
                reaps.stop(pending.instance);
                io.channel_closed(stream, pending.geometry.instance, pending.producer.origin);
                forget_channel_stream(io, stream);
            }
            // Removing the entry frees the slot for a future OPEN and drops
            // its resize/screen handles. The reader bridge task, if still
            // blocked inside the process's own I/O, is left to end on its
            // own -- this crate has no way to interrupt a blocking `Read` --
            // and anything it pushes afterwards lands on a stream no longer
            // in `channels`, so it is dropped just like data addressed to a
            // channel that was never opened. A line channel's reader waiting
            // on its gate instead is woken by the gate closing for good
            // (`forget_channel_stream`), and ends.
            //
            // The process is not left running, though: `CLOSE` means the
            // client stopped watching, not that the process already exited,
            // so a channel closed while its process is still alive gets the
            // same reap a still-open channel gets when the whole session
            // ends (see the module docs) -- drop the writer, then force the
            // process down and wait for it on a blocking task. No `Exit`
            // follows: the client already knows it closed the channel, and
            // a record after its own CLOSE would only be confusing.
            if let Some(ch) = channels.remove(&stream) {
                io.channel_closed(
                    stream,
                    ChannelInstance::new(ch.instance).unwrap(),
                    ch.producer.origin,
                );
                forget_channel_stream(io, stream);
                let Channel {
                    input_tx,
                    wait,
                    _open_slot,
                    instance,
                    ..
                } = ch;
                drop(input_tx);
                if let Some(wait) = wait {
                    reaps.start(stream, instance, wait, _open_slot, true);
                } else {
                    reaps.stop(instance);
                }
            }
        }
        Ok(ClientRecord::AboutRequest) => update.about(io, context.attachment, response),
        Ok(ClientRecord::UpdateOffer(offer)) => {
            update.offer(io, context.attachment, offer, response)
        }
        Err(ChannelCodecError::UnknownKind(_)) => {}
        Err(ChannelCodecError::Malformed)
            if matches!(raw.kind, 0x11 | crate::channel::REC_RESIZE_REQUEST) =>
        {
            if context.attachment.has_geometry() {
                io.protocol_failure(context.attachment, None);
            }
            log::warn!("malformed correlated resize; application input stopped");
            return false;
        }
        Err(ChannelCodecError::Malformed) => {
            log::warn!(
                "malformed control record from client (kind {:#04x}, {} bytes) -- \
                 whatever channel it named may now hang open forever",
                raw.kind,
                raw.payload.len()
            );
        }
    }
    true
}

/// All fallible steps precede model/request mutation. A failed ioctl drops
/// the reservation, releasing provisional storage without changing the model.
fn resize_channel(ch: &mut Channel, size: TerminalSize) -> Result<(), ResizeRefusal> {
    if (ch.request.cols, ch.request.rows) == (size.cols(), size.rows()) {
        return Ok(());
    }
    let prepared = ch.screen.prepare_resize(size).map_err(|e| match e {
        crate::shell_server::ScreenPreparationError::ResourceLimit(_) => {
            ResizeRefusal::ResourceLimit
        }
        crate::shell_server::ScreenPreparationError::PreparationFailed(_) => {
            ResizeRefusal::ScreenPreparationFailed
        }
    })?;
    ch.resize
        .try_resize(size.cols(), size.rows())
        .map_err(|_| ResizeRefusal::PtyResizeFailed)?;
    prepared.commit();
    ch.request.cols = size.cols();
    ch.request.rows = size.rows();
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn open_channel_async(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    executor: &crate::channel_open::ChannelOpenExecutor,
    opening: &mut HashMap<u8, PendingOpen>,
    req: OpenRequest,
    term: Option<&str>,
    instance: u64,
    update: &SessionUpdate,
    context: &ProducerContext,
    response: crate::control_budget::ResponseOwner,
    terminal: crate::control_budget::ResponseOwner,
) {
    let stream = req.stream;
    if opening.contains_key(&stream) {
        reserved_refusal(
            io,
            stream,
            "channel already opening".into(),
            context.attachment,
            response,
        );
        return;
    }
    let prepared = match prepare_open(io, channels, req, term, instance, context) {
        Ok(prepared) => prepared,
        Err(reason) => {
            reserved_refusal(io, stream, reason, context.attachment, response);
            return;
        }
    };
    let admitted =
        io.admit_effect(|| admit_prepared_open(prepared, update, &context.opens.registry));
    let job = match admitted {
        Err(()) => return,
        Ok(result) => match result {
            Ok(job) => job,
            Err(reason) => {
                let reason = if reason == crate::channel_open::OpenRefusal::Restarting {
                    "the daemon is restarting"
                } else {
                    "too many pending channels"
                };
                reserved_refusal(io, stream, reason.into(), context.attachment, response);
                return;
            }
        },
    };
    // Capacity and identity are charged before scheduling any blocking work.
    if executor.submit(&job).is_err() {
        job.custody()
            .refuse_before_creation("channel opening unavailable".into());
        job.cleanup(); // No backend was scheduled; this is a proved no-child transition.
        reserved_refusal(
            io,
            stream,
            "channel opening unavailable".into(),
            context.attachment,
            response,
        );
        return;
    }
    opening.insert(
        stream,
        PendingOpen {
            job,
            response,
            terminal,
        },
    );
}

fn complete_opens(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    opening: &mut HashMap<u8, PendingOpen>,
    chan_out_tx: &mpsc::Sender<(u8, u64, Option<Vec<u8>>)>,
    update: &SessionUpdate,
    context: &ProducerContext,
    reaps: &mut ReapSet,
) -> bool {
    let mut decisions_complete = true;
    // At most MAX_CHANNELS jobs can be active or unresolved in this session.
    let completed: Vec<_> = opening
        .iter()
        .filter_map(|(&stream, job)| job.take_outcome().map(|outcome| (stream, outcome)))
        .collect();
    for (stream, outcome) in completed {
        let Some(PendingOpen {
            job,
            response,
            terminal,
        }) = opening.remove(&stream)
        else {
            continue;
        };
        let request = job.request();
        let identity = request.identity;
        let req = request.request.clone();
        if identity.generation != context.attachment.generation {
            // The old attachment was deliberately superseded, not a missing
            // decision of the current attachment.
            continue;
        }
        if channels.contains_key(&stream) {
            decisions_complete = false;
            continue;
        }
        match outcome {
            crate::channel_open::OpenOutcome::Failed(reason) => {
                let current = update
                    .idle_epoch_guard()
                    .is_ok_and(|epoch| identity.invalidation_epoch == epoch.epoch());
                // The exact attachment/request was checked above. Publication
                // follows this epoch check without awaiting another loop turn.
                if current {
                    reserved_refusal(io, stream, reason, context.attachment, response);
                } else {
                    decisions_complete = false;
                }
            }
            crate::channel_open::OpenOutcome::Ready(channel) => {
                let Some(adopted) = job.try_adopt(channel) else {
                    decisions_complete = false;
                    continue;
                };
                let Some(installation) =
                    PreparedInstallation::new(channels, req, identity.instance, context)
                else {
                    let current = update
                        .idle_epoch_guard()
                        .is_ok_and(|epoch| identity.invalidation_epoch == epoch.epoch());
                    if current {
                        reserved_refusal(
                            io,
                            stream,
                            "channel preparation unavailable".into(),
                            context.attachment,
                            response,
                        );
                    } else {
                        decisions_complete = false;
                    }
                    continue;
                };
                let Ok(epoch) = update.idle_epoch_guard() else {
                    decisions_complete = false;
                    continue;
                };
                let committed = io.admit_effect(|| adopted.commit(&epoch, &identity, installation));
                // Installation is now owned by the session. Backend callbacks and
                // bridge scheduling must not hold up restart publication.
                drop(epoch);
                let committed = match committed {
                    Ok(committed) => committed,
                    Err(()) => {
                        reserved_refusal(
                            io,
                            stream,
                            "the login ended".into(),
                            context.attachment,
                            response,
                        );
                        continue;
                    }
                };
                if let Some(bridges) = committed {
                    // The response owner remains outside guarded commit so a
                    // failed installation cannot wake budget waiters under the
                    // restart watch guard. No callback runs before this move.
                    channels
                        .get_mut(&stream)
                        .expect("committed installation")
                        .producer
                        .terminal_response = Some(terminal);
                    start_installed(io, channels, chan_out_tx, bridges, context, reaps, response);
                } else {
                    decisions_complete = false;
                }
            }
        }
    }
    decisions_complete
}

struct PendingOpen {
    job: crate::channel_open::OpenJob,
    response: crate::control_budget::ResponseOwner,
    terminal: crate::control_budget::ResponseOwner,
}
impl std::ops::Deref for PendingOpen {
    type Target = crate::channel_open::OpenJob;
    fn deref(&self) -> &Self::Target {
        &self.job
    }
}

/// Classification reads runner-owned state only and launches no factory work.
fn known_open_refusal(
    channels: &HashMap<u8, Channel>,
    opening: &HashMap<u8, PendingOpen>,
    req: &OpenRequest,
    update: &SessionUpdate,
    context: &ProducerContext,
) -> Option<String> {
    let reason = if update.restarting() {
        Some("the daemon is restarting")
    } else if opening.contains_key(&req.stream) {
        Some("channel already opening")
    } else if channels.contains_key(&req.stream) {
        Some("channel already open")
    } else if channels.len() >= MAX_CHANNELS {
        Some("too many channels")
    } else if context.opens.session.is_none() {
        Some("channel opening identity exhausted")
    } else {
        None
    };
    if let Some(reason) = reason {
        return Some(reason.into());
    }
    if req.cols != 0 && req.rows != 0 {
        if let Err(reason) = TerminalSize::new(req.cols, req.rows) {
            return Some(reason.to_string());
        }
    }
    None
}

fn reserved_refusal(
    io: &SessionIo,
    stream: u8,
    reason: String,
    origin: AttachmentContext,
    mut response: crate::control_budget::ResponseOwner,
) {
    let reason = crate::channel::bounded_control_diagnostic(reason, 1);
    let bytes = crate::channel::encode_server_owned(ServerRecord::Refused { stream, reason });
    let part = response
        .take_record(bytes.len())
        .expect("reserved open refusal");
    io.send_reserved_control(origin, bytes, part);
}

/// Validation and owned request data are prepared before watching restart state.
struct PreparedOpen {
    session: Arc<crate::channel_open::SessionOpenLedger>,
    request: crate::channel_open::OpenRequestSnapshot,
}

fn prepare_open(
    io: &SessionIo,
    channels: &HashMap<u8, Channel>,
    req: OpenRequest,
    term: Option<&str>,
    instance: u64,
    context: &ProducerContext,
) -> Result<PreparedOpen, String> {
    let stream = req.stream;
    if channels.contains_key(&stream) {
        return Err("channel already open".into());
    }
    if channels.len() >= MAX_CHANNELS {
        return Err("too many channels".into());
    }
    // Either zero dimension preserves the generic no-PTY request exactly.
    if req.cols != 0 && req.rows != 0 {
        TerminalSize::new(req.cols, req.rows).map_err(|reason| reason.to_string())?;
    }
    let session = context
        .opens
        .session
        .as_ref()
        .ok_or_else(|| "channel opening identity exhausted".to_string())?
        .clone();
    let identity = crate::channel_open::OpenIdentity {
        session: session.id(),
        instance: ChannelInstance::new(instance).expect("nonzero instance"),
        stream,
        generation: context.attachment.generation,
        // Filled from the guarded current state at actual admission.
        invalidation_epoch: 0,
    };
    Ok(PreparedOpen {
        session,
        request: crate::channel_open::OpenRequestSnapshot {
            // The session's authenticated principal/login are immutable.
            owner: io.principal().clone(),
            login: io.login(),
            request: req,
            term: term.map(str::to_owned),
            identity,
        },
    })
}

fn admit_prepared_open(
    prepared: PreparedOpen,
    update: &SessionUpdate,
    registry: &Arc<crate::channel_open::ChannelOpenRegistry>,
) -> Result<crate::channel_open::OpenJob, crate::channel_open::OpenRefusal> {
    let epoch = update.idle_epoch_guard()?;
    let PreparedOpen {
        session,
        mut request,
    } = prepared;
    request.identity.invalidation_epoch = epoch.epoch();
    // Guarded admission cannot cross Announced -> Idle rollback and reuse a
    // stale epoch. No output, backend callback or scheduling occurs here.
    let admitted = registry.try_reserve(&session, request);
    drop(epoch);
    admitted
}

/// Existing direct fixtures reserve at an explicitly chosen epoch. Production
/// uses guarded admission above and publishes any refusal after it returns.
#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn reserve_open(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    req: OpenRequest,
    term: Option<&str>,
    instance: u64,
    epoch: u64,
    context: &ProducerContext,
) -> Option<crate::channel_open::OpenJob> {
    let stream = req.stream;
    let result = prepare_open(io, channels, req, term, instance, context).and_then(|prepared| {
        let PreparedOpen {
            session,
            mut request,
        } = prepared;
        request.identity.invalidation_epoch = epoch;
        context
            .opens
            .registry
            .try_reserve(&session, request)
            .map_err(|_| "too many pending channels".into())
    });
    match result {
        Ok(job) => Some(job),
        Err(reason) => {
            refuse(io, stream, reason, context.attachment);
            None
        }
    }
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn open_channel(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    spawner: &Arc<dyn ChannelSpawner>,
    chan_out_tx: &mpsc::Sender<(u8, u64, Option<Vec<u8>>)>,
    req: OpenRequest,
    term: Option<&str>,
    instance: u64,
    context: &ProducerContext,
) {
    let Some(job) = reserve_open(io, channels, req.clone(), term, instance, 0, context) else {
        return;
    };
    let stream = req.stream;
    let uninstalled = match spawner.spawn(io.principal(), io.login(), &req, term, job.custody()) {
        Ok(spawned) => spawned,
        Err(failure) => {
            // Synchronous prerequisite. Task 7 moves this work onto its admitted worker.
            job.cleanup();
            refuse(io, stream, failure.reason, context.attachment);
            return;
        }
    };
    let job_id = job.id();
    let (spawned, open_slot) = match job.adopt(uninstalled) {
        Ok(adopted) => adopted,
        Err(result) => {
            drop(result);
            context.opens.registry.cleanup(job_id);
            refuse(
                io,
                stream,
                "channel ended before installation".into(),
                context.attachment,
            );
            return;
        }
    };
    install_open(
        io,
        channels,
        chan_out_tx,
        req,
        instance,
        context,
        spawned,
        open_slot,
    );
}

/// An inert, preallocated insertion. Preparing or dropping it cannot start
/// process bridges or extract the registry's child/model custody.
pub(crate) struct PreparedInstallation<'a> {
    entry: std::collections::hash_map::VacantEntry<'a, u8, Channel>,
    producer: ProducerState,
    input_tx: mpsc::UnboundedSender<WriterInput>,
    input_budget: crate::channel_input::ChannelInputBudget,
    input_rx: mpsc::UnboundedReceiver<WriterInput>,
    gate: Arc<SendGate>,
    request: OpenRequest,
    instance: u64,
}
pub(crate) struct InstalledBridges {
    stream: u8,
    instance: u64,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    input_rx: mpsc::UnboundedReceiver<WriterInput>,
}
impl<'a> PreparedInstallation<'a> {
    fn new(
        channels: &'a mut HashMap<u8, Channel>,
        request: OpenRequest,
        instance: ChannelInstance,
        context: &ProducerContext,
    ) -> Option<Self> {
        channels.try_reserve(1).ok()?;
        let std::collections::hash_map::Entry::Vacant(entry) = channels.entry(request.stream)
        else {
            return None;
        };
        let (input_tx, input_rx) = mpsc::unbounded_channel();
        Some(Self {
            entry,
            producer: ProducerState::new(instance, context),
            input_budget: context.input_budget.channel(),
            input_tx,
            input_rx,
            // This inert gate is replaced with the bridge's shared gate before any
            // reader starts or lifecycle output is published.
            gate: Arc::new(SendGate::new(GateKind::Pipe)),
            request,
            instance: instance.get(),
        })
    }
    pub(crate) fn matches(&self, identity: &crate::channel_open::OpenIdentity) -> bool {
        self.request.stream == identity.stream
            && self.instance == identity.instance.get()
            && self.producer.origin.generation == identity.generation
    }
    /// Only concrete moves and a previously reserved vacant insertion occur here.
    /// No backend callback, allocation, task launch, I/O or publication.
    pub(crate) fn commit(
        self,
        spawned: SpawnedChannel,
        slot: crate::channel_open::InstalledSlot,
    ) -> InstalledBridges {
        let SpawnedChannel {
            reader,
            writer,
            resize,
            screen,
            wait,
        } = spawned;
        let bridges = InstalledBridges {
            stream: self.request.stream,
            instance: self.instance,
            reader,
            writer,
            input_rx: self.input_rx,
        };
        self.entry.insert(Channel {
            _open_slot: Some(slot),
            producer: self.producer,
            input_tx: Some(self.input_tx),
            input_budget: self.input_budget,
            resize,
            screen,
            input_consumed: 0,
            last_acked: 0,
            gate: self.gate,
            screened: false,
            stale: false,
            instance: self.instance,
            request: self.request,
            wait: Some(wait),
            terminal_code: None,
            ending: false,
        });
        bridges
    }
}

/// A reaped child cannot refund an installed slot while either I/O worker is
/// still running. Latching the child receipt also forbids later PID signalling.
struct IoOwnedWait {
    child: Box<dyn ChannelWait>,
    reaped: Option<Option<i32>>,
    workers: [crate::session_manager::WorkerReceipt; 2],
}
impl ChannelWait for IoOwnedWait {
    fn poll_leader_status(&mut self) -> Option<LeaderStatus> {
        if let Some(code) = self.reaped {
            Some(LeaderStatus::Exited { code })
        } else {
            self.child.poll_leader_status()
        }
    }
    fn poll_exit(&mut self) -> ChildStatus {
        if self.reaped.is_none() {
            match self.child.poll_exit() {
                ChildStatus::Reaped { code } => self.reaped = Some(code),
                status => return status,
            }
        }
        for worker in &self.workers {
            match worker.joined() {
                None => return ChildStatus::WaitingForWorkers,
                Some(Err(error)) => return ChildStatus::Unknown(error),
                Some(Ok(())) => {}
            }
        }
        ChildStatus::Reaped {
            code: self.reaped.unwrap(),
        }
    }
    fn set_reap_notifier(&mut self, notifier: ReapNotifier) {
        self.child.set_reap_notifier(notifier.clone());
        for worker in &self.workers {
            worker.set_notifier(notifier.clone());
        }
    }
    fn kill(&mut self) {
        if self.reaped.is_none() {
            self.child.kill();
        }
    }
    fn cleanup_uninstalled(
        &mut self,
        _authority: &crate::channel_open::CleanupAuthority<'_>,
    ) -> crate::channel_open::CleanupStatus {
        // This wrapper is created only after installation. A never-installed
        // cleanup authority cannot certify its running I/O workers.
        crate::channel_open::CleanupStatus::Unknown
    }
    fn wait(mut self: Box<Self>) -> i32 {
        loop {
            if let ChildStatus::Reaped { code } = self.poll_exit() {
                return code.unwrap_or(-1);
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
}

fn start_installed(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    chan_out_tx: &mpsc::Sender<(u8, u64, Option<Vec<u8>>)>,
    bridges: InstalledBridges,
    context: &ProducerContext,
    reaps: &mut ReapSet,
    response: crate::control_budget::ResponseOwner,
) {
    let ch = channels
        .get_mut(&bridges.stream)
        .expect("committed installation");
    // Custody precedes callbacks, worker scheduling and publication. On unwind
    // ReapSet transfers this exact owner to factory retirement synchronously.
    reaps.start_active(
        bridges.stream,
        bridges.instance,
        ch.wait.take().expect("installed child custody"),
        ch._open_slot.take(),
    );
    let workers = spawn_installed_workers(io, ch, chan_out_tx, bridges);
    reaps.attach_workers(ch.instance, workers);
    publish_installed(io, ch, context, response);
}

fn spawn_installed_workers(
    io: &SessionIo,
    ch: &mut Channel,
    chan_out_tx: &mpsc::Sender<(u8, u64, Option<Vec<u8>>)>,
    bridges: InstalledBridges,
) -> [crate::session_manager::WorkerReceipt; 2] {
    let InstalledBridges {
        stream,
        instance,
        reader,
        writer,
        input_rx,
    } = bridges;
    let recoverable = ch.screen.has_screen();
    ch.screened = recoverable;
    ch.gate = io.send_gate(
        stream,
        if recoverable {
            GateKind::Screen
        } else {
            GateKind::Pipe
        },
    );
    let reader_gate = (!recoverable).then(|| ch.gate.clone());
    let reader_out = chan_out_tx.clone();
    let reader = io.spawn_blocking_owned(move || {
        channel_reader_loop(stream, instance, reader, reader_out, reader_gate)
    });
    let reporter = io.consumption_reporter();
    let writer =
        io.spawn_blocking_owned(move || channel_writer_loop(stream, input_rx, writer, reporter));
    [reader, writer]
}

fn publish_installed(
    io: &SessionIo,
    ch: &mut Channel,
    context: &ProducerContext,
    mut response: crate::control_budget::ResponseOwner,
) {
    io.set_stream_resyncable(ch.request.stream, ch.screened);
    let bytes = encode_server(&ServerRecord::Opened {
        stream: ch.request.stream,
    });
    let part = response
        .take_record(bytes.len())
        .expect("one reserved Opened");
    io.send_reserved_control(context.attachment, bytes, part);
    checkpoint(io, ch);
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
fn install_open(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    chan_out_tx: &mpsc::Sender<(u8, u64, Option<Vec<u8>>)>,
    req: OpenRequest,
    instance: u64,
    context: &ProducerContext,
    spawned: SpawnedChannel,
    open_slot: crate::channel_open::InstalledSlot,
) {
    let Some(mut prepared) = PreparedInstallation::new(
        channels,
        req,
        ChannelInstance::new(instance).expect("nonzero instance"),
        context,
    ) else {
        return;
    };
    let [response, terminal] = io
        .control_budget()
        .reserve_open()
        .expect("fixture open pair");
    prepared.producer.terminal_response = Some(terminal.into_owner());
    let bridges = prepared.commit(spawned, open_slot);
    let ch = channels
        .get_mut(&bridges.stream)
        .expect("fixture installation");
    let workers = spawn_installed_workers(io, ch, chan_out_tx, bridges);
    ch.wait = Some(Box::new(IoOwnedWait {
        child: ch.wait.take().expect("fixture child custody"),
        reaped: None,
        workers,
    }));
    publish_installed(io, ch, context, response.into_owner());
}

/// Send `ServerRecord::Refused` for `stream` with `reason` on
/// [`CONTROL_STREAM`].
#[cfg(test)]
fn refuse(io: &SessionIo, stream: u8, reason: String, origin: AttachmentContext) {
    io.channel_refused(origin, stream, reason);
}

/// The blocking loop for one channel's reader: forwards chunks read from its
/// process into the shared output channel, tagged with `stream`. Mirrors
/// `shell_server`'s PTY-reading loop, generalised: many instances share one
/// destination channel instead of each getting its own, and EOF/an error is
/// reported as `None` rather than simply stopping, since here it does not
/// end the whole loop -- just this one channel. With a `gate` (a line
/// channel's) it waits for the gate before every read, and ends, reporting
/// nothing, once the gate closes for good: the channel is gone then.
fn channel_reader_loop(
    stream: u8,
    instance: u64,
    mut reader: Box<dyn Read + Send>,
    tx: mpsc::Sender<(u8, u64, Option<Vec<u8>>)>,
    gate: Option<Arc<SendGate>>,
) {
    let mut buf = vec![0u8; CHUNK_SIZE];
    loop {
        // Before the read, not after it: a chunk read and then held would
        // sit in the shared queue in front of every other channel's output.
        if let Some(g) = &gate {
            if !g.wait_open() {
                return; // the channel is gone
            }
        }
        match reader.read(&mut buf) {
            Ok(0) | Err(_) => {
                let _ = tx.blocking_send((stream, instance, None));
                return;
            }
            Ok(n) => {
                if tx
                    .blocking_send((stream, instance, Some(buf[..n].to_vec())))
                    .is_err()
                {
                    return;
                }
            }
        }
    }
}

/// The blocking loop for one channel's writer: pulls keystrokes off its own
/// input channel and writes them to its process, reporting each chunk taken
/// once written (spec §4.10.3). A process that is gone takes the rest too:
/// the loop drains its queue to the end -- until the channel goes and the
/// runner drops the sender -- so every byte the client sent is accounted
/// for, and a stream number reused later on this connection gets its whole
/// window.
fn channel_writer_loop(
    stream: u8,
    mut rx: mpsc::UnboundedReceiver<WriterInput>,
    mut writer: Box<dyn Write + Send>,
    reporter: ConsumptionReporter,
) {
    let mut broken = false;
    while let Some(input) = rx.blocking_recv() {
        let (chunk, receipt) = input.into_parts();
        if !broken && writer.write_all(chunk.bytes()).is_err() {
            broken = true;
        }
        let network_bytes = chunk.network_bytes();
        if let Some(receipt) = receipt {
            // A required reply discarded after any prior write error is also
            // failure. Settle before quota release so receipts stay bounded
            // by admitted payload ownership, even during concurrent refill.
            receipt.finish(!broken);
        }
        // Release retained payload/quota before advertising receive capacity.
        drop(chunk);
        if network_bytes != 0 {
            reporter.consumed(stream, network_bytes);
        }
    }
}

// `pub(crate)`: `session_manager`'s own tests reuse `FakeSpawner` for the R12
// reattach-and-reuse end-to-end test (the real channel runner behind the
// real bridge and ledger, not a second, hand-rolled double) -- see
// `session_manager::tests::a_channel_reused_after_a_reattach_is_credited_only_its_own_report`.
#[cfg(test)]
#[path = "channel_server_tests.rs"]
pub(crate) mod tests;
