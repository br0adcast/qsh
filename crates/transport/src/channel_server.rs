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
#[cfg(test)]
#[path = "control_input.rs"]
mod control_input;

use crate::session_manager::{ConsumptionReporter, LoginId, SessionInbound, SessionIo, StreamData};
use crate::shell_frame::{RawRecord, RecordDeframer};
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
    Reaped { code: Option<i32> },
    Unknown(String),
}

#[path = "channel_reap.rs"]
pub(crate) mod reaping;
pub use reaping::ReapNotifier;
use reaping::ReapSet;

/// Exclusive child lifecycle operations. The runner calls observation/stop on
/// blocking workers; a pending or failed observation never releases custody.
pub trait ChannelWait: Send {
    /// Nonblocking observation by the exclusive wait owner. After Unknown the
    /// owner must retain custody and must not signal a possibly reused PID.
    fn poll_exit(&mut self) -> ChildStatus;

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
    About(Option<About>),
    Offer {
        size: u64,
        decision: Result<Box<dyn UpdateTransfer>, UpdateAnswer>,
    },
}

/// How a blocking update task ended.
enum UpdateTaskEnd {
    Verified(Box<dyn UpdateTransfer>),
    Failed(UpdateResult),
}

/// Everything one session keeps about updating the daemon.
struct SessionUpdate {
    daemon: Option<Arc<dyn DaemonUpdates>>,
    restart_rx: Option<watch::Receiver<RestartSignal>>,
    replies_tx: mpsc::UnboundedSender<DaemonReply>,
    replies_rx: mpsc::UnboundedReceiver<DaemonReply>,
    slot: UpdateSlot,
    task: Option<tokio::task::JoinHandle<UpdateTaskEnd>>,
    /// The restart this session last told its client `Restarting` about.
    /// A watch channel keeps only the latest value, so a runner busy
    /// elsewhere can see `Draining` without ever having seen `Announced`, or
    /// the next attempt's `Announced` without the `Idle` between them; the
    /// number is what lets it say it exactly once per attempt.
    announced: Option<u64>,
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
        let (replies_tx, replies_rx) = mpsc::unbounded_channel();
        SessionUpdate {
            daemon,
            restart_rx,
            replies_tx,
            replies_rx,
            slot: UpdateSlot::Idle,
            task: None,
            announced: None,
            joined: None,
            reaped: None,
            released: None,
            handed: 0,
            taken: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Ask the daemon about itself off the loop; the answer comes back as a
    /// [`DaemonReply`]. Nobody behind this session: stay silent.
    fn about(&self) {
        let Some(daemon) = self.daemon.clone() else {
            return;
        };
        let replies = self.replies_tx.clone();
        tokio::task::spawn_blocking(move || {
            let _ = replies.send(DaemonReply::About(daemon.about()));
        });
    }

    fn offer(&mut self, io: &SessionIo, offer: UpdateOffer) {
        let Some(daemon) = self.daemon.clone() else {
            return;
        };
        if !matches!(self.slot, UpdateSlot::Idle) {
            send_answer(io, UpdateAnswer::InProgress);
            return;
        }
        self.slot = UpdateSlot::Deciding;
        let from = io.principal().clone();
        let replies = self.replies_tx.clone();
        tokio::task::spawn_blocking(move || {
            let decision = daemon.offer(&from, &offer);
            let _ = replies.send(DaemonReply::Offer {
                size: offer.size,
                decision,
            });
        });
    }

    fn on_reply(&mut self, io: &SessionIo, reply: DaemonReply) {
        match reply {
            DaemonReply::About(Some(about)) => {
                io.send(CONTROL_STREAM, encode_server(&ServerRecord::About(about)));
            }
            DaemonReply::About(None) => {}
            DaemonReply::Offer {
                decision: Err(refusal),
                ..
            } => {
                self.slot = UpdateSlot::Idle;
                send_answer(io, refusal);
            }
            DaemonReply::Offer {
                size,
                decision: Ok(transfer),
            } => {
                let (tx, rx) = std::sync::mpsc::channel::<Vec<u8>>();
                let stall = self
                    .daemon
                    .as_ref()
                    .map_or(TRANSFER_STALL, |d| d.stall_timeout());
                self.handed = 0;
                self.taken.store(0, Ordering::SeqCst);
                let taken = Arc::clone(&self.taken);
                let reporter = io.consumption_reporter();
                self.task = Some(tokio::task::spawn_blocking(move || {
                    receive_and_verify(rx, transfer, size, stall, &reporter, &taken)
                }));
                // An empty image is already whole: dropping `tx` here tells
                // the receiver so.
                self.slot = if size == 0 {
                    UpdateSlot::Finishing
                } else {
                    UpdateSlot::Receiving {
                        tx,
                        remaining: size,
                    }
                };
                send_answer(io, UpdateAnswer::Accept);
            }
        }
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

    /// Tell this session's client `Restarting`, once per restart.
    fn announce(&mut self, io: &SessionIo, restart: u64) {
        if self.announced != Some(restart) {
            self.announced = Some(restart);
            io.send(CONTROL_STREAM, encode_server(&ServerRecord::Restarting));
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
                send_result(io, UpdateResult::Restarting);
                self.task = Some(tokio::task::spawn_blocking(move || {
                    UpdateTaskEnd::Failed(transfer.restart())
                }));
            }
            UpdateTaskEnd::Failed(result) => {
                send_result(io, result);
                self.slot = UpdateSlot::Idle;
            }
        }
    }
}

fn send_answer(io: &SessionIo, answer: UpdateAnswer) {
    io.send(
        CONTROL_STREAM,
        encode_server(&ServerRecord::UpdateAnswer(answer)),
    );
}

fn send_result(io: &SessionIo, result: UpdateResult) {
    io.send(
        CONTROL_STREAM,
        encode_server(&ServerRecord::UpdateResult(result)),
    );
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

/// The next reply from a blocking call into the daemon. The session holds a
/// sender itself, so this never ends on its own.
async fn next_reply(rx: &mut mpsc::UnboundedReceiver<DaemonReply>) -> DaemonReply {
    match rx.recv().await {
        Some(reply) => reply,
        None => std::future::pending().await,
    }
}

/// Waits for the running update task, and clears the slot it was in.
async fn join_update(task: &mut Option<tokio::task::JoinHandle<UpdateTaskEnd>>) -> UpdateTaskEnd {
    let end = match task.as_mut() {
        Some(handle) => handle.await.unwrap_or_else(|_| {
            UpdateTaskEnd::Failed(UpdateResult::Rejected {
                code: RejectCode::Other,
                detail: "the update task failed".to_string(),
            })
        }),
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
    input_tx: mpsc::UnboundedSender<WriterInput>,
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
                    if ch
                        .input_tx
                        .send(WriterInput::LocalReply { receipt, chunk })
                        .is_ok()
                    {
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
    OutputReady,
    OpenReady,
    Reaped(reaping::Completion),
    /// The restart signal moved.
    Restart(RestartSignal),
    /// A blocking call into the daemon came back.
    Reply(DaemonReply),
    /// This session's update task ended.
    Update(UpdateTaskEnd),
}

fn reset_attachment_outputs(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    exits: &mut HashMap<u8, PendingExit>,
    context: AttachmentContext,
) {
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
    // The barrier cannot wait for producer/metadata gates. Its snapshot is
    // published in one replaceable mailbox, never copied into the output FIFO.
    io.publish_resume_snapshot(context, || {
        use crate::channel::{ActiveChannel, ChannelSnapshot, DrainingChannel, OpenClassification};
        let mut active = Vec::with_capacity(channels.len());
        let mut draining = Vec::with_capacity(exits.len() + channels.len());
        for (&stream, ch) in channels.iter() {
            let instance = ChannelInstance::new(ch.instance).expect("channel instance");
            if ch.wait.is_none() {
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
    // The new client's screens are empty until this repaints
    // them -- see this module's own docs above ("Repaint and the
    // live-channel list") for the fuller rationale.
    repaint_all(io, channels);
}

fn send_pending_exit(io: &SessionIo, stream: u8, pending: &mut PendingExit) {
    let code = pending
        .code
        .expect("child termination confirmed before Exit");
    forget_channel_stream(io, stream);
    let permit = pending.producer.exit_permit.take().expect("one final Exit");
    io.send_channel_exit(
        crate::channel::DrainingChannel {
            stream,
            instance: pending.geometry.instance,
            open: pending.open,
        },
        pending.producer.origin,
        code,
        permit,
    );
}

/// Transfer process custody exactly once, independently of output backpressure.
/// Natural EOF observes without signalling; an explicit stop also reaches a
/// process already being observed by the registered reaper.
fn begin_channel_ending(ch: &mut Channel, reaps: &mut ReapSet, stop: bool) {
    ch.input_budget.close();
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
    let mut control_buf = RecordDeframer::for_control();
    let mut control_overflow_logged = false;
    // A protocol failure stops further application input for this attachment.
    let mut unsupported_control = false;
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
        let wakeup = tokio::select! {
            ev = io.recv() => Wakeup::Inbound(ev),
            c = chan_out_rx.recv() => Wakeup::ChannelOut(c),
            _ = ack_tick.tick() => Wakeup::AckTick,
            _ = producer.ready.notified() => Wakeup::OutputReady,
            _ = producer.opens.notified() => Wakeup::OpenReady,
            done = reaps.next(), if !reaps.is_empty() => Wakeup::Reaped(done),
            signal = restart_signal_changed(&mut update.restart_rx) => Wakeup::Restart(signal),
            reply = next_reply(&mut update.replies_rx) => Wakeup::Reply(reply),
            end = join_update(&mut update.task), if update.task.is_some() => Wakeup::Update(end),
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
                    let records = control_buf.push(&data);
                    if control_buf.overflowed() && !control_overflow_logged {
                        control_overflow_logged = true;
                        log::warn!(
                            "session control stream: a record declared a length past \
                             CONTROL_RECORD_MAX; nothing more on it is read (spec §4.16)"
                        );
                    }
                    for raw in records {
                        if !apply_control_record(
                            &io,
                            &mut channels,
                            &mut exits,
                            &mut next_instance,
                            &executor,
                            &mut opening,
                            raw,
                            &mut term,
                            &mut update,
                            &producer,
                            &mut reaps,
                        ) {
                            unsupported_control = true;
                            for ch in channels.values_mut() {
                                ch.producer.failed = true;
                                ch.producer.deferred = None;
                            }
                            break;
                        }
                    }
                    // Applied, held as an unfinished record, or dropped:
                    // taken (spec §4.10.3).
                    io.consumed(CONTROL_STREAM, n);
                } else if stream_id == UPDATE_STREAM {
                    update.receive(&io, data);
                } else if let Some(ch) = channels.get_mut(&stream_id) {
                    if ch.wait.is_none() {
                        // Ending channels retain output, but accept no new input.
                        io.consumed(stream_id, n);
                        continue;
                    }
                    match ch.input_budget.try_network(data) {
                        Ok(Some(chunk)) => {
                            // Echo offsets cover admitted network input only.
                            ch.input_consumed += n as u64;
                            if ch.input_tx.send(WriterInput::Network(chunk)).is_err() {
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
                // A cold attachment has no retained lifecycle inventory.
            }
            Wakeup::Inbound(Some(SessionInbound::ResumeReset(context))) => {
                if !context.has_geometry() {
                    io.protocol_failure(context, None);
                    break;
                }
                opening.clear(); // Drop cancels; registry custody survives until proof.
                producer.attachment = context;
                // A new connection's control stream starts from its first
                // byte: nothing half-read on the old one carries over.
                control_buf = RecordDeframer::for_control();
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
            Wakeup::OpenReady => {}
            Wakeup::Reaped(done) => {
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
            Wakeup::Restart(signal) => {
                opening.retain(|_, job| {
                    signal.phase == RestartPhase::Idle
                        && job.request().identity.invalidation_epoch == signal.invalidation_epoch
                });
                match signal.phase {
                    RestartPhase::Idle => {}
                    RestartPhase::Announced => {
                        opening.clear();
                        update.announce(&io, signal.restart);
                        update.join(signal.restart);
                    }
                    RestartPhase::Draining => {
                        opening.clear();
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
            Wakeup::Reply(reply) => update.on_reply(&io, reply),
            Wakeup::Update(end) => update.on_task_end(&io, end),
        }
        if reaps.is_empty() && producer.opens.occupied() == 0 {
            if let Some(restart) = draining.take() {
                update.confirm_released(restart);
            }
        }
        complete_opens(
            &io,
            &mut channels,
            &mut opening,
            &chan_out_tx,
            &update,
            &producer,
        );
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
    producer.input_budget.close();
    io.close_send_gates();
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
            reply = next_reply(&mut update.replies_rx) => update.on_reply(&io, reply),
            end = join_update(&mut update.task), if update.task.is_some() => update.on_task_end(&io, end),
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
/// [`RecordDeframer`]), so there is nothing left to resynchronise. A
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
    opening: &mut HashMap<u8, crate::channel_open::OpenJob>,
    raw: RawRecord,
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
            if update.restarting() {
                // Its process would outlive the drain and become a child of
                // the new binary, which never waits for it.
                refuse(
                    io,
                    req.stream,
                    "the daemon is restarting".to_string(),
                    context.attachment,
                );
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
        Ok(ClientRecord::AboutRequest) => update.about(),
        Ok(ClientRecord::UpdateOffer(offer)) => update.offer(io, offer),
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
    opening: &mut HashMap<u8, crate::channel_open::OpenJob>,
    req: OpenRequest,
    term: Option<&str>,
    instance: u64,
    update: &SessionUpdate,
    context: &ProducerContext,
) {
    let stream = req.stream;
    if opening.contains_key(&stream) {
        refuse(
            io,
            stream,
            "channel already opening".into(),
            context.attachment,
        );
        return;
    }
    let prepared = match prepare_open(io, channels, req, term, instance, context) {
        Ok(prepared) => prepared,
        Err(reason) => {
            refuse(io, stream, reason, context.attachment);
            return;
        }
    };
    let job = match admit_prepared_open(prepared, update, &context.opens.registry) {
        Ok(job) => job,
        Err(reason) => {
            let reason = if reason == crate::channel_open::OpenRefusal::Restarting {
                "the daemon is restarting"
            } else {
                "too many pending channels"
            };
            refuse(io, stream, reason.into(), context.attachment);
            return;
        }
    };
    // Capacity and identity are charged before scheduling any blocking work.
    if executor.submit(&job).is_err() {
        job.custody()
            .refuse_before_creation("channel opening unavailable".into());
        job.cleanup(); // No backend was scheduled; this is a proved no-child transition.
        refuse(
            io,
            stream,
            "channel opening unavailable".into(),
            context.attachment,
        );
        return;
    }
    opening.insert(stream, job);
}

fn complete_opens(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    opening: &mut HashMap<u8, crate::channel_open::OpenJob>,
    chan_out_tx: &mpsc::Sender<(u8, u64, Option<Vec<u8>>)>,
    update: &SessionUpdate,
    context: &ProducerContext,
) {
    // At most MAX_CHANNELS jobs can be active or unresolved in this session.
    let completed: Vec<_> = opening
        .iter()
        .filter_map(|(&stream, job)| job.take_outcome().map(|outcome| (stream, outcome)))
        .collect();
    for (stream, outcome) in completed {
        let Some(job) = opening.remove(&stream) else {
            continue;
        };
        let request = job.request();
        let identity = request.identity;
        let req = request.request.clone();
        if identity.generation != context.attachment.generation || channels.contains_key(&stream) {
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
                    refuse(io, stream, reason, context.attachment);
                }
            }
            crate::channel_open::OpenOutcome::Ready(channel) => {
                let Some(adopted) = job.try_adopt(channel) else {
                    continue;
                };
                let Some(installation) =
                    PreparedInstallation::new(channels, req, identity.instance, context)
                else {
                    let current = update
                        .idle_epoch_guard()
                        .is_ok_and(|epoch| identity.invalidation_epoch == epoch.epoch());
                    if current {
                        refuse(
                            io,
                            stream,
                            "channel preparation unavailable".into(),
                            context.attachment,
                        );
                    }
                    continue;
                };
                let Ok(epoch) = update.idle_epoch_guard() else {
                    continue;
                };
                let committed = adopted.commit(&epoch, &identity, installation);
                // Installation is now owned by the session. Backend callbacks and
                // bridge scheduling must not hold up restart publication.
                drop(epoch);
                if let Some(bridges) = committed {
                    start_installed(io, channels, chan_out_tx, bridges, context);
                }
            }
        }
    }
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
            input_tx: self.input_tx,
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
        });
        bridges
    }
}

fn start_installed(
    io: &SessionIo,
    channels: &mut HashMap<u8, Channel>,
    chan_out_tx: &mpsc::Sender<(u8, u64, Option<Vec<u8>>)>,
    bridges: InstalledBridges,
    context: &ProducerContext,
) {
    let InstalledBridges {
        stream,
        instance,
        reader,
        writer,
        input_rx,
    } = bridges;
    let ch = channels.get_mut(&stream).expect("committed installation");
    // Only the actual model determines recoverability, never the requested flag.
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
    tokio::task::spawn_blocking(move || {
        channel_reader_loop(stream, instance, reader, reader_out, reader_gate)
    });
    let reporter = io.consumption_reporter();
    tokio::task::spawn_blocking(move || channel_writer_loop(stream, input_rx, writer, reporter));
    io.set_stream_resyncable(stream, recoverable);
    io.channel_opened(context.attachment, stream);
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
    let Some(prepared) = PreparedInstallation::new(
        channels,
        req,
        ChannelInstance::new(instance).expect("nonzero instance"),
        context,
    ) else {
        return;
    };
    let bridges = prepared.commit(spawned, open_slot);
    start_installed(io, channels, chan_out_tx, bridges, context);
}

/// Send `ServerRecord::Refused` for `stream` with `reason` on
/// [`CONTROL_STREAM`].
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
pub(crate) mod tests {
    include!("channel_server_open_tests.rs");
    include!("channel_server_reap_tests.rs");
    include!("channel_server_reply_tests.rs");
    include!("channel_server_reply_delivery_tests.rs");
    include!("channel_server_sync_deadline_tests.rs");
    include!("channel_server_control_bounds_tests.rs");
    use super::*;
    use crate::channel::{decode_server, encode_client, ChannelKind, ClientRecord, OpenRequest};
    use crate::channel::{
        About, DaemonMode, RejectCode, UpdateAnswer, UpdateOffer, UpdateResult, PROTOCOL_VERSION,
        UPDATE_STREAM,
    };
    use crate::send_gate::{GateKind, GateWait};
    use crate::session_manager::{SessionInbound, SessionIo, SessionOutbound, StreamData};
    use crate::shell_frame::{
        encode_record, RecordDeframer, ShellDeframer, ShellRecord, CONTROL_RECORD_MAX,
    };
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::mpsc as std_mpsc;
    use std::sync::{Arc, Mutex};
    use tokio::sync::watch;

    fn channel_context() -> AttachmentContext {
        AttachmentContext {
            features: crate::Features::CHANNEL_GEOMETRY,
            ..AttachmentContext::default()
        }
    }
    fn channel_producer() -> ProducerContext {
        ProducerContext {
            attachment: channel_context(),
            ..ProducerContext::default()
        }
    }
    fn established_checkpoint() -> ShellRecord {
        ShellRecord::Geometry(GeometryRecord {
            instance: ChannelInstance::new(1).unwrap(),
            request_id: 0,
            outcome: GeometryOutcome::Established,
            cols: 80,
            rows: 24,
        })
    }
    fn shell_record(output: ChannelOutput) -> Option<ShellRecord> {
        match output {
            ChannelOutput::Data(bytes) => Some(ShellRecord::Data(bytes)),
            ChannelOutput::EchoAck(offset, _) => Some(ShellRecord::EchoAck(offset)),
            ChannelOutput::Geometry(record, _) => Some(ShellRecord::Geometry(record)),
            ChannelOutput::OutputGap(cause, _) => Some(ShellRecord::OutputGap {
                instance: ChannelInstance::new(1).unwrap(),
                cause,
            }),
            ChannelOutput::DeliveryMarker(..) => None,
        }
    }
    fn delivery_marker(msg: &SessionOutbound) -> Option<(u8, u64, u64)> {
        match msg {
            SessionOutbound::ChannelOutput {
                stream,
                origin,
                output: ChannelOutput::DeliveryMarker(marker, _),
                ..
            } => Some((*stream, marker.token, origin.generation)),
            _ => None,
        }
    }
    type Fixture = (
        SessionIo,
        mpsc::Sender<SessionInbound>,
        mpsc::UnboundedReceiver<SessionOutbound>,
    );
    fn channel_pair() -> Fixture {
        let fixture = SessionIo::test_pair();
        fixture
            .1
            .try_send(SessionInbound::Live(channel_context()))
            .unwrap();
        fixture
    }
    fn channel_pair_for(principal: Principal, login: LoginId) -> Fixture {
        let fixture = SessionIo::test_pair_for(principal, login);
        fixture
            .1
            .try_send(SessionInbound::Live(channel_context()))
            .unwrap();
        fixture
    }
    fn channel_pair_with_gates() -> (
        SessionIo,
        mpsc::Sender<SessionInbound>,
        mpsc::UnboundedReceiver<SessionOutbound>,
        Arc<crate::send_gate::GateTable>,
    ) {
        let fixture = SessionIo::test_pair_with_gates();
        fixture
            .1
            .try_send(SessionInbound::Live(channel_context()))
            .unwrap();
        fixture
    }
    async fn next_snapshot(
        rx: &mut mpsc::UnboundedReceiver<SessionOutbound>,
        read: &impl Fn(u64) -> Option<crate::channel::ChannelSnapshot>,
    ) -> ServerRecord {
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let SessionOutbound::ResumeBarrier { generation } =
                    rx.recv().await.expect("runner alive")
                {
                    return ServerRecord::ChannelSnapshot(
                        read(generation).expect("matching snapshot mailbox"),
                    );
                }
            }
        })
        .await
        .expect("snapshot before deadline")
    }

    /// A channel's "process", standing in for a pseudo-terminal: it emits
    /// `greeting` once, then whatever the test feeds it, one read per chunk,
    /// and reports EOF when the test drops its feeder. Every `read` call is
    /// counted, so a test can tell a reader waiting on its gate from one
    /// waiting inside `read`.
    struct FakeProcess {
        greeting: Option<Vec<u8>>,
        feed: std_mpsc::Receiver<Vec<u8>>,
        reads: Arc<AtomicUsize>,
        exited: Arc<AtomicBool>,
    }

    impl Read for FakeProcess {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            if let Some(g) = self.greeting.take() {
                buf[..g.len()].copy_from_slice(&g);
                return Ok(g.len());
            }
            match self.feed.recv() {
                Ok(bytes) => {
                    buf[..bytes.len()].copy_from_slice(&bytes);
                    if bytes.is_empty() {
                        self.exited.store(true, Ordering::SeqCst);
                    }
                    Ok(bytes.len())
                }
                Err(_) => {
                    self.exited.store(true, Ordering::SeqCst);
                    Ok(0)
                }
            }
        }
    }

    /// Collects everything written towards a channel's process.
    #[derive(Clone)]
    #[allow(clippy::type_complexity)]
    struct FakeWriter {
        stream: u8,
        attempts: Arc<AtomicUsize>,
        written: Arc<Mutex<Vec<(u8, Vec<u8>)>>>,
        /// While set, a write waits -- a process that does not read.
        held: Arc<(Mutex<bool>, std::sync::Condvar)>,
        /// Once set, a write fails -- a process that is gone.
        broken: Arc<AtomicBool>,
    }

    impl Write for FakeWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            let (lock, cond) = &*self.held;
            let mut held = lock.lock().unwrap();
            while *held {
                held = cond.wait(held).unwrap();
            }
            if self.broken.load(Ordering::SeqCst) {
                return Err(std::io::Error::other("the process is gone"));
            }
            self.written
                .lock()
                .unwrap()
                .push((self.stream, buf.to_vec()));
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// Records the sizes applied to one channel.
    struct FakeResize {
        stream: u8,
        sizes: Arc<Mutex<Vec<(u8, u16, u16)>>>,
    }

    impl ResizeHandle for FakeResize {
        fn try_resize(&self, cols: u16, rows: u16) -> Result<(), String> {
            self.sizes.lock().unwrap().push((self.stream, cols, rows));
            Ok(())
        }
    }

    /// A screen model that says a fixed thing when asked to repaint, and
    /// records that it was asked. `NoScreen` would be indistinguishable from
    /// "was never asked", which is exactly the distinction one test needs.
    struct FakeScreen {
        stream: u8,
        repaints: Arc<Mutex<Vec<u8>>>,
    }

    struct FakePreparedResize;
    impl crate::shell_server::PreparedScreenResize for FakePreparedResize {
        fn commit(self: Box<Self>) {}
    }

    impl SessionScreen for FakeScreen {
        fn absorb(
            &mut self,
            _bytes: &[u8],
        ) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            Ok(Vec::new())
        }
        fn flush_pending_output(
            &mut self,
        ) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            Ok(Vec::new())
        }
        fn prepare_resize(
            &mut self,
            size: TerminalSize,
        ) -> Result<
            Box<dyn crate::shell_server::PreparedScreenResize + '_>,
            crate::shell_server::ScreenPreparationError,
        > {
            let _ = size;
            Ok(Box::new(FakePreparedResize))
        }
        fn repaint(
            &mut self,
        ) -> Result<crate::shell_server::ScreenRepaint, crate::shell_server::ScreenReplyError>
        {
            self.repaints.lock().unwrap().push(self.stream);
            Ok(crate::shell_server::ScreenRepaint {
                bytes: b"REPAINT".to_vec(),
                replies: Vec::new(),
            })
        }
    }

    /// Records that its process was force-killed and/or waited on, tagged by
    /// stream -- `kill` distinguishes "asked to stop" from "asked for its
    /// code", the same two calls a real `portable_pty::Child` needs (see the
    /// module docs on why neither may be skipped).
    struct FakeWait {
        stream: u8,
        code: i32,
        killed: Arc<Mutex<Vec<u8>>>,
        waited: Arc<Mutex<Vec<u8>>>,
        wait_hold: Arc<(Mutex<bool>, std::sync::Condvar)>,
        exited: Arc<AtomicBool>,
        observed: bool,
    }

    impl ChannelWait for FakeWait {
        fn poll_exit(&mut self) -> ChildStatus {
            let mut observed = self.waited.lock().unwrap();
            if !self.observed {
                observed.push(self.stream);
                self.observed = true;
            }
            if *self.wait_hold.0.lock().unwrap() || !self.exited.load(Ordering::SeqCst) {
                ChildStatus::Running
            } else {
                ChildStatus::Reaped {
                    code: Some(self.code),
                }
            }
        }
        fn cleanup_uninstalled(
            &mut self,
            authority: &crate::channel_open::CleanupAuthority<'_>,
        ) -> crate::channel_open::CleanupStatus {
            self.kill();
            self.waited.lock().unwrap().push(self.stream);
            authority.reaped()
        }
        fn kill(&mut self) {
            self.killed.lock().unwrap().push(self.stream);
            self.exited.store(true, Ordering::SeqCst);
        }

        fn wait(self: Box<Self>) -> i32 {
            self.waited.lock().unwrap().push(self.stream);
            let (lock, changed) = &*self.wait_hold;
            let mut held = lock.lock().unwrap();
            while *held {
                held = changed.wait(held).unwrap();
            }
            self.code
        }
    }

    /// Everything the tests need to steer and observe the spawner.
    #[allow(clippy::type_complexity)]
    pub(crate) struct FakeSpawner {
        opens: Arc<crate::channel_open::ChannelOpenRegistry>,
        write_attempts: Arc<AtomicUsize>,
        /// When set, every `spawn` refuses with this reason.
        refuse: Mutex<Option<String>>,
        written: Arc<Mutex<Vec<(u8, Vec<u8>)>>>,
        pub(crate) sizes: Arc<Mutex<Vec<(u8, u16, u16)>>>,
        repaints: Arc<Mutex<Vec<u8>>>,
        /// One sender per opened channel: it feeds the channel's process
        /// output ([`FakeSpawner::feed`]), and dropping it ends the process,
        /// which is how a test makes a channel exit on cue.
        enders: Mutex<Vec<(u8, std_mpsc::Sender<Vec<u8>>)>>,
        /// Every `read` call of every channel's process, together: the gate
        /// tests open one line channel and watch its reader.
        reads: Arc<AtomicUsize>,
        exit_code: i32,
        /// Streams whose `ChannelWait::kill`/`wait` was called, in call
        /// order -- how a test checks that a channel still running when the
        /// session ends was reaped rather than leaked.
        killed: Arc<Mutex<Vec<u8>>>,
        waited: Arc<Mutex<Vec<u8>>>,
        /// Stands in for a spawner with no emulator to build a real screen
        /// model from: when set, every spawned channel gets `NoScreen`, no
        /// matter what `req.screen` asked for.
        force_no_screen: Mutex<bool>,
        reply_queries: AtomicBool,
        /// The terminal type each spawn was handed, per channel, in spawn
        /// order.
        terms: Arc<Mutex<Vec<(u8, Option<String>)>>>,
        /// The owner each spawn was handed, per channel, in spawn order.
        owners: Arc<Mutex<Vec<(u8, Principal)>>>,
        /// The login each spawn was handed, in spawn order.
        logins: Mutex<Vec<LoginId>>,
        /// Shared with every `FakeWriter` this spawner hands out: see
        /// [`FakeSpawner::hold_writes`].
        held: Arc<(Mutex<bool>, std::sync::Condvar)>,
        wait_hold: Arc<(Mutex<bool>, std::sync::Condvar)>,
        /// Shared with every `FakeWriter` this spawner hands out: see
        /// [`FakeSpawner::break_writes`].
        broken: Arc<AtomicBool>,
    }

    impl FakeSpawner {
        pub(crate) fn new() -> Arc<FakeSpawner> {
            Arc::new(FakeSpawner {
                opens: crate::channel_open::ChannelOpenRegistry::new(Default::default()),
                write_attempts: Arc::new(AtomicUsize::new(0)),
                refuse: Mutex::new(None),
                written: Arc::new(Mutex::new(Vec::new())),
                sizes: Arc::new(Mutex::new(Vec::new())),
                repaints: Arc::new(Mutex::new(Vec::new())),
                enders: Mutex::new(Vec::new()),
                reads: Arc::new(AtomicUsize::new(0)),
                exit_code: 0,
                killed: Arc::new(Mutex::new(Vec::new())),
                waited: Arc::new(Mutex::new(Vec::new())),
                force_no_screen: Mutex::new(false),
                reply_queries: AtomicBool::new(false),
                terms: Arc::new(Mutex::new(Vec::new())),
                owners: Arc::new(Mutex::new(Vec::new())),
                logins: Mutex::new(Vec::new()),
                held: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
                wait_hold: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
                broken: Arc::new(AtomicBool::new(false)),
            })
        }

        /// Every channel's process stops reading its input (`true`) or
        /// reads again.
        pub(crate) fn hold_writes(&self, hold: bool) {
            let (lock, cond) = &*self.held;
            *lock.lock().unwrap() = hold;
            cond.notify_all();
        }

        /// Every channel's process is gone: writes fail.
        pub(crate) fn break_writes(&self) {
            self.broken.store(true, Ordering::SeqCst);
            self.hold_writes(false);
        }

        /// Ends the process behind `stream`, so its reader reports EOF.
        pub(crate) fn end_channel(&self, stream: u8) {
            self.enders.lock().unwrap().retain(|(s, _)| *s != stream);
        }

        /// Whether the reader of the process behind `stream` has let go of it
        /// -- its reader loop ended. Probes with an empty chunk, which a
        /// reader still alive would take as EOF: only for a test's end.
        fn process_released(&self, stream: u8) -> bool {
            let enders = self.enders.lock().unwrap();
            let (_, tx) = enders
                .iter()
                .find(|(s, _)| *s == stream)
                .expect("a channel that was opened");
            tx.send(Vec::new()).is_err()
        }

        /// Has the process behind `stream` write `bytes`.
        fn feed(&self, stream: u8, bytes: &[u8]) {
            let enders = self.enders.lock().unwrap();
            let (_, tx) = enders
                .iter()
                .find(|(s, _)| *s == stream)
                .expect("an open channel");
            tx.send(bytes.to_vec()).expect("the process is running");
        }
    }

    impl ChannelSpawner for FakeSpawner {
        fn open_registry(&self) -> Arc<crate::channel_open::ChannelOpenRegistry> {
            self.opens.clone()
        }
        fn spawn(
            &self,
            owner: &Principal,
            login: LoginId,
            req: &OpenRequest,
            term: Option<&str>,
            custody: &crate::channel_open::OpenCustody,
        ) -> Result<crate::channel_open::UninstalledChannel, crate::channel_open::SpawnFailure>
        {
            self.owners
                .lock()
                .unwrap()
                .push((req.stream, owner.clone()));
            self.logins.lock().unwrap().push(login);
            self.terms
                .lock()
                .unwrap()
                .push((req.stream, term.map(str::to_string)));
            if let Some(reason) = self.refuse.lock().unwrap().clone() {
                return Err(custody.refuse_before_creation(reason));
            }
            let (end_tx, end_rx) = std_mpsc::channel::<Vec<u8>>();
            self.enders.lock().unwrap().push((req.stream, end_tx));
            let exited = Arc::new(AtomicBool::new(false));
            let spawned = SpawnedChannel {
                reader: Box::new(FakeProcess {
                    greeting: Some(b"hello from the shell".to_vec()),
                    feed: end_rx,
                    reads: self.reads.clone(),
                    exited: exited.clone(),
                }),
                writer: Box::new(FakeWriter {
                    stream: req.stream,
                    attempts: self.write_attempts.clone(),
                    written: self.written.clone(),
                    held: self.held.clone(),
                    broken: self.broken.clone(),
                }),
                resize: Box::new(FakeResize {
                    stream: req.stream,
                    sizes: self.sizes.clone(),
                }),
                screen: if req.screen && self.reply_queries.load(Ordering::SeqCst) {
                    Box::new(terminal_replies::QueryScreen::default())
                } else if req.screen && !*self.force_no_screen.lock().unwrap() {
                    Box::new(FakeScreen {
                        stream: req.stream,
                        repaints: self.repaints.clone(),
                    })
                } else {
                    Box::new(crate::shell_server::NoScreen)
                },
                wait: Box::new(FakeWait {
                    stream: req.stream,
                    code: self.exit_code,
                    killed: self.killed.clone(),
                    waited: self.waited.clone(),
                    wait_hold: self.wait_hold.clone(),
                    exited,
                    observed: false,
                }),
            };
            Ok(custody.protect(spawned.wait, spawned.screen).finish(
                spawned.reader,
                spawned.writer,
                spawned.resize,
            ))
        }
    }

    fn open(stream: u8, kind: ChannelKind, screen: bool) -> SessionInbound {
        SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: encode_client(&ClientRecord::Open(OpenRequest {
                stream,
                kind,
                cols: 80,
                rows: 24,
                screen,
                command: if kind == ChannelKind::Shell {
                    Vec::new()
                } else {
                    b"tmux -C attach".to_vec()
                },
            })),
        })
    }

    /// Drains outbound stream data until a control record arrives, and
    /// returns it. Ignores recoverability declarations -- these tests check
    /// them separately (see `collect_declarations`). Fails the test rather
    /// than hanging if the runner goes quiet: a missing answer must read as
    /// a failure, not a stuck suite.
    async fn next_control(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
    ) -> ServerRecord {
        let mut d = RecordDeframer::new();
        loop {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("the runner must answer within five seconds")
                .expect("the runner must not drop its outbound channel");
            let msg = match msg {
                SessionOutbound::ChannelExit { stream, code, .. } => {
                    return match code {
                        Some(code) => ServerRecord::Exit { stream, code },
                        None => ServerRecord::ExitStatusUnavailable { stream },
                    }
                }
                SessionOutbound::ChannelOpened { stream, .. } => {
                    return ServerRecord::Opened { stream }
                }
                SessionOutbound::ChannelRefused { stream, reason, .. } => {
                    return ServerRecord::Refused { stream, reason }
                }
                other => other,
            };
            let SessionOutbound::Data(sd) = msg else {
                continue;
            };
            if sd.stream_id != CONTROL_STREAM {
                continue;
            }
            if let Some(raw) = d.push(&sd.data).into_iter().next() {
                return decode_server(&raw).expect("a well-formed server record");
            }
        }
    }

    /// Opens a shell channel on stream 16 and waits for the server to
    /// confirm it. `spawn` runs synchronously, in the same loop iteration
    /// that queues `Opened` for the client, so seeing `Opened` here is proof
    /// that whatever `spawn` did (recording a login, say) already happened
    /// -- a test can rely on that ordering instead of sleeping.
    async fn open_a_shell_channel(
        inbound: &tokio::sync::mpsc::Sender<SessionInbound>,
        outbound: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
    ) {
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(outbound).await,
            ServerRecord::Opened { stream: 16 },
            "the channel must open before this helper returns"
        );
    }

    /// Sum the `Consumed` reports on the runner's outbound queue, by stream,
    /// until `stream` has `want` or `within` passes; everything else read is
    /// dropped.
    async fn consumed_within(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        stream: u8,
        want: usize,
        within: std::time::Duration,
    ) -> BTreeMap<u8, usize> {
        let mut sums = BTreeMap::new();
        let deadline = tokio::time::Instant::now() + within;
        while sums.get(&stream).copied().unwrap_or(0) < want {
            let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await else {
                break;
            };
            if let SessionOutbound::Consumed { stream_id, n } = msg {
                *sums.entry(stream_id).or_insert(0) += n;
            }
        }
        sums
    }

    /// A report is a synchronous send on an in-process unbounded channel,
    /// made from inside the handling of one record (a control record
    /// applied, a chunk written, a chunk dropped) -- no I/O, no other task's
    /// scheduling to wait on. A duplicate of a report that already reached
    /// `want` is therefore already queued immediately behind it by the time
    /// `want` is seen, not merely "eventually" -- so a settle window many
    /// times an in-process `mpsc` hand-off (microseconds) is enough to
    /// catch it, without making the passing case slow.
    const REPORT_SETTLE: std::time::Duration = std::time::Duration::from_millis(100);

    /// [`consumed_within`] five seconds -- long enough for a report that is
    /// due -- and then, review Important 2: keeps draining for
    /// [`REPORT_SETTLE`] more, folding whatever else arrives into the same
    /// sums. `consumed_within` alone stops the instant `stream` reaches
    /// `want`, so a report that duplicates one already counted (queued
    /// right behind it, see `REPORT_SETTLE`'s own doc) is left unread in the
    /// channel and never seen: every caller here asserts an EXACT total, so
    /// that duplicate must be caught, not merely tolerated by stopping
    /// early.
    async fn consumed_until(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        stream: u8,
        want: usize,
    ) -> BTreeMap<u8, usize> {
        let mut sums = consumed_within(rx, stream, want, std::time::Duration::from_secs(5)).await;
        let deadline = tokio::time::Instant::now() + REPORT_SETTLE;
        while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            if let SessionOutbound::Consumed { stream_id, n } = msg {
                *sums.entry(stream_id).or_insert(0) += n;
            }
        }
        sums
    }

    /// Review Minor 1: releases a spawner's held writers no matter how the
    /// scope holding them ends. Without this, a failing assertion made
    /// while `hold_writes(true)` is still in effect panics with the
    /// writer's blocking thread still parked on the condvar; dropping the
    /// tokio runtime then waits for every blocking thread, and the suite
    /// hangs instead of reporting the failure. `hold_writes(false)` is
    /// idempotent, so an explicit release earlier in the test (needed for
    /// the rest of it to proceed) makes this guard's own drop a harmless
    /// no-op.
    struct ReleaseHeldWrites(Arc<FakeSpawner>);

    impl Drop for ReleaseHeldWrites {
        fn drop(&mut self) {
            self.0.hold_writes(false);
        }
    }

    // These tests observe the actual producer transaction and owned outbound
    // records. No bridge passthrough or remote delivery guarantee is assumed.
    struct ResizeRig {
        io: SessionIo,
        _inbound: mpsc::Sender<SessionInbound>,
        outbound: mpsc::UnboundedReceiver<SessionOutbound>,
        channel: Channel,
        geometry: Arc<Mutex<(u16, u16)>>,
        pending: Arc<AtomicUsize>,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    impl ResizeRig {
        fn new(prepare_fails: bool, ioctl_fails: bool) -> Self {
            let (io, inbound, outbound) = channel_pair();
            let geometry = Arc::new(Mutex::new((80, 24)));
            let pending = Arc::new(AtomicUsize::new(0));
            let events = Arc::new(Mutex::new(vec![]));
            let (input_tx, _) = mpsc::unbounded_channel();
            let producer = ProducerContext {
                attachment: AttachmentContext {
                    generation: 1,
                    session_id: 11,
                    features: crate::Features::CHANNEL_GEOMETRY,
                },
                ..channel_producer()
            };
            let channel = Channel {
                _open_slot: None,
                input_budget: producer.input_budget.channel(),
                input_tx,
                resize: Box::new(TransactionPty {
                    fail: ioctl_fails,
                    events: events.clone(),
                }),
                screen: Box::new(TransactionScreen {
                    geometry: geometry.clone(),
                    pending: pending.clone(),
                    fail: prepare_fails,
                    events: events.clone(),
                }),
                input_consumed: 0,
                last_acked: 0,
                gate: Arc::new(SendGate::new(GateKind::Pipe)),
                screened: false,
                stale: false,
                instance: 1,
                request: OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 80,
                    rows: 24,
                    screen: false,
                    command: vec![],
                },
                wait: Some(Box::new(FakeWait {
                    stream: 16,
                    code: 0,
                    killed: Arc::default(),
                    waited: Arc::default(),
                    wait_hold: Arc::new((Mutex::new(false), std::sync::Condvar::new())),
                    exited: Arc::new(AtomicBool::new(true)),
                    observed: false,
                })),
                terminal_code: None,
                producer: ProducerState::new(ChannelInstance::new(1).unwrap(), &producer),
            };
            Self {
                io,
                _inbound: inbound,
                outbound,
                channel,
                geometry,
                pending,
                events,
            }
        }
        fn intent(&self, id: u64, cols: u16, rows: u16) -> ResizeIntent {
            ResizeIntent {
                instance: ChannelInstance::new(1).unwrap(),
                request_id: ResizeRequestId::new(id).unwrap(),
                cols,
                rows,
                origin: self.channel.producer.origin,
            }
        }
        fn resize(&mut self, id: u64, cols: u16, rows: u16) -> bool {
            let request = self.intent(id, cols, rows);
            process_resize(&self.io, &mut self.channel, request)
        }
        fn next_geometry(&mut self) -> GeometryRecord {
            match self.outbound.try_recv().expect("one correlated outcome") {
                SessionOutbound::ChannelOutput {
                    stream: 16,
                    instance,
                    origin,
                    output: ChannelOutput::Geometry(record, _),
                    ..
                } => {
                    assert_eq!(instance.get(), 1);
                    assert_eq!(origin.generation, 1);
                    record
                }
                _ => panic!("resize returns geometry, never OPEN refusal or Exit"),
            }
        }
        fn assert_geometry(&self, cols: u16, rows: u16) {
            assert_eq!(*self.geometry.lock().unwrap(), (cols, rows));
            assert_eq!(
                (self.channel.request.cols, self.channel.request.rows),
                (cols, rows)
            );
            assert_eq!(self.pending.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn resize_refusal_preserves_all_geometry() {
        let mut rig = ResizeRig::new(true, false);
        assert!(rig.resize(1, 100, 30));
        rig.assert_geometry(80, 24);
        assert_eq!(*rig.events.lock().unwrap(), vec!["prepare"]);
        assert_eq!(
            rig.next_geometry().outcome,
            GeometryOutcome::Refused(ResizeRefusal::ResourceLimit)
        );
    }
    #[test]
    fn resize_ioctl_failure_releases_preparation() {
        let mut rig = ResizeRig::new(false, true);
        assert!(rig.resize(1, 100, 30));
        rig.assert_geometry(80, 24);
        assert_eq!(*rig.events.lock().unwrap(), vec!["prepare", "ioctl"]);
        assert_eq!(
            rig.next_geometry().outcome,
            GeometryOutcome::Refused(ResizeRefusal::PtyResizeFailed)
        );
    }
    #[test]
    fn resize_success_orders_geometry_before_data() {
        let mut rig = ResizeRig::new(false, false);
        forward_output(&rig.io, 16, &mut rig.channel, b"old");
        assert!(rig.resize(1, 100, 30));
        forward_output(&rig.io, 16, &mut rig.channel, b"new");
        rig.assert_geometry(100, 30);
        assert_eq!(
            *rig.events.lock().unwrap(),
            vec!["prepare", "ioctl", "commit"]
        );
        assert!(
            matches!(rig.outbound.try_recv().unwrap(),SessionOutbound::ChannelOutput { output:ChannelOutput::Data(ref b), .. } if b==b"old")
        );
        let record = rig.next_geometry();
        assert_eq!((record.request_id, record.cols, record.rows), (1, 100, 30));
        assert_eq!(record.outcome, GeometryOutcome::Applied);
        assert!(
            matches!(rig.outbound.try_recv().unwrap(),SessionOutbound::ChannelOutput { output:ChannelOutput::Data(ref b), .. } if b==b"new")
        );
    }
    #[test]
    fn resize_outcome_reserved_before_effect() {
        let mut rig = ResizeRig::new(false, false);
        let held = rig
            .channel
            .producer
            .timeline
            .try_reserve(EntryClass::Ordinary, 8192)
            .unwrap();
        assert!(rig.resize(1, 100, 30));
        assert!(rig.events.lock().unwrap().is_empty());
        rig.assert_geometry(80, 24);
        assert!(rig.outbound.try_recv().is_err());
        drop(held);
        resume_producer(&rig.io, &mut rig.channel);
        rig.assert_geometry(100, 30);
        assert_eq!(rig.next_geometry().outcome, GeometryOutcome::Applied);
    }
    #[test]
    fn one_deferred_resize_waits_without_failure() {
        let mut rig = ResizeRig::new(false, false);
        let held = rig
            .channel
            .producer
            .timeline
            .try_reserve(EntryClass::Ordinary, 8192)
            .unwrap();
        assert!(rig.resize(1, 100, 30));
        assert!(rig.channel.producer.deferred.is_some());
        assert!(!rig.channel.gate.is_open());
        assert!(!rig.channel.producer.failed);
        drop(held);
        assert!(rig
            .channel
            .producer
            .timeline
            .take_notification(ChannelInstance::new(1).unwrap(), 1));
        resume_producer(&rig.io, &mut rig.channel);
        assert!(rig.channel.producer.deferred.is_none());
        assert!(rig.channel.gate.is_open());
        assert_eq!(rig.next_geometry().outcome, GeometryOutcome::Applied);
    }
    #[test]
    fn second_distinct_deferred_resize_fails_once() {
        let mut rig = ResizeRig::new(false, false);
        let _held = rig
            .channel
            .producer
            .timeline
            .try_reserve(EntryClass::Ordinary, 8192)
            .unwrap();
        assert!(rig.resize(1, 100, 30));
        assert!(!rig.resize(2, 101, 31));
        assert!(!rig.resize(3, 102, 32));
        assert!(rig.events.lock().unwrap().is_empty());
        assert!(matches!(
            rig.outbound.try_recv().unwrap(),
            SessionOutbound::ProtocolFailure {
                code: Some(ProtocolErrorCode::ResizePipelineOverflow),
                ..
            }
        ));
        assert!(rig.outbound.try_recv().is_err());
    }
    #[test]
    fn duplicate_deferred_resize_allocates_nothing() {
        let mut rig = ResizeRig::new(false, false);
        let _held = rig
            .channel
            .producer
            .timeline
            .try_reserve(EntryClass::Ordinary, 8192)
            .unwrap();
        assert!(rig.resize(1, 100, 30));
        let allocated = crate::conn::tests::allocation_probe::measure(|| {
            for _ in 0..1000 {
                assert!(rig.resize(1, 100, 30));
            }
        });
        assert_eq!(allocated, 0);
        assert!(rig.outbound.try_recv().is_err());
        assert!(rig.events.lock().unwrap().is_empty());
        assert_eq!(
            rig.channel.producer.timeline.usage(EntryClass::Ordinary),
            (1, 8192)
        );
    }
    #[test]
    fn reset_cancels_unexecuted_deferred_resize() {
        let mut rig = ResizeRig::new(false, false);
        let held = rig
            .channel
            .producer
            .timeline
            .try_reserve(EntryClass::Ordinary, 8192)
            .unwrap();
        assert!(rig.resize(1, 100, 30));
        let origin = AttachmentContext {
            generation: 2,
            session_id: 12,
            ..rig.channel.producer.origin
        };
        reset_producer(&mut rig.channel, origin);
        drop(held);
        resume_producer(&rig.io, &mut rig.channel);
        assert!(rig.channel.producer.deferred.is_none());
        assert!(rig.events.lock().unwrap().is_empty());
        rig.assert_geometry(80, 24);
        assert!(!rig
            .channel
            .producer
            .timeline
            .take_notification(ChannelInstance::new(1).unwrap(), 1));
    }
    #[test]
    fn first_checkpoint_transfers_single_gap_reserve_with_shared_budget() {
        let mut rig = ResizeRig::new(false, false);
        assert!(checkpoint(&rig.io, &mut rig.channel));
        let first = rig.outbound.try_recv().unwrap();
        let shared = match &first {
            SessionOutbound::ChannelOutput {
                gap_reserve: Some(gap),
                ..
            } => gap.budget(),
            _ => panic!("first checkpoint must transfer its reserved gap slot"),
        };
        assert!(checkpoint(&rig.io, &mut rig.channel));
        let second = rig.outbound.try_recv().unwrap();
        assert!(matches!(
            &second,
            SessionOutbound::ChannelOutput {
                gap_reserve: None,
                ..
            }
        ));
        assert_eq!(shared.usage(EntryClass::Lifecycle), (6, 151));
        drop(first); // cancellation releases exactly checkpoint + gap
        assert_eq!(shared.usage(EntryClass::Lifecycle), (4, 83));
        drop(second);
        assert_eq!(shared.usage(EntryClass::Lifecycle), (3, 56));
    }

    #[tokio::test]
    async fn typed_exit_keeps_reservation_until_bridge_handoff_or_drop() {
        let rig = ResizeRig::new(false, false);
        let timeline = rig.channel.producer.timeline.clone();
        let mut outbound = rig.outbound;
        let mut reaps = ReapSet::default();
        let mut pending = finish_channel(&rig.io, rig.channel, &mut reaps);
        pending.code = Some(reaps.next().await.code);
        let _marker = outbound.try_recv().unwrap();
        send_pending_exit(&rig.io, 16, &mut pending);
        assert!(matches!(
            outbound.try_recv().unwrap(),
            SessionOutbound::StreamClass {
                stream_id: 16,
                class: StreamClass::Interactive
            }
        ));
        let exit = outbound.try_recv().unwrap();
        assert!(
            matches!(&exit,SessionOutbound::ChannelExit {stream:16,instance,origin,code:Some(0),..} if instance.get()==1 && origin.generation==1)
        );
        assert_eq!(timeline.usage(EntryClass::Lifecycle), (4, 97));
        drop(exit);
        assert_eq!(timeline.usage(EntryClass::Lifecycle), (3, 87));
    }

    #[test]
    fn lifecycle_inventory_keeps_gap_and_final_state_reserved() {
        let rig = ResizeRig::new(false, false);
        let budget = &rig.channel.producer.timeline;
        // Marker 32, Exit 10, gap/bootstrap 41, terminal failure 14 stay reserved.
        assert_eq!(budget.usage(EntryClass::Lifecycle), (4, 97));
        let mut checkpoints = Vec::new();
        for _ in 0..4 {
            checkpoints.push(budget.try_reserve(EntryClass::Lifecycle, 27).unwrap());
        }
        assert!(budget.try_reserve(EntryClass::Lifecycle, 27).is_none());
        assert_eq!(budget.usage(EntryClass::Lifecycle), (8, 205));
        assert_eq!(std::mem::size_of::<DeliveryMarker>(), 8);
        assert!(std::mem::size_of::<DeliveryMarker>() <= DELIVERY_MARKER_BYTES);
        // Entry count bounds retained wrappers separately from wire-byte costs.
        assert!(std::mem::size_of::<ChannelOutput>() <= 64);
        assert!(std::mem::size_of::<crate::session_manager::OutputCharge>() <= 24);
        assert!(std::mem::size_of::<SessionOutbound>() <= 160);
    }

    #[tokio::test]
    async fn stage6_activation_runner_refuses_open_before_geometry_profile() {
        for live in [false, true] {
            let spawner = FakeSpawner::new();
            let (io, inbound, mut outbound) = SessionIo::test_pair();
            let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
            if live {
                inbound
                    .send(SessionInbound::Live(AttachmentContext::default()))
                    .await
                    .unwrap();
            }
            let _ = inbound.send(open(16, ChannelKind::Shell, false)).await;
            let reply = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                loop {
                    let msg = outbound.recv().await;
                    if matches!(msg, Some(SessionOutbound::Consumed { .. })) {
                        continue;
                    }
                    break msg;
                }
            })
            .await;
            drop(inbound);
            runner.await.unwrap();
            spawner.end_channel(16);
            assert!(
                spawner.owners.lock().unwrap().is_empty(),
                "missing profile must never spawn"
            );
            assert!(
                matches!(reply, Ok(Some(SessionOutbound::ProtocolFailure { .. }))),
                "explicit scoped failure"
            );
        }
    }

    #[tokio::test]
    async fn eof_retains_typed_marker_and_gate_until_delivery() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let gate = io.send_gate(16, GateKind::Pipe);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(SessionInbound::Live(AttachmentContext {
                generation: 1,
                session_id: 11,
                features: crate::Features::CHANNEL_GEOMETRY,
            }))
            .await
            .unwrap();
        open_a_shell_channel(&inbound, &mut outbound).await;
        spawner.end_channel(16);
        let marker = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                match outbound.recv().await.unwrap() {
                    SessionOutbound::ChannelOutput {
                        output: ChannelOutput::DeliveryMarker(marker, _),
                        ..
                    } => break Some(marker),
                    SessionOutbound::NotifyDelivered { .. } => break None,
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        let open_before_delivery = gate.is_open();
        if let Some(marker) = marker {
            inbound
                .send(SessionInbound::Delivered {
                    stream: 16,
                    token: marker.token,
                    generation: 1,
                })
                .await
                .unwrap();
        }
        drop(inbound);
        runner.await.unwrap();
        assert!(marker.is_some(), "EOF needs a typed final-position marker");
        assert!(open_before_delivery, "PendingExit must retain the gate");
    }
    #[test]
    fn correlated_same_size_resize_applies_without_preparation_or_repaint() {
        let mut rig = ResizeRig::new(false, false);
        assert!(rig.resize(1, 80, 24));
        assert!(rig.events.lock().unwrap().is_empty());
        assert_eq!(rig.next_geometry().outcome, GeometryOutcome::Applied);
        assert!(rig.outbound.try_recv().is_err());
    }

    #[test]
    fn resize_rejects_bad_identity_and_replays_exact_duplicate_without_effect() {
        let mut rig = ResizeRig::new(false, false);
        assert!(rig.resize(1, 100, 30));
        let _ = rig.next_geometry();
        assert!(rig.resize(1, 100, 30));
        assert!(rig.outbound.try_recv().is_err());
        assert_eq!(
            *rig.events.lock().unwrap(),
            vec!["prepare", "ioctl", "commit"]
        );
        assert!(!rig.resize(1, 101, 30));
        assert!(matches!(
            rig.outbound.try_recv().unwrap(),
            SessionOutbound::ProtocolFailure { code: None, .. }
        ));
        for (instance, id) in [(2, 1), (1, 2)] {
            let mut rig = ResizeRig::new(false, false);
            let request = ResizeIntent {
                instance: ChannelInstance::new(instance).unwrap(),
                ..rig.intent(id, 100, 30)
            };
            assert!(!process_resize(&rig.io, &mut rig.channel, request));
            rig.assert_geometry(80, 24);
            assert!(rig.events.lock().unwrap().is_empty());
        }
    }
    #[test]
    fn invalid_size_and_no_pty_use_reserved_refusals() {
        for no_pty in [false, true] {
            let mut rig = ResizeRig::new(false, false);
            if no_pty {
                rig.channel.request.cols = 0;
            }
            assert!(rig.resize(1, 0, 30));
            assert!(rig.events.lock().unwrap().is_empty());
            let geometry = rig.next_geometry();
            assert_eq!(
                geometry.outcome,
                GeometryOutcome::Refused(if no_pty {
                    ResizeRefusal::NoPty
                } else {
                    ResizeRefusal::InvalidSize
                })
            );
            assert_eq!(geometry.cols, if no_pty { 0 } else { 80 });
        }
    }
    #[test]
    fn no_screen_checkpoint_after_data_uses_ordinary_capacity() {
        let mut rig = ResizeRig::new(false, false);
        forward_output(&rig.io, 16, &mut rig.channel, b"before");
        let _data = rig.outbound.try_recv().unwrap();
        let lifecycle = rig.channel.producer.timeline.usage(EntryClass::Lifecycle);
        assert!(checkpoint(&rig.io, &mut rig.channel));
        assert_eq!(
            rig.channel.producer.timeline.usage(EntryClass::Ordinary),
            (1, 27)
        );
        assert_eq!(
            rig.channel.producer.timeline.usage(EntryClass::Lifecycle),
            lifecycle
        );
    }
    #[test]
    fn lifecycle_saturation_holds_bounded_data_until_capacity_wakes() {
        let mut rig = ResizeRig::new(false, false);
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                rig.channel
                    .producer
                    .timeline
                    .try_reserve(EntryClass::Lifecycle, 27)
                    .unwrap(),
            );
        }
        assert!(!checkpoint(&rig.io, &mut rig.channel));
        forward_output(&rig.io, 16, &mut rig.channel, b"held");
        assert!(!rig.channel.gate.is_open());
        assert!(rig.outbound.try_recv().is_err());
        drop(held.pop());
        assert!(rig
            .channel
            .producer
            .timeline
            .take_notification(ChannelInstance::new(1).unwrap(), 1));
        resume_producer(&rig.io, &mut rig.channel);
        assert_eq!(rig.next_geometry().outcome, GeometryOutcome::Established);
        assert!(
            matches!(rig.outbound.try_recv().unwrap(),SessionOutbound::ChannelOutput{output:ChannelOutput::Data(ref bytes),..} if bytes==b"held")
        );
        assert!(rig.channel.producer.queued_data.is_empty());
    }
    #[test]
    fn repaint_capacity_wake_preserves_data_first_order() {
        assert_repaint_capacity_wake_order(false);
    }
    #[test]
    fn repaint_capacity_wake_preserves_resize_first_order() {
        assert_repaint_capacity_wake_order(true);
    }
    fn assert_repaint_capacity_wake_order(resize_first: bool) {
        let mut rig = ResizeRig::new(false, false);
        let mut held = Vec::new();
        for _ in 0..4 {
            held.push(
                rig.channel
                    .producer
                    .timeline
                    .try_reserve(EntryClass::Lifecycle, GEOMETRY_BYTES)
                    .unwrap(),
            );
        }
        assert!(!checkpoint(&rig.io, &mut rig.channel));
        forward_output(&rig.io, 16, &mut rig.channel, b"older");
        drop(held.pop());
        let mut channels = HashMap::from([(16, rig.channel)]);
        // Repaint wins the runner select before the pending OutputReady wake.
        repaint_all(&rig.io, &mut channels);
        let ch = channels.get_mut(&16).unwrap();
        if !resize_first {
            forward_output(&rig.io, 16, ch, b"newer");
        }
        let request = ResizeIntent {
            instance: ChannelInstance::new(ch.instance).unwrap(),
            origin: ch.producer.origin,
            request_id: ResizeRequestId::new(1).unwrap(),
            cols: 100,
            rows: 30,
        };
        assert!(process_resize(&rig.io, ch, request));
        if resize_first {
            forward_output(&rig.io, 16, ch, b"newer");
        }
        // The delayed wake must not replay those bytes under changed geometry.
        resume_producer(&rig.io, ch);
        let mut owned = Vec::new();
        while let Ok(message) = rig.outbound.try_recv() {
            owned.push(message);
        }
        let data: Vec<_> = owned
            .iter()
            .filter_map(|message| match message {
                SessionOutbound::ChannelOutput {
                    output: ChannelOutput::Data(bytes),
                    ..
                } => Some(bytes.as_slice()),
                _ => None,
            })
            .collect();
        assert_eq!(data, vec![b"older".as_slice(), b"newer".as_slice()]);
        assert!(matches!(
            &owned[0],
            SessionOutbound::ChannelOutput {
                output: ChannelOutput::Geometry(_, _),
                ..
            }
        ));
        assert!(matches!(
            &owned[if resize_first { 2 } else { 3 }],
            SessionOutbound::ChannelOutput {
                output: ChannelOutput::Geometry(
                    GeometryRecord {
                        outcome: GeometryOutcome::Applied,
                        cols: 100,
                        rows: 30,
                        ..
                    },
                    _
                ),
                ..
            }
        ));
        assert_eq!(owned.len(), 4);
        assert!(ch.producer.queued_data.is_empty());
        assert_eq!(ch.producer.timeline.usage(EntryClass::Lifecycle), (8, 205));
        // Both DATA charges remain owned after the queue entries are drained.
        ch.gate.update(crate::send_gate::PIPE_HIGH);
        ch.gate.update(crate::send_gate::PIPE_LOW);
        assert!(!ch.gate.is_open());
    }
    #[test]
    fn screen_resize_outputs_checkpoint_then_authoritative_repaint() {
        let mut rig = ResizeRig::new(false, false);
        rig.channel.screened = true;
        rig.channel.screen = Box::new(FakeScreen {
            stream: 16,
            repaints: Arc::default(),
        });
        assert!(rig.resize(1, 100, 30));
        assert_eq!(rig.next_geometry().outcome, GeometryOutcome::Applied);
        assert!(
            matches!(rig.outbound.try_recv().unwrap(),SessionOutbound::ChannelOutput{output:ChannelOutput::Data(ref bytes),..} if bytes==b"REPAINT")
        );
        assert!(matches!(
            rig.outbound.try_recv().unwrap(),
            SessionOutbound::ChannelOutput {
                output: ChannelOutput::EchoAck(0, _),
                ..
            }
        ));
    }
    #[tokio::test]
    async fn coalesced_resize_records_each_admit_before_effect_and_fail_once() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(SessionInbound::Live(AttachmentContext {
                generation: 1,
                session_id: 11,
                features: crate::Features::CHANNEL_GEOMETRY,
            }))
            .await
            .unwrap();
        open_a_shell_channel(&inbound, &mut outbound).await;
        let mut bytes = Vec::new();
        for id in 1..=135 {
            bytes.extend(encode_client(&ClientRecord::ResizeRequest {
                stream: 16,
                instance: ChannelInstance::new(1).unwrap(),
                request_id: ResizeRequestId::new(id).unwrap(),
                cols: 80 + id as u16,
                rows: 24,
            }));
        }
        let n = bytes.len();
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: bytes,
            }))
            .await
            .unwrap();
        let mut owned = Vec::new();
        let mut failures = 0;
        let mut outcomes = 0;
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            loop {
                let message=outbound.recv().await.unwrap();
                let finished=matches!(&message,SessionOutbound::Consumed{stream_id:CONTROL_STREAM,n:bytes} if *bytes==n);
                match &message {
                    SessionOutbound::ProtocolFailure{code:Some(ProtocolErrorCode::ResizePipelineOverflow),..}=>failures+=1,
                    SessionOutbound::ChannelOutput{output:ChannelOutput::Geometry(g,_),..} if g.request_id>0=>outcomes+=1,
                    _=>{}
                }
                owned.push(message); // keep permits while the entire batch runs
                if finished {break;}
            }
        }).await.unwrap();
        drop(inbound);
        spawner.end_channel(16);
        runner.await.unwrap();
        assert_eq!(outcomes, 128);
        assert_eq!(failures, 1);
        assert_eq!(spawner.sizes.lock().unwrap().len(), 128);
    }
    #[tokio::test]
    async fn geometry_screen_eof_owns_final_snapshot_before_marker() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(SessionInbound::Live(AttachmentContext {
                generation: 0,
                session_id: 11,
                features: crate::Features::CHANNEL_GEOMETRY,
            }))
            .await
            .unwrap();
        let open = encode_client(&ClientRecord::Open(OpenRequest {
            stream: 16,
            kind: crate::channel::ChannelKind::Shell,
            cols: 80,
            rows: 24,
            screen: true,
            command: Vec::new(),
        }));
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: open,
            }))
            .await
            .unwrap();
        while !matches!(outbound.recv().await.unwrap(),SessionOutbound::ChannelOutput {output:ChannelOutput::Data(ref bytes),..} if bytes==b"hello from the shell")
        {
        }
        spawner.end_channel(16);
        let seen = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut seen = Vec::new();
            loop {
                if let SessionOutbound::ChannelOutput { output, .. } =
                    outbound.recv().await.unwrap()
                {
                    match output {
                        ChannelOutput::Geometry(..) => seen.push("geometry"),
                        ChannelOutput::Data(data) => {
                            assert_eq!(data, b"REPAINT");
                            seen.push("snapshot");
                        }
                        ChannelOutput::EchoAck(..) => seen.push("ack"),
                        ChannelOutput::OutputGap(..) => panic!("unexpected terminal failure"),
                        ChannelOutput::DeliveryMarker(..) => {
                            seen.push("marker");
                            break seen;
                        }
                    }
                }
            }
        })
        .await
        .unwrap();
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(seen, vec!["geometry", "snapshot", "ack", "marker"]);
    }
    #[tokio::test]
    async fn complete_old_resize_precedes_resume_reset() {
        assert_correlated_resize_reset_order(false).await;
    }
    #[tokio::test]
    async fn partial_old_resize_never_crosses_reset() {
        assert_correlated_resize_reset_order(true).await;
    }
    async fn assert_correlated_resize_reset_order(partial: bool) {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        let old = AttachmentContext {
            generation: 1,
            session_id: 11,
            features: crate::Features::CHANNEL_GEOMETRY,
        };
        inbound.send(SessionInbound::Live(old)).await.unwrap();
        open_a_shell_channel(&inbound, &mut outbound).await;
        let request = |cols| {
            encode_client(&ClientRecord::ResizeRequest {
                stream: 16,
                instance: ChannelInstance::new(1).unwrap(),
                request_id: ResizeRequestId::new(1).unwrap(),
                cols,
                rows: 30,
            })
        };
        let mut bytes = request(100);
        if partial {
            bytes.truncate(bytes.len() - 1);
        }
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: bytes,
            }))
            .await
            .unwrap();
        inbound
            .send(SessionInbound::ResumeReset(AttachmentContext {
                generation: 2,
                session_id: 12,
                ..old
            }))
            .await
            .unwrap();
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: request(120),
            }))
            .await
            .unwrap();
        let seen = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut seen = Vec::new();
            loop {
                match outbound.recv().await.unwrap() {
                    SessionOutbound::ResumeBarrier { generation } => seen.push((generation, 0, 0)),
                    SessionOutbound::ChannelOutput {
                        origin,
                        output: ChannelOutput::Geometry(g, _),
                        ..
                    } => {
                        if g.request_id > 0 {
                            seen.push((origin.generation, g.request_id, g.cols));
                        }
                        if origin.generation == 2 && g.request_id == 1 {
                            break seen;
                        }
                    }
                    SessionOutbound::ProtocolFailure { .. } => {
                        panic!("reset must start fresh framing and request scope")
                    }
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        drop(inbound);
        spawner.end_channel(16);
        runner.await.unwrap();
        if partial {
            assert_eq!(seen, vec![(2, 0, 0), (2, 1, 120)]);
            assert_eq!(*spawner.sizes.lock().unwrap(), vec![(16, 120, 30)]);
        } else {
            assert_eq!(seen, vec![(1, 1, 100), (2, 0, 0), (2, 1, 120)]);
            assert_eq!(
                *spawner.sizes.lock().unwrap(),
                vec![(16, 100, 30), (16, 120, 30)]
            );
        }
    }
    #[test]
    fn reset_flushes_already_read_bytes_in_old_scope_before_barrier() {
        let mut rig = ResizeRig::new(false, false);
        assert!(checkpoint(&rig.io, &mut rig.channel));
        let initial = rig.outbound.try_recv().unwrap();
        let ordinary = rig
            .channel
            .producer
            .timeline
            .try_reserve(EntryClass::Ordinary, 8192)
            .unwrap();
        let mut held = Vec::new();
        for _ in 0..3 {
            held.push(
                rig.channel
                    .producer
                    .timeline
                    .try_reserve(EntryClass::Lifecycle, 27)
                    .unwrap(),
            );
        }
        assert!(!checkpoint(&rig.io, &mut rig.channel));
        forward_output(&rig.io, 16, &mut rig.channel, b"old read");
        let origin = AttachmentContext {
            generation: 2,
            session_id: 12,
            ..rig.channel.producer.origin
        };
        let mut channels = HashMap::from([(16, rig.channel)]);
        reset_attachment_outputs(&rig.io, &mut channels, &mut HashMap::new(), origin);
        let gate = channels[&16].gate.clone();
        let mut visible = vec![(1, b"geometry".to_vec())];
        let mut owned = vec![initial];
        while let Ok(message) = rig.outbound.try_recv() {
            match &message {
                SessionOutbound::ChannelOutput {
                    origin,
                    output: ChannelOutput::Data(bytes),
                    ..
                } => visible.push((origin.generation, bytes.clone())),
                SessionOutbound::ResumeBarrier { generation } => {
                    visible.push((*generation, b"barrier".to_vec()))
                }
                SessionOutbound::ChannelOutput {
                    output: ChannelOutput::Geometry(..),
                    ..
                } => panic!("new boundary is still capacity blocked"),
                _ => {}
            }
            owned.push(message);
        }
        assert_eq!(
            visible,
            vec![
                (1, b"geometry".to_vec()),
                (1, b"old read".to_vec()),
                (2, b"barrier".to_vec())
            ]
        );
        assert!(channels[&16].producer.queued_data.is_empty());
        assert_eq!(
            channels[&16].producer.timeline.usage(EntryClass::Lifecycle),
            (8, 205)
        );
        assert_eq!(
            channels[&16].producer.timeline.usage(EntryClass::Ordinary),
            (1, 8192)
        );
        gate.update(crate::send_gate::PIPE_HIGH);
        gate.update(crate::send_gate::PIPE_LOW);
        gate.set_metadata_blocked(false);
        assert!(
            !gate.is_open(),
            "queued DATA and geometry still own framed pending bytes"
        );
        drop(owned);
        assert!(
            gate.is_open(),
            "dropping owned output releases the pending charge exactly once"
        );
        assert_eq!(
            channels[&16].producer.timeline.usage(EntryClass::Lifecycle),
            (6, 137)
        );
        drop(ordinary);
    }
    // Transactions are observed independently of the implementation: a pending
    // resource and a model frame stay unchanged when either admission or PTY fails.
    struct TransactionScreen {
        geometry: Arc<Mutex<(u16, u16)>>,
        pending: Arc<AtomicUsize>,
        fail: bool,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    struct TransactionResize<'a> {
        screen: &'a mut TransactionScreen,
        size: TerminalSize,
    }
    impl Drop for TransactionResize<'_> {
        fn drop(&mut self) {
            self.screen.pending.fetch_sub(1, Ordering::SeqCst);
        }
    }
    impl crate::shell_server::PreparedScreenResize for TransactionResize<'_> {
        fn commit(self: Box<Self>) {
            self.screen.events.lock().unwrap().push("commit");
            *self.screen.geometry.lock().unwrap() = (self.size.cols(), self.size.rows());
        }
    }
    impl SessionScreen for TransactionScreen {
        fn absorb(
            &mut self,
            _bytes: &[u8],
        ) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            Ok(Vec::new())
        }
        fn flush_pending_output(
            &mut self,
        ) -> Result<Vec<u8>, crate::shell_server::ScreenReplyError> {
            Ok(Vec::new())
        }
        fn repaint(
            &mut self,
        ) -> Result<crate::shell_server::ScreenRepaint, crate::shell_server::ScreenReplyError>
        {
            Ok(crate::shell_server::ScreenRepaint {
                bytes: Vec::new(),
                replies: Vec::new(),
            })
        }
        fn prepare_resize(
            &mut self,
            size: TerminalSize,
        ) -> Result<
            Box<dyn crate::shell_server::PreparedScreenResize + '_>,
            crate::shell_server::ScreenPreparationError,
        > {
            self.events.lock().unwrap().push("prepare");
            if self.fail {
                return Err(crate::shell_server::ScreenPreparationError::ResourceLimit(
                    "budget refused".into(),
                ));
            }
            self.pending.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(TransactionResize { screen: self, size }))
        }
    }
    struct TransactionPty {
        fail: bool,
        events: Arc<Mutex<Vec<&'static str>>>,
    }
    impl ResizeHandle for TransactionPty {
        fn try_resize(&self, _cols: u16, _rows: u16) -> Result<(), String> {
            self.events.lock().unwrap().push("ioctl");
            if self.fail {
                Err("ioctl failed".into())
            } else {
                Ok(())
            }
        }
    }

    #[tokio::test]
    async fn same_size_resize_has_no_ioctl() {
        let spawner = FakeSpawner::new();
        let dyn_spawner: Arc<dyn ChannelSpawner> = spawner.clone();
        let (io, _inbound, _outbound) = channel_pair();
        let (tx, _rx) = mpsc::channel(8);
        let mut channels = HashMap::new();
        open_channel(
            &io,
            &mut channels,
            &dyn_spawner,
            &tx,
            OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols: 80,
                rows: 24,
                screen: false,
                command: vec![],
            },
            None,
            1,
            &channel_producer(),
        );
        let result = resize_channel(
            channels.get_mut(&16).unwrap(),
            TerminalSize::new(80, 24).unwrap(),
        );
        spawner.end_channel(16);
        drop(channels);
        assert!(result.is_ok());
        assert!(
            spawner.sizes.lock().unwrap().is_empty(),
            "equal geometry must not invoke ioctl"
        );
    }

    #[tokio::test]
    async fn resize_transaction_commits_only_after_successful_ioctl() {
        for (fail_prepare, fail_ioctl, want) in [
            (true, false, vec!["prepare"]),
            (false, true, vec!["prepare", "ioctl"]),
            (false, false, vec!["prepare", "ioctl", "commit"]),
        ] {
            let spawner = FakeSpawner::new();
            let dyn_spawner: Arc<dyn ChannelSpawner> = spawner.clone();
            let (io, _inbound, _outbound) = channel_pair();
            let (tx, _rx) = mpsc::channel(8);
            let mut channels = HashMap::new();
            open_channel(
                &io,
                &mut channels,
                &dyn_spawner,
                &tx,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols: 2,
                    rows: 1,
                    screen: false,
                    command: vec![],
                },
                None,
                1,
                &channel_producer(),
            );
            let geometry = Arc::new(Mutex::new((2, 1)));
            let pending = Arc::new(AtomicUsize::new(0));
            let events = Arc::new(Mutex::new(vec![]));
            let ch = channels.get_mut(&16).unwrap();
            ch.screen = Box::new(TransactionScreen {
                geometry: geometry.clone(),
                pending: pending.clone(),
                fail: fail_prepare,
                events: events.clone(),
            });
            ch.resize = Box::new(TransactionPty {
                fail: fail_ioctl,
                events: events.clone(),
            });
            let result = resize_channel(ch, TerminalSize::new(2, 2).unwrap());
            assert_eq!(result.is_ok(), !fail_prepare && !fail_ioctl);
            assert_eq!(*events.lock().unwrap(), want);
            assert_eq!(
                pending.load(Ordering::SeqCst),
                0,
                "cancel or commit returns scratch"
            );
            let expected = if result.is_ok() { (2, 2) } else { (2, 1) };
            assert_eq!(*geometry.lock().unwrap(), expected);
            assert_eq!(
                (ch.request.cols, ch.request.rows),
                expected,
                "lifecycle metadata must report committed geometry"
            );
            spawner.end_channel(16);
            drop(channels);
        }
    }

    #[tokio::test]
    async fn zero_open_keeps_generic_no_pty_fields_and_resize_cannot_change_mode() {
        for (cols, rows) in [(0, 0), (0, 700), (900, 0)] {
            let spawner = FakeSpawner::new();
            let dyn_spawner: Arc<dyn ChannelSpawner> = spawner.clone();
            let (io, _inbound, _outbound) = channel_pair();
            let (tx, _rx) = mpsc::channel(8);
            let mut channels = HashMap::new();
            let request = OpenRequest {
                stream: 16,
                kind: ChannelKind::Shell,
                cols,
                rows,
                screen: false,
                command: vec![],
            };
            open_channel(
                &io,
                &mut channels,
                &dyn_spawner,
                &tx,
                request.clone(),
                None,
                1,
                &channel_producer(),
            );
            assert_eq!(channels[&16].request, request);
            let raw = crate::shell_frame::RecordDeframer::for_control().push(&encode_client(
                &ClientRecord::ResizeRequest {
                    instance: ChannelInstance::new(1).unwrap(),
                    request_id: ResizeRequestId::new(1).unwrap(),
                    stream: 16,
                    cols: 2,
                    rows: 1,
                },
            ));
            for record in raw {
                apply_control_record(
                    &io,
                    &mut channels,
                    &mut HashMap::new(),
                    &mut 2,
                    &crate::channel_open::ChannelOpenExecutor::new(
                        dyn_spawner.clone(),
                        dyn_spawner.open_registry(),
                    ),
                    &mut HashMap::new(),
                    record,
                    &mut None,
                    &mut SessionUpdate::new(None),
                    &channel_producer(),
                    &mut ReapSet::default(),
                );
            }
            assert_eq!(channels[&16].request, request);
            assert!(spawner.sizes.lock().unwrap().is_empty());
            spawner.end_channel(16);
            drop(channels);
        }
    }

    #[tokio::test]
    async fn invalid_resize_never_reaches_model_or_pty() {
        let spawner = FakeSpawner::new();
        let dyn_spawner: Arc<dyn ChannelSpawner> = spawner.clone();
        let (io, _inbound, _outbound) = channel_pair();
        let (tx, _rx) = mpsc::channel(8);
        let mut channels = HashMap::new();
        let request = OpenRequest {
            stream: 16,
            kind: ChannelKind::Shell,
            cols: 2,
            rows: 1,
            screen: true,
            command: vec![],
        };
        open_channel(
            &io,
            &mut channels,
            &dyn_spawner,
            &tx,
            request.clone(),
            None,
            1,
            &channel_producer(),
        );
        let events = Arc::new(Mutex::new(vec![]));
        channels.get_mut(&16).unwrap().screen = Box::new(TransactionScreen {
            geometry: Arc::new(Mutex::new((2, 1))),
            pending: Arc::new(AtomicUsize::new(0)),
            fail: false,
            events: events.clone(),
        });
        for (index, (cols, rows)) in [(0, 1), (2, 0), (1, 1), (513, 1), (2, 257)]
            .into_iter()
            .enumerate()
        {
            for record in
                RecordDeframer::for_control().push(&encode_client(&ClientRecord::ResizeRequest {
                    instance: ChannelInstance::new(1).unwrap(),
                    request_id: ResizeRequestId::new(index as u64 + 1).unwrap(),
                    stream: 16,
                    cols,
                    rows,
                }))
            {
                apply_control_record(
                    &io,
                    &mut channels,
                    &mut HashMap::new(),
                    &mut 2,
                    &crate::channel_open::ChannelOpenExecutor::new(
                        dyn_spawner.clone(),
                        dyn_spawner.open_registry(),
                    ),
                    &mut HashMap::new(),
                    record,
                    &mut None,
                    &mut SessionUpdate::new(None),
                    &channel_producer(),
                    &mut ReapSet::default(),
                );
            }
        }
        assert_eq!(channels[&16].request, request);
        assert!(spawner.sizes.lock().unwrap().is_empty());
        assert!(events.lock().unwrap().is_empty());
        spawner.end_channel(16);
        drop(channels);
    }

    #[tokio::test]
    async fn invalid_nonzero_open_never_calls_spawner() {
        let spawner = FakeSpawner::new();
        *spawner.refuse.lock().unwrap() = Some("spy must not run".into());
        let (io, _inbound, _outbound) = channel_pair();
        let (tx, _rx) = mpsc::channel(1);
        let dyn_spawner: Arc<dyn ChannelSpawner> = spawner.clone();
        for (cols, rows) in [(1, 1), (513, 1), (2, 257), (u16::MAX, u16::MAX)] {
            open_channel(
                &io,
                &mut HashMap::new(),
                &dyn_spawner,
                &tx,
                OpenRequest {
                    stream: 16,
                    kind: ChannelKind::Shell,
                    cols,
                    rows,
                    screen: true,
                    command: vec![],
                },
                None,
                1,
                &channel_producer(),
            );
        }
        assert!(
            spawner.owners.lock().unwrap().is_empty(),
            "validate before invoking a spawner"
        );
    }

    #[tokio::test]
    async fn retired_or_malformed_resize_stops_suffix_until_attachment_reset() {
        for (kind, payload) in [
            (0x11, vec![16, 0, 80, 0, 24]),
            (0x11, vec![]),
            (0x16, vec![]),
        ] {
            let spawner = FakeSpawner::new();
            let (io, inbound, mut outbound) = channel_pair();
            let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
            let SessionInbound::Data(prefix) = open(16, ChannelKind::Shell, false) else {
                unreachable!()
            };
            let SessionInbound::Data(suffix) = open(17, ChannelKind::Shell, false) else {
                unreachable!()
            };
            let bytes = [
                prefix.data,
                crate::shell_frame::encode_record(kind, &payload),
                suffix.data,
            ]
            .concat();
            let n = bytes.len();
            inbound
                .send(SessionInbound::Data(StreamData {
                    stream_id: CONTROL_STREAM,
                    data: bytes,
                }))
                .await
                .unwrap();
            consumed_until(&mut outbound, CONTROL_STREAM, n).await;
            let before_reset = spawner
                .owners
                .lock()
                .unwrap()
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            inbound
                .send(SessionInbound::ResumeReset(channel_context()))
                .await
                .unwrap();
            let event = open(18, ChannelKind::Shell, false);
            let SessionInbound::Data(ref data) = event else {
                unreachable!()
            };
            let n = data.data.len();
            inbound.send(event).await.unwrap();
            consumed_until(&mut outbound, CONTROL_STREAM, n).await;
            let after_reset = spawner
                .owners
                .lock()
                .unwrap()
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>();
            for stream in [16, 17, 18] {
                spawner.end_channel(stream);
            }
            drop(inbound);
            runner.await.unwrap();
            assert_eq!(
                before_reset,
                vec![16],
                "no application input after retired/malformed resize"
            );
            assert_eq!(after_reset, vec![16, 18]);
            assert!(spawner.sizes.lock().unwrap().is_empty());
        }
    }

    /// Spec §4.10.3: a control record is taken once applied.
    #[tokio::test]
    async fn control_records_are_taken_once_applied() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        let record = open(16, ChannelKind::Shell, false);
        let SessionInbound::Data(ref sd) = record else {
            unreachable!("an OPEN is control-stream data")
        };
        let len = sd.data.len();
        inbound.send(record).await.unwrap();
        assert_eq!(
            consumed_until(&mut outbound, CONTROL_STREAM, len)
                .await
                .get(&CONTROL_STREAM),
            Some(&len)
        );
        drop(inbound);
        let _ = runner.await;
    }

    /// Spec §4.16 (QSH-06): a control record declaring more than the control
    /// limit stops the control stream -- nothing after it is applied -- and
    /// every byte of it is still reported taken (spec §4.10.3).
    #[tokio::test]
    async fn a_control_record_past_the_limit_is_dropped_whole_and_reported() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        let payload_len = CONTROL_RECORD_MAX + 1;
        // An unknown record kind -- not 0x10 (OPEN): zeros under OPEN could
        // parse as an Open of stream 0 and draw a Refused, which would
        // muddy what this test is checking.
        let mut lie = vec![0xffu8];
        lie.extend_from_slice(&u32::try_from(payload_len).unwrap().to_be_bytes());
        lie.extend(vec![0u8; payload_len]);
        let n = lie.len();
        let mid = n / 2;
        let (first, second) = lie.split_at(mid);
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: first.to_vec(),
            }))
            .await
            .unwrap();
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: second.to_vec(),
            }))
            .await
            .unwrap();
        assert_eq!(
            consumed_until(&mut outbound, CONTROL_STREAM, n)
                .await
                .get(&CONTROL_STREAM),
            Some(&n),
            "every byte of the lie, across both chunks, is reported taken"
        );
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(500),
                next_control(&mut outbound)
            )
            .await
            .is_err(),
            "nothing after the lie is applied"
        );
        drop(inbound);
        let _ = runner.await;
    }

    /// A warm reattach is a new connection whose control stream starts
    /// afresh: a record the old connection cut short must not splice onto
    /// the new one's first bytes (decision 7, pre-existing).
    #[tokio::test]
    async fn a_warm_reattach_starts_the_control_stream_afresh() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let snapshots = io.snapshot_reader_for_test();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        let mut cut = vec![0x10];
        cut.extend_from_slice(&100u32.to_be_bytes());
        cut.extend(vec![0u8; 10]);
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: cut,
            }))
            .await
            .unwrap();
        inbound
            .send(SessionInbound::ResumeReset(channel_context()))
            .await
            .unwrap();
        assert_eq!(
            next_snapshot(&mut outbound, &snapshots).await,
            ServerRecord::ChannelSnapshot(
                crate::channel::ChannelSnapshot::new(vec![], vec![]).unwrap()
            )
        );
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        drop(inbound);
        let _ = runner.await;
    }

    /// A warm reattach's renewed control deframer must still be
    /// `for_control()`'s 64 KiB cap, not `new()`'s 64 MiB (task 6 review,
    /// Minor 3): a record that overflows the control limit but sits well
    /// under `RECORD_MAX` would, under the wrong cap, simply be "held,
    /// waiting for more" rather than dropped for good, and once its whole
    /// declared payload arrived it would frame as one (unknown, skipped)
    /// record -- after which the following `open(16)` would parse
    /// normally and succeed. Under the right cap it never gets that far.
    #[tokio::test]
    async fn a_warm_reattach_renews_the_controls_record_cap() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let snapshots = io.snapshot_reader_for_test();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(SessionInbound::ResumeReset(channel_context()))
            .await
            .unwrap();
        assert_eq!(
            next_snapshot(&mut outbound, &snapshots).await,
            ServerRecord::ChannelSnapshot(
                crate::channel::ChannelSnapshot::new(vec![], vec![]).unwrap()
            )
        );

        let payload_len = CONTROL_RECORD_MAX + 1;
        let mut lie = vec![0xffu8]; // an unknown kind, not OPEN's 0x10
        lie.extend_from_slice(&u32::try_from(payload_len).unwrap().to_be_bytes());
        lie.extend(vec![0u8; payload_len]);
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: lie,
            }))
            .await
            .unwrap();
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(500), next_control(&mut outbound))
                .await
                .is_err(),
            "the renewed control stream must still cap at CONTROL_RECORD_MAX, so the Open never applies"
        );
        drop(inbound);
        let _ = runner.await;
    }

    /// Downstream input retention must stay bounded without transport credit.
    #[tokio::test]
    async fn input25_overflow_stops_only_the_held_channel_without_stream_credit() {
        input25_overflow(false, false, 4096, 2048).await;
    }

    #[tokio::test]
    async fn input25_overflow_stays_bounded_with_stream_credit() {
        input25_overflow(true, false, 4096, 2048).await;
    }

    #[tokio::test]
    async fn input25_warm_attach_does_not_refund_held_network_input() {
        input25_overflow(true, true, 4096, 2048).await;
    }

    #[tokio::test]
    async fn input25_tiny_fragments_hit_item_limit_before_byte_limit() {
        input25_overflow(false, false, 1, 16_384).await;
    }

    async fn input25_overflow(credit: bool, warm: bool, chunk: usize, items: usize) {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let snapshots = io.snapshot_reader_for_test();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        let mut context = channel_context();
        if credit {
            context.features = context.features | crate::Features::STREAM_CREDIT;
        }
        inbound.send(SessionInbound::Live(context)).await.unwrap();
        open_a_shell_channel(&inbound, &mut outbound).await;
        spawner.hold_writes(true);
        let release = ReleaseHeldWrites(spawner.clone());

        // The same downstream budget applies independently of negotiated credit.
        // Keep the real writer and its queue occupied, including across reattach.
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: vec![b'x'; chunk],
            }))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while spawner.write_attempts.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the actual writer must own the first chunk");
        for _ in 0..(items - 1) {
            inbound
                .send(SessionInbound::Data(StreamData {
                    stream_id: 16,
                    data: vec![b'x'; chunk],
                }))
                .await
                .unwrap();
        }
        if warm {
            context.generation += 1;
            inbound
                .send(SessionInbound::ResumeReset(context))
                .await
                .unwrap();
            let _ = next_snapshot(&mut outbound, &snapshots).await;
        } else {
            inbound
                .send(open(24, ChannelKind::Shell, false))
                .await
                .unwrap();
            assert_eq!(
                next_control(&mut outbound).await,
                ServerRecord::Opened { stream: 24 }
            );
        }
        assert!(
            spawner.killed.lock().unwrap().is_empty(),
            "the exact configured byte/item boundary fits"
        );
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: vec![b'x'; chunk],
            }))
            .await
            .unwrap();
        // This record follows every data item in the same inbound FIFO. Its
        // response proves the session handled the backlog and stayed responsive.
        inbound
            .send(open(20, ChannelKind::Shell, false))
            .await
            .unwrap();
        let sibling = loop {
            let record = next_control(&mut outbound).await;
            if matches!(record, ServerRecord::Exit { stream: 16, .. }) {
                continue;
            }
            break record;
        };
        let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if spawner.killed.lock().unwrap().contains(&16) {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok();
        let sibling_stopped = spawner.killed.lock().unwrap().contains(&20);

        // Release all owned blocking I/O before reporting the behavioral result.
        spawner.break_writes();
        drop(release);
        spawner.end_channel(16);
        spawner.end_channel(20);
        spawner.end_channel(24);
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(sibling, ServerRecord::Opened { stream: 20 });
        assert!(
            !sibling_stopped,
            "overload must not stop an unrelated channel"
        );
        assert!(
            stopped,
            "input above the retained budget must stop the overloaded channel"
        );
    }

    #[tokio::test]
    async fn input25_aggregate_exhaustion_rejects_incoming_channel_then_recovers() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        inbound
            .send(open(20, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 20 }
        );
        spawner.hold_writes(true);
        let release = ReleaseHeldWrites(spawner.clone());
        const HALF: usize = 4 * 1024 * 1024;
        for stream in [16, 20] {
            inbound
                .send(SessionInbound::Data(StreamData {
                    stream_id: stream,
                    data: vec![b'x'; HALF],
                }))
                .await
                .unwrap();
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while spawner.write_attempts.load(Ordering::SeqCst) < 2 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        inbound
            .send(open(24, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 24 }
        );
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 24,
                data: vec![b'y'],
            }))
            .await
            .unwrap();
        let refused = consumed_until(&mut outbound, 24, 1).await;
        let stopped = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while !spawner.killed.lock().unwrap().contains(&24) {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok();
        let prior_stopped = spawner.killed.lock().unwrap().iter().any(|s| *s != 24);
        drop(release);
        // Both actual writes release their payload quota before reporting it.
        let completed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut total = 0;
            while total < 2 * HALF {
                if let Some(SessionOutbound::Consumed {
                    stream_id: 16 | 20,
                    n,
                }) = outbound.recv().await
                {
                    total += n;
                }
            }
            total
        })
        .await
        .unwrap();
        inbound
            .send(open(28, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 28 }
        );
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 28,
                data: vec![b'z'],
            }))
            .await
            .unwrap();
        let recovered = consumed_until(&mut outbound, 28, 1).await;
        let wrote = spawner
            .written
            .lock()
            .unwrap()
            .iter()
            .any(|(s, b)| *s == 28 && b == b"z");
        for stream in [16, 20, 24, 28] {
            spawner.end_channel(stream);
        }
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(refused.get(&24), Some(&1));
        assert!(stopped && !prior_stopped);
        assert_eq!(completed, 2 * HALF);
        assert_eq!(recovered.get(&28), Some(&1));
        assert!(
            wrote,
            "release must restore admission and actual sibling input"
        );
    }

    #[tokio::test]
    async fn input25_reused_stream_keeps_retired_writer_debt() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        spawner.hold_writes(true);
        let release = ReleaseHeldWrites(spawner.clone());
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: vec![b'x'; 8 * 1024 * 1024],
            }))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while spawner.write_attempts.load(Ordering::SeqCst) == 0 {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();
        // A new channel instance has its own quota, but shares the old debt.
        open_a_shell_channel(&inbound, &mut outbound).await;
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: vec![b'y'],
            }))
            .await
            .unwrap();
        let rejected = consumed_until(&mut outbound, 16, 1).await;
        spawner.break_writes();
        drop(release);
        let retired = consumed_until(&mut outbound, 16, 8 * 1024 * 1024).await;
        spawner.end_channel(16);
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(
            rejected.get(&16),
            Some(&1),
            "new input cannot bypass retired debt"
        );
        assert_eq!(retired.get(&16), Some(&(8 * 1024 * 1024)));
        assert!(spawner.written.lock().unwrap().is_empty());
    }

    /// Spec §4.10.3: a channel's input is taken once its process has it --
    /// not before, while the process does not read.
    #[tokio::test]
    async fn a_channels_input_is_taken_once_its_process_has_it() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        spawner.hold_writes(true);
        let _release = ReleaseHeldWrites(spawner.clone());
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: vec![b'x'; 3000],
            }))
            .await
            .unwrap();
        let before =
            consumed_within(&mut outbound, 16, 1, std::time::Duration::from_millis(300)).await;
        assert_eq!(before.get(&16), None, "held by the process: not taken");
        spawner.hold_writes(false);
        assert_eq!(
            consumed_until(&mut outbound, 16, 3000).await.get(&16),
            Some(&3000)
        );
        drop(inbound);
        let _ = runner.await;
    }

    /// Spec §4.10.3 (Review Focus 3): input the runner drops -- for a stream
    /// with no channel, open or never opened -- is taken at once.
    #[tokio::test]
    async fn input_the_runner_drops_is_reported_at_once() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 40,
                data: vec![1u8; 500],
            }))
            .await
            .unwrap();
        assert_eq!(
            consumed_until(&mut outbound, 40, 500).await.get(&40),
            Some(&500)
        );
        drop(inbound);
        let _ = runner.await;
    }

    /// Spec §4.10.3 (Review Focus 3): a channel closed with input still
    /// queued for its process, which is gone, reports every byte of it.
    #[tokio::test]
    async fn input_left_in_a_closed_channels_queue_is_reported() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        open_a_shell_channel(&inbound, &mut outbound).await;
        spawner.hold_writes(true);
        let _release = ReleaseHeldWrites(spawner.clone());
        for _ in 0..4 {
            inbound
                .send(SessionInbound::Data(StreamData {
                    stream_id: 16,
                    data: vec![b'y'; 1000],
                }))
                .await
                .unwrap();
        }
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();
        spawner.break_writes();
        assert_eq!(
            consumed_until(&mut outbound, 16, 4000).await.get(&16),
            Some(&4000)
        );
        drop(inbound);
        let _ = runner.await;
    }

    /// Drains outbound stream data until `stream` delivers a DATA record.
    /// Ignores recoverability declarations, same as `next_control`.
    async fn next_channel_data(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        stream: u8,
    ) -> Vec<u8> {
        let mut d = ShellDeframer::new();
        loop {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("the channel must produce output within five seconds")
                .expect("the runner must not drop its outbound channel");
            let msg = match msg {
                SessionOutbound::ChannelOutput {
                    stream: id,
                    output: ChannelOutput::Data(bytes),
                    ..
                } if id == stream => return bytes,
                other => other,
            };
            let SessionOutbound::Data(sd) = msg else {
                continue;
            };
            if sd.stream_id != stream {
                continue;
            }
            for rec in d.push(&sd.data) {
                if let ShellRecord::Data(bytes) = rec {
                    return bytes;
                }
            }
        }
    }

    /// Waits until `probe` is satisfied, so a test never races the runner's
    /// own tasks. Fails loudly instead of looping forever.
    async fn until(mut probe: impl FnMut() -> bool) {
        for _ in 0..500 {
            if probe() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        panic!("the condition never became true");
    }

    /// Drains outbound messages until `want` declarations have arrived,
    /// ignoring data. Fails loudly rather than hanging if they never come.
    async fn collect_declarations(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        want: usize,
    ) -> Vec<(u8, bool)> {
        let mut got = Vec::new();
        while got.len() < want {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("declarations must arrive within five seconds")
                .expect("the runner must not drop its outbound channel");
            if let SessionOutbound::Resyncable {
                stream_id,
                resyncable,
            } = msg
            {
                got.push((stream_id, resyncable));
            }
        }
        got
    }

    /// Opening a channel tells the connection whether that channel's
    /// backlog can be dropped after a long absence: it can exactly when the
    /// channel keeps a screen model to redraw from. Getting this backwards
    /// is silent data loss for a line protocol like `tmux -C`.
    #[tokio::test]
    async fn opening_a_channel_declares_whether_its_backlog_is_recoverable() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();

        let mut declared = collect_declarations(&mut outbound, 2).await;
        // Independent admitted opens may complete in either order.
        declared.sort_unstable_by_key(|(stream, _)| *stream);
        assert_eq!(
            declared,
            vec![(16u8, true), (17u8, false)],
            "a channel with a screen is recoverable; one without is not"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// A channel is declared recoverable off what the SPAWNED channel's
    /// screen model actually answers, never off `req.screen` -- what the
    /// client merely asked for. `FakeSpawner::force_no_screen` stands in for
    /// a spawner with no emulator to build a real screen model from: it
    /// hands back `NoScreen` unconditionally, even though this request asks
    /// for a screen. Declaring recoverable anyway would be exactly the bug
    /// this test guards against: the connection would drop the backlog
    /// after a long absence and have nothing to repaint it from, leaving
    /// the client desynced forever with no evidence why.
    #[tokio::test]
    async fn a_channel_whose_spawner_returned_no_screen_is_declared_unrecoverable_even_if_asked_for_one(
    ) {
        let spawner = FakeSpawner::new();
        *spawner.force_no_screen.lock().unwrap() = true;
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();

        let declared = collect_declarations(&mut outbound, 1).await;
        assert_eq!(
            declared,
            vec![(16u8, false)],
            "the request asked for a screen, but the spawner handed back \
             NoScreen -- the channel must be declared unrecoverable to match \
             what it actually got, not what it asked for"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// The plain case: the client asks for a shell channel, the server opens
    /// it, and bytes flow both ways on the channel's own stream -- never on
    /// the control stream, which is the whole reason for the split.
    #[tokio::test]
    async fn an_opened_channel_carries_bytes_both_ways() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );

        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: b"ls\r".to_vec(),
            }))
            .await
            .unwrap();
        let written = spawner.written.clone();
        until(|| !written.lock().unwrap().is_empty()).await;
        assert_eq!(
            written.lock().unwrap().as_slice(),
            &[(16u8, b"ls\r".to_vec())],
            "input reaches the channel it was addressed to"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// The spawner is told whose session asks for the channel, and it is the
    /// session's OWN principal: the system mode's spawner asks a privileged
    /// helper that opens a channel only for an account it has verified, so
    /// a placeholder here would refuse every channel -- or, worse, open one
    /// for the wrong account. The principal is a distinctive one, not the
    /// usual test placeholder, so a spawner handed some other fixed value
    /// cannot pass by coincidence.
    #[tokio::test]
    async fn the_spawner_is_told_whose_session_asks_for_the_channel() {
        let spawner = FakeSpawner::new();
        let alice = Principal {
            uid: 4242,
            name: "alice".to_string(),
            identity: "SHA256:alice".to_string(),
            incarnation: 0,
        };
        let (io, inbound, mut outbound) = channel_pair_for(alice.clone(), [0u8; 16]);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            spawner.owners.lock().unwrap().as_slice(),
            &[(16u8, alice)],
            "the spawner must be handed the principal of the session that asked"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// The spawner learns WHICH login asks, not only whose account: two logins
    /// of the same person are different sessions, and the system mode gives
    /// each its own PAM session.
    #[tokio::test]
    async fn a_channel_carries_the_login_that_asked_for_it() {
        let (io, inbound, mut outbound) = channel_pair_for(
            Principal {
                uid: 1000,
                name: "alice".into(),
                identity: "SHA256:x".into(),
                incarnation: 0,
            },
            [9u8; 16],
        );
        let spawner = FakeSpawner::new();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        open_a_shell_channel(&inbound, &mut outbound).await;

        assert_eq!(
            spawner.logins.lock().expect("logins").as_slice(),
            &[[9u8; 16]],
            "the spawner must be told the login the session belongs to"
        );
        drop(inbound);
        runner.await.expect("runner");
    }

    /// A refusal names a reason and creates nothing: input addressed to the
    /// refused channel reaches no process at all.
    #[tokio::test]
    async fn a_refused_channel_reports_why_and_stays_closed() {
        let spawner = FakeSpawner::new();
        *spawner.refuse.lock().unwrap() = Some("shell not found".to_string());
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Refused {
                stream: 16,
                reason: "shell not found".to_string()
            },
            "the reason reaches the user verbatim"
        );

        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: b"ls\r".to_vec(),
            }))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(
            spawner.written.lock().unwrap().is_empty(),
            "a refused channel has no process to write to"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// Opening past the cap is refused, and the channels already open keep
    /// working: a refusal is an answer, not a session-level failure.
    #[tokio::test]
    async fn opening_past_the_cap_is_refused_without_disturbing_the_rest() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        for n in 0..MAX_CHANNELS {
            let stream = FIRST_CHANNEL_STREAM + n as u8;
            inbound
                .send(open(stream, ChannelKind::Shell, false))
                .await
                .unwrap();
            assert_eq!(
                next_control(&mut outbound).await,
                ServerRecord::Opened { stream }
            );
        }

        let over = FIRST_CHANNEL_STREAM + MAX_CHANNELS as u8;
        inbound
            .send(open(over, ChannelKind::Shell, false))
            .await
            .unwrap();
        match next_control(&mut outbound).await {
            ServerRecord::Refused { stream, .. } => assert_eq!(stream, over),
            other => panic!("expected a refusal past the cap, got {other:?}"),
        }

        // The first channel still carries input.
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: FIRST_CHANNEL_STREAM,
                data: b"still here\r".to_vec(),
            }))
            .await
            .unwrap();
        let written = spawner.written.clone();
        until(|| {
            written
                .lock()
                .unwrap()
                .iter()
                .any(|(s, b)| *s == FIRST_CHANNEL_STREAM && b == b"still here\r")
        })
        .await;

        drop(inbound);
        runner.await.unwrap();
    }

    /// A close retains the slot until the exact child has actually reaped.
    #[tokio::test]
    async fn a_closed_channel_frees_its_slot_only_after_reaping() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        for n in 0..MAX_CHANNELS {
            let stream = FIRST_CHANNEL_STREAM + n as u8;
            inbound
                .send(open(stream, ChannelKind::Shell, false))
                .await
                .unwrap();
            assert_eq!(
                next_control(&mut outbound).await,
                ServerRecord::Opened { stream }
            );
        }
        *spawner.wait_hold.0.lock().unwrap() = true;
        let release = asynchronous_reaping::ReleaseWait(spawner.wait_hold.clone());
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close {
                    stream: FIRST_CHANNEL_STREAM,
                }),
            }))
            .await
            .unwrap();
        until(|| {
            spawner
                .killed
                .lock()
                .unwrap()
                .contains(&FIRST_CHANNEL_STREAM)
        })
        .await;
        let over = FIRST_CHANNEL_STREAM + MAX_CHANNELS as u8;
        inbound
            .send(open(over, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert!(matches!(next_control(&mut outbound).await,
            ServerRecord::Refused { stream, .. } if stream == over));
        assert_eq!(spawner.opens.outstanding(), 1, "close is not cleanup proof");
        drop(release);
        until(|| spawner.opens.outstanding() == 0).await;
        inbound
            .send(open(over, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: over }
        );
        drop(inbound);
        runner.await.unwrap();
    }

    /// Reusing a stream number that is already open is refused, and the
    /// channel that holds it keeps working. The client picks its own
    /// numbers, so this is its mistake to be told about -- not a reason to
    /// tear the session down.
    #[tokio::test]
    async fn reopening_a_stream_that_is_already_open_is_refused() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );

        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        match next_control(&mut outbound).await {
            ServerRecord::Refused { stream, reason } => {
                assert_eq!(stream, 16);
                assert!(
                    reason.contains("already open"),
                    "the refusal must say the number is taken, got: {reason:?}"
                );
            }
            other => panic!("expected a refusal for a stream already in use, got {other:?}"),
        }

        // The channel holding the number is untouched.
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: b"alive\r".to_vec(),
            }))
            .await
            .unwrap();
        let written = spawner.written.clone();
        until(|| {
            written
                .lock()
                .unwrap()
                .iter()
                .any(|(s, b)| *s == 16 && b == b"alive\r")
        })
        .await;

        drop(inbound);
        runner.await.unwrap();
    }

    /// A channel whose process ends reports its exit code, and the code is
    /// the one the process actually returned rather than an assumption.
    #[tokio::test]
    async fn a_finished_channel_reports_its_exit_code() {
        let mut spawner = FakeSpawner::new();
        Arc::get_mut(&mut spawner).unwrap().exit_code = 130;
        let (io, inbound, outbound) = channel_pair();
        let mut outbound = auto_deliver(&inbound, outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        // Drain the greeting so the next control record is the exit.
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );

        spawner.end_channel(16);
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 130
            },
            "the exit code travels, rather than being guessed at as zero"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// The session outlives a channel that ended. This is the whole point of
    /// channels: the app's tmux control client can die without taking the
    /// shell with it.
    #[tokio::test]
    async fn one_channel_ending_leaves_the_others_running() {
        let spawner = FakeSpawner::new();
        let (io, inbound, outbound) = channel_pair();
        let mut outbound = auto_deliver(&inbound, outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );

        spawner.end_channel(17);
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 17,
                code: 0
            }
        );

        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: 16,
                data: b"alive\r".to_vec(),
            }))
            .await
            .unwrap();
        let written = spawner.written.clone();
        until(|| {
            written
                .lock()
                .unwrap()
                .iter()
                .any(|(s, b)| *s == 16 && b == b"alive\r")
        })
        .await;

        drop(inbound);
        runner.await.unwrap();
    }

    /// A resize reaches the channel it names and no other. Getting this
    /// wrong would resize the user's shell whenever the control client's
    /// geometry changed.
    #[tokio::test]
    async fn a_resize_applies_to_one_channel_only() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );

        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::ResizeRequest {
                    instance: ChannelInstance::new(1).unwrap(),
                    request_id: ResizeRequestId::new(1).unwrap(),
                    stream: 16,
                    cols: 120,
                    rows: 40,
                }),
            }))
            .await
            .unwrap();

        let sizes = spawner.sizes.clone();
        until(|| !sizes.lock().unwrap().is_empty()).await;
        assert_eq!(
            sizes.lock().unwrap().as_slice(),
            &[(16u8, 120u16, 40u16)],
            "only the named channel is resized"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// A repaint asks every channel that has a screen model, and no others:
    /// replaying a screen into a line protocol like `tmux -C` would corrupt
    /// the conversation.
    #[tokio::test]
    async fn a_repaint_reaches_only_the_channels_that_asked_for_a_screen() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );

        inbound.send(SessionInbound::Repaint).await.unwrap();

        let repaints = spawner.repaints.clone();
        until(|| !repaints.lock().unwrap().is_empty()).await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(
            repaints.lock().unwrap().as_slice(),
            &[16u8],
            "the channel without a screen model is never asked to repaint"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// A warm reattach announces what is already running, so the client binds
    /// instead of opening a second copy of each channel. The list carries the
    /// geometry too, or a client cannot tell whether the size it wants is
    /// already applied.
    // `runner` is intentionally never awaited: the brief's test body ends at
    // the assertion, leaving the session running in the background for the
    // test process to tear down.
    #[allow(unused_variables)]
    #[tokio::test]
    async fn a_warm_reattach_announces_the_live_channels_first() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let snapshots = io.snapshot_reader_for_test();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );

        inbound
            .send(SessionInbound::ResumeReset(channel_context()))
            .await
            .unwrap();

        match next_snapshot(&mut outbound, &snapshots).await {
            ServerRecord::ChannelSnapshot(snapshot) => {
                assert!(snapshot.draining().is_empty());
                let list: Vec<_> = snapshot
                    .active()
                    .iter()
                    .map(|entry| &entry.request)
                    .collect();
                assert_eq!(list.len(), 1, "one channel is running, one is announced");
                assert_eq!(list[0].stream, 16);
                assert_eq!(list[0].kind, ChannelKind::Shell);
                assert_eq!(
                    (list[0].cols, list[0].rows),
                    (80, 24),
                    "geometry travels with the list"
                );
                assert!(list[0].screen, "so does whether the channel keeps a screen");
            }
            other => panic!("a warm reattach must announce the live channels, got {other:?}"),
        }
    }

    /// The client's terminal type reaches the spawner, and only for channels
    /// opened after it was announced. Without this the daemon has to assume
    /// one terminal for every client -- which is how a console client's Home
    /// key ends up doing nothing and leaving a `~` behind.
    #[tokio::test]
    async fn a_terminal_type_reaches_the_spawner_of_every_later_channel() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        // A channel opened before the announcement: nothing to pass on.
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );

        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Term("rxvt-unicode-256color".to_string())),
            }))
            .await
            .unwrap();
        inbound
            .send(open(17, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );

        let terms = spawner.terms.lock().unwrap().clone();
        assert_eq!(
            terms,
            vec![
                (16, None),
                (17, Some("rxvt-unicode-256color".to_string()))
            ],
            "the channel opened before the announcement gets nothing, the one after it gets the name"
        );

        drop(inbound);
        let _ = runner.await;
    }

    /// A terminal type the codec refuses never reaches the spawner: the
    /// record is malformed, so the session keeps whatever it had -- here,
    /// nothing -- rather than passing a name with a newline in it into a
    /// process's environment.
    #[tokio::test]
    async fn a_refused_terminal_type_leaves_the_spawner_with_none() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_record(0x13, b"xterm\n256color"),
            }))
            .await
            .unwrap();
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );

        assert_eq!(
            spawner.terms.lock().unwrap().clone(),
            vec![(16, None)],
            "a name the codec refuses is not a name the spawner may see"
        );

        drop(inbound);
        let _ = runner.await;
    }

    /// A cold start announces nothing: an empty list is indistinguishable
    /// from a server that never answered, and a client waiting for one would
    /// hang forever.
    #[tokio::test]
    async fn a_cold_start_sends_no_channel_list() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(SessionInbound::Live(channel_context()))
            .await
            .unwrap();
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();

        // The FIRST control record after a cold start is the answer to the
        // open, never a channel list.
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// A channel still running when the SESSION ends (not the channel's own
    /// EOF) must not leak its process: `portable_pty::Child` is not reaped on
    /// drop, so once a real `ChannelSpawner` is wired in, forgetting this
    /// path would leave a zombie behind on every torn-down session that still
    /// had a channel open. `FakeProcess` never reaches EOF on its own here
    /// (its `end_tx` is never dropped), so a passing test proves the runner
    /// itself killed and waited on it -- not that it merely happened to exit.
    #[tokio::test]
    async fn a_still_running_channel_is_killed_and_waited_when_the_session_ends() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );

        // The manager drops the io: the session tears down while channel 16
        // is still running (blocked in `FakeProcess::read`, exactly as an
        // unresponsive real process would be).
        drop(inbound);
        runner.await.unwrap();

        assert_eq!(
            spawner.killed.lock().unwrap().as_slice(),
            &[16u8],
            "a channel still running when the session ends must be force-killed"
        );
        assert_eq!(
            spawner.waited.lock().unwrap().as_slice(),
            &[16u8],
            "and waited on afterwards, or its process leaks as a zombie"
        );
    }

    /// A channel the CLIENT closes while its process is still running must
    /// not leak either: `CLOSE` is the client saying "stop watching this",
    /// not "this process already exited". `FakeProcess` never reaches EOF on
    /// its own here, so a passing test proves `CLOSE` itself did the
    /// reaping -- not that the process happened to end on its own.
    #[tokio::test]
    async fn a_closed_channel_is_killed_and_waited_even_though_its_process_is_still_running() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );

        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();

        let killed = spawner.killed.clone();
        let waited = spawner.waited.clone();
        until(|| !killed.lock().unwrap().is_empty() && !waited.lock().unwrap().is_empty()).await;
        assert_eq!(
            killed.lock().unwrap().as_slice(),
            &[16u8],
            "a channel closed by the client is force-killed, not merely dropped"
        );
        assert_eq!(
            waited.lock().unwrap().as_slice(),
            &[16u8],
            "and waited on, or its process leaks as a zombie"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// Drains outbound messages until a class declaration arrives, ignoring
    /// everything else. Fails loudly rather than hanging if none comes.
    async fn next_class_declaration(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
    ) -> (u8, StreamClass) {
        loop {
            let msg = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv())
                .await
                .expect("a class declaration must arrive within five seconds")
                .expect("the runner must not drop its outbound channel");
            if let SessionOutbound::StreamClass { stream_id, class } = msg {
                return (stream_id, class);
            }
        }
    }

    /// Task 7 review: a channel that goes away -- closed by the client, or
    /// its process ended -- puts its stream back in the interactive class.
    /// The bridge declares every class it kept again after a warm reattach,
    /// so a class left behind would reach whatever channel reuses the number.
    #[tokio::test]
    async fn a_channel_that_goes_away_puts_its_stream_back_in_the_interactive_class() {
        let spawner = FakeSpawner::new();
        let (io, inbound, outbound) = channel_pair();
        let mut outbound = auto_deliver(&inbound, outbound);
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        inbound
            .send(open(17, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );

        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();
        assert_eq!(
            next_class_declaration(&mut outbound).await,
            (16, StreamClass::Interactive),
            "closed by the client"
        );
        spawner.end_channel(17);
        assert_eq!(
            next_class_declaration(&mut outbound).await,
            (17, StreamClass::Interactive),
            "its process ended"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// A warm reattach announces EVERY live channel, not just the first --
    /// the atomic snapshot preserves a bounded list, and each entry
    /// keeps its own identity, kind, geometry and screen flag rather than
    /// collapsing into a count.
    #[tokio::test]
    async fn a_warm_reattach_announces_every_live_channel_with_its_own_details() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let snapshots = io.snapshot_reader_for_test();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );

        inbound
            .send(SessionInbound::ResumeReset(channel_context()))
            .await
            .unwrap();

        match next_snapshot(&mut outbound, &snapshots).await {
            ServerRecord::ChannelSnapshot(snapshot) => {
                assert!(snapshot.draining().is_empty());
                let list: Vec<_> = snapshot
                    .active()
                    .iter()
                    .map(|entry| &entry.request)
                    .collect();
                assert_eq!(list.len(), 2, "both live channels are announced");
                assert_eq!(list[0].stream, 16);
                assert_eq!(list[0].kind, ChannelKind::Shell);
                assert_eq!(
                    (list[0].cols, list[0].rows),
                    (80, 24),
                    "each entry carries its own geometry"
                );
                assert!(list[0].screen, "channel 16 was opened with a screen model");
                assert_eq!(list[1].stream, 17);
                assert_eq!(list[1].kind, ChannelKind::Command);
                assert_eq!((list[1].cols, list[1].rows), (80, 24));
                assert!(
                    !list[1].screen,
                    "channel 17 was opened without a screen model"
                );
            }
            other => panic!("a warm reattach must announce every live channel, got {other:?}"),
        }

        drop(inbound);
        runner.await.unwrap();
    }

    /// A warm reattach swaps in a brand-new `Connection`
    /// (`BridgeControl::Attach`), and a connection's recoverability
    /// declarations are its own state -- they do not travel to the
    /// replacement (see `Connection::set_stream_resyncable`'s own doc).
    /// Everything a still-live channel declared when it was opened is gone
    /// the moment the old `Connection` is dropped, unless this runner says
    /// it again on `ResumeReset`. Missing this redeclaration means a channel
    /// WITH a screen model falls back to the connection's default (never
    /// drop the backlog) after the very first roam: the next long absence
    /// replays the accumulated backlog in full instead of getting a single
    /// repaint -- the exact defect this whole seam exists to prevent, just
    /// one warm reattach later than the open-time declaration covers.
    #[tokio::test]
    async fn resume_reset_redeclares_every_live_channels_recoverability() {
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );

        // Everything above already drained the two OPEN-time declarations as
        // a side effect of `next_control`/`next_channel_data` skipping past
        // them -- what is collected below can only be fresh ones.
        inbound
            .send(SessionInbound::ResumeReset(channel_context()))
            .await
            .unwrap();

        let mut redeclared = collect_declarations(&mut outbound, 2).await;
        redeclared.sort_by_key(|(stream, _)| *stream);
        assert_eq!(
            redeclared,
            vec![(16u8, true), (17u8, false)],
            "ResumeReset must redeclare every live channel's recoverability \
             on the NEW connection -- a channel with a screen stays \
             recoverable, one without stays unrecoverable"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// Same bug as
    /// `a_channel_whose_spawner_returned_no_screen_is_declared_unrecoverable_even_if_asked_for_one`,
    /// on the OTHER path that used to read `req.screen`: the `ResumeReset`
    /// redeclare loop must also ask the channel's own screen model, not the
    /// request it was opened with, or a warm reattach would flip a channel
    /// that never had a real screen back to "recoverable" the moment it
    /// redeclares.
    #[tokio::test]
    async fn resume_reset_redeclares_off_the_actual_screen_model_not_the_request() {
        let spawner = FakeSpawner::new();
        *spawner.force_no_screen.lock().unwrap() = true;
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));

        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );

        inbound
            .send(SessionInbound::ResumeReset(channel_context()))
            .await
            .unwrap();

        let redeclared = collect_declarations(&mut outbound, 1).await;
        assert_eq!(
            redeclared,
            vec![(16u8, false)],
            "the request asked for a screen, but the spawner never gave one \
             -- ResumeReset must redeclare unrecoverable, matching what the \
             channel actually has, not what it originally asked for"
        );

        drop(inbound);
        runner.await.unwrap();
    }

    /// A daemon stand-in: answers `About` with a fixed description, answers
    /// offers with `answer` or accepts them, and writes down what happened
    /// (`joined <n>` and `released <n>` for the restart numbers sessions
    /// report). A transfer's `restart` announces, waits for this session's
    /// runner to join, drains, waits for it to release its channels, and
    /// fails -- the way an `exec` that did not happen does.
    struct FakeDaemon {
        answer: Mutex<Option<UpdateAnswer>>,
        restart_tx: Arc<watch::Sender<RestartSignal>>,
        log: Arc<Mutex<Vec<String>>>,
        busy: Arc<AtomicBool>,
        stall: std::time::Duration,
        /// Handed to every transfer's [`FakeTransfer::fail`]: while set, its
        /// disk refuses every write.
        fail_writes: Arc<AtomicBool>,
    }

    impl FakeDaemon {
        fn new() -> Arc<FakeDaemon> {
            FakeDaemon::with_stall(TRANSFER_STALL)
        }

        fn with_stall(stall: std::time::Duration) -> Arc<FakeDaemon> {
            Arc::new(FakeDaemon {
                answer: Mutex::new(None),
                restart_tx: Arc::new(watch::channel(RestartSignal::IDLE).0),
                log: Arc::new(Mutex::new(Vec::new())),
                busy: Arc::new(AtomicBool::new(false)),
                stall,
                fail_writes: Arc::new(AtomicBool::new(false)),
            })
        }

        fn log(&self) -> Vec<String> {
            self.log.lock().unwrap().clone()
        }
    }

    fn fake_about() -> About {
        About {
            build: 7,
            checksum: [7; 32],
            arch: "x86_64".to_string(),
            protocol: PROTOCOL_VERSION,
            mode: DaemonMode::Personal,
        }
    }

    impl DaemonUpdates for FakeDaemon {
        fn about(&self) -> Option<About> {
            Some(fake_about())
        }

        fn offer(
            &self,
            _from: &Principal,
            offer: &UpdateOffer,
        ) -> Result<Box<dyn UpdateTransfer>, UpdateAnswer> {
            if let Some(answer) = self.answer.lock().unwrap().clone() {
                return Err(answer);
            }
            if self.busy.swap(true, Ordering::SeqCst) {
                return Err(UpdateAnswer::InProgress);
            }
            self.log
                .lock()
                .unwrap()
                .push(format!("offer {}", offer.size));
            Ok(Box::new(FakeTransfer {
                log: Arc::clone(&self.log),
                busy: Arc::clone(&self.busy),
                restart_tx: Arc::clone(&self.restart_tx),
                written: 0,
                fail: Arc::clone(&self.fail_writes),
            }))
        }

        fn restart_signal(&self) -> watch::Receiver<RestartSignal> {
            self.restart_tx.subscribe()
        }

        fn restart_joined(&self, restart: u64) -> bool {
            // Held across the check, as the real daemon does: the signal
            // cannot move to `Draining` between the look and the count.
            let signal = self.restart_tx.borrow();
            if *signal != RestartSignal::announced(restart, restart) {
                return false;
            }
            self.log.lock().unwrap().push(format!("joined {restart}"));
            true
        }

        fn channels_released(&self, restart: u64) {
            self.log.lock().unwrap().push(format!("released {restart}"));
        }

        fn stall_timeout(&self) -> std::time::Duration {
            self.stall
        }
    }

    struct FakeTransfer {
        log: Arc<Mutex<Vec<String>>>,
        busy: Arc<AtomicBool>,
        restart_tx: Arc<watch::Sender<RestartSignal>>,
        written: usize,
        /// While set, every write fails -- the disk is full.
        fail: Arc<AtomicBool>,
    }

    impl UpdateTransfer for FakeTransfer {
        fn write(&mut self, bytes: &[u8]) -> Result<(), String> {
            if self.fail.load(Ordering::SeqCst) {
                return Err("the disk is full".to_string());
            }
            self.written += bytes.len();
            Ok(())
        }

        fn verify(&mut self) -> Result<(), UpdateResult> {
            self.log
                .lock()
                .unwrap()
                .push(format!("verify {}", self.written));
            Ok(())
        }

        fn restart(self: Box<Self>) -> UpdateResult {
            self.log.lock().unwrap().push("restart".to_string());
            let wait_for = |line: &str| {
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
                while !self.log.lock().unwrap().iter().any(|l| l == line)
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
            };
            self.restart_tx.send_replace(RestartSignal::announced(1, 1));
            // The one runner of these tests joins, then releases its channels.
            wait_for("joined 1");
            self.restart_tx.send_replace(RestartSignal::draining(1, 1));
            wait_for("released 1");
            self.restart_tx.send_replace(RestartSignal::idle(1));
            UpdateResult::Rejected {
                code: RejectCode::ExecFailed,
                detail: "exec is not available in a test".to_string(),
            }
        }
    }

    impl Drop for FakeTransfer {
        fn drop(&mut self) {
            self.log.lock().unwrap().push("dropped".to_string());
            self.busy.store(false, Ordering::SeqCst);
        }
    }

    fn control(rec: ClientRecord) -> SessionInbound {
        SessionInbound::Data(StreamData {
            stream_id: CONTROL_STREAM,
            data: encode_client(&rec),
        })
    }

    fn image_bytes(data: &[u8]) -> SessionInbound {
        SessionInbound::Data(StreamData {
            stream_id: UPDATE_STREAM,
            data: data.to_vec(),
        })
    }

    fn offer_of(size: u64) -> ClientRecord {
        ClientRecord::UpdateOffer(UpdateOffer {
            build: 8,
            checksum: [8; 32],
            arch: "x86_64".to_string(),
            size,
        })
    }

    fn with_daemon(daemon: &Arc<FakeDaemon>) -> Option<Arc<dyn DaemonUpdates>> {
        Some(Arc::clone(daemon) as Arc<dyn DaemonUpdates>)
    }

    /// With nobody speaking for the daemon, `About` goes unanswered -- the
    /// silence a client reads as "this daemon cannot update itself" -- and
    /// the session carries on: the next request is answered as usual.
    #[tokio::test]
    async fn a_session_without_a_daemon_behind_it_leaves_about_unanswered() {
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session(io, FakeSpawner::new()));
        inbound
            .send(control(ClientRecord::AboutRequest))
            .await
            .unwrap();
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 },
            "the first answer is the channel's: About got none"
        );
        drop(inbound);
        runner.await.unwrap();
    }

    #[tokio::test]
    async fn an_about_request_is_answered_with_what_the_daemon_says() {
        let daemon = FakeDaemon::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        inbound
            .send(control(ClientRecord::AboutRequest))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::About(fake_about())
        );
        drop(inbound);
        runner.await.unwrap();
    }

    /// A refused offer is answered and nothing is received: bytes on the
    /// update stream without an `Accept` in this session go nowhere.
    #[tokio::test]
    async fn a_refused_offer_is_answered_and_stray_image_bytes_are_dropped() {
        let daemon = FakeDaemon::new();
        *daemon.answer.lock().unwrap() = Some(UpdateAnswer::Managed);
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        inbound.send(control(offer_of(16))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Managed)
        );
        inbound
            .send(image_bytes(b"sixteen bytes!!!"))
            .await
            .unwrap();
        // Answered after the bytes, so the runner has handled them by now.
        inbound
            .send(control(ClientRecord::AboutRequest))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::About(fake_about())
        );
        assert!(daemon.log().is_empty(), "no transfer was ever created");
        drop(inbound);
        runner.await.unwrap();
    }

    /// The whole accepted path: exactly `size` bytes reach the transfer
    /// (a tail past it is dropped), it is verified, `Restarting` is reported
    /// BEFORE the restart is attempted, the announcement reaches this very
    /// session too, the drain is confirmed, and a restart that returns is
    /// reported as the result it returned.
    #[tokio::test]
    async fn an_accepted_image_is_written_verified_and_restarted() {
        let daemon = FakeDaemon::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        inbound.send(control(offer_of(10))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept)
        );
        inbound.send(image_bytes(b"01234")).await.unwrap();
        inbound.send(image_bytes(b"56789-tail")).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateResult(UpdateResult::Restarting)
        );
        let rest = vec![
            next_control(&mut outbound).await,
            next_control(&mut outbound).await,
        ];
        assert!(rest.contains(&ServerRecord::Restarting), "{rest:?}");
        assert!(
            rest.contains(&ServerRecord::UpdateResult(UpdateResult::Rejected {
                code: RejectCode::ExecFailed,
                detail: "exec is not available in a test".to_string()
            })),
            "{rest:?}"
        );
        until(|| daemon.log().contains(&"dropped".to_string())).await;
        assert_eq!(
            daemon.log(),
            vec![
                "offer 10",
                "verify 10",
                "restart",
                "joined 1",
                "released 1",
                "dropped"
            ]
        );
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
    }

    /// One update at a time: a second offer in the same session, while the
    /// first is still on its way, gets `InProgress` without the daemon being
    /// asked; so does an offer from another session.
    #[tokio::test]
    async fn a_second_offer_while_one_is_in_flight_gets_in_progress() {
        let daemon = FakeDaemon::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        let (io2, inbound2, mut outbound2) = channel_pair();
        let runner2 = tokio::spawn(run_channel_session_with(
            io2,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        inbound.send(control(offer_of(10))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept)
        );
        inbound.send(control(offer_of(10))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::InProgress)
        );
        inbound2.send(control(offer_of(10))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound2).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::InProgress)
        );
        drop(inbound);
        drop(inbound2);
        runner.await.unwrap();
        runner2.await.unwrap();
    }

    /// A client that stopped sending must not hold the daemon's one update
    /// slot for as long as its session lives: past the stall the transfer is
    /// rejected and dropped, and a new offer is accepted.
    #[tokio::test]
    async fn a_stalled_transfer_is_rejected_and_frees_the_slot() {
        let daemon = FakeDaemon::with_stall(std::time::Duration::from_millis(200));
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        inbound.send(control(offer_of(10))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept)
        );
        inbound.send(image_bytes(b"0123")).await.unwrap();
        match next_control(&mut outbound).await {
            ServerRecord::UpdateResult(UpdateResult::Rejected { code, detail }) => {
                assert_eq!(code, RejectCode::TransferStalled, "{detail}")
            }
            other => panic!("expected a rejection, got {other:?}"),
        }
        until(|| daemon.log().contains(&"dropped".to_string())).await;
        inbound.send(control(offer_of(10))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept),
            "the slot is free again"
        );
        drop(inbound);
        runner.await.unwrap();
    }

    /// The sender went away half-way: the transfer is dropped (the real one
    /// deletes its staged file on drop) and never verified.
    #[tokio::test]
    async fn a_session_that_ends_mid_transfer_drops_its_transfer() {
        let daemon = FakeDaemon::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        inbound.send(control(offer_of(10))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept)
        );
        inbound.send(image_bytes(b"0123")).await.unwrap();
        drop(inbound);
        runner.await.unwrap();
        until(|| daemon.log().contains(&"dropped".to_string())).await;
        assert!(!daemon.log().iter().any(|l| l.starts_with("verify")));
        assert!(
            released_count(&daemon) == 0,
            "a session that ends outside a restart has no drain to confirm"
        );
    }

    /// Spec §4.10.3: an image's bytes are taken as the transfer writes them.
    #[tokio::test]
    async fn update_bytes_are_taken_once_the_image_has_them() {
        let daemon = FakeDaemon::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        inbound.send(control(offer_of(1000))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept)
        );
        inbound.send(image_bytes(&[2u8; 600])).await.unwrap();
        assert_eq!(
            consumed_until(&mut outbound, UPDATE_STREAM, 600)
                .await
                .get(&UPDATE_STREAM),
            Some(&600)
        );
        drop(inbound);
        runner.await.unwrap();
    }

    /// Spec §4.10.3 (Review Focus 3): bytes with no transfer accepted and
    /// bytes past the offered size are taken at once; when a transfer ends
    /// early -- its disk refused a write -- what was queued to it and never
    /// taken is taken then. Every byte sent on `UPDATE_STREAM` is reported,
    /// whichever way it went.
    #[tokio::test]
    async fn update_bytes_nobody_writes_are_reported_too() {
        let daemon = FakeDaemon::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        // No transfer accepted: dropped, and taken at once.
        inbound.send(image_bytes(&[1u8; 700])).await.unwrap();
        assert_eq!(
            consumed_until(&mut outbound, UPDATE_STREAM, 700)
                .await
                .get(&UPDATE_STREAM),
            Some(&700)
        );
        // A transfer whose disk refuses its writes, sent 100 bytes more than
        // it offered.
        daemon.fail_writes.store(true, Ordering::SeqCst);
        inbound.send(control(offer_of(1000))).await.unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::UpdateAnswer(UpdateAnswer::Accept)
        );
        for chunk in [300usize, 300, 300, 200] {
            inbound.send(image_bytes(&vec![2u8; chunk])).await.unwrap();
        }
        assert_eq!(
            consumed_until(&mut outbound, UPDATE_STREAM, 1100)
                .await
                .get(&UPDATE_STREAM),
            Some(&1100)
        );
        drop(inbound);
        runner.await.unwrap();
    }

    /// The announcement reaches every session, not only the one that sent
    /// the image: each tells its own client.
    #[tokio::test]
    async fn the_restart_announcement_reaches_every_session() {
        let daemon = FakeDaemon::new();
        let (io1, inbound1, mut outbound1) = channel_pair();
        let (io2, inbound2, mut outbound2) = channel_pair();
        let r1 = tokio::spawn(run_channel_session_with(
            io1,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        let r2 = tokio::spawn(run_channel_session_with(
            io2,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        // Both runners are in their loops once they have answered.
        inbound1
            .send(control(ClientRecord::AboutRequest))
            .await
            .unwrap();
        inbound2
            .send(control(ClientRecord::AboutRequest))
            .await
            .unwrap();
        let _ = next_control(&mut outbound1).await;
        let _ = next_control(&mut outbound2).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(1, 1));
        assert_eq!(next_control(&mut outbound1).await, ServerRecord::Restarting);
        assert_eq!(next_control(&mut outbound2).await, ServerRecord::Restarting);
        drop(inbound1);
        drop(inbound2);
        r1.await.unwrap();
        r2.await.unwrap();
    }

    /// Before the exec every session -- a parked one included -- ends its
    /// channels itself and waits for their processes: a process left behind
    /// would become a child of the new binary that nobody waits for. A
    /// session that saw the announcement joined that restart, and says so
    /// once its channels are reaped, with the restart's number.
    #[tokio::test]
    async fn draining_ends_and_reaps_every_channel_then_says_so() {
        let daemon = FakeDaemon::new();
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            spawner.clone(),
            with_daemon(&daemon),
        ));
        open_a_shell_channel(&inbound, &mut outbound).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(1, 1));
        assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
        until(|| daemon.log().contains(&"joined 1".to_string())).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(1, 1));
        let killed = spawner.killed.clone();
        let waited = spawner.waited.clone();
        until(|| daemon.log().contains(&"released 1".to_string())).await;
        assert_eq!(killed.lock().unwrap().as_slice(), &[16u8]);
        assert_eq!(waited.lock().unwrap().as_slice(), &[16u8]);
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(released_count(&daemon), 1);
    }

    /// A session whose loop never saw the announcement -- the watch folded
    /// it into `Draining` -- was not counted by the daemon: it still tells
    /// its client and ends and reaps its channels (best effort, so nothing
    /// is left for the new binary), but confirms nothing, or the daemon's
    /// count would overshoot.
    #[tokio::test]
    async fn a_session_that_only_sees_the_drain_reaps_but_does_not_confirm() {
        let daemon = FakeDaemon::new();
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            spawner.clone(),
            with_daemon(&daemon),
        ));
        open_a_shell_channel(&inbound, &mut outbound).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(1, 1));
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Restarting,
            "a client about to lose its channels hears why"
        );
        let waited = spawner.waited.clone();
        until(|| waited.lock().unwrap().as_slice() == [16u8]).await;
        assert_eq!(spawner.killed.lock().unwrap().as_slice(), &[16u8]);
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(released_count(&daemon), 0, "never joined, never confirms");
        assert!(!daemon.log().iter().any(|l| l.starts_with("joined")));
    }

    /// Fails the test if any control record arrives within a short while:
    /// how a test says "and nothing else follows".
    async fn assert_no_control(rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>) {
        let quiet = tokio::time::timeout(std::time::Duration::from_millis(300), async {
            let mut d = RecordDeframer::new();
            loop {
                let Some(msg) = rx.recv().await else {
                    return std::future::pending::<ServerRecord>().await;
                };
                let msg = match msg {
                    SessionOutbound::ChannelOpened { stream, .. } => {
                        return ServerRecord::Opened { stream }
                    }
                    SessionOutbound::ChannelRefused { stream, reason, .. } => {
                        return ServerRecord::Refused { stream, reason }
                    }
                    SessionOutbound::ChannelExit { stream, code, .. } => {
                        return match code {
                            Some(code) => ServerRecord::Exit { stream, code },
                            None => ServerRecord::ExitStatusUnavailable { stream },
                        }
                    }
                    other => other,
                };
                let SessionOutbound::Data(sd) = msg else {
                    continue;
                };
                if sd.stream_id != CONTROL_STREAM {
                    continue;
                }
                if let Some(raw) = d.push(&sd.data).into_iter().next() {
                    return decode_server(&raw).expect("a well-formed server record");
                }
            }
        })
        .await;
        if let Ok(record) = quiet {
            panic!("nothing more was expected, got {record:?}");
        }
    }

    fn released_count(daemon: &FakeDaemon) -> usize {
        daemon
            .log()
            .iter()
            .filter(|l| l.starts_with("released"))
            .count()
    }

    fn logged(daemon: &FakeDaemon, line: &str) -> usize {
        daemon.log().iter().filter(|l| *l == line).count()
    }

    /// Once a restart is under way no channel may be opened: its process
    /// would outlive the drain and become a child of the new binary that
    /// nobody waits for. Refused, and the spawner is never asked.
    #[tokio::test]
    async fn a_channel_opened_during_a_restart_is_refused_and_nothing_spawns() {
        for signal in [
            RestartSignal::announced(1, 1),
            RestartSignal::draining(1, 1),
        ] {
            let daemon = FakeDaemon::new();
            let spawner = FakeSpawner::new();
            let (io, inbound, mut outbound) = channel_pair();
            let runner = tokio::spawn(run_channel_session_with(
                io,
                spawner.clone(),
                with_daemon(&daemon),
            ));
            daemon.restart_tx.send_replace(signal);
            assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
            inbound
                .send(open(16, ChannelKind::Shell, false))
                .await
                .unwrap();
            match next_control(&mut outbound).await {
                ServerRecord::Refused { stream, .. } => assert_eq!(stream, 16, "{signal:?}"),
                other => panic!("{signal:?}: expected a refusal, got {other:?}"),
            }
            assert!(
                spawner.owners.lock().unwrap().is_empty(),
                "{signal:?}: the spawner must not be asked"
            );
            drop(inbound);
            runner.await.unwrap();
        }
    }

    /// A session that starts while a restart is announced has seen no change
    /// of the signal, yet must act on it all the same: tell its client and,
    /// once the daemon drains, confirm -- it existed when the daemon
    /// announced, so the daemon counts on it.
    #[tokio::test]
    async fn a_session_that_starts_during_an_announced_restart_tells_and_confirms() {
        let daemon = FakeDaemon::new();
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(1, 1));
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
        until(|| logged(&daemon, "joined 1") == 1).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(1, 1));
        until(|| released_count(&daemon) == 1).await;
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(
            daemon.log(),
            vec!["joined 1", "released 1"],
            "joined and confirmed once each, not again on exit"
        );
    }

    /// A session that first hears of a restart when it is already draining
    /// was not there when the daemon counted whom to wait for: it tells its
    /// client and refuses channels, but confirms nothing -- not in the loop,
    /// not on exit -- or the count would overshoot and the daemon could exec
    /// while a counted session is still reaping. The next restart it does
    /// take part in.
    #[tokio::test]
    async fn a_session_that_starts_during_a_drain_tells_but_never_confirms_it() {
        // Exits during the drain.
        let daemon = FakeDaemon::new();
        let spawner = FakeSpawner::new();
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(1, 1));
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            spawner.clone(),
            with_daemon(&daemon),
        ));
        assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert!(matches!(
            next_control(&mut outbound).await,
            ServerRecord::Refused { stream: 16, .. }
        ));
        assert!(spawner.owners.lock().unwrap().is_empty());
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(released_count(&daemon), 0, "never counted, never confirms");

        // Stays for the next restart.
        let daemon = FakeDaemon::new();
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(1, 1));
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
        assert_no_control(&mut outbound).await;
        assert_eq!(released_count(&daemon), 0);
        daemon.restart_tx.send_replace(RestartSignal::idle(1));
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(2, 2));
        assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
        until(|| logged(&daemon, "joined 2") == 1).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(2, 2));
        until(|| released_count(&daemon) == 1).await;
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(
            daemon.log(),
            vec!["joined 2", "released 2"],
            "the next restart is joined and confirmed"
        );
    }

    /// Two restarts in a row: each is told exactly once, even when the end
    /// of the first and the start of the second reach the session as one
    /// change (a watch keeps only the latest value).
    #[tokio::test]
    async fn two_restarts_in_a_row_are_each_announced_once() {
        let daemon = FakeDaemon::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            FakeSpawner::new(),
            with_daemon(&daemon),
        ));
        // Subscribed and in its loop once it has answered: a session that
        // subscribed mid-drain would rightly never confirm restart 1.
        inbound
            .send(control(ClientRecord::AboutRequest))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::About(fake_about())
        );
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(1, 1));
        assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
        until(|| logged(&daemon, "joined 1") == 1).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(1, 1));
        until(|| released_count(&daemon) == 1).await;
        // Back to back: the session is likely to see only the last of these.
        daemon.restart_tx.send_replace(RestartSignal::idle(1));
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(2, 2));
        daemon
            .restart_tx
            .send_replace(RestartSignal::draining(2, 2));
        assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
        assert_no_control(&mut outbound).await;
        drop(inbound);
        runner.await.unwrap();
        // Whether or not the session caught the second announcement, it
        // confirms exactly what it joined -- the balance the daemon waits on.
        assert_eq!(logged(&daemon, "joined 1"), 1);
        assert_eq!(logged(&daemon, "released 1"), 1);
        assert_eq!(logged(&daemon, "released 2"), logged(&daemon, "joined 2"));
        assert!(logged(&daemon, "joined 2") <= 1);
    }

    /// A session whose client goes away while a restart is under way still
    /// ends its channels and confirms: the daemon counted it, and without
    /// the confirmation it would wait out its whole drain timeout.
    #[tokio::test]
    async fn a_session_that_ends_during_a_restart_still_confirms_its_drain() {
        let daemon = FakeDaemon::new();
        let spawner = FakeSpawner::new();
        let (io, inbound, mut outbound) = channel_pair();
        let runner = tokio::spawn(run_channel_session_with(
            io,
            spawner.clone(),
            with_daemon(&daemon),
        ));
        open_a_shell_channel(&inbound, &mut outbound).await;
        daemon
            .restart_tx
            .send_replace(RestartSignal::announced(1, 1));
        assert_eq!(next_control(&mut outbound).await, ServerRecord::Restarting);
        until(|| logged(&daemon, "joined 1") == 1).await;
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(spawner.waited.lock().unwrap().as_slice(), &[16u8]);
        assert_eq!(daemon.log(), vec!["joined 1", "released 1"]);
    }

    /// Every shell record on `stream` that arrives within `window`.
    async fn records_within(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        stream: u8,
        window: std::time::Duration,
    ) -> Vec<ShellRecord> {
        let mut d = ShellDeframer::new();
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + window;
        while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            let msg = match msg {
                SessionOutbound::ChannelOutput {
                    stream: id, output, ..
                } if id == stream => {
                    out.extend(shell_record(output));
                    continue;
                }
                other => other,
            };
            if let SessionOutbound::Data(sd) = msg {
                if sd.stream_id == stream {
                    out.extend(d.push(&sd.data));
                }
            }
        }
        out
    }

    fn keystrokes(stream: u8, bytes: &[u8]) -> SessionInbound {
        SessionInbound::Data(StreamData {
            stream_id: stream,
            data: bytes.to_vec(),
        })
    }

    /// Spec §4.7.2 / §9.2: behind a closed gate a screen channel's output is
    /// absorbed by the model and dropped whole -- no `REC_DATA`, no echo ack;
    /// the `Writable` after the gate opens sends one repaint and an echo ack
    /// of everything consumed, unconditionally.
    #[tokio::test]
    async fn a_screen_channel_behind_a_closed_gate_drops_output_and_repaints_once_open() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );
        let _ = gates.gate(16, GateKind::Screen).update(200 * 1024);
        inbound.send(keystrokes(16, b"ls")).await.unwrap();
        spawner.feed(16, b"out1");
        spawner.feed(16, b"out2");
        let quiet = records_within(&mut outbound, 16, std::time::Duration::from_millis(300)).await;
        assert!(
            quiet.is_empty(),
            "nothing goes out behind a closed gate: {quiet:?}"
        );
        assert!(gates.gate(16, GateKind::Screen).update(0));
        inbound
            .send(SessionInbound::Writable { stream: 16 })
            .await
            .unwrap();
        let after = records_within(&mut outbound, 16, std::time::Duration::from_millis(300)).await;
        assert_eq!(
            after,
            vec![
                established_checkpoint(),
                ShellRecord::Data(b"REPAINT".to_vec()),
                ShellRecord::EchoAck(2)
            ]
        );
    }

    /// The first chunk after the gate reopened repaints in its place: the
    /// model already holds it.
    #[tokio::test]
    async fn the_first_chunk_after_a_screen_gate_reopens_is_sent_as_a_repaint() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        let _ = next_channel_data(&mut outbound, 16).await;
        let gate = gates.gate(16, GateKind::Screen);
        let _ = gate.update(200 * 1024);
        spawner.feed(16, b"dropped");
        let _ = records_within(&mut outbound, 16, std::time::Duration::from_millis(200)).await;
        let _ = gate.update(0);
        spawner.feed(16, b"new");
        let after = records_within(&mut outbound, 16, std::time::Duration::from_millis(300)).await;
        assert_eq!(
            after,
            vec![
                established_checkpoint(),
                ShellRecord::Data(b"REPAINT".to_vec()),
                ShellRecord::EchoAck(0)
            ]
        );
        spawner.feed(16, b"live again");
        assert_eq!(next_channel_data(&mut outbound, 16).await, b"live again");
    }

    /// Review Focus 1: a `ResumeReset` repaints every screen channel, so a
    /// stale one is stale no longer -- its next chunk is live output, not a
    /// second repaint.
    #[tokio::test]
    async fn a_resume_reset_repaint_clears_a_stale_screen_channel() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        let _ = next_channel_data(&mut outbound, 16).await;
        let gate = gates.gate(16, GateKind::Screen);
        let _ = gate.update(200 * 1024);
        spawner.feed(16, b"dropped");
        let _ = records_within(&mut outbound, 16, std::time::Duration::from_millis(200)).await;
        let _ = gate.force_open();
        inbound
            .send(SessionInbound::ResumeReset(channel_context()))
            .await
            .unwrap();
        assert_eq!(next_channel_data(&mut outbound, 16).await, b"REPAINT");
        spawner.feed(16, b"live");
        assert_eq!(next_channel_data(&mut outbound, 16).await, b"live");
    }

    /// Spec §4.7.2 / §9.2: a line channel's reader waits on its closed gate
    /// before reading -- the process blocks on its PTY -- and reads on once
    /// the gate opens.
    #[tokio::test]
    async fn a_line_channels_reader_stops_reading_behind_a_closed_gate() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 17).await,
            b"hello from the shell"
        );
        until(|| spawner.reads.load(Ordering::SeqCst) == 2).await; // waiting inside read
        let gate = gates.gate(17, GateKind::Pipe);
        let _ = gate.update(600 * 1024);
        spawner.feed(17, b"one"); // the read already under way returns it
        assert_eq!(next_channel_data(&mut outbound, 17).await, b"one");
        spawner.feed(17, b"two");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert_eq!(
            spawner.reads.load(Ordering::SeqCst),
            2,
            "no read behind a closed gate"
        );
        assert!(gate.update(0));
        assert_eq!(next_channel_data(&mut outbound, 17).await, b"two");
    }

    /// Counts, from now on, the messages carrying `stream`'s data, and
    /// passes everything on.
    fn counting(
        mut rx: tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        stream: u8,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        Arc<AtomicUsize>,
    ) {
        let count = Arc::new(AtomicUsize::new(0));
        let (tx, out) = tokio::sync::mpsc::unbounded_channel();
        let counted = Arc::clone(&count);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if matches!(&msg, SessionOutbound::ChannelOutput { stream: id, output: ChannelOutput::Data(_), .. } if *id == stream)
                {
                    counted.fetch_add(1, Ordering::SeqCst);
                }
                if tx.send(msg).is_err() {
                    return;
                }
            }
        });
        (out, count)
    }

    /// Spec §9.2: a line channel's closed gate holds back nothing of a
    /// screen channel -- its reader waits before reading, not in the shared
    /// queue -- while the line channel's own output stays in its process:
    /// of forty chunks at most the one its reader had under way goes out.
    #[tokio::test]
    async fn a_closed_line_gate_does_not_hold_back_a_screen_channel() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );
        let _ = next_channel_data(&mut outbound, 17).await;
        let (mut outbound, line_messages) = counting(outbound, 17);
        let _ = gates.gate(17, GateKind::Pipe).update(600 * 1024);
        for _ in 0..40 {
            spawner.feed(17, &[b'l'; 1024]); // one taken by the read under way, the rest wait
        }
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        assert_eq!(
            next_channel_data(&mut outbound, 16).await,
            b"hello from the shell"
        );
        spawner.feed(16, b"screen output");
        assert_eq!(next_channel_data(&mut outbound, 16).await, b"screen output");
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(
            line_messages.load(Ordering::SeqCst) <= 1,
            "the line channel's process holds the rest: {} chunks went out",
            line_messages.load(Ordering::SeqCst)
        );
    }

    /// Review Focus 2: a line channel closed while its reader waits on the
    /// gate -- the gate is closed for good, which wakes the reader, and the
    /// process is reaped.
    #[tokio::test]
    async fn closing_a_line_channel_wakes_its_reader_off_a_closed_gate() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );
        let _ = next_channel_data(&mut outbound, 17).await;
        until(|| spawner.reads.load(Ordering::SeqCst) == 2).await;
        let gate = gates.gate(17, GateKind::Pipe);
        let _ = gate.update(600 * 1024);
        spawner.feed(17, b"one");
        let _ = next_channel_data(&mut outbound, 17).await; // now waiting on the gate
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 17 }),
            }))
            .await
            .unwrap();
        until(|| gate.wait_open_for(std::time::Duration::ZERO) == GateWait::Closed).await;
        until(|| spawner.killed.lock().unwrap().contains(&17)).await;
        until(|| spawner.process_released(17)).await;
    }

    /// Opens line channel 17, shuts its gate and has its process write once
    /// more, so its reader goes on to wait on the shut gate. Returns the gate.
    async fn a_line_reader_waiting_on_its_gate(
        inbound: &tokio::sync::mpsc::Sender<SessionInbound>,
        outbound: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        gates: &crate::send_gate::GateTable,
        spawner: &FakeSpawner,
    ) -> Arc<SendGate> {
        inbound
            .send(open(17, ChannelKind::Command, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(outbound).await,
            ServerRecord::Opened { stream: 17 }
        );
        let _ = next_channel_data(outbound, 17).await;
        until(|| spawner.reads.load(Ordering::SeqCst) == 2).await;
        let gate = gates.gate(17, GateKind::Pipe);
        let _ = gate.update(600 * 1024);
        spawner.feed(17, b"one");
        assert_eq!(next_channel_data(outbound, 17).await, b"one");
        gate
    }

    /// Task 7 review: the session's end wakes a line channel's reader that
    /// waits on its shut gate -- the runner closes every gate before it
    /// reaps -- and the reader lets go of its process.
    #[tokio::test]
    async fn a_session_that_ends_wakes_a_line_reader_waiting_on_its_gate() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        let runner = tokio::spawn(run_channel_session(io, spawner.clone()));
        let gate =
            a_line_reader_waiting_on_its_gate(&inbound, &mut outbound, &gates, &spawner).await;
        drop(inbound);
        runner.await.unwrap();
        assert_eq!(
            gate.wait_open_for(std::time::Duration::ZERO),
            GateWait::Closed
        );
        until(|| spawner.process_released(17)).await;
        assert_eq!(spawner.killed.lock().unwrap().as_slice(), &[17u8]);
    }

    /// Task 7 review: the daemon's runtime dropped with a session still
    /// running -- its runner is dropped mid-loop and never reaps -- must not
    /// hang on a line channel's reader waiting on its shut gate: a runtime's
    /// drop waits for every blocking thread. The session's io closes the
    /// gates as it goes.
    #[test]
    fn dropping_the_runtime_under_a_line_reader_waiting_on_its_gate_does_not_hang() {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        rt.block_on(async {
            tokio::spawn(run_channel_session(io, spawner.clone()));
            let _ =
                a_line_reader_waiting_on_its_gate(&inbound, &mut outbound, &gates, &spawner).await;
        });
        let (dropped_tx, dropped_rx) = std_mpsc::channel::<()>();
        std::thread::spawn(move || {
            drop(rt);
            let _ = dropped_tx.send(());
        });
        dropped_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("the runtime drops: the reader woke off its gate");
        // Still here: the session did not end, the runtime went under it.
        drop(inbound);
    }

    /// Plays the bridge's part in delivery for a test that does not look at
    /// it: every `NotifyDelivered` is answered at once, as by a client that
    /// acknowledges everything the moment it is sent; everything else passes
    /// through as it came. The inbound sender is held weakly, so a test that
    /// drops its own still ends the session.
    fn auto_deliver(
        inbound: &tokio::sync::mpsc::Sender<SessionInbound>,
        mut outbound: tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
    ) -> tokio::sync::mpsc::UnboundedReceiver<SessionOutbound> {
        let weak = inbound.downgrade();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(msg) = outbound.recv().await {
                if let Some((stream_id, token, generation)) = delivery_marker(&msg) {
                    if let Some(inbound) = weak.upgrade() {
                        let _ = inbound
                            .send(SessionInbound::Delivered {
                                generation,
                                stream: stream_id,
                                token,
                            })
                            .await;
                    }
                    continue;
                }
                if tx.send(msg).is_err() {
                    return;
                }
            }
        });
        rx
    }

    /// What the runner sent, in order, as far as these tests care: channel
    /// records on `stream`, control records, and delivery requests.
    #[derive(Debug, PartialEq)]
    enum Seen {
        Record(ShellRecord),
        Control(ServerRecord),
        NotifyDelivered(u8),
    }

    /// The delivery requests the runner makes, `(stream, token)` in order,
    /// recorded as they pass; everything passes on.
    #[allow(clippy::type_complexity)]
    fn delivery_requests(
        mut rx: tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
    ) -> (
        tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        Arc<Mutex<Vec<(u8, u64)>>>,
    ) {
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (tx, out) = tokio::sync::mpsc::unbounded_channel();
        let seen = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                if let Some((stream_id, token, _)) = delivery_marker(&msg) {
                    seen.lock().unwrap().push((stream_id, token));
                }
                if tx.send(msg).is_err() {
                    return;
                }
            }
        });
        (out, requests)
    }

    /// The token of the latest delivery request for `stream`.
    fn token_for(requests: &Mutex<Vec<(u8, u64)>>, stream: u8) -> u64 {
        requests
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|(s, _)| *s == stream)
            .map(|(_, t)| *t)
            .expect("a delivery request for the stream")
    }

    /// Everything within `window`, in order.
    async fn seen_within(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<SessionOutbound>,
        stream: u8,
        window: std::time::Duration,
    ) -> Vec<Seen> {
        let mut records = ShellDeframer::new();
        let mut control = RecordDeframer::new();
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + window;
        while let Ok(Some(msg)) = tokio::time::timeout_at(deadline, rx.recv()).await {
            match msg {
                SessionOutbound::ChannelOutput {
                    stream: id,
                    output: ChannelOutput::DeliveryMarker(..),
                    ..
                } if id == stream => out.push(Seen::NotifyDelivered(id)),
                SessionOutbound::ChannelOutput {
                    stream: id, output, ..
                } if id == stream => out.extend(shell_record(output).map(Seen::Record)),
                SessionOutbound::ChannelExit { stream, code, .. } => {
                    out.push(Seen::Control(match code {
                        Some(code) => ServerRecord::Exit { stream, code },
                        None => ServerRecord::ExitStatusUnavailable { stream },
                    }))
                }
                SessionOutbound::Data(sd) if sd.stream_id == stream => {
                    out.extend(records.push(&sd.data).into_iter().map(Seen::Record));
                }
                SessionOutbound::Data(sd) if sd.stream_id == CONTROL_STREAM => {
                    for raw in control.push(&sd.data) {
                        out.push(Seen::Control(decode_server(&raw).expect("a server record")));
                    }
                }
                SessionOutbound::NotifyDelivered { stream_id, .. } => {
                    out.push(Seen::NotifyDelivered(stream_id));
                }
                _ => {}
            }
        }
        out
    }

    /// Review, Important 2: a channel's `Exit` goes on the control stream,
    /// which does not wait for the channel's own stream -- and on `Exit` the
    /// client drops whatever of the channel arrives after it. So the runner
    /// asks to hear when everything it put on the channel's stream is
    /// delivered, and says `Exit` only then.
    #[tokio::test]
    async fn a_channel_that_exits_says_so_only_once_its_output_is_delivered() {
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        spawner.feed(16, b"last words");
        spawner.end_channel(16);
        let before = seen_within(&mut outbound, 16, std::time::Duration::from_millis(300)).await;
        assert_eq!(
            before,
            vec![
                Seen::Record(established_checkpoint()),
                Seen::Record(ShellRecord::Data(b"hello from the shell".to_vec())),
                Seen::Record(ShellRecord::Data(b"last words".to_vec())),
                Seen::NotifyDelivered(16),
            ],
            "the output, then the request -- and no Exit yet"
        );
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: token_for(&requests, 16),
            })
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
    }

    /// Review, Important 2: a screen channel whose process ends while it is
    /// stale shows its last frame -- one repaint and the echo ack before its
    /// channel goes -- and the `Exit` waits for that to be delivered too.
    #[tokio::test]
    async fn a_stale_screen_channel_that_exits_repaints_and_then_says_so() {
        let (io, inbound, outbound, gates) = channel_pair_with_gates();
        let (mut outbound, requests) = delivery_requests(outbound);
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        let _ = next_channel_data(&mut outbound, 16).await;
        let _ = gates.gate(16, GateKind::Screen).update(200 * 1024);
        inbound.send(keystrokes(16, b"q")).await.unwrap();
        spawner.feed(16, b"the last frame");
        let _ = records_within(&mut outbound, 16, std::time::Duration::from_millis(200)).await;
        spawner.end_channel(16);
        let before = seen_within(&mut outbound, 16, std::time::Duration::from_millis(300)).await;
        assert_eq!(
            before,
            vec![
                Seen::Record(established_checkpoint()),
                Seen::Record(ShellRecord::Data(b"REPAINT".to_vec())),
                Seen::Record(ShellRecord::EchoAck(1)),
                Seen::NotifyDelivered(16),
            ]
        );
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: token_for(&requests, 16),
            })
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
    }

    /// A client that closes a channel whose exit is still on its way owes
    /// itself no `Exit` -- a `Close` is never answered -- and a stream number
    /// it opens again is a new channel no old `Exit` may end.
    #[tokio::test]
    async fn an_exit_still_waiting_is_dropped_by_a_close_or_a_reopen() {
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        for stream in [16, 17] {
            inbound
                .send(open(stream, ChannelKind::Shell, false))
                .await
                .unwrap();
            assert_eq!(
                next_control(&mut outbound).await,
                ServerRecord::Opened { stream }
            );
            spawner.end_channel(stream);
        }
        until(|| requests.lock().unwrap().len() == 2).await;
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();
        inbound
            .send(open(17, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 17 }
        );
        for stream in [16, 17] {
            inbound
                .send(SessionInbound::Delivered {
                    generation: 0,
                    stream,
                    token: token_for(&requests, stream),
                })
                .await
                .unwrap();
        }
        assert_no_control(&mut outbound).await;
    }

    /// Re-review, Minor 3: an answer to an earlier channel's delivery
    /// request -- the client closed that channel and opened the number again
    /// -- never releases the later channel's `Exit`; only the answer to its
    /// own request does.
    #[tokio::test]
    async fn a_late_answer_for_an_earlier_channel_never_releases_a_later_exit() {
        let (io, inbound, outbound) = channel_pair();
        let (mut outbound, requests) = delivery_requests(outbound);
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        spawner.end_channel(16);
        until(|| requests.lock().unwrap().len() == 1).await;
        let earlier = token_for(&requests, 16);
        inbound
            .send(SessionInbound::Data(StreamData {
                stream_id: CONTROL_STREAM,
                data: encode_client(&ClientRecord::Close { stream: 16 }),
            }))
            .await
            .unwrap();
        inbound
            .send(open(16, ChannelKind::Shell, false))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        spawner.end_channel(16);
        until(|| requests.lock().unwrap().len() == 2).await;
        let later = token_for(&requests, 16);
        assert_ne!(earlier, later, "each channel asks with its own token");
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: earlier,
            })
            .await
            .unwrap();
        assert_no_control(&mut outbound).await;
        inbound
            .send(SessionInbound::Delivered {
                generation: 0,
                stream: 16,
                token: later,
            })
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Exit {
                stream: 16,
                code: 0
            }
        );
    }

    /// Review, Minor 4: the echo ack tick does not go ahead of a pending
    /// repaint. The gate is open again but the channel is still stale -- no
    /// chunk and no `Writable` has come yet -- so the ack waits and goes out
    /// right after the repaint.
    #[tokio::test]
    async fn the_ack_tick_waits_while_a_repaint_is_pending() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        let _ = next_channel_data(&mut outbound, 16).await;
        let gate = gates.gate(16, GateKind::Screen);
        let _ = gate.update(200 * 1024);
        inbound.send(keystrokes(16, b"ab")).await.unwrap();
        spawner.feed(16, b"dropped");
        let _ = records_within(&mut outbound, 16, std::time::Duration::from_millis(200)).await;
        assert!(gate.update(0), "open again");
        let pending =
            records_within(&mut outbound, 16, std::time::Duration::from_millis(200)).await;
        assert!(
            pending.is_empty(),
            "the tick sends nothing ahead of the repaint: {pending:?}"
        );
        inbound
            .send(SessionInbound::Writable { stream: 16 })
            .await
            .unwrap();
        assert_eq!(
            records_within(&mut outbound, 16, std::time::Duration::from_millis(300)).await,
            vec![
                established_checkpoint(),
                ShellRecord::Data(b"REPAINT".to_vec()),
                ShellRecord::EchoAck(2)
            ]
        );
    }

    /// Review, Minor 4: a `Writable` that finds the gate shut again -- it
    /// reopened and closed before the runner got to it -- repaints nothing;
    /// the next one does.
    #[tokio::test]
    async fn a_writable_that_finds_the_gate_shut_again_waits_for_the_next() {
        let (io, inbound, mut outbound, gates) = channel_pair_with_gates();
        let spawner = FakeSpawner::new();
        tokio::spawn(run_channel_session(io, spawner.clone()));
        inbound
            .send(open(16, ChannelKind::Shell, true))
            .await
            .unwrap();
        assert_eq!(
            next_control(&mut outbound).await,
            ServerRecord::Opened { stream: 16 }
        );
        let _ = next_channel_data(&mut outbound, 16).await;
        let gate = gates.gate(16, GateKind::Screen);
        let _ = gate.update(200 * 1024);
        spawner.feed(16, b"dropped");
        let _ = records_within(&mut outbound, 16, std::time::Duration::from_millis(200)).await;
        inbound
            .send(SessionInbound::Writable { stream: 16 })
            .await
            .unwrap();
        let early = records_within(&mut outbound, 16, std::time::Duration::from_millis(200)).await;
        assert!(early.is_empty(), "no repaint behind a shut gate: {early:?}");
        assert!(gate.update(0));
        inbound
            .send(SessionInbound::Writable { stream: 16 })
            .await
            .unwrap();
        assert_eq!(
            records_within(&mut outbound, 16, std::time::Duration::from_millis(300)).await,
            vec![
                established_checkpoint(),
                ShellRecord::Data(b"REPAINT".to_vec()),
                ShellRecord::EchoAck(0)
            ]
        );
    }
}
