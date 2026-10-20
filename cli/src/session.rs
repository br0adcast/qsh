//! The client's behavior, as a state machine over events.
//!
//! Everything the client decides lives here: what to send, what to paint,
//! when to leave. Time arrives as a parameter rather than from a clock, and
//! nothing in this module touches a terminal or a socket -- so all of it is
//! testable by handing it events and reading back actions. The layers around
//! it (termios, signals, the socket) stay thin enough to have little left to
//! get wrong.

use client::channel::ChannelId;
use client::ShellState;
use prediction::DisplayPreference;
use render::{Renderer, TermCaps};
use terminal::MouseTracking;
use transport::channel_geometry::{
    ChannelInstance, GeometryOutcome, GeometryRecord, OutputGapCause, ResizeRefusal,
};
use transport::{LinkState, Stats};

use crate::args::PredictMode;
use crate::escape::{Command, Escape, Piece, Prefix};
use crate::mouse::MouseShift;
use crate::statusline::{self, Link};
use crate::window::{self, Boxed, Outcome, Roads, Row};
use crate::{overlay, status};

/// What the top row says while the link is gone and a reconnect is under way.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Plate {
    /// A round is trying `to`, or has not said where yet.
    Reconnecting { to: Option<String> },
    /// No round now; the next one starts at `until_ms`. `hint` says why every
    /// address failed, when there is one reason worth telling.
    Waiting { until_ms: i64, hint: Option<String> },
}

/// How long the size must hold still before the server hears about it.
/// Dragging a window edge produces dozens of SIGWINCH a second, and each
/// record costs an ioctl on the server's PTY plus a SIGWINCH inside the
/// remote application -- vim and htop redraw once per record.
const RESIZE_QUIET_MS: i64 = 130;

/// How often the status line's values may change (spec §8.1: once a
/// second, not on every tick).
const LINE_REFRESH_MS: i64 = 1_000;

/// Bound on `ShellChannel::Opening`'s queued keystrokes. The round trip to
/// confirm a channel is ordinarily far shorter than a human can type, but
/// nothing here can force the far side to ever answer at all -- and a real
/// terminal limits typeahead too. Past this many bytes, further keystrokes
/// are dropped rather than queued without bound.
const MAX_QUEUED_INPUT_BYTES: usize = 64 * 1024;

/// Everything that can happen to the client.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum UiEvent {
    /// Raw bytes read from the local keyboard.
    Stdin(Vec<u8>),
    /// Framed shell-output records for the shell channel, decoded from
    /// whichever wire stream `main` has bound it to.
    Stream0(Vec<u8>),
    /// The peer dropped its backlog on the shell channel; a repaint follows.
    StreamReset,
    /// The link changed state.
    Link(LinkState),
    /// An owner-provided network notification; the CLI installs no OS watcher.
    NetworkChanged,
    /// Fresh transport statistics (the round trip drives prediction).
    Stats(Stats),
    /// The local terminal changed size (SIGWINCH, already measured).
    Resized { cols: u16, rows: u16 },
    /// Returned from the background (SIGCONT).
    Resumed,
    /// A signal asking us to stop -- SIGTERM, SIGHUP, SIGINT or SIGQUIT:
    /// close down in an orderly way rather than dying where we stand.
    Terminate,
    /// A periodic nudge, so prediction can expire on time.
    Tick,
    /// Raw bytes newly arrived on a wire stream -- the session-control
    /// stream, or a channel's own. `Session` has no notion of streams or
    /// channels; `main` is the one that decodes this into the channel
    /// protocol (open/refuse/exit) and into `Stream0`/`StreamReset` for the
    /// shell channel's own output, so this variant only crosses the
    /// mpsc channel the driver thread and the main loop share -- `handle`
    /// itself never does anything with it.
    Wire { stream: u8, bytes: Vec<u8> },
    /// The peer dropped its backlog on a wire stream. Same reasoning as
    /// `Wire`: `main` decides whether the stream is the shell channel's own
    /// before this ever becomes a `StreamReset`.
    WireReset(u8),
    /// Reconnect round number `round` is trying `to` (a host). Shown only
    /// while the link is gone; `main` lets it through only while that round
    /// is the one under way.
    Reconnecting { round: u64, to: String },
    /// No round now; the next one starts at `until_ms` (on the session's
    /// clock). `hint`, when there is one, says what to do about it.
    ReconnectWaiting { until_ms: i64, hint: Option<String> },
    /// Owner-polled recovery activity; no worker may enqueue this event.
    RecoveryStatus {
        view: Option<crate::recovery_status::View>,
    },
    /// Roads as `main` sees them now, in command-line order; the one in use
    /// has `in_use` set.
    Roads { roads: Vec<window::Road> },
    /// The switch the window asked for is over.
    RoadSwitched { ok: bool },
    /// An event of connection number `link`, forwarded (see `background::forward`).
    /// `main` unwraps it; `Session::handle` ignores it.
    FromLink { link: u64, event: Box<UiEvent> },
}

/// What the caller must do. The session never performs an effect itself.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Action {
    /// Bytes for the local terminal.
    Write(Vec<u8>),
    /// Open the shell channel at this size. Emitted once, on the first
    /// `Live`.
    OpenShell { cols: u16, rows: u16 },
    /// Bytes for a channel.
    SendChannel { ch: ChannelId, bytes: Vec<u8> },
    /// Latest physical intent; hold wire submission until the debounce expires.
    DeferResize { cols: u16, rows: u16 },
    /// A new size for a channel.
    ResizeChannel { ch: ChannelId, cols: u16, rows: u16 },
    /// The authenticated resumed inventory no longer contains the tracked shell.
    /// The owner may offer replacement after restoring the terminal.
    ShellUnavailable,
    /// Leave with this exit code.
    Exit(i32),
    /// The person asked to reconnect now (`Ctrl-] r`).
    Reconnect,
    /// A line for the person, printed once the terminal is restored.
    Notice(String),
    /// Leave without ending the session on the server (`Ctrl-] .`): let the
    /// link go quietly.
    Keep,
    /// Move the traffic to this road (in a thread: it waits up to a second).
    UseRoad(std::net::SocketAddr),
}

/// The client's own chrome around the shell: the prefix, the status line
/// and how windows are drawn.
#[derive(Clone, Copy, Debug)]
pub struct Chrome {
    pub prefix: Prefix,
    /// The status line at the start (`--status`); `Ctrl-] h` toggles it.
    pub line: bool,
    pub glyphs: window::Glyphs,
}

/// The shell's size in a terminal of `cols` x `rows`: one row fewer when the
/// status line is shown. A terminal under two rows has no line (spec §8.1).
pub fn shell_size(cols: u16, rows: u16, line: bool) -> (u16, u16) {
    if cols == 0 || rows == 0 {
        return (80, 24);
    }
    let viewport = terminal_size::ViewportSize::new(cols, rows);
    let shell_rows = viewport.rows() - u16::from(line && viewport.rows() >= 2);
    let size = terminal_size::TerminalSize::for_viewport(viewport.cols(), shell_rows);
    (size.cols(), size.rows())
}

/// A window over the frame.
#[derive(Clone, Debug)]
enum Open {
    /// The connection-state window (`Ctrl-] s`).
    Roads(Roads),
    /// The key help (`Ctrl-] ?`).
    Help,
}

/// Where the client's one channel sits in its lifecycle. This client only
/// ever opens a shell -- never a second channel -- so a single field
/// captures "has one already been asked for" (so a repeat `Live`, a path
/// recovering rather than a fresh session, does not open a second), a place
/// to hold keyboard bytes typed before the far side confirms it, and, once
/// confirmed, which number to address it by.
#[derive(Clone, PartialEq, Eq, Debug)]
enum ShellChannel {
    /// Never asked to open one.
    Unopened,
    /// Asked; waiting for the far side to confirm or refuse it. `queued`
    /// holds keyboard bytes that arrived in the meantime: the round trip is
    /// ordinarily far shorter than a human can type, but a busy daemon can
    /// still stretch it long enough for a few keystrokes to land first, and
    /// dropping those silently would be a real, if rare, bug. Bounded by
    /// [`MAX_QUEUED_INPUT_BYTES`] -- a real terminal limits typeahead too.
    Opening { queued: Vec<u8> },
    /// Confirmed: this is the channel input, resizes, and the far side's
    /// own channel events all address.
    Ready(ChannelId),
    /// Final output is readable, but input and resize are closed.
    Draining(ChannelId),
    /// The link is gone: `ch` is the channel the shell had (when it was
    /// confirmed), for the reconnect to find again. Input goes nowhere.
    Detached { ch: Option<ChannelId> },
    /// A new connection reached the session; waiting for the server's list
    /// of what it still runs (`on_announced`). Input goes nowhere.
    Reattaching { ch: Option<ChannelId> },
}

pub struct Session {
    shell: ShellState,
    renderer: Renderer,
    rtt_ms: i64,
    /// The last frame actually handed to the renderer -- the COMPOSED one
    /// (`overlay::compose`: the status line, the plate, a window), since
    /// that is what the renderer actually saw. `Renderer::render` keeps
    /// repositioning the cursor on every call, even when nothing changed
    /// (`crates/render`'s own `an_unchanged_frame_produces_no_drawing` only
    /// promises no CONTENT redraw, not empty bytes) -- so deciding "is there
    /// anything worth painting" has to happen here, by comparing frames,
    /// before the renderer ever sees an unchanged one. Comparing the
    /// composed frame, not the raw one, matters while the link is down: the
    /// plate's seconds count changes every second even when the shell's own
    /// screen does not, and that must still repaint. `None` means the next
    /// paint must go through regardless of content, which is why this is
    /// reset alongside every `renderer.invalidate()` (`StreamReset`,
    /// `Resumed`, `Resized`, the link coming back up after `PathDown`) AND
    /// alongside `renderer.finish()` in `leave`: `finish` resets the
    /// renderer's own cache too, and puts the real terminal into a state
    /// (SGR reset, mirrored modes off, `\r\n`) this cache does not describe.
    last_frame: Option<terminal::Frame>,
    /// The TERMINAL's current size; the shell's is [`Session::size`].
    cols: u16,
    rows: u16,
    /// Actual physical extent; zero suppresses paint/RESIZE and a taller
    /// terminal disables physical-scroll shortcuts.
    raw_cols: u16,
    raw_rows: u16,
    logical_size: terminal_size::TerminalSize,
    desired_size: terminal_size::TerminalSize,
    geometry_instance: Option<ChannelInstance>,
    resize_notice: Option<String>,
    continuity_notice: Option<OutputGapCause>,
    /// The last shell size, waiting out `RESIZE_QUIET_MS`, and the moment it
    /// may go out.
    pending_size: Option<(u16, u16)>,
    resize_due_ms: i64,
    /// When the link went down, so the plate can count. `None` while the
    /// link is up; `Some` is also what "the link is `PathDown`" means for
    /// the status line.
    lost_since_ms: Option<i64>,
    /// What the top row says while a reconnect is under way; it wins over
    /// the `lost_since_ms` text.
    plate: Option<Plate>,
    /// The one channel this client ever opens.
    shell_channel: ShellChannel,
    chrome: Chrome,
    /// Splits keyboard input into what the shell gets and prefix commands.
    escape: Escape,
    /// Moves mouse reports up under the status line.
    mouse: MouseShift,
    /// Whether the person wants the status line: `chrome.line` at the start,
    /// then `Ctrl-] h`. It is shown only in a terminal of two rows or more.
    line_shown: bool,
    /// The window over the frame, if one is open.
    window: Option<Open>,
    /// The unfinished end of the last read while a window was open, read
    /// again in front of the next one: a key sequence cut in two (an arrow,
    /// `ESC [ 1 5 ~`) here, and after it, in `window_tail`, what
    /// `MouseShift::strip` left unfinished -- a mouse report or a paste
    /// marker. A lone trailing `ESC` is not held: it is the Esc key, which
    /// closes. When the window closes the key goes nowhere, but the
    /// `strip` part is handed back to `mouse`: it may be the cut end of a
    /// paste, and dropped it would leave the paste open for good.
    window_held: Vec<u8>,
    window_tail: Vec<u8>,
    /// The roads from the last snapshot, in command-line order.
    roads: Vec<window::Road>,
    recovery_view: Option<crate::recovery_status::View>,
    /// Seconds of silence on the road in use, from the last `Stats`.
    silent_secs: u64,
    /// What the status line says: the road in use
    /// and the link. Recomputed at most once a second (`LINE_REFRESH_MS`),
    /// and at once when the link, the plate or the line changes.
    line_view: (Option<String>, Link),
    line_refreshed_ms: i64,
    /// Whether the shell's own frame has mouse tracking on, as last painted.
    shell_mouse: bool,
    /// The selected history frame stays fixed until a navigation key arrives.
    history_frame: Option<terminal::Frame>,
    history_held: Vec<u8>,
    history_tail: Vec<u8>,
}

impl Session {
    pub fn new(
        cols: u16,
        rows: u16,
        caps: TermCaps,
        predict: PredictMode,
        chrome: Chrome,
    ) -> Session {
        let (shell_cols, shell_rows) = shell_size(cols, rows, chrome.line);
        Self::new_with_logical_size(
            (cols, rows),
            terminal_size::TerminalSize::new(shell_cols, shell_rows).expect("adapted shell size"),
            caps,
            predict,
            chrome,
        )
    }

    /// Start with the exact logical size already used to open the channel.
    /// In particular, an empty physical display retains the preceding size.
    pub fn new_with_logical_size(
        (cols, rows): (u16, u16),
        size: terminal_size::TerminalSize,
        caps: TermCaps,
        predict: PredictMode,
        chrome: Chrome,
    ) -> Self {
        let pref = match predict {
            PredictMode::Adaptive => DisplayPreference::Adaptive,
            PredictMode::Always => DisplayPreference::Always,
            PredictMode::Never => DisplayPreference::Never,
        };
        let (shell_cols, shell_rows) = (size.cols(), size.rows());
        Session {
            // `predict_overwrite` stays off: predicting
            // an overwrite is the prediction most often wrong on screen.
            shell: ShellState::new(shell_cols, shell_rows, pref, false),
            renderer: Renderer::new(caps),
            rtt_ms: 0,
            last_frame: None,
            cols: terminal_size::ViewportSize::new(cols, rows).cols(),
            rows: terminal_size::ViewportSize::new(cols, rows).rows(),
            raw_cols: cols,
            raw_rows: rows,
            logical_size: terminal_size::TerminalSize::new(shell_cols, shell_rows)
                .expect("adapted shell size"),
            desired_size: size,
            geometry_instance: None,
            resize_notice: None,
            continuity_notice: None,
            pending_size: None,
            resize_due_ms: 0,
            lost_since_ms: None,
            plate: None,
            shell_channel: ShellChannel::Unopened,
            chrome,
            escape: Escape::new(chrome.prefix),
            mouse: MouseShift::new(),
            line_shown: chrome.line,
            window: None,
            window_held: Vec::new(),
            window_tail: Vec::new(),
            roads: Vec::new(),
            recovery_view: None,
            silent_secs: 0,
            line_view: (None, Link::Unknown),
            line_refreshed_ms: 0,
            shell_mouse: false,
            history_frame: None,
            history_held: Vec::new(),
            history_tail: Vec::new(),
        }
    }

    pub fn handle(&mut self, ev: UiEvent, now_ms: i64) -> Vec<Action> {
        match ev {
            UiEvent::Stdin(bytes) => self.on_stdin(bytes, now_ms),
            UiEvent::Stream0(bytes) => {
                let frame = self.shell.on_stream0(&bytes, now_ms, self.rtt_ms);
                self.paint_at(&frame, now_ms)
            }
            UiEvent::StreamReset => {
                self.close_history();
                let frame = self.shell.on_reset();
                // Our idea of the screen came from a backlog the peer has
                // thrown away: diffing against it would paint nonsense.
                self.renderer.invalidate();
                self.last_frame = None;
                self.paint_at(&frame, now_ms)
            }
            UiEvent::Link(state) => self.on_link(state, now_ms),
            UiEvent::Stats(stats) => {
                self.rtt_ms = i64::from(stats.rtt_ms);
                self.silent_secs = u64::from(stats.silent_secs);
                Vec::new()
            }
            UiEvent::Resized { cols, rows } => self.on_resize(cols, rows, now_ms),
            UiEvent::Resumed => {
                // Job control typically clears bracketed paste and mouse
                // tracking, and something else has been drawing on this
                // terminal while we were stopped.
                self.renderer.invalidate();
                self.last_frame = None;
                self.repaint(now_ms)
            }
            UiEvent::Terminate => self.leave(0),
            UiEvent::Tick => self.on_tick(now_ms),
            // `main` intercepts these before they ever reach `handle`: it is
            // the one that knows what a stream number means, and decodes
            // them into the channel protocol or into `Stream0`/`StreamReset`
            // itself. They only pass through `UiEvent` because that is the
            // one channel the driver thread and the main loop already
            // share; a call landing here regardless has nothing to do.
            //
            // `FromLink` is the same kind of thing: `main` unwraps it.
            UiEvent::Wire { .. }
            | UiEvent::WireReset(_)
            | UiEvent::FromLink { .. }
            | UiEvent::NetworkChanged => Vec::new(),
            // Progress of a reconnect round shows only while the link is
            // gone; a late message from the background thread after the
            // return must not paint over a live session.
            UiEvent::Reconnecting { to, .. } => {
                self.set_plate(Plate::Reconnecting { to: Some(to) }, now_ms)
            }
            UiEvent::ReconnectWaiting { until_ms, hint } => {
                self.set_plate(Plate::Waiting { until_ms, hint }, now_ms)
            }
            UiEvent::RecoveryStatus { view } => {
                if self.recovery_view == view {
                    return Vec::new();
                }
                if view.is_none() {
                    self.clear_recovery_view();
                }
                self.recovery_view = view;
                self.repaint(now_ms)
            }
            UiEvent::Roads { roads } => {
                self.roads = roads;
                if matches!(self.window, Some(Open::Roads(_))) {
                    self.repaint(now_ms)
                } else {
                    Vec::new()
                }
            }
            UiEvent::RoadSwitched { ok } => self.on_road_switched(ok, now_ms),
        }
    }

    /// The raw physical extent, including an empty display.
    pub fn physical_size(&self) -> (u16, u16) {
        (self.raw_cols, self.raw_rows)
    }

    /// The validated logical shell size, retained through empty displays.
    pub fn size(&self) -> (u16, u16) {
        (self.logical_size.cols(), self.logical_size.rows())
    }

    /// The most recent nonempty physical viewport intent, not a remote result.
    pub fn desired_size(&self) -> (u16, u16) {
        (self.desired_size.cols(), self.desired_size.rows())
    }

    pub fn set_history_limit(&mut self, lines: usize) {
        self.shell.set_history_limit(lines);
    }

    /// Whether a window (the connection state or the help) is open: keys go
    /// to it, not to the shell.
    pub fn window_open(&self) -> bool {
        self.window.is_some()
    }

    /// Whether the status line is on screen now.
    fn line_on(&self) -> bool {
        self.line_shown && self.rows >= 2
    }

    fn on_tick(&mut self, now_ms: i64) -> Vec<Action> {
        let mut actions = self.due_resize(now_ms);
        let line_changed =
            now_ms - self.line_refreshed_ms >= LINE_REFRESH_MS && self.refresh_line(now_ms);
        if line_changed || self.lost_since_ms.is_some() || self.plate.is_some() {
            actions.extend(self.repaint(now_ms));
        }
        if let Some(frame) = self.shell.tick(now_ms, self.rtt_ms) {
            actions.extend(self.paint_at(&frame, now_ms));
        }
        actions
    }

    /// The link as the status line reports it now.
    fn link_now(&self, now_ms: i64) -> Link {
        match &self.plate {
            Some(Plate::Reconnecting { to }) => Link::Reconnecting { to: to.clone() },
            Some(Plate::Waiting { until_ms, hint }) => Link::Waiting {
                secs: seconds_until(*until_ms, now_ms),
                hint: hint.clone(),
            },
            None => statusline::link_of(
                self.rtt_ms.clamp(0, i64::from(u32::MAX)) as u32,
                self.silent_secs,
                self.lost_since_ms.is_some(),
            ),
        }
    }

    /// Recomputes what the status line says; whether it changed.
    fn refresh_line(&mut self, now_ms: i64) -> bool {
        self.line_refreshed_ms = now_ms;
        let road = self
            .roads
            .iter()
            .find(|r| r.in_use)
            .map(|r| r.label.clone());
        let view = (road, self.link_now(now_ms));
        let changed = view != self.line_view;
        self.line_view = view;
        changed
    }

    fn set_plate(&mut self, plate: Plate, now_ms: i64) -> Vec<Action> {
        if !matches!(self.shell_channel, ShellChannel::Detached { .. }) {
            return Vec::new();
        }
        self.plate = Some(plate);
        self.refresh_line(now_ms);
        self.repaint(now_ms)
    }

    /// Paints the shell's frame as it stands.
    fn repaint(&mut self, now_ms: i64) -> Vec<Action> {
        let frame = self.shell.frame(now_ms, self.rtt_ms);
        self.paint_at(&frame, now_ms)
    }

    /// The link is gone; a reconnect is under way. Input goes nowhere until
    /// `on_reattached`.
    pub fn on_link_gone(&mut self, now_ms: i64) -> Vec<Action> {
        self.lost_since_ms.get_or_insert(now_ms);
        let ch = match &self.shell_channel {
            ShellChannel::Ready(ch) | ShellChannel::Draining(ch) => Some(*ch),
            ShellChannel::Detached { ch } | ShellChannel::Reattaching { ch } => *ch,
            _ => None,
        };
        self.shell_channel = ShellChannel::Detached { ch };
        self.plate = Some(Plate::Reconnecting { to: None });
        self.refresh_line(now_ms);
        self.repaint(now_ms)
    }

    /// A new connection reached the same session: start over on it.
    pub fn on_reattached(&mut self, now_ms: i64) -> Vec<Action> {
        let frame = self.shell.on_reattach();
        self.renderer.invalidate();
        self.last_frame = None;
        self.plate = None;
        self.clear_recovery_view();
        self.lost_since_ms = None;
        // The last `Stats` were the dead link's: its silence and round trip
        // say nothing about the new one. Until the new link's own figures
        // come in, the line shows no link at all rather than a stale alarm.
        self.silent_secs = 0;
        self.rtt_ms = 0;
        self.refresh_line(now_ms);
        let ch = match &self.shell_channel {
            ShellChannel::Detached { ch } | ShellChannel::Reattaching { ch } => *ch,
            ShellChannel::Ready(ch) | ShellChannel::Draining(ch) => Some(*ch),
            _ => None,
        };
        self.shell_channel = ShellChannel::Reattaching { ch };
        self.paint_at(&frame, now_ms)
    }

    /// The server listed what it is running (a warm reattach).
    pub fn on_announced(&mut self, live: &[ChannelId], _now_ms: i64) -> Vec<Action> {
        let (cols, rows) = self.desired_size();
        if let ShellChannel::Reattaching { ch } = self.shell_channel {
            return match ch {
                Some(ch) if live.contains(&ch) => {
                    self.shell_channel = ShellChannel::Opening { queued: Vec::new() };
                    Vec::new()
                }
                _ => {
                    let mut actions = vec![
                        Action::Notice(status::shell_ended_text()),
                        Action::ShellUnavailable,
                    ];
                    actions.extend(self.leave(13));
                    actions
                }
            };
        }
        if live.is_empty() {
            // Our session came back, but everything in it has ended. Nothing
            // to adopt: open a shell the way a fresh session would.
            self.shell_channel = ShellChannel::Opening { queued: Vec::new() };
            vec![Action::OpenShell { cols, rows }]
        } else {
            // Only ordered Geometry establishes the retained shell's size.
            Vec::new()
        }
    }

    /// Reconcile both live processes and retained final-output lifecycles.
    pub fn on_snapshot(
        &mut self,
        active: &[ChannelId],
        draining: &[ChannelId],
        now_ms: i64,
    ) -> Vec<Action> {
        let present: Vec<_> = active.iter().chain(draining).copied().collect();
        self.on_announced(&present, now_ms)
    }

    pub fn on_channel_draining(&mut self, ch: ChannelId) {
        self.shell_channel = ShellChannel::Draining(ch);
        self.pending_size = None;
    }

    /// Called only after the channel owner validated lifecycle and geometry.
    pub fn on_geometry(&mut self, record: GeometryRecord, now_ms: i64) -> Vec<Action> {
        let Ok(size) = terminal_size::TerminalSize::new(record.cols, record.rows) else {
            return vec![
                Action::Notice("qsh: shell channel has no valid PTY geometry".into()),
                Action::Exit(1),
            ];
        };
        if self.geometry_instance != Some(record.instance) {
            self.geometry_instance = Some(record.instance);
            self.resize_notice = None;
            self.continuity_notice = None;
        } else if record.outcome == GeometryOutcome::Applied {
            self.resize_notice = None;
        }
        if self.logical_size != size {
            self.logical_size = size;
            self.history_frame = None;
        }
        let frame = self.shell.geometry_frame(record.cols, record.rows, now_ms);
        self.renderer.invalidate();
        self.last_frame = None;
        self.paint_at(&frame, now_ms)
    }

    pub fn on_resize_refused(&mut self, reason: ResizeRefusal, now_ms: i64) -> Vec<Action> {
        let reason = match reason {
            ResizeRefusal::InvalidSize => "invalid size",
            ResizeRefusal::NoPty => "no PTY",
            ResizeRefusal::ResourceLimit => "resource limit",
            ResizeRefusal::PtyResizeFailed => "PTY resize failed",
            ResizeRefusal::ScreenPreparationFailed => "screen preparation failed",
        };
        let (cols, rows) = self.size();
        self.resize_notice = Some(format!("Resize refused: {reason}; terminal remains {cols}x{rows}. Change the window size to retry."));
        self.repaint(now_ms)
    }

    pub fn on_output_gap(&mut self, cause: OutputGapCause, now_ms: i64) -> Vec<Action> {
        let terminal_failure = cause == OutputGapCause::TerminalReplyFailure;
        let first_terminal_failure = terminal_failure
            && self.continuity_notice != Some(OutputGapCause::TerminalReplyFailure);
        if terminal_failure || self.continuity_notice.is_none() {
            self.continuity_notice = Some(cause);
        }
        let mut actions = self.repaint(now_ms);
        if first_terminal_failure {
            actions.push(Action::Notice(
                "qsh: the server could not deliver terminal replies; the channel was stopped and some output may be missing".into(),
            ));
        }
        actions
    }

    fn live_notice(&self) -> Option<&str> {
        self.resize_notice.as_deref().or_else(|| {
            self.continuity_notice.map(|cause| match cause {
                OutputGapCause::PreviousConnectionOutputUnconfirmed => {
                    "Output continuity lost: some previous output was not confirmed."
                }
                OutputGapCause::TerminalReplyFailure => {
                    "Terminal replies failed: channel stopped; some output may be missing."
                }
            })
        })
    }

    /// Marks the shell channel as already requested, without emitting an
    /// `OpenShell` action for it: for when the caller opened it itself
    /// before this `Session` even existed. `climb::settle_opening` does
    /// exactly that, during the connection trial, so the far side's
    /// `Opened` confirmation can flip a candidate key's verdict the moment
    /// it arrives instead of the client waiting out the full auth deadline
    /// in silence -- see its own doc for why. A login that resumed the
    /// session its token names opened nothing on purpose, and is told the
    /// same: the server announces the channels it still runs, and the shell
    /// is bound from that list (`on_announced`, then `on_channel_ready`).
    ///
    /// A no-op once the channel is already `Opening` or `Ready`: called
    /// right after `Session::new`, so in practice it only ever fires once.
    /// A caller that opened nothing (the defensive case where the trial's
    /// own `open_shell` returned `None`) must not call this unless the login
    /// resumed a session -- the server announces its channels then; without
    /// that, the later, real `on_link(Live)` replaying the same transition
    /// from the queued events would wrongly skip opening a channel that was
    /// never actually requested.
    pub fn assume_channel_opening(&mut self) {
        if self.shell_channel == ShellChannel::Unopened {
            self.shell_channel = ShellChannel::Opening { queued: Vec::new() };
        }
    }

    /// The far side confirmed the shell channel: input may flow from now on.
    /// Flushes whatever was typed and queued while it was still `Opening`,
    /// through the exact same path an immediate keystroke takes -- so a
    /// queued keystroke's echo is predicted just like any other, only later.
    pub fn on_channel_ready(&mut self, ch: ChannelId, now_ms: i64) -> Vec<Action> {
        let queued = match std::mem::replace(&mut self.shell_channel, ShellChannel::Ready(ch)) {
            ShellChannel::Opening { queued } => queued,
            _ => Vec::new(),
        };
        if self.raw_cols != 0
            && self.raw_rows != 0
            && self.desired_size != self.logical_size
            && self.pending_size.is_none()
        {
            self.pending_size = Some(self.desired_size());
        }
        let mut actions = self.due_resize(now_ms);
        if !queued.is_empty() {
            actions.extend(self.send_now(ch, queued, now_ms));
        }
        actions
    }

    /// The channel's process ended with `code`. Silent for a channel this
    /// session is not (or is no longer) tracking: a stale or duplicate event
    /// for a stream that is not the one shell channel it ever opened.
    pub fn on_channel_exit(&mut self, ch: ChannelId, code: i32, _now_ms: i64) -> Vec<Action> {
        match &self.shell_channel {
            ShellChannel::Ready(known) | ShellChannel::Draining(known) if *known == ch => {
                self.leave(code)
            }
            // A refusal arrives before the channel is ever `Ready` -- there
            // is no confirmed number to compare against yet, only the one
            // channel this session is waiting on, so any `ch` here is it.
            ShellChannel::Opening { .. } => self.leave(code),
            _ => Vec::new(),
        }
    }

    /// The remote child ended, but its status was lost. The local failure code
    /// must not be represented as an exit status supplied by the remote process.
    pub fn on_channel_exit_status_unavailable(&mut self, ch: ChannelId) -> Vec<Action> {
        let tracked = match &self.shell_channel {
            ShellChannel::Ready(known) | ShellChannel::Draining(known) => *known == ch,
            ShellChannel::Opening { .. } => true,
            _ => false,
        };
        if !tracked {
            return Vec::new();
        }
        let mut actions = vec![Action::Notice(
            "qsh: the remote process ended, but its exit status is unavailable".into(),
        )];
        actions.extend(self.leave(1));
        actions
    }

    /// Splits keyboard bytes into input and prefix commands (spec §8.3), in
    /// order. Input goes to the shell, or to the window while one is open.
    fn on_stdin(&mut self, bytes: Vec<u8>, now_ms: i64) -> Vec<Action> {
        let mut actions = Vec::new();
        for piece in self.escape.feed(&bytes) {
            match piece {
                Piece::Input(input) => actions.extend(self.on_input(input, now_ms)),
                Piece::Command(Command::Leave) => {
                    // Leaving on the user's own instruction is not a shell
                    // that exited: code 1, not 0. The session stays on the
                    // server.
                    actions.push(Action::Keep);
                    actions.extend(self.leave(1));
                    return actions;
                }
                Piece::Command(Command::Reconnect) => {
                    // What came before goes first. What follows in the same
                    // read is dropped: it belongs to the link about to be
                    // let go, and sent or predicted now it would only be
                    // painted after the plate the reconnect puts up.
                    actions.push(Action::Reconnect);
                    return actions;
                }
                Piece::Command(Command::Window) => {
                    let open = match self.window {
                        Some(_) => None,
                        None => Some(Open::Roads(Roads::new())),
                    };
                    actions.extend(self.set_window(open, now_ms));
                }
                Piece::Command(Command::Help) => {
                    let open = match self.window {
                        Some(Open::Help) => None,
                        _ => Some(Open::Help),
                    };
                    actions.extend(self.set_window(open, now_ms));
                }
                Piece::Command(Command::ToggleLine) => actions.extend(self.toggle_line(now_ms)),
                Piece::Command(Command::Scroll) => {
                    self.close_window();
                    self.shell.set_history_view(true);
                    self.history_frame = Some(self.shell.frame(now_ms, self.rtt_ms));
                    actions.extend(self.repaint(now_ms));
                }
            }
        }
        actions
    }

    /// Keyboard input that is not a prefix command.
    fn on_input(&mut self, input: Vec<u8>, now_ms: i64) -> Vec<Action> {
        if self.window.is_some() {
            return self.on_window_input(input, now_ms);
        }
        if self.history_frame.is_some() {
            return self.on_history_input(input, now_ms);
        }
        let shift = u16::from(self.line_on() && self.shell_mouse);
        let shell_rows = self
            .rows
            .saturating_sub(shift)
            .min(self.logical_size.rows());
        let input = self.mouse.apply_bounded(
            &input,
            shift,
            self.cols.min(self.logical_size.cols()),
            shell_rows,
        );
        if input.is_empty() {
            return Vec::new();
        }
        self.queue_or_send(input, now_ms)
    }

    fn close_history(&mut self) {
        self.history_frame = None;
        self.history_held.clear();
        self.mouse.hand_back(std::mem::take(&mut self.history_tail));
        self.shell.set_history_view(false);
    }

    fn on_history_input(&mut self, input: Vec<u8>, now_ms: i64) -> Vec<Action> {
        let mut held = std::mem::take(&mut self.history_held);
        held.append(&mut self.history_tail);
        held.extend(input);
        let (bytes, tail) = self.mouse.strip(&held);
        self.history_tail = tail;
        let mut i = 0;
        while i < bytes.len() {
            let len = if bytes[i] == 0x1b && matches!(bytes.get(i + 1), Some(b'[' | b'O')) {
                let Some(len) = crate::escape::sequence_len(&bytes[i..]) else {
                    self.history_held.extend_from_slice(&bytes[i..]);
                    break;
                };
                len
            } else {
                1
            };
            let page = i32::from(self.size().1);
            let delta = match &bytes[i..i + len] {
                b"q" | b"\x1b" => {
                    self.close_history();
                    return self.repaint(now_ms);
                }
                b"\x1b[A" | b"\x1bOA" => 1,
                b"\x1b[B" | b"\x1bOB" => -1,
                b"\x1b[5~" => page,
                b"\x1b[6~" => -page,
                b"\x1b[H" | b"\x1bOH" | b"\x1b[1~" | b"\x1b[7~" | b"g" => i32::MAX,
                b"\x1b[F" | b"\x1bOF" | b"\x1b[4~" | b"\x1b[8~" | b"G" => -i32::MAX,
                _ => 0,
            };
            if delta != 0 {
                self.history_frame = Some(self.shell.scroll_frame(delta, now_ms, self.rtt_ms));
            }
            i += len;
        }
        self.repaint(now_ms)
    }

    /// Opens `open` (or closes the window with `None`) and repaints.
    fn set_window(&mut self, open: Option<Open>, now_ms: i64) -> Vec<Action> {
        self.close_window();
        self.window = open;
        self.repaint(now_ms)
    }

    /// Closes the window, if one is open: a key it held goes nowhere, and
    /// the unfinished report or paste marker `strip` left goes back to
    /// `mouse`, to be read in front of the next bytes wherever they go.
    fn close_window(&mut self) {
        self.window = None;
        self.window_held.clear();
        self.mouse.hand_back(std::mem::take(&mut self.window_tail));
    }

    /// Keys for the open window. The help closes on any key, and the key
    /// goes nowhere; the connection-state window reads arrows, digits,
    /// `Enter`, `Esc` and `q`. What follows a key that closes the window in
    /// the same read goes nowhere either.
    fn on_window_input(&mut self, input: Vec<u8>, now_ms: i64) -> Vec<Action> {
        let mut held = std::mem::take(&mut self.window_held);
        held.append(&mut self.window_tail);
        held.extend_from_slice(&input);
        // Mouse reports and pastes are not key presses: they never drive a
        // window (an SGR report's digits would pick rows, a pasted `2\r`
        // would switch roads).
        let (mut bytes, tail) = self.mouse.strip(&held);
        // A key sequence cut off at the end waits, whole, for the rest.
        let (keys, cut) = window::keys(&bytes);
        self.window_held = bytes.split_off(bytes.len() - cut);
        self.window_tail = tail;
        if bytes.is_empty() {
            return Vec::new();
        }
        if matches!(self.window, Some(Open::Help)) {
            return self.set_window(None, now_ms);
        }
        if self.recovery_view.is_some() {
            let count = window::recovery_lines(
                &self.recovery_details(now_ms),
                self.cols,
                self.chrome.glyphs.utf8,
            )
            .len();
            let max = count.saturating_sub(window::road_capacity(
                self.cols,
                self.rows.saturating_sub(1),
            ));
            for key in keys {
                let Some(Open::Roads(state)) = &mut self.window else {
                    break;
                };
                state.switching = None;
                state.selected = state.selected.min(max);
                match key {
                    window::Key::Up => state.selected = state.selected.saturating_sub(1),
                    window::Key::Down => state.selected = (state.selected + 1).min(max),
                    window::Key::Close => self.close_window(),
                    _ => {}
                }
            }
            return self.repaint(now_ms);
        }
        let rows = self.visible_rows();
        let mut actions = Vec::new();
        for key in keys {
            let Some(Open::Roads(state)) = &mut self.window else {
                break;
            };
            clamp_selection(state, rows.len());
            match state.on_key(key, &rows) {
                Outcome::Stay => {}
                Outcome::Close => self.close_window(),
                Outcome::Switch(i) => actions.push(Action::UseRoad(self.roads[i].addr)),
            }
        }
        actions.extend(self.repaint(now_ms));
        actions
    }

    fn on_road_switched(&mut self, ok: bool, now_ms: i64) -> Vec<Action> {
        let Some(Open::Roads(state)) = &mut self.window else {
            return Vec::new();
        };
        if ok {
            // As in the app: a switch that worked closes the window.
            return self.set_window(None, now_ms);
        }
        state.switching = None;
        self.repaint(now_ms)
    }

    /// The window's rows as the person can see them: one per road, cut to
    /// what the box has room for on this terminal (none when it does not
    /// fit at all). Keys act on these only, so `Enter` never switches to a
    /// road out of sight.
    fn visible_rows(&self) -> Vec<Row> {
        let link = &self.line_view.1;
        let mut rows: Vec<Row> = self.roads.iter().map(|r| window::row(r, link)).collect();
        let shown = window::road_capacity(self.cols, self.rows);
        rows.truncate(shown);
        rows
    }

    /// The open window's box, its selection first kept on a visible row.
    ///
    /// A window the terminal is too small to draw is closed rather than
    /// left open out of sight, where it would swallow every key typed.
    fn window_box(&mut self) -> Option<Boxed> {
        let boxed = self.draw_window();
        if boxed.is_none() {
            self.close_window();
        }
        boxed
    }

    fn draw_window(&mut self) -> Option<Boxed> {
        let (cols, rows, glyphs) = (self.cols, self.rows, self.chrome.glyphs);
        match &self.window {
            None => None,
            Some(Open::Help) => {
                let name = self.chrome.prefix.name().unwrap_or_default();
                window::help_box(&name, cols, rows, glyphs)
            }
            Some(Open::Roads(state)) if self.recovery_view.is_some() => {
                let mut boxed = window::recovery_box(
                    &self.recovery_details(self.line_refreshed_ms),
                    state,
                    cols,
                    rows.saturating_sub(1),
                    glyphs,
                )?;
                boxed.top += 1;
                Some(boxed)
            }
            Some(Open::Roads(_)) => {
                let visible = self.visible_rows().len();
                let link = self.line_view.1.clone();
                let all: Vec<Row> = self.roads.iter().map(|r| window::row(r, &link)).collect();
                let Some(Open::Roads(state)) = &mut self.window else {
                    return None;
                };
                clamp_selection(state, visible);
                window::roads_box(&all, state, cols, rows, glyphs)
            }
        }
    }

    /// `Ctrl-] h`: the line goes or comes back, and the shell's size with it.
    fn toggle_line(&mut self, now_ms: i64) -> Vec<Action> {
        let before = self.desired_size();
        self.line_shown = !self.line_shown;
        self.refresh_line(now_ms);
        if self.raw_cols == 0
            || self.raw_rows == 0
            || shell_size(self.cols, self.rows, self.line_shown) == before
        {
            // An empty display or unchanged logical geometry.
            return self.repaint(now_ms);
        }
        self.apply_shell_size(now_ms)
    }

    /// Sends keyboard bytes to the shell channel once it is confirmed, or
    /// queues them if it is not there yet -- see `ShellChannel::Opening`'s
    /// own doc for why a queue and not a drop. Bytes typed before the
    /// channel is even `Opening` (the link itself is not `Live` yet) are
    /// dropped: rare enough, and remote enough from the far side ever
    /// existing at all, that it is not worth a place to hold them.
    fn queue_or_send(&mut self, bytes: Vec<u8>, now_ms: i64) -> Vec<Action> {
        let ready = match &self.shell_channel {
            ShellChannel::Ready(ch) => Some(*ch),
            _ => None,
        };
        if let Some(ch) = ready {
            return self.send_now(ch, bytes, now_ms);
        }
        if let ShellChannel::Opening { queued } = &mut self.shell_channel {
            let room = MAX_QUEUED_INPUT_BYTES.saturating_sub(queued.len());
            let take = bytes.len().min(room);
            queued.extend_from_slice(&bytes[..take]);
        }
        Vec::new()
    }

    /// Sends `bytes` to the confirmed channel `ch` right now, and predicts
    /// their echo. The one place that actually calls
    /// `Action::SendChannel` -- both an immediate keystroke and a queue
    /// flushed by `on_channel_ready` go through here, so both get their
    /// echo predicted the same way.
    fn send_now(&mut self, ch: ChannelId, bytes: Vec<u8>, now_ms: i64) -> Vec<Action> {
        let mut actions = vec![Action::SendChannel {
            ch,
            bytes: bytes.clone(),
        }];
        let frame = self.shell.on_input(&bytes, now_ms, self.rtt_ms);
        actions.extend(self.paint_at(&frame, now_ms));
        actions
    }

    fn on_link(&mut self, state: LinkState, now_ms: i64) -> Vec<Action> {
        match state {
            // The link fell away without the shell channel ever reporting
            // its own exit: no channel-protocol message said why, so this is
            // the same "no way to guess" situation the old single-stream
            // client faced for every close. With channels this is now the
            // RARE path -- the ordinary end is `on_channel_exit`, which
            // carries the shell's real code and leaves before the link even
            // gets a chance to fall to `Closed` (the client closes the
            // connection itself right after handling that exit). This arm
            // still leaves 0, not 1: 1 is not exclusively the user's own
            // `Ctrl-] .` any more (`main.rs` also reports a channel refusal
            // as `on_channel_exit(ch, 1, ..)`), but both of those are
            // "left without the ordinary way ever happening", which this
            // `Closed` path is not -- it is the ordinary way, just with no
            // real code to report.
            LinkState::Closed => self.leave(0),
            LinkState::PathDown => {
                if self.lost_since_ms.is_none() {
                    self.lost_since_ms = Some(now_ms);
                }
                self.refresh_line(now_ms);
                self.repaint(now_ms)
            }
            LinkState::Live | LinkState::Connecting => {
                if state == LinkState::Live {
                    self.clear_recovery_view();
                }
                let was_lost = self.lost_since_ms.take().is_some();
                let line_changed = self.refresh_line(now_ms);
                let mut actions = if was_lost {
                    // The plate covered a row of the shell's screen; the
                    // renderer must not diff the row it is about to uncover
                    // against the plate it painted there.
                    self.renderer.invalidate();
                    self.last_frame = None;
                    self.repaint(now_ms)
                } else if line_changed {
                    self.repaint(now_ms)
                } else {
                    Vec::new()
                };
                if matches!(state, LinkState::Live) && self.shell_channel == ShellChannel::Unopened
                {
                    self.shell_channel = ShellChannel::Opening { queued: Vec::new() };
                    let (cols, rows) = self.desired_size();
                    actions.push(Action::OpenShell { cols, rows });
                }
                actions
            }
        }
    }

    fn on_resize(&mut self, cols: u16, rows: u16, now_ms: i64) -> Vec<Action> {
        let restored = (self.raw_cols == 0 || self.raw_rows == 0) && cols != 0 && rows != 0;
        self.raw_cols = cols;
        self.raw_rows = rows;
        let viewport = terminal_size::ViewportSize::new(cols, rows);
        self.cols = viewport.cols();
        self.rows = viewport.rows();
        let mut actions = self.apply_shell_size(now_ms);
        if restored {
            let (cols, rows) = self.desired_size();
            self.pending_size = Some((cols, rows));
            self.resize_due_ms = now_ms + RESIZE_QUIET_MS;
            if !actions.contains(&Action::DeferResize { cols, rows }) {
                actions.insert(0, Action::DeferResize { cols, rows });
            }
        }
        actions
    }

    /// Physical intent for transfer, including a zero viewport's send suspension.
    pub fn deferred_size(&self) -> (u16, u16) {
        if self.raw_cols == 0 || self.raw_rows == 0 {
            (0, 0)
        } else {
            self.desired_size()
        }
    }

    /// Project the committed grid immediately, but debounce only the request.
    /// Physical movement never commits a remote size or reflows shell output.
    fn apply_shell_size(&mut self, now_ms: i64) -> Vec<Action> {
        if self.raw_cols == 0 || self.raw_rows == 0 {
            self.pending_size = None;
            self.renderer.invalidate();
            self.last_frame = None;
            return vec![Action::DeferResize { cols: 0, rows: 0 }];
        }
        let (cols, rows) = shell_size(self.cols, self.rows, self.line_shown);
        let desired = terminal_size::TerminalSize::new(cols, rows).expect("adapted shell size");
        let changed = self.desired_size != desired;
        if changed {
            self.desired_size = desired;
            self.resize_notice = None;
            self.pending_size = Some((cols, rows));
            self.resize_due_ms = now_ms + RESIZE_QUIET_MS;
        }
        let frame = self.shell.frame(now_ms, self.rtt_ms);
        // The size changed, so the renderer's idea of the screen is the wrong
        // shape: a diff against it would be meaningless.
        self.renderer.invalidate();
        self.last_frame = None;
        let mut actions = self.paint_at(&frame, now_ms);
        if changed {
            actions.insert(0, Action::DeferResize { cols, rows });
        }
        actions
    }

    /// The resize action, if the size has held still long enough AND the
    /// channel is confirmed. A settled size that arrives before the channel
    /// is `Ready` simply waits: the next `Tick` past the debounce re-checks
    /// both conditions, so nothing is lost, only delayed.
    fn due_resize(&mut self, now_ms: i64) -> Vec<Action> {
        match (self.pending_size, &self.shell_channel) {
            (Some((cols, rows)), ShellChannel::Ready(ch)) if now_ms >= self.resize_due_ms => {
                let ch = *ch;
                self.pending_size = None;
                vec![Action::ResizeChannel { ch, cols, rows }]
            }
            _ => Vec::new(),
        }
    }

    /// The resize action regardless of the clock -- for the way out, where
    /// there is no later tick to wait for. Dropped in silence if the channel
    /// was never confirmed: leaving, there is nowhere left to send it.
    fn flush_resize(&mut self) -> Vec<Action> {
        match (self.pending_size.take(), &self.shell_channel) {
            (Some((cols, rows)), ShellChannel::Ready(ch)) => {
                vec![Action::ResizeChannel {
                    ch: *ch,
                    cols,
                    rows,
                }]
            }
            _ => Vec::new(),
        }
    }

    /// The plate's text, when the line is hidden and the link is in trouble.
    fn plate_text(&self, now_ms: i64) -> Option<String> {
        let prefix = self.chrome.prefix.name();
        let prefix = prefix.as_deref();
        match (&self.plate, self.lost_since_ms) {
            (Some(Plate::Reconnecting { to }), _) => {
                Some(status::reconnecting_text(to.as_deref(), prefix))
            }
            (Some(Plate::Waiting { until_ms, hint }), _) => Some(status::waiting_text(
                seconds_until(*until_ms, now_ms),
                prefix,
                hint.as_deref(),
            )),
            (None, Some(since)) => Some(status::lost_text(
                ((now_ms - since).max(0) / 1000) as u64,
                prefix,
            )),
            (None, None) => None,
        }
    }

    fn recovery_details(&self, now_ms: i64) -> Vec<String> {
        let age = self
            .lost_since_ms
            .map_or(0, |since| ((now_ms - since).max(0) / 1000) as u64)
            .max(self.silent_secs);
        let mut details = vec![format!("Outage: {}", statusline::human_age(age))];
        if let Some(view) = &self.recovery_view {
            details.extend(view.details());
        }
        details
    }

    fn clear_recovery_view(&mut self) {
        if self.recovery_view.take().is_some() && matches!(self.window, Some(Open::Roads(_))) {
            self.close_window();
        }
    }

    fn outage(&self) -> bool {
        self.recovery_view.is_some()
            || self.lost_since_ms.is_some()
            || matches!(
                self.line_view.1,
                Link::Silent { .. } | Link::Reconnecting { .. } | Link::Waiting { .. }
            )
    }

    fn recovery_cells(&self) -> Vec<terminal::Cell> {
        if let Some(view) = &self.recovery_view {
            let left = statusline::left_part(self.chrome.prefix.name().as_deref());
            return statusline::recovery_row(
                self.cols,
                &left,
                &view.header_spans(),
                self.chrome.glyphs.colour,
                self.chrome.glyphs.utf8,
            );
        }
        let text = self.plate_text(self.line_refreshed_ms).unwrap_or_else(|| {
            statusline::right_part(self.line_view.0.as_deref(), &self.line_view.1).0
        });
        statusline::recovery_line(
            self.cols,
            &text,
            self.chrome.glyphs.colour,
            self.chrome.glyphs.utf8,
        )
    }

    /// The status line's cells, as `line_view` says.
    fn line_cells(&self) -> Vec<terminal::Cell> {
        if let Some(notice) = self.live_notice() {
            return statusline::recovery_line(
                self.cols,
                notice,
                self.chrome.glyphs.colour,
                self.chrome.glyphs.utf8,
            );
        }
        if self.recovery_view.is_some() {
            return self.recovery_cells();
        }
        let left = statusline::left_part(self.chrome.prefix.name().as_deref());
        let (road, link) = &self.line_view;
        let (right, alarm) = if self.history_frame.is_some() && !self.outage() {
            (
                statusline::scroll_part(self.shell.display_offset(), self.shell.history_size()),
                false,
            )
        } else {
            statusline::right_part(road.as_deref(), link)
        };
        if matches!(link, Link::Latency { .. } | Link::Silent { .. })
            && self.history_frame.is_none()
        {
            statusline::connected_line(
                self.cols,
                &left,
                &right,
                alarm,
                self.chrome.glyphs.colour,
                self.chrome.glyphs.utf8,
            )
        } else {
            statusline::line(self.cols, &left, &right, alarm, self.chrome.glyphs.colour)
        }
    }

    /// Paints `frame` with the client's chrome: the status line above it
    /// (or, with the line hidden, the plate over its top row while the link
    /// is in trouble) and the open window on top. All of it goes onto a
    /// COPY, on the way to the renderer (`overlay::compose`): `frame` is (or
    /// came from) the screen model, and chrome inside it would survive the
    /// reason for it.
    ///
    /// Skips the renderer entirely when the composed copy is exactly the
    /// last one painted, since `Renderer::render` still emits
    /// cursor-placement bytes on every call even when there is nothing to
    /// draw. `last_frame` is `None` right after `renderer.invalidate()`, so
    /// an invalidated renderer always goes through regardless of content.
    fn paint_at(&mut self, frame: &terminal::Frame, now_ms: i64) -> Vec<Action> {
        if self.raw_cols == 0 || self.raw_rows == 0 {
            return Vec::new();
        }
        let mut history = self.history_frame.clone();
        if let Some(h) = &mut history {
            if h.cols != frame.cols || h.rows != frame.rows {
                *h = frame.clone();
                self.history_frame = Some(h.clone());
            }
            h.cursor_visible = false;
            h.mouse_tracking = MouseTracking::Off;
            h.mouse_sgr = false;
            h.app_cursor = false;
            h.app_keypad = false;
        }
        let frame = history.as_ref().unwrap_or(frame);
        let projected = crate::viewport::project_padded(
            frame,
            terminal_size::ViewportSize::new(self.cols, self.rows - u16::from(self.line_on())),
        );
        let frame = &projected;
        self.shell_mouse = frame.mouse_tracking != MouseTracking::Off;
        // The hidden-status alarm replaces the entire top row on a copy; it
        // must also remain visible while local scrollback is being inspected.
        let alarm = if !self.line_on() && self.outage() {
            let mut copy = frame.clone();
            if copy.rows > 0 {
                for (cell, alarm) in copy
                    .cells
                    .iter_mut()
                    .take(usize::from(copy.cols))
                    .zip(self.recovery_cells())
                {
                    *cell = alarm;
                }
            }
            Some(copy)
        } else {
            None
        };
        let frame = alarm.as_ref().unwrap_or(frame);
        let line = self.line_on().then(|| self.line_cells());
        let plate = if !self.line_on() && self.live_notice().is_some() {
            self.live_notice().map(str::to_owned)
        } else if self.line_on() || alarm.is_some() {
            None
        } else if self.history_frame.is_some() {
            Some(statusline::scroll_part(
                self.shell.display_offset(),
                self.shell.history_size(),
            ))
        } else {
            self.plate_text(now_ms)
        };
        let boxed = self.window_box();
        let mut shown = overlay::compose(frame, line.as_deref(), plate.as_deref(), boxed.as_ref());
        if self.recovery_view.is_some() && matches!(self.window, Some(Open::Roads(_))) {
            // Recovery details reserve row zero: keep its activity contrast
            // while the shell behind the window is dimmed.
            for cell in shown.cells.iter_mut().take(usize::from(shown.cols)) {
                cell.flags &= !terminal::FLAG_DIM;
            }
        }
        if self.last_frame.as_ref() == Some(&shown) {
            return Vec::new();
        }
        self.renderer
            .set_physical_scroll_eligible(shown.rows == self.raw_rows);
        let bytes = self.renderer.render(&shown);
        self.last_frame = Some(shown);
        if bytes.is_empty() {
            Vec::new()
        } else {
            vec![Action::Write(bytes)]
        }
    }

    /// Bytes that hand the terminal back ahead of a stop (SIGTSTP): what
    /// `leave` writes, without leaving. The next paint after `Resumed` is a
    /// full one, the mirrored modes with it.
    pub fn suspend(&mut self) -> Vec<u8> {
        self.last_frame = None;
        self.renderer.finish()
    }

    fn leave(&mut self, code: i32) -> Vec<Action> {
        // A resize still waiting out the debounce must not be swallowed: it
        // is what keeps a warm reconnect from resuming at the wrong size.
        let mut actions = self.flush_resize();
        let bytes = self.renderer.finish();
        // `finish` resets the renderer's own idea of the screen; ours has to
        // go with it, or a `handle` call reached after `Exit` (a duplicate
        // `Link(Closed)`, or a runtime-loop bug) could see a frame equal to
        // the pre-exit one and conclude there is nothing left to paint --
        // even though `finish` just put the real terminal into a different
        // state than that frame describes.
        self.last_frame = None;
        actions.push(Action::Write(bytes));
        actions.push(Action::Exit(code));
        actions
    }
}

/// Keeps the window's selection on one of the `visible` rows: a snapshot can
/// shrink between polls, and a short terminal clips rows.
fn clamp_selection(state: &mut Roads, visible: usize) {
    state.selected = state.selected.min(visible.saturating_sub(1));
}

/// Whole seconds from `now_ms` to `until_ms`, rounded up, never negative.
fn seconds_until(until_ms: i64, now_ms: i64) -> u64 {
    let left = (until_ms - now_ms).max(0);
    ((left + 999) / 1000) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use render::TermCaps;

    #[test]
    fn stage6_boundary_geometry_clears_predictions_even_at_the_same_size() {
        let mut s = Session::new(20, 5, TermCaps::truecolor(), PredictMode::Always, plain());
        s.on_link(LinkState::Live, 0);
        s.on_channel_ready(16, 0);
        s.handle(UiEvent::Stdin(b"predicted".to_vec()), 10);
        assert!(s.shell.prediction_active());
        s.on_geometry(
            GeometryRecord {
                instance: ChannelInstance::new(1).unwrap(),
                request_id: 0,
                outcome: GeometryOutcome::Established,
                cols: 20,
                rows: 5,
            },
            11,
        );
        assert!(!s.shell.prediction_active());
    }

    #[test]
    fn stage6_intent_physical_change_defers_immediately_and_zero_suspends() {
        let mut s = ready_session();
        assert!(s.on_resize(100, 30, 0).contains(&Action::DeferResize {
            cols: 100,
            rows: 30
        }));
        assert!(s
            .on_resize(0, 0, 1)
            .contains(&Action::DeferResize { cols: 0, rows: 0 }));
        assert!(control(&s.on_tick(1000)).is_empty());
        assert!(s.on_resize(100, 30, 1001).contains(&Action::DeferResize {
            cols: 100,
            rows: 30
        }));
        assert!(s.on_tick(1200).contains(&Action::ResizeChannel {
            ch: 16,
            cols: 100,
            rows: 30
        }));
    }

    #[test]
    fn committed_geometry_and_live_notices_do_not_feed_resize() {
        let mut s = wide_ready_session();
        let record = GeometryRecord {
            instance: ChannelInstance::new(1).unwrap(),
            request_id: 0,
            outcome: GeometryOutcome::Established,
            cols: 80,
            rows: 5,
        };
        s.on_geometry(record, 0);
        s.on_resize(100, 30, 10);
        s.due_resize(200);
        let refused = GeometryRecord {
            request_id: 1,
            outcome: GeometryOutcome::Refused(ResizeRefusal::ResourceLimit),
            ..record
        };
        s.on_geometry(refused, 210);
        let notice = s.on_resize_refused(ResizeRefusal::ResourceLimit, 211);
        assert!(row0(&notice, 100, 30).contains("Resize refused: resource limit"));
        assert_eq!(s.size(), (80, 5));
        assert_eq!(s.desired_size(), (100, 30));
        for now in [300, 1000, 5000] {
            assert!(control(&s.on_tick(now)).is_empty());
            assert!(control(&s.on_resize(100, 30, now)).is_empty());
            assert!(control(&s.on_announced(&[16], now)).is_empty());
        }
        s.on_resize(120, 40, 5100);
        s.on_geometry(
            GeometryRecord {
                request_id: 2,
                outcome: GeometryOutcome::Applied,
                cols: 120,
                rows: 40,
                ..record
            },
            5300,
        );
        assert_eq!(s.size(), (120, 40));
        assert!(s.resize_notice.is_none());
    }

    #[test]
    fn draining_snapshot_preserves_final_output_without_input_or_resize() {
        let mut s = session();
        s.assume_channel_opening();
        assert!(s.on_snapshot(&[], &[16], 0).is_empty());
        s.on_channel_draining(16);
        assert!(sent(&s.handle(UiEvent::Stdin(b"no".to_vec()), 1)).is_empty());
        s.on_resize(30, 7, 2);
        assert!(control(&s.on_tick(1000)).is_empty());
        assert!(s.on_channel_exit(16, 37, 1001).contains(&Action::Exit(37)));
    }

    #[test]
    fn physical_resize_only_changes_projection_while_pending() {
        let mut s = ready_session();
        let committed = s.size();
        let _ = s.on_resize(100, 30, 10);
        assert_eq!(
            s.size(),
            committed,
            "a local viewport is not remote geometry"
        );
        let frame = s.shell.frame(10, 0);
        assert_eq!((frame.cols, frame.rows), committed);
        let shown = s.last_frame.as_ref().unwrap();
        assert_eq!((shown.cols, shown.rows), (100, 30));
        assert!(s.due_resize(1000).contains(&Action::ResizeChannel {
            ch: 16,
            cols: 100,
            rows: 30,
        }));
        assert_eq!(s.size(), committed, "sending does not commit geometry");
    }

    #[test]
    fn warm_announced_never_sends_a_blind_resize() {
        let mut s = ready_session();
        s.on_link_gone(10);
        s.on_reattached(20);
        let actions = s.on_announced(&[16], 30);
        assert!(
            control(&actions).is_empty(),
            "metadata is not a resize result: {actions:?}"
        );
    }

    #[test]
    fn physical_extents_have_bounded_coherent_logical_sizes() {
        for (cols, rows, expected) in [(1, 1, (2, 1)), (1, 2, (2, 1)), (65535, 65535, (512, 256))] {
            let mut s = Session::new(
                cols,
                rows,
                TermCaps::truecolor(),
                PredictMode::Never,
                Chrome {
                    line: true,
                    ..plain()
                },
            );
            assert_eq!(s.size(), expected);
            let actions = s.on_link(LinkState::Live, 0);
            assert!(actions.contains(&Action::OpenShell {
                cols: expected.0,
                rows: expected.1
            }));
            assert_eq!(
                (s.shell.frame(0, 0).cols, s.shell.frame(0, 0).rows),
                expected
            );
        }
    }

    #[test]
    fn empty_physical_extent_retains_size_without_paint_or_resize() {
        let mut s = ready_session();
        let before = s.size();
        assert_eq!(
            s.on_resize(0, 0, 10),
            vec![Action::DeferResize { cols: 0, rows: 0 }]
        );
        assert_eq!(s.size(), before);
        assert!(s
            .on_tick(1000)
            .iter()
            .all(|a| !matches!(a, Action::Write(_) | Action::ResizeChannel { .. })));
        let s = Session::new(0, 0, TermCaps::truecolor(), PredictMode::Never, plain());
        assert_eq!(s.size(), (80, 24));
    }

    #[test]
    fn one_column_projection_hides_clipped_wide_glyphs_and_cursor() {
        for glyph in ['界', '😀'] {
            let mut s = Session::new(1, 2, TermCaps::truecolor(), PredictMode::Never, plain());
            let mut f = terminal::Frame::blank(2, 2);
            f.cells[0].ch = glyph;
            f.cells[0].flags = terminal::FLAG_WIDE;
            f.cells[1].flags = terminal::FLAG_WIDE_SPACER;
            f.cursor_col = 1;
            s.paint_at(&f, 0);
            let shown = s.last_frame.unwrap();
            assert_eq!((shown.cols, shown.rows), (1, 2));
            assert_eq!(shown.cells[0], terminal::Cell::blank());
            assert!(!shown.cursor_visible);
        }
    }

    #[test]
    fn status_toggle_recomputes_one_size_and_zero_notifications_keep_it() {
        let mut s = ready_session();
        let committed = s.size();
        s.on_resize(1, 2, 10);
        assert_eq!(s.desired_size(), (2, 2));
        s.toggle_line(20);
        assert_eq!(s.desired_size(), (2, 1));
        assert_eq!(
            (s.shell.frame(20, 0).cols, s.shell.frame(20, 0).rows),
            committed
        );
        assert!(s.due_resize(1000).contains(&Action::ResizeChannel {
            ch: 16,
            cols: 2,
            rows: 1
        }));
        let f = s.last_frame.as_ref().unwrap();
        assert_eq!((f.cols, f.rows), (1, 2));
        s.on_resize(0, 2, 1010);
        s.toggle_line(1020);
        assert_eq!(s.desired_size(), (2, 1));
        assert!(s.due_resize(2000).is_empty());
        s.on_resize(1, 2, 2010);
        assert_eq!(s.desired_size(), (2, 2));
    }

    #[test]
    fn replacement_with_empty_display_keeps_the_open_channels_logical_size() {
        let size = terminal_size::TerminalSize::new(42, 7).unwrap();
        let mut s = Session::new_with_logical_size(
            (0, 0),
            size,
            TermCaps::truecolor(),
            PredictMode::Never,
            Chrome {
                line: true,
                ..plain()
            },
        );
        assert_eq!(s.physical_size(), (0, 0));
        assert_eq!(s.size(), (42, 7));
        assert_eq!(
            (s.shell.frame(0, 0).cols, s.shell.frame(0, 0).rows),
            (42, 7)
        );
        assert!(s.repaint(0).is_empty());
        assert!(s
            .on_link(LinkState::Live, 0)
            .contains(&Action::OpenShell { cols: 42, rows: 7 }));
    }

    #[test]
    fn empty_viewport_suppresses_warm_reattach_resize() {
        let mut s = ready_session();
        s.on_resize(0, 0, 10);
        s.on_link_gone(20);
        s.on_reattached(30);
        assert!(s
            .on_announced(&[16], 40)
            .iter()
            .all(|a| !matches!(a, Action::ResizeChannel { .. })));
    }

    #[test]
    fn physical_size_transitions_clear_exterior_without_large_frames() {
        let mut s = ready_session();
        for (cols, rows) in [(65535, 65535), (1, 1), (80, 24)] {
            let actions = s.on_resize(cols, rows, 10);
            assert!(actions.iter().any(
                |a| matches!(a, Action::Write(bytes) if bytes.windows(4).any(|w| w == b"\x1b[2J"))
            ));
            let f = s.last_frame.as_ref().unwrap();
            assert!(f.cols <= 512 && f.rows <= 257 && f.cells.len() <= 512 * 257);
        }
    }

    // An independent physical sink: unlike TerminalCore this accepts width one.
    // It checks emitted addressing and printable Unicode widths, including
    // delayed right-margin wrap, without reusing projection/model geometry.
    fn assert_physical_output(bytes: &[u8], width: usize, height: usize) {
        use unicode_width::UnicodeWidthChar;
        let text = std::str::from_utf8(bytes).unwrap();
        let mut chars = text.chars().peekable();
        let (mut x, mut y) = (0, 0);
        while let Some(ch) = chars.next() {
            match ch {
                '\x1b' => {
                    if chars.next() == Some('[') {
                        let mut args = String::new();
                        let final_ch = loop {
                            let ch = chars.next().expect("terminated CSI");
                            if ('@'..='~').contains(&ch) {
                                break ch;
                            }
                            args.push(ch);
                        };
                        if final_ch == 'H' || final_ch == 'f' {
                            let mut coordinates = args
                                .split(';')
                                .map(|s| s.parse::<usize>().unwrap_or(1).max(1) - 1);
                            y = coordinates.next().unwrap_or(0);
                            x = coordinates.next().unwrap_or(0);
                            assert!(
                                x < width && y < height,
                                "address ({x},{y}) outside {width}x{height}"
                            );
                        }
                    }
                }
                '\r' => x = 0,
                '\n' => {
                    y += 1;
                    assert!(y < height, "unexpected physical scroll");
                }
                ch if !ch.is_control() => {
                    let advance = ch.width().unwrap_or(0);
                    if advance > 0 {
                        if x == width {
                            x = 0;
                            y += 1;
                        }
                        assert!(
                            y < height && x + advance <= width,
                            "glyph {ch:?} crosses physical edge at ({x},{y})"
                        );
                        x += advance;
                    }
                }
                _ => {}
            }
        }
    }

    #[test]
    fn one_column_sink_accepts_shell_status_help_and_recovery_output() {
        for height in [1, 2] {
            for line in [false, true] {
                let mut s = Session::new(
                    1,
                    height,
                    TermCaps::truecolor(),
                    PredictMode::Never,
                    Chrome { line, ..plain() },
                );
                for mode in 0..4 {
                    s.window = match mode {
                        1 => Some(Open::Help),
                        3 => Some(Open::Roads(Roads::new())),
                        _ => None,
                    };
                    if mode >= 2 {
                        s.recovery_view = Some(recovery_view());
                    }
                    for glyph in ['x', '界', '😀'] {
                        let mut f = terminal::Frame::blank(2, s.size().1);
                        f.cells[0].ch = glyph;
                        if glyph != 'x' {
                            f.cells[0].flags = terminal::FLAG_WIDE;
                            f.cells[1].flags = terminal::FLAG_WIDE_SPACER;
                        }
                        f.cursor_col = 1;
                        s.renderer.invalidate();
                        s.last_frame = None;
                        for action in s.paint_at(&f, mode) {
                            if let Action::Write(bytes) = action {
                                assert_physical_output(&bytes, 1, height as usize);
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn unicode_chrome_respects_physical_cell_widths() {
        for width in 1..=20 {
            let shell = terminal::Frame::blank(width, 7);
            let line = statusline::line(width, "", "界😀reconnecting", true, true);
            let help = window::help_box("界😀", width, 7, plain().glyphs);
            let recovery = window::recovery_box(
                &["界😀recovery details".into()],
                &Roads::new(),
                width,
                7,
                plain().glyphs,
            );
            let rows = [Row {
                label: "界😀server".into(),
                in_use: true,
                value: "42 ms".into(),
                dot: window::Dot::InUse,
                can_switch: false,
            }];
            let roads = window::roads_box(&rows, &Roads::new(), width, 7, plain().glyphs);
            let frames = [
                overlay::compose(&shell, Some(&line), None, None),
                overlay::compose(&shell, None, Some("界😀reconnecting"), None),
                overlay::compose(&shell, None, None, help.as_ref()),
                overlay::compose(&shell, None, None, recovery.as_ref()),
                overlay::compose(&shell, None, None, roads.as_ref()),
            ];
            for frame in frames {
                let mut renderer = Renderer::new(TermCaps::truecolor());
                assert_physical_output(
                    &renderer.render(&frame),
                    width as usize,
                    frame.rows as usize,
                );
            }
        }
    }

    /// The chrome the older tests were written against: the default prefix,
    /// no status line, one address.
    fn plain() -> Chrome {
        Chrome {
            prefix: crate::escape::DEFAULT_PREFIX,
            line: false,
            glyphs: crate::window::Glyphs {
                utf8: true,
                colour: true,
            },
        }
    }

    fn session() -> Session {
        Session::new(20, 5, TermCaps::truecolor(), PredictMode::Never, plain())
    }

    /// A session with its one channel already open and confirmed by the far
    /// side, at channel 16 -- ready to accept keyboard input and send
    /// resizes, the way a real session is after `Live` and the server's
    /// `Opened`.
    fn ready_session() -> Session {
        let mut s = session();
        let _ = s.on_link(LinkState::Live, 0);
        let _ = s.on_channel_ready(16, 0);
        s
    }

    fn recovery_view() -> crate::recovery_status::View {
        use crate::recovery_status::{QshState, Target, View};
        View {
            targets: (1..=12)
                .map(|i| Target {
                    host: format!("host-{i}.example"),
                    label: format!("host-{i}.example:60000"),
                    endpoint: None,
                    qsh: QshState::Trying,
                    ssh: None,
                })
                .collect(),
        }
    }

    #[test]
    fn recovery_keeps_the_help_hint_in_its_normal_columns() {
        let mut s = lined(100, 8);
        s.on_link(LinkState::Live, 0);
        let normal = s.line_cells();
        let hint = " Ctrl-] ? ";
        assert_eq!(
            normal
                .iter()
                .take(hint.len())
                .map(|c| c.ch)
                .collect::<String>(),
            hint
        );
        let mut view = recovery_view();
        view.targets.truncate(1);
        s.handle(UiEvent::RecoveryStatus { view: Some(view) }, 1);
        for cols in [100, 40, 20] {
            s.handle(UiEvent::Resized { cols, rows: 8 }, 2);
            let cells = &s.last_frame.as_ref().unwrap().cells[..usize::from(cols)];
            let text: String = cells.iter().map(|c| c.ch).collect();
            assert!(text.starts_with(hint), "{text:?}");
            assert_eq!(cells[hint.len()].ch, ' ');
            assert!(cells.iter().all(|c| c.bg == terminal::Color::Indexed(1)));
            if cols == 100 {
                assert!(
                    text.ends_with("reconnecting: host-1.example [QSH]"),
                    "{text:?}"
                );
                assert!(!text.contains("s details"));
                assert!(!text.contains(". exit"));
            } else {
                assert_eq!(cells.last().unwrap().ch, '…');
            }
        }
        s.on_reattached(3);
        assert_eq!(
            s.line_cells()
                .iter()
                .take(hint.len())
                .map(|c| c.ch)
                .collect::<String>(),
            hint
        );
    }

    #[test]
    fn recovery_details_keep_elapsed_outage_time() {
        let mut s = lined(80, 8);
        s.on_link_gone(1_000);
        s.handle(
            UiEvent::RecoveryStatus {
                view: Some(recovery_view()),
            },
            1_000,
        );
        assert_eq!(s.recovery_details(6_000)[0], "Outage: 5 s");
        assert_eq!(s.recovery_details(66_000)[0], "Outage: 1 min");
    }

    #[test]
    fn recovery_details_are_scrollable_and_never_switch_roads() {
        let mut s = lined(80, 8);
        s.on_link_gone(0);
        s.handle(
            UiEvent::RecoveryStatus {
                view: Some(recovery_view()),
            },
            1,
        );
        s.handle(UiEvent::Stdin(b"\x1ds".to_vec()), 2);
        assert!(
            s.last_frame.as_ref().unwrap().cells[..80]
                .iter()
                .all(|c| c.bg == terminal::Color::Indexed(1)),
            "details must not cover the outage row"
        );
        assert!(
            s.last_frame.as_ref().unwrap().cells[..80]
                .iter()
                .all(|c| c.flags & terminal::FLAG_DIM == 0),
            "details must preserve active protocol brightness"
        );
        for now in 3..40 {
            s.handle(UiEvent::Stdin(b"\x1b[B".to_vec()), now);
        }
        let text: String = s
            .draw_window()
            .unwrap()
            .lines
            .iter()
            .flatten()
            .map(|c| c.ch)
            .collect();
        assert!(text.contains("host-12.example"), "{text}");
        let actions = s.handle(UiEvent::Stdin(b"\r".to_vec()), 40);
        assert!(!actions.iter().any(|a| matches!(a, Action::UseRoad(_))));
        assert!(sent(&actions).is_empty());
        s.on_reattached(41);
        assert!(
            !s.window_open(),
            "success dismisses read-only recovery details"
        );
    }

    #[test]
    fn recovery_alarm_covers_hidden_status_and_scrollback_and_resizes_without_rotating() {
        for line in [false, true] {
            let mut s = Session::new(
                40,
                6,
                TermCaps::truecolor(),
                PredictMode::Never,
                Chrome { line, ..plain() },
            );
            s.on_link(LinkState::Live, 0);
            s.on_channel_ready(16, 0);
            s.on_link_gone(1);
            s.history_frame = Some(terminal::Frame::blank(40, s.size().1));
            s.handle(
                UiEvent::RecoveryStatus {
                    view: Some(recovery_view()),
                },
                2,
            );
            let top = s.last_frame.as_ref().unwrap().cells[..40].to_vec();
            assert!(top
                .iter()
                .map(|c| c.ch)
                .collect::<String>()
                .starts_with(" Ctrl-] ?  reconnecting:"));
            assert!(top.iter().all(|c| c.bg == terminal::Color::Indexed(1)));
            assert_eq!(top[39].ch, '…');
            s.handle(UiEvent::Tick, 10_000);
            assert_eq!(s.last_frame.as_ref().unwrap().cells[..40], top);
            s.handle(UiEvent::Resized { cols: 9, rows: 6 }, 10_001);
            assert_eq!(s.last_frame.as_ref().unwrap().cell(0, 8).ch, '…');
            s.on_reattached(10_002);
            assert!(s.recovery_view.is_none());
            assert!(s.last_frame.as_ref().unwrap().cells[..9]
                .iter()
                .all(|c| c.bg != terminal::Color::Indexed(1)));
        }
    }

    fn sent(actions: &[Action]) -> Vec<u8> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::SendChannel { bytes, .. } => Some(bytes.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    fn written(actions: &[Action]) -> Vec<u8> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Write(b) => Some(b.clone()),
                _ => None,
            })
            .flatten()
            .collect()
    }

    /// A stream-0 data record as the server sends it: `type(1) | len(u32 BE)
    /// | payload`. `ShellState` deframes it; feeding raw bytes here would
    /// test a protocol we do not speak.
    fn record(payload: &[u8]) -> Vec<u8> {
        let mut v = vec![0u8];
        v.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn session_with_history() -> Session {
        let mut chrome = plain();
        chrome.line = true;
        let mut s = Session::new(40, 6, TermCaps::truecolor(), PredictMode::Never, chrome);
        s.on_link(LinkState::Live, 0);
        s.on_channel_ready(16, 0);
        let output: String = (1..=40).map(|n| format!("line{n:03}\r\n")).collect();
        s.handle(UiEvent::Stream0(record(output.as_bytes())), 1);
        s
    }

    fn shown_row(s: &Session, row: u16) -> String {
        let f = s.last_frame.as_ref().expect("painted frame");
        (0..f.cols).map(|c| f.cell(row, c).ch).collect()
    }

    #[test]
    fn scroll_mode_enters_and_navigation_stays_on_the_client() {
        let mut s = session_with_history();
        let live = shown_row(&s, 1);
        let actions = s.handle(UiEvent::Stdin(b"\x1d[".to_vec()), 2);
        assert!(sent(&actions).is_empty());
        assert!(shown_row(&s, 0).contains("scroll: 0/36"));
        for (key, offset) in [
            (b"\x1b[A".as_slice(), 1),
            (b"\x1b[5~".as_slice(), 6),
            (b"\x1b[B".as_slice(), 5),
            (b"\x1b[6~".as_slice(), 0),
            (b"\x1b[H".as_slice(), 36),
            (b"\x1b[F".as_slice(), 0),
            (b"g".as_slice(), 36),
            (b"G".as_slice(), 0),
        ] {
            let actions = s.handle(UiEvent::Stdin(key.to_vec()), 3);
            assert!(sent(&actions).is_empty(), "scroll keys are local: {key:?}");
            assert_eq!(s.shell.display_offset(), offset, "key {key:?}");
        }
        assert_eq!(shown_row(&s, 1), live);
        s.handle(UiEvent::Stdin(b"\x1b[5~".to_vec()), 4);
        assert_ne!(shown_row(&s, 1), live);
        let actions = s.handle(UiEvent::Stdin(b"qignored".to_vec()), 5);
        assert!(sent(&actions).is_empty(), "the closing read is local too");
        assert_eq!(shown_row(&s, 1), live);
        assert!(!shown_row(&s, 0).contains("scroll:"));
        assert_eq!(sent(&s.handle(UiEvent::Stdin(b"x".to_vec()), 6)), b"x");
    }

    #[test]
    fn scroll_mode_keeps_the_view_when_output_arrives_even_at_the_bottom() {
        for key in [b"".as_slice(), b"\x1b[5~".as_slice()] {
            let mut s = session_with_history();
            s.handle(UiEvent::Stdin(b"\x1d[".to_vec()), 2);
            s.handle(UiEvent::Stdin(key.to_vec()), 3);
            let before = s.last_frame.as_ref().unwrap().cells[40..].to_vec();
            s.handle(UiEvent::Stream0(record(b"new001\r\nnew002\r\n")), 4);
            assert_eq!(s.last_frame.as_ref().unwrap().cells[40..], before);
            let offset = if key.is_empty() { 2 } else { 7 };
            assert!(shown_row(&s, 0).contains(&format!("scroll: {offset}/38")));
            s.handle(UiEvent::Stdin(b"\x1b".to_vec()), 5);
            assert_eq!(s.shell.display_offset(), 0);
            assert!(shown_row(&s, 4).contains("new002"));
        }
    }

    #[test]
    fn scroll_mode_reads_a_split_arrow_and_drops_pastes() {
        let mut s = session_with_history();
        s.handle(UiEvent::Stdin(b"\x1d[".to_vec()), 2);
        assert!(sent(&s.handle(UiEvent::Stdin(b"\x1b[".to_vec()), 3)).is_empty());
        s.handle(UiEvent::Stdin(b"A".to_vec()), 4);
        assert_eq!(s.shell.display_offset(), 1);
        s.handle(UiEvent::Stdin(b"\x1b[200~qgG\x1b[201~".to_vec()), 5);
        assert!(shown_row(&s, 0).contains("scroll: 1/36"));
    }

    #[test]
    fn scroll_mode_reset_discards_the_history_and_returns_live() {
        let mut s = session_with_history();
        s.handle(UiEvent::Stdin(b"\x1d[g".to_vec()), 2);
        s.handle(UiEvent::StreamReset, 3);
        assert_eq!(s.shell.display_offset(), 0);
        assert!(!shown_row(&s, 0).contains("scroll:"));
        s.handle(UiEvent::Stdin(b"\x1d[".to_vec()), 4);
        assert!(shown_row(&s, 0).contains("no history"));
    }

    #[test]
    fn scroll_mode_can_go_home_repeatedly_and_zero_disables_history() {
        let mut s = session_with_history();
        s.handle(UiEvent::Stdin(b"\x1d[gg".to_vec()), 2);
        assert_eq!(s.shell.display_offset(), 36);
        s.handle(UiEvent::Stdin(b"q".to_vec()), 3);
        s.set_history_limit(0);
        s.handle(
            UiEvent::Stream0(record(b"a\r\nb\r\nc\r\nd\r\ne\r\nf\r\n")),
            4,
        );
        s.handle(UiEvent::Stdin(b"\x1d[".to_vec()), 5);
        assert!(shown_row(&s, 0).contains("no history"));
        let a = s.handle(UiEvent::Stdin(b"gg\x1b[5~".to_vec()), 6);
        assert!(sent(&a).is_empty());
        assert_eq!(s.shell.display_offset(), 0);
    }

    /// Keyboard bytes go to the shell channel UNCHANGED. The client is a
    /// pipe for input: anything it "helpfully" rewrites is a key some
    /// application stops receiving.
    #[test]
    fn keyboard_bytes_reach_the_shell_channel_untouched() {
        let mut s = ready_session();
        let a = s.handle(UiEvent::Stdin(b"ls\r\x03\x1b[A".to_vec()), 0);
        assert_eq!(sent(&a), b"ls\r\x03\x1b[A");
    }

    /// Shell output is decoded into the screen model and drawn. The exact
    /// bytes are the renderer's business (tested in `crates/render`); what
    /// matters here is that the character reached the screen at all.
    #[test]
    fn shell_output_is_drawn() {
        let mut s = session();
        let a = s.handle(UiEvent::Stream0(record(b"hi")), 0);
        let out = written(&a);
        assert!(!out.is_empty(), "output must produce a paint");
        assert!(
            String::from_utf8_lossy(&out).contains("hi"),
            "the text must be in the paint: {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    /// A tick with nothing pending must not write. A client that repaints on
    /// every timer wastes the link it exists to conserve, and on a slow one
    /// the waste is visible.
    #[test]
    fn an_idle_tick_writes_nothing() {
        let mut s = session();
        let _ = s.handle(UiEvent::Stream0(record(b"hi")), 0);
        let a = s.handle(UiEvent::Tick, 20);
        assert!(written(&a).is_empty(), "an idle tick must be silent");
    }

    /// Repainting the same frame twice must produce nothing the second time:
    /// that is the renderer's diff doing its job through the session.
    #[test]
    fn the_same_output_twice_paints_once() {
        let mut s = session();
        let _ = s.handle(UiEvent::Stream0(record(b"hi")), 0);
        let a = s.handle(UiEvent::Stream0(Vec::new()), 10);
        assert!(written(&a).is_empty(), "nothing changed, nothing to paint");
    }

    /// A stream reset means the peer dropped its backlog: whatever we think
    /// is on screen is no longer trustworthy, so the next paint is a full
    /// one. Without this the screen keeps a diff against a frame that never
    /// existed.
    #[test]
    fn a_reset_forces_a_full_repaint() {
        let mut s = session();
        let _ = s.handle(UiEvent::Stream0(record(b"hi")), 0);
        let after_reset = s.handle(UiEvent::StreamReset, 10);
        assert!(
            !written(&after_reset).is_empty(),
            "a reset must repaint rather than trust the old screen"
        );
    }

    /// The link falling away without a channel exit ever reporting why is
    /// the fallback path, and it is still not a failure.
    #[test]
    fn the_link_closing_ends_the_program_successfully() {
        let mut s = session();
        let a = s.handle(UiEvent::Link(LinkState::Closed), 0);
        assert!(
            a.iter().any(|x| matches!(x, Action::Exit(0))),
            "a closed link exits 0: {a:?}"
        );
    }

    /// The terminal is handed back the way it was found -- default colours,
    /// no mirrored modes, a visible cursor. `Renderer::finish` knows how;
    /// the session must remember to ask.
    #[test]
    fn exiting_hands_the_terminal_back() {
        let mut s = session();
        let a = s.handle(UiEvent::Terminate, 0);
        let out = written(&a);
        assert!(
            out.windows(4).any(|w| w == b"\x1b[0m"),
            "the exit path must reset the pen: {:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(a.iter().any(|x| matches!(x, Action::Exit(_))));
    }

    /// The channel and size of every `ResizeChannel` action, in order.
    fn control(actions: &[Action]) -> Vec<(ChannelId, u16, u16)> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::ResizeChannel { ch, cols, rows } => Some((*ch, *cols, *rows)),
                _ => None,
            })
            .collect()
    }

    /// The local frame follows the window immediately: the user must see the
    /// terminal respond to their own drag.
    #[test]
    fn a_resize_repaints_at_the_new_size_at_once() {
        let mut s = session();
        let a = s.handle(UiEvent::Resized { cols: 40, rows: 10 }, 0);
        assert!(!written(&a).is_empty(), "the new size must be painted now");
    }

    /// ...but the server is not told yet. Every record costs an ioctl and a
    /// SIGWINCH inside the remote application.
    #[test]
    fn a_resize_does_not_reach_the_server_immediately() {
        let mut s = session();
        let a = s.handle(UiEvent::Resized { cols: 40, rows: 10 }, 0);
        assert!(
            control(&a).is_empty(),
            "the record must wait out the debounce"
        );
    }

    /// After the quiet period the last size goes out, once.
    #[test]
    fn the_settled_size_is_sent_once_after_the_quiet_period() {
        let mut s = ready_session();
        let _ = s.handle(UiEvent::Resized { cols: 40, rows: 10 }, 0);
        assert!(
            control(&s.handle(UiEvent::Tick, 100)).is_empty(),
            "too early"
        );
        let late = s.handle(UiEvent::Tick, 131);
        assert_eq!(
            control(&late),
            vec![(16, 40, 10)],
            "the channel and the settled size, once the debounce has passed"
        );
        assert!(
            control(&s.handle(UiEvent::Tick, 200)).is_empty(),
            "and only once"
        );
    }

    /// A drag is a stream of sizes; only where it stops is worth sending.
    #[test]
    fn a_drag_sends_only_the_size_it_ended_on() {
        let mut s = ready_session();
        for (i, cols) in [30u16, 34, 38, 42].iter().enumerate() {
            let a = s.handle(
                UiEvent::Resized {
                    cols: *cols,
                    rows: 10,
                },
                i as i64 * 20,
            );
            assert!(control(&a).is_empty(), "nothing goes out mid-drag");
        }
        // Still inside the quiet period measured from the LAST change.
        assert!(control(&s.handle(UiEvent::Tick, 100)).is_empty());
        assert_eq!(
            control(&s.handle(UiEvent::Tick, 191)),
            vec![(16, 42, 10)],
            "only the size the drag ended on"
        );
    }

    /// Leaving with a resize still pending must not swallow it: the session
    /// is closing, but the record is what keeps a warm reconnect from
    /// resuming at the wrong size.
    #[test]
    fn a_pending_resize_is_flushed_before_leaving() {
        let mut s = ready_session();
        let _ = s.handle(UiEvent::Resized { cols: 40, rows: 10 }, 0);
        let a = s.handle(UiEvent::Terminate, 10);
        assert_eq!(control(&a), vec![(16, 40, 10)]);
    }

    fn frame_text(actions: &[Action]) -> String {
        String::from_utf8_lossy(&written(actions)).into_owned()
    }

    /// A dead link with nothing on screen about it looks exactly like a
    /// hung terminal, and the user's next move is to kill the window.
    #[test]
    fn a_lost_link_says_so_on_screen() {
        let mut s = session();
        let a = s.handle(UiEvent::Link(LinkState::PathDown), 0);
        assert!(
            frame_text(&a).contains("link lost"),
            "the overlay must appear: {:?}",
            frame_text(&a)
        );
    }

    /// The count is the difference between "it is stuck" and "it is trying".
    #[test]
    fn the_overlay_counts_the_seconds() {
        let mut s = session();
        // Widen the terminal first, well past the whole overlay text, so
        // this assertion does not depend on exactly where `overlay` cuts
        // the row.
        let _ = s.handle(UiEvent::Resized { cols: 40, rows: 5 }, 0);
        let _ = s.handle(UiEvent::Link(LinkState::PathDown), 0);
        let a = s.handle(UiEvent::Tick, 7_000);
        // Checking for "7" alone, not the contiguous "7s": the renderer
        // diffs against the frame from the first overlay (which already
        // showed "0s") and repaints only the column that actually changed
        // (`changed_span` in `crates/render`) -- the surrounding "s" is
        // byte-identical in both and is never re-emitted.
        assert!(
            frame_text(&a).contains('7'),
            "the elapsed time must advance: {:?}",
            frame_text(&a)
        );
    }

    /// And it goes away by itself. An overlay that outlives its reason is
    /// worse than none: the user stops believing the next one.
    #[test]
    fn the_overlay_disappears_when_the_link_returns() {
        let mut s = session();
        let _ = s.handle(UiEvent::Stream0(record(b"hi")), 0);
        let _ = s.handle(UiEvent::Link(LinkState::PathDown), 0);
        let back = s.handle(UiEvent::Link(LinkState::Live), 3_000);
        assert!(
            !frame_text(&back).contains("link lost"),
            "the overlay must be gone: {:?}",
            frame_text(&back)
        );
        assert!(
            frame_text(&back).contains("hi"),
            "and the shell's own screen must be back: {:?}",
            frame_text(&back)
        );
    }

    /// The overlay is painted over a copy: the screen model must not learn
    /// about it, or it would still be there after the link came back.
    #[test]
    fn the_overlay_never_enters_the_screen_model() {
        let mut s = session();
        let _ = s.handle(UiEvent::Link(LinkState::PathDown), 0);
        let _ = s.handle(UiEvent::Tick, 1_000);
        let frame = s.shell.frame(1_000, 0);
        let top: String = frame.cells[..frame.cols as usize]
            .iter()
            .map(|c| c.ch)
            .collect();
        assert!(
            !top.contains("qsh"),
            "the model must be clean, found: {top:?}"
        );
    }

    /// The escape exists for a server that is not coming back. It must work
    /// while the link is down -- which is the only time it is needed.
    #[test]
    fn the_escape_leaves_with_an_error_code() {
        let mut s = session();
        let _ = s.handle(UiEvent::Link(LinkState::PathDown), 0);
        let a = s.handle(UiEvent::Stdin(vec![0x1d, b'.']), 100);
        assert!(
            a.iter().any(|x| matches!(x, Action::Exit(1))),
            "Ctrl-] . must leave, and not pretend the shell exited: {a:?}"
        );
        assert!(
            sent(&a).is_empty(),
            "the escape itself must not reach the shell"
        );
    }

    /// Spec §8.3: after the prefix, a key that is not a command goes nowhere,
    /// and the prefix with it.
    #[test]
    fn a_key_after_the_prefix_that_is_no_command_is_swallowed() {
        let mut s = ready_session();
        let a = s.handle(UiEvent::Stdin(vec![b'a', 0x1d, b'x', b'b']), 0);
        assert_eq!(sent(&a), b"ab", "the prefix and its key go nowhere");
        assert!(!a.iter().any(|x| matches!(x, Action::Exit(_))));
    }

    #[test]
    fn prediction_budget_fallback_preserves_every_raw_and_bracketed_input_byte() {
        for mode in [PredictMode::Adaptive, PredictMode::Never] {
            for bracketed in [false, true] {
                let mut s = Session::new(80, 24, TermCaps::truecolor(), mode, plain());
                s.on_link(LinkState::Live, 0);
                s.on_channel_ready(16, 0);
                let mut payload = Vec::new();
                if bracketed {
                    payload.extend_from_slice(b"\x1b[200~");
                }
                for _ in 0..4096 {
                    payload.extend_from_slice("p界e\u{301}".as_bytes());
                }
                if bracketed {
                    payload.extend_from_slice(b"\x1b[201~");
                }
                let mut delivered = Vec::new();
                for chunk in payload.chunks(997) {
                    delivered.extend(sent(&s.handle(UiEvent::Stdin(chunk.to_vec()), 1000)));
                }
                assert_eq!(delivered, payload, "prediction must never truncate input");
                assert!(!s.shell.prediction_active());
                assert!(!s.window_open());
            }
        }
    }

    #[test]
    fn bracketed_paste_sends_prefix_commands_to_the_shell_without_local_actions() {
        for key in [0x1d, 0x02, 0x1b] {
            let mut bytes = b"\x1b[200~".to_vec();
            for command in b".shr?[" {
                bytes.extend([key, *command]);
            }
            bytes.extend_from_slice(b"\x1b[201~");
            for cut in 0..=bytes.len() {
                let mut chrome = plain();
                chrome.prefix = Prefix::Key(key);
                let mut s = Session::new(20, 5, TermCaps::truecolor(), PredictMode::Never, chrome);
                s.on_link(LinkState::Live, 0);
                s.on_channel_ready(16, 0);
                let mut actions = s.handle(UiEvent::Stdin(bytes[..cut].to_vec()), 0);
                actions.extend(s.handle(UiEvent::Stdin(bytes[cut..].to_vec()), 1));
                assert_eq!(sent(&actions), bytes, "cut {cut}, prefix {key}");
                // Sending input may also repaint the existing frame.
                assert!(actions
                    .iter()
                    .all(|a| matches!(a, Action::SendChannel { .. } | Action::Write(_))));
                assert!(!s.window_open());
                assert!(s.history_frame.is_none());
                assert!(!s.line_shown);
                assert_eq!(s.size(), (20, 5));
            }
        }
    }

    /// The two halves may arrive in separate reads -- they usually do, since
    /// the user types them as two keystrokes.
    #[test]
    fn the_escape_works_when_split_across_reads() {
        let mut s = session();
        let first = s.handle(UiEvent::Stdin(vec![0x1d]), 0);
        assert!(sent(&first).is_empty(), "the first half is held, not sent");
        let second = s.handle(UiEvent::Stdin(vec![b'.']), 10);
        assert!(second.iter().any(|x| matches!(x, Action::Exit(1))));
    }

    /// A held prefix is swallowed with an ordinary key that arrives in a
    /// later read, as it is within one read.
    #[test]
    fn a_held_prefix_is_swallowed_with_the_key_after_it() {
        let mut s = ready_session();
        let _ = s.handle(UiEvent::Stdin(vec![0x1d]), 0);
        let a = s.handle(UiEvent::Stdin(vec![b'x']), 10);
        assert!(sent(&a).is_empty(), "{a:?}");
        let a = s.handle(UiEvent::Stdin(vec![b'y']), 20);
        assert_eq!(sent(&a), b"y", "and only that one key");
    }

    /// The prefix twice sends one, and nothing is left waiting: the `.`
    /// after it is ordinary input.
    #[test]
    fn the_prefix_twice_sends_one_and_holds_none() {
        let mut s = ready_session();
        let a = s.handle(UiEvent::Stdin(vec![0x1d, 0x1d]), 0);
        assert_eq!(sent(&a), vec![0x1d], "one goes out");
        let b = s.handle(UiEvent::Stdin(vec![b'.']), 10);
        assert_eq!(sent(&b), b".", "nothing was held");
        assert!(!b.iter().any(|x| matches!(x, Action::Exit(_))));
    }

    /// `climb::settle_opening` opens the shell channel itself, during the
    /// connection trial, before this `Session` even exists -- so that the
    /// `Live` transition it later replays from the queue (the very same one
    /// that happened during the trial) must not open a second one.
    #[test]
    fn assuming_the_channel_is_already_opening_suppresses_the_next_lives_open() {
        let mut s = session();
        s.assume_channel_opening();
        let actions = s.on_link(LinkState::Live, 0);
        assert!(
            !actions
                .iter()
                .any(|a| matches!(a, Action::OpenShell { .. })),
            "a channel opened by the caller before Live must not be opened again: {actions:?}"
        );
    }

    /// A first login that resumed a kept session: the channel is assumed
    /// opening, `Live` opens nothing (the server would refuse a stream it
    /// still runs), the announced shell is bound, and what was typed
    /// meanwhile goes to it.
    #[test]
    fn a_resumed_first_login_binds_the_announced_shell_instead_of_opening_one() {
        let mut s = session();
        s.assume_channel_opening();
        let live = s.on_link(LinkState::Live, 0);
        assert!(
            !live.iter().any(|a| matches!(a, Action::OpenShell { .. })),
            "a resumed session's shell is announced, not opened: {live:?}"
        );
        let typed = s.handle(UiEvent::Stdin(b"x".to_vec()), 5);
        assert!(sent(&typed).is_empty(), "no channel to send to yet");
        let announced = s.on_announced(&[16], 10);
        assert!(
            announced.is_empty(),
            "wait for authoritative Established geometry"
        );
        let ready = s.on_channel_ready(16, 20);
        assert_eq!(sent(&ready), b"x", "what was typed meanwhile reaches it");
    }

    /// The client opens exactly one channel, and only once the link is live:
    /// an open sent before the handshake completes reaches nobody, and a
    /// second open would give the user two shells.
    #[test]
    fn the_shell_channel_is_opened_once_the_link_is_live() {
        // The existing helper in this module builds a 20x5 session; this test
        // needs a known, different size to prove the open carries the real
        // one, so it constructs its own.
        let mut s = Session::new(120, 40, TermCaps::truecolor(), PredictMode::Never, plain());
        assert!(
            s.on_link(LinkState::Connecting, 0).is_empty(),
            "nothing is opened before the link is live"
        );

        let actions = s.on_link(LinkState::Live, 10);
        assert_eq!(
            actions
                .iter()
                .filter(|a| matches!(a, Action::OpenShell { .. }))
                .count(),
            1,
            "exactly one shell channel is opened"
        );
        assert!(
            matches!(
                actions
                    .iter()
                    .find(|a| matches!(a, Action::OpenShell { .. })),
                Some(Action::OpenShell {
                    cols: 120,
                    rows: 40
                })
            ),
            "opened at the terminal's real size, so the far side never has to resize"
        );

        // A second Live (a warm reattach) must not open a second shell: the
        // announced-channel path binds instead.
        let again = s.on_link(LinkState::Live, 20);
        assert!(
            !again.iter().any(|a| matches!(a, Action::OpenShell { .. })),
            "a reattach binds to the running channel, it does not open another"
        );
    }

    /// The shell channel ending is the ordinary exit, with the code the far
    /// side reported rather than the zero we used to assume.
    #[test]
    fn the_shell_channels_exit_code_becomes_the_programs() {
        let mut s = session();
        s.on_link(LinkState::Live, 0);
        s.on_channel_ready(16, 10);

        let actions = s.on_channel_exit(16, 130, 20);
        assert!(
            actions.contains(&Action::Exit(130)),
            "the reported code is the program's, got: {actions:?}"
        );
    }

    /// Keystrokes typed in the window between `Live` and the far side's
    /// `Opened` are queued, not dropped (see `ShellChannel::Opening`'s own
    /// doc) -- and once confirmed, they must reach the channel the far
    /// side ACTUALLY reported, not a hardcoded number. Every other test in
    /// this file happens to use channel 16, which is also
    /// `FIRST_CHANNEL_STREAM` -- so none of them would catch the automaton
    /// regressing to addressing that constant instead of the number
    /// `on_channel_ready` was actually told.
    #[test]
    fn queued_keystrokes_before_ready_flush_to_the_confirmed_channel_not_a_constant() {
        let mut s = session();
        s.on_link(LinkState::Live, 0);
        let queued = s.handle(UiEvent::Stdin(b"ls\r".to_vec()), 5);
        assert!(
            sent(&queued).is_empty(),
            "nothing sent yet: the channel is not confirmed"
        );

        let flushed = s.on_channel_ready(37, 10);
        assert!(
            flushed.iter().any(
                |a| matches!(a, Action::SendChannel { ch, bytes } if *ch == 37 && bytes == b"ls\r")
            ),
            "the queued keystrokes must flush to channel 37, not a hardcoded number: {flushed:?}"
        );
    }

    /// A real terminal limits typeahead too: an unbounded queue here would
    /// let a burst of input typed before the channel is even confirmed
    /// grow without bound.
    #[test]
    fn queued_keystrokes_before_ready_are_capped() {
        let mut s = session();
        s.on_link(LinkState::Live, 0);
        let huge = vec![b'x'; 128 * 1024];
        let _ = s.handle(UiEvent::Stdin(huge), 5);

        let flushed = s.on_channel_ready(37, 10);
        let sent_len: usize = flushed
            .iter()
            .filter_map(|a| match a {
                Action::SendChannel { bytes, .. } => Some(bytes.len()),
                _ => None,
            })
            .sum();
        assert!(
            sent_len <= 64 * 1024,
            "queued keystrokes must be capped rather than growing without bound, got {sent_len}"
        );
    }

    /// A resize that settles before the channel is confirmed waits (there
    /// is nowhere to address it yet); once confirmed, the next settled
    /// size goes to the channel the far side actually reported, not a
    /// hardcoded number -- same reasoning as the keystroke test above.
    #[test]
    fn a_resize_settled_before_ready_waits_then_addresses_the_confirmed_channel() {
        let mut s = session();
        s.on_link(LinkState::Live, 0);
        let _ = s.handle(UiEvent::Resized { cols: 50, rows: 10 }, 0);
        // Past the debounce, but the channel is still not confirmed.
        assert!(
            control(&s.handle(UiEvent::Tick, 131)).is_empty(),
            "no channel to address yet"
        );

        let ready = s.on_channel_ready(37, 140);
        assert_eq!(
            control(&ready),
            vec![(37, 50, 10)],
            "the settled resize must go out now, addressed to the confirmed channel"
        );
    }

    /// A channel-exit report for a number this session never confirmed as
    /// its own (a stale event, or one meant for some other channel
    /// entirely) is silent: it must not end the session on somebody
    /// else's exit code.
    #[test]
    fn on_channel_exit_is_silent_for_a_channel_this_session_is_not_tracking() {
        let mut s = session();
        s.on_link(LinkState::Live, 0);
        s.on_channel_ready(37, 10);

        let actions = s.on_channel_exit(99, 5, 20);
        assert!(
            actions.is_empty(),
            "an exit for a channel this session never opened must be silent: {actions:?}"
        );
    }

    /// The top row of what `actions` painted, read back through a terminal
    /// model -- what a person would see there.
    fn row0(actions: &[Action], cols: u16, rows: u16) -> String {
        let mut t = terminal::TerminalCore::new(cols, rows);
        t.feed(&written(actions));
        let f = t.frame();
        (0..cols).map(|c| f.cell(0, c).ch).collect::<String>()
    }

    fn wide_ready_session() -> Session {
        let mut s = Session::new(80, 5, TermCaps::truecolor(), PredictMode::Never, plain());
        let _ = s.on_link(LinkState::Live, 0);
        let _ = s.on_channel_ready(16, 0);
        s
    }

    #[test]
    fn the_prefix_r_asks_to_reconnect_and_sends_nothing() {
        let mut s = ready_session();
        let a = s.handle(UiEvent::Stdin(b"ab\x1dr".to_vec()), 0);
        assert_eq!(sent(&a), b"ab", "what came before the escape still goes");
        assert!(a.contains(&Action::Reconnect), "{a:?}");
        let a = s.handle(UiEvent::Stdin(vec![0x1d]), 1);
        let a2 = s.handle(UiEvent::Stdin(vec![b'r']), 2);
        assert!(sent(&a).is_empty() && sent(&a2).is_empty());
        assert!(
            a2.contains(&Action::Reconnect),
            "split across reads: {a2:?}"
        );
    }

    /// What follows `Ctrl-] r` in the same read belongs to the link being
    /// let go: it is neither sent nor predicted, and `Reconnect` is the last
    /// thing asked for.
    #[test]
    fn bytes_after_the_prefix_r_in_the_same_read_go_nowhere() {
        let mut s = Session::new(20, 5, TermCaps::truecolor(), PredictMode::Always, plain());
        let _ = s.on_link(LinkState::Live, 0);
        let _ = s.on_channel_ready(16, 0);
        let a = s.handle(UiEvent::Stdin(b"\x1drls".to_vec()), 10);
        assert_eq!(a, vec![Action::Reconnect], "nothing sent, nothing painted");
    }

    #[test]
    fn keys_typed_while_the_link_is_gone_go_nowhere() {
        let mut s = ready_session();
        let _ = s.on_link_gone(0);
        let a = s.handle(UiEvent::Stdin(b"ls\r".to_vec()), 10);
        assert!(sent(&a).is_empty(), "a dead channel gets nothing: {a:?}");
        let a = s.handle(UiEvent::Stdin(vec![0x1d, b'.']), 20);
        assert!(
            a.contains(&Action::Exit(1)),
            "the way out still works: {a:?}"
        );
    }

    #[test]
    fn a_lost_link_shows_where_it_is_reconnecting_to() {
        let mut s = wide_ready_session();
        let mut all = s.on_link_gone(0);
        assert!(
            row0(&all, 80, 5).starts_with("[qsh] reconnecting... Ctrl-] . -- exit"),
            "{}",
            row0(&all, 80, 5)
        );
        // The renderer paints only the difference, so the second paint is
        // read back on top of the first, as a real terminal would see it.
        all.extend(s.handle(
            UiEvent::Reconnecting {
                round: 1,
                to: "10.8.0.1".into(),
            },
            10,
        ));
        assert!(
            row0(&all, 80, 5).contains("reconnecting to 10.8.0.1"),
            "{}",
            row0(&all, 80, 5)
        );
    }

    #[test]
    fn the_wait_counts_down_in_whole_seconds() {
        let mut s = wide_ready_session();
        let _ = s.on_link_gone(0);
        let a = s.handle(
            UiEvent::ReconnectWaiting {
                until_ms: 8_000,
                hint: None,
            },
            100,
        );
        assert!(
            row0(&a, 80, 5).contains("next attempt in 8 s"),
            "{}",
            row0(&a, 80, 5)
        );
        let a = s.handle(UiEvent::Tick, 6_500);
        assert!(!written(&a).is_empty(), "the countdown repaints on its own");
    }

    #[test]
    fn a_late_progress_message_after_the_return_is_ignored() {
        let mut s = ready_session();
        let _ = s.on_link_gone(0);
        let _ = s.on_reattached(10);
        let a = s.handle(
            UiEvent::Reconnecting {
                round: 1,
                to: "x".into(),
            },
            20,
        );
        assert!(
            written(&a).is_empty(),
            "nothing is shown over a live session: {a:?}"
        );
    }

    #[test]
    fn after_the_return_the_same_channel_is_adopted_at_the_current_size() {
        let mut s = ready_session();
        let _ = s.on_link_gone(0);
        let _ = s.on_reattached(10);
        let a = s.on_announced(&[16], 20);
        assert!(a.is_empty(), "snapshot does not commit geometry");
        let _ = s.on_channel_ready(16, 21);
        let a = s.handle(UiEvent::Stdin(b"x".to_vec()), 30);
        assert_eq!(sent(&a), b"x", "input flows again");
    }

    #[test]
    fn a_resize_while_away_reaches_the_server_after_the_return() {
        let mut s = ready_session();
        let _ = s.on_link_gone(0);
        let _ = s.handle(UiEvent::Resized { cols: 30, rows: 7 }, 10);
        let _ = s.on_reattached(1_000);
        let a = s.on_announced(&[16], 1_010);
        assert!(a.is_empty(), "snapshot does not commit geometry");
        assert_eq!(s.size(), (20, 5));
        assert!(s
            .on_channel_ready(16, 1011)
            .contains(&Action::ResizeChannel {
                ch: 16,
                cols: 30,
                rows: 7
            }));
    }

    #[test]
    fn a_shell_missing_after_authenticated_resume_requests_replacement() {
        let mut s = ready_session();
        let _ = s.on_link_gone(0);
        let _ = s.on_reattached(10);
        let a = s.on_announced(&[], 20);
        assert!(
            a.contains(&Action::Notice(status::shell_ended_text())),
            "{a:?}"
        );
        assert!(a.contains(&Action::ShellUnavailable), "{a:?}");
        assert!(a.contains(&Action::Exit(13)), "{a:?}");
    }

    #[test]
    fn returning_to_a_session_left_by_another_run_is_as_before() {
        let mut s = session();
        assert_eq!(
            s.on_announced(&[], 0),
            vec![Action::OpenShell { cols: 20, rows: 5 }]
        );
        let mut s = session();
        assert!(s.on_announced(&[16, 17], 0).is_empty());
    }

    #[test]
    fn the_dead_link_s_channel_exit_is_not_the_shell_s() {
        let mut s = ready_session();
        let _ = s.on_link_gone(0);
        assert!(s.on_channel_exit(16, 0, 10).is_empty());
    }

    fn lined(cols: u16, rows: u16) -> Session {
        let chrome = Chrome {
            prefix: crate::escape::DEFAULT_PREFIX,
            line: true,
            glyphs: crate::window::Glyphs {
                utf8: true,
                colour: true,
            },
        };
        let mut s = Session::new(
            cols,
            rows,
            TermCaps::truecolor(),
            PredictMode::Never,
            chrome,
        );
        let _ = s.on_link(LinkState::Live, 0);
        let _ = s.on_channel_ready(16, 0);
        s
    }

    fn road(
        label: &str,
        port: u16,
        in_use: bool,
        state: transport::paths::PathState,
        ms: Option<u32>,
    ) -> crate::window::Road {
        crate::window::Road {
            addr: format!("127.0.0.1:{port}").parse().unwrap(),
            label: label.into(),
            in_use,
            state,
            ewma_ms: ms,
            failed_ago_ms: None,
        }
    }

    fn roads_event() -> UiEvent {
        use transport::paths::PathState;
        UiEvent::Roads {
            roads: vec![
                road("a:1", 1, true, PathState::Verified, Some(40)),
                road("b:2", 2, false, PathState::Verified, Some(38)),
            ],
        }
    }

    /// Everything on a `cols` x `rows` screen after `actions`, row by row.
    fn screen_text(actions: &[Action], cols: u16, rows: u16) -> String {
        let mut t = terminal::TerminalCore::new(cols, rows);
        t.feed(&written(actions));
        let f = t.frame();
        (0..rows)
            .flat_map(|r| (0..cols).map(move |c| (r, c)))
            .map(|(r, c)| f.cell(r, c).ch)
            .collect()
    }

    /// Ahead of a stop the terminal is handed back as on the way out -- the
    /// mirrored modes off, the cursor shown -- and the paint after `Resumed`
    /// is a full one, the modes with it.
    #[test]
    fn a_suspend_hands_the_terminal_back_and_the_return_repaints_in_full() {
        let mut s = lined(20, 5);
        let _ = s.handle(UiEvent::Stream0(record(b"\x1b[?2004hhello")), 0);
        let back = s.suspend();
        let back = String::from_utf8_lossy(&back);
        assert!(back.contains("\x1b[?2004l"), "{back:?}");
        assert!(back.contains("\x1b[?25h"), "{back:?}");
        let again = written(&s.handle(UiEvent::Resumed, 1));
        let again = String::from_utf8_lossy(&again);
        assert!(again.contains("\x1b[2J"), "a full repaint: {again:?}");
        assert!(again.contains("\x1b[?2004h"), "the modes again: {again:?}");
        assert!(again.contains("hello"), "{again:?}");
    }

    #[test]
    fn the_shell_is_one_row_shorter_under_the_line() {
        let s = lined(80, 24);
        assert_eq!(s.size(), (80, 23));
    }

    #[test]
    fn one_row_terminal_has_no_status_line() {
        let s = lined(80, 1);
        assert_eq!(s.size(), (80, 1));
    }

    #[test]
    fn the_shell_opens_at_its_own_size() {
        let chrome = Chrome {
            line: true,
            ..plain()
        };
        let mut s = Session::new(80, 24, TermCaps::truecolor(), PredictMode::Never, chrome);
        let a = s.on_link(LinkState::Live, 0);
        assert!(
            a.contains(&Action::OpenShell { cols: 80, rows: 23 }),
            "{a:?}"
        );
    }

    #[test]
    fn the_line_shows_the_road_and_the_latency() {
        let mut s = lined(40, 5);
        let _ = s.handle(roads_event(), 0);
        let stats = transport::Stats {
            rtt_ms: 42,
            ..Default::default()
        };
        let _ = s.handle(UiEvent::Stats(stats), 0);
        let _ = s.handle(UiEvent::Tick, 1_000);
        // A full repaint: the renderer paints only differences, and `row0`
        // reads what was painted into a fresh terminal.
        let a = s.handle(UiEvent::Resumed, 1_001);
        let top = row0(&a, 40, 5);
        assert!(top.starts_with(" Ctrl-] ?"), "{top}");
        assert!(top.trim_end().ends_with("a:1  42 ms"), "{top}");
    }

    /// The dead link's last `Stats` say nothing about the new one: after the
    /// return the line shows no silence and no alarm until the new link's
    /// own figures come in.
    #[test]
    fn after_the_return_the_line_forgets_the_dead_links_silence() {
        let mut s = lined(40, 5);
        let stats = transport::Stats {
            rtt_ms: 40,
            silent_secs: 45,
            ..Default::default()
        };
        let _ = s.handle(UiEvent::Stats(stats), 0);
        let _ = s.handle(UiEvent::Tick, 1_000);
        let _ = s.on_link_gone(1_001);
        let returned = s.on_reattached(2_000);
        let a = s.handle(UiEvent::Resumed, 2_001);
        for actions in [&returned, &a] {
            let top = row0(actions, 40, 5);
            assert!(!top.contains("45 s"), "{top}");
            assert!(!top.contains("40 ms"), "{top}");
            let mut t = terminal::TerminalCore::new(40, 5);
            t.feed(&written(actions));
            let f = t.frame();
            assert!(
                (0..40).all(|c| f.cell(0, c).bg != terminal::Color::Indexed(1)),
                "no alarm on the line after the return: {top}"
            );
        }
    }

    #[test]
    fn the_line_changes_at_most_once_a_second() {
        let mut s = lined(40, 5);
        let stats = transport::Stats {
            rtt_ms: 42,
            ..Default::default()
        };
        let _ = s.handle(UiEvent::Stats(stats), 100);
        let a = s.handle(UiEvent::Tick, 500);
        assert!(written(&a).is_empty(), "too early: {a:?}");
        let a = s.handle(UiEvent::Resumed, 501);
        assert!(!row0(&a, 40, 5).contains("42 ms"), "{}", row0(&a, 40, 5));
        let _ = s.handle(UiEvent::Tick, 1_000);
        let a = s.handle(UiEvent::Resumed, 1_001);
        assert!(row0(&a, 40, 5).contains("42 ms"), "{}", row0(&a, 40, 5));
    }

    #[test]
    fn a_single_destination_is_rendered_with_latency() {
        for label in [
            "host.example:60000",
            "192.0.2.8:60000",
            "[2001:db8::8]:60000",
        ] {
            let chrome = Chrome {
                line: true,
                ..plain()
            };
            let mut s = Session::new(60, 5, TermCaps::truecolor(), PredictMode::Never, chrome);
            s.handle(
                UiEvent::Roads {
                    roads: vec![road(
                        label,
                        1,
                        true,
                        transport::paths::PathState::Verified,
                        Some(42),
                    )],
                },
                0,
            );
            s.handle(
                UiEvent::Stats(transport::Stats {
                    rtt_ms: 42,
                    ..Default::default()
                }),
                0,
            );
            s.handle(UiEvent::Tick, 1_000);
            let actions = s.handle(UiEvent::Resumed, 1_001);
            let top = row0(&actions, 60, 5);
            assert!(top.starts_with(" Ctrl-] ?"), "{top}");
            assert!(top.ends_with(&format!("{label}  42 ms ")), "{top}");
        }
    }

    #[test]
    fn connected_destination_overflow_has_an_ellipsis_without_wrapping() {
        let mut s = lined(20, 5);
        s.handle(
            UiEvent::Roads {
                roads: vec![road(
                    "very-long-host.example:60000",
                    1,
                    true,
                    transport::paths::PathState::Verified,
                    Some(42),
                )],
            },
            0,
        );
        s.handle(
            UiEvent::Stats(transport::Stats {
                rtt_ms: 42,
                ..Default::default()
            }),
            0,
        );
        s.handle(UiEvent::Tick, 1_000);
        let actions = s.handle(UiEvent::Resumed, 1_001);
        let top = row0(&actions, 20, 5);
        assert_eq!(top, "very-long-host.exa… ");
        let mut terminal = terminal::TerminalCore::new(20, 5);
        terminal.feed(&written(&actions));
        assert!((0..20).all(|c| terminal.frame().cell(1, c).ch == ' '));
    }

    #[test]
    fn connected_destination_resize_preserves_complete_cells_and_shell_rows() {
        for utf8 in [true, false] {
            let mut s = lined(60, 5);
            s.chrome.glyphs.utf8 = utf8;
            s.handle(UiEvent::Stream0(record(b"SHELL")), 0);
            s.handle(
                UiEvent::Roads {
                    roads: vec![road(
                        "e\u{301}界界-long.example:60000",
                        1,
                        true,
                        transport::paths::PathState::Verified,
                        Some(42),
                    )],
                },
                0,
            );
            s.handle(
                UiEvent::Stats(transport::Stats {
                    rtt_ms: 42,
                    ..Default::default()
                }),
                0,
            );
            s.handle(UiEvent::Tick, 1_000);
            for cols in [60, 20, 6, 5, 4, 2, 1, 60] {
                s.handle(UiEvent::Resized { cols, rows: 5 }, 1_001);
                let actions = s.handle(UiEvent::Resumed, 1_002);
                let mut terminal = terminal::TerminalCore::new(cols, 5);
                terminal.feed(&written(&actions));
                let frame = terminal.frame();
                let top: String = (0..cols).map(|c| frame.cell(0, c).ch).collect();
                assert_eq!(frame.cell(0, cols - 1).ch, ' ', "margin {cols}: {top}");
                if cols == 60 {
                    assert!(top.starts_with(" Ctrl-] ?"), "{top}");
                    assert!(top.ends_with("42 ms "), "{top}");
                    if utf8 {
                        let owner = (0..cols).find(|&c| frame.cell(0, c).ch == 'e').unwrap();
                        assert_eq!(frame.cell(0, owner).combining.as_slice(), &['\u{301}']);
                    } else {
                        assert!(!top.contains('界'), "{top}");
                    }
                } else if cols > 1 {
                    assert!(
                        top.ends_with(if utf8 {
                            "… "
                        } else if cols >= 4 {
                            "... "
                        } else {
                            ". "
                        }),
                        "{cols}: {top}"
                    );
                }
                for c in 0..cols {
                    let flags = frame.cell(0, c).flags;
                    if flags & terminal::FLAG_WIDE != 0 {
                        assert!(c + 1 < cols);
                        assert_ne!(frame.cell(0, c + 1).flags & terminal::FLAG_WIDE_SPACER, 0);
                    }
                    if flags & terminal::FLAG_WIDE_SPACER != 0 {
                        assert!(c > 0);
                        assert_ne!(frame.cell(0, c - 1).flags & terminal::FLAG_WIDE, 0);
                    }
                }
                let shell: String = (0..cols).map(|c| frame.cell(1, c).ch).collect();
                assert!(
                    shell.starts_with(&"SHELL"[..usize::from(cols).min(5)]),
                    "{cols}: {shell}"
                );
            }
        }
    }

    #[test]
    fn initially_hidden_status_does_not_cover_the_shell_with_a_destination() {
        let mut s = Session::new(60, 5, TermCaps::truecolor(), PredictMode::Never, plain());
        s.on_link(LinkState::Live, 0);
        s.on_channel_ready(16, 0);
        s.handle(UiEvent::Stream0(record(b"SHELL")), 0);
        s.handle(
            UiEvent::Roads {
                roads: vec![road(
                    "host.example:60000",
                    1,
                    true,
                    transport::paths::PathState::Verified,
                    Some(42),
                )],
            },
            0,
        );
        s.handle(
            UiEvent::Stats(transport::Stats {
                rtt_ms: 42,
                ..Default::default()
            }),
            0,
        );
        s.handle(UiEvent::Tick, 1_000);
        let actions = s.handle(UiEvent::Resumed, 1_001);
        assert!(row0(&actions, 60, 5).starts_with("SHELL"));
        assert!(!screen_text(&actions, 60, 5).contains("host.example"));
        assert_eq!(s.desired_size(), (60, 5));
    }

    #[test]
    fn connected_destination_follows_the_active_path_and_status_visibility() {
        let mut s = lined(60, 5);
        s.handle(roads_event(), 0);
        s.handle(
            UiEvent::Stats(transport::Stats {
                rtt_ms: 42,
                ..Default::default()
            }),
            0,
        );
        s.handle(UiEvent::Tick, 1_000);
        s.handle(UiEvent::Stdin(vec![0x1d, b'h']), 1_001);
        let hidden = s.handle(UiEvent::Resumed, 1_002);
        assert!(!screen_text(&hidden, 60, 5).contains("a:1"));
        assert_eq!(s.desired_size(), (60, 5));
        s.handle(
            UiEvent::Roads {
                roads: vec![
                    road(
                        "a:1",
                        1,
                        false,
                        transport::paths::PathState::Verified,
                        Some(40),
                    ),
                    road(
                        "b:2",
                        2,
                        true,
                        transport::paths::PathState::Verified,
                        Some(42),
                    ),
                ],
            },
            1_003,
        );
        s.handle(UiEvent::Stdin(vec![0x1d, b'h']), 1_004);
        let shown = s.handle(UiEvent::Resumed, 1_005);
        assert!(row0(&shown, 60, 5).ends_with("b:2  42 ms "));
        assert_eq!(s.desired_size(), (60, 4));
        s.on_link_gone(1_006);
        s.handle(
            UiEvent::Reconnecting {
                round: 1,
                to: "host.example".into(),
            },
            1_007,
        );
        let reconnecting = s.handle(UiEvent::Resumed, 1_008);
        assert!(row0(&reconnecting, 60, 5).contains("reconnecting to host.example"));
        s.on_reattached(1_009);
        let returned = s.handle(UiEvent::Resumed, 1_010);
        assert!(!row0(&returned, 60, 5).contains("42 ms"));
        s.handle(
            UiEvent::Stats(transport::Stats {
                rtt_ms: 38,
                ..Default::default()
            }),
            1_011,
        );
        s.handle(UiEvent::Tick, 2_010);
        let live = s.handle(UiEvent::Resumed, 2_011);
        assert!(row0(&live, 60, 5).ends_with("b:2  38 ms "));
    }

    #[test]
    fn hiding_the_line_gives_the_shell_its_row_back() {
        let mut s = lined(80, 24);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b'h']), 0);
        assert_eq!(s.desired_size(), (80, 24));
        assert_eq!(s.size(), (80, 23));
        let a = s.handle(UiEvent::Tick, 1_000);
        assert!(
            a.contains(&Action::ResizeChannel {
                ch: 16,
                cols: 80,
                rows: 24
            }),
            "{a:?}"
        );
    }

    #[test]
    fn keys_go_to_the_window_not_the_shell() {
        let mut s = lined(80, 24);
        let _ = s.handle(roads_event(), 0);
        let a = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 10);
        assert!(s.window_open());
        assert!(sent(&a).is_empty());
        let a = s.handle(UiEvent::Stdin(b"ls\x1b[B".to_vec()), 20);
        assert!(
            sent(&a).is_empty(),
            "nothing typed into the window reaches the shell: {a:?}"
        );
        let a = s.handle(UiEvent::Stdin(b"\r".to_vec()), 30);
        assert!(
            a.contains(&Action::UseRoad("127.0.0.1:2".parse().unwrap())),
            "{a:?}"
        );
        let _ = s.handle(UiEvent::RoadSwitched { ok: true }, 40);
        assert!(!s.window_open(), "a switch that worked closes the window");
        let a = s.handle(UiEvent::Stdin(b"x".to_vec()), 50);
        assert_eq!(sent(&a), b"x");
    }

    /// A key sequence is one key in the window, even cut in two by a read:
    /// the `2` of `ESC [ 1 ; 2 A` (Shift-Up) or of `ESC [ 1 2 ~` (F2) picks
    /// no row, so `Enter` stays on the road in use and switches nowhere.
    #[test]
    fn the_digits_of_a_key_sequence_pick_no_row() {
        let mut s = lined(80, 24);
        let _ = s.handle(roads_event(), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 10);
        let _ = s.handle(UiEvent::Stdin(b"\x1b[1;2".to_vec()), 20);
        let _ = s.handle(UiEvent::Stdin(b"A\x1b[12~".to_vec()), 30);
        let a = s.handle(UiEvent::Stdin(b"\r".to_vec()), 40);
        assert!(!a.iter().any(|x| matches!(x, Action::UseRoad(_))), "{a:?}");
        assert!(s.window_open());
    }

    /// A window closed by a key in the middle of a paste leaves the paste
    /// open no longer than the paste: the cut end marker the window held is
    /// read with the next bytes, and the next click is moved up again.
    #[test]
    fn closing_the_window_mid_paste_does_not_leave_the_paste_open() {
        let mut s = lined(80, 24);
        let _ = s.handle(roads_event(), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 10);
        // The frame shows a mouse-tracking application, so clicks are moved.
        let _ = s.handle(UiEvent::Stream0(record(b"\x1b[?1000h\x1b[?1006h")), 15);
        let _ = s.handle(UiEvent::Stdin(b"q\x1b[200~pasted\x1b[20".to_vec()), 20);
        assert!(!s.window_open(), "q closes the window");
        let a = s.handle(UiEvent::Stdin(b"1~".to_vec()), 30);
        assert_eq!(sent(&a), b"\x1b[201~", "the paste's end reaches the shell");
        let a = s.handle(UiEvent::Stdin(b"\x1b[<0;10;5M".to_vec()), 40);
        assert_eq!(
            sent(&a),
            b"\x1b[<0;10;4M",
            "the paste is over: a click is moved under the line again"
        );
    }

    #[test]
    fn a_switch_that_failed_keeps_the_window() {
        let mut s = lined(80, 24);
        let _ = s.handle(roads_event(), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's', b'2', b'\r']), 10);
        let _ = s.handle(UiEvent::RoadSwitched { ok: false }, 20);
        assert!(s.window_open());
    }

    #[test]
    fn the_window_follows_a_resize() {
        let mut s = lined(80, 24);
        let _ = s.handle(roads_event(), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 10);
        let a = s.handle(UiEvent::Resized { cols: 40, rows: 10 }, 20);
        let text = screen_text(&a, 40, 10);
        assert!(text.contains("Connection state"), "{text}");
        assert!(s.window_open());
    }

    /// The selection never points past what the window shows: a snapshot
    /// can shrink between polls, and a short terminal clips rows -- `Enter`
    /// must never switch to a road the person cannot see.
    #[test]
    fn enter_never_switches_to_a_road_out_of_sight() {
        use transport::paths::PathState;
        let three = UiEvent::Roads {
            roads: vec![
                road("a:1", 1, true, PathState::Verified, Some(40)),
                road("b:2", 2, false, PathState::Verified, Some(38)),
                road("c:3", 3, false, PathState::Verified, Some(37)),
            ],
        };
        // The snapshot shrinks under the selection.
        let mut s = lined(80, 24);
        let _ = s.handle(three.clone(), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's', b'3']), 10);
        let _ = s.handle(
            UiEvent::Roads {
                roads: vec![
                    road("a:1", 1, true, PathState::Verified, Some(40)),
                    road("b:2", 2, false, PathState::Verified, Some(38)),
                ],
            },
            20,
        );
        let a = s.handle(UiEvent::Stdin(b"\r".to_vec()), 30);
        assert!(
            a.contains(&Action::UseRoad("127.0.0.1:2".parse().unwrap())),
            "the selection moved to the last row left: {a:?}"
        );

        // A terminal of three rows: the box has room for one road only.
        let mut s = lined(80, 3);
        let _ = s.handle(three, 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's', b'3', b'\r']), 10);
        let a = s.handle(UiEvent::Stdin(vec![b'2', b'\r']), 20);
        assert!(
            !a.iter().any(|x| matches!(x, Action::UseRoad(_))),
            "neither road 3 nor road 2 is on screen: {a:?}"
        );
    }

    /// A window the terminal cannot show is not left open out of sight,
    /// swallowing keys.
    #[test]
    fn a_window_too_big_for_the_terminal_does_not_stay_open() {
        let mut s = lined(6, 24);
        let _ = s.handle(roads_event(), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 10);
        assert!(!s.window_open());
        let a = s.handle(UiEvent::Stdin(b"x".to_vec()), 20);
        assert_eq!(sent(&a), b"x");

        let mut s = lined(80, 24);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b'?']), 0);
        assert!(s.window_open());
        let _ = s.handle(UiEvent::Resized { cols: 6, rows: 24 }, 10);
        assert!(!s.window_open(), "shrunk out of sight");
    }

    /// A mouse report or a paste is not a key press: in the connection-state
    /// window it selects nothing, closes nothing and switches nothing.
    #[test]
    fn mouse_reports_and_pastes_do_not_drive_the_roads_window() {
        let mut s = lined(80, 24);
        let _ = s.handle(roads_event(), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 10);
        let mut inputs: Vec<Vec<u8>> = vec![
            // SGR: its digits would be `Pick`s.
            b"\x1b[<0;10;2M".to_vec(),
            b"\x1b[<35;22;2M".to_vec(),
            // X10: a coordinate byte `q` would be `Close`.
            vec![0x1b, b'[', b'M', 32, 50, b'q'],
            // A paste of "2" and Enter would switch to road 2.
            b"\x1b[200~2\r\x1b[201~".to_vec(),
        ];
        // And a report split across reads.
        inputs.push(b"\x1b[<0;1".to_vec());
        inputs.push(b"2;2M".to_vec());
        for (i, input) in inputs.into_iter().enumerate() {
            let a = s.handle(UiEvent::Stdin(input.clone()), 20 + i as i64);
            assert!(s.window_open(), "{input:?} closed the window");
            assert!(sent(&a).is_empty(), "{input:?}: {a:?}");
            assert!(
                !a.iter().any(|x| matches!(x, Action::UseRoad(_))),
                "{input:?}: {a:?}"
            );
        }
        let a = s.handle(UiEvent::Stdin(b"\r".to_vec()), 40);
        assert!(
            !a.iter().any(|x| matches!(x, Action::UseRoad(_))),
            "the selection is still on the road in use: {a:?}"
        );
    }

    #[test]
    fn a_mouse_report_does_not_close_the_help() {
        let mut s = lined(80, 24);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b'?']), 0);
        let _ = s.handle(UiEvent::Stdin(b"\x1b[<0;10;5M".to_vec()), 10);
        let _ = s.handle(UiEvent::Stdin(b"\x1b[<0;10;5m".to_vec()), 11);
        assert!(s.window_open());
        let a = s.handle(UiEvent::Stdin(b"z".to_vec()), 20);
        assert!(!s.window_open(), "a real key still closes it");
        assert!(sent(&a).is_empty());
    }

    #[test]
    fn the_prefix_leaves_keeping_the_session() {
        let mut s = lined(80, 24);
        let a = s.handle(UiEvent::Stdin(vec![0x1d, b'.']), 0);
        let keep = a.iter().position(|x| *x == Action::Keep).expect("keep");
        let exit = a
            .iter()
            .position(|x| *x == Action::Exit(1))
            .expect("exit 1");
        assert!(keep < exit, "{a:?}");
    }

    #[test]
    fn the_help_closes_on_any_key() {
        let mut s = lined(80, 24);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b'?']), 0);
        assert!(s.window_open());
        let a = s.handle(UiEvent::Stdin(b"z".to_vec()), 10);
        assert!(!s.window_open());
        assert!(sent(&a).is_empty(), "the key that closed it goes nowhere");
    }

    #[test]
    fn the_prefix_s_closes_any_window() {
        let mut s = lined(80, 24);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b'?']), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 10);
        assert!(!s.window_open());
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 20);
        assert!(s.window_open());
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 30);
        assert!(!s.window_open());
    }

    /// An arrow key split between two reads still moves the selection rather
    /// than closing the window.
    #[test]
    fn an_arrow_split_across_reads_is_still_an_arrow() {
        let mut s = lined(80, 24);
        let _ = s.handle(roads_event(), 0);
        let _ = s.handle(UiEvent::Stdin(vec![0x1d, b's']), 10);
        let _ = s.handle(UiEvent::Stdin(b"\x1b[".to_vec()), 20);
        assert!(s.window_open());
        let _ = s.handle(UiEvent::Stdin(b"B".to_vec()), 30);
        let a = s.handle(UiEvent::Stdin(b"\r".to_vec()), 40);
        assert!(
            a.contains(&Action::UseRoad("127.0.0.1:2".parse().unwrap())),
            "{a:?}"
        );
    }

    #[test]
    fn reconnecting_shows_on_the_line_not_as_a_plate() {
        let mut s = lined(60, 5);
        let _ = s.on_link_gone(0);
        let a = s.handle(UiEvent::Resumed, 1);
        let top = row0(&a, 60, 5);
        assert!(
            top.starts_with(" Ctrl-] ?") && top.contains("reconnecting"),
            "{top}"
        );
    }

    #[test]
    fn a_mouse_click_moves_up_under_the_line() {
        let mut s = lined(80, 24);
        // The shell turned SGR mouse tracking on.
        let _ = s.handle(UiEvent::Stream0(record(b"\x1b[?1000h\x1b[?1006h")), 0);
        let a = s.handle(UiEvent::Stdin(b"\x1b[<0;10;5M".to_vec()), 10);
        assert_eq!(sent(&a), b"\x1b[<0;10;4M");
    }

    #[test]
    fn without_mouse_tracking_the_bytes_are_untouched() {
        let mut s = lined(80, 24);
        let a = s.handle(UiEvent::Stdin(b"\x1b[<0;10;5M".to_vec()), 10);
        assert_eq!(sent(&a), b"\x1b[<0;10;5M");
    }

    #[test]
    fn the_line_never_enters_the_screen_model() {
        let mut s = lined(40, 5);
        let _ = s.handle(UiEvent::Stream0(record(b"hi")), 0);
        let frame = s.shell.frame(10, 0);
        assert_eq!(frame.rows, 4);
        assert_eq!(frame.cell(0, 0).ch, 'h');
    }
}
