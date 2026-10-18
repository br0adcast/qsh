//! `qsh`: a terminal over the qsh transport.
//!
//! The order here is not arbitrary. Everything that asks the user something
//! -- the server's fingerprint on first contact, a key's passphrase --
//! happens BEFORE raw mode: afterwards the terminal is busy with a picture,
//! and a question printed over a frame ruins both.

use std::collections::VecDeque;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::time::{Duration, Instant};

use render::{ColorDepth, TermCaps};

use ::connect::reconnect::{Event, Order, Phase, Reconnect, RoundEnd, Stop};
use ::connect::recovery_gate::{AddressId, RecoveryEpoch};
use ::connect::Address;
use client::channel::{ChannelId, ChannelSession, SessionEvent};
use client::qsh::QshSubstrate;
use qsh::port_probe::{PortProbe, RefusalWindow};
use qsh::road_catalog::{BoundedResolver, RoadCatalog, RoadWork};
use transport::driver_std::UseRoadOutcome;
use transport::paths::{PathState, RoadInfo};
use transport::shell_frame::{encode_record, REC_DATA, REC_ECHO_ACK};
use transport::LinkState;

use qsh::background::Round;
use qsh::climb::{Climb, Climbed, Connected, Mode, Setup, Sink, Trial};
use qsh::session::{self as session, Action, Chrome, Session, UiEvent};
use qsh::ticker::Ticker;
use qsh::{
    args, background, connect, known_hosts, log, prompt, sessions, signals, status, trust, tty,
    window,
};

/// How often the loop wakes to expire predictions, advance the "link lost"
/// counter and let a settled resize out.
const TICK: Duration = Duration::from_millis(20);

/// How often the roads are looked at while the connection-state window is
/// open, and while it is not (the status line names the road in use).
const ROADS_WINDOW_MS: i64 = 500;
const ROADS_LINE_MS: i64 = 1000;

fn main() {
    let argv: Vec<_> = std::env::args_os().skip(1).collect();
    let parsed = match args::parse_args_os(&argv) {
        Ok(a) => a,
        Err(args::ArgError::HelpRequested) => {
            print!("{}", args::USAGE);
            std::process::exit(0);
        }
        Err(args::ArgError::VersionRequested) => {
            print!("{}", args::VERSION_TEXT);
            std::process::exit(0);
        }
        Err(e) => {
            eprintln!("qsh: {e}\n\n{}", args::USAGE);
            std::process::exit(2);
        }
    };
    log::init(parsed.verbose);
    log::log(&log::start_marker(&parsed));
    let code = run(parsed);
    log::log(&log::exit_marker(code));
    std::process::exit(code);
}

fn run(a: args::Args) -> i32 {
    if let Err(error) = signals::install() {
        eprintln!("qsh: could not install signal handlers: {error}");
        return 1;
    }
    let config = match qsh::paths::prepare_config() {
        Ok(path) => path,
        Err(error) => {
            eprintln!("qsh: {error}");
            log::error(&error.to_string());
            return 1;
        }
    };
    // Determined once, here, rather than inside `interactive`: the trial
    // has to tell the server this size when it opens the shell channel,
    // before any attempt is even known to work, and a later fresh query
    // could in principle disagree with what was actually sent.
    let (cols, rows) = tty::window_size(std::io::stdout().as_raw_fd()).unwrap_or((80, 24));
    // The shell gets the terminal minus the status line: that is the size
    // the trial opens the shell channel at, and the one `Session` keeps.
    let (shell_cols, shell_rows) = session::shell_size(cols, rows, a.status_line);

    // Which session for this login and endpoint this run is coming back to.
    // The lock is held for the whole run: another `qsh` using that tuple takes
    // the next slot instead of stealing this one's shell.
    let mut claim = sessions::claim(
        &config.join("sessions"),
        &a.login,
        &a.addresses[0].host,
        a.addresses[0].qsh_port,
    );

    let mut setup = Arc::new(Setup::new(
        a,
        // The one Noise static key of this process (spec §4.2).
        transport::generate_keypair(),
        // The qsh server keys pinned so far -- not ssh's `known_hosts`,
        // which the ssh step reads for itself.
        sshauth::known_hosts::KnownHosts::open(config.join("known_hosts")),
        Box::new(trust::UdpDiscovery),
        prompt::Tty::new(),
        known_hosts::KnownHosts::standard(),
        std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from),
        dirs::home_dir().map(|h| h.join(".ssh")),
        claim.token,
    ));

    // The connection's own channel: a failed attempt's events are dropped
    // from it, and once logged in they reach the main loop's through the
    // forwarder, stamped with the connection's number.
    let (link_tx, link_rx) = mpsc::channel::<UiEvent>();
    let mut climb = Climb::new(
        &setup,
        setup.args().addresses.clone(),
        0,
        Mode::Login,
        shell_cols,
        shell_rows,
        link_tx,
        &link_rx,
    );
    let climbed = climb.run();
    if signals::termination_requested() {
        return 130;
    }
    let connected = match climbed {
        Climbed::Exit(code) => return code,
        Climbed::Connected(c) => c,
        Climbed::Failed { .. } => unreachable!("only a background round ends as Failed"),
    };
    drop(climb);
    if setup.args().authorize_ssh {
        let server = setup
            .server_identity()
            .expect("successful QSH login establishes identity");
        let mut endpoints = Vec::new();
        for address in &setup.args().addresses {
            if let Some(route) = &address.ssh {
                let endpoint = ::connect::server_identity::SshEndpoint {
                    host: address.host.clone(),
                    port: route.port,
                };
                if !endpoints.contains(&endpoint) {
                    endpoints.push(endpoint);
                }
            }
        }
        let permit = setup.begin_ssh_authorization(::connect::recovery_gate::RecoveryEpoch {
            connection: 0,
            network: 0,
        });
        let cancel = knock::Cancel::new();
        if let Err(error) =
            qsh::ssh_authorization::authorize_ssh(&server, &endpoints, &setup, &permit, &cancel)
        {
            eprintln!("qsh: {error}; QSH session remains connected");
        }
        setup.invalidate_ssh_authorization();
        if signals::termination_requested() {
            return 130;
        }
    }
    let mut connected = connected;
    let mut events = link_rx;
    let mut display = DisplaySize {
        physical: (cols, rows),
        logical: (shell_cols, shell_rows),
    };
    let mut addresses = setup.args().addresses.clone();
    let mut epoch = RecoveryEpoch {
        connection: 0,
        network: 0,
    };
    let mut resolver = BoundedResolver::new();
    loop {
        let (code, links) = connected_session(
            setup.clone(),
            connected,
            events,
            &mut display,
            addresses,
            epoch,
            resolver,
        );
        let lost = links.replacement_at.is_some();
        addresses = links.addresses.clone();
        let first = links.replacement_at.unwrap_or(links.at);
        epoch = RecoveryEpoch {
            connection: links.road_epoch.connection + 1,
            network: links.road_epoch.network,
        };
        let active = links.road_active;
        let mut catalog = RoadCatalog::new(addresses.clone(), epoch);
        for (id, endpoint) in links.catalog.endpoints() {
            catalog.seed(id, endpoint);
        }
        // Cancels workers and invalidates their authorization before any question.
        resolver = links.leave();
        if !lost {
            return code;
        }
        discard_terminal_input();
        let accepted =
            prompt::Tty::new().confirm_replacement("Start a new session?", &knock::Cancel::new());
        if signals::termination_requested() {
            return 130;
        }
        if !matches!(accepted, Ok(true)) {
            return 13;
        }
        discard_terminal_input();
        let token = match claim.replace_token() {
            Ok(token) => token,
            Err(error) => {
                eprintln!("qsh: could not save the replacement session: {error}");
                return 1;
            }
        };
        setup = Arc::new(setup.replacement(token));
        if let Some(physical) = tty::window_size(std::io::stdout().as_raw_fd()) {
            display.physical = physical;
            if physical.0 != 0 && physical.1 != 0 {
                display.logical =
                    session::shell_size(physical.0, physical.1, setup.args().status_line);
            }
        }
        let shell_size = display.logical;
        let start_round = |epoch, catalog: &RoadCatalog| {
            let (progress, _) = mpsc::channel();
            background::spawn_catalog_round(
                setup.clone(),
                addresses.clone(),
                first,
                shell_size,
                1,
                progress,
                epoch,
                catalog.address_ids(),
                catalog.endpoints(),
                true,
            )
        };
        let mut task = start_round(epoch, &catalog);
        eprintln!("qsh: starting a new session");
        let started = Instant::now();
        loop {
            resolve_roads(
                &mut catalog,
                &mut resolver,
                epoch,
                started.elapsed(),
                active,
                true,
            );
            task.update_endpoints(epoch, catalog.endpoints());
            if signals::termination_requested() {
                return 130;
            }
            match task.try_recv() {
                Ok(Round::Connected {
                    connected: fresh,
                    events: fresh_events,
                }) => {
                    connected = fresh;
                    events = fresh_events;
                    break;
                }
                Ok(Round::Failed { .. }) | Err(TryRecvError::Disconnected) => {
                    // A DNS revision can invalidate a queued result. It remains
                    // a failed path, rather than a refusal of the accepted choice.
                    drop(task);
                    epoch.connection += 1;
                    resolver.cancel();
                    catalog.reset(epoch);
                    task = start_round(epoch, &catalog);
                }
                Err(TryRecvError::Empty) => std::thread::sleep(TICK),
            }
        }
        // Stop the replacement recovery before the live session takes ownership.
        drop(task);
        resolver.cancel();
        epoch.connection += 1;
    }
}

struct DisplaySize {
    physical: (u16, u16),
    logical: (u16, u16),
}

/// Everything before this point uses the restored controlling terminal.
fn connected_session(
    setup: Arc<Setup>,
    connected: Connected,
    events: Receiver<UiEvent>,
    display: &mut DisplaySize,
    mut addresses: Vec<Address>,
    road_epoch: RecoveryEpoch,
    resolver: BoundedResolver,
) -> (i32, Links) {
    let (tx, rx) = mpsc::channel::<UiEvent>();
    background::forward(0, events, tx.clone());
    let Connected {
        attempt,
        trial,
        addr,
        port,
        remote,
    } = connected;
    log::log(&format!("logged in at address {addr}, qsh port {port}"));
    log::log(&connect::features_line(attempt.client.features()));
    if let Some(buffers) = attempt.client.socket_buffers() {
        log::log(&buffers.line());
    }

    // No death timer of this client's own: the link dies by the transport's
    // client death timer (`CLIENT_DEATH_AFTER`, 45 s), and that death is
    // this client's cue to
    // reconnect into the same session (spec §5.2, decision 1 of the slice 4
    // plan). A short outage never gets that far: the transport rides it out
    // by itself.

    // The addresses as this run knows them from now on: the one logged in at
    // keeps the port the daemon was actually reached on (spec §5.1).
    addresses[addr].qsh_port = port;
    let labels = labels(remote, &addresses, addr);
    let mut catalog = RoadCatalog::new(addresses.clone(), road_epoch);
    catalog.seed(AddressId(addr), remote);

    // The trial's size is the shell's; `interactive` wants the terminal's.
    let Trial {
        channel_session,
        opened_ch,
        ..
    } = trial;
    let links = Links {
        setup: setup.clone(),
        live: Some(Live {
            attempt,
            channel_session,
            link: 0,
        }),
        shell_channel: opened_ch,
        next_link: 1,
        reconnect: Reconnect::new(addr),
        addresses,
        at: addr,
        labels,
        roads_at: None,
        catalog,
        resolver,
        road_epoch,
        road_origin: Instant::now(),
        road_active: remote,
        refusal: None,
        probe_attempt: 0,
        keep: false,
        round: None,
        rounds: 0,
        round_line: None,
        farewell: None,
        stopped: false,
        replacement_at: None,
        tx: tx.clone(),
    };
    interactive(setup, links, display, tx, rx)
}

/// Keep the same bounded resolver pool across shell lifetimes, including the
/// restored-terminal wait for an accepted replacement. DNS never grants trust.
fn resolve_roads(
    catalog: &mut RoadCatalog,
    resolver: &mut BoundedResolver,
    epoch: RecoveryEpoch,
    now: Duration,
    active: SocketAddr,
    urgent: bool,
) -> Option<Vec<SocketAddr>> {
    for result in resolver.poll(now) {
        catalog.resolved(result.epoch, result.request, result.address, result.result);
    }
    let mut publish = None;
    for work in catalog.refresh(now, active, urgent) {
        match work {
            RoadWork::Resolve {
                request,
                address,
                host,
                port,
            } => {
                if !resolver.submit(epoch, request, address, host, port, now) {
                    catalog.deferred(request, address);
                }
            }
            RoadWork::Publish { paths } => publish = Some(paths),
        }
    }
    publish
}

/// A road as the window names it: the address's index on the command line,
/// the socket address it resolved to, and `host:port` as the person knows it.
type Label = (usize, SocketAddr, String);

/// Initial labels use only numeric endpoints and the authenticated login road.
/// Names remain in RoadCatalog and join asynchronously as DNS completes.
fn labels(remote: SocketAddr, addresses: &[Address], live: usize) -> Vec<Label> {
    addresses
        .iter()
        .enumerate()
        .filter_map(|(i, a)| {
            let at = if i == live {
                Some(remote)
            } else {
                a.host
                    .parse::<IpAddr>()
                    .ok()
                    .map(|ip| SocketAddr::new(ip, a.qsh_port))
            };
            at.map(|at| (i, at, host_port(&a.host, a.qsh_port)))
        })
        .collect()
}

/// `host:port`, an IPv6 literal in brackets.
fn host_port(host: &str, port: u16) -> String {
    format!("{}:{port}", status::bracketed(host))
}

/// The roads this session may use: the address in use (`live`) first, then
/// the others.
///
/// The address in use is on the list deliberately -- the table chooses from
/// what it holds, so leaving it off would mean nothing to come back to when it
/// revives.
#[cfg(test)]
fn paths(labels: &[Label], live: usize) -> Vec<SocketAddr> {
    let in_use = labels.iter().filter(|l| l.0 == live);
    let others = labels.iter().filter(|l| l.0 != live);
    in_use.chain(others).map(|l| l.1).collect()
}

/// The roads as the window lists them: command-line order, the one in use
/// marked. `roads` is what the transport's table says about each; with none
/// (one address: the table was never handed roads) the one road is the
/// address in use, answering at `rtt_ms`.
fn road_list(
    labels: &[Label],
    roads: &[RoadInfo],
    active: Option<SocketAddr>,
    rtt_ms: u32,
) -> Vec<window::Road> {
    if roads.is_empty() {
        let one = labels
            .iter()
            .find(|l| Some(l.1) == active)
            .or(labels.first());
        return one
            .map(|(_, addr, label)| window::Road {
                addr: *addr,
                label: label.clone(),
                in_use: true,
                state: PathState::Verified,
                ewma_ms: (rtt_ms > 0).then_some(rtt_ms),
                failed_ago_ms: None,
            })
            .into_iter()
            .collect();
    }
    labels
        .iter()
        .map(|(_, addr, label)| {
            let info = roads.iter().find(|r| r.addr == *addr);
            window::Road {
                addr: *addr,
                label: label.clone(),
                in_use: active == Some(*addr),
                state: info.map_or(PathState::Unverified, |r| r.state),
                ewma_ms: info.and_then(|r| r.ewma_ms),
                failed_ago_ms: info.and_then(|r| r.failed_ago_ms),
            }
        })
        .collect()
}

/// The addresses, as `(host, port)`, whose road answered the live
/// session's own checks (spec §4a rule 4): only the session's peer can
/// answer one, so the daemon there holds the session's key.
fn proven_roads(labels: &[Label], addresses: &[Address], table: &[RoadInfo]) -> Vec<(String, u16)> {
    labels
        .iter()
        .filter(|(_, at, _)| {
            table
                .iter()
                .any(|r| r.addr == *at && r.state == PathState::Verified)
        })
        .map(|(i, _, _)| (addresses[*i].host.clone(), addresses[*i].qsh_port))
        .collect()
}

/// Flushes `shell_bytes` -- whatever `Data`/`InputConsumed` records the
/// current batch's `Wire` events have decoded and re-framed so far -- through
/// `Session` in ONE `Stream0` call, if there is anything to flush. This, not
/// one `handle` call per record, is what lets a delivery that decodes into
/// many records collapse into one diff-paint: see `shell_bytes`'s own doc at
/// its declaration in `interactive` for the failure this avoids.
fn flush_shell_bytes(shell_bytes: &mut Vec<u8>, sess: &mut Session, now_ms: i64) -> Vec<Action> {
    if shell_bytes.is_empty() {
        Vec::new()
    } else {
        sess.handle(UiEvent::Stream0(std::mem::take(shell_bytes)), now_ms)
    }
}

/// The connection a session is running on.
struct Live {
    attempt: connect::Attempt,
    /// The one substrate instance of this connection: incoming bytes go
    /// through `channel_session.on_bytes`, which hands them to the substrate
    /// and maps what comes back into `SessionEvent`s in one call, so there
    /// is no second, independent decode-only instance to keep in sync with
    /// it (a closed channel's deframer used to outlive the channel exactly
    /// because that second instance was the one `close()` never reached).
    channel_session: ChannelSession<QshSubstrate<Sink>>,
    /// Its number: its events arrive stamped with it (`background::forward`).
    link: u64,
}

/// The link side of the main loop: the connection in use, if there is one,
/// and everything that brings a dead one back into the same session (spec
/// §5.2) -- the reconnect automaton, the round under way, the addresses as
/// this run knows them.
struct Links {
    setup: Arc<Setup>,
    /// `None` from the moment a link is let go until a round brings one back.
    live: Option<Live>,
    /// The wire stream the shell channel is on, on the live connection --
    /// known immediately, from the trial's own `open_shell` call, not once
    /// the far side confirms it: the two travel on independent streams, so
    /// the channel's own data could in principle arrive before its `Opened`
    /// record does. After a return, `Ready` sets it for the channel the
    /// server still had.
    shell_channel: Option<ChannelId>,
    /// The number the next connection gets.
    next_link: u64,
    reconnect: Reconnect,
    /// A port a daemon reported replaces the one on the command line, for
    /// the rest of the run (spec §5.1).
    addresses: Vec<Address>,
    /// The address the session is on now -- or, between two connections,
    /// was on last: whose host the way out names.
    at: usize,
    /// The live connection's roads as the window names them.
    labels: Vec<Label>,
    /// When the roads were last looked at; `None` makes the next turn look.
    roads_at: Option<i64>,
    catalog: RoadCatalog,
    resolver: BoundedResolver,
    road_epoch: RecoveryEpoch,
    road_origin: Instant,
    road_active: SocketAddr,
    refusal: Option<(RefusalWindow, Option<PortProbe>, Duration)>,
    probe_attempt: u64,
    /// The person left with `Ctrl-] .`: the live link is let go quietly, so
    /// the session stays on the server.
    keep: bool,
    /// The round under way: its answer arrives here.
    round: Option<background::RoundTask>,
    /// The number of the last round started: its progress is the only one
    /// shown, and only while it runs.
    rounds: u64,
    /// What the last round that got no session had to say: a changed key or
    /// a gone session, for the way out; after every address failed, the
    /// hint to show until the next round.
    round_line: Option<String>,
    /// The line that ended the run (`Order::Stop`), for once the terminal is
    /// restored.
    farewell: Option<String>,
    /// The session or tracked shell is unavailable, or its key changed:
    /// there is no kept shell to report on the way out.
    stopped: bool,
    /// Explicit lifecycle evidence that the tracked shell is unavailable,
    /// and the authenticated road to prefer if replacement is accepted.
    replacement_at: Option<usize>,
    /// The main loop's own channel: where rounds say how they go, and where
    /// every connection's forwarder delivers.
    tx: Sender<UiEvent>,
}

impl Links {
    /// `ev` as the main loop should see it: a connection's event unwrapped
    /// when it is the live connection's, and `None` for anything from a
    /// connection already let go -- an old link's late `Closed` must not end
    /// the run, nor its bytes land in the new connection's channels -- and
    /// for a round's progress once that round is not the one under way.
    fn current(&self, ev: UiEvent) -> Option<UiEvent> {
        match ev {
            UiEvent::FromLink { link, event } => match &self.live {
                Some(live) if live.link == link => Some(*event),
                _ => None,
            },
            // Progress travels apart from the round's answer, so it can
            // arrive late: after the round ended, and a `Waiting` plate went
            // up that it must not replace.
            UiEvent::Reconnecting { round, .. }
                if !progress_counts(round, self.rounds, self.round.is_some()) =>
            {
                None
            }
            other => Some(other),
        }
    }

    /// Whether the live link just ended without a `Close`: the transport's
    /// own death timer ran out. That is the cue to reconnect; a graceful end
    /// goes to `Session`, which leaves.
    fn died(&self) -> bool {
        self.live
            .as_ref()
            .is_some_and(|live| !live.attempt.client.closed_gracefully())
    }

    /// Tells the automaton what happened and does what it says.
    fn on(&mut self, event: Event, sess: &mut Session, now_ms: i64) -> Vec<Action> {
        // Nothing follows `Stop`: the run is on its way out.
        if self.reconnect.phase() == Phase::Over {
            return Vec::new();
        }
        if event == Event::Now {
            if let Some(round) = &self.round {
                round.retry_now();
            }
        }
        let order = self.reconnect.on(event, at(now_ms));
        let mut actions = self.obey(order, sess, now_ms);
        if let (Event::RoundOver(RoundEnd::AllFailed), Phase::Waiting { until }) =
            (event, self.reconnect.phase())
        {
            actions.extend(sess.handle(
                UiEvent::ReconnectWaiting {
                    until_ms: until.as_millis() as i64,
                    hint: self.round_line.take(),
                },
                now_ms,
            ));
        }
        actions
    }

    /// One turn of the loop: time passed, and the round under way may have
    /// an answer.
    fn turn(&mut self, sess: &mut Session, now_ms: i64) -> Vec<Action> {
        self.refresh_catalog();
        let accelerate = self.poll_refusal();
        let mut actions = self.refresh_roads(sess, now_ms);
        actions.extend(self.refresh_recovery_status(sess, now_ms));
        if accelerate {
            log::log("recovery: refused live port after complete QSH path sweep");
            actions.extend(self.on(Event::Now, sess, now_ms));
        }
        actions.extend(self.on(Event::Tick, sess, now_ms));
        let Some(round) = &self.round else {
            return actions;
        };
        let ended = match round.try_recv() {
            Ok(ended) => ended,
            Err(TryRecvError::Empty) => return actions,
            // The round's thread died without an answer (a panic): as a round
            // that got nowhere, so the next one comes after the pause.
            Err(TryRecvError::Disconnected) => {
                log::log("reconnect: the round ended without an answer; counted as all failed");
                Round::Failed {
                    end: RoundEnd::AllFailed,
                    line: None,
                }
            }
        };
        if let Round::Failed {
            end: RoundEnd::SessionGone { addr },
            ..
        } = &ended
        {
            // Keep the road that just authenticated the expected server, rather
            // than paying the old live road's timeout again after consent.
            if let Some(endpoint) = round.endpoint(*addr) {
                self.addresses[*addr].qsh_port = endpoint.port();
                self.catalog.seed(AddressId(*addr), endpoint);
            }
        }
        self.round = None;
        match ended {
            Round::Connected { connected, events } => {
                actions.extend(self.adopt(connected, events, sess, now_ms));
            }
            Round::Failed { end, line } => {
                log::log(&format!("reconnect: the round ended: {end:?}"));
                self.round_line = line;
                actions.extend(self.on(Event::RoundOver(end), sess, now_ms));
            }
        }
        actions
    }

    /// Carries out one order of the automaton.
    fn obey(&mut self, order: Order, sess: &mut Session, now_ms: i64) -> Vec<Action> {
        match order {
            Order::Nothing => Vec::new(),
            Order::Climb { first, detach } => {
                log::log(&format!(
                    "reconnect: a round from address {first}{}",
                    if detach {
                        ", letting the live link go"
                    } else {
                        ""
                    }
                ));
                // Let go quietly, never `close`: `Close` tells the server to
                // drop the session at once, and the round would have nothing
                // to come back to. A link that already died has nothing left
                // to say, so this only waits for its thread.
                if let Some(live) = self.live.take() {
                    live.attempt.detach();
                }
                self.advance_epoch(false);
                self.shell_channel = None;
                let actions = sess.on_link_gone(now_ms);
                self.rounds += 1;
                self.round = Some(background::spawn_catalog_round(
                    self.setup.clone(),
                    self.addresses.clone(),
                    first,
                    sess.size(),
                    self.rounds,
                    self.tx.clone(),
                    self.road_epoch,
                    self.catalog.address_ids(),
                    self.catalog.endpoints(),
                    false,
                ));
                actions
            }
            Order::Stop(stop) => {
                if let Stop::SessionGone { addr } = stop {
                    self.replacement_at = Some(addr);
                }
                let (code, line) = match stop {
                    Stop::KeyChanged { .. } => (11, self.round_line.take()),
                    Stop::SessionGone { addr } => (
                        13,
                        Some(self.round_line.take().unwrap_or_else(|| {
                            status::session_gone_text(&self.addresses[addr].host)
                        })),
                    ),
                };
                log::log(&format!("reconnect: stop: {stop:?}"));
                self.farewell = line;
                self.stopped = true;
                // `Session` puts the terminal back the way any exit of its
                // own does (`Terminate` is the one way to ask it to); only
                // the code is this order's, not its 0.
                let mut actions: Vec<Action> = sess
                    .handle(UiEvent::Terminate, now_ms)
                    .into_iter()
                    .filter(|a| !matches!(a, Action::Exit(_)))
                    .collect();
                actions.push(Action::Exit(code));
                actions
            }
        }
    }

    /// A round got back into the session: this connection is the live one now.
    fn adopt(
        &mut self,
        connected: Connected,
        events: Receiver<UiEvent>,
        sess: &mut Session,
        now_ms: i64,
    ) -> Vec<Action> {
        let Connected {
            attempt,
            trial,
            addr,
            port,
            remote,
        } = connected;
        log::log(&format!("reconnected at address {addr}, qsh port {port}"));
        log::log(&connect::features_line(attempt.client.features()));
        self.addresses[addr].qsh_port = port;
        self.at = addr;
        self.advance_epoch(false);
        self.catalog = RoadCatalog::new(self.addresses.clone(), self.road_epoch);
        self.catalog.seed(AddressId(addr), remote);
        self.road_active = remote;
        self.labels = labels(remote, &self.addresses, addr);
        self.roads_at = None;
        // Before the forwarder starts: the server's list of what it still
        // runs (`on_announced`) must find the session already reattaching.
        let mut actions = sess.on_reattached(now_ms);
        let link = self.next_link;
        self.next_link += 1;
        background::forward(link, events, self.tx.clone());
        self.shell_channel = trial.opened_ch;
        self.live = Some(Live {
            attempt,
            channel_session: trial.channel_session,
            link,
        });
        actions.extend(self.on(Event::RoundOver(RoundEnd::Connected { addr }), sess, now_ms));
        actions
    }

    /// DNS and catalog scheduling run every loop turn, independently of UI
    /// publication and background SSH rounds. No resolver call runs here.
    fn refresh_catalog(&mut self) {
        let now = self.road_origin.elapsed();
        let urgent = if let Some(live) = &self.live {
            let client = &live.attempt.client;
            self.road_active = client.active_path().unwrap_or(self.road_active);
            for (endpoint, sent) in client.path_probes() {
                if let Some(sent) = sent.checked_duration_since(self.road_origin) {
                    self.catalog.probed(endpoint, sent);
                }
            }
            u64::from(client.stats().silent_secs) >= transport::PATH_DOWN_AFTER.as_secs()
        } else {
            true
        };
        if let Some(paths) = resolve_roads(
            &mut self.catalog,
            &mut self.resolver,
            self.road_epoch,
            now,
            self.road_active,
            urgent,
        ) {
            if let Some(live) = &self.live {
                live.attempt.client.set_paths(paths);
            }
        }
        if let Some(round) = &self.round {
            round.update_endpoints(self.road_epoch, self.catalog.endpoints());
        }
        self.labels = self
            .catalog
            .endpoints()
            .into_iter()
            .map(|(id, endpoint)| {
                let address = &self.addresses[id.0];
                (id.0, endpoint, host_port(&address.host, address.qsh_port))
            })
            .collect();
        if !self
            .labels
            .iter()
            .any(|(_, endpoint, _)| *endpoint == self.road_active)
        {
            let address = &self.addresses[self.at];
            self.labels.push((
                self.at,
                self.road_active,
                host_port(&address.host, address.qsh_port),
            ));
        }
    }

    /// Invalidate every writer before changing the common catalog/worker epoch.
    fn advance_epoch(&mut self, network: bool) {
        self.setup.invalidate_ssh_authorization();
        self.round = None;
        if network {
            self.road_epoch.network += 1;
        } else {
            self.road_epoch.connection += 1;
        }
        self.resolver.cancel();
        self.catalog.reset(self.road_epoch);
        self.refusal = None;
    }

    /// Notification hook only: desktop also keeps periodic DNS/probes/retries.
    /// No platform network watcher is installed by this module.
    fn network_changed(&mut self, sess: &mut Session, now_ms: i64) -> Vec<Action> {
        let recovering = self.round.is_some();
        self.advance_epoch(true);
        if recovering {
            self.obey(
                Order::Climb {
                    first: self.at,
                    detach: false,
                },
                sess,
                now_ms,
            )
        } else {
            Vec::new()
        }
    }

    fn poll_refusal(&mut self) -> bool {
        let Some(live) = &self.live else {
            self.refusal = None;
            return false;
        };
        let client = &live.attempt.client;
        if u64::from(client.stats().silent_secs) < transport::PATH_DOWN_AFTER.as_secs() {
            self.refusal = None;
            return false;
        }
        let now = self.road_origin.elapsed();
        let active = client.active_path().unwrap_or(self.road_active);
        if self.refusal.is_none() {
            self.probe_attempt += 1;
            self.refusal = Some((
                RefusalWindow::new(
                    self.road_epoch,
                    self.probe_attempt,
                    now,
                    self.catalog.address_ids(),
                ),
                None,
                Duration::ZERO,
            ));
        }
        let (window, probe, retry_at) = self.refusal.as_mut().expect("refusal window");
        if now >= *retry_at {
            *probe = PortProbe::start(active, self.road_epoch, self.probe_attempt).ok();
            *retry_at = now + Duration::from_secs(1);
        }
        if let Some(probe) = probe {
            window.observe_refusal(probe.poll());
        }
        for (endpoint, sent) in client.path_probes() {
            if let Some(sent) = sent.checked_duration_since(self.road_origin) {
                window.probed(endpoint, sent);
            }
        }
        let verified: Vec<_> = client
            .roads()
            .iter()
            .filter(|road| road.state == PathState::Verified)
            .map(|road| road.addr)
            .collect();
        window.ready(now, active, &self.catalog.endpoints(), &verified)
    }

    /// Observe current work only; the complete catalog remains the source of
    /// logical names even when transport probes rotate through eight sockets.
    fn refresh_recovery_status(&self, sess: &mut Session, now_ms: i64) -> Vec<Action> {
        let outage = self.round.is_some()
            || self.live.is_none()
            || self.live.as_ref().is_some_and(|l| {
                u64::from(l.attempt.client.stats().silent_secs)
                    >= transport::PATH_DOWN_AFTER.as_secs()
            });
        let view = outage.then(|| {
            let activity = self.round.as_ref().map(background::RoundTask::activity);
            let warm: Vec<_> = self
                .live
                .as_ref()
                .map(|live| {
                    let table = live.attempt.client.roads();
                    live.attempt
                        .client
                        .path_probes()
                        .into_iter()
                        .filter(|(endpoint, _)| table.iter().any(|r| r.addr == *endpoint))
                        .collect()
                })
                .unwrap_or_default();
            qsh::recovery_status::View::build(
                &self.addresses,
                &self.catalog.endpoints(),
                &self.catalog.resolving(),
                &warm,
                activity.as_ref(),
                Instant::now(),
            )
        });
        sess.handle(UiEvent::RecoveryStatus { view }, now_ms)
    }

    /// Tells `Session` how the live connection's roads look, when it is time
    /// to: every `ROADS_WINDOW_MS` while a window is open, every
    /// `ROADS_LINE_MS` otherwise. The road in use is also where the next
    /// round starts, should this link die.
    fn refresh_roads(&mut self, sess: &mut Session, now_ms: i64) -> Vec<Action> {
        let Some(live) = &self.live else {
            return Vec::new();
        };
        let every = if sess.window_open() {
            ROADS_WINDOW_MS
        } else {
            ROADS_LINE_MS
        };
        if self.roads_at.is_some_and(|at| now_ms - at < every) {
            return Vec::new();
        }
        self.roads_at = Some(now_ms);
        let client = &live.attempt.client;
        let table = client.roads();
        self.setup
            .remember_roads(&proven_roads(&self.labels, &self.addresses, &table));
        let roads = road_list(
            &self.labels,
            &table,
            client.active_path(),
            client.stats().rtt_ms,
        );
        let in_use = roads
            .iter()
            .find(|r| r.in_use)
            .and_then(|r| self.labels.iter().find(|l| l.1 == r.addr));
        if let Some(&(i, _, _)) = in_use {
            self.at = i;
            self.reconnect.in_use(i);
        }
        sess.handle(UiEvent::Roads { roads }, now_ms)
    }

    /// Moves the traffic to road `addr`, as the window asked. The transport
    /// may take up to a second to answer, so it is asked on a thread of its
    /// own, and the answer arrives as `UiEvent::RoadSwitched`. With no link
    /// there is nothing to move: the answer is `false` at once.
    fn use_road(&self, addr: SocketAddr, sess: &mut Session, now_ms: i64) -> Vec<Action> {
        let Some(live) = &self.live else {
            log::log(&format!("no link to move to road {addr}"));
            return sess.handle(UiEvent::RoadSwitched { ok: false }, now_ms);
        };
        let client = live.attempt.client.clone();
        let tx = self.tx.clone();
        let link = live.link;
        let started = std::thread::Builder::new()
            .name("qsh-use-road".into())
            .spawn(move || {
                let outcome = client.use_road(addr);
                log::log(&format!("road {addr}: {outcome:?}"));
                let ok = matches!(
                    outcome,
                    UseRoadOutcome::Moved | UseRoadOutcome::AlreadyInUse
                );
                // The main loop gone means the run is ending: nobody to tell.
                let _ = tx.send(UiEvent::FromLink {
                    link,
                    event: Box::new(UiEvent::RoadSwitched { ok }),
                });
            });
        match started {
            Ok(_) => Vec::new(),
            Err(e) => {
                log::log(&format!("could not ask for road {addr}: {e}"));
                sess.handle(UiEvent::RoadSwitched { ok: false }, now_ms)
            }
        }
    }

    /// The way out, once the terminal is restored: the line that ended the
    /// run, if any; what became of the session; the live connection closed
    /// -- or, when the person left with `Ctrl-] .`, let go quietly, so the
    /// server keeps the session for the next run.
    /// A round still under way is not waited for: the process exits, and
    /// the round's thread with it. A round whose answer is already waiting
    /// holds a live connection into the session: it is let go quietly, not
    /// dropped -- dropping it could send `Close` while "kept" is printed.
    fn leave(mut self) -> BoundedResolver {
        self.setup.invalidate_ssh_authorization();
        self.resolver.cancel();
        let host = self.addresses[self.at].host.as_str();
        if let Some(Ok(Round::Connected { connected, .. })) =
            self.round.as_ref().map(background::RoundTask::try_recv)
        {
            log::log("leaving: a round had just got back in; letting it go");
            connected.attempt.detach();
        }
        if let Some(line) = &self.farewell {
            eprintln!("{line}");
        }
        match &self.live {
            Some(live) => {
                // Read before `close`, which ends the connection with this
                // client's own `Close` and would make any ending look
                // graceful.
                let closed = live
                    .attempt
                    .events
                    .closed
                    .load(std::sync::atomic::Ordering::SeqCst);
                let graceful = live.attempt.client.closed_gracefully();
                // A peer that already said `Close` has dropped the session:
                // there is nothing kept to tell the person about.
                if self.keep && !graceful {
                    log::log("leaving; letting the link go, the session stays");
                    eprintln!("{}", status::left_kept_notice(host));
                    live.attempt.detach();
                    return self.resolver;
                }
                if let Some(notice) = status::kept_session_notice(host, closed, graceful) {
                    eprintln!("{notice}");
                }
                live.attempt.close();
            }
            // Leaving in the middle of a reconnect: the link was let go
            // quietly, so the server still has the session -- and a person
            // who left with `Ctrl-] .` is told they left.
            None if !self.stopped => {
                eprintln!("{}", status::mid_reconnect_notice(host, self.keep));
            }
            None => {}
        }
        self.resolver
    }
}

/// Whether progress stamped `round` is shown: only while it is the `current`
/// round and that round is still `running`.
fn progress_counts(round: u64, current: u64, running: bool) -> bool {
    running && round == current
}

/// `now_ms` on the session's clock, as the automaton takes it.
fn at(now_ms: i64) -> Duration {
    Duration::from_millis(now_ms.max(0) as u64)
}

/// Applies one batch of `Action`s: writes to the terminal and drives the
/// channel session. Returns the exit code once an `Exit` is among them, or
/// once the shell channel could not be opened -- the caller stops applying
/// (and stops the whole batch) the moment this returns `Some`. `Ctrl-] r`
/// (`Action::Reconnect`) is carried out on the spot, and what it asks for
/// comes after the rest of the batch -- `Session` asks for nothing after
/// `Reconnect` in the same read, so nothing is reordered; a notice is kept
/// for the way out.
fn apply_actions(
    actions: Vec<Action>,
    stdout: &mut impl Write,
    links: &mut Links,
    sess: &mut Session,
    notices: &mut Vec<String>,
    now_ms: i64,
) -> Option<i32> {
    let mut queue = VecDeque::from(actions);
    while let Some(action) = queue.pop_front() {
        match action {
            Action::Write(bytes) => {
                let _ = stdout.write_all(&bytes);
                let _ = stdout.flush();
            }
            Action::Exit(c) => return Some(c),
            // Printed after the terminal is restored, not here in raw mode.
            Action::Notice(text) => notices.push(text),
            Action::ShellUnavailable => {
                links.replacement_at = Some(links.at);
                links.stopped = true;
            }
            Action::Reconnect => {
                queue.extend(links.on(Event::Now, sess, now_ms));
            }
            // Carried out on the way out (`Links::leave`).
            Action::Keep => links.keep = true,
            Action::UseRoad(addr) => queue.extend(links.use_road(addr, sess, now_ms)),
            channel_action => {
                // Between two connections there is no channel to drive:
                // `Session` asks for nothing then (and drops what is typed
                // after `Ctrl-] r` in the same read).
                let Some(live) = links.live.as_mut() else {
                    log::log(&format!(
                        "no link for {}; dropped",
                        match &channel_action {
                            Action::OpenShell { .. } => "opening the shell",
                            Action::SendChannel { .. } => "input",
                            _ => "a resize",
                        }
                    ));
                    continue;
                };
                match channel_action {
                    Action::OpenShell { cols, rows } => {
                        match live.channel_session.open_shell(cols, rows) {
                            Some(ch) => links.shell_channel = Some(ch),
                            None => {
                                notices.push(
                                    "qsh: could not open shell channel: channel numbers exhausted"
                                        .into(),
                                );
                                return Some(1);
                            }
                        }
                    }
                    Action::SendChannel { ch, bytes } => live.channel_session.send(ch, &bytes),
                    Action::ResizeChannel { ch, cols, rows } => {
                        live.channel_session.resize(ch, cols, rows)
                    }
                    _ => unreachable!("every other action is handled above"),
                }
            }
        }
    }
    None
}

/// What one `Wire` event of the live connection means: decoded into the
/// channel protocol, and the shell channel's own records accumulated into
/// `shell_bytes` for one `Stream0` call (see its doc in `interactive`).
fn on_wire(
    stream: u8,
    bytes: &[u8],
    links: &mut Links,
    sess: &mut Session,
    shell_bytes: &mut Vec<u8>,
    now_ms: &impl Fn() -> i64,
) -> Vec<Action> {
    let mut actions = Vec::new();
    // `current` only lets the live connection's events through.
    let Some(live) = links.live.as_mut() else {
        return actions;
    };
    for se in live.channel_session.on_bytes(stream, bytes) {
        match se {
            SessionEvent::Ready(ch) => {
                actions.extend(flush_shell_bytes(shell_bytes, sess, now_ms()));
                links.shell_channel = Some(ch);
                actions.extend(sess.on_channel_ready(ch, now_ms()));
            }
            SessionEvent::Announced { live } => {
                actions.extend(sess.on_announced(&live, now_ms()));
            }
            SessionEvent::Exit { ch, code } => {
                actions.extend(flush_shell_bytes(shell_bytes, sess, now_ms()));
                actions.extend(sess.on_channel_exit(ch, code, now_ms()));
            }
            SessionEvent::Refused { ch, reason } => {
                actions.extend(flush_shell_bytes(shell_bytes, sess, now_ms()));
                // `log::log` alone is not enough: the person would just see
                // a bare exit code and a closed terminal, with no idea why
                // unless they went looking in the log. A notice, printed
                // once the terminal is restored: stderr is set aside while
                // raw mode is on.
                actions.push(Action::Notice(qsh::report::channel_refused(&reason)));
                log::log(&format!("channel refused by server: {reason}"));
                actions.extend(sess.on_channel_exit(ch, 1, now_ms()));
            }
            SessionEvent::Vanished { ch } => {
                actions.extend(flush_shell_bytes(shell_bytes, sess, now_ms()));
                // Unlike `Refused`/`Exit`, there is no reason to report: the
                // server simply no longer lists this channel (typically
                // after a warm reattach), and neither side can say why it is
                // gone. A notice, as with `Refused` above.
                actions.push(Action::Notice(
                    "qsh: shell channel vanished: the server no longer knows about it".into(),
                ));
                log::log(&format!(
                    "channel {ch} missing from the list the server announced"
                ));
                actions.extend(sess.on_channel_exit(ch, 1, now_ms()));
            }
            // This client carries no daemon images and never asks the
            // daemon about itself; a `Restarting` it did not ask for is
            // followed by the connection ending the ordinary way.
            SessionEvent::Daemon(_) => {}
            // The far side's own record already stripped the framing;
            // re-frame it as the one record it came from so it reaches
            // `ShellState` through the exact pipeline it always has.
            // Accumulated, not sent right away -- see `shell_bytes`'s own
            // doc in `interactive`.
            SessionEvent::Data { bytes, .. } => {
                shell_bytes.extend(encode_record(REC_DATA, &bytes));
            }
            // This console path consumes qsh, whose wire format has no SSH
            // extended-data record. Never turn unexpected extensions into
            // terminal control bytes, including an unknown SSH stream type.
            SessionEvent::ExtendedData { data_type, .. } => {
                log::warn(&format!(
                    "unexpected SSH extended data type {data_type} on qsh channel"
                ));
            }
            SessionEvent::InputConsumed { offset, .. } => {
                shell_bytes.extend(encode_record(REC_ECHO_ACK, &offset.to_be_bytes()));
            }
        }
    }
    actions
}

fn interactive(
    setup: Arc<Setup>,
    mut links: Links,
    display: &mut DisplaySize,
    tx: mpsc::Sender<UiEvent>,
    rx: mpsc::Receiver<UiEvent>,
) -> (i32, Links) {
    let out_fd = std::io::stdout().as_raw_fd();

    // Signal handlers first: they ask the user nothing, so the ordering
    // rule above does not apply to them, and installing them here means a
    // failure is reported while the terminal is still completely untouched
    // -- rather than after `RawMode::enter` has already put it in raw mode,
    // where the message itself would come out with no line-ending
    // translation.
    if let Err(e) = signals::install() {
        eprintln!("qsh: could not install signal handlers: {e}");
        return (1, links);
    }

    tty::RawMode::install_panic_hook();
    let raw = match tty::RawMode::enter(std::io::stdin().as_raw_fd()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("qsh: terminal unavailable: {e}");
            return (1, links);
        }
    };
    // From here until `restore` nothing may write to the terminal but the
    // renderer: a library's own line on stderr would land over the frame.
    // So stderr goes into the log, a record per line.
    set_stderr_aside(&raw);
    // The session is drawn on the alternate screen: once it is over, the
    // terminal shows what it showed before, the lines printed on the way in,
    // and the lines printed on the way out -- `restore` switches back before
    // those. The lines of the way in are all out by now: stdout is flushed,
    // since the switch is written to the descriptor itself.
    let _ = std::io::stdout().flush();
    if let Err(e) = raw.enter_alternate_screen(out_fd) {
        log::warn(&format!("could not switch to the alternate screen: {e}"));
    }

    let caps = TermCaps::detect(
        std::env::var("TERM").ok().as_deref(),
        std::env::var("COLORTERM").ok().as_deref(),
    );
    let a = setup.args();
    let env = |name: &str| std::env::var(name).ok();
    let chrome = Chrome {
        prefix: a.escape,
        line: a.status_line,
        glyphs: window::Glyphs {
            utf8: window::utf8_locale(
                env("LC_ALL").as_deref(),
                env("LC_CTYPE").as_deref(),
                env("LANG").as_deref(),
            ),
            colour: caps.color != ColorDepth::Mono,
        },
        several: a.addresses.len() > 1,
    };
    let mut sess = Session::new_with_logical_size(
        display.physical,
        terminal_size::TerminalSize::new(display.logical.0, display.logical.1)
            .expect("adapted shell size"),
        caps,
        a.predict,
        chrome,
    );
    sess.set_history_limit(a.history);
    // The climb's trial already opened the shell channel, the moment the link
    // came alive, so its `Opened` confirmation could flip the verdict fast
    // instead of the client waiting out the full auth deadline in silence
    // -- see `climb::settle_opening`. `Session` must be told, or its own
    // `on_link(Live)` -- replaying, from the queue, the very same `Live`
    // transition the trial already acted on -- would open a SECOND
    // channel. `shell_channel.is_some()` is the defensive case: `open_shell`
    // returning `None` during the trial (unreachable for a fresh session's
    // first channel, but not provably so) means nothing was actually
    // requested, and `Session`'s own path should run normally instead.
    //
    // A login that resumed the session the token names -- the run before
    // this one left with `Ctrl-] .`, or was killed -- opened nothing on
    // purpose: the server announces the channels it still runs, and the
    // shell is bound from that list (`SessionEvent::Ready` after
    // `Announced`). `Session` must not open one on `Live` either, or the
    // server refuses it as a stream already open and the run ends.
    let resumed = links
        .live
        .as_ref()
        .is_some_and(|live| live.attempt.client.resumed());
    if links.shell_channel.is_some() || resumed {
        sess.assume_channel_opening();
    }

    let input = InputReader::start(tx.clone());

    let started = std::time::Instant::now();
    // The one clock of the run: `Session`'s, and the reconnect automaton's
    // (through `at`).
    let now_ms = move || started.elapsed().as_millis() as i64;
    let mut stdout = std::io::stdout();
    let mut ticker = Ticker::new(TICK, started);

    // A `loop { ... break value; }` rather than a pre-initialized `mut code`:
    // the loop's only way out sets the real code right before leaving, so a
    // placeholder initial value would never be read.
    let mut notices: Vec<String> = Vec::new();
    let code = loop {
        let mut pending = signals::take_pending();
        if pending.suspend {
            // SIGTSTP: the terminal goes back to the shell the way it would
            // on the way out -- the mirrored modes off, its own screen, its
            // own settings -- and only then does the process stop. Once it
            // is continued, `Resumed` below brings raw mode, the alternate
            // screen and a full repaint back. The SIGCONT that ends the stop
            // is taken here too, or it would repaint a second time; a group
            // the kernel does not stop comes straight back all the same.
            let _ = stdout.write_all(&sess.suspend());
            let _ = stdout.flush();
            raw.suspend();
            log::log("stopping (SIGTSTP)");
            signals::stop();
            log::log("continued");
            let later = signals::take_pending();
            pending.resized |= later.resized;
            pending.terminate |= later.terminate;
            pending.resumed = true;
        }
        let mut events = Vec::new();
        if pending.resized {
            let (c, r) = tty::window_size(out_fd).unwrap_or(sess.physical_size());
            events.push(UiEvent::Resized { cols: c, rows: r });
        }
        if pending.resumed {
            // Whatever had this terminal while we were stopped left it
            // cooked, and `Resumed` only repaints -- painting a frame into a
            // terminal that echoes and buffers by line is not the way back,
            // so raw mode, the alternate screen (when the stop left it), the
            // mirrored modes, and the screen all need restoring first.
            // Nothing to do but log a failure: the repaint below is still
            // worth attempting, and the terminal is busy with a picture.
            if let Err(e) = raw.reenter() {
                log::log(&format!("could not restore raw mode: {e}"));
            }
            events.push(UiEvent::Resumed);
        }
        if pending.terminate {
            events.push(UiEvent::Terminate);
        }
        match rx.recv_timeout(TICK) {
            Ok(ev) => events.push(ev),
            // The wait running out is not itself the tick -- see below.
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => events.push(UiEvent::Terminate),
        }
        // Scoop up whatever else is ALREADY queued, without waiting for it.
        // A multi-packet delivery -- a repaint catching up on a long
        // absence, in particular -- can land in this channel as several
        // separate `Wire` events microseconds apart; batching them into one
        // `events` Vec is what lets the accumulation below collapse them
        // into one diff-paint instead of one per packet.
        while let Ok(ev) = rx.try_recv() {
            events.push(ev);
        }
        // A tick is due because time passed, not because the channel went
        // quiet. During a sustained burst of output (`yes`, a large `cat`, a
        // compile) `recv_timeout` never times out, and a tick derived from
        // that timeout would never fire at all -- leaving a settled resize
        // unsent and expired predictions on screen for the whole burst.
        if ticker.due(std::time::Instant::now()) {
            events.push(UiEvent::Tick);
        }

        let mut leaving = None;
        // Bytes this batch's `Wire` events have decoded into `Data`/
        // `InputConsumed` so far, re-framed and waiting for a `Stream0`
        // call. Kept OUTSIDE the loop over `ev`, not just the `Wire` arm:
        // several `Wire` events in the same batch (see the drain above)
        // must reach `Session` as ONE `Stream0` call, or `ShellState`
        // diffs-paints after every fragment instead of once for the whole
        // burst -- the exact bug a repaint after a long absence exposed,
        // since it decodes into far more records than an ordinary
        // keystroke's echo does. Flushed (see `flush_shell_bytes`) before
        // any event that is not itself accumulating into it, so ordering
        // relative to those never changes -- only consecutive `Data` gets
        // to wait.
        let mut shell_bytes: Vec<u8> = Vec::new();
        // What this batch's `Wire` events brought, by stream: reported taken
        // once the batch has reached the terminal (spec §4.13).
        let mut taken = connect::Taken::default();
        // Labeled so an `Exit` stops the WHOLE batch, not just the actions
        // of the event that produced it: `leave` ends with
        // `Renderer::finish`, which resets the real terminal, and an event
        // still queued behind the exit would paint over a screen that is no
        // longer the one any frame describes.
        'batch: for ev in events {
            // Every connection's events come stamped with its number (see
            // `background::forward`); only the live connection's get through.
            let Some(ev) = links.current(ev) else {
                continue;
            };
            // `Wire`/`WireReset` never reach `Session::handle`: `main` is the
            // one that knows what a stream number means, so it decodes them
            // here into the channel protocol, or into the `Stream0`/
            // `StreamReset` `Session` already understands.
            let actions = match ev {
                UiEvent::Wire { stream, bytes } => {
                    taken.add(stream, bytes.len());
                    on_wire(
                        stream,
                        &bytes,
                        &mut links,
                        &mut sess,
                        &mut shell_bytes,
                        &now_ms,
                    )
                }
                UiEvent::WireReset(stream) => {
                    let mut actions = flush_shell_bytes(&mut shell_bytes, &mut sess, now_ms());
                    if Some(stream) == links.shell_channel {
                        // Whatever partial record the substrate was holding
                        // for THIS channel belongs to a byte offset the peer
                        // has now abandoned: keeping it would splice the
                        // next bytes onto a leftover that no longer means
                        // anything -- the same reasoning
                        // `ShellState::on_reset` already applies to its own
                        // deframer. Only this one channel's stream, not the
                        // whole substrate: recreating it outright would also
                        // discard `CONTROL_STREAM`'s own in-flight state,
                        // for no reason connected to this reset at all.
                        // `ChannelSession::reset_stream` is the generic seam
                        // for this -- qsh implements it, and a substrate
                        // with no framing (SSH) just gets the trait's
                        // no-op default.
                        if let Some(live) = links.live.as_mut() {
                            live.channel_session.reset_stream(stream);
                        }
                        actions.extend(sess.handle(UiEvent::StreamReset, now_ms()));
                    }
                    actions
                }
                // The live link died under the session -- no `Close` from
                // either side, so the server keeps the session: reconnect
                // into it rather than leave (`Session` would leave with 0).
                UiEvent::NetworkChanged => links.network_changed(&mut sess, now_ms()),
                UiEvent::Link(LinkState::Closed) if links.died() => {
                    let mut actions = flush_shell_bytes(&mut shell_bytes, &mut sess, now_ms());
                    log::log("the link died; reconnecting");
                    actions.extend(links.on(Event::LinkDead, &mut sess, now_ms()));
                    actions
                }
                other => {
                    let mut actions = flush_shell_bytes(&mut shell_bytes, &mut sess, now_ms());
                    actions.extend(sess.handle(other, now_ms()));
                    actions
                }
            };
            if let Some(c) = apply_actions(
                actions,
                &mut stdout,
                &mut links,
                &mut sess,
                &mut notices,
                now_ms(),
            ) {
                leaving = Some(c);
                break 'batch;
            }
        }
        // The batch may have ended on `Data` with nothing after it to force
        // an earlier flush -- the ordinary case, in fact. Flush what is
        // left, so it does not sit unpainted until the NEXT batch happens
        // to bring something that triggers a flush of its own.
        if leaving.is_none() {
            let trailing = flush_shell_bytes(&mut shell_bytes, &mut sess, now_ms());
            leaving = apply_actions(
                trailing,
                &mut stdout,
                &mut links,
                &mut sess,
                &mut notices,
                now_ms(),
            );
            // What reached the terminal is taken (spec §4.13). The bytes
            // are the live connection's -- no other one's get through, and
            // none is adopted mid-batch; with the link let go, nobody is
            // owed the report.
            if let Some(live) = &links.live {
                live.attempt.report_taken(&mut taken);
            }
        }
        // Then the reconnect: time passed, and a round may have answered.
        if leaving.is_none() {
            let turn = links.turn(&mut sess, now_ms());
            leaving = apply_actions(
                turn,
                &mut stdout,
                &mut links,
                &mut sess,
                &mut notices,
                now_ms(),
            );
        }
        if let Some(c) = leaving {
            break c;
        }
    };

    // The terminal first: `close` joins the driver thread, and every
    // millisecond of that join is a millisecond the user's terminal is still
    // in raw mode for no reason. Restoring costs nothing and cannot fail in
    // a way that would stop the close. It switches back to the terminal's
    // own screen, so every line printed from here on stays there.
    input.stop();
    raw.restore();
    for notice in &notices {
        eprintln!("{notice}");
    }
    display.physical = sess.physical_size();
    display.logical = sess.size();
    (code, links)
}

/// The input reader has one owner per interactive shell. Joining before cooked
/// mode prevents it from stealing a prompt reply or feeding a later session.
struct InputReader {
    cancel: knock::Cancel,
    thread: std::thread::JoinHandle<()>,
}
impl InputReader {
    fn start(tx: Sender<UiEvent>) -> Self {
        let cancel = knock::Cancel::new();
        let stopped = cancel.clone();
        let thread = std::thread::spawn(move || {
            let stdin_fd = std::io::stdin().as_raw_fd();
            let mut buf = [0u8; 4096];
            while !stopped.is_cancelled() {
                let mut fd = libc::pollfd {
                    fd: stdin_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: stdin remains open and fd points to one valid pollfd.
                if unsafe { libc::poll(&mut fd, 1, 20) } <= 0 {
                    continue;
                }
                if stopped.is_cancelled() {
                    break;
                }
                // Read the descriptor directly: Rust's buffered stdin can retain
                // keystrokes beyond a terminal flush between sessions.
                // SAFETY: stdin_fd is live and buf is writable for its full length.
                let n = unsafe { libc::read(stdin_fd, buf.as_mut_ptr().cast(), buf.len()) };
                if n == 0 {
                    break;
                }
                if n < 0 {
                    if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                        continue;
                    }
                    break;
                }
                if tx.send(UiEvent::Stdin(buf[..n as usize].to_vec())).is_err() {
                    break;
                }
            }
        });
        Self { cancel, thread }
    }
    fn stop(self) {
        self.cancel.cancel();
        let _ = self.thread.join();
    }
}

fn discard_terminal_input() {
    // SAFETY: this only discards pending input on this run's terminal; the input
    // reader has stopped and the next session has not started reading yet.
    unsafe {
        libc::tcflush(std::io::stdin().as_raw_fd(), libc::TCIFLUSH);
    }
}

/// Points stderr into the log while `raw` lasts (or, failing that, at
/// `/dev/null`: still not over the frame). A failure is logged and
/// otherwise ignored: the session is worth more than a clean frame.
fn set_stderr_aside(raw: &tty::RawMode) {
    let Err(e) = raw.set_stderr_to_log() else {
        return;
    };
    log::warn(&format!("could not send stderr to the log: {e}"));
    let result = std::fs::OpenOptions::new()
        .write(true)
        .open("/dev/null")
        .and_then(|null| raw.set_stderr_aside(&null).map_err(std::io::Error::from));
    if let Err(e) = result {
        log::warn(&format!("could not set stderr aside: {e}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(literal: &str) -> SocketAddr {
        literal.parse().expect("a literal address")
    }

    fn address(host: &str, qsh_port: u16) -> Address {
        Address {
            host: host.into(),
            qsh_port,
            ssh: None,
        }
    }

    /// The road in use leads the list: the table picks from what it holds, so
    /// leaving it off would leave nothing to return to when it comes back.
    #[test]
    fn the_road_in_use_is_on_the_list_and_comes_first() {
        let addresses = vec![address("127.0.0.2", 61000), address("box", 60022)];
        let labels = labels(addr("127.0.0.1:60022"), &addresses, 1);
        assert_eq!(
            paths(&labels, 1),
            vec![addr("127.0.0.1:60022"), addr("127.0.0.2:61000")]
        );
    }

    /// After a return the roads are rebuilt the same way: the address in use
    /// is at the address it was reached at, and another address keeps the
    /// port a daemon reported for it earlier in the run. The window lists
    /// them in command-line order.
    #[test]
    fn the_roads_are_every_address_with_the_port_it_is_known_by() {
        let addresses = vec![
            address("127.0.0.1", 60022),
            address("h1", 60000),
            address("::1", 61000),
        ];
        assert_eq!(
            labels(addr("127.0.0.9:60000"), &addresses, 1),
            vec![
                (0, addr("127.0.0.1:60022"), "127.0.0.1:60022".to_string()),
                (1, addr("127.0.0.9:60000"), "h1:60000".to_string()),
                (2, addr("[::1]:61000"), "[::1]:61000".to_string()),
            ]
        );
    }

    /// A round's progress is shown only while that very round runs: a late
    /// message from a round already over -- or an earlier one -- must not
    /// replace the countdown to the next.
    #[test]
    fn progress_counts_only_for_the_round_under_way() {
        assert!(progress_counts(3, 3, true));
        assert!(!progress_counts(3, 3, false), "the round is over");
        assert!(!progress_counts(2, 3, true), "an earlier round's");
        assert!(!progress_counts(2, 3, false));
    }

    #[test]
    fn the_road_list_follows_the_command_line_and_marks_the_road_in_use() {
        use transport::paths::{PathState, RoadInfo};
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let b: SocketAddr = "127.0.0.2:2".parse().unwrap();
        let labels = vec![(0, a, "one:1".to_string()), (1, b, "two:2".to_string())];
        let roads = vec![
            RoadInfo {
                addr: b,
                state: PathState::Verified,
                ewma_ms: Some(38),
                failed_ago_ms: None,
            },
            RoadInfo {
                addr: a,
                state: PathState::Verified,
                ewma_ms: Some(40),
                failed_ago_ms: None,
            },
        ];
        let list = road_list(&labels, &roads, Some(b), 41);
        assert_eq!(
            list.iter().map(|r| r.label.as_str()).collect::<Vec<_>>(),
            vec!["one:1", "two:2"]
        );
        assert!(!list[0].in_use && list[1].in_use);
        assert_eq!(list[0].ewma_ms, Some(40));
    }

    /// Spec §4a rule 4: a road counts as proven only while the table says
    /// its checks were answered -- never one only listed, nor one that
    /// failed -- and it is named by the address it belongs to.
    #[test]
    fn only_a_road_whose_checks_were_answered_is_proven() {
        let (a, b, c): (SocketAddr, SocketAddr, SocketAddr) = (
            "127.0.0.1:1".parse().unwrap(),
            "127.0.0.2:2".parse().unwrap(),
            "127.0.0.3:3".parse().unwrap(),
        );
        let addresses = vec![address("one", 1), address("two", 2), address("three", 3)];
        let labels = vec![
            (0, a, "one:1".to_string()),
            (1, b, "two:2".to_string()),
            (2, c, "three:3".to_string()),
        ];
        let info = |addr, state| RoadInfo {
            addr,
            state,
            ewma_ms: None,
            failed_ago_ms: None,
        };
        let table = vec![
            info(a, PathState::Verified),
            info(b, PathState::Unverified),
            info(c, PathState::Dead),
        ];
        assert_eq!(
            proven_roads(&labels, &addresses, &table),
            vec![("one".to_string(), 1)]
        );
        assert!(proven_roads(&labels, &addresses, &[]).is_empty());
    }

    #[test]
    fn one_address_is_one_road_in_use() {
        let a: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let list = road_list(&[(0, a, "one:1".to_string())], &[], Some(a), 41);
        assert_eq!(list.len(), 1);
        assert!(list[0].in_use);
        assert_eq!(list[0].ewma_ms, Some(41));
    }

    /// Initial labels omit unresolved names while preserving command-line IDs.
    /// The catalog, tested separately, retains those names for later retries.
    #[test]
    fn initial_labels_defer_names_without_blocking_working_roads() {
        let addresses = vec![
            address("box", 60022),
            address("no-such-host.invalid", 60022),
            address("127.0.0.3", 60022),
        ];
        let labels = labels(addr("127.0.0.1:60022"), &addresses, 0);
        assert_eq!(
            paths(&labels, 0),
            vec![addr("127.0.0.1:60022"), addr("127.0.0.3:60022")],
            "the name that failed is gone, the one that worked is not"
        );
        assert_eq!(
            labels.iter().map(|l| l.0).collect::<Vec<_>>(),
            vec![0, 2],
            "the window keeps the command line's numbering"
        );
    }
}
