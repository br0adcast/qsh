//! The executor around the address ladder (spec §4.1): the ladder itself
//! (`::connect::Ladder`) decides what to try next without any I/O; this
//! module does the trying -- the network, the questions, the lines on
//! stderr -- and feeds each outcome back.
//!
//! At login everything here runs before raw mode: a question or a progress
//! line printed over a frame ruins both. A reconnect round (`Mode::Background`)
//! runs behind the live terminal instead, and so it asks nobody and prints
//! nothing: a step that needs a question is skipped, its lines go to the log
//! only, and where it is trying goes to the main loop as an event.

use std::collections::HashSet;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use ::connect::{Action, DirectOutcome, GiveUp, NoAnswerWhy, Outcome, SshOutcome};
use client::channel::{ChannelId, ChannelSession};
use client::qsh::QshSubstrate;
use sshauth::discover::DiscoveryError;
use transport::driver_std::SendFailure;

use crate::args::Args;
use crate::connect::{self as attempt, Login, Verdict};
use crate::known_hosts::KnownHosts;
use crate::prompt::Tty;
use crate::recovery::Recovery;
use crate::session::UiEvent;
use crate::ssh_step::{SshStep, SshStepError};
use crate::{keys, log, report, status, trust};

/// Where the substrate sends its bytes: the connection's `send_bytes`.
pub type Sink = Box<dyn FnMut(u8, Vec<u8>) + Send>;

/// What the connection trial hands `interactive`: the channel session it
/// already built (and already used to open the shell channel -- see
/// `settle_opening`), whatever channel number that produced, and the
/// terminal size it told the server. Bundled into one value rather than
/// four separate parameters purely to keep `interactive`'s own argument
/// count down; there is no meaning to the grouping beyond that.
pub struct Trial {
    pub channel_session: ChannelSession<QshSubstrate<Sink>>,
    pub opened_ch: Option<ChannelId>,
    pub cols: u16,
    pub rows: u16,
}

/// A login that worked: the attempt, its trial, which address it was (an
/// index into `Args::addresses`), the qsh port it was reached on, and the
/// socket address dialled.
pub struct Connected {
    pub attempt: attempt::Attempt,
    pub trial: Trial,
    pub addr: usize,
    pub port: u16,
    pub remote: SocketAddr,
}

// Returned once per climb, and moved straight into its parts: the size of
// the large variant costs nothing worth a box.
#[allow(clippy::large_enum_variant)]
pub enum Climbed {
    Connected(Connected),
    /// Login only: the ladder ended without a session; the exit code.
    Exit(i32),
    /// Background only: the round ended without a session. `line` is what to
    /// print on the way out if this ends the run (a changed key, a gone
    /// session) -- or, after a round where every address failed, the hint to
    /// show until the next one (`status::needs_prompt_hint`).
    Failed {
        end: ::connect::reconnect::RoundEnd,
        line: Option<String>,
    },
}

/// Who the climb answers to: the person at login, nobody in the background.
pub enum Mode {
    /// Before raw mode: lines on stderr, questions on the terminal.
    Login,
    /// A reconnect round behind the live terminal: lines only in the log,
    /// no questions, and where it is trying goes to `progress`, stamped
    /// with the round's number.
    Background {
        progress: Sender<UiEvent>,
        round: u64,
    },
}

/// Which qsh step of an address this is: the first try, or the one after
/// ssh brought the daemon up.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    /// Step 1: sign with the SSH key candidates.
    First,
    /// Step 3: the process key is on the daemon's list.
    AfterSsh,
}

/// What every climb of this run shares: the login's and every reconnect round's.
pub struct Setup {
    args: Args,
    /// The one Noise static key of this process (spec §4.2).
    keypair: transport::handshake::Keypair,
    /// The qsh server keys pinned so far.
    pins: sshauth::known_hosts::KnownHosts,
    discovery: Arc<dyn trust::Discover + Send + Sync>,
    tty: Tty,
    ssh_hosts: KnownHosts,
    /// `$SSH_AUTH_SOCK`, read once by `main`.
    agent: Option<PathBuf>,
    /// `~/.ssh`, for the ssh step's default key files.
    ssh_dir: Option<PathBuf>,
    /// Which session on the server this run is coming back to.
    token: [u8; 16],
    /// Loaded once per process, at the first step 1 whose server key is
    /// known -- discovered from an answer, or pinned from an earlier run --
    /// before its handshake: an address with no key to show must not make
    /// anyone type a passphrase. A pinned key means no packet has been
    /// exchanged yet. Empty when there were no keys at all: that step is
    /// then a refusal, and the ladder can still go to ssh. Every round after
    /// the login takes these, so the background never asks for a passphrase.
    candidates: Mutex<Option<Loaded>>,
    /// The server key of the session this run is in, once a login worked:
    /// the key a road that carried the session is pinned for (spec §4a
    /// rule 4). A return into the same session is by the same key -- any
    /// other ends the run as a changed key -- so the first login's stands.
    session_key: Mutex<Option<[u8; 32]>>,
    /// The roads, as `(host, port)`, already weighed for rule 4: each is
    /// looked up in the store once per run, not on every look at the roads.
    weighed: Mutex<HashSet<(String, u16)>>,
    /// Endpoints where SSH installed this process's key, including the
    /// initial login. Warm recovery must retain that way of authenticating.
    allowlisted: Mutex<HashSet<(String, u16)>>,
    trust_write: Mutex<Option<crate::ssh_bindings::TrustWritePermit>>,
}

impl Setup {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        args: Args,
        keypair: transport::handshake::Keypair,
        pins: sshauth::known_hosts::KnownHosts,
        discovery: Box<dyn trust::Discover + Send + Sync>,
        tty: Tty,
        ssh_hosts: KnownHosts,
        agent: Option<PathBuf>,
        ssh_dir: Option<PathBuf>,
        token: [u8; 16],
    ) -> Setup {
        Setup {
            args,
            keypair,
            pins,
            discovery: Arc::from(discovery),
            tty,
            ssh_hosts,
            agent,
            ssh_dir,
            token,
            candidates: Mutex::new(None),
            session_key: Mutex::new(None),
            weighed: Mutex::new(HashSet::new()),
            allowlisted: Mutex::new(HashSet::new()),
            trust_write: Mutex::new(None),
        }
    }

    /// A consented replacement retains identity and credentials, but old workers
    /// keep their own immutable token and cannot close or resume this session.
    pub fn replacement(&self, token: [u8; 16]) -> Self {
        Self {
            args: self.args.clone(),
            keypair: transport::handshake::Keypair {
                private: self.keypair.private,
                public: self.keypair.public,
            },
            pins: sshauth::known_hosts::KnownHosts::open(self.pins.path().to_owned()),
            discovery: self.discovery.clone(),
            tty: self.tty.clone(),
            ssh_hosts: self.ssh_hosts.clone(),
            agent: self.agent.clone(),
            ssh_dir: self.ssh_dir.clone(),
            token,
            candidates: Mutex::new(self.cached_candidates()),
            session_key: Mutex::new(self.server_identity().map(|s| s.qsh_key)),
            weighed: Mutex::new(
                self.weighed
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone(),
            ),
            // Closing the old session (including a shell-free loss probe)
            // removes its process key from the daemon's self-cleaning list.
            // Only fresh SSH enrollment can restore this authentication path.
            allowlisted: Mutex::new(HashSet::new()),
            trust_write: Mutex::new(None),
        }
    }

    pub fn args(&self) -> &Args {
        &self.args
    }

    pub fn bring_up(
        &self,
        address: &::connect::Address,
        cancel: &knock::Cancel,
    ) -> Result<bringup::Ready, SshStepError> {
        let Some(server) = self.server_identity() else {
            return Err(SshStepError::NeedsPrompt);
        };
        let route = address
            .ssh
            .as_ref()
            .expect("SSH recovery only visits SSH addresses");
        let endpoint = ::connect::server_identity::SshEndpoint {
            host: address.host.clone(),
            port: route.port,
        };
        let keys = self
            .ssh_bindings()
            .allowed(&server, &endpoint)
            .map_err(|e| SshStepError::Failed(::connect::SshFailure::plain(e.to_string())))?;
        self.ssh_step(true)
            .run_bound(address, route, self.keypair.public, &keys, cancel)
    }

    /// The authenticated QSH peer; SSH readiness never changes this identity.
    pub fn server_identity(&self) -> Option<::connect::server_identity::ServerIdentity> {
        self.session_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map(|qsh_key| ::connect::server_identity::ServerIdentity {
                qsh_key,
                username: self.args.login.clone(),
            })
    }

    /// Begin explicit foreground setup for the controller's current epoch.
    /// The setup retains a clone so epoch changes can invalidate a writer
    /// even while it is waiting for a filesystem lock. A live QSH path alone
    /// does not invalidate foreground setup.
    pub fn begin_ssh_authorization(
        &self,
        epoch: ::connect::recovery_gate::RecoveryEpoch,
    ) -> crate::ssh_bindings::TrustWritePermit {
        let mut active = self.trust_write.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(previous) = active.take() {
            previous.invalidate();
        }
        let permit = crate::ssh_bindings::TrustWritePermit::new(epoch);
        *active = Some(permit.clone());
        permit
    }

    /// Call before cancelling setup or changing its connection/network epoch.
    pub fn invalidate_ssh_authorization(&self) {
        if let Some(permit) = self
            .trust_write
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            permit.invalidate();
        }
    }

    pub(crate) fn ssh_bindings(&self) -> crate::ssh_bindings::SshBindings {
        crate::ssh_bindings::SshBindings::open(self.pins.path().with_file_name("ssh_bindings.json"))
    }

    pub(crate) fn ssh_hosts(&self) -> &KnownHosts {
        &self.ssh_hosts
    }
    pub(crate) fn tty(&self) -> &Tty {
        &self.tty
    }

    pub(crate) fn ssh_verification_params(
        &self,
        endpoint: &::connect::server_identity::SshEndpoint,
    ) -> Option<ssh::SshParams> {
        let address = self.args.addresses.iter().find(|a| {
            a.host == endpoint.host && a.ssh.as_ref().is_some_and(|s| s.port == endpoint.port)
        })?;
        Some(ssh::SshParams {
            host: endpoint.host.clone(),
            port: endpoint.port,
            username: self.args.login.clone(),
            known_host_keys: self.ssh_hosts.lookup(&endpoint.host, endpoint.port).known,
            connect_timeout: crate::ssh_step::SSH_CONNECT_TIMEOUT,
            keepalive_interval: std::time::Duration::from_secs(15),
            compression: false,
            tcp_nodelay: true,
            knock: address.ssh.as_ref()?.knock.clone(),
        })
    }

    fn allowlist(&self, host: &str, port: u16) {
        self.allowlisted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((host.to_owned(), port));
    }

    fn is_allowlisted(&self, host: &str, port: u16) -> bool {
        self.allowlisted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&(host.to_owned(), port))
    }

    /// The ssh step, as one climb step uses it.
    fn ssh_step(&self, background: bool) -> SshStep<'_> {
        SshStep {
            login: &self.args.login,
            identity: self.args.identity.as_deref(),
            no_password: self.args.no_password,
            agent: self.agent.clone(),
            ssh_dir: self.ssh_dir.clone(),
            known_hosts: &self.ssh_hosts,
            tty: &self.tty,
            background,
            images: Arc::new(crate::releases::GitHubImages::new(crate::paths::cache_dir())),
        }
    }

    /// The key candidates, if loaded: a copy, so no lock is held while they
    /// are tried over the network.
    fn cached_candidates(&self) -> Option<Loaded> {
        self.candidates
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Spec §4a rule 4: every road of `proven` -- `(host, port)` of an
    /// address whose road answered the live session's own checks, which
    /// only the session's peer can answer -- is pinned for the session's
    /// key, silently, with a line in the log. A different key already
    /// pinned there is left alone, with a warning: that line is stale, and
    /// the next run through that address will say the key changed.
    pub fn remember_roads(&self, proven: &[(String, u16)]) {
        let Some(key) = *self.session_key.lock().unwrap_or_else(|e| e.into_inner()) else {
            return;
        };
        for (host, port) in proven {
            let fresh = self
                .weighed
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert((host.clone(), *port));
            if !fresh {
                continue;
            }
            let road = trust::label(host, *port);
            match trust::remember_proven(host, *port, &key, &self.pins) {
                Ok(trust::Proven::Remembered) => log::log(&format!(
                    "road {road} carried the session: its server key is remembered"
                )),
                Ok(trust::Proven::AlreadyKnown) => {}
                Ok(trust::Proven::Stale { pinned }) => log::warn(&format!(
                    "road {road} carried the session, whose key is {}, but known_hosts pins {} \
                     for it; left as it is -- the next run through {road} will report a changed \
                     key",
                    sshauth::known_hosts::key_fingerprint(&key),
                    sshauth::known_hosts::key_fingerprint(&pinned)
                )),
                Err(e) => log::warn(&format!("road {road}: could not remember its key: {e}")),
            }
        }
    }

    fn cache_candidates(&self, loaded: &Loaded) {
        let mut slot = self.candidates.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            *slot = Some(loaded.clone());
        }
    }
}

/// Step 1's keys, and -- when there are none -- where they were looked for,
/// for the refusal's line.
#[derive(Clone, Default)]
struct Loaded {
    keys: Vec<keys::Candidate>,
    looked: Vec<String>,
}

impl std::fmt::Debug for Loaded {
    // The labels only: a signer has nothing to show.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Loaded")
            .field(
                "keys",
                &self.keys.iter().map(|k| &k.label).collect::<Vec<_>>(),
            )
            .field("looked", &self.looked)
            .finish()
    }
}

pub struct Climb<'a> {
    fresh_session: bool,
    setup: &'a Setup,
    /// The addresses as this run knows them now: a port a daemon reported
    /// replaces the one on the command line (spec §5.1).
    addrs: Vec<::connect::Address>,
    /// Where a background round starts: the address the session last worked at.
    first: usize,
    mode: Mode,
    cols: u16,
    rows: u16,
    /// This climb's own channel for its attempts' events: `forget` drops a
    /// failed attempt's from it, and the one that worked hands it on.
    tx: Sender<UiEvent>,
    rx: &'a Receiver<UiEvent>,
    /// What each address said beyond the ladder's reasons, for the summary;
    /// indexed like `addrs`.
    details: Vec<report::Detail>,
    /// The login that worked, until `Action::Connected` hands it out.
    connected: Option<(attempt::Attempt, Trial, SocketAddr)>,
    /// Background: the loud line of this round (a changed key), for the way out.
    loud: Option<String>,
    recovery: Option<&'a Recovery>,
    revision: u64,
    recovery_attempt: Option<(
        ::connect::recovery_gate::RecoveryEpoch,
        ::connect::recovery_gate::SweepId,
    )>,
    bootstrap: Option<(usize, ssh::HostKeyInfo)>,
}

impl<'a> Climb<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        setup: &'a Setup,
        addresses: Vec<::connect::Address>,
        first: usize,
        mode: Mode,
        cols: u16,
        rows: u16,
        tx: Sender<UiEvent>,
        rx: &'a Receiver<UiEvent>,
    ) -> Climb<'a> {
        let details = vec![report::Detail::default(); addresses.len()];
        Climb {
            setup,
            addrs: addresses,
            first,
            mode,
            cols,
            rows,
            tx,
            rx,
            details,
            connected: None,
            loud: None,
            recovery: None,
            revision: 0,
            fresh_session: false,
            recovery_attempt: None,
            bootstrap: None,
        }
    }
}

impl<'a> Climb<'a> {
    /// Only the foreground owner's explicit consent may enable a fresh shell.
    pub fn allow_new_session(mut self, allow: bool) -> Self {
        self.fresh_session = allow;
        self
    }

    /// In recovery this ladder owns only UDP. The SSH worker publishes
    /// its results and never starts a second warm attachment.
    pub fn recovering(
        mut self,
        recovery: &'a Recovery,
        epoch: ::connect::recovery_gate::RecoveryEpoch,
        sweep: ::connect::recovery_gate::SweepId,
    ) -> Self {
        self.recovery_attempt = Some((epoch, sweep));
        self.revision = recovery.revision();
        self.recovery = Some(recovery);
        self
    }

    fn interrupted(&self) -> bool {
        (!self.background() && crate::signals::termination_requested())
            || self.recovery.is_some_and(|r| r.interrupted(self.revision))
    }

    pub fn run(&mut self) -> Climbed {
        let cancel = knock::Cancel::new();
        if let Some(recovery) = self.recovery {
            return self.run_cancellable(&recovery.cancel);
        }
        if self.background() {
            return self.run_cancellable(&cancel);
        }
        crate::signals::with_termination_cancel(&cancel, || self.run_cancellable(&cancel))
    }

    fn run_cancellable(&mut self, cancel: &knock::Cancel) -> Climbed {
        let mut addrs = self.addrs.clone();
        if let Some(recovery) = self.recovery {
            for (i, addr) in addrs.iter_mut().enumerate() {
                addr.ssh = None;
                if let Some(port) = recovery.port(i) {
                    addr.qsh_port = port;
                    self.addrs[i].qsh_port = port;
                    self.setup.allowlist(&addr.host, port);
                }
            }
        }
        let mut ladder = if self.background() {
            ::connect::Ladder::background(addrs.clone(), self.first)
        } else {
            ::connect::Ladder::new(addrs.clone())
        };
        if !self.background() {
            if let Some(code) = self.pins_disagree() {
                return Climbed::Exit(code);
            }
        }
        let mut action = ladder.first();
        loop {
            if !self.background() && self.interrupted() {
                return Climbed::Exit(130);
            }
            if self.interrupted()
                && matches!(
                    action,
                    Action::TryDirect { .. }
                        | Action::TrySsh { .. }
                        | Action::TryDirectAfterSsh { .. }
                )
            {
                return Climbed::Failed {
                    end: ::connect::reconnect::RoundEnd::AllFailed,
                    line: None,
                };
            }
            // `Action`'s `Debug` holds indices and ports only.
            log::log(&format!("ladder: {action:?}"));
            action = match action {
                Action::TryDirect { addr } => {
                    let (outcome, line) =
                        match self.direct(addr, addrs[addr].qsh_port, Stage::First, cancel) {
                            Ok(v) => v,
                            Err(code) => return Climbed::Exit(code),
                        };
                    self.advance(&mut ladder, Outcome::Direct(outcome), line)
                }
                Action::TrySsh { addr } => {
                    let host = &addrs[addr].host;
                    let route = addrs[addr]
                        .ssh
                        .as_ref()
                        .expect("the ladder asks for ssh only where there is one");
                    self.progress(host);
                    self.say(&report::trying_ssh(host, route));
                    let result = self.setup.ssh_step(self.background()).run_identified(
                        &addrs[addr],
                        route,
                        self.setup.keypair.public,
                        cancel,
                    );
                    if !self.background() && crate::signals::termination_requested() {
                        return Climbed::Exit(130);
                    }
                    match result {
                        Ok(identified) => {
                            self.bootstrap = Some((addr, identified.ssh_host_key));
                            let ready = identified.ready;
                            let port = ready.port_for(addrs[addr].qsh_port);
                            self.setup.allowlist(host, port);
                            self.say(&report::qshd_ready(host, addrs[addr].qsh_port, port));
                            if let Some(w) = &ready.warning {
                                self.say(&report::qshd_warning(host, w));
                            }
                            let outcome = Outcome::Ssh(SshOutcome::Ready { port });
                            log::log(&format!("ladder: outcome {outcome:?}"));
                            ladder.on(outcome)
                        }
                        Err(SshStepError::InstallDeclined) => {
                            self.say(&report::install_declined());
                            self.advance(
                                &mut ladder,
                                Outcome::Ssh(SshOutcome::InstallDeclined),
                                None,
                            )
                        }
                        Err(SshStepError::NeedsPrompt) => {
                            let line = report::ssh_failed(
                                host,
                                &::connect::SshFailure::plain("needs a prompt"),
                            );
                            self.advance(
                                &mut ladder,
                                Outcome::Ssh(SshOutcome::NeedsPrompt),
                                Some(line),
                            )
                        }
                        Err(SshStepError::Failed(why)) => {
                            let line = report::ssh_failed(host, &why);
                            self.advance(
                                &mut ladder,
                                Outcome::Ssh(SshOutcome::Failed(why)),
                                Some(line),
                            )
                        }
                    }
                }
                Action::TryDirectAfterSsh { addr, port } => {
                    let (outcome, line) = match self.direct(addr, port, Stage::AfterSsh, cancel) {
                        Ok(v) => v,
                        Err(code) => return Climbed::Exit(code),
                    };
                    self.advance(&mut ladder, Outcome::Direct(outcome), line)
                }
                Action::Connected { addr, port } => {
                    let (attempt, trial, remote) = self
                        .connected
                        .take()
                        .expect("a Connected action follows a login");
                    if !self.background() {
                        if let Some((bootstrap_addr, info)) = self.bootstrap.take() {
                            if bootstrap_addr == addr {
                                if let Some(server) = self.setup.server_identity() {
                                    let endpoint = ::connect::server_identity::SshEndpoint {
                                        host: addrs[addr].host.clone(),
                                        port: addrs[addr]
                                            .ssh
                                            .as_ref()
                                            .expect("bootstrap used SSH")
                                            .port,
                                    };
                                    let permit = self.setup.begin_ssh_authorization(
                                        ::connect::recovery_gate::RecoveryEpoch {
                                            connection: 0,
                                            network: 0,
                                        },
                                    );
                                    if let Err(error) = crate::ssh_authorization::offer_binding(
                                        &server, &endpoint, &info, self.setup, &permit, cancel,
                                    ) {
                                        eprintln!("qsh: {error}; QSH session remains connected");
                                    }
                                    self.setup.invalidate_ssh_authorization();
                                }
                            }
                        }
                    }
                    return Climbed::Connected(Connected {
                        attempt,
                        trial,
                        addr,
                        port,
                        remote,
                    });
                }
                Action::GiveUp(give_up) => return self.give_up(give_up, &addrs),
            };
        }
    }

    /// Spec §4a rule 1, at login, before the first attempt: addresses of one
    /// command line with different keys pinned are not one server. `Some`
    /// is the exit code. A store that cannot be read is left to the first
    /// attempt, which says so in its own words.
    fn pins_disagree(&mut self) -> Option<i32> {
        let line = self.line();
        match trust::pins_disagree(&line, &self.setup.pins) {
            Ok(None) => None,
            Ok(Some(d)) => {
                self.say_loud(report::pins_disagree(
                    &d.first.0,
                    &d.first.1,
                    &d.second.0,
                    &d.second.1,
                    self.setup.pins.path(),
                ));
                Some(11)
            }
            Err(e) => {
                log::warn(&format!("comparing the pinned keys: {e}"));
                None
            }
        }
    }

    /// Every address of the command line as `(host, port)`, on the port
    /// this run knows it by.
    fn line(&self) -> Vec<(String, u16)> {
        self.addrs
            .iter()
            .map(|a| (a.host.clone(), a.qsh_port))
            .collect()
    }

    /// How the ladder ended without a session, for this mode.
    fn give_up(&mut self, give_up: GiveUp, addrs: &[::connect::Address]) -> Climbed {
        use ::connect::reconnect::RoundEnd;
        if !self.background() {
            return match give_up {
                GiveUp::KeyChanged { .. } => Climbed::Exit(11),
                GiveUp::Declined { .. } => Climbed::Exit(1),
                GiveUp::SessionGone { .. } => {
                    unreachable!("a login never finds its session gone")
                }
                GiveUp::AllFailed(failures) => {
                    for line in report::exit_12_summary(
                        addrs,
                        &failures,
                        &self.details,
                        &self.setup.args.login,
                        &log::path(),
                    ) {
                        eprintln!("{line}");
                        log::shown(&line);
                    }
                    Climbed::Exit(12)
                }
            };
        }
        match give_up {
            GiveUp::KeyChanged { addr } => Climbed::Failed {
                end: RoundEnd::KeyChanged { addr },
                line: self.loud.take(),
            },
            GiveUp::SessionGone { addr } => Climbed::Failed {
                end: RoundEnd::SessionGone { addr },
                line: Some(status::session_gone_text(&addrs[addr].host)),
            },
            GiveUp::AllFailed(failures) => {
                for line in
                    report::all_failed(addrs, &failures, &self.details, &self.setup.args.login)
                {
                    log::shown(&line);
                }
                // Waiting will not help a round that could only have gone on
                // by asking: the line says so, and names the way out.
                let hint = every_address_needs_a_question(&failures)
                    .then(|| status::needs_prompt_hint(self.setup.args().escape.name().as_deref()));
                Climbed::Failed {
                    end: RoundEnd::AllFailed,
                    line: hint,
                }
            }
            GiveUp::Declined { .. } => {
                unreachable!("nobody is asked in the background, so nobody declines")
            }
        }
    }

    fn background(&self) -> bool {
        matches!(self.mode, Mode::Background { .. })
    }

    /// A line about how the climb goes: stderr at login, only the log in
    /// the background -- the terminal there belongs to the live session.
    /// The log has it either way.
    fn say(&self, line: &str) {
        if let Mode::Login = self.mode {
            eprintln!("{line}");
        }
        log::shown(line);
    }

    /// A line that must not be lost (a changed key): in the background it
    /// is also kept, to be printed on the way out if the round ends the run.
    fn say_loud(&mut self, line: String) {
        log::shown_warning(&line);
        match self.mode {
            Mode::Login => eprintln!("{line}"),
            Mode::Background { .. } => self.loud = Some(line),
        }
    }

    /// Background: tells the main loop where the round is trying now.
    fn progress(&self, host: &str) {
        if let Mode::Background { progress, round } = &self.mode {
            // The main loop gone means the run is ending: nothing to tell.
            let _ = progress.send(UiEvent::Reconnecting {
                round: *round,
                to: host.to_string(),
            });
        }
    }

    /// Feeds the ladder and says the step's own line -- unless the ladder
    /// has just ended with every address failed: the summary says it then.
    fn advance(
        &mut self,
        ladder: &mut ::connect::Ladder,
        outcome: Outcome,
        line: Option<String>,
    ) -> Action {
        log::log(&format!("ladder: outcome {outcome:?}"));
        let next = ladder.on(outcome);
        if let Some(line) = line {
            if !matches!(next, Action::GiveUp(GiveUp::AllFailed(_))) {
                self.say(&line);
            }
        }
        next
    }

    /// Step 1 or 3 at address `i`, qsh port `port`: the outcome for the
    /// ladder and the line to say about it, if any. `Err` is an exit code,
    /// only at login, only when the keys could not be loaded.
    fn direct(
        &mut self,
        i: usize,
        port: u16,
        stage: Stage,
        cancel: &knock::Cancel,
    ) -> Result<(DirectOutcome, Option<String>), i32> {
        use ::connect::recovery_gate::{AddressId, AddressOutcome};
        let result = self.direct_attempt(i, port, stage, cancel);
        // Cancellation or a new SSH endpoint can interrupt a handshake. That
        // is not a completed failed address in the sweep that started it.
        if !self.interrupted() {
            if let (Some(recovery), Some((epoch, sweep)), Ok((outcome, _))) =
                (self.recovery, self.recovery_attempt, &result)
            {
                let outcome = match outcome {
                    DirectOutcome::Connected | DirectOutcome::SessionGone => {
                        AddressOutcome::Recovered
                    }
                    DirectOutcome::KeyChanged => AddressOutcome::IdentityMismatch,
                    DirectOutcome::NeedsPrompt | DirectOutcome::Declined => {
                        AddressOutcome::NeedsUser
                    }
                    _ => AddressOutcome::Failed,
                };
                recovery.finish(self.revision, epoch, sweep, AddressId(i), outcome);
            }
        }
        result
    }

    fn direct_attempt(
        &mut self,
        i: usize,
        port: u16,
        stage: Stage,
        cancel: &knock::Cancel,
    ) -> Result<(DirectOutcome, Option<String>), i32> {
        let host = self.addrs[i].host.clone();
        self.progress(&host);
        log::log(&format!(
            "ladder: address {i}: qsh on port {port}, {stage:?}"
        ));
        // Not simply the first answer: the daemon binds IPv4 only, and a
        // dual-stack resolver puts the AAAA record first. See
        // `connect::preferred_addr`.
        // `Err(None)`: the resolver answered with no address at all.
        let resolved = if let Some(recovery) = self.recovery.filter(|r| r.catalog_managed()) {
            let started = std::time::Instant::now();
            loop {
                if self.interrupted() || cancel.is_cancelled() {
                    break Err(None);
                }
                if let Some(endpoint) = recovery.endpoint(i) {
                    break Ok(endpoint);
                }
                if started.elapsed() >= crate::road_catalog::DNS_TIMEOUT {
                    break Err(None);
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        } else if self.background() {
            match (host.as_str(), port).to_socket_addrs() {
                Ok(it) => attempt::preferred_addr(it).ok_or(None),
                Err(error) => Err(Some(error.to_string())),
            }
        } else {
            knock::resolve(&host, cancel)
                .map(|ip| SocketAddr::new(ip, port))
                .map_err(|error| Some(error.to_string()))
        };
        if !self.background() && self.interrupted() {
            return Err(130);
        }
        let sockaddr = match resolved {
            Ok(a) => a,
            Err(why) => {
                let line = report::could_not_resolve(&host, why.as_deref());
                self.details[i].unresolved = why;
                return Ok((DirectOutcome::Unresolved, Some(line)));
            }
        };
        let sockaddr = match dial_target(&host, sockaddr) {
            Ok(a) => a,
            Err(why) => {
                let line = report::no_answer(&host, port, &why);
                return Ok((DirectOutcome::NoAnswer(why), Some(line)));
            }
        };

        let background = self.background();
        let ask: &dyn trust::Confirm = if background {
            &NoQuestions
        } else {
            &self.setup.tty
        };
        let diagnostic = self
            .recovery
            .map(|r| r.discovery(i, self.revision, self.setup.discovery.clone()));
        let foreground_discovery = trust::ForegroundDiscovery(self.setup.discovery.as_ref());
        let discovery: &dyn trust::Discover = diagnostic
            .as_ref()
            .map(|d| d as &dyn trust::Discover)
            .unwrap_or_else(|| {
                if self.background() {
                    self.setup.discovery.as_ref()
                } else {
                    &foreground_discovery
                }
            });
        let session_key = *self
            .setup
            .session_key
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let server = if let (Some(_), Some(key)) = (self.recovery, session_key) {
            trust::recovery_server_key(&host, port, key, &self.setup.pins)
        } else {
            trust::server_key(
                &host,
                port,
                sockaddr,
                &self.setup.pins,
                &self.line(),
                ask,
                discovery,
            )
        };
        if !self.background() && self.interrupted() {
            return Err(130);
        }
        let server = match server {
            Ok(k) => k,
            Err(e) => {
                return Ok(match e {
                    trust::TrustError::NoAnswer { reason, .. } => {
                        log::warn(&format!(
                            "could not get the server's key for {host}:{port}: {reason}"
                        ));
                        let why = discovery_why(reason, cfg!(target_os = "macos"));
                        let line = report::no_answer(&host, port, &why);
                        (DirectOutcome::NoAnswer(why), Some(line))
                    }
                    trust::TrustError::KeyChanged { .. } => {
                        self.say_loud(format!("qsh: {e}"));
                        (DirectOutcome::KeyChanged, None)
                    }
                    trust::TrustError::Refused => {
                        self.say(&format!("qsh: {e}"));
                        (refusal(background), None)
                    }
                    // The pin store could not be read, or a new pin not be
                    // written. At login going on is not possible. In the
                    // background only reading can fail (a write follows a
                    // "yes", and nobody says yes there): the address is
                    // skipped like a question nobody could answer, and the
                    // next round tries again -- a pin file unreadable for a
                    // moment recovers, where ending the run would drop a
                    // live session. `say` puts the store's own error in the
                    // log, so it is not hidden behind "needs a prompt".
                    trust::TrustError::Store(_) => {
                        self.say(&format!("qsh: {e}"));
                        (refusal(background), None)
                    }
                });
            }
        };

        let stage = if self.recovery.is_some() && self.setup.is_allowlisted(&host, port) {
            Stage::AfterSsh
        } else {
            stage
        };
        match stage {
            Stage::First => self.sign_in(i, &host, port, sockaddr, server),
            Stage::AfterSsh => Ok(self.on_the_list(i, &host, port, sockaddr, server)),
        }
    }

    /// The key candidates for step 1: the ones loaded earlier in this run,
    /// or loaded now. `Err` is an exit code (login only).
    fn candidates(&self) -> Result<Loaded, i32> {
        if let Some(c) = self.setup.cached_candidates() {
            return Ok(c);
        }
        let args = &self.setup.args;
        if !self.background() {
            let loaded = keys::candidates(
                args.identity.as_deref(),
                passphrase_asker(&self.setup.tty, args.no_password),
                &args.login,
            );
            return match step_one_keys(loaded) {
                Ok(c) => {
                    self.setup.cache_candidates(&c);
                    Ok(c)
                }
                Err(e) => {
                    eprintln!("qsh: {e}");
                    Err(10)
                }
            };
        }
        // The login went through ssh and never signed: load them now, asking
        // nobody -- a key behind a passphrase is left out.
        let loaded = keys::candidates(args.identity.as_deref(), &keys::NeverAsk, &args.login);
        match step_one_keys(loaded) {
            Ok(c) => {
                self.setup.cache_candidates(&c);
                Ok(c)
            }
            Err(e) => {
                log::warn(&format!("{e}; signing with no key this round"));
                Ok(Loaded::default())
            }
        }
    }

    /// Step 1's logins: every key candidate in turn, until one is taken.
    fn sign_in(
        &mut self,
        i: usize,
        host: &str,
        port: u16,
        sockaddr: SocketAddr,
        server: trust::ServerKey,
    ) -> Result<(DirectOutcome, Option<String>), i32> {
        let loaded = self.candidates()?;
        let mut offered = Vec::new();
        let mut won = None;
        let mut silent = None;
        let mut proved = false;
        for candidate in &loaded.keys {
            if self.interrupted() {
                break;
            }
            log::log(&format!("trying key {}", candidate.label));
            let (verdict, att, trial) = self.try_login(
                sockaddr,
                server.key,
                Login::Signature(candidate.signer.clone()),
            );
            log::log(&format!("{} -> {verdict:?}", candidate.label));
            if handshake_done(&verdict) && !proved {
                proved = true;
                self.proved(host, port, &server);
            }
            match verdict {
                Verdict::Working => {
                    won = Some((att, trial));
                    break;
                }
                Verdict::AuthRefused => {
                    self.forget(&att);
                    offered.push(candidate.label.clone());
                }
                Verdict::Unreachable(send) => {
                    self.forget(&att);
                    silent = Some(send);
                    break;
                }
                Verdict::StillTrying => unreachable!("settle only returns a decision"),
            }
        }
        if let Some((att, trial)) = won {
            return Ok(self.logged_in(att, trial, sockaddr, server.key));
        }
        if let Some(send) = silent {
            return Ok(self.silence(i, host, port, sockaddr, server, send));
        }
        let looked = if offered.is_empty() {
            loaded.looked
        } else {
            Vec::new()
        };
        let line = report::refused(host, port, &self.setup.args.login, &offered, &looked);
        self.details[i].offered = offered;
        self.details[i].looked = looked;
        Ok((DirectOutcome::Refused, Some(line)))
    }

    /// Step 3's login: one attempt, let in by the daemon's list.
    fn on_the_list(
        &mut self,
        i: usize,
        host: &str,
        port: u16,
        sockaddr: SocketAddr,
        server: trust::ServerKey,
    ) -> (DirectOutcome, Option<String>) {
        log::log("trying the process key on the daemon's list");
        let (verdict, att, trial) = self.try_login(sockaddr, server.key, Login::Allowlist);
        log::log(&format!("the process key -> {verdict:?}"));
        if handshake_done(&verdict) {
            self.proved(host, port, &server);
        }
        match verdict {
            Verdict::Working => self.logged_in(att, trial, sockaddr, server.key),
            Verdict::AuthRefused => {
                self.forget(&att);
                (
                    DirectOutcome::Refused,
                    Some(report::refused_after_ssh(host, port)),
                )
            }
            Verdict::Unreachable(send) => {
                self.forget(&att);
                self.silence(i, host, port, sockaddr, server, send)
            }
            Verdict::StillTrying => unreachable!("settle only returns a decision"),
        }
    }

    /// Recovery must land in the session the token names, unless the owner
    /// obtained explicit consent for a replacement. A fresh probe without
    /// that consent opens no shell and is closed before reporting loss.
    fn logged_in(
        &mut self,
        att: attempt::Attempt,
        trial: Trial,
        sockaddr: SocketAddr,
        key: [u8; 32],
    ) -> (DirectOutcome, Option<String>) {
        if self.interrupted() {
            self.forget(&att);
            return (
                DirectOutcome::NoAnswer(NoAnswerWhy::Silent { waited_secs: 0 }),
                None,
            );
        }
        let outcome = landed(
            self.background() && !self.fresh_session,
            att.client.resumed(),
        );
        if outcome == DirectOutcome::Connected {
            let mut slot = self
                .setup
                .session_key
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if slot.is_none() {
                *slot = Some(key);
            }
        }
        if outcome == DirectOutcome::SessionGone {
            log::log("the server started a fresh session: the one this run had is gone");
            // Closed, not let go: nobody is coming back to a fresh session.
            att.close();
            self.drain();
        } else {
            self.connected = Some((att, trial, sockaddr));
        }
        (outcome, None)
    }

    /// An attempt that never got a handshake: what the client observed.
    ///
    /// A send the OS refused says it all, and nothing more is asked. Past
    /// that, silence is ambiguous when the key came out of the store: a
    /// server whose key has changed cannot complete the handshake against
    /// the old one, and looks exactly like a daemon that is not running. Ask
    /// discovery once, here and nowhere else, before blaming a daemon that
    /// may be up the whole time -- and its answer (the same key, nothing, or
    /// something else) is what the line says.
    fn silence(
        &mut self,
        i: usize,
        host: &str,
        port: u16,
        sockaddr: SocketAddr,
        server: trust::ServerKey,
        send: Option<SendFailure>,
    ) -> (DirectOutcome, Option<String>) {
        if self.interrupted() {
            return (
                DirectOutcome::NoAnswer(NoAnswerWhy::Silent { waited_secs: 0 }),
                None,
            );
        }
        let diagnostic = self
            .recovery
            .map(|r| r.discovery(i, self.revision, self.setup.discovery.clone()));
        let foreground_discovery = trust::ForegroundDiscovery(self.setup.discovery.as_ref());
        let discovery: &dyn trust::Discover = diagnostic
            .as_ref()
            .map(|d| d as &dyn trust::Discover)
            .unwrap_or_else(|| {
                if self.background() {
                    self.setup.discovery.as_ref()
                } else {
                    &foreground_discovery
                }
            });
        let on_macos = cfg!(target_os = "macos");
        let why = match (send, &server.source) {
            (Some(failure), _) => send_why(sockaddr, failure, on_macos),
            // The server named this key on this run: it answers the key
            // request, and not the login.
            (None, trust::KeySource::Discovered) => NoAnswerWhy::KeyedButSilent,
            // Spec §4a rule 3: the neighbour's key got nothing here. One key
            // request tells another server from a silence with another
            // cause; the key it offers is never pinned -- it proves nothing.
            (None, trust::KeySource::Neighbour { of }) => {
                match trust::after_neighbour_silence(sockaddr, server.key, discovery) {
                    trust::NeighbourSilence::OtherServer { offered } => {
                        let line = report::not_the_same_server(
                            &trust::label(host, port),
                            of,
                            &server.key,
                            &offered,
                        );
                        self.say_loud(line);
                        return (DirectOutcome::KeyChanged, None);
                    }
                    trust::NeighbourSilence::SameKey => NoAnswerWhy::KeyedButSilent,
                    trust::NeighbourSilence::NoKey(DiscoveryError::Silent { .. }) => {
                        NoAnswerWhy::Silent {
                            waited_secs: transport::HANDSHAKE_GIVE_UP_AFTER.as_secs(),
                        }
                    }
                    trust::NeighbourSilence::NoKey(e) => discovery_why(e, on_macos),
                }
            }
            (None, trust::KeySource::Pinned) => {
                match trust::after_silence(
                    host,
                    port,
                    sockaddr,
                    server.key,
                    discovery,
                    &self.setup.pins,
                ) {
                    trust::AfterSilence::Changed(e) => {
                        self.say_loud(format!("qsh: {e}"));
                        return (DirectOutcome::KeyChanged, None);
                    }
                    trust::AfterSilence::SameKey => NoAnswerWhy::KeyedButSilent,
                    // Silence to both: what the handshake itself waited.
                    trust::AfterSilence::NoKey(DiscoveryError::Silent { .. }) => {
                        NoAnswerWhy::Silent {
                            waited_secs: transport::HANDSHAKE_GIVE_UP_AFTER.as_secs(),
                        }
                    }
                    trust::AfterSilence::NoKey(e) => discovery_why(e, on_macos),
                }
            }
        };
        let line = report::no_answer(host, port, &why);
        (DirectOutcome::NoAnswer(why), Some(line))
    }

    /// A handshake completed at `host:port` with `server`'s key. When that
    /// key was a neighbour's, it is this address's too (spec §4a rule 2):
    /// pinned without asking, with one line. A key pinned there in the
    /// meantime -- another `qsh` -- is left as it is.
    fn proved(&self, host: &str, port: u16, server: &trust::ServerKey) {
        // Recovery publication is owned by the main loop after stamp validation.
        // A late handshake must never write trust from its worker thread.
        if self.recovery.is_some() || self.interrupted() {
            return;
        }
        let trust::KeySource::Neighbour { of } = &server.source else {
            return;
        };
        let addr = trust::label(host, port);
        match trust::remember_proven(host, port, &server.key, &self.setup.pins) {
            Ok(trust::Proven::Remembered) => self.say(&report::same_server(&addr, of)),
            Ok(trust::Proven::AlreadyKnown) => {}
            Ok(trust::Proven::Stale { pinned }) => log::warn(&format!(
                "{addr} holds the key of {of}, but known_hosts pinned {} for it meanwhile; \
                 left as it is",
                sshauth::known_hosts::key_fingerprint(&pinned)
            )),
            Err(e) => log::warn(&format!("{addr}: could not remember its key: {e}")),
        }
    }

    /// Ends an attempt that did not work, and drops what it queued: the next
    /// one -- or the session, if a later address works -- starts clean.
    ///
    /// An attempt whose handshake landed in our session is let go quietly
    /// (`detach`), whatever its verdict: on a lossy network the handshake can
    /// resume the session and the verdict still come out refused or
    /// unreachable, and a `Close` would then tear down the very session a
    /// return is for (or, at login, the one a warm return found).
    fn forget(&self, att: &attempt::Attempt) {
        match let_go(att.client.resumed()) {
            LetGo::Detach => att.detach(),
            LetGo::Close => att.close(),
        }
        self.drain();
    }

    /// Drops what the attempts so far have queued.
    fn drain(&self) {
        while self.rx.try_recv().is_ok() {}
    }

    /// One connection attempt, judged.
    fn try_login(
        &self,
        sockaddr: SocketAddr,
        server_pub: [u8; 32],
        login: Login,
    ) -> (Verdict, attempt::Attempt, Trial) {
        let att = attempt::Attempt::open(
            sockaddr,
            server_pub,
            self.setup.keypair.private,
            login,
            self.tx.clone(),
            self.setup.token,
        );
        if let Some((epoch, sweep)) = self.recovery_attempt {
            att.probe_port_refusal_stamped(sockaddr, epoch, sweep.0);
        } else {
            att.probe_port_refusal(sockaddr);
        }
        // The one substrate this run's session ever uses: `ChannelSession`
        // owns it for both directions from here on, so `interactive` needs
        // no second instance just to decode incoming bytes.
        // `on_malformed_control` is set here, not later, since this is the
        // only place the substrate is built -- a malformed control record is
        // this build's only way to learn a channel may be stuck `Opening`
        // forever with no evidence why (see `QshSubstrate::on_stream`). Its
        // reach does NOT widen by being set here instead of in
        // `interactive`: it only fires from inside control-stream decoding,
        // which only `ChannelSession::on_bytes` drives, and that is called
        // from exactly one place -- `interactive`'s main loop. The trial
        // (`settle_opening`, below) never decodes anything, and a refused
        // attempt's queued events are drained (`forget`) rather than read.
        let sink: Sink = Box::new({
            let client = Arc::clone(&att.client);
            move |stream, data| client.send_bytes(stream, data)
        });
        let mut channel_session =
            ChannelSession::new(QshSubstrate::new(sink).on_malformed_control(log::warn));
        // What terminal this client's own emulator is, before anything is
        // opened: the daemon spawns each channel with what it knew at that
        // moment. Without it the daemon assumes xterm-256color for every
        // client, and keys this terminal encodes differently -- Home
        // and End first of all -- arrive as sequences the remote does not
        // recognize.
        if let Ok(term) = std::env::var("TERM") {
            channel_session.announce_term(&term);
        }
        let (verdict, opened_ch) = settle_opening(
            &att,
            &mut channel_session,
            self.cols,
            self.rows,
            !self.background() || self.fresh_session,
            || self.interrupted(),
        );
        (
            verdict,
            att,
            Trial {
                channel_session,
                opened_ch,
                cols: self.cols,
                rows: self.rows,
            },
        )
    }
}

/// Whether an attempt's handshake completed: the server proved it holds
/// the private half of the key it was made with. A Noise IK handshake
/// completes only against that holder, so a refused login proves it as
/// well as a working one; only an attempt that never got that far does not.
fn handshake_done(verdict: &Verdict) -> bool {
    matches!(verdict, Verdict::Working | Verdict::AuthRefused)
}

/// The keys step 1 signs with, from what loading them gave. No key at all
/// is not the end: this step is refused with nothing offered, and an
/// address with ssh still has its fallback -- a password-only ssh account
/// has no key to sign qsh with. Only a key that exists and would not load
/// (an unreadable `-i`) stops the run.
fn step_one_keys(
    loaded: Result<Vec<keys::Candidate>, keys::KeyError>,
) -> Result<Loaded, keys::KeyError> {
    match loaded {
        Ok(keys) => Ok(Loaded {
            keys,
            looked: Vec::new(),
        }),
        Err(keys::KeyError::NoKeys { looked }) => {
            log::log(&format!(
                "no key to sign qsh with; looked: {}",
                looked.join("; ")
            ));
            Ok(Loaded {
                keys: Vec::new(),
                looked,
            })
        }
        Err(e) => Err(e),
    }
}

/// The address to dial for `resolved`, the preferred answer for `host`.
///
/// The transport's socket is IPv4 (see `preferred_addr`): an IPv6 address
/// is not worth a key request or a handshake that cannot work -- except an
/// IPv4-mapped one (`::ffff:a.b.c.d`), which is the IPv4 address it maps.
/// `Err` says which it was: a name resolving to IPv6 only, or an IPv6
/// address written as such.
fn dial_target(host: &str, resolved: SocketAddr) -> Result<SocketAddr, NoAnswerWhy> {
    match resolved {
        SocketAddr::V4(_) => Ok(resolved),
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => Ok(SocketAddr::new(v4.into(), v6.port())),
            None => Err(NoAnswerWhy::Ipv6Only {
                literal: host.parse::<std::net::IpAddr>().is_ok(),
            }),
        },
    }
}

/// What a key request that produced no key amounts to for the ladder.
fn discovery_why(e: DiscoveryError, on_macos: bool) -> NoAnswerWhy {
    match e {
        DiscoveryError::SendFailed { addr, kind, text } => send_why(addr, (kind, text), on_macos),
        DiscoveryError::Silent { waited, .. } => NoAnswerWhy::Silent {
            waited_secs: waited.as_secs(),
        },
        DiscoveryError::Malformed { .. } => NoAnswerWhy::NotQshd {
            reason: "the key offer is malformed".into(),
        },
        DiscoveryError::NotAKeyOffer { .. } => NoAnswerWhy::NotQshd {
            reason: "the reply is not a key offer".into(),
        },
        DiscoveryError::ReadFailed {
            addr,
            kind: std::io::ErrorKind::ConnectionRefused,
            text,
        } => send_why(
            addr,
            (std::io::ErrorKind::ConnectionRefused, text),
            on_macos,
        ),
        DiscoveryError::ReadFailed { text, .. } => NoAnswerWhy::Socket {
            reason: format!("reading the reply: {text}"),
        },
        DiscoveryError::Local(reason) => NoAnswerWhy::Socket { reason },
    }
}

/// A send to `to` the OS refused, with the Local Network hint where it fits.
fn send_why(to: SocketAddr, (kind, os_error): SendFailure, on_macos: bool) -> NoAnswerWhy {
    if kind == std::io::ErrorKind::ConnectionRefused {
        return NoAnswerWhy::PortRefused;
    }
    NoAnswerWhy::SendFailed {
        to,
        os_error,
        local_network_hint: sshauth::addr::local_network_hint(on_macos, kind, to.ip()),
    }
}

/// Who answers a key file's passphrase question: nobody under
/// `--no-password`, which promises never to ask.
fn passphrase_asker(tty: &Tty, no_password: bool) -> &dyn keys::Passphrase {
    static NEVER: keys::NeverAsk = keys::NeverAsk;
    if no_password {
        &NEVER
    } else {
        tty
    }
}

/// Whether every address of a round that got nowhere ended on a step that
/// needed a question: the last thing that could have let each one on was a
/// question nobody in the background may ask, so the next round would end
/// the same way.
fn every_address_needs_a_question(failures: &[::connect::Failure]) -> bool {
    !failures.is_empty()
        && failures
            .iter()
            .all(|f| f.reasons.last() == Some(&::connect::Reason::NeedsPrompt))
}

/// The background's answer to every trust question: no. Nobody is at the
/// terminal to be asked -- it belongs to the live session.
struct NoQuestions;

impl trust::Confirm for NoQuestions {
    fn ask(&self, _prompt: &str) -> bool {
        false
    }
}

/// What a refusal to trust a server key is to the ladder: the person's no
/// at login; in the background, a question nobody could answer.
fn refusal(background: bool) -> DirectOutcome {
    if background {
        DirectOutcome::NeedsPrompt
    } else {
        DirectOutcome::Declined
    }
}

/// What a working login is to the ladder. In the background it counts only
/// if it `resumed` the session the token names; landing in a fresh one
/// means the server no longer has ours.
fn landed(background: bool, resumed: bool) -> DirectOutcome {
    if background && !resumed {
        DirectOutcome::SessionGone
    } else {
        DirectOutcome::Connected
    }
}

/// How an attempt that did not work is let go.
#[derive(Debug, PartialEq, Eq)]
enum LetGo {
    /// Quietly: the server keeps the session the attempt landed in.
    Detach,
    /// With a `Close`: nothing of ours is on the far side.
    Close,
}

/// An attempt that `resumed` our session is detached, never closed.
fn let_go(resumed: bool) -> LetGo {
    if resumed {
        LetGo::Detach
    } else {
        LetGo::Close
    }
}

/// Like [`attempt::Attempt::settle_with`], but the thing done on `Live` is
/// to open the shell channel at `cols`x`rows` when a fresh shell is allowed,
/// and remember what came back. Sending this the moment the link comes alive,
/// rather than only once the whole attempt is judged `Working`, is what
/// makes a working key's verdict fast: under the channel protocol a cold
/// server answers nothing at all until asked for a channel, so without
/// this every accepted key sat out the full auth deadline in silence (the
/// coordinator's finding -- the old, single-stream protocol's shell used
/// to print its prompt unprompted, which is what made the verdict instant
/// before). A refused key gets no `Opened` in reply, `got_data` never
/// flips, and `settle_with` resolves the verdict exactly as it did before
/// this existed.
fn settle_opening(
    att: &attempt::Attempt,
    channel_session: &mut ChannelSession<QshSubstrate<Sink>>,
    cols: u16,
    rows: u16,
    open_fresh: bool,
    interrupted: impl Fn() -> bool,
) -> (Verdict, Option<ChannelId>) {
    let mut opened_ch = None;
    let verdict = att.settle_until(
        || {
            // A resumed session already has its channels; the server announces
            // them unprompted, and opening one here would ask for a stream it
            // still holds. Nothing is lost for the verdict either: that
            // announcement is itself the traffic this open exists to provoke.
            // Recovery probes must not create a replacement shell before
            // the owner asks. With no channel, authentication settles from
            // the live link at the existing signature deadline instead.
            if open_fresh && !att.client.resumed() {
                opened_ch = channel_session.open_shell(cols, rows);
            }
        },
        interrupted,
    );
    (verdict, opened_ch)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::path::PathBuf;

    #[test]
    fn replacement_without_signers_refuses_each_road_before_allowing_ssh() {
        use ::connect::recovery_gate::{RecoveryEpoch, SweepId};
        use std::time::{Duration, Instant};

        let home = tempfile::tempdir().unwrap();
        let roads = [
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        ];
        let args = crate::args::parse_args(
            &roads
                .iter()
                .map(|r| r.local_addr().unwrap().to_string())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let old = Setup::new(
            args,
            transport::generate_keypair(),
            sshauth::known_hosts::KnownHosts::open(home.path().join("known_hosts")),
            Box::new(trust::UdpDiscovery),
            Tty::at(home.path().join("no-tty")),
            KnownHosts::new(home.path().join("ssh_known_hosts"), None),
            None,
            None,
            [1; 16],
        );
        *old.session_key.lock().unwrap() = Some([7; 32]);
        old.cache_candidates(&Loaded::default());
        for road in &roads {
            old.allowlist("127.0.0.1", road.local_addr().unwrap().port());
        }
        let setup = old.replacement([2; 16]);
        let epoch = RecoveryEpoch {
            connection: 2,
            network: 1,
        };
        let sweep = SweepId(1);
        let recovery = Recovery::new(epoch, roads.len());
        recovery.begin_sweep(sweep);
        let (tx, rx) = std::sync::mpsc::channel();
        let mut climb = Climb::new(
            &setup,
            setup.args.addresses.clone(),
            0,
            Mode::Background {
                progress: tx.clone(),
                round: 1,
            },
            80,
            24,
            tx,
            &rx,
        )
        .recovering(&recovery, epoch, sweep)
        .allow_new_session(true);
        let started = Instant::now();
        for (i, road) in roads.iter().enumerate() {
            assert!(!recovery.ssh_allowed(), "SSH must wait for every road");
            let (outcome, _) = climb
                .direct(
                    i,
                    road.local_addr().unwrap().port(),
                    Stage::First,
                    &recovery.cancel,
                )
                .unwrap();
            assert_eq!(outcome, DirectOutcome::Refused);
        }
        assert!(
            recovery.ssh_allowed(),
            "completed QSH refusals admit bound SSH"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "stale enrollment waited for UDP"
        );
        assert_eq!(setup.server_identity(), old.server_identity());
        assert_eq!(old.token, [1; 16]);
        assert_eq!(setup.token, [2; 16]);
    }

    #[test]
    fn no_key_at_all_is_a_refusal_with_nothing_offered_not_the_end() {
        let loaded = step_one_keys(Err(keys::KeyError::NoKeys {
            looked: vec!["~/.ssh/id_ed25519 -- no such file".into()],
        }))
        .expect("no keys lets the ladder go on");
        assert!(loaded.keys.is_empty());
        assert_eq!(
            loaded.looked,
            vec!["~/.ssh/id_ed25519 -- no such file".to_string()],
            "where they were looked for is kept for the refusal's line"
        );
    }

    #[test]
    fn a_key_that_would_not_load_still_stops_the_run() {
        let err = step_one_keys(Err(keys::KeyError::IdentityUnreadable {
            path: PathBuf::from("/k"),
            why: "no such file".into(),
        }))
        .expect_err("an unreadable -i is exit 10");
        assert!(matches!(err, keys::KeyError::IdentityUnreadable { .. }));
    }

    fn at(literal: &str) -> SocketAddr {
        literal.parse().expect("addr")
    }

    /// What discovery observed becomes what the ladder is told, one case
    /// each: the OS's words for a refused send (with the Local Network hint
    /// only on macOS to a local address), the wait for silence, and
    /// something else answering.
    #[test]
    fn what_discovery_observed_is_what_the_ladder_is_told() {
        let lan = at("192.168.0.200:60200");
        let refused = || DiscoveryError::SendFailed {
            addr: lan,
            kind: std::io::ErrorKind::HostUnreachable,
            text: "No route to host (os error 65)".into(),
        };
        assert_eq!(
            discovery_why(refused(), true),
            NoAnswerWhy::SendFailed {
                to: lan,
                os_error: "No route to host (os error 65)".into(),
                local_network_hint: true,
            }
        );
        assert_eq!(
            discovery_why(refused(), false),
            NoAnswerWhy::SendFailed {
                to: lan,
                os_error: "No route to host (os error 65)".into(),
                local_network_hint: false,
            }
        );
        assert_eq!(
            discovery_why(
                DiscoveryError::Silent {
                    addr: lan,
                    waited: trust::DISCOVERY_TIMEOUT
                },
                true
            ),
            NoAnswerWhy::Silent { waited_secs: 5 }
        );
        assert_eq!(
            discovery_why(DiscoveryError::NotAKeyOffer { addr: lan }, true),
            NoAnswerWhy::NotQshd {
                reason: "the reply is not a key offer".into()
            }
        );
        assert_eq!(
            discovery_why(DiscoveryError::Malformed { addr: lan }, true),
            NoAnswerWhy::NotQshd {
                reason: "the key offer is malformed".into()
            }
        );
        assert!(matches!(
            discovery_why(DiscoveryError::Local("opening: no".into()), true),
            NoAnswerWhy::Socket { .. }
        ));
    }

    /// IPv4 is dialled as it is; an IPv4-mapped IPv6 address as the IPv4
    /// address it maps; any other IPv6 address is not dialled, and says
    /// whether it was a name or a literal.
    #[test]
    fn only_ipv4_is_dialled_and_a_mapped_address_is_ipv4() {
        assert_eq!(
            dial_target("h", at("192.0.2.7:60022")),
            Ok(at("192.0.2.7:60022"))
        );
        assert_eq!(
            dial_target("::ffff:192.168.0.200", at("[::ffff:192.168.0.200]:60022")),
            Ok(at("192.168.0.200:60022"))
        );
        assert_eq!(
            dial_target("h.example", at("[2001:db8::1]:60022")),
            Err(NoAnswerWhy::Ipv6Only { literal: false })
        );
        assert_eq!(
            dial_target("2001:db8::1", at("[2001:db8::1]:60022")),
            Err(NoAnswerWhy::Ipv6Only { literal: true })
        );
    }

    /// The transport's send failure, to a public address, gets no hint even
    /// on macOS: the permission governs the local network only.
    #[test]
    fn a_transport_send_failure_to_a_public_address_gets_no_hint() {
        let why = send_why(
            at("203.0.113.7:60200"),
            (
                std::io::ErrorKind::HostUnreachable,
                "No route to host (os error 65)".into(),
            ),
            true,
        );
        assert!(
            matches!(
                why,
                NoAnswerWhy::SendFailed {
                    local_network_hint: false,
                    ..
                }
            ),
            "{why:?}"
        );
    }

    #[test]
    fn the_background_asks_nobody() {
        use crate::trust::Confirm as _;
        assert!(!NoQuestions.ask("Trust it?"));
    }

    #[test]
    fn a_trust_refusal_in_the_background_is_a_question_nobody_could_answer() {
        assert_eq!(refusal(true), DirectOutcome::NeedsPrompt);
        assert_eq!(refusal(false), DirectOutcome::Declined);
    }

    #[test]
    fn a_fresh_session_in_the_background_is_the_old_one_gone() {
        assert_eq!(landed(true, false), DirectOutcome::SessionGone);
        assert_eq!(landed(true, true), DirectOutcome::Connected);
        assert_eq!(
            landed(false, false),
            DirectOutcome::Connected,
            "at login a fresh session is fine"
        );
    }

    /// An attempt that landed in our session is let go quietly even when
    /// its verdict says it did not work: `Close` would tear down the very
    /// session a return is for. Only an attempt that never resumed it --
    /// a fresh session, or no handshake at all -- is closed.
    #[test]
    fn an_attempt_that_resumed_our_session_is_detached_never_closed() {
        assert_eq!(let_go(true), LetGo::Detach);
        assert_eq!(let_go(false), LetGo::Close);
    }

    #[test]
    fn a_round_where_every_address_needs_a_question_says_so() {
        use ::connect::{Failure, Reason};
        let all = vec![
            Failure {
                addr: 0,
                reasons: vec![Reason::NeedsPrompt],
            },
            Failure {
                addr: 1,
                reasons: vec![Reason::NeedsPrompt],
            },
        ];
        assert!(every_address_needs_a_question(&all));
        let mixed = vec![
            Failure {
                addr: 0,
                reasons: vec![Reason::NeedsPrompt],
            },
            Failure {
                addr: 1,
                reasons: vec![Reason::NoAnswer(NoAnswerWhy::KeyedButSilent)],
            },
        ];
        assert!(!every_address_needs_a_question(&mixed));
        assert!(!every_address_needs_a_question(&[]));
        let asked_last = vec![
            Failure {
                addr: 0,
                reasons: vec![
                    Reason::NoAnswer(NoAnswerWhy::KeyedButSilent),
                    Reason::NeedsPrompt,
                ],
            },
            Failure {
                addr: 1,
                reasons: vec![Reason::NeedsPrompt],
            },
        ];
        assert!(
            every_address_needs_a_question(&asked_last),
            "only a question would have let address 0 on"
        );
        let asked_first = vec![Failure {
            addr: 0,
            reasons: vec![
                Reason::NeedsPrompt,
                Reason::NoAnswer(NoAnswerWhy::KeyedButSilent),
            ],
        }];
        assert!(!every_address_needs_a_question(&asked_first));
    }

    #[test]
    fn the_setup_is_shared_across_threads() {
        fn shareable<T: Send + Sync>() {}
        shareable::<Setup>();
    }

    /// A pseudo-terminal with a line already typed: the terminal asker
    /// would read it, so a `None` is the choice, not a missing terminal.
    #[test]
    fn with_no_password_a_passphrase_is_never_asked_for() {
        let _serialize = crate::tty::SIGNAL_TESTS
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let pty = nix::pty::openpty(None, None).expect("openpty");
        let path = std::fs::read_link(format!("/proc/self/fd/{}", pty.slave.as_raw_fd()))
            .expect("the slave's path");
        let tty = Tty::at(path);
        let mut master = std::fs::File::from(pty.master);

        master.write_all(b"typed\n").expect("type");
        assert_eq!(passphrase_asker(&tty, true).ask("Passphrase: "), None);
        assert_eq!(
            passphrase_asker(&tty, false).ask("Passphrase: ").as_deref(),
            Some("typed"),
            "the terminal answers when asking is allowed, or this proves nothing"
        );
    }
}

#[cfg(test)]
#[path = "../tests/support/recovery_ssh.rs"]
mod authorization_server;

#[cfg(test)]
mod authorization_tests {
    use super::*;
    use std::{
        io::{Read, Write},
        os::fd::AsRawFd,
        time::{Duration, Instant},
    };

    #[test]
    fn stale_epoch_or_cancelled_host_consent_cannot_append_ssh_trust() {
        for change_epoch in [true, false] {
            let home = tempfile::tempdir().unwrap();
            let ssh = authorization_server::Server::start();
            let args =
                crate::args::parse_args(&[format!("fixture@127.0.0.1,ssh={}", ssh.port)]).unwrap();
            let pty = nix::pty::openpty(None, None).unwrap();
            let tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
            let mut master = std::fs::File::from(pty.master);
            let hosts = home.path().join("ssh_known_hosts");
            let setup = Setup::new(
                args,
                transport::generate_keypair(),
                sshauth::known_hosts::KnownHosts::open(home.path().join("known_hosts")),
                Box::new(trust::UdpDiscovery),
                tty,
                KnownHosts::new(hosts.clone(), None),
                None,
                None,
                [1; 16],
            );
            *setup.session_key.lock().unwrap() = Some([7; 32]);
            let server = setup.server_identity().unwrap();
            let endpoints = [::connect::server_identity::SshEndpoint {
                host: "127.0.0.1".into(),
                port: ssh.port,
            }];
            let permit = setup.begin_ssh_authorization(::connect::recovery_gate::RecoveryEpoch {
                connection: 1,
                network: 1,
            });
            let cancel = knock::Cancel::new();
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    crate::ssh_authorization::authorize_ssh(
                        &server, &endpoints, &setup, &permit, &cancel,
                    )
                });
                let mut shown = String::new();
                let deadline = Instant::now() + Duration::from_secs(3);
                while !shown.contains("Are you sure you want to continue connecting") {
                    assert!(Instant::now() < deadline, "no host consent: {shown}");
                    let mut fd = libc::pollfd {
                        fd: master.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut fd, 1, 20) } > 0 {
                        let mut bytes = [0; 2048];
                        let n = master.read(&mut bytes).unwrap();
                        shown.push_str(&String::from_utf8_lossy(&bytes[..n]));
                    }
                }
                if change_epoch {
                    setup.invalidate_ssh_authorization();
                } else {
                    cancel.cancel();
                }
                master.write_all(b"yes\nyes\n").unwrap();
                assert!(matches!(
                    worker.join().unwrap(),
                    Err(crate::ssh_authorization::AuthorizationError::Cancelled)
                ));
            });
            assert!(!hosts.exists(), "stale consent appended SSH host trust");
            assert!(!home.path().join("ssh_bindings.json").exists());
            ssh.untouched();
        }
    }
}
