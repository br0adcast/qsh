//! Channels backed by pseudo-terminals: the `qshd` half of
//! `transport::channel_server`'s seam.
//!
//! The transport knows a channel is a reader, a writer, a resize handle, a
//! screen model and something that waits for an exit code. This is where
//! those come from `portable-pty`, and where a screen model is built for the
//! channels that asked for one.
//!
//! A pseudo-terminal opens at the size the request names -- not at
//! [`pty::DEFAULT_PTY_SIZE`] followed by a resize a moment later, which is
//! exactly the cycle that makes tmux reflow a pane and leave a blank line in
//! the scrollback. A request with no size (`cols == 0 || rows == 0`) means a
//! channel with no pseudo-terminal at all; there is no such channel here to
//! offer, so it is refused with a reason rather than quietly handed the
//! pseudo-terminal default.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use portable_pty::{Child, CommandBuilder, PtySize};

use transport::auth::Principal;
use transport::channel::{ChannelKind, OpenRequest};
use transport::channel_open::{ChannelOpenRegistry, OpenCustody, SpawnFailure, UninstalledChannel};
#[cfg(test)]
use transport::channel_server::SpawnedChannel;
use transport::channel_server::{
    run_channel_session_with, ChannelSpawner, ChannelWait, DaemonUpdates,
};
use transport::conn::Consumption;
use transport::session_manager::{LoginId, SessionBackend, SessionIo};
use transport::shell_server::{NoScreen, SessionScreen};

use crate::pty;
use crate::screen_budget::ScreenBudget;
use terminal_size::TerminalSize;

/// Opens a channel by spawning a pseudo-terminal through `portable-pty`.
pub struct PtyChannelSpawner {
    opens: Arc<ChannelOpenRegistry>,
    budget: Arc<ScreenBudget>,
}

impl PtyChannelSpawner {
    pub fn new(budget: Arc<ScreenBudget>) -> Self {
        Self {
            budget,
            opens: ChannelOpenRegistry::new(Default::default()),
        }
    }
}

impl ChannelSpawner for PtyChannelSpawner {
    fn open_registry(&self) -> Arc<ChannelOpenRegistry> {
        self.opens.clone()
    }
    /// Owner uid keys the shared screen budget, including aliases.
    ///
    /// `_login` is ignored: the personal mode has exactly one login, for
    /// the process's whole life, and opens no PAM session for it -- that
    /// machinery belongs to the system mode's spawner
    /// (`helper::spawner::HelperChannelSpawner`), where several logins share
    /// one daemon.
    fn spawn(
        &self,
        owner: &Principal,
        _login: LoginId,
        req: &OpenRequest,
        term: Option<&str>,
        custody: &OpenCustody,
    ) -> Result<UninstalledChannel, SpawnFailure> {
        if req.cols == 0 || req.rows == 0 {
            return Err(custody.refuse_before_creation(
                "a channel without a terminal is not supported yet".to_string(),
            ));
        }
        TerminalSize::new(req.cols, req.rows)
            .map_err(|e| custody.refuse_before_creation(e.to_string()))?;
        let screen = make_screen(req, owner, Arc::clone(&self.budget))
            .map_err(|e| custody.refuse_before_creation(e))?;
        let size = PtySize {
            rows: req.rows,
            cols: req.cols,
            pixel_width: 0,
            pixel_height: 0,
        };
        // Never inside a replacement's exec window: this child would inherit
        // the descriptors it makes inheritable (see `crate::update`). Held
        // until the spawn has returned -- the child has exec'd by then.
        let permit = crate::update::spawn_permit();
        let (master, child) = match req.kind {
            // Kernel echo stays ON: a full-screen program puts its own
            // terminal into raw mode, so kernel echo neither helps nor
            // hinders, same as a `tmux attach` client today.
            ChannelKind::Shell => pty::spawn_shell(size, term),
            // Echo OFF, unconditionally: today every command channel is the
            // app's `tmux -C` control-mode client, which must not see its
            // own writes echoed back. `spawn_command_no_echo` is the whole
            // channel, hard-coded rather than decided per request -- there
            // is no way here yet for a command channel to ask for echo ON.
            ChannelKind::Command => pty::spawn_command_no_echo(
                size,
                command_builder(&req.command).map_err(|e| custody.refuse_before_creation(e))?,
                term,
            ),
        }
        .map_err(|e| custody.refuse_before_creation(format!("could not open channel: {e:#}")))?;
        drop(permit);
        finish_personal_spawn(master, child, screen, custody)
    }
}

/// Assemble the spawned PTY at the descriptor-preparation boundary.
fn finish_personal_spawn(
    master: Box<dyn portable_pty::MasterPty + Send>,
    child: Box<dyn Child + Send + Sync>,
    screen: Box<dyn SessionScreen>,
    custody: &OpenCustody,
) -> Result<UninstalledChannel, SpawnFailure> {
    let construction = custody.protect(Box::new(ChildWait(child)), screen);
    let reader = master
        .try_clone_reader()
        .map_err(|e| custody.failure(format!("reading from the channel is unavailable: {e:#}")))?;
    let writer = master
        .take_writer()
        .map_err(|e| custody.failure(format!("writing to the channel is unavailable: {e:#}")))?;
    Ok(construction.finish(reader, writer, Box::new(pty::PtyResizeHandle::new(master))))
}

#[cfg(test)]
impl PtyChannelSpawner {
    fn spawn(
        &self,
        owner: &Principal,
        login: LoginId,
        req: &OpenRequest,
        term: Option<&str>,
    ) -> Result<SpawnedChannel, String> {
        fixture_spawn(self, owner, login, req, term)
    }
}

/// Existing backend fixtures inspect raw descriptors. Their spawner keeps the
/// registration alive on Unknown; this adapter does not infer cleanup from Err.
#[cfg(test)]
pub(crate) fn fixture_spawn(
    spawner: &dyn ChannelSpawner,
    owner: &Principal,
    login: LoginId,
    req: &OpenRequest,
    term: Option<&str>,
) -> Result<SpawnedChannel, String> {
    use transport::channel_open::{OpenIdentity, OpenRequestSnapshot};
    let registry = spawner.open_registry();
    let session = registry.session().unwrap();
    let job = registry
        .try_reserve(
            &session,
            OpenRequestSnapshot {
                owner: owner.clone(),
                login,
                request: req.clone(),
                term: term.map(str::to_owned),
                identity: OpenIdentity {
                    session: session.id(),
                    instance: transport::channel_geometry::ChannelInstance::new(1).unwrap(),
                    stream: req.stream,
                    generation: 0,
                    invalidation_epoch: 0,
                },
            },
        )
        .map_err(|_| "fixture open admission refused".to_string())?;
    match ChannelSpawner::spawn(spawner, owner, login, req, term, job.custody()) {
        Ok(channel) => {
            let (channel, _slot) = job
                .adopt(channel)
                .map_err(|_| "fixture adoption refused".to_string())?;
            Ok(channel)
        }
        Err(failure) => {
            job.cleanup();
            Err(failure.reason)
        }
    }
}

/// Splits a command line into words, honouring single quotes -- the same
/// quoting the client already uses when it builds tmux commands, and no
/// more: a full shell grammar here would be a second, subtly different
/// shell.
///
/// Shared by [`command_builder`] here (personal mode, wraps the result in a
/// `portable_pty::CommandBuilder`) and by the system mode's worker
/// (`helper::spawner`, which sends the words on as `argv` -- the helper
/// itself never parses a command line). The two modes must not disagree
/// about what a command line means, so this is the one place that decides.
pub(crate) fn split_command(command: &[u8]) -> Result<Vec<String>, String> {
    let text = std::str::from_utf8(command).map_err(|_| "command must be UTF-8".to_string())?;
    let mut parts: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut had_any = false;
    for c in text.chars() {
        match c {
            '\'' => {
                in_quotes = !in_quotes;
                had_any = true;
            }
            c if c.is_whitespace() && !in_quotes => {
                if had_any {
                    parts.push(std::mem::take(&mut current));
                    had_any = false;
                }
            }
            c => {
                current.push(c);
                had_any = true;
            }
        }
    }
    if in_quotes {
        return Err("unterminated quote in the command".to_string());
    }
    if had_any {
        parts.push(current);
    }
    if parts.is_empty() {
        return Err("empty command".to_string());
    }
    Ok(parts)
}

/// Parses the request's command line into something `portable-pty` can
/// launch. See [`split_command`] for the quoting rules.
fn command_builder(command: &[u8]) -> Result<CommandBuilder, String> {
    let parts = split_command(command)?;
    let (program, args) = parts
        .split_first()
        .expect("split_command returns at least one word on success");
    let mut cmd = CommandBuilder::new(program);
    for a in args {
        cmd.arg(a);
    }
    Ok(cmd)
}

/// Waits for the channel's child and reports its code. Blocking, which is
/// why `run_channel_session` calls it on a blocking task.
struct ChildWait(Box<dyn Child + Send + Sync>);

impl ChannelWait for ChildWait {
    fn cleanup_uninstalled(
        &mut self,
        authority: &transport::channel_open::CleanupAuthority<'_>,
    ) -> transport::channel_open::CleanupStatus {
        // A successful kill request alone does not establish termination.
        let _ = self.0.kill();
        match self.0.wait() {
            Ok(_) => authority.reaped(),
            Err(_) => transport::channel_open::CleanupStatus::Unknown,
        }
    }
    fn kill(&mut self) {
        // Best-effort: a process that has already exited on its own has
        // nothing left to kill, and that is not a reason to panic -- the
        // matching `wait()` still fetches whatever exit code is there.
        let _ = self.0.kill();
    }

    fn wait(mut self: Box<Self>) -> i32 {
        self.0.wait().map(|s| s.exit_code() as i32).unwrap_or(-1)
    }
}

/// A screen model for the channels that asked for one, `NoScreen` for the
/// ones that didn't -- `serve` and `transport-ensure` share this backend, so
/// both get a repaint after a long absence, not only `serve`'s clients.
///
/// `pub(crate)`: the system mode's worker (`helper::spawner`) builds a
/// screen model the same way, off the same request, so a channel looks the
/// same to a reattaching client whichever mode opened it.
pub(crate) fn make_screen(
    req: &OpenRequest,
    owner: &Principal,
    budget: Arc<ScreenBudget>,
) -> Result<Box<dyn SessionScreen>, String> {
    if req.screen {
        let size = TerminalSize::new(req.cols, req.rows).map_err(|e| e.to_string())?;
        Ok(Box::new(crate::screen::PtyScreen::try_new(
            size, owner.uid, budget,
        )?))
    } else {
        Ok(Box::new(NoScreen))
    }
}

/// One `run_channel_session_with` per accepted session.
///
/// Holds the spawner rather than hard-coding [`PtyChannelSpawner`], so the
/// same session router works for both modes: the personal mode's spawner
/// opens its own pseudo-terminals, the system mode's asks the privileged
/// helper for them across the seam (`helper::spawner::HelperChannelSpawner`).
pub struct ChannelSessionBackend {
    spawner: Arc<dyn ChannelSpawner>,
    /// Speaks for the daemon to every session: `About`, updates. `None`
    /// leaves those records unanswered, as a daemon that predates them does.
    daemon: Option<Arc<dyn DaemonUpdates>>,
}

impl ChannelSessionBackend {
    /// The personal mode: this process opens its own pseudo-terminals.
    pub fn new(budget: Arc<ScreenBudget>) -> ChannelSessionBackend {
        ChannelSessionBackend {
            spawner: Arc::new(PtyChannelSpawner::new(budget)),
            daemon: None,
        }
    }

    /// The system mode: channels come from the helper across the seam.
    pub fn with_spawner(spawner: Arc<dyn ChannelSpawner>) -> ChannelSessionBackend {
        ChannelSessionBackend {
            spawner,
            daemon: None,
        }
    }

    /// Every session this backend runs speaks for `daemon`.
    pub fn with_daemon(mut self, daemon: Arc<dyn DaemonUpdates>) -> ChannelSessionBackend {
        self.daemon = Some(daemon);
        self
    }
}

impl SessionBackend for ChannelSessionBackend {
    fn required_features(&self) -> transport::Features {
        transport::Features::CHANNEL_GEOMETRY
    }

    fn run(&self, io: SessionIo) -> Pin<Box<dyn Future<Output = ()> + Send>> {
        // Logged here once per session; the runner hands the same principal
        // to the spawner with every channel it asks for, and the system
        // mode's spawner opens the channel for exactly that account.
        crate::log::info(
            "qshd",
            &format!(
                "session starting for {} (uid {})",
                io.principal().name,
                io.principal().uid
            ),
        );
        Box::pin(run_channel_session_with(
            io,
            Arc::clone(&self.spawner),
            self.daemon.clone(),
        ))
    }

    /// The channel runner reports every byte it takes (spec §4.10.3):
    /// control records once applied, a channel's input once its process has
    /// it, the update image once on disk, and whatever it drops.
    fn consumption(&self) -> Consumption {
        Consumption::Explicit
    }
}

#[cfg(test)]
mod tests {
    include!("channel_backend_open_tests.rs");
    use super::*;
    fn budget() -> Arc<ScreenBudget> {
        Arc::new(ScreenBudget::new(
            crate::screen_budget::BudgetLimits::default(),
        ))
    }
    fn spawner() -> PtyChannelSpawner {
        PtyChannelSpawner::new(budget())
    }
    use crate::test_support::suppress_shell_history;
    use std::io::{Read, Write};
    use std::time::Duration;

    /// How long [`read_until`] waits before concluding the reading thread is
    /// stuck rather than merely slow.
    const READ_UNTIL_TIMEOUT: Duration = Duration::from_secs(5);

    /// Reads from a channel until `needle` shows up, or gives up. Reading
    /// "until a marker" rather than "one chunk" is what makes the test
    /// independent of how a pseudo-terminal splits its output.
    ///
    /// The actual reading happens on a DEDICATED THREAD, and the caller waits
    /// on it with [`READ_UNTIL_TIMEOUT`] via `recv_timeout`: `Read::read` on a
    /// pseudo-terminal has no deadline of its own, so waiting on it directly
    /// here would have no way to fail fast if the marker never shows up and
    /// no EOF ever arrives either. Proven by mutation: swap the requested
    /// geometry back for the pseudo-terminal default -- the very regression
    /// this test exists to catch -- and without the thread-plus-timeout, the
    /// read blocks forever instead of the test failing. A thread still
    /// blocked past the deadline is leaked, which is fine for a test that is
    /// about to panic anyway.
    fn read_until(ch: &mut SpawnedChannel, needle: &str) -> String {
        let needle = needle.to_string();
        // A separate clone travels into the thread: the panics below still
        // need `needle` on THIS thread after the `recv_timeout`, including
        // in the timeout arm, which never gets anything back from the
        // (possibly still-running) thread at all.
        let needle_for_thread = needle.clone();
        // Move the real reader out of `ch` for the thread; every caller below
        // is done with `ch` once `read_until` returns, so the placeholder
        // (immediate EOF) left in its place is never observed.
        let mut reader = std::mem::replace(&mut ch.reader, Box::new(std::io::empty()));
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut seen = String::new();
            let mut buf = [0u8; 4096];
            for _ in 0..200 {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        seen.push_str(&String::from_utf8_lossy(&buf[..n]));
                        if seen.contains(&needle_for_thread) {
                            let _ = tx.send(Ok(seen));
                            return;
                        }
                    }
                    Err(_) => break,
                }
            }
            let _ = tx.send(Err(seen));
        });

        match rx.recv_timeout(READ_UNTIL_TIMEOUT) {
            Ok(Ok(seen)) => seen,
            Ok(Err(seen)) => panic!("never saw {needle:?}; what arrived was: {seen:?}"),
            Err(_) => panic!(
                "never saw {needle:?} within {READ_UNTIL_TIMEOUT:?}: the reading thread is \
                 still blocked rather than having given up -- exactly what a regression back to \
                 a fixed pseudo-terminal size looks like"
            ),
        }
    }

    /// Whose session asks: its uid owns the screen reservation.
    fn owner() -> Principal {
        Principal {
            uid: nix::unistd::Uid::current().as_raw(),
            name: "test".to_string(),
            identity: "test".to_string(),
            incarnation: 0,
        }
    }

    /// Which login asks: ignored by `PtyChannelSpawner` too, so any value
    /// will do.
    fn login() -> LoginId {
        [0u8; 16]
    }

    fn request(kind: ChannelKind, cols: u16, rows: u16, command: &[u8]) -> OpenRequest {
        OpenRequest {
            stream: 16,
            kind,
            cols,
            rows,
            screen: false,
            command: command.to_vec(),
        }
    }

    #[test]
    fn screen_budget_no_screen_and_failed_spawn_release_all_credits() {
        let budget = budget();
        let spawner = PtyChannelSpawner::new(budget.clone());
        let mut req = request(ChannelKind::Command, 2, 1, b"'");
        assert!(!make_screen(&req, &owner(), budget.clone())
            .unwrap()
            .has_screen());
        assert_eq!(budget.used(), crate::screen_budget::Usage::default());
        req.screen = true;
        assert!(spawner.spawn(&owner(), login(), &req, None).is_err());
        assert_eq!(
            budget.used(),
            crate::screen_budget::Usage::default(),
            "command parsing after admission failed"
        );
    }

    #[test]
    fn screen_budget_separate_spawners_and_uid_aliases_share_model_limits_before_spawn() {
        let budget = Arc::new(ScreenBudget::new(crate::screen_budget::BudgetLimits {
            owner_models: 1,
            global_models: 2,
            ..crate::screen_budget::BudgetLimits::default()
        }));
        let mut req = request(ChannelKind::Command, 2, 1, b"'");
        req.screen = true;
        let a = make_screen(&req, &owner(), budget.clone()).unwrap();
        let mut alias = owner();
        alias.name = "same-uid-alias".into();
        alias.identity = "other-key".into();
        let first = PtyChannelSpawner::new(budget.clone());
        let second = PtyChannelSpawner::new(budget.clone());
        for spawner in [&first, &second] {
            let reason = spawner.spawn(&alias, login(), &req, None).err().unwrap();
            assert!(
                reason.contains("owner terminal screen budget"),
                "refuse before command parsing / child: {reason}"
            );
        }
        alias.uid = alias.uid.wrapping_add(1);
        let b = make_screen(&req, &alias, budget.clone()).unwrap();
        alias.uid = alias.uid.wrapping_add(1);
        let reason = second.spawn(&alias, login(), &req, None).err().unwrap();
        assert!(reason.contains("global terminal screen budget"));
        drop((a, b));
        assert_eq!(budget.used(), crate::screen_budget::Usage::default());
    }

    /// A shell channel opens `$SHELL` at the size asked for, not at the
    /// pseudo-terminal default. Opening at 80x24 and resizing a moment later
    /// is what makes tmux reflow a pane and leave a blank line behind.
    #[test]
    fn a_shell_channel_opens_at_the_size_requested() {
        suppress_shell_history();
        let mut ch = spawner()
            .spawn(
                &owner(),
                login(),
                &request(ChannelKind::Shell, 100, 30, b""),
                None,
            )
            .expect("a shell channel must open");

        // `stty size` prints "rows cols" -- the shell's own view of its
        // terminal, which is the thing under test. The marker around it
        // keeps the answer apart from the prompt and from the echo of the
        // command itself.
        ch.writer
            .write_all(b"echo MARK-$(stty size | tr ' ' 'x')-MARK\n")
            .unwrap();
        ch.writer.flush().unwrap();
        let seen = read_until(&mut ch, "MARK-30x100-MARK");
        assert!(
            seen.contains("MARK-30x100-MARK"),
            "the shell must see the requested geometry, got: {seen:?}"
        );
    }

    /// A command channel runs the command, not the shell. The marker is
    /// computed by the command rather than written literally, so the echo of
    /// the request itself cannot make the test pass.
    #[test]
    fn a_command_channel_runs_the_command() {
        suppress_shell_history();
        let mut ch = spawner()
            .spawn(
                &owner(),
                login(),
                &request(ChannelKind::Command, 80, 24, b"sh -c 'echo ready-$((6*7))'"),
                None,
            )
            .expect("a command channel must open");

        let seen = read_until(&mut ch, "ready-42");
        assert!(seen.contains("ready-42"), "the command ran, got: {seen:?}");
    }

    /// A channel is not opened while a replacement's exec window is open:
    /// its process would inherit the descriptors the window makes
    /// inheritable. It opens once the window closes.
    #[test]
    fn a_channel_waits_for_the_exec_window() {
        // Serialised with the tests that look at the gate from outside.
        let _fds = crate::test_support::fd_flags_lock();
        suppress_shell_history();
        let window = crate::update::exec_window_for_test();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let ch = spawner().spawn(
                &owner(),
                login(),
                &request(ChannelKind::Command, 80, 24, b"sh -c 'echo ready-$((6*7))'"),
                None,
            );
            let _ = tx.send(ch);
        });
        assert!(
            rx.recv_timeout(Duration::from_millis(200)).is_err(),
            "held off while the window is open"
        );
        drop(window);
        let mut ch = rx
            .recv_timeout(READ_UNTIL_TIMEOUT)
            .expect("opened once the window closed")
            .expect("a command channel must open");
        let seen = read_until(&mut ch, "ready-42");
        assert!(seen.contains("ready-42"), "the command ran, got: {seen:?}");
    }

    /// The terminal type the client announced becomes the child's `TERM`.
    /// Without it every client is assumed to be the app's emulator, and a
    /// console client's Home key -- encoded by ITS terminal -- reaches a
    /// shell configured for a different one, does nothing, and leaves its
    /// trailing `~` in the line.
    #[test]
    fn the_announced_terminal_type_becomes_the_childs_term() {
        suppress_shell_history();
        let mut ch = spawner()
            .spawn(
                &owner(),
                login(),
                &request(ChannelKind::Command, 80, 24, b"sh -c 'echo T=$TERM'"),
                Some("rxvt-unicode-256color"),
            )
            .expect("a command channel must open");

        let seen = read_until(&mut ch, "T=");
        assert!(
            seen.contains("T=rxvt-unicode-256color"),
            "the child must see the announced terminal type, got: {seen:?}"
        );
    }

    /// A client that announced nothing still gets a terminal type: the
    /// daemon's own default, which is what every client got before the
    /// announcement existed.
    #[test]
    fn a_client_that_announced_nothing_gets_the_default_term() {
        suppress_shell_history();
        let mut ch = spawner()
            .spawn(
                &owner(),
                login(),
                &request(ChannelKind::Command, 80, 24, b"sh -c 'echo T=$TERM'"),
                None,
            )
            .expect("a command channel must open");

        let seen = read_until(&mut ch, "T=");
        assert!(
            seen.contains("T=xterm-256color"),
            "the default terminal type must still be set, got: {seen:?}"
        );
    }

    /// A request with no terminal is refused with a reason rather than
    /// silently getting the pseudo-terminal default: a channel that quietly
    /// gets 80x24 is exactly the bug this guards against.
    #[test]
    fn a_channel_without_a_terminal_is_refused_with_a_reason() {
        // `SpawnedChannel` holds trait objects (`Box<dyn Read + Send>` and
        // friends) that implement neither `Debug` nor `Clone`, so
        // `Result::expect_err` -- which needs the `Ok` side to be `Debug` for
        // its panic message -- cannot be used here; match instead.
        let err = match spawner().spawn(
            &owner(),
            login(),
            &request(ChannelKind::Shell, 0, 0, b""),
            None,
        ) {
            Err(reason) => reason,
            Ok(_) => panic!("a channel with no terminal must be refused"),
        };
        assert!(
            err.contains("without a terminal"),
            "the refusal must say what was wrong, got: {err:?}"
        );
    }

    /// A command line with no quoting splits on plain whitespace.
    #[test]
    fn command_builder_splits_on_whitespace() {
        let cmd = command_builder(b"tmux -C attach").expect("a plain command line parses");
        let mut expected = CommandBuilder::new("tmux");
        expected.arg("-C");
        expected.arg("attach");
        assert_eq!(cmd, expected);
    }

    /// Single quotes keep a space-containing argument together, and are
    /// themselves stripped from the result.
    #[test]
    fn command_builder_keeps_a_quoted_argument_together() {
        let cmd =
            command_builder(b"sh -c 'echo hello world'").expect("a quoted command line parses");
        let mut expected = CommandBuilder::new("sh");
        expected.arg("-c");
        expected.arg("echo hello world");
        assert_eq!(cmd, expected);
    }

    /// An unterminated quote is refused rather than silently closed at end
    /// of string -- a client that got the quoting wrong deserves to know.
    #[test]
    fn command_builder_refuses_an_unterminated_quote() {
        let err = command_builder(b"sh -c 'echo hello").expect_err("must be refused");
        assert!(
            err.contains("unterminated quote"),
            "the refusal must say what was wrong, got: {err:?}"
        );
    }

    /// An empty command line has no program to run.
    #[test]
    fn command_builder_refuses_an_empty_command() {
        let err = command_builder(b"").expect_err("must be refused");
        assert!(
            err.contains("empty command"),
            "the refusal must say what was wrong, got: {err:?}"
        );
    }

    /// The command line arrives over the wire -- from a peer already
    /// authenticated, but untrusted content all the same -- so it is not
    /// guaranteed to be valid UTF-8. Refused with a reason rather than
    /// panicking on the `str::from_utf8` call or silently lossy-decoding
    /// bytes into a program name nobody asked to run.
    #[test]
    fn command_builder_refuses_invalid_utf8() {
        let err = command_builder(&[0xFF, 0xFE, b's', b'h']).expect_err("must be refused");
        assert!(
            err.contains("UTF-8"),
            "the refusal must say what was wrong, got: {err:?}"
        );
    }

    /// Spec §4.10.3: the channel runner reports every byte it takes, so the
    /// bridge counts this backend by its reports.
    #[test]
    fn the_channel_backend_reports_what_it_takes() {
        use transport::session_manager::SessionBackend;
        assert_eq!(
            ChannelSessionBackend::new(budget()).consumption(),
            transport::conn::Consumption::Explicit
        );
    }
}
