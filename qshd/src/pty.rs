//! Launching a shell in a pseudo-terminal (PTY) via the `portable-pty` crate.
//!
//! The shell is taken from the `$SHELL` environment variable; if it is not
//! set, `/bin/sh` is used. The PTY gives the shell process the experience
//! of a real terminal (control sequences, window size, etc.) -- the same
//! thing an SSH server does on interactive login. Byte exchange with the
//! PTY master side (`master`, see [`spawn_shell`]) is synchronous/blocking
//! -- `session.rs` builds the bridge to the async QUIC stream.

use anyhow::{Context, Result};
use nix::sys::termios::{self, LocalFlags, SetArg};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::os::fd::BorrowedFd;
use std::sync::OnceLock;

/// Fallback pseudo-terminal size for a caller with no real size to open at
/// yet (rows by columns). `main.rs` (the binary crate, a separate crate from
/// this library one) passes it explicitly wherever it used to be implicit,
/// so this has to be `pub`, not merely `pub(crate)`. Where a real size IS
/// known -- a channel's `OpenRequest` -- it is used instead, right from the
/// first frame: see `channel_backend`'s module docs for why that matters.
pub const DEFAULT_PTY_SIZE: PtySize = PtySize {
    rows: 24,
    cols: 80,
    pixel_width: 0,
    pixel_height: 0,
};

/// Terminal type for programs running on the server (`tmux`, `vim`, claude
/// code). Without it `tmux attach` fails with "open terminal failed:
/// terminal does not support clear": the daemon's environment has no
/// `TERM` set. In SSH the terminal type comes from the client via
/// `pty-req`, but qsh has no such negotiation -- so we set it to match the
/// client's emulator (a Termux fork -- `xterm-256color`; a terminfo entry
/// for it exists on any host with tmux).
pub(crate) const TERM_VALUE: &str = "xterm-256color";

/// Preferred character-classification (`LC_CTYPE`) locales, in the order
/// they are tried, spelled the way [`normalize_locale`] compares them.
/// `C.UTF-8` comes first: it carries no regional baggage -- messages stay
/// English, sorting stays byte order -- and UTF-8 character handling is
/// the only thing we actually want out of it. `en_US.UTF-8` is next
/// because it exists on far more hosts than any other regional locale.
const PREFERRED_UTF8_LOCALES: [&str; 2] = ["c.utf8", "en_us.utf8"];

/// Lowercases a locale name and drops the dash in the encoding part, so
/// the two spellings of one and the same locale compare equal: `locale -a`
/// reports `C.utf8`, while the conventional way to write it into the
/// environment is `C.UTF-8`.
fn normalize_locale(name: &str) -> String {
    name.to_ascii_lowercase().replace('-', "")
}

/// Whether a locale name means UTF-8 character handling. Deliberately as
/// lax as tmux's own check (`strcasestr` for "UTF-8" or "UTF8"), so
/// suffixed names like `en_US.UTF-8@euro` count too.
fn locale_is_utf8(name: &str) -> bool {
    normalize_locale(name).contains("utf8")
}

/// Whether the environment ALREADY gives programs UTF-8 character
/// handling -- decided exactly the way the tmux client decides it
/// (`client.c`): the first NON-EMPTY of `LC_ALL`, `LC_CTYPE`, `LANG` wins
/// on its own, and the rest are never consulted.
///
/// This is the whole reason one host rendered Cyrillic and another
/// rendered underscores: `qshd` is installed over a NON-INTERACTIVE ssh
/// exec, which reads no login profile, and the app sends no environment of
/// its own -- so on a host where the locale comes from `/etc/profile`
/// rather than `/etc/environment`, the daemon (and every tmux client it
/// spawns) inherits none, and tmux then prints `_` for every cell it will
/// not claim to render.
fn env_ctype_is_utf8(lc_all: Option<&str>, lc_ctype: Option<&str>, lang: Option<&str>) -> bool {
    [lc_all, lc_ctype, lang]
        .into_iter()
        .flatten()
        .find(|value| !value.is_empty())
        .is_some_and(locale_is_utf8)
}

/// Which variable carries the chosen locale to a child process.
/// `LC_ALL` overrides every other locale variable, so on a host that
/// exports a non-UTF-8 `LC_ALL` setting `LC_CTYPE` would be silently
/// inert -- there the only way to get UTF-8 character handling is to
/// override `LC_ALL` itself. Everywhere else the narrower `LC_CTYPE` is
/// used, leaving message language, collation and date format alone.
fn ctype_env_var(lc_all: Option<&str>) -> &'static str {
    match lc_all {
        Some(value) if !value.is_empty() => "LC_ALL",
        _ => "LC_CTYPE",
    }
}

/// Picks the locale to hand child processes out of what `locale -a`
/// reported: [`PREFERRED_UTF8_LOCALES`] in order, then any UTF-8 locale at
/// all. Returns the name EXACTLY as the system spelled it -- only that
/// spelling is guaranteed to exist here -- or `None` when the host has no
/// UTF-8 locale, in which case nothing is set: an unusable `LC_CTYPE`
/// makes perl and friends print a warning block on every single launch.
fn pick_utf8_locale(available: &[String]) -> Option<String> {
    let utf8: Vec<&String> = available
        .iter()
        .filter(|name| locale_is_utf8(name))
        .collect();

    for preferred in PREFERRED_UTF8_LOCALES {
        if let Some(found) = utf8.iter().find(|name| normalize_locale(name) == preferred) {
            return Some((*found).clone());
        }
    }

    utf8.first().map(|name| (*name).clone())
}

/// The system's locale list (`locale -a`). Any failure -- no `locale`
/// binary, a non-zero exit -- comes back as an empty list, and the daemon
/// then sets no locale at all: exactly the behavior that existed before
/// this was added.
fn system_locales() -> Vec<String> {
    let Ok(output) = std::process::Command::new("locale").arg("-a").output() else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|line| !line.is_empty())
        .collect()
}

/// The locale variable and value for child processes -- ready to hand to
/// `Command::envs` -- or `None` when nothing is needed: either the
/// daemon's own environment already means UTF-8, or the host has no UTF-8
/// locale to offer. Which variable it is, is [`ctype_env_var`]'s call.
/// Computed once (`locale -a` costs a process spawn) and reused by every
/// PTY afterwards.
pub(crate) fn utf8_locale_env() -> Option<(&'static str, &'static str)> {
    static RESOLVED: OnceLock<Option<(&'static str, String)>> = OnceLock::new();

    RESOLVED
        .get_or_init(|| {
            let lc_all = std::env::var("LC_ALL").ok();
            let lc_ctype = std::env::var("LC_CTYPE").ok();
            let lang = std::env::var("LANG").ok();
            if env_ctype_is_utf8(lc_all.as_deref(), lc_ctype.as_deref(), lang.as_deref()) {
                return None;
            }
            let locale = pick_utf8_locale(&system_locales())?;
            Some((ctype_env_var(lc_all.as_deref()), locale))
        })
        .as_ref()
        .map(|(var, locale)| (*var, locale.as_str()))
}

/// The locale variable and value for a child whose environment is built
/// from nothing rather than inherited from the daemon's -- as the system
/// mode's helper builds every channel's (`helper::server::child_env`).
///
/// [`utf8_locale_env`] answers `None` when the daemon's own environment
/// already means UTF-8, because a child that inherits that environment
/// needs nothing more. A child that inherits NOTHING would then get no
/// locale at all -- and a daemon started by systemd is exactly that case,
/// since systemd hands its services the machine's `LANG`. So such a child is
/// given a UTF-8 locale all the same -- see [`fresh_locale`] for which
/// variable and why never `LC_ALL`.
///
/// Runs no program of its own: it reads the daemon's locale variables and
/// `utf8_locale_env`'s memoized answer, which the system mode resolves
/// before it splits (`serve.rs`), so the helper never runs `locale -a`.
#[cfg(feature = "system")]
pub(crate) fn utf8_locale_for_fresh_env() -> Option<(&'static str, String)> {
    let lc_all = std::env::var("LC_ALL").ok();
    let lc_ctype = std::env::var("LC_CTYPE").ok();
    let lang = std::env::var("LANG").ok();
    fresh_locale(
        utf8_locale_env().map(|(_, locale)| locale.to_string()),
        lc_all.as_deref(),
        lc_ctype.as_deref(),
        lang.as_deref(),
    )
}

/// Decide the one locale variable a freshly built environment gets, pure so
/// it can be tested without touching the process environment.
///
/// `picked` is [`utf8_locale_env`]'s value: `Some` when the daemon's own
/// environment was NOT UTF-8 and it chose one from `locale -a`, `None`
/// otherwise. The three arguments after it are the daemon's own locale
/// variables.
///
/// Never `LC_ALL`, whichever branch (M6): a fresh environment has nothing to
/// override, and `LC_ALL` would override the account's OWN `LANG`/`LC_*` --
/// set in `~/.profile`, say -- for every category, for good. A `locale -a`
/// pick is handed on as `LC_CTYPE` (character handling is all it is for); an
/// inherited UTF-8 value is handed on as `LANG` (the widest but still
/// overridable variable), so the account can still narrow any category it
/// likes.
#[cfg(feature = "system")]
fn fresh_locale(
    picked: Option<String>,
    lc_all: Option<&str>,
    lc_ctype: Option<&str>,
    lang: Option<&str>,
) -> Option<(&'static str, String)> {
    if let Some(locale) = picked {
        return Some(("LC_CTYPE", locale));
    }
    utf8_env_var(lc_all, lc_ctype, lang).map(|(_var, value)| ("LANG", value))
}

/// The variable that makes the environment mean UTF-8, with its value --
/// the first non-empty of `LC_ALL`, `LC_CTYPE`, `LANG`, the precedence
/// [`env_ctype_is_utf8`] follows -- or `None` when that one does not mean
/// UTF-8, or none is set.
#[cfg(feature = "system")]
fn utf8_env_var(
    lc_all: Option<&str>,
    lc_ctype: Option<&str>,
    lang: Option<&str>,
) -> Option<(&'static str, String)> {
    [("LC_ALL", lc_all), ("LC_CTYPE", lc_ctype), ("LANG", lang)]
        .into_iter()
        .find_map(|(var, value)| value.filter(|v| !v.is_empty()).map(|v| (var, v)))
        .filter(|(_, value)| locale_is_utf8(value))
        .map(|(var, value)| (var, value.to_string()))
}

/// What every PTY child gets on top of the environment it inherits from
/// the daemon: the terminal type and, when the daemon's own environment
/// lacks it, a UTF-8 locale (see [`utf8_locale_env`]). `LANG` is never
/// touched: character handling is all we need here -- the language of
/// messages, the sorting order and the date format stay whatever the host
/// chose.
///
/// `term` is what the client announced about its own emulator; [`TERM_VALUE`]
/// stands in when it announced nothing. Getting this wrong is not cosmetic:
/// a client whose Home key is `\e[1~` talking to a shell configured for
/// `\eOH` gets no Home at all, and the trailing `~` lands in the line.
fn apply_base_env(cmd: &mut CommandBuilder, term: Option<&str>) {
    cmd.env("TERM", term.unwrap_or(TERM_VALUE));
    if let Some((var, locale)) = utf8_locale_env() {
        cmd.env(var, locale);
    }
}

/// Launches `$SHELL` (or `/bin/sh` if the variable is not set) in a new
/// pseudo-terminal of `size` and returns the PTY master side (`master`)
/// along with a handle to the child process.
///
/// The pseudo-terminal opens at `size` from the very first frame: it used to
/// always open at [`DEFAULT_PTY_SIZE`] and rely on a resize landing a moment
/// later, which is exactly the "80x24 then the real size" cycle that makes
/// tmux reflow a pane and leave a blank line behind (see the channels design
/// doc). Callers that have no real size yet pass `DEFAULT_PTY_SIZE`
/// themselves, which keeps their own behavior unchanged.
///
/// The `PtyPair` slave side is deliberately not returned -- the caller has
/// no use for it: by the time `spawn_command` returns, the child process
/// has already inherited its file descriptors, and all further byte
/// exchange goes through the master side (`try_clone_reader`/`take_writer`).
pub fn spawn_shell(
    size: PtySize,
    term: Option<&str>,
) -> Result<(Box<dyn MasterPty + Send>, Box<dyn Child + Send + Sync>)> {
    let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(size)
        .context("opening the pseudo-terminal")?;

    let mut cmd = CommandBuilder::new(&shell);
    apply_base_env(&mut cmd, term);
    let child = pair
        .slave
        .spawn_command(cmd)
        .with_context(|| format!("starting the shell {shell}"))?;

    // `slave` is only needed for the duration of spawn_command -- the
    // child process has already inherited its descriptors, no need to
    // keep the Box around after that.
    drop(pair.slave);

    Ok((pair.master, child))
}

/// Launches an arbitrary command in a new pseudo-terminal with echo
/// DISABLED on the PTY master side -- needed for the TMUXC stream (`tmux -C
/// attach`): the tmux control-mode client decides for itself what to show
/// on screen, and must not get back what it wrote to the stream itself
/// (the PTY line discipline reflects input to output by default, as in a
/// normal terminal).
///
/// Otherwise built like [`spawn_shell`]: opens at `size` (see that
/// function's docs for why), returns the PTY master side and a handle to the
/// child process, does not hand back the slave side -- further exchange
/// only goes through the master.
pub fn spawn_command_no_echo(
    size: PtySize,
    mut cmd: CommandBuilder,
    term: Option<&str>,
) -> Result<(Box<dyn MasterPty + Send>, Box<dyn Child + Send + Sync>)> {
    apply_base_env(&mut cmd, term);

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(size)
        .context("opening the pseudo-terminal")?;

    disable_echo(pair.master.as_ref()).context("disabling echo on the PTY master side")?;

    let child = pair
        .slave
        .spawn_command(cmd)
        .context("starting the command in the PTY")?;

    // `slave` is only needed for the duration of spawn_command -- see spawn_shell.
    drop(pair.slave);

    Ok((pair.master, child))
}

/// Launches an arbitrary command in a new pseudo-terminal with the DEFAULT
/// echo setting LEFT ON -- needed for channel A of the tmux hybrid (`tmux
/// new-session -A -s <name>`): unlike [`spawn_command_no_echo`], here the
/// line discipline's echo is NOT touched -- `tmux` puts its own PTY into
/// raw mode (the way full-screen programs like `vim` do), so kernel echo
/// neither gets in its way nor is needed.
///
/// Otherwise built like [`spawn_shell`], but the command is supplied by the
/// caller rather than taken from `$SHELL`, and opens at `size` (see
/// `spawn_shell`'s docs for why).
pub fn spawn_command(
    size: PtySize,
    mut cmd: CommandBuilder,
    term: Option<&str>,
) -> Result<(Box<dyn MasterPty + Send>, Box<dyn Child + Send + Sync>)> {
    apply_base_env(&mut cmd, term);

    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(size)
        .context("opening the pseudo-terminal")?;

    let child = pair
        .slave
        .spawn_command(cmd)
        .context("starting the command in the PTY")?;

    // `slave` is only needed for the duration of spawn_command -- see spawn_shell.
    drop(pair.slave);

    Ok((pair.master, child))
}

/// Clears the `ECHO`/`ECHONL` flags in the PTY master side's termios. The
/// line discipline is shared kernel state for both sides of a single PTY,
/// so changing it via the master side also disables echo for the slave
/// (the one the child process sees) -- the same trick system programs
/// (e.g. password prompts) use to hide typed characters.
///
/// `portable-pty` does not expose a termios API directly -- only the
/// master side's raw file descriptor via [`MasterPty::as_raw_fd`]; termios
/// is read and written on top of it via the `nix` crate.
fn disable_echo(master: &(dyn MasterPty + Send)) -> Result<()> {
    let fd = master
        .as_raw_fd()
        .context("the PTY master side does not hand over a file descriptor")?;
    // SAFETY: the descriptor belongs to `master` and lives at least until
    // the end of this function (`master` itself is not dropped earlier) --
    // we borrow it for the duration of the termios calls without taking
    // ownership.
    let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };

    let mut attrs =
        termios::tcgetattr(borrowed).context("reading the PTY master side's termios")?;
    attrs
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHONL);
    termios::tcsetattr(borrowed, SetArg::TCSANOW, &attrs)
        .context("writing the PTY master side's termios")?;

    Ok(())
}

/// A resize handle for the PTY built on top of the master side (`master`),
/// implementing [`transport::shell_server::ResizeHandle`]. This lets the
/// transport's async loop (`serve_shell`) resize the PTY without depending
/// on `portable-pty` (otherwise there would be a circular dependency:
/// transport crate -> qshd). The PTY is set up here, in qshd, and the
/// transport is handed a ready-made handle.
pub struct PtyResizeHandle {
    master: Box<dyn MasterPty + Send>,
}

impl PtyResizeHandle {
    /// Wrap the PTY master side in a resize handle. `master` is taken after
    /// `try_clone_reader`/`take_writer` -- those borrow `&self` and do not
    /// consume `master` itself, so it can be handed over here whole.
    pub fn new(master: Box<dyn MasterPty + Send>) -> Self {
        PtyResizeHandle { master }
    }
}

impl transport::shell_server::ResizeHandle for PtyResizeHandle {
    fn try_resize(&self, cols: u16, rows: u16) -> Result<(), String> {
        terminal_size::TerminalSize::new(cols, rows).map_err(|e| e.to_string())?;
        self.master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| format!("resizing the terminal: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::{spawn_command_no_echo, spawn_shell, DEFAULT_PTY_SIZE};
    use crate::test_support::suppress_shell_history;
    use portable_pty::CommandBuilder;
    use std::io::{Read, Write};
    use std::time::Duration;

    /// `spawn_shell()` brings up a shell in a PTY; a command written to the
    /// PTY master side reaches the shell, and its output comes back through
    /// the master side. The full QUIC+PTY exchange is device-gated; this
    /// only checks the bare fact that the PTY starts up and
    /// relays data.
    #[test]
    fn shell_echoes_command_output() {
        // See `test_support::suppress_shell_history`: `spawn_shell` below
        // launches the invoking user's REAL `$SHELL`, which is interactive
        // (it's attached to a PTY) and would append to that user's own
        // `~/.bash_history` on exit if `HISTFILE` were left unset. Shared,
        // not a call local to this module, because `cargo test -p qshd
        // --lib` runs this crate's modules -- this one included -- as
        // concurrent tests in one process.
        suppress_shell_history();
        let (master, mut child) =
            spawn_shell(DEFAULT_PTY_SIZE, None).expect("shell started in the PTY");

        let mut writer = master
            .take_writer()
            .expect("PTY master side's writer obtained");
        writer
            .write_all(b"echo qsh-ok\n")
            .expect("command written to the PTY");
        drop(writer);

        let mut reader = master
            .try_clone_reader()
            .expect("PTY master side's reader clones");

        // The shell does not exit on its own, and reading from the PTY is
        // blocking and won't yield EOF while it's alive. Read on a
        // separate thread and wait for the result with a timeout, so the
        // test doesn't hang if something goes wrong.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut collected = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        collected.extend_from_slice(&buf[..n]);
                        if String::from_utf8_lossy(&collected).contains("qsh-ok") {
                            let _ = tx.send(collected.clone());
                            break;
                        }
                    }
                }
            }
        });

        let output = rx
            .recv_timeout(Duration::from_secs(10))
            .expect("PTY output received within the allotted time");
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("qsh-ok"),
            "PTY output must contain 'qsh-ok', got: {text:?}"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    /// `spawn_command_no_echo()` disables echo on the PTY master side: what
    /// is written to it does NOT come back on the same read -- unlike a
    /// regular PTY (see `shell_echoes_command_output` above, where the
    /// output does contain the written command -- there the shell itself
    /// prints it via `echo`, but PTY echo is also on by default).
    ///
    /// The test command is `sleep`: it doesn't read stdin and doesn't
    /// print anything on its own, so the only possible source of bytes on
    /// the PTY master side is exactly the line discipline's echo, if it
    /// isn't disabled. `cat` wouldn't work for this: it copies stdin to
    /// stdout on its own, independent of the PTY's echo state, so the
    /// test wouldn't prove anything.
    #[test]
    fn no_echo_disables_local_echo() {
        let mut cmd = CommandBuilder::new("sleep");
        cmd.arg("2");
        let (master, mut child) = spawn_command_no_echo(DEFAULT_PTY_SIZE, cmd, None)
            .expect("command started in the PTY without echo");

        let mut writer = master
            .take_writer()
            .expect("PTY master side's writer obtained");
        writer
            .write_all(b"no-echo-check\n")
            .expect("line written to the PTY master side");
        drop(writer);

        let mut reader = master
            .try_clone_reader()
            .expect("PTY master side's reader clones");

        // Read on a separate thread: `read()` is blocking and, if echo is
        // truly disabled, will return nothing while `sleep` is alive. For
        // this test that's exactly the expected outcome -- a short
        // timeout for receiving the result instead of waiting for EOF.
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut buf = [0u8; 256];
            let result = reader.read(&mut buf).map(|n| buf[..n].to_vec());
            let _ = tx.send(result);
        });

        match rx.recv_timeout(Duration::from_millis(300)) {
            Err(_) => {
                // Timeout -- nothing arrived from the PTY in the allotted
                // time: echo is indeed disabled, this is the test's
                // successful outcome.
            }
            Ok(Ok(bytes)) => panic!(
                "echo must be disabled, but bytes arrived from the PTY master side: {:?}",
                String::from_utf8_lossy(&bytes)
            ),
            Ok(Err(e)) => panic!("reading the PTY master side failed: {e}"),
        }

        let _ = child.kill();
        let _ = child.wait();
    }
}

#[cfg(test)]
mod locale_tests {
    use super::{ctype_env_var, env_ctype_is_utf8, pick_utf8_locale};

    fn names(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    /// `locale -a` prints names in normalized form (`C.utf8`, not
    /// `C.UTF-8`), so the choice must be spelling-insensitive -- but the
    /// value handed to the child process must be the EXACT string the
    /// system reported, not a reconstructed one: only that spelling is
    /// guaranteed to exist on this host.
    #[test]
    fn picks_c_utf8_first_and_keeps_the_system_spelling() {
        let available = names(&["C", "C.utf8", "en_US.utf8", "ru_RU.utf8"]);
        assert_eq!(pick_utf8_locale(&available).as_deref(), Some("C.utf8"));

        let dashed = names(&["ru_RU.UTF-8", "C.UTF-8"]);
        assert_eq!(pick_utf8_locale(&dashed).as_deref(), Some("C.UTF-8"));
    }

    /// Without `C.*`, `en_US` is the next preference -- it exists on far
    /// more hosts than any other regional locale.
    #[test]
    fn falls_back_to_en_us_then_to_any_utf8() {
        let with_en = names(&["POSIX", "ru_RU.utf8", "en_US.utf8"]);
        assert_eq!(pick_utf8_locale(&with_en).as_deref(), Some("en_US.utf8"));

        let regional_only = names(&["POSIX", "ru_RU.utf8"]);
        assert_eq!(
            pick_utf8_locale(&regional_only).as_deref(),
            Some("ru_RU.utf8")
        );
    }

    /// A host with no UTF-8 locale at all gets NOTHING set: forcing a
    /// missing locale makes perl and friends print "Setting locale failed"
    /// on every single launch -- worse than the underscores we're curing.
    #[test]
    fn picks_nothing_when_the_host_has_no_utf8_locale() {
        let available = names(&["C", "POSIX", "en_US.iso88591"]);
        assert_eq!(pick_utf8_locale(&available), None);
    }

    /// `LC_ALL` overrides `LC_CTYPE` for every category, so on a host that
    /// exports a non-UTF-8 `LC_ALL` setting `LC_CTYPE` would be silently
    /// inert -- the only variable that takes effect there is `LC_ALL`
    /// itself.
    #[test]
    fn overrides_lc_all_when_it_is_the_one_in_charge() {
        assert_eq!(ctype_env_var(Some("C")), "LC_ALL");
        assert_eq!(ctype_env_var(Some("")), "LC_CTYPE");
        assert_eq!(ctype_env_var(None), "LC_CTYPE");
    }

    /// The environment check mirrors tmux's own precedence (`client.c`):
    /// the FIRST non-empty of `LC_ALL`, `LC_CTYPE`, `LANG` decides, and
    /// the ones after it are not consulted at all.
    #[test]
    fn env_check_follows_tmux_precedence() {
        // LC_ALL wins even when a UTF-8 LC_CTYPE follows it.
        assert!(!env_ctype_is_utf8(
            Some("C"),
            Some("en_US.UTF-8"),
            Some("en_US.UTF-8")
        ));
        assert!(env_ctype_is_utf8(Some("C.UTF-8"), None, None));
        assert!(env_ctype_is_utf8(None, Some("C.utf8"), Some("C")));
        assert!(env_ctype_is_utf8(None, None, Some("en_US.UTF-8")));
        // An empty variable counts as unset -- that is how tmux reads it.
        assert!(env_ctype_is_utf8(Some(""), Some(""), Some("ru_RU.utf8")));
        // Nothing set at all: exactly the daemon's case on the bad host.
        assert!(!env_ctype_is_utf8(None, None, None));
    }

    /// A freshly built environment is handed exactly one UTF-8 locale
    /// variable, and NEVER `LC_ALL` (M6): a `locale -a` pick goes on as
    /// `LC_CTYPE`, an inherited value as `LANG` -- even when the daemon's own
    /// UTF-8 came from `LC_ALL` -- so the account can still narrow any
    /// category, and nothing when there is no UTF-8 locale to hand on.
    #[cfg(feature = "system")]
    #[test]
    fn a_fresh_environment_gets_a_narrow_utf8_locale_never_lc_all() {
        use super::fresh_locale;
        // A locale -a pick (daemon env was not UTF-8): LC_CTYPE, not LC_ALL.
        assert_eq!(
            fresh_locale(Some("C.UTF-8".to_string()), Some("C"), None, None),
            Some(("LC_CTYPE", "C.UTF-8".to_string())),
            "a locale -a pick must be handed on as LC_CTYPE, never LC_ALL"
        );
        // systemd's case: inherited LANG, already UTF-8.
        assert_eq!(
            fresh_locale(None, None, None, Some("en_US.UTF-8")),
            Some(("LANG", "en_US.UTF-8".to_string()))
        );
        // The daemon's UTF-8 came from LC_ALL -- still handed on as LANG, so
        // it does not override the account's own settings.
        assert_eq!(
            fresh_locale(None, Some("C.UTF-8"), Some("C"), None),
            Some(("LANG", "C.UTF-8".to_string())),
            "an inherited LC_ALL must be handed on as LANG, never LC_ALL"
        );
        // LC_ALL decides and is not UTF-8: nothing.
        assert_eq!(
            fresh_locale(None, Some("C"), None, Some("en_US.UTF-8")),
            None
        );
        // Nothing to hand on.
        assert_eq!(fresh_locale(None, None, None, None), None);
    }
}
