//! Command-line arguments. Kept apart from `main` so the whole surface is
//! testable without a process: parsing is the one place where a mistake
//! greets the user before anything else does.

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

use crate::knock_spec;

/// The default qsh port, matching what `qshd serve` binds.
pub const DEFAULT_PORT: u16 = 60022;
/// The port `--ssh` and the `ssh` setting mean when none is written.
pub const DEFAULT_SSH_PORT: u16 = 22;
/// How many addresses one command line may name.
pub const MAX_ADDRESSES: usize = 8;

pub const USAGE: &str = "\
qsh -- a terminal over the qsh transport

Usage:
    qsh [OPTIONS] ADDRESS [ADDRESS ...]

    ADDRESS is [user@]host[:port][,SETTING ...], for example
        qsh alice@home.example,ssh=2222,knock=tcp:7000+udp:8000 10.8.0.1,ssh

qsh runs over IPv4 only, and so does qshd: a host name is reached at its
IPv4 address. An IPv6 address goes in brackets, quoted for the shell
('[2001:db8::1]:60022,ssh'), but carries no session: the ssh login and
the knock get through over it, the qsh login does not.

The addresses are other ways to reach the same daemon, tried left to right;
once a session runs, the rest are kept as backup paths. Up to 8 may be
named; a ninth is an error. At each address qsh logs in directly first; if
that gets no answer or no key is taken and the address has ssh, it knocks,
logs in over ssh, starts the qshd installed there with this run's key and
logs in over qsh again on the port qshd reports. Progress goes to stderr,
questions to the terminal.

`user@` names the account to claim, for qsh and ssh alike. Without one,
-l USER is used, then the local account name. Every address that names an
account must name the same one.

Address settings:
    ssh, ssh=N            this address can be reached over ssh (port 22 or N)
    nossh                 no ssh for this address, whatever --ssh says
    knock=STEPS           knock before ssh, instead of --knock
    noknock               no knock for this address, whatever --knock says

Knock steps look like tcp:7000+200ms+udp:8000:data: a step is tcp:PORT or
udp:PORT[:DATA] (DATA is text without + or commas, or 0x and hex digits),
and a pause such as 200ms or 1s waits after the step before it. A knock is
only used before ssh. Its data is never printed or logged: qsh only says
how many steps it has.

Options:
    -l USER               account to claim when no address names one
    -p, --port N          qsh port for addresses that name none (default 60022)
    --ssh, --ssh=N        every address without its own ssh setting has ssh
                          (write the port joined: --ssh=2222)
    --knock STEPS         knock before ssh for every address that has ssh
                          and no knock setting of its own
    -i, --identity PATH   qsh signs with this key only; ssh tries it first
    --authorize-ssh       explicitly authorize SSH recovery for this QSH server
    --no-password         never ask for a password or a passphrase
    --predict MODE        adaptive | always | never (default adaptive)
    --escape ^X|none      the prefix key for the commands below (default
                          ^], Ctrl-]); ^X is any of ^@ to ^_, none turns
                          the commands off. A prefix is not sent to the
                          shell on its own: ^[ (Esc) or ^M (Enter) would
                          swallow that key, so pick another
    --status on|off       the status line on the top row (default on)
    --history N           retain N lines of history (default 10000; 0 disables it)
    --verbose             more detail in the log (see below)
    -h, --help            this help
    -V, --version         version, license and where the source lives

Keys, once the session runs (the prefix is Ctrl-] unless --escape says
otherwise):
    Ctrl-] .              leave; the session stays on the server, and the
                          same qsh command run again returns to it (it
                          is found by the first address named)
    Ctrl-] s              connection state: every address and how it is
                          doing; arrows or 1-8 pick one, Enter moves the
                          session to a live spare, Esc or q closes it
    Ctrl-] h              hide or show the status line
    Ctrl-] r              reconnect now
    Ctrl-] [              scroll history: arrows move a line, PgUp/PgDn a page,
                          Home/End or g/G the ends; q or Esc returns live
    Ctrl-] ?              these keys
    Ctrl-] Ctrl-]         send one Ctrl-]
    After the prefix any other key is swallowed together with it.

The status line takes the top row, and the shell gets one row less: on the
left the prefix and ? for the keys, on the right the address in use (when
several are named) and the latency -- or, on red, how long the link has
been silent, where it is reconnecting to, or when the next attempt is.

When the link dies (the transport gives up on it after 45 s of silence),
qsh returns to the same session by itself: it walks the addresses again in
the background, the one that last worked first, and asks nothing -- an
address that would need a question is skipped. A round that gets nowhere is
tried again after 1, 2, 4, 8, 16, then every 30 s, until the session is
back or you leave. Ctrl-] r starts a round at once, and over a link that
still works it lets that link go first. The status line says what is going
on; with --status off, a plate on the top row does. After the expected server
confirms session loss, qsh restores the terminal and asks whether to start a
new session. The default is Yes; Enter, yes, or y starts a fresh shell.

Every run is logged to ~/.cache/qsh/log on Linux and macOS (or
$XDG_CACHE_HOME/qsh/log), one line per record: the time in UTC, the process
id, the level and the part of qsh it comes from. Past 1 MiB it moves to log.1. A knock's
ports and data, passwords, passphrases and keys are never written.

Exit codes (when the shell on the server exits, qsh exits with its code):
    1    the qsh server's key was declined, or the session could not start;
         also leaving with Ctrl-] . (the session stays on the server)
    2    the command line is wrong
    10   the keys to log in with could not be loaded
    11   the qsh server's key has changed (at login or on a reconnect)
    12   every address failed (each one is listed with why)
    13   the server session is gone and a new session was not confirmed
";

/// Printed by `--version`. The source link is not decoration: section 13 of
/// the AGPL expects a program people reach over a network to tell them where
/// its source lives.
pub const VERSION_TEXT: &str = concat!(
    "qsh ",
    env!("CARGO_PKG_VERSION"),
    "\nAGPL-3.0-only, source: https://github.com/br0adcast/qsh\n",
    "This program comes with absolutely no warranty.\n"
);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PredictMode {
    Adaptive,
    Always,
    Never,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Args {
    /// The account being claimed: named by `user@` on an address, by `-l`,
    /// or the local account. What the client will hand the signer, and what
    /// the server checks against `authorized_keys`.
    pub login: String,
    /// 1..=MAX_ADDRESSES, in the order they are tried.
    pub addresses: Vec<connect::Address>,
    pub identity: Option<PathBuf>,
    /// `--no-password`: never ask for a password or a passphrase.
    pub no_password: bool,
    /// Explicit foreground setup of SSH recovery bindings.
    pub authorize_ssh: bool,
    pub predict: PredictMode,
    /// `--escape`: the key that starts a client command.
    pub escape: crate::escape::Prefix,
    /// `--status on|off`: whether the status line is shown at the start.
    pub status_line: bool,
    pub history: usize,
    pub verbose: bool,
}

/// Everything that can be wrong with a command line, as the user will read
/// it. Exit code 2 is the caller's job -- see `main`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ArgError {
    InvalidUtf8 {
        argument: usize,
    },
    NoHost,
    AuthorizationNeedsSsh,
    MissingValue(String),
    BadPort(String),
    BadPredict(String),
    BadEscape(String),
    BadStatus(String),
    BadHistory(String),
    UnknownFlag(String),
    /// Two addresses named different accounts.
    ConflictingLogin {
        first: String,
        second: String,
    },
    /// No `user@` given and the environment names nobody.
    NoLogin,
    /// More than `MAX_ADDRESSES` addresses.
    TooManyAddresses,
    /// `index` counts from 1; `host` is what could be read of the host,
    /// never the settings.
    BadAddress {
        index: usize,
        host: String,
        what: String,
    },
    /// The `--knock` flag.
    BadKnock {
        what: String,
    },
    /// `--help`: not a failure, but it ends the program the same way.
    HelpRequested,
    /// `--version`: like `--help`, an early exit rather than a failure.
    VersionRequested,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArgError::InvalidUtf8 { argument } => {
                write!(f, "argument {argument} must be valid UTF-8")
            }
            ArgError::AuthorizationNeedsSsh => write!(f, "--authorize-ssh requires an SSH address"),
            ArgError::NoHost => write!(f, "no server address given"),
            ArgError::MissingValue(flag) => write!(f, "option {flag} needs a value"),
            ArgError::BadPort(v) => write!(f, "port must be a number 1..65535, got {v:?}"),
            ArgError::BadPredict(v) => {
                write!(f, "--predict must be adaptive, always or never, got {v:?}")
            }
            ArgError::BadEscape(what) => write!(f, "--escape: {what}"),
            ArgError::BadStatus(v) => write!(f, "--status: expected on or off, not {v:?}"),
            ArgError::BadHistory(v) => {
                write!(f, "--history: expected a nonnegative number, not {v:?}")
            }
            ArgError::UnknownFlag(v) => write!(f, "unknown option {v}"),
            ArgError::ConflictingLogin { first, second } => write!(
                f,
                "addresses name different accounts ({first} and {second}); every address \
                 leads to the same daemon, so there is only one account to claim"
            ),
            ArgError::NoLogin => write!(
                f,
                "no account named, and the environment names nobody either; say who: qsh alice@host"
            ),
            ArgError::TooManyAddresses => write!(f, "at most {MAX_ADDRESSES} addresses"),
            ArgError::BadAddress { index, host, what } => {
                let host = if host.is_empty() { "?" } else { host };
                write!(f, "address {index} ({host}): {what}")
            }
            ArgError::BadKnock { what } => write!(f, "--knock: {what}"),
            ArgError::HelpRequested => write!(f, "{USAGE}"),
            ArgError::VersionRequested => write!(f, "{VERSION_TEXT}"),
        }
    }
}

impl std::error::Error for ArgError {}

enum SshSetting {
    Inherit,
    On(u16),
    Off,
}

enum KnockSetting {
    Inherit,
    Steps(Vec<knock::KnockStep>),
    Off,
}

/// One address as written, before the flags are applied.
struct Written {
    login: Option<String>,
    host: String,
    port: Option<u16>,
    ssh: SshSetting,
    knock: KnockSetting,
}

pub fn parse_args(argv: &[String]) -> Result<Args, ArgError> {
    parse_args_os(&argv.iter().map(OsString::from).collect::<Vec<_>>())
}

fn argument_text((index, value): (usize, &OsString)) -> Result<&str, ArgError> {
    value.to_str().ok_or(ArgError::InvalidUtf8 {
        argument: index + 1,
    })
}

/// Parse OS arguments, preserving identity paths and validating consumed text.
pub fn parse_args_os(argv: &[OsString]) -> Result<Args, ArgError> {
    let mut raws: Vec<String> = Vec::new();
    let mut port: Option<u16> = None;
    let mut login_flag: Option<String> = None;
    let mut ssh_flag: Option<u16> = None;
    let mut knock_flag: Option<Vec<knock::KnockStep>> = None;
    let mut no_password = false;
    let mut authorize_ssh = false;
    let mut identity = None;
    let mut predict = PredictMode::Adaptive;
    let mut escape = crate::escape::DEFAULT_PREFIX;
    let mut status_line = true;
    let mut history = 10_000;
    let mut verbose = false;

    let mut it = argv.iter().enumerate();
    while let Some(arg) = it.next() {
        match argument_text(arg)? {
            "-h" | "--help" => return Err(ArgError::HelpRequested),
            "-V" | "--version" => return Err(ArgError::VersionRequested),
            "--verbose" => verbose = true,
            "--authorize-ssh" => authorize_ssh = true,
            "--no-password" => no_password = true,
            "-l" => {
                let v = argument_text(it.next().ok_or(ArgError::MissingValue("-l".into()))?)?;
                login_flag = Some(v.to_owned());
            }
            "-p" | "--port" => {
                let v = argument_text(
                    it.next()
                        .ok_or(ArgError::MissingValue("-p/--port".into()))?,
                )?;
                port = Some(parse_port(v)?);
            }
            "--ssh" => ssh_flag = Some(DEFAULT_SSH_PORT),
            "--knock" => {
                let v = argument_text(it.next().ok_or(ArgError::MissingValue("--knock".into()))?)?;
                knock_flag =
                    Some(knock_spec::parse(v).map_err(|what| ArgError::BadKnock { what })?);
            }
            "-i" | "--identity" => {
                let (_, v) = it
                    .next()
                    .ok_or(ArgError::MissingValue("-i/--identity".into()))?;
                identity = Some(PathBuf::from(v));
            }
            "--predict" => {
                let v = argument_text(
                    it.next()
                        .ok_or(ArgError::MissingValue("--predict".into()))?,
                )?;
                predict = match v {
                    "adaptive" => PredictMode::Adaptive,
                    "always" => PredictMode::Always,
                    "never" => PredictMode::Never,
                    other => return Err(ArgError::BadPredict(other.to_string())),
                };
            }
            "--escape" => {
                let v = argument_text(it.next().ok_or(ArgError::MissingValue("--escape".into()))?)?;
                escape = crate::escape::parse_prefix(v).map_err(ArgError::BadEscape)?;
            }
            "--status" => {
                let v = argument_text(it.next().ok_or(ArgError::MissingValue("--status".into()))?)?;
                status_line = match v {
                    "on" => true,
                    "off" => false,
                    other => return Err(ArgError::BadStatus(other.to_string())),
                };
            }
            "--history" => {
                let v = argument_text(
                    it.next()
                        .ok_or(ArgError::MissingValue("--history".into()))?,
                )?;
                history = v
                    .parse::<usize>()
                    .map_err(|_| ArgError::BadHistory(v.to_owned()))?;
                if history > i32::MAX as usize {
                    return Err(ArgError::BadHistory(v.to_owned()));
                }
            }
            other => {
                if let Some(n) = other.strip_prefix("--ssh=") {
                    ssh_flag = Some(parse_port(n)?);
                } else if other.starts_with('-') {
                    return Err(ArgError::UnknownFlag(other.to_string()));
                } else {
                    raws.push(other.to_string());
                }
            }
        }
    }

    if raws.is_empty() {
        return Err(ArgError::NoHost);
    }
    if raws.len() > MAX_ADDRESSES {
        return Err(ArgError::TooManyAddresses);
    }
    let written = raws
        .iter()
        .enumerate()
        .map(|(i, raw)| read_address(i + 1, raw))
        .collect::<Result<Vec<_>, _>>()?;

    // Every address leads to one daemon, so there is one account: the first
    // address that names one sets it, and a second, different name is refused.
    let mut named: Option<String> = None;
    for w in &written {
        if let Some(l) = &w.login {
            match &named {
                Some(first) if first != l => {
                    return Err(ArgError::ConflictingLogin {
                        first: first.clone(),
                        second: l.clone(),
                    })
                }
                Some(_) => {}
                None => named = Some(l.clone()),
            }
        }
    }
    let login = resolve_login(named.or(login_flag), local_login())?;

    let addresses = written
        .into_iter()
        .enumerate()
        .map(|(i, w)| resolve(i + 1, w, port, ssh_flag, knock_flag.as_deref()))
        .collect::<Result<Vec<_>, _>>()?;

    if authorize_ssh && !addresses.iter().any(|a| a.ssh.is_some()) {
        return Err(ArgError::AuthorizationNeedsSsh);
    }

    Ok(Args {
        login,
        addresses,
        identity,
        no_password,
        authorize_ssh,
        predict,
        escape,
        status_line,
        history,
        verbose,
    })
}

/// Read `[user@]host[:port]` and the settings after the commas, without yet
/// applying any flag.
fn read_address(index: usize, raw: &str) -> Result<Written, ArgError> {
    let mut parts = raw.split(',');
    let target = parts.next().unwrap_or("");
    let (login, target) = match target.rsplit_once('@') {
        Some((user, rest)) => (Some(user.to_string()), rest),
        None => (None, target),
    };
    let bad = |host: &str, what: String| ArgError::BadAddress {
        index,
        host: host.to_string(),
        what,
    };
    // A host-part error shows the host part only (it ends before the first
    // comma, so no setting text can reach it); with no host read, `?`.
    let (host, port) = split_host_port(target).map_err(|what| {
        let shown = if what == "no host" { "" } else { target };
        bad(shown, what)
    })?;

    let mut ssh = SshSetting::Inherit;
    let mut knock = KnockSetting::Inherit;
    for (position, setting) in parts.enumerate().map(|(i, s)| (i + 1, s)) {
        if setting.is_empty() {
            return Err(bad(&host, "an empty setting".into()));
        }
        let (name, value) = match setting.split_once('=') {
            Some((n, v)) => (n, Some(v)),
            None => (setting, None),
        };
        match (name, value) {
            ("ssh", _) | ("nossh", None) => {
                if !matches!(ssh, SshSetting::Inherit) {
                    return Err(bad(&host, "ssh is set twice".into()));
                }
                ssh = match (name, value) {
                    ("ssh", None) => SshSetting::On(DEFAULT_SSH_PORT),
                    ("ssh", Some(p)) => match p.parse::<u16>() {
                        Ok(p) if p > 0 => SshSetting::On(p),
                        _ => return Err(bad(&host, "bad port".into())),
                    },
                    _ => SshSetting::Off,
                };
            }
            ("knock", Some(_)) | ("noknock", None) => {
                if !matches!(knock, KnockSetting::Inherit) {
                    return Err(bad(&host, "knock is set twice".into()));
                }
                knock = match value {
                    Some(steps) => KnockSetting::Steps(
                        knock_spec::parse(steps).map_err(|what| bad(&host, what))?,
                    ),
                    None => KnockSetting::Off,
                };
            }
            // Only a near miss of a real setting name (`knok`) is quoted.
            // Anything else could be knock steps written without `knock=`, or
            // a piece of them cut at a comma, and a knock is a secret: say
            // where, not what.
            _ => {
                let what = if is_near_miss(name) {
                    format!("unknown setting {name:?}")
                } else {
                    format!("unknown setting {position}")
                };
                return Err(bad(&host, what));
            }
        }
    }
    Ok(Written {
        login,
        host,
        port,
        ssh,
        knock,
    })
}

/// True when `name` is a lowercase word within two edits of a setting name.
fn is_near_miss(name: &str) -> bool {
    fn distance(a: &[u8], b: &[u8]) -> usize {
        let mut row: Vec<usize> = (0..=b.len()).collect();
        for (i, &x) in a.iter().enumerate() {
            let mut prev = row[0];
            row[0] = i + 1;
            for (j, &y) in b.iter().enumerate() {
                let cur = row[j + 1];
                row[j + 1] = (prev + usize::from(x != y)).min(row[j] + 1).min(cur + 1);
                prev = cur;
            }
        }
        row[b.len()]
    }
    name.bytes().all(|b| b.is_ascii_lowercase())
        && ["ssh", "nossh", "knock", "noknock"]
            .iter()
            .any(|known| distance(name.as_bytes(), known.as_bytes()) <= 2)
}

/// Split `host`, `host:port` or `[v6]:port`. The error is the `what` of a
/// `BadAddress`.
fn split_host_port(target: &str) -> Result<(String, Option<u16>), String> {
    let port_of = |p: &str| match p.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err("bad port".to_string()),
    };
    let (host, port) = if let Some(rest) = target.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "a bracketed host needs a closing ]".to_string())?;
        match after {
            "" => (host, None),
            _ => match after.strip_prefix(':') {
                Some(p) => (host, Some(port_of(p)?)),
                None => return Err("only :port may follow ]".into()),
            },
        }
    } else {
        match target.matches(':').count() {
            0 => (target, None),
            1 => {
                let (h, p) = target.split_once(':').expect("one colon");
                (h, Some(port_of(p)?))
            }
            _ => return Err(format!("an IPv6 address goes in brackets: [{target}]")),
        }
    };
    if host.is_empty() {
        return Err("no host".into());
    }
    Ok((host.to_string(), port))
}

/// Apply the flags to one written address.
fn resolve(
    index: usize,
    w: Written,
    port: Option<u16>,
    ssh: Option<u16>,
    knock: Option<&[knock::KnockStep]>,
) -> Result<connect::Address, ArgError> {
    let ssh_port = match w.ssh {
        SshSetting::On(p) => Some(p),
        SshSetting::Off => None,
        SshSetting::Inherit => ssh,
    };
    let route = match ssh_port {
        None => {
            if matches!(w.knock, KnockSetting::Steps(_)) {
                return Err(ArgError::BadAddress {
                    index,
                    host: w.host,
                    what: "knock is only used before ssh".into(),
                });
            }
            None
        }
        Some(p) => Some(connect::SshRoute {
            port: p,
            knock: match w.knock {
                KnockSetting::Steps(s) => s,
                KnockSetting::Off => Vec::new(),
                KnockSetting::Inherit => knock.map(<[_]>::to_vec).unwrap_or_default(),
            },
        }),
    };
    Ok(connect::Address {
        host: w.host,
        qsh_port: w.port.or(port).unwrap_or(DEFAULT_PORT),
        ssh: route,
    })
}

/// Which account to claim: the one the address named, else the one the
/// environment says we are. Pure so it can be tested without touching the
/// environment, which a test sharing a process with other threads cannot
/// do safely.
fn resolve_login(
    from_address: Option<String>,
    from_env: Option<String>,
) -> Result<String, ArgError> {
    if let Some(login) = from_address {
        if login.is_empty() {
            return Err(ArgError::NoLogin);
        }
        return Ok(login);
    }
    match from_env {
        Some(login) if !login.is_empty() => Ok(login),
        _ => Err(ArgError::NoLogin),
    }
}

/// The account this machine's user is logged in as -- what `qsh host`
/// claims when the command line names nobody. Falls back to `USER` and
/// then to `LOGNAME`, which is the order `ssh` itself reads them in.
fn local_login() -> Option<String> {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .ok()
}

fn parse_port(v: &str) -> Result<u16, ArgError> {
    match v.parse::<u16>() {
        Ok(p) if p > 0 => Ok(p),
        _ => Err(ArgError::BadPort(v.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn os_text_arguments_report_the_consumed_position_without_the_value() {
        use std::os::unix::ffi::OsStringExt;
        let invalid = std::ffi::OsString::from_vec(b"\x1b[31msecret\n\xff".to_vec());
        for prefix in [
            vec![],
            vec!["-l"],
            vec!["-p"],
            vec!["--port"],
            vec!["--knock"],
            vec!["--predict"],
            vec!["--escape"],
            vec!["--status"],
            vec!["--history"],
        ] {
            let mut args: Vec<std::ffi::OsString> = prefix.into_iter().map(Into::into).collect();
            args.push(invalid.clone());
            assert_eq!(
                parse_args_os(&args).unwrap_err().to_string(),
                format!("argument {} must be valid UTF-8", args.len())
            );
        }
        for invalid in [b"--bad-\xff".as_slice(), b"alice@host-\xff", b"--ssh=\xff"] {
            let args = [std::ffi::OsString::from_vec(invalid.to_vec())];
            assert_eq!(
                parse_args_os(&args).unwrap_err().to_string(),
                "argument 1 must be valid UTF-8"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn identity_values_preserve_os_paths_and_option_boundaries() {
        use std::os::unix::ffi::OsStringExt;
        for flag in ["-i", "--identity"] {
            for path in [
                std::ffi::OsString::from_vec(b"identity-\xff".to_vec()),
                "--help".into(),
                "--".into(),
            ] {
                let parsed =
                    parse_args_os(&[flag.into(), path.clone(), "alice@example.org".into()])
                        .unwrap();
                assert_eq!(parsed.identity, Some(PathBuf::from(path)));
            }
            assert!(matches!(
                parse_args_os(&[flag.into()]),
                Err(ArgError::MissingValue(_))
            ));
        }
        let invalid = std::ffi::OsString::from_vec(vec![0xff]);
        assert_eq!(
            parse_args_os(&["--".into(), invalid.clone()]).unwrap_err(),
            ArgError::UnknownFlag("--".into())
        );
        assert_eq!(
            parse_args_os(&["--".into()]).unwrap_err(),
            ArgError::UnknownFlag("--".into())
        );
        assert_eq!(
            parse_args_os(&["--help".into(), invalid.clone()]).unwrap_err(),
            ArgError::HelpRequested
        );
        assert_eq!(
            parse_args_os(&["--version".into(), invalid]).unwrap_err(),
            ArgError::VersionRequested
        );
        let parsed = parse_args_os(&[
            "-l".into(),
            "flag-user".into(),
            "named@example.org".into(),
            "-i".into(),
            "first".into(),
            "--identity".into(),
            "second".into(),
        ])
        .unwrap();
        assert_eq!(parsed.login, "named");
        assert_eq!(parsed.identity, Some(PathBuf::from("second")));
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// The help says where the log is, on both systems qsh runs on.
    #[test]
    fn the_help_names_the_log_on_linux_and_macos() {
        assert!(USAGE.contains("~/.cache/qsh/log"));
        assert!(USAGE.contains("$XDG_CACHE_HOME/qsh/log"));
        assert!(USAGE.contains("--verbose             more detail in the log"));
    }

    /// The bare form is the one people type: a host and nothing else.
    #[test]
    fn a_host_alone_takes_every_default() {
        let a = parse_args(&argv(&["example.org"])).expect("parses");
        assert_eq!(one(&a).host, "example.org");
        assert_eq!(
            one(&a).qsh_port,
            60022,
            "the default port is the one qshd serve binds"
        );
        assert_eq!(a.predict, PredictMode::Adaptive);
        assert!(a.identity.is_none());
        assert!(!a.verbose);
        assert!(one(&a).ssh.is_none());
        assert_eq!(a.addresses.len(), 1);
    }

    /// `user@host` now selects the account, instead of being dropped.
    #[test]
    fn a_user_prefix_becomes_the_login() {
        let a = parse_args(&argv(&["alice@example.org"])).expect("parses");
        assert_eq!(one(&a).host, "example.org");
        assert_eq!(a.login, "alice");
    }

    /// A spare may carry its own `user@`, but the account is the
    /// connection's, not the address's: every road leads to one daemon, so a
    /// second name there is a mistake worth refusing rather than silently
    /// preferring one of them.
    #[test]
    fn a_spare_with_a_different_user_is_refused() {
        assert!(matches!(
            parse_args(&argv(&["alice@h", "bob@vpn.example"])),
            Err(ArgError::ConflictingLogin { .. })
        ));
    }

    /// The same name on a spare is harmless and accepted.
    #[test]
    fn a_spare_repeating_the_same_user_is_accepted() {
        let a = parse_args(&argv(&["alice@h", "alice@vpn.example:61000"])).expect("parses");
        assert_eq!(a.login, "alice");
        assert_eq!(a.addresses[1].host, "vpn.example");
        assert_eq!(a.addresses[1].qsh_port, 61000);
    }

    /// `resolve_login` is where the decision lives, and it is what gets
    /// tested directly: exercising it through `parse_args` would mean
    /// setting `USER`/`LOGNAME`, which a test sharing a process with other
    /// threads cannot safely do.
    mod resolve_login_tests {
        use super::*;

        /// An address name is used as-is, with no environment consulted.
        #[test]
        fn an_address_name_wins_with_no_environment() {
            assert_eq!(
                resolve_login(Some("alice".to_string()), None),
                Ok("alice".to_string())
            );
        }

        /// An address name wins even when the environment names someone
        /// else: the address is the more deliberate of the two.
        #[test]
        fn an_address_name_wins_over_the_environment() {
            assert_eq!(
                resolve_login(Some("alice".to_string()), Some("bob".to_string())),
                Ok("alice".to_string())
            );
        }

        /// With no address name, the environment's account is the claim --
        /// the same thing `ssh` does.
        #[test]
        fn the_environment_is_used_when_the_address_names_nobody() {
            assert_eq!(
                resolve_login(None, Some("bob".to_string())),
                Ok("bob".to_string())
            );
        }

        /// Neither an address nor an environment names anyone: nothing to
        /// claim, and the caller must say so plainly rather than send a
        /// blank name to the server.
        #[test]
        fn no_address_and_no_environment_is_refused() {
            assert_eq!(resolve_login(None, None), Err(ArgError::NoLogin));
        }

        /// An environment variable that is set but empty is exactly as
        /// useless as one that is absent.
        #[test]
        fn an_empty_environment_name_is_refused_too() {
            assert_eq!(
                resolve_login(None, Some(String::new())),
                Err(ArgError::NoLogin)
            );
        }

        /// `qsh @host` names an empty login, not no login: it must be
        /// refused here, with a message the user can act on, rather than
        /// waved through to fail later inside `encode_auth_record`. It must
        /// not fall back to the environment either -- an explicit (if
        /// blank) address login is not "nothing was named".
        #[test]
        fn an_empty_address_name_is_refused_too() {
            assert_eq!(
                resolve_login(Some(String::new()), Some("bob".to_string())),
                Err(ArgError::NoLogin)
            );
        }
    }

    /// `host:port` is the other shape people type.
    #[test]
    fn a_port_can_ride_on_the_host() {
        let a = parse_args(&argv(&["example.org:61000"])).expect("parses");
        assert_eq!(one(&a).host, "example.org");
        assert_eq!(one(&a).qsh_port, 61000);
    }

    #[test]
    fn every_flag_is_read() {
        let a = parse_args(&argv(&[
            "--port",
            "61000",
            "--no-password",
            "-i",
            "/tmp/k",
            "--predict",
            "never",
            "--verbose",
            "h",
        ]))
        .expect("parses");
        assert_eq!(one(&a).qsh_port, 61000);
        assert!(a.no_password);
        assert_eq!(a.identity.as_deref(), Some(std::path::Path::new("/tmp/k")));
        assert_eq!(a.predict, PredictMode::Never);
        assert!(a.verbose);
        assert_eq!(one(&a).host, "h");
    }

    /// Several addresses on one command line: the first is where the session
    /// starts, the rest become roads to the same daemon. There is no flag --
    /// naming more than one address is itself the request.
    #[test]
    fn addresses_after_the_first_become_spare_roads() {
        let a =
            parse_args(&argv(&["example.org", "vpn.example:61000", "10.0.0.2"])).expect("parses");
        assert_eq!(one(&a).host, "example.org");
        assert_eq!(one(&a).qsh_port, DEFAULT_PORT);
        let spares: Vec<(&str, u16)> = a.addresses[1..]
            .iter()
            .map(|s| (s.host.as_str(), s.qsh_port))
            .collect();
        assert_eq!(
            spares,
            vec![("vpn.example", 61000), ("10.0.0.2", DEFAULT_PORT)],
            "a spare keeps its own port, or takes the default"
        );
    }

    /// A spare wears every shape the first address does -- so long as the
    /// account it names, if any, agrees with the one already established.
    #[test]
    fn a_spare_may_carry_a_user_and_a_port() {
        let a = parse_args(&argv(&["user@h", "user@vpn.example:61000"])).expect("parses");
        assert_eq!(a.addresses[1].qsh_port, 61000);
    }

    /// `--port` names the daemon's port, so it covers every address that does
    /// not carry one of its own -- not only the first.
    #[test]
    fn the_port_flag_covers_a_spare_that_names_no_port() {
        let a = parse_args(&argv(&["--port", "61000", "h", "spare.example"])).expect("parses");
        assert_eq!(one(&a).qsh_port, 61000);
        assert_eq!(a.addresses[1].qsh_port, 61000);
    }

    /// Under the new rules a port on the first address belongs to that
    /// address alone: a spare that names none takes the flag or the default.
    #[test]
    fn a_port_on_the_first_address_does_not_spread_to_a_spare() {
        let a = parse_args(&argv(&["example.org:5000", "spare.example"])).expect("parses");
        assert_eq!(one(&a).qsh_port, 5000);
        assert_eq!(a.addresses[1].qsh_port, DEFAULT_PORT);
    }

    /// One address is the ordinary case, and it must stay exactly as it was.
    #[test]
    fn a_single_address_leaves_no_spares() {
        let a = parse_args(&argv(&["example.org"])).expect("parses");
        assert_eq!(a.addresses.len(), 1, "one address is one road");
    }

    #[test]
    fn version_is_requested_by_both_spellings() {
        for flag in ["--version", "-V"] {
            assert_eq!(
                parse_args(&argv(&[flag])),
                Err(ArgError::VersionRequested),
                "{flag} must ask for the version"
            );
        }
    }

    #[test]
    fn the_version_text_names_the_version_the_license_and_the_source() {
        assert!(VERSION_TEXT.contains(env!("CARGO_PKG_VERSION")));
        assert!(VERSION_TEXT.contains("AGPL-3.0-only"));
        assert!(VERSION_TEXT.contains("https://github.com/br0adcast/qsh"));
        assert!(
            VERSION_TEXT.contains("no warranty"),
            "the AGPL's own disclaimer belongs here"
        );
    }

    #[test]
    fn what_is_refused_is_refused_with_a_reason() {
        for (bad, expect) in [
            (vec![], "no server address"),
            (vec!["--port"], "needs a value"),
            (vec!["--port", "abc", "h"], "port"),
            (vec!["--port", "0", "h"], "port"),
            (vec!["--predict", "sometimes", "h"], "predict"),
            (vec!["--wat", "h"], "unknown"),
        ] {
            let e = parse_args(&argv(&bad)).expect_err("must be refused");
            let msg = e.to_string();
            assert!(
                msg.contains(expect),
                "argv {bad:?}: expected the message to mention {expect:?}, got {msg:?}"
            );
        }
    }

    fn one(a: &Args) -> &connect::Address {
        &a.addresses[0]
    }

    #[test]
    fn the_address_port_beats_the_port_flag() {
        let a = parse_args(&argv(&["-p", "61000", "example.org:1", "b"])).unwrap();
        assert_eq!(a.addresses[0].qsh_port, 1);
        assert_eq!(a.addresses[1].qsh_port, 61000);
    }

    #[test]
    fn the_short_port_flag_works() {
        assert_eq!(
            one(&parse_args(&argv(&["-p", "61000", "h"])).unwrap()).qsh_port,
            61000
        );
    }

    #[test]
    fn ssh_settings_per_address_and_from_the_flag() {
        let a = parse_args(&argv(&["--ssh", "a,ssh=2222", "b", "c,nossh"])).unwrap();
        assert_eq!(a.addresses[0].ssh.as_ref().map(|s| s.port), Some(2222));
        assert_eq!(a.addresses[1].ssh.as_ref().map(|s| s.port), Some(22));
        assert!(a.addresses[2].ssh.is_none());
        let a = parse_args(&argv(&["--ssh=2200", "a", "b,ssh"])).unwrap();
        assert_eq!(a.addresses[0].ssh.as_ref().map(|s| s.port), Some(2200));
        assert_eq!(a.addresses[1].ssh.as_ref().map(|s| s.port), Some(22));
        assert!(parse_args(&argv(&["a"])).unwrap().addresses[0]
            .ssh
            .is_none());
    }

    #[test]
    fn the_knock_flag_goes_only_to_addresses_with_ssh() {
        let a = parse_args(&argv(&[
            "--knock",
            "tcp:7000+udp:8000",
            "a,ssh",
            "b",
            "c,ssh,noknock",
        ]))
        .unwrap();
        assert_eq!(a.addresses[0].ssh.as_ref().unwrap().knock.len(), 2);
        assert!(a.addresses[1].ssh.is_none());
        assert!(a.addresses[2].ssh.as_ref().unwrap().knock.is_empty());
    }

    #[test]
    fn an_address_knock_beats_the_flag() {
        let a = parse_args(&argv(&["--knock", "tcp:1", "a,ssh,knock=udp:2+udp:3"])).unwrap();
        assert_eq!(a.addresses[0].ssh.as_ref().unwrap().knock.len(), 2);
    }

    #[test]
    fn a_knock_without_ssh_is_refused() {
        assert_eq!(
            parse_args(&argv(&["h,knock=tcp:1"]))
                .unwrap_err()
                .to_string(),
            "address 1 (h): knock is only used before ssh"
        );
    }

    #[test]
    fn ipv6_goes_in_brackets() {
        let a = parse_args(&argv(&["[2001:db8::1]:61000,ssh"])).unwrap();
        assert_eq!(one(&a).host, "2001:db8::1");
        assert_eq!(one(&a).qsh_port, 61000);
        assert_eq!(one(&parse_args(&argv(&["[::1]"])).unwrap()).host, "::1");
        assert_eq!(
            parse_args(&argv(&["2001:db8::1"])).unwrap_err().to_string(),
            "address 1 (2001:db8::1): an IPv6 address goes in brackets: [2001:db8::1]"
        );
    }

    #[test]
    fn settings_mistakes_are_named() {
        let cases = [
            ("h,ssh,nossh", "address 1 (h): ssh is set twice"),
            (
                "h,ssh,knock=tcp:1,noknock",
                "address 1 (h): knock is set twice",
            ),
            ("h,,ssh", "address 1 (h): an empty setting"),
            ("h,knok=udp:1:x", "address 1 (h): unknown setting \"knok\""),
            ("h,ssh=0", "address 1 (h): bad port"),
        ];
        for (raw, want) in cases {
            assert_eq!(
                parse_args(&argv(&[raw])).unwrap_err().to_string(),
                want,
                "{raw}"
            );
        }
    }

    #[test]
    fn a_knock_error_never_repeats_the_data() {
        let err = parse_args(&argv(&["h,ssh,knock=tcp:1:s3cr3t"]))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("s3cr3t"), "{err}");
        assert_eq!(
            err,
            "address 1 (h): knock element 1: a TCP knock carries no data"
        );
        let err = parse_args(&argv(&["--knock", "udp:1:s3cr3t+x", "h,ssh"]))
            .unwrap_err()
            .to_string();
        assert!(!err.contains("s3cr3t"), "{err}");
    }

    #[test]
    fn at_most_eight_addresses() {
        let eight: Vec<String> = (1..=8).map(|i| format!("10.0.0.{i}")).collect();
        assert_eq!(parse_args(&eight).unwrap().addresses.len(), 8);
        let mut nine = eight.clone();
        nine.push("10.0.0.9".into());
        assert_eq!(
            parse_args(&nine).unwrap_err().to_string(),
            "at most 8 addresses"
        );
    }

    #[test]
    fn the_login_flag_is_used_when_no_address_names_one() {
        assert_eq!(
            parse_args(&argv(&["-l", "carol", "h"])).unwrap().login,
            "carol"
        );
        assert_eq!(
            parse_args(&argv(&["-l", "carol", "alice@h"]))
                .unwrap()
                .login,
            "alice"
        );
    }

    #[test]
    fn no_password_is_read() {
        assert!(
            parse_args(&argv(&["--no-password", "h"]))
                .unwrap()
                .no_password
        );
        assert!(!parse_args(&argv(&["h"])).unwrap().no_password);
    }

    #[test]
    fn a_bad_knock_flag_is_named() {
        assert_eq!(
            parse_args(&argv(&["--knock", "tcp:1:x", "h,ssh"]))
                .unwrap_err()
                .to_string(),
            "--knock: knock element 1: a TCP knock carries no data"
        );
    }

    #[test]
    fn an_unknown_setting_never_repeats_knock_text() {
        let err = parse_args(&argv(&["h,ssh,tcp:7000+udp:8000:s3cr3t"]))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "address 1 (h): unknown setting 2");
        assert!(!err.contains("s3cr3t") && !err.contains("7000"), "{err}");
        let err = parse_args(&argv(&["h,ssh,knock=udp:1:abc,def"]))
            .unwrap_err()
            .to_string();
        assert_eq!(err, "address 1 (h): unknown setting 3");
        assert!(!err.contains("def") && !err.contains("abc"), "{err}");
    }

    #[test]
    fn a_missing_host_is_shown_as_a_question_mark() {
        for raw in [":80,ssh=2222", ",ssh", "alice@", "[]:5,ssh"] {
            let err = parse_args(&argv(&[raw])).unwrap_err().to_string();
            assert_eq!(err, "address 1 (?): no host", "{raw}");
        }
    }

    #[test]
    fn ssh_flag_forms_and_their_mistakes() {
        let a = parse_args(&argv(&["--ssh", "2222", "h"])).unwrap();
        assert_eq!(a.addresses.len(), 2);
        assert_eq!(a.addresses[0].host, "2222");
        assert_eq!(a.addresses[1].host, "h");
        for x in &a.addresses {
            assert_eq!(x.ssh.as_ref().map(|s| s.port), Some(22));
        }
        for bad in ["--ssh=abc", "--ssh=0"] {
            assert!(matches!(
                parse_args(&argv(&[bad, "h"])),
                Err(ArgError::BadPort(_))
            ));
        }
    }

    #[test]
    fn address_syntax_mistakes() {
        let cases = [
            (
                "[::1",
                "address 1 ([::1): a bracketed host needs a closing ]",
            ),
            ("h:0", "address 1 (h:0): bad port"),
            ("h:65536", "address 1 (h:65536): bad port"),
            ("h,ssh,ssh=2222", "address 1 (h): ssh is set twice"),
            ("h,ssh,knock=", "address 1 (h): knock: no steps"),
        ];
        for (raw, want) in cases {
            assert_eq!(
                parse_args(&argv(&[raw])).unwrap_err().to_string(),
                want,
                "{raw}"
            );
        }
    }

    #[test]
    fn the_escape_and_the_status_line_are_read() {
        let a = parse_args(&argv(&["h"])).unwrap();
        assert_eq!(a.escape, crate::escape::DEFAULT_PREFIX);
        assert!(a.status_line);
        let a = parse_args(&argv(&["--escape", "^b", "--status", "off", "h"])).unwrap();
        assert_eq!(a.escape, crate::escape::Prefix::Key(0x02));
        assert!(!a.status_line);
        assert_eq!(
            parse_args(&argv(&["--escape", "none", "h"]))
                .unwrap()
                .escape,
            crate::escape::Prefix::None
        );
        assert_eq!(
            parse_args(&argv(&["--escape", "x", "h"]))
                .unwrap_err()
                .to_string(),
            "--escape: expected ^X (from ^@ to ^_) or none"
        );
        assert_eq!(
            parse_args(&argv(&["--status", "maybe", "h"]))
                .unwrap_err()
                .to_string(),
            "--status: expected on or off, not \"maybe\""
        );
    }

    #[test]
    fn the_history_flag_accepts_zero_and_rejects_non_numbers() {
        assert_eq!(parse_args(&argv(&["h"])).unwrap().history, 10_000);
        for n in ["0", "250", "10000"] {
            assert_eq!(
                parse_args(&argv(&["--history", n, "h"])).unwrap().history,
                n.parse::<usize>().unwrap()
            );
        }
        for n in ["-1", "no", "1.5"] {
            assert!(parse_args(&argv(&["--history", n, "h"]))
                .unwrap_err()
                .to_string()
                .starts_with("--history:"));
        }
        assert_eq!(
            parse_args(&argv(&["--history"])).unwrap_err().to_string(),
            "option --history needs a value"
        );
        assert!(USAGE.contains("--history N"));
        assert!(USAGE.contains("Ctrl-] ["));
    }
}
