//! The client's log: `$XDG_CACHE_HOME/qsh/log`, or `~/.cache/qsh/log` on Unix,
//! written on every run through the shared `logging` crate -- one
//! timestamped line per record, with the pid, the level and the component.
//! The terminal is busy drawing the remote shell's own screen, so detail
//! goes here and only precise messages go to the person.
//!
//! Nothing secret is written: a knock is only a mark on its address, and
//! no password, passphrase or key material ever reaches a record.

use std::io::Write;
use std::path::PathBuf;

use crate::args::{Args, PredictMode};

/// Past this the log is moved to `log.1` and a fresh one started.
const MAX_BYTES: u64 = 1024 * 1024;

/// This program's own crates: logged at `info` (`debug` with `--verbose`).
/// Everything else -- libraries such as `alacritty_terminal` or `vte`, which
/// log every sequence they do not handle -- only from `warn` up.
const OWN: &[&str] = &[
    "qsh",
    "stderr",
    "transport",
    "connect",
    "client",
    "ssh",
    "sshauth",
    "knock",
    "bringup",
    "terminal",
    "render",
    "prediction",
];

/// Which records are kept: see [`OWN`]; `russh` gets one step more than
/// other libraries, since how an ssh login went is often the question.
pub fn filter(verbose: bool) -> logging::Filter {
    use ::log::LevelFilter;
    let (own, russh) = if verbose {
        (LevelFilter::Debug, LevelFilter::Info)
    } else {
        (LevelFilter::Info, LevelFilter::Warn)
    };
    let mut per_component: Vec<(String, LevelFilter)> =
        OWN.iter().map(|c| (c.to_string(), own)).collect();
    per_component.push(("russh".into(), russh));
    logging::Filter {
        default: LevelFilter::Warn,
        per_component,
    }
}

/// Opens the log and installs it as the process's logger. A log that
/// cannot be opened is disabled for this run; one startup warning explains why.
pub fn init(verbose: bool) {
    static ATTEMPTED: std::sync::Once = std::sync::Once::new();
    ATTEMPTED.call_once(|| {
        match logging::FileSink::try_open_in_private_dir(&path(), MAX_BYTES) {
            Ok(sink) => { let _ = logging::install(sink, filter(verbose)); }
            Err(error) => {
                let warning = logging::diagnostic(&format!(
                    "file logging disabled: {error}. Check this path's ownership, permissions and free space"));
                let _ = writeln!(std::io::stderr(), "qsh: {warning}");
            }
        }
    });
}

/// Where the log is, the path the person is told to look at.
pub fn path() -> PathBuf {
    crate::paths::cache_dir().join("log")
}

/// A record of this program's own, at `info`.
pub fn log(msg: &str) {
    ::log::info!(target: "qsh", "{msg}");
}

/// A record of this program's own, at `warn`.
pub fn warn(msg: &str) {
    ::log::warn!(target: "qsh", "{msg}");
}

/// A record of this program's own, at `error`.
pub fn error(msg: &str) {
    ::log::error!(target: "qsh", "{msg}");
}

/// A record of this program's own, at `debug` (kept with `--verbose`).
pub fn debug(msg: &str) {
    ::log::debug!(target: "qsh", "{msg}");
}

/// A line the person also saw on the terminal, kept in the log too.
pub fn shown(line: &str) {
    log(shown_text(line));
}

/// [`shown`], at `warn`: a line that must not be lost.
pub fn shown_warning(line: &str) {
    warn(shown_text(line));
}

/// The terminal's line without its `qsh: ` prefix: the log's own header
/// already names the component.
fn shown_text(line: &str) -> &str {
    line.strip_prefix("qsh: ").unwrap_or(line)
}

/// The first line of every run: what runs (the version and the build stamp,
/// the HEAD commit's time as `qshd` has it -- see `cli/build.rs`), where,
/// and what it was asked to reach. Addresses as `host:port`, with `+ssh:N` and a bare `+knock` --
/// never a knock's ports or data; the other options by their values, none
/// of which is a secret.
pub fn start_marker(a: &Args) -> String {
    let addresses: Vec<String> = a
        .addresses
        .iter()
        .map(|addr| {
            let mut s = if addr.host.contains(':') {
                format!("[{}]:{}", addr.host, addr.qsh_port)
            } else {
                format!("{}:{}", addr.host, addr.qsh_port)
            };
            if let Some(route) = &addr.ssh {
                s.push_str(&format!("+ssh:{}", route.port));
                if !route.knock.is_empty() {
                    s.push_str("+knock");
                }
            }
            s
        })
        .collect();
    let predict = match a.predict {
        PredictMode::Adaptive => "adaptive",
        PredictMode::Always => "always",
        PredictMode::Never => "never",
    };
    let mut m = format!(
        "qsh {} (build {}) starting: {}/{}, addresses: {}, login {}, predict {predict}, escape {}, status {}",
        env!("CARGO_PKG_VERSION"),
        env!("QSH_BUILD"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        addresses.join(" "),
        a.login,
        a.escape.name().unwrap_or_else(|| "none".into()),
        if a.status_line { "on" } else { "off" },
    );
    if let Some(identity) = &a.identity {
        m.push_str(&format!(", identity {}", identity.display()));
    }
    if a.no_password {
        m.push_str(", no-password");
    }
    if a.verbose {
        m.push_str(", verbose");
    }
    m
}

/// The last line of every run that gets as far as [`init`].
pub fn exit_marker(code: i32) -> String {
    format!("qsh exiting with code {code}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::args::parse_args;

    fn args(argv: &[&str]) -> crate::args::Args {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        parse_args(&argv).expect("parse")
    }

    #[test]
    fn the_start_marker_names_the_addresses_but_never_the_knock() {
        let a = args(&[
            "u@h:1,ssh=2,knock=udp:7000:secret+tcp:8000",
            "10.0.0.9",
            "--predict",
            "never",
        ]);
        let m = start_marker(&a);
        for secret in ["7000", "8000", "secret"] {
            assert!(!m.contains(secret), "{secret} in {m}");
        }
        let head = format!(
            "qsh {} (build {}) starting: {}/{}, addresses: h:1+ssh:2+knock 10.0.0.9:60022",
            env!("CARGO_PKG_VERSION"),
            env!("QSH_BUILD"),
            std::env::consts::OS,
            std::env::consts::ARCH
        );
        assert!(m.starts_with(&head), "{m}");
        assert!(m.contains("predict never"), "{m}");
    }

    #[test]
    fn a_bracketed_address_keeps_its_brackets() {
        let m = start_marker(&args(&["u@[2001:db8::1]:5,ssh"]));
        assert!(m.contains("addresses: [2001:db8::1]:5+ssh:22,"), "{m}");
    }

    #[test]
    fn the_path_is_the_cache_dir_s() {
        let root = std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(|| dirs::home_dir().expect("home").join(".cache"));
        let want = root.join("qsh/log");
        assert_eq!(path(), want);
    }

    #[test]
    fn a_shown_line_loses_only_its_program_prefix() {
        assert_eq!(shown_text("qsh: 1.2.3.4: no answer"), "1.2.3.4: no answer");
        assert_eq!(shown_text("qsh:   a: b"), "  a: b");
        assert_eq!(shown_text("plain"), "plain");
    }

    #[test]
    fn own_code_logs_info_and_russh_warn_unless_verbose() {
        use ::log::LevelFilter;
        let limit = |f: &logging::Filter, c: &str| {
            f.per_component
                .iter()
                .find(|(n, _)| n == c)
                .map(|(_, l)| *l)
                .unwrap_or(f.default)
        };
        let quiet = filter(false);
        assert_eq!(limit(&quiet, "qsh"), LevelFilter::Info);
        assert_eq!(limit(&quiet, "transport"), LevelFilter::Info);
        assert_eq!(limit(&quiet, "stderr"), LevelFilter::Info);
        assert_eq!(limit(&quiet, "russh"), LevelFilter::Warn);
        let loud = filter(true);
        assert_eq!(limit(&loud, "qsh"), LevelFilter::Debug);
        assert_eq!(limit(&loud, "connect"), LevelFilter::Debug);
        assert_eq!(limit(&loud, "russh"), LevelFilter::Info);
    }
    #[test]
    fn path_diagnostics_initial_log_failure_is_visible_once() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let cache = dir.path().join("cache\nname");
        std::fs::create_dir_all(cache.join("qsh/log")).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "log::tests::path_diagnostics_initial_log_failure_body",
                "--ignored",
                "--nocapture",
            ])
            .env("HOME", dir.path())
            .env("XDG_CACHE_HOME", &cache)
            .env("XDG_CONFIG_HOME", dir.path().join("config"))
            .env("HISTFILE", "/dev/null")
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            stderr.matches("file logging disabled").count(),
            1,
            "{stderr}"
        );
        assert!(stderr.contains("cache\\nname"), "{stderr}");
        assert!(!stderr.contains("cache\nname"));
    }

    #[test]
    #[ignore = "isolated logger environment, run by initial failure wrapper"]
    fn path_diagnostics_initial_log_failure_body() {
        init(false);
        init(false);
    }
}
