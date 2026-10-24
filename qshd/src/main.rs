//! The `qshd` daemon. Four subcommands of the new transport (Noise over
//! UDP, `transport::Connection`):
//!
//! - `transport-echo --port <P> [--client-pubkey <base64> ...]
//!   [--server-key-file <path>]` -- diagnostic echo server with no PTY: a
//!   helper for early verification of the transport itself.
//! - `transport-shell --port <P> [--client-pubkey <base64> ...]
//!   [--server-key-file <path>]` -- interactive shell (`$SHELL` in a PTY)
//!   over the transport, no daemonization.
//! - `transport-ensure --name <session> --port <P> [--default-port <D>]
//!   [--client-pubkey <base64>]` -- the production path: SELF-INSTALLING
//!   and SELF-DAEMONIZING, and -- like `serve` below -- hands out CHANNELS
//!   rather than driving tmux itself; deciding what to put in a channel is
//!   the client's job. It FIRST asks over the control Unix socket
//!   (`control.rs`) whether a daemon is already alive: if it is, it
//!   reconciles versions (`version::reconcile`) and either reuses it
//!   (live-adding the client key via `ADD-CLIENT`) or stops it and brings
//!   up a new one. If there is no daemon, it binds the UDP socket and the
//!   control socket synchronously, prints `server-pubkey:`/`TRANSPORT-READY
//!   {json}` to stdout (picked up by the caller -- the SSH login), and
//!   DAEMONIZES: the parent exits (the SSH `exec` gets the lines and
//!   finishes), while the detached daemon keeps serving channel sessions and
//!   the control socket (STATUS/ADD-CLIENT/STOP).
//!   It admits both kinds of client: the app, by the static key it put on
//!   the allowlist over SSH, and a console client, by a signature checked
//!   against the same `~/.ssh/authorized_keys` `serve` uses -- otherwise
//!   reaching one shell from a phone and a terminal would take two daemons
//!   on two ports.
//! - `serve [--port N] [--authorized-keys PATH] [--host-key PATH]` -- the
//!   standing-service path (`serve.rs`): a long-lived
//!   daemon on a fixed port, reached only by an SSH signature -- it has no
//!   allowlist, because nothing bootstraps one over SSH here.
//!   Unlike `transport-ensure` it neither forks nor installs itself and has
//!   no control socket -- a service manager (systemd/launchd, see
//!   `docs/qshd-service.md`) owns the process and its restarts. Shares the
//!   same channel session backend as `transport-ensure`
//!   ([`qshd::channel_backend::ChannelSessionBackend`]) -- the two commands
//!   are two ways to start one subsystem, not two subsystems.
//!
//! - `transport-resume` -- never typed by anyone: the personal daemon
//!   `exec`s its accepted replacement with this argument and the handover
//!   descriptor in `QSHD_HANDOVER_FD` (`handover.rs`). The new binary IS the
//!   daemon already -- same pid, same sockets -- and carries on serving.
//!   Every other command ignores, and removes, a stray `QSHD_HANDOVER_FD`.
//!
//! The qsh path (QUIC/quinn/mTLS: the `ensure`/`echo` commands) has been
//! removed -- replaced by the `transport-*`
//! path above.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde::Serialize;

use qshd::{
    channel_backend, control, handover, load_or_create_transport_key, log, pty, serve, state,
    transport_daemon, update, version,
};

/// Printed by `--version`. Carries the build stamp as well as the version:
/// the stamp is what client and daemon compare when deciding which side is
/// newer, so a mismatch is diagnosed from this line.
fn version_text() -> String {
    format!(
        "qshd {} (build {})\n\
         AGPL-3.0-only, source: https://github.com/br0adcast/qsh\n\
         This program comes with absolutely no warranty.\n",
        env!("CARGO_PKG_VERSION"),
        crate::state::build_label(),
    )
}

/// Printed by `--help`. `qshd` is installed to `/usr/bin` by the `.deb`/
/// `.rpm` packages, so running it bare (or with a typo'd subcommand) has to
/// answer with something a human can act on, not just the one-line error
/// from the `bail!` in `main` below.
fn help_text() -> String {
    [
        format!(
            "qshd {} -- hands out channels to whoever proves their identity",
            env!("CARGO_PKG_VERSION")
        ),
        String::new(),
        "Usage: qshd <COMMAND> [OPTIONS]".to_string(),
        String::new(),
        "Commands:".to_string(),
        "  transport-echo    --port <P> [--client-pubkey <base64> ...] \
         [--server-key-file <path>]"
            .to_string(),
        "                    Diagnostic echo server, no PTY.".to_string(),
        "  transport-shell   --port <P> [--client-pubkey <base64> ...] \
         [--server-key-file <path>]"
            .to_string(),
        "                    Interactive shell over the transport, no daemonization.".to_string(),
        "  transport-ensure  --name <session> --port <P> [--default-port <D>] \
         [--client-pubkey <base64>]"
            .to_string(),
        "                    Self-installing, self-daemonizing production path, started \
         over SSH."
            .to_string(),
        "  serve             [--port <P>] [--authorized-keys <path>] [--host-key <path>]"
            .to_string(),
        "                    Long-lived daemon for a service manager (systemd/launchd); \
         see docs/qshd-service.md."
            .to_string(),
        "  self-check        Print this binary's build, architecture, protocol and handover \
         versions and transport features as JSON."
            .to_string(),
        String::new(),
        "Flags:".to_string(),
        "  --version, -V     Print the version and build stamp.".to_string(),
        "  --help, -h        Print this help.".to_string(),
    ]
    .join("\n")
        + "\n"
}

// `main` is deliberately NOT `#[tokio::main]`: the `transport-ensure`
// command daemonizes via `fork`, and forking a multi-threaded tokio
// process is undefined behavior. So the runtime is created manually, and
// ONLY after the fork (in the daemon) or in the diagnostic
// `transport-echo`/`transport-shell` -- each subcommand brings it up
// itself.
fn main() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();

    // A process a running daemon started by exec'ing its own replacement: it
    // IS the daemon already. Only this command reads the handover; any other
    // one drops a stray descriptor number so nothing it spawns inherits it.
    if args.first().map(OsString::as_os_str) == Some(OsStr::new("transport-resume")) {
        return run_transport_resume_command();
    }
    std::env::remove_var(handover::HANDOVER_FD_ENV);

    match args.first().map(|arg| argument_text(arg, 1)).transpose()? {
        Some("transport-echo") => run_transport_echo_command(&args),
        Some("transport-shell") => run_transport_shell_command(&args),
        Some("transport-ensure") => run_transport_ensure(&args),
        Some("serve") => serve::run_serve_command_os(&args),
        Some("self-check") => {
            print!("{}", state::SelfCheck::current().to_line());
            Ok(())
        }
        Some("--version") | Some("-V") => {
            print!("{}", version_text());
            Ok(())
        }
        Some("--help") | Some("-h") => {
            print!("{}", help_text());
            Ok(())
        }
        other => bail!(
            "expected command `transport-echo`, `transport-shell`, `transport-ensure`, \
             `serve` or `self-check` (or the `--version`/`--help` flags), got: {:?}",
            other
        ),
    }
}

fn argument_text(value: &OsStr, argument: usize) -> Result<&str> {
    value
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("argument {argument} must be valid UTF-8"))
}

/// Timeout for waiting until the old daemon releases the control
/// socket/port on the `Replace` branch (see `run_transport_ensure`): the
/// old daemon received `STOP` and should exit quickly (it has no active
/// connections left -- otherwise `reconcile` would have returned
/// `KeepOldWarn`, not `Replace`).
const RELEASE_TIMEOUT: Duration = Duration::from_secs(5);

/// Polls with increasing delay (under the overall [`RELEASE_TIMEOUT`])
/// whether a daemon just stopped via `STOP` has released the control
/// socket and the requested port: the socket file should disappear (the
/// daemon removes it before exiting), and the port should become bindable
/// again (checked via a trial bind-and-release, since the real bind for
/// production use will have to happen later anyway).
fn wait_for_daemon_release(sock_path: &Path, port: u16) -> Result<()> {
    let deadline = std::time::Instant::now() + RELEASE_TIMEOUT;
    let mut delay = Duration::from_millis(50);

    loop {
        let sock_gone = !sock_path.exists();
        let port_free = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).is_ok();
        if sock_gone && port_free {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            bail!(
                "the old qshd daemon did not release the control socket/port {port} within {:?}",
                RELEASE_TIMEOUT
            );
        }
        std::thread::sleep(delay);
        delay = (delay * 2).min(Duration::from_millis(500));
    }
}

/// The `transport-echo` command: a diagnostic echo server on the NEW
/// transport (the `transport::Connection` core via the `driver_tokio`
/// async driver). Brings up a single UDP socket, takes the server Noise
/// key from a persistent file (or creates one if missing), and prints its
/// public part as the line `server-pubkey: <base64>` -- the client reads
/// it over SSH.
fn run_transport_echo_command(args: &[OsString]) -> Result<()> {
    let parsed = parse_transport_echo_args(args)?;

    let cache_dir = default_cache_dir();
    let key_path = parsed
        .server_key_file
        .clone()
        .unwrap_or_else(|| default_transport_key_path(&cache_dir));
    let keypair = load_or_create_transport_key(&key_path)?;

    // The server's public key is this command's only line of stdout.
    println!("server-pubkey: {}", BASE64.encode(keypair.public));
    std::io::stdout().flush().context("flushing stdout")?;

    let cfg = transport::ConnectionConfig {
        required_features: transport::Features::NONE,
        features: transport::Features::from_bits(
            transport::Features::SUPPORTED.bits() & !transport::Features::AUTH_ACCEPTED.bits(),
        ),
        role: transport::Role::Server,
        local_static_priv: keypair.private,
        remote_static_pub: None,
        auth: transport::AuthPolicy::Allowlist(parsed.client_pubkeys),
    };
    let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), parsed.port);

    let runtime = tokio::runtime::Runtime::new().context("creating the runtime")?;
    runtime.block_on(async move {
        let socket = tokio::net::UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding port {}", parsed.port))?;
        transport::log_socket_buffers(&transport::tune_udp_buffers(&socket));
        transport::driver_tokio::serve_echo(socket, cfg).await;
        Ok::<(), anyhow::Error>(())
    })
}

/// Result of parsing `transport-echo --port <P> [--client-pubkey <base64>
/// ...] [--server-key-file <path>]`: `port` -- where to listen,
/// `client_pubkeys` -- the parsed 32-byte X25519 static client keys (the
/// server's allowlist, the flag can repeat), `server_key_file` -- an
/// optional path to the server Noise key file (defaults to qshd's cache
/// directory).
struct ParsedTransportEchoArgs {
    port: u16,
    client_pubkeys: Vec<[u8; 32]>,
    server_key_file: Option<PathBuf>,
}

/// Parses `transport-echo ...` by hand (mirrors the style of
/// `parse_echo_args`, no external CLI libraries). `--client-pubkey` can
/// repeat; each is the base64 of a client's 32-byte X25519 static key.
/// `--server-key-file` overrides the path to the server Noise key file.
fn parse_transport_echo_args(args: &[OsString]) -> Result<ParsedTransportEchoArgs> {
    let command = args.first().map(|arg| argument_text(arg, 1)).transpose()?;
    if command != Some("transport-echo") {
        bail!("expected command `transport-echo`, got: {:?}", command);
    }

    let mut port: Option<u16> = None;
    let mut client_pubkeys: Vec<[u8; 32]> = Vec::new();
    let mut server_key_file: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match argument_text(&args[i], i + 1)? {
            "--port" => {
                let value = args.get(i + 1).context("--port requires a value")?;
                let value = argument_text(value, i + 2)?;
                port = Some(value.parse().context("--port: expected a number 0-65535")?);
                i += 2;
            }
            "--client-pubkey" => {
                let value = args
                    .get(i + 1)
                    .context("--client-pubkey requires a value")?;
                let value = argument_text(value, i + 2)?;
                let raw = BASE64
                    .decode(value)
                    .context("--client-pubkey: expected valid base64")?;
                let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "--client-pubkey: expected 32 bytes of an X25519 key, got {}",
                        raw.len()
                    )
                })?;
                client_pubkeys.push(key);
                i += 2;
            }
            "--server-key-file" => {
                let value = args
                    .get(i + 1)
                    .context("--server-key-file requires a value")?;
                server_key_file = Some(PathBuf::from(value));
                i += 2;
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let port = port.context("--port is required")?;
    Ok(ParsedTransportEchoArgs {
        port,
        client_pubkeys,
        server_key_file,
    })
}

/// The `transport-shell` command: an interactive shell (`$SHELL` in a PTY)
/// over the NEW transport (the `transport::Connection` core via the
/// `shell_server` async bridge), unlike `transport-echo` which has no PTY.
/// Mirrors `transport-echo` in argument parsing and in printing
/// `server-pubkey:` (the same server Noise key from the persistent file).
/// Difference: the PTY is brought up SYNCHRONOUSLY, before the runtime
/// (`portable-pty` is blocking), and `serve_shell` is handed already-ready
/// master-side reader/writer and a resize handle. Does not touch
/// `transport-echo` -- it's a separate `match` arm in `main`.
fn run_transport_shell_command(args: &[OsString]) -> Result<()> {
    let parsed = parse_transport_shell_args(args)?;

    let cache_dir = default_cache_dir();
    let key_path = parsed
        .server_key_file
        .clone()
        .unwrap_or_else(|| default_transport_key_path(&cache_dir));
    let keypair = load_or_create_transport_key(&key_path)?;

    // The server's public key is the only protocol line on stdout.
    println!("server-pubkey: {}", BASE64.encode(keypair.public));
    std::io::stdout().flush().context("flushing stdout")?;

    let cfg = transport::ConnectionConfig {
        required_features: transport::Features::NONE,
        features: transport::Features::from_bits(
            transport::Features::SUPPORTED.bits() & !transport::Features::AUTH_ACCEPTED.bits(),
        ),
        role: transport::Role::Server,
        local_static_priv: keypair.private,
        remote_static_pub: None,
        auth: transport::AuthPolicy::Allowlist(parsed.client_pubkeys),
    };
    let addr = SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), parsed.port);

    // The PTY is brought up BEFORE the runtime: `portable-pty` is
    // blocking, and the shell itself needs to start living right away.
    // `try_clone_reader`/`take_writer` borrow `&self`, so `master` is then
    // handed over whole to the resize handle.
    let (master, mut child) =
        pty::spawn_shell(pty::DEFAULT_PTY_SIZE, None).context("starting the shell in a PTY")?;
    let reader = master
        .try_clone_reader()
        .context("getting the PTY master side's reader")?;
    let writer = master
        .take_writer()
        .context("getting the PTY master side's writer")?;
    let resize: Box<dyn transport::shell_server::ResizeHandle> =
        Box::new(pty::PtyResizeHandle::new(master));

    let runtime = tokio::runtime::Runtime::new().context("creating the runtime")?;
    runtime.block_on(async move {
        let socket = tokio::net::UdpSocket::bind(addr)
            .await
            .with_context(|| format!("binding port {}", parsed.port))?;
        transport::log_socket_buffers(&transport::tune_udp_buffers(&socket));
        transport::shell_server::serve_shell(socket, cfg, reader, writer, resize).await;
        Ok::<(), anyhow::Error>(())
    })?;

    // `serve_shell` returned -- the shell exited (EOF on the PTY read);
    // clean up the child process just in case (it's usually already dead).
    let _ = child.kill();
    let _ = child.wait();
    Ok(())
}

/// Result of parsing `transport-shell --port <P> [--client-pubkey <base64>
/// ...] [--server-key-file <path>]` -- the same fields with the same
/// meaning as [`ParsedTransportEchoArgs`] (parsing mirrors `transport-echo`).
struct ParsedTransportShellArgs {
    port: u16,
    client_pubkeys: Vec<[u8; 32]>,
    server_key_file: Option<PathBuf>,
}

/// Parses `transport-shell ...` by hand -- an exact copy of
/// [`parse_transport_echo_args`]'s logic (the same flags: `--port`, a
/// repeatable `--client-pubkey` as base64 of a 32-byte X25519 key,
/// `--server-key-file`).
fn parse_transport_shell_args(args: &[OsString]) -> Result<ParsedTransportShellArgs> {
    let command = args.first().map(|arg| argument_text(arg, 1)).transpose()?;
    if command != Some("transport-shell") {
        bail!("expected command `transport-shell`, got: {:?}", command);
    }

    let mut port: Option<u16> = None;
    let mut client_pubkeys: Vec<[u8; 32]> = Vec::new();
    let mut server_key_file: Option<PathBuf> = None;

    let mut i = 1;
    while i < args.len() {
        match argument_text(&args[i], i + 1)? {
            "--port" => {
                let value = args.get(i + 1).context("--port requires a value")?;
                let value = argument_text(value, i + 2)?;
                port = Some(value.parse().context("--port: expected a number 0-65535")?);
                i += 2;
            }
            "--client-pubkey" => {
                let value = args
                    .get(i + 1)
                    .context("--client-pubkey requires a value")?;
                let value = argument_text(value, i + 2)?;
                let raw = BASE64
                    .decode(value)
                    .context("--client-pubkey: expected valid base64")?;
                let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "--client-pubkey: expected 32 bytes of an X25519 key, got {}",
                        raw.len()
                    )
                })?;
                client_pubkeys.push(key);
                i += 2;
            }
            "--server-key-file" => {
                let value = args
                    .get(i + 1)
                    .context("--server-key-file requires a value")?;
                server_key_file = Some(PathBuf::from(value));
                i += 2;
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let port = port.context("--port is required")?;
    Ok(ParsedTransportShellArgs {
        port,
        client_pubkeys,
        server_key_file,
    })
}

/// Result of parsing `transport-ensure --name <session> --port <P>
/// [--default-port <D>] [--client-pubkey <base64>]`:
/// `name` is REQUIRED by the parser (the client passes `--name s5-<id>`),
/// but the daemon hands out channels rather than driving tmux itself, so it
/// has no session to pick by it: it only travels in the handover of an
/// update, as a label;
/// `port` -- the port requested by this call; `default_port` -- the
/// daemon's default port EXACTLY AS passed by the flag (`None` if the flag
/// wasn't given -- unlike the old `ensure`'s `ParsedEnsureArgs::default_port`,
/// where a missing flag is immediately substituted with the current
/// `port`; here the caller's original intent is preserved, so the next
/// task (daemonization and reuse via the control socket) can tell
/// "default-port not given" apart from "default-port equals port" when
/// making decisions); `ports` -- the set of ports for the initial bind:
/// the union of `{port}` and `{default_port}` (if given), no duplicates;
/// `client_pubkey` -- an optional client static Noise key (32-byte X25519,
/// already decoded from base64) to add to the new transport's IN-MEMORY
/// allowlist -- via `ADD-CLIENT` if reusing a live daemon, or seeded into
/// [`transport_daemon::build_server_allowlist`] if becoming the daemon.
struct ParsedTransportEnsureArgs {
    name: String,
    port: u16,
    // Part of the CLI parsing contract (checked by unit tests), but not
    // yet consumed by the daemon body: the new transport roams natively
    // by changing the source address on a SINGLE port (the manager serves
    // one socket), so `become_transport_daemon` only listens on `port`. The
    // flag is kept for symmetry with `ensure` and for future use.
    #[allow(dead_code)]
    default_port: Option<u16>,
    ports: Vec<u16>,
    client_pubkey: Option<[u8; 32]>,
}

/// Parses `transport-ensure ...` by hand -- combines the `--port`/
/// `--default-port` flags in the style of [`parse_ensure_args_full`] with
/// a `--client-pubkey` shaped like (but not in count -- here there is
/// exactly one key) the repeatable one from the `transport-*` commands,
/// plus a REQUIRED `--name` (see [`ParsedTransportEnsureArgs`]).
fn parse_transport_ensure_args(args: &[OsString]) -> Result<ParsedTransportEnsureArgs> {
    let command = args.first().map(|arg| argument_text(arg, 1)).transpose()?;
    if command != Some("transport-ensure") {
        bail!("expected command `transport-ensure`, got: {:?}", command);
    }

    let mut name: Option<String> = None;
    let mut port: Option<u16> = None;
    let mut default_port: Option<u16> = None;
    let mut client_pubkey: Option<[u8; 32]> = None;

    let mut i = 1;
    while i < args.len() {
        match argument_text(&args[i], i + 1)? {
            "--name" => {
                let value = args.get(i + 1).context("--name requires a value")?;
                let value = argument_text(value, i + 2)?;
                name = Some(value.to_owned());
                i += 2;
            }
            "--port" => {
                let value = args.get(i + 1).context("--port requires a value")?;
                let value = argument_text(value, i + 2)?;
                port = Some(value.parse().context("--port: expected a number 0-65535")?);
                i += 2;
            }
            "--default-port" => {
                let value = args.get(i + 1).context("--default-port requires a value")?;
                let value = argument_text(value, i + 2)?;
                default_port = Some(
                    value
                        .parse()
                        .context("--default-port: expected a number 0-65535")?,
                );
                i += 2;
            }
            "--client-pubkey" => {
                let value = args
                    .get(i + 1)
                    .context("--client-pubkey requires a value")?;
                let value = argument_text(value, i + 2)?;
                let raw = BASE64
                    .decode(value)
                    .context("--client-pubkey: expected valid base64")?;
                let key: [u8; 32] = raw.as_slice().try_into().map_err(|_| {
                    anyhow::anyhow!(
                        "--client-pubkey: expected 32 bytes of an X25519 key, got {}",
                        raw.len()
                    )
                })?;
                client_pubkey = Some(key);
                i += 2;
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    let name = name.context("--name is required")?;
    let port = port.context("--port is required")?;
    let mut ports = vec![port];
    if let Some(default_port) = default_port {
        if default_port != port {
            ports.push(default_port);
        }
    }

    Ok(ParsedTransportEnsureArgs {
        name,
        port,
        default_port,
        ports,
        client_pubkey,
    })
}

/// Body of the `TRANSPORT-READY` line (see [`write_transport_ready`]) --
/// the minimal set of fields the new transport's client bootstrap will
/// need to parse: `version` -- the same
/// `qshd` version string as in the old path's `QSH-READY`/`server.json`
/// ([`state::QSHD_VERSION`]); `ports` -- the ports the daemon actually listens on. A separate
/// struct from `ServerState` rather than reuse: the new transport doesn't
/// need `cert_fingerprint`/`pid` -- there's no mTLS certificate here at
/// all, trust comes via the Noise key, which is printed as a separate
/// `server-pubkey:` line before this one. `#[derive(Serialize)]`
/// serializes the fields in declaration order -- `version`, then `ports`,
/// then `warning`.
#[derive(Serialize)]
struct TransportReadyBody {
    version: String,
    /// The ports the daemon actually listens on -- for a live daemon, from
    /// its `STATUS`, not the ones this call asked for.
    ports: Vec<u16>,
    /// Present (non-null) only when the daemon was kept because other
    /// clients are active and its version differs -- the app shows this as
    /// a connect/cancel dialog. Serialized as `null` otherwise (no
    /// `#[serde(skip_serializing_if)]`: the field is always present in the
    /// JSON, the client tolerates both `null` and an absent field).
    warning: Option<String>,
}

/// The ports to put in `TRANSPORT-READY` when reusing a live daemon: the
/// ones it says it listens on. A status that lists no ports (a daemon
/// that reports none, or a malformed answer) falls back to the requested
/// ones, which is what the call reported before this fix.
fn ready_ports(status: &control::StatusResponse, requested: &[u16]) -> Vec<u16> {
    if status.ports.is_empty() {
        requested.to_vec()
    } else {
        status.ports.iter().map(|p| p.port).collect()
    }
}

/// Prints exactly two protocol lines of the new transport to `w` -- first
/// `server-pubkey: <base64>` (the server's static public Noise key, which
/// the client pins as the SSH host key -- the same approach already used
/// by `run_transport_echo_command`/`run_transport_shell_command`), then
/// `TRANSPORT-READY {json}` (see [`TransportReadyBody`]) -- and flushes the
/// output buffer. Writes to the given `Write` rather than directly to
/// `std::io::stdout()`: this way output parsing is unit-tested without
/// capturing global stdout; the production call (`become_transport_daemon`)
/// will pass `std::io::stdout()` -- in the parent process, BEFORE the fork.
fn write_transport_ready(
    w: &mut impl Write,
    pubkey: &[u8; 32],
    ports: &[u16],
    warning: Option<&str>,
) -> Result<()> {
    writeln!(w, "server-pubkey: {}", BASE64.encode(pubkey)).context("printing server-pubkey")?;
    let body = TransportReadyBody {
        version: state::QSHD_VERSION.to_string(),
        ports: ports.to_vec(),
        warning: warning.map(str::to_string),
    };
    let json = serde_json::to_string(&body).context("serializing TRANSPORT-READY to JSON")?;
    writeln!(w, "TRANSPORT-READY {json}").context("printing TRANSPORT-READY")?;
    w.flush().context("flushing output")
}

/// Bound contention separately from the client's total ensure budget.
const ENSURE_LOCK_WAIT: Duration = Duration::from_secs(5);

/// The `transport-ensure` subcommand: a self-installing SELF-DAEMONIZING
/// server for the NEW transport, that survives the SSH `exec` closing.
/// Mirrors the structure of the removed qsh path's
/// `run_ensure`, but on the transport's UDP socket and with a Noise key
/// allowlist instead of quinn/mTLS:
///
/// 1. we poll the control socket: the daemon is alive and up to date
///    (`UpToDate`/`KeepOldWarn`) -> live-add the key (`ADD-CLIENT`, IN-MEMORY
///    ONLY), print `TRANSPORT-READY`
///    using our own server key (the same file the daemon uses) and exit
///    without forking; the daemon is stale (`Replace`) -> `STOP` + wait for
///    release and become the daemon; there is no daemon -> become the
///    daemon;
/// 2. [`become_transport_daemon`] binds the UDP socket and the control
///    socket synchronously, seeding the initial IN-MEMORY allowlist from
///    `--client-pubkey` alone ([`transport_daemon::build_server_allowlist`]
///    -- there is no on-disk set to union with anymore), prints ready in the
///    parent, and daemonizes.
fn run_transport_ensure(args: &[OsString]) -> Result<()> {
    let parsed = parse_transport_ensure_args(args)?;

    let cache_dir = default_cache_dir();
    let sock_path = control_sock_path(&cache_dir);
    let transaction = control::EnsureLock::acquire(&sock_path, ENSURE_LOCK_WAIT)
        .context("locking the transport ensure transaction")?;

    // The server Noise key is read/created from the same file the daemon
    // uses (`load_or_create_transport_key`): when reusing a live daemon,
    // its public part is printed in `TRANSPORT-READY` -- it matches the
    // daemon's key byte-for-byte (same file), so the client sees a stable
    // `server-pubkey`, like an SSH host key.
    let key_path = default_transport_key_path(&cache_dir);
    let keypair = load_or_create_transport_key(&key_path)?;

    // Try the control socket BEFORE binding our own sockets -- like
    // `run_ensure`: is a daemon already alive.
    match ask_status(&sock_path)? {
        control::ControlReply::Answered(line) => {
            let status = control::StatusResponse::from_line(&line)
                .context("parsing the transport control socket's STATUS response")?;
            let action =
                version::reconcile(state::build_label(), &state::self_checksum()?, &status);
            // `KeepOldWarn` is a `Reuse` too (see `decide_reuse` below) --
            // the reason is both logged to stderr (unchanged) and carried
            // into `TRANSPORT-READY` so the app can surface it to the user.
            let warning: Option<String> = match &action {
                version::ReconcileAction::KeepOldWarn(reason) => {
                    eprintln!("qshd: {reason}");
                    Some(reason.clone())
                }
                _ => None,
            };
            match transport_daemon::decide_reuse(&action) {
                transport_daemon::EnsureDecision::Reuse => {
                    // The live daemon is up to date: live-add the client
                    // key to its IN-MEMORY allowlist, then print
                    // `TRANSPORT-READY` and exit -- no fork.
                    if let Some(pubkey) = parsed.client_pubkey {
                        control::client_request(
                            &sock_path,
                            &control::ControlRequest::AddClient(pubkey),
                        )?;
                    }
                    write_transport_ready(
                        &mut std::io::stdout(),
                        &keypair.public,
                        &ready_ports(&status, &parsed.ports),
                        warning.as_deref(),
                    )?;
                    return Ok(());
                }
                transport_daemon::EnsureDecision::BecomeDaemon => {
                    // The daemon is stale (`Replace`): ask it to stop,
                    // wait for the socket/port to be released, and become
                    // the daemon ourselves.
                    control::client_request(&sock_path, &control::ControlRequest::Stop)?;
                    wait_for_daemon_release(&sock_path, parsed.port)?;
                    // Falls through to the "become the daemon" branch below.
                }
            }
        }
        control::ControlReply::NoDaemon => {
            // No daemon -- falls through to the "become the daemon" branch below.
        }
        control::ControlReply::TimedOut => {
            // The connection was ACCEPTED -- twice, `ask_status` asked
            // again -- so a daemon holds the control socket: it is alive,
            // merely too slow to answer `STATUS` within `CLIENT_READ_TIMEOUT` (e.g. hashing its own executable
            // under CPU load, before that got cached -- see
            // `state::self_checksum`). This is NOT "no daemon": binding our
            // own UDP socket now would race a daemon that is still there and
            // either fail with a misleading "old version" `AddrInUse` (if it
            // still holds the port) or -- worse -- succeed and produce a
            // second, orphaned daemon fighting the first one for the same
            // socket. Fail honestly instead of guessing which happened.
            anyhow::bail!(
                "qshd's control socket is busy: the daemon is alive but did not answer \
                 within {}s -- probably busy with internal work right now; try connecting \
                 again.",
                control::CLIENT_READ_TIMEOUT.as_secs()
            );
        }
    }

    // The initial allowlist for starting the session manager -- IN-MEMORY
    // only, just this call's `--client-pubkey` (no on-disk set to union
    // with anymore).
    let allowlist = transport_daemon::build_server_allowlist(parsed.client_pubkey);
    become_transport_daemon(
        &parsed,
        &cache_dir,
        &sock_path,
        keypair,
        allowlist,
        transaction,
    )
}

/// How long `transport-ensure` waits before asking a second time when the
/// first `STATUS` went unanswered.
const REPLACEMENT_RETRY: Duration = Duration::from_millis(500);

/// `STATUS`, asked a second time -- [`REPLACEMENT_RETRY`] later -- when the
/// first went unanswered: closed without an answer while the socket file is
/// there, or accepted and not answered in time. A daemon replacing itself
/// does exactly that: the connections it had accepted do not survive its
/// exec (and those that arrive during it wait on the control gate), while
/// the listening socket does -- a moment later the same socket answers from
/// the new binary. Reading that as "no daemon" would send this process off
/// to bind a port the daemon still holds. A genuinely stale socket file
/// costs half a second here.
fn ask_status(sock_path: &Path) -> Result<control::ControlReply> {
    ask_status_with(sock_path, REPLACEMENT_RETRY, || {
        control::client_request(sock_path, &control::ControlRequest::Status)
    })
}

/// [`ask_status`] with the request and the pause passed in.
fn ask_status_with(
    sock_path: &Path,
    pause: Duration,
    mut ask: impl FnMut() -> Result<control::ControlReply>,
) -> Result<control::ControlReply> {
    let first = ask()?;
    let again = match &first {
        control::ControlReply::Answered(_) => false,
        control::ControlReply::NoDaemon => sock_path.exists(),
        control::ControlReply::TimedOut => true,
    };
    if !again {
        return Ok(first);
    }
    std::thread::sleep(pause);
    ask()
}

/// Becomes the transport daemon: binds the transport's UDP socket and the
/// control Unix socket SYNCHRONOUSLY, BEFORE the fork (the tokio runtime
/// does not survive `fork`, so everything async only happens after
/// `daemonize().execute()`), prints `TRANSPORT-READY` in the parent, and
/// daemonizes. From here on only the detached daemon runs --
/// [`transport_daemon::run_transport_daemon`].
///
/// The transport listens on EXACTLY ONE port (`parsed.port`): the new
/// transport roams natively by changing the source address on a single
/// socket (unlike qsh's port range), and the session manager serves exactly
/// one socket. `--default-port` is parsed for CLI compatibility, but no
/// second socket is brought up here.
fn become_transport_daemon(
    parsed: &ParsedTransportEnsureArgs,
    cache_dir: &Path,
    sock_path: &Path,
    keypair: transport::handshake::Keypair,
    allowlist: Vec<[u8; 32]>,
    transaction: control::EnsureLock,
) -> Result<()> {
    // The transport's UDP socket -- synchronously, before the fork (like `become_daemon`).
    let socket = match UdpSocket::bind((Ipv4Addr::UNSPECIFIED, parsed.port)) {
        Ok(socket) => socket,
        Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
            // We only get here after confirming (via `client_request`)
            // that there is no live daemon with a control socket. So the
            // port is held by SOME OTHER process with no control socket
            // -- likely an old-version daemon. Print what to do (like
            // `become_daemon`).
            anyhow::bail!(
                "port {} is already taken by another process, and qshd's control socket is \
                 not answering -- probably an old-version daemon is running on the server \
                 (without a control socket). Stop it (`pkill qshd`) and try connecting again.",
                parsed.port
            );
        }
        Err(e) => {
            return Err(anyhow::Error::new(e))
                .with_context(|| format!("binding port {}", parsed.port));
        }
    };

    // The control socket -- also synchronously, before the fork, owner-only
    // from its first instant (spec §4.16, QSH-14). By this point there is
    // definitely no live daemon (see `run_transport_ensure`), so a file at
    // the name is a stale one, and `bind_private` replaces it.
    let (listener, mut cleanup) = control::bind_private_owned(sock_path)
        .with_context(|| format!("binding the control socket {}", sock_path.display()))?;
    let bound_port = socket
        .local_addr()
        .context("reading the bound UDP port")?
        .port();

    // Print `TRANSPORT-READY` in the PARENT, BEFORE the fork: otherwise
    // the SSH `exec` won't see the lines (the same criticality as
    // `print_ready` in `become_daemon`).
    // Only the port actually bound is reported: `--default-port` is parsed
    // but not bound here.
    write_transport_ready(
        &mut std::io::stdout(),
        &keypair.public,
        std::slice::from_ref(&bound_port),
        None,
    )?;

    // Daemonize: the parent exits after its upstream outcome (the SSH `exec` gets
    // EOF and returns the captured lines), the daemon inherits the bound
    // sockets.
    match daemonize::Daemonize::new().execute() {
        daemonize::Outcome::Parent(result) => {
            // Even a parent wait error does not prove that its forked child
            // failed. Only the child's own guard may now unlink publication.
            cleanup.leave_to_child();
            let parent = result.context("daemonizing qshd (transport parent)")?;
            std::process::exit(parent.first_child_exit_code);
        }
        daemonize::Outcome::Child(result) => {
            result.context("daemonizing qshd (transport child)")?;
        }
    }
    // Parent/intermediate copies close when daemonize exits them. The final
    // child releases its copy after publication/fork, before serving requests.
    drop(transaction);

    // From here on -- ONLY the daemon. stdout/stderr went to /dev/null:
    // events and panics are written to `<cache_dir>/qshd.log`.
    log::init(cache_dir);
    std::panic::set_hook(Box::new(|info| {
        log::error("qshd", &format!("PANIC: {info}"));
    }));

    let binary_path = state::own_binary_path().unwrap_or_else(|e| {
        log::warn(
            "qshd",
            &format!("cannot tell where its own binary is ({e:#}); updates over qsh are off"),
        );
        PathBuf::new()
    });
    run_personal_daemon(PersonalStart {
        socket,
        listener,
        keypair,
        allowlist,
        cache_dir: cache_dir.to_path_buf(),
        sock_path: sock_path.to_path_buf(),
        cleanup,
        port: bound_port,
        ports: parsed
            .ports
            .iter()
            .map(|&port| {
                if port == parsed.port {
                    bound_port
                } else {
                    port
                }
            })
            .collect(),
        name: parsed.name.clone(),
        binary_path,
    })
}

/// Everything the personal daemon's body starts from: a fresh daemon after
/// the fork, or a replaced one after its `exec` (`run_transport_resume`).
struct PersonalStart {
    socket: UdpSocket,
    listener: std::os::unix::net::UnixListener,
    keypair: transport::handshake::Keypair,
    allowlist: Vec<[u8; 32]>,
    cache_dir: PathBuf,
    sock_path: PathBuf,
    cleanup: control::SocketCleanup,
    port: u16,
    ports: Vec<u16>,
    name: String,
    /// Where this daemon's binary lives -- read from `/proc/self/exe` by the
    /// daemon itself (directly, or by the process it replaced), never taken
    /// from a client. Empty when that could not be read: no updates then.
    binary_path: PathBuf,
}

/// The personal daemon's body: the session router with the channel backend
/// speaking for the daemon, and the control server, in one runtime. The
/// caller has already set up the log and the panic hook.
///
/// Three things are shared between the router, the control server and the
/// update service, and each is made exactly once here: the active-session
/// counter (the router keeps it, the update service reads it), the control
/// gate (the control server holds it for reading per request, a replacement
/// takes it for writing), and the admission gate (the router's nonce source
/// refuses while it is closed, a replacement closes it through its exec).
fn run_personal_daemon(start: PersonalStart) -> Result<()> {
    // The manager's backend-lifecycle notices (cap-eviction / rejection / GC
    // teardown -- "no silent cap") are `log` records of the `transport`
    // component: `log::init`, already called, routes them into `qshd.log`.

    let udp_fd = start.socket.as_raw_fd();
    let control_fd = start.listener.as_raw_fd();
    // Shared in-memory allowlist: the control server mutates it on
    // `ADD-CLIENT`, and `SessionManager::serve` snapshots it FRESH at every
    // handshake -- so a live-added key is honored without a restart, and an
    // ended session's key is scrubbed off it (self-cleaning).
    let shared_allowlist: transport_daemon::SharedAllowlist =
        Arc::new(std::sync::Mutex::new(start.allowlist));
    let active_count = Arc::new(AtomicUsize::new(0));
    let control_gate = Arc::new(tokio::sync::RwLock::new(()));
    let admission = Arc::new(update::AdmissionGate::default());

    // The same session backend `serve` hands its router: the daemon has no
    // startup session of its own to decide, and no tmux to drive -- it hands
    // out channels, and what to put in them (attaching to an existing tmux
    // session or something else entirely) is the client's decision now.
    let mut backend = channel_backend::ChannelSessionBackend::new(Arc::new(
        qshd::screen_budget::ScreenBudget::new(qshd::screen_budget::BudgetLimits::default()),
    ));
    if !start.binary_path.as_os_str().is_empty() {
        // `None`: the checksum is worked out on the first `About`, off the
        // start-up path. `personal` sweeps away staged files an update that
        // never finished left behind -- all but the one this process may be
        // running from, should its rename have failed.
        let opens = backend.open_registry();
        backend = backend.with_daemon(Arc::new(update::DaemonSelf::personal(
            opens,
            None,
            start.binary_path.clone(),
            nix::unistd::Uid::current().as_raw(),
            Arc::clone(&active_count),
            Some(update::HandoverBase {
                udp_fd,
                control_fd,
                control_path: start.sock_path.clone(),
                cache_dir: start.cache_dir.clone(),
                port: start.port,
                ports: start.ports.clone(),
                name: start.name.clone(),
                allowlist: Arc::clone(&shared_allowlist),
                control_gate: Arc::clone(&control_gate),
                admission: Arc::clone(&admission),
            }),
        )));
    }
    // Otherwise already logged by the caller: with nowhere to rename a new
    // binary onto, this daemon does not answer `About` and takes no image.

    let runtime =
        tokio::runtime::Runtime::new().context("creating the transport daemon's runtime")?;
    runtime.block_on(async {
        let mut signals = transport_daemon::PersonalSignals::register()?;
        transport_daemon::run_transport_daemon_until_stop(
            start.socket,
            start.keypair.private,
            personal_server_auth(shared_allowlist, start.keypair.public, admission),
            Arc::new(backend),
            start.listener,
            start.cleanup,
            vec![start.port],
            active_count,
            control_gate,
            signals.requested(),
        )
        .await
    })
}

/// The authentication of a `transport-ensure` daemon: two gates, because
/// two kinds of client reach this daemon. The app arrives with its key
/// already on the allowlist, put there over SSH by the very
/// `transport-ensure` invocation that started this daemon. A console client
/// cannot arrive that way -- it takes a fresh Noise static key for every
/// connection, so there is nothing an allowlist could hold -- and proves
/// itself by signing with an SSH key instead, checked against the same
/// `authorized_keys` that `serve` uses. Without the verifier the user would
/// need a second daemon on a second port to reach the very same shell.
///
/// This widens nothing: whoever can sign with a key in `authorized_keys` can
/// already log in over SSH and start anything at all, this daemon included.
///
/// One deliberate side effect: the manager answers a key-discovery request
/// only when a verifier is set, so this daemon tells anyone who asks what
/// its public key is. That is what lets a console client reach a host it has
/// never pinned, and it is the exposure `serve` has always accepted -- a
/// fingerprint of the service, and nothing that admits anybody.
///
/// `admission` closes both gates at once: the router asks the nonce source
/// once for every handshake it is about to admit, on either path, and a
/// replacement closes this gate from its last count of the sessions through
/// its exec (see `update::GatedNonces`).
fn personal_server_auth(
    allowlist: transport_daemon::SharedAllowlist,
    server_pub: [u8; 32],
    admission: Arc<update::AdmissionGate>,
) -> transport::ServerAuth {
    transport::ServerAuth {
        allowlist,
        verifier: signature_verifier(),
        server_pub,
        // The app's key is on the allowlist itself -- there is no verifier,
        // and so no `Principal`, on that path. It runs as this daemon's own
        // account, the same one `signature_verifier` hands its own verifier.
        self_principal: {
            let uid = nix::unistd::Uid::current().as_raw();
            let name = std::env::var("USER")
                .or_else(|_| std::env::var("LOGNAME"))
                .unwrap_or_else(|_| uid.to_string());
            transport::Principal {
                uid,
                name,
                identity: "allowlist".to_string(),
                incarnation: 0,
            }
        },
        // `transport-ensure` never runs the system mode (that is `serve
        // --system`'s job), so there is no privileged helper here to ask
        // instead -- mint locally, the same as every other personal-mode
        // daemon, behind the admission gate.
        nonces: Arc::new(update::GatedNonces::new(
            Arc::new(qshd::RandomNonces),
            admission,
        )),
        // One login, no PAM session, nothing else keyed by a login -- see
        // `ForgetNothing`'s own docs.
        logins: Arc::new(qshd::ForgetNothing),
    }
}

/// `transport-resume`: take the handover this process was exec'd with and
/// go on being the daemon. A handover that is missing or cannot be read is
/// fatal -- and logged first, to the log of the cache directory this
/// process would have used: its stdout and stderr lead nowhere, and a
/// daemon that vanished after an update is looked for in its log.
fn run_transport_resume_command() -> Result<()> {
    let refuse = |why: String| -> anyhow::Error {
        log::init(&default_cache_dir());
        log::error("update", &format!("transport-resume: {why}"));
        anyhow::anyhow!(why)
    };
    // SAFETY: main enters this branch before opening descriptors or starting
    // threads. The inherited raw descriptors have no Rust owners in this image;
    // validation rejects malformed numbers before any ownership construction.
    match unsafe { handover::take_from_env() } {
        Ok(Some(handover)) => run_transport_resume(handover),
        Ok(None) => Err(refuse(format!(
            "started without a handover ({} is not set): this command is only ever run by a \
             daemon replacing itself",
            handover::HANDOVER_FD_ENV
        ))),
        Err(e) => Err(refuse(format!("{e:#}"))),
    }
}

/// The daemon, started again by its own `exec` of an accepted update
/// (spec §4.4, §4.5): rename itself onto the binary's path, take over the
/// sockets, and carry on -- no fork, no fresh bind, no new control socket.
fn run_transport_resume(handover: handover::PreparedHandover) -> Result<()> {
    log::init(&handover.description().cache_dir);
    std::panic::set_hook(Box::new(|info| {
        log::error("qshd", &format!("PANIC: {info}"));
    }));
    let result = resume_personal_daemon(handover);
    if let Err(e) = &result {
        log::error("update", &format!("transport-resume: {e:#}"));
    }
    result
}

fn resume_personal_daemon(handover: handover::PreparedHandover) -> Result<()> {
    // A failed rename leaves this process running from the staged path
    // (which `DaemonSelf::personal` then keeps, as its own executable) and
    // the old file at the binary's path. `About` and `STATUS` hash
    // `/proc/self/exe` -- the new image this process runs -- so the next
    // check does not see the old file and offers nothing: the daemon runs
    // the new build until it exits. The stale file at the binary's path is
    // replaced on the next daemon start.
    if let Err(e) = handover.settle_binary() {
        log::warn("update", &format!("{e:#}"));
    }
    let (handover, socket, listener, allowlist) = handover.into_parts();
    let cleanup = control::SocketCleanup::capture(&listener, &handover.control_path)
        .context("retaining the inherited control socket publication")?;
    let keypair = load_or_create_transport_key(&default_transport_key_path(&handover.cache_dir))?;
    log::info(
        "update",
        &format!(
            "resumed after an update: pid={} build={}",
            std::process::id(),
            state::build_label()
        ),
    );
    run_personal_daemon(PersonalStart {
        socket,
        listener,
        keypair,
        allowlist,
        cache_dir: handover.cache_dir.clone(),
        sock_path: handover.control_path.clone(),
        cleanup,
        port: handover.port,
        ports: handover.ports.clone(),
        name: handover.name.clone(),
        binary_path: handover.binary_path.clone(),
    })
}

/// The signature gate for a `transport-ensure` daemon: the user's own
/// `~/.ssh/authorized_keys`, the same file `serve` checks.
///
/// `None` when `HOME` is unset, which leaves only the allowlist. That is a
/// degraded gate, not an open one, and it is the honest answer: without
/// `HOME` there is no file to name, and guessing one (the working directory,
/// say) would decide who may open a shell here from wherever the daemon
/// happened to be launched. A daemon started the normal way -- over SSH, by
/// the app -- always has `HOME`.
///
/// A missing or unreadable file is not fatal either: `AuthorizedKeysVerifier`
/// reads it per handshake, so a file created later starts working without a
/// restart, and one that never appears simply admits nobody by signature.
fn signature_verifier() -> Option<Arc<dyn transport::AuthVerifier>> {
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        log::warn(
            "qshd",
            "HOME not set, signature login disabled -- \
             only the key list remains",
        );
        return None;
    };
    let path = home.join(".ssh").join("authorized_keys");
    log::info("qshd", &format!("signature login via {}", path.display()));
    // The account this daemon serves -- it runs as exactly one. The name is
    // a log label only (nothing selects an account here), so the
    // environment is a good enough source and keeps the static musl build
    // free of an NSS lookup.
    let uid = nix::unistd::Uid::current().as_raw();
    let name = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .unwrap_or_else(|_| uid.to_string());
    Some(Arc::new(sshauth::verify::AuthorizedKeysVerifier::new(
        path, uid, name,
    )))
}

/// Default path for the server Noise key file: `transport_server_key.bin`
/// in the daemon's cache directory -- alongside `cert.der`/`server.json`.
fn default_transport_key_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("transport_server_key.bin")
}

/// Default daemon cache directory: `dirs::cache_dir()` (on Linux --
/// `$XDG_CACHE_HOME`, or `~/.cache` if the variable isn't set) plus `qsh`.
/// Tests use a different directory -- passed directly to the caller as a
/// parameter (`default_transport_key_path`/`state`); this function is not
/// involved there.
fn default_cache_dir() -> PathBuf {
    dirs::cache_dir()
        .unwrap_or_else(|| PathBuf::from(".cache"))
        .join("qsh")
}

/// Path to the daemon's control Unix socket: `control.sock` in the cache
/// directory -- alongside `server.json`/certificate/key.
fn control_sock_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("control.sock")
}

#[cfg(test)]
mod tests {
    use super::{
        ask_status_with, control, help_text, load_or_create_transport_key,
        parse_transport_echo_args, parse_transport_ensure_args, parse_transport_shell_args,
        personal_server_auth, ready_ports, state, update, version_text, write_transport_ready,
    };
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine as _;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    #[test]
    fn transport_os_paths_preserve_bytes_and_existing_option_boundaries() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        fn path(command: &str, args: &[OsString]) -> anyhow::Result<Option<std::path::PathBuf>> {
            match command {
                "transport-echo" => Ok(parse_transport_echo_args(args)?.server_key_file),
                _ => Ok(parse_transport_shell_args(args)?.server_key_file),
            }
        }
        for command in ["transport-echo", "transport-shell"] {
            for value in [
                OsString::from_vec(b"key-\xff".to_vec()),
                "--help".into(),
                "--".into(),
            ] {
                let argv = [
                    command.into(),
                    "--port".into(),
                    "0".into(),
                    "--server-key-file".into(),
                    value.clone(),
                ];
                assert_eq!(path(command, &argv).unwrap(), Some(value.into()));
            }
            let missing = [command.into(), "--server-key-file".into()];
            assert_eq!(
                path(command, &missing).unwrap_err().to_string(),
                "--server-key-file requires a value"
            );
            for trailing in [vec![], vec![OsString::from_vec(vec![0xff])]] {
                let mut argv = vec![command.into(), "--".into()];
                argv.extend(trailing);
                assert_eq!(
                    path(command, &argv).unwrap_err().to_string(),
                    "unknown argument: --"
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn transport_text_values_require_utf8_at_the_consumed_position() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        for command in ["transport-echo", "transport-shell", "transport-ensure"] {
            for flag in ["--port", "--client-pubkey"] {
                let argv = [command.into(), flag.into(), OsString::from_vec(vec![0xff])];
                let error = match command {
                    "transport-echo" => parse_transport_echo_args(&argv).err(),
                    "transport-shell" => parse_transport_shell_args(&argv).err(),
                    _ => parse_transport_ensure_args(&argv).err(),
                }
                .unwrap();
                assert_eq!(error.to_string(), "argument 3 must be valid UTF-8");
            }
        }
        for flag in ["--name", "--default-port"] {
            let argv = [
                "transport-ensure".into(),
                flag.into(),
                OsString::from_vec(vec![0xff]),
            ];
            assert_eq!(
                parse_transport_ensure_args(&argv)
                    .err()
                    .unwrap()
                    .to_string(),
                "argument 3 must be valid UTF-8"
            );
        }
        let argv = [
            "transport-ensure".into(),
            "--".into(),
            OsString::from_vec(vec![0xff]),
        ];
        assert_eq!(
            parse_transport_ensure_args(&argv)
                .err()
                .unwrap()
                .to_string(),
            "unknown argument: --"
        );
    }

    fn args(items: &[&str]) -> Vec<std::ffi::OsString> {
        items.iter().map(std::ffi::OsString::from).collect()
    }

    #[test]
    fn requires_transport_echo_command() {
        assert!(parse_transport_echo_args(&args(&["--port", "60001"])).is_err());
    }

    #[test]
    fn transport_echo_requires_port() {
        assert!(parse_transport_echo_args(&args(&["transport-echo"])).is_err());
    }

    #[test]
    fn transport_echo_parses_port_without_extras() {
        let parsed =
            parse_transport_echo_args(&args(&["transport-echo", "--port", "60001"])).unwrap();
        assert_eq!(parsed.port, 60001);
        assert!(parsed.client_pubkeys.is_empty());
        assert!(parsed.server_key_file.is_none());
    }

    #[test]
    fn transport_echo_parses_repeated_client_pubkeys() {
        let key_a = B64.encode([1u8; 32]);
        let key_b = B64.encode([2u8; 32]);
        let parsed = parse_transport_echo_args(&args(&[
            "transport-echo",
            "--port",
            "60001",
            "--client-pubkey",
            &key_a,
            "--client-pubkey",
            &key_b,
        ]))
        .unwrap();
        assert_eq!(parsed.client_pubkeys, vec![[1u8; 32], [2u8; 32]]);
    }

    #[test]
    fn transport_echo_rejects_wrong_length_pubkey() {
        // Base64 of three bytes -- valid base64, but not a 32-byte key.
        let short = B64.encode([9u8; 3]);
        assert!(parse_transport_echo_args(&args(&[
            "transport-echo",
            "--port",
            "60001",
            "--client-pubkey",
            &short,
        ]))
        .is_err());
    }

    #[test]
    fn transport_echo_parses_server_key_file() {
        let parsed = parse_transport_echo_args(&args(&[
            "transport-echo",
            "--port",
            "60001",
            "--server-key-file",
            "/tmp/qsh-key.bin",
        ]))
        .unwrap();
        assert_eq!(
            parsed.server_key_file.as_deref(),
            Some(std::path::Path::new("/tmp/qsh-key.bin"))
        );
    }

    #[test]
    fn requires_transport_shell_command() {
        assert!(parse_transport_shell_args(&args(&["--port", "60001"])).is_err());
    }

    #[test]
    fn transport_shell_requires_port() {
        assert!(parse_transport_shell_args(&args(&["transport-shell"])).is_err());
    }

    #[test]
    fn transport_shell_parses_port_without_extras() {
        let parsed =
            parse_transport_shell_args(&args(&["transport-shell", "--port", "60001"])).unwrap();
        assert_eq!(parsed.port, 60001);
        assert!(parsed.client_pubkeys.is_empty());
        assert!(parsed.server_key_file.is_none());
    }

    #[test]
    fn transport_shell_parses_repeated_client_pubkeys() {
        let key_a = B64.encode([1u8; 32]);
        let key_b = B64.encode([2u8; 32]);
        let parsed = parse_transport_shell_args(&args(&[
            "transport-shell",
            "--port",
            "60001",
            "--client-pubkey",
            &key_a,
            "--client-pubkey",
            &key_b,
        ]))
        .unwrap();
        assert_eq!(parsed.client_pubkeys, vec![[1u8; 32], [2u8; 32]]);
    }

    #[test]
    fn transport_shell_rejects_wrong_length_pubkey() {
        let short = B64.encode([9u8; 3]);
        assert!(parse_transport_shell_args(&args(&[
            "transport-shell",
            "--port",
            "60001",
            "--client-pubkey",
            &short,
        ]))
        .is_err());
    }

    #[test]
    fn transport_shell_parses_server_key_file() {
        let parsed = parse_transport_shell_args(&args(&[
            "transport-shell",
            "--port",
            "60001",
            "--server-key-file",
            "/tmp/qsh-key.bin",
        ]))
        .unwrap();
        assert_eq!(
            parsed.server_key_file.as_deref(),
            Some(std::path::Path::new("/tmp/qsh-key.bin"))
        );
    }

    #[test]
    fn transport_key_is_created_then_reused_stably() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("temp dir");
        let path = dir.path().join("transport_server_key.bin");

        let first = load_or_create_transport_key(&path).expect("key created");
        assert!(path.exists(), "key file written to disk");
        let second = load_or_create_transport_key(&path).expect("key re-read");

        // The key must stay the same across runs (the client pins the
        // public part, like an SSH host key).
        assert_eq!(first.private, second.private);
        assert_eq!(first.public, second.public);
    }

    #[cfg(unix)]
    #[test]
    fn transport_key_file_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("temp dir");
        let path = dir.path().join("transport_server_key.bin");
        let _ = load_or_create_transport_key(&path).expect("key created");
        // The private key file is created with 0600 (rw-------)
        // permissions right away, with no umask-readable window between
        // creation and setting the permissions.
        let mode = std::fs::metadata(&path)
            .expect("key file metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "expected exactly 0600 permissions");
    }

    #[test]
    fn requires_transport_ensure_command() {
        assert!(parse_transport_ensure_args(&args(&["--port", "60000"])).is_err());
    }

    #[test]
    fn transport_ensure_requires_name() {
        assert!(
            parse_transport_ensure_args(&args(&["transport-ensure", "--port", "60000"])).is_err()
        );
    }

    #[test]
    fn transport_ensure_requires_port() {
        assert!(
            parse_transport_ensure_args(&args(&["transport-ensure", "--name", "main"])).is_err()
        );
    }

    #[test]
    fn transport_ensure_parses_name_port_and_client_pubkey() {
        let key = B64.encode([5u8; 32]);
        let parsed = parse_transport_ensure_args(&args(&[
            "transport-ensure",
            "--name",
            "main",
            "--port",
            "60000",
            "--client-pubkey",
            &key,
        ]))
        .unwrap();

        assert_eq!(parsed.name, "main");
        assert_eq!(parsed.port, 60000);
        assert_eq!(parsed.default_port, None);
        assert_eq!(parsed.ports, vec![60000]);
        assert_eq!(parsed.client_pubkey, Some([5u8; 32]));
    }

    #[test]
    fn transport_ensure_without_client_pubkey_is_none() {
        let parsed = parse_transport_ensure_args(&args(&[
            "transport-ensure",
            "--name",
            "main",
            "--port",
            "60000",
        ]))
        .unwrap();
        assert!(parsed.client_pubkey.is_none());
    }

    #[test]
    fn transport_ensure_parses_distinct_default_port() {
        let parsed = parse_transport_ensure_args(&args(&[
            "transport-ensure",
            "--name",
            "main",
            "--port",
            "60000",
            "--default-port",
            "60999",
        ]))
        .unwrap();

        assert_eq!(parsed.default_port, Some(60999));
        assert_eq!(parsed.ports, vec![60000, 60999]);
    }

    #[test]
    fn transport_ensure_default_port_equal_to_port_is_not_duplicated() {
        let parsed = parse_transport_ensure_args(&args(&[
            "transport-ensure",
            "--name",
            "main",
            "--port",
            "60000",
            "--default-port",
            "60000",
        ]))
        .unwrap();

        assert_eq!(parsed.default_port, Some(60000));
        assert_eq!(parsed.ports, vec![60000]);
    }

    #[test]
    fn transport_ensure_rejects_wrong_length_client_pubkey() {
        let short = B64.encode([1u8; 3]);
        assert!(parse_transport_ensure_args(&args(&[
            "transport-ensure",
            "--name",
            "main",
            "--port",
            "60000",
            "--client-pubkey",
            &short,
        ]))
        .is_err());
    }

    #[test]
    fn transport_ensure_rejects_invalid_base64_client_pubkey() {
        assert!(parse_transport_ensure_args(&args(&[
            "transport-ensure",
            "--name",
            "main",
            "--port",
            "60000",
            "--client-pubkey",
            "not-valid-base64!!",
        ]))
        .is_err());
    }

    #[test]
    fn transport_ensure_rejects_unknown_argument() {
        assert!(parse_transport_ensure_args(&args(&[
            "transport-ensure",
            "--name",
            "main",
            "--port",
            "60000",
            "--bogus",
        ]))
        .is_err());
    }

    #[test]
    fn ready_ports_are_the_ones_the_live_daemon_reports() {
        let status = control::StatusResponse {
            version: "0.3.0".into(),
            build: 1,
            checksum: "x".into(),
            ports: vec![control::PortStatus {
                port: 60000,
                default: true,
                connections: 0,
            }],
            total_connections: 0,
            pid: 1,
        };
        assert_eq!(ready_ports(&status, &[60022]), vec![60000]);
    }

    #[test]
    fn a_status_without_ports_falls_back_to_the_requested_ones() {
        let status = control::StatusResponse {
            version: "0.3.0".into(),
            build: 1,
            checksum: "x".into(),
            ports: vec![],
            total_connections: 0,
            pid: 1,
        };
        assert_eq!(ready_ports(&status, &[60022]), vec![60022]);
    }

    #[test]
    fn write_transport_ready_prints_exact_two_lines() {
        let pubkey = [7u8; 32];
        let mut buf: Vec<u8> = Vec::new();

        write_transport_ready(&mut buf, &pubkey, &[60000, 60999], None).unwrap();

        let text = String::from_utf8(buf).unwrap();
        let mut lines = text.lines();
        let first = lines.next().expect("first line");
        let second = lines.next().expect("second line");
        assert!(lines.next().is_none(), "there must be no extra lines");
        assert!(text.ends_with('\n'), "output must end with a newline");

        assert_eq!(first, format!("server-pubkey: {}", B64.encode(pubkey)));

        let prefix = "TRANSPORT-READY ";
        assert!(second.starts_with(prefix), "second line: {second}");
        let value: serde_json::Value = serde_json::from_str(&second[prefix.len()..]).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"version": state::QSHD_VERSION, "ports": [60000, 60999], "warning": null})
        );
    }

    #[test]
    fn transport_ready_carries_optional_warning() {
        let mut buf = Vec::new();
        let pk = [0u8; 32];
        write_transport_ready(&mut buf, &pk, &[60000], Some("daemon differs")).unwrap();
        let s = String::from_utf8(buf).unwrap();
        assert!(s.contains("server-pubkey: "));
        assert!(s.contains("\"warning\":\"daemon differs\""));

        let mut buf2 = Vec::new();
        write_transport_ready(&mut buf2, &pk, &[60000], None).unwrap();
        let s2 = String::from_utf8(buf2).unwrap();
        assert!(s2.contains("TRANSPORT-READY "));
        // No warning -> field is null (client tolerates absence/null).
        assert!(s2.contains("\"warning\":null"));
    }

    #[test]
    fn the_version_text_names_the_version_the_license_the_source_and_the_build() {
        let text = version_text();
        assert!(text.contains(env!("CARGO_PKG_VERSION")));
        assert!(text.contains("AGPL-3.0-only"));
        assert!(text.contains("https://github.com/br0adcast/qsh"));
        assert!(text.contains("no warranty"));
        // The build stamp is what the client and the daemon compare when they
        // decide which of them is newer, so a version that hides it is
        // useless for diagnosing a mismatch.
        assert!(text.contains(&crate::state::build_label().to_string()));
    }

    #[test]
    fn the_help_text_names_every_subcommand_and_both_flags() {
        let text = help_text();
        for subcommand in [
            "transport-echo",
            "transport-shell",
            "transport-ensure",
            "serve",
            "self-check",
        ] {
            assert!(
                text.contains(subcommand),
                "missing subcommand: {subcommand}"
            );
        }
        assert!(text.contains("--version"));
        assert!(text.contains("-V"));
        assert!(text.contains("--help"));
        assert!(text.contains("-h"));
    }

    /// Runs [`ask_status_with`] over a scripted sequence of replies and
    /// returns what it answered and how many times it asked.
    fn scripted(
        sock_exists: bool,
        replies: Vec<control::ControlReply>,
    ) -> (control::ControlReply, usize) {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("control.sock");
        if sock_exists {
            std::fs::write(&sock, b"").unwrap();
        }
        let mut replies = replies.into_iter();
        let mut asked = 0;
        let reply = ask_status_with(&sock, Duration::ZERO, || {
            asked += 1;
            Ok(replies.next().expect("asked more often than scripted"))
        })
        .unwrap();
        (reply, asked)
    }

    /// A daemon mid-exec closes the connections it had accepted and, a
    /// moment later, answers from the new binary on the same socket: an
    /// unanswered `STATUS` with the socket file present is asked again.
    #[test]
    fn an_unanswered_status_with_the_socket_present_is_asked_again() {
        let answered = control::ControlReply::Answered("{}".to_string());
        assert_eq!(
            scripted(
                true,
                vec![control::ControlReply::NoDaemon, answered.clone()]
            ),
            (answered.clone(), 2)
        );
    }

    /// Accepted and never answered -- a request that waited on the control
    /// gate through an exec -- is asked again too.
    #[test]
    fn a_status_that_timed_out_is_asked_again() {
        let answered = control::ControlReply::Answered("{}".to_string());
        assert_eq!(
            scripted(
                true,
                vec![control::ControlReply::TimedOut, answered.clone()]
            ),
            (answered, 2)
        );
        assert_eq!(
            scripted(
                true,
                vec![
                    control::ControlReply::TimedOut,
                    control::ControlReply::TimedOut
                ]
            ),
            (control::ControlReply::TimedOut, 2),
            "only once"
        );
    }

    #[test]
    fn no_socket_file_or_an_answer_is_asked_once() {
        assert_eq!(
            scripted(false, vec![control::ControlReply::NoDaemon]),
            (control::ControlReply::NoDaemon, 1)
        );
        let answered = control::ControlReply::Answered("{}".to_string());
        assert_eq!(scripted(true, vec![answered.clone()]), (answered, 1));
    }

    struct NoopBinder;
    impl transport::driver_std::Binder for NoopBinder {
        fn bind(&self, _fd: i32) -> bool {
            true
        }
    }

    #[derive(Default)]
    struct Live(Mutex<bool>);
    impl transport::driver_std::ClientEvents for Live {
        fn on_input_failure(&self, failure: transport::driver_std::InputFailure) {
            panic!("unexpected accepted-input failure: {failure:?}");
        }
        fn on_bytes(&self, _stream_id: u8, _data: Vec<u8>) {}
        fn on_state(&self, state: transport::LinkState) {
            if state == transport::LinkState::Live {
                *self.0.lock().unwrap() = true;
            }
        }
        fn on_stats(&self, _stats: transport::Stats) {}
        fn on_reset(&self, _stream_id: u8) {}
    }

    fn live_within(events: &Live, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if *events.0.lock().unwrap() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    /// The personal daemon's real authentication, in a real router: while a
    /// replacement holds the admission gate closed, a client whose key IS on
    /// the allowlist is not admitted; once it opens again, the same client's
    /// next msg1 is.
    #[test]
    fn a_handshake_is_refused_while_the_admission_gate_is_closed() {
        let server = transport::handshake::generate_keypair();
        let client = transport::handshake::generate_keypair();
        let admission = Arc::new(update::AdmissionGate::default());
        admission.close();
        let auth = personal_server_auth(
            Arc::new(Mutex::new(vec![client.public])),
            server.public,
            Arc::clone(&admission),
        );

        let runtime = tokio::runtime::Runtime::new().unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let port = socket.local_addr().unwrap().port();
        socket.set_nonblocking(true).unwrap();
        let socket = {
            let _entered = runtime.enter();
            tokio::net::UdpSocket::from_std(socket).unwrap()
        };
        runtime.spawn(transport::SessionManager::serve(
            Arc::new(socket),
            server.private,
            auth,
            transport::BackendFactory(Arc::new(qshd::channel_backend::ChannelSessionBackend::new(
                Arc::new(qshd::screen_budget::ScreenBudget::new(
                    qshd::screen_budget::BudgetLimits::default(),
                )),
            ))),
            Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            transport::LoginEndedReports::none(),
        ));

        let events = Arc::new(Live::default());
        let connection = transport::driver_std::StdClient::connect(
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), port),
            transport::ConnectionConfig {
                required_features: transport::Features::NONE,
                features: transport::Features::SUPPORTED,
                role: transport::Role::Client,
                local_static_priv: client.private,
                remote_static_pub: Some(server.public),
                auth: transport::AuthPolicy::Allowlist(Vec::new()),
            },
            [4; 16],
            transport::StartKind::Cold,
            Arc::new(NoopBinder),
            events.clone(),
            None,
        );
        assert!(
            !live_within(&events, Duration::from_secs(2)),
            "admitted while the gate was closed"
        );
        admission.open();
        assert!(
            live_within(&events, Duration::from_secs(15)),
            "the same client is admitted once the gate is open"
        );
        connection.close();
    }
}
