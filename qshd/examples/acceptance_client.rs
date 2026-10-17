//! A throwaway wire-protocol client for `packaging/acceptance.sh`.
//!
//! WHY THIS EXISTS. The acceptance tier (task 9b of the system-mode-slice3
//! plan) has to prove the qsh security property end to end, against the
//! INSTALLED `qshd` package running as root in a fresh container: two real
//! accounts, two real keys, each gets a shell running as itself, and a
//! foreign account presenting another account's session token gets refused
//! rather than handed that session. Proving that needs a real client that
//! speaks the actual wire protocol (Noise handshake, SSH-signature proof,
//! the channel framing) -- and the only thing in this workspace that already
//! does that outside of `qsh` itself is the test harness in
//! `qshd/tests/common/mod.rs`, which is private to `cargo test` binaries and
//! spawns the daemon via `CARGO_BIN_EXE_qshd` (a build-tree path baked in at
//! compile time, which is exactly what this tier must NOT use -- see that
//! file's own module docs and `packaging/acceptance.sh`'s header for why).
//!
//! The `qsh` client (`cli/`) cannot stand in for it either: it is
//! interactive-only (raw terminal mode, an on-first-contact trust prompt),
//! with no batch or one-shot mode to script from a shell.
//!
//! So this is a small, purpose-built CLI, in the same shape as
//! `common::Session` but driven by arguments instead of by test code, built
//! from the SAME crates (`transport`, `sshauth`) the real client and the
//! existing root-gated integration suites already use. It never ships: an
//! example target is not part of `cargo build --release -p qsh -p qshd`
//! (the release workflow's own build step), and is not listed in any
//! packaging asset list (`cli/Cargo.toml`'s `[package.metadata.deb]`/
//! `[package.metadata.generate-rpm]`).
//!
//! WHERE IT RUNS: `packaging/acceptance.sh` builds this binary once, on the
//! HOST driving the containers (statically, against musl, so the result
//! runs unmodified regardless of the container's glibc), then `docker cp`s
//! it INTO the same container the installed `qshd` is running in and drives
//! it there with `docker exec` -- never from the host by a raw connect, and
//! there is no `--network host` anywhere in this design. That is not
//! incidental: a sandboxed CI runner's own network namespace was measured,
//! while writing this tier, not to reach a container's published ports or
//! its bridge IP at all, while `docker exec` always works (it goes through
//! the Docker API, not through IP routing) -- see `packaging/acceptance.sh`'s
//! own header for the details. So every `--port`/`--server-pub` pair this
//! binary is ever handed names `127.0.0.1` from INSIDE that same container,
//! where the installed daemon bound it.
//!
//! Subcommands:
//!
//!   genkey <path>
//!       Writes a fresh, unencrypted Ed25519 key to <path> (mode 0600,
//!       OpenSSH format) and prints its public line (also OpenSSH format) to
//!       stdout -- ready to append to some account's `authorized_keys`.
//!
//!   probe --port N --server-pub BASE64 --key PATH --login NAME
//!         [--command CMD] [--token HEX32] [--timeout-secs N]
//!       Connects to 127.0.0.1:N, proves itself as NAME with the key at
//!       PATH, and opens a Command channel running CMD (or, with no
//!       --command, a plain Shell channel -- used only to ask "did this
//!       open", never to type into it). --token forces the connection's
//!       16-byte token to an exact value instead of a fresh random one --
//!       the lever the security-regression check needs to make one login
//!       collide with another's session on purpose. Prints exactly one
//!       `RESULT=` line to stdout (see `print_result`) and exits 0 (opened),
//!       2 (refused) or 3 (neither within the deadline).

use std::io::Write;
use std::net::{Ipv4Addr, SocketAddr};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, LineEnding, PrivateKey};
use sshauth::sign_file::FileSigner;

use transport::channel::{
    decode_server, encode_client, ChannelKind, ClientRecord, OpenRequest, ServerRecord,
    CONTROL_STREAM, FIRST_CHANNEL_STREAM,
};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::shell_frame::{RecordDeframer, ShellDeframer, ShellRecord};
use transport::{LinkState, Stats};

const USAGE: &str = "\
qshd-acceptance-client -- a throwaway client for packaging/acceptance.sh

Usage:
    acceptance_client genkey <path>
    acceptance_client probe --port N --server-pub BASE64 --key PATH --login NAME
                             [--command CMD] [--token HEX32] [--timeout-secs N]
";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("genkey") => {
            let Some(path) = args.next() else {
                eprintln!("genkey needs a path\n\n{USAGE}");
                return ExitCode::from(2);
            };
            cmd_genkey(Path::new(&path))
        }
        Some("probe") => cmd_probe(args.collect()),
        Some(other) => {
            eprintln!("unknown subcommand {other:?}\n\n{USAGE}");
            ExitCode::from(2)
        }
        None => {
            eprint!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// `genkey <path>`: a fresh, unencrypted Ed25519 key at `path` (0600), its
/// public line on stdout. Unencrypted on purpose -- this key exists for the
/// length of one container's life and never leaves it; a passphrase would
/// only give the acceptance script something to type.
fn cmd_genkey(path: &Path) -> ExitCode {
    let key = match PrivateKey::random(&mut OsRng, Algorithm::Ed25519) {
        Ok(k) => k,
        Err(e) => {
            eprintln!("acceptance_client: generating a key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let encoded = match key.to_openssh(LineEnding::LF) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("acceptance_client: encoding the private key: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = std::fs::write(path, encoded.as_bytes()) {
        eprintln!("acceptance_client: writing {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
        eprintln!("acceptance_client: chmod 600 {}: {e}", path.display());
        return ExitCode::FAILURE;
    }
    let public = match key.public_key().to_openssh() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acceptance_client: encoding the public key: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!("{public}");
    ExitCode::SUCCESS
}

struct ProbeArgs {
    port: u16,
    server_pub: [u8; 32],
    key_path: PathBuf,
    login: String,
    command: Option<String>,
    token: Option<[u8; 16]>,
    timeout: Duration,
}

fn parse_probe_args(mut args: std::vec::IntoIter<String>) -> Result<ProbeArgs, String> {
    let mut port = None;
    let mut server_pub = None;
    let mut key_path = None;
    let mut login = None;
    let mut command = None;
    let mut token = None;
    let mut timeout = Duration::from_secs(10);

    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{flag} needs a value"));
        match flag.as_str() {
            "--port" => port = Some(value()?.parse::<u16>().map_err(|e| e.to_string())?),
            "--server-pub" => {
                let raw = BASE64
                    .decode(value()?.trim())
                    .map_err(|e| format!("--server-pub: {e}"))?;
                let arr: [u8; 32] = raw
                    .try_into()
                    .map_err(|v: Vec<u8>| format!("--server-pub: {} bytes, want 32", v.len()))?;
                server_pub = Some(arr);
            }
            "--key" => key_path = Some(PathBuf::from(value()?)),
            "--login" => login = Some(value()?),
            "--command" => command = Some(value()?),
            "--token" => {
                let hex = value()?;
                token = Some(parse_hex16(&hex)?);
            }
            "--timeout-secs" => {
                let secs: u64 = value()?
                    .parse()
                    .map_err(|e: std::num::ParseIntError| e.to_string())?;
                timeout = Duration::from_secs(secs);
            }
            other => return Err(format!("unknown flag {other}")),
        }
    }

    Ok(ProbeArgs {
        port: port.ok_or("--port is required")?,
        server_pub: server_pub.ok_or("--server-pub is required")?,
        key_path: key_path.ok_or("--key is required")?,
        login: login.ok_or("--login is required")?,
        command,
        token,
        timeout,
    })
}

fn parse_hex16(s: &str) -> Result<[u8; 16], String> {
    if s.len() != 32 {
        return Err(format!("--token: want 32 hex characters, got {}", s.len()));
    }
    let mut out = [0u8; 16];
    for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
        let pair = std::str::from_utf8(chunk).map_err(|_| "--token: not ASCII".to_string())?;
        out[i] = u8::from_str_radix(pair, 16).map_err(|e| format!("--token: {e}"))?;
    }
    Ok(out)
}

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

#[derive(Default)]
struct Collected {
    control: Vec<ServerRecord>,
    shell_output: Vec<u8>,
    live: bool,
}

struct Events {
    control_deframer: Mutex<RecordDeframer>,
    shell_deframer: Mutex<ShellDeframer>,
    collected: Mutex<Collected>,
}

impl Default for Events {
    fn default() -> Self {
        Events {
            control_deframer: Mutex::new(RecordDeframer::new()),
            shell_deframer: Mutex::new(ShellDeframer::new()),
            collected: Mutex::new(Collected::default()),
        }
    }
}

impl ClientEvents for Events {
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        if stream_id == CONTROL_STREAM {
            let raws = self.control_deframer.lock().expect("lock").push(&data);
            let mut collected = self.collected.lock().expect("lock");
            for raw in raws {
                if let Ok(rec) = decode_server(&raw) {
                    collected.control.push(rec);
                }
            }
        } else if stream_id == FIRST_CHANNEL_STREAM {
            let recs = self.shell_deframer.lock().expect("lock").push(&data);
            let mut collected = self.collected.lock().expect("lock");
            for rec in recs {
                if let ShellRecord::Data(bytes) = rec {
                    collected.shell_output.extend(bytes);
                }
            }
        }
    }

    fn on_state(&self, state: LinkState) {
        if state == LinkState::Live {
            self.collected.lock().expect("lock").live = true;
        }
    }

    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream_id: u8) {}
}

/// What the probe found, printed as one `RESULT=` line so the shell driving
/// this can `grep`/`cut` it without parsing anything structured.
enum Outcome {
    /// The channel opened. `exit` is `Some` only for a Command channel that
    /// also finished running; a Shell channel (no `--command`) is never
    /// typed into, so it has no exit code to report.
    Opened {
        exit: Option<i32>,
        output: String,
    },
    Refused {
        reason: String,
    },
    /// Neither an `Opened`/`Refused` record nor, in the worse case, even a
    /// live link arrived within the deadline. `live` says which: a login
    /// that never completed the handshake at all (the shape a foreign-owner
    /// token collision takes -- see `session_manager::refuse_foreign_owner`,
    /// which returns before a single msg2 goes out) looks different from one
    /// that went live but then heard nothing about its channel, and a reader
    /// of this line should be able to tell the two apart without re-running
    /// anything.
    Timeout {
        live: bool,
    },
}

fn one_line(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

fn print_result(outcome: &Outcome) {
    match outcome {
        Outcome::Opened {
            exit: Some(code),
            output,
        } => {
            println!("RESULT=opened exit={code} output={}", one_line(output));
        }
        Outcome::Opened { exit: None, output } => {
            println!("RESULT=opened output={}", one_line(output));
        }
        Outcome::Refused { reason } => {
            println!("RESULT=refused reason={}", one_line(reason));
        }
        Outcome::Timeout { live } => {
            println!("RESULT=timeout live={live}");
        }
    }
}

fn cmd_probe(args: Vec<String>) -> ExitCode {
    let parsed = match parse_probe_args(args.into_iter()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("acceptance_client: {e}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let signer = match FileSigner::load(&parsed.key_path, None) {
        Ok(s) => s.with_login(parsed.login.clone()),
        Err(e) => {
            eprintln!(
                "acceptance_client: loading {}: {e}",
                parsed.key_path.display()
            );
            return ExitCode::from(2);
        }
    };

    let mut token = [0u8; 16];
    match parsed.token {
        Some(forced) => token = forced,
        None => OsRng.fill_bytes(&mut token),
    }

    let events = Arc::new(Events::default());
    let client = StdClient::connect(
        SocketAddr::new(Ipv4Addr::LOCALHOST.into(), parsed.port),
        ConnectionConfig {
            features: transport::Features::SUPPORTED,
            role: Role::Client,
            local_static_priv: generate_keypair().private,
            remote_static_pub: Some(parsed.server_pub),
            auth: AuthPolicy::SshSignature,
        },
        token,
        StartKind::Cold,
        Arc::new(NoopBinder),
        events.clone(),
        Some(Arc::new(signer)),
    );

    let deadline = Instant::now() + parsed.timeout;
    let live = || events.collected.lock().expect("lock").live;
    while Instant::now() < deadline && !live() {
        std::thread::sleep(Duration::from_millis(20));
    }

    let outcome = if !live() {
        Outcome::Timeout { live: false }
    } else {
        let (kind, command_bytes) = match &parsed.command {
            None => (ChannelKind::Shell, Vec::new()),
            Some(c) => (ChannelKind::Command, c.as_bytes().to_vec()),
        };
        client.send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind,
                cols: 80,
                rows: 24,
                screen: false,
                command: command_bytes,
            })),
        );

        let verdict = |records: &[ServerRecord]| -> Option<Result<Option<i32>, String>> {
            let refused = records.iter().find_map(|r| match r {
                ServerRecord::Refused { stream, reason } if *stream == FIRST_CHANNEL_STREAM => {
                    Some(reason.clone())
                }
                _ => None,
            });
            if let Some(reason) = refused {
                return Some(Err(reason));
            }
            let opened = records.iter().any(
                |r| matches!(r, ServerRecord::Opened { stream } if *stream == FIRST_CHANNEL_STREAM),
            );
            if !opened {
                return None;
            }
            if parsed.command.is_none() {
                // A shell channel: opening is the whole answer, never typed into.
                return Some(Ok(None));
            }
            records.iter().find_map(|r| match r {
                ServerRecord::Exit { stream, code } if *stream == FIRST_CHANNEL_STREAM => {
                    Some(Ok(Some(*code)))
                }
                _ => None,
            })
        };

        loop {
            let records = events.collected.lock().expect("lock").control.clone();
            match verdict(&records) {
                Some(Ok(exit)) => {
                    let output = String::from_utf8_lossy(
                        &events.collected.lock().expect("lock").shell_output,
                    )
                    .into_owned();
                    break Outcome::Opened { exit, output };
                }
                Some(Err(reason)) => break Outcome::Refused { reason },
                None if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(20));
                }
                None => break Outcome::Timeout { live: true },
            }
        }
    };

    client.close();
    let _ = std::io::stdout().flush();
    print_result(&outcome);
    match outcome {
        Outcome::Opened { .. } => ExitCode::SUCCESS,
        Outcome::Refused { .. } => ExitCode::from(2),
        Outcome::Timeout { .. } => ExitCode::from(3),
    }
}
