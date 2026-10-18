//! Shared harness for this crate's `qshd serve --system` integration
//! tests: start a real daemon binary, prove it is actually alive (not just
//! that it printed a banner), and drive channels through it as an
//! authenticated client.
//!
//! Only reachable from files that are themselves gated behind
//! `#![cfg(feature = "system")]` -- `system_mode_shell.rs`,
//! `serve_system_split.rs`, `system_mode_accounts.rs` and
//! `system_mode_pam.rs` -- so this module's own content simply never gets
//! loaded (module resolution never looks at this file) when the crate is
//! built without the feature. Nothing here needs its own `cfg`.
//!
//! `serve_auth.rs`, this crate's other end-to-end auth check, drives
//! `SessionManager::serve` directly rather than a spawned `qshd` process,
//! so it shares no code with the pieces below -- there was nothing of this
//! shape to pull out of it.
//!
//! Cargo compiles this file once PER integration-test binary that declares
//! `mod common;` -- there is no single shared crate a `dead_code` lint could
//! see all the callers of at once. `serve_system_split.rs` only ever calls
//! `start_daemon`; `system_mode_shell.rs`, `system_mode_accounts.rs` and
//! `system_mode_pam.rs` call most of the rest. Silencing `dead_code` here is
//! the standard shape of that trade-off, not a sign anything below is
//! actually unused.
#![allow(dead_code)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdout, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use nix::unistd::{Gid, Uid, User};
use rand_core::{OsRng, RngCore};
use ssh_key::{Algorithm, PrivateKey};
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

/// Waits for `probe` to hold, or gives up (returning `false`) after a
/// fixed deadline. Generous on purpose: a slow machine must make a test
/// using this slower, never flaky.
pub(crate) fn wait_until(mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// Where `serve`'s binary is, for a `Command` that starts a real process
/// rather than calling into this crate in-process.
fn qshd_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_qshd"))
}

/// Keep authorization sources below safe root-owned ancestors. The rest of
/// each daemon's state remains in its ordinary temporary directory. These
/// fixtures exist only inside the disposable container and disappear with it.
pub(crate) fn authorized_keys_path(dir: &Path) -> PathBuf {
    assert!(Uid::effective().is_root());
    assert_eq!(std::env::var(DISPOSABLE_HOST_VAR).as_deref(), Ok("1"));
    Path::new("/var/lib/qshd-test-keys")
        .join(dir.file_name().expect("unique test directory"))
        .join("authorized_keys")
}

/// Writes `key`'s public half as the sole line of a fresh `authorized_keys`
/// file at [`authorized_keys_path`], and returns its path.
pub(crate) fn write_authorized_keys(dir: &Path, key: &PrivateKey) -> PathBuf {
    let path = authorized_keys_path(dir);
    std::fs::create_dir_all(path.parent().expect("the path has a parent"))
        .expect("create .ssh directory");
    for parent in [Path::new("/var/lib/qshd-test-keys"), path.parent().unwrap()] {
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let mut f = std::fs::File::create(&path).expect("create authorized_keys");
    f.set_permissions(std::fs::Permissions::from_mode(0o644))
        .unwrap();
    writeln!(
        f,
        "{}",
        key.public_key().to_openssh().expect("encode public key")
    )
    .expect("write authorized_keys");
    f.flush().expect("flush");
    path
}

/// Where a `qshd serve --system` daemon writes its own file log:
/// `/var/log/qshd/qshd.log`, a MACHINE-WIDE path and not a per-test one.
/// The helper writes the DETAILED reason for every refused login here (the
/// wire only ever carries a fixed one), which is how a test can tell WHICH
/// check refused a login, not merely that one did.
///
/// This used to be `<dir>/qsh/qshd.log`, built from the `$XDG_CACHE_HOME`
/// [`start_daemon_with`] points at the test's own temporary directory. The
/// system mode stopped honouring that: `serve::cache_dir` returns
/// `/var/log/qshd` outright for `--system`, deliberately, so a service's
/// diagnostics do not move with whichever account happens to own `$HOME`.
/// Every test that read the log kept reading the old path, found nothing
/// there, and failed -- four of them, in three suites, on every single
/// container run. A path derived from `dir` cannot be right here whatever
/// it is derived from, so this function no longer takes one: the daemon
/// has ONE log and the tests read exactly it.
///
/// Because the path is machine-wide, the log outlives a single daemon.
/// [`start_daemon_with`] deletes it before every start, which is what keeps
/// "the log contains X" a statement about the daemon this test started
/// rather than about some earlier test's. That deletion is as irreversible
/// as everything else these suites do, and is why they run only where
/// [`on_a_disposable_host`] lets them.
pub(crate) fn daemon_log_path() -> PathBuf {
    PathBuf::from(SYSTEM_LOG_DIR).join("qshd.log")
}

/// The directory `serve::cache_dir` hands `qshd::log::init` in the system
/// mode -- taken FROM THE CRATE, not written out again here. A second copy
/// of a path is a second source of truth for it, and the daemon moving its
/// log is exactly how these tests came to be reading a file nothing writes.
use qshd::serve::SYSTEM_LOG_DIR;

/// Removes the machine-wide log and its one rotation, so the daemon
/// [`start_daemon_with`] is about to start writes into an empty file.
///
/// Without this, every test in a binary would read one log that every
/// earlier test in the same binary had already written to. A test asserting
/// "the log contains X" would then pass on a line some other daemon wrote
/// (`serve_system_split.rs`'s authentication-seam test reads exactly such a
/// line, and every other test in that file kills a helper, which is the
/// event that produces it), and a test counting occurrences would count
/// from a floor it did not set.
///
/// Best-effort: a missing file is the state this wants, and no test can do
/// anything useful about a failure to remove one -- the assertion that
/// reads the log afterwards is what turns a stale log into a loud failure.
fn clear_system_log() {
    let _ = std::fs::remove_file(daemon_log_path());
    let _ = std::fs::remove_file(PathBuf::from(SYSTEM_LOG_DIR).join("qshd.log.1"));
}

/// The login name of the account running the suite, from passwd -- what a
/// suite that logs in as that same account (`system_mode_shell.rs`) sends.
pub(crate) fn current_login() -> String {
    nix::unistd::User::from_uid(nix::unistd::Uid::current())
        .expect("read this account's passwd entry")
        .expect("the account running the suite exists")
        .name
}

/// A live `qshd serve --system` child process. `Drop` kills and reaps it
/// even if an assertion panics first -- this mode never exits on its own
/// while both halves are healthy, so nothing else would.
pub(crate) struct Daemon {
    pub(crate) child: Child,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Reads `serve`'s two-line startup banner (`server-pubkey:` then
/// `host-key-fingerprint:`) off `stdout`. Returns `None` -- rather than
/// panicking -- when the first line is not what was expected, so a caller
/// can tell "this attempt lost the port race" (see `start_daemon_with`)
/// apart from a genuine decoding bug, which still panics: a malformed
/// SECOND line, or a first line that claims to be the banner but fails to
/// base64-decode, cannot be explained by another process holding the port.
fn read_server_pubkey(stdout: &mut ChildStdout) -> Option<[u8; 32]> {
    let mut reader = BufReader::new(stdout);
    let mut line1 = String::new();
    reader
        .read_line(&mut line1)
        .expect("stdout is read without an I/O error");
    if !line1.starts_with("server-pubkey: ") {
        return None;
    }
    let raw = BASE64
        .decode(line1.trim_start_matches("server-pubkey: ").trim_end())
        .expect("a genuine server-pubkey line decodes from base64");
    let mut server_pub = [0u8; 32];
    server_pub.copy_from_slice(&raw);

    let mut line2 = String::new();
    reader
        .read_line(&mut line2)
        .expect("the second line (host-key-fingerprint) is read from stdout");
    assert!(
        line2.starts_with("host-key-fingerprint: "),
        "expected a host-key-fingerprint line right after a genuine server-pubkey one, got: \
         {line2:?}"
    );
    Some(server_pub)
}

/// How many fresh ports `start_daemon_with` will try before giving up.
const START_DAEMON_ATTEMPTS: u32 = 5;

/// Starts `qshd serve --system` the way the suites that log in as the
/// account running them need it: [`start_daemon_with`], plus
/// `--authorized-keys-template` pointed at [`authorized_keys_path`] -- the
/// file `write_authorized_keys(dir, ...)` writes, or nothing, for a caller
/// that never calls it: the helper refuses a login whose key file is
/// missing, and starts regardless -- and `--permit-root`, because that
/// account is root (see below), and without the flag the helper refuses
/// that login however good the proof.
///
/// The caller must be root: since Task 1 of the system-mode-slice2b plan
/// (`qshd/src/serve.rs`), `--system` refuses to start at all otherwise --
/// the helper has to be able to become any account. Every caller of this
/// function must check `nix::unistd::Uid::effective().is_root()` itself and
/// skip (loudly) before reaching here; this function does not check on a
/// caller's behalf, because a skip decided this deep would leave the caller
/// unable to tell "skipped" apart from "hung."
///
/// Returns the live daemon, its Noise public key, and the port it is
/// actually listening on.
pub(crate) fn start_daemon(dir: &Path) -> (Daemon, [u8; 32], u16) {
    let keys = authorized_keys_path(dir);
    start_daemon_with(
        dir,
        &[
            "--permit-root",
            "--authorized-keys-template",
            keys.to_str().expect("utf-8 path"),
        ],
    )
}

/// Starts `qshd serve --system`, on a freshly picked port, with its host
/// key in `dir` (never the system mode's real default of
/// `/etc/qshd/host_key` -- a test must not go near that path), as
/// `--worker-user nobody`, followed by the caller's `extra_args` -- which
/// decide who may log in and how: [`start_daemon`] passes its two defaults,
/// while `system_mode_accounts.rs`, whose clients log in as real accounts
/// of their own, passes the `%h/.ssh/authorized_keys` template and no
/// `--permit-root`. `$HOME` and `$XDG_CACHE_HOME` are pointed at `dir` as
/// well, so that nothing the daemon itself writes lands in the real home of
/// the account running the suite. Its file log is NOT among that any more:
/// the system mode writes to `/var/log/qshd` and reaches neither variable
/// (see [`daemon_log_path`]), which is why every start below begins by
/// emptying that one file. A channel's shell never sees them: the helper builds
/// that environment from passwd, so the shell gets the account's real
/// `HOME` (see [`Session::run_in_shell`] for what that means for its
/// history). Its stdin is `/dev/null`, never whatever the test runner's
/// happens to be (a terminal, or a socket under some CI runners): the
/// helper keeps its descriptors 0-2 for its whole life, and a suite that
/// inspects its descriptor table (`serve_system_split.rs`) must find
/// nothing there it did not put there.
///
/// Same caller obligation as [`start_daemon`]: be root, and skip loudly
/// before calling this otherwise.
///
/// Picking a free port is inherently racy: `free_udp_port`-style helpers
/// (used identically across this crate's other integration tests) bind an
/// ephemeral port and close it right away, and nothing stops another
/// process -- most concretely another test binary in the same `cargo test`
/// run, since this crate does not serialise port choice across binaries --
/// from taking that same number before `serve` gets to bind it for real.
/// `serve` binds its socket before printing anything (see
/// `qshd/src/serve.rs`), so losing that race shows up here as a process
/// that never reaches the banner -- worth a retry with a different number,
/// not a hard test failure. Exhausting every attempt still fails loudly,
/// with the last attempt's stderr attached, rather than hanging: each
/// attempt's own `read_server_pubkey` call returns as soon as the process
/// either prints its banner or exits.
pub(crate) fn start_daemon_with(dir: &Path, extra_args: &[&str]) -> (Daemon, [u8; 32], u16) {
    start_daemon_with_groups(dir, extra_args, None)
}

/// Install synthetic inherited groups only in the disposable daemon child.
pub(crate) fn start_daemon_with_groups(
    dir: &Path,
    extra_args: &[&str],
    groups: Option<Vec<nix::unistd::Gid>>,
) -> (Daemon, [u8; 32], u16) {
    use std::os::unix::process::CommandExt;
    let host_key = dir.join("host_key");
    let mut last_attempt_port = 0u16;
    let mut last_stderr = String::new();

    for _ in 0..START_DAEMON_ATTEMPTS {
        clear_system_log();
        let port = free_udp_port();
        let mut command = Command::new(qshd_binary());
        if let Some(groups) = groups.clone() {
            // SAFETY: setgroups is the only child operation; the list is prepared before fork.
            unsafe {
                command.pre_exec(move || {
                    nix::unistd::setgroups(&groups).map_err(std::io::Error::from)
                });
            }
        }
        let mut child = command
            .args([
                "serve",
                "--system",
                "--port",
                &port.to_string(),
                "--host-key",
                host_key.to_str().expect("utf-8 path"),
                // The default worker account (`qshd`) does not exist on a
                // machine that has not been set up to run this daemon --
                // this suite's own first manual root run demonstrated
                // exactly that failure. `nobody` exists, unprivileged, on
                // essentially every Unix this suite runs on, so tests here
                // get a real, successful privilege drop rather than one
                // that only works on a machine pre-provisioned for it.
                "--worker-user",
                "nobody",
            ])
            .args(extra_args)
            .env("XDG_CACHE_HOME", dir)
            .env("HOME", dir)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("the `qshd serve --system` process starts");

        let mut stdout = child.stdout.take().expect("process stdout captured");
        if let Some(server_pub) = read_server_pubkey(&mut stdout) {
            // `serve` writes every log line to stderr too (for the journal),
            // the helper's and the worker's alike: a pipe nobody reads fills
            // up after some hundred lines and then blocks whichever process
            // writes next -- the helper included. Drained for the daemon's
            // whole life; the lines themselves are in `daemon_log_path()`.
            if let Some(mut stderr) = child.stderr.take() {
                std::thread::spawn(move || {
                    let _ = std::io::copy(&mut stderr, &mut std::io::sink());
                });
            }
            return (Daemon { child }, server_pub, port);
        }

        // Lost the race (or a real bug): collect the evidence, reap this
        // attempt so it cannot leak, and either try again or give up.
        last_stderr.clear();
        if let Some(mut se) = child.stderr.take() {
            let _ = se.read_to_string(&mut last_stderr);
        }
        last_attempt_port = port;
        let _ = child.kill();
        let _ = child.wait();
    }

    panic!(
        "the daemon never printed a valid startup banner in {START_DAEMON_ATTEMPTS} attempts, \
         each on a fresh port; last attempt was on port {last_attempt_port}; its stderr: \
         {last_stderr}"
    );
}

/// Picks a free UDP port by binding an ephemeral one and closing it right
/// away, handing the number back. See `start_daemon_with`'s docs for the
/// race this has, and how the caller here copes with it.
fn free_udp_port() -> u16 {
    UdpSocket::bind(("127.0.0.1", 0))
        .expect("an ephemeral port is bound to pick a free number")
        .local_addr()
        .expect("the bound socket's local address")
        .port()
}

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _fd: i32) -> bool {
        true
    }
}

#[derive(Default)]
struct ShellRunCollected {
    control: Vec<ServerRecord>,
    shell_output: Vec<u8>,
    live: bool,
}

struct ShellRunEvents {
    control_deframer: Mutex<RecordDeframer>,
    shell_deframer: Mutex<ShellDeframer>,
    collected: Mutex<ShellRunCollected>,
}

impl Default for ShellRunEvents {
    fn default() -> Self {
        ShellRunEvents {
            control_deframer: Mutex::new(RecordDeframer::new()),
            shell_deframer: Mutex::new(ShellDeframer::new()),
            collected: Mutex::new(ShellRunCollected::default()),
        }
    }
}

impl ClientEvents for ShellRunEvents {
    fn on_bytes(&self, stream_id: u8, data: Vec<u8>) {
        if stream_id == CONTROL_STREAM {
            let raws = self
                .control_deframer
                .lock()
                .expect("control deframer")
                .push(&data);
            let mut collected = self.collected.lock().expect("collected");
            for raw in raws {
                if let Ok(rec) = decode_server(&raw) {
                    collected.control.push(rec);
                }
            }
        } else if stream_id == FIRST_CHANNEL_STREAM {
            let recs = self
                .shell_deframer
                .lock()
                .expect("shell deframer")
                .push(&data);
            let mut collected = self.collected.lock().expect("collected");
            for rec in recs {
                if let ShellRecord::Data(bytes) = rec {
                    collected.shell_output.extend(bytes);
                }
            }
        }
    }

    fn on_state(&self, state: LinkState) {
        if state == LinkState::Live {
            self.collected.lock().expect("collected").live = true;
        }
    }

    fn on_stats(&self, _stats: Stats) {}
    fn on_reset(&self, _stream_id: u8) {}
}

/// A string's POSIX `\NNN` octal-escape form, one triplet per byte. `printf`
/// interprets these in its format operand with no `-e` flag needed, on any
/// POSIX-ish shell.
///
/// [`Session::run_in_shell`] sends this instead of the marker's own bytes,
/// because sending the bytes directly does NOT work: a pseudo-terminal
/// echoes the whole line it was just given, verbatim, the moment it
/// arrives -- before the shell has executed one byte of it. A first
/// version of this harness sent `; echo <marker>` and waited for `<marker>`
/// to show up in the channel's output; that wait was satisfied almost
/// instantly by the echoed INPUT line itself, regardless of whether the
/// shell ever ran anything at all -- caught by sending a command that never
/// returns (`sleep 999`) and watching the "positive" wait still succeed in
/// well under a second. Escaping the marker this way means its human-
/// readable text can only come from `printf` actually running: the echoed
/// input line shows the escape codes, not the text they decode to.
fn octal_escape(s: &str) -> String {
    s.bytes().map(|b| format!("\\{b:03o}")).collect()
}

/// One client connection to a daemon, logged in as a given account, with
/// at most one channel on [`FIRST_CHANNEL_STREAM`]. `Drop` closes the
/// connection, so a test that panics half-way still hangs up.
///
/// The login is the name the client proves itself as (a mandatory part of
/// the proof, since the server always issues a nonce -- see
/// `sshauth::v2_fields`); the system mode's helper resolves it with
/// `getpwnam` and reads THAT account's key file. Whether the login was
/// accepted is not something this type decides: a refused login still
/// completes the handshake, and simply never gets an answer to anything it
/// asks for afterwards -- see [`Session::saw_opened`].
pub(crate) struct Session {
    client: StdClient,
    events: Arc<ShellRunEvents>,
}

impl Session {
    /// Connects to `port` as `key`, proving itself as `login`, and waits
    /// (bounded) for the handshake to complete.
    ///
    /// Each connection gets a fresh random token: the server keys a
    /// device's session by it, and a Cold handshake that repeats a token
    /// still in use REPLACES that session, tearing its backend down (see
    /// `transport::session_manager`'s docs) -- two sessions held open at
    /// once under one token would end each other.
    pub(crate) fn connect(
        port: u16,
        server_pub: [u8; 32],
        key: &PrivateKey,
        login: &str,
    ) -> Session {
        let mut token = [0u8; 16];
        OsRng.fill_bytes(&mut token);
        let events = Arc::new(ShellRunEvents::default());
        let client = StdClient::connect(
            SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port),
            ConnectionConfig {
                required_features: transport::Features::NONE,
                features: transport::Features::SUPPORTED,
                role: Role::Client,
                local_static_priv: generate_keypair().private,
                remote_static_pub: Some(server_pub),
                auth: AuthPolicy::SshSignature,
            },
            token,
            StartKind::Cold,
            Arc::new(NoopBinder),
            events.clone(),
            Some(Arc::new(
                FileSigner::from_key(key.clone()).with_login(login.to_string()),
            )),
        );
        let session = Session { client, events };
        assert!(
            wait_until(|| session.events.collected.lock().expect("collected").live),
            "the handshake with the daemon must complete"
        );
        session
    }

    /// Asks for a channel on [`FIRST_CHANNEL_STREAM`]: the account's login
    /// shell for `None`, `command` run by the account's shell
    /// (`<shell> -c <command>`, the helper's doing) for `Some`. Does not
    /// wait for the answer -- see [`Session::wait_for_opened`] and
    /// [`Session::saw_opened`].
    pub(crate) fn request_channel(&self, command: Option<&str>) {
        let (kind, command) = match command {
            None => (ChannelKind::Shell, Vec::new()),
            Some(command) => (ChannelKind::Command, command.as_bytes().to_vec()),
        };
        self.client.send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream: FIRST_CHANNEL_STREAM,
                kind,
                cols: 80,
                rows: 24,
                screen: false,
                command,
            })),
        );
    }

    /// A second command channel in the same login. Its output can be a fixture file.
    pub(crate) fn run_another_command(&self, command: &str) {
        let stream = FIRST_CHANNEL_STREAM + 1;
        self.client.send_bytes(
            CONTROL_STREAM,
            encode_client(&ClientRecord::Open(OpenRequest {
                stream,
                kind: ChannelKind::Command,
                cols: 80,
                rows: 24,
                screen: false,
                command: command.as_bytes().to_vec(),
            })),
        );
        assert!(
            wait_until(|| self
                .control_records()
                .contains(&ServerRecord::Exit { stream, code: 0 })),
            "second channel must execute successfully: {:?}",
            self.control_records()
        );
    }

    /// Every control record the daemon has sent so far.
    pub(crate) fn control_records(&self) -> Vec<ServerRecord> {
        self.events
            .collected
            .lock()
            .expect("collected")
            .control
            .clone()
    }

    /// Everything the channel has printed so far.
    pub(crate) fn output(&self) -> String {
        String::from_utf8_lossy(
            &self
                .events
                .collected
                .lock()
                .expect("collected")
                .shell_output,
        )
        .into_owned()
    }

    /// Whether the daemon has confirmed the channel open -- which it only
    /// ever does for a session whose login it accepted.
    pub(crate) fn saw_opened(&self) -> bool {
        self.control_records().contains(&ServerRecord::Opened {
            stream: FIRST_CHANNEL_STREAM,
        })
    }

    /// Waits (bounded) for the daemon to confirm the channel open, and
    /// fails loudly otherwise.
    ///
    /// A `Refused` ends the wait at once rather than letting it run out:
    /// the daemon has answered, and no later record will change that, so
    /// waiting the full budget only delays a failure that is already
    /// decided -- and reports it as a timeout instead of as the helper's
    /// own reason.
    pub(crate) fn wait_for_opened(&self) {
        let refusal = || {
            self.control_records()
                .into_iter()
                .find_map(|record| match record {
                    ServerRecord::Refused { stream, reason } if stream == FIRST_CHANNEL_STREAM => {
                        Some(reason)
                    }
                    _ => None,
                })
        };
        wait_until(|| self.saw_opened() || refusal().is_some());
        if let Some(reason) = refusal() {
            panic!("the daemon refused the channel: {reason:?}");
        }
        assert!(
            self.saw_opened(),
            // The control records say which stage stopped it: nothing at
            // all means the session itself never bound -- its login was
            // refused.
            "the daemon must confirm the channel is open; control records so far: {:?}",
            self.control_records()
        );
    }

    /// [`Session::request_channel`] for the login shell, then
    /// [`Session::wait_for_opened`].
    pub(crate) fn open_shell(&self) {
        self.request_channel(None);
        self.wait_for_opened();
    }

    /// Types `command` into the open shell channel, waits for it to have
    /// run, and returns everything the channel has printed so far,
    /// `command`'s own output included.
    ///
    /// A sentinel is appended after `command` (`; printf <escaped marker>`)
    /// and this waits for the marker's DECODED text to come back one more
    /// time than it had before, not for a fixed delay and not for
    /// `command`'s own text. See `octal_escape`'s docs for why the marker
    /// is sent escaped rather than literally: only the shell's real
    /// execution of `printf` can produce the readable marker, so its
    /// absence -- rather than some other, unrelated text already sitting in
    /// the shell's prompt, or the echo of what was typed -- is exactly what
    /// a broken seam (or a daemon that died right after printing its
    /// startup banner) shows up as: a bounded, loud timeout, never a silent
    /// pass and never a hang.
    ///
    /// `unset HISTFILE` goes first: the shell is the account's real login
    /// shell, with its real `HOME` from passwd -- the helper passes a
    /// channel nothing of the daemon's environment, so no
    /// `HISTFILE=/dev/null` set there could reach it -- and an interactive
    /// shell saves what it was given to that home's history when the
    /// channel ends (the kernel's hang-up, when a test kills the daemon, is
    /// enough for bash). Unset, the history goes nowhere.
    pub(crate) fn run_in_shell(&self, command: &str) -> String {
        let marker = "QSHD_SYSTEM_MODE_SHELL_DONE";
        let seen_before = self.output().matches(marker).count();
        self.client.send_bytes(
            FIRST_CHANNEL_STREAM,
            format!(
                "unset HISTFILE; {command}; printf '{}'\n",
                octal_escape(marker)
            )
            .into_bytes(),
        );
        assert!(
            wait_until(|| self.output().matches(marker).count() > seen_before),
            "the shell must run the command and print the marker that follows it; got: {:?}",
            self.output()
        );
        self.output()
    }

    /// Waits (bounded) for the channel's program to end, and returns its
    /// exit code. Fails at once, with the helper's reason, if the daemon
    /// refused the channel instead, and loudly -- never by hanging -- if
    /// neither happens in time.
    pub(crate) fn wait_for_exit(&self) -> i32 {
        let exit_or_refusal = |records: &[ServerRecord]| {
            records.iter().find_map(|record| match record {
                ServerRecord::Exit { stream, code } if *stream == FIRST_CHANNEL_STREAM => {
                    Some(Ok(*code))
                }
                ServerRecord::Refused { stream, reason } if *stream == FIRST_CHANNEL_STREAM => {
                    Some(Err(reason.clone()))
                }
                _ => None,
            })
        };
        wait_until(|| exit_or_refusal(&self.control_records()).is_some());
        match exit_or_refusal(&self.control_records()) {
            Some(Ok(code)) => code,
            Some(Err(reason)) => panic!("the daemon refused the channel: {reason:?}"),
            None => panic!(
                "the channel's program must run and exit; control records so far: {:?}, output \
                 so far: {:?}",
                self.control_records(),
                self.output()
            ),
        }
    }

    /// Waits (bounded) until the channel's output so far satisfies `probe`;
    /// `false` if it never did.
    pub(crate) fn wait_for_output(&self, mut probe: impl FnMut(&str) -> bool) -> bool {
        wait_until(|| probe(&self.output()))
    }

    /// Ends the session the way a client that means to leave does: a `Close`
    /// frame on the wire, then the driver joined. The server reads it as
    /// `SessionEnded { graceful: true }` and tears the backend down at once
    /// -- where a client that merely goes silent leaves a `Retained` entry
    /// that nothing collects for RETAIN_AFTER_DEATH (an hour). Only the
    /// graceful path ends a login, so only it closes its PAM session.
    pub(crate) fn disconnect_gracefully(&self) {
        self.client.close();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.client.close();
    }
}

/// Connects to `port` as `key`, logging in as `login`, opens one shell
/// channel, runs `command` in it, and returns everything the channel
/// printed back, including `command`'s own output. See [`Session`] for the
/// pieces, and [`Session::run_in_shell`] for how the wait is bounded.
pub(crate) fn run_one_command_in_a_shell(
    port: u16,
    server_pub: [u8; 32],
    key: &PrivateKey,
    login: &str,
    command: &str,
) -> String {
    let session = Session::connect(port, server_pub, key, login);
    session.open_shell();
    session.run_in_shell(command)
}

// ---------------------------------------------------------------------------
// Real accounts, and the machine-wide files a suite that uses them writes.
//
// Everything below was written for `system_mode_accounts.rs` (slice 2b, task
// 9) and moved here whole when `system_mode_pam.rs` needed the same pieces:
// each file in `qshd/tests/` is its own crate, so nothing private to one is
// visible to another. The only rename is `write_authorized_keys_for_account`,
// which would otherwise collide with this module's own
// [`write_authorized_keys`] (a different function: one file for whichever
// account logs in, rather than one per account's home).
// ---------------------------------------------------------------------------

/// The variable that says "this machine is disposable: create and remove
/// accounts on it, and write to `/etc/pam.d`". Set by the container command
/// in `system_mode_accounts.rs`'s docs, and never on a machine anyone keeps.
pub(crate) const DISPOSABLE_HOST_VAR: &str = "QSHD_TEST_DISPOSABLE_HOST";

/// The account names are fixed, and several tests create `qshd-test-alice`:
/// two at once would collide on `useradd`, or one's cleanup would remove the
/// account the other is using -- and, since `system_mode_pam.rs`, one's
/// `/etc/pam.d/qshd` would decide the other's logins. Cargo runs tests on
/// parallel threads unless told otherwise, so they take turns here rather
/// than rely on `--test-threads=1`.
///
/// This is per test BINARY, because Cargo compiles this module once per
/// binary. Two binaries that both use these accounts must therefore not run
/// at the same time -- which is why the container command runs one binary,
/// not `--test '*'`.
static ACCOUNT_TESTS: Mutex<()> = Mutex::new(());

/// Runs `body` on a machine this suite is allowed to damage -- root, on a
/// host declared disposable -- holding [`ACCOUNT_TESTS`] for as long as it
/// runs. Anywhere else it prints a loud `SKIPPED` line naming `test`, what
/// that test `does` to the machine, and which of the two conditions this
/// machine failed; `body` is then never called at all.
///
/// **The body is an argument, not something the caller runs after reading a
/// verdict.** Two earlier shapes of this guard both left a hole:
///
/// - a `disposable_root()` check beside a `skipped()` announcement -- two
///   calls with nothing tying them, so a test could consult one and forget
///   the other;
/// - one call returning `Option<MutexGuard>` -- better, but a returned
///   value can be discarded. `#[must_use]` catches a bare call and clippy's
///   `let_underscore_lock` catches `let Some(_) = ...`, yet `let _ = ...;`
///   followed by the body compiled clean under `-D warnings` and, on a
///   machine that is not disposable, printed `SKIPPED` and then created
///   real accounts anyway. `if ....is_none() { return; }` compiled clean
///   too, and ran the body with the turn already dropped.
///
/// There is no value here for a caller to mishandle: `body` runs when this
/// function calls it, and this function calls it only after both conditions
/// hold and the turn is in hand. Nothing can stop a test from writing its
/// body outside the guard entirely -- that is the same as not calling this
/// at all -- but every shape that calls the guard and then mishandles what
/// it says is gone.
///
/// `does` is the suite's own words -- what IT does to the machine, not what
/// some other suite does. The two suites differ: one creates real accounts
/// (a uid 0 alias among them), the other creates accounts AND overwrites
/// the machine's `/etc/pam.d/qshd`, and a skip line that claims the wrong
/// one teaches whoever reads it something false.
///
/// Cargo hides a passing test's output, so the line is only visible with
/// `--nocapture`: a skip nobody sees is a test nobody runs. That is a
/// known hole, not a solved problem -- cargo still reports a skipped test
/// as `ok`.
pub(crate) fn on_a_disposable_host(test: &str, does: &str, body: impl FnOnce()) {
    let root = Uid::effective().is_root();
    let disposable = std::env::var(DISPOSABLE_HOST_VAR).is_ok_and(|v| v == "1");
    if !root || !disposable {
        eprintln!(
            "SKIPPED {test}: this test {does}, so it runs only as root (here: {root}) AND with \
             {DISPOSABLE_HOST_VAR}=1 (here: {disposable}), which only a disposable container may \
             set -- see the suite's own module docs for the command."
        );
        return;
    }
    // A test that panicked while holding the lock poisons it. The lock
    // guards no data, only turns, so the next test simply goes ahead. The
    // guard lives to the end of this call, which is to say for exactly as
    // long as `body` runs.
    let _turn = ACCOUNT_TESTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    body();
}

/// How long an account command (`useradd`, `userdel`, `chage`) may take
/// before the test gives up on it. Generous: they are local and quick, but
/// nothing in this suite waits without a deadline.
const ACCOUNT_COMMAND_DEADLINE: Duration = Duration::from_secs(30);

/// Runs `program args...` to its end within [`ACCOUNT_COMMAND_DEADLINE`],
/// and prints what ran and how it ended -- the record of exactly which
/// accounts this suite created and removed. `Err` carries the exit code
/// (`None` if it had none) and a description with the command's stderr.
pub(crate) fn run_account_command(
    program: &str,
    args: &[&str],
) -> Result<(), (Option<i32>, String)> {
    let shown = format!("{program} {}", args.join(" "));
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| (None, format!("`{shown}` did not start: {e}")))?;
    let deadline = Instant::now() + ACCOUNT_COMMAND_DEADLINE;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                eprintln!("ACCOUNT COMMAND `{shown}`: killed after {ACCOUNT_COMMAND_DEADLINE:?}");
                return Err((
                    None,
                    format!("`{shown}` did not finish within {ACCOUNT_COMMAND_DEADLINE:?}"),
                ));
            }
            Err(e) => return Err((None, format!("waiting for `{shown}`: {e}"))),
        }
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let stderr = stderr.trim();
    if stderr.is_empty() {
        eprintln!("ACCOUNT COMMAND `{shown}`: {status}");
    } else {
        eprintln!("ACCOUNT COMMAND `{shown}`: {status} (stderr: {stderr})");
    }
    if status.success() {
        Ok(())
    } else {
        Err((
            status.code(),
            format!("`{shown}` ended with {status}: {stderr}"),
        ))
    }
}

/// [`run_account_command`], with its failure turned into a loud panic that
/// names the command: a test that silently ignores a failed `chage` goes on
/// to prove nothing at all.
pub(crate) fn run_account_command_or_panic(program: &str, args: &[&str]) {
    if let Err((code, err)) = run_account_command(program, args) {
        panic!("{program} {args:?} failed (exit {code:?}): {err}");
    }
}

/// What `userdel` exits with when a process of the account's uid is still
/// running.
const USERDEL_USER_BUSY: i32 = 8;

/// An account a test created itself -- the only kind of account `Drop` ever
/// removes. It is constructed right after a `useradd` that succeeded, and
/// never for a name that was already taken (see [`TestAccount::create_with`]).
pub(crate) struct CreatedAccount {
    name: String,
    /// A uid 0 alias: `userdel` refuses one without `--force`, because uid 0
    /// always has a process running (the test itself, and pid 1).
    uid0_alias: bool,
}

impl Drop for CreatedAccount {
    fn drop(&mut self) {
        if !self.uid0_alias {
            // The shells a test started go a moment after the daemon does --
            // the kernel hangs their terminals up once the worker holding the
            // other end is gone, and `--init` reaps them -- and until then
            // `userdel` sees them and refuses. Worth a short, bounded wait
            // before anything as blunt as `--force`.
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match run_account_command("userdel", &["--remove", &self.name]) {
                    Ok(()) => return,
                    Err((Some(USERDEL_USER_BUSY), _)) if Instant::now() < deadline => {
                        std::thread::sleep(Duration::from_millis(200));
                    }
                    Err(_) => break,
                }
            }
        }
        if let Err((_, e)) = run_account_command("userdel", &["--remove", "--force", &self.name]) {
            eprintln!(
                "LEFT BEHIND: the test account {} could not be removed: {e}",
                self.name
            );
        }
    }
}

/// A real account, created for one test and removed when it drops: its name
/// and uid as passwd has them, and a fresh key listed in its own
/// `~/.ssh/authorized_keys`.
pub(crate) struct TestAccount {
    pub(crate) name: String,
    pub(crate) uid: Uid,
    pub(crate) key: PrivateKey,
    _created: CreatedAccount,
}

impl TestAccount {
    /// `useradd --create-home --shell <shell> <name>`.
    pub(crate) fn create(name: &str, shell: &str) -> TestAccount {
        Self::create_with(name, &["--shell", shell], false)
    }

    /// `useradd --create-home --shell /bin/sh --non-unique --uid 0 <name>`:
    /// a second name for uid 0, the shape `toor` has on the BSDs.
    pub(crate) fn create_uid0_alias(name: &str) -> TestAccount {
        Self::create_with(
            name,
            &["--shell", "/bin/sh", "--non-unique", "--uid", "0"],
            true,
        )
    }

    fn create_with(name: &str, options: &[&str], uid0_alias: bool) -> TestAccount {
        assert!(
            name.starts_with("qshd-test-"),
            "a test account's name must start with qshd-test-, got {name}"
        );
        // Never touch an account this test did not create: one that already
        // exists belongs to somebody else -- or is a leftover to remove by
        // hand -- and `CreatedAccount`'s `Drop` would delete it.
        if User::from_name(name).expect("read passwd").is_some() {
            panic!(
                "an account named {name} already exists; this test removes only accounts it \
                 created itself, so it refuses to go on -- if it is a leftover of an earlier run, \
                 remove it by hand (userdel --remove {name})"
            );
        }
        let key = PrivateKey::random(&mut rand_core::OsRng, Algorithm::Ed25519).expect("keygen");

        let mut args = vec!["--create-home"];
        args.extend_from_slice(options);
        args.push(name);
        if let Err((_, e)) = run_account_command("useradd", &args) {
            panic!("creating the test account {name}: {e}");
        }
        // From here on the account is ours, and must go however the test
        // ends -- a panic below included.
        let created = CreatedAccount {
            name: name.to_string(),
            uid0_alias,
        };

        let user = User::from_name(name)
            .expect("read passwd")
            .unwrap_or_else(|| panic!("useradd reported success, yet {name} is not in passwd"));
        write_authorized_keys_for_account(&user.dir, user.uid, user.gid, &key);
        TestAccount {
            name: name.to_string(),
            uid: user.uid,
            key,
            _created: created,
        }
    }
}

/// Lists `key` as the only line of `<home>/.ssh/authorized_keys`, with the
/// modes and owner `sshd`'s `StrictModes` would ask for: the directory
/// `0700`, the file `0600`, both the account's own.
///
/// Not [`write_authorized_keys`], which writes ONE file for a daemon started
/// with an `--authorized-keys-template` that has no `%h` in it; this one
/// writes a real account's own file, which is what the default template
/// (`%h/.ssh/authorized_keys`) makes the helper read.
pub(crate) fn write_authorized_keys_for_account(home: &Path, uid: Uid, gid: Gid, key: &PrivateKey) {
    let owned_with_mode = |path: &Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
            .unwrap_or_else(|e| panic!("chmod {mode:o} {}: {e}", path.display()));
        std::os::unix::fs::chown(path, Some(uid.as_raw()), Some(gid.as_raw()))
            .unwrap_or_else(|e| panic!("chown {}: {e}", path.display()));
    };

    // NSS homes are real authorization paths. Keep this precondition explicit
    // so a fixture cannot pass by being refused before the intended check.
    use std::os::unix::fs::MetadataExt;
    for ancestor in home.ancestors() {
        let metadata = std::fs::symlink_metadata(ancestor).unwrap();
        assert!(metadata.is_dir());
        assert!(metadata.uid() == 0 || metadata.uid() == uid.as_raw());
        assert_eq!(metadata.mode() & 0o022, 0);
    }

    let ssh_dir = home.join(".ssh");
    std::fs::create_dir(&ssh_dir).unwrap_or_else(|e| panic!("create {}: {e}", ssh_dir.display()));
    owned_with_mode(&ssh_dir, 0o700);

    let path = ssh_dir.join("authorized_keys");
    let mut file =
        std::fs::File::create(&path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    writeln!(
        file,
        "{}",
        key.public_key().to_openssh().expect("encode public key")
    )
    .expect("write authorized_keys");
    file.flush().expect("flush authorized_keys");
    drop(file);
    owned_with_mode(&path, 0o600);
}

/// How many times the daemon's log mentions `needle` so far.
///
/// The wire carries one fixed reason for every refusal, so the helper's log
/// is the only place that says WHICH check it was (see [`daemon_log_path`]).
pub(crate) fn log_mentions(log: &Path, needle: &str) -> usize {
    std::fs::read_to_string(log)
        .map(|text| text.matches(needle).count())
        .unwrap_or(0)
}

/// A system-mode daemon as real accounts meet it: each account's own key
/// file (`%h/.ssh/authorized_keys` -- the daemon's default, spelled out so
/// the tests do not lean on it) and NO `--permit-root`.
/// [`start_daemon_with`] adds `--worker-user nobody`.
pub(crate) fn start_daemon_for_accounts(dir: &Path) -> (Daemon, [u8; 32], u16) {
    start_daemon_with(
        dir,
        &["--authorized-keys-template", "%h/.ssh/authorized_keys"],
    )
}

/// Where the daemon reads its PAM stack from, and the ONLY place it will:
/// `config::HelperConfig::pam_service` is `"qshd"` and no command line
/// changes it, because the service is part of what is shipped, not a setting
/// of a run.
const PAM_SERVICE_FILE: &str = "/etc/pam.d/qshd";

/// Writes `text` as [`PAM_SERVICE_FILE`], the machine's real one.
///
/// This is why the suites that call it run only on a disposable host: the
/// file is shared by everything on the machine, and a test that installs a
/// `pam_deny` stack in it would, on a machine anyone keeps, be locking that
/// machine's own `qshd` out. It is also the point -- a test that pointed the
/// daemon at a stack of its own would prove nothing about the file the
/// package ships.
///
/// PAM reads the file at every `pam_start`, so a test may call this again
/// mid-run and have the next login decided by the new text, with no daemon
/// restart.
pub(crate) fn install_service_file(text: &str) {
    let path = Path::new(PAM_SERVICE_FILE);
    std::fs::create_dir_all(path.parent().expect("the path has a parent"))
        .unwrap_or_else(|e| panic!("create /etc/pam.d: {e}"));
    std::fs::write(path, text).unwrap_or_else(|e| panic!("write {PAM_SERVICE_FILE}: {e}"));
    eprintln!("INSTALLED {PAM_SERVICE_FILE}:\n{text}");
}

/// How long [`start_daemon_expecting_refusal`] waits for the process to
/// exit. The refusal it is proving happens before a single descriptor is
/// bound (see `serve.rs`'s `refuse_without_pam_service`), so this is not a
/// generous allowance for slow startup work -- there is none to wait out.
const REFUSAL_DEADLINE: Duration = Duration::from_secs(10);

/// Starts `qshd serve --system` with the same arguments
/// [`start_daemon_for_accounts`] uses, for a caller that expects the
/// process to REFUSE rather than serve: hands back its stderr, the only
/// stream a refusal's reason can be read from (`serve` prints its banner to
/// stdout, and a refusal that reached that point would mean this function
/// was the wrong one to call).
///
/// The verdict is read off stdout, not inferred from a deadline. A
/// background thread blocks on the first line stdout ever produces: if
/// that line is the startup banner (`server-pubkey: ...`), the daemon
/// served, and this fails the instant that line arrives -- typically well
/// under a second, never waiting out [`REFUSAL_DEADLINE`] to say so. If
/// stdout instead closes with no such line, that is the refusal itself
/// (`serve` writes its reason to stderr and exits before printing
/// anything to stdout), and the loop moves on to reaping the process. A
/// process that neither prints the banner nor exits within
/// [`REFUSAL_DEADLINE`] is the one case this still cannot observe without
/// a bound -- "it does not exit" has no evidence of its own -- and that
/// panic says so explicitly, rather than folding it into the same message
/// as a proven "it served".
pub(crate) fn start_daemon_expecting_refusal(dir: &Path) -> String {
    let host_key = dir.join("host_key");
    let mut child = Command::new(qshd_binary())
        .args([
            "serve",
            "--system",
            "--port",
            &free_udp_port().to_string(),
            "--host-key",
            host_key.to_str().expect("utf-8 path"),
            "--worker-user",
            "nobody",
            "--authorized-keys-template",
            "%h/.ssh/authorized_keys",
        ])
        .env("XDG_CACHE_HOME", dir)
        .env("HOME", dir)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the `qshd serve --system` process starts");

    // Reads exactly one line and sends it, whatever it is (the banner, a
    // blank line at EOF, or -- if the pipe never closes and nothing is
    // ever written -- nothing at all, which is what the `recv_timeout`
    // below is the bound for).
    let stdout = child.stdout.take().expect("process stdout captured");
    let (banner_tx, banner_rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        let _ = BufReader::new(stdout).read_line(&mut line);
        let _ = banner_tx.send(line);
    });

    match banner_rx.recv_timeout(REFUSAL_DEADLINE) {
        Ok(line) if line.starts_with("server-pubkey: ") => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the daemon must refuse, not serve: it printed its startup banner instead of \
                 exiting on its own -- {line:?}"
            );
        }
        Ok(_) => {
            // No banner: stdout closed the way a refusal's does. `wait`
            // below is what actually confirms the process is gone, not
            // this.
        }
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "the daemon must refuse, not serve: it neither printed a startup banner nor \
                 closed stdout within {REFUSAL_DEADLINE:?}"
            );
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            unreachable!("the reader thread always sends exactly one line before its half closes")
        }
    }

    // Bounded exactly as the pre-witness code was: stdout closing does not
    // by itself prove the process has exited, only that this end of the
    // pipe is done.
    let deadline = Instant::now() + REFUSAL_DEADLINE;
    let status = loop {
        match child.try_wait().expect("polling the child does not error") {
            Some(status) => break status,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(20)),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                panic!(
                    "the daemon must refuse, not serve: stdout closed without a banner, but the \
                     process was still running after {REFUSAL_DEADLINE:?} instead of exiting on \
                     its own"
                );
            }
        }
    };
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    assert!(
        !status.success(),
        "the daemon must refuse to start, yet it exited successfully; stderr: {stderr}"
    );
    stderr
}
