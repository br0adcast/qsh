//! Reconnecting, end to end (spec §5.2): a real `qshd serve`, a real `qsh`
//! on a pseudo-terminal that is its controlling terminal, and -- where the
//! network has to die -- a UDP relay between them that can be cut.
//!
//! The plate is read through [`top_row`], never from the raw bytes: the
//! renderer repaints only the cells that changed, so a plate's text can be
//! split across several writes. A shell's answer is looked for in the raw
//! bytes, with its marker split (`echo BEFORE'RE'TURN`,
//! `echo MA\RK$QSH_MARK`), so the typed command -- which the screen
//! echoes, and prediction may paint early -- never matches it.

#[path = "support/releases.rs"]
#[allow(dead_code)]
mod releases;
mod support;

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use support::*;

/// The client's terminal, as the tests spawn it.
const COLS: u16 = 80;
const ROWS: u16 = 24;

/// Everything the client has painted so far, collected on a background
/// thread.
struct Screen {
    seen: Arc<Mutex<Vec<u8>>>,
}

impl Screen {
    fn of(client: &Client) -> Screen {
        let seen = Arc::new(Mutex::new(Vec::new()));
        drain_into(
            client.master.try_clone().expect("clone master"),
            seen.clone(),
        );
        Screen { seen }
    }

    fn bytes(&self) -> Vec<u8> {
        self.seen.lock().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn text(&self) -> String {
        String::from_utf8_lossy(&self.bytes()).into_owned()
    }

    fn has(&self, needle: &str) -> bool {
        self.text().contains(needle)
    }

    /// The top row as a person reads it now.
    fn top(&self) -> String {
        top_row(&self.bytes(), COLS, ROWS)
    }

    /// Whether the top row read `needle` at any moment so far, not only now:
    /// a plate shown for a fraction of a second and gone again still counts.
    /// The output is replayed through the terminal model byte by byte and
    /// the top row read after each one.
    fn top_ever_had(&self, needle: &str) -> bool {
        let mut model = terminal::TerminalCore::new(COLS, ROWS);
        self.bytes().iter().any(|&byte| {
            model.feed(&[byte]);
            let frame = model.frame();
            (0..COLS)
                .map(|col| frame.cell(0, col).ch)
                .collect::<String>()
                .contains(needle)
        })
    }
}

/// What the client wrote to its `--verbose` log so far (`XDG_CACHE_HOME` is
/// the test's config directory).
fn verbose_log(config: &std::path::Path) -> String {
    std::fs::read_to_string(config.join("qsh").join("log")).unwrap_or_default()
}

/// Waits up to `within` for `probe` to hold. For the waits longer than
/// [`wait_until`]'s own limit: the ones set by the transport's death timer.
fn wait_for(within: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        if probe() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    probe()
}

/// First contact: the fingerprint is shown and trusted.
fn answer_yes(client: &mut Client, screen: &Screen, daemon: &Daemon) {
    assert!(
        wait_until(|| screen.has("Key fingerprint")),
        "the fingerprint must be shown on first contact; client saw: {}\ndaemon: {}",
        screen.text(),
        daemon.output_text()
    );
    client.master.write_all(b"yes\n").expect("answer");
}

/// Sets a variable only this shell process knows, and waits for the shell
/// to have run it.
fn mark_the_shell(client: &mut Client, screen: &Screen, daemon: &Daemon) {
    client.type_line("export QSH_MARK=kept");
    client.type_line("echo BEFORE'RE'TURN");
    assert!(
        wait_until(|| screen.has("BEFORERETURN")),
        "the shell must answer before anything else happens; client saw: {}\ndaemon: {}",
        screen.text(),
        daemon.output_text()
    );
}

/// Asks the shell for its mark until it answers `MARKkept`, or `within`
/// runs out. Typed again every second: keystrokes typed while no link
/// is live are dropped, not queued, and the test cannot see the exact
/// moment the new link is ready.
///
/// So an attempt may arrive cut short, its head dropped. The marker is split
/// by a backslash rather than by quotes for that reason: a tail such as
/// `'K$QSH_MARK` would open a quote and leave the shell waiting for the rest
/// of it, swallowing every later attempt, while a tail of this one is only a
/// command that is not found. Each attempt starts with Ctrl-U, which clears a
/// half-typed line without a signal (a Ctrl-C here makes the shell drop the
/// keystrokes that follow it).
fn the_same_shell_answers(client: &mut Client, screen: &Screen, within: Duration) -> bool {
    let deadline = Instant::now() + within;
    while Instant::now() < deadline {
        client.master.write_all(b"\x15").expect("type ctrl-u");
        client.type_line("echo MA\\RK$QSH_MARK");
        if wait_for(Duration::from_secs(1), || screen.has("MARKkept")) {
            assert!(!screen.has("Start a new session?"));
            return true;
        }
    }
    screen.has("MARKkept")
}

/// `exit` ends the shell, and the run ends with it: code 0.
fn exit_cleanly(client: &mut Client, screen: &Screen, daemon: &Daemon) {
    client.type_line("exit");
    let status = wait_for_exit(&mut client.child).unwrap_or_else(|| {
        panic!(
            "the client must exit once its shell does; client saw: {}\ndaemon: {}",
            screen.text(),
            daemon.output_text()
        )
    });
    assert_eq!(
        status.code(),
        Some(0),
        "a shell that exited is not a failure; client saw: {}\ndaemon: {}",
        screen.text(),
        daemon.output_text()
    );
}

/// `qsh` to `127.0.0.1` on `port` -- the relay's, when there is one -- with
/// the status line off: these scenarios read the reconnect plate.
fn spawn_to(port: u16, key_path: &std::path::Path, config: &std::path::Path) -> Client {
    spawn_qsh(
        &[
            "--port",
            &port.to_string(),
            "-i",
            key_path.to_str().expect("utf-8"),
            "--status",
            "off",
            "127.0.0.1",
        ],
        config,
    )
}

/// Grant a test-only public SSH key so greeting/backoff tests reach their
/// loopback listener under the same explicit authorization policy as users.
fn seed_recovery_binding(config: &std::path::Path, daemon_port: u16, ssh_port: u16) {
    use connect::server_identity::{ServerIdentity, SshBinding, SshEndpoint};
    let qsh_key =
        sshauth::discover::discover(([127, 0, 0, 1], daemon_port).into(), Duration::from_secs(1))
            .unwrap();
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let binding = SshBinding {
        server: ServerIdentity {
            qsh_key,
            username: qsh::args::parse_args(&["127.0.0.1".into()]).unwrap().login,
        },
        endpoint: SshEndpoint {
            host: "127.0.0.1".into(),
            port: ssh_port,
        },
        host_key: sshauth::record::encode_public_key(key.public_key()).unwrap(),
    };
    qsh::known_hosts::KnownHosts::new(config.join(".ssh/known_hosts"), None)
        .add("127.0.0.1", ssh_port, "ssh-ed25519", &binding.host_key)
        .unwrap();
    qsh::ssh_bindings::SshBindings::open(config.join("qsh/ssh_bindings.json"))
        .grant(
            &binding,
            &qsh::ssh_bindings::TrustWritePermit::new(connect::recovery_gate::RecoveryEpoch {
                connection: 0,
                network: 0,
            }),
        )
        .unwrap();
}

/// `Ctrl-] r` over a live link lets it go and returns to the same session:
/// a new connection is made (the client's log says it reattached, the
/// plate said it was reconnecting), the shell still knows a variable set
/// before, and no reconnect plate is left on the screen.
#[test]
fn ctrl_bracket_r_comes_back_to_the_same_shell() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_client_with(
        &daemon,
        &key_path,
        config.path(),
        &["--verbose", "--status", "off"],
    );
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    assert!(
        !verbose_log(config.path()).contains("reconnected at address"),
        "nothing has reconnected yet: {}",
        verbose_log(config.path())
    );

    let pressed = Instant::now();
    client.master.write_all(b"\x1dr").expect("type ctrl-] r");
    // Written only once a round's new connection has been adopted: without
    // a reconnect the original link would answer the mark below just the
    // same, so this is what proves Ctrl-] r did anything.
    assert!(
        wait_until(|| {
            let log = verbose_log(config.path());
            log.contains("letting the live link go") && log.contains("reconnected at address 0")
        }),
        "Ctrl-] r must let the live link go and reconnect; the verbose log: {}\ndaemon: {}",
        verbose_log(config.path()),
        daemon.output_text()
    );
    let reconnected_after = pressed.elapsed();
    assert!(
        screen.top_ever_had("reconnecting"),
        "the plate must have said it was reconnecting; client saw: {}",
        screen.text()
    );
    assert!(
        the_same_shell_answers(&mut client, &screen, Duration::from_secs(20)),
        "after Ctrl-] r the run must be back in the SAME shell, which still knows QSH_MARK; \
         client saw: {}\ndaemon: {}",
        screen.text(),
        daemon.output_text()
    );
    let back_after = pressed.elapsed();
    let top = screen.top();
    assert!(
        !top.contains("reconnecting"),
        "once back, no reconnect plate is left on the top row: {top:?}"
    );

    exit_cleanly(&mut client, &screen, &daemon);
    eprintln!(
        "ctrl_bracket_r: reconnected {reconnected_after:?}, back in the shell {back_after:?} \
         after Ctrl-] r; whole test {:?}",
        started.elapsed()
    );
}

/// A network that dies under a running session: the plate says the link is
/// lost, the transport's death timer (45 s) ends the link and a round starts
/// by itself, UDP rounds continue without a countdown; once the
/// network is back, the client is in the same shell again.
#[test]
fn a_dead_link_reconnects_by_itself_after_a_failed_round() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_to(relay.port, &key_path, config.path());
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);

    relay.cut();
    let cut = Instant::now();
    assert!(
        wait_for(Duration::from_secs(10), || {
            let top = screen.top();
            top.starts_with(" Ctrl-] ? ") && top.ends_with("reconnecting: 127.0.0.1 [QSH]")
        }),
        "a silent link must say so on the top row, with the prefix in use; \
         top row: {:?}\ndaemon: {}",
        screen.top(),
        daemon.output_text()
    );
    let lost_at = cut.elapsed();

    assert!(
        wait_for(Duration::from_secs(60), || verbose_log(config.path())
            .contains("recovery: UDP round 1")
            && screen.top().contains("reconnecting: 127.0.0.1 [QSH]")),
        "the death timer must end the link and start a round by itself; top row: {:?}\n\
         daemon: {}",
        screen.top(),
        daemon.output_text()
    );
    let reconnecting_at = cut.elapsed();
    // Decision 1 of the plan: the reconnect waits for the transport's own
    // death timer (45 s), not for anything shorter of the client's own.
    assert!(
        reconnecting_at >= Duration::from_secs(40),
        "a round must not start before the transport gives up on the link; \
         it started {reconnecting_at:?} after the cut"
    );

    assert!(
        wait_for(Duration::from_secs(40), || verbose_log(config.path())
            .contains("recovery: UDP round 2")),
        "UDP must continue to a second round without a growing pause; \
         top row: {:?}\ndaemon: {}",
        screen.top(),
        daemon.output_text()
    );
    let waiting_at = cut.elapsed();
    assert!(!screen.top().contains("next attempt in"));

    relay.restore();
    let restored = Instant::now();
    assert!(
        the_same_shell_answers(&mut client, &screen, Duration::from_secs(60)),
        "once the network is back, the run must return to the SAME shell; top row: {:?}\n\
         client saw: {}\ndaemon: {}",
        screen.top(),
        screen.text(),
        daemon.output_text()
    );
    let back_after = restored.elapsed();

    exit_cleanly(&mut client, &screen, &daemon);
    eprintln!(
        "dead_link: link lost at {lost_at:?}, reconnecting at {reconnecting_at:?}, \
         next attempt at {waiting_at:?} after the cut; back {back_after:?} after the restore; \
         whole test {:?}",
        started.elapsed()
    );
}

/// ICMP refusal accelerates a dead live socket and the following UDP rounds.
#[test]
fn a_closed_live_port_starts_recovery_and_retries_before_the_silent_deadline() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_to(relay.port, &key_path, config.path());
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    drop(relay);
    assert!(
        wait_for(Duration::from_secs(15), || verbose_log(config.path())
            .contains("recovery: UDP round 2")),
        "explicit refusal should reach a second UDP round before 45 seconds: {}",
        verbose_log(config.path())
    );
    assert!(client.child.try_wait().unwrap().is_none());
    client.master.write_all(b"\x1d.").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(1));
}

/// A refused primary must not detach a session that another path can carry.
#[test]
fn refusal_on_one_road_keeps_the_authenticated_alternative_and_shell() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let config = tempfile::tempdir().unwrap();
    let first = format!("127.0.0.1:{},ssh=1", relay.port);
    let second = format!("127.0.0.1:{}", daemon.port);
    let mut client = spawn_qsh(
        &[
            "--verbose",
            "-i",
            key_path.to_str().unwrap(),
            &first,
            &second,
        ],
        config.path(),
    );
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    drop(relay);
    assert!(
        the_same_shell_answers(&mut client, &screen, Duration::from_secs(15)),
        "{}",
        screen.text()
    );
    let log = verbose_log(config.path());
    assert!(!log.contains("recovery: UDP round"), "{log}");
    assert!(!log.contains("trying ssh"), "{log}");
    exit_cleanly(&mut client, &screen, &daemon);
}

/// Consent after authenticated loss starts a fresh, usable shell in this run.
#[test]
fn accepting_session_loss_starts_a_new_shell() {
    let _serial = serialised();
    let (mut daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    let size = libc::winsize {
        ws_col: 100,
        ws_row: 30,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: the PTY master is live and size points to a valid winsize.
    assert_eq!(
        unsafe {
            libc::ioctl(
                std::os::fd::AsRawFd::as_raw_fd(&client.master),
                libc::TIOCSWINSZ,
                &size,
            )
        },
        0
    );
    assert!(
        wait_for(Duration::from_secs(5), || {
            client.type_line("echo OLD'SIZE'$(stty size)");
            wait_for(Duration::from_millis(100), || screen.has("OLDSIZE29 100"))
        }),
        "{}",
        screen.text()
    );
    daemon.track_shell_starts();
    daemon.restart();
    client.master.write_all(b"\x1dr").unwrap();
    assert!(
        wait_until(|| screen.has("Start a new session? [Y/n]")),
        "{}",
        screen.text()
    );
    assert!(client.child.try_wait().unwrap().is_none());
    assert_eq!(daemon.shell_starts(), 0, "no shell may open before consent");
    let flags = nix::sys::termios::tcgetattr(&client.master)
        .unwrap()
        .local_flags;
    assert!(
        flags.contains(nix::sys::termios::LocalFlags::ECHO | nix::sys::termios::LocalFlags::ICANON)
    );
    let tokens = || {
        std::fs::read_dir(config.path().join("qsh/sessions"))
            .unwrap()
            .map(|file| std::fs::read(file.unwrap().path()).unwrap())
            .collect::<Vec<_>>()
    };
    let old_tokens = tokens();
    client
        .master
        .write_all(b"yes\necho LEAK'ED'REPLY\n")
        .unwrap();
    assert!(
        wait_until(|| screen.text().matches("\x1b[?1049h").count() == 2),
        "{}",
        screen.text()
    );
    assert_eq!(daemon.shell_starts(), 1);
    assert_ne!(tokens(), old_tokens);

    client.type_line("echo NEW'RE'PLY-${QSH_MARK:-fresh}");
    assert!(
        wait_until(|| screen.has("NEWREPLY-fresh")),
        "{}",
        screen.text()
    );
    client.type_line("echo NEW'SIZE'$(stty size)");
    assert!(
        wait_until(|| screen.has("NEWSIZE29 100")),
        "{}",
        screen.text()
    );
    assert!(!screen.has("NEWREPLY-kept"));
    assert!(!screen.has("LEAKEDREPLY"));
    client.type_line("export REPLACEMENT_MARK=retained");
    client.type_line("echo SAVE'D'REPLACEMENT");
    assert!(
        wait_until(|| screen.has("SAVEDREPLACEMENT")),
        "{}",
        screen.text()
    );
    daemon.restart();
    client.master.write_all(b"\x1dr").unwrap();
    assert!(
        wait_until(|| screen.text().matches("Start a new session? [Y/n]").count() == 2),
        "{}",
        screen.text()
    );
    assert_eq!(daemon.shell_starts(), 1);
    client.master.write_all(b"yes\n").unwrap();
    assert!(
        wait_until(|| screen.text().matches("\x1b[?1049h").count() == 3),
        "{}",
        screen.text()
    );
    client.type_line("export REPLACEMENT_MARK=twice");
    client.type_line("echo SECO'ND'-$REPLACEMENT_MARK");
    assert!(
        wait_until(|| screen.has("SECOND-twice")),
        "{}",
        screen.text()
    );
    client.master.write_all(b"\x1d.").unwrap();
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(1));
    let mut resumed = spawn_client(&daemon, &key_path, config.path());
    let resumed_screen = Screen::of(&resumed);
    resumed.type_line("echo RESU'MED'-$REPLACEMENT_MARK");
    assert!(
        wait_until(|| resumed_screen.has("RESUMED-twice")),
        "{}",
        resumed_screen.text()
    );
    assert_eq!(daemon.shell_starts(), 2);
    assert!(!resumed_screen.has("Start a new session?"));
    exit_cleanly(&mut resumed, &resumed_screen, &daemon);
}

#[test]
fn a_normal_shell_exit_with_13_does_not_offer_replacement() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    client.type_line("exit 13");
    assert_eq!(wait_for_exit(&mut client.child).unwrap().code(), Some(13));
    assert!(!screen.has("Start a new session?"));
}

fn refuse_session_loss(reply: &[u8], expected: i32) {
    let _serial = serialised();
    let (mut daemon, key_path) = start_daemon();
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_client(&daemon, &key_path, config.path());
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    daemon.track_shell_starts();
    daemon.restart();
    client.master.write_all(b"\x1dr").unwrap();
    assert!(
        wait_until(|| screen.has("Start a new session? [Y/n]")),
        "{}",
        screen.text()
    );
    let flags = nix::sys::termios::tcgetattr(&client.master)
        .unwrap()
        .local_flags;
    assert!(
        flags.contains(nix::sys::termios::LocalFlags::ECHO | nix::sys::termios::LocalFlags::ICANON)
    );
    assert_eq!(daemon.shell_starts(), 0);
    let asked = screen.text();
    assert!(asked.rfind("\x1b[?1049l").unwrap() < asked.find("Start a new session?").unwrap());
    let pressed = Instant::now();
    client.master.write_all(reply).unwrap();
    assert_eq!(
        wait_for_exit(&mut client.child).unwrap().code(),
        Some(expected),
        "{}",
        screen.text()
    );
    assert!(pressed.elapsed() < Duration::from_secs(3));
    assert_eq!(daemon.shell_starts(), 0);
    assert!(screen.has("the session on 127.0.0.1 is no longer on the server"));
}

#[test]
fn declining_session_loss_ends_the_run_with_13() {
    refuse_session_loss(b"no\n", 13);
}

#[test]
fn eof_after_session_loss_refuses_a_new_shell() {
    refuse_session_loss(b"\x04", 13);
}

#[test]
fn ctrl_c_cancels_the_loss_question_with_a_restored_terminal() {
    refuse_session_loss(b"\x03", 130);
}

/// A foreign daemon is a failed path, and the original key is tried again
/// when that same endpoint returns to the expected daemon.
#[test]
fn a_changed_server_key_during_recovery_is_retryable_without_repinning() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let (foreign, _) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_to(relay.port, &key_path, config.path());
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    let pins = config.path().join("qsh/known_hosts");
    let before = std::fs::read(&pins).unwrap();
    relay.redirect(foreign.port);
    client.master.write_all(b"\x1dr").unwrap();
    assert!(
        wait_for(Duration::from_secs(35), || verbose_log(config.path())
            .contains("outcome Direct(KeyChanged)")),
        "the foreign key must be diagnosed: {}",
        verbose_log(config.path())
    );
    assert!(
        client.child.try_wait().unwrap().is_none(),
        "a foreign daemon cannot end recovery"
    );
    assert_eq!(std::fs::read(&pins).unwrap(), before);
    relay.redirect(daemon.port);
    assert!(
        the_same_shell_answers(&mut client, &screen, Duration::from_secs(20)),
        "the same address must retry the expected key: {}",
        verbose_log(config.path())
    );
    assert_eq!(std::fs::read(&pins).unwrap(), before);
    exit_cleanly(&mut client, &screen, &daemon);
}

/// Every QSH path must fail before SSH starts. A foreign first path must
/// neither stop the run nor reach SSH while the second path still works.
#[test]
fn a_foreign_first_daemon_does_not_block_the_expected_second_path_or_enable_ssh() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let (foreign, _) = start_daemon();
    let first = UdpRelay::start(daemon.port);
    let second = UdpRelay::start(daemon.port);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let first_address = format!(
        "127.0.0.1:{},ssh={}",
        first.port,
        listener.local_addr().unwrap().port()
    );
    let second_address = format!("127.0.0.1:{}", second.port);
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_qsh(
        &[
            "-i",
            key_path.to_str().unwrap(),
            "--status",
            "off",
            &first_address,
            &second_address,
        ],
        config.path(),
    );
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    seed_recovery_binding(
        config.path(),
        daemon.port,
        listener.local_addr().unwrap().port(),
    );
    let pins = config.path().join("qsh/known_hosts");
    let key =
        sshauth::discover::discover(([127, 0, 0, 1], daemon.port).into(), Duration::from_secs(1))
            .unwrap();
    sshauth::known_hosts::KnownHosts::open(pins.clone())
        .pin("127.0.0.1", second.port, &key)
        .unwrap();
    let before = std::fs::read(&pins).unwrap();
    first.redirect(foreign.port);
    client.master.write_all(b"\x1dr").unwrap();
    assert!(
        wait_for(Duration::from_secs(20), || verbose_log(config.path())
            .contains("reconnected at address 1")),
        "the second path must recover after the first fails: {}",
        verbose_log(config.path())
    );
    assert!(the_same_shell_answers(
        &mut client,
        &screen,
        Duration::from_secs(10)
    ));
    assert!(
        matches!(listener.accept(), Err(e) if e.kind() == std::io::ErrorKind::WouldBlock),
        "SSH must not start when the second QSH address recovers"
    );
    assert!(!verbose_log(config.path()).contains("trying ssh"));
    assert_eq!(std::fs::read(&pins).unwrap(), before);
    assert!(client.child.try_wait().unwrap().is_none());
    exit_cleanly(&mut client, &screen, &daemon);
}

/// A stalled SSH greeting must not suspend UDP recovery. The same shell
/// returns while the accepted TCP connection still has said nothing.
#[test]
fn udp_recovers_while_ssh_is_waiting_for_its_greeting() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = format!(
        "127.0.0.1:{},ssh={}",
        relay.port,
        listener.local_addr().unwrap().port()
    );
    let config = tempfile::tempdir().unwrap();
    let request = bringup::ImageRequest::new(
        bringup::Platform::from_uname("Linux", std::env::consts::ARCH).unwrap(),
        env!("CARGO_PKG_VERSION"),
    )
    .unwrap();
    releases::seed_release_cache(&config.path().join("qsh"), &request, &qshd_path());
    let mut client = spawn_qsh(
        &[
            "-i",
            key_path.to_str().unwrap(),
            "--status",
            "off",
            &address,
        ],
        config.path(),
    );
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    seed_recovery_binding(
        config.path(),
        daemon.port,
        listener.local_addr().unwrap().port(),
    );
    relay.cut();
    client.master.write_all(b"\x1dr").unwrap();
    let mut ssh = None;
    assert!(
        wait_for(Duration::from_secs(30), || {
            if let Ok((stream, _)) = listener.accept() {
                ssh = Some(stream);
                true
            } else {
                false
            }
        }),
        "SSH fallback must start: {}",
        verbose_log(config.path())
    );
    relay.restore();
    assert!(
        wait_for(Duration::from_secs(4), || verbose_log(config.path())
            .contains("reconnected at address 0")),
        "UDP must recover without waiting for the SSH greeting: {}",
        verbose_log(config.path())
    );
    assert!(the_same_shell_answers(
        &mut client,
        &screen,
        Duration::from_secs(10)
    ));
    // SSH must be cancelled after UDP wins, without waiting ten seconds.
    let mut ssh = ssh.unwrap();
    ssh.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut buf = [0u8; 1024];
    loop {
        match std::io::Read::read(&mut ssh, &mut buf) {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => break,
            Err(e) => panic!("the losing SSH connection must close promptly: {e}"),
        }
    }
    assert!(
        !screen.text().contains("Install qshd"),
        "background recovery cannot offer installation: {}",
        screen.text()
    );
    exit_cleanly(&mut client, &screen, &daemon);
}

#[test]
fn udp_recovers_during_a_long_ssh_backoff() {
    let _serial = serialised();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = format!(
        "127.0.0.1:{},ssh={}",
        relay.port,
        listener.local_addr().unwrap().port()
    );
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_qsh(
        &[
            "-i",
            key_path.to_str().unwrap(),
            "--status",
            "off",
            &address,
        ],
        config.path(),
    );
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    seed_recovery_binding(
        config.path(),
        daemon.port,
        listener.local_addr().unwrap().port(),
    );
    relay.cut();
    client.master.write_all(b"\x1dr").unwrap();
    let mut tcp_admissions = 0;
    assert!(
        wait_for(Duration::from_secs(45), || {
            // An immediate EOF makes each SSH step fail without adding a timeout.
            if let Ok((stream, _)) = listener.accept() {
                tcp_admissions += 1;
                drop(stream);
            }
            verbose_log(config.path()).contains("next SSH round in 16 s; UDP keeps trying")
        }),
        "SSH must retain its growing pauses: {}",
        verbose_log(config.path())
    );
    assert!(
        tcp_admissions >= 5,
        "five actual TCP logins must produce the 16-second backoff; NeedsPrompt alone is not evidence: {tcp_admissions}; {}",
        verbose_log(config.path())
    );
    assert!(!screen.top().contains("next attempt in"));
    relay.restore();
    assert!(
        wait_for(Duration::from_secs(4), || verbose_log(config.path())
            .contains("reconnected at address 0")),
        "a 16-second SSH pause must not delay UDP: {}",
        verbose_log(config.path())
    );
    assert!(the_same_shell_answers(
        &mut client,
        &screen,
        Duration::from_secs(10)
    ));
    exit_cleanly(&mut client, &screen, &daemon);
}

/// `Ctrl-] .` in the middle of a round leaves at once -- the round is not
/// waited for -- and says the session is kept on the server.
#[test]
fn leaving_while_reconnecting_is_quick_and_keeps_the_session() {
    let _serial = serialised();
    let started = Instant::now();
    let (daemon, key_path) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let config = tempfile::tempdir().expect("tempdir");
    let mut client = spawn_to(relay.port, &key_path, config.path());
    let screen = Screen::of(&client);

    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);

    relay.cut();
    client.master.write_all(b"\x1dr").expect("type ctrl-] r");
    assert!(
        wait_until(|| screen.top().contains("reconnecting: 127.0.0.1 [QSH]")),
        "Ctrl-] r must start a round, and the plate must say so; top row: {:?}\ndaemon: {}",
        screen.top(),
        daemon.output_text()
    );

    let pressed = Instant::now();
    client.master.write_all(b"\x1d.").expect("type ctrl-] .");
    let mut status = None;
    while pressed.elapsed() < Duration::from_secs(3) {
        if let Ok(Some(s)) = client.child.try_wait() {
            status = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let left_after = pressed.elapsed();
    let status = status.unwrap_or_else(|| {
        panic!(
            "leaving mid-round must take no longer than 3 s; top row: {:?}\nclient saw: {}",
            screen.top(),
            screen.text()
        )
    });
    assert_eq!(
        status.code(),
        Some(1),
        "leaving on the user's own instruction is exit 1; client saw: {}",
        screen.text()
    );
    assert!(
        wait_until(|| screen.has("the session is kept on the server")),
        "the way back must be printed on the way out; client saw: {}",
        screen.text()
    );
    eprintln!(
        "leaving_mid_round: exit 1 {left_after:?} after Ctrl-] .; whole test {:?}",
        started.elapsed()
    );
}

#[test]
fn enter_after_session_loss_starts_a_new_shell() {
    let _serial = serialised();
    let (mut daemon, key) = start_daemon();
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_client(&daemon, &key, config.path());
    let screen = Screen::of(&client);
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    daemon.restart();
    client.master.write_all(b"\x1dr").unwrap();
    assert!(
        wait_until(|| screen.has("Start a new session?")),
        "{}",
        screen.text()
    );
    client.master.write_all(b"\n").unwrap();
    assert!(
        wait_until(|| screen.text().matches("\x1b[?1049h").count() == 2),
        "Enter must accept: {}",
        screen.text()
    );
    client.type_line("echo DEFAULT'YES'-$((6*7))");
    assert!(
        wait_until(|| screen.has("DEFAULTYES-42")),
        "{}",
        screen.text()
    );
    assert!(screen.has("Start a new session? [Y/n]"));
    exit_cleanly(&mut client, &screen, &daemon);
}

#[test]
fn replacement_starts_at_the_road_that_confirmed_loss() {
    let _serial = serialised();
    let (mut daemon, key) = start_daemon();
    let first = UdpRelay::start(daemon.port);
    let second = UdpRelay::start(daemon.port);
    second.cut();
    let config = tempfile::tempdir().unwrap();
    let expected =
        sshauth::discover::discover(([127, 0, 0, 1], daemon.port).into(), Duration::from_secs(1))
            .unwrap();
    let pins = sshauth::known_hosts::KnownHosts::open(config.path().join("qsh/known_hosts"));
    for port in [first.port, second.port] {
        pins.pin("127.0.0.1", port, &expected).unwrap();
    }
    let mut client = spawn_qsh(
        &[
            "--verbose",
            "-i",
            key.to_str().unwrap(),
            &format!("127.0.0.1:{}", first.port),
            &format!("127.0.0.1:{}", second.port),
        ],
        config.path(),
    );
    let screen = Screen::of(&client);
    mark_the_shell(&mut client, &screen, &daemon);
    first.cut();
    daemon.restart();
    second.restore();
    client.master.write_all(b"\x1dr").unwrap();
    assert!(
        wait_for(Duration::from_secs(30), || screen
            .has("Start a new session?")),
        "{}",
        verbose_log(config.path())
    );
    let accepted = Instant::now();
    client.master.write_all(b"y\n").unwrap();
    assert!(
        wait_for(Duration::from_secs(15), || screen
            .text()
            .matches("\x1b[?1049h")
            .count()
            == 2),
        "replacement must eventually use the confirmed road; {}",
        verbose_log(config.path())
    );
    client.type_line("echo QUICK'FRESH'-$((6*7))");
    assert!(
        wait_until(|| screen.has("QUICKFRESH-42")),
        "{}",
        screen.text()
    );
    let usable_after = accepted.elapsed();
    eprintln!("accepted replacement usable in {usable_after:?}");
    assert!(
        usable_after < Duration::from_secs(3),
        "replacement must prefer the confirmed road, was {usable_after:?}; {}",
        verbose_log(config.path())
    );
    exit_cleanly(&mut client, &screen, &daemon);
}

#[test]
fn ended_shell_on_authenticated_resume_delivers_its_retained_exit() {
    let _serial = serialised();
    let (daemon, key) = start_daemon();
    let relay = UdpRelay::start(daemon.port);
    let config = tempfile::tempdir().unwrap();
    let mut client = spawn_to(relay.port, &key, config.path());
    // Observe the complete stream through EOF before excluding error diagnostics:
    // those notices can be printed after alternate-screen restoration.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let screen = Screen { seen: seen.clone() };
    let mut reader = client.master.try_clone().unwrap();
    let (drained_tx, drained_rx) = std::sync::mpsc::channel();
    let drain = std::thread::spawn(move || {
        let mut buf = [0; 4096];
        loop {
            match std::io::Read::read(&mut reader, &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => seen.lock().unwrap().extend_from_slice(&buf[..n]),
            }
        }
        let _ = drained_tx.send(());
    });
    answer_yes(&mut client, &screen, &daemon);
    mark_the_shell(&mut client, &screen, &daemon);
    let pid_path = config.path().join("test-shell-pid");
    client.type_line(&format!("printf '%s' \"$$\" > '{}'", pid_path.display()));
    assert!(wait_until(
        || std::fs::read_to_string(&pid_path).is_ok_and(|s| !s.is_empty())
    ));
    let pid =
        nix::unistd::Pid::from_raw(std::fs::read_to_string(&pid_path).unwrap().parse().unwrap());
    relay.cut();
    client.master.write_all(b"\x1dr").unwrap();
    nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGKILL).unwrap();
    assert!(wait_until(|| matches!(
        nix::sys::signal::kill(pid, None),
        Err(nix::errno::Errno::ESRCH)
    )));
    relay.restore();
    // The process is gone, but its retained output/Exit lifecycle is still
    // authoritative. Resuming it must finish that lifecycle, not misclassify it
    // as an absent shell and offer to replace it.
    let status = wait_for_exit(&mut client.child)
        .expect("the retained final Exit must end the resumed client");
    assert_eq!(
        status.code(),
        Some(1),
        "portable-pty maps SIGKILL to exit 1"
    );
    drained_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("client output must reach EOF after its process exits");
    drain.join().unwrap();
    assert!(screen.has("\x1b[?1049l"));
    assert_eq!(screen.text().matches("\x1b[?1049h").count(), 1);
    assert!(!screen.has("channel protocol failure"));
    assert!(!screen.has("resumed attachment already admitted channel metadata"));
    assert!(!screen.has("Start a new session?"));
    assert!(!screen.has("the shell on the server ended while the link was down"));
}
