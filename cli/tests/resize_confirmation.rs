//! Geometry confirmation and recovery through real daemon, ordered client and PTY.
mod support;

use client::channel::{AttachmentIntent, ChannelSession, ResizeDisposition, SessionEvent};
use client::qsh::QshSubstrate;
use client::ShellState;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};
use transport::channel::{
    decode_client, decode_server, ClientRecord, ServerRecord, CONTROL_STREAM,
};
use transport::channel_geometry::{GeometryOutcome, ResizeRefusal};
use transport::conn::{AuthPolicy, ConnectionConfig, Role};
use transport::driver_std::{Binder, ClientEvents, StdClient};
use transport::handshake::generate_keypair;
use transport::handshake_payload::StartKind;
use transport::shell_frame::{encode_shell, RecordDeframer, ShellRecord};
use transport::{Features, LinkState, Stats};

struct NoopBinder;
impl Binder for NoopBinder {
    fn bind(&self, _: i32) -> bool {
        true
    }
}
enum Incoming {
    Bytes(u8, Vec<u8>),
    Reset(u8),
    State(LinkState),
}
struct Events(mpsc::Sender<Incoming>);
impl ClientEvents for Events {
    fn on_bytes(&self, ch: u8, bytes: Vec<u8>) {
        let _ = self.0.send(Incoming::Bytes(ch, bytes));
    }
    fn on_reset(&self, ch: u8) {
        let _ = self.0.send(Incoming::Reset(ch));
    }
    fn on_state(&self, state: LinkState) {
        let _ = self.0.send(Incoming::State(state));
    }
    fn on_stats(&self, _: Stats) {}
}
struct Connection(Arc<StdClient>);
impl Drop for Connection {
    fn drop(&mut self) {
        self.0.detach();
    }
}
type Sink = Box<dyn FnMut(u8, Vec<u8>) + Send>;
struct Harness {
    connection: Connection,
    owner: ChannelSession<QshSubstrate<Sink>>,
    incoming: mpsc::Receiver<Incoming>,
    sent: Arc<Mutex<Vec<ClientRecord>>>,
    controls: RecordDeframer,
    snapshots: Vec<transport::channel::ChannelSnapshot>,
    events: Vec<SessionEvent>,
    model: ShellState,
    live: bool,
}
impl Harness {
    fn connect(
        daemon: &support::Daemon,
        key: &std::path::Path,
        private: [u8; 32],
        kind: StartKind,
        intent: Option<AttachmentIntent>,
    ) -> Self {
        let server = sshauth::discover::discover(
            ([127, 0, 0, 1], daemon.port).into(),
            Duration::from_secs(1),
        )
        .unwrap();
        let (tx, incoming) = mpsc::channel();
        let conn = Arc::new(StdClient::connect(
            ([127, 0, 0, 1], daemon.port).into(),
            ConnectionConfig {
                features: Features::SUPPORTED,
                required_features: Features::CHANNEL_GEOMETRY,
                role: Role::Client,
                local_static_priv: private,
                remote_static_pub: Some(server),
                auth: AuthPolicy::SshSignature,
            },
            [67; 16],
            kind,
            Arc::new(NoopBinder),
            Arc::new(Events(tx)),
            Some(Arc::new(
                sshauth::sign_file::FileSigner::load(key, None)
                    .unwrap()
                    .with_login("client".into()),
            )),
        ));
        let sent = Arc::new(Mutex::new(vec![]));
        let observed = sent.clone();
        let writer = conn.clone();
        let sink: Sink = Box::new(move |ch, bytes| {
            if ch == CONTROL_STREAM {
                for raw in RecordDeframer::for_control().push(&bytes) {
                    observed.lock().unwrap().push(decode_client(&raw).unwrap());
                }
            }
            writer.send_bytes(ch, bytes);
        });
        let mut owner = ChannelSession::new(QshSubstrate::new(sink));
        if let Some(intent) = intent {
            owner.import_attachment_intent(intent).unwrap();
        }
        let mut model = ShellState::new(512, 255, prediction::DisplayPreference::Never, false);
        model.set_history_limit(64);
        Self {
            connection: Connection(conn),
            owner,
            incoming,
            sent,
            controls: RecordDeframer::for_control(),
            snapshots: vec![],
            events: vec![],
            model,
            live: false,
        }
    }
    fn wait(&mut self, mut ready: impl FnMut(&mut Self) -> bool) {
        let until = Instant::now() + Duration::from_secs(20);
        while !ready(self) {
            assert!(
                Instant::now() < until,
                "ordered client did not make progress; geometry: {:?}; {} events total; last 16 event kinds: {:?}",
                self.owner.committed_geometry(16),
                self.events.len(),
                self.events
                    .iter()
                    .rev()
                    .take(16)
                    .map(|event| match event {
                        SessionEvent::Geometry { .. } => "Geometry",
                        SessionEvent::Data { .. } => "Data",
                        SessionEvent::InputConsumed { .. } => "InputConsumed",
                        SessionEvent::ResizeRefused { .. } => "ResizeRefused",
                        SessionEvent::Ready(_) => "Ready",
                        SessionEvent::Exit { .. } => "Exit",
                        SessionEvent::ProtocolFailure(_) => "ProtocolFailure",
                        _ => "Lifecycle",
                    })
                    .collect::<Vec<_>>()
            );
            match self.incoming.recv_timeout(Duration::from_millis(100)) {
                Ok(Incoming::Bytes(ch, bytes)) => {
                    if ch == CONTROL_STREAM {
                        for raw in self.controls.push(&bytes) {
                            if let ServerRecord::ChannelSnapshot(snapshot) =
                                decode_server(&raw).unwrap()
                            {
                                self.snapshots.push(snapshot);
                            }
                        }
                    }
                    for event in self.owner.on_bytes(ch, &bytes) {
                        match &event {
                            SessionEvent::Geometry { record, .. } => {
                                self.model.geometry_frame(record.cols, record.rows, 0);
                            }
                            SessionEvent::Data { bytes, .. } => {
                                self.model.on_stream0(
                                    &encode_shell(&ShellRecord::Data(bytes.clone())).unwrap(),
                                    0,
                                    0,
                                );
                            }
                            SessionEvent::InputConsumed { offset, .. } => {
                                self.model.on_stream0(
                                    &encode_shell(&ShellRecord::EchoAck(*offset)).unwrap(),
                                    0,
                                    0,
                                );
                            }
                            SessionEvent::ProtocolFailure(error) => {
                                panic!("protocol failure: {error:?}")
                            }
                            _ => {}
                        }
                        self.events.push(event);
                    }
                    self.connection.0.consumed(ch, bytes.len());
                }
                Ok(Incoming::Reset(ch)) => {
                    self.owner.reset_stream(ch);
                    self.model.on_reset();
                }
                Ok(Incoming::State(state)) => {
                    assert_ne!(state, LinkState::Closed);
                    self.live = state == LinkState::Live;
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(error) => panic!("driver ended: {error}"),
            }
        }
    }
    fn text(&mut self) -> String {
        self.model.frame(0, 0).cells.iter().map(|c| c.ch).collect()
    }
    fn command(&mut self, command: &str, result: &str) {
        self.owner.send(16, format!("{command}\n").as_bytes());
        self.wait(|s| s.text().contains(result));
    }
    fn resize_requests(&self) -> usize {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .filter(|r| matches!(r, ClientRecord::ResizeRequest { .. }))
            .count()
    }
}

#[test]
fn warm_recovery_repaints_retained_wrapped_text_at_the_new_width() {
    let _serial = support::serialised();
    let (daemon, key) = support::start_daemon();
    let private = generate_keypair().private;
    let mut original = Harness::connect(&daemon, &key, private, StartKind::Cold, None);
    original.model.set_history_limit(0);
    original.wait(|s| s.live);
    assert_eq!(original.owner.open_shell(80, 24), Some(16));
    original.wait(|s| s.owner.is_ready(16));
    let instance = original.owner.committed_geometry(16).unwrap().instance;

    // Only this initial write supplies application output. Replace the
    // interactive shell with a silent reader that ignores SIGWINCH: neither
    // readline nor an application redraw can repair a missing server repaint.
    let wrapped = "ABCDEFGHIJKLMNOPQRSTUVWXYZ".repeat(5);
    // Leave blank rows above the text so zero-history reflow can discard
    // them instead of discarding the start of the retained wrapped line.
    let output = format!("\x1bc\x1b[5;1H{wrapped}\r\nRETAINED-END\x1b[6;17H");
    let octal: String = output
        .bytes()
        .map(|byte| format!("\\0{byte:03o}"))
        .collect();
    let program = format!(
        "trap '' WINCH; printf '%b' '{octal}'; \
         while IFS= read -r command; do case \"$command\" in \
         size) printf 'PTY-%s\\n' \"$(stty size)\";; quit) exit 0;; esac; done"
    );
    let command = format!(
        "stty -echo; exec /bin/sh -c '{}'\n",
        program.replace('\'', "'\\''")
    );
    original.owner.send(16, command.as_bytes());

    // The independent reference receives the original application bytes,
    // never any replay generated by the daemon or recovered client.
    let mut reference = terminal::TerminalCore::with_options(
        terminal_size::TerminalSize::new(80, 24).unwrap(),
        terminal::TerminalOptions {
            history_lines: 0,
            replay: true,
        },
    );
    reference.feed(output.as_bytes());
    let before = reference.frame();
    assert_eq!(before.cell(4, 79).ch, 'B');
    assert_eq!(before.cell(5, 0).ch, 'C');
    assert_eq!((before.cursor_row, before.cursor_col), (5, 16));
    original.wait(|s| s.model.frame(0, 0) == before);

    original.connection.0.detach();
    let mut intent = original.owner.into_attachment_intent();
    assert_eq!(
        intent.defer_resize(16, 60, 20),
        ResizeDisposition::Coalesced
    );
    reference.resize(60, 20);
    let expected = reference.frame();
    assert_eq!(expected.cell(3, 59).ch, 'H');
    assert_eq!(expected.cell(4, 0).ch, 'I');
    assert_eq!(expected.cell(5, 0).ch, 'Q');
    assert_eq!((expected.cursor_row, expected.cursor_col), (4, 36));

    let mut resumed = Harness::connect(&daemon, &key, private, StartKind::Warm, Some(intent));
    resumed.model.set_history_limit(0);
    resumed.wait(|s| s.owner.is_ready(16));
    // As in the CLI's Ready/debounce path, release the deferred physical
    // size through the normal correlated resize API only once ready.
    assert_eq!(resumed.owner.resize(16, 60, 20), ResizeDisposition::Sent);
    // Applied alone is not enough: require actual later DATA and the complete
    // retained frame. No new input/output or manually generated repaint is
    // allowed to make this assertion pass.
    resumed.wait(|s| {
        let applied = s.events.iter().position(|event| {
            matches!(event, SessionEvent::Geometry { ch: 16, record }
                if record.instance == instance && record.outcome == GeometryOutcome::Applied
                    && (record.cols, record.rows) == (60, 20))
        });
        applied.is_some_and(|at| {
            s.events[at + 1..].iter().any(
                |event| matches!(event, SessionEvent::Data { ch: 16, bytes } if !bytes.is_empty()),
            )
        }) && s.model.frame(0, 0) == expected
    });
    assert_eq!(resumed.resize_requests(), 1);
    assert!(resumed
        .sent
        .lock()
        .unwrap()
        .iter()
        .all(|record| { !matches!(record, ClientRecord::Open(_)) }));
    let snapshot = resumed.snapshots.first().unwrap();
    assert_eq!(snapshot.active().len(), 1);
    assert_eq!(snapshot.active()[0].instance, instance);
    assert_eq!(
        (
            snapshot.active()[0].request.cols,
            snapshot.active()[0].request.rows
        ),
        (80, 24)
    );
    let committed = resumed.owner.committed_geometry(16).unwrap();
    assert_eq!(committed.instance, instance);
    assert_eq!((committed.cols, committed.rows), (60, 20));
    assert_eq!(committed.outcome, GeometryOutcome::Applied);
    assert!(resumed.owner.is_ready(16));

    // Probe the real PTY only after retained-content convergence, so its
    // output cannot conceal the recovery failure this test is meant to catch.
    resumed.command("size", "PTY-20 60");
    resumed.owner.send(16, b"quit\n");
    resumed.wait(|s| {
        s.events
            .iter()
            .any(|event| matches!(event, SessionEvent::Exit { ch: 16, code: 0 }))
    });
    resumed.connection.0.close();
}

#[test]
fn default_budget_refusal_keeps_ordered_geometry_pty_and_repaint_coherent() {
    let _serial = support::serialised();
    let (daemon, key) = support::start_daemon();
    // Height-only shrink keeps the initial high water; preparation temporarily
    // owns the retained row envelope twice, still within the default uid pool.
    let retained_rows = 4 * (255 + (2 * 255 + 1) * 512 + 255);
    assert_eq!(2 * retained_rows, 2_097_136);
    assert!(2 * retained_rows <= qshd::screen_budget::BudgetLimits::default().owner_rows);
    let private = generate_keypair().private;
    let mut h = Harness::connect(&daemon, &key, private, StartKind::Cold, None);
    h.wait(|s| s.live);
    assert_eq!(h.owner.open_shell(512, 255), Some(16));
    h.wait(|s| s.owner.is_ready(16));
    let established = h
        .events
        .iter()
        .position(|e| {
            matches!(e,
        SessionEvent::Geometry { ch:16, record } if record.outcome == GeometryOutcome::Established)
        })
        .unwrap();
    let ready = h
        .events
        .iter()
        .position(|e| matches!(e, SessionEvent::Ready(16)))
        .unwrap();
    assert!(established < ready);
    h.command(
        "stty -echo; unset PROMPT_COMMAND; PS1=''; printf 'INITIAL-%s\\n' \"$(stty size)\"",
        "INITIAL-255 512",
    );
    assert_eq!(h.owner.resize(16, 512, 256), ResizeDisposition::Sent);
    h.wait(|s| {
        s.events.iter().any(|e| {
            matches!(
                e,
                SessionEvent::ResizeRefused {
                    reason: ResizeRefusal::ResourceLimit,
                    ..
                }
            )
        })
    });
    let geometry = h.owner.committed_geometry(16).unwrap();
    assert_eq!(
        (geometry.request_id, geometry.cols, geometry.rows),
        (1, 512, 255)
    );
    assert_eq!(
        geometry.outcome,
        GeometryOutcome::Refused(ResizeRefusal::ResourceLimit)
    );
    assert_eq!(h.resize_requests(), 1);
    assert_eq!(h.owner.resize(16, 512, 256), ResizeDisposition::Unchanged);
    assert!(h.owner.is_ready(16));
    h.command("printf 'REFUSED-%s\\n' \"$(stty size)\"", "REFUSED-255 512");
    h.command(
        r"printf '\033[2J\033[1;511HABCD\033[254;1HEDGE\033[3;1HCOMPLETE'",
        "COMPLETE",
    );
    let frame = h.model.frame(0, 0);
    assert_eq!((frame.cols, frame.rows), (512, 255));
    assert_eq!(
        (
            frame.cell(0, 510).ch,
            frame.cell(0, 511).ch,
            frame.cell(1, 0).ch,
            frame.cell(1, 1).ch
        ),
        ('A', 'B', 'C', 'D')
    );
    assert_eq!(frame.cell(253, 0).ch, 'E');
    assert_eq!((frame.cursor_row, frame.cursor_col), (2, 8));
    h.connection.0.detach();
    let intent = h.owner.into_attachment_intent();
    let mut resumed = Harness::connect(&daemon, &key, private, StartKind::Warm, Some(intent));
    resumed.wait(|s| s.owner.is_ready(16) && s.text().contains("COMPLETE"));
    let snapshot = resumed.snapshots.last().unwrap();
    assert_eq!(
        (
            snapshot.active()[0].request.cols,
            snapshot.active()[0].request.rows
        ),
        (512, 255)
    );
    assert_eq!(resumed.resize_requests(), 0);
    assert_eq!(
        resumed.owner.resize(16, 512, 256),
        ResizeDisposition::Unchanged
    );
    let frame = resumed.model.frame(0, 0);
    assert_eq!(
        (
            frame.cell(0, 510).ch,
            frame.cell(1, 0).ch,
            frame.cell(253, 0).ch
        ),
        ('A', 'C', 'E')
    );
    assert_eq!(resumed.owner.resize(16, 512, 254), ResizeDisposition::Sent);
    resumed.wait(|s| {
        s.owner.committed_geometry(16).is_some_and(|g| {
            g.request_id == 1 && g.outcome == GeometryOutcome::Applied && g.rows == 254
        })
    });
    assert_eq!(resumed.resize_requests(), 1);
    resumed.command("printf 'APPLIED-%s\\n' \"$(stty size)\"", "APPLIED-254 512");
    resumed.command(
        r"printf '\033[2J\033[1;511HWXYZ\033[253;1HSHRUNK\033[3;1HDONE'",
        "DONE",
    );
    let frame = resumed.model.frame(0, 0);
    assert_eq!((frame.cols, frame.rows), (512, 254));
    assert_eq!(
        (
            frame.cell(0, 510).ch,
            frame.cell(1, 0).ch,
            frame.cell(252, 0).ch
        ),
        ('W', 'Y', 'S')
    );
    assert_eq!((frame.cursor_row, frame.cursor_col), (2, 4));
    resumed.owner.send(16, b"exit 0\n");
    resumed.wait(|s| {
        s.events
            .iter()
            .any(|e| matches!(e, SessionEvent::Exit { ch: 16, code: 0 }))
    });
    resumed.connection.0.close();
}

/// Decode only new renderer bytes, applying physical window changes at their
/// actual boundary instead of replaying earlier output at the final size.
struct PhysicalScreen {
    seen: Arc<Mutex<Vec<u8>>>,
    read: usize,
    model: terminal::TerminalCore,
}
impl PhysicalScreen {
    fn new(client: &support::Client) -> Self {
        let seen = Arc::new(Mutex::new(Vec::new()));
        support::drain_into(client.master.try_clone().unwrap(), seen.clone());
        Self {
            seen,
            read: 0,
            model: terminal::TerminalCore::new(512, 255),
        }
    }
    fn frame(&mut self) -> terminal::Frame {
        let bytes = self.seen.lock().unwrap();
        assert!(
            bytes.len() < 4 * 1024 * 1024,
            "sparse fixture output exceeded its bound"
        );
        self.model.feed(&bytes[self.read..]);
        self.read = bytes.len();
        self.model.frame()
    }
    fn has(&mut self, needle: &str) -> bool {
        self.frame()
            .cells
            .iter()
            .map(|c| c.ch)
            .collect::<String>()
            .contains(needle)
    }
    fn wait(&mut self, needle: &str) {
        assert!(
            support::wait_until(|| self.has(needle)),
            "missing rendered {needle}; escaped output tail: {}",
            {
                let bytes = self.seen.lock().unwrap();
                format!(
                    "{} bytes total, last {} bytes: {}",
                    bytes.len(),
                    bytes.len().min(1024),
                    String::from_utf8_lossy(&bytes[bytes.len().saturating_sub(1024)..])
                        .escape_debug()
                )
            }
        );
    }
    fn resize(&mut self, client: &support::Client, rows: u16) {
        use std::os::fd::AsRawFd;
        self.frame();
        self.model.resize(512, rows);
        let size = libc::winsize {
            ws_col: 512,
            ws_row: rows,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        // SAFETY: the master descriptor and winsize remain valid for ioctl.
        assert_eq!(
            unsafe { libc::ioctl(client.master.as_raw_fd(), libc::TIOCSWINSZ, &size) },
            0
        );
    }
    fn addressed(&mut self, first: char, wrapped: char, bottom: u16) {
        assert!(
            support::wait_until(|| {
                let f = self.frame();
                f.cell(10, 510).ch == first
                    && f.cell(11, 0).ch == wrapped
                    && f.cell(bottom, 0).ch == 'E'
            }),
            "addressed/wrapped output did not match authoritative geometry"
        );
    }
}

#[test]
fn default_budget_refusal_is_visible_with_chrome_off_and_renders_after_reconnect() {
    use std::io::Write;
    let _serial = support::serialised();
    let (daemon, key) = support::start_daemon();
    let config = tempfile::tempdir().unwrap();
    let port = daemon.port.to_string();
    let args: Vec<std::ffi::OsString> = [
        "--port",
        &port,
        "-i",
        key.to_str().unwrap(),
        "--status",
        "off",
        "127.0.0.1,nossh",
    ]
    .iter()
    .map(std::ffi::OsString::from)
    .collect();
    let (mut client, slave) = support::spawn_qsh_os_at(&args, config.path(), None, 512, 255);
    // Keep the slave alive just as the existing PTY helpers do while running.
    let mut screen = PhysicalScreen::new(&client);
    screen.wait("Key fingerprint");
    client.master.write_all(b"yes\n").unwrap();
    client.type_line(
        "stty -echo; unset PROMPT_COMMAND; PS1=''; printf 'INITIAL-%s\\n' \"$(stty size)\"",
    );
    screen.wait("INITIAL-255 512");
    screen.resize(&client, 256);
    screen.wait("Resize refused: resource limit; terminal remains 512x255");
    client.type_line("printf 'REFUSED-%s\\n' \"$(stty size)\"");
    screen.wait("REFUSED-255 512");
    client.type_line(r"printf '\033[2J\033[11;511HABCD\033[254;1HEDGE\033[20;1HPAINTED'");
    screen.wait("PAINTED");
    screen.addressed('A', 'C', 253);
    assert_eq!(
        (screen.frame().cursor_row, screen.frame().cursor_col),
        (19, 7)
    );
    assert!(screen.has("Resize refused"));
    assert_eq!(screen.frame().cell(255, 0).ch, ' ');
    let before_reconnect = screen.seen.lock().unwrap().len();
    client.master.write_all(b"\x1dr").unwrap();
    assert!(support::wait_until(|| {
        let repainted = screen.seen.lock().unwrap()[before_reconnect..]
            .windows(7)
            .any(|w| w == b"\x1b[H\x1b[2J");
        repainted && !screen.has("reconnecting:") && screen.has("PAINTED")
    }));
    // A new output marker proves the resumed shell accepts input, beyond
    // merely retaining old pixels. The ordered-owner test checks instance intent.
    client.type_line("printf 'RETURN-%s\\n' \"$(stty size)\"");
    screen.wait("RETURN-255 512");
    screen.addressed('A', 'C', 253);
    assert!(screen.has("Resize refused"));
    screen.resize(&client, 254);
    client.type_line("until [ \"$(stty size)\" = '254 512' ]; do sleep 0.02; done; printf 'APPLIED-%s\\n' \"$(stty size)\"");
    screen.wait("APPLIED-254 512");
    assert!(!screen.has("Resize refused"));
    client.type_line(r"printf '\033[2J\033[11;511HWXYZ\033[253;1HEDGE\033[20;1HSHRUNK'");
    screen.wait("SHRUNK");
    screen.addressed('W', 'Y', 252);
    assert_eq!(
        (screen.frame().cursor_row, screen.frame().cursor_col),
        (19, 6)
    );
    client.type_line("exit 0");
    assert_eq!(
        support::wait_for_exit(&mut client.child).unwrap().code(),
        Some(0)
    );
    drop(slave);
}
