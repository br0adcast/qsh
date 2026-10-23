mod support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use client::channel::{ChannelSubstrate, ResizeSemantics, SubstrateEvent};
use support::*;
use transport::channel::{ChannelKind, OpenRequest};

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<SubstrateEvent>>,
    closed: Mutex<Vec<String>>,
}

impl ssh::SshEvents for Recorder {
    fn on_channel(&self, event: SubstrateEvent) {
        self.events.lock().unwrap().push(event);
    }
    fn on_closed(&self, reason: String) {
        self.closed.lock().unwrap().push(reason);
    }
}

impl Recorder {
    /// Everything channel `ch` printed so far.
    fn output(&self, ch: u8) -> String {
        let mut out = Vec::new();
        for e in self.events.lock().unwrap().iter() {
            if let SubstrateEvent::Data { ch: c, bytes } = e {
                if *c == ch {
                    out.extend_from_slice(bytes);
                }
            }
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    fn wait_for(&self, what: impl Fn(&Recorder) -> bool, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while Instant::now() < deadline {
            if what(self) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn exit_of(&self, ch: u8) -> Option<i32> {
        self.events.lock().unwrap().iter().find_map(|e| match e {
            SubstrateEvent::Exit { ch: c, code } if *c == ch => Some(*code),
            _ => None,
        })
    }
}

fn up() -> Option<(
    TestSshd,
    ssh::SshConnection,
    ssh::SshSubstrate,
    Arc<Recorder>,
)> {
    sshd_or_skip()?;
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let known = wire_of(&sshd.host_public_key_line());
    let rec = Arc::new(Recorder::default());
    let (conn, sub) = ssh::connect(
        params(&sshd, vec![known]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
        Arc::new(knock::NoBind),
        rec.clone(),
        &knock::Cancel::new(),
    )
    .expect("connect");
    Some((sshd, conn, sub, rec))
}

fn shell(stream: u8, cols: u16, rows: u16) -> OpenRequest {
    OpenRequest {
        stream,
        kind: ChannelKind::Shell,
        cols,
        rows,
        screen: true,
        command: Vec::new(),
    }
}

fn command(stream: u8, cmd: &str) -> OpenRequest {
    OpenRequest {
        stream,
        kind: ChannelKind::Command,
        cols: 0,
        rows: 0,
        screen: false,
        command: cmd.as_bytes().to_vec(),
    }
}

#[test]
fn a_shell_channel_has_a_pty_of_the_requested_size_and_follows_a_resize() {
    let Some((_sshd, _conn, mut sub, rec)) = up() else {
        return;
    };
    assert_eq!(sub.resize_semantics(), ResizeSemantics::Unconfirmed);
    sub.announce_term("xterm-256color")
        .expect("fixture channel operation admitted");
    sub.open(&shell(16, 90, 30))
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(
        |r| r
            .events
            .lock()
            .unwrap()
            .contains(&SubstrateEvent::Opened(16)),
        Duration::from_secs(5)
    ));
    sub.send(16, b"stty size; echo T=$TERM; echo DO'NE'1\n")
        .expect("fixture channel operation admitted");
    assert!(
        rec.wait_for(|r| r.output(16).contains("DONE1"), Duration::from_secs(5)),
        "{}",
        rec.output(16)
    );
    assert!(rec.output(16).contains("30 90"));
    assert!(rec.output(16).contains("T=xterm-256color"));
    sub.resize(16, 120, 40)
        .expect("fixture channel operation admitted");
    sub.send(16, b"stty size; echo DO'NE'2\n")
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(|r| r.output(16).contains("DONE2"), Duration::from_secs(5)));
    assert!(rec.output(16).contains("40 120"));
    assert!(
        !rec.events
            .lock()
            .unwrap()
            .iter()
            .any(|event| matches!(event, SubstrateEvent::Geometry { .. })),
        "successful SSH transmission is not a correlated remote resize result"
    );
}

#[test]
fn an_exec_channel_reports_its_output_and_exit_code() {
    let Some((_sshd, _conn, mut sub, rec)) = up() else {
        return;
    };
    sub.open(&command(16, "echo out; exit 3"))
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(|r| r.exit_of(16).is_some(), Duration::from_secs(5)));
    assert_eq!(rec.exit_of(16), Some(3));
    assert!(rec.output(16).contains("out"));
}

#[test]
fn a_command_pty_does_not_echo_input_into_its_output() {
    let Some((_sshd, _conn, mut sub, rec)) = up() else {
        return;
    };
    let mut req = command(
        16,
        "test -t 0 && test -t 1 || exit 90; printf READY >&2; IFS= read -r line; test \"$line\" = input-marker || exit 91; printf DONE",
    );
    req.cols = 80;
    req.rows = 24;
    sub.open(&req).expect("fixture channel operation admitted");
    assert!(rec.wait_for(|r| r.output(16).contains("READY"), Duration::from_secs(5)));
    sub.send(16, b"input-marker\n")
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(|r| r.exit_of(16).is_some(), Duration::from_secs(5)));
    assert_eq!(rec.exit_of(16), Some(0));
    assert_eq!(
        rec.output(16),
        "READYDONE",
        "only the command's output belongs on this channel"
    );
}

#[test]
fn exec_stderr_is_not_stdout() {
    let Some((_sshd, _conn, mut sub, rec)) = up() else {
        return;
    };
    sub.open(&command(
        16,
        "printf stdout; printf stderr >&2; printf tail; exit 3",
    ))
    .expect("fixture channel operation admitted");
    assert!(rec.wait_for(|r| r.exit_of(16).is_some(), Duration::from_secs(5)));
    assert_eq!(rec.output(16), "stdouttail");
    let stderr: Vec<u8> = rec
        .events
        .lock()
        .unwrap()
        .iter()
        .filter_map(|event| match event {
            SubstrateEvent::ExtendedData {
                ch: 16,
                data_type: 1,
                bytes,
            } => Some(bytes.as_slice()),
            _ => None,
        })
        .flatten()
        .copied()
        .collect();
    assert_eq!(stderr, b"stderr");
    assert_eq!(rec.exit_of(16), Some(3));
}

#[test]
fn two_channels_share_one_connection() {
    let Some((_sshd, _conn, mut sub, rec)) = up() else {
        return;
    };
    sub.open(&shell(16, 80, 24))
        .expect("fixture channel operation admitted");
    sub.open(&command(17, "echo second"))
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(|r| r.exit_of(17).is_some(), Duration::from_secs(5)));
    assert!(rec.output(17).contains("second"));
    sub.send(16, b"echo fi'rst'\n")
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(|r| r.output(16).contains("first"), Duration::from_secs(5)));
}

#[test]
fn each_channel_exits_exactly_once() {
    let Some((_sshd, _conn, mut sub, rec)) = up() else {
        return;
    };
    sub.open(&command(16, "true"))
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(|r| r.exit_of(16).is_some(), Duration::from_secs(5)));
    std::thread::sleep(Duration::from_millis(300));
    let exits = rec
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| matches!(e, SubstrateEvent::Exit { ch: 16, .. }))
        .count();
    assert_eq!(exits, 1);
}

/// The network drops the connection (a relay in front of sshd is cut): the
/// session hears Closed exactly once and says it is closed.
#[test]
fn cutting_the_connection_reports_closed() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let proxy = Proxy::start(sshd.port);
    let mut p = params(&sshd, vec![wire_of(&sshd.host_public_key_line())]);
    p.port = proxy.port;
    let rec = Arc::new(Recorder::default());
    let (conn, mut sub) = ssh::connect(
        p,
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
        Arc::new(knock::NoBind),
        rec.clone(),
        &knock::Cancel::new(),
    )
    .expect("connect");
    sub.open(&shell(16, 80, 24))
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(
        |r| r
            .events
            .lock()
            .unwrap()
            .contains(&SubstrateEvent::Opened(16)),
        Duration::from_secs(5)
    ));
    proxy.cut();
    assert!(
        rec.wait_for(
            |r| !r.closed.lock().unwrap().is_empty(),
            Duration::from_secs(10)
        ),
        "no Closed"
    );
    assert!(conn.is_closed());
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(rec.closed.lock().unwrap().len(), 1, "closed exactly once");
}

#[test]
fn close_ends_the_connection_quietly() {
    let Some((_sshd, conn, _sub, rec)) = up() else {
        return;
    };
    conn.close();
    assert!(rec.wait_for(
        |r| !r.closed.lock().unwrap().is_empty(),
        Duration::from_secs(5)
    ));
    conn.close(); // idempotent
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(rec.closed.lock().unwrap().len(), 1, "closed exactly once");
}

/// A channel whose program never reads stdin fills its SSH window; writes
/// to it then wait for a window adjust that never comes. That must stall
/// only that channel: another channel still works, and `close()` still ends
/// the connection.
#[test]
fn a_full_window_on_one_channel_stalls_neither_the_others_nor_close() {
    let Some((_sshd, conn, mut sub, rec)) = up() else {
        return;
    };
    sub.open(&command(16, "sleep 60"))
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(
        |r| r
            .events
            .lock()
            .unwrap()
            .contains(&SubstrateEvent::Opened(16)),
        Duration::from_secs(5)
    ));
    sub.open(&shell(17, 80, 24))
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(
        |r| r
            .events
            .lock()
            .unwrap()
            .contains(&SubstrateEvent::Opened(17)),
        Duration::from_secs(5)
    ));
    let chunk = vec![b'x'; 64 * 1024];
    for step in 0..40 {
        sub.send(16, &chunk)
            .expect("fixture channel operation admitted");
        // A round trip lets the connection process each chunk before the
        // next one is queued. The blocked tail stays below the 1 MiB cap.
        sub.send(17, format!("echo pro'gress{step}'\n").as_bytes())
            .expect("fixture channel operation admitted");
        assert!(
            rec.wait_for(
                |r| r.output(17).contains(&format!("progress{step}")),
                Duration::from_secs(5)
            ),
            "the second channel stalled behind the full one"
        );
    }
    conn.close();
    assert!(
        rec.wait_for(
            |r| !r.closed.lock().unwrap().is_empty(),
            Duration::from_secs(5)
        ),
        "close() stalled behind the full channel"
    );
    assert!(conn.is_closed());
}

#[test]
fn close_bypasses_a_full_write_queue() {
    let Some((_sshd, conn, mut sub, rec)) = up() else {
        return;
    };
    sub.open(&command(16, "sleep 60"))
        .expect("fixture channel operation admitted");
    assert!(rec.wait_for(
        |r| r
            .events
            .lock()
            .unwrap()
            .contains(&SubstrateEvent::Opened(16)),
        Duration::from_secs(5)
    ));
    for _ in 0..512 {
        match sub.send(16, &[b'x'; 4096]) {
            Ok(()) => {}
            Err(error) => assert!(matches!(
                error,
                client::channel::ChannelSendError::Full | client::channel::ChannelSendError::Gone
            )),
        }
    }
    let closed = Instant::now();
    conn.close();
    assert!(rec.wait_for(
        |r| !r.closed.lock().unwrap().is_empty(),
        Duration::from_secs(2)
    ));
    assert!(closed.elapsed() < Duration::from_secs(2));
}

#[test]
fn an_oversized_packet_closes_with_a_resource_limit_reason() {
    let Some((_sshd, conn, mut sub, rec)) = up() else {
        return;
    };
    assert_eq!(
        sub.send(16, &vec![b'x'; 1024 * 1024 + 1]),
        Err(client::channel::ChannelSendError::Full)
    );
    assert!(
        rec.wait_for(
            |r| !r.closed.lock().unwrap().is_empty(),
            Duration::from_secs(2)
        ),
        "overflow left the connection alive"
    );
    assert!(conn.is_closed());
    assert!(rec.closed.lock().unwrap()[0].contains("resource limit"));
}

#[test]
fn on_closed_may_close_the_connection_again() {
    use std::sync::atomic::{AtomicBool, Ordering};
    struct CloseAgain {
        connection: Mutex<Option<ssh::SshConnection>>,
        completed: AtomicBool,
    }
    impl ssh::SshEvents for CloseAgain {
        fn on_channel(&self, _: SubstrateEvent) {}
        fn on_closed(&self, _: String) {
            self.connection.lock().unwrap().as_ref().unwrap().close();
            self.completed.store(true, Ordering::SeqCst);
        }
    }
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let events = Arc::new(CloseAgain {
        connection: Mutex::new(None),
        completed: AtomicBool::new(false),
    });
    let (connection, _sub) = ssh::connect(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
        Arc::new(knock::NoBind),
        events.clone(),
        &knock::Cancel::new(),
    )
    .unwrap();
    {
        let mut slot = events.connection.lock().unwrap();
        *slot = Some(connection);
        slot.as_ref().unwrap().close();
    }
    let started = Instant::now();
    while !events.completed.load(Ordering::SeqCst) && started.elapsed() < Duration::from_secs(2) {
        std::thread::yield_now();
    }
    assert!(
        events.completed.load(Ordering::SeqCst),
        "on_closed deadlocked while calling close again"
    );
}
