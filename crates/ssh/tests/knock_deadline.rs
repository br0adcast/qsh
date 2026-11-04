//! Knocking and the TCP connect share one deadline of `connect_timeout`,
//! set once the host name has resolved: over loopback sockets this test
//! owns, a knock whose pauses do not fit ends at that deadline, and nothing
//! is dialled after it.

use std::net::{TcpListener, UdpSocket};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The SSH port: a listener nobody accepts on. A dial still completes into
/// its backlog, so `dialled` sees it afterwards without a thread.
struct SshPort(TcpListener);

impl SshPort {
    fn new() -> Self {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.set_nonblocking(true).unwrap();
        SshPort(l)
    }

    fn port(&self) -> u16 {
        self.0.local_addr().unwrap().port()
    }

    fn dialled(&self) -> bool {
        match self.0.accept() {
            Ok(_) => true,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(e) => panic!("accept: {e}"),
        }
    }
}

/// The knocked port: a datagram socket that reports what reached it.
struct KnockPort(UdpSocket);

impl KnockPort {
    fn new() -> Self {
        let s = UdpSocket::bind("127.0.0.1:0").unwrap();
        s.set_read_timeout(Some(Duration::from_millis(500)))
            .unwrap();
        KnockPort(s)
    }

    fn step(&self, delay_after_ms: u32) -> knock::KnockStep {
        knock::KnockStep {
            protocol: knock::KnockProtocol::Udp,
            port: self.0.local_addr().unwrap().port(),
            payload: b"knock-data".to_vec(),
            delay_after_ms,
        }
    }

    fn received(&self) -> Option<Vec<u8>> {
        let mut buf = [0u8; 64];
        self.0.recv(&mut buf).ok().map(|n| buf[..n].to_vec())
    }
}

fn params(ssh: &SshPort, timeout: Duration, knock: Vec<knock::KnockStep>) -> ssh::SshParams {
    ssh::SshParams {
        host: "127.0.0.1".into(),
        port: ssh.port(),
        username: "u".into(),
        known_host_keys: Vec::new(),
        connect_timeout: timeout,
        keepalive_interval: Duration::ZERO,
        compression: false,
        tcp_nodelay: true,
        knock,
    }
}

fn probe(
    p: ssh::SshParams,
    cancel: &knock::Cancel,
) -> (Result<ssh::HostKeyInfo, ssh::SshError>, Duration) {
    let started = Instant::now();
    let r = ssh::verify_host(p, Arc::new(knock::NoBind), cancel);
    (r, started.elapsed())
}

/// A 3 s pause under a 400 ms timeout: the knock goes out, the pause ends
/// at the deadline, and the SSH port is never dialled. The error names
/// neither the knocked port nor its data.
#[test]
fn a_pause_longer_than_the_timeout_ends_at_the_deadline_without_a_dial() {
    let ssh = SshPort::new();
    let knocked = KnockPort::new();
    let step = knocked.step(3_000);
    let knocked_port = step.port.to_string();
    let (r, took) = probe(
        params(&ssh, Duration::from_millis(400), vec![step]),
        &knock::Cancel::new(),
    );
    assert_eq!(knocked.received().as_deref(), Some(&b"knock-data"[..]));
    assert!(
        took >= Duration::from_millis(400) && took < Duration::from_millis(1_200),
        "took {took:?}: {r:?}"
    );
    assert!(!ssh.dialled(), "dialled after the deadline");
    match r {
        Err(ssh::SshError::Connect(m)) => {
            assert!(m.contains("knock") && m.contains("400ms"), "{m}");
            assert!(
                !m.contains(&knocked_port) && !m.contains("knock-data"),
                "{m}"
            );
        }
        other => panic!("{other:?}"),
    }
}

/// The longest pause the knock grammar accepts (over 49 days) is cut at
/// the deadline like any other.
#[test]
fn the_longest_accepted_pause_ends_at_the_deadline() {
    let ssh = SshPort::new();
    let knocked = KnockPort::new();
    let (r, took) = probe(
        params(
            &ssh,
            Duration::from_millis(300),
            vec![knocked.step(u32::MAX)],
        ),
        &knock::Cancel::new(),
    );
    assert!(matches!(r, Err(ssh::SshError::Connect(_))), "{r:?}");
    assert!(took < Duration::from_millis(1_100), "took {took:?}");
    assert!(knocked.received().is_some());
    assert!(!ssh.dialled());
}

/// A knock that fits leaves the rest of the deadline to the TCP connect:
/// the SSH port is dialled. Nobody answers there, so the probe then fails.
#[test]
fn a_knock_that_fits_is_followed_by_the_dial() {
    let ssh = SshPort::new();
    let knocked = KnockPort::new();
    let (r, _) = probe(
        params(&ssh, Duration::from_millis(700), vec![knocked.step(100)]),
        &knock::Cancel::new(),
    );
    assert!(r.is_err());
    assert!(knocked.received().is_some());
    assert!(ssh.dialled(), "{r:?}");
}

#[test]
fn without_a_knock_the_port_is_dialled() {
    let ssh = SshPort::new();
    let (r, _) = probe(
        params(&ssh, Duration::from_millis(500), Vec::new()),
        &knock::Cancel::new(),
    );
    assert!(r.is_err());
    assert!(ssh.dialled(), "{r:?}");
}

#[test]
fn a_cancel_during_a_knock_pause_dials_nothing() {
    let ssh = SshPort::new();
    let knocked = KnockPort::new();
    let cancel = knock::Cancel::new();
    let remote = cancel.clone();
    let canceller = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        remote.cancel();
    });
    let (r, took) = probe(
        params(&ssh, Duration::from_secs(30), vec![knocked.step(10_000)]),
        &cancel,
    );
    canceller.join().unwrap();
    assert!(matches!(r, Err(ssh::SshError::Cancelled)), "{r:?}");
    assert!(
        took < Duration::from_millis(150) + knock::SLICE * 4,
        "took {took:?}"
    );
    assert!(knocked.received().is_some());
    assert!(!ssh.dialled());
}

/// A zero timeout leaves no time: nothing is knocked and nothing dialled.
#[test]
fn a_zero_timeout_knocks_and_dials_nothing() {
    let ssh = SshPort::new();
    let knocked = KnockPort::new();
    let (r, _) = probe(
        params(&ssh, Duration::ZERO, vec![knocked.step(0)]),
        &knock::Cancel::new(),
    );
    assert!(matches!(r, Err(ssh::SshError::Connect(_))), "{r:?}");
    assert_eq!(knocked.received(), None);
    assert!(!ssh.dialled());
}

/// The binder is a synchronous callback the deadline cannot cut short; one
/// that outlasts it is followed by no dial.
#[test]
fn a_binder_that_outlasts_the_deadline_is_followed_by_no_dial() {
    struct SlowBind;
    impl knock::SocketBind for SlowBind {
        fn bind(&self, _fd: i32) -> bool {
            std::thread::sleep(Duration::from_millis(300));
            true
        }
    }
    if !cfg!(unix) {
        return;
    }
    let ssh = SshPort::new();
    let r = ssh::verify_host(
        params(&ssh, Duration::from_millis(100), Vec::new()),
        Arc::new(SlowBind),
        &knock::Cancel::new(),
    );
    assert!(matches!(r, Err(ssh::SshError::Connect(_))), "{r:?}");
    assert!(!ssh.dialled(), "dialled after the deadline");
}
