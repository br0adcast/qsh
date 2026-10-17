mod support;

use std::net::UdpSocket;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use support::*;

struct CountingBind(Arc<AtomicU32>);
impl knock::SocketBind for CountingBind {
    fn bind(&self, _fd: i32) -> bool {
        self.0.fetch_add(1, Ordering::SeqCst);
        true
    }
}

fn login(
    sshd: &TestSshd,
    signer: SoftSigner,
    mut p: ssh::SshParams,
    bind: Arc<dyn knock::SocketBind>,
) -> Result<ssh::SshConnection, ssh::SshError> {
    p.known_host_keys = vec![wire_of(&sshd.host_public_key_line())];
    ssh::connect(
        p,
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
        bind,
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(c, _)| c)
}

/// The knock goes out before the login, to the address that is then dialled.
#[test]
fn a_knock_precedes_the_connection() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let knocked = UdpSocket::bind("127.0.0.1:0").unwrap();
    knocked
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut p = params(&sshd, vec![]);
    p.knock = vec![knock::KnockStep {
        protocol: knock::KnockProtocol::Udp,
        port: knocked.local_addr().unwrap().port(),
        payload: b"open".to_vec(),
        delay_after_ms: 0,
    }];
    let conn = login(&sshd, signer, p, Arc::new(knock::NoBind)).expect("login");
    let mut buf = [0u8; 8];
    let n = knocked.recv(&mut buf).expect("the knock arrived");
    assert_eq!(&buf[..n], b"open");
    conn.close();
}

/// Every socket -- the knock's and the SSH one -- is offered to the binder.
#[test]
fn the_ssh_socket_is_offered_to_the_binder() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let count = Arc::new(AtomicU32::new(0));
    let conn = login(
        &sshd,
        signer,
        params(&sshd, vec![]),
        Arc::new(CountingBind(Arc::clone(&count))),
    )
    .expect("login");
    if cfg!(unix) {
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
    conn.close();
}

#[test]
fn compression_is_negotiated_when_asked() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let conn = login(
        &sshd,
        signer,
        params(&sshd, vec![]),
        Arc::new(knock::NoBind),
    )
    .expect("login");
    conn.close();
    std::thread::sleep(Duration::from_millis(200));
    assert!(
        sshd.log().contains("compression: zlib@openssh.com"),
        "{}",
        sshd.log()
    );
}

/// A silent address (a blackhole of the TEST-NET range) must not hold the
/// caller for the whole connect timeout once Cancel is pressed.
#[test]
fn cancel_during_connect_returns_quickly() {
    let cancel = knock::Cancel::new();
    let remote = cancel.clone();
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        remote.cancel();
    });
    let p = ssh::SshParams {
        host: "192.0.2.1".into(),
        port: 22,
        username: "u".into(),
        known_host_keys: Vec::new(),
        connect_timeout: Duration::from_secs(30),
        keepalive_interval: Duration::ZERO,
        compression: false,
        tcp_nodelay: true,
        knock: Vec::new(),
    };
    let started = Instant::now();
    let r = ssh::connect(
        p,
        ssh::SshAuthPlan::single(ssh::AuthMethod::Password(ssh::Zeroizing::new("x".into()))),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &cancel,
    );
    assert!(matches!(r, Err(ssh::SshError::Cancelled)), "{:?}", r.err());
    assert!(started.elapsed() < Duration::from_millis(200) + knock::SLICE * 4);
}

#[test]
fn a_refused_port_is_an_unreachable_error_with_its_kind() {
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let p = ssh::SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "u".into(),
        known_host_keys: Vec::new(),
        connect_timeout: Duration::from_secs(2),
        keepalive_interval: Duration::ZERO,
        compression: false,
        tcp_nodelay: true,
        knock: Vec::new(),
    };
    let r = ssh::connect(
        p,
        ssh::SshAuthPlan::single(ssh::AuthMethod::Password(ssh::Zeroizing::new("x".into()))),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    );
    // The OS's refusal is kept as data -- its kind and the target -- not
    // flattened into text.
    assert!(
        matches!(
            r,
            Err(ssh::SshError::Unreachable {
                kind: std::io::ErrorKind::ConnectionRefused,
                ..
            })
        ),
        "{:?}",
        r.err()
    );
}
