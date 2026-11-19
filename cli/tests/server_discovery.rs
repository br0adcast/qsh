//! Real CLI ownership and diagnostics against an authenticated bootstrap peer.
mod support;

use std::io::Read;
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

struct Peer {
    addr: std::net::SocketAddr,
    public: [u8; 32],
    bootstrap_requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl Peer {
    fn start(discovery: bool, reject_first: bool) -> Self {
        use transport::bootstrap::{BootstrapResponder, ServerInfo, SessionProfile};
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .unwrap();
        let addr = socket.local_addr().unwrap();
        let key = transport::generate_keypair();
        let public = key.public;
        let mut responder = BootstrapResponder::new(
            key.private,
            ServerInfo {
                generation: [9; 16],
                core_version: "99.0.0".into(),
                session_protocols: vec![SessionProfile {
                    wire: 99,
                    handshake: 99,
                    channel: 99,
                }],
            },
        )
        .unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let bootstrap_requests = Arc::new(AtomicUsize::new(0));
        let (done, count) = (stop.clone(), bootstrap_requests.clone());
        let thread = std::thread::spawn(move || {
            let mut bytes = [0; 65536];
            let mut rejected = false;
            let mut pending_bootstrap = None;
            while !done.load(Ordering::SeqCst) {
                let Ok((n, source)) = socket.recv_from(&mut bytes) else {
                    continue;
                };
                if bytes[..n].starts_with(b"QSHB") {
                    count.fetch_add(1, Ordering::SeqCst);
                    if discovery {
                        if reject_first && !rejected {
                            pending_bootstrap = Some((bytes[..n].to_vec(), source));
                            continue;
                        }
                        if let Some(reply) =
                            responder.on_datagram(Instant::now(), source, &bytes[..n])
                        {
                            socket.send_to(&reply, source).unwrap();
                        }
                    }
                } else if reject_first
                    && matches!(
                        transport::wire::parse(&bytes[..n]),
                        Ok(transport::wire::Frame::Handshake {
                            kind: transport::wire::Kind::HandshakeInit,
                            ..
                        })
                    )
                {
                    let Ok(transport::wire::Frame::Handshake { body, .. }) =
                        transport::wire::parse(&bytes[..n])
                    else {
                        unreachable!()
                    };
                    let mut noise = transport::handshake::Handshake::new_responder(&key.private);
                    noise.read_msg(body).unwrap();
                    let mut payload = transport::handshake_payload::encode_msg2(
                        7,
                        false,
                        &[0; 16],
                        transport::Features::SUPPORTED,
                    );
                    payload[0] = 99;
                    let response = noise.write_msg(&payload);
                    socket
                        .send_to(
                            &transport::wire::encode_handshake(
                                transport::wire::Kind::HandshakeResp,
                                &response,
                            ),
                            source,
                        )
                        .unwrap();
                    rejected = true;
                    // A real authenticated ordinary rejection is queued first.
                    // Only then can the independent bootstrap cookie exchange start.
                    if let Some((request, source)) = pending_bootstrap.take() {
                        if let Some(reply) = responder.on_datagram(Instant::now(), source, &request)
                        {
                            socket.send_to(&reply, source).unwrap();
                        }
                    }
                } else if matches!(
                    transport::wire::parse(&bytes[..n]),
                    Ok(transport::wire::Frame::Handshake {
                        kind: transport::wire::Kind::KeyRequest,
                        ..
                    })
                ) {
                    let reply = transport::wire::encode_handshake(
                        transport::wire::Kind::KeyOffer,
                        &transport::wire::encode_key_offer_body(&public),
                    );
                    socket.send_to(&reply, source).unwrap();
                }
            }
        });
        Self {
            addr,
            public,
            bootstrap_requests,
            stop,
            thread: Some(thread),
        }
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.take().unwrap().join().unwrap();
    }
}

fn run(discovery: bool) -> (i32, String, usize, Duration) {
    run_with_rejection(discovery, false)
}

fn run_with_rejection(discovery: bool, reject_first: bool) -> (i32, String, usize, Duration) {
    use std::os::unix::fs::PermissionsExt;
    let peer = Peer::start(discovery, reject_first);
    let home = tempfile::tempdir().unwrap();
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    let identity = home.path().join("identity");
    std::fs::write(
        &identity,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    std::fs::set_permissions(&identity, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pins = home.path().join("qsh/known_hosts");
    std::fs::create_dir_all(pins.parent().unwrap()).unwrap();
    sshauth::known_hosts::KnownHosts::open(pins)
        .pin("127.0.0.1", peer.addr.port(), &peer.public)
        .unwrap();
    let address = format!("discovery-fixture@{}", peer.addr);
    let (mut client, slave) =
        support::spawn_qsh_on(&["-i", identity.to_str().unwrap(), &address], home.path());
    let flags = rustix::fs::fcntl_getfl(&client.master).unwrap();
    rustix::fs::fcntl_setfl(&client.master, flags | rustix::fs::OFlags::NONBLOCK).unwrap();
    let started = Instant::now();
    let mut output = Vec::new();
    let drain = |master: &mut std::fs::File, output: &mut Vec<u8>| {
        let mut bytes = [0; 4096];
        for _ in 0..256 {
            match master.read(&mut bytes) {
                Ok(0) => break,
                Ok(n) => {
                    assert!(output.len() + n <= 1024 * 1024);
                    output.extend_from_slice(&bytes[..n]);
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.raw_os_error() == Some(libc::EIO) =>
                {
                    break
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => panic!("PTY read: {e}"),
            }
        }
    };
    let status = loop {
        drain(&mut client.master, &mut output);
        if let Some(status) = client.child.try_wait().unwrap() {
            drain(&mut client.master, &mut output);
            break status;
        }
        assert!(
            started.elapsed() < Duration::from_secs(25),
            "discovery CLI timed out: {}",
            String::from_utf8_lossy(&output)
        );
        std::thread::sleep(Duration::from_millis(10));
    };
    // Keep the slave through the final drain, including on Darwin.
    drop(slave);
    assert!(!home.path().join(".local/bin/qsh").exists());
    (
        status.code().unwrap(),
        String::from_utf8_lossy(&output).into_owned(),
        peer.bootstrap_requests.load(Ordering::SeqCst),
        started.elapsed(),
    )
}

#[test]
fn source_incompatible_initial_discovery_pty_shows_manual_rebuild_without_download_offer() {
    if option_env!("QSH_CLIENT_OFFICIAL") == Some("1") {
        return;
    }
    let (code, output, requests, _) = run(true);
    assert_eq!(code, 12, "{output}");
    assert!(
        requests >= 2,
        "bootstrap cookie and authenticated request must run"
    );
    assert!(output.contains("authenticated qshd 99.0.0"), "{output}");
    assert!(
        output.contains("wire 2, handshake 2, channel 2"),
        "{output}"
    );
    assert!(
        output.contains("rebuild a compatible qsh client"),
        "{output}"
    );
    assert!(
        !output.contains("Update this qsh") && !output.contains("Update client and relaunch"),
        "{output}"
    );
}

#[test]
fn legacy_unknown_initial_discovery_pty_keeps_ordinary_timeout_and_no_release_claim() {
    let (code, output, requests, elapsed) = run(false);
    assert_eq!(code, 12, "{output}");
    assert!(requests > 0, "discovery starts alongside admission");
    assert!(
        elapsed < Duration::from_secs(15),
        "bootstrap must not add a serial timeout: {elapsed:?}"
    );
    assert!(
        !output.contains("authenticated qshd 99.0.0")
            && !output.contains("rebuild a compatible qsh client"),
        "{output}"
    );
}

#[test]
fn authenticated_ordinary_rejection_cannot_cancel_initial_discovery_pty() {
    if option_env!("QSH_CLIENT_OFFICIAL") == Some("1") {
        return;
    }
    let (code, output, requests, _) = run_with_rejection(true, true);
    assert_eq!(code, 12, "{output}");
    assert!(
        requests >= 2,
        "discovery must complete its authenticated exchange after ordinary failure: {output}"
    );
    assert!(
        output.contains("authenticated qshd 99.0.0")
            && output.contains("rebuild a compatible qsh client"),
        "{output}"
    );
}
