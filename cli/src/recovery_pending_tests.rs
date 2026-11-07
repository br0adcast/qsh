//! Real loopback bootstrap work is retained independently of ordinary admission.
use super::*;
use std::net::UdpSocket;
use std::sync::atomic::AtomicUsize;
use transport::bootstrap::{BootstrapResponder, ServerInfo, SessionProfile};

const EPOCH: RecoveryEpoch = RecoveryEpoch {
    connection: 530,
    network: 3,
};

struct Peer {
    address: SocketAddr,
    key: [u8; 32],
    release: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicUsize>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Peer {
    fn new() -> Self {
        let key = transport::generate_keypair();
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(10)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let release = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicUsize::new(0));
        let (allow, cancel, count) = (release.clone(), stop.clone(), requests.clone());
        let worker = std::thread::spawn(move || {
            let mut responder = BootstrapResponder::new(
                key.private,
                ServerInfo {
                    generation: [53; 16],
                    core_version: "0.7.0".into(),
                    session_protocols: vec![SessionProfile {
                        wire: 255,
                        handshake: 255,
                        channel: 255,
                    }],
                },
            )
            .unwrap();
            let mut oldest = None;
            let mut queued: Vec<(SocketAddr, Vec<u8>)> = Vec::new();
            let mut bytes = [0; 2048];
            while !cancel.load(Ordering::SeqCst) {
                if allow.load(Ordering::SeqCst) {
                    for (source, packet) in queued.drain(..) {
                        if let Some(reply) = responder.on_datagram(Instant::now(), source, &packet)
                        {
                            let _ = socket.send_to(&reply, source);
                        }
                    }
                }
                let Ok((len, source)) = socket.recv_from(&mut bytes) else {
                    continue;
                };
                if !bytes[..len].starts_with(b"QSHB") {
                    continue;
                }
                count.fetch_add(1, Ordering::SeqCst);
                if oldest.is_none() {
                    oldest = Some(source);
                }
                if oldest != Some(source) {
                    continue;
                }
                if allow.load(Ordering::SeqCst) {
                    if let Some(reply) =
                        responder.on_datagram(Instant::now(), source, &bytes[..len])
                    {
                        let _ = socket.send_to(&reply, source);
                    }
                } else {
                    queued.push((source, bytes[..len].to_vec()));
                }
            }
        });
        Self {
            address,
            key: key.public,
            release,
            stop,
            requests,
            worker: Some(worker),
        }
    }

    fn attempt(&self) -> crate::connect::Attempt {
        let (tx, _rx) = std::sync::mpsc::channel();
        let attempt = crate::connect::Attempt::open(
            self.address,
            self.key,
            transport::generate_keypair().private,
            crate::connect::Login::Allowlist,
            tx,
            crate::connect::AttemptScope {
                token: [53; 16],
                input_budget: Default::default(),
            },
        );
        let until = Instant::now() + Duration::from_secs(1);
        while attempt.client.discovery_deadline().is_none() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(attempt.client.discovery_deadline().is_some());
        attempt
    }
}
impl Drop for Peer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.worker.take().unwrap().join().unwrap();
    }
}

#[test]
fn discovery_pending_old_exchange_survives_reprobes_and_has_active_qsh_until_cleanup() {
    let peer = Peer::new();
    let recovery = Recovery::new(EPOCH, 1);
    recovery.begin_sweep(SweepId(1));
    let mut clients = Vec::new();
    for n in 0..4 {
        let query = recovery
            .begin_qsh_metadata(
                recovery.revision(),
                EPOCH,
                SweepId(1),
                vec![(AddressId(0), peer.address)],
            )
            .unwrap();
        let attempt = peer.attempt();
        clients.push(attempt.client.clone());
        if n == 0 {
            let until = Instant::now() + Duration::from_secs(1);
            while peer.requests.load(Ordering::SeqCst) == 0 && Instant::now() < until {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(peer.requests.load(Ordering::SeqCst) > 0);
        }
        assert_eq!(
            recovery.retain_failed_discovery(attempt, query),
            n < 3,
            "bounded overlap cancels new redundant metadata, never older work"
        );
    }
    assert_eq!(recovery.pending_discovery_count(), 3);
    recovery.clear_qsh_attempt(recovery.revision(), SweepId(1));
    assert_eq!(
        recovery.activity().qsh,
        vec![QshActivity {
            address: AddressId(0),
            endpoint: Some(peer.address)
        }]
    );
    recovery.begin_sweep(SweepId(2));
    recovery.finish(
        recovery.revision(),
        EPOCH,
        SweepId(2),
        AddressId(0),
        AddressOutcome::Failed,
    );
    peer.release.store(true, Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(1);
    while recovery.discovered_server_info().is_none() && Instant::now() < until {
        recovery.poll_pending_discovery();
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(peer.requests.load(Ordering::SeqCst) > 0);
    assert_eq!(
        recovery.discovered_server_info().unwrap().info().generation,
        [53; 16],
        "still-active older request can finish after its source sweep ended"
    );
    recovery.stop();
    assert_eq!(recovery.pending_discovery_count(), 0);
    assert!(recovery.activity().qsh.is_empty());
    assert!(
        clients.iter().all(|client| client.discovery_complete()),
        "cancel joins every retained driver"
    );
}

#[test]
fn discovery_pending_catalog_change_reaps_owned_driver_and_discards_late_evidence() {
    let peer = Peer::new();
    let recovery = Recovery::with_catalog(
        EPOCH,
        vec![AddressId(0)],
        vec![(AddressId(0), peer.address)],
    );
    recovery.begin_sweep(SweepId(1));
    let query = recovery
        .begin_qsh_metadata(
            recovery.revision(),
            EPOCH,
            SweepId(1),
            vec![(AddressId(0), peer.address)],
        )
        .unwrap();
    let attempt = peer.attempt();
    let client = attempt.client.clone();
    assert!(recovery.retain_failed_discovery(attempt, query));
    recovery.update_endpoints(
        EPOCH,
        vec![(AddressId(0), "127.0.0.2:53000".parse().unwrap())],
    );
    assert_eq!(recovery.pending_discovery_count(), 0);
    assert!(client.discovery_complete());
    peer.release.store(true, Ordering::SeqCst);
    recovery.poll_pending_discovery();
    assert!(recovery.discovered_server_info().is_none());
    assert!(recovery.display_server_info().is_none());
    assert!(recovery.activity().qsh.is_empty());
}
