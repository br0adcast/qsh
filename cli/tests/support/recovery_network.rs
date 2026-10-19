//! Loopback topology controls, with no recovery policy of their own.
#[path = "recovery_ssh.rs"]
mod fake;
use super::support::UdpRelay;
use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU16, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct RecoveryNetwork {
    qsh_key: [u8; 32],
    roads: [UdpRelay; 2],
    ssh: [TcpMapping; 2],
    expected: fake::Server,
    foreign: fake::Server,
}
impl RecoveryNetwork {
    pub fn new(daemon: u16) -> Self {
        let qsh_key =
            sshauth::discover::discover(([127, 0, 0, 1], daemon).into(), Duration::from_secs(1))
                .unwrap();
        let expected = fake::Server::start();
        let foreign = fake::Server::start();
        Self {
            qsh_key,
            roads: [UdpRelay::start(daemon), UdpRelay::start(daemon)],
            ssh: [
                TcpMapping::start(expected.port),
                TcpMapping::start(expected.port),
            ],
            expected,
            foreign,
        }
    }
    pub fn addresses(&self) -> [String; 2] {
        std::array::from_fn(|i| {
            format!("127.0.0.1:{},ssh={}", self.roads[i].port, self.ssh[i].port)
        })
    }
    pub fn switch_mapping(&self, targets: [Option<u16>; 2]) {
        for (road, target) in self.roads.iter().zip(targets) {
            road.cut();
            if let Some(port) = target {
                road.redirect(port);
                road.restore();
            }
        }
    }
    pub fn probes(&self) -> [usize; 2] {
        std::array::from_fn(|i| self.roads[i].received())
    }
    pub fn handshakes(&self) -> [Vec<std::time::Instant>; 2] {
        std::array::from_fn(|i| self.roads[i].handshakes())
    }
    pub fn pin_qsh(&self, home: &Path) {
        let store = sshauth::known_hosts::KnownHosts::open(home.join("qsh/known_hosts"));
        for road in &self.roads {
            store.pin("127.0.0.1", road.port, &self.qsh_key).unwrap();
        }
    }
    pub fn grant(&self, home: &Path) {
        use connect::{
            recovery_gate::RecoveryEpoch,
            server_identity::{ServerIdentity, SshBinding, SshEndpoint},
        };
        let server = ServerIdentity {
            qsh_key: self.qsh_key,
            username: qsh::args::parse_args(&["127.0.0.1".into()]).unwrap().login,
        };
        let store = qsh::ssh_bindings::SshBindings::open(home.join("qsh/ssh_bindings.json"));
        for endpoint in &self.ssh {
            qsh::known_hosts::KnownHosts::new(home.join(".ssh/known_hosts"), None)
                .add(
                    "127.0.0.1",
                    endpoint.port,
                    "ssh-ed25519",
                    &self.expected.wire(),
                )
                .unwrap();
            store
                .grant(
                    &SshBinding {
                        server: server.clone(),
                        endpoint: SshEndpoint {
                            host: "127.0.0.1".into(),
                            port: endpoint.port,
                        },
                        host_key: self.expected.wire(),
                    },
                    &qsh::ssh_bindings::TrustWritePermit::new(RecoveryEpoch {
                        connection: 0,
                        network: 0,
                    }),
                )
                .unwrap();
        }
    }
    pub fn trust_foreign_ssh(&self, home: &Path) {
        for endpoint in &self.ssh {
            qsh::known_hosts::KnownHosts::new(home.join(".ssh/known_hosts"), None)
                .add(
                    "127.0.0.1",
                    endpoint.port,
                    "ssh-ed25519",
                    &self.foreign.wire(),
                )
                .unwrap();
        }
    }
    pub fn switch_ssh(&self, road: usize, foreign: bool) {
        self.ssh[road].target.store(
            if foreign {
                self.foreign.port
            } else {
                self.expected.port
            },
            Ordering::SeqCst,
        );
    }
    pub fn hold_ssh(&self, hold: bool) {
        for ssh in &self.ssh {
            ssh.hold.store(hold, Ordering::SeqCst);
        }
    }
    pub fn ssh_connections(&self) -> usize {
        self.ssh
            .iter()
            .map(|ssh| ssh.accepted.load(Ordering::SeqCst))
            .sum()
    }
    pub fn ssh_closed(&self) -> usize {
        self.ssh
            .iter()
            .map(|ssh| ssh.closed.load(Ordering::SeqCst))
            .sum()
    }
    pub fn expected_exec(&self) -> usize {
        self.expected.activity.exec.load(Ordering::SeqCst)
    }
    pub fn foreign_connections(&self) -> usize {
        self.foreign.activity.connections.load(Ordering::SeqCst)
    }
    pub fn foreign_untouched(&self) {
        self.foreign.untouched();
    }
    pub fn untouched(&self) {
        self.expected.untouched();
        self.foreign.untouched();
    }
}

/// Each new TCP connection uses the mapping current at accept time. Holding
/// withholds the server greeting while still detecting client cancellation.
struct TcpMapping {
    port: u16,
    target: Arc<AtomicU16>,
    hold: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    closed: Arc<AtomicUsize>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<std::thread::JoinHandle<()>>,
}
impl TcpMapping {
    fn start(target_port: u16) -> Self {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let target = Arc::new(AtomicU16::new(target_port));
        let hold = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let closed = Arc::new(AtomicUsize::new(0));
        let (stop, mut stopped) = tokio::sync::oneshot::channel();
        let (mapping, held, admissions, closures) = (
            target.clone(),
            hold.clone(),
            accepted.clone(),
            closed.clone(),
        );
        let thread = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                loop { tokio::select! {
                    _ = &mut stopped => break,
                    next = listener.accept() => {
                        let (mut client, _) = next.unwrap();
                        admissions.fetch_add(1, Ordering::SeqCst);
                        let target = mapping.load(Ordering::SeqCst);
                        let (held, closures) = (held.clone(), closures.clone());
                        tokio::spawn(async move {
                            let mut pending = Vec::new();
                            let mut buf = [0; 4096];
                            while held.load(Ordering::SeqCst) {
                                tokio::select! {
                                    read = client.read(&mut buf) => match read {
                                        Ok(0) | Err(_) => { closures.fetch_add(1, Ordering::SeqCst); return; },
                                        Ok(n) => pending.extend_from_slice(&buf[..n]),
                                    },
                                    _ = tokio::time::sleep(Duration::from_millis(10)) => {},
                                }
                            }
                            if let Ok(mut upstream) = tokio::net::TcpStream::connect(("127.0.0.1", target)).await {
                                if upstream.write_all(&pending).await.is_ok() { let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await; }
                            }
                            closures.fetch_add(1, Ordering::SeqCst);
                        });
                    }
                }}
            });
        });
        Self {
            port,
            target,
            hold,
            accepted,
            closed,
            stop: Some(stop),
            thread: Some(thread),
        }
    }
}
impl Drop for TcpMapping {
    fn drop(&mut self) {
        let _ = self.stop.take().unwrap().send(());
        let _ = self.thread.take().unwrap().join();
    }
}
