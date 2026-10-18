//! The daemon key returned by the verified SSH login constrains QSH discovery.
#[path = "../../crates/ssh/tests/support/fake_server.rs"]
#[allow(dead_code)]
mod fake;

use qsh::{
    climb::{Climb, Climbed, Mode, Setup},
    known_hosts::KnownHosts,
    prompt::Tty,
    trust::Discover,
};
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

struct DiscoveryAfterSsh(AtomicUsize);
impl Discover for DiscoveryAfterSsh {
    fn key(&self, addr: SocketAddr) -> Result<[u8; 32], sshauth::discover::DiscoveryError> {
        if self.0.fetch_add(1, Ordering::SeqCst) == 0 {
            Err(sshauth::discover::DiscoveryError::Silent {
                addr,
                waited: Duration::ZERO,
            })
        } else {
            Ok([9; 32])
        }
    }
}

#[test]
fn verified_ssh_ready_refuses_a_different_discovery_key_without_prompting() {
    let home = tempfile::tempdir().unwrap();
    let ssh = fake::FakeServer::start(fake::FakeAuth {
        accept_any_key: true,
        exec_outputs: vec![
            b"os Linux\narch x86_64\nhome /test\npath /test/qshd\n".to_vec(),
            b"server-pubkey: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nTRANSPORT-READY {\"version\":\"0.5.0\",\"ports\":[60022]}\n".to_vec(),
        ],
        ..Default::default()
    });
    let identity = home.path().join("identity");
    let key =
        ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    std::fs::write(
        &identity,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let ssh_hosts = KnownHosts::new(home.path().join("ssh_known_hosts"), None);
    ssh_hosts
        .add(
            "127.0.0.1",
            ssh.port,
            "ssh-ed25519",
            &ssh.host_public_key_wire(),
        )
        .unwrap();
    let args = qsh::args::parse_args(&[
        "--no-password".into(),
        "-i".into(),
        identity.to_str().unwrap().into(),
        format!("fixture@127.0.0.1:60022,ssh={}", ssh.port),
    ])
    .unwrap();
    let pins = home.path().join("known_hosts");
    let setup = Setup::new(
        args,
        transport::generate_keypair(),
        sshauth::known_hosts::KnownHosts::open(pins.clone()),
        Box::new(DiscoveryAfterSsh(AtomicUsize::new(0))),
        Tty::at(home.path().join("no-tty")),
        ssh_hosts,
        None,
        None,
        [1; 16],
    );
    let (tx, rx) = std::sync::mpsc::channel();
    let result = Climb::new(
        &setup,
        setup.args().addresses.clone(),
        0,
        Mode::Login,
        80,
        24,
        tx,
        &rx,
    )
    .run();
    assert!(
        matches!(result, Climbed::Exit(11)),
        "a discovery/SSH key mismatch must be a key refusal"
    );
    assert!(
        !pins.exists(),
        "a mismatching discovery key cannot establish trust"
    );
}
