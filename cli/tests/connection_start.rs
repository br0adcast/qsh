//! Foreground fallback on a real PTY, without a platform-specific daemon fixture.
mod support;

use std::sync::{Arc, Mutex};
use support::{free_udp_port, serialised, spawn_qsh};

#[test]
fn a_closed_port_with_a_pinned_key_reaches_ssh_promptly() {
    let _serial = serialised();
    let home = tempfile::tempdir().unwrap();
    let identity =
        ssh_key::PrivateKey::random(&mut rand_core::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let key = home.path().join("identity");
    std::fs::write(
        &key,
        identity
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let port = free_udp_port();
    let pins = home.path().join("qsh/known_hosts");
    std::fs::create_dir_all(pins.parent().unwrap()).unwrap();
    sshauth::known_hosts::KnownHosts::open(pins)
        .pin("127.0.0.1", port, &[21; 32])
        .unwrap();
    let started = std::time::Instant::now();
    let address = format!("127.0.0.1:{port},ssh=1");
    let client = spawn_qsh(&["-i", key.to_str().unwrap(), &address], home.path());
    let output = Arc::new(Mutex::new(Vec::new()));
    support::drain_into(client.master.try_clone().unwrap(), output.clone());
    let screen = || String::from_utf8_lossy(&output.lock().unwrap()).into_owned();
    while started.elapsed() < std::time::Duration::from_secs(2)
        && !screen().contains("trying ssh:1")
    {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(screen().contains("trying ssh:1"), "{}", screen());
}
