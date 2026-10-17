mod support;

use std::sync::Arc;
use support::*;

fn go(params: ssh::SshParams, auth: ssh::SshAuthPlan) -> Result<(), ssh::SshError> {
    ssh::connect(
        params,
        auth,
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(c, _)| c.close())
}

#[test]
fn an_unknown_host_key_stops_with_its_fingerprint() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let expected = ssh::host_key_info(&wire_of(&sshd.host_public_key_line())).unwrap();
    match go(
        params(&sshd, vec![]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
    ) {
        Err(ssh::SshError::UnknownHostKey(info)) => {
            assert_eq!(info.fingerprint, expected.fingerprint);
            assert_eq!(info.key_type, "ssh-ed25519");
            assert!(info.fingerprint.starts_with("SHA256:") && !info.fingerprint.ends_with('='));
        }
        other => panic!("expected UnknownHostKey, got {other:?}"),
    }
}

/// The fingerprint matches what ssh-keygen prints for the same key.
#[test]
fn the_fingerprint_matches_ssh_keygen() {
    let Some(()) = sshd_or_skip() else { return };
    let sshd = TestSshd::start(&[]);
    let out = std::process::Command::new("ssh-keygen")
        .arg("-lf")
        .arg(sshd.dir.path().join("host_ed25519.pub"))
        .output()
        .unwrap();
    let line = String::from_utf8(out.stdout).unwrap();
    let theirs = line.split_whitespace().nth(1).unwrap().to_string();
    let ours = ssh::host_key_info(&wire_of(&sshd.host_public_key_line()))
        .unwrap()
        .fingerprint;
    assert_eq!(ours, theirs);
}

#[test]
fn a_known_host_key_and_an_external_signer_log_in() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let known = wire_of(&sshd.host_public_key_line());
    go(
        params(&sshd, vec![known]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
    )
    .expect("login");
}

#[test]
fn a_pem_key_logs_in_ed25519_and_ecdsa() {
    let Some(()) = sshd_or_skip() else { return };
    let keys = tempfile::tempdir().unwrap();
    let (ed_pem, ed_pub) = keygen("ed25519", keys.path());
    let (ec_pem, ec_pub) = keygen("ecdsa", keys.path());
    let sshd = TestSshd::start(&[ed_pub, ec_pub]);
    let known = wire_of(&sshd.host_public_key_line());
    go(
        params(&sshd, vec![known.clone()]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::PrivateKeyPem(ssh::Zeroizing::new(ed_pem))),
    )
    .expect("ed25519");
    go(
        params(&sshd, vec![known]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::PrivateKeyPem(ssh::Zeroizing::new(ec_pem))),
    )
    .expect("ecdsa");
}

#[test]
fn a_key_not_in_authorized_keys_is_refused() {
    let Some(()) = sshd_or_skip() else { return };
    let sshd = TestSshd::start(&[SoftSigner::random().authorized_line()]);
    let known = wire_of(&sshd.host_public_key_line());
    match go(
        params(&sshd, vec![known]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(SoftSigner::random()))),
    ) {
        Err(ssh::SshError::AuthFailed(_)) => {}
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

/// Same address, different key -- even a different key TYPE is "changed",
/// never "unknown": the address has a remembered key and this is not it.
#[test]
fn a_different_key_is_changed_not_unknown() {
    let Some(()) = sshd_or_skip() else { return };
    let sshd = TestSshd::start(&[]);
    let other = SoftSigner::random().public_wire(); // an ecdsa key, not the host's ed25519
    match go(
        params(&sshd, vec![other]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Password(ssh::Zeroizing::new("x".into()))),
    ) {
        Err(ssh::SshError::HostKeyChanged(info)) => assert_eq!(info.key_type, "ssh-ed25519"),
        other => panic!("expected HostKeyChanged, got {other:?}"),
    }
}

/// A peer that accepts TCP and then says nothing must not hang the setup:
/// the greeting with key exchange is bounded by `connect_timeout`, as is
/// each network wait of the login, separately (time spent asking a person
/// is not counted).
#[test]
fn a_silent_peer_times_out_the_handshake() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    // Keeps the accepted socket open (and silent) until the test ends.
    let accepted = std::thread::spawn(move || listener.accept().map(|(s, _)| s));
    let params = ssh::SshParams {
        host: "127.0.0.1".into(),
        port,
        username: "nobody".into(),
        known_host_keys: Vec::new(),
        connect_timeout: std::time::Duration::from_secs(1),
        keepalive_interval: std::time::Duration::from_secs(15),
        compression: true,
        tcp_nodelay: true,
        knock: Vec::new(),
    };
    let (tx, rx) = std::sync::mpsc::channel();
    let started = std::time::Instant::now();
    std::thread::spawn(move || {
        let _ = tx.send(go(
            params,
            ssh::SshAuthPlan::single(ssh::AuthMethod::Password(ssh::Zeroizing::new("x".into()))),
        ));
    });
    let result = rx
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("the setup did not give up on a silent peer");
    let elapsed = started.elapsed();
    match result {
        Err(ssh::SshError::Connect(_)) => {}
        other => panic!("expected Connect, got {other:?}"),
    }
    assert!(
        elapsed < std::time::Duration::from_secs(3),
        "took {elapsed:?}"
    );
    let _socket = accepted.join().unwrap().unwrap();
}

#[test]
fn cancel_during_success_does_not_leak_a_connection() {
    struct CancelOnSign {
        signer: SoftSigner,
        cancel: knock::Cancel,
    }
    impl ssh::ExternalSigner for CancelOnSign {
        fn public_key(&self) -> Result<Vec<u8>, String> {
            self.signer.public_key()
        }
        fn sign_ssh(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            let signature = self.signer.sign_ssh(data)?;
            self.cancel.cancel();
            Ok(signature)
        }
    }

    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let cancel = knock::Cancel::new();
    let events = Arc::new(NullEvents);
    let lifetime = Arc::downgrade(&events);
    let result = ssh::connect(
        params(&sshd, vec![wire_of(&sshd.host_public_key_line())]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(CancelOnSign {
            signer,
            cancel: cancel.clone(),
        }))),
        Arc::new(knock::NoBind),
        events,
        &cancel,
    );
    assert!(
        matches!(result, Err(ssh::SshError::Cancelled)),
        "{:?}",
        result.err()
    );
    let stopped = std::time::Instant::now();
    while lifetime.upgrade().is_some() && stopped.elapsed() < std::time::Duration::from_secs(2) {
        std::thread::yield_now();
    }
    assert!(
        lifetime.upgrade().is_none(),
        "the connection thread kept its events alive"
    );
}

#[test]
fn setup_reports_knocking_before_connecting() {
    struct Stages(std::sync::Mutex<Vec<ssh::SshConnectStage>>);
    impl ssh::SshEvents for Stages {
        fn on_connect_stage(&self, stage: ssh::SshConnectStage) {
            self.0.lock().unwrap().push(stage);
        }
        fn on_channel(&self, _: client::channel::SubstrateEvent) {}
        fn on_closed(&self, _: String) {}
    }
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let mut p = params(&sshd, vec![wire_of(&sshd.host_public_key_line())]);
    p.knock = vec![knock::KnockStep {
        protocol: knock::KnockProtocol::Udp,
        port: 9,
        payload: vec![],
        delay_after_ms: 0,
    }];
    let events = Arc::new(Stages(std::sync::Mutex::new(Vec::new())));
    let (connection, _) = ssh::connect(
        p,
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
        Arc::new(knock::NoBind),
        events.clone(),
        &knock::Cancel::new(),
    )
    .unwrap();
    connection.close();
    assert_eq!(
        *events.0.lock().unwrap(),
        vec![
            ssh::SshConnectStage::Knocking,
            ssh::SshConnectStage::Connecting
        ]
    );
}
