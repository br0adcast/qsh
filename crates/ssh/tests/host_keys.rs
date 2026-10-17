mod support;

use std::sync::Arc;
use support::*;

fn login(params: ssh::SshParams, signer: SoftSigner) -> Result<(), ssh::SshError> {
    ssh::connect(
        params,
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(signer))),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .map(|(c, _)| c.close())
}

/// The server has ed25519 and ecdsa host keys and would pick ed25519 by
/// default. Only the ecdsa one is known: offering its type first makes the
/// server show the key we know, instead of a "changed" key that is not.
#[test]
fn a_known_key_of_a_second_type_is_trusted() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![signer.authorized_line()],
        host_key_types: vec!["ed25519", "ecdsa"],
        ..SshdOptions::default()
    });
    let ecdsa = wire_of(&sshd.host_public_key_line_of("ecdsa"));
    login(params(&sshd, vec![ecdsa]), signer).expect("the known ecdsa key is trusted");
}

/// Two known keys for one host: either one matches.
#[test]
fn any_of_several_known_keys_is_trusted() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start(&[signer.authorized_line()]);
    let host = wire_of(&sshd.host_public_key_line());
    let stranger = SoftSigner::random().public_wire();
    login(params(&sshd, vec![stranger, host]), signer).expect("login");
}

/// An RSA host key is known: it is asked for with SHA-2, and trusted.
#[test]
fn a_known_rsa_host_key_is_trusted() {
    let Some(()) = sshd_or_skip() else { return };
    let signer = SoftSigner::random();
    let sshd = TestSshd::start_with(SshdOptions {
        authorized_keys: vec![signer.authorized_line()],
        host_key_types: vec!["ed25519", "rsa"],
        ..SshdOptions::default()
    });
    let rsa = wire_of(&sshd.host_public_key_line_of("rsa"));
    login(params(&sshd, vec![rsa]), signer).expect("the known rsa key is trusted");
}

/// No known key: unknown, never changed.
#[test]
fn no_known_key_is_unknown() {
    let Some(()) = sshd_or_skip() else { return };
    let sshd = TestSshd::start(&[]);
    match login(params(&sshd, vec![]), SoftSigner::random()) {
        Err(ssh::SshError::UnknownHostKey(_)) => {}
        other => panic!("expected UnknownHostKey, got {other:?}"),
    }
}

fn fake_params(server: &fake_server::FakeServer, known: Vec<Vec<u8>>) -> ssh::SshParams {
    ssh::SshParams {
        host: "127.0.0.1".into(),
        port: server.port,
        username: "test-user".into(),
        known_host_keys: known,
        connect_timeout: std::time::Duration::from_secs(2),
        keepalive_interval: std::time::Duration::ZERO,
        compression: false,
        tcp_nodelay: true,
        knock: vec![],
    }
}

struct CountingSigner {
    key: SoftSigner,
    signs: std::sync::atomic::AtomicUsize,
}

impl ssh::ExternalSigner for CountingSigner {
    fn public_key(&self) -> Result<Vec<u8>, String> {
        Ok(self.key.public_wire())
    }
    fn sign_ssh(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        self.signs.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        ssh::ExternalSigner::sign_ssh(&self.key, data)
    }
}

#[test]
fn wrong_bound_host_key_never_reaches_userauth() {
    use std::sync::atomic::Ordering;
    let activity = Arc::new(fake_server::ServerActivity::default());
    let server = fake_server::FakeServer::start(fake_server::FakeAuth {
        accept_any_key: true,
        activity: activity.clone(),
        ..Default::default()
    });
    let signer = Arc::new(CountingSigner {
        key: SoftSigner::random(),
        signs: 0.into(),
    });
    let result = ssh::connect(
        fake_params(&server, vec![SoftSigner::random().public_wire()]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(signer.clone())),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    );
    assert!(matches!(result, Err(ssh::SshError::HostKeyChanged(_))));
    assert_eq!(activity.connections.load(Ordering::SeqCst), 1);
    assert_eq!(activity.userauth.load(Ordering::SeqCst), 0);
    assert_eq!(activity.exec.load(Ordering::SeqCst), 0);
    assert_eq!(server.sftp_channels.opened.load(Ordering::SeqCst), 0);
    assert_eq!(signer.signs.load(Ordering::SeqCst), 0);

    // Positive control: this same server accepts the key and requests a
    // signature when the host key is authorized, so the counters are live.
    let (connection, _) = ssh::connect(
        fake_params(&server, vec![server.host_public_key_wire()]),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(signer.clone())),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .expect("the server accepts any user public key");
    assert!(activity.userauth.load(Ordering::SeqCst) > 0);
    assert!(signer.signs.load(Ordering::SeqCst) > 0);
    connection.close();
}

#[test]
fn verify_host_has_no_userauth() {
    use std::sync::atomic::Ordering;
    let activity = Arc::new(fake_server::ServerActivity::default());
    let server = fake_server::FakeServer::start(fake_server::FakeAuth {
        accept_any_key: true,
        activity: activity.clone(),
        ..Default::default()
    });
    let wire = server.host_public_key_wire();
    let verified = ssh::verify_host(
        fake_params(&server, vec![wire.clone()]),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    )
    .expect("verified KEX");
    assert_eq!(verified.key, wire);
    assert_eq!(verified.key_type, "ssh-ed25519");
    assert_eq!(activity.connections.load(Ordering::SeqCst), 1);
    assert_eq!(activity.userauth.load(Ordering::SeqCst), 0);
    assert_eq!(activity.exec.load(Ordering::SeqCst), 0);
    assert_eq!(server.sftp_channels.opened.load(Ordering::SeqCst), 0);
}

#[test]
fn connection_reports_the_host_key_from_its_login() {
    let server = fake_server::FakeServer::start(fake_server::FakeAuth {
        accept_any_key: true,
        ..Default::default()
    });
    let wire = server.host_public_key_wire();
    let (connection, _) = ssh::connect(
        fake_params(
            &server,
            vec![SoftSigner::random().public_wire(), wire.clone()],
        ),
        ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(SoftSigner::random()))),
        Arc::new(knock::NoBind),
        Arc::new(NullEvents),
        &knock::Cancel::new(),
    )
    .expect("login");
    assert_eq!(connection.server_host_key().key, wire);
    connection.close();
}

#[test]
fn verify_host_refuses_unknown_and_changed_keys_without_userauth() {
    use std::sync::atomic::Ordering;
    let activity = Arc::new(fake_server::ServerActivity::default());
    let server = fake_server::FakeServer::start(fake_server::FakeAuth {
        accept_any_key: true,
        activity: activity.clone(),
        ..Default::default()
    });
    let wire = server.host_public_key_wire();
    let unknown = ssh::verify_host(
        fake_params(&server, vec![]),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    );
    assert!(matches!(unknown, Err(ssh::SshError::UnknownHostKey(info)) if info.key == wire));
    let changed = ssh::verify_host(
        fake_params(&server, vec![SoftSigner::random().public_wire()]),
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    );
    assert!(matches!(changed, Err(ssh::SshError::HostKeyChanged(info)) if info.key == wire));
    assert_eq!(activity.userauth.load(Ordering::SeqCst), 0);
    assert_eq!(activity.exec.load(Ordering::SeqCst), 0);
}
