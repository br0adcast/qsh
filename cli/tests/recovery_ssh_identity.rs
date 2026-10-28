#[path = "support/recovery_ssh.rs"]
mod fake;
use qsh::{known_hosts::KnownHosts, prompt::Tty, ssh_step::SshStep};
use std::{
    path::Path,
    sync::{atomic::Ordering, Arc},
};
fn attempt(home: &Path, server: &fake::Server, grants: &[Vec<u8>]) {
    let identity = home.join("identity");
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    std::fs::write(
        &identity,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let known = KnownHosts::new(home.join("known_hosts"), None);
    let tty = Tty::at("/nonexistent/qsh-test-tty");
    let step = SshStep {
        login: "fixture",
        identity: Some(&identity),
        no_password: true,
        agent: None,
        ssh_dir: None,
        known_hosts: &known,
        tty: &tty,
        background: true,
        install_policy: bringup::InstallPolicy::RestartOnly,
        images: Arc::new(qsh::releases::GitHubImages::new(Some(home.join("cache")))),
    };
    let route = connect::SshRoute {
        port: server.port,
        knock: vec![],
    };
    let addr = connect::Address {
        host: "127.0.0.1".into(),
        qsh_port: 60022,
        ssh: Some(route.clone()),
    };
    let _ = step.run_bound(&addr, &route, [9; 32], grants, &knock::Cancel::new());
}
fn trust(home: &Path, server: &fake::Server) {
    KnownHosts::new(home.join("known_hosts"), None)
        .add("127.0.0.1", server.port, "ssh-ed25519", &server.wire())
        .unwrap();
}
#[test]
fn known_ssh_host_without_a_binding_cannot_authenticate() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    trust(home.path(), &server);
    attempt(home.path(), &server, &[]);
    server.untouched();
    assert_eq!(server.activity.connections.load(Ordering::SeqCst), 0);
}
#[test]
fn another_known_host_key_cannot_inherit_recovery_authorization() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    let old = fake::Server::start();
    trust(home.path(), &server);
    KnownHosts::new(home.path().join("known_hosts"), None)
        .add("127.0.0.1", server.port, "ssh-ed25519", &old.wire())
        .unwrap();
    attempt(home.path(), &server, &[old.wire()]);
    server.untouched();
    assert_eq!(server.activity.connections.load(Ordering::SeqCst), 1);
}
#[test]
fn revocation_wins_over_an_explicit_binding() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    trust(home.path(), &server);
    use std::io::Write;
    writeln!(
        std::fs::OpenOptions::new()
            .append(true)
            .open(home.path().join("known_hosts"))
            .unwrap(),
        "@revoked [127.0.0.1]:{} {}",
        server.port,
        server.key.to_openssh().unwrap()
    )
    .unwrap();
    attempt(home.path(), &server, &[server.wire()]);
    server.untouched();
    assert_eq!(server.activity.connections.load(Ordering::SeqCst), 0);
}
#[test]
fn removing_known_host_trust_blocks_binding_and_restoring_it_recovers() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    attempt(home.path(), &server, &[server.wire()]);
    server.untouched();
    trust(home.path(), &server);
    attempt(home.path(), &server, &[server.wire()]);
    assert!(server.activity.auth.load(Ordering::SeqCst) > 0);
    assert!(server.activity.sign.load(Ordering::SeqCst) > 0);
    assert!(server.activity.exec.load(Ordering::SeqCst) > 0);
    std::fs::remove_file(home.path().join("known_hosts")).unwrap();
    let before = server.activity.auth.load(Ordering::SeqCst);
    attempt(home.path(), &server, &[server.wire()]);
    assert_eq!(server.activity.auth.load(Ordering::SeqCst), before);
}

#[test]
fn a_new_endpoint_cannot_reuse_old_network_bindings() {
    use connect::{
        recovery_gate::RecoveryEpoch,
        server_identity::{ServerIdentity, SshBinding, SshEndpoint},
    };
    use qsh::ssh_bindings::{SshBindings, TrustWritePermit};
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    trust(home.path(), &server);
    let store = SshBindings::open(home.path().join("ssh_bindings.json"));
    let identity = ServerIdentity {
        qsh_key: [11; 32],
        username: "fixture".into(),
    };
    let previous = SshEndpoint {
        host: "old-network.invalid".into(),
        port: server.port,
    };
    store
        .grant(
            &SshBinding {
                server: identity.clone(),
                endpoint: previous.clone(),
                host_key: server.wire(),
            },
            &TrustWritePermit::new(RecoveryEpoch {
                connection: 1,
                network: 1,
            }),
        )
        .unwrap();
    let current = SshEndpoint {
        host: "127.0.0.1".into(),
        port: server.port,
    };
    let keys = store.allowed(&identity, &current).unwrap();
    attempt(home.path(), &server, &keys);
    server.untouched();
    assert_eq!(server.activity.connections.load(Ordering::SeqCst), 0);
    // Returning to the exact authorized tuple still yields the original key;
    // a failed attempt has not permanently disabled that grant.
    assert_eq!(
        store.allowed(&identity, &previous).unwrap(),
        vec![server.wire()]
    );
}
