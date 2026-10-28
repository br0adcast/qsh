#[path = "support/recovery_ssh.rs"]
mod fake;
use qsh::{known_hosts::KnownHosts, prompt::Tty, ssh_step::SshStep};
use std::{
    path::Path,
    sync::{atomic::Ordering, Arc},
};
fn attempt(home: &Path, server: &fake::Server) {
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
    let _ = step.run_recovery(&addr, &route, [9; 32], &knock::Cancel::new());
}
fn trust(home: &Path, server: &fake::Server) {
    KnownHosts::new(home.join("known_hosts"), None)
        .add("127.0.0.1", server.port, "ssh-ed25519", &server.wire())
        .unwrap();
}
#[test]
fn approved_target_without_a_binding_authenticates() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    trust(home.path(), &server);
    attempt(home.path(), &server);
    assert!(server.activity.sign.load(Ordering::SeqCst) > 0);
}
#[test]
fn multiple_approved_target_keys_authenticate() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    let old = fake::Server::start();
    trust(home.path(), &server);
    KnownHosts::new(home.path().join("known_hosts"), None)
        .add("127.0.0.1", server.port, "ssh-ed25519", &old.wire())
        .unwrap();
    attempt(home.path(), &server);
    assert!(server.activity.sign.load(Ordering::SeqCst) > 0);
}
#[test]
fn revocation_wins_over_ordinary_approval() {
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
    attempt(home.path(), &server);
    server.untouched();
    assert_eq!(server.activity.connections.load(Ordering::SeqCst), 0);
}
#[test]
fn removing_known_host_trust_blocks_auth_and_restoring_it_recovers() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    attempt(home.path(), &server);
    server.untouched();
    trust(home.path(), &server);
    attempt(home.path(), &server);
    assert!(server.activity.auth.load(Ordering::SeqCst) > 0);
    assert!(server.activity.sign.load(Ordering::SeqCst) > 0);
    assert!(server.activity.exec.load(Ordering::SeqCst) > 0);
    std::fs::remove_file(home.path().join("known_hosts")).unwrap();
    let before = server.activity.auth.load(Ordering::SeqCst);
    attempt(home.path(), &server);
    assert_eq!(server.activity.auth.load(Ordering::SeqCst), before);
}

#[test]
fn legacy_binding_file_cannot_authorize_or_be_modified() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    let path = home.path().join("ssh_bindings.json");
    std::fs::write(&path, b"unreadable legacy syntax").unwrap();
    attempt(home.path(), &server);
    server.untouched();
    assert_eq!(server.activity.connections.load(Ordering::SeqCst), 0);
    assert_eq!(std::fs::read(path).unwrap(), b"unreadable legacy syntax");
}
