//! Owned loopback KEX proves memory keys restrict the real login before credentials.
use super::*;
use crate::climb::authorization_server as fake;
use std::sync::atomic::{AtomicUsize, Ordering};

fn attempt(
    home: &Path,
    server: &fake::Server,
    key: &[u8],
    cancel: &knock::Cancel,
    started: &AtomicUsize,
) {
    let identity = home.join("identity");
    let private = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    std::fs::write(
        &identity,
        private
            .to_openssh(ssh_key::LineEnding::LF)
            .unwrap()
            .as_bytes(),
    )
    .unwrap();
    let known = KnownHosts::new(home.join("known_hosts"), None);
    let tty = Tty::at(home.join("no-tty"));
    let step = SshStep {
        login: "fixture",
        identity: Some(&identity),
        no_password: true,
        agent: None,
        ssh_dir: None,
        known_hosts: &known,
        tty: &tty,
        background: true,
        images: Arc::new(crate::releases::GitHubImages::new(home.join("cache"))),
    };
    let route = ::connect::SshRoute {
        port: server.port,
        knock: vec![],
    };
    let address = ::connect::Address {
        host: "127.0.0.1".into(),
        qsh_port: 60022,
        ssh: Some(route.clone()),
    };
    let origin = ::connect::server_identity::SshEndpoint {
        host: "origin.example.test".into(),
        port: 2222,
    };
    let _ = step.run_bootstrap_observed(&address, &route, [9; 32], &origin, key, cancel, || {
        started.fetch_add(1, Ordering::SeqCst);
    });
}

#[test]
fn ssh_first_attested_unknown_alias_reaches_real_auth_without_store_or_prompt() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    let started = AtomicUsize::new(0);
    attempt(
        home.path(),
        &server,
        &server.wire(),
        &knock::Cancel::new(),
        &started,
    );
    assert_eq!(started.load(Ordering::SeqCst), 1);
    assert!(server.activity.auth.load(Ordering::SeqCst) > 0);
    assert!(server.activity.sign.load(Ordering::SeqCst) > 0);
    assert!(server.activity.exec.load(Ordering::SeqCst) > 0);
    assert!(!home.path().join("known_hosts").exists());
    assert!(!home.path().join("ssh_bindings.json").exists());
}

#[test]
fn ssh_first_foreign_key_never_reaches_auth_and_same_key_retry_still_works() {
    let home = tempfile::tempdir().unwrap();
    let trusted = fake::Server::start();
    let foreign = fake::Server::start();
    let started = AtomicUsize::new(0);
    let attested = trusted.wire();
    attempt(
        home.path(),
        &trusted,
        &attested,
        &knock::Cancel::new(),
        &started,
    );
    let signed = trusted.activity.sign.load(Ordering::SeqCst);
    assert!(signed > 0);
    attempt(
        home.path(),
        &foreign,
        &attested,
        &knock::Cancel::new(),
        &started,
    );
    assert_eq!(foreign.activity.connections.load(Ordering::SeqCst), 1);
    foreign.untouched();
    attempt(
        home.path(),
        &trusted,
        &attested,
        &knock::Cancel::new(),
        &started,
    );
    assert!(trusted.activity.sign.load(Ordering::SeqCst) > signed);
}

#[test]
fn ssh_first_origin_target_conflict_revocation_and_unreadable_fail_before_connect() {
    use std::io::Write;
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    let foreign = fake::Server::start();
    for origin in [true, false] {
        for revoked in [true, false] {
            let path = home.path().join("known_hosts");
            let mut f = std::fs::File::create(&path).unwrap();
            let endpoint = if origin {
                "[origin.example.test]:2222".to_string()
            } else {
                format!("[127.0.0.1]:{}", server.port)
            };
            writeln!(
                f,
                "{}{} {}",
                if revoked { "@revoked " } else { "" },
                endpoint,
                if revoked {
                    server.key.to_openssh().unwrap()
                } else {
                    foreign.key.to_openssh().unwrap()
                }
            )
            .unwrap();
            drop(f);
            let started = AtomicUsize::new(0);
            attempt(
                home.path(),
                &server,
                &server.wire(),
                &knock::Cancel::new(),
                &started,
            );
            assert_eq!(started.load(Ordering::SeqCst), 0);
            assert_eq!(server.activity.connections.load(Ordering::SeqCst), 0);
            std::fs::remove_file(path).unwrap();
        }
    }
    std::fs::create_dir(home.path().join("known_hosts")).unwrap();
    attempt(
        home.path(),
        &server,
        &server.wire(),
        &knock::Cancel::new(),
        &AtomicUsize::new(0),
    );
    assert_eq!(server.activity.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn ssh_first_cancelled_attempt_does_not_start() {
    let home = tempfile::tempdir().unwrap();
    let server = fake::Server::start();
    let cancel = knock::Cancel::new();
    cancel.cancel();
    let started = AtomicUsize::new(0);
    attempt(home.path(), &server, &server.wire(), &cancel, &started);
    assert_eq!(started.load(Ordering::SeqCst), 0);
    assert_eq!(server.activity.connections.load(Ordering::SeqCst), 0);
}

#[test]
fn ssh_first_unrelated_known_key_cannot_widen_the_attested_singleton() {
    let home = tempfile::tempdir().unwrap();
    let trusted = fake::Server::start();
    let foreign = fake::Server::start();
    let known = KnownHosts::new(home.path().join("known_hosts"), None);
    for key in [trusted.wire(), foreign.wire()] {
        known
            .add("127.0.0.1", foreign.port, "ssh-ed25519", &key)
            .unwrap();
    }
    let before = std::fs::read(home.path().join("known_hosts")).unwrap();
    attempt(
        home.path(),
        &foreign,
        &trusted.wire(),
        &knock::Cancel::new(),
        &AtomicUsize::new(0),
    );
    assert_eq!(foreign.activity.connections.load(Ordering::SeqCst), 1);
    foreign.untouched();
    assert_eq!(
        std::fs::read(home.path().join("known_hosts")).unwrap(),
        before
    );
}
