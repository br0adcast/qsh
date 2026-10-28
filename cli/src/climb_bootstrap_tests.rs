//! Synthetic keys and loopback-only SSH responses exercise the real trust boundary.
use super::*;
// Reuse the Linux sandbox's instance instead of loading the module twice.
#[cfg(target_os = "linux")]
use crate::ssh_step::test_support::ssh_support::fake_server as fake;
// Other platforms need neither the real-daemon sandbox nor Linux pidfds.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
#[path = "../../crates/ssh/tests/support/fake_server.rs"]
mod fake;

fn fixture(keys: &[[u8; 32]]) -> (tempfile::TempDir, fake::FakeServer, Setup) {
    use base64::Engine as _;
    let home = tempfile::tempdir().unwrap();
    let outputs = keys.iter().flat_map(|key| [
        b"os Linux\narch x86_64\nhome /test\npath /test/qshd\n".to_vec(),
        format!("server-pubkey: {}\nTRANSPORT-READY {{\"version\":\"0.5.0\",\"ports\":[60023]}}\n", base64::engine::general_purpose::STANDARD.encode(key)).into_bytes(),
    ]).collect();
    let ssh = fake::FakeServer::start(fake::FakeAuth {
        accept_any_key: true,
        exec_outputs: outputs,
        ..Default::default()
    });
    let identity = home.path().join("identity");
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
    let hosts = KnownHosts::new(home.path().join("ssh_known_hosts"), None);
    hosts
        .add(
            "127.0.0.1",
            ssh.port,
            "ssh-ed25519",
            &ssh.host_public_key_wire(),
        )
        .unwrap();
    let args = crate::args::parse_args(&[
        "--no-password".into(),
        "-i".into(),
        identity.to_str().unwrap().into(),
        format!("fixture@127.0.0.1:60022,ssh={}", ssh.port),
    ])
    .unwrap();
    let setup = Setup::new(
        args,
        transport::generate_keypair(),
        sshauth::known_hosts::KnownHosts::open(home.path().join("known_hosts")),
        Box::new(trust::UdpDiscovery),
        Tty::at(home.path().join("no-tty")),
        hosts,
        None,
        None,
        [1; 16],
    );
    *setup.session_key.lock().unwrap() = Some([7; 32]);
    (home, ssh, setup)
}

#[test]
fn background_ssh_rejects_a_foreign_ready_key_and_retries_the_same_route() {
    let (_home, _ssh, setup) = fixture(&[[9; 32], [7; 32]]);
    let address = &setup.args.addresses[0];
    assert!(
        setup.bring_up(address, &knock::Cancel::new()).is_err(),
        "a foreign daemon cannot publish a recovery port"
    );
    assert!(
        !setup.pins.path().exists(),
        "background SSH cannot create pins"
    );
    let ready = setup
        .bring_up(address, &knock::Cancel::new())
        .expect("a later matching result remains retryable");
    assert_eq!(ready.server_pubkey, [7; 32]);
    assert_eq!(ready.port_for(address.qsh_port), 60023);
    assert!(
        !setup.pins.path().exists(),
        "matching background readiness also cannot pin"
    );
}

#[test]
fn background_ssh_rejects_a_conflicting_pin_on_the_returned_port() {
    let (_home, _ssh, setup) = fixture(&[[7; 32], [7; 32]]);
    setup.pins.pin("127.0.0.1", 60023, &[9; 32]).unwrap();
    let original = std::fs::read(setup.pins.path()).unwrap();
    assert!(setup
        .bring_up(&setup.args.addresses[0], &knock::Cancel::new())
        .is_err());
    assert_eq!(std::fs::read(setup.pins.path()).unwrap(), original);
    setup.pins.pin("127.0.0.1", 60023, &[7; 32]).unwrap();
    assert!(setup
        .bring_up(&setup.args.addresses[0], &knock::Cancel::new())
        .is_ok());
}

#[test]
fn background_ssh_cannot_publish_from_an_unreadable_endpoint_pin_store() {
    let (_home, _ssh, setup) = fixture(&[[7; 32], [7; 32]]);
    std::fs::create_dir(setup.pins.path()).unwrap();
    assert!(setup
        .bring_up(&setup.args.addresses[0], &knock::Cancel::new())
        .is_err());
    std::fs::remove_dir(setup.pins.path()).unwrap();
    assert!(setup
        .bring_up(&setup.args.addresses[0], &knock::Cancel::new())
        .is_ok());
    assert!(!setup.pins.path().exists());
}

struct FixedDiscovery([u8; 32]);
impl trust::Discover for FixedDiscovery {
    fn key(&self, _: SocketAddr) -> Result<[u8; 32], sshauth::discover::DiscoveryError> {
        Ok(self.0)
    }
}

#[test]
fn an_ssh_bootstrap_grant_is_bound_to_the_exact_route_port_and_stage() {
    let (_home, _ssh, mut setup) = fixture(&[[7; 32]]);
    let address = setup.args.addresses[0].clone();
    let identified = setup
        .ssh_step(false, setup.install_policy(false, false))
        .run_identified(
            &address,
            address.ssh.as_ref().unwrap(),
            setup.keypair.public,
            &knock::Cancel::new(),
        )
        .unwrap();
    *setup.session_key.lock().unwrap() = None;
    setup.discovery = Arc::new(FixedDiscovery([9; 32]));
    setup.args.addresses.push(address.clone());
    let mut foreign = address;
    foreign.host = "127.0.0.2".into();
    setup.args.addresses.push(foreign);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut climb = Climb::new(
        &setup,
        setup.args.addresses.clone(),
        0,
        Mode::Login,
        80,
        24,
        tx,
        &rx,
    );
    climb.bootstrap = Some(SshBootstrap {
        addr: 0,
        port: 60023,
        key: identified.ready.server_pubkey,
        ssh_host_key: identified.ssh_host_key,
    });
    for (index, port, stage, expected) in [
        (0, 60023, Stage::AfterSsh, DirectOutcome::KeyChanged),
        (0, 60022, Stage::AfterSsh, DirectOutcome::Declined),
        (1, 60023, Stage::AfterSsh, DirectOutcome::Declined),
        (2, 60023, Stage::AfterSsh, DirectOutcome::Declined),
        (0, 60023, Stage::First, DirectOutcome::Declined),
    ] {
        let (outcome, _) = climb
            .direct(index, port, stage, &knock::Cancel::new())
            .unwrap();
        assert_eq!(outcome, expected, "route {index}, port {port}, {stage:?}");
        assert!(
            !setup.pins.path().exists(),
            "neither a mismatch nor an unrelated route can establish trust"
        );
    }
}

#[test]
fn foreground_replacement_cannot_adopt_another_ssh_returned_daemon_key() {
    let (_home, _ssh, mut setup) = fixture(&[[9; 32]]);
    let address = &setup.args.addresses[0];
    let identified = setup
        .ssh_step(false, setup.install_policy(false, false))
        .run_identified(
            address,
            address.ssh.as_ref().unwrap(),
            setup.keypair.public,
            &knock::Cancel::new(),
        )
        .unwrap();
    setup.discovery = Arc::new(FixedDiscovery([9; 32]));
    let replacement = setup.replacement([2; 16]);
    let (tx, rx) = std::sync::mpsc::channel();
    let mut climb = Climb::new(
        &replacement,
        replacement.args.addresses.clone(),
        0,
        Mode::Login,
        80,
        24,
        tx,
        &rx,
    );
    climb.bootstrap = Some(SshBootstrap {
        addr: 0,
        port: 60023,
        key: identified.ready.server_pubkey,
        ssh_host_key: identified.ssh_host_key,
    });
    let (outcome, _) = climb
        .direct(0, 60023, Stage::AfterSsh, &knock::Cancel::new())
        .unwrap();
    assert_eq!(outcome, DirectOutcome::KeyChanged);
    assert_eq!(replacement.server_identity(), setup.server_identity());
    assert!(!setup.pins.path().exists());
}

fn memory_bootstrap(key: [u8; 32], ssh_key: Vec<u8>) -> SshBootstrap {
    SshBootstrap {
        addr: 0,
        port: 60023,
        key,
        ssh_host_key: ssh::HostKeyInfo {
            key_type: "ssh-ed25519".into(),
            fingerprint: "synthetic".into(),
            key: ssh_key,
        },
    }
}

#[test]
fn ssh_first_selected_identity_publishes_without_store_and_replacement_retains_it() {
    let (home, ssh, setup) = fixture(&[]);
    let origin = ::connect::server_identity::SshEndpoint {
        host: "127.0.0.1".into(),
        port: ssh.port,
    };
    assert!(!setup.has_bootstrap_recovery_trust());
    assert!(setup.remember_bootstrap(
        memory_bootstrap([7; 32], ssh.host_public_key_wire()),
        0,
        60023,
        origin,
        &knock::Cancel::new()
    ));
    assert!(setup.has_bootstrap_recovery_trust());
    assert!(!home.path().join("ssh_bindings.json").exists());
    let replacement = setup.replacement([8; 16]);
    assert!(
        replacement.has_bootstrap_recovery_trust(),
        "same-client replacement retains evidence"
    );
    assert_ne!(replacement.token, setup.token);
}

#[test]
fn ssh_first_mismatched_or_cancelled_bootstrap_never_publishes() {
    let (_home, ssh, setup) = fixture(&[]);
    let origin = ::connect::server_identity::SshEndpoint {
        host: "127.0.0.1".into(),
        port: ssh.port,
    };
    for (addr, port, key) in [
        (1, 60023, [7; 32]),
        (0, 60022, [7; 32]),
        (0, 60023, [9; 32]),
    ] {
        assert!(!setup.remember_bootstrap(
            memory_bootstrap(key, ssh.host_public_key_wire()),
            addr,
            port,
            origin.clone(),
            &knock::Cancel::new()
        ));
        assert!(!setup.has_bootstrap_recovery_trust());
    }
    let cancel = knock::Cancel::new();
    cancel.cancel();
    assert!(!setup.remember_bootstrap(
        memory_bootstrap([7; 32], ssh.host_public_key_wire()),
        0,
        60023,
        origin,
        &cancel
    ));
    assert!(!setup.has_bootstrap_recovery_trust());
}

#[test]
fn ssh_first_new_connection_is_empty_and_foreign_identity_cannot_inherit() {
    let (_home, ssh, setup) = fixture(&[]);
    let origin = ::connect::server_identity::SshEndpoint {
        host: "127.0.0.1".into(),
        port: ssh.port,
    };
    assert!(setup.remember_bootstrap(
        memory_bootstrap([7; 32], ssh.host_public_key_wire()),
        0,
        60023,
        origin,
        &knock::Cancel::new()
    ));
    *setup.session_key.lock().unwrap() = Some([9; 32]);
    assert!(!setup.has_bootstrap_recovery_trust());
    assert!(!setup.replacement([8; 16]).has_bootstrap_recovery_trust());
    let (_home2, _ssh2, fresh) = fixture(&[]);
    assert!(!fresh.has_bootstrap_recovery_trust());
}

#[test]
fn ssh_first_memory_recovery_ignores_corrupt_store_and_rechecks_qsh_identity() {
    let (home, ssh, setup) = fixture(&[[7; 32]]);
    let origin = ::connect::server_identity::SshEndpoint {
        host: "127.0.0.1".into(),
        port: ssh.port,
    };
    assert!(setup.remember_bootstrap(
        memory_bootstrap([7; 32], ssh.host_public_key_wire()),
        0,
        60023,
        origin,
        &knock::Cancel::new()
    ));
    let path = home.path().join("ssh_bindings.json");
    std::fs::write(&path, b"invalid-json").unwrap();
    let ready = setup
        .bring_up(&setup.args.addresses[0], &knock::Cancel::new())
        .expect("memory trust must not read the legacy store");
    assert_eq!(ready.server_pubkey, [7; 32]);
    assert_eq!(std::fs::read(&path).unwrap(), b"invalid-json");
}

#[test]
fn ssh_first_origin_uses_ssh_port_and_established_evidence_is_immutable() {
    let (_home, ssh, mut setup) = fixture(&[]);
    setup.args.addresses[0].ssh.as_mut().unwrap().port = 2222;
    let origin = ::connect::server_identity::SshEndpoint {
        host: "127.0.0.1".into(),
        port: 2222,
    };
    let mut bootstrap = memory_bootstrap([7; 32], ssh.host_public_key_wire());
    bootstrap.port = 60000;
    assert!(setup.remember_bootstrap(bootstrap, 0, 60000, origin.clone(), &knock::Cancel::new()));
    let replacement = setup.replacement([8; 16]);
    assert_eq!(
        replacement
            .bootstrap_recovery
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()
            .origin
            .port,
        2222
    );
    let mut other = memory_bootstrap([7; 32], vec![9]);
    other.port = 60000;
    assert!(!setup.remember_bootstrap(other, 0, 60000, origin, &knock::Cancel::new()));
    *setup.bootstrap_recovery.lock().unwrap() = None;
    assert!(
        replacement.has_bootstrap_recovery_trust(),
        "replacement owns a value snapshot"
    );
}

#[test]
fn ssh_first_wrong_origin_or_unauthenticated_peer_cannot_publish() {
    let (_home, ssh, setup) = fixture(&[]);
    let mut origin = ::connect::server_identity::SshEndpoint {
        host: "127.0.0.1".into(),
        port: 60023,
    };
    assert!(!setup.remember_bootstrap(
        memory_bootstrap([7; 32], ssh.host_public_key_wire()),
        0,
        60023,
        origin.clone(),
        &knock::Cancel::new()
    ));
    origin.port = ssh.port;
    *setup.session_key.lock().unwrap() = None;
    assert!(!setup.remember_bootstrap(
        memory_bootstrap([7; 32], ssh.host_public_key_wire()),
        0,
        60023,
        origin,
        &knock::Cancel::new()
    ));
}
