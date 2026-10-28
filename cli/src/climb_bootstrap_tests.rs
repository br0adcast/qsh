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
    let epoch = ::connect::recovery_gate::RecoveryEpoch {
        connection: 1,
        network: 1,
    };
    setup
        .ssh_bindings()
        .grant(
            &::connect::server_identity::SshBinding {
                server: setup.server_identity().unwrap(),
                endpoint: ::connect::server_identity::SshEndpoint {
                    host: "127.0.0.1".into(),
                    port: ssh.port,
                },
                host_key: ssh.host_public_key_wire(),
            },
            &crate::ssh_bindings::TrustWritePermit::new(epoch),
        )
        .unwrap();
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
