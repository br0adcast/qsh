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
    let outputs = keys.iter().flat_map(|key| [
        b"os Linux\narch x86_64\nhome /test\npath /test/qshd\n".to_vec(),
            b"QSH-TRUST /test/qshd\n".to_vec(),
        format!("server-pubkey: {}\nTRANSPORT-READY {{\"version\":\"0.5.0\",\"ports\":[60023]}}\n", base64::engine::general_purpose::STANDARD.encode(key)).into_bytes(),
    ]).collect();
    fixture_with_auth(fake::FakeAuth {
        accept_any_key: true,
        exec_outputs: outputs,
        ..Default::default()
    })
}

fn fixture_with_auth(auth: fake::FakeAuth) -> (tempfile::TempDir, fake::FakeServer, Setup) {
    let home = tempfile::tempdir().unwrap();
    let ssh = fake::FakeServer::start(auth);
    let identity = home.path().join("identity");
    let key = ssh_key::PrivateKey::random(
        &mut ssh_key::rand_core::UnwrapErr(ssh_key::getrandom::SysRng),
        ssh_key::Algorithm::Ed25519,
    )
    .unwrap();
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&identity)
        .unwrap()
        .write_all(key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes())
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
        serving_version: "0.5.0".into(),
        serving_profiles: None,
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
        serving_version: "0.5.0".into(),
        serving_profiles: None,
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
        serving_version: "0.5.0".into(),
        serving_profiles: None,
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

#[test]
fn ssh_selected_version_is_display_context_for_unknown_handshake_failure() {
    let mut bootstrap = memory_bootstrap([7; 32], vec![1]);
    bootstrap.serving_version = "0.5.0".into();
    bootstrap.serving_profiles = None;
    let line = bootstrap.failure_diagnostic("handshake timed out");
    assert!(line.starts_with("handshake timed out"));
    assert!(line.contains("selected running qshd 0.5.0"));
    assert!(line.contains("session profile unknown"));
    assert!(!line.contains("incompatible"));
    bootstrap.serving_profiles = Some(vec![[2, 1, 1]]);
    assert!(!bootstrap
        .failure_diagnostic("handshake timed out")
        .contains("unknown"));
}

#[test]
fn busy_user_decline_stops_all_routes_before_later_connection_activity() {
    use std::io::Write;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    struct NoAnswerDiscovery(Arc<Mutex<Vec<SocketAddr>>>);
    impl trust::Discover for NoAnswerDiscovery {
        fn key(&self, addr: SocketAddr) -> Result<[u8; 32], sshauth::discover::DiscoveryError> {
            self.0.lock().unwrap().push(addr);
            Err(sshauth::discover::DiscoveryError::Silent {
                addr,
                waited: Duration::ZERO,
            })
        }
    }
    struct ProbeEvents;
    impl transport::driver_std::ClientEvents for ProbeEvents {
        fn on_bytes(&self, _: u8, _: Vec<u8>) {}
        fn on_state(&self, _: transport::LinkState) {}
        fn on_stats(&self, _: transport::Stats) {}
        fn on_reset(&self, _: u8) {}
        fn on_input_failure(&self, failure: transport::driver_std::InputFailure) {
            panic!("unexpected probe input: {failure:?}");
        }
    }
    struct OwnedProbe(Arc<transport::driver_std::StdClient>);
    impl Drop for OwnedProbe {
        fn drop(&mut self) {
            self.0.detach();
        }
    }
    let _serial = crate::tty::SIGNAL_TESTS
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    for input in [
        &b"1\n"[..],
        &b"\n"[..],
        &b"\x04"[..],
        &b"3\n\n"[..],
        &b"3\n1\n"[..],
        &b"3\n\x04"[..],
    ] {
        let activity = Arc::new(fake::ServerActivity::default());
        let ensures = Arc::new(AtomicUsize::new(0));
        let registrations = Arc::new(AtomicUsize::new(0));
        let ensure_count = ensures.clone();
        let registration_count = registrations.clone();
        let auth = fake::FakeAuth {
            accept_any_key: true,
            activity: activity.clone(),
            exec_reply: Some(Arc::new(move |command| {
                let command = std::str::from_utf8(command).unwrap();
                let command = command
                    .strip_prefix("/bin/sh -c '")
                    .unwrap()
                    .strip_suffix('\'')
                    .unwrap()
                    .replace(r"'\''", "'");
                if command.contains(" transport-ensure ") {
                    if command.contains("--busy-decision") {
                        registration_count.fetch_add(1, Ordering::SeqCst);
                    }
                    if ensure_count.fetch_add(1, Ordering::SeqCst) > 0 {
                        return b"unexpected later ensure\n".to_vec();
                    }
                    let attempt = command
                        .split("--busy-attempt ")
                        .nth(1)
                        .unwrap()
                        .split_whitespace()
                        .next()
                        .unwrap()
                        .trim_matches('\'');
                    return format!("TRANSPORT-BUSY {}\n",serde_json::json!({"schema":1,"attempt":attempt,"identity":{"version":"0.5.9","build":1,"checksum":"ab".repeat(32),"pid":42},"active_connections":2,"serving_profiles":null,"preservation":"unknown"})).into_bytes();
                }
                if command.ends_with(" bootstrap-capabilities") {
                    return b"{\"schema\":1,\"busy_decisions\":true}\n".to_vec();
                }
                if command.contains("QSH-TRUST") {
                    return b"QSH-TRUST /test/qshd\n".to_vec();
                }
                b"os Linux\narch x86_64\nhome /test\npath /test/qshd\n".to_vec()
            })),
            ..Default::default()
        };
        let (_home, _ssh, mut setup) = fixture_with_auth(auth);
        let pty = nix::pty::openpty(None, None).unwrap();
        setup.tty = Tty::at(nix::unistd::ttyname(&pty.slave).unwrap());
        let mut master = std::fs::File::from(pty.master);
        master.write_all(input).unwrap();
        setup.args.no_password = false;
        *setup.session_key.lock().unwrap() = None;
        let mut later = setup.args.addresses[0].clone();
        later.qsh_port += 1;
        setup.args.addresses.push(later);
        let discoveries = Arc::new(Mutex::new(Vec::new()));
        setup.discovery = Arc::new(NoAnswerDiscovery(discoveries.clone()));
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
        let probe_peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let peer = probe_peer.local_addr().unwrap();
        let probe = OwnedProbe(Arc::new(transport::driver_std::StdClient::connect(
            peer,
            transport::conn::ConnectionConfig {
                role: transport::conn::Role::Client,
                local_static_priv: transport::generate_keypair().private,
                remote_static_pub: Some([7; 32]),
                auth: transport::conn::AuthPolicy::Allowlist(Vec::new()),
                features: transport::Features::SUPPORTED,
                required_features: transport::Features::NONE,
            },
            [9; 16],
            transport::handshake_payload::StartKind::Cold,
            Arc::new(attempt::NoopBinder),
            Arc::new(ProbeEvents),
            None,
        )));
        assert!(!probe.0.is_gone());
        climb
            .retained_discovery
            .0
            .lock()
            .unwrap()
            .insert(peer, probe.0.clone());
        let cancel = knock::Cancel::new();
        let result = climb.run_cancellable(&cancel);
        assert_eq!(
            discoveries.lock().unwrap().len(),
            1,
            "busy cancellation cannot try a later direct route"
        );
        assert_eq!(
            activity.connections.load(Ordering::SeqCst),
            1,
            "no later SSH login"
        );
        assert_eq!(
            ensures.load(Ordering::SeqCst),
            1,
            "no later ensure/registration/handshake path"
        );
        assert_eq!(registrations.load(Ordering::SeqCst), 0);
        assert!(
            cancel.is_cancelled(),
            "explicit user decline cancels this attempt's parallel owners"
        );
        assert!(climb.retained_discovery.0.lock().unwrap().is_empty());
        assert!(
            probe.0.is_gone(),
            "retained parallel transport owner must be stopped and joined before returning"
        );
        assert!(matches!(result, Climbed::Exit(1)));
    }
}
