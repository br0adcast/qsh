#[path = "../../ssh/tests/support/mod.rs"]
mod support;

use bringup::*;
use std::sync::{atomic::Ordering, Arc};
use std::time::Duration;
use support::fake_server::{FakeAuth, FakeServer, ServerActivity};

struct Silent;
impl InstallApproval for Silent {
    fn approve(&self, _: &InstallOffer, _: &knock::Cancel) -> Result<bool, BringUpError> {
        panic!("existing-only bringup must not request installation")
    }
}
impl BringUpObserver for Silent {
    fn on_progress(&self, _: BringUpProgress) {}
}

#[test]
fn identified_ready_names_the_same_connection_key() {
    let activity = Arc::new(ServerActivity::default());
    let server = FakeServer::start(FakeAuth {
        accept_any_key: true,
        activity: activity.clone(),
        exec_outputs: vec![
            b"os Linux\narch x86_64\nhome /test\npath /test/qshd\n".to_vec(),
            b"QSH-TRUST /test/qshd\n".to_vec(),
            b"server-pubkey: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nTRANSPORT-READY {\"version\":\"0.5.0\",\"ports\":[60022]}\n".to_vec(),
        ],
        ..Default::default()
    });
    let wire = server.host_public_key_wire();
    let result = bring_up_identified(
        BringUpRequest {
            report_busy: false,
            busy_decision: None,
            destructive_consent: None,
            name: "identity-test".into(),
            ssh: ssh::SshParams {
                host: "127.0.0.1".into(),
                port: server.port,
                username: "test-user".into(),
                known_host_keys: vec![support::SoftSigner::random().public_wire(), wire.clone()],
                connect_timeout: Duration::from_secs(2),
                keepalive_interval: Duration::ZERO,
                compression: false,
                tcp_nodelay: true,
                knock: vec![],
            },
            auth: ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(
                support::SoftSigner::random(),
            ))),
            qsh_port: 60022,
            client_pubkey: [9; 32],
        },
        InstallPolicy::ExistingOnly,
        BringUpHooks {
            source: None,
            approval: Arc::new(Silent),
            observer: Arc::new(Silent),
            timing: InstallTiming::default(),
        },
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    )
    .expect("identified bringup");
    assert_eq!(result.ssh_host_key.key, wire);
    assert_eq!(result.ssh_host_key.key_type, "ssh-ed25519");
    assert_eq!(result.ready.server_pubkey, [7; 32]);
    assert_eq!(result.ready.ports, [60022]);
    assert_eq!(
        activity.connections.load(Ordering::SeqCst),
        1,
        "verification and login share a connection"
    );
    assert!(activity.userauth.load(Ordering::SeqCst) > 0);
    assert_eq!(activity.exec.load(Ordering::SeqCst), 3);
}

#[test]
fn ready_records_without_exit_status_are_not_success() {
    let activity = Arc::new(ServerActivity::default());
    let server = FakeServer::start(FakeAuth {
        accept_any_key: true,
        activity: activity.clone(),
        exec_outputs: vec![
            b"os Linux\narch x86_64\nhome /test\npath /test/qshd\n".to_vec(),
            b"QSH-TRUST /test/qshd\n".to_vec(),
            b"server-pubkey: BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=\nTRANSPORT-READY {\"version\":\"0.5.0\",\"ports\":[60022]}\n".to_vec(),
        ],
        // Lookup and trust succeed; omit only the ensure exit status.
        exec_missing_status: Some(2),
        ..Default::default()
    });
    let error = bring_up_identified(
        BringUpRequest {
            report_busy: false,
            busy_decision: None,
            destructive_consent: None,
            name: "missing-status-test".into(),
            ssh: ssh::SshParams {
                host: "127.0.0.1".into(),
                port: server.port,
                username: "test-user".into(),
                known_host_keys: vec![server.host_public_key_wire()],
                connect_timeout: Duration::from_secs(2),
                keepalive_interval: Duration::ZERO,
                compression: false,
                tcp_nodelay: true,
                knock: vec![],
            },
            auth: ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(
                support::SoftSigner::random(),
            ))),
            qsh_port: 60022,
            client_pubkey: [9; 32],
        },
        InstallPolicy::ExistingOnly,
        BringUpHooks {
            source: None,
            approval: Arc::new(Silent),
            observer: Arc::new(Silent),
            timing: InstallTiming::default(),
        },
        Arc::new(knock::NoBind),
        &knock::Cancel::new(),
    )
    .unwrap_err();
    assert!(matches!(error, BringUpError::EnsureFailed(_)), "{error:?}");
    assert!(error.to_string().contains("exit -1"), "{error}");
    assert_eq!(activity.exec.load(Ordering::SeqCst), 3);
}

#[test]
fn busy_cancel_and_unqualified_force_have_no_ssh_or_daemon_effect() {
    let activity = Arc::new(ServerActivity::default());
    let server = FakeServer::start(FakeAuth {
        activity: activity.clone(),
        ..Default::default()
    });
    let info = BusyDaemonInfo {
        schema: 1,
        attempt: BusyAttemptId::from_bytes([1; 16]),
        identity: BusyDaemonIdentity {
            version: "0.5.9".into(),
            build: 1,
            checksum: "ab".repeat(32),
            pid: 42,
            generation: None,
        },
        candidate: bringup::CandidateImageIdentity {
            build: 2,
            checksum: "ef".repeat(32),
        },
        active_connections: 2,
        serving_profiles: None,
        preservation: PreservationCapability::Unknown,
    };
    for (choice, confirmed) in [
        (BusyChoice::Cancel, false),
        (BusyChoice::ForceUpdate, false),
        (BusyChoice::ForceUpdate, true),
    ] {
        let result = bring_up_identified(
            BringUpRequest {
                report_busy: true,
                busy_decision: Some(PendingBusy::new(info.clone()).unwrap().decide(choice)),
                destructive_consent: confirmed.then(|| info.confirm_destructive_restart()),
                name: "busy-test".into(),
                ssh: ssh::SshParams {
                    host: "127.0.0.1".into(),
                    port: server.port,
                    username: "test-user".into(),
                    known_host_keys: vec![server.host_public_key_wire()],
                    connect_timeout: Duration::from_secs(2),
                    keepalive_interval: Duration::ZERO,
                    compression: false,
                    tcp_nodelay: true,
                    knock: vec![],
                },
                auth: ssh::SshAuthPlan::single(ssh::AuthMethod::Signer(Arc::new(
                    support::SoftSigner::random(),
                ))),
                qsh_port: 60022,
                client_pubkey: [9; 32],
            },
            InstallPolicy::ExistingOnly,
            BringUpHooks {
                source: None,
                approval: Arc::new(Silent),
                observer: Arc::new(Silent),
                timing: InstallTiming::default(),
            },
            Arc::new(knock::NoBind),
            &knock::Cancel::new(),
        );
        if choice == BusyChoice::Cancel {
            assert!(matches!(result, Err(BringUpError::Declined)));
        } else {
            assert!(matches!(
                result,
                Err(BringUpError::DestructiveRestartUnavailable)
            ));
        }
    }
    assert_eq!(activity.connections.load(Ordering::SeqCst), 0);
    assert_eq!(activity.exec.load(Ordering::SeqCst), 0);
}
