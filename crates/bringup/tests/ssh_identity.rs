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
            service_restart_consent: None,
            pending_busy_target: None,
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
            service_restart_consent: None,
            pending_busy_target: None,
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
        schema: 2,
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
        service_restart: None,
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
                service_restart_consent: None,
                pending_busy_target: None,
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

#[test]
fn service_confirmation_pins_the_observed_ssh_target_key_and_helper() {
    let activity = Arc::new(ServerActivity::default());
    let server = FakeServer::start(FakeAuth {
        accept_any_key: true,
        activity: activity.clone(),
        exec_reply: Some(Arc::new(|raw| {
            let command = std::str::from_utf8(raw).unwrap();
            let command = command
                .strip_prefix("/bin/sh -c '")
                .and_then(|text| text.strip_suffix('\''))
                .unwrap_or(command)
                .replace(r"'\''", "'");
            if command.contains(" transport-ensure ") {
                let attempt = command
                    .split("--busy-attempt ")
                    .nth(1)
                    .unwrap()
                    .split_whitespace()
                    .next()
                    .unwrap()
                    .trim_matches('\'');
                if command.contains("--service-restart-consent") {
                    assert!(!command.contains("--destructive-consent"));
                    return format!("TRANSPORT-RESTART-FAILED {{\"attempt\":\"{attempt}\",\"disposition\":\"uncertain\"}}\n").into_bytes();
                }
                return format!("TRANSPORT-BUSY {}\n", serde_json::json!({
                    "schema":2,"attempt":attempt,
                    "identity":{"version":"0.5.0","build":1,"checksum":"ab".repeat(32),"pid":42},
                    "candidate":{"build":2,"checksum":"ef".repeat(32)},
                    "active_connections":2,"serving_profiles":null,"preservation":"unknown",
                    "service_restart":{"profile":"personal_transport_v1","uid":1000,"endpoint":"/fixture/cache/qsh/control.sock","port":60022}
                })).into_bytes();
            }
            if command.ends_with(" bootstrap-capabilities") {
                return b"{\"schema\":1,\"busy_decisions\":true,\"account_service_restart_v1\":true}\n".to_vec();
            }
            if command.contains("QSH-TRUST") {
                return b"QSH-TRUST /fixture/qshd\n".to_vec();
            }
            b"os Linux\narch x86_64\nhome /fixture\npath /fixture/qshd\n".to_vec()
        })),
        ..Default::default()
    });
    let request = || BringUpRequest {
        report_busy: true,
        busy_decision: None,
        destructive_consent: None,
        service_restart_consent: None,
        pending_busy_target: None,
        name: "service-boundary".into(),
        ssh: ssh::SshParams {
            host: "127.0.0.1".into(),
            port: server.port,
            username: "fixture".into(),
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
    };
    let run = |request| {
        bring_up_identified(
            request,
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
    };
    let Err(BringUpError::ObservedBusy(observation)) = run(request()) else {
        panic!("authenticated BUSY observation required");
    };
    assert_eq!(
        observation.target.host_key.key,
        server.host_public_key_wire()
    );
    assert_eq!(observation.target.helper_path, "/fixture/qshd");
    let selected = || {
        let mut next = request();
        next.busy_decision = Some(
            PendingBusy::new(observation.info.clone())
                .unwrap()
                .decide(BusyChoice::ForceUpdate),
        );
        next.service_restart_consent = observation.info.confirm_service_restart();
        next.pending_busy_target = Some(observation.target.clone());
        next
    };
    let before = activity.connections.load(Ordering::SeqCst);
    for field in ["host", "port", "username", "recovery", "scope"] {
        let mut next = selected();
        match field {
            "host" => next.ssh.host = "different.invalid".into(),
            "port" => next.ssh.port = server.port.wrapping_add(1),
            "username" => next.ssh.username = "another".into(),
            "recovery" => next.report_busy = false,
            _ => next.destructive_consent = Some(observation.info.confirm_destructive_restart()),
        }
        assert!(
            matches!(run(next), Err(BringUpError::InvalidRequest(_))),
            "{field}"
        );
    }
    assert_eq!(activity.connections.load(Ordering::SeqCst), before);
    let mut changed_key = selected();
    changed_key
        .pending_busy_target
        .as_mut()
        .unwrap()
        .host_key
        .key
        .push(0);
    let commands = activity.exec.load(Ordering::SeqCst);
    assert!(run(changed_key).is_err());
    assert_eq!(
        activity.exec.load(Ordering::SeqCst),
        commands,
        "changed host must receive no helper commands"
    );
    let mut changed_path = selected();
    changed_path
        .pending_busy_target
        .as_mut()
        .unwrap()
        .helper_path = "/fixture/another-qshd".into();
    assert!(matches!(run(changed_path), Err(BringUpError::Verify(_))));
    assert!(matches!(
        run(selected()),
        Err(BringUpError::DestructiveRestartUncertain { .. })
    ));
}
