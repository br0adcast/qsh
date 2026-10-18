use connect::{recovery_gate::AddressId, Address};
use qsh::recovery::{Activity, QshActivity};
use qsh::recovery_status::View;
use std::time::{Duration, Instant};

#[test]
fn aliases_unresolved_and_all_catalog_entries_survive_the_view() {
    let mut addresses: Vec<Address> = (1..=10)
        .map(|i| Address {
            host: format!("192.0.2.{i}"),
            qsh_port: 60000,
            ssh: None,
        })
        .collect();
    addresses[1].host = "alias.example".into();
    addresses[9].host = "unresolved.example".into();
    let shared = "192.0.2.1:60000".parse().unwrap();
    let view = View::build(
        &addresses,
        &[(AddressId(0), shared), (AddressId(1), shared)],
        &[],
        &[(shared, Instant::now())],
        None,
        Instant::now(),
    );
    assert!(view
        .header()
        .starts_with("reconnecting: 192.0.2.1 [QSH], alias.example [QSH]"));
    assert!(!view.header().contains("60000"));
    assert!(view.header().contains("unresolved.example [QSH]"));
    assert_eq!(view.targets.len(), 10);
    let details = view.details().join("\n");
    assert!(details.contains("alias.example:60000 -> 192.0.2.1:60000"));
    assert!(details.contains("unresolved.example:60000"));
    assert!(details.contains("unresolved"));
}

#[test]
fn historical_warm_probes_do_not_remain_active() {
    let addresses = vec![Address {
        host: "warm.example".into(),
        qsh_port: 60000,
        ssh: None,
    }];
    let endpoint = "192.0.2.1:60000".parse().unwrap();
    let sent = Instant::now();
    let endpoints = [(AddressId(0), endpoint)];
    let probes = [(endpoint, sent)];
    let recent = View::build(&addresses, &endpoints, &[], &probes, None, sent);
    let expired = View::build(
        &addresses,
        &endpoints,
        &[],
        &probes,
        None,
        sent + transport::paths::PROBE_TIMEOUT,
    );
    assert_eq!(recent.header(), expired.header());
    assert!(recent.header_spans().iter().any(|(_, active)| *active));
    assert!(!expired.header_spans().iter().any(|(_, active)| *active));
}

#[test]
fn ssh_backoff_does_not_hide_an_actual_qsh_attempt() {
    let addresses = vec![Address {
        host: "a.example".into(),
        qsh_port: 60000,
        ssh: Some(connect::SshRoute {
            port: 22,
            knock: vec![],
        }),
    }];
    let now = Instant::now();
    let activity = Activity {
        qsh: Some(QshActivity {
            address: AddressId(0),
            endpoint: Some("192.0.2.1:60001".parse().unwrap()),
        }),
        ssh: None,
        ssh_retry_at: Some(now + Duration::from_secs(8)),
        ssh_allowed: true,
    };
    let view = View::build(&addresses, &[], &[], &[], Some(&activity), now);
    assert_eq!(view.header(), "reconnecting: a.example [QSH/SSH]");
    assert!(view
        .details()
        .join("\n")
        .contains("a.example:60000 -> 192.0.2.1:60001"));
    assert!(view.details().join("\n").contains("retry in 8 s"));
    assert!(view.details().join("\n").contains("a.example:22"));
}

#[test]
fn header_positions_are_stable_across_protocol_activity_and_backoff() {
    use qsh::recovery_status::{QshState, SshState};
    let addresses = vec![Address {
        host: "host.example".into(),
        qsh_port: 60000,
        ssh: Some(connect::SshRoute {
            port: 22,
            knock: vec![],
        }),
    }];
    let mut view = View::build(&addresses, &[], &[], &[], None, Instant::now());
    let text = view.header();
    let idle = view.header_spans();
    view.targets[0].qsh = QshState::Trying;
    view.targets[0].ssh.as_mut().unwrap().1 = SshState::Trying;
    assert_eq!(view.header(), text);
    assert_ne!(view.header_spans(), idle);
    assert_eq!(view.header_spans()[1], idle[1], "host style stays fixed");
    view.targets[0].qsh = QshState::Resolving;
    view.targets[0].ssh.as_mut().unwrap().1 = SshState::Backoff(8);
    assert_eq!(view.header(), text);
    assert!(!view.header_spans().iter().any(|(_, active)| *active));
}
