//! These tests obtain real cryptographic bootstrap evidence; no proof constructor is exposed.
use super::*;
use transport::bootstrap::{
    BootstrapClient, BootstrapError, BootstrapResponder, ServerInfo, SessionProfile,
};

const EPOCH: RecoveryEpoch = RecoveryEpoch {
    connection: 530,
    network: 1,
};

fn authenticated_info(compatible: bool) -> AuthenticatedServerInfo {
    let server = transport::generate_keypair();
    let local = transport::generate_keypair();
    let info = ServerInfo {
        generation: [5; 16],
        core_version: "0.7.0".into(),
        session_protocols: vec![SessionProfile {
            wire: if compatible {
                transport::wire::VERSION
            } else {
                255
            },
            handshake: transport::handshake_payload::HS_VERSION,
            channel: transport::channel::PROTOCOL_VERSION,
        }],
    };
    let mut responder = BootstrapResponder::new(server.private, info).unwrap();
    let mut client = BootstrapClient::new(local.private, server.public, [9; 32]);
    let source = "127.0.0.1:53000".parse().unwrap();
    let cookie = responder
        .on_datagram(Instant::now(), source, &client.request())
        .unwrap();
    assert_eq!(client.accept(&cookie), Err(BootstrapError::Retry));
    let reply = responder
        .on_datagram(Instant::now(), source, &client.request())
        .unwrap();
    AuthenticatedServerInfo::Bootstrap(client.accept(&reply).unwrap())
}

fn ssh_attempt(recovery: &Recovery) -> SshAttempt {
    recovery.begin_sweep(SweepId(1));
    for address in 0..2 {
        recovery.finish(
            recovery.revision(),
            EPOCH,
            SweepId(1),
            AddressId(address),
            AddressOutcome::Failed,
        );
    }
    let attempt = recovery.begin_ssh().unwrap();
    recovery.observe_ssh(&attempt, AddressId(0));
    attempt
}

#[test]
fn discovery_incompatible_metadata_skips_restart_but_unknown_retains_normal_recovery() {
    let recovery = Recovery::new(EPOCH, 2);
    let attempt = ssh_attempt(&recovery);
    assert!(recovery.discovery_permits_recovery(&attempt, 0, None));
    assert!(recovery.discovery_permits_recovery(&attempt, 0, Some(authenticated_info(true))));
    assert!(
        recovery.discovered_server_info().is_none(),
        "pre-start compatible proof is retired"
    );
    assert!(!recovery.discovery_permits_recovery(&attempt, 0, Some(authenticated_info(false))));
    assert_eq!(
        recovery.discovered_server_info().unwrap().info().generation,
        [5; 16]
    );
    assert_eq!(
        recovery.port(0),
        None,
        "discovery cannot manufacture readiness"
    );
}

#[test]
fn discovery_publication_is_address_attempt_epoch_and_catalog_bound() {
    let recovery = Recovery::new(EPOCH, 2);
    let attempt = ssh_attempt(&recovery);
    let proof = authenticated_info(false);
    assert!(
        !recovery.publish_server_info(&attempt, 1, proof.clone()),
        "another configured address has no current SSH activity"
    );
    assert!(recovery.publish_server_info(&attempt, 0, proof.clone()));
    let wrong_epoch = SshAttempt {
        epoch: RecoveryEpoch {
            network: 2,
            ..EPOCH
        },
        revision: attempt.revision,
        attempt: attempt.attempt,
        cancel: attempt.cancel.clone(),
        serial: attempt.serial,
    };
    assert!(!recovery.publish_server_info(&wrong_epoch, 0, proof.clone()));
    recovery.update_endpoints(
        EPOCH,
        vec![(AddressId(0), "127.0.0.2:53000".parse().unwrap())],
    );
    assert!(recovery.discovered_server_info().is_none());
    assert!(!recovery.publish_server_info(&attempt, 0, proof));
}

#[test]
fn discovery_other_qsh_route_wins_and_revokes_pending_ssh_proof() {
    let recovery = Recovery::new(EPOCH, 2);
    let attempt = ssh_attempt(&recovery);
    let proof = authenticated_info(false);
    assert!(recovery.publish_server_info(&attempt, 0, proof.clone()));
    recovery.begin_sweep(SweepId(2));
    recovery.finish(
        recovery.revision(),
        EPOCH,
        SweepId(2),
        AddressId(1),
        AddressOutcome::Recovered,
    );
    assert!(attempt.cancel.is_cancelled());
    assert!(recovery.discovered_server_info().is_none());
    assert!(!recovery.publish_server_info(&attempt, 0, proof));
}

#[test]
fn discovery_udp_only_proof_waits_for_all_addresses_without_retiring_other_route() {
    let recovery = Recovery::new(EPOCH, 2);
    recovery.begin_sweep(SweepId(1));
    assert!(recovery.publish_qsh_server_info(
        recovery.revision(),
        EPOCH,
        SweepId(1),
        0,
        authenticated_info(false)
    ));
    recovery.finish(
        recovery.revision(),
        EPOCH,
        SweepId(1),
        AddressId(0),
        AddressOutcome::Failed,
    );
    assert!(
        recovery.discovered_server_info().is_none(),
        "pending alternate route must still authenticate"
    );
    assert!(!recovery.ssh_allowed());
    recovery.finish(
        recovery.revision(),
        EPOCH,
        SweepId(1),
        AddressId(1),
        AddressOutcome::Failed,
    );
    assert!(recovery.discovered_server_info().is_some());
}

#[test]
fn discovery_phase_runs_restart_only_for_unknown_and_never_for_proven_incompatible() {
    use std::cell::Cell;
    let recovery = Recovery::new(EPOCH, 2);
    let attempt = ssh_attempt(&recovery);
    let restart_calls = Cell::new(0);
    let restart = || {
        restart_calls.set(restart_calls.get() + 1);
        Err(crate::ssh_step::SshStepError::NeedsPrompt)
    };
    assert!(recovery
        .recover_after_discovery(&attempt, 0, || Ok(None), restart)
        .is_some());
    assert_eq!(restart_calls.get(), 1);
    assert!(recovery
        .recover_after_discovery(&attempt, 0, || Ok(Some(authenticated_info(false))), restart)
        .is_none());
    assert_eq!(
        restart_calls.get(),
        1,
        "proven incompatible peer must not run ensure/add-client recovery"
    );
}

#[test]
fn discovery_restart_does_not_publish_prestart_proof_or_uploaded_binary_version() {
    let recovery = Recovery::new(EPOCH, 2);
    let attempt = ssh_attempt(&recovery);
    let result = recovery.recover_after_discovery(
        &attempt,
        0,
        || Ok(Some(authenticated_info(true))),
        || {
            Ok(bringup::Ready {
                serving_profiles: None,
                server_pubkey: [7; 32],
                ports: vec![60022],
                version: "99.0.0-uploaded-binary".into(),
                warning: None,
            })
        },
    );
    assert!(matches!(result, Some(Ok(_))));
    assert!(
        recovery.discovered_server_info().is_none(),
        "restart retires old generation proof; Ready.version is not live metadata"
    );
}

#[test]
fn discovery_previous_udp_sweep_cannot_suppress_a_new_ssh_query_or_restart() {
    let recovery = Recovery::new(EPOCH, 2);
    let attempt = ssh_attempt(&recovery);
    assert!(recovery.publish_qsh_server_info(
        recovery.revision(),
        EPOCH,
        SweepId(1),
        0,
        authenticated_info(false)
    ));
    assert!(recovery.server_info_for(&attempt, 0).is_some());
    recovery.begin_sweep(SweepId(2));
    assert!(
        recovery.display_server_info().is_some(),
        "an inflight refresh can keep contextual display"
    );
    assert!(
        recovery.discovered_server_info().is_some(),
        "inflight work does not supersede the latest completed observation"
    );
    assert!(
        recovery.server_info_for(&attempt, 0).is_none(),
        "old sweep metadata cannot prevent discovery/restart after daemon death"
    );
    let calls = std::cell::Cell::new(0);
    assert!(recovery
        .recover_after_discovery(
            &attempt,
            0,
            || Ok(None),
            || {
                calls.set(calls.get() + 1);
                Err(crate::ssh_step::SshStepError::NeedsPrompt)
            }
        )
        .is_some());
    assert_eq!(calls.get(), 1);
    assert!(
        recovery.discovered_server_info().is_none(),
        "completed current Unknown supersedes old proof"
    );
}

#[test]
fn discovery_completed_unknown_retires_update_authority_but_keeps_display_context() {
    let recovery = Recovery::new(EPOCH, 2);
    let attempt = ssh_attempt(&recovery);
    assert!(recovery.publish_server_info(&attempt, 0, authenticated_info(false)));
    assert!(recovery.discovered_server_info().is_some());
    let calls = std::cell::Cell::new(0);
    let result = recovery.recover_after_discovery(
        &attempt,
        0,
        || Ok(None),
        || {
            calls.set(calls.get() + 1);
            Err(crate::ssh_step::SshStepError::NeedsPrompt)
        },
    );
    assert!(result.is_some());
    assert_eq!(
        calls.get(),
        1,
        "unknown discovery preserves normal RestartOnly"
    );
    assert!(recovery.discovered_server_info().is_none());
    assert!(
        recovery.display_server_info().is_some(),
        "cached text is distinct from action authority"
    );
}

#[test]
fn discovery_current_qsh_incompatibility_arriving_during_ssh_unknown_prevents_restart() {
    let recovery = Recovery::new(EPOCH, 2);
    let attempt = ssh_attempt(&recovery);
    let calls = std::cell::Cell::new(0);
    let result = recovery.recover_after_discovery(
        &attempt,
        0,
        || {
            assert!(recovery.publish_qsh_server_info(
                recovery.revision(),
                EPOCH,
                SweepId(1),
                0,
                authenticated_info(false)
            ));
            Ok(None)
        },
        || {
            calls.set(calls.get() + 1);
            Err(crate::ssh_step::SshStepError::NeedsPrompt)
        },
    );
    assert!(result.is_none());
    assert_eq!(
        calls.get(),
        0,
        "Unknown SSH cannot authorize mutation against concurrent current proof"
    );
    assert!(
        recovery.discovered_server_info().is_none(),
        "newer completed Unknown requires refresh before an update choice"
    );
    assert!(recovery.display_server_info().is_some());
}

#[test]
fn discovery_late_old_request_cannot_override_newer_completed_unknown() {
    let recovery = Recovery::new(EPOCH, 2);
    recovery.begin_sweep(SweepId(1));
    let target = vec![(AddressId(0), "127.0.0.1:53000".parse().unwrap())];
    let old = recovery
        .begin_qsh_metadata(recovery.revision(), EPOCH, SweepId(1), target.clone())
        .unwrap();
    let new = recovery
        .begin_qsh_metadata(recovery.revision(), EPOCH, SweepId(1), target)
        .unwrap();
    assert!(
        old.serial < new.serial,
        "metadata request order is allocated before I/O"
    );
    assert!(recovery.complete_qsh_metadata(&old, AddressId(0), Some(authenticated_info(false))));
    assert!(recovery.complete_qsh_metadata(&new, AddressId(0), None));
    assert!(!recovery.complete_qsh_metadata(&old, AddressId(0), Some(authenticated_info(false))));
    for address in 0..2 {
        recovery.finish(
            recovery.revision(),
            EPOCH,
            SweepId(1),
            AddressId(address),
            AddressOutcome::Failed,
        );
    }
    assert!(recovery.discovered_server_info().is_none());
    assert!(recovery.display_server_info().is_some());
}

#[test]
fn discovery_prior_ssh_result_never_suppresses_a_fresh_query_or_normal_restart() {
    let recovery = Recovery::new(EPOCH, 2);
    let old = ssh_attempt(&recovery);
    assert!(recovery.publish_server_info(&old, 0, authenticated_info(false)));
    recovery.finish_ssh(&old);
    let current = recovery.begin_ssh().unwrap();
    recovery.observe_ssh(&current, AddressId(0));
    assert!(
        recovery.server_info_for(&current, 0).is_none(),
        "older SSH request cannot stand in for fresh discovery"
    );
    let calls = std::cell::Cell::new(0);
    assert!(recovery
        .recover_after_discovery(
            &current,
            0,
            || Ok(None),
            || {
                calls.set(calls.get() + 1);
                Err(crate::ssh_step::SshStepError::NeedsPrompt)
            }
        )
        .is_some());
    assert_eq!(calls.get(), 1);
    assert!(recovery.discovered_server_info().is_none());
}
