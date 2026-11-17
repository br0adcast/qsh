use super::super::authorization::AuthenticatedPeer;
use super::super::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
use super::*;
use crate::session_owner::authorization::HostMode;
use crate::session_owner::host::{HostLimits, HostState};

fn host() -> HostState {
    let bytes = ByteLimits {
        channel_bytes: 100,
        session_bytes: 200,
        account_bytes: 300,
        global_bytes: 400,
    };
    let resources = ResourceLimits {
        max_reservations: 8,
        screen: ScreenLimits {
            global_cells: 1000,
            account_cells: 500,
            global_rows: 100,
            account_rows: 50,
            global_models: 10,
            account_models: 5,
        },
        snapshot_transfer: bytes,
        control_queue: bytes,
    };
    let limits = HostLimits::new(resources, 4, 4, 4, 4, 100).unwrap();
    HostState::new(HostMode::System, limits).unwrap()
}

fn admit(host: &mut HostState) -> FrontendAdmission {
    host.admit_frontend(AuthenticatedPeer::for_test(
        host.instance(),
        HostMode::System,
    ))
    .unwrap()
}
fn candidate() -> FrontendIdentity {
    FrontendIdentity {
        generation: transport::session_resume::FrontendGeneration::new([9; 16]).unwrap(),
        build: super::super::status_contract::BuildIdentity::new("test", 1, [3; 32]).unwrap(),
    }
}
#[test]
fn replacement529_excludes_concurrent_requesters_until_exact_release() {
    let mut h = host();
    let first = admit(&mut h);
    let second = admit(&mut h);
    let g = h.begin_replacement(first, candidate()).unwrap();
    assert!(matches!(
        h.begin_replacement(second, candidate()),
        Err(ReplacementError::Busy)
    ));
    let id = g.id();
    h.finish_replacement(g).unwrap();
    let next = h.begin_replacement(second, candidate()).unwrap();
    assert_ne!(id, next.id());
}
#[test]
fn replacement529_foreign_and_retired_requesters_cannot_acquire() {
    let mut h = host();
    let mut other = host();
    let foreign = admit(&mut other);
    assert!(matches!(
        h.begin_replacement(foreign, candidate()),
        Err(ReplacementError::Refused)
    ));
    let f = admit(&mut h);
    h.retire_frontend(f).unwrap();
    assert!(matches!(
        h.begin_replacement(f, candidate()),
        Err(ReplacementError::Refused)
    ));
}
#[test]
fn replacement529_drop_before_work_releases_only_own_slot() {
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    drop(g);
    assert!(h.begin_replacement(f, candidate()).is_ok());
}
#[test]
fn replacement529_foreign_host_cannot_release_guard() {
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    let mut other = host();
    let (error, g) = other.finish_replacement(g).unwrap_err();
    assert_eq!(error, ReplacementError::Refused);
    assert!(matches!(
        h.begin_replacement(f, candidate()),
        Err(ReplacementError::Busy)
    ));
    h.finish_replacement(g).unwrap();
}

fn observation(
    g: &ReplacementGuard,
    status: super::super::status_contract::ReplacementStatus,
) -> ReplacementObservation {
    ReplacementObservation {
        slot: g.slot.clone(),
        fact: super::super::status_contract::ReplacementFact {
            transaction: Some(g.id()),
            status,
            serving: None,
        },
    }
}
#[test]
fn replacement529_work_abandonment_keeps_exclusion() {
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    h.begin_replacement_work(&g).unwrap();
    drop(g);
    assert!(matches!(
        h.begin_replacement(f, candidate()),
        Err(ReplacementError::Busy)
    ));
}
#[test]
fn replacement529_unsettled_work_cannot_be_finished() {
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    h.begin_replacement_work(&g).unwrap();
    let (e, g) = h.finish_replacement(g).unwrap_err();
    assert_eq!(e, ReplacementError::Unavailable);
    drop(g);
    assert!(matches!(
        h.begin_replacement(f, candidate()),
        Err(ReplacementError::Busy)
    ));
}
#[test]
fn replacement529_observation_requires_exact_host_slot_and_order() {
    use super::super::status_contract::ReplacementStatus::*;
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    assert_eq!(
        g.slot.lock().unwrap().transaction.status(),
        None,
        "candidate intent records no preparation"
    );
    h.begin_replacement_work(&g).unwrap();
    let premature = observation(&g, Fenced);
    let (e, premature) = h.observe_replacement(premature).unwrap_err();
    assert_eq!(e, ReplacementError::Refused);
    assert_eq!(premature.fact.status, Fenced);
    let prepared = observation(&g, Prepared);
    let mut other = host();
    let (e, prepared) = other.observe_replacement(prepared).unwrap_err();
    assert_eq!(e, ReplacementError::Refused);
    h.observe_replacement(prepared).unwrap();
    h.observe_replacement(observation(&g, Fenced)).unwrap();
    h.observe_replacement(observation(&g, DetachedFailure))
        .unwrap();
    h.settle_replacement(settlement(&g)).unwrap();
    h.finish_replacement(g).unwrap();
    assert!(h.begin_replacement(f, candidate()).is_ok());
}
#[test]
fn replacement529_retired_requester_fact_is_returned_and_never_advances() {
    use super::super::status_contract::ReplacementStatus::*;
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    h.begin_replacement_work(&g).unwrap();
    h.retire_frontend(f).unwrap();
    let (e, observation) = h
        .observe_replacement(observation(&g, Prepared))
        .unwrap_err();
    assert_eq!(e, ReplacementError::Refused);
    assert_eq!(observation.fact.status, Prepared);
    assert_eq!(g.slot.lock().unwrap().transaction.status(), None);
    drop(g);
    let other = admit(&mut h);
    assert!(matches!(
        h.begin_replacement(other, candidate()),
        Err(ReplacementError::Busy)
    ));
}
#[test]
fn replacement529_delayed_old_guard_cannot_release_successor() {
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    // Explicit fixture of a delayed internal capability, impossible to clone publicly.
    let delayed = ReplacementGuard {
        slot: g.slot.clone(),
        id: g.id(),
    };
    h.finish_replacement(g).unwrap();
    let next = h.begin_replacement(f, candidate()).unwrap();
    let (_, delayed) = h.finish_replacement(delayed).unwrap_err();
    drop(delayed);
    assert!(matches!(
        h.begin_replacement(f, candidate()),
        Err(ReplacementError::Busy)
    ));
    h.finish_replacement(next).unwrap();
}

#[test]
fn replacement529_abandoned_slot_releases_only_after_exact_terminal_settlement() {
    use super::super::status_contract::ReplacementStatus::*;
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    h.begin_replacement_work(&g).unwrap();
    let prepared = observation(&g, Prepared);
    let fenced = observation(&g, Fenced);
    let completed = observation(&g, DetachedFailure);
    let cleanup = settlement(&g);
    drop(g);
    h.observe_replacement(prepared).unwrap();
    h.observe_replacement(fenced).unwrap();
    assert!(matches!(
        h.begin_replacement(f, candidate()),
        Err(ReplacementError::Busy)
    ));
    h.observe_replacement(completed).unwrap();
    assert!(matches!(
        h.begin_replacement(f, candidate()),
        Err(ReplacementError::Busy)
    ));
    h.settle_replacement(cleanup).unwrap();
    assert!(h.begin_replacement(f, candidate()).is_ok());
}
#[test]
fn replacement529_copied_fact_and_cleanup_transaction_ids_refuse() {
    use super::super::status_contract::ReplacementStatus::*;
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    h.begin_replacement_work(&g).unwrap();
    let mut bad = settlement(&g);
    bad.transaction = ReplacementId::new([7; 16]).unwrap();
    assert!(h.settle_replacement(bad).is_err());
    let mut bad = observation(&g, Prepared);
    bad.fact.transaction = Some(ReplacementId::new([7; 16]).unwrap());
    let (_, bad) = h.observe_replacement(bad).unwrap_err();
    assert_eq!(
        bad.fact.transaction,
        Some(ReplacementId::new([7; 16]).unwrap())
    );
    assert_eq!(g.slot.lock().unwrap().transaction.status(), None);
}

fn settlement(g: &ReplacementGuard) -> ReplacementCleanupSettlement {
    ReplacementCleanupSettlement {
        slot: g.slot.clone(),
        host: g.slot.lock().unwrap().host,
        transaction: g.id(),
    }
}
#[test]
fn replacement529_partial_authority_retirement_refuses_stale_host_registration() {
    let mut h = host();
    let f = admit(&mut h);
    h.retire_frontend_authority_for_test(f);
    assert!(matches!(
        h.begin_replacement(f, candidate()),
        Err(ReplacementError::Refused)
    ));
}
#[test]
fn replacement529_retired_requester_cleanup_discharges_only_abandoned_exact_slot() {
    use super::super::status_contract::ReplacementStatus::*;
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    h.begin_replacement_work(&g).unwrap();
    let cleanup = settlement(&g);
    let delayed = settlement(&g);
    let stale_intent = observation(&g, Prepared);
    h.retire_frontend(f).unwrap();
    drop(g);
    assert!(h.observe_replacement(stale_intent).is_err());
    let next = admit(&mut h);
    assert!(matches!(
        h.begin_replacement(next, candidate()),
        Err(ReplacementError::Busy)
    ));
    h.settle_replacement(cleanup).unwrap();
    let successor = h.begin_replacement(next, candidate()).unwrap();
    let (e, delayed) = h.settle_replacement(delayed).unwrap_err();
    assert_eq!(e, ReplacementError::Refused);
    assert_eq!(
        delayed.transaction,
        delayed.slot.lock().unwrap().transaction.id()
    );
    assert!(matches!(
        h.begin_replacement(next, candidate()),
        Err(ReplacementError::Busy)
    ));
    h.finish_replacement(successor).unwrap();
}

#[test]
fn replacement529_exact_cleanup_is_terminal_for_work_and_fact_authority() {
    use super::super::status_contract::ReplacementStatus::*;
    let mut h = host();
    let f = admit(&mut h);
    let g = h.begin_replacement(f, candidate()).unwrap();
    h.begin_replacement_work(&g).unwrap();
    h.settle_replacement(settlement(&g)).unwrap();
    let rearm = h.begin_replacement_work(&g);
    let later_fact = h.observe_replacement(observation(&g, Prepared));
    h.finish_replacement(g).unwrap();
    assert_eq!(rearm, Err(ReplacementError::Refused));
    assert!(matches!(later_fact, Err((ReplacementError::Refused, _))));
    assert!(h.begin_replacement(f, candidate()).is_ok());
}
