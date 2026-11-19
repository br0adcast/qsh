use super::super::authorization::{AuthenticatedPeer, PolicyResult};
use super::super::resource_contract::{ByteLimits, ResourceLimits, ScreenLimits};
use super::*;

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
    let mut limits = HostLimits::new(resources, 4, 4, 4, 4, 100).unwrap();
    limits.sessions = 2;
    limits.sessions_per_account = 2;
    HostState::new(HostMode::System, limits).unwrap()
}
fn auth(
    h: &mut HostState,
    uid: u32,
    name: &str,
    now: u64,
) -> (FrontendAdmission, AuthenticationAttempt) {
    let f = h
        .admit_frontend(AuthenticatedPeer::for_test(h.instance(), HostMode::System))
        .unwrap();
    let i = h.begin_authentication(f, now, now + 100).unwrap();
    let HostDecision::Authenticated(a) = h
        .apply_policy_result(PolicyResult::allow_for_test(i, uid, name), now + 1)
        .unwrap()
    else {
        panic!()
    };
    (f, a)
}
fn issue(h: &mut HostState, a: AuthenticationAttempt, s: SessionLocator, now: u64) -> GrantOffer {
    let i = h.begin_issue(a, s, now, now + 100).unwrap();
    let HostDecision::GrantIssued(g) = h
        .apply_policy_result(PolicyResult::allow_for_test(i, 1000, "alice"), now + 1)
        .unwrap()
    else {
        panic!()
    };
    g
}

#[test]
fn host529_reconstruction_mints_new_scopes_and_rejects_old_authority() {
    let mut h = host();
    let old_host = h.instance();
    assert_ne!(h.grant_scope, h.resource_scope);
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    let mut rebuilt = host();
    assert_ne!(old_host, rebuilt.instance());
    assert_ne!(h.grant_scope, rebuilt.grant_scope);
    assert_ne!(h.resource_scope, rebuilt.resource_scope);
    assert!(rebuilt.create_session(a, 4).is_err());
    assert!(rebuilt.begin_issue(a, s, 5, 50).is_err());
}

#[test]
fn host529_catalog_capacity_and_never_established_churn_keep_fresh_identities() {
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let mut seen = std::collections::HashSet::new();
    for round in 0..8 {
        let now = 3 + round * 30_000;
        if round != 0 {
            h.sweep(now).unwrap();
        }
        for _ in 0..2 {
            assert!(seen.insert(h.create_session(a, now).unwrap()));
        }
        assert_eq!(h.create_session(a, now).unwrap_err(), HostError::Capacity);
        assert_eq!(h.catalog_len(), 2);
    }
    assert_eq!(seen.len(), 16);
}

#[test]
fn host529_live_detached_and_unknown_resource_debt_never_age_out() {
    use super::super::resource_contract::{Reservation, ReservationId, ReservationKind};
    use transport::channel_geometry::ChannelInstance;
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let live = h.create_session(a, 3).unwrap();
    h.establish_owner(OwnerEstablished::for_test(h.instance(), live))
        .unwrap();
    let debt = h.create_session(a, 4).unwrap();
    let e = h.catalog.iter().find(|e| e.locator == debt).unwrap();
    let reservation = Reservation {
        id: ReservationId::new(1).unwrap(),
        principal: e.principal,
        locator: debt,
        channel: ChannelInstance::new(1).unwrap(),
        kind: ReservationKind::ControlQueue,
        bytes: 1,
        screen_charge: None,
    };
    h.resources
        .lock()
        .unwrap()
        .reserve(
            e.resources.unwrap(),
            reservation,
            RequestId::new(1).unwrap(),
        )
        .unwrap();
    h.sweep(1_000_000).unwrap();
    assert_eq!(h.catalog_len(), 2);
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    assert_eq!(
        h.create_session(a, 1_000_001).unwrap_err(),
        HostError::Capacity
    );
}

#[test]
fn host529_fresh_policy_each_phase_and_epoch_are_single_use() {
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    let g = issue(&mut h, a, s, 4);
    let intent = h.begin_consume(a, g.grant(), g.binding(), 6, 100).unwrap();
    let replay = PolicyResult::allow_for_test(intent.copy_for_test(), 1000, "alice");
    let HostDecision::GrantConsumed(first) = h
        .apply_policy_result(PolicyResult::allow_for_test(intent, 1000, "alice"), 7)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(first.attachment().epoch.get(), 1);
    assert!(h.apply_policy_result(replay, 8).is_err());
    assert!(h.begin_consume(a, g.grant(), g.binding(), 9, 100).is_err());
    let next = issue(&mut h, a, s, 10);
    let i = h
        .begin_consume(a, next.grant(), next.binding(), 12, 100)
        .unwrap();
    let HostDecision::GrantConsumed(second) = h
        .apply_policy_result(PolicyResult::allow_for_test(i, 1000, "alice"), 13)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(second.attachment().epoch.get(), 2);
    assert_eq!(
        h.resources.lock().unwrap().principals(),
        1,
        "grant retirement never retires durable resource registration"
    );
    assert_eq!(h.grants.principals(), 0);
}

#[test]
fn host529_revocation_between_issue_and_consume_leaves_catalog_and_resources_intact() {
    let mut h = host();
    let (f, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    let g = issue(&mut h, a, s, 4);
    let i = h.begin_consume(a, g.grant(), g.binding(), 6, 100).unwrap();
    h.revoke_account(1000).unwrap();
    assert!(h
        .apply_policy_result(PolicyResult::allow_for_test(i, 1000, "alice"), 7)
        .is_err());
    assert_eq!(h.catalog_len(), 1);
    assert_eq!(h.resources.lock().unwrap().principals(), 1);
    assert_eq!(h.grants.grants(), 0);
    assert!(
        h.begin_authentication(f, 8, 100).is_ok(),
        "a new actual proof may establish a new attempt; revocation has no watcher claim"
    );
}

#[test]
fn host529_stolen_locator_wrong_frontend_and_failed_policy_cannot_consume() {
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    let g = issue(&mut h, a, s, 4);
    let (_, stranger) = auth(&mut h, 1001, "mallory", 6);
    assert!(h.begin_issue(stranger, s, 8, 100).is_err());
    assert!(h
        .begin_consume(stranger, g.grant(), g.binding(), 9, 100)
        .is_err());
    let i = h.begin_consume(a, g.grant(), g.binding(), 10, 100).unwrap();
    assert!(h
        .apply_policy_result(PolicyResult::refuse_for_test(i), 11)
        .is_err());
    assert_eq!(h.catalog[0].last_epoch, 0);
}

#[test]
fn host529_completed_tombstones_hold_capacity_until_five_minutes_or_authenticated_ack() {
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let first = h.create_session(a, 3).unwrap();
    let second = h.create_session(a, 3).unwrap();
    for locator in [first, second] {
        h.establish_owner(OwnerEstablished::for_test(h.instance(), locator))
            .unwrap();
        let i = h.begin_owner_cleanup(locator).unwrap();
        h.complete_owner(OwnerCompletion::for_test(i, Vec::new()), 4)
            .unwrap();
    }
    h.sweep(300_003).unwrap();
    assert_eq!(h.catalog_len(), 2);
    assert_eq!(
        h.create_session(a, 300_003).unwrap_err(),
        HostError::Capacity
    );
    let (_, wrong_account) = auth(&mut h, 1001, "mallory", 300_003);
    assert!(h.acknowledge_completion(wrong_account, first).is_err());
    h.acknowledge_completion(a, first).unwrap();
    assert_eq!(h.catalog_len(), 1);
    assert_eq!(h.completed_facts(a, second).unwrap().len(), 0);
    h.sweep(300_004).unwrap();
    assert_eq!(h.catalog_len(), 0);
    assert_ne!(h.create_session(a, 300_004).unwrap(), first);
}

#[test]
fn host529_expired_offer_can_be_replaced_without_resetting_session_or_epoch() {
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    let old = issue(&mut h, a, s, 4);
    assert!(
        h.begin_issue(a, s, old.binding().expires_at_monotonic, 1000)
            .is_ok(),
        "expired grant must not retain a registration slot or block legitimate retry"
    );
    assert_eq!(h.catalog[0].last_epoch, 0);
    assert_eq!(h.resources.lock().unwrap().principals(), 1);
}

#[test]
fn host529_grace_reclamation_also_revokes_unconsumed_session_grants() {
    let mut h = host();
    h.limits.grant_lifetime_ms = 100_000;
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    let g = issue(&mut h, a, s, 4);
    h.sweep(30_003).unwrap();
    assert_eq!(h.catalog_len(), 0);
    assert_eq!(
        h.grants.grants(),
        0,
        "a removed never-established session cannot retain attach authority"
    );
    assert_eq!(h.grants.principals(), 0);
    assert!(h
        .begin_consume(a, g.grant(), g.binding(), 30_004, 30_100)
        .is_err());
}

#[test]
fn host529_owner_completion_cannot_refund_unknown_backing_debt() {
    use super::super::resource_contract::{Reservation, ReservationId, ReservationKind};
    use transport::channel_geometry::ChannelInstance;
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    h.establish_owner(OwnerEstablished::for_test(h.instance(), s))
        .unwrap();
    let e = &h.catalog[0];
    h.resources
        .lock()
        .unwrap()
        .reserve(
            e.resources.unwrap(),
            Reservation {
                id: ReservationId::new(1).unwrap(),
                principal: e.principal,
                locator: s,
                channel: ChannelInstance::new(1).unwrap(),
                kind: ReservationKind::ControlQueue,
                bytes: 1,
                screen_charge: None,
            },
            RequestId::new(1).unwrap(),
        )
        .unwrap();
    let intent = h.begin_owner_cleanup(s).unwrap();
    assert_eq!(
        h.complete_owner(OwnerCompletion::for_test(intent, Vec::new()), 4),
        Err(HostError::ResourceDebt)
    );
    assert!(h.acknowledge_completion(a, s).is_err());
    h.sweep(1_000_000).unwrap();
    assert_eq!(h.catalog_len(), 1);
    assert_eq!(h.resources.lock().unwrap().reservations(), 1);
    assert_eq!(h.resources.lock().unwrap().principals(), 1);
}

#[test]
fn host529_attach_epoch_exhaustion_refuses_without_wrapping_or_resource_reset() {
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    h.catalog[0].last_epoch = u64::MAX;
    let g = issue(&mut h, a, s, 4);
    let i = h.begin_consume(a, g.grant(), g.binding(), 6, 100).unwrap();
    assert!(matches!(
        h.apply_policy_result(PolicyResult::allow_for_test(i, 1000, "alice"), 7),
        Err(HostError::Exhausted)
    ));
    assert_eq!(h.catalog[0].last_epoch, u64::MAX);
    assert_eq!(h.resources.lock().unwrap().principals(), 1);
}

#[test]
fn host529_completion_preserves_exit_and_final_input_output_cursors() {
    use transport::channel_geometry::ChannelInstance;
    let mut h = host();
    let (_, a) = auth(&mut h, 1000, "alice", 1);
    let s = h.create_session(a, 3).unwrap();
    h.establish_owner(OwnerEstablished::for_test(h.instance(), s))
        .unwrap();
    let channel = ChannelInstance::new(7).unwrap();
    let fact = CompletedChannelFact {
        exit: ExitReceipt {
            attachment: Attachment {
                locator: s,
                frontend: FrontendGeneration::new([3; 16]).unwrap(),
                epoch: AttachEpoch::new(1).unwrap(),
            },
            channel,
            receipt_id: RequestId::new(9).unwrap(),
            fact: ExitFact::Reaped { status: 37 },
        },
        input: InputPosition {
            epoch: InputEpoch::new([5; 16]).unwrap(),
            accepted: 91,
            committed: 90,
        },
        output: OutputCursor {
            channel,
            offset: 999,
        },
    };
    let intent = h.begin_owner_cleanup(s).unwrap();
    h.complete_owner(OwnerCompletion::for_test(intent, vec![fact]), 4)
        .unwrap();
    h.sweep(300_003).unwrap();
    assert_eq!(h.completed_facts(a, s).unwrap(), &[fact]);
    assert_eq!(h.resources.lock().unwrap().principals(), 0);
}
