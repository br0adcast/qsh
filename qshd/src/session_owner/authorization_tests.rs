use super::*;
use transport::session_resume::{OwnerInstance, RetainedSessionId};

fn authority() -> AuthorizationState {
    AuthorizationState::new(
        HostInstance::new([1; 16]).unwrap(),
        HostMode::System,
        2,
        2,
        2,
    )
    .unwrap()
}
fn admitted(a: &mut AuthorizationState) -> FrontendAdmission {
    a.admit_frontend(AuthenticatedPeer::for_test(a.host, HostMode::System))
        .unwrap()
}
fn authenticated(a: &mut AuthorizationState, f: FrontendAdmission) -> AuthenticationAttempt {
    let intent = a.begin_authentication(f, 1, 100).unwrap();
    match a
        .resolve(PolicyResult::allow_for_test(intent, 1000, "alice"), 2)
        .unwrap()
    {
        PolicyResolution::Authenticated(attempt) => attempt,
        _ => panic!("authentication result"),
    }
}

#[test]
fn host529_result_is_one_use_and_bound_to_its_exact_operation() {
    let mut a = authority();
    let f = admitted(&mut a);
    let attempt = authenticated(&mut a, f);
    let locator = SessionLocator {
        session: RetainedSessionId::new([4; 16]).unwrap(),
        owner: OwnerInstance::new([5; 16]).unwrap(),
    };
    let intent = a
        .begin_policy(attempt, PolicyKind::IssueGrant, locator, None, 3, 100)
        .unwrap();
    let replay = PolicyResult::allow_for_test(intent.copy_for_test(), 1000, "alice");
    assert!(matches!(
        a.resolve(PolicyResult::allow_for_test(intent, 1000, "alice"), 4),
        Ok(PolicyResolution::Approved(_))
    ));
    let next = a
        .begin_policy(
            attempt,
            PolicyKind::ConsumeGrant,
            locator,
            Some(AttachGrant::new([7; 32]).unwrap()),
            5,
            100,
        )
        .unwrap();
    assert_eq!(a.resolve(replay, 6).unwrap_err(), AuthorityError::Refused);
    assert!(matches!(
        a.resolve(PolicyResult::allow_for_test(next, 1000, "alice"), 7),
        Ok(PolicyResolution::Approved(_))
    ));
}

#[test]
fn host529_revocation_cancellation_and_frontend_retirement_invalidate_late_results() {
    for action in 0..3 {
        let mut a = authority();
        let f = admitted(&mut a);
        let attempt = authenticated(&mut a, f);
        let locator = SessionLocator {
            session: RetainedSessionId::new([4; 16]).unwrap(),
            owner: OwnerInstance::new([5; 16]).unwrap(),
        };
        let intent = a
            .begin_policy(attempt, PolicyKind::IssueGrant, locator, None, 3, 100)
            .unwrap();
        let result = PolicyResult::allow_for_test(intent, 1000, "alice");
        match action {
            0 => a.revoke_account(1000).unwrap(),
            1 => a.cancel_attempt(attempt).unwrap(),
            _ => {
                a.retire_frontend(f).unwrap();
            }
        }
        assert_eq!(a.resolve(result, 4).unwrap_err(), AuthorityError::Refused);
        assert_eq!(a.pending_count(), 0);
        // Authority cancellation says nothing about the separately owned verifier child.
    }
}

#[test]
fn host529_foreign_host_changed_account_expiry_and_refusal_never_authenticate() {
    let mut a = authority();
    let f = admitted(&mut a);
    let i = a.begin_authentication(f, 1, 100).unwrap();
    let mut foreign = PolicyResult::allow_for_test(i.copy_for_test(), 1000, "alice");
    foreign.binding.host = HostInstance::new([9; 16]).unwrap();
    assert_eq!(a.resolve(foreign, 2).unwrap_err(), AuthorityError::Refused);
    let attempt = match a
        .resolve(PolicyResult::allow_for_test(i, 1000, "alice"), 3)
        .unwrap()
    {
        PolicyResolution::Authenticated(a) => a,
        _ => panic!(),
    };
    let locator = SessionLocator {
        session: RetainedSessionId::new([4; 16]).unwrap(),
        owner: OwnerInstance::new([5; 16]).unwrap(),
    };
    let i = a
        .begin_policy(attempt, PolicyKind::IssueGrant, locator, None, 4, 100)
        .unwrap();
    assert_eq!(
        a.resolve(PolicyResult::allow_for_test(i, 1001, "alice"), 5)
            .unwrap_err(),
        AuthorityError::Refused
    );
    let i = a.begin_authentication(f, 6, 100).unwrap();
    assert_eq!(
        a.resolve(PolicyResult::allow_for_test(i, 1000, "alice"), 100)
            .unwrap_err(),
        AuthorityError::Refused
    );
    assert_eq!(
        a.attempt_count(),
        0,
        "account mismatch and expired authentication both retire their transient attempts"
    );
    let i = a.begin_authentication(f, 101, 200).unwrap();
    assert_eq!(
        a.resolve(PolicyResult::refuse_for_test(i), 102)
            .unwrap_err(),
        AuthorityError::Refused
    );
    assert_eq!(a.attempt_count(), 0);
}

#[test]
fn host529_bounded_churn_retires_slots_without_resetting_operation_high_water() {
    let mut a = authority();
    let f = admitted(&mut a);
    let mut last = 0;
    for now in 1..20 {
        let intent = a.begin_authentication(f, now * 2, 100).unwrap();
        assert!(intent.binding.operation > last);
        last = intent.binding.operation;
        let attempt = intent.binding.attempt;
        a.cancel_attempt(attempt).unwrap();
        assert_eq!(
            a.resolve(
                PolicyResult::allow_for_test(intent, 1000, "alice"),
                now * 2 + 1
            )
            .unwrap_err(),
            AuthorityError::Refused
        );
    }
    a.last_operation = u64::MAX;
    assert_eq!(
        a.begin_authentication(f, 50, 100).unwrap_err(),
        AuthorityError::Exhausted
    );
    assert_eq!(a.attempt_count(), 0);
}

#[test]
fn host529_revocation_revision_exhaustion_fails_closed_without_counter_reset() {
    let mut a = authority();
    let f = admitted(&mut a);
    let attempt = authenticated(&mut a, f);
    a.revision = u64::MAX;
    assert_eq!(a.revoke_account(1000), Err(AuthorityError::Exhausted));
    assert!(
        a.identity(attempt).is_err(),
        "known revocation must invalidate admission even when the revision cannot advance"
    );
    assert!(
        a.begin_authentication(f, 3, 100).is_err(),
        "an exhausted authority cannot mint a new lifetime under a reused revision"
    );
    assert_eq!(a.revision, u64::MAX);
}

#[test]
fn host529_pending_and_frontend_capacity_recover_without_resurrecting_old_incarnations() {
    let mut a = authority();
    let f = admitted(&mut a);
    let other = admitted(&mut a);
    assert_eq!(
        a.admit_frontend(AuthenticatedPeer::for_test(a.host, HostMode::System))
            .unwrap_err(),
        AuthorityError::Capacity
    );
    let first = a.begin_authentication(f, 1, 100).unwrap();
    let second = a.begin_authentication(other, 2, 100).unwrap();
    assert_eq!(
        a.begin_authentication(f, 3, 100).unwrap_err(),
        AuthorityError::Capacity
    );
    a.retire_frontend(f).unwrap();
    let replacement = admitted(&mut a);
    assert_ne!(f, replacement);
    assert!(a.begin_authentication(f, 4, 100).is_err());
    assert!(a
        .resolve(PolicyResult::allow_for_test(first, 1000, "alice"), 5)
        .is_err());
    let new = a.begin_authentication(replacement, 6, 100).unwrap();
    assert!(a
        .resolve(PolicyResult::allow_for_test(new, 1000, "alice"), 7)
        .is_ok());
    assert!(a
        .resolve(PolicyResult::allow_for_test(second, 1001, "bob"), 8)
        .is_ok());
}

#[test]
fn host529_personal_and_system_peer_authority_are_distinct() {
    let host = HostInstance::new([1; 16]).unwrap();
    let mut a = AuthorizationState::new(
        host,
        HostMode::Personal {
            canonical_uid: 1000,
        },
        2,
        2,
        2,
    )
    .unwrap();
    assert!(a
        .admit_frontend(AuthenticatedPeer::for_test(host, HostMode::System))
        .is_err());
    let f = a
        .admit_frontend(AuthenticatedPeer::for_test(
            host,
            HostMode::Personal {
                canonical_uid: 1000,
            },
        ))
        .unwrap();
    let intent = a.begin_authentication(f, 1, 100).unwrap();
    assert!(a
        .resolve(PolicyResult::allow_for_test(intent, 0, "root"), 2)
        .is_err());
    assert_eq!(a.attempt_count(), 0);
}
