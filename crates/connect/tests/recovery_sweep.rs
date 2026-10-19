use std::net::SocketAddr;
use std::time::{Duration, Instant};

use connect::recovery_gate::{
    AddressId, AddressOutcome as O, GateDecision, RecoveryEpoch, RecoveryGate, SweepId,
};
use connect::recovery_sweep::{CheckMembership, Completion, RecoveryMethod as M, RecoverySweep};

const EPOCH: RecoveryEpoch = RecoveryEpoch {
    connection: 7,
    network: 3,
};
fn endpoint(n: u16) -> SocketAddr {
    ([127, 0, 0, 1], 42000 + n).into()
}
fn check(address: usize, physical: u16, method: M) -> CheckMembership {
    CheckMembership {
        address: AddressId(address),
        endpoint: endpoint(physical),
        method,
    }
}
fn sweep(checks: Vec<CheckMembership>) -> RecoverySweep {
    RecoverySweep::new(EPOCH, SweepId(1), 4, checks)
}
fn completion(address: usize, outcome: O) -> Completion {
    Completion {
        address: AddressId(address),
        outcome,
    }
}

#[test]
fn selected_failure_gives_other_endpoint_the_next_selection_turn() {
    let now = Instant::now();
    let method = M::Signature { candidate: 0 };
    let mut sweep = sweep(vec![check(0, 0, method), check(1, 1, method)]);
    let first = sweep.next_attempt().unwrap();
    assert_eq!(first.endpoints, vec![endpoint(0), endpoint(1)]);
    assert!(sweep.next_attempt().is_none(), "one active attempt only");
    for address in &first.endpoints {
        assert!(sweep.sent(first.id, *address, now, true));
    }
    assert!(sweep.selected(first.id, endpoint(0), now));
    assert!(!sweep.selected(first.id, endpoint(1), now));
    assert_eq!(
        sweep.expire(
            first.id,
            endpoint(0),
            now + Duration::from_secs(6),
            Duration::from_secs(5)
        ),
        vec![completion(0, O::Failed)]
    );
    assert!(sweep.retire(first.id));
    let second = sweep.next_attempt().unwrap();
    assert_eq!(second.id.method, method);
    assert_ne!(first.id.serial, second.id.serial);
    assert_eq!(
        second.endpoints,
        vec![endpoint(1)],
        "fast failed A cannot consume B's next initiator"
    );
    assert!(!sweep.sent(second.id, endpoint(0), now, true));
    assert!(sweep.sent(second.id, endpoint(1), now, true));
    assert!(sweep.selected(second.id, endpoint(1), now));
    assert_eq!(
        sweep.finish_checked(second.id, endpoint(1), O::Recovered),
        vec![completion(1, O::Recovered)]
    );
    assert!(sweep.complete());
    assert!(sweep.next_attempt().is_none());
}

#[test]
fn aliases_and_distinct_methods_complete_logical_members_honestly_before_ssh() {
    let now = Instant::now();
    let mut sweep = sweep(vec![
        check(0, 0, M::Signature { candidate: 0 }),
        check(1, 0, M::Signature { candidate: 0 }),
        check(1, 0, M::Signature { candidate: 0 }),
        check(0, 0, M::Allowlist),
        check(1, 0, M::Allowlist),
    ]);
    let mut gate = RecoveryGate::new(EPOCH, vec![AddressId(0), AddressId(1)]);
    gate.begin_sweep(SweepId(1));
    let first = sweep.next_attempt().unwrap();
    assert_eq!(first.endpoints, vec![endpoint(0)]);
    sweep.sent(first.id, endpoint(0), now, true);
    assert!(sweep
        .finish_checked(first.id, endpoint(0), O::Failed)
        .is_empty());
    assert!(!sweep.complete());
    assert!(!gate.ssh_allowed());
    sweep.retire(first.id);
    let second = sweep.next_attempt().unwrap();
    assert_eq!(second.id.method, M::Allowlist);
    assert!(sweep
        .finish_checked(first.id, endpoint(0), O::Failed)
        .is_empty());
    assert!(
        sweep
            .finish_checked(second.id, endpoint(0), O::Failed)
            .is_empty(),
        "queued work cannot fail"
    );
    sweep.sent(second.id, endpoint(0), now, false);
    let completed = sweep.finish_checked(second.id, endpoint(0), O::Failed);
    assert_eq!(
        completed,
        vec![completion(0, O::Failed), completion(1, O::Failed)]
    );
    assert_eq!(
        gate.finish(
            EPOCH,
            SweepId(1),
            completed[0].address,
            completed[0].outcome
        ),
        GateDecision::Continue
    );
    assert_eq!(
        gate.finish(
            EPOCH,
            SweepId(1),
            completed[1].address,
            completed[1].outcome
        ),
        GateDecision::AllowSsh
    );
    assert!(sweep.complete());
}

#[test]
fn queued_cancelled_and_old_revision_work_cannot_finish_an_address() {
    let now = Instant::now();
    let checks = vec![check(0, 0, M::Allowlist)];
    let mut sweep = sweep(checks.clone());
    let old = sweep.next_attempt().unwrap();
    assert!(!sweep.selected(old.id, endpoint(0), now));
    assert!(sweep
        .finish_checked(old.id, endpoint(0), O::Failed)
        .is_empty());
    assert!(sweep
        .expire(
            old.id,
            endpoint(0),
            now + Duration::from_secs(100),
            Duration::from_secs(10)
        )
        .is_empty());
    sweep.sent(old.id, endpoint(0), now, true);
    assert!(sweep.retire(old.id));
    assert!(
        !sweep.complete(),
        "retirement is cancellation, not a terminal outcome"
    );
    let current = sweep.next_attempt().unwrap();
    assert!(sweep
        .finish_checked(old.id, endpoint(0), O::Failed)
        .is_empty());
    assert!(!sweep.retire(old.id));
    assert_eq!(current.endpoints, vec![endpoint(0)]);
    let mut revised = RecoverySweep::new(EPOCH, SweepId(1), 5, checks);
    let fresh = revised.next_attempt().unwrap();
    assert!(!revised.sent(current.id, endpoint(0), now, true));
    assert!(!revised.selected(current.id, endpoint(0), now));
    assert_ne!(fresh.id, current.id);
}

#[test]
fn elapsed_bounds_start_at_actual_checks_and_preserve_unselected_obligations() {
    let now = Instant::now();
    let mut sweep = sweep(vec![check(0, 0, M::Allowlist), check(1, 1, M::Allowlist)]);
    let first = sweep.next_attempt().unwrap();
    let sent_at = now + Duration::from_secs(20);
    sweep.sent(first.id, endpoint(0), sent_at, true);
    sweep.sent(first.id, endpoint(1), sent_at, true);
    assert!(sweep
        .expire(
            first.id,
            endpoint(0),
            sent_at + Duration::from_secs(9),
            Duration::from_secs(10)
        )
        .is_empty());
    sweep.selected(first.id, endpoint(0), sent_at + Duration::from_secs(9));
    assert!(
        sweep
            .expire(
                first.id,
                endpoint(1),
                sent_at + Duration::from_secs(100),
                Duration::from_secs(10)
            )
            .is_empty(),
        "another endpoint consumed Noise; unselected work keeps its own next turn"
    );
    assert!(
        sweep
            .expire(
                first.id,
                endpoint(0),
                sent_at + Duration::from_secs(10),
                Duration::from_secs(5)
            )
            .is_empty(),
        "selected acceptance bound starts at selection"
    );
    assert_eq!(
        sweep.expire(
            first.id,
            endpoint(0),
            sent_at + Duration::from_secs(14),
            Duration::from_secs(5)
        ),
        vec![completion(0, O::Failed)]
    );
}

#[test]
fn signature_candidate_identity_is_not_interchangeable_with_another_candidate() {
    let now = Instant::now();
    let mut sweep = sweep(vec![
        check(0, 0, M::Signature { candidate: 0 }),
        check(0, 0, M::Signature { candidate: 1 }),
    ]);
    let first = sweep.next_attempt().unwrap();
    sweep.sent(first.id, endpoint(0), now, true);
    assert!(sweep
        .finish_checked(first.id, endpoint(0), O::Failed)
        .is_empty());
    sweep.retire(first.id);
    let second = sweep.next_attempt().unwrap();
    assert_eq!(second.id.method, M::Signature { candidate: 1 });
    let mut wrong = second.id;
    wrong.method = M::Signature { candidate: 0 };
    assert!(!sweep.sent(wrong, endpoint(0), now, true));
    assert!(sweep
        .finish_checked(wrong, endpoint(0), O::Failed)
        .is_empty());
    sweep.sent(second.id, endpoint(0), now, true);
    assert_eq!(
        sweep.finish_checked(second.id, endpoint(0), O::Failed),
        vec![completion(0, O::Failed)]
    );
}

#[test]
fn a_fresh_sweep_retries_foreign_identity_and_requires_selection_for_success() {
    let now = Instant::now();
    let checks = vec![check(0, 0, M::Allowlist)];
    let mut first = sweep(checks.clone());
    let attempt = first.next_attempt().unwrap();
    first.sent(attempt.id, endpoint(0), now, true);
    assert!(first
        .finish_checked(attempt.id, endpoint(0), O::Recovered)
        .is_empty());
    assert_eq!(
        first.finish_checked(attempt.id, endpoint(0), O::IdentityMismatch),
        vec![completion(0, O::IdentityMismatch)]
    );
    let mut next = RecoverySweep::new(EPOCH, SweepId(2), 4, checks);
    let attempt = next.next_attempt().unwrap();
    assert_eq!(attempt.endpoints, vec![endpoint(0)]);
    next.sent(attempt.id, endpoint(0), now, true);
    next.selected(attempt.id, endpoint(0), now);
    assert_eq!(
        next.finish_checked(attempt.id, endpoint(0), O::Recovered),
        vec![completion(0, O::Recovered)]
    );
}

#[test]
fn interleaved_methods_do_not_let_failed_a_take_b_next_selection_turn() {
    let now = Instant::now();
    let signature = M::Signature { candidate: 0 };
    let mut sweep = sweep(vec![
        check(0, 0, M::Allowlist),
        check(0, 0, signature),
        check(1, 1, M::Allowlist),
        check(1, 1, signature),
    ]);
    let first = sweep.next_attempt().unwrap();
    for &address in &first.endpoints {
        sweep.sent(first.id, address, now, true);
    }
    sweep.selected(first.id, endpoint(0), now);
    assert!(sweep
        .finish_checked(first.id, endpoint(0), O::Failed)
        .is_empty());
    sweep.retire(first.id);
    let second = sweep.next_attempt().unwrap();
    assert_eq!(
        second.id.method,
        M::Allowlist,
        "unfinished B keeps this method's next turn"
    );
    assert_eq!(second.endpoints, vec![endpoint(1)]);
    sweep.sent(second.id, endpoint(1), now, true);
    sweep.finish_checked(second.id, endpoint(1), O::Failed);
    sweep.retire(second.id);
    let third = sweep.next_attempt().unwrap();
    assert_eq!(third.id.method, signature);
    assert_eq!(
        third.endpoints,
        vec![endpoint(0), endpoint(1)],
        "all unfinished candidate obligations remain"
    );
}

#[test]
fn authenticated_protocol_failure_excludes_only_consumed_endpoint_for_all_methods() {
    let now = Instant::now();
    let checks = vec![
        check(0, 0, M::Allowlist),
        check(0, 0, M::Signature { candidate: 0 }),
        check(1, 0, M::Allowlist),
        check(1, 0, M::Signature { candidate: 0 }),
        check(2, 1, M::Allowlist),
        check(2, 1, M::Signature { candidate: 0 }),
    ];
    let mut state = sweep(checks.clone());
    let plan = state.next_attempt().unwrap();
    assert!(
        state
            .finish_protocol_failure(plan.id, endpoint(0))
            .is_empty(),
        "queued work cannot exclude a source"
    );
    state.sent(plan.id, endpoint(0), now, true);
    state.sent(plan.id, endpoint(1), now, true);
    assert!(
        state
            .finish_protocol_failure(plan.id, endpoint(0))
            .is_empty(),
        "actual send is not authenticated failure"
    );
    state.selected(plan.id, endpoint(0), now);
    assert!(
        state
            .finish_protocol_failure(plan.id, endpoint(1))
            .is_empty(),
        "failure belongs only to consumed source"
    );
    let mut stale = plan.id;
    stale.revision += 1;
    assert!(state.finish_protocol_failure(stale, endpoint(0)).is_empty());
    let mut completed = state.finish_protocol_failure(plan.id, endpoint(0));
    completed.sort_by_key(|c| c.address.0);
    assert_eq!(
        completed,
        vec![completion(0, O::Failed), completion(1, O::Failed)]
    );
    let mut gate = RecoveryGate::new(EPOCH, vec![AddressId(0), AddressId(1), AddressId(2)]);
    gate.begin_sweep(SweepId(1));
    for completion in completed {
        assert_eq!(
            gate.finish(EPOCH, SweepId(1), completion.address, completion.outcome),
            GateDecision::Continue
        );
    }
    assert!(!gate.ssh_allowed(), "B's required checks remain");
    assert!(
        state
            .finish_protocol_failure(plan.id, endpoint(0))
            .is_empty(),
        "no duplicate completion"
    );
    state.retire(plan.id);
    let next = state.next_attempt().unwrap();
    assert_eq!(next.id.method, M::Allowlist);
    assert_eq!(next.endpoints, vec![endpoint(1)]);
    state.sent(next.id, endpoint(1), now, true);
    state.finish_checked(next.id, endpoint(1), O::Failed);
    state.retire(next.id);
    let last = state.next_attempt().unwrap();
    assert_eq!(last.id.method, M::Signature { candidate: 0 });
    assert_eq!(
        last.endpoints,
        vec![endpoint(1)],
        "no later candidate retried for incompatible A"
    );
    let mut fresh = RecoverySweep::new(EPOCH, SweepId(2), 4, checks);
    assert_eq!(
        fresh.next_attempt().unwrap().endpoints,
        vec![endpoint(0), endpoint(1)],
        "new sweep retries repaired endpoints"
    );
}
