use connect::recovery_gate::{
    AddressId, AddressOutcome as O, GateDecision as D, RecoveryEpoch, RecoveryGate, SweepId,
};

const EPOCH: RecoveryEpoch = RecoveryEpoch {
    connection: 7,
    network: 3,
};

fn gate() -> RecoveryGate {
    RecoveryGate::new(EPOCH, vec![AddressId(0), AddressId(1)])
}

#[test]
fn full_sweep_traces_only_allow_ssh_after_every_address_failed() {
    for (outcomes, decisions) in [
        ([O::Failed, O::Recovered], [D::Continue, D::Recovered]),
        ([O::Failed, O::Failed], [D::Continue, D::AllowSsh]),
        (
            [O::IdentityMismatch, O::Recovered],
            [D::Continue, D::Recovered],
        ),
        ([O::NeedsUser, O::Failed], [D::Continue, D::AllowSsh]),
    ] {
        let mut gate = gate();
        gate.begin_sweep(SweepId(1));
        for (addr, (outcome, decision)) in outcomes.into_iter().zip(decisions).enumerate() {
            assert_eq!(
                gate.finish(EPOCH, SweepId(1), AddressId(addr), outcome),
                decision
            );
        }
    }
}

#[test]
fn pending_duplicates_unknown_addresses_and_stale_results_cannot_open_the_gate() {
    let mut gate = gate();
    gate.begin_sweep(SweepId(1));
    assert_eq!(
        gate.finish(EPOCH, SweepId(1), AddressId(0), O::Failed),
        D::Continue
    );
    for (epoch, sweep, addr) in [
        (EPOCH, SweepId(1), AddressId(0)),
        (EPOCH, SweepId(1), AddressId(99)),
        (
            RecoveryEpoch {
                network: 2,
                ..EPOCH
            },
            SweepId(1),
            AddressId(1),
        ),
        (
            RecoveryEpoch {
                connection: 6,
                ..EPOCH
            },
            SweepId(1),
            AddressId(1),
        ),
        (EPOCH, SweepId(0), AddressId(1)),
        (EPOCH, SweepId(2), AddressId(1)),
    ] {
        for outcome in [O::Failed, O::Recovered] {
            assert_eq!(gate.finish(epoch, sweep, addr, outcome), D::Ignore);
        }
    }
    gate.begin_sweep(SweepId(2));
    assert_eq!(
        gate.finish(EPOCH, SweepId(1), AddressId(1), O::Failed),
        D::Ignore
    );
    assert_eq!(
        gate.finish(EPOCH, SweepId(2), AddressId(1), O::Failed),
        D::Continue
    );
    assert_eq!(
        gate.finish(EPOCH, SweepId(2), AddressId(0), O::Failed),
        D::AllowSsh
    );
}

#[test]
fn mismatched_addresses_can_recover_in_the_next_sweep_and_close_ssh_permission() {
    let mut gate = gate();
    gate.begin_sweep(SweepId(1));
    assert_eq!(
        gate.finish(EPOCH, SweepId(1), AddressId(0), O::IdentityMismatch),
        D::Continue
    );
    assert_eq!(
        gate.finish(EPOCH, SweepId(1), AddressId(1), O::Failed),
        D::AllowSsh
    );
    assert!(gate.ssh_allowed());
    assert_eq!(
        gate.finish(EPOCH, SweepId(1), AddressId(0), O::Recovered),
        D::Ignore
    );
    assert!(
        gate.ssh_allowed(),
        "a duplicate late success cannot revoke permission"
    );
    gate.begin_sweep(SweepId(2));
    assert!(
        gate.ssh_allowed(),
        "starting UDP again must preserve SSH permission"
    );
    assert_eq!(
        gate.finish(EPOCH, SweepId(2), AddressId(0), O::Recovered),
        D::Recovered
    );
    assert!(!gate.ssh_allowed());
    assert_eq!(
        gate.finish(EPOCH, SweepId(2), AddressId(1), O::Failed),
        D::Ignore
    );
    gate.begin_sweep(SweepId(3));
    assert_eq!(
        gate.finish(EPOCH, SweepId(3), AddressId(1), O::Failed),
        D::Ignore
    );
}

#[test]
fn allow_ssh_is_emitted_once_until_reset_and_old_sweeps_cannot_restart_progress() {
    let mut gate = gate();
    for sweep in [1, 2] {
        gate.begin_sweep(SweepId(sweep));
        assert_eq!(
            gate.finish(EPOCH, SweepId(sweep), AddressId(0), O::Failed),
            D::Continue
        );
        gate.begin_sweep(SweepId(sweep));
        gate.begin_sweep(SweepId(0));
        assert_eq!(
            gate.finish(EPOCH, SweepId(sweep), AddressId(1), O::Failed),
            if sweep == 1 { D::AllowSsh } else { D::Continue }
        );
    }
    let new_epoch = RecoveryEpoch {
        network: 4,
        ..EPOCH
    };
    gate.reset(new_epoch);
    assert!(!gate.ssh_allowed());
    gate.begin_sweep(SweepId(1));
    assert_eq!(
        gate.finish(EPOCH, SweepId(1), AddressId(0), O::Recovered),
        D::Ignore
    );
    assert_eq!(
        gate.finish(new_epoch, SweepId(1), AddressId(0), O::Failed),
        D::Continue
    );
    assert_eq!(
        gate.finish(new_epoch, SweepId(1), AddressId(1), O::Failed),
        D::AllowSsh
    );
}
