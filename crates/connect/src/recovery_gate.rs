//! Full-sweep SSH admission and generation identifiers for recovery results.

/// The connection and network generation that started a recovery attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RecoveryEpoch {
    pub connection: u64,
    pub network: u64,
}

/// A complete pass over the eligible addresses within one epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SweepId(pub u64);

/// An address within a recovery pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AddressId(pub usize);

/// The terminal result of one address attempt. A mismatch is local to that
/// attempt: the same address remains eligible in the next sweep.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressOutcome {
    Failed,
    IdentityMismatch,
    NeedsUser,
    Recovered,
}

/// What a current, previously pending result permits the recovery driver to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateDecision {
    Ignore,
    Continue,
    AllowSsh,
    Recovered,
}

/// SSH is admitted only after a complete unsuccessful QSH sweep. Permission
/// survives subsequent sweeps until recovery succeeds or the epoch is reset.
/// The driver owns cancellation and must stop its workers when cancelled.
pub struct RecoveryGate {
    epoch: RecoveryEpoch,
    addresses: std::collections::HashSet<AddressId>,
    pending: std::collections::HashSet<AddressId>,
    sweep: Option<SweepId>,
    ssh_allowed: bool,
    recovered: bool,
}

impl RecoveryGate {
    pub fn new(epoch: RecoveryEpoch, addresses: Vec<AddressId>) -> Self {
        Self {
            epoch,
            addresses: addresses.into_iter().collect(),
            pending: std::collections::HashSet::new(),
            sweep: None,
            ssh_allowed: false,
            recovered: false,
        }
    }

    /// Start a newer sweep, discarding unfinished results from an interrupted
    /// one. Repeated or older sweep starts cannot erase completed progress.
    pub fn begin_sweep(&mut self, id: SweepId) {
        if self.recovered || self.sweep.is_some_and(|sweep| id.0 <= sweep.0) {
            return;
        }
        self.sweep = Some(id);
        self.pending.clone_from(&self.addresses);
    }

    pub fn finish(
        &mut self,
        epoch: RecoveryEpoch,
        sweep: SweepId,
        addr: AddressId,
        outcome: AddressOutcome,
    ) -> GateDecision {
        if self.recovered
            || epoch != self.epoch
            || self.sweep != Some(sweep)
            || !self.pending.remove(&addr)
        {
            return GateDecision::Ignore;
        }
        if outcome == AddressOutcome::Recovered {
            self.recovered = true;
            self.ssh_allowed = false;
            return GateDecision::Recovered;
        }
        if self.pending.is_empty() && !self.ssh_allowed {
            self.ssh_allowed = true;
            return GateDecision::AllowSsh;
        }
        GateDecision::Continue
    }

    pub fn ssh_allowed(&self) -> bool {
        self.ssh_allowed
    }

    /// Change generations, revoking any permission earned by an older one.
    pub fn reset(&mut self, epoch: RecoveryEpoch) {
        self.epoch = epoch;
        self.sweep = None;
        self.pending.clear();
        self.ssh_allowed = false;
        self.recovered = false;
    }
}
