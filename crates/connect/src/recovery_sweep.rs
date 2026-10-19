//! Method- and generation-scoped accounting for one shared recovery sweep.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::recovery_gate::{AddressId, AddressOutcome, RecoveryEpoch, SweepId};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RecoveryMethod {
    Signature { candidate: usize },
    Allowlist,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CheckMembership {
    pub address: AddressId,
    pub endpoint: SocketAddr,
    pub method: RecoveryMethod,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AttemptId {
    pub epoch: RecoveryEpoch,
    pub sweep: SweepId,
    pub revision: u64,
    pub serial: u64,
    pub method: RecoveryMethod,
}

#[derive(Debug, PartialEq, Eq)]
pub struct AttemptPlan {
    pub id: AttemptId,
    pub endpoints: Vec<SocketAddr>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub address: AddressId,
    pub outcome: AddressOutcome,
}

struct CheckGroup {
    endpoint: SocketAddr,
    method: RecoveryMethod,
    aliases: Vec<AddressId>,
    done: bool,
}

struct LogicalProgress {
    remaining: usize,
    outcome: AddressOutcome,
}

struct ActiveCheck {
    group: usize,
    first_sent: Option<Instant>,
    sent_successfully: bool,
}

struct ActiveAttempt {
    id: AttemptId,
    checks: HashMap<SocketAddr, ActiveCheck>,
    selected: Option<(SocketAddr, Instant)>,
}

/// The owner supplies actual check evidence and retires the old network driver
/// before requesting another attempt. Cancellation itself completes no check.
/// This state does not perform DNS, socket I/O, signing, or trust-store writes.
pub struct RecoverySweep {
    epoch: RecoveryEpoch,
    sweep: SweepId,
    revision: u64,
    serial: u64,
    current_method: Option<RecoveryMethod>,
    groups: Vec<CheckGroup>,
    pending_groups: usize,
    logical: HashMap<AddressId, LogicalProgress>,
    active: Option<ActiveAttempt>,
    recovered: bool,
}

impl RecoverySweep {
    pub fn new(
        epoch: RecoveryEpoch,
        sweep: SweepId,
        revision: u64,
        memberships: Vec<CheckMembership>,
    ) -> Self {
        let mut groups: Vec<CheckGroup> = Vec::new();
        let mut indices = HashMap::new();
        let mut logical = HashMap::new();
        for membership in memberships {
            let index = *indices
                .entry((membership.method, membership.endpoint))
                .or_insert_with(|| {
                    groups.push(CheckGroup {
                        endpoint: membership.endpoint,
                        method: membership.method,
                        aliases: Vec::new(),
                        done: false,
                    });
                    groups.len() - 1
                });
            let aliases = &mut groups[index].aliases;
            if !aliases.contains(&membership.address) {
                aliases.push(membership.address);
                logical
                    .entry(membership.address)
                    .or_insert(LogicalProgress {
                        remaining: 0,
                        outcome: AddressOutcome::Failed,
                    })
                    .remaining += 1;
            }
        }
        Self {
            epoch,
            sweep,
            revision,
            serial: 0,
            current_method: None,
            pending_groups: groups.len(),
            groups,
            logical,
            active: None,
            recovered: false,
        }
    }

    /// One method and candidate per initiator. Completed endpoint checks are
    /// omitted, so a responder that consumed the previous initiator and failed
    /// cannot consume this method's next turn ahead of unfinished endpoints.
    pub fn next_attempt(&mut self) -> Option<AttemptPlan> {
        if self.active.is_some() || self.recovered {
            return None;
        }
        let method = self
            .current_method
            .filter(|method| {
                self.groups
                    .iter()
                    .any(|group| !group.done && group.method == *method)
            })
            .or_else(|| {
                self.groups
                    .iter()
                    .find(|group| !group.done)
                    .map(|group| group.method)
            })?;
        self.current_method = Some(method);
        self.serial = self.serial.checked_add(1)?;
        let id = AttemptId {
            epoch: self.epoch,
            sweep: self.sweep,
            revision: self.revision,
            serial: self.serial,
            method,
        };
        let mut checks = HashMap::new();
        let mut endpoints = Vec::new();
        for (index, group) in self.groups.iter().enumerate() {
            if group.method == method && !group.done {
                endpoints.push(group.endpoint);
                checks.insert(
                    group.endpoint,
                    ActiveCheck {
                        group: index,
                        first_sent: None,
                        sent_successfully: false,
                    },
                );
            }
        }
        self.active = Some(ActiveAttempt {
            id,
            checks,
            selected: None,
        });
        Some(AttemptPlan { id, endpoints })
    }

    fn active_mut(&mut self, id: AttemptId) -> Option<&mut ActiveAttempt> {
        if self.recovered {
            return None;
        }
        self.active.as_mut().filter(|active| active.id == id)
    }

    /// Called only after an actual socket attempt. An explicit send error is
    /// a real check, but only a successful send permits response selection.
    pub fn sent(
        &mut self,
        id: AttemptId,
        endpoint: SocketAddr,
        now: Instant,
        success: bool,
    ) -> bool {
        let Some(active) = self.active_mut(id) else {
            return false;
        };
        let Some(check) = active.checks.get_mut(&endpoint) else {
            return false;
        };
        check.first_sent.get_or_insert(now);
        check.sent_successfully |= success;
        true
    }

    /// Records the source that consumed the initiator. It is not by itself
    /// authentication acceptance; the owner supplies that terminal outcome.
    pub fn selected(&mut self, id: AttemptId, endpoint: SocketAddr, now: Instant) -> bool {
        let Some(active) = self.active_mut(id) else {
            return false;
        };
        let Some(check) = active.checks.get(&endpoint) else {
            return false;
        };
        if active.selected.is_some()
            || !check.sent_successfully
            || check.first_sent.is_none_or(|sent| now < sent)
        {
            return false;
        }
        active.selected = Some((endpoint, now));
        true
    }

    /// Complete an attributable check, never another endpoint's failure.
    /// An authentication success additionally requires this attempt's selected
    /// source. The caller must validate authenticated acceptance before using
    /// Recovered (including authenticated session loss, whose consent is UI-owned).
    pub fn finish_checked(
        &mut self,
        id: AttemptId,
        endpoint: SocketAddr,
        outcome: AddressOutcome,
    ) -> Vec<Completion> {
        let Some(active) = self.active_mut(id) else {
            return Vec::new();
        };
        let Some(check) = active.checks.get(&endpoint) else {
            return Vec::new();
        };
        if check.first_sent.is_none() {
            return Vec::new();
        }
        if outcome == AddressOutcome::Recovered
            && active.selected.map(|selected| selected.0) != Some(endpoint)
        {
            return Vec::new();
        }
        let index = check.group;
        // Removing the active check also rejects duplicate sends/completions.
        active.checks.remove(&endpoint);
        self.complete_group(index, outcome)
    }

    fn complete_group(&mut self, index: usize, outcome: AddressOutcome) -> Vec<Completion> {
        self.groups[index].done = true;
        self.pending_groups -= 1;
        if outcome == AddressOutcome::Recovered {
            self.recovered = true;
            return self.groups[index]
                .aliases
                .iter()
                .map(|&address| Completion { address, outcome })
                .collect();
        }
        let mut completions = Vec::new();
        for address in &self.groups[index].aliases {
            let progress = self
                .logical
                .get_mut(address)
                .expect("registered logical membership");
            progress.remaining -= 1;
            progress.outcome = combined_outcome(progress.outcome, outcome);
            if progress.remaining == 0 {
                completions.push(Completion {
                    address: *address,
                    outcome: progress.outcome,
                });
            }
        }
        completions
    }

    /// An authenticated protocol rejection makes other credentials irrelevant
    /// for the consumed endpoint in this sweep. No other endpoint is excluded.
    /// The caller must supply a real authenticated protocol rejection; silence,
    /// refusal hints, cancellation and a failed credential do not qualify.
    pub fn finish_protocol_failure(
        &mut self,
        id: AttemptId,
        endpoint: SocketAddr,
    ) -> Vec<Completion> {
        let Some(active) = self.active_mut(id) else {
            return Vec::new();
        };
        if active.selected.map(|selected| selected.0) != Some(endpoint)
            || !active
                .checks
                .get(&endpoint)
                .is_some_and(|check| check.sent_successfully)
        {
            return Vec::new();
        }
        active.checks.remove(&endpoint);
        let groups: Vec<_> = self
            .groups
            .iter()
            .enumerate()
            .filter(|(_, group)| group.endpoint == endpoint && !group.done)
            .map(|(index, _)| index)
            .collect();
        let mut completions = Vec::new();
        for index in groups {
            completions.extend(self.complete_group(index, AddressOutcome::Failed));
        }
        completions
    }

    /// The owner supplies its existing network/acceptance bound. An unselected
    /// endpoint never expires behind another selected initiator: it retains its
    /// selection opportunity in the next attempt. No queued-time deadline exists.
    pub fn expire(
        &mut self,
        id: AttemptId,
        endpoint: SocketAddr,
        now: Instant,
        bound: Duration,
    ) -> Vec<Completion> {
        let Some(active) = self.active_mut(id) else {
            return Vec::new();
        };
        let start = match active.selected {
            Some((selected, at)) if selected == endpoint => Some(at),
            Some(_) => None,
            None => active
                .checks
                .get(&endpoint)
                .and_then(|check| check.first_sent),
        };
        if start
            .and_then(|start| now.checked_duration_since(start))
            .is_some_and(|elapsed| elapsed >= bound)
        {
            self.finish_checked(id, endpoint, AddressOutcome::Failed)
        } else {
            Vec::new()
        }
    }

    /// Retirement is local cancellation, not proof of any pending failure.
    pub fn retire(&mut self, id: AttemptId) -> bool {
        if self.active.as_ref().is_none_or(|active| active.id != id) {
            return false;
        }
        self.active = None;
        true
    }

    pub fn complete(&self) -> bool {
        self.recovered || self.pending_groups == 0
    }
}

fn combined_outcome(previous: AddressOutcome, next: AddressOutcome) -> AddressOutcome {
    match (previous, next) {
        (AddressOutcome::NeedsUser, _) | (_, AddressOutcome::NeedsUser) => {
            AddressOutcome::NeedsUser
        }
        (AddressOutcome::IdentityMismatch, _) | (_, AddressOutcome::IdentityMismatch) => {
            AddressOutcome::IdentityMismatch
        }
        _ => AddressOutcome::Failed,
    }
}
