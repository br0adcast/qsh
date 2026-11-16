//! Host-owned replacement exclusion; no staging or serving authority.
use super::authorization::{fresh_bytes, FrontendAdmission};
use super::host::HostState;
use super::status_contract::{FrontendIdentity, ReplacementId, ReplacementTransaction};
use std::sync::{Arc, Mutex};
use transport::session_resume::HostInstance;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReplacementError {
    Busy,
    Refused,
    Unavailable,
}
#[derive(Debug)]
pub(super) struct ReplacementSlot {
    host: HostInstance,
    requester: FrontendAdmission,
    transaction: ReplacementTransaction,
    released: bool,
    work_begun: bool,
    abandoned: bool,
    physically_settled: bool,
}
/// A capability bound to the exact retained host slot, never just its public ID.
#[derive(Debug)]
pub(crate) struct ReplacementGuard {
    slot: Arc<Mutex<ReplacementSlot>>,
    id: ReplacementId,
}
impl ReplacementGuard {
    pub(crate) fn id(&self) -> ReplacementId {
        self.id
    }
}
impl Drop for ReplacementGuard {
    fn drop(&mut self) {
        if let Ok(mut slot) = self.slot.lock() {
            if slot.work_begun && !slot.physically_settled {
                slot.abandoned = true;
            } else {
                slot.released = true;
            }
        }
    }
}
impl HostState {
    pub(crate) fn begin_replacement(
        &mut self,
        requester: FrontendAdmission,
        candidate: FrontendIdentity,
    ) -> Result<ReplacementGuard, ReplacementError> {
        if !self.frontend_is_current(requester) {
            return Err(ReplacementError::Refused);
        }
        if let Some(slot) = &self.replacement {
            if !slot
                .lock()
                .map_err(|_| ReplacementError::Unavailable)?
                .released
            {
                return Err(ReplacementError::Busy);
            }
        }
        let id = ReplacementId::new(fresh_bytes().map_err(|_| ReplacementError::Unavailable)?)
            .ok_or(ReplacementError::Unavailable)?;
        let slot = Arc::new(Mutex::new(ReplacementSlot {
            host: self.instance(),
            requester,
            transaction: ReplacementTransaction::new(id, candidate),
            released: false,
            work_begun: false,
            abandoned: false,
            physically_settled: false,
        }));
        self.replacement = Some(slot.clone());
        Ok(ReplacementGuard { slot, id })
    }
    fn owns_replacement(&self, slot: &Arc<Mutex<ReplacementSlot>>) -> bool {
        self.replacement
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, slot))
    }
    pub(super) fn begin_replacement_work(
        &mut self,
        guard: &ReplacementGuard,
    ) -> Result<(), ReplacementError> {
        if !self.owns_replacement(&guard.slot) {
            return Err(ReplacementError::Refused);
        }
        let mut slot = guard
            .slot
            .lock()
            .map_err(|_| ReplacementError::Unavailable)?;
        if slot.host != self.instance()
            || slot.transaction.id() != guard.id
            || !self.frontend_is_current(slot.requester)
            || slot.released
            || slot.abandoned
            || slot.physically_settled
        {
            return Err(ReplacementError::Refused);
        }
        slot.work_begun = true;
        Ok(())
    }
    /// Consume only an observation sealed by the physical owner. The public DTO
    /// remains untrusted; this envelope has no public constructor or wire decoder.
    pub(super) fn observe_replacement(
        &mut self,
        observation: ReplacementObservation,
    ) -> Result<(), (ReplacementError, ReplacementObservation)> {
        let result = (|| {
            if !self.owns_replacement(&observation.slot) {
                return Err(ReplacementError::Refused);
            }
            let mut slot = observation
                .slot
                .lock()
                .map_err(|_| ReplacementError::Unavailable)?;
            if slot.host != self.instance()
                || !self.frontend_is_current(slot.requester)
                || !slot.work_begun
                || slot.released
                || slot.physically_settled
            {
                return Err(ReplacementError::Refused);
            }
            slot.transaction
                .record(observation.fact.clone())
                .map_err(|_| ReplacementError::Refused)?;
            Ok(())
        })();
        result.map_err(|error| (error, observation))
    }
    pub(super) fn settle_replacement(
        &mut self,
        settlement: ReplacementCleanupSettlement,
    ) -> Result<(), (ReplacementError, ReplacementCleanupSettlement)> {
        let result = (|| {
            if !self.owns_replacement(&settlement.slot) || settlement.host != self.instance() {
                return Err(ReplacementError::Refused);
            }
            let mut slot = settlement
                .slot
                .lock()
                .map_err(|_| ReplacementError::Unavailable)?;
            if slot.host != settlement.host
                || slot.transaction.id() != settlement.transaction
                || !slot.work_begun
                || slot.released
            {
                return Err(ReplacementError::Refused);
            }
            // Cleanup discharges the exact physical operation; it never records
            // a serving/intent fact and never renews the requester's authority.
            slot.physically_settled = true;
            if slot.abandoned || !self.frontend_is_current(slot.requester) {
                slot.released = true;
            }
            Ok(())
        })();
        result.map_err(|error| (error, settlement))
    }
    pub(crate) fn finish_replacement(
        &mut self,
        guard: ReplacementGuard,
    ) -> Result<(), (ReplacementError, ReplacementGuard)> {
        let valid = self
            .replacement
            .as_ref()
            .is_some_and(|slot| Arc::ptr_eq(slot, &guard.slot))
            && guard.slot.lock().is_ok_and(|slot| {
                slot.host == self.instance()
                    && slot.transaction.id() == guard.id
                    && self.frontend_is_current(slot.requester)
                    && !slot.released
            });
        if !valid {
            return Err((ReplacementError::Refused, guard));
        }
        if guard
            .slot
            .lock()
            .map_or(true, |slot| slot.work_begun && !slot.physically_settled)
        {
            return Err((ReplacementError::Unavailable, guard));
        }
        // Guard Drop releases only its own exact slot; another host cannot clear it.
        drop(guard);
        Ok(())
    }
}
/// Exact physical cleanup, independent of the requester's now-revoked authority.
/// No production constructor exists before an actual cleanup owner supplies it.
#[derive(Debug)]
pub(super) struct ReplacementCleanupSettlement {
    slot: Arc<Mutex<ReplacementSlot>>,
    host: HostInstance,
    transaction: ReplacementId,
}
/// Private receipt envelope. No production staging/serving constructor exists.
#[derive(Debug)]
pub(super) struct ReplacementObservation {
    slot: Arc<Mutex<ReplacementSlot>>,
    fact: super::status_contract::ReplacementFact,
}
#[cfg(test)]
#[path = "host_replacement_tests.rs"]
mod tests;
