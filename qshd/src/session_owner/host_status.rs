//! Bounded resident observations. No production serving receipt constructor.
use super::authorization::{fresh_bytes, FrontendAdmission};
use super::host::HostState;
use super::host_engine::{LocalBinding, LocalOwnerEngine};
use super::status_contract::{
    BuildIdentity, FrontendIdentity, OwnerStatus, StatusCursor, StatusEpoch, StatusPage,
    MAX_STATUS_OWNERS,
};
use std::sync::Arc;
use transport::session_resume::HostInstance;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusError {
    Refused,
    StaleCursor,
    Unavailable,
}
pub(super) fn decode_checksum(checksum: &str) -> Result<[u8; 32], StatusError> {
    if checksum.len() != 64 {
        return Err(StatusError::Unavailable);
    }
    fn nibble(v: u8) -> Option<u8> {
        match v {
            b'0'..=b'9' => Some(v - b'0'),
            b'a'..=b'f' => Some(v - b'a' + 10),
            b'A'..=b'F' => Some(v - b'A' + 10),
            _ => None,
        }
    }
    let mut out = [0; 32];
    let (pairs, _) = checksum.as_bytes().as_chunks::<2>();
    for (target, bytes) in out.iter_mut().zip(pairs) {
        *target = (nibble(bytes[0]).ok_or(StatusError::Unavailable)? << 4)
            | nibble(bytes[1]).ok_or(StatusError::Unavailable)?;
    }
    Ok(out)
}
pub(super) fn resident_build_identity() -> Result<BuildIdentity, StatusError> {
    let checksum = crate::state::self_checksum().map_err(|_| StatusError::Unavailable)?;
    BuildIdentity::new(
        env!("CARGO_PKG_VERSION"),
        crate::state::build_label(),
        decode_checksum(&checksum)?,
    )
    .map_err(|_| StatusError::Unavailable)
}
/// Opaque until an actual listener owner exists. Candidate/DTO values cannot mint it.
#[derive(Debug)]
pub(super) struct ServingObservation {
    host: HostInstance,
    frontend: FrontendAdmission,
    identity: FrontendIdentity,
}
#[derive(Debug)]
struct OwnerStamp {
    binding: Arc<LocalBinding>,
    revision: u64,
}
#[derive(Debug)]
struct ObservedStatus {
    rows: Vec<OwnerStatus>,
    stamps: Vec<OwnerStamp>,
    revision: u64,
}
impl ObservedStatus {
    fn same(&self, other: &Self) -> bool {
        self.revision == other.revision
            && self.rows == other.rows
            && self.stamps.len() == other.stamps.len()
            && self
                .stamps
                .iter()
                .zip(&other.stamps)
                .all(|(a, b)| a.revision == b.revision && Arc::ptr_eq(&a.binding, &b.binding))
    }
}
#[derive(Debug)]
pub(super) struct StatusSnapshot {
    requester: FrontendAdmission,
    frontend: FrontendIdentity,
    build: BuildIdentity,
    epoch: StatusEpoch,
    expected: usize,
    observed: ObservedStatus,
}
pub(super) struct StatusCatalogRow {
    pub(super) binding: Arc<LocalBinding>,
    pub(super) final_status: Option<OwnerStatus>,
    pub(super) completed: bool,
}
impl HostState {
    pub(super) fn observe_serving(
        &mut self,
        observation: ServingObservation,
    ) -> Result<(), Box<(StatusError, ServingObservation)>> {
        if observation.host != self.instance()
            || observation.identity.generation != observation.frontend.generation()
            || !self.frontend_is_current(observation.frontend)
            || self.supervision_is_stopping()
        {
            return Err(Box::new((StatusError::Refused, observation)));
        }
        self.note_status_mutation();
        self.status_serving = Some(observation);
        Ok(())
    }
    pub(super) fn status_frontend_lost(&mut self, frontend: FrontendAdmission) {
        if self
            .status_serving
            .as_ref()
            .is_some_and(|serving| serving.frontend == frontend)
        {
            self.status_serving = None;
        }
        self.note_status_mutation();
    }
    fn status_serving_identity(&self) -> Result<FrontendIdentity, StatusError> {
        let serving = self
            .status_serving
            .as_ref()
            .ok_or(StatusError::Unavailable)?;
        if serving.host != self.instance()
            || !self.frontend_is_current(serving.frontend)
            || self.supervision_is_stopping()
        {
            return Err(StatusError::Unavailable);
        }
        Ok(serving.identity.clone())
    }
    fn sample_status(&self, owners: &[&LocalOwnerEngine]) -> Result<ObservedStatus, StatusError> {
        if !self.supervision_roster_complete(owners) {
            return Err(StatusError::Unavailable);
        }
        let revision = self.status_revision().ok_or(StatusError::Unavailable)?;
        let catalog = self.status_catalog_roster()?;
        let mut rows = Vec::new();
        rows.try_reserve_exact(catalog.len())
            .map_err(|_| StatusError::Unavailable)?;
        for entry in catalog {
            if entry.completed {
                rows.push(entry.final_status.ok_or(StatusError::Unavailable)?);
            } else {
                let owner = owners
                    .iter()
                    .find(|owner| Arc::ptr_eq(owner.supervision_binding(), &entry.binding))
                    .ok_or(StatusError::Unavailable)?;
                rows.push(owner.status_observation()?);
            }
        }
        rows.sort_by_key(|row| {
            (
                *row.locator.session.as_bytes(),
                *row.locator.owner.as_bytes(),
            )
        });
        let mut stamps = Vec::new();
        stamps
            .try_reserve_exact(owners.len())
            .map_err(|_| StatusError::Unavailable)?;
        for owner in owners {
            stamps.push(OwnerStamp {
                binding: owner.supervision_binding().clone(),
                revision: owner.status_revision().ok_or(StatusError::Unavailable)?,
            });
        }
        Ok(ObservedStatus {
            rows,
            stamps,
            revision,
        })
    }
    // The immutable borrows exclude installation/close. Every live predicate
    // sampled true can only fall until such a mutation. Two complete all-true
    // sweeps therefore share a coherent boundary; an initial false is never
    // published as inactive0 and cannot hide a false-to-true observation ABA.
    fn collect_status(
        &self,
        owners: &[&LocalOwnerEngine],
        between: impl FnOnce(),
    ) -> Result<ObservedStatus, StatusError> {
        let first = self.sample_status(owners)?;
        between();
        let second = self.sample_status(owners)?;
        if !first.same(&second) || self.status_revision() != Some(second.revision) {
            return Err(StatusError::Unavailable);
        }
        Ok(second)
    }
    pub(super) fn status_page(
        &mut self,
        requester: FrontendAdmission,
        cursor: Option<StatusCursor>,
        owners: &[&LocalOwnerEngine],
    ) -> Result<StatusPage, StatusError> {
        self.status_page_inner(requester, cursor, owners, || {})
    }
    fn status_page_inner(
        &mut self,
        requester: FrontendAdmission,
        cursor: Option<StatusCursor>,
        owners: &[&LocalOwnerEngine],
        between: impl FnOnce(),
    ) -> Result<StatusPage, StatusError> {
        let previous = self.status_snapshot.take();
        if !self.frontend_is_current(requester) {
            return Err(StatusError::Refused);
        }
        let stale = if cursor.is_some() {
            StatusError::StaleCursor
        } else {
            StatusError::Unavailable
        };
        let frontend = self.status_serving_identity().map_err(|_| stale)?;
        let snapshot = if let Some(cursor) = cursor {
            let snapshot = previous.ok_or(StatusError::StaleCursor)?;
            if snapshot.requester != requester
                || snapshot.epoch != cursor.epoch
                || u64::try_from(snapshot.expected).ok() != Some(cursor.index)
                || snapshot.frontend != frontend
                || self.status_revision() != Some(snapshot.observed.revision)
            {
                return Err(StatusError::StaleCursor);
            }
            let observed = self
                .collect_status(owners, between)
                .map_err(|_| StatusError::StaleCursor)?;
            if !snapshot.observed.same(&observed) {
                return Err(StatusError::StaleCursor);
            }
            snapshot
        } else {
            let observed = self.collect_status(owners, between)?;
            if self.status_resident_build.is_none() {
                self.status_resident_build = Some(resident_build_identity()?);
            }
            StatusSnapshot {
                requester,
                frontend,
                build: self
                    .status_resident_build
                    .clone()
                    .ok_or(StatusError::Unavailable)?,
                epoch: StatusEpoch::new(fresh_bytes().map_err(|_| StatusError::Unavailable)?)
                    .ok_or(StatusError::Unavailable)?,
                expected: 0,
                observed,
            }
        };
        self.publish_status_page(snapshot)
    }
    fn publish_status_page(
        &mut self,
        mut snapshot: StatusSnapshot,
    ) -> Result<StatusPage, StatusError> {
        let start = snapshot.expected;
        let end = start
            .saturating_add(MAX_STATUS_OWNERS)
            .min(snapshot.observed.rows.len());
        let next = (end < snapshot.observed.rows.len()).then_some(StatusCursor {
            epoch: snapshot.epoch,
            index: end as u64,
        });
        let page = StatusPage {
            host: self.instance(),
            host_build: snapshot.build.clone(),
            frontend: snapshot.frontend.clone(),
            epoch: snapshot.epoch,
            cursor: start as u64,
            total: snapshot.observed.rows.len() as u64,
            owners: snapshot.observed.rows[start..end].to_vec(),
            next,
        };
        page.validate().map_err(|_| StatusError::Unavailable)?;
        if next.is_some() {
            snapshot.expected = end;
            self.status_snapshot = Some(snapshot);
        }
        Ok(page)
    }
    #[cfg(test)]
    pub(super) fn install_serving_for_test(&mut self, frontend: FrontendAdmission) {
        // Fixture-only independent listener receipt. No production constructor.
        let identity = FrontendIdentity {
            generation: frontend.generation(),
            build: resident_build_identity().unwrap(),
        };
        self.observe_serving(ServingObservation {
            host: self.instance(),
            frontend,
            identity,
        })
        .unwrap();
    }
}
#[cfg(test)]
#[path = "host_status_tests.rs"]
mod tests;
