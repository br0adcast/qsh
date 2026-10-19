//! Bounded observations of a token's binding while admissions are in flight.
//!
//! Only the manager changes revisions. An admission owns an observation until
//! commit/refusal cleanup finishes; a terminal deletion invalidates it even if
//! the token becomes absent again. Unobserved tokens need no permanent history.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

#[derive(Clone, Debug)]
pub(crate) struct BindingRevision {
    state: Arc<AtomicU64>,
    observed: u64,
}

impl BindingRevision {
    pub(crate) fn is_current(&self) -> bool {
        self.observed != 0 && self.state.load(Ordering::Relaxed) == self.observed
    }
}

/// Reserved before any binding mutation. Exhaustion therefore cannot leave a
/// route partially installed. A reservation may be discarded without a change.
pub(crate) struct RevisionChange(u64);

pub(crate) struct BindingRevisions {
    entries: HashMap<[u8; 16], Arc<AtomicU64>>,
    next: u64,
    limit: usize,
}

impl BindingRevisions {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            entries: HashMap::new(),
            next: 1,
            limit,
        }
    }

    fn allocate(&mut self) -> Option<u64> {
        if self.next == 0 {
            return None;
        }
        let value = self.next;
        self.next = value.checked_add(1).unwrap_or(0);
        Some(value)
    }

    pub(crate) fn prune(&mut self) {
        self.entries.retain(|_, state| Arc::strong_count(state) > 1);
    }

    pub(crate) fn capture(&mut self, token: [u8; 16]) -> Option<BindingRevision> {
        self.prune();
        if self.next == 0 {
            return None;
        }
        if !self.entries.contains_key(&token) {
            if self.entries.len() >= self.limit {
                return None;
            }
            let revision = self.allocate()?;
            self.entries
                .insert(token, Arc::new(AtomicU64::new(revision)));
        }
        let state = Arc::clone(self.entries.get(&token)?);
        let observed = state.load(Ordering::Relaxed);
        Some(BindingRevision { state, observed })
    }

    pub(crate) fn reserve_change(&mut self) -> Option<RevisionChange> {
        self.allocate().map(RevisionChange)
    }

    pub(crate) fn commit(&mut self, token: [u8; 16], change: RevisionChange) {
        if let Some(state) = self.entries.get(&token) {
            state.store(change.0, Ordering::Relaxed);
        }
    }

    pub(crate) fn invalidate(&mut self, token: [u8; 16]) {
        // Terminal cleanup must still succeed after generation exhaustion.
        // Zero is never issued as an observation; it invalidates every lease.
        if self.entries.contains_key(&token) {
            let revision = self.allocate().unwrap_or(0);
            self.commit(token, RevisionChange(revision));
        }
        self.prune();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observation_survives_cleanup_and_absent_token_recreation() {
        let mut revisions = BindingRevisions::new(2);
        let old = revisions.capture([1; 16]).unwrap();
        let twin = revisions.capture([1; 16]).unwrap();
        assert!(old.is_current() && twin.is_current());
        let change = revisions.reserve_change().unwrap();
        revisions.commit([1; 16], change);
        assert!(!old.is_current() && !twin.is_current());
        let current = revisions.capture([1; 16]).unwrap();
        revisions.invalidate([1; 16]);
        assert!(!current.is_current());
        let recreated = revisions.capture([1; 16]).unwrap();
        assert!(recreated.is_current());
        assert!(!old.is_current());
        drop((old, twin, current, recreated));
        revisions.prune();
        assert!(revisions.entries.is_empty());
    }

    #[test]
    fn observations_are_bounded_and_release_capacity() {
        let mut revisions = BindingRevisions::new(2);
        let first = revisions.capture([1; 16]).unwrap();
        let second = revisions.capture([2; 16]).unwrap();
        assert!(revisions.capture([3; 16]).is_none());
        drop(first);
        let third = revisions.capture([3; 16]).unwrap();
        assert!(second.is_current() && third.is_current());
        assert_eq!(revisions.entries.len(), 2);
    }

    #[test]
    fn exhausted_generation_refuses_changes_but_can_invalidate() {
        let mut revisions = BindingRevisions::new(2);
        let old = revisions.capture([1; 16]).unwrap();
        revisions.next = u64::MAX;
        let last = revisions.reserve_change().unwrap();
        revisions.commit([1; 16], last);
        assert!(!old.is_current());
        assert!(revisions.reserve_change().is_none());
        assert!(revisions.capture([1; 16]).is_none());
        revisions.invalidate([1; 16]);
        assert!(!old.is_current());
        assert_eq!(old.state.load(Ordering::Relaxed), 0);
    }
}
