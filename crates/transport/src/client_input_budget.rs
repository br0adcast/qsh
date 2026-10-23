//! Owned client-input admission, independent of connection/ACK scheduling.
//!
//! Lengths here include every encoded application-record byte handed to the
//! driver. The two payload phases cover an owned pending vector and the
//! reliable sender's copy. Stream-frame/packet scratch and sender segment
//! metadata have separate finite transport bounds; these counters are not RSS.

use std::sync::{Arc, Mutex};

pub const INPUT_BYTES: usize = crate::conn::SEND_HARD_CAP;
pub const INPUT_ENTRIES: usize = INPUT_BYTES / 4096;

#[derive(Clone, Debug)]
pub struct ClientInputBudget(Arc<Mutex<State>>);

#[derive(Debug)]
struct State {
    bytes: usize,
    entries: usize,
    storage: usize,
    limit: usize,
    entry_limit: usize,
}

impl Default for ClientInputBudget {
    fn default() -> Self {
        Self::with_limits(INPUT_BYTES, INPUT_ENTRIES)
    }
}

impl ClientInputBudget {
    pub(crate) fn with_limits(limit: usize, entry_limit: usize) -> Self {
        Self(Arc::new(Mutex::new(State {
            bytes: 0,
            entries: 0,
            storage: 0,
            limit,
            entry_limit,
        })))
    }

    #[cfg(test)]
    pub(crate) fn reserve(&self, bytes: usize) -> Result<Option<InputPermit>, ()> {
        self.reserve_owned(bytes, bytes)
    }

    /// Reserve a complete already-encoded record, before queue publication.
    /// Empty input creates no retained obligation and needs no nonexistent ACK.
    pub(crate) fn reserve_owned(
        &self,
        bytes: usize,
        capacity: usize,
    ) -> Result<Option<InputPermit>, ()> {
        if bytes == 0 {
            return Ok(None);
        }
        let storage = capacity.checked_add(bytes).ok_or(())?;
        let mut state = self.0.lock().expect("client input budget");
        if capacity < bytes
            || bytes > state.limit.saturating_sub(state.bytes)
            || storage > (2 * state.limit).saturating_sub(state.storage)
            || state.entries == state.entry_limit
        {
            return Err(());
        }
        state.bytes += bytes;
        state.entries += 1;
        state.storage += storage;
        drop(state);
        Ok(Some(InputPermit {
            budget: self.clone(),
            bytes,
            storage,
        }))
    }

    #[cfg(test)]
    pub(crate) fn usage(&self) -> (usize, usize, usize) {
        let state = self.0.lock().unwrap();
        (state.bytes, state.entries, state.storage)
    }
}

/// One non-cloneable record obligation. Moving it between producer, command,
/// pending source and ACK custody never refunds it. The actual owner drops it
/// only after rejection, validated ACK or destruction of its connection.
#[derive(Debug)]
pub(crate) struct InputPermit {
    budget: ClientInputBudget,
    bytes: usize,
    storage: usize,
}

impl InputPermit {
    pub(crate) fn len(&self) -> usize {
        self.bytes
    }
}

impl Drop for InputPermit {
    fn drop(&mut self) {
        let mut state = self.budget.0.lock().expect("client input budget");
        state.bytes -= self.bytes;
        state.entries -= 1;
        state.storage -= self.storage;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;
    use std::thread;

    #[test]
    fn whole_rejection_preserves_bytes_and_entries_without_partial_debit() {
        let budget = ClientInputBudget::with_limits(10, 3);
        let first = budget.reserve(7).unwrap().unwrap();
        assert!(budget.reserve(4).is_err());
        assert_eq!(budget.usage(), (7, 1, 14));
        let second = budget.reserve(3).unwrap().unwrap();
        assert!(budget.reserve(1).is_err());
        assert_eq!(budget.usage(), (10, 2, 20));
        drop(first);
        assert_eq!(budget.usage(), (3, 1, 6));
        drop(second);
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    #[test]
    fn tiny_records_reach_independent_entry_limit_and_empty_input_is_free() {
        let budget = ClientInputBudget::with_limits(1000, 2);
        let records = [budget.reserve(1).unwrap(), budget.reserve(1).unwrap()];
        assert!(budget.reserve(1).is_err());
        assert!(budget.reserve(0).unwrap().is_none());
        assert_eq!(budget.usage(), (2, 2, 4));
        drop(records);
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    #[test]
    fn retired_owner_stays_charged_until_its_final_permit_is_destroyed() {
        let old = ClientInputBudget::with_limits(10, 1);
        let new = old.clone();
        let held = old.reserve(8).unwrap().unwrap();
        drop(old);
        assert!(new.reserve(1).is_err());
        assert_eq!(new.usage(), (8, 1, 16));
        drop(held);
        let next = new.reserve(10).unwrap().unwrap();
        assert_eq!(new.usage(), (10, 1, 20));
        drop(next);
        assert_eq!(new.usage(), (0, 0, 0));
    }

    #[test]
    fn concurrent_producers_reserve_whole_records_under_one_shared_limit() {
        let budget = ClientInputBudget::with_limits(7, 2);
        let start = Arc::new(Barrier::new(3));
        let keep = Arc::new(Barrier::new(3));
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let (budget, start, keep) = (budget.clone(), start.clone(), keep.clone());
                thread::spawn(move || {
                    start.wait();
                    let permit = budget.reserve(4);
                    keep.wait();
                    permit
                })
            })
            .collect();
        start.wait();
        keep.wait();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(budget.usage(), (4, 1, 8));
        drop(results);
        assert_eq!(budget.usage(), (0, 0, 0));
    }

    #[test]
    fn source_backing_and_reliable_copy_have_independent_storage_charge() {
        let budget = ClientInputBudget::with_limits(10, 3);
        let held = budget.reserve_owned(2, 12).unwrap().unwrap();
        assert_eq!(budget.usage(), (2, 1, 14));
        assert!(budget.reserve_owned(4, 4).is_err());
        assert!(budget.reserve_owned(1, 1000).is_err());
        assert!(budget.reserve_owned(0, 1000).unwrap().is_none());
        assert_eq!(budget.usage(), (2, 1, 14));
        drop(held);
        assert_eq!(budget.usage(), (0, 0, 0));
    }
}
