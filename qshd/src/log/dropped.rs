//! A count of log records a full queue had no room for, owed as a report
//! of its own (the session owner's and the frontend's queues to the host).

use std::sync::atomic::{AtomicU64, Ordering};

/// Records that had no room, not yet reported. Whoever reports the count
/// takes it whole ([`DroppedRecords::take`]), so records and reports racing
/// each other never count a record twice, and the count never wraps.
#[derive(Debug, Default)]
pub(crate) struct DroppedRecords(AtomicU64);

impl DroppedRecords {
    /// `n` more records had no room.
    pub(crate) fn add(&self, n: u64) {
        // A compare-exchange loop rather than `fetch_update`, which newer
        // toolchains deprecate in favor of a name the supported one lacks.
        let mut owed = self.0.load(Ordering::SeqCst);
        loop {
            match self.0.compare_exchange_weak(
                owed,
                owed.saturating_add(n),
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => break,
                Err(now) => owed = now,
            }
        }
    }

    /// What is owed, taken: zero until more records are dropped.
    pub(crate) fn take(&self) -> u64 {
        self.0.swap(0, Ordering::SeqCst)
    }

    /// Report what is owed through `send`, if anything is. `false` when
    /// `send` refused the report: the count is owed again.
    pub(crate) fn report(&self, send: impl FnOnce(u64) -> bool) -> bool {
        match self.take() {
            0 => true,
            n if send(n) => true,
            n => {
                self.add(n);
                false
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn owed(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused report leaves the count owed, an accepted one takes it,
    /// and nothing is reported while nothing is owed.
    #[test]
    fn a_refused_report_is_owed_again_and_an_accepted_one_is_taken() {
        let dropped = DroppedRecords::default();
        assert!(dropped.report(|_| panic!("nothing is owed")));
        dropped.add(3);
        assert!(!dropped.report(|n| {
            assert_eq!(n, 3);
            false
        }));
        assert_eq!(dropped.owed(), 3);
        dropped.add(1);
        let mut reported = 0;
        assert!(dropped.report(|n| {
            reported = n;
            true
        }));
        assert_eq!((reported, dropped.owed()), (4, 0));
    }

    /// The count stops at its top rather than wrapping to a small number.
    #[test]
    fn the_count_saturates_instead_of_wrapping() {
        let dropped = DroppedRecords::default();
        dropped.add(u64::MAX - 1);
        dropped.add(5);
        assert_eq!(dropped.take(), u64::MAX);
        assert_eq!(dropped.take(), 0);
    }
}
