//! Bounded admission envelope; raw credit spending is not whole-batch delivery.
use transport::qualification305::Snapshot;
pub const BATCH: u64 = 8192;
pub const MAX_GRANTS: u16 = 96;
#[derive(Default)]
pub struct Pace {
    pub grants: u16,
    last_sequence: u64,
    baseline: Option<u64>,
    final_grant: bool,
}
impl Pace {
    pub fn grant(&mut self, s: Snapshot) -> Result<bool, &'static str> {
        if !s.values_available || !s.valid || s.retired || s.sequence <= self.last_sequence {
            return Ok(false);
        }
        self.last_sequence = s.sequence;
        let Some(credit) = s.credit_remaining else {
            return Ok(false);
        };
        if credit == 0 || self.final_grant {
            return Ok(false);
        }
        if !s.gate_byte_open
            || s.gate_closed
            || s.gate_metadata_blocked
            || s.source_pending != 0
            || s.reliable_tail > transport::send_gate::SCREEN_LOW
        {
            return Ok(false);
        }
        if self
            .baseline
            .is_some_and(|before| before.saturating_sub(credit) < BATCH)
        {
            return Ok(false);
        }
        if self.grants >= MAX_GRANTS {
            return Err("Screen grant cap reached without blocked witness");
        }
        self.grants += 1;
        self.baseline = Some(credit);
        self.final_grant = credit < BATCH;
        Ok(true)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    fn sample(sequence: u64, credit: Option<u64>) -> Snapshot {
        Snapshot {
            values_available: true,
            valid: true,
            sequence,
            credit_remaining: credit,
            gate_byte_open: true,
            offset_room: 100,
            ..Default::default()
        }
    }
    #[test]
    fn qualification305_pacing_uses_fresh_credit_lowwater_not_metadata_or_raw_chunks() {
        let mut pace = Pace::default();
        assert!(pace.grant(sample(1, Some(BATCH * 4))).unwrap());
        for s in [
            sample(1, Some(BATCH * 2)),
            sample(2, Some(BATCH * 4 - 13)),
            sample(3, Some(BATCH * 5)),
            sample(4, None),
        ] {
            assert!(!pace.grant(s).unwrap());
        }
        assert!(pace.grant(sample(5, Some(BATCH * 3))).unwrap());
        assert_eq!(pace.grants, 2);
        assert!(!pace.grant(sample(6, Some(BATCH * 3))).unwrap());
        assert!(!pace.grant(sample(7, Some(BATCH * 4))).unwrap());
        assert!(pace.grant(sample(8, Some(BATCH * 2))).unwrap());
        assert_eq!(pace.grants, 3);
    }
    #[test]
    fn qualification305_pacing_waits_for_effective_gate_and_source_settlement() {
        for changed in [
            Snapshot {
                gate_byte_open: false,
                ..sample(1, Some(BATCH * 2))
            },
            Snapshot {
                gate_closed: true,
                ..sample(1, Some(BATCH * 2))
            },
            Snapshot {
                gate_metadata_blocked: true,
                ..sample(1, Some(BATCH * 2))
            },
            Snapshot {
                source_pending: 1,
                ..sample(1, Some(BATCH * 2))
            },
            Snapshot {
                reliable_tail: transport::send_gate::SCREEN_LOW + 1,
                ..sample(1, Some(BATCH * 2))
            },
            Snapshot {
                valid: false,
                ..sample(1, Some(BATCH * 2))
            },
        ] {
            assert!(!Pace::default().grant(changed).unwrap());
        }
    }
    #[test]
    fn qualification305_pacing_caps_initial_grant_and_stops_after_final_partial_credit() {
        let mut pace = Pace::default();
        let credit = (u64::from(MAX_GRANTS) + 2) * BATCH;
        for i in 0..MAX_GRANTS {
            assert!(pace
                .grant(sample(
                    u64::from(i) + 1,
                    Some(credit - u64::from(i) * BATCH)
                ))
                .unwrap());
        }
        assert!(pace
            .grant(sample(u64::from(MAX_GRANTS) + 1, Some(BATCH)))
            .is_err());
        let mut last = Pace::default();
        assert!(last.grant(sample(1, Some(100))).unwrap());
        assert!(!last.grant(sample(2, Some(50))).unwrap());
        assert!(!last.grant(sample(3, Some(0))).unwrap());
        assert_eq!(last.grants, 1);
    }
}
