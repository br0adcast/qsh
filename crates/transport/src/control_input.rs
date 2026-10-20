//! Bounded retained control input, including the one record awaiting admission.

use crate::shell_frame::{RawRecord, CONTROL_RECORD_MAX};
use std::collections::VecDeque;

pub(super) const INPUT_LIMIT: usize = crate::reliability::STREAM_WINDOW as usize;
const HEADER: usize = 1 + 4;

#[derive(Default)]
pub(super) struct ControlInput {
    encoded: VecDeque<u8>,
    pending: Option<RawRecord>,
    held: usize,
    overflowed: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct Overflow {
    pub(super) dropped: usize,
}

impl ControlInput {
    /// Return immediately dropped bytes after framing became untrustworthy.
    /// A capacity error returns the incoming allocation without appending it.
    pub(super) fn push(&mut self, bytes: Vec<u8>) -> Result<usize, Vec<u8>> {
        if self.overflowed {
            return Ok(bytes.len());
        }
        let Some(total) = self.held.checked_add(bytes.len()) else {
            return Err(bytes);
        };
        if total > INPUT_LIMIT {
            return Err(bytes);
        }
        self.held = total;
        self.encoded.extend(bytes);
        Ok(0)
    }

    /// Materialize at most one complete record. Peeking again retains the same
    /// pending object; no credit is returned until its admission completes.
    pub(super) fn peek(&mut self) -> Result<Option<&RawRecord>, Overflow> {
        if self.pending.is_none() && !self.overflowed && self.encoded.len() >= HEADER {
            let mut header = [0; HEADER];
            for (slot, byte) in header.iter_mut().zip(self.encoded.iter()) {
                *slot = *byte;
            }
            let len = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
            if len > CONTROL_RECORD_MAX {
                let dropped = self.held;
                self.encoded = VecDeque::new();
                self.held = 0;
                self.overflowed = true;
                return Err(Overflow { dropped });
            }
            if self.encoded.len() >= HEADER + len {
                drop(self.encoded.drain(..HEADER));
                self.pending = Some(RawRecord {
                    kind: header[0],
                    payload: self.encoded.drain(..len).collect(),
                });
            }
        }
        Ok(self.pending.as_ref())
    }

    pub(super) fn complete(&mut self) -> Option<(RawRecord, usize)> {
        let record = self.pending.take()?;
        let consumed = HEADER + record.payload.len();
        self.held -= consumed;
        Some((record, consumed))
    }

    pub(super) fn held(&self) -> usize {
        self.held
    }

    /// Settle all old-generation input once, including its decoded record.
    pub(super) fn reset(&mut self) -> usize {
        let dropped = self.held;
        *self = Self::default();
        dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::{encode_client, ClientRecord};
    use crate::shell_frame::encode_record;

    #[test]
    fn capacity_input_pending_record_counts_toward_the_whole_receive_window() {
        let mut input = ControlInput::default();
        let first = encode_record(0xfe, &vec![0; CONTROL_RECORD_MAX]);
        input.push(first.clone()).unwrap();
        assert!(input.peek().unwrap().is_some());
        let about = encode_client(&ClientRecord::AboutRequest);
        let extra: Vec<_> = (0..INPUT_LIMIT - first.len() + 1)
            .map(|i| about[i % about.len()])
            .collect();
        let rejected = match input.push(extra) {
            Err(bytes) => bytes,
            Ok(_) => panic!("pending payload escaped the total input limit"),
        };
        assert_eq!(input.held(), first.len());
        assert_eq!(input.complete().unwrap().1, first.len());
        assert!(
            input.push(rejected).is_ok(),
            "settled credit is reusable once"
        );
        assert_eq!(input.held(), INPUT_LIMIT - first.len() + 1);
    }

    #[test]
    fn capacity_input_fragmented_maximum_record_returns_credit_only_on_completion() {
        let mut input = ControlInput::default();
        let record = encode_record(0xfe, &vec![b'a'; CONTROL_RECORD_MAX]);
        input.push(record[..3].to_vec()).unwrap();
        assert!(input.peek().unwrap().is_none());
        assert_eq!(input.held(), 3);
        input.push(record[3..].to_vec()).unwrap();
        let raw = input.peek().unwrap().unwrap();
        assert_eq!(raw.kind, 0xfe);
        assert_eq!(raw.payload, vec![b'a'; CONTROL_RECORD_MAX]);
        assert_eq!(input.held(), record.len());
        assert_eq!(input.complete().unwrap().1, record.len());
        assert_eq!(input.held(), 0);
        assert!(input.complete().is_none());
    }

    #[test]
    fn capacity_input_reset_settles_pending_and_partial_old_generation_once() {
        let mut input = ControlInput::default();
        let about = encode_client(&ClientRecord::AboutRequest);
        let mut bytes = about.repeat(128);
        bytes.extend_from_slice(&about[..2]);
        input.push(bytes.clone()).unwrap();
        input.peek().unwrap();
        assert_eq!(input.complete().unwrap().1, about.len());
        input.peek().unwrap();
        assert_eq!(input.reset(), bytes.len() - about.len());
        assert_eq!(input.reset(), 0);
        input.push(about.clone()).unwrap();
        assert_eq!(input.peek().unwrap().unwrap().kind, about[0]);
        assert_eq!(input.complete().unwrap().1, about.len());
    }

    #[test]
    fn capacity_input_oversize_header_preserves_existing_stop_framing_semantics() {
        let mut input = ControlInput::default();
        let about = encode_client(&ClientRecord::AboutRequest);
        let mut bytes = vec![0xfe];
        bytes.extend_from_slice(&((CONTROL_RECORD_MAX + 1) as u32).to_be_bytes());
        bytes.extend_from_slice(&about);
        input.push(bytes.clone()).unwrap();
        assert_eq!(
            input.peek(),
            Err(Overflow {
                dropped: bytes.len()
            })
        );
        assert_eq!(input.held(), 0);
        assert_eq!(input.push(about.clone()).unwrap(), about.len());
        assert!(input.peek().unwrap().is_none());
        assert_eq!(input.reset(), 0);
        input.push(about).unwrap();
        assert!(input.peek().unwrap().is_some());
    }

    #[test]
    fn capacity_input_repeated_peeks_materialize_only_one_record() {
        let mut input = ControlInput::default();
        let about = encode_client(&ClientRecord::AboutRequest);
        input.push(about.repeat(128)).unwrap();
        assert!(input.peek().unwrap().is_some());
        let tail = input.encoded.len();
        assert!(input.peek().unwrap().is_some());
        assert_eq!(input.encoded.len(), tail);
        assert_eq!(input.held(), 128 * about.len());
        assert_eq!(input.complete().unwrap().1, about.len());
        assert_eq!(input.held(), 127 * about.len());
    }
}
