//! Finite fixture custody of original transport chunks; not an application queue.
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct Budget {
    used: Arc<AtomicUsize>,
    limit: usize,
}
pub struct Raw {
    stream: u8,
    sequence: u64,
    bytes: Vec<u8>,
    charged: Arc<AtomicUsize>,
    charge: usize,
}
impl Raw {
    pub fn stream(&self) -> u8 {
        self.stream
    }
}
impl Drop for Raw {
    fn drop(&mut self) {
        self.charged.fetch_sub(self.charge, Ordering::AcqRel);
    }
}
impl Budget {
    pub fn new(limit: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            limit,
        }
    }
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }
    pub fn chunk(&self, stream: u8, sequence: u64, bytes: Vec<u8>) -> Result<Raw, Vec<u8>> {
        let n = bytes.len();
        if n == 0
            || self
                .used
                .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                    used.checked_add(n).filter(|next| *next <= self.limit)
                })
                .is_err()
        {
            return Err(bytes);
        }
        Ok(Raw {
            stream,
            sequence,
            bytes,
            charged: self.used.clone(),
            charge: n,
        })
    }
}
pub struct Hold {
    stream: u8,
    limit: usize,
    entries: usize,
    bytes: usize,
    fifo: VecDeque<Raw>,
}
impl Hold {
    pub fn new(stream: u8, limit: usize, entries: usize) -> Self {
        Self {
            stream,
            limit,
            entries,
            bytes: 0,
            fifo: VecDeque::new(),
        }
    }
    pub fn push(&mut self, raw: Raw) -> Result<(), Raw> {
        let Some(next) = self.bytes.checked_add(raw.bytes.len()) else {
            return Err(raw);
        };
        if raw.stream != self.stream || next > self.limit || self.fifo.len() >= self.entries {
            return Err(raw);
        }
        self.bytes = next;
        self.fifo.push_back(raw);
        Ok(())
    }
    pub fn pop(&mut self) -> Option<Raw> {
        let raw = self.fifo.pop_front()?;
        self.bytes -= raw.bytes.len();
        Some(raw)
    }
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}
pub struct Ledger {
    next: [u64; 256],
    pub processed_bytes: u64,
    pub processed_chunks: u64,
}
impl Default for Ledger {
    fn default() -> Self {
        Self {
            next: [0; 256],
            processed_bytes: 0,
            processed_chunks: 0,
        }
    }
}
impl Ledger {
    pub fn process(
        &mut self,
        raw: Raw,
        decode: impl FnOnce(u8, &[u8]) -> Result<(), String>,
        consumed: impl FnOnce(u8, usize),
    ) -> Result<(), String> {
        let expected = &mut self.next[usize::from(raw.stream)];
        if raw.sequence != *expected {
            return Err("duplicate or missing original transport chunk".into());
        }
        let next = expected.checked_add(1).ok_or("chunk sequence overflow")?;
        decode(raw.stream, &raw.bytes)?;
        consumed(raw.stream, raw.bytes.len());
        *expected = next;
        self.processed_bytes += raw.bytes.len() as u64;
        self.processed_chunks += 1;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn qualification305_raw_framed_chunks_are_consumed_once_in_fifo_order() {
        let budget = Budget::new(100);
        let mut held = Hold::new(18, 100, 4);
        let fragments = [vec![1, 0], vec![0, 0, 3, b'A'], vec![b'B', b'C']];
        for (sequence, bytes) in fragments.iter().enumerate() {
            assert!(held
                .push(
                    budget
                        .chunk(18, sequence as u64, bytes.clone())
                        .ok()
                        .unwrap()
                )
                .is_ok());
        }
        let original = budget.used();
        assert_eq!(held.bytes(), original);
        let mut ledger = Ledger::default();
        let mut decoded = Vec::new();
        let mut consumed = Vec::new();
        while let Some(raw) = held.pop() {
            ledger
                .process(
                    raw,
                    |_, bytes| {
                        decoded.extend_from_slice(bytes);
                        Ok(())
                    },
                    |stream, n| consumed.push((stream, n)),
                )
                .unwrap();
        }
        assert_eq!(decoded, fragments.concat());
        assert_eq!(consumed, vec![(18, 2), (18, 4), (18, 2)]);
        assert_eq!(ledger.processed_bytes, 8);
        assert_eq!(budget.used(), 0);
        assert_eq!(held.bytes(), 0);
        assert!(ledger
            .process(
                budget.chunk(18, 2, vec![9]).ok().unwrap(),
                |_, _| panic!("duplicate decode"),
                |_, _| panic!("duplicate consumption")
            )
            .is_err());
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn qualification305_caps_return_the_original_owner_and_teardown_refunds() {
        let budget = Budget::new(5);
        let bytes = vec![1; 6];
        let ptr = bytes.as_ptr();
        let rejected = budget.chunk(18, 0, bytes).err().unwrap();
        assert_eq!(rejected.as_ptr(), ptr);
        assert_eq!(budget.used(), 0);
        let mut hold = Hold::new(18, 4, 1);
        let first = budget.chunk(18, 0, vec![2; 3]).ok().unwrap();
        let ptr = first.bytes.as_ptr();
        assert!(hold.push(first).is_ok());
        let second = budget.chunk(18, 1, vec![3; 2]).ok().unwrap();
        let rejected = hold.push(second).err().unwrap();
        assert_eq!(budget.used(), 5);
        drop(rejected);
        assert_eq!(budget.used(), 3);
        assert_eq!(hold.pop().unwrap().bytes.as_ptr(), ptr);
        assert_eq!(budget.used(), 0);
        assert!(hold
            .push(budget.chunk(18, 1, vec![4; 3]).ok().unwrap())
            .is_ok());
        drop(hold);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn qualification305_other_streams_progress_while_screen_is_held() {
        let budget = Budget::new(50);
        let mut hold = Hold::new(18, 20, 4);
        let mut ledger = Ledger::default();
        let mut order = Vec::new();
        assert!(hold
            .push(budget.chunk(18, 0, vec![b'S']).ok().unwrap())
            .is_ok());
        for stream in [16, 17] {
            ledger
                .process(
                    budget.chunk(stream, 0, vec![stream]).ok().unwrap(),
                    |stream, _| {
                        order.push(stream);
                        Ok(())
                    },
                    |_, _| {},
                )
                .unwrap();
        }
        assert_eq!(order, vec![16, 17]);
        assert_eq!(budget.used(), 1);
        ledger
            .process(
                hold.pop().unwrap(),
                |stream, _| {
                    order.push(stream);
                    Ok(())
                },
                |_, _| {},
            )
            .unwrap();
        assert_eq!(order, vec![16, 17, 18]);
        assert_eq!(budget.used(), 0);
    }
    #[test]
    fn qualification305_decode_failure_never_acknowledges_unprocessed_bytes() {
        let budget = Budget::new(10);
        let mut ledger = Ledger::default();
        assert!(ledger
            .process(
                budget.chunk(18, 0, vec![1, 2]).ok().unwrap(),
                |_, _| Err("injected".into()),
                |_, _| panic!("failed decode consumed")
            )
            .is_err());
        assert_eq!(ledger.processed_bytes, 0);
        assert_eq!(budget.used(), 0);
    }
}

#[cfg(test)]
mod bound_tests {
    use super::*;
    #[test]
    fn qualification305_entry_byte_stream_and_sequence_fences_are_independent() {
        let budget = Budget::new(100);
        let mut entries = Hold::new(18, 100, 1);
        assert!(entries
            .push(budget.chunk(18, 0, vec![1]).ok().unwrap())
            .is_ok());
        assert!(entries
            .push(budget.chunk(18, 1, vec![2]).ok().unwrap())
            .is_err());
        let mut bytes = Hold::new(18, 3, 4);
        assert!(bytes
            .push(budget.chunk(18, 0, vec![1, 2]).ok().unwrap())
            .is_ok());
        assert!(bytes
            .push(budget.chunk(18, 1, vec![3, 4]).ok().unwrap())
            .is_err());
        assert!(bytes
            .push(budget.chunk(17, 0, vec![5]).ok().unwrap())
            .is_err());
        let mut ledger = Ledger::default();
        assert!(ledger
            .process(
                budget.chunk(19, 1, vec![7]).ok().unwrap(),
                |_, _| panic!("missing prefix decoded"),
                |_, _| panic!("missing prefix consumed")
            )
            .is_err());
        drop(entries);
        drop(bytes);
        assert_eq!(budget.used(), 0);
    }
}
