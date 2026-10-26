//! Owned keyboard ingress and provenance through bounded parser buffers.
//!
//! Counters cover unique reads, logical source bytes and raw source capacity.
//! Parser/action copies have a separate four-phase content allowance; these
//! counters are not an allocator or RSS measurement. Range provenance keeps a
//! suffix from retaining already-consumed reads during continuous input.
//! Nonempty source permits are byte-bounded (at most INGRESS_BYTES owners),
//! rather than limited by historical read count. Recovery additionally owns
//! one independent 64 KiB FIFO allocation/lease per Session, including actions.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::{Arc, Mutex};

pub const INGRESS_BYTES: usize = 64 * 1024;
pub const READ_BYTES: usize = 4096;

#[derive(Clone, Debug)]
pub struct IngressBudget(Arc<Mutex<State>>);

#[derive(Debug)]
struct State {
    bytes: usize,
    reads: usize,
    capacity: usize,
    byte_limit: usize,
}

impl Default for IngressBudget {
    fn default() -> Self {
        Self::with_limit(INGRESS_BYTES)
    }
}

#[derive(Debug)]
pub struct IngressFull {
    pub bytes: Vec<u8>,
}

/// One FIFO pressure fence. The reader holds one fixed scratch read and waits
/// for this acknowledgement before publishing any newer keyboard event.
#[derive(Debug)]
pub struct IngressBlocked(Arc<BlockedRead>);
#[derive(Debug)]
struct BlockedRead {
    budget: IngressBudget,
    bytes: usize,
    reply: Mutex<Option<Reply>>,
}
#[derive(Debug)]
struct Reply {
    sender: Option<std::sync::mpsc::SyncSender<bool>>,
    wake: Option<crate::input_wake::WakeSender>,
}
impl Reply {
    fn send(mut self, value: bool) {
        if let Some(sender) = self.sender.take() {
            let _ = sender.send(value);
        }
    }
}
impl Drop for Reply {
    fn drop(&mut self) {
        // Disconnect must be observable before the wake, including when the
        // last marker is dropped without ever resolving its pressure fence.
        drop(self.sender.take());
        if let Some(wake) = self.wake.take() {
            let _ = wake.notify();
        }
    }
}
impl PartialEq for IngressBlocked {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for IngressBlocked {}
impl IngressBlocked {
    pub fn channel(budget: IngressBudget, bytes: usize) -> (Self, std::sync::mpsc::Receiver<bool>) {
        Self::channel_inner(budget, bytes, None)
    }

    #[doc(hidden)]
    pub fn channel_notified(
        budget: IngressBudget,
        bytes: usize,
        wake: crate::input_wake::WakeSender,
    ) -> (Self, std::sync::mpsc::Receiver<bool>) {
        Self::channel_inner(budget, bytes, Some(wake))
    }

    fn channel_inner(
        budget: IngressBudget,
        bytes: usize,
        wake: Option<crate::input_wake::WakeSender>,
    ) -> (Self, std::sync::mpsc::Receiver<bool>) {
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        (
            Self(Arc::new(BlockedRead {
                budget,
                bytes,
                reply: Mutex::new(Some(Reply {
                    sender: Some(tx),
                    wake,
                })),
            })),
            rx,
        )
    }

    /// Called only after the UI has processed this marker's published prefix.
    /// No budget mutex is held while acknowledging or waiting for the reader.
    pub fn resolve(&self) -> bool {
        let available = self.0.budget.can_admit(self.0.bytes);
        let reply = self.0.reply.lock().expect("ingress acknowledgement").take();
        if let Some(reply) = reply {
            reply.send(available);
        }
        available
    }
}

impl IngressBudget {
    fn with_limit(byte_limit: usize) -> Self {
        Self(Arc::new(Mutex::new(State {
            bytes: 0,
            reads: 0,
            capacity: 0,
            byte_limit,
        })))
    }

    fn can_admit(&self, bytes: usize) -> bool {
        let state = self.0.lock().expect("keyboard ingress budget");
        bytes <= state.byte_limit.saturating_sub(state.bytes)
            && bytes <= state.byte_limit.saturating_sub(state.capacity)
    }

    fn reserve(&self, bytes: usize, capacity: usize) -> Option<Arc<ReadPermit>> {
        let mut state = self.0.lock().expect("keyboard ingress budget");
        if bytes > state.byte_limit.saturating_sub(state.bytes)
            || capacity > state.byte_limit.saturating_sub(state.capacity)
        {
            return None;
        }
        state.bytes += bytes;
        state.capacity += capacity;
        state.reads += 1;
        drop(state);
        Some(Arc::new(ReadPermit {
            budget: self.clone(),
            bytes,
            capacity,
        }))
    }

    /// The reader calls this on its fixed stack scratch, before heap copying.
    pub fn admit_slice(&self, bytes: &[u8]) -> Result<InputBytes, IngressFull> {
        if bytes.is_empty() {
            return Ok(InputBytes::default());
        }
        let permit = self
            .reserve(bytes.len(), bytes.len())
            .ok_or_else(|| IngressFull { bytes: Vec::new() })?;
        let data = bytes.to_vec();
        // Do not publish an allocation larger than the reserved source phase.
        if data.capacity() > permit.capacity {
            return Err(IngressFull { bytes: data });
        }
        Ok(InputBytes::admitted(data, permit))
    }

    /// An already-owned producer receives its complete unchanged allocation
    /// back on rejection. Empty input retains neither allocation nor lease.
    pub fn admit_owned(&self, bytes: Vec<u8>) -> Result<InputBytes, IngressFull> {
        if bytes.is_empty() {
            return Ok(InputBytes::default());
        }
        let Some(permit) = self.reserve(bytes.len(), bytes.capacity()) else {
            return Err(IngressFull { bytes });
        };
        Ok(InputBytes::admitted(bytes, permit))
    }

    pub fn usage(&self) -> (usize, usize, usize) {
        let state = self.0.lock().expect("keyboard ingress budget");
        (state.bytes, state.reads, state.capacity)
    }
}

#[derive(Debug)]
struct ReadPermit {
    budget: IngressBudget,
    bytes: usize,
    capacity: usize,
}
impl Drop for ReadPermit {
    fn drop(&mut self) {
        let mut state = self.budget.0.lock().expect("keyboard ingress budget");
        state.bytes -= self.bytes;
        state.reads -= 1;
        state.capacity -= self.capacity;
    }
}

/// Shared custody is deduplicated by actual permit identity, never reissued.
#[derive(Clone, Debug, Default)]
struct Owners(Option<Arc<Vec<Arc<ReadPermit>>>>);
impl Owners {
    fn one(permit: Arc<ReadPermit>) -> Self {
        Self(Some(Arc::new(vec![permit])))
    }
    fn same(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (None, None) => true,
            (Some(a), Some(b)) => {
                Arc::ptr_eq(a, b)
                    || (a.len() == b.len()
                        && a.iter().zip(b.iter()).all(|(a, b)| Arc::ptr_eq(a, b)))
            }
            _ => false,
        }
    }
    fn extend_unique(&self, into: &mut BTreeMap<usize, Arc<ReadPermit>>) {
        if let Some(owners) = &self.0 {
            for owner in owners.iter() {
                into.entry(Arc::as_ptr(owner) as usize)
                    .or_insert_with(|| owner.clone());
            }
        }
    }
}

#[derive(Debug)]
struct Span {
    end: usize,
    owners: Owners,
}

#[derive(Debug, Default)]
struct Sources {
    len: usize,
    spans: Vec<Span>,
}
impl Sources {
    fn push(&mut self, len: usize, owners: Owners) {
        if len == 0 {
            return;
        }
        self.len += len;
        if let Some(last) = self
            .spans
            .last_mut()
            .filter(|last| last.owners.same(&owners))
        {
            last.end = self.len;
        } else {
            self.spans.push(Span {
                end: self.len,
                owners,
            });
        }
    }
    fn append(&mut self, other: Self) {
        let mut start = 0;
        for span in other.spans {
            self.push(span.end - start, span.owners);
            start = span.end;
        }
    }
    fn slice(&self, range: Range<usize>) -> Self {
        assert!(range.start <= range.end && range.end <= self.len);
        let mut out = Self::default();
        let first = self.spans.partition_point(|span| span.end <= range.start);
        let mut start = first.checked_sub(1).map_or(0, |i| self.spans[i].end);
        for span in &self.spans[first..] {
            if start >= range.end {
                break;
            }
            let len = span.end.min(range.end) - start.max(range.start);
            out.push(len, span.owners.clone());
            start = span.end;
        }
        out
    }
    fn owners(&self) -> Owners {
        let mut owners = BTreeMap::new();
        for span in &self.spans {
            span.owners.extend_unique(&mut owners);
        }
        if owners.is_empty() {
            Owners::default()
        } else {
            Owners(Some(Arc::new(owners.into_values().collect())))
        }
    }
}

/// Compact recovery FIFO. Its single allocation has a separate per-session
/// reservation, retained by emitted actions until their final aliases drop.
/// Original ingress guards are released only by their ordinary owners.
#[derive(Debug, Default)]
pub(crate) struct PendingInput {
    bytes: Vec<u8>,
    permit: Option<Arc<ReadPermit>>,
}
impl PartialEq for PendingInput {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Eq for PendingInput {}
impl PendingInput {
    pub(crate) fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub(crate) fn append(&mut self, input: &InputBytes, budget: &IngressBudget) -> Result<(), ()> {
        if input.len() > INGRESS_BYTES.saturating_sub(self.bytes.len()) {
            return Err(());
        }
        if input.is_empty() {
            return Ok(());
        }
        if self.permit.is_none() {
            let permit = budget.reserve(INGRESS_BYTES, INGRESS_BYTES).ok_or(())?;
            let bytes = Vec::with_capacity(INGRESS_BYTES);
            if bytes.capacity() > INGRESS_BYTES {
                return Err(());
            }
            self.bytes = bytes;
            self.permit = Some(permit);
        }
        self.bytes.extend_from_slice(input.as_slice());
        Ok(())
    }
    pub(crate) fn into_input(self) -> Option<InputBytes> {
        self.permit
            .map(|permit| InputBytes::admitted(self.bytes, permit))
    }
    #[cfg(test)]
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
}

/// Non-cloneable payload. Field order destroys storage before final custody.
/// Equality compares its value, while ownership is verified through counters.
#[derive(Debug, Default)]
pub struct InputBytes {
    bytes: Vec<u8>,
    sources: Sources,
}
impl PartialEq for InputBytes {
    fn eq(&self, other: &Self) -> bool {
        self.bytes == other.bytes
    }
}
impl Eq for InputBytes {}
impl InputBytes {
    fn admitted(bytes: Vec<u8>, permit: Arc<ReadPermit>) -> Self {
        let mut sources = Sources::default();
        sources.push(bytes.len(), Owners::one(permit));
        Self { bytes, sources }
    }
    /// Only standalone, borrowed parser helpers use this. Production stdin
    /// obtains its source through IngressBudget and retains it through parsing.
    pub(crate) fn unleased(bytes: Vec<u8>) -> Self {
        let mut sources = Sources::default();
        sources.push(bytes.len(), Owners::default());
        Self { bytes, sources }
    }
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }
    pub(crate) fn append(&mut self, mut other: Self) {
        self.bytes.append(&mut other.bytes);
        self.sources.append(other.sources);
    }
    pub(crate) fn copy_range(&self, range: Range<usize>) -> Self {
        Self {
            bytes: self.bytes[range.clone()].to_vec(),
            sources: self.sources.slice(range),
        }
    }
    pub(crate) fn origin(&self) -> InputOrigin {
        InputOrigin(self.sources.owners())
    }
    pub(crate) fn clear(&mut self) {
        *self = Self::default();
    }
    pub(crate) fn split_off(&mut self, at: usize) -> Self {
        let tail_sources = self.sources.slice(at..self.len());
        let head_sources = self.sources.slice(0..at);
        let bytes = self.bytes.split_off(at);
        self.sources = head_sources;
        Self {
            bytes,
            sources: tail_sources,
        }
    }
    pub(crate) fn into_vec(self) -> Vec<u8> {
        assert!(
            self.sources
                .spans
                .iter()
                .all(|span| span.owners.0.is_none()),
            "guarded parser output must retain custody"
        );
        self.bytes
    }
    #[cfg(test)]
    fn owner_count(&self) -> usize {
        self.sources.owners().0.map_or(0, |owners| owners.len())
    }
}
impl std::ops::Deref for InputBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

pub(crate) struct InputOrigin(Owners);
impl InputOrigin {
    pub(crate) fn derived(&self, bytes: Vec<u8>) -> InputBytes {
        let mut sources = Sources::default();
        sources.push(bytes.len(), self.0.clone());
        InputBytes { bytes, sources }
    }
}

#[derive(Default)]
pub(crate) struct InputBuilder {
    bytes: Vec<u8>,
    sources: Sources,
}
impl InputBuilder {
    pub(crate) fn original(&mut self, input: &InputBytes, range: Range<usize>) {
        self.bytes.extend_from_slice(&input.bytes[range.clone()]);
        self.sources.append(input.sources.slice(range));
    }
    pub(crate) fn derived(&mut self, bytes: &[u8], input: &InputBytes, range: Range<usize>) {
        self.bytes.extend_from_slice(bytes);
        self.sources
            .push(bytes.len(), input.sources.slice(range).owners());
    }
    pub(crate) fn finish(self) -> InputBytes {
        InputBytes {
            bytes: self.bytes,
            sources: self.sources,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    include!("input_ingress_tests.rs");
}
