//! Input admission shared by queued and writer-held chunks.
//!
//! One session budget must survive attachment changes and remain shared with
//! retired writers. Each installed channel instance receives a fresh channel
//! budget. Closing either budget prevents admission without refunding live
//! chunks. Queue removal alone never returns capacity.

use std::fmt;
use std::sync::{Arc, Mutex};

const NETWORK_BYTES: usize = 8 * 1024 * 1024;
const NETWORK_ITEMS: usize = 16_384;
const LOCAL_CHANNEL_BYTES: usize = 64 * 1024;
const LOCAL_SESSION_BYTES: usize = 512 * 1024;
const LOCAL_CHANNEL_ITEMS: usize = 64;
const LOCAL_SESSION_ITEMS: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputOrigin {
    Network,
    LocalReply,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputScope {
    Channel,
    Session,
}

/// Admission refusal contains no input bytes or terminal-controlled text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputLimit {
    Closed(InputScope),
    Bytes {
        origin: InputOrigin,
        scope: InputScope,
    },
    Items {
        origin: InputOrigin,
        scope: InputScope,
    },
}

#[derive(Clone, Copy)]
struct QuotaLimits {
    channel_bytes: usize,
    session_bytes: usize,
    channel_items: usize,
    session_items: usize,
}

#[derive(Clone, Copy)]
struct InputLimits {
    network: QuotaLimits,
    local: QuotaLimits,
}

impl Default for InputLimits {
    fn default() -> Self {
        Self {
            // The bridge pending cap is 8 MiB, and the stream window is 512 KiB.
            // This also admits an 8 MiB paste split into 512-byte chunks. Tiny
            // fragments may exhaust the item quota before the byte quota.
            network: QuotaLimits {
                channel_bytes: NETWORK_BYTES,
                session_bytes: NETWORK_BYTES,
                channel_items: NETWORK_ITEMS,
                session_items: NETWORK_ITEMS,
            },
            local: QuotaLimits {
                channel_bytes: LOCAL_CHANNEL_BYTES,
                session_bytes: LOCAL_SESSION_BYTES,
                channel_items: LOCAL_CHANNEL_ITEMS,
                session_items: LOCAL_SESSION_ITEMS,
            },
        }
    }
}

impl InputLimits {
    fn quota(self, origin: InputOrigin) -> QuotaLimits {
        match origin {
            InputOrigin::Network => self.network,
            InputOrigin::LocalReply => self.local,
        }
    }
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
struct QuotaUsage {
    bytes: usize,
    items: usize,
}

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
struct Usage {
    network: QuotaUsage,
    local: QuotaUsage,
}

impl Usage {
    fn quota_mut(&mut self, origin: InputOrigin) -> &mut QuotaUsage {
        match origin {
            InputOrigin::Network => &mut self.network,
            InputOrigin::LocalReply => &mut self.local,
        }
    }
}

#[derive(Default)]
struct State {
    closed: bool,
    usage: Usage,
}

struct Session {
    state: Mutex<State>,
    limits: InputLimits,
}

/// Aggregate quotas must be shared by all current and retired channel writers.
#[derive(Clone)]
pub struct SessionInputBudget(Arc<Session>);

impl Default for SessionInputBudget {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionInputBudget {
    pub fn new() -> Self {
        Self::with_limits(InputLimits::default())
    }

    fn with_limits(limits: InputLimits) -> Self {
        Self(Arc::new(Session {
            state: Mutex::default(),
            limits,
        }))
    }

    pub fn channel(&self) -> ChannelInputBudget {
        ChannelInputBudget {
            session: self.clone(),
            state: Arc::new(Mutex::default()),
        }
    }

    pub fn close(&self) {
        self.0.state.lock().unwrap().closed = true;
    }

    #[cfg(test)]
    fn usage(&self) -> Usage {
        self.0.state.lock().unwrap().usage
    }
}

/// Clones share the installed instance's quota and closed state.
#[derive(Clone)]
pub struct ChannelInputBudget {
    session: SessionInputBudget,
    state: Arc<Mutex<State>>,
}

impl ChannelInputBudget {
    pub fn try_network(&self, bytes: Vec<u8>) -> Result<Option<InputChunk>, InputLimit> {
        self.try_input(bytes, InputOrigin::Network)
    }

    pub fn try_local_reply(&self, bytes: Vec<u8>) -> Result<Option<InputChunk>, InputLimit> {
        self.try_input(bytes, InputOrigin::LocalReply)
    }

    fn try_input(
        &self,
        bytes: Vec<u8>,
        origin: InputOrigin,
    ) -> Result<Option<InputChunk>, InputLimit> {
        let len = bytes.len();
        let quota = self.session.0.limits.quota(origin);
        let permit = {
            // Admission and release always lock session before channel. Validate
            // all counters before changing either scope, including closed state.
            let mut session = self.session.0.state.lock().unwrap();
            let mut channel = self.state.lock().unwrap();
            if session.closed {
                return Err(InputLimit::Closed(InputScope::Session));
            }
            if channel.closed {
                return Err(InputLimit::Closed(InputScope::Channel));
            }
            if len == 0 {
                return Ok(None);
            }
            let session = session.usage.quota_mut(origin);
            let channel = channel.usage.quota_mut(origin);
            check(
                session,
                quota.session_bytes,
                quota.session_items,
                len,
                origin,
                InputScope::Session,
            )?;
            check(
                channel,
                quota.channel_bytes,
                quota.channel_items,
                len,
                origin,
                InputScope::Channel,
            )?;
            session.bytes += len;
            session.items += 1;
            channel.bytes += len;
            channel.items += 1;
            InputPermit {
                channel: self.clone(),
                origin,
                len,
            }
        };
        // Do not allocate/normalize before checking the limits. The owned permit
        // also refunds if a future fallible normalization unwinds. Keep no spare
        // Vec capacity beyond the charged length in a queued or held chunk.
        let bytes = bytes.into_boxed_slice().into_vec();
        Ok(Some(InputChunk { bytes, permit }))
    }

    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
    }

    #[cfg(test)]
    fn usage(&self) -> Usage {
        self.state.lock().unwrap().usage
    }
}

fn check(
    usage: &QuotaUsage,
    bytes: usize,
    items: usize,
    len: usize,
    origin: InputOrigin,
    scope: InputScope,
) -> Result<(), InputLimit> {
    if len > bytes.saturating_sub(usage.bytes) {
        return Err(InputLimit::Bytes { origin, scope });
    }
    if usage.items >= items {
        return Err(InputLimit::Items { origin, scope });
    }
    Ok(())
}

struct InputPermit {
    channel: ChannelInputBudget,
    origin: InputOrigin,
    len: usize,
}

impl Drop for InputPermit {
    fn drop(&mut self) {
        let mut session = self.channel.session.0.state.lock().unwrap();
        let mut channel = self.channel.state.lock().unwrap();
        for usage in [&mut session.usage, &mut channel.usage] {
            let quota = usage.quota_mut(self.origin);
            quota.bytes = quota
                .bytes
                .checked_sub(self.len)
                .expect("input byte accounting");
            quota.items = quota.items.checked_sub(1).expect("input item accounting");
        }
    }
}

/// A non-cloneable input payload whose reservation lasts through the actual write.
///
/// There is deliberately no method to extract the Vec and discard its permit.
pub struct InputChunk {
    bytes: Vec<u8>,
    permit: InputPermit,
}

impl InputChunk {
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn origin(&self) -> InputOrigin {
        self.permit.origin
    }

    /// Only received network bytes count toward transport consumption. Local
    /// replies must never advance input credit or echo acknowledgements.
    pub fn network_bytes(&self) -> usize {
        match self.origin() {
            InputOrigin::Network => self.bytes.len(),
            InputOrigin::LocalReply => 0,
        }
    }
}

impl fmt::Debug for InputChunk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InputChunk")
            .field("origin", &self.origin())
            .field("len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Write};
    use std::sync::{mpsc, Arc, Barrier};
    use std::time::Duration;

    fn small() -> SessionInputBudget {
        SessionInputBudget::with_limits(InputLimits {
            network: QuotaLimits {
                channel_bytes: 4,
                session_bytes: 4,
                channel_items: 2,
                session_items: 2,
            },
            local: QuotaLimits {
                channel_bytes: 3,
                session_bytes: 3,
                channel_items: 1,
                session_items: 1,
            },
        })
    }

    struct BlockedWriter {
        entered: mpsc::Sender<()>,
        release: mpsc::Receiver<()>,
    }
    impl Write for BlockedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.entered.send(()).unwrap();
            self.release.recv().unwrap();
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    struct Worker {
        release: Option<mpsc::Sender<()>>,
        join: Option<std::thread::JoinHandle<()>>,
    }
    impl Worker {
        fn finish(mut self) {
            self.release.take().unwrap().send(()).unwrap();
            self.join.take().unwrap().join().unwrap();
        }
    }
    impl Drop for Worker {
        fn drop(&mut self) {
            if let Some(release) = self.release.take() {
                let _ = release.send(());
            }
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    #[test]
    fn dequeued_input_stays_charged_until_the_actual_write_finishes() {
        let session = small();
        let channel = session.channel();
        let (tx, rx) = mpsc::channel::<InputChunk>();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let join = std::thread::spawn(move || {
            let chunk = rx.recv().unwrap();
            BlockedWriter {
                entered: entered_tx,
                release: release_rx,
            }
            .write_all(chunk.bytes())
            .unwrap();
            assert_eq!(chunk.network_bytes(), 4);
            drop(chunk);
        });
        let worker = Worker {
            release: Some(release_tx),
            join: Some(join),
        };
        tx.send(channel.try_network(vec![1; 4]).unwrap().unwrap())
            .unwrap();
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        drop(tx);
        assert_eq!(session.usage().network.bytes, 4);
        assert_eq!(session.usage().network.items, 1);
        assert!(channel.try_network(vec![2]).is_err());
        worker.finish();
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn session_refusal_does_not_partially_reserve_the_new_channel() {
        let session = small();
        let first = session.channel();
        let next = session.channel();
        let held = first.try_network(vec![1; 4]).unwrap().unwrap();
        assert!(next.try_network(vec![2]).is_err());
        assert_eq!(next.usage(), Usage::default());
        drop(held);
        let accepted = next.try_network(vec![2; 4]).unwrap().unwrap();
        assert_eq!(next.usage().network.bytes, 4);
        drop(accepted);
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn network_and_local_reply_keep_separate_quotas_and_one_fifo_order() {
        let session = small();
        let channel = session.channel();
        let (tx, rx) = mpsc::channel();
        tx.send(channel.try_network(b"net!".to_vec()).unwrap().unwrap())
            .unwrap();
        tx.send(channel.try_local_reply(b"ans".to_vec()).unwrap().unwrap())
            .unwrap();
        assert!(channel.try_network(vec![1]).is_err());
        assert!(channel.try_local_reply(vec![1]).is_err());
        let network = rx.recv().unwrap();
        let local = rx.recv().unwrap();
        assert_eq!(network.bytes(), b"net!");
        assert_eq!(network.network_bytes(), 4);
        assert_eq!(local.bytes(), b"ans");
        assert_eq!(local.network_bytes(), 0);
        assert_eq!(local.origin(), InputOrigin::LocalReply);
        drop((network, local));
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn retiring_a_writer_does_not_reset_the_session_budget_for_stream_reuse() {
        let session = small();
        let old = session.channel();
        let stale_sender = old.clone();
        let held = old.try_network(vec![1; 4]).unwrap().unwrap();
        old.close();
        drop(old);
        let reused = session.channel();
        assert!(stale_sender.try_network(vec![2]).is_err());
        assert!(reused.try_network(vec![3]).is_err());
        assert_eq!(session.usage().network.bytes, 4);
        drop(held);
        assert!(reused.try_network(vec![3; 4]).unwrap().is_some());
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn failed_send_and_dropped_receiver_release_their_owned_chunks() {
        let session = small();
        let channel = session.channel();
        let (tx, rx) = mpsc::channel();
        drop(rx);
        let failed = tx
            .send(channel.try_network(vec![1; 4]).unwrap().unwrap())
            .unwrap_err();
        assert_eq!(session.usage().network.bytes, 4);
        drop(failed);
        assert_eq!(session.usage(), Usage::default());
        let (tx, rx) = mpsc::channel();
        tx.send(channel.try_network(vec![1; 4]).unwrap().unwrap())
            .unwrap();
        tx.send(channel.try_local_reply(vec![2; 3]).unwrap().unwrap())
            .unwrap();
        drop(rx);
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn concurrent_admissions_cannot_oversubscribe_or_leak_a_partial_reservation() {
        let session = small();
        let ready = Arc::new(Barrier::new(3));
        let (tx, rx) = mpsc::channel();
        let workers: Vec<_> = (0..2)
            .map(|_| {
                let channel = session.channel();
                let ready = ready.clone();
                let tx = tx.clone();
                std::thread::spawn(move || {
                    ready.wait();
                    tx.send(channel.try_network(vec![1; 4])).unwrap();
                })
            })
            .collect();
        ready.wait();
        let first = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let second = rx.recv_timeout(Duration::from_secs(2)).unwrap();
        for worker in workers {
            worker.join().unwrap();
        }
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
        assert_eq!(session.usage().network.bytes, 4);
        drop((first, second));
        assert_eq!(session.usage(), Usage::default());
    }
    #[test]
    fn the_default_budget_accepts_eight_mib_in_normal_chunks() {
        let session = SessionInputBudget::new();
        let channel = session.channel();
        let chunks: Vec<_> = (0..16_384)
            .map(|_| channel.try_network(vec![0; 512]).unwrap().unwrap())
            .collect();
        assert_eq!(
            session.usage().network,
            QuotaUsage {
                bytes: 8 * 1024 * 1024,
                items: 16_384
            }
        );
        assert_eq!(
            channel.try_network(vec![0]).unwrap_err(),
            InputLimit::Bytes {
                origin: InputOrigin::Network,
                scope: InputScope::Session,
            }
        );
        drop(chunks);
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn tiny_network_fragments_hit_the_item_limit_before_the_byte_limit() {
        let session = SessionInputBudget::new();
        let channel = session.channel();
        let chunks: Vec<_> = (0..16_384)
            .map(|_| channel.try_network(vec![0]).unwrap().unwrap())
            .collect();
        assert_eq!(session.usage().network.bytes, 16_384);
        assert_eq!(
            channel.try_network(vec![0]).unwrap_err(),
            InputLimit::Items {
                origin: InputOrigin::Network,
                scope: InputScope::Session,
            }
        );
        assert!(channel.try_local_reply(vec![0]).unwrap().is_some());
        drop(chunks);
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn local_reply_quotas_bound_each_channel_and_the_aggregate() {
        let session = SessionInputBudget::new();
        let channels: Vec<_> = (0..9).map(|_| session.channel()).collect();
        let mut chunks = Vec::new();
        for channel in &channels[..8] {
            chunks.push(
                channel
                    .try_local_reply(vec![0; 64 * 1024])
                    .unwrap()
                    .unwrap(),
            );
        }
        assert_eq!(session.usage().local.bytes, 512 * 1024);
        assert_eq!(
            channels[8].try_local_reply(vec![0]).unwrap_err(),
            InputLimit::Bytes {
                origin: InputOrigin::LocalReply,
                scope: InputScope::Session,
            }
        );
        drop(chunks.pop());
        assert_eq!(
            channels[0].try_local_reply(vec![0]).unwrap_err(),
            InputLimit::Bytes {
                origin: InputOrigin::LocalReply,
                scope: InputScope::Channel,
            }
        );
        assert!(channels[8].try_network(vec![0]).unwrap().is_some());
        drop(chunks);
        assert_eq!(session.usage(), Usage::default());

        let mut items = Vec::new();
        for channel in &channels[..8] {
            for _ in 0..64 {
                items.push(channel.try_local_reply(vec![0]).unwrap().unwrap());
            }
        }
        assert_eq!(session.usage().local.items, 512);
        assert_eq!(
            channels[8].try_local_reply(vec![0]).unwrap_err(),
            InputLimit::Items {
                origin: InputOrigin::LocalReply,
                scope: InputScope::Session,
            }
        );
        drop(items.pop());
        assert_eq!(
            channels[0].try_local_reply(vec![0]).unwrap_err(),
            InputLimit::Items {
                origin: InputOrigin::LocalReply,
                scope: InputScope::Channel,
            }
        );
        drop(items);
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn empty_and_oversized_input_do_not_reserve_and_accepted_capacity_is_exact() {
        let session = small();
        let channel = session.channel();
        assert!(channel
            .try_network(Vec::with_capacity(1024))
            .unwrap()
            .is_none());
        assert!(channel.try_local_reply(Vec::new()).unwrap().is_none());
        assert_eq!(session.usage(), Usage::default());
        let mut oversized = Vec::with_capacity(1024);
        oversized.extend_from_slice(b"large");
        assert_eq!(
            channel.try_network(oversized).unwrap_err(),
            InputLimit::Bytes {
                origin: InputOrigin::Network,
                scope: InputScope::Session,
            }
        );
        assert_eq!(channel.usage(), Usage::default());
        assert_eq!(session.usage(), Usage::default());
        let mut padded = Vec::with_capacity(1024);
        padded.extend_from_slice(b"four");
        let chunk = channel.try_network(padded).unwrap().unwrap();
        assert_eq!(chunk.bytes.capacity(), 4);
        assert_eq!(chunk.bytes(), b"four");
        assert_eq!(session.usage().network.bytes, 4);
        // Debug formatting must never expose the input bytes or control codes.
        let debug = format!("{chunk:?}");
        assert!(!debug.contains("four"));
        assert!(debug.contains("Network"));
        drop(chunk);
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn closing_session_or_channel_keeps_live_charges_and_is_distinct_from_full() {
        let session = small();
        let channel = session.channel();
        let held = channel.try_network(vec![1; 4]).unwrap().unwrap();
        channel.close();
        assert_eq!(
            channel.try_network(vec![1]).unwrap_err(),
            InputLimit::Closed(InputScope::Channel)
        );
        assert_eq!(
            channel.try_local_reply(Vec::new()).unwrap_err(),
            InputLimit::Closed(InputScope::Channel)
        );
        let next = session.channel();
        assert!(matches!(
            next.try_network(vec![1]),
            Err(InputLimit::Bytes { .. })
        ));
        session.close();
        assert_eq!(
            next.try_network(vec![1]).unwrap_err(),
            InputLimit::Closed(InputScope::Session)
        );
        assert_eq!(
            session.channel().try_local_reply(vec![1]).unwrap_err(),
            InputLimit::Closed(InputScope::Session)
        );
        assert_eq!(session.usage().network.bytes, 4);
        drop(held);
        assert_eq!(session.usage(), Usage::default());
    }

    #[test]
    fn writer_unwind_returns_capacity_without_poisoning_admission() {
        let session = small();
        let channel = session.channel();
        let chunk = channel.try_network(vec![1; 4]).unwrap().unwrap();
        let result = std::panic::catch_unwind(move || {
            let _held_during_write = chunk;
            panic!("injected writer panic");
        });
        assert!(result.is_err());
        assert_eq!(session.usage(), Usage::default());
        assert!(channel.try_network(vec![2; 4]).unwrap().is_some());
    }
}
