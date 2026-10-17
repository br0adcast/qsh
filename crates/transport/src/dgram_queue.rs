//! A session's datagram route (spec §4.16, QSH-04): the queue between the
//! manager's socket loop and one session's bridge (or its probation). It
//! never blocks the socket loop and holds a bounded number of bytes: a
//! datagram past the bound is dropped, as the network drops one, and its
//! sender sends it again.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

/// What one route may hold, counted as [`DGRAM_ENTRY_COST`] plus each
/// datagram's length. The bridge reads its route at CPU speed -- it waits for
/// nothing but a backend that lets `PENDING_CAP` pile up -- so this
/// only has to absorb a burst: a thousand full-sized datagrams, a tenth of a
/// second at 10 MB/s. Counted in bytes, not datagrams: a datagram on loopback,
/// or from a sender on the path that knows a session id, can be 64 KiB.
pub(crate) const DGRAM_QUEUE_BYTES: usize = 1024 * 1024;

/// What the route of a connection in probation may hold (spec §4.16): its
/// peer is not proven yet, and a probation reads nothing while its proof is
/// verified, so 128 probations at a full megabyte each could hold 128 MiB. A
/// probation's traffic is a handshake, one authentication record and
/// whatever the client types before the proof lands -- 128 KiB is well past
/// that. Raised to [`DGRAM_QUEUE_BYTES`] when the route is handed to a
/// bridge ([`DgramRx::raise_bound`]).
pub(crate) const PROBATION_DGRAM_QUEUE_BYTES: usize = 128 * 1024;

/// What a queued datagram costs beyond its bytes: the tuple, the `Vec`, the
/// channel's node.
pub(crate) const DGRAM_ENTRY_COST: usize = 64;

/// What both ends of a route share: what it holds, and what it may hold.
struct Counters {
    /// Bytes queued, each datagram counted with [`DGRAM_ENTRY_COST`].
    queued: AtomicUsize,
    /// The most `queued` may reach. Only ever raised.
    bound: AtomicUsize,
}

/// The route's sending end: the manager's.
#[derive(Clone)]
pub(crate) struct DgramTx {
    tx: mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    counters: Arc<Counters>,
}

/// The route's receiving end: the bridge's, or its probation's.
pub(crate) struct DgramRx {
    rx: mpsc::UnboundedReceiver<(SocketAddr, Vec<u8>)>,
    counters: Arc<Counters>,
}

/// A new, empty route of a bridge: [`DGRAM_QUEUE_BYTES`].
pub(crate) fn dgram_queue() -> (DgramTx, DgramRx) {
    dgram_queue_of(DGRAM_QUEUE_BYTES)
}

/// A new, empty route of a connection in probation:
/// [`PROBATION_DGRAM_QUEUE_BYTES`], until [`DgramRx::raise_bound`].
pub(crate) fn probation_dgram_queue() -> (DgramTx, DgramRx) {
    dgram_queue_of(PROBATION_DGRAM_QUEUE_BYTES)
}

fn dgram_queue_of(bound: usize) -> (DgramTx, DgramRx) {
    let (tx, rx) = mpsc::unbounded_channel();
    let counters = Arc::new(Counters {
        queued: AtomicUsize::new(0),
        bound: AtomicUsize::new(bound),
    });
    (
        DgramTx {
            tx,
            counters: Arc::clone(&counters),
        },
        DgramRx { rx, counters },
    )
}

impl DgramTx {
    /// Queue a datagram from `src`. `false`: dropped -- the route holds its
    /// bound already, or its reader is gone.
    pub(crate) fn send(&self, src: SocketAddr, bytes: Vec<u8>) -> bool {
        let cost = bytes.len() + DGRAM_ENTRY_COST;
        let bound = self.counters.bound.load(Ordering::Acquire);
        if self.counters.queued.fetch_add(cost, Ordering::AcqRel) + cost > bound {
            self.counters.queued.fetch_sub(cost, Ordering::AcqRel);
            return false;
        }
        if self.tx.send((src, bytes)).is_err() {
            self.counters.queued.fetch_sub(cost, Ordering::AcqRel);
            return false;
        }
        true
    }

    /// Test-only: what the route may hold now.
    #[cfg(test)]
    pub(crate) fn bound(&self) -> usize {
        self.counters.bound.load(Ordering::Acquire)
    }

    /// Whether the reader is gone.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

impl DgramRx {
    /// Let the route hold up to `bound` from now on (never less than it may
    /// already): a probation's route handed to its bridge takes a bridge's
    /// [`DGRAM_QUEUE_BYTES`]. What it holds already stays, in order.
    pub(crate) fn raise_bound(&self, bound: usize) {
        self.counters.bound.fetch_max(bound, Ordering::AcqRel);
    }

    /// The next datagram; `None` once every sender is gone. Cancel-safe.
    pub(crate) async fn recv(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        let (src, bytes) = self.rx.recv().await?;
        self.counters
            .queued
            .fetch_sub(bytes.len() + DGRAM_ENTRY_COST, Ordering::AcqRel);
        Some((src, bytes))
    }

    /// The next datagram if one is queued.
    pub(crate) fn try_recv(&mut self) -> Option<(SocketAddr, Vec<u8>)> {
        let (src, bytes) = self.rx.try_recv().ok()?;
        self.counters
            .queued
            .fetch_sub(bytes.len() + DGRAM_ENTRY_COST, Ordering::AcqRel);
        Some((src, bytes))
    }

    /// Test-only: [`DgramRx::try_recv`] that tells an open, empty route
    /// (`Empty`) from one whose senders are all gone (`Disconnected`).
    #[cfg(test)]
    pub(crate) fn try_recv_or_why(
        &mut self,
    ) -> Result<(SocketAddr, Vec<u8>), mpsc::error::TryRecvError> {
        let (src, bytes) = self.rx.try_recv()?;
        self.counters
            .queued
            .fetch_sub(bytes.len() + DGRAM_ENTRY_COST, Ordering::AcqRel);
        Ok((src, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spec §4.16 (QSH-04): a route holds at most `DGRAM_QUEUE_BYTES`, each
    /// datagram costing its length plus `DGRAM_ENTRY_COST`; past that a
    /// datagram is dropped, as the network would; a read frees its room.
    #[tokio::test]
    async fn a_route_holds_at_most_its_bytes_and_frees_them_as_they_are_read() {
        let (tx, mut rx) = dgram_queue();
        let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let big = vec![0u8; 64 * 1024 - DGRAM_ENTRY_COST];
        let mut taken = 0;
        while tx.send(src, big.clone()) {
            taken += 1;
        }
        assert_eq!(taken, DGRAM_QUEUE_BYTES / (64 * 1024));
        assert!(!tx.send(src, vec![0u8; 1]), "full");
        let (_, first) = rx.recv().await.expect("queued");
        assert_eq!(first.len(), big.len());
        assert!(tx.send(src, big.clone()), "a read frees its room");
        let mut left = 0;
        while rx.try_recv().is_some() {
            left += 1;
        }
        assert_eq!(left, taken);
    }

    /// Spec §4.16 (ruling R14): a probation's route holds at most
    /// `PROBATION_DGRAM_QUEUE_BYTES`; raised when it is handed to a bridge,
    /// it takes up to `DGRAM_QUEUE_BYTES`, and nothing it held is lost.
    #[tokio::test]
    async fn a_probation_route_holds_128_kib_until_it_is_raised_and_loses_nothing() {
        let (tx, mut rx) = probation_dgram_queue();
        let src: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let entry = 1024;
        let payload = |i: usize| {
            let mut b = vec![0u8; entry - DGRAM_ENTRY_COST];
            b[..8].copy_from_slice(&(i as u64).to_be_bytes());
            b
        };
        let mut sent = 0usize;
        while tx.send(src, payload(sent)) {
            sent += 1;
        }
        assert_eq!(sent, PROBATION_DGRAM_QUEUE_BYTES / entry);
        rx.raise_bound(DGRAM_QUEUE_BYTES);
        while tx.send(src, payload(sent)) {
            sent += 1;
        }
        assert_eq!(
            sent,
            DGRAM_QUEUE_BYTES / entry,
            "the raise takes a bridge's bound"
        );
        for i in 0..sent {
            let (_, bytes) = rx.try_recv().expect("nothing lost at the raise");
            assert_eq!(bytes, payload(i), "in order");
        }
        assert!(rx.try_recv().is_none());
        rx.raise_bound(PROBATION_DGRAM_QUEUE_BYTES);
        let mut again = 0;
        while tx.send(src, payload(again)) {
            again += 1;
        }
        assert_eq!(again, DGRAM_QUEUE_BYTES / entry, "a bound is never lowered");
    }

    /// A route whose reader is gone takes nothing.
    #[tokio::test]
    async fn a_route_whose_reader_is_gone_takes_nothing() {
        let (tx, rx) = dgram_queue();
        drop(rx);
        assert!(!tx.send("127.0.0.1:1".parse().unwrap(), vec![1]));
        assert!(tx.is_closed());
    }
}
