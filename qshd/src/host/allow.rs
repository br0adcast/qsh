//! The allowlist of a host (#529): the daemon's set of admitted client keys,
//! of which every frontend holds a mirror.
//!
//! The host's list is the truth. Every addition (`ADD-CLIENT`) gets a
//! sequence number, also when the key is already there, and reaches the
//! running frontend as a (key, sequence) pair. A frontend's router scrubs a
//! key when its session's connection ends, and reports the sequence it knew
//! (`ForgetKey`): the host removes the key only if no addition came since,
//! so a key added again while a scrub is on its way stays. The host scrubs
//! the keys of the sessions it ends itself (expiry, an owner's end) the same
//! way, by the sequence the key had when the session was last reported
//! under it.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use transport::SharedAllowlist;

/// How long `ADD-CLIENT` waits for the running frontend to admit the key
/// it adds: well within the client's own wait for the answer
/// ([`crate::control::CLIENT_READ_TIMEOUT`]), which fails the registration.
pub(crate) const ADD_CLIENT_WAIT: Duration = Duration::from_secs(1);

/// What the running frontend has of the allowlist.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Taken {
    /// A frontend runs (it may still be starting).
    pub(crate) running: bool,
    /// The highest addition it has applied.
    pub(crate) seq: u64,
}

/// See the module documentation.
pub struct HostAllowlist {
    /// The keys, as the control server's replies and the in-process router
    /// read them.
    keys: SharedAllowlist,
    /// Each key's last addition.
    seqs: Mutex<HashMap<[u8; 32], u64>>,
    /// The last sequence number given: never one twice.
    last: std::sync::atomic::AtomicU64,
    /// Woken at every addition: the host sends the running frontend what
    /// it lacks.
    added: tokio::sync::Notify,
    taken: tokio::sync::watch::Sender<Taken>,
    /// Keys the host scrubbed itself, for the running frontend to drop.
    revoked: Mutex<Vec<([u8; 32], u64)>>,
}

impl HostAllowlist {
    /// The host of `keys`; every key already there counts as added once.
    pub fn new(keys: SharedAllowlist) -> Arc<HostAllowlist> {
        let seqs: HashMap<[u8; 32], u64> = {
            let list = keys.lock().unwrap_or_else(|e| e.into_inner());
            list.iter()
                .enumerate()
                .map(|(i, key)| (*key, i as u64 + 1))
                .collect()
        };
        let last = std::sync::atomic::AtomicU64::new(seqs.len() as u64);
        Arc::new(HostAllowlist {
            keys,
            seqs: Mutex::new(seqs),
            last,
            added: tokio::sync::Notify::new(),
            taken: tokio::sync::watch::Sender::new(Taken::default()),
            revoked: Mutex::new(Vec::new()),
        })
    }

    pub fn keys(&self) -> &SharedAllowlist {
        &self.keys
    }

    fn seqs(&self) -> std::sync::MutexGuard<'_, HashMap<[u8; 32], u64>> {
        self.seqs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Add `key` (again): its new sequence number.
    pub(crate) fn add(&self, key: [u8; 32]) -> u64 {
        let mut list = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        if !list.contains(&key) {
            list.push(key);
        }
        let mut seqs = self.seqs();
        let seq = self.last.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        seqs.insert(key, seq);
        drop((seqs, list));
        self.added.notify_one();
        seq
    }

    /// [`HostAllowlist::add`], answered once the running frontend admits
    /// handshakes under `key`, at most `within` later. While no frontend
    /// runs, at once: the next one starts with every key. Past `within` the
    /// key is on the host's list all the same: the running frontend admits
    /// it once it applies the packet it was sent (a frontend whose channel
    /// does not even take that packet within its send bound is killed and
    /// replaced by one that starts with the key; one that takes it but
    /// never confirms is not replaced for that).
    pub(crate) async fn add_and_wait(&self, key: [u8; 32], within: Duration) {
        let seq = self.add(key);
        let mut taken = self.taken.subscribe();
        let _ = tokio::time::timeout(
            within,
            taken.wait_for(|taken| !taken.running || taken.seq >= seq),
        )
        .await;
    }

    /// The sequence `key` has now, if it is on the list.
    pub(crate) fn seq_of(&self, key: &[u8; 32]) -> Option<u64> {
        self.seqs().get(key).copied()
    }

    /// Remove `key` if its last addition is `seq`: a key added again since
    /// stays.
    pub(crate) fn forget(&self, key: &[u8; 32], seq: u64) -> bool {
        let mut list = self.keys.lock().unwrap_or_else(|e| e.into_inner());
        let mut seqs = self.seqs();
        if seqs.get(key) != Some(&seq) {
            return false;
        }
        seqs.remove(key);
        list.retain(|k| k != key);
        true
    }

    /// [`HostAllowlist::forget`] for a session the host ended itself: the
    /// running frontend, whose router did not see that end, drops the key
    /// too (`HostAllowlist::take_revoked`).
    pub(crate) fn scrub(&self, key: &[u8; 32], seq: u64) {
        if self.forget(key, seq) && self.taken().running {
            self.revoked
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((*key, seq));
            self.added.notify_one();
        }
    }

    /// The host's own scrubs since the running frontend last heard.
    pub(crate) fn take_revoked(&self) -> Vec<([u8; 32], u64)> {
        std::mem::take(&mut *self.revoked.lock().unwrap_or_else(|e| e.into_inner()))
    }

    /// Every key added after what `sent` says the frontend has.
    pub(crate) fn fresh(&self, sent: &HashMap<[u8; 32], u64>) -> Vec<([u8; 32], u64)> {
        self.seqs()
            .iter()
            .filter(|(key, seq)| sent.get(*key).is_none_or(|had| had < *seq))
            .map(|(key, seq)| (*key, *seq))
            .collect()
    }

    pub(crate) async fn added(&self) {
        self.added.notified().await
    }

    /// What the running frontend has.
    pub(crate) fn set_taken(&self, taken: Taken) {
        self.taken.send_replace(taken);
    }

    pub(crate) fn taken(&self) -> Taken {
        *self.taken.borrow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> Arc<HostAllowlist> {
        HostAllowlist::new(Arc::new(Mutex::new(Vec::new())))
    }

    /// A scrub of an addition that was superseded leaves the key: adding a
    /// key again wins over a scrub still on its way.
    #[test]
    fn adding_a_key_again_wins_over_a_scrub_on_its_way() {
        let allow = list();
        let first = allow.add([1; 32]);
        let again = allow.add([1; 32]);
        assert!(again > first);
        assert!(!allow.forget(&[1; 32], first), "a stale scrub");
        assert!(allow.keys().lock().unwrap().contains(&[1; 32]));
        assert!(allow.forget(&[1; 32], again));
        assert!(allow.keys().lock().unwrap().is_empty());
        assert_eq!(allow.seq_of(&[1; 32]), None);
    }

    /// The host's own scrub reaches the running frontend, and only the
    /// running one; a key added again since is not scrubbed.
    #[test]
    fn a_host_scrub_is_sent_to_the_running_frontend() {
        let allow = list();
        let a = allow.add([1; 32]);
        allow.scrub(&[1; 32], a);
        assert!(allow.take_revoked().is_empty(), "no frontend runs");
        let b = allow.add([2; 32]);
        allow.set_taken(Taken {
            running: true,
            seq: b,
        });
        allow.scrub(&[2; 32], b);
        assert_eq!(allow.take_revoked(), [([2; 32], b)]);
        let c = allow.add([3; 32]);
        allow.add([3; 32]);
        allow.scrub(&[3; 32], c);
        assert!(allow.take_revoked().is_empty(), "added again since");
        assert!(allow.keys().lock().unwrap().contains(&[3; 32]));
    }

    /// A frontend is sent what it lacks: new keys, and keys added again.
    #[test]
    fn a_frontend_is_sent_every_addition_it_lacks() {
        let allow = list();
        let a = allow.add([1; 32]);
        let mut sent = HashMap::new();
        assert_eq!(allow.fresh(&sent), [([1; 32], a)]);
        sent.insert([1; 32], a);
        assert!(allow.fresh(&sent).is_empty());
        let again = allow.add([1; 32]);
        assert_eq!(allow.fresh(&sent), [([1; 32], again)]);
    }

    /// `ADD-CLIENT` is answered once the running frontend has the key, not
    /// before; at once while none runs; and after its bound at the latest.
    #[tokio::test(start_paused = true)]
    async fn an_addition_is_answered_once_the_frontend_has_it() {
        let allow = list();
        let started = tokio::time::Instant::now();
        allow.add_and_wait([1; 32], Duration::from_secs(2)).await;
        assert_eq!(started.elapsed(), Duration::ZERO, "no frontend runs");

        allow.set_taken(Taken {
            running: true,
            seq: allow.seq_of(&[1; 32]).unwrap(),
        });
        let waiting = {
            let allow = allow.clone();
            tokio::spawn(async move {
                let started = tokio::time::Instant::now();
                allow.add_and_wait([2; 32], Duration::from_secs(2)).await;
                started.elapsed()
            })
        };
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(!waiting.is_finished(), "the frontend does not have it yet");
        allow.set_taken(Taken {
            running: true,
            seq: allow.seq_of(&[2; 32]).unwrap(),
        });
        assert_eq!(waiting.await.unwrap(), Duration::from_millis(300));

        let started = tokio::time::Instant::now();
        allow.add_and_wait([3; 32], Duration::from_secs(2)).await;
        assert_eq!(started.elapsed(), Duration::from_secs(2), "bounded");
    }

    /// `ADD-CLIENT` on a host whose running frontend never confirms a key
    /// is still answered well before the client gives up on the answer
    /// (`CLIENT_READ_TIMEOUT`), which would fail the registration.
    #[tokio::test(start_paused = true)]
    async fn an_unconfirmed_addition_is_answered_before_the_client_gives_up() {
        assert!(ADD_CLIENT_WAIT * 2 <= crate::control::CLIENT_READ_TIMEOUT);
        let allow = list();
        allow.set_taken(Taken {
            running: true,
            seq: 0,
        });
        let control = crate::transport_daemon::ControlAllowlist::Host(allow.clone());
        let started = tokio::time::Instant::now();
        control.add([4; 32]).await;
        assert_eq!(started.elapsed(), ADD_CLIENT_WAIT);
        assert!(
            allow.keys().lock().unwrap().contains(&[4; 32]),
            "on the host's list"
        );
    }
}
