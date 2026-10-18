//! The complete logical address list, independent of the transport's bounded table.
//!
//! DNS supplies candidates, never proof of server identity. Published endpoints
//! use only the existing session's authenticated path probes.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use connect::recovery_gate::{AddressId, RecoveryEpoch};
use connect::Address;
use transport::paths::{MAX_PATHS, PROBE_TIMEOUT};

pub const DNS_TIMEOUT: Duration = Duration::from_secs(5);
pub const DNS_REFRESH: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolveError {
    Timeout,
    NoAddress,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RoadWork {
    Resolve {
        request: u64,
        address: AddressId,
        host: String,
        port: u16,
    },
    Publish {
        paths: Vec<SocketAddr>,
    },
}

#[derive(Clone, Copy)]
struct PendingResolve {
    request: u64,
    deadline: Duration,
    due: Duration,
}

struct Entry {
    configured: Address,
    endpoint: Option<SocketAddr>,
    pending: Option<PendingResolve>,
    next_refresh: Duration,
}

/// Pure scheduling state. Address IDs always index the original configured list.
pub struct RoadCatalog {
    epoch: RecoveryEpoch,
    entries: Vec<Entry>,
    next_request: u64,
    cursor: usize,
    published: Vec<SocketAddr>,
    /// Publication and first actual probe times; repeated probes cannot restart dwell.
    published_at: Duration,
    first_probes: Vec<(SocketAddr, Duration)>,
    urgent: bool,
}

impl RoadCatalog {
    pub fn new(addresses: Vec<Address>, epoch: RecoveryEpoch) -> Self {
        Self {
            epoch,
            entries: addresses
                .into_iter()
                .map(|configured| Entry {
                    endpoint: configured
                        .host
                        .parse::<IpAddr>()
                        .ok()
                        .map(|ip| SocketAddr::new(ip, configured.qsh_port)),
                    configured,
                    pending: None,
                    next_refresh: Duration::ZERO,
                })
                .collect(),
            next_request: 0,
            cursor: 0,
            published: Vec::new(),
            published_at: Duration::ZERO,
            first_probes: Vec::new(),
            urgent: false,
        }
    }

    pub fn address_ids(&self) -> Vec<AddressId> {
        (0..self.entries.len()).map(AddressId).collect()
    }

    pub fn resolving(&self) -> Vec<AddressId> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| e.pending.is_some())
            .map(|(i, _)| AddressId(i))
            .collect()
    }

    pub fn endpoints(&self) -> Vec<(AddressId, SocketAddr)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(i, e)| e.endpoint.map(|p| (AddressId(i), p)))
            .collect()
    }

    /// Seed the authenticated endpoint used at login, including a reported port.
    pub fn seed(&mut self, address: AddressId, endpoint: SocketAddr) {
        if let Some(entry) = self.entries.get_mut(address.0) {
            entry.configured.qsh_port = endpoint.port();
            entry.endpoint = Some(endpoint);
        }
    }

    pub fn refresh(&mut self, now: Duration, active: SocketAddr, urgent: bool) -> Vec<RoadWork> {
        let immediate = urgent && !self.urgent;
        self.urgent = urgent;
        let mut work = Vec::new();
        // When worker capacity is bounded, names still waiting for their first
        // turn must precede periodic retries from the start of a long list.
        let mut resolve_order: Vec<_> = (0..self.entries.len()).collect();
        resolve_order.sort_by_key(|i| self.entries[*i].next_refresh);
        for i in resolve_order {
            let entry = &mut self.entries[i];
            if entry.pending.is_some_and(|pending| now >= pending.deadline) {
                // A late completion of this request is no longer authoritative.
                entry.pending = None;
            }
            if entry.configured.host.parse::<IpAddr>().is_ok() {
                continue;
            }
            if immediate {
                entry.next_refresh = now;
            }
            if entry.pending.is_none() && now >= entry.next_refresh {
                let request = self.next_request;
                self.next_request = self
                    .next_request
                    .checked_add(1)
                    .expect("DNS request counter exhausted");
                entry.pending = Some(PendingResolve {
                    request,
                    deadline: now + DNS_TIMEOUT,
                    due: entry.next_refresh,
                });
                entry.next_refresh = now + DNS_REFRESH;
                work.push(RoadWork::Resolve {
                    request,
                    address: AddressId(i),
                    host: entry.configured.host.clone(),
                    port: entry.configured.qsh_port,
                });
            }
        }

        let mut candidates = Vec::new();
        for (_, endpoint) in self.endpoints() {
            if endpoint != active && !candidates.contains(&endpoint) {
                candidates.push(endpoint);
            }
        }
        let all_fit = candidates.len() < MAX_PATHS;
        let finished = !self.published.is_empty()
            && self.published.iter().all(|path| {
                self.first_probes
                    .iter()
                    .any(|(p, sent)| p == path && now.saturating_sub(*sent) >= PROBE_TIMEOUT)
            });
        let active_changed = self.published.first() != Some(&active);
        let removed = self
            .published
            .iter()
            .any(|path| *path != active && !candidates.contains(path));
        // New DNS results can join an underfull table immediately. A full group
        // stays put until every path actually had a complete probe window.
        let underfull = self.published.len() < MAX_PATHS
            && candidates.iter().any(|p| !self.published.contains(p));
        if self.published.is_empty()
            || active_changed
            || removed
            || underfull
            || (!all_fit && finished)
        {
            if !all_fit && finished && !active_changed && !removed && !underfull {
                self.cursor = (self.cursor + MAX_PATHS - 1) % candidates.len();
            }
            let mut paths = vec![active];
            if !candidates.is_empty() {
                for n in 0..candidates.len().min(MAX_PATHS - 1) {
                    paths.push(candidates[(self.cursor + n) % candidates.len()]);
                }
            }
            if paths != self.published {
                // Retained paths have already been probed; new members must
                // be observed after this publication (even after re-entry).
                self.first_probes
                    .retain(|(p, _)| paths.contains(p) && self.published.contains(p));
                self.published = paths.clone();
                self.published_at = now;
                work.push(RoadWork::Publish { paths });
            }
        }
        work
    }

    /// Report a probe's actual send time on the same clock passed to `refresh`.
    /// Stale snapshots and repeat probes cannot shorten or restart the window.
    pub fn probed(&mut self, endpoint: SocketAddr, sent: Duration) {
        if sent >= self.published_at
            && self.published.contains(&endpoint)
            && !self.first_probes.iter().any(|(p, _)| *p == endpoint)
        {
            self.first_probes.push((endpoint, sent));
        }
    }

    pub fn resolved(
        &mut self,
        epoch: RecoveryEpoch,
        request: u64,
        address: AddressId,
        result: Result<SocketAddr, ResolveError>,
    ) {
        if epoch != self.epoch {
            return;
        }
        let Some(entry) = self.entries.get_mut(address.0) else {
            return;
        };
        if !entry
            .pending
            .is_some_and(|pending| pending.request == request)
        {
            return;
        }
        entry.pending = None;
        if let Ok(endpoint) = result {
            entry.endpoint = Some(endpoint);
        }
    }

    /// A saturated bounded worker did not accept this request. Retry next turn;
    /// accepted requests retain their refresh cadence so later IDs get a turn.
    pub fn deferred(&mut self, request: u64, address: AddressId) {
        if let Some(entry) = self.entries.get_mut(address.0) {
            if entry
                .pending
                .is_some_and(|pending| pending.request == request)
            {
                let pending = entry.pending.take().expect("matching pending request");
                entry.next_refresh = pending.due;
            }
        }
    }

    pub fn reset(&mut self, epoch: RecoveryEpoch) {
        self.epoch = epoch;
        self.urgent = false;
        for entry in &mut self.entries {
            entry.pending = None;
            entry.next_refresh = Duration::ZERO;
        }
        self.published.clear();
        self.first_probes.clear();
        self.cursor = 0;
    }
}

/// Maximum OS resolver calls alive at once. Timeouts do not replenish slots:
/// a stuck system resolver cannot cause an unbounded number of leaked threads.
pub const DNS_WORKERS: usize = 4;

#[derive(Debug)]
pub struct Resolution {
    pub epoch: RecoveryEpoch,
    pub request: u64,
    pub address: AddressId,
    pub result: Result<SocketAddr, ResolveError>,
}

struct Job {
    epoch: RecoveryEpoch,
    request: u64,
    address: AddressId,
    host: String,
    port: u16,
}

struct ResolverSlot {
    tx: std::sync::mpsc::SyncSender<Job>,
    running: Option<AddressId>,
    pending: Option<(RecoveryEpoch, u64, AddressId, Duration)>,
}

/// Nonblocking UI-facing worker pool with no waiting-job queue. Rejected work
/// must be deferred in the catalog. A five-second logical timeout invalidates
/// the answer but cannot interrupt libc's resolver. That slot stays occupied
/// until libc returns. Keep this pool across reconnects; `cancel` invalidates
/// results without creating replacement threads or joining blocked workers.
pub struct BoundedResolver {
    slots: Vec<ResolverSlot>,
    rx: std::sync::mpsc::Receiver<(usize, Resolution)>,
}

impl Default for BoundedResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl BoundedResolver {
    pub fn new() -> Self {
        use std::net::ToSocketAddrs;
        Self::with_lookup(|host, port| {
            let addresses = (host, port)
                .to_socket_addrs()
                .map_err(|_| ResolveError::Failed)?;
            crate::connect::preferred_addr(addresses).ok_or(ResolveError::NoAddress)
        })
    }

    fn with_lookup(
        lookup: impl Fn(&str, u16) -> Result<SocketAddr, ResolveError> + Send + Sync + 'static,
    ) -> Self {
        use std::sync::{mpsc, Arc};
        let lookup = Arc::new(lookup);
        let (completed_tx, rx) = mpsc::sync_channel(DNS_WORKERS);
        let slots = (0..DNS_WORKERS)
            .map(|slot| {
                let (tx, jobs) = mpsc::sync_channel::<Job>(1);
                let lookup = Arc::clone(&lookup);
                let completed = completed_tx.clone();
                std::thread::Builder::new()
                    .name(format!("qsh-dns-{slot}"))
                    .spawn(move || {
                        while let Ok(job) = jobs.recv() {
                            let result = lookup(&job.host, job.port);
                            if completed
                                .send((
                                    slot,
                                    Resolution {
                                        epoch: job.epoch,
                                        request: job.request,
                                        address: job.address,
                                        result,
                                    },
                                ))
                                .is_err()
                            {
                                break;
                            }
                        }
                    })
                    .expect("start bounded DNS worker");
                ResolverSlot {
                    tx,
                    running: None,
                    pending: None,
                }
            })
            .collect();
        Self { slots, rx }
    }

    /// Returns false on saturation; never waits for a worker or DNS response.
    pub fn submit(
        &mut self,
        epoch: RecoveryEpoch,
        request: u64,
        address: AddressId,
        host: String,
        port: u16,
        now: Duration,
    ) -> bool {
        if self.slots.iter().any(|slot| slot.running == Some(address)) {
            return false;
        }
        let Some(slot) = self.slots.iter_mut().find(|slot| slot.running.is_none()) else {
            return false;
        };
        if slot
            .tx
            .try_send(Job {
                epoch,
                request,
                address,
                host,
                port,
            })
            .is_err()
        {
            return false;
        }
        slot.running = Some(address);
        slot.pending = Some((epoch, request, address, now + DNS_TIMEOUT));
        true
    }

    pub fn poll(&mut self, now: Duration) -> Vec<Resolution> {
        let mut out = Vec::new();
        // Expire first so a completed but unread answer cannot beat the budget.
        for slot in &mut self.slots {
            if slot
                .pending
                .is_some_and(|(_, _, _, deadline)| now >= deadline)
            {
                let (epoch, request, address, _) = slot.pending.take().expect("pending deadline");
                out.push(Resolution {
                    epoch,
                    request,
                    address,
                    result: Err(ResolveError::Timeout),
                });
            }
        }
        while let Ok((index, result)) = self.rx.try_recv() {
            let slot = &mut self.slots[index];
            slot.running = None;
            if slot.pending.take().is_some() {
                out.push(result);
            }
        }
        out
    }

    pub fn cancel(&mut self) {
        for slot in &mut self.slots {
            slot.pending = None;
        }
    }

    pub fn busy(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.running.is_some())
            .count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{mpsc, Arc, Condvar, Mutex};
    use std::time::Instant;

    #[test]
    fn resolver_timeouts_keep_worker_slots_bounded_and_other_jobs_can_finish() {
        let blocked = Arc::new((Mutex::new(false), Condvar::new()));
        let release = Arc::clone(&blocked);
        let (started_tx, started_rx) = mpsc::channel();
        let mut worker = BoundedResolver::with_lookup(move |host, port| {
            if host == "hung.invalid" {
                started_tx.send(()).unwrap();
                let (lock, cv) = &*release;
                let guard = lock.lock().unwrap();
                drop(cv.wait_while(guard, |released| !*released).unwrap());
            }
            Ok(SocketAddr::from(([192, 0, 2, 1], port)))
        });
        let epoch = RecoveryEpoch {
            connection: 1,
            network: 1,
        };
        assert!(worker.submit(
            epoch,
            0,
            AddressId(0),
            "hung.invalid".into(),
            60000,
            Duration::ZERO
        ));
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(worker.submit(
            epoch,
            1,
            AddressId(1),
            "ready.invalid".into(),
            60000,
            Duration::ZERO
        ));
        let until = Instant::now() + Duration::from_secs(1);
        let mut ready = Vec::new();
        while Instant::now() < until {
            ready.extend(worker.poll(Duration::from_secs(1)));
            if ready.iter().any(|r| r.request == 1) {
                break;
            }
            std::thread::yield_now();
        }
        assert!(ready.iter().any(|r| r.request == 1 && r.result.is_ok()));
        let timed_out = worker.poll(DNS_TIMEOUT);
        assert!(timed_out
            .iter()
            .any(|r| r.request == 0 && r.result == Err(ResolveError::Timeout)));
        assert!(
            !worker.submit(
                epoch,
                999,
                AddressId(0),
                "hung.invalid".into(),
                60000,
                DNS_TIMEOUT
            ),
            "one stuck address must not consume additional worker slots on retry"
        );
        for n in 1..DNS_WORKERS {
            assert!(worker.submit(
                epoch,
                n as u64 + 1,
                AddressId(n + 1),
                "hung.invalid".into(),
                60000,
                DNS_TIMEOUT
            ));
        }
        assert!(!worker.submit(
            epoch,
            99,
            AddressId(99),
            "overflow.invalid".into(),
            60000,
            DNS_TIMEOUT
        ));
        worker.poll(DNS_TIMEOUT * 2);
        assert!(
            !worker.submit(
                epoch,
                100,
                AddressId(100),
                "overflow.invalid".into(),
                60000,
                DNS_TIMEOUT * 2
            ),
            "logical timeout must not spawn replacement threads"
        );
        let (lock, cv) = &*blocked;
        *lock.lock().unwrap() = true;
        cv.notify_all();
        let until = Instant::now() + Duration::from_secs(1);
        while worker.busy() != 0 && Instant::now() < until {
            assert!(
                worker.poll(DNS_TIMEOUT * 3).is_empty(),
                "late completions cannot revive a timed-out request"
            );
            std::thread::yield_now();
        }
        assert_eq!(worker.busy(), 0);
    }
}
