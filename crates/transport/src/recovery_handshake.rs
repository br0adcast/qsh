//! Scheduling for one cryptographic recovery attempt across a full catalog.
//!
//! Connection owns the sole initiator and msg1. This module owns endpoint
//! work, not cryptographic state or sockets. Sending is acknowledged separately
//! so a queued endpoint cannot acquire a deadline or response eligibility.

use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::wire::COOKIE_LEN;

/// Logical catalog membership. Multiple members may name one physical endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecoveryEndpoint {
    pub address: usize,
    pub endpoint: SocketAddr,
}

/// One scheduled copy of the connection's unchanged msg1 body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HandshakeDispatch {
    pub endpoint: SocketAddr,
    pub cookie: Option<[u8; COOKIE_LEN]>,
}

/// Every recovery poll, including cookie-triggered work, shares this allowance.
/// Eight sends per 50 ms service interval gives 19 initially queued endpoints
/// a first turn within 100 ms, as the virtual-time test verifies. This is a
/// work limit per service interval, never a limit on catalog membership.
pub const HANDSHAKE_SEND_BUDGET: usize = 8;
pub const HANDSHAKE_SERVICE_INTERVAL: Duration = Duration::from_millis(50);
pub const HANDSHAKE_RETRY_INTERVAL: Duration = Duration::from_millis(500);

type Due = (Instant, u64, usize);

struct PendingDispatch {
    advance_cookie_turn: bool,
}

struct Endpoint {
    address: SocketAddr,
    aliases: Vec<usize>,
    due: Option<Due>,
    pending: Option<PendingDispatch>,
    first_checked: Option<Instant>,
    sent_once: bool,
    retransmitted: bool,
    cookie: Option<[u8; COOKIE_LEN]>,
    plain_turn: bool,
    immediate_cookie: bool,
    finished: bool,
}

pub struct RecoveryHandshake {
    endpoints: Vec<Endpoint>,
    indices: HashMap<SocketAddr, usize>,
    due: BTreeSet<Due>,
    sequence: u64,
    budget_at: Instant,
    remaining: usize,
    selected: Option<SocketAddr>,
    retired: bool,
}

impl RecoveryHandshake {
    pub fn new(now: Instant, endpoints: Vec<RecoveryEndpoint>) -> Self {
        let mut schedule = Self {
            endpoints: Vec::new(),
            indices: HashMap::new(),
            due: BTreeSet::new(),
            sequence: 0,
            budget_at: now,
            remaining: HANDSHAKE_SEND_BUDGET,
            selected: None,
            retired: false,
        };
        for endpoint in endpoints {
            if let Some(&index) = schedule.indices.get(&endpoint.endpoint) {
                let aliases = &mut schedule.endpoints[index].aliases;
                if !aliases.contains(&endpoint.address) {
                    aliases.push(endpoint.address);
                }
                continue;
            }
            let index = schedule.endpoints.len();
            schedule.indices.insert(endpoint.endpoint, index);
            schedule.endpoints.push(Endpoint {
                address: endpoint.endpoint,
                aliases: vec![endpoint.address],
                due: None,
                pending: None,
                first_checked: None,
                sent_once: false,
                retransmitted: false,
                cookie: None,
                plain_turn: false,
                immediate_cookie: false,
                finished: false,
            });
            schedule.enqueue(index, now);
        }
        schedule
    }

    fn enqueue(&mut self, index: usize, now: Instant) {
        if self.retired || self.endpoints[index].finished {
            return;
        }
        let Some(sequence) = self.sequence.checked_add(1) else {
            // Fail closed rather than wrap ordering and revive old work.
            self.retire();
            return;
        };
        self.sequence = sequence;
        let endpoint = &mut self.endpoints[index];
        if let Some(previous) = endpoint.due.take() {
            self.due.remove(&previous);
        }
        let due = (now, sequence, index);
        endpoint.due = Some(due);
        self.due.insert(due);
    }

    /// Reserve bounded dispatches. The I/O owner calls `sent` for each one.
    /// Repeated polling at the same time cannot replenish the allowance.
    pub fn poll(&mut self, now: Instant) -> Vec<HandshakeDispatch> {
        if self.retired {
            return Vec::new();
        }
        if now >= self.budget_at + HANDSHAKE_SERVICE_INTERVAL {
            self.budget_at = now;
            self.remaining = HANDSHAKE_SEND_BUDGET;
        }
        let mut work = Vec::new();
        while self.remaining > 0 {
            let Some(&(at, _, index)) = self.due.first() else {
                break;
            };
            if at > now {
                break;
            }
            self.due.pop_first();
            let endpoint = &mut self.endpoints[index];
            endpoint.due = None;
            let immediate = std::mem::take(&mut endpoint.immediate_cookie);
            endpoint.pending = Some(PendingDispatch {
                advance_cookie_turn: !immediate && endpoint.cookie.is_some(),
            });
            let cookie = if immediate || !endpoint.plain_turn {
                endpoint.cookie
            } else {
                None
            };
            work.push(HandshakeDispatch {
                endpoint: endpoint.address,
                cookie,
            });
            self.remaining -= 1;
        }
        work
    }

    /// A real socket send was attempted, successfully or with an explicit error.
    /// An unsent reservation is never evidence for a completed endpoint check.
    pub fn sent(&mut self, now: Instant, address: SocketAddr, success: bool) {
        if self.retired {
            return;
        }
        let Some(&index) = self.indices.get(&address) else {
            return;
        };
        let endpoint = &mut self.endpoints[index];
        if endpoint.finished {
            return;
        }
        let Some(pending) = endpoint.pending.take() else {
            return;
        };
        endpoint.retransmitted |= endpoint.first_checked.is_some();
        endpoint.first_checked.get_or_insert(now);
        endpoint.sent_once |= success;
        if pending.advance_cookie_turn {
            endpoint.plain_turn = !endpoint.plain_turn;
        }
        let next = if endpoint.immediate_cookie {
            now
        } else {
            now + HANDSHAKE_RETRY_INTERVAL
        };
        self.enqueue(index, next);
    }

    pub fn aliases(&self, address: SocketAddr) -> &[usize] {
        self.indices
            .get(&address)
            .map_or(&[], |&index| self.endpoints[index].aliases.as_slice())
    }

    pub fn addresses(&self) -> impl Iterator<Item = SocketAddr> + '_ {
        self.endpoints.iter().map(|endpoint| endpoint.address)
    }

    pub fn first_checked(&self, address: SocketAddr) -> Option<Instant> {
        self.indices
            .get(&address)
            .and_then(|&index| self.endpoints[index].first_checked)
    }

    pub fn retransmitted(&self, address: SocketAddr) -> bool {
        self.indices
            .get(&address)
            .is_some_and(|&index| self.endpoints[index].retransmitted)
    }

    pub fn can_select(&self, address: SocketAddr) -> bool {
        !self.retired
            && self.selected.is_none()
            && self.indices.get(&address).is_some_and(|&index| {
                let endpoint = &self.endpoints[index];
                !endpoint.finished && endpoint.sent_once
            })
    }

    pub fn select(&mut self, address: SocketAddr) -> bool {
        if !self.can_select(address) {
            return false;
        }
        self.selected = Some(address);
        true
    }

    pub fn selected(&self) -> Option<SocketAddr> {
        self.selected
    }

    /// Caller verifies the msg1 echo first. A cookie never changes a deadline.
    pub fn on_cookie(
        &mut self,
        now: Instant,
        address: SocketAddr,
        cookie: [u8; COOKIE_LEN],
    ) -> bool {
        if self.retired {
            return false;
        }
        let Some(&index) = self.indices.get(&address) else {
            return false;
        };
        let endpoint = &mut self.endpoints[index];
        if endpoint.finished || !endpoint.sent_once {
            return false;
        }
        let first = endpoint.cookie.replace(cookie).is_none();
        if first {
            endpoint.immediate_cookie = true;
            endpoint.plain_turn = false;
            if endpoint.pending.is_none() {
                self.enqueue(index, now);
            }
        }
        true
    }

    pub fn finish(&mut self, address: SocketAddr) {
        let Some(&index) = self.indices.get(&address) else {
            return;
        };
        let endpoint = &mut self.endpoints[index];
        endpoint.finished = true;
        endpoint.pending = None;
        if let Some(due) = endpoint.due.take() {
            self.due.remove(&due);
        }
    }

    pub fn retire(&mut self) {
        self.retired = true;
        self.due.clear();
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        self.due.first().map(|&(at, _, _)| {
            if self.remaining == 0 {
                at.max(self.budget_at + HANDSHAKE_SERVICE_INTERVAL)
            } else {
                at
            }
        })
    }
}

#[cfg(test)]
#[path = "recovery_handshake_tests.rs"]
mod tests;
