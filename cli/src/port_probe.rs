//! Best-effort ICMP refusal hints, independent of the unconnected multipath socket.
use std::collections::HashMap;
use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use connect::recovery_gate::{AddressId, RecoveryEpoch};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeResult {
    Pending,
    Refused {
        epoch: RecoveryEpoch,
        attempt: u64,
        target: SocketAddr,
    },
    Finished,
}

pub struct PortProbe {
    socket: Option<UdpSocket>,
    epoch: RecoveryEpoch,
    attempt: u64,
    target: SocketAddr,
}

impl PortProbe {
    pub fn start(target: SocketAddr, epoch: RecoveryEpoch, attempt: u64) -> io::Result<Self> {
        let bind = if target.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(bind)?;
        socket.connect(target)?;
        socket.set_nonblocking(true)?;
        socket.send(&transport::wire::encode_key_request())?;
        Ok(Self {
            socket: Some(socket),
            epoch,
            attempt,
            target,
        })
    }

    /// Borrowed only for the main owner's synchronous poll; no other thread closes it.
    pub fn raw_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.socket.as_ref().map(AsRawFd::as_raw_fd)
    }
    /// Responses are never trusted; only explicit refusal accelerates a caller.
    pub fn poll(&mut self) -> ProbeResult {
        let Some(socket) = &self.socket else {
            return ProbeResult::Finished;
        };
        let mut buf = [0; 256];
        let result = socket.recv(&mut buf);
        if matches!(&result, Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted))
        {
            return ProbeResult::Pending;
        }
        self.socket = None;
        if matches!(result, Err(e) if e.kind() == io::ErrorKind::ConnectionRefused) {
            ProbeResult::Refused {
                epoch: self.epoch,
                attempt: self.attempt,
                target: self.target,
            }
        } else {
            ProbeResult::Finished
        }
    }
}

/// A live transport gets a complete ordinary-probe pass before refusal can
/// retire it. Times use the owner's monotonic clock; no new sessions are made.
pub struct RefusalWindow {
    epoch: RecoveryEpoch,
    attempt: u64,
    started: Duration,
    addresses: Vec<AddressId>,
    probes: HashMap<SocketAddr, Duration>,
    refused: Option<SocketAddr>,
}

impl RefusalWindow {
    pub fn new(
        epoch: RecoveryEpoch,
        attempt: u64,
        started: Duration,
        addresses: Vec<AddressId>,
    ) -> Self {
        Self {
            epoch,
            attempt,
            started,
            addresses,
            probes: HashMap::new(),
            refused: None,
        }
    }

    pub fn observe_refusal(&mut self, result: ProbeResult) {
        if let ProbeResult::Refused {
            epoch,
            attempt,
            target,
        } = result
        {
            if epoch == self.epoch && attempt == self.attempt {
                self.refused = Some(target);
            }
        }
    }

    pub fn probed(&mut self, endpoint: SocketAddr, sent: Duration) {
        if sent >= self.started {
            self.probes.entry(endpoint).or_insert(sent);
        }
    }

    pub fn needs_probe_observation(&self, endpoints: &[(AddressId, SocketAddr)]) -> bool {
        self.addresses.iter().any(|id| {
            endpoints
                .iter()
                .find(|(candidate, _)| candidate == id)
                .is_some_and(|(_, endpoint)| !self.probes.contains_key(endpoint))
        })
    }
    pub fn next_deadline(
        &self,
        now: Duration,
        endpoints: &[(AddressId, SocketAddr)],
    ) -> Option<Duration> {
        let mut last = None;
        for id in &self.addresses {
            let deadline = match endpoints.iter().find(|(candidate, _)| candidate == id) {
                Some((_, endpoint)) => self
                    .probes
                    .get(endpoint)?
                    .checked_add(transport::paths::PROBE_TIMEOUT)?,
                None => self.started.checked_add(crate::road_catalog::DNS_TIMEOUT)?,
            };
            last = Some(last.map_or(deadline, |previous: Duration| previous.max(deadline)));
        }
        last.filter(|deadline| *deadline > now)
    }
    pub fn ready(
        &self,
        now: Duration,
        active: SocketAddr,
        endpoints: &[(AddressId, SocketAddr)],
        verified: &[SocketAddr],
    ) -> bool {
        self.refused == Some(active)
            && verified.is_empty()
            && !self.addresses.is_empty()
            && self.addresses.iter().all(|id| {
                match endpoints.iter().find(|(candidate, _)| candidate == id) {
                    Some((_, endpoint)) => self.probes.get(endpoint).is_some_and(|sent| {
                        now.saturating_sub(*sent) >= transport::paths::PROBE_TIMEOUT
                    }),
                    None => now.saturating_sub(self.started) >= crate::road_catalog::DNS_TIMEOUT,
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ui_wait_refusal_observes_missing_actual_send_then_waits_full_proof() {
        let epoch = RecoveryEpoch {
            connection: 1,
            network: 0,
        };
        let endpoint = "192.0.2.1:60000".parse().unwrap();
        let endpoints = [(AddressId(0), endpoint)];
        let mut window = RefusalWindow::new(epoch, 1, Duration::ZERO, vec![AddressId(0)]);
        assert!(window.needs_probe_observation(&endpoints));
        assert_eq!(window.next_deadline(Duration::ZERO, &endpoints), None);
        window.probed(endpoint, Duration::from_secs(1));
        assert!(!window.needs_probe_observation(&endpoints));
        assert_eq!(
            window.next_deadline(Duration::from_secs(1), &endpoints),
            Some(Duration::from_secs(1) + transport::paths::PROBE_TIMEOUT)
        );
        assert_eq!(
            window.next_deadline(
                Duration::from_secs(1) + transport::paths::PROBE_TIMEOUT,
                &endpoints
            ),
            None
        );
    }
    #[test]
    fn ui_wait_refusal_unknown_dns_uses_owner_timeout_not_busy_polling() {
        let window = RefusalWindow::new(
            RecoveryEpoch {
                connection: 1,
                network: 0,
            },
            1,
            Duration::ZERO,
            vec![AddressId(0)],
        );
        assert!(!window.needs_probe_observation(&[]));
        assert_eq!(
            window.next_deadline(Duration::ZERO, &[]),
            Some(crate::road_catalog::DNS_TIMEOUT)
        );
        assert_eq!(
            window.next_deadline(crate::road_catalog::DNS_TIMEOUT, &[]),
            None
        );
    }
}
