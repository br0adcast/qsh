//! Attempt-local concurrent discovery. Silence remains unknown; admission never waits.
use crate::bootstrap::{BootstrapClient, BootstrapError, VerifiedServerInfo};
use crate::Datagram;
use rand::RngCore;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

const RETRY: Duration = Duration::from_millis(300);
const LIFETIME: Duration = Duration::from_secs(2);
struct Probe {
    endpoint: SocketAddr,
    client: BootstrapClient,
    next: Instant,
    done: bool,
}
pub struct DiscoveryRound {
    probes: Vec<Probe>,
    deadline: Instant,
}
impl DiscoveryRound {
    pub fn new(
        now: Instant,
        endpoints: impl IntoIterator<Item = SocketAddr>,
        local_private: [u8; 32],
        pinned_server: [u8; 32],
    ) -> Self {
        let secret = zeroize::Zeroizing::new(local_private);
        let mut probes: Vec<Probe> = Vec::new();
        for endpoint in endpoints {
            if probes.iter().any(|p| p.endpoint == endpoint) {
                continue;
            }
            let mut challenge = [0; 32];
            rand::rngs::OsRng.fill_bytes(&mut challenge);
            probes.push(Probe {
                endpoint,
                client: BootstrapClient::new(*secret, pinned_server, challenge),
                next: now,
                done: false,
            });
        }
        Self {
            probes,
            deadline: now + LIFETIME,
        }
    }
    pub fn poll(&mut self, now: Instant) -> Vec<Datagram> {
        if now >= self.deadline {
            self.expire(now);
            return Vec::new();
        }
        self.probes
            .iter_mut()
            .filter_map(|p| {
                if p.done || now < p.next {
                    return None;
                }
                p.next = now + RETRY;
                Some(Datagram {
                    to: p.endpoint,
                    bytes: p.client.request(),
                })
            })
            .collect()
    }
    pub fn deadline(&self) -> Instant {
        self.deadline
    }
    pub fn is_complete(&self, now: Instant) -> bool {
        now >= self.deadline || self.probes.iter().all(|probe| probe.done)
    }
    pub fn next_deadline(&self) -> Option<Instant> {
        self.probes
            .iter()
            .filter(|p| !p.done)
            .map(|p| p.next.min(self.deadline))
            .min()
    }
    pub fn accept(
        &mut self,
        now: Instant,
        source: SocketAddr,
        bytes: &[u8],
    ) -> Option<VerifiedServerInfo> {
        if now >= self.deadline {
            for p in &mut self.probes {
                p.done = true;
            }
            return None;
        }
        let p = self
            .probes
            .iter_mut()
            .find(|p| p.endpoint == source && !p.done)?;
        match p.client.accept(bytes) {
            Ok(info) => {
                p.done = true;
                Some(info)
            }
            Err(BootstrapError::Retry) => {
                p.next = now;
                None
            }
            _ => None,
        }
    }
    pub fn expire(&mut self, now: Instant) {
        if now >= self.deadline {
            for p in &mut self.probes {
                p.done = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootstrap::{BootstrapResponder, ServerInfo, SessionProfile};
    use crate::handshake::generate_keypair;
    #[test]
    fn bootstrap_round_keeps_alternatives_live_and_rejects_retired_reply() {
        let now = Instant::now();
        let server = generate_keypair();
        let wrong = generate_keypair();
        let local = generate_keypair();
        let a = "192.0.2.1:1".parse().unwrap();
        let b = "192.0.2.2:1".parse().unwrap();
        let source = "192.0.2.3:1".parse().unwrap();
        let info = ServerInfo {
            generation: [4; 16],
            core_version: "0.6.0".into(),
            session_protocols: vec![SessionProfile {
                wire: 99,
                handshake: 99,
                channel: 99,
            }],
        };
        let mut good = BootstrapResponder::new(server.private, info.clone()).unwrap();
        let mut bad = BootstrapResponder::new(wrong.private, info.clone()).unwrap();
        let mut round = DiscoveryRound::new(now, [a, b], local.private, server.public);
        let first = round.poll(now);
        assert_eq!(first.len(), 2);
        for dg in first {
            let responder = if dg.to == a { &mut bad } else { &mut good };
            let cookie = responder.on_datagram(now, source, &dg.bytes).unwrap();
            assert!(round.accept(now, dg.to, &cookie).is_none());
        }
        let retry = round.poll(now);
        assert_eq!(retry.len(), 2);
        let mut response = None;
        for dg in retry {
            let responder = if dg.to == a { &mut bad } else { &mut good };
            if let Some(reply) = responder.on_datagram(now, source, &dg.bytes) {
                assert_eq!(dg.to, b);
                response = Some(reply);
            }
        }
        let response = response.unwrap();
        assert_eq!(round.accept(now, b, &response).unwrap().info(), &info);
        assert!(round.accept(now, b, &response).is_none());
        let mut fresh = DiscoveryRound::new(now, [b], local.private, server.public);
        assert!(fresh.accept(now, b, &response).is_none());
        round.expire(now + LIFETIME);
        assert!(round.poll(now + LIFETIME).is_empty());
        assert!(round.next_deadline().is_none());
    }
    #[test]
    fn bootstrap_round_checks_last_of_more_than_64_configured_endpoints() {
        let now = Instant::now();
        let server = generate_keypair();
        let local = generate_keypair();
        let endpoints: Vec<SocketAddr> = (1..=70)
            .map(|port| SocketAddr::from(([192, 0, 2, 1], port)))
            .collect();
        let last = *endpoints.last().unwrap();
        let mut round = DiscoveryRound::new(now, endpoints.clone(), local.private, server.public);
        let sends = round.poll(now);
        assert_eq!(sends.len(), 70);
        let request = &sends.iter().find(|dg| dg.to == last).unwrap().bytes;
        let info = ServerInfo {
            generation: [1; 16],
            core_version: "0.6.0".into(),
            session_protocols: vec![],
        };
        let mut responder = BootstrapResponder::new(server.private, info.clone()).unwrap();
        let source = "192.0.2.7:5000".parse().unwrap();
        let cookie = responder.on_datagram(now, source, request).unwrap();
        round.accept(now, last, &cookie);
        let retry = round.poll(now);
        assert_eq!(retry.len(), 1);
        assert_eq!(retry[0].to, last);
        let response = responder.on_datagram(now, source, &retry[0].bytes).unwrap();
        assert_eq!(round.accept(now, last, &response).unwrap().info(), &info);
        let mut new_round = DiscoveryRound::new(now, endpoints, local.private, server.public);
        assert!(new_round.accept(now, last, &response).is_none());
    }
}
