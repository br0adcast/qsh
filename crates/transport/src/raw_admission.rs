//! Fresh-key admission for the two single-client diagnostic server owners.
//! A bounded candidate may answer transport traffic, but cannot replace the
//! active connection or touch its shell until fresh possession is confirmed.

use std::net::SocketAddr;
use std::time::Instant;

use crate::conn::{AuthPolicy, Connection, ConnectionConfig, Datagram, Event, LinkState};
use crate::wire::{parse, Frame, Kind};

#[derive(Default)]
pub(crate) struct PendingAdmission {
    candidate: Option<Candidate>,
}

struct Candidate {
    conn: Connection,
    deadline: Instant,
}

pub(crate) struct Admitted {
    pub conn: Connection,
    pub events: Vec<Event>,
}

pub(crate) enum PacketResult {
    Unrelated,
    Handled,
    Admitted(Box<Admitted>),
}

impl PendingAdmission {
    pub(crate) fn next_timeout(&self) -> Option<Instant> {
        self.candidate.as_ref().map(|candidate| {
            candidate
                .conn
                .next_timeout()
                .map_or(candidate.deadline, |next| next.min(candidate.deadline))
        })
    }

    fn expire(&mut self, now: Instant) {
        if self
            .candidate
            .as_ref()
            .is_some_and(|candidate| now >= candidate.deadline)
        {
            self.candidate = None;
        }
    }

    pub(crate) fn on_timeout(&mut self, now: Instant, out: &mut Vec<Datagram>) {
        self.expire(now);
        if let Some(candidate) = self.candidate.as_mut() {
            out.extend(candidate.conn.on_timeout_if_due(now));
            if candidate.conn.poll_events().iter().any(fatal) {
                self.candidate = None;
            }
        }
    }

    pub(crate) fn on_packet(
        &mut self,
        cfg: &ConnectionConfig,
        now: Instant,
        src: SocketAddr,
        bytes: &[u8],
        out: &mut Vec<Datagram>,
    ) -> PacketResult {
        self.expire(now);
        match parse(bytes) {
            Ok(Frame::Handshake {
                kind: Kind::HandshakeInit,
                ..
            }) => {
                // These raw owners have no signature verifier. A static key
                // allowlist and a fresh authenticated packet are both required.
                if !matches!(cfg.auth, AuthPolicy::Allowlist(_)) {
                    return PacketResult::Handled;
                }
                // These raw diagnostic owners implement fresh-key proof, but
                // no committed admission acknowledgement. Never advertise it
                // just because the transport codec implements the bit.
                let mut raw = cfg.clone();
                raw.features = crate::Features::from_bits(
                    raw.features.bits() & !crate::Features::AUTH_ACCEPTED.bits(),
                );
                let mut conn = Connection::new(raw);
                let reply = conn.on_datagram(now, src, bytes);
                if conn.state() == LinkState::Live {
                    conn.set_undelivered_cap(crate::probation::PROBATION_UNDELIVERED_MAX);
                    let _ = conn.poll_events();
                    self.candidate = Some(Candidate {
                        conn,
                        deadline: now + crate::auth::AUTH_DEADLINE,
                    });
                    out.extend(reply);
                }
                PacketResult::Handled
            }
            Ok(Frame::Transport { session_id, .. }) => {
                let Some(candidate) = self
                    .candidate
                    .as_mut()
                    .filter(|c| c.conn.session_id() == session_id)
                else {
                    return PacketResult::Unrelated;
                };
                out.extend(candidate.conn.on_datagram(now, src, bytes));
                let events = candidate.conn.poll_events();
                // Inspect the complete batch: a proof preceding Close or an
                // exhausted stream cannot authorize any application effects.
                if events.iter().any(fatal) {
                    self.candidate = None;
                    return PacketResult::Handled;
                }
                if !events
                    .iter()
                    .any(|event| matches!(event, Event::PeerKeyConfirmed { .. }))
                {
                    return PacketResult::Handled;
                }
                let cost = events.iter().fold(0usize, |sum, event| {
                    sum.saturating_add(std::mem::size_of::<Event>())
                        .saturating_add(match event {
                            Event::StreamData { data, .. } => data.len(),
                            _ => 0,
                        })
                });
                if cost > crate::probation::PROBATION_UNDELIVERED_MAX {
                    self.candidate = None;
                    return PacketResult::Handled;
                }
                let mut candidate = self.candidate.take().expect("matched candidate");
                candidate
                    .conn
                    .set_undelivered_cap(crate::conn::UNDELIVERED_CAP);
                PacketResult::Admitted(Box::new(Admitted {
                    conn: candidate.conn,
                    events,
                }))
            }
            _ => PacketResult::Unrelated,
        }
    }
}

fn fatal(event: &Event) -> bool {
    matches!(
        event,
        Event::StateChanged(LinkState::Closed) | Event::OffsetSpaceExhausted { .. }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::Role;
    use crate::handshake::generate_keypair;
    use crate::reliability::StreamFrame;

    fn fixture() -> (
        PendingAdmission,
        ConnectionConfig,
        Connection,
        SocketAddr,
        Instant,
    ) {
        let server = generate_keypair();
        let client = generate_keypair();
        let cfg = ConnectionConfig {
            required_features: crate::Features::NONE,
            features: crate::Features::SUPPORTED,
            role: Role::Server,
            local_static_priv: server.private,
            remote_static_pub: None,
            auth: AuthPolicy::Allowlist(vec![client.public]),
        };
        let mut client = Connection::new(ConnectionConfig {
            role: Role::Client,
            local_static_priv: client.private,
            remote_static_pub: Some(server.public),
            auth: AuthPolicy::Allowlist(Vec::new()),
            ..cfg.clone()
        });
        let now = Instant::now();
        let src = "127.0.0.1:10101".parse().unwrap();
        let dst = "127.0.0.1:10102".parse().unwrap();
        let msg1 = client.start(now, dst).remove(0);
        let mut pending = PendingAdmission::default();
        let mut out = Vec::new();
        assert!(matches!(
            pending.on_packet(&cfg, now, src, &msg1.bytes, &mut out),
            PacketResult::Handled
        ));
        assert_eq!(out.len(), 1);
        client.on_datagram(now, dst, &out[0].bytes);
        (pending, cfg, client, src, now)
    }

    #[test]
    fn raw_admission_preserves_data_from_the_fresh_proof_packet() {
        let (mut pending, cfg, mut client, src, now) = fixture();
        let packet = client
            .frames_for_test(vec![StreamFrame::Data {
                stream_id: 0,
                offset: 0,
                data: b"first".to_vec(),
            }])
            .remove(0);
        let mut out = Vec::new();
        let PacketResult::Admitted(admitted) =
            pending.on_packet(&cfg, now, src, &packet.bytes, &mut out)
        else {
            panic!("fresh data must prove possession")
        };
        assert!(admitted.events.iter().any(
            |event| matches!(event, Event::StreamData { stream_id: 0, data } if data == b"first")
        ));
        assert!(pending.candidate.is_none());
    }

    #[test]
    fn raw_admission_close_wins_over_proof_and_data_in_the_same_packet() {
        let (mut pending, cfg, mut client, src, now) = fixture();
        let packet = client.packed_for_test(vec![
            StreamFrame::Ping { token: 1 },
            StreamFrame::Data {
                stream_id: 0,
                offset: 0,
                data: b"never applied".to_vec(),
            },
            StreamFrame::Close { stream_id: 0 },
        ]);
        assert!(matches!(
            pending.on_packet(&cfg, now, src, &packet.bytes, &mut Vec::new()),
            PacketResult::Handled
        ));
        assert!(pending.candidate.is_none());
    }

    #[test]
    fn raw_admission_expires_before_dispatching_a_late_fresh_packet() {
        let (mut pending, cfg, mut client, src, now) = fixture();
        let deadline = now + crate::auth::AUTH_DEADLINE;
        let packet = client
            .frames_for_test(vec![StreamFrame::Ping { token: 1 }])
            .remove(0);
        assert!(matches!(
            pending.on_packet(&cfg, deadline, src, &packet.bytes, &mut Vec::new()),
            PacketResult::Unrelated
        ));
        assert!(pending.candidate.is_none());
    }
    #[test]
    fn auth17_raw_owner_explicitly_excludes_admission_acceptance() {
        let (pending, _, client, _, _) = fixture();
        assert!(!client.features().contains(crate::Features::AUTH_ACCEPTED));
        assert!(!pending
            .candidate
            .as_ref()
            .unwrap()
            .conn
            .features()
            .contains(crate::Features::AUTH_ACCEPTED));
    }
}
