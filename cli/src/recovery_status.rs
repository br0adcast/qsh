//! Read-only recovery presentation. Logical names remain distinct even when
//! they resolve to the same socket; a configured route is not an active attempt.
use crate::recovery::Activity;
use connect::{recovery_gate::AddressId, Address};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QshState {
    Queued,
    Unresolved,
    Resolving,
    Checking,
    Trying,
}
impl QshState {
    fn text(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Unresolved => "unresolved",
            Self::Resolving => "resolving",
            Self::Checking => "checking",
            Self::Trying => "trying",
        }
    }
    fn active(self) -> bool {
        matches!(self, Self::Checking | Self::Trying)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SshState {
    Gated,
    Queued,
    Trying,
    Backoff(u64),
}
impl SshState {
    fn text(self) -> String {
        match self {
            Self::Gated => "waiting for QSH".into(),
            Self::Queued => "queued".into(),
            Self::Trying => "trying".into(),
            Self::Backoff(secs) => format!("retry in {secs} s"),
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub label: String,
    pub endpoint: Option<SocketAddr>,
    pub qsh: QshState,
    pub ssh: Option<(String, SshState)>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct View {
    pub targets: Vec<Target>,
}
impl View {
    pub fn build(
        addresses: &[Address],
        endpoints: &[(AddressId, SocketAddr)],
        resolving: &[AddressId],
        warm: &[(SocketAddr, Instant)],
        activity: Option<&Activity>,
        now: Instant,
    ) -> Self {
        Self::build_with_deadline(addresses, endpoints, resolving, warm, activity, now).0
    }

    pub fn build_with_deadline(
        addresses: &[Address],
        endpoints: &[(AddressId, SocketAddr)],
        resolving: &[AddressId],
        warm: &[(SocketAddr, Instant)],
        activity: Option<&Activity>,
        now: Instant,
    ) -> (Self, Option<Instant>) {
        let mut deadline: Option<Instant> = None;
        let targets = addresses
            .iter()
            .enumerate()
            .map(|(i, addr)| {
                let id = AddressId(i);
                let current = activity.and_then(|a| a.qsh.iter().find(|q| q.address == id));
                let endpoint = current
                    .and_then(|q| q.endpoint)
                    .or_else(|| endpoints.iter().find(|(a, _)| *a == id).map(|(_, e)| *e));
                let qsh = if let Some(current) = current {
                    if current.endpoint.is_some() {
                        QshState::Trying
                    } else {
                        QshState::Resolving
                    }
                } else if endpoint.is_some_and(|e| {
                    warm.iter().any(|(probe, sent)| {
                        *probe == e
                            && now.saturating_duration_since(*sent)
                                < transport::paths::PROBE_TIMEOUT
                    })
                }) {
                    QshState::Checking
                } else if resolving.contains(&id) {
                    QshState::Resolving
                } else if endpoint.is_none() {
                    QshState::Unresolved
                } else {
                    QshState::Queued
                };
                if qsh == QshState::Checking {
                    if let Some(expires) = warm
                        .iter()
                        .filter(|(probe, _)| Some(*probe) == endpoint)
                        .filter_map(|(_, sent)| sent.checked_add(transport::paths::PROBE_TIMEOUT))
                        .filter(|expires| *expires > now)
                        .max()
                    {
                        deadline = Some(deadline.map_or(expires, |previous| previous.min(expires)));
                    }
                }
                let label = target(&addr.host, addr.qsh_port);
                let ssh = addr.ssh.as_ref().map(|route| {
                    let state = match activity {
                        Some(a) if a.ssh == Some(id) => SshState::Trying,
                        Some(a) if a.ssh_retry_at.is_some_and(|until| until > now) => {
                            let left = a.ssh_retry_at.unwrap().duration_since(now);
                            let seconds = left.as_secs() + u64::from(left.subsec_nanos() > 0);
                            let next = a.ssh_retry_at.unwrap() - Duration::from_secs(seconds - 1);
                            deadline = Some(deadline.map_or(next, |previous| previous.min(next)));
                            SshState::Backoff(seconds)
                        }
                        Some(a) if a.ssh_allowed => SshState::Queued,
                        _ => SshState::Gated,
                    };
                    (target(&addr.host, route.port), state)
                });
                Target {
                    host: crate::report::printable(&addr.host),
                    label,
                    endpoint,
                    qsh,
                    ssh,
                }
            })
            .collect();
        (Self { targets }, deadline)
    }
    /// Stable text and positions: only brightness depends on worker activity.
    pub fn header_spans(&self) -> Vec<(String, bool)> {
        let mut spans = vec![("reconnecting: ".into(), false)];
        for (i, target) in self.targets.iter().enumerate() {
            if i > 0 {
                spans.push((", ".into(), false));
            }
            let qsh = target.qsh.active();
            let ssh = target
                .ssh
                .as_ref()
                .is_some_and(|(_, state)| *state == SshState::Trying);
            spans.push((target.host.clone(), false));
            spans.push((" [".into(), false));
            spans.push(("QSH".into(), qsh));
            if target.ssh.is_some() {
                spans.push(("/".into(), false));
                spans.push(("SSH".into(), ssh));
            }
            spans.push(("]".into(), false));
        }
        spans
    }

    pub fn header(&self) -> String {
        self.header_spans()
            .into_iter()
            .map(|(text, _)| text)
            .collect()
    }
    pub fn details(&self) -> Vec<String> {
        self.targets
            .iter()
            .enumerate()
            .flat_map(|(i, t)| {
                let endpoint = t.endpoint.map(|e| format!(" -> {e}")).unwrap_or_default();
                let mut state = format!("   QSH: {}", t.qsh.text());
                if let Some((label, ssh)) = &t.ssh {
                    state.push_str(&format!(" | SSH: {label} ({})", ssh.text()));
                }
                [format!("{}. {}{endpoint}", i + 1, t.label), state]
            })
            .collect()
    }
}
fn target(host: &str, port: u16) -> String {
    format!(
        "{}:{port}",
        crate::status::bracketed(&crate::report::printable(host))
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    fn address(host: &str) -> Address {
        Address {
            host: host.into(),
            qsh_port: 60000,
            ssh: Some(connect::SshRoute {
                port: 22,
                knock: Vec::new(),
            }),
        }
    }
    #[test]
    fn ui_wait_recovery_backoff_keeps_its_fractional_ceil_phase() {
        let start = Instant::now();
        let addresses = [address("example.test")];
        let activity = Activity {
            qsh: Vec::new(),
            ssh: None,
            ssh_retry_at: Some(start + Duration::from_millis(10250)),
            ssh_allowed: true,
        };
        for (at, secs, next) in [
            (7000, 4, 7250),
            (7250, 3, 8250),
            (8250, 2, 9250),
            (9250, 1, 10250),
        ] {
            let (view, deadline) = View::build_with_deadline(
                &addresses,
                &[],
                &[],
                &[],
                Some(&activity),
                start + Duration::from_millis(at),
            );
            assert_eq!(
                view.targets[0].ssh.as_ref().unwrap().1,
                SshState::Backoff(secs)
            );
            assert_eq!(deadline, Some(start + Duration::from_millis(next)));
        }
        let (view, deadline) = View::build_with_deadline(
            &addresses,
            &[],
            &[],
            &[],
            Some(&activity),
            start + Duration::from_millis(10250),
        );
        assert_eq!(view.targets[0].ssh.as_ref().unwrap().1, SshState::Queued);
        assert_eq!(deadline, None);
    }
    #[test]
    fn ui_wait_recovery_individual_checking_expiry_precedes_group_maximum() {
        let start = Instant::now();
        let addresses = [address("first.test"), address("second.test")];
        let a = "192.0.2.1:60000".parse().unwrap();
        let b = "192.0.2.2:60000".parse().unwrap();
        let endpoints = [(AddressId(0), a), (AddressId(1), b)];
        let warm = [(a, start), (b, start + Duration::from_millis(400))];
        let (view, deadline) =
            View::build_with_deadline(&addresses, &endpoints, &[], &warm, None, start);
        assert_eq!(view.targets[0].qsh, QshState::Checking);
        assert_eq!(deadline, Some(start + transport::paths::PROBE_TIMEOUT));
        let (view, deadline) = View::build_with_deadline(
            &addresses,
            &endpoints,
            &[],
            &warm,
            None,
            start + transport::paths::PROBE_TIMEOUT,
        );
        assert_eq!(view.targets[0].qsh, QshState::Queued);
        assert_eq!(view.targets[1].qsh, QshState::Checking);
        assert_eq!(
            deadline,
            Some(start + Duration::from_millis(400) + transport::paths::PROBE_TIMEOUT)
        );
    }
}
