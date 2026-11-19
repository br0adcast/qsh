//! Typed authenticated metadata and connection-generation binding.
use connect::upgrade::{evaluate_upgrade, ReleaseChannel, UpgradeDecision};
use transport::bootstrap::{ServerInfo, SessionProfile, VerifiedServerInfo};

#[derive(Clone, Debug)]
pub enum AuthenticatedServerInfo {
    Bootstrap(VerifiedServerInfo),
    Ssh(ssh::VerifiedSshServerInfo),
}

impl AuthenticatedServerInfo {
    pub fn info(&self) -> &ServerInfo {
        match self {
            Self::Bootstrap(proof) => proof.info(),
            Self::Ssh(proof) => proof.info(),
        }
    }

    /// A proof about another process cannot describe this attached transport.
    pub fn bound_to(&self, generation: Option<[u8; 16]>) -> Option<&ServerInfo> {
        (generation == Some(self.info().generation)).then(|| self.info())
    }
}

pub fn decision(info: Option<&ServerInfo>) -> UpgradeDecision {
    let version = env!("CARGO_PKG_VERSION");
    let channel = if semver::Version::parse(version).is_ok_and(|v| !v.pre.is_empty()) {
        ReleaseChannel::Preview
    } else {
        ReleaseChannel::Stable
    };
    evaluate_upgrade(
        version,
        SessionProfile {
            wire: transport::wire::VERSION,
            handshake: transport::handshake_payload::HS_VERSION,
            channel: transport::channel::PROTOCOL_VERSION,
        },
        info,
        channel,
    )
}

pub fn incompatibility(info: &ServerInfo) -> connect::NoAnswerWhy {
    connect::NoAnswerWhy::ServerIncompatible {
        version: info.core_version.clone(),
        wire: transport::wire::VERSION,
        handshake: transport::handshake_payload::HS_VERSION,
        channel: transport::channel::PROTOCOL_VERSION,
    }
}

/// Deduplicate advisory intent only; the working transport remains authoritative.
#[derive(Default)]
pub struct RestartAdvisory {
    seen: bool,
}
impl RestartAdvisory {
    pub fn observe(&mut self) -> bool {
        !std::mem::replace(&mut self.seen, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_intent_deduplicates_without_becoming_release_evidence() {
        let mut hint = RestartAdvisory::default();
        assert!(hint.observe());
        assert!(!hint.observe());
        assert_eq!(
            decision(None).compatibility,
            connect::upgrade::Compatibility::Unknown
        );
        assert!(decision(None).offer.is_none());
    }
}
