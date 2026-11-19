//! Untrusted admission bytes and pure correlation, never peer/FD authority.
use super::protocol::{OwnerProtocolError as Error, OwnerRole};
use super::wire::Reader;
use transport::session_resume::{HostInstance, OwnerInstance};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAdmission {
    Offer {
        channel: [u8; 16],
        challenge: [u8; 32],
        min_version: u16,
        max_version: u16,
    },
    Ack {
        channel: [u8; 16],
        challenge: [u8; 32],
        selected_version: u16,
    },
}
impl LocalAdmission {
    pub const fn kind(&self) -> u8 {
        match self {
            Self::Offer { .. } => 3,
            Self::Ack { .. } => 4,
        }
    }
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Offer { .. } => 52,
            Self::Ack { .. } => 50,
        }
    }
    pub(super) fn validate(&self) -> Result<(), Error> {
        let (channel, challenge) = match self {
            Self::Offer {
                channel,
                challenge,
                min_version,
                max_version,
            } => {
                if *min_version == 0 || *min_version > 1 || *max_version < 1 {
                    return Err(Error::UnsupportedVersion);
                }
                (channel, challenge)
            }
            Self::Ack {
                channel,
                challenge,
                selected_version,
            } => {
                if *selected_version != 1 {
                    return Err(Error::UnsupportedVersion);
                }
                (channel, challenge)
            }
        };
        if *channel == [0; 16] || *challenge == [0; 32] {
            return Err(Error::Malformed);
        }
        Ok(())
    }
    pub(super) fn role_allowed(&self, role: OwnerRole, owner_specific: bool) -> bool {
        if owner_specific {
            match self {
                Self::Offer { .. } => matches!(role, OwnerRole::Frontend | OwnerRole::Owner),
                Self::Ack { .. } => matches!(role, OwnerRole::Owner | OwnerRole::Host),
            }
        } else {
            match self {
                Self::Offer { .. } => role == OwnerRole::Frontend,
                Self::Ack { .. } => role == OwnerRole::Host,
            }
        }
    }
    pub(super) fn put(&self, out: &mut Vec<u8>) {
        match self {
            Self::Offer {
                channel,
                challenge,
                min_version,
                max_version,
            } => {
                out.extend_from_slice(channel);
                out.extend_from_slice(challenge);
                out.extend_from_slice(&min_version.to_be_bytes());
                out.extend_from_slice(&max_version.to_be_bytes());
            }
            Self::Ack {
                channel,
                challenge,
                selected_version,
            } => {
                out.extend_from_slice(channel);
                out.extend_from_slice(challenge);
                out.extend_from_slice(&selected_version.to_be_bytes());
            }
        }
    }
    pub(super) fn read(kind: u8, r: &mut Reader<'_>) -> Result<Self, Error> {
        let channel = r.array()?;
        let challenge = r.array()?;
        let v = match kind {
            3 => Self::Offer {
                channel,
                challenge,
                min_version: r.u16()?,
                max_version: r.u16()?,
            },
            4 => Self::Ack {
                channel,
                challenge,
                selected_version: r.u16()?,
            },
            _ => return Err(Error::UnknownKind(kind)),
        };
        v.validate()?;
        Ok(v)
    }
    pub(super) fn matches_reply(&self, other: &Self) -> bool {
        matches!((self,other),(Self::Offer{channel:a,challenge:b,min_version,max_version},Self::Ack{channel:c,challenge:d,selected_version}) if a==c&&b==d&&min_version<=selected_version&&selected_version<=max_version)
    }
}
/// A caller-provided routing expectation. This is freely constructible data,
/// not the future nonclone locally provisioned descriptor/credential record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionSpec {
    pub host: HostInstance,
    pub owner: Option<OwnerInstance>,
    pub requester: OwnerRole,
    pub channel: [u8; 16],
    pub challenge: [u8; 32],
    pub min_version: u16,
    pub max_version: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct AdmissionState {
    spec: AdmissionSpec,
    pending: Option<u64>,
    ready: bool,
}
impl AdmissionState {
    pub(super) fn new(
        spec: AdmissionSpec,
        local: OwnerRole,
        peer: OwnerRole,
        host: HostInstance,
        owner: Option<OwnerInstance>,
    ) -> Result<Self, Error> {
        let responder = match (spec.owner, spec.requester) {
            (None, OwnerRole::Frontend) | (Some(_), OwnerRole::Owner) => OwnerRole::Host,
            (Some(_), OwnerRole::Frontend) => OwnerRole::Owner,
            _ => return Err(Error::Binding),
        };
        if spec.host != host
            || spec.owner != owner
            || !((local == spec.requester && peer == responder)
                || (peer == spec.requester && local == responder))
        {
            return Err(Error::Binding);
        }
        LocalAdmission::Offer {
            channel: spec.channel,
            challenge: spec.challenge,
            min_version: spec.min_version,
            max_version: spec.max_version,
        }
        .validate()?;
        Ok(Self {
            spec,
            pending: None,
            ready: false,
        })
    }
    pub(super) fn ready(&self) -> bool {
        self.ready
    }
    pub(super) fn apply(
        &mut self,
        id: u64,
        role: OwnerRole,
        m: &LocalAdmission,
    ) -> Result<(), Error> {
        m.validate()?;
        if self.ready || id == 0 {
            return Err(Error::InvalidState);
        }
        match m {
            LocalAdmission::Offer {
                channel,
                challenge,
                min_version,
                max_version,
            } => {
                if self.pending.is_some()
                    || role != self.spec.requester
                    || *channel != self.spec.channel
                    || *challenge != self.spec.challenge
                    || *min_version != self.spec.min_version
                    || *max_version != self.spec.max_version
                {
                    return Err(Error::Binding);
                }
                self.pending = Some(id);
            }
            LocalAdmission::Ack {
                channel, challenge, ..
            } => {
                if self.pending != Some(id)
                    || role == self.spec.requester
                    || *channel != self.spec.channel
                    || *challenge != self.spec.challenge
                {
                    return Err(Error::Binding);
                }
                self.pending = None;
                self.ready = true;
            }
        }
        Ok(())
    }
}
