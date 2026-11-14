//! Explicit consent for one account's unmanaged personal transport service.
use serde::{Deserialize, Serialize};

use crate::{BusyAttemptId, CandidateImageIdentity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonalServiceProfile {
    PersonalTransportV1,
}

/// Descriptive selector only. The helper must independently derive its route
/// and account; these fields never authorize opening a caller-selected socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersonalServiceSelector {
    pub profile: PersonalServiceProfile,
    pub uid: u32,
    pub endpoint: String,
    pub port: u16,
}
impl PersonalServiceSelector {
    pub fn valid(&self) -> bool {
        self.uid != 0
            && self.port != 0
            && self.endpoint.starts_with('/')
            && self.endpoint.len() <= 2048
            && !self.endpoint.chars().any(char::is_control)
            && self.endpoint.ends_with("/control.sock")
            && !self
                .endpoint
                .split('/')
                .any(|part| matches!(part, "." | ".."))
    }
}
impl<'de> Deserialize<'de> for PersonalServiceSelector {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            profile: PersonalServiceProfile,
            uid: u32,
            endpoint: String,
            port: u16,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            profile: fields.profile,
            uid: fields.uid,
            endpoint: fields.endpoint,
            port: fields.port,
        };
        if value.valid() {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(
                "invalid personal service selector",
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRestartAction {
    RestartAccountService,
}

/// User confirmation, not an exact-process capability or a retry grant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceRestartConsent {
    pub attempt: BusyAttemptId,
    pub service: PersonalServiceSelector,
    pub candidate: CandidateImageIdentity,
    pub action: ServiceRestartAction,
}
impl ServiceRestartConsent {
    pub fn matches(&self, info: &crate::BusyDaemonInfo) -> bool {
        info.valid()
            && info.schema == 2
            && self.attempt == info.attempt
            && Some(&self.service) == info.service_restart.as_ref()
            && self.candidate == info.candidate
    }
}
