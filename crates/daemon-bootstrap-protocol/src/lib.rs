//! Identity-scoped startup decisions before registration or session handshake.
use serde::{Deserialize, Serialize};

fn hex_field(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Static executable API support, separate from live daemon/session metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapToolCapabilities {
    pub schema: u8,
    pub busy_decisions: bool,
}

/// Caller-generated correlation token, never a bearer capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BusyAttemptId(String);
impl BusyAttemptId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes.iter().map(|b| format!("{b:02x}")).collect())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for BusyAttemptId {
    type Error = &'static str;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        if hex_field(&value, 16) {
            Ok(Self(value))
        } else {
            Err("invalid busy attempt ID")
        }
    }
}
impl From<BusyAttemptId> for String {
    fn from(value: BusyAttemptId) -> Self {
        value.0
    }
}

/// Reported by the actual serving process over a trusted local/SSH route.
/// Missing modern generation is explicit; a PID alone is not a stop authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BusyDaemonIdentity {
    pub version: String,
    pub build: u64,
    pub checksum: String,
    pub pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
}
impl<'de> Deserialize<'de> for BusyDaemonIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            version: String,
            build: u64,
            checksum: String,
            pid: u32,
            generation: Option<String>,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            version: fields.version,
            build: fields.build,
            checksum: fields.checksum,
            pid: fields.pid,
            generation: fields.generation,
        };
        if value.valid() {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(
                "invalid BusyDaemonIdentity fields",
            ))
        }
    }
}

impl BusyDaemonIdentity {
    pub fn valid(&self) -> bool {
        !self.version.is_empty()
            && self.version.len() <= 128
            && self.version.is_ascii()
            && !self.version.bytes().any(|b| b.is_ascii_control())
            && hex_field(&self.checksum, 32)
            && self.generation.as_ref().is_none_or(|g| hex_field(g, 16))
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BusyChoice {
    #[default]
    Cancel,
    ContinueOld,
    ForceUpdate,
}

/// Absence of a qualified preservation contract never means safe to restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PreservationCapability {
    Unknown,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BusyDaemonInfo {
    pub schema: u8,
    pub attempt: BusyAttemptId,
    pub identity: BusyDaemonIdentity,
    pub active_connections: u64,
    /// Complete [wire, handshake, channel] profiles; None means unknown.
    pub serving_profiles: Option<Vec<[u8; 3]>>,
    pub preservation: PreservationCapability,
}
impl<'de> Deserialize<'de> for BusyDaemonInfo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            schema: u8,
            attempt: BusyAttemptId,
            identity: BusyDaemonIdentity,
            active_connections: u64,
            serving_profiles: Option<Vec<[u8; 3]>>,
            preservation: PreservationCapability,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            schema: fields.schema,
            attempt: fields.attempt,
            identity: fields.identity,
            active_connections: fields.active_connections,
            serving_profiles: fields.serving_profiles,
            preservation: fields.preservation,
        };
        if value.valid() {
            Ok(value)
        } else {
            Err(serde::de::Error::custom("invalid BusyDaemonInfo fields"))
        }
    }
}

impl BusyDaemonInfo {
    pub fn valid(&self) -> bool {
        self.schema == 1
            && self.identity.valid()
            && self.active_connections > 0
            && self.serving_profiles.as_ref().is_none_or(|p| p.len() <= 16)
    }
    /// Caller confirmation only, never a server-issued stop authority.
    pub fn confirm_destructive_restart(&self) -> DestructiveRestartConsent {
        DestructiveRestartConsent {
            attempt: self.attempt.clone(),
            identity: self.identity.clone(),
        }
    }
}

/// The local UI consumes this pending choice exactly once. This is ownership,
/// not a server-enforced anti-replay or destructive-operation capability.
#[derive(Debug)]
pub struct PendingBusy(BusyDaemonInfo);
impl PendingBusy {
    pub fn new(info: BusyDaemonInfo) -> Option<Self> {
        info.valid().then_some(Self(info))
    }
    pub fn info(&self) -> &BusyDaemonInfo {
        &self.0
    }
    pub fn decide(self, choice: BusyChoice) -> BusyDecision {
        BusyDecision {
            attempt: self.0.attempt,
            identity: self.0.identity,
            choice,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BusyDecision {
    pub attempt: BusyAttemptId,
    pub identity: BusyDaemonIdentity,
    pub choice: BusyChoice,
}
impl<'de> Deserialize<'de> for BusyDecision {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            attempt: BusyAttemptId,
            identity: BusyDaemonIdentity,
            choice: BusyChoice,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            attempt: fields.attempt,
            identity: fields.identity,
            choice: fields.choice,
        };
        if value.valid() {
            Ok(value)
        } else {
            Err(serde::de::Error::custom("invalid BusyDecision fields"))
        }
    }
}

impl BusyDecision {
    pub fn valid(&self) -> bool {
        self.identity.valid()
    }
    pub fn matches(&self, info: &BusyDaemonInfo) -> bool {
        self.valid()
            && info.valid()
            && self.attempt == info.attempt
            && self.identity == info.identity
    }
}

/// Separate, identity-scoped user consent for an interrupting restart. Dispatch
/// still requires a bounded one-use server receipt or qualified exact endpoint
/// custody; serializing this value cannot authorize generic STOP.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestructiveRestartConsent {
    pub attempt: BusyAttemptId,
    pub identity: BusyDaemonIdentity,
}
impl<'de> Deserialize<'de> for DestructiveRestartConsent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            attempt: BusyAttemptId,
            identity: BusyDaemonIdentity,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            attempt: fields.attempt,
            identity: fields.identity,
        };
        if value.identity.valid() {
            Ok(value)
        } else {
            Err(serde::de::Error::custom(
                "invalid DestructiveRestartConsent fields",
            ))
        }
    }
}

impl DestructiveRestartConsent {
    pub fn matches(&self, info: &BusyDaemonInfo) -> bool {
        info.valid() && self.attempt == info.attempt && self.identity == info.identity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn info() -> BusyDaemonInfo {
        BusyDaemonInfo {
            schema: 1,
            attempt: BusyAttemptId::from_bytes([18; 16]),
            identity: BusyDaemonIdentity {
                version: "0.5.9".into(),
                build: 1,
                checksum: "ab".repeat(32),
                pid: 42,
                generation: Some("cd".repeat(16)),
            },
            active_connections: 2,
            serving_profiles: Some(vec![[2, 1, 1]]),
            preservation: PreservationCapability::Unknown,
        }
    }
    #[test]
    fn wire_dtos_reject_malformed_bounded_fields_and_round_trip() {
        let live = info();
        let encoded = serde_json::to_value(&live).unwrap();
        assert_eq!(
            serde_json::from_value::<BusyDaemonInfo>(encoded.clone()).unwrap(),
            live
        );
        for (field, invalid) in [
            ("schema", serde_json::json!(2)),
            ("active_connections", serde_json::json!(0)),
            ("serving_profiles", serde_json::json!(vec![[2, 1, 1]; 17])),
            ("unexpected", serde_json::json!(true)),
        ] {
            let mut value = encoded.clone();
            value[field] = invalid;
            assert!(serde_json::from_value::<BusyDaemonInfo>(value).is_err());
        }
        let mut value = encoded;
        value["identity"]["version"] = "bad\nversion".into();
        assert!(serde_json::from_value::<BusyDaemonInfo>(value).is_err());
        let decision = PendingBusy::new(live.clone())
            .unwrap()
            .decide(BusyChoice::ForceUpdate);
        assert_eq!(
            serde_json::from_str::<BusyDecision>(&serde_json::to_string(&decision).unwrap())
                .unwrap(),
            decision
        );
        let consent = live.confirm_destructive_restart();
        assert_eq!(
            serde_json::from_str::<DestructiveRestartConsent>(
                &serde_json::to_string(&consent).unwrap()
            )
            .unwrap(),
            consent
        );
    }
    #[test]
    fn attempt_ids_reject_malformed_wire_values() {
        for invalid in ["", "not-an-attempt", &"ab".repeat(17), &"zz".repeat(16)] {
            assert!(serde_json::from_str::<BusyAttemptId>(
                &serde_json::to_string(invalid).unwrap()
            )
            .is_err());
        }
        let valid = BusyAttemptId::from_bytes([18; 16]);
        assert_eq!(
            serde_json::to_string(&valid).unwrap(),
            format!("\"{}\"", "12".repeat(16))
        );
    }
    #[test]
    fn busy_choice_defaults_to_cancel_and_scopes_every_answer() {
        assert_eq!(BusyChoice::default(), BusyChoice::Cancel);
        let live = info();
        for choice in [
            BusyChoice::Cancel,
            BusyChoice::ContinueOld,
            BusyChoice::ForceUpdate,
        ] {
            let decision = PendingBusy::new(live.clone()).unwrap().decide(choice);
            assert!(decision.matches(&live));
            let mut replacement = live.clone();
            replacement.identity.generation = Some("ef".repeat(16));
            assert!(!decision.matches(&replacement));
            replacement = live.clone();
            replacement.attempt = BusyAttemptId::from_bytes([52; 16]);
            assert!(!decision.matches(&replacement));
        }
    }
    #[test]
    fn destructive_consent_is_separate_and_identity_scoped() {
        let live = info();
        let consent = live.confirm_destructive_restart();
        assert!(consent.matches(&live));
        let mut replacement = live;
        replacement.identity.pid += 1;
        assert!(!consent.matches(&replacement));
    }
    #[test]
    fn busy_record_validates_profile_and_identity_bounds() {
        let live = info();
        assert!(live.valid());
        let mut invalid = live.clone();
        invalid.serving_profiles = Some(vec![]);
        assert!(invalid.valid());
        invalid.serving_profiles = Some(vec![[2, 1, 1]; 17]);
        assert!(!invalid.valid());
        invalid = live.clone();
        invalid.identity.generation = Some("x".repeat(32));
        assert!(!invalid.valid());
        invalid = live.clone();
        invalid.schema = 0;
        assert!(!invalid.valid());
    }
}
