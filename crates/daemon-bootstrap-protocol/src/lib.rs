//! Explicit startup decisions before registration or session handshake.
use serde::{Deserialize, Serialize};
mod service;
pub use service::{
    PersonalServiceProfile, PersonalServiceSelector, ServiceRestartAction, ServiceRestartConsent,
};

fn hex_field(text: &str, bytes: usize) -> bool {
    text.len() == bytes * 2 && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Static executable API support, separate from live daemon/session metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BootstrapToolCapabilities {
    pub schema: u8,
    pub busy_decisions: bool,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub account_service_restart_v1: bool,
}

/// Exact selected executable bytes and actual build, never inferred from a release label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateImageIdentity {
    pub build: u64,
    pub checksum: String,
}
impl CandidateImageIdentity {
    pub fn valid(&self) -> bool {
        hex_field(&self.checksum, 32)
    }
}
impl<'de> Deserialize<'de> for CandidateImageIdentity {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            build: u64,
            checksum: String,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            build: fields.build,
            checksum: fields.checksum,
        };
        if value.valid() {
            Ok(value)
        } else {
            Err(serde::de::Error::custom("invalid candidate checksum"))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestructiveRestartAction {
    #[serde(rename = "stop_and_restart")]
    StopAndRestart,
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
    pub candidate: CandidateImageIdentity,
    pub active_connections: u64,
    /// Complete [wire, handshake, channel] profiles; None means unknown.
    pub serving_profiles: Option<Vec<[u8; 3]>>,
    pub preservation: PreservationCapability,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_restart: Option<PersonalServiceSelector>,
}
impl<'de> Deserialize<'de> for BusyDaemonInfo {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            schema: u8,
            attempt: BusyAttemptId,
            identity: BusyDaemonIdentity,
            candidate: CandidateImageIdentity,
            active_connections: u64,
            serving_profiles: Option<Vec<[u8; 3]>>,
            preservation: PreservationCapability,
            service_restart: Option<PersonalServiceSelector>,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            schema: fields.schema,
            attempt: fields.attempt,
            identity: fields.identity,
            candidate: fields.candidate,
            active_connections: fields.active_connections,
            serving_profiles: fields.serving_profiles,
            preservation: fields.preservation,
            service_restart: fields.service_restart,
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
        self.schema == 2
            && self
                .service_restart
                .as_ref()
                .is_none_or(PersonalServiceSelector::valid)
            && self.identity.valid()
            && self.candidate.valid()
            && self.active_connections > 0
            && self.serving_profiles.as_ref().is_none_or(|p| p.len() <= 16)
    }
    pub fn confirm_service_restart(&self) -> Option<ServiceRestartConsent> {
        self.valid().then_some(())?;
        Some(ServiceRestartConsent {
            attempt: self.attempt.clone(),
            service: self.service_restart.clone()?,
            candidate: self.candidate.clone(),
            action: ServiceRestartAction::RestartAccountService,
        })
    }
    /// Caller confirmation only, never a server-issued stop authority.
    pub fn confirm_destructive_restart(&self) -> DestructiveRestartConsent {
        DestructiveRestartConsent {
            attempt: self.attempt.clone(),
            identity: self.identity.clone(),
            candidate: self.candidate.clone(),
            action: DestructiveRestartAction::StopAndRestart,
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
            candidate: self.0.candidate,
            choice,
            service_restart: self.0.service_restart,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BusyDecision {
    pub attempt: BusyAttemptId,
    pub identity: BusyDaemonIdentity,
    pub candidate: CandidateImageIdentity,
    pub choice: BusyChoice,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_restart: Option<PersonalServiceSelector>,
}
impl<'de> Deserialize<'de> for BusyDecision {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            attempt: BusyAttemptId,
            identity: BusyDaemonIdentity,
            candidate: CandidateImageIdentity,
            choice: BusyChoice,
            service_restart: Option<PersonalServiceSelector>,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            attempt: fields.attempt,
            identity: fields.identity,
            candidate: fields.candidate,
            choice: fields.choice,
            service_restart: fields.service_restart,
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
            && self.candidate.valid()
            && self
                .service_restart
                .as_ref()
                .is_none_or(PersonalServiceSelector::valid)
    }
    pub fn matches(&self, info: &BusyDaemonInfo) -> bool {
        self.valid()
            && info.valid()
            && self.attempt == info.attempt
            && self.identity == info.identity
            && self.candidate == info.candidate
            && self.service_restart == info.service_restart
    }
}

/// Separate, identity-scoped user consent for an interrupting restart. Dispatch
/// still requires a bounded one-use server receipt or qualified exact endpoint
/// custody; serializing this value cannot authorize generic STOP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DestructiveRestartConsent {
    pub attempt: BusyAttemptId,
    pub identity: BusyDaemonIdentity,
    pub candidate: CandidateImageIdentity,
    pub action: DestructiveRestartAction,
}
impl<'de> Deserialize<'de> for DestructiveRestartConsent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            attempt: BusyAttemptId,
            identity: BusyDaemonIdentity,
            candidate: CandidateImageIdentity,
            action: DestructiveRestartAction,
        }
        let fields = Fields::deserialize(deserializer)?;
        let value = Self {
            attempt: fields.attempt,
            identity: fields.identity,
            candidate: fields.candidate,
            action: fields.action,
        };
        if value.identity.valid() && value.candidate.valid() {
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
        info.valid()
            && self.attempt == info.attempt
            && self.identity == info.identity
            && self.candidate == info.candidate
            && self.action == DestructiveRestartAction::StopAndRestart
    }
}

/// A failed explicit destructive operation never becomes readiness. The
/// attempt binds this terminal result to the pending authenticated SSH call.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestructiveRestartFailure {
    pub attempt: BusyAttemptId,
    pub disposition: DestructiveRestartDisposition,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestructiveRestartDisposition {
    Refused,
    Uncertain,
}

#[cfg(test)]
mod tests {
    use super::*;
    fn info() -> BusyDaemonInfo {
        BusyDaemonInfo {
            schema: 2,
            attempt: BusyAttemptId::from_bytes([18; 16]),
            identity: BusyDaemonIdentity {
                version: "0.5.9".into(),
                build: 1,
                checksum: "ab".repeat(32),
                pid: 42,
                generation: Some("cd".repeat(16)),
            },
            candidate: CandidateImageIdentity {
                build: 2,
                checksum: "ef".repeat(32),
            },
            active_connections: 2,
            serving_profiles: Some(vec![[2, 1, 1]]),
            preservation: PreservationCapability::Unknown,
            service_restart: None,
        }
    }
    #[test]
    fn service_offer_requires_schema2_and_explicit_personal_selector() {
        let modern = serde_json::to_value(info()).unwrap();
        assert!(modern.get("service_restart").is_none());
        let mut offered = modern.clone();
        offered["schema"] = 2.into();
        offered["identity"]
            .as_object_mut()
            .unwrap()
            .remove("generation");
        offered["service_restart"] = serde_json::json!({
            "profile":"personal_transport_v1", "uid":1000,
            "endpoint":"/fixture/cache/qsh/control.sock", "port":60022
        });
        let live: BusyDaemonInfo = serde_json::from_value(offered.clone())
            .expect("explicit schema2 personal-service offer");
        assert_eq!(serde_json::to_value(live).unwrap(), offered);
        let mut invalid = offered.clone();
        invalid["schema"] = 1.into();
        assert!(serde_json::from_value::<BusyDaemonInfo>(invalid).is_err());
        for (field, value) in [
            ("uid", serde_json::json!(0)),
            ("port", serde_json::json!(0)),
            ("endpoint", serde_json::json!("relative/control.sock")),
            ("profile", serde_json::json!("system")),
        ] {
            let mut invalid = offered.clone();
            invalid["service_restart"][field] = value;
            assert!(serde_json::from_value::<BusyDaemonInfo>(invalid).is_err());
        }
    }

    #[test]
    fn service_consent_is_checked_and_never_reinterpreted_as_exact_consent() {
        let mut live = info();
        assert!(live.confirm_service_restart().is_none());
        live.service_restart = Some(PersonalServiceSelector {
            profile: PersonalServiceProfile::PersonalTransportV1,
            uid: 1000,
            endpoint: "/fixture/qsh/control.sock".into(),
            port: 60022,
        });
        let consent = live.confirm_service_restart().unwrap();
        let encoded = serde_json::to_value(&consent).unwrap();
        assert_eq!(encoded["action"], "restart_account_service");
        assert!(serde_json::from_value::<DestructiveRestartConsent>(encoded.clone()).is_err());
        assert_eq!(
            serde_json::from_value::<ServiceRestartConsent>(encoded.clone()).unwrap(),
            consent
        );
        for field in ["action", "unknown", "candidate", "service"] {
            let mut invalid = encoded.clone();
            match field {
                "action" => invalid[field] = "stop_and_restart".into(),
                "unknown" => invalid[field] = true.into(),
                "candidate" => invalid[field]["checksum"] = "bad".into(),
                _ => invalid[field]["uid"] = 0.into(),
            }
            assert!(
                serde_json::from_value::<ServiceRestartConsent>(invalid).is_err(),
                "{field}"
            );
        }
        for changed in ["attempt", "candidate", "service"] {
            let mut other = live.clone();
            match changed {
                "attempt" => other.attempt = BusyAttemptId::from_bytes([8; 16]),
                "candidate" => other.candidate.build += 1,
                _ => other.service_restart.as_mut().unwrap().port += 1,
            }
            assert!(!consent.matches(&other), "{changed}");
        }
        live.identity.pid += 1;
        live.identity.generation = Some("aa".repeat(16));
        assert!(consent.matches(&live));
    }

    #[test]
    fn destructive_consent_binds_candidate_and_explicit_action() {
        let mut value = serde_json::to_value(info()).unwrap();
        value["candidate"] = serde_json::json!({"build":2,"checksum":"ef".repeat(32)});
        let live: BusyDaemonInfo =
            serde_json::from_value(value.clone()).expect("candidate-bound BUSY schema");
        let consent = live.confirm_destructive_restart();
        let encoded = serde_json::to_value(&consent).unwrap();
        assert_eq!(encoded["candidate"], value["candidate"]);
        assert_eq!(encoded["action"], "stop_and_restart");
        let mut changed = value.clone();
        changed["candidate"]["build"] = 3.into();
        assert!(!consent.matches(&serde_json::from_value(changed).unwrap()));
        let mut changed = value.clone();
        changed["candidate"]["checksum"] = "aa".repeat(32).into();
        assert!(!consent.matches(&serde_json::from_value(changed).unwrap()));
        let mut changed = value.clone();
        changed["candidate"]["checksum"] = "invalid".into();
        assert!(serde_json::from_value::<BusyDaemonInfo>(changed).is_err());
        let mut changed = encoded;
        changed["action"] = "preserve_sessions".into();
        assert!(serde_json::from_value::<DestructiveRestartConsent>(changed).is_err());
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
            ("schema", serde_json::json!(1)),
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
