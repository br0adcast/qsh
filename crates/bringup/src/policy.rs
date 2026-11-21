//! Caller-owned installation policy and approval.

use std::sync::Arc;

use crate::{BringUpError, BringUpObserver, ImageRequest, ImageSource, InstallTiming};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallPolicy {
    ExistingOnly,
    /// Recovery may reuse/restart an installed daemon with its existing identity.
    /// Never install, create an identity, or replace a live daemon.
    RestartOnly,
    /// A foreground login: asks before installing `version` when qshd is
    /// missing, or when the found cached copy is older than `version`.
    AskIfMissing {
        version: String,
    },
    EnsureBundled {
        version: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOffer {
    pub username: String,
    pub host: String,
    pub ssh_port: u16,
    pub image: ImageRequest,
    pub remote_path: String,
    /// The older cached qshd version this install supersedes, when one was
    /// found; `None` when qshd is missing. Declining an upgrade still runs
    /// the found copy. It is printed by SemVer, so it is plain ASCII.
    pub replaces: Option<String>,
}

pub trait InstallApproval: Send + Sync {
    fn approve(&self, offer: &InstallOffer, cancel: &knock::Cancel) -> Result<bool, BringUpError>;
}

pub struct BringUpHooks {
    pub source: Option<Arc<dyn ImageSource>>,
    pub approval: Arc<dyn InstallApproval>,
    pub observer: Arc<dyn BringUpObserver>,
    pub timing: InstallTiming,
}
