//! Caller-owned installation policy and approval.

use std::sync::Arc;

use crate::{BringUpError, BringUpObserver, ImageRequest, ImageSource, InstallTiming};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstallPolicy {
    ExistingOnly,
    AskIfMissing { version: String },
    EnsureBundled { version: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallOffer {
    pub username: String,
    pub host: String,
    pub ssh_port: u16,
    pub image: ImageRequest,
    pub remote_path: String,
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
