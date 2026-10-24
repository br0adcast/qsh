//! Installation progress reported synchronously to the caller.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BringUpStage {
    Knocking,
    Connecting,
    Locating,
    /// Fetching and validating release checksum metadata, before any image transfer.
    CheckingMetadata,
    Downloading,
    Uploading,
    Verifying,
    Publishing,
    Starting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BringUpProgress {
    pub stage: BringUpStage,
    pub completed: u64,
    pub total: Option<u64>,
    pub finished: bool,
}

pub trait BringUpObserver: Send + Sync {
    fn on_progress(&self, event: BringUpProgress);
}
