//! Per-stage network budgets; approval time is outside these budgets.

use std::time::Duration;

#[derive(Debug, Clone, Copy)]
pub struct InstallTiming {
    pub locate: Duration,
    pub metadata: Duration,
    pub download: Duration,
    pub download_idle: Duration,
    pub upload: Duration,
    pub upload_idle: Duration,
    pub verify: Duration,
    pub publish: Duration,
    pub ensure: Duration,
}

impl Default for InstallTiming {
    fn default() -> Self {
        Self {
            locate: Duration::from_secs(10),
            metadata: Duration::from_secs(20),
            download: Duration::from_secs(180),
            download_idle: Duration::from_secs(30),
            upload: Duration::from_secs(180),
            upload_idle: Duration::from_secs(30),
            verify: Duration::from_secs(10),
            publish: Duration::from_secs(10),
            ensure: Duration::from_secs(30),
        }
    }
}
