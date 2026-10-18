//! Platform-specific daemon images supplied by the caller.

use std::{fmt, sync::Arc};

use crate::{BringUpError, BringUpObserver, InstallTiming};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerOs {
    Linux,
    Darwin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServerArch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Platform {
    pub os: ServerOs,
    pub arch: ServerArch,
}

impl Platform {
    pub fn from_uname(os: &str, arch: &str) -> Result<Self, BringUpError> {
        let unsupported = || {
            let os_budget = crate::exec::MAX_DIAGNOSTIC / 2;
            BringUpError::UnsupportedPlatform(format!(
                "{}/{}",
                crate::exec::escaped(os, os_budget),
                crate::exec::escaped(arch, crate::exec::MAX_DIAGNOSTIC - os_budget - 1)
            ))
        };
        Ok(Self {
            os: match os {
                "Linux" => ServerOs::Linux,
                "Darwin" => ServerOs::Darwin,
                _ => return Err(unsupported()),
            },
            arch: match arch {
                "x86_64" => ServerArch::X86_64,
                "aarch64" | "arm64" => ServerArch::Aarch64,
                _ => return Err(unsupported()),
            },
        })
    }

    pub fn target(&self) -> &'static str {
        match (self.os, self.arch) {
            (ServerOs::Linux, ServerArch::X86_64) => "x86_64-unknown-linux-musl",
            (ServerOs::Linux, ServerArch::Aarch64) => "aarch64-unknown-linux-musl",
            (ServerOs::Darwin, ServerArch::X86_64) => "x86_64-apple-darwin",
            (ServerOs::Darwin, ServerArch::Aarch64) => "aarch64-apple-darwin",
        }
    }

    /// Names an image after the caller has validated its version.
    pub fn file_name(&self, version: &str) -> String {
        let arch = match self.arch {
            ServerArch::X86_64 => "x86_64",
            ServerArch::Aarch64 => "aarch64",
        };
        let suffix = match self.os {
            ServerOs::Linux => "",
            ServerOs::Darwin => "-darwin",
        };
        format!("qshd-{version}-{arch}{suffix}")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRequest {
    pub platform: Platform,
    pub version: String,
}

impl ImageRequest {
    pub fn new(platform: Platform, version: impl Into<String>) -> Result<Self, BringUpError> {
        let request = Self {
            platform,
            version: version.into(),
        };
        request.validate()?;
        Ok(request)
    }

    /// Must be called before constructing a URL or path, including for struct literals.
    pub fn validate(&self) -> Result<(), BringUpError> {
        valid_version(&self.version).map(|_| ()).ok_or_else(|| {
            BringUpError::InvalidRequest(
                "the image version must be SemVer without build metadata".into(),
            )
        })
    }
}

pub(crate) fn valid_version(version: &str) -> Option<semver::Version> {
    semver::Version::parse(version)
        .ok()
        .filter(|version| version.build.is_empty())
}

#[derive(Debug, Clone)]
pub struct DaemonImage {
    pub request: ImageRequest,
    pub size: u64,
    pub sha256: [u8; 32],
    pub bytes: Arc<[u8]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImageError {
    Unavailable(String),
    Download(String),
    Checksum,
    Archive(String),
    Invalid(String),
    Cancelled,
}

impl fmt::Display for ImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unavailable(reason) => write!(f, "daemon image unavailable: {reason}"),
            Self::Download(reason) => write!(f, "daemon image download failed: {reason}"),
            Self::Checksum => write!(f, "daemon image checksum does not match"),
            Self::Archive(reason) => write!(f, "daemon image archive failed: {reason}"),
            Self::Invalid(reason) => write!(f, "invalid daemon image: {reason}"),
            Self::Cancelled => write!(f, "daemon image loading cancelled"),
        }
    }
}

impl std::error::Error for ImageError {}

pub trait ImageSource: Send + Sync {
    fn load(
        &self,
        request: &ImageRequest,
        timing: &InstallTiming,
        cancel: &knock::Cancel,
        observer: &dyn BringUpObserver,
    ) -> Result<DaemonImage, ImageError>;
}
