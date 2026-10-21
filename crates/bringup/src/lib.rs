#![forbid(unsafe_code)]

//! Finds or installs a verified `qshd` over SSH so the client can log in
//! over qsh. Shared by the console client and, after part 3, the app, so it
//! knows nothing about its caller: sockets come through `SocketBind`,
//! questions through the plan's `AuthPrompter`.

use std::fmt;

mod ensure;
mod exec;
mod image;
mod install;
mod locate;
mod policy;
mod progress;
mod shell;
mod timing;

pub use image::{
    DaemonImage, ImageError, ImageRequest, ImageSource, Platform, ServerArch, ServerOs,
};
pub use locate::ServiceKind;
pub use policy::{BringUpHooks, InstallApproval, InstallOffer, InstallPolicy};
pub use progress::{BringUpObserver, BringUpProgress, BringUpStage};
pub use timing::InstallTiming;

pub struct BringUpRequest {
    pub name: String,
    pub ssh: ssh::SshParams,
    pub auth: ssh::SshAuthPlan,
    pub qsh_port: u16,
    pub client_pubkey: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    /// Reported by the verified SSH login for endpoint identity binding.
    /// Noise must still prove that the daemon holds the corresponding private key.
    pub server_pubkey: [u8; 32],
    /// Where the daemon actually listens (`TRANSPORT-READY`, qshd >= this slice).
    pub ports: Vec<u16>,
    /// The version of the `qshd` binary that ran `transport-ensure`
    /// (`state::QSHD_VERSION` in its `write_transport_ready`), which may
    /// differ from a live daemon it reused -- see `warning`.
    pub version: String,
    pub warning: Option<String>,
}

/// Daemon readiness and the verified SSH identity of the same connection
/// that performed its lookup, installation, and startup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentifiedReady {
    pub ready: Ready,
    pub ssh_host_key: ssh::HostKeyInfo,
}

impl Ready {
    /// The port to reach the daemon on: the one asked for if the daemon
    /// listens there, else the first one it does listen on.
    pub fn port_for(&self, requested: u16) -> u16 {
        if self.ports.contains(&requested) {
            requested
        } else {
            self.ports.first().copied().unwrap_or(requested)
        }
    }
}

#[derive(Debug)]
pub enum BringUpError {
    InvalidRequest(String),
    UnsupportedPlatform(String),
    InstallRequired,
    Declined,
    Image(ImageError),
    Transfer(String),
    Verify(String),
    Publish(String),
    Ssh(ssh::SshError),
    QshdMissing,
    /// A qshd service already runs on the server; starting a per-user daemon
    /// would fail on its port or run a second one next to it.
    ServiceRunning(ServiceKind),
    /// A step failed; the text says which, with the command's own words.
    EnsureFailed(String),
    /// `transport-ensure` said it succeeded but its answer does not parse.
    BadReady(String),
}

impl fmt::Display for BringUpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BringUpError::InvalidRequest(reason) => write!(f, "invalid bring-up request: {reason}"),
            BringUpError::UnsupportedPlatform(platform) => {
                write!(f, "unsupported server platform: {platform}")
            }
            BringUpError::InstallRequired => write!(f, "qshd installation is required"),
            BringUpError::Declined => write!(f, "qshd installation declined"),
            BringUpError::Image(error) => write!(f, "{error}"),
            BringUpError::Transfer(reason) => write!(f, "qshd transfer failed: {reason}"),
            BringUpError::Verify(reason) => write!(f, "qshd verification failed: {reason}"),
            BringUpError::Publish(reason) => write!(f, "qshd publication failed: {reason}"),
            BringUpError::Ssh(e) => write!(f, "{e}"),
            BringUpError::QshdMissing => write!(f, "qshd is not installed"),
            BringUpError::ServiceRunning(ServiceKind::System) => write!(
                f,
                "qshd runs as a system service here; bringing it up over SSH will not help"
            ),
            BringUpError::ServiceRunning(ServiceKind::User) => write!(
                f,
                "qshd runs as this account's own service (qshd serve) here; \
                 bringing it up over SSH will not help"
            ),
            BringUpError::EnsureFailed(t) | BringUpError::BadReady(t) => write!(f, "{t}"),
        }
    }
}

impl std::error::Error for BringUpError {}

/// Uses an existing daemon, preserving the original bring-up policy.
pub fn bring_up(
    req: BringUpRequest,
    bind: std::sync::Arc<dyn knock::SocketBind>,
    cancel: &knock::Cancel,
) -> Result<Ready, BringUpError> {
    struct Silent;
    impl InstallApproval for Silent {
        fn approve(&self, _: &InstallOffer, _: &knock::Cancel) -> Result<bool, BringUpError> {
            Ok(false)
        }
    }
    impl BringUpObserver for Silent {
        fn on_progress(&self, _: BringUpProgress) {}
    }
    bring_up_with(
        req,
        InstallPolicy::ExistingOnly,
        BringUpHooks {
            source: None,
            approval: std::sync::Arc::new(Silent),
            observer: std::sync::Arc::new(Silent),
            timing: InstallTiming::default(),
        },
        bind,
        cancel,
    )
    .map_err(|error| match error {
        BringUpError::InstallRequired => BringUpError::QshdMissing,
        other => other,
    })
}

/// Brings up a daemon with caller-supplied installation policy on one SSH login.
/// Blocking; caller-owned approval and image loading must honor cancellation.
/// The connection is closed on every outcome. SSH reports the intended daemon
/// identity; callers must still authenticate the daemon through Noise.
pub fn bring_up_with(
    req: BringUpRequest,
    policy: InstallPolicy,
    hooks: BringUpHooks,
    bind: std::sync::Arc<dyn knock::SocketBind>,
    cancel: &knock::Cancel,
) -> Result<Ready, BringUpError> {
    bring_up_identified(req, policy, hooks, bind, cancel).map(|identified| identified.ready)
}

/// Brings up a daemon and returns the verified host key of that SSH login.
/// Uses the same policy and cleanup as `bring_up_with`.
pub fn bring_up_identified(
    req: BringUpRequest,
    policy: InstallPolicy,
    hooks: BringUpHooks,
    bind: std::sync::Arc<dyn knock::SocketBind>,
    cancel: &knock::Cancel,
) -> Result<IdentifiedReady, BringUpError> {
    install::bring_up(req, policy, hooks, bind, cancel)
}

/// What the lookup's run says: the qshd to start, or why there is none. The
/// script exits 0 whatever it finds, so any other code -- `-1` included, a
/// channel that ended without a status -- is a failed lookup, never "not
/// installed".
#[cfg(test)]
fn located(code: i32, out: &str) -> Result<String, BringUpError> {
    match locate::probe(code, out)?.located {
        locate::Located::Found(path) => Ok(path),
        locate::Located::Service(kind) => Err(BringUpError::ServiceRunning(kind)),
        locate::Located::Missing => Err(BringUpError::QshdMissing),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn darwin_never_selects_linux_cache() {
        let linux = Platform::from_uname("Linux", "x86_64").unwrap();
        let darwin = Platform::from_uname("Darwin", "arm64").unwrap();
        assert_eq!(darwin.target(), "aarch64-apple-darwin");
        assert_eq!(linux.file_name("0.4.0"), "qshd-0.4.0-x86_64");
        assert_eq!(darwin.file_name("0.4.0"), "qshd-0.4.0-aarch64-darwin");
    }

    #[test]
    fn image_requests_reject_unsafe_or_non_semver_versions() {
        let platform = Platform::from_uname("Linux", "x86_64").unwrap();
        for version in [
            "",
            "1.2",
            "v1.2.3",
            "01.2.3",
            "1.2.3+build",
            "../1.2.3",
            "1.2.3\n",
        ] {
            assert!(
                matches!(
                    ImageRequest::new(platform, version),
                    Err(BringUpError::InvalidRequest(_))
                ),
                "{version:?}"
            );
        }
        assert_eq!(
            ImageRequest::new(platform, "1.2.3-rc.2").unwrap().version,
            "1.2.3-rc.2"
        );
        let request = ImageRequest {
            platform,
            version: "0.4.0+local".into(),
        };
        assert!(request.validate().is_err());
    }

    #[test]
    fn all_release_targets_are_distinct_and_unsupported_platforms_fail() {
        assert_eq!(
            Platform::from_uname("Linux", "x86_64").unwrap().target(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            Platform::from_uname("Linux", "aarch64").unwrap().target(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            Platform::from_uname("Darwin", "x86_64").unwrap().target(),
            "x86_64-apple-darwin"
        );
        for (os, arch) in [
            ("FreeBSD", "x86_64"),
            ("Linux", "riscv64"),
            ("linux", "x86_64"),
        ] {
            assert!(matches!(
                Platform::from_uname(os, arch),
                Err(BringUpError::UnsupportedPlatform(_))
            ));
        }
    }

    #[test]
    fn a_lookup_that_found_qshd_gives_its_path() {
        let out = "os Linux\narch x86_64\nhome /h\npath /usr/local/bin/qshd\n";
        assert_eq!(located(0, out).unwrap(), "/usr/local/bin/qshd");
    }

    #[test]
    fn a_lookup_that_found_nothing_is_qshd_missing() {
        assert!(matches!(
            located(0, "os Linux\narch x86_64\nhome /h\n"),
            Err(BringUpError::QshdMissing)
        ));
    }

    #[test]
    fn a_failed_lookup_is_not_qshd_missing() {
        for (code, out, expected) in [
            (-1, "", "the qshd lookup failed: exit code -1"),
            (
                127,
                "sh: not found\n",
                "the qshd lookup failed: sh: not found",
            ),
            // Output that would read as "nothing found" still does not
            // count when the script did not finish.
            (-1, "arch x86_64\n", "the qshd lookup failed: arch x86_64"),
        ] {
            match located(code, out) {
                Err(BringUpError::EnsureFailed(m)) => assert_eq!(m, expected),
                other => panic!("code {code}: expected a failed lookup, got {other:?}"),
            }
        }
    }

    fn ready(ports: Vec<u16>) -> Ready {
        Ready {
            ports,
            server_pubkey: [7; 32],
            version: "0.3.0".into(),
            warning: None,
        }
    }

    #[test]
    fn the_asked_port_is_used_when_the_daemon_is_there() {
        assert_eq!(ready(vec![60000, 60022]).port_for(60022), 60022);
    }

    #[test]
    fn otherwise_the_daemon_s_first_port() {
        assert_eq!(ready(vec![60000]).port_for(60022), 60000);
    }

    #[test]
    fn no_ports_at_all_keeps_the_asked_one() {
        assert_eq!(ready(vec![]).port_for(60022), 60022);
    }

    #[test]
    fn errors_read_as_sentences() {
        assert_eq!(
            BringUpError::QshdMissing.to_string(),
            "qshd is not installed"
        );
        assert_eq!(BringUpError::EnsureFailed("t".into()).to_string(), "t");
    }

    #[test]
    fn a_running_service_reads_as_a_sentence() {
        assert_eq!(
            BringUpError::ServiceRunning(ServiceKind::System).to_string(),
            "qshd runs as a system service here; bringing it up over SSH will not help"
        );
        assert_eq!(
            BringUpError::ServiceRunning(ServiceKind::User).to_string(),
            "qshd runs as this account's own service (qshd serve) here; bringing it up over SSH will not help"
        );
    }

    #[test]
    fn a_lookup_that_saw_a_service_is_service_running() {
        assert!(matches!(
            located(
                0,
                "os Linux\narch x86_64\nhome /h\nservice system\npath /usr/bin/qshd\n"
            ),
            Err(BringUpError::ServiceRunning(ServiceKind::System))
        ));
        assert!(matches!(
            located(1, "service system\n"),
            Err(BringUpError::EnsureFailed(_))
        ));
    }
}
