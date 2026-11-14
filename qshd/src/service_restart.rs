//! Account-service intent is deliberately distinct from exact-process receipts.
use crate::control::{EnsureLock, ServiceStopDispatch};
use daemon_bootstrap_protocol::{
    CandidateImageIdentity, PersonalServiceSelector, ServiceRestartConsent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceRestartOutcome {
    Released,
    Refused,
    Uncertain,
}

fn run(
    authorized: bool,
    dispatch: impl FnOnce() -> ServiceStopDispatch,
    released: impl FnOnce() -> bool,
) -> ServiceRestartOutcome {
    if !authorized {
        return ServiceRestartOutcome::Refused;
    }
    match dispatch() {
        ServiceStopDispatch::Refused => ServiceRestartOutcome::Refused,
        ServiceStopDispatch::Uncertain => ServiceRestartOutcome::Uncertain,
        ServiceStopDispatch::Acknowledged if released() => ServiceRestartOutcome::Released,
        ServiceStopDispatch::Acknowledged => ServiceRestartOutcome::Uncertain,
    }
}

/// Constructed only from the current effective account and retained route.
pub struct ValidatedPersonalService(PersonalServiceSelector);
impl ValidatedPersonalService {
    pub fn current(
        transaction: &EnsureLock,
        consent: &ServiceRestartConsent,
        port: u16,
    ) -> Option<Self> {
        let local = transaction.personal_service_selector(port)?;
        (local == consent.service).then_some(Self(local))
    }
}
/// Only a validated adopted private launch can authorize service destruction.
pub struct ValidatedCandidate<'a> {
    identity: CandidateImageIdentity,
    stage: &'a SelectedStage,
}
impl<'a> ValidatedCandidate<'a> {
    pub fn staged(stage: &'a SelectedStage, expected: &CandidateImageIdentity) -> Option<Self> {
        stage.validate(expected).ok()?;
        Some(Self {
            identity: expected.clone(),
            stage,
        })
    }
}

fn released_legacy_profile(version: &str, generation: Option<&str>) -> bool {
    version == "0.5.0" && generation.is_none()
}

pub fn offered_service(
    transaction: &EnsureLock,
    port: u16,
    version: &str,
    generation: Option<&str>,
) -> Option<PersonalServiceSelector> {
    // Deliberate first legacy subset: actual generation-less personal peers.
    if !cfg!(any(target_os = "linux", target_os = "macos"))
        || !released_legacy_profile(version, generation)
    {
        return None;
    }
    // Discovery is read-only. Probe filesystem publication only after the
    // separate service confirmation, before any destructive write.
    transaction.personal_service_selector(port)
}

pub fn restart_personal_service(
    transaction: &EnsureLock,
    consent: &ServiceRestartConsent,
    service: &ValidatedPersonalService,
    candidate: &ValidatedCandidate<'_>,
) -> ServiceRestartOutcome {
    let authorized = consent.service == service.0
        && consent.candidate == candidate.identity
        && transaction.preflight_absent_publication().is_ok();
    run(
        authorized,
        || {
            if candidate.stage.validate(&consent.candidate).is_err() {
                return ServiceStopDispatch::Refused;
            }
            transaction.stop_service_once()
        },
        || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            loop {
                let Ok(exists) = transaction.endpoint_exists() else {
                    return false;
                };
                if !exists
                    && std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, service.0.port))
                        .is_ok()
                {
                    return true;
                }
                if std::time::Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    #[test]
    fn modern_metadata_failure_never_becomes_a_legacy_service_offer() {
        assert!(released_legacy_profile("0.5.0", None));
        for version in ["0.6.0-rc1", "0.5.9", "99.0.0"] {
            assert!(!released_legacy_profile(version, None), "{version}");
        }
        assert!(!released_legacy_profile("0.5.0", Some("ab")));
    }
    #[test]
    fn confirmed_service_dispatches_once_and_requires_acknowledged_release() {
        for (dispatch, released, expected) in [
            (
                ServiceStopDispatch::Acknowledged,
                true,
                ServiceRestartOutcome::Released,
            ),
            (
                ServiceStopDispatch::Acknowledged,
                false,
                ServiceRestartOutcome::Uncertain,
            ),
            (
                ServiceStopDispatch::Uncertain,
                true,
                ServiceRestartOutcome::Uncertain,
            ),
            (
                ServiceStopDispatch::Refused,
                true,
                ServiceRestartOutcome::Refused,
            ),
        ] {
            let writes = Cell::new(0);
            let observations = Cell::new(0);
            let outcome = run(
                true,
                || {
                    writes.set(writes.get() + 1);
                    dispatch
                },
                || {
                    observations.set(observations.get() + 1);
                    released
                },
            );
            assert_eq!(outcome, expected);
            assert_eq!(writes.get(), 1);
            assert_eq!(
                observations.get(),
                usize::from(dispatch == ServiceStopDispatch::Acknowledged)
            );
        }
    }
    #[test]
    fn unqualified_service_or_candidate_has_zero_dispatch_or_observation() {
        assert_eq!(
            run(
                false,
                || panic!("unauthorized write"),
                || panic!("unauthorized observation")
            ),
            ServiceRestartOutcome::Refused
        );
    }
}

#[cfg(test)]
mod authority_tests {
    use super::*;
    use daemon_bootstrap_protocol::{BusyAttemptId, PersonalServiceProfile, ServiceRestartAction};
    #[test]
    fn service_authority_uses_the_local_account_route_and_requested_port() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let endpoint = directory.path().join("control.sock");
        let transaction =
            EnsureLock::acquire(&endpoint, std::time::Duration::from_secs(1)).unwrap();
        let mut consent = ServiceRestartConsent {
            attempt: BusyAttemptId::from_bytes([1; 16]),
            service: PersonalServiceSelector {
                profile: PersonalServiceProfile::PersonalTransportV1,
                uid: nix::unistd::geteuid().as_raw(),
                endpoint: endpoint.to_str().unwrap().into(),
                port: 60022,
            },
            candidate: CandidateImageIdentity {
                build: 1,
                checksum: "ab".repeat(32),
            },
            action: ServiceRestartAction::RestartAccountService,
        };
        let eligible =
            !nix::unistd::geteuid().is_root() && nix::unistd::geteuid() == nix::unistd::getuid();
        assert_eq!(
            ValidatedPersonalService::current(&transaction, &consent, 60022).is_some(),
            eligible
        );
        consent.service.port += 1;
        assert!(ValidatedPersonalService::current(&transaction, &consent, 60022).is_none());
        consent.service.port -= 1;
        consent.service.uid = consent.service.uid.wrapping_add(1);
        assert!(ValidatedPersonalService::current(&transaction, &consent, 60022).is_none());
        consent.service.uid = nix::unistd::geteuid().as_raw();
        consent.service.endpoint = directory
            .path()
            .join("another/control.sock")
            .to_str()
            .unwrap()
            .into();
        assert!(ValidatedPersonalService::current(&transaction, &consent, 60022).is_none());
    }
}

/// Service staging keeps the installer limit, below the generic stage cap.
const MAX_SELECTED_IMAGE: u64 = 32 * 1024 * 1024;
const STAGE_ROOT: &str = "service-staging";

fn open_selected_file_with_parent(
    path: &std::path::Path,
    private: bool,
) -> Result<(std::fs::File, std::fs::File), crate::service_stage::StageError> {
    use crate::service_stage::StageError;
    use nix::fcntl::{openat, OFlag};
    use nix::sys::stat::Mode;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute() {
        return Err(StageError::Invalid);
    }
    let (parent, leaf) = crate::host_key::trusted_parent(path, false)?;
    let fd = openat(
        Some(parent.as_raw_fd()),
        leaf.as_os_str(),
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .map_err(std::io::Error::from)?;
    // SAFETY: openat returned a new read-only descriptor owned by this File.
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    let uid = nix::unistd::geteuid().as_raw();
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.mode() & 0o7022 != 0
        || metadata.mode() & 0o111 == 0
        || (metadata.uid() != uid && metadata.uid() != 0)
        || (private && (metadata.uid() != uid || metadata.mode() & 0o7777 != 0o500))
    {
        return Err(StageError::Untrusted);
    }
    if metadata.len() == 0 || metadata.len() > MAX_SELECTED_IMAGE {
        return Err(StageError::TooLarge);
    }
    let (current, _) = crate::host_key::trusted_parent(path, false)?;
    if parent.metadata()?.dev() != current.metadata()?.dev()
        || parent.metadata()?.ino() != current.metadata()?.ino()
    {
        return Err(StageError::Changed);
    }
    Ok((file, parent))
}
fn open_selected_file(
    path: &std::path::Path,
    private: bool,
) -> Result<std::fs::File, crate::service_stage::StageError> {
    open_selected_file_with_parent(path, private).map(|(file, _)| file)
}

fn stage_root(
    cache: &std::path::Path,
    create: bool,
) -> Result<crate::service_stage::StageRoot, crate::service_stage::StageError> {
    let route = cache.join(STAGE_ROOT);
    let (directory, _) = crate::host_key::trusted_parent(&route.join(".root"), create)?;
    crate::service_stage::StageRoot::from_trusted(directory, route)
}

/// The selected bytes and the persistent destination are separate authorities.
/// Parent identity survives reexec through the opaque operation, not a public
/// path override. Legitimate leaf replacement does not change that route.
pub struct SelectedHelper {
    path: std::path::PathBuf,
    source: std::fs::File,
    parent: std::fs::File,
    parent_identity: [u64; 2],
}
impl SelectedHelper {
    pub fn open(
        path: &std::path::Path,
        cache: &std::path::Path,
    ) -> Result<Self, crate::service_stage::StageError> {
        use crate::service_stage::StageError;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::MetadataExt;
        if !path.is_absolute()
            || path.as_os_str().as_bytes().len() > 2048
            || path
                .as_os_str()
                .as_bytes()
                .iter()
                .any(|byte| byte.is_ascii_control())
            || path.components().any(|part| {
                !matches!(
                    part,
                    std::path::Component::RootDir | std::path::Component::Normal(_)
                )
            })
            || path.starts_with(cache.join(STAGE_ROOT))
            || is_stage_artifact(path)
        {
            return Err(StageError::Invalid);
        }
        let (source, parent) = open_selected_file_with_parent(path, false)?;
        let metadata = parent.metadata()?;
        let selected = Self {
            path: path.into(),
            source,
            parent,
            parent_identity: [metadata.dev(), metadata.ino()],
        };
        selected.revalidate()?;
        Ok(selected)
    }
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
    pub fn parent_identity(&self) -> [u64; 2] {
        self.parent_identity
    }
    fn revalidate(&self) -> Result<(), crate::service_stage::StageError> {
        use std::os::unix::fs::MetadataExt;
        let (current, _) = crate::host_key::trusted_parent(&self.path, false)?;
        for parent in [&self.parent, &current] {
            let metadata = parent.metadata()?;
            if [metadata.dev(), metadata.ino()] != self.parent_identity {
                return Err(crate::service_stage::StageError::Changed);
            }
        }
        // Destination policy is independent of the copied artifact's identity.
        // A safe future rename may replace this leaf; a symlink cannot.
        open_selected_file(&self.path, false)?;
        Ok(())
    }
}
fn is_stage_artifact(path: &std::path::Path) -> bool {
    let Some(parent) = path.parent() else {
        return false;
    };
    path.file_name() == Some(std::ffi::OsStr::new("qshd"))
        && parent.parent().and_then(std::path::Path::file_name)
            == Some(std::ffi::OsStr::new(STAGE_ROOT))
        && parent
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| {
                name.strip_prefix("stage-").is_some_and(|nonce| {
                    nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
                })
            })
}

pub fn prepare_selected_stage(
    cache: &std::path::Path,
    source: &mut SelectedHelper,
    candidate: &CandidateImageIdentity,
    operation: &[u8],
) -> Result<crate::service_stage::PreparedStage, crate::service_stage::StageError> {
    source.revalidate()?;
    let root = stage_root(cache, true)?;
    crate::service_stage::PreparedStage::prepare(
        root,
        &mut source.source,
        candidate.clone(),
        std::env::consts::ARCH,
        transport::channel::PROTOCOL_VERSION,
        operation,
        |path| {
            // Recheck the installer bound after copying too; a growing source
            // cannot turn the generic stage allowance into a product limit.
            open_selected_file(path, true).map_err(|error| error.to_string())?;
            crate::update::run_self_check(path, crate::update::SELF_CHECK_TIMEOUT)
        },
    )
}

/// Checked artifact/launch custody, never an executing-image or PID authority.
pub struct SelectedStage {
    inner: crate::service_stage::AdoptedStage,
    candidate: CandidateImageIdentity,
    operation: Vec<u8>,
    cache: std::path::PathBuf,
    executable: std::path::PathBuf,
    installed: SelectedHelper,
}
impl SelectedStage {
    pub fn adopt(
        context: crate::service_stage::StageLaunchContext,
        candidate: &CandidateImageIdentity,
        operation: &[u8],
        cache: &std::path::Path,
        executable: &std::path::Path,
        installed: SelectedHelper,
    ) -> Result<Self, crate::service_stage::StageError> {
        validate_stage_route(cache, executable, candidate)?;
        let inner = crate::service_stage::AdoptedStage::adopt(context, candidate, operation)?;
        let selected = Self {
            inner,
            candidate: candidate.clone(),
            operation: operation.to_vec(),
            cache: cache.into(),
            executable: executable.into(),
            installed,
        };
        selected.validate(candidate)?;
        Ok(selected)
    }
    pub fn validate(
        &self,
        candidate: &CandidateImageIdentity,
    ) -> Result<(), crate::service_stage::StageError> {
        if candidate != &self.candidate {
            return Err(crate::service_stage::StageError::Changed);
        }
        self.installed.revalidate()?;
        validate_stage_route(&self.cache, &self.executable, candidate)?;
        self.inner.validate(candidate, &self.operation)
    }
    pub fn installed_helper(&self) -> &std::path::Path {
        self.installed.path()
    }
    pub fn disarm_cleanup(&mut self) {
        self.inner.disarm_cleanup();
    }
    pub fn cleanup(self) -> Result<(), crate::service_stage::StageError> {
        self.inner.cleanup()
    }
}

fn validate_stage_route(
    cache: &std::path::Path,
    executable: &std::path::Path,
    candidate: &CandidateImageIdentity,
) -> Result<(), crate::service_stage::StageError> {
    use crate::service_stage::StageError;
    use sha2::{Digest, Sha256};
    use std::io::Read;
    stage_root(cache, false)?.revalidate()?;
    let parent = executable.parent().ok_or(StageError::Invalid)?;
    let name = parent
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or(StageError::Invalid)?;
    let nonce = name.strip_prefix("stage-").ok_or(StageError::Invalid)?;
    if executable.file_name() != Some(std::ffi::OsStr::new("qshd"))
        || parent.parent() != Some(cache.join(STAGE_ROOT).as_path())
        || nonce.len() != 32
        || !nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(StageError::Invalid);
    }
    let mut file = open_selected_file(executable, true)?;
    let mut hasher = Sha256::new();
    let mut chunk = [0; 64 * 1024];
    let mut size = 0u64;
    loop {
        let count = file.read(&mut chunk)?;
        if count == 0 {
            break;
        }
        size += count as u64;
        if size > MAX_SELECTED_IMAGE {
            return Err(StageError::TooLarge);
        }
        hasher.update(&chunk[..count]);
    }
    if hex::encode(hasher.finalize()) != candidate.checksum.to_ascii_lowercase() {
        return Err(StageError::Changed);
    }
    Ok(())
}

#[cfg(test)]
mod selected_stage_tests {
    use super::*;
    use std::fs::{self, Permissions};
    use std::os::unix::fs::{symlink, PermissionsExt};
    fn fixture() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let directory = tempfile::Builder::new()
            .permissions(Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let cache = directory.path().join("cache");
        fs::create_dir(&cache).unwrap();
        fs::set_permissions(&cache, Permissions::from_mode(0o700)).unwrap();
        let installed = directory.path().join("qshd");
        fs::write(&installed, b"selected artifact").unwrap();
        fs::set_permissions(&installed, Permissions::from_mode(0o500)).unwrap();
        (directory, cache, installed)
    }
    #[test]
    fn installed_destination_allows_safe_leaf_replacement_but_refuses_symlinks_and_aliases() {
        let (directory, cache, installed) = fixture();
        let selected = SelectedHelper::open(&installed, &cache).unwrap();
        let replacement = directory.path().join("replacement");
        fs::write(&replacement, b"different future executable").unwrap();
        fs::set_permissions(&replacement, Permissions::from_mode(0o500)).unwrap();
        fs::rename(&replacement, &installed).unwrap();
        selected.revalidate().unwrap();
        let alias = directory.path().join("alias");
        fs::hard_link(&installed, &alias).unwrap();
        assert!(selected.revalidate().is_err());
        fs::remove_file(alias).unwrap();
        fs::rename(&installed, &replacement).unwrap();
        symlink(&replacement, &installed).unwrap();
        assert!(selected.revalidate().is_err());
    }
    #[test]
    fn installed_destination_parent_replacement_is_refused() {
        let (directory, cache, source) = fixture();
        let parent = directory.path().join("bin");
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
        let installed = parent.join("qshd");
        fs::rename(source, &installed).unwrap();
        let selected = SelectedHelper::open(&installed, &cache).unwrap();
        fs::rename(&parent, directory.path().join("old-bin")).unwrap();
        fs::create_dir(&parent).unwrap();
        fs::set_permissions(&parent, Permissions::from_mode(0o700)).unwrap();
        fs::copy(directory.path().join("old-bin/qshd"), &installed).unwrap();
        assert!(selected.revalidate().is_err());
    }
    #[test]
    fn selected_helper_cannot_target_a_private_service_stage_or_exceed_installer_bound() {
        let (_directory, cache, installed) = fixture();
        let stage = cache.join("service-staging/stage-0123456789abcdef0123456789abcdef/qshd");
        assert!(SelectedHelper::open(&stage, &cache).is_err());
        let elsewhere = std::path::Path::new(
            "/elsewhere/service-staging/stage-0123456789abcdef0123456789abcdef/qshd",
        );
        assert!(SelectedHelper::open(elsewhere, &cache).is_err());
        fs::set_permissions(&installed, Permissions::from_mode(0o700)).unwrap();
        let file = fs::OpenOptions::new().write(true).open(&installed).unwrap();
        file.set_len(MAX_SELECTED_IMAGE + 1).unwrap();
        drop(file);
        fs::set_permissions(&installed, Permissions::from_mode(0o500)).unwrap();
        assert!(matches!(
            SelectedHelper::open(&installed, &cache),
            Err(crate::service_stage::StageError::TooLarge)
        ));
    }
    #[test]
    fn selected_stage_route_hash_and_private_mode_are_rechecked() {
        use sha2::{Digest, Sha256};
        let (_directory, cache, installed) = fixture();
        let bytes = fs::read(&installed).unwrap();
        let candidate = CandidateImageIdentity {
            build: 42,
            checksum: hex::encode(Sha256::digest(&bytes)),
        };
        let stage = crate::service_stage::PreparedStage::prepare(
            stage_root(&cache, true).unwrap(),
            &mut fs::File::open(&installed).unwrap(),
            candidate.clone(),
            std::env::consts::ARCH,
            transport::channel::PROTOCOL_VERSION,
            b"operation",
            |_| {
                Ok(crate::state::SelfCheck {
                    build: 42,
                    arch: std::env::consts::ARCH.into(),
                    protocol: transport::channel::PROTOCOL_VERSION,
                    protocols: vec![transport::channel::PROTOCOL_VERSION],
                    handover_versions: vec![],
                    transport_features: vec![],
                })
            },
        )
        .unwrap();
        validate_stage_route(&cache, stage.executable(), &candidate).unwrap();
        let mut changed = candidate.clone();
        changed.checksum = "ab".repeat(32);
        assert!(validate_stage_route(&cache, stage.executable(), &changed).is_err());
        assert!(
            validate_stage_route(cache.parent().unwrap(), stage.executable(), &candidate).is_err()
        );
        fs::set_permissions(stage.executable(), Permissions::from_mode(0o700)).unwrap();
        assert!(validate_stage_route(&cache, stage.executable(), &candidate).is_err());
    }
}
