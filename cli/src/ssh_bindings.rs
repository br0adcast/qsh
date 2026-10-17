//! Explicit SSH recovery grants, independent of either known-hosts store.
//!
//! Writers lock a stable sibling file across read/modify/replace. Readers see
//! only complete snapshots. A permit serializes invalidation with the final
//! rename, so a cancelled recovery attempt cannot publish new trust.

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use connect::recovery_gate::RecoveryEpoch;
use connect::server_identity::{ServerIdentity, SshBinding, SshEndpoint};
use serde::{Deserialize, Serialize};

/// Failure to read or persist explicit recovery authorization. Callers must
/// disable SSH recovery on error; an established QSH connection is unaffected.
#[derive(Debug)]
pub enum BindingError {
    Io(io::Error),
    InvalidFormat,
    UnsupportedVersion,
    Cancelled,
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "SSH binding store: {error}"),
            Self::InvalidFormat => f.write_str("invalid SSH binding store or binding"),
            Self::UnsupportedVersion => f.write_str("unsupported SSH binding store version"),
            Self::Cancelled => f.write_str("SSH trust write cancelled"),
        }
    }
}

impl std::error::Error for BindingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for BindingError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Authorization to persist trust for one recovery generation. Clones share
/// invalidation. Once `invalidate` returns, no unfinished write can commit;
/// writes that committed before invalidation remain authorized and durable.
#[derive(Clone)]
pub struct TrustWritePermit {
    epoch: Arc<Mutex<Option<RecoveryEpoch>>>,
}

impl TrustWritePermit {
    pub fn new(epoch: RecoveryEpoch) -> Self {
        Self {
            epoch: Arc::new(Mutex::new(Some(epoch))),
        }
    }

    pub fn invalidate(&self) {
        // Recover poison so cancellation itself never panics. A poisoned
        // permit is refused by writers, even if the old value was active.
        *self.epoch.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }

    pub(crate) fn ensure_active(&self) -> Result<(), BindingError> {
        drop(self.active()?);
        Ok(())
    }

    /// Serialize ordinary foreground host-trust writes with epoch invalidation.
    /// The closure must not call back into this permit or the binding store.
    pub(crate) fn write_if_active<T>(
        &self,
        cancel: &knock::Cancel,
        write: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, BindingError> {
        let _active = self.active()?;
        check_cancel(Some(cancel))?;
        write().map_err(BindingError::Io)
    }

    fn active(&self) -> Result<MutexGuard<'_, Option<RecoveryEpoch>>, BindingError> {
        let guard = self.epoch.lock().map_err(|_| BindingError::Cancelled)?;
        if guard.is_none() {
            return Err(BindingError::Cancelled);
        }
        Ok(guard)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Store {
    version: u32,
    bindings: Vec<Record>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Record {
    qsh_key: [u8; 32],
    username: String,
    host: String,
    port: u16,
    host_key: Vec<u8>,
}

impl Record {
    fn from_binding(binding: &SshBinding) -> Self {
        Self {
            qsh_key: binding.server.qsh_key,
            username: binding.server.username.clone(),
            host: binding.endpoint.host.clone(),
            port: binding.endpoint.port,
            host_key: binding.host_key.clone(),
        }
    }

    fn validate(&self) -> Result<(), BindingError> {
        if self.port == 0
            || self.host.is_empty()
            || self
                .host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || self.username.is_empty()
            || self.username.chars().any(char::is_control)
            || sshauth::record::decode_public_key(&self.host_key).is_err()
        {
            return Err(BindingError::InvalidFormat);
        }
        Ok(())
    }
}

/// Version 1 JSON store, normally `paths::config_dir()/ssh_bindings.json`.
/// Opening or reading an absent store creates no file or directory.
pub struct SshBindings {
    path: PathBuf,
}

impl SshBindings {
    pub fn open(path: PathBuf) -> Self {
        Self { path }
    }

    /// Public host keys explicitly granted for exactly this QSH key, user,
    /// host and port. Every record is validated before any key is returned.
    pub fn allowed(
        &self,
        server: &ServerIdentity,
        endpoint: &SshEndpoint,
    ) -> Result<Vec<Vec<u8>>, BindingError> {
        let mut keys = Vec::new();
        for record in self.read()?.bindings {
            if record.qsh_key == server.qsh_key
                && record.username == server.username
                && record.host == endpoint.host
                && record.port == endpoint.port
                && !keys.contains(&record.host_key)
            {
                keys.push(record.host_key);
            }
        }
        Ok(keys)
    }

    /// Persist a previously confirmed public-key association. Does not import,
    /// update or bypass QSH/OpenSSH known-hosts policy.
    pub fn grant(
        &self,
        binding: &SshBinding,
        permit: &TrustWritePermit,
    ) -> Result<(), BindingError> {
        self.grant_inner(binding, permit, None)
    }

    /// Foreground writes check cancellation again after waiting for the store
    /// lock and immediately before commit. Epoch changes invalidate `permit`.
    pub fn grant_cancellable(
        &self,
        binding: &SshBinding,
        permit: &TrustWritePermit,
        cancel: &knock::Cancel,
    ) -> Result<(), BindingError> {
        self.grant_inner(binding, permit, Some(cancel))
    }

    fn grant_inner(
        &self,
        binding: &SshBinding,
        permit: &TrustWritePermit,
        cancel: Option<&knock::Cancel>,
    ) -> Result<(), BindingError> {
        check_cancel(cancel)?;
        drop(permit.active()?);
        let record = Record::from_binding(binding);
        record.validate()?;
        fs::create_dir_all(self.directory())?;
        let _lock = WriteLock::acquire(&self.path)?;
        drop(permit.active()?);
        check_cancel(cancel)?;
        let mut store = self.read()?;
        if store.bindings.contains(&record) {
            return Ok(());
        }
        store.bindings.push(record);
        let contents = serde_json::to_vec(&store).map_err(|_| BindingError::InvalidFormat)?;
        self.write_atomic_cancellable(&contents, permit, cancel)
    }

    fn read(&self) -> Result<Store, BindingError> {
        let contents = match fs::read(&self.path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Store {
                    version: 1,
                    bindings: Vec::new(),
                });
            }
            Err(error) => return Err(error.into()),
        };
        // Deserialize once: duplicate fields, including `version`, must fail.
        let store: Store =
            serde_json::from_slice(&contents).map_err(|_| BindingError::InvalidFormat)?;
        if store.version != 1 {
            return Err(BindingError::UnsupportedVersion);
        }
        for record in &store.bindings {
            record.validate()?;
        }
        Ok(store)
    }

    fn directory(&self) -> &Path {
        self.path
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
    }

    #[cfg(test)]
    fn write_atomic(&self, contents: &[u8], permit: &TrustWritePermit) -> Result<(), BindingError> {
        self.write_atomic_cancellable(contents, permit, None)
    }

    fn write_atomic_cancellable(
        &self,
        contents: &[u8],
        permit: &TrustWritePermit,
        cancel: Option<&knock::Cancel>,
    ) -> Result<(), BindingError> {
        let mut prefix = std::ffi::OsString::from(".");
        prefix.push(self.path.file_name().ok_or(BindingError::InvalidFormat)?);
        prefix.push(".tmp.");
        // NamedTempFile uses exclusive creation, 0600 on Unix, and removes
        // its path on all handled failures (including cancellation/rename).
        let mut temporary = tempfile::Builder::new()
            .prefix(&prefix)
            .tempfile_in(self.directory())?;
        temporary.write_all(contents)?;
        temporary.as_file().sync_all()?;
        // Open before committing, so inability to open the directory cannot
        // report failure after a successful rename. fsync errors can still
        // occur after commit and are honestly returned as I/O failures.
        #[cfg(unix)]
        let directory = File::open(self.directory())?;
        let _active = permit.active()?;
        check_cancel(cancel)?;
        fs::rename(temporary.path(), &self.path)?;
        #[cfg(unix)]
        directory.sync_all()?;
        Ok(())
    }
}

fn check_cancel(cancel: Option<&knock::Cancel>) -> Result<(), BindingError> {
    if cancel.is_some_and(knock::Cancel::is_cancelled) {
        Err(BindingError::Cancelled)
    } else {
        Ok(())
    }
}

/// The fd, rather than the replaceable store inode, owns the advisory lock.
struct WriteLock {
    _file: File,
}

impl WriteLock {
    #[cfg(unix)]
    fn acquire(path: &Path) -> Result<Self, BindingError> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;
        let mut name = std::ffi::OsString::from(".");
        name.push(path.file_name().ok_or(BindingError::InvalidFormat)?);
        name.push(".lock");
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path.with_file_name(name))?;
        loop {
            // SAFETY: the guard owns this open fd throughout lock acquisition.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                return Ok(Self { _file: file });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error.into());
            }
        }
    }

    #[cfg(not(unix))]
    fn acquire(_path: &Path) -> Result<Self, BindingError> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "SSH binding file locks require Unix",
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn permit() -> TrustWritePermit {
        TrustWritePermit::new(RecoveryEpoch {
            connection: 1,
            network: 1,
        })
    }

    #[test]
    fn rename_failure_removes_prepared_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target");
        fs::create_dir(&target).unwrap();
        let store = SshBindings::open(target.clone());
        assert!(matches!(
            store.write_atomic(b"prepared", &permit()),
            Err(BindingError::Io(_))
        ));
        assert!(target.is_dir());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn cancellation_at_commit_removes_prepared_temporary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ssh_bindings.json");
        let authorization = permit();
        // Hold the real commit mutex while the writer prepares its file.
        let mut state = authorization.epoch.lock().unwrap();
        let worker_permit = authorization.clone();
        let store = SshBindings::open(path.clone());
        let worker = std::thread::spawn(move || store.write_atomic(b"prepared", &worker_permit));
        let deadline = Instant::now() + Duration::from_secs(5);
        while fs::read_dir(dir.path()).unwrap().count() == 0 {
            assert!(
                Instant::now() < deadline,
                "writer did not prepare a temporary file"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        // This is exactly invalidate's state change, under the same mutex.
        *state = None;
        drop(state);
        assert!(matches!(
            worker.join().unwrap(),
            Err(BindingError::Cancelled)
        ));
        assert!(!path.exists());
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }
}
