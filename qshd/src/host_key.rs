//! Persistent Noise identity: prepare privately, then publish without replacing a winner.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

use anyhow::{bail, Context, Result};
use std::ffi::{CStr, OsStr};
use transport::handshake::Keypair;

mod publication;
mod trusted;

/// Shared private directory policy; no key reading or permission repair.
pub(crate) fn trusted_parent(path: &Path, create: bool) -> io::Result<(File, std::ffi::OsString)> {
    trusted::resolve_parent(path, nix::unistd::Uid::effective(), create)
}

/// Load a persistent server Noise key, or atomically publish a new one if absent.
///
/// The file holds 64 raw bytes: the 32-byte X25519 private key followed by its
/// public key. Existing invalid or unreadable files are errors, never replaced.
/// Existing files are validated through the same opened descriptor before any
/// secret bytes are read: regular, owned by the effective UID, single-linked,
/// and below trusted parent directories. Group/other access is repaired on that
/// descriptor and checked before reading; failed repair is an error. A warning
/// after successful repair does not claim to undo any earlier disclosure.
/// Concurrent creators load the winner rather than changing its identity.
/// Creation requires filesystem/kernel support for atomic exclusive rename;
/// unsupported creation fails without a hard-link fallback. Existing trusted
/// keys do not require this support. All creation operations and winner reads
/// stay relative to the same verified parent directory descriptor.
/// Staging files are private from creation (mode 0600 on Unix). The staged file
/// is synced before publication; this does not promise power-loss durability of
/// the containing directory or cleanup of temporary names after a process crash.
pub fn load_or_create_transport_key(path: &Path) -> Result<Keypair> {
    load_or_create_with(path, &mut FileIo)
}

/// Load the existing trusted identity without creating a key or parent directory.
/// Validation and permission repair use the same descriptor policy as ordinary startup.
pub fn load_transport_key(path: &Path) -> Result<Keypair> {
    let bytes = FileIo
        .read(path, trusted::HOST_KEY)
        .context("existing qshd identity is unavailable; recovery cannot create an identity")?;
    decode_key(path, &bytes)
}

// Keep filesystem phase boundaries explicit so failure tests exercise the real
// staging/publication path while substituting only the failing operation.
trait KeyFileIo {
    /// The bytes of the trusted `expected` file at `path`.
    fn read(&mut self, path: &Path, expected: trusted::Expected) -> io::Result<Vec<u8>> {
        let loaded = trusted::read_as(
            path,
            nix::unistd::Uid::effective(),
            &mut trusted::FileIo,
            expected,
        )?;
        warn_repair(path, loaded.repaired_mode, expected.what);
        Ok(loaded.bytes)
    }

    fn write(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
        file.write_all(bytes)
    }

    fn sync(&mut self, file: &File) -> io::Result<()> {
        file.sync_all()
    }

    fn stage(&mut self, parent: &File) -> io::Result<publication::Stage> {
        publication::create(parent)
    }

    fn publish(&mut self, parent: &File, stage: &CStr, leaf: &OsStr) -> io::Result<()> {
        publication::rename(parent, stage, leaf)
    }

    fn cleanup(&mut self, parent: &File, stage: &CStr) -> io::Result<()> {
        publication::remove(parent, stage)
    }
}

struct FileIo;
impl KeyFileIo for FileIo {}

/// A static key file: the 32-byte private key, then its public key.
const KEY_FILE_LEN: usize = trusted::HOST_KEY.len;

/// The session-reset secret file: 32 raw bytes.
const SESSION_RESET_SECRET: trusted::Expected = trusted::Expected {
    len: transport::session_reset::SESSION_RESET_SECRET_LEN,
    what: "session-reset secret",
};

fn decode_key(path: &Path, bytes: &[u8]) -> Result<Keypair> {
    if bytes.len() != KEY_FILE_LEN {
        bail!(
            "key file {} is corrupt: expected 64 bytes, found {}",
            logging::diagnostic(&path.to_string_lossy()),
            bytes.len()
        );
    }
    let mut private = [0u8; 32];
    let mut public = [0u8; 32];
    private.copy_from_slice(&bytes[..32]);
    public.copy_from_slice(&bytes[32..]);
    Ok(Keypair { private, public })
}

fn load_or_create_with(path: &Path, io: &mut impl KeyFileIo) -> Result<Keypair> {
    let bytes = load_or_create_file(path, io, trusted::HOST_KEY, || {
        let keypair = transport::handshake::generate_keypair();
        let mut bytes = vec![0u8; 64];
        bytes[..32].copy_from_slice(&keypair.private);
        bytes[32..].copy_from_slice(&keypair.public);
        Ok(bytes)
    })?;
    decode_key(path, &bytes)
}

/// The session-reset secret kept beside the static key at `key_path`
/// (`transport::session_reset`): `<key file name>.session-reset`.
pub fn session_reset_secret_path(key_path: &Path) -> std::path::PathBuf {
    let mut name = key_path.file_name().unwrap_or_default().to_os_string();
    name.push(".session-reset");
    key_path.with_file_name(name)
}

/// Load the daemon's session-reset secret, or atomically publish a new one if
/// absent: 32 raw random bytes, under exactly the rules of the static key
/// ([`load_or_create_transport_key`]) -- trusted parents, owner, single link,
/// mode 0600 (repaired on the opened descriptor), never replaced when it is
/// there but invalid, and a concurrent creator's winner read back.
pub fn load_or_create_session_reset_secret(
    path: &Path,
) -> Result<transport::session_reset::SessionResetSecret> {
    load_or_create_secret_with(path, &mut FileIo)
}

fn load_or_create_secret_with(
    path: &Path,
    io: &mut impl KeyFileIo,
) -> Result<transport::session_reset::SessionResetSecret> {
    use transport::session_reset::{SessionResetSecret, SESSION_RESET_SECRET_LEN};
    let bytes = load_or_create_file(path, io, SESSION_RESET_SECRET, || {
        let secret = SessionResetSecret::generate()?;
        Ok(secret.expose().to_vec())
    })?;
    let Ok(raw) = <[u8; SESSION_RESET_SECRET_LEN]>::try_from(&bytes[..]) else {
        bail!(
            "session-reset secret {} is corrupt: expected {SESSION_RESET_SECRET_LEN} bytes, found {}",
            logging::diagnostic(&path.to_string_lossy()),
            bytes.len()
        );
    };
    Ok(SessionResetSecret::from_bytes(raw))
}

/// The `len` bytes of the file at `path`, read under the trusted-file rules, or --
/// when there is none -- the bytes `generate` makes, published there without
/// replacing a concurrent creator's winner (whose bytes are returned then).
fn load_or_create_file(
    path: &Path,
    io: &mut impl KeyFileIo,
    expected: trusted::Expected,
    generate: impl FnOnce() -> io::Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    let what = expected.what;
    match io.read(path, expected) {
        Ok(bytes) => return Ok(bytes),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("reading {}", logging::diagnostic(&path.to_string_lossy()))
            })
        }
    }

    let (parent, leaf) = trusted::prepare_parent(path, nix::unistd::Uid::effective())
        .with_context(|| {
            format!(
                "preparing parent for {}",
                logging::diagnostic(&path.to_string_lossy())
            )
        })?;
    let mut staged = io.stage(&parent).with_context(|| {
        format!(
            "staging {what} for {}",
            logging::diagnostic(&path.to_string_lossy())
        )
    })?;
    let bytes = match generate() {
        Ok(bytes) => bytes,
        Err(error) => {
            let error = anyhow::Error::new(error).context("generating a key");
            return Err(cleanup_error(io, &parent, &staged.name, what, error));
        }
    };
    let preparation = io
        .write(&mut staged.file, &bytes)
        .with_context(|| {
            format!(
                "writing staged {what} for {}",
                logging::diagnostic(&path.to_string_lossy())
            )
        })
        .and_then(|()| {
            io.sync(&staged.file).with_context(|| {
                format!(
                    "syncing staged {what} for {}",
                    logging::diagnostic(&path.to_string_lossy())
                )
            })
        });
    if let Err(error) = preparation {
        return Err(cleanup_error(io, &parent, &staged.name, what, error));
    }
    match io.publish(&parent, &staged.name, &leaf) {
        Ok(()) => Ok(bytes),
        Err(error) => {
            let exists = error.kind() == io::ErrorKind::AlreadyExists;
            let error = anyhow::Error::new(error).context(format!(
                "publishing {what} {} (requires atomic exclusive rename support)",
                logging::diagnostic(&path.to_string_lossy())
            ));
            // Only our exclusive staging name is removed. A failed cleanup is
            // an error even when another creator has already published a key.
            if let Err(cleanup) = io.cleanup(&parent, &staged.name) {
                return Err(error.context(format!("removing owned {what} stage failed: {cleanup}")));
            }
            if !exists {
                return Err(error);
            }
            // Never re-resolve the original pathname after an EEXIST race.
            let loaded = trusted::read_at_as(
                &parent,
                &leaf,
                nix::unistd::Uid::effective(),
                &mut trusted::FileIo,
                expected,
            )
            .with_context(|| {
                format!(
                    "reading winning {what} {}",
                    logging::diagnostic(&path.to_string_lossy())
                )
            })?;
            warn_repair(path, loaded.repaired_mode, what);
            Ok(loaded.bytes)
        }
    }
}

fn cleanup_error(
    io: &mut impl KeyFileIo,
    parent: &File,
    name: &CStr,
    what: &str,
    error: anyhow::Error,
) -> anyhow::Error {
    match io.cleanup(parent, name) {
        Ok(()) => error,
        Err(cleanup) => error.context(format!("removing owned {what} stage failed: {cleanup}")),
    }
}

fn warn_repair(path: &Path, mode: Option<u32>, what: &str) {
    if let Some(mode) = mode {
        crate::log::warn("qshd", &format!(
            "{what} {} was accessible to more than its owner (mode {mode:03o}); \
             verified file permissions tightened to 0600, which cannot undo a possible past disclosure",
            logging::diagnostic(&path.to_string_lossy())
        ));
    }
}

#[cfg(test)]
mod existing_identity_tests {
    #[test]
    fn existing_identity_never_creates_a_missing_parent_or_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent").join("identity");
        assert!(super::load_transport_key(&path).is_err());
        assert!(!path.parent().unwrap().exists());
    }

    #[test]
    fn existing_identity_preserves_the_original_and_rejects_invalid_bytes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let path = dir.path().join("identity");
        let original = super::load_or_create_transport_key(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            super::load_transport_key(&path).unwrap().public,
            original.public
        );
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        std::fs::write(&path, b"invalid").unwrap();
        assert!(super::load_transport_key(&path).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"invalid");
    }
}

#[cfg(test)]
mod session_reset_secret_tests {
    use std::os::unix::fs::PermissionsExt;

    fn private_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    /// Beside the key, named after it; created once, private, and read back
    /// unchanged by every later start.
    #[test]
    fn the_reset_secret_is_created_once_beside_the_key_and_kept() {
        let dir = private_dir();
        let key = dir.path().join("host_key");
        let path = super::session_reset_secret_path(&key);
        assert_eq!(path, dir.path().join("host_key.session-reset"));
        let first = super::load_or_create_session_reset_secret(&path).unwrap();
        let stored = std::fs::read(&path).unwrap();
        assert_eq!(stored, first.expose());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let again = super::load_or_create_session_reset_secret(&path).unwrap();
        assert_eq!(
            again.expose(),
            first.expose(),
            "the same secret after a restart"
        );
        assert_eq!(std::fs::read(&path).unwrap(), stored);
        assert_eq!(
            std::fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no stage left"
        );
    }

    /// The static key's rules: a file that is there but wrong is refused and
    /// left as it is, never replaced; one open to others is tightened first.
    #[test]
    fn a_wrong_reset_secret_is_refused_and_never_replaced() {
        let dir = private_dir();
        let path = dir.path().join("k.session-reset");
        std::fs::write(&path, [7u8; 31]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let error = format!(
            "{:#}",
            super::load_or_create_session_reset_secret(&path).unwrap_err()
        );
        assert!(
            error.contains("session-reset secret must contain exactly 32 bytes")
                && !error.contains("host key"),
            "named as what it is, never as the identity: {error}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), [7u8; 31]);

        std::fs::write(&path, [9u8; 32]).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let secret = super::load_or_create_session_reset_secret(&path).unwrap();
        assert_eq!(secret.expose(), &[9u8; 32]);
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let link = dir.path().join("link.session-reset");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(super::load_or_create_session_reset_secret(&link).is_err());
    }
}

#[cfg(test)]
#[path = "host_key/publication_flow_tests.rs"]
mod publication_flow_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    const WAIT: Duration = Duration::from_secs(10);

    fn private_dir() -> tempfile::TempDir {
        use std::os::unix::fs::PermissionsExt;
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap()
    }

    fn assert_identity(path: &Path, key: &Keypair) {
        let stored = std::fs::read(path).unwrap();
        assert_eq!(stored.len(), 64);
        assert!(
            stored[..32] == key.private,
            "stored private identity differs"
        );
        assert!(stored[32..] == key.public, "stored public identity differs");
    }

    #[derive(Clone, Copy)]
    enum Failure {
        Write,
        Sync,
        Publish,
    }

    struct FailingIo(Failure);
    impl KeyFileIo for FailingIo {
        fn write(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
            if matches!(self.0, Failure::Write) {
                file.write_all(&bytes[..17])?;
                return Err(io::Error::other("injected partial write failure"));
            }
            FileIo.write(file, bytes)
        }
        fn sync(&mut self, file: &File) -> io::Result<()> {
            if matches!(self.0, Failure::Sync) {
                return Err(io::Error::other("injected sync failure"));
            }
            FileIo.sync(file)
        }
        fn publish(&mut self, parent: &File, stage: &CStr, leaf: &OsStr) -> io::Result<()> {
            if matches!(self.0, Failure::Publish) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected publication failure",
                ));
            }
            FileIo.publish(parent, stage, leaf)
        }
    }

    fn fails_without_publishing(failure: Failure, message: &str) {
        let dir = private_dir();
        let path = dir.path().join("host.key");
        let unrelated = dir.path().join(".qshd-host-key-unrelated");
        std::fs::write(&unrelated, b"unrelated staging file").unwrap();
        let error = load_or_create_with(&path, &mut FailingIo(failure))
            .err()
            .expect("injected error");
        assert!(format!("{error:#}").contains(message));
        assert!(
            !path.exists(),
            "partial identity must never occupy the permanent name"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        assert_eq!(
            std::fs::read(&unrelated).unwrap(),
            b"unrelated staging file"
        );
        let key = load_or_create_transport_key(&path).expect("a subsequent creation succeeds");
        assert_identity(&path, &key);
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 2);
    }

    #[test]
    fn parent_path_replacement_does_not_redirect_publication() {
        use std::os::unix::fs::DirBuilderExt;
        struct SwapParent {
            original: std::path::PathBuf,
            moved: std::path::PathBuf,
        }
        impl KeyFileIo for SwapParent {
            fn write(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
                std::fs::rename(&self.original, &self.moved)?;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&self.original)?;
                FileIo.write(file, bytes)
            }
        }
        let dir = private_dir();
        let original = dir.path().join("parent");
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&original)
            .unwrap();
        let moved = dir.path().join("pinned");
        let path = original.join("host.key");
        let key = load_or_create_with(
            &path,
            &mut SwapParent {
                original: original.clone(),
                moved: moved.clone(),
            },
        )
        .unwrap();
        assert!(!path.exists(), "replacement directory must stay untouched");
        assert_identity(&moved.join("host.key"), &key);
        assert_eq!(std::fs::read_dir(&moved).unwrap().count(), 1);
    }

    #[test]
    fn partial_write_failure_leaves_no_permanent_identity() {
        fails_without_publishing(Failure::Write, "injected partial write failure");
    }

    #[test]
    fn sync_failure_leaves_no_permanent_identity() {
        fails_without_publishing(Failure::Sync, "injected sync failure");
    }

    #[test]
    fn publication_failure_leaves_no_permanent_identity() {
        fails_without_publishing(Failure::Publish, "injected publication failure");
    }

    struct PausedWriter {
        ready: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    impl KeyFileIo for PausedWriter {
        fn write(&mut self, file: &mut File, bytes: &[u8]) -> io::Result<()> {
            file.write_all(&bytes[..17])?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(file.metadata()?.permissions().mode() & 0o777, 0o600);
            }
            self.ready.send(()).unwrap();
            self.resume.recv_timeout(WAIT).unwrap();
            file.write_all(&bytes[17..])
        }
    }

    #[test]
    fn reader_cannot_observe_partial_identity() {
        let dir = private_dir();
        let path = dir.path().join("host.key");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        std::thread::scope(|scope| {
            let writer = scope.spawn(|| {
                load_or_create_with(
                    &path,
                    &mut PausedWriter {
                        ready: ready_tx,
                        resume: resume_rx,
                    },
                )
            });
            ready_rx.recv_timeout(WAIT).unwrap();
            let observation = std::fs::read(&path);
            resume_tx.send(()).unwrap();
            let key = writer.join().unwrap().unwrap();
            assert!(
                matches!(observation, Err(error) if error.kind() == io::ErrorKind::NotFound),
                "the permanent name became visible during a partial write"
            );
            assert_identity(&path, &key);
        });
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    struct PausedPublisher {
        ready: mpsc::Sender<()>,
        resume: mpsc::Receiver<()>,
    }
    impl KeyFileIo for PausedPublisher {
        fn publish(&mut self, parent: &File, stage: &CStr, leaf: &OsStr) -> io::Result<()> {
            self.ready.send(()).unwrap();
            self.resume.recv_timeout(WAIT).unwrap();
            FileIo.publish(parent, stage, leaf)
        }
    }

    #[test]
    fn concurrent_creators_return_the_same_published_identity() {
        let dir = private_dir();
        let path = dir.path().join("host.key");
        let (ready_tx, ready_rx) = mpsc::channel();
        let (go_a, wait_a) = mpsc::channel();
        let (go_b, wait_b) = mpsc::channel();
        std::thread::scope(|scope| {
            let mut a = PausedPublisher {
                ready: ready_tx.clone(),
                resume: wait_a,
            };
            let mut b = PausedPublisher {
                ready: ready_tx,
                resume: wait_b,
            };
            let path = &path;
            let first = scope.spawn(move || load_or_create_with(path, &mut a));
            let second = scope.spawn(move || load_or_create_with(path, &mut b));
            ready_rx.recv_timeout(WAIT).unwrap();
            ready_rx.recv_timeout(WAIT).unwrap();
            assert!(!path.exists());
            go_a.send(()).unwrap();
            go_b.send(()).unwrap();
            let first = first.join().unwrap().unwrap();
            let second = second.join().unwrap().unwrap();
            assert!(
                first.private == second.private && first.public == second.public,
                "creators returned different identities"
            );
            assert_identity(path, &first);
        });
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn concurrent_corrupt_winner_is_preserved_and_refused() {
        struct CorruptWinner;
        impl KeyFileIo for CorruptWinner {
            fn publish(&mut self, parent: &File, stage: &CStr, leaf: &OsStr) -> io::Result<()> {
                let fd = nix::fcntl::openat(
                    parent,
                    leaf,
                    nix::fcntl::OFlag::O_CREAT
                        | nix::fcntl::OFlag::O_EXCL
                        | nix::fcntl::OFlag::O_WRONLY,
                    nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR,
                )?;
                // SAFETY: openat returned a uniquely owned descriptor.
                let mut corrupt = File::from(fd);
                corrupt.write_all(b"incomplete existing identity")?;
                FileIo.publish(parent, stage, leaf)
            }
        }
        let dir = private_dir();
        let path = dir.path().join("host.key");
        assert!(load_or_create_with(&path, &mut CorruptWinner).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"incomplete existing identity"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn existing_corrupt_identity_is_preserved_and_refused() {
        let dir = private_dir();
        let path = dir.path().join("host.key");
        std::fs::write(&path, b"incomplete existing identity").unwrap();
        assert!(load_or_create_transport_key(&path).is_err());
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"incomplete existing identity"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn unreadable_identity_never_stages_a_replacement() {
        struct DeniedRead {
            reads: usize,
        }
        impl KeyFileIo for DeniedRead {
            fn read(&mut self, _: &Path, _: trusted::Expected) -> io::Result<Vec<u8>> {
                self.reads += 1;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "injected unreadable identity",
                ))
            }
        }
        let dir = private_dir();
        let path = dir.path().join("not-created/host.key");
        let mut denied = DeniedRead { reads: 0 };
        let error = load_or_create_with(&path, &mut denied).err().unwrap();
        assert_eq!(
            error.downcast_ref::<io::Error>().unwrap().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        assert_eq!(denied.reads, 1);

        let existing = dir.path().join("unreadable.key");
        std::fs::write(&existing, b"unreadable existing identity").unwrap();
        assert!(load_or_create_with(&existing, &mut denied).is_err());
        assert_eq!(denied.reads, 2, "read errors must not retry or publish");
        assert_eq!(
            std::fs::read(&existing).unwrap(),
            b"unreadable existing identity"
        );
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn existing_identity_keeps_its_bytes_and_permissions() {
        let dir = private_dir();
        let path = dir.path().join("nested/host.key");
        let key = load_or_create_transport_key(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let loaded = load_or_create_transport_key(&path).unwrap();
        assert!(key.private == loaded.private && key.public == loaded.public);
        assert_identity(&path, &key);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o400
            );
        }
        assert_eq!(
            std::fs::read_dir(path.parent().unwrap()).unwrap().count(),
            1
        );
    }

    #[test]
    fn directory_at_identity_path_is_not_replaced() {
        let dir = private_dir();
        let path = dir.path().join("host.key");
        std::fs::create_dir(&path).unwrap();
        assert!(load_or_create_transport_key(&path).is_err());
        assert!(path.is_dir());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[cfg(unix)]
    #[test]
    fn existing_symlink_is_refused_without_changing_its_target() {
        let dir = private_dir();
        let target = dir.path().join("original.key");
        let key = load_or_create_transport_key(&target).unwrap();
        let link = dir.path().join("host.key");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let refused = load_or_create_transport_key(&link).is_err();
        assert_identity(&target, &key);
        assert_eq!(std::fs::read_link(&link).unwrap(), target);
        assert!(
            refused,
            "an existing key symlink must fail before its secret is used"
        );
    }

    #[cfg(unix)]
    #[test]
    fn dangling_symlink_at_identity_path_is_not_replaced() {
        let dir = private_dir();
        let path = dir.path().join("host.key");
        let absent = dir.path().join("absent");
        std::os::unix::fs::symlink(&absent, &path).unwrap();
        assert!(load_or_create_transport_key(&path).is_err());
        assert_eq!(std::fs::read_link(&path).unwrap(), absent);
        assert!(!absent.exists());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
    }

    #[test]
    fn bare_relative_filename_uses_the_child_working_directory() {
        const CHILD: &str = "QSHD_TEST_RELATIVE_HOST_KEY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let path = Path::new("host.key");
            let key = load_or_create_transport_key(path).unwrap();
            assert_identity(path, &key);
            assert_eq!(std::fs::read_dir(".").unwrap().count(), 1);
            return;
        }
        let dir = private_dir();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "host_key::tests::bare_relative_filename_uses_the_child_working_directory",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .current_dir(dir.path())
            // The parent owns the only libtest summary in strict CI logs.
            // Panic diagnostics still reach stderr if this child fails.
            .stdout(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + WAIT;
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("relative host-key child timed out");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(
            std::fs::read(dir.path().join("host.key")).unwrap().len(),
            64
        );
    }
}
