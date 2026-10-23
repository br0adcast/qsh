//! Reading an account's authorized keys, as that account.
//!
//! The helper is root, so it could simply open the file. It deliberately
//! does not: it switches its EFFECTIVE identity to the account first --
//! user, group, AND supplementary groups -- and lets the kernel decide.
//! Every opened directory from `/` and the regular-file leaf must be owned
//! by root or that account, and not writable by group or others. Symlinks
//! and ambiguous path syntax are refused. Owned directory descriptors anchor
//! each next lookup; the leaf is read through the descriptor validated by
//! fstat. This preserves object identity across pathname replacement, not
//! immutable contents or permissions: root, the account and filesystem
//! authority remain trusted. Account-credential access also works with
//! root-squashed NFS homes without reading on root's authority.
//!
//! All three of user, group and supplementary groups move, not just the
//! user. An earlier version of this module switched only the effective
//! user id, reasoning that the default template
//! (`%h/.ssh/authorized_keys`) is a file the account owns outright, so
//! owner bits alone would decide. That reasoning missed the other half of
//! the kernel's rule: once the effective uid does NOT match a file's
//! owner, the GROUP bits decide instead, checked against the process's
//! effective gid and supplementary groups -- and a helper that has moved
//! only its uid is still carrying root's gid (0) and root's groups the
//! whole time. A `root:root`, `0640` file behind `root:root`, `0750`
//! directories -- `/etc/sudoers` is the standing example -- was therefore
//! readable through the uid-only version even though the account itself
//! could never read it: group 0 matched the helper's leftover effective
//! gid, not the account's. The reverse hole existed too: a file the
//! account COULD read through its OWN group membership was denied,
//! because the helper was never in that group. Either way, the login
//! decision was being made on a file the account could not have read on
//! its own authority -- exactly the outcome switching identity exists to
//! prevent. Switching gid and groups too closes both directions.
//!
//! The order matters in both directions, and is not interchangeable,
//! following the same rule [`super::drop_worker_privileges`] documents for
//! its own permanent version of this move:
//! - IN: supplementary groups, then the group id, then the user id.
//!   `setgroups` needs `CAP_SETGID` regardless of the target list, so it
//!   has to run while the helper is still fully root.
//! - OUT: the user id first, then the group id, then supplementary groups.
//!   Restoring the user id to root is always possible even after
//!   capabilities were stripped by the earlier uid transition, because the
//!   real and saved user ids never move here -- only `seteuid`, never
//!   `setuid` or `setresuid`, touches the effective id -- and POSIX lets an
//!   unprivileged effective id return to the real or saved id without any
//!   capability at all. Once the effective user id is back to 0, the
//!   kernel restores the full effective capability set from the untouched
//!   permitted set (the permitted set is only ever cleared by a uid
//!   transition where the real AND saved ids leave root too, which never
//!   happens here), and `CAP_SETGID` is available again for the group and
//!   the group list.
//!
//! The guard that does this ([`EffectiveIdentity`]) is built BEFORE the
//! first `set*` call, holding all three previous values, so a failure
//! partway through the switch -- `setgroups` took but `setegid` did not,
//! say -- still has something to roll back to through the same guard,
//! rather than needing a second, ad hoc recovery path. Any failure while
//! restoring aborts the process outright: there is no safe way to keep
//! running once it is no longer certain which identity is active.
//!
//! Reading itself is bounded, the way `sshd`'s `auth_openkeyfile` is:
//! opened `O_NONBLOCK` and checked with `fstat` before a single byte is
//! read, refusing anything that is not a regular file, then capped at
//! [`MAX_AUTHORIZED_KEYS_BYTES`]. Both close a denial-of-service an
//! account can otherwise inflict on every login on the machine, not just
//! its own, by putting something other than a plain file at its own key
//! path: a FIFO would make a blocking `open` hang -- and this helper is
//! single-threaded, so that one call stops it from serving anyone, ever
//! again -- and a symlink to `/dev/zero` (or simply an enormous regular
//! file) would grow this still-privileged process's memory without limit
//! if the read had no cap.
//!
//! The trick is sound only because the helper is single-threaded: between
//! the switch and the switch back it does nothing else at all, on this
//! thread or any other -- there is no other thread whose file access could
//! be affected by, or race, this process-wide identity change. Tests in
//! this crate's own multi-threaded harness are a different story:
//! `seteuid`/`setegid`/`setgroups` apply to every thread in the process at
//! once (glibc's wrappers synchronize them across the whole thread group),
//! not just the calling test's, so a test that switches to a genuinely
//! different identity could leave a concurrently-running, unrelated test
//! executing as that identity too. Such tests live in their own
//! single-threaded integration binary under `qshd/tests/` rather than in
//! this module's own `#[cfg(test)]` block, which runs under `cargo test
//! -p qshd --features system --lib` without `--test-threads=1`.

use std::fmt;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;

use nix::fcntl::{self, OFlag};
use nix::sys::stat::{self, SFlag};
use nix::unistd::{Gid, Uid};

use super::account::Account;

/// Real authorized_keys files are a handful of kilobytes at most, even
/// with a few hundred keys in them. This bounds a single read generously
/// above that -- large enough that no legitimate file is ever truncated --
/// so an account cannot make the helper allocate unbounded memory by
/// pointing its key path at something large: a giant regular file, or --
/// absent the regular-file check next to this constant's only use -- a
/// symlink to `/dev/zero`.
const MAX_AUTHORIZED_KEYS_BYTES: u64 = 1024 * 1024; // 1 MiB

/// Why `read_for` did not return the account's keys.
#[derive(Debug)]
pub enum AuthorizedError {
    /// Could not become the account long enough to read its file.
    Switch(String),
    /// The account's own effective identity still could not read the file
    /// -- anything other than "not found", which is not an error at all,
    /// see `read_for`'s docs. Also covers the file failing the
    /// not-a-regular-file or too-large checks below.
    Read { path: String, why: String },
}

impl fmt::Display for AuthorizedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AuthorizedError::Switch(msg) => {
                write!(f, "could not switch to the account to read its keys: {msg}")
            }
            AuthorizedError::Read { path, why } => {
                write!(f, "could not read {path} as the account: {why}")
            }
        }
    }
}

impl std::error::Error for AuthorizedError {}

/// Captured by the helper before fork; never reconstructed from a possibly
/// reparented verifier. Unrelated readers pass no verifier context.
#[derive(Clone, Copy)]
pub(super) struct VerifierParent {
    #[cfg(target_os = "linux")]
    helper_pid: nix::unistd::Pid,
    #[cfg(test)]
    observer: fn(VerifierBoundary),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerifierBoundary {
    BeforeInitialArm,
    Armed,
    GroupsInstalled,
    BeforeRearm(IdentityTransition),
    AfterRearm(IdentityTransition),
    BeforeRead,
    BeforeRestore,
    Restored,
}

#[cfg(test)]
pub(super) fn ignore_verifier_boundary(_: VerifierBoundary) {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IdentityTransition {
    EntryGroup,
    EntryUser,
    RestoreUser,
    RestoreGroup,
}

impl VerifierParent {
    #[cfg(target_os = "linux")]
    pub(super) fn new(
        helper_pid: nix::unistd::Pid,
        #[cfg(test)] observer: fn(VerifierBoundary),
    ) -> Self {
        Self {
            helper_pid,
            #[cfg(test)]
            observer,
        }
    }

    fn check_or_exit(self) {
        #[cfg(target_os = "linux")]
        if super::arm_and_verify_pdeathsig(self.helper_pid).is_err() {
            // A verifier must not turn lost parent protection into an ordinary
            // authentication error and resume potentially blocking work.
            unsafe { nix::libc::_exit(127) };
        }
    }

    pub(super) fn arm_initial(self) {
        #[cfg(test)]
        self.observe(VerifierBoundary::BeforeInitialArm);
        self.check_or_exit();
        #[cfg(test)]
        self.observe(VerifierBoundary::Armed);
    }

    fn rearm(self, _transition: IdentityTransition) {
        #[cfg(test)]
        self.observe(VerifierBoundary::BeforeRearm(_transition));
        self.check_or_exit();
        #[cfg(test)]
        self.observe(VerifierBoundary::AfterRearm(_transition));
    }

    #[cfg(test)]
    fn observe(self, boundary: VerifierBoundary) {
        (self.observer)(boundary);
    }
}

/// A guard that puts the effective identity -- user, group, and
/// supplementary groups, in that order -- back. Being a guard rather than
/// a sequence of calls is the point: an early return, an error, or a panic
/// must not be able to leave the helper running as somebody else, in
/// somebody else's group, or carrying somebody else's supplementary
/// groups.
struct EffectiveIdentity {
    previous_uid: Uid,
    previous_gid: Gid,
    previous_groups: Vec<Gid>,
    verifier_parent: Option<VerifierParent>,
}

impl EffectiveIdentity {
    /// Become `account`: its supplementary groups, then its group, then
    /// its user -- see this module's docs for why that order. The guard
    /// (capturing the previous identity) is built BEFORE the first `set*`
    /// call, not after the last one, so a failure partway through the
    /// switch still has something to roll back to when this returns `Err`
    /// and the partially-built guard drops.
    fn become_account(
        account: &Account,
        verifier_parent: Option<VerifierParent>,
    ) -> Result<EffectiveIdentity, AuthorizedError> {
        let guard = EffectiveIdentity {
            verifier_parent,
            previous_uid: Uid::effective(),
            previous_gid: Gid::effective(),
            previous_groups: nix::unistd::getgroups()
                .map_err(|e| AuthorizedError::Switch(e.to_string()))?,
        };
        nix::unistd::setgroups(&account.groups)
            .map_err(|e| AuthorizedError::Switch(e.to_string()))?;
        // Supplementary-group changes do not clear PDEATHSIG. Effective gid
        // and uid transitions do, including the reverse transitions in Drop.
        #[cfg(test)]
        if let Some(parent) = verifier_parent {
            parent.observe(VerifierBoundary::GroupsInstalled);
        }
        nix::unistd::setegid(account.gid).map_err(|e| AuthorizedError::Switch(e.to_string()))?;
        if let Some(parent) = verifier_parent {
            parent.rearm(IdentityTransition::EntryGroup);
        }
        nix::unistd::seteuid(account.uid).map_err(|e| AuthorizedError::Switch(e.to_string()))?;
        if let Some(parent) = verifier_parent {
            parent.rearm(IdentityTransition::EntryUser);
        }
        Ok(guard)
    }
}

impl Drop for EffectiveIdentity {
    fn drop(&mut self) {
        // Order is the reverse of becoming the account, and is not a
        // choice: `setgroups` needs `CAP_SETGID`, which is only present
        // again once the effective user id is back to root -- see this
        // module's docs.
        #[cfg(test)]
        if let Some(parent) = self.verifier_parent {
            parent.observe(VerifierBoundary::BeforeRestore);
        }
        let restored = (|| -> nix::Result<()> {
            nix::unistd::seteuid(self.previous_uid)?;
            if let Some(parent) = self.verifier_parent {
                parent.rearm(IdentityTransition::RestoreUser);
            }
            nix::unistd::setegid(self.previous_gid)?;
            if let Some(parent) = self.verifier_parent {
                parent.rearm(IdentityTransition::RestoreGroup);
            }
            nix::unistd::setgroups(&self.previous_groups)?;
            Ok(())
        })()
        .is_ok();
        if !restored {
            // There is no recovering from this and no safe way to
            // continue: the helper would go on believing it is root while
            // it is not, or worse, stay as somebody else, in somebody
            // else's group. Die loudly instead.
            crate::log::error(
                "helper",
                "could not restore the effective identity after reading \
                 authorized_keys -- aborting",
            );
            std::process::abort();
        }
        #[cfg(test)]
        if let Some(parent) = self.verifier_parent {
            parent.observe(VerifierBoundary::Restored);
        }
    }
}

/// The exact flags used when opening an authorization leaf. Pulled out
/// into a named constant, rather than written inline at the one call site,
/// specifically so this module's own fork-based test can reference the
/// SAME value (as a plain integer, computed once before the fork -- see
/// that test) instead of a hand-copied duplicate that could silently drift
/// out of sync with the real flags over time.
///
/// `O_NOCTTY` is the one that matters most outside this file: without it,
/// a process that is a session leader with no controlling terminal --
/// which, under systemd, the helper's own main process (the parent in
/// `split_and_run`) is -- acquires whatever terminal device it opens here
/// AS its controlling terminal.
///
/// The terminal has to be one no session has claimed: a device that is
/// already some other session's controlling terminal cannot become this
/// process's, so pointing the template at `$(tty)` -- the account's own
/// login terminal -- does nothing. What does work is a pty the account
/// opened itself and kept the master of (`openpty`, and never a `setsid`
/// on the slave), pointed at by its own `authorized_keys` path. One login
/// attempt is then enough to attach it to the helper, after which a `^C`
/// or a hang-up on the master sends the resulting `SIGINT`/`SIGHUP` to the
/// helper: the helper dies (a clean exit as far as systemd's
/// `Restart=on-failure` is concerned, so it does not even restart), the
/// worker follows through its parent-death signal, and every session on
/// the machine drops -- a denial of service reachable by any account, not
/// just root. The open happens under the account's switched identity, but
/// the controlling-terminal attachment is a property of the PROCESS, not
/// the identity, so switching identity does nothing to prevent it; only
/// `O_NOCTTY` does.
const OPEN_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_NONBLOCK)
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_NOCTTY)
    .union(OFlag::O_NOFOLLOW);

/// Keep the kernel's old full-path work bound even though traversal is now
/// component-wise. Inspect raw bytes: Path::components normalizes dot segments.
fn absolute_components(path: &Path) -> std::io::Result<Vec<&std::ffi::OsStr>> {
    use std::os::unix::ffi::OsStrExt;
    let bytes = path.as_os_str().as_bytes();
    if !bytes.starts_with(b"/")
        || bytes.ends_with(b"/")
        || bytes.len() >= 4096
        || bytes.contains(&0)
    {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput,
            "authorized_keys requires an absolute file path shorter than 4096 bytes, without NUL or trailing slash"));
    }
    let mut components = Vec::new();
    for part in bytes
        .split(|byte| *byte == b'/')
        .filter(|part| !part.is_empty())
    {
        if part == b"." || part == b".." {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "authorized_keys path must not contain dot or parent components",
            ));
        }
        components.push(std::ffi::OsStr::from_bytes(part));
    }
    Ok(components)
}

fn validate_object(fd: std::os::fd::RawFd, uid: Uid, kind: SFlag) -> std::io::Result<()> {
    let metadata = stat::fstat(fd).map_err(std::io::Error::from)?;
    if metadata.st_mode & SFlag::S_IFMT.bits() != kind.bits() {
        let reason = if kind == SFlag::S_IFREG {
            "not a regular file"
        } else {
            "not a directory"
        };
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            reason,
        ));
    }
    if metadata.st_uid != 0 && metadata.st_uid != uid.as_raw() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "authorized_keys object has an untrusted owner",
        ));
    }
    if metadata.st_mode & 0o022 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "authorized_keys object is writable by group or others",
        ));
    }
    Ok(())
}

const DIRECTORY_FLAGS: OFlag = OFlag::O_PATH
    .union(OFlag::O_DIRECTORY)
    .union(OFlag::O_NOFOLLOW)
    .union(OFlag::O_CLOEXEC);

/// The descriptor, rather than its old pathname, anchors the next lookup.
struct TrustedDirectory(std::fs::File);

impl TrustedDirectory {
    fn from_fd(fd: std::os::fd::RawFd, uid: Uid) -> std::io::Result<Self> {
        // SAFETY: the successful open transfers its sole descriptor immediately.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        validate_object(file.as_raw_fd(), uid, SFlag::S_IFDIR)?;
        Ok(Self(file))
    }

    fn root(uid: Uid) -> std::io::Result<Self> {
        let fd = fcntl::open(Path::new("/"), DIRECTORY_FLAGS, stat::Mode::empty())?;
        Self::from_fd(fd, uid)
    }

    fn child(&self, name: &std::ffi::OsStr, uid: Uid) -> std::io::Result<Self> {
        let fd = fcntl::openat(
            Some(self.0.as_raw_fd()),
            name,
            DIRECTORY_FLAGS,
            stat::Mode::empty(),
        )?;
        Self::from_fd(fd, uid)
    }

    fn leaf(&self, name: &std::ffi::OsStr, uid: Uid) -> std::io::Result<std::fs::File> {
        let fd = fcntl::openat(
            Some(self.0.as_raw_fd()),
            name,
            OPEN_FLAGS,
            stat::Mode::empty(),
        )?;
        // SAFETY: immediately own the new fd, including on validation failure.
        let file = unsafe { std::fs::File::from_raw_fd(fd) };
        validate_object(file.as_raw_fd(), uid, SFlag::S_IFREG)?;
        Ok(file)
    }
}

/// All components come from absolute_components, so no openat argument can
/// escape this descriptor through slashes, dot or parent segments.
fn read_beneath(
    mut dir: TrustedDirectory,
    components: &[&std::ffi::OsStr],
    uid: Uid,
) -> std::io::Result<Option<String>> {
    let (leaf, parents) = components.split_last().expect("validated file path");
    for name in parents {
        dir = match dir.child(name, uid) {
            Ok(child) => child,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
    }
    match dir.leaf(leaf, uid) {
        Ok(file) => read_opened_regular_file(file),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

fn read_trusted_file(path: &Path, uid: Uid) -> std::io::Result<Option<String>> {
    let components = absolute_components(path)?;
    read_beneath(TrustedDirectory::root(uid)?, &components, uid)
}

/// Explicit test-only byte-reader mock for helper protocol tests. It bypasses
/// identity and path-trust policy, and cannot be selected by production.
#[cfg(test)]
pub(super) fn read_regular_file_bounded(path: &Path) -> std::io::Result<Option<String>> {
    let fd = match fcntl::open(path, OPEN_FLAGS, stat::Mode::empty()) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    // SAFETY: this is the sole owner of the descriptor just opened above.
    read_opened_regular_file(unsafe { std::fs::File::from_raw_fd(fd) })
}

fn read_opened_regular_file(mut file: std::fs::File) -> std::io::Result<Option<String>> {
    let fd = file.as_raw_fd();
    let metadata = stat::fstat(fd).map_err(std::io::Error::from)?;
    if metadata.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFREG.bits() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to read authorized_keys: not a regular file",
        ));
    }

    // Regular-file and network-filesystem I/O can still block. The verifier
    // child timeout bounds the attempt; O_NONBLOCK only prevents FIFO open
    // from waiting for a writer before the type check above.
    fcntl::fcntl(fd, fcntl::FcntlArg::F_SETFL(OFlag::empty())).map_err(std::io::Error::from)?;

    let mut buf = Vec::new();
    let read = (&mut file)
        .take(MAX_AUTHORIZED_KEYS_BYTES + 1)
        .read_to_end(&mut buf)?;
    if read > MAX_AUTHORIZED_KEYS_BYTES as usize {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("authorized_keys is larger than {MAX_AUTHORIZED_KEYS_BYTES} bytes"),
        ));
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))
}

/// Turn what the bounded reader found into `read_for`'s result:
/// a missing file is not an error (an account that has added no key admits
/// nobody, which is a policy, not a failure), and any other read failure
/// becomes an [`AuthorizedError::Read`] naming the path. Split out from
/// `read_for` itself so this pure mapping -- which needs no privilege at
/// all -- can be tested directly, independent of the identity switch that
/// the rest of `read_for` cannot exercise without root (see this module's
/// docs and `qshd/tests/authorized_keys_privilege.rs`).
///
/// Shared with the explicit test-only protocol reader.
pub(super) fn to_key_text(
    found: std::io::Result<Option<String>>,
    path: &Path,
) -> Result<String, AuthorizedError> {
    match found {
        Ok(Some(text)) => Ok(text),
        Ok(None) => Ok(String::new()),
        Err(e) => Err(AuthorizedError::Read {
            path: path.display().to_string(),
            why: e.to_string(),
        }),
    }
}

/// Read `account`'s authorized keys. A missing file is not an error: an
/// account that has added no key admits nobody, which is a policy, not a
/// failure.
pub fn read_for(account: &Account, template: &str) -> Result<String, AuthorizedError> {
    read_for_verifier(account, template, None)
}

pub(super) fn read_for_verifier(
    account: &Account,
    template: &str,
    verifier_parent: Option<VerifierParent>,
) -> Result<String, AuthorizedError> {
    let path = super::account::expand_template(template, account);
    let _as_them = EffectiveIdentity::become_account(account, verifier_parent)?;
    #[cfg(test)]
    if let Some(parent) = verifier_parent {
        parent.observe(VerifierBoundary::BeforeRead);
    }
    to_key_text(read_trusted_file(&path, account.uid), &path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn safe_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        set_mode(dir.path(), 0o700);
        dir
    }

    fn write_safe(path: impl AsRef<Path>, bytes: impl AsRef<[u8]>) -> std::io::Result<()> {
        std::fs::write(path.as_ref(), bytes)?;
        set_mode(path.as_ref(), 0o644);
        Ok(())
    }

    fn create_safe_dir(path: impl AsRef<Path>) -> std::io::Result<()> {
        std::fs::create_dir(path.as_ref())?;
        set_mode(path.as_ref(), 0o755);
        Ok(())
    }

    // This anchor is test-only: it proves descendant traversal, not production
    // root trust. Production always obtains its anchor from root().
    fn anchor(path: &Path) -> TrustedDirectory {
        let fd = fcntl::open(path, DIRECTORY_FLAGS, stat::Mode::empty()).unwrap();
        TrustedDirectory::from_fd(fd, Uid::effective()).unwrap()
    }

    fn anchored_read(dir: &Path, relative: &str) -> std::io::Result<Option<String>> {
        let absolute = std::path::PathBuf::from(format!("/{relative}"));
        let components = absolute_components(&absolute)?;
        read_beneath(anchor(dir), &components, Uid::effective())
    }

    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn each_writable_ancestor_is_refused_before_reading_or_missing_leaf() {
        let dir = safe_tempdir();
        let higher = dir.path().join("higher");
        let parent = higher.join("parent");
        std::fs::create_dir_all(&parent).unwrap();
        set_mode(&higher, 0o755);
        set_mode(&parent, 0o755);
        write_safe(parent.join("keys"), "safe").unwrap();
        for object in [&higher, &parent] {
            for mode in [0o775, 0o757] {
                assert_eq!(
                    anchored_read(dir.path(), "higher/parent/keys")
                        .unwrap()
                        .as_deref(),
                    Some("safe")
                );
                set_mode(object, mode);
                for leaf in ["keys", "missing"] {
                    let error =
                        anchored_read(dir.path(), &format!("higher/parent/{leaf}")).unwrap_err();
                    assert!(
                        error.to_string().contains("writable by group or others"),
                        "{error}"
                    );
                }
                set_mode(object, 0o755);
            }
        }
    }

    #[test]
    fn symlinks_are_refused_for_leaf_directory_and_loop() {
        use std::os::unix::fs::symlink;
        let dir = safe_tempdir();
        create_safe_dir(dir.path().join("safe")).unwrap();
        write_safe(dir.path().join("safe/keys"), "safe").unwrap();
        assert_eq!(
            anchored_read(dir.path(), "safe/keys").unwrap().as_deref(),
            Some("safe")
        );
        symlink("safe/keys", dir.path().join("leaf")).unwrap();
        symlink("safe", dir.path().join("parent")).unwrap();
        symlink("loop", dir.path().join("loop")).unwrap();
        for path in ["leaf", "parent/keys", "loop", "loop/keys"] {
            assert!(anchored_read(dir.path(), path).is_err(), "{path}");
        }
    }

    #[test]
    fn repeated_success_and_refusal_close_every_descriptor() {
        const CHILD: &str = "QSHD_TEST_AUTHORIZED_FD_CHILD";
        if std::env::var(CHILD).as_deref() != Ok("1") {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "helper::authorized::tests::repeated_success_and_refusal_close_every_descriptor", "--nocapture"])
                .env(CHILD, "1").output().unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("descriptor checks completed"));
            return;
        }
        // A fresh test process excludes unrelated concurrent fd activity.
        let dir = safe_tempdir();
        write_safe(dir.path().join("keys"), "safe").unwrap();
        write_safe(dir.path().join("unsafe"), "unsafe").unwrap();
        set_mode(&dir.path().join("unsafe"), 0o666);
        std::os::unix::fs::symlink("keys", dir.path().join("link")).unwrap();
        let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
        let before = count();
        for _ in 0..256 {
            assert_eq!(
                anchored_read(dir.path(), "keys").unwrap().as_deref(),
                Some("safe")
            );
            assert!(anchored_read(dir.path(), "missing").unwrap().is_none());
            assert!(anchored_read(dir.path(), "unsafe").is_err());
            assert!(anchored_read(dir.path(), "link").is_err());
        }
        assert_eq!(count(), before);
        println!("descriptor checks completed");
    }

    #[test]
    fn path_syntax_is_checked_before_normalization() {
        for path in [
            "",
            "keys",
            "/",
            "//",
            "/keys/",
            "/./keys",
            "/a/../keys",
            "/a/.",
            "/a/..",
            "/a\0b",
        ] {
            assert!(absolute_components(Path::new(path)).is_err(), "{path:?}");
        }
        assert!(absolute_components(Path::new(&format!("/{}", "a".repeat(4095)))).is_err());
        assert_eq!(
            absolute_components(Path::new("//a///keys")).unwrap(),
            vec![std::ffi::OsStr::new("a"), std::ffi::OsStr::new("keys")]
        );
    }

    #[test]
    fn production_root_walk_refuses_private_keys_below_tmp() {
        let dir = tempfile::tempdir_in("/tmp").unwrap();
        set_mode(dir.path(), 0o700);
        let path = dir.path().join("keys");
        write_safe(&path, "safe").unwrap();
        assert_eq!(
            anchored_read(dir.path(), "keys").unwrap().as_deref(),
            Some("safe")
        );
        let error = read_trusted_file(&path, Uid::effective()).unwrap_err();
        assert!(
            error.to_string().contains("writable by group or others"),
            "{error}"
        );
    }

    #[test]
    fn opened_directory_is_not_redirected_by_path_replacement() {
        let dir = safe_tempdir();
        let parent = dir.path().join("parent");
        create_safe_dir(&parent).unwrap();
        write_safe(parent.join("keys"), "original").unwrap();
        let opened = anchor(dir.path())
            .child(std::ffi::OsStr::new("parent"), Uid::effective())
            .unwrap();
        std::fs::rename(&parent, dir.path().join("moved")).unwrap();
        create_safe_dir(&parent).unwrap();
        write_safe(parent.join("keys"), "replacement").unwrap();
        set_mode(&parent, 0o777);
        assert_eq!(
            read_beneath(opened, &[std::ffi::OsStr::new("keys")], Uid::effective())
                .unwrap()
                .as_deref(),
            Some("original")
        );
        assert!(anchored_read(dir.path(), "parent/keys").is_err());
    }

    #[test]
    fn opened_leaf_metadata_and_bytes_survive_path_replacement() {
        let dir = safe_tempdir();
        let path = dir.path().join("keys");
        write_safe(&path, "original").unwrap();
        let opened = anchor(dir.path())
            .leaf(std::ffi::OsStr::new("keys"), Uid::effective())
            .unwrap();
        let inode = stat::fstat(opened.as_raw_fd()).unwrap().st_ino;
        std::fs::rename(&path, dir.path().join("moved")).unwrap();
        write_safe(&path, "replacement").unwrap();
        set_mode(&path, 0o666);
        if Uid::effective().is_root()
            && std::env::var("QSHD_TEST_DISPOSABLE_HOST").as_deref() == Ok("1")
        {
            std::os::unix::fs::chown(&path, Some(61002), Some(61002)).unwrap();
        }
        assert_eq!(stat::fstat(opened.as_raw_fd()).unwrap().st_ino, inode);
        assert_eq!(
            read_opened_regular_file(opened).unwrap().as_deref(),
            Some("original")
        );
        assert!(anchored_read(dir.path(), "keys").is_err());
    }

    #[test]
    fn trusted_leaf_keeps_type_size_and_utf8_bounds() {
        let dir = safe_tempdir();
        assert!(anchored_read(dir.path(), "missing/keys").unwrap().is_none());
        let path = dir.path().join("keys");
        write_safe(&path, vec![b'a'; MAX_AUTHORIZED_KEYS_BYTES as usize]).unwrap();
        assert_eq!(
            anchored_read(dir.path(), "keys").unwrap().unwrap().len(),
            MAX_AUTHORIZED_KEYS_BYTES as usize
        );
        write_safe(&path, vec![b'a'; MAX_AUTHORIZED_KEYS_BYTES as usize + 1]).unwrap();
        assert!(anchored_read(dir.path(), "keys")
            .unwrap_err()
            .to_string()
            .contains("larger than"));
        write_safe(&path, [0xff]).unwrap();
        assert_eq!(
            anchored_read(dir.path(), "keys").unwrap_err().kind(),
            std::io::ErrorKind::InvalidData
        );
        std::fs::remove_file(&path).unwrap();
        create_safe_dir(&path).unwrap();
        assert!(anchored_read(dir.path(), "keys")
            .unwrap_err()
            .to_string()
            .contains("not a regular file"));
        std::fs::remove_dir(&path).unwrap();
        let _socket = std::os::unix::net::UnixListener::bind(&path).unwrap();
        assert!(anchored_read(dir.path(), "keys").is_err());
        std::fs::remove_file(&path).unwrap();
        nix::unistd::mkfifo(&path, stat::Mode::from_bits_truncate(0o600)).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            tx.send(anchored_read(dir.path(), "keys").is_err()).unwrap();
        });
        assert!(rx.recv_timeout(std::time::Duration::from_secs(2)).unwrap());
    }

    // Every test below exercises `read_regular_file_bounded` and
    // `to_key_text` directly rather than `read_for`. That is not a
    // shortcut: `read_for` now always goes through
    // `EffectiveIdentity::become_account`, whose first call is
    // `setgroups` -- and `setgroups` needs `CAP_SETGID` unconditionally,
    // for ANY target list, including a list identical to the caller's own
    // (unlike `seteuid`/`setegid`, there is no "same value" exemption for
    // an unprivileged caller). So even "become yourself" now fails without
    // root, and a test that called `read_for` here would fail every time
    // this crate is tested the ordinary way. The file-reading behaviour
    // below has nothing to do with identity, so it is tested at the layer
    // that actually implements it; the identity switch itself is tested
    // for real, under root, in `qshd/tests/authorized_keys_privilege.rs`.

    /// Reading as the account itself means the kernel does the permission
    /// checks, the symlink resolution and the directory traversal -- so a
    /// link pointing into somebody else's file cannot be followed on our
    /// authority. (The identity switch that makes that true is exercised
    /// under root, see the note above; this proves the read on top of it
    /// returns real content.)
    #[test]
    fn a_readable_file_comes_back() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keys");
        std::fs::write(&path, "ssh-ed25519 AAAA test\n").expect("write");
        let text = read_regular_file_bounded(&path)
            .expect("read")
            .expect("the file exists");
        assert!(text.contains("ssh-ed25519"));
    }

    #[test]
    fn group_writable_authorization_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = safe_tempdir();
        let path = dir.path().join("keys");
        std::fs::write(&path, "attacker key").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            anchored_read(dir.path(), "keys").unwrap().as_deref(),
            Some("attacker key")
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o664)).unwrap();
        assert!(
            anchored_read(dir.path(), "keys").is_err(),
            "group-writable authorization must be refused"
        );
    }

    /// A missing file reads as `None`, not an error -- `to_key_text` below
    /// is what turns that into an empty string; the account that has
    /// added no key admits nobody, which is a policy, not a failure.
    #[test]
    fn a_missing_file_is_none() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent");
        assert!(read_regular_file_bounded(&path).expect("read").is_none());
    }

    /// The other, non-"not found" error path: a directory where a file was
    /// expected. Opening a directory itself succeeds on Linux; it is the
    /// `fstat` check that refuses it, the same way it refuses a FIFO or a
    /// device below.
    #[test]
    fn a_directory_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let err = read_regular_file_bounded(dir.path()).expect_err("a directory must be refused");
        assert!(err.to_string().contains("not a regular file"), "got: {err}");
    }

    /// A FIFO at the key path must be refused immediately, not block the
    /// (single-threaded, in production) reader forever. No root needed:
    /// planting a FIFO in a tempdir the caller owns is an ordinary,
    /// unprivileged filesystem operation.
    ///
    /// The call runs on a background thread with a bounded wait here,
    /// specifically so that a regression (a blocking `open` again) fails
    /// this test suite within a few seconds instead of hanging it forever
    /// -- which is the whole point of the fix this test guards.
    #[test]
    fn a_fifo_is_refused_without_blocking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("fifo");
        nix::unistd::mkfifo(&path, stat::Mode::from_bits_truncate(0o600)).expect("mkfifo");

        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let result = read_regular_file_bounded(&path);
            // The receiver may already be gone if this test itself timed
            // out and moved on; that is fine, there is nothing left to
            // report to. The thread itself may stay blocked forever if the
            // fix regresses -- acceptable for a test process about to
            // report a failure and exit, see this module's docs on why
            // that block is the thing being guarded against in the first
            // place.
            let _ = tx.send(result.is_ok());
        });
        match rx.recv_timeout(std::time::Duration::from_secs(2)) {
            Ok(was_ok) => assert!(!was_ok, "a fifo must be refused, not read"),
            Err(_) => panic!(
                "read_regular_file_bounded did not return within 2s on a FIFO -- it is \
                 blocking in open() instead of refusing the FIFO immediately"
            ),
        }
    }

    /// A regular file larger than the cap is refused rather than read in
    /// full -- the other half of the same bound, for the case the
    /// not-a-regular-file check does not catch (an ordinary file that is
    /// simply too big).
    #[test]
    fn a_file_over_the_size_limit_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("keys");
        std::fs::write(&path, vec![b'a'; MAX_AUTHORIZED_KEYS_BYTES as usize + 1]).expect("write");
        let err = read_regular_file_bounded(&path)
            .expect_err("a file over the size limit must be refused");
        assert!(err.to_string().contains("larger than"), "got: {err}");
    }

    /// `to_key_text`'s three branches, exercised directly and without
    /// needing a filesystem at all: found text passes through untouched,
    /// a missing file becomes an empty string, and any other error is
    /// wrapped as `AuthorizedError::Read` naming the path.
    #[test]
    fn to_key_text_maps_found_missing_and_error() {
        let path = Path::new("/some/path");

        assert_eq!(
            to_key_text(Ok(Some("keys".to_string())), path).expect("passes through"),
            "keys"
        );
        assert_eq!(
            to_key_text(Ok(None), path).expect("missing becomes empty"),
            ""
        );

        let err = to_key_text(Err(std::io::Error::other("boom")), path)
            .expect_err("an io error must become AuthorizedError::Read");
        assert!(matches!(err, AuthorizedError::Read { .. }));
        assert!(err.to_string().contains("/some/path"));
        assert!(err.to_string().contains("boom"));
    }

    /// `AuthorizedError` needs `Display` and `std::error::Error`: a later
    /// task wraps it with `.with_context(...)`, which requires exactly
    /// that.
    #[test]
    fn authorized_error_implements_the_error_trait() {
        fn assert_error<E: std::error::Error>() {}
        assert_error::<AuthorizedError>();
        assert_eq!(
            AuthorizedError::Switch("nope".to_string()).to_string(),
            "could not switch to the account to read its keys: nope"
        );
    }

    /// `OPEN_FLAGS` (and so `read_regular_file_bounded`) must never acquire
    /// a controlling terminal, no matter what kind of device the template
    /// happens to point at. Proving that needs an actual process that is a
    /// session leader with no controlling terminal -- the exact shape the
    /// helper's own main process has under systemd -- so this forks one.
    ///
    /// Needs no root: the test's own pty pair is enough.
    ///
    /// Not the only test in this crate's multi-threaded test binary that
    /// forks -- every `helper::server` test that opens a channel forks too,
    /// through a channel's own launch -- but the only one whose child is written by
    /// hand right here, which is why the obligation is spelled out at
    /// length below. `fork`'s own safety docs say a multithreaded program's
    /// child may call only async-signal-safe functions -- allocation is
    /// explicitly called out as NOT safe -- which rules out calling
    /// `read_regular_file_bounded` itself (an ordinary, allocating Rust
    /// function) from the child. So everything the child needs -- the pty
    /// slave's path as a `CString`, and `OPEN_FLAGS` as a plain integer --
    /// is computed here, in the parent, BEFORE the fork; the child then
    /// touches nothing but raw, non-allocating `libc` calls on values it
    /// already has in its inherited memory. That is also what makes this
    /// fork safe regardless of how many other threads this shared test
    /// binary happens to have running at the moment it runs: the child
    /// never touches anything (like the allocator's own lock) that a
    /// vanished sibling thread could have been holding.
    /// The child reports WHICH of the things that can happen happened, as
    /// its exit code, so a failure names the case instead of leaving it to
    /// be guessed -- and so that the two cases that prove nothing cannot
    /// pass for the one that proves everything (an earlier version checked
    /// only whether `/dev/tty` opened, and so passed both with `O_NOCTTY`
    /// removed AND with the slave's path broken, because a terminal that
    /// was never opened cannot have been acquired either):
    ///
    /// - `0`: the slave opened, and `/dev/tty` then failed with `ENXIO` --
    ///   "this process has no controlling terminal", the one correct
    ///   outcome.
    /// - `1`: the slave opened and `/dev/tty` OPENED -- `O_NOCTTY` is
    ///   missing and the pty became this process's controlling terminal.
    /// - `2`: the slave itself could not be opened, so nothing was tested.
    /// - `3`: `/dev/tty` failed with some errno OTHER than `ENXIO`, which
    ///   is a different failure and must not be read as success.
    /// - `4`: `setsid` failed, so this child never was the session leader
    ///   without a controlling terminal that the whole test needs it to be.
    #[test]
    fn open_flags_never_acquire_a_controlling_terminal() {
        // `O_CLOEXEC` on the master: this binary runs its tests in
        // parallel, and several of them exec other processes -- a master
        // without it leaks into every one of them for as long as they run.
        let master = nix::pty::posix_openpt(OFlag::O_RDWR | OFlag::O_NOCTTY | OFlag::O_CLOEXEC)
            .expect("posix_openpt");
        nix::pty::grantpt(&master).expect("grantpt");
        nix::pty::unlockpt(&master).expect("unlockpt");
        let slave_name = nix::pty::ptsname_r(&master).expect("ptsname_r");
        let slave_path = std::ffi::CString::new(slave_name).expect("no NUL in ptsname");
        let dev_tty_path = std::ffi::CString::new("/dev/tty").expect("no NUL");
        let open_flags_bits = OPEN_FLAGS.bits();

        // SAFETY: `fork` itself -- the child that follows takes the
        // async-signal-safety obligation seriously, see this test's docs.
        match unsafe { nix::unistd::fork() }.expect("fork") {
            nix::unistd::ForkResult::Child => {
                // SAFETY: from here to `_exit`, only async-signal-safe
                // libc calls on values already computed above, before the
                // fork -- no allocation, no locking. `setsid` makes this
                // process a session leader with no controlling terminal
                // (it cannot already be a process group leader: it is a
                // freshly forked child); the first `open` is exactly what
                // `read_regular_file_bounded` does, with the exact same
                // flags; the second checks whether that open acquired a
                // controlling terminal by trying to open `/dev/tty`, which
                // only resolves to something if one exists.
                unsafe {
                    if libc::setsid() < 0 {
                        libc::_exit(4);
                    }
                    let fd = libc::open(slave_path.as_ptr(), open_flags_bits);
                    if fd < 0 {
                        libc::_exit(2);
                    }
                    libc::close(fd);
                    let ctty_fd = libc::open(dev_tty_path.as_ptr(), libc::O_RDWR);
                    if ctty_fd >= 0 {
                        libc::close(ctty_fd);
                        libc::_exit(1);
                    }
                    // `errno` for the open that just failed. `ENXIO` is the
                    // kernel's way of saying this process has no
                    // controlling terminal at all -- which, after opening a
                    // pty slave a moment ago, is exactly what `O_NOCTTY`
                    // bought. Any other errno is some unrelated failure and
                    // must not be counted as the flag working.
                    if nix::errno::Errno::last() != nix::errno::Errno::ENXIO {
                        libc::_exit(3);
                    }
                    libc::_exit(0);
                }
            }
            nix::unistd::ForkResult::Parent { child } => {
                let status = nix::sys::wait::waitpid(child, None).expect("waitpid");
                match status {
                    nix::sys::wait::WaitStatus::Exited(_, 0) => {}
                    nix::sys::wait::WaitStatus::Exited(_, 1) => panic!(
                        "the child acquired a controlling terminal: /dev/tty opened after the \
                         pty slave was opened with OPEN_FLAGS -- O_NOCTTY is missing from them"
                    ),
                    nix::sys::wait::WaitStatus::Exited(_, 2) => panic!(
                        "the child could not open the pty slave at all, so this test checked \
                         nothing about O_NOCTTY: a terminal that was never opened cannot have \
                         been acquired (is the slave's path still right?)"
                    ),
                    nix::sys::wait::WaitStatus::Exited(_, 3) => panic!(
                        "/dev/tty failed for a reason other than ENXIO -- that is not the \
                         'no controlling terminal' answer this test reads as success"
                    ),
                    nix::sys::wait::WaitStatus::Exited(_, 4) => panic!(
                        "setsid failed in the child, so it never was a session leader without a \
                         controlling terminal -- the one shape in which this test means anything"
                    ),
                    nix::sys::wait::WaitStatus::Exited(_, code) => {
                        panic!("the child exited with an unexpected code {code}")
                    }
                    other => panic!("the child did not exit cleanly: {other:?}"),
                }
            }
        }
    }
}
