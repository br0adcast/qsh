//! Reading an account's authorized keys, as that account.
//!
//! The helper is root, so it could simply open the file. It deliberately
//! does not: it switches its EFFECTIVE identity to the account first --
//! user, group, AND supplementary groups -- and lets the kernel decide.
//! That way the permission checks, the symlink resolution and every
//! directory on the path are evaluated with the account's own rights -- so
//! a link planted in a world-writable directory and pointing at somebody
//! else's key file cannot be followed on root's authority. It is also the
//! only thing that works on a home directory mounted over NFS with root
//! squashed.
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
use std::os::unix::io::FromRawFd;
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
}

impl EffectiveIdentity {
    /// Become `account`: its supplementary groups, then its group, then
    /// its user -- see this module's docs for why that order. The guard
    /// (capturing the previous identity) is built BEFORE the first `set*`
    /// call, not after the last one, so a failure partway through the
    /// switch still has something to roll back to when this returns `Err`
    /// and the partially-built guard drops.
    fn become_account(account: &Account) -> Result<EffectiveIdentity, AuthorizedError> {
        let guard = EffectiveIdentity {
            previous_uid: Uid::effective(),
            previous_gid: Gid::effective(),
            previous_groups: nix::unistd::getgroups()
                .map_err(|e| AuthorizedError::Switch(e.to_string()))?,
        };
        nix::unistd::setgroups(&account.groups)
            .map_err(|e| AuthorizedError::Switch(e.to_string()))?;
        nix::unistd::setegid(account.gid).map_err(|e| AuthorizedError::Switch(e.to_string()))?;
        nix::unistd::seteuid(account.uid).map_err(|e| AuthorizedError::Switch(e.to_string()))?;
        Ok(guard)
    }
}

impl Drop for EffectiveIdentity {
    fn drop(&mut self) {
        // Order is the reverse of becoming the account, and is not a
        // choice: `setgroups` needs `CAP_SETGID`, which is only present
        // again once the effective user id is back to root -- see this
        // module's docs.
        let restored = nix::unistd::seteuid(self.previous_uid).is_ok()
            && nix::unistd::setegid(self.previous_gid).is_ok()
            && nix::unistd::setgroups(&self.previous_groups).is_ok();
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
    }
}

/// The exact `open` flags [`read_regular_file_bounded`] uses. Pulled out
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
    .union(OFlag::O_NOCTTY);

/// Open `path` under whatever identity is currently effective, refuse
/// anything that is not a regular file, and read at most
/// [`MAX_AUTHORIZED_KEYS_BYTES`] bytes -- see this module's docs for why
/// both of those matter. `Ok(None)` means the file does not exist, which
/// `read_for` turns into an empty result rather than an error.
///
/// `pub(super)`: visible to the rest of `helper`, not wider -- `server`'s
/// own tests build a `read_keys_plainly` that reads the same file with the
/// same bounds but never switches identity (`read_for` always calls
/// `setgroups`, which needs `CAP_SETGID` even to "become yourself" and so
/// cannot run unprivileged), reusing this function and [`to_key_text`]
/// rather than a hand-copied duplicate that could drift from the real
/// bounds over time.
pub(super) fn read_regular_file_bounded(path: &Path) -> std::io::Result<Option<String>> {
    // `O_NONBLOCK`: opening a FIFO for reading alone blocks until some
    // process opens it for writing. An account can put a FIFO at its own
    // key path, and this helper is single-threaded, so a blocking `open`
    // here would stop it from serving every login on the machine, not
    // just this account's, forever. `O_NONBLOCK` makes `open` return
    // immediately no matter what is at the other end; `fstat` right after
    // is what actually tells a FIFO (or a device, or a socket) apart from
    // a regular file, and refuses it before a single byte is read.
    //
    // `O_NOCTTY`: see [`OPEN_FLAGS`]'s own docs -- without it, opening a
    // terminal device here could make it this (possibly session-leader,
    // possibly controlling-terminal-less) process's controlling terminal.
    let fd = match fcntl::open(path, OPEN_FLAGS, stat::Mode::empty()) {
        Ok(fd) => fd,
        Err(nix::errno::Errno::ENOENT) => return Ok(None),
        Err(e) => return Err(std::io::Error::from(e)),
    };
    // SAFETY: `fd` was just returned by `open` above and nothing else has
    // a copy of it. Wrapping it in a `File` immediately, rather than
    // juggling the raw descriptor by hand, is what makes every exit path
    // below -- including the early returns -- close it via the ordinary
    // `Drop` glue.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };

    let metadata = stat::fstat(fd).map_err(std::io::Error::from)?;
    if metadata.st_mode & SFlag::S_IFMT.bits() != SFlag::S_IFREG.bits() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to read authorized_keys: not a regular file",
        ));
    }

    // Back to ordinary blocking mode before anything reads from it: a
    // regular file never blocks on `read` regardless of this flag, but
    // there is no reason to leave a nonblocking descriptor as a surprise
    // for whatever touches it next.
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

/// Turn what [`read_regular_file_bounded`] found into `read_for`'s result:
/// a missing file is not an error (an account that has added no key admits
/// nobody, which is a policy, not a failure), and any other read failure
/// becomes an [`AuthorizedError::Read`] naming the path. Split out from
/// `read_for` itself so this pure mapping -- which needs no privilege at
/// all -- can be tested directly, independent of the identity switch that
/// the rest of `read_for` cannot exercise without root (see this module's
/// docs and `qshd/tests/authorized_keys_privilege.rs`).
///
/// `pub(super)`: see [`read_regular_file_bounded`]'s docs -- widened for the
/// same test-only reader, no wider.
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
    let path = super::account::expand_template(template, account);
    let _as_them = EffectiveIdentity::become_account(account)?;
    to_key_text(read_regular_file_bounded(&path), &path)
}

#[cfg(test)]
mod tests {
    use super::*;

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
