//! The client's record of which server key belongs to which host.
//!
//! Trust on first use, exactly as SSH does it: the first key seen for a host
//! is shown to the user and pinned; a key that changes afterwards is refused
//! loudly rather than trusted quietly -- that case is either a reinstalled
//! server or an attacker, and the two are indistinguishable from here.
//!
//! Every write (`pin`) rewrites the whole file to a sibling temp file and
//! then `rename`s it into place, so a crash mid-write can never leave a
//! half-written line for `check` to stumble over: readers only ever see the
//! old complete file or the new complete one. On Unix both the known-hosts
//! file and its temp file are created `0600` so only the owner can read
//! which servers this client trusts. A failure after the temp file is
//! created (a write error, a failed rename) removes it; only a hard crash in
//! that same narrow window can leave an orphaned `.known_hosts.tmp.*` file
//! behind, and that file is inert -- `check` never reads it.
//!
//! `pin` also holds an advisory lock (`flock` on a sibling `.lock` file --
//! never on `self.path` itself, since `pin` replaces that path's inode via
//! `rename`, and a lock held on the old inode would stop protecting
//! anything the instant the new file lands there) across its entire
//! read-modify-write-rename. That is what makes two processes pinning at
//! the same moment safe even for two DIFFERENT hosts: without it, both
//! would read the same pre-image and whichever `rename` landed second would
//! silently discard the other's just-approved pin, sending that host back
//! to `Unknown`. (OpenSSH's own `known_hosts` sidesteps this differently --
//! by appending a line per accepted key instead of rewriting the file -- so
//! it is not a precedent for skipping the lock here.)

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use sha2::{Digest, Sha256};
use transport::auth::AuthError;

/// What the store says about a host's key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HostVerdict {
    /// Never seen: show the fingerprint and ask before pinning.
    Unknown,
    /// Seen before, same key.
    Known,
    /// Seen before with a DIFFERENT key. Refuse; someone must look at this.
    Changed { pinned: [u8; 32] },
}

impl fmt::Display for HostVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HostVerdict::Unknown => f.write_str("unknown host"),
            HostVerdict::Known => f.write_str("known host"),
            HostVerdict::Changed { .. } => f.write_str("host key changed"),
        }
    }
}

/// The `SHA256:` fingerprint of a server's raw X25519 transport key, in the
/// same shape OpenSSH prints for its own keys -- short enough to read aloud
/// and compare, unambiguous enough that a changed key produces a visibly
/// different string.
///
/// This is a different function from [`crate::verify::fingerprint`], not a
/// duplicate of it: that one fingerprints a client's `ssh-key` `PublicKey`
/// (the standard SSH wire encoding, as it appears in `authorized_keys`);
/// this one fingerprints the server's bare 32-byte Noise static key, which
/// has no SSH key type or wire encoding of its own to hash.
pub fn key_fingerprint(key: &[u8; 32]) -> String {
    let digest = Sha256::digest(key);
    format!("SHA256:{}", BASE64.encode(digest).trim_end_matches('='))
}

/// One parsed `host port base64-key` line.
struct Entry {
    host: String,
    port: u16,
    key: [u8; 32],
}

/// Parse a single line, or `None` if it is blank, a `#` comment, or
/// malformed in any way (missing field, unparseable port, non-base64 key,
/// or a key that doesn't decode to exactly 32 bytes). A malformed line is
/// silently skipped rather than treated as an error -- the same tolerance
/// OpenSSH's own `known_hosts` reader has for lines it doesn't understand --
/// so a hand-edited or partially-written file degrades to "that entry is
/// unknown," never to a crash or a false match.
fn parse_line(line: &str) -> Option<Entry> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let mut parts = line.split_whitespace();
    let host = parts.next()?;
    let port = parts.next()?.parse::<u16>().ok()?;
    let key = parts.next()?;
    let decoded = BASE64.decode(key).ok()?;
    let key = <[u8; 32]>::try_from(decoded.as_slice()).ok()?;
    Some(Entry {
        host: host.to_string(),
        port,
        key,
    })
}

/// The known-hosts file: `host port base64-key`, one entry per line, `#`
/// comments and blank lines ignored -- the same shape as OpenSSH's own file.
/// A `host`/`port` pair matches only itself: the host is compared for exact
/// string equality (never a prefix or suffix) and the port for exact
/// numeric equality, so `example.org:60022` is a distinct entry from
/// `example.org:60023` or `evil-example.org:60022`.
pub struct KnownHosts {
    path: PathBuf,
}

impl KnownHosts {
    /// A store backed by `path` (usually `~/.config/qsh/known_hosts`). The
    /// file need not exist yet -- an absent file just means nothing is
    /// pinned.
    pub fn open(path: PathBuf) -> KnownHosts {
        KnownHosts { path }
    }

    /// Read and parse every well-formed entry in the file. An absent file
    /// is not an error (nothing pinned yet); any other read failure
    /// (permissions, the path being a directory, ...) is, since silently
    /// treating it as "nothing pinned" would let a broken store masquerade
    /// as a trustworthy empty one.
    fn read_entries(&self) -> Result<Vec<Entry>, AuthError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Ok(text.lines().filter_map(parse_line).collect()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(e) => Err(AuthError::Backend(format!(
                "reading {}: {e}",
                self.path.display()
            ))),
        }
    }

    /// What we know about `host:port`'s key. If the file holds more than
    /// one entry for the same `host:port` (only possible via a hand-edited
    /// file -- `pin` never writes a duplicate), the LAST one wins, so a
    /// manually appended correction takes effect rather than being shadowed
    /// by the stale line above it.
    pub fn check(&self, host: &str, port: u16, key: &[u8; 32]) -> Result<HostVerdict, AuthError> {
        let entries = self.read_entries()?;
        match entries
            .iter()
            .rev()
            .find(|e| e.host == host && e.port == port)
        {
            None => Ok(HostVerdict::Unknown),
            Some(e) if &e.key == key => Ok(HostVerdict::Known),
            Some(e) => Ok(HostVerdict::Changed { pinned: e.key }),
        }
    }

    /// Record `key` as this host's key. The caller has already shown the
    /// fingerprint and got a yes -- this function does not ask.
    ///
    /// Pinning a `host:port` that already has an entry REPLACES it rather
    /// than appending a second line, so a later `check` sees the new key
    /// as `Known` instead of finding the old line first and reporting
    /// `Changed` against a key the caller just approved.
    ///
    /// Holds [`PinLock`] for the whole read-modify-write-rename, so a
    /// concurrent `pin` (even for a different host) waits instead of
    /// racing -- see the module doc-comment.
    pub fn pin(&self, host: &str, port: u16, key: &[u8; 32]) -> Result<(), AuthError> {
        let _lock = PinLock::acquire(&self.path)?;

        let mut entries = self.read_entries()?;
        entries.retain(|e| !(e.host == host && e.port == port));
        entries.push(Entry {
            host: host.to_string(),
            port,
            key: *key,
        });

        self.write_atomic(render(&entries).as_bytes())
        // `_lock` is dropped (and released) here, after the rename below
        // has already made the new contents visible.
    }

    /// Record `key` as this host's key ONLY if nothing is pinned for it yet,
    /// and say what was on file before: `Unknown` means it is pinned now;
    /// `Known` and `Changed` mean the file was left exactly as it was.
    ///
    /// For a key the caller learned without asking anyone -- a handshake
    /// that proved the server holds it -- where an existing line, even a
    /// stale one, is for a person to remove, not for this call to replace.
    /// The check and the write happen under one [`PinLock`], so another
    /// process pinning this host in between cannot be overwritten.
    pub fn pin_if_absent(
        &self,
        host: &str,
        port: u16,
        key: &[u8; 32],
    ) -> Result<HostVerdict, AuthError> {
        let _lock = PinLock::acquire(&self.path)?;

        let mut entries = self.read_entries()?;
        // The same "last line wins" as `check`.
        if let Some(e) = entries
            .iter()
            .rev()
            .find(|e| e.host == host && e.port == port)
        {
            return Ok(if &e.key == key {
                HostVerdict::Known
            } else {
                HostVerdict::Changed { pinned: e.key }
            });
        }
        entries.push(Entry {
            host: host.to_string(),
            port,
            key: *key,
        });
        self.write_atomic(render(&entries).as_bytes())?;
        Ok(HostVerdict::Unknown)
    }

    /// Where the store lives, for a line that tells a person which file to
    /// edit.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Replace the file's contents without ever leaving a half-written
    /// file on disk: write to a fresh sibling temp file, then `rename` it
    /// over `self.path`. `rename` on the same filesystem is atomic, so a
    /// crash or a kill signal between the two calls leaves either the old
    /// file (untouched) or the new one (complete) -- never a mix of both.
    /// Any failure after the temp file is created removes it, so an
    /// ordinary error path never leaves it behind.
    fn write_atomic(&self, contents: &[u8]) -> Result<(), AuthError> {
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)
                .map_err(|e| AuthError::Backend(format!("creating {}: {e}", dir.display())))?;
        }
        let tmp_path = self.temp_path();
        if let Err(e) = write_owner_only(&tmp_path, contents) {
            let _ = fs::remove_file(&tmp_path);
            return Err(AuthError::Backend(format!(
                "writing {}: {e}",
                tmp_path.display()
            )));
        }
        fs::rename(&tmp_path, &self.path).map_err(|e| {
            let _ = fs::remove_file(&tmp_path);
            AuthError::Backend(format!("replacing {}: {e}", self.path.display()))
        })
    }

    /// A sibling path in the same directory (so the later `rename` stays on
    /// one filesystem), named uniquely enough that two `pin` calls -- even
    /// from two threads of the same process -- do not collide.
    fn temp_path(&self) -> PathBuf {
        let name = self
            .path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("known_hosts");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        self.path
            .with_file_name(format!(".{name}.tmp.{}.{nanos}", std::process::id()))
    }
}

/// The file's contents for `entries`, one `host port base64-key` line each.
fn render(entries: &[Entry]) -> String {
    let mut contents = String::new();
    for e in entries {
        contents.push_str(&format!("{} {} {}\n", e.host, e.port, BASE64.encode(e.key)));
    }
    contents
}

/// Write a brand-new file with `contents`, owner-only on Unix. `create_new`
/// (rather than `create` + `truncate`) refuses to follow a pre-planted
/// symlink at this exact path -- cheap insurance, since `path` is always a
/// freshly chosen temp path (see `temp_path`) that has no legitimate reason
/// to already exist.
#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_owner_only(path: &Path, contents: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(contents)?;
    file.sync_all()
}

/// An advisory lock held across `pin`'s whole read-modify-write-rename --
/// see the module doc-comment for why it exists and why it lives on a
/// SIBLING file rather than `self.path`.
///
/// Unix only: `flock(2)` via a raw fd. Other targets get a no-op lock (the
/// same reach as the rest of this module's Unix-specific hardening, e.g.
/// owner-only permissions).
#[cfg(unix)]
struct PinLock {
    /// Kept alive only to hold the fd open -- and therefore the flock held
    /// -- until this guard drops. Never read from directly.
    _file: File,
}

#[cfg(not(unix))]
struct PinLock;

#[cfg(unix)]
impl PinLock {
    /// Block until the lock for `known_hosts_path` is free, then hold it
    /// until the returned guard is dropped.
    fn acquire(known_hosts_path: &Path) -> Result<PinLock, AuthError> {
        use std::os::unix::fs::OpenOptionsExt;
        use std::os::unix::io::AsRawFd;

        let lock_path = lock_path_for(known_hosts_path);
        if let Some(dir) = lock_path.parent().filter(|d| !d.as_os_str().is_empty()) {
            fs::create_dir_all(dir)
                .map_err(|e| AuthError::Backend(format!("creating {}: {e}", dir.display())))?;
        }
        // The lock file is long-lived and reused by every `pin` -- it holds
        // no data, it exists only to be flock'd, so there is nothing to
        // reset or clean up between calls. `O_NOFOLLOW` refuses to open it
        // if the last path component is a symlink -- the same class of
        // pre-planted-symlink concern as the temp file's `create_new`,
        // except this file IS reused across calls, so `create_new` isn't
        // the right tool here. Nothing is ever written through this
        // handle beyond its own creation, so the worst a followed symlink
        // could do is lock the wrong file, never corrupt one -- but
        // refusing it costs nothing.
        let file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false) // reused across calls; its bytes are never read
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|e| {
                AuthError::Backend(format!("opening lock file {}: {e}", lock_path.display()))
            })?;
        // SAFETY: `file` is a valid, open file descriptor for the duration
        // of this call, which is all `flock` needs.
        //
        // Retried on `EINTR`: `flock` blocks while another holder has the
        // lock, and a signal delivered during that wait (this crate is
        // used by a terminal CLI, which handles `SIGWINCH` on every window
        // resize) interrupts the syscall without the lock being free yet.
        // Treating that as a hard failure would fail an ordinary `pin()`
        // for no reason other than someone resizing their terminal.
        loop {
            let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if rc == 0 {
                break;
            }
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(AuthError::Backend(format!(
                "locking {}: {err}",
                lock_path.display()
            )));
        }
        Ok(PinLock { _file: file })
    }
}

#[cfg(not(unix))]
impl PinLock {
    fn acquire(_known_hosts_path: &Path) -> Result<PinLock, AuthError> {
        Ok(PinLock)
    }
}

/// The lock file's path: a sibling of `known_hosts_path` with `.lock`
/// appended to the file name, so two independent stores in the same
/// directory (unusual, but not forbidden) never share a lock.
#[cfg(unix)]
fn lock_path_for(known_hosts_path: &Path) -> PathBuf {
    let name = known_hosts_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("known_hosts");
    known_hosts_path.with_file_name(format!(".{name}.lock"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_key(key: &[u8; 32]) -> String {
        BASE64.encode(key)
    }

    #[test]
    fn an_unknown_host_is_reported_as_unknown_then_pinned() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        let hosts = KnownHosts::open(path.clone());
        assert_eq!(
            hosts.check("example.org", 60022, &[1u8; 32]).unwrap(),
            HostVerdict::Unknown
        );

        hosts.pin("example.org", 60022, &[1u8; 32]).expect("pin");
        assert_eq!(
            hosts.check("example.org", 60022, &[1u8; 32]).unwrap(),
            HostVerdict::Known
        );
        // A different port is a different entry.
        assert_eq!(
            hosts.check("example.org", 60023, &[1u8; 32]).unwrap(),
            HostVerdict::Unknown
        );
    }

    /// A changed key is the loud case: never silently trusted, and the old
    /// fingerprint comes back so the user can see what changed.
    #[test]
    fn a_changed_key_is_reported_with_the_pinned_one() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = KnownHosts::open(dir.path().join("known_hosts"));
        hosts.pin("example.org", 60022, &[1u8; 32]).expect("pin");
        match hosts.check("example.org", 60022, &[2u8; 32]).unwrap() {
            HostVerdict::Changed { pinned } => assert_eq!(pinned, [1u8; 32]),
            other => panic!("expected a changed-key verdict, got {other:?}"),
        }
    }

    #[test]
    fn comments_and_blank_lines_are_ignored() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "# a comment\n\nexample.org 60022 {}\n",
                base64_key(&[3u8; 32])
            ),
        )
        .expect("write");
        let hosts = KnownHosts::open(path);
        assert_eq!(
            hosts.check("example.org", 60022, &[3u8; 32]).unwrap(),
            HostVerdict::Known
        );
    }

    #[test]
    fn a_fingerprint_is_stable_and_key_specific() {
        let a = key_fingerprint(&[1u8; 32]);
        assert!(a.starts_with("SHA256:"));
        assert_eq!(a, key_fingerprint(&[1u8; 32]));
        assert_ne!(a, key_fingerprint(&[2u8; 32]));
    }

    /// Independently computed (Python `hashlib.sha256` + unpadded base64)
    /// so this fails if the fingerprint is ever computed over the wrong
    /// bytes -- the base64 text instead of the raw key, a truncated key,
    /// padded output, and so on -- not just if it becomes internally
    /// inconsistent.
    #[test]
    fn a_fingerprint_matches_an_independently_computed_value() {
        assert_eq!(
            key_fingerprint(&[1u8; 32]),
            "SHA256:cs1uhCLEB/ttCYaQ8RMLfe1+wvf14dML2dUh8BU2N5M"
        );
    }

    /// Re-pinning after a `Changed` verdict must replace the old entry, not
    /// add a second one -- otherwise the stale first line would keep
    /// winning and a key the user just approved would look `Changed` forever.
    #[test]
    fn re_pinning_a_changed_key_replaces_the_old_entry() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = KnownHosts::open(dir.path().join("known_hosts"));
        hosts
            .pin("example.org", 60022, &[1u8; 32])
            .expect("first pin");
        hosts.pin("example.org", 60022, &[2u8; 32]).expect("re-pin");
        assert_eq!(
            hosts.check("example.org", 60022, &[2u8; 32]).unwrap(),
            HostVerdict::Known,
            "the new key must be recognized, not shadowed by the old entry"
        );
    }

    /// A host name can never be satisfied by a prefix, suffix or substring
    /// of a pinned one -- only exact equality counts.
    #[test]
    fn a_similar_but_different_host_name_does_not_match() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = KnownHosts::open(dir.path().join("known_hosts"));
        hosts.pin("example.org", 60022, &[1u8; 32]).expect("pin");
        assert_eq!(
            hosts.check("evil-example.org", 60022, &[1u8; 32]).unwrap(),
            HostVerdict::Unknown
        );
        assert_eq!(
            hosts
                .check("example.org.evil.com", 60022, &[1u8; 32])
                .unwrap(),
            HostVerdict::Unknown
        );
        assert_eq!(
            hosts.check("example.or", 60022, &[1u8; 32]).unwrap(),
            HostVerdict::Unknown
        );
    }

    /// A line with a garbage port or a key that isn't 32 bytes of base64
    /// must be skipped, not crash the reader or corrupt an unrelated
    /// lookup.
    #[test]
    fn lines_with_a_bad_port_or_key_are_skipped() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        std::fs::write(
            &path,
            format!(
                "example.org not-a-port {}\nexample.org 60022 not-base64!!\nexample.org 60022 {}\nexample.com 60022 {}\n",
                base64_key(&[9u8; 32]),
                BASE64.encode([9u8; 16]), // decodes, but the wrong length
                base64_key(&[3u8; 32]),
            ),
        )
        .expect("write");
        let hosts = KnownHosts::open(path);
        assert_eq!(
            hosts.check("example.com", 60022, &[3u8; 32]).unwrap(),
            HostVerdict::Known
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_created_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        let hosts = KnownHosts::open(path.clone());
        hosts.pin("example.org", 60022, &[1u8; 32]).expect("pin");
        let mode = fs::metadata(&path).expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o600,
            "known_hosts must be readable only by its owner"
        );
    }

    /// Two processes pinning at the same moment must not race: without a
    /// lock, both read the same pre-image and whichever `rename` lands
    /// second silently discards the other's just-approved pin -- even
    /// though the two pins are for two DIFFERENT hosts, which a naive
    /// "same host" duplicate check would not catch. This test holds the
    /// exact lock `pin` itself takes, standing in for another process's
    /// in-flight pin, and proves `pin` waits for it rather than racing
    /// past it.
    #[cfg(unix)]
    #[test]
    fn a_pin_in_progress_blocks_a_concurrent_pin_of_a_different_host_until_it_finishes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        let hosts = KnownHosts::open(path.clone());
        hosts
            .pin("a.example.org", 60022, &[1u8; 32])
            .expect("pin a");

        let held = PinLock::acquire(&path).expect("acquire the lock pin() itself uses");
        let hosts_for_thread = KnownHosts::open(path.clone());
        let handle =
            std::thread::spawn(move || hosts_for_thread.pin("b.example.org", 60022, &[2u8; 32]));

        // Give the background pin() every chance to (wrongly) finish while
        // the lock is held.
        std::thread::sleep(std::time::Duration::from_millis(200));
        assert_eq!(
            hosts.check("b.example.org", 60022, &[2u8; 32]).unwrap(),
            HostVerdict::Unknown,
            "pin() must wait for the lock, not race past it"
        );

        drop(held);
        handle
            .join()
            .expect("pin thread")
            .expect("pin succeeds once the lock is free");

        // The point of the lock: a concurrent pin of a DIFFERENT host must
        // never be lost to a last-rename-wins race.
        assert_eq!(
            hosts.check("a.example.org", 60022, &[1u8; 32]).unwrap(),
            HostVerdict::Known,
            "the first host's pin must survive a concurrent pin of a different host"
        );
        assert_eq!(
            hosts.check("b.example.org", 60022, &[2u8; 32]).unwrap(),
            HostVerdict::Known
        );
    }

    /// A symlink planted at the exact lock-file path must not be followed:
    /// `O_NOFOLLOW` makes `open` fail on it rather than locking (or
    /// creating) whatever it points to.
    #[cfg(unix)]
    #[test]
    fn the_lock_file_refuses_to_follow_a_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");
        let lock_path = dir.path().join(".known_hosts.lock");
        let elsewhere = dir.path().join("elsewhere");
        std::fs::write(&elsewhere, b"").expect("write the symlink's target");
        std::os::unix::fs::symlink(&elsewhere, &lock_path)
            .expect("plant a symlink at the lock path");

        assert!(
            PinLock::acquire(&path).is_err(),
            "acquire() must refuse to follow a symlink planted at the lock path"
        );
    }

    /// A host with nothing on file is pinned; one with a line -- the same
    /// key or another -- keeps that line untouched, and the caller is told
    /// which it was.
    #[test]
    fn pin_if_absent_pins_only_a_host_with_nothing_on_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let hosts = KnownHosts::open(dir.path().join("known_hosts"));

        assert_eq!(
            hosts.pin_if_absent("a", 1, &[1u8; 32]).expect("pin"),
            HostVerdict::Unknown
        );
        assert_eq!(hosts.check("a", 1, &[1u8; 32]).unwrap(), HostVerdict::Known);

        assert_eq!(
            hosts.pin_if_absent("a", 1, &[1u8; 32]).expect("again"),
            HostVerdict::Known
        );
        assert_eq!(
            hosts
                .pin_if_absent("a", 1, &[2u8; 32])
                .expect("another key"),
            HostVerdict::Changed { pinned: [1u8; 32] }
        );
        assert_eq!(
            hosts.check("a", 1, &[1u8; 32]).unwrap(),
            HostVerdict::Known,
            "a line already there is never replaced"
        );
    }

    #[test]
    fn the_store_names_its_file() {
        let path = PathBuf::from("/some/where/known_hosts");
        assert_eq!(KnownHosts::open(path.clone()).path(), path.as_path());
    }

    /// `flock` blocks while another holder has the lock, and a signal
    /// delivered during that wait interrupts the syscall with `EINTR` even
    /// though the lock is not free yet -- exactly what a terminal client's
    /// `SIGWINCH` handler (installed without `SA_RESTART`) does on every
    /// window resize. `acquire` must retry rather than treat that as a
    /// failure: this test signals a thread that is genuinely blocked
    /// inside `flock`, while the lock is still held elsewhere, and checks
    /// that the interrupted call has NOT given up.
    #[cfg(unix)]
    #[test]
    fn flock_retries_after_being_interrupted_by_a_signal() {
        use std::sync::mpsc;

        extern "C" fn no_op_handler(_: libc::c_int) {}

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("known_hosts");

        // Stand in for another process's in-flight pin.
        let held = PinLock::acquire(&path).expect("acquire the lock first");

        let (tid_tx, tid_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let path_for_thread = path.clone();
        let handle = std::thread::spawn(move || {
            tid_tx
                .send(unsafe { libc::pthread_self() })
                .expect("send tid");
            let result = PinLock::acquire(&path_for_thread);
            let _ = done_tx.send(());
            result
        });
        let tid = tid_rx.recv().expect("receive the blocked thread's id");

        // A handler with `sa_flags = 0` (no `SA_RESTART`) so the signal
        // interrupts the blocking `flock` instead of the OS silently
        // resuming it.
        unsafe {
            let mut sa: libc::sigaction = std::mem::zeroed();
            sa.sa_sigaction = no_op_handler as *const () as usize;
            sa.sa_flags = 0;
            libc::sigemptyset(&mut sa.sa_mask);
            let rc = libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut());
            assert_eq!(rc, 0, "installing the SIGUSR1 handler");
        }

        // Give the background thread time to actually be parked inside
        // `flock` before signalling it.
        std::thread::sleep(std::time::Duration::from_millis(100));
        let rc = unsafe { libc::pthread_kill(tid, libc::SIGUSR1) };
        assert_eq!(rc, 0, "signalling the blocked thread");

        // The signal fires while `held` is still held. Without a retry
        // loop, `acquire` gives up right here -- before the lock is ever
        // free -- and `done_tx` fires almost immediately. With the retry,
        // the thread stays parked in `flock` and nothing arrives.
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(
            done_rx.try_recv().is_err(),
            "acquire() must not give up on an EINTR while the lock is still held by someone else"
        );

        drop(held);
        handle
            .join()
            .expect("thread")
            .expect("acquire succeeds once the lock is free, even after being interrupted");
    }
}
